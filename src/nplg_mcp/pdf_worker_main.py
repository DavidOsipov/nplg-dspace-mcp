# Copyright (c) 2026 David Osipov
"""Single-request, resource-constrained PDF worker entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import resource
import socket
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Protocol, cast, runtime_checkable

from .config import (
    HARD_MAX_PAGE_PIXELS,
    HARD_MAX_RENDER_PAGES,
    HARD_MAX_RENDER_PIXELS,
    HARD_MAX_TILE_DIMENSION,
    HARD_MAX_TILE_OVERLAP,
    HARD_MAX_TILES_PER_PAGE,
)
from .errors import AppError, ErrorCode
from .json_types import dataclass_to_json
from .pdf_executor import PdfProcessorSettings
from .pdf_ipc import (
    MAX_COMMAND_FRAME_BYTES,
    MAX_RESULT_FRAME_BYTES,
    InspectCommand,
    InspectPayload,
    ManifestPayload,
    PdfCommand,
    PdfFailure,
    PdfInspectionOutput,
    PdfResult,
    PdfSuccess,
    PublicWorkerError,
    RenderPagesCommand,
    RenderPagesOutput,
    RenderPagesPayload,
    RenderTilesCommand,
    RenderTilesOutput,
    RenderTilesPayload,
    encode_frame,
    parse_command_frame,
)

_LIMIT_ENVIRON = {
    "NPLG_PDF_CPU_SECONDS": (1, 3_600),
    "NPLG_PDF_ADDRESS_SPACE_BYTES": (256 * 1024 * 1024, 8 * 1024 * 1024 * 1024),
    "NPLG_PDF_FILE_SIZE_BYTES": (1_048_576, 1024 * 1024 * 1024),
    "NPLG_PDF_OPEN_FILES": (16, 1_024),
    "NPLG_PDF_PROCESSES": (1, 64),
    "NPLG_PDF_MAX_PAGES_PER_RENDER": (1, HARD_MAX_RENDER_PAGES),
    "NPLG_PDF_MAX_PAGE_PIXELS": (1, HARD_MAX_PAGE_PIXELS),
    "NPLG_PDF_MAX_RENDER_PIXELS": (1, HARD_MAX_RENDER_PIXELS),
    "NPLG_PDF_FALLBACK_DPI": (72, 1_200),
    "NPLG_PDF_TILE_WIDTH": (256, HARD_MAX_TILE_DIMENSION),
    "NPLG_PDF_TILE_HEIGHT": (256, HARD_MAX_TILE_DIMENSION),
    "NPLG_PDF_TILE_OVERLAP": (0, HARD_MAX_TILE_OVERLAP),
    "NPLG_PDF_MAX_TILES_PER_PAGE": (1, HARD_MAX_TILES_PER_PAGE),
}
_FRAME_PREFIX_BYTES = 4
_PEER_CREDENTIAL_BYTES = 12

if TYPE_CHECKING:
    from asyncio import StreamReader, StreamWriter


@runtime_checkable
class _UnixSocketPeer(Protocol):
    """The narrow socket capability required for local peer verification."""

    family: socket.AddressFamily

    def getsockopt(self, level: int, option: int, buffer_size: int) -> bytes:
        """Return the fixed-width peer-credential record."""
        ...


def _peer_credentials(value: bytes) -> tuple[int, int, int]:
    """Decode exactly one native Linux ``ucred`` record without dynamic types."""
    if len(value) != _PEER_CREDENTIAL_BYTES:
        message = "PDF worker peer credentials are malformed"
        raise RuntimeError(message)
    return (
        int.from_bytes(value[0:4], byteorder=sys.byteorder, signed=True),
        int.from_bytes(value[4:8], byteorder=sys.byteorder, signed=True),
        int.from_bytes(value[8:12], byteorder=sys.byteorder, signed=True),
    )


@dataclass(frozen=True, slots=True)
class _WorkerOptions:
    """Typed projection of the worker's intentionally tiny CLI namespace."""

    unix_socket: Path | None


def _configured_integer(name: str) -> int:
    raw = os.environ.get(name, "")
    minimum, maximum = _LIMIT_ENVIRON[name]
    try:
        value = int(raw)
    except ValueError as exc:
        message = f"{name} is invalid"
        raise RuntimeError(message) from exc
    if not minimum <= value <= maximum:
        message = f"{name} is outside its allowed range"
        raise RuntimeError(message)
    return value


def _apply_resource_limits() -> int:
    """Apply hard ceilings before importing PDFium or reading a request."""
    cpu = _configured_integer("NPLG_PDF_CPU_SECONDS")
    address_space = _configured_integer("NPLG_PDF_ADDRESS_SPACE_BYTES")
    file_size = _configured_integer("NPLG_PDF_FILE_SIZE_BYTES")
    open_files = _configured_integer("NPLG_PDF_OPEN_FILES")
    processes = _configured_integer("NPLG_PDF_PROCESSES")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
    resource.setrlimit(resource.RLIMIT_NOFILE, (open_files, open_files))
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (processes, processes))
    return file_size


def _work_root() -> Path:
    raw = os.environ.get("NPLG_PDF_WORK_ROOT", "")
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        message = "PDF worker root is invalid"
        raise RuntimeError(message)
    metadata = path.stat()
    if metadata.st_mode & 0o077:
        message = "PDF worker root permissions are invalid"
        raise RuntimeError(message)
    return path


def _processor_settings() -> PdfProcessorSettings:
    return PdfProcessorSettings(
        max_pages_per_render=_configured_integer("NPLG_PDF_MAX_PAGES_PER_RENDER"),
        max_page_pixels=_configured_integer("NPLG_PDF_MAX_PAGE_PIXELS"),
        max_render_pixels=_configured_integer("NPLG_PDF_MAX_RENDER_PIXELS"),
        fallback_dpi=_configured_integer("NPLG_PDF_FALLBACK_DPI"),
        tile_width=_configured_integer("NPLG_PDF_TILE_WIDTH"),
        tile_height=_configured_integer("NPLG_PDF_TILE_HEIGHT"),
        tile_overlap=_configured_integer("NPLG_PDF_TILE_OVERLAP"),
        max_tiles_per_page=_configured_integer("NPLG_PDF_MAX_TILES_PER_PAGE"),
    )


def _read_command() -> PdfCommand:
    input_stream = cast("BinaryIO", sys.stdin.buffer)
    prefix = input_stream.read(_FRAME_PREFIX_BYTES)
    if len(prefix) != _FRAME_PREFIX_BYTES:
        message = "PDF worker command prefix is truncated"
        raise RuntimeError(message)
    size = int.from_bytes(prefix, "big")
    if size < 1 or size > MAX_COMMAND_FRAME_BYTES:
        message = "PDF worker command length is outside the allowed range"
        raise RuntimeError(message)
    body = input_stream.read(size)
    if len(body) != size or input_stream.read(1):
        message = "PDF worker command is truncated or has trailing data"
        raise RuntimeError(message)
    return parse_command_frame(body)


async def _read_socket_command(reader: StreamReader) -> PdfCommand:
    """Read exactly one bounded request frame from an AF_UNIX peer."""
    prefix = await reader.readexactly(_FRAME_PREFIX_BYTES)
    size = int.from_bytes(prefix, "big")
    if size < 1 or size > MAX_COMMAND_FRAME_BYTES:
        message = "PDF worker command length is outside the allowed range"
        raise RuntimeError(message)
    body = await reader.readexactly(size)
    if await reader.read(1):
        message = "PDF worker command has trailing data"
        raise RuntimeError(message)
    return parse_command_frame(body)


def _request_root(root: Path, command: PdfCommand) -> Path:
    """Confine a socket request to its UUID-derived, parent-created job directory."""
    path = root / command.request_id.hex
    try:
        metadata = path.lstat()
    except OSError as exc:
        message = "PDF worker request staging directory is unavailable"
        raise RuntimeError(message) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_mode & 0o077
    ):
        message = "PDF worker request staging directory is invalid"
        raise RuntimeError(message)
    return path


def _execute(
    command: PdfCommand,
    work_root: Path,
    *,
    max_bytes: int,
    settings: PdfProcessorSettings,
) -> PdfSuccess:
    # Delay native and persistence imports until resource limits are active.
    from .pdf import PdfProcessor  # noqa: PLC0415
    from .storage import ContentAddressedStore  # noqa: PLC0415

    store = ContentAddressedStore(work_root / "cache", max_bytes=max_bytes)
    processor = PdfProcessor(
        store=store,
        fallback_dpi=settings.fallback_dpi,
        max_pages_per_render=settings.max_pages_per_render,
        max_page_pixels=settings.max_page_pixels,
        max_render_pixels=settings.max_render_pixels,
        tile_width=settings.tile_width,
        tile_height=settings.tile_height,
        tile_overlap=settings.tile_overlap,
        max_tiles_per_page=settings.max_tiles_per_page,
    )
    if isinstance(command, InspectCommand):
        source = store.resolve_asset(command.source_relative_path)
        inspected = processor.inspect(source)
        inspection_output = PdfInspectionOutput.model_validate_json(
            json.dumps(
                dataclass_to_json(inspected, context="worker inspection"),
                allow_nan=False,
                separators=(",", ":"),
            ),
            strict=True,
        )
        return PdfSuccess(
            request_id=command.request_id,
            status="ok",
            payload=InspectPayload(operation="inspect", value=inspection_output),
        )
    if isinstance(command, RenderPagesCommand):
        source = store.resolve_asset(command.source_relative_path)
        rendered = processor.render_pages(
            source,
            pages=command.parameters.pages,
            mode=command.parameters.mode,
        )
        render_output = RenderPagesOutput.model_validate_json(
            json.dumps(
                dataclass_to_json(rendered, context="worker render manifest"),
                allow_nan=False,
                separators=(",", ":"),
            ),
            strict=True,
        )
        return PdfSuccess(
            request_id=command.request_id,
            status="ok",
            payload=RenderPagesPayload(
                operation="render_pages",
                value=render_output,
            ),
        )
    if isinstance(command, RenderTilesCommand):
        parameters = command.parameters
        tiled = processor.render_tiles(
            parameters.render_id,
            page_number=parameters.page_number,
            tile_width=parameters.tile_width,
            tile_height=parameters.tile_height,
            overlap=parameters.overlap,
        )
        tile_output = RenderTilesOutput.model_validate_json(
            json.dumps(
                dataclass_to_json(tiled, context="worker tile manifest"),
                allow_nan=False,
                separators=(",", ":"),
            ),
            strict=True,
        )
        return PdfSuccess(
            request_id=command.request_id,
            status="ok",
            payload=RenderTilesPayload(
                operation="render_tiles",
                value=tile_output,
            ),
        )
    rendered = processor.get_manifest(command.parameters.render_id)
    manifest_output = RenderPagesOutput.model_validate_json(
        json.dumps(
            dataclass_to_json(rendered, context="worker render manifest"),
            allow_nan=False,
            separators=(",", ":"),
        ),
        strict=True,
    )
    return PdfSuccess(
        request_id=command.request_id,
        status="ok",
        payload=ManifestPayload(operation="manifest", value=manifest_output),
    )


def _failure(command: PdfCommand, error: Exception) -> PdfFailure:
    if isinstance(error, AppError):
        code = error.code
        message = error.message
    else:
        code = ErrorCode.INTERNAL_ERROR
        message = "The PDF worker could not complete the request."
    return PdfFailure(
        request_id=command.request_id,
        status="error",
        operation=command.operation,
        payload=PublicWorkerError(code=code, message=message[:512]),
    )


def _verified_unix_peer(writer: StreamWriter) -> None:
    """Accept only a same-identity AF_UNIX client on the private socket."""
    stream_socket = cast("object", writer.get_extra_info("socket"))
    if (
        not isinstance(stream_socket, _UnixSocketPeer)
        or stream_socket.family != socket.AF_UNIX
    ):
        message = "PDF worker transport is not AF_UNIX"
        raise RuntimeError(message)
    credentials = stream_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _process_id, peer_uid, _peer_group = _peer_credentials(credentials)
    if peer_uid != os.geteuid():
        message = "PDF worker peer identity is invalid"
        raise RuntimeError(message)


def _validate_server_socket_path(path: Path) -> None:
    """Reject unsafe replacement or traversal targets before binding a socket."""
    if not path.is_absolute() or path.exists() or path.is_symlink():
        message = "PDF worker socket path is invalid"
        raise RuntimeError(message)
    parent = path.parent
    parent_metadata = parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or parent_metadata.st_mode & 0o077
    ):
        message = "PDF worker socket directory is invalid"
        raise RuntimeError(message)


def _set_private_socket_mode(path: Path) -> None:
    """Constrain the newly created endpoint to its owner before accepting peers."""
    path.chmod(0o600)


def _remove_socket(path: Path) -> None:
    """Remove only the server-created socket during ordinary worker shutdown."""
    with suppress(FileNotFoundError):
        path.unlink()


async def _serve_one_unix_request(
    reader: StreamReader,
    writer: StreamWriter,
    *,
    root: Path,
    max_bytes: int,
    settings: PdfProcessorSettings,
) -> None:
    """Process one EOF-delimited request and never leave a framing ambiguity."""
    try:
        _verified_unix_peer(writer)
        command = await _read_socket_command(reader)
        try:
            result: PdfResult = _execute(
                command,
                _request_root(root, command),
                max_bytes=max_bytes,
                settings=settings,
            )
        except Exception as exc:  # noqa: BLE001 - sanitize all parser failures.
            result = _failure(command, exc)
        writer.write(encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES))
        await writer.drain()
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()


async def _serve_unix_socket(
    path: Path,
    *,
    root: Path,
    max_bytes: int,
    settings: PdfProcessorSettings,
) -> None:
    """Serve a new authenticated connection for every parent request."""
    _validate_server_socket_path(path)
    server = await asyncio.start_unix_server(
        lambda reader, writer: _serve_one_unix_request(
            reader,
            writer,
            root=root,
            max_bytes=max_bytes,
            settings=settings,
        ),
        path=str(path),
    )
    _set_private_socket_mode(path)
    try:
        async with server:
            await server.serve_forever()
    finally:
        _remove_socket(path)


def main(argv: list[str] | None = None) -> int:
    """Execute exactly one command and emit exactly one result frame."""
    parser = argparse.ArgumentParser(add_help=False)
    _ = parser.add_argument("--unix-socket", type=Path)
    options = cast("_WorkerOptions", parser.parse_args(argv))
    _ = os.umask(0o077)
    max_bytes = _apply_resource_limits()
    settings = _processor_settings()
    root = _work_root()
    if options.unix_socket is not None:
        _ = asyncio.run(
            _serve_unix_socket(
                options.unix_socket,
                root=root,
                max_bytes=max_bytes,
                settings=settings,
            )
        )
        return 0
    command = _read_command()
    result: PdfResult
    try:
        result = _execute(
            command,
            root,
            max_bytes=max_bytes,
            settings=settings,
        )
    except Exception as exc:  # noqa: BLE001 - sanitize every worker failure.
        result = _failure(command, exc)
    frame = encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES)
    output_stream = cast("BinaryIO", sys.stdout.buffer)
    _ = output_stream.write(frame)
    output_stream.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
