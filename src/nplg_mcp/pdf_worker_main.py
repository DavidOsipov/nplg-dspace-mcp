# Copyright (c) 2026 David Osipov
"""Single-request, resource-constrained PDF worker entry point."""

from __future__ import annotations

import json
import os
import resource
import sys
from pathlib import Path
from typing import BinaryIO, cast

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


def main() -> int:
    """Execute exactly one command and emit exactly one result frame."""
    _ = os.umask(0o077)
    max_bytes = _apply_resource_limits()
    settings = _processor_settings()
    root = _work_root()
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
