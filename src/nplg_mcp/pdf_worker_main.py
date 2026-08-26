# Copyright (c) 2026 David Osipov
"""Single-request, resource-constrained PDF worker entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import resource
import select
import signal
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
    parse_result_frame,
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
_PRIVATE_SOCKET_DIRECTORY_MODE = 0o700
_PRIVATE_SOCKET_ENDPOINT_MODE = 0o600
_DEFAULT_JOB_TIMEOUT_SECONDS = 30.0
_COMMAND_READ_TIMEOUT_SECONDS = 1.0
_JOB_TIMEOUT_GRACE_SECONDS = 1.0
_JOB_TERMINATION_GRACE_SECONDS = 0.25
_JOB_GROUP_POLL_SECONDS = 0.01
_JOB_EXIT_POLL_SECONDS = 0.01
_PEER_DISCONNECT_POLL_SECONDS = 0.01
_MAX_JOB_STDERR_BYTES = 65_536
_DESCRIPTOR_INHERITABLE = False

if TYPE_CHECKING:
    from asyncio import StreamReader, StreamWriter
    from asyncio.subprocess import Process


@runtime_checkable
class _UnixSocketPeer(Protocol):
    """The narrow socket capability required for local peer verification."""

    family: socket.AddressFamily

    def getsockopt(self, level: int, option: int, buffer_size: int) -> bytes:
        """Return the fixed-width peer-credential record."""
        ...


@runtime_checkable
class _FileDescriptorPeer(Protocol):
    """Socket-like capability required only while watching peer lifetime."""

    def fileno(self) -> int:
        """Return the live connection descriptor."""
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


@dataclass(frozen=True, slots=True)
class _SocketEndpointIdentity:
    """Stable filesystem identity for exactly one bound Unix endpoint."""

    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int
    link_count: int
    change_time_ns: int


@dataclass(frozen=True, slots=True)
class _JobResourceLimits:
    """Validated resource ceilings inherited and reset by every job child."""

    cpu_seconds: int
    address_space_bytes: int
    file_size_bytes: int
    open_files: int
    processes: int


@dataclass(frozen=True, slots=True)
class _JobLaunchOptions:
    """Disposable executable and hard wall-clock ceiling for Unix jobs."""

    worker_argv: tuple[str, ...]
    timeout_seconds: float


@dataclass(frozen=True, slots=True)
class _JobExecutionContext:
    """Complete immutable policy passed to each authenticated connection."""

    root: Path
    max_bytes: int
    settings: PdfProcessorSettings
    worker_argv: tuple[str, ...]
    timeout_seconds: float


class _PeerDisconnectedError(RuntimeError):
    """The authenticated caller abandoned a still-running disposable job."""


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


def _configured_resource_limits() -> _JobResourceLimits:
    """Validate every process ceiling without constraining the supervisor."""
    return _JobResourceLimits(
        cpu_seconds=_configured_integer("NPLG_PDF_CPU_SECONDS"),
        address_space_bytes=_configured_integer("NPLG_PDF_ADDRESS_SPACE_BYTES"),
        file_size_bytes=_configured_integer("NPLG_PDF_FILE_SIZE_BYTES"),
        open_files=_configured_integer("NPLG_PDF_OPEN_FILES"),
        processes=_configured_integer("NPLG_PDF_PROCESSES"),
    )


def _apply_resource_limits(limits: _JobResourceLimits | None = None) -> int:
    """Apply hard ceilings before importing PDFium or reading a request."""
    configured = limits or _configured_resource_limits()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (configured.cpu_seconds, configured.cpu_seconds),
    )
    resource.setrlimit(
        resource.RLIMIT_AS,
        (configured.address_space_bytes, configured.address_space_bytes),
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (configured.file_size_bytes, configured.file_size_bytes),
    )
    resource.setrlimit(
        resource.RLIMIT_NOFILE,
        (configured.open_files, configured.open_files),
    )
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(
            resource.RLIMIT_NPROC,
            (configured.processes, configured.processes),
        )
    return configured.file_size_bytes


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


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare the immutable parent-directory identity used by this process."""
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_uid,
        left.st_gid,
        left.st_nlink,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_uid,
        right.st_gid,
        right.st_nlink,
        right.st_ctime_ns,
    )


def _require_private_socket_parent(
    before: os.stat_result,
    opened: os.stat_result,
    after: os.stat_result,
) -> None:
    """Require a stable exact-mode directory owned by this process identity."""
    if (
        not _same_file_identity(before, opened)
        or not _same_file_identity(opened, after)
        or not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != _PRIVATE_SOCKET_DIRECTORY_MODE
        or opened.st_uid != os.geteuid()
        or opened.st_gid != os.getegid()
    ):
        message = "PDF worker socket directory is invalid"
        raise RuntimeError(message)


def _require_unused_socket_name(parent_descriptor: int, name: str) -> None:
    """Require an absent final entry without following a dangling symlink."""
    try:
        _ = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        message = "PDF worker socket path is invalid"
        raise RuntimeError(message) from exc
    message = "PDF worker socket path is invalid"
    raise RuntimeError(message)


def _open_server_socket_parent(path: Path) -> int:
    """Open one private owned parent and reject path substitution."""
    if not path.is_absolute() or path.name in {"", ".", ".."} or ".." in path.parts:
        message = "PDF worker socket path is invalid"
        raise RuntimeError(message)
    directory_flag = cast("object", getattr(os, "O_DIRECTORY", None))
    nofollow_flag = cast("object", getattr(os, "O_NOFOLLOW", None))
    cloexec_flag = cast("object", getattr(os, "O_CLOEXEC", None))
    if any(
        type(flag) is not int for flag in (directory_flag, nofollow_flag, cloexec_flag)
    ):
        message = "PDF worker socket directory protection is unavailable"
        raise RuntimeError(message)
    directory_flag = cast("int", directory_flag)
    nofollow_flag = cast("int", nofollow_flag)
    cloexec_flag = cast("int", cloexec_flag)
    flags = os.O_RDONLY | directory_flag | nofollow_flag | cloexec_flag
    parent = path.parent
    try:
        before = parent.lstat()
        descriptor = os.open(parent, flags)
    except OSError as exc:
        message = "PDF worker socket directory is invalid"
        raise RuntimeError(message) from exc
    try:
        opened = os.fstat(descriptor)
        after = parent.lstat()
        _require_private_socket_parent(before, opened, after)
        _require_unused_socket_name(descriptor, path.name)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _validate_server_socket_path(path: Path) -> int:
    """Return a validated parent descriptor for one unused socket path."""
    return _open_server_socket_parent(path)


def _endpoint_identity(parent_descriptor: int, name: str) -> _SocketEndpointIdentity:
    """Capture one endpoint without following a replacement symlink."""
    try:
        metadata = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        message = "PDF worker socket endpoint is invalid"
        raise RuntimeError(message) from exc
    return _SocketEndpointIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        owner_uid=metadata.st_uid,
        owner_gid=metadata.st_gid,
        link_count=metadata.st_nlink,
        change_time_ns=metadata.st_ctime_ns,
    )


def _require_private_socket(identity: _SocketEndpointIdentity) -> None:
    """Accept only the socket created privately for this worker identity."""
    if (
        not stat.S_ISSOCK(identity.mode)
        or stat.S_IMODE(identity.mode) != _PRIVATE_SOCKET_ENDPOINT_MODE
        or identity.owner_uid != os.geteuid()
        or identity.owner_gid != os.getegid()
        or identity.link_count != 1
    ):
        message = "PDF worker socket endpoint is invalid"
        raise RuntimeError(message)


def _remove_server_socket(
    parent_descriptor: int,
    name: str,
    expected: _SocketEndpointIdentity,
) -> None:
    """Unlink only the exact bound inode; preserve every replacement."""
    try:
        current = _endpoint_identity(parent_descriptor, name)
    except RuntimeError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return
        raise
    if current != expected:
        message = "PDF worker socket endpoint identity changed"
        raise RuntimeError(message)
    os.unlink(name, dir_fd=parent_descriptor)


def _validated_job_argv(worker_argv: tuple[str, ...] | None) -> tuple[str, ...]:
    """Return one absolute executable command for disposable job children."""
    argv = (
        (sys.executable, "-m", "nplg_mcp.pdf_worker_main")
        if worker_argv is None
        else worker_argv
    )
    if not argv or any(
        type(value) is not str or not value or "\x00" in value for value in argv
    ):
        message = "PDF job worker argv is invalid"
        raise RuntimeError(message)
    executable = Path(argv[0])
    if (
        not executable.is_absolute()
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
    ):
        message = "PDF job worker argv is invalid"
        raise RuntimeError(message)
    return argv


def _job_environment(
    work_root: Path,
    execution: _JobExecutionContext,
) -> dict[str, str]:
    """Forward only reviewed worker policy values to one disposable child."""
    environment = {
        name: os.environ[name] for name in _LIMIT_ENVIRON if name in os.environ
    }
    settings = execution.settings
    environment.update(
        {
            "LANG": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "PYTHONUTF8": "1",
            "NPLG_PDF_WORK_ROOT": str(work_root),
            "NPLG_PDF_FILE_SIZE_BYTES": str(execution.max_bytes),
            "NPLG_PDF_MAX_PAGES_PER_RENDER": str(settings.max_pages_per_render),
            "NPLG_PDF_MAX_PAGE_PIXELS": str(settings.max_page_pixels),
            "NPLG_PDF_MAX_RENDER_PIXELS": str(settings.max_render_pixels),
            "NPLG_PDF_FALLBACK_DPI": str(settings.fallback_dpi),
            "NPLG_PDF_TILE_WIDTH": str(settings.tile_width),
            "NPLG_PDF_TILE_HEIGHT": str(settings.tile_height),
            "NPLG_PDF_TILE_OVERLAP": str(settings.tile_overlap),
            "NPLG_PDF_MAX_TILES_PER_PAGE": str(settings.max_tiles_per_page),
        }
    )
    return environment


async def _write_job_command(stream: StreamWriter, command: PdfCommand) -> None:
    """Write and close exactly one bounded command frame."""
    stream.write(encode_frame(command, maximum=MAX_COMMAND_FRAME_BYTES))
    await stream.drain()
    stream.close()
    with suppress(BrokenPipeError, ConnectionResetError):
        await stream.wait_closed()


async def _read_job_result(stream: StreamReader) -> PdfResult:
    """Read one bounded EOF-terminated result from a disposable job."""
    prefix = await stream.readexactly(_FRAME_PREFIX_BYTES)
    size = int.from_bytes(prefix, "big")
    if size < 1 or size > MAX_RESULT_FRAME_BYTES:
        message = "PDF job result length is outside the allowed range"
        raise RuntimeError(message)
    body = await stream.readexactly(size)
    if await stream.read(1):
        message = "PDF job emitted trailing output"
        raise RuntimeError(message)
    return parse_result_frame(body)


async def _read_job_stderr(stream: StreamReader) -> None:
    """Drain stderr without allowing a child-controlled memory sink."""
    total = 0
    while chunk := await stream.read(8_192):
        total += len(chunk)
        if total > _MAX_JOB_STDERR_BYTES:
            message = "PDF job stderr exceeded its limit"
            raise RuntimeError(message)


async def _require_job_success(process: Process) -> None:
    """Turn a nonzero leader exit into an immediately observable task failure."""
    while process.returncode is None:  # noqa: ASYNC110 - wait() is pipe-coupled.
        await asyncio.sleep(_JOB_EXIT_POLL_SECONDS)
    if process.returncode != 0:
        message = "PDF job exited unsuccessfully"
        raise RuntimeError(message)


async def _communicate_with_job(
    process: Process,
    command: PdfCommand,
) -> PdfResult:
    """Exchange strict frames while concurrently bounding both output pipes."""
    if process.stdin is None or process.stdout is None or process.stderr is None:
        message = "PDF job process pipes are unavailable"
        raise RuntimeError(message)
    write_task = asyncio.create_task(_write_job_command(process.stdin, command))
    result_task = asyncio.create_task(_read_job_result(process.stdout))
    stderr_task = asyncio.create_task(_read_job_stderr(process.stderr))
    wait_task = asyncio.create_task(_require_job_success(process))
    tasks = (write_task, result_task, stderr_task, wait_task)
    object_tasks = tuple(cast("asyncio.Task[object]", task) for task in tasks)
    try:
        pending = set(object_tasks)
        while pending:
            completed, pending = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_EXCEPTION,
            )
            for completed_task in completed:
                exception = completed_task.exception()
                if exception is not None:
                    raise exception
        await write_task
        await stderr_task
        await wait_task
        return await result_task
    finally:
        for task in object_tasks:
            if not task.done():
                _ = task.cancel()
        for task in object_tasks:
            with suppress(
                asyncio.CancelledError,
                OSError,
                RuntimeError,
                ValueError,
            ):
                _ = await task


async def _wait_for_peer_disconnect(writer: StreamWriter) -> None:
    """Distinguish the framing half-close from a full peer disconnect."""
    peer = cast("object", writer.get_extra_info("socket"))
    if not isinstance(peer, _FileDescriptorPeer):
        pending: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        await pending
        return
    descriptor = os.dup(peer.fileno())
    try:
        os.set_inheritable(descriptor, _DESCRIPTOR_INHERITABLE)
        poller = select.poll()
        poller.register(
            descriptor,
            select.POLLHUP | select.POLLERR | select.POLLNVAL,
        )
        while True:
            events = poller.poll(0)
            if any(
                flags & (select.POLLHUP | select.POLLERR | select.POLLNVAL)
                for _file_descriptor, flags in events
            ):
                return
            await asyncio.sleep(_PEER_DISCONNECT_POLL_SECONDS)
    finally:
        os.close(descriptor)


async def _wait_for_job_group_exit(process_group: int) -> None:
    expires_at = asyncio.get_running_loop().time() + _JOB_TERMINATION_GRACE_SECONDS
    while True:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return
        if asyncio.get_running_loop().time() >= expires_at:
            message = "PDF job process group survived termination"
            raise RuntimeError(message)
        await asyncio.sleep(_JOB_GROUP_POLL_SECONDS)


async def _terminate_job_process_group(process: Process) -> None:
    """Signal, kill, and reap one child group under a bounded grace period."""
    process_group = process.pid
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGTERM)
    with suppress(TimeoutError):
        async with asyncio.timeout(_JOB_TERMINATION_GRACE_SECONDS):
            _ = await process.wait()
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGKILL)
    if process.returncode is None:
        _ = await process.wait()
    await _wait_for_job_group_exit(process_group)


async def _wait_for_job_cleanup(cleanup: asyncio.Task[None]) -> None:
    """Complete reaping even when a caller repeats task cancellation."""
    cancellation: asyncio.CancelledError | None = None
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as exc:
            cancellation = exc
    cleanup.result()
    if cancellation is not None:
        raise cancellation


async def _abort_job_spawn(
    spawn: asyncio.Task[Process],
    disconnected: asyncio.Task[None],
) -> None:
    """Cancel an incomplete launch and reap any concurrently transferred child."""
    if not spawn.done():
        _ = spawn.cancel()
    if not disconnected.done():
        _ = disconnected.cancel()
    process: Process | None = None
    with suppress(
        asyncio.CancelledError,
        OSError,
        RuntimeError,
        ValueError,
    ):
        process = await spawn
    with suppress(asyncio.CancelledError, OSError, RuntimeError, ValueError):
        await disconnected
    if process is not None:
        await _terminate_job_process_group(process)


def _require_spawned_process(process: Process | None) -> Process:
    """Reject an impossible launch result before transferring ownership."""
    if process is None:
        message = "PDF job process ownership was not transferred"
        raise RuntimeError(message)
    return process


async def _launch_disposable_job(
    work_root: Path,
    writer: StreamWriter,
    *,
    execution: _JobExecutionContext,
    expires_at: float,
) -> tuple[Process, asyncio.Task[None]]:
    """Transfer one child handle before returning its live peer watcher."""
    process: Process | None = None
    spawn = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *execution.worker_argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/",
            env=_job_environment(work_root, execution),
            shell=False,
            start_new_session=True,
            close_fds=True,
        )
    )
    disconnected = asyncio.create_task(_wait_for_peer_disconnect(writer))
    try:
        try:
            async with asyncio.timeout_at(expires_at):
                launch_completed, _launch_pending = await asyncio.wait(
                    {spawn, disconnected},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if disconnected in launch_completed:
                    disconnected.result()
                    raise _PeerDisconnectedError
                process = spawn.result()
        finally:
            if process is None:
                cleanup = asyncio.create_task(_abort_job_spawn(spawn, disconnected))
                await _wait_for_job_cleanup(cleanup)
    except TimeoutError as exc:
        message = "PDF job exceeded its hard wall-clock timeout"
        raise TimeoutError(message) from exc
    return _require_spawned_process(process), disconnected


async def _run_disposable_job(
    command: PdfCommand,
    work_root: Path,
    writer: StreamWriter,
    *,
    execution: _JobExecutionContext,
) -> PdfResult:
    """Run one PDF operation in a fresh, always-reaped OS process group."""
    process: Process | None = None
    expires_at = asyncio.get_running_loop().time() + execution.timeout_seconds
    try:
        process, disconnected = await _launch_disposable_job(
            work_root,
            writer,
            execution=execution,
            expires_at=expires_at,
        )
        remaining = expires_at - asyncio.get_running_loop().time()
        if remaining <= 0.0:
            message = "PDF job exceeded its hard wall-clock timeout"
            raise TimeoutError(message)
        communication = asyncio.create_task(_communicate_with_job(process, command))
        tasks = {communication, disconnected}
        try:
            async with asyncio.timeout(remaining):
                job_completed, _job_pending = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if disconnected in job_completed:
                    raise _PeerDisconnectedError
                return communication.result()
        finally:
            object_tasks = tuple(cast("asyncio.Task[object]", task) for task in tasks)
            for task in object_tasks:
                if not task.done():
                    _ = task.cancel()
            for task in object_tasks:
                with suppress(
                    asyncio.CancelledError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ):
                    _ = await task
    finally:
        if process is not None:
            cleanup = asyncio.create_task(_terminate_job_process_group(process))
            await _wait_for_job_cleanup(cleanup)


async def _serve_one_unix_request(
    reader: StreamReader,
    writer: StreamWriter,
    *,
    execution: _JobExecutionContext,
) -> None:
    """Process one EOF-delimited request and never leave a framing ambiguity."""
    try:
        _verified_unix_peer(writer)
        try:
            async with asyncio.timeout(_COMMAND_READ_TIMEOUT_SECONDS):
                command = await _read_socket_command(reader)
        except TimeoutError:
            return
        except (asyncio.IncompleteReadError, OSError, RuntimeError, ValueError):
            # An authenticated local peer still controls every frame byte.  Treat
            # expected framing/schema rejection as a silent protocol close so the
            # event loop never logs attacker-controlled exception details.
            return
        try:
            result: PdfResult = await _run_disposable_job(
                command,
                _request_root(execution.root, command),
                writer,
                execution=execution,
            )
        except _PeerDisconnectedError:
            return
        except Exception as exc:  # noqa: BLE001 - sanitize all parser failures.
            result = _failure(command, exc)
        try:
            writer.write(encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES))
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            return
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
    job_options: _JobLaunchOptions | None = None,
) -> None:
    """Serve a new authenticated connection for every parent request."""
    selected_options = job_options or _JobLaunchOptions(
        worker_argv=(sys.executable, "-m", "nplg_mcp.pdf_worker_main"),
        timeout_seconds=_DEFAULT_JOB_TIMEOUT_SECONDS,
    )
    job_argv = _validated_job_argv(selected_options.worker_argv)
    timeout_seconds = selected_options.timeout_seconds
    if (
        type(timeout_seconds) is not float
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0.0
    ):
        message = "PDF job timeout is invalid"
        raise RuntimeError(message)
    execution = _JobExecutionContext(
        root=root,
        max_bytes=max_bytes,
        settings=settings,
        worker_argv=job_argv,
        timeout_seconds=timeout_seconds,
    )
    parent_descriptor = _validate_server_socket_path(path)
    server: asyncio.Server | None = None
    endpoint_identity: _SocketEndpointIdentity | None = None
    try:
        binding_path = f"/proc/self/fd/{parent_descriptor}/{path.name}"

        async def serve_connection(
            reader: StreamReader,
            writer: StreamWriter,
        ) -> None:
            await _serve_one_unix_request(
                reader,
                writer,
                execution=execution,
            )

        previous_umask = os.umask(0o177)
        try:
            if sys.version_info >= (3, 13):
                server = await asyncio.start_unix_server(
                    serve_connection,
                    path=binding_path,
                    start_serving=False,
                    cleanup_socket=False,
                )
            else:
                server = await asyncio.start_unix_server(
                    serve_connection,
                    path=binding_path,
                    start_serving=False,
                )
        finally:
            _ = os.umask(previous_umask)
        observed_identity = _endpoint_identity(parent_descriptor, path.name)
        if stat.S_ISSOCK(observed_identity.mode):
            endpoint_identity = observed_identity
        _require_private_socket(observed_identity)
        async with server:
            await server.serve_forever()
    finally:
        try:
            if server is not None:
                server.close()
                await server.wait_closed()
        finally:
            try:
                if endpoint_identity is not None:
                    _remove_server_socket(
                        parent_descriptor,
                        path.name,
                        endpoint_identity,
                    )
            finally:
                os.close(parent_descriptor)


def main(argv: list[str] | None = None) -> int:
    """Execute exactly one command and emit exactly one result frame."""
    parser = argparse.ArgumentParser(add_help=False)
    _ = parser.add_argument("--unix-socket", type=Path)
    options = cast("_WorkerOptions", parser.parse_args(argv))
    _ = os.umask(0o077)
    limits = _configured_resource_limits()
    settings = _processor_settings()
    root = _work_root()
    if options.unix_socket is not None:
        _ = asyncio.run(
            _serve_unix_socket(
                options.unix_socket,
                root=root,
                max_bytes=limits.file_size_bytes,
                settings=settings,
                job_options=_JobLaunchOptions(
                    worker_argv=(
                        sys.executable,
                        "-m",
                        "nplg_mcp.pdf_worker_main",
                    ),
                    timeout_seconds=(
                        float(limits.cpu_seconds) + _JOB_TIMEOUT_GRACE_SECONDS
                    ),
                ),
            )
        )
        return 0
    max_bytes = _apply_resource_limits(limits)
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
