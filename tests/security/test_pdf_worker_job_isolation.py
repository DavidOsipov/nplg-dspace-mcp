# Copyright (c) 2026 David Osipov
"""Adversarial lifecycle tests for disposable Unix PDF worker jobs."""

from __future__ import annotations

import asyncio
import os
import resource
import socket
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast
from uuid import UUID

import pytest

import nplg_mcp.pdf_worker_main as worker_main_module
from nplg_mcp.errors import ErrorCode
from nplg_mcp.pdf_executor import PdfProcessorSettings
from nplg_mcp.pdf_ipc import (
    MAX_COMMAND_FRAME_BYTES,
    MAX_RESULT_FRAME_BYTES,
    InspectCommand,
    InspectParams,
    PdfCommand,
    PdfFailure,
    PdfResult,
    PdfSuccess,
    PublicWorkerError,
    RenderPagesCommand,
    RenderPagesParams,
    encode_frame,
    parse_result_frame,
)
from nplg_mcp.storage import ContentAddressedStore
from tests.helpers.pdf_factory import make_raster_pdf

if TYPE_CHECKING:
    from asyncio.subprocess import Process


class _ServeUnixSocket(Protocol):
    async def __call__(
        self,
        path: Path,
        *,
        root: Path,
        max_bytes: int,
        settings: PdfProcessorSettings,
        job_options: object | None = None,
    ) -> None: ...


class _JobOptionsFactory(Protocol):
    def __call__(
        self,
        *,
        worker_argv: tuple[str, ...],
        timeout_seconds: float,
    ) -> object: ...


class _JobExecutionContextFactory(Protocol):
    def __call__(
        self,
        *,
        root: Path,
        max_bytes: int,
        settings: PdfProcessorSettings,
        worker_argv: tuple[str, ...],
        timeout_seconds: float,
    ) -> object: ...


class _RunDisposableJob(Protocol):
    async def __call__(
        self,
        command: InspectCommand,
        work_root: Path,
        writer: object,
        *,
        execution: object,
    ) -> PdfResult: ...


class _WaitForPeerDisconnect(Protocol):
    async def __call__(self, writer: object) -> None: ...


class _ReadJobResult(Protocol):
    async def __call__(self, stream: asyncio.StreamReader) -> PdfResult: ...


class _ReadJobStderr(Protocol):
    async def __call__(self, stream: asyncio.StreamReader) -> None: ...


class _WaitForJobCleanup(Protocol):
    async def __call__(self, cleanup: asyncio.Task[None]) -> None: ...


class _CreateSubprocess(Protocol):
    async def __call__(self, *argv: str, **options: object) -> Process: ...


_WORKER_NAMESPACE = cast(
    "dict[str, object]",
    cast("object", worker_main_module.__dict__),
)
_SERVE_UNIX_SOCKET = cast(
    "_ServeUnixSocket",
    _WORKER_NAMESPACE["_serve_unix_socket"],
)
_JOB_OPTIONS = cast(
    "_JobOptionsFactory",
    _WORKER_NAMESPACE["_JobLaunchOptions"],
)
_JOB_EXECUTION_CONTEXT = cast(
    "_JobExecutionContextFactory",
    _WORKER_NAMESPACE["_JobExecutionContext"],
)
_RUN_DISPOSABLE_JOB = cast(
    "_RunDisposableJob",
    _WORKER_NAMESPACE["_run_disposable_job"],
)
_WAIT_FOR_PEER_DISCONNECT = cast(
    "_WaitForPeerDisconnect",
    _WORKER_NAMESPACE["_wait_for_peer_disconnect"],
)
_READ_JOB_RESULT = cast(
    "_ReadJobResult",
    _WORKER_NAMESPACE["_read_job_result"],
)
_READ_JOB_STDERR = cast(
    "_ReadJobStderr",
    _WORKER_NAMESPACE["_read_job_stderr"],
)
_WAIT_FOR_JOB_CLEANUP = cast(
    "_WaitForJobCleanup",
    _WORKER_NAMESPACE["_wait_for_job_cleanup"],
)
_FRAME_PREFIX_BYTES = 4
_JOB_STDERR_LIMIT_BYTES = 65_536
_JOB_TIMEOUT_SECONDS = 1.0
_SPAWN_WINDOW_TIMEOUT_SECONDS = 0.05
_SPAWN_TEST_WATCHDOG_SECONDS = 0.5
_SPAWN_PROMPT_BOUND_SECONDS = 0.25
_CRASH_PROMPT_BOUND_SECONDS = 0.75
_COMMAND_FRAME_TEST_TIMEOUT_SECONDS = 0.05
_COMMAND_FRAME_CLOSE_BOUND_SECONDS = 0.25
_PROCESS_WAIT_SECONDS = 2.0
_EXPECTED_JOB_COUNT = 2
_EXPECTED_CPU_SECONDS = 30
_EXPECTED_ADDRESS_SPACE_BYTES = 1_073_741_824
_EXPECTED_FILE_SIZE_BYTES = 536_870_912
_EXPECTED_OPEN_FILES = 64
_EXPECTED_PROCESSES = 8


def _worker_environment(root: Path) -> dict[str, str]:
    return {
        "NPLG_PDF_WORK_ROOT": str(root),
        "NPLG_PDF_CPU_SECONDS": str(_EXPECTED_CPU_SECONDS),
        "NPLG_PDF_ADDRESS_SPACE_BYTES": str(_EXPECTED_ADDRESS_SPACE_BYTES),
        "NPLG_PDF_FILE_SIZE_BYTES": str(_EXPECTED_FILE_SIZE_BYTES),
        "NPLG_PDF_OPEN_FILES": str(_EXPECTED_OPEN_FILES),
        "NPLG_PDF_PROCESSES": str(_EXPECTED_PROCESSES),
        "NPLG_PDF_MAX_PAGES_PER_RENDER": "8",
        "NPLG_PDF_MAX_PAGE_PIXELS": "120000000",
        "NPLG_PDF_MAX_RENDER_PIXELS": "480000000",
        "NPLG_PDF_FALLBACK_DPI": "400",
        "NPLG_PDF_TILE_WIDTH": "2048",
        "NPLG_PDF_TILE_HEIGHT": "2048",
        "NPLG_PDF_TILE_OVERLAP": "128",
        "NPLG_PDF_MAX_TILES_PER_PAGE": "100",
    }


def _apply_worker_environment(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
) -> None:
    for name, value in _worker_environment(root).items():
        monkeypatch.setenv(name, value)


def _stage_inspect(
    root: Path,
    request_value: int,
    source_bytes: bytes,
) -> InspectCommand:
    request_id = UUID(int=request_value)
    job_root = root / request_id.hex
    job_root.mkdir(mode=0o700)
    store = ContentAddressedStore(job_root / "cache")
    artifact = store.put_bytes(
        source_bytes,
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    return InspectCommand(
        request_id=request_id,
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )


def _stage_render_pages(
    root: Path,
    request_value: int,
    source_bytes: bytes,
) -> RenderPagesCommand:
    request_id = UUID(int=request_value)
    job_root = root / request_id.hex
    job_root.mkdir(mode=0o700)
    store = ContentAddressedStore(job_root / "cache")
    artifact = store.put_bytes(
        source_bytes,
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    return RenderPagesCommand(
        request_id=request_id,
        operation="render_pages",
        source_relative_path=artifact.relative_path,
        parameters=RenderPagesParams(pages=(1,), mode="native"),
    )


def _wait_for_path(path: Path) -> None:
    expires_at = time.monotonic() + _PROCESS_WAIT_SECONDS
    while not path.exists():
        if time.monotonic() >= expires_at:
            message = f"timed out waiting for {path.name}"
            raise TimeoutError(message)
        time.sleep(0.01)


async def _wait_for_socket(path: Path, task: asyncio.Task[None]) -> None:
    await asyncio.to_thread(_wait_for_path, path)
    if task.done():
        task.result()


async def _exchange(path: Path, command: PdfCommand) -> PdfResult:
    reader, writer = await asyncio.open_unix_connection(str(path))
    try:
        writer.write(encode_frame(command, maximum=MAX_COMMAND_FRAME_BYTES))
        await writer.drain()
        writer.write_eof()
        await writer.drain()
        prefix = await reader.readexactly(_FRAME_PREFIX_BYTES)
        size = int.from_bytes(prefix, "big")
        body = await reader.readexactly(size)
        assert await reader.read(1) == b""
        return parse_result_frame(body)
    finally:
        writer.close()
        await writer.wait_closed()


def _unchecked_frame(body: bytes) -> bytes:
    """Frame adversarial bytes without passing them through the trusted encoder."""
    return len(body).to_bytes(_FRAME_PREFIX_BYTES, "big") + body


async def _send_untrusted_frame(path: Path, frame: bytes) -> None:
    reader, writer = await asyncio.open_unix_connection(str(path))
    try:
        writer.write(frame)
        await writer.drain()
        writer.write_eof()
        await writer.drain()
        assert (
            await asyncio.wait_for(
                reader.read(1),
                timeout=_COMMAND_FRAME_CLOSE_BOUND_SECONDS,
            )
            == b""
        )
    finally:
        writer.close()
        await writer.wait_closed()


def _wait_for_process_file(path: Path, expected: int) -> tuple[int, ...]:
    expires_at = time.monotonic() + _PROCESS_WAIT_SECONDS
    while True:
        try:
            values = tuple(
                int(value) for value in path.read_text(encoding="ascii").splitlines()
            )
        except FileNotFoundError:
            values = ()
        if len(values) == expected:
            return values
        if time.monotonic() >= expires_at:
            message = f"timed out waiting for {path.name}"
            raise TimeoutError(message)
        time.sleep(0.01)


async def _read_processes(path: Path, *, expected: int) -> tuple[int, ...]:
    return await asyncio.to_thread(_wait_for_process_file, path, expected)


def _process_is_gone(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return True
    return False


def _wait_for_resource_limits(
    process_id: int,
    expected: tuple[tuple[int, tuple[int, int]], ...],
) -> tuple[tuple[int, int], ...]:
    expires_at = time.monotonic() + _PROCESS_WAIT_SECONDS
    wanted = tuple(value for _limit, value in expected)
    while True:
        current = tuple(
            resource.prlimit(process_id, limit) for limit, _value in expected
        )
        if current == wanted:
            return current
        if time.monotonic() >= expires_at:
            message = "disposable PDF resource limits were not applied"
            raise TimeoutError(message)
        time.sleep(0.005)


def _wait_for_processes_gone(processes: tuple[int, ...]) -> None:
    expires_at = time.monotonic() + _PROCESS_WAIT_SECONDS
    while not all(_process_is_gone(process) for process in processes):
        if time.monotonic() >= expires_at:
            message = "disposable PDF process group survived cleanup"
            raise TimeoutError(message)
        time.sleep(0.01)


async def _require_processes_gone(processes: tuple[int, ...]) -> None:
    await asyncio.to_thread(_wait_for_processes_gone, processes)


async def _stop_server(task: asyncio.Task[None]) -> None:
    _ = task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def _scenario_argv(probe_root: Path) -> tuple[str, ...]:
    fixture = Path(__file__).parents[1] / "fixtures" / "pdf_worker_job_scenarios.py"
    return (sys.executable, str(fixture), str(probe_root))


def _stream_reader(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


class _NonPollableWriter:
    """Minimal peer used when cancellation, not disconnect, drives cleanup."""

    @staticmethod
    def get_extra_info(_name: str) -> object:
        return object()


class _DescriptorPeer:
    def __init__(self, descriptor: int) -> None:
        super().__init__()
        self._descriptor = descriptor

    def fileno(self) -> int:
        return self._descriptor


class _PollableWriter:
    def __init__(self, descriptor: int) -> None:
        super().__init__()
        self._peer = _DescriptorPeer(descriptor)

    def get_extra_info(self, _name: str) -> object:
        return self._peer


async def _start_server(
    *,
    root: Path,
    socket_path: Path,
    worker_argv: tuple[str, ...] | None = None,
    job_timeout_seconds: float | None = None,
) -> asyncio.Task[None]:
    job_options: object | None = None
    if worker_argv is not None or job_timeout_seconds is not None:
        if worker_argv is None or job_timeout_seconds is None:
            message = "test job options must be complete"
            raise ValueError(message)
        job_options = _JOB_OPTIONS(
            worker_argv=worker_argv,
            timeout_seconds=job_timeout_seconds,
        )
    task = asyncio.create_task(
        _SERVE_UNIX_SOCKET(
            socket_path,
            root=root,
            max_bytes=_EXPECTED_FILE_SIZE_BYTES,
            settings=PdfProcessorSettings(),
            job_options=job_options,
        )
    )
    await _wait_for_socket(socket_path, task)
    return task


@pytest.mark.asyncio
async def test_unix_job_timeout_reaps_process_group_before_next_success(
    tmp_path: Path,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    socket_parent = tmp_path / "socket"
    socket_parent.mkdir(mode=0o700)
    probe_root = tmp_path / "probes"
    probe_root.mkdir(mode=0o700)
    source = b"%PDF-1.7\njob-isolation-fixture"
    timeout_command = _stage_inspect(root, 1, source)
    success_command = _stage_inspect(root, 3, source)
    socket_path = socket_parent / "worker.sock"
    server = await _start_server(
        root=root,
        socket_path=socket_path,
        worker_argv=_scenario_argv(probe_root),
        job_timeout_seconds=_JOB_TIMEOUT_SECONDS,
    )
    try:
        timed_out = await _exchange(socket_path, timeout_command)
        processes = await _read_processes(
            probe_root / f"{timeout_command.request_id.hex}.pids",
            expected=2,
        )
        await _require_processes_gone(processes)
        recovered = await _exchange(socket_path, success_command)
    finally:
        await _stop_server(server)

    assert isinstance(timed_out, PdfFailure)
    assert isinstance(recovered, PdfSuccess)


@pytest.mark.asyncio
async def test_partial_command_frame_is_closed_before_next_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    socket_parent = tmp_path / "socket"
    socket_parent.mkdir(mode=0o700)
    probe_root = tmp_path / "probes"
    probe_root.mkdir(mode=0o700)
    source = b"%PDF-1.7\npartial-frame-fixture"
    success_command = _stage_inspect(root, 16, source)
    socket_path = socket_parent / "worker.sock"
    monkeypatch.setitem(
        _WORKER_NAMESPACE,
        "_COMMAND_READ_TIMEOUT_SECONDS",
        _COMMAND_FRAME_TEST_TIMEOUT_SECONDS,
    )
    server = await _start_server(
        root=root,
        socket_path=socket_path,
        worker_argv=_scenario_argv(probe_root),
        job_timeout_seconds=_JOB_TIMEOUT_SECONDS,
    )
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    try:
        writer.write(b"\x00\x00")
        await writer.drain()
        assert (
            await asyncio.wait_for(
                reader.read(1),
                timeout=_COMMAND_FRAME_CLOSE_BOUND_SECONDS,
            )
            == b""
        )
        assert tuple(probe_root.iterdir()) == ()
        recovered = await _exchange(socket_path, success_command)
    finally:
        writer.close()
        await writer.wait_closed()
        await _stop_server(server)

    assert isinstance(recovered, PdfSuccess)


@pytest.mark.asyncio
async def test_invalid_command_frames_are_silent_and_next_request_recovers(
    tmp_path: Path,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    socket_parent = tmp_path / "socket"
    socket_parent.mkdir(mode=0o700)
    probe_root = tmp_path / "probes"
    probe_root.mkdir(mode=0o700)
    source = b"%PDF-1.7\ninvalid-command-recovery-fixture"
    success_command = _stage_inspect(root, 17, source)
    socket_path = socket_parent / "worker.sock"
    sentinel = b"ATTACKER_CONTROLLED_SENTINEL"
    valid_body = success_command.model_dump_json().encode("utf-8")
    extra_field_body = valid_body[:-1] + b',"attacker_marker":"' + sentinel + b'"}'
    duplicate_key_body = b'{"operation":"inspect","operation":"inspect"}'
    invalid_frames = (
        b"\x00\x00",
        (MAX_COMMAND_FRAME_BYTES + 1).to_bytes(_FRAME_PREFIX_BYTES, "big"),
        _unchecked_frame(b'{"attacker_marker":"' + sentinel),
        _unchecked_frame(extra_field_body),
        _unchecked_frame(duplicate_key_body),
    )
    reported: list[dict[str, object]] = []
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()

    def record_loop_exception(
        _loop: asyncio.AbstractEventLoop,
        context: dict[str, object],
    ) -> None:
        reported.append(context.copy())

    loop.set_exception_handler(record_loop_exception)
    server = await _start_server(
        root=root,
        socket_path=socket_path,
        worker_argv=_scenario_argv(probe_root),
        job_timeout_seconds=_JOB_TIMEOUT_SECONDS,
    )
    try:
        for frame in invalid_frames:
            await _send_untrusted_frame(socket_path, frame)
            await asyncio.sleep(0)
        assert tuple(probe_root.iterdir()) == ()
        recovered = await _exchange(socket_path, success_command)
        await asyncio.sleep(0)
    finally:
        await _stop_server(server)
        loop.set_exception_handler(previous_handler)

    assert reported == []
    assert sentinel.decode("ascii") not in repr(reported)
    assert isinstance(recovered, PdfSuccess)


@pytest.mark.asyncio
async def test_caller_cancellation_reaps_the_running_process_group(
    tmp_path: Path,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    probe_root = tmp_path / "probes"
    probe_root.mkdir(mode=0o700)
    source = b"%PDF-1.7\ncaller-cancellation-fixture"
    command = _stage_inspect(root, 4, source)
    work_root = root / command.request_id.hex
    execution = _JOB_EXECUTION_CONTEXT(
        root=root,
        max_bytes=_EXPECTED_FILE_SIZE_BYTES,
        settings=PdfProcessorSettings(),
        worker_argv=_scenario_argv(probe_root),
        timeout_seconds=30.0,
    )
    task = asyncio.create_task(
        _RUN_DISPOSABLE_JOB(
            command,
            work_root,
            _NonPollableWriter(),
            execution=execution,
        )
    )
    process_ids = await _read_processes(
        probe_root / f"{command.request_id.hex}.pids",
        expected=2,
    )
    _ = task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    await _require_processes_gone(process_ids)


@pytest.mark.asyncio
async def test_hard_job_timeout_cancels_a_nonreturning_process_spawn_promptly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    source = b"%PDF-1.7\nspawn-timeout-fixture"
    command = _stage_inspect(root, 10, source)
    work_root = root / command.request_id.hex
    execution = _JOB_EXECUTION_CONTEXT(
        root=root,
        max_bytes=_EXPECTED_FILE_SIZE_BYTES,
        settings=PdfProcessorSettings(),
        worker_argv=(sys.executable, "-m", "nplg_mcp.pdf_worker_main"),
        timeout_seconds=_SPAWN_WINDOW_TIMEOUT_SECONDS,
    )
    spawn_entered = asyncio.Event()
    spawn_cancelled = asyncio.Event()
    release_spawn = asyncio.Event()

    async def nonreturning_spawn(*_argv: str, **_options: object) -> Process:
        spawn_entered.set()
        try:
            _ = await release_spawn.wait()
            message = "test watchdog released a nonreturning spawn"
            raise RuntimeError(message)
        except asyncio.CancelledError:
            spawn_cancelled.set()
            raise

    async def release_test_watchdog() -> None:
        await asyncio.sleep(_SPAWN_TEST_WATCHDOG_SECONDS)
        release_spawn.set()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", nonreturning_spawn)
    watchdog = asyncio.create_task(release_test_watchdog())
    started_at = asyncio.get_running_loop().time()
    try:
        with pytest.raises(TimeoutError):
            _ = await _RUN_DISPOSABLE_JOB(
                command,
                work_root,
                _NonPollableWriter(),
                execution=execution,
            )
    finally:
        _ = watchdog.cancel()
        with suppress(asyncio.CancelledError):
            await watchdog
    elapsed = asyncio.get_running_loop().time() - started_at

    assert spawn_entered.is_set()
    assert spawn_cancelled.is_set()
    assert elapsed < _SPAWN_PROMPT_BOUND_SECONDS


@pytest.mark.asyncio
async def test_peer_watcher_closes_duplicate_when_descriptor_setup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    duplicated: list[int] = []

    def fail_descriptor_setup(descriptor: int, _inheritable: object) -> None:
        duplicated.append(descriptor)
        message = "synthetic descriptor setup failure"
        raise OSError(message)

    monkeypatch.setattr(os, "set_inheritable", fail_descriptor_setup)
    try:
        with pytest.raises(OSError, match="descriptor setup"):
            await _WAIT_FOR_PEER_DISCONNECT(_PollableWriter(local.fileno()))
        assert len(duplicated) == 1
        with pytest.raises(OSError, match="Bad file descriptor"):
            _ = os.fstat(duplicated[0])
    finally:
        local.close()
        peer.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [0, MAX_RESULT_FRAME_BYTES + 1])
async def test_job_result_reader_rejects_out_of_range_frame_size(size: int) -> None:
    prefix = size.to_bytes(_FRAME_PREFIX_BYTES, "big")

    with pytest.raises(RuntimeError, match="result length"):
        _ = await _READ_JOB_RESULT(_stream_reader(prefix))


@pytest.mark.asyncio
async def test_job_result_reader_rejects_trailing_output() -> None:
    result = PdfFailure(
        request_id=UUID(int=13),
        status="error",
        operation="inspect",
        payload=PublicWorkerError(
            code=ErrorCode.INTERNAL_ERROR,
            message="bounded failure",
        ),
    )
    frame = encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES)

    with pytest.raises(RuntimeError, match="trailing output"):
        _ = await _READ_JOB_RESULT(_stream_reader(frame + b"x"))


@pytest.mark.asyncio
async def test_job_stderr_reader_accepts_exact_limit() -> None:
    await _READ_JOB_STDERR(_stream_reader(b"x" * _JOB_STDERR_LIMIT_BYTES))


@pytest.mark.asyncio
async def test_job_stderr_reader_rejects_limit_plus_one() -> None:
    payload = b"x" * (_JOB_STDERR_LIMIT_BYTES + 1)

    with pytest.raises(RuntimeError, match="stderr exceeded"):
        await _READ_JOB_STDERR(_stream_reader(payload))


@pytest.mark.asyncio
async def test_nonpollable_peer_watcher_remains_cancellable() -> None:
    watcher = asyncio.create_task(
        _WAIT_FOR_PEER_DISCONNECT(_NonPollableWriter()),
    )
    await asyncio.sleep(0)

    _ = watcher.cancel()
    with pytest.raises(asyncio.CancelledError):
        await watcher


@pytest.mark.asyncio
async def test_job_cleanup_survives_repeated_cancellation() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def cleanup_operation() -> None:
        entered.set()
        _ = await release.wait()

    cleanup = asyncio.create_task(cleanup_operation())
    waiter = asyncio.create_task(_WAIT_FOR_JOB_CLEANUP(cleanup))
    _ = await entered.wait()
    _ = waiter.cancel()
    await asyncio.sleep(0)
    _ = waiter.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert cleanup.done()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "worker_argv",
    [
        (),
        ("relative-python",),
        (sys.executable, ""),
        (sys.executable, "argument\x00suffix"),
    ],
)
async def test_unix_server_rejects_invalid_job_argv_before_binding(
    tmp_path: Path,
    worker_argv: tuple[str, ...],
) -> None:
    options = _JOB_OPTIONS(worker_argv=worker_argv, timeout_seconds=1.0)

    with pytest.raises(RuntimeError, match="job worker argv"):
        await _SERVE_UNIX_SOCKET(
            tmp_path / "missing" / "worker.sock",
            root=tmp_path,
            max_bytes=_EXPECTED_FILE_SIZE_BYTES,
            settings=PdfProcessorSettings(),
            job_options=options,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timeout_seconds",
    [0.0, -1.0, float("nan"), float("inf"), True, 1, "1"],
)
async def test_unix_server_rejects_invalid_job_timeout_before_binding(
    tmp_path: Path,
    timeout_seconds: object,
) -> None:
    options = _JOB_OPTIONS(
        worker_argv=(sys.executable, "-m", "nplg_mcp.pdf_worker_main"),
        timeout_seconds=cast("float", timeout_seconds),
    )

    with pytest.raises(RuntimeError, match="job timeout"):
        await _SERVE_UNIX_SOCKET(
            tmp_path / "missing" / "worker.sock",
            root=tmp_path,
            max_bytes=_EXPECTED_FILE_SIZE_BYTES,
            settings=PdfProcessorSettings(),
            job_options=options,
        )


@pytest.mark.asyncio
async def test_unix_peer_cancellation_reaps_process_group_before_next_success(
    tmp_path: Path,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    socket_parent = tmp_path / "socket"
    socket_parent.mkdir(mode=0o700)
    probe_root = tmp_path / "probes"
    probe_root.mkdir(mode=0o700)
    source = b"%PDF-1.7\njob-isolation-fixture"
    cancelled_command = _stage_inspect(root, 4, source)
    success_command = _stage_inspect(root, 5, source)
    socket_path = socket_parent / "worker.sock"
    server = await _start_server(
        root=root,
        socket_path=socket_path,
        worker_argv=_scenario_argv(probe_root),
        job_timeout_seconds=30.0,
    )
    try:
        _reader, writer = await asyncio.open_unix_connection(str(socket_path))
        writer.write(encode_frame(cancelled_command, maximum=MAX_COMMAND_FRAME_BYTES))
        await writer.drain()
        writer.write_eof()
        await writer.drain()
        processes = await _read_processes(
            probe_root / f"{cancelled_command.request_id.hex}.pids",
            expected=2,
        )
        writer.close()
        await writer.wait_closed()
        await _require_processes_gone(processes)
        recovered = await _exchange(socket_path, success_command)
    finally:
        await _stop_server(server)

    assert isinstance(recovered, PdfSuccess)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("crash_request", "success_request"),
    [(2, 6), (11, 12)],
)
async def test_unix_job_crash_is_reaped_before_next_success(
    tmp_path: Path,
    crash_request: int,
    success_request: int,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    socket_parent = tmp_path / "socket"
    socket_parent.mkdir(mode=0o700)
    probe_root = tmp_path / "probes"
    probe_root.mkdir(mode=0o700)
    source = b"%PDF-1.7\njob-isolation-fixture"
    crash_command = _stage_inspect(root, crash_request, source)
    success_command = _stage_inspect(root, success_request, source)
    socket_path = socket_parent / "worker.sock"
    server = await _start_server(
        root=root,
        socket_path=socket_path,
        worker_argv=_scenario_argv(probe_root),
        job_timeout_seconds=30.0,
    )
    try:
        crashed = await _exchange(socket_path, crash_command)
        processes = await _read_processes(
            probe_root / f"{crash_command.request_id.hex}.pids",
            expected=1,
        )
        await _require_processes_gone(processes)
        recovered = await _exchange(socket_path, success_command)
    finally:
        await _stop_server(server)

    assert isinstance(crashed, PdfFailure)
    assert isinstance(recovered, PdfSuccess)


@pytest.mark.asyncio
async def test_descendant_pipe_holder_is_killed_promptly_on_job_crash(
    tmp_path: Path,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    socket_parent = tmp_path / "socket"
    socket_parent.mkdir(mode=0o700)
    probe_root = tmp_path / "probes"
    probe_root.mkdir(mode=0o700)
    source = b"%PDF-1.7\ndescendant-crash-fixture"
    crash_command = _stage_inspect(root, 14, source)
    success_command = _stage_inspect(root, 15, source)
    process_path = probe_root / f"{crash_command.request_id.hex}.pids"
    socket_path = socket_parent / "worker.sock"
    server = await _start_server(
        root=root,
        socket_path=socket_path,
        worker_argv=_scenario_argv(probe_root),
        job_timeout_seconds=5.0,
    )
    processes: tuple[int, ...] = ()
    try:
        started_at = asyncio.get_running_loop().time()
        crashed = await asyncio.wait_for(
            _exchange(socket_path, crash_command),
            timeout=_CRASH_PROMPT_BOUND_SECONDS,
        )
        elapsed = asyncio.get_running_loop().time() - started_at
        processes = await _read_processes(process_path, expected=2)
        await _require_processes_gone(processes)
        recovered = await _exchange(socket_path, success_command)
    finally:
        if not processes and process_path.exists():
            processes = await _read_processes(process_path, expected=2)
        if processes:
            await _require_processes_gone(processes)
        await _stop_server(server)

    assert elapsed < _CRASH_PROMPT_BOUND_SECONDS
    assert isinstance(crashed, PdfFailure)
    assert isinstance(recovered, PdfSuccess)


@pytest.mark.asyncio
async def test_unix_jobs_use_fresh_processes_with_exact_resource_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "jobs"
    root.mkdir(mode=0o700)
    socket_parent = tmp_path / "socket"
    socket_parent.mkdir(mode=0o700)
    source_path = make_raster_pdf(tmp_path / "source.pdf", width=120, height=80)
    first = _stage_inspect(root, 7, source_path.path.read_bytes())
    second = _stage_render_pages(root, 8, source_path.path.read_bytes())
    socket_path = socket_parent / "worker.sock"
    _apply_worker_environment(monkeypatch, root)

    def reject_in_process(*_arguments: object, **_options: object) -> None:
        message = "PDF parsing reached the persistent supervisor"
        raise AssertionError(message)

    monkeypatch.setitem(_WORKER_NAMESPACE, "_execute", reject_in_process)
    real_create = cast("_CreateSubprocess", asyncio.create_subprocess_exec)
    process_ids: list[int] = []
    observed_limits: list[tuple[tuple[int, int], ...]] = []

    async def capture_process(*argv: str, **options: object) -> Process:
        process = await real_create(*argv, **options)
        expected: tuple[tuple[int, tuple[int, int]], ...] = (
            (resource.RLIMIT_CORE, (0, 0)),
            (
                resource.RLIMIT_CPU,
                (_EXPECTED_CPU_SECONDS, _EXPECTED_CPU_SECONDS),
            ),
            (
                resource.RLIMIT_AS,
                (_EXPECTED_ADDRESS_SPACE_BYTES, _EXPECTED_ADDRESS_SPACE_BYTES),
            ),
            (
                resource.RLIMIT_FSIZE,
                (_EXPECTED_FILE_SIZE_BYTES, _EXPECTED_FILE_SIZE_BYTES),
            ),
            (
                resource.RLIMIT_NOFILE,
                (_EXPECTED_OPEN_FILES, _EXPECTED_OPEN_FILES),
            ),
        )
        if hasattr(resource, "RLIMIT_NPROC"):
            expected = (
                *expected,
                (
                    resource.RLIMIT_NPROC,
                    (_EXPECTED_PROCESSES, _EXPECTED_PROCESSES),
                ),
            )
        current = await asyncio.to_thread(
            _wait_for_resource_limits,
            process.pid,
            expected,
        )
        process_ids.append(process.pid)
        observed_limits.append(current)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_process)
    server = await _start_server(root=root, socket_path=socket_path)
    try:
        first_result = await _exchange(socket_path, first)
        second_result = await _exchange(socket_path, second)
    finally:
        await _stop_server(server)

    assert isinstance(first_result, PdfSuccess)
    assert isinstance(second_result, PdfSuccess)
    assert second_result.payload.operation == "render_pages"
    assert len(set(process_ids)) == _EXPECTED_JOB_COUNT
    assert len(observed_limits) == _EXPECTED_JOB_COUNT
