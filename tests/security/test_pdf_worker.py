# Copyright (c) 2026 David Osipov
"""Security tests for the disposable PDF worker boundary."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import sys
import threading
import time
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, cast, override
from uuid import UUID

import pytest
from PIL import Image

from nplg_mcp.bounded_work import STORAGE_WORK
from nplg_mcp.pdf_executor import (
    MonotonicDeadline,
    PdfCircuitBreaker,
    PdfCircuitPolicy,
    PdfProcessorSettings,
    PdfResourceLimits,
    PdfWorkerError,
    PdfWorkerOperationalError,
    PdfWorkerPolicy,
    PdfWorkerUnavailableError,
)
from nplg_mcp.pdf_ipc import (
    InspectCommand,
    InspectParams,
    InspectPayload,
    ManifestCommand,
    ManifestParams,
    ManifestPayload,
    PdfFailure,
    PdfSuccess,
    RenderPagesCommand,
    RenderPagesParams,
    RenderPagesPayload,
    RenderTilesCommand,
    RenderTilesParams,
    RenderTilesPayload,
    parse_command_frame,
)
from nplg_mcp.pdf_worker_client import SubprocessPdfExecutor
from nplg_mcp.storage import ContentAddressedStore
from tests.helpers.pdf_factory import make_raster_pdf

if TYPE_CHECKING:
    from asyncio.subprocess import Process

    from nplg_mcp.pdf_ipc import PdfResult

_INSPECTED_WIDTH = 120
_INSPECTED_HEIGHT = 80
_EXPECTED_TERMINATION_WAITS = 2


class _MonotonicClock:
    def __init__(self) -> None:
        super().__init__()
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


class _PipeLessProcess:
    def __init__(self) -> None:
        super().__init__()
        self.pid = 424_242
        self.returncode: int | None = None
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.wait_count = 0

    async def wait(self) -> int:
        self.wait_count += 1
        if self.wait_count >= _EXPECTED_TERMINATION_WAITS:
            self.returncode = 0
        return 0


class _DelayedTerminationExecutor(SubprocessPdfExecutor):
    """Expose deterministic cleanup barriers for repeated-cancellation tests."""

    def __init__(
        self,
        *,
        store: ContentAddressedStore,
        worker_argv: tuple[str, ...],
    ) -> None:
        super().__init__(store=store, worker_argv=worker_argv)
        self.cleanup_started = asyncio.Event()
        self.release_cleanup = asyncio.Event()

    @override
    async def _terminate_process_group(self, process: Process) -> None:
        self.cleanup_started.set()
        _ = await self.release_cleanup.wait()
        await super()._terminate_process_group(process)


@pytest.mark.asyncio
@pytest.mark.parametrize("seconds", [0.0, -1.0, float("nan"), float("inf")])
async def test_pdf_deadline_rejects_every_nonpositive_or_nonfinite_duration(
    seconds: float,
) -> None:
    with pytest.raises(ValueError, match="deadline duration"):
        _ = MonotonicDeadline.after(seconds)


def test_pdf_resource_limits_reject_nonpositive_exact_integer_limits() -> None:
    with pytest.raises(ValueError, match="positive integers"):
        _ = PdfResourceLimits(cpu_seconds=0)


@pytest.mark.parametrize("grace", [0.0, -1.0, 6.0, float("nan")])
def test_pdf_resource_limits_reject_invalid_termination_grace(grace: float) -> None:
    with pytest.raises(ValueError, match="termination grace"):
        _ = PdfResourceLimits(termination_grace_seconds=grace)


def test_pdf_processor_settings_reject_out_of_range_values() -> None:
    with pytest.raises(ValueError, match="outside their allowed range"):
        _ = PdfProcessorSettings(max_pages_per_render=0)


def test_pdf_processor_settings_reject_overlap_consuming_a_tile() -> None:
    with pytest.raises(ValueError, match="overlap must be smaller"):
        _ = PdfProcessorSettings(tile_width=256, tile_height=256, tile_overlap=256)


@pytest.mark.parametrize("capacity", [0, 2, True])
def test_pdf_worker_policy_rejects_every_nonserialized_capacity(
    capacity: object,
) -> None:
    with pytest.raises(ValueError, match="capacity must equal 1"):
        _ = PdfWorkerPolicy(capacity=cast("int", capacity))


def test_pdf_circuit_opens_and_requires_one_successful_half_open_probe() -> None:
    clock = _MonotonicClock()
    circuit = PdfCircuitBreaker(
        policy=PdfCircuitPolicy(failure_threshold=2, open_seconds=10.0),
        clock=clock,
    )

    circuit.ensure_ready()
    circuit.before_attempt()
    circuit.record_operational_failure()
    circuit.before_attempt()
    circuit.record_operational_failure()

    with pytest.raises(PdfWorkerUnavailableError, match="temporarily unavailable"):
        circuit.ensure_ready()
    with pytest.raises(PdfWorkerUnavailableError, match="temporarily unavailable"):
        circuit.before_attempt()

    clock.value += 10.0
    circuit.ensure_ready()
    circuit.before_attempt()
    with pytest.raises(PdfWorkerUnavailableError, match="temporarily unavailable"):
        circuit.before_attempt()
    circuit.record_success()
    circuit.ensure_ready()


def test_cancelled_half_open_probe_does_not_count_as_an_operational_failure() -> None:
    clock = _MonotonicClock()
    circuit = PdfCircuitBreaker(
        policy=PdfCircuitPolicy(failure_threshold=1, open_seconds=1.0),
        clock=clock,
    )
    circuit.before_attempt()
    circuit.record_operational_failure()
    clock.value += 1.0
    circuit.before_attempt()

    circuit.record_cancelled()
    circuit.before_attempt()


def test_pdf_circuit_rejects_a_nonfinite_monotonic_clock() -> None:
    clock = _MonotonicClock()
    clock.value = float("nan")
    circuit = PdfCircuitBreaker(
        policy=PdfCircuitPolicy(failure_threshold=1, open_seconds=1.0),
        clock=clock,
    )

    with pytest.raises(RuntimeError, match="monotonic clock"):
        circuit.record_operational_failure()


def test_pdf_circuit_rejects_an_overflowed_open_deadline() -> None:
    clock = _MonotonicClock()
    clock.value = sys.float_info.max
    circuit = PdfCircuitBreaker(
        policy=PdfCircuitPolicy(failure_threshold=1, open_seconds=3_600.0),
        clock=clock,
    )

    with pytest.raises(RuntimeError, match="open deadline"):
        circuit.record_operational_failure()


@pytest.mark.parametrize(
    ("failure_threshold", "open_seconds"),
    [(True, 1.0), (1, float("nan")), (0, 1.0), (1, 0.0)],
)
def test_pdf_circuit_rejects_forged_policy(
    failure_threshold: object,
    open_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="circuit policy"):
        _ = PdfCircuitPolicy(
            failure_threshold=cast("int", failure_threshold),
            open_seconds=open_seconds,
        )


def test_pdf_command_frame_rejects_parent_traversal() -> None:
    """A worker command must never name a source outside its job directory."""
    frame = (
        b'{"request_id":"00000000-0000-4000-8000-000000000001",'
        b'"operation":"inspect","source_relative_path":"../secret.pdf",'
        b'"parameters":{}}'
    )

    with pytest.raises(ValueError, match="relative path"):
        _ = parse_command_frame(frame)


def test_executor_rejects_a_nonexistent_absolute_worker_executable(
    tmp_path: Path,
) -> None:
    """Worker selection must fail before an untrusted operation is accepted."""
    store = ContentAddressedStore(tmp_path / "cache")

    with pytest.raises(ValueError, match="worker argv"):
        _ = SubprocessPdfExecutor(
            store=store,
            worker_argv=(str(tmp_path / "missing-worker"),),
        )


def _process_is_gone(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return True
    return False


async def _read_process_ids(path: Path, *, expected: int) -> tuple[int, ...]:
    for _ in range(200):
        try:
            payload = await asyncio.to_thread(path.read_text, encoding="ascii")
            values = tuple(int(value) for value in payload.splitlines())
        except (FileNotFoundError, ValueError):
            values = ()
        if len(values) == expected and all(value > 0 for value in values):
            return values
        await asyncio.sleep(0.01)
    pytest.fail(f"worker PID readiness did not publish {expected} complete values")


@pytest.mark.asyncio
async def test_cancellation_kills_and_reaps_the_worker_process_group(
    tmp_path: Path,
) -> None:
    """Removing process-group termination must leave an observable orphan."""
    store = ContentAddressedStore(tmp_path / "cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nworker-cancellation-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    pid_file = tmp_path / "worker-pids"
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_hang.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), str(pid_file)),
    )
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000002"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    task: asyncio.Task[PdfResult] = asyncio.create_task(
        executor.execute(command, deadline=MonotonicDeadline.after(10.0))
    )
    worker_pid, descendant_pid = await _read_process_ids(pid_file, expected=2)

    _ = task.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await task

    assert _process_is_gone(worker_pid)
    assert _process_is_gone(descendant_pid)


@pytest.mark.asyncio
async def test_repeated_cancellation_cannot_interrupt_worker_cleanup(
    tmp_path: Path,
) -> None:
    """A second cancellation must not orphan the group or its private job tree."""
    store = ContentAddressedStore(tmp_path / "repeated-cancel-cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nrepeated-cancellation-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    pid_file = tmp_path / "repeated-cancel-pids"
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_hang.py"
    executor = _DelayedTerminationExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), str(pid_file)),
    )
    task: asyncio.Task[PdfResult] = asyncio.create_task(
        executor.execute(
            InspectCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000051"),
                operation="inspect",
                source_relative_path=artifact.relative_path,
                parameters=InspectParams(),
            ),
            deadline=MonotonicDeadline.after(10.0),
        )
    )
    worker_pid, descendant_pid = await _read_process_ids(pid_file, expected=2)

    _ = task.cancel()
    async with asyncio.timeout(2.0):
        _ = await executor.cleanup_started.wait()
    _ = task.cancel()
    executor.release_cleanup.set()
    with pytest.raises(asyncio.CancelledError):
        async with asyncio.timeout(2.0):
            _ = await task

    assert _process_is_gone(worker_pid)
    assert _process_is_gone(descendant_pid)
    assert list((store.root / ".pdf-worker-jobs").iterdir()) == []


@pytest.mark.asyncio
async def test_worker_job_tree_is_removed_when_termination_reports_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "termination-failure-cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\ntermination-failure-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_bad_frame.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), "truncated"),
    )

    async def failed_termination(_process: Process) -> None:
        message = "injected termination failure"
        raise PdfWorkerOperationalError(message)

    monkeypatch.setattr(executor, "_terminate_process_group", failed_termination)

    with pytest.raises(PdfWorkerOperationalError, match="termination failure"):
        _ = await executor.execute(
            InspectCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000052"),
                operation="inspect",
                source_relative_path=artifact.relative_path,
                parameters=InspectParams(),
            ),
            deadline=MonotonicDeadline.after(5.0),
        )

    assert list((store.root / ".pdf-worker-jobs").iterdir()) == []


@pytest.mark.asyncio
async def test_process_start_failure_removes_unstarted_worker_job_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "start-failure-cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nstart-failure-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = SubprocessPdfExecutor(store=store)

    async def fail_start(*_args: object, **_kwargs: object) -> Process:
        message = "injected process start failure"
        raise OSError(message)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_start)

    with pytest.raises(PdfWorkerOperationalError, match="could not be started"):
        _ = await executor.execute(
            InspectCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000058"),
                operation="inspect",
                source_relative_path=artifact.relative_path,
                parameters=InspectParams(),
            ),
            deadline=MonotonicDeadline.after(5.0),
        )

    assert list((store.root / ".pdf-worker-jobs").iterdir()) == []


@pytest.mark.asyncio
async def test_cleanup_has_reserved_capacity_when_storage_workers_are_saturated(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "cleanup-capacity-cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\ncleanup-capacity-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = SubprocessPdfExecutor(store=store)
    loop = asyncio.get_running_loop()
    release = threading.Event()
    started = (asyncio.Event(), asyncio.Event())

    def occupy_storage(index: int) -> None:
        _ = loop.call_soon_threadsafe(started[index].set)
        if not release.wait(timeout=5.0):
            message = "storage saturation fixture timed out"
            raise TimeoutError(message)

    blockers = [
        asyncio.create_task(
            STORAGE_WORK.run_to_completion(partial(occupy_storage, index))
        )
        for index in range(2)
    ]
    try:
        async with asyncio.timeout(2.0):
            _ = await asyncio.gather(*(event.wait() for event in started))

        with pytest.raises(PdfWorkerOperationalError, match="capacity is exhausted"):
            _ = await executor.execute(
                InspectCommand(
                    request_id=UUID("00000000-0000-4000-8000-000000000059"),
                    operation="inspect",
                    source_relative_path=artifact.relative_path,
                    parameters=InspectParams(),
                ),
                deadline=MonotonicDeadline.after(5.0),
            )

        assert list((store.root / ".pdf-worker-jobs").iterdir()) == []
    finally:
        release.set()
        for blocker in blockers:
            await blocker


@pytest.mark.asyncio
async def test_cleanup_recovers_permissions_before_removing_hostile_worker_tree(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "permission-cleanup-cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\npermission-cleanup-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_bad_frame.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), "permission-tree"),
    )

    with pytest.raises(PdfWorkerOperationalError, match="transport failed"):
        _ = await executor.execute(
            InspectCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000060"),
                operation="inspect",
                source_relative_path=artifact.relative_path,
                parameters=InspectParams(),
            ),
            deadline=MonotonicDeadline.after(5.0),
        )

    assert list((store.root / ".pdf-worker-jobs").iterdir()) == []


@pytest.mark.asyncio
async def test_cleanup_reports_operational_failure_when_bounded_retry_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "failed-cleanup-cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nfailed-cleanup-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = SubprocessPdfExecutor(store=store)
    attempts = 0
    expected_attempts = 2

    async def fail_start(*_args: object, **_kwargs: object) -> Process:
        message = "injected process start failure"
        raise OSError(message)

    def fail_removal(_path: Path, **_kwargs: object) -> None:
        nonlocal attempts
        attempts += 1
        message = "injected persistent cleanup failure"
        raise PermissionError(message)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_start)
    monkeypatch.setattr(shutil, "rmtree", fail_removal)

    with pytest.raises(PdfWorkerOperationalError, match="job cleanup failed"):
        _ = await executor.execute(
            InspectCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000061"),
                operation="inspect",
                source_relative_path=artifact.relative_path,
                parameters=InspectParams(),
            ),
            deadline=MonotonicDeadline.after(5.0),
        )

    assert attempts == expected_attempts


@pytest.mark.asyncio
async def test_deadline_kills_and_reaps_the_worker_process_group(
    tmp_path: Path,
) -> None:
    """A hard deadline must reap both the worker and its descendant."""
    store = ContentAddressedStore(tmp_path / "cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nworker-timeout-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    pid_file = tmp_path / "worker-pids"
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_hang.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), str(pid_file)),
    )
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000014"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    with pytest.raises(PdfWorkerError, match="deadline"):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(0.2),
        )

    worker_pid, descendant_pid = await _read_process_ids(pid_file, expected=2)
    assert _process_is_gone(worker_pid)
    assert _process_is_gone(descendant_pid)
    assert list(store.root.parent.glob(".nplg-pdf-worker-*")) == []


@pytest.mark.asyncio
async def test_executor_capacity_wait_uses_the_caller_absolute_deadline(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "capacity-deadline-cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\ncapacity-deadline-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    pid_file = tmp_path / "capacity-deadline-pids"
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_hang.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), str(pid_file)),
    )
    first = asyncio.create_task(
        executor.execute(
            InspectCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000047"),
                operation="inspect",
                source_relative_path=artifact.relative_path,
                parameters=InspectParams(),
            ),
            deadline=MonotonicDeadline.after(10.0),
        )
    )
    worker_pid, descendant_pid = await _read_process_ids(pid_file, expected=2)
    try:
        with pytest.raises(PdfWorkerError, match="awaiting capacity"):
            async with asyncio.timeout(0.5):
                _ = await executor.execute(
                    InspectCommand(
                        request_id=UUID("00000000-0000-4000-8000-000000000048"),
                        operation="inspect",
                        source_relative_path=artifact.relative_path,
                        parameters=InspectParams(),
                    ),
                    deadline=MonotonicDeadline.after(0.05),
                )
    finally:
        _ = first.cancel()
        with pytest.raises(asyncio.CancelledError):
            _ = await first

    assert _process_is_gone(worker_pid)
    assert _process_is_gone(descendant_pid)


@pytest.mark.asyncio
async def test_success_reaps_a_same_group_descendant(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "success-descendant-cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nsuccess-descendant-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    pid_file = tmp_path / "success-descendant-pid"
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_success_descendant.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), str(pid_file)),
    )

    result = await executor.execute(
        InspectCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000044"),
            operation="inspect",
            source_relative_path=artifact.relative_path,
            parameters=InspectParams(),
        ),
        deadline=MonotonicDeadline.after(5.0),
    )
    (descendant_pid,) = await _read_process_ids(pid_file, expected=1)

    assert isinstance(result, PdfSuccess)
    try:
        assert _process_is_gone(descendant_pid)
    finally:
        with suppress(ProcessLookupError):
            os.kill(descendant_pid, signal.SIGKILL)


@pytest.mark.asyncio
async def test_worker_job_directory_stays_inside_the_writable_cache_mount(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "read-only-parent"
    store = ContentAddressedStore(parent / "cache")
    source = make_raster_pdf(tmp_path / "source.pdf", width=120, height=80, dpi=200)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    original_mode = parent.stat().st_mode & 0o777
    parent.chmod(0o500)
    try:
        result = await SubprocessPdfExecutor(store=store).execute(
            InspectCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000045"),
                operation="inspect",
                source_relative_path=artifact.relative_path,
                parameters=InspectParams(),
            ),
            deadline=MonotonicDeadline.after(5.0),
        )
    finally:
        parent.chmod(original_mode)

    assert isinstance(result, PdfSuccess)
    job_root = store.root / ".pdf-worker-jobs"
    assert job_root.is_dir()
    assert list(job_root.iterdir()) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    ["truncated", "oversized", "trailing", "invalid-json"],
)
async def test_parent_rejects_malformed_or_unbounded_worker_frames(
    tmp_path: Path,
    mode: str,
) -> None:
    """Malformed worker bytes must become one sanitized transport failure."""
    store = ContentAddressedStore(tmp_path / mode)
    artifact = store.put_bytes(
        b"%PDF-1.7\nbad-frame-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_bad_frame.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), mode),
    )
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000015"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    with pytest.raises(PdfWorkerError, match="PDF worker"):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(2.0),
        )

    assert list(store.root.parent.glob(".nplg-pdf-worker-*")) == []


@pytest.mark.asyncio
async def test_repeated_worker_transport_failures_open_the_executor_circuit(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "circuit")
    artifact = store.put_bytes(
        b"%PDF-1.7\ncircuit-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_bad_frame.py"
    executor = SubprocessPdfExecutor(
        store=store,
        policy=PdfWorkerPolicy(
            circuit=PdfCircuitPolicy(failure_threshold=2, open_seconds=30.0)
        ),
        worker_argv=(sys.executable, str(helper), "invalid-json"),
    )
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000019"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    for _ in range(2):
        with pytest.raises(PdfWorkerError, match="transport"):
            _ = await executor.execute(
                command,
                deadline=MonotonicDeadline.after(2.0),
            )

    with pytest.raises(PdfWorkerUnavailableError, match="temporarily unavailable"):
        executor.ensure_ready()
    with pytest.raises(PdfWorkerUnavailableError, match="temporarily unavailable"):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(2.0),
        )


@pytest.mark.asyncio
async def test_disposable_worker_inspects_a_staged_pdf_without_child_cache_access(
    tmp_path: Path,
) -> None:
    """Replacing the worker with in-process PDFium must break this boundary test."""
    store = ContentAddressedStore(tmp_path / "authoritative")
    source = make_raster_pdf(
        tmp_path / "source.pdf",
        width=_INSPECTED_WIDTH,
        height=_INSPECTED_HEIGHT,
        dpi=200,
    )
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = SubprocessPdfExecutor(store=store)
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000003"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    result = await executor.execute(command, deadline=MonotonicDeadline.after(15.0))

    assert isinstance(result, PdfSuccess)
    assert isinstance(result.payload, InspectPayload)
    assert result.payload.value.source_sha256 == artifact.sha256
    assert result.payload.value.page_count == 1
    assert result.payload.value.pages[0].native_width == _INSPECTED_WIDTH
    assert result.payload.value.pages[0].native_height == _INSPECTED_HEIGHT
    assert list(store.root.parent.glob(".nplg-pdf-worker-*")) == []


@pytest.mark.asyncio
async def test_parent_rejects_a_worker_result_bound_to_another_source(
    tmp_path: Path,
) -> None:
    """A typed child result is not trusted until its source digest is verified."""
    store = ContentAddressedStore(tmp_path / "authoritative")
    artifact = store.put_bytes(
        b"%PDF-1.7\nsource-binding-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_forged_inspect.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper)),
    )
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000013"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    with pytest.raises(PdfWorkerError, match="source digest mismatch"):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(5.0),
        )


@pytest.mark.asyncio
async def test_parent_rejects_a_nonzero_worker_exit_after_a_valid_frame(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "nonzero")
    artifact = store.put_bytes(
        b"%PDF-1.7\nnonzero-worker-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_forged_inspect.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), "exit-nonzero"),
    )
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000026"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    with pytest.raises(PdfWorkerError, match="exited unsuccessfully"):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(5.0),
        )


@pytest.mark.asyncio
async def test_parent_returns_a_typed_failure_for_invalid_pdf_bytes(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "invalid-pdf")
    artifact = store.put_bytes(
        b"not-a-pdf",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = SubprocessPdfExecutor(store=store)
    result = await executor.execute(
        InspectCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000028"),
            operation="inspect",
            source_relative_path=artifact.relative_path,
            parameters=InspectParams(),
        ),
        deadline=MonotonicDeadline.after(5.0),
    )

    assert isinstance(result, PdfFailure)


@pytest.mark.asyncio
async def test_parent_fails_closed_when_spawned_process_pipes_are_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "missing-pipes")
    artifact = store.put_bytes(
        b"%PDF-1.7\nmissing-pipes",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    process = _PipeLessProcess()
    group_gone = False

    async def create_process(
        *_command: str,
        **_options: object,
    ) -> Process:
        return cast("Process", process)

    def observe_signal(_process_group: int, sent_signal: int) -> None:
        nonlocal group_gone
        if sent_signal == signal.SIGKILL:
            group_gone = True
        elif sent_signal == 0 and group_gone:
            raise ProcessLookupError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    monkeypatch.setattr(os, "killpg", observe_signal)
    executor = SubprocessPdfExecutor(store=store)
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000029"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    with pytest.raises(PdfWorkerError, match="pipes are unavailable"):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(5.0),
        )

    assert process.wait_count == _EXPECTED_TERMINATION_WAITS


@pytest.mark.asyncio
async def test_parent_rejects_an_input_swapped_between_stat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "swapped-input")
    artifact = store.put_bytes(
        b"%PDF-1.7\nauthoritative",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    alternate = tmp_path / "alternate.pdf"
    _ = alternate.write_bytes(b"%PDF-1.7\nalternate")
    real_open = os.open

    def swapping_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        selected = alternate if path == artifact.absolute_path else path
        return real_open(selected, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", swapping_open)
        executor = SubprocessPdfExecutor(store=store)
        with pytest.raises(PdfWorkerError, match="identity changed before staging"):
            _ = await executor.execute(
                InspectCommand(
                    request_id=UUID("00000000-0000-4000-8000-000000000030"),
                    operation="inspect",
                    source_relative_path=artifact.relative_path,
                    parameters=InspectParams(),
                ),
                deadline=MonotonicDeadline.after(5.0),
            )


@pytest.mark.asyncio
async def test_parent_rejects_input_metadata_drift_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "drifting-input")
    artifact = store.put_bytes(
        b"%PDF-1.7\nauthoritative",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    source = artifact.absolute_path
    initial = source.stat()
    real_fsync = os.fsync

    def mutating_fsync(descriptor: int) -> None:
        os.utime(
            source,
            ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
        )
        real_fsync(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", mutating_fsync)
        executor = SubprocessPdfExecutor(store=store)
        with pytest.raises(PdfWorkerError, match="identity changed during staging"):
            _ = await executor.execute(
                InspectCommand(
                    request_id=UUID("00000000-0000-4000-8000-000000000031"),
                    operation="inspect",
                    source_relative_path=artifact.relative_path,
                    parameters=InspectParams(),
                ),
                deadline=MonotonicDeadline.after(5.0),
            )


@pytest.mark.asyncio
async def test_parent_uses_safe_no_follow_fallback_when_flag_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "portable-no-follow")
    source = make_raster_pdf(tmp_path / "source.pdf", width=120, height=80, dpi=200)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    command = RenderPagesCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000032"),
        operation="render_pages",
        source_relative_path=artifact.relative_path,
        parameters=RenderPagesParams(pages=(1,), mode="native"),
    )

    with monkeypatch.context() as patch:
        patch.delattr(os, "O_NOFOLLOW")
        result = await SubprocessPdfExecutor(store=store).execute(
            command,
            deadline=MonotonicDeadline.after(15.0),
        )

    assert isinstance(result, PdfSuccess)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("defect", "message"),
    [
        ("absent", "render input is unavailable"),
        ("directory-symlink", "contains a symlink"),
        ("file-symlink", "input is not a regular file"),
    ],
)
async def test_parent_rejects_unsafe_authoritative_render_trees_before_spawn(
    tmp_path: Path,
    defect: str,
    message: str,
) -> None:
    store = ContentAddressedStore(tmp_path / "render-tree")
    render_id = "rnd_" + "2" * 32
    render_root = store.root / "renders" / render_id
    if defect != "absent":
        render_root.mkdir(parents=True)
        target = tmp_path / "outside"
        if defect == "directory-symlink":
            target.mkdir()
            (render_root / "linked-directory").symlink_to(
                target,
                target_is_directory=True,
            )
        else:
            _ = target.write_bytes(b"outside")
            (render_root / "linked-file").symlink_to(target)
    executor = SubprocessPdfExecutor(store=store)
    command = ManifestCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000027"),
        operation="manifest",
        parameters=ManifestParams(render_id=render_id),
    )

    with pytest.raises(PdfWorkerError, match=message):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(5.0),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "message"),
    [("request", "request ID mismatch"), ("operation", "operation mismatch")],
)
async def test_parent_rejects_cross_wired_worker_envelopes(
    tmp_path: Path,
    mode: str,
    message: str,
) -> None:
    """Typed responses still require exact request and operation binding."""
    store = ContentAddressedStore(tmp_path / mode)
    artifact = store.put_bytes(
        b"%PDF-1.7\nresult-binding-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_forged_inspect.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), mode),
    )
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000018"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    with pytest.raises(PdfWorkerError, match=message):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(5.0),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("unexpected", "unexpected page path"),
        ("manifest-path", "unexpected render manifest path"),
        ("final-symlink", "output path is invalid"),
        ("intermediate-symlink", "output path is invalid"),
        ("oversized", "file-size limit"),
        ("directory", "not a regular file"),
        ("digest", "identity or digest"),
        ("dimensions", "image dimensions"),
        ("not-jpeg", "image dimensions"),
        ("truncated-jpeg", "image body is invalid"),
        ("render-id", "render ID mismatch"),
        ("page-set", "page selection mismatch"),
        ("manifest-invalid", "manifest is invalid"),
        ("manifest-mismatch", "does not match"),
        ("manifest-oversized", "manifest exceeded"),
        ("extra", "unexpected or missing output paths"),
        ("symlink-directory-extra", "output contains a symlink"),
        ("fifo-extra", "output contains a special file"),
    ],
)
async def test_parent_rejects_malicious_child_output_before_publication(
    tmp_path: Path,
    mode: str,
    message: str,
) -> None:
    """Only validated regular output beneath the private job may be published."""
    store = ContentAddressedStore(tmp_path / "authoritative")
    artifact = store.put_bytes(
        b"%PDF-1.7\nmalicious-output-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_malicious_output.py"
    executor = SubprocessPdfExecutor(
        store=store,
        policy=PdfWorkerPolicy(resources=PdfResourceLimits(file_size_bytes=1_024)),
        worker_argv=(sys.executable, str(helper), mode),
    )
    command = RenderPagesCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000019"),
        operation="render_pages",
        source_relative_path=artifact.relative_path,
        parameters=RenderPagesParams(pages=(1,), mode="native"),
    )

    with pytest.raises(PdfWorkerError, match=message):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(5.0),
        )

    assert list((store.root / "renders").iterdir()) == []
    assert list(store.root.parent.glob(".nplg-pdf-worker-*")) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            (
                "pixel-budget",
                (1,),
                PdfProcessorSettings(max_page_pixels=1, max_render_pixels=1),
                "page pixel limit",
            ),
            id="per-page",
        ),
        pytest.param(
            (
                "aggregate-pixel-budget",
                (1, 2),
                PdfProcessorSettings(max_page_pixels=2, max_render_pixels=3),
                "aggregate pixel limit",
            ),
            id="aggregate",
        ),
        pytest.param(
            (
                "aggregate-pixel-budget",
                (1, 2),
                PdfProcessorSettings(
                    max_pages_per_render=1,
                    max_page_pixels=2,
                    max_render_pixels=4,
                ),
                "page-count limit",
            ),
            id="page-count",
        ),
        pytest.param(
            (
                "header-pixel-budget",
                (1,),
                PdfProcessorSettings(max_page_pixels=1, max_render_pixels=1),
                "page pixel limit",
            ),
            id="jpeg-header-before-decode",
        ),
    ],
)
async def test_parent_rejects_consistent_oversized_images_before_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[str, tuple[int, ...], PdfProcessorSettings, str],
) -> None:
    mode, pages, processor, expected_message = case
    store = ContentAddressedStore(tmp_path / mode)
    artifact = store.put_bytes(
        b"%PDF-1.7\nparent-pixel-budget-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_malicious_output.py"
    executor = SubprocessPdfExecutor(
        store=store,
        policy=PdfWorkerPolicy(processor=processor),
        worker_argv=(sys.executable, str(helper), mode),
    )

    def forbidden_decode(_image: Image.Image) -> None:
        message = "parent attempted image decode before enforcing pixel policy"
        raise AssertionError(message)

    monkeypatch.setattr(Image.Image, "load", forbidden_decode)

    with pytest.raises(PdfWorkerError, match=expected_message):
        _ = await executor.execute(
            RenderPagesCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000053"),
                operation="render_pages",
                source_relative_path=artifact.relative_path,
                parameters=RenderPagesParams(pages=pages, mode="native"),
            ),
            deadline=MonotonicDeadline.after(5.0),
        )

    assert list((store.root / "renders").iterdir()) == []


@pytest.mark.asyncio
async def test_parent_caps_tile_grid_before_constructing_expected_tiles(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "parent-tile-budget")
    source = make_raster_pdf(tmp_path / "source.pdf", width=600, height=400, dpi=200)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    render = await SubprocessPdfExecutor(store=store).execute(
        RenderPagesCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000054"),
            operation="render_pages",
            source_relative_path=artifact.relative_path,
            parameters=RenderPagesParams(pages=(1,), mode="native"),
        ),
        deadline=MonotonicDeadline.after(15.0),
    )
    assert isinstance(render, PdfSuccess)
    assert isinstance(render.payload, RenderPagesPayload)
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_malicious_tiles.py"
    executor = SubprocessPdfExecutor(
        store=store,
        policy=PdfWorkerPolicy(
            processor=PdfProcessorSettings(max_tiles_per_page=1),
        ),
        worker_argv=(sys.executable, str(helper), "tile-metadata"),
    )

    with pytest.raises(PdfWorkerError, match="tile-count limit"):
        _ = await executor.execute(
            RenderTilesCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000055"),
                operation="render_tiles",
                parameters=RenderTilesParams(
                    render_id=render.payload.value.render_id,
                    page_number=1,
                    tile_width=256,
                    tile_height=256,
                    overlap=0,
                ),
            ),
            deadline=MonotonicDeadline.after(5.0),
        )


@pytest.mark.asyncio
async def test_parent_rejects_oversized_staged_tile_source_before_grid_allocation(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "parent-tile-source-budget")
    source = make_raster_pdf(tmp_path / "source.pdf", width=600, height=400, dpi=200)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    render = await SubprocessPdfExecutor(store=store).execute(
        RenderPagesCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000056"),
            operation="render_pages",
            source_relative_path=artifact.relative_path,
            parameters=RenderPagesParams(pages=(1,), mode="native"),
        ),
        deadline=MonotonicDeadline.after(15.0),
    )
    assert isinstance(render, PdfSuccess)
    assert isinstance(render.payload, RenderPagesPayload)
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_malicious_tiles.py"
    executor = SubprocessPdfExecutor(
        store=store,
        policy=PdfWorkerPolicy(
            processor=PdfProcessorSettings(
                max_page_pixels=1,
                max_render_pixels=1,
            ),
        ),
        worker_argv=(sys.executable, str(helper), "tile-metadata"),
    )

    with pytest.raises(PdfWorkerError, match="page pixel limit"):
        _ = await executor.execute(
            RenderTilesCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000057"),
                operation="render_tiles",
                parameters=RenderTilesParams(
                    render_id=render.payload.value.render_id,
                    page_number=1,
                    tile_width=256,
                    tile_height=256,
                    overlap=0,
                ),
            ),
            deadline=MonotonicDeadline.after(5.0),
        )


@pytest.mark.asyncio
async def test_parent_rehashes_worker_output_during_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "publication-race")
    source = make_raster_pdf(tmp_path / "source.pdf", width=120, height=80, dpi=200)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = SubprocessPdfExecutor(store=store)
    real_stage = store.stage
    mutated = False

    def stage_with_race(*, suffix: str = "") -> object:
        nonlocal mutated
        if not mutated:
            candidates = [
                *store.root.glob(".pdf-worker-jobs/.nplg-pdf-worker-*/cache"),
                *store.root.parent.glob(".nplg-pdf-worker-*/cache"),
            ]
            assert len(candidates) == 1
            page_paths = list(candidates[0].glob("renders/*/page-0001.jpg"))
            assert len(page_paths) == 1
            page_path = page_paths[0]
            _ = page_path.write_bytes(b"x" * page_path.stat().st_size)
            mutated = True
        return real_stage(suffix=suffix)

    monkeypatch.setattr(store, "stage", stage_with_race)

    with pytest.raises(PdfWorkerError, match="publication digest"):
        _ = await executor.execute(
            RenderPagesCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000046"),
                operation="render_pages",
                source_relative_path=artifact.relative_path,
                parameters=RenderPagesParams(pages=(1,), mode="native"),
            ),
            deadline=MonotonicDeadline.after(15.0),
        )

    assert mutated is True
    assert list((store.root / "renders").iterdir()) == []


@pytest.mark.asyncio
async def test_parent_deadline_covers_output_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "publication-deadline")
    artifact = store.put_bytes(
        b"%PDF-1.7\npublication-deadline-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_malicious_output.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), "valid"),
    )
    real_stage = store.stage
    delayed = False

    def delayed_stage(*, suffix: str = "") -> object:
        nonlocal delayed
        if not delayed:
            delayed = True
            time.sleep(1.0)
        return real_stage(suffix=suffix)

    monkeypatch.setattr(store, "stage", delayed_stage)

    with pytest.raises(PdfWorkerError, match=r"deadline.*publication"):
        _ = await executor.execute(
            RenderPagesCommand(
                request_id=UUID("00000000-0000-4000-8000-000000000049"),
                operation="render_pages",
                source_relative_path=artifact.relative_path,
                parameters=RenderPagesParams(pages=(1,), mode="native"),
            ),
            deadline=MonotonicDeadline.after(0.75),
        )

    assert delayed is True
    assert list((store.root / "renders").iterdir()) == []


@pytest.mark.asyncio
async def test_pdf_output_publication_does_not_block_the_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "publication-event-loop")
    artifact = store.put_bytes(
        b"%PDF-1.7\npublication-event-loop-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_malicious_output.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), "valid"),
    )
    real_stage = store.stage
    heartbeat = asyncio.Event()
    loop = asyncio.get_running_loop()
    heartbeat_seen_during_publication = False
    delayed = False

    def delayed_stage(*, suffix: str = "") -> object:
        nonlocal delayed, heartbeat_seen_during_publication
        if not delayed:
            delayed = True
            _ = loop.call_soon_threadsafe(heartbeat.set)
            time.sleep(0.2)
            heartbeat_seen_during_publication = heartbeat.is_set()
        return real_stage(suffix=suffix)

    monkeypatch.setattr(store, "stage", delayed_stage)

    result = await executor.execute(
        RenderPagesCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000050"),
            operation="render_pages",
            source_relative_path=artifact.relative_path,
            parameters=RenderPagesParams(pages=(1,), mode="native"),
        ),
        deadline=MonotonicDeadline.after(5.0),
    )

    assert isinstance(result, PdfSuccess)
    assert delayed is True
    assert heartbeat_seen_during_publication is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("render-id", "render ID mismatch"),
        ("manifest-path", "unexpected tile manifest path"),
        ("tile-path", "unexpected tile path"),
        ("page-number", "page selection mismatch"),
        ("geometry", "tile geometry mismatch"),
        ("root", "unexpected tile manifest path"),
        ("tile-metadata", "tile metadata mismatch"),
        ("extra-directory", None),
    ],
)
async def test_parent_rejects_malicious_tile_claims_and_allows_empty_directories(
    tmp_path: Path,
    mode: str,
    message: str | None,
) -> None:
    store = ContentAddressedStore(tmp_path / "malicious-tiles")
    source = make_raster_pdf(tmp_path / "source.pdf", width=120, height=80, dpi=200)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    render = await SubprocessPdfExecutor(store=store).execute(
        RenderPagesCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000033"),
            operation="render_pages",
            source_relative_path=artifact.relative_path,
            parameters=RenderPagesParams(pages=(1,), mode="native"),
        ),
        deadline=MonotonicDeadline.after(15.0),
    )
    assert isinstance(render, PdfSuccess)
    assert isinstance(render.payload, RenderPagesPayload)
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_malicious_tiles.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper), mode),
    )
    command = RenderTilesCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000034"),
        operation="render_tiles",
        parameters=RenderTilesParams(
            render_id=render.payload.value.render_id,
            page_number=1,
            tile_width=256,
            tile_height=256,
            overlap=0,
        ),
    )

    if message is None:
        result = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(5.0),
        )
        assert isinstance(result, PdfSuccess)
        assert isinstance(result.payload, RenderTilesPayload)
        assert store.resolve_asset(
            result.payload.value.manifest_relative_path
        ).is_file()
    else:
        with pytest.raises(PdfWorkerError, match=message):
            _ = await executor.execute(
                command,
                deadline=MonotonicDeadline.after(5.0),
            )


@pytest.mark.asyncio
async def test_parent_validates_and_publishes_render_outputs_manifest_last(
    tmp_path: Path,
) -> None:
    """Removing parent publication must leave no authoritative render result."""
    store = ContentAddressedStore(tmp_path / "authoritative")
    source = make_raster_pdf(tmp_path / "source.pdf", width=120, height=80, dpi=200)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = SubprocessPdfExecutor(store=store)
    command = RenderPagesCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000004"),
        operation="render_pages",
        source_relative_path=artifact.relative_path,
        parameters=RenderPagesParams(pages=(1,), mode="native"),
    )

    result = await executor.execute(command, deadline=MonotonicDeadline.after(15.0))

    assert isinstance(result, PdfSuccess)
    assert isinstance(result.payload, RenderPagesPayload)
    rendered = result.payload.value
    page = rendered.pages[0]
    page_path = store.resolve_asset(page.relative_path)
    manifest_path = store.resolve_asset(rendered.manifest_relative_path)
    assert page_path.stat().st_size > 0
    assert manifest_path.stat().st_size > 0

    repeated = await executor.execute(
        command,
        deadline=MonotonicDeadline.after(15.0),
    )
    assert repeated == result
    _ = page_path.write_bytes(b"tampered-authoritative-page")
    repaired = await executor.execute(
        command,
        deadline=MonotonicDeadline.after(15.0),
    )
    assert repaired == result
    assert store.resolve_asset(page.relative_path).read_bytes() != (
        b"tampered-authoritative-page"
    )
    assert list(store.root.parent.glob(".nplg-pdf-worker-*")) == []


@pytest.mark.asyncio
async def test_disposable_worker_reads_manifest_and_publishes_validated_tiles(
    tmp_path: Path,
) -> None:
    """Bypassing staged render inputs or tile publication must break parity."""
    store = ContentAddressedStore(tmp_path / "authoritative")
    source = make_raster_pdf(tmp_path / "source.pdf", width=600, height=400, dpi=200)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = SubprocessPdfExecutor(store=store)
    render = await executor.execute(
        RenderPagesCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000005"),
            operation="render_pages",
            source_relative_path=artifact.relative_path,
            parameters=RenderPagesParams(pages=(1,), mode="native"),
        ),
        deadline=MonotonicDeadline.after(15.0),
    )
    assert isinstance(render, PdfSuccess)
    assert isinstance(render.payload, RenderPagesPayload)
    render_id = render.payload.value.render_id

    manifest = await executor.execute(
        ManifestCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000006"),
            operation="manifest",
            parameters=ManifestParams(render_id=render_id),
        ),
        deadline=MonotonicDeadline.after(15.0),
    )
    tile_command = RenderTilesCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000007"),
        operation="render_tiles",
        parameters=RenderTilesParams(
            render_id=render_id,
            page_number=1,
            tile_width=256,
            tile_height=256,
            overlap=32,
        ),
    )
    tiled = await executor.execute(
        tile_command,
        deadline=MonotonicDeadline.after(15.0),
    )

    assert isinstance(manifest, PdfSuccess)
    assert isinstance(manifest.payload, ManifestPayload)
    assert manifest.payload.value == render.payload.value
    assert isinstance(tiled, PdfSuccess)
    assert isinstance(tiled.payload, RenderTilesPayload)
    assert tiled.payload.value.tiles
    for tile in tiled.payload.value.tiles:
        assert store.resolve_asset(tile.relative_path).stat().st_size > 0
    assert store.resolve_asset(tiled.payload.value.manifest_relative_path).is_file()

    repeated_tiles = await executor.execute(
        tile_command,
        deadline=MonotonicDeadline.after(15.0),
    )
    assert repeated_tiles == tiled
    first_tile_path = store.resolve_asset(tiled.payload.value.tiles[0].relative_path)
    _ = first_tile_path.write_bytes(b"tampered-authoritative-tile")
    repaired_tiles = await executor.execute(
        tile_command,
        deadline=MonotonicDeadline.after(15.0),
    )
    assert repaired_tiles == tiled
    assert store.resolve_asset(
        tiled.payload.value.tiles[0].relative_path
    ).read_bytes() != (b"tampered-authoritative-tile")
    assert list(store.root.parent.glob(".nplg-pdf-worker-*")) == []


@pytest.mark.asyncio
async def test_stderr_overflow_is_detected_without_waiting_for_the_deadline(
    tmp_path: Path,
) -> None:
    """Sequential pipe reads can deadlock when a hostile child fills stderr."""
    store = ContentAddressedStore(tmp_path / "cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nstderr-overflow-fixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    helper = Path(__file__).parents[1] / "fixtures" / "pdf_worker_stderr.py"
    executor = SubprocessPdfExecutor(
        store=store,
        worker_argv=(sys.executable, str(helper)),
    )
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000008"),
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )

    with pytest.raises(PdfWorkerError, match="stderr exceeded"):
        _ = await executor.execute(
            command,
            deadline=MonotonicDeadline.after(0.5),
        )
