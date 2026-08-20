# Copyright (c) 2026 David Osipov
"""Unit tests for bounded blocking-work lifetime accounting."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING, NoReturn, cast

import pytest

from nplg_mcp.bounded_work import BlockingWorkCapacityError, BoundedThreadRunner

if TYPE_CHECKING:
    from collections.abc import Awaitable


class _FailingExecutor:
    def submit(self, _operation: object) -> NoReturn:
        message = "synthetic submit failure"
        raise RuntimeError(message)


def _runner_became_idle(runner: BoundedThreadRunner) -> bool:
    deadline = time.monotonic() + 1.0
    while runner.active != 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    return runner.active == 0


@pytest.mark.parametrize("prefix", ["", "bad\x00prefix"])
def test_runner_rejects_invalid_thread_name_prefix(prefix: str) -> None:
    with pytest.raises(ValueError, match="thread_name_prefix"):
        _ = BoundedThreadRunner(capacity=1, thread_name_prefix=prefix)


def test_cancelled_worker_releases_capacity_after_origin_event_loop_closes() -> None:
    started = threading.Event()
    release = threading.Event()
    runner = BoundedThreadRunner(capacity=1, thread_name_prefix="test-bounded")

    def blocked() -> str:
        started.set()
        assert release.wait(timeout=2.0)
        return "finished"

    async def cancel_before_worker_finishes() -> None:
        task = asyncio.create_task(runner.run(blocked))
        assert await asyncio.to_thread(started.wait, 1.0)
        _ = task.cancel()
        with pytest.raises(asyncio.CancelledError):
            _ = await task

    asyncio.run(cancel_before_worker_finishes())
    assert runner.active == 1
    release.set()
    assert _runner_became_idle(runner)
    assert asyncio.run(runner.run(lambda: "recovered")) == "recovered"


@pytest.mark.asyncio
async def test_run_rejects_excess_work_without_queueing() -> None:
    started = threading.Event()
    release = threading.Event()
    runner = BoundedThreadRunner(capacity=1, thread_name_prefix="test-capacity")

    def blocked() -> None:
        started.set()
        assert release.wait(timeout=2.0)

    first = asyncio.create_task(runner.run(blocked))
    try:
        assert await asyncio.to_thread(started.wait, 1.0)
        rejected = cast("Awaitable[None]", runner.run(lambda: None))
        with pytest.raises(BlockingWorkCapacityError, match="capacity"):
            await rejected
    finally:
        release.set()
        await first


@pytest.mark.asyncio
async def test_run_to_completion_defers_cancellation_and_rejects_queueing() -> None:
    started = threading.Event()
    release = threading.Event()
    runner = BoundedThreadRunner(capacity=1, thread_name_prefix="test-completion")

    def blocked() -> str:
        started.set()
        assert release.wait(timeout=2.0)
        return "finished"

    first = asyncio.create_task(runner.run_to_completion(blocked))
    assert await asyncio.to_thread(started.wait, 1.0)
    rejected = cast(
        "Awaitable[str]",
        runner.run_to_completion(lambda: "must-not-run"),
    )
    with pytest.raises(BlockingWorkCapacityError, match="capacity"):
        _ = await rejected
    _ = first.cancel()
    await asyncio.sleep(0)
    assert not first.done()
    _ = first.cancel()
    await asyncio.sleep(0)
    assert not first.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        _ = await first
    assert runner.active == 0


@pytest.mark.asyncio
async def test_submit_failures_release_run_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = BoundedThreadRunner(capacity=1, thread_name_prefix="test-submit-run")
    monkeypatch.setattr(runner, "_executor", _FailingExecutor())
    failed = cast("Awaitable[None]", runner.run(lambda: None))

    with pytest.raises(RuntimeError, match="synthetic submit failure"):
        await failed

    assert runner.active == 0


@pytest.mark.asyncio
async def test_submit_failures_release_run_to_completion_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = BoundedThreadRunner(
        capacity=1,
        thread_name_prefix="test-submit-completion",
    )
    monkeypatch.setattr(runner, "_executor", _FailingExecutor())
    failed = cast("Awaitable[None]", runner.run_to_completion(lambda: None))

    with pytest.raises(RuntimeError, match="synthetic submit failure"):
        await failed

    assert runner.active == 0
