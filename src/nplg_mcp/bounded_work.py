# Copyright (c) 2026 David Osipov
"""Bound synchronous work without sharing the event loop's default executor."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from .admission import AdmissionGate

if TYPE_CHECKING:
    from collections.abc import Callable


class BlockingWorkCapacityError(RuntimeError):
    """Reject work when every bounded worker remains occupied."""


class BoundedThreadRunner:
    """Run uncancellable synchronous calls behind a fail-fast lifetime gate."""

    def __init__(self, *, capacity: int, thread_name_prefix: str) -> None:
        """Create a dedicated pool whose permits follow real worker lifetime."""
        super().__init__()
        if not thread_name_prefix or "\x00" in thread_name_prefix:
            message = "thread_name_prefix must be non-empty and contain no NUL"
            raise ValueError(message)
        self._gate = AdmissionGate(capacity)
        self._executor = ThreadPoolExecutor(
            max_workers=capacity,
            thread_name_prefix=thread_name_prefix,
        )

    @property
    def active(self) -> int:
        """Return jobs whose underlying worker call has not completed."""
        return self._gate.active

    async def run[ResultT](self, operation: Callable[[], ResultT]) -> ResultT:
        """Submit immediately and retain capacity after caller cancellation."""
        if not self._gate.try_acquire():
            message = "bounded blocking-work capacity is exhausted"
            raise BlockingWorkCapacityError(message)
        loop = asyncio.get_running_loop()
        try:
            concurrent_future = self._executor.submit(operation)
        except BaseException:
            self._gate.release()
            raise
        concurrent_future.add_done_callback(self._release_permit)
        future = asyncio.wrap_future(concurrent_future, loop=loop)
        return await asyncio.shield(future)

    async def run_to_completion[ResultT](
        self,
        operation: Callable[[], ResultT],
    ) -> ResultT:
        """Keep the caller alive until storage state is safe to abandon."""
        if not self._gate.try_acquire():
            message = "bounded blocking-work capacity is exhausted"
            raise BlockingWorkCapacityError(message)
        loop = asyncio.get_running_loop()
        completed = asyncio.Event()
        try:
            concurrent_future = self._executor.submit(operation)
        except BaseException:
            self._gate.release()
            raise
        concurrent_future.add_done_callback(self._release_permit)
        concurrent_future.add_done_callback(
            lambda _completed: loop.call_soon_threadsafe(completed.set)
        )
        future = asyncio.wrap_future(concurrent_future, loop=loop)
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            while not concurrent_future.done():
                try:
                    _ = await completed.wait()
                except asyncio.CancelledError:
                    continue
            _ = concurrent_future.exception()
            raise

    def _release_permit(self, _completed: object) -> None:
        """Release capacity from the worker thread, independent of event loops."""
        self._gate.release()


DNS_WORK = BoundedThreadRunner(capacity=1, thread_name_prefix="nplg-dns")
PARSER_WORK = BoundedThreadRunner(capacity=1, thread_name_prefix="nplg-parser")
READINESS_WORK = BoundedThreadRunner(capacity=1, thread_name_prefix="nplg-readiness")
STORAGE_WORK = BoundedThreadRunner(capacity=2, thread_name_prefix="nplg-storage")
