# Copyright (c) 2026 David Osipov
"""Instance-local upstream bulkhead and monotonic circuit breaker."""

from __future__ import annotations

import asyncio
import math
import random as random_module
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .contracts import MonotonicDeadline

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

_MAX_CAPACITY = 64
_MAX_FAILURE_THRESHOLD = 100
_MAX_OPEN_SECONDS = 3_600.0
_MAX_ATTEMPT_SECONDS = 59.0
_MAX_JITTER_RATIO = 0.5
_MAX_RETRY_AFTER_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class Closed:
    """Closed circuit state."""

    consecutive_failures: int = 0


@dataclass(frozen=True, slots=True)
class Open:
    """Open circuit state."""

    retry_at: float
    reopen_count: int


@dataclass(frozen=True, slots=True)
class HalfOpen:
    """Half-open circuit state with one admitted probe."""

    retry_at: float
    reopen_count: int


type CircuitState = Closed | Open | HalfOpen


@dataclass(frozen=True, slots=True)
class UpstreamGuardPolicy:
    """Closed policy for one instance-local upstream guard."""

    capacity: int = 2
    failure_threshold: int = 3
    base_open_seconds: float = 1.0
    max_open_seconds: float = 30.0
    max_attempt_seconds: float = 15.0
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        """Reject coercive or unbounded guard policy values."""
        valid = (
            type(self.capacity) is int
            and 1 <= self.capacity <= _MAX_CAPACITY
            and type(self.failure_threshold) is int
            and 1 <= self.failure_threshold <= _MAX_FAILURE_THRESHOLD
            and type(self.base_open_seconds) is float
            and math.isfinite(self.base_open_seconds)
            and 0.0 < self.base_open_seconds <= _MAX_OPEN_SECONDS
            and type(self.max_open_seconds) is float
            and math.isfinite(self.max_open_seconds)
            and self.base_open_seconds <= self.max_open_seconds <= _MAX_OPEN_SECONDS
            and type(self.max_attempt_seconds) is float
            and math.isfinite(self.max_attempt_seconds)
            and 0.0 < self.max_attempt_seconds <= _MAX_ATTEMPT_SECONDS
            and type(self.jitter_ratio) is float
            and math.isfinite(self.jitter_ratio)
            and 0.0 <= self.jitter_ratio <= _MAX_JITTER_RATIO
        )
        if not valid:
            message = "upstream guard policy is invalid"
            raise ValueError(message)


class UpstreamUnavailableError(RuntimeError):
    """Sanitized fail-fast decision from an upstream guard."""

    def __init__(self, retry_after_seconds: float) -> None:
        """Create one validated sanitized retry decision."""
        if (
            type(retry_after_seconds) is not float
            or not math.isfinite(retry_after_seconds)
            or not 0.0 < retry_after_seconds <= _MAX_RETRY_AFTER_SECONDS
        ):
            message = "retry decision is invalid"
            raise ValueError(message)
        self.retry_after_seconds = retry_after_seconds
        super().__init__("The upstream service is temporarily unavailable.")


class AttemptPermit:
    """One admitted upstream attempt with an explicit classified outcome."""

    __slots__ = (
        "_finalized",
        "_generation",
        "_guard",
        "_outcome_lock",
        "_probe",
        "deadline",
    )

    def __init__(
        self,
        *,
        guard: UpstreamGuard,
        deadline: MonotonicDeadline,
        probe: bool,
        generation: int,
    ) -> None:
        """Bind this permit to its guard, deadline, and probe classification."""
        super().__init__()
        self._guard = guard
        self.deadline = deadline
        self._probe = probe
        self._generation = generation
        self._finalized = False
        self._outcome_lock = asyncio.Lock()

    @property
    def finalized(self) -> bool:
        """Return whether the permit has recorded its one terminal outcome."""
        return self._finalized

    async def _record(
        self,
        outcome: Literal["success", "transient", "excluded"],
    ) -> None:
        async with self._outcome_lock:
            if self._finalized:
                message = "upstream attempt outcome was already recorded"
                raise RuntimeError(message)
            completion = asyncio.create_task(
                self._guard.complete_attempt(
                    probe=self._probe,
                    generation=self._generation,
                    outcome=outcome,
                )
            )
            cancellation: asyncio.CancelledError | None = None
            while not completion.done():
                try:
                    await asyncio.shield(completion)
                except asyncio.CancelledError as error:
                    cancellation = cancellation or error
                except Exception:  # noqa: BLE001 - defer until finalization.
                    break
            try:
                await completion
            except asyncio.CancelledError as error:
                cancellation = cancellation or error
            except Exception:
                self._finalized = True
                raise
            self._finalized = True
            if cancellation is not None:
                raise cancellation

    async def record_success(self) -> None:
        """Close/reset the circuit after a valid upstream response."""
        await self._record("success")

    async def record_transient_failure(self) -> None:
        """Count one reviewed timeout, connection, 429, or 5xx failure."""
        await self._record("transient")

    async def record_excluded_failure(self) -> None:
        """Release without counting excluded failures.

        Caller, validation, cancellation, and security failures are not upstream
        availability signals.
        """
        await self._record("excluded")


class _PermitContext:
    __slots__ = ("_deadline", "_guard", "_permit")

    def __init__(self, guard: UpstreamGuard, deadline: MonotonicDeadline) -> None:
        super().__init__()
        self._guard = guard
        self._deadline = deadline
        self._permit: AttemptPermit | None = None

    async def __aenter__(self) -> AttemptPermit:
        permit = await self._guard.admit(self._deadline)
        self._permit = permit
        return permit

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        permit = self._permit
        if permit is not None and not permit.finalized:
            await permit.record_excluded_failure()


class UpstreamGuard:
    """Bound concurrency and transient-failure amplification for one upstream."""

    __slots__ = (
        "_active",
        "_clock",
        "_generation",
        "_last_now",
        "_lock",
        "_observer",
        "_policy",
        "_random",
        "_state",
    )

    def __init__(
        self,
        *,
        policy: UpstreamGuardPolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
        random: Callable[[], float] | None = None,
        transition_observer: Callable[[str, str], None] | None = None,
    ) -> None:
        """Bind a strict policy and injected monotonic/random sources."""
        super().__init__()
        actual = policy or UpstreamGuardPolicy()
        self._policy = UpstreamGuardPolicy(
            capacity=actual.capacity,
            failure_threshold=actual.failure_threshold,
            base_open_seconds=actual.base_open_seconds,
            max_open_seconds=actual.max_open_seconds,
            max_attempt_seconds=actual.max_attempt_seconds,
            jitter_ratio=actual.jitter_ratio,
        )
        self._clock = clock
        self._random = random or random_module.random
        self._observer = transition_observer
        self._last_now: float | None = None
        self._lock = asyncio.Lock()
        self._active = 0
        self._generation: int = 0
        self._state: CircuitState = Closed()

    def _now(self) -> float:
        value = self._clock()
        if (
            type(value) is not float
            or not math.isfinite(value)
            or value < 0.0
            or (self._last_now is not None and value < self._last_now)
        ):
            message = "upstream guard monotonic clock is invalid"
            raise RuntimeError(message)
        self._last_now = value
        return value

    @property
    def state(self) -> CircuitState:
        """Return the current immutable circuit snapshot."""
        return self._state

    @staticmethod
    def _state_label(state: CircuitState) -> str:
        if isinstance(state, Closed):
            return "closed"
        if isinstance(state, Open):
            return "open"
        return "half_open"

    def _set_state(self, state: CircuitState) -> None:
        before = self._state_label(self._state)
        after = self._state_label(state)
        self._state = state
        if before != after and self._observer is not None:
            try:
                self._observer(before, after)
            except Exception:  # noqa: BLE001 - telemetry must never alter state.
                return

    @staticmethod
    def _unavailable(seconds: float) -> UpstreamUnavailableError:
        return UpstreamUnavailableError(
            min(_MAX_RETRY_AFTER_SECONDS, max(0.001, seconds))
        )

    def acquire(self, deadline: MonotonicDeadline) -> _PermitContext:
        """Admit one bounded attempt or return a sanitized fail-fast decision."""
        if type(deadline) is not MonotonicDeadline:
            message = "upstream deadline is invalid"
            raise TypeError(message)
        return _PermitContext(self, deadline)

    async def admit(self, deadline: MonotonicDeadline) -> AttemptPermit:
        """Perform the atomic state and bulkhead admission transition."""
        async with self._lock:
            now = self._now()
            request_remaining = deadline.remaining(now=now)
            if request_remaining <= 0.0:
                message = "upstream request deadline expired"
                raise TimeoutError(message)
            state = self._state
            probe = False
            half_open: HalfOpen | None = None
            if isinstance(state, Open):
                if now < state.retry_at:
                    raise self._unavailable(state.retry_at - now)
                if self._active >= self._policy.capacity:
                    raise self._unavailable(0.1)
                half_open = HalfOpen(
                    retry_at=state.retry_at,
                    reopen_count=state.reopen_count,
                )
                self._generation += 1
                probe = True
            elif isinstance(state, HalfOpen):
                raise self._unavailable(max(0.1, state.retry_at - now))
            elif self._active >= self._policy.capacity:
                raise self._unavailable(0.1)
            self._active += 1
            attempt_seconds = min(
                request_remaining,
                self._policy.max_attempt_seconds,
            )
            attempt_deadline = MonotonicDeadline(
                created_at=now,
                expires_at=now + attempt_seconds,
            )
            permit = AttemptPermit(
                guard=self,
                deadline=attempt_deadline,
                probe=probe,
                generation=self._generation,
            )
            if half_open is not None:
                try:
                    self._set_state(half_open)
                except asyncio.CancelledError:
                    self._active -= 1
                    self._generation += 1
                    self._state = Open(
                        retry_at=now,
                        reopen_count=half_open.reopen_count,
                    )
                    raise
            return permit

    def _open_interval(self, reopen_count: int) -> float:
        exponent = max(0, min(reopen_count - 1, 30))
        baseline = min(
            self._policy.max_open_seconds,
            self._policy.base_open_seconds * math.ldexp(1.0, exponent),
        )
        sample = self._random()
        if (
            type(sample) is not float
            or not math.isfinite(sample)
            or not 0.0 <= sample <= 1.0
        ):
            message = "upstream guard random sample is invalid"
            raise RuntimeError(message)
        factor = 1.0 + self._policy.jitter_ratio * ((2.0 * sample) - 1.0)
        return min(self._policy.max_open_seconds, baseline * factor)

    def _transient_reopen_count(
        self,
        *,
        state: CircuitState,
        probe: bool,
    ) -> int | None:
        if probe and isinstance(state, HalfOpen):
            return state.reopen_count + 1
        if isinstance(state, Closed):
            failures = state.consecutive_failures + 1
            if failures < self._policy.failure_threshold:
                self._set_state(Closed(consecutive_failures=failures))
                return None
            return 1
        return state.reopen_count + 1

    async def complete_attempt(
        self,
        *,
        probe: bool,
        generation: int,
        outcome: str,
    ) -> None:
        """Atomically release capacity and apply one classified outcome."""
        async with self._lock:
            if self._active <= 0:
                message = "upstream guard permit accounting is invalid"
                raise RuntimeError(message)
            self._active -= 1
            if generation != self._generation:
                return
            state = self._state
            if outcome == "success":
                if not isinstance(state, Closed):
                    self._generation += 1
                self._set_state(Closed())
                return
            if outcome == "excluded":
                if probe and isinstance(state, HalfOpen):
                    self._generation += 1
                    self._set_state(
                        Open(
                            retry_at=self._now(),
                            reopen_count=state.reopen_count,
                        )
                    )
                return
            if outcome != "transient":
                message = "upstream attempt outcome is invalid"
                raise RuntimeError(message)
            reopen_count = self._transient_reopen_count(state=state, probe=probe)
            if reopen_count is None:
                return
            self._generation += 1
            now = self._now()
            retry_at = now + self._open_interval(reopen_count)
            if not math.isfinite(retry_at) or retry_at <= now:
                message = "upstream guard retry deadline is invalid"
                raise RuntimeError(message)
            self._set_state(Open(retry_at=retry_at, reopen_count=reopen_count))
