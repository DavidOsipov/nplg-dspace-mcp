# Copyright (c) 2026 David Osipov
# pyright: reportPrivateUsage=false
"""Task 17 deterministic bulkhead and circuit-breaker tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.resilience import (
    Closed,
    HalfOpen,
    Open,
    UpstreamGuard,
    UpstreamGuardPolicy,
    UpstreamUnavailableError,
)

_MAX_RETRY_AFTER_SECONDS = 60.0
_FORGED_BOOLEAN: object = True


@dataclass(slots=True)
class _Clock:
    now: float = 10.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _deadline(clock: _Clock, seconds: float = 30.0) -> MonotonicDeadline:
    return MonotonicDeadline.after(seconds, clock=clock)


def _opaque(value: object) -> object:
    return value


def test_policy_rejects_coercive_and_unbounded_values() -> None:
    """Mutation caught: forged capacity, threshold, interval, deadline, or jitter."""
    invalid: tuple[Callable[[], UpstreamGuardPolicy], ...] = (
        lambda: UpstreamGuardPolicy(capacity=cast("int", _FORGED_BOOLEAN)),
        lambda: UpstreamGuardPolicy(capacity=0),
        lambda: UpstreamGuardPolicy(failure_threshold=0),
        lambda: UpstreamGuardPolicy(base_open_seconds=0.0),
        lambda: UpstreamGuardPolicy(max_open_seconds=3_601.0),
        lambda: UpstreamGuardPolicy(max_attempt_seconds=60.0),
        lambda: UpstreamGuardPolicy(jitter_ratio=1.0),
    )

    for create_policy in invalid:
        with pytest.raises(ValueError, match="guard policy"):
            _ = create_policy()


@pytest.mark.asyncio
async def test_expired_deadline_is_rejected_before_bulkhead_or_circuit_mutation() -> (
    None
):
    """Mutation caught: consuming capacity for an already-expired request."""
    clock = _Clock()
    guard = UpstreamGuard(clock=clock)
    expired = _deadline(clock, 0.0)

    with pytest.raises(TimeoutError):
        async with guard.acquire(expired):
            pytest.fail("expired request was admitted")

    final_state = guard.state
    assert final_state == Closed()


@pytest.mark.asyncio
async def test_bulkhead_saturation_fails_fast_without_consuming_request_capacity() -> (
    None
):
    """Mutation caught: queueing unboundedly when the per-upstream bulkhead is full."""
    clock = _Clock()
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(capacity=1),
        clock=clock,
        random=lambda: 0.5,
    )

    async with guard.acquire(_deadline(clock)) as first:
        with pytest.raises(UpstreamUnavailableError) as captured:
            async with guard.acquire(_deadline(clock)):
                pytest.fail("saturated bulkhead admitted a second attempt")
        await first.record_success()

    assert 0.0 < captured.value.retry_after_seconds <= _MAX_RETRY_AFTER_SECONDS
    async with guard.acquire(_deadline(clock)) as recovered:
        await recovered.record_success()


@pytest.mark.asyncio
async def test_only_classified_transient_failures_open_the_circuit() -> None:
    """Mutation caught: caller/local failures poisoning upstream circuit state."""
    clock = _Clock()
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=2),
        clock=clock,
        random=lambda: 0.5,
    )

    async with guard.acquire(_deadline(clock)) as excluded:
        await excluded.record_excluded_failure()
    excluded_state = guard.state
    assert excluded_state == Closed()

    async with guard.acquire(_deadline(clock)) as first:
        await first.record_transient_failure()
    first_failure_state = guard.state
    assert first_failure_state == Closed(consecutive_failures=1)

    async with guard.acquire(_deadline(clock)) as second:
        await second.record_transient_failure()
    opened_state = guard.state
    assert isinstance(opened_state, Open)

    with pytest.raises(UpstreamUnavailableError):
        async with guard.acquire(_deadline(clock)):
            pytest.fail("open circuit admitted ordinary traffic")


@pytest.mark.asyncio
async def test_exactly_one_half_open_probe_recovers_or_reopens_with_backoff() -> None:
    """Mutation caught: half-open stampede or failed probe closing the circuit."""
    clock = _Clock()
    policy = UpstreamGuardPolicy(
        capacity=3,
        failure_threshold=1,
        base_open_seconds=2.0,
        max_open_seconds=10.0,
    )
    guard = UpstreamGuard(policy=policy, clock=clock, random=lambda: 0.5)

    async with guard.acquire(_deadline(clock)) as failed:
        await failed.record_transient_failure()
    opened = guard.state
    assert isinstance(opened, Open)
    clock.now = opened.retry_at

    async with guard.acquire(_deadline(clock)) as probe:
        probing_state = guard.state
        assert isinstance(probing_state, HalfOpen)
        with pytest.raises(UpstreamUnavailableError):
            async with guard.acquire(_deadline(clock)):
                pytest.fail("second half-open probe was admitted")
        await probe.record_transient_failure()

    reopened = _opaque(guard.state)
    assert isinstance(reopened, Open)
    assert reopened.retry_at > opened.retry_at
    clock.now = reopened.retry_at
    async with guard.acquire(_deadline(clock)) as recovery:
        await recovery.record_success()
    recovered_state = guard.state
    assert recovered_state == Closed()


@pytest.mark.asyncio
async def test_cancellation_releases_capacity_without_counting_a_failure() -> None:
    """Mutation caught: cancellation leaking a permit or incrementing failures."""
    clock = _Clock()
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(capacity=1),
        clock=clock,
        random=lambda: 0.5,
    )

    with pytest.raises(asyncio.CancelledError):
        async with guard.acquire(_deadline(clock)):
            raise asyncio.CancelledError

    cancelled_state = guard.state
    assert cancelled_state == Closed()
    async with guard.acquire(_deadline(clock)) as permit:
        await permit.record_success()


@pytest.mark.asyncio
async def test_unrelated_upstream_guard_instances_do_not_share_state() -> None:
    """Mutation caught: process-global circuit state coupling unrelated upstreams."""
    clock = _Clock()
    first = UpstreamGuard(policy=UpstreamGuardPolicy(failure_threshold=1), clock=clock)
    second = UpstreamGuard(policy=UpstreamGuardPolicy(failure_threshold=1), clock=clock)

    async with first.acquire(_deadline(clock)) as failed:
        await failed.record_transient_failure()

    first_state = first.state
    second_state = second.state
    assert isinstance(first_state, Open)
    assert second_state == Closed()
    async with second.acquire(_deadline(clock)) as successful:
        await successful.record_success()


@pytest.mark.asyncio
async def test_older_attempt_cannot_close_a_newer_open_generation() -> None:
    """Mutation caught: stale success closing a circuit opened by its sibling."""
    clock = _Clock()
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(capacity=2, failure_threshold=1),
        clock=clock,
        random=lambda: 0.5,
    )

    async with guard.acquire(_deadline(clock)) as older:
        async with guard.acquire(_deadline(clock)) as failing:
            await failing.record_transient_failure()
        opened = guard.state
        assert isinstance(opened, Open)
        await older.record_success()

    final_state = guard.state
    assert final_state == opened


@pytest.mark.asyncio
async def test_transition_observer_emits_only_low_cardinality_state_labels() -> None:
    """Mutation caught: absent or payload-bearing circuit transition telemetry."""
    clock = _Clock()
    events: list[tuple[str, str]] = []
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        clock=clock,
        random=lambda: 0.5,
        transition_observer=lambda before, after: events.append((before, after)),
    )

    async with guard.acquire(_deadline(clock)) as failed:
        await failed.record_transient_failure()
    opened = guard.state
    assert isinstance(opened, Open)
    clock.now = opened.retry_at
    async with guard.acquire(_deadline(clock)) as probe:
        await probe.record_success()

    assert events == [
        ("closed", "open"),
        ("open", "half_open"),
        ("half_open", "closed"),
    ]


@pytest.mark.asyncio
async def test_raising_transition_observer_cannot_strand_recovery_state() -> None:
    """Mutation caught: telemetry failure aborting a half-open admission."""
    clock = _Clock()

    def raising_observer(before: str, after: str) -> None:
        if (before, after) == ("open", "half_open"):
            message = "observer payload must not escape"
            raise RuntimeError(message)

    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        clock=clock,
        random=lambda: 0.5,
        transition_observer=raising_observer,
    )

    async with guard.acquire(_deadline(clock)) as failed:
        await failed.record_transient_failure()
    opened = guard.state
    assert isinstance(opened, Open)

    clock.now = opened.retry_at
    async with guard.acquire(_deadline(clock)) as recovery:
        assert isinstance(guard.state, HalfOpen)
        await recovery.record_success()

    final_state: object = guard.state
    assert isinstance(final_state, Closed)


@pytest.mark.asyncio
async def test_cancelling_observer_releases_half_open_probe_before_reraise() -> None:
    """Mutation caught: cancellation stranding half-open state or guard capacity."""
    clock = _Clock()
    cancellations = 0

    def cancelling_observer(before: str, after: str) -> None:
        nonlocal cancellations
        if (before, after) == ("open", "half_open") and cancellations == 0:
            cancellations += 1
            raise asyncio.CancelledError

    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(capacity=1, failure_threshold=1),
        clock=clock,
        random=lambda: 0.5,
        transition_observer=cancelling_observer,
    )
    async with guard.acquire(_deadline(clock)) as failed:
        await failed.record_transient_failure()
    opened = guard.state
    assert isinstance(opened, Open)
    clock.now = opened.retry_at

    with pytest.raises(asyncio.CancelledError):
        _ = await guard.admit(_deadline(clock))

    assert cancellations == 1
    reopened: object = guard.state
    assert isinstance(reopened, Open)
    async with guard.acquire(_deadline(clock)) as recovery:
        half_open: object = guard.state
        assert isinstance(half_open, HalfOpen)
        await recovery.record_success()
    closed: object = guard.state
    assert isinstance(closed, Closed)


@pytest.mark.parametrize(
    "retry_after",
    [cast("float", _FORGED_BOOLEAN), 0.0, float("nan"), float("inf"), 61.0],
)
def test_retry_decision_rejects_nonexact_nonfinite_or_unbounded_values(
    retry_after: float,
) -> None:
    """Mutation caught: coercing an unsafe public Retry-After decision."""
    with pytest.raises(ValueError, match="retry decision"):
        _ = UpstreamUnavailableError(retry_after)


@pytest.mark.asyncio
async def test_permit_rejects_a_duplicate_terminal_outcome() -> None:
    """Mutation caught: applying two outcomes and releasing one permit twice."""
    clock = _Clock()
    guard = UpstreamGuard(clock=clock)

    async with guard.acquire(_deadline(clock)) as permit:
        await permit.record_success()
        with pytest.raises(RuntimeError, match="already recorded"):
            await permit.record_excluded_failure()


@pytest.mark.asyncio
async def test_cancelled_outcome_waiting_for_guard_lock_completes_accounting() -> None:
    """Mutation caught: finalized-before-accounting leaking guard capacity."""
    clock = _Clock()
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(capacity=1),
        clock=clock,
    )
    permit = await guard.admit(_deadline(clock))
    _ = await guard._lock.acquire()  # noqa: SLF001 - deterministic contention.
    recording = asyncio.create_task(permit.record_success())
    try:
        await asyncio.sleep(0)
        assert _opaque(permit.finalized) is False
        _ = recording.cancel()
        await asyncio.sleep(0)
        assert not recording.done()
        assert _opaque(permit.finalized) is False
    finally:
        guard._lock.release()  # noqa: SLF001 - release deterministic contention.

    with pytest.raises(asyncio.CancelledError):
        await recording
    assert _opaque(permit.finalized) is True
    final_state: object = guard.state
    assert isinstance(final_state, Closed)
    async with guard.acquire(_deadline(clock)) as next_permit:
        await next_permit.record_excluded_failure()


@pytest.mark.asyncio
async def test_repeated_cancellation_cannot_cancel_contended_outcome_accounting() -> (
    None
):
    """Mutation caught: second cancellation killing private permit accounting."""
    clock = _Clock()
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(capacity=1),
        clock=clock,
    )
    permit = await guard.admit(_deadline(clock))
    _ = await guard._lock.acquire()  # noqa: SLF001 - deterministic contention.
    recording = asyncio.create_task(permit.record_success())
    try:
        await asyncio.sleep(0)
        _ = recording.cancel()
        await asyncio.sleep(0)
        assert not recording.done()
        _ = recording.cancel()
        await asyncio.sleep(0)
        assert not recording.done()
        assert _opaque(permit.finalized) is False
    finally:
        guard._lock.release()  # noqa: SLF001 - release deterministic contention.

    with pytest.raises(asyncio.CancelledError):
        await recording
    assert _opaque(permit.finalized) is True
    final_state: object = guard.state
    assert isinstance(final_state, Closed)
    async with guard.acquire(_deadline(clock)) as next_permit:
        await next_permit.record_excluded_failure()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_now",
    [cast("float", _FORGED_BOOLEAN), -1.0, float("nan")],
)
async def test_guard_rejects_invalid_or_nonmonotonic_clock_values(
    invalid_now: float,
) -> None:
    """Mutation caught: circuit mutation driven by a forged monotonic clock."""
    guard = UpstreamGuard(clock=lambda: invalid_now)
    with pytest.raises(RuntimeError, match="monotonic clock"):
        async with guard.acquire(MonotonicDeadline(created_at=0.0, expires_at=30.0)):
            pytest.fail("invalid clock admitted work")

    clock = _Clock()
    rollback_guard = UpstreamGuard(clock=clock)
    async with rollback_guard.acquire(_deadline(clock)) as permit:
        await permit.record_success()
    clock.now -= 1.0
    with pytest.raises(RuntimeError, match="monotonic clock"):
        async with rollback_guard.acquire(_deadline(clock)):
            pytest.fail("regressed clock admitted work")


def test_guard_rejects_a_forged_deadline_type() -> None:
    """Mutation caught: coercing caller-controlled deadline objects."""
    guard = UpstreamGuard()
    with pytest.raises(TypeError, match="deadline"):
        _ = guard.acquire(cast("MonotonicDeadline", object()))


@pytest.mark.asyncio
async def test_excluded_half_open_probe_reopens_without_counting_failure() -> None:
    """Mutation caught: excluded probe leaving the circuit stuck half-open."""
    clock = _Clock()
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        clock=clock,
        random=lambda: 0.5,
    )
    async with guard.acquire(_deadline(clock)) as failed:
        await failed.record_transient_failure()
    opened = guard.state
    assert isinstance(opened, Open)
    clock.now = opened.retry_at

    async with guard.acquire(_deadline(clock)):
        assert isinstance(guard.state, HalfOpen)

    reopened = _opaque(guard.state)
    assert isinstance(reopened, Open)
    assert reopened.retry_at == clock.now


@pytest.mark.asyncio
async def test_guard_rejects_invalid_random_outcome_and_internal_accounting() -> None:
    """Mutation caught: invalid entropy/outcome/accounting silently corrupting state."""
    clock = _Clock()
    bad_random = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        clock=clock,
        random=lambda: float("nan"),
    )
    async with bad_random.acquire(_deadline(clock)) as permit:
        with pytest.raises(RuntimeError, match="random sample"):
            await permit.record_transient_failure()

    invalid_outcome = UpstreamGuard(clock=clock)
    permit = await invalid_outcome.admit(_deadline(clock))
    with pytest.raises(RuntimeError, match="outcome"):
        await invalid_outcome.complete_attempt(
            probe=False,
            generation=0,
            outcome="forged",
        )
    assert not permit.finalized

    with pytest.raises(RuntimeError, match="accounting"):
        await invalid_outcome.complete_attempt(
            probe=False,
            generation=0,
            outcome="success",
        )


@pytest.mark.asyncio
async def test_open_state_defensive_paths_remain_fail_closed() -> None:
    """Mutation caught: admitting at-capacity recovery or mishandling Open outcome."""
    clock = _Clock()
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(capacity=2, failure_threshold=1),
        clock=clock,
        random=lambda: 0.5,
    )
    older = await guard.admit(_deadline(clock))
    opener = await guard.admit(_deadline(clock))
    await opener.record_transient_failure()
    opened = guard.state
    assert isinstance(opened, Open)
    clock.now = opened.retry_at

    guard._active = 2  # noqa: SLF001 - exercise defensive at-capacity branch.
    with pytest.raises(UpstreamUnavailableError):
        _ = await guard.admit(_deadline(clock))

    guard._active = 1  # noqa: SLF001 - restore the one outstanding older permit.
    await older.record_excluded_failure()

    direct = UpstreamGuard(clock=clock, random=lambda: 0.5)
    direct_permit = await direct.admit(_deadline(clock))
    direct._state = Open(retry_at=clock.now + 1.0, reopen_count=1)  # noqa: SLF001
    await direct_permit.record_transient_failure()
    assert isinstance(direct.state, Open)


@pytest.mark.asyncio
async def test_retry_deadline_must_advance_the_monotonic_clock() -> None:
    """Mutation caught: accepting a rounded or overflowing retry deadline."""
    huge = float.fromhex("0x1.fffffffffffffp+1023")
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        clock=lambda: huge,
        random=lambda: 0.5,
    )
    guard._active = 1  # noqa: SLF001 - exercise defensive invariant.
    with pytest.raises(RuntimeError, match="retry deadline"):
        await guard.complete_attempt(
            probe=False,
            generation=0,
            outcome="transient",
        )
