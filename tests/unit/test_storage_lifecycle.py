# Copyright (c) 2026 David Osipov
"""Strict lifecycle, capacity, and trustworthy-clock contracts."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event, Lock
from typing import TYPE_CHECKING, Protocol, cast

import pytest
from pydantic import ValidationError

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.storage import ContentAddressedStore, StoreLifecycleConfiguration
from nplg_mcp.storage_lifecycle import (
    INSERTION_HIGH_WATER_FILENAME,
    INSERTION_SEQUENCE_FILENAME,
    ClockAssessment,
    ClockBlocker,
    ClockHighWater,
    InsertionHighWaterRecord,
    InsertionSequenceRecord,
    LifecycleAlert,
    LifecycleAlertEvent,
    LifecycleBlocker,
    PersistentInsertionOrder,
    PruneBlocker,
    PublicationBlocker,
    PublicationReservationError,
    RetentionClockSample,
    RetentionPolicy,
    StorageCapacity,
    SystemRetentionClock,
    UnsatisfiedPruneReport,
    filesystem_capacity,
    validate_retention_capacity,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class _StrictModelType(Protocol):
    @classmethod
    def model_validate(cls, value: object, *, strict: bool) -> object: ...


class _ClockStateWriter(Protocol):
    def __call__(
        self,
        directory: int,
        record: object,
        *,
        require_absent: bool = False,
    ) -> None: ...


_GIB = 1024 * 1024 * 1024
_FOUR_BYTES = 4
_CLOCK_TEST_ADVANCE_SECONDS = 120
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_STATE_MODE = 0o600
_NON_PRIVATE_STATE_MODE = 0o666
_CLOCK_ORIGIN = datetime.now(UTC)
_POLICY = RetentionPolicy(
    maximum_age_seconds=3600,
    maximum_bytes=_GIB,
    maximum_objects=1000,
    minimum_free_bytes=64 * 1024 * 1024,
    minimum_free_inodes=128,
)
_CAPACITY = StorageCapacity(
    total_bytes=4 * _GIB,
    available_bytes=3 * _GIB,
    total_inodes=100_000,
    available_inodes=90_000,
)


def _policy_payload() -> dict[str, object]:
    return {
        "maximum_age_seconds": _POLICY.maximum_age_seconds,
        "maximum_bytes": _POLICY.maximum_bytes,
        "maximum_objects": _POLICY.maximum_objects,
        "minimum_free_bytes": _POLICY.minimum_free_bytes,
        "minimum_free_inodes": _POLICY.minimum_free_inodes,
    }


def _sample(
    *,
    seconds: float,
    wall_seconds: float | None = None,
    boot_id: str = "boot-a",
    synchronized: bool = True,
) -> RetentionClockSample:
    applied_wall_seconds = seconds if wall_seconds is None else wall_seconds
    return RetentionClockSample(
        utc_now=_CLOCK_ORIGIN + timedelta(seconds=applied_wall_seconds),
        monotonic_now=float(seconds),
        boot_id=boot_id,
        synchronized=synchronized,
    )


def _zero_write(_descriptor: int, _raw: bytes) -> int:
    return 0


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            StorageCapacity,
            {
                "total_bytes": True,
                "available_bytes": 1,
                "total_inodes": 1,
                "available_inodes": 1,
            },
        ),
        (
            StorageCapacity,
            {
                "total_bytes": 1,
                "available_bytes": 1,
                "total_inodes": 1,
                "available_inodes": 2,
            },
        ),
        (
            StorageCapacity,
            {
                "total_bytes": 1,
                "available_bytes": 2,
                "total_inodes": 1,
                "available_inodes": 1,
            },
        ),
        (
            RetentionPolicy,
            {
                **_policy_payload(),
                "maximum_age_seconds": "3600",
            },
        ),
        (
            RetentionPolicy,
            {
                **_policy_payload(),
                "unexpected": 1,
            },
        ),
    ],
)
def test_lifecycle_models_reject_coercion_impossible_counts_and_extra_fields(
    model: type[_StrictModelType],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _ = model.model_validate(payload, strict=True)


@pytest.mark.parametrize(
    ("configured_max", "capacity", "message"),
    [
        (_GIB - 1, _CAPACITY, "maximum_bytes"),
        (
            2 * _GIB,
            StorageCapacity(
                total_bytes=_GIB + 64 * 1024 * 1024 - 1,
                available_bytes=_GIB,
                total_inodes=100_000,
                available_inodes=90_000,
            ),
            "byte reserve",
        ),
        (
            2 * _GIB,
            StorageCapacity(
                total_bytes=4 * _GIB,
                available_bytes=3 * _GIB,
                total_inodes=128,
                available_inodes=128,
            ),
            "inode reserve",
        ),
    ],
)
def test_impossible_retention_capacity_fails_startup(
    configured_max: int,
    capacity: StorageCapacity,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_retention_capacity(
            _POLICY,
            configured_cache_max_bytes=configured_max,
            capacity=capacity,
        )


def test_exact_retention_capacity_boundary_is_accepted() -> None:
    validate_retention_capacity(
        _POLICY,
        configured_cache_max_bytes=_GIB,
        capacity=StorageCapacity(
            total_bytes=_GIB + 64 * 1024 * 1024,
            available_bytes=_GIB,
            total_inodes=129,
            available_inodes=128,
        ),
    )


def test_clock_high_water_requires_a_healthy_window_and_survives_restart(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    first = guard.observe(_sample(seconds=0))
    warming = guard.observe(_sample(seconds=30))
    trusted = guard.observe(_sample(seconds=60))
    restarted = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    ).observe(_sample(seconds=61))

    assert (first.trusted, first.blocker) == (False, ClockBlocker.MISSING_STATE)
    assert (warming.trusted, warming.blocker) == (False, ClockBlocker.WARMING_UP)
    assert (trusted.trusted, trusted.blocker) == (True, None)
    assert (restarted.trusted, restarted.blocker) == (True, None)


def test_clock_rollback_closes_admission_until_a_new_healthy_window(
    tmp_path: Path,
) -> None:
    guard = ClockHighWater(
        tmp_path / "clock-high-water.json",
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    _ = guard.observe(_sample(seconds=0))
    assert guard.observe(_sample(seconds=60)).trusted is True

    rolled_back = guard.observe(_sample(seconds=61, wall_seconds=50))
    warming = guard.observe(_sample(seconds=121, wall_seconds=110))
    recovered = guard.observe(_sample(seconds=181, wall_seconds=170))

    assert (rolled_back.trusted, rolled_back.blocker) == (
        False,
        ClockBlocker.WALL_ROLLBACK,
    )
    assert (warming.trusted, warming.blocker) == (False, ClockBlocker.WARMING_UP)
    assert (recovered.trusted, recovered.blocker) == (True, None)


def test_monotonic_rollback_cannot_reuse_a_previously_trusted_window(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    _ = guard.observe(_sample(seconds=0))
    assert guard.observe(_sample(seconds=60)).trusted is True

    rolled_back = guard.observe(_sample(seconds=59, wall_seconds=61))
    restarted = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    warming = restarted.observe(_sample(seconds=61, wall_seconds=63))
    recovered = restarted.observe(_sample(seconds=121, wall_seconds=123))

    assert (rolled_back.trusted, rolled_back.blocker) == (
        False,
        ClockBlocker.MONOTONIC_ROLLBACK,
    )
    assert (warming.trusted, warming.blocker) == (False, ClockBlocker.WARMING_UP)
    assert (recovered.trusted, recovered.blocker) == (True, None)


def test_clock_state_rejects_non_private_mode_without_laundering(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    _ = guard.observe(_sample(seconds=0))
    assert guard.observe(_sample(seconds=60)).trusted is True
    original = state.read_bytes()
    state.chmod(_NON_PRIVATE_STATE_MODE)

    result = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    ).observe(_sample(seconds=61))

    assert (result.trusted, result.blocker) == (False, ClockBlocker.CORRUPT_STATE)
    assert state.read_bytes() == original
    assert state.stat().st_mode & 0o777 == _NON_PRIVATE_STATE_MODE


def test_lifecycle_state_writers_enforce_private_mode_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    state = tmp_path / ".retention-clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    previous_umask = os.umask(0o777)
    try:
        initial = _sample(seconds=0)
        assert guard.observe(initial).trusted is False
        assert guard.observe(initial).trusted is True
        store = ContentAddressedStore(
            tmp_path,
            max_bytes=_GIB,
            lifecycle=StoreLifecycleConfiguration(
                policy=_POLICY,
                capacity_sampler=lambda: _CAPACITY,
                clock_high_water=guard,
                clock_sampler=lambda: _sample(seconds=_CLOCK_TEST_ADVANCE_SECONDS),
            ),
        )
        artifact = store.put_bytes(
            b"document",
            namespace="documents",
            filename="source.pdf",
            media_type="application/pdf",
        )
    finally:
        _ = os.umask(previous_umask)

    for path in (
        state,
        tmp_path / INSERTION_HIGH_WATER_FILENAME,
        artifact.absolute_path.parent / INSERTION_SEQUENCE_FILENAME,
    ):
        assert path.stat().st_mode & 0o777 == _PRIVATE_STATE_MODE


@pytest.mark.parametrize(
    ("sample", "blocker"),
    [
        (_sample(seconds=1, synchronized=False), ClockBlocker.UNSYNCHRONIZED),
        (_sample(seconds=1, boot_id="boot-b"), ClockBlocker.BOOT_CHANGED),
        (_sample(seconds=1, wall_seconds=100), ClockBlocker.FORWARD_STEP),
    ],
)
def test_clock_anomalies_fail_closed(
    tmp_path: Path,
    sample: RetentionClockSample,
    blocker: ClockBlocker,
) -> None:
    guard = ClockHighWater(
        tmp_path / "clock-high-water.json",
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    _ = guard.observe(_sample(seconds=0))

    result = guard.observe(sample)

    assert (result.trusted, result.blocker) == (False, blocker)


def test_clock_sample_requires_exact_utc_and_finite_strict_monotonic() -> None:
    for utc_now, monotonic_now in (
        (datetime(2026, 8, 25, tzinfo=UTC).replace(tzinfo=None), 1.0),
        (datetime(2026, 8, 25, tzinfo=timezone(timedelta(hours=1))), 1.0),
        (datetime(2026, 8, 25, tzinfo=UTC), True),
        (datetime(2026, 8, 25, tzinfo=UTC), float("inf")),
    ):
        with pytest.raises(ValidationError):
            _ = RetentionClockSample(
                utc_now=utc_now,
                monotonic_now=monotonic_now,
                boot_id="boot-a",
                synchronized=True,
            )


class _MutableCapacity:
    def __init__(self, value: StorageCapacity) -> None:
        super().__init__()
        self.value = value

    def __call__(self) -> StorageCapacity:
        return self.value


class _MutableClock:
    def __init__(self, value: RetentionClockSample) -> None:
        super().__init__()
        self.value = value

    def __call__(self) -> RetentionClockSample:
        return self.value


def _set_tree_mtime(path: Path, *, seconds_before_origin: int) -> None:
    timestamp = (_CLOCK_ORIGIN - timedelta(seconds=seconds_before_origin)).timestamp()
    for directory, directories, files in os.walk(path):
        base = Path(directory)
        for name in (*directories, *files):
            os.utime(base / name, (timestamp, timestamp))
    os.utime(path, (timestamp, timestamp))


def _lifecycle_store(
    tmp_path: Path,
    *,
    policy: RetentionPolicy,
    configured_max: int,
    capacity: _MutableCapacity,
) -> tuple[ContentAddressedStore, _MutableClock]:
    state_path = tmp_path / ".retention-clock-high-water.json"
    guard = ClockHighWater(
        state_path,
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    first = _sample(seconds=0)
    assert guard.observe(first).trusted is False
    assert guard.observe(first).trusted is True
    clock = _MutableClock(_sample(seconds=_CLOCK_TEST_ADVANCE_SECONDS))
    return (
        ContentAddressedStore(
            tmp_path,
            max_bytes=configured_max,
            lifecycle=StoreLifecycleConfiguration(
                policy=policy,
                capacity_sampler=capacity,
                clock_high_water=guard,
                clock_sampler=clock,
            ),
        ),
        clock,
    )


@pytest.mark.parametrize("replacement_kind", ["directory", "symlink"])
def test_lifecycle_rejects_store_root_identity_drift_before_sampling_or_pruning(
    tmp_path: Path,
    replacement_kind: str,
) -> None:
    root = tmp_path / "cache"
    capacity = _MutableCapacity(_CAPACITY)
    store, clock = _lifecycle_store(
        root,
        policy=_POLICY,
        configured_max=_GIB,
        capacity=capacity,
    )
    held_root = tmp_path / "held-cache"
    _ = root.rename(held_root)
    if replacement_kind == "directory":
        root.mkdir(mode=0o700)
        for name in (".staging", "documents", "renders"):
            (root / name).mkdir(mode=0o700)
    else:
        root.symlink_to(held_root, target_is_directory=True)

    with pytest.raises(AppError, match="storage root") as caught:
        _ = store.prune(_POLICY, clock=clock())

    assert caught.value.code is ErrorCode.INTERNAL_ERROR
    assert str(root) not in str(caught.value)
    if replacement_kind == "directory":
        assert not (root / ".retention-clock-high-water.json").exists()


@pytest.mark.asyncio
async def test_publication_rejects_root_drift_before_clock_or_staging_side_effects(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    store, clock = _lifecycle_store(
        root,
        policy=_POLICY,
        configured_max=_GIB,
        capacity=_MutableCapacity(_CAPACITY),
    )
    held_root = tmp_path / "held-cache"
    _ = root.rename(held_root)
    root.mkdir(mode=0o700)
    for name in (".staging", "documents", "renders"):
        (root / name).mkdir(mode=0o700)

    with pytest.raises(AppError, match="storage root"):
        async with store.reserve_publication(
            _POLICY,
            maximum_new_bytes=1,
            maximum_new_objects=1,
            maximum_new_inodes=1,
            clock=clock(),
        ):
            pytest.fail("root drift must reject before entering the reservation")

    assert not (root / ".retention-clock-high-water.json").exists()
    assert tuple((root / ".staging").iterdir()) == ()
    assert store.publication_reserved_bytes == 0
    assert store.publication_reserved_objects == 0
    assert store.publication_reserved_inodes == 0


@pytest.mark.asyncio
async def test_publication_commit_rechecks_the_held_root_identity_exactly_once(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    store, clock = _lifecycle_store(
        root,
        policy=_POLICY,
        configured_max=_GIB,
        capacity=_MutableCapacity(_CAPACITY),
    )
    reservation_context = store.reserve_publication(
        _POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )
    reservation = await reservation_context.__aenter__()
    held_root = tmp_path / "held-cache"
    _ = root.rename(held_root)
    root.mkdir(mode=0o700)
    for name in (".staging", "documents", "renders"):
        (root / name).mkdir(mode=0o700)

    try:
        with pytest.raises(AppError, match="storage root"):
            await reservation.commit(
                actual_bytes=0,
                actual_objects=0,
                actual_inodes=0,
            )
    finally:
        await reservation_context.__aexit__(None, None, None)

    assert not (root / ".retention-clock-high-water.json").exists()
    assert store.publication_reserved_bytes == 0
    assert store.publication_reserved_objects == 0
    assert store.publication_reserved_inodes == 0


@pytest.mark.asyncio
async def test_restart_removes_crashed_staging_and_reconstructs_reservations_empty(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    capacity = _MutableCapacity(_CAPACITY)
    crashed, clock = _lifecycle_store(
        root,
        policy=_POLICY,
        configured_max=_GIB,
        capacity=capacity,
    )
    reservation_context = crashed.reserve_publication(
        _POLICY,
        maximum_new_bytes=_FOUR_BYTES,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )
    reservation = await reservation_context.__aenter__()
    writer = crashed.stage(suffix=".bin")
    _ = writer.__enter__()
    assert writer.write(b"lost") == _FOUR_BYTES
    orphan = next(iter(crashed.staging_dir.iterdir()))
    assert crashed.reserved_bytes == _FOUR_BYTES
    assert crashed.publication_reserved_bytes == _FOUR_BYTES

    try:
        restarted = ContentAddressedStore(
            root,
            max_bytes=_GIB,
            lifecycle=StoreLifecycleConfiguration(
                policy=_POLICY,
                capacity_sampler=capacity,
                clock_high_water=ClockHighWater(
                    root / ".retention-clock-high-water.json",
                    healthy_window_seconds=0,
                    maximum_forward_slew_seconds=5,
                ),
                clock_sampler=clock,
            ),
        )

        assert not orphan.exists()
        assert tuple(restarted.staging_dir.iterdir()) == ()
        assert restarted.reserved_bytes == 0
        assert restarted.publication_reserved_bytes == 0
        assert restarted.publication_reserved_objects == 0
        assert restarted.publication_reserved_inodes == 0
    finally:
        writer.__exit__(None, None, None)
        await reservation_context.__aexit__(None, None, None)

    assert reservation.closed
    assert crashed.reserved_bytes == 0
    assert crashed.publication_reserved_bytes == 0


@pytest.mark.asyncio
async def test_concurrent_publication_reservations_are_atomic_and_exact_once(
    tmp_path: Path,
) -> None:
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=10,
        maximum_objects=2,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=64 * 1024 * 1024 + 10,
            available_bytes=64 * 1024 * 1024 + 10,
            total_inodes=1000,
            available_inodes=1000,
        )
    )
    store, clock = _lifecycle_store(
        tmp_path,
        policy=policy,
        configured_max=10,
        capacity=capacity,
    )

    async with store.reserve_publication(
        policy,
        maximum_new_bytes=6,
        maximum_new_objects=1,
        maximum_new_inodes=2,
        clock=clock(),
    ) as first:
        assert (
            first.reserved_bytes,
            first.reserved_objects,
            first.reserved_inodes,
        ) == (
            6,
            1,
            2,
        )
        with pytest.raises(PublicationReservationError) as raised:
            async with store.reserve_publication(
                policy,
                maximum_new_bytes=6,
                maximum_new_objects=1,
                maximum_new_inodes=2,
                clock=clock(),
            ):
                pass
        assert raised.value.blocker is PublicationBlocker.BYTE_BUDGET
        assert raised.value.safe_details == {"blocker": "byte_budget"}
        await first.commit(actual_bytes=5, actual_objects=1, actual_inodes=2)

    assert store.publication_reserved_bytes == 0
    assert store.publication_reserved_objects == 0
    assert store.publication_reserved_inodes == 0
    with pytest.raises(RuntimeError, match="already closed"):
        await first.abort()
    assert tuple(store.staging_dir.iterdir()) == ()


@pytest.mark.asyncio
async def test_reservation_commit_rechecks_filesystem_shrink_and_releases(
    tmp_path: Path,
) -> None:
    minimum_free = 64 * 1024 * 1024
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=10,
        maximum_objects=2,
        minimum_free_bytes=minimum_free,
        minimum_free_inodes=128,
    )
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=minimum_free + 10,
            available_bytes=minimum_free + 10,
            total_inodes=1000,
            available_inodes=1000,
        )
    )
    store, clock = _lifecycle_store(
        tmp_path,
        policy=policy,
        configured_max=10,
        capacity=capacity,
    )

    async def commit_after_capacity_shrink() -> None:
        async with store.reserve_publication(
            policy,
            maximum_new_bytes=10,
            maximum_new_objects=1,
            maximum_new_inodes=2,
            clock=clock(),
        ) as reservation:
            capacity.value = StorageCapacity(
                total_bytes=minimum_free + 10,
                available_bytes=minimum_free + 4,
                total_inodes=1000,
                available_inodes=1000,
            )
            await reservation.commit(
                actual_bytes=5,
                actual_objects=1,
                actual_inodes=2,
            )

    with pytest.raises(PublicationReservationError) as raised:
        await commit_after_capacity_shrink()

    assert raised.value.blocker is PublicationBlocker.BYTE_HEADROOM
    assert store.publication_reserved_bytes == 0


@pytest.mark.asyncio
async def test_reservation_exception_and_clock_anomaly_release_every_dimension(
    tmp_path: Path,
) -> None:
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=10,
        maximum_objects=2,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=128 * 1024 * 1024,
            available_bytes=128 * 1024 * 1024,
            total_inodes=1000,
            available_inodes=1000,
        )
    )
    store, clock = _lifecycle_store(
        tmp_path,
        policy=policy,
        configured_max=10,
        capacity=capacity,
    )

    cancellation = "cancelled"
    with pytest.raises(RuntimeError, match=cancellation):
        async with store.reserve_publication(
            policy,
            maximum_new_bytes=5,
            maximum_new_objects=1,
            maximum_new_inodes=2,
            clock=clock(),
        ):
            raise RuntimeError(cancellation)
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)

    clock.value = _sample(seconds=2, wall_seconds=0)
    with pytest.raises(PublicationReservationError) as raised:
        async with store.reserve_publication(
            policy,
            maximum_new_bytes=1,
            maximum_new_objects=1,
            maximum_new_inodes=1,
            clock=clock(),
        ):
            pass
    assert raised.value.blocker is PublicationBlocker.CLOCK_ANOMALY


@pytest.mark.asyncio
async def test_corrupt_clock_recovery_keeps_publication_closed_until_full_window(
    tmp_path: Path,
) -> None:
    capacity = _MutableCapacity(_CAPACITY)
    state = tmp_path / ".retention-clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    assert guard.observe(_sample(seconds=0)).trusted is False
    assert guard.observe(_sample(seconds=60)).trusted is True
    clock = _MutableClock(_sample(seconds=61))
    store = ContentAddressedStore(
        tmp_path,
        max_bytes=_GIB,
        lifecycle=StoreLifecycleConfiguration(
            policy=_POLICY,
            capacity_sampler=capacity,
            clock_high_water=guard,
            clock_sampler=clock,
        ),
    )
    _ = state.write_bytes(b"{]")
    state.chmod(_PRIVATE_STATE_MODE)

    with pytest.raises(PublicationReservationError) as raised:
        async with store.reserve_publication(
            _POLICY,
            maximum_new_bytes=1,
            maximum_new_objects=1,
            maximum_new_inodes=1,
            clock=clock(),
        ):
            pass
    assert raised.value.blocker is PublicationBlocker.CLOCK_ANOMALY
    assert tuple(store.staging_dir.iterdir()) == ()

    warming = store.prune(_POLICY, clock=_sample(seconds=91))
    recovered = store.prune(_POLICY, clock=_sample(seconds=121))

    assert warming.status == "unsatisfied"
    assert PruneBlocker.CLOCK_ANOMALY in warming.blockers
    assert recovered.status == "satisfied"
    async with store.reserve_publication(
        _POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=_sample(seconds=122),
    ):
        pass


def test_prune_never_deletes_a_leased_object(tmp_path: Path) -> None:
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=4,
        maximum_objects=1,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=128 * 1024 * 1024,
            available_bytes=128 * 1024 * 1024,
            total_inodes=1000,
            available_inodes=1000,
        )
    )
    store, clock = _lifecycle_store(
        tmp_path,
        policy=policy,
        configured_max=8,
        capacity=capacity,
    )
    leased = store.put_bytes(
        b"aaaa",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    removable = store.put_bytes(
        b"bbbb",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    _set_tree_mtime(leased.absolute_path.parent, seconds_before_origin=0)
    _set_tree_mtime(removable.absolute_path.parent, seconds_before_origin=0)

    with store.lease_asset(leased.relative_path) as leased_path:
        report = store.prune(policy, clock=clock())
        assert leased_path.is_file()
        assert report.status == "satisfied"
        assert report.freed_bytes == _FOUR_BYTES
        assert report.freed_objects == 1
        assert report.retained_leased_objects == 1

    assert leased.absolute_path.is_file()
    assert not removable.absolute_path.exists()


def test_prune_reports_leased_pressure_without_exposing_identity(
    tmp_path: Path,
) -> None:
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=1,
        maximum_objects=1,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=128 * 1024 * 1024,
            available_bytes=128 * 1024 * 1024,
            total_inodes=1000,
            available_inodes=1000,
        )
    )
    store, clock = _lifecycle_store(
        tmp_path,
        policy=policy,
        configured_max=4,
        capacity=capacity,
    )
    artifact = store.put_bytes(
        b"data",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    _set_tree_mtime(artifact.absolute_path.parent, seconds_before_origin=0)

    with store.lease_asset(artifact.relative_path):
        report = store.prune(policy, clock=clock())

    assert report.status == "unsatisfied"
    assert report.blockers == (PruneBlocker.LEASED_OBJECTS,)
    assert artifact.object_id not in report.model_dump_json()


def test_quota_prune_uses_restart_stable_insertion_order_not_mtime(
    tmp_path: Path,
) -> None:
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=128 * 1024 * 1024,
            available_bytes=128 * 1024 * 1024,
            total_inodes=1000,
            available_inodes=1000,
        )
    )
    bootstrap_policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=8,
        maximum_objects=2,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    bootstrap, _bootstrap_clock = _lifecycle_store(
        tmp_path,
        policy=bootstrap_policy,
        configured_max=8,
        capacity=capacity,
    )
    first = bootstrap.put_bytes(
        b"aaaa",
        namespace="documents",
        filename="first.pdf",
        media_type="application/pdf",
    )
    second = bootstrap.put_bytes(
        b"bbbb",
        namespace="documents",
        filename="second.pdf",
        media_type="application/pdf",
    )
    _set_tree_mtime(first.absolute_path.parent, seconds_before_origin=10)
    _set_tree_mtime(second.absolute_path.parent, seconds_before_origin=100)
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=4,
        maximum_objects=2,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    restart_guard = ClockHighWater(
        tmp_path / ".retention-clock-high-water.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    restart_sample = _sample(seconds=_CLOCK_TEST_ADVANCE_SECONDS)
    assert restart_guard.observe(restart_sample).trusted is True
    clock = _MutableClock(_sample(seconds=_CLOCK_TEST_ADVANCE_SECONDS + 1))
    store = ContentAddressedStore(
        tmp_path,
        max_bytes=4,
        lifecycle=StoreLifecycleConfiguration(
            policy=policy,
            capacity_sampler=capacity,
            clock_high_water=restart_guard,
            clock_sampler=clock,
        ),
    )

    report = store.prune(policy, clock=clock())

    assert report.status == "satisfied"
    assert not first.absolute_path.exists()
    assert second.absolute_path.is_file()


def test_render_transaction_holds_prune_lease_until_closed(tmp_path: Path) -> None:
    render_id = f"rnd_{'1' * 32}"
    relative_manifest = f"renders/{render_id}/manifest.json"
    bootstrap = ContentAddressedStore(tmp_path, max_bytes=100)
    _ = bootstrap.put_render_bytes(relative_manifest, b"manifest")
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=1,
        maximum_objects=1,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=128 * 1024 * 1024,
            available_bytes=128 * 1024 * 1024,
            total_inodes=1000,
            available_inodes=1000,
        )
    )
    store, clock = _lifecycle_store(
        tmp_path,
        policy=policy,
        configured_max=1,
        capacity=capacity,
    )
    _set_tree_mtime(
        tmp_path / "renders" / render_id,
        seconds_before_origin=0,
    )
    transaction = store.begin_render_transaction(
        f"renders/{render_id}",
        completion_file="manifest.json",
    )

    leased_report = store.prune(policy, clock=clock())

    assert leased_report.status == "unsatisfied"
    assert leased_report.blockers[0] is PruneBlocker.LEASED_OBJECTS
    assert (tmp_path / relative_manifest).is_file()
    transaction.rollback()

    released_report = store.prune(policy, clock=clock())
    assert released_report.status == "satisfied"
    assert not (tmp_path / relative_manifest).exists()


def test_insertion_sequence_record_rejects_coercion_and_extra_fields() -> None:
    record = InsertionSequenceRecord.build(
        object_key=f"documents/doc_{'a' * 64}",
        sequence=1,
    )
    valid: dict[str, object] = {
        "schema_version": record.schema_version,
        "object_key": record.object_key,
        "sequence": record.sequence,
        "record_digest": record.record_digest,
    }
    for payload in (
        {**valid, "sequence": True},
        {**valid, "sequence": "1"},
        {**valid, "unexpected": 1},
    ):
        with pytest.raises(ValidationError):
            _ = InsertionSequenceRecord.model_validate(payload, strict=True)


def test_restart_rejects_tampered_insertion_sequence_digest(tmp_path: Path) -> None:
    store, _clock = _lifecycle_store(
        tmp_path,
        policy=_POLICY,
        configured_max=_GIB,
        capacity=_MutableCapacity(_CAPACITY),
    )
    artifact = store.put_bytes(
        b"document",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    sequence_path = artifact.absolute_path.parent / INSERTION_SEQUENCE_FILENAME
    decoded = cast(
        "object",
        json.loads(sequence_path.read_text(encoding="utf-8")),
    )
    payload = cast("dict[str, object]", decoded)
    assert isinstance(payload, dict)
    payload["record_digest"] = "0" * 64
    _ = sequence_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="sequence state is invalid"):
        _ = ContentAddressedStore(
            tmp_path,
            max_bytes=_GIB,
            lifecycle=StoreLifecycleConfiguration(
                policy=_POLICY,
                capacity_sampler=lambda: _CAPACITY,
                clock_high_water=ClockHighWater(
                    tmp_path / ".retention-clock-high-water.json",
                    healthy_window_seconds=0,
                    maximum_forward_slew_seconds=5,
                ),
                clock_sampler=lambda: _sample(seconds=_CLOCK_TEST_ADVANCE_SECONDS),
            ),
        )


def test_restart_rejects_symlinked_insertion_high_water(tmp_path: Path) -> None:
    _store, _clock = _lifecycle_store(
        tmp_path,
        policy=_POLICY,
        configured_max=_GIB,
        capacity=_MutableCapacity(_CAPACITY),
    )
    high_water = tmp_path / INSERTION_HIGH_WATER_FILENAME
    target = tmp_path / "attacker-state.json"
    _ = target.write_text("{}", encoding="utf-8")
    high_water.unlink()
    high_water.symlink_to(target)

    with pytest.raises(ValueError, match="safe regular file"):
        _ = ContentAddressedStore(
            tmp_path,
            max_bytes=_GIB,
            lifecycle=StoreLifecycleConfiguration(
                policy=_POLICY,
                capacity_sampler=lambda: _CAPACITY,
                clock_high_water=ClockHighWater(
                    tmp_path / ".retention-clock-high-water.json",
                    healthy_window_seconds=0,
                    maximum_forward_slew_seconds=5,
                ),
                clock_sampler=lambda: _sample(seconds=_CLOCK_TEST_ADVANCE_SECONDS),
            ),
        )


def test_system_retention_clock_samples_one_canonical_boot_identity(
    tmp_path: Path,
) -> None:
    boot_id = tmp_path / "boot_id"
    _ = boot_id.write_bytes(b"550e8400-e29b-41d4-a716-446655440000\n")
    utc_now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)

    sample = SystemRetentionClock(
        synchronized=True,
        boot_id_path=boot_id,
        utc_sampler=lambda: utc_now,
        monotonic_sampler=lambda: 42.5,
    )()

    assert sample == RetentionClockSample(
        utc_now=utc_now,
        monotonic_now=42.5,
        boot_id="550e8400-e29b-41d4-a716-446655440000",
        synchronized=True,
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"boot-a\nboot-b\n",
        b" boot-a\n",
        b"boot-a \n",
        b"boot/a\n",
        b"x" * 129,
        b"\xff\n",
    ],
)
def test_system_retention_clock_rejects_ambiguous_boot_identity(
    tmp_path: Path,
    raw: bytes,
) -> None:
    boot_id = tmp_path / "boot_id"
    _ = boot_id.write_bytes(raw)

    with pytest.raises(ValueError, match="boot identity"):
        _ = SystemRetentionClock(
            synchronized=False,
            boot_id_path=boot_id,
        )()


def test_system_retention_clock_rejects_symlinked_boot_identity(
    tmp_path: Path,
) -> None:
    target = tmp_path / "attacker-boot-id"
    _ = target.write_text("boot-a\n", encoding="utf-8")
    boot_id = tmp_path / "boot_id"
    boot_id.symlink_to(target)

    with pytest.raises(ValueError, match="boot identity"):
        _ = SystemRetentionClock(
            synchronized=False,
            boot_id_path=boot_id,
        )()


@pytest.mark.asyncio
async def test_rejected_publication_latches_until_satisfied_prune_and_alerts_once(
    tmp_path: Path,
) -> None:
    minimum_free = 64 * 1024 * 1024
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=10,
        maximum_objects=2,
        minimum_free_bytes=minimum_free,
        minimum_free_inodes=128,
    )
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=minimum_free + 10,
            available_bytes=minimum_free + 4,
            total_inodes=1000,
            available_inodes=1000,
        )
    )
    state_path = tmp_path / ".retention-clock-high-water.json"
    guard = ClockHighWater(
        state_path,
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    initial = _sample(seconds=0)
    assert guard.observe(initial).trusted is False
    assert guard.observe(initial).trusted is True
    clock = _MutableClock(_sample(seconds=_CLOCK_TEST_ADVANCE_SECONDS))
    alerts: list[LifecycleAlert] = []
    store = ContentAddressedStore(
        tmp_path,
        max_bytes=10,
        lifecycle=StoreLifecycleConfiguration(
            policy=policy,
            capacity_sampler=capacity,
            clock_high_water=guard,
            clock_sampler=clock,
            alert_observer=alerts.append,
        ),
    )

    for _attempt in range(2):
        with pytest.raises(PublicationReservationError) as raised:
            async with store.reserve_publication(
                policy,
                maximum_new_bytes=5,
                maximum_new_objects=1,
                maximum_new_inodes=2,
                clock=clock(),
            ):
                pass
        assert raised.value.blocker is PublicationBlocker.BYTE_HEADROOM

    closed_after_denial = store.lifecycle_admission_closed
    assert closed_after_denial is True
    assert alerts == [
        LifecycleAlert(
            event=LifecycleAlertEvent.ADMISSION_CLOSED,
            blockers=(LifecycleBlocker.BYTE_HEADROOM,),
        )
    ]

    capacity.value = StorageCapacity(
        total_bytes=minimum_free + 10,
        available_bytes=minimum_free + 10,
        total_inodes=1000,
        available_inodes=1000,
    )
    with pytest.raises(PublicationReservationError) as still_closed:
        async with store.reserve_publication(
            policy,
            maximum_new_bytes=5,
            maximum_new_objects=1,
            maximum_new_inodes=2,
            clock=clock(),
        ):
            pass
    assert still_closed.value.blocker is PublicationBlocker.BYTE_HEADROOM

    report = store.prune(policy, clock=clock())
    assert report.status == "satisfied"
    assert not store.lifecycle_admission_closed
    async with store.reserve_publication(
        policy,
        maximum_new_bytes=5,
        maximum_new_objects=1,
        maximum_new_inodes=2,
        clock=clock(),
    ):
        pass
    assert len(alerts) == 1


def test_lifecycle_alert_contract_rejects_coercion_and_schema_drift() -> None:
    valid: dict[str, object] = {
        "event": "admission_closed",
        "blockers": ["clock_anomaly"],
    }
    invalid_payloads: tuple[dict[str, object], ...] = (
        {**valid, "event": True},
        {**valid, "blockers": []},
        {**valid, "blockers": ["unknown"]},
        {**valid, "unexpected": "value"},
    )
    for payload in invalid_payloads:
        with pytest.raises(ValidationError):
            _ = LifecycleAlert.model_validate(payload, strict=True)


def _changed_stat(
    metadata: os.stat_result,
    *,
    index: int,
    value: int,
) -> os.stat_result:
    fields = list(metadata)
    fields[index] = value
    return os.stat_result(fields)


def _write_private_model(
    path: Path,
    model: InsertionSequenceRecord | InsertionHighWaterRecord,
) -> None:
    _ = path.write_text(model.model_dump_json(), encoding="utf-8")
    path.chmod(_PRIVATE_STATE_MODE)


def _insertion_object(root: Path, token: str) -> tuple[str, Path]:
    key = f"documents/doc_{token * 64}"
    path = root / key
    path.mkdir(parents=True)
    return key, path


def test_private_state_writer_rejects_failed_mode_postcondition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-chmod metadata mismatch must abort the durable write."""
    real_fstat = os.fstat

    def wrong_link_count(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        return _changed_stat(metadata, index=stat.ST_NLINK, value=2)

    monkeypatch.setattr(os, "fstat", wrong_link_count)
    guard = ClockHighWater(
        tmp_path / "clock-high-water.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )

    with pytest.raises(ValueError, match="private file postcondition"):
        _ = guard.observe(_sample(seconds=0))
    assert not (tmp_path / "clock-high-water.json").exists()
    assert tuple(tmp_path.iterdir()) == ()


def test_insertion_state_writer_removes_temporary_after_failed_postcondition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Insertion state must not retain a partial temp file after rejection."""
    root = tmp_path / "cache"
    root.mkdir()
    real_fstat = os.fstat

    def wrong_link_count(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        return _changed_stat(metadata, index=stat.ST_NLINK, value=2)

    monkeypatch.setattr(os, "fstat", wrong_link_count)

    with pytest.raises(ValueError, match="private file postcondition"):
        PersistentInsertionOrder(root).initialize(())
    assert not (root / INSERTION_HIGH_WATER_FILENAME).exists()
    assert tuple(root.iterdir()) == ()


def _system_clock_with_invalid_authority(
    field: str,
    value: object,
) -> SystemRetentionClock:
    if field == "synchronized":
        return SystemRetentionClock(synchronized=cast("bool", value))
    if field == "boot_id_path":
        return SystemRetentionClock(
            synchronized=True,
            boot_id_path=cast("Path", value),
        )
    if field == "utc_sampler":
        return SystemRetentionClock(
            synchronized=True,
            utc_sampler=cast("Callable[[], datetime]", value),
        )
    return SystemRetentionClock(
        synchronized=True,
        monotonic_sampler=cast("Callable[[], float]", value),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("synchronized", 1),
        ("boot_id_path", "boot-id"),
        ("utc_sampler", None),
        ("monotonic_sampler", None),
    ],
)
def test_system_retention_clock_rejects_coerced_authorities(
    field: str,
    value: object,
) -> None:
    with pytest.raises(TypeError):
        _ = _system_clock_with_invalid_authority(field, value)


def test_state_io_remains_strict_without_optional_open_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Portable fallbacks remain covered when CLOEXEC/NOFOLLOW are unavailable."""
    boot_id = tmp_path / "boot-id"
    _ = boot_id.write_text("boot-a\n", encoding="ascii")
    root = tmp_path / "cache"
    root.mkdir(mode=0o700)
    key, object_path = _insertion_object(root, "a")
    monkeypatch.delattr(os, "O_CLOEXEC")
    monkeypatch.delattr(os, "O_NOFOLLOW")

    sample = SystemRetentionClock(
        synchronized=True,
        boot_id_path=boot_id,
        utc_sampler=lambda: _CLOCK_ORIGIN,
        monotonic_sampler=lambda: 1.0,
    )()
    assert sample.boot_id == "boot-a"

    guard = ClockHighWater(
        root / "clock-high-water.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    assert guard.observe(_sample(seconds=0)).trusted is False
    assert guard.observe(_sample(seconds=0)).trusted is True

    order = PersistentInsertionOrder(root)
    order.initialize(((key, object_path),))
    restarted = PersistentInsertionOrder(root)
    restarted.initialize(((key, object_path),))
    assert restarted.sequence_for(key) == 1


def test_boot_identity_rejects_descriptor_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boot_id = tmp_path / "boot-id"
    _ = boot_id.write_text("boot-a\n", encoding="ascii")
    real_fstat = os.fstat

    def changed_inode(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        return _changed_stat(
            metadata,
            index=stat.ST_INO,
            value=metadata.st_ino + 1,
        )

    monkeypatch.setattr(os, "fstat", changed_inode)

    with pytest.raises(ValueError, match="boot identity"):
        _ = SystemRetentionClock(
            synchronized=True,
            boot_id_path=boot_id,
        )()


def test_report_and_clock_decision_models_reject_inconsistent_state() -> None:
    for blockers in (
        (PruneBlocker.BYTE_HEADROOM, PruneBlocker.LEASED_OBJECTS),
        (PruneBlocker.LEASED_OBJECTS, PruneBlocker.LEASED_OBJECTS),
    ):
        with pytest.raises(ValidationError, match="canonically ordered"):
            _ = UnsatisfiedPruneReport(
                status="unsatisfied",
                blockers=blockers,
                freed_bytes=0,
                freed_objects=0,
                retained_leased_objects=0,
                post_stored_bytes=0,
                post_stored_objects=0,
                post_available_bytes=0,
                post_available_inodes=0,
            )

    with pytest.raises(ValidationError, match="canonically ordered"):
        _ = LifecycleAlert(
            event=LifecycleAlertEvent.PRUNE_UNSATISFIED,
            blockers=(LifecycleBlocker.BYTE_HEADROOM, LifecycleBlocker.LEASED_OBJECTS),
        )
    with pytest.raises(ValidationError, match="exactly one blocker"):
        _ = LifecycleAlert(
            event=LifecycleAlertEvent.ADMISSION_CLOSED,
            blockers=(LifecycleBlocker.BYTE_BUDGET, LifecycleBlocker.OBJECT_BUDGET),
        )
    with pytest.raises(ValidationError, match="must agree"):
        _ = ClockAssessment(
            trusted=True,
            age_deletion_allowed=False,
            blocker=None,
        )
    with pytest.raises(ValidationError, match="must have no blocker"):
        _ = ClockAssessment(
            trusted=True,
            age_deletion_allowed=True,
            blocker=ClockBlocker.WARMING_UP,
        )


def test_filesystem_capacity_requires_a_directory_descriptor(tmp_path: Path) -> None:
    for descriptor in (True, -1):
        with pytest.raises(ValueError, match="non-negative exact descriptor"):
            _ = filesystem_capacity(descriptor)

    regular = tmp_path / "file"
    _ = regular.write_bytes(b"x")
    file_descriptor = os.open(regular, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="identify a directory"):
            _ = filesystem_capacity(file_descriptor)
    finally:
        os.close(file_descriptor)

    directory_descriptor = os.open(tmp_path, os.O_RDONLY)
    try:
        capacity = filesystem_capacity(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    assert capacity.total_bytes >= capacity.available_bytes
    assert capacity.total_inodes >= capacity.available_inodes


@pytest.mark.parametrize(
    ("healthy_window", "forward_slew"),
    [(True, 5), (-1, 5), (0, True), (0, 61)],
)
def test_clock_high_water_rejects_invalid_intervals(
    tmp_path: Path,
    healthy_window: object,
    forward_slew: object,
) -> None:
    with pytest.raises(ValueError, match="must be an integer"):
        _ = ClockHighWater(
            tmp_path / "clock-high-water.json",
            healthy_window_seconds=cast("int", healthy_window),
            maximum_forward_slew_seconds=cast("int", forward_slew),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "non-utc",
        "coerced-monotonic",
        "future-healthy-origin",
        "trusted-without-origin",
        "digest-mismatch",
    ],
)
def test_clock_state_rejects_digest_validity_and_semantic_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    _ = guard.observe(_sample(seconds=0))
    decoded = cast("object", json.loads(state.read_bytes()))
    payload = cast("dict[str, object]", decoded)
    if mutation == "non-utc":
        payload["utc_high_water"] = "2026-08-25T01:00:00+01:00"
    elif mutation == "coerced-monotonic":
        payload["last_monotonic"] = 0
    elif mutation == "future-healthy-origin":
        payload["last_monotonic"] = 1.0
        payload["healthy_since_monotonic"] = 2.0
    elif mutation == "trusted-without-origin":
        payload["trusted"] = True
        payload["healthy_since_monotonic"] = None
    else:
        payload["record_digest"] = "0" * 64
    _ = state.write_text(json.dumps(payload), encoding="utf-8")
    state.chmod(_PRIVATE_STATE_MODE)

    assessment = guard.observe(_sample(seconds=1))

    assert assessment.blocker is ClockBlocker.CORRUPT_STATE


@pytest.mark.parametrize("raw_kind", ["duplicate", "malformed"])
def test_clock_state_rejects_non_strict_json(
    tmp_path: Path,
    raw_kind: str,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    _ = guard.observe(_sample(seconds=0))
    if raw_kind == "duplicate":
        raw = state.read_bytes().replace(
            b'"schema_version":"1.0",',
            b'"schema_version":"1.0","schema_version":"1.0",',
            1,
        )
    else:
        raw = b"{]"
    _ = state.write_bytes(raw)
    state.chmod(_PRIVATE_STATE_MODE)

    assert guard.observe(_sample(seconds=1)).blocker is ClockBlocker.CORRUPT_STATE


def test_clock_state_recovers_from_malformed_private_record_after_healthy_window(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    corrupt = b"{]"
    _ = state.write_bytes(corrupt)
    state.chmod(_PRIVATE_STATE_MODE)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    closed = guard.observe(_sample(seconds=0))
    warming = guard.observe(_sample(seconds=30))
    recovered = guard.observe(_sample(seconds=60))

    assert (closed.trusted, closed.blocker) == (
        False,
        ClockBlocker.CORRUPT_STATE,
    )
    assert (warming.trusted, warming.blocker) == (False, ClockBlocker.WARMING_UP)
    assert (recovered.trusted, recovered.blocker) == (True, None)
    quarantined = tuple(tmp_path.glob(".clock-high-water.json.corrupt-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == corrupt
    assert stat.S_IMODE(quarantined[0].stat().st_mode) == _PRIVATE_STATE_MODE


def test_clock_high_water_serializes_concurrent_state_transitions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = ClockHighWater(
        tmp_path / "clock-high-water.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    real_write = os.write
    start = Barrier(2)
    counter_lock = Lock()
    active_writes = 0
    maximum_active_writes = 0

    def delayed_write(descriptor: int, raw: bytes) -> int:
        nonlocal active_writes, maximum_active_writes
        with counter_lock:
            active_writes += 1
            maximum_active_writes = max(maximum_active_writes, active_writes)
        try:
            time.sleep(0.05)
            return real_write(descriptor, raw)
        finally:
            with counter_lock:
                active_writes -= 1

    monkeypatch.setattr(os, "write", delayed_write)

    def observe(seconds: float) -> ClockAssessment:
        _ = start.wait()
        return guard.observe(_sample(seconds=seconds))

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(observe, (0.0, 0.0)))

    assert {result.trusted for result in results} == {False, True}
    assert maximum_active_writes == 1


def test_clock_high_water_rejects_recursive_observation_before_relocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = ClockHighWater(
        tmp_path / "clock-high-water.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    real_read = cast(
        "Callable[[int], object]",
        object.__getattribute__(guard, "_read"),
    )
    real_flock = fcntl.flock
    exclusive_lock_calls = 0
    nested_attempted = False

    def reject_second_exclusive_lock(descriptor: int, operation: int) -> None:
        nonlocal exclusive_lock_calls
        if operation & fcntl.LOCK_EX:
            exclusive_lock_calls += 1
            if exclusive_lock_calls > 1:
                raise BlockingIOError
        real_flock(descriptor, operation)

    def recursively_observe(directory: int) -> object:
        nonlocal nested_attempted
        if not nested_attempted:
            nested_attempted = True
            with pytest.raises(RuntimeError, match="already in progress"):
                _ = guard.observe(_sample(seconds=0))
        return real_read(directory)

    monkeypatch.setattr(fcntl, "flock", reject_second_exclusive_lock)
    monkeypatch.setattr(guard, "_read", recursively_observe)

    result = guard.observe(_sample(seconds=0))

    assert nested_attempted is True
    assert (result.trusted, result.blocker) == (False, ClockBlocker.MISSING_STATE)


def test_clock_high_water_prevents_cross_instance_stale_trust_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    initializer = ClockHighWater(
        state,
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    _ = initializer.observe(_sample(seconds=0))
    assert initializer.observe(_sample(seconds=1)).trusted is True
    stale_observer = ClockHighWater(
        state,
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    rollback_observer = ClockHighWater(
        state,
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    stale_write_entered = Event()
    rollback_finished = Event()
    real_stale_write = cast(
        "_ClockStateWriter",
        object.__getattribute__(stale_observer, "_write"),
    )

    def delayed_stale_write(
        directory: int,
        record: object,
        *,
        require_absent: bool = False,
    ) -> None:
        stale_write_entered.set()
        _ = rollback_finished.wait(timeout=0.2)
        real_stale_write(
            directory,
            record,
            require_absent=require_absent,
        )

    monkeypatch.setattr(stale_observer, "_write", delayed_stale_write)

    def observe_rollback() -> ClockAssessment:
        try:
            return rollback_observer.observe(
                _sample(seconds=2, wall_seconds=0),
            )
        finally:
            rollback_finished.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        stale_future = executor.submit(stale_observer.observe, _sample(seconds=2))
        assert stale_write_entered.wait(timeout=1)
        rollback_future = executor.submit(observe_rollback)
        stale_result = stale_future.result(timeout=2)
        rollback_result = rollback_future.result(timeout=2)

    assert stale_result.trusted is True
    assert (rollback_result.trusted, rollback_result.blocker) == (
        False,
        ClockBlocker.WALL_ROLLBACK,
    )
    persisted = cast("dict[str, object]", json.loads(state.read_bytes()))
    assert persisted["trusted"] is False


def test_clock_state_reconciles_partial_digest_quarantine_after_crash(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    corrupt = b"{]"
    _ = state.write_bytes(corrupt)
    state.chmod(_PRIVATE_STATE_MODE)
    quarantine = tmp_path / (
        ".clock-high-water.json.corrupt-" + hashlib.sha256(corrupt).hexdigest()
    )
    _ = quarantine.write_bytes(b"{")
    quarantine.chmod(_PRIVATE_STATE_MODE)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    result = guard.observe(_sample(seconds=0))

    assert (result.trusted, result.blocker) == (False, ClockBlocker.CORRUPT_STATE)
    assert quarantine.read_bytes() == corrupt
    persisted = cast("dict[str, object]", json.loads(state.read_bytes()))
    assert persisted["trusted"] is False


def test_clock_state_does_not_launder_nonprefix_quarantine_evidence(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    corrupt = b"{]"
    _ = state.write_bytes(corrupt)
    state.chmod(_PRIVATE_STATE_MODE)
    quarantine = tmp_path / (
        ".clock-high-water.json.corrupt-" + hashlib.sha256(corrupt).hexdigest()
    )
    wrong_evidence = b"XX"
    _ = quarantine.write_bytes(wrong_evidence)
    quarantine.chmod(_PRIVATE_STATE_MODE)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    result = guard.observe(_sample(seconds=0))

    assert (result.trusted, result.blocker) == (False, ClockBlocker.CORRUPT_STATE)
    assert state.read_bytes() == corrupt
    assert quarantine.read_bytes() == wrong_evidence
    assert tuple(tmp_path.glob(f"{quarantine.name}.incomplete-*")) == ()


def test_clock_state_never_discards_source_if_quarantine_evidence_disappears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    corrupt = b"{]"
    _ = state.write_bytes(corrupt)
    state.chmod(_PRIVATE_STATE_MODE)
    quarantine = tmp_path / (
        ".clock-high-water.json.corrupt-" + hashlib.sha256(corrupt).hexdigest()
    )
    real_fsync = os.fsync
    evidence_removed = False

    def remove_evidence_before_directory_sync(descriptor: int) -> None:
        nonlocal evidence_removed
        if (
            not evidence_removed
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
            and quarantine.exists()
        ):
            quarantine.unlink()
            evidence_removed = True
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", remove_evidence_before_directory_sync)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    result = guard.observe(_sample(seconds=0))

    assert evidence_removed is True
    assert (result.trusted, result.blocker) == (False, ClockBlocker.CORRUPT_STATE)
    source_preserved = state.exists() and state.read_bytes() == corrupt
    evidence_preserved = quarantine.exists() and quarantine.read_bytes() == corrupt
    assert source_preserved or evidence_preserved


def test_clock_state_rejects_writable_parent_mode_without_mutation(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    corrupt = b"{]"
    _ = state.write_bytes(corrupt)
    state.chmod(_PRIVATE_STATE_MODE)
    tmp_path.chmod(0o770)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    with pytest.raises(ValueError, match="private directory"):
        _ = guard.observe(_sample(seconds=0))

    assert state.read_bytes() == corrupt
    assert tuple(tmp_path.glob(".clock-high-water.json.corrupt-*")) == ()


def test_clock_state_creates_only_one_private_parent_leaf(
    tmp_path: Path,
) -> None:
    missing_parent = tmp_path / "missing-cache"
    guard = ClockHighWater(
        missing_parent / "clock-high-water.json",
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    result = guard.observe(_sample(seconds=0))

    assert (result.trusted, result.blocker) == (False, ClockBlocker.MISSING_STATE)
    assert stat.S_IMODE(missing_parent.stat().st_mode) == _PRIVATE_DIRECTORY_MODE


def test_clock_state_private_leaf_creation_survives_restrictive_umask(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "cache"
    state = parent / "clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    previous_umask = os.umask(0o777)
    try:
        result = guard.observe(_sample(seconds=0))
    finally:
        _ = os.umask(previous_umask)

    assert (result.trusted, result.blocker) == (False, ClockBlocker.MISSING_STATE)
    assert stat.S_IMODE(parent.stat().st_mode) == _PRIVATE_DIRECTORY_MODE
    assert stat.S_IMODE(state.stat().st_mode) == _PRIVATE_STATE_MODE


def test_clock_state_never_recursively_creates_missing_ancestors(
    tmp_path: Path,
) -> None:
    missing_root = tmp_path / "missing-root"
    guard = ClockHighWater(
        missing_root / "cache" / "clock-high-water.json",
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    with pytest.raises(ValueError, match="requires an existing ancestor"):
        _ = guard.observe(_sample(seconds=0))

    assert not missing_root.exists()


def test_clock_state_rechecks_parent_mode_before_quarantine_source_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    corrupt = b"{]"
    _ = state.write_bytes(corrupt)
    state.chmod(_PRIVATE_STATE_MODE)
    real_fsync = os.fsync
    mode_drifted = False

    def drift_mode_before_directory_sync(descriptor: int) -> None:
        nonlocal mode_drifted
        if not mode_drifted and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            tmp_path.chmod(0o770)
            mode_drifted = True
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", drift_mode_before_directory_sync)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    try:
        result = guard.observe(_sample(seconds=0))
    finally:
        tmp_path.chmod(0o700)

    assert mode_drifted is True
    assert (result.trusted, result.blocker) == (False, ClockBlocker.CORRUPT_STATE)
    assert state.read_bytes() == corrupt


def test_clock_state_rechecks_parent_mode_before_main_state_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    real_fsync = os.fsync
    mode_drifted = False

    def drift_mode_after_temporary_sync(descriptor: int) -> None:
        nonlocal mode_drifted
        metadata = os.fstat(descriptor)
        if not mode_drifted and stat.S_ISREG(metadata.st_mode):
            tmp_path.chmod(0o770)
            mode_drifted = True
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", drift_mode_after_temporary_sync)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    try:
        with pytest.raises(ValueError, match="private directory"):
            _ = guard.observe(_sample(seconds=0))
    finally:
        tmp_path.chmod(0o700)

    assert mode_drifted is True
    assert not state.exists()
    assert tuple(tmp_path.glob(".clock-high-water.json.tmp-*")) == ()


def test_clock_state_does_not_recover_if_record_changes_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    _ = state.write_bytes(b"{]")
    state.chmod(_PRIVATE_STATE_MODE)
    replacement = b'{"changed":"during-read"}'
    real_read = os.read

    def mutate_after_read(descriptor: int, maximum: int) -> bytes:
        raw = real_read(descriptor, maximum)
        _ = state.write_bytes(replacement)
        state.chmod(_PRIVATE_STATE_MODE)
        return raw

    monkeypatch.setattr(os, "read", mutate_after_read)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    result = guard.observe(_sample(seconds=0))

    assert (result.trusted, result.blocker) == (False, ClockBlocker.CORRUPT_STATE)
    assert state.read_bytes() == replacement
    assert tuple(tmp_path.glob(".clock-high-water.json.corrupt-*")) == ()


def test_clock_state_recovery_never_fsyncs_a_two_link_intermediate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    _ = state.write_bytes(b"{]")
    state.chmod(_PRIVATE_STATE_MODE)
    real_fsync = os.fsync

    def assert_atomic_directory_state(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            active_links = state.stat().st_nlink if state.exists() else 0
            quarantined = tuple(tmp_path.glob(".clock-high-water.json.corrupt-*"))
            assert active_links in {0, 1}
            assert all(item.stat().st_nlink == 1 for item in quarantined)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", assert_atomic_directory_state)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    result = guard.observe(_sample(seconds=0))

    assert (result.trusted, result.blocker) == (False, ClockBlocker.CORRUPT_STATE)


def test_clock_state_quarantine_zero_progress_preserves_source_without_partial_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    corrupt = b"{]"
    _ = state.write_bytes(corrupt)
    state.chmod(_PRIVATE_STATE_MODE)
    monkeypatch.setattr(os, "write", _zero_write)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    result = guard.observe(_sample(seconds=0))

    assert (result.trusted, result.blocker) == (False, ClockBlocker.CORRUPT_STATE)
    assert state.read_bytes() == corrupt
    assert tuple(tmp_path.glob(".clock-high-water.json.corrupt-*")) == ()


def test_clock_state_baseline_zero_progress_leaves_no_temporary_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    monkeypatch.setattr(os, "write", _zero_write)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )

    with pytest.raises(OSError, match="made no progress"):
        _ = guard.observe(_sample(seconds=0))

    assert not state.exists()
    assert tuple(tmp_path.glob(".clock-high-water.json.tmp-*")) == ()


@pytest.mark.parametrize("failure", ["identity", "oversized-read"])
def test_clock_state_rejects_read_time_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = ClockHighWater(
        state,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    _ = guard.observe(_sample(seconds=0))
    if failure == "identity":
        real_fstat = os.fstat

        def changed_inode(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            if stat.S_ISDIR(metadata.st_mode):
                return metadata
            return _changed_stat(
                metadata,
                index=stat.ST_INO,
                value=metadata.st_ino + 1,
            )

        monkeypatch.setattr(os, "fstat", changed_inode)
    else:

        def oversized_read(_descriptor: int, _maximum: int) -> bytes:
            return b"x" * 4_097

        monkeypatch.setattr(os, "read", oversized_read)

    assert guard.observe(_sample(seconds=1)).blocker is ClockBlocker.CORRUPT_STATE


def test_clock_state_rejects_symlink_swap_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    _ = target.write_text("unchanged", encoding="utf-8")
    state = tmp_path / "clock-high-water.json"
    state.symlink_to(target)
    guard = ClockHighWater(
        state,
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )

    def missing_state_read(
        _directory: int,
    ) -> tuple[None, ClockBlocker, None]:
        return None, ClockBlocker.MISSING_STATE, None

    monkeypatch.setattr(guard, "_read", missing_state_read)

    with pytest.raises(ValueError, match="must not be a symlink"):
        _ = guard.observe(_sample(seconds=0))
    assert target.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.parametrize("failure", ["identity", "short-read", "invalid-json"])
def test_insertion_high_water_rejects_read_time_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    state = root / INSERTION_HIGH_WATER_FILENAME
    _write_private_model(state, InsertionHighWaterRecord.build(next_sequence=1))
    if failure == "identity":
        real_fstat = os.fstat

        def changed_inode(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            return _changed_stat(
                metadata,
                index=stat.ST_INO,
                value=metadata.st_ino + 1,
            )

        monkeypatch.setattr(os, "fstat", changed_inode)
    elif failure == "short-read":

        def short_read(_descriptor: int, _maximum: int) -> bytes:
            return b"{}"

        monkeypatch.setattr(os, "read", short_read)
    else:
        _ = state.write_bytes(b"{]")
        state.chmod(_PRIVATE_STATE_MODE)

    with pytest.raises(
        ValueError,
        match=r"identity changed|changed or exceeded|not valid strict JSON",
    ):
        PersistentInsertionOrder(root).initialize(())


@pytest.mark.parametrize("root_kind", ["file", "symlink"])
def test_insertion_order_rejects_untrusted_root(
    tmp_path: Path,
    root_kind: str,
) -> None:
    root = tmp_path / "cache"
    if root_kind == "file":
        _ = root.write_bytes(b"x")
    else:
        target = tmp_path / "target"
        target.mkdir()
        root.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="trusted directory"):
        _ = PersistentInsertionOrder(root)


@pytest.mark.parametrize("path_kind", ["mismatch", "symlink", "file"])
def test_insertion_order_rejects_object_path_drift(
    tmp_path: Path,
    path_kind: str,
) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    key = f"documents/doc_{'a' * 64}"
    expected = root / key
    expected.parent.mkdir()
    if path_kind == "mismatch":
        path = root / "wrong"
        path.mkdir()
    elif path_kind == "symlink":
        target = root / "target"
        target.mkdir()
        expected.symlink_to(target, target_is_directory=True)
        path = expected
    else:
        _ = expected.write_bytes(b"x")
        path = expected

    with pytest.raises(ValueError, match="does not match its key"):
        _ = PersistentInsertionOrder(root).ensure(key, path)


def test_insertion_order_rejects_untrusted_record_parent_and_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    order = PersistentInsertionOrder(root)
    order.initialize(())
    missing_key = f"documents/doc_{'a' * 64}"
    missing_path = root / missing_key

    def accept_raced_path(_key: str, path: Path) -> Path:
        return path

    monkeypatch.setattr(order, "_validated_object_path", accept_raced_path)
    with pytest.raises(ValueError, match="parent must be a trusted directory"):
        _ = order.ensure(missing_key, missing_path)

    monkeypatch.undo()
    key, object_path = _insertion_object(root, "b")
    target = object_path / "target"
    _ = target.write_bytes(b"x")
    (object_path / INSERTION_SEQUENCE_FILENAME).symlink_to(target)
    with pytest.raises(ValueError, match="path must not be a symlink"):
        _ = order.ensure(key, object_path)


def test_insertion_order_rejects_exhausted_sequence_space(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    key, object_path = _insertion_object(root, "a")
    order = PersistentInsertionOrder(root)
    order.initialize(())
    object.__setattr__(order, "_next_sequence", 9_223_372_036_854_775_807)

    with pytest.raises(ValueError, match="sequence space is exhausted"):
        _ = order.ensure(key, object_path)


@pytest.mark.parametrize("defect", ["unsorted", "duplicate"])
def test_insertion_order_rejects_noncanonical_bootstrap_inventory(
    tmp_path: Path,
    defect: str,
) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    first = _insertion_object(root, "a")
    second = _insertion_object(root, "b")
    objects = (second, first) if defect == "unsorted" else (first, first)

    with pytest.raises(ValueError, match=r"canonical|duplicate"):
        PersistentInsertionOrder(root).initialize(objects)


def test_insertion_order_requires_high_water_when_sequence_exists(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    key, object_path = _insertion_object(root, "a")
    _write_private_model(
        object_path / INSERTION_SEQUENCE_FILENAME,
        InsertionSequenceRecord.build(object_key=key, sequence=1),
    )

    with pytest.raises(ValueError, match="high-water state is missing"):
        PersistentInsertionOrder(root).initialize(((key, object_path),))


def test_insertion_order_rejects_invalid_high_water_record(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    record = InsertionHighWaterRecord.build(next_sequence=1)
    payload = cast(
        "dict[str, object]",
        cast("object", record.model_dump(mode="json")),
    )
    payload["record_digest"] = "0" * 64
    state = root / INSERTION_HIGH_WATER_FILENAME
    _ = state.write_text(json.dumps(payload), encoding="utf-8")
    state.chmod(_PRIVATE_STATE_MODE)

    with pytest.raises(ValueError, match="high-water state is invalid"):
        PersistentInsertionOrder(root).initialize(())


@pytest.mark.parametrize("binding", ["object-key", "high-water"])
def test_insertion_order_rejects_record_binding_drift(
    tmp_path: Path,
    binding: str,
) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    key, object_path = _insertion_object(root, "a")
    _write_private_model(
        root / INSERTION_HIGH_WATER_FILENAME,
        InsertionHighWaterRecord.build(next_sequence=2),
    )
    record = InsertionSequenceRecord.build(
        object_key=(f"documents/doc_{'b' * 64}" if binding == "object-key" else key),
        sequence=(1 if binding == "object-key" else 2),
    )
    _write_private_model(object_path / INSERTION_SEQUENCE_FILENAME, record)

    with pytest.raises(ValueError, match="not bound below high-water"):
        PersistentInsertionOrder(root).initialize(((key, object_path),))


def test_insertion_order_rejects_duplicate_sequences(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    first = _insertion_object(root, "a")
    second = _insertion_object(root, "b")
    _write_private_model(
        root / INSERTION_HIGH_WATER_FILENAME,
        InsertionHighWaterRecord.build(next_sequence=3),
    )
    for key, path in (first, second):
        _write_private_model(
            path / INSERTION_SEQUENCE_FILENAME,
            InsertionSequenceRecord.build(object_key=key, sequence=1),
        )

    with pytest.raises(ValueError, match="must be unique"):
        PersistentInsertionOrder(root).initialize((first, second))


def test_insertion_order_existing_missing_and_remove_noop_paths(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    key, object_path = _insertion_object(root, "a")
    order = PersistentInsertionOrder(root)
    order.initialize(((key, object_path),))

    assert order.ensure(key, object_path) == 1
    with pytest.raises(ValueError, match="no initialized insertion sequence"):
        _ = order.sequence_for(f"documents/doc_{'b' * 64}")
    order.remove(f"documents/doc_{'b' * 64}")
    order.remove(key)
