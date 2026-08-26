# Copyright (c) 2026 David Osipov
"""Real lifecycle store with a deterministic public lease barrier for tests."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, override

from nplg_mcp.storage import ContentAddressedStore, StoreLifecycleConfiguration
from nplg_mcp.storage_lifecycle import (
    ClockHighWater,
    RetentionClockSample,
    RetentionPolicy,
    StorageCapacity,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from nplg_mcp.storage_lifecycle import LifecycleAlert

_GIB = 1024 * 1024 * 1024
_CLOCK_ORIGIN = datetime(2026, 1, 1, tzinfo=UTC)


def retention_sample(seconds: float) -> RetentionClockSample:
    """Build a deterministic trustworthy-clock sample for lease tests."""
    return RetentionClockSample(
        utc_now=_CLOCK_ORIGIN + timedelta(seconds=seconds),
        monotonic_now=seconds,
        boot_id="lease-barrier-boot",
        synchronized=True,
    )


class LeaseBarrierStore(ContentAddressedStore):
    """Block an entered real asset lease until the coordinating test releases it."""

    _BARRIER_TIMEOUT_SECONDS = 5.0

    def __init__(
        self,
        root: Path,
        *,
        lifecycle: StoreLifecycleConfiguration,
    ) -> None:
        """Initialize a real lifecycle store and a closed lease barrier."""
        super().__init__(root, max_bytes=_GIB, lifecycle=lifecycle)
        self.lease_acquisitions = 0
        self.lease_releases = 0
        self.leased_relative_paths: list[str] = []
        self._lease_entered = threading.Event()
        self._lease_continue = threading.Event()

    def wait_until_leased(self, timeout_seconds: float = 1.0) -> bool:
        """Wait for the next real lease to enter without exposing test internals."""
        return self._lease_entered.wait(timeout_seconds)

    def release_lease_barrier(self) -> None:
        """Allow the currently blocked lease consumer to continue."""
        self._lease_continue.set()

    def arm_lease_barrier(self) -> None:
        """Reset observations and block the next lease after balanced setup work."""
        if self.lease_acquisitions != self.lease_releases:
            msg = "test lease barrier cannot reset an active lease"
            raise RuntimeError(msg)
        self.lease_acquisitions = 0
        self.lease_releases = 0
        self.leased_relative_paths.clear()
        self._lease_entered.clear()
        self._lease_continue.clear()

    def lifecycle_capacity_for_test(self) -> StorageCapacity:
        """Return the deterministic configured capacity before probe rebinding."""
        sampler = self._capacity_sampler_override
        if sampler is None:
            msg = "lease-test capacity sampler is unavailable"
            raise RuntimeError(msg)
        return sampler()

    def install_lifecycle_probes_for_test(
        self,
        *,
        capacity_sampler: Callable[[], StorageCapacity] | None = None,
        alert_observer: Callable[[LifecycleAlert], None] | None = None,
    ) -> None:
        """Install deterministic reentrancy probes after safe construction."""
        if capacity_sampler is not None:
            self._capacity_sampler_override = capacity_sampler
        if alert_observer is not None:
            self._lifecycle_alert_observer = alert_observer

    @override
    def acquire_asset_lease(self, relative_path: str) -> tuple[str, Path]:
        key, path = super().acquire_asset_lease(relative_path)
        self.lease_acquisitions += 1
        self.leased_relative_paths.append(relative_path)
        self._lease_entered.set()
        if not self._lease_continue.wait(self._BARRIER_TIMEOUT_SECONDS):
            super().release_asset_lease(key)
            self.lease_releases += 1
            msg = "test lease barrier timed out"
            raise TimeoutError(msg)
        return key, path

    @override
    def release_asset_lease(
        self,
        key: str,
        *,
        transaction_token: object | None = None,
    ) -> None:
        super().release_asset_lease(key, transaction_token=transaction_token)
        if transaction_token is None:
            self.lease_releases += 1


def lease_barrier_store(
    tmp_path: Path,
) -> tuple[LeaseBarrierStore, RetentionPolicy, RetentionClockSample]:
    """Create a real pressure-prunable store whose next lease is controllable."""
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=_GIB,
        maximum_objects=1,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    capacity = StorageCapacity(
        total_bytes=4 * _GIB,
        available_bytes=3 * _GIB,
        total_inodes=1_000_000,
        available_inodes=900_000,
    )
    guard = ClockHighWater(
        tmp_path / "lease-clock-high-water.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    initial = retention_sample(0.0)
    _ = guard.observe(initial)
    if not guard.observe(initial).trusted:
        msg = "lease-test clock did not establish trust"
        raise RuntimeError(msg)
    clock = retention_sample(1.0)
    lifecycle = StoreLifecycleConfiguration(
        policy=policy,
        capacity_sampler=lambda: capacity,
        clock_high_water=guard,
        clock_sampler=lambda: clock,
    )
    return (
        LeaseBarrierStore(tmp_path / "lease-cache", lifecycle=lifecycle),
        policy,
        clock,
    )
