# Copyright (c) 2026 David Osipov
"""Aggregate lifecycle reservation tests for page and tile PDF renders."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

from nplg_mcp.config import load_config
from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.errors import ErrorCode
from nplg_mcp.full_runtime import build_full_services
from nplg_mcp.pdf_executor import (
    PdfPostprocessingPublicationPlan,
    PdfPublicationPlan,
    PublicationReservingPdfExecutor,
    derive_pdf_publication_plan,
)
from nplg_mcp.pdf_ipc import (
    InspectCommand,
    InspectParams,
    PdfFailure,
    PublicWorkerError,
    RenderPagesCommand,
    RenderPagesParams,
    RenderTilesCommand,
    RenderTilesParams,
)
from nplg_mcp.pdf_worker_slot import PdfWorkerSlotPolicy
from nplg_mcp.rate_limit import AsyncRateLimiter
from nplg_mcp.repository import NplgRepository
from nplg_mcp.storage import ContentAddressedStore, StoreLifecycleConfiguration
from nplg_mcp.storage_lifecycle import (
    ClockHighWater,
    PublicationBlocker,
    PublicationReservationError,
    RetentionClockSample,
    RetentionPolicy,
    StorageCapacity,
)
from nplg_mcp.tools import ToolService

if TYPE_CHECKING:
    from nplg_mcp.pdf_ipc import PdfCommand, PdfResult


_GIB = 1024 * 1024 * 1024
_CLOCK_ORIGIN = datetime(2026, 8, 25, tzinfo=UTC)
_DEADLINE = MonotonicDeadline(created_at=0.0, expires_at=60.0)
_TILE_OUTPUT_FILE_COUNT = 101
_TILE_TOPOLOGY_INODE_COUNT = 105
_DUPLICATE_ATTEMPTS = 2


class _ExecutorAction(Protocol):
    def __call__(self) -> None: ...


class _LifecycleLogRecord(Protocol):
    lifecycle_event: object
    lifecycle_blockers: object


@dataclass(slots=True)
class _FakePdfExecutor:
    action: _ExecutorAction
    calls: int = 0
    ready_calls: int = 0

    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        assert deadline is _DEADLINE
        self.calls += 1
        self.action()
        return PdfFailure(
            request_id=command.request_id,
            status="error",
            operation=command.operation,
            payload=PublicWorkerError(
                code=ErrorCode.PDF_PROCESSING_FAILED,
                message="bounded worker failure",
            ),
        )

    def ensure_ready(self) -> None:
        self.ready_calls += 1


class _MutableCapacity:
    def __init__(self, value: StorageCapacity) -> None:
        super().__init__()
        self.value = value

    def __call__(self) -> StorageCapacity:
        return self.value


@dataclass(frozen=True, slots=True)
class _FakeQuotaRoot:
    path: Path


@dataclass(frozen=True, slots=True)
class _FakeStagingQuota:
    root: _FakeQuotaRoot


def _fake_worker_staging_quota(
    *,
    policy: PdfWorkerSlotPolicy,
) -> _FakeStagingQuota:
    return _FakeStagingQuota(root=_FakeQuotaRoot(path=Path(policy.root)))


def _fake_slot_policy_loader(_path: Path) -> PdfWorkerSlotPolicy:
    return _slot_policy()


class _RetentionClock:
    def __init__(self, *, start: float = 61.0) -> None:
        super().__init__()
        self._seconds = start

    def __call__(self) -> RetentionClockSample:
        sample = _clock_sample(self._seconds)
        self._seconds += 1.0
        return sample


def _clock_sample(seconds: float) -> RetentionClockSample:
    return RetentionClockSample(
        utc_now=_CLOCK_ORIGIN + timedelta(seconds=seconds),
        monotonic_now=seconds,
        boot_id="boot-a",
        synchronized=True,
    )


def _slot_policy(
    *,
    maximum_total_bytes: int = _GIB,
    maximum_total_inodes: int = 65_536,
) -> PdfWorkerSlotPolicy:
    payload: dict[str, object] = {
        "version": 1,
        "root": "/var/lib/nplg/pdf-worker-slot",
        "filesystem_type": "ext4",
        "maximum_total_bytes": maximum_total_bytes,
        "minimum_available_bytes": maximum_total_bytes,
        "maximum_total_inodes": maximum_total_inodes,
        "minimum_available_inodes": maximum_total_inodes,
        "mount_options": ["nodev", "noexec", "nosuid", "rw"],
        "concurrency": 1,
    }
    return PdfWorkerSlotPolicy.model_validate(payload, strict=True)


def _page_command(*, page_count: int = 8) -> RenderPagesCommand:
    return RenderPagesCommand(
        request_id=UUID("00000000-0000-0000-0000-000000000001"),
        operation="render_pages",
        source_relative_path="documents/source.pdf",
        parameters=RenderPagesParams(
            pages=tuple(range(1, page_count + 1)),
            mode="native",
        ),
    )


def _tile_command() -> RenderTilesCommand:
    return RenderTilesCommand(
        request_id=UUID("00000000-0000-0000-0000-000000000002"),
        operation="render_tiles",
        parameters=RenderTilesParams(
            render_id="rnd_00000000000000000000000000000000",
            page_number=1,
            tile_width=256,
            tile_height=256,
            overlap=0,
        ),
    )


def _inspect_command() -> InspectCommand:
    return InspectCommand(
        request_id=UUID("00000000-0000-0000-0000-000000000003"),
        operation="inspect",
        source_relative_path="documents/source.pdf",
        parameters=InspectParams(),
    )


def _lifecycle_store(
    tmp_path: Path,
    *,
    available_bytes: int = 3 * _GIB,
    capacity: _MutableCapacity | None = None,
) -> tuple[ContentAddressedStore, StoreLifecycleConfiguration]:
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=2 * _GIB,
        maximum_objects=1000,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    selected_capacity = capacity or _MutableCapacity(
        StorageCapacity(
            total_bytes=4 * _GIB,
            available_bytes=available_bytes,
            total_inodes=1_000_000,
            available_inodes=900_000,
        )
    )
    clock_high_water = ClockHighWater(
        tmp_path / "clock-high-water.json",
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    _ = clock_high_water.observe(_clock_sample(0.0))
    assert clock_high_water.observe(_clock_sample(60.0)).trusted is True
    clock = _RetentionClock()
    lifecycle = StoreLifecycleConfiguration(
        policy=policy,
        capacity_sampler=selected_capacity,
        clock_high_water=clock_high_water,
        clock_sampler=clock,
    )
    return (
        ContentAddressedStore(
            tmp_path / "cache",
            max_bytes=2 * _GIB,
            lifecycle=lifecycle,
        ),
        lifecycle,
    )


def test_publication_plan_includes_manifest_tree_and_temporary_topology() -> None:
    page_plan = derive_pdf_publication_plan(_page_command(), _slot_policy())
    tile_plan = derive_pdf_publication_plan(_tile_command(), _slot_policy())

    assert page_plan == PdfPublicationPlan(
        operation="render_pages",
        maximum_output_files=9,
        maximum_output_directories=1,
        maximum_temporary_files=1,
        maximum_new_bytes=_GIB,
        maximum_new_objects=1,
        maximum_new_inodes=65_536,
    )
    assert tile_plan == PdfPublicationPlan(
        operation="render_tiles",
        maximum_output_files=101,
        maximum_output_directories=3,
        maximum_temporary_files=1,
        maximum_new_bytes=_GIB,
        maximum_new_objects=1,
        maximum_new_inodes=65_536,
    )


def test_publication_plan_never_under_reserves_topology() -> None:
    plan = derive_pdf_publication_plan(
        _tile_command(),
        _slot_policy(maximum_total_bytes=1, maximum_total_inodes=1),
    )

    assert plan.maximum_new_bytes == _TILE_OUTPUT_FILE_COUNT
    assert plan.maximum_new_inodes == _TILE_TOPOLOGY_INODE_COUNT


@pytest.mark.parametrize(
    "payload",
    [
        {"maximum_index_files": True},
        {"maximum_index_files": 0},
        {"maximum_index_files": 102},
        {"maximum_index_files": "1"},
        {"maximum_index_files": 1, "unexpected": 1},
    ],
)
def test_postprocessing_publication_plan_rejects_forged_bounds(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _ = PdfPostprocessingPublicationPlan.model_validate(payload, strict=True)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "operation": "render_pages",
            "maximum_output_files": True,
            "maximum_output_directories": 1,
            "maximum_temporary_files": 1,
            "maximum_new_bytes": 1,
            "maximum_new_objects": 1,
            "maximum_new_inodes": 1,
        },
        {
            "operation": "render_pages",
            "maximum_output_files": 1,
            "maximum_output_directories": 1,
            "maximum_temporary_files": 1,
            "maximum_new_bytes": 1,
            "maximum_new_objects": 1,
            "maximum_new_inodes": 1,
            "unexpected": 1,
        },
    ],
)
def test_publication_plan_is_a_strict_closed_schema(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _ = PdfPublicationPlan.model_validate(payload, strict=True)


@pytest.mark.parametrize(
    ("maximum_new_bytes", "maximum_new_inodes", "message"),
    [
        (1, 4, "bytes do not cover every bounded output"),
        (2, 3, "inodes do not cover the complete tree"),
    ],
)
def test_publication_plan_rejects_under_reserved_tree_capacity(
    maximum_new_bytes: int,
    maximum_new_inodes: int,
    message: str,
) -> None:
    payload: dict[str, object] = {
        "operation": "render_pages",
        "maximum_output_files": 2,
        "maximum_output_directories": 1,
        "maximum_temporary_files": 1,
        "maximum_new_bytes": maximum_new_bytes,
        "maximum_new_objects": 1,
        "maximum_new_inodes": maximum_new_inodes,
    }

    with pytest.raises(ValidationError, match=message):
        _ = PdfPublicationPlan.model_validate(payload, strict=True)


@pytest.mark.asyncio
async def test_nonpublication_command_bypasses_storage_reservation(
    tmp_path: Path,
) -> None:
    """Inspection must not consume the page/tile publication reservation budget."""
    store, lifecycle = _lifecycle_store(tmp_path)
    inner = _FakePdfExecutor(lambda: None)
    executor = PublicationReservingPdfExecutor(
        inner=inner,
        store=store,
        lifecycle=lifecycle,
        slot_policy=_slot_policy(),
    )

    _ = await executor.execute(_inspect_command(), deadline=_DEADLINE)

    assert inner.calls == 1
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_reservation_is_held_before_worker_dispatch_and_released_on_return(
    tmp_path: Path,
) -> None:
    store, lifecycle = _lifecycle_store(tmp_path)

    def assert_reserved() -> None:
        assert (
            store.publication_reserved_bytes,
            store.publication_reserved_objects,
            store.publication_reserved_inodes,
        ) == (_GIB, 1, 65_536)

    inner = _FakePdfExecutor(assert_reserved)
    executor = PublicationReservingPdfExecutor(
        inner=inner,
        store=store,
        lifecycle=lifecycle,
        slot_policy=_slot_policy(),
    )

    _ = await executor.execute(_page_command(), deadline=_DEADLINE)

    assert inner.calls == 1
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_admission_denial_occurs_before_worker_dispatch(
    tmp_path: Path,
) -> None:
    minimum_free = 64 * 1024 * 1024
    store, lifecycle = _lifecycle_store(
        tmp_path,
        available_bytes=minimum_free + _GIB - 1,
    )
    inner = _FakePdfExecutor(lambda: None)
    executor = PublicationReservingPdfExecutor(
        inner=inner,
        store=store,
        lifecycle=lifecycle,
        slot_policy=_slot_policy(),
    )

    with pytest.raises(PublicationReservationError) as raised:
        _ = await executor.execute(_tile_command(), deadline=_DEADLINE)

    assert raised.value.blocker is PublicationBlocker.BYTE_HEADROOM
    assert inner.calls == 0
    assert store.publication_reserved_bytes == 0


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("worker timeout"),
        RuntimeError("partial output"),
        asyncio.CancelledError("caller cancelled"),
    ],
)
@pytest.mark.asyncio
async def test_every_exceptional_exit_releases_the_complete_reservation_once(
    tmp_path: Path,
    failure: BaseException,
) -> None:
    store, lifecycle = _lifecycle_store(tmp_path)

    def fail() -> None:
        raise failure

    executor = PublicationReservingPdfExecutor(
        inner=_FakePdfExecutor(fail),
        store=store,
        lifecycle=lifecycle,
        slot_policy=_slot_policy(),
    )

    with pytest.raises(type(failure), match=str(failure)):
        _ = await executor.execute(_tile_command(), deadline=_DEADLINE)

    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_commit_recheck_failure_aborts_and_releases_once(tmp_path: Path) -> None:
    capacity = _MutableCapacity(
        StorageCapacity(
            total_bytes=4 * _GIB,
            available_bytes=3 * _GIB,
            total_inodes=1_000_000,
            available_inodes=900_000,
        )
    )
    store, lifecycle = _lifecycle_store(tmp_path, capacity=capacity)

    def shrink_after_admission() -> None:
        capacity.value = StorageCapacity(
            total_bytes=4 * _GIB,
            available_bytes=64 * 1024 * 1024 - 1,
            total_inodes=1_000_000,
            available_inodes=900_000,
        )

    executor = PublicationReservingPdfExecutor(
        inner=_FakePdfExecutor(shrink_after_admission),
        store=store,
        lifecycle=lifecycle,
        slot_policy=_slot_policy(),
    )

    with pytest.raises(PublicationReservationError) as raised:
        _ = await executor.execute(_page_command(), deadline=_DEADLINE)

    assert raised.value.blocker is PublicationBlocker.BYTE_HEADROOM
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_duplicate_noop_return_releases_reservation_and_next_job_proceeds(
    tmp_path: Path,
) -> None:
    store, lifecycle = _lifecycle_store(tmp_path)
    inner = _FakePdfExecutor(lambda: None)
    executor = PublicationReservingPdfExecutor(
        inner=inner,
        store=store,
        lifecycle=lifecycle,
        slot_policy=_slot_policy(),
    )

    _ = await executor.execute(_page_command(), deadline=_DEADLINE)
    _ = await executor.execute(_page_command(), deadline=_DEADLINE)

    assert inner.calls == _DUPLICATE_ATTEMPTS
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_forged_command_is_rejected_before_reservation_or_dispatch(
    tmp_path: Path,
) -> None:
    store, lifecycle = _lifecycle_store(tmp_path)
    inner = _FakePdfExecutor(lambda: None)
    executor = PublicationReservingPdfExecutor(
        inner=inner,
        store=store,
        lifecycle=lifecycle,
        slot_policy=_slot_policy(),
    )
    forged = RenderPagesCommand.model_construct(
        request_id=UUID("00000000-0000-0000-0000-000000000003"),
        operation="render_pages",
        source_relative_path="documents/source.pdf",
        parameters=RenderPagesParams.model_construct(
            pages=tuple(range(1, 10)),
            mode="native",
        ),
    )

    with pytest.raises(ValidationError):
        _ = await executor.execute(forged, deadline=_DEADLINE)

    assert inner.calls == 0
    assert store.publication_reserved_bytes == 0


def test_wrapper_readiness_delegates_without_reserving(tmp_path: Path) -> None:
    store, lifecycle = _lifecycle_store(tmp_path)
    inner = _FakePdfExecutor(lambda: None)
    executor = PublicationReservingPdfExecutor(
        inner=inner,
        store=store,
        lifecycle=lifecycle,
        slot_policy=_slot_policy(),
    )

    executor.ensure_ready()

    assert inner.ready_calls == 1
    assert store.publication_reserved_bytes == 0


@pytest.mark.asyncio
async def test_production_unix_runtime_selects_aggregate_reservation_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = replace(
        load_config(
            {
                "NODE_ENV": "test",
                "DEPLOYMENT_PROFILE": "private-full",
                "PDF_EXECUTOR": "unix-worker",
                "CACHE_DIR": str(tmp_path),
                "CACHE_MAX_BYTES": str(_GIB),
                "ASSET_SIGNING_SECRET": "s" * 32,
                "CURSOR_SIGNING_SECRET": "c" * 32,
                "ALLOW_ANONYMOUS": "true",
            }
        ),
        environment="production",
        retention_clock_synchronized=True,
    )
    monkeypatch.setattr(
        "nplg_mcp.full_runtime.load_pdf_worker_slot_policy",
        _fake_slot_policy_loader,
    )
    monkeypatch.setattr(
        "nplg_mcp.full_runtime.WorkerStagingQuota",
        _fake_worker_staging_quota,
    )
    async with httpx.AsyncClient() as client:
        services = build_full_services(
            config=config,
            repository=NplgRepository(
                client=client,
                validate_dns=False,
                cursor_signing_secret=b"c" * 32,
            ),
            client=client,
            limiter=AsyncRateLimiter(rate_per_second=1.0),
        )

    assert isinstance(services.tools, ToolService)
    assert isinstance(services.tools.pdf, PublicationReservingPdfExecutor)
    with caplog.at_level(logging.WARNING, logger="nplg_mcp.lifecycle"):
        report = services.tools.store.reconcile_lifecycle()

    assert report.status == "unsatisfied"
    records = [
        record
        for record in caplog.records
        if record.getMessage() == "nplg_artifact_lifecycle_alert"
    ]
    assert len(records) == 1
    lifecycle_record = cast("_LifecycleLogRecord", records[0])
    assert lifecycle_record.lifecycle_event == "prune_unsatisfied"
    assert lifecycle_record.lifecycle_blockers == "clock_anomaly"
    assert str(tmp_path) not in records[0].getMessage()


@pytest.mark.asyncio
async def test_full_runtime_rejects_a_symlinked_configured_cache_root(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    configured = tmp_path / "configured-cache"
    configured.symlink_to(target, target_is_directory=True)
    config = load_config(
        {
            "NODE_ENV": "test",
            "DEPLOYMENT_PROFILE": "private-full",
            "PDF_EXECUTOR": "serialized",
            "CACHE_DIR": str(configured),
            "CACHE_MAX_BYTES": str(_GIB),
            "ASSET_SIGNING_SECRET": "s" * 32,
            "CURSOR_SIGNING_SECRET": "c" * 32,
            "ALLOW_ANONYMOUS": "true",
        }
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="cache root"):
            _ = build_full_services(
                config=config,
                repository=NplgRepository(
                    client=client,
                    validate_dns=False,
                    cursor_signing_secret=b"c" * 32,
                ),
                client=client,
                limiter=AsyncRateLimiter(rate_per_second=1.0),
            )
