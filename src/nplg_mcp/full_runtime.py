# Copyright (c) 2026 David Osipov
"""Private-full runtime composition, isolated from metadata-only startup."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .downloader import DocumentDownloader
from .malware import ClamAvUnixSocketScanner
from .pdf_executor import (
    PdfExecutor,
    PdfProcessorSettings,
    PdfWorkerPolicy,
    PublicationReservingPdfExecutor,
)
from .pdf_worker_client import (
    SubprocessPdfExecutor,
    UnixSocketPdfExecutor,
    WorkerStagingBinding,
)
from .pdf_worker_slot import WorkerStagingQuota, load_pdf_worker_slot_policy
from .services import FullServiceComposition
from .storage import ContentAddressedStore, StoreLifecycleConfiguration
from .storage_lifecycle import (
    ClockHighWater,
    LifecycleAlert,
    RetentionPolicy,
    SystemRetentionClock,
)
from .tools import ToolService, ToolServiceDependencies

if TYPE_CHECKING:
    from .config import AppConfig
    from .http_types import HttpClientProtocol
    from .rate_limit import AsyncRateLimiter
    from .repository import NplgRepository

_LIFECYCLE_LOGGER = logging.getLogger("nplg_mcp.lifecycle")


def _observe_lifecycle_alert(alert: LifecycleAlert) -> None:
    """Emit only enum-bounded lifecycle state, never paths or usage values."""
    _LIFECYCLE_LOGGER.warning(
        "nplg_artifact_lifecycle_alert",
        extra={
            "lifecycle_event": alert.event.value,
            "lifecycle_blockers": ",".join(blocker.value for blocker in alert.blockers),
        },
    )


def build_full_services(
    *,
    config: AppConfig,
    repository: NplgRepository,
    client: HttpClientProtocol,
    limiter: AsyncRateLimiter,
) -> FullServiceComposition:
    """Construct the private-full downloader, store, PDF, and tool services."""
    cache_root = config.cache_dir.expanduser().absolute()
    retention_policy = RetentionPolicy(
        maximum_age_seconds=config.retention_max_age_seconds,
        maximum_bytes=config.cache_max_bytes,
        maximum_objects=config.retention_max_objects,
        minimum_free_bytes=config.retention_min_free_bytes,
        minimum_free_inodes=config.retention_min_free_inodes,
    )
    retention_clock = SystemRetentionClock(
        synchronized=config.retention_clock_synchronized,
    )
    lifecycle = StoreLifecycleConfiguration(
        policy=retention_policy,
        capacity_sampler=None,
        clock_high_water=ClockHighWater(
            cache_root / ".retention-clock-high-water.json",
            healthy_window_seconds=config.retention_healthy_window_seconds,
            maximum_forward_slew_seconds=(config.retention_max_forward_slew_seconds),
        ),
        clock_sampler=retention_clock,
        alert_observer=_observe_lifecycle_alert,
    )
    store = ContentAddressedStore(
        cache_root,
        max_bytes=config.cache_max_bytes,
        lifecycle=lifecycle,
    )
    downloader = DocumentDownloader(
        client=client,
        store=store,
        max_bytes=config.max_download_bytes,
        max_redirects=config.max_redirects,
        limiter=limiter,
        total_timeout_seconds=float(config.upstream_timeout_seconds),
        guard=repository.guard,
        scanner=ClamAvUnixSocketScanner(
            socket_path=config.scanner_socket_path,
            max_bytes=config.max_download_bytes,
        ),
        require_scanner=True,
        retention_policy=retention_policy,
        retention_clock=retention_clock,
    )
    policy = PdfWorkerPolicy(
        capacity=config.max_concurrent_pdf_jobs,
        processor=PdfProcessorSettings(
            max_pages_per_render=config.max_render_pages,
            max_page_pixels=config.max_page_pixels,
            max_render_pixels=config.max_render_pixels,
            tile_width=config.tile_width,
            tile_height=config.tile_height,
            tile_overlap=config.tile_overlap,
        ),
    )
    pdf: PdfExecutor
    slot_policy = None
    if config.pdf_executor == "unix-worker":
        staging_quota: WorkerStagingQuota | None = None
        if config.environment == "production":
            slot_policy = load_pdf_worker_slot_policy(
                config.pdf_worker_slot_policy_path
            )
            staging_quota = WorkerStagingQuota(policy=slot_policy)
        pdf = UnixSocketPdfExecutor(
            store=store,
            socket_path=config.pdf_worker_socket_path,
            staging=WorkerStagingBinding(
                root=config.pdf_worker_slot_root,
                quota=staging_quota,
            ),
            policy=policy,
        )
    else:
        pdf = SubprocessPdfExecutor(store=store, policy=policy)
    if slot_policy is not None:
        pdf = PublicationReservingPdfExecutor(
            inner=pdf,
            store=store,
            lifecycle=lifecycle,
            slot_policy=slot_policy,
        )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=repository,
            downloader=downloader,
            pdf=pdf,
            store=store,
        ),
        config=config,
    )
    return FullServiceComposition(tools=tools, store=store, http_client=client)
