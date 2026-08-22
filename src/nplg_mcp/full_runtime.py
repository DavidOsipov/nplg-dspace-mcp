# Copyright (c) 2026 David Osipov
"""Private-full runtime composition, isolated from metadata-only startup."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .downloader import DocumentDownloader
from .malware import ClamAvUnixSocketScanner
from .pdf_executor import PdfExecutor, PdfProcessorSettings, PdfWorkerPolicy
from .pdf_worker_client import (
    SubprocessPdfExecutor,
    UnixSocketPdfExecutor,
    WorkerStagingBinding,
)
from .pdf_worker_slot import WorkerStagingQuota, load_pdf_worker_slot_policy
from .services import FullServiceComposition
from .storage import ContentAddressedStore
from .tools import ToolService, ToolServiceDependencies

if TYPE_CHECKING:
    from .config import AppConfig
    from .http_types import HttpClientProtocol
    from .rate_limit import AsyncRateLimiter
    from .repository import NplgRepository


def build_full_services(
    *,
    config: AppConfig,
    repository: NplgRepository,
    client: HttpClientProtocol,
    limiter: AsyncRateLimiter,
) -> FullServiceComposition:
    """Construct the private-full downloader, store, PDF, and tool services."""
    store = ContentAddressedStore(
        config.cache_dir,
        max_bytes=config.cache_max_bytes,
    )
    downloader = DocumentDownloader(
        client=client,
        store=store,
        max_bytes=config.max_download_bytes,
        max_redirects=config.max_redirects,
        limiter=limiter,
        total_timeout_seconds=config.upstream_timeout_seconds,
        scanner=ClamAvUnixSocketScanner(
            socket_path=config.scanner_socket_path,
            max_bytes=config.max_download_bytes,
        ),
        require_scanner=True,
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
