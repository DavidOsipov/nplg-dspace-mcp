# Copyright (c) 2026 David Osipov
"""Private-full runtime composition, isolated from metadata-only startup."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .downloader import DocumentDownloader
from .pdf_executor import PdfProcessorSettings, PdfWorkerPolicy
from .pdf_worker_client import SubprocessPdfExecutor
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
) -> tuple[ToolService, ContentAddressedStore]:
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
    )
    pdf = SubprocessPdfExecutor(
        store=store,
        policy=PdfWorkerPolicy(
            capacity=config.max_concurrent_pdf_jobs,
            processor=PdfProcessorSettings(
                max_pages_per_render=config.max_render_pages,
                max_page_pixels=config.max_page_pixels,
                max_render_pixels=config.max_render_pixels,
                tile_width=config.tile_width,
                tile_height=config.tile_height,
                tile_overlap=config.tile_overlap,
            ),
        ),
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
    return tools, store
