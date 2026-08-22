# Copyright (c) 2026 David Osipov
"""Shared deterministic application and tool-service factories."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, cast

from nplg_mcp.config import (
    AppConfig,
    load_config,
)
from nplg_mcp.config import (
    DeploymentProfile as DeploymentProfileName,
)
from nplg_mcp.downloader import DownloadResult
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parsers import Bitstream, DocumentRecord, SearchItem, SearchPage
from nplg_mcp.pdf import PdfProcessor
from nplg_mcp.services import MetadataServiceComposition
from nplg_mcp.storage import ContentAddressedStore
from nplg_mcp.tools import (
    DownloaderProtocol,
    RepositoryProtocol,
    ToolService,
    ToolServiceDependencies,
)
from tests.helpers.inline_pdf_executor import InlinePdfExecutor
from tests.helpers.pdf_factory import make_raster_pdf

if TYPE_CHECKING:
    from pathlib import Path

FixtureFaultMode = Literal["none", "app_error", "generic_error"]
FIXTURE_ERROR_CANARY = "nplg-baseline-private-canary"
FIXED_UTC_NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)


def fixture_utc_now() -> datetime:
    """Return the fixed UTC instant used by deterministic fixture factories."""
    return FIXED_UTC_NOW


def base_environment(**overrides: str) -> dict[str, str]:
    """Return the deterministic environment shared by unit and contract tests."""
    environment = {
        "NODE_ENV": "test",
        "ASSET_SIGNING_SECRET": "s" * 32,
        "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
        "ALLOW_ANONYMOUS": "true",
        "CACHE_DIR": ".data/test-cache",
    }
    environment.update(overrides)
    return environment


class _FixtureRepository:
    def __init__(self, fault_mode: FixtureFaultMode) -> None:
        super().__init__()
        self._fault_mode = fault_mode
        self.public_file = Bitstream(
            bitstream_id="bs_public",
            handle="1234/560449",
            filename="issue.pdf",
            source_url="https://dspace.nplg.gov.ge/bitstream/1234/560449/1/issue.pdf",
            reported_size=123,
            reported_format="Adobe PDF",
            access_status="public",
        )

    async def search(
        self,
        query: str,
        *,
        cursor: str | None = None,
        page_size: int = 20,
        scope_handle: str | None = None,
    ) -> SearchPage:
        del cursor, page_size, scope_handle
        if self._fault_mode == "app_error":
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The fixture repository was unavailable.",
                http_status=502,
                internal_details={"canary": FIXTURE_ERROR_CANARY},
            )
        if self._fault_mode == "generic_error":
            raise RuntimeError(FIXTURE_ERROR_CANARY)
        return SearchPage(
            items=(
                SearchItem(
                    handle="1234/560449",
                    canonical_url="https://dspace.nplg.gov.ge/handle/1234/560449",
                    title=query,
                ),
            ),
            total=1,
            next_offset=None,
            source_url="https://dspace.nplg.gov.ge/simple-search",
        )

    async def get_metadata(self, handle: str) -> DocumentRecord:
        return DocumentRecord(
            handle=handle,
            canonical_url=f"https://dspace.nplg.gov.ge/handle/{handle}",
            title="fixture",
            languages=("ka",),
            metadata_source="oai_dim",
        )

    async def list_files(self, handle: str) -> tuple[Bitstream, ...]:
        del handle
        return (self.public_file,)


class _FixtureDownloader:
    def __init__(self, store: ContentAddressedStore, pdf_bytes: bytes) -> None:
        super().__init__()
        self.store = store
        self._pdf_bytes = pdf_bytes

    async def download(self, bitstream: Bitstream) -> DownloadResult:
        artifact = self.store.put_bytes(
            self._pdf_bytes,
            namespace="documents",
            filename="source.pdf",
            media_type="application/pdf",
        )
        return DownloadResult(
            artifact=artifact,
            source_bitstream_id=bitstream.bitstream_id,
            source_url=bitstream.source_url,
            bytes_downloaded=artifact.size,
        )


def _config_for(
    tmp_path: Path,
    *,
    deployment_profile: DeploymentProfileName = "private-full",
    frozen_origin: bool = False,
) -> AppConfig:
    config = load_config(base_environment(CACHE_DIR=str(tmp_path)))
    return replace(
        config,
        deployment_profile=deployment_profile,
        public_base_url=(
            "http://testserver" if frozen_origin else config.public_base_url
        ),
    )


def _pdf_for(config: AppConfig, store: ContentAddressedStore) -> PdfProcessor:
    return PdfProcessor(
        store=store,
        max_pages_per_render=config.max_render_pages,
        max_page_pixels=config.max_page_pixels,
        max_render_pixels=config.max_render_pixels,
        tile_width=config.tile_width,
        tile_height=config.tile_height,
        tile_overlap=config.tile_overlap,
    )


def make_tool_service(
    tmp_path: Path,
    *,
    pdf_processor: PdfProcessor | None = None,
    fault_mode: FixtureFaultMode = "none",
    deployment_profile: DeploymentProfileName = "private-full",
    frozen_origin: bool = False,
) -> ToolService:
    """Construct a production ToolService with offline deterministic collaborators."""
    config = _config_for(
        tmp_path,
        deployment_profile=deployment_profile,
        frozen_origin=frozen_origin,
    )
    store = ContentAddressedStore(tmp_path, max_bytes=config.cache_max_bytes)
    fixture = make_raster_pdf(
        tmp_path / "fixture-source.pdf",
        width=600,
        height=400,
        dpi=200,
    )
    pdf = pdf_processor or _pdf_for(config, store)
    return ToolService(
        dependencies=ToolServiceDependencies(
            repository=cast("RepositoryProtocol", _FixtureRepository(fault_mode)),
            downloader=cast(
                "DownloaderProtocol",
                _FixtureDownloader(store, fixture.path.read_bytes()),
            ),
            pdf=InlinePdfExecutor(processor=pdf, store=store),
            store=store,
        ),
        config=config,
        utc_now=fixture_utc_now,
    )


def make_app_services(tmp_path: Path) -> MetadataServiceComposition:
    """Construct the concrete metadata composition used by SDK contract tests."""
    tools = make_tool_service(tmp_path, deployment_profile="alpic-metadata")
    return MetadataServiceComposition(tools=tools, http_client=None)
