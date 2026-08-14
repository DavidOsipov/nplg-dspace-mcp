from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from nplg_mcp.config import AppConfig
from nplg_mcp.downloader import DownloadResult
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parsers import Bitstream, DocumentRecord, SearchItem, SearchPage
from nplg_mcp.pdf import PdfInspection, RenderedPage, RenderManifest, TileManifest
from nplg_mcp.storage import ContentAddressedStore
from nplg_mcp.tokens import verify_asset_token
from nplg_mcp.tools import SearchDocumentsInput, ToolService


def test_search_page_size_is_capped_at_fifty() -> None:
    with pytest.raises(ValidationError):
        SearchDocumentsInput.model_validate({"query": "ივერია", "page_size": 51})


class FakeRepository:
    def __init__(self) -> None:
        self.public_file = Bitstream(
            bitstream_id="bs_public",
            handle="1234/560449",
            filename="issue.pdf",
            source_url="https://dspace.nplg.gov.ge/bitstream/1234/560449/1/issue.pdf",
            reported_size=123,
            reported_format="Adobe PDF",
            access_status="public",
        )

    async def search(self, query: str, *, cursor: str | None = None, page_size: int = 20, scope_handle: str | None = None) -> SearchPage:
        assert query == "ივერია"
        return SearchPage(
            items=(SearchItem(handle="1234/560449", canonical_url="https://dspace.nplg.gov.ge/handle/1234/560449", title="ივერია"),),
            total=1,
            next_offset=None,
            source_url="https://dspace.nplg.gov.ge/simple-search",
        )

    async def get_metadata(self, handle: str) -> DocumentRecord:
        return DocumentRecord(
            handle=handle,
            canonical_url=f"https://dspace.nplg.gov.ge/handle/{handle}",
            title="ბორჯომი N34",
            languages=("ka",),
            metadata_source="oai_dim",
        )

    async def list_files(self, handle: str) -> tuple[Bitstream, ...]:
        assert handle == "1234/560449"
        return (self.public_file,)


class FakeDownloader:
    def __init__(self, store: ContentAddressedStore) -> None:
        self.store = store
        self.calls: list[str] = []

    async def download(self, bitstream: Bitstream) -> DownloadResult:
        self.calls.append(bitstream.bitstream_id)
        artifact = self.store.put_bytes(
            b"%PDF-1.7\nfixture",
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


class FakePdfProcessor:
    def __init__(self, store: ContentAddressedStore) -> None:
        self.store = store
        self.deleted: list[str] = []
        page = self.store.put_bytes(
            b"jpeg-page",
            namespace="renders",
            filename="page-0001.jpg",
            media_type="image/jpeg",
        )
        # Tool tests do not rely on the content-addressed render directory shape;
        # they only exercise signed delivery of a validated stored relative path.
        self.page_path = page.relative_path

    def inspect(self, pdf_path: Path) -> PdfInspection:
        assert pdf_path.name == "source.pdf"
        return PdfInspection(source_sha256="a" * 64, page_count=1, renderer_version="test", pages=())

    def render_pages(self, pdf_path: Path, *, pages: tuple[int, ...], mode: str) -> RenderManifest:
        assert pages == (1,)
        assert mode == "native"
        return RenderManifest(
            render_id="rnd_" + "1" * 32,
            source_sha256="a" * 64,
            renderer_version="test",
            mode="native",
            pages=(
                RenderedPage(
                    page_number=1,
                    width=100,
                    height=200,
                    rotation=0,
                    classification="single_raster_jpeg",
                    effective_dpi_x=300.0,
                    effective_dpi_y=300.0,
                    resolution_source="embedded_scan",
                    conversion_path="direct_extract",
                    relative_path=self.page_path,
                    sha256="b" * 64,
                    media_type="image/jpeg",
                    resize_applied=False,
                    pixel_dimensions_preserved=True,
                    renderer_resampling="none",
                    reencoded=False,
                    lossy_conversion=False,
                ),
            ),
            manifest_relative_path="renders/rnd_" + "1" * 32 + "/manifest.json",
        )

    def render_tiles(self, render_id: str, *, page_number: int, tile_width: int | None = None, tile_height: int | None = None, overlap: int | None = None) -> TileManifest:
        return TileManifest(
            render_id=render_id,
            page_number=page_number,
            page_sha256="b" * 64,
            tile_width=tile_width or 2048,
            tile_height=tile_height or 2048,
            overlap=128 if overlap is None else overlap,
            tiles=(),
            manifest_relative_path=f"renders/{render_id}/tiles/page-{page_number:04d}/manifest.json",
        )

    def get_manifest(self, render_id: str) -> RenderManifest:
        return self.render_pages(Path("source.pdf"), pages=(1,), mode="native")

    def delete_render(self, render_id: str) -> bool:
        self.deleted.append(render_id)
        return True


def config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        environment="test",
        nplg_base_url="https://dspace.nplg.gov.ge/",
        cache_dir=tmp_path,
        public_base_url="https://mcp.example.test",
        asset_signing_secret=b"s" * 32,
        api_bearer_token=None,
        api_key=None,
        allow_anonymous=True,
        max_download_bytes=1024 * 1024,
        max_render_pages=8,
        max_page_pixels=120_000_000,
        max_render_pixels=480_000_000,
        max_request_body_bytes=1024 * 1024,
        tile_width=2048,
        tile_height=2048,
        tile_overlap=128,
        asset_ttl_seconds=3600,
        upstream_timeout_seconds=30,
        upstream_rate_per_second=1,
        max_redirects=3,
    )


def service(tmp_path: Path) -> tuple[ToolService, FakeDownloader]:
    store = ContentAddressedStore(tmp_path)
    downloader = FakeDownloader(store)
    return (
        ToolService(
            repository=FakeRepository(),
            downloader=downloader,
            pdf=FakePdfProcessor(store),
            store=store,
            config=config(tmp_path),
        ),
        downloader,
    )


def test_tool_catalog_is_deterministic_and_strict(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    first = tools.list_tools()
    second = tools.list_tools()

    assert first == second
    assert [tool["name"] for tool in first] == sorted(tool["name"] for tool in first)
    assert {tool["name"] for tool in first} >= {
        "search_documents",
        "get_document_metadata",
        "list_document_files",
        "download_document_file",
        "inspect_pdf",
        "render_pdf_pages",
        "render_pdf_page_tiles",
        "get_render_manifest",
    }
    assert "delete_render" not in {tool["name"] for tool in first}
    cache_writing_tools = {"download_document_file", "render_pdf_pages", "render_pdf_page_tiles"}
    for tool in first:
        assert tool["inputSchema"]["type"] == "object"
        assert tool["inputSchema"]["additionalProperties"] is False
        assert tool["annotations"]["readOnlyHint"] is (tool["name"] not in cache_writing_tools)
        assert tool["annotations"]["destructiveHint"] is False
        assert tool["annotations"]["idempotentHint"] is (tool["name"] != "download_document_file")
        json.dumps(tool, ensure_ascii=False)


@pytest.mark.asyncio
async def test_search_preserves_georgian_unicode_and_structured_fields(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    result = await tools.call("search_documents", {"query": "ივერია", "page_size": 10})

    assert result["items"][0]["title"] == "ივერია"
    assert result["total"] == 1
    assert result["next_cursor"] is None


@pytest.mark.asyncio
async def test_download_uses_only_discovered_bitstream_and_returns_bound_signed_url(tmp_path: Path) -> None:
    tools, downloader = service(tmp_path)
    result = await tools.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )

    assert downloader.calls == ["bs_public"]
    assert result["artifact_id"].startswith("doc_")
    assert result["asset_url"].startswith("https://mcp.example.test/assets/")
    token = result["asset_url"].rsplit("/", 1)[-1]
    grant = verify_asset_token(config(tmp_path).asset_signing_secret, token, now=datetime.now(UTC))
    assert grant.path == result["relative_path"]
    assert grant.media_type == "application/pdf"


@pytest.mark.asyncio
async def test_unknown_bitstream_is_rejected_before_any_download(tmp_path: Path) -> None:
    tools, downloader = service(tmp_path)

    with pytest.raises(AppError) as caught:
        await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "attacker-controlled"},
        )

    assert caught.value.code is ErrorCode.NOT_FOUND
    assert downloader.calls == []


@pytest.mark.asyncio
async def test_artifact_chain_inspect_render_tile_manifest_and_delete(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    downloaded = await tools.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )
    artifact_id = downloaded["artifact_id"]

    inspected = await tools.call("inspect_pdf", {"artifact_id": artifact_id})
    assert inspected["page_count"] == 1

    rendered = await tools.call("render_pdf_pages", {"artifact_id": artifact_id, "pages": [1]})
    assert rendered["render_id"].startswith("rnd_")
    assert rendered["pages"][0]["asset_url"].startswith("https://mcp.example.test/assets/")

    tiled = await tools.call(
        "render_pdf_page_tiles",
        {"render_id": rendered["render_id"], "page_number": 1},
    )
    assert tiled["page_number"] == 1

    manifest = await tools.call("get_render_manifest", {"render_id": rendered["render_id"]})
    assert manifest["render_id"] == rendered["render_id"]


@pytest.mark.asyncio
async def test_render_deletion_is_not_exposed_as_an_mcp_tool(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(AppError) as caught:
        await tools.call("delete_render", {"render_id": "rnd_" + "0" * 32})

    assert caught.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_tool_argument_validation_rejects_unknown_fields_and_arbitrary_urls(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(AppError) as extra:
        await tools.call("search_documents", {"query": "x", "url": "https://evil.example"})
    assert extra.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(AppError) as blank:
        await tools.call("search_documents", {"query": "   "})
    assert blank.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [{"tile_width": 4097}, {"tile_height": 4097}, {"overlap": 513}])
async def test_tile_tool_rejects_geometry_above_compiled_ceilings(
    tmp_path: Path, arguments: dict[str, int]
) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(AppError) as oversized:
        await tools.call(
            "render_pdf_page_tiles",
            {"render_id": "rnd_" + "1" * 32, "page_number": 1, **arguments},
        )

    assert oversized.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_pdf_jobs_respect_the_configured_concurrency_limit(tmp_path: Path) -> None:
    import asyncio
    import threading
    from dataclasses import replace

    class BlockingPdf(FakePdfProcessor):
        def __init__(self, store: ContentAddressedStore) -> None:
            super().__init__(store)
            self.active = 0
            self.max_active = 0
            self.started = threading.Event()
            self.release = threading.Event()
            self.lock = threading.Lock()

        def inspect(self, pdf_path: Path) -> PdfInspection:
            with self.lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
                self.started.set()
            try:
                assert self.release.wait(timeout=2)
                return super().inspect(pdf_path)
            finally:
                with self.lock:
                    self.active -= 1

    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    pdf = BlockingPdf(store)
    cfg = replace(config(tmp_path), max_concurrent_pdf_jobs=1)
    tools = ToolService(
        repository=FakeRepository(),
        downloader=FakeDownloader(store),
        pdf=pdf,
        store=store,
        config=cfg,
    )

    first = asyncio.create_task(tools.call("inspect_pdf", {"artifact_id": artifact.object_id}))
    assert await asyncio.to_thread(pdf.started.wait, 1)
    second = asyncio.create_task(tools.call("inspect_pdf", {"artifact_id": artifact.object_id}))
    await asyncio.sleep(0.05)

    assert pdf.max_active == 1
    pdf.release.set()
    await asyncio.gather(first, second)
    assert pdf.max_active == 1


@pytest.mark.asyncio
async def test_cancelled_pdf_request_keeps_permit_until_native_worker_exits(tmp_path: Path) -> None:
    import asyncio
    import threading
    from dataclasses import replace

    class BlockingPdf(FakePdfProcessor):
        def __init__(self, store: ContentAddressedStore) -> None:
            super().__init__(store)
            self.active = 0
            self.max_active = 0
            self.started_count = 0
            self.first_started = threading.Event()
            self.second_started = threading.Event()
            self.release = threading.Event()
            self.lock = threading.Lock()

        def inspect(self, pdf_path: Path) -> PdfInspection:
            with self.lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
                self.started_count += 1
                if self.started_count == 1:
                    self.first_started.set()
                else:
                    self.second_started.set()
            try:
                assert self.release.wait(timeout=2)
                return super().inspect(pdf_path)
            finally:
                with self.lock:
                    self.active -= 1

    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    pdf = BlockingPdf(store)
    tools = ToolService(
        repository=FakeRepository(),
        downloader=FakeDownloader(store),
        pdf=pdf,
        store=store,
        config=replace(config(tmp_path), max_concurrent_pdf_jobs=1),
    )

    first = asyncio.create_task(tools.call("inspect_pdf", {"artifact_id": artifact.object_id}))
    assert await asyncio.to_thread(pdf.first_started.wait, 1)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    second = asyncio.create_task(tools.call("inspect_pdf", {"artifact_id": artifact.object_id}))
    assert not await asyncio.to_thread(pdf.second_started.wait, 0.2)
    assert pdf.max_active == 1

    pdf.release.set()
    await second
    assert pdf.max_active == 1
