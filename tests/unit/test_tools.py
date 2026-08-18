# Copyright (c) 2026 David Osipov
"""Unit tests for the typed tool service."""

from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypeVar, cast, override

import pytest
from pydantic import ValidationError

from nplg_mcp.config import AppConfig, PdfExecutor
from nplg_mcp.downloader import DownloadResult
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.json_types import load_json_value, require_json_object
from nplg_mcp.parsers import Bitstream, DocumentRecord, SearchItem, SearchPage
from nplg_mcp.pdf import (
    PdfInspection,
    RenderedPage,
    RenderedTile,
    RenderManifest,
    TileManifest,
)
from nplg_mcp.storage import ContentAddressedStore
from nplg_mcp.tokens import verify_asset_token
from nplg_mcp.tools import (
    SearchDocumentsInput,
    ToolService,
    ToolServiceDependencies,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from nplg_mcp.json_types import JsonObject, JsonValue
ControlledResultT = TypeVar("ControlledResultT")
_EXPECTED_SERIALIZED_CALL_COUNT = 2
_EXPECTED_DEFAULT_TILE_OVERLAP = 128


def _json_string(value: JsonValue | None, *, context: str) -> str:
    if not isinstance(value, str):
        msg = f"{context} must be a string"
        raise TypeError(msg)
    return value


def _json_integer(value: JsonValue | None, *, context: str) -> int:
    if type(value) is not int:
        msg = f"{context} must be an integer"
        raise AssertionError(msg)
    return value


def _json_array(value: JsonValue | None, *, context: str) -> list[JsonValue]:
    if not isinstance(value, list):
        msg = f"{context} must be an array"
        raise TypeError(msg)
    return value


def test_search_page_size_is_capped_at_fifty() -> None:
    invalid: JsonObject = {"query": "ივერია", "page_size": 51}
    with pytest.raises(ValidationError):
        _ = SearchDocumentsInput.model_validate(invalid)


class FakeRepository:
    """Deterministic repository collaborator for tool tests."""

    def __init__(self) -> None:
        """Create one public fixture bitstream."""
        super().__init__()
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
        assert query == "ივერია"
        return SearchPage(
            items=(
                SearchItem(
                    handle="1234/560449",
                    canonical_url="https://dspace.nplg.gov.ge/handle/1234/560449",
                    title="ივერია",
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
            title="ბორჯომი N34",
            languages=("ka",),
            metadata_source="oai_dim",
        )

    async def list_files(self, handle: str) -> tuple[Bitstream, ...]:
        assert handle == "1234/560449"
        return (self.public_file,)


class FakeDownloader:
    """Deterministic content-addressed downloader for tool tests."""

    def __init__(self, store: ContentAddressedStore) -> None:
        """Bind the test store and initialize the call ledger."""
        super().__init__()
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
    """Deterministic PDF collaborator for tool tests."""

    def __init__(self, store: ContentAddressedStore) -> None:
        """Bind the test store and publish one stable rendered page."""
        super().__init__()
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
        return PdfInspection(
            source_sha256="a" * 64, page_count=1, renderer_version="test", pages=()
        )

    def render_pages(
        self, pdf_path: Path, *, pages: tuple[int, ...], mode: str
    ) -> RenderManifest:
        assert pdf_path.name == "source.pdf"
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

    def render_tiles(
        self,
        render_id: str,
        *,
        page_number: int,
        tile_width: int | None = None,
        tile_height: int | None = None,
        overlap: int | None = None,
    ) -> TileManifest:
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
        del render_id
        return self.render_pages(Path("source.pdf"), pages=(1,), mode="native")

    def delete_render(self, render_id: str) -> bool:
        self.deleted.append(render_id)
        return True


class MalformedPdfProcessor(FakePdfProcessor):
    """Return one malformed collaborator result selected by the test."""

    def __init__(
        self,
        store: ContentAddressedStore,
        fault: Literal["pages", "relative_path", "page_number", "tiles"],
    ) -> None:
        """Bind the fake store and selected malformed output shape."""
        super().__init__(store)
        self.fault = fault

    @override
    def render_pages(
        self, pdf_path: Path, *, pages: tuple[int, ...], mode: str
    ) -> RenderManifest:
        manifest = super().render_pages(pdf_path, pages=pages, mode=mode)
        if self.fault == "pages":
            return replace(
                manifest,
                pages=cast("tuple[RenderedPage, ...]", "not-an-array"),
            )
        page = manifest.pages[0]
        if self.fault == "relative_path":
            page = replace(page, relative_path=cast("str", 7))
        elif self.fault == "page_number":
            malformed_page_number: object = True
            page = replace(page, page_number=cast("int", malformed_page_number))
        return replace(manifest, pages=(page,))

    @override
    def render_tiles(
        self,
        render_id: str,
        *,
        page_number: int,
        tile_width: int | None = None,
        tile_height: int | None = None,
        overlap: int | None = None,
    ) -> TileManifest:
        manifest = super().render_tiles(
            render_id,
            page_number=page_number,
            tile_width=tile_width,
            tile_height=tile_height,
            overlap=overlap,
        )
        if self.fault == "tiles":
            return replace(
                manifest,
                tiles=cast("tuple[RenderedTile, ...]", "not-an-array"),
            )
        return manifest


class CancelOncePdfProcessor(FakePdfProcessor):
    """Cancel one worker result before returning normal PDF inspection output."""

    def __init__(self, store: ContentAddressedStore) -> None:
        """Bind the fake store and arm the one-shot cancellation."""
        super().__init__(store)
        self.cancel_next = True

    @override
    def inspect(self, pdf_path: Path) -> PdfInspection:
        if self.cancel_next:
            self.cancel_next = False
            raise asyncio.CancelledError
        return super().inspect(pdf_path)


class PopulatedTilePdfProcessor(FakePdfProcessor):
    """Return one persisted tile to exercise the normal tool result shape."""

    @override
    def render_tiles(
        self,
        render_id: str,
        *,
        page_number: int,
        tile_width: int | None = None,
        tile_height: int | None = None,
        overlap: int | None = None,
    ) -> TileManifest:
        manifest = super().render_tiles(
            render_id,
            page_number=page_number,
            tile_width=tile_width,
            tile_height=tile_height,
            overlap=overlap,
        )
        tile = self.store.put_bytes(
            b"jpeg-tile",
            namespace="renders",
            filename="tile-x0000-y0000.jpg",
            media_type="image/jpeg",
        )
        return replace(
            manifest,
            tiles=(
                RenderedTile(
                    tile_id="x0000-y0000-w2048-h2048",
                    page_number=page_number,
                    x=0,
                    y=0,
                    width=2048,
                    height=2048,
                    full_page_width=2048,
                    full_page_height=2048,
                    overlap=manifest.overlap,
                    relative_path=tile.relative_path,
                    sha256=tile.sha256,
                    media_type="image/jpeg",
                ),
            ),
        )


class ObservedPdfJobLimiter:
    """Observe real semaphore admission without changing its behavior."""

    _MAX_OBSERVED_ATTEMPTS = 3

    def __init__(self, delegate: asyncio.Semaphore) -> None:
        """Wrap the exact production semaphore instance."""
        super().__init__()
        self._delegate = delegate
        self._attempted = tuple(
            asyncio.Event() for _ in range(self._MAX_OBSERVED_ATTEMPTS)
        )
        self._found_locked: list[bool] = []

    async def acquire(self) -> None:
        attempt_index = len(self._found_locked)
        self._found_locked.append(self._delegate.locked())
        if attempt_index < len(self._attempted):
            self._attempted[attempt_index].set()
        _ = await self._delegate.acquire()

    def release(self) -> None:
        self._delegate.release()

    async def wait_for_attempt(self, attempt_number: int) -> None:
        if not 1 <= attempt_number <= len(self._attempted):
            msg = "attempt_number is outside the observable test range"
            raise ValueError(msg)
        observed = await asyncio.wait_for(
            self._attempted[attempt_number - 1].wait(),
            timeout=2,
        )
        assert observed is True

    def found_locked_on_attempt(self, attempt_number: int) -> bool:
        return self._found_locked[attempt_number - 1]


class ForgedExecutor:
    """Non-string value that claims equality with the valid executor."""

    __hash__ = object.__hash__

    @override
    def __eq__(self, other: object) -> bool:
        return other == "serialized"


class ControlledPdfProcessor(FakePdfProcessor):
    """Block the first native call and expose deterministic worker events."""

    _FIRST_ENTRY = 1
    _SECOND_ENTRY = 2

    def __init__(
        self,
        store: ContentAddressedStore,
        *,
        fail_first: bool = False,
    ) -> None:
        """Initialize a processor with an event-controlled first operation."""
        super().__init__(store)
        self.first_entered = threading.Event()
        self.first_completed = threading.Event()
        self.second_entered = threading.Event()
        self._release_first = threading.Event()
        self._lock = threading.Lock()
        self._entry_count = 0
        self._active_calls = 0
        self._fail_first = fail_first
        self.maximum_simultaneous_calls = 0
        self.entered_operations: list[str] = []

    def _run_controlled(
        self,
        operation: str,
        function: Callable[[], ControlledResultT],
    ) -> ControlledResultT:
        with self._lock:
            self._entry_count += 1
            entry_number = self._entry_count
            self._active_calls += 1
            self.maximum_simultaneous_calls = max(
                self.maximum_simultaneous_calls,
                self._active_calls,
            )
            self.entered_operations.append(operation)
            if entry_number == self._FIRST_ENTRY:
                self.first_entered.set()
            elif entry_number == self._SECOND_ENTRY:
                self.second_entered.set()
        try:
            if entry_number == self._FIRST_ENTRY and not self._release_first.wait(
                timeout=5
            ):
                msg = "test-controlled PDF worker did not receive release"
                raise TimeoutError(msg)
            if entry_number == self._FIRST_ENTRY and self._fail_first:
                msg = "test-controlled first PDF operation failed"
                raise RuntimeError(msg)
            return function()
        finally:
            with self._lock:
                self._active_calls -= 1
            if entry_number == self._FIRST_ENTRY:
                self.first_completed.set()

    @override
    def inspect(self, pdf_path: Path) -> PdfInspection:
        parent_inspect = super().inspect
        return self._run_controlled("inspect", lambda: parent_inspect(pdf_path))

    @override
    def get_manifest(self, render_id: str) -> RenderManifest:
        parent_get_manifest = super().get_manifest
        return self._run_controlled(
            "get_manifest",
            lambda: parent_get_manifest(render_id),
        )

    def release_first_call(self) -> None:
        self._release_first.set()


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


def test_tool_service_dependencies_are_frozen_and_slotted(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    dependencies = ToolServiceDependencies(
        repository=FakeRepository(),
        downloader=FakeDownloader(store),
        pdf=FakePdfProcessor(store),
        store=store,
    )

    assert not hasattr(dependencies, "__dict__")
    repository_field = "repository"
    with pytest.raises(FrozenInstanceError):
        setattr(dependencies, repository_field, FakeRepository())


def observed_pdf_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_first: bool = False,
) -> tuple[
    ToolService,
    ControlledPdfProcessor,
    ObservedPdfJobLimiter,
    str,
]:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    processor = ControlledPdfProcessor(store, fail_first=fail_first)
    real_semaphore = asyncio.Semaphore
    configured_limiters: list[ObservedPdfJobLimiter] = []

    def observed_semaphore(capacity: int = 1) -> ObservedPdfJobLimiter:
        if configured_limiters:
            msg = "ToolService constructed more than one PDF limiter"
            raise AssertionError(msg)
        observed_limiter = ObservedPdfJobLimiter(real_semaphore(capacity))
        configured_limiters.append(observed_limiter)
        return observed_limiter

    with monkeypatch.context() as constructor_patch:
        constructor_patch.setattr(asyncio, "Semaphore", observed_semaphore)
        tool_service = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=processor,
                store=store,
            ),
            config=config(tmp_path),
        )
    assert len(configured_limiters) == 1
    return tool_service, processor, configured_limiters[0], artifact.object_id


async def await_successful_pdf_tasks(
    tasks: list[asyncio.Task[JsonObject]],
) -> list[JsonObject]:
    results: list[JsonObject] = []
    for task in tasks:
        result = await asyncio.wait_for(task, timeout=2)
        results.append(result)
    return results


def service(tmp_path: Path) -> tuple[ToolService, FakeDownloader]:
    store = ContentAddressedStore(tmp_path)
    downloader = FakeDownloader(store)
    return (
        ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=downloader,
                pdf=FakePdfProcessor(store),
                store=store,
            ),
            config=config(tmp_path),
        ),
        downloader,
    )


def test_tool_service_rejects_direct_parallel_pdf_config(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    unsafe_config = replace(config(tmp_path), max_concurrent_pdf_jobs=2)

    with pytest.raises(ValueError, match="MAX_CONCURRENT_PDF_JOBS must equal 1"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=FakePdfProcessor(store),
                store=store,
            ),
            config=unsafe_config,
        )


@pytest.mark.parametrize("unsafe_capacity", [True, 1.0])
def test_tool_service_requires_exact_integer_pdf_capacity(
    tmp_path: Path,
    unsafe_capacity: object,
) -> None:
    store = ContentAddressedStore(tmp_path)
    unsafe_config = replace(
        config(tmp_path),
        max_concurrent_pdf_jobs=cast("int", unsafe_capacity),
    )

    with pytest.raises(ValueError, match="MAX_CONCURRENT_PDF_JOBS must equal 1"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=FakePdfProcessor(store),
                store=store,
            ),
            config=unsafe_config,
        )


def test_tool_service_rejects_direct_nonserialized_pdf_config(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    unsafe_config = replace(
        config(tmp_path),
        pdf_executor=cast("PdfExecutor", "threaded"),
    )

    with pytest.raises(ValueError, match="PDF_EXECUTOR must be serialized"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=FakePdfProcessor(store),
                store=store,
            ),
            config=unsafe_config,
        )


def test_tool_service_rejects_executor_with_forged_equality(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    unsafe_config = replace(
        config(tmp_path),
        pdf_executor=cast("PdfExecutor", ForgedExecutor()),
    )

    with pytest.raises(ValueError, match="PDF_EXECUTOR must be serialized"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=FakePdfProcessor(store),
                store=store,
            ),
            config=unsafe_config,
        )


def test_tool_catalog_is_deterministic_and_strict(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    first = tools.list_tools()
    second = tools.list_tools()

    assert first == second
    names = [_json_string(tool.get("name"), context="tool name") for tool in first]
    assert names == sorted(names)
    assert set(names) >= {
        "search_documents",
        "get_document_metadata",
        "list_document_files",
        "download_document_file",
        "inspect_pdf",
        "render_pdf_pages",
        "render_pdf_page_tiles",
        "get_render_manifest",
    }
    assert "delete_render" not in names
    cache_writing_tools = {
        "download_document_file",
        "render_pdf_pages",
        "render_pdf_page_tiles",
    }
    for tool in first:
        name = _json_string(tool.get("name"), context="tool name")
        schema = require_json_object(tool.get("inputSchema"), context="input schema")
        annotations = require_json_object(
            tool.get("annotations"),
            context="tool annotations",
        )
        assert schema.get("type") == "object"
        assert schema.get("additionalProperties") is False
        assert annotations.get("readOnlyHint") is (name not in cache_writing_tools)
        assert annotations.get("destructiveHint") is False
        assert annotations.get("idempotentHint") is (name != "download_document_file")
        _ = json.dumps(tool, ensure_ascii=False)


@pytest.mark.asyncio
async def test_search_preserves_georgian_unicode_and_structured_fields(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    result = await tools.call("search_documents", {"query": "ივერია", "page_size": 10})

    items = _json_array(result.get("items"), context="search items")
    first_item = require_json_object(items[0], context="search item")
    assert _json_string(first_item.get("title"), context="search title") == "ივერია"
    assert _json_integer(result.get("total"), context="search total") == 1
    assert result.get("next_cursor") is None


@pytest.mark.asyncio
async def test_download_uses_only_discovered_bitstream_and_returns_bound_signed_url(
    tmp_path: Path,
) -> None:
    tools, downloader = service(tmp_path)
    result = await tools.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )

    assert downloader.calls == ["bs_public"]
    artifact_id = _json_string(result.get("artifact_id"), context="artifact ID")
    asset_url = _json_string(result.get("asset_url"), context="asset URL")
    relative_path = _json_string(
        result.get("relative_path"),
        context="relative path",
    )
    assert artifact_id.startswith("doc_")
    assert asset_url.startswith("https://mcp.example.test/assets/")
    token = asset_url.rsplit("/", 1)[-1]
    grant = verify_asset_token(
        config(tmp_path).asset_signing_secret, token, now=datetime.now(UTC)
    )
    assert grant.path == relative_path
    assert grant.media_type == "application/pdf"


@pytest.mark.asyncio
async def test_unknown_bitstream_is_rejected_before_any_download(
    tmp_path: Path,
) -> None:
    tools, downloader = service(tmp_path)

    with pytest.raises(AppError) as caught:
        _ = await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "attacker-controlled"},
        )

    assert caught.value.code is ErrorCode.NOT_FOUND
    assert downloader.calls == []


@pytest.mark.asyncio
async def test_artifact_chain_inspect_render_tile_manifest_and_delete(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    downloaded = await tools.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )
    artifact_id = _json_string(
        downloaded.get("artifact_id"),
        context="artifact ID",
    )

    inspected = await tools.call("inspect_pdf", {"artifact_id": artifact_id})
    assert inspected["page_count"] == 1

    rendered = await tools.call(
        "render_pdf_pages", {"artifact_id": artifact_id, "pages": [1]}
    )
    render_id = _json_string(rendered.get("render_id"), context="render ID")
    pages = _json_array(rendered.get("pages"), context="rendered pages")
    page = require_json_object(pages[0], context="rendered page")
    page_asset_url = _json_string(page.get("asset_url"), context="page asset URL")
    assert render_id.startswith("rnd_")
    assert page_asset_url.startswith(
        "https://mcp.example.test/assets/",
    )

    tiled = await tools.call(
        "render_pdf_page_tiles",
        {"render_id": render_id, "page_number": 1},
    )
    assert _json_integer(tiled.get("page_number"), context="tile page number") == 1

    manifest = await tools.call(
        "get_render_manifest",
        {"render_id": render_id},
    )
    assert _json_string(manifest.get("render_id"), context="manifest render ID") == (
        render_id
    )


@pytest.mark.asyncio
async def test_render_deletion_is_not_exposed_as_an_mcp_tool(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(AppError) as caught:
        _ = await tools.call("delete_render", {"render_id": "rnd_" + "0" * 32})

    assert caught.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_tool_argument_validation_rejects_unknown_fields_and_arbitrary_urls(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(AppError) as extra:
        _ = await tools.call(
            "search_documents", {"query": "x", "url": "https://evil.example"}
        )
    assert extra.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(AppError) as blank:
        _ = await tools.call("search_documents", {"query": "   "})
    assert blank.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arguments", [{"tile_width": 4097}, {"tile_height": 4097}, {"overlap": 513}]
)
async def test_tile_tool_rejects_geometry_above_compiled_ceilings(
    tmp_path: Path, arguments: dict[str, int]
) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(AppError) as oversized:
        _ = await tools.call(
            "render_pdf_page_tiles",
            {"render_id": "rnd_" + "1" * 32, "page_number": 1, **arguments},
        )

    assert oversized.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_serialized_pdf_backend_never_enters_pdfium_concurrently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, processor, limiter, artifact_id = observed_pdf_service(
        tmp_path,
        monkeypatch,
    )
    first = asyncio.create_task(
        tools.call("inspect_pdf", {"artifact_id": artifact_id}),
    )
    pending_tasks = [first]
    results: list[JsonObject] = []
    try:
        assert await asyncio.to_thread(processor.first_entered.wait, 2)
        second = asyncio.create_task(
            tools.call("inspect_pdf", {"artifact_id": artifact_id}),
        )
        pending_tasks.append(second)
        await limiter.wait_for_attempt(2)
        assert limiter.found_locked_on_attempt(2) is True
        assert not second.done()
        assert not processor.second_entered.is_set()
        assert processor.maximum_simultaneous_calls == 1
    finally:
        processor.release_first_call()
        results = await await_successful_pdf_tasks(pending_tasks)
    assert len(results) == _EXPECTED_SERIALIZED_CALL_COUNT
    assert processor.maximum_simultaneous_calls == 1


@pytest.mark.asyncio
async def test_cancelled_pdf_request_keeps_permit_until_native_worker_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, processor, limiter, artifact_id = observed_pdf_service(
        tmp_path,
        monkeypatch,
    )
    first = asyncio.create_task(
        tools.call("inspect_pdf", {"artifact_id": artifact_id}),
    )
    pending_tasks: list[asyncio.Task[JsonObject]] = []
    first_cancelled = False
    results: list[JsonObject] = []
    try:
        assert await asyncio.to_thread(processor.first_entered.wait, 2)
        _ = first.cancel()
        with pytest.raises(asyncio.CancelledError):
            _ = await first
        first_cancelled = True
        second = asyncio.create_task(
            tools.call("inspect_pdf", {"artifact_id": artifact_id}),
        )
        pending_tasks.append(second)
        await limiter.wait_for_attempt(2)
        assert limiter.found_locked_on_attempt(2) is True
        assert not processor.first_completed.is_set()
        assert not processor.second_entered.is_set()
        assert not second.done()
    finally:
        processor.release_first_call()
        assert await asyncio.to_thread(processor.first_completed.wait, 2)
        if not first_cancelled:
            pending_tasks.insert(0, first)
        results = await await_successful_pdf_tasks(pending_tasks)
    assert first.cancelled()
    assert len(results) == 1
    assert processor.maximum_simultaneous_calls == 1


@pytest.mark.asyncio
async def test_cancelled_queued_pdf_waiter_does_not_release_or_leak_permit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, processor, limiter, artifact_id = observed_pdf_service(
        tmp_path,
        monkeypatch,
    )
    first = asyncio.create_task(
        tools.call("inspect_pdf", {"artifact_id": artifact_id}),
    )
    pending_tasks = [first]
    results: list[JsonObject] = []
    try:
        assert await asyncio.to_thread(processor.first_entered.wait, 2)
        second = asyncio.create_task(
            tools.call("inspect_pdf", {"artifact_id": artifact_id}),
        )
        await limiter.wait_for_attempt(2)
        assert limiter.found_locked_on_attempt(2) is True
        _ = second.cancel()
        with pytest.raises(asyncio.CancelledError):
            _ = await second
        assert second.cancelled()

        third = asyncio.create_task(
            tools.call("inspect_pdf", {"artifact_id": artifact_id}),
        )
        pending_tasks.append(third)
        await limiter.wait_for_attempt(3)
        assert limiter.found_locked_on_attempt(3) is True
        assert not processor.first_completed.is_set()
        assert not processor.second_entered.is_set()
        assert not third.done()
    finally:
        processor.release_first_call()
        results = await await_successful_pdf_tasks(pending_tasks)
    assert len(results) == _EXPECTED_SERIALIZED_CALL_COUNT
    assert processor.maximum_simultaneous_calls == 1


@pytest.mark.asyncio
async def test_pdf_worker_exception_releases_the_next_queued_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, processor, limiter, artifact_id = observed_pdf_service(
        tmp_path,
        monkeypatch,
        fail_first=True,
    )
    first = asyncio.create_task(
        tools.call("inspect_pdf", {"artifact_id": artifact_id}),
    )
    successors: list[asyncio.Task[JsonObject]] = []
    try:
        assert await asyncio.to_thread(processor.first_entered.wait, 2)
        second = asyncio.create_task(
            tools.call("inspect_pdf", {"artifact_id": artifact_id}),
        )
        successors.append(second)
        await limiter.wait_for_attempt(2)
        assert limiter.found_locked_on_attempt(2) is True
        assert not processor.second_entered.is_set()
    finally:
        processor.release_first_call()
    with pytest.raises(RuntimeError, match="first PDF operation failed"):
        _ = await await_successful_pdf_tasks([first])
    assert await asyncio.to_thread(processor.first_completed.wait, 2)
    assert len(successors) == 1
    results = await await_successful_pdf_tasks(successors)
    assert len(results) == 1
    assert processor.entered_operations == ["inspect", "inspect"]
    assert processor.maximum_simultaneous_calls == 1


@pytest.mark.asyncio
async def test_distinct_pdf_operations_share_one_serialized_limiter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, processor, limiter, artifact_id = observed_pdf_service(
        tmp_path,
        monkeypatch,
    )
    first = asyncio.create_task(
        tools.call("inspect_pdf", {"artifact_id": artifact_id}),
    )
    pending_tasks = [first]
    results: list[JsonObject] = []
    try:
        assert await asyncio.to_thread(processor.first_entered.wait, 2)
        second = asyncio.create_task(
            tools.call("get_render_manifest", {"render_id": "rnd_" + "1" * 32}),
        )
        pending_tasks.append(second)
        await limiter.wait_for_attempt(2)
        assert limiter.found_locked_on_attempt(2) is True
        assert not processor.second_entered.is_set()
        assert not second.done()
    finally:
        processor.release_first_call()
        results = await await_successful_pdf_tasks(pending_tasks)
    assert len(results) == _EXPECTED_SERIALIZED_CALL_COUNT
    assert processor.entered_operations == ["inspect", "get_manifest"]
    assert processor.maximum_simultaneous_calls == 1


@pytest.mark.asyncio
async def test_tile_overlap_must_fit_each_explicit_dimension(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32

    explicit_none = await tools.call(
        "render_pdf_page_tiles",
        {"render_id": render_id, "page_number": 1, "overlap": None},
    )
    assert explicit_none.get("overlap") == _EXPECTED_DEFAULT_TILE_OVERLAP

    valid = await tools.call(
        "render_pdf_page_tiles",
        {
            "render_id": render_id,
            "page_number": 1,
            "tile_width": 512,
            "tile_height": 512,
            "overlap": 128,
        },
    )
    assert valid.get("overlap") == _EXPECTED_DEFAULT_TILE_OVERLAP

    invalid_geometry: tuple[JsonObject, ...] = (
        {
            "render_id": render_id,
            "page_number": 1,
            "tile_width": 256,
            "tile_height": 512,
            "overlap": 256,
        },
        {
            "render_id": render_id,
            "page_number": 1,
            "tile_width": 512,
            "tile_height": 256,
            "overlap": 256,
        },
    )
    for arguments in invalid_geometry:
        with pytest.raises(AppError, match="declared schema"):
            _ = await tools.call("render_pdf_page_tiles", arguments)


@pytest.mark.asyncio
async def test_tool_resources_cover_about_document_render_and_not_found(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    downloaded = await tools.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )
    artifact_id = _json_string(downloaded.get("artifact_id"), context="artifact ID")
    render_id = "rnd_" + "1" * 32

    resources = tools.list_resources()
    assert [item.get("uri") for item in resources] == ["nplg://about"]

    about = await tools.read_resource("nplg://about")
    about_payload = require_json_object(
        load_json_value(about["text"]), context="about resource"
    )
    assert about_payload.get("read_only") is True

    document = await tools.read_resource(f"nplg://artifact/{artifact_id}")
    document_payload = require_json_object(
        load_json_value(document["text"]), context="document resource"
    )
    assert document_payload.get("artifact_id") == artifact_id

    render = await tools.read_resource(f"nplg://render/{render_id}/manifest")
    render_payload = require_json_object(
        load_json_value(render["text"]), context="render resource"
    )
    assert render_payload.get("render_id") == render_id

    with pytest.raises(AppError, match="not found"):
        _ = await tools.read_resource("nplg://unknown")


@pytest.mark.asyncio
async def test_metadata_and_file_tools_expose_repository_results(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)

    metadata = await tools.call(
        "get_document_metadata",
        {"handle": "1234/560449"},
    )
    files = await tools.call("list_document_files", {"handle": "1234/560449"})

    assert metadata.get("title") == "ბორჯომი N34"
    listed = _json_array(files.get("files"), context="listed files")
    assert (
        require_json_object(listed[0], context="listed file").get("bitstream_id")
        == "bs_public"
    )


@pytest.mark.asyncio
async def test_signed_asset_generation_requires_an_aware_utc_clock(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)

    def naive_now() -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC).replace(tzinfo=None)

    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=FakePdfProcessor(store),
            store=store,
        ),
        config=config(tmp_path),
        utc_now=naive_now,
    )

    with pytest.raises(ValueError, match="timezone-aware UTC"):
        _ = await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("pages", "pages must be an array"),
        ("relative_path", "relative_path must be a string"),
        ("page_number", "page_number must be an integer"),
        ("tiles", "tiles must be an array"),
    ],
)
@pytest.mark.asyncio
async def test_tool_service_rejects_malformed_pdf_collaborator_results(
    tmp_path: Path,
    fault: Literal["pages", "relative_path", "page_number", "tiles"],
    message: str,
) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=MalformedPdfProcessor(store, fault),
            store=store,
        ),
        config=config(tmp_path),
    )

    tool_name = "render_pdf_page_tiles" if fault == "tiles" else "render_pdf_pages"
    arguments: JsonObject = (
        {"render_id": "rnd_" + "1" * 32, "page_number": 1}
        if fault == "tiles"
        else {"artifact_id": artifact.object_id, "pages": [1]}
    )
    with pytest.raises(TypeError, match=message):
        _ = await tools.call(tool_name, arguments)


@pytest.mark.asyncio
async def test_pdf_job_releases_permit_when_task_creation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=FakePdfProcessor(store),
            store=store,
        ),
        config=config(tmp_path),
    )

    def fail_create_task(
        coroutine: Coroutine[object, object, object],
        *,
        name: str | None = None,
        context: object | None = None,
    ) -> asyncio.Task[object]:
        del name, context
        coroutine.close()
        message = "task creation failed"
        raise RuntimeError(message)

    with monkeypatch.context() as task_patch:
        task_patch.setattr(asyncio, "create_task", fail_create_task)
        with pytest.raises(RuntimeError, match="task creation failed"):
            _ = await tools.call(
                "inspect_pdf",
                {"artifact_id": artifact.object_id},
            )

    recovered = await asyncio.wait_for(
        tools.call("inspect_pdf", {"artifact_id": artifact.object_id}),
        timeout=2,
    )
    assert recovered.get("artifact_id") == artifact.object_id


@pytest.mark.asyncio
async def test_pdf_job_releases_permit_after_worker_cancellation(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=CancelOncePdfProcessor(store),
            store=store,
        ),
        config=config(tmp_path),
    )

    with pytest.raises(asyncio.CancelledError):
        _ = await tools.call("inspect_pdf", {"artifact_id": artifact.object_id})
    await asyncio.sleep(0)

    recovered = await asyncio.wait_for(
        tools.call("inspect_pdf", {"artifact_id": artifact.object_id}),
        timeout=2,
    )
    assert recovered.get("artifact_id") == artifact.object_id


@pytest.mark.asyncio
async def test_render_tiles_exposes_signed_tile_and_resource_coordinates(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=PopulatedTilePdfProcessor(store),
            store=store,
        ),
        config=config(tmp_path),
    )

    result = await tools.call(
        "render_pdf_page_tiles",
        {"render_id": "rnd_" + "1" * 32, "page_number": 1},
    )

    tiles = _json_array(result.get("tiles"), context="tiles")
    tile = require_json_object(tiles[0], context="tiles[0]")
    assert tile["resource_uri"] == (
        "nplg://render/rnd_11111111111111111111111111111111/page/1/"
        "tile/x0000-y0000-w2048-h2048"
    )
    asset_url = _json_string(tile.get("asset_url"), context="asset_url")
    assert asset_url.startswith("https://mcp.example.test/assets/")
