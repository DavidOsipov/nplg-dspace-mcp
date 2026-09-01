# Copyright (c) 2026 David Osipov
"""Unit tests for the typed tool service."""
# ruff: noqa: SLF001

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import threading
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypeVar, cast, override

import pytest
from pydantic import BaseModel, ValidationError

import nplg_mcp.tools as tools_module
from nplg_mcp.config import (
    HARD_MAX_INLINE_RESOURCE_BYTES,
    HARD_MAX_RENDER_PAGES,
    HARD_MAX_TILES_PER_PAGE,
    AppConfig,
)
from nplg_mcp.contracts import RenderTilesInput, SearchDocumentsInput
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
from nplg_mcp.pdf_executor import (
    PdfWorkerError,
    PdfWorkerUnavailableError,
    PublicationReservingPdfExecutor,
)
from nplg_mcp.pdf_worker_slot import PdfWorkerSlotPolicy
from nplg_mcp.storage import ContentAddressedStore, StoreLifecycleConfiguration
from nplg_mcp.storage_lifecycle import (
    ClockHighWater,
    PublicationBlocker,
    PublicationReservationError,
    RetentionClockSample,
    RetentionPolicy,
    StorageCapacity,
)
from nplg_mcp.tokens import verify_asset_token
from nplg_mcp.tools import (
    ToolService,
    ToolServiceDependencies,
)
from tests.helpers.inline_pdf_executor import InlinePdfExecutor
from tests.helpers.lease_store import lease_barrier_store, retention_sample

if TYPE_CHECKING:
    from collections.abc import Callable

    from nplg_mcp.config import PdfExecutor as PdfExecutorMode
    from nplg_mcp.contracts import MonotonicDeadline, StrictOutput
    from nplg_mcp.json_types import JsonObject, JsonValue
    from nplg_mcp.pdf_ipc import PdfCommand, PdfResult, PdfSuccess
ControlledResultT = TypeVar("ControlledResultT")
_GIB = 1024 * 1024 * 1024
_RENDER_RESOURCE_INDEX_BYTES = 4096
_EXPECTED_SERIALIZED_CALL_COUNT = 2
_EXPECTED_DEFAULT_TILE_OVERLAP = 128
_EXPLICIT_TILE_DIMENSION_BOUNDARY = 256
_METADATA_TOOL_NAMES = {
    "get_document_metadata",
    "list_document_files",
    "search_documents",
}


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


def _output_json(value: StrictOutput) -> JsonObject:
    return cast(
        "JsonObject",
        value.model_dump(mode="json", by_alias=True),
    )


def test_search_page_size_is_capped_at_fifty() -> None:
    invalid: JsonObject = {"query": "ივერია", "page_size": 51}
    with pytest.raises(ValidationError):
        _ = SearchDocumentsInput.model_validate(invalid)


def test_frozen_protocol_schema_leaves_non_search_tools_unchanged() -> None:
    schema: JsonObject = {"type": "object"}

    projected = tools_module._frozen_protocol_input_schema(  # pyright: ignore[reportPrivateUsage]
        "get_document_metadata",
        schema,
    )

    assert projected is schema


@pytest.mark.parametrize(
    ("schema", "expected"),
    cast(
        "list[tuple[JsonObject, str]]",
        [
            ({}, "properties"),
            ({"properties": {}}, "query schema"),
            ({"properties": {"query": {}}}, "query schema lacks"),
            (
                {"properties": {"query": {"pattern": "^x$"}}},
                "cursor schema",
            ),
            (
                {
                    "properties": {
                        "query": {"pattern": "^x$"},
                        "cursor": {},
                    }
                },
                "alternatives",
            ),
            (
                {
                    "properties": {
                        "query": {"pattern": "^x$"},
                        "cursor": {"anyOf": []},
                    }
                },
                "alternatives",
            ),
            (
                {
                    "properties": {
                        "query": {"pattern": "^x$"},
                        "cursor": {"anyOf": [None]},
                    }
                },
                "alternatives",
            ),
            (
                {
                    "properties": {
                        "query": {"pattern": "^x$"},
                        "cursor": {"anyOf": [{}]},
                    }
                },
                "minimum length",
            ),
            (
                {
                    "properties": {
                        "query": {"pattern": "^x$"},
                        "cursor": {"anyOf": [{"minLength": 0}]},
                    }
                },
                "cursor schema lacks the strict text pattern",
            ),
        ],
    ),
)
def test_frozen_search_schema_projection_fails_closed_on_shape_drift(
    schema: JsonObject,
    expected: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=expected):
        _ = tools_module._frozen_protocol_input_schema(  # pyright: ignore[reportPrivateUsage]
            "search_documents",
            copy.deepcopy(schema),
        )


def test_frozen_search_schema_projection_removes_only_new_refinements() -> None:
    schema: JsonObject = {
        "properties": {
            "query": {"pattern": "^x$", "type": "string"},
            "cursor": {
                "anyOf": [
                    {"minLength": 0, "pattern": "^x*$", "type": "string"},
                    {"type": "null"},
                ]
            },
        }
    }

    projected = tools_module._frozen_protocol_input_schema(  # pyright: ignore[reportPrivateUsage]
        "search_documents",
        schema,
    )

    assert projected == {
        "properties": {
            "query": {"type": "string"},
            "cursor": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        }
    }


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

    def __init__(
        self,
        store: ContentAddressedStore,
        *,
        page_content: bytes = b"jpeg-page",
    ) -> None:
        """Bind the test store and publish one stable rendered page."""
        super().__init__()
        self.store = store
        self.deleted: list[str] = []
        self.render_id = "rnd_" + "1" * 32
        self.page_path, self.page_sha256 = self.store.put_render_bytes(
            f"renders/{self.render_id}/page-0001.jpg",
            page_content,
        )
        self.manifest_path = f"renders/{self.render_id}/manifest.json"
        manifest_document: JsonObject = {"render_id": self.render_id}
        _ = self.store.put_render_bytes(
            self.manifest_path,
            json.dumps(
                manifest_document,
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
        )

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
            render_id=self.render_id,
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
                    sha256=self.page_sha256,
                    media_type="image/jpeg",
                    resize_applied=False,
                    pixel_dimensions_preserved=True,
                    renderer_resampling="none",
                    reencoded=False,
                    lossy_conversion=False,
                ),
            ),
            manifest_relative_path=self.manifest_path,
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
        manifest_path = (
            f"renders/{render_id}/tiles/page-{page_number:04d}/manifest.json"
        )
        manifest_document: JsonObject = {
            "page_number": page_number,
            "render_id": render_id,
        }
        _ = self.store.put_render_bytes(
            manifest_path,
            json.dumps(
                manifest_document,
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
        )
        return TileManifest(
            render_id=render_id,
            page_number=page_number,
            page_sha256=self.page_sha256,
            tile_width=tile_width or 2048,
            tile_height=tile_height or 2048,
            overlap=128 if overlap is None else overlap,
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
                    overlap=128 if overlap is None else overlap,
                    relative_path=self.page_path,
                    sha256=self.page_sha256,
                    media_type="image/jpeg",
                ),
            ),
            manifest_relative_path=manifest_path,
        )

    def get_manifest(self, render_id: str) -> RenderManifest:
        del render_id
        return self.render_pages(Path("source.pdf"), pages=(1,), mode="native")

    def delete_render(self, render_id: str) -> bool:
        self.deleted.append(render_id)
        return True


class SharedPagePdfProcessor(FakePdfProcessor):
    """Publish one identical page from two legitimate render requests."""

    def __init__(self, store: ContentAddressedStore) -> None:
        """Persist stable render artifacts for the one- and two-page requests."""
        super().__init__(store, page_content=b"shared-jpeg-page-one")
        self.render_ids: dict[tuple[int, ...], str] = {
            (1,): "rnd_" + "1" * 32,
            (1, 2): "rnd_" + "2" * 32,
        }
        self.page_paths: dict[tuple[int, ...], tuple[str, str]] = {}
        for pages, render_id in self.render_ids.items():
            if pages == (1,):
                page_path, page_digest = self.page_path, self.page_sha256
            else:
                page_path, page_digest = store.put_render_bytes(
                    f"renders/{render_id}/page-0001.jpg",
                    b"shared-jpeg-page-one",
                )
            self.page_paths[pages] = (page_path, page_digest)
            if pages != (1,):
                manifest_document: JsonObject = {"render_id": render_id}
                _ = store.put_render_bytes(
                    f"renders/{render_id}/manifest.json",
                    json.dumps(manifest_document).encode(),
                )
        self.second_page_path, self.second_page_digest = store.put_render_bytes(
            f"renders/{self.render_ids[(1, 2)]}/page-0002.jpg",
            b"jpeg-page-two",
        )

    @staticmethod
    def _page(
        page_number: int,
        relative_path: str,
        sha256: str,
    ) -> RenderedPage:
        return RenderedPage(
            page_number=page_number,
            width=100,
            height=200,
            rotation=0,
            classification="single_raster_jpeg",
            effective_dpi_x=300.0,
            effective_dpi_y=300.0,
            resolution_source="embedded_scan",
            conversion_path="direct_extract",
            relative_path=relative_path,
            sha256=sha256,
            media_type="image/jpeg",
            resize_applied=False,
            pixel_dimensions_preserved=True,
            renderer_resampling="none",
            reencoded=False,
            lossy_conversion=False,
        )

    @override
    def render_pages(
        self,
        pdf_path: Path,
        *,
        pages: tuple[int, ...],
        mode: str,
    ) -> RenderManifest:
        assert pdf_path.name == "source.pdf"
        assert pages in self.render_ids
        assert mode == "native"
        render_id = self.render_ids[pages]
        first_path, first_digest = self.page_paths[pages]
        rendered_pages = [self._page(1, first_path, first_digest)]
        if pages == (1, 2):
            rendered_pages.append(
                self._page(2, self.second_page_path, self.second_page_digest)
            )
        return RenderManifest(
            render_id=render_id,
            source_sha256="a" * 64,
            renderer_version="test",
            mode="native",
            pages=tuple(rendered_pages),
            manifest_relative_path=f"renders/{render_id}/manifest.json",
        )


class DuplicatePagePdfProcessor(FakePdfProcessor):
    """Publish identical page bytes at two paths in one render."""

    def __init__(self, store: ContentAddressedStore) -> None:
        """Create two same-render paths containing identical JPEG bytes."""
        super().__init__(store, page_content=b"duplicate-blank-page")
        self.second_path, self.second_sha256 = store.put_render_bytes(
            f"renders/{self.render_id}/page-0002.jpg",
            b"duplicate-blank-page",
        )

    @override
    def render_pages(
        self,
        pdf_path: Path,
        *,
        pages: tuple[int, ...],
        mode: str,
    ) -> RenderManifest:
        assert pages == (1, 2)
        first = super().render_pages(pdf_path, pages=(1,), mode=mode)
        second_page = replace(
            first.pages[0],
            page_number=2,
            relative_path=self.second_path,
            sha256=self.second_sha256,
        )
        return replace(first, pages=(first.pages[0], second_page))


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


class FailOncePdfExecutor(InlinePdfExecutor):
    """Fail before one operation, then delegate normally."""

    def __init__(
        self,
        *,
        processor: FakePdfProcessor,
        store: ContentAddressedStore,
    ) -> None:
        """Bind a delegate and arm one deterministic startup failure."""
        super().__init__(processor=processor, store=store)
        self._fail_next = True

    @override
    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        if self._fail_next:
            self._fail_next = False
            message = "executor start failed"
            raise RuntimeError(message)
        return await super().execute(command, deadline=deadline)


class CancellationAwarePdfExecutor(InlinePdfExecutor):
    """Prove cancellation cleanup completes before the executor returns."""

    def __init__(
        self,
        *,
        processor: FakePdfProcessor,
        store: ContentAddressedStore,
    ) -> None:
        """Bind a delegate and one cancellation-cleanup observation."""
        super().__init__(processor=processor, store=store)
        self.started = asyncio.Event()
        self.cleaned_up = asyncio.Event()
        self._cancel_first = True

    @override
    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        if self._cancel_first:
            self._cancel_first = False
            self.started.set()
            try:
                _ = await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cleaned_up.set()
                raise
        return await super().execute(command, deadline=deadline)


class ExpiredDeadlineProbePdfExecutor:
    """Record executor ingress without performing a PDF operation."""

    def __init__(self) -> None:
        """Initialize the zero-side-effect call ledger."""
        super().__init__()
        self.execute_calls = 0

    def ensure_ready(self) -> None:
        """Return successfully because the probe has no circuit."""

    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        del command, deadline
        self.execute_calls += 1
        message = "expired deadline crossed the executor boundary"
        raise PdfWorkerError(message)


class UnreadyPdfExecutor(InlinePdfExecutor):
    """Expose one open worker circuit to the ToolService readiness hook."""

    @override
    def ensure_ready(self) -> None:
        message = "PDF worker is temporarily unavailable"
        raise PdfWorkerUnavailableError(message)


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
        tile_path, tile_sha256 = self.store.put_render_bytes(
            f"renders/{render_id}/tile-x0000-y0000.jpg",
            b"jpeg-tile",
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
                    relative_path=tile_path,
                    sha256=tile_sha256,
                    media_type="image/jpeg",
                ),
            ),
        )


class _OverproducingPagePdfProcessor(SharedPagePdfProcessor):
    """Return the schema maximum rather than the smaller requested selection."""

    @override
    def render_pages(
        self,
        pdf_path: Path,
        *,
        pages: tuple[int, ...],
        mode: str,
    ) -> RenderManifest:
        assert pages == (1,)
        return super().render_pages(pdf_path, pages=(1, 2), mode=mode)


class _MutablePublicationCapacity:
    """Expose one deterministic capacity value to lifecycle admission."""

    def __init__(self, value: StorageCapacity) -> None:
        super().__init__()
        self.value = value

    def __call__(self) -> StorageCapacity:
        return self.value


class _PublicationClock:
    """Issue strictly advancing trusted samples for reservation boundaries."""

    def __init__(self) -> None:
        super().__init__()
        self._seconds = 61.0

    def __call__(self) -> RetentionClockSample:
        seconds = self._seconds
        self._seconds += 1.0
        return RetentionClockSample(
            utc_now=datetime(2026, 8, 25, tzinfo=UTC) + timedelta(seconds=seconds),
            monotonic_now=seconds,
            boot_id="tool-publication-test",
            synchronized=True,
        )


class _IndexReservationObservingStore(ContentAddressedStore):
    """Observe real lifecycle accounting exactly when an index is published."""

    def __init__(
        self,
        root: Path,
        *,
        lifecycle: StoreLifecycleConfiguration,
    ) -> None:
        super().__init__(root, max_bytes=2 * _GIB, lifecycle=lifecycle)
        self.index_reservations: list[tuple[int, int, int]] = []
        self.index_failure: BaseException | None = None

    @override
    def put_render_bytes(self, relative_path: str, data: bytes) -> tuple[str, str]:
        if "/resources/" in relative_path:
            self.index_reservations.append(
                (
                    self.publication_reserved_bytes,
                    self.publication_reserved_objects,
                    self.publication_reserved_inodes,
                )
            )
            failure = self.index_failure
            if failure is not None:
                raise failure
        return super().put_render_bytes(relative_path, data)


class _ObservedInlinePdfExecutor(InlinePdfExecutor):
    """Count real executor dispatches and optionally close later admission."""

    def __init__(
        self,
        *,
        processor: FakePdfProcessor,
        store: _IndexReservationObservingStore,
        lifecycle: StoreLifecycleConfiguration,
        close_admission_during_dispatch: bool = False,
    ) -> None:
        super().__init__(processor=processor, store=store)
        self._publication_store = store
        self._lifecycle = lifecycle
        self._close_admission_during_dispatch = close_admission_during_dispatch
        self.execute_calls = 0

    @override
    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        self.execute_calls += 1
        if self._close_admission_during_dispatch:
            try:
                async with self._publication_store.reserve_publication(
                    self._lifecycle.policy,
                    maximum_new_bytes=self._publication_store.max_bytes,
                    maximum_new_objects=1,
                    maximum_new_inodes=1,
                    clock=self._lifecycle.clock_sampler(),
                ):
                    message = "oversized reservation was unexpectedly admitted"
                    raise AssertionError(message)
            except PublicationReservationError:
                pass
        return await super().execute(command, deadline=deadline)


class _InvalidAssetUrlToolService(ToolService):
    """Force final output validation to fail after artifact registration."""

    @override
    def _signed_asset_url(self, relative_path: str, media_type: str) -> str:
        del relative_path, media_type
        return "not-an-http-url"


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

    async def occupy(self) -> None:
        """Occupy the real test semaphore before a public tool call."""
        _ = await self._delegate.acquire()

    def release_occupied(self) -> None:
        """Release a permit acquired by ``occupy``."""
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

    @property
    def acquire_attempts(self) -> int:
        """Return the number of capacity-boundary crossings."""
        return len(self._found_locked)


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
        cursor_signing_secret=b"c" * 32,
    )


def _publication_slot_policy() -> PdfWorkerSlotPolicy:
    payload: dict[str, object] = {
        "version": 1,
        "root": "/var/lib/nplg/pdf-worker-slot",
        "filesystem_type": "ext4",
        "maximum_total_bytes": _GIB,
        "minimum_available_bytes": _GIB,
        "maximum_total_inodes": 65_536,
        "minimum_available_inodes": 65_536,
        "mount_options": ["nodev", "noexec", "nosuid", "rw"],
        "concurrency": 1,
    }
    return PdfWorkerSlotPolicy.model_validate(
        payload,
        strict=True,
    )


@dataclass(frozen=True, slots=True)
class _PublicationToolOptions:
    """Typed variations for the lifecycle-backed render fixture."""

    available_bytes: int = 3 * _GIB
    index_failure: BaseException | None = None
    close_admission_during_dispatch: bool = False
    service_type: type[ToolService] = ToolService
    processor_type: type[FakePdfProcessor] = FakePdfProcessor


def _publication_tool_service(
    tmp_path: Path,
    *,
    options: _PublicationToolOptions | None = None,
) -> tuple[
    ToolService,
    _IndexReservationObservingStore,
    _ObservedInlinePdfExecutor,
    str,
]:
    selected = options or _PublicationToolOptions()
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=2 * _GIB,
        maximum_objects=1000,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    capacity = _MutablePublicationCapacity(
        StorageCapacity(
            total_bytes=4 * _GIB,
            available_bytes=selected.available_bytes,
            total_inodes=1_000_000,
            available_inodes=900_000,
        )
    )
    clock_high_water = ClockHighWater(
        tmp_path / "publication-clock-high-water.json",
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )
    initial = RetentionClockSample(
        utc_now=datetime(2026, 8, 25, tzinfo=UTC),
        monotonic_now=0.0,
        boot_id="tool-publication-test",
        synchronized=True,
    )
    trusted = RetentionClockSample(
        utc_now=initial.utc_now + timedelta(seconds=60),
        monotonic_now=60.0,
        boot_id=initial.boot_id,
        synchronized=True,
    )
    _ = clock_high_water.observe(initial)
    assert clock_high_water.observe(trusted).trusted is True
    lifecycle = StoreLifecycleConfiguration(
        policy=policy,
        capacity_sampler=capacity,
        clock_high_water=clock_high_water,
        clock_sampler=_PublicationClock(),
    )
    store = _IndexReservationObservingStore(
        tmp_path / "publication-cache",
        lifecycle=lifecycle,
    )
    processor = selected.processor_type(store)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    inner = _ObservedInlinePdfExecutor(
        processor=processor,
        store=store,
        lifecycle=lifecycle,
        close_admission_during_dispatch=selected.close_admission_during_dispatch,
    )
    store.index_failure = selected.index_failure
    wrapped = PublicationReservingPdfExecutor(
        inner=inner,
        store=store,
        lifecycle=lifecycle,
        slot_policy=_publication_slot_policy(),
    )
    tools = selected.service_type(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=wrapped,
            store=store,
        ),
        config=config(tmp_path),
    )
    return tools, store, inner, artifact.object_id


def test_tool_service_dependencies_are_frozen_and_slotted(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    dependencies = ToolServiceDependencies(
        repository=FakeRepository(),
        downloader=FakeDownloader(store),
        pdf=InlinePdfExecutor(processor=FakePdfProcessor(store), store=store),
        store=store,
    )

    assert not hasattr(dependencies, "__dict__")
    repository_field = "repository"
    with pytest.raises(FrozenInstanceError):
        setattr(dependencies, repository_field, FakeRepository())


def test_tool_service_readiness_maps_an_open_pdf_circuit_to_503(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=UnreadyPdfExecutor(
                processor=FakePdfProcessor(store),
                store=store,
            ),
            store=store,
        ),
        config=config(tmp_path),
    )

    with pytest.raises(AppError) as caught:
        tools.ensure_ready()

    assert caught.value.http_status == HTTPStatus.SERVICE_UNAVAILABLE
    assert caught.value.code is ErrorCode.PDF_PROCESSING_FAILED


@pytest.mark.asyncio
async def test_tool_service_readiness_reports_closed_lifecycle_without_mutation(
    tmp_path: Path,
) -> None:
    store, policy, clock = lease_barrier_store(tmp_path)
    artifact = store.put_bytes(
        b"document",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    with pytest.raises(PublicationReservationError):
        async with store.reserve_publication(
            policy,
            maximum_new_bytes=1,
            maximum_new_objects=1,
            maximum_new_inodes=1,
            clock=clock,
        ):
            pass
    assert store.lifecycle_admission_closed
    expired_timestamp = clock.utc_now.timestamp() - 7200.0
    os.utime(
        artifact.absolute_path,
        (expired_timestamp, expired_timestamp),
        follow_symlinks=False,
    )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=ExpiredDeadlineProbePdfExecutor(),
            store=store,
        ),
        config=config(tmp_path),
    )

    with pytest.raises(AppError) as caught:
        tools.ensure_ready()

    assert caught.value.http_status == HTTPStatus.SERVICE_UNAVAILABLE
    assert caught.value.code is ErrorCode.CACHE_FULL
    assert store.lifecycle_admission_closed
    assert artifact.absolute_path.exists()


def test_metadata_profile_readiness_does_not_consult_private_pdf_circuit(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=UnreadyPdfExecutor(
                processor=FakePdfProcessor(store),
                store=store,
            ),
            store=store,
        ),
        config=replace(config(tmp_path), deployment_profile="alpic-metadata"),
    )

    tools.ensure_ready()


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
                pdf=InlinePdfExecutor(processor=processor, store=store),
                store=store,
            ),
            config=config(tmp_path),
        )
    assert len(configured_limiters) == 1
    return tool_service, processor, configured_limiters[0], artifact.object_id


async def await_successful_pdf_tasks(
    tasks: list[asyncio.Task[StrictOutput]],
) -> list[JsonObject]:
    results: list[JsonObject] = []
    for task in tasks:
        result = await asyncio.wait_for(task, timeout=2)
        results.append(_output_json(result))
    return results


def service(tmp_path: Path) -> tuple[TestableToolService, FakeDownloader]:
    store = ContentAddressedStore(tmp_path)
    downloader = FakeDownloader(store)
    return (
        TestableToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=downloader,
                pdf=InlinePdfExecutor(
                    processor=FakePdfProcessor(store),
                    store=store,
                ),
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
                pdf=InlinePdfExecutor(
                    processor=FakePdfProcessor(store),
                    store=store,
                ),
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
                pdf=InlinePdfExecutor(
                    processor=FakePdfProcessor(store),
                    store=store,
                ),
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
        pdf_executor=cast("PdfExecutorMode", "threaded"),
    )

    with pytest.raises(ValueError, match="PDF_EXECUTOR must be serialized"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=InlinePdfExecutor(
                    processor=FakePdfProcessor(store),
                    store=store,
                ),
                store=store,
            ),
            config=unsafe_config,
        )


def test_tool_service_rejects_executor_with_forged_equality(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    unsafe_config = replace(
        config(tmp_path),
        pdf_executor=cast("PdfExecutorMode", ForgedExecutor()),
    )

    with pytest.raises(ValueError, match="PDF_EXECUTOR must be serialized"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=InlinePdfExecutor(
                    processor=FakePdfProcessor(store),
                    store=store,
                ),
                store=store,
            ),
            config=unsafe_config,
        )


def test_tool_service_rejects_a_forged_deployment_profile(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    unsafe_config = replace(
        config(tmp_path),
        deployment_profile=cast(
            "Literal['alpic-metadata', 'distributed-full', 'private-full']",
            "private-full-suffix",
        ),
    )

    with pytest.raises(ValueError, match="DEPLOYMENT_PROFILE"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=InlinePdfExecutor(
                    processor=FakePdfProcessor(store),
                    store=store,
                ),
                store=store,
            ),
            config=unsafe_config,
        )


def test_tool_service_rejects_missing_reviewed_tool_title(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(
        tools_module._TOOL_TITLES,  # pyright: ignore[reportPrivateUsage]
        "search_documents",
    )

    with pytest.raises(ValueError, match="tool title is unavailable"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(repository=FakeRepository()),
            config=replace(config(tmp_path), deployment_profile="alpic-metadata"),
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


def test_tool_annotations_repeat_the_human_readable_title(tmp_path: Path) -> None:
    """Catch descriptors that omit the client-visible annotation title."""
    tools, _ = service(tmp_path)

    for tool in tools.list_tools():
        title = _json_string(tool.get("title"), context="tool title")
        annotations = require_json_object(
            tool.get("annotations"),
            context="tool annotations",
        )
        assert annotations.get("title") == title


def test_search_input_schema_describes_every_parameter(tmp_path: Path) -> None:
    """Catch search parameters that clients cannot explain to users."""
    tools, _ = service(tmp_path)
    search = next(
        tool for tool in tools.list_tools() if tool.get("name") == "search_documents"
    )
    schema = require_json_object(search.get("inputSchema"), context="search schema")
    properties = require_json_object(
        schema.get("properties"),
        context="search properties",
    )

    assert set(properties) == {"query", "cursor", "page_size", "scope_handle"}
    for name in properties:
        parameter = require_json_object(
            properties.get(name),
            context=f"search parameter {name}",
        )
        description = parameter.get("description")
        assert isinstance(description, str)
        assert description.strip()


@pytest.mark.asyncio
async def test_alpic_metadata_profile_closes_discovery_and_direct_dispatch(
    tmp_path: Path,
) -> None:
    full_tools, _ = service(tmp_path)
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=full_tools.repository,
            downloader=full_tools.downloader,
            pdf=full_tools.pdf,
            store=full_tools.store,
        ),
        config=replace(full_tools.config, deployment_profile="alpic-metadata"),
    )

    names = {
        _json_string(tool.get("name"), context="tool name")
        for tool in tools.list_tools()
    }
    assert names == _METADATA_TOOL_NAMES

    for forbidden in (
        "download_document_file",
        "get_render_manifest",
        "inspect_pdf",
        "render_pdf_page_tiles",
        "render_pdf_pages",
    ):
        with pytest.raises(AppError) as caught:
            _ = await tools.call(forbidden, {})
        assert caught.value.code is ErrorCode.INVALID_INPUT

    for forbidden_uri in (
        "nplg://artifact/doc_" + ("1" * 64),
        "nplg://render/rnd_" + ("1" * 32) + "/manifest",
    ):
        with pytest.raises(AppError) as caught:
            _ = await tools.read_resource(forbidden_uri)
        assert caught.value.code is ErrorCode.NOT_FOUND
        assert caught.value.http_status == HTTPStatus.NOT_FOUND


def test_distributed_profile_remains_fail_closed(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(ValueError, match="distributed-full"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(
                repository=tools.repository,
                downloader=tools.downloader,
                pdf=tools.pdf,
                store=tools.store,
            ),
            config=replace(tools.config, deployment_profile="distributed-full"),
        )


@pytest.mark.asyncio
async def test_search_preserves_georgian_unicode_and_structured_fields(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    result = _output_json(
        await tools.call("search_documents", {"query": "ივერია", "page_size": 10})
    )

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
    result = _output_json(
        await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )
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
        config(tmp_path).require_asset_signing_secret(), token, now=datetime.now(UTC)
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
    downloaded = _output_json(
        await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )
    )
    artifact_id = _json_string(
        downloaded.get("artifact_id"),
        context="artifact ID",
    )

    inspected = _output_json(
        await tools.call("inspect_pdf", {"artifact_id": artifact_id})
    )
    assert inspected["page_count"] == 1

    rendered = _output_json(
        await tools.call(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1]},
        )
    )
    render_id = _json_string(rendered.get("render_id"), context="render ID")
    pages = _json_array(rendered.get("pages"), context="rendered pages")
    page = require_json_object(pages[0], context="rendered page")
    page_asset_url = _json_string(page.get("asset_url"), context="page asset URL")
    assert render_id.startswith("rnd_")
    assert page_asset_url.startswith(
        "https://mcp.example.test/assets/",
    )

    tiled = _output_json(
        await tools.call(
            "render_pdf_page_tiles",
            {"render_id": render_id, "page_number": 1},
        )
    )
    assert _json_integer(tiled.get("page_number"), context="tile page number") == 1

    manifest = _output_json(
        await tools.call(
            "get_render_manifest",
            {"render_id": render_id},
        )
    )
    assert _json_string(manifest.get("render_id"), context="manifest render ID") == (
        render_id
    )


@pytest.mark.asyncio
async def test_private_pdf_pipeline_versions_do_not_leak_into_public_outputs(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    downloaded = _output_json(
        await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )
    )
    artifact_id = _json_string(downloaded.get("artifact_id"), context="artifact ID")
    rendered = _output_json(
        await tools.call(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1]},
        )
    )
    render_id = _json_string(rendered.get("render_id"), context="render ID")
    tiled = _output_json(
        await tools.call(
            "render_pdf_page_tiles",
            {"render_id": render_id, "page_number": 1},
        )
    )
    manifest = _output_json(
        await tools.call("get_render_manifest", {"render_id": render_id})
    )
    private_fields = {
        "manifest_schema_version",
        "render_pipeline_version",
        "classification_algorithm_version",
        "tile_pipeline_version",
    }

    for public_output in (rendered, tiled, manifest):
        assert private_fields.isdisjoint(public_output)


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
async def test_cancelled_pdf_request_releases_permit_after_executor_cleanup(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = CancellationAwarePdfExecutor(
        processor=FakePdfProcessor(store),
        store=store,
    )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=executor,
            store=store,
        ),
        config=config(tmp_path),
    )
    first = asyncio.create_task(
        tools.call("inspect_pdf", {"artifact_id": artifact.object_id}),
    )
    async with asyncio.timeout(2):
        _ = await executor.started.wait()
    _ = first.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await first

    assert executor.cleaned_up.is_set()
    recovered = _output_json(
        await asyncio.wait_for(
            tools.call("inspect_pdf", {"artifact_id": artifact.object_id}),
            timeout=2,
        )
    )
    assert first.cancelled()
    assert recovered.get("artifact_id") == artifact.object_id


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
async def test_queued_pdf_call_uses_the_same_absolute_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, processor, limiter, artifact_id = observed_pdf_service(
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(tools_module, "_PDF_JOB_TIMEOUT_SECONDS", 0.01)
    await limiter.occupy()
    try:
        with pytest.raises(AppError) as captured:
            async with asyncio.timeout(0.5):
                _ = await tools.call("inspect_pdf", {"artifact_id": artifact_id})
    finally:
        limiter.release_occupied()

    assert captured.value.code is ErrorCode.PDF_PROCESSING_FAILED
    assert captured.value.http_status == HTTPStatus.SERVICE_UNAVAILABLE
    assert processor.entered_operations == []


@pytest.mark.asyncio
async def test_expired_tool_deadline_has_no_pdf_side_effects(
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
    executor = ExpiredDeadlineProbePdfExecutor()
    real_semaphore = asyncio.Semaphore
    configured_limiters: list[ObservedPdfJobLimiter] = []

    def observed_semaphore(capacity: int = 1) -> ObservedPdfJobLimiter:
        limiter = ObservedPdfJobLimiter(real_semaphore(capacity))
        configured_limiters.append(limiter)
        return limiter

    with monkeypatch.context() as constructor_patch:
        constructor_patch.setattr(asyncio, "Semaphore", observed_semaphore)
        tools = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=executor,
                store=store,
            ),
            config=config(tmp_path),
            monotonic_clock=lambda: 100.0,
        )
    assert len(configured_limiters) == 1
    limiter = configured_limiters[0]
    before = tuple(
        sorted(path.relative_to(store.root) for path in store.root.rglob("*"))
    )
    monkeypatch.setattr(tools_module, "_PDF_JOB_TIMEOUT_SECONDS", 0.0)

    with pytest.raises(AppError) as captured:
        _ = await tools.call("inspect_pdf", {"artifact_id": artifact.object_id})

    after = tuple(
        sorted(path.relative_to(store.root) for path in store.root.rglob("*"))
    )
    assert captured.value.code is ErrorCode.PDF_PROCESSING_FAILED
    assert limiter.acquire_attempts == 0
    assert executor.execute_calls == 0
    assert after == before


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
    successors: list[asyncio.Task[StrictOutput]] = []
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

    explicit_none = _output_json(
        await tools.call(
            "render_pdf_page_tiles",
            {"render_id": render_id, "page_number": 1, "overlap": None},
        )
    )
    assert explicit_none.get("overlap") == _EXPECTED_DEFAULT_TILE_OVERLAP

    valid = _output_json(
        await tools.call(
            "render_pdf_page_tiles",
            {
                "render_id": render_id,
                "page_number": 1,
                "tile_width": 512,
                "tile_height": 512,
                "overlap": 128,
            },
        )
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
async def test_tile_operational_boundary_rejects_unsafe_geometry_before_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    render_id = "rnd_" + "1" * 32
    unsafe_geometry: JsonObject = {
        "render_id": render_id,
        "page_number": 1,
        "tile_width": _EXPLICIT_TILE_DIMENSION_BOUNDARY,
        "tile_height": 512,
        "overlap": _EXPLICIT_TILE_DIMENSION_BOUNDARY,
    }
    accepted = RenderTilesInput.model_validate(unsafe_geometry, strict=True)
    assert accepted.overlap == _EXPLICIT_TILE_DIMENSION_BOUNDARY

    store = ContentAddressedStore(tmp_path)
    executor = ExpiredDeadlineProbePdfExecutor()
    real_semaphore = asyncio.Semaphore
    configured_limiters: list[ObservedPdfJobLimiter] = []

    def observed_semaphore(capacity: int = 1) -> ObservedPdfJobLimiter:
        limiter = ObservedPdfJobLimiter(real_semaphore(capacity))
        configured_limiters.append(limiter)
        return limiter

    with monkeypatch.context() as constructor_patch:
        constructor_patch.setattr(asyncio, "Semaphore", observed_semaphore)
        tools = ToolService(
            dependencies=ToolServiceDependencies(
                repository=FakeRepository(),
                downloader=FakeDownloader(store),
                pdf=executor,
                store=store,
            ),
            config=config(tmp_path),
        )
    assert len(configured_limiters) == 1
    limiter = configured_limiters[0]
    before = tuple(
        sorted(path.relative_to(store.root) for path in store.root.rglob("*"))
    )

    with pytest.raises(AppError, match="declared schema"):
        _ = await tools.call("render_pdf_page_tiles", unsafe_geometry)

    after = tuple(
        sorted(path.relative_to(store.root) for path in store.root.rglob("*"))
    )
    assert limiter.acquire_attempts == 0
    assert executor.execute_calls == 0
    assert after == before


@pytest.mark.asyncio
async def test_identical_page_content_across_render_requests_remains_readable(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    processor = SharedPagePdfProcessor(store)
    dependencies = ToolServiceDependencies(
        repository=FakeRepository(),
        downloader=FakeDownloader(store),
        pdf=InlinePdfExecutor(processor=processor, store=store),
        store=store,
    )
    tools = ToolService(dependencies=dependencies, config=config(tmp_path))
    downloaded = _output_json(
        await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )
    )
    artifact_id = _json_string(downloaded.get("artifact_id"), context="artifact ID")

    first = _output_json(
        await tools.call(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1]},
        )
    )
    second = _output_json(
        await tools.call(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1, 2]},
        )
    )
    first_page = require_json_object(
        _json_array(first.get("pages"), context="first render pages")[0],
        context="first rendered page",
    )
    second_page = require_json_object(
        _json_array(second.get("pages"), context="second render pages")[0],
        context="second rendered page",
    )
    resource_uri = _json_string(
        first_page.get("resource_uri"),
        context="first page resource URI",
    )
    assert second_page.get("resource_uri") == resource_uri

    live = await tools.read_resource(resource_uri)
    restarted = ToolService(dependencies=dependencies, config=config(tmp_path))
    rediscovered = await restarted.read_resource(resource_uri)

    assert live["blob"] == rediscovered["blob"]
    assert live["sha256"] == resource_uri.removeprefix("nplg://artifact/doc_")
    assert live["render_id"] == ""
    assert rediscovered["render_id"] == ""


@pytest.mark.asyncio
async def test_identical_page_content_at_two_paths_in_one_render_survives_restart(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    processor = DuplicatePagePdfProcessor(store)
    dependencies = ToolServiceDependencies(
        repository=FakeRepository(),
        downloader=FakeDownloader(store),
        pdf=InlinePdfExecutor(processor=processor, store=store),
        store=store,
    )
    tools = ToolService(dependencies=dependencies, config=config(tmp_path))
    downloaded = _output_json(
        await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )
    )
    artifact_id = _json_string(downloaded.get("artifact_id"), context="artifact ID")
    rendered = _output_json(
        await tools.call(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1, 2]},
        )
    )
    pages = _json_array(rendered.get("pages"), context="rendered pages")
    first = require_json_object(pages[0], context="first page")
    second = require_json_object(pages[1], context="second page")
    resource_uri = _json_string(first.get("resource_uri"), context="resource URI")
    assert second.get("resource_uri") == resource_uri

    restarted = ToolService(dependencies=dependencies, config=config(tmp_path))
    resource = await restarted.read_resource(resource_uri)

    assert resource["sha256"] == resource_uri.removeprefix("nplg://artifact/doc_")
    assert resource["render_id"] == processor.render_id


@pytest.mark.asyncio
async def test_tool_resources_cover_about_document_render_and_not_found(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    downloaded = _output_json(
        await tools.call(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )
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


def test_document_resource_rejects_oversize_before_reading_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)
    source = tools.store.put_bytes(
        b"bounded",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    with source.absolute_path.open("r+b") as stream:
        _ = stream.truncate(HARD_MAX_INLINE_RESOURCE_BYTES + 1)
    tools.force_missing_document_for_test(source.absolute_path)
    content_read = False

    def reject_content_read(descriptor: int, size: int) -> bytes:
        nonlocal content_read
        del descriptor, size
        content_read = True
        pytest.fail("oversize resource content reached os.read")

    monkeypatch.setattr(os, "read", reject_content_read)

    with pytest.raises(AppError) as captured:
        _ = tools.read_artifact_for_test(
            f"nplg://artifact/{source.object_id}",
            source.object_id,
        )

    assert captured.value.code is ErrorCode.DOWNLOAD_TOO_LARGE
    assert captured.value.http_status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert content_read is False


def test_registered_resource_rejects_oversize_declaration_before_content_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    data = b"jpeg"
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"doc_{digest}"
    relative_path = f"renders/{render_id}/page.jpg"
    _ = tools.store.put_render_bytes(relative_path, data)
    index = _persist_render_index(
        tools,
        render_id=render_id,
        identity=(
            artifact_id,
            relative_path,
            digest,
            HARD_MAX_INLINE_RESOURCE_BYTES + 1,
        ),
    )
    assert tools.load_and_cache_resource_for_test(index.parents[2], artifact_id)
    content_read = False

    def reject_content_read(descriptor: int, size: int) -> bytes:
        nonlocal content_read
        del descriptor, size
        content_read = True
        pytest.fail("oversize registered resource content reached os.read")

    monkeypatch.setattr(os, "read", reject_content_read)

    with pytest.raises(AppError) as captured:
        _ = tools.read_artifact_for_test(
            f"nplg://artifact/{artifact_id}",
            artifact_id,
        )

    assert captured.value.code is ErrorCode.DOWNLOAD_TOO_LARGE
    assert captured.value.http_status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert content_read is False


@pytest.mark.asyncio
async def test_document_resource_read_holds_a_prune_lease_until_bytes_are_copied(
    tmp_path: Path,
) -> None:
    """Removing the resource-read lease must expose the source to pruning."""
    store, policy, clock = lease_barrier_store(tmp_path)
    source = store.put_bytes(
        b"%PDF-1.7\nresource-read",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    processor = FakePdfProcessor(store)
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=InlinePdfExecutor(processor=processor, store=store),
            store=store,
        ),
        config=config(tmp_path),
    )
    uri = f"nplg://artifact/{source.object_id}"

    def read_resource() -> dict[str, str]:
        return asyncio.run(tools.read_resource(uri))

    operation = asyncio.create_task(asyncio.to_thread(read_resource))
    entered = await asyncio.to_thread(store.wait_until_leased)
    if not entered:
        store.release_lease_barrier()
        _ = await operation
        pytest.fail("document resource read did not acquire the public asset lease")

    while_reading = store.prune(policy, clock=clock)
    assert source.absolute_path.is_file()
    assert not (store.root / "renders" / processor.render_id).exists()
    assert while_reading.retained_leased_objects == 1
    assert (store.lease_acquisitions, store.lease_releases) == (1, 0)

    store.release_lease_barrier()
    result = await operation
    assert result["sha256"] == source.sha256
    assert (store.lease_acquisitions, store.lease_releases) == (1, 1)

    replacement = store.put_bytes(
        b"replacement",
        namespace="documents",
        filename="replacement.pdf",
        media_type="application/pdf",
    )
    after_read = store.prune(policy, clock=retention_sample(2.0))
    assert after_read.retained_leased_objects == 0
    assert not source.absolute_path.exists()
    assert replacement.absolute_path.is_file()


@pytest.mark.asyncio
async def test_document_resource_integrity_error_releases_its_lease_exactly_once(
    tmp_path: Path,
) -> None:
    store, _policy, _clock = lease_barrier_store(tmp_path)
    source = store.put_bytes(
        b"%PDF-1.7\nauthoritative",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    processor = FakePdfProcessor(store)
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=InlinePdfExecutor(processor=processor, store=store),
            store=store,
        ),
        config=config(tmp_path),
    )
    _ = source.absolute_path.write_bytes(b"tampered")
    store.release_lease_barrier()

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = await tools.read_resource(f"nplg://artifact/{source.object_id}")

    assert (store.lease_acquisitions, store.lease_releases) == (1, 1)


@pytest.mark.asyncio
async def test_render_registration_hash_holds_a_prune_lease_until_digest_finishes(
    tmp_path: Path,
) -> None:
    """Content identity hashing must protect the complete render object root."""
    store, policy, clock = lease_barrier_store(tmp_path)
    processor = FakePdfProcessor(store)
    source = store.put_bytes(
        b"%PDF-1.7\nrender-source",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=InlinePdfExecutor(processor=processor, store=store),
            store=store,
        ),
        config=config(tmp_path),
    )

    def render_page() -> StrictOutput:
        return asyncio.run(
            tools.call(
                "render_pdf_pages",
                {"artifact_id": source.object_id, "pages": [1]},
            )
        )

    operation = asyncio.create_task(asyncio.to_thread(render_page))
    entered = await asyncio.to_thread(store.wait_until_leased)
    if not entered:
        store.release_lease_barrier()
        _ = await operation
        pytest.fail("render content hashing did not acquire the public asset lease")

    while_hashing = store.prune(policy, clock=clock)
    render_root = store.root / "renders" / processor.render_id
    assert render_root.is_dir()
    assert not source.absolute_path.exists()
    assert while_hashing.retained_leased_objects == 1
    assert (store.lease_acquisitions, store.lease_releases) == (1, 0)

    store.release_lease_barrier()
    rendered = _output_json(await operation)
    assert rendered.get("render_id") == processor.render_id
    assert (store.lease_acquisitions, store.lease_releases) == (1, 1)


@pytest.mark.asyncio
async def test_registered_render_resource_read_holds_its_object_lease(
    tmp_path: Path,
) -> None:
    store, policy, clock = lease_barrier_store(tmp_path)
    store.release_lease_barrier()
    processor = FakePdfProcessor(store)
    source = store.put_bytes(
        b"%PDF-1.7\nregistered-resource",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=InlinePdfExecutor(processor=processor, store=store),
            store=store,
        ),
        config=config(tmp_path),
    )
    rendered = _output_json(
        await tools.call(
            "render_pdf_pages",
            {"artifact_id": source.object_id, "pages": [1]},
        )
    )
    page = require_json_object(
        _json_array(rendered.get("pages"), context="rendered pages")[0],
        context="rendered page",
    )
    resource_uri = _json_string(page.get("resource_uri"), context="resource URI")
    store.arm_lease_barrier()

    def read_resource() -> dict[str, str]:
        return asyncio.run(tools.read_resource(resource_uri))

    operation = asyncio.create_task(asyncio.to_thread(read_resource))
    entered = await asyncio.to_thread(store.wait_until_leased)
    if not entered:
        store.release_lease_barrier()
        _ = await operation
        pytest.fail("registered render read did not acquire the public asset lease")

    while_reading = store.prune(policy, clock=clock)
    assert (store.root / "renders" / processor.render_id).is_dir()
    assert not source.absolute_path.exists()
    assert while_reading.retained_leased_objects == 1

    store.release_lease_barrier()
    resource = await operation
    assert resource["sha256"] == processor.page_sha256
    assert store.leased_relative_paths == [processor.page_path]
    assert (store.lease_acquisitions, store.lease_releases) == (1, 1)


@pytest.mark.asyncio
async def test_duplicate_render_registration_leases_index_and_representative_reads(
    tmp_path: Path,
) -> None:
    """The duplicate path reads three files; omitting either lease is observable."""
    store, _policy, _clock = lease_barrier_store(tmp_path)
    store.release_lease_barrier()
    processor = FakePdfProcessor(store)
    source = store.put_bytes(
        b"%PDF-1.7\nduplicate-registration",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=InlinePdfExecutor(processor=processor, store=store),
            store=store,
        ),
        config=config(tmp_path),
    )
    arguments: JsonObject = {"artifact_id": source.object_id, "pages": [1]}
    _ = await tools.call("render_pdf_pages", arguments)
    store.arm_lease_barrier()

    def render_again() -> StrictOutput:
        return asyncio.run(tools.call("render_pdf_pages", arguments))

    operation = asyncio.create_task(asyncio.to_thread(render_again))
    entered = await asyncio.to_thread(store.wait_until_leased)
    if not entered:
        store.release_lease_barrier()
        _ = await operation
        pytest.fail("duplicate registration did not lease its content hash input")
    store.release_lease_barrier()
    _ = await operation

    artifact_id = f"doc_{processor.page_sha256}"
    expected_index = f"renders/{processor.render_id}/resources/{artifact_id}/index.json"
    assert store.leased_relative_paths == [
        processor.page_path,
        expected_index,
        processor.page_path,
    ]
    assert (store.lease_acquisitions, store.lease_releases) == (3, 3)


@pytest.mark.asyncio
async def test_metadata_and_file_tools_expose_repository_results(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)

    metadata = _output_json(
        await tools.call(
            "get_document_metadata",
            {"handle": "1234/560449"},
        )
    )
    files = _output_json(
        await tools.call("list_document_files", {"handle": "1234/560449"})
    )

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
            pdf=InlinePdfExecutor(processor=FakePdfProcessor(store), store=store),
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
        ("pages", "pages"),
        ("relative_path", "relative_path"),
        ("page_number", "page_number"),
        ("tiles", "tiles"),
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
            pdf=InlinePdfExecutor(
                processor=MalformedPdfProcessor(store, fault),
                store=store,
            ),
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
    with pytest.raises(ValidationError, match=message):
        _ = await tools.call(tool_name, arguments)


@pytest.mark.asyncio
async def test_pdf_job_releases_permit_when_executor_start_fails(
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
            pdf=FailOncePdfExecutor(
                processor=FakePdfProcessor(store),
                store=store,
            ),
            store=store,
        ),
        config=config(tmp_path),
    )

    with pytest.raises(RuntimeError, match="executor start failed"):
        _ = await tools.call(
            "inspect_pdf",
            {"artifact_id": artifact.object_id},
        )

    recovered = _output_json(
        await asyncio.wait_for(
            tools.call("inspect_pdf", {"artifact_id": artifact.object_id}),
            timeout=2,
        )
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
            pdf=InlinePdfExecutor(
                processor=CancelOncePdfProcessor(store),
                store=store,
            ),
            store=store,
        ),
        config=config(tmp_path),
    )

    with pytest.raises(asyncio.CancelledError):
        _ = await tools.call("inspect_pdf", {"artifact_id": artifact.object_id})
    await asyncio.sleep(0)

    recovered = _output_json(
        await asyncio.wait_for(
            tools.call("inspect_pdf", {"artifact_id": artifact.object_id}),
            timeout=2,
        )
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
            pdf=InlinePdfExecutor(
                processor=PopulatedTilePdfProcessor(store),
                store=store,
            ),
            store=store,
        ),
        config=config(tmp_path),
    )

    result = _output_json(
        await tools.call(
            "render_pdf_page_tiles",
            {"render_id": "rnd_" + "1" * 32, "page_number": 1},
        )
    )

    tiles = _json_array(result.get("tiles"), context="tiles")
    tile = require_json_object(tiles[0], context="tiles[0]")
    assert tile["resource_uri"] == (
        "nplg://artifact/"
        "doc_99917095357c700e296f8ce53aa2aaa3b83479ef0f3c16ce7a8992278f9fc023"
    )
    asset_url = _json_string(tile.get("asset_url"), context="asset_url")
    assert asset_url.startswith("https://mcp.example.test/assets/")


@pytest.mark.parametrize("operation", ["pages", "tiles"])
@pytest.mark.asyncio
async def test_render_resource_indexes_hold_bounded_publication_capacity(
    tmp_path: Path,
    operation: Literal["pages", "tiles"],
) -> None:
    tools, store, inner, artifact_id = _publication_tool_service(tmp_path)
    if operation == "pages":
        tool_name = "render_pdf_pages"
        arguments: JsonObject = {"artifact_id": artifact_id, "pages": [1]}
        maximum_indexes = HARD_MAX_RENDER_PAGES
        actual_indexes = 1
    else:
        tool_name = "render_pdf_page_tiles"
        arguments = {"render_id": "rnd_" + "1" * 32, "page_number": 1}
        maximum_indexes = HARD_MAX_TILES_PER_PAGE + 1
        actual_indexes = 2
    expected_reservation = (
        maximum_indexes * _RENDER_RESOURCE_INDEX_BYTES,
        1,
        2 * maximum_indexes + 2,
    )

    _ = await tools.call(tool_name, arguments)

    assert inner.execute_calls == 1
    assert store.index_reservations == [expected_reservation] * actual_indexes
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_page_index_reservation_covers_schema_bounded_worker_overproduction(
    tmp_path: Path,
) -> None:
    tools, store, inner, artifact_id = _publication_tool_service(
        tmp_path,
        options=_PublicationToolOptions(
            processor_type=_OverproducingPagePdfProcessor,
        ),
    )

    _ = await tools.call(
        "render_pdf_pages",
        {"artifact_id": artifact_id, "pages": [1]},
    )

    assert inner.execute_calls == 1
    assert store.index_reservations == [(32_768, 1, 18), (32_768, 1, 18)]
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_render_index_reservation_precedes_worker_headroom_admission(
    tmp_path: Path,
) -> None:
    minimum_free_bytes = 64 * 1024 * 1024
    tools, store, inner, artifact_id = _publication_tool_service(
        tmp_path,
        options=_PublicationToolOptions(
            available_bytes=(
                minimum_free_bytes + _GIB + _RENDER_RESOURCE_INDEX_BYTES - 1
            ),
        ),
    )

    with pytest.raises(PublicationReservationError) as caught:
        _ = await tools.call(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1]},
        )

    assert caught.value.blocker is PublicationBlocker.BYTE_HEADROOM
    assert inner.execute_calls == 0
    assert store.index_reservations == []
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_render_index_reservation_survives_later_closed_admission(
    tmp_path: Path,
) -> None:
    tools, store, inner, artifact_id = _publication_tool_service(
        tmp_path,
        options=_PublicationToolOptions(close_admission_during_dispatch=True),
    )

    _ = await tools.call(
        "render_pdf_pages",
        {"artifact_id": artifact_id, "pages": [1]},
    )

    assert inner.execute_calls == 1
    assert store.lifecycle_admission_closed
    assert store.index_reservations == [(32_768, 1, 18)]
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.parametrize("failure_type", [RuntimeError, asyncio.CancelledError])
@pytest.mark.asyncio
async def test_render_index_exception_or_cancellation_releases_reservation(
    tmp_path: Path,
    failure_type: type[BaseException],
) -> None:
    failure = failure_type("postprocessing index failure")
    tools, store, inner, artifact_id = _publication_tool_service(
        tmp_path,
        options=_PublicationToolOptions(index_failure=failure),
    )

    with pytest.raises(failure_type, match="postprocessing index failure"):
        _ = await tools.call(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1]},
        )

    assert inner.execute_calls == 1
    assert store.index_reservations == [(32_768, 1, 18)]
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_render_index_reservation_covers_final_output_validation(
    tmp_path: Path,
) -> None:
    tools, store, inner, artifact_id = _publication_tool_service(
        tmp_path,
        options=_PublicationToolOptions(service_type=_InvalidAssetUrlToolService),
    )

    with pytest.raises(ValidationError, match="asset_url"):
        _ = await tools.call(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1]},
        )

    assert inner.execute_calls == 1
    assert store.index_reservations == [(32_768, 1, 18)]
    assert (
        store.publication_reserved_bytes,
        store.publication_reserved_objects,
        store.publication_reserved_inodes,
    ) == (0, 0, 0)


def test_private_full_requires_every_stateful_dependency(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires downloader, PDF, and store"):
        _ = ToolService(
            dependencies=ToolServiceDependencies(repository=FakeRepository()),
            config=config(tmp_path),
        )


def test_document_resolution_rejects_an_invalid_internal_identifier(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    attribute_name = "_resolve_document"
    resolve_document = cast(
        "Callable[[str], Path]",
        getattr(tools, attribute_name),
    )

    with pytest.raises(AppError) as caught:
        _ = resolve_document("../outside")

    assert caught.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    ("tool_name", "argument_kind", "expected_message"),
    [
        ("inspect_pdf", "artifact", "unexpected inspect payload"),
        ("render_pdf_pages", "pages", "unexpected render payload"),
        ("render_pdf_page_tiles", "tiles", "unexpected tile payload"),
        ("get_render_manifest", "manifest", "unexpected manifest payload"),
    ],
)
@pytest.mark.asyncio
async def test_tool_service_rejects_operation_mismatched_worker_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    argument_kind: Literal["artifact", "pages", "tiles", "manifest"],
    expected_message: str,
) -> None:
    tools, _ = service(tmp_path)
    artifact = tools.store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    async def mismatched_result(command: PdfCommand) -> PdfSuccess:
        await asyncio.sleep(0)
        del command
        return cast("PdfSuccess", UnexpectedPdfSuccess())

    monkeypatch.setattr(tools, "_run_pdf_job", mismatched_result)
    render_id = "rnd_" + ("1" * 32)
    arguments_by_kind: dict[str, JsonObject] = {
        "artifact": {"artifact_id": artifact.object_id},
        "pages": {"artifact_id": artifact.object_id, "pages": [1]},
        "tiles": {"render_id": render_id, "page_number": 1},
        "manifest": {"render_id": render_id},
    }

    with pytest.raises(PdfWorkerError, match=expected_message):
        _ = await tools.call(tool_name, arguments_by_kind[argument_kind])


@pytest.mark.parametrize(
    ("fault", "expected_error", "expected_message"),
    [
        ("pages", TypeError, "pages must be an array"),
        ("relative_path", TypeError, "relative_path must be a string"),
        ("page_number", ValidationError, "pages.0.page_number"),
        (
            "manifest_relative_path",
            TypeError,
            "manifest_relative_path must be a string",
        ),
        ("tiles", TypeError, "tiles must be an array"),
    ],
)
@pytest.mark.asyncio
async def test_tool_service_rejects_corrupt_typed_serialization_at_trust_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: Literal[
        "pages",
        "relative_path",
        "page_number",
        "manifest_relative_path",
        "tiles",
    ],
    expected_error: type[Exception],
    expected_message: str,
) -> None:
    tools, _ = service(tmp_path)
    artifact = tools.store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    render_id = "rnd_" + ("1" * 32)
    valid_page: JsonObject = {
        "relative_path": f"renders/{render_id}/page-0001.jpg",
        "media_type": "image/jpeg",
        "page_number": 1,
        "sha256": "bc9cf615b74a3779185e9bd9ce5b988453aada714f8ee6e6238afc5416d11459",
    }
    forged_payloads: dict[str, JsonObject] = {
        "pages": {
            "render_id": render_id,
            "pages": "not-an-array",
            "manifest_relative_path": f"renders/{render_id}/manifest.json",
        },
        "relative_path": {
            "render_id": render_id,
            "pages": [{**valid_page, "relative_path": 7}],
            "manifest_relative_path": f"renders/{render_id}/manifest.json",
        },
        "page_number": {
            "render_id": render_id,
            "pages": [{**valid_page, "page_number": True}],
            "manifest_relative_path": f"renders/{render_id}/manifest.json",
        },
        "manifest_relative_path": {
            "render_id": render_id,
            "pages": [valid_page],
        },
        "tiles": {"tiles": "not-an-array"},
    }

    def forged_model_json(value: BaseModel, *, context: str) -> JsonObject:
        del value, context
        return forged_payloads[fault]

    monkeypatch.setattr(tools_module, "_model_json", forged_model_json)
    tool_name = "render_pdf_page_tiles" if fault == "tiles" else "render_pdf_pages"
    arguments: JsonObject = (
        {"render_id": render_id, "page_number": 1}
        if fault == "tiles"
        else {"artifact_id": artifact.object_id, "pages": [1]}
    )

    with pytest.raises(expected_error, match=expected_message):
        _ = await tools.call(tool_name, arguments)


class UnexpectedPdfSuccess:
    """Deliberately violate the executor's typed result contract in one test."""

    payload: object = object()


class TestableToolService(ToolService):
    """Typed public test facade for internal fail-closed resource invariants."""

    __test__ = False
    _forced_document_path: Path | None = None

    def ensure_profile_catalog_for_test(self) -> None:
        self._ensure_profile_catalog()

    def resource_index_path_for_test(self, render_id: str, artifact_id: str) -> str:
        return self._resource_index_relative_path(render_id, artifact_id)

    def prune_resource_for_test(self, render_id: str, artifact_id: str) -> None:
        self._prune_resource_index(render_id, artifact_id)

    def resource_is_cached_for_test(self, artifact_id: str) -> bool:
        return artifact_id in self._resource_artifacts

    def load_resource_index_for_test(
        self,
        render_directory: Path,
        artifact_id: str,
    ) -> bool:
        return (
            self._load_render_resource_index(render_directory, artifact_id) is not None
        )

    def load_and_cache_resource_for_test(
        self,
        render_directory: Path,
        artifact_id: str,
    ) -> bool:
        resource = self._load_render_resource_index(render_directory, artifact_id)
        if resource is None:
            return False
        self._resource_artifacts[artifact_id] = resource.owners
        return True

    def discover_resource_for_test(
        self,
        artifact_id: str,
    ) -> bool:
        return self._discover_render_artifact(artifact_id) is not None

    def read_artifact_for_test(self, uri: str, artifact_id: str) -> dict[str, str]:
        return self._read_artifact_resource(uri, artifact_id)

    def register_render_for_test(
        self,
        *,
        relative_path: str,
        sha256: str | None,
        media_type: str,
        render_id: str,
    ) -> str:
        return self._register_render_artifact(
            relative_path=relative_path,
            sha256=sha256,
            media_type=media_type,
            render_id=render_id,
        )

    def force_missing_document_for_test(self, path: Path) -> None:
        self._forced_document_path = path

    @override
    def _resolve_document(self, artifact_id: str) -> Path:
        if self._forced_document_path is not None:
            return self._forced_document_path
        return super()._resolve_document(artifact_id)

    @property
    def pdf_limiter_for_test(self) -> asyncio.Semaphore:
        return self._pdf_jobs


_FUTURE_TIMESTAMP = 4_102_444_800


@dataclass(frozen=True, slots=True)
class _PersistRenderIndexOptions:
    expires_at: int = _FUTURE_TIMESTAMP
    media_type: str = "image/jpeg"


_DEFAULT_PERSIST_RENDER_INDEX_OPTIONS = _PersistRenderIndexOptions()


def _persist_render_index(
    tools: TestableToolService,
    *,
    render_id: str,
    identity: tuple[str, str, str, int],
    options: _PersistRenderIndexOptions = _DEFAULT_PERSIST_RENDER_INDEX_OPTIONS,
) -> Path:
    """Persist one controlled strict render-resource sidecar."""
    artifact_id, relative_path, sha256, size = identity
    payload_document: JsonObject = {
        "artifact_id": artifact_id,
        "expires_at": options.expires_at,
        "media_type": options.media_type,
        "relative_path": relative_path,
        "render_id": render_id,
        "sha256": sha256,
        "size": size,
        "version": 1,
    }
    payload = json.dumps(
        payload_document,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    index_relative_path = tools.resource_index_path_for_test(render_id, artifact_id)
    written, _ = tools.store.put_render_bytes(index_relative_path, payload)
    return tools.store.root / written


def test_profile_catalog_rejects_exact_name_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)

    def wrong_names(_profile: object) -> tuple[()]:
        return ()

    monkeypatch.setattr(tools_module, "tool_names_for_profile", wrong_names)

    with pytest.raises(ValueError, match="deployment profile"):
        tools.ensure_profile_catalog_for_test()


def test_pruning_absent_resource_still_removes_persisted_subtree(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    artifact_id = "doc_" + "2" * 64

    tools.prune_resource_for_test(render_id, artifact_id)

    assert not tools.resource_is_cached_for_test(artifact_id)


def test_render_index_rejects_invalid_render_directory(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_directory = tools.store.root / "renders" / "not-a-render"
    render_directory.mkdir(parents=True)

    with pytest.raises(AppError, match="Render storage is corrupted"):
        _ = tools.load_resource_index_for_test(
            render_directory,
            "doc_" + "2" * 64,
        )


def test_render_index_rejects_non_file_index(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    artifact_id = "doc_" + "2" * 64
    index = (
        tools.store.root
        / "renders"
        / render_id
        / "resources"
        / artifact_id
        / "index.json"
    )
    index.mkdir(parents=True)

    with pytest.raises(AppError, match="index is invalid"):
        _ = tools.load_resource_index_for_test(index.parents[2], artifact_id)


def test_render_index_rejects_requested_artifact_rebinding(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    data = b"jpeg"
    digest = hashlib.sha256(data).hexdigest()
    actual_artifact_id = f"doc_{digest}"
    requested_artifact_id = "doc_" + "2" * 64
    relative_path = f"renders/{render_id}/page.jpg"
    _ = tools.store.put_render_bytes(relative_path, data)
    source_index = _persist_render_index(
        tools,
        render_id=render_id,
        identity=(actual_artifact_id, relative_path, digest, len(data)),
    )
    payload = source_index.read_bytes()
    requested_index = tools.resource_index_path_for_test(
        render_id,
        requested_artifact_id,
    )
    _ = tools.store.put_render_bytes(requested_index, payload)

    with pytest.raises(AppError, match="provenance is invalid"):
        _ = tools.load_resource_index_for_test(
            tools.store.root / "renders" / render_id,
            requested_artifact_id,
        )


def test_render_index_expiry_prunes_authorization(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    data = b"jpeg"
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"doc_{digest}"
    relative_path = f"renders/{render_id}/page.jpg"
    _ = tools.store.put_render_bytes(relative_path, data)
    index = _persist_render_index(
        tools,
        render_id=render_id,
        identity=(artifact_id, relative_path, digest, len(data)),
        options=_PersistRenderIndexOptions(expires_at=0),
    )

    assert not tools.load_resource_index_for_test(index.parents[2], artifact_id)
    assert not index.exists()


def test_render_discovery_returns_none_without_render_root(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    renders_root = tools.store.root / "renders"
    for render_directory in tuple(renders_root.iterdir()):
        assert tools.store.delete_render_subtree(f"renders/{render_directory.name}")
    renders_root.rmdir()

    assert not tools.discover_resource_for_test("doc_" + "2" * 64)


def test_render_discovery_rejects_non_directory_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)
    renders_root = tools.store.root / "renders"
    original_is_dir = Path.is_dir

    def false_for_render(path: Path) -> bool:
        return False if path == renders_root else original_is_dir(path)

    monkeypatch.setattr(
        Path,
        "is_dir",
        false_for_render,
    )

    with pytest.raises(AppError, match="Render storage is corrupted"):
        _ = tools.discover_resource_for_test("doc_" + "2" * 64)


def test_render_discovery_enforces_scan_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)
    (tools.store.root / "renders" / ("rnd_" + "1" * 32)).mkdir(
        parents=True,
        exist_ok=True,
    )
    monkeypatch.setattr(tools_module, "_MAX_RENDER_RESOURCE_SCAN_DIRECTORIES", 0)

    with pytest.raises(AppError, match="exceeds its scan bound"):
        _ = tools.discover_resource_for_test("doc_" + "2" * 64)


def test_render_discovery_accepts_identical_content_with_multiple_owners(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    data = b"same-jpeg"
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"doc_{digest}"
    for digit in ("1", "2"):
        render_id = "rnd_" + digit * 32
        relative_path = f"renders/{render_id}/page.jpg"
        _ = tools.store.put_render_bytes(relative_path, data)
        _ = _persist_render_index(
            tools,
            render_id=render_id,
            identity=(artifact_id, relative_path, digest, len(data)),
        )

    assert tools.discover_resource_for_test(artifact_id) is True
    resource = tools.read_artifact_for_test(
        f"nplg://artifact/{artifact_id}",
        artifact_id,
    )
    assert resource["sha256"] == digest
    assert resource["render_id"] == ""


def test_multi_owner_pruning_retains_a_valid_authorized_owner(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    data = b"same-jpeg"
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"doc_{digest}"
    render_ids = tuple("rnd_" + digit * 32 for digit in ("1", "2"))
    for render_id in render_ids:
        relative_path = f"renders/{render_id}/page.jpg"
        _ = tools.store.put_render_bytes(relative_path, data)
        _ = _persist_render_index(
            tools,
            render_id=render_id,
            identity=(artifact_id, relative_path, digest, len(data)),
        )
    assert tools.discover_resource_for_test(artifact_id) is True

    tools.prune_resource_for_test(render_ids[0], artifact_id)
    resource = tools.read_artifact_for_test(
        f"nplg://artifact/{artifact_id}",
        artifact_id,
    )

    assert tools.resource_is_cached_for_test(artifact_id) is True
    assert resource["render_id"] == render_ids[1]


def test_multi_owner_discovery_rejects_conflicting_media_identity(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    data = b"same-content"
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"doc_{digest}"
    first_render = "rnd_" + "1" * 32
    first_path = f"renders/{first_render}/page.jpg"
    _ = tools.store.put_render_bytes(first_path, data)
    _ = _persist_render_index(
        tools,
        render_id=first_render,
        identity=(artifact_id, first_path, digest, len(data)),
    )
    second_render = "rnd_" + "2" * 32
    second_path = f"renders/{second_render}/manifest.json"
    _ = tools.store.put_render_bytes(second_path, data)
    _ = _persist_render_index(
        tools,
        render_id=second_render,
        identity=(artifact_id, second_path, digest, len(data)),
        options=_PersistRenderIndexOptions(media_type="application/json"),
    )

    with pytest.raises(AppError, match="provenance is ambiguous"):
        _ = tools.discover_resource_for_test(artifact_id)


@pytest.mark.parametrize(
    ("relative_path", "code"),
    [
        (
            "renders/rnd_11111111111111111111111111111111/missing.jpg",
            ErrorCode.NOT_FOUND,
        ),
        (
            "renders/rnd_11111111111111111111111111111111/../bad.jpg",
            ErrorCode.INVALID_INPUT,
        ),
    ],
)
def test_registered_resource_maps_only_storage_not_found(
    tmp_path: Path,
    relative_path: str,
    code: ErrorCode,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    digest = "2" * 64
    artifact_id = f"doc_{digest}"
    index = _persist_render_index(
        tools,
        render_id=render_id,
        identity=(artifact_id, relative_path, digest, 1),
    )
    assert tools.load_and_cache_resource_for_test(index.parents[2], artifact_id)

    with pytest.raises(AppError) as captured:
        _ = tools.read_artifact_for_test(f"nplg://artifact/{artifact_id}", artifact_id)

    expected = ErrorCode.NOT_FOUND if code is ErrorCode.NOT_FOUND else code
    assert captured.value.code is expected


def test_registered_resource_prunes_after_read_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    data = b"jpeg"
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"doc_{digest}"
    relative_path = f"renders/{render_id}/page.jpg"
    path = tools.store.root / relative_path
    _ = tools.store.put_render_bytes(relative_path, data)
    index = _persist_render_index(
        tools,
        render_id=render_id,
        identity=(artifact_id, relative_path, digest, len(data)),
    )
    assert tools.load_and_cache_resource_for_test(index.parents[2], artifact_id)

    def resolved_deleted_path(_relative: str) -> Path:
        return path

    monkeypatch.setattr(tools.store, "resolve_asset", resolved_deleted_path)
    path.unlink()

    with pytest.raises(AppError) as captured:
        _ = tools.read_artifact_for_test(f"nplg://artifact/{artifact_id}", artifact_id)

    assert captured.value.code is ErrorCode.NOT_FOUND
    assert not tools.resource_is_cached_for_test(artifact_id)


def test_unregistered_document_deletion_skips_render_pruning(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    artifact_id = "doc_" + "2" * 64
    missing = tools.store.root / "documents" / artifact_id / "source.pdf"

    tools.force_missing_document_for_test(missing)

    with pytest.raises(AppError) as captured:
        _ = tools.read_artifact_for_test(f"nplg://artifact/{artifact_id}", artifact_id)

    assert captured.value.code is ErrorCode.NOT_FOUND


def test_unregistered_document_rejects_content_digest_mismatch(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    artifact_id = "doc_" + "2" * 64
    mismatched = tools.store.put_bytes(
        b"not-the-addressed-content",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    tools.force_missing_document_for_test(mismatched.absolute_path)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools.read_artifact_for_test(f"nplg://artifact/{artifact_id}", artifact_id)


def test_registered_resource_rejects_size_mismatch_with_valid_digest(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    data = b"jpeg"
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"doc_{digest}"
    relative_path = f"renders/{render_id}/page.jpg"
    _ = tools.store.put_render_bytes(relative_path, data)
    index = _persist_render_index(
        tools,
        render_id=render_id,
        identity=(artifact_id, relative_path, digest, len(data) + 1),
    )
    assert tools.load_and_cache_resource_for_test(index.parents[2], artifact_id)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools.read_artifact_for_test(f"nplg://artifact/{artifact_id}", artifact_id)


def test_render_registration_rejects_unapproved_media_type(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(AppError, match="media type is invalid"):
        _ = tools.register_render_for_test(
            relative_path="renders/rnd_" + "1" * 32 + "/page.jpg",
            sha256=None,
            media_type="text/plain",
            render_id="rnd_" + "1" * 32,
        )


def test_render_registration_rejects_cross_render_path(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)

    with pytest.raises(AppError, match="provenance is invalid"):
        _ = tools.register_render_for_test(
            relative_path="renders/rnd_" + "2" * 32 + "/page.jpg",
            sha256=None,
            media_type="image/jpeg",
            render_id="rnd_" + "1" * 32,
        )


def test_render_registration_rejects_empty_artifact(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    relative_path = f"renders/{render_id}/page.jpg"
    _ = tools.store.put_render_bytes(relative_path, b"")

    with pytest.raises(AppError, match="size is invalid"):
        _ = tools.register_render_for_test(
            relative_path=relative_path,
            sha256=None,
            media_type="image/jpeg",
            render_id=render_id,
        )


def test_render_registration_rejects_supplied_digest_mismatch(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    relative_path = f"renders/{render_id}/page.jpg"
    _ = tools.store.put_render_bytes(relative_path, b"jpeg")

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools.register_render_for_test(
            relative_path=relative_path,
            sha256="2" * 64,
            media_type="image/jpeg",
            render_id=render_id,
        )


def test_render_registration_accepts_same_content_at_two_paths_in_one_render(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/first.jpg"
    second_path = f"renders/{render_id}/second.jpg"
    _ = tools.store.put_render_bytes(first_path, b"jpeg")
    _ = tools.store.put_render_bytes(second_path, b"jpeg")
    first_id = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )

    second_id = tools.register_render_for_test(
        relative_path=second_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    restarted, _ = service(tmp_path)
    resource = restarted.read_artifact_for_test(
        f"nplg://artifact/{first_id}",
        first_id,
    )

    assert second_id == first_id
    assert resource["sha256"] == first_id.removeprefix("doc_")
    assert resource["render_id"] == render_id


@pytest.mark.parametrize("path_count", [33, 100])
def test_same_render_duplicate_content_scales_to_allowed_tile_count_after_restart(
    tmp_path: Path,
    path_count: int,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    artifact_ids: set[str] = set()
    for index in range(path_count):
        relative_path = f"renders/{render_id}/tile-{index:04}.jpg"
        _ = tools.store.put_render_bytes(relative_path, b"identical-tile")
        artifact_ids.add(
            tools.register_render_for_test(
                relative_path=relative_path,
                sha256=None,
                media_type="image/jpeg",
                render_id=render_id,
            )
        )

    [artifact_id] = artifact_ids
    restarted, _ = service(tmp_path)
    resource = restarted.read_artifact_for_test(
        f"nplg://artifact/{artifact_id}",
        artifact_id,
    )

    assert resource["sha256"] == artifact_id.removeprefix("doc_")
    assert resource["render_id"] == render_id


@pytest.mark.parametrize("reader_mode", ["in-process", "restart"])
def test_missing_representative_is_replaced_by_verified_same_render_duplicate(
    tmp_path: Path,
    reader_mode: str,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/tile-0000.jpg"
    second_path = f"renders/{render_id}/tile-0001.jpg"
    data = b"identical-tile"
    _ = tools.store.put_render_bytes(first_path, data)
    artifact_id = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    (tools.store.root / first_path).unlink()
    _ = tools.store.put_render_bytes(second_path, data)

    duplicate_id = tools.register_render_for_test(
        relative_path=second_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    reader = service(tmp_path)[0] if reader_mode == "restart" else tools
    resource = reader.read_artifact_for_test(
        f"nplg://artifact/{artifact_id}",
        artifact_id,
    )

    assert duplicate_id == artifact_id
    assert resource["sha256"] == artifact_id.removeprefix("doc_")
    assert resource["render_id"] == render_id


def test_representative_deleted_after_resolution_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/tile-0000.jpg"
    second_path = f"renders/{render_id}/tile-0001.jpg"
    data = b"identical-tile"
    _ = tools.store.put_render_bytes(first_path, data)
    artifact_id = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    _ = tools.store.put_render_bytes(second_path, data)
    real_resolve = tools.store.resolve_asset

    def resolve_then_delete(relative_path: str) -> Path:
        resolved = real_resolve(relative_path)
        if relative_path == first_path:
            resolved.unlink()
        return resolved

    monkeypatch.setattr(tools.store, "resolve_asset", resolve_then_delete)

    duplicate_id = tools.register_render_for_test(
        relative_path=second_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    resource = tools.read_artifact_for_test(
        f"nplg://artifact/{artifact_id}",
        artifact_id,
    )

    assert duplicate_id == artifact_id
    assert resource["sha256"] == artifact_id.removeprefix("doc_")


def test_missing_representative_index_is_not_silently_recreated(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/tile-0000.jpg"
    second_path = f"renders/{render_id}/tile-0001.jpg"
    data = b"identical-tile"
    _ = tools.store.put_render_bytes(first_path, data)
    artifact_id = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    index_path = tools.store.root / tools.resource_index_path_for_test(
        render_id,
        artifact_id,
    )
    index_path.unlink()
    _ = tools.store.put_render_bytes(second_path, data)

    with pytest.raises(AppError, match="index is invalid"):
        _ = tools.register_render_for_test(
            relative_path=second_path,
            sha256=None,
            media_type="image/jpeg",
            render_id=render_id,
        )


def test_symlink_representative_is_not_replaced_by_duplicate(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/tile-0000.jpg"
    second_path = f"renders/{render_id}/tile-0001.jpg"
    data = b"identical-tile"
    _ = tools.store.put_render_bytes(first_path, data)
    _ = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    (tools.store.root / first_path).unlink()
    _ = tools.store.put_render_bytes(second_path, data)
    (tools.store.root / first_path).symlink_to(tools.store.root / second_path)

    with pytest.raises(AppError, match="provenance is invalid"):
        _ = tools.register_render_for_test(
            relative_path=second_path,
            sha256=None,
            media_type="image/jpeg",
            render_id=render_id,
        )


def test_empty_representative_is_not_replaced_by_duplicate(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/tile-0000.jpg"
    second_path = f"renders/{render_id}/tile-0001.jpg"
    data = b"identical-tile"
    _ = tools.store.put_render_bytes(first_path, data)
    _ = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    _ = (tools.store.root / first_path).write_bytes(b"")
    _ = tools.store.put_render_bytes(second_path, data)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools.register_render_for_test(
            relative_path=second_path,
            sha256=None,
            media_type="image/jpeg",
            render_id=render_id,
        )


@pytest.mark.parametrize("fault", ["invalid", "unavailable", "read"])
def test_representative_lookup_fault_is_not_silently_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/tile-0000.jpg"
    second_path = f"renders/{render_id}/tile-0001.jpg"
    data = b"identical-tile"
    _ = tools.store.put_render_bytes(first_path, data)
    _ = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    _ = tools.store.put_render_bytes(second_path, data)
    real_resolve = tools.store.resolve_asset
    real_read_bytes = Path.read_bytes

    def faulty_resolve(relative_path: str) -> Path:
        if relative_path == first_path:
            code = (
                ErrorCode.INVALID_INPUT if fault == "invalid" else ErrorCode.NOT_FOUND
            )
            raise AppError(code, "injected lookup fault")
        return real_resolve(relative_path)

    def faulty_read_bytes(path: Path) -> bytes:
        if path == tools.store.root / first_path:
            message = "injected read fault"
            raise OSError(message)
        return real_read_bytes(path)

    if fault == "read":
        monkeypatch.setattr(Path, "read_bytes", faulty_read_bytes)
    else:
        monkeypatch.setattr(tools.store, "resolve_asset", faulty_resolve)

    with pytest.raises(AppError) as captured:
        _ = tools.register_render_for_test(
            relative_path=second_path,
            sha256=None,
            media_type="image/jpeg",
            render_id=render_id,
        )

    assert captured.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.INTERNAL_ERROR}


def test_same_render_duplicate_with_conflicting_media_type_is_rejected(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    data = b"same-content"
    image_path = f"renders/{render_id}/tile.jpg"
    manifest_path = f"renders/{render_id}/other/manifest.json"
    _ = tools.store.put_render_bytes(image_path, data)
    _ = tools.register_render_for_test(
        relative_path=image_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    _ = tools.store.put_render_bytes(manifest_path, data)

    with pytest.raises(AppError, match="provenance is ambiguous"):
        _ = tools.register_render_for_test(
            relative_path=manifest_path,
            sha256=None,
            media_type="application/json",
            render_id=render_id,
        )


def test_corrupt_representative_is_not_replaced_by_duplicate(tmp_path: Path) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/tile-0000.jpg"
    second_path = f"renders/{render_id}/tile-0001.jpg"
    data = b"identical-tile"
    _ = tools.store.put_render_bytes(first_path, data)
    _ = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    _ = (tools.store.root / first_path).write_bytes(b"corrupted-tile")
    _ = tools.store.put_render_bytes(second_path, data)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools.register_render_for_test(
            relative_path=second_path,
            sha256=None,
            media_type="image/jpeg",
            render_id=render_id,
        )


def test_corrupt_index_is_not_overwritten_when_representative_is_missing(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    first_path = f"renders/{render_id}/tile-0000.jpg"
    second_path = f"renders/{render_id}/tile-0001.jpg"
    data = b"identical-tile"
    _ = tools.store.put_render_bytes(first_path, data)
    artifact_id = tools.register_render_for_test(
        relative_path=first_path,
        sha256=None,
        media_type="image/jpeg",
        render_id=render_id,
    )
    (tools.store.root / first_path).unlink()
    index_path = tools.store.root / tools.resource_index_path_for_test(
        render_id,
        artifact_id,
    )
    _ = index_path.write_bytes(b"{")
    _ = tools.store.put_render_bytes(second_path, data)

    with pytest.raises(AppError, match="index is invalid"):
        _ = tools.register_render_for_test(
            relative_path=second_path,
            sha256=None,
            media_type="image/jpeg",
            render_id=render_id,
        )


def test_restart_rejects_representative_path_with_mismatched_content(
    tmp_path: Path,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    expected = b"expected-jpeg"
    digest = hashlib.sha256(expected).hexdigest()
    artifact_id = f"doc_{digest}"
    forged_path = f"renders/{render_id}/representative.jpg"
    _ = tools.store.put_render_bytes(forged_path, b"forged-jpeg")
    _ = _persist_render_index(
        tools,
        render_id=render_id,
        identity=(artifact_id, forged_path, digest, len(expected)),
    )
    restarted, _ = service(tmp_path)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = restarted.read_artifact_for_test(
            f"nplg://artifact/{artifact_id}",
            artifact_id,
        )


@pytest.mark.parametrize("forgery", ["cross-render", "wrong-media"])
def test_restart_rejects_forged_representative_path_binding(
    tmp_path: Path,
    forgery: str,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    data = b"expected-jpeg"
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = f"doc_{digest}"
    primary_path = f"renders/{render_id}/first.jpg"
    _ = tools.store.put_render_bytes(primary_path, data)
    forged_paths: dict[str, str] = {
        "cross-render": f"renders/rnd_{'2' * 32}/second.jpg",
        "wrong-media": f"renders/{render_id}/second.json",
    }
    index = _persist_render_index(
        tools,
        render_id=render_id,
        identity=(artifact_id, forged_paths[forgery], digest, len(data)),
    )
    restarted, _ = service(tmp_path)

    with pytest.raises(AppError, match="provenance is invalid"):
        _ = restarted.load_resource_index_for_test(
            index.parents[2],
            artifact_id,
        )


def test_render_registration_rejects_index_write_path_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)
    render_id = "rnd_" + "1" * 32
    relative_path = f"renders/{render_id}/page.jpg"
    _ = tools.store.put_render_bytes(relative_path, b"jpeg")
    original_put = tools.store.put_render_bytes

    def wrong_index_path(path: str, data: bytes) -> tuple[str, str]:
        written, digest = original_put(path, data)
        return f"{written}.wrong", digest

    monkeypatch.setattr(tools.store, "put_render_bytes", wrong_index_path)

    with pytest.raises(AppError, match="index path mismatch"):
        _ = tools.register_render_for_test(
            relative_path=relative_path,
            sha256=None,
            media_type="image/jpeg",
            render_id=render_id,
        )


@pytest.mark.asyncio
async def test_pdf_job_does_not_release_unacquired_permit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools, _ = service(tmp_path)
    artifact = tools.store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    async def timeout_acquire() -> bool:
        raise TimeoutError

    monkeypatch.setattr(tools.pdf_limiter_for_test, "acquire", timeout_acquire)

    with pytest.raises(AppError) as captured:
        _ = await tools.call("inspect_pdf", {"artifact_id": artifact.object_id})

    assert captured.value.code is ErrorCode.PDF_PROCESSING_FAILED
