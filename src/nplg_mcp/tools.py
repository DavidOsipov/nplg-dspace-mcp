# Copyright (c) 2026 David Osipov
"""Typed service layer for the NPLG MCP tool operations."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol, cast
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
)

from .config import (
    HARD_MAX_TILE_DIMENSION,
    HARD_MAX_TILE_OVERLAP,
    AppConfig,
    validate_deployment_profile,
)
from .errors import AppError, ErrorCode
from .json_types import (
    JsonObject,
    dataclass_to_json,
    load_json_value,
    require_json_object,
    validation_details,
)
from .tokens import sign_asset_token

if TYPE_CHECKING:
    from pathlib import Path

    from .downloader import DownloadResult
    from .parsers import Bitstream, DocumentRecord, SearchPage
    from .pdf_executor import PdfExecutor
    from .pdf_ipc import PdfCommand, PdfSuccess, RenderPagesOutput
    from .storage import ContentAddressedStore

_DOCUMENT_ID_RE = re.compile(r"^doc_[0-9a-f]{64}$")
_RENDER_ID_RE = re.compile(r"^rnd_[0-9a-f]{32}$")
_PDF_JOB_TIMEOUT_SECONDS = 35.0


class StrictInput(BaseModel):
    """Strict base model for every public tool-input boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)


class SearchDocumentsInput(StrictInput):
    """Validated input for repository search."""

    query: str = Field(min_length=1, max_length=500)
    cursor: str | None = Field(default=None, max_length=128)
    page_size: int = Field(default=20, ge=1, le=50)
    scope_handle: str | None = Field(default=None, max_length=128)

    @field_validator("query")
    @classmethod
    def non_blank_query(cls, value: str) -> str:
        """Normalize internal whitespace and reject an empty query."""
        normalized = " ".join(value.split())
        if not normalized:
            msg = "query must contain non-whitespace characters"
            raise ValueError(msg)
        return normalized


class HandleInput(StrictInput):
    """Validated canonical-handle input."""

    handle: str = Field(min_length=3, max_length=128)


class DownloadDocumentInput(HandleInput):
    """Validated input for one discovered document bitstream."""

    bitstream_id: str = Field(min_length=1, max_length=128)


class ArtifactInput(StrictInput):
    """Validated content-addressed document identifier."""

    artifact_id: str = Field(pattern=r"^doc_[0-9a-f]{64}$")


class RenderPagesInput(ArtifactInput):
    """Validated page-render request."""

    pages: list[int] = Field(min_length=1, max_length=8)
    mode: str = Field(default="native", pattern=r"^native$")


class RenderTilesInput(StrictInput):
    """Validated crop-only tile request."""

    render_id: str = Field(pattern=r"^rnd_[0-9a-f]{32}$")
    page_number: int = Field(ge=1)
    tile_width: int | None = Field(default=None, ge=256, le=HARD_MAX_TILE_DIMENSION)
    tile_height: int | None = Field(default=None, ge=256, le=HARD_MAX_TILE_DIMENSION)
    overlap: int | None = Field(default=None, ge=0, le=HARD_MAX_TILE_OVERLAP)

    @field_validator("overlap")
    @classmethod
    def overlap_must_fit_explicit_geometry(
        cls, value: int | None, info: ValidationInfo[dict[str, object] | None]
    ) -> int | None:
        """Reject an overlap that consumes either explicit tile dimension."""
        if value is None:
            return value
        raw_data: object = info.data
        data = cast("dict[str, object]", raw_data)
        width = data.get("tile_width")
        height = data.get("tile_height")
        if type(width) is int and value >= width:
            msg = "overlap must be smaller than tile_width"
            raise ValueError(msg)
        if type(height) is int and value >= height:
            msg = "overlap must be smaller than tile_height"
            raise ValueError(msg)
        return value


class RenderIdInput(StrictInput):
    """Validated deterministic render identifier."""

    render_id: str = Field(pattern=r"^rnd_[0-9a-f]{32}$")


def _json_string(value: object, *, context: str) -> str:
    if not isinstance(value, str):
        msg = f"{context} must be a string"
        raise TypeError(msg)
    return value


def _json_integer(value: object, *, context: str) -> int:
    if type(value) is not int:
        msg = f"{context} must be an integer"
        raise TypeError(msg)
    return value


def _model_json(value: BaseModel, *, context: str) -> JsonObject:
    """Serialize one validated Pydantic model and recheck its JSON shape."""
    return require_json_object(
        load_json_value(value.model_dump_json()),
        context=context,
    )


class RepositoryProtocol(Protocol):
    """Repository operations consumed by the tool service."""

    async def search(
        self,
        query: str,
        *,
        cursor: str | None = None,
        page_size: int = 20,
        scope_handle: str | None = None,
    ) -> SearchPage:
        """Search repository records with an optional continuation cursor."""
        ...

    async def get_metadata(self, handle: str) -> DocumentRecord:
        """Return full metadata for one canonical handle."""
        ...

    async def list_files(self, handle: str) -> tuple[Bitstream, ...]:
        """Return discovered files for one canonical handle."""
        ...


class DownloaderProtocol(Protocol):
    """Bounded public-bitstream downloader consumed by the tool service."""

    async def download(self, bitstream: Bitstream) -> DownloadResult:
        """Download one previously discovered public bitstream."""
        ...


Handler = Callable[[BaseModel], Awaitable[JsonObject]]
UtcClock = Callable[[], datetime]


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


def _validated_serialized_pdf_capacity(executor: object, capacity: object) -> int:
    if type(executor) is not str or executor != "serialized":
        msg = "PDF_EXECUTOR must be serialized"
        raise ValueError(msg)
    if type(capacity) is not int or capacity != 1:
        msg = "MAX_CONCURRENT_PDF_JOBS must equal 1 for serialized PDF_EXECUTOR"
        raise ValueError(msg)
    return capacity


def _joined_text(*parts: str) -> str:
    return " ".join(parts)


@dataclass(frozen=True, slots=True)
class ToolServiceDependencies:
    """Immutable typed collaborators used by the tool service."""

    repository: RepositoryProtocol
    downloader: DownloaderProtocol | None = None
    pdf: PdfExecutor | None = None
    store: ContentAddressedStore | None = None


class ToolService:
    """Validated, stateless orchestration layer exposed through MCP tools."""

    def __init__(
        self,
        *,
        dependencies: ToolServiceDependencies,
        config: AppConfig,
        utc_now: UtcClock = _system_utc_now,
    ) -> None:
        """Bind validated configuration and typed runtime collaborators."""
        super().__init__()
        self.repository = dependencies.repository
        self.config = config
        self._utc_now = utc_now
        profile = validate_deployment_profile(config.deployment_profile)
        self._profile = profile
        if profile == "alpic-metadata":
            metadata_definitions: dict[
                str,
                tuple[str, str, type[StrictInput], Handler],
            ] = {
                "get_document_metadata": (
                    "Read full document metadata",
                    _joined_text(
                        "Read rich Dublin Core metadata for an NPLG item, preferring",
                        "OAI-DIM and falling back to the full XMLUI/Manakin record.",
                    ),
                    HandleInput,
                    self._get_metadata,
                ),
                "list_document_files": (
                    "List document files",
                    _joined_text(
                        "List public or restricted bitstreams bound to a canonical",
                        "NPLG item handle.",
                    ),
                    HandleInput,
                    self._list_files,
                ),
                "search_documents": (
                    "Search NPLG Iverieli",
                    _joined_text(
                        "Search the NPLG DSpace repository, optionally within a",
                        "canonical collection handle, and return an opaque",
                        "continuation cursor.",
                    ),
                    SearchDocumentsInput,
                    self._search,
                ),
            }
            self._definitions = metadata_definitions
            return
        if profile == "distributed-full":
            msg = "distributed-full is not implemented and must remain disabled"
            raise ValueError(msg)
        downloader = dependencies.downloader
        pdf = dependencies.pdf
        store = dependencies.store
        if downloader is None or pdf is None or store is None:
            msg = "private-full requires downloader, PDF, and store dependencies"
            raise ValueError(msg)
        max_concurrent_pdf_jobs = _validated_serialized_pdf_capacity(
            config.pdf_executor,
            config.max_concurrent_pdf_jobs,
        )
        self.downloader = downloader
        self.pdf = pdf
        self.store = store
        self._pdf_jobs = asyncio.Semaphore(max_concurrent_pdf_jobs)
        definitions: dict[str, tuple[str, str, type[StrictInput], Handler]] = {
            "download_document_file": (
                "Download a public PDF",
                _joined_text(
                    "Download a PDF bitstream previously discovered on the",
                    "requested NPLG item page. Arbitrary URLs are not accepted.",
                ),
                DownloadDocumentInput,
                self._download_document,
            ),
            "get_document_metadata": (
                "Read full document metadata",
                _joined_text(
                    "Read rich Dublin Core metadata for an NPLG item, preferring",
                    "OAI-DIM and falling back to the full XMLUI/Manakin record.",
                ),
                HandleInput,
                self._get_metadata,
            ),
            "get_render_manifest": (
                "Read a render manifest",
                _joined_text(
                    "Read deterministic page-render metadata and signed image",
                    "URLs for an existing render identifier.",
                ),
                RenderIdInput,
                self._get_render_manifest,
            ),
            "inspect_pdf": (
                "Inspect a downloaded PDF",
                _joined_text(
                    "Classify every PDF page and report embedded scan dimensions,",
                    "effective DPI, crop, rotation, and text-overlay characteristics.",
                ),
                ArtifactInput,
                self._inspect_pdf,
            ),
            "list_document_files": (
                "List document files",
                _joined_text(
                    "List public or restricted bitstreams bound to a canonical",
                    "NPLG item handle.",
                ),
                HandleInput,
                self._list_files,
            ),
            "render_pdf_page_tiles": (
                "Create crop-only page tiles",
                _joined_text(
                    "Crop a rendered page into overlapping JPEG tiles without",
                    "resizing. Defaults are 2048\N{MULTIPLICATION SIGN}2048 with",
                    "128-pixel overlap.",
                ),
                RenderTilesInput,
                self._render_tiles,
            ),
            "render_pdf_pages": (
                "Render PDF pages as JPEG",
                _joined_text(
                    "Render selected pages on their native embedded-scan pixel",
                    "grid when determinable; otherwise use an explicitly labelled",
                    "400-DPI fallback.",
                ),
                RenderPagesInput,
                self._render_pages,
            ),
            "search_documents": (
                "Search NPLG Iverieli",
                _joined_text(
                    "Search the NPLG DSpace repository, optionally within a",
                    "canonical collection handle, and return an opaque",
                    "continuation cursor.",
                ),
                SearchDocumentsInput,
                self._search,
            ),
        }
        self._definitions = definitions

    def list_tools(self) -> list[JsonObject]:
        """Return the deterministic tool catalog and strict input schemas."""
        tools: list[JsonObject] = []
        cache_writing_tools = {
            "download_document_file",
            "render_pdf_pages",
            "render_pdf_page_tiles",
        }
        for name in sorted(self._definitions):
            title, description, model, _ = self._definitions[name]
            raw_schema: object = model.model_json_schema()
            schema = require_json_object(raw_schema, context="tool input schema")
            # Pydantic emits titles that provide no protocol value and make tool
            # catalogs noisier. Class docstrings likewise describe Python model
            # internals rather than the tool. Preserve field-level descriptions
            # and constraints.
            _ = schema.pop("title", None)
            _ = schema.pop("description", None)
            tools.append(
                {
                    "name": name,
                    "title": title,
                    "description": description,
                    "inputSchema": schema,
                    "annotations": {
                        "readOnlyHint": name not in cache_writing_tools,
                        "destructiveHint": False,
                        "idempotentHint": name != "download_document_file",
                        "openWorldHint": name
                        in {
                            "search_documents",
                            "get_document_metadata",
                            "list_document_files",
                            "download_document_file",
                        },
                    },
                }
            )
        return tools

    def ensure_ready(self) -> None:
        """Fail readiness when the private PDF worker circuit is open."""
        if (
            validate_deployment_profile(self.config.deployment_profile)
            != "private-full"
        ):
            return
        from .pdf_executor import PdfWorkerUnavailableError  # noqa: PLC0415

        try:
            self.pdf.ensure_ready()
        except PdfWorkerUnavailableError as exc:
            raise AppError(
                ErrorCode.PDF_PROCESSING_FAILED,
                "The PDF worker is temporarily unavailable.",
                http_status=503,
            ) from exc

    async def call(self, name: str, arguments: JsonObject) -> JsonObject:
        """Validate arguments and invoke one advertised tool handler."""
        definition = self._definitions.get(name)
        if definition is None:
            raise AppError(
                ErrorCode.INVALID_INPUT, "The requested tool does not exist."
            )
        _, _, model, handler = definition
        try:
            parsed = model.model_validate(arguments)
        except ValidationError as exc:
            raw_errors: object = exc.errors(include_url=False, include_input=False)
            details = validation_details(raw_errors)
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Tool arguments did not match the declared schema.",
                safe_details={"validation": details},
            ) from exc
        return await handler(parsed)

    def list_resources(self) -> list[JsonObject]:
        """Return deterministic compatibility resource definitions."""
        return [
            {
                "uri": "nplg://about",
                "name": "NPLG DSpace MCP server information",
                "title": "NPLG DSpace MCP — usage and provenance",
                "description": _joined_text(
                    "Read-only server scope, visual-analysis rules, and",
                    "provenance requirements.",
                ),
                "mimeType": "application/json",
            }
        ]

    async def read_resource(self, uri: str) -> dict[str, str]:
        """Read one bounded compatibility resource by URI."""
        if uri == "nplg://about":
            payload: JsonObject = {
                "name": "nplg-dspace-mcp",
                "read_only": True,
                "upstream": self.config.nplg_base_url,
                "visual_analysis": {
                    "ocr_is_not_authoritative": True,
                    "page_images": "native embedded-scan grid when determinable",
                    "fallback": "400 DPI, explicitly labelled",
                    "tiles": {
                        "width": self.config.tile_width,
                        "height": self.config.tile_height,
                        "overlap": self.config.tile_overlap,
                        "resize": False,
                    },
                },
            }
            return {
                "uri": uri,
                "mime_type": "application/json",
                "text": json.dumps(payload, ensure_ascii=False, sort_keys=True),
            }

        if self._profile != "private-full":
            raise AppError(
                ErrorCode.NOT_FOUND,
                "The requested MCP resource was not found.",
                http_status=404,
            )

        document_match = re.fullmatch(r"nplg://artifact/(doc_[0-9a-f]{64})", uri)
        if document_match:
            artifact_id = uri.removeprefix("nplg://artifact/")
            path = self._resolve_document(artifact_id)
            payload = {
                "artifact_id": artifact_id,
                "sha256": artifact_id.removeprefix("doc_"),
                "asset_url": self._signed_asset_url(
                    path.relative_to(self.store.root).as_posix(),
                    "application/pdf",
                ),
            }
            return {
                "uri": uri,
                "mime_type": "application/json",
                "text": json.dumps(payload, sort_keys=True),
            }

        render_match = re.fullmatch(r"nplg://render/(rnd_[0-9a-f]{32})/manifest", uri)
        if render_match:
            render_id = uri.removeprefix("nplg://render/").removesuffix("/manifest")
            payload = await self._get_render_manifest(
                RenderIdInput(render_id=render_id)
            )
            return {
                "uri": uri,
                "mime_type": "application/json",
                "text": json.dumps(payload, ensure_ascii=False, sort_keys=True),
            }
        raise AppError(
            ErrorCode.NOT_FOUND,
            "The requested MCP resource was not found.",
            http_status=404,
        )

    def _signed_asset_url(self, relative_path: str, media_type: str) -> str:
        now = self._utc_now()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            msg = "ToolService UTC clock must return a timezone-aware UTC value"
            raise ValueError(msg)
        token = sign_asset_token(
            self.config.asset_signing_secret,
            path=relative_path,
            media_type=media_type,
            expires_at=now + timedelta(seconds=self.config.asset_ttl_seconds),
        )
        return f"{self.config.public_base_url}/assets/{token}"

    def _resolve_document(self, artifact_id: str) -> Path:
        if not _DOCUMENT_ID_RE.fullmatch(artifact_id):
            raise AppError(
                ErrorCode.INVALID_INPUT, "Document artifact identifier is invalid."
            )
        return self.store.resolve_asset(f"documents/{artifact_id}/source.pdf")

    def _manifest_dict(self, manifest: RenderPagesOutput) -> JsonObject:
        payload = _model_json(manifest, context="render manifest")
        pages_value = payload.get("pages")
        if not isinstance(pages_value, list):
            msg = "render manifest pages must be an array"
            raise TypeError(msg)
        for page_value in pages_value:
            page = require_json_object(page_value, context="rendered page")
            page["asset_url"] = self._signed_asset_url(
                _json_string(page.get("relative_path"), context="relative_path"),
                _json_string(page.get("media_type"), context="media_type"),
            )
            render_id = _json_string(payload.get("render_id"), context="render_id")
            page_number = _json_integer(
                page.get("page_number"),
                context="page_number",
            )
            page["resource_uri"] = f"nplg://render/{render_id}/page/{page_number}"
        payload["manifest_asset_url"] = self._signed_asset_url(
            _json_string(
                payload.get("manifest_relative_path"),
                context="manifest_relative_path",
            ),
            "application/json",
        )
        render_id = _json_string(payload.get("render_id"), context="render_id")
        payload["resource_uri"] = f"nplg://render/{render_id}/manifest"
        return payload

    async def _search(self, parsed: BaseModel) -> JsonObject:
        values = SearchDocumentsInput.model_validate(parsed)
        page = await self.repository.search(
            values.query,
            cursor=values.cursor,
            page_size=values.page_size,
            scope_handle=values.scope_handle,
        )
        return dataclass_to_json(page, context="search page")

    async def _get_metadata(self, parsed: BaseModel) -> JsonObject:
        values = HandleInput.model_validate(parsed)
        return dataclass_to_json(
            await self.repository.get_metadata(values.handle),
            context="document metadata",
        )

    async def _list_files(self, parsed: BaseModel) -> JsonObject:
        values = HandleInput.model_validate(parsed)
        files = await self.repository.list_files(values.handle)
        return {
            "handle": values.handle,
            "files": [dataclass_to_json(item, context="bitstream") for item in files],
        }

    async def _download_document(self, parsed: BaseModel) -> JsonObject:
        values = DownloadDocumentInput.model_validate(parsed)
        files = await self.repository.list_files(values.handle)
        bitstream = next(
            (item for item in files if item.bitstream_id == values.bitstream_id), None
        )
        if bitstream is None:
            raise AppError(
                ErrorCode.NOT_FOUND,
                "The requested bitstream was not discovered on this item page.",
                http_status=404,
            )
        result = await self.downloader.download(bitstream)
        artifact = result.artifact
        return {
            "artifact_id": artifact.object_id,
            "sha256": artifact.sha256,
            "size": artifact.size,
            "media_type": artifact.media_type,
            "relative_path": artifact.relative_path,
            "asset_url": self._signed_asset_url(
                artifact.relative_path, artifact.media_type
            ),
            "resource_uri": f"nplg://artifact/{artifact.object_id}",
            "source_bitstream_id": result.source_bitstream_id,
            "source_url": result.source_url,
            "bytes_downloaded": result.bytes_downloaded,
        }

    async def _run_pdf_job(
        self,
        command: PdfCommand,
    ) -> PdfSuccess:
        from .pdf_executor import (  # noqa: PLC0415
            MonotonicDeadline,
            PdfWorkerError,
            PdfWorkerUnavailableError,
        )
        from .pdf_ipc import PdfFailure  # noqa: PLC0415

        deadline = MonotonicDeadline.after(_PDF_JOB_TIMEOUT_SECONDS)
        acquired = False
        try:
            try:
                async with asyncio.timeout(deadline.remaining()):
                    _ = await self._pdf_jobs.acquire()
            except TimeoutError as exc:
                raise AppError(
                    ErrorCode.PDF_PROCESSING_FAILED,
                    "The PDF worker is temporarily unavailable.",
                    http_status=503,
                ) from exc
            acquired = True
            result = await self.pdf.execute(
                command,
                deadline=deadline,
            )
        except PdfWorkerUnavailableError as exc:
            raise AppError(
                ErrorCode.PDF_PROCESSING_FAILED,
                "The PDF worker is temporarily unavailable.",
                http_status=503,
            ) from exc
        except PdfWorkerError as exc:
            raise AppError(
                ErrorCode.PDF_PROCESSING_FAILED,
                "The PDF operation could not be completed safely.",
                http_status=422,
            ) from exc
        finally:
            if acquired:
                self._pdf_jobs.release()
        if isinstance(result, PdfFailure):
            raise AppError(result.payload.code, result.payload.message)
        return result

    @staticmethod
    def _document_relative_path(artifact_id: str) -> str:
        return f"documents/{artifact_id}/source.pdf"

    async def _inspect_pdf(self, parsed: BaseModel) -> JsonObject:
        from .pdf_executor import PdfWorkerError  # noqa: PLC0415
        from .pdf_ipc import (  # noqa: PLC0415
            InspectCommand,
            InspectParams,
            InspectPayload,
        )

        values = ArtifactInput.model_validate(parsed)
        _ = self._resolve_document(values.artifact_id)
        result = await self._run_pdf_job(
            InspectCommand(
                request_id=uuid4(),
                operation="inspect",
                source_relative_path=self._document_relative_path(values.artifact_id),
                parameters=InspectParams(),
            )
        )
        if not isinstance(result.payload, InspectPayload):
            message = "PDF worker returned an unexpected inspect payload"
            raise PdfWorkerError(message)
        payload = _model_json(result.payload.value, context="PDF inspection")
        payload["artifact_id"] = values.artifact_id
        payload["resource_uri"] = f"nplg://artifact/{values.artifact_id}"
        return payload

    async def _render_pages(self, parsed: BaseModel) -> JsonObject:
        from .pdf_executor import PdfWorkerError  # noqa: PLC0415
        from .pdf_ipc import (  # noqa: PLC0415
            RenderPagesCommand,
            RenderPagesParams,
            RenderPagesPayload,
        )

        values = RenderPagesInput.model_validate(parsed)
        _ = self._resolve_document(values.artifact_id)
        result = await self._run_pdf_job(
            RenderPagesCommand(
                request_id=uuid4(),
                operation="render_pages",
                source_relative_path=self._document_relative_path(values.artifact_id),
                parameters=RenderPagesParams(
                    pages=tuple(values.pages),
                    mode="native",
                ),
            )
        )
        if not isinstance(result.payload, RenderPagesPayload):
            message = "PDF worker returned an unexpected render payload"
            raise PdfWorkerError(message)
        payload = self._manifest_dict(result.payload.value)
        payload["artifact_id"] = values.artifact_id
        return payload

    async def _render_tiles(self, parsed: BaseModel) -> JsonObject:
        from .pdf_executor import PdfWorkerError  # noqa: PLC0415
        from .pdf_ipc import (  # noqa: PLC0415
            RenderTilesCommand,
            RenderTilesParams,
            RenderTilesPayload,
        )

        values = RenderTilesInput.model_validate(parsed)
        result = await self._run_pdf_job(
            RenderTilesCommand(
                request_id=uuid4(),
                operation="render_tiles",
                parameters=RenderTilesParams(
                    render_id=values.render_id,
                    page_number=values.page_number,
                    tile_width=values.tile_width,
                    tile_height=values.tile_height,
                    overlap=values.overlap,
                ),
            )
        )
        if not isinstance(result.payload, RenderTilesPayload):
            message = "PDF worker returned an unexpected tile payload"
            raise PdfWorkerError(message)
        payload = _model_json(result.payload.value, context="tile manifest")
        tiles_value = payload.get("tiles")
        if not isinstance(tiles_value, list):
            msg = "tile manifest tiles must be an array"
            raise TypeError(msg)
        for tile_value in tiles_value:
            tile = require_json_object(tile_value, context="rendered tile")
            tile["asset_url"] = self._signed_asset_url(
                _json_string(tile.get("relative_path"), context="relative_path"),
                _json_string(tile.get("media_type"), context="media_type"),
            )
            tile_id = _json_string(tile.get("tile_id"), context="tile_id")
            page_uri = f"nplg://render/{values.render_id}/page/{values.page_number}"
            tile["resource_uri"] = f"{page_uri}/tile/{tile_id}"
        payload["manifest_asset_url"] = self._signed_asset_url(
            _json_string(
                payload.get("manifest_relative_path"),
                context="manifest_relative_path",
            ),
            "application/json",
        )
        geometry_key = (
            f"w{_json_integer(payload.get('tile_width'), context='tile_width'):04d}"
            f"-h{_json_integer(payload.get('tile_height'), context='tile_height'):04d}"
            f"-o{_json_integer(payload.get('overlap'), context='overlap'):03d}"
        )
        payload["resource_uri"] = (
            f"nplg://render/{values.render_id}/page/{values.page_number}/tiles/{geometry_key}"
        )
        return payload

    async def _get_render_manifest(self, parsed: BaseModel) -> JsonObject:
        from .pdf_executor import PdfWorkerError  # noqa: PLC0415
        from .pdf_ipc import (  # noqa: PLC0415
            ManifestCommand,
            ManifestParams,
            ManifestPayload,
        )

        values = RenderIdInput.model_validate(parsed)
        result = await self._run_pdf_job(
            ManifestCommand(
                request_id=uuid4(),
                operation="manifest",
                parameters=ManifestParams(render_id=values.render_id),
            )
        )
        if not isinstance(result.payload, ManifestPayload):
            message = "PDF worker returned an unexpected manifest payload"
            raise PdfWorkerError(message)
        return self._manifest_dict(result.payload.value)
