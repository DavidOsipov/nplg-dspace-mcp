from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .config import HARD_MAX_TILE_DIMENSION, HARD_MAX_TILE_OVERLAP, AppConfig
from .downloader import DocumentDownloader
from .errors import AppError, ErrorCode
from .pdf import PdfProcessor
from .repository import NplgRepository
from .storage import ContentAddressedStore
from .tokens import sign_asset_token

_DOCUMENT_ID_RE = re.compile(r"^doc_[0-9a-f]{64}$")
_RENDER_ID_RE = re.compile(r"^rnd_[0-9a-f]{32}$")


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SearchDocumentsInput(StrictInput):
    query: str = Field(min_length=1, max_length=500)
    cursor: str | None = Field(default=None, max_length=128)
    page_size: int = Field(default=20, ge=1, le=50)
    scope_handle: str | None = Field(default=None, max_length=128)

    @field_validator("query")
    @classmethod
    def non_blank_query(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("query must contain non-whitespace characters")
        return normalized


class HandleInput(StrictInput):
    handle: str = Field(min_length=3, max_length=128)


class DownloadDocumentInput(HandleInput):
    bitstream_id: str = Field(min_length=1, max_length=128)


class ArtifactInput(StrictInput):
    artifact_id: str = Field(pattern=r"^doc_[0-9a-f]{64}$")


class RenderPagesInput(ArtifactInput):
    pages: list[int] = Field(min_length=1, max_length=8)
    mode: str = Field(default="native", pattern=r"^native$")


class RenderTilesInput(StrictInput):
    render_id: str = Field(pattern=r"^rnd_[0-9a-f]{32}$")
    page_number: int = Field(ge=1)
    tile_width: int | None = Field(default=None, ge=256, le=HARD_MAX_TILE_DIMENSION)
    tile_height: int | None = Field(default=None, ge=256, le=HARD_MAX_TILE_DIMENSION)
    overlap: int | None = Field(default=None, ge=0, le=HARD_MAX_TILE_OVERLAP)

    @field_validator("overlap")
    @classmethod
    def overlap_must_fit_explicit_geometry(cls, value: int | None, info):  # type: ignore[no-untyped-def]
        if value is None:
            return value
        width = info.data.get("tile_width")
        height = info.data.get("tile_height")
        if width is not None and value >= width:
            raise ValueError("overlap must be smaller than tile_width")
        if height is not None and value >= height:
            raise ValueError("overlap must be smaller than tile_height")
        return value


class RenderIdInput(StrictInput):
    render_id: str = Field(pattern=r"^rnd_[0-9a-f]{32}$")


class RepositoryProtocol(Protocol):
    async def search(self, query: str, *, cursor: str | None = None, page_size: int = 20, scope_handle: str | None = None): ...
    async def get_metadata(self, handle: str): ...
    async def list_files(self, handle: str): ...


class DownloaderProtocol(Protocol):
    async def download(self, bitstream): ...


class PdfProtocol(Protocol):
    def inspect(self, pdf_path: Path): ...
    def render_pages(self, pdf_path: Path, *, pages: tuple[int, ...], mode: str): ...
    def render_tiles(self, render_id: str, *, page_number: int, tile_width: int | None = None, tile_height: int | None = None, overlap: int | None = None): ...
    def get_manifest(self, render_id: str): ...
    def delete_render(self, render_id: str) -> bool: ...


Handler = Callable[[BaseModel], Awaitable[dict[str, Any]]]


class ToolService:
    """Validated, stateless orchestration layer exposed through MCP tools."""

    def __init__(
        self,
        *,
        repository: RepositoryProtocol | NplgRepository,
        downloader: DownloaderProtocol | DocumentDownloader,
        pdf: PdfProtocol | PdfProcessor,
        store: ContentAddressedStore,
        config: AppConfig,
    ) -> None:
        self.repository = repository
        self.downloader = downloader
        self.pdf = pdf
        self.store = store
        self.config = config
        self._pdf_jobs = asyncio.Semaphore(config.max_concurrent_pdf_jobs)
        self._pdf_worker_tasks: set[asyncio.Task[Any]] = set()
        self._definitions: dict[str, tuple[str, str, type[StrictInput], Handler]] = {
            "download_document_file": (
                "Download a public PDF",
                "Download a PDF bitstream previously discovered on the requested NPLG item page. Arbitrary URLs are not accepted.",
                DownloadDocumentInput,
                self._download_document,
            ),
            "get_document_metadata": (
                "Read full document metadata",
                "Read rich Dublin Core metadata for an NPLG item, preferring OAI-DIM and falling back to the full XMLUI/Manakin record.",
                HandleInput,
                self._get_metadata,
            ),
            "get_render_manifest": (
                "Read a render manifest",
                "Read deterministic page-render metadata and signed image URLs for an existing render identifier.",
                RenderIdInput,
                self._get_render_manifest,
            ),
            "inspect_pdf": (
                "Inspect a downloaded PDF",
                "Classify every PDF page and report embedded scan dimensions, effective DPI, crop, rotation, and text-overlay characteristics.",
                ArtifactInput,
                self._inspect_pdf,
            ),
            "list_document_files": (
                "List document files",
                "List public or restricted bitstreams bound to a canonical NPLG item handle.",
                HandleInput,
                self._list_files,
            ),
            "render_pdf_page_tiles": (
                "Create crop-only page tiles",
                "Crop a rendered page into overlapping JPEG tiles without resizing. Defaults are 2048×2048 with 128-pixel overlap.",
                RenderTilesInput,
                self._render_tiles,
            ),
            "render_pdf_pages": (
                "Render PDF pages as JPEG",
                "Render selected pages on their native embedded-scan pixel grid when determinable; otherwise use an explicitly labelled 400-DPI fallback.",
                RenderPagesInput,
                self._render_pages,
            ),
            "search_documents": (
                "Search NPLG Iverieli",
                "Search the NPLG DSpace repository, optionally within a canonical collection handle, and return an opaque continuation cursor.",
                SearchDocumentsInput,
                self._search,
            ),
        }

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cache_writing_tools = {"download_document_file", "render_pdf_pages", "render_pdf_page_tiles"}
        for name in sorted(self._definitions):
            title, description, model, _ = self._definitions[name]
            schema = model.model_json_schema()
            # Pydantic emits titles that provide no protocol value and make tool
            # catalogs noisier. Preserve property descriptions and constraints.
            schema.pop("title", None)
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
                        "openWorldHint": name in {
                            "search_documents",
                            "get_document_metadata",
                            "list_document_files",
                            "download_document_file",
                        },
                    },
                }
            )
        return tools

    async def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        definition = self._definitions.get(name)
        if definition is None:
            raise AppError(ErrorCode.INVALID_INPUT, "The requested tool does not exist.")
        if not isinstance(arguments, dict):
            raise AppError(ErrorCode.INVALID_INPUT, "Tool arguments must be a JSON object.")
        _, _, model, handler = definition
        try:
            parsed = model.model_validate(arguments)
        except ValidationError as exc:
            details = [
                {
                    "location": ".".join(str(part) for part in error["loc"]),
                    "message": error["msg"],
                    "type": error["type"],
                }
                for error in exc.errors(include_url=False, include_input=False)
            ]
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Tool arguments did not match the declared schema.",
                safe_details={"validation": details},
            ) from exc
        return await handler(parsed)

    def list_resources(self) -> list[dict[str, Any]]:
        return [
            {
                "uri": "nplg://about",
                "name": "NPLG DSpace MCP server information",
                "title": "NPLG DSpace MCP — usage and provenance",
                "description": "Read-only server scope, visual-analysis rules, and provenance requirements.",
                "mimeType": "application/json",
            }
        ]

    async def read_resource(self, uri: str) -> dict[str, str]:
        if uri == "nplg://about":
            payload = {
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

        document_match = re.fullmatch(r"nplg://artifact/(doc_[0-9a-f]{64})", uri)
        if document_match:
            artifact_id = document_match.group(1)
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
            payload = await self._get_render_manifest(RenderIdInput(render_id=render_match.group(1)))
            return {
                "uri": uri,
                "mime_type": "application/json",
                "text": json.dumps(payload, ensure_ascii=False, sort_keys=True),
            }
        raise AppError(ErrorCode.NOT_FOUND, "The requested MCP resource was not found.", http_status=404)

    def _signed_asset_url(self, relative_path: str, media_type: str) -> str:
        token = sign_asset_token(
            self.config.asset_signing_secret,
            path=relative_path,
            media_type=media_type,
            expires_at=datetime.now(UTC) + timedelta(seconds=self.config.asset_ttl_seconds),
        )
        return f"{self.config.public_base_url}/assets/{token}"

    def _resolve_document(self, artifact_id: str) -> Path:
        if not _DOCUMENT_ID_RE.fullmatch(artifact_id):
            raise AppError(ErrorCode.INVALID_INPUT, "Document artifact identifier is invalid.")
        return self.store.resolve_asset(f"documents/{artifact_id}/source.pdf")

    def _manifest_dict(self, manifest: Any) -> dict[str, Any]:
        payload = asdict(manifest)
        for page in payload.get("pages", []):
            page["asset_url"] = self._signed_asset_url(page["relative_path"], page["media_type"])
            page["resource_uri"] = f"nplg://render/{payload['render_id']}/page/{page['page_number']}"
        if "manifest_relative_path" in payload:
            payload["manifest_asset_url"] = self._signed_asset_url(payload["manifest_relative_path"], "application/json")
        payload["resource_uri"] = f"nplg://render/{payload['render_id']}/manifest"
        return payload

    async def _search(self, parsed: BaseModel) -> dict[str, Any]:
        values = SearchDocumentsInput.model_validate(parsed)
        page = await self.repository.search(
            values.query,
            cursor=values.cursor,
            page_size=values.page_size,
            scope_handle=values.scope_handle,
        )
        return asdict(page)

    async def _get_metadata(self, parsed: BaseModel) -> dict[str, Any]:
        values = HandleInput.model_validate(parsed)
        return asdict(await self.repository.get_metadata(values.handle))

    async def _list_files(self, parsed: BaseModel) -> dict[str, Any]:
        values = HandleInput.model_validate(parsed)
        files = await self.repository.list_files(values.handle)
        return {"handle": values.handle, "files": [asdict(item) for item in files]}

    async def _download_document(self, parsed: BaseModel) -> dict[str, Any]:
        values = DownloadDocumentInput.model_validate(parsed)
        files = await self.repository.list_files(values.handle)
        bitstream = next((item for item in files if item.bitstream_id == values.bitstream_id), None)
        if bitstream is None:
            raise AppError(ErrorCode.NOT_FOUND, "The requested bitstream was not discovered on this item page.", http_status=404)
        result = await self.downloader.download(bitstream)
        artifact = result.artifact
        return {
            "artifact_id": artifact.object_id,
            "sha256": artifact.sha256,
            "size": artifact.size,
            "media_type": artifact.media_type,
            "relative_path": artifact.relative_path,
            "asset_url": self._signed_asset_url(artifact.relative_path, artifact.media_type),
            "resource_uri": f"nplg://artifact/{artifact.object_id}",
            "source_bitstream_id": result.source_bitstream_id,
            "source_url": result.source_url,
            "bytes_downloaded": result.bytes_downloaded,
        }

    async def _run_pdf_job(self, function: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        await self._pdf_jobs.acquire()
        try:
            worker = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
        except BaseException:
            self._pdf_jobs.release()
            raise

        self._pdf_worker_tasks.add(worker)

        def finish(completed: asyncio.Task[Any]) -> None:
            self._pdf_worker_tasks.discard(completed)
            self._pdf_jobs.release()
            if not completed.cancelled():
                completed.exception()

        worker.add_done_callback(finish)
        return await asyncio.shield(worker)

    async def _inspect_pdf(self, parsed: BaseModel) -> dict[str, Any]:
        values = ArtifactInput.model_validate(parsed)
        path = self._resolve_document(values.artifact_id)
        inspection = await self._run_pdf_job(self.pdf.inspect, path)
        payload = asdict(inspection)
        payload["artifact_id"] = values.artifact_id
        payload["resource_uri"] = f"nplg://artifact/{values.artifact_id}"
        return payload

    async def _render_pages(self, parsed: BaseModel) -> dict[str, Any]:
        values = RenderPagesInput.model_validate(parsed)
        path = self._resolve_document(values.artifact_id)
        manifest = await self._run_pdf_job(
            self.pdf.render_pages,
            path,
            pages=tuple(values.pages),
            mode=values.mode,
        )
        payload = self._manifest_dict(manifest)
        payload["artifact_id"] = values.artifact_id
        return payload

    async def _render_tiles(self, parsed: BaseModel) -> dict[str, Any]:
        values = RenderTilesInput.model_validate(parsed)
        manifest = await self._run_pdf_job(
            self.pdf.render_tiles,
            values.render_id,
            page_number=values.page_number,
            tile_width=values.tile_width,
            tile_height=values.tile_height,
            overlap=values.overlap,
        )
        payload = asdict(manifest)
        for tile in payload["tiles"]:
            tile["asset_url"] = self._signed_asset_url(tile["relative_path"], tile["media_type"])
            tile["resource_uri"] = (
                f"nplg://render/{values.render_id}/page/{values.page_number}/tile/{tile['tile_id']}"
            )
        payload["manifest_asset_url"] = self._signed_asset_url(payload["manifest_relative_path"], "application/json")
        geometry_key = f"w{payload['tile_width']:04d}-h{payload['tile_height']:04d}-o{payload['overlap']:03d}"
        payload["resource_uri"] = f"nplg://render/{values.render_id}/page/{values.page_number}/tiles/{geometry_key}"
        return payload

    async def _get_render_manifest(self, parsed: BaseModel) -> dict[str, Any]:
        values = RenderIdInput.model_validate(parsed)
        manifest = await self._run_pdf_job(self.pdf.get_manifest, values.render_id)
        return self._manifest_dict(manifest)
