# Copyright (c) 2026 David Osipov
"""Typed service layer for the NPLG MCP tool operations."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast
from uuid import uuid4

from pydantic import Field, StringConstraints, ValidationError

from .config import (
    HARD_MAX_INLINE_RESOURCE_BYTES,
    HARD_MAX_RENDER_PAGES,
    HARD_MAX_TILES_PER_PAGE,
    AppConfig,
    validate_deployment_profile,
)
from .contracts import (
    ArtifactInput,
    DeploymentProfile,
    DocumentFilesOutput,
    DocumentMetadataOutput,
    DownloadDocumentInput,
    DownloadDocumentOutput,
    HandleInput,
    MonotonicDeadline,
    PdfInspectionOutput,
    RegisteredTool,
    RenderIdInput,
    RenderManifestOutput,
    RenderPagesInput,
    RenderPagesOutput,
    RenderTilesInput,
    RenderTilesOutput,
    SearchDocumentsInput,
    SearchDocumentsOutput,
    StrictModel,
    StrictOutput,
    ToolAnnotations,
    ToolCatalog,
    ToolDefinition,
)
from .errors import AppError, ErrorCode
from .json_types import (
    JsonObject,
    dataclass_to_json,
    load_json_value,
    require_json_object,
)
from .pdf_postprocessing import (
    MAX_RENDER_RESOURCE_INDEX_BYTES,
    PdfPostprocessingReservationAuthority,
)
from .profiles import tool_names_for_profile
from .tokens import sign_asset_token

if TYPE_CHECKING:
    from pathlib import Path

    from pydantic import BaseModel

    from .downloader import DownloadResult
    from .parsers import Bitstream, DocumentRecord, SearchPage
    from .pdf_executor import PdfExecutor
    from .pdf_ipc import (
        PdfCommand,
        PdfSuccess,
    )
    from .pdf_ipc import (
        RenderPagesOutput as PdfRenderPagesOutput,
    )
    from .storage import ContentAddressedStore

_DOCUMENT_ID_RE = re.compile(r"^doc_[0-9a-f]{64}$")
_RENDER_ID_RE = re.compile(r"^rnd_[0-9a-f]{32}$")
_PDF_JOB_TIMEOUT_SECONDS = 35.0
_MAX_RENDER_RESOURCE_SCAN_DIRECTORIES = 4096
_PRIVATE_RESOURCE_FILE_MODE = 0o600
_RESOURCE_READ_CHUNK_BYTES = 64 * 1024
_METADATA_PROFILES = frozenset(
    {
        DeploymentProfile.ALPIC_METADATA,
        DeploymentProfile.PRIVATE_FULL,
        DeploymentProfile.DISTRIBUTED_FULL,
    }
)
_FULL_PROFILES = frozenset(
    {
        DeploymentProfile.PRIVATE_FULL,
        DeploymentProfile.DISTRIBUTED_FULL,
    }
)
_CACHE_WRITING_TOOLS = frozenset(
    {
        "download_document_file",
        "render_pdf_page_tiles",
        "render_pdf_pages",
    }
)
_OPEN_WORLD_TOOLS = frozenset(
    {
        "download_document_file",
        "get_document_metadata",
        "list_document_files",
        "search_documents",
    }
)
_TOOL_TITLES = {
    "download_document_file": "Download a public PDF",
    "get_document_metadata": "Read full document metadata",
    "get_render_manifest": "Read a render manifest",
    "inspect_pdf": "Inspect a downloaded PDF",
    "list_document_files": "List document files",
    "render_pdf_page_tiles": "Create crop-only page tiles",
    "render_pdf_pages": "Render PDF pages as JPEG",
    "search_documents": "Search NPLG Iverieli",
}
_PRIVATE_PDF_PIPELINE_VERSION_FIELDS = (
    "manifest_schema_version",
    "render_pipeline_version",
    "classification_algorithm_version",
    "tile_pipeline_version",
)


def _tool_annotations(name: str) -> ToolAnnotations:
    """Return the closed reviewed annotations for one known tool name."""
    return ToolAnnotations(
        read_only_hint=name not in _CACHE_WRITING_TOOLS,
        destructive_hint=False,
        idempotent_hint=name != "download_document_file",
        open_world_hint=name in _OPEN_WORLD_TOOLS,
    )


def _tool_title(name: str) -> str:
    """Return the single reviewed human-readable title for a known tool."""
    title = _TOOL_TITLES.get(name)
    if title is None:
        message = "tool title is unavailable"
        raise ValueError(message)
    return title


def _json_string(value: object, *, context: str) -> str:
    if not isinstance(value, str):
        msg = f"{context} must be a string"
        raise TypeError(msg)
    return value


def _model_json(value: BaseModel, *, context: str) -> JsonObject:
    """Serialize one validated Pydantic model and recheck its JSON shape."""
    return require_json_object(
        load_json_value(value.model_dump_json()),
        context=context,
    )


def _remove_private_pdf_pipeline_versions(payload: JsonObject) -> None:
    """Remove worker cache identities from the unchanged public tool contract."""
    for field in _PRIVATE_PDF_PIPELINE_VERSION_FIELDS:
        _ = payload.pop(field, None)


def _public_model_schema(
    model: type[StrictModel],
    *,
    context: str,
    mode: Literal["validation", "serialization"],
) -> JsonObject:
    """Return one closed public model schema without presentation-only headings."""
    raw_schema: object = model.model_json_schema(mode=mode)
    schema = require_json_object(raw_schema, context=context)
    _ = schema.pop("title", None)
    _ = schema.pop("description", None)
    return schema


def _frozen_protocol_input_schema(name: str, schema: JsonObject) -> JsonObject:
    """Project the strict model schema onto the frozen pre-SDK wire contract."""
    if name != "search_documents":
        return schema

    properties_value = schema.get("properties")
    if type(properties_value) is not dict:
        msg = "search input schema properties are malformed"
        raise TypeError(msg)
    properties = properties_value

    query_value = properties.get("query")
    if type(query_value) is not dict:
        msg = "search query schema is malformed"
        raise TypeError(msg)
    query = query_value
    if type(query.pop("pattern", None)) is not str:
        msg = "search query schema lacks the strict text pattern"
        raise ValueError(msg)

    cursor_value = properties.get("cursor")
    if type(cursor_value) is not dict:
        msg = "search cursor schema is malformed"
        raise TypeError(msg)
    cursor = cursor_value
    alternatives_value = cursor.get("anyOf")
    if (
        type(alternatives_value) is not list
        or not alternatives_value
        or type(alternatives_value[0]) is not dict
    ):
        msg = "search cursor alternatives are malformed"
        raise TypeError(msg)
    string_alternative = alternatives_value[0]
    if type(string_alternative.pop("minLength", None)) is not int:
        msg = "search cursor schema lacks the strict minimum length"
        raise ValueError(msg)
    if type(string_alternative.pop("pattern", None)) is not str:
        msg = "search cursor schema lacks the strict text pattern"
        raise ValueError(msg)
    return schema


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


UtcClock = Callable[[], datetime]
MonotonicClock = Callable[[], float]


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


def _validated_pdf_worker_capacity(executor: object, capacity: object) -> int:
    if type(executor) is not str or executor not in {"serialized", "unix-worker"}:
        msg = "PDF_EXECUTOR must be serialized or unix-worker"
        raise ValueError(msg)
    if type(capacity) is not int or capacity != 1:
        msg = "MAX_CONCURRENT_PDF_JOBS must equal 1 for PDF_EXECUTOR"
        raise ValueError(msg)
    return capacity


def _joined_text(*parts: str) -> str:
    return " ".join(parts)


def _resource_file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _inline_resource_too_large() -> AppError:
    return AppError(
        ErrorCode.DOWNLOAD_TOO_LARGE,
        "The requested resource exceeds the bounded inline delivery limit.",
        http_status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
    )


def _resource_integrity_failure() -> AppError:
    return AppError(
        ErrorCode.INTERNAL_ERROR,
        "Stored artifact integrity verification failed.",
        http_status=HTTPStatus.INTERNAL_SERVER_ERROR,
    )


def _validate_inline_resource_metadata(
    metadata: os.stat_result,
    *,
    expected_size: int | None,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_RESOURCE_FILE_MODE
    ):
        raise _resource_integrity_failure()
    if metadata.st_size > HARD_MAX_INLINE_RESOURCE_BYTES:
        raise _inline_resource_too_large()
    if metadata.st_size < 1 or (
        expected_size is not None and metadata.st_size != expected_size
    ):
        raise _resource_integrity_failure()


def _read_exact_resource_descriptor(descriptor: int, *, size: int) -> bytes:
    content = bytearray()
    while len(content) < size:
        remaining = size - len(content)
        chunk = os.read(descriptor, min(remaining, _RESOURCE_READ_CHUNK_BYTES))
        if not chunk or len(chunk) > remaining:
            raise _resource_integrity_failure()
        content.extend(chunk)
    if os.read(descriptor, 1):
        raise _resource_integrity_failure()
    return bytes(content)


def _secure_resource_open_flags() -> int:
    try:
        required = (os.O_CLOEXEC, os.O_NOFOLLOW, os.O_NONBLOCK)
    except AttributeError as exc:
        raise _resource_integrity_failure() from exc
    if any(type(flag) is not int for flag in required):
        raise _resource_integrity_failure()
    close_on_exec, no_follow, nonblocking = required
    return os.O_RDONLY | close_on_exec | no_follow | nonblocking


def read_verified_inline_resource_file(
    path: Path,
    *,
    expected_size: int | None,
) -> bytes:
    """Read one exact private regular file through a non-following descriptor."""
    if expected_size is not None:
        if type(expected_size) is not int or expected_size < 1:
            raise _resource_integrity_failure()
        if expected_size > HARD_MAX_INLINE_RESOURCE_BYTES:
            raise _inline_resource_too_large()
    before = path.lstat()
    _validate_inline_resource_metadata(before, expected_size=expected_size)
    expected_identity = _resource_file_identity(before)
    descriptor = os.open(path, _secure_resource_open_flags())
    try:
        inheritable = False
        os.set_inheritable(descriptor, inheritable)
        opened = os.fstat(descriptor)
        _validate_inline_resource_metadata(opened, expected_size=expected_size)
        if _resource_file_identity(opened) != expected_identity:
            raise _resource_integrity_failure()
        content = _read_exact_resource_descriptor(
            descriptor,
            size=opened.st_size,
        )
        after_read = os.fstat(descriptor)
        after_name = path.lstat()
        if (
            os.get_inheritable(descriptor)
            or _resource_file_identity(after_read) != expected_identity
            or _resource_file_identity(after_name) != expected_identity
        ):
            raise _resource_integrity_failure()
    finally:
        os.close(descriptor)
    return content


@dataclass(frozen=True, slots=True)
class ToolServiceDependencies:
    """Immutable typed collaborators used by the tool service."""

    repository: RepositoryProtocol
    downloader: DownloaderProtocol | None = None
    pdf: PdfExecutor | None = None
    store: ContentAddressedStore | None = None


@dataclass(frozen=True, slots=True)
class _RegisteredArtifact:
    """One render-owned immutable binary addressable through an artifact URI."""

    relative_path: str
    sha256: str
    size: int
    media_type: Literal["application/json", "image/jpeg"]
    render_id: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class _LoadedArtifactIndex:
    owners: tuple[_RegisteredArtifact, ...]
    sha256: str


class _ArtifactIndexEntry(StrictModel):
    """One strict, bounded persisted authorization for a render artifact."""

    version: Literal[1]
    artifact_id: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^doc_[0-9a-f]{64}$"),
    ]
    relative_path: Annotated[
        str,
        StringConstraints(strict=True, min_length=1, max_length=1024),
    ]
    sha256: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"),
    ]
    size: Annotated[int, Field(strict=True, ge=1)]
    media_type: Literal["application/json", "image/jpeg"]
    render_id: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^rnd_[0-9a-f]{32}$"),
    ]
    expires_at: Annotated[int, Field(strict=True, ge=0)]


def _registered_artifact_sort_key(item: _RegisteredArtifact) -> tuple[str, str]:
    return item.render_id, item.relative_path


class ToolService:
    """Validated, stateless orchestration layer exposed through MCP tools."""

    def __init__(
        self,
        *,
        dependencies: ToolServiceDependencies,
        config: AppConfig,
        utc_now: UtcClock = _system_utc_now,
        monotonic_clock: MonotonicClock = time.monotonic,
    ) -> None:
        """Bind validated configuration and typed runtime collaborators."""
        super().__init__()
        self.repository = dependencies.repository
        self.config = config
        self._utc_now = utc_now
        self._monotonic_clock = monotonic_clock
        self._resource_artifacts: dict[str, tuple[_RegisteredArtifact, ...]] = {}
        profile = validate_deployment_profile(config.deployment_profile)
        self._profile = DeploymentProfile(profile)
        if profile == "alpic-metadata":
            self._catalog = ToolCatalog(
                (
                    ToolDefinition[HandleInput, DocumentMetadataOutput](
                        name="get_document_metadata",
                        title=_tool_title("get_document_metadata"),
                        description=_joined_text(
                            "Read rich Dublin Core metadata for an NPLG item,",
                            "preferring OAI-DIM and falling back to the full",
                            "XMLUI/Manakin record.",
                        ),
                        input_model=HandleInput,
                        output_model=DocumentMetadataOutput,
                        handler=self._get_metadata,
                        annotations=_tool_annotations("get_document_metadata"),
                        profiles=_METADATA_PROFILES,
                    ),
                    ToolDefinition[HandleInput, DocumentFilesOutput](
                        name="list_document_files",
                        title=_tool_title("list_document_files"),
                        description=_joined_text(
                            "List public or restricted bitstreams bound to a",
                            "canonical NPLG item handle.",
                        ),
                        input_model=HandleInput,
                        output_model=DocumentFilesOutput,
                        handler=self._list_files,
                        annotations=_tool_annotations("list_document_files"),
                        profiles=_METADATA_PROFILES,
                    ),
                    ToolDefinition[SearchDocumentsInput, SearchDocumentsOutput](
                        name="search_documents",
                        title=_tool_title("search_documents"),
                        description=_joined_text(
                            "Search the NPLG DSpace repository, optionally within",
                            "a canonical collection handle, and return an opaque",
                            "continuation cursor.",
                        ),
                        input_model=SearchDocumentsInput,
                        output_model=SearchDocumentsOutput,
                        handler=self._search,
                        annotations=_tool_annotations("search_documents"),
                        profiles=_METADATA_PROFILES,
                    ),
                )
            )
            self._ensure_profile_catalog()
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
        max_concurrent_pdf_jobs = _validated_pdf_worker_capacity(
            config.pdf_executor,
            config.max_concurrent_pdf_jobs,
        )
        self.downloader = downloader
        self.pdf = pdf
        self._pdf_postprocessing_reservation = (
            pdf if isinstance(pdf, PdfPostprocessingReservationAuthority) else None
        )
        self.store = store
        self._pdf_jobs = asyncio.Semaphore(max_concurrent_pdf_jobs)
        definitions: tuple[RegisteredTool, ...] = (
            ToolDefinition[DownloadDocumentInput, DownloadDocumentOutput](
                name="download_document_file",
                title=_tool_title("download_document_file"),
                description=_joined_text(
                    "Download a PDF bitstream previously discovered on the",
                    "requested NPLG item page. Arbitrary URLs are not accepted.",
                ),
                input_model=DownloadDocumentInput,
                output_model=DownloadDocumentOutput,
                handler=self._download_document,
                annotations=_tool_annotations("download_document_file"),
                profiles=_FULL_PROFILES,
            ),
            ToolDefinition[HandleInput, DocumentMetadataOutput](
                name="get_document_metadata",
                title=_tool_title("get_document_metadata"),
                description=_joined_text(
                    "Read rich Dublin Core metadata for an NPLG item, preferring",
                    "OAI-DIM and falling back to the full XMLUI/Manakin record.",
                ),
                input_model=HandleInput,
                output_model=DocumentMetadataOutput,
                handler=self._get_metadata,
                annotations=_tool_annotations("get_document_metadata"),
                profiles=_METADATA_PROFILES,
            ),
            ToolDefinition[RenderIdInput, RenderManifestOutput](
                name="get_render_manifest",
                title=_tool_title("get_render_manifest"),
                description=_joined_text(
                    "Read deterministic page-render metadata and signed image",
                    "URLs for an existing render identifier.",
                ),
                input_model=RenderIdInput,
                output_model=RenderManifestOutput,
                handler=self._get_render_manifest,
                annotations=_tool_annotations("get_render_manifest"),
                profiles=_FULL_PROFILES,
            ),
            ToolDefinition[ArtifactInput, PdfInspectionOutput](
                name="inspect_pdf",
                title=_tool_title("inspect_pdf"),
                description=_joined_text(
                    "Classify every PDF page and report embedded scan dimensions,",
                    "effective DPI, crop, rotation, and text-overlay characteristics.",
                ),
                input_model=ArtifactInput,
                output_model=PdfInspectionOutput,
                handler=self._inspect_pdf,
                annotations=_tool_annotations("inspect_pdf"),
                profiles=_FULL_PROFILES,
            ),
            ToolDefinition[HandleInput, DocumentFilesOutput](
                name="list_document_files",
                title=_tool_title("list_document_files"),
                description=_joined_text(
                    "List public or restricted bitstreams bound to a canonical",
                    "NPLG item handle.",
                ),
                input_model=HandleInput,
                output_model=DocumentFilesOutput,
                handler=self._list_files,
                annotations=_tool_annotations("list_document_files"),
                profiles=_METADATA_PROFILES,
            ),
            ToolDefinition[RenderTilesInput, RenderTilesOutput](
                name="render_pdf_page_tiles",
                title=_tool_title("render_pdf_page_tiles"),
                description=_joined_text(
                    "Crop a rendered page into overlapping JPEG tiles without",
                    "resizing. Defaults are 2048\N{MULTIPLICATION SIGN}2048 with",
                    "128-pixel overlap.",
                ),
                input_model=RenderTilesInput,
                output_model=RenderTilesOutput,
                handler=self._render_tiles,
                annotations=_tool_annotations("render_pdf_page_tiles"),
                profiles=_FULL_PROFILES,
            ),
            ToolDefinition[RenderPagesInput, RenderPagesOutput](
                name="render_pdf_pages",
                title=_tool_title("render_pdf_pages"),
                description=_joined_text(
                    "Render selected pages on their native embedded-scan pixel",
                    "grid when determinable; otherwise use an explicitly labelled",
                    "400-DPI fallback.",
                ),
                input_model=RenderPagesInput,
                output_model=RenderPagesOutput,
                handler=self._render_pages,
                annotations=_tool_annotations("render_pdf_pages"),
                profiles=_FULL_PROFILES,
            ),
            ToolDefinition[SearchDocumentsInput, SearchDocumentsOutput](
                name="search_documents",
                title=_tool_title("search_documents"),
                description=_joined_text(
                    "Search the NPLG DSpace repository, optionally within a",
                    "canonical collection handle, and return an opaque",
                    "continuation cursor.",
                ),
                input_model=SearchDocumentsInput,
                output_model=SearchDocumentsOutput,
                handler=self._search,
                annotations=_tool_annotations("search_documents"),
                profiles=_METADATA_PROFILES,
            ),
        )
        self._catalog = ToolCatalog(definitions)
        self._ensure_profile_catalog()

    def _ensure_profile_catalog(self) -> None:
        """Reject accidental profile widening or narrowing during composition."""
        actual = tuple(definition.name for definition in self._catalog.definitions)
        expected = tool_names_for_profile(self._profile)
        if actual != expected:
            message = "tool catalog does not match the deployment profile"
            raise ValueError(message)

    def list_tools(self) -> list[JsonObject]:
        """Return the deterministic catalog with closed input and output schemas."""
        tools: list[JsonObject] = []
        for definition in self._catalog.definitions:
            input_schema = _frozen_protocol_input_schema(
                definition.name,
                _public_model_schema(
                    definition.input_model,
                    context="tool input schema",
                    mode="validation",
                ),
            )
            output_schema = _public_model_schema(
                definition.output_model,
                context="tool output schema",
                mode="serialization",
            )
            tools.append(
                {
                    "name": definition.name,
                    "title": definition.title,
                    "description": definition.description,
                    "inputSchema": input_schema,
                    "outputSchema": output_schema,
                    "annotations": {
                        "title": definition.title,
                        "readOnlyHint": definition.annotations.read_only_hint,
                        "destructiveHint": definition.annotations.destructive_hint,
                        "idempotentHint": definition.annotations.idempotent_hint,
                        "openWorldHint": definition.annotations.open_world_hint,
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

        self.store.ensure_ready()
        try:
            self.pdf.ensure_ready()
        except PdfWorkerUnavailableError as exc:
            raise AppError(
                ErrorCode.PDF_PROCESSING_FAILED,
                "The PDF worker is temporarily unavailable.",
                http_status=503,
            ) from exc

    async def call(self, name: str, arguments: JsonObject) -> StrictOutput:
        """Strictly validate arguments and the selected handler's output."""
        return await self._catalog.call(name, arguments)

    def list_resources(self) -> list[JsonObject]:
        """Return resource definitions available to the active profile."""
        if self._profile is not DeploymentProfile.PRIVATE_FULL:
            return []
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

    def _utc_timestamp(self) -> int:
        now = self._utc_now()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            msg = "ToolService UTC clock must return a timezone-aware UTC value"
            raise ValueError(msg)
        return int(now.timestamp())

    @staticmethod
    def _resource_index_subtree(render_id: str, artifact_id: str) -> str:
        return f"renders/{render_id}/resources/{artifact_id}"

    @classmethod
    def _resource_index_relative_path(
        cls,
        render_id: str,
        artifact_id: str,
    ) -> str:
        return f"{cls._resource_index_subtree(render_id, artifact_id)}/index.json"

    @staticmethod
    def _validate_registered_artifact(entry: _ArtifactIndexEntry) -> None:
        relative_path = entry.relative_path
        invalid_path = (
            not relative_path.startswith(f"renders/{entry.render_id}/")
            or relative_path.startswith(f"renders/{entry.render_id}/resources/")
            or (entry.media_type == "image/jpeg" and not relative_path.endswith(".jpg"))
            or (
                entry.media_type == "application/json"
                and not relative_path.endswith("/manifest.json")
            )
        )
        if entry.artifact_id != f"doc_{entry.sha256}" or invalid_path:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact provenance is invalid.",
                http_status=500,
            )

    def _prune_resource_index(self, render_id: str, artifact_id: str) -> None:
        cached = self._resource_artifacts.get(artifact_id, ())
        retained = tuple(item for item in cached if item.render_id != render_id)
        if retained:
            self._resource_artifacts[artifact_id] = retained
        elif artifact_id in self._resource_artifacts:
            del self._resource_artifacts[artifact_id]
        _ = self.store.delete_render_subtree(
            self._resource_index_subtree(render_id, artifact_id)
        )

    @staticmethod
    def _require_bounded_resource_index(index_path: Path) -> None:
        metadata = index_path.lstat()
        if (
            index_path.is_symlink()
            or not index_path.is_file()
            or metadata.st_size < 1
            or metadata.st_size > MAX_RENDER_RESOURCE_INDEX_BYTES
        ):
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact index is invalid.",
                http_status=500,
            )

    @classmethod
    def _read_bounded_resource_index(cls, index_path: Path) -> bytes:
        cls._require_bounded_resource_index(index_path)
        return index_path.read_bytes()

    def _load_render_resource_index(
        self,
        render_directory: Path,
        artifact_id: str,
    ) -> _LoadedArtifactIndex | None:
        render_id = render_directory.name
        if (
            not _RENDER_ID_RE.fullmatch(render_id)
            or render_directory.is_symlink()
            or not render_directory.is_dir()
        ):
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Render storage is corrupted.",
                http_status=500,
            )
        index_path = render_directory / "resources" / artifact_id / "index.json"
        index_relative_path = index_path.relative_to(self.store.root).as_posix()
        try:
            self._require_bounded_resource_index(index_path)
        except FileNotFoundError:
            return None
        try:
            with self.store.lease_asset(index_relative_path) as leased_index:
                raw_index = self._read_bounded_resource_index(leased_index)
            entry = _ArtifactIndexEntry.model_validate_json(
                raw_index,
                strict=True,
            )
        except FileNotFoundError:
            return None
        except AppError as exc:
            if exc.code is not ErrorCode.NOT_FOUND:
                raise
            try:
                self._require_bounded_resource_index(index_path)
            except FileNotFoundError:
                return None
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact index is invalid.",
                http_status=500,
            ) from exc
        except (OSError, ValidationError) as exc:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact index is invalid.",
                http_status=500,
            ) from exc
        self._validate_registered_artifact(entry)
        if entry.artifact_id != artifact_id or entry.render_id != render_id:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact provenance is invalid.",
                http_status=500,
            )
        if entry.expires_at <= self._utc_timestamp():
            self._prune_resource_index(render_id, artifact_id)
            return None
        return _LoadedArtifactIndex(
            owners=(
                _RegisteredArtifact(
                    relative_path=entry.relative_path,
                    sha256=entry.sha256,
                    size=entry.size,
                    media_type=entry.media_type,
                    render_id=entry.render_id,
                    expires_at=entry.expires_at,
                ),
            ),
            sha256=hashlib.sha256(raw_index).hexdigest(),
        )

    def _discover_render_artifact(
        self,
        artifact_id: str,
    ) -> tuple[_RegisteredArtifact, ...] | None:
        renders_root = self.store.root / "renders"
        if not renders_root.exists():
            return None
        if renders_root.is_symlink() or not renders_root.is_dir():
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Render storage is corrupted.",
                http_status=500,
            )
        discovered: list[_RegisteredArtifact] = []
        scanned = 0
        try:
            render_directories = renders_root.iterdir()
            for render_directory in render_directories:
                scanned += 1
                if scanned > _MAX_RENDER_RESOURCE_SCAN_DIRECTORIES:
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Render resource index exceeds its scan bound.",
                        http_status=500,
                    )
                loaded = self._load_render_resource_index(
                    render_directory,
                    artifact_id,
                )
                if loaded is None:
                    continue
                for candidate in loaded.owners:
                    if discovered and any(
                        item.sha256 != candidate.sha256
                        or item.size != candidate.size
                        or item.media_type != candidate.media_type
                        or (
                            item.render_id == candidate.render_id
                            and item.relative_path == candidate.relative_path
                        )
                        for item in discovered
                    ):
                        raise AppError(
                            ErrorCode.INTERNAL_ERROR,
                            "Rendered artifact provenance is ambiguous.",
                            http_status=500,
                        )
                    discovered.append(candidate)
        except OSError as exc:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Render resource index is unavailable.",
                http_status=500,
            ) from exc
        if not discovered:
            return None
        registered = tuple(sorted(discovered, key=_registered_artifact_sort_key))
        self._resource_artifacts[artifact_id] = registered
        return registered

    def _registered_artifact(
        self,
        artifact_id: str,
    ) -> tuple[_RegisteredArtifact, ...] | None:
        registered = self._resource_artifacts.get(artifact_id)
        if registered is None:
            return self._discover_render_artifact(artifact_id)
        now = self._utc_timestamp()
        for item in registered:
            if item.expires_at <= now:
                self._prune_resource_index(item.render_id, artifact_id)
        retained = self._resource_artifacts.get(artifact_id)
        if not retained:
            return None
        return retained

    def _about_resource(self) -> dict[str, str]:
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
            "uri": "nplg://about",
            "mime_type": "application/json",
            "text": json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
            ),
        }

    def _read_registered_owner_group(
        self,
        artifact_id: str,
        owners: tuple[_RegisteredArtifact, ...],
    ) -> tuple[Path, bytes, _RegisteredArtifact] | None:
        selected: tuple[Path, bytes, _RegisteredArtifact] | None = None
        for candidate in owners:
            if candidate.size > HARD_MAX_INLINE_RESOURCE_BYTES:
                raise _inline_resource_too_large()
            try:
                with self.store.lease_asset(candidate.relative_path) as candidate_path:
                    candidate_content = read_verified_inline_resource_file(
                        candidate_path,
                        expected_size=candidate.size,
                    )
            except (FileNotFoundError, AppError) as exc:
                if isinstance(exc, AppError) and exc.code is not ErrorCode.NOT_FOUND:
                    raise
                self._prune_resource_index(candidate.render_id, artifact_id)
                return None
            actual_sha256 = hashlib.sha256(candidate_content).hexdigest()
            if (
                actual_sha256 != candidate.sha256
                or len(candidate_content) != candidate.size
            ):
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "Stored artifact integrity verification failed.",
                    http_status=500,
                )
            if selected is None:
                selected = (candidate_path, candidate_content, candidate)
        return selected

    def _read_artifact_resource(self, uri: str, artifact_id: str) -> dict[str, str]:
        registered_owners = self._registered_artifact(artifact_id)
        path: Path
        content: bytes
        if registered_owners is None:
            path = self._resolve_document(artifact_id)
            relative_path = path.relative_to(self.store.root).as_posix()
            media_type = "application/pdf"
            expected_sha256 = artifact_id.removeprefix("doc_")
            render_id = ""
            expected_size: int | None = None
            try:
                with self.store.lease_asset(relative_path) as path:
                    content = read_verified_inline_resource_file(
                        path,
                        expected_size=None,
                    )
            except (FileNotFoundError, AppError) as exc:
                if isinstance(exc, AppError) and exc.code is not ErrorCode.NOT_FOUND:
                    raise
                raise AppError(
                    ErrorCode.NOT_FOUND,
                    "The requested MCP resource was not found.",
                    http_status=404,
                ) from exc
        else:
            selected: tuple[Path, bytes, _RegisteredArtifact] | None = None
            owners_by_render: dict[str, list[_RegisteredArtifact]] = {}
            for candidate in registered_owners:
                owners_by_render.setdefault(candidate.render_id, []).append(candidate)
            for owner_group in owners_by_render.values():
                selected = self._read_registered_owner_group(
                    artifact_id,
                    tuple(owner_group),
                )
                if selected is not None:
                    break
            if selected is None:
                raise AppError(
                    ErrorCode.NOT_FOUND,
                    "The requested MCP resource was not found.",
                    http_status=404,
                )
            selected_path, selected_content, selected_owner = selected
            path = selected_path
            content = selected_content
            media_type = selected_owner.media_type
            expected_sha256 = selected_owner.sha256
            expected_size = selected_owner.size
            retained_owners = self._resource_artifacts.get(
                artifact_id,
                registered_owners,
            )
            owner_render_ids = {owner.render_id for owner in retained_owners}
            render_id = selected_owner.render_id if len(owner_render_ids) == 1 else ""
        actual_sha256 = hashlib.sha256(content).hexdigest()
        if actual_sha256 != expected_sha256 or (
            expected_size is not None and len(content) != expected_size
        ):
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Stored artifact integrity verification failed.",
                http_status=500,
            )
        payload = {
            "artifact_id": artifact_id,
            "sha256": expected_sha256,
            "size": len(content),
            "media_type": media_type,
            "render_id": render_id,
            "asset_url": self._signed_asset_url(
                path.relative_to(self.store.root).as_posix(),
                media_type,
            ),
        }
        return {
            "uri": uri,
            "mime_type": media_type,
            "text": json.dumps(payload, allow_nan=False, sort_keys=True),
            "blob": base64.b64encode(content).decode("ascii"),
            "sha256": expected_sha256,
            "size": str(len(content)),
            "render_id": render_id,
        }

    async def read_resource(self, uri: str) -> dict[str, str]:
        """Read one bounded private-full resource by URI."""
        if self._profile is not DeploymentProfile.PRIVATE_FULL:
            raise AppError(
                ErrorCode.NOT_FOUND,
                "The requested MCP resource was not found.",
                http_status=404,
            )

        if uri == "nplg://about":
            return self._about_resource()

        document_match = re.fullmatch(r"nplg://artifact/(doc_[0-9a-f]{64})", uri)
        if document_match:
            artifact_id = uri.removeprefix("nplg://artifact/")
            return self._read_artifact_resource(uri, artifact_id)

        render_match = re.fullmatch(r"nplg://render/(rnd_[0-9a-f]{32})/manifest", uri)
        if render_match:
            render_id = uri.removeprefix("nplg://render/").removesuffix("/manifest")
            result = await self._get_render_manifest(RenderIdInput(render_id=render_id))
            payload = cast(
                "JsonObject",
                result.model_dump(mode="json", by_alias=True),
            )
            return {
                "uri": uri,
                "mime_type": "application/json",
                "text": json.dumps(
                    payload,
                    allow_nan=False,
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            }
        raise AppError(
            ErrorCode.NOT_FOUND,
            "The requested MCP resource was not found.",
            http_status=404,
        )

    def _signed_asset_url(self, relative_path: str, media_type: str) -> str:
        now = datetime.fromtimestamp(self._utc_timestamp(), tz=UTC)
        asset_signing_secret = self.config.require_asset_signing_secret()
        token = sign_asset_token(
            asset_signing_secret,
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

    def _manifest_dict(self, manifest: PdfRenderPagesOutput) -> JsonObject:
        payload = _model_json(manifest, context="render manifest")
        _remove_private_pdf_pipeline_versions(payload)
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
            artifact_id = self._register_render_artifact(
                relative_path=_json_string(
                    page.get("relative_path"), context="relative_path"
                ),
                sha256=_json_string(page.get("sha256"), context="sha256"),
                media_type=_json_string(page.get("media_type"), context="media_type"),
                render_id=render_id,
            )
            page["resource_uri"] = f"nplg://artifact/{artifact_id}"
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

    def _render_artifact_content_identity(
        self,
        *,
        relative_path: str,
        sha256: str | None,
        media_type: str,
        render_id: str,
    ) -> tuple[str, int, Literal["application/json", "image/jpeg"]]:
        if media_type not in {"application/json", "image/jpeg"}:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact media type is invalid.",
                http_status=500,
            )
        if not _RENDER_ID_RE.fullmatch(render_id) or not relative_path.startswith(
            f"renders/{render_id}/"
        ):
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact provenance is invalid.",
                http_status=500,
            )
        digest = hashlib.sha256()
        try:
            with self.store.lease_asset(relative_path) as path:
                size = path.stat().st_size
                if size < 1 or size > self.config.cache_max_bytes:
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Rendered artifact size is invalid.",
                        http_status=500,
                    )
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
        except OSError as exc:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact integrity verification failed.",
                http_status=500,
            ) from exc
        actual_sha256 = digest.hexdigest()
        if sha256 is not None and actual_sha256 != sha256:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact integrity verification failed.",
                http_status=500,
            )
        return (
            actual_sha256,
            size,
            cast("Literal['application/json', 'image/jpeg']", media_type),
        )

    def _persist_render_resource_index(
        self,
        artifact_id: str,
        owner: _RegisteredArtifact,
    ) -> None:
        payload = self._render_resource_index_payload(artifact_id, owner)
        index_relative_path = self._resource_index_relative_path(
            owner.render_id,
            artifact_id,
        )
        written_path, _ = self.store.put_render_bytes(index_relative_path, payload)
        if written_path != index_relative_path:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact index path mismatch.",
                http_status=500,
            )

    def _render_resource_index_payload(
        self,
        artifact_id: str,
        owner: _RegisteredArtifact,
    ) -> bytes:
        entry = _ArtifactIndexEntry(
            version=1,
            artifact_id=artifact_id,
            relative_path=owner.relative_path,
            sha256=owner.sha256,
            size=owner.size,
            media_type=owner.media_type,
            render_id=owner.render_id,
            expires_at=owner.expires_at,
        )
        payload = json.dumps(
            _model_json(entry, context="render artifact index"),
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_RENDER_RESOURCE_INDEX_BYTES:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact index is invalid.",
                http_status=500,
            )
        return payload

    def _replace_render_resource_index(
        self,
        artifact_id: str,
        owner: _RegisteredArtifact,
        *,
        expected_index_sha256: str,
    ) -> None:
        payload = self._render_resource_index_payload(artifact_id, owner)
        index_relative_path = self._resource_index_relative_path(
            owner.render_id,
            artifact_id,
        )
        written_path, _ = self.store.replace_render_bytes_if_matches(
            index_relative_path,
            payload,
            expected_sha256=expected_index_sha256,
        )
        if written_path != index_relative_path:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact index path mismatch.",
                http_status=500,
            )

    def _validated_representative_candidate(
        self,
        owner: _RegisteredArtifact,
    ) -> Path | None:
        candidate = self.store.root / owner.relative_path
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            return None
        if candidate.is_symlink() or not candidate.is_file():
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact provenance is invalid.",
                http_status=500,
            )
        if metadata.st_size < 1:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Stored artifact integrity verification failed.",
                http_status=500,
            )
        return candidate

    def _representative_is_missing(self, owner: _RegisteredArtifact) -> bool:
        candidate = self._validated_representative_candidate(owner)
        if candidate is None:
            return True
        try:
            with self.store.lease_asset(owner.relative_path) as path:
                content = path.read_bytes()
        except AppError as exc:
            if exc.code is not ErrorCode.NOT_FOUND:
                raise
            refreshed = self._validated_representative_candidate(owner)
            if refreshed is None:
                return True
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Render resource index is unavailable.",
                http_status=500,
            ) from exc
        except FileNotFoundError:
            return True
        except OSError as exc:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Stored artifact integrity verification failed.",
                http_status=500,
            ) from exc
        if (
            len(content) != owner.size
            or hashlib.sha256(content).hexdigest() != owner.sha256
        ):
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Stored artifact integrity verification failed.",
                http_status=500,
            )
        return False

    def _register_render_artifact(
        self,
        *,
        relative_path: str,
        sha256: str | None,
        media_type: str,
        render_id: str,
    ) -> str:
        """Register one validated render binary under its content-derived URI."""
        actual_sha256, size, strict_media_type = self._render_artifact_content_identity(
            relative_path=relative_path,
            sha256=sha256,
            media_type=media_type,
            render_id=render_id,
        )
        artifact_id = f"doc_{actual_sha256}"
        existing_owners = self._registered_artifact(artifact_id)
        matching_owner = (
            self._matching_render_owner(
                existing_owners,
                content_identity=(actual_sha256, size, media_type),
                render_id=render_id,
            )
            if existing_owners is not None
            else None
        )
        if matching_owner is not None and existing_owners is not None:
            render_directory = self.store.root / "renders" / render_id
            loaded = self._load_render_resource_index(render_directory, artifact_id)
            if loaded is None or loaded.owners != (matching_owner,):
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "Rendered artifact index is invalid.",
                    http_status=500,
                )
            if not self._representative_is_missing(matching_owner):
                return artifact_id
            replacement = _RegisteredArtifact(
                relative_path=relative_path,
                sha256=actual_sha256,
                size=size,
                media_type=strict_media_type,
                render_id=render_id,
                expires_at=matching_owner.expires_at,
            )
            self._replace_render_resource_index(
                artifact_id,
                replacement,
                expected_index_sha256=loaded.sha256,
            )
            self._resource_artifacts[artifact_id] = tuple(
                replacement if item.render_id == render_id else item
                for item in existing_owners
            )
            return artifact_id
        registered = _RegisteredArtifact(
            relative_path=relative_path,
            sha256=actual_sha256,
            size=size,
            media_type=strict_media_type,
            render_id=render_id,
            expires_at=self._utc_timestamp() + self.config.asset_ttl_seconds,
        )
        owners = (*existing_owners, registered) if existing_owners else (registered,)
        self._persist_render_resource_index(
            artifact_id,
            registered,
        )
        self._resource_artifacts[artifact_id] = tuple(
            sorted(owners, key=_registered_artifact_sort_key)
        )
        return artifact_id

    @staticmethod
    def _matching_render_owner(
        owners: tuple[_RegisteredArtifact, ...],
        *,
        content_identity: tuple[str, int, str],
        render_id: str,
    ) -> _RegisteredArtifact | None:
        sha256, size, media_type = content_identity
        if any(
            item.sha256 != sha256 or item.size != size or item.media_type != media_type
            for item in owners
        ):
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Rendered artifact provenance is ambiguous.",
                http_status=500,
            )
        return next((item for item in owners if item.render_id == render_id), None)

    async def _search(
        self,
        values: SearchDocumentsInput,
    ) -> SearchDocumentsOutput:
        page = await self.repository.search(
            values.query,
            cursor=values.cursor,
            page_size=values.page_size,
            scope_handle=values.scope_handle,
        )
        return SearchDocumentsOutput.model_validate(
            dataclass_to_json(page, context="search page"),
            strict=True,
        )

    async def _get_metadata(
        self,
        values: HandleInput,
    ) -> DocumentMetadataOutput:
        return DocumentMetadataOutput.model_validate(
            dataclass_to_json(
                await self.repository.get_metadata(values.handle),
                context="document metadata",
            ),
            strict=True,
        )

    async def _list_files(self, values: HandleInput) -> DocumentFilesOutput:
        files = await self.repository.list_files(values.handle)
        file_values: list[JsonObject] = [
            dataclass_to_json(item, context="bitstream") for item in files
        ]
        payload: dict[str, object] = {
            "handle": values.handle,
            "files": file_values,
        }
        return DocumentFilesOutput.model_validate(payload, strict=True)

    async def _download_document(
        self,
        values: DownloadDocumentInput,
    ) -> DownloadDocumentOutput:
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
        payload: dict[str, object] = {
            "artifact_id": artifact.object_id,
            "sha256": artifact.sha256,
            "size": artifact.size,
            "media_type": artifact.media_type,
            "relative_path": artifact.relative_path,
            "asset_url": self._signed_asset_url(
                artifact.relative_path,
                artifact.media_type,
            ),
            "resource_uri": f"nplg://artifact/{artifact.object_id}",
            "source_bitstream_id": result.source_bitstream_id,
            "source_url": result.source_url,
            "bytes_downloaded": result.bytes_downloaded,
        }
        return DownloadDocumentOutput.model_validate(payload, strict=True)

    async def _run_pdf_job(
        self,
        command: PdfCommand,
    ) -> PdfSuccess:
        from .pdf_executor import (  # noqa: PLC0415
            PdfWorkerError,
            PdfWorkerUnavailableError,
        )
        from .pdf_ipc import PdfFailure  # noqa: PLC0415

        deadline = MonotonicDeadline.after(
            _PDF_JOB_TIMEOUT_SECONDS,
            clock=self._monotonic_clock,
        )
        acquired = False
        try:
            try:
                remaining = deadline.remaining(now=self._monotonic_clock())
                if remaining <= 0.0:
                    raise AppError(
                        ErrorCode.PDF_PROCESSING_FAILED,
                        "The PDF worker is temporarily unavailable.",
                        http_status=503,
                    )
                async with asyncio.timeout(remaining):
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

    def _reserve_render_resource_indexes(
        self,
        *,
        maximum_index_files: int,
    ) -> AbstractAsyncContextManager[None]:
        authority = self._pdf_postprocessing_reservation
        if authority is None:
            return nullcontext()
        return authority.reserve_postprocessing_publication(
            maximum_index_files=maximum_index_files,
        )

    async def _inspect_pdf(
        self,
        values: ArtifactInput,
    ) -> PdfInspectionOutput:
        from .pdf_executor import PdfWorkerError  # noqa: PLC0415
        from .pdf_ipc import (  # noqa: PLC0415
            InspectCommand,
            InspectParams,
            InspectPayload,
        )

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
        return PdfInspectionOutput.model_validate(payload, strict=True)

    async def _render_pages(
        self,
        values: RenderPagesInput,
    ) -> RenderPagesOutput:
        from .pdf_executor import PdfWorkerError  # noqa: PLC0415
        from .pdf_ipc import (  # noqa: PLC0415
            RenderPagesCommand,
            RenderPagesParams,
            RenderPagesPayload,
        )

        _ = self._resolve_document(values.artifact_id)
        async with self._reserve_render_resource_indexes(
            maximum_index_files=HARD_MAX_RENDER_PAGES,
        ):
            result = await self._run_pdf_job(
                RenderPagesCommand(
                    request_id=uuid4(),
                    operation="render_pages",
                    source_relative_path=self._document_relative_path(
                        values.artifact_id
                    ),
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
            return RenderPagesOutput.model_validate(payload, strict=True)

    async def _render_tiles(
        self,
        values: RenderTilesInput,
    ) -> RenderTilesOutput:
        from .pdf_executor import PdfWorkerError  # noqa: PLC0415
        from .pdf_ipc import (  # noqa: PLC0415
            RenderTilesCommand,
            RenderTilesParams,
            RenderTilesPayload,
        )

        if values.overlap is not None and (
            (values.tile_width is not None and values.overlap >= values.tile_width)
            or (values.tile_height is not None and values.overlap >= values.tile_height)
        ):
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Tool arguments did not match the declared schema.",
            )

        async with self._reserve_render_resource_indexes(
            maximum_index_files=HARD_MAX_TILES_PER_PAGE + 1,
        ):
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
            _remove_private_pdf_pipeline_versions(payload)
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
                artifact_id = self._register_render_artifact(
                    relative_path=_json_string(
                        tile.get("relative_path"), context="relative_path"
                    ),
                    sha256=_json_string(tile.get("sha256"), context="sha256"),
                    media_type=_json_string(
                        tile.get("media_type"), context="media_type"
                    ),
                    render_id=values.render_id,
                )
                tile["resource_uri"] = f"nplg://artifact/{artifact_id}"
            payload["manifest_asset_url"] = self._signed_asset_url(
                _json_string(
                    payload.get("manifest_relative_path"),
                    context="manifest_relative_path",
                ),
                "application/json",
            )
            manifest_artifact_id = self._register_render_artifact(
                relative_path=_json_string(
                    payload.get("manifest_relative_path"),
                    context="manifest_relative_path",
                ),
                sha256=None,
                media_type="application/json",
                render_id=values.render_id,
            )
            payload["resource_uri"] = f"nplg://artifact/{manifest_artifact_id}"
            return RenderTilesOutput.model_validate(payload, strict=True)

    async def _get_render_manifest(
        self,
        values: RenderIdInput,
    ) -> RenderManifestOutput:
        from .pdf_executor import PdfWorkerError  # noqa: PLC0415
        from .pdf_ipc import (  # noqa: PLC0415
            ManifestCommand,
            ManifestParams,
            ManifestPayload,
        )

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
        return RenderManifestOutput.model_validate(
            self._manifest_dict(result.payload.value),
            strict=True,
        )
