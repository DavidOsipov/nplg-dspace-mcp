# Copyright (c) 2026 David Osipov
"""Authoritative typed model pairs for the closed public tool catalog."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .inputs import (
    ArtifactInput,
    DownloadDocumentInput,
    HandleInput,
    RenderIdInput,
    RenderPagesInput,
    RenderTilesInput,
    SearchDocumentsInput,
)
from .outputs import (
    DocumentFilesOutput,
    DocumentMetadataOutput,
    DownloadDocumentOutput,
    PdfInspectionOutput,
    RenderManifestOutput,
    RenderPagesOutput,
    RenderTilesOutput,
    SearchDocumentsOutput,
)

if TYPE_CHECKING:
    from .base import StrictInput, StrictOutput

type ToolName = Literal[
    "download_document_file",
    "get_document_metadata",
    "get_render_manifest",
    "inspect_pdf",
    "list_document_files",
    "render_pdf_page_tiles",
    "render_pdf_pages",
    "search_documents",
]


@dataclass(frozen=True, slots=True)
class ToolModelBinding:
    """Bind one public tool name to its sole reviewed input/output pair."""

    name: ToolName
    input_model: type[StrictInput]
    output_model: type[StrictOutput]


_TOOL_MODEL_BINDINGS: tuple[ToolModelBinding, ...] = (
    ToolModelBinding(
        "download_document_file", DownloadDocumentInput, DownloadDocumentOutput
    ),
    ToolModelBinding("get_document_metadata", HandleInput, DocumentMetadataOutput),
    ToolModelBinding("get_render_manifest", RenderIdInput, RenderManifestOutput),
    ToolModelBinding("inspect_pdf", ArtifactInput, PdfInspectionOutput),
    ToolModelBinding("list_document_files", HandleInput, DocumentFilesOutput),
    ToolModelBinding("render_pdf_page_tiles", RenderTilesInput, RenderTilesOutput),
    ToolModelBinding("render_pdf_pages", RenderPagesInput, RenderPagesOutput),
    ToolModelBinding("search_documents", SearchDocumentsInput, SearchDocumentsOutput),
)


def _tool_name_utf8(name: str) -> bytes:
    """Return the canonical ordering key for one closed tool name."""
    return name.encode("utf-8")


def tool_model_bindings() -> tuple[ToolModelBinding, ...]:
    """Return the exact immutable UTF-8-name-sorted model authority."""
    names = tuple(binding.name for binding in _TOOL_MODEL_BINDINGS)
    if names != tuple(sorted(names, key=_tool_name_utf8)):
        message = "authoritative model inventory is not UTF-8-name sorted"
        raise ValueError(message)
    if len(names) != len(set(names)):
        message = "authoritative model inventory contains duplicate tool names"
        raise ValueError(message)
    return _TOOL_MODEL_BINDINGS


def require_tool_model_binding(
    name: str,
    input_model: type[StrictInput],
    output_model: type[StrictOutput],
) -> None:
    """Reject a catalog definition that disagrees with the model authority."""
    for binding in tool_model_bindings():
        if binding.name != name:
            continue
        if (
            binding.input_model is not input_model
            or binding.output_model is not output_model
        ):
            message = "tool definition disagrees with authoritative model inventory"
            raise ValueError(message)
        return
    message = "tool definition is absent from authoritative model inventory"
    raise ValueError(message)
