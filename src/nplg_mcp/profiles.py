# Copyright (c) 2026 David Osipov
"""Closed deployment profiles and their exact public tool inventories."""

from __future__ import annotations

from enum import StrEnum


class DeploymentProfile(StrEnum):
    """Reviewed deployment profiles with distinct authority boundaries."""

    ALPIC_METADATA = "alpic-metadata"
    PRIVATE_FULL = "private-full"
    DISTRIBUTED_FULL = "distributed-full"


type ToolName = str

METADATA_TOOL_NAMES: tuple[ToolName, ...] = (
    "get_document_metadata",
    "list_document_files",
    "search_documents",
)
FULL_TOOL_NAMES: tuple[ToolName, ...] = (
    "download_document_file",
    "get_document_metadata",
    "get_render_manifest",
    "inspect_pdf",
    "list_document_files",
    "render_pdf_page_tiles",
    "render_pdf_pages",
    "search_documents",
)


def tool_names_for_profile(profile: DeploymentProfile) -> tuple[ToolName, ...]:
    """Return the immutable exact tool inventory for one validated profile."""
    if profile is DeploymentProfile.ALPIC_METADATA:
        return METADATA_TOOL_NAMES
    if profile is DeploymentProfile.PRIVATE_FULL:
        return FULL_TOOL_NAMES
    message = "distributed-full is not implemented and must remain disabled"
    raise ValueError(message)
