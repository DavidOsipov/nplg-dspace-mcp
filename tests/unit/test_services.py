# Copyright (c) 2026 David Osipov
"""Tests for acyclic profile-specific service composition records."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from nplg_mcp.profiles import DeploymentProfile, tool_names_for_profile
from nplg_mcp.services import (
    FullServiceComposition,
    FullServices,
    MetadataServiceComposition,
    MetadataServices,
)
from tests.helpers.app_factory import make_tool_service

if TYPE_CHECKING:
    from pathlib import Path

    from nplg_mcp.services import ToolSurface


def test_metadata_composition_has_no_optional_store_hole(tmp_path: Path) -> None:
    tools = make_tool_service(tmp_path, deployment_profile="alpic-metadata")
    composition = MetadataServiceComposition(tools=tools, http_client=None)

    assert isinstance(composition, MetadataServices)
    assert not hasattr(composition, "store")
    assert tuple(item["name"] for item in composition.tools.list_tools()) == (
        "get_document_metadata",
        "list_document_files",
        "search_documents",
    )


def test_full_composition_requires_a_nonoptional_store(tmp_path: Path) -> None:
    tools = make_tool_service(tmp_path)
    composition = FullServiceComposition(
        tools=cast("ToolSurface", tools),
        store=tools.store,
        http_client=None,
    )

    assert isinstance(composition, FullServices)
    assert composition.store is tools.store


def test_profile_tool_inventory_is_closed_and_deterministic() -> None:
    assert tool_names_for_profile(DeploymentProfile.ALPIC_METADATA) == (
        "get_document_metadata",
        "list_document_files",
        "search_documents",
    )
    assert tool_names_for_profile(DeploymentProfile.PRIVATE_FULL) == (
        "download_document_file",
        "get_document_metadata",
        "get_render_manifest",
        "inspect_pdf",
        "list_document_files",
        "render_pdf_page_tiles",
        "render_pdf_pages",
        "search_documents",
    )
