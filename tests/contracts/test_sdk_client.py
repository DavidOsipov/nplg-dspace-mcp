# Copyright (c) 2026 David Osipov
# mypy: disable-error-code="explicit-any,misc"
"""Black-box contracts for the official MCP SDK adapter."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta
from typing import TYPE_CHECKING, cast

import pytest
from mcp import Client, types
from mcp.shared.exceptions import MCPError

from nplg_mcp.json_types import JsonObject, require_json_object
from nplg_mcp.mcp_server import create_mcp_server
from nplg_mcp.profiles import DeploymentProfile
from nplg_mcp.sdk_boundary import SdkHandlers
from nplg_mcp.services import FullServiceComposition
from tests.helpers.app_factory import FIXED_UTC_NOW, make_tool_service

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.context import ServerRequestContext

    from nplg_mcp.services import MetadataServices
    from nplg_mcp.tools import ToolService


INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


async def _render_first_page_resource(
    tools: ToolService,
) -> tuple[str, JsonObject, str]:
    downloaded = await tools.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )
    artifact_id = downloaded.model_dump(mode="json")["artifact_id"]
    assert isinstance(artifact_id, str)
    rendered = await tools.call(
        "render_pdf_pages",
        {"artifact_id": artifact_id, "pages": [1]},
    )
    rendered_content = require_json_object(
        rendered.model_dump(mode="json"),
        context="rendered output",
    )
    pages = rendered_content["pages"]
    assert isinstance(pages, list)
    page = require_json_object(pages[0], context="rendered page")
    resource_uri = page["resource_uri"]
    render_id = rendered_content["render_id"]
    assert isinstance(resource_uri, str)
    assert isinstance(render_id, str)
    return resource_uri, page, render_id


@pytest.mark.asyncio
async def test_official_client_lists_strict_metadata_tools(
    app_services: MetadataServices,
) -> None:
    """The official in-memory client receives the closed metadata catalog."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)

    async with Client(server, mode="2026-07-28") as client:
        result = await client.list_tools()

    assert [tool.name for tool in result.tools] == [
        "get_document_metadata",
        "list_document_files",
        "search_documents",
    ]
    assert all(tool.output_schema is not None for tool in result.tools)
    wire = result.model_dump(mode="json", by_alias=True)
    assert wire["ttlMs"] == 0
    assert wire["cacheScope"] == "private"


@pytest.mark.asyncio
async def test_default_official_client_records_a_discovery_result(
    app_services: MetadataServices,
) -> None:
    """The default client exercises modern discovery rather than a pinned shortcut."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)

    async with Client(server) as client:
        assert client.session.discover_result is not None


def test_official_server_has_no_ambient_telemetry_middleware(
    app_services: MetadataServices,
) -> None:
    """The SDK default telemetry adapter is opt-in, never ambient server state."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)

    assert server.middleware == []


@pytest.mark.asyncio
async def test_official_client_returns_revalidated_structured_output(
    app_services: MetadataServices,
) -> None:
    """A successful call returns structured, Pydantic-revalidated JSON only once."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)

    async with Client(server, mode="2026-07-28") as client:
        result = await client.call_tool("search_documents", {"query": "fixture"})

    assert result.is_error is False
    assert result.content == []
    assert result.structured_content == {
        "items": [
            {
                "authors": [],
                "canonical_url": "https://dspace.nplg.gov.ge/handle/1234/560449",
                "handle": "1234/560449",
                "issue_date": None,
                "title": "fixture",
            }
        ],
        "next_cursor": None,
        "next_offset": None,
        "source_url": "https://dspace.nplg.gov.ge/simple-search",
        "total": 1,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("search_documents", {"query": "fixture", "unexpected": True}),
        ("search_documents", {"query": 1}),
        ("search_documents", {"query": "fixture", "page_size": True}),
        ("unknown_tool", {}),
    ],
)
async def test_official_client_rejects_invalid_raw_tool_arguments(
    app_services: MetadataServices,
    name: str,
    arguments: dict[str, object],
) -> None:
    """Bad raw arguments fail at the adapter with the standard invalid-params code."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)

    async with Client(server, mode="2026-07-28") as client:
        with pytest.raises(MCPError) as captured:
            _ = await client.call_tool(name, arguments)

    assert captured.value.error.code == INVALID_PARAMS
    assert "fixture" not in captured.value.error.message


@pytest.mark.asyncio
async def test_metadata_profile_registers_no_local_resource_templates(
    app_services: MetadataServices,
) -> None:
    """Metadata-only deployment cannot advertise local artifact or render state."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)

    async with Client(server, mode="2026-07-28") as client:
        result = await client.list_resource_templates()

    assert result.resource_templates == []
    wire = result.model_dump(mode="json", by_alias=True)
    assert wire["ttlMs"] == 0
    assert wire["cacheScope"] == "private"


@pytest.mark.asyncio
async def test_private_profile_registers_only_canonical_local_templates(
    tmp_path: Path,
) -> None:
    """Private-full advertises canonical artifact and manifest templates only."""
    tools = make_tool_service(tmp_path)
    services = FullServiceComposition(tools=tools, store=tools.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)

    async with Client(server, mode="2026-07-28") as client:
        result = await client.list_resource_templates()

    assert [template.uri_template for template in result.resource_templates] == [
        "nplg://artifact/{artifact_id}",
        "nplg://render/{render_id}/manifest",
    ]
    assert all(
        "/page/" not in template.uri_template and "/tile/" not in template.uri_template
        for template in result.resource_templates
    )
    wire = result.model_dump(mode="json", by_alias=True)
    assert wire["ttlMs"] == 0
    assert wire["cacheScope"] == "private"


@pytest.mark.asyncio
async def test_valid_absent_resource_has_exact_bounded_invalid_params_error(
    app_services: MetadataServices,
) -> None:
    """A canonical but absent resource is never an empty successful read."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)

    async with Client(server, mode="2026-07-28") as client:
        with pytest.raises(MCPError) as captured:
            _ = await client.read_resource("nplg://artifact/doc_" + "0" * 64)

    error = captured.value.error
    assert error.code == INVALID_PARAMS
    assert error.message == "Resource not found"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "uri",
    [
        "nplg://artifact/not-an-artifact",
        "nplg://render/not-a-render/manifest",
        "nplg://render/rnd_" + "0" * 32 + "/page/1",
        "nplg://unknown",
        "nplg://artifact/doc_" + "0" * 64 + "\x00canary",
    ],
)
async def test_malformed_resource_uri_is_invalid_before_service_entry(
    app_services: MetadataServices,
    uri: str,
) -> None:
    """Malformed and removed URI forms fail at the SDK adapter before lookup."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)

    async with Client(server, mode="2026-07-28") as client:
        with pytest.raises(MCPError) as captured:
            _ = await client.read_resource(uri)

    assert captured.value.error.code == INVALID_PARAMS
    assert "canary" not in captured.value.error.message


@pytest.mark.asyncio
async def test_rendered_page_and_tile_links_are_canonical_readable_artifacts(
    tmp_path: Path,
) -> None:
    """Every emitted page/tile URI identifies the exact immutable JPEG bytes."""
    tools = make_tool_service(tmp_path)
    services = FullServiceComposition(tools=tools, store=tools.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)

    async with Client(server, mode="2026-07-28") as client:
        downloaded = await client.call_tool(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )
        assert downloaded.structured_content is not None
        artifact_id = downloaded.structured_content["artifact_id"]
        assert isinstance(artifact_id, str)
        rendered = await client.call_tool(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1]},
        )
        assert rendered.structured_content is not None
        rendered_content = require_json_object(
            rendered.structured_content,
            context="rendered structured content",
        )
        pages = rendered_content["pages"]
        assert isinstance(pages, list)
        page = require_json_object(pages[0], context="rendered page")
        page_uri = page["resource_uri"]
        assert isinstance(page_uri, str)
        page_sha256 = page["sha256"]
        assert isinstance(page_sha256, str)
        assert page_uri == "nplg://artifact/doc_" + page_sha256
        page_read = await client.read_resource(page_uri)

        render_id = rendered_content["render_id"]
        assert isinstance(render_id, str)
        tiled = await client.call_tool(
            "render_pdf_page_tiles",
            {"render_id": render_id, "page_number": 1},
        )
        assert tiled.structured_content is not None
        tiled_content = require_json_object(
            tiled.structured_content,
            context="tiled structured content",
        )
        tiles_value = tiled_content["tiles"]
        assert isinstance(tiles_value, list)
        tile = require_json_object(tiles_value[0], context="rendered tile")
        tile_uri = tile["resource_uri"]
        assert isinstance(tile_uri, str)
        tile_sha256 = tile["sha256"]
        assert isinstance(tile_sha256, str)
        assert tile_uri == "nplg://artifact/doc_" + tile_sha256
        tile_read = await client.read_resource(tile_uri)

    for expected, result in ((page, page_read), (tile, tile_read)):
        assert len(result.contents) == 1
        content = result.contents[0]
        assert isinstance(content, types.BlobResourceContents)
        raw = base64.b64decode(content.blob, validate=True)
        assert hashlib.sha256(raw).hexdigest() == expected["sha256"]
        assert content.mime_type == "image/jpeg"
        wire = result.model_dump(mode="json", by_alias=True)
        assert wire["ttlMs"] == 0
        assert wire["cacheScope"] == "private"


@pytest.mark.asyncio
async def test_tile_manifest_resource_resolves_exact_persisted_manifest_not_pages(
    tmp_path: Path,
) -> None:
    """The tile result's top-level URI identifies its own persisted JSON bytes."""
    tools = make_tool_service(tmp_path)
    services = FullServiceComposition(tools=tools, store=tools.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)

    async with Client(server, mode="2026-07-28") as client:
        downloaded = await client.call_tool(
            "download_document_file",
            {"handle": "1234/560449", "bitstream_id": "bs_public"},
        )
        assert downloaded.structured_content is not None
        artifact_id = downloaded.structured_content["artifact_id"]
        assert isinstance(artifact_id, str)
        rendered = await client.call_tool(
            "render_pdf_pages",
            {"artifact_id": artifact_id, "pages": [1]},
        )
        assert rendered.structured_content is not None
        rendered_content = require_json_object(
            rendered.structured_content,
            context="rendered structured content",
        )
        render_id = rendered_content["render_id"]
        assert isinstance(render_id, str)
        tiled = await client.call_tool(
            "render_pdf_page_tiles",
            {"render_id": render_id, "page_number": 1},
        )
        assert tiled.structured_content is not None
        tiled_content = require_json_object(
            tiled.structured_content,
            context="tiled structured content",
        )
        manifest_uri = tiled_content["resource_uri"]
        assert isinstance(manifest_uri, str)
        assert manifest_uri.startswith("nplg://artifact/doc_")
        manifest_read = await client.read_resource(manifest_uri)

    assert len(manifest_read.contents) == 1
    content = manifest_read.contents[0]
    assert isinstance(content, types.BlobResourceContents)
    assert content.mime_type == "application/json"
    raw = base64.b64decode(content.blob, validate=True)
    manifest_relative_path = tiled_content["manifest_relative_path"]
    assert isinstance(manifest_relative_path, str)
    expected = tools.store.resolve_asset(manifest_relative_path).read_bytes()
    pages_relative_path = rendered_content["manifest_relative_path"]
    assert isinstance(pages_relative_path, str)
    pages_manifest = tools.store.resolve_asset(pages_relative_path).read_bytes()
    assert raw == expected
    assert raw != pages_manifest
    assert manifest_uri == "nplg://artifact/doc_" + hashlib.sha256(raw).hexdigest()


@pytest.mark.asyncio
async def test_rendered_jpeg_resource_survives_service_restart(
    tmp_path: Path,
) -> None:
    """A persisted, manifest-authorized JPEG remains readable after restart."""
    tools = make_tool_service(tmp_path)
    downloaded = await tools.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )
    artifact_id = downloaded.model_dump(mode="json")["artifact_id"]
    assert isinstance(artifact_id, str)
    rendered = await tools.call(
        "render_pdf_pages",
        {"artifact_id": artifact_id, "pages": [1]},
    )
    rendered_content = require_json_object(
        rendered.model_dump(mode="json"),
        context="rendered output",
    )
    pages = rendered_content["pages"]
    assert isinstance(pages, list)
    page = require_json_object(pages[0], context="rendered page")
    resource_uri = page["resource_uri"]
    expected_sha256 = page["sha256"]
    assert isinstance(resource_uri, str)
    assert isinstance(expected_sha256, str)

    restarted = make_tool_service(tmp_path)
    services = FullServiceComposition(tools=restarted, store=restarted.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)
    async with Client(server, mode="2026-07-28") as client:
        result = await client.read_resource(resource_uri)

    assert len(result.contents) == 1
    content = result.contents[0]
    assert isinstance(content, types.BlobResourceContents)
    raw = base64.b64decode(content.blob, validate=True)
    assert hashlib.sha256(raw).hexdigest() == expected_sha256
    assert content.mime_type == "image/jpeg"


@pytest.mark.asyncio
async def test_post_lookup_missing_key_fault_is_sanitized_internal_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All adaptation faults after a successful lookup stay behind -32603."""
    tools = make_tool_service(tmp_path)
    canary = "post-lookup-keyerror-canary"

    async def malformed_resource(_uri: str) -> dict[str, str]:
        return {
            "uri": "nplg://artifact/doc_" + "0" * 64,
            "mime_type": "image/jpeg",
            "blob": canary,
        }

    monkeypatch.setattr(tools, "read_resource", malformed_resource)
    services = FullServiceComposition(tools=tools, store=tools.store)
    handlers = SdkHandlers(services, DeploymentProfile.PRIVATE_FULL)
    params = types.ReadResourceRequestParams(uri="nplg://artifact/doc_" + "0" * 64)
    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            cast("ServerRequestContext[None]", None),
            params,
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"
    assert canary not in str(captured.value.error.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_expired_render_resource_is_rejected_and_authorization_pruned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = make_tool_service(tmp_path)
    resource_uri, page, render_id = await _render_first_page_resource(tools)
    artifact_id = resource_uri.removeprefix("nplg://artifact/")
    index_subtree = tools.store.root / "renders" / render_id / "resources" / artifact_id
    page_relative_path = page["relative_path"]
    assert isinstance(page_relative_path, str)
    page_path = tools.store.resolve_asset(page_relative_path)
    assert index_subtree.is_dir()

    expired_now = FIXED_UTC_NOW + timedelta(seconds=tools.config.asset_ttl_seconds + 1)
    monkeypatch.setattr(tools, "_utc_now", lambda: expired_now)
    services = FullServiceComposition(tools=tools, store=tools.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)
    async with Client(server, mode="2026-07-28") as client:
        with pytest.raises(MCPError) as captured:
            _ = await client.read_resource(resource_uri)

    assert captured.value.error.code == INVALID_PARAMS
    assert captured.value.error.message == "Resource not found"
    assert not index_subtree.exists()
    assert page_path.is_file()


@pytest.mark.asyncio
async def test_concurrent_render_asset_deletion_is_not_an_empty_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = make_tool_service(tmp_path)
    resource_uri, page, _render_id = await _render_first_page_resource(tools)
    page_relative_path = page["relative_path"]
    assert isinstance(page_relative_path, str)
    original_resolve = tools.store.resolve_asset

    def delete_after_resolution(relative_path: str) -> Path:
        path = original_resolve(relative_path)
        if relative_path == page_relative_path:
            path.unlink()
        return path

    monkeypatch.setattr(tools.store, "resolve_asset", delete_after_resolution)
    services = FullServiceComposition(tools=tools, store=tools.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)
    async with Client(server, mode="2026-07-28") as client:
        with pytest.raises(MCPError) as captured:
            _ = await client.read_resource(resource_uri)

    assert captured.value.error.code == INVALID_PARAMS
    assert captured.value.error.message == "Resource not found"


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["digest", "mime"])
async def test_restart_rejects_swapped_render_index_identity(
    tmp_path: Path,
    mutation: str,
) -> None:
    tools = make_tool_service(tmp_path)
    resource_uri, _page, render_id = await _render_first_page_resource(tools)
    artifact_id = resource_uri.removeprefix("nplg://artifact/")
    index_path = (
        tools.store.root
        / "renders"
        / render_id
        / "resources"
        / artifact_id
        / "index.json"
    )
    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert isinstance(index, dict)
    if mutation == "digest":
        index["sha256"] = "1" * 64
    else:
        index["media_type"] = "application/json"
    _ = index_path.write_text(
        json.dumps(index, allow_nan=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    restarted = make_tool_service(tmp_path)
    services = FullServiceComposition(tools=restarted, store=restarted.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)
    async with Client(server, mode="2026-07-28") as client:
        with pytest.raises(MCPError) as captured:
            _ = await client.read_resource(resource_uri)

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"
    assert artifact_id not in str(captured.value.error.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_restart_rejects_cross_render_provenance_rebinding(
    tmp_path: Path,
) -> None:
    tools = make_tool_service(tmp_path)
    resource_uri, _page, render_id = await _render_first_page_resource(tools)
    artifact_id = resource_uri.removeprefix("nplg://artifact/")
    index_path = (
        tools.store.root
        / "renders"
        / render_id
        / "resources"
        / artifact_id
        / "index.json"
    )
    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert isinstance(index, dict)
    index["render_id"] = "rnd_" + "f" * 32
    _ = index_path.write_text(
        json.dumps(index, allow_nan=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    restarted = make_tool_service(tmp_path)
    services = FullServiceComposition(tools=restarted, store=restarted.store)
    handlers = SdkHandlers(services, DeploymentProfile.PRIVATE_FULL)
    params = types.ReadResourceRequestParams(uri=resource_uri)
    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            cast("ServerRequestContext[None]", None),
            params,
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"


@pytest.mark.asyncio
async def test_injected_lookup_keyerror_is_sanitized_internal_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = make_tool_service(tmp_path)
    canary = "lookup-keyerror-path-token-canary"

    async def failed_lookup(_uri: str) -> dict[str, str]:
        raise KeyError(canary)

    monkeypatch.setattr(tools, "read_resource", failed_lookup)
    services = FullServiceComposition(tools=tools, store=tools.store)
    handlers = SdkHandlers(services, DeploymentProfile.PRIVATE_FULL)
    params = types.ReadResourceRequestParams(uri="nplg://artifact/doc_" + "0" * 64)
    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            cast("ServerRequestContext[None]", None),
            params,
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"
    assert canary not in str(captured.value.error.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_mutant_legacy_page_uri_is_killed_at_live_sdk_output_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = make_tool_service(tmp_path)
    _resource_uri, _page, render_id = await _render_first_page_resource(tools)
    rendered = await tools.call(
        "get_render_manifest",
        {"render_id": render_id},
    )
    mutant = require_json_object(
        rendered.model_dump(mode="json"),
        context="mutant render output",
    )
    mutant["artifact_id"] = "doc_" + "0" * 64
    pages = mutant["pages"]
    assert isinstance(pages, list)
    page = require_json_object(pages[0], context="mutant rendered page")
    page["resource_uri"] = f"nplg://render/{render_id}/page/1"

    async def mutant_call(_name: str, _arguments: JsonObject) -> JsonObject:
        return mutant

    monkeypatch.setattr(tools, "call", mutant_call)
    services = FullServiceComposition(tools=tools, store=tools.store)
    handlers = SdkHandlers(services, DeploymentProfile.PRIVATE_FULL)
    params = types.CallToolRequestParams(
        name="render_pdf_pages",
        arguments={"artifact_id": "doc_" + "0" * 64, "pages": [1]},
    )
    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_call_tool(
            cast("ServerRequestContext[None]", None),
            params,
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"
