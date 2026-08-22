# Copyright (c) 2026 David Osipov
# mypy: disable-error-code="explicit-any,misc"
"""Adversarial contracts for the narrow official MCP SDK boundary."""

from __future__ import annotations

import ast
import base64
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

import pytest
from mcp import types
from mcp.shared.exceptions import MCPError

from nplg_mcp.sdk_boundary import SdkHandlers
from nplg_mcp.services import MetadataServiceComposition

if TYPE_CHECKING:
    from mcp.server.context import ServerRequestContext

    from nplg_mcp.contracts import StrictOutput
    from nplg_mcp.json_types import JsonObject
    from nplg_mcp.services import ToolSurface
    from nplg_mcp.tools import ToolService


INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _call_log() -> list[tuple[str, JsonObject]]:
    """Create one precisely typed empty call log."""
    return []


def _resource_payload() -> dict[str, str]:
    """Create one precisely typed empty resource payload."""
    return {}


@dataclass(slots=True)
class RecordingTools:
    """Tool surface wrapper that exposes whether the SDK boundary dispatched."""

    delegate: ToolSurface
    calls: list[tuple[str, JsonObject]] = field(default_factory=_call_log)

    def list_tools(self) -> list[JsonObject]:
        """Return the delegate catalog unchanged."""
        return self.delegate.list_tools()

    async def call(self, name: str, arguments: JsonObject) -> StrictOutput | JsonObject:
        """Record a handler entry before calling the strict delegate."""
        self.calls.append((name, arguments))
        return await self.delegate.call(name, arguments)

    def list_resources(self) -> list[JsonObject]:
        """Return the delegate resources unchanged."""
        return self.delegate.list_resources()

    async def read_resource(self, uri: str) -> dict[str, str]:
        """Return the delegate resource unchanged."""
        return await self.delegate.read_resource(uri)


@dataclass(slots=True)
class InvalidOutputTools(RecordingTools):
    """A deliberately untrusted handler result containing a secret-like canary."""

    @override
    async def call(self, name: str, arguments: JsonObject) -> StrictOutput | JsonObject:
        """Return malformed output after recording one legitimate handler entry."""
        self.calls.append((name, arguments))
        return {"sensitive_adapter_fixture": "canary-secret-value"}


@dataclass(slots=True)
class ResourcePayloadTools(RecordingTools):
    """Return one deliberately controlled service resource payload."""

    resource: dict[str, str] = field(default_factory=_resource_payload)

    @override
    async def read_resource(self, uri: str) -> dict[str, str]:
        """Return an owned copy so adaptation cannot mutate the fixture."""
        _ = uri
        return dict(self.resource)


def _blob_resource(uri: str) -> dict[str, str]:
    """Build one internally consistent canonical blob service payload."""
    raw = b"bounded-sdk-resource"
    return {
        "uri": uri,
        "mime_type": "image/jpeg",
        "text": "",
        "blob": base64.b64encode(raw).decode("ascii"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": str(len(raw)),
        "render_id": "",
    }


def _context() -> ServerRequestContext[None]:
    """Provide the unused SDK request context for direct boundary tests."""
    return cast("ServerRequestContext[None]", None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arguments",
    [
        {"query": "fixture", "unexpected": True},
        {"query": 1},
        {"query": "fixture", "page_size": True},
    ],
)
async def test_sdk_boundary_rejects_bad_raw_arguments_before_tool_entry(
    tool_service: ToolService,
    arguments: dict[str, object],
) -> None:
    """Adapter validation is a pre-dispatch boundary, not a service convenience."""
    tools = RecordingTools(tool_service)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.CallToolRequestParams(name="search_documents", arguments=arguments)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_call_tool(_context(), params)

    assert captured.value.error.code == INVALID_PARAMS
    assert tools.calls == []
    assert "fixture" not in captured.value.error.message


@pytest.mark.asyncio
async def test_sdk_boundary_sanitizes_invalid_untrusted_handler_output(
    tool_service: ToolService,
) -> None:
    """Malformed handler output is an internal failure without a canary disclosure."""
    tools = InvalidOutputTools(tool_service)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.CallToolRequestParams(
        name="search_documents",
        arguments={"query": "fixture"},
    )

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_call_tool(_context(), params)

    assert captured.value.error.code == INTERNAL_ERROR
    assert "canary-secret-value" not in captured.value.error.message
    assert tools.calls == [("search_documents", {"query": "fixture"})]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload_kind", ["blob_uri", "text_uri"])
async def test_sdk_boundary_sanitizes_resource_uri_binding_mismatch(
    tool_service: ToolService,
    payload_kind: str,
) -> None:
    """Neither binary nor text service payloads may rebind the requested URI."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    mismatched_uri = "nplg://artifact/doc_" + "1" * 64
    if payload_kind == "blob_uri":
        resource = _blob_resource(mismatched_uri)
    else:
        resource = {
            "uri": mismatched_uri,
            "mime_type": "application/json",
            "text": "{}",
        }
    tools = ResourcePayloadTools(tool_service, resource=resource)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.ReadResourceRequestParams(uri=requested_uri)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(_context(), params)

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"
    assert mismatched_uri not in str(captured.value.error.model_dump(mode="json"))


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", ["size", "digest"])
async def test_sdk_boundary_sanitizes_each_blob_identity_mismatch(
    tool_service: ToolService,
    mismatch: str,
) -> None:
    """Size and digest are independently mandatory blob identity bindings."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    resource = _blob_resource(requested_uri)
    if mismatch == "size":
        resource["size"] = str(int(resource["size"]) + 1)
    else:
        resource["sha256"] = "f" * 64
    tools = ResourcePayloadTools(tool_service, resource=resource)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.ReadResourceRequestParams(uri=requested_uri)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(_context(), params)

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"


@pytest.mark.asyncio
async def test_sdk_boundary_omits_empty_render_provenance_metadata(
    tool_service: ToolService,
) -> None:
    """A non-render artifact must not invent an empty render provenance value."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    resource = _blob_resource(requested_uri)
    tools = ResourcePayloadTools(tool_service, resource=resource)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.ReadResourceRequestParams(uri=requested_uri)

    result = await handlers.on_read_resource(_context(), params)

    assert len(result.contents) == 1
    content = result.contents[0]
    assert isinstance(content, types.BlobResourceContents)
    assert content.meta is not None
    assert content.meta == {
        "sha256": resource["sha256"],
        "size": int(resource["size"]),
    }


def test_server_uses_all_constructor_bound_handlers_without_decorators() -> None:
    """The low-level SDK registration seam cannot silently revert to decorators."""
    source = Path("src/nplg_mcp/mcp_server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "create_mcp_server"
    )
    calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Server"
    ]

    assert len(calls) == 1
    registered = {keyword.arg for keyword in calls[0].keywords}
    assert {
        "on_list_tools",
        "on_call_tool",
        "on_list_resources",
        "on_list_resource_templates",
        "on_read_resource",
    } <= registered
    assert ".tool(" not in source
    assert ".resource(" not in source


def test_runtime_manifests_pin_the_official_sdk_transport_stack() -> None:
    """Application and lock inputs make MCP's distinct HTTPX2 stack explicit."""
    requirements = Path("requirements.in").read_text(encoding="utf-8")
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    expected = {
        "mcp==2.0.0",
        "mcp-types==2.0.0",
        "httpx2==2.9.0",
        "httpcore2==2.9.0",
        "truststore==0.10.4",
        "jsonschema==4.26.0",
        "opentelemetry-api==1.44.0",
        "PyJWT[crypto]==2.13.0",
        "python-multipart==0.0.32",
        "sse-starlette==3.4.8",
    }

    assert all(requirement.lower() in requirements.lower() for requirement in expected)
    assert all(
        f'"{requirement}"'.lower() in project.lower() for requirement in expected
    )
