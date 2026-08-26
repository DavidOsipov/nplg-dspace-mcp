# Copyright (c) 2026 David Osipov
"""Auth-disabled loopback fixture for the reviewed official MCP harness only."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, cast

from fastapi import FastAPI
from mcp import types
from mcp.server import Server
from mcp.shared.exceptions import MCPError
from mcp_types import (
    MISSING_REQUIRED_CLIENT_CAPABILITY,
    ClientCapabilities,
    MissingRequiredClientCapabilityErrorData,
    SamplingCapability,
)

from nplg_mcp.config import load_config
from nplg_mcp.http_security import (
    McpSecurityMiddleware,
    build_transport_security_settings,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from mcp.server.context import ServerRequestContext

_FIXTURE_PROFILE = "official-conformance-fixture"
_MAX_PORT = 65_535
_FIXTURE_TOOLS = (
    "test_logging_tool",
    "test_missing_capability",
    "test_streaming_elicitation",
)


def _fixture_port() -> int:
    """Read only the runner-owned loopback port, defaulting for unit imports."""
    raw = os.environ.get("NPLG_MCP_FIXTURE_PORT", "8000")
    if not raw.isascii() or not raw.isdecimal() or raw.startswith("0"):
        msg = "official conformance fixture port is invalid"
        raise RuntimeError(msg)
    port = int(raw)
    if not 1 <= port <= _MAX_PORT:
        msg = "official conformance fixture port is invalid"
        raise RuntimeError(msg)
    return port


async def _list_tools(
    _context: ServerRequestContext[None, object],
    _params: types.PaginatedRequestParams | None,
) -> types.ListToolsResult:
    """Advertise only the upstream harness diagnostic surface."""
    tools = [_fixture_tool(name) for name in _FIXTURE_TOOLS]
    return types.ListToolsResult(tools=tools, ttl_ms=0, cache_scope="private")


def _fixture_tool(name: str) -> types.Tool:
    """Cross the SDK model edge with one project-typed diagnostic schema."""
    raw: dict[str, object] = {
        "name": name,
        "description": "Official conformance fixture diagnostic tool.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    }
    return types.Tool.model_validate(raw, strict=True)  # type: ignore[misc]


async def _call_tool(
    _context: ServerRequestContext[None, object],
    params: types.CallToolRequestParams,
) -> types.CallToolResult:
    """Implement only diagnostics named by alpha.11's stateless scenario."""
    if params.name == "test_missing_capability":
        data = cast(
            "dict[str, object]",
            MissingRequiredClientCapabilityErrorData(
                required_capabilities=ClientCapabilities(
                    sampling=SamplingCapability(),
                )
            ).model_dump(mode="json", by_alias=True, exclude_none=True),
        )
        raise MCPError(
            code=MISSING_REQUIRED_CLIENT_CAPABILITY,
            message="Required client capability is missing",
            data=data,
        )
    if params.name not in _FIXTURE_TOOLS:
        msg = "official conformance fixture tool is not registered"
        raise RuntimeError(msg)
    return types.CallToolResult(
        content=[types.TextContent(text="Official fixture diagnostic completed.")]
    )


@asynccontextmanager
async def _server_lifespan(_: Server[None]) -> AsyncGenerator[None, None]:
    """Yield no state; the outer fixture lifespan owns the SDK manager."""
    yield None


server = Server(
    "nplg-official-conformance-fixture",
    version="0.1.0",
    title="NPLG Official Conformance Fixture",
    lifespan=_server_lifespan,
    on_list_tools=_list_tools,
    on_call_tool=_call_tool,
)
server.middleware.clear()

_port = _fixture_port()
_config = load_config(
    {
        "NODE_ENV": "test",
        "ASSET_SIGNING_SECRET": "fixture-only-signing-material-0000",
        "CURSOR_SIGNING_SECRET": "fixture-only-cursor-material-00000",
        "PUBLIC_BASE_URL": f"http://127.0.0.1:{_port}",
        "ALLOW_ANONYMOUS": "true",
        "CACHE_DIR": os.devnull,
        "NPLG_MCP_ALLOWED_HOSTS_JSON": f'["127.0.0.1:{_port}"]',
        "NPLG_MCP_ALLOWED_ORIGINS_JSON": "[]",
    }
)
_sdk_app = server.streamable_http_app(
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=False,
    max_request_body_size=_config.mcp_max_body_bytes,
    transport_security=build_transport_security_settings(_config),
)
_secured_sdk_app = McpSecurityMiddleware(_sdk_app, config=_config)


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    """Start exactly one SDK manager before accepting fixture traffic."""
    async with server.session_manager.run():
        _secured_sdk_app.start()
        try:
            yield
        finally:
            await _secured_sdk_app.shutdown()


app = FastAPI(lifespan=_lifespan)
app.state.fixture_profile = _FIXTURE_PROFILE
app.state.mcp_server = server
app.mount("/", _secured_sdk_app)
