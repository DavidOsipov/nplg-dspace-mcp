# Copyright (c) 2026 David Osipov
# mypy: disable-error-code="misc"
"""Official MCP SDK server construction for the NPLG service boundary."""

# MCP 2.0.0's low-level Server registration keeps a generic request payload as
# Any. Handler values cross that vendor-owned edge only here and in the strict
# SdkHandlers adapter. Upstream: https://github.com/modelcontextprotocol/python-sdk/tree/v2.0.0

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from mcp.server import Server

from .sdk_boundary import SdkHandlers

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from .profiles import DeploymentProfile
    from .services import FullServices, MetadataServices

_SERVER_NAME = "nplg-dspace-mcp"
_SERVER_VERSION = "0.1.0"
_SERVER_TITLE = "NPLG DSpace MCP"


@asynccontextmanager
async def _server_lifespan(_: Server[None]) -> AsyncGenerator[None, None]:
    """Yield no SDK-owned state because the outer application owns resources."""
    yield None


def create_mcp_server(
    services: MetadataServices | FullServices,
    profile: DeploymentProfile,
) -> Server[None]:
    """Bind strict service handlers to the official low-level MCP server API."""
    handlers = SdkHandlers(services, profile)
    server = Server(
        _SERVER_NAME,
        version=_SERVER_VERSION,
        title=_SERVER_TITLE,
        lifespan=_server_lifespan,
        on_list_tools=handlers.on_list_tools,
        on_call_tool=handlers.on_call_tool,
        on_list_resources=handlers.on_list_resources,
        on_list_resource_templates=handlers.on_list_resource_templates,
        on_read_resource=handlers.on_read_resource,
    )
    # The SDK enables OpenTelemetryMiddleware by default. It may capture exception
    # text and ambient tracing context, neither of which is an approved NPLG channel.
    server.middleware.clear()
    return server
