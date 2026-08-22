# Copyright (c) 2026 David Osipov
# mypy: disable-error-code="explicit-any,misc"
"""Narrow typed adaptation from strict services to MCP SDK result models."""

# MCP 2.0.0 exposes protocol-edge dict[str, Any] fields. This is the sole
# project adapter allowed to cross that boundary; strict Pydantic validation
# occurs before service dispatch and before output serialization.
# Upstream: https://github.com/modelcontextprotocol/python-sdk/tree/v2.0.0

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Literal, cast

from mcp import types
from mcp.shared.exceptions import MCPError
from mcp_types import INTERNAL_ERROR, INVALID_PARAMS
from pydantic import StringConstraints, ValidationError

from .contracts import StrictModel
from .contracts.tool_models import tool_model_bindings
from .errors import AppError, ErrorCode, InvalidResourceUriError, validate_resource_uri
from .profiles import DeploymentProfile

if TYPE_CHECKING:
    from mcp.server.context import ServerRequestContext

    from .contracts import StrictOutput
    from .contracts.tool_models import ToolModelBinding
    from .json_types import JsonObject
    from .services import FullServices, MetadataServices


def _binding_for_tool(name: str) -> ToolModelBinding:
    """Return the single reviewed Pydantic model pair for an exact tool name."""
    for binding in tool_model_bindings():
        if binding.name == name:
            return binding
    raise MCPError(code=INVALID_PARAMS, message="Invalid request parameters")


def _serialized_output(value: StrictOutput) -> JsonObject:
    """Serialize a previously strict-validated tool output as an owned JSON object."""
    return cast("JsonObject", value.model_dump(mode="json", by_alias=True))


class _TextResourcePayload(StrictModel):
    """Closed service-to-SDK shape for a text resource."""

    uri: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=512)]
    mime_type: Annotated[
        str,
        StringConstraints(strict=True, min_length=3, max_length=128),
    ]
    text: Annotated[str, StringConstraints(strict=True, max_length=4 * 1024 * 1024)]


class _BlobResourcePayload(StrictModel):
    """Closed service-to-SDK shape for a digest-bound binary resource."""

    uri: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=512)]
    mime_type: Literal["application/json", "application/pdf", "image/jpeg"]
    text: Annotated[str, StringConstraints(strict=True, max_length=4 * 1024 * 1024)]
    blob: Annotated[str, StringConstraints(strict=True, min_length=4)]
    sha256: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"),
    ]
    size: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^[1-9][0-9]{0,19}$"),
    ]
    render_id: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^(|rnd_[0-9a-f]{32})$"),
    ]


def _adapt_resource(uri: str, resource: dict[str, str]) -> types.ReadResourceResult:
    """Validate the complete read result before constructing SDK content models."""
    if "blob" in resource:
        blob_payload = _BlobResourcePayload.model_validate(resource, strict=True)
        if blob_payload.uri != uri:
            message = "resource URI binding is invalid"
            raise ValueError(message)
        raw = base64.b64decode(blob_payload.blob, validate=True)
        if (
            len(raw) != int(blob_payload.size)
            or hashlib.sha256(raw).hexdigest() != blob_payload.sha256
        ):
            message = "resource digest binding is invalid"
            raise ValueError(message)
        metadata: dict[str, str | int] = {
            "sha256": blob_payload.sha256,
            "size": int(blob_payload.size),
        }
        if blob_payload.render_id:
            metadata["renderId"] = blob_payload.render_id
        content: types.TextResourceContents | types.BlobResourceContents = (
            types.BlobResourceContents.model_validate(
                {
                    "uri": uri,
                    "mimeType": blob_payload.mime_type,
                    "blob": blob_payload.blob,
                    "_meta": metadata,
                },
                strict=True,
            )
        )
    else:
        text_payload = _TextResourcePayload.model_validate(resource, strict=True)
        if text_payload.uri != uri:
            message = "resource URI binding is invalid"
            raise ValueError(message)
        content = types.TextResourceContents(
            uri=uri,
            mime_type=text_payload.mime_type,
            text=text_payload.text,
        )
    return types.ReadResourceResult(
        contents=[content],
        ttl_ms=0,
        cache_scope="private",
    )


@dataclass(frozen=True, slots=True)
class SdkHandlers:
    """Closed constructor-bound official SDK handlers for one service composition."""

    services: MetadataServices | FullServices
    profile: DeploymentProfile = DeploymentProfile.ALPIC_METADATA

    async def on_list_tools(
        self,
        _context: ServerRequestContext[None],
        __: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        """Project the immutable catalog into explicit SDK tool models."""
        tools = [
            types.Tool.model_validate(tool, strict=True)
            for tool in self.services.tools.list_tools()
        ]
        return types.ListToolsResult(tools=tools, ttl_ms=0, cache_scope="private")

    async def on_call_tool(
        self,
        _context: ServerRequestContext[None],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        """Strictly validate raw arguments before dispatch and validate output again."""
        binding = _binding_for_tool(params.name)
        raw_arguments = {} if params.arguments is None else params.arguments
        try:
            _ = binding.input_model.model_validate(
                raw_arguments,
                strict=True,
            )
        except ValidationError as exc:
            raise MCPError(
                code=INVALID_PARAMS,
                message="Invalid request parameters",
            ) from exc
        output = await self.services.tools.call(
            params.name,
            cast("JsonObject", raw_arguments),
        )
        try:
            validated_output = binding.output_model.model_validate(output, strict=True)
        except ValidationError as exc:
            raise MCPError(
                code=INTERNAL_ERROR,
                message="Internal server error",
            ) from exc
        return types.CallToolResult(
            content=[],
            structured_content=_serialized_output(validated_output),
        )

    async def on_list_resources(
        self,
        _context: ServerRequestContext[None],
        __: types.PaginatedRequestParams | None,
    ) -> types.ListResourcesResult:
        """Project available resources into explicit SDK resource models."""
        resources = [
            types.Resource.model_validate(resource, strict=True)
            for resource in self.services.tools.list_resources()
        ]
        return types.ListResourcesResult(
            resources=resources,
            ttl_ms=0,
            cache_scope="private",
        )

    async def on_list_resource_templates(
        self,
        _context: ServerRequestContext[None],
        __: types.PaginatedRequestParams | None,
    ) -> types.ListResourceTemplatesResult:
        """Advertise only canonical local-resource templates in full profiles."""
        templates: list[types.ResourceTemplate] = []
        if self.profile is DeploymentProfile.PRIVATE_FULL:
            templates = [
                types.ResourceTemplate(
                    name="Private content-addressed artifact",
                    title="Read a private NPLG artifact",
                    uri_template="nplg://artifact/{artifact_id}",
                    description=(
                        "Read one authorized content-addressed PDF, rendered "
                        "JPEG, or tile manifest by its canonical project identifier."
                    ),
                    mime_type="application/octet-stream",
                ),
                types.ResourceTemplate(
                    name="Private render manifest",
                    title="Read a private NPLG render manifest",
                    uri_template="nplg://render/{render_id}/manifest",
                    description=(
                        "Read one authorized bounded render manifest by its "
                        "canonical project identifier."
                    ),
                    mime_type="application/json",
                ),
            ]
        return types.ListResourceTemplatesResult(
            resource_templates=templates,
            ttl_ms=0,
            cache_scope="private",
        )

    async def on_read_resource(
        self,
        _context: ServerRequestContext[None],
        params: types.ReadResourceRequestParams,
    ) -> types.ReadResourceResult:
        """Validate and adapt one resource without leaking lookup failures."""
        try:
            uri = validate_resource_uri(params.uri)
        except InvalidResourceUriError as exc:
            raise MCPError(
                code=INVALID_PARAMS,
                message="Invalid request parameters",
            ) from exc
        try:
            resource = await self.services.tools.read_resource(uri)
            return _adapt_resource(uri, resource)
        except AppError as exc:
            if exc.code is ErrorCode.NOT_FOUND:
                data = (
                    {"uri": uri}
                    if self.profile is DeploymentProfile.PRIVATE_FULL
                    else None
                )
                raise MCPError(
                    code=INVALID_PARAMS,
                    message="Resource not found",
                    data=data,
                ) from exc
            raise MCPError(
                code=INTERNAL_ERROR,
                message="Internal server error",
            ) from exc
        except Exception as exc:
            raise MCPError(
                code=INTERNAL_ERROR,
                message="Internal server error",
            ) from exc
