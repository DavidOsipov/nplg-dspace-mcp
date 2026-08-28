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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Literal, cast

from mcp import types
from mcp.shared.exceptions import MCPError
from mcp_types import INTERNAL_ERROR, INVALID_PARAMS
from pydantic import StringConstraints, ValidationError, field_validator

from .agent_workflow import (
    AGENT_WORKFLOW_DESCRIPTION,
    AGENT_WORKFLOW_MARKDOWN,
    AGENT_WORKFLOW_MIME_TYPE,
    AGENT_WORKFLOW_NAME,
    AGENT_WORKFLOW_TITLE,
    AGENT_WORKFLOW_URI,
)
from .config import HARD_MAX_INLINE_RESOURCE_BYTES
from .contracts import StrictModel
from .contracts.tool_models import tool_model_bindings
from .errors import (
    AppError,
    ErrorCode,
    InvalidResourceUriError,
    to_public_error,
    validate_resource_uri,
)
from .profiles import DeploymentProfile
from .resource_admission import (
    INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES,
    InlineResourceAdmission,
    inline_blob_response_reservation_bytes,
    inline_text_response_reservation_bytes,
)

if TYPE_CHECKING:
    from mcp.server.context import ServerRequestContext

    from .contracts import StrictOutput
    from .contracts.tool_models import ToolModelBinding
    from .json_types import JsonObject
    from .services import FullServices, MetadataServices

_MAX_VALIDATION_LOCATIONS = 16
_BASE64_VALIDATION_CHUNK_CODE_POINTS = 64 * 1024
_MAX_INLINE_RESOURCE_BASE64_CODE_POINTS = (
    (HARD_MAX_INLINE_RESOURCE_BYTES + 2) // 3
) * 4
_TOOL_SUCCESS_SUMMARY = "Tool completed successfully."


def _binding_for_tool(name: str) -> ToolModelBinding:
    """Return the single reviewed Pydantic model pair for an exact tool name."""
    for binding in tool_model_bindings():
        if binding.name == name:
            return binding
    raise MCPError(
        code=INVALID_PARAMS,
        message="Unknown tool.",
        data={"code": "UNKNOWN_TOOL"},
    )


def _safe_validation_locations(
    binding: ToolModelBinding,
    error: ValidationError,
) -> list[str]:
    """Return only bounded schema-owned top-level validation locations."""
    known_fields = set(binding.input_model.model_fields)
    known_fields.update(
        field.alias
        for field in binding.input_model.model_fields.values()
        if field.alias is not None
    )
    locations: list[str] = []
    raw_errors = cast(
        "list[object]",
        error.errors(include_url=False, include_input=False),
    )
    for raw_error in raw_errors[:_MAX_VALIDATION_LOCATIONS]:
        location = "arguments"
        if isinstance(raw_error, dict):
            fields = cast("dict[object, object]", raw_error)
            raw_location = fields.get("loc")
            if isinstance(raw_location, tuple) and raw_location:
                typed_location = cast("tuple[object, ...]", raw_location)
                first = typed_location[0]
                if type(first) is str and first in known_fields:
                    location = first
        if location not in locations:
            locations.append(location)
    return locations or ["arguments"]


def _tool_error_result(error: AppError) -> types.CallToolResult:
    """Project one bounded project error into the actionable tool channel."""
    public_error = to_public_error(error)
    message = public_error.get("message")
    if not isinstance(message, str):
        message = "The server could not complete the request."
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        structured_content={"error": public_error},
        is_error=True,
    )


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

    @field_validator("text")
    @classmethod
    def _validate_utf8_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > HARD_MAX_INLINE_RESOURCE_BYTES:
            message = "resource text exceeds the inline delivery limit"
            raise ValueError(message)
        return value


class _BlobResourcePayload(StrictModel):
    """Closed service-to-SDK shape for a digest-bound binary resource."""

    uri: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=512)]
    mime_type: Literal["application/json", "application/pdf", "image/jpeg"]
    text: Annotated[str, StringConstraints(strict=True, max_length=4 * 1024 * 1024)]
    blob: Annotated[
        str,
        StringConstraints(
            strict=True,
            min_length=4,
            max_length=_MAX_INLINE_RESOURCE_BASE64_CODE_POINTS,
        ),
    ]
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

    @field_validator("text")
    @classmethod
    def _validate_utf8_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > HARD_MAX_INLINE_RESOURCE_BYTES:
            message = "resource text exceeds the inline delivery limit"
            raise ValueError(message)
        return value


def _validate_blob_identity(
    blob: str,
    *,
    expected_size: int,
    expected_sha256: str,
) -> None:
    if not 1 <= expected_size <= HARD_MAX_INLINE_RESOURCE_BYTES:
        message = "resource exceeds the inline delivery limit"
        raise ValueError(message)
    expected_encoded_length = ((expected_size + 2) // 3) * 4
    if len(blob) != expected_encoded_length:
        message = "resource base64 length binding is invalid"
        raise ValueError(message)
    digest = hashlib.sha256()
    decoded_size = 0
    for offset in range(0, len(blob), _BASE64_VALIDATION_CHUNK_CODE_POINTS):
        chunk = blob[offset : offset + _BASE64_VALIDATION_CHUNK_CODE_POINTS]
        decoded = base64.b64decode(chunk, validate=True)
        if base64.b64encode(decoded).decode("ascii") != chunk:
            message = "resource base64 encoding is not canonical"
            raise ValueError(message)
        decoded_size += len(decoded)
        if decoded_size > expected_size:
            message = "resource size binding is invalid"
            raise ValueError(message)
        digest.update(decoded)
    if decoded_size != expected_size or digest.hexdigest() != expected_sha256:
        message = "resource digest binding is invalid"
        raise ValueError(message)


def _adapt_resource(uri: str, resource: dict[str, str]) -> types.ReadResourceResult:
    """Validate the complete read result before constructing SDK content models."""
    if "blob" in resource:
        blob_payload = _BlobResourcePayload.model_validate(resource, strict=True)
        if blob_payload.uri != uri:
            message = "resource URI binding is invalid"
            raise ValueError(message)
        declared_size = int(blob_payload.size)
        _validate_blob_identity(
            blob_payload.blob,
            expected_size=declared_size,
            expected_sha256=blob_payload.sha256,
        )
        metadata: dict[str, str | int] = {
            "sha256": blob_payload.sha256,
            "size": declared_size,
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


def _resource_response_reservation_bytes(result: types.ReadResourceResult) -> int:
    if len(result.contents) != 1:
        message = "resource response must contain exactly one content item"
        raise ValueError(message)
    content = result.contents[0]
    if isinstance(content, types.BlobResourceContents):
        padding_bytes = len(content.blob) - len(content.blob.rstrip("="))
        decoded_bytes = ((len(content.blob) // 4) * 3) - padding_bytes
        return inline_blob_response_reservation_bytes(
            decoded_bytes=decoded_bytes,
            base64_bytes=len(content.blob),
        )
    return inline_text_response_reservation_bytes(len(content.text.encode("utf-8")))


def _resource_read_reservation_bytes(profile: DeploymentProfile) -> int:
    """Return the exact pre-admission bound for one profile's resource read."""
    if profile is DeploymentProfile.ALPIC_METADATA:
        return inline_text_response_reservation_bytes(
            len(AGENT_WORKFLOW_MARKDOWN.encode("utf-8"))
        )
    return INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES


@dataclass(frozen=True, slots=True)
class SdkHandlers:
    """Closed constructor-bound official SDK handlers for one service composition."""

    services: MetadataServices | FullServices
    profile: DeploymentProfile = DeploymentProfile.ALPIC_METADATA
    resource_admission: InlineResourceAdmission = field(
        default_factory=InlineResourceAdmission,
    )

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
            return _tool_error_result(
                AppError(
                    ErrorCode.INVALID_INPUT,
                    "Tool arguments did not match the declared schema.",
                    safe_details={
                        "locations": _safe_validation_locations(binding, exc),
                    },
                )
            )
        try:
            output = await self.services.tools.call(
                params.name,
                cast("JsonObject", raw_arguments),
            )
            validated_output = binding.output_model.model_validate(output, strict=True)
        except AppError as exc:
            return _tool_error_result(exc)
        except Exception as exc:
            raise MCPError(
                code=INTERNAL_ERROR,
                message="Internal tool error.",
            ) from exc
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=_TOOL_SUCCESS_SUMMARY)],
            structured_content=_serialized_output(validated_output),
        )

    async def on_list_resources(
        self,
        _context: ServerRequestContext[None],
        __: types.PaginatedRequestParams | None,
    ) -> types.ListResourcesResult:
        """Project available resources into explicit SDK resource models."""
        resources: list[types.Resource] = []
        if self.profile is DeploymentProfile.ALPIC_METADATA:
            resources = [
                types.Resource.model_validate(
                    {
                        "uri": AGENT_WORKFLOW_URI,
                        "name": AGENT_WORKFLOW_NAME,
                        "title": AGENT_WORKFLOW_TITLE,
                        "description": AGENT_WORKFLOW_DESCRIPTION,
                        "mimeType": AGENT_WORKFLOW_MIME_TYPE,
                    },
                    strict=True,
                )
            ]
        elif self.profile is DeploymentProfile.PRIVATE_FULL:
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
        if (
            self.profile is DeploymentProfile.ALPIC_METADATA
            and uri != AGENT_WORKFLOW_URI
        ):
            raise MCPError(
                code=INVALID_PARAMS,
                message="Resource not found",
            )
        reservation = self.resource_admission.try_reserve(
            _resource_read_reservation_bytes(self.profile)
        )
        if reservation is None:
            raise MCPError(
                code=INTERNAL_ERROR,
                message="Internal server error",
            )
        try:
            if self.profile is DeploymentProfile.ALPIC_METADATA:
                resource = {
                    "uri": AGENT_WORKFLOW_URI,
                    "mime_type": AGENT_WORKFLOW_MIME_TYPE,
                    "text": AGENT_WORKFLOW_MARKDOWN,
                }
            else:
                resource = await self.services.tools.read_resource(uri)
            result = _adapt_resource(uri, resource)
            reservation.shrink(_resource_response_reservation_bytes(result))
        except AppError as exc:
            if exc.code is ErrorCode.NOT_FOUND:
                raise MCPError(
                    code=INVALID_PARAMS,
                    message="Resource not found",
                    data={"uri": uri},
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
        else:
            return result
        finally:
            if not reservation.request_scoped:
                reservation.release()
