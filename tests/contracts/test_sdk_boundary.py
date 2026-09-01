# Copyright (c) 2026 David Osipov
# mypy: disable-error-code="explicit-any,misc"
"""Adversarial contracts for the narrow official MCP SDK boundary."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Never, cast, override

import pytest
from mcp import Client, types
from mcp.shared.exceptions import MCPError
from pydantic import ValidationError

from nplg_mcp import sdk_boundary
from nplg_mcp.agent_workflow import (
    AGENT_WORKFLOW_MARKDOWN,
    AGENT_WORKFLOW_MIME_TYPE,
    AGENT_WORKFLOW_URI,
)
from nplg_mcp.config import HARD_MAX_INLINE_RESOURCE_BYTES
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.mcp_server import create_mcp_server
from nplg_mcp.profiles import DeploymentProfile
from nplg_mcp.resource_admission import (
    InlineResourceAdmission,
    inline_text_response_reservation_bytes,
)
from nplg_mcp.sdk_boundary import SdkHandlers
from nplg_mcp.services import FullServiceComposition, MetadataServiceComposition

if TYPE_CHECKING:
    from mcp.server.context import ServerRequestContext

    from nplg_mcp.contracts import StrictOutput
    from nplg_mcp.json_types import JsonObject
    from nplg_mcp.services import ToolSurface
    from nplg_mcp.tools import ToolService


INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
_EXPECTED_BASE64_VALIDATION_CHUNK_CODE_POINTS = 64 * 1024
_EXPECTED_ADMITTED_RESOURCE_READS = 2


def _call_log() -> list[tuple[str, JsonObject]]:
    """Create one precisely typed empty call log."""
    return []


def _resource_read_log() -> list[str]:
    """Create one precisely typed empty resource-read log."""
    return []


def _resource_list_log() -> list[None]:
    """Create one precisely typed empty resource-list log."""
    return []


def _resource_payload() -> dict[str, str]:
    """Create one precisely typed empty resource payload."""
    return {}


@dataclass(slots=True)
class RecordingTools:
    """Tool surface wrapper that exposes whether the SDK boundary dispatched."""

    delegate: ToolSurface
    calls: list[tuple[str, JsonObject]] = field(default_factory=_call_log)
    resource_reads: list[str] = field(default_factory=_resource_read_log)
    resource_lists: list[None] = field(default_factory=_resource_list_log)

    def list_tools(self) -> list[JsonObject]:
        """Return the delegate catalog unchanged."""
        return self.delegate.list_tools()

    async def call(self, name: str, arguments: JsonObject) -> StrictOutput | JsonObject:
        """Record a handler entry before calling the strict delegate."""
        self.calls.append((name, arguments))
        return await self.delegate.call(name, arguments)

    def list_resources(self) -> list[JsonObject]:
        """Return the delegate resources unchanged."""
        self.resource_lists.append(None)
        return self.delegate.list_resources()

    async def read_resource(self, uri: str) -> dict[str, str]:
        """Return the delegate resource unchanged."""
        self.resource_reads.append(uri)
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
class DomainErrorTools(RecordingTools):
    """Raise one expected project-owned domain error after handler entry."""

    @override
    async def call(self, name: str, arguments: JsonObject) -> StrictOutput | JsonObject:
        self.calls.append((name, arguments))
        raise AppError(
            ErrorCode.UPSTREAM_FAILURE,
            "The upstream repository is temporarily unavailable.",
            http_status=502,
            internal_details={"canary": "domain-private-canary"},
        )


@dataclass(slots=True)
class UnexpectedErrorTools(RecordingTools):
    """Raise one unexpected canary-bearing exception after handler entry."""

    @override
    async def call(self, name: str, arguments: JsonObject) -> StrictOutput | JsonObject:
        self.calls.append((name, arguments))
        message = "unexpected-private-canary"
        raise RuntimeError(message)


@dataclass(slots=True)
class ResourcePayloadTools(RecordingTools):
    """Return one deliberately controlled service resource payload."""

    resource: dict[str, str] = field(default_factory=_resource_payload)

    @override
    async def read_resource(self, uri: str) -> dict[str, str]:
        """Return an owned copy so adaptation cannot mutate the fixture."""
        self.resource_reads.append(uri)
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
    """Known-tool validation is an actionable tool result before service entry."""
    tools = RecordingTools(tool_service)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.CallToolRequestParams(name="search_documents", arguments=arguments)

    result = await handlers.on_call_tool(_context(), params)

    assert result.is_error is True
    assert result.structured_content is None
    assert "structuredContent" not in result.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    assert len(result.content) == 1
    assert isinstance(result.content[0], types.TextContent)
    assert result.content[0].text == "Tool arguments did not match the declared schema."
    assert tools.calls == []


@pytest.mark.asyncio
async def test_sdk_boundary_does_not_inspect_untrusted_validation_diagnostics(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dependency diagnostics are unnecessary and never enter the error path."""
    tools = RecordingTools(tool_service)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.CallToolRequestParams(
        name="search_documents",
        arguments={"query": 1},
    )

    def forbidden_errors(
        _error: ValidationError,
        *,
        include_url: bool = True,
        include_context: bool = True,
        include_input: bool = True,
    ) -> list[object]:
        _ = include_url, include_context, include_input
        pytest.fail("validation diagnostics must not be inspected")

    monkeypatch.setattr(ValidationError, "errors", forbidden_errors)

    result = await handlers.on_call_tool(_context(), params)

    assert result.is_error is True
    assert result.structured_content is None
    assert "structuredContent" not in result.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    assert len(result.content) == 1
    assert isinstance(result.content[0], types.TextContent)
    assert result.content[0].text == (
        "Tool arguments did not match the declared schema."
    )
    assert tools.calls == []


@pytest.mark.asyncio
async def test_sdk_boundary_uses_fallback_text_for_malformed_public_error_message(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed public-error projection cannot enter SDK text content."""
    tools = RecordingTools(tool_service)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.CallToolRequestParams(
        name="search_documents",
        arguments={"query": 1},
    )

    def malformed_public_error(_error: BaseException) -> JsonObject:
        return {
            "code": ErrorCode.INTERNAL_ERROR.value,
            "message": 7,
        }

    monkeypatch.setattr(sdk_boundary, "to_public_error", malformed_public_error)

    result = await handlers.on_call_tool(_context(), params)

    assert result.is_error is True
    assert result.structured_content is None
    assert "structuredContent" not in result.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    assert len(result.content) == 1
    content = result.content[0]
    assert isinstance(content, types.TextContent)
    assert content.text == "The server could not complete the request."
    assert tools.calls == []


@pytest.mark.asyncio
async def test_sdk_boundary_uses_exact_protocol_error_for_unknown_tool(
    tool_service: ToolService,
) -> None:
    """An unknown tool is a sanitized protocol error and never enters services."""
    tools = RecordingTools(tool_service)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.CallToolRequestParams(
        name="attacker-controlled-unknown-tool",
        arguments={},
    )

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_call_tool(_context(), params)

    assert captured.value.error.code == INVALID_PARAMS
    assert captured.value.error.message == "Unknown tool."
    assert captured.value.error.data == {"code": "UNKNOWN_TOOL"}
    assert "attacker-controlled" not in str(
        captured.value.error.model_dump(mode="json")
    )
    assert tools.calls == []


@pytest.mark.asyncio
async def test_sdk_boundary_returns_expected_domain_error_as_tool_result(
    tool_service: ToolService,
) -> None:
    """An actionable AppError stays in the tool-result channel without private data."""
    tools = DomainErrorTools(tool_service)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.CallToolRequestParams(
        name="search_documents",
        arguments={"query": "fixture"},
    )

    result = await handlers.on_call_tool(_context(), params)

    assert result.is_error is True
    assert result.structured_content is None
    assert "structuredContent" not in result.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    assert len(result.content) == 1
    assert isinstance(result.content[0], types.TextContent)
    assert result.content[0].text == (
        "The upstream repository is temporarily unavailable."
    )
    assert "domain-private-canary" not in str(
        result.model_dump(mode="json", by_alias=True)
    )
    assert tools.calls == [("search_documents", {"query": "fixture"})]


@pytest.mark.asyncio
async def test_sdk_boundary_sanitizes_unexpected_tool_exception(
    tool_service: ToolService,
) -> None:
    """Unexpected tool failures use the project-owned internal protocol error."""
    tools = UnexpectedErrorTools(tool_service)
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.CallToolRequestParams(
        name="search_documents",
        arguments={"query": "fixture"},
    )

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_call_tool(_context(), params)

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal tool error."
    assert captured.value.error.data is None
    assert "unexpected-private-canary" not in str(
        captured.value.error.model_dump(mode="json")
    )
    assert tools.calls == [("search_documents", {"query": "fixture"})]


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
    assert captured.value.error.message == "Internal tool error."
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
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )
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
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )
    params = types.ReadResourceRequestParams(uri=requested_uri)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(_context(), params)

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"


@pytest.mark.asyncio
async def test_sdk_boundary_rejects_blob_encoded_length_mismatch_before_decode(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An impossible encoded length is rejected without decoding attacker data."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    resource = _blob_resource(requested_uri)
    resource["size"] = str(int(resource["size"]) + 2)
    tools = ResourcePayloadTools(tool_service, resource=resource)
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )
    decode_called = False
    real_decode = base64.b64decode

    def measured_decode(value: str, *, validate: bool) -> bytes:
        nonlocal decode_called
        decode_called = True
        return real_decode(value, validate=validate)

    monkeypatch.setattr(base64, "b64decode", measured_decode)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            _context(),
            types.ReadResourceRequestParams(uri=requested_uri),
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"
    assert decode_called is False


@pytest.mark.asyncio
async def test_sdk_boundary_stops_before_hashing_decoded_size_overflow(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Decoded bytes exceeding the declaration are rejected before hashing."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    tools = ResourcePayloadTools(
        tool_service,
        resource={
            "uri": requested_uri,
            "mime_type": "image/jpeg",
            "text": "",
            "blob": "Zm9v",
            "sha256": "0" * 64,
            "size": "1",
            "render_id": "",
        },
    )
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )

    class HashingMustNotStart:
        def update(self, _decoded: bytes) -> None:
            pytest.fail("oversize decoded bytes reached the digest")

        def hexdigest(self) -> str:
            return "0" * 64

    def rejecting_sha256() -> HashingMustNotStart:
        return HashingMustNotStart()

    monkeypatch.setattr(hashlib, "sha256", rejecting_sha256)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            _context(),
            types.ReadResourceRequestParams(uri=requested_uri),
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"


@pytest.mark.asyncio
async def test_sdk_boundary_rejects_oversize_blob_declaration_before_decode(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    resource = _blob_resource(requested_uri)
    resource["size"] = str(HARD_MAX_INLINE_RESOURCE_BYTES + 1)
    tools = ResourcePayloadTools(tool_service, resource=resource)
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )
    params = types.ReadResourceRequestParams(uri=requested_uri)
    decode_called = False

    def reject_decode(_value: str, *, validate: bool) -> bytes:
        nonlocal decode_called
        _ = validate
        decode_called = True
        pytest.fail("oversize blob was decoded")

    monkeypatch.setattr(base64, "b64decode", reject_decode)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(_context(), params)

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"
    assert decode_called is False


@pytest.mark.asyncio
async def test_sdk_boundary_rejects_text_over_utf8_byte_limit(
    tool_service: ToolService,
) -> None:
    """Multibyte text cannot exceed the byte-denominated inline ceiling."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    over_limit = "🙂" * ((HARD_MAX_INLINE_RESOURCE_BYTES // 4) + 1)
    tools = ResourcePayloadTools(
        tool_service,
        resource={
            "uri": requested_uri,
            "mime_type": "application/json",
            "text": over_limit,
        },
    )
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            _context(),
            types.ReadResourceRequestParams(uri=requested_uri),
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"


@pytest.mark.asyncio
async def test_sdk_boundary_rejects_blob_text_over_utf8_byte_limit(
    tool_service: ToolService,
) -> None:
    """Unused blob text cannot bypass the byte-denominated inline ceiling."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    resource = _blob_resource(requested_uri)
    resource["text"] = "🙂" * ((HARD_MAX_INLINE_RESOURCE_BYTES // 4) + 1)
    tools = ResourcePayloadTools(tool_service, resource=resource)
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            _context(),
            types.ReadResourceRequestParams(uri=requested_uri),
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"


@pytest.mark.asyncio
async def test_sdk_boundary_accepts_text_at_exact_utf8_byte_limit(
    tool_service: ToolService,
) -> None:
    """The byte ceiling remains inclusive for exact multibyte content."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    exact_limit = "🙂" * (HARD_MAX_INLINE_RESOURCE_BYTES // 4)
    tools = ResourcePayloadTools(
        tool_service,
        resource={
            "uri": requested_uri,
            "mime_type": "application/json",
            "text": exact_limit,
        },
    )
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )

    result = await handlers.on_read_resource(
        _context(),
        types.ReadResourceRequestParams(uri=requested_uri),
    )

    assert len(result.contents) == 1
    content = result.contents[0]
    assert isinstance(content, types.TextResourceContents)
    assert len(content.text.encode("utf-8")) == HARD_MAX_INLINE_RESOURCE_BYTES


@pytest.mark.asyncio
async def test_sdk_boundary_rejects_noncanonical_base64_pad_bits(
    tool_service: ToolService,
) -> None:
    """Equivalent but noncanonical RFC 4648 spellings fail closed."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    raw = b"f"
    tools = ResourcePayloadTools(
        tool_service,
        resource={
            "uri": requested_uri,
            "mime_type": "image/jpeg",
            "text": "",
            "blob": "Zh==",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": "1",
            "render_id": "",
        },
    )
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            _context(),
            types.ReadResourceRequestParams(uri=requested_uri),
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"


@pytest.mark.asyncio
async def test_sdk_boundary_accepts_canonical_one_byte_base64(
    tool_service: ToolService,
) -> None:
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    raw = b"f"
    tools = ResourcePayloadTools(
        tool_service,
        resource={
            "uri": requested_uri,
            "mime_type": "image/jpeg",
            "text": "",
            "blob": "Zg==",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": "1",
            "render_id": "",
        },
    )
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )

    result = await handlers.on_read_resource(
        _context(),
        types.ReadResourceRequestParams(uri=requested_uri),
    )

    assert len(result.contents) == 1
    content = result.contents[0]
    assert isinstance(content, types.BlobResourceContents)
    assert content.blob == "Zg=="


@pytest.mark.asyncio
async def test_sdk_boundary_rejects_multiple_adapted_resource_contents(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compromised adapter cannot reserve or publish an ambiguous response."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    tools = ResourcePayloadTools(
        tool_service,
        resource={
            "uri": requested_uri,
            "mime_type": "application/json",
            "text": "{}",
        },
    )
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )

    def multiple_contents(
        uri: str,
        _resource: dict[str, str],
    ) -> types.ReadResourceResult:
        content = types.TextResourceContents(
            uri=uri,
            mime_type="application/json",
            text="{}",
        )
        return types.ReadResourceResult(
            contents=[content, content],
            ttl_ms=0,
            cache_scope="private",
        )

    monkeypatch.setattr(sdk_boundary, "_adapt_resource", multiple_contents)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            _context(),
            types.ReadResourceRequestParams(uri=requested_uri),
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"


@pytest.mark.asyncio
async def test_resource_response_admission_rejects_third_maximum_reader(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Maximum-size response work is rejected before a third service read."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    tools = ResourcePayloadTools(
        tool_service,
        resource={
            "uri": requested_uri,
            "mime_type": "application/json",
            "text": "{}",
        },
    )
    release = asyncio.Event()
    two_entered = asyncio.Event()
    entered: list[str] = []

    async def blocking_read(
        _tools: ResourcePayloadTools,
        uri: str,
    ) -> dict[str, str]:
        entered.append(uri)
        if len(entered) >= _EXPECTED_ADMITTED_RESOURCE_READS:
            two_entered.set()
        _ = await release.wait()
        return dict(tools.resource)

    monkeypatch.setattr(ResourcePayloadTools, "read_resource", blocking_read)
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )
    params = types.ReadResourceRequestParams(uri=requested_uri)
    tasks = [
        asyncio.create_task(handlers.on_read_resource(_context(), params))
        for _ in range(3)
    ]
    try:
        async with asyncio.timeout(1):
            _ = await two_entered.wait()
        await asyncio.sleep(0)
        calls_before_release = len(entered)
    finally:
        release.set()
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)

    assert calls_before_release == _EXPECTED_ADMITTED_RESOURCE_READS
    failures = [outcome for outcome in outcomes if isinstance(outcome, MCPError)]
    assert len(failures) == 1
    assert failures[0].error.code == INTERNAL_ERROR
    assert failures[0].error.message == "Internal server error"


@pytest.mark.asyncio
async def test_sdk_boundary_validates_blob_digest_in_bounded_decode_chunks(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    raw = b"x" * (_EXPECTED_BASE64_VALIDATION_CHUNK_CODE_POINTS * 2)
    resource = {
        "uri": requested_uri,
        "mime_type": "image/jpeg",
        "text": "",
        "blob": base64.b64encode(raw).decode("ascii"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": str(len(raw)),
        "render_id": "",
    }
    tools = ResourcePayloadTools(tool_service, resource=resource)
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )
    params = types.ReadResourceRequestParams(uri=requested_uri)
    real_decode = base64.b64decode
    maximum_decode_input = 0

    def measured_decode(value: str, *, validate: bool) -> bytes:
        nonlocal maximum_decode_input
        maximum_decode_input = max(maximum_decode_input, len(value))
        return real_decode(value, validate=validate)

    monkeypatch.setattr(base64, "b64decode", measured_decode)

    result = await handlers.on_read_resource(_context(), params)

    assert len(result.contents) == 1
    assert maximum_decode_input <= _EXPECTED_BASE64_VALIDATION_CHUNK_CODE_POINTS


@pytest.mark.asyncio
async def test_sdk_boundary_omits_empty_render_provenance_metadata(
    tool_service: ToolService,
) -> None:
    """A non-render artifact must not invent an empty render provenance value."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    resource = _blob_resource(requested_uri)
    tools = ResourcePayloadTools(tool_service, resource=resource)
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.PRIVATE_FULL,
    )
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


@pytest.mark.asyncio
async def test_private_full_server_registers_resource_handlers(
    tool_service: ToolService,
) -> None:
    """Private-full retains its resource capability and resource catalog."""
    services = FullServiceComposition(tools=tool_service, store=tool_service.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)

    async with Client(server, mode="2026-07-28") as client:
        resources = await client.list_resources()

    assert [resource.uri for resource in resources.resources] == ["nplg://about"]


@pytest.mark.asyncio
async def test_metadata_boundary_serves_static_workflow_without_service_entry(
    tool_service: ToolService,
) -> None:
    """The metadata resource is immutable and independent of private services."""
    tools = ResourcePayloadTools(
        tool_service,
        resource={"uri": AGENT_WORKFLOW_URI, "mime_type": "text/plain", "text": "bad"},
    )
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))

    listed = await handlers.on_list_resources(_context(), None)
    read = await handlers.on_read_resource(
        _context(),
        types.ReadResourceRequestParams(uri=AGENT_WORKFLOW_URI),
    )

    assert [resource.uri for resource in listed.resources] == [AGENT_WORKFLOW_URI]
    assert len(read.contents) == 1
    content = read.contents[0]
    assert isinstance(content, types.TextResourceContents)
    assert content.uri == AGENT_WORKFLOW_URI
    assert content.mime_type == AGENT_WORKFLOW_MIME_TYPE
    assert content.text == AGENT_WORKFLOW_MARKDOWN
    assert tools.resource_reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["list", "templates", "read"])
async def test_sdk_boundary_rejects_disabled_resource_profile_before_dispatch(
    tool_service: ToolService,
    monkeypatch: pytest.MonkeyPatch,
    handler: Literal["list", "templates", "read"],
) -> None:
    """Disabled profiles cannot list or read resources through any SDK handler."""
    tools = RecordingTools(tool_service)
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=tool_service.store),
        DeploymentProfile.DISTRIBUTED_FULL,
    )

    def reject_resource_admission(
        _admission: InlineResourceAdmission,
        _requested_bytes: int,
    ) -> Never:
        message = "resource admission must not start"
        raise AssertionError(message)

    async def invoke_resource_handler() -> None:
        if handler == "list":
            _ = await handlers.on_list_resources(_context(), None)
        elif handler == "templates":
            _ = await handlers.on_list_resource_templates(_context(), None)
        else:
            _ = await handlers.on_read_resource(
                _context(),
                types.ReadResourceRequestParams(uri="nplg://about"),
            )

    monkeypatch.setattr(
        InlineResourceAdmission,
        "try_reserve",
        reject_resource_admission,
    )

    with pytest.raises(RuntimeError, match=r"^Invalid deployment profile\.$"):
        await invoke_resource_handler()

    assert tools.calls == []
    assert tools.resource_lists == []
    assert tools.resource_reads == []


@pytest.mark.asyncio
async def test_metadata_workflow_reserves_only_its_fixed_response_bound(
    tool_service: ToolService,
) -> None:
    """A small immutable workflow must not consume the 4 MiB blob headroom."""
    required_bytes = inline_text_response_reservation_bytes(
        len(AGENT_WORKFLOW_MARKDOWN.encode("utf-8"))
    )
    admission = InlineResourceAdmission(capacity_bytes=required_bytes)
    handlers = SdkHandlers(
        MetadataServiceComposition(tools=tool_service),
        resource_admission=admission,
    )

    result = await handlers.on_read_resource(
        _context(),
        types.ReadResourceRequestParams(uri=AGENT_WORKFLOW_URI),
    )

    assert len(result.contents) == 1
    assert admission.active_bytes == 0


@pytest.mark.asyncio
async def test_metadata_workflow_fails_closed_below_its_response_bound(
    tool_service: ToolService,
) -> None:
    required_bytes = inline_text_response_reservation_bytes(
        len(AGENT_WORKFLOW_MARKDOWN.encode("utf-8"))
    )
    admission = InlineResourceAdmission(capacity_bytes=required_bytes - 1)
    handlers = SdkHandlers(
        MetadataServiceComposition(tools=tool_service),
        resource_admission=admission,
    )

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(
            _context(),
            types.ReadResourceRequestParams(uri=AGENT_WORKFLOW_URI),
        )

    assert captured.value.error.code == INTERNAL_ERROR
    assert captured.value.error.message == "Internal server error"
    assert admission.active_bytes == 0


@pytest.mark.asyncio
async def test_metadata_boundary_rejects_resource_reads_before_service_entry(
    tool_service: ToolService,
) -> None:
    """Metadata profile cannot adapt resources even from an untrusted service."""
    requested_uri = "nplg://artifact/doc_" + "0" * 64
    tools = ResourcePayloadTools(tool_service, resource=_blob_resource(requested_uri))
    handlers = SdkHandlers(MetadataServiceComposition(tools=tools))
    params = types.ReadResourceRequestParams(uri=requested_uri)

    with pytest.raises(MCPError) as captured:
        _ = await handlers.on_read_resource(_context(), params)

    assert captured.value.error.code == INVALID_PARAMS
    assert captured.value.error.message == "Resource not found"
    assert tools.resource_reads == []


def test_runtime_manifests_pin_the_official_sdk_transport_stack() -> None:
    """Application and lock inputs make MCP's distinct HTTPX2 stack explicit."""
    requirements = Path("requirements.in").read_text(encoding="utf-8")
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    expected = {
        "mcp==2.1.1",
        "mcp-types==2.1.1",
        "httpx2==2.12.0",
        "httpcore2==2.12.0",
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
