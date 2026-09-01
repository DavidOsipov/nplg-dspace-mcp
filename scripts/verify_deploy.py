#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Verify a deployed NPLG MCP without depending on the project package."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import os
import sys
import unicodedata
from contextlib import redirect_stderr, redirect_stdout, suppress
from dataclasses import dataclass, field
from http import HTTPStatus
from http.client import (
    HTTPConnection,
    HTTPException,
    HTTPResponse,
    HTTPSConnection,
    IncompleteRead,
)
from pathlib import Path
from time import monotonic, sleep
from typing import TYPE_CHECKING, Literal, Protocol, cast
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import TextIO, TypeGuard

PROTOCOL = "2026-07-28"
ALPIC_GATEWAY_PROTOCOL = "2025-11-25"
ALPIC_METADATA_TOOLS: frozenset[str] = frozenset(
    {
        "get_document_metadata",
        "list_document_files",
        "search_documents",
    }
)
PRIVATE_FULL_TOOLS: frozenset[str] = frozenset(
    {
        "download_document_file",
        "get_document_metadata",
        "get_render_manifest",
        "inspect_pdf",
        "list_document_files",
        "render_pdf_page_tiles",
        "render_pdf_pages",
        "search_documents",
    }
)
EXPECTED_TOOLS: frozenset[str] = ALPIC_METADATA_TOOLS
AGENT_WORKFLOW_URI = "nplg://skills/georgian-newspaper-visual-analysis"
AGENT_WORKFLOW_NAME = "Georgian newspaper visual analysis"
AGENT_WORKFLOW_MIME_TYPE = "text/markdown"
AGENT_WORKFLOW_TITLE = "Client-side Georgian newspaper visual analysis"
AGENT_WORKFLOW_DESCRIPTION = (
    "Bounded instructions for retrieving one public NPLG PDF and inspecting it "
    "in the client environment."
)
AGENT_WORKFLOW_SHA256 = (
    "dbd7f1df2f41e424e8bda6e55ea54bb65033beefc6bc7fecb7032a6519edb3d6"
)
METADATA_DISCOVERY_INSTRUCTIONS = (
    "This anonymous server exposes three read-only NPLG metadata tools. "
    f"Resource-capable clients should list and read {AGENT_WORKFLOW_URI} before "
    "retrieving a public PDF URL; all PDF processing remains client-side."
)
METHOD_NOT_FOUND = -32601
SERVER_NAME = "nplg-dspace-mcp"
SERVER_TITLE = "NPLG DSpace MCP"
SERVER_VERSION = "0.1.0"
MAX_AGENT_WORKFLOW_BYTES = 16 * 1024
_AGENT_WORKFLOW_REQUIRED_MARKERS: tuple[str, ...] = (
    "name: georgian-newspaper-visual-analysis",
    "`search_documents`",
    "`get_document_metadata`",
    "`list_document_files`",
    "`access_status`",
    "exactly `public`",
    "exact returned `source_url`",
    "bounded",
    "client-controlled local",
    "local SHA-256",
    "untrusted data",
    "prompt injection",
    "OCR is not authoritative",
    "stop at metadata",
)
_AGENT_WORKFLOW_FORBIDDEN_OPERATIONS: tuple[str, ...] = (
    "download_document_file",
    "inspect_pdf",
    "render_pdf_pages",
    "render_pdf_page_tiles",
    "get_render_manifest",
    "delete_render",
)
_ALLOWED_WORKFLOW_CONTROLS = frozenset({"\t", "\n", "\r"})
CACHE_WRITING_TOOLS: frozenset[str] = frozenset(
    {
        "download_document_file",
        "render_pdf_pages",
        "render_pdf_page_tiles",
    }
)
MAX_RESPONSE_BYTES = 1_048_576
MAX_SESSION_ID_BYTES = 1_024
MAX_CANONICAL_OUTPUT_BYTES = 65_536
MAX_SSE_EVENTS = 256
MAX_SSE_EVENT_ID_BYTES = 1_024
MAX_SSE_RETRY_DIGITS = 10
MAX_SSE_RESUME_ATTEMPTS = 8
MAX_SSE_SERVER_REQUESTS = 4
MAX_SSE_SESSION_EVENT_IDS = 4_096
MAX_REQUEST_TIMEOUT_SECONDS = 10_000.0
MILLISECONDS_PER_SECOND = 1_000
_HTTP_LOCAL_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_LOGGING_LEVELS: frozenset[str] = frozenset(
    {
        "alert",
        "critical",
        "debug",
        "emergency",
        "error",
        "info",
        "notice",
        "warning",
    }
)
_ASCII_PRINTABLE_MIN = 0x20
_ASCII_PRINTABLE_MAX = 0x7E
_SESSION_ASCII_MIN = 0x21
_SSE_LINE_FEED = 0x0A
_SSE_CARRIAGE_RETURN = 0x0D
_SSE_BYTE_ORDER_MARK = b"\xef\xbb\xbf"
_SURROGATE_MIN = 0xD800
_SURROGATE_MAX = 0xDFFF

type JsonPrimitive = bool | int | float | str | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
type JsonRpcRequestId = int | str
type DeploymentProfile = Literal["alpic-metadata", "private-full"]
type RpcMode = Literal["normal", "initialize", "discover"]


class _SocketTimeoutSetter(Protocol):
    """Narrow the untyped stdlib HTTP connection socket boundary."""

    def settimeout(self, value: float | None, /) -> None:
        """Set the maximum duration of the next blocking socket operation."""


_EXPECTED_METADATA_CAPABILITIES: JsonObject = {
    "resources": {"listChanged": False, "subscribe": False},
    "tools": {"listChanged": False},
}
_EXPECTED_AGENT_WORKFLOW_DESCRIPTOR: JsonObject = {
    "uri": AGENT_WORKFLOW_URI,
    "name": AGENT_WORKFLOW_NAME,
    "title": AGENT_WORKFLOW_TITLE,
    "description": AGENT_WORKFLOW_DESCRIPTION,
    "mimeType": AGENT_WORKFLOW_MIME_TYPE,
}
_EXPECTED_SERVER_META: JsonObject = {
    "io.modelcontextprotocol/serverInfo": {
        "name": SERVER_NAME,
        "title": SERVER_TITLE,
        "version": SERVER_VERSION,
    }
}
_EXPECTED_SERVER_INFO: JsonObject = {
    "name": SERVER_NAME,
    "title": SERVER_TITLE,
    "version": SERVER_VERSION,
}

DEPLOYMENT_PROFILES: tuple[DeploymentProfile, ...] = (
    "alpic-metadata",
    "private-full",
)
EXPECTED_TOOLS_BY_PROFILE: dict[DeploymentProfile, frozenset[str]] = {
    "alpic-metadata": ALPIC_METADATA_TOOLS,
    "private-full": PRIVATE_FULL_TOOLS,
}
_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_BASELINE_TOOL_CATALOG = (
    _REPOSITORY_ROOT / "contracts" / "baseline" / "tool-catalog.json"
)
_BASELINE_MANIFEST = _REPOSITORY_ROOT / "contracts" / "baseline" / "manifest.json"
_GENERATED_CONTRACT_SCHEMA = (
    _REPOSITORY_ROOT / "contracts" / "generated" / "tool-contracts.schema.json"
)
_GENERATED_CONTRACT_MANIFEST = (
    _REPOSITORY_ROOT / "contracts" / "generated" / "schema-manifest.json"
)
_OUTPUT_SCHEMA_ROOTS_BY_TOOL: dict[str, str] = {
    "download_document_file": "output.DownloadDocumentOutput",
    "get_document_metadata": "output.DocumentMetadataOutput",
    "get_render_manifest": "output.RenderManifestOutput",
    "inspect_pdf": "output.PdfInspectionOutput",
    "list_document_files": "output.DocumentFilesOutput",
    "render_pdf_page_tiles": "output.RenderTilesOutput",
    "render_pdf_pages": "output.RenderPagesOutput",
    "search_documents": "output.SearchDocumentsOutput",
}
_INPUT_SCHEMA_ROOTS_BY_TOOL: dict[str, str] = {
    "download_document_file": "input.DownloadDocumentInput",
    "get_document_metadata": "input.HandleInput",
    "get_render_manifest": "input.RenderIdInput",
    "inspect_pdf": "input.ArtifactInput",
    "list_document_files": "input.HandleInput",
    "render_pdf_page_tiles": "input.RenderTilesInput",
    "render_pdf_pages": "input.RenderPagesInput",
    "search_documents": "input.SearchDocumentsInput",
}
_CONTRACT_SCHEMA_ID = "https://nplg-dspace-mcp.invalid/contracts/tool-contracts/v1"
_CONTRACT_EXPORTER_VERSION = "1.0.0-title-strip-codepoint-v1"
_CONTRACT_PYDANTIC_VERSION = "2.13.4"
_CONTRACT_ZOD_VERSION = "4.5.4"
_CONTRACT_MANIFEST_VERSION = 1
_BASELINE_MANIFEST_VERSION = 3
_BASELINE_CANONICALIZATION = "nplg-json-sort-utf8-lf-v1"
_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


class VerificationError(RuntimeError):
    """Sanitized deployment-verification failure."""


def _validate_request_timeout(timeout: float) -> None:
    """Reject unsafe or platform-dependent request timeout values."""
    if not math.isfinite(timeout) or timeout <= 0:
        msg = "--timeout must be a positive finite number"
        raise VerificationError(msg)
    if timeout > MAX_REQUEST_TIMEOUT_SECONDS:
        msg = "--timeout must not exceed 10000 seconds"
        raise VerificationError(msg)


class _SessionExpiredDuringRequestError(VerificationError):
    """Signal one session-bound auxiliary request rejected with HTTP 404."""

    session_id: str

    def __init__(self, session_id: str) -> None:
        super().__init__("deployment session expired during an MCP request")
        self.session_id = session_id


@dataclass(frozen=True, slots=True)
class _SseEvent:
    """One bounded SSE event with explicit cursor and retry state."""

    payload: bytes | None
    event_id: str | None
    event_id_present: bool
    retry_ms: int | None


@dataclass(frozen=True, slots=True)
class _SseContinuation:
    """A closed resumable stream that has not delivered its response yet."""

    event_id: str
    retry_ms: int


@dataclass(frozen=True, slots=True)
class _SseBatch:
    """One validated SSE response batch and its required client actions."""

    response: JsonObject | None
    continuation: _SseContinuation | None
    ping_ids: tuple[JsonRpcRequestId, ...]


@dataclass(frozen=True, slots=True)
class _HttpHop:
    """One bounded HTTP response captured before semantic decoding."""

    status: int
    headers: dict[str, str]
    raw: bytes
    sse_batch: _SseBatch | None
    observed_session: str | None


@dataclass(frozen=True, slots=True)
class _HttpRequest:
    """One fully described outbound deployment-verifier request."""

    method: str
    path: str
    body: bytes | None
    headers: Mapping[str, str]
    request_id: int | None
    sse_state: _SseStreamState


@dataclass(frozen=True, slots=True)
class _SseReadContext:
    """Immutable transport state for one bounded streaming response."""

    connection: HTTPConnection
    request_id: int
    session_id: str | None
    state: _SseStreamState
    deadline: float


def _new_sse_matches() -> list[JsonObject]:
    """Create one strictly typed response accumulator."""
    return []


def _new_sse_ping_ids() -> list[JsonRpcRequestId]:
    """Create one strictly typed server-ping accumulator."""
    return []


def _new_sse_event_ids() -> set[str]:
    """Create one client/session-wide SSE event-ID uniqueness ledger."""
    return set()


@dataclass(slots=True)
class _SseStreamState:
    """Bounded state for one logical SSE exchange across HTTP resume hops."""

    matches: list[JsonObject] = field(default_factory=_new_sse_matches)
    ping_ids: list[JsonRpcRequestId] = field(default_factory=_new_sse_ping_ids)
    event_ids: set[str] = field(default_factory=_new_sse_event_ids)
    last_event_id: str | None = None
    retry_ms: int = 0
    event_count: int = 0


@dataclass(slots=True)
class _SseFramer:
    """Split an arbitrary byte stream into normalized SSE frames in O(n)."""

    pending: bytearray = field(default_factory=bytearray)
    _bom_prefix: bytearray = field(default_factory=bytearray)
    _line_has_bytes: bool = False
    _event_has_bytes: bool = False
    _after_carriage_return: bool = False
    _bom_checked: bool = False

    def feed(self, chunk: bytes) -> tuple[bytes, ...]:
        """Consume each byte once and return every newly completed event."""
        frames: list[bytes] = []
        for value in chunk:
            if not self._bom_checked:
                self._bom_prefix.append(value)
                prefix = bytes(self._bom_prefix)
                if _SSE_BYTE_ORDER_MARK.startswith(prefix):
                    if len(prefix) == len(_SSE_BYTE_ORDER_MARK):
                        self._bom_prefix.clear()
                        self._bom_checked = True
                    continue
                self._bom_checked = True
                buffered = bytes(self._bom_prefix)
                self._bom_prefix.clear()
                for buffered_value in buffered:
                    self._feed_byte(buffered_value, frames)
                continue
            self._feed_byte(value, frames)
        return tuple(frames)

    def _feed_byte(self, value: int, frames: list[bytes]) -> None:
        """Consume one post-BOM byte in the SSE line-ending state machine."""
        if self._after_carriage_return:
            self._after_carriage_return = False
            if value == _SSE_LINE_FEED:
                return
        if value == _SSE_CARRIAGE_RETURN:
            self._after_carriage_return = True
            self._finish_line(frames)
            return
        if value == _SSE_LINE_FEED:
            self._finish_line(frames)
            return
        self.pending.append(value)
        self._line_has_bytes = True
        self._event_has_bytes = True

    def _finish_line(self, frames: list[bytes]) -> None:
        """Normalize one line ending and dispatch a non-empty event on a blank."""
        self.pending.append(_SSE_LINE_FEED)
        if self._line_has_bytes:
            self._line_has_bytes = False
            return
        if self._event_has_bytes:
            frames.append(bytes(self.pending))
        self.pending.clear()
        self._event_has_bytes = False

    def completed_retry_ms(self) -> int | None:
        """Return the last valid retry field from completed pending lines."""
        completed = bytes(self.pending)
        if self._line_has_bytes:
            final_line_ending = completed.rfind(b"\n")
            if final_line_ending < 0:
                return None
            completed = completed[: final_line_ending + 1]
        if not completed:
            return None
        try:
            text = completed.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            msg = "deployment returned invalid SSE"
            raise VerificationError(msg) from exc
        retry_ms: int | None = None
        for line in text.split("\n"):
            field_name, separator, value = line.partition(":")
            if separator and value.startswith(" "):
                value = value[1:]
            if field_name == "retry":
                parsed_retry = _sse_retry(value)
                if parsed_retry is not None:
                    retry_ms = parsed_retry
        return retry_ms


def _apply_completed_sse_retry(state: _SseStreamState, framer: _SseFramer) -> None:
    """Commit line-scoped retry state while discarding an incomplete event."""
    completed_retry_ms = framer.completed_retry_ms()
    if completed_retry_ms is not None:
        state.retry_ms = completed_retry_ms


def _origin_identity(value: str) -> tuple[str, str, int]:
    """Return a canonical scheme, host, and effective port for one URL."""
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        explicit_port = parsed.port
    except ValueError as exc:
        message = "deployment URLs must be valid HTTP(S) URLs"
        raise VerificationError(message) from exc
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or username is not None
        or password is not None
        or parsed.query
        or parsed.fragment
    ):
        message = "deployment URLs must be valid HTTP(S) URLs"
        raise VerificationError(message)
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, hostname.lower(), explicit_port or default_port


def _validate_probe_base_url(*, base_url: str, probe_base_url: str) -> None:
    """Keep unauthenticated probes on a distinct loopback HTTP origin."""
    if _origin_identity(probe_base_url) == _origin_identity(base_url):
        message = "--probe-base-url must be distinct from --base-url"
        raise VerificationError(message)
    parsed = urlsplit(probe_base_url)
    hostname = parsed.hostname
    if (
        parsed.scheme != "http"
        or hostname is None
        or hostname.lower() not in _HTTP_LOCAL_HOSTS
    ):
        message = "--probe-base-url must use a loopback HTTP origin"
        raise VerificationError(message)


def _is_json_value(value: object) -> TypeGuard[JsonValue]:
    if value is None or type(value) in {bool, int}:
        return True
    if type(value) is str:
        return all(
            not _SURROGATE_MIN <= ord(character) <= _SURROGATE_MAX
            for character in value
        )
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_value(item) for item in cast("list[object]", value))
    if isinstance(value, dict):
        entries = cast("dict[object, object]", value)
        return all(
            type(key) is str and _is_json_value(key) and _is_json_value(item)
            for key, item in entries.items()
        )
    return False


def _strict_json_object(pairs: list[tuple[str, object]]) -> JsonObject:
    """Reject duplicate members before constructing one JSON object."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            msg = "deployment returned duplicate JSON object members"
            raise ValueError(msg)
        result[key] = value
    return cast("JsonObject", result)


def _load_json_value(raw: bytes) -> JsonValue:
    try:
        value: object = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
        if not _is_json_value(value):
            msg = "deployment returned an invalid JSON value"
            raise VerificationError(msg)
    except (RecursionError, ValueError) as exc:
        msg = "deployment returned malformed JSON"
        raise VerificationError(msg) from exc
    return value


def _require_object(value: JsonValue, *, context: str) -> JsonObject:
    if not isinstance(value, dict):
        msg = f"{context} returned an invalid object"
        raise VerificationError(msg)
    return value


def _dump_json(value: JsonValue, *, indent: int | None = None) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        indent=indent,
        sort_keys=True,
    )


def _safe_header_value(value: str) -> str:
    if (
        value
        and value == value.strip()
        and all(
            _ASCII_PRINTABLE_MIN <= ord(char) <= _ASCII_PRINTABLE_MAX for char in value
        )
    ):
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def _response_headers(
    raw_headers: Sequence[tuple[str, str]],
) -> dict[str, str]:
    """Normalize response headers while rejecting framing ambiguities."""
    response_headers: dict[str, str] = {}
    for key, value in raw_headers:
        normalized = key.lower()
        if normalized in response_headers and normalized in {
            "content-type",
            "mcp-session-id",
        }:
            label = "Content-Type" if normalized == "content-type" else "session header"
            msg = f"deployment returned duplicate {label}"
            raise VerificationError(msg)
        _ = response_headers.setdefault(normalized, value)
    return response_headers


def _validated_sse_event_id(value: str) -> str:
    """Return one bounded WHATWG SSE cursor without normalizing it."""
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        msg = "deployment returned an invalid SSE event identifier"
        raise VerificationError(msg) from exc
    if (
        not encoded
        or len(encoded) > MAX_SSE_EVENT_ID_BYTES
        or any(forbidden in value for forbidden in ("\x00", "\r", "\n"))
    ):
        msg = "deployment returned an invalid SSE event identifier"
        raise VerificationError(msg)
    return value


def _sse_event_id_header(value: str) -> str:
    """Encode one validated UTF-8 SSE cursor for ``http.client``'s byte carrier."""
    validated = _validated_sse_event_id(value)
    return validated.encode("utf-8").decode("latin-1")


def _sse_retry(value: str) -> int | None:
    """Return one valid WHATWG retry interval and ignore malformed fields."""
    if not (
        0 < len(value) <= MAX_SSE_RETRY_DIGITS and value.isascii() and value.isdecimal()
    ):
        return None
    return int(value)


def _sse_event(  # noqa: C901 - closed WHATWG field state machine
    event: str,
) -> _SseEvent:
    """Parse one bounded standard message event and its reconnection fields."""
    event_type = ""
    data_lines: list[str] = []
    event_id: str | None = None
    event_id_present = False
    retry_ms: int | None = None
    for line in event.split("\n"):
        if not line or line.startswith(":"):
            continue
        field_name, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field_name == "event":
            event_type = value
        elif field_name == "data":
            data_lines.append(value)
        elif field_name == "id":
            if "\x00" in value:
                continue
            event_id = None if not value else _validated_sse_event_id(value)
            event_id_present = True
        elif field_name == "retry":
            parsed_retry = _sse_retry(value)
            if parsed_retry is not None:
                retry_ms = parsed_retry
    if event_type not in {"", "message"}:
        msg = "deployment returned invalid SSE event type"
        raise VerificationError(msg)
    payload = "\n".join(data_lines)
    return _SseEvent(
        payload=payload.encode("utf-8") if payload else None,
        event_id=event_id,
        event_id_present=event_id_present,
        retry_ms=retry_ms,
    )


def _sse_events(raw: bytes) -> tuple[_SseEvent, ...]:
    """Parse one bounded standard SSE response without discarding cursor state."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        msg = "deployment returned invalid SSE"
        raise VerificationError(msg) from exc
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.endswith("\n\n"):
        msg = "deployment returned invalid SSE"
        raise VerificationError(msg)
    events = [event for event in normalized[:-2].split("\n\n") if event]
    if len(events) > MAX_SSE_EVENTS:
        msg = "deployment returned invalid SSE"
        raise VerificationError(msg)
    return tuple(_sse_event(event) for event in events)


def _validate_logging_notification(params: JsonValue) -> None:
    """Validate the closed 2025-11-25 logging notification shape."""
    if not isinstance(params, dict) or not {
        "level",
        "data",
    } <= set(params) <= {"_meta", "level", "logger", "data"}:
        msg = "deployment returned an invalid SSE logging notification"
        raise VerificationError(msg)
    level = params.get("level")
    logger = params.get("logger")
    metadata = params.get("_meta")
    if (
        type(level) is not str
        or level not in _LOGGING_LEVELS
        or ("logger" in params and type(logger) is not str)
        or ("_meta" in params and not isinstance(metadata, dict))
    ):
        msg = "deployment returned an invalid SSE logging notification"
        raise VerificationError(msg)


def _validate_ping_request(payload: JsonObject) -> JsonRpcRequestId:
    """Return one strict server ping identifier for the required response."""
    request_id = payload.get("id")
    params = payload.get("params")
    if (
        not (
            type(request_id) is int
            or (type(request_id) is str and len(request_id) <= MAX_SSE_EVENT_ID_BYTES)
        )
        or not {"jsonrpc", "id", "method"} <= set(payload)
        or not set(payload) <= {"jsonrpc", "id", "method", "params"}
        or ("params" in payload and not isinstance(params, dict))
    ):
        msg = "deployment returned an invalid SSE ping request"
        raise VerificationError(msg)
    return request_id


def _validate_preceding_sse_message(
    payload: JsonObject,
    *,
    allow_logging: bool,
) -> JsonRpcRequestId | None:
    """Validate one supported server message before the correlated response."""
    method = payload.get("method")
    if payload.get("jsonrpc") != "2.0" or type(method) is not str:
        msg = "deployment returned an unsupported SSE server message"
        raise VerificationError(msg)
    if "id" in payload:
        if method != "ping":
            msg = "deployment returned an unsupported SSE server request"
            raise VerificationError(msg)
        return _validate_ping_request(payload)
    if method != "notifications/message" or not set(payload) <= {
        "jsonrpc",
        "method",
        "params",
    }:
        msg = "deployment returned an unsupported SSE notification"
        raise VerificationError(msg)
    if not allow_logging:
        msg = "deployment returned an undeclared SSE logging notification"
        raise VerificationError(msg)
    _validate_logging_notification(payload.get("params"))
    return None


def _classify_sse_message(
    payload: JsonObject,
    *,
    request_id: int,
    allow_logging: bool,
) -> tuple[JsonObject | None, JsonRpcRequestId | None]:
    """Classify one SSE object as the response or a supported server message."""
    response_id = payload.get("id")
    if (
        type(response_id) is int
        and response_id == request_id
        and "method" not in payload
    ):
        return payload, None
    return None, _validate_preceding_sse_message(
        payload,
        allow_logging=allow_logging,
    )


def _append_sse_ping(
    ping_ids: list[JsonRpcRequestId],
    ping_id: JsonRpcRequestId,
) -> None:
    """Append one unique ping within the bounded server-request allowance."""
    if ping_id in ping_ids or len(ping_ids) >= MAX_SSE_SERVER_REQUESTS:
        msg = "deployment returned invalid or duplicate SSE pings"
        raise VerificationError(msg)
    ping_ids.append(ping_id)


def _accumulate_sse_event(
    state: _SseStreamState,
    event: _SseEvent,
    *,
    request_id: int,
    allow_logging: bool,
) -> JsonRpcRequestId | None:
    """Merge one validated SSE event into one response-hop state."""
    if event.event_id_present:
        if event.event_id is not None:
            if event.event_id in state.event_ids:
                msg = "deployment returned duplicate SSE event identifiers"
                raise VerificationError(msg)
            if len(state.event_ids) >= MAX_SSE_SESSION_EVENT_IDS:
                msg = "deployment exceeded the SSE event identifier limit"
                raise VerificationError(msg)
            state.event_ids.add(event.event_id)
        state.last_event_id = event.event_id
    if event.retry_ms is not None:
        state.retry_ms = event.retry_ms
    if event.payload is None:
        return None
    payload = _require_object(
        _load_json_value(event.payload),
        context="SSE event",
    )
    matched, ping_id = _classify_sse_message(
        payload,
        request_id=request_id,
        allow_logging=allow_logging,
    )
    if matched is not None:
        state.matches.append(matched)
    if ping_id is not None:
        _append_sse_ping(state.ping_ids, ping_id)
    return ping_id


def _consume_sse_frame(
    state: _SseStreamState,
    frame: bytes,
    *,
    request_id: int,
    allow_logging: bool,
) -> tuple[JsonRpcRequestId, ...]:
    """Consume one complete SSE frame and return newly observed ping IDs."""
    try:
        events = _sse_events(frame)
    except VerificationError as exc:
        msg = "deployment returned invalid SSE"
        raise VerificationError(msg) from exc
    state.event_count += len(events)
    if state.event_count > MAX_SSE_EVENTS:
        msg = "deployment returned invalid SSE"
        raise VerificationError(msg)
    new_ping_ids: list[JsonRpcRequestId] = []
    for event in events:
        try:
            ping_id = _accumulate_sse_event(
                state,
                event,
                request_id=request_id,
                allow_logging=allow_logging,
            )
        except VerificationError as exc:
            msg = "deployment returned invalid SSE"
            raise VerificationError(msg) from exc
        if ping_id is not None:
            new_ping_ids.append(ping_id)
    return tuple(new_ping_ids)


def _finalize_sse_batch(
    matches: list[JsonObject],
    ping_ids: list[JsonRpcRequestId],
    *,
    last_event_id: str | None,
    retry_ms: int,
) -> _SseBatch:
    """Build one unambiguous response or resumable continuation batch."""
    if len(matches) > 1:
        msg = "deployment returned invalid or ambiguous SSE response"
        raise VerificationError(msg)
    if matches:
        return _SseBatch(
            response=matches[0],
            continuation=None,
            ping_ids=tuple(ping_ids),
        )
    if last_event_id is None:
        msg = "deployment returned invalid or ambiguous SSE response"
        raise VerificationError(msg)
    return _SseBatch(
        response=None,
        continuation=_SseContinuation(event_id=last_event_id, retry_ms=retry_ms),
        ping_ids=tuple(ping_ids),
    )


def _matching_sse_payload(
    raw: bytes,
    *,
    request_id: int,
    allow_logging: bool,
) -> _SseBatch:
    """Return one validated response batch with pings and reconnection state."""
    state = _SseStreamState()
    stream = raw.removeprefix(_SSE_BYTE_ORDER_MARK)
    _ = _consume_sse_frame(
        state,
        stream,
        request_id=request_id,
        allow_logging=allow_logging,
    )
    return _finalize_sse_batch(
        state.matches,
        state.ping_ids,
        last_event_id=state.last_event_id,
        retry_ms=state.retry_ms,
    )


def _response_payload(
    raw: bytes,
    response_headers: Mapping[str, str],
    *,
    request_id: int | None,
    allow_logging: bool,
) -> JsonValue | _SseBatch:
    """Decode one bounded JSON or correlated standard SSE response."""
    if not raw:
        return None
    content_type = response_headers.get("content-type")
    if content_type is None:
        msg = "deployment returned an unsupported Content-Type"
        raise VerificationError(msg)
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "text/event-stream":
        if request_id is None:
            msg = "deployment returned SSE without a request identifier"
            raise VerificationError(msg)
        return _matching_sse_payload(
            raw,
            request_id=request_id,
            allow_logging=allow_logging,
        )
    if media_type == "application/json":
        return _load_json_value(raw)
    msg = "deployment returned an unsupported Content-Type"
    raise VerificationError(msg)


def _response_media_type(response_headers: Mapping[str, str]) -> str | None:
    """Return the normalized response media type when one was supplied."""
    content_type = response_headers.get("content-type")
    return (
        None if content_type is None else content_type.partition(";")[0].strip().lower()
    )


def _observe_response_session(
    response_headers: Mapping[str, str],
    request_headers: Mapping[str, str],
    *,
    previous: str | None,
) -> str | None:
    """Retain one session across resume hops and reject any rotation."""
    raw_session = response_headers.get("mcp-session-id")
    if raw_session is None:
        return previous
    response_session = _validated_session_id(raw_session)
    request_session = request_headers.get("Mcp-Session-Id")
    if (request_session is not None and response_session != request_session) or (
        previous is not None and response_session != previous
    ):
        msg = "deployment rotated session identifiers across SSE responses"
        raise VerificationError(msg)
    return response_session


def _skip_response_decode(
    hop: _HttpHop,
    *,
    method: str,
    session_bound: bool,
    is_resume: bool,
) -> bool:
    """Identify transport statuses whose bounded bodies are deliberately ignored."""
    return (
        method == "DELETE"
        or (hop.status == HTTPStatus.NOT_FOUND and session_bound)
        or (is_resume and hop.status == HTTPStatus.METHOD_NOT_ALLOWED)
    )


def _validate_resume_hop(hop: _HttpHop, *, is_resume: bool) -> None:
    """Require every resumed GET response to remain a successful SSE stream."""
    if is_resume and (
        hop.status != HTTPStatus.OK
        or not hop.raw
        or _response_media_type(hop.headers) != "text/event-stream"
    ):
        msg = "deployment returned an invalid SSE resume response"
        raise VerificationError(msg)


def _validated_session_id(value: str) -> str:
    """Validate the bounded visible-ASCII session identifier contract."""
    if not 0 < len(value) <= MAX_SESSION_ID_BYTES or not all(
        _SESSION_ASCII_MIN <= ord(char) <= _ASCII_PRINTABLE_MAX for char in value
    ):
        msg = "deployment returned an invalid session identifier"
        raise VerificationError(msg)
    return value


@dataclass(slots=True)
class McpClient:
    """Bounded Streamable HTTP client for deployment verification."""

    base_url: str
    bearer_token: str | None = None
    timeout: float = 30.0
    api_key: str | None = None
    _request_id: int = 0
    _session_id: str | None = field(default=None, init=False, repr=False)
    _negotiated_protocol: str | None = field(default=None, init=False, repr=False)
    _logging_capability: bool = field(default=False, init=False, repr=False)
    _initialization_evidence: bytes | None = field(default=None, init=False, repr=False)
    _initialized_notified: bool = field(default=False, init=False, repr=False)
    _lifecycle_ready: bool = field(default=False, init=False, repr=False)
    _seen_sse_event_ids: set[str] = field(
        default_factory=_new_sse_event_ids,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Validate URL, credential, and deadline policy."""
        self.base_url = self.base_url.rstrip("/")
        try:
            parsed = urlsplit(self.base_url)
            _ = parsed.port
        except ValueError as exc:
            msg = "--base-url must be an HTTP(S) origin or base path"
            raise VerificationError(msg) from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            msg = "--base-url must be an HTTP(S) origin or base path"
            raise VerificationError(msg)
        if parsed.scheme == "http" and parsed.hostname not in _HTTP_LOCAL_HOSTS:
            msg = "Plain HTTP is allowed only for local verification"
            raise VerificationError(msg)
        if self.bearer_token and self.api_key:
            msg = "Configure either a bearer token or an API key, not both"
            raise VerificationError(msg)
        _validate_request_timeout(self.timeout)

    @property
    def origin(self) -> str:
        """Return the validated request origin."""
        parsed = urlsplit(self.base_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @property
    def session_active(self) -> bool:
        """Report whether initialization established a stateful session."""
        return self._session_id is not None

    def _connection(self, *, timeout: float | None = None) -> HTTPConnection:
        parsed = urlsplit(self.base_url)
        hostname = parsed.hostname
        if hostname is None:
            msg = "deployment host is unavailable"
            raise VerificationError(msg)
        request_timeout = self.timeout if timeout is None else timeout
        if parsed.scheme == "https":
            return HTTPSConnection(hostname, parsed.port, timeout=request_timeout)
        return HTTPConnection(hostname, parsed.port, timeout=request_timeout)

    def _target(self, path: str) -> str:
        base_path = urlsplit(self.base_url).path.rstrip("/")
        return f"{base_path}{path}" or "/"

    @staticmethod
    def _remaining_request_timeout(deadline: float) -> float:
        """Return the remaining total request budget or fail closed."""
        remaining = deadline - monotonic()
        if remaining <= 0:
            msg = "deployment request timeout exceeded"
            raise VerificationError(msg)
        return remaining

    @classmethod
    def _tighten_connection_timeout(
        cls,
        connection: HTTPConnection,
        *,
        deadline: float,
    ) -> float:
        """Apply the remaining total budget to the next socket operation."""
        remaining = cls._remaining_request_timeout(deadline)
        if connection.sock is not None:
            timeout_socket = cast("_SocketTimeoutSetter", connection.sock)
            timeout_socket.settimeout(remaining)
        return remaining

    def _read_response_body(
        self,
        response: HTTPResponse,
        connection: HTTPConnection,
        *,
        deadline: float,
    ) -> bytes:
        """Read a non-SSE body incrementally under one absolute deadline."""
        raw = bytearray()
        while True:
            _ = self._tighten_connection_timeout(connection, deadline=deadline)
            chunk = response.read1(MAX_RESPONSE_BYTES + 1 - len(raw))
            _ = self._remaining_request_timeout(deadline)
            if not chunk:
                return bytes(raw)
            raw.extend(chunk)
            if len(raw) > MAX_RESPONSE_BYTES:
                return bytes(raw)

    def _request_once(
        self,
        request: _HttpRequest,
        *,
        deadline: float,
        previous_session: str | None,
    ) -> _HttpHop:
        """Execute one bounded HTTP hop and close both response and connection."""
        connection: HTTPConnection | None = None
        try:
            connection = self._connection(
                timeout=self._remaining_request_timeout(deadline)
            )
            connection.request(
                request.method,
                self._target(request.path),
                body=request.body,
                headers=dict(request.headers),
            )
            _ = self._tighten_connection_timeout(connection, deadline=deadline)
            response = connection.getresponse()
            try:
                response_headers = _response_headers(response.getheaders())
                observed_session = _observe_response_session(
                    response_headers,
                    request.headers,
                    previous=previous_session,
                )
                if (
                    response.status == HTTPStatus.OK
                    and request.request_id is not None
                    and _response_media_type(response_headers) == "text/event-stream"
                ):
                    raw, sse_batch = self._read_sse_response(
                        response,
                        _SseReadContext(
                            connection=connection,
                            request_id=request.request_id,
                            session_id=observed_session,
                            state=request.sse_state,
                            deadline=deadline,
                        ),
                    )
                else:
                    raw = self._read_response_body(
                        response,
                        connection,
                        deadline=deadline,
                    )
                    sse_batch = None
                hop = _HttpHop(
                    status=response.status,
                    headers=response_headers,
                    raw=raw,
                    sse_batch=sse_batch,
                    observed_session=observed_session,
                )
            finally:
                response.close()
        except TimeoutError as exc:
            msg = "deployment request timeout exceeded"
            raise VerificationError(msg) from exc
        except (HTTPException, OSError, ValueError) as exc:
            msg = "deployment request failed"
            raise VerificationError(msg) from exc
        finally:
            if connection is not None:
                connection.close()
        if len(hop.raw) > MAX_RESPONSE_BYTES:
            msg = "deployment response exceeded the size limit"
            raise VerificationError(msg)
        return hop

    def _read_sse_response(
        self,
        response: HTTPResponse,
        context: _SseReadContext,
    ) -> tuple[bytes, _SseBatch]:
        """Consume SSE event by event so server pings are answered promptly."""
        raw = bytearray()
        framer = _SseFramer()
        while not context.state.matches:
            remaining = MAX_RESPONSE_BYTES + 1 - len(raw)
            _ = self._tighten_connection_timeout(
                context.connection,
                deadline=context.deadline,
            )
            at_eof = False
            try:
                chunk = response.read1(remaining)
            except TimeoutError as exc:
                msg = "deployment request timeout exceeded"
                raise VerificationError(msg) from exc
            except IncompleteRead as exc:
                chunk = exc.partial
                at_eof = True
            except OSError as exc:
                if context.state.last_event_id is None:
                    msg = "deployment request failed"
                    raise VerificationError(msg) from exc
                chunk = b""
                at_eof = True
            _ = self._remaining_request_timeout(context.deadline)
            at_eof = at_eof or not chunk
            if chunk:
                raw.extend(chunk)
                if len(raw) > MAX_RESPONSE_BYTES:
                    msg = "deployment response exceeded the size limit"
                    raise VerificationError(msg)
            for frame in framer.feed(chunk):
                new_ping_ids = _consume_sse_frame(
                    context.state,
                    frame,
                    request_id=context.request_id,
                    allow_logging=self._logging_capability,
                )
                self._respond_to_server_pings(
                    new_ping_ids,
                    session_id=context.session_id,
                    deadline=context.deadline,
                )
            if at_eof:
                _apply_completed_sse_retry(context.state, framer)
                break
        batch = _finalize_sse_batch(
            context.state.matches,
            [],
            last_event_id=context.state.last_event_id,
            retry_ms=context.state.retry_ms,
        )
        return bytes(raw), batch

    def _resolve_sse_batch(
        self,
        batch: _SseBatch,
        *,
        status: int,
        session_id: str | None,
        deadline: float,
    ) -> JsonObject | _SseContinuation:
        """Answer pings and return the response or required continuation."""
        if status != HTTPStatus.OK:
            msg = "deployment returned an invalid status before SSE resumption"
            raise VerificationError(msg)
        self._respond_to_server_pings(
            batch.ping_ids,
            session_id=session_id,
            deadline=deadline,
        )
        if batch.response is not None:
            return batch.response
        if batch.continuation is None:
            msg = "deployment returned invalid SSE state"
            raise VerificationError(msg)
        return batch.continuation

    @staticmethod
    def _wait_for_sse_retry(
        continuation: _SseContinuation,
        *,
        deadline: float,
    ) -> None:
        """Respect one SSE retry interval within the request's total deadline."""
        delay = continuation.retry_ms / MILLISECONDS_PER_SECOND
        if delay >= deadline - monotonic():
            msg = "deployment SSE retry exceeded the request timeout"
            raise VerificationError(msg)
        sleep(delay)

    def _resume_request_headers(
        self,
        continuation: _SseContinuation,
        *,
        session_id: str | None,
    ) -> dict[str, str]:
        """Build one strict SSE resumption GET header set."""
        headers = self._request_headers(
            "stream/resume",
            include_negotiated=self._negotiated_protocol is not None,
        )
        del headers["Content-Type"]
        headers["Accept"] = "text/event-stream"
        headers["Last-Event-ID"] = _sse_event_id_header(continuation.event_id)
        if session_id is not None:
            headers["Mcp-Session-Id"] = session_id
        return headers

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        request_id: int | None = None,
    ) -> tuple[int, dict[str, str], JsonValue, bool]:
        return self._request_json_until(
            _HttpRequest(
                method=method,
                path=path,
                body=body,
                headers=dict(headers or {}),
                request_id=request_id,
                sse_state=_SseStreamState(event_ids=self._seen_sse_event_ids),
            ),
            deadline=monotonic() + self.timeout,
        )

    def _request_json_until(
        self,
        request: _HttpRequest,
        *,
        deadline: float,
    ) -> tuple[int, dict[str, str], JsonValue, bool]:
        """Execute an MCP exchange and all auxiliary hops by one deadline."""
        current_method = request.method
        current_body = request.body
        current_headers = dict(request.headers)
        resume_attempts = 0
        observed_session: str | None = None
        while True:
            _ = self._remaining_request_timeout(deadline)
            hop = self._request_once(
                _HttpRequest(
                    method=current_method,
                    path=request.path,
                    body=current_body,
                    headers=current_headers,
                    request_id=request.request_id,
                    sse_state=request.sse_state,
                ),
                deadline=deadline,
                previous_session=observed_session,
            )
            observed_session = hop.observed_session
            session_bound = any(
                key.lower() == "mcp-session-id" for key in current_headers
            )
            is_resume = current_method == "GET" and resume_attempts > 0
            if (
                hop.status == HTTPStatus.NOT_FOUND
                and session_bound
                and current_method != "DELETE"
            ):
                request_session = next(
                    value
                    for key, value in current_headers.items()
                    if key.lower() == "mcp-session-id"
                )
                raise _SessionExpiredDuringRequestError(
                    _validated_session_id(request_session)
                )
            if _skip_response_decode(
                hop,
                method=current_method,
                session_bound=session_bound,
                is_resume=is_resume,
            ):
                return hop.status, hop.headers, None, bool(hop.raw)
            _validate_resume_hop(hop, is_resume=is_resume)
            payload = (
                hop.sse_batch
                if hop.sse_batch is not None
                else _response_payload(
                    hop.raw,
                    hop.headers,
                    request_id=request.request_id,
                    allow_logging=self._logging_capability,
                )
            )
            if not isinstance(payload, _SseBatch):
                if observed_session is not None:
                    _ = hop.headers.setdefault("mcp-session-id", observed_session)
                return hop.status, hop.headers, payload, bool(hop.raw)
            resolved = self._resolve_sse_batch(
                payload,
                status=hop.status,
                session_id=observed_session,
                deadline=deadline,
            )
            if isinstance(resolved, dict):
                if observed_session is not None:
                    _ = hop.headers.setdefault("mcp-session-id", observed_session)
                return hop.status, hop.headers, resolved, bool(hop.raw)
            if resume_attempts >= MAX_SSE_RESUME_ATTEMPTS:
                msg = "deployment exceeded the SSE resumption limit"
                raise VerificationError(msg)
            self._wait_for_sse_retry(resolved, deadline=deadline)
            resume_attempts += 1
            current_method = "GET"
            current_body = None
            current_headers = self._resume_request_headers(
                resolved,
                session_id=observed_session,
            )

    def _request_headers(
        self,
        method: str,
        *,
        name: str | None = None,
        include_negotiated: bool = True,
    ) -> dict[str, str]:
        """Build one explicit MCP request header set."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Origin": self.origin,
            "Mcp-Method": method,
        }
        if include_negotiated:
            headers["MCP-Protocol-Version"] = self._negotiated_protocol or PROTOCOL
            if self._session_id is not None:
                headers["Mcp-Session-Id"] = self._session_id
        if name is not None:
            headers["Mcp-Name"] = _safe_header_value(name)
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    def _respond_to_server_pings(
        self,
        ping_ids: tuple[JsonRpcRequestId, ...],
        *,
        session_id: str | None,
        deadline: float,
    ) -> None:
        """Promptly answer each bounded ping observed before an SSE response."""
        for ping_id in ping_ids:
            envelope: JsonObject = {
                "jsonrpc": "2.0",
                "id": ping_id,
                "result": {},
            }
            headers = self._request_headers(
                "ping/response",
                include_negotiated=self._negotiated_protocol is not None,
            )
            if session_id is not None:
                headers["Mcp-Session-Id"] = session_id
            status, response_headers, payload, body_present = self._request_json_until(
                _HttpRequest(
                    method="POST",
                    path="/mcp",
                    body=_dump_json(envelope).encode("utf-8"),
                    headers=headers,
                    request_id=None,
                    sse_state=_SseStreamState(event_ids=self._seen_sse_event_ids),
                ),
                deadline=deadline,
            )
            if (
                status != HTTPStatus.ACCEPTED
                or body_present
                or payload is not None
                or (session_id is None and "mcp-session-id" in response_headers)
            ):
                msg = "deployment rejected an SSE ping response"
                raise VerificationError(msg)

    def _validate_followup_session(self, response_headers: Mapping[str, str]) -> None:
        """Reject a session created or rotated after initialization."""
        response_session = response_headers.get("mcp-session-id")
        if response_session is None:
            return
        validated = _validated_session_id(response_session)
        if self._session_id is None:
            msg = "deployment returned an unexpected session after initialization"
            raise VerificationError(msg)
        if validated != self._session_id:
            msg = "deployment rotated session identifiers"
            raise VerificationError(msg)

    def _require_lifecycle(self) -> None:
        """Reject normal requests before the selected MCP lifecycle completes."""
        if not self._lifecycle_ready:
            msg = "deployment client lifecycle is incomplete"
            raise VerificationError(msg)

    def get(self, path: str) -> JsonObject:
        """Read and validate one deployment health object."""
        status, _, payload, _ = self._request_json("GET", path)
        if status != HTTPStatus.OK:
            msg = f"GET {path} returned HTTP {status}"
            raise VerificationError(msg)
        return _require_object(payload, context=f"GET {path}")

    def _recover_rpc_session(
        self,
        error: _SessionExpiredDuringRequestError,
        *,
        mode: RpcMode,
        sent_session: str | None,
        already_recovered: bool,
    ) -> str | None:
        """Recover one RPC lifecycle or return an expired initialization ID."""
        if already_recovered:
            msg = "deployment session expired repeatedly"
            raise VerificationError(msg) from error
        if mode == "normal" and sent_session == error.session_id:
            self._restart_expired_session(error.session_id)
            return None
        if mode == "initialize" and sent_session is None:
            self._seen_sse_event_ids.clear()
            return error.session_id
        msg = "deployment returned unexpected session expiry"
        raise VerificationError(msg) from error

    @staticmethod
    def _reject_reused_initialization_session(
        response_headers: Mapping[str, str],
        expired_session: str | None,
    ) -> None:
        """Reject a replacement initialization that reuses its expired ID."""
        response_session = response_headers.get("mcp-session-id")
        if (
            expired_session is not None
            and response_session is not None
            and _validated_session_id(response_session) == expired_session
        ):
            msg = "deployment reused an expired session identifier"
            raise VerificationError(msg)

    def _rpc_response(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        allowed_statuses: tuple[HTTPStatus, ...],
        name: str | None = None,
        mode: RpcMode = "normal",
    ) -> tuple[int, JsonObject, dict[str, str]]:
        """Call one bounded modern MCP method and validate its envelope."""
        recovered_session = False
        expired_initialization_session: str | None = None
        while True:
            self._request_id += 1
            values: JsonObject = dict(params or {})
            if mode != "initialize":
                values["_meta"] = {
                    "io.modelcontextprotocol/protocolVersion": (
                        self._negotiated_protocol or PROTOCOL
                    ),
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "nplg-deploy-verifier",
                        "version": "1.0",
                    },
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            envelope: JsonObject = {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
                "params": values,
            }
            headers = self._request_headers(
                method,
                name=name,
                include_negotiated=mode != "initialize",
            )
            sent_session = self._session_id if mode == "normal" else None
            try:
                status, response_headers, payload, _ = self._request_json(
                    "POST",
                    "/mcp",
                    body=_dump_json(envelope).encode("utf-8"),
                    headers=headers,
                    request_id=self._request_id,
                )
            except _SessionExpiredDuringRequestError as exc:
                expired_initialization_session = self._recover_rpc_session(
                    exc,
                    mode=mode,
                    sent_session=sent_session,
                    already_recovered=recovered_session,
                )
                recovered_session = True
                continue
            if status not in allowed_statuses:
                msg = f"{method} returned HTTP {status}"
                raise VerificationError(msg)
            self._reject_reused_initialization_session(
                response_headers,
                expired_initialization_session,
            )
            if mode == "normal":
                self._validate_followup_session(response_headers)
            response = _require_object(payload, context=method)
            response_id = response.get("id")
            if (
                response.get("jsonrpc") != "2.0"
                or type(response_id) is not int
                or response_id != self._request_id
            ):
                msg = f"{method} returned an invalid JSON-RPC envelope"
                raise VerificationError(msg)
            return status, response, response_headers

    def _restart_expired_session(self, expired_session: str) -> None:
        """Start exactly one fresh hosted lifecycle after a session-expiry 404."""
        if self._negotiated_protocol != ALPIC_GATEWAY_PROTOCOL:
            msg = "deployment returned session expiry outside the hosted lifecycle"
            raise VerificationError(msg)
        self._session_id = None
        self._negotiated_protocol = None
        self._logging_capability = False
        self._initialized_notified = False
        self._lifecycle_ready = False
        self._seen_sse_event_ids.clear()
        replacement_session = self._initialize_replacement_session()
        if replacement_session == expired_session:
            msg = "deployment reused an expired session identifier"
            raise VerificationError(msg)
        self._notify_initialized(allow_session_recovery=False)

    def _initialize_replacement_session(self) -> str | None:
        """Initialize after expiry without retaining a stale type narrowing."""
        _ = self.initialize()
        return self._session_id

    def initialize(self) -> JsonObject:
        """Negotiate the provider gateway's legacy lifecycle and optional session."""
        if self._negotiated_protocol is not None:
            msg = "deployment client was initialized more than once"
            raise VerificationError(msg)
        params: JsonObject = {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {
                "name": "nplg-deploy-verifier",
                "version": "1.0",
            },
        }
        _, response, response_headers = self._rpc_response(
            "initialize",
            params,
            allowed_statuses=(HTTPStatus.OK,),
            mode="initialize",
        )
        if "error" in response:
            msg = "initialize returned a JSON-RPC error"
            raise VerificationError(msg)
        result = _require_object(response.get("result"), context="initialize")
        protocol = result.get("protocolVersion")
        if protocol != ALPIC_GATEWAY_PROTOCOL:
            msg = "initialize negotiated an unsupported protocol"
            raise VerificationError(msg)
        evidence = _dump_json(result).encode("utf-8")
        if (
            self._initialization_evidence is not None
            and evidence != self._initialization_evidence
        ):
            msg = "replacement initialization changed negotiated evidence"
            raise VerificationError(msg)
        self._initialization_evidence = evidence
        capabilities = result.get("capabilities")
        self._logging_capability = bool(
            isinstance(capabilities, dict)
            and isinstance(capabilities.get("logging"), dict)
        )
        response_session = response_headers.get("mcp-session-id")
        session_id = (
            None
            if response_session is None
            else _validated_session_id(response_session)
        )
        self._negotiated_protocol = ALPIC_GATEWAY_PROTOCOL
        self._session_id = session_id
        return result

    def discover(self) -> JsonObject:
        """Complete the direct application's sessionless modern discovery."""
        if self._negotiated_protocol is not None:
            msg = "deployment client completed more than one MCP lifecycle"
            raise VerificationError(msg)
        _, response, response_headers = self._rpc_response(
            "server/discover",
            allowed_statuses=(HTTPStatus.OK,),
            mode="discover",
        )
        if "mcp-session-id" in response_headers:
            msg = "modern deployment unexpectedly created a session"
            raise VerificationError(msg)
        if "error" in response:
            msg = "server/discover returned a JSON-RPC error"
            raise VerificationError(msg)
        result = response.get("result")
        versions = result.get("supportedVersions") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or result.get("resultType") != "complete"
            or not isinstance(versions, list)
            or PROTOCOL not in versions
        ):
            msg = "server/discover omitted the modern MCP result shape"
            raise VerificationError(msg)
        self._negotiated_protocol = PROTOCOL
        self._lifecycle_ready = True
        return result

    def _notify_initialized(self, *, allow_session_recovery: bool) -> None:
        """Complete initialization with at most one full session restart."""
        if self._negotiated_protocol != ALPIC_GATEWAY_PROTOCOL:
            msg = "deployment client has not been initialized"
            raise VerificationError(msg)
        if self._initialized_notified:
            msg = "deployment client sent duplicate initialized notifications"
            raise VerificationError(msg)
        envelope: JsonObject = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        sent_session = self._session_id
        try:
            status, response_headers, payload, body_present = self._request_json(
                "POST",
                "/mcp",
                body=_dump_json(envelope).encode("utf-8"),
                headers=self._request_headers("notifications/initialized"),
            )
        except _SessionExpiredDuringRequestError as exc:
            if sent_session is None or sent_session != exc.session_id:
                msg = "deployment returned unexpected session expiry"
                raise VerificationError(msg) from exc
            if not allow_session_recovery:
                msg = "deployment session expired repeatedly"
                raise VerificationError(msg) from exc
            self._restart_expired_session(sent_session)
            return
        if status == HTTPStatus.NOT_FOUND and sent_session is not None:
            if not allow_session_recovery:
                msg = "deployment session expired repeatedly"
                raise VerificationError(msg)
            self._restart_expired_session(sent_session)
            return
        self._validate_followup_session(response_headers)
        if status != HTTPStatus.ACCEPTED:
            msg = f"notifications/initialized returned HTTP {status}"
            raise VerificationError(msg)
        if body_present or payload is not None:
            msg = "notifications/initialized returned an unexpected body"
            raise VerificationError(msg)
        self._initialized_notified = True
        self._lifecycle_ready = True

    def notify_initialized(self) -> None:
        """Complete initialization before normal MCP operations."""
        self._notify_initialized(allow_session_recovery=True)

    def terminate_session(self) -> None:
        """Release a completed hosted session when the gateway supports DELETE."""
        if self._session_id is None:
            return
        headers = self._request_headers("session/delete")
        del headers["Content-Type"]
        status, _, _, _ = self._request_json(
            "DELETE",
            "/mcp",
            headers=headers,
        )
        if status not in {
            HTTPStatus.OK,
            HTTPStatus.ACCEPTED,
            HTTPStatus.NO_CONTENT,
            HTTPStatus.NOT_FOUND,
            HTTPStatus.METHOD_NOT_ALLOWED,
        }:
            msg = f"session termination returned HTTP {status}"
            raise VerificationError(msg)
        self._session_id = None
        self._negotiated_protocol = None
        self._logging_capability = False
        self._initialization_evidence = None
        self._initialized_notified = False
        self._lifecycle_ready = False
        self._seen_sse_event_ids.clear()

    def rpc(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        name: str | None = None,
    ) -> tuple[JsonObject, dict[str, str]]:
        """Call one modern MCP JSON-RPC method."""
        self._require_lifecycle()
        _, response, response_headers = self._rpc_response(
            method,
            params,
            allowed_statuses=(HTTPStatus.OK,),
            name=name,
        )
        if "error" in response:
            msg = f"{method} returned a JSON-RPC error"
            raise VerificationError(msg)
        result = response.get("result")
        if not isinstance(result, dict) or result.get("resultType") != "complete":
            msg = f"{method} omitted the modern MCP result shape"
            raise VerificationError(msg)
        return result, response_headers

    def rpc_error_code(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        name: str | None = None,
    ) -> tuple[int, dict[str, str]]:
        """Call one method expected to return a bounded JSON-RPC error."""
        self._require_lifecycle()
        _, response, response_headers = self._rpc_response(
            method,
            params,
            allowed_statuses=(HTTPStatus.OK, HTTPStatus.NOT_FOUND),
            name=name,
        )
        error = response.get("error")
        if set(response) != {"jsonrpc", "id", "error"} or not isinstance(error, dict):
            msg = f"{method} omitted the expected JSON-RPC error"
            raise VerificationError(msg)
        code = error.get("code")
        message = error.get("message")
        if (
            not {"code", "message"} <= set(error) <= {"code", "message", "data"}
            or type(code) is not int
            or not isinstance(message, str)
        ):
            msg = f"{method} returned an invalid JSON-RPC error"
            raise VerificationError(msg)
        return code, response_headers

    def call_tool(self, name: str, arguments: JsonObject) -> JsonObject:
        """Call one MCP tool and return its structured content."""
        result, _ = self.rpc(
            "tools/call", {"name": name, "arguments": arguments}, name=name
        )
        if result.get("isError") is True:
            msg = f"Tool {name} failed"
            raise VerificationError(msg)
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            msg = f"Tool {name} returned no structuredContent"
            raise VerificationError(msg)
        return structured


class DeploymentClient(Protocol):
    """Operations required by deployment verification."""

    def get(self, path: str) -> JsonObject:
        """Read a deployment health endpoint."""
        ...

    @property
    def session_active(self) -> bool:
        """Report whether initialization established a stateful session."""
        ...

    def initialize(self) -> JsonObject:
        """Negotiate the MCP protocol and optional session."""
        ...

    def discover(self) -> JsonObject:
        """Complete the sessionless modern discovery lifecycle."""
        ...

    def notify_initialized(self) -> None:
        """Complete MCP initialization."""
        ...

    def rpc(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        name: str | None = None,
    ) -> tuple[JsonObject, dict[str, str]]:
        """Call one deployment JSON-RPC method."""
        ...

    def rpc_error_code(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        name: str | None = None,
    ) -> tuple[int, dict[str, str]]:
        """Call one method that must return a JSON-RPC error code."""
        ...


class ClientFactory(Protocol):
    """Construct a deployment-verification client."""

    def __call__(
        self,
        *,
        base_url: str,
        bearer_token: str | None,
        timeout: float,
        api_key: str | None,
    ) -> DeploymentClient:
        """Return a configured client."""
        ...


class DeploymentVerifier(Protocol):
    """Verify one selected deployment profile."""

    def __call__(
        self,
        client: DeploymentClient,
        /,
        *,
        profile: DeploymentProfile,
    ) -> JsonObject:
        """Return one bounded verification result."""
        ...


@dataclass(frozen=True, slots=True)
class CliDependencies:
    """Injected environment and effects for ``main``."""

    environ: Mapping[str, str]
    stdout: TextIO
    stderr: TextIO
    client_factory: ClientFactory
    verifier: DeploymentVerifier


def _artifact_object(path: Path) -> JsonObject:
    """Load one checked-in contract artifact through the strict JSON boundary."""
    try:
        return _require_object(_load_json_value(path.read_bytes()), context="contract")
    except (OSError, VerificationError) as exc:
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message) from exc


def _rewrite_output_schema(
    value: JsonValue,
    *,
    definitions: JsonObject,
    pending: list[str],
) -> JsonValue:
    """Restore root-local output-schema references from the aggregate artifact."""
    if isinstance(value, list):
        return [
            _rewrite_output_schema(item, definitions=definitions, pending=pending)
            for item in value
        ]
    if not isinstance(value, dict):
        return value
    rewritten: JsonObject = {}
    for key, item in value.items():
        if key != "$ref":
            rewritten[key] = _rewrite_output_schema(
                item,
                definitions=definitions,
                pending=pending,
            )
            continue
        if type(item) is not str or not item.startswith("#/$defs/output."):
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        name = item.removeprefix("#/$defs/output.")
        source_key = f"output.{name}"
        if source_key not in definitions:
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        pending.append(source_key)
        rewritten[key] = f"#/$defs/{name}"
    return rewritten


def _reconstruct_output_schema(
    definitions: JsonObject,
    *,
    root_key: str,
) -> JsonObject:
    """Reconstruct one tool's local output schema from its aggregate authority."""
    root = definitions.get(root_key)
    if not isinstance(root, dict):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    pending = [root_key]
    local_definitions: dict[str, JsonValue] = {}
    root_schema: JsonObject | None = None
    while pending:
        source_key = pending.pop()
        if source_key == root_key and root_schema is not None:
            continue
        if (
            source_key != root_key
            and source_key.removeprefix("output.") in local_definitions
        ):
            continue
        source = definitions.get(source_key)
        if not isinstance(source, dict) or not source_key.startswith("output."):
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        rewritten = _rewrite_output_schema(
            copy.deepcopy(source),
            definitions=definitions,
            pending=pending,
        )
        if not isinstance(rewritten, dict):
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        if source_key == root_key:
            root_schema = rewritten
        else:
            local_definitions[source_key.removeprefix("output.")] = rewritten
    if root_schema is None:
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    if local_definitions:
        root_schema["$defs"] = {
            name: local_definitions[name] for name in sorted(local_definitions)
        }
    return root_schema


def _public_input_schema(
    definitions: JsonObject,
    *,
    name: str,
    root_key: str,
) -> JsonObject:
    """Project one generated input root onto the reviewed public wire schema."""
    source = definitions.get(root_key)
    if not isinstance(source, dict):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    schema = copy.deepcopy(source)
    _ = schema.pop("title", None)
    _ = schema.pop("description", None)
    if name != "search_documents":
        return schema
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    query = properties.get("query")
    cursor = properties.get("cursor")
    if not isinstance(query, dict) or not isinstance(cursor, dict):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    if type(query.pop("pattern", None)) is not str:
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    alternatives = cursor.get("anyOf")
    if (
        not isinstance(alternatives, list)
        or not alternatives
        or not isinstance(alternatives[0], dict)
        or type(alternatives[0].pop("minLength", None)) is not int
        or type(alternatives[0].pop("pattern", None)) is not str
    ):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    return schema


def _normalized_schema_digest(schema: JsonObject) -> str:
    """Return the generated manifest's title-insensitive schema digest."""

    def normalize(value: JsonValue) -> JsonValue:
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, dict):
            return {
                key: normalize(item) for key, item in value.items() if key != "title"
            }
        return value

    normalized = normalize(schema)
    rendered = json.dumps(
        normalized,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(f"{rendered}\n".encode()).hexdigest()


def _canonical_json_digest(value: JsonValue) -> str:
    """Return the canonical whole-artifact digest used by checked-in manifests."""
    rendered = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(f"{rendered}\n".encode()).hexdigest()


def _expected_schema_keys() -> frozenset[str]:
    """Return the reviewed root-schema inventory for every public tool pair."""
    return frozenset(_INPUT_SCHEMA_ROOTS_BY_TOOL.values()) | frozenset(
        _OUTPUT_SCHEMA_ROOTS_BY_TOOL.values()
    )


def _validate_baseline_authority(baseline: JsonObject, manifest: JsonObject) -> None:
    """Bind the baseline tool catalog to its reviewed canonical digest."""
    entries = manifest.get("entries")
    if (
        manifest.get("schema_version") != _BASELINE_MANIFEST_VERSION
        or manifest.get("canonicalization") != _BASELINE_CANONICALIZATION
        or not isinstance(entries, list)
    ):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    records = [
        item
        for item in entries
        if isinstance(item, dict) and item.get("path") == "tool-catalog.json"
    ]
    if len(records) != 1 or set(records[0]) != {"path", "sha256"}:
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    digest = records[0].get("sha256")
    if type(digest) is not str or digest != _canonical_json_digest(baseline):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)


def _validate_generated_authority(
    aggregate: JsonObject,
    manifest: JsonObject,
) -> tuple[JsonObject, dict[str, str]]:
    """Validate generated-schema identity, inventory, and declared digests."""
    definitions = aggregate.get("$defs")
    records = manifest.get("schemas")
    expected_keys = _expected_schema_keys()
    if (
        set(aggregate) != {"$defs", "$id", "$schema", "description"}
        or aggregate.get("$id") != _CONTRACT_SCHEMA_ID
        or aggregate.get("$schema") != _DRAFT_2020_12
        or not isinstance(definitions, dict)
        or set(manifest)
        != {"aggregate_sha256", "exporter_version", "schema_id", "schemas", "version"}
        or manifest.get("version") != _CONTRACT_MANIFEST_VERSION
        or manifest.get("schema_id") != _CONTRACT_SCHEMA_ID
        or manifest.get("exporter_version") != _CONTRACT_EXPORTER_VERSION
        or manifest.get("aggregate_sha256") != _canonical_json_digest(aggregate)
        or not isinstance(records, list)
    ):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    manifest_digests: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "$id",
            "exporter_version",
            "json_pointer",
            "key",
            "normalized_sha256",
            "pydantic_version",
            "zod_version",
        }:
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        key = record.get("key")
        digest = record.get("normalized_sha256")
        if (
            type(key) is not str
            or type(digest) is not str
            or key in manifest_digests
            or record.get("$id") != _CONTRACT_SCHEMA_ID
            or record.get("exporter_version") != _CONTRACT_EXPORTER_VERSION
            or record.get("json_pointer") != f"#/$defs/{key}"
            or record.get("pydantic_version") != _CONTRACT_PYDANTIC_VERSION
            or record.get("zod_version") != _CONTRACT_ZOD_VERSION
        ):
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        manifest_digests[key] = digest
    if frozenset(manifest_digests) != expected_keys:
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    for key in expected_keys:
        source = definitions.get(key)
        if not isinstance(source, dict):
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        schema = (
            _reconstruct_output_schema(definitions, root_key=key)
            if key.startswith("output.")
            else source
        )
        if manifest_digests[key] != _normalized_schema_digest(schema):
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
    return definitions, manifest_digests


def _expected_tool_descriptors() -> dict[str, JsonObject]:
    """Load exact public descriptors from the checked-in contract authority."""
    baseline = _artifact_object(_BASELINE_TOOL_CATALOG)
    aggregate = _artifact_object(_GENERATED_CONTRACT_SCHEMA)
    manifest = _artifact_object(_GENERATED_CONTRACT_MANIFEST)
    baseline_manifest = _artifact_object(_BASELINE_MANIFEST)
    expected_names = ALPIC_METADATA_TOOLS | PRIVATE_FULL_TOOLS
    if (
        expected_names != frozenset(_INPUT_SCHEMA_ROOTS_BY_TOOL)
        or expected_names != frozenset(_OUTPUT_SCHEMA_ROOTS_BY_TOOL)
        or frozenset(baseline) != expected_names
    ):
        message = "Local deployment contract authority is invalid"
        raise VerificationError(message)
    _validate_baseline_authority(baseline, baseline_manifest)
    definitions, _ = _validate_generated_authority(aggregate, manifest)
    expected: dict[str, JsonObject] = {}
    for name in expected_names:
        descriptor = baseline.get(name)
        root_key = _OUTPUT_SCHEMA_ROOTS_BY_TOOL[name]
        if not isinstance(descriptor, dict):
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        expected_descriptor = copy.deepcopy(descriptor)
        title = expected_descriptor.get("title")
        annotations = expected_descriptor.get("annotations")
        if not isinstance(title, str) or not isinstance(annotations, dict):
            message = "Local deployment contract authority is invalid"
            raise VerificationError(message)
        annotations["title"] = title
        input_schema = _public_input_schema(
            definitions,
            name=name,
            root_key=_INPUT_SCHEMA_ROOTS_BY_TOOL[name],
        )
        output_schema = _reconstruct_output_schema(definitions, root_key=root_key)
        _ = output_schema.pop("title", None)
        _ = output_schema.pop("description", None)
        expected_descriptor["inputSchema"] = input_schema
        expected_descriptor["outputSchema"] = output_schema
        expected[name] = expected_descriptor
    return expected


def _tool_catalog(listed: JsonObject) -> dict[str, JsonObject]:
    raw_items = listed.get("tools")
    if not isinstance(raw_items, list):
        msg = "Tool catalog is not a list"
        raise VerificationError(msg)
    catalog: dict[str, JsonObject] = {}
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            msg = "Tool catalog contains an invalid entry"
            raise VerificationError(msg)
        name = raw_item.get("name")
        if not isinstance(name, str):
            msg = "Tool catalog contains an unnamed entry"
            raise VerificationError(msg)
        if name in catalog:
            msg = "Tool catalog contains duplicate names"
            raise VerificationError(msg)
        catalog[name] = raw_item
    return catalog


def _verify_annotations(catalog: Mapping[str, JsonObject]) -> None:
    mismatches: list[str] = []
    for name, item in catalog.items():
        annotations = item.get("annotations")
        if not isinstance(annotations, dict):
            mismatches.append(name)
            continue
        expected_read_only = name not in CACHE_WRITING_TOOLS
        if (
            annotations.get("readOnlyHint") is not expected_read_only
            or annotations.get("destructiveHint") is not False
        ):
            mismatches.append(name)
    if mismatches:
        msg = f"Tool annotation mismatch: {sorted(mismatches)}"
        raise VerificationError(msg)


def _verify_tool_descriptors(
    catalog: Mapping[str, JsonObject],
    *,
    expected_tools: frozenset[str],
) -> None:
    """Require exact profile-scoped public tool descriptor equality."""
    expected = _expected_tool_descriptors()
    mismatches = [
        name
        for name, descriptor in expected.items()
        if name in expected_tools
        if _dump_json(catalog[name]) != _dump_json(descriptor)
    ]
    if mismatches:
        msg = f"Tool descriptor mismatch: {sorted(mismatches)}"
        raise VerificationError(msg)


def _require_nonempty_list(value: JsonValue | None, *, context: str) -> None:
    if not isinstance(value, list) or not value:
        msg = f"{context} did not return the expected entry"
        raise VerificationError(msg)


def _verify_metadata_workflow_text(text: str) -> None:
    """Bind one strict UTF-8 instruction payload to the reviewed digest."""
    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        message = "Metadata workflow resource text is invalid"
        raise VerificationError(message) from exc
    if not 0 < len(encoded) <= MAX_AGENT_WORKFLOW_BYTES or any(
        unicodedata.category(character) in {"Cc", "Cf"}
        and character not in _ALLOWED_WORKFLOW_CONTROLS
        for character in text
    ):
        message = "Metadata workflow resource text is invalid"
        raise VerificationError(message)
    if any(marker not in text for marker in _AGENT_WORKFLOW_REQUIRED_MARKERS):
        message = "Metadata workflow resource is missing required safety guidance"
        raise VerificationError(message)
    if any(operation in text for operation in _AGENT_WORKFLOW_FORBIDDEN_OPERATIONS):
        message = "Metadata workflow resource advertises server-side PDF operations"
        raise VerificationError(message)
    if hashlib.sha256(encoded).hexdigest() != AGENT_WORKFLOW_SHA256:
        message = "Metadata workflow resource digest is invalid"
        raise VerificationError(message)


def _verify_metadata_initialization(initialization: JsonObject) -> None:
    """Require the reviewed standard initialization advertisement."""
    expected: JsonObject = {
        "protocolVersion": ALPIC_GATEWAY_PROTOCOL,
        "capabilities": _EXPECTED_METADATA_CAPABILITIES,
        "instructions": METADATA_DISCOVERY_INSTRUCTIONS,
        "serverInfo": _EXPECTED_SERVER_INFO,
    }
    if _dump_json(initialization) != _dump_json(expected):
        message = "Metadata workflow resource initialization is invalid"
        raise VerificationError(message)


def _verify_metadata_resource_catalog(resources: JsonObject) -> None:
    """Require one exact agent-visible descriptor and result envelope."""
    expected: JsonObject = {
        "resources": [_EXPECTED_AGENT_WORKFLOW_DESCRIPTOR],
        "ttlMs": 0,
        "cacheScope": "private",
        "resultType": "complete",
        "_meta": _EXPECTED_SERVER_META,
    }
    if _dump_json(resources) != _dump_json(expected):
        message = "Metadata workflow resource catalog is invalid"
        raise VerificationError(message)


def _verify_metadata_resource_read(read_result: JsonObject) -> None:
    """Require one exact text content envelope, then verify its reviewed bytes."""
    contents = read_result.get("contents")
    if (
        not isinstance(contents, list)
        or len(contents) != 1
        or not isinstance(contents[0], dict)
    ):
        message = "Metadata workflow resource content is invalid"
        raise VerificationError(message)
    content = contents[0]
    text = content.get("text")
    if not isinstance(text, str):
        message = "Metadata workflow resource content is invalid"
        raise VerificationError(message)
    expected: JsonObject = {
        "contents": [
            {
                "uri": AGENT_WORKFLOW_URI,
                "mimeType": AGENT_WORKFLOW_MIME_TYPE,
                "text": text,
            }
        ],
        "ttlMs": 0,
        "cacheScope": "private",
        "resultType": "complete",
        "_meta": _EXPECTED_SERVER_META,
    }
    if _dump_json(read_result) != _dump_json(expected):
        message = "Metadata workflow resource content is invalid"
        raise VerificationError(message)
    _verify_metadata_workflow_text(text)


def _verify_metadata_workflow_resource(
    initialization: JsonObject,
    resources: JsonObject,
    read_result: JsonObject,
) -> None:
    """Verify one bounded client workflow without importing project code."""
    _verify_metadata_initialization(initialization)
    _verify_metadata_resource_catalog(resources)
    _verify_metadata_resource_read(read_result)


def _verify_metadata_resource_surface(
    client: DeploymentClient,
    initialization: JsonObject,
) -> tuple[dict[str, str], ...]:
    """Probe the exact static resource surface and absent template method."""
    resources, resources_headers = client.rpc("resources/list")
    workflow, workflow_headers = client.rpc(
        "resources/read",
        {"uri": AGENT_WORKFLOW_URI},
        name=AGENT_WORKFLOW_URI,
    )
    template_error, template_headers = client.rpc_error_code("resources/templates/list")
    _verify_metadata_workflow_resource(initialization, resources, workflow)
    if template_error != METHOD_NOT_FOUND:
        message = "Metadata resource templates are unexpectedly available"
        raise VerificationError(message)
    return resources_headers, workflow_headers, template_headers


def _verify_private_resource_surface(
    client: DeploymentClient,
) -> tuple[dict[str, str], ...]:
    """Retain the private profile's existing about-resource smoke check."""
    resources, resources_headers = client.rpc("resources/list")
    about, about_headers = client.rpc(
        "resources/read", {"uri": "nplg://about"}, name="nplg://about"
    )
    resource_items = resources.get("resources")
    _require_nonempty_list(resource_items, context="resources/list")
    if not isinstance(resource_items, list) or not any(
        isinstance(item, dict) and item.get("uri") == "nplg://about"
        for item in resource_items
    ):
        msg = "nplg://about resource was not listed"
        raise VerificationError(msg)
    contents = about.get("contents")
    _require_nonempty_list(contents, context="resources/read")
    if (
        not isinstance(contents, list)
        or not isinstance(contents[0], dict)
        or contents[0].get("uri") != "nplg://about"
    ):
        msg = "nplg://about could not be read"
        raise VerificationError(msg)
    return resources_headers, about_headers


def verify(
    client: DeploymentClient,
    *,
    profile: DeploymentProfile = "alpic-metadata",
) -> JsonObject:
    """Verify the initialized MCP contract for one explicit profile."""
    expected_tools = EXPECTED_TOOLS_BY_PROFILE.get(profile)
    if expected_tools is None:
        msg = "Deployment profile is unsupported"
        raise VerificationError(msg)
    initialization: JsonObject | None = None
    discovery: JsonObject | None = None
    if profile == "alpic-metadata":
        initialization = client.initialize()
        protocol = initialization.get("protocolVersion")
        if protocol != ALPIC_GATEWAY_PROTOCOL:
            msg = "initialize did not negotiate the hosted protocol"
            raise VerificationError(msg)
        client.notify_initialized()
    else:
        discovery = client.discover()
        versions = discovery.get("supportedVersions")
        if not isinstance(versions, list) or PROTOCOL not in versions:
            msg = "server/discover did not advertise the requested protocol"
            raise VerificationError(msg)
        if client.session_active:
            msg = "The modern endpoint unexpectedly created a session"
            raise VerificationError(msg)
        protocol = PROTOCOL
    listed, list_headers = client.rpc("tools/list")

    catalog = _tool_catalog(listed)
    if frozenset(catalog) != expected_tools:
        msg = "Tool catalog mismatch"
        raise VerificationError(msg)
    _verify_annotations(catalog)
    _verify_tool_descriptors(catalog, expected_tools=expected_tools)
    if listed.get("cacheScope") != "private" or (
        discovery is not None and discovery.get("cacheScope") != "private"
    ):
        msg = "Modern list/discovery results must declare private cache scope"
        raise VerificationError(msg)
    del list_headers
    if profile == "alpic-metadata":
        if initialization is None:
            msg = "Metadata initialization evidence is unavailable"
            raise VerificationError(msg)
        _ = _verify_metadata_resource_surface(
            client,
            initialization,
        )
    else:
        _ = _verify_private_resource_surface(client)
    return {
        "status": "pass",
        "protocol": protocol,
        "profile": profile,
        "tool_count": len(catalog),
        "probes_checked": False,
        "sessionless": not client.session_active,
    }


def verify_probes(client: DeploymentClient) -> JsonObject:
    """Verify private health probes through an explicitly separate client."""
    health = client.get("/healthz")
    ready = client.get("/readyz")
    if health != {"status": "ok"} or ready != {"status": "ready"}:
        msg = "Health or readiness response was unexpected"
        raise VerificationError(msg)
    return {"health": health, "ready": ready}


@dataclass(frozen=True, slots=True)
class VerifyArguments:
    """Validated deployment-verifier arguments."""

    base_url: str
    token: str | None
    api_key: str | None
    timeout: float
    profile: DeploymentProfile
    probe_base_url: str | None


def _parser(environ: Mapping[str, str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    _ = parser.add_argument(
        "--base-url",
        required=True,
        help="Deployment base URL, for example https://mcp.example.com",
    )
    parser.set_defaults(
        token=environ.get("API_BEARER_TOKEN"),
        api_key=environ.get("API_KEY"),
    )
    _ = parser.add_argument("--timeout", type=float, default=30.0)
    _ = parser.add_argument(
        "--profile",
        choices=DEPLOYMENT_PROFILES,
        default="alpic-metadata",
    )
    _ = parser.add_argument(
        "--probe-base-url",
        help="Distinct private application URL used only for health probes",
    )
    return parser


def _parse_args(
    argv: Sequence[str], dependencies: CliDependencies
) -> VerifyArguments | int:
    if any(
        argument.partition("=")[0].startswith(("--tok", "--api")) for argument in argv
    ):
        return _write_failure(
            dependencies,
            "credentials must be supplied through environment variables",
            exit_code=2,
        )
    try:
        with (
            redirect_stdout(dependencies.stdout),
            redirect_stderr(dependencies.stderr),
        ):
            values = cast(
                "dict[str, object]",
                vars(_parser(dependencies.environ).parse_args(argv)),
            )
    except SystemExit as exc:
        return exc.code if type(exc.code) is int else 1
    base_url = values["base_url"]
    token = values["token"]
    api_key = values["api_key"]
    timeout = values["timeout"]
    profile = values["profile"]
    probe_base_url = values["probe_base_url"]
    if not isinstance(base_url, str) or type(timeout) is not float:
        return 2
    if (
        (token is not None and not isinstance(token, str))
        or (api_key is not None and not isinstance(api_key, str))
        or not isinstance(profile, str)
        or profile not in EXPECTED_TOOLS_BY_PROFILE
        or (probe_base_url is not None and not isinstance(probe_base_url, str))
    ):
        return 2
    return VerifyArguments(
        base_url,
        token,
        api_key,
        timeout,
        profile,
        probe_base_url,
    )


def _default_client_factory(
    *,
    base_url: str,
    bearer_token: str | None,
    timeout: float,
    api_key: str | None,
) -> DeploymentClient:
    return McpClient(
        base_url=base_url,
        bearer_token=bearer_token,
        timeout=timeout,
        api_key=api_key,
    )


def _default_dependencies() -> CliDependencies:
    return CliDependencies(
        environ=os.environ,
        stdout=sys.stdout,
        stderr=sys.stderr,
        client_factory=_default_client_factory,
        verifier=verify,
    )


def _write_failure(
    dependencies: CliDependencies,
    message: str,
    *,
    exit_code: int = 1,
) -> int:
    try:
        _ = dependencies.stderr.write(f"FAIL: {message}\n")
    except (OSError, UnicodeError):
        return exit_code
    return exit_code


def _write_output(result: JsonObject, dependencies: CliDependencies) -> int:
    try:
        payload = _dump_json(result, indent=2) + "\n"
        encoded = payload.encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError):
        return _write_failure(dependencies, "deployment returned invalid JSON")
    if len(encoded) > MAX_CANONICAL_OUTPUT_BYTES:
        return _write_failure(
            dependencies,
            "deployment output exceeded the size limit",
        )
    try:
        _ = dependencies.stdout.write(payload)
    except (OSError, UnicodeError):
        return _write_failure(dependencies, "output write failed")
    return 0


def main(argv: Sequence[str], *, dependencies: CliDependencies) -> int:
    """Run the injected deployment-verification CLI."""
    parsed = _parse_args(argv, dependencies)
    if isinstance(parsed, int):
        return parsed
    try:
        _validate_request_timeout(parsed.timeout)
    except VerificationError as exc:
        return _write_failure(dependencies, str(exc), exit_code=2)
    if parsed.probe_base_url is not None:
        try:
            _validate_probe_base_url(
                base_url=parsed.base_url,
                probe_base_url=parsed.probe_base_url,
            )
        except VerificationError as exc:
            return _write_failure(dependencies, str(exc), exit_code=2)
    try:
        client = dependencies.client_factory(
            base_url=parsed.base_url,
            bearer_token=parsed.token,
            timeout=parsed.timeout,
            api_key=parsed.api_key,
        )
        verifier_succeeded = False
        try:
            result = dependencies.verifier(client, profile=parsed.profile)
            verifier_succeeded = True
        finally:
            if isinstance(client, McpClient):
                if verifier_succeeded:
                    client.terminate_session()
                else:
                    with suppress(VerificationError):
                        client.terminate_session()
        if parsed.probe_base_url is not None:
            probe_client = dependencies.client_factory(
                base_url=parsed.probe_base_url,
                bearer_token=None,
                timeout=parsed.timeout,
                api_key=None,
            )
            result.update(verify_probes(probe_client))
            result["probes_checked"] = True
    except VerificationError as exc:
        return _write_failure(dependencies, str(exc))
    except KeyboardInterrupt:
        _ = _write_failure(dependencies, "deployment verification cancelled")
        return 130
    return _write_output(result, dependencies)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], dependencies=_default_dependencies()))
