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
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from http import HTTPStatus
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, cast
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import TextIO, TypeGuard

PROTOCOL = "2026-07-28"
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
MAX_CANONICAL_OUTPUT_BYTES = 65_536
_HTTP_LOCAL_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_ASCII_PRINTABLE_MIN = 0x20
_ASCII_PRINTABLE_MAX = 0x7E
_SURROGATE_MIN = 0xD800
_SURROGATE_MAX = 0xDFFF

type JsonPrimitive = bool | int | float | str | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
type DeploymentProfile = Literal["alpic-metadata", "private-full"]

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


def _origin_identity(value: str) -> tuple[str, str, int]:
    """Return a canonical scheme, host, and effective port for one URL."""
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        message = "deployment URLs must be valid HTTP(S) URLs"
        raise VerificationError(message)
    try:
        explicit_port = parsed.port
    except ValueError as exc:
        message = "deployment URLs must contain a valid port"
        raise VerificationError(message) from exc
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, parsed.hostname.lower(), explicit_port or default_port


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


@dataclass(slots=True)
class McpClient:
    """Bounded, sessionless HTTP client for deployment verification."""

    base_url: str
    bearer_token: str | None = None
    timeout: float = 30.0
    api_key: str | None = None
    _request_id: int = 0

    def __post_init__(self) -> None:
        """Validate URL, credential, and deadline policy."""
        self.base_url = self.base_url.rstrip("/")
        parsed = urlsplit(self.base_url)
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
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            msg = "--timeout must be a positive finite number"
            raise VerificationError(msg)

    @property
    def origin(self) -> str:
        """Return the validated request origin."""
        parsed = urlsplit(self.base_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _connection(self) -> HTTPConnection:
        parsed = urlsplit(self.base_url)
        hostname = parsed.hostname
        if hostname is None:
            msg = "deployment host is unavailable"
            raise VerificationError(msg)
        if parsed.scheme == "https":
            return HTTPSConnection(hostname, parsed.port, timeout=self.timeout)
        return HTTPConnection(hostname, parsed.port, timeout=self.timeout)

    def _target(self, path: str) -> str:
        base_path = urlsplit(self.base_url).path.rstrip("/")
        return f"{base_path}{path}" or "/"

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, dict[str, str], JsonValue]:
        connection = self._connection()
        try:
            connection.request(
                method,
                self._target(path),
                body=body,
                headers=dict(headers or {}),
            )
            response = connection.getresponse()
            try:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
                response_headers = {
                    key.lower(): value for key, value in response.getheaders()
                }
            finally:
                response.close()
        except (HTTPException, OSError, TimeoutError, ValueError) as exc:
            msg = "deployment request failed"
            raise VerificationError(msg) from exc
        finally:
            connection.close()
        if len(raw) > MAX_RESPONSE_BYTES:
            msg = "deployment response exceeded the size limit"
            raise VerificationError(msg)
        payload: JsonValue = None if not raw else _load_json_value(raw)
        return status, response_headers, payload

    def get(self, path: str) -> JsonObject:
        """Read and validate one deployment health object."""
        status, _, payload = self._request_json("GET", path)
        if status != HTTPStatus.OK:
            msg = f"GET {path} returned HTTP {status}"
            raise VerificationError(msg)
        return _require_object(payload, context=f"GET {path}")

    def _rpc_response(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        allowed_statuses: tuple[HTTPStatus, ...],
        name: str | None = None,
    ) -> tuple[int, JsonObject, dict[str, str]]:
        """Call one bounded modern MCP method and validate its envelope."""
        self._request_id += 1
        values: JsonObject = dict(params or {})
        values["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
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
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Origin": self.origin,
            "MCP-Protocol-Version": PROTOCOL,
            "Mcp-Method": method,
        }
        if name is not None:
            headers["Mcp-Name"] = _safe_header_value(name)
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.api_key:
            headers["x-api-key"] = self.api_key
        status, response_headers, payload = self._request_json(
            "POST",
            "/mcp",
            body=_dump_json(envelope).encode("utf-8"),
            headers=headers,
        )
        if status not in allowed_statuses:
            msg = f"{method} returned HTTP {status}"
            raise VerificationError(msg)
        response = _require_object(payload, context=method)
        if response.get("jsonrpc") != "2.0" or response.get("id") != self._request_id:
            msg = f"{method} returned an invalid JSON-RPC envelope"
            raise VerificationError(msg)
        return status, response, response_headers

    def rpc(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        name: str | None = None,
    ) -> tuple[JsonObject, dict[str, str]]:
        """Call one modern MCP JSON-RPC method."""
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


def _verify_metadata_discovery(discover: JsonObject) -> None:
    """Require only the reviewed tool/resource capability advertisement."""
    expected: JsonObject = {
        "cacheScope": "private",
        "capabilities": _EXPECTED_METADATA_CAPABILITIES,
        "instructions": METADATA_DISCOVERY_INSTRUCTIONS,
        "resultType": "complete",
        "supportedVersions": [PROTOCOL],
        "ttlMs": 0,
        "_meta": _EXPECTED_SERVER_META,
    }
    if _dump_json(discover) != _dump_json(expected):
        message = "Metadata workflow resource discovery is invalid"
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
    discover: JsonObject,
    resources: JsonObject,
    read_result: JsonObject,
) -> None:
    """Verify one bounded client workflow without importing project code."""
    _verify_metadata_discovery(discover)
    _verify_metadata_resource_catalog(resources)
    _verify_metadata_resource_read(read_result)


def _verify_metadata_resource_surface(
    client: DeploymentClient,
    discover: JsonObject,
) -> tuple[dict[str, str], ...]:
    """Probe the exact static resource surface and absent template method."""
    resources, resources_headers = client.rpc("resources/list")
    workflow, workflow_headers = client.rpc(
        "resources/read",
        {"uri": AGENT_WORKFLOW_URI},
        name=AGENT_WORKFLOW_URI,
    )
    template_error, template_headers = client.rpc_error_code("resources/templates/list")
    _verify_metadata_workflow_resource(discover, resources, workflow)
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
    """Verify the sessionless MCP contract for one explicit profile."""
    expected_tools = EXPECTED_TOOLS_BY_PROFILE.get(profile)
    if expected_tools is None:
        msg = "Deployment profile is unsupported"
        raise VerificationError(msg)
    discover, discover_headers = client.rpc("server/discover")
    listed, list_headers = client.rpc("tools/list")

    versions = discover.get("supportedVersions")
    if not isinstance(versions, list) or PROTOCOL not in versions:
        msg = "server/discover did not advertise the requested protocol"
        raise VerificationError(msg)
    catalog = _tool_catalog(listed)
    if frozenset(catalog) != expected_tools:
        msg = "Tool catalog mismatch"
        raise VerificationError(msg)
    _verify_annotations(catalog)
    _verify_tool_descriptors(catalog, expected_tools=expected_tools)
    if discover.get("cacheScope") != "private" or listed.get("cacheScope") != "private":
        msg = "Modern list/discovery results must declare private cache scope"
        raise VerificationError(msg)
    if "mcp-session-id" in discover_headers or "mcp-session-id" in list_headers:
        msg = "The stateless endpoint unexpectedly created a session"
        raise VerificationError(msg)
    if profile == "alpic-metadata":
        resource_headers = _verify_metadata_resource_surface(
            client,
            discover,
        )
    else:
        resource_headers = _verify_private_resource_surface(client)
    if any("mcp-session-id" in headers for headers in resource_headers):
        msg = "The stateless endpoint unexpectedly created a session"
        raise VerificationError(msg)
    return {
        "status": "pass",
        "protocol": PROTOCOL,
        "profile": profile,
        "tool_count": len(catalog),
        "probes_checked": False,
        "sessionless": True,
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
    if not math.isfinite(parsed.timeout) or parsed.timeout <= 0:
        return _write_failure(
            dependencies,
            "--timeout must be a positive finite number",
            exit_code=2,
        )
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
        result = dependencies.verifier(client, profile=parsed.profile)
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
