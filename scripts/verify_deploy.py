#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Verify a deployed NPLG MCP without depending on the project package."""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from http import HTTPStatus
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from typing import TYPE_CHECKING, Protocol, cast
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from typing import TextIO, TypeGuard

PROTOCOL = "2026-07-28"
EXPECTED_TOOLS: frozenset[str] = frozenset(
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

type JsonPrimitive = bool | int | float | str | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]


class VerificationError(RuntimeError):
    """Sanitized deployment-verification failure."""


def _is_json_value(value: object) -> TypeGuard[JsonValue]:
    if value is None or type(value) in {bool, int, str}:
        return True
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_value(item) for item in cast("list[object]", value))
    if isinstance(value, dict):
        entries = cast("dict[object, object]", value)
        return all(
            type(key) is str and _is_json_value(item) for key, item in entries.items()
        )
    return False


def _load_json_value(raw: bytes) -> JsonValue:
    try:
        value: object = json.loads(raw.decode("utf-8"))
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

    def rpc(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        name: str | None = None,
    ) -> tuple[JsonObject, dict[str, str]]:
        """Call one modern MCP JSON-RPC method."""
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
        if status != HTTPStatus.OK:
            msg = f"{method} returned HTTP {status}"
            raise VerificationError(msg)
        response = _require_object(payload, context=method)
        if response.get("jsonrpc") != "2.0" or response.get("id") != self._request_id:
            msg = f"{method} returned an invalid JSON-RPC envelope"
            raise VerificationError(msg)
        if "error" in response:
            msg = f"{method} returned a JSON-RPC error"
            raise VerificationError(msg)
        result = response.get("result")
        if not isinstance(result, dict) or result.get("resultType") != "complete":
            msg = f"{method} omitted the modern MCP result shape"
            raise VerificationError(msg)
        return result, response_headers

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


@dataclass(frozen=True, slots=True)
class CliDependencies:
    """Injected environment and effects for ``main``."""

    environ: Mapping[str, str]
    stdout: TextIO
    stderr: TextIO
    client_factory: ClientFactory
    verifier: Callable[[DeploymentClient], JsonObject]


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


def _require_nonempty_list(value: JsonValue | None, *, context: str) -> None:
    if not isinstance(value, list) or not value:
        msg = f"{context} did not return the expected entry"
        raise VerificationError(msg)


def verify(client: DeploymentClient) -> JsonObject:
    """Verify the deployed health and public MCP contract."""
    health = client.get("/healthz")
    ready = client.get("/readyz")
    discover, discover_headers = client.rpc("server/discover")
    listed, list_headers = client.rpc("tools/list")
    resources, _ = client.rpc("resources/list")
    about, _ = client.rpc(
        "resources/read", {"uri": "nplg://about"}, name="nplg://about"
    )

    if health != {"status": "ok"} or ready != {"status": "ready"}:
        msg = "Health or readiness response was unexpected"
        raise VerificationError(msg)
    versions = discover.get("supportedVersions")
    if not isinstance(versions, list) or PROTOCOL not in versions:
        msg = "server/discover did not advertise the requested protocol"
        raise VerificationError(msg)
    catalog = _tool_catalog(listed)
    if frozenset(catalog) != EXPECTED_TOOLS:
        msg = "Tool catalog mismatch"
        raise VerificationError(msg)
    _verify_annotations(catalog)
    if discover.get("cacheScope") != "private" or listed.get("cacheScope") != "private":
        msg = "Modern list/discovery results must declare private cache scope"
        raise VerificationError(msg)
    if "mcp-session-id" in discover_headers or "mcp-session-id" in list_headers:
        msg = "The stateless endpoint unexpectedly created a session"
        raise VerificationError(msg)
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
    return {
        "status": "pass",
        "protocol": PROTOCOL,
        "tool_count": len(catalog),
        "health": health,
        "ready": ready,
        "sessionless": True,
    }


@dataclass(frozen=True, slots=True)
class VerifyArguments:
    """Validated deployment-verifier arguments."""

    base_url: str
    token: str | None
    api_key: str | None
    timeout: float


def _parser(environ: Mapping[str, str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--base-url",
        required=True,
        help="Deployment base URL, for example https://mcp.example.com",
    )
    _ = parser.add_argument(
        "--token",
        default=environ.get("API_BEARER_TOKEN"),
        help="Bearer token; defaults to API_BEARER_TOKEN",
    )
    _ = parser.add_argument(
        "--api-key",
        default=environ.get("API_KEY"),
        help="API key; defaults to API_KEY",
    )
    _ = parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def _parse_args(
    argv: Sequence[str], dependencies: CliDependencies
) -> VerifyArguments | int:
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
    if not isinstance(base_url, str) or type(timeout) is not float:
        return 2
    if token is not None and not isinstance(token, str):
        return 2
    if api_key is not None and not isinstance(api_key, str):
        return 2
    return VerifyArguments(base_url, token, api_key, timeout)


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
    try:
        client = dependencies.client_factory(
            base_url=parsed.base_url,
            bearer_token=parsed.token,
            timeout=parsed.timeout,
            api_key=parsed.api_key,
        )
        result = dependencies.verifier(client)
    except VerificationError as exc:
        return _write_failure(dependencies, str(exc))
    except KeyboardInterrupt:
        _ = _write_failure(dependencies, "deployment verification cancelled")
        return 130
    return _write_output(result, dependencies)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], dependencies=_default_dependencies()))
