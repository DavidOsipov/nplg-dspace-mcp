#!/usr/bin/env python3
"""Verify a deployed NPLG MCP without depending on the project package."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

PROTOCOL = "2026-07-28"
EXPECTED_TOOLS = {
    "download_document_file",
    "get_document_metadata",
    "get_render_manifest",
    "inspect_pdf",
    "list_document_files",
    "render_pdf_page_tiles",
    "render_pdf_pages",
    "search_documents",
}
CACHE_WRITING_TOOLS = {
    "download_document_file",
    "render_pdf_page_tiles",
    "render_pdf_pages",
}


class VerificationError(RuntimeError):
    pass


def _safe_header_value(value: str) -> str:
    if value and value == value.strip() and all(0x20 <= ord(char) <= 0x7E for char in value):
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


@dataclass(slots=True)
class McpClient:
    base_url: str
    bearer_token: str | None = None
    timeout: float = 30.0
    api_key: str | None = None
    _request_id: int = 0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query or parsed.fragment:
            raise VerificationError("--base-url must be an HTTP(S) origin or base path")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise VerificationError("Plain HTTP is allowed only for local verification")
        if self.bearer_token and self.api_key:
            raise VerificationError("Configure either a bearer token or an API key, not both")

    @property
    def origin(self) -> str:
        parsed = urlsplit(self.base_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _open_json(self, request: Request) -> tuple[int, dict[str, str], Any]:
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - operator-supplied deployment URL
                raw = response.read()
                status = response.status
                headers = {key.lower(): value for key, value in response.headers.items()}
        except HTTPError as exc:
            raw = exc.read()
            status = exc.code
            headers = {key.lower(): value for key, value in exc.headers.items()}
        except URLError as exc:
            raise VerificationError(f"Connection failed: {exc.reason}") from exc
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VerificationError(f"HTTP {status} returned non-JSON data") from exc
        return status, headers, payload

    def get(self, path: str) -> Any:
        status, _, payload = self._open_json(Request(f"{self.base_url}{path}", method="GET"))
        if status != 200:
            raise VerificationError(f"GET {path} returned HTTP {status}: {payload!r}")
        return payload

    def rpc(self, method: str, params: dict[str, Any] | None = None, *, name: str | None = None) -> tuple[Any, dict[str, str]]:
        self._request_id += 1
        values = dict(params or {})
        values["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientInfo": {"name": "nplg-deploy-verifier", "version": "1.0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        body = json.dumps(
            {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": values},
            ensure_ascii=False,
        ).encode("utf-8")
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
        status, response_headers, payload = self._open_json(
            Request(f"{self.base_url}/mcp", data=body, headers=headers, method="POST")
        )
        if status != 200:
            raise VerificationError(f"{method} returned HTTP {status}: {payload!r}")
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or payload.get("id") != self._request_id:
            raise VerificationError(f"{method} returned an invalid JSON-RPC envelope")
        if "error" in payload:
            raise VerificationError(f"{method} returned JSON-RPC error: {payload['error']!r}")
        result = payload.get("result")
        if not isinstance(result, dict) or result.get("resultType") != "complete":
            raise VerificationError(f"{method} omitted the modern MCP result shape")
        return result, response_headers

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result, _ = self.rpc("tools/call", {"name": name, "arguments": arguments}, name=name)
        if result.get("isError") is True:
            raise VerificationError(f"Tool {name} failed: {result.get('structuredContent')!r}")
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise VerificationError(f"Tool {name} returned no structuredContent")
        return structured


def verify(client: McpClient) -> dict[str, Any]:
    health = client.get("/healthz")
    ready = client.get("/readyz")
    discover, discover_headers = client.rpc("server/discover")
    listed, list_headers = client.rpc("tools/list")
    resources, _ = client.rpc("resources/list")
    about, _ = client.rpc("resources/read", {"uri": "nplg://about"}, name="nplg://about")

    if health != {"status": "ok"} or ready != {"status": "ready"}:
        raise VerificationError("Health or readiness response was unexpected")
    if PROTOCOL not in discover.get("supportedVersions", []):
        raise VerificationError("server/discover did not advertise the requested protocol")
    tool_items = [item for item in listed.get("tools", []) if isinstance(item, dict)]
    tools = {item.get("name") for item in tool_items}
    if tools != EXPECTED_TOOLS:
        raise VerificationError(f"Tool catalog mismatch: expected {sorted(EXPECTED_TOOLS)}, got {sorted(tools)}")
    annotation_mismatches = [
        item.get("name")
        for item in tool_items
        if not isinstance(item.get("annotations"), dict)
        or item["annotations"].get("readOnlyHint") is not (item.get("name") not in CACHE_WRITING_TOOLS)
        or item["annotations"].get("destructiveHint") is not False
    ]
    if annotation_mismatches:
        raise VerificationError(
            f"Tool annotation mismatch: {sorted(str(name) for name in annotation_mismatches)}"
        )
    if discover.get("cacheScope") != "private" or listed.get("cacheScope") != "private":
        raise VerificationError("Modern list/discovery results must declare private cache scope")
    if "mcp-session-id" in discover_headers or "mcp-session-id" in list_headers:
        raise VerificationError("The 2026 stateless endpoint unexpectedly created a session")
    if not any(item.get("uri") == "nplg://about" for item in resources.get("resources", [])):
        raise VerificationError("nplg://about resource was not listed")
    contents = about.get("contents", [])
    if not contents or contents[0].get("uri") != "nplg://about":
        raise VerificationError("nplg://about could not be read")

    return {
        "status": "pass",
        "protocol": PROTOCOL,
        "tool_count": len(tools),
        "health": health,
        "ready": ready,
        "sessionless": True,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Deployment base URL, for example https://mcp.example.com")
    parser.add_argument("--token", default=os.getenv("API_BEARER_TOKEN"), help="Bearer token; defaults to API_BEARER_TOKEN")
    parser.add_argument("--api-key", default=os.getenv("API_KEY"), help="API key; defaults to API_KEY")
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify(
            McpClient(
                base_url=args.base_url,
                bearer_token=args.token,
                timeout=args.timeout,
                api_key=args.api_key,
            )
        )
    except VerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
