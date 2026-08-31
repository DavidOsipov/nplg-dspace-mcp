# Copyright (c) 2026 David Osipov
"""Conformance tests for the retained MCP HTTP compatibility layer."""

from __future__ import annotations

import asyncio
import base64
import logging
import socket
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from http import HTTPStatus
from http.cookiejar import Cookie, CookieJar
from typing import TYPE_CHECKING, Literal, cast, override

import httpx
import pytest
import pytest_asyncio
import uvicorn
from pydantic import SecretStr

import nplg_mcp.app as app_module
import nplg_mcp.http_security as http_security_module
from nplg_mcp.app import create_app
from nplg_mcp.bounded_work import STORAGE_WORK
from nplg_mcp.config import (
    ApiPrincipalCredential,
    AppConfig,
    CanonicalHost,
    CanonicalOrigin,
)
from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.http_security import McpSecurityMiddleware
from nplg_mcp.json_types import dump_json, load_json_value, require_json_object
from nplg_mcp.network import BoundAsyncHTTPTransport
from nplg_mcp.services import (
    AppServices,
    FullServiceComposition,
    MetadataServiceComposition,
)
from nplg_mcp.storage import ContentAddressedStore, StoreLifecycleConfiguration
from nplg_mcp.storage_lifecycle import (
    ClockHighWater,
    RetentionClockSample,
    RetentionPolicy,
    StorageCapacity,
)
from nplg_mcp.tokens import sign_asset_token
from tests.helpers.app_factory import make_tool_service

if TYPE_CHECKING:
    from collections.abc import (
        AsyncIterator,
        Callable,
        Mapping,
    )
    from contextlib import AbstractContextManager
    from pathlib import Path

    from fastapi import FastAPI
    from starlette.types import Message, Receive, Scope, Send

    from nplg_mcp.contracts import StrictOutput
    from nplg_mcp.http_types import HttpClientProtocol
    from nplg_mcp.json_types import JsonObject, JsonValue
    from nplg_mcp.repository import NplgRepository
    from nplg_mcp.services import ToolSurface
    from nplg_mcp.tools import ToolService

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
METRICS_SECRET = "m" * 32
JSON_RPC_INVALID_REQUEST = -32600
JSON_RPC_METHOD_NOT_FOUND = -32601
JSON_RPC_INVALID_PARAMS = -32602
JSON_RPC_INTERNAL_ERROR = -32603
MCP_PROTOCOL_VERSION_REQUIRED = -32020
MCP_PROTOCOL_VERSION_UNSUPPORTED = -32022
REQUEST_BODY_LIMIT_BYTES = 4096
OVERSIZED_REQUEST_CHUNK_BYTES = REQUEST_BODY_LIMIT_BYTES + 1
EXPECTED_ADMITTED_TOOL_CALLS = 2
_STORAGE_WORK_CAPACITY = 2
_LEASE_TEST_GIB = 1024 * 1024 * 1024
_LEASE_TEST_CLOCK_ORIGIN = datetime(2026, 1, 1, tzinfo=UTC)


class _LeaseAuditedStore(ContentAddressedStore):
    """Observe the public lease contract while retaining real prune behavior."""

    def __init__(
        self,
        root: Path,
        *,
        lifecycle: StoreLifecycleConfiguration,
    ) -> None:
        super().__init__(root, max_bytes=_LEASE_TEST_GIB, lifecycle=lifecycle)
        self.lease_acquisitions = 0
        self.lease_releases = 0

    @override
    def acquire_asset_lease(self, relative_path: str) -> tuple[str, Path]:
        leased = super().acquire_asset_lease(relative_path)
        self.lease_acquisitions += 1
        return leased

    @override
    def release_asset_lease(
        self,
        key: str,
        *,
        transaction_token: object | None = None,
    ) -> None:
        if transaction_token is None:
            self.lease_releases += 1
        super().release_asset_lease(key, transaction_token=transaction_token)


def _lease_clock_sample(seconds: float) -> RetentionClockSample:
    return RetentionClockSample(
        utc_now=_LEASE_TEST_CLOCK_ORIGIN + timedelta(seconds=seconds),
        monotonic_now=seconds,
        boot_id="lease-test-boot",
        synchronized=True,
    )


def _lease_test_store(
    tmp_path: Path,
) -> tuple[_LeaseAuditedStore, RetentionPolicy, RetentionClockSample]:
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=_LEASE_TEST_GIB,
        maximum_objects=1,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    capacity = StorageCapacity(
        total_bytes=4 * _LEASE_TEST_GIB,
        available_bytes=3 * _LEASE_TEST_GIB,
        total_inodes=1_000_000,
        available_inodes=900_000,
    )
    guard = ClockHighWater(
        tmp_path / "lease-clock-high-water.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    initial = _lease_clock_sample(0.0)
    _ = guard.observe(initial)
    assert guard.observe(initial).trusted is True
    clock = _lease_clock_sample(1.0)
    lifecycle = StoreLifecycleConfiguration(
        policy=policy,
        capacity_sampler=lambda: capacity,
        clock_high_water=guard,
        clock_sampler=lambda: clock,
    )
    return (
        _LeaseAuditedStore(tmp_path / "lease-cache", lifecycle=lifecycle),
        policy,
        clock,
    )


class StubTools:
    """Small typed tool-service double for HTTP protocol behavior."""

    @staticmethod
    def _bounded_adversarial_result(value: object) -> JsonObject | None:
        if value == "deep-result":
            root: JsonObject = {}
            node = root
            for _ in range(65):
                child: JsonObject = {}
                node["child"] = child
                node = child
            return root
        if value == "cycle-result":
            cyclic: JsonObject = {}
            cyclic["self"] = cast("JsonValue", cyclic)
            return cyclic
        if value == "many-values-result":
            values: list[JsonValue] = [None for _ in range(16_385)]
            return {"values": values}
        if value == "multibyte-result":
            return {"value": "\U0001f600" * 300_000}
        return None

    @staticmethod
    def _invalid_adversarial_result(value: object) -> JsonObject | None:
        if value == "invalid-key-result":
            invalid: dict[object, object] = {1: "value"}
            return cast("JsonObject", invalid)
        if value == "nonfinite-result":
            return {"value": float("inf")}
        return None

    def list_tools(self) -> list[JsonObject]:
        return [
            {
                "name": "echo",
                "title": "Echo",
                "description": "Echo structured input.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
            }
        ]

    async def call(self, name: str, arguments: JsonObject) -> JsonObject:
        if name != "echo":
            raise AppError(ErrorCode.INVALID_INPUT, "Unknown tool.")
        if arguments.get("value") == "domain-error":
            raise AppError(ErrorCode.RESTRICTED, "Restricted fixture.", http_status=403)
        if arguments.get("value") == "unexpected-error":
            msg = "sensitive fixture detail"
            raise RuntimeError(msg)
        if arguments.get("value") == "asset":
            return {
                "asset_url": "https://mcp.example.test/assets/signed-capability",
                "relative_path": "documents/doc_fixture/source.pdf",
                "media_type": "application/pdf",
                "size": 123,
            }
        if arguments.get("value") == "nested-assets":
            return {
                "items": [
                    {
                        "asset_url": "https://mcp.example.test/assets/minimal",
                        "media_type": None,
                        "size": True,
                    },
                    {
                        "asset_url": "ftp://mcp.example.test/assets/rejected",
                        "relative_path": "rejected.bin",
                    },
                    {
                        "asset_url": "https://mcp.example.test/assets/minimal",
                        "relative_path": "duplicate.bin",
                    },
                    {
                        "manifest_asset_url": (
                            "https://mcp.example.test/assets/manifest"
                        ),
                        "manifest_relative_path": "renders/manifest.json",
                    },
                ]
            }
        if arguments.get("value") == "oversized-result":
            return {"value": "x" * (2 * 1024 * 1024)}
        bounded = self._bounded_adversarial_result(arguments.get("value"))
        if bounded is not None:
            return bounded
        invalid = self._invalid_adversarial_result(arguments.get("value"))
        if invalid is not None:
            return invalid
        return {"echo": arguments["value"]}

    def list_resources(self) -> list[JsonObject]:
        return [
            {
                "uri": "nplg://about",
                "name": "NPLG MCP server information",
                "mimeType": "application/json",
            }
        ]

    async def read_resource(self, uri: str) -> dict[str, str]:
        if uri != "nplg://about":
            raise AppError(ErrorCode.NOT_FOUND, "Resource not found.", http_status=404)
        return {
            "uri": uri,
            "mime_type": "application/json",
            "text": dump_json({"read_only": True}),
        }


class UnreadyStubTools(StubTools):
    """Expose a sanitized stateful-dependency readiness failure."""

    def ensure_ready(self) -> None:
        raise AppError(
            ErrorCode.PDF_PROCESSING_FAILED,
            "The PDF worker is temporarily unavailable.",
            http_status=503,
        )


def config(
    tmp_path: Path,
    *,
    token: str | None = None,
    api_key: str | None = None,
    anonymous: bool = True,
) -> AppConfig:
    return AppConfig(
        environment="test",
        nplg_base_url="https://dspace.nplg.gov.ge/",
        cache_dir=tmp_path,
        public_base_url="https://mcp.example.test",
        asset_signing_secret=b"s" * 32,
        api_bearer_token=token,
        api_key=api_key,
        allow_anonymous=anonymous,
        max_download_bytes=1024 * 1024,
        max_render_pages=8,
        max_page_pixels=120_000_000,
        max_render_pixels=480_000_000,
        max_request_body_bytes=REQUEST_BODY_LIMIT_BYTES,
        tile_width=2048,
        tile_height=2048,
        tile_overlap=128,
        asset_ttl_seconds=3600,
        upstream_timeout_seconds=30,
        upstream_rate_per_second=1,
        max_redirects=3,
        cursor_signing_secret=b"c" * 32,
        max_concurrent_mcp_requests=16,
        max_concurrent_asset_streams=8,
    )


def rpc_body(
    method: str, params: JsonObject | None = None, *, request_id: int = 1
) -> JsonObject:
    values: JsonObject = dict(params or {})
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": values}


def modern_body(
    method: str, params: JsonObject | None = None, *, request_id: int = 1
) -> JsonObject:
    values: JsonObject = dict(params or {})
    values["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": {"name": "pytest", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return rpc_body(method, values, request_id=request_id)


def _json_array(value: JsonValue, *, context: str) -> list[JsonValue]:
    if not isinstance(value, list):
        msg = f"{context} must be a JSON array"
        raise TypeError(msg)
    return value


def _json_object(value: JsonValue, *, context: str) -> JsonObject:
    return require_json_object(value, context=context)


def _json_string(value: JsonValue, *, context: str) -> str:
    if not isinstance(value, str):
        msg = f"{context} must be a JSON string"
        raise TypeError(msg)
    return value


def _response_object(response: httpx.Response) -> JsonObject:
    return require_json_object(
        load_json_value(response.content),
        context="HTTP response body",
    )


def _response_value(response: httpx.Response, *path: str | int) -> JsonValue:
    value: JsonValue = _response_object(response)
    traversed: list[str] = []
    for segment in path:
        traversed.append(str(segment))
        context = ".".join(traversed)
        if isinstance(segment, str):
            values = _json_object(value, context=context)
            if segment not in values:
                pytest.fail(f"HTTP response is missing {context}")
            value = values[segment]
        else:
            value = _json_array(value, context=context)[segment]
    return value


def _http_scope(
    path: str,
    *,
    method: str,
    headers: tuple[tuple[bytes, bytes], ...] = (),
) -> dict[str, object]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"mcp.example.test"), *headers],
        "client": ("127.0.0.1", 12345),
        "server": ("mcp.example.test", 443),
    }


async def _send_ok_json(send: Send) -> None:
    """Send one minimal typed ASGI JSON response from boundary test doubles."""
    headers: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
    start: dict[str, object] = {
        "type": "http.response.start",
        "status": HTTPStatus.OK,
        "headers": headers,
    }
    body: dict[str, object] = {"type": "http.response.body", "body": b"{}"}
    await send(cast("Message", start))
    await send(cast("Message", body))


def modern_headers(method: str, *, name: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MODERN,
        "Mcp-Method": method,
        "Content-Type": "application/json",
        "Origin": "https://mcp.example.test",
    }
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


@pytest_asyncio.fixture  # type: ignore[misc]
async def app(tmp_path: Path) -> AsyncIterator[FastAPI]:
    cfg = replace(
        config(tmp_path, token=METRICS_SECRET),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = create_app(
        cfg,
        services=FullServiceComposition(
            tools=StubTools(), store=ContentAddressedStore(tmp_path)
        ),
    )
    started = asyncio.Event()
    stop = asyncio.Event()

    async def run_lifespan() -> None:
        async with application.router.lifespan_context(application):
            started.set()
            _ = await stop.wait()

    task = asyncio.create_task(run_lifespan())
    async with asyncio.timeout(1):
        _ = await started.wait()
    try:
        yield application
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_official_sdk_backend_is_reachable_only_at_mcp(app: FastAPI) -> None:
    """One outer mount reaches the live official SDK with canonical policy headers."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            json=modern_body("server/discover"),
        )
        doubled = await client.post(
            "/mcp/mcp",
            headers=modern_headers("server/discover"),
            json=modern_body("server/discover"),
        )

    assert response.status_code == HTTPStatus.OK
    assert _response_value(response, "result", "supportedVersions") == [MODERN]
    assert doubled.status_code == HTTPStatus.NOT_FOUND
    assert response.headers.get_list("content-security-policy") == [
        (
            "default-src 'none'; base-uri 'none'; object-src 'none'; "
            "frame-ancestors 'none'"
        )
    ]
    assert response.headers.get_list("x-content-type-options") == ["nosniff"]
    assert response.headers.get_list("referrer-policy") == ["no-referrer"]
    assert response.headers.get_list("cache-control") == ["no-store, no-transform"]
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "version",
    [None, "2025-03-26", "2025-06-18", LEGACY],
    ids=["absent", "2025-03-26", "2025-06-18", "2025-11-25"],
)
async def test_modern_only_guard_rejects_project_owned_versions(
    app: FastAPI,
    version: str | None,
) -> None:
    """Absent and handshake-era versions stop at the project routing boundary."""
    headers = modern_headers("server/discover")
    if version is None:
        del headers["MCP-Protocol-Version"]
    else:
        headers["MCP-Protocol-Version"] = version
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post(
            "/mcp",
            headers=headers,
            json=modern_body("server/discover"),
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert _response_object(response) == {"error": "Invalid MCP protocol version"}


@pytest.mark.asyncio
async def test_safe_unsupported_version_reaches_sdk_oracles(app: FastAPI) -> None:
    """A bounded non-handshake sentinel remains the official SDK's decision."""
    sentinel = "v999.0.0"
    body = modern_body("server/discover")
    params = _json_object(body["params"], context="params")
    meta = _json_object(params["_meta"], context="params._meta")
    meta["io.modelcontextprotocol/protocolVersion"] = sentinel
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://mcp.example.test",
    ) as client:
        unsupported = await client.post(
            "/mcp",
            headers={
                **modern_headers("server/discover"),
                "MCP-Protocol-Version": sentinel,
            },
            json=body,
        )
        mismatched = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            json=body,
        )

    assert unsupported.status_code == HTTPStatus.BAD_REQUEST
    assert _response_value(unsupported, "error") == {
        "code": MCP_PROTOCOL_VERSION_UNSUPPORTED,
        "message": "Unsupported protocol version",
        "data": {"supported": [MODERN], "requested": sentinel},
    }
    assert mismatched.status_code == HTTPStatus.BAD_REQUEST
    assert _response_value(mismatched, "error", "code") == MCP_PROTOCOL_VERSION_REQUIRED


@pytest.mark.asyncio
async def test_safe_http_token_protocol_version_reaches_sdk_unchanged(
    tmp_path: Path,
) -> None:
    """Non-handshake HTTP token punctuation is an SDK oracle input, not outer policy."""
    seen_versions: list[bytes] = []

    async def recording_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        del receive
        scope_values = cast("dict[str, object]", scope)
        headers = cast("list[tuple[bytes, bytes]]", scope_values["headers"])
        seen_versions.extend(
            value for name, value in headers if name.lower() == b"mcp-protocol-version"
        )
        await _send_ok_json(send)

    configured = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(recording_sdk, config=configured)
    application.start()
    headers = {
        **modern_headers("server/discover"),
        "MCP-Protocol-Version": "v999+test",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post("/mcp", headers=headers, content=b"{}")

    assert response.status_code == HTTPStatus.OK
    assert seen_versions == [b"v999+test"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe_version",
    [
        b"",
        b"a" * 33,
        b" leading",
        b"trailing ",
        b"v1,v2",
        b"v1\tv2",
        b"v1\r\n v2",
        b"v1/v2",
        b"\xff",
    ],
    ids=[
        "empty",
        "first-length-excess",
        "leading-space",
        "trailing-space",
        "comma",
        "tab",
        "obs-fold",
        "non-token-ascii",
        "non-ascii",
    ],
)
async def test_unsafe_protocol_version_bytes_stop_before_sdk(
    tmp_path: Path,
    unsafe_version: bytes,
) -> None:
    """Unsafe, ambiguous, or unbounded version bytes never enter SDK dispatch."""
    calls = 0

    async def recording_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        await _send_ok_json(send)

    configured = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(recording_sdk, config=configured)
    application.start()
    raw_headers = (
        *(
            (name.lower().encode(), value.encode())
            for name, value in modern_headers("server/discover").items()
            if name != "MCP-Protocol-Version"
        ),
        (b"mcp-protocol-version", unsafe_version),
    )
    scope = cast("Scope", _http_scope("/mcp", method="POST", headers=raw_headers))
    received = False

    async def receive() -> Message:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": b"{}", "more_body": False}

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await application(scope, receive, send)

    messages = [cast("dict[str, object]", message) for message in sent]
    starts = [
        message for message in messages if message.get("type") == "http.response.start"
    ]
    assert [message.get("status") for message in starts] == [HTTPStatus.BAD_REQUEST]
    assert calls == 0


@pytest.mark.asyncio
async def test_protocol_version_byte_length_accepts_exact_limit(
    tmp_path: Path,
) -> None:
    """The 32-byte safe token boundary is forwarded rather than rejected early."""
    seen_versions: list[bytes] = []

    async def recording_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        del receive
        scope_values = cast("dict[str, object]", scope)
        headers = cast("list[tuple[bytes, bytes]]", scope_values["headers"])
        seen_versions.extend(
            value for name, value in headers if name.lower() == b"mcp-protocol-version"
        )
        await _send_ok_json(send)

    configured = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(recording_sdk, config=configured)
    application.start()
    headers = {
        **modern_headers("server/discover"),
        "MCP-Protocol-Version": "a" * 32,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post("/mcp", headers=headers, content=b"{}")

    assert response.status_code == HTTPStatus.OK
    assert seen_versions == [b"a" * 32]


@pytest.mark.asyncio
async def test_outer_and_sdk_host_origin_decisions_agree(app: FastAPI) -> None:
    """Exact configured authorities are shared; absent Origin remains admissible."""
    body = modern_body("server/discover")
    base_headers = modern_headers("server/discover")
    without_origin = dict(base_headers)
    del without_origin["Origin"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://mcp.example.test",
    ) as client:
        admitted = await client.post("/mcp", headers=without_origin, json=body)
        wrong_host = await client.post(
            "/mcp",
            headers={**base_headers, "Host": "evil.example"},
            json=body,
        )
        wrong_origin = await client.post(
            "/mcp",
            headers={**base_headers, "Origin": "https://evil.example"},
            json=body,
        )

    assert admitted.status_code == HTTPStatus.OK
    for rejected in (wrong_host, wrong_origin):
        assert rejected.status_code == HTTPStatus.FORBIDDEN
        assert _response_object(rejected) == {"error": "Host or Origin is not allowed"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "encoding_headers",
    [
        [("Content-Encoding", "gzip")],
        [("Content-Encoding", "br")],
        [("Content-Encoding", "deflate")],
        [("Content-Encoding", "identity, gzip")],
        [("Content-Encoding", "identity"), ("Content-Encoding", "identity")],
    ],
    ids=["gzip", "br", "deflate", "comma-separated", "duplicate-identity"],
)
async def test_content_encoding_is_identity_only(
    app: FastAPI,
    encoding_headers: list[tuple[str, str]],
) -> None:
    """Compressed and ambiguous bodies stop before the SDK parser."""
    headers = [*modern_headers("server/discover").items(), *encoding_headers]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post(
            "/mcp",
            headers=headers,
            content=dump_json(modern_body("server/discover")).encode(),
        )

    assert response.status_code == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    assert _response_object(response) == {"error": "Unsupported content encoding"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "framing_headers",
    [
        [("Content-Length", "2"), ("Content-Length", "2")],
        [("Content-Length", "2"), ("Transfer-Encoding", "chunked")],
    ],
    ids=["duplicate-content-length", "content-length-transfer-encoding"],
)
async def test_ambiguous_framing_never_reaches_sdk(
    tmp_path: Path,
    framing_headers: list[tuple[str, str]],
) -> None:
    calls = 0

    async def recording_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(recording_sdk, config=cfg)
    application.start()
    headers = [*modern_headers("server/discover").items(), *framing_headers]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post("/mcp", headers=headers, content=b"{}")

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert calls == 0


@pytest.mark.asyncio
async def test_body_limit_rejects_first_excess_chunk_before_sdk(
    tmp_path: Path,
) -> None:
    calls = 0

    async def recording_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        max_request_body_bytes=2,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(recording_sdk, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        exact = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}",
        )
        excess = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}x",
        )

    assert exact.status_code == HTTPStatus.OK
    assert excess.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/merge-patch+json"],
)
async def test_json_post_requires_exact_json_media_type(
    tmp_path: Path,
    content_type: str | None,
) -> None:
    calls = 0

    async def recording_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(recording_sdk, config=cfg)
    application.start()
    headers = modern_headers("server/discover")
    if content_type is None:
        del headers["Content-Type"]
    else:
        headers["Content-Type"] = content_type
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post("/mcp", headers=headers, content=b"{}")

    assert response.status_code == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    assert calls == 0


@pytest.mark.asyncio
async def test_original_json_bytes_reach_sdk_exactly_once(tmp_path: Path) -> None:
    original = b'{ "value" : "\\u0061" }'
    original_receive_calls = 0
    sdk_bodies: list[bytes] = []

    async def recording_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        del scope
        message = cast("dict[str, object]", await receive())
        sdk_bodies.append(cast("bytes", message.get("body", b"")))
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(recording_sdk, config=cfg)
    application.start()
    raw_headers = tuple(
        (name.lower().encode(), value.encode())
        for name, value in modern_headers("server/discover").items()
    )
    scope = cast("Scope", _http_scope("/mcp", method="POST", headers=raw_headers))

    async def receive() -> Message:
        nonlocal original_receive_calls
        original_receive_calls += 1
        event: dict[str, object] = {
            "type": "http.request",
            "body": original,
            "more_body": False,
        }
        return cast("Message", event)

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await application(scope, receive, send)

    assert sdk_bodies == [original]
    assert original_receive_calls == 1
    assert sent


@pytest.mark.asyncio
async def test_response_policy_replaces_conflicting_downstream_headers(
    tmp_path: Path,
) -> None:
    async def conflicting_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        start: dict[str, object] = {
            "type": "http.response.start",
            "status": HTTPStatus.OK,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-security-policy", b"default-src *"),
                (b"content-security-policy", b"script-src *"),
                (b"x-content-type-options", b"invalid"),
                (b"referrer-policy", b"unsafe-url"),
                (b"cache-control", b"public, max-age=3600"),
                (b"access-control-allow-origin", b"*"),
                (b"x-accel-buffering", b"yes"),
            ],
        }
        body: dict[str, object] = {
            "type": "http.response.body",
            "body": b"{}",
        }
        await send(cast("Message", start))
        await send(cast("Message", body))

    cfg = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(conflicting_sdk, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}",
        )

    assert response.headers.get_list("content-security-policy") == [
        (
            "default-src 'none'; base-uri 'none'; object-src 'none'; "
            "frame-ancestors 'none'"
        )
    ]
    assert response.headers.get_list("x-content-type-options") == ["nosniff"]
    assert response.headers.get_list("referrer-policy") == ["no-referrer"]
    assert response.headers.get_list("cache-control") == ["no-store, no-transform"]
    assert "access-control-allow-origin" not in response.headers
    assert "x-accel-buffering" not in response.headers


@pytest.mark.asyncio
async def test_sse_policy_preserves_single_no_buffering_and_keepalive(
    tmp_path: Path,
) -> None:
    keepalive = b": ping - 2026-08-21T00:00:00+00:00\n\n"

    async def silent_sse(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        start: dict[str, object] = {
            "type": "http.response.start",
            "status": HTTPStatus.OK,
            "headers": [
                (b"content-type", b"text/event-stream"),
                (b"x-accel-buffering", b"yes"),
                (b"x-accel-buffering", b"no"),
            ],
        }
        body: dict[str, object] = {
            "type": "http.response.body",
            "body": keepalive,
        }
        await send(cast("Message", start))
        await send(cast("Message", body))

    cfg = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(silent_sse, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}",
        )

    assert response.headers.get_list("x-accel-buffering") == ["no"]
    assert response.content == keepalive


@pytest.mark.asyncio
async def test_json_preflight_rejects_duplicate_keys_before_sdk(app: FastAPI) -> None:
    """Escaped-equivalent duplicate members cannot reach SDK JSON allocation."""
    payload = (
        b'{"jsonrpc":"2.0","id":1,"method":"server/discover",'
        b'"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":'
        b'"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},'
        b'"dup":1,"\\u0064up":2}}}'
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=payload,
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert _response_object(response) == {"error": "Invalid JSON request body"}


@pytest.mark.asyncio
async def test_protected_mcp_retains_auth_admission_until_sdk_oauth_task(
    tmp_path: Path,
) -> None:
    """The SDK migration does not temporarily expose a configured protected app."""
    secret = "a" * 32
    configured = replace(
        config(tmp_path, token=secret, anonymous=False),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(),
    )
    protected = create_app(
        configured,
        services=MetadataServiceComposition(tools=StubTools()),
    )
    async with (
        protected.router.lifespan_context(protected),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=protected),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        missing = await client.post(
            "/mcp",
            headers={
                key: value
                for key, value in modern_headers("server/discover").items()
                if key != "Origin"
            },
            json=modern_body("server/discover"),
        )
        admitted = await client.post(
            "/mcp",
            headers={
                **{
                    key: value
                    for key, value in modern_headers("server/discover").items()
                    if key != "Origin"
                },
                "Authorization": f"Bearer {secret}",
            },
            json=modern_body("server/discover", request_id=2),
        )

    assert missing.status_code == HTTPStatus.UNAUTHORIZED
    assert _response_object(missing) == {"error": "API authentication is required"}
    assert admitted.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_streamable_http_strict_arguments_never_enter_handler(
    tmp_path: Path,
) -> None:
    class RecordingTools:
        def __init__(self, delegate: ToolSurface) -> None:
            super().__init__()
            self.delegate = delegate
            self.calls: list[tuple[str, JsonObject]] = []

        def list_tools(self) -> list[JsonObject]:
            return self.delegate.list_tools()

        async def call(
            self,
            name: str,
            arguments: JsonObject,
        ) -> StrictOutput | JsonObject:
            self.calls.append((name, arguments))
            return await self.delegate.call(name, arguments)

        def list_resources(self) -> list[JsonObject]:
            return self.delegate.list_resources()

        async def read_resource(self, uri: str) -> dict[str, str]:
            return await self.delegate.read_resource(uri)

    canary = "http-strict-argument-canary"
    tools = RecordingTools(
        make_tool_service(tmp_path, deployment_profile="alpic-metadata")
    )
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = create_app(
        configured,
        services=MetadataServiceComposition(tools=tools),
    )
    invalid_arguments: list[JsonObject] = [
        {"query": "fixture", "unexpected": canary},
        {"query": "fixture", "pageSize": 20},
        {"query": "fixture", "page_size": "20"},
        {"query": "fixture", "page_size": True},
        {"query": "fixture", "filters": {"unexpected": canary}},
    ]
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        rejected = [
            await client.post(
                "/mcp",
                headers=modern_headers("tools/call", name="search_documents"),
                json=modern_body(
                    "tools/call",
                    {"name": "search_documents", "arguments": arguments},
                ),
            )
            for arguments in invalid_arguments
        ]
        admitted = await client.post(
            "/mcp",
            headers=modern_headers("tools/call", name="search_documents"),
            json=modern_body(
                "tools/call",
                {"name": "search_documents", "arguments": {"query": "fixture"}},
            ),
        )

    for response in rejected:
        assert response.status_code == HTTPStatus.OK
        assert _response_value(response, "result", "isError") is True
        assert (
            _response_value(
                response,
                "result",
                "structuredContent",
                "error",
                "code",
            )
            == ErrorCode.INVALID_INPUT.value
        )
        assert _response_value(response, "result", "content", 0, "text") == (
            "Tool arguments did not match the declared schema."
        )
        assert canary not in response.text
    assert tools.calls == [("search_documents", {"query": "fixture"})]
    assert admitted.status_code == HTTPStatus.OK
    assert _response_value(admitted, "result", "content", 0, "text") == (
        "Tool completed successfully."
    )


@pytest.mark.asyncio
async def test_streamable_http_preserves_exact_unknown_tool_protocol_error(
    tmp_path: Path,
) -> None:
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = create_app(configured)
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        response = await client.post(
            "/mcp",
            headers=modern_headers(
                "tools/call",
                name="attacker-controlled-unknown-tool",
            ),
            json=modern_body(
                "tools/call",
                {"name": "attacker-controlled-unknown-tool", "arguments": {}},
            ),
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert _response_value(response, "error", "code") == JSON_RPC_INVALID_PARAMS
    assert _response_value(response, "error", "message") == "Unknown tool."
    assert _response_value(response, "error", "data") == {"code": "UNKNOWN_TOOL"}
    assert "attacker-controlled" not in response.text


@pytest.mark.asyncio
async def test_streamable_http_keeps_domain_and_unexpected_tool_failures_separate(
    tmp_path: Path,
) -> None:
    class FaultTools:
        def __init__(self, delegate: ToolSurface) -> None:
            super().__init__()
            self.delegate = delegate

        def list_tools(self) -> list[JsonObject]:
            return self.delegate.list_tools()

        async def call(
            self,
            name: str,
            arguments: JsonObject,
        ) -> StrictOutput | JsonObject:
            query = arguments.get("query")
            if query == "domain-error":
                raise AppError(
                    ErrorCode.RESTRICTED,
                    "The requested operation is restricted.",
                    http_status=403,
                    internal_details={"canary": "domain-http-private-canary"},
                )
            if query == "unexpected-error":
                message = "unexpected-http-private-canary"
                raise RuntimeError(message)
            return await self.delegate.call(name, arguments)

        def list_resources(self) -> list[JsonObject]:
            return self.delegate.list_resources()

        async def read_resource(self, uri: str) -> dict[str, str]:
            return await self.delegate.read_resource(uri)

    tools = FaultTools(make_tool_service(tmp_path, deployment_profile="alpic-metadata"))
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = create_app(
        configured,
        services=MetadataServiceComposition(tools=tools),
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        domain = await client.post(
            "/mcp",
            headers=modern_headers("tools/call", name="search_documents"),
            json=modern_body(
                "tools/call",
                {
                    "name": "search_documents",
                    "arguments": {"query": "domain-error"},
                },
            ),
        )
        unexpected = await client.post(
            "/mcp",
            headers=modern_headers("tools/call", name="search_documents"),
            json=modern_body(
                "tools/call",
                {
                    "name": "search_documents",
                    "arguments": {"query": "unexpected-error"},
                },
                request_id=2,
            ),
        )

    assert domain.status_code == HTTPStatus.OK
    assert _response_value(domain, "result", "isError") is True
    assert (
        _response_value(
            domain,
            "result",
            "structuredContent",
            "error",
            "code",
        )
        == ErrorCode.RESTRICTED.value
    )
    assert _response_value(domain, "result", "content", 0, "text") == (
        "The requested operation is restricted."
    )
    assert "domain-http-private-canary" not in domain.text
    assert unexpected.status_code == HTTPStatus.OK
    assert _response_value(unexpected, "error", "code") == JSON_RPC_INTERNAL_ERROR
    assert _response_value(unexpected, "error", "message") == "Internal tool error."
    assert "unexpected-http-private-canary" not in unexpected.text


@pytest.mark.asyncio
async def test_modern_server_discover_is_stateless_and_cacheable(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            json=modern_body("server/discover"),
        )

    assert response.status_code == HTTPStatus.OK
    assert "Mcp-Session-Id" not in response.headers
    assert _response_value(response, "result", "resultType") == "complete"
    assert _response_value(response, "result", "supportedVersions") == [MODERN]
    assert _response_value(response, "result", "capabilities") == {
        "tools": {"listChanged": False},
        "resources": {"listChanged": False, "subscribe": False},
    }
    assert _response_value(response, "result", "ttlMs") == 0
    assert _response_value(response, "result", "cacheScope") == "private"
    assert (
        _response_value(
            response,
            "result",
            "_meta",
            "io.modelcontextprotocol/serverInfo",
            "name",
        )
        == "nplg-dspace-mcp"
    )


@pytest.mark.asyncio
async def test_official_modern_tools_list_includes_required_result_shape(
    app: FastAPI,
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        listed = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            json=modern_body("tools/list"),
        )

    assert listed.status_code == HTTPStatus.OK
    assert _response_value(listed, "result", "resultType") == "complete"
    assert _response_value(listed, "result", "tools", 0, "name") == "echo"
    assert _response_value(listed, "result", "cacheScope") == "private"


@pytest.mark.asyncio
async def test_modern_rejects_missing_or_mismatched_headers_and_meta(
    app: FastAPI,
) -> None:
    body = modern_body("tools/call", {"name": "echo", "arguments": {"value": "x"}})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        missing_name = await client.post(
            "/mcp", headers=modern_headers("tools/call"), json=body
        )
        mismatch = await client.post(
            "/mcp",
            headers=modern_headers("tools/call", name="different"),
            json=body,
        )
        bad_meta = modern_body("tools/list")
        params = _json_object(bad_meta["params"], context="params")
        meta = _json_object(params["_meta"], context="params._meta")
        del meta["io.modelcontextprotocol/clientCapabilities"]
        missing_meta = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            json=bad_meta,
        )

    for response in (missing_name, mismatch):
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert (
            _response_value(response, "error", "code") == MCP_PROTOCOL_VERSION_REQUIRED
        )
    assert missing_meta.status_code == HTTPStatus.BAD_REQUEST
    assert _response_value(missing_meta, "error", "code") == JSON_RPC_INVALID_PARAMS


@pytest.mark.asyncio
async def test_non_initialize_request_requires_an_explicit_protocol_version(
    app: FastAPI,
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.post(
            "/mcp",
            headers={
                "Content-Type": "application/json",
                "Origin": "https://mcp.example.test",
            },
            json=rpc_body("tools/list"),
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert _response_object(response) == {"error": "Invalid MCP protocol version"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("header", "conflicting"),
    [
        ("MCP-Protocol-Version", LEGACY),
        ("Mcp-Method", "tools/list"),
        ("Mcp-Name", "different"),
    ],
)
async def test_duplicate_mcp_singleton_headers_are_rejected(
    app: FastAPI,
    header: str,
    conflicting: str,
) -> None:
    headers = list(modern_headers("tools/call", name="echo").items())
    headers.append((header, conflicting))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.post(
            "/mcp",
            headers=headers,
            json=modern_body(
                "tools/call", {"name": "echo", "arguments": {"value": "x"}}
            ),
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    expected = (
        "Invalid MCP protocol version"
        if header == "MCP-Protocol-Version"
        else "Ambiguous request headers"
    )
    assert _response_object(response) == {"error": expected}


@pytest.mark.asyncio
async def test_duplicate_origin_and_host_headers_fail_closed(app: FastAPI) -> None:
    base_headers = list(modern_headers("tools/list").items())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        duplicate_origin = await client.post(
            "/mcp",
            headers=[*base_headers, ("Origin", "https://evil.example")],
            json=modern_body("tools/list"),
        )
        duplicate_host = await client.post(
            "/mcp",
            headers=[
                *base_headers,
                ("Host", "mcp.example.test"),
                ("Host", "evil.example"),
            ],
            json=modern_body("tools/list"),
        )

    assert duplicate_origin.status_code == HTTPStatus.FORBIDDEN
    assert duplicate_host.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.asyncio
async def test_unsupported_version_returns_reserved_mcp_error(app: FastAPI) -> None:
    body = modern_body("tools/list")
    params = _json_object(body["params"], context="params")
    meta = _json_object(params["_meta"], context="params._meta")
    meta["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "MCP-Protocol-Version": "2099-01-01",
            },
            json=body,
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert (
        _response_value(response, "error", "code") == MCP_PROTOCOL_VERSION_UNSUPPORTED
    )
    assert _response_value(response, "error", "data") == {
        "requested": "2099-01-01",
        "supported": [MODERN],
    }


@pytest.mark.asyncio
async def test_live_outer_app_rejects_legacy_initialize_and_followup(
    app: FastAPI,
) -> None:
    initialize: JsonObject = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY,
            "capabilities": {},
            "clientInfo": {"name": "legacy-test", "version": "1"},
        },
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        initialized = await client.post(
            "/mcp",
            headers={
                "Content-Type": "application/json",
                "Origin": "https://mcp.example.test",
            },
            json=initialize,
        )
        listed = await client.post(
            "/mcp",
            headers={
                "Content-Type": "application/json",
                "MCP-Protocol-Version": LEGACY,
                "Origin": "https://mcp.example.test",
            },
            json=rpc_body("tools/list", request_id=2),
        )

    assert initialized.status_code == HTTPStatus.BAD_REQUEST
    assert listed.status_code == HTTPStatus.BAD_REQUEST
    assert _response_object(initialized) == {"error": "Invalid MCP protocol version"}
    assert _response_object(listed) == {"error": "Invalid MCP protocol version"}


@pytest.mark.asyncio
async def test_json_rpc_parse_invalid_request_method_and_params_errors(
    app: FastAPI,
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        parsed = await client.post(
            "/mcp", headers=modern_headers("tools/list"), content=b"{"
        )
        invalid_body: JsonObject = {"jsonrpc": "2.0", "id": 1}
        invalid = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            json=invalid_body,
        )
        unknown = await client.post(
            "/mcp",
            headers=modern_headers("unknown/method"),
            json=modern_body("unknown/method"),
        )
        params = await client.post(
            "/mcp",
            headers=modern_headers("tools/call", name="echo"),
            json=modern_body("tools/call", {"name": "echo", "arguments": []}),
        )

    assert _response_object(parsed) == {"error": "Invalid JSON request body"}
    assert _response_value(invalid, "error", "code") == JSON_RPC_INVALID_REQUEST
    assert unknown.status_code == HTTPStatus.NOT_FOUND
    assert _response_value(unknown, "error", "code") == JSON_RPC_METHOD_NOT_FOUND
    assert _response_value(params, "error", "code") == JSON_RPC_INVALID_PARAMS


@pytest.mark.asyncio
async def test_resources_list_and_read(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        listed = await client.post(
            "/mcp",
            headers=modern_headers("resources/list"),
            json=modern_body("resources/list"),
        )
        read = await client.post(
            "/mcp",
            headers=modern_headers("resources/read", name="nplg://about"),
            json=modern_body("resources/read", {"uri": "nplg://about"}),
        )

    assert _response_value(listed, "result", "resources", 0, "uri") == "nplg://about"
    content = _json_object(
        _response_value(read, "result", "contents", 0), context="contents[0]"
    )
    assert _response_value(read, "result", "ttlMs") == 0
    assert _response_value(read, "result", "cacheScope") == "private"
    assert content["uri"] == "nplg://about"
    text = _json_string(content["text"], context="contents[0].text")
    assert load_json_value(text) == {"read_only": True}


@pytest.mark.asyncio
async def test_modern_decodes_base64_sentinel_mcp_name_header(app: FastAPI) -> None:
    uri = "nplg://about"
    encoded = base64.b64encode(uri.encode("utf-8")).decode("ascii")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.post(
            "/mcp",
            headers=modern_headers("resources/read", name=f"=?base64?{encoded}?="),
            json=modern_body("resources/read", {"uri": uri}),
        )

    assert response.status_code == HTTPStatus.OK
    assert _response_value(response, "result", "contents", 0, "uri") == uri


@pytest.mark.asyncio
async def test_readiness_fails_when_a_stateful_tool_dependency_is_open(
    tmp_path: Path,
) -> None:
    application = create_app(
        config(tmp_path),
        services=FullServiceComposition(
            tools=UnreadyStubTools(),
            store=ContentAddressedStore(tmp_path),
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        health = await client.get("/healthz")
        ready = await client.get("/readyz")

    assert health.status_code == HTTPStatus.OK
    assert ready.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert load_json_value(ready.text) == {
        "error": {
            "code": ErrorCode.PDF_PROCESSING_FAILED.value,
            "message": "The PDF worker is temporarily unavailable.",
        }
    }


@pytest.mark.asyncio
async def test_readiness_does_not_consume_authenticated_storage_capacity(
    tmp_path: Path,
) -> None:
    application = create_app(
        config(tmp_path),
        services=FullServiceComposition(
            tools=StubTools(),
            store=ContentAddressedStore(tmp_path),
        ),
    )
    loop = asyncio.get_running_loop()
    release = threading.Event()
    started = (asyncio.Event(), asyncio.Event())

    def occupy_storage(index: int) -> None:
        _ = loop.call_soon_threadsafe(started[index].set)
        if not release.wait(timeout=5.0):
            message = "readiness storage-saturation fixture timed out"
            raise TimeoutError(message)

    blockers: list[asyncio.Task[None]] = [
        asyncio.create_task(
            STORAGE_WORK.run_to_completion(partial(occupy_storage, index))
        )
        for index in range(_STORAGE_WORK_CAPACITY)
    ]
    try:
        async with asyncio.timeout(2.0):
            _ = await started[0].wait()
            _ = await started[1].wait()
        assert STORAGE_WORK.active == _STORAGE_WORK_CAPACITY

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://mcp.example.test",
        ) as client:
            ready = await client.get("/readyz")
    finally:
        release.set()
        for blocker in blockers:
            await blocker

    assert ready.status_code == HTTPStatus.OK
    assert load_json_value(ready.text) == {"status": "ready"}
    assert STORAGE_WORK.active == 0


@pytest.mark.asyncio
async def test_readiness_is_nonmutating_for_full_profile_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    original_stage = store.stage
    stage_calls = 0

    def observed_stage(
        *,
        suffix: str = ".tmp",
    ) -> AbstractContextManager[object, bool | None]:
        nonlocal stage_calls
        stage_calls += 1
        return cast(
            "AbstractContextManager[object, bool | None]",
            original_stage(suffix=suffix),
        )

    monkeypatch.setattr(store, "stage", observed_stage)
    application = create_app(
        config(tmp_path),
        services=FullServiceComposition(tools=StubTools(), store=store),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        responses = [await client.get("/readyz") for _ in range(8)]

    assert all(response.status_code == HTTPStatus.OK for response in responses)
    assert stage_calls == 0
    assert tuple(store.staging_dir.iterdir()) == ()


@pytest.mark.asyncio
async def test_metadata_only_runtime_is_ready_without_storage_and_has_no_assets(
    tmp_path: Path,
) -> None:
    cfg = replace(config(tmp_path), deployment_profile="alpic-metadata")
    application = create_app(
        cfg,
        services=MetadataServiceComposition(tools=StubTools()),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        ready = await client.get("/readyz")
        asset = await client.get("/assets/not-present")

    assert ready.status_code == HTTPStatus.OK
    assert load_json_value(ready.text) == {"status": "ready"}
    assert asset.status_code == HTTPStatus.NOT_FOUND


def test_header_mapping_fallback_is_case_insensitive() -> None:
    attribute_name = "_header_values"
    header_values = cast(
        "Callable[[dict[str, str], str], list[str]]",
        getattr(app_module, attribute_name),
    )
    values = header_values(
        {"HOST": "mcp.example.test", "Other": "ignored"},
        "host",
    )

    assert values == ["mcp.example.test"]


def test_runtime_composition_rejects_distributed_profile_before_construction(
    tmp_path: Path,
) -> None:
    cfg = replace(config(tmp_path), deployment_profile="distributed-full")
    attribute_name = "_runtime_services"
    runtime_services = cast(
        "Callable[[AppConfig], AppServices]",
        getattr(app_module, attribute_name),
    )

    with pytest.raises(ValueError, match="distributed-full"):
        _ = runtime_services(cfg)


def test_app_error_response_rejects_wrong_exception_type() -> None:
    attribute_name = "_app_error_response"
    app_error_response = cast(
        "Callable[[Exception], object]",
        getattr(app_module, attribute_name),
    )

    with pytest.raises(TypeError, match="another exception type"):
        _ = app_error_response(RuntimeError("must not be disclosed"))


@pytest.mark.asyncio
async def test_bearer_auth_origin_request_limit_health_and_metrics(
    tmp_path: Path,
) -> None:
    secret = "t" * 32
    cfg = replace(
        config(tmp_path, token=secret, anonymous=False),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    protected = create_app(
        cfg,
        services=FullServiceComposition(
            tools=StubTools(), store=ContentAddressedStore(tmp_path)
        ),
    )
    async with (
        protected.router.lifespan_context(protected),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=protected),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        health = await client.get("/healthz")
        ready = await client.get("/readyz")
        metrics = await client.get("/metrics")
        authorized_metrics = await client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {secret}"},
        )
        unauthorized = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            json=modern_body("tools/list"),
        )
        wrong_bearer = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "Authorization": "Bearer " + ("x" * 32),
            },
            json=modern_body("tools/list"),
        )
        bad_origin = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "Origin": "https://evil.example",
                "Authorization": f"Bearer {secret}",
            },
            json=modern_body("tools/list"),
        )
        malformed_origin = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "Origin": "https://mcp.example.test/not-an-origin",
                "Authorization": f"Bearer {secret}",
            },
            json=modern_body("tools/list"),
        )
        bad_host = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "Host": "evil.example",
                "Authorization": f"Bearer {secret}",
            },
            json=modern_body("tools/list"),
        )
        authorized = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "Authorization": f"Bearer {secret}",
            },
            json=modern_body("tools/list"),
        )
        oversized = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "Authorization": f"Bearer {secret}",
            },
            content=b"x" * (cfg.max_request_body_bytes + 1),
        )

    assert health.status_code == ready.status_code == HTTPStatus.OK
    assert metrics.status_code == HTTPStatus.NOT_FOUND
    assert authorized_metrics.status_code == HTTPStatus.OK
    assert "nplg_mcp_requests_total" not in authorized_metrics.text
    assert unauthorized.status_code == HTTPStatus.UNAUTHORIZED
    assert wrong_bearer.status_code == HTTPStatus.UNAUTHORIZED
    assert (
        bad_origin.status_code == malformed_origin.status_code == HTTPStatus.FORBIDDEN
    )
    assert bad_host.status_code == HTTPStatus.FORBIDDEN
    assert authorized.status_code == HTTPStatus.OK
    assert oversized.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE


@pytest.mark.asyncio
async def test_api_key_auth_is_exact_and_rejects_credential_ambiguity(
    tmp_path: Path,
) -> None:
    secret = "k" * 32
    cfg = replace(
        config(tmp_path, api_key=secret, anonymous=False),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    protected = create_app(
        cfg,
        services=FullServiceComposition(
            tools=StubTools(), store=ContentAddressedStore(tmp_path)
        ),
    )
    async with (
        protected.router.lifespan_context(protected),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=protected),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        missing = await client.post(
            "/mcp", headers=modern_headers("tools/list"), json=modern_body("tools/list")
        )
        wrong = await client.post(
            "/mcp",
            headers={**modern_headers("tools/list"), "x-api-key": "x" * 32},
            json=modern_body("tools/list"),
        )
        valid = await client.post(
            "/mcp",
            headers={**modern_headers("tools/list"), "x-api-key": secret},
            json=modern_body("tools/list"),
        )
        ambiguous = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "x-api-key": secret,
                "Authorization": "Bearer " + ("t" * 32),
            },
            json=modern_body("tools/list"),
        )

    assert (
        missing.status_code
        == wrong.status_code
        == ambiguous.status_code
        == HTTPStatus.UNAUTHORIZED
    )
    assert valid.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_application_assembles_nplg_client_with_pinned_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Catch app assembly without the pinned transport or trust_env=False."""
    real_client = httpx.AsyncClient
    captured: dict[str, object] = {}

    def client_spy(*args: object, **kwargs: object) -> httpx.AsyncClient:
        assert not args
        captured.update(kwargs)
        return real_client(
            timeout=cast("httpx.Timeout", kwargs["timeout"]),
            follow_redirects=cast("bool", kwargs["follow_redirects"]),
            trust_env=cast("bool", kwargs["trust_env"]),
            limits=cast("httpx.Limits", kwargs["limits"]),
            transport=cast("httpx.AsyncBaseTransport", kwargs["transport"]),
            headers=cast("Mapping[str, str]", kwargs["headers"]),
            cookies=cast("CookieJar", kwargs["cookies"]),
        )

    monkeypatch.setattr("nplg_mcp.app.httpx.AsyncClient", client_spy)
    application = create_app(config(tmp_path))
    runtime = application.services
    assert runtime is not None
    client = runtime.http_client
    assert isinstance(client, real_client)
    assert captured["trust_env"] is False
    assert isinstance(captured["transport"], BoundAsyncHTTPTransport)
    await client.aclose()


@pytest.mark.asyncio
async def test_application_emits_only_sanitized_circuit_transition_fields(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mutation caught: missing app observer or payload-bearing transition logs."""
    query_marker = "query-marker-task17"
    opaque_marker = "opaque-marker-task17"
    body_marker = "body-marker-task17"
    monkeypatch.setenv("NPLG_TEST_QUERY_MARKER", query_marker)
    monkeypatch.setenv("HTTPS_PROXY", f"http://{opaque_marker}.invalid:8080")
    monkeypatch.setenv("NPLG_TEST_BODY_MARKER", body_marker)
    caplog.set_level(logging.INFO, logger="nplg_mcp.upstream")
    application = create_app(config(tmp_path))
    runtime = application.services
    assert runtime is not None
    tools = cast("ToolService", runtime.tools)
    repository = cast("NplgRepository", tools.repository)
    guard = repository.guard
    deadline = MonotonicDeadline.after(30.0, clock=time.monotonic)
    try:
        for _ in range(3):
            async with guard.acquire(deadline) as permit:
                await permit.record_transient_failure()
    finally:
        if runtime.http_client is not None:
            await runtime.http_client.aclose()

    records = [
        record
        for record in caplog.records
        if record.name == "nplg_mcp.upstream"
        and record.getMessage() == "nplg_upstream_circuit_transition"
    ]
    assert len(records) == 1
    record = records[0]
    fields = cast("dict[str, object]", record.__dict__)
    assert fields["upstream_state"] == "open"
    assert fields["upstream_transition"] == "closed_to_open"
    rendered = " ".join(str(value) for value in fields.values())
    assert query_marker not in rendered
    assert opaque_marker not in rendered
    assert body_marker not in rendered


@pytest.mark.asyncio
async def test_runtime_upstream_client_never_persists_response_cookies(
    tmp_path: Path,
) -> None:
    application = create_app(config(tmp_path))
    runtime = application.services
    assert runtime is not None
    client = runtime.http_client
    assert isinstance(client, httpx.AsyncClient)

    origin_request = httpx.Request("GET", "https://dspace.nplg.gov.ge/handle/1234/1")
    response = httpx.Response(
        200,
        headers={"set-cookie": "nplg_session=caller-state; Path=/; Secure"},
        request=origin_request,
    )
    outgoing = httpx.Request("GET", "https://dspace.nplg.gov.ge/handle/1234/2")
    try:
        client.cookies.extract_cookies(response)
        client.cookies.jar.set_cookie(
            Cookie(
                version=0,
                name="preloaded_session",
                value="caller-state",
                port=None,
                port_specified=False,
                domain="dspace.nplg.gov.ge",
                domain_specified=True,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=True,
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={},
                rfc2109=False,
            )
        )
        client.cookies.set_cookie_header(outgoing)
    finally:
        await client.aclose()

    assert "cookie" not in outgoing.headers
    assert len(client.cookies) == 1


@pytest.mark.asyncio
async def test_signed_asset_delivery_is_bound_to_path_and_media_type(
    tmp_path: Path,
) -> None:
    cfg = config(tmp_path)
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"jpeg", namespace="renders", filename="page.jpg", media_type="image/jpeg"
    )
    app = create_app(
        cfg, services=FullServiceComposition(tools=StubTools(), store=store)
    )
    token = sign_asset_token(
        cfg.require_asset_signing_secret(),
        path=artifact.relative_path,
        media_type="image/jpeg",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.get(f"/assets/{token}")
        tampered = await client.get(f"/assets/{token}x")

    assert response.status_code == HTTPStatus.OK
    assert response.content == b"jpeg"
    assert response.headers["content-type"].startswith("image/jpeg")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "private, no-store"
    assert tampered.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.asyncio
async def test_signed_asset_delivery_rejects_expiry_beyond_configured_ttl(
    tmp_path: Path,
) -> None:
    cfg = replace(config(tmp_path), asset_ttl_seconds=60)
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"jpeg", namespace="renders", filename="page.jpg", media_type="image/jpeg"
    )
    app = create_app(
        cfg, services=FullServiceComposition(tools=StubTools(), store=store)
    )
    token = sign_asset_token(
        cfg.require_asset_signing_secret(),
        path=artifact.relative_path,
        media_type="image/jpeg",
        expires_at=datetime.now(UTC) + timedelta(minutes=2),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.get(f"/assets/{token}")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert _response_value(response, "error", "code") == ErrorCode.UNAUTHORIZED.value


@pytest.mark.asyncio
async def test_asset_admission_is_held_until_stream_completion(
    tmp_path: Path,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    disconnect = asyncio.Event()
    first_status: int | None = None

    async def receive_message() -> dict[str, object]:
        _ = await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send_message(message: dict[str, object]) -> None:
        nonlocal first_status
        message_type = message.get("type")
        if message_type == "http.response.start":
            status = message.get("status")
            if not isinstance(status, int):
                pytest.fail("asset response start omitted its integer status")
            first_status = status
        if message_type == "http.response.body" and not entered.is_set():
            entered.set()
            _ = await release.wait()

    cfg = replace(config(tmp_path), max_concurrent_asset_streams=1)
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"asset", namespace="renders", filename="page.jpg", media_type="image/jpeg"
    )
    app = create_app(
        cfg, services=FullServiceComposition(tools=StubTools(), store=store)
    )
    token = sign_asset_token(
        cfg.require_asset_signing_secret(),
        path=artifact.relative_path,
        media_type="image/jpeg",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    scope = _http_scope(f"/assets/{token}", method="GET")

    async def stream_first_asset() -> None:
        await app(
            cast("Scope", scope),
            cast("Receive", receive_message),
            cast("Send", send_message),
        )

    first = asyncio.create_task(stream_first_asset())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        async with asyncio.timeout(1):
            _ = await entered.wait()
        second = await asyncio.wait_for(client.get(f"/assets/{token}"), timeout=1)
        release.set()
        await first
        third = await client.get(f"/assets/{token}")

    assert second.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert second.headers["retry-after"] == "1"
    assert _response_value(second, "error", "code") == "RATE_LIMITED"
    assert first_status == third.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_asset_response_stops_reading_after_client_disconnect(
    tmp_path: Path,
) -> None:
    payload = b"x" * (3 * 1024 * 1024)
    cfg = config(tmp_path)
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        payload,
        namespace="renders",
        filename="large-asset.bin",
        media_type="application/octet-stream",
    )
    app = create_app(
        cfg, services=FullServiceComposition(tools=StubTools(), store=store)
    )
    token = sign_asset_token(
        cfg.require_asset_signing_secret(),
        path=artifact.relative_path,
        media_type="application/octet-stream",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    sent_bytes = 0
    receive_calls = 0

    async def receive_message() -> dict[str, object]:
        nonlocal receive_calls
        receive_calls += 1
        return {"type": "http.disconnect"}

    async def send_message(message: dict[str, object]) -> None:
        nonlocal sent_bytes
        body = message.get("body")
        if isinstance(body, bytes):
            sent_bytes += len(body)
        await asyncio.sleep(0)

    scope = _http_scope(f"/assets/{token}", method="GET")
    await app(
        cast("Scope", scope),
        cast("Receive", receive_message),
        cast("Send", send_message),
    )

    assert receive_calls >= 1
    assert sent_bytes < len(payload)


@pytest.mark.asyncio
@pytest.mark.parametrize("termination", ["disconnect", "cancel"])
async def test_active_asset_stream_is_leased_until_disconnect_or_cancellation(
    tmp_path: Path,
    termination: Literal["disconnect", "cancel"],
) -> None:
    """Removing the response lease must let prune delete the active object."""
    body_entered = asyncio.Event()
    disconnect = asyncio.Event()

    async def receive_message() -> dict[str, object]:
        _ = await disconnect.wait()
        return {"type": "http.disconnect"}

    async def blocked_send(message: dict[str, object]) -> None:
        body = message.get("body")
        if isinstance(body, bytes) and body:
            body_entered.set()
            _ = await asyncio.Event().wait()

    store, policy, clock = _lease_test_store(tmp_path)
    active = store.put_bytes(
        b"actively-streamed",
        namespace="renders",
        filename="active.bin",
        media_type="application/octet-stream",
    )
    evictable = store.put_bytes(
        b"evictable",
        namespace="renders",
        filename="evictable.bin",
        media_type="application/octet-stream",
    )
    cfg = config(tmp_path)
    app = create_app(
        cfg, services=FullServiceComposition(tools=StubTools(), store=store)
    )
    token = sign_asset_token(
        cfg.require_asset_signing_secret(),
        path=active.relative_path,
        media_type=active.media_type,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    request = asyncio.create_task(
        app(
            cast("Scope", _http_scope(f"/assets/{token}", method="GET")),
            cast("Receive", receive_message),
            cast("Send", blocked_send),
        )
    )
    async with asyncio.timeout(1):
        _ = await body_entered.wait()

    while_active = store.prune(policy, clock=clock)

    assert active.absolute_path.is_file()
    assert not evictable.absolute_path.exists()
    assert while_active.retained_leased_objects == 1
    assert (store.lease_acquisitions, store.lease_releases) == (1, 0)

    if termination == "disconnect":
        disconnect.set()
        await request
    else:
        _ = request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request

    assert (store.lease_acquisitions, store.lease_releases) == (1, 1)
    replacement = store.put_bytes(
        b"replacement",
        namespace="renders",
        filename="replacement.bin",
        media_type="application/octet-stream",
    )
    after_stream = store.prune(policy, clock=_lease_clock_sample(2.0))
    assert after_stream.retained_leased_objects == 0
    assert not active.absolute_path.exists()
    assert replacement.absolute_path.is_file()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["success", "send-error"])
async def test_asset_stream_releases_its_lease_exactly_once_on_terminal_outcomes(
    tmp_path: Path,
    outcome: Literal["success", "send-error"],
) -> None:
    """Dropping the response cleanup must leave a durable lease behind."""
    never_disconnect = asyncio.Event()

    async def receive_message() -> dict[str, object]:
        _ = await never_disconnect.wait()
        return {"type": "http.disconnect"}

    async def send_message(message: dict[str, object]) -> None:
        body = message.get("body")
        if outcome == "send-error" and isinstance(body, bytes) and body:
            msg = "test asset send failure"
            raise RuntimeError(msg)

    store, _policy, _clock = _lease_test_store(tmp_path)
    artifact = store.put_bytes(
        b"leased-response",
        namespace="renders",
        filename="response.bin",
        media_type="application/octet-stream",
    )
    cfg = config(tmp_path)
    app = create_app(
        cfg, services=FullServiceComposition(tools=StubTools(), store=store)
    )
    token = sign_asset_token(
        cfg.require_asset_signing_secret(),
        path=artifact.relative_path,
        media_type=artifact.media_type,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    invocation = app(
        cast("Scope", _http_scope(f"/assets/{token}", method="GET")),
        cast("Receive", receive_message),
        cast("Send", send_message),
    )

    if outcome == "send-error":
        with pytest.raises(RuntimeError, match="test asset send failure"):
            await invocation
    else:
        await invocation

    assert (store.lease_acquisitions, store.lease_releases) == (1, 1)


@pytest.mark.asyncio
async def test_asset_stream_idle_timeout_releases_its_admission_permit(
    tmp_path: Path,
) -> None:
    never_disconnect = asyncio.Event()
    send_entered = asyncio.Event()

    async def receive_message() -> dict[str, object]:
        _ = await never_disconnect.wait()
        return {"type": "http.disconnect"}

    async def stalled_send(_message: dict[str, object]) -> None:
        send_entered.set()
        _ = await asyncio.Event().wait()

    cfg = replace(
        config(tmp_path),
        max_concurrent_asset_streams=1,
        asset_stream_idle_timeout_seconds=0.01,
        asset_stream_total_timeout_seconds=0.1,
    )
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"asset", namespace="renders", filename="page.jpg", media_type="image/jpeg"
    )
    app = create_app(
        cfg, services=FullServiceComposition(tools=StubTools(), store=store)
    )
    token = sign_asset_token(
        cfg.require_asset_signing_secret(),
        path=artifact.relative_path,
        media_type="image/jpeg",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    await asyncio.wait_for(
        app(
            cast("Scope", _http_scope(f"/assets/{token}", method="GET")),
            cast("Receive", receive_message),
            cast("Send", stalled_send),
        ),
        timeout=0.5,
    )
    assert send_entered.is_set()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.get(f"/assets/{token}")

    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_asset_stream_total_timeout_stops_a_slow_reader(
    tmp_path: Path,
) -> None:
    payload = b"x" * (3 * 1024 * 1024)
    never_disconnect = asyncio.Event()
    sent_bytes = 0

    async def receive_message() -> dict[str, object]:
        _ = await never_disconnect.wait()
        return {"type": "http.disconnect"}

    async def slow_send(message: dict[str, object]) -> None:
        nonlocal sent_bytes
        body = message.get("body")
        if isinstance(body, bytes):
            sent_bytes += len(body)
        await asyncio.sleep(0.01)

    cfg = replace(
        config(tmp_path),
        asset_stream_idle_timeout_seconds=0.02,
        asset_stream_total_timeout_seconds=0.05,
    )
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        payload,
        namespace="renders",
        filename="large-asset.bin",
        media_type="application/octet-stream",
    )
    app = create_app(
        cfg, services=FullServiceComposition(tools=StubTools(), store=store)
    )
    token = sign_asset_token(
        cfg.require_asset_signing_secret(),
        path=artifact.relative_path,
        media_type="application/octet-stream",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    await asyncio.wait_for(
        app(
            cast("Scope", _http_scope(f"/assets/{token}", method="GET")),
            cast("Receive", receive_message),
            cast("Send", slow_send),
        ),
        timeout=0.5,
    )

    assert 0 < sent_bytes < len(payload)


@pytest.mark.parametrize(
    ("idle_timeout", "total_timeout", "message"),
    [
        (0.0, 120.0, "idle timeout"),
        (10.0, 5.0, "total timeout"),
    ],
)
def test_app_rejects_forged_asset_stream_timeouts(
    tmp_path: Path,
    idle_timeout: float,
    total_timeout: float,
    message: str,
) -> None:
    cfg = replace(
        config(tmp_path),
        asset_stream_idle_timeout_seconds=idle_timeout,
        asset_stream_total_timeout_seconds=total_timeout,
    )

    with pytest.raises(ValueError, match=message):
        _ = create_app(
            cfg,
            services=FullServiceComposition(
                tools=StubTools(), store=ContentAddressedStore(tmp_path)
            ),
        )


@pytest.mark.asyncio
async def test_non_ascii_asset_token_returns_stable_unauthorized_response(
    tmp_path: Path,
) -> None:
    cfg = config(tmp_path)
    app = create_app(
        cfg,
        services=FullServiceComposition(
            tools=StubTools(), store=ContentAddressedStore(tmp_path)
        ),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.get("/assets/%C3%A9.AA")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert _response_value(response, "error", "code") == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_official_sdk_path_does_not_expose_dead_or_untrusted_mcp_metrics(
    app: FastAPI,
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        for index in range(20):
            _ = await client.post(
                "/mcp",
                headers={
                    "Content-Type": "application/json",
                    "Mcp-Method": f"attacker-{index}",
                },
                json=rpc_body("unknown/method", request_id=index),
            )
        metrics = await client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {METRICS_SECRET}"},
        )

    assert metrics.status_code == HTTPStatus.OK
    assert "attacker-" not in metrics.text
    assert "nplg_mcp_requests_total" not in metrics.text


@pytest.mark.asyncio
async def test_official_sdk_requests_do_not_fabricate_legacy_method_outcomes(
    tmp_path: Path,
) -> None:
    cfg = replace(
        config(tmp_path, token=METRICS_SECRET),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    app = create_app(
        cfg,
        services=FullServiceComposition(
            tools=StubTools(), store=ContentAddressedStore(tmp_path)
        ),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
        ) as client,
    ):
        _ = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            json=modern_body("tools/list"),
        )
        _ = await client.post(
            "/mcp",
            headers={
                **modern_headers("tools/list"),
                "Mcp-Method": "server/discover",
            },
            json=modern_body("tools/list", request_id=2),
        )
        metrics = await client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {METRICS_SECRET}"},
        )

    assert "nplg_mcp_requests_total" not in metrics.text
    assert "server/discover" not in metrics.text


@pytest.mark.asyncio
async def test_mcp_admission_rejects_excess_work_without_queueing(
    tmp_path: Path,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def blocking_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        if calls == 1:
            entered.set()
            _ = await release.wait()
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        max_concurrent_mcp_requests=1,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(blocking_sdk, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        first = asyncio.create_task(
            client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                content=b"{}",
            )
        )
        async with asyncio.timeout(1):
            _ = await entered.wait()
        second = await asyncio.wait_for(
            client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                content=b"{}",
            ),
            timeout=1,
        )

        assert second.status_code == HTTPStatus.SERVICE_UNAVAILABLE
        assert second.headers["retry-after"] == "1"
        assert _response_value(second, "error", "code") == "RATE_LIMITED"
        assert calls == 1

        release.set()
        assert (await first).status_code == HTTPStatus.OK
        third = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}",
        )

    assert third.status_code == HTTPStatus.OK
    assert calls == EXPECTED_ADMITTED_TOOL_CALLS


@pytest.mark.asyncio
async def test_anonymous_bodies_consume_available_global_capacity_and_recover(
    tmp_path: Path,
) -> None:
    """Mutation caught: registering anonymous callers in PrincipalAdmission."""
    entered = [asyncio.Event() for _ in range(5)]
    release = asyncio.Event()

    async def stalled_body(slot: int) -> AsyncIterator[bytes]:
        entered[slot].set()
        yield b"{"
        _ = await release.wait()

    async def accepting_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        max_concurrent_mcp_requests=5,
        max_concurrent_mcp_requests_per_principal=4,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(accepting_sdk, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        stalled: list[asyncio.Task[httpx.Response]] = []
        try:
            for slot, entered_body in enumerate(entered):
                stalled.append(
                    asyncio.create_task(
                        client.post(
                            "/mcp",
                            headers=modern_headers("server/discover"),
                            content=stalled_body(slot),
                        )
                    )
                )
                async with asyncio.timeout(1):
                    _ = await entered_body.wait()

            exhausted = await client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                content=b"{}",
            )
            assert exhausted.status_code == HTTPStatus.SERVICE_UNAVAILABLE
            assert _response_value(exhausted, "error", "code") == "RATE_LIMITED"
        finally:
            release.set()
            for stalled_request in stalled:
                _ = await stalled_request

        recovered = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}",
        )

    assert recovered.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_cancelled_anonymous_body_releases_global_admission(
    tmp_path: Path,
) -> None:
    """Cancellation cannot strand the global permit held by an anonymous body."""
    entered = asyncio.Event()

    async def stalled_body() -> AsyncIterator[bytes]:
        entered.set()
        yield b"{"
        _ = await asyncio.Event().wait()

    async def accepting_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        max_concurrent_mcp_requests=1,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(accepting_sdk, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        cancelled = asyncio.create_task(
            client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                content=stalled_body(),
            )
        )
        async with asyncio.timeout(1):
            _ = await entered.wait()
        _ = cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            _ = await cancelled
        recovered = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}",
        )

    assert recovered.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_anonymous_handler_error_releases_global_admission(
    tmp_path: Path,
) -> None:
    """A downstream error cannot strand the global permit for anonymous traffic."""
    calls = 0

    async def fail_once(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        if calls == 1:
            msg = "test downstream failure"
            raise RuntimeError(msg)
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        max_concurrent_mcp_requests=1,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(fail_once, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        with pytest.raises(RuntimeError, match="test downstream failure"):
            _ = await client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                content=b"{}",
            )
        recovered = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}",
        )

    assert recovered.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_global_exhaustion_rolls_back_authenticated_principal_admission(
    tmp_path: Path,
) -> None:
    """A failed global acquisition cannot strand an authenticated permit."""
    entered = asyncio.Event()
    release = asyncio.Event()

    async def stalled_body() -> AsyncIterator[bytes]:
        entered.set()
        yield b"{"
        _ = await release.wait()
        yield b"}"

    async def accepting_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        await _send_ok_json(send)

    token = "a" * 32
    cfg = replace(
        config(tmp_path),
        api_principals=(
            ApiPrincipalCredential(
                principal_id="researcher-a",
                bearer_token=SecretStr(token),
            ),
        ),
        max_concurrent_mcp_requests=1,
        max_concurrent_mcp_requests_per_principal=1,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(accepting_sdk, config=cfg)
    application.start()
    authenticated_headers = {
        **modern_headers("server/discover"),
        "Authorization": f"Bearer {token}",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        anonymous = asyncio.create_task(
            client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                content=stalled_body(),
            )
        )
        try:
            async with asyncio.timeout(1):
                _ = await entered.wait()
            globally_exhausted = await client.post(
                "/mcp",
                headers=authenticated_headers,
                content=b"{}",
            )
        finally:
            release.set()
            anonymous_response = await anonymous
        recovered = await client.post(
            "/mcp",
            headers=authenticated_headers,
            content=b"{}",
        )

    assert globally_exhausted.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert _response_value(globally_exhausted, "error", "code") == "RATE_LIMITED"
    assert anonymous_response.status_code == HTTPStatus.OK
    assert recovered.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_principal_admission_prevents_one_credential_from_starving_another(
    tmp_path: Path,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def blocking_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        if calls == 1:
            entered.set()
            _ = await release.wait()
        await _send_ok_json(send)

    first_token = "a" * 32
    second_token = "b" * 32
    cfg = replace(
        config(tmp_path, anonymous=False),
        api_principals=(
            ApiPrincipalCredential(
                principal_id="researcher-a",
                bearer_token=SecretStr(first_token),
            ),
            ApiPrincipalCredential(
                principal_id="researcher-b",
                bearer_token=SecretStr(second_token),
            ),
        ),
        max_concurrent_mcp_requests=2,
        max_concurrent_mcp_requests_per_principal=1,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(blocking_sdk, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        first = asyncio.create_task(
            client.post(
                "/mcp",
                headers={
                    **modern_headers("server/discover"),
                    "Authorization": f"Bearer {first_token}",
                },
                content=b"{}",
            )
        )
        async with asyncio.timeout(1):
            _ = await entered.wait()

        same_principal = await client.post(
            "/mcp",
            headers={
                **modern_headers("server/discover"),
                "Authorization": f"Bearer {first_token}",
            },
            content=b"{}",
        )
        other_principal = await client.post(
            "/mcp",
            headers={
                **modern_headers("server/discover"),
                "Authorization": f"Bearer {second_token}",
            },
            content=b"{}",
        )
        release.set()
        first_response = await first

    assert same_principal.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert same_principal.headers["retry-after"] == "1"
    assert other_principal.status_code == HTTPStatus.OK
    assert first_response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_application_deadline_cancels_silent_handler_and_releases_permit(
    tmp_path: Path,
) -> None:
    cancelled = asyncio.Event()
    calls = 0

    async def silent_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        del scope, receive
        calls += 1
        if calls == 1:
            try:
                _ = await asyncio.Event().wait()
            finally:
                cancelled.set()
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        max_concurrent_mcp_requests=1,
        mcp_application_deadline_seconds=0.05,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(silent_sdk, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        timed_out = await asyncio.wait_for(
            client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                content=b"{}",
            ),
            timeout=1,
        )
        after = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            content=b"{}",
        )

    assert timed_out.status_code == HTTPStatus.GATEWAY_TIMEOUT
    assert _response_object(timed_out) == {
        "error": {
            "code": "REQUEST_TIMEOUT",
            "message": "The MCP request exceeded its application deadline.",
        }
    }
    assert cancelled.is_set()
    assert after.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_application_deadline_never_starts_a_second_response(
    tmp_path: Path,
) -> None:
    """A deadline after response start closes that stream without a second start."""
    cancelled = asyncio.Event()

    async def started_then_blocked(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        del scope, receive
        start: dict[str, object] = {
            "type": "http.response.start",
            "status": HTTPStatus.OK,
            "headers": [(b"content-type", b"text/event-stream")],
        }
        body: dict[str, object] = {
            "type": "http.response.body",
            "body": b"event: partial\n\n",
            "more_body": True,
        }
        await send(cast("Message", start))
        await send(cast("Message", body))
        try:
            _ = await asyncio.Event().wait()
        finally:
            cancelled.set()

    configured = replace(
        config(tmp_path),
        mcp_application_deadline_seconds=0.01,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(started_then_blocked, config=configured)
    application.start()
    raw_headers = tuple(
        (name.lower().encode(), value.encode())
        for name, value in modern_headers("server/discover").items()
    )
    scope = cast("Scope", _http_scope("/mcp", method="POST", headers=raw_headers))
    received = False

    async def receive() -> Message:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": b"{}", "more_body": False}

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await asyncio.wait_for(application(scope, receive, send), timeout=1)

    messages = [cast("dict[str, object]", message) for message in sent]
    starts = [
        message for message in messages if message.get("type") == "http.response.start"
    ]
    assert [message.get("status") for message in starts] == [HTTPStatus.OK]
    assert cancelled.is_set()
    assert sent[-1] == {
        "type": "http.response.body",
        "body": b"",
        "more_body": False,
    }


@pytest.mark.asyncio
async def test_real_socket_disconnect_cancels_or_deadline_bounds_handler(
    tmp_path: Path,
) -> None:
    class BlockingTools:
        def __init__(self, delegate: ToolSurface) -> None:
            super().__init__()
            self.delegate = delegate
            self.entered = asyncio.Event()
            self.cancelled = asyncio.Event()

        def list_tools(self) -> list[JsonObject]:
            return self.delegate.list_tools()

        async def call(
            self,
            name: str,
            arguments: JsonObject,
        ) -> StrictOutput | JsonObject:
            del name, arguments
            self.entered.set()
            try:
                _ = await asyncio.Event().wait()
            finally:
                self.cancelled.set()
            msg = "cancelled handler must not return"
            raise AssertionError(msg)

        def list_resources(self) -> list[JsonObject]:
            return self.delegate.list_resources()

        async def read_resource(self, uri: str) -> dict[str, str]:
            return await self.delegate.read_resource(uri)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.setblocking(False)  # noqa: FBT003 - socket API is positional-only
    port = cast("tuple[str, int]", listener.getsockname())[1]
    authority = f"127.0.0.1:{port}"
    tools = BlockingTools(
        make_tool_service(tmp_path, deployment_profile="alpic-metadata")
    )
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_application_deadline_seconds=20.0,
        mcp_allowed_hosts=(CanonicalHost(authority),),
        mcp_allowed_origins=(),
    )
    application = create_app(
        configured,
        services=MetadataServiceComposition(tools=tools),
    )
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host="127.0.0.1",
            port=port,
            lifespan="on",
            log_level="critical",
        )
    )
    server_task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(2):
            while not server.started:  # noqa: ASYNC110 - Uvicorn exposes a flag
                await asyncio.sleep(0)

        request_body = modern_body(
            "tools/call",
            {"name": "search_documents", "arguments": {"query": "fixture"}},
        )
        headers = {
            **modern_headers("tools/call", name="search_documents"),
            "Host": authority,
        }
        del headers["Origin"]
        keepalive_bytes = bytearray()
        async with (
            httpx.AsyncClient(
                base_url=f"http://{authority}",
                timeout=25.0,
                trust_env=False,
            ) as client,
            client.stream(
                "POST",
                "/mcp",
                headers=headers,
                json=request_body,
            ) as response,
        ):
            assert response.status_code == HTTPStatus.OK
            assert response.headers["content-type"].startswith("text/event-stream")
            assert response.headers.get_list("x-accel-buffering") == ["no"]
            async with asyncio.timeout(17):
                async for chunk in response.aiter_bytes():
                    keepalive_bytes.extend(chunk)
                    if b": ping" in keepalive_bytes:
                        break
            assert b": ping" in keepalive_bytes
            assert tools.entered.is_set()

        disconnected_at = asyncio.get_running_loop().time()
        async with asyncio.timeout(4):
            _ = await tools.cancelled.wait()
        assert asyncio.get_running_loop().time() - disconnected_at < 1
    finally:
        server.should_exit = True
        await asyncio.wait_for(server_task, timeout=3)


@pytest.mark.asyncio
async def test_stalled_request_body_times_out_and_releases_admission_permit(
    tmp_path: Path,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def stalled_body() -> AsyncIterator[bytes]:
        entered.set()
        yield b"{"
        _ = await release.wait()

    async def accepting_sdk(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        await _send_ok_json(send)

    cfg = replace(
        config(tmp_path),
        max_concurrent_mcp_requests=1,
        request_body_timeout_seconds=0.05,
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(accepting_sdk, config=cfg)
    application.start()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://mcp.example.test",
    ) as client:
        first = asyncio.create_task(
            client.post(
                "/mcp",
                headers=modern_headers("tools/list"),
                content=stalled_body(),
            )
        )
        async with asyncio.timeout(1):
            _ = await entered.wait()
        second = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            json=modern_body("tools/list"),
        )
        try:
            timed_out = await asyncio.wait_for(first, timeout=0.5)
        finally:
            release.set()
        third = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            json=modern_body("tools/list"),
        )

    assert second.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert timed_out.status_code == HTTPStatus.REQUEST_TIMEOUT
    assert _response_value(timed_out, "error", "code") == "REQUEST_TIMEOUT"
    assert third.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_get_mcp_is_not_a_long_lived_sse_endpoint(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.get("/mcp")
    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED


@pytest.mark.asyncio
async def test_trace_is_disabled_at_backend(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.request("TRACE", "/mcp", content=b"trace")

    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED
    assert response.headers["allow"] == "POST"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
    )


@pytest.mark.asyncio
async def test_bounded_body_rejects_negative_content_length_before_streaming(
    tmp_path: Path,
) -> None:
    request_body = dump_json(modern_body("tools/list")).encode()
    configured = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = create_app(
        configured,
        services=FullServiceComposition(
            tools=StubTools(), store=ContentAddressedStore(tmp_path)
        ),
    )
    receive_calls = 0

    async def unread_body() -> AsyncIterator[bytes]:
        nonlocal receive_calls
        receive_calls += 1
        yield request_body

    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        response = await client.post(
            "/mcp",
            headers={**modern_headers("tools/list"), "Content-Length": "-1"},
            content=unread_body(),
        )

    assert receive_calls == 0
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert _response_object(response) == {"error": "Invalid Content-Length"}


@pytest.mark.asyncio
async def test_bounded_body_checks_chunk_size_before_buffer_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extend_calls = 0

    class GuardedBuffer:
        """Fail if the request implementation buffers an oversized chunk."""

        def __init__(self) -> None:
            super().__init__()
            self.contents = bytearray()

        def __len__(self) -> int:
            return len(self.contents)

        def extend(self, value: bytes) -> None:
            nonlocal extend_calls
            extend_calls += 1
            if len(self.contents) + len(value) > REQUEST_BODY_LIMIT_BYTES:
                msg = "oversized chunk was buffered before the limit check"
                raise AssertionError(msg)

            self.contents.extend(value)

        def __bytes__(self) -> bytes:
            return bytes(self.contents)

    configured = replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = create_app(
        configured,
        services=FullServiceComposition(
            tools=StubTools(), store=ContentAddressedStore(tmp_path)
        ),
    )

    async def oversized_body() -> AsyncIterator[bytes]:
        yield b"a" * OVERSIZED_REQUEST_CHUNK_BYTES

    monkeypatch.setattr(
        http_security_module,
        "bytearray",
        GuardedBuffer,
        raising=False,
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        response = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            content=oversized_body(),
        )

    assert extend_calls == 0
    assert response.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert _response_object(response) == {"error": "Request body is too large"}


@pytest.mark.asyncio
async def test_modern_http_rejects_client_to_server_notification(app: FastAPI) -> None:
    body = modern_body("tools/list")
    del body["id"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.post(
            "/mcp",
            headers=modern_headers("tools/list"),
            json=body,
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert _response_value(response, "error", "code") == JSON_RPC_INVALID_REQUEST


@pytest.mark.asyncio
async def test_http_request_guards_reject_malformed_authorities_and_media_types(
    app: FastAPI,
) -> None:
    body = dump_json(modern_body("tools/list")).encode()
    cases: list[tuple[dict[str, str], HTTPStatus]] = [
        ({**modern_headers("tools/list"), "Host": "bad host"}, HTTPStatus.FORBIDDEN),
        (
            {**modern_headers("tools/list"), "Host": "user@mcp.example.test"},
            HTTPStatus.FORBIDDEN,
        ),
        (
            {**modern_headers("tools/list"), "Host": "mcp.example.test:bad"},
            HTTPStatus.FORBIDDEN,
        ),
        (
            {
                **modern_headers("tools/list"),
                "Origin": "https://mcp.example.test %",
            },
            HTTPStatus.FORBIDDEN,
        ),
        (
            {
                **modern_headers("tools/list"),
                "Origin": "https://mcp.example.test:bad",
            },
            HTTPStatus.FORBIDDEN,
        ),
        (
            {
                key: value
                for key, value in modern_headers("tools/list").items()
                if key != "Content-Type"
            },
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            {**modern_headers("tools/list"), "Content-Type": "text/plain"},
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            {**modern_headers("tools/list"), "Content-Length": "not-a-number"},
            HTTPStatus.BAD_REQUEST,
        ),
    ]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        for headers, expected_status in cases:
            response = await client.post("/mcp", headers=headers, content=body)
            assert response.status_code == expected_status

        duplicate_length = await client.post(
            "/mcp",
            headers=[
                *modern_headers("tools/list").items(),
                ("Content-Length", str(len(body))),
                ("Content-Length", str(len(body) + 1)),
            ],
            content=body,
        )
        duplicate_type = await client.post(
            "/mcp",
            headers=[
                *modern_headers("tools/list").items(),
                ("Content-Type", "application/problem+json"),
            ],
            content=body,
        )

    assert duplicate_length.status_code == HTTPStatus.BAD_REQUEST
    assert duplicate_type.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_metrics_hide_malformed_public_host(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
    ) as client:
        response = await client.get(
            "/metrics",
            headers={
                "Host": "mcp.example.test:bad",
                "Authorization": f"Bearer {METRICS_SECRET}",
            },
        )

    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response.text == "Not Found"


@pytest.mark.asyncio
async def test_application_lifespan_closes_only_owned_upstream_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CloseObserver:
        def __init__(self) -> None:
            super().__init__()
            self.closed: bool = False

        async def aclose(self) -> None:
            self.closed = True

        def is_closed(self) -> bool:
            return self.closed

    owned_client = CloseObserver()
    owned_services = FullServiceComposition(
        tools=StubTools(),
        store=ContentAddressedStore(tmp_path / "owned"),
        http_client=cast("HttpClientProtocol", owned_client),
    )

    def runtime_services(_: AppConfig) -> AppServices:
        return owned_services

    monkeypatch.setattr(app_module, "_runtime_services", runtime_services)
    owned_app = create_app(config(tmp_path / "owned"))
    async with owned_app.router.lifespan_context(owned_app):
        assert not owned_client.is_closed()
    assert owned_client.is_closed()

    injected_client = CloseObserver()
    injected_services = FullServiceComposition(
        tools=StubTools(),
        store=ContentAddressedStore(tmp_path / "injected"),
        http_client=cast("HttpClientProtocol", injected_client),
    )
    injected_app = create_app(
        config(tmp_path / "injected"),
        services=injected_services,
    )
    async with injected_app.router.lifespan_context(injected_app):
        assert not injected_client.is_closed()
    assert not injected_client.is_closed()
