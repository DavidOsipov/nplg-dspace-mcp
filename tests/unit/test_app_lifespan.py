# Copyright (c) 2026 David Osipov
"""Behavioral lifespan contracts for the mounted official MCP SDK app."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import replace
from http import HTTPStatus
from typing import TYPE_CHECKING, cast

import httpx
import pytest

import nplg_mcp.app as app_module
from nplg_mcp.app import create_app
from nplg_mcp.config import CanonicalHost, CanonicalOrigin
from nplg_mcp.json_types import load_json_value, require_json_object
from nplg_mcp.services import MetadataServiceComposition
from tests.conformance.test_mcp_http import (
    MODERN,
    StubTools,
    config,
    modern_body,
    modern_headers,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path

    from mcp.server import Server
    from starlette.types import Receive, Scope, Send

    from nplg_mcp.config import AppConfig
    from nplg_mcp.contracts import StrictOutput
    from nplg_mcp.http_types import HttpClientProtocol
    from nplg_mcp.json_types import JsonObject


def _manager_running(server: Server[None]) -> bool:
    return server.session_manager._task_group is not None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.asyncio
async def test_pre_start_request_is_bounded_without_manager_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before lifespan startup, outer admission returns 503 without SDK entry."""
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    app = create_app(
        configured,
        services=MetadataServiceComposition(tools=StubTools()),
    )
    server = app.mcp_server
    assert server is not None
    manager_entries = 0

    async def recording_manager(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        nonlocal manager_entries
        del scope, receive, send
        manager_entries += 1
        msg = "pre-start request reached the SDK manager"
        raise AssertionError(msg)

    monkeypatch.setattr(server.session_manager, "asgi_app", recording_manager)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
        base_url="https://mcp.example.test",
    ) as client:
        response = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            json=modern_body("server/discover"),
        )

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert load_json_value(response.content) == {"error": "MCP service is not running"}
    assert manager_entries == 0


@pytest.mark.asyncio
async def test_session_manager_is_running_before_first_and_repeated_request(
    tmp_path: Path,
) -> None:
    """The outer lifespan owns one manager before either mounted request begins."""
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    app = create_app(
        configured,
        services=MetadataServiceComposition(tools=StubTools()),
    )

    server = app.mcp_server
    assert server is not None
    assert not _manager_running(server)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
    async with app.router.lifespan_context(app):
        assert _manager_running(server)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://mcp.example.test",
        ) as client:
            first = await client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                json=modern_body("server/discover"),
            )
            repeated = await client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                json=modern_body("server/discover", request_id=2),
            )
            doubled = await client.post(
                "/mcp/mcp",
                headers=modern_headers("server/discover"),
                json=modern_body("server/discover", request_id=3),
            )

    assert first.status_code == HTTPStatus.OK
    assert repeated.status_code == HTTPStatus.OK
    assert doubled.status_code == HTTPStatus.NOT_FOUND
    payload = require_json_object(load_json_value(first.content), context="response")
    result = require_json_object(payload["result"], context="response.result")
    assert result["supportedVersions"] == [MODERN]
    assert not _manager_running(server)


@pytest.mark.asyncio
async def test_manager_drains_before_owned_service_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    drained = asyncio.Event()
    service_closed = asyncio.Event()
    dependency_closed_observations: list[bool] = []
    shutdown_order: list[str] = []

    class CloseObserver:
        def __init__(self) -> None:
            super().__init__()
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True
            shutdown_order.append("service-closed")
            service_closed.set()

    observer = CloseObserver()
    delegate = StubTools()

    class BlockingTools:
        def list_tools(self) -> list[JsonObject]:
            return delegate.list_tools()

        async def call(
            self,
            name: str,
            arguments: JsonObject,
        ) -> StrictOutput | JsonObject:
            del name, arguments
            entered.set()
            try:
                _ = await asyncio.Event().wait()
            finally:
                dependency_closed_observations.append(observer.closed)
                shutdown_order.append("handler-drained")
                drained.set()
            msg = "cancelled handler must not return"
            raise AssertionError(msg)

        def list_resources(self) -> list[JsonObject]:
            return delegate.list_resources()

        async def read_resource(self, uri: str) -> dict[str, str]:
            return await delegate.read_resource(uri)

    runtime = MetadataServiceComposition(
        tools=BlockingTools(),
        http_client=cast("HttpClientProtocol", observer),
    )

    def runtime_services(_config: AppConfig) -> MetadataServiceComposition:
        return runtime

    monkeypatch.setattr(app_module, "_runtime_services", runtime_services)
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    app = create_app(configured)
    server = app.mcp_server
    assert server is not None
    lifespan_started = asyncio.Event()
    shutdown_requested = asyncio.Event()

    async def own_lifespan() -> None:
        async with app.router.lifespan_context(app):
            lifespan_started.set()
            _ = await shutdown_requested.wait()

    lifespan_task = asyncio.create_task(own_lifespan())
    async with asyncio.timeout(1):
        _ = await lifespan_started.wait()
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
        base_url="https://mcp.example.test",
    )
    request = asyncio.create_task(
        client.post(
            "/mcp",
            headers=modern_headers("tools/call", name="search_documents"),
            json=modern_body(
                "tools/call",
                {
                    "name": "search_documents",
                    "arguments": {"query": "blocked during shutdown"},
                },
            ),
        )
    )
    try:
        async with asyncio.timeout(1):
            _ = await entered.wait()
        shutdown_requested.set()
        async with asyncio.timeout(1):
            _ = await drained.wait()
            _ = await service_closed.wait()
            await lifespan_task
        with pytest.raises(asyncio.CancelledError):
            _ = await request
    finally:
        shutdown_requested.set()
        _ = lifespan_task.cancel()
        with suppress(asyncio.CancelledError):
            await lifespan_task
        _ = request.cancel()
        with suppress(asyncio.CancelledError):
            _ = await request
        await client.aclose()

    assert dependency_closed_observations == [False]
    assert shutdown_order == ["handler-drained", "service-closed"]
    assert not _manager_running(server)


@pytest.mark.asyncio
async def test_startup_failure_unwinds_only_entered_contexts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closes = 0

    class CloseObserver:
        async def aclose(self) -> None:
            nonlocal closes
            closes += 1

    runtime = MetadataServiceComposition(
        tools=StubTools(),
        http_client=cast("HttpClientProtocol", CloseObserver()),
    )

    def runtime_services(_config: AppConfig) -> MetadataServiceComposition:
        return runtime

    monkeypatch.setattr(app_module, "_runtime_services", runtime_services)
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    app = create_app(configured)
    server = app.mcp_server
    assert server is not None

    @asynccontextmanager
    async def failing_manager() -> AsyncGenerator[None, None]:
        msg = "manager startup failed"
        failure = asyncio.Event()
        failure.set()
        if failure.is_set():
            raise RuntimeError(msg)
        yield None

    monkeypatch.setattr(server.session_manager, "run", failing_manager)
    with pytest.raises(RuntimeError, match="manager startup failed"):
        async with app.router.lifespan_context(app):
            pytest.fail("startup failure must not yield")

    assert closes == 1
    assert not _manager_running(server)


@pytest.mark.asyncio
async def test_requests_outside_lifespan_cannot_reuse_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = replace(
        config(tmp_path),
        deployment_profile="alpic-metadata",
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    app = create_app(
        configured,
        services=MetadataServiceComposition(tools=StubTools()),
    )
    server = app.mcp_server
    assert server is not None
    manager_entries = 0
    manager_app = server.session_manager.asgi_app

    async def recording_manager(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        nonlocal manager_entries
        manager_entries += 1
        await manager_app(scope, receive, send)

    monkeypatch.setattr(server.session_manager, "asgi_app", recording_manager)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="https://mcp.example.test",
    ) as client:
        rejected_before_startup = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            json=modern_body("server/discover"),
        )
        assert manager_entries == 0
        async with app.router.lifespan_context(app):
            admitted = await client.post(
                "/mcp",
                headers=modern_headers("server/discover"),
                json=modern_body("server/discover"),
            )
            assert manager_entries == 1
        rejected_after_shutdown = await client.post(
            "/mcp",
            headers=modern_headers("server/discover"),
            json=modern_body("server/discover", request_id=2),
        )
        assert manager_entries == 1

    assert admitted.status_code == HTTPStatus.OK
    assert rejected_before_startup.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert load_json_value(rejected_before_startup.content) == {
        "error": "MCP service is not running"
    }
    assert rejected_after_shutdown.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert load_json_value(rejected_after_shutdown.content) == {
        "error": "MCP service is not running"
    }
