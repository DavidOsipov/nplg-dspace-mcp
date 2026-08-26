# Copyright (c) 2026 David Osipov
"""Lifecycle tests for aggregate inline-resource response admission."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from http import HTTPStatus
from typing import TYPE_CHECKING, cast, override

import pytest
from mcp import types
from mcp.shared.exceptions import MCPError

from nplg_mcp.config import (
    HARD_MAX_INLINE_RESOURCE_BYTES,
    CanonicalHost,
    CanonicalOrigin,
    load_config,
)
from nplg_mcp.http_security import McpSecurityMiddleware
from nplg_mcp.profiles import DeploymentProfile
from nplg_mcp.resource_admission import (
    INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES,
    InlineResourceAdmission,
    inline_blob_response_reservation_bytes,
    inline_text_response_reservation_bytes,
)
from nplg_mcp.sdk_boundary import SdkHandlers
from nplg_mcp.services import FullServiceComposition
from tests.helpers.app_factory import base_environment

_EXPECTED_TWO_RESOURCE_CALLS = 2
_ACCOUNTING_CAPACITY_BYTES = 10
_ACCOUNTING_FIRST_BYTES = 6
_ACCOUNTING_SECOND_BYTES = 4
_ACCOUNTING_RETAINED_BYTES = 2

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.context import ServerRequestContext
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from nplg_mcp.contracts import StrictOutput
    from nplg_mcp.json_types import JsonObject
    from nplg_mcp.services import AssetStore


@dataclass(slots=True)
class _ResourceTools:
    calls: int = 0

    def list_tools(self) -> list[JsonObject]:
        return []

    async def call(
        self,
        name: str,
        arguments: JsonObject,
    ) -> StrictOutput | JsonObject:
        del name, arguments
        return {}

    def list_resources(self) -> list[JsonObject]:
        return []

    async def read_resource(self, uri: str) -> dict[str, str]:
        self.calls += 1
        return {"uri": uri, "mime_type": "application/json", "text": "{}"}


@dataclass(slots=True)
class _BlockingResourceTools(_ResourceTools):
    entered: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)

    @override
    async def read_resource(self, uri: str) -> dict[str, str]:
        self.calls += 1
        self.entered.set()
        _ = await self.release.wait()
        return {"uri": uri, "mime_type": "application/json", "text": "{}"}


def _context() -> ServerRequestContext[None, object]:
    return cast("ServerRequestContext[None, object]", None)


def _store() -> AssetStore:
    return cast("AssetStore", object())


def _scope() -> Scope:
    values: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"mcp.example.test"),
            (b"origin", b"https://mcp.example.test"),
            (b"content-type", b"application/json"),
            (b"mcp-protocol-version", b"v999+test"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("mcp.example.test", 443),
    }
    return cast("Scope", values)


def _message(values: dict[str, object]) -> Message:
    return cast("Message", values)


def _receive() -> Receive:
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if sent:
            return _message({"type": "http.disconnect"})
        sent = True
        return _message({"type": "http.request", "body": b"{}", "more_body": False})

    return receive


async def _send_json(send: Send) -> None:
    await send(
        _message(
            {
                "type": "http.response.start",
                "status": HTTPStatus.OK,
                "headers": [(b"content-type", b"application/json")],
            }
        )
    )
    await send(
        _message(
            {
                "type": "http.response.body",
                "body": b"{}",
            }
        )
    )


@pytest.mark.asyncio
async def test_resource_reservation_is_held_through_final_asgi_send(
    tmp_path: Path,
) -> None:
    """Releasing at handler return must expose a second service read here."""
    admission = InlineResourceAdmission(
        capacity_bytes=INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES,
    )
    tools = _ResourceTools()
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=_store()),
        DeploymentProfile.PRIVATE_FULL,
        admission,
    )
    params = types.ReadResourceRequestParams(uri="nplg://about")
    overloads: list[MCPError] = []

    async def resource_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        try:
            _ = await handlers.on_read_resource(
                _context(),
                params,
            )
        except MCPError as exc:  # type: ignore[misc]
            overloads.append(exc)
        await _send_json(send)

    configured = replace(
        load_config(base_environment(CACHE_DIR=str(tmp_path))),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(
        cast("ASGIApp", resource_app),
        config=configured,
        resource_admission=admission,
    )
    application.start()
    final_send_entered = asyncio.Event()
    release_send = asyncio.Event()

    async def blocking_send(message: Message) -> None:
        message_values = cast("dict[str, object]", message)
        if message_values.get("type") == "http.response.body":
            final_send_entered.set()
            _ = await release_send.wait()

    first = asyncio.create_task(
        application(_scope(), _receive(), blocking_send),
    )
    try:
        async with asyncio.timeout(1):
            _ = await final_send_entered.wait()
        second_messages: list[Message] = []

        async def collect_send(message: Message) -> None:
            second_messages.append(message)

        await application(_scope(), _receive(), collect_send)
    finally:
        release_send.set()
        await first

    assert tools.calls == 1
    assert len(overloads) == 1
    assert second_messages
    assert admission.active_bytes == 0


@pytest.mark.asyncio
async def test_small_held_response_releases_unused_byte_reservation(
    tmp_path: Path,
) -> None:
    """A small adapted response must not retain its worst-case reservation."""
    admission = InlineResourceAdmission(
        capacity_bytes=INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES + (1024 * 1024),
    )
    tools = _ResourceTools()
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=_store()),
        DeploymentProfile.PRIVATE_FULL,
        admission,
    )
    params = types.ReadResourceRequestParams(uri="nplg://about")
    overloads: list[MCPError] = []

    async def resource_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        try:
            _ = await handlers.on_read_resource(
                _context(),
                params,
            )
        except MCPError as exc:  # type: ignore[misc]
            overloads.append(exc)
        await _send_json(send)

    configured = replace(
        load_config(base_environment(CACHE_DIR=str(tmp_path))),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(
        cast("ASGIApp", resource_app),
        config=configured,
        resource_admission=admission,
    )
    application.start()
    final_send_entered = asyncio.Event()
    release_send = asyncio.Event()

    async def blocking_send(message: Message) -> None:
        message_values = cast("dict[str, object]", message)
        if message_values.get("type") == "http.response.body":
            final_send_entered.set()
            _ = await release_send.wait()

    first = asyncio.create_task(application(_scope(), _receive(), blocking_send))
    try:
        async with asyncio.timeout(1):
            _ = await final_send_entered.wait()
        second_messages: list[Message] = []

        async def collect_send(message: Message) -> None:
            second_messages.append(message)

        await application(_scope(), _receive(), collect_send)
    finally:
        release_send.set()
        await first

    assert tools.calls == _EXPECTED_TWO_RESOURCE_CALLS
    assert overloads == []
    assert second_messages
    assert admission.active_bytes == 0


@pytest.mark.asyncio
async def test_timeout_holds_resource_bytes_through_terminal_partial_body(
    tmp_path: Path,
) -> None:
    """Timeout cleanup must not release bytes before its closing body is sent."""
    admission = InlineResourceAdmission(
        capacity_bytes=INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES,
    )
    tools = _ResourceTools()
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=_store()),
        DeploymentProfile.PRIVATE_FULL,
        admission,
    )
    params = types.ReadResourceRequestParams(uri="nplg://about")
    never_complete = asyncio.Event()

    async def partial_resource_app(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        del scope, receive
        _ = await handlers.on_read_resource(_context(), params)
        await send(
            _message(
                {
                    "type": "http.response.start",
                    "status": HTTPStatus.OK,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
        )
        _ = await never_complete.wait()

    configured = replace(
        load_config(base_environment(CACHE_DIR=str(tmp_path))),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
        mcp_application_deadline_seconds=0.05,
    )
    application = McpSecurityMiddleware(
        cast("ASGIApp", partial_resource_app),
        config=configured,
        resource_admission=admission,
    )
    application.start()
    terminal_send_entered = asyncio.Event()
    release_terminal_send = asyncio.Event()

    async def blocking_terminal_send(message: Message) -> None:
        message_values = cast("dict[str, object]", message)
        if message_values.get("type") == "http.response.body":
            terminal_send_entered.set()
            _ = await release_terminal_send.wait()

    operation = asyncio.create_task(
        application(_scope(), _receive(), blocking_terminal_send)
    )
    try:
        async with asyncio.timeout(1):
            _ = await terminal_send_entered.wait()
        bytes_during_terminal_send = admission.active_bytes
    finally:
        release_terminal_send.set()
        await operation

    assert bytes_during_terminal_send > 0
    assert admission.active_bytes == 0


@pytest.mark.asyncio
async def test_cancelled_asgi_send_releases_all_resource_bytes(
    tmp_path: Path,
) -> None:
    admission = InlineResourceAdmission(
        capacity_bytes=INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES,
    )
    tools = _ResourceTools()
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=_store()),
        DeploymentProfile.PRIVATE_FULL,
        admission,
    )
    params = types.ReadResourceRequestParams(uri="nplg://about")

    async def resource_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        _ = await handlers.on_read_resource(_context(), params)
        await _send_json(send)

    configured = replace(
        load_config(base_environment(CACHE_DIR=str(tmp_path))),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(
        cast("ASGIApp", resource_app),
        config=configured,
        resource_admission=admission,
    )
    application.start()
    body_send_entered = asyncio.Event()
    never_complete = asyncio.Event()

    async def blocked_send(message: Message) -> None:
        message_values = cast("dict[str, object]", message)
        if message_values.get("type") == "http.response.body":
            body_send_entered.set()
            _ = await never_complete.wait()

    operation = asyncio.create_task(application(_scope(), _receive(), blocked_send))
    async with asyncio.timeout(1):
        _ = await body_send_entered.wait()
    assert admission.active_bytes > 0

    _ = operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation
    assert admission.active_bytes == 0


@pytest.mark.asyncio
async def test_failed_asgi_send_releases_all_resource_bytes(tmp_path: Path) -> None:
    admission = InlineResourceAdmission(
        capacity_bytes=INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES,
    )
    tools = _ResourceTools()
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=_store()),
        DeploymentProfile.PRIVATE_FULL,
        admission,
    )
    params = types.ReadResourceRequestParams(uri="nplg://about")

    async def resource_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        _ = await handlers.on_read_resource(_context(), params)
        await _send_json(send)

    configured = replace(
        load_config(base_environment(CACHE_DIR=str(tmp_path))),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
    )
    application = McpSecurityMiddleware(
        cast("ASGIApp", resource_app),
        config=configured,
        resource_admission=admission,
    )
    application.start()

    async def failed_send(message: Message) -> None:
        message_values = cast("dict[str, object]", message)
        if message_values.get("type") == "http.response.body":
            error_message = "fixture send failure"
            raise ConnectionError(error_message)

    with pytest.raises(ConnectionError, match="fixture send failure"):
        await application(_scope(), _receive(), failed_send)

    assert admission.active_bytes == 0


@pytest.mark.asyncio
async def test_cancelled_resource_read_releases_exact_reservation() -> None:
    admission = InlineResourceAdmission(
        capacity_bytes=INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES,
    )
    tools = _BlockingResourceTools()
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=_store()),
        DeploymentProfile.PRIVATE_FULL,
        admission,
    )
    params = types.ReadResourceRequestParams(uri="nplg://about")
    operation = asyncio.create_task(handlers.on_read_resource(_context(), params))
    async with asyncio.timeout(1):
        _ = await tools.entered.wait()

    assert admission.active_bytes == INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES
    _ = operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await operation
    assert admission.active_bytes == 0

    tools.release.set()
    result = await handlers.on_read_resource(_context(), params)
    assert len(result.contents) == 1
    assert admission.active_bytes == 0


@pytest.mark.asyncio
async def test_resource_capacity_does_not_penalize_unrelated_mcp_operations() -> None:
    admission = InlineResourceAdmission(
        capacity_bytes=INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES,
    )
    tools = _BlockingResourceTools()
    handlers = SdkHandlers(
        FullServiceComposition(tools=tools, store=_store()),
        DeploymentProfile.PRIVATE_FULL,
        admission,
    )
    params = types.ReadResourceRequestParams(uri="nplg://about")
    resource_operation = asyncio.create_task(
        handlers.on_read_resource(_context(), params)
    )
    async with asyncio.timeout(1):
        _ = await tools.entered.wait()

    listed = await handlers.on_list_tools(_context(), None)

    assert listed.tools == []
    tools.release.set()
    _ = await resource_operation
    assert admission.active_bytes == 0


def test_inline_resource_admission_uses_exact_leak_free_byte_accounting() -> None:
    admission = InlineResourceAdmission(capacity_bytes=_ACCOUNTING_CAPACITY_BYTES)
    first = admission.try_reserve(_ACCOUNTING_FIRST_BYTES)
    second = admission.try_reserve(_ACCOUNTING_SECOND_BYTES)
    assert first is not None
    assert second is not None
    assert admission.active_bytes == _ACCOUNTING_CAPACITY_BYTES
    assert admission.try_reserve(1) is None

    first.shrink(_ACCOUNTING_RETAINED_BYTES)
    assert admission.active_bytes == (
        _ACCOUNTING_RETAINED_BYTES + _ACCOUNTING_SECOND_BYTES
    )
    third = admission.try_reserve(_ACCOUNTING_SECOND_BYTES)
    assert third is not None
    assert admission.active_bytes == _ACCOUNTING_CAPACITY_BYTES

    first.release()
    second.release()
    third.release()
    assert admission.active_bytes == 0
    with pytest.raises(RuntimeError, match="release is unbalanced"):
        first.release()


@pytest.mark.parametrize(
    "invalid_size",
    [True, -1, HARD_MAX_INLINE_RESOURCE_BYTES + 1, "1"],
)
def test_inline_text_reservation_rejects_unvalidated_sizes(
    invalid_size: object,
) -> None:
    with pytest.raises(ValueError, match="outside the validated range"):
        _ = inline_text_response_reservation_bytes(cast("int", invalid_size))


@pytest.mark.parametrize(
    ("decoded_bytes", "base64_bytes"),
    [
        (True, 4),
        (0, 4),
        (HARD_MAX_INLINE_RESOURCE_BYTES + 1, 4),
        (1, True),
        (1, 3),
        (1, ((HARD_MAX_INLINE_RESOURCE_BYTES + 2) // 3 * 4) + 1),
    ],
)
def test_inline_blob_reservation_rejects_unvalidated_sizes(
    decoded_bytes: object,
    base64_bytes: object,
) -> None:
    with pytest.raises(ValueError, match="outside the validated range"):
        _ = inline_blob_response_reservation_bytes(
            decoded_bytes=cast("int", decoded_bytes),
            base64_bytes=cast("int", base64_bytes),
        )


def test_inline_reservation_helpers_accept_exact_boundaries() -> None:
    assert inline_text_response_reservation_bytes(0) > 0
    assert (
        inline_text_response_reservation_bytes(
            HARD_MAX_INLINE_RESOURCE_BYTES,
        )
        <= INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES
    )
    assert (
        inline_blob_response_reservation_bytes(
            decoded_bytes=1,
            base64_bytes=4,
        )
        <= INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES
    )


@pytest.mark.parametrize("invalid_capacity", [True, 0, -1, "10"])
def test_inline_resource_admission_rejects_invalid_capacity(
    invalid_capacity: object,
) -> None:
    with pytest.raises(ValueError, match="capacity must be a positive integer"):
        _ = InlineResourceAdmission(cast("int", invalid_capacity))


@pytest.mark.parametrize("invalid_request", [True, 0, -1, "1"])
def test_inline_resource_admission_rejects_invalid_reservation_size(
    invalid_request: object,
) -> None:
    admission = InlineResourceAdmission(capacity_bytes=1)

    with pytest.raises(ValueError, match="reservation must be a positive integer"):
        _ = admission.try_reserve(cast("int", invalid_request))


@pytest.mark.parametrize("invalid_retained_bytes", [True, 0, -1, 7, "1"])
def test_inline_resource_reservation_rejects_invalid_shrink_size(
    invalid_retained_bytes: object,
) -> None:
    admission = InlineResourceAdmission(capacity_bytes=_ACCOUNTING_FIRST_BYTES)
    reservation = admission.try_reserve(_ACCOUNTING_FIRST_BYTES)
    assert reservation is not None

    with pytest.raises(ValueError, match="only shrink to a positive size"):
        reservation.shrink(cast("int", invalid_retained_bytes))
    assert admission.active_bytes == _ACCOUNTING_FIRST_BYTES


def test_inline_resource_reservation_allows_exact_noop_shrink() -> None:
    admission = InlineResourceAdmission(capacity_bytes=_ACCOUNTING_FIRST_BYTES)
    reservation = admission.try_reserve(_ACCOUNTING_FIRST_BYTES)
    assert reservation is not None

    reservation.shrink(_ACCOUNTING_FIRST_BYTES)

    assert admission.active_bytes == _ACCOUNTING_FIRST_BYTES
    reservation.release()


def test_released_inline_resource_reservation_cannot_be_resized() -> None:
    admission = InlineResourceAdmission(capacity_bytes=1)
    reservation = admission.try_reserve(1)
    assert reservation is not None
    reservation.release()

    with pytest.raises(RuntimeError, match="cannot be resized"):
        reservation.shrink(1)


@pytest.mark.parametrize("invalid_return", [True, 0, -1, "1"])
def test_inline_resource_admission_rejects_invalid_return_size(
    invalid_return: object,
) -> None:
    admission = InlineResourceAdmission(capacity_bytes=1)

    with pytest.raises(ValueError, match="return must be a positive integer"):
        admission.return_reserved_bytes(cast("int", invalid_return))
    assert admission.active_bytes == 0


def test_inline_resource_admission_rejects_unbalanced_return() -> None:
    admission = InlineResourceAdmission(capacity_bytes=1)

    with pytest.raises(RuntimeError, match="accounting is unbalanced"):
        admission.return_reserved_bytes(1)


def test_empty_inline_resource_request_scope_is_leak_free() -> None:
    admission = InlineResourceAdmission(capacity_bytes=1)

    with admission.request_scope():
        assert admission.active_bytes == 0

    assert admission.active_bytes == 0
