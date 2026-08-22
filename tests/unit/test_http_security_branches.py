# Copyright (c) 2026 David Osipov
"""Focused decision coverage for the MCP HTTP security boundary."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from http import HTTPStatus
from typing import TYPE_CHECKING, cast

import pytest

from nplg_mcp.config import CanonicalHost, CanonicalOrigin
from nplg_mcp.http_security import McpSecurityMiddleware
from tests.conformance.test_mcp_http import config, modern_headers

if TYPE_CHECKING:
    from pathlib import Path

    from starlette.types import Message, Receive, Scope, Send

    from nplg_mcp.config import AppConfig


def _configured(tmp_path: Path, *, deadline: float = 20.0) -> AppConfig:
    return replace(
        config(tmp_path),
        mcp_allowed_hosts=(CanonicalHost("mcp.example.test"),),
        mcp_allowed_origins=(CanonicalOrigin("https://mcp.example.test"),),
        mcp_application_deadline_seconds=deadline,
    )


def _mcp_scope(*, content_length: int | None = None) -> Scope:
    headers = [
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in modern_headers("server/discover").items()
    ]
    headers.insert(0, (b"host", b"mcp.example.test"))
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode("ascii")))
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
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("mcp.example.test", 443),
    }
    return cast("Scope", values)


async def _send_ok(send: Send) -> None:
    start: dict[str, object] = {
        "type": "http.response.start",
        "status": HTTPStatus.OK,
        "headers": [(b"content-type", b"application/json")],
    }
    body: dict[str, object] = {
        "type": "http.response.body",
        "body": b"{}",
        "more_body": False,
    }
    await send(cast("Message", start))
    await send(cast("Message", body))


@pytest.mark.parametrize("deadline", [0.0, 20.01], ids=["zero", "above-maximum"])
def test_constructor_rejects_deadline_outside_closed_security_bound(
    tmp_path: Path,
    deadline: float,
) -> None:
    """The outer application deadline must remain in the interval (0, 20]."""

    async def downstream(_scope: Scope, _receive: Receive, _send: Send) -> None:
        pytest.fail("invalid middleware configuration must not invoke its app")

    with pytest.raises(ValueError, match=r"interval \(0, 20\] seconds"):
        _ = McpSecurityMiddleware(
            downstream,
            config=_configured(tmp_path, deadline=deadline),
        )


@pytest.mark.asyncio
async def test_disconnect_during_bounded_body_returns_408_without_sdk_entry(
    tmp_path: Path,
) -> None:
    """A client disconnect is a bounded body timeout, not an SDK event."""
    sdk_entries = 0

    async def downstream(_scope: Scope, _receive: Receive, _send: Send) -> None:
        nonlocal sdk_entries
        sdk_entries += 1

    application = McpSecurityMiddleware(downstream, config=_configured(tmp_path))
    application.start()

    async def receive() -> Message:
        event: dict[str, object] = {"type": "http.disconnect"}
        return cast("Message", event)

    sent: list[dict[str, object]] = []

    async def send(message: Message) -> None:
        sent.append(cast("dict[str, object]", message))

    await application(_mcp_scope(), receive, send)

    starts = [
        message for message in sent if message.get("type") == "http.response.start"
    ]
    assert [message.get("status") for message in starts] == [HTTPStatus.REQUEST_TIMEOUT]
    assert sdk_entries == 0


@pytest.mark.asyncio
async def test_bounded_body_ignores_unexpected_event_before_request_chunk(
    tmp_path: Path,
) -> None:
    """An unrelated ASGI event cannot become request bytes or stall progress."""
    sdk_entries = 0
    incoming: list[dict[str, object]] = [
        {"type": "unexpected.event"},
        {"type": "http.request", "body": b"{}", "more_body": False},
    ]

    async def downstream(_scope: Scope, _receive: Receive, send: Send) -> None:
        nonlocal sdk_entries
        sdk_entries += 1
        await _send_ok(send)

    application = McpSecurityMiddleware(downstream, config=_configured(tmp_path))
    application.start()

    async def receive() -> Message:
        return cast("Message", incoming.pop(0))

    sent: list[dict[str, object]] = []

    async def send(message: Message) -> None:
        sent.append(cast("dict[str, object]", message))

    await application(_mcp_scope(), receive, send)

    starts = [
        message for message in sent if message.get("type") == "http.response.start"
    ]
    assert [message.get("status") for message in starts] == [HTTPStatus.OK]
    assert sdk_entries == 1
    assert incoming == []


@pytest.mark.asyncio
async def test_deadline_after_complete_response_does_not_send_another_body(
    tmp_path: Path,
) -> None:
    """A completed downstream response remains terminal if its handler then stalls."""
    cancelled = asyncio.Event()

    async def complete_then_block(
        _scope: Scope,
        _receive: Receive,
        send: Send,
    ) -> None:
        await _send_ok(send)
        try:
            _ = await asyncio.Event().wait()
        finally:
            cancelled.set()

    application = McpSecurityMiddleware(
        complete_then_block,
        config=_configured(tmp_path, deadline=0.01),
    )
    application.start()
    received = False

    async def receive() -> Message:
        nonlocal received
        if received:
            disconnect: dict[str, object] = {"type": "http.disconnect"}
            return cast("Message", disconnect)
        received = True
        request: dict[str, object] = {
            "type": "http.request",
            "body": b"{}",
            "more_body": False,
        }
        return cast("Message", request)

    sent: list[dict[str, object]] = []

    async def send(message: Message) -> None:
        sent.append(cast("dict[str, object]", message))

    await asyncio.wait_for(application(_mcp_scope(), receive, send), timeout=1)

    assert cancelled.is_set()
    assert [message.get("type") for message in sent] == [
        "http.response.start",
        "http.response.body",
    ]


@pytest.mark.asyncio
async def test_declared_body_length_mismatch_stops_before_sdk_entry(
    tmp_path: Path,
) -> None:
    """A syntactically valid but short body cannot bypass framing validation."""
    sdk_entries = 0

    async def downstream(_scope: Scope, _receive: Receive, _send: Send) -> None:
        nonlocal sdk_entries
        sdk_entries += 1

    application = McpSecurityMiddleware(downstream, config=_configured(tmp_path))
    application.start()

    async def receive() -> Message:
        request: dict[str, object] = {
            "type": "http.request",
            "body": b"{}",
            "more_body": False,
        }
        return cast("Message", request)

    sent: list[dict[str, object]] = []

    async def send(message: Message) -> None:
        sent.append(cast("dict[str, object]", message))

    await application(_mcp_scope(content_length=3), receive, send)

    starts = [
        message for message in sent if message.get("type") == "http.response.start"
    ]
    assert [message.get("status") for message in starts] == [HTTPStatus.BAD_REQUEST]
    assert sdk_entries == 0
