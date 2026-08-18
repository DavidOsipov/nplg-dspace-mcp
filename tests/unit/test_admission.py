# Copyright (c) 2026 David Osipov
"""Unit tests for the admission gate and middleware."""

import pytest
from starlette.types import Message, Receive, Scope, Send

from nplg_mcp.admission import AdmissionGate, PathAdmissionMiddleware


def test_admission_gate_is_fail_fast_and_releases_capacity() -> None:
    capacity = 2
    gate = AdmissionGate(capacity)

    assert gate.try_acquire() is True
    assert gate.try_acquire() is True
    assert gate.try_acquire() is False
    assert gate.active == capacity

    gate.release()
    assert gate.try_acquire() is True
    gate.release()
    gate.release()
    assert gate.active == 0


def test_admission_gate_rejects_invalid_capacity_and_unbalanced_release() -> None:
    for invalid in (0, -1, True):
        try:
            _ = AdmissionGate(invalid)
        except ValueError:
            pass
        else:
            msg = "invalid admission capacity was accepted"
            raise AssertionError(msg)

    gate = AdmissionGate(1)
    try:
        gate.release()
    except RuntimeError:
        pass
    else:
        msg = "unbalanced admission release was accepted"
        raise AssertionError(msg)


async def test_path_admission_releases_permit_when_response_send_fails() -> None:
    async def app(_scope: Scope, _receive: Receive, send: Send) -> None:
        response_start: dict[str, object] = {
            "type": "http.response.start",
            "status": 200,
            "headers": [],
        }
        await send(response_start)

    middleware = PathAdmissionMiddleware(app, capacity=1, path_prefix="/assets/")
    scope: Scope = {"type": "http", "path": "/assets/token"}

    async def receive() -> Message:
        return {"type": "http.disconnect"}

    async def failing_send(_message: Message) -> None:
        msg = "peer send failed"
        raise RuntimeError(msg)

    with pytest.raises(RuntimeError, match="peer send failed"):
        await middleware(scope, receive, failing_send)
    assert middleware.gate.active == 0

    sent: list[Message] = []

    async def collecting_send(message: Message) -> None:
        sent.append(message)

    await middleware(scope, receive, collecting_send)
    assert middleware.gate.active == 0
    assert sent == [{"type": "http.response.start", "status": 200, "headers": []}]
