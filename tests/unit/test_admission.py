# Copyright (c) 2026 David Osipov
"""Unit tests for the admission gate and middleware."""

import pytest
from starlette.types import Message, Receive, Scope, Send

from nplg_mcp.admission import (
    AdmissionGate,
    PathAdmissionMiddleware,
    PrincipalAdmission,
)


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


@pytest.mark.parametrize("principal_ids", [(), ("duplicate", "duplicate")])
def test_principal_admission_rejects_empty_or_duplicate_registry(
    principal_ids: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="unique configured identifiers"):
        _ = PrincipalAdmission(principal_ids, capacity=1)


def test_principal_admission_rejects_unknown_principal_operations() -> None:
    admission = PrincipalAdmission(("configured",), capacity=1)

    with pytest.raises(ValueError, match="identifier is not configured"):
        _ = admission.try_acquire("unknown")
    with pytest.raises(ValueError, match="identifier is not configured"):
        admission.release("unknown")


def test_principal_admission_enforces_and_releases_configured_capacity() -> None:
    admission = PrincipalAdmission(("configured",), capacity=1)

    assert admission.try_acquire("configured") is True
    assert admission.try_acquire("configured") is False
    admission.release("configured")
    assert admission.try_acquire("configured") is True
    admission.release("configured")


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
