import pytest

from nplg_mcp.admission import AdmissionGate, PathAdmissionMiddleware


def test_admission_gate_is_fail_fast_and_releases_capacity() -> None:
    gate = AdmissionGate(2)

    assert gate.try_acquire() is True
    assert gate.try_acquire() is True
    assert gate.try_acquire() is False
    assert gate.active == 2

    gate.release()
    assert gate.try_acquire() is True
    gate.release()
    gate.release()
    assert gate.active == 0


def test_admission_gate_rejects_invalid_capacity_and_unbalanced_release() -> None:
    for invalid in (0, -1, True):
        try:
            AdmissionGate(invalid)  # type: ignore[arg-type]
        except ValueError:
            pass
        else:
            raise AssertionError("invalid admission capacity was accepted")

    gate = AdmissionGate(1)
    try:
        gate.release()
    except RuntimeError:
        pass
    else:
        raise AssertionError("unbalanced admission release was accepted")


async def test_path_admission_releases_permit_when_response_send_fails() -> None:
    async def app(scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        await send({"type": "http.response.start", "status": 200, "headers": []})

    middleware = PathAdmissionMiddleware(app, capacity=1, path_prefix="/assets/")
    scope = {"type": "http", "path": "/assets/token"}

    async def receive() -> dict[str, str]:
        return {"type": "http.disconnect"}

    async def failing_send(message) -> None:  # type: ignore[no-untyped-def]
        raise RuntimeError("peer send failed")

    with pytest.raises(RuntimeError, match="peer send failed"):
        await middleware(scope, receive, failing_send)  # type: ignore[arg-type]
    assert middleware.gate.active == 0

    sent: list[dict[str, object]] = []

    async def collecting_send(message: dict[str, object]) -> None:
        sent.append(message)

    await middleware(scope, receive, collecting_send)  # type: ignore[arg-type]
    assert middleware.gate.active == 0
    assert sent == [{"type": "http.response.start", "status": 200, "headers": []}]
