from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import nplg_mcp.__main__ as entrypoint


def test_main_disables_access_logs_that_would_disclose_signed_asset_tokens(monkeypatch) -> None:
    sentinel = SimpleNamespace(state=SimpleNamespace(config=SimpleNamespace(max_concurrent_http_requests=128)))
    captured: dict[str, Any] = {}

    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "8123")
    monkeypatch.setattr(entrypoint, "build_default_app", lambda: sentinel)

    def fake_run(app: object, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(entrypoint.uvicorn, "run", fake_run)

    entrypoint.main()

    assert captured == {
        "app": sentinel,
        "host": "0.0.0.0",
        "port": 8123,
        "proxy_headers": True,
        "forwarded_allow_ips": "127.0.0.1",
        "access_log": False,
        "limit_concurrency": 128,
    }
