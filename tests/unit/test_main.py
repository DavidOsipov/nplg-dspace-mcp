# Copyright (c) 2026 David Osipov
"""Unit tests for the command-line entry point."""

from __future__ import annotations

import runpy
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, TypedDict, cast

import pytest
import uvicorn

import nplg_mcp.__main__ as entrypoint
import nplg_mcp.app as app_module

if TYPE_CHECKING:
    from typing import Unpack


class _RunKwargs(TypedDict):
    host: str
    port: int
    proxy_headers: bool
    forwarded_allow_ips: str
    access_log: bool
    limit_concurrency: int


def test_main_disables_access_logs_that_would_disclose_signed_asset_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = SimpleNamespace(
        state=SimpleNamespace(config=SimpleNamespace(max_concurrent_http_requests=128))
    )
    captured: dict[str, object] = {}

    monkeypatch.setenv("HOST", "192.0.2.1")
    monkeypatch.setenv("PORT", "8123")
    monkeypatch.setattr(entrypoint, "build_default_app", lambda: sentinel)

    def fake_run(
        app: object,
        **kwargs: Unpack[_RunKwargs],
    ) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)

    exit_code = entrypoint.main()

    assert exit_code == 0
    assert captured == {
        "app": sentinel,
        "host": "192.0.2.1",
        "port": 8123,
        "proxy_headers": True,
        "forwarded_allow_ips": "127.0.0.1",
        "access_log": False,
        "limit_concurrency": 128,
    }


def test_main_fails_before_server_start_when_app_has_no_concurrency_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(entrypoint, "build_default_app", object)

    def forbidden_run(
        app: object,
        **kwargs: Unpack[_RunKwargs],
    ) -> None:
        del app, kwargs
        msg = "uvicorn must not start without a configured concurrency limit"
        raise AssertionError(msg)

    monkeypatch.setattr(uvicorn, "run", forbidden_run)

    with pytest.raises(RuntimeError, match="does not expose a concurrency limit"):
        _ = entrypoint.main()


def test_python_module_entrypoint_uses_defaults_and_exits_successfully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = SimpleNamespace(
        state=SimpleNamespace(config=SimpleNamespace(max_concurrent_http_requests=64))
    )
    captured: dict[str, object] = {}

    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delitem(sys.modules, "nplg_mcp.__main__")
    monkeypatch.setattr(app_module, "build_default_app", lambda: sentinel)

    def fake_run(
        app: object,
        **kwargs: Unpack[_RunKwargs],
    ) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)

    with pytest.raises(SystemExit) as captured_exit:
        _ = cast(
            "object",
            runpy.run_module("nplg_mcp.__main__", run_name="__main__"),
        )

    assert captured_exit.value.code == 0
    assert captured == {
        "app": sentinel,
        "host": "127.0.0.1",
        "port": 8000,
        "proxy_headers": True,
        "forwarded_allow_ips": "127.0.0.1",
        "access_log": False,
        "limit_concurrency": 64,
    }
