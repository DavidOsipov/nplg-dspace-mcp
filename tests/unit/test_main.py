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
from nplg_mcp.private_tls import PrivateTlsMaterialError, PrivateTlsPaths

if TYPE_CHECKING:
    from typing import Unpack


class _RunKwargs(TypedDict):
    host: str
    port: int
    proxy_headers: bool
    forwarded_allow_ips: str
    access_log: bool
    limit_concurrency: int


def test_main_requires_mutual_tls_for_the_private_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The internal origin must not silently downgrade to plaintext."""
    sentinel = SimpleNamespace(
        state=SimpleNamespace(
            config=SimpleNamespace(
                max_concurrent_http_requests=16,
                private_edge_tls=True,
            )
        )
    )
    captured: dict[str, object] = {}
    validated: list[PrivateTlsPaths] = []
    monkeypatch.setattr(entrypoint, "build_default_app", lambda: sentinel)

    def record_material(paths: PrivateTlsPaths, *, now: object) -> None:
        del now
        validated.append(paths)

    monkeypatch.setattr(entrypoint, "validate_private_tls_material", record_material)

    def fake_run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)

    assert entrypoint.main() == 0
    assert captured["ssl_certfile"] == "/run/secrets/app_server_cert"
    assert captured["ssl_keyfile"] == "/run/secrets/app_server_key"
    assert captured["ssl_ca_certs"] == "/run/secrets/caddy_client_ca"
    assert captured["ssl_cert_reqs"] != 0
    assert len(validated) == 1
    validated_paths = validated[0]
    assert validated_paths.server_name == "app.internal"


def test_main_rejects_private_tls_material_before_server_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = SimpleNamespace(
        state=SimpleNamespace(
            config=SimpleNamespace(
                max_concurrent_http_requests=16,
                private_edge_tls=True,
            )
        )
    )
    monkeypatch.setattr(entrypoint, "build_default_app", lambda: sentinel)

    def reject_material(paths: object, *, now: object) -> None:
        del paths, now
        error = PrivateTlsMaterialError.for_reason("test fixture")
        raise error

    def forbidden_run(app: object, **kwargs: object) -> None:
        del app, kwargs
        msg = "uvicorn must not start with invalid private TLS material"
        raise AssertionError(msg)

    monkeypatch.setattr(entrypoint, "validate_private_tls_material", reject_material)
    monkeypatch.setattr(uvicorn, "run", forbidden_run)

    with pytest.raises(PrivateTlsMaterialError, match="test fixture"):
        _ = entrypoint.main()


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
