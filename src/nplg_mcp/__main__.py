# Copyright (c) 2026 David Osipov
"""Command-line entry point for the NPLG MCP server."""

from __future__ import annotations

import os
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, TypedDict, runtime_checkable

import uvicorn

from .app import build_default_app
from .private_tls import PrivateTlsPaths, validate_private_tls_material


@runtime_checkable
class _ConfigLimit(Protocol):
    max_concurrent_http_requests: int


@runtime_checkable
class _PrivateTlsConfig(Protocol):
    private_edge_tls: bool


@runtime_checkable
class _StateWithConfig(Protocol):
    config: _ConfigLimit


@runtime_checkable
class _StateBearingApp(Protocol):
    state: _StateWithConfig


class _TlsRunKwargs(TypedDict, total=False):
    ssl_certfile: str
    ssl_keyfile: str
    ssl_ca_certs: str
    ssl_cert_reqs: int


_APP_SERVER_CERTIFICATE = Path("/run/secrets/app_server_cert")
_APP_SERVER_KEY = Path("/run/secrets/app_server_key")
_APP_SERVER_CA = Path("/run/secrets/app_server_ca")
_CADDY_CLIENT_CA = Path("/run/secrets/caddy_client_ca")
_APP_SERVER_NAME = "app.internal"


def _http_concurrency_limit(app: object) -> int:
    if isinstance(app, _StateBearingApp):
        return app.state.config.max_concurrent_http_requests
    msg = "application does not expose a concurrency limit"
    raise RuntimeError(msg)


def _private_tls_options(app: object) -> _TlsRunKwargs:
    """Return only the fixed, secret-mounted mTLS origin configuration."""
    if not isinstance(app, _StateBearingApp):
        msg = "application does not expose a TLS configuration"
        raise TypeError(msg)
    config = app.state.config
    if not isinstance(config, _PrivateTlsConfig) or not config.private_edge_tls:
        return {}
    paths = PrivateTlsPaths(
        server_certificate=_APP_SERVER_CERTIFICATE,
        server_key=_APP_SERVER_KEY,
        app_server_ca=_APP_SERVER_CA,
        caddy_client_ca=_CADDY_CLIENT_CA,
        server_name=_APP_SERVER_NAME,
    )
    validate_private_tls_material(paths, now=datetime.now(tz=UTC))
    return {
        "ssl_certfile": str(paths.server_certificate),
        "ssl_keyfile": str(paths.server_key),
        "ssl_ca_certs": str(paths.caddy_client_ca),
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
    }


def main() -> int:
    """Start the ASGI server and return a successful process status."""
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app = build_default_app()
    uvicorn.run(
        app,
        host=host,
        port=port,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        access_log=False,
        limit_concurrency=_http_concurrency_limit(app),
        **_private_tls_options(app),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
