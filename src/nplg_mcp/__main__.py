# Copyright (c) 2026 David Osipov
"""Command-line entry point for the NPLG MCP server."""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

import uvicorn

from .app import build_default_app


@runtime_checkable
class _ConfigLimit(Protocol):
    max_concurrent_http_requests: int


@runtime_checkable
class _StateWithConfig(Protocol):
    config: _ConfigLimit


@runtime_checkable
class _StateBearingApp(Protocol):
    state: _StateWithConfig


def _http_concurrency_limit(app: object) -> int:
    if isinstance(app, _StateBearingApp):
        return app.state.config.max_concurrent_http_requests
    msg = "application does not expose a concurrency limit"
    raise RuntimeError(msg)


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
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
