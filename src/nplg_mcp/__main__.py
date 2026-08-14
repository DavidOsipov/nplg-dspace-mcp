from __future__ import annotations

import os

import uvicorn

from .app import build_default_app


def main() -> None:
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
        limit_concurrency=app.state.config.max_concurrent_http_requests,
    )


if __name__ == "__main__":
    main()
