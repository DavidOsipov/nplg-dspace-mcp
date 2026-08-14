from __future__ import annotations

import asyncio
import hmac
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from prometheus_client import CollectorRegistry, Counter, generate_latest
from starlette.types import Receive, Scope, Send

from .admission import AdmissionGate, PathAdmissionMiddleware
from .config import AppConfig, load_config
from .downloader import DocumentDownloader
from .errors import AppError, ErrorCode, to_public_error
from .pdf import PdfProcessor
from .protocol import McpProtocol, ProtocolFailure
from .rate_limit import AsyncRateLimiter
from .repository import NplgRepository
from .storage import ContentAddressedStore
from .tokens import verify_asset_token
from .tools import ToolService

_METRIC_METHOD_LABELS = frozenset(
    {
        "initialize",
        "server/discover",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
    }
)


def _metric_method_label(value: str | None) -> str:
    if value in _METRIC_METHOD_LABELS:
        return value
    return "unknown"


def _metric_outcome(status: int, payload: dict[str, Any] | None) -> str:
    if status >= 400 or (isinstance(payload, dict) and "error" in payload):
        return "error"
    result = payload.get("result") if isinstance(payload, dict) else None
    if isinstance(result, dict) and result.get("isError") is True:
        return "error"
    return "ok"


@dataclass(slots=True)
class AppServices:
    tools: Any
    store: ContentAddressedStore
    http_client: httpx.AsyncClient | None = None


class _RejectAllCookiesPolicy(DefaultCookiePolicy):
    """Prevent process-wide upstream state from crossing MCP callers."""

    def set_ok(self, cookie: Any, request: Any) -> bool:
        return False

    def return_ok(self, cookie: Any, request: Any) -> bool:
        return False

    def domain_return_ok(self, domain: str, request: Any) -> bool:
        return False

    def path_return_ok(self, path: str, request: Any) -> bool:
        return False


class _DisconnectAwareFileResponse(FileResponse):
    """Stop local file reads promptly when the ASGI peer disconnects."""

    @staticmethod
    async def _wait_for_disconnect(receive: Receive) -> None:
        while True:
            if (await receive())["type"] == "http.disconnect":
                return

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        stream = asyncio.create_task(super().__call__(scope, receive, send))
        disconnect = asyncio.create_task(self._wait_for_disconnect(receive))
        try:
            completed, _ = await asyncio.wait({stream, disconnect}, return_when=asyncio.FIRST_COMPLETED)
            if stream in completed:
                await stream
            else:
                stream.cancel()
                await asyncio.gather(stream, return_exceptions=True)
        finally:
            for task in (stream, disconnect):
                if not task.done():
                    task.cancel()
            await asyncio.gather(stream, disconnect, return_exceptions=True)


def _origin(value: str) -> tuple[str, str, int]:
    if not value or any(character.isspace() for character in value) or "%" in value or "\\" in value:
        raise ValueError("invalid origin")
    parsed = urlsplit(value)
    if (
        not parsed.scheme
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid origin")
    default_port = 443 if parsed.scheme == "https" else 80
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid origin") from exc
    return parsed.scheme.lower(), parsed.hostname.lower(), port or default_port


def _request_authority(value: str, *, scheme: str) -> tuple[str, int]:
    if not value or any(character.isspace() for character in value) or "%" in value or "\\" in value:
        raise ValueError("invalid host")
    parsed = urlsplit(f"{scheme}://{value}")
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid host") from exc
    default_port = 443 if scheme == "https" else 80
    return parsed.hostname.lower(), port or default_port


def _header_values(headers: Any, name: str) -> list[str]:
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        return list(getlist(name))
    lower = name.lower()
    return [value for key, value in headers.items() if key.lower() == lower]


def _require_public_host(request: Request, config: AppConfig) -> None:
    scheme, hostname, port = _origin(config.public_base_url)
    host_values = _header_values(request.headers, "host")
    if len(host_values) != 1:
        raise AppError(ErrorCode.UNAUTHORIZED, "Host is not allowed.", http_status=403)
    try:
        supplied_host, supplied_port = _request_authority(host_values[0], scheme=scheme)
    except ValueError as exc:
        raise AppError(ErrorCode.UNAUTHORIZED, "Host is not allowed.", http_status=403) from exc
    if (supplied_host, supplied_port) != (hostname, port):
        raise AppError(ErrorCode.UNAUTHORIZED, "Host is not allowed.", http_status=403)


def _has_valid_api_credential(request: Request, config: AppConfig) -> bool:
    bearer_values = request.headers.getlist("authorization")
    api_key_values = request.headers.getlist("x-api-key")
    if len(bearer_values) + len(api_key_values) != 1:
        return False
    if bearer_values:
        expected = f"Bearer {config.api_bearer_token or ''}"
        return config.api_bearer_token is not None and hmac.compare_digest(
            bearer_values[0].encode("utf-8"),
            expected.encode("utf-8"),
        )
    expected_api_key = config.api_key or ""
    return config.api_key is not None and hmac.compare_digest(
        api_key_values[0].encode("utf-8"),
        expected_api_key.encode("utf-8"),
    )


def _runtime_services(config: AppConfig) -> AppServices:
    store = ContentAddressedStore(config.cache_dir, max_bytes=config.cache_max_bytes)
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(config.upstream_timeout_seconds),
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        headers={
            "User-Agent": "nplg-dspace-mcp/0.1.0 (+read-only research connector)",
            "Accept-Encoding": "identity",
        },
        cookies=CookieJar(policy=_RejectAllCookiesPolicy()),
    )
    limiter = AsyncRateLimiter(config.upstream_rate_per_second)
    repository = NplgRepository(
        client=client,
        max_redirects=config.max_redirects,
        limiter=limiter,
        total_timeout_seconds=config.upstream_timeout_seconds,
    )
    downloader = DocumentDownloader(
        client=client,
        store=store,
        max_bytes=config.max_download_bytes,
        max_redirects=config.max_redirects,
        limiter=limiter,
        total_timeout_seconds=config.upstream_timeout_seconds,
    )
    pdf = PdfProcessor(
        store=store,
        max_pages_per_render=config.max_render_pages,
        max_page_pixels=config.max_page_pixels,
        max_render_pixels=config.max_render_pixels,
        tile_width=config.tile_width,
        tile_height=config.tile_height,
        tile_overlap=config.tile_overlap,
    )
    tools = ToolService(
        repository=repository,
        downloader=downloader,
        pdf=pdf,
        store=store,
        config=config,
    )
    return AppServices(tools=tools, store=store, http_client=client)


async def _bounded_body(request: Request, maximum: int) -> bytes:
    declared_values = _header_values(request.headers, "content-length")
    if len(declared_values) > 1:
        raise AppError(ErrorCode.INVALID_INPUT, "Content-Length is invalid.", http_status=400)
    declared = declared_values[0] if declared_values else None
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise AppError(ErrorCode.INVALID_INPUT, "Content-Length is invalid.", http_status=400) from exc
        if declared_size < 0:
            raise AppError(ErrorCode.INVALID_INPUT, "Content-Length is invalid.", http_status=400)
        if declared_size > maximum:
            raise AppError(ErrorCode.INVALID_INPUT, "The request body is too large.", http_status=413)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise AppError(ErrorCode.INVALID_INPUT, "The request body is too large.", http_status=413)
        body.extend(chunk)
    return bytes(body)


def create_app(config: AppConfig | None = None, *, services: AppServices | None = None) -> FastAPI:
    cfg = config or load_config(os.environ)
    runtime = services or _runtime_services(cfg)
    protocol = McpProtocol(runtime.tools)
    admission = AdmissionGate(cfg.max_concurrent_mcp_requests)
    registry = CollectorRegistry(auto_describe=True)
    request_counter = Counter(
        "nplg_mcp_requests_total",
        "MCP HTTP requests by method and outcome.",
        labelnames=("method", "outcome"),
        registry=registry,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if services is None and runtime.http_client is not None:
                await runtime.http_client.aclose()

    app = FastAPI(
        title="NPLG DSpace MCP",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(
        PathAdmissionMiddleware,
        capacity=cfg.max_concurrent_asset_streams,
        path_prefix="/assets/",
    )
    app.state.config = cfg
    app.state.services = runtime

    @app.exception_handler(AppError)
    async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content={"error": to_public_error(exc)})

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def ready() -> dict[str, str]:
        with runtime.store.stage(suffix=".ready"):
            pass
        return {"status": "ready"}

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        try:
            _require_public_host(request, cfg)
        except AppError:
            return PlainTextResponse("Not Found", status_code=404)
        if (cfg.api_bearer_token is None and cfg.api_key is None) or not _has_valid_api_credential(request, cfg):
            return PlainTextResponse("Not Found", status_code=404)
        return Response(generate_latest(registry), media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.post("/mcp")
    async def mcp_endpoint(request: Request) -> Response:
        method_label = "unknown"
        try:
            _require_public_host(request, cfg)
            origin_values = _header_values(request.headers, "origin")
            if len(origin_values) > 1:
                raise AppError(ErrorCode.UNAUTHORIZED, "Origin is not allowed.", http_status=403)
            origin = origin_values[0] if origin_values else None
            if origin is not None:
                try:
                    if _origin(origin) != _origin(cfg.public_base_url):
                        raise AppError(ErrorCode.UNAUTHORIZED, "Origin is not allowed.", http_status=403)
                except ValueError as exc:
                    raise AppError(ErrorCode.UNAUTHORIZED, "Origin is not allowed.", http_status=403) from exc

            if not cfg.allow_anonymous:
                if not _has_valid_api_credential(request, cfg):
                    raise AppError(ErrorCode.UNAUTHORIZED, "API authentication is required.", http_status=401)

            content_type_values = _header_values(request.headers, "content-type")
            if len(content_type_values) != 1:
                raise AppError(ErrorCode.INVALID_INPUT, "Content-Type must be application/json.", http_status=415)
            content_type = content_type_values[0].split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise AppError(ErrorCode.INVALID_INPUT, "Content-Type must be application/json.", http_status=415)
            if not admission.try_acquire():
                busy = AppError(
                    ErrorCode.RATE_LIMITED,
                    "The MCP server is at its concurrent request limit.",
                    http_status=503,
                )
                request_counter.labels(method=method_label, outcome="error").inc()
                return JSONResponse(
                    status_code=503,
                    content={"error": to_public_error(busy)},
                    headers={"Retry-After": "1"},
                )
            try:
                try:
                    raw = await asyncio.wait_for(
                        _bounded_body(request, cfg.max_request_body_bytes),
                        timeout=cfg.request_body_timeout_seconds,
                    )
                except TimeoutError as exc:
                    raise AppError(
                        ErrorCode.REQUEST_TIMEOUT,
                        "The request body was not received within the allowed time.",
                        http_status=408,
                    ) from exc
                try:
                    payload = protocol.parse_json(raw)
                except ProtocolFailure as failure:
                    response = McpProtocol._error(None, failure)
                    request_counter.labels(method=method_label, outcome="error").inc()
                    return JSONResponse(status_code=response.status, content=response.payload)

                method_label = _metric_method_label(payload.get("method"))
                response = await protocol.handle(payload, request.headers)
                request_counter.labels(method=method_label, outcome=_metric_outcome(response.status, response.payload)).inc()
                if response.payload is None:
                    return Response(status_code=response.status)
                return JSONResponse(status_code=response.status, content=response.payload)
            finally:
                admission.release()
        except AppError as exc:
            request_counter.labels(method=method_label, outcome="error").inc()
            return JSONResponse(status_code=exc.http_status, content={"error": to_public_error(exc)})

    @app.get("/assets/{token}")
    async def asset(token: str, request: Request) -> Response:
        _require_public_host(request, cfg)
        grant = verify_asset_token(cfg.asset_signing_secret, token)
        path = runtime.store.resolve_asset(grant.path)
        headers = {
            "Cache-Control": "private, no-store",
            "Content-Disposition": f'inline; filename="{path.name.replace(chr(34), "")}"',
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cross-Origin-Resource-Policy": "same-site",
            "X-Content-Type-Options": "nosniff",
        }
        return _DisconnectAwareFileResponse(path, media_type=grant.media_type, headers=headers)

    return app


def build_default_app() -> FastAPI:
    return create_app()
