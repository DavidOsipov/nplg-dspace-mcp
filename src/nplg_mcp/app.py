# Copyright (c) 2026 David Osipov
"""FastAPI application assembly and HTTP security middleware."""

from __future__ import annotations

import asyncio
import hmac
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from typing import TYPE_CHECKING, Protocol, cast, override, runtime_checkable
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from prometheus_client import CollectorRegistry, Counter, generate_latest

from .admission import AdmissionGate, PathAdmissionMiddleware
from .config import AppConfig, load_config
from .downloader import DocumentDownloader
from .errors import AppError, ErrorCode, to_public_error
from .pdf import PdfProcessor
from .protocol import McpProtocol, ProtocolFailure, ProtocolResponse, ToolSurface
from .rate_limit import AsyncRateLimiter
from .repository import NplgRepository
from .storage import ContentAddressedStore
from .tokens import verify_asset_token
from .tools import ToolService, ToolServiceDependencies

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Mapping
    from urllib.request import Request as UrlRequest

    from starlette.types import Receive, Scope, Send

    from .http_types import HttpClientProtocol
    from .json_types import JsonObject

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
_HTTP_CLIENT_ERROR = 400


def _metric_method_label(value: str | None) -> str:
    if value in _METRIC_METHOD_LABELS:
        return value
    return "unknown"


def _metric_outcome(status: int, payload: JsonObject | None) -> str:
    if status >= _HTTP_CLIENT_ERROR or (payload is not None and "error" in payload):
        return "error"
    result = payload.get("result") if payload is not None else None
    if isinstance(result, dict) and result.get("isError") is True:
        return "error"
    return "ok"


@dataclass(slots=True)
class AppServices:
    """Runtime services owned by one application instance."""

    tools: ToolSurface
    store: ContentAddressedStore
    http_client: HttpClientProtocol | None = None


class NplgFastAPI(FastAPI):
    """FastAPI application with typed access to NPLG runtime state."""

    config: AppConfig | None = None
    services: AppServices | None = None


@runtime_checkable
class _HeaderList(Protocol):
    def getlist(self, name: str) -> list[str]: ...


class _RejectAllCookiesPolicy(DefaultCookiePolicy):
    """Prevent process-wide upstream state from crossing MCP callers."""

    @override
    def set_ok(self, cookie: Cookie, request: UrlRequest) -> bool:
        return False

    @override
    def return_ok(self, cookie: Cookie, request: UrlRequest) -> bool:
        return False

    @override
    def domain_return_ok(self, domain: str, request: UrlRequest) -> bool:
        return False

    @override
    def path_return_ok(self, path: str, request: UrlRequest) -> bool:
        return False


class _DisconnectAwareFileResponse(FileResponse):
    """Stop local file reads promptly when the ASGI peer disconnects."""

    @staticmethod
    async def _wait_for_disconnect(receive: Receive) -> None:
        while True:
            raw_message: object = await receive()
            message = cast("Mapping[str, object]", raw_message)
            message_type: object = message.get("type")
            if message_type == "http.disconnect":
                return

    @override
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        stream = asyncio.create_task(super().__call__(scope, receive, send))
        disconnect = asyncio.create_task(self._wait_for_disconnect(receive))
        try:
            completed, _ = await asyncio.wait(
                {stream, disconnect}, return_when=asyncio.FIRST_COMPLETED
            )
            if stream in completed:
                await stream
            else:
                _ = stream.cancel()
                cancelled_stream: object = await asyncio.gather(
                    stream, return_exceptions=True
                )
                del cancelled_stream
        finally:
            for task in (stream, disconnect):
                if not task.done():
                    _ = task.cancel()
            cancelled_tasks: object = await asyncio.gather(
                stream, disconnect, return_exceptions=True
            )
            del cancelled_tasks


def _origin(value: str) -> tuple[str, str, int]:
    if (
        not value
        or any(character.isspace() for character in value)
        or "%" in value
        or "\\" in value
    ):
        msg = "invalid origin"
        raise ValueError(msg)
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
        msg = "invalid origin"
        raise ValueError(msg)
    default_port = 443 if parsed.scheme == "https" else 80
    try:
        port = parsed.port
    except ValueError as exc:
        msg = "invalid origin"
        raise ValueError(msg) from exc
    return parsed.scheme.lower(), parsed.hostname.lower(), port or default_port


def _request_authority(value: str, *, scheme: str) -> tuple[str, int]:
    if (
        not value
        or any(character.isspace() for character in value)
        or "%" in value
        or "\\" in value
    ):
        msg = "invalid host"
        raise ValueError(msg)
    parsed = urlsplit(f"{scheme}://{value}")
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        msg = "invalid host"
        raise ValueError(msg)
    try:
        port = parsed.port
    except ValueError as exc:
        msg = "invalid host"
        raise ValueError(msg) from exc
    default_port = 443 if scheme == "https" else 80
    return parsed.hostname.lower(), port or default_port


def _header_values(headers: Mapping[str, str] | _HeaderList, name: str) -> list[str]:
    if isinstance(headers, _HeaderList):
        return headers.getlist(name)
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
        raise AppError(
            ErrorCode.UNAUTHORIZED, "Host is not allowed.", http_status=403
        ) from exc
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
    http_client = httpx.AsyncClient(
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
    client = cast("HttpClientProtocol", http_client)
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
        dependencies=ToolServiceDependencies(
            repository=repository,
            downloader=downloader,
            pdf=pdf,
            store=store,
        ),
        config=config,
    )
    return AppServices(tools=tools, store=store, http_client=client)


async def _bounded_body(request: Request, maximum: int) -> bytes:
    declared_values = _header_values(request.headers, "content-length")
    if len(declared_values) > 1:
        raise AppError(
            ErrorCode.INVALID_INPUT, "Content-Length is invalid.", http_status=400
        )
    declared = declared_values[0] if declared_values else None
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise AppError(
                ErrorCode.INVALID_INPUT, "Content-Length is invalid.", http_status=400
            ) from exc
        if declared_size < 0:
            raise AppError(
                ErrorCode.INVALID_INPUT, "Content-Length is invalid.", http_status=400
            )
        if declared_size > maximum:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "The request body is too large.",
                http_status=413,
            )
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "The request body is too large.",
                http_status=413,
            )
        body.extend(chunk)
    return bytes(body)


def _json_response(
    *,
    status_code: int,
    content: JsonObject,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """Keep the untyped JSONResponse content seam behind one typed helper."""
    return JSONResponse(status_code=status_code, content=content, headers=headers)


def _app_error_response(exc: Exception) -> JSONResponse:
    if not isinstance(exc, AppError):
        msg = "AppError handler received another exception type"
        raise TypeError(msg)
    return _json_response(
        status_code=exc.http_status,
        content={"error": to_public_error(exc)},
    )


def _require_allowed_origin(request: Request, config: AppConfig) -> None:
    origin_values = _header_values(request.headers, "origin")
    if len(origin_values) > 1:
        raise AppError(
            ErrorCode.UNAUTHORIZED,
            "Origin is not allowed.",
            http_status=403,
        )
    origin = origin_values[0] if origin_values else None
    if origin is None:
        return
    try:
        origin_matches = _origin(origin) == _origin(config.public_base_url)
    except ValueError as exc:
        raise AppError(
            ErrorCode.UNAUTHORIZED,
            "Origin is not allowed.",
            http_status=403,
        ) from exc
    if not origin_matches:
        raise AppError(
            ErrorCode.UNAUTHORIZED,
            "Origin is not allowed.",
            http_status=403,
        )


def _require_api_authentication(request: Request, config: AppConfig) -> None:
    if not config.allow_anonymous and not _has_valid_api_credential(request, config):
        raise AppError(
            ErrorCode.UNAUTHORIZED,
            "API authentication is required.",
            http_status=401,
        )


def _require_json_content_type(request: Request) -> None:
    content_type_values = _header_values(request.headers, "content-type")
    if len(content_type_values) != 1:
        raise AppError(
            ErrorCode.INVALID_INPUT,
            "Content-Type must be application/json.",
            http_status=415,
        )
    media_type = content_type_values[0].split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise AppError(
            ErrorCode.INVALID_INPUT,
            "Content-Type must be application/json.",
            http_status=415,
        )


async def _receive_request_body(request: Request, config: AppConfig) -> bytes:
    try:
        return await asyncio.wait_for(
            _bounded_body(request, config.max_request_body_bytes),
            timeout=config.request_body_timeout_seconds,
        )
    except TimeoutError as exc:
        raise AppError(
            ErrorCode.REQUEST_TIMEOUT,
            "The request body was not received within the allowed time.",
            http_status=408,
        ) from exc


def _protocol_http_response(response: ProtocolResponse) -> Response:
    if response.payload is None:
        return Response(status_code=response.status)
    return _json_response(status_code=response.status, content=response.payload)


def _record_request(
    request_counter: Counter,
    *,
    method: str,
    outcome: str,
) -> None:
    request_counter.labels(method=method, outcome=outcome).inc()


def _busy_response(request_counter: Counter, method_label: str) -> JSONResponse:
    busy = AppError(
        ErrorCode.RATE_LIMITED,
        "The MCP server is at its concurrent request limit.",
        http_status=503,
    )
    _record_request(request_counter, method=method_label, outcome="error")
    return _json_response(
        status_code=503,
        content={"error": to_public_error(busy)},
        headers={"Retry-After": "1"},
    )


async def _admitted_mcp_response(
    request: Request,
    *,
    config: AppConfig,
    protocol: McpProtocol,
    admission: AdmissionGate,
    request_counter: Counter,
) -> Response:
    method_label = "unknown"
    try:
        raw = await _receive_request_body(request, config)
        try:
            payload = protocol.parse_json(raw)
        except ProtocolFailure as failure:
            response = McpProtocol.error_response(None, failure)
            _record_request(request_counter, method=method_label, outcome="error")
            return _protocol_http_response(response)

        raw_method = payload.get("method")
        method_label = _metric_method_label(
            raw_method if isinstance(raw_method, str) else None
        )
        response = await protocol.handle(payload, request.headers)
        _record_request(
            request_counter,
            method=method_label,
            outcome=_metric_outcome(response.status, response.payload),
        )
        return _protocol_http_response(response)
    except AppError as exc:
        _record_request(request_counter, method=method_label, outcome="error")
        return _json_response(
            status_code=exc.http_status,
            content={"error": to_public_error(exc)},
        )
    finally:
        admission.release()


async def _mcp_response(
    request: Request,
    *,
    config: AppConfig,
    protocol: McpProtocol,
    admission: AdmissionGate,
    request_counter: Counter,
) -> Response:
    method_label = "unknown"
    try:
        _require_public_host(request, config)
        _require_allowed_origin(request, config)
        _require_api_authentication(request, config)
        _require_json_content_type(request)
        if not admission.try_acquire():
            return _busy_response(request_counter, method_label)
    except AppError as exc:
        _record_request(request_counter, method=method_label, outcome="error")
        return _json_response(
            status_code=exc.http_status,
            content={"error": to_public_error(exc)},
        )
    return await _admitted_mcp_response(
        request,
        config=config,
        protocol=protocol,
        admission=admission,
        request_counter=request_counter,
    )


def _metrics_response(
    request: Request,
    *,
    config: AppConfig,
    registry: CollectorRegistry,
) -> Response:
    try:
        _require_public_host(request, config)
    except AppError:
        return PlainTextResponse("Not Found", status_code=404)
    credentials_missing = config.api_bearer_token is None and config.api_key is None
    if credentials_missing or not _has_valid_api_credential(request, config):
        return PlainTextResponse("Not Found", status_code=404)
    return Response(
        generate_latest(registry),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


def _asset_response(
    token: str,
    request: Request,
    *,
    config: AppConfig,
    services: AppServices,
) -> Response:
    _require_public_host(request, config)
    grant = verify_asset_token(config.asset_signing_secret, token)
    path = services.store.resolve_asset(grant.path)
    filename = path.name.replace('"', "")
    headers = {
        "Cache-Control": "private, no-store",
        "Content-Disposition": f'inline; filename="{filename}"',
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cross-Origin-Resource-Policy": "same-site",
        "X-Content-Type-Options": "nosniff",
    }
    return _DisconnectAwareFileResponse(
        path,
        media_type=grant.media_type,
        headers=headers,
    )


def create_app(
    config: AppConfig | None = None, *, services: AppServices | None = None
) -> NplgFastAPI:
    """Create one configured FastAPI application and its bounded routes."""
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
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        try:
            yield
        finally:
            if services is None and runtime.http_client is not None:
                await runtime.http_client.aclose()

    app = NplgFastAPI(
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
    app.config = cfg
    app.services = runtime
    # Preserve the original Starlette state coordinates for integrations that
    # inspect the application through its framework-owned state container.
    app.state.config = cfg
    app.state.services = runtime

    async def app_error_handler(_: Request, exc: Exception) -> JSONResponse:
        return _app_error_response(exc)

    async def health() -> dict[str, str]:
        return {"status": "ok"}

    async def ready() -> dict[str, str]:
        with runtime.store.stage(suffix=".ready"):
            pass
        return {"status": "ready"}

    async def metrics(request: Request) -> Response:
        return _metrics_response(request, config=cfg, registry=registry)

    async def mcp_endpoint(request: Request) -> Response:
        return await _mcp_response(
            request,
            config=cfg,
            protocol=protocol,
            admission=admission,
            request_counter=request_counter,
        )

    async def asset(token: str, request: Request) -> Response:
        return _asset_response(token, request, config=cfg, services=runtime)

    app.add_exception_handler(AppError, app_error_handler)
    app.add_api_route("/healthz", health, methods=["GET"])
    app.add_api_route("/readyz", ready, methods=["GET"])
    app.add_api_route("/metrics", metrics, methods=["GET"])
    app.add_api_route("/mcp", mcp_endpoint, methods=["POST"])
    app.add_api_route("/assets/{token}", asset, methods=["GET"])

    return app


def build_default_app() -> NplgFastAPI:
    """Create the default environment-configured application."""
    return create_app()
