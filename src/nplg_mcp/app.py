# Copyright (c) 2026 David Osipov
"""FastAPI application assembly and HTTP security middleware."""

from __future__ import annotations

import asyncio
import hmac
import importlib
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from typing import TYPE_CHECKING, Protocol, cast, override, runtime_checkable
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from prometheus_client import CollectorRegistry, Counter, generate_latest

from .admission import AdmissionGate, PathAdmissionMiddleware, PrincipalAdmission
from .bounded_work import STORAGE_WORK, BlockingWorkCapacityError
from .config import AppConfig, load_config, validate_deployment_profile
from .errors import AppError, ErrorCode, to_public_error
from .network import create_bound_http_transport
from .protocol import McpProtocol, ProtocolFailure, ProtocolResponse, ToolSurface
from .rate_limit import AsyncRateLimiter
from .repository import NplgRepository
from .tokens import verify_asset_token
from .tools import ToolService, ToolServiceDependencies

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Mapping
    from contextlib import AbstractContextManager
    from pathlib import Path
    from urllib.request import Request as UrlRequest

    from starlette.types import Message, Receive, Scope, Send

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
    store: _AssetStore | None
    http_client: HttpClientProtocol | None = None


@dataclass(frozen=True, slots=True)
class _McpBoundary:
    """Immutable dependencies for one admitted MCP request."""

    config: AppConfig
    protocol: McpProtocol
    admission: AdmissionGate
    principal_admission: PrincipalAdmission
    request_counter: Counter


class NplgFastAPI(FastAPI):
    """FastAPI application with typed access to NPLG runtime state."""

    config: AppConfig | None = None
    services: AppServices | None = None


@runtime_checkable
class _HeaderList(Protocol):
    def getlist(self, name: str) -> list[str]: ...


class _AssetStore(Protocol):
    """Narrow asset/readiness store surface used by the HTTP application."""

    def resolve_asset(self, relative_path: str) -> Path:
        """Resolve one validated relative asset path."""
        ...

    def stage(
        self,
        *,
        suffix: str = ".tmp",
    ) -> AbstractContextManager[object, bool | None]:
        """Create one bounded readiness staging file."""
        ...


@runtime_checkable
class _ReadinessSurface(Protocol):
    """Optional runtime readiness hook for stateful tool dependencies."""

    def ensure_ready(self) -> None:
        """Raise a sanitized application error when traffic is unsafe."""
        ...


class _FullRuntimeModule(Protocol):
    """Lazily imported full-profile composition boundary."""

    def build_full_services(
        self,
        *,
        config: AppConfig,
        repository: NplgRepository,
        client: HttpClientProtocol,
        limiter: AsyncRateLimiter,
    ) -> tuple[ToolSurface, _AssetStore]:
        """Construct private-full-only storage, download, and PDF services."""
        ...


def _full_runtime_module() -> _FullRuntimeModule:
    module = importlib.import_module("nplg_mcp.full_runtime")
    return cast("_FullRuntimeModule", module)


def _ensure_runtime_ready(runtime: AppServices) -> None:
    """Check storage and optional stateful dependencies without network I/O."""
    if runtime.store is not None:
        with runtime.store.stage(suffix=".ready"):
            pass
    if isinstance(runtime.tools, _ReadinessSurface):
        runtime.tools.ensure_ready()


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


@dataclass(frozen=True, slots=True)
class _AssetStreamTimeouts:
    idle_seconds: float
    total_seconds: float


class _DisconnectAwareFileResponse(FileResponse):
    """Bound file delivery by disconnect, per-send, and total deadlines."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        headers: Mapping[str, str],
        media_type: str,
        timeouts: _AssetStreamTimeouts,
    ) -> None:
        super().__init__(
            path,
            headers=headers,
            media_type=media_type,
        )
        self._timeouts = timeouts

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
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._timeouts.total_seconds

        async def bounded_send(message: Message) -> None:
            remaining = deadline - loop.time()
            timeout = max(0.0, min(self._timeouts.idle_seconds, remaining))
            async with asyncio.timeout(timeout):
                await send(message)

        async def stream_file() -> None:
            try:
                async with asyncio.timeout_at(deadline):
                    await super(_DisconnectAwareFileResponse, self).__call__(
                        scope,
                        receive,
                        cast("Send", bounded_send),
                    )
            except TimeoutError:
                return

        stream = asyncio.create_task(stream_file())
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


def _api_principal(request: Request, config: AppConfig) -> str | None:
    bearer_values = request.headers.getlist("authorization")
    api_key_values = request.headers.getlist("x-api-key")
    if len(bearer_values) + len(api_key_values) != 1:
        return None
    presented = bearer_values[0] if bearer_values else api_key_values[0]
    matched_principal: str | None = None
    for principal in config.api_principals:
        secret = (
            principal.bearer_value() if bearer_values else principal.api_key_value()
        )
        expected = (
            f"Bearer {secret}" if bearer_values and secret is not None else secret or ""
        )
        if secret is not None and hmac.compare_digest(
            presented.encode("utf-8"), expected.encode("utf-8")
        ):
            matched_principal = principal.principal_id
    if bearer_values and config.api_bearer_token is not None:
        expected = f"Bearer {config.api_bearer_token}"
        if hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
            matched_principal = "legacy-bearer"
    if (
        api_key_values
        and config.api_key is not None
        and hmac.compare_digest(
            presented.encode("utf-8"),
            config.api_key.encode("utf-8"),
        )
    ):
        matched_principal = "legacy-api-key"
    return matched_principal


def _has_valid_api_credential(request: Request, config: AppConfig) -> bool:
    return _api_principal(request, config) is not None


def _configured_principal_ids(config: AppConfig) -> tuple[str, ...]:
    identifiers = [principal.principal_id for principal in config.api_principals]
    if config.api_bearer_token is not None:
        identifiers.append("legacy-bearer")
    if config.api_key is not None:
        identifiers.append("legacy-api-key")
    if config.allow_anonymous:
        identifiers.append("anonymous")
    return tuple(identifiers)


def _runtime_services(config: AppConfig) -> AppServices:
    profile = validate_deployment_profile(config.deployment_profile)
    if profile == "distributed-full":
        msg = "distributed-full is not implemented and must remain disabled"
        raise ValueError(msg)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(config.upstream_timeout_seconds),
        follow_redirects=False,
        trust_env=False,
        limits=limits,
        transport=create_bound_http_transport(limits=limits),
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
    if profile == "alpic-metadata":
        tools = ToolService(
            dependencies=ToolServiceDependencies(repository=repository),
            config=config,
        )
        return AppServices(tools=tools, store=None, http_client=client)

    full_tools, store = _full_runtime_module().build_full_services(
        config=config,
        repository=repository,
        client=client,
        limiter=limiter,
    )
    return AppServices(tools=full_tools, store=store, http_client=client)


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


def _require_api_authentication(request: Request, config: AppConfig) -> str:
    principal_id = _api_principal(request, config)
    if principal_id is not None:
        return principal_id
    credential_count = len(request.headers.getlist("authorization")) + len(
        request.headers.getlist("x-api-key")
    )
    if config.allow_anonymous and credential_count == 0:
        return "anonymous"
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
    boundary: _McpBoundary,
    *,
    principal_id: str,
) -> Response:
    method_label = "unknown"
    try:
        raw = await _receive_request_body(request, boundary.config)
        try:
            payload = boundary.protocol.parse_json(raw)
        except ProtocolFailure as failure:
            response = McpProtocol.error_response(None, failure)
            _record_request(
                boundary.request_counter,
                method=method_label,
                outcome="error",
            )
            return _protocol_http_response(response)

        raw_method = payload.get("method")
        method_label = _metric_method_label(
            raw_method if isinstance(raw_method, str) else None
        )
        response = await boundary.protocol.handle(payload, request.headers)
        _record_request(
            boundary.request_counter,
            method=method_label,
            outcome=_metric_outcome(response.status, response.payload),
        )
        return _protocol_http_response(response)
    except AppError as exc:
        _record_request(
            boundary.request_counter,
            method=method_label,
            outcome="error",
        )
        return _json_response(
            status_code=exc.http_status,
            content={"error": to_public_error(exc)},
        )
    finally:
        boundary.admission.release()
        boundary.principal_admission.release(principal_id)


async def _mcp_response(
    request: Request,
    boundary: _McpBoundary,
) -> Response:
    method_label = "unknown"
    try:
        _require_public_host(request, boundary.config)
        _require_allowed_origin(request, boundary.config)
        principal_id = _require_api_authentication(request, boundary.config)
        _require_json_content_type(request)
        if not boundary.principal_admission.try_acquire(principal_id):
            return _busy_response(boundary.request_counter, method_label)
        if not boundary.admission.try_acquire():
            boundary.principal_admission.release(principal_id)
            return _busy_response(boundary.request_counter, method_label)
    except AppError as exc:
        _record_request(
            boundary.request_counter,
            method=method_label,
            outcome="error",
        )
        return _json_response(
            status_code=exc.http_status,
            content={"error": to_public_error(exc)},
        )
    return await _admitted_mcp_response(
        request,
        boundary,
        principal_id=principal_id,
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
    credentials_missing = (
        not config.api_principals
        and config.api_bearer_token is None
        and config.api_key is None
    )
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
    grant = verify_asset_token(
        config.asset_signing_secret,
        token,
        max_ttl_seconds=config.asset_ttl_seconds,
    )
    store = services.store
    if store is None:
        raise AppError(
            ErrorCode.NOT_FOUND,
            "The requested asset was not found.",
            http_status=404,
        )
    path = store.resolve_asset(grant.path)
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
        timeouts=_AssetStreamTimeouts(
            idle_seconds=config.asset_stream_idle_timeout_seconds,
            total_seconds=config.asset_stream_total_timeout_seconds,
        ),
    )


def _validate_startup_config(config: AppConfig) -> None:
    """Reject unsafe or unavailable profiles before constructing services."""
    profile = validate_deployment_profile(config.deployment_profile)
    if config.environment == "production" and config.allow_anonymous:
        msg = "anonymous authorization is forbidden in production"
        raise ValueError(msg)
    if config.environment == "production" and not config.api_principals:
        msg = "production requires a named API principal registry"
        raise ValueError(msg)
    if (
        config.environment == "production"
        and config.max_concurrent_mcp_requests_per_principal
        >= config.max_concurrent_mcp_requests
    ):
        msg = "production per-principal admission must reserve global capacity"
        raise ValueError(msg)
    if profile == "distributed-full":
        msg = "distributed-full is not implemented and must remain disabled"
        raise ValueError(msg)
    if config.environment == "production" and profile == "private-full":
        msg = "private-full production requires an OS-isolated PDF worker backend"
        raise ValueError(msg)
    if config.asset_stream_idle_timeout_seconds <= 0:
        msg = "asset stream idle timeout must be positive"
        raise ValueError(msg)
    if (
        config.asset_stream_total_timeout_seconds
        < config.asset_stream_idle_timeout_seconds
    ):
        msg = "asset stream total timeout must cover the idle timeout"
        raise ValueError(msg)


def create_app(
    config: AppConfig | None = None, *, services: AppServices | None = None
) -> NplgFastAPI:
    """Create one configured FastAPI application and its bounded routes."""
    cfg = config or load_config(os.environ)
    _validate_startup_config(cfg)
    runtime = services or _runtime_services(cfg)
    protocol = McpProtocol(runtime.tools)
    admission = AdmissionGate(cfg.max_concurrent_mcp_requests)
    principal_admission = PrincipalAdmission(
        _configured_principal_ids(cfg),
        cfg.max_concurrent_mcp_requests_per_principal,
    )
    registry = CollectorRegistry(auto_describe=True)
    request_counter = Counter(
        "nplg_mcp_requests_total",
        "MCP HTTP requests by method and outcome.",
        labelnames=("method", "outcome"),
        registry=registry,
    )
    mcp_boundary = _McpBoundary(
        config=cfg,
        protocol=protocol,
        admission=admission,
        principal_admission=principal_admission,
        request_counter=request_counter,
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
        try:
            await STORAGE_WORK.run_to_completion(
                partial(_ensure_runtime_ready, runtime)
            )
        except BlockingWorkCapacityError as exc:
            raise AppError(
                ErrorCode.RATE_LIMITED,
                "The readiness storage check is at capacity.",
                http_status=503,
            ) from exc
        return {"status": "ready"}

    async def metrics(request: Request) -> Response:
        return _metrics_response(request, config=cfg, registry=registry)

    async def mcp_endpoint(request: Request) -> Response:
        return await _mcp_response(request, mcp_boundary)

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
