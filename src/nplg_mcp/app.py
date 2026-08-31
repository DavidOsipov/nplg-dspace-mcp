# Copyright (c) 2026 David Osipov
"""FastAPI application assembly and HTTP security middleware."""

from __future__ import annotations

import asyncio
import hmac
import importlib
import logging
import os
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from functools import partial
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Never, Protocol, cast, override, runtime_checkable
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from prometheus_client import CollectorRegistry, generate_latest

from .admission import PathAdmissionMiddleware
from .bounded_work import READINESS_WORK, BlockingWorkCapacityError
from .capabilities import (
    AlpicTasksCapabilityVerdict,
    CapabilityContractError,
    OAuthProviderCapabilityVerdict,
    probe_alpic_tasks_capability,
    probe_oauth_provider,
)
from .config import (
    AppConfig,
    canonicalize_alpic_gateway_host,
    load_config,
    validate_deployment_profile,
)
from .errors import AppError, ErrorCode, to_public_error
from .http_security import McpSecurityMiddleware, build_transport_security_settings
from .mcp_server import create_mcp_server
from .network import create_bound_http_transport
from .profiles import DeploymentProfile as SdkDeploymentProfile
from .rate_limit import AsyncRateLimiter
from .repository import NplgRepository
from .resilience import UpstreamGuard, UpstreamGuardPolicy
from .resource_admission import InlineResourceAdmission
from .security import OutboundPurpose, build_outbound_headers
from .services import (
    AppServices,
    FullServiceComposition,
    MetadataServiceComposition,
    validate_service_composition,
)
from .tokens import verify_asset_token
from .tools import ToolService, ToolServiceDependencies

_UPSTREAM_LOGGER = logging.getLogger("nplg_mcp.upstream")
_UPSTREAM_TRANSITIONS = {
    ("closed", "open"): "closed_to_open",
    ("open", "half_open"): "open_to_half_open",
    ("half_open", "closed"): "half_open_to_closed",
    ("half_open", "open"): "half_open_to_open",
}

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
    from contextlib import AbstractAsyncContextManager, AbstractContextManager
    from pathlib import Path
    from urllib.request import Request as UrlRequest

    from mcp.server import Server
    from starlette.types import Message, Receive, Scope, Send

    from .http_types import HttpClientProtocol
    from .json_types import JsonObject


class _NoneContextStack(Protocol):
    async def enter_async_context(
        self,
        context: AbstractAsyncContextManager[None],
    ) -> None:
        """Enter and register one context that yields no runtime value."""


async def _enter_owned_context(
    stack: AsyncExitStack,
    context: AbstractAsyncContextManager[None],
) -> None:
    """Enter one typed owned context despite contextlib's broad implementation."""
    typed_stack = cast("_NoneContextStack", stack)
    await typed_stack.enter_async_context(context)


class NplgFastAPI(FastAPI):
    """FastAPI application with typed access to NPLG runtime state."""

    config: AppConfig | None = None
    services: AppServices | None = None
    mcp_server: Server[None] | None = None


@runtime_checkable
class _HeaderList(Protocol):
    def getlist(self, name: str) -> list[str]: ...


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
    ) -> FullServiceComposition:
        """Construct private-full-only storage, download, and PDF services."""
        ...


def _full_runtime_module() -> _FullRuntimeModule:
    module = importlib.import_module("nplg_mcp.full_runtime")
    return cast("_FullRuntimeModule", module)


def _ensure_runtime_ready(runtime: AppServices) -> None:
    """Read stateful dependency health without mutating persistent storage."""
    if isinstance(runtime, FullServiceComposition):
        runtime.store.ensure_ready()
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
        relative_path: str,
        *,
        headers: Mapping[str, str],
        lease: AbstractContextManager[Path],
        media_type: str,
        timeouts: _AssetStreamTimeouts,
    ) -> None:
        super().__init__(
            relative_path,
            headers=headers,
            media_type=media_type,
        )
        self._lease = lease
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
        with self._lease as path:
            self.path = path
            await self._stream_leased_file(scope, receive, send)

    async def _stream_leased_file(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
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


def _observe_upstream_transition(before: str, after: str) -> None:
    transition = _UPSTREAM_TRANSITIONS.get((before, after))
    if transition is None:
        return
    _UPSTREAM_LOGGER.info(
        "nplg_upstream_circuit_transition",
        extra={
            "upstream_state": after,
            "upstream_transition": transition,
        },
    )


def _reject_distributed_full(verdict: AlpicTasksCapabilityVerdict) -> Never:
    """Consume the typed verdict without treating support as implementation."""
    if verdict.supported is False:
        msg = "distributed-full is disabled: Alpic Tasks capability is unsupported"
        raise ValueError(msg)
    msg = "distributed-full requires a separately approved implementation plan"
    raise ValueError(msg)


def _reject_unavailable_production_oauth(
    verdict: OAuthProviderCapabilityVerdict,
) -> Never:
    """Revalidate capability evidence and keep unimplemented auth unreachable."""
    try:
        validated = OAuthProviderCapabilityVerdict.model_validate_json(
            verdict.model_dump_json()
        )
    except (AttributeError, TypeError, ValueError) as exc:
        msg = "production OAuth provider capability assessment failed closed"
        raise ValueError(msg) from exc
    if validated.supported is False:
        msg = "production OAuth provider capability is unsupported"
        raise ValueError(msg)
    msg = "production OAuth requires a separately approved implementation"
    raise ValueError(msg)


def _validate_production_auth_activation(config: AppConfig) -> None:
    """Stop production before dependency construction until OAuth is implemented."""
    if config.environment != "production":
        return
    if config.deployment_profile == "alpic-metadata" and config.allow_anonymous:
        return
    try:
        verdict = probe_oauth_provider()
    except CapabilityContractError as exc:
        msg = "production OAuth provider capability assessment failed closed"
        raise ValueError(msg) from exc
    _reject_unavailable_production_oauth(verdict)


def _runtime_services(config: AppConfig) -> AppServices:
    profile = validate_deployment_profile(config.deployment_profile)
    if profile == "distributed-full":
        try:
            verdict = probe_alpic_tasks_capability()
        except CapabilityContractError as exc:
            msg = "distributed-full capability assessment failed closed"
            raise ValueError(msg) from exc
        _reject_distributed_full(verdict)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(config.upstream_timeout_seconds),
        follow_redirects=False,
        trust_env=False,
        limits=limits,
        transport=create_bound_http_transport(limits=limits),
        headers=build_outbound_headers(OutboundPurpose.METADATA),
        cookies=CookieJar(policy=_RejectAllCookiesPolicy()),
    )
    client = cast("HttpClientProtocol", http_client)
    limiter = AsyncRateLimiter(config.upstream_rate_per_second)
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(
            capacity=2,
            failure_threshold=3,
            base_open_seconds=1.0,
            max_open_seconds=30.0,
            max_attempt_seconds=min(15.0, config.upstream_timeout_seconds),
            jitter_ratio=0.2,
        ),
        transition_observer=_observe_upstream_transition,
    )
    repository = NplgRepository(
        client=client,
        max_redirects=config.max_redirects,
        limiter=limiter,
        total_timeout_seconds=float(config.upstream_timeout_seconds),
        guard=guard,
        cursor_signing_secret=config.cursor_signing_secret,
    )
    if profile == "alpic-metadata":
        tools = ToolService(
            dependencies=ToolServiceDependencies(repository=repository),
            config=config,
        )
        return MetadataServiceComposition(tools=tools, http_client=client)

    return _full_runtime_module().build_full_services(
        config=config,
        repository=repository,
        client=client,
        limiter=limiter,
    )


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
    try:
        asset_signing_secret = config.require_asset_signing_secret()
    except ValueError:
        raise AppError(
            ErrorCode.NOT_FOUND,
            "The requested asset was not found.",
            http_status=404,
        ) from None
    grant = verify_asset_token(
        asset_signing_secret,
        token,
        max_ttl_seconds=config.asset_ttl_seconds,
    )
    if not isinstance(services, FullServiceComposition):
        raise AppError(
            ErrorCode.NOT_FOUND,
            "The requested asset was not found.",
            http_status=404,
        )
    store = services.store
    filename = PurePosixPath(grant.path).name.replace('"', "")
    headers = {
        "Cache-Control": "private, no-store",
        "Content-Disposition": f'inline; filename="{filename}"',
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cross-Origin-Resource-Policy": "same-site",
        "X-Content-Type-Options": "nosniff",
    }
    return _DisconnectAwareFileResponse(
        grant.path,
        media_type=grant.media_type,
        headers=headers,
        lease=store.lease_asset(grant.path),
        timeouts=_AssetStreamTimeouts(
            idle_seconds=config.asset_stream_idle_timeout_seconds,
            total_seconds=config.asset_stream_total_timeout_seconds,
        ),
    )


def _validate_startup_config(config: AppConfig) -> None:
    """Reject unsafe or unavailable profiles before constructing services."""
    profile = validate_deployment_profile(config.deployment_profile)
    gateway_host_is_valid = False
    if config.alpic_gateway_host is not None:
        try:
            gateway_host_is_valid = (
                canonicalize_alpic_gateway_host(config.alpic_gateway_host)
                == config.alpic_gateway_host
            )
        except ValueError:
            gateway_host_is_valid = False
    if config.mcp_authority_mode == "alpic-gateway" and (
        config.environment != "production"
        or profile != "alpic-metadata"
        or not config.allow_anonymous
        or not gateway_host_is_valid
    ):
        msg = "Alpic gateway authority requires anonymous production alpic-metadata"
        raise ValueError(msg)
    if (
        config.environment == "production"
        and config.allow_anonymous
        and profile != "alpic-metadata"
    ):
        msg = "anonymous production access is limited to alpic-metadata"
        raise ValueError(msg)
    if config.environment == "production" and (
        config.api_bearer_token is not None
        or config.api_key is not None
        or config.api_principals
    ):
        msg = "static authentication configuration is forbidden in production"
        raise ValueError(msg)
    if (
        config.environment == "production"
        and config.max_concurrent_mcp_requests_per_principal
        >= config.max_concurrent_mcp_requests
    ):
        msg = "production per-principal admission must reserve global capacity"
        raise ValueError(msg)
    if (
        config.environment == "production"
        and profile == "private-full"
        and config.pdf_executor != "unix-worker"
    ):
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


def _register_full_profile_asset_route(
    app: NplgFastAPI,
    *,
    config: AppConfig,
    services: AppServices,
    endpoint: Callable[[str, Request], Awaitable[Response]],
) -> None:
    """Expose the legacy asset route only to the full service composition."""
    if not isinstance(services, FullServiceComposition):
        return
    app.add_middleware(
        PathAdmissionMiddleware,
        capacity=config.max_concurrent_asset_streams,
        path_prefix="/assets/",
    )
    app.add_api_route("/assets/{token}", endpoint, methods=["GET"])


def create_app(
    config: AppConfig | None = None, *, services: AppServices | None = None
) -> NplgFastAPI:
    """Create one configured FastAPI application and its bounded routes."""
    cfg = config or load_config(os.environ)
    _validate_startup_config(cfg)
    _validate_production_auth_activation(cfg)
    runtime = services or _runtime_services(cfg)
    validate_service_composition(cfg.deployment_profile, runtime)
    mcp_server = create_mcp_server(
        runtime,
        SdkDeploymentProfile(cfg.deployment_profile),
        resource_admission=(resource_admission := InlineResourceAdmission()),
    )
    sdk_app = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=False,
        max_request_body_size=cfg.mcp_max_body_bytes,
        transport_security=build_transport_security_settings(cfg),
    )
    secured_sdk_app = McpSecurityMiddleware(
        sdk_app,
        config=cfg,
        resource_admission=resource_admission,
    )
    registry = CollectorRegistry(auto_describe=True)

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncGenerator[None, None]:
        async with AsyncExitStack() as stack:
            owned_client = runtime.http_client if services is None else None
            if owned_client is not None:

                @asynccontextmanager
                async def owned_client_context() -> AsyncGenerator[None, None]:
                    try:
                        yield
                    finally:
                        await owned_client.aclose()

                await _enter_owned_context(stack, owned_client_context())
            async with mcp_server.session_manager.run():
                secured_sdk_app.start()
                try:
                    yield
                finally:
                    await secured_sdk_app.shutdown()

    app = NplgFastAPI(
        title="NPLG DSpace MCP",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.config = cfg
    app.services = runtime
    app.mcp_server = mcp_server
    # Preserve the original Starlette state coordinates for integrations that
    # inspect the application through its framework-owned state container.
    app.state.config = cfg
    app.state.services = runtime
    app.state.mcp_server = mcp_server

    async def app_error_handler(_: Request, exc: Exception) -> JSONResponse:
        return _app_error_response(exc)

    async def health() -> dict[str, str]:
        return {"status": "ok"}

    async def ready() -> dict[str, str]:
        try:
            await READINESS_WORK.run_to_completion(
                partial(_ensure_runtime_ready, runtime)
            )
        except BlockingWorkCapacityError as exc:
            raise AppError(
                ErrorCode.RATE_LIMITED,
                "The readiness check is at capacity.",
                http_status=503,
            ) from exc
        return {"status": "ready"}

    async def metrics(request: Request) -> Response:
        return _metrics_response(request, config=cfg, registry=registry)

    async def asset(token: str, request: Request) -> Response:
        return _asset_response(token, request, config=cfg, services=runtime)

    _register_full_profile_asset_route(
        app,
        config=cfg,
        services=runtime,
        endpoint=asset,
    )
    app.add_exception_handler(AppError, app_error_handler)
    app.add_api_route("/healthz", health, methods=["GET"])
    app.add_api_route("/readyz", ready, methods=["GET"])
    app.add_api_route("/metrics", metrics, methods=["GET"])
    app.mount("/", secured_sdk_app)

    return app


def build_default_app() -> NplgFastAPI:
    """Create the default environment-configured application."""
    return create_app()
