# Copyright (c) 2026 David Osipov
"""Project-owned HTTP admission around the official MCP SDK ASGI app."""

# Starlette's ASGI Scope/Message aliases intentionally expose vendor-owned Any.
# All crossings stay in this one transport adapter and are explicitly cast.

from __future__ import annotations

import asyncio
import hmac
from contextlib import suppress
from typing import TYPE_CHECKING, Protocol, cast

from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse as StarletteJSONResponse

from .admission import AdmissionGate, PrincipalAdmission
from .errors import AppError, ErrorCode, to_public_error
from .json_preflight import JsonPreflightError, JsonPreflightLimits, preflight_json
from .resource_admission import InlineResourceAdmission

if TYPE_CHECKING:
    from collections.abc import Mapping

    from starlette.background import BackgroundTask
    from starlette.responses import Response
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from .config import AppConfig
    from .json_types import JsonObject

_RESPONSE_POLICY = (
    (
        b"content-security-policy",
        (
            b"default-src 'none'; base-uri 'none'; object-src 'none'; "
            b"frame-ancestors 'none'"
        ),
    ),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store, no-transform"),
)
_POLICY_NAMES = frozenset(name for name, _ in _RESPONSE_POLICY)
_HANDSHAKE_VERSIONS = frozenset({b"2025-03-26", b"2025-06-18", b"2025-11-25"})
_SAFE_VERSION_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~"
)
_MAX_APPLICATION_DEADLINE_SECONDS = 20.0
_MAX_VERSION_BYTES = 32


class _TypedReceive(Protocol):
    async def __call__(self) -> Mapping[str, object]:
        """Return one ASGI event through a typed project-owned view."""
        ...


class _JSONResponse(StarletteJSONResponse):
    """Narrow Starlette's untyped JSON content constructor to project JSON."""

    def __init__(
        self,
        content: JsonObject,
        status_code: int = 200,
        headers: Mapping[str, str] | None = None,
        media_type: str | None = None,
        background: BackgroundTask | None = None,
    ) -> None:
        super().__init__(content, status_code, headers, media_type, background)


def build_transport_security_settings(
    config: AppConfig,
) -> TransportSecuritySettings:
    """Build the SDK policy from the exact immutable project allowlists."""
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(config.mcp_allowed_hosts),
        allowed_origins=list(config.mcp_allowed_origins),
    )


class McpSecurityMiddleware:
    """Enforce project HTTP admission and canonical response policy."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: AppConfig,
        resource_admission: InlineResourceAdmission | None = None,
    ) -> None:
        """Bind immutable limits and zero-waiter gates to the SDK application."""
        super().__init__()
        if not (
            0
            < config.mcp_application_deadline_seconds
            <= _MAX_APPLICATION_DEADLINE_SECONDS
        ):
            msg = "MCP application deadline must be in the interval (0, 20] seconds"
            raise ValueError(msg)
        self._app = app
        self._config = config
        self._resource_admission = resource_admission or InlineResourceAdmission()
        self._accepting_requests = False
        self._active_requests: set[asyncio.Task[object]] = set()
        self._admission = AdmissionGate(config.max_concurrent_mcp_requests)
        principal_ids = [principal.principal_id for principal in config.api_principals]
        if config.api_bearer_token is not None:
            principal_ids.append("legacy-bearer")
        if config.api_key is not None:
            principal_ids.append("legacy-api-key")
        self._principal_admission = (
            PrincipalAdmission(
                principal_ids,
                config.max_concurrent_mcp_requests_per_principal,
            )
            if principal_ids
            else None
        )

    def start(self) -> None:
        """Open MCP admission only after the SDK manager has started."""
        self._accepting_requests = True

    async def shutdown(self) -> None:
        """Reject new MCP traffic and cancel/drain every active outer request."""
        self._accepting_requests = False
        current = cast("asyncio.Task[object] | None", asyncio.current_task())
        active = tuple(
            task
            for task in self._active_requests
            if task is not current and not task.done()
        )
        for task in active:
            _ = task.cancel()
        if active:
            done, _ = await asyncio.wait(active)
            for task in done:
                with suppress(asyncio.CancelledError):
                    _ = task.exception()

    async def _bounded_body(self, receive: Receive) -> bytes:
        typed_receive = cast("_TypedReceive", receive)
        body = bytearray()
        more_body = True
        while more_body:
            message = await typed_receive()
            message_type = message.get("type")
            if message_type == "http.disconnect":
                raise TimeoutError
            if message_type != "http.request":
                continue
            chunk = cast("bytes", message.get("body", b""))
            if len(body) + len(chunk) > self._config.mcp_max_body_bytes:
                raise OverflowError
            body.extend(chunk)
            more_body = bool(message.get("more_body", False))
        return bytes(body)

    @staticmethod
    async def _send_with_policy(raw_message: Message, send: Send) -> None:
        """Replace downstream security metadata with one canonical header set."""
        message = cast("dict[str, object]", raw_message)
        if message.get("type") != "http.response.start":
            await send(raw_message)
            return
        raw_headers = cast("list[tuple[bytes, bytes]]", message.get("headers", []))
        is_sse = any(
            name.lower() == b"content-type"
            and value.lower().startswith(b"text/event-stream")
            for name, value in raw_headers
        )
        headers = [
            (name, value)
            for name, value in raw_headers
            if name.lower() not in _POLICY_NAMES
            and not name.lower().startswith(b"access-control-")
            and name.lower() != b"x-accel-buffering"
        ]
        headers.extend(_RESPONSE_POLICY)
        if is_sse:
            headers.append((b"x-accel-buffering", b"no"))
        message["headers"] = headers
        await send(cast("Message", message))

    async def _send_response(
        self,
        response: Response,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Apply the same immutable policy to one project-owned response."""

        async def policy_send(message: Message) -> None:
            await self._send_with_policy(message, send)

        await response(scope, receive, policy_send)

    def _authenticated_principal(
        self,
        headers: list[tuple[bytes, bytes]],
    ) -> str | None:
        authorization = [
            value for name, value in headers if name.lower() == b"authorization"
        ]
        api_keys = [value for name, value in headers if name.lower() == b"x-api-key"]
        if not authorization and not api_keys:
            return "anonymous" if self._config.allow_anonymous else None
        if len(authorization) + len(api_keys) != 1:
            return None
        presented = authorization[0] if authorization else api_keys[0]
        matched: str | None = None
        for principal in self._config.api_principals:
            secret = (
                principal.bearer_value() if authorization else principal.api_key_value()
            )
            expected = (
                f"Bearer {secret}".encode()
                if authorization and secret is not None
                else (secret or "").encode()
            )
            if secret is not None and hmac.compare_digest(presented, expected):
                matched = principal.principal_id
        legacy = (
            self._config.api_bearer_token if authorization else self._config.api_key
        )
        if legacy is not None:
            expected = f"Bearer {legacy}".encode() if authorization else legacy.encode()
            if hmac.compare_digest(presented, expected):
                matched = "legacy-bearer" if authorization else "legacy-api-key"
        return matched

    def _try_acquire_admission(
        self,
        principal_id: str,
    ) -> tuple[bool, PrincipalAdmission | None]:
        """Acquire global capacity and, only for a stable identity, its fair share."""
        if principal_id == "anonymous":
            return self._admission.try_acquire(), None
        principal_admission = self._principal_admission
        if principal_admission is None or not principal_admission.try_acquire(
            principal_id
        ):
            return False, None
        if self._admission.try_acquire():
            return True, principal_admission
        principal_admission.release(principal_id)
        return False, None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Apply authenticated admission before the bounded security pipeline."""
        scope_values = cast("Mapping[str, object]", scope)
        if scope_values.get("type") != "http" or scope_values.get("path") != "/mcp":
            await self._security_call(scope, receive, send)
            return
        if not self._accepting_requests:
            response = _JSONResponse(
                {"error": "MCP service is not running"},
                status_code=503,
            )
            await self._send_response(response, scope, receive, send)
            return
        request_task = cast("asyncio.Task[object]", asyncio.current_task())
        self._active_requests.add(request_task)
        try:
            await self._admitted_call(scope, receive, send, scope_values)
        finally:
            self._active_requests.discard(request_task)

    async def _admitted_call(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        scope_values: Mapping[str, object],
    ) -> None:
        """Apply principal/global limits and the application deadline."""
        headers = cast("list[tuple[bytes, bytes]]", scope_values.get("headers", []))
        principal_id = self._authenticated_principal(headers)
        if principal_id is None:
            await self._security_call(scope, receive, send)
            return

        globally_acquired, principal_admission = self._try_acquire_admission(
            principal_id
        )
        if not globally_acquired:
            busy = AppError(
                ErrorCode.RATE_LIMITED,
                "The MCP server is at its concurrent request limit.",
                http_status=503,
            )
            response = _JSONResponse(
                {"error": to_public_error(busy)},
                status_code=503,
                headers={"Retry-After": "1"},
            )
            await self._send_response(response, scope, receive, send)
            return
        response_started = False
        response_complete = False

        async def tracked_send(message: Message) -> None:
            nonlocal response_complete, response_started
            message_values = cast("Mapping[str, object]", message)
            message_type = message_values.get("type")
            if message_type == "http.response.start":
                response_started = True
            elif message_type == "http.response.body" and not message_values.get(
                "more_body", False
            ):
                response_complete = True
            await send(message)

        try:
            with self._resource_admission.request_scope():
                try:
                    async with asyncio.timeout(
                        self._config.mcp_application_deadline_seconds
                    ):
                        await self._security_call(scope, receive, tracked_send)
                except TimeoutError:
                    if response_started:
                        if not response_complete:
                            closing_body: dict[str, object] = {
                                "type": "http.response.body",
                                "body": b"",
                                "more_body": False,
                            }
                            await send(cast("Message", closing_body))
                        return
                    timed_out = AppError(
                        ErrorCode.REQUEST_TIMEOUT,
                        "The MCP request exceeded its application deadline.",
                        http_status=504,
                    )
                    response = _JSONResponse(
                        {"error": to_public_error(timed_out)},
                        status_code=504,
                    )
                    await self._send_response(response, scope, receive, send)
        finally:
            self._admission.release()
            if principal_admission is not None:
                principal_admission.release(principal_id)

    async def _security_call(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        async def policy_send(raw_message: Message) -> None:
            await self._send_with_policy(raw_message, send)

        scope_values = cast("Mapping[str, object]", scope)
        if scope_values.get("type") == "http" and scope_values.get("path") == "/mcp":
            headers = cast("list[tuple[bytes, bytes]]", scope_values.get("headers", []))
            host_values = [value for name, value in headers if name.lower() == b"host"]
            origin_values = [
                value for name, value in headers if name.lower() == b"origin"
            ]
            allowed_hosts = {
                value.encode("ascii") for value in self._config.mcp_allowed_hosts
            }
            allowed_origins = {
                value.encode("ascii") for value in self._config.mcp_allowed_origins
            }
            invalid_authority = (
                len(host_values) != 1
                or host_values[0] not in allowed_hosts
                or len(origin_values) > 1
                or bool(origin_values and origin_values[0] not in allowed_origins)
            )
            if invalid_authority:
                response = _JSONResponse(
                    {"error": "Host or Origin is not allowed"},
                    status_code=403,
                )
                await response(scope, receive, policy_send)
                return
            content_encodings = [
                value for name, value in headers if name.lower() == b"content-encoding"
            ]
            if len(content_encodings) > 1 or (
                content_encodings and content_encodings[0] != b"identity"
            ):
                response = _JSONResponse(
                    {"error": "Unsupported content encoding"},
                    status_code=415,
                )
                await response(scope, receive, policy_send)
                return
            if self._authenticated_principal(headers) is None:
                response = _JSONResponse(
                    {"error": "API authentication is required"},
                    status_code=401,
                )
                await response(scope, receive, policy_send)
                return
            method = cast("str", scope_values.get("method", ""))
            if method != "POST":
                response = _JSONResponse(
                    {"error": "Method not allowed"},
                    status_code=405,
                    headers={"Allow": "POST"},
                )
                await response(scope, receive, policy_send)
                return
            versions = [
                value
                for name, value in headers
                if name.lower() == b"mcp-protocol-version"
            ]
            unsafe_version = (
                len(versions) != 1
                or not 1 <= len(versions[0]) <= _MAX_VERSION_BYTES
                or any(byte not in _SAFE_VERSION_BYTES for byte in versions[0])
                or versions[0] in _HANDSHAKE_VERSIONS
            )
            if unsafe_version:
                response = _JSONResponse(
                    {"error": "Invalid MCP protocol version"},
                    status_code=400,
                )
                await response(scope, receive, policy_send)
                return

            singleton_names = (
                b"content-type",
                b"content-length",
                b"transfer-encoding",
                b"mcp-method",
                b"mcp-name",
            )
            values_by_name = {
                singleton: [
                    value for name, value in headers if name.lower() == singleton
                ]
                for singleton in singleton_names
            }
            if any(len(values) > 1 for values in values_by_name.values()):
                response = _JSONResponse(
                    {"error": "Ambiguous request headers"},
                    status_code=400,
                )
                await response(scope, receive, policy_send)
                return
            content_types = values_by_name[b"content-type"]
            if (
                len(content_types) != 1
                or content_types[0].split(b";", 1)[0].strip().lower()
                != b"application/json"
            ):
                response = _JSONResponse(
                    {"error": "Content-Type must be application/json"},
                    status_code=415,
                )
                await response(scope, receive, policy_send)
                return
            declared_values = values_by_name[b"content-length"]
            transfer_values = values_by_name[b"transfer-encoding"]
            if declared_values and transfer_values:
                response = _JSONResponse(
                    {"error": "Ambiguous request framing"},
                    status_code=400,
                )
                await response(scope, receive, policy_send)
                return
            declared: int | None = None
            if declared_values:
                try:
                    declared_text = declared_values[0].decode("ascii")
                except UnicodeDecodeError:
                    response = _JSONResponse(
                        {"error": "Invalid Content-Length"},
                        status_code=400,
                    )
                    await response(scope, receive, policy_send)
                    return
                if not declared_text.isdecimal():
                    response = _JSONResponse(
                        {"error": "Invalid Content-Length"},
                        status_code=400,
                    )
                    await response(scope, receive, policy_send)
                    return
                declared = int(declared_text)
                if declared > self._config.mcp_max_body_bytes:
                    response = _JSONResponse(
                        {"error": "Request body is too large"},
                        status_code=413,
                    )
                    await response(scope, receive, policy_send)
                    return
            try:
                async with asyncio.timeout(self._config.request_body_timeout_seconds):
                    body = await self._bounded_body(receive)
            except TimeoutError:
                body_timeout = AppError(
                    ErrorCode.REQUEST_TIMEOUT,
                    "The request body was not received within the allowed time.",
                    http_status=408,
                )
                response = _JSONResponse(
                    {"error": to_public_error(body_timeout)},
                    status_code=408,
                )
                await response(scope, receive, policy_send)
                return
            except OverflowError:
                response = _JSONResponse(
                    {"error": "Request body is too large"},
                    status_code=413,
                )
                await response(scope, receive, policy_send)
                return
            if declared is not None and declared != len(body):
                response = _JSONResponse(
                    {"error": "Invalid Content-Length"},
                    status_code=400,
                )
                await response(scope, receive, policy_send)
                return
            try:
                preflight_json(
                    body,
                    limits=JsonPreflightLimits(
                        max_body_bytes=self._config.mcp_max_body_bytes
                    ),
                )
            except JsonPreflightError:
                response = _JSONResponse(
                    {"error": "Invalid JSON request body"},
                    status_code=400,
                )
                await response(scope, receive, policy_send)
                return

            replayed = False

            async def replay_receive() -> Message:
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {
                        "type": "http.request",
                        "body": body,
                        "more_body": False,
                    }
                return await receive()

            await self._app(scope, replay_receive, policy_send)
            return

        await self._app(scope, receive, policy_send)
