# Copyright (c) 2026 David Osipov
"""Admission controls for the HTTP boundary."""

from __future__ import annotations

from threading import Lock
from typing import TYPE_CHECKING

from starlette.responses import JSONResponse

from .errors import AppError, ErrorCode, to_public_error

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


class AdmissionGate:
    """A process-local, zero-waiter concurrency gate."""

    def __init__(self, capacity: int) -> None:
        """Create a gate with a fixed positive capacity."""
        super().__init__()
        if type(capacity) is not int or capacity <= 0:
            msg = "admission capacity must be a positive integer"
            raise ValueError(msg)
        self._capacity = capacity
        self._active = 0
        self._lock = Lock()

    @property
    def active(self) -> int:
        """Return the number of permits currently held."""
        with self._lock:
            return self._active

    def try_acquire(self) -> bool:
        """Acquire immediately when capacity is available."""
        with self._lock:
            if self._active >= self._capacity:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        """Release one previously acquired permit."""
        with self._lock:
            if self._active <= 0:
                msg = "admission gate release is unbalanced"
                raise RuntimeError(msg)
            self._active -= 1


class PathAdmissionMiddleware:
    """Fail-fast admission held across the complete ASGI response lifecycle."""

    def __init__(self, app: ASGIApp, *, capacity: int, path_prefix: str) -> None:
        """Wrap an ASGI application with path-scoped admission control."""
        super().__init__()
        self.app = app
        self.gate = AdmissionGate(capacity)
        self.path_prefix = path_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Admit a matching HTTP request for its complete response lifecycle."""
        raw_path: object = scope.get("path", "")
        path = raw_path if isinstance(raw_path, str) else ""
        scope_type: object = scope.get("type", "")
        if scope_type != "http" or not path.startswith(self.path_prefix):
            await self.app(scope, receive, send)
            return
        if not self.gate.try_acquire():
            busy = AppError(
                ErrorCode.RATE_LIMITED,
                "The server is at its concurrent asset-stream limit.",
                http_status=503,
            )
            content: dict[str, object] = {"error": to_public_error(busy)}
            response = JSONResponse(
                status_code=503,
                content=content,
                headers={"Retry-After": "1"},
            )
            await response(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            self.gate.release()
