from __future__ import annotations

from threading import Lock

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .errors import AppError, ErrorCode, to_public_error


class AdmissionGate:
    """A process-local, zero-waiter concurrency gate."""

    def __init__(self, capacity: int) -> None:
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity <= 0:
            raise ValueError("admission capacity must be a positive integer")
        self._capacity = capacity
        self._active = 0
        self._lock = Lock()

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    def try_acquire(self) -> bool:
        with self._lock:
            if self._active >= self._capacity:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active <= 0:
                raise RuntimeError("admission gate release is unbalanced")
            self._active -= 1


class PathAdmissionMiddleware:
    """Fail-fast admission held across the complete ASGI response lifecycle."""

    def __init__(self, app: ASGIApp, *, capacity: int, path_prefix: str) -> None:
        self.app = app
        self.gate = AdmissionGate(capacity)
        self.path_prefix = path_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not str(scope.get("path", "")).startswith(self.path_prefix):
            await self.app(scope, receive, send)
            return
        if not self.gate.try_acquire():
            busy = AppError(
                ErrorCode.RATE_LIMITED,
                "The server is at its concurrent asset-stream limit.",
                http_status=503,
            )
            response = JSONResponse(
                status_code=503,
                content={"error": to_public_error(busy)},
                headers={"Retry-After": "1"},
            )
            await response(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            self.gate.release()
