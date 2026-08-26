# Copyright (c) 2026 David Osipov
"""Byte-denominated admission for bounded inline MCP resource responses."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
from typing import TYPE_CHECKING

from .config import HARD_MAX_INLINE_RESOURCE_BYTES

_BASE64_CODE_POINTS = ((HARD_MAX_INLINE_RESOURCE_BYTES + 2) // 3) * 4
_MAX_JSON_ESCAPED_BYTES_PER_UTF8_BYTE = 6
_RESPONSE_ENVELOPE_BYTES = 64 * 1024
_MIN_BASE64_CODE_POINTS = 4

if TYPE_CHECKING:
    from collections.abc import Generator

# This reservation covers the larger of the two supported response shapes:
# raw + base64 + serialized base64 for blobs, or UTF-8 text plus its worst-case
# JSON escaping. The envelope allowance covers bounded protocol metadata.
INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES = (
    max(
        HARD_MAX_INLINE_RESOURCE_BYTES + (2 * _BASE64_CODE_POINTS),
        HARD_MAX_INLINE_RESOURCE_BYTES
        + (_MAX_JSON_ESCAPED_BYTES_PER_UTF8_BYTE * HARD_MAX_INLINE_RESOURCE_BYTES),
    )
    + _RESPONSE_ENVELOPE_BYTES
)
INLINE_RESOURCE_AGGREGATE_CAPACITY_BYTES = (
    2 * INLINE_RESOURCE_RESPONSE_RESERVATION_BYTES
)


def inline_text_response_reservation_bytes(utf8_bytes: int) -> int:
    """Return a conservative live-memory weight for validated text content."""
    if (
        type(utf8_bytes) is not int
        or not 0 <= utf8_bytes <= HARD_MAX_INLINE_RESOURCE_BYTES
    ):
        msg = "inline text response size is outside the validated range"
        raise ValueError(msg)
    return _RESPONSE_ENVELOPE_BYTES + (
        (1 + _MAX_JSON_ESCAPED_BYTES_PER_UTF8_BYTE) * utf8_bytes
    )


def inline_blob_response_reservation_bytes(
    *,
    decoded_bytes: int,
    base64_bytes: int,
) -> int:
    """Return a conservative live-memory weight for validated blob content."""
    if (
        type(decoded_bytes) is not int
        or not 1 <= decoded_bytes <= HARD_MAX_INLINE_RESOURCE_BYTES
        or type(base64_bytes) is not int
        or not _MIN_BASE64_CODE_POINTS <= base64_bytes <= _BASE64_CODE_POINTS
    ):
        msg = "inline blob response size is outside the validated range"
        raise ValueError(msg)
    return _RESPONSE_ENVELOPE_BYTES + decoded_bytes + (2 * base64_bytes)


class InlineResourceReservation:
    """One exact byte reservation owned by a single resource operation."""

    __slots__ = (
        "_admission",
        "_released",
        "_request_scoped",
        "_reserved_bytes",
    )

    def __init__(
        self,
        admission: InlineResourceAdmission,
        reserved_bytes: int,
        *,
        request_scoped: bool,
    ) -> None:
        """Bind exact accounting to its owning admission authority."""
        super().__init__()
        self._admission = admission
        self._reserved_bytes = reserved_bytes
        self._released = False
        self._request_scoped = request_scoped

    @property
    def request_scoped(self) -> bool:
        """Return whether the enclosing HTTP request owns final release."""
        return self._request_scoped

    def shrink(self, retained_bytes: int) -> None:
        """Return unused worst-case bytes while retaining response ownership."""
        if self._released:
            msg = "released inline resource reservation cannot be resized"
            raise RuntimeError(msg)
        if (
            type(retained_bytes) is not int
            or retained_bytes <= 0
            or retained_bytes > self._reserved_bytes
        ):
            msg = "inline resource reservation may only shrink to a positive size"
            raise ValueError(msg)
        released_bytes = self._reserved_bytes - retained_bytes
        if released_bytes:
            self._admission.return_reserved_bytes(released_bytes)
            self._reserved_bytes = retained_bytes

    def release(self) -> None:
        """Release this reservation exactly once."""
        if self._released:
            msg = "inline resource reservation release is unbalanced"
            raise RuntimeError(msg)
        self._admission.return_reserved_bytes(self._reserved_bytes)
        self._released = True


class _InlineResourceRequestScope:
    __slots__ = ("reservations",)

    def __init__(self) -> None:
        """Create an empty reservation ledger for one outer request."""
        super().__init__()
        self.reservations: list[InlineResourceReservation] = []


class InlineResourceAdmission:
    """A process-local, zero-waiter aggregate byte budget."""

    def __init__(
        self,
        capacity_bytes: int = INLINE_RESOURCE_AGGREGATE_CAPACITY_BYTES,
    ) -> None:
        """Create an exact positive byte budget."""
        super().__init__()
        if type(capacity_bytes) is not int or capacity_bytes <= 0:
            msg = "inline resource capacity must be a positive integer"
            raise ValueError(msg)
        self._capacity_bytes = capacity_bytes
        self._active_bytes = 0
        self._lock = Lock()
        self._request_scope: ContextVar[_InlineResourceRequestScope | None] = (
            ContextVar(
                f"inline_resource_request_scope_{id(self)}",
                default=None,
            )
        )

    @property
    def active_bytes(self) -> int:
        """Return the exact number of currently reserved bytes."""
        with self._lock:
            return self._active_bytes

    def try_reserve(self, requested_bytes: int) -> InlineResourceReservation | None:
        """Reserve bytes immediately or return ``None`` without queueing."""
        if type(requested_bytes) is not int or requested_bytes <= 0:
            msg = "inline resource reservation must be a positive integer"
            raise ValueError(msg)
        with self._lock:
            if requested_bytes > self._capacity_bytes - self._active_bytes:
                return None
            self._active_bytes += requested_bytes
        request_scope = self._request_scope.get()
        reservation = InlineResourceReservation(
            self,
            requested_bytes,
            request_scoped=request_scope is not None,
        )
        if request_scope is not None:
            request_scope.reservations.append(reservation)
        return reservation

    @contextmanager
    def request_scope(self) -> Generator[None]:
        """Hold reservations until one complete outer response has finished."""
        scope = _InlineResourceRequestScope()
        token = self._request_scope.set(scope)
        try:
            yield
        finally:
            self._request_scope.reset(token)
            for reservation in reversed(scope.reservations):
                reservation.release()

    def return_reserved_bytes(self, reserved_bytes: int) -> None:
        """Return bytes owned by one authority-created reservation."""
        if type(reserved_bytes) is not int or reserved_bytes <= 0:
            msg = "inline resource return must be a positive integer"
            raise ValueError(msg)
        with self._lock:
            if reserved_bytes > self._active_bytes:
                msg = "inline resource admission accounting is unbalanced"
                raise RuntimeError(msg)
            self._active_bytes -= reserved_bytes
