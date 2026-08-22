# Copyright (c) 2026 David Osipov
"""Interfaces and limits for isolated PDF execution."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from .config import (
    HARD_MAX_PAGE_PIXELS,
    HARD_MAX_RENDER_PAGES,
    HARD_MAX_RENDER_PIXELS,
    HARD_MAX_TILE_DIMENSION,
    HARD_MAX_TILE_OVERLAP,
    HARD_MAX_TILES_PER_PAGE,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from .contracts import MonotonicDeadline
    from .pdf_ipc import PdfCommand, PdfResult

_MAX_TERMINATION_GRACE_SECONDS = 5.0
_MAX_CIRCUIT_FAILURE_THRESHOLD = 100
_MAX_CIRCUIT_OPEN_SECONDS = 3_600.0
DEFAULT_FALLBACK_DPI = 400


@dataclass(frozen=True, slots=True)
class PdfResourceLimits:
    """Closed worker resource ceilings applied before hostile input is read."""

    cpu_seconds: int = 30
    address_space_bytes: int = 1_073_741_824
    file_size_bytes: int = 536_870_912
    open_files: int = 64
    processes: int = 8
    stderr_bytes: int = 65_536
    termination_grace_seconds: float = 0.25

    def __post_init__(self) -> None:
        """Reject forged or unusable resource policies."""
        integers = (
            self.cpu_seconds,
            self.address_space_bytes,
            self.file_size_bytes,
            self.open_files,
            self.processes,
            self.stderr_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in integers):
            message = "PDF resource limits must be positive integers"
            raise ValueError(message)
        if (
            not math.isfinite(self.termination_grace_seconds)
            or self.termination_grace_seconds <= 0
            or self.termination_grace_seconds > _MAX_TERMINATION_GRACE_SECONDS
        ):
            message = "PDF termination grace period is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class PdfProcessorSettings:
    """Trusted deterministic PDF policy forwarded to each disposable worker."""

    max_pages_per_render: int = HARD_MAX_RENDER_PAGES
    max_page_pixels: int = HARD_MAX_PAGE_PIXELS
    max_render_pixels: int = HARD_MAX_RENDER_PIXELS
    fallback_dpi: int = DEFAULT_FALLBACK_DPI
    tile_width: int = 2048
    tile_height: int = 2048
    tile_overlap: int = 128
    max_tiles_per_page: int = HARD_MAX_TILES_PER_PAGE

    def __post_init__(self) -> None:
        """Reject forged settings before they reach the child environment."""
        bounded = (
            (self.max_pages_per_render, 1, HARD_MAX_RENDER_PAGES),
            (self.max_page_pixels, 1, HARD_MAX_PAGE_PIXELS),
            (self.max_render_pixels, 1, HARD_MAX_RENDER_PIXELS),
            (self.fallback_dpi, 72, 1_200),
            (self.tile_width, 256, HARD_MAX_TILE_DIMENSION),
            (self.tile_height, 256, HARD_MAX_TILE_DIMENSION),
            (self.tile_overlap, 0, HARD_MAX_TILE_OVERLAP),
            (self.max_tiles_per_page, 1, HARD_MAX_TILES_PER_PAGE),
        )
        if any(
            type(value) is not int or not minimum <= value <= maximum
            for value, minimum, maximum in bounded
        ):
            message = "PDF processor settings are outside their allowed range"
            raise ValueError(message)
        if self.tile_overlap >= min(self.tile_width, self.tile_height):
            message = "PDF tile overlap must be smaller than both dimensions"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class PdfCircuitPolicy:
    """Bounded failure threshold and monotonic open interval."""

    failure_threshold: int = 3
    open_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Reject coercive or unbounded circuit policy values."""
        if (
            type(self.failure_threshold) is not int
            or not 1 <= self.failure_threshold <= _MAX_CIRCUIT_FAILURE_THRESHOLD
            or type(self.open_seconds) is not float
            or not math.isfinite(self.open_seconds)
            or not 0 < self.open_seconds <= _MAX_CIRCUIT_OPEN_SECONDS
        ):
            message = "PDF circuit policy is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class PdfWorkerPolicy:
    """Closed configuration bundle for one disposable-worker executor."""

    resources: PdfResourceLimits = field(default_factory=PdfResourceLimits)
    processor: PdfProcessorSettings = field(default_factory=PdfProcessorSettings)
    circuit: PdfCircuitPolicy = field(default_factory=PdfCircuitPolicy)
    capacity: int = 1

    def __post_init__(self) -> None:
        """Keep worker execution serialized with an exact integer capacity."""
        if type(self.capacity) is not int or self.capacity != 1:
            message = "disposable PDF executor capacity must equal 1"
            raise ValueError(message)


class PdfCircuitBreaker:
    """Instance-local circuit for worker transport and process failures."""

    __slots__ = (
        "_clock",
        "_consecutive_failures",
        "_half_open_probe",
        "_last_now",
        "_open_until",
        "_policy",
    )

    def __init__(
        self,
        *,
        policy: PdfCircuitPolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind an injected monotonic clock and a closed strict policy."""
        super().__init__()
        actual_policy = policy or PdfCircuitPolicy()
        # Recheck forged dataclass instances at the stateful boundary.
        validated_policy = PdfCircuitPolicy(
            failure_threshold=actual_policy.failure_threshold,
            open_seconds=actual_policy.open_seconds,
        )
        self._policy = validated_policy
        self._clock = clock
        self._last_now: float | None = None
        self._consecutive_failures = 0
        self._open_until: float | None = None
        self._half_open_probe = False

    def _now(self) -> float:
        value = self._clock()
        if (
            type(value) is not float
            or not math.isfinite(value)
            or value < 0
            or (self._last_now is not None and value < self._last_now)
        ):
            message = "PDF circuit monotonic clock is invalid"
            raise RuntimeError(message)
        self._last_now = value
        return value

    @staticmethod
    def _unavailable() -> PdfWorkerUnavailableError:
        message = "PDF worker is temporarily unavailable"
        return PdfWorkerUnavailableError(message)

    def ensure_ready(self) -> None:
        """Fail readiness until the cooldown permits a half-open traffic probe."""
        open_until = self._open_until
        if open_until is not None and (
            self._half_open_probe or self._now() < open_until
        ):
            raise self._unavailable()

    def before_attempt(self) -> None:
        """Admit a closed attempt or exactly one probe after the open interval."""
        open_until = self._open_until
        if open_until is None:
            return
        if self._half_open_probe or self._now() < open_until:
            raise self._unavailable()
        self._half_open_probe = True

    def record_success(self) -> None:
        """Close the circuit after a valid worker response."""
        self._consecutive_failures = 0
        self._open_until = None
        self._half_open_probe = False

    def record_operational_failure(self) -> None:
        """Open only after bounded process or transport failure amplification."""
        self._consecutive_failures += 1
        if (
            not self._half_open_probe
            and self._consecutive_failures < self._policy.failure_threshold
        ):
            return
        now = self._now()
        open_until = now + self._policy.open_seconds
        if not math.isfinite(open_until) or open_until <= now:
            message = "PDF circuit open deadline is invalid"
            raise RuntimeError(message)
        self._consecutive_failures = self._policy.failure_threshold
        self._open_until = open_until
        self._half_open_probe = False

    def record_cancelled(self) -> None:
        """Release a half-open probe without counting caller cancellation."""
        self._half_open_probe = False


class PdfExecutor(Protocol):
    """Execute one strict PDF command before an absolute deadline."""

    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        """Return a validated worker result."""
        ...

    def ensure_ready(self) -> None:
        """Raise when the worker circuit is not ready for normal traffic."""
        ...


class PdfWorkerError(RuntimeError):
    """Sanitized failure at the worker transport or isolation boundary."""


class PdfWorkerOperationalError(PdfWorkerError):
    """Process start, exit, deadline, or framing failure counted by the circuit."""


class PdfWorkerUnavailableError(PdfWorkerError):
    """Fail fast while the instance-local worker circuit is open."""
