# Copyright (c) 2026 David Osipov
"""Interfaces and limits for isolated PDF execution."""

from __future__ import annotations

import math
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Annotated,
    Literal,
    Protocol,
    Self,
    overload,
)

from pydantic import Field, TypeAdapter, model_validator

from .config import (
    HARD_MAX_CACHE_BYTES,
    HARD_MAX_PAGE_PIXELS,
    HARD_MAX_RENDER_PAGES,
    HARD_MAX_RENDER_PIXELS,
    HARD_MAX_TILE_DIMENSION,
    HARD_MAX_TILE_OVERLAP,
    HARD_MAX_TILES_PER_PAGE,
)
from .contracts.base import StrictModel
from .pdf_ipc import (
    PdfCommand,
    PdfResult,
    RenderPagesCommand,
    RenderTilesCommand,
)
from .pdf_postprocessing import MAX_RENDER_RESOURCE_INDEX_BYTES
from .pdf_worker_slot import PdfWorkerSlotPolicy

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable

    from .contracts import MonotonicDeadline
    from .storage import ContentAddressedStore, StoreLifecycleConfiguration

_MAX_TERMINATION_GRACE_SECONDS = 5.0
_MAX_CIRCUIT_FAILURE_THRESHOLD = 100
_MAX_CIRCUIT_OPEN_SECONDS = 3_600.0
DEFAULT_FALLBACK_DPI = 400
_MAX_PDF_PUBLICATION_FILES = HARD_MAX_TILES_PER_PAGE + 1
_MAX_PDF_PUBLICATION_DIRECTORIES = 3
_MAX_PDF_PUBLICATION_TEMPORARY_FILES = 1
_MAX_PDF_PUBLICATION_INODES = 10_000_000
_PDF_COMMAND_ADAPTER: TypeAdapter[PdfCommand] = TypeAdapter(PdfCommand)


class PdfPublicationPlan(StrictModel):
    """Closed worst-case accounting for one authoritative render tree."""

    operation: Literal["render_pages", "render_tiles"]
    maximum_output_files: Annotated[
        int,
        Field(strict=True, ge=2, le=_MAX_PDF_PUBLICATION_FILES),
    ]
    maximum_output_directories: Annotated[
        int,
        Field(strict=True, ge=1, le=_MAX_PDF_PUBLICATION_DIRECTORIES),
    ]
    maximum_temporary_files: Annotated[
        int,
        Field(strict=True, ge=1, le=_MAX_PDF_PUBLICATION_TEMPORARY_FILES),
    ]
    maximum_new_bytes: Annotated[
        int,
        Field(strict=True, ge=1, le=HARD_MAX_CACHE_BYTES),
    ]
    maximum_new_objects: Annotated[
        int,
        Field(strict=True, ge=1, le=1),
    ]
    maximum_new_inodes: Annotated[
        int,
        Field(strict=True, ge=1, le=_MAX_PDF_PUBLICATION_INODES),
    ]

    @model_validator(mode="after")
    def _require_complete_tree_capacity(self) -> Self:
        minimum_inodes = (
            self.maximum_output_files
            + self.maximum_output_directories
            + self.maximum_temporary_files
        )
        if self.maximum_new_bytes < self.maximum_output_files:
            message = "PDF publication bytes do not cover every bounded output"
            raise ValueError(message)
        if self.maximum_new_inodes < minimum_inodes:
            message = "PDF publication inodes do not cover the complete tree"
            raise ValueError(message)
        return self


class PdfPostprocessingPublicationPlan(StrictModel):
    """Closed capacity plan for resource indexes emitted after rendering."""

    maximum_index_files: Annotated[
        int,
        Field(strict=True, ge=1, le=HARD_MAX_TILES_PER_PAGE + 1),
    ]

    @property
    def maximum_new_bytes(self) -> int:
        """Return the bounded aggregate serialized index size."""
        return self.maximum_index_files * MAX_RENDER_RESOURCE_INDEX_BYTES

    @property
    def maximum_new_objects(self) -> int:
        """Reserve the render object root before the worker can create it."""
        return 1

    @property
    def maximum_new_inodes(self) -> int:
        """Cover one resources directory, index trees, and one staged file."""
        return 2 * self.maximum_index_files + 2


def _validated_pdf_command(command: PdfCommand) -> PdfCommand:
    """Revalidate even model-constructed commands at the reservation boundary."""
    return _PDF_COMMAND_ADAPTER.validate_json(
        command.model_dump_json(),
        strict=True,
    )


def _validated_slot_policy(policy: PdfWorkerSlotPolicy) -> PdfWorkerSlotPolicy:
    """Reject forged slot policies before deriving accounting authority."""
    return PdfWorkerSlotPolicy.model_validate_json(
        policy.model_dump_json(),
        strict=True,
    )


def _derive_validated_publication_plan(
    command: PdfCommand,
    slot_policy: PdfWorkerSlotPolicy,
) -> PdfPublicationPlan | None:
    if isinstance(command, RenderPagesCommand):
        maximum_output_files = len(command.parameters.pages) + 1
        maximum_output_directories = 1
    elif isinstance(command, RenderTilesCommand):
        # Page dimensions are worker-validated after dispatch, so reserve the
        # protocol maximum rather than trusting an unavailable tile estimate.
        maximum_output_files = HARD_MAX_TILES_PER_PAGE + 1
        # A new tiles/page/geometry subtree can accompany the manifest.
        maximum_output_directories = 3
    else:
        return None
    maximum_temporary_files = 1
    minimum_topology_inodes = (
        maximum_output_files + maximum_output_directories + maximum_temporary_files
    )
    return PdfPublicationPlan(
        operation=command.operation,
        maximum_output_files=maximum_output_files,
        maximum_output_directories=maximum_output_directories,
        maximum_temporary_files=maximum_temporary_files,
        # The authoritative copy cannot exceed the verified aggregate worker
        # slot.  The maxima also cover at least one byte/inode per topology
        # entry if a malformed deployment policy understates its capacity.
        maximum_new_bytes=max(
            slot_policy.maximum_total_bytes,
            maximum_output_files,
        ),
        maximum_new_objects=1,
        maximum_new_inodes=max(
            slot_policy.maximum_total_inodes,
            minimum_topology_inodes,
        ),
    )


@overload
def derive_pdf_publication_plan(
    command: RenderPagesCommand | RenderTilesCommand,
    slot_policy: PdfWorkerSlotPolicy,
) -> PdfPublicationPlan: ...


@overload
def derive_pdf_publication_plan(
    command: PdfCommand,
    slot_policy: PdfWorkerSlotPolicy,
) -> PdfPublicationPlan | None: ...


def derive_pdf_publication_plan(
    command: PdfCommand,
    slot_policy: PdfWorkerSlotPolicy,
) -> PdfPublicationPlan | None:
    """Derive one full-slot page/tile reservation from strict inputs."""
    validated_command = _validated_pdf_command(command)
    validated_policy = _validated_slot_policy(slot_policy)
    return _derive_validated_publication_plan(validated_command, validated_policy)


class PublicationReservingPdfExecutor:
    """Reserve a complete render tree before either PDF backend is invoked."""

    __slots__ = ("_inner", "_lifecycle", "_slot_policy", "_store")

    def __init__(
        self,
        *,
        inner: PdfExecutor,
        store: ContentAddressedStore,
        lifecycle: StoreLifecycleConfiguration,
        slot_policy: PdfWorkerSlotPolicy,
    ) -> None:
        """Bind one store authority and immutable verified slot policy."""
        super().__init__()
        self._inner = inner
        self._store = store
        self._lifecycle = lifecycle
        self._slot_policy = _validated_slot_policy(slot_policy)

    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        """Reserve before dispatch and release once on every exit path."""
        validated_command = _validated_pdf_command(command)
        plan = _derive_validated_publication_plan(
            validated_command,
            self._slot_policy,
        )
        if plan is None:
            return await self._inner.execute(validated_command, deadline=deadline)
        async with self._store.reserve_publication(
            self._lifecycle.policy,
            maximum_new_bytes=plan.maximum_new_bytes,
            maximum_new_objects=plan.maximum_new_objects,
            maximum_new_inodes=plan.maximum_new_inodes,
            clock=self._lifecycle.clock_sampler(),
        ) as reservation:
            result = await self._inner.execute(validated_command, deadline=deadline)
            # PDF publication has already passed through ContentAddressedStore,
            # whose under-lock commit recheck observes the persisted deltas. No
            # unaccounted bytes, objects, or inodes remain to be converted.
            await reservation.commit(
                actual_bytes=0,
                actual_objects=0,
                actual_inodes=0,
            )
            return result

    @asynccontextmanager
    async def reserve_postprocessing_publication(
        self,
        *,
        maximum_index_files: int,
    ) -> AsyncGenerator[None, None]:
        """Hold bounded index capacity across worker dispatch and validation."""
        plan = PdfPostprocessingPublicationPlan(
            maximum_index_files=maximum_index_files,
        )
        async with self._store.reserve_publication(
            self._lifecycle.policy,
            maximum_new_bytes=plan.maximum_new_bytes,
            maximum_new_objects=plan.maximum_new_objects,
            maximum_new_inodes=plan.maximum_new_inodes,
            clock=self._lifecycle.clock_sampler(),
        ) as reservation:
            yield
            # Index files are already persisted through ContentAddressedStore,
            # so its commit recheck observes the authoritative deltas.
            await reservation.commit(
                actual_bytes=0,
                actual_objects=0,
                actual_inodes=0,
            )

    def ensure_ready(self) -> None:
        """Delegate readiness without consuming publication capacity."""
        self._inner.ensure_ready()


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
