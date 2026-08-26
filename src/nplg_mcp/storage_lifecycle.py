# Copyright (c) 2026 David Osipov
"""Strict capacity, retention, and trustworthy-clock lifecycle contracts."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Annotated, Final, Literal, Protocol, Self, cast

from pydantic import (
    AwareDatetime,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from .config import HARD_MAX_CACHE_BYTES
from .contracts.base import StrictModel
from .errors import AppError, ErrorCode

if TYPE_CHECKING:
    from collections.abc import Callable

    from .json_types import JsonObject

_MAX_STORED_OBJECTS = 10_000_000
_MAX_FILESYSTEM_COUNT = 9_223_372_036_854_775_807
_MAX_CLOCK_STATE_BYTES = 4_096
_MIN_JSON_OBJECT_BYTES = 2
_MAX_HEALTHY_WINDOW_SECONDS = 3_600
_MAX_FORWARD_SLEW_SECONDS = 60
_MAX_BOOT_ID_BYTES = 128
_CLOCK_STATE_SCHEMA: Final = "1.0"
_INSERTION_STATE_SCHEMA: Final = "1.0"
_INSERTION_STATE_MAX_BYTES = 4_096
_PRIVATE_STATE_DIRECTORY_MODE = 0o700
_PRIVATE_STATE_FILE_MODE = 0o600
INSERTION_SEQUENCE_FILENAME = ".lifecycle-insertion-sequence.json"
INSERTION_HIGH_WATER_FILENAME = ".lifecycle-insertion-high-water.json"
KERNEL_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_BOOT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_INVALID_BOOT_ID = "unsafe boot identity observation"


@dataclass(frozen=True, slots=True)
class _PrivateStateSnapshot:
    """Complete non-atime snapshot of one bounded private state record."""

    device: int
    inode: int
    mode: int
    owner: int
    group: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    raw: bytes

    @classmethod
    def capture(cls, metadata: os.stat_result, *, raw: bytes) -> Self:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            owner=metadata.st_uid,
            group=metadata.st_gid,
            links=metadata.st_nlink,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
            raw=raw,
        )

    def matches(self, metadata: os.stat_result) -> bool:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) == (
            self.device,
            self.inode,
            self.mode,
            self.owner,
            self.group,
            self.links,
            self.size,
            self.modified_ns,
            self.changed_ns,
        )

    def identifies(self, metadata: os.stat_result) -> bool:
        return (metadata.st_dev, metadata.st_ino) == (self.device, self.inode)

    def matches_published_content(self, metadata: os.stat_result) -> bool:
        """Match stable content metadata while permitting rename ctime updates."""
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
        ) == (
            self.device,
            self.inode,
            self.mode,
            self.owner,
            self.group,
            self.links,
            self.size,
            self.modified_ns,
        )


def _has_private_state_attributes(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and stat.S_IMODE(metadata.st_mode) == _PRIVATE_STATE_FILE_MODE
    )


def _has_private_state_metadata(metadata: os.stat_result) -> bool:
    return _has_private_state_attributes(metadata) and metadata.st_nlink == 1


def _has_private_directory_metadata(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and stat.S_IMODE(metadata.st_mode) == _PRIVATE_STATE_DIRECTORY_MODE
    )


def _prepare_private_state_descriptor(descriptor: int, *, context: str) -> None:
    os.fchmod(descriptor, _PRIVATE_STATE_FILE_MODE)
    metadata = os.fstat(descriptor)
    if not _has_private_state_metadata(metadata):
        msg = f"{context} did not reach its private file postcondition"
        raise ValueError(msg)


def _read_exact_descriptor(descriptor: int, *, expected_size: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining > 0:
        chunk = os.read(descriptor, remaining)
        if not chunk or len(chunk) > remaining:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        return None
    return b"".join(chunks)


def _write_all_descriptor(descriptor: int, raw: bytes, *, context: str) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            msg = f"{context} write made no progress"
            raise OSError(msg)
        offset += written


StoredByteCount = Annotated[
    int,
    Field(strict=True, ge=0, le=HARD_MAX_CACHE_BYTES),
]
PositiveStoredByteCount = Annotated[
    int,
    Field(strict=True, ge=1, le=HARD_MAX_CACHE_BYTES),
]
StoredObjectCount = Annotated[
    int,
    Field(strict=True, ge=0, le=_MAX_STORED_OBJECTS),
]
PositiveStoredObjectCount = Annotated[
    int,
    Field(strict=True, ge=1, le=_MAX_STORED_OBJECTS),
]
FilesystemCount = Annotated[
    int,
    Field(strict=True, ge=0, le=_MAX_FILESYSTEM_COUNT),
]
RetentionAgeSeconds = Annotated[
    int,
    Field(strict=True, ge=60, le=31_536_000),
]
RetentionByteBudget = PositiveStoredByteCount
RetentionObjectBudget = PositiveStoredObjectCount
MinimumFreeBytes = Annotated[
    int,
    Field(strict=True, ge=67_108_864, le=HARD_MAX_CACHE_BYTES),
]
MinimumFreeInodes = Annotated[
    int,
    Field(strict=True, ge=128, le=_MAX_STORED_OBJECTS),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
BootId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        strip_whitespace=False,
    ),
]
InsertionObjectKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=(
            r"^(?:documents/doc_[0-9a-f]{64}|"
            r"renders/rnd_(?:[0-9a-f]{32}|[0-9a-f]{64}))$"
        ),
        strip_whitespace=False,
    ),
]
InsertionSequence = Annotated[
    int,
    Field(strict=True, ge=1, le=_MAX_FILESYSTEM_COUNT),
]


class StorageCapacity(StrictModel):
    """One bounded filesystem byte/inode observation."""

    total_bytes: FilesystemCount
    available_bytes: FilesystemCount
    total_inodes: FilesystemCount
    available_inodes: FilesystemCount

    @model_validator(mode="after")
    def _counts_do_not_exceed_totals(self) -> Self:
        if self.available_bytes > self.total_bytes:
            msg = "available bytes must not exceed total bytes"
            raise ValueError(msg)
        if self.available_inodes > self.total_inodes:
            msg = "available inodes must not exceed total inodes"
            raise ValueError(msg)
        return self


class RetentionPolicy(StrictModel):
    """Closed local artifact retention and free-space policy."""

    maximum_age_seconds: RetentionAgeSeconds
    maximum_bytes: RetentionByteBudget
    maximum_objects: RetentionObjectBudget
    minimum_free_bytes: MinimumFreeBytes
    minimum_free_inodes: MinimumFreeInodes


class RetentionClockSample(StrictModel):
    """One wall/monotonic/boot observation with explicit sync state."""

    utc_now: AwareDatetime
    monotonic_now: Annotated[
        float,
        Field(strict=True, ge=0.0, allow_inf_nan=False),
    ]
    boot_id: BootId
    synchronized: bool

    @field_validator("utc_now")
    @classmethod
    def _require_exact_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            msg = "retention clock must use the UTC timezone"
            raise ValueError(msg)
        return value.astimezone(UTC)

    @field_validator("monotonic_now", mode="before")
    @classmethod
    def _require_exact_float(cls, value: object) -> object:
        if type(value) is not float:
            msg = "monotonic clock must be an exact float"
            raise ValueError(msg)
        return value


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


def _read_boot_identity_unchecked(path: Path) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(_INVALID_BOOT_ID)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise ValueError(_INVALID_BOOT_ID)
        raw = os.read(descriptor, _MAX_BOOT_ID_BYTES + 2)
    finally:
        os.close(descriptor)
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or len(raw) > _MAX_BOOT_ID_BYTES:
        raise ValueError(_INVALID_BOOT_ID)
    value = raw.decode("ascii")
    if _BOOT_ID_PATTERN.fullmatch(value) is None:
        raise ValueError(_INVALID_BOOT_ID)
    return value


def _read_boot_identity(path: Path) -> str:
    try:
        return _read_boot_identity_unchecked(path)
    except (OSError, UnicodeError, ValueError) as exc:
        msg = "retention boot identity is unavailable or unsafe"
        raise ValueError(msg) from exc


class SystemRetentionClock:
    """Sample UTC, monotonic time, and one non-followed kernel boot identity."""

    __slots__ = (
        "_boot_id_path",
        "_monotonic_sampler",
        "_synchronized",
        "_utc_sampler",
    )

    def __init__(
        self,
        *,
        synchronized: bool,
        boot_id_path: Path = KERNEL_BOOT_ID_PATH,
        utc_sampler: Callable[[], datetime] = _system_utc_now,
        monotonic_sampler: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind explicit synchronization state and injectable clock authorities."""
        super().__init__()
        raw_synchronized = cast("object", synchronized)
        raw_boot_id_path = cast("object", boot_id_path)
        raw_utc_sampler = cast("object", utc_sampler)
        raw_monotonic_sampler = cast("object", monotonic_sampler)
        if type(raw_synchronized) is not bool:
            msg = "retention synchronization state must be an exact boolean"
            raise TypeError(msg)
        if not isinstance(raw_boot_id_path, Path):
            msg = "retention boot identity path must be a pathlib.Path"
            raise TypeError(msg)
        if not callable(raw_utc_sampler) or not callable(raw_monotonic_sampler):
            msg = "retention clock samplers must be callable"
            raise TypeError(msg)
        self._synchronized = synchronized
        self._boot_id_path = boot_id_path
        self._utc_sampler = utc_sampler
        self._monotonic_sampler = monotonic_sampler

    def __call__(self) -> RetentionClockSample:
        """Return one strict sample or reject an ambiguous platform observation."""
        return RetentionClockSample(
            utc_now=self._utc_sampler(),
            monotonic_now=self._monotonic_sampler(),
            boot_id=_read_boot_identity(self._boot_id_path),
            synchronized=self._synchronized,
        )


class InsertionSequenceRecord(StrictModel):
    """Digest-bound insertion order for one persisted artifact object."""

    schema_version: Literal["1.0"]
    object_key: InsertionObjectKey
    sequence: InsertionSequence
    record_digest: Sha256

    @model_validator(mode="after")
    def _digest_binds_record(self) -> Self:
        expected = _json_digest(
            cast(
                "JsonObject",
                self.model_dump(mode="json", exclude={"record_digest"}),
            )
        )
        if self.record_digest != expected:
            msg = "insertion sequence digest does not match its canonical record"
            raise ValueError(msg)
        return self

    @classmethod
    def build(cls, *, object_key: str, sequence: int) -> Self:
        """Build one strictly validated, digest-bound sequence record."""
        payload: JsonObject = {
            "schema_version": _INSERTION_STATE_SCHEMA,
            "object_key": object_key,
            "sequence": sequence,
        }
        return cls(
            schema_version=_INSERTION_STATE_SCHEMA,
            object_key=object_key,
            sequence=sequence,
            record_digest=_json_digest(payload),
        )


class InsertionHighWaterRecord(StrictModel):
    """Digest-bound next sequence, persisted before each allocation."""

    schema_version: Literal["1.0"]
    next_sequence: InsertionSequence
    record_digest: Sha256

    @model_validator(mode="after")
    def _digest_binds_record(self) -> Self:
        expected = _json_digest(
            cast(
                "JsonObject",
                self.model_dump(mode="json", exclude={"record_digest"}),
            )
        )
        if self.record_digest != expected:
            msg = "insertion high-water digest does not match its canonical record"
            raise ValueError(msg)
        return self

    @classmethod
    def build(cls, *, next_sequence: int) -> Self:
        """Build one strictly validated, digest-bound high-water record."""
        payload: JsonObject = {
            "schema_version": _INSERTION_STATE_SCHEMA,
            "next_sequence": next_sequence,
        }
        return cls(
            schema_version=_INSERTION_STATE_SCHEMA,
            next_sequence=next_sequence,
            record_digest=_json_digest(payload),
        )


class PruneBlocker(StrEnum):
    """Low-cardinality reasons a prune cannot establish a safe post-state."""

    LEASED_OBJECTS = "leased_objects"
    BYTE_HEADROOM = "byte_headroom"
    INODE_HEADROOM = "inode_headroom"
    CLOCK_ANOMALY = "clock_anomaly"


class SatisfiedPruneReport(StrictModel):
    """A post-prune state that satisfies every configured bound."""

    status: Literal["satisfied"]
    freed_bytes: StoredByteCount
    freed_objects: StoredObjectCount
    retained_leased_objects: StoredObjectCount
    post_stored_bytes: StoredByteCount
    post_stored_objects: StoredObjectCount
    post_available_bytes: FilesystemCount
    post_available_inodes: FilesystemCount


class UnsatisfiedPruneReport(StrictModel):
    """A bounded report that discloses reasons, never object identities."""

    status: Literal["unsatisfied"]
    blockers: Annotated[
        tuple[PruneBlocker, ...],
        Field(min_length=1, max_length=4),
    ]
    freed_bytes: StoredByteCount
    freed_objects: StoredObjectCount
    retained_leased_objects: StoredObjectCount
    post_stored_bytes: StoredByteCount
    post_stored_objects: StoredObjectCount
    post_available_bytes: FilesystemCount
    post_available_inodes: FilesystemCount

    @model_validator(mode="after")
    def _blockers_are_unique_and_canonical(self) -> Self:
        canonical = tuple(
            blocker for blocker in PruneBlocker if blocker in self.blockers
        )
        if self.blockers != canonical:
            msg = "prune blockers must be unique and canonically ordered"
            raise ValueError(msg)
        return self


type PruneReport = Annotated[
    SatisfiedPruneReport | UnsatisfiedPruneReport,
    Field(discriminator="status"),
]


class PublicationBlocker(StrEnum):
    """Stable publication-admission denial reasons."""

    BYTE_BUDGET = "byte_budget"
    OBJECT_BUDGET = "object_budget"
    BYTE_HEADROOM = "byte_headroom"
    INODE_HEADROOM = "inode_headroom"
    CLOCK_ANOMALY = "clock_anomaly"


class LifecycleBlocker(StrEnum):
    """Closed union of path-free lifecycle alert reasons."""

    BYTE_BUDGET = "byte_budget"
    OBJECT_BUDGET = "object_budget"
    LEASED_OBJECTS = "leased_objects"
    BYTE_HEADROOM = "byte_headroom"
    INODE_HEADROOM = "inode_headroom"
    CLOCK_ANOMALY = "clock_anomaly"


class LifecycleAlertEvent(StrEnum):
    """Low-cardinality lifecycle state transitions safe for telemetry."""

    ADMISSION_CLOSED = "admission_closed"
    PRUNE_UNSATISFIED = "prune_unsatisfied"


class LifecycleAlert(StrictModel):
    """One bounded lifecycle alert without paths, counts, or object metadata."""

    event: LifecycleAlertEvent
    blockers: Annotated[
        tuple[LifecycleBlocker, ...],
        Field(min_length=1, max_length=4),
    ]

    @model_validator(mode="after")
    def _blockers_are_unique_canonical_and_event_bounded(self) -> Self:
        canonical = tuple(
            blocker for blocker in LifecycleBlocker if blocker in self.blockers
        )
        if self.blockers != canonical:
            msg = "lifecycle alert blockers must be unique and canonically ordered"
            raise ValueError(msg)
        if self.event is LifecycleAlertEvent.ADMISSION_CLOSED and len(canonical) != 1:
            msg = "admission-closed alerts require exactly one blocker"
            raise ValueError(msg)
        return self


class PublicationReservationError(AppError):
    """Fail a publication without disclosing paths or capacity measurements."""

    blocker: PublicationBlocker

    def __init__(self, blocker: PublicationBlocker) -> None:
        """Construct one bounded, path-free admission failure."""
        self.blocker = blocker
        super().__init__(
            ErrorCode.CACHE_FULL,
            "The local artifact lifecycle policy rejected publication.",
            http_status=507,
            safe_details={"blocker": blocker.value},
        )


class PublicationReservation(Protocol):
    """One exact-once worst-case reservation."""

    @property
    def reserved_bytes(self) -> int:
        """Return the reserved byte ceiling."""
        ...

    @property
    def reserved_objects(self) -> int:
        """Return the reserved logical-object ceiling."""
        ...

    @property
    def reserved_inodes(self) -> int:
        """Return the reserved physical-inode ceiling."""
        ...

    async def commit(
        self,
        *,
        actual_bytes: StoredByteCount,
        actual_objects: StoredObjectCount,
        actual_inodes: StoredObjectCount,
    ) -> None:
        """Convert the reservation after an exact aggregate recheck."""
        ...

    async def abort(self) -> None:
        """Release the reservation exactly once."""
        ...


def validate_retention_capacity(
    policy: RetentionPolicy,
    *,
    configured_cache_max_bytes: int,
    capacity: StorageCapacity,
) -> None:
    """Reject a retention policy the configured filesystem can never satisfy."""
    if (
        type(configured_cache_max_bytes) is not int
        or configured_cache_max_bytes < policy.maximum_bytes
        or configured_cache_max_bytes > HARD_MAX_CACHE_BYTES
    ):
        msg = "configured cache maximum must cover policy maximum_bytes"
        raise ValueError(msg)
    if policy.maximum_bytes + policy.minimum_free_bytes > capacity.total_bytes:
        msg = "filesystem cannot preserve the configured byte reserve"
        raise ValueError(msg)
    if policy.minimum_free_inodes >= capacity.total_inodes:
        msg = "filesystem cannot preserve the configured inode reserve"
        raise ValueError(msg)


def filesystem_capacity(descriptor: int) -> StorageCapacity:
    """Sample capacity from one already-held verified directory descriptor."""
    if type(descriptor) is not int or descriptor < 0:
        msg = "filesystem capacity requires a non-negative exact descriptor"
        raise ValueError(msg)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        msg = "filesystem capacity descriptor must identify a directory"
        raise ValueError(msg)
    capacity = os.fstatvfs(descriptor)
    fragment_size = capacity.f_frsize
    return StorageCapacity(
        total_bytes=capacity.f_blocks * fragment_size,
        available_bytes=capacity.f_bavail * fragment_size,
        total_inodes=capacity.f_files,
        available_inodes=capacity.f_favail,
    )


class ClockBlocker(StrEnum):
    """Stable causes for untrusted retention time."""

    MISSING_STATE = "missing_state"
    CORRUPT_STATE = "corrupt_state"
    UNSYNCHRONIZED = "unsynchronized"
    BOOT_CHANGED = "boot_changed"
    MONOTONIC_ROLLBACK = "monotonic_rollback"
    WALL_ROLLBACK = "wall_rollback"
    FORWARD_STEP = "forward_step"
    WARMING_UP = "warming_up"


class ClockAssessment(StrictModel):
    """Low-cardinality clock decision used by pruning and admission."""

    trusted: bool
    age_deletion_allowed: bool
    blocker: ClockBlocker | None

    @model_validator(mode="after")
    def _decision_is_consistent(self) -> Self:
        if self.trusted != self.age_deletion_allowed:
            msg = "trusted clock and age-deletion decision must agree"
            raise ValueError(msg)
        if self.trusted == (self.blocker is not None):
            msg = "trusted clock must have no blocker"
            raise ValueError(msg)
        return self


class _ClockHighWaterRecord(StrictModel):
    schema_version: Literal["1.0"]
    boot_id: BootId
    utc_high_water: AwareDatetime
    last_observed_utc: AwareDatetime
    last_monotonic: Annotated[
        float,
        Field(strict=True, ge=0.0, allow_inf_nan=False),
    ]
    healthy_since_monotonic: (
        Annotated[
            float,
            Field(strict=True, ge=0.0, allow_inf_nan=False),
        ]
        | None
    )
    trusted: bool
    record_digest: Sha256

    @field_validator("utc_high_water", "last_observed_utc")
    @classmethod
    def _record_times_are_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            msg = "clock state timestamps must use UTC"
            raise ValueError(msg)
        return value.astimezone(UTC)

    @field_validator("last_monotonic", "healthy_since_monotonic", mode="before")
    @classmethod
    def _record_monotonic_is_exact_float(cls, value: object) -> object:
        if value is not None and type(value) is not float:
            msg = "clock state monotonic values must be exact floats"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _record_is_consistent_and_digest_bound(self) -> Self:
        if (
            self.healthy_since_monotonic is not None
            and self.healthy_since_monotonic > self.last_monotonic
        ):
            msg = "clock state healthy window starts after its latest sample"
            raise ValueError(msg)
        if self.trusted and self.healthy_since_monotonic is None:
            msg = "trusted clock state requires a healthy-window origin"
            raise ValueError(msg)
        expected = _json_digest(
            cast(
                "JsonObject",
                self.model_dump(mode="json", exclude={"record_digest"}),
            )
        )
        if self.record_digest != expected:
            msg = "clock state digest does not match its canonical record"
            raise ValueError(msg)
        return self


def _canonical_json_bytes(value: JsonObject) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _json_digest(value: JsonObject) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class _ClockRecordInput:
    """Typed input for one persisted high-water record."""

    boot_id: str
    utc_high_water: datetime
    last_observed_utc: datetime
    last_monotonic: float
    healthy_since_monotonic: float | None
    trusted: bool


def _clock_record(values: _ClockRecordInput) -> _ClockHighWaterRecord:
    digest_payload: JsonObject = {
        "schema_version": _CLOCK_STATE_SCHEMA,
        "boot_id": values.boot_id,
        "utc_high_water": values.utc_high_water.isoformat().replace("+00:00", "Z"),
        "last_observed_utc": values.last_observed_utc.isoformat().replace(
            "+00:00", "Z"
        ),
        "last_monotonic": values.last_monotonic,
        "healthy_since_monotonic": values.healthy_since_monotonic,
        "trusted": values.trusted,
    }
    return _ClockHighWaterRecord(
        schema_version=_CLOCK_STATE_SCHEMA,
        boot_id=values.boot_id,
        utc_high_water=values.utc_high_water,
        last_observed_utc=values.last_observed_utc,
        last_monotonic=values.last_monotonic,
        healthy_since_monotonic=values.healthy_since_monotonic,
        trusted=values.trusted,
        record_digest=_json_digest(digest_payload),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            msg = "clock state contains duplicate JSON keys"
            raise ValueError(msg)
        result[key] = value
    return result


class ClockHighWater:
    """Persist and assess a restart-stable UTC/monotonic high-water record."""

    def __init__(
        self,
        path: Path,
        *,
        healthy_window_seconds: int,
        maximum_forward_slew_seconds: int,
    ) -> None:
        """Bind one private state path and bounded recovery intervals."""
        super().__init__()
        if (
            type(healthy_window_seconds) is not int
            or not 0 <= healthy_window_seconds <= _MAX_HEALTHY_WINDOW_SECONDS
        ):
            msg = "healthy_window_seconds must be an integer from 0 through 3600"
            raise ValueError(msg)
        if (
            type(maximum_forward_slew_seconds) is not int
            or not 0 <= maximum_forward_slew_seconds <= _MAX_FORWARD_SLEW_SECONDS
        ):
            msg = "maximum_forward_slew_seconds must be an integer from 0 through 60"
            raise ValueError(msg)
        self._path = path
        self._healthy_window_seconds = float(healthy_window_seconds)
        self._maximum_forward_slew_seconds = float(maximum_forward_slew_seconds)
        self._transition_lock = RLock()
        self._transition_active = False

    def _read_stable_snapshot(
        self,
        directory: int,
        metadata: os.stat_result,
    ) -> _PrivateStateSnapshot | None:
        initial = _PrivateStateSnapshot.capture(metadata, raw=b"")
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path.name, flags, dir_fd=directory)
            try:
                opened = os.fstat(descriptor)
                if not initial.matches(opened) or not _has_private_state_metadata(
                    opened
                ):
                    return None
                raw = _read_exact_descriptor(
                    descriptor,
                    expected_size=metadata.st_size,
                )
                after_read = os.fstat(descriptor)
                after_name = os.stat(
                    self._path.name,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
            finally:
                os.close(descriptor)
        except OSError:
            return None
        if (
            raw is None
            or not initial.matches(after_read)
            or not initial.matches(after_name)
        ):
            return None
        return _PrivateStateSnapshot.capture(after_read, raw=raw)

    def _read(
        self,
        directory: int,
    ) -> tuple[
        _ClockHighWaterRecord | None,
        ClockBlocker | None,
        _PrivateStateSnapshot | None,
    ]:
        try:
            metadata = os.stat(
                self._path.name,
                dir_fd=directory,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None, ClockBlocker.MISSING_STATE, None
        if (
            not _has_private_state_metadata(metadata)
            or metadata.st_size < _MIN_JSON_OBJECT_BYTES
            or metadata.st_size > _MAX_CLOCK_STATE_BYTES
        ):
            return None, ClockBlocker.CORRUPT_STATE, None
        snapshot = self._read_stable_snapshot(directory, metadata)
        if snapshot is None:
            return None, ClockBlocker.CORRUPT_STATE, None
        try:
            _ = cast(
                "object",
                json.loads(snapshot.raw, object_pairs_hook=_reject_duplicate_keys),
            )
            record = _ClockHighWaterRecord.model_validate_json(
                snapshot.raw,
                strict=True,
            )
        except (UnicodeError, json.JSONDecodeError, ValidationError, ValueError):
            return None, ClockBlocker.CORRUPT_STATE, snapshot
        return record, None, None

    @staticmethod
    def _unlink_if_same_inode_at(
        directory: int,
        name: str,
        snapshot: _PrivateStateSnapshot,
    ) -> None:
        try:
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if snapshot.identifies(metadata):
                os.unlink(name, dir_fd=directory)
        except OSError:
            return

    @staticmethod
    def _require_snapshot_identity(
        snapshot: _PrivateStateSnapshot,
        metadata: os.stat_result,
        *,
        context: str,
    ) -> None:
        if not snapshot.matches(metadata):
            msg = f"{context} identity changed"
            raise ValueError(msg)

    @staticmethod
    def _existing_quarantine_matches(
        directory: int,
        name: str,
        snapshot: _PrivateStateSnapshot,
    ) -> bool:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=directory)
            try:
                before = os.fstat(descriptor)
                if not _has_private_state_metadata(before) or before.st_size != len(
                    snapshot.raw
                ):
                    return False
                raw = _read_exact_descriptor(
                    descriptor,
                    expected_size=before.st_size,
                )
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            return False
        return raw == snapshot.raw and _PrivateStateSnapshot.capture(
            before, raw=raw or b""
        ).matches(after)

    def _create_quarantine_copy_at(
        self,
        directory: int,
        name: str,
        snapshot: _PrivateStateSnapshot,
    ) -> None:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        create_flags |= os.O_NOFOLLOW
        descriptor = os.open(name, create_flags, 0o600, dir_fd=directory)
        created = _PrivateStateSnapshot.capture(os.fstat(descriptor), raw=b"")
        try:
            try:
                _prepare_private_state_descriptor(
                    descriptor,
                    context="clock state quarantine",
                )
                _write_all_descriptor(
                    descriptor,
                    snapshot.raw,
                    context="clock state quarantine",
                )
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                if not _has_private_state_metadata(metadata) or metadata.st_size != len(
                    snapshot.raw
                ):
                    msg = "clock state quarantine postcondition failed"
                    raise ValueError(msg)
                created = _PrivateStateSnapshot.capture(metadata, raw=snapshot.raw)
            finally:
                os.close(descriptor)
            published = os.stat(name, dir_fd=directory, follow_symlinks=False)
            self._require_snapshot_identity(
                created,
                published,
                context="clock state quarantine",
            )
        except (OSError, ValueError):
            self._unlink_if_same_inode_at(directory, name, created)
            raise

    def _ensure_quarantine_copy_at(
        self,
        directory: int,
        name: str,
        snapshot: _PrivateStateSnapshot,
    ) -> bool:
        if self._existing_quarantine_matches(directory, name, snapshot):
            return True
        if not self._preserve_quarantine_residue_at(directory, name, snapshot):
            return False
        pending_name = f"{name}.pending"
        if not self._existing_quarantine_matches(
            directory,
            pending_name,
            snapshot,
        ):
            if not self._preserve_quarantine_residue_at(
                directory,
                pending_name,
                snapshot,
            ):
                return False
            try:
                self._create_quarantine_copy_at(
                    directory,
                    pending_name,
                    snapshot,
                )
            except (OSError, ValueError):
                return False
        try:
            self._require_private_state_directory(
                directory,
                context="clock state quarantine publication",
            )
            os.rename(
                pending_name,
                name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
        except OSError:
            return False
        return self._existing_quarantine_matches(directory, name, snapshot)

    @staticmethod
    def _read_quarantine_residue_at(
        directory: int,
        name: str,
        metadata: os.stat_result,
    ) -> _PrivateStateSnapshot | None:
        initial = _PrivateStateSnapshot.capture(metadata, raw=b"")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=directory)
            try:
                opened = os.fstat(descriptor)
                if not initial.matches(opened) or not _has_private_state_metadata(
                    opened
                ):
                    return None
                raw = _read_exact_descriptor(
                    descriptor,
                    expected_size=opened.st_size,
                )
                after_read = os.fstat(descriptor)
                after_name = os.stat(
                    name,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
            finally:
                os.close(descriptor)
        except OSError:
            return None
        if (
            raw is None
            or not initial.matches(after_read)
            or not initial.matches(after_name)
        ):
            return None
        return _PrivateStateSnapshot.capture(after_read, raw=raw)

    def _preserve_quarantine_residue_at(
        self,
        directory: int,
        name: str,
        expected: _PrivateStateSnapshot,
    ) -> bool:
        """Move a bounded private crash residue aside without overwriting it."""
        try:
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        residue = (
            self._read_quarantine_residue_at(directory, name, metadata)
            if _has_private_state_metadata(metadata)
            and metadata.st_size <= _MAX_CLOCK_STATE_BYTES
            else None
        )
        if (
            residue is None
            or len(residue.raw) >= len(expected.raw)
            or not expected.raw.startswith(residue.raw)
        ):
            return False
        residue_name = f"{name}.incomplete-{secrets.token_hex(16)}"
        try:
            self._require_private_state_directory(
                directory,
                context="clock state quarantine residue preservation",
            )
            os.rename(
                name,
                residue_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            preserved = os.stat(
                residue_name,
                dir_fd=directory,
                follow_symlinks=False,
            )
            if not residue.matches_published_content(preserved):
                return False
            os.fsync(directory)
        except OSError:
            return False
        return True

    def _recover_corrupt_state_at(
        self,
        directory: int,
        *,
        name: str,
        quarantine_name: str,
        snapshot: _PrivateStateSnapshot,
    ) -> bool:
        if not stat.S_ISDIR(os.fstat(directory).st_mode):
            return False
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not snapshot.matches(before) or not _has_private_state_metadata(before):
            return False
        if not self._ensure_quarantine_copy_at(
            directory,
            quarantine_name,
            snapshot,
        ):
            return False
        os.fsync(directory)
        if not self._recovery_evidence_is_stable_at(
            directory,
            name=name,
            quarantine_name=quarantine_name,
            snapshot=snapshot,
        ):
            return False
        os.unlink(name, dir_fd=directory)
        os.fsync(directory)
        return True

    def _recovery_evidence_is_stable_at(
        self,
        directory: int,
        *,
        name: str,
        quarantine_name: str,
        snapshot: _PrivateStateSnapshot,
    ) -> bool:
        if not self._existing_quarantine_matches(
            directory,
            quarantine_name,
            snapshot,
        ):
            return False
        try:
            active = os.stat(name, dir_fd=directory, follow_symlinks=False)
            self._require_private_state_directory(
                directory,
                context="clock state quarantine source unlink",
            )
        except (OSError, ValueError):
            return False
        return snapshot.matches(active) and self._existing_quarantine_matches(
            directory,
            quarantine_name,
            snapshot,
        )

    def _quarantine_corrupt_state(
        self,
        directory: int,
        snapshot: _PrivateStateSnapshot,
    ) -> bool:
        """Persist an exact bounded copy, then remove only the observed state."""
        name = self._path.name
        if name in {"", ".", ".."}:
            return False
        if not all(
            hasattr(os, flag) for flag in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
        ):
            return False
        quarantine_name = f".{name}.corrupt-{hashlib.sha256(snapshot.raw).hexdigest()}"
        try:
            return self._recover_corrupt_state_at(
                directory,
                name=name,
                quarantine_name=quarantine_name,
                snapshot=snapshot,
            )
        except (NotImplementedError, OSError, ValueError):
            return False

    @staticmethod
    def _open_state_directory(parent: Path) -> int:
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        return os.open(parent, directory_flags)

    @staticmethod
    def _require_private_state_directory(directory: int, *, context: str) -> None:
        metadata = os.fstat(directory)
        if not _has_private_directory_metadata(metadata):
            msg = f"{context} requires a service-owned private directory"
            raise ValueError(msg)

    @staticmethod
    def _prepare_created_state_directory(
        parent: Path,
        before: os.stat_result,
    ) -> os.stat_result:
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_gid != os.getegid()
        ):
            msg = "new clock state parent is not service-owned"
            raise ValueError(msg)
        expected_identity = (before.st_dev, before.st_ino)
        parent.chmod(
            _PRIVATE_STATE_DIRECTORY_MODE,
            follow_symlinks=False,
        )
        prepared = parent.lstat()
        if (
            prepared.st_dev,
            prepared.st_ino,
        ) != expected_identity or not _has_private_directory_metadata(prepared):
            msg = "new clock state parent private postcondition failed"
            raise ValueError(msg)
        return prepared

    def _open_locked_state_directory(self) -> int:
        """Open and exclusively lock the exact service-private parent directory."""
        name = self._path.name
        if name in {"", ".", ".."}:
            msg = "clock state path must have a safe basename"
            raise ValueError(msg)
        parent = self._path.parent
        try:
            before = parent.lstat()
        except FileNotFoundError as error:
            try:
                parent.mkdir(mode=_PRIVATE_STATE_DIRECTORY_MODE)
                created = True
            except FileNotFoundError:
                msg = "clock state parent creation requires an existing ancestor"
                raise ValueError(msg) from error
            except FileExistsError:
                created = False
            before = parent.lstat()
        else:
            created = False
        if created:
            before = self._prepare_created_state_directory(parent, before)
        elif not _has_private_directory_metadata(before):
            msg = "clock state parent must be a service-owned private directory"
            raise ValueError(msg)
        directory = self._open_state_directory(parent)
        try:
            inheritable = False
            os.set_inheritable(directory, inheritable)
            fcntl.flock(directory, fcntl.LOCK_EX)
            self._validate_locked_state_directory(directory, parent, before)
        except (OSError, ValueError):
            os.close(directory)
            raise
        return directory

    @staticmethod
    def _validate_locked_state_directory(
        directory: int,
        parent: Path,
        before: os.stat_result,
    ) -> None:
        opened = os.fstat(directory)
        named = parent.lstat()
        expected_identity = (before.st_dev, before.st_ino)
        if (
            not _has_private_directory_metadata(opened)
            or not _has_private_directory_metadata(named)
            or (opened.st_dev, opened.st_ino) != expected_identity
            or (named.st_dev, named.st_ino) != expected_identity
            or os.get_inheritable(directory)
        ):
            msg = "clock state parent private directory identity changed"
            raise ValueError(msg)

    @staticmethod
    def _close_locked_state_directory(directory: int) -> None:
        try:
            fcntl.flock(directory, fcntl.LOCK_UN)
        finally:
            os.close(directory)

    @staticmethod
    def _validate_write_target_at(
        directory: int,
        name: str,
        *,
        require_absent: bool,
    ) -> None:
        try:
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(current.st_mode):
            msg = "clock state path must not be a symlink"
            raise ValueError(msg)
        if require_absent:
            msg = "clock state path changed before exclusive creation"
            raise ValueError(msg)
        if not _has_private_state_metadata(current):
            msg = "clock state path is not a private regular file"
            raise ValueError(msg)

    def _create_temporary_state_at(
        self,
        directory: int,
        name: str,
        raw: bytes,
    ) -> _PrivateStateSnapshot:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            create_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        descriptor = os.open(name, create_flags, 0o600, dir_fd=directory)
        created: _PrivateStateSnapshot | None = None
        try:
            try:
                created = _PrivateStateSnapshot.capture(os.fstat(descriptor), raw=b"")
                _prepare_private_state_descriptor(descriptor, context="clock state")
                _write_all_descriptor(
                    descriptor,
                    raw,
                    context="clock state",
                )
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                if not _has_private_state_metadata(metadata) or metadata.st_size != len(
                    raw
                ):
                    msg = "clock state write postcondition failed"
                    raise ValueError(msg)
                final_snapshot = _PrivateStateSnapshot.capture(metadata, raw=raw)
                created = final_snapshot
                return final_snapshot
            finally:
                os.close(descriptor)
        except (OSError, ValueError):
            if created is not None:
                self._unlink_if_same_inode_at(directory, name, created)
            raise

    def _publish_temporary_state_at(
        self,
        directory: int,
        *,
        temporary_name: str,
        name: str,
        created: _PrivateStateSnapshot,
        require_absent: bool,
    ) -> None:
        if require_absent:
            self._validate_write_target_at(
                directory,
                name,
                require_absent=True,
            )
        self._require_private_state_directory(
            directory,
            context="clock state publication",
        )
        os.rename(
            temporary_name,
            name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        active = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not created.matches_published_content(active):
            msg = "clock state publication identity changed"
            raise ValueError(msg)
        os.fsync(directory)

    def _write(
        self,
        directory: int,
        record: _ClockHighWaterRecord,
        *,
        require_absent: bool = False,
    ) -> None:
        name = self._path.name
        if name in {"", ".", ".."}:
            msg = "clock state path must have a safe basename"
            raise ValueError(msg)
        raw = _canonical_json_bytes(cast("JsonObject", record.model_dump(mode="json")))
        temporary_name = f".{name}.tmp-{secrets.token_hex(16)}"
        self._validate_write_target_at(
            directory,
            name,
            require_absent=require_absent,
        )
        created = self._create_temporary_state_at(
            directory,
            temporary_name,
            raw,
        )
        try:
            self._publish_temporary_state_at(
                directory,
                temporary_name=temporary_name,
                name=name,
                created=created,
                require_absent=require_absent,
            )
        except (OSError, ValueError):
            self._unlink_if_same_inode_at(directory, temporary_name, created)
            raise

    @staticmethod
    def _assessment(*, trusted: bool, blocker: ClockBlocker | None) -> ClockAssessment:
        return ClockAssessment(
            trusted=trusted,
            age_deletion_allowed=trusted,
            blocker=blocker,
        )

    def _baseline(
        self,
        directory: int,
        sample: RetentionClockSample,
        *,
        blocker: ClockBlocker,
        require_absent: bool = False,
    ) -> ClockAssessment:
        healthy_since = sample.monotonic_now if sample.synchronized else None
        self._write(
            directory,
            _clock_record(
                _ClockRecordInput(
                    boot_id=sample.boot_id,
                    utc_high_water=sample.utc_now,
                    last_observed_utc=sample.utc_now,
                    last_monotonic=sample.monotonic_now,
                    healthy_since_monotonic=healthy_since,
                    trusted=False,
                )
            ),
            require_absent=require_absent,
        )
        return self._assessment(trusted=False, blocker=blocker)

    def observe(self, sample: RetentionClockSample) -> ClockAssessment:
        """Persist one observation and fail closed on rollback or restart drift."""
        with self._transition_lock:
            if self._transition_active:
                msg = "clock high-water observation is already in progress"
                raise RuntimeError(msg)
            self._transition_active = True
            try:
                directory = self._open_locked_state_directory()
                try:
                    return self._observe_locked(directory, sample)
                finally:
                    self._close_locked_state_directory(directory)
            finally:
                self._transition_active = False

    def _observe_absent_state(
        self,
        directory: int,
        sample: RetentionClockSample,
        *,
        blocker: ClockBlocker | None,
        recoverable_state: _PrivateStateSnapshot | None,
    ) -> ClockAssessment:
        if blocker is not ClockBlocker.CORRUPT_STATE:
            return self._baseline(
                directory,
                sample,
                blocker=blocker or ClockBlocker.CORRUPT_STATE,
                require_absent=True,
            )
        if recoverable_state is not None and self._quarantine_corrupt_state(
            directory,
            recoverable_state,
        ):
            return self._baseline(
                directory,
                sample,
                blocker=ClockBlocker.CORRUPT_STATE,
                require_absent=True,
            )
        return self._assessment(
            trusted=False,
            blocker=ClockBlocker.CORRUPT_STATE,
        )

    def _observe_locked(
        self,
        directory: int,
        sample: RetentionClockSample,
    ) -> ClockAssessment:
        """Apply one serialized high-water transition."""
        record, state_blocker, recoverable_state = self._read(directory)
        if record is None:
            return self._observe_absent_state(
                directory,
                sample,
                blocker=state_blocker,
                recoverable_state=recoverable_state,
            )
        if not sample.synchronized:
            self._write(
                directory,
                _clock_record(
                    _ClockRecordInput(
                        boot_id=record.boot_id,
                        utc_high_water=max(record.utc_high_water, sample.utc_now),
                        last_observed_utc=sample.utc_now,
                        last_monotonic=max(
                            record.last_monotonic,
                            sample.monotonic_now,
                        ),
                        healthy_since_monotonic=None,
                        trusted=False,
                    )
                ),
            )
            return self._assessment(
                trusted=False,
                blocker=ClockBlocker.UNSYNCHRONIZED,
            )
        if sample.boot_id != record.boot_id:
            return self._baseline(
                directory,
                sample,
                blocker=ClockBlocker.BOOT_CHANGED,
            )
        if sample.monotonic_now < record.last_monotonic:
            self._write(
                directory,
                _clock_record(
                    _ClockRecordInput(
                        boot_id=record.boot_id,
                        utc_high_water=max(record.utc_high_water, sample.utc_now),
                        last_observed_utc=sample.utc_now,
                        last_monotonic=sample.monotonic_now,
                        healthy_since_monotonic=None,
                        trusted=False,
                    )
                ),
            )
            return self._assessment(
                trusted=False,
                blocker=ClockBlocker.MONOTONIC_ROLLBACK,
            )
        monotonic_delta = sample.monotonic_now - record.last_monotonic
        wall_delta = (sample.utc_now - record.last_observed_utc).total_seconds()
        if wall_delta < 0:
            blocker = ClockBlocker.WALL_ROLLBACK
        elif wall_delta > monotonic_delta + self._maximum_forward_slew_seconds:
            blocker = ClockBlocker.FORWARD_STEP
        else:
            blocker = None
        if blocker is not None:
            self._write(
                directory,
                _clock_record(
                    _ClockRecordInput(
                        boot_id=record.boot_id,
                        utc_high_water=max(record.utc_high_water, sample.utc_now),
                        last_observed_utc=sample.utc_now,
                        last_monotonic=sample.monotonic_now,
                        healthy_since_monotonic=None,
                        trusted=False,
                    )
                ),
            )
            return self._assessment(trusted=False, blocker=blocker)
        healthy_since = record.healthy_since_monotonic
        if healthy_since is None:
            healthy_since = sample.monotonic_now
        trusted = record.trusted or (
            sample.monotonic_now - healthy_since >= self._healthy_window_seconds
        )
        self._write(
            directory,
            _clock_record(
                _ClockRecordInput(
                    boot_id=record.boot_id,
                    utc_high_water=max(record.utc_high_water, sample.utc_now),
                    last_observed_utc=sample.utc_now,
                    last_monotonic=sample.monotonic_now,
                    healthy_since_monotonic=healthy_since,
                    trusted=trusted,
                )
            ),
        )
        return self._assessment(
            trusted=trusted,
            blocker=None if trusted else ClockBlocker.WARMING_UP,
        )


def _read_private_record(path: Path) -> bytes | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not _has_private_state_metadata(metadata)
        or metadata.st_size < _MIN_JSON_OBJECT_BYTES
        or metadata.st_size > _INSERTION_STATE_MAX_BYTES
    ):
        msg = "insertion-order state is not a safe regular file"
        raise ValueError(msg)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ) or not _has_private_state_metadata(opened):
            msg = "insertion-order state identity changed while opening"
            raise ValueError(msg)
        raw = os.read(descriptor, _INSERTION_STATE_MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size or len(raw) > _INSERTION_STATE_MAX_BYTES:
        msg = "insertion-order state changed or exceeded its bound"
        raise ValueError(msg)
    try:
        _ = cast(
            "object",
            json.loads(raw, object_pairs_hook=_reject_duplicate_keys),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        msg = "insertion-order state is not valid strict JSON"
        raise ValueError(msg) from exc
    return raw


def _write_private_record(path: Path, record: StrictModel) -> None:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        msg = "insertion-order state parent must be a trusted directory"
        raise ValueError(msg)
    if path.is_symlink():
        msg = "insertion-order state path must not be a symlink"
        raise ValueError(msg)
    raw = _canonical_json_bytes(cast("JsonObject", record.model_dump(mode="json")))
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(16)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        try:
            _prepare_private_state_descriptor(
                descriptor,
                context="insertion-order state",
            )
            offset = 0
            while offset < len(raw):
                offset += os.write(descriptor, raw[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _ = temporary.replace(path)
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _insertion_object_key(item: tuple[str, Path]) -> str:
    return item[0]


class PersistentInsertionOrder:
    """Persist one monotonic quota-eviction sequence per artifact object."""

    def __init__(self, root: Path) -> None:
        """Bind the already validated store root."""
        super().__init__()
        if root.is_symlink() or not root.is_dir():
            msg = "insertion-order root must be a trusted directory"
            raise ValueError(msg)
        self._root = root
        self._high_water_path = root / INSERTION_HIGH_WATER_FILENAME
        self._next_sequence = 1
        self._sequences: dict[str, int] = {}

    def _validated_object_path(self, key: str, path: Path) -> Path:
        record = InsertionSequenceRecord.build(object_key=key, sequence=1)
        del record
        namespace, object_id = key.split("/", maxsplit=1)
        expected = self._root / namespace / object_id
        if path != expected or path.is_symlink() or not path.is_dir():
            msg = "insertion-order object path does not match its key"
            raise ValueError(msg)
        return path

    def _write_high_water(self, next_sequence: int) -> None:
        record = InsertionHighWaterRecord.build(next_sequence=next_sequence)
        _write_private_record(self._high_water_path, record)
        self._next_sequence = next_sequence

    def _allocate(self, key: str, path: Path) -> int:
        path = self._validated_object_path(key, path)
        if self._next_sequence >= _MAX_FILESYSTEM_COUNT:
            msg = "insertion-order sequence space is exhausted"
            raise ValueError(msg)
        sequence = self._next_sequence
        self._write_high_water(sequence + 1)
        record = InsertionSequenceRecord.build(
            object_key=key,
            sequence=sequence,
        )
        _write_private_record(path / INSERTION_SEQUENCE_FILENAME, record)
        self._sequences[key] = sequence
        return sequence

    def _load_object_sequence(self, key: str, object_path: Path) -> int:
        object_path = self._validated_object_path(key, object_path)
        raw = _read_private_record(object_path / INSERTION_SEQUENCE_FILENAME)
        if raw is None:
            return self._allocate(key, object_path)
        try:
            record = InsertionSequenceRecord.model_validate_json(
                raw,
                strict=True,
            )
        except ValidationError as exc:
            msg = "artifact insertion sequence state is invalid"
            raise ValueError(msg) from exc
        if record.object_key != key or record.sequence >= self._next_sequence:
            msg = "artifact insertion sequence is not bound below high-water"
            raise ValueError(msg)
        self._sequences[key] = record.sequence
        return record.sequence

    def initialize(self, objects: tuple[tuple[str, Path], ...]) -> None:
        """Load, reconcile, and strictly validate every persisted sequence."""
        if tuple(sorted(objects, key=_insertion_object_key)) != objects:
            msg = "insertion-order bootstrap objects must be canonical"
            raise ValueError(msg)
        if len({key for key, _path in objects}) != len(objects):
            msg = "insertion-order bootstrap contains duplicate object keys"
            raise ValueError(msg)
        high_water_raw = _read_private_record(self._high_water_path)
        if high_water_raw is None:
            if any(
                (path / INSERTION_SEQUENCE_FILENAME).exists() for _key, path in objects
            ):
                msg = "insertion high-water state is missing"
                raise ValueError(msg)
            self._write_high_water(1)
        else:
            try:
                high_water = InsertionHighWaterRecord.model_validate_json(
                    high_water_raw,
                    strict=True,
                )
            except ValidationError as exc:
                msg = "insertion high-water state is invalid"
                raise ValueError(msg) from exc
            self._next_sequence = high_water.next_sequence
        used_sequences: set[int] = set()
        for key, object_path in objects:
            sequence = self._load_object_sequence(key, object_path)
            if sequence in used_sequences:
                msg = "artifact insertion sequences must be unique"
                raise ValueError(msg)
            used_sequences.add(sequence)

    def ensure(self, key: str, path: Path) -> int:
        """Return an existing sequence or durably allocate the next one."""
        path = self._validated_object_path(key, path)
        existing = self._sequences.get(key)
        if existing is not None:
            return existing
        return self._allocate(key, path)

    def sequence_for(self, key: str) -> int:
        """Return the initialized sequence for one current object."""
        try:
            return self._sequences[key]
        except KeyError as exc:
            msg = "artifact object has no initialized insertion sequence"
            raise ValueError(msg) from exc

    def remove(self, key: str) -> None:
        """Forget one removed object's in-memory sequence."""
        if key in self._sequences:
            del self._sequences[key]
