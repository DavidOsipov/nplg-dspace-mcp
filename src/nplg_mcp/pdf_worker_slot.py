# Copyright (c) 2026 David Osipov
"""Validation for the dedicated PDF worker filesystem slot.

The private worker is deliberately given a separate filesystem rather than a
subdirectory of the application's content-addressed cache.  The host owns the
actual ext4 allocation; this module verifies that the mounted slot still
matches the reviewed policy before the parent dispatches any untrusted PDF.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from threading import Lock, Thread, current_thread
from typing import TYPE_CHECKING, Protocol, Self, cast
from weakref import WeakSet

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictInt,
    StrictStr,
    ValidationInfo,
    field_validator,
)

_REQUIRED_MOUNT_OPTIONS = frozenset({"rw", "nodev", "nosuid", "noexec"})
_MAX_POLICY_BYTES = 16 * 1024
_MIN_JSON_OBJECT_BYTES = 2
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

if TYPE_CHECKING:
    from types import TracebackType


class PdfWorkerSlotError(RuntimeError):
    """The dedicated worker slot does not meet its reviewed security policy."""


class PdfWorkerSlotPolicy(BaseModel):
    """Strict, checked-in capacity and mount policy for one worker slot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: StrictInt
    root: StrictStr
    filesystem_type: StrictStr
    maximum_total_bytes: StrictInt
    minimum_available_bytes: StrictInt
    maximum_total_inodes: StrictInt
    minimum_available_inodes: StrictInt
    mount_options: tuple[StrictStr, ...]
    concurrency: StrictInt

    @field_validator("version")
    @classmethod
    def _require_version_one(cls, value: int) -> int:
        if value != 1:
            message = "PDF worker slot policy version must equal 1"
            raise ValueError(message)
        return value

    @field_validator("root")
    @classmethod
    def _require_absolute_root(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute() or str(path) != value or "\x00" in value:
            message = "PDF worker slot root must be a canonical absolute path"
            raise ValueError(message)
        return value

    @field_validator("filesystem_type")
    @classmethod
    def _require_ext4(cls, value: str) -> str:
        if value != "ext4":
            message = "PDF worker slot filesystem type must be ext4"
            raise ValueError(message)
        return value

    @field_validator(
        "maximum_total_bytes",
        "minimum_available_bytes",
        "maximum_total_inodes",
        "minimum_available_inodes",
    )
    @classmethod
    def _require_positive_capacity(cls, value: int) -> int:
        if type(value) is not int or value <= 0:
            message = "PDF worker slot capacities must be positive integers"
            raise ValueError(message)
        return value

    @field_validator("mount_options", mode="before")
    @classmethod
    def _require_json_option_array(cls, value: object) -> tuple[object, ...]:
        if type(value) is not list:
            message = "PDF worker slot mount options must be a JSON array"
            raise ValueError(message)
        return tuple(cast("list[object]", value))

    @field_validator("mount_options")
    @classmethod
    def _require_exact_mount_options(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if frozenset(value) != _REQUIRED_MOUNT_OPTIONS or len(value) != len(
            _REQUIRED_MOUNT_OPTIONS
        ):
            message = "PDF worker slot mount options are not the reviewed set"
            raise ValueError(message)
        return value

    @field_validator("concurrency")
    @classmethod
    def _require_serial_execution(cls, value: int) -> int:
        if value != 1:
            message = "PDF worker slot concurrency must equal 1"
            raise ValueError(message)
        return value

    @field_validator("minimum_available_bytes")
    @classmethod
    def _require_byte_headroom_not_over_capacity(
        cls, value: int, info: ValidationInfo[object]
    ) -> int:
        values = cast("dict[str, object]", info.data)
        maximum = values.get("maximum_total_bytes")
        if type(maximum) is int and value > maximum:
            message = "PDF worker slot byte headroom exceeds total capacity"
            raise ValueError(message)
        return value

    @field_validator("minimum_available_inodes")
    @classmethod
    def _require_inode_headroom_not_over_capacity(
        cls, value: int, info: ValidationInfo[object]
    ) -> int:
        values = cast("dict[str, object]", info.data)
        maximum = values.get("maximum_total_inodes")
        if type(maximum) is int and value > maximum:
            message = "PDF worker slot inode headroom exceeds total capacity"
            raise ValueError(message)
        return value


class WorkerSlotFilesystem(BaseModel):
    """One validated filesystem observation used for slot admission."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    filesystem_type: StrictStr
    mount_options: frozenset[StrictStr]
    total_bytes: StrictInt
    available_bytes: StrictInt
    total_inodes: StrictInt
    available_inodes: StrictInt

    @field_validator(
        "total_bytes",
        "available_bytes",
        "total_inodes",
        "available_inodes",
    )
    @classmethod
    def _require_nonnegative_integer(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            message = "worker slot filesystem metrics must be non-negative integers"
            raise ValueError(message)
        return value


class WorkerSlotFilesystemInspector(Protocol):
    """Inject filesystem observation in tests without weakening production checks."""

    def inspect(self, root: Path) -> WorkerSlotFilesystem:
        """Return a complete observation for the configured mountpoint."""
        raise NotImplementedError


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build one JSON object while refusing duplicate-key ambiguity."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = "PDF worker slot policy contains duplicate JSON keys"
            raise PdfWorkerSlotError(message)
        result[key] = value
    return result


def load_pdf_worker_slot_policy(path: Path) -> PdfWorkerSlotPolicy:
    """Load one bounded, regular, immutable JSON policy without link following."""
    if not path.is_absolute() or "\x00" in str(path):
        message = "PDF worker slot policy path is invalid"
        raise PdfWorkerSlotError(message)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        message = "PDF worker slot policy cannot be opened safely"
        raise PdfWorkerSlotError(message) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or metadata.st_size < _MIN_JSON_OBJECT_BYTES
            or metadata.st_size > _MAX_POLICY_BYTES
        ):
            message = "PDF worker slot policy is not a safe regular file"
            raise PdfWorkerSlotError(message)
        payload = bytearray()
        while len(payload) <= _MAX_POLICY_BYTES:
            chunk = os.read(descriptor, _MAX_POLICY_BYTES + 1 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != metadata.st_size or len(payload) > _MAX_POLICY_BYTES:
            message = "PDF worker slot policy changed or exceeded its size limit"
            raise PdfWorkerSlotError(message)
    finally:
        os.close(descriptor)
    try:
        decoded = bytes(payload).decode("utf-8")
        document = cast(
            "object", json.loads(decoded, object_pairs_hook=_reject_duplicate_json_keys)
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        message = "PDF worker slot policy is not valid JSON"
        raise PdfWorkerSlotError(message) from exc
    if type(document) is not dict:
        message = "PDF worker slot policy root must be a JSON object"
        raise PdfWorkerSlotError(message)
    policy_document = cast("dict[str, object]", document)
    try:
        return PdfWorkerSlotPolicy.model_validate(policy_document, strict=True)
    except ValueError as exc:
        message = "PDF worker slot policy does not meet the strict schema"
        raise PdfWorkerSlotError(message) from exc


@dataclass(frozen=True, slots=True)
class QuotaBoundStagingRoot:
    """A slot root whose filesystem capacity passed policy validation."""

    path: Path
    policy: PdfWorkerSlotPolicy


@dataclass(frozen=True, slots=True, init=False)
class DirectoryFd:
    """Opaque, validated directory descriptor for descriptor-relative traversal."""

    _value: int
    _device: int

    @property
    def fileno(self) -> int:
        """Return the validated descriptor only to trusted local helpers."""
        return self._value

    @property
    def device(self) -> int:
        """Return the filesystem device recorded during descriptor validation."""
        return self._device

    def close(self) -> None:
        """Close the owned descriptor; callers cannot replace its integer value."""
        os.close(self._value)

    def __enter__(self) -> Self:
        """Permit one scoped descriptor-relative operation."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the descriptor regardless of the nested operation's result."""
        del exc_type, exc_value, traceback
        self.close()


def _directory_fd_from_validated(descriptor: int, *, device: int) -> DirectoryFd:
    """Construct an opaque descriptor after the private validation helper succeeds."""
    instance = object.__new__(DirectoryFd)
    object.__setattr__(instance, "_value", descriptor)
    object.__setattr__(instance, "_device", device)
    return instance


def validate_safe_path_segment(value: object) -> str:
    """Accept one bounded ASCII child name, never a path or dot component."""
    if (
        type(value) is not str
        or value in {".", ".."}
        or _SAFE_PATH_SEGMENT.fullmatch(value) is None
    ):
        message = "PDF worker slot child name is invalid"
        raise PdfWorkerSlotError(message)
    return value


def _validated_directory_from_descriptor(
    raw_descriptor: int,
    *,
    directory_fd: DirectoryFd | None,
) -> DirectoryFd:
    """Validate a newly opened descriptor before allowing relative traversal."""
    if type(raw_descriptor) is not int or raw_descriptor < 0:
        message = "PDF worker slot directory descriptor is invalid"
        raise PdfWorkerSlotError(message)
    if os.get_inheritable(raw_descriptor):
        message = "PDF worker slot directory descriptor is inheritable"
        raise PdfWorkerSlotError(message)
    metadata = os.fstat(raw_descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        message = "PDF worker slot target is not a safe directory"
        raise PdfWorkerSlotError(message)
    if directory_fd is not None and metadata.st_dev != directory_fd.device:
        message = "PDF worker slot child directory is on another device"
        raise PdfWorkerSlotError(message)
    return _directory_fd_from_validated(raw_descriptor, device=metadata.st_dev)


def _open_validated_directory(
    path: str | Path,
    *,
    directory_fd: DirectoryFd | None = None,
) -> DirectoryFd:
    """Open one non-symlinked directory and close the fd on every failed check."""
    nofollow = cast("object", getattr(os, "O_NOFOLLOW", None))
    if type(nofollow) is not int:
        message = "PDF worker slot requires O_NOFOLLOW support"
        raise PdfWorkerSlotError(message)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow
    try:
        if directory_fd is None:
            raw_descriptor = os.open(path, flags)
        else:
            raw_descriptor = os.open(path, flags, dir_fd=directory_fd.fileno)
    except OSError as exc:
        message = "PDF worker slot directory cannot be opened safely"
        raise PdfWorkerSlotError(message) from exc
    try:
        return _validated_directory_from_descriptor(
            raw_descriptor,
            directory_fd=directory_fd,
        )
    except BaseException:
        os.close(raw_descriptor)
        raise


def _validate_root_descriptor_metadata(metadata: os.stat_result) -> None:
    """Require the application identity and private directory mode at startup."""
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        message = "PDF worker slot root directory ownership or mode is unsafe"
        raise PdfWorkerSlotError(message)


def open_configured_root_fd(policy: PdfWorkerSlotPolicy) -> DirectoryFd:
    """Open the policy root without allowing a final-component symlink swap."""
    descriptor = _open_validated_directory(Path(policy.root))
    try:
        _validate_root_descriptor_metadata(os.fstat(descriptor.fileno))
    except BaseException:
        descriptor.close()
        raise
    return descriptor


def open_child_directory_fd(parent: DirectoryFd, name: object) -> DirectoryFd:
    """Open one same-filesystem child through a validated parent descriptor."""
    if type(parent) is not DirectoryFd:
        message = "PDF worker slot parent descriptor is invalid"
        raise PdfWorkerSlotError(message)
    return _open_validated_directory(
        validate_safe_path_segment(name),
        directory_fd=parent,
    )


class _WorkerSlotLeaseState(Enum):
    ISSUED = "issued"
    ENTERED = "entered"


def _current_async_task() -> object | None:
    """Return the exact running task, or no task in synchronous code."""
    try:
        return cast("object | None", asyncio.current_task())
    except RuntimeError:
        return None


class WorkerSlotLease:
    """One non-transferable reservation of the complete worker slot."""

    def __init__(
        self,
        *,
        quota: WorkerStagingQuota,
        root: QuotaBoundStagingRoot,
    ) -> None:
        """Bind this lease to the only quota instance allowed to release it."""
        super().__init__()
        self._quota = quota
        self._root = root

    def __enter__(self) -> QuotaBoundStagingRoot:
        """Expose the verified root only while the parent owns this lease."""
        return self._quota.enter(self)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release capacity on success, failure, or cancellation unwinding."""
        del exc_type, exc_value, traceback
        self.release()

    def release(self) -> None:
        """Release the single slot exactly once."""
        self._quota.release(self)


class WorkerStagingQuota:
    """Lease a dedicated filesystem as one complete, serialized worker quota."""

    def __init__(
        self,
        *,
        policy: PdfWorkerSlotPolicy,
        inspector: WorkerSlotFilesystemInspector | None = None,
    ) -> None:
        """Validate the fixed slot once at startup before accepting any dispatch."""
        super().__init__()
        self._policy = policy
        self._inspector = inspector
        self._lock = Lock()
        self._active_lease: WorkerSlotLease | None = None
        self._active_lease_state: _WorkerSlotLeaseState | None = None
        self._active_owner_thread: Thread | None = None
        self._active_owner_task: object | None = None
        self._released_leases: WeakSet[WorkerSlotLease] = WeakSet()
        if self._inspector is None:
            with open_configured_root_fd(self._policy):
                pass
        self._root = validate_quota_bound_staging_root(
            self._policy,
            inspector=self._inspector,
        )

    @property
    def root(self) -> QuotaBoundStagingRoot:
        """Return the root whose initial startup validation succeeded."""
        return self._root

    def lease(self) -> WorkerSlotLease:
        """Reserve the whole verified slot before handing it to the worker."""
        with self._lock:
            if self._active_lease is not None:
                message = "PDF worker slot is already leased"
                raise PdfWorkerSlotError(message)
            root = validate_quota_bound_staging_root(
                self._policy,
                inspector=self._inspector,
            )
            lease = WorkerSlotLease(quota=self, root=root)
            self._active_lease = lease
            self._active_lease_state = _WorkerSlotLeaseState.ISSUED
            self._active_owner_thread = current_thread()
            self._active_owner_task = _current_async_task()
            return lease

    def enter(self, lease: WorkerSlotLease) -> QuotaBoundStagingRoot:
        """Return the root only for the exact live lease issued by this quota."""
        with self._lock:
            if type(lease) is not WorkerSlotLease:
                message = "PDF worker slot lease is invalid"
                raise PdfWorkerSlotError(message)
            if lease in self._released_leases:
                message = "PDF worker slot lease was already released"
                raise PdfWorkerSlotError(message)
            if self._active_lease is not lease:
                message = "PDF worker slot lease is invalid"
                raise PdfWorkerSlotError(message)
            self._require_owner_context()
            if self._active_lease_state is _WorkerSlotLeaseState.ENTERED:
                message = "PDF worker slot lease is already entered"
                raise PdfWorkerSlotError(message)
            if self._active_lease_state is not _WorkerSlotLeaseState.ISSUED:
                message = "PDF worker slot lease is invalid"
                raise PdfWorkerSlotError(message)
            self._active_lease_state = _WorkerSlotLeaseState.ENTERED
            return self._root

    def _require_owner_context(self) -> None:
        """Reject transfer away from the exact issuing thread and async task."""
        if (
            self._active_owner_thread is not current_thread()
            or self._active_owner_task is not _current_async_task()
        ):
            message = "PDF worker slot lease belongs to another execution context"
            raise PdfWorkerSlotError(message)

    def release(self, lease: WorkerSlotLease) -> None:
        """Return one slot lease; callers can never underflow the reservation."""
        with self._lock:
            if type(lease) is not WorkerSlotLease:
                message = "PDF worker slot lease is invalid"
                raise PdfWorkerSlotError(message)
            if self._active_lease is lease:
                self._require_owner_context()
                if self._active_lease_state not in {
                    _WorkerSlotLeaseState.ISSUED,
                    _WorkerSlotLeaseState.ENTERED,
                }:
                    message = "PDF worker slot lease is invalid"
                    raise PdfWorkerSlotError(message)
                self._released_leases.add(lease)
                self._active_lease = None
                self._active_lease_state = None
                self._active_owner_thread = None
                self._active_owner_task = None
                return
            if lease not in self._released_leases:
                message = "PDF worker slot lease is invalid"
                raise PdfWorkerSlotError(message)


class _SystemWorkerSlotFilesystemInspector:
    """Read the mount and statvfs facts that constrain the worker slot."""

    def inspect(self, root: Path) -> WorkerSlotFilesystem:
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            message = "PDF worker slot root is not a regular directory"
            raise PdfWorkerSlotError(message)
        mount_options, filesystem_type = _mount_details(root, metadata.st_dev)
        stats = os.statvfs(root)
        return WorkerSlotFilesystem(
            filesystem_type=filesystem_type,
            mount_options=mount_options,
            total_bytes=stats.f_blocks * stats.f_frsize,
            available_bytes=stats.f_bavail * stats.f_frsize,
            total_inodes=stats.f_files,
            available_inodes=stats.f_favail,
        )


def _decode_mountinfo_path(value: str) -> str:
    """Decode only the octal escapes defined by Linux mountinfo."""
    decoded: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 3 < len(value):
            escaped = value[index + 1 : index + 4]
            if escaped.isdigit() and all(
                character in "01234567" for character in escaped
            ):
                decoded.append(chr(int(escaped, 8)))
                index += 4
                continue
        decoded.append(value[index])
        index += 1
    return "".join(decoded)


def _mount_details(root: Path, device: int) -> tuple[frozenset[str], str]:
    """Require that root itself is one mount with no nested mounts below it."""
    expected_device = f"{os.major(device)}:{os.minor(device)}"
    root_text = root.as_posix()
    matches: list[tuple[frozenset[str], str]] = []
    nested_mount = False
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        message = "PDF worker slot mount metadata is unavailable"
        raise PdfWorkerSlotError(message) from exc
    for line in lines:
        fields = line.split(" ")
        try:
            separator = fields.index("-")
            mountpoint = _decode_mountinfo_path(fields[4])
            mount_device = fields[2]
            mount_options = frozenset(fields[5].split(","))
            filesystem_type = fields[separator + 1]
        except (IndexError, ValueError):
            message = "PDF worker slot mount metadata is malformed"
            raise PdfWorkerSlotError(message) from None
        if mountpoint == root_text:
            if mount_device != expected_device:
                message = "PDF worker slot mount device does not match its root"
                raise PdfWorkerSlotError(message)
            matches.append((mount_options, filesystem_type))
        if mountpoint.startswith(f"{root_text}/"):
            nested_mount = True
    if nested_mount or len(matches) != 1:
        message = "PDF worker slot must be exactly one non-nested mount"
        raise PdfWorkerSlotError(message)
    return matches[0]


def validate_quota_bound_staging_root(
    policy: PdfWorkerSlotPolicy,
    *,
    inspector: WorkerSlotFilesystemInspector | None = None,
) -> QuotaBoundStagingRoot:
    """Fail closed unless the dedicated mount still satisfies every limit."""
    root = Path(policy.root)
    observed = (inspector or _SystemWorkerSlotFilesystemInspector()).inspect(root)
    if observed.filesystem_type != policy.filesystem_type:
        message = "PDF worker slot filesystem type does not match policy"
        raise PdfWorkerSlotError(message)
    if not _REQUIRED_MOUNT_OPTIONS.issubset(observed.mount_options):
        message = "PDF worker slot mount options do not match policy"
        raise PdfWorkerSlotError(message)
    if observed.total_bytes != policy.maximum_total_bytes:
        message = "PDF worker slot total byte capacity does not match policy"
        raise PdfWorkerSlotError(message)
    if observed.available_bytes < policy.minimum_available_bytes:
        message = "PDF worker slot available byte headroom is insufficient"
        raise PdfWorkerSlotError(message)
    if observed.total_inodes != policy.maximum_total_inodes:
        message = "PDF worker slot total inode capacity does not match policy"
        raise PdfWorkerSlotError(message)
    if observed.available_inodes < policy.minimum_available_inodes:
        message = "PDF worker slot available inode headroom is insufficient"
        raise PdfWorkerSlotError(message)
    return QuotaBoundStagingRoot(path=root, policy=policy)
