# Copyright (c) 2026 David Osipov
"""Content-addressed local storage with bounded metadata."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import secrets
import shutil
import stat
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path, PurePosixPath
from threading import RLock, current_thread
from typing import TYPE_CHECKING, BinaryIO, Never, Protocol, Self, cast

from .errors import AppError, ErrorCode
from .storage_lifecycle import (
    INSERTION_SEQUENCE_FILENAME,
    ClockHighWater,
    LifecycleAlert,
    LifecycleAlertEvent,
    LifecycleBlocker,
    PersistentInsertionOrder,
    PruneBlocker,
    PruneReport,
    PublicationBlocker,
    PublicationReservationError,
    RetentionClockSample,
    RetentionPolicy,
    SatisfiedPruneReport,
    StorageCapacity,
    UnsatisfiedPruneReport,
    filesystem_capacity,
    validate_retention_capacity,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

_ALLOWED_NAMESPACES = {"documents": "doc", "renders": "rnd"}
_DEFAULT_MAX_BYTES = 20 * 1024 * 1024 * 1024
_RENDER_ID_LENGTH = 36
_MIN_RENDER_SUBTREE_PARTS = 2
_MIN_OBJECT_KEY_PARTS = 2
_SHA256_HEX_LENGTH = 64
_MAX_LIFECYCLE_OBJECTS = 10_000_000
_MAX_ORPHAN_STAGING_ENTRIES = 4_096
_MAX_ORPHAN_STAGING_DEPTH = 8
_MAX_ARTIFACT_TREE_ENTRIES = 10_000_000
_MAX_ARTIFACT_TREE_DEPTH = 16
_MAX_STAGING_ENTRY_NAME_BYTES = 255
_ASCII_CONTROL_LIMIT = 0x20
_ASCII_DELETE = 0x7F
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_STORAGE_ROOT_IDENTITY_ERROR = "Artifact storage root identity is invalid."


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int

    def __post_init__(self) -> None:
        """Reject forged or unusable filesystem identities."""
        if (
            type(self.device) is not int
            or type(self.inode) is not int
            or self.device < 0
            or self.inode < 0
        ):
            msg = "directory identity requires non-negative exact integers"
            raise ValueError(msg)


def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    if not stat.S_ISDIR(metadata.st_mode):
        msg = "storage path must identify a directory"
        raise ValueError(msg)
    return _DirectoryIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _open_verified_directory(
    path: Path | str,
    *,
    directory_fd: int | None = None,
) -> tuple[int, _DirectoryIdentity]:
    """Open one directory without following a swapped or aliased path."""
    before = os.stat(path, dir_fd=directory_fd, follow_symlinks=False)
    expected = _directory_identity(before)
    nofollow = cast("object", getattr(os, "O_NOFOLLOW", None))
    directory_only = cast("object", getattr(os, "O_DIRECTORY", None))
    close_on_exec = cast("object", getattr(os, "O_CLOEXEC", None))
    if (
        type(nofollow) is not int
        or type(directory_only) is not int
        or type(close_on_exec) is not int
    ):
        msg = "storage directory descriptor requires secure open flags"
        raise ValueError(msg)
    flags = os.O_RDONLY | nofollow | directory_only | close_on_exec
    descriptor = os.open(path, flags, dir_fd=directory_fd)
    try:
        opened = _directory_identity(os.fstat(descriptor))
        inheritable = os.get_inheritable(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    if opened != expected or inheritable:
        os.close(descriptor)
        msg = "directory identity changed while opening"
        raise ValueError(msg)
    return descriptor, opened


def _validate_storage_root_parent(path: Path) -> None:
    """Require a real parent chain with protected root-entry replacement."""
    current = Path(path.anchor)
    for component in path.parent.parts[1:]:
        current /= component
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            msg = "cache root parent chain must contain only real directories"
            raise ValueError(msg)
    parent_metadata = path.parent.lstat()
    writable_by_another_principal = bool(parent_metadata.st_mode & 0o022)
    replacement_protected_by_sticky_bit = bool(parent_metadata.st_mode & stat.S_ISVTX)
    if parent_metadata.st_uid not in {0, os.geteuid()} or (
        writable_by_another_principal and not replacement_protected_by_sticky_bit
    ):
        msg = "cache root parent must not be writable by another principal"
        raise ValueError(msg)


def _validate_owned_private_directory(
    descriptor: int,
    *,
    context: str,
    created: bool,
) -> None:
    """Bind a new directory, or reject drift on a pre-existing directory."""
    metadata = os.fstat(descriptor)
    _ = _directory_identity(metadata)
    if metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid():
        msg = f"{context} must be owned by the service process"
        raise ValueError(msg)
    if stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE:
        if not created:
            msg = f"{context} must already have mode 0700"
            raise ValueError(msg)
        os.fchmod(descriptor, _PRIVATE_DIRECTORY_MODE)
        metadata = os.fstat(descriptor)
    if (
        metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        msg = f"{context} did not reach its private ownership and mode postcondition"
        raise ValueError(msg)


def _ensure_private_directory_at(
    name: str,
    *,
    parent_descriptor: int,
    context: str,
) -> None:
    """Create or verify one descriptor-relative service-owned directory."""
    created = False
    try:
        os.mkdir(name, mode=_PRIVATE_DIRECTORY_MODE, dir_fd=parent_descriptor)
        created = True
        os.chmod(
            name,
            _PRIVATE_DIRECTORY_MODE,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileExistsError:
        pass
    try:
        descriptor, _ = _open_verified_directory(
            name,
            directory_fd=parent_descriptor,
        )
        try:
            _validate_owned_private_directory(
                descriptor,
                context=context,
                created=created,
            )
        finally:
            os.close(descriptor)
    except (OSError, ValueError) as exc:
        msg = f"{context} directory is unsafe"
        raise ValueError(msg) from exc


def _ensure_private_directory_path(path: Path, *, context: str) -> None:
    created = False
    try:
        path.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        created = True
        path.chmod(_PRIVATE_DIRECTORY_MODE, follow_symlinks=False)
    except FileExistsError:
        pass
    try:
        descriptor, _ = _open_verified_directory(path)
        try:
            _validate_owned_private_directory(
                descriptor,
                context=context,
                created=created,
            )
        finally:
            os.close(descriptor)
    except (OSError, ValueError) as exc:
        msg = f"{context} directory is unsafe"
        raise ValueError(msg) from exc


def _validate_private_regular_file_at(
    name: str,
    *,
    parent_descriptor: int,
    before: os.stat_result,
    context: str,
) -> None:
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_gid != os.getegid()
        or stat.S_IMODE(before.st_mode) != _PRIVATE_FILE_MODE
    ):
        msg = f"{context} is not a safe private regular file"
        raise ValueError(msg)
    nofollow = cast("object", getattr(os, "O_NOFOLLOW", None))
    close_on_exec = cast("object", getattr(os, "O_CLOEXEC", None))
    if type(nofollow) is not int or type(close_on_exec) is not int:
        msg = f"{context} requires secure file-open flags"
        raise ValueError(msg)
    descriptor = os.open(
        name,
        os.O_RDONLY | nofollow | close_on_exec,
        dir_fd=parent_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or opened.st_gid != os.getegid()
            or stat.S_IMODE(opened.st_mode) != _PRIVATE_FILE_MODE
        ):
            msg = f"{context} identity or private metadata changed while opening"
            raise ValueError(msg)
    finally:
        os.close(descriptor)


def _prepare_private_staged_descriptor(descriptor: int) -> None:
    """Enforce the staged-file metadata postcondition before exposing a stream."""
    os.fchmod(descriptor, _PRIVATE_FILE_MODE)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
    ):
        msg = "staged artifact did not reach its private file postcondition"
        raise ValueError(msg)


def _raise_invalid_asset_path() -> Never:
    raise AppError(ErrorCode.INVALID_INPUT, "Asset path is invalid.")


def _raise_missing_asset() -> Never:
    raise AppError(
        ErrorCode.NOT_FOUND,
        "The requested artifact was not found.",
        http_status=404,
    )


def _raise_corrupt_asset_storage() -> Never:
    raise AppError(
        ErrorCode.INTERNAL_ERROR,
        "Artifact storage is corrupted.",
        http_status=500,
    )


def _validated_asset_parts(relative_path: str) -> tuple[str, ...]:
    if not relative_path or "\\" in relative_path or "\x00" in relative_path:
        _raise_invalid_asset_path()
    pure = PurePosixPath(relative_path)
    if (
        pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != relative_path
    ):
        _raise_invalid_asset_path()
    if not pure.parts or pure.parts[0] not in _ALLOWED_NAMESPACES:
        raise AppError(
            ErrorCode.INVALID_INPUT,
            "Asset path is outside an approved namespace.",
        )
    return pure.parts


def _open_resolved_asset_directory(
    component: str,
    *,
    parent_descriptor: int,
    metadata: os.stat_result,
) -> int:
    if stat.S_ISLNK(metadata.st_mode):
        _raise_invalid_asset_path()
    if not stat.S_ISDIR(metadata.st_mode):
        _raise_missing_asset()
    if (
        metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        _raise_corrupt_asset_storage()
    child_descriptor, _ = _open_verified_directory(
        component,
        directory_fd=parent_descriptor,
    )
    return child_descriptor


def _validate_resolved_asset_file(
    component: str,
    *,
    parent_descriptor: int,
    metadata: os.stat_result,
) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        _raise_invalid_asset_path()
    if not stat.S_ISREG(metadata.st_mode):
        _raise_missing_asset()
    _validate_private_regular_file_at(
        component,
        parent_descriptor=parent_descriptor,
        before=metadata,
        context="resolved artifact",
    )


def _resolve_private_asset(
    root_descriptor: int,
    root: Path,
    parts: tuple[str, ...],
) -> Path:
    candidate = root
    try:
        descriptor = os.dup(root_descriptor)
        try:
            for component in parts[:-1]:
                metadata = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                child_descriptor = _open_resolved_asset_directory(
                    component,
                    parent_descriptor=descriptor,
                    metadata=metadata,
                )
                parent_descriptor = descriptor
                descriptor = child_descriptor
                os.close(parent_descriptor)
                candidate /= component
            final_component = parts[-1]
            final_metadata = os.stat(
                final_component,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            _validate_resolved_asset_file(
                final_component,
                parent_descriptor=descriptor,
                metadata=final_metadata,
            )
            return candidate / final_component
        finally:
            os.close(descriptor)
    except FileNotFoundError as exc:
        try:
            _raise_missing_asset()
        except AppError as missing:
            raise missing from exc
    except (OSError, ValueError) as exc:
        try:
            _raise_corrupt_asset_storage()
        except AppError as corrupt:
            raise corrupt from exc


def _validate_artifact_directory(
    descriptor: int,
    *,
    depth: int,
    entry_count: list[int],
) -> None:
    if depth > _MAX_ARTIFACT_TREE_DEPTH:
        msg = "pre-existing artifact tree exceeded its depth bound"
        raise ValueError(msg)
    with os.scandir(descriptor) as entries:
        for entry in entries:
            entry_count[0] += 1
            if entry_count[0] > _MAX_ARTIFACT_TREE_ENTRIES:
                msg = "pre-existing artifact tree exceeded its entry bound"
                raise ValueError(msg)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                if (
                    metadata.st_uid != os.geteuid()
                    or metadata.st_gid != os.getegid()
                    or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
                ):
                    msg = "pre-existing artifact tree directory is not private"
                    raise ValueError(msg)
                child_descriptor, _ = _open_verified_directory(
                    entry.name,
                    directory_fd=descriptor,
                )
                try:
                    _validate_owned_private_directory(
                        child_descriptor,
                        context="pre-existing artifact tree",
                        created=False,
                    )
                    _validate_artifact_directory(
                        child_descriptor,
                        depth=depth + 1,
                        entry_count=entry_count,
                    )
                finally:
                    os.close(child_descriptor)
            elif stat.S_ISREG(metadata.st_mode):
                _validate_private_regular_file_at(
                    entry.name,
                    parent_descriptor=descriptor,
                    before=metadata,
                    context="pre-existing artifact tree file",
                )
            else:
                msg = "pre-existing artifact tree contains a link or special file"
                raise ValueError(msg)


def _validate_preexisting_artifact_tree(root_descriptor: int) -> None:
    """Reject untrusted restored state before cleanup or accounting."""
    try:
        entry_count = [0]
        for namespace in sorted(_ALLOWED_NAMESPACES):
            namespace_descriptor, _ = _open_verified_directory(
                namespace,
                directory_fd=root_descriptor,
            )
            try:
                _validate_artifact_directory(
                    namespace_descriptor,
                    depth=0,
                    entry_count=entry_count,
                )
            finally:
                os.close(namespace_descriptor)
    except (OSError, ValueError) as exc:
        msg = "pre-existing artifact tree is unsafe"
        raise ValueError(msg) from exc


@dataclass(frozen=True, slots=True)
class _OrphanStagingEntry:
    name: str
    identity: _DirectoryIdentity
    is_directory: bool
    children: tuple[_OrphanStagingEntry, ...] = ()


@dataclass(slots=True)
class _StagingRecoveryBudget:
    root_device: int
    maximum_bytes: int
    entries: int = 0
    bytes: int = 0

    def consume(self, metadata: os.stat_result) -> None:
        """Account one validated node before any orphan is deleted."""
        self.entries += 1
        if self.entries > _MAX_ORPHAN_STAGING_ENTRIES:
            msg = "cache staging recovery inventory exceeds its entry bound"
            raise ValueError(msg)
        if stat.S_ISREG(metadata.st_mode):
            self.bytes += metadata.st_size
            if self.bytes > self.maximum_bytes:
                msg = "cache staging recovery byte inventory exceeds max_bytes"
                raise ValueError(msg)


def _validate_staging_entry_name(name: str) -> None:
    encoded = os.fsencode(name)
    if (
        not name
        or name in {".", ".."}
        or len(encoded) > _MAX_STAGING_ENTRY_NAME_BYTES
        or not name.isascii()
        or any(
            ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE
            for character in name
        )
    ):
        msg = "cache staging recovery entry name is unsafe"
        raise ValueError(msg)


def _regular_file_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        msg = "cache staging recovery rejects non-regular entries"
        raise ValueError(msg)
    return _DirectoryIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _open_verified_regular_file(
    path: str,
    *,
    directory_fd: int,
) -> tuple[int, _DirectoryIdentity]:
    """Open one regular file as metadata without following a raced path."""
    nofollow = cast("object", getattr(os, "O_NOFOLLOW", None))
    metadata_only = cast("object", getattr(os, "O_PATH", None))
    close_on_exec = cast("object", getattr(os, "O_CLOEXEC", None))
    if (
        type(nofollow) is not int
        or type(metadata_only) is not int
        or type(close_on_exec) is not int
    ):
        msg = "cache staging recovery requires secure metadata open flags"
        raise ValueError(msg)
    before = os.stat(path, dir_fd=directory_fd, follow_symlinks=False)
    expected = _regular_file_identity(before)
    flags = metadata_only | nofollow | close_on_exec
    descriptor = os.open(path, flags, dir_fd=directory_fd)
    try:
        opened = _regular_file_identity(os.fstat(descriptor))
        inheritable = os.get_inheritable(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    if opened != expected or inheritable:
        os.close(descriptor)
        msg = "cache staging recovery file identity changed while opening"
        raise ValueError(msg)
    return descriptor, opened


def _inventory_orphan_staging(
    descriptor: int,
    *,
    depth: int,
    budget: _StagingRecoveryBudget,
) -> tuple[_OrphanStagingEntry, ...]:
    entries: list[_OrphanStagingEntry] = []
    # pathlib cannot enumerate without reopening this held descriptor.
    for name in sorted(os.listdir(descriptor)):
        _validate_staging_entry_name(name)
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if metadata.st_dev != budget.root_device:
            msg = "cache staging recovery entry crossed its filesystem boundary"
            raise ValueError(msg)
        budget.consume(metadata)
        if stat.S_ISREG(metadata.st_mode):
            identity = _regular_file_identity(metadata)
            file_descriptor, opened = _open_verified_regular_file(
                name,
                directory_fd=descriptor,
            )
            try:
                if opened != identity:
                    msg = "cache staging recovery file identity changed"
                    raise ValueError(msg)
            finally:
                os.close(file_descriptor)
            entries.append(
                _OrphanStagingEntry(
                    name=name,
                    identity=identity,
                    is_directory=False,
                )
            )
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            msg = "cache staging recovery rejects non-regular entries"
            raise ValueError(msg)
        if depth >= _MAX_ORPHAN_STAGING_DEPTH:
            msg = "cache staging recovery depth exceeds its bound"
            raise ValueError(msg)
        expected = _DirectoryIdentity(
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        child_descriptor, opened = _open_verified_directory(
            name,
            directory_fd=descriptor,
        )
        try:
            if opened != expected:
                msg = "cache staging recovery directory identity changed"
                raise ValueError(msg)
            children = _inventory_orphan_staging(
                child_descriptor,
                depth=depth + 1,
                budget=budget,
            )
        finally:
            os.close(child_descriptor)
        entries.append(
            _OrphanStagingEntry(
                name=name,
                identity=expected,
                is_directory=True,
                children=children,
            )
        )
    return tuple(entries)


def _same_staging_entry(
    metadata: os.stat_result,
    entry: _OrphanStagingEntry,
) -> bool:
    return (
        metadata.st_dev == entry.identity.device
        and metadata.st_ino == entry.identity.inode
        and stat.S_ISDIR(metadata.st_mode) == entry.is_directory
        and (entry.is_directory or stat.S_ISREG(metadata.st_mode))
    )


def _delete_orphan_staging_inventory(
    descriptor: int,
    entries: tuple[_OrphanStagingEntry, ...],
) -> None:
    for entry in entries:
        before = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
        if not _same_staging_entry(before, entry):
            msg = "cache staging recovery entry identity changed before deletion"
            raise ValueError(msg)
        if not entry.is_directory:
            file_descriptor, opened = _open_verified_regular_file(
                entry.name,
                directory_fd=descriptor,
            )
            try:
                current = os.stat(
                    entry.name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if opened != entry.identity or not _same_staging_entry(current, entry):
                    msg = "cache staging recovery entry identity changed before unlink"
                    raise ValueError(msg)
                os.unlink(entry.name, dir_fd=descriptor)
                unlinked = os.fstat(file_descriptor)
                if (
                    not stat.S_ISREG(unlinked.st_mode)
                    or unlinked.st_dev != entry.identity.device
                    or unlinked.st_ino != entry.identity.inode
                    or unlinked.st_nlink != 0
                ):
                    msg = "cache staging recovery path changed during unlink"
                    raise ValueError(msg)
            finally:
                os.close(file_descriptor)
            continue
        child_descriptor, opened = _open_verified_directory(
            entry.name,
            directory_fd=descriptor,
        )
        try:
            if opened != entry.identity:
                msg = (
                    "cache staging recovery directory identity changed before deletion"
                )
                raise ValueError(msg)
            _delete_orphan_staging_inventory(child_descriptor, entry.children)
            with os.scandir(child_descriptor) as remaining_entries:
                directory_changed = next(remaining_entries, None) is not None
            if directory_changed:
                msg = "cache staging recovery directory changed during deletion"
                raise ValueError(msg)
            os.fsync(child_descriptor)
        finally:
            os.close(child_descriptor)
        current = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
        if not _same_staging_entry(current, entry):
            msg = "cache staging recovery directory identity changed before removal"
            raise ValueError(msg)
        os.rmdir(entry.name, dir_fd=descriptor)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        # Directory fsync is not supported by every mounted filesystem; the
        # file move remains atomic even when durability cannot be strengthened.
        pass


def _remove_storage_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def _cleanup_tile_page(page_directory: Path) -> None:
    if page_directory.is_symlink() or not page_directory.is_dir():
        _remove_storage_path(page_directory)
        return
    page_changed = False
    for geometry in tuple(page_directory.iterdir()):
        marker = geometry / "manifest.json"
        if (
            geometry.is_symlink()
            or not geometry.is_dir()
            or marker.is_symlink()
            or not marker.is_file()
        ):
            _remove_storage_path(geometry)
            page_changed = True
    if page_changed:
        _fsync_directory(page_directory)
    with contextlib.suppress(OSError):
        page_directory.rmdir()


def _cleanup_render_tiles(render: Path) -> None:
    tiles = render / "tiles"
    if tiles.is_symlink() or (tiles.exists() and not tiles.is_dir()):
        tiles.unlink(missing_ok=True)
        _fsync_directory(render)
        return
    if not tiles.exists():
        return
    for page_directory in tuple(tiles.iterdir()):
        _cleanup_tile_page(page_directory)
    with contextlib.suppress(OSError):
        tiles.rmdir()


def _path_name(path: Path) -> str:
    return path.name


def _render_completion_exists(completion: Path) -> bool:
    if completion.is_symlink():
        raise AppError(
            ErrorCode.INTERNAL_ERROR,
            "Render storage is corrupted.",
            http_status=500,
        )
    return completion.is_file()


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    """Describe one immutable artifact in the local content-addressed store."""

    object_id: str
    sha256: str
    size: int
    media_type: str
    relative_path: str
    absolute_path: Path


@dataclass(frozen=True, slots=True)
class _StagedSnapshot:
    sha256: str
    size: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True, slots=True)
class _StagedFileCommit:
    namespace: str
    filename: str
    media_type: str
    snapshot: _StagedSnapshot


@dataclass(frozen=True, slots=True)
class _StagedRenderCommit:
    relative_path: str
    snapshot: _StagedSnapshot


@dataclass(frozen=True, slots=True)
class _StagedRenderReplacement:
    relative_path: str
    expected_sha256: str
    snapshot: _StagedSnapshot


@dataclass(frozen=True, slots=True)
class _StagedOperations:
    verify_access: Callable[[], None]
    verify_cleanup: Callable[[], None]
    verify_root: Callable[[], None]
    reserve: Callable[[Path, int], None]
    release: Callable[[Path, int], None]
    commit_file: Callable[[Path, _StagedFileCommit], StoredArtifact]
    commit_render: Callable[[Path, _StagedRenderCommit], tuple[str, str]]
    replace_render: Callable[[Path, _StagedRenderReplacement], tuple[str, str]]
    discard: Callable[[Path], None]


class _LockProtocol(Protocol):
    def acquire(self) -> bool: ...
    def release(self) -> None: ...

    def __enter__(self) -> object: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
        /,
    ) -> None: ...


class _StagedWriter:
    def __init__(
        self, operations: _StagedOperations, path: Path, stream: BinaryIO
    ) -> None:
        super().__init__()
        self._operations = operations
        self._path = path
        self._stream: BinaryIO | None = stream
        self._digest = hashlib.sha256()
        self._size = 0

    def __enter__(self) -> Self:
        self._operations.verify_access()
        if self._stream is None:
            msg = "staged writer is already closed"
            raise RuntimeError(msg)
        return self

    def write(self, data: bytes) -> int:
        self._operations.verify_access()
        if self._stream is None:
            msg = "staged writer is not open"
            raise RuntimeError(msg)
        self._operations.reserve(self._path, len(data))
        try:
            written = self._stream.write(data)
        except BaseException:
            self._operations.release(self._path, len(data))
            raise
        if written != len(data):
            self._operations.release(self._path, len(data) - written)
        self._digest.update(data[:written])
        self._size += written
        return written

    def _snapshot(self) -> _StagedSnapshot:
        self._operations.verify_access()
        if self._stream is None:
            msg = "staged writer is not open"
            raise RuntimeError(msg)
        self._stream.flush()
        os.fsync(self._stream.fileno())
        before = os.fstat(self._stream.fileno())
        digest = hashlib.sha256()
        offset = 0
        while chunk := os.pread(self._stream.fileno(), 1024 * 1024, offset):
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(self._stream.fileno())
        before_fingerprint = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_fingerprint = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_size != self._size
            or offset != self._size
            or before_fingerprint != after_fingerprint
            or digest.digest() != self._digest.digest()
        ):
            raise AppError(
                ErrorCode.INVALID_INPUT, "Staged artifact changed before commit."
            )
        return _StagedSnapshot(
            sha256=digest.hexdigest(),
            size=self._size,
            device=after.st_dev,
            inode=after.st_ino,
            mtime_ns=after.st_mtime_ns,
            ctime_ns=after.st_ctime_ns,
        )

    def commit(
        self, *, namespace: str, filename: str, media_type: str
    ) -> StoredArtifact:
        if self._stream is None:
            msg = "staged writer is not open"
            raise RuntimeError(msg)
        snapshot = self._snapshot()
        try:
            return self._operations.commit_file(
                self._path,
                _StagedFileCommit(
                    namespace=namespace,
                    filename=filename,
                    media_type=media_type,
                    snapshot=snapshot,
                ),
            )
        finally:
            self._stream.close()
            self._stream = None

    def prepare_for_scan(self) -> tuple[Path, str]:
        """Return a stable staged pathname and digest before trusted publication.

        The follow-up ``commit`` repeats the snapshot check, so a scanner cannot
        turn a clean verdict for one byte sequence into publication of another.
        """
        self._operations.verify_root()
        snapshot = self._snapshot()
        return self._path, snapshot.sha256

    def commit_render(self, relative_path: str) -> tuple[str, str]:
        if self._stream is None:
            msg = "staged writer is not open"
            raise RuntimeError(msg)
        snapshot = self._snapshot()
        try:
            return self._operations.commit_render(
                self._path,
                _StagedRenderCommit(
                    relative_path=relative_path,
                    snapshot=snapshot,
                ),
            )
        finally:
            self._stream.close()
            self._stream = None

    def replace_render(
        self,
        relative_path: str,
        *,
        expected_sha256: str,
    ) -> tuple[str, str]:
        if self._stream is None:
            msg = "staged writer is not open"
            raise RuntimeError(msg)
        snapshot = self._snapshot()
        try:
            return self._operations.replace_render(
                self._path,
                _StagedRenderReplacement(
                    relative_path=relative_path,
                    expected_sha256=expected_sha256,
                    snapshot=snapshot,
                ),
            )
        finally:
            self._stream.close()
            self._stream = None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._operations.verify_cleanup()
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        self._operations.discard(self._path)


@dataclass(frozen=True, slots=True)
class _RenderTransactionBinding:
    lock: _LockProtocol
    verify_root: Callable[[], None]
    delete_subtree: Callable[[Path], bool]
    release_lease: Callable[[], None]
    stage: Callable[
        [str, object, Callable[[], None], Callable[[], None], Path],
        _StagedWriter,
    ]


def _current_async_task() -> object | None:
    """Return the exact running task, or no task in synchronous code."""
    try:
        return cast("object | None", asyncio.current_task())
    except RuntimeError:
        return None


class _RenderTransaction:
    def __init__(
        self,
        subtree: Path,
        completion: Path,
        binding: _RenderTransactionBinding,
        transaction_token: object,
        *,
        complete: bool,
    ) -> None:
        super().__init__()
        self._subtree = subtree
        self._completion = completion
        self._binding = binding
        self._transaction_token = transaction_token
        self._complete = complete
        self._closed = False
        self._owner_thread = current_thread()
        self._owner_task = _current_async_task()

    @property
    def complete(self) -> bool:
        """Return the immutable public completion observation."""
        return self._complete

    def _require_owner_context(self) -> None:
        if (
            self._owner_thread is not current_thread()
            or self._owner_task is not _current_async_task()
        ):
            msg = "render transaction belongs to another execution context"
            raise RuntimeError(msg)

    def _require_active_owner_context(self) -> None:
        if self._closed:
            msg = "render transaction is already closed"
            raise RuntimeError(msg)
        self._require_owner_context()
        self._binding.verify_root()

    def stage(self, *, suffix: str = "") -> _StagedWriter:
        """Create a writer scoped to this live transaction and owner context."""
        self._require_active_owner_context()
        return self._binding.stage(
            suffix,
            self._transaction_token,
            self._require_active_owner_context,
            self._require_owner_context,
            self._subtree,
        )

    def commit(self) -> None:
        if self._closed:
            msg = "render transaction is already closed"
            raise RuntimeError(msg)
        self._require_owner_context()
        try:
            self._binding.verify_root()
        except BaseException:
            self._closed = True
            try:
                self._binding.release_lease()
            finally:
                self._binding.lock.release()
            raise
        if self._completion.is_symlink() or not self._completion.is_file():
            self.rollback()
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "A render transaction did not publish its completion manifest.",
                http_status=500,
            )
        self._closed = True
        try:
            self._binding.release_lease()
        finally:
            self._binding.lock.release()

    def rollback(self) -> None:
        if self._closed:
            return
        self._require_owner_context()
        try:
            self._binding.verify_root()
            if not self._complete:
                _ = self._binding.delete_subtree(self._subtree)
        finally:
            self._closed = True
            try:
                self._binding.release_lease()
            finally:
                self._binding.lock.release()

    def reset(self) -> None:
        if self._closed:
            msg = "render transaction is already closed"
            raise RuntimeError(msg)
        self._require_owner_context()
        self._binding.verify_root()
        _ = self._binding.delete_subtree(self._subtree)
        self._complete = False


@dataclass(frozen=True, slots=True)
class _StoredObject:
    key: str
    path: Path
    size: int
    inodes: int
    modified_ns: int
    insertion_sequence: int


@dataclass(slots=True)
class _PruneWorkingSet:
    objects: list[_StoredObject]
    policy: RetentionPolicy
    capacity: StorageCapacity
    cutoff_ns: int
    clock_trusted: bool


@dataclass(frozen=True, slots=True)
class _PruneFinalization:
    policy: RetentionPolicy
    now_ns: int
    trusted_clock_observation: bool
    freed_bytes: int
    freed_objects: int
    post_capacity: StorageCapacity


def _stored_object_order(item: _StoredObject) -> tuple[int, str]:
    return item.insertion_sequence, item.key


def _ignore_lifecycle_alert(alert: LifecycleAlert) -> None:
    del alert


def _allow_staged_access() -> None:
    """Authorize ordinary staged writers without a transaction owner."""


@dataclass(frozen=True, slots=True)
class StoreLifecycleConfiguration:
    """Runtime authorities required to enforce one retention policy."""

    policy: RetentionPolicy
    capacity_sampler: Callable[[], StorageCapacity] | None
    clock_high_water: ClockHighWater
    clock_sampler: Callable[[], RetentionClockSample]
    alert_observer: Callable[[LifecycleAlert], None] = _ignore_lifecycle_alert

    def __post_init__(self) -> None:
        """Reject forged non-callable lifecycle authorities at composition."""
        capacity_sampler = cast("object", self.capacity_sampler)
        if capacity_sampler is not None and not callable(capacity_sampler):
            msg = "capacity_sampler must be callable or None"
            raise TypeError(msg)
        for name, value in (
            ("clock_sampler", cast("object", self.clock_sampler)),
            ("alert_observer", cast("object", self.alert_observer)),
        ):
            if not callable(value):
                msg = f"{name} must be callable"
                raise TypeError(msg)


@dataclass(frozen=True, slots=True)
class _PublicationRequest:
    policy: RetentionPolicy
    maximum_new_bytes: int
    maximum_new_objects: int
    maximum_new_inodes: int
    clock: RetentionClockSample


@dataclass(frozen=True, slots=True)
class _PublicationCommit:
    actual_bytes: int
    actual_objects: int
    actual_inodes: int
    clock_sample: RetentionClockSample
    capacity: StorageCapacity


class _AssetLease:
    def __init__(self, store: ContentAddressedStore, relative_path: str) -> None:
        super().__init__()
        self._store = store
        self._relative_path = relative_path
        self._key: str | None = None
        self._path: Path | None = None

    def __enter__(self) -> Path:
        if self._key is not None:
            msg = "asset lease is already active"
            raise RuntimeError(msg)
        key, path = self._store.acquire_asset_lease(self._relative_path)
        self._key = key
        self._path = path
        return path

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        key = self._key
        if key is None:
            return
        self._key = None
        self._path = None
        self._store.release_asset_lease(key)


class _PublicationReservation:
    def __init__(
        self, store: ContentAddressedStore, request: _PublicationRequest
    ) -> None:
        super().__init__()
        self._store = store
        self._request = request
        self._active = False
        self._closed = False
        self._baseline_used_bytes = 0
        self._baseline_stored_objects = 0
        self._baseline_available_inodes = 0

    @property
    def reserved_bytes(self) -> int:
        return self._request.maximum_new_bytes

    @property
    def reserved_objects(self) -> int:
        return self._request.maximum_new_objects

    @property
    def reserved_inodes(self) -> int:
        return self._request.maximum_new_inodes

    @property
    def policy(self) -> RetentionPolicy:
        return self._request.policy

    @property
    def clock(self) -> RetentionClockSample:
        return self._request.clock

    @property
    def active(self) -> bool:
        return self._active

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def baseline_used_bytes(self) -> int:
        return self._baseline_used_bytes

    @property
    def baseline_stored_objects(self) -> int:
        return self._baseline_stored_objects

    @property
    def baseline_available_inodes(self) -> int:
        return self._baseline_available_inodes

    def activate(
        self,
        *,
        baseline_used_bytes: int,
        baseline_stored_objects: int,
        baseline_available_inodes: int,
    ) -> None:
        if self._active or self._closed:
            msg = "publication reservation cannot be entered twice"
            raise RuntimeError(msg)
        self._baseline_used_bytes = baseline_used_bytes
        self._baseline_stored_objects = baseline_stored_objects
        self._baseline_available_inodes = baseline_available_inodes
        self._active = True

    def close(self) -> None:
        if not self._active or self._closed:
            msg = "publication reservation is not active"
            raise RuntimeError(msg)
        self._active = False
        self._closed = True

    def begin(self) -> None:
        self._store.begin_publication_reservation(self)

    async def commit(
        self,
        *,
        actual_bytes: int,
        actual_objects: int,
        actual_inodes: int,
    ) -> None:
        if self._closed:
            msg = "publication reservation is already closed"
            raise RuntimeError(msg)
        self._store.commit_publication_reservation(
            self,
            actual_bytes=actual_bytes,
            actual_objects=actual_objects,
            actual_inodes=actual_inodes,
        )

    async def abort(self) -> None:
        if self._closed:
            msg = "publication reservation is already closed"
            raise RuntimeError(msg)
        self._store.abort_publication_reservation(self)


class _PublicationReservationContext:
    def __init__(self, reservation: _PublicationReservation) -> None:
        super().__init__()
        self._reservation = reservation

    async def __aenter__(self) -> _PublicationReservation:
        self._reservation.begin()
        return self._reservation

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        if not self._reservation.closed:
            await self._reservation.abort()


@dataclass(slots=True)
class _StoreRuntimeState:
    insertion_order: PersistentInsertionOrder | None
    max_bytes: int
    lock: _LockProtocol
    render_locks: tuple[_LockProtocol, ...]
    used_bytes: int
    reserved_bytes: int
    staging_reservations: dict[Path, int]
    retention_policy: RetentionPolicy | None
    capacity_sampler_override: Callable[[], StorageCapacity] | None
    clock_high_water: ClockHighWater | None
    clock_sampler: Callable[[], RetentionClockSample] | None
    publication_reservations: set[_PublicationReservation]
    publication_reserved_bytes: int
    publication_reserved_objects: int
    publication_reserved_inodes: int
    lifecycle_alert_observer: Callable[[LifecycleAlert], None]
    admission_closed_blocker: PublicationBlocker | None
    asset_leases: dict[str, int]
    render_transaction_leases: dict[str, set[object]]


class ContentAddressedStore:
    """Persist bounded document and render artifacts under a trusted root."""

    def __init__(
        self,
        root: Path | str,
        *,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        lifecycle: StoreLifecycleConfiguration | None = None,
    ) -> None:
        """Initialize the storage root and reconcile existing cache usage."""
        super().__init__()
        if type(max_bytes) is not int or max_bytes <= 0:
            msg = "max_bytes must be a positive integer"
            raise ValueError(msg)
        self.root = Path(root).expanduser().absolute()
        self.staging_dir = self.root / ".staging"
        if self.root.parent.exists() or self.root.parent.is_symlink():
            _validate_storage_root_parent(self.root)
        root_created = False
        try:
            self.root.mkdir(
                parents=True,
                mode=_PRIVATE_DIRECTORY_MODE,
            )
            root_created = True
            self.root.chmod(_PRIVATE_DIRECTORY_MODE, follow_symlinks=False)
        except FileExistsError:
            pass
        _validate_storage_root_parent(self.root)
        root_descriptor: int | None = None
        try:
            root_descriptor, root_identity = _open_verified_directory(self.root)
            _validate_owned_private_directory(
                root_descriptor,
                context="cache root",
                created=root_created,
            )
        except (OSError, ValueError) as exc:
            if root_descriptor is not None:
                os.close(root_descriptor)
            msg = "cache root directory is unsafe"
            raise ValueError(msg) from exc
        self._root_descriptor = root_descriptor
        self._root_identity = root_identity
        self._root_descriptor_finalizer = weakref.finalize(
            self,
            os.close,
            self._root_descriptor,
        )
        _ensure_private_directory_at(
            ".staging",
            parent_descriptor=self._root_descriptor,
            context="cache staging",
        )
        for namespace in _ALLOWED_NAMESPACES:
            _ensure_private_directory_at(
                namespace,
                parent_descriptor=self._root_descriptor,
                context="cache namespace",
            )
        _validate_preexisting_artifact_tree(self._root_descriptor)
        self._cleanup_stale_staging(maximum_bytes=max_bytes)
        self._cleanup_incomplete_renders()
        runtime = self._build_runtime_state(lifecycle=lifecycle, max_bytes=max_bytes)
        (
            self._insertion_order,
            self.max_bytes,
            self._lock,
            self._render_locks,
            self._used_bytes,
            self._reserved_bytes,
            self._staging_reservations,
            self._retention_policy,
            self._capacity_sampler_override,
            self._clock_high_water,
            self._clock_sampler,
            self._publication_reservations,
            self._publication_reserved_bytes,
            self._publication_reserved_objects,
            self._publication_reserved_inodes,
            self._lifecycle_alert_observer,
            self._admission_closed_blocker,
            self._asset_leases,
            self._render_transaction_leases,
        ) = (
            runtime.insertion_order,
            runtime.max_bytes,
            runtime.lock,
            runtime.render_locks,
            runtime.used_bytes,
            runtime.reserved_bytes,
            runtime.staging_reservations,
            runtime.retention_policy,
            runtime.capacity_sampler_override,
            runtime.clock_high_water,
            runtime.clock_sampler,
            runtime.publication_reservations,
            runtime.publication_reserved_bytes,
            runtime.publication_reserved_objects,
            runtime.publication_reserved_inodes,
            runtime.lifecycle_alert_observer,
            runtime.admission_closed_blocker,
            runtime.asset_leases,
            runtime.render_transaction_leases,
        )
        if lifecycle is not None:
            validate_retention_capacity(
                lifecycle.policy,
                configured_cache_max_bytes=max_bytes,
                capacity=self._sample_capacity(),
            )

    def _build_runtime_state(
        self,
        *,
        lifecycle: StoreLifecycleConfiguration | None,
        max_bytes: int,
    ) -> _StoreRuntimeState:
        """Build process-local accounting after disk state is reconciled."""
        insertion_order: PersistentInsertionOrder | None = None
        if lifecycle is not None:
            insertion_order = PersistentInsertionOrder(self.root)
            insertion_order.initialize(self._object_roots())
        return _StoreRuntimeState(
            insertion_order=insertion_order,
            max_bytes=max_bytes,
            lock=RLock(),
            render_locks=tuple(RLock() for _ in range(64)),
            used_bytes=self._scan_existing_bytes(),
            reserved_bytes=0,
            staging_reservations={},
            retention_policy=lifecycle.policy if lifecycle is not None else None,
            capacity_sampler_override=(
                lifecycle.capacity_sampler if lifecycle is not None else None
            ),
            clock_high_water=(
                lifecycle.clock_high_water if lifecycle is not None else None
            ),
            clock_sampler=(lifecycle.clock_sampler if lifecycle is not None else None),
            publication_reservations=set(),
            publication_reserved_bytes=0,
            publication_reserved_objects=0,
            publication_reserved_inodes=0,
            lifecycle_alert_observer=(
                lifecycle.alert_observer
                if lifecycle is not None
                else _ignore_lifecycle_alert
            ),
            admission_closed_blocker=None,
            asset_leases={},
            render_transaction_leases={},
        )

    def _scan_existing_bytes(self) -> int:
        total = 0
        for namespace in _ALLOWED_NAMESPACES:
            top = self.root / namespace
            for directory, directories, files in os.walk(top, followlinks=False):
                base = Path(directory)
                directories[:] = [
                    name for name in directories if not (base / name).is_symlink()
                ]
                for name in files:
                    if name == INSERTION_SEQUENCE_FILENAME:
                        continue
                    candidate = base / name
                    metadata = candidate.lstat()
                    if stat.S_ISREG(metadata.st_mode):
                        total += metadata.st_size
        return total

    def _object_roots(self) -> tuple[tuple[str, Path], ...]:
        objects: list[tuple[str, Path]] = []
        for namespace in sorted(_ALLOWED_NAMESPACES):
            top = self.root / namespace
            for child in sorted(top.iterdir(), key=_path_name):
                if child.is_symlink() or not child.is_dir():
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Artifact storage is corrupted.",
                        http_status=500,
                    )
                objects.append((f"{namespace}/{child.name}", child))
        return tuple(objects)

    def _cleanup_stale_staging(self, *, maximum_bytes: int) -> None:
        """Validate a bounded orphan tree before descriptor-relative removal."""
        self._verify_store_root_identity()
        staging_descriptor, staging_identity = _open_verified_directory(
            ".staging",
            directory_fd=self._root_descriptor,
        )
        try:
            if staging_identity.device != self._root_identity.device:
                msg = "cache staging recovery crossed its filesystem boundary"
                raise ValueError(msg)
            entries = _inventory_orphan_staging(
                staging_descriptor,
                depth=0,
                budget=_StagingRecoveryBudget(
                    root_device=self._root_identity.device,
                    maximum_bytes=maximum_bytes,
                ),
            )
            _delete_orphan_staging_inventory(staging_descriptor, entries)
            with os.scandir(staging_descriptor) as remaining_entries:
                incomplete_post_state = next(remaining_entries, None) is not None
            if incomplete_post_state:
                msg = "cache staging recovery did not reach an empty post-state"
                raise ValueError(msg)
            os.fsync(staging_descriptor)
        except OSError as exc:
            msg = "cache staging recovery encountered an unsafe filesystem state"
            raise ValueError(msg) from exc
        finally:
            os.close(staging_descriptor)

    @staticmethod
    def _is_render_id(value: str) -> bool:
        return (
            len(value) == _RENDER_ID_LENGTH
            and value.startswith("rnd_")
            and all(character in "0123456789abcdef" for character in value[4:])
        )

    def _cleanup_incomplete_renders(self) -> None:
        renders = self.root / "renders"
        renders_changed = False
        for render in renders.iterdir():
            if not self._is_render_id(render.name):
                continue
            completion = render / "manifest.json"
            if render.is_symlink() or not render.is_dir():
                render.unlink(missing_ok=True)
                renders_changed = True
                continue
            if completion.is_symlink() or not completion.is_file():
                shutil.rmtree(render)
                renders_changed = True
                continue
            _cleanup_render_tiles(render)
        if renders_changed:
            _fsync_directory(renders)

    def _verify_store_root_identity(self) -> None:
        """Reject a closed, replaced, or symlink-swapped configured root."""
        current_descriptor: int | None = None
        try:
            held_identity = _directory_identity(os.fstat(self._root_descriptor))
            current_descriptor, current_identity = _open_verified_directory(self.root)
        except (OSError, ValueError) as exc:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                _STORAGE_ROOT_IDENTITY_ERROR,
                http_status=500,
            ) from exc
        finally:
            if current_descriptor is not None:
                os.close(current_descriptor)
        if (
            held_identity != self._root_identity
            or current_identity != self._root_identity
        ):
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                _STORAGE_ROOT_IDENTITY_ERROR,
                http_status=500,
            )

    def _sample_capacity(self) -> StorageCapacity:
        """Sample only after proving the path still names the held root."""
        self._verify_store_root_identity()
        sampler = self._capacity_sampler_override
        if sampler is not None:
            return sampler()
        return filesystem_capacity(self._root_descriptor)

    @property
    def used_bytes(self) -> int:
        """Return the committed byte count."""
        with self._lock:
            return self._used_bytes

    @property
    def reserved_bytes(self) -> int:
        """Return the bytes reserved by open staged writers."""
        with self._lock:
            return self._reserved_bytes

    @property
    def publication_reserved_bytes(self) -> int:
        """Return worst-case bytes held by operation-wide reservations."""
        with self._lock:
            return self._publication_reserved_bytes

    @property
    def publication_reserved_objects(self) -> int:
        """Return logical objects held by operation-wide reservations."""
        with self._lock:
            return self._publication_reserved_objects

    @property
    def publication_reserved_inodes(self) -> int:
        """Return physical inodes held by operation-wide reservations."""
        with self._lock:
            return self._publication_reserved_inodes

    @property
    def lifecycle_admission_closed(self) -> bool:
        """Return whether publication awaits a satisfied lifecycle prune."""
        with self._lock:
            return self._admission_closed_blocker is not None

    @property
    def lifecycle_configured(self) -> bool:
        """Return whether strict retention authorities are bound to this store."""
        return self._retention_policy is not None

    def ensure_ready(self) -> None:
        """Validate a read-only storage snapshot for the readiness endpoint."""
        try:
            self._verify_store_root_identity()
            _validate_storage_root_parent(self.root)
            _validate_owned_private_directory(
                self._root_descriptor,
                context="cache root readiness",
                created=False,
            )
            for name in sorted({".staging", *_ALLOWED_NAMESPACES}):
                descriptor, identity = _open_verified_directory(
                    name,
                    directory_fd=self._root_descriptor,
                )
                try:
                    _validate_owned_private_directory(
                        descriptor,
                        context="cache readiness directory",
                        created=False,
                    )
                    if identity.device != self._root_identity.device:
                        message = "cache readiness crossed its filesystem boundary"
                        raise ValueError(message)
                finally:
                    os.close(descriptor)
            capacity = self._sample_capacity()
        except AppError:
            raise
        except (OSError, ValueError) as exc:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Artifact storage readiness validation failed.",
                http_status=503,
            ) from exc

        with self._lock:
            policy = self._retention_policy
            lifecycle_closed = self._admission_closed_blocker is not None
            used_and_reserved_bytes = (
                self._used_bytes
                + self._reserved_bytes
                + self._publication_reserved_bytes
            )
            reserved_capacity_bytes = (
                self._reserved_bytes + self._publication_reserved_bytes
            )
            stored_objects = len(self._stored_objects()) if policy is not None else 0
            used_and_reserved_objects = (
                stored_objects + self._publication_reserved_objects
            )
            publication_reserved_inodes = self._publication_reserved_inodes
        insufficient_capacity = capacity.available_bytes == 0 or (
            capacity.available_inodes == 0
        )
        if policy is not None:
            insufficient_capacity = insufficient_capacity or (
                used_and_reserved_bytes > policy.maximum_bytes
                or used_and_reserved_objects > policy.maximum_objects
                or capacity.available_bytes
                < policy.minimum_free_bytes + reserved_capacity_bytes
                or capacity.available_inodes
                < policy.minimum_free_inodes + publication_reserved_inodes
            )
        elif used_and_reserved_bytes > self.max_bytes:
            insufficient_capacity = True
        if lifecycle_closed or insufficient_capacity:
            raise AppError(
                ErrorCode.CACHE_FULL,
                "The artifact lifecycle is not ready for publication.",
                http_status=503,
            )

    @staticmethod
    def _validate_publication_maximum(
        value: int,
        *,
        name: str,
        maximum: int,
    ) -> int:
        if type(value) is not int or not 1 <= value <= maximum:
            msg = f"{name} must be a positive exact integer within policy bounds"
            raise ValueError(msg)
        return value

    def _require_lifecycle_policy(self, policy: RetentionPolicy) -> None:
        if self._retention_policy is None or policy != self._retention_policy:
            msg = "publication must use the configured retention policy"
            raise ValueError(msg)
        if self._clock_high_water is None or self._clock_sampler is None:
            msg = "retention lifecycle clock authority is unavailable"
            raise ValueError(msg)

    def _emit_lifecycle_alert(self, alert: LifecycleAlert) -> None:
        with contextlib.suppress(Exception):
            self._lifecycle_alert_observer(alert)

    def _close_admission(
        self,
        blocker: PublicationBlocker,
        *,
        alert: LifecycleAlert,
        pending_alerts: list[LifecycleAlert] | None = None,
    ) -> PublicationBlocker:
        existing = self._admission_closed_blocker
        if existing is not None:
            return existing
        self._admission_closed_blocker = blocker
        if pending_alerts is None:
            self._emit_lifecycle_alert(alert)
        else:
            pending_alerts.append(alert)
        return blocker

    def _publication_denial(
        self,
        blocker: PublicationBlocker,
        *,
        pending_alerts: list[LifecycleAlert],
    ) -> Never:
        effective = self._close_admission(
            blocker,
            alert=LifecycleAlert(
                event=LifecycleAlertEvent.ADMISSION_CLOSED,
                blockers=(LifecycleBlocker(blocker.value),),
            ),
            pending_alerts=pending_alerts,
        )
        raise PublicationReservationError(effective)

    def _tree_stats(self, path: Path) -> tuple[int, int, int]:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Artifact storage is corrupted.",
                http_status=500,
            )
        size = 0
        inodes = 1
        modified_ns = metadata.st_mtime_ns
        for directory, directories, files in os.walk(path, followlinks=False):
            base = Path(directory)
            for name in directories:
                child = base / name
                child_metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISDIR(child_metadata.st_mode):
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Artifact storage is corrupted.",
                        http_status=500,
                    )
                inodes += 1
                modified_ns = min(modified_ns, child_metadata.st_mtime_ns)
            for name in files:
                child = base / name
                child_metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISREG(child_metadata.st_mode):
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Artifact storage is corrupted.",
                        http_status=500,
                    )
                if name != INSERTION_SEQUENCE_FILENAME:
                    size += child_metadata.st_size
                inodes += 1
                modified_ns = min(modified_ns, child_metadata.st_mtime_ns)
        return size, inodes, modified_ns

    def _stored_objects(self) -> tuple[_StoredObject, ...]:
        insertion_order = self._insertion_order
        if insertion_order is None:
            msg = "retention lifecycle insertion order is unavailable"
            raise RuntimeError(msg)
        objects: list[_StoredObject] = []
        for namespace in tuple(sorted(_ALLOWED_NAMESPACES)):
            top = self.root / namespace
            for child in sorted(top.iterdir(), key=_path_name):
                if child.is_symlink() or not child.is_dir():
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Artifact storage is corrupted.",
                        http_status=500,
                    )
                size, inodes, modified_ns = self._tree_stats(child)
                key = f"{namespace}/{child.name}"
                objects.append(
                    _StoredObject(
                        key=key,
                        path=child,
                        size=size,
                        inodes=inodes,
                        modified_ns=modified_ns,
                        insertion_sequence=insertion_order.sequence_for(key),
                    )
                )
        if len(objects) > _MAX_LIFECYCLE_OBJECTS:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Artifact object inventory exceeds its safety bound.",
                http_status=500,
            )
        return tuple(objects)

    def reserve_publication(
        self,
        policy: RetentionPolicy,
        *,
        maximum_new_bytes: int,
        maximum_new_objects: int,
        maximum_new_inodes: int,
        clock: RetentionClockSample,
    ) -> _PublicationReservationContext:
        """Reserve the complete worst-case operation before any side effect."""
        self._require_lifecycle_policy(policy)
        reservation = _PublicationReservation(
            self,
            _PublicationRequest(
                policy=policy,
                maximum_new_bytes=self._validate_publication_maximum(
                    maximum_new_bytes,
                    name="maximum_new_bytes",
                    maximum=self.max_bytes,
                ),
                maximum_new_objects=self._validate_publication_maximum(
                    maximum_new_objects,
                    name="maximum_new_objects",
                    maximum=_MAX_LIFECYCLE_OBJECTS,
                ),
                maximum_new_inodes=self._validate_publication_maximum(
                    maximum_new_inodes,
                    name="maximum_new_inodes",
                    maximum=_MAX_LIFECYCLE_OBJECTS,
                ),
                clock=clock,
            ),
        )
        return _PublicationReservationContext(reservation)

    def _activate_publication_reservation_locked(
        self,
        reservation: _PublicationReservation,
        *,
        capacity: StorageCapacity,
        pending_alerts: list[LifecycleAlert],
    ) -> None:
        """Validate and activate one reservation while accounting is locked."""
        if reservation.active or reservation.closed:
            msg = "publication reservation cannot be entered twice"
            raise RuntimeError(msg)
        closed_blocker = self._admission_closed_blocker
        if closed_blocker is not None:
            raise PublicationReservationError(closed_blocker)
        clock_authority = self._clock_high_water
        if clock_authority is None:
            msg = "retention lifecycle clock authority is unavailable"
            raise RuntimeError(msg)
        if not clock_authority.observe(reservation.clock).trusted:
            self._publication_denial(
                PublicationBlocker.CLOCK_ANOMALY,
                pending_alerts=pending_alerts,
            )
        objects = self._stored_objects()
        if (
            self._used_bytes
            + self._reserved_bytes
            + self._publication_reserved_bytes
            + reservation.reserved_bytes
            > reservation.policy.maximum_bytes
        ):
            self._publication_denial(
                PublicationBlocker.BYTE_BUDGET,
                pending_alerts=pending_alerts,
            )
        if (
            len(objects)
            + self._publication_reserved_objects
            + reservation.reserved_objects
            > reservation.policy.maximum_objects
        ):
            self._publication_denial(
                PublicationBlocker.OBJECT_BUDGET,
                pending_alerts=pending_alerts,
            )
        if capacity.available_bytes < (
            reservation.policy.minimum_free_bytes
            + self._reserved_bytes
            + self._publication_reserved_bytes
            + reservation.reserved_bytes
        ):
            self._publication_denial(
                PublicationBlocker.BYTE_HEADROOM,
                pending_alerts=pending_alerts,
            )
        if capacity.available_inodes < (
            reservation.policy.minimum_free_inodes
            + self._publication_reserved_inodes
            + reservation.reserved_inodes
        ):
            self._publication_denial(
                PublicationBlocker.INODE_HEADROOM,
                pending_alerts=pending_alerts,
            )
        reservation.activate(
            baseline_used_bytes=self._used_bytes,
            baseline_stored_objects=len(objects),
            baseline_available_inodes=capacity.available_inodes,
        )
        self._publication_reservations.add(reservation)
        self._publication_reserved_bytes += reservation.reserved_bytes
        self._publication_reserved_objects += reservation.reserved_objects
        self._publication_reserved_inodes += reservation.reserved_inodes

    def begin_publication_reservation(
        self,
        reservation: _PublicationReservation,
    ) -> None:
        """Admit one prevalidated reservation under atomic accounting."""
        pending_alerts: list[LifecycleAlert] = []
        try:
            with self._lock:
                self._verify_store_root_identity()
                capacity_sampler = self._capacity_sampler_override
                capacity = self._sample_capacity()
                if capacity_sampler is not self._capacity_sampler_override:
                    msg = "retention lifecycle capacity authority changed"
                    raise RuntimeError(msg)
                self._activate_publication_reservation_locked(
                    reservation,
                    capacity=capacity,
                    pending_alerts=pending_alerts,
                )
        finally:
            for alert in pending_alerts:
                self._emit_lifecycle_alert(alert)

    @staticmethod
    def _validate_actual_publication(
        value: int,
        *,
        name: str,
        reserved: int,
    ) -> int:
        if type(value) is not int or not 0 <= value <= reserved:
            msg = f"{name} must be an exact integer within its reservation"
            raise ValueError(msg)
        return value

    def _commit_publication_reservation_locked(
        self,
        reservation: _PublicationReservation,
        *,
        commit: _PublicationCommit,
        pending_alerts: list[LifecycleAlert],
    ) -> None:
        """Revalidate and consume one reservation while accounting is locked."""
        if reservation not in self._publication_reservations:
            msg = "publication reservation is not active"
            raise RuntimeError(msg)
        clock_authority = self._clock_high_water
        if clock_authority is None:
            msg = "retention lifecycle clock authority is unavailable"
            raise RuntimeError(msg)
        if not clock_authority.observe(commit.clock_sample).trusted:
            self._publication_denial(
                PublicationBlocker.CLOCK_ANOMALY,
                pending_alerts=pending_alerts,
            )
        objects = self._stored_objects()
        observed_bytes = max(
            0,
            self._used_bytes - reservation.baseline_used_bytes,
        )
        remaining_bytes = max(0, commit.actual_bytes - observed_bytes)
        observed_objects = max(
            0,
            len(objects) - reservation.baseline_stored_objects,
        )
        remaining_objects = max(0, commit.actual_objects - observed_objects)
        observed_inodes = max(
            0,
            reservation.baseline_available_inodes - commit.capacity.available_inodes,
        )
        remaining_inodes = max(0, commit.actual_inodes - observed_inodes)
        other_reserved_bytes = (
            self._publication_reserved_bytes - reservation.reserved_bytes
        )
        other_reserved_objects = (
            self._publication_reserved_objects - reservation.reserved_objects
        )
        other_reserved_inodes = (
            self._publication_reserved_inodes - reservation.reserved_inodes
        )
        if (
            self._used_bytes
            + self._reserved_bytes
            + other_reserved_bytes
            + remaining_bytes
            > reservation.policy.maximum_bytes
        ):
            self._publication_denial(
                PublicationBlocker.BYTE_BUDGET,
                pending_alerts=pending_alerts,
            )
        if (
            len(objects) + other_reserved_objects + remaining_objects
            > reservation.policy.maximum_objects
        ):
            self._publication_denial(
                PublicationBlocker.OBJECT_BUDGET,
                pending_alerts=pending_alerts,
            )
        if commit.capacity.available_bytes < (
            reservation.policy.minimum_free_bytes
            + self._reserved_bytes
            + other_reserved_bytes
            + remaining_bytes
        ):
            self._publication_denial(
                PublicationBlocker.BYTE_HEADROOM,
                pending_alerts=pending_alerts,
            )
        if commit.capacity.available_inodes < (
            reservation.policy.minimum_free_inodes
            + other_reserved_inodes
            + remaining_inodes
        ):
            self._publication_denial(
                PublicationBlocker.INODE_HEADROOM,
                pending_alerts=pending_alerts,
            )
        self._release_publication_reservation_locked(reservation)

    def commit_publication_reservation(
        self,
        reservation: _PublicationReservation,
        *,
        actual_bytes: int,
        actual_objects: int,
        actual_inodes: int,
    ) -> None:
        """Recheck and atomically convert one aggregate reservation."""
        actual_bytes = self._validate_actual_publication(
            actual_bytes,
            name="actual_bytes",
            reserved=reservation.reserved_bytes,
        )
        actual_objects = self._validate_actual_publication(
            actual_objects,
            name="actual_objects",
            reserved=reservation.reserved_objects,
        )
        actual_inodes = self._validate_actual_publication(
            actual_inodes,
            name="actual_inodes",
            reserved=reservation.reserved_inodes,
        )
        pending_alerts: list[LifecycleAlert] = []
        try:
            with self._lock:
                if reservation not in self._publication_reservations:
                    msg = "publication reservation is not active"
                    raise RuntimeError(msg)
                self._verify_store_root_identity()
                clock_sampler = self._clock_sampler
                capacity_sampler = self._capacity_sampler_override
                if clock_sampler is None:
                    msg = "retention lifecycle clock authority is unavailable"
                    raise RuntimeError(msg)
                clock_sample = clock_sampler()
                capacity = self._sample_capacity()
                if (
                    clock_sampler is not self._clock_sampler
                    or capacity_sampler is not self._capacity_sampler_override
                ):
                    msg = "retention lifecycle authority changed"
                    raise RuntimeError(msg)
                self._commit_publication_reservation_locked(
                    reservation,
                    commit=_PublicationCommit(
                        actual_bytes=actual_bytes,
                        actual_objects=actual_objects,
                        actual_inodes=actual_inodes,
                        clock_sample=clock_sample,
                        capacity=capacity,
                    ),
                    pending_alerts=pending_alerts,
                )
        finally:
            for alert in pending_alerts:
                self._emit_lifecycle_alert(alert)

    def _release_publication_reservation_locked(
        self,
        reservation: _PublicationReservation,
    ) -> None:
        if reservation not in self._publication_reservations:
            msg = "publication reservation is not active"
            raise RuntimeError(msg)
        self._publication_reservations.remove(reservation)
        self._publication_reserved_bytes -= reservation.reserved_bytes
        self._publication_reserved_objects -= reservation.reserved_objects
        self._publication_reserved_inodes -= reservation.reserved_inodes
        reservation.close()

    def abort_publication_reservation(
        self,
        reservation: _PublicationReservation,
    ) -> None:
        """Release one active aggregate reservation without publication."""
        with self._lock:
            self._release_publication_reservation_locked(reservation)

    @staticmethod
    def _asset_object_key(relative_path: str) -> str:
        pure = PurePosixPath(relative_path)
        if len(pure.parts) < _MIN_OBJECT_KEY_PARTS:
            raise AppError(ErrorCode.INVALID_INPUT, "Asset path is invalid.")
        return "/".join(pure.parts[:2])

    def acquire_asset_lease(self, relative_path: str) -> tuple[str, Path]:
        """Resolve and lease one existing artifact object."""
        with self._lock:
            key = self._asset_object_key(relative_path)
            if self._render_transaction_leases.get(key):
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "The render is currently in use and cannot be read.",
                    http_status=409,
                )
            path = self.resolve_asset(relative_path)
            self._asset_leases[key] = self._asset_leases.get(key, 0) + 1
            return key, path

    def release_asset_lease(
        self,
        key: str,
        *,
        transaction_token: object | None = None,
    ) -> None:
        """Release one exact reader or render-transaction lease."""
        with self._lock:
            if transaction_token is not None:
                transaction_leases = self._render_transaction_leases.get(key)
                if transaction_leases != {transaction_token}:
                    msg = "render transaction lease release is unbalanced"
                    raise RuntimeError(msg)
                del self._render_transaction_leases[key]
                return
            current = self._asset_leases.get(key)
            if current is None or current < 1:
                msg = "asset lease release is unbalanced"
                raise RuntimeError(msg)
            if current == 1:
                del self._asset_leases[key]
            else:
                self._asset_leases[key] = current - 1

    def _register_render_transaction_locked(
        self,
        object_key: str,
        transaction_token: object,
    ) -> None:
        """Register one exact transaction while accounting is locked."""
        if object_key in self._render_transaction_leases:
            msg = "render transaction is already active"
            raise RuntimeError(msg)
        self._render_transaction_leases[object_key] = {transaction_token}

    def _require_render_mutation_authority_locked(
        self,
        object_key: str,
        transaction_token: object | None,
    ) -> None:
        """Reject readers, foreign writers, and unscoped transaction writes."""
        if self._asset_leases.get(object_key, 0) > 0:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "The render is currently in use and cannot be modified.",
                http_status=409,
            )
        transaction_leases = self._render_transaction_leases.get(object_key)
        if transaction_token is None:
            if transaction_leases:
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "The render is currently in use and cannot be modified.",
                    http_status=409,
                )
            return
        if transaction_leases != {transaction_token}:
            msg = "render transaction mutation authority is unavailable"
            raise RuntimeError(msg)

    @staticmethod
    def _require_render_transaction_destination(
        destination: Path,
        transaction_subtree: Path | None,
        transaction_token: object | None,
    ) -> None:
        """Bind a transaction token to files strictly below its subtree."""
        if transaction_token is None:
            if transaction_subtree is not None:
                msg = "render transaction destination authority is invalid"
                raise RuntimeError(msg)
            return
        if transaction_subtree is None:
            msg = "render transaction destination authority is invalid"
            raise RuntimeError(msg)
        try:
            relative = destination.relative_to(transaction_subtree)
        except ValueError as exc:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Render asset path is outside its transaction subtree.",
            ) from exc
        if not relative.parts:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Render asset path is outside its transaction subtree.",
            )

    @staticmethod
    def _invoke_render_transaction_guard(
        transaction_guard: Callable[[], None] | None,
    ) -> None:
        if transaction_guard is not None:
            transaction_guard()

    def lease_asset(self, relative_path: str) -> _AssetLease:
        """Hold one object against pruning for the complete read/stream lifetime."""
        return _AssetLease(self, relative_path)

    @staticmethod
    def _prune_pressure(state: _PruneWorkingSet) -> bool:
        return (
            sum(item.size for item in state.objects) > state.policy.maximum_bytes
            or len(state.objects) > state.policy.maximum_objects
            or state.capacity.available_bytes < state.policy.minimum_free_bytes
            or state.capacity.available_inodes < state.policy.minimum_free_inodes
        )

    def _prune_unleased(self, state: _PruneWorkingSet) -> tuple[int, int]:
        freed_bytes = 0
        freed_objects = 0
        for candidate in sorted(state.objects, key=_stored_object_order):
            expired = state.clock_trusted and candidate.modified_ns < state.cutoff_ns
            if not expired and not self._prune_pressure(state):
                continue
            if self._asset_leases.get(
                candidate.key, 0
            ) > 0 or self._render_transaction_leases.get(candidate.key):
                continue
            _remove_storage_path(candidate.path)
            insertion_order = self._insertion_order
            if insertion_order is not None:
                insertion_order.remove(candidate.key)
            _fsync_directory(candidate.path.parent)
            state.objects.remove(candidate)
            freed_bytes += candidate.size
            freed_objects += 1
        return freed_bytes, freed_objects

    def _record_unsatisfied_prune(
        self,
        blockers: tuple[PruneBlocker, ...],
        *,
        pending_alerts: list[LifecycleAlert] | None = None,
    ) -> None:
        if PruneBlocker.CLOCK_ANOMALY in blockers:
            publication_blocker = PublicationBlocker.CLOCK_ANOMALY
        elif PruneBlocker.INODE_HEADROOM in blockers:
            publication_blocker = PublicationBlocker.INODE_HEADROOM
        elif PruneBlocker.BYTE_HEADROOM in blockers:
            publication_blocker = PublicationBlocker.BYTE_HEADROOM
        else:
            publication_blocker = PublicationBlocker.OBJECT_BUDGET
        _ = self._close_admission(
            publication_blocker,
            alert=LifecycleAlert(
                event=LifecycleAlertEvent.PRUNE_UNSATISFIED,
                blockers=tuple(LifecycleBlocker(blocker.value) for blocker in blockers),
            ),
            pending_alerts=pending_alerts,
        )

    def _finish_prune_locked(
        self,
        finalization: _PruneFinalization,
        *,
        pending_alerts: list[LifecycleAlert],
    ) -> PruneReport:
        """Build and latch an exact prune result while accounting is locked."""
        objects = list(self._stored_objects())
        self._used_bytes = self._scan_existing_bytes()
        clock_trusted = finalization.trusted_clock_observation and not any(
            item.modified_ns > finalization.now_ns for item in objects
        )
        retained_leased = sum(
            1
            for item in objects
            if self._asset_leases.get(item.key, 0) > 0
            or self._render_transaction_leases.get(item.key)
        )
        post_bytes = sum(item.size for item in objects)
        post_objects = len(objects)
        blockers: list[PruneBlocker] = []
        budget_unsatisfied = (
            post_bytes > finalization.policy.maximum_bytes
            or post_objects > finalization.policy.maximum_objects
        )
        if budget_unsatisfied:
            blockers.append(
                PruneBlocker.LEASED_OBJECTS
                if retained_leased > 0
                else PruneBlocker.BYTE_HEADROOM
            )
        if (
            finalization.post_capacity.available_bytes
            < finalization.policy.minimum_free_bytes
        ):
            blockers.append(PruneBlocker.BYTE_HEADROOM)
        if (
            finalization.post_capacity.available_inodes
            < finalization.policy.minimum_free_inodes
        ):
            blockers.append(PruneBlocker.INODE_HEADROOM)
        if not clock_trusted:
            blockers.append(PruneBlocker.CLOCK_ANOMALY)
        canonical_blockers = tuple(
            blocker for blocker in PruneBlocker if blocker in blockers
        )
        report_values = {
            "freed_bytes": finalization.freed_bytes,
            "freed_objects": finalization.freed_objects,
            "retained_leased_objects": retained_leased,
            "post_stored_bytes": post_bytes,
            "post_stored_objects": post_objects,
            "post_available_bytes": finalization.post_capacity.available_bytes,
            "post_available_inodes": finalization.post_capacity.available_inodes,
        }
        if canonical_blockers:
            self._record_unsatisfied_prune(
                canonical_blockers,
                pending_alerts=pending_alerts,
            )
            return UnsatisfiedPruneReport(
                status="unsatisfied",
                blockers=canonical_blockers,
                **report_values,
            )
        self._admission_closed_blocker = None
        return SatisfiedPruneReport(status="satisfied", **report_values)

    def prune(
        self,
        policy: RetentionPolicy,
        *,
        clock: RetentionClockSample,
    ) -> PruneReport:
        """Prune unleased objects and report the exact bounded post-state."""
        self._require_lifecycle_policy(policy)
        now_ns = int(clock.utc_now.timestamp() * 1_000_000_000)
        pending_alerts: list[LifecycleAlert] = []
        try:
            with self._lock:
                self._verify_store_root_identity()
                capacity_sampler = self._capacity_sampler_override
                before_capacity = self._sample_capacity()
                if capacity_sampler is not self._capacity_sampler_override:
                    msg = "retention lifecycle capacity authority changed"
                    raise RuntimeError(msg)
                clock_authority = self._clock_high_water
                if clock_authority is None:
                    msg = "retention lifecycle clock authority is unavailable"
                    raise RuntimeError(msg)
                trusted_clock_observation = clock_authority.observe(clock).trusted
                objects = list(self._stored_objects())
                future_timestamp = any(item.modified_ns > now_ns for item in objects)
                working_set = _PruneWorkingSet(
                    objects=objects,
                    policy=policy,
                    capacity=before_capacity,
                    cutoff_ns=(now_ns - policy.maximum_age_seconds * 1_000_000_000),
                    clock_trusted=(trusted_clock_observation and not future_timestamp),
                )
                freed_bytes, freed_objects = self._prune_unleased(working_set)
                self._used_bytes = self._scan_existing_bytes()
                post_capacity = self._sample_capacity()
                if capacity_sampler is not self._capacity_sampler_override:
                    msg = "retention lifecycle capacity authority changed"
                    raise RuntimeError(msg)
                report = self._finish_prune_locked(
                    _PruneFinalization(
                        policy=policy,
                        now_ns=now_ns,
                        trusted_clock_observation=trusted_clock_observation,
                        freed_bytes=freed_bytes,
                        freed_objects=freed_objects,
                        post_capacity=post_capacity,
                    ),
                    pending_alerts=pending_alerts,
                )
        finally:
            for alert in pending_alerts:
                self._emit_lifecycle_alert(alert)
        return report

    def reconcile_lifecycle(self) -> PruneReport:
        """Sample configured authorities and reopen only after a satisfied prune."""
        policy = self._retention_policy
        clock_sampler = self._clock_sampler
        if policy is None or clock_sampler is None:
            msg = "retention lifecycle is unavailable"
            raise ValueError(msg)
        return self.prune(policy, clock=clock_sampler())

    def _cache_full(self) -> AppError:
        return AppError(
            ErrorCode.CACHE_FULL,
            "The local artifact cache has reached its configured capacity.",
            http_status=507,
            safe_details={"maximum_bytes": self.max_bytes},
        )

    def _reserve_staging_bytes(self, path: Path, amount: int) -> None:
        if amount < 0:
            msg = "reservation amount must not be negative"
            raise ValueError(msg)
        if amount == 0:
            return
        with self._lock:
            if path not in self._staging_reservations:
                raise AppError(
                    ErrorCode.INVALID_INPUT,
                    "Staged artifact is not managed by this store.",
                )
            if self._used_bytes + self._reserved_bytes + amount > self.max_bytes:
                raise self._cache_full()
            self._staging_reservations[path] += amount
            self._reserved_bytes += amount

    def _release_staging_bytes(self, path: Path, amount: int) -> None:
        if amount <= 0:
            return
        with self._lock:
            current = self._staging_reservations.get(path)
            if current is None or amount > current:
                msg = "staging reservation release is unbalanced"
                raise RuntimeError(msg)
            self._staging_reservations[path] = current - amount
            self._reserved_bytes -= amount

    @staticmethod
    def _validate_namespace(namespace: str) -> str:
        if namespace not in _ALLOWED_NAMESPACES:
            raise AppError(
                ErrorCode.INVALID_INPUT, "Artifact namespace is not permitted."
            )
        return namespace

    @staticmethod
    def _validate_filename(filename: str) -> str:
        if (
            not filename
            or filename in {".", ".."}
            or "\x00" in filename
            or "/" in filename
            or "\\" in filename
        ):
            raise AppError(ErrorCode.INVALID_INPUT, "Artifact filename is invalid.")
        if PurePosixPath(filename).name != filename:
            raise AppError(ErrorCode.INVALID_INPUT, "Artifact filename is invalid.")
        return filename

    @staticmethod
    def _validate_media_type(media_type: str) -> str:
        value = media_type.strip().lower()
        if (
            not value
            or "/" not in value
            or any(character.isspace() for character in value)
        ):
            raise AppError(ErrorCode.INVALID_INPUT, "Artifact media type is invalid.")
        return value

    def _validated_render_subtree(
        self, relative_path: str
    ) -> tuple[PurePosixPath, Path]:
        pure = PurePosixPath(relative_path)
        if (
            pure.is_absolute()
            or len(pure.parts) < _MIN_RENDER_SUBTREE_PARTS
            or pure.parts[0] != "renders"
            or any(part in {"", ".", ".."} for part in pure.parts)
            or pure.as_posix() != relative_path
            or "\\" in relative_path
            or "\x00" in relative_path
        ):
            raise AppError(ErrorCode.INVALID_INPUT, "Render subtree path is invalid.")
        render_id = pure.parts[1]
        if (
            len(render_id) != _RENDER_ID_LENGTH
            or not render_id.startswith("rnd_")
            or any(character not in "0123456789abcdef" for character in render_id[4:])
        ):
            raise AppError(
                ErrorCode.INVALID_INPUT, "Render subtree identifier is invalid."
            )
        destination = self.root.joinpath(*pure.parts)
        current = self.root
        for part in pure.parts:
            current /= part
            if current.is_symlink():
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "Render storage is corrupted.",
                    http_status=500,
                )
        return pure, destination

    def _render_lock_for(self, pure: PurePosixPath) -> _LockProtocol:
        digest = hashlib.sha256(pure.parts[1].encode("ascii")).digest()
        return self._render_locks[
            int.from_bytes(digest[:2], "big") % len(self._render_locks)
        ]

    @staticmethod
    def _render_tree_bytes(path: Path) -> int:
        if not path.exists():
            return 0
        if path.is_symlink() or not path.is_dir():
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Render storage is corrupted.",
                http_status=500,
            )
        total = 0
        for directory, directories, files in os.walk(path, followlinks=False):
            base = Path(directory)
            for name in directories:
                if (base / name).is_symlink():
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Render storage is corrupted.",
                        http_status=500,
                    )
            for name in files:
                candidate = base / name
                metadata = candidate.lstat()
                if not stat.S_ISREG(metadata.st_mode):
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Render storage is corrupted.",
                        http_status=500,
                    )
                if name != INSERTION_SEQUENCE_FILENAME:
                    total += metadata.st_size
        return total

    def _delete_render_subtree_locked(
        self,
        path: Path,
        *,
        transaction_token: object | None = None,
    ) -> bool:
        self._verify_store_root_identity()
        with self._lock:
            relative = path.relative_to(self.root)
            if len(relative.parts) < _MIN_OBJECT_KEY_PARTS:
                msg = "render transaction lease authority is invalid"
                raise RuntimeError(msg)
            object_key = "/".join(relative.parts[:_MIN_OBJECT_KEY_PARTS])
            transaction_leases = self._render_transaction_leases.get(
                object_key,
                set(),
            )
            if (
                transaction_token is not None
                and transaction_token not in transaction_leases
            ):
                msg = "render transaction lease authority is unavailable"
                raise RuntimeError(msg)
            foreign_transaction_lease = bool(
                transaction_leases
                - ({transaction_token} if transaction_token is not None else set())
            )
            if (
                self._asset_leases.get(object_key, 0) > 0
                or foreign_transaction_lease
                or (transaction_token is None and transaction_leases)
            ):
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "The render is currently in use and cannot be modified.",
                    http_status=409,
                )
            _ = self._render_tree_bytes(path)
            if not path.exists():
                return False
            removes_object_root = path.parent == self.root / "renders"
            object_key = f"renders/{path.name}"
            try:
                shutil.rmtree(path)
            finally:
                insertion_order = self._insertion_order
                if removes_object_root and insertion_order is not None:
                    insertion_order.remove(object_key)
                _ = self._render_tree_bytes(path)
                # Deletion is also the recovery path for a cache that was
                # externally truncated or corrupted. Reconcile committed bytes
                # while the quota lock excludes in-process publishers.
                self._used_bytes = self._scan_existing_bytes()
            return True

    def begin_render_transaction(
        self, relative_subtree: str, *, completion_file: str
    ) -> _RenderTransaction:
        """Lock one render subtree and recover it unless already complete."""
        self._verify_store_root_identity()
        pure, subtree = self._validated_render_subtree(relative_subtree)
        completion_file = self._validate_filename(completion_file)
        completion = subtree / completion_file
        lock = self._render_lock_for(pure)
        _ = lock.acquire()
        object_key = "/".join(pure.parts[:_MIN_OBJECT_KEY_PARTS])
        transaction_token = object()
        try:
            with self._lock:
                self._register_render_transaction_locked(
                    object_key,
                    transaction_token,
                )
                complete = _render_completion_exists(completion)
            if not complete:
                _ = self._delete_render_subtree_locked(
                    subtree,
                    transaction_token=transaction_token,
                )
            return _RenderTransaction(
                subtree,
                completion,
                _RenderTransactionBinding(
                    lock=lock,
                    verify_root=self._verify_store_root_identity,
                    delete_subtree=partial(
                        self._delete_render_subtree_locked,
                        transaction_token=transaction_token,
                    ),
                    release_lease=partial(
                        self.release_asset_lease,
                        object_key,
                        transaction_token=transaction_token,
                    ),
                    stage=self._stage_render_transaction,
                ),
                transaction_token,
                complete=complete,
            )
        except BaseException:
            try:
                with contextlib.suppress(RuntimeError):
                    self.release_asset_lease(
                        object_key,
                        transaction_token=transaction_token,
                    )
            finally:
                lock.release()
            raise

    def delete_render_subtree(self, relative_subtree: str) -> bool:
        """Delete one validated render subtree and reconcile cache usage."""
        self._verify_store_root_identity()
        pure, subtree = self._validated_render_subtree(relative_subtree)
        lock = self._render_lock_for(pure)
        with lock:
            return self._delete_render_subtree_locked(subtree)

    def _stage_render_transaction(
        self,
        suffix: str,
        transaction_token: object,
        transaction_guard: Callable[[], None],
        transaction_cleanup_guard: Callable[[], None],
        transaction_subtree: Path,
    ) -> _StagedWriter:
        """Create one writer bound to an exact live transaction capability."""
        return self.stage(
            suffix=suffix,
            _transaction_token=transaction_token,
            _transaction_guard=transaction_guard,
            _transaction_cleanup_guard=transaction_cleanup_guard,
            _transaction_subtree=transaction_subtree,
        )

    def stage(
        self,
        *,
        suffix: str = "",
        _transaction_token: object | None = None,
        _transaction_guard: Callable[[], None] | None = None,
        _transaction_cleanup_guard: Callable[[], None] | None = None,
        _transaction_subtree: Path | None = None,
    ) -> _StagedWriter:
        """Create an exclusive bounded writer in the staging directory."""
        transaction_values = (
            _transaction_token,
            _transaction_guard,
            _transaction_cleanup_guard,
            _transaction_subtree,
        )
        if any(value is None for value in transaction_values) and any(
            value is not None for value in transaction_values
        ):
            msg = "render transaction staging authority is invalid"
            raise RuntimeError(msg)
        if _transaction_guard is not None:
            _transaction_guard()
        self._verify_store_root_identity()
        if "/" in suffix or "\\" in suffix or "\x00" in suffix:
            raise AppError(ErrorCode.INVALID_INPUT, "Staging suffix is invalid.")
        path = self.staging_dir / f"stage-{secrets.token_hex(16)}{suffix}"
        nofollow = cast("object", getattr(os, "O_NOFOLLOW", None))
        if type(nofollow) is not int:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Secure staging file creation is unavailable.",
                http_status=500,
            )
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | nofollow
        descriptor = os.open(path, flags, 0o600)
        try:
            _prepare_private_staged_descriptor(descriptor)
            stream = os.fdopen(descriptor, "w+b")
        except BaseException:
            os.close(descriptor)
            path.unlink(missing_ok=True)
            raise
        try:
            with self._lock:
                self._staging_reservations[path] = 0
            return _StagedWriter(
                _StagedOperations(
                    verify_access=(
                        _transaction_guard
                        if _transaction_guard is not None
                        else _allow_staged_access
                    ),
                    verify_cleanup=(
                        _transaction_cleanup_guard
                        if _transaction_cleanup_guard is not None
                        else _allow_staged_access
                    ),
                    verify_root=self._verify_store_root_identity,
                    reserve=self._reserve_staging_bytes,
                    release=self._release_staging_bytes,
                    commit_file=self._commit_staged_file,
                    commit_render=partial(
                        self._commit_staged_render,
                        transaction_token=_transaction_token,
                        transaction_guard=_transaction_guard,
                        transaction_subtree=_transaction_subtree,
                    ),
                    replace_render=partial(
                        self._replace_staged_render,
                        transaction_token=_transaction_token,
                        transaction_guard=_transaction_guard,
                        transaction_subtree=_transaction_subtree,
                    ),
                    discard=self._discard_staged_file,
                ),
                path,
                stream,
            )
        except BaseException:
            stream.close()
            path.unlink(missing_ok=True)
            with self._lock:
                reservation = self._staging_reservations.pop(path, 0)
                self._reserved_bytes -= reservation
            raise

    def _discard_staged_file(self, staged: Path | str) -> None:
        path = Path(staged)
        try:
            self._verify_store_root_identity()
        except BaseException:
            with self._lock:
                reservation = self._staging_reservations.pop(path, 0)
                self._reserved_bytes -= reservation
            raise
        path.unlink(missing_ok=True)
        with self._lock:
            reservation = self._staging_reservations.pop(path, 0)
            self._reserved_bytes -= reservation

    def put_bytes(
        self, data: bytes, *, namespace: str, filename: str, media_type: str
    ) -> StoredArtifact:
        """Publish bytes at their deterministic content-addressed location."""
        self._verify_store_root_identity()
        namespace = self._validate_namespace(namespace)
        filename = self._validate_filename(filename)
        media_type = self._validate_media_type(media_type)
        sha256 = hashlib.sha256(data).hexdigest()
        object_id = f"{_ALLOWED_NAMESPACES[namespace]}_{sha256}"
        destination = self.root / namespace / object_id / filename
        if destination.exists():
            if _sha256_path(destination) != sha256:
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "A content-address collision was detected.",
                    http_status=500,
                )
            return StoredArtifact(
                object_id=object_id,
                sha256=sha256,
                size=len(data),
                media_type=media_type,
                relative_path=destination.relative_to(self.root).as_posix(),
                absolute_path=destination,
            )
        with self.stage(suffix=Path(filename).suffix) as stream:
            _ = stream.write(data)
            return stream.commit(
                namespace=namespace, filename=filename, media_type=media_type
            )

    @staticmethod
    def _validate_staged_identity(
        path: Path,
        snapshot: _StagedSnapshot,
    ) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError as exc:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Staged artifact identity changed before commit.",
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != snapshot.size
            or metadata.st_dev != snapshot.device
            or metadata.st_ino != snapshot.inode
            or metadata.st_mtime_ns != snapshot.mtime_ns
            or metadata.st_ctime_ns != snapshot.ctime_ns
        ):
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Staged artifact identity changed before commit.",
            )

    def _reconcile_staged_size_locked(self, path: Path, *, size: int) -> int:
        reserved = self._staging_reservations.get(path)
        if reserved is None:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Staged artifact is not managed by this store.",
            )
        if size > reserved:
            additional = size - reserved
            if self._used_bytes + self._reserved_bytes + additional > self.max_bytes:
                raise self._cache_full()
            self._staging_reservations[path] += additional
            self._reserved_bytes += additional
        elif size < reserved:
            self._staging_reservations[path] = size
            self._reserved_bytes -= reserved - size
        return size

    def _ensure_insertion_sequence(self, key: str, object_path: Path) -> None:
        insertion_order = self._insertion_order
        if insertion_order is not None:
            _ = insertion_order.ensure(key, object_path)

    @staticmethod
    def _validate_published_identity(
        destination: Path,
        snapshot: _StagedSnapshot,
    ) -> None:
        published = destination.lstat()
        if (
            published.st_dev != snapshot.device
            or published.st_ino != snapshot.inode
            or published.st_size != snapshot.size
            or published.st_mtime_ns != snapshot.mtime_ns
        ):
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Staged artifact identity changed during commit.",
            )

    def _release_staged_reservation_locked(self, path: Path, reserved: int) -> None:
        del self._staging_reservations[path]
        self._reserved_bytes -= reserved

    def _consume_existing_document_locked(
        self,
        staged: Path,
        destination: Path,
        object_dir: Path,
        object_key: str,
        snapshot: _StagedSnapshot,
    ) -> None:
        if _sha256_path(destination) != snapshot.sha256:
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "A content-address collision was detected.",
                http_status=500,
            )
        self._ensure_insertion_sequence(object_key, object_dir)
        self._validate_staged_identity(staged, snapshot)
        staged.unlink(missing_ok=True)
        self._release_staged_reservation_locked(staged, snapshot.size)

    def _publish_new_document_locked(
        self,
        staged: Path,
        destination: Path,
        object_dir: Path,
        object_key: str,
        snapshot: _StagedSnapshot,
    ) -> None:
        try:
            self._ensure_insertion_sequence(object_key, object_dir)
            _ = staged.replace(destination)
            self._validate_published_identity(destination, snapshot)
        except BaseException:
            destination.unlink(missing_ok=True)
            insertion_order = self._insertion_order
            if insertion_order is not None:
                insertion_order.remove(object_key)
            _remove_storage_path(object_dir)
            raise
        self._release_staged_reservation_locked(staged, snapshot.size)
        self._used_bytes += snapshot.size

    def _commit_staged_file(
        self,
        staged: Path,
        request: _StagedFileCommit,
    ) -> StoredArtifact:
        self._verify_store_root_identity()
        namespace = self._validate_namespace(request.namespace)
        filename = self._validate_filename(request.filename)
        media_type = self._validate_media_type(request.media_type)
        snapshot = request.snapshot
        sha256 = snapshot.sha256
        size = snapshot.size
        staged_path = staged.absolute()
        if staged_path.parent != self.staging_dir:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Staged artifact is outside the storage staging directory.",
            )
        object_id = f"{_ALLOWED_NAMESPACES[namespace]}_{sha256}"
        object_dir = self.root / namespace / object_id
        object_key = f"{namespace}/{object_id}"
        _ensure_private_directory_path(
            object_dir,
            context="document object",
        )
        destination = object_dir / filename
        with self._lock:
            self._validate_staged_identity(staged_path, snapshot)
            _ = self._reconcile_staged_size_locked(staged_path, size=size)
            if destination.exists():
                self._consume_existing_document_locked(
                    staged_path,
                    destination,
                    object_dir,
                    object_key,
                    snapshot,
                )
            else:
                self._publish_new_document_locked(
                    staged_path,
                    destination,
                    object_dir,
                    object_key,
                    snapshot,
                )
        if destination.exists():
            _fsync_directory(object_dir)
        _fsync_directory(self.staging_dir)
        relative_path = destination.relative_to(self.root).as_posix()
        return StoredArtifact(
            object_id=object_id,
            sha256=sha256,
            size=size,
            media_type=media_type,
            relative_path=relative_path,
            absolute_path=destination,
        )

    def _validated_render_destination(self, relative_path: str) -> tuple[Path, Path]:
        pure = PurePosixPath(relative_path)
        if (
            pure.is_absolute()
            or not pure.parts
            or pure.parts[0] != "renders"
            or any(part in {"", ".", ".."} for part in pure.parts)
            or pure.as_posix() != relative_path
            or "\\" in relative_path
            or "\x00" in relative_path
        ):
            raise AppError(ErrorCode.INVALID_INPUT, "Render asset path is invalid.")
        destination = self.root / Path(*pure.parts)
        current = self.root
        for index, component in enumerate(pure.parts):
            current /= component
            if current.is_symlink():
                if index == len(pure.parts) - 1:
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "Render storage is corrupted.",
                        http_status=500,
                    )
                raise AppError(
                    ErrorCode.INVALID_INPUT,
                    "Render asset path is invalid.",
                )
        parent = destination.parent
        if destination.is_symlink():
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Render storage is corrupted.",
                http_status=500,
            )
        return destination, parent

    def _commit_staged_render(
        self,
        staged: Path,
        request: _StagedRenderCommit,
        *,
        transaction_token: object | None = None,
        transaction_guard: Callable[[], None] | None = None,
        transaction_subtree: Path | None = None,
    ) -> tuple[str, str]:
        self._invoke_render_transaction_guard(transaction_guard)
        self._verify_store_root_identity()
        relative_path = request.relative_path
        snapshot = request.snapshot
        sha256 = snapshot.sha256
        size = snapshot.size
        destination, parent = self._validated_render_destination(relative_path)
        render_id = PurePosixPath(relative_path).parts[1]
        object_key = f"renders/{render_id}"
        object_root = self.root / "renders" / render_id
        with self._lock:
            self._require_render_transaction_destination(
                destination,
                transaction_subtree,
                transaction_token,
            )
            self._require_render_mutation_authority_locked(
                object_key,
                transaction_token,
            )
            current = self.root / "renders"
            for component in parent.relative_to(current).parts:
                current /= component
                _ensure_private_directory_path(
                    current,
                    context="render object",
                )
            self._validate_staged_identity(
                staged,
                snapshot,
            )
            reserved = self._staging_reservations.get(staged)
            if reserved is None:
                raise AppError(
                    ErrorCode.INVALID_INPUT,
                    "Staged artifact is not managed by this store.",
                )
            if size != reserved:
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "Staged render accounting is inconsistent.",
                    http_status=500,
                )
            if destination.exists():
                if _sha256_path(destination) != sha256:
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "A deterministic render collision was detected.",
                        http_status=500,
                    )
                if self._insertion_order is not None:
                    _ = self._insertion_order.ensure(object_key, object_root)
                self._validate_staged_identity(
                    staged,
                    snapshot,
                )
                staged.unlink(missing_ok=True)
                del self._staging_reservations[staged]
                self._reserved_bytes -= reserved
            else:
                if self._insertion_order is not None:
                    _ = self._insertion_order.ensure(object_key, object_root)
                _ = staged.replace(destination)
                published = destination.lstat()
                if (
                    published.st_dev != snapshot.device
                    or published.st_ino != snapshot.inode
                    or published.st_size != size
                    or published.st_mtime_ns != snapshot.mtime_ns
                ):
                    destination.unlink(missing_ok=True)
                    raise AppError(
                        ErrorCode.INVALID_INPUT,
                        "Staged artifact identity changed during commit.",
                    )
                del self._staging_reservations[staged]
                self._reserved_bytes -= reserved
                self._used_bytes += size
        if destination.exists():
            _fsync_directory(parent)
        _fsync_directory(self.staging_dir)
        return relative_path, sha256

    def _replace_staged_render(
        self,
        staged: Path,
        request: _StagedRenderReplacement,
        *,
        transaction_token: object | None = None,
        transaction_guard: Callable[[], None] | None = None,
        transaction_subtree: Path | None = None,
    ) -> tuple[str, str]:
        self._invoke_render_transaction_guard(transaction_guard)
        self._verify_store_root_identity()
        relative_path = request.relative_path
        expected_sha256 = request.expected_sha256
        if len(expected_sha256) != _SHA256_HEX_LENGTH or any(
            character not in "0123456789abcdef" for character in expected_sha256
        ):
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "Expected render digest is invalid.",
            )
        snapshot = request.snapshot
        sha256 = snapshot.sha256
        size = snapshot.size
        destination, parent = self._validated_render_destination(relative_path)
        object_key = "/".join(PurePosixPath(relative_path).parts[:2])
        with self._lock:
            self._require_render_transaction_destination(
                destination,
                transaction_subtree,
                transaction_token,
            )
            self._require_render_mutation_authority_locked(
                object_key,
                transaction_token,
            )
            self._validate_staged_identity(staged, snapshot)
            reserved = self._staging_reservations.get(staged)
            if reserved is None:
                raise AppError(
                    ErrorCode.INVALID_INPUT,
                    "Staged artifact is not managed by this store.",
                )
            if size != reserved:
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "Staged render accounting is inconsistent.",
                    http_status=500,
                )
            if (
                not destination.is_file()
                or destination.is_symlink()
                or _sha256_path(destination) != expected_sha256
            ):
                raise AppError(
                    ErrorCode.INTERNAL_ERROR,
                    "Render replacement precondition failed.",
                    http_status=500,
                )
            replaced_size = destination.stat().st_size
            self._validate_staged_identity(staged, snapshot)
            _ = staged.replace(destination)
            published = destination.lstat()
            if (
                published.st_dev != snapshot.device
                or published.st_ino != snapshot.inode
                or published.st_size != size
                or published.st_mtime_ns != snapshot.mtime_ns
            ):
                try:
                    destination.unlink(missing_ok=True)
                finally:
                    self._used_bytes = self._scan_existing_bytes()
                raise AppError(
                    ErrorCode.INVALID_INPUT,
                    "Staged artifact identity changed during commit.",
                )
            del self._staging_reservations[staged]
            self._reserved_bytes -= reserved
            self._used_bytes += size - replaced_size
        _fsync_directory(parent)
        _fsync_directory(self.staging_dir)
        return relative_path, sha256

    def put_render_bytes(self, relative_path: str, data: bytes) -> tuple[str, str]:
        """Publish a deterministic render asset and return its path and digest."""
        with self.stage(suffix=Path(relative_path).suffix) as stream:
            _ = stream.write(data)
            return stream.commit_render(relative_path)

    def replace_render_bytes_if_matches(
        self,
        relative_path: str,
        data: bytes,
        *,
        expected_sha256: str,
    ) -> tuple[str, str]:
        """Atomically replace one render file when its digest is unchanged."""
        with self.stage(suffix=Path(relative_path).suffix) as stream:
            _ = stream.write(data)
            return stream.replace_render(
                relative_path,
                expected_sha256=expected_sha256,
            )

    def resolve_asset(self, relative_path: str) -> Path:
        """Resolve an existing regular asset inside an approved namespace."""
        self._verify_store_root_identity()
        parts = _validated_asset_parts(relative_path)
        return _resolve_private_asset(self._root_descriptor, self.root, parts)
