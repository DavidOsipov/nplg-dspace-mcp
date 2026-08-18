# Copyright (c) 2026 David Osipov
"""Content-addressed local storage with bounded metadata."""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import Lock, RLock
from typing import TYPE_CHECKING, BinaryIO, Protocol, Self

from .errors import AppError, ErrorCode

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

_ALLOWED_NAMESPACES = {"documents": "doc", "renders": "rnd"}
_DEFAULT_MAX_BYTES = 20 * 1024 * 1024 * 1024
_RENDER_ID_LENGTH = 36
_MIN_RENDER_SUBTREE_PARTS = 2


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
class _StagedOperations:
    reserve: Callable[[Path, int], None]
    release: Callable[[Path, int], None]
    commit_file: Callable[[Path, _StagedFileCommit], StoredArtifact]
    commit_render: Callable[[Path, _StagedRenderCommit], tuple[str, str]]
    discard: Callable[[Path], None]


class _LockProtocol(Protocol):
    def acquire(self) -> bool: ...
    def release(self) -> None: ...

    def __enter__(self) -> object: ...
    def __exit__(
        self,
        t: type[BaseException] | None,
        v: BaseException | None,
        tb: TracebackType | None,
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
        if self._stream is None:
            msg = "staged writer is already closed"
            raise RuntimeError(msg)
        return self

    def write(self, data: bytes) -> int:
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

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        self._operations.discard(self._path)


class _RenderTransaction:
    def __init__(
        self,
        subtree: Path,
        completion: Path,
        lock: _LockProtocol,
        delete_subtree: Callable[[Path], bool],
        *,
        complete: bool,
    ) -> None:
        super().__init__()
        self._subtree = subtree
        self._completion = completion
        self._lock = lock
        self._delete_subtree = delete_subtree
        self.complete = complete
        self._closed = False

    def commit(self) -> None:
        if self._closed:
            msg = "render transaction is already closed"
            raise RuntimeError(msg)
        if self._completion.is_symlink() or not self._completion.is_file():
            self.rollback()
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "A render transaction did not publish its completion manifest.",
                http_status=500,
            )
        self._closed = True
        self._lock.release()

    def rollback(self) -> None:
        if self._closed:
            return
        try:
            if not self.complete:
                _ = self._delete_subtree(self._subtree)
        finally:
            self._closed = True
            self._lock.release()

    def reset(self) -> None:
        if self._closed:
            msg = "render transaction is already closed"
            raise RuntimeError(msg)
        _ = self._delete_subtree(self._subtree)
        self.complete = False


class ContentAddressedStore:
    """Persist bounded document and render artifacts under a trusted root."""

    _render_locks: tuple[_LockProtocol, ...]

    def __init__(
        self, root: Path | str, *, max_bytes: int = _DEFAULT_MAX_BYTES
    ) -> None:
        """Initialize the storage root and reconcile existing cache usage."""
        super().__init__()
        if type(max_bytes) is not int or max_bytes <= 0:
            msg = "max_bytes must be a positive integer"
            raise ValueError(msg)
        self.root = Path(root).expanduser().resolve()
        self.staging_dir = self.root / ".staging"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.staging_dir.is_symlink():
            msg = "cache staging directory must not be a symlink"
            raise ValueError(msg)
        self.staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.staging_dir.chmod(0o700)
        for namespace in _ALLOWED_NAMESPACES:
            namespace_path = self.root / namespace
            if namespace_path.is_symlink():
                msg = "cache namespace must not be a symlink"
                raise ValueError(msg)
            namespace_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._cleanup_stale_staging()
        self._cleanup_incomplete_renders()
        self.max_bytes = max_bytes
        self._lock = Lock()
        self._render_locks: tuple[_LockProtocol, ...] = tuple(
            RLock() for _ in range(64)
        )
        self._used_bytes = self._scan_existing_bytes()
        self._reserved_bytes = 0
        self._staging_reservations: dict[Path, int] = {}

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
                    candidate = base / name
                    metadata = candidate.lstat()
                    if stat.S_ISREG(metadata.st_mode):
                        total += metadata.st_size
        return total

    def _cleanup_stale_staging(self) -> None:
        for candidate in self.staging_dir.iterdir():
            if candidate.is_symlink() or not candidate.is_dir():
                candidate.unlink(missing_ok=True)
            else:
                shutil.rmtree(candidate)

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
                total += metadata.st_size
        return total

    def _delete_render_subtree_locked(self, path: Path) -> bool:
        with self._lock:
            _ = self._render_tree_bytes(path)
            if not path.exists():
                return False
            try:
                shutil.rmtree(path)
            finally:
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
        pure, subtree = self._validated_render_subtree(relative_subtree)
        completion_file = self._validate_filename(completion_file)
        completion = subtree / completion_file
        lock = self._render_lock_for(pure)
        _ = lock.acquire()
        try:
            complete = _render_completion_exists(completion)
            if not complete:
                _ = self._delete_render_subtree_locked(subtree)
            return _RenderTransaction(
                subtree,
                completion,
                lock,
                self._delete_render_subtree_locked,
                complete=complete,
            )
        except BaseException:
            lock.release()
            raise

    def delete_render_subtree(self, relative_subtree: str) -> bool:
        """Delete one validated render subtree and reconcile cache usage."""
        pure, subtree = self._validated_render_subtree(relative_subtree)
        lock = self._render_lock_for(pure)
        with lock:
            return self._delete_render_subtree_locked(subtree)

    def stage(self, *, suffix: str = "") -> _StagedWriter:
        """Create an exclusive bounded writer in the staging directory."""
        if "/" in suffix or "\\" in suffix or "\x00" in suffix:
            raise AppError(ErrorCode.INVALID_INPUT, "Staging suffix is invalid.")
        path = self.staging_dir / f"stage-{secrets.token_hex(16)}{suffix}"
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
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
                    reserve=self._reserve_staging_bytes,
                    release=self._release_staging_bytes,
                    commit_file=self._commit_staged_file,
                    commit_render=self._commit_staged_render,
                    discard=self._discard_staged_file,
                ),
                path,
                stream,
            )
        except BaseException:
            stream.close()
            path.unlink(missing_ok=True)
            raise

    def _discard_staged_file(self, staged: Path | str) -> None:
        path = Path(staged)
        path.unlink(missing_ok=True)
        with self._lock:
            reservation = self._staging_reservations.pop(path, 0)
            self._reserved_bytes -= reservation

    def put_bytes(
        self, data: bytes, *, namespace: str, filename: str, media_type: str
    ) -> StoredArtifact:
        """Publish bytes at their deterministic content-addressed location."""
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

    def _commit_staged_file(
        self,
        staged: Path,
        request: _StagedFileCommit,
    ) -> StoredArtifact:
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
        object_dir.mkdir(parents=True, exist_ok=True)
        destination = object_dir / filename
        with self._lock:
            self._validate_staged_identity(
                staged_path,
                snapshot,
            )
            reserved = self._staging_reservations.get(staged_path)
            if reserved is None:
                raise AppError(
                    ErrorCode.INVALID_INPUT,
                    "Staged artifact is not managed by this store.",
                )
            if size > reserved:
                additional = size - reserved
                if (
                    self._used_bytes + self._reserved_bytes + additional
                    > self.max_bytes
                ):
                    raise self._cache_full()
                self._staging_reservations[staged_path] += additional
                self._reserved_bytes += additional
                reserved = size
            elif size < reserved:
                self._staging_reservations[staged_path] = size
                self._reserved_bytes -= reserved - size
                reserved = size
            if destination.exists():
                if _sha256_path(destination) != sha256:
                    raise AppError(
                        ErrorCode.INTERNAL_ERROR,
                        "A content-address collision was detected.",
                        http_status=500,
                    )
                self._validate_staged_identity(
                    staged_path,
                    snapshot,
                )
                staged_path.unlink(missing_ok=True)
                del self._staging_reservations[staged_path]
                self._reserved_bytes -= reserved
            else:
                _ = staged_path.replace(destination)
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
                del self._staging_reservations[staged_path]
                self._reserved_bytes -= reserved
                self._used_bytes += size
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

    def _commit_staged_render(
        self,
        staged: Path,
        request: _StagedRenderCommit,
    ) -> tuple[str, str]:
        relative_path = request.relative_path
        snapshot = request.snapshot
        sha256 = snapshot.sha256
        size = snapshot.size
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
        render_root = (self.root / "renders").resolve()
        destination = self.root / Path(*pure.parts)
        parent = destination.parent.resolve()
        try:
            _ = parent.relative_to(render_root)
        except ValueError as exc:
            raise AppError(
                ErrorCode.INVALID_INPUT, "Render asset path escapes storage."
            ) from exc
        if destination.is_symlink():
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "Render storage is corrupted.",
                http_status=500,
            )
        with self._lock:
            parent.mkdir(parents=True, exist_ok=True)
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
                self._validate_staged_identity(
                    staged,
                    snapshot,
                )
                staged.unlink(missing_ok=True)
                del self._staging_reservations[staged]
                self._reserved_bytes -= reserved
            else:
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

    def put_render_bytes(self, relative_path: str, data: bytes) -> tuple[str, str]:
        """Publish a deterministic render asset and return its path and digest."""
        with self.stage(suffix=Path(relative_path).suffix) as stream:
            _ = stream.write(data)
            return stream.commit_render(relative_path)

    def resolve_asset(self, relative_path: str) -> Path:
        """Resolve an existing regular asset inside an approved namespace."""
        if not relative_path or "\\" in relative_path or "\x00" in relative_path:
            raise AppError(ErrorCode.INVALID_INPUT, "Asset path is invalid.")
        pure = PurePosixPath(relative_path)
        if (
            pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
            or pure.as_posix() != relative_path
        ):
            raise AppError(ErrorCode.INVALID_INPUT, "Asset path is invalid.")
        if not pure.parts or pure.parts[0] not in _ALLOWED_NAMESPACES:
            raise AppError(
                ErrorCode.INVALID_INPUT, "Asset path is outside an approved namespace."
            )
        candidate = (self.root / Path(*pure.parts)).resolve()
        try:
            _ = candidate.relative_to(self.root)
        except ValueError as exc:
            raise AppError(
                ErrorCode.INVALID_INPUT, "Asset path escapes the storage root."
            ) from exc
        if not candidate.is_file() or candidate.is_symlink():
            raise AppError(
                ErrorCode.NOT_FOUND,
                "The requested artifact was not found.",
                http_status=404,
            )
        return candidate
