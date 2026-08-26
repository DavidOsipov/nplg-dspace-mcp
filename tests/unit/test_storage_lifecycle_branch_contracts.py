# Copyright (c) 2026 David Osipov
"""Adversarial branch contracts for private clock-state persistence."""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

import pytest

from nplg_mcp.storage_lifecycle import ClockBlocker, ClockHighWater

if TYPE_CHECKING:
    from collections.abc import Generator


class _StateReader(Protocol):
    def __call__(
        self,
        directory: int,
    ) -> tuple[object | None, ClockBlocker | None, object | None]: ...


class _SnapshotAction(Protocol):
    def __call__(self, directory: int, name: str, snapshot: object) -> object: ...


class _SnapshotIdentityCheck(Protocol):
    def __call__(
        self,
        snapshot: object,
        metadata: os.stat_result,
        *,
        context: str,
    ) -> None: ...


class _QuarantineAction(Protocol):
    def __call__(self, directory: int, snapshot: object) -> bool: ...


class _ResidueReader(Protocol):
    def __call__(
        self,
        directory: int,
        name: str,
        metadata: os.stat_result,
    ) -> object | None: ...


class _CorruptStateRecovery(Protocol):
    def __call__(
        self,
        directory: int,
        *,
        name: str,
        quarantine_name: str,
        snapshot: object,
    ) -> bool: ...


class _DirectoryOpener(Protocol):
    def __call__(self, parent: Path) -> int: ...


class _CreatedDirectoryPreparer(Protocol):
    def __call__(
        self,
        parent: Path,
        before: os.stat_result,
    ) -> os.stat_result: ...


class _LockedDirectoryOpener(Protocol):
    def __call__(self) -> int: ...


class _LockedDirectoryValidator(Protocol):
    def __call__(
        self,
        directory: int,
        parent: Path,
        before: os.stat_result,
    ) -> None: ...


class _WriteTargetValidator(Protocol):
    def __call__(
        self,
        directory: int,
        name: str,
        *,
        require_absent: bool,
    ) -> None: ...


class _TemporaryStateCreator(Protocol):
    def __call__(self, directory: int, name: str, raw: bytes) -> object: ...


class _TemporaryStatePublisher(Protocol):
    def __call__(
        self,
        directory: int,
        *,
        temporary_name: str,
        name: str,
        created: object,
        require_absent: bool,
    ) -> None: ...


class _StateWriter(Protocol):
    def __call__(
        self,
        directory: int,
        record: object,
        *,
        require_absent: bool = False,
    ) -> None: ...


class _Stat(Protocol):
    def __call__(
        self,
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result: ...


_CORRUPT_STATE = b"{]"
_FINAL_REGULAR_FSTAT_CALL = 3
_INHERITABLE = True
_NONPRIVATE_DIRECTORY_MODE = 0o755
_PRIVATE_STATE_MODE = 0o600


def _guard(path: Path) -> ClockHighWater:
    return ClockHighWater(
        path,
        healthy_window_seconds=60,
        maximum_forward_slew_seconds=5,
    )


@contextmanager
def _directory_descriptor(path: Path) -> Generator[int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _corrupt_snapshot(
    guard: ClockHighWater,
    state: Path,
    directory: int,
) -> object:
    _ = state.write_bytes(_CORRUPT_STATE)
    state.chmod(_PRIVATE_STATE_MODE)
    read = cast("_StateReader", object.__getattribute__(guard, "_read"))
    record, blocker, snapshot = read(directory)
    assert record is None
    assert blocker is ClockBlocker.CORRUPT_STATE
    assert snapshot is not None
    return snapshot


def _changed_stat(
    metadata: os.stat_result,
    *,
    index: int,
    value: int,
) -> os.stat_result:
    fields = list(metadata)
    fields[index] = value
    return os.stat_result(fields)


def _final_regular_fstat_has_wrong_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fstat = os.fstat
    regular_calls = 0

    def wrong_final_size(descriptor: int) -> os.stat_result:
        nonlocal regular_calls
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            regular_calls += 1
            if regular_calls == _FINAL_REGULAR_FSTAT_CALL:
                return _changed_stat(
                    metadata,
                    index=stat.ST_SIZE,
                    value=metadata.st_size + 1,
                )
        return metadata

    monkeypatch.setattr(os, "fstat", wrong_final_size)


def test_cleanup_preserves_replacement_with_a_different_inode(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        replacement = tmp_path / "replacement"
        _ = replacement.write_bytes(b"replacement")
        replacement.chmod(_PRIVATE_STATE_MODE)
        unlink = cast(
            "_SnapshotAction",
            object.__getattribute__(guard, "_unlink_if_same_inode_at"),
        )
        _ = unlink(directory, replacement.name, snapshot)

    assert replacement.read_bytes() == b"replacement"


def test_snapshot_identity_check_rejects_replacement(tmp_path: Path) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        replacement = tmp_path / "replacement"
        _ = replacement.write_bytes(b"replacement")
        replacement.chmod(_PRIVATE_STATE_MODE)
        require_identity = cast(
            "_SnapshotIdentityCheck",
            object.__getattribute__(guard, "_require_snapshot_identity"),
        )

        with pytest.raises(ValueError, match="replacement identity changed"):
            require_identity(
                snapshot,
                replacement.stat(),
                context="replacement",
            )

    assert replacement.read_bytes() == b"replacement"


def test_quarantine_copy_removes_file_after_size_postcondition_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        create = cast(
            "_SnapshotAction",
            object.__getattribute__(guard, "_create_quarantine_copy_at"),
        )
        _final_regular_fstat_has_wrong_size(monkeypatch)

        with pytest.raises(ValueError, match="quarantine postcondition failed"):
            _ = create(directory, ".quarantine", snapshot)

    assert not (tmp_path / ".quarantine").exists()
    assert state.read_bytes() == _CORRUPT_STATE


def test_exact_quarantine_is_reused_without_republication(tmp_path: Path) -> None:
    state = tmp_path / "clock-high-water.json"
    quarantine = tmp_path / ".quarantine"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        _ = quarantine.write_bytes(_CORRUPT_STATE)
        quarantine.chmod(_PRIVATE_STATE_MODE)
        ensure = cast(
            "_SnapshotAction",
            object.__getattribute__(guard, "_ensure_quarantine_copy_at"),
        )

        assert ensure(directory, quarantine.name, snapshot) is True

    assert quarantine.read_bytes() == _CORRUPT_STATE


def test_exact_pending_quarantine_is_published(tmp_path: Path) -> None:
    state = tmp_path / "clock-high-water.json"
    quarantine = tmp_path / ".quarantine"
    pending = tmp_path / ".quarantine.pending"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        _ = pending.write_bytes(_CORRUPT_STATE)
        pending.chmod(_PRIVATE_STATE_MODE)
        ensure = cast(
            "_SnapshotAction",
            object.__getattribute__(guard, "_ensure_quarantine_copy_at"),
        )

        assert ensure(directory, quarantine.name, snapshot) is True

    assert quarantine.read_bytes() == _CORRUPT_STATE
    assert not pending.exists()


def test_nonprefix_pending_quarantine_is_not_laundered(tmp_path: Path) -> None:
    state = tmp_path / "clock-high-water.json"
    pending = tmp_path / ".quarantine.pending"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        _ = pending.write_bytes(b"XX")
        pending.chmod(_PRIVATE_STATE_MODE)
        ensure = cast(
            "_SnapshotAction",
            object.__getattribute__(guard, "_ensure_quarantine_copy_at"),
        )

        assert ensure(directory, ".quarantine", snapshot) is False

    assert pending.read_bytes() == b"XX"
    assert state.read_bytes() == _CORRUPT_STATE


@pytest.mark.parametrize("failure", ["opened-identity", "short-read"])
def test_residue_reader_rejects_unstable_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    residue = tmp_path / ".quarantine.pending"
    _ = residue.write_bytes(b"{")
    residue.chmod(_PRIVATE_STATE_MODE)
    guard = _guard(tmp_path / "clock-high-water.json")
    with _directory_descriptor(tmp_path) as directory:
        read_residue = cast(
            "_ResidueReader",
            object.__getattribute__(guard, "_read_quarantine_residue_at"),
        )
        metadata = residue.stat()
        if failure == "opened-identity":
            real_fstat = os.fstat

            def changed_opened_inode(descriptor: int) -> os.stat_result:
                opened = real_fstat(descriptor)
                return _changed_stat(
                    opened,
                    index=stat.ST_INO,
                    value=opened.st_ino + 1,
                )

            monkeypatch.setattr(os, "fstat", changed_opened_inode)
        else:

            def empty_read(_descriptor: int, _maximum: int) -> bytes:
                return b""

            monkeypatch.setattr(os, "read", empty_read)

        assert read_residue(directory, residue.name, metadata) is None

    assert residue.read_bytes() == b"{"


def test_residue_preservation_rejects_post_rename_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    residue = tmp_path / ".quarantine"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        _ = residue.write_bytes(b"{")
        residue.chmod(_PRIVATE_STATE_MODE)
        real_stat = cast("_Stat", os.stat)

        def changed_preserved_size(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *,
            dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> os.stat_result:
            metadata = real_stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )
            if isinstance(path, str) and ".incomplete-" in path:
                return _changed_stat(
                    metadata,
                    index=stat.ST_SIZE,
                    value=metadata.st_size + 1,
                )
            return metadata

        monkeypatch.setattr(os, "stat", changed_preserved_size)
        preserve = cast(
            "_SnapshotAction",
            object.__getattribute__(guard, "_preserve_quarantine_residue_at"),
        )

        assert preserve(directory, residue.name, snapshot) is False

    assert not residue.exists()
    preserved = tuple(tmp_path.glob(f"{residue.name}.incomplete-*"))
    assert len(preserved) == 1
    assert preserved[0].read_bytes() == b"{"
    assert state.read_bytes() == _CORRUPT_STATE


def test_recovery_rejects_non_directory_descriptor(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        recover = cast(
            "_CorruptStateRecovery",
            object.__getattribute__(guard, "_recover_corrupt_state_at"),
        )
        state_descriptor = os.open(state, os.O_RDONLY | os.O_CLOEXEC)
        try:
            assert (
                recover(
                    state_descriptor,
                    name=state.name,
                    quarantine_name=".quarantine",
                    snapshot=snapshot,
                )
                is False
            )
        finally:
            os.close(state_descriptor)

    assert state.read_bytes() == _CORRUPT_STATE
    assert not (tmp_path / ".quarantine").exists()


def test_recovery_rejects_stale_source_snapshot(tmp_path: Path) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        recover = cast(
            "_CorruptStateRecovery",
            object.__getattribute__(guard, "_recover_corrupt_state_at"),
        )
        _ = state.write_bytes(b"changed")
        state.chmod(_PRIVATE_STATE_MODE)
        assert (
            recover(
                directory,
                name=state.name,
                quarantine_name=".quarantine",
                snapshot=snapshot,
            )
            is False
        )

    assert state.read_bytes() == b"changed"
    assert not (tmp_path / ".quarantine").exists()


def test_quarantine_rejects_unsafe_basename(tmp_path: Path) -> None:
    state = tmp_path / "clock-high-water.json"
    source_guard = _guard(state)
    unsafe_guard = _guard(Path())
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(source_guard, state, directory)
        quarantine = cast(
            "_QuarantineAction",
            object.__getattribute__(unsafe_guard, "_quarantine_corrupt_state"),
        )

        assert quarantine(directory, snapshot) is False

    assert state.read_bytes() == _CORRUPT_STATE


def test_quarantine_requires_all_kernel_path_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "clock-high-water.json"
    guard = _guard(state)
    with _directory_descriptor(tmp_path) as directory:
        snapshot = _corrupt_snapshot(guard, state, directory)
        quarantine = cast(
            "_QuarantineAction",
            object.__getattribute__(guard, "_quarantine_corrupt_state"),
        )
        monkeypatch.delattr(os, "O_NOFOLLOW")

        assert quarantine(directory, snapshot) is False

    assert state.read_bytes() == _CORRUPT_STATE


def test_state_directory_opens_without_optional_o_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _guard(tmp_path / "clock-high-water.json")
    open_directory = cast(
        "_DirectoryOpener",
        object.__getattribute__(guard, "_open_state_directory"),
    )
    monkeypatch.delattr(os, "O_DIRECTORY")

    descriptor = open_directory(tmp_path)
    try:
        assert stat.S_ISDIR(os.fstat(descriptor).st_mode)
    finally:
        os.close(descriptor)


def test_created_parent_rejects_non_directory_metadata(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    _ = parent.write_bytes(b"")
    guard = _guard(tmp_path / "clock-high-water.json")
    prepare = cast(
        "_CreatedDirectoryPreparer",
        object.__getattribute__(guard, "_prepare_created_state_directory"),
    )

    with pytest.raises(ValueError, match="not service-owned"):
        _ = prepare(parent, parent.lstat())


def test_created_parent_rejects_failed_private_mode_postcondition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "cache"
    parent.mkdir()
    parent.chmod(_NONPRIVATE_DIRECTORY_MODE)
    guard = _guard(parent / "clock-high-water.json")
    prepare = cast(
        "_CreatedDirectoryPreparer",
        object.__getattribute__(guard, "_prepare_created_state_directory"),
    )

    def ignore_chmod(
        path: Path,
        mode: int,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        _ = (path, mode, follow_symlinks)

    monkeypatch.setattr(Path, "chmod", ignore_chmod)

    with pytest.raises(ValueError, match="private postcondition failed"):
        _ = prepare(parent, parent.lstat())

    assert stat.S_IMODE(parent.stat().st_mode) == _NONPRIVATE_DIRECTORY_MODE


def test_locked_state_open_rejects_unsafe_basename() -> None:
    guard = _guard(Path())
    open_locked = cast(
        "_LockedDirectoryOpener",
        object.__getattribute__(guard, "_open_locked_state_directory"),
    )

    with pytest.raises(ValueError, match="safe basename"):
        _ = open_locked()


def test_locked_directory_rejects_inheritable_descriptor(tmp_path: Path) -> None:
    guard = _guard(tmp_path / "clock-high-water.json")
    validate = cast(
        "_LockedDirectoryValidator",
        object.__getattribute__(guard, "_validate_locked_state_directory"),
    )
    before = tmp_path.lstat()
    with _directory_descriptor(tmp_path) as directory:
        os.set_inheritable(directory, _INHERITABLE)

        with pytest.raises(ValueError, match="directory identity changed"):
            validate(directory, tmp_path, before)


def test_write_target_requires_absence_for_existing_private_file(
    tmp_path: Path,
) -> None:
    state = tmp_path / "clock-high-water.json"
    _ = state.write_bytes(b"{}")
    state.chmod(_PRIVATE_STATE_MODE)
    guard = _guard(state)
    validate = cast(
        "_WriteTargetValidator",
        object.__getattribute__(guard, "_validate_write_target_at"),
    )
    with (
        _directory_descriptor(tmp_path) as directory,
        pytest.raises(ValueError, match="changed before exclusive creation"),
    ):
        validate(directory, state.name, require_absent=True)

    assert state.read_bytes() == b"{}"


def test_write_target_rejects_nonprivate_regular_file(tmp_path: Path) -> None:
    state = tmp_path / "clock-high-water.json"
    _ = state.write_bytes(b"{}")
    state.chmod(0o640)
    guard = _guard(state)
    validate = cast(
        "_WriteTargetValidator",
        object.__getattribute__(guard, "_validate_write_target_at"),
    )
    with (
        _directory_descriptor(tmp_path) as directory,
        pytest.raises(ValueError, match="not a private regular file"),
    ):
        validate(directory, state.name, require_absent=False)

    assert state.read_bytes() == b"{}"


def test_temporary_write_removes_file_after_size_postcondition_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temporary = tmp_path / ".clock.tmp"
    guard = _guard(tmp_path / "clock-high-water.json")
    create = cast(
        "_TemporaryStateCreator",
        object.__getattribute__(guard, "_create_temporary_state_at"),
    )
    with _directory_descriptor(tmp_path) as directory:
        _final_regular_fstat_has_wrong_size(monkeypatch)

        with pytest.raises(ValueError, match="write postcondition failed"):
            _ = create(directory, temporary.name, b"{}")

    assert not temporary.exists()


def test_temporary_write_preserves_unidentified_residue_after_fstat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temporary = tmp_path / ".clock.tmp"
    guard = _guard(tmp_path / "clock-high-water.json")
    create = cast(
        "_TemporaryStateCreator",
        object.__getattribute__(guard, "_create_temporary_state_at"),
    )
    real_fstat = os.fstat
    fstat_error = "simulated fstat failure"

    def fail_regular_fstat(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            raise OSError(fstat_error)
        return metadata

    monkeypatch.setattr(os, "fstat", fail_regular_fstat)
    with (
        _directory_descriptor(tmp_path) as directory,
        pytest.raises(OSError, match=fstat_error),
    ):
        _ = create(directory, temporary.name, b"{}")

    assert temporary.read_bytes() == b""


def test_publication_rejects_changed_content_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temporary = tmp_path / ".clock.tmp"
    state = tmp_path / "clock-high-water.json"
    guard = _guard(state)
    create = cast(
        "_TemporaryStateCreator",
        object.__getattribute__(guard, "_create_temporary_state_at"),
    )
    publish = cast(
        "_TemporaryStatePublisher",
        object.__getattribute__(guard, "_publish_temporary_state_at"),
    )
    with _directory_descriptor(tmp_path) as directory:
        created = create(directory, temporary.name, b"{}")
        real_stat = cast("_Stat", os.stat)

        def changed_active_size(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *,
            dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> os.stat_result:
            metadata = real_stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )
            if path == state.name and dir_fd == directory:
                return _changed_stat(
                    metadata,
                    index=stat.ST_SIZE,
                    value=metadata.st_size + 1,
                )
            return metadata

        monkeypatch.setattr(os, "stat", changed_active_size)

        with pytest.raises(ValueError, match="publication identity changed"):
            publish(
                directory,
                temporary_name=temporary.name,
                name=state.name,
                created=created,
                require_absent=False,
            )

    assert state.read_bytes() == b"{}"
    assert not temporary.exists()


def test_state_write_rejects_unsafe_basename_before_serialization(
    tmp_path: Path,
) -> None:
    guard = _guard(Path())
    write = cast(
        "_StateWriter",
        object.__getattribute__(guard, "_write"),
    )
    with (
        _directory_descriptor(tmp_path) as directory,
        pytest.raises(ValueError, match="safe basename"),
    ):
        write(directory, object())
