# Copyright (c) 2026 David Osipov
"""White-box fault injection for content-addressed storage internals."""

# These tests exercise descriptor, filesystem-race, and recovery guards that have
# no public seam; private access is confined to this implementation-test module.
# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

import os
import stat
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http import HTTPStatus
from pathlib import Path
from typing import BinaryIO, Never, cast

import pytest

import nplg_mcp.storage as storage_module
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.storage import ContentAddressedStore, StoreLifecycleConfiguration
from nplg_mcp.storage_lifecycle import (
    ClockHighWater,
    LifecycleAlert,
    LifecycleAlertEvent,
    LifecycleBlocker,
    PruneBlocker,
    PublicationBlocker,
    PublicationReservationError,
    RetentionClockSample,
    RetentionPolicy,
    StorageCapacity,
)

_FINAL_DIRECTORY_IDENTITY_READ = 3
_GROWN_RESERVATION_BYTES = 3
_NESTED_TREE_INODES = 3
_POST_PRUNE_CAPACITY_SAMPLE_COUNT = 2
_PRIVATE_DIRECTORY_MODE = 0o700
_GIB = 1024 * 1024 * 1024
_COVERAGE_CLOCK_ORIGIN = datetime.now(UTC)
_COVERAGE_POLICY = RetentionPolicy(
    maximum_age_seconds=3600,
    maximum_bytes=_GIB,
    maximum_objects=1000,
    minimum_free_bytes=64 * 1024 * 1024,
    minimum_free_inodes=128,
)
_COVERAGE_CAPACITY = StorageCapacity(
    total_bytes=4 * _GIB,
    available_bytes=3 * _GIB,
    total_inodes=100_000,
    available_inodes=90_000,
)


def _only_staged_path(store: ContentAddressedStore) -> Path:
    entries = tuple(store.staging_dir.iterdir())
    assert len(entries) == 1
    return entries[0]


def _mkdir_private(path: Path, *, parents: bool = False) -> None:
    existing_ancestor = path.parent
    while not existing_ancestor.exists():
        existing_ancestor = existing_ancestor.parent
    path.mkdir(parents=parents, mode=0o700)
    current = path
    while current != existing_ancestor:
        current.chmod(0o700)
        current = current.parent


def _write_private(path: Path, data: bytes) -> None:
    _ = path.write_bytes(data)
    path.chmod(0o600)


def _changed_storage_stat(
    metadata: os.stat_result,
    *,
    index: int,
    value: int,
) -> os.stat_result:
    fields = list(metadata)
    fields[index] = value
    return os.stat_result(fields)


def _coverage_sample(
    seconds: float,
    *,
    synchronized: bool = True,
) -> RetentionClockSample:
    return RetentionClockSample(
        utc_now=_COVERAGE_CLOCK_ORIGIN + timedelta(seconds=seconds),
        monotonic_now=float(seconds),
        boot_id="storage-coverage-boot",
        synchronized=synchronized,
    )


class _CoverageCapacity:
    def __init__(self, value: StorageCapacity = _COVERAGE_CAPACITY) -> None:
        super().__init__()
        self.value = value

    def __call__(self) -> StorageCapacity:
        return self.value


class _CoverageClock:
    def __init__(self, value: RetentionClockSample) -> None:
        super().__init__()
        self.value = value

    def __call__(self) -> RetentionClockSample:
        return self.value


def _coverage_lifecycle_store(
    tmp_path: Path,
    *,
    policy: RetentionPolicy = _COVERAGE_POLICY,
    capacity: _CoverageCapacity | None = None,
) -> tuple[ContentAddressedStore, _CoverageClock, _CoverageCapacity]:
    selected_capacity = capacity or _CoverageCapacity()
    high_water = ClockHighWater(
        tmp_path / "retention-clock.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    initial = _coverage_sample(0)
    assert high_water.observe(initial).trusted is False
    assert high_water.observe(initial).trusted is True
    clock = _CoverageClock(_coverage_sample(120))
    store = ContentAddressedStore(
        tmp_path / "cache",
        max_bytes=policy.maximum_bytes,
        lifecycle=StoreLifecycleConfiguration(
            policy=policy,
            capacity_sampler=selected_capacity,
            clock_high_water=high_water,
            clock_sampler=clock,
        ),
    )
    return store, clock, selected_capacity


@pytest.mark.parametrize(
    ("device", "inode"),
    [(True, 1), (-1, 1), (1, True), (1, -1)],
)
def test_directory_identity_rejects_non_exact_or_negative_coordinates(
    device: int,
    inode: int,
) -> None:
    with pytest.raises(ValueError, match="non-negative exact integers"):
        _ = storage_module._DirectoryIdentity(device=device, inode=inode)


def test_verified_directory_closes_descriptor_when_metadata_read_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "held"
    directory.mkdir()
    real_fstat = os.fstat
    opened: list[int] = []

    def failing_fstat(descriptor: int) -> os.stat_result:
        opened.append(descriptor)
        msg = "simulated descriptor failure"
        raise OSError(msg)

    monkeypatch.setattr(os, "fstat", failing_fstat)
    with pytest.raises(OSError, match="descriptor failure"):
        _ = storage_module._open_verified_directory(directory)
    monkeypatch.setattr(os, "fstat", real_fstat)

    assert len(opened) == 1
    with pytest.raises(OSError, match="Bad file descriptor"):
        _ = os.fstat(opened[0])


def test_verified_directory_rejects_identity_drift_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "held"
    directory.mkdir()
    real_fstat = os.fstat

    def changed_fstat(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        return _changed_storage_stat(
            metadata,
            index=1,
            value=metadata.st_ino + 1,
        )

    monkeypatch.setattr(os, "fstat", changed_fstat)
    with pytest.raises(ValueError, match="identity changed while opening"):
        _ = storage_module._open_verified_directory(directory)


def test_private_directory_validation_repairs_only_new_directories_and_rechecks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o755)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        storage_module._validate_owned_private_directory(
            descriptor,
            context="new directory",
            created=True,
        )
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == _PRIVATE_DIRECTORY_MODE

        real_fstat = os.fstat

        def wrong_owner(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            return _changed_storage_stat(
                metadata,
                index=4,
                value=os.geteuid() + 1,
            )

        monkeypatch.setattr(os, "fstat", wrong_owner)
        with pytest.raises(ValueError, match="owned by the service process"):
            storage_module._validate_owned_private_directory(
                descriptor,
                context="existing directory",
                created=False,
            )
    finally:
        os.close(descriptor)


def test_private_directory_validation_rejects_failed_mode_postcondition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o755)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    real_fstat = os.fstat

    def unchanged_mode(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        return _changed_storage_stat(metadata, index=0, value=stat.S_IFDIR | 0o755)

    def ignore_mode_change(descriptor: int, mode: int) -> None:
        del descriptor, mode

    monkeypatch.setattr(os, "fstat", unchanged_mode)
    monkeypatch.setattr(os, "fchmod", ignore_mode_change)
    try:
        with pytest.raises(ValueError, match="private ownership and mode"):
            storage_module._validate_owned_private_directory(
                descriptor,
                context="new directory",
                created=True,
            )
    finally:
        os.close(descriptor)


def test_private_regular_file_validation_requires_secure_open_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    artifact = directory / "artifact.bin"
    _write_private(artifact, b"payload")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.delattr(os, "O_NOFOLLOW")
    try:
        with pytest.raises(ValueError, match="secure file-open flags"):
            storage_module._validate_private_regular_file_at(
                artifact.name,
                parent_descriptor=descriptor,
                before=artifact.stat(),
                context="artifact",
            )
    finally:
        os.close(descriptor)


def test_private_regular_file_validation_rejects_open_time_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    artifact = directory / "artifact.bin"
    _write_private(artifact, b"payload")
    parent_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    real_fstat = os.fstat

    def changed_fstat(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            return _changed_storage_stat(
                metadata,
                index=1,
                value=metadata.st_ino + 1,
            )
        return metadata

    monkeypatch.setattr(os, "fstat", changed_fstat)
    try:
        with pytest.raises(ValueError, match="identity or private metadata changed"):
            storage_module._validate_private_regular_file_at(
                artifact.name,
                parent_descriptor=parent_descriptor,
                before=artifact.stat(),
                context="artifact",
            )
    finally:
        os.close(parent_descriptor)


def test_staged_descriptor_rejects_failed_private_file_postcondition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    descriptor = os.open(artifact, os.O_CREAT | os.O_RDWR, 0o600)
    real_fstat = os.fstat

    def multiply_linked(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        return _changed_storage_stat(metadata, index=3, value=2)

    monkeypatch.setattr(os, "fstat", multiply_linked)
    try:
        with pytest.raises(ValueError, match="private file postcondition"):
            storage_module._prepare_private_staged_descriptor(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("defect", ["intermediate-file", "final-directory"])
def test_asset_resolution_treats_non_directories_and_non_files_as_missing(
    tmp_path: Path,
    defect: str,
) -> None:
    store = ContentAddressedStore(tmp_path)
    object_root = store.root / "documents" / "doc_fault"
    if defect == "intermediate-file":
        _write_private(object_root, b"not-a-directory")
        relative_path = "documents/doc_fault/source.bin"
    else:
        _mkdir_private(object_root)
        _mkdir_private(object_root / "source.bin")
        relative_path = "documents/doc_fault/source.bin"

    with pytest.raises(AppError) as raised:
        _ = store.resolve_asset(relative_path)

    assert raised.value.code is ErrorCode.NOT_FOUND


def test_asset_resolution_maps_unsafe_directory_metadata_to_corruption(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    object_root = store.root / "documents" / "doc_fault"
    _mkdir_private(object_root)
    object_root.chmod(0o755)

    with pytest.raises(AppError) as raised:
        _ = store.resolve_asset("documents/doc_fault/source.bin")

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_asset_resolution_maps_descriptor_errors_to_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)

    def failing_stat(
        path: str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        del path, dir_fd, follow_symlinks
        msg = "simulated descriptor-relative read failure"
        raise PermissionError(msg)

    monkeypatch.setattr(os, "stat", failing_stat)
    with pytest.raises(AppError) as raised:
        _ = storage_module._resolve_private_asset(
            store._root_descriptor,
            store.root,
            ("documents", "missing"),
        )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_asset_resolution_transfers_child_ownership_before_parent_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"payload",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    parts = tuple(artifact.relative_path.split("/"))
    real_close = os.close
    real_open_child = storage_module._open_resolved_asset_directory
    opened_children: list[int] = []
    close_calls: list[int] = []

    def tracked_open_child(
        component: str,
        *,
        parent_descriptor: int,
        metadata: os.stat_result,
    ) -> int:
        child = real_open_child(
            component,
            parent_descriptor=parent_descriptor,
            metadata=metadata,
        )
        opened_children.append(child)
        return child

    def fail_first_close_after_release(descriptor: int) -> None:
        close_calls.append(descriptor)
        real_close(descriptor)
        if len(close_calls) == 1:
            msg = "simulated parent close failure after descriptor release"
            raise OSError(msg)

    with monkeypatch.context() as patch:
        patch.setattr(
            storage_module,
            "_open_resolved_asset_directory",
            tracked_open_child,
        )
        patch.setattr(os, "close", fail_first_close_after_release)
        with pytest.raises(AppError) as raised:
            _ = storage_module._resolve_private_asset(
                store._root_descriptor,
                store.root,
                parts,
            )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert raised.value.message == "Artifact storage is corrupted."
    assert raised.value.http_status == HTTPStatus.INTERNAL_SERVER_ERROR
    assert raised.value.safe_details is None
    assert len(opened_children) == 1
    child_descriptor = opened_children[0]
    child_was_open = False
    try:
        _ = os.fstat(child_descriptor)
    except OSError:
        child_was_open = False
    else:
        child_was_open = True
    finally:
        if child_was_open:
            real_close(child_descriptor)
    parent_descriptor = close_calls[0]
    assert (
        close_calls.count(parent_descriptor),
        close_calls.count(child_descriptor),
        child_was_open,
    ) == (1, 1, False)


def test_artifact_tree_validation_enforces_depth_and_entry_bounds(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="depth bound"):
            storage_module._validate_artifact_directory(
                descriptor,
                depth=storage_module._MAX_ARTIFACT_TREE_DEPTH + 1,
                entry_count=[0],
            )
        _write_private(directory / "artifact.bin", b"payload")
        with pytest.raises(ValueError, match="entry bound"):
            storage_module._validate_artifact_directory(
                descriptor,
                depth=0,
                entry_count=[storage_module._MAX_ARTIFACT_TREE_ENTRIES],
            )
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    "name",
    ["", ".", "..", "non-ascii-é", "control-\x1f", "delete-\x7f"],
)
def test_staging_recovery_rejects_unsafe_entry_names(name: str) -> None:
    with pytest.raises(ValueError, match="entry name is unsafe"):
        storage_module._validate_staging_entry_name(name)


def test_verified_regular_file_requires_secure_metadata_open_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    artifact = directory / "artifact.bin"
    _write_private(artifact, b"payload")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.delattr(os, "O_PATH")
    try:
        with pytest.raises(ValueError, match="secure metadata open flags"):
            _ = storage_module._open_verified_regular_file(
                artifact.name,
                directory_fd=descriptor,
            )
    finally:
        os.close(descriptor)


def test_verified_regular_file_rejects_identity_drift_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    artifact = directory / "artifact.bin"
    _write_private(artifact, b"payload")
    parent_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    real_fstat = os.fstat

    def changed_fstat(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            return _changed_storage_stat(
                metadata,
                index=1,
                value=metadata.st_ino + 1,
            )
        return metadata

    monkeypatch.setattr(os, "fstat", changed_fstat)
    try:
        with pytest.raises(ValueError, match="identity changed while opening"):
            _ = storage_module._open_verified_regular_file(
                artifact.name,
                directory_fd=parent_descriptor,
            )
    finally:
        os.close(parent_descriptor)


def test_staging_inventory_rejects_cross_filesystem_identity(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    _write_private(directory / "artifact.bin", b"payload")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="filesystem boundary"):
            _ = storage_module._inventory_orphan_staging(
                descriptor,
                depth=0,
                budget=storage_module._StagingRecoveryBudget(
                    root_device=os.fstat(descriptor).st_dev + 1,
                    maximum_bytes=100,
                ),
            )
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("entry_kind", ["file", "directory"])
def test_staging_inventory_rejects_open_time_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_kind: str,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    entry = directory / "entry"
    if entry_kind == "file":
        _write_private(entry, b"payload")
        real_open = storage_module._open_verified_regular_file

        def changed_file_open(
            path: str,
            *,
            directory_fd: int,
        ) -> tuple[int, storage_module._DirectoryIdentity]:
            descriptor, identity = real_open(path, directory_fd=directory_fd)
            return descriptor, storage_module._DirectoryIdentity(
                device=identity.device,
                inode=identity.inode + 1,
            )

        monkeypatch.setattr(
            storage_module,
            "_open_verified_regular_file",
            changed_file_open,
        )
    else:
        entry.mkdir(mode=0o700)
        real_open_directory = storage_module._open_verified_directory

        def changed_directory_open(
            path: Path | str,
            *,
            directory_fd: int | None = None,
        ) -> tuple[int, storage_module._DirectoryIdentity]:
            descriptor, identity = real_open_directory(
                path,
                directory_fd=directory_fd,
            )
            return descriptor, storage_module._DirectoryIdentity(
                device=identity.device,
                inode=identity.inode + 1,
            )

        monkeypatch.setattr(
            storage_module,
            "_open_verified_directory",
            changed_directory_open,
        )

    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="identity changed"):
            _ = storage_module._inventory_orphan_staging(
                descriptor,
                depth=0,
                budget=storage_module._StagingRecoveryBudget(
                    root_device=os.fstat(descriptor).st_dev,
                    maximum_bytes=100,
                ),
            )
    finally:
        os.close(descriptor)


def test_cleanup_helpers_remove_unsafe_page_and_tiles_nodes(tmp_path: Path) -> None:
    render = tmp_path / "render"
    render.mkdir()
    page = render / "unsafe-page"
    _write_private(page, b"not-a-directory")
    storage_module._cleanup_tile_page(page)
    assert not page.exists()

    tiles = render / "tiles"
    _write_private(tiles, b"not-a-directory")
    storage_module._cleanup_render_tiles(render)
    assert not tiles.exists()


def _staging_inventory(
    directory: Path,
) -> tuple[int, tuple[storage_module._OrphanStagingEntry, ...]]:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    entries = storage_module._inventory_orphan_staging(
        descriptor,
        depth=0,
        budget=storage_module._StagingRecoveryBudget(
            root_device=os.fstat(descriptor).st_dev,
            maximum_bytes=1024,
        ),
    )
    return descriptor, entries


def test_staging_deletion_rejects_identity_replacement_before_open(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    artifact = directory / "artifact.bin"
    _write_private(artifact, b"original")
    descriptor, entries = _staging_inventory(directory)
    artifact.unlink()
    artifact.mkdir(mode=0o700)
    try:
        with pytest.raises(ValueError, match="identity changed before deletion"):
            storage_module._delete_orphan_staging_inventory(descriptor, entries)
    finally:
        os.close(descriptor)


def test_staging_deletion_rejects_file_identity_drift_before_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    _write_private(directory / "artifact.bin", b"payload")
    descriptor, entries = _staging_inventory(directory)
    real_open = storage_module._open_verified_regular_file

    def changed_open(
        path: str,
        *,
        directory_fd: int,
    ) -> tuple[int, storage_module._DirectoryIdentity]:
        opened, identity = real_open(path, directory_fd=directory_fd)
        return opened, storage_module._DirectoryIdentity(
            device=identity.device,
            inode=identity.inode + 1,
        )

    monkeypatch.setattr(storage_module, "_open_verified_regular_file", changed_open)
    try:
        with pytest.raises(ValueError, match="identity changed before unlink"):
            storage_module._delete_orphan_staging_inventory(descriptor, entries)
    finally:
        os.close(descriptor)


def test_staging_deletion_requires_unlinked_descriptor_postcondition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    artifact = directory / "artifact.bin"
    _write_private(artifact, b"payload")
    descriptor, entries = _staging_inventory(directory)
    real_unlink = os.unlink

    def ineffective_unlink(
        path: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if path != artifact.name or dir_fd != descriptor:
            real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", ineffective_unlink)
    try:
        with pytest.raises(ValueError, match="path changed during unlink"):
            storage_module._delete_orphan_staging_inventory(descriptor, entries)
    finally:
        os.close(descriptor)


def test_staging_deletion_rejects_directory_identity_drift_before_recursion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    (directory / "child").mkdir(mode=0o700)
    descriptor, entries = _staging_inventory(directory)
    real_open = storage_module._open_verified_directory

    def changed_open(
        path: Path | str,
        *,
        directory_fd: int | None = None,
    ) -> tuple[int, storage_module._DirectoryIdentity]:
        opened, identity = real_open(path, directory_fd=directory_fd)
        return opened, storage_module._DirectoryIdentity(
            device=identity.device,
            inode=identity.inode + 1,
        )

    monkeypatch.setattr(storage_module, "_open_verified_directory", changed_open)
    try:
        with pytest.raises(ValueError, match="identity changed before deletion"):
            storage_module._delete_orphan_staging_inventory(descriptor, entries)
    finally:
        os.close(descriptor)


def test_staging_deletion_rejects_directory_entries_created_during_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    (directory / "child").mkdir(mode=0o700)
    descriptor, entries = _staging_inventory(directory)
    real_scandir = os.scandir

    def injecting_scandir(descriptor: int) -> object:
        raced = Path(f"/proc/self/fd/{descriptor}") / "raced.bin"
        _write_private(raced, b"raced")
        return real_scandir(descriptor)

    monkeypatch.setattr(os, "scandir", injecting_scandir)
    try:
        with pytest.raises(ValueError, match="changed during deletion"):
            storage_module._delete_orphan_staging_inventory(descriptor, entries)
    finally:
        os.close(descriptor)


def test_staging_deletion_rechecks_directory_identity_before_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    (directory / "child").mkdir(mode=0o700)
    descriptor, entries = _staging_inventory(directory)
    real_stat = os.stat
    relative_reads = 0

    def changed_third_stat(
        path: str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal relative_reads
        metadata = real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )
        if path == "child" and dir_fd == descriptor:
            relative_reads += 1
            if relative_reads == _FINAL_DIRECTORY_IDENTITY_READ:
                return _changed_storage_stat(
                    metadata,
                    index=1,
                    value=metadata.st_ino + 1,
                )
        return metadata

    monkeypatch.setattr(os, "stat", changed_third_stat)
    try:
        with pytest.raises(ValueError, match="identity changed before removal"):
            storage_module._delete_orphan_staging_inventory(descriptor, entries)
    finally:
        os.close(descriptor)


def test_cleanup_tile_page_preserves_complete_geometry_inventory(
    tmp_path: Path,
) -> None:
    page = tmp_path / "page"
    page.mkdir()
    for name in ("geometry-a", "geometry-b"):
        geometry = page / name
        geometry.mkdir()
        _ = (geometry / "manifest.json").write_text("{}", encoding="utf-8")

    storage_module._cleanup_tile_page(page)

    assert sorted(path.name for path in page.iterdir()) == [
        "geometry-a",
        "geometry-b",
    ]


def test_private_directory_path_cleanup_handles_preopen_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private"

    def failing_open(
        path: Path | str,
        *,
        directory_fd: int | None = None,
    ) -> tuple[int, storage_module._DirectoryIdentity]:
        del path, directory_fd
        msg = "simulated directory open failure"
        raise OSError(msg)

    monkeypatch.setattr(storage_module, "_open_verified_directory", failing_open)
    with pytest.raises(ValueError, match="directory is unsafe"):
        storage_module._ensure_private_directory_path(directory, context="artifact")


def test_asset_resolution_cleanup_handles_root_duplication_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)

    def failing_dup(descriptor: int) -> int:
        del descriptor
        msg = "simulated root descriptor duplication failure"
        raise OSError(msg)

    monkeypatch.setattr(os, "dup", failing_dup)
    with pytest.raises(AppError) as raised:
        _ = storage_module._resolve_private_asset(
            store._root_descriptor,
            store.root,
            ("documents", "missing"),
        )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_staged_writer_scan_revalidates_root_and_rejects_closed_reuse(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    writer = store.stage()
    _ = writer.write(b"payload")

    staged_path, digest = writer.prepare_for_scan()

    assert staged_path == _only_staged_path(store)
    assert digest == sha256(b"payload").hexdigest()
    writer.__exit__(None, None, None)
    with pytest.raises(RuntimeError, match="not open"):
        _ = writer.prepare_for_scan()
    with pytest.raises(RuntimeError, match="not open"):
        _ = writer.replace_render(
            "renders/rnd_0123456789abcdef/manifest.json",
            expected_sha256="0" * 64,
        )


def test_render_transaction_root_failure_releases_lease_and_lock(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    store = ContentAddressedStore(root)
    render_id = "rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    transaction = store.begin_render_transaction(
        f"renders/{render_id}",
        completion_file="manifest.json",
    )
    held = tmp_path / "held"
    _ = root.rename(held)
    root.mkdir(mode=0o700)
    for namespace in (".staging", "documents", "renders"):
        (root / namespace).mkdir(mode=0o700)

    with pytest.raises(AppError, match="storage root"):
        transaction.commit()

    assert store._asset_leases == {}


@pytest.mark.parametrize(
    "invalid_authority",
    ["capacity_sampler", "clock_sampler", "alert_observer"],
)
def test_lifecycle_configuration_rejects_non_callable_authorities(
    invalid_authority: str,
) -> None:
    def ignore_alert(alert: object) -> None:
        del alert

    configuration = object.__new__(storage_module.StoreLifecycleConfiguration)
    object.__setattr__(configuration, "capacity_sampler", None)
    object.__setattr__(configuration, "clock_sampler", lambda: None)
    object.__setattr__(configuration, "alert_observer", ignore_alert)
    object.__setattr__(configuration, invalid_authority, 1)

    with pytest.raises(TypeError, match=invalid_authority):
        configuration.__post_init__()


def test_asset_lease_rejects_reentry_and_inactive_exit(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"payload",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    lease = store.lease_asset(artifact.relative_path)
    lease.__exit__(None, None, None)

    with lease as path:
        assert path == artifact.absolute_path
        with pytest.raises(RuntimeError, match="already active"):
            _ = lease.__enter__()


def test_store_creation_handles_a_previously_absent_parent_chain(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "absent" / "cache")

    assert store.root.is_dir()


def test_object_inventory_rejects_non_directory_namespace_children(
    tmp_path: Path,
) -> None:
    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path)
    _write_private(store.root / "documents" / "invalid.bin", b"payload")

    with pytest.raises(AppError) as raised:
        _ = store._object_roots()

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_stale_staging_cleanup_rejects_cross_device_descriptor_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    real_open = storage_module._open_verified_directory

    def changed_open(
        path: Path | str,
        *,
        directory_fd: int | None = None,
    ) -> tuple[int, storage_module._DirectoryIdentity]:
        descriptor, identity = real_open(path, directory_fd=directory_fd)
        if path == ".staging":
            return descriptor, storage_module._DirectoryIdentity(
                device=identity.device + 1,
                inode=identity.inode,
            )
        return descriptor, identity

    monkeypatch.setattr(storage_module, "_open_verified_directory", changed_open)
    with pytest.raises(ValueError, match="filesystem boundary"):
        store._cleanup_stale_staging(maximum_bytes=store.max_bytes)


def test_stale_staging_cleanup_requires_an_empty_post_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    _write_private(store.staging_dir / "orphan.bin", b"payload")

    def skip_deletion(
        descriptor: int,
        entries: tuple[storage_module._OrphanStagingEntry, ...],
    ) -> None:
        del descriptor, entries

    monkeypatch.setattr(
        storage_module,
        "_delete_orphan_staging_inventory",
        skip_deletion,
    )
    with pytest.raises(ValueError, match="empty post-state"):
        store._cleanup_stale_staging(maximum_bytes=store.max_bytes)


def test_stale_staging_cleanup_maps_operating_system_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)

    def failing_fsync(descriptor: int) -> None:
        del descriptor
        msg = "simulated staging durability failure"
        raise OSError(msg)

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(ValueError, match="unsafe filesystem state"):
        store._cleanup_stale_staging(maximum_bytes=store.max_bytes)


def test_incomplete_render_cleanup_ignores_unknown_ids_and_removes_non_directories(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    unknown = store.root / "renders" / "not-a-render"
    unknown.mkdir(mode=0o700)
    invalid_render = store.root / "renders" / "rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    _write_private(invalid_render, b"not-a-directory")

    store._cleanup_incomplete_renders()

    assert unknown.is_dir()
    assert not invalid_render.exists()


def test_store_root_verification_rejects_current_path_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    real_open = storage_module._open_verified_directory

    def changed_open(
        path: Path | str,
        *,
        directory_fd: int | None = None,
    ) -> tuple[int, storage_module._DirectoryIdentity]:
        descriptor, identity = real_open(path, directory_fd=directory_fd)
        if Path(path) == store.root:
            return descriptor, storage_module._DirectoryIdentity(
                device=identity.device,
                inode=identity.inode + 1,
            )
        return descriptor, identity

    monkeypatch.setattr(storage_module, "_open_verified_directory", changed_open)
    with pytest.raises(AppError, match="storage root"):
        store._verify_store_root_identity()


@pytest.mark.parametrize("value", [False, 0, 1001])
def test_publication_maximum_requires_a_positive_bounded_exact_integer(
    value: int,
) -> None:
    with pytest.raises(ValueError, match="positive exact integer"):
        _ = ContentAddressedStore._validate_publication_maximum(
            value,
            name="maximum_new_objects",
            maximum=1000,
        )


def test_lifecycle_policy_requires_exact_configuration_and_clock_authorities(
    tmp_path: Path,
) -> None:
    plain_store = ContentAddressedStore(tmp_path / "plain")
    assert plain_store.lifecycle_configured is False
    with pytest.raises(ValueError, match="configured retention policy"):
        plain_store._require_lifecycle_policy(_COVERAGE_POLICY)

    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path / "strict")
    store._clock_sampler = None
    with pytest.raises(ValueError, match="clock authority"):
        store._require_lifecycle_policy(_COVERAGE_POLICY)


def test_admission_closure_preserves_the_first_effective_blocker(
    tmp_path: Path,
) -> None:
    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path)
    first = store._close_admission(
        PublicationBlocker.BYTE_BUDGET,
        alert=LifecycleAlert(
            event=LifecycleAlertEvent.ADMISSION_CLOSED,
            blockers=(LifecycleBlocker.BYTE_BUDGET,),
        ),
    )
    second = store._close_admission(
        PublicationBlocker.INODE_HEADROOM,
        alert=LifecycleAlert(
            event=LifecycleAlertEvent.ADMISSION_CLOSED,
            blockers=(LifecycleBlocker.INODE_HEADROOM,),
        ),
    )

    assert first is PublicationBlocker.BYTE_BUDGET
    assert second is first


def test_tree_stats_counts_nested_directories_and_rejects_unsafe_nodes(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    root = store.root / "renders" / "rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    nested = root / "nested"
    _mkdir_private(nested, parents=True)
    _write_private(nested / "asset.bin", b"payload")

    size, inodes, _modified_ns = store._tree_stats(root)

    assert size == len(b"payload")
    assert inodes == _NESTED_TREE_INODES

    unsafe_root = store.root / "renders" / "rnd_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    _write_private(unsafe_root, b"not-a-directory")
    with pytest.raises(AppError) as raised_root:
        _ = store._tree_stats(unsafe_root)
    assert raised_root.value.code is ErrorCode.INTERNAL_ERROR

    outside = tmp_path / "outside"
    outside.mkdir()
    linked_directory = nested / "linked"
    linked_directory.symlink_to(outside, target_is_directory=True)
    with pytest.raises(AppError) as raised_directory:
        _ = store._tree_stats(root)
    assert raised_directory.value.code is ErrorCode.INTERNAL_ERROR
    linked_directory.unlink()

    linked_file = nested / "linked.bin"
    linked_file.symlink_to(outside / "missing")
    with pytest.raises(AppError) as raised_file:
        _ = store._tree_stats(root)
    assert raised_file.value.code is ErrorCode.INTERNAL_ERROR


def test_stored_object_inventory_requires_order_and_enforces_safety_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plain_store = ContentAddressedStore(tmp_path / "plain")
    with pytest.raises(RuntimeError, match="insertion order"):
        _ = plain_store._stored_objects()

    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path / "strict")
    artifact = store.put_bytes(
        b"payload",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    monkeypatch.setattr(storage_module, "_MAX_LIFECYCLE_OBJECTS", 0)
    with pytest.raises(AppError, match="inventory exceeds"):
        _ = store._stored_objects()
    assert artifact.absolute_path.is_file()


@pytest.mark.asyncio
async def test_publication_reservation_state_machine_rejects_invalid_reuse(
    tmp_path: Path,
) -> None:
    store, clock, _capacity = _coverage_lifecycle_store(tmp_path)
    inactive_context = store.reserve_publication(
        _COVERAGE_POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )
    inactive = inactive_context._reservation
    with pytest.raises(RuntimeError, match="not active"):
        inactive.close()
    with pytest.raises(RuntimeError, match="not active"):
        await inactive.commit(actual_bytes=0, actual_objects=0, actual_inodes=0)

    active_context = store.reserve_publication(
        _COVERAGE_POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )
    active = await active_context.__aenter__()
    with pytest.raises(RuntimeError, match="entered twice"):
        active.activate(
            baseline_used_bytes=0,
            baseline_stored_objects=0,
            baseline_available_inodes=1,
        )
    with pytest.raises(RuntimeError, match="entered twice"):
        active.begin()
    await active.abort()
    with pytest.raises(RuntimeError, match="already closed"):
        await active.commit(actual_bytes=0, actual_objects=0, actual_inodes=0)
    with pytest.raises(RuntimeError, match="not active"):
        store.abort_publication_reservation(active)


def test_publication_begin_requires_clock_authority_after_request_creation(
    tmp_path: Path,
) -> None:
    store, clock, _capacity = _coverage_lifecycle_store(tmp_path)
    context = store.reserve_publication(
        _COVERAGE_POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )
    store._clock_high_water = None

    with pytest.raises(RuntimeError, match="clock authority"):
        context._reservation.begin()


def test_publication_begin_rejects_capacity_authority_rebinding_during_sample(
    tmp_path: Path,
) -> None:
    store, clock, _capacity = _coverage_lifecycle_store(tmp_path)
    replacement = _CoverageCapacity()

    def drifting_capacity() -> StorageCapacity:
        store._capacity_sampler_override = replacement
        return _COVERAGE_CAPACITY

    store._capacity_sampler_override = drifting_capacity
    context = store.reserve_publication(
        _COVERAGE_POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )

    with pytest.raises(RuntimeError, match="capacity authority changed"):
        context._reservation.begin()


@pytest.mark.parametrize("blocker", ["object", "inode"])
def test_publication_begin_reports_object_and_inode_reservation_pressure(
    tmp_path: Path,
    blocker: str,
) -> None:
    policy = RetentionPolicy(
        maximum_age_seconds=_COVERAGE_POLICY.maximum_age_seconds,
        maximum_bytes=_COVERAGE_POLICY.maximum_bytes,
        maximum_objects=1 if blocker == "object" else 1000,
        minimum_free_bytes=_COVERAGE_POLICY.minimum_free_bytes,
        minimum_free_inodes=_COVERAGE_POLICY.minimum_free_inodes,
    )
    capacity = _CoverageCapacity()
    if blocker == "inode":
        capacity.value = StorageCapacity(
            total_bytes=_COVERAGE_CAPACITY.total_bytes,
            available_bytes=_COVERAGE_CAPACITY.available_bytes,
            total_inodes=1000,
            available_inodes=policy.minimum_free_inodes,
        )
    store, clock, _capacity = _coverage_lifecycle_store(
        tmp_path,
        policy=policy,
        capacity=capacity,
    )
    if blocker == "object":
        _ = store.put_bytes(
            b"existing",
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )
    context = store.reserve_publication(
        policy,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )

    with pytest.raises(PublicationReservationError) as raised:
        context._reservation.begin()

    expected = (
        PublicationBlocker.OBJECT_BUDGET
        if blocker == "object"
        else PublicationBlocker.INODE_HEADROOM
    )
    assert raised.value.blocker is expected


@pytest.mark.parametrize("value", [False, -1, 2])
def test_actual_publication_requires_a_bounded_exact_integer(value: int) -> None:
    with pytest.raises(ValueError, match="within its reservation"):
        _ = ContentAddressedStore._validate_actual_publication(
            value,
            name="actual_objects",
            reserved=1,
        )


@pytest.mark.asyncio
async def test_publication_commit_rechecks_clock_authority_and_trust(
    tmp_path: Path,
) -> None:
    missing_store, missing_clock, _capacity = _coverage_lifecycle_store(
        tmp_path / "missing"
    )
    missing_context = missing_store.reserve_publication(
        _COVERAGE_POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=missing_clock(),
    )
    missing = await missing_context.__aenter__()
    saved_sampler = missing_store._clock_sampler
    missing_store._clock_sampler = None
    with pytest.raises(RuntimeError, match="clock authority"):
        await missing.commit(actual_bytes=0, actual_objects=0, actual_inodes=0)
    missing_store._clock_sampler = saved_sampler
    await missing.abort()

    anomalous_store, anomalous_clock, _capacity = _coverage_lifecycle_store(
        tmp_path / "anomalous"
    )
    anomalous_context = anomalous_store.reserve_publication(
        _COVERAGE_POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=anomalous_clock(),
    )
    anomalous = await anomalous_context.__aenter__()
    anomalous_clock.value = _coverage_sample(121, synchronized=False)
    with pytest.raises(PublicationReservationError) as raised:
        await anomalous.commit(actual_bytes=0, actual_objects=0, actual_inodes=0)
    assert raised.value.blocker is PublicationBlocker.CLOCK_ANOMALY
    await anomalous.abort()


@pytest.mark.asyncio
@pytest.mark.parametrize("authority", ["clock", "capacity"])
async def test_publication_commit_rejects_authority_rebinding_during_sample(
    tmp_path: Path,
    authority: str,
) -> None:
    store, clock, _capacity = _coverage_lifecycle_store(tmp_path)
    context = store.reserve_publication(
        _COVERAGE_POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )
    reservation = await context.__aenter__()
    if authority == "clock":
        replacement_clock = _CoverageClock(clock())

        def drifting_clock() -> RetentionClockSample:
            store._clock_sampler = replacement_clock
            return clock()

        store._clock_sampler = drifting_clock
    else:
        replacement_capacity = _CoverageCapacity()

        def drifting_capacity() -> StorageCapacity:
            store._capacity_sampler_override = replacement_capacity
            return _COVERAGE_CAPACITY

        store._capacity_sampler_override = drifting_capacity

    with pytest.raises(RuntimeError, match="lifecycle authority changed"):
        await reservation.commit(
            actual_bytes=0,
            actual_objects=0,
            actual_inodes=0,
        )

    await reservation.abort()


@pytest.mark.parametrize("state", ["inactive", "missing-clock"])
def test_locked_publication_commit_rejects_invalid_internal_state(
    tmp_path: Path,
    state: str,
) -> None:
    store, clock, _capacity = _coverage_lifecycle_store(tmp_path)
    context = store.reserve_publication(
        _COVERAGE_POLICY,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )
    reservation = context._reservation
    expected = "not active"
    saved_clock_authority = store._clock_high_water
    if state == "missing-clock":
        reservation.begin()
        store._clock_high_water = None
        expected = "clock authority"
    commit = storage_module._PublicationCommit(
        actual_bytes=0,
        actual_objects=0,
        actual_inodes=0,
        clock_sample=clock(),
        capacity=_COVERAGE_CAPACITY,
    )

    try:
        with store._lock, pytest.raises(RuntimeError, match=expected):
            store._commit_publication_reservation_locked(
                reservation,
                commit=commit,
                pending_alerts=[],
            )
    finally:
        store._clock_high_water = saved_clock_authority
        if reservation.active:
            store.abort_publication_reservation(reservation)


@pytest.mark.asyncio
@pytest.mark.parametrize("pressure", ["byte", "object", "inode"])
async def test_publication_commit_rechecks_each_resource_dimension(
    tmp_path: Path,
    pressure: str,
) -> None:
    policy = RetentionPolicy(
        maximum_age_seconds=_COVERAGE_POLICY.maximum_age_seconds,
        maximum_bytes=10 if pressure == "byte" else _COVERAGE_POLICY.maximum_bytes,
        maximum_objects=1 if pressure == "object" else 1000,
        minimum_free_bytes=_COVERAGE_POLICY.minimum_free_bytes,
        minimum_free_inodes=_COVERAGE_POLICY.minimum_free_inodes,
    )
    capacity = _CoverageCapacity()
    store, clock, _capacity = _coverage_lifecycle_store(
        tmp_path,
        policy=policy,
        capacity=capacity,
    )
    context = store.reserve_publication(
        policy,
        maximum_new_bytes=1,
        maximum_new_objects=1,
        maximum_new_inodes=1,
        clock=clock(),
    )
    reservation = await context.__aenter__()
    if pressure == "byte":
        store._used_bytes = policy.maximum_bytes + 1
    elif pressure == "object":
        for payload in (b"first", b"second"):
            _ = store.put_bytes(
                payload,
                namespace="documents",
                filename="source.bin",
                media_type="application/octet-stream",
            )
    else:
        capacity.value = StorageCapacity(
            total_bytes=_COVERAGE_CAPACITY.total_bytes,
            available_bytes=_COVERAGE_CAPACITY.available_bytes,
            total_inodes=1000,
            available_inodes=policy.minimum_free_inodes - 1,
        )

    with pytest.raises(PublicationReservationError) as raised:
        await reservation.commit(actual_bytes=0, actual_objects=0, actual_inodes=0)

    expected = {
        "byte": PublicationBlocker.BYTE_BUDGET,
        "object": PublicationBlocker.OBJECT_BUDGET,
        "inode": PublicationBlocker.INODE_HEADROOM,
    }[pressure]
    assert raised.value.blocker is expected
    await reservation.abort()


def test_asset_object_key_and_release_accounting_reject_invalid_sequences(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    with pytest.raises(AppError) as raised:
        _ = store._asset_object_key("documents")
    assert raised.value.code is ErrorCode.INVALID_INPUT

    artifact = store.put_bytes(
        b"payload",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    first_key, _ = store.acquire_asset_lease(artifact.relative_path)
    second_key, _ = store.acquire_asset_lease(artifact.relative_path)
    assert first_key == second_key
    store.release_asset_lease(first_key)
    assert store._asset_leases == {first_key: 1}
    store.release_asset_lease(first_key)
    with pytest.raises(RuntimeError, match="unbalanced"):
        store.release_asset_lease(first_key)


@pytest.mark.parametrize("authority", ["short-path", "missing-token"])
def test_locked_render_deletion_requires_exact_transaction_authority(
    tmp_path: Path,
    authority: str,
) -> None:
    store = ContentAddressedStore(tmp_path)
    path = store.root / "renders"
    transaction_token: object | None = None
    expected = "authority is invalid"
    if authority == "missing-token":
        path /= "rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        transaction_token = object()
        expected = "authority is unavailable"

    with pytest.raises(RuntimeError, match=expected):
        _ = store._delete_render_subtree_locked(
            path,
            transaction_token=transaction_token,
        )


@pytest.mark.parametrize(
    ("blockers", "expected"),
    [
        ((PruneBlocker.INODE_HEADROOM,), PublicationBlocker.INODE_HEADROOM),
        ((PruneBlocker.BYTE_HEADROOM,), PublicationBlocker.BYTE_HEADROOM),
    ],
)
def test_unsatisfied_prune_maps_resource_blockers_to_admission(
    tmp_path: Path,
    blockers: tuple[PruneBlocker, ...],
    expected: PublicationBlocker,
) -> None:
    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path)

    store._record_unsatisfied_prune(blockers)

    assert store._admission_closed_blocker is expected


def test_prune_defensively_requires_bound_clock_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, clock, _capacity = _coverage_lifecycle_store(tmp_path)

    def skip_policy_check(policy: RetentionPolicy) -> None:
        del policy

    monkeypatch.setattr(store, "_require_lifecycle_policy", skip_policy_check)
    store._clock_high_water = None
    with pytest.raises(RuntimeError, match="clock authority"):
        _ = store.prune(_COVERAGE_POLICY, clock=clock())


def test_prune_rejects_capacity_authority_rebinding_during_sample(
    tmp_path: Path,
) -> None:
    store, clock, _capacity = _coverage_lifecycle_store(tmp_path)
    replacement = _CoverageCapacity()

    def drifting_capacity() -> StorageCapacity:
        store._capacity_sampler_override = replacement
        return _COVERAGE_CAPACITY

    store._capacity_sampler_override = drifting_capacity

    with pytest.raises(RuntimeError, match="capacity authority changed"):
        _ = store.prune(_COVERAGE_POLICY, clock=clock())


def test_prune_rejects_capacity_authority_rebinding_after_post_prune_sample(
    tmp_path: Path,
) -> None:
    store, clock, _capacity = _coverage_lifecycle_store(tmp_path)
    replacement = _CoverageCapacity()
    sample_count = 0

    def drifting_capacity() -> StorageCapacity:
        nonlocal sample_count
        sample_count += 1
        if sample_count == _POST_PRUNE_CAPACITY_SAMPLE_COUNT:
            store._capacity_sampler_override = replacement
        return _COVERAGE_CAPACITY

    store._capacity_sampler_override = drifting_capacity

    with pytest.raises(RuntimeError, match="capacity authority changed"):
        _ = store.prune(_COVERAGE_POLICY, clock=clock())

    assert sample_count == _POST_PRUNE_CAPACITY_SAMPLE_COUNT


@pytest.mark.parametrize("pressure", ["leased", "budget", "inode"])
def test_prune_reports_each_unsatisfied_resource_dimension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pressure: str,
) -> None:
    broad_policy = RetentionPolicy(
        maximum_age_seconds=_COVERAGE_POLICY.maximum_age_seconds,
        maximum_bytes=100,
        maximum_objects=1000,
        minimum_free_bytes=_COVERAGE_POLICY.minimum_free_bytes,
        minimum_free_inodes=_COVERAGE_POLICY.minimum_free_inodes,
    )
    capacity = _CoverageCapacity()
    store, clock, _capacity = _coverage_lifecycle_store(
        tmp_path,
        policy=broad_policy,
        capacity=capacity,
    )
    artifact = store.put_bytes(
        b"payload",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    narrow_policy = RetentionPolicy(
        maximum_age_seconds=broad_policy.maximum_age_seconds,
        maximum_bytes=1 if pressure != "inode" else broad_policy.maximum_bytes,
        maximum_objects=broad_policy.maximum_objects,
        minimum_free_bytes=broad_policy.minimum_free_bytes,
        minimum_free_inodes=broad_policy.minimum_free_inodes,
    )
    store._retention_policy = narrow_policy
    if pressure == "leased":
        lease = store.lease_asset(artifact.relative_path)
        with lease:
            report = store.prune(narrow_policy, clock=clock())
    else:
        if pressure == "budget":

            def skip_prune(state: storage_module._PruneWorkingSet) -> tuple[int, int]:
                del state
                return 0, 0

            monkeypatch.setattr(store, "_prune_unleased", skip_prune)
        else:
            capacity.value = StorageCapacity(
                total_bytes=_COVERAGE_CAPACITY.total_bytes,
                available_bytes=_COVERAGE_CAPACITY.available_bytes,
                total_inodes=1000,
                available_inodes=narrow_policy.minimum_free_inodes - 1,
            )
        report = store.prune(narrow_policy, clock=clock())

    assert report.status == "unsatisfied"
    if pressure == "leased":
        assert PruneBlocker.LEASED_OBJECTS in report.blockers
    elif pressure == "budget":
        assert PruneBlocker.BYTE_HEADROOM in report.blockers
    else:
        assert PruneBlocker.INODE_HEADROOM in report.blockers


def test_reconcile_and_staging_reservations_reject_unavailable_or_unbalanced_state(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    with pytest.raises(ValueError, match="lifecycle is unavailable"):
        _ = store.reconcile_lifecycle()
    with pytest.raises(ValueError, match="must not be negative"):
        store._reserve_staging_bytes(store.staging_dir / "missing", -1)
    with pytest.raises(AppError) as unmanaged:
        store._reserve_staging_bytes(store.staging_dir / "missing", 1)
    assert unmanaged.value.code is ErrorCode.INVALID_INPUT
    with pytest.raises(RuntimeError, match="unbalanced"):
        store._release_staging_bytes(store.staging_dir / "missing", 1)


def test_reconcile_lifecycle_uses_configured_authorities(tmp_path: Path) -> None:
    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path)

    report = store.reconcile_lifecycle()

    assert report.status == "satisfied"
    assert report.freed_bytes == 0
    assert report.freed_objects == 0


def test_filename_validation_retains_a_defensive_normalization_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NormalizedPath:
        def __init__(self, value: str) -> None:
            super().__init__()
            self.name = f"normalized-{value}"

    monkeypatch.setattr(storage_module, "PurePosixPath", _NormalizedPath)
    with pytest.raises(AppError) as raised:
        _ = ContentAddressedStore._validate_filename("source.bin")
    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_render_object_deletion_updates_persistent_insertion_order(
    tmp_path: Path,
) -> None:
    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path)
    render_id = "rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    relative_path = f"renders/{render_id}/manifest.json"
    _ = store.put_render_bytes(relative_path, b"payload")

    assert store.delete_render_subtree(f"renders/{render_id}") is True
    assert store._insertion_order is not None
    with pytest.raises(ValueError, match="no initialized insertion sequence"):
        _ = store._insertion_order.sequence_for(f"renders/{render_id}")


def test_render_transaction_constructor_failure_releases_acquired_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    render_id = "rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def failing_transaction(
        subtree: Path,
        completion: Path,
        binding: storage_module._RenderTransactionBinding,
        transaction_token: object,
        *,
        complete: bool,
    ) -> Never:
        del subtree, completion, binding, transaction_token, complete
        msg = "simulated transaction construction failure"
        raise RuntimeError(msg)

    monkeypatch.setattr(storage_module, "_RenderTransaction", failing_transaction)
    with pytest.raises(RuntimeError, match="construction failure"):
        _ = store.begin_render_transaction(
            f"renders/{render_id}",
            completion_file="manifest.json",
        )
    assert store._asset_leases == {}
    assert store._render_transaction_leases == {}


def test_stage_constructor_failure_cleans_path_and_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)

    def failing_writer(
        operations: storage_module._StagedOperations,
        path: Path,
        stream: BinaryIO,
    ) -> Never:
        del operations, path, stream
        msg = "simulated writer construction failure"
        raise RuntimeError(msg)

    monkeypatch.setattr(storage_module, "_StagedWriter", failing_writer)
    with pytest.raises(RuntimeError, match="construction failure"):
        _ = store.stage()

    assert tuple(store.staging_dir.iterdir()) == ()
    assert store._staging_reservations == {}
    assert store.reserved_bytes == 0


def test_discard_releases_reservation_when_root_verification_fails(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    store = ContentAddressedStore(root)
    writer = store.stage()
    _ = writer.write(b"payload")
    held = tmp_path / "held-cache"
    _ = root.rename(held)
    root.mkdir(mode=0o700)
    for namespace in (".staging", "documents", "renders"):
        (root / namespace).mkdir(mode=0o700)

    with pytest.raises(AppError, match="storage root"):
        writer.__exit__(None, None, None)

    assert store._staging_reservations == {}
    assert store.reserved_bytes == 0


def test_staged_size_reconciliation_handles_unmanaged_growth_and_shrink(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=10)
    path = store.staging_dir / "managed"
    with pytest.raises(AppError) as unmanaged:
        _ = store._reconcile_staged_size_locked(path, size=1)
    assert unmanaged.value.code is ErrorCode.INVALID_INPUT

    store._staging_reservations[path] = 1
    store._reserved_bytes = 1
    assert (
        store._reconcile_staged_size_locked(
            path,
            size=_GROWN_RESERVATION_BYTES,
        )
        == _GROWN_RESERVATION_BYTES
    )
    assert store._staging_reservations[path] == _GROWN_RESERVATION_BYTES
    assert store.reserved_bytes == _GROWN_RESERVATION_BYTES
    assert store._reconcile_staged_size_locked(path, size=1) == 1
    assert store._staging_reservations[path] == 1
    assert store.reserved_bytes == 1

    store._used_bytes = store.max_bytes
    with pytest.raises(AppError) as full:
        _ = store._reconcile_staged_size_locked(path, size=2)
    assert full.value.code is ErrorCode.CACHE_FULL


def test_existing_byte_scan_ignores_non_regular_entries_after_startup(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    fifo = store.root / "documents" / "late-fifo"
    os.mkfifo(fifo)

    assert store._scan_existing_bytes() == 0


@pytest.mark.parametrize("entry_kind", ["directory-symlink", "fifo"])
def test_artifact_tree_validator_reaches_each_nonregular_entry_branch(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    documents = tmp_path / "documents"
    _mkdir_private(documents)
    _write_private(documents / "valid.bin", b"valid")
    outside = tmp_path / "outside"
    _mkdir_private(outside)
    unsafe_entry = documents / entry_kind
    if entry_kind == "directory-symlink":
        unsafe_entry.symlink_to(outside, target_is_directory=True)
    else:
        os.mkfifo(unsafe_entry, mode=0o600)
    descriptor = os.open(documents, os.O_RDONLY | os.O_DIRECTORY)

    try:
        with pytest.raises(
            ValueError,
            match="pre-existing artifact tree contains a link or special file",
        ):
            storage_module._validate_artifact_directory(
                descriptor,
                depth=0,
                entry_count=[0],
            )
    finally:
        os.close(descriptor)

    assert outside.is_dir()
    assert unsafe_entry.exists() or unsafe_entry.is_symlink()


def test_root_verification_rejects_drift_when_opener_returns_no_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)

    def malformed_open(
        path: Path | str,
        *,
        directory_fd: int | None = None,
    ) -> tuple[int, storage_module._DirectoryIdentity]:
        del path, directory_fd
        changed = storage_module._DirectoryIdentity(
            device=store._root_identity.device,
            inode=store._root_identity.inode + 1,
        )
        return cast("tuple[int, storage_module._DirectoryIdentity]", (None, changed))

    monkeypatch.setattr(storage_module, "_open_verified_directory", malformed_open)
    with pytest.raises(AppError, match="storage root"):
        store._verify_store_root_identity()


def test_stored_objects_rejects_late_non_directory_child(tmp_path: Path) -> None:
    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path)
    _write_private(store.root / "documents" / "late-file", b"payload")

    with pytest.raises(AppError) as raised:
        _ = store._stored_objects()

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_plain_store_prune_working_set_removes_without_insertion_registry(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    object_root = store.root / "documents" / "doc_manual"
    _mkdir_private(object_root)
    _write_private(object_root / "source.bin", b"payload")
    candidate = storage_module._StoredObject(
        key="documents/doc_manual",
        path=object_root,
        size=len(b"payload"),
        inodes=2,
        modified_ns=0,
        insertion_sequence=0,
    )
    state = storage_module._PruneWorkingSet(
        objects=[candidate],
        policy=RetentionPolicy(
            maximum_age_seconds=60,
            maximum_bytes=1,
            maximum_objects=1,
            minimum_free_bytes=_COVERAGE_POLICY.minimum_free_bytes,
            minimum_free_inodes=_COVERAGE_POLICY.minimum_free_inodes,
        ),
        capacity=StorageCapacity(
            total_bytes=_COVERAGE_POLICY.minimum_free_bytes + 2,
            available_bytes=_COVERAGE_POLICY.minimum_free_bytes + 2,
            total_inodes=1000,
            available_inodes=1000,
        ),
        cutoff_ns=1,
        clock_trusted=True,
    )

    assert store._prune_unleased(state) == (len(b"payload"), 1)
    assert not object_root.exists()


def test_prune_reports_available_byte_headroom_pressure(tmp_path: Path) -> None:
    capacity = _CoverageCapacity(
        StorageCapacity(
            total_bytes=_COVERAGE_CAPACITY.total_bytes,
            available_bytes=_COVERAGE_POLICY.minimum_free_bytes - 1,
            total_inodes=_COVERAGE_CAPACITY.total_inodes,
            available_inodes=_COVERAGE_CAPACITY.available_inodes,
        )
    )
    store, clock, _capacity = _coverage_lifecycle_store(
        tmp_path,
        capacity=capacity,
    )

    report = store.prune(_COVERAGE_POLICY, clock=clock())

    assert report.status == "unsatisfied"
    assert PruneBlocker.BYTE_HEADROOM in report.blockers


def test_document_publish_failure_removes_persistent_insertion_sequence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path)
    real_replace = Path.replace

    def replace_then_mutate(source: Path, target: Path | str) -> Path:
        published = real_replace(source, target)
        _ = Path(target).write_bytes(b"tampered")
        return published

    monkeypatch.setattr(Path, "replace", replace_then_mutate)
    with pytest.raises(AppError):
        _ = store.put_bytes(
            b"payload",
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )

    assert store._insertion_order is not None
    object_key = f"documents/doc_{sha256(b'payload').hexdigest()}"
    with pytest.raises(ValueError, match="no initialized insertion sequence"):
        _ = store._insertion_order.sequence_for(object_key)


def test_staged_file_commit_rejects_a_path_outside_the_managed_directory(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    writer = store.stage()
    _ = writer.write(b"payload")
    snapshot = writer._snapshot()
    try:
        with pytest.raises(AppError) as raised:
            _ = store._commit_staged_file(
                tmp_path / "outside.bin",
                storage_module._StagedFileCommit(
                    namespace="documents",
                    filename="source.bin",
                    media_type="application/octet-stream",
                    snapshot=snapshot,
                ),
            )
    finally:
        writer.__exit__(None, None, None)

    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_document_commit_tolerates_external_disappearance_before_directory_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    payload = b"payload"
    digest = sha256(payload).hexdigest()
    destination = store.root / "documents" / f"doc_{digest}" / "source.bin"
    real_exists = Path.exists

    def hide_destination(path: Path) -> bool:
        if path == destination:
            return False
        return real_exists(path)

    monkeypatch.setattr(Path, "exists", hide_destination)
    artifact = store.put_bytes(
        payload,
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )

    assert artifact.absolute_path.is_file()


def test_render_destination_rechecks_a_final_component_for_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    relative_path = "renders/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/resources/index.json"
    destination = store.root / relative_path
    real_is_symlink = Path.is_symlink
    destination_checks = 0

    def swapped_is_symlink(path: Path) -> bool:
        nonlocal destination_checks
        if path == destination:
            destination_checks += 1
            return destination_checks > 1
        return real_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", swapped_is_symlink)
    with pytest.raises(AppError) as raised:
        _ = store._validated_render_destination(relative_path)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


@pytest.mark.parametrize(
    ("operation", "defect"),
    [
        ("commit", "unmanaged"),
        ("commit", "accounting"),
        ("replace", "unmanaged"),
        ("replace", "accounting"),
    ],
)
def test_render_staged_operations_reject_unmanaged_or_inconsistent_reservations(
    tmp_path: Path,
    operation: str,
    defect: str,
) -> None:
    store = ContentAddressedStore(tmp_path)
    writer = store.stage()
    _ = writer.write(b"payload")
    snapshot = writer._snapshot()
    staged = writer._path
    if defect == "unmanaged":
        del store._staging_reservations[staged]
        store._reserved_bytes -= snapshot.size
    else:
        store._staging_reservations[staged] += 1
        store._reserved_bytes += 1
    relative_path = "renders/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/resources/index.json"
    try:
        if operation == "commit":
            with pytest.raises(AppError) as raised:
                _ = store._commit_staged_render(
                    staged,
                    storage_module._StagedRenderCommit(
                        relative_path=relative_path,
                        snapshot=snapshot,
                    ),
                )
        else:
            with pytest.raises(AppError) as raised:
                _ = store._replace_staged_render(
                    staged,
                    storage_module._StagedRenderReplacement(
                        relative_path=relative_path,
                        expected_sha256="0" * 64,
                        snapshot=snapshot,
                    ),
                )
    finally:
        writer.__exit__(None, None, None)

    expected = (
        ErrorCode.INVALID_INPUT if defect == "unmanaged" else ErrorCode.INTERNAL_ERROR
    )
    assert raised.value.code is expected


def test_lifecycle_render_commit_registers_both_new_and_existing_destinations(
    tmp_path: Path,
) -> None:
    store, _clock, _capacity = _coverage_lifecycle_store(tmp_path)
    relative_path = "renders/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/resources/index.json"

    _ = store.put_render_bytes(relative_path, b"payload")
    _ = store.put_render_bytes(relative_path, b"payload")

    assert store._insertion_order is not None
    assert (
        store._insertion_order.sequence_for(
            "renders/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        == 1
    )


def test_render_commit_tolerates_hidden_destination_before_directory_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    relative_path = "renders/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/resources/index.json"
    destination = store.root / relative_path
    real_exists = Path.exists

    def hide_destination(path: Path) -> bool:
        if path == destination:
            return False
        return real_exists(path)

    monkeypatch.setattr(Path, "exists", hide_destination)
    written_path, _digest = store.put_render_bytes(relative_path, b"payload")

    assert written_path == relative_path
    assert destination.is_file()
