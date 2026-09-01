# Copyright (c) 2026 David Osipov
"""Unit tests for content-addressed storage."""

import os
import secrets
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import sha256
from http import HTTPStatus
from pathlib import Path
from typing import BinaryIO, Never, Protocol, cast

import pytest

from nplg_mcp import storage as storage_module
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.storage import (
    ContentAddressedStore,
    StoredArtifact,
)
from tests.helpers.lease_store import lease_barrier_store

_SMALL_PAYLOAD_SIZE = 4
_QUOTA_BYTES = 8
_RECOVERY_PAYLOAD_SIZE = 10
_VALID_TILE_LAYOUT_BYTES = 10
_OVERBOUND_ORPHAN_ENTRIES = 4_097
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_DRIFTED_DIRECTORY_MODE = 0o750


class _ReadinessDirectoryIdentity(Protocol):
    @property
    def device(self) -> int: ...

    @property
    def inode(self) -> int: ...


@dataclass(frozen=True, slots=True)
class _CrossFilesystemDirectoryIdentity:
    device: int
    inode: int


class _OpenVerifiedDirectory(Protocol):
    def __call__(
        self,
        path: Path | str,
        *,
        directory_fd: int | None = None,
    ) -> tuple[int, _ReadinessDirectoryIdentity]: ...


@pytest.mark.parametrize(
    "relative_directory",
    [".", ".staging", "documents", "renders"],
)
def test_readiness_rejects_private_directory_mode_drift_without_repair(
    tmp_path: Path,
    relative_directory: str,
) -> None:
    store = ContentAddressedStore(tmp_path)
    drifted = store.root / relative_directory
    drifted.chmod(_DRIFTED_DIRECTORY_MODE)

    with pytest.raises(AppError) as captured:
        store.ensure_ready()

    assert captured.value.code is ErrorCode.INTERNAL_ERROR
    assert captured.value.http_status == HTTPStatus.SERVICE_UNAVAILABLE
    assert stat.S_IMODE(drifted.stat().st_mode) == _DRIFTED_DIRECTORY_MODE


def test_readiness_sanitizes_child_directory_cross_filesystem_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    root_descriptor_attribute = "_root_descriptor"
    root_descriptor = cast("int", getattr(store, root_descriptor_attribute))
    open_verified_directory_attribute = "_open_verified_directory"
    open_verified_directory = cast(
        "_OpenVerifiedDirectory",
        getattr(storage_module, open_verified_directory_attribute),
    )

    def open_child_with_cross_filesystem_identity(
        path: Path | str,
        *,
        directory_fd: int | None = None,
    ) -> tuple[int, _ReadinessDirectoryIdentity]:
        descriptor, identity = open_verified_directory(
            path,
            directory_fd=directory_fd,
        )
        if directory_fd == root_descriptor:
            return descriptor, _CrossFilesystemDirectoryIdentity(
                device=identity.device + 1,
                inode=identity.inode,
            )
        return descriptor, identity

    monkeypatch.setattr(
        storage_module,
        "_open_verified_directory",
        open_child_with_cross_filesystem_identity,
    )

    with pytest.raises(AppError) as captured:
        store.ensure_ready()

    assert captured.value.code is ErrorCode.INTERNAL_ERROR
    assert captured.value.http_status == HTTPStatus.SERVICE_UNAVAILABLE


def test_readiness_preserves_existing_app_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    expected = AppError(
        ErrorCode.INVALID_INPUT,
        "Existing readiness error.",
        http_status=418,
    )

    def raise_existing_app_error() -> None:
        raise expected

    monkeypatch.setattr(store, "_verify_store_root_identity", raise_existing_app_error)

    with pytest.raises(AppError) as captured:
        store.ensure_ready()

    assert captured.value is expected


def test_readiness_accepts_healthy_store_without_lifecycle(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"healthy",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )

    store.ensure_ready()

    assert store.resolve_asset(artifact.relative_path).read_bytes() == b"healthy"


def test_readiness_rejects_used_bytes_over_maximum_without_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)
    monkeypatch.setattr(store, "_used_bytes", store.max_bytes + 1)

    with pytest.raises(AppError) as captured:
        store.ensure_ready()

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert captured.value.http_status == HTTPStatus.SERVICE_UNAVAILABLE


def test_readiness_rejects_persisted_object_capacity_drift(tmp_path: Path) -> None:
    store, _policy, _clock = lease_barrier_store(tmp_path)
    first = store.put_bytes(
        b"first",
        namespace="documents",
        filename="first.bin",
        media_type="application/octet-stream",
    )
    second = store.put_bytes(
        b"second",
        namespace="documents",
        filename="second.bin",
        media_type="application/octet-stream",
    )
    assert first.object_id != second.object_id

    with pytest.raises(AppError) as captured:
        store.ensure_ready()

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert captured.value.http_status == HTTPStatus.SERVICE_UNAVAILABLE


class _StagedWriterProtocol(Protocol):
    def write(self, data: bytes) -> int: ...

    def commit(
        self, *, namespace: str, filename: str, media_type: str
    ) -> StoredArtifact: ...

    def commit_render(self, relative_path: str) -> tuple[str, str]: ...


class _FailingWriteStream:
    def write(self, data: bytes) -> int:
        del data
        msg = "simulated stream write failure"
        raise OSError(msg)

    def close(self) -> None:
        pass


class _ShortWriteStream:
    def write(self, data: bytes, /) -> int:
        return min(1, len(data))

    def close(self) -> None:
        pass


def _write_then_abort(destination: _StagedWriterProtocol) -> Never:
    _ = destination.write(b"1234")
    msg = "abort"
    raise RuntimeError(msg)


def _write_and_commit(destination: _StagedWriterProtocol, data: bytes) -> None:
    _ = destination.write(data)
    _ = destination.commit(
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
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


def _build_private_complete_tile_layout(
    tmp_path: Path,
) -> tuple[Path, Path, Path]:
    render = tmp_path / "renders" / f"rnd_{'a' * 32}"
    tiles = render / "tiles"
    _mkdir_private(tiles, parents=True)
    render_marker = render / "manifest.json"
    _write_private(render_marker, b"render")
    tile_marker = tiles / "page-valid" / "geometry-complete" / "manifest.json"
    _mkdir_private(tile_marker.parent, parents=True)
    _write_private(tile_marker, b"tile")
    return tiles, render_marker, tile_marker


def test_content_addressed_store_is_deterministic_atomic_and_deduplicated(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)

    first = store.put_bytes(
        b"%PDF-1.7\nfirst",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    second = store.put_bytes(
        b"%PDF-1.7\nfirst",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    assert first == second
    assert first.object_id.startswith("doc_")
    assert (
        first.sha256
        == "eb23680cd6b2852b2cf8cbbb6ca2e03d4a4b7e9784c4c16d0acea2c3640e40dd"
    )
    assert first.relative_path == f"documents/{first.object_id}/source.pdf"
    assert first.absolute_path.read_bytes() == b"%PDF-1.7\nfirst"
    assert list((tmp_path / ".staging").iterdir()) == []


def test_same_content_with_different_filename_keeps_one_object_directory(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    first = store.put_bytes(
        b"same",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    second = store.put_bytes(
        b"same",
        namespace="documents",
        filename="original.pdf",
        media_type="application/pdf",
    )

    assert first.object_id == second.object_id
    assert first.absolute_path.parent == second.absolute_path.parent
    assert first.absolute_path.exists()
    assert second.absolute_path.exists()


@pytest.mark.parametrize(
    ("namespace", "filename"),
    [
        ("../documents", "source.pdf"),
        ("documents/other", "source.pdf"),
        ("documents", "../escape.pdf"),
        ("documents", "/absolute.pdf"),
        ("documents", "nested/file.pdf"),
        ("documents", "file\\name.pdf"),
        ("unknown", "source.pdf"),
    ],
)
def test_store_rejects_traversal_and_unapproved_namespaces(
    tmp_path: Path, namespace: str, filename: str
) -> None:
    store = ContentAddressedStore(tmp_path)
    with pytest.raises(AppError) as raised:
        _ = store.put_bytes(
            b"x",
            namespace=namespace,
            filename=filename,
            media_type="application/octet-stream",
        )
    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_resolve_asset_cannot_escape_root(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"jpeg", namespace="renders", filename="page-0001.jpg", media_type="image/jpeg"
    )

    assert store.resolve_asset(artifact.relative_path) == artifact.absolute_path
    with pytest.raises(AppError) as raised:
        _ = store.resolve_asset("renders/../../etc/passwd")
    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_import_file_removes_staging_file_after_commit(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    with store.stage(suffix=".pdf") as staged:
        _ = staged.write(b"%PDF-1.4\nbody")
        artifact = staged.commit(
            namespace="documents",
            filename="source.pdf",
            media_type="application/pdf",
        )

    assert artifact.absolute_path.exists()
    assert list((tmp_path / ".staging").iterdir()) == []
    assert not hasattr(store, "create_staging_path")


def test_deduplication_verifies_existing_large_artifact_without_read_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    _ = store.put_bytes(
        b"same",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    def forbidden_read_bytes(self: Path) -> bytes:
        msg = f"read_bytes must not buffer the whole artifact: {self}"
        raise AssertionError(msg)

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    duplicate = store.put_bytes(
        b"same",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    assert duplicate.size == _SMALL_PAYLOAD_SIZE


def test_cache_quota_rejects_new_bytes_without_exceeding_limit(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=_QUOTA_BYTES)
    _ = store.put_bytes(
        b"12345678",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    with pytest.raises(AppError) as captured:
        _ = store.put_bytes(
            b"x", namespace="renders", filename="page.jpg", media_type="image/jpeg"
        )

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert store.used_bytes == _QUOTA_BYTES
    assert (
        sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file())
        == _QUOTA_BYTES
    )
    assert list((tmp_path / ".staging").iterdir()) == []


def test_cache_quota_counts_existing_files_and_deduplication_once(
    tmp_path: Path,
) -> None:
    first = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)
    artifact = first.put_bytes(
        b"same",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    assert (
        first.put_bytes(
            b"same",
            namespace="documents",
            filename="source.pdf",
            media_type="application/pdf",
        )
        == artifact
    )
    assert first.used_bytes == _SMALL_PAYLOAD_SIZE

    reopened = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)
    assert reopened.used_bytes == _SMALL_PAYLOAD_SIZE
    with pytest.raises(AppError) as captured:
        _ = reopened.put_bytes(
            b"x", namespace="renders", filename="page.jpg", media_type="image/jpeg"
        )
    assert captured.value.code is ErrorCode.CACHE_FULL


def test_cache_quota_reservation_is_thread_safe(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=_QUOTA_BYTES)

    def write(value: bytes) -> ErrorCode | None:
        try:
            _ = store.put_bytes(
                value,
                namespace="documents",
                filename="source.pdf",
                media_type="application/pdf",
            )
        except AppError as exc:
            return exc.code
        return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(write, (b"a" * 8, b"b" * 8)))

    assert sorted(outcome is None for outcome in outcomes) == [False, True]
    assert ErrorCode.CACHE_FULL in outcomes
    assert store.used_bytes == _QUOTA_BYTES
    assert (
        sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file())
        == _QUOTA_BYTES
    )


def test_aborted_staged_writer_releases_reserved_capacity(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)

    with (
        pytest.raises(RuntimeError, match="abort"),
        store.stage(suffix=".bin") as destination,
    ):
        _write_then_abort(destination)

    assert store.used_bytes == 0
    assert store.reserved_bytes == 0
    assert list((tmp_path / ".staging").iterdir()) == []


def test_staged_commit_fsyncs_file_before_atomic_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    fsynced_descriptors: set[int] = set()
    real_fsync = os.fsync
    real_replace = os.replace

    def recording_fsync(descriptor: int) -> None:
        fsynced_descriptors.add(descriptor)
        real_fsync(descriptor)

    def checked_replace(source: Path | str, destination: Path | str) -> None:
        assert fsynced_descriptors
        real_replace(source, destination)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    monkeypatch.setattr(os, "replace", checked_replace)

    with store.stage(suffix=".pdf") as staged:
        _ = staged.write(b"%PDF-1.4\nbody")
        artifact = staged.commit(
            namespace="documents",
            filename="source.pdf",
            media_type="application/pdf",
        )

    assert artifact.absolute_path.is_file()


def test_startup_discards_abandoned_regular_staging(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".staging"
    _mkdir_private(staging, parents=True)
    abandoned = staging / "stage-abandoned.bin"
    _ = abandoned.write_bytes(b"1234")

    store = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)

    assert not abandoned.exists()
    assert store.used_bytes == 0
    assert (
        store.put_bytes(
            b"1234",
            namespace="documents",
            filename="source.pdf",
            media_type="application/pdf",
        ).size
        == _SMALL_PAYLOAD_SIZE
    )


def test_startup_discards_incomplete_render_and_tile_transactions(
    tmp_path: Path,
) -> None:
    renders = tmp_path / "renders"
    incomplete_render = renders / f"rnd_{'a' * 32}"
    _mkdir_private(incomplete_render, parents=True)
    _write_private(incomplete_render / "page-0001.jpg", b"orphan-page")

    complete_render = renders / f"rnd_{'b' * 32}"
    _mkdir_private(complete_render)
    _write_private(complete_render / "page-0001.jpg", b"page")
    _write_private(complete_render / "manifest.json", b"{}")
    incomplete_tiles = complete_render / "tiles" / "page-0001" / "w2048-h2048-o128"
    _mkdir_private(incomplete_tiles, parents=True)
    _write_private(incomplete_tiles / "tile.jpg", b"orphan-tile")

    store = ContentAddressedStore(tmp_path)

    assert not incomplete_render.exists()
    assert not incomplete_tiles.exists()
    assert (complete_render / "page-0001.jpg").is_file()
    assert (complete_render / "manifest.json").is_file()
    assert store.used_bytes == len(b"page{}")


def test_startup_rejects_dangling_render_tiles_symlink(tmp_path: Path) -> None:
    render = tmp_path / "renders" / f"rnd_{'c' * 32}"
    _mkdir_private(render, parents=True)
    _write_private(render / "manifest.json", b"{}")
    tiles = render / "tiles"
    tiles.symlink_to(tmp_path / "missing-target", target_is_directory=True)

    with pytest.raises(ValueError, match="pre-existing artifact tree"):
        _ = ContentAddressedStore(tmp_path)

    assert tiles.is_symlink()


def test_staged_writer_retains_exclusive_descriptor_across_symlink_swap(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    victim = tmp_path / "victim"
    _ = victim.write_bytes(b"safe")
    writer = store.stage(suffix=".bin")
    staged_path = _only_staged_path(store)
    staged_path.unlink()
    staged_path.symlink_to(victim)

    with writer as staged:
        _ = staged.write(b"attacker-controlled")

    assert victim.read_bytes() == b"safe"
    assert not staged_path.exists()
    assert store.reserved_bytes == 0


def test_staged_commit_rejects_regular_file_identity_swap(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    writer = store.stage(suffix=".bin")
    staged_path = _only_staged_path(store)
    staged_path.unlink()
    _ = staged_path.write_bytes(b"replacement")

    with pytest.raises(AppError) as captured, writer as staged:
        _write_and_commit(staged, b"intended")

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert not list((store.root / "documents").rglob("source.bin"))
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0


def test_staged_commit_rejects_same_inode_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    real_fsync = os.fsync

    def mutate_after_sync(descriptor: int) -> None:
        real_fsync(descriptor)
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            _ = os.pwrite(descriptor, b"evil", 0)

    monkeypatch.setattr(os, "fsync", mutate_after_sync)

    with pytest.raises(AppError) as captured, store.stage(suffix=".bin") as staged:
        _write_and_commit(staged, b"good")

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert not list((store.root / "documents").rglob("source.bin"))
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0


def test_render_publish_fsyncs_destination_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    events: list[tuple[str, bool | None]] = []
    real_fsync = os.fsync
    real_replace = os.replace

    def recording_fsync(descriptor: int) -> None:
        events.append(("fsync", stat.S_ISDIR(os.fstat(descriptor).st_mode)))
        real_fsync(descriptor)

    def recording_replace(source: Path | str, destination: Path | str) -> None:
        events.append(("replace", None))
        real_replace(source, destination)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    monkeypatch.setattr(os, "replace", recording_replace)

    _ = store.put_render_bytes(f"renders/rnd_{'a' * 32}/page-0001.jpg", b"jpeg")

    replace_index = events.index(("replace", None))
    assert any(
        kind == "fsync" and is_directory
        for kind, is_directory in events[replace_index + 1 :]
    )


@pytest.mark.parametrize("max_bytes", [0, -1, True])
def test_store_rejects_non_positive_or_boolean_quota(
    tmp_path: Path, max_bytes: int
) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        _ = ContentAddressedStore(tmp_path, max_bytes=max_bytes)


def test_store_root_requires_nofollow_descriptor_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(os, "O_NOFOLLOW")

    with pytest.raises(ValueError, match="cache root") as raised:
        _ = ContentAddressedStore(tmp_path)

    assert isinstance(raised.value.__cause__, ValueError)
    assert "descriptor requires" in str(raised.value.__cause__)


def test_store_rejects_a_permissive_existing_root(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir(mode=0o700)
    root.chmod(0o777)

    with pytest.raises(ValueError, match="cache root"):
        _ = ContentAddressedStore(root)


@pytest.mark.parametrize("name", [".staging", "documents", "renders"])
def test_store_rejects_permissive_existing_namespaces(
    tmp_path: Path,
    name: str,
) -> None:
    root = tmp_path / "cache"
    root.mkdir(mode=0o700)
    child = root / name
    child.mkdir(mode=0o700)
    child.chmod(0o777)

    with pytest.raises(ValueError, match=r"cache (?:staging|namespace)"):
        _ = ContentAddressedStore(root)


def test_store_rejects_root_not_owned_by_the_service_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "cache"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(os, "geteuid", lambda: root.stat().st_uid + 1)

    with pytest.raises(ValueError, match="cache root") as raised:
        _ = ContentAddressedStore(root)

    detail = str(raised.value.__cause__ or raised.value)
    assert "owned by the service process" in detail or "another principal" in detail


def test_store_rejects_a_symlinked_configured_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    root = tmp_path / "cache"
    root.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="cache root"):
        _ = ContentAddressedStore(root)


@pytest.mark.parametrize("parent_kind", ["writable", "symlink"])
def test_store_rejects_an_untrusted_configured_root_parent(
    tmp_path: Path,
    parent_kind: str,
) -> None:
    real_parent = tmp_path / "real-parent"
    _mkdir_private(real_parent)
    if parent_kind == "writable":
        real_parent.chmod(0o777)
        parent = real_parent
    else:
        parent = tmp_path / "parent-alias"
        parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="cache root parent"):
        _ = ContentAddressedStore(parent / "cache")

    assert not (real_parent / "cache").exists()


def test_store_accepts_a_private_root_under_a_sticky_shared_parent(
    tmp_path: Path,
) -> None:
    shared_parent = tmp_path / "shared"
    shared_parent.mkdir(mode=0o700)
    shared_parent.chmod(0o1777)
    root = shared_parent / "cache"

    store = ContentAddressedStore(root)

    assert store.root == root
    assert (
        stat.S_IMODE(root.stat(follow_symlinks=False).st_mode)
        == _PRIVATE_DIRECTORY_MODE
    )


def test_store_rejects_root_swap_before_plain_publication(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    store = ContentAddressedStore(root)
    held_root = tmp_path / "held-cache"
    _ = root.rename(held_root)
    _ = ContentAddressedStore(root)

    with pytest.raises(AppError) as raised:
        _ = store.put_bytes(
            b"document",
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert not tuple((root / "documents").rglob("source.bin"))
    assert not tuple((held_root / "documents").rglob("source.bin"))


def test_store_creates_private_document_and_render_directories(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    store = ContentAddressedStore(root)

    document = store.put_bytes(
        b"document",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    render_id = f"rnd_{'a' * 32}"
    _ = store.put_render_bytes(f"renders/{render_id}/page-0001.jpg", b"jpeg")

    for directory in (
        root,
        root / ".staging",
        root / "documents",
        root / "renders",
        document.absolute_path.parent,
        root / "renders" / render_id,
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == _PRIVATE_DIRECTORY_MODE


def test_store_enforces_private_modes_under_a_restrictive_umask(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    previous_umask = os.umask(0o777)
    try:
        document = store.put_bytes(
            b"document",
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )
        render_id = f"rnd_{'d' * 32}"
        _ = store.put_render_bytes(f"renders/{render_id}/page-0001.jpg", b"jpeg")
    finally:
        _ = os.umask(previous_umask)

    assert (
        stat.S_IMODE(document.absolute_path.parent.stat().st_mode)
        == _PRIVATE_DIRECTORY_MODE
    )
    assert stat.S_IMODE(document.absolute_path.stat().st_mode) == _PRIVATE_FILE_MODE
    assert (
        stat.S_IMODE((tmp_path / "renders" / render_id).stat().st_mode)
        == _PRIVATE_DIRECTORY_MODE
    )
    assert (
        stat.S_IMODE(
            (tmp_path / "renders" / render_id / "page-0001.jpg").stat().st_mode
        )
        == _PRIVATE_FILE_MODE
    )


def test_store_rejects_a_permissive_preexisting_document_object(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    payload = b"document"
    object_dir = tmp_path / "documents" / f"doc_{sha256(payload).hexdigest()}"
    object_dir.mkdir(mode=0o700)
    object_dir.chmod(0o777)

    with pytest.raises(ValueError, match="document object"):
        _ = store.put_bytes(
            payload,
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )

    assert list(store.staging_dir.iterdir()) == []


def test_store_rejects_a_permissive_preexisting_render_object(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    render_id = f"rnd_{'b' * 32}"
    object_dir = tmp_path / "renders" / render_id
    object_dir.mkdir(mode=0o700)
    object_dir.chmod(0o777)

    with pytest.raises(ValueError, match="render object"):
        _ = store.put_render_bytes(f"renders/{render_id}/page-0001.jpg", b"jpeg")

    assert list(store.staging_dir.iterdir()) == []


@pytest.mark.parametrize(
    "unsafe_state",
    ["directory-mode", "directory-no-access", "file-mode", "hardlink"],
)
def test_store_rejects_an_unsafe_preexisting_artifact_tree(
    tmp_path: Path,
    unsafe_state: str,
) -> None:
    _ = ContentAddressedStore(tmp_path)
    object_dir = tmp_path / "documents" / f"doc_{'c' * 64}"
    _mkdir_private(object_dir)
    artifact = object_dir / "source.bin"
    _ = artifact.write_bytes(b"artifact")
    artifact.chmod(0o600)
    if unsafe_state == "directory-mode":
        object_dir.chmod(0o777)
    elif unsafe_state == "directory-no-access":
        object_dir.chmod(0o000)
    elif unsafe_state == "file-mode":
        artifact.chmod(0o644)
    else:
        os.link(artifact, object_dir / "alias.bin")

    try:
        with pytest.raises(ValueError, match="pre-existing artifact tree"):
            _ = ContentAddressedStore(tmp_path)
    finally:
        object_dir.chmod(0o700)
        artifact.chmod(0o600)


@pytest.mark.parametrize("namespace", ["documents", "renders"])
def test_store_rejects_symlinked_cache_directories(
    tmp_path: Path, namespace: str
) -> None:
    root = tmp_path / "cache"
    target = tmp_path / "target"
    _mkdir_private(target)
    _mkdir_private(root)
    (root / namespace).symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="namespace"):
        _ = ContentAddressedStore(root)

    assert target.is_dir()


def test_store_rejects_symlinked_staging_directory(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    target = tmp_path / "target"
    _mkdir_private(target)
    _mkdir_private(root)
    (root / ".staging").symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="staging"):
        _ = ContentAddressedStore(root)

    assert target.is_dir()


def test_startup_discards_stale_staging_directories(tmp_path: Path) -> None:
    stale = tmp_path / ".staging" / "stage-abandoned"
    _mkdir_private(stale, parents=True)
    _ = (stale / "payload").write_bytes(b"abandoned")

    store = ContentAddressedStore(tmp_path)

    assert not stale.exists()
    assert store.used_bytes == 0


@pytest.mark.parametrize("entry_kind", ["symlink", "fifo"])
def test_startup_rejects_unsafe_orphan_staging_entries_without_deleting_targets(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    root = tmp_path / "cache"
    staging = root / ".staging"
    _mkdir_private(staging, parents=True)
    target = tmp_path / "outside-target"
    _ = target.write_bytes(b"must-survive")
    entry = staging / f"stage-{'a' * 32}.pdf"
    if entry_kind == "symlink":
        entry.symlink_to(target)
    else:
        os.mkfifo(entry, mode=0o600)

    with pytest.raises(ValueError, match="staging recovery"):
        _ = ContentAddressedStore(root)

    assert target.read_bytes() == b"must-survive"
    assert entry.exists() or entry.is_symlink()


def test_startup_rejects_overbound_orphan_inventory_before_partial_cleanup(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    staging = root / ".staging"
    _mkdir_private(staging, parents=True)
    for index in range(_OVERBOUND_ORPHAN_ENTRIES):
        _ = (staging / f"stage-{index:032x}.bin").write_bytes(b"")

    with pytest.raises(ValueError, match="staging recovery inventory"):
        _ = ContentAddressedStore(root)

    assert len(tuple(staging.iterdir())) == _OVERBOUND_ORPHAN_ENTRIES


def test_startup_rejects_overdeep_or_oversized_orphan_trees(
    tmp_path: Path,
) -> None:
    deep_root = tmp_path / "deep-cache"
    deep_staging = deep_root / ".staging"
    current = deep_staging / "stage-tree"
    _mkdir_private(current, parents=True)
    for index in range(9):
        current = current / f"level-{index}"
        _mkdir_private(current)
    _ = (current / "payload.bin").write_bytes(b"x")

    with pytest.raises(ValueError, match="staging recovery depth"):
        _ = ContentAddressedStore(deep_root)

    byte_root = tmp_path / "byte-cache"
    byte_staging = byte_root / ".staging"
    _mkdir_private(byte_staging, parents=True)
    oversized = byte_staging / f"stage-{'b' * 32}.bin"
    with oversized.open("wb") as stream:
        _ = stream.truncate(_QUOTA_BYTES + 1)

    with pytest.raises(ValueError, match="staging recovery byte"):
        _ = ContentAddressedStore(byte_root, max_bytes=_QUOTA_BYTES)

    assert oversized.stat().st_size == _QUOTA_BYTES + 1


def test_startup_rejects_orphan_replaced_with_symlink_during_descriptor_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "cache"
    staging = root / ".staging"
    _mkdir_private(staging, parents=True)
    target = tmp_path / "outside-target"
    _ = target.write_bytes(b"must-survive")
    entry = staging / f"stage-{'c' * 32}.bin"
    _ = entry.write_bytes(b"orphan")
    real_open = os.open
    replaced = False

    def swap_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if dir_fd is not None and os.fsdecode(path) == entry.name and not replaced:
            entry.unlink()
            entry.symlink_to(target)
            replaced = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_before_open)

    with pytest.raises(ValueError, match="staging recovery"):
        _ = ContentAddressedStore(root)

    assert replaced
    assert target.read_bytes() == b"must-survive"
    assert entry.is_symlink()


def test_startup_rejects_render_symlinks_without_deleting_targets(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    renders = root / "renders"
    _mkdir_private(renders, parents=True)
    unrelated = renders / "notes"
    _mkdir_private(unrelated)
    victim = tmp_path / "victim"
    _mkdir_private(victim)
    render_link = renders / f"rnd_{'d' * 32}"
    render_link.symlink_to(victim, target_is_directory=True)

    with pytest.raises(ValueError, match="pre-existing artifact tree"):
        _ = ContentAddressedStore(root)

    assert unrelated.is_dir()
    assert render_link.is_symlink()
    assert victim.is_dir()


def test_startup_rejects_symlinked_completion_manifest(tmp_path: Path) -> None:
    render = tmp_path / "renders" / f"rnd_{'e' * 32}"
    _mkdir_private(render, parents=True)
    victim = tmp_path / "victim"
    _ = victim.write_bytes(b"safe")
    (render / "manifest.json").symlink_to(victim)

    with pytest.raises(ValueError, match="pre-existing artifact tree"):
        _ = ContentAddressedStore(tmp_path)

    assert render.exists()
    assert victim.read_bytes() == b"safe"


def test_startup_preserves_completed_render_without_tiles(tmp_path: Path) -> None:
    render = tmp_path / "renders" / f"rnd_{'f' * 32}"
    _mkdir_private(render, parents=True)
    _write_private(render / "manifest.json", b"{}")

    store = ContentAddressedStore(tmp_path)

    assert (render / "manifest.json").is_file()
    assert store.used_bytes == len(b"{}")


def test_startup_rejects_symlinked_tile_page_fail_closed(
    tmp_path: Path,
) -> None:
    tiles, render_marker, tile_marker = _build_private_complete_tile_layout(tmp_path)
    victim = tmp_path / "victim-page"
    _mkdir_private(victim)
    victim_marker = victim / "sentinel.bin"
    _write_private(victim_marker, b"outside")
    page_link = tiles / "page-link"
    page_link.symlink_to(victim, target_is_directory=True)

    with pytest.raises(ValueError, match="pre-existing artifact tree"):
        _ = ContentAddressedStore(tmp_path)

    assert page_link.is_symlink()
    assert victim_marker.read_bytes() == b"outside"
    assert render_marker.read_bytes() == b"render"
    assert tile_marker.read_bytes() == b"tile"


def test_startup_recovers_private_regular_tile_page(tmp_path: Path) -> None:
    tiles, render_marker, tile_marker = _build_private_complete_tile_layout(tmp_path)
    invalid_page = tiles / "page-file"
    _write_private(invalid_page, b"invalid")

    store = ContentAddressedStore(tmp_path)

    assert not invalid_page.exists()
    assert render_marker.read_bytes() == b"render"
    assert tile_marker.read_bytes() == b"tile"
    assert store.used_bytes == _VALID_TILE_LAYOUT_BYTES


def test_startup_recovers_private_regular_tile_geometry(tmp_path: Path) -> None:
    tiles, render_marker, tile_marker = _build_private_complete_tile_layout(tmp_path)
    invalid_geometry = tiles / "page-valid" / "geometry-file"
    _write_private(invalid_geometry, b"invalid")

    store = ContentAddressedStore(tmp_path)

    assert not invalid_geometry.exists()
    assert render_marker.read_bytes() == b"render"
    assert tile_marker.read_bytes() == b"tile"
    assert store.used_bytes == _VALID_TILE_LAYOUT_BYTES


def test_startup_rejects_symlinked_tile_geometry_fail_closed(
    tmp_path: Path,
) -> None:
    tiles, render_marker, tile_marker = _build_private_complete_tile_layout(tmp_path)
    victim = tmp_path / "victim-geometry"
    _mkdir_private(victim)
    victim_marker = victim / "sentinel.bin"
    _write_private(victim_marker, b"outside")
    geometry_link = tiles / "page-valid" / "geometry-link"
    geometry_link.symlink_to(victim, target_is_directory=True)

    with pytest.raises(ValueError, match="pre-existing artifact tree"):
        _ = ContentAddressedStore(tmp_path)

    assert geometry_link.is_symlink()
    assert victim_marker.read_bytes() == b"outside"
    assert render_marker.read_bytes() == b"render"
    assert tile_marker.read_bytes() == b"tile"


def test_startup_recovers_incomplete_private_tile_geometry(tmp_path: Path) -> None:
    tiles, render_marker, tile_marker = _build_private_complete_tile_layout(tmp_path)
    incomplete_geometry = tiles / "page-valid" / "geometry-incomplete"
    _mkdir_private(incomplete_geometry)

    store = ContentAddressedStore(tmp_path)

    assert not incomplete_geometry.exists()
    assert render_marker.read_bytes() == b"render"
    assert tile_marker.read_bytes() == b"tile"
    assert store.used_bytes == _VALID_TILE_LAYOUT_BYTES


def test_directory_fsync_failure_does_not_undo_atomic_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    real_open = os.open

    def reject_directory_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if flags == os.O_RDONLY and dir_fd is None and Path(os.fsdecode(path)).is_dir():
            msg = "directory fsync unsupported"
            raise OSError(msg)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", reject_directory_open)

    artifact = store.put_bytes(
        b"durable enough",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )

    assert artifact.absolute_path.read_bytes() == b"durable enough"


def test_empty_staged_write_reserves_no_capacity(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)

    with store.stage(suffix=".bin") as staged:
        assert staged.write(b"") == 0
        assert store.reserved_bytes == 0

    assert store.used_bytes == 0


def test_failed_stream_write_releases_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)

    def failing_fdopen(descriptor: int, mode: str) -> BinaryIO:
        del mode
        os.close(descriptor)
        return cast("BinaryIO", _FailingWriteStream())

    monkeypatch.setattr(os, "fdopen", failing_fdopen)

    with pytest.raises(OSError, match="simulated"), store.stage() as staged:
        _ = staged.write(b"1234")

    assert store.reserved_bytes == 0
    assert store.used_bytes == 0


def test_failed_empty_stream_write_keeps_zero_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)

    def failing_fdopen(descriptor: int, mode: str) -> BinaryIO:
        del mode
        os.close(descriptor)
        return cast("BinaryIO", _FailingWriteStream())

    monkeypatch.setattr(os, "fdopen", failing_fdopen)

    with pytest.raises(OSError, match="simulated"), store.stage() as staged:
        _ = staged.write(b"")

    assert store.reserved_bytes == 0
    assert store.used_bytes == 0


def test_short_stream_write_releases_unused_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)

    def short_fdopen(descriptor: int, mode: str) -> BinaryIO:
        del mode
        os.close(descriptor)
        return cast("BinaryIO", _ShortWriteStream())

    monkeypatch.setattr(os, "fdopen", short_fdopen)

    with store.stage() as staged:
        assert staged.write(b"1234") == 1
        assert store.reserved_bytes == 1

    assert store.reserved_bytes == 0
    assert store.used_bytes == 0


def test_closed_staged_writer_rejects_every_reuse(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    writer = store.stage(suffix=".bin")
    with writer as staged:
        _ = staged.write(b"data")
        _ = staged.commit(
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )

    with pytest.raises(RuntimeError, match="already closed"), writer:
        pass
    with pytest.raises(RuntimeError, match="not open"):
        _ = writer.write(b"again")
    with pytest.raises(RuntimeError, match="not open"):
        _ = writer.commit(
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )
    with pytest.raises(RuntimeError, match="not open"):
        _ = writer.commit_render(f"renders/rnd_{'a' * 32}/page.jpg")


def test_stage_closes_descriptor_and_removes_path_when_fdopen_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    descriptors_seen: list[int] = []

    def failing_fdopen(descriptor: int, mode: str) -> Never:
        del mode
        descriptors_seen.append(descriptor)
        msg = "fdopen failed"
        raise OSError(msg)

    monkeypatch.setattr(os, "fdopen", failing_fdopen)

    with pytest.raises(OSError, match="fdopen failed"):
        _ = store.stage(suffix=".bin")

    assert descriptors_seen
    with pytest.raises(OSError, match="Bad file descriptor"):
        _ = os.fstat(descriptors_seen[0])
    assert not tuple(store.staging_dir.iterdir())


def test_stage_fails_closed_if_nofollow_support_disappears_before_file_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    real_token_hex = secrets.token_hex

    def withdraw_nofollow_support(nbytes: int | None = None) -> str:
        monkeypatch.delattr(os, "O_NOFOLLOW")
        return real_token_hex(nbytes)

    monkeypatch.setattr(secrets, "token_hex", withdraw_nofollow_support)

    with pytest.raises(AppError) as raised:
        _ = store.stage(suffix=".bin")

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert store.reserved_bytes == 0
    assert not tuple(store.staging_dir.iterdir())


@pytest.mark.parametrize("suffix", ["/x", "\\x", "\x00"])
def test_stage_rejects_unsafe_suffix(tmp_path: Path, suffix: str) -> None:
    store = ContentAddressedStore(tmp_path)

    with pytest.raises(AppError) as raised:
        _ = store.stage(suffix=suffix)

    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize("media_type", ["", "application pdf", "text/plain value"])
def test_store_rejects_invalid_media_type(tmp_path: Path, media_type: str) -> None:
    store = ContentAddressedStore(tmp_path)

    with pytest.raises(AppError) as raised:
        _ = store.put_bytes(
            b"x",
            namespace="documents",
            filename="source.bin",
            media_type=media_type,
        )

    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_direct_put_detects_corrupted_content_address(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"same",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    _ = artifact.absolute_path.write_bytes(b"evil")

    with pytest.raises(AppError) as raised:
        _ = store.put_bytes(
            b"same",
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_replacement_atomically_compares_existing_digest(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    relative_path = f"renders/rnd_{'a' * 32}/resources/index.json"
    written_path, old_digest = store.put_render_bytes(relative_path, b"old-index")

    replaced_path, new_digest = store.replace_render_bytes_if_matches(
        relative_path,
        b"new-index",
        expected_sha256=old_digest,
    )

    assert written_path == replaced_path == relative_path
    assert new_digest == sha256(b"new-index").hexdigest()
    assert (store.root / relative_path).read_bytes() == b"new-index"
    assert not tuple(store.staging_dir.iterdir())


def test_render_replacement_rejects_stale_digest_without_overwrite(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    relative_path = f"renders/rnd_{'a' * 32}/resources/index.json"
    _ = store.put_render_bytes(relative_path, b"old-index")

    with pytest.raises(AppError) as raised:
        _ = store.replace_render_bytes_if_matches(
            relative_path,
            b"new-index",
            expected_sha256="0" * 64,
        )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert (store.root / relative_path).read_bytes() == b"old-index"
    assert not tuple(store.staging_dir.iterdir())


@pytest.mark.parametrize("expected_sha256", ["short", "g" * 64])
def test_render_replacement_rejects_invalid_expected_digest(
    tmp_path: Path,
    expected_sha256: str,
) -> None:
    store = ContentAddressedStore(tmp_path)
    relative_path = f"renders/rnd_{'a' * 32}/resources/index.json"
    _ = store.put_render_bytes(relative_path, b"old-index")

    with pytest.raises(AppError) as raised:
        _ = store.replace_render_bytes_if_matches(
            relative_path,
            b"new-index",
            expected_sha256=expected_sha256,
        )

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert (store.root / relative_path).read_bytes() == b"old-index"


@pytest.mark.parametrize("destination_state", ["missing", "symlink"])
def test_render_replacement_requires_regular_existing_destination(
    tmp_path: Path,
    destination_state: str,
) -> None:
    store = ContentAddressedStore(tmp_path)
    relative_path = f"renders/rnd_{'a' * 32}/resources/index.json"
    _, old_digest = store.put_render_bytes(relative_path, b"old-index")
    destination = store.root / relative_path
    destination.unlink()
    if destination_state == "symlink":
        target = store.root / "renders" / f"rnd_{'a' * 32}" / "target.json"
        _ = target.write_bytes(b"old-index")
        destination.symlink_to(target)

    with pytest.raises(AppError) as raised:
        _ = store.replace_render_bytes_if_matches(
            relative_path,
            b"new-index",
            expected_sha256=old_digest,
        )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert not tuple(store.staging_dir.iterdir())


def test_render_replacement_rejects_staged_identity_change_during_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    relative_path = f"renders/rnd_{'a' * 32}/resources/index.json"
    _, old_digest = store.put_render_bytes(relative_path, b"old-index")
    real_replace = Path.replace

    def replace_then_mutate(source: Path, target: Path | str) -> Path:
        published = real_replace(source, target)
        _ = Path(target).write_bytes(b"tampered")
        return published

    monkeypatch.setattr(Path, "replace", replace_then_mutate)

    with pytest.raises(AppError) as raised:
        _ = store.replace_render_bytes_if_matches(
            relative_path,
            b"new-index",
            expected_sha256=old_digest,
        )

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert not (store.root / relative_path).exists()
    assert not tuple(store.staging_dir.iterdir())


def test_render_replacement_identity_failure_reconciles_quota_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=18)
    relative_path = f"renders/rnd_{'a' * 32}/resources/index.json"
    _, old_digest = store.put_render_bytes(relative_path, b"old-index")
    real_replace = Path.replace

    def replace_then_mutate(source: Path, target: Path | str) -> Path:
        published = real_replace(source, target)
        _ = Path(target).write_bytes(b"tampered")
        return published

    monkeypatch.setattr(Path, "replace", replace_then_mutate)

    with pytest.raises(AppError) as raised:
        _ = store.replace_render_bytes_if_matches(
            relative_path,
            b"new-index",
            expected_sha256=old_digest,
        )

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0
    assert not tuple(store.staging_dir.iterdir())
    monkeypatch.setattr(Path, "replace", real_replace)

    next_path = f"renders/rnd_{'b' * 32}/next.bin"
    written_path, _ = store.put_render_bytes(next_path, b"0123456789")

    assert written_path == next_path
    assert store.used_bytes == _RECOVERY_PAYLOAD_SIZE
    assert (store.root / next_path).read_bytes() == b"0123456789"


def test_two_open_writers_deduplicate_at_commit(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    first = store.stage(suffix=".bin")
    second = store.stage(suffix=".bin")

    with first as first_staged, second as second_staged:
        _ = first_staged.write(b"same")
        _ = second_staged.write(b"same")
        first_artifact = first_staged.commit(
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )
        second_artifact = second_staged.commit(
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )

    assert first_artifact == second_artifact
    assert store.used_bytes == _SMALL_PAYLOAD_SIZE
    assert store.reserved_bytes == 0


def test_staged_commit_detects_existing_content_collision(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    writer = store.stage(suffix=".bin")
    with writer as staged:
        _ = staged.write(b"same")
        digest = sha256(b"same").hexdigest()
        destination = store.root / "documents" / f"doc_{digest}" / "source.bin"
        _mkdir_private(destination.parent, parents=True)
        _ = destination.write_bytes(b"evil")

        with pytest.raises(AppError) as raised:
            _ = staged.commit(
                namespace="documents",
                filename="source.bin",
                media_type="application/octet-stream",
            )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert store.reserved_bytes == 0


def test_staged_commit_rejects_missing_staged_identity(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    writer = store.stage(suffix=".bin")
    staged_path = _only_staged_path(store)

    with writer as staged:
        _ = staged.write(b"data")
        staged_path.unlink()
        with pytest.raises(AppError) as raised:
            _ = staged.commit(
                namespace="documents",
                filename="source.bin",
                media_type="application/octet-stream",
            )

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert store.reserved_bytes == 0


def test_staged_file_commit_rejects_identity_change_during_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    real_replace = Path.replace

    def replace_then_mutate(source: Path, target: Path | str) -> Path:
        published = real_replace(source, target)
        _ = Path(target).write_bytes(b"tampered")
        return published

    monkeypatch.setattr(Path, "replace", replace_then_mutate)

    with pytest.raises(AppError) as raised:
        _ = store.put_bytes(
            b"data",
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert not tuple((store.root / "documents").rglob("source.bin"))
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0


@pytest.mark.parametrize(
    "relative_subtree",
    [
        "",
        "renders",
        "documents/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/renders/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "renders/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/../other",
        "renders\\rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "renders/rnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00",
        "renders/not-a-render-id",
        f"renders/rnd_{'G' * 32}",
    ],
)
def test_render_subtree_operations_reject_invalid_paths(
    tmp_path: Path, relative_subtree: str
) -> None:
    store = ContentAddressedStore(tmp_path)

    with pytest.raises(AppError) as raised:
        _ = store.delete_render_subtree(relative_subtree)

    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_render_subtree_operation_rejects_symlinked_segment(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    victim = tmp_path / "victim"
    victim.mkdir()
    render_id = f"rnd_{'b' * 32}"
    (store.root / "renders" / render_id).symlink_to(victim, target_is_directory=True)

    with pytest.raises(AppError) as raised:
        _ = store.delete_render_subtree(f"renders/{render_id}/tiles")

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert victim.is_dir()


def test_delete_render_rejects_file_in_place_of_subtree(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    subtree = f"renders/rnd_{'c' * 32}"
    _ = (store.root / subtree).write_bytes(b"corrupt")

    with pytest.raises(AppError) as raised:
        _ = store.delete_render_subtree(subtree)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_delete_render_rejects_symlinked_child_directory(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    subtree = f"renders/rnd_{'d' * 32}"
    root = store.root / subtree
    root.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (root / "child").symlink_to(victim, target_is_directory=True)

    with pytest.raises(AppError) as raised:
        _ = store.delete_render_subtree(subtree)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert victim.is_dir()


def test_delete_render_rejects_non_regular_asset(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    subtree = f"renders/rnd_{'e' * 32}"
    root = store.root / subtree
    root.mkdir()
    os.mkfifo(root / "asset")

    with pytest.raises(AppError) as raised:
        _ = store.delete_render_subtree(subtree)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_delete_render_walks_multiple_regular_directories(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    subtree = f"renders/rnd_{'0' * 32}"
    root = store.root / subtree
    (root / "first").mkdir(parents=True)
    (root / "second").mkdir()
    _ = (root / "first" / "asset").write_bytes(b"one")
    _ = (root / "second" / "asset").write_bytes(b"two")

    assert store.delete_render_subtree(subtree) is True
    assert not root.exists()


def test_render_transaction_without_manifest_rolls_back_and_closes(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    subtree = f"renders/rnd_{'f' * 32}"
    transaction = store.begin_render_transaction(
        subtree, completion_file="manifest.json"
    )
    with transaction.stage(suffix=".jpg") as staged:
        _ = staged.write(b"page")
        _ = staged.commit_render(f"{subtree}/page.jpg")

    with pytest.raises(AppError) as raised:
        transaction.commit()

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert not (store.root / subtree).exists()
    with pytest.raises(RuntimeError, match="already closed"):
        transaction.commit()
    with pytest.raises(RuntimeError, match="already closed"):
        transaction.reset()


def test_complete_render_transaction_rollback_preserves_subtree(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path)
    subtree = f"renders/rnd_{'1' * 32}"
    _ = store.put_render_bytes(f"{subtree}/manifest.json", b"{}")
    transaction = store.begin_render_transaction(
        subtree, completion_file="manifest.json"
    )

    assert transaction.complete is True
    transaction.rollback()
    transaction.rollback()

    assert (store.root / subtree / "manifest.json").is_file()


def test_render_transaction_reset_rebuilds_completed_subtree(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    subtree = f"renders/rnd_{'2' * 32}"
    _ = store.put_render_bytes(f"{subtree}/manifest.json", b"old")
    transaction = store.begin_render_transaction(
        subtree, completion_file="manifest.json"
    )

    transaction.reset()
    assert transaction.complete is False
    assert not (store.root / subtree).exists()
    with transaction.stage(suffix=".json") as staged:
        _ = staged.write(b"new")
        _ = staged.commit_render(f"{subtree}/manifest.json")
    transaction.commit()

    assert (store.root / subtree / "manifest.json").read_bytes() == b"new"


def test_begin_render_transaction_releases_lock_after_corrupt_manifest(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    subtree = f"renders/rnd_{'3' * 32}"
    root = store.root / subtree
    root.mkdir()
    victim = tmp_path / "victim"
    _ = victim.write_bytes(b"safe")
    completion = root / "manifest.json"
    completion.symlink_to(victim)

    with pytest.raises(AppError) as raised:
        _ = store.begin_render_transaction(subtree, completion_file="manifest.json")
    assert raised.value.code is ErrorCode.INTERNAL_ERROR

    completion.unlink()
    _ = completion.write_bytes(b"{}")

    def open_and_rollback() -> None:
        transaction = store.begin_render_transaction(
            subtree, completion_file="manifest.json"
        )
        transaction.rollback()

    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(open_and_rollback).result(timeout=2)


def test_render_asset_deduplicates_and_detects_collision(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    relative_path = f"renders/rnd_{'4' * 32}/page.jpg"

    first = store.put_render_bytes(relative_path, b"same")
    second = store.put_render_bytes(relative_path, b"same")

    assert first == second
    assert store.used_bytes == _SMALL_PAYLOAD_SIZE

    with pytest.raises(AppError) as raised:
        _ = store.put_render_bytes(relative_path, b"different")

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert store.used_bytes == _SMALL_PAYLOAD_SIZE
    assert store.reserved_bytes == 0


@pytest.mark.parametrize(
    "relative_path",
    [
        "",
        "documents/file.jpg",
        "/renders/file.jpg",
        "renders/../file.jpg",
        "renders\\file.jpg",
        "renders/file.jpg\x00",
    ],
)
def test_render_publish_rejects_invalid_asset_paths(
    tmp_path: Path, relative_path: str
) -> None:
    store = ContentAddressedStore(tmp_path)

    with pytest.raises(AppError) as raised:
        _ = store.put_render_bytes(relative_path, b"image")

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert store.reserved_bytes == 0


def test_render_publish_rejects_parent_symlink_escape(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    outside = tmp_path / "outside"
    _mkdir_private(outside)
    render_id = f"rnd_{'5' * 32}"
    render = store.root / "renders" / render_id
    _mkdir_private(render)
    (render / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(AppError) as raised:
        _ = store.put_render_bytes(f"renders/{render_id}/escape/page.jpg", b"image")

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert not (outside / "page.jpg").exists()
    assert store.reserved_bytes == 0


def test_render_publish_rejects_symlink_destination(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    outside = tmp_path / "outside.jpg"
    _ = outside.write_bytes(b"safe")
    relative_path = f"renders/rnd_{'6' * 32}/page.jpg"
    destination = store.root / relative_path
    destination.parent.mkdir()
    destination.symlink_to(outside)

    with pytest.raises(AppError) as raised:
        _ = store.put_render_bytes(relative_path, b"image")

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert outside.read_bytes() == b"safe"
    assert store.reserved_bytes == 0


def test_render_commit_rejects_identity_change_during_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    real_replace = Path.replace

    def replace_then_mutate(source: Path, target: Path | str) -> Path:
        published = real_replace(source, target)
        _ = Path(target).write_bytes(b"tampered")
        return published

    monkeypatch.setattr(Path, "replace", replace_then_mutate)
    relative_path = f"renders/rnd_{'7' * 32}/page.jpg"

    with pytest.raises(AppError) as raised:
        _ = store.put_render_bytes(relative_path, b"image")

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert not (store.root / relative_path).exists()
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0


@pytest.mark.parametrize(
    "relative_path",
    [
        "",
        "documents\\file",
        "documents/file\x00",
        "/documents/file",
        "documents/../file",
    ],
)
def test_resolve_asset_rejects_invalid_path_forms(
    tmp_path: Path, relative_path: str
) -> None:
    store = ContentAddressedStore(tmp_path)

    with pytest.raises(AppError) as raised:
        _ = store.resolve_asset(relative_path)

    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_resolve_asset_rejects_unapproved_missing_and_escaping_paths(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")

    with pytest.raises(AppError) as unapproved:
        _ = store.resolve_asset("other/file")
    assert unapproved.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(AppError) as missing:
        _ = store.resolve_asset("documents/missing")
    assert missing.value.code is ErrorCode.NOT_FOUND

    outside = tmp_path / "outside"
    _ = outside.write_bytes(b"secret")
    (store.root / "documents" / "escape").symlink_to(outside)
    with pytest.raises(AppError) as escaping:
        _ = store.resolve_asset("documents/escape")
    assert escaping.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize("link_kind", ["final", "intermediate"])
def test_resolve_asset_rejects_same_root_symlink_aliases(
    tmp_path: Path,
    link_kind: str,
) -> None:
    store = ContentAddressedStore(tmp_path)
    first = store.put_bytes(
        b"first",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    second = store.put_bytes(
        b"second",
        namespace="documents",
        filename="source.bin",
        media_type="application/octet-stream",
    )
    if link_kind == "final":
        first.absolute_path.unlink()
        first.absolute_path.symlink_to(second.absolute_path)
        relative_path = first.relative_path
    else:
        alias = store.root / "documents" / "doc_alias"
        alias.symlink_to(second.absolute_path.parent, target_is_directory=True)
        relative_path = f"documents/{alias.name}/{second.absolute_path.name}"

    with pytest.raises(AppError) as raised:
        _ = store.resolve_asset(relative_path)

    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize("entry_kind", ["directory-symlink", "fifo"])
def test_existing_byte_scan_rejects_symlinked_directories_and_special_files(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    root = tmp_path / "cache"
    documents = root / "documents"
    _mkdir_private(documents, parents=True)
    _write_private(documents / "first", b"one")
    _write_private(documents / "second", b"two")
    outside = tmp_path / "outside"
    _mkdir_private(outside)
    _write_private(outside / "large", b"not-counted")
    unsafe_entry = documents / entry_kind
    if entry_kind == "directory-symlink":
        unsafe_entry.symlink_to(outside, target_is_directory=True)
    else:
        os.mkfifo(unsafe_entry, mode=0o600)

    with pytest.raises(ValueError, match="pre-existing artifact tree"):
        _ = ContentAddressedStore(root)

    assert (outside / "large").read_bytes() == b"not-counted"
    assert unsafe_entry.exists() or unsafe_entry.is_symlink()
