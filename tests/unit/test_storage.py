# Copyright (c) 2026 David Osipov
"""Unit tests for content-addressed storage."""

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO, Never, Protocol, cast

import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.storage import ContentAddressedStore, StoredArtifact

_SMALL_PAYLOAD_SIZE = 4
_QUOTA_BYTES = 8


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


def test_startup_discards_abandoned_staging_without_following_symlinks(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".staging"
    staging.mkdir(parents=True)
    abandoned = staging / "stage-abandoned.bin"
    _ = abandoned.write_bytes(b"1234")
    victim = tmp_path / "victim"
    _ = victim.write_bytes(b"safe")
    link = staging / "stage-link.bin"
    link.symlink_to(victim)

    store = ContentAddressedStore(tmp_path, max_bytes=_SMALL_PAYLOAD_SIZE)

    assert not abandoned.exists()
    assert not link.exists()
    assert victim.read_bytes() == b"safe"
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
    incomplete_render.mkdir(parents=True)
    _ = (incomplete_render / "page-0001.jpg").write_bytes(b"orphan-page")

    complete_render = renders / f"rnd_{'b' * 32}"
    complete_render.mkdir()
    _ = (complete_render / "page-0001.jpg").write_bytes(b"page")
    _ = (complete_render / "manifest.json").write_bytes(b"{}")
    incomplete_tiles = complete_render / "tiles" / "page-0001" / "w2048-h2048-o128"
    incomplete_tiles.mkdir(parents=True)
    _ = (incomplete_tiles / "tile.jpg").write_bytes(b"orphan-tile")

    store = ContentAddressedStore(tmp_path)

    assert not incomplete_render.exists()
    assert not incomplete_tiles.exists()
    assert (complete_render / "page-0001.jpg").is_file()
    assert (complete_render / "manifest.json").is_file()
    assert store.used_bytes == len(b"page{}")


def test_startup_unlinks_dangling_render_tiles_symlink(tmp_path: Path) -> None:
    render = tmp_path / "renders" / f"rnd_{'c' * 32}"
    render.mkdir(parents=True)
    _ = (render / "manifest.json").write_bytes(b"{}")
    tiles = render / "tiles"
    tiles.symlink_to(tmp_path / "missing-target", target_is_directory=True)

    store = ContentAddressedStore(tmp_path)

    assert not tiles.is_symlink()
    assert store.used_bytes == len(b"{}")


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


@pytest.mark.parametrize("namespace", ["documents", "renders"])
def test_store_rejects_symlinked_cache_directories(
    tmp_path: Path, namespace: str
) -> None:
    root = tmp_path / "cache"
    target = tmp_path / "target"
    target.mkdir()
    root.mkdir()
    (root / namespace).symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="namespace"):
        _ = ContentAddressedStore(root)

    assert target.is_dir()


def test_store_rejects_symlinked_staging_directory(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    target = tmp_path / "target"
    target.mkdir()
    root.mkdir()
    (root / ".staging").symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="staging"):
        _ = ContentAddressedStore(root)

    assert target.is_dir()


def test_startup_discards_stale_staging_directories(tmp_path: Path) -> None:
    stale = tmp_path / ".staging" / "stage-abandoned"
    stale.mkdir(parents=True)
    _ = (stale / "payload").write_bytes(b"abandoned")

    store = ContentAddressedStore(tmp_path)

    assert not stale.exists()
    assert store.used_bytes == 0


def test_startup_ignores_non_render_names_and_removes_render_symlinks(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    renders = root / "renders"
    renders.mkdir(parents=True)
    unrelated = renders / "notes"
    unrelated.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    render_link = renders / f"rnd_{'d' * 32}"
    render_link.symlink_to(victim, target_is_directory=True)

    store = ContentAddressedStore(root)

    assert unrelated.is_dir()
    assert not render_link.exists()
    assert victim.is_dir()
    assert store.used_bytes == 0


def test_startup_removes_symlinked_completion_manifest(tmp_path: Path) -> None:
    render = tmp_path / "renders" / f"rnd_{'e' * 32}"
    render.mkdir(parents=True)
    victim = tmp_path / "victim"
    _ = victim.write_bytes(b"safe")
    (render / "manifest.json").symlink_to(victim)

    store = ContentAddressedStore(tmp_path)

    assert not render.exists()
    assert victim.read_bytes() == b"safe"
    assert store.used_bytes == 0


def test_startup_preserves_completed_render_without_tiles(tmp_path: Path) -> None:
    render = tmp_path / "renders" / f"rnd_{'f' * 32}"
    render.mkdir(parents=True)
    _ = (render / "manifest.json").write_bytes(b"{}")

    store = ContentAddressedStore(tmp_path)

    assert (render / "manifest.json").is_file()
    assert store.used_bytes == len(b"{}")


def test_startup_cleans_invalid_tile_pages_and_geometries(tmp_path: Path) -> None:
    render = tmp_path / "renders" / f"rnd_{'a' * 32}"
    tiles = render / "tiles"
    tiles.mkdir(parents=True)
    _ = (render / "manifest.json").write_bytes(b"{}")
    victim = tmp_path / "victim"
    victim.mkdir()
    (tiles / "page-symlink").symlink_to(victim, target_is_directory=True)
    _ = (tiles / "page-file").write_bytes(b"invalid")
    page = tiles / "page-0001"
    page.mkdir()
    _ = (page / "geometry-file").write_bytes(b"invalid")
    (page / "geometry-link").symlink_to(victim, target_is_directory=True)
    (page / "geometry-incomplete").mkdir()
    complete = page / "geometry-complete"
    complete.mkdir()
    _ = (complete / "manifest.json").write_bytes(b"{}")

    store = ContentAddressedStore(tmp_path)

    assert not (tiles / "page-symlink").exists()
    assert not (tiles / "page-file").exists()
    assert not (page / "geometry-file").exists()
    assert not (page / "geometry-link").exists()
    assert not (page / "geometry-incomplete").exists()
    assert (complete / "manifest.json").is_file()
    assert victim.is_dir()
    assert store.used_bytes == len(b"{}{}")


def test_directory_fsync_failure_does_not_undo_atomic_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    real_open = os.open

    def reject_directory_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        if Path(os.fsdecode(path)).is_dir():
            msg = "directory fsync unsupported"
            raise OSError(msg)
        return real_open(path, flags, mode)

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


def test_stage_works_when_nofollow_flag_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ContentAddressedStore(tmp_path)
    monkeypatch.delattr(os, "O_NOFOLLOW")

    with store.stage(suffix=".bin") as staged:
        assert staged.write(b"x") == 1

    assert store.reserved_bytes == 0


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
        destination.parent.mkdir(parents=True)
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
    _ = store.put_render_bytes(f"{subtree}/page.jpg", b"page")

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
    _ = store.put_render_bytes(f"{subtree}/manifest.json", b"new")
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
    outside.mkdir()
    render_id = f"rnd_{'5' * 32}"
    render = store.root / "renders" / render_id
    render.mkdir()
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


def test_existing_byte_scan_ignores_symlinked_directories_and_special_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache"
    documents = root / "documents"
    documents.mkdir(parents=True)
    _ = (documents / "first").write_bytes(b"one")
    _ = (documents / "second").write_bytes(b"two")
    os.mkfifo(documents / "pipe")
    outside = tmp_path / "outside"
    outside.mkdir()
    _ = (outside / "large").write_bytes(b"not-counted")
    (documents / "linked-directory").symlink_to(outside, target_is_directory=True)

    store = ContentAddressedStore(root)

    assert store.used_bytes == len(b"onetwo")
