import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.storage import ContentAddressedStore


def test_content_addressed_store_is_deterministic_atomic_and_deduplicated(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)

    first = store.put_bytes(b"%PDF-1.7\nfirst", namespace="documents", filename="source.pdf", media_type="application/pdf")
    second = store.put_bytes(b"%PDF-1.7\nfirst", namespace="documents", filename="source.pdf", media_type="application/pdf")

    assert first == second
    assert first.object_id.startswith("doc_")
    assert first.sha256 == "eb23680cd6b2852b2cf8cbbb6ca2e03d4a4b7e9784c4c16d0acea2c3640e40dd"
    assert first.relative_path == f"documents/{first.object_id}/source.pdf"
    assert first.absolute_path.read_bytes() == b"%PDF-1.7\nfirst"
    assert list((tmp_path / ".staging").iterdir()) == []


def test_same_content_with_different_filename_keeps_one_object_directory(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    first = store.put_bytes(b"same", namespace="documents", filename="source.pdf", media_type="application/pdf")
    second = store.put_bytes(b"same", namespace="documents", filename="original.pdf", media_type="application/pdf")

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
def test_store_rejects_traversal_and_unapproved_namespaces(tmp_path: Path, namespace: str, filename: str) -> None:
    store = ContentAddressedStore(tmp_path)
    with pytest.raises(AppError) as raised:
        store.put_bytes(b"x", namespace=namespace, filename=filename, media_type="application/octet-stream")
    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_resolve_asset_cannot_escape_root(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(b"jpeg", namespace="renders", filename="page-0001.jpg", media_type="image/jpeg")

    assert store.resolve_asset(artifact.relative_path) == artifact.absolute_path
    with pytest.raises(AppError) as raised:
        store.resolve_asset("renders/../../etc/passwd")
    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_import_file_removes_staging_file_after_commit(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    with store.stage(suffix=".pdf") as staged:
        staged.write(b"%PDF-1.4\nbody")
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
    store.put_bytes(b"same", namespace="documents", filename="source.pdf", media_type="application/pdf")

    def forbidden_read_bytes(self: Path) -> bytes:
        raise AssertionError(f"read_bytes must not buffer the whole artifact: {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    duplicate = store.put_bytes(b"same", namespace="documents", filename="source.pdf", media_type="application/pdf")

    assert duplicate.size == 4


def test_cache_quota_rejects_new_bytes_without_exceeding_limit(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=8)
    store.put_bytes(b"12345678", namespace="documents", filename="source.pdf", media_type="application/pdf")

    with pytest.raises(AppError) as captured:
        store.put_bytes(b"x", namespace="renders", filename="page.jpg", media_type="image/jpeg")

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert store.used_bytes == 8
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) == 8
    assert list((tmp_path / ".staging").iterdir()) == []


def test_cache_quota_counts_existing_files_and_deduplication_once(tmp_path: Path) -> None:
    first = ContentAddressedStore(tmp_path, max_bytes=4)
    artifact = first.put_bytes(b"same", namespace="documents", filename="source.pdf", media_type="application/pdf")
    assert first.put_bytes(b"same", namespace="documents", filename="source.pdf", media_type="application/pdf") == artifact
    assert first.used_bytes == 4

    reopened = ContentAddressedStore(tmp_path, max_bytes=4)
    assert reopened.used_bytes == 4
    with pytest.raises(AppError) as captured:
        reopened.put_bytes(b"x", namespace="renders", filename="page.jpg", media_type="image/jpeg")
    assert captured.value.code is ErrorCode.CACHE_FULL


def test_cache_quota_reservation_is_thread_safe(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=8)

    def write(value: bytes) -> ErrorCode | None:
        try:
            store.put_bytes(value, namespace="documents", filename="source.pdf", media_type="application/pdf")
        except AppError as exc:
            return exc.code
        return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(write, (b"a" * 8, b"b" * 8)))

    assert sorted(outcome is None for outcome in outcomes) == [False, True]
    assert ErrorCode.CACHE_FULL in outcomes
    assert store.used_bytes == 8
    assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) == 8


def test_aborted_staged_writer_releases_reserved_capacity(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path, max_bytes=4)

    with pytest.raises(RuntimeError, match="abort"):
        with store.stage(suffix=".bin") as destination:
            destination.write(b"1234")
            raise RuntimeError("abort")

    assert store.used_bytes == 0
    assert store.reserved_bytes == 0
    assert list((tmp_path / ".staging").iterdir()) == []


def test_staged_commit_fsyncs_file_before_atomic_publish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
        staged.write(b"%PDF-1.4\nbody")
        artifact = staged.commit(
            namespace="documents",
            filename="source.pdf",
            media_type="application/pdf",
        )

    assert artifact.absolute_path.is_file()


def test_startup_discards_abandoned_staging_without_following_symlinks(tmp_path: Path) -> None:
    staging = tmp_path / ".staging"
    staging.mkdir(parents=True)
    abandoned = staging / "stage-abandoned.bin"
    abandoned.write_bytes(b"1234")
    victim = tmp_path / "victim"
    victim.write_bytes(b"safe")
    link = staging / "stage-link.bin"
    link.symlink_to(victim)

    store = ContentAddressedStore(tmp_path, max_bytes=4)

    assert not abandoned.exists()
    assert not link.exists()
    assert victim.read_bytes() == b"safe"
    assert store.used_bytes == 0
    assert store.put_bytes(
        b"1234",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    ).size == 4


def test_startup_discards_incomplete_render_and_tile_transactions(tmp_path: Path) -> None:
    renders = tmp_path / "renders"
    incomplete_render = renders / f"rnd_{'a' * 32}"
    incomplete_render.mkdir(parents=True)
    (incomplete_render / "page-0001.jpg").write_bytes(b"orphan-page")

    complete_render = renders / f"rnd_{'b' * 32}"
    complete_render.mkdir()
    (complete_render / "page-0001.jpg").write_bytes(b"page")
    (complete_render / "manifest.json").write_bytes(b"{}")
    incomplete_tiles = complete_render / "tiles" / "page-0001" / "w2048-h2048-o128"
    incomplete_tiles.mkdir(parents=True)
    (incomplete_tiles / "tile.jpg").write_bytes(b"orphan-tile")

    store = ContentAddressedStore(tmp_path)

    assert not incomplete_render.exists()
    assert not incomplete_tiles.exists()
    assert (complete_render / "page-0001.jpg").is_file()
    assert (complete_render / "manifest.json").is_file()
    assert store.used_bytes == len(b"page{}")


def test_startup_unlinks_dangling_render_tiles_symlink(tmp_path: Path) -> None:
    render = tmp_path / "renders" / f"rnd_{'c' * 32}"
    render.mkdir(parents=True)
    (render / "manifest.json").write_bytes(b"{}")
    tiles = render / "tiles"
    tiles.symlink_to(tmp_path / "missing-target", target_is_directory=True)

    store = ContentAddressedStore(tmp_path)

    assert not tiles.is_symlink()
    assert store.used_bytes == len(b"{}")


def test_staged_writer_retains_exclusive_descriptor_across_symlink_swap(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    victim = tmp_path / "victim"
    victim.write_bytes(b"safe")
    writer = store.stage(suffix=".bin")
    staged_path = writer._path
    staged_path.unlink()
    staged_path.symlink_to(victim)

    with writer as staged:
        staged.write(b"attacker-controlled")

    assert victim.read_bytes() == b"safe"
    assert not staged_path.exists()
    assert store.reserved_bytes == 0


def test_staged_commit_rejects_regular_file_identity_swap(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    writer = store.stage(suffix=".bin")
    staged_path = writer._path
    staged_path.unlink()
    staged_path.write_bytes(b"replacement")

    with pytest.raises(AppError) as captured:
        with writer as staged:
            staged.write(b"intended")
            staged.commit(
                namespace="documents",
                filename="source.bin",
                media_type="application/octet-stream",
            )

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert not list((store.root / "documents").rglob("source.bin"))
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0


def test_staged_commit_rejects_same_inode_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = ContentAddressedStore(tmp_path)
    real_fsync = os.fsync

    def mutate_after_sync(descriptor: int) -> None:
        real_fsync(descriptor)
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.pwrite(descriptor, b"evil", 0)

    monkeypatch.setattr(os, "fsync", mutate_after_sync)

    with pytest.raises(AppError) as captured:
        with store.stage(suffix=".bin") as staged:
            staged.write(b"good")
            staged.commit(
                namespace="documents",
                filename="source.bin",
                media_type="application/octet-stream",
            )

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert not list((store.root / "documents").rglob("source.bin"))
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0


def test_render_publish_fsyncs_destination_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    store.put_render_bytes(f"renders/rnd_{'a' * 32}/page-0001.jpg", b"jpeg")

    replace_index = events.index(("replace", None))
    assert any(kind == "fsync" and is_directory for kind, is_directory in events[replace_index + 1 :])
