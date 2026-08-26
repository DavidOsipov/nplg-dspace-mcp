# Copyright (c) 2026 David Osipov
"""Adversarial branch tests for the parent-side PDF worker client."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import socket
import stat
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Self, cast
from uuid import UUID

import pytest
from PIL import Image

from nplg_mcp import pdf_worker_client as subject
from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.pdf_executor import (
    PdfResourceLimits,
    PdfWorkerError,
    PdfWorkerOperationalError,
    PdfWorkerPolicy,
)
from nplg_mcp.pdf_identity import (
    PDF_PIPELINE_VERSIONS,
    TileGeometryRequest,
    tile_geometry_identifier,
)
from nplg_mcp.pdf_ipc import (
    MAX_RESULT_FRAME_BYTES,
    InspectCommand,
    InspectParams,
    ManifestCommand,
    ManifestParams,
    PdfCommand,
    PdfFailure,
    PdfResult,
    PdfSuccess,
    PublicWorkerError,
    RenderedPageOutput,
    RenderedTileOutput,
    RenderPagesCommand,
    RenderPagesOutput,
    RenderPagesParams,
    RenderPagesPayload,
    RenderTilesCommand,
    RenderTilesOutput,
    RenderTilesParams,
)
from nplg_mcp.pdf_worker_client import (
    SubprocessPdfExecutor,
    UnixSocketPdfExecutor,
    WorkerStagingBinding,
)
from nplg_mcp.pdf_worker_slot import (
    PdfWorkerSlotPolicy,
    WorkerSlotFilesystem,
    WorkerStagingQuota,
)
from nplg_mcp.storage import ContentAddressedStore

if TYPE_CHECKING:
    from asyncio import StreamReader, StreamWriter
    from collections.abc import Iterator
    from types import TracebackType

_SOURCE_SHA256 = "1" * 64
_PAGE_SHA256 = "2" * 64
_RENDER_ID = "rnd_" + "3" * 32
_OTHER_RENDER_ID = "rnd_" + "4" * 32
_REQUEST_ID = UUID("00000000-0000-4000-8000-000000000081")
_EXPECTED_TWO_CALLS = 2
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_PERMISSIVE_DIRECTORY_MODE = 0o755
_ABSOLUTE_NUL_SOCKET = Path.cwd() / "invalid\x00socket"


def _deadline(seconds: float = 5.0) -> MonotonicDeadline:
    return MonotonicDeadline.after(seconds, clock=time.monotonic)


def _inspect_command(*, request_id: UUID = _REQUEST_ID) -> InspectCommand:
    return InspectCommand(
        request_id=request_id,
        operation="inspect",
        source_relative_path=f"documents/doc_{_SOURCE_SHA256}/source.pdf",
        parameters=InspectParams(),
    )


def _render_command(*, request_id: UUID = _REQUEST_ID) -> RenderPagesCommand:
    return RenderPagesCommand(
        request_id=request_id,
        operation="render_pages",
        source_relative_path=f"documents/doc_{_SOURCE_SHA256}/source.pdf",
        parameters=RenderPagesParams(pages=(1,), mode="native"),
    )


def _render_output(
    *,
    render_id: str = _RENDER_ID,
    manifest_render_id: str | None = None,
    page_sha256: str = _PAGE_SHA256,
) -> RenderPagesOutput:
    manifest_identity = manifest_render_id or render_id
    return RenderPagesOutput(
        manifest_schema_version=PDF_PIPELINE_VERSIONS.manifest_schema_version,
        render_pipeline_version=PDF_PIPELINE_VERSIONS.render_pipeline_version,
        classification_algorithm_version=(
            PDF_PIPELINE_VERSIONS.classification_algorithm_version
        ),
        tile_pipeline_version=PDF_PIPELINE_VERSIONS.tile_pipeline_version,
        render_id=render_id,
        source_sha256=_SOURCE_SHA256,
        renderer_version="test-renderer/1",
        mode="native",
        pages=(
            RenderedPageOutput(
                page_number=1,
                width=120,
                height=80,
                rotation=0,
                classification="raster",
                effective_dpi_x=200.0,
                effective_dpi_y=200.0,
                resolution_source="embedded",
                conversion_path="native",
                relative_path=f"renders/{render_id}/page-0001.jpg",
                sha256=page_sha256,
                media_type="image/jpeg",
                resize_applied=False,
                pixel_dimensions_preserved=True,
                renderer_resampling="none",
                reencoded=True,
                lossy_conversion=True,
            ),
        ),
        manifest_relative_path=f"renders/{manifest_identity}/manifest.json",
    )


def _tile_output(
    *,
    page_sha256: str = _PAGE_SHA256,
    tile_x: int = 0,
    tile_page_number: int = 1,
    tile_overlap: int = 0,
) -> RenderTilesOutput:
    geometry = tile_geometry_identifier(
        TileGeometryRequest(width=256, height=256, overlap=0)
    )
    tile_id = f"p0001_{geometry}_x{tile_x:06d}_y000000"
    root = f"renders/{_RENDER_ID}/tiles/page-0001/{geometry}"
    return RenderTilesOutput(
        manifest_schema_version=PDF_PIPELINE_VERSIONS.manifest_schema_version,
        render_pipeline_version=PDF_PIPELINE_VERSIONS.render_pipeline_version,
        classification_algorithm_version=(
            PDF_PIPELINE_VERSIONS.classification_algorithm_version
        ),
        tile_pipeline_version=PDF_PIPELINE_VERSIONS.tile_pipeline_version,
        render_id=_RENDER_ID,
        page_number=1,
        page_sha256=page_sha256,
        tile_width=256,
        tile_height=256,
        overlap=0,
        tiles=(
            RenderedTileOutput(
                tile_id=tile_id,
                page_number=tile_page_number,
                x=tile_x,
                y=0,
                width=120,
                height=80,
                full_page_width=120,
                full_page_height=80,
                overlap=tile_overlap,
                relative_path=f"{root}/{tile_id}.jpg",
                sha256="5" * 64,
                media_type="image/jpeg",
                resize_applied=False,
                pixel_dimensions_preserved=True,
                renderer_resampling="none",
                reencoded=True,
                lossy_conversion=True,
            ),
        ),
        manifest_relative_path=f"{root}/manifest.json",
    )


def _write_render_manifest(job_path: Path, manifest: RenderPagesOutput) -> None:
    path = job_path / "cache" / manifest.manifest_relative_path
    path.parent.mkdir(parents=True, mode=0o700)
    _ = path.write_text(manifest.model_dump_json(), encoding="utf-8")
    path.chmod(0o600)


def _healthy_filesystem() -> WorkerSlotFilesystem:
    return WorkerSlotFilesystem(
        filesystem_type="ext4",
        mount_options=frozenset({"rw", "nodev", "nosuid", "noexec"}),
        total_bytes=1_073_741_824,
        available_bytes=805_306_368,
        total_inodes=65_536,
        available_inodes=32_768,
    )


class _HealthyInspector:
    def __init__(self, root: Path) -> None:
        super().__init__()
        self._root = root

    def inspect(self, root: Path) -> WorkerSlotFilesystem:
        assert root == self._root
        return _healthy_filesystem()


def _quota(root: Path) -> WorkerStagingQuota:
    payload: dict[str, object] = {
        "version": 1,
        "root": str(root),
        "filesystem_type": "ext4",
        "maximum_total_bytes": 1_073_741_824,
        "minimum_available_bytes": 805_306_368,
        "maximum_total_inodes": 65_536,
        "minimum_available_inodes": 32_768,
        "mount_options": ["rw", "nodev", "nosuid", "noexec"],
        "concurrency": 1,
    }
    policy = PdfWorkerSlotPolicy.model_validate(payload, strict=True)
    return WorkerStagingQuota(policy=policy, inspector=_HealthyInspector(root))


class _RejectingAssetLease:
    def __enter__(self) -> Path:
        raise AppError(ErrorCode.INTERNAL_ERROR, "test-controlled lease failure")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback


class _ShortDestinationWriter:
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback

    @staticmethod
    def write(data: bytes) -> int:
        return len(data) - 1

    @staticmethod
    def flush() -> None:
        pytest.fail("a short worker-input write must fail before flush")

    @staticmethod
    def fileno() -> int:
        pytest.fail("a short worker-input write must fail before fsync")


class _ShortStagedWriter:
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback

    def write(self, data: bytes) -> int:
        del self
        return len(data) - 1

    def commit_render(self, relative_path: str) -> tuple[str, str]:
        del self, relative_path
        pytest.fail("a short publication write must not commit")


class _FakeUnixPeer:
    def __init__(
        self,
        credentials: bytes,
        *,
        family: socket.AddressFamily = socket.AF_UNIX,
    ) -> None:
        super().__init__()
        self.family = family
        self._credentials = credentials

    def getsockopt(self, level: int, option: int, buffer_size: int) -> bytes:
        assert (level, option, buffer_size) == (
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            12,
        )
        return self._credentials


class _FakeUnixWriter:
    def __init__(self, peer: object) -> None:
        super().__init__()
        self._peer = peer
        self.closed = False

    def get_extra_info(self, name: str, default: object | None = None) -> object:
        assert name == "socket"
        del default
        return self._peer

    @staticmethod
    def write(_data: bytes) -> None:
        pytest.fail("an unauthenticated peer must not receive a request")

    @staticmethod
    async def drain() -> None:
        pytest.fail("an unauthenticated peer must not be drained")

    @staticmethod
    def write_eof() -> None:
        pytest.fail("an unauthenticated peer must not receive EOF")

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        assert self.closed is True


def _peer_record(*, user_id: int) -> bytes:
    return b"".join(
        value.to_bytes(4, byteorder=sys.byteorder, signed=True)
        for value in (123, user_id, 456)
    )


def _bind_private_socket(path: Path) -> socket.socket:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    path.chmod(0o600)
    return listener


def test_private_worker_directory_rejects_existing_request_component(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir(mode=0o700)

    with pytest.raises(PdfWorkerError, match="already exists"):
        subject._ensure_private_worker_directory(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            existing,
            allow_existing=False,
        )


def test_job_tree_cleanup_tolerates_both_disappearance_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    SubprocessPdfExecutor._remove_job_tree(tmp_path / "already-gone")  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    job_path = tmp_path / "disappearing"
    job_path.mkdir(mode=0o700)
    calls = 0

    def disappearing_rmtree(_path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PermissionError
        raise FileNotFoundError

    monkeypatch.setattr(shutil, "rmtree", disappearing_rmtree)

    SubprocessPdfExecutor._remove_job_tree(job_path)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001

    assert calls == _EXPECTED_TWO_CALLS


def test_permission_recovery_rejects_a_non_directory_job_path(tmp_path: Path) -> None:
    job_path = tmp_path / "job"
    _ = job_path.write_bytes(b"not-a-directory")

    with pytest.raises(OSError, match="not a private directory"):
        SubprocessPdfExecutor._restore_job_tree_permissions(job_path)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001


def test_permission_recovery_ignores_vanished_and_symlinked_children(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job_path = tmp_path / "job"
    job_path.mkdir(mode=0o700)
    real_child = job_path / "real"
    real_child.mkdir(mode=0o755)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    (job_path / "linked").symlink_to(outside, target_is_directory=True)

    def controlled_walk(
        root: Path,
        *,
        topdown: bool,
        followlinks: bool,
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        assert root == job_path
        assert topdown is True
        assert followlinks is False
        yield str(job_path), ["vanished", "real", "linked"], []

    monkeypatch.setattr(os, "walk", controlled_walk)

    SubprocessPdfExecutor._restore_job_tree_permissions(job_path)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001

    assert stat.S_IMODE(real_child.stat().st_mode) == _PRIVATE_DIRECTORY_MODE
    assert stat.S_IMODE(outside.stat().st_mode) == _PERMISSIVE_DIRECTORY_MODE


def test_stage_inputs_preserves_nonavailability_application_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    job_path = tmp_path / "job"
    job_path.mkdir(mode=0o700)

    def reject_lease(_relative_path: str) -> _RejectingAssetLease:
        return _RejectingAssetLease()

    monkeypatch.setattr(store, "lease_asset", reject_lease)

    with pytest.raises(AppError) as raised:
        _ = executor._stage_inputs(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            ManifestCommand(
                request_id=_REQUEST_ID,
                operation="manifest",
                parameters=ManifestParams(render_id=_RENDER_ID),
            ),
            job_path,
            deadline=_deadline(),
        )

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_tree_diagnosis_completes_for_regular_files(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    render_root = tmp_path / "render"
    nested = render_root / "nested"
    nested.mkdir(parents=True)
    _ = (render_root / "manifest.json").write_bytes(b"{}")
    _ = (nested / "page.jpg").write_bytes(b"jpeg")

    executor._diagnose_unavailable_render_tree(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        render_root,
        deadline=_deadline(),
    )


def test_render_tree_diagnosis_tolerates_a_file_disappearing_mid_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    render_root = tmp_path / "render"
    render_root.mkdir()

    def vanished_file_walk(
        root: Path,
        *,
        followlinks: bool,
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        assert root == render_root
        assert followlinks is False
        yield str(render_root), [], ["vanished.jpg"]

    monkeypatch.setattr(os, "walk", vanished_file_walk)

    executor._diagnose_unavailable_render_tree(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        render_root,
        deadline=_deadline(),
    )


def test_input_copy_rejects_a_non_regular_source(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    source = tmp_path / "directory"
    source.mkdir()

    with pytest.raises(PdfWorkerError, match="not a regular file"):
        _ = executor._copy_regular_file(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            source,
            tmp_path / "copy",
            deadline=_deadline(),
        )


def test_input_copy_rejects_a_short_destination_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    source = tmp_path / "source.pdf"
    _ = source.write_bytes(b"worker input")
    destination = tmp_path / "copy.pdf"

    def short_open(_path: Path, mode: str) -> _ShortDestinationWriter:
        assert mode == "xb"
        return _ShortDestinationWriter()

    monkeypatch.setattr(Path, "open", short_open)

    with pytest.raises(PdfWorkerError, match="staging was incomplete"):
        _ = executor._copy_regular_file(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            source,
            destination,
            deadline=_deadline(),
        )


def test_input_copy_uses_the_portable_descriptor_path_without_no_follow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    source = tmp_path / "source.pdf"
    data = b"portable worker input"
    _ = source.write_bytes(data)
    destination = tmp_path / "copy.pdf"

    with monkeypatch.context() as patch:
        patch.delattr(os, "O_NOFOLLOW")
        digest = executor._copy_regular_file(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            source,
            destination,
            deadline=_deadline(),
        )

    assert digest == hashlib.sha256(data).hexdigest()
    assert destination.read_bytes() == data
    assert stat.S_IMODE(destination.stat().st_mode) == _PRIVATE_FILE_MODE


def test_render_tree_copy_rejects_an_unavailable_source(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    source = tmp_path / "not-a-tree"
    _ = source.write_bytes(b"not a directory")

    with pytest.raises(PdfWorkerError, match="render input is unavailable"):
        executor._copy_regular_tree(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            source,
            tmp_path / "destination",
            deadline=_deadline(),
        )


def test_render_tree_copy_rejects_a_symlinked_child_directory(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (source / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PdfWorkerError, match="contains a symlink"):
        executor._copy_regular_tree(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            source,
            tmp_path / "destination",
            deadline=_deadline(),
        )


@pytest.mark.asyncio
async def test_process_group_survival_after_kill_is_operational_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(
        store=store,
        policy=PdfWorkerPolicy(
            resources=PdfResourceLimits(termination_grace_seconds=0.001)
        ),
    )

    def surviving_group(_process_group: int, sent_signal: int) -> None:
        assert sent_signal == 0

    monkeypatch.setattr(os, "killpg", surviving_group)

    with pytest.raises(PdfWorkerOperationalError, match="survived termination"):
        await executor._wait_for_process_group_exit(123_456)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001


def test_render_result_requires_parent_staged_source_identity(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    command = _render_command()
    result = PdfSuccess(
        request_id=command.request_id,
        status="ok",
        payload=RenderPagesPayload(
            operation="render_pages",
            value=_render_output(),
        ),
    )

    with pytest.raises(PdfWorkerError, match="source identity is unavailable"):
        executor._validate_result_binding(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            command,
            result,
            expected_source_sha256=None,
            job_path=tmp_path / "job",
            deadline=_deadline(),
        )


def test_output_descriptor_uses_the_portable_path_without_no_follow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    job_path = tmp_path / "job"
    relative_path = f"renders/{_RENDER_ID}/page.jpg"
    output_path = job_path / "cache" / relative_path
    output_path.parent.mkdir(parents=True)
    _ = output_path.write_bytes(b"worker output")

    with monkeypatch.context() as patch:
        patch.delattr(os, "O_NOFOLLOW")
        descriptor = executor._validated_descriptor(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            job_path,
            relative_path,
        )
    try:
        assert os.read(descriptor, 64) == b"worker output"
    finally:
        os.close(descriptor)


def test_output_validation_rechecks_dimensions_after_image_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    job_path = tmp_path / "job"
    output_path = job_path / "cache" / "renders" / _RENDER_ID / "page.jpg"
    output_path.parent.mkdir(parents=True)
    body = b"test-controlled image body"
    _ = output_path.write_bytes(body)
    calls = 0

    def sequenced_image(_stream: object) -> Image.Image:
        nonlocal calls
        calls += 1
        dimensions = (1, 1) if calls == 1 else (2, 1)
        image = Image.new("RGB", dimensions, "white")
        image.format = "JPEG"
        return image

    monkeypatch.setattr(Image, "open", sequenced_image)

    with pytest.raises(PdfWorkerError, match="dimensions are invalid"):
        executor._validate_output_file(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            job_path,
            f"renders/{_RENDER_ID}/page.jpg",
            expected_sha256=hashlib.sha256(body).hexdigest(),
            expected_dimensions=(1, 1),
            deadline=_deadline(),
        )

    assert calls == _EXPECTED_TWO_CALLS


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"{", "source manifest is invalid"),
        (b"x" * (MAX_RESULT_FRAME_BYTES + 1), "source manifest exceeded"),
    ],
    ids=("invalid-json", "oversized-json"),
)
def test_staged_render_manifest_rejects_invalid_or_oversized_json(
    tmp_path: Path,
    body: bytes,
    message: str,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    job_path = tmp_path / "job"
    manifest_path = job_path / "cache" / "renders" / _RENDER_ID / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    _ = manifest_path.write_bytes(body)

    with pytest.raises(PdfWorkerError, match=message):
        _ = executor._load_staged_render_manifest(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            job_path,
            _RENDER_ID,
            deadline=_deadline(),
        )


def test_staged_render_manifest_rejects_a_cross_wired_identity(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    job_path = tmp_path / "job"
    manifest = _render_output(
        render_id=_OTHER_RENDER_ID,
        manifest_render_id=_RENDER_ID,
    )
    _write_render_manifest(job_path, manifest)

    with pytest.raises(PdfWorkerError, match="identity mismatch"):
        _ = executor._load_staged_render_manifest(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            job_path,
            _RENDER_ID,
            deadline=_deadline(),
        )


@pytest.mark.parametrize(
    ("rendered", "message"),
    [
        (_tile_output(page_sha256="6" * 64), "source page mismatch"),
        (_tile_output(tile_x=1), "tile metadata mismatch"),
    ],
)
def test_tile_binding_rejects_cross_wired_source_and_grid_metadata(
    tmp_path: Path,
    rendered: RenderTilesOutput,
    message: str,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    job_path = tmp_path / "job"
    _write_render_manifest(job_path, _render_output())
    command = RenderTilesCommand(
        request_id=_REQUEST_ID,
        operation="render_tiles",
        parameters=RenderTilesParams(
            render_id=_RENDER_ID,
            page_number=1,
            tile_width=256,
            tile_height=256,
            overlap=0,
        ),
    )

    with pytest.raises(PdfWorkerError, match=message):
        executor._validate_tile_result_binding(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            command,
            rendered,
            job_path,
            deadline=_deadline(),
        )


def test_authoritative_comparison_returns_false_for_a_missing_asset(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)

    assert (
        executor._authoritative_matches(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            tmp_path / "job",
            {f"renders/{_RENDER_ID}/missing.jpg"},
            deadline=_deadline(),
        )
        is False
    )


def test_publication_rejects_a_short_staged_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    executor = SubprocessPdfExecutor(store=store)
    job_path = tmp_path / "job"
    relative_path = f"renders/{_RENDER_ID}/page.jpg"
    output_path = job_path / "cache" / relative_path
    output_path.parent.mkdir(parents=True)
    body = b"verified worker output"
    _ = output_path.write_bytes(body)
    transaction = store.begin_render_transaction(
        f"renders/{_RENDER_ID}",
        completion_file="manifest.json",
    )

    def short_stage(*, suffix: str = "") -> _ShortStagedWriter:
        assert suffix == ".jpg"
        return _ShortStagedWriter()

    monkeypatch.setattr(transaction, "stage", short_stage)

    try:
        with pytest.raises(PdfWorkerError, match="publication was incomplete"):
            executor._publish_one(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
                job_path,
                relative_path,
                transaction=transaction,
                expected_sha256=hashlib.sha256(body).hexdigest(),
                deadline=_deadline(),
            )
    finally:
        transaction.rollback()


@pytest.mark.parametrize("root", [Path("relative"), Path("invalid\x00root")])
def test_worker_staging_binding_rejects_nonabsolute_or_nul_roots(root: Path) -> None:
    with pytest.raises(ValueError, match="staging root is invalid"):
        _ = WorkerStagingBinding(root=root)


def test_worker_staging_binding_rejects_a_mismatched_quota_root(
    tmp_path: Path,
) -> None:
    quota_root = tmp_path / "quota"
    quota_root.mkdir(mode=0o700)

    with pytest.raises(ValueError, match="does not bind"):
        _ = WorkerStagingBinding(root=tmp_path / "other", quota=_quota(quota_root))


@pytest.mark.parametrize(
    "socket_path",
    [Path("relative.sock"), _ABSOLUTE_NUL_SOCKET],
)
def test_unix_executor_rejects_nonabsolute_or_nul_socket_paths(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")

    with pytest.raises(ValueError, match="socket path is invalid"):
        _ = UnixSocketPdfExecutor(store=store, socket_path=socket_path)


def test_unix_work_parent_rejects_a_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(PdfWorkerError, match="not a private directory"):
        UnixSocketPdfExecutor._prepare_work_parent(linked)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001


@pytest.mark.asyncio
async def test_unix_executor_uses_and_releases_a_healthy_quota_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = tmp_path / "slot"
    slot.mkdir(mode=0o700)
    quota = _quota(slot)
    store = ContentAddressedStore(tmp_path / "cache")
    executor = UnixSocketPdfExecutor(
        store=store,
        socket_path=tmp_path / "worker.sock",
        staging=WorkerStagingBinding(root=slot, quota=quota),
    )
    command = _inspect_command()
    expected = PdfFailure(
        request_id=command.request_id,
        status="error",
        operation="inspect",
        payload=PublicWorkerError(
            code=ErrorCode.INVALID_DOCUMENT,
            message="test-controlled failure",
        ),
    )
    observed_work_root: Path | None = None

    async def execute_in_root(
        _command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
        work_parent: Path,
    ) -> PdfResult:
        nonlocal observed_work_root
        assert deadline.remaining(now=time.monotonic()) > 0
        observed_work_root = work_parent
        return expected

    monkeypatch.setattr(executor, "_execute_in_work_root", execute_in_root)

    result = await executor._execute_with_permit(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        command,
        deadline=_deadline(),
    )

    assert result == expected
    assert observed_work_root == slot
    with quota.lease() as released_root:
        assert released_root.path == slot


@pytest.mark.asyncio
async def test_unix_executor_rejects_a_reused_request_identifier(
    tmp_path: Path,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nrequest-reuse",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    command = InspectCommand(
        request_id=_REQUEST_ID,
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )
    work_parent = store.root / ".pdf-worker-jobs"
    work_parent.mkdir(mode=0o700)
    (work_parent / command.request_id.hex).mkdir(mode=0o700)
    executor = UnixSocketPdfExecutor(
        store=store,
        socket_path=tmp_path / "worker.sock",
    )

    with pytest.raises(PdfWorkerOperationalError, match="identifier was reused"):
        _ = await executor.execute(command, deadline=_deadline())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "message"),
    [(TimeoutError(), "exceeded its deadline"), (OSError(), "transport failed")],
)
async def test_unix_transport_failures_are_typed_and_clean_the_job_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    message: str,
) -> None:
    store = ContentAddressedStore(tmp_path / message.replace(" ", "-"))
    artifact = store.put_bytes(
        b"%PDF-1.7\ntransport-failure",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    command = InspectCommand(
        request_id=_REQUEST_ID,
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )
    executor = UnixSocketPdfExecutor(
        store=store,
        socket_path=tmp_path / "worker.sock",
    )

    async def failed_exchange(_command: PdfCommand) -> PdfResult:
        raise failure

    monkeypatch.setattr(executor, "_exchange_unix", failed_exchange)

    with pytest.raises(PdfWorkerOperationalError, match=message):
        _ = await executor.execute(command, deadline=_deadline())

    assert list((store.root / ".pdf-worker-jobs").iterdir()) == []


@pytest.mark.asyncio
async def test_unix_transport_cancellation_propagates_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\ncancelled-transport",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    command = InspectCommand(
        request_id=_REQUEST_ID,
        operation="inspect",
        source_relative_path=artifact.relative_path,
        parameters=InspectParams(),
    )
    executor = UnixSocketPdfExecutor(
        store=store,
        socket_path=tmp_path / "worker.sock",
    )

    async def cancelled_exchange(_command: PdfCommand) -> PdfResult:
        raise asyncio.CancelledError

    monkeypatch.setattr(executor, "_exchange_unix", cancelled_exchange)

    with pytest.raises(asyncio.CancelledError):
        _ = await executor.execute(command, deadline=_deadline())

    assert list((store.root / ".pdf-worker-jobs").iterdir()) == []


@pytest.mark.parametrize("defect", ["missing", "regular-file"])
def test_unix_socket_path_must_be_an_available_private_socket(
    tmp_path: Path,
    defect: str,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    socket_path = tmp_path / "worker.sock"
    executor = UnixSocketPdfExecutor(store=store, socket_path=socket_path)
    if defect == "regular-file":
        _ = socket_path.write_bytes(b"not a socket")
        socket_path.chmod(0o600)
        message = "ownership or mode is invalid"
    else:
        message = "socket is unavailable"

    with pytest.raises(PdfWorkerOperationalError, match=message):
        executor._verify_socket_path()  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("peer", "message"),
    [
        (
            _FakeUnixPeer(_peer_record(user_id=os.geteuid()), family=socket.AF_INET),
            "not AF_UNIX",
        ),
        (_FakeUnixPeer(b"malformed"), "credentials are malformed"),
        (
            _FakeUnixPeer(_peer_record(user_id=os.geteuid() + 1)),
            "peer identity is invalid",
        ),
    ],
)
async def test_unix_exchange_authenticates_transport_and_peer_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    peer: object,
    message: str,
) -> None:
    store = ContentAddressedStore(tmp_path / "cache")
    socket_path = tmp_path / "worker.sock"
    writer = _FakeUnixWriter(peer)

    async def open_connection(_path: str) -> tuple[StreamReader, StreamWriter]:
        return asyncio.StreamReader(), cast("StreamWriter", writer)

    monkeypatch.setattr(asyncio, "open_unix_connection", open_connection)
    with _bind_private_socket(socket_path):
        executor = UnixSocketPdfExecutor(store=store, socket_path=socket_path)
        with pytest.raises(PdfWorkerOperationalError, match=message):
            _ = await executor._exchange_unix(_inspect_command())  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001

    assert writer.closed is True
