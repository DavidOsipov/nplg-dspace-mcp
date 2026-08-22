# Copyright (c) 2026 David Osipov
"""In-process contract tests for the otherwise disposable PDF worker entry point."""

from __future__ import annotations

import io
import os
import resource
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import UUID

import pytest

import nplg_mcp.pdf_worker_main as worker_main
from nplg_mcp.pdf_ipc import (
    MAX_COMMAND_FRAME_BYTES,
    InspectCommand,
    InspectParams,
    ManifestCommand,
    ManifestParams,
    PdfFailure,
    PdfSuccess,
    RenderPagesCommand,
    RenderPagesParams,
    RenderPagesPayload,
    RenderTilesCommand,
    RenderTilesParams,
    encode_frame,
    parse_result_frame,
)
from nplg_mcp.storage import ContentAddressedStore
from tests.helpers.pdf_factory import make_raster_pdf

if TYPE_CHECKING:
    from typing import TextIO

    from nplg_mcp.pdf_ipc import PdfCommand, PdfResult

_FRAME_PREFIX_BYTES = 4


def _worker_environment(work_root: Path) -> dict[str, str]:
    return {
        "NPLG_PDF_WORK_ROOT": str(work_root),
        "NPLG_PDF_CPU_SECONDS": "30",
        "NPLG_PDF_ADDRESS_SPACE_BYTES": "1073741824",
        "NPLG_PDF_FILE_SIZE_BYTES": "536870912",
        "NPLG_PDF_OPEN_FILES": "64",
        "NPLG_PDF_PROCESSES": "8",
        "NPLG_PDF_FALLBACK_DPI": "400",
        "NPLG_PDF_MAX_PAGES_PER_RENDER": "8",
        "NPLG_PDF_MAX_PAGE_PIXELS": "100000000",
        "NPLG_PDF_MAX_RENDER_PIXELS": "250000000",
        "NPLG_PDF_TILE_WIDTH": "2048",
        "NPLG_PDF_TILE_HEIGHT": "2048",
        "NPLG_PDF_TILE_OVERLAP": "128",
        "NPLG_PDF_MAX_TILES_PER_PAGE": "100",
    }


def _apply_environment(
    monkeypatch: pytest.MonkeyPatch,
    work_root: Path,
    *,
    overrides: dict[str, str] | None = None,
) -> None:
    environment = _worker_environment(work_root)
    environment.update(overrides or {})
    for name, value in environment.items():
        monkeypatch.setenv(name, value)


def _bind_standard_streams(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> io.BytesIO:
    input_buffer = io.BytesIO(payload)
    output_buffer = io.BytesIO()
    input_stream = io.TextIOWrapper(input_buffer, encoding="utf-8")
    output_stream = io.TextIOWrapper(output_buffer, encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", cast("TextIO", input_stream))
    monkeypatch.setattr(sys, "stdout", cast("TextIO", output_stream))
    return output_buffer


def _disable_process_only_mutations(monkeypatch: pytest.MonkeyPatch) -> None:
    def ignore_limit(_resource: int, _limits: tuple[int, int]) -> None:
        return None

    def ignore_umask(_mask: int) -> int:
        return 0o022

    monkeypatch.setattr(resource, "setrlimit", ignore_limit)
    monkeypatch.setattr(os, "umask", ignore_umask)


def _invoke_worker(
    monkeypatch: pytest.MonkeyPatch,
    work_root: Path,
    command: PdfCommand,
) -> PdfResult:
    _apply_environment(monkeypatch, work_root)
    _disable_process_only_mutations(monkeypatch)
    output = _bind_standard_streams(
        monkeypatch,
        encode_frame(command, maximum=MAX_COMMAND_FRAME_BYTES),
    )

    assert worker_main.main([]) == 0

    frame = output.getvalue()
    assert len(frame) >= _FRAME_PREFIX_BYTES
    size = int.from_bytes(frame[:_FRAME_PREFIX_BYTES], "big")
    assert len(frame) == _FRAME_PREFIX_BYTES + size
    return parse_result_frame(frame[_FRAME_PREFIX_BYTES:])


def test_worker_main_executes_every_closed_operation_with_strict_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work_root = tmp_path / "worker"
    work_root.mkdir(mode=0o700)
    store = ContentAddressedStore(work_root / "cache")
    source = make_raster_pdf(tmp_path / "source.pdf", width=120, height=80)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    inspected = _invoke_worker(
        monkeypatch,
        work_root,
        InspectCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000021"),
            operation="inspect",
            source_relative_path=artifact.relative_path,
            parameters=InspectParams(),
        ),
    )
    assert isinstance(inspected, PdfSuccess)
    rendered = _invoke_worker(
        monkeypatch,
        work_root,
        RenderPagesCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000022"),
            operation="render_pages",
            source_relative_path=artifact.relative_path,
            parameters=RenderPagesParams(pages=(1,), mode="native"),
        ),
    )
    assert isinstance(rendered, PdfSuccess)
    assert isinstance(rendered.payload, RenderPagesPayload)
    render_id = rendered.payload.value.render_id
    tiled = _invoke_worker(
        monkeypatch,
        work_root,
        RenderTilesCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000023"),
            operation="render_tiles",
            parameters=RenderTilesParams(
                render_id=render_id,
                page_number=1,
                tile_width=256,
                tile_height=256,
                overlap=0,
            ),
        ),
    )
    assert isinstance(tiled, PdfSuccess)
    manifested = _invoke_worker(
        monkeypatch,
        work_root,
        ManifestCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000024"),
            operation="manifest",
            parameters=ManifestParams(render_id=render_id),
        ),
    )
    assert isinstance(manifested, PdfSuccess)


def test_worker_main_sanitizes_an_application_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work_root = tmp_path / "worker"
    work_root.mkdir(mode=0o700)
    _ = ContentAddressedStore(work_root / "cache")
    result = _invoke_worker(
        monkeypatch,
        work_root,
        InspectCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000025"),
            operation="inspect",
            source_relative_path="documents/doc_" + "0" * 64 + "/source.pdf",
            parameters=InspectParams(),
        ),
    )

    assert isinstance(result, PdfFailure)
    assert result.payload.message


def test_worker_main_applies_portable_limits_without_process_limit_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work_root = tmp_path / "worker"
    work_root.mkdir(mode=0o700)
    _ = ContentAddressedStore(work_root / "cache")
    monkeypatch.delattr(resource, "RLIMIT_NPROC")
    result = _invoke_worker(
        monkeypatch,
        work_root,
        InspectCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000035"),
            operation="inspect",
            source_relative_path="documents/doc_" + "0" * 64 + "/source.pdf",
            parameters=InspectParams(),
        ),
    )

    assert isinstance(result, PdfFailure)


def test_worker_main_sanitizes_an_unexpected_processing_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work_root = tmp_path / "worker"
    work_root.mkdir(mode=0o700)
    store = ContentAddressedStore(work_root / "cache")
    source = make_raster_pdf(tmp_path / "source.pdf", width=120, height=80)
    artifact = store.put_bytes(
        source.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    def fail_json_conversion(_value: object, *, context: str) -> dict[str, object]:
        del context
        message = "synthetic conversion failure"
        raise RuntimeError(message)

    monkeypatch.setattr(
        "nplg_mcp.pdf_worker_main.dataclass_to_json",
        fail_json_conversion,
    )
    result = _invoke_worker(
        monkeypatch,
        work_root,
        InspectCommand(
            request_id=UUID("00000000-0000-4000-8000-000000000036"),
            operation="inspect",
            source_relative_path=artifact.relative_path,
            parameters=InspectParams(),
        ),
    )

    assert isinstance(result, PdfFailure)
    assert result.payload.message == "The PDF worker could not complete the request."


@pytest.mark.parametrize("value", ["not-an-integer", "0", "3601"])
def test_worker_main_rejects_invalid_resource_limit_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    work_root = tmp_path / "worker"
    work_root.mkdir(mode=0o700)
    _apply_environment(
        monkeypatch,
        work_root,
        overrides={"NPLG_PDF_CPU_SECONDS": value},
    )
    _disable_process_only_mutations(monkeypatch)

    with pytest.raises(RuntimeError, match="NPLG_PDF_CPU_SECONDS"):
        _ = worker_main.main([])


@pytest.mark.parametrize("defect", ["relative", "symlink", "permissions"])
def test_worker_main_rejects_an_unsafe_work_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    work_root = tmp_path / "worker"
    work_root.mkdir(mode=0o700)
    configured = work_root
    if defect == "relative":
        configured = Path("relative-worker")
    elif defect == "symlink":
        link = tmp_path / "worker-link"
        link.symlink_to(work_root, target_is_directory=True)
        configured = link
    else:
        work_root.chmod(0o755)
    _apply_environment(monkeypatch, configured)
    _disable_process_only_mutations(monkeypatch)

    with pytest.raises(RuntimeError, match="worker root"):
        _ = worker_main.main([])


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        (0).to_bytes(_FRAME_PREFIX_BYTES, "big"),
        (4).to_bytes(_FRAME_PREFIX_BYTES, "big") + b"{}",
        (2).to_bytes(_FRAME_PREFIX_BYTES, "big") + b"{}x",
    ],
)
def test_worker_main_rejects_truncated_oversized_or_trailing_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    work_root = tmp_path / "worker"
    work_root.mkdir(mode=0o700)
    _apply_environment(monkeypatch, work_root)
    _disable_process_only_mutations(monkeypatch)
    _ = _bind_standard_streams(monkeypatch, payload)

    with pytest.raises(RuntimeError, match="command"):
        _ = worker_main.main([])
