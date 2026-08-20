# Copyright (c) 2026 David Osipov
"""Return typed render metadata backed by malicious staged output paths."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from PIL import Image

from nplg_mcp.pdf_ipc import (
    MAX_RESULT_FRAME_BYTES,
    PdfSuccess,
    RenderedPageOutput,
    RenderPagesCommand,
    RenderPagesOutput,
    RenderPagesPayload,
    encode_frame,
    parse_command_frame,
)

_WRONG_RENDER_ID = "rnd_11111111111111111111111111111111"
_RENDERER_VERSION = "malicious-test-worker"
_PATH_DEFECT_MODES = frozenset(
    {
        "directory",
        "final-symlink",
        "intermediate-symlink",
        "manifest-path",
        "oversized",
        "unexpected",
    }
)
_VALID_PAGE_MODES = frozenset(
    {
        "aggregate-pixel-budget",
        "digest",
        "dimensions",
        "extra",
        "fifo-extra",
        "header-pixel-budget",
        "manifest-invalid",
        "manifest-mismatch",
        "manifest-oversized",
        "not-jpeg",
        "page-set",
        "pixel-budget",
        "render-id",
        "symlink-directory-extra",
        "truncated-jpeg",
        "valid",
    }
)


@dataclass(frozen=True, slots=True)
class _OutputClaims:
    page_relative_path: str
    manifest_relative_path: str
    width: int = 1
    sha256: str = "0" * 64


@dataclass(frozen=True, slots=True)
class _DefectPaths:
    cache: Path
    output_root: Path
    source: Path
    work_root: Path


def _render_id(source_sha256: str, command: RenderPagesCommand) -> str:
    key = {
        "fallback_dpi": 400,
        "mode": command.parameters.mode,
        "pages": list(command.parameters.pages),
        "renderer_version": _RENDERER_VERSION,
        "source_sha256": source_sha256,
    }
    digest = hashlib.sha256(
        json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"rnd_{digest[:32]}"


def _default_claims(render_id: str, *, page_number: int = 1) -> _OutputClaims:
    root = f"renders/{render_id}"
    return _OutputClaims(
        page_relative_path=f"{root}/page-{page_number:04d}.jpg",
        manifest_relative_path=f"{root}/manifest.json",
    )


def _image_bytes(*, image_format: str, width: int = 1) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (width, 1), "white").save(output, format=image_format)
    return output.getvalue()


def _stage_path_defect(
    mode: str,
    *,
    render_id: str,
    paths: _DefectPaths,
) -> _OutputClaims:
    claims = _default_claims(render_id)
    if mode == "unexpected":
        return _OutputClaims(
            page_relative_path=f"renders/{render_id}/unexpected.jpg",
            manifest_relative_path=claims.manifest_relative_path,
        )
    if mode == "manifest-path":
        return _OutputClaims(
            page_relative_path=claims.page_relative_path,
            manifest_relative_path=f"renders/{render_id}/unexpected.json",
        )
    if mode == "final-symlink":
        paths.output_root.mkdir(parents=True)
        (paths.output_root / "page-0001.jpg").symlink_to(paths.source)
    elif mode == "intermediate-symlink":
        alternate = paths.work_root / "alternate" / render_id
        alternate.mkdir(parents=True)
        _ = (alternate / "page-0001.jpg").write_bytes(b"not-an-image")
        (paths.cache / "renders").symlink_to(paths.work_root / "alternate")
    elif mode == "oversized":
        paths.output_root.mkdir(parents=True)
        _ = (paths.output_root / "page-0001.jpg").write_bytes(b"x" * 2_048)
    elif mode == "directory":
        (paths.output_root / "page-0001.jpg").mkdir(parents=True)
    else:
        raise RuntimeError(mode)
    return claims


def _stage_valid_page(
    mode: str,
    *,
    output_root: Path,
    render_id: str,
    page_number: int,
) -> _OutputClaims:
    output_root.mkdir(parents=True, exist_ok=True)
    actual_width = (
        2
        if mode in {"aggregate-pixel-budget", "header-pixel-budget", "pixel-budget"}
        else 1
    )
    page_bytes = _image_bytes(
        image_format="PNG" if mode == "not-jpeg" else "JPEG",
        width=actual_width,
    )
    if mode == "truncated-jpeg":
        page_bytes = page_bytes[:-2]
    _ = (output_root / f"page-{page_number:04d}.jpg").write_bytes(page_bytes)
    digest = hashlib.sha256(page_bytes).hexdigest()
    claims = _default_claims(render_id, page_number=page_number)
    return _OutputClaims(
        page_relative_path=claims.page_relative_path,
        manifest_relative_path=claims.manifest_relative_path,
        width=(
            2 if mode in {"aggregate-pixel-budget", "dimensions", "pixel-budget"} else 1
        ),
        sha256="0" * 64 if mode == "digest" else digest,
    )


def _stage_manifest_defect(
    mode: str,
    *,
    output: RenderPagesOutput,
    output_root: Path,
    work_root: Path,
) -> None:
    manifest_path = output_root / "manifest.json"
    if mode == "manifest-invalid":
        _ = manifest_path.write_bytes(b"not-json")
    elif mode == "manifest-mismatch":
        different = RenderPagesOutput(
            render_id=output.render_id,
            source_sha256=output.source_sha256,
            renderer_version="different",
            mode=output.mode,
            pages=output.pages,
            manifest_relative_path=output.manifest_relative_path,
        )
        _ = manifest_path.write_text(different.model_dump_json(), encoding="utf-8")
    elif mode == "manifest-oversized":
        _ = manifest_path.write_bytes(b"x" * (MAX_RESULT_FRAME_BYTES + 1))
    else:
        _ = manifest_path.write_text(output.model_dump_json(), encoding="utf-8")
    if mode == "extra":
        _ = (output_root / "extra.bin").write_bytes(b"extra")
    elif mode == "symlink-directory-extra":
        alternate = work_root / "alternate-directory"
        alternate.mkdir()
        (output_root / "extra-directory").symlink_to(
            alternate,
            target_is_directory=True,
        )
    elif mode == "fifo-extra":
        os.mkfifo(output_root / "extra.fifo", mode=0o600)


def main() -> None:
    """Create the selected unsafe output and describe it with valid IPC types."""
    input_stream = cast("BinaryIO", sys.stdin.buffer)
    output_stream = cast("BinaryIO", sys.stdout.buffer)
    size = int.from_bytes(input_stream.read(4), "big")
    command = parse_command_frame(input_stream.read(size))
    if not isinstance(command, RenderPagesCommand):
        message = "render_pages command required"
        raise TypeError(message)
    work_root = Path(os.environ["NPLG_PDF_WORK_ROOT"])
    source = work_root / "cache" / command.source_relative_path
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    mode = sys.argv[1]
    render_id = (
        _WRONG_RENDER_ID if mode == "render-id" else _render_id(source_sha256, command)
    )
    page_numbers = (
        command.parameters.pages
        if mode == "aggregate-pixel-budget"
        else (2 if mode == "page-set" else 1,)
    )
    cache = work_root / "cache"
    output_root = cache / "renders" / render_id
    claims: tuple[_OutputClaims, ...]
    if mode in _PATH_DEFECT_MODES:
        claims = (
            _stage_path_defect(
                mode,
                render_id=render_id,
                paths=_DefectPaths(
                    cache=cache,
                    output_root=output_root,
                    source=source,
                    work_root=work_root,
                ),
            ),
        )
    elif mode in _VALID_PAGE_MODES:
        claims = tuple(
            _stage_valid_page(
                mode,
                output_root=output_root,
                render_id=render_id,
                page_number=page_number,
            )
            for page_number in page_numbers
        )
    else:
        raise RuntimeError(mode)
    output = RenderPagesOutput(
        render_id=render_id,
        source_sha256=source_sha256,
        renderer_version=_RENDERER_VERSION,
        mode="native",
        pages=tuple(
            RenderedPageOutput(
                page_number=page_number,
                width=page_claims.width,
                height=1,
                rotation=0,
                classification="image-only",
                effective_dpi_x=72.0,
                effective_dpi_y=72.0,
                resolution_source="native-raster",
                conversion_path="direct-jpeg-extraction",
                relative_path=page_claims.page_relative_path,
                sha256=page_claims.sha256,
                media_type="image/jpeg",
                resize_applied=False,
                pixel_dimensions_preserved=True,
                renderer_resampling="none",
                reencoded=False,
                lossy_conversion=False,
            )
            for page_number, page_claims in zip(page_numbers, claims, strict=True)
        ),
        manifest_relative_path=claims[0].manifest_relative_path,
    )
    if mode in _VALID_PAGE_MODES:
        _stage_manifest_defect(
            mode,
            output=output,
            output_root=output_root,
            work_root=work_root,
        )
    result = PdfSuccess(
        request_id=command.request_id,
        status="ok",
        payload=RenderPagesPayload(operation="render_pages", value=output),
    )
    _ = output_stream.write(encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES))
    output_stream.flush()


if __name__ == "__main__":
    main()
