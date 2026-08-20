# Copyright (c) 2026 David Osipov
"""Emit typed tile results with adversarial identities and output paths."""

from __future__ import annotations

import hashlib
import io
import os
import sys
from pathlib import Path
from typing import BinaryIO, cast

from PIL import Image

from nplg_mcp.pdf_ipc import (
    MAX_RESULT_FRAME_BYTES,
    PdfSuccess,
    RenderedTileOutput,
    RenderPagesOutput,
    RenderTilesCommand,
    RenderTilesOutput,
    RenderTilesPayload,
    encode_frame,
    parse_command_frame,
)

_WRONG_RENDER_ID = "rnd_33333333333333333333333333333333"


def _jpeg_bytes(*, width: int, height: int) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (width, height), "white").save(output, format="JPEG")
    return output.getvalue()


def main() -> None:
    """Stage one selected tile-path defect and emit a strict success envelope."""
    input_stream = cast("BinaryIO", sys.stdin.buffer)
    output_stream = cast("BinaryIO", sys.stdout.buffer)
    size = int.from_bytes(input_stream.read(4), "big")
    command = parse_command_frame(input_stream.read(size))
    if not isinstance(command, RenderTilesCommand):
        message = "render_tiles command required"
        raise TypeError(message)
    mode = sys.argv[1]
    render_id = (
        _WRONG_RENDER_ID if mode == "render-id" else command.parameters.render_id
    )
    work_root = Path(os.environ["NPLG_PDF_WORK_ROOT"])
    source_manifest = RenderPagesOutput.model_validate_json(
        (
            work_root
            / "cache"
            / "renders"
            / command.parameters.render_id
            / "manifest.json"
        ).read_bytes(),
        strict=True,
    )
    source_page = next(
        page
        for page in source_manifest.pages
        if page.page_number == command.parameters.page_number
    )
    page_number = 2 if mode == "page-number" else 1
    tile_width = 512 if mode == "geometry" else 256
    geometry = f"w{tile_width:04d}-h0256-o000"
    root = f"renders/{render_id}/tiles/page-{page_number:04d}/{geometry}"
    if mode == "root":
        root = f"renders/{render_id}/tiles/page-{page_number:04d}"
    tile_id = f"p{page_number:04d}_{geometry}_x000000_y000000"
    tile_relative_path = f"{root}/{tile_id}.jpg"
    manifest_relative_path = f"{root}/manifest.json"
    if mode == "manifest-path":
        manifest_relative_path = f"{root}/unexpected.json"
    elif mode == "tile-path":
        tile_relative_path = f"renders/{render_id}/elsewhere/tile.jpg"
    elif mode not in {
        "extra-directory",
        "geometry",
        "page-number",
        "render-id",
        "root",
        "tile-metadata",
    }:
        raise RuntimeError(mode)
    output_width = min(tile_width, source_page.width)
    output_height = min(256, source_page.height)
    page_bytes = _jpeg_bytes(width=output_width, height=output_height)
    output = RenderTilesOutput(
        render_id=render_id,
        page_number=page_number,
        page_sha256=source_page.sha256,
        tile_width=tile_width,
        tile_height=256,
        overlap=0,
        tiles=(
            RenderedTileOutput(
                tile_id=tile_id,
                page_number=2 if mode == "tile-metadata" else page_number,
                x=0,
                y=0,
                width=output_width,
                height=output_height,
                full_page_width=source_page.width,
                full_page_height=source_page.height,
                overlap=1 if mode == "tile-metadata" else 0,
                relative_path=tile_relative_path,
                sha256=hashlib.sha256(page_bytes).hexdigest(),
                media_type="image/jpeg",
                resize_applied=False,
                pixel_dimensions_preserved=True,
                renderer_resampling="none",
                reencoded=True,
                lossy_conversion=True,
            ),
        ),
        manifest_relative_path=manifest_relative_path,
    )
    if mode in {
        "extra-directory",
        "geometry",
        "page-number",
        "root",
        "tile-metadata",
    }:
        output_root = work_root / "cache" / root
        output_root.mkdir(parents=True)
        _ = (output_root / f"{tile_id}.jpg").write_bytes(page_bytes)
        _ = (output_root / "manifest.json").write_text(
            output.model_dump_json(),
            encoding="utf-8",
        )
        (output_root / "empty-directory").mkdir()
    result = PdfSuccess(
        request_id=command.request_id,
        status="ok",
        payload=RenderTilesPayload(operation="render_tiles", value=output),
    )
    _ = output_stream.write(encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES))
    output_stream.flush()


if __name__ == "__main__":
    main()
