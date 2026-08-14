from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from PIL import Image

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.pdf import PdfProcessor
from nplg_mcp.storage import ContentAddressedStore
from tests.helpers.pdf_factory import (
    make_encrypted_pdf,
    make_mixed_pdf,
    make_raster_pdf,
    make_vector_pdf,
)


def processor(
    tmp_path: Path,
    *,
    cache_max_bytes: int = 20 * 1024 * 1024 * 1024,
    **overrides: int,
) -> PdfProcessor:
    values = {
        "max_pages_per_render": 8,
        "max_page_pixels": 120_000_000,
        "max_render_pixels": 480_000_000,
        "fallback_dpi": 400,
        "tile_width": 2048,
        "tile_height": 2048,
        "tile_overlap": 128,
        "max_tiles_per_page": 100,
    }
    values.update(overrides)
    return PdfProcessor(store=ContentAddressedStore(tmp_path / "cache", max_bytes=cache_max_bytes), **values)


def test_single_jpeg_is_extracted_byte_identically(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "single-jpeg.pdf")
    service = processor(tmp_path)

    inspection = service.inspect(source.path)
    page = inspection.pages[0]
    assert page.classification == "single_raster_jpeg"
    assert page.native_width == source.width
    assert page.native_height == source.height
    assert page.direct_jpeg_eligible is True

    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    rendered = manifest.pages[0]
    assert rendered.conversion_path == "direct_extract"
    assert rendered.width == source.width
    assert rendered.height == source.height
    assert rendered.resize_applied is False
    assert rendered.pixel_dimensions_preserved is True
    assert rendered.renderer_resampling == "none"
    assert rendered.reencoded is False
    assert rendered.lossy_conversion is False
    assert service.store.resolve_asset(rendered.relative_path).read_bytes() == source.image_bytes


def test_png_scan_is_reencoded_without_changing_pixel_dimensions(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "single-png.pdf", image_format="PNG", width=900, height=1300)
    service = processor(tmp_path)

    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    rendered = manifest.pages[0]
    assert rendered.conversion_path == "native_raster_reencode"
    assert (rendered.width, rendered.height) == (900, 1300)
    assert rendered.renderer_resampling == "none"
    assert rendered.reencoded is True
    assert rendered.lossy_conversion is True
    with Image.open(service.store.resolve_asset(rendered.relative_path)) as image:
        assert image.size == (900, 1300)


def test_raster_with_ocr_overlay_uses_native_grid_compositor(tmp_path: Path) -> None:
    source = make_raster_pdf(
        tmp_path / "overlay.pdf",
        width=1200,
        height=800,
        overlay="OCR layer",
        invisible_overlay=True,
    )
    service = processor(tmp_path)

    inspection = service.inspect(source.path)
    assert inspection.pages[0].classification == "raster_with_overlay"
    assert inspection.pages[0].direct_jpeg_eligible is False

    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    rendered = manifest.pages[0]
    assert rendered.conversion_path == "native_grid_render"
    assert (rendered.width, rendered.height) == (1200, 800)
    assert rendered.renderer_resampling == "possible"
    assert rendered.resize_applied is False


def test_rotation_and_crop_are_physically_applied_on_native_grid(tmp_path: Path) -> None:
    rotated = make_raster_pdf(tmp_path / "rotated.pdf", width=1200, height=800, rotation=90)
    cropped = make_raster_pdf(tmp_path / "cropped.pdf", width=1200, height=800, crop_fraction=0.5)
    service = processor(tmp_path)

    rotated_page = service.render_pages(rotated.path, pages=(1,), mode="native").pages[0]
    assert (rotated_page.width, rotated_page.height) == (800, 1200)
    assert rotated_page.rotation == 90
    assert rotated_page.conversion_path == "native_grid_render"

    cropped_page = service.render_pages(cropped.path, pages=(1,), mode="native").pages[0]
    assert (cropped_page.width, cropped_page.height) == (600, 800)
    assert cropped_page.conversion_path == "native_grid_render"


def test_vector_and_mixed_pages_use_explicit_400_dpi_fallback(tmp_path: Path) -> None:
    vector = make_vector_pdf(tmp_path / "vector.pdf")
    mixed = make_mixed_pdf(tmp_path / "mixed.pdf")
    service = processor(tmp_path)

    vector_page = service.render_pages(vector, pages=(1,), mode="native").pages[0]
    assert (vector_page.width, vector_page.height) == (400, 400)
    assert vector_page.resolution_source == "fallback_400_dpi"
    assert vector_page.conversion_path == "fallback_400dpi"

    mixed_inspection = service.inspect(mixed)
    assert mixed_inspection.pages[0].classification == "mixed"
    assert service.render_pages(mixed, pages=(1,), mode="native").pages[0].resolution_source == "fallback_400_dpi"


def test_render_manifest_is_deterministic_and_persisted(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "deterministic.pdf", overlay="visible")
    service = processor(tmp_path)

    first = service.render_pages(source.path, pages=(1,), mode="native")
    second = service.render_pages(source.path, pages=(1,), mode="native")

    assert first == second
    assert first.render_id.startswith("rnd_")
    assert service.get_manifest(first.render_id) == first
    manifest_path = service.store.resolve_asset(first.manifest_relative_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["render_id"] == first.render_id
    assert payload["source_sha256"] == first.source_sha256


def test_missing_cached_page_is_invalidated_and_rebuilt(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "missing-cached-page.pdf")
    service = processor(tmp_path)
    first = service.render_pages(source.path, pages=(1,), mode="native")
    page_path = service.store.resolve_asset(first.pages[0].relative_path)
    page_path.unlink()

    rebuilt = service.render_pages(source.path, pages=(1,), mode="native")

    rebuilt_path = service.store.resolve_asset(rebuilt.pages[0].relative_path)
    assert rebuilt == first
    assert hashlib.sha256(rebuilt_path.read_bytes()).hexdigest() == rebuilt.pages[0].sha256
    assert service.store.used_bytes == sum(
        path.stat().st_size for path in service.store.root.rglob("*") if path.is_file() and not path.is_symlink()
    )


def test_tiles_are_crops_of_full_page_with_exact_coordinates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_raster_pdf(tmp_path / "tiles.pdf", width=3000, height=2200)
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")

    def resizing_is_forbidden(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("resize must not be used")

    monkeypatch.setattr(Image.Image, "resize", resizing_is_forbidden)
    tiled = service.render_tiles(manifest.render_id, page_number=1)

    assert len(tiled.tiles) == 4
    assert [(tile.x, tile.y, tile.width, tile.height) for tile in tiled.tiles] == [
        (0, 0, 2048, 2048),
        (1920, 0, 1080, 2048),
        (0, 1920, 2048, 280),
        (1920, 1920, 1080, 280),
    ]
    for tile in tiled.tiles:
        with Image.open(service.store.resolve_asset(tile.relative_path)) as image:
            assert image.size == (tile.width, tile.height)
            assert tile.resize_applied is False


def test_tile_limit_is_rejected_before_materializing_boxes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_raster_pdf(tmp_path / "tile-limit.pdf", width=3000, height=2200)
    service = processor(tmp_path, max_tiles_per_page=3)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")

    def forbidden_box_allocation(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("tile boxes must not be materialized above the configured limit")

    monkeypatch.setattr("nplg_mcp.pdf.TileBox", forbidden_box_allocation)
    with pytest.raises(AppError) as captured:
        service.render_tiles(manifest.render_id, page_number=1)

    assert captured.value.code is ErrorCode.PDF_PROCESSING_FAILED
    assert captured.value.http_status == 422
    assert captured.value.safe_details == {"tiles": 4, "maximum": 3}


def test_distinct_tile_geometries_have_independent_deterministic_cache_namespaces(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "tile-geometries.pdf", width=3000, height=2200)
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")

    first = service.render_tiles(
        manifest.render_id,
        page_number=1,
        tile_width=2048,
        tile_height=2048,
        overlap=128,
    )
    second = service.render_tiles(
        manifest.render_id,
        page_number=1,
        tile_width=1024,
        tile_height=1024,
        overlap=64,
    )

    assert first.manifest_relative_path != second.manifest_relative_path
    assert {tile.relative_path for tile in first.tiles}.isdisjoint(tile.relative_path for tile in second.tiles)
    assert {tile.tile_id for tile in first.tiles}.isdisjoint(tile.tile_id for tile in second.tiles)
    for tiled in (first, second):
        payload = json.loads(service.store.resolve_asset(tiled.manifest_relative_path).read_text(encoding="utf-8"))
        assert payload["tile_width"] == tiled.tile_width
        assert payload["tile_height"] == tiled.tile_height
        assert payload["overlap"] == tiled.overlap
        assert [item["relative_path"] for item in payload["tiles"]] == [item.relative_path for item in tiled.tiles]

    assert service.render_tiles(manifest.render_id, page_number=1, tile_width=2048, tile_height=2048, overlap=128) == first
    assert service.render_tiles(manifest.render_id, page_number=1, tile_width=1024, tile_height=1024, overlap=64) == second


def test_corrupt_cached_tile_geometry_is_invalidated_and_rebuilt(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "corrupt-cached-tile.pdf", width=3000, height=2200)
    service = processor(tmp_path)
    pages = service.render_pages(source.path, pages=(1,), mode="native")
    first = service.render_tiles(pages.render_id, page_number=1)
    corrupt_path = service.store.resolve_asset(first.tiles[0].relative_path)
    corrupt_path.write_bytes(b"corrupt")

    rebuilt = service.render_tiles(pages.render_id, page_number=1)

    assert rebuilt == first
    for tile in rebuilt.tiles:
        tile_path = service.store.resolve_asset(tile.relative_path)
        assert hashlib.sha256(tile_path.read_bytes()).hexdigest() == tile.sha256
    assert service.store.used_bytes == sum(
        path.stat().st_size for path in service.store.root.rglob("*") if path.is_file() and not path.is_symlink()
    )


def test_render_output_cannot_bypass_aggregate_cache_quota(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "quota.pdf", width=900, height=700)
    service = processor(tmp_path, cache_max_bytes=32)

    with pytest.raises(AppError) as captured:
        service.render_pages(source.path, pages=(1,), mode="native")

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert service.store.used_bytes == 0
    assert service.store.reserved_bytes == 0
    assert list((service.store.root / ".staging").iterdir()) == []
    assert not list((service.store.root / "renders").rglob("manifest.json"))


def test_page_manifest_cache_full_rolls_back_render_and_quota(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "manifest-quota.pdf")
    service = processor(tmp_path, cache_max_bytes=len(source.image_bytes))

    with pytest.raises(AppError) as captured:
        service.render_pages(source.path, pages=(1,), mode="native")

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert service.store.used_bytes == 0
    assert service.store.reserved_bytes == 0
    assert not any((service.store.root / "renders").rglob("*"))

    retry = processor(tmp_path)
    manifest = retry.render_pages(source.path, pages=(1,), mode="native")
    assert retry.store.resolve_asset(manifest.manifest_relative_path).is_file()


def test_tile_cache_full_rolls_back_only_target_geometry(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "tile-quota.pdf", width=3000, height=2200)
    service = processor(tmp_path)
    page_manifest = service.render_pages(source.path, pages=(1,), mode="native")
    page_path = service.store.resolve_asset(page_manifest.pages[0].relative_path)
    manifest_path = service.store.resolve_asset(page_manifest.manifest_relative_path)
    baseline_bytes = service.store.used_bytes

    completed = service.render_tiles(page_manifest.render_id, page_number=1)
    first_tile_bytes = service.store.resolve_asset(completed.tiles[0].relative_path).stat().st_size
    tile_subtree = completed.manifest_relative_path.rsplit("/", 1)[0]
    assert service.store.delete_render_subtree(tile_subtree) is True
    assert service.store.used_bytes == baseline_bytes

    limited = processor(tmp_path, cache_max_bytes=baseline_bytes + first_tile_bytes)
    with pytest.raises(AppError) as captured:
        limited.render_tiles(page_manifest.render_id, page_number=1)

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert limited.store.used_bytes == baseline_bytes
    assert limited.store.reserved_bytes == 0
    assert page_path.is_file()
    assert manifest_path.is_file()
    assert not (limited.store.root / tile_subtree).exists()


def test_delete_render_releases_capacity_without_restart(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "delete-accounting.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    released_bytes = service.store.used_bytes

    assert service.delete_render(manifest.render_id) is True
    assert service.store.used_bytes == 0
    assert service.store.reserved_bytes == 0
    assert not (service.store.root / "renders" / manifest.render_id).exists()

    service.store.max_bytes = released_bytes
    artifact = service.store.put_bytes(
        b"x" * released_bytes,
        namespace="documents",
        filename="replacement.bin",
        media_type="application/octet-stream",
    )
    assert artifact.size == released_bytes
    assert service.store.used_bytes == released_bytes


def test_limits_encrypted_and_malformed_documents_fail_closed(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "too-large.pdf", width=1200, height=800)
    encrypted = make_encrypted_pdf(tmp_path / "encrypted.pdf")
    malformed = tmp_path / "malformed.pdf"
    malformed.write_bytes(b"%PDF-1.7\ntruncated")

    with pytest.raises(AppError) as pixels:
        processor(tmp_path, max_page_pixels=1000).render_pages(source.path, pages=(1,), mode="native")
    assert pixels.value.code is ErrorCode.PDF_PROCESSING_FAILED

    with pytest.raises(AppError) as locked:
        processor(tmp_path).inspect(encrypted)
    assert locked.value.code is ErrorCode.INVALID_DOCUMENT

    with pytest.raises(AppError) as broken:
        processor(tmp_path).inspect(malformed)
    assert broken.value.code is ErrorCode.INVALID_DOCUMENT


def test_page_selection_is_one_based_bounded_and_unique(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "selection.pdf")
    service = processor(tmp_path)

    for pages in ((), (0,), (2,), (1, 1)):
        with pytest.raises(AppError) as raised:
            service.render_pages(source.path, pages=pages, mode="native")
        assert raised.value.code is ErrorCode.INVALID_INPUT
