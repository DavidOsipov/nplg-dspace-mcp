# Copyright (c) 2026 David Osipov
"""Integration tests for PDF artifacts and rendering."""

from __future__ import annotations

import hashlib
import inspect
import io
import json
from typing import TYPE_CHECKING, Never, cast

import pypdfium2 as pdfium
import pytest
from PIL import Image

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.json_types import (
    JsonObject,
    JsonValue,
    load_json_value,
    require_json_object,
)
from nplg_mcp.pdf import PdfProcessor
from nplg_mcp.storage import ContentAddressedStore
from tests.helpers.pdf_factory import (
    make_encrypted_pdf,
    make_mixed_pdf,
    make_raster_pdf,
    make_vector_pdf,
)

_PDF_PROCESSOR_SIGNATURE = (
    "(*, store: 'ContentAddressedStore', max_pages_per_render: 'int' = 8, "
    "max_page_pixels: 'int' = 120000000, max_render_pixels: 'int' = 480000000, "
    "fallback_dpi: 'int' = 400, tile_width: 'int' = 2048, "
    "tile_height: 'int' = 2048, tile_overlap: 'int' = 128, "
    "max_tiles_per_page: 'int' = 100, max_document_pages: 'int' = 2000) -> "
    "'None'"
)
_RIGHT_ANGLE_DEGREES = 90
_DEFAULT_TILE_COUNT = 4
_UNPROCESSABLE_ENTITY = 422

if TYPE_CHECKING:
    from pathlib import Path


class _WrongSizeBitmap:
    def __init__(self, wrapped: pdfium.PdfBitmap) -> None:
        super().__init__()
        self._wrapped = wrapped
        self.width = wrapped.width + 1
        self.height = wrapped.height

    def to_pil(self) -> Image.Image:
        return self._wrapped.to_pil()

    def close(self, *_args: object, **_kwargs: object) -> bool:
        return self._wrapped.close()


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
    return PdfProcessor(
        store=ContentAddressedStore(tmp_path / "cache", max_bytes=cache_max_bytes),
        **values,
    )


def _manifest_payload(
    service: PdfProcessor, relative_path: str
) -> tuple[Path, JsonObject]:
    path = service.store.resolve_asset(relative_path)
    payload = require_json_object(
        load_json_value(path.read_text(encoding="utf-8")),
        context="test manifest",
    )
    return path, payload


def _first_object(values: JsonValue, *, context: str) -> JsonObject:
    assert isinstance(values, list)
    assert values
    return require_json_object(values[0], context=context)


def _write_manifest_payload(path: Path, payload: JsonObject) -> None:
    _ = path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def _solid_jpeg(width: int, height: int) -> bytes:
    output = io.BytesIO()
    with Image.new("RGB", (width, height), "red") as image:
        image.save(
            output,
            format="JPEG",
            quality=95,
            subsampling=0,
            progressive=False,
        )
    return output.getvalue()


def test_pdf_processor_preserves_explicit_constructor_contract(tmp_path: Path) -> None:
    signature = inspect.signature(PdfProcessor)

    assert str(signature) == _PDF_PROCESSOR_SIGNATURE
    with pytest.raises(TypeError, match="misspelled_limit"):
        _ = signature.bind(
            store=ContentAddressedStore(tmp_path / "signature-cache"),
            misspelled_limit=1,
        )


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
    assert (
        service.store.resolve_asset(rendered.relative_path).read_bytes()
        == source.image_bytes
    )


def test_png_scan_is_reencoded_without_changing_pixel_dimensions(
    tmp_path: Path,
) -> None:
    source = make_raster_pdf(
        tmp_path / "single-png.pdf", image_format="PNG", width=900, height=1300
    )
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


def test_rotation_and_crop_are_physically_applied_on_native_grid(
    tmp_path: Path,
) -> None:
    rotated = make_raster_pdf(
        tmp_path / "rotated.pdf", width=1200, height=800, rotation=90
    )
    cropped = make_raster_pdf(
        tmp_path / "cropped.pdf", width=1200, height=800, crop_fraction=0.5
    )
    service = processor(tmp_path)

    rotated_page = service.render_pages(rotated.path, pages=(1,), mode="native").pages[
        0
    ]
    assert (rotated_page.width, rotated_page.height) == (800, 1200)
    assert rotated_page.rotation == _RIGHT_ANGLE_DEGREES
    assert rotated_page.conversion_path == "native_grid_render"

    cropped_page = service.render_pages(cropped.path, pages=(1,), mode="native").pages[
        0
    ]
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
    assert (
        service.render_pages(mixed, pages=(1,), mode="native")
        .pages[0]
        .resolution_source
        == "fallback_400_dpi"
    )


def test_render_manifest_is_deterministic_and_persisted(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "deterministic.pdf", overlay="visible")
    service = processor(tmp_path)

    first = service.render_pages(source.path, pages=(1,), mode="native")
    second = service.render_pages(source.path, pages=(1,), mode="native")

    assert first == second
    assert first.render_id.startswith("rnd_")
    assert service.get_manifest(first.render_id) == first
    manifest_path = service.store.resolve_asset(first.manifest_relative_path)
    payload = require_json_object(
        load_json_value(manifest_path.read_text(encoding="utf-8")),
        context="test render manifest",
    )
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
    assert (
        hashlib.sha256(rebuilt_path.read_bytes()).hexdigest() == rebuilt.pages[0].sha256
    )
    assert service.store.used_bytes == sum(
        path.stat().st_size
        for path in service.store.root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def test_tiles_are_crops_of_full_page_with_exact_coordinates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "tiles.pdf", width=3000, height=2200)
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")

    def resizing_is_forbidden(*_args: object, **_kwargs: object) -> Never:
        msg = "resize must not be used"
        raise AssertionError(msg)

    monkeypatch.setattr(Image.Image, "resize", resizing_is_forbidden)
    tiled = service.render_tiles(manifest.render_id, page_number=1)

    assert len(tiled.tiles) == _DEFAULT_TILE_COUNT
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


def test_tile_limit_is_rejected_before_materializing_boxes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "tile-limit.pdf", width=3000, height=2200)
    service = processor(tmp_path, max_tiles_per_page=3)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")

    def forbidden_box_allocation(*_args: object, **_kwargs: object) -> Never:
        msg = "tile boxes must not be materialized above the configured limit"
        raise AssertionError(msg)

    monkeypatch.setattr("nplg_mcp.pdf.TileBox", forbidden_box_allocation)
    with pytest.raises(AppError) as captured:
        _ = service.render_tiles(manifest.render_id, page_number=1)

    assert captured.value.code is ErrorCode.PDF_PROCESSING_FAILED
    assert captured.value.http_status == _UNPROCESSABLE_ENTITY
    assert captured.value.safe_details == {
        "tiles": _DEFAULT_TILE_COUNT,
        "maximum": 3,
    }


def test_distinct_tile_geometries_have_independent_deterministic_cache_namespaces(
    tmp_path: Path,
) -> None:
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
    assert {tile.relative_path for tile in first.tiles}.isdisjoint(
        tile.relative_path for tile in second.tiles
    )
    assert {tile.tile_id for tile in first.tiles}.isdisjoint(
        tile.tile_id for tile in second.tiles
    )
    for tiled in (first, second):
        payload = require_json_object(
            load_json_value(
                service.store.resolve_asset(tiled.manifest_relative_path).read_text(
                    encoding="utf-8"
                )
            ),
            context="test tile manifest",
        )
        tile_values = payload["tiles"]
        assert isinstance(tile_values, list)
        tile_payloads = [
            require_json_object(item, context="test tile manifest entry")
            for item in tile_values
        ]
        assert payload["tile_width"] == tiled.tile_width
        assert payload["tile_height"] == tiled.tile_height
        assert payload["overlap"] == tiled.overlap
        assert [item["relative_path"] for item in tile_payloads] == [
            item.relative_path for item in tiled.tiles
        ]

    assert (
        service.render_tiles(
            manifest.render_id,
            page_number=1,
            tile_width=2048,
            tile_height=2048,
            overlap=128,
        )
        == first
    )
    assert (
        service.render_tiles(
            manifest.render_id,
            page_number=1,
            tile_width=1024,
            tile_height=1024,
            overlap=64,
        )
        == second
    )


def test_corrupt_cached_tile_geometry_is_invalidated_and_rebuilt(
    tmp_path: Path,
) -> None:
    source = make_raster_pdf(
        tmp_path / "corrupt-cached-tile.pdf", width=3000, height=2200
    )
    service = processor(tmp_path)
    pages = service.render_pages(source.path, pages=(1,), mode="native")
    first = service.render_tiles(pages.render_id, page_number=1)
    corrupt_path = service.store.resolve_asset(first.tiles[0].relative_path)
    _ = corrupt_path.write_bytes(b"corrupt")

    rebuilt = service.render_tiles(pages.render_id, page_number=1)

    assert rebuilt == first
    for tile in rebuilt.tiles:
        tile_path = service.store.resolve_asset(tile.relative_path)
        assert hashlib.sha256(tile_path.read_bytes()).hexdigest() == tile.sha256
    assert service.store.used_bytes == sum(
        path.stat().st_size
        for path in service.store.root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def test_render_output_cannot_bypass_aggregate_cache_quota(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "quota.pdf", width=900, height=700)
    service = processor(tmp_path, cache_max_bytes=32)

    with pytest.raises(AppError) as captured:
        _ = service.render_pages(source.path, pages=(1,), mode="native")

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert service.store.used_bytes == 0
    assert service.store.reserved_bytes == 0
    assert list((service.store.root / ".staging").iterdir()) == []
    assert not list((service.store.root / "renders").rglob("manifest.json"))


def test_page_manifest_cache_full_rolls_back_render_and_quota(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "manifest-quota.pdf")
    service = processor(tmp_path, cache_max_bytes=len(source.image_bytes))

    with pytest.raises(AppError) as captured:
        _ = service.render_pages(source.path, pages=(1,), mode="native")

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
    first_tile_bytes = (
        service.store.resolve_asset(completed.tiles[0].relative_path).stat().st_size
    )
    tile_subtree = completed.manifest_relative_path.rsplit("/", 1)[0]
    assert service.store.delete_render_subtree(tile_subtree) is True
    assert service.store.used_bytes == baseline_bytes

    limited = processor(tmp_path, cache_max_bytes=baseline_bytes + first_tile_bytes)
    with pytest.raises(AppError) as captured:
        _ = limited.render_tiles(page_manifest.render_id, page_number=1)

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
    _ = malformed.write_bytes(b"%PDF-1.7\ntruncated")

    with pytest.raises(AppError) as pixels:
        _ = processor(tmp_path, max_page_pixels=1000).render_pages(
            source.path, pages=(1,), mode="native"
        )
    assert pixels.value.code is ErrorCode.PDF_PROCESSING_FAILED

    with pytest.raises(AppError) as locked:
        _ = processor(tmp_path).inspect(encrypted)
    assert locked.value.code is ErrorCode.INVALID_DOCUMENT

    with pytest.raises(AppError) as broken:
        _ = processor(tmp_path).inspect(malformed)
    assert broken.value.code is ErrorCode.INVALID_DOCUMENT


def test_page_selection_is_one_based_bounded_and_unique(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "selection.pdf")
    service = processor(tmp_path)

    for pages in ((), (0,), (2,), (1, 1)):
        with pytest.raises(AppError) as raised:
            _ = service.render_pages(source.path, pages=pages, mode="native")
        assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_pages_per_render": 0},
        {"max_pages_per_render": 65},
        {"max_page_pixels": 0},
        {"max_render_pixels": 0},
        {"fallback_dpi": 71},
        {"fallback_dpi": 1201},
        {"max_tiles_per_page": 0},
    ],
)
def test_pdf_processor_rejects_invalid_processing_limits(
    tmp_path: Path, overrides: dict[str, int]
) -> None:
    with pytest.raises(ValueError, match="must"):
        _ = processor(tmp_path, **overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"tile_width": True},
        {"tile_width": 0},
        {"tile_width": 1_000_000},
        {"tile_overlap": 1_000_000},
        {"tile_width": 128, "tile_overlap": 128},
    ],
)
def test_pdf_processor_rejects_invalid_tile_geometry(
    tmp_path: Path, overrides: dict[str, int]
) -> None:
    with pytest.raises(AppError) as raised:
        _ = processor(tmp_path, **overrides)

    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_inspect_and_render_enforce_document_page_limit(tmp_path: Path) -> None:
    source = make_vector_pdf(tmp_path / "page-limit.pdf")
    service = processor(tmp_path, max_document_pages=0)

    with pytest.raises(AppError) as inspection:
        _ = service.inspect(source)
    assert inspection.value.code is ErrorCode.PDF_PROCESSING_FAILED

    with pytest.raises(AppError) as rendering:
        _ = service.render_pages(source, pages=(1,), mode="native")
    assert rendering.value.code is ErrorCode.PDF_PROCESSING_FAILED


def test_render_rejects_unsupported_mode_before_opening_document(
    tmp_path: Path,
) -> None:
    service = processor(tmp_path)

    with pytest.raises(AppError) as raised:
        _ = service.render_pages(tmp_path / "missing.pdf", pages=(1,), mode="resized")

    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_pdf_input_must_be_a_regular_file(tmp_path: Path) -> None:
    service = processor(tmp_path)
    path = tmp_path / "missing.pdf"

    with pytest.raises(AppError) as raised:
        _ = service.inspect(path)

    assert raised.value.code is ErrorCode.INVALID_DOCUMENT


def test_render_rejects_non_finite_pdf_rectangle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_vector_pdf(tmp_path / "invalid-rectangle.pdf")
    service = processor(tmp_path)

    def invalid_cropbox(
        _page: object, *_args: object, **_kwargs: object
    ) -> tuple[float, float, float, float]:
        return 0.0, 0.0, float("nan"), 72.0

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfPage.get_cropbox", invalid_cropbox)

    with pytest.raises(AppError) as raised:
        _ = service.render_pages(source, pages=(1,), mode="native")

    assert raised.value.code is ErrorCode.PDF_PROCESSING_FAILED


def test_zero_area_crop_is_classified_conservatively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "zero-crop.pdf")
    service = processor(tmp_path)

    def zero_cropbox(
        _page: object, *_args: object, **_kwargs: object
    ) -> tuple[float, float, float, float]:
        return 0.0, 0.0, 0.0, 0.0

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfPage.get_cropbox", zero_cropbox)

    page = service.inspect(source.path).pages[0]

    assert page.classification == "vector"
    assert page.has_drawings is True


def test_non_intersecting_image_is_not_a_meaningful_page_raster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "outside-crop.pdf")
    service = processor(tmp_path)

    def outside_bounds(_image: object) -> tuple[float, float, float, float]:
        return -100.0, -100.0, -50.0, -50.0

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfImage.get_bounds", outside_bounds)

    page = service.inspect(source.path).pages[0]

    assert page.image_count == 0
    assert page.classification == "vector"


def test_image_with_invalid_pixel_dimensions_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "invalid-image-size.pdf")
    service = processor(tmp_path)

    def invalid_size(_image: object) -> tuple[int, int]:
        return 0, 0

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfImage.get_px_size", invalid_size)

    page = service.inspect(source.path).pages[0]

    assert page.image_count == 0
    assert page.classification == "vector"


def test_jpx_filter_is_classified_as_non_jpeg_raster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "jpx-filter.pdf")
    service = processor(tmp_path)

    def jpx_filters(_image: object, *_args: object, **_kwargs: object) -> list[str]:
        return ["JPXDecode"]

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfImage.get_filters", jpx_filters)

    page = service.inspect(source.path).pages[0]

    assert page.dominant_extension == "jp2"
    assert page.classification == "single_raster_other"


def test_pdf_object_enumeration_failure_disables_direct_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "object-failure.pdf")
    service = processor(tmp_path)

    def fail_objects(_page: object, *_args: object, **_kwargs: object) -> Never:
        msg = "object enumeration failed"
        raise RuntimeError(msg)

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfPage.get_objects", fail_objects)

    page = service.inspect(source.path).pages[0]

    assert page.classification == "vector"
    assert page.has_drawings is True
    assert page.direct_jpeg_eligible is False


def test_text_extraction_failure_disables_direct_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "text-failure.pdf")
    service = processor(tmp_path)

    def fail_textpage(_page: object) -> Never:
        msg = "text extraction failed"
        raise RuntimeError(msg)

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfPage.get_textpage", fail_textpage)

    page = service.inspect(source.path).pages[0]

    assert page.has_text is True
    assert page.direct_jpeg_eligible is False


def test_invalid_page_dimensions_fail_before_rendering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_vector_pdf(tmp_path / "invalid-dimensions.pdf")
    service = processor(tmp_path)

    def zero_size(_page: object) -> tuple[float, float]:
        return 0.0, 0.0

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfPage.get_size", zero_size)

    with pytest.raises(AppError) as raised:
        _ = service.render_pages(source, pages=(1,), mode="native")

    assert raised.value.code is ErrorCode.INVALID_DOCUMENT


def test_inconsistent_page_geometry_cannot_be_resampled_to_requested_grid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_vector_pdf(tmp_path / "inconsistent-geometry.pdf")
    service = processor(tmp_path)
    real_get_size = pdfium.PdfPage.get_size
    calls = 0

    def changing_size(page: pdfium.PdfPage) -> tuple[float, float]:
        nonlocal calls
        calls += 1
        width, height = real_get_size(page)
        return (width, height) if calls == 1 else (width, height * 2)

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfPage.get_size", changing_size)

    with pytest.raises(AppError) as raised:
        _ = service.render_pages(source, pages=(1,), mode="native")

    assert raised.value.code is ErrorCode.PDF_PROCESSING_FAILED


def test_pdfium_render_failure_is_normalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_vector_pdf(tmp_path / "render-failure.pdf")
    service = processor(tmp_path)

    def fail_render(_page: object, *_args: object, **_kwargs: object) -> Never:
        msg = "renderer failed"
        raise RuntimeError(msg)

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfPage.render", fail_render)

    with pytest.raises(AppError) as raised:
        _ = service.render_pages(source, pages=(1,), mode="native")

    assert raised.value.code is ErrorCode.PDF_PROCESSING_FAILED


def test_pdfium_bitmap_with_wrong_grid_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_vector_pdf(tmp_path / "wrong-bitmap-grid.pdf")
    service = processor(tmp_path)
    real_render = pdfium.PdfPage.render

    def wrong_size_render(
        page: pdfium.PdfPage, *args: object, **kwargs: object
    ) -> pdfium.PdfBitmap:
        assert not args
        scale = kwargs["scale"]
        assert isinstance(scale, float)
        bitmap = real_render(
            page,
            scale=scale,
            rev_byteorder=True,
            fill_color=(255, 255, 255, 255),
            draw_annots=True,
        )
        return cast("pdfium.PdfBitmap", _WrongSizeBitmap(bitmap))

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfPage.render", wrong_size_render)

    with pytest.raises(AppError) as raised:
        _ = service.render_pages(source, pages=(1,), mode="native")

    assert raised.value.code is ErrorCode.PDF_PROCESSING_FAILED
    assert raised.value.safe_details == {
        "requested": [400, 400],
        "actual": [401, 400],
    }


@pytest.mark.parametrize(
    ("replacement", "expected_path"),
    [
        (b"not a JPEG", "native_grid_render"),
        (b"\xff\xd8invalid\xff\xd9", "native_grid_render"),
    ],
)
def test_invalid_embedded_jpeg_falls_back_to_grid_render(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: bytes,
    expected_path: str,
) -> None:
    source = make_raster_pdf(tmp_path / "invalid-embedded-jpeg.pdf")
    service = processor(tmp_path)

    def invalid_data(_image: object, *_args: object, **_kwargs: object) -> bytes:
        return replacement

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfImage.get_data", invalid_data)

    page = service.render_pages(source.path, pages=(1,), mode="native").pages[0]

    assert page.conversion_path == expected_path


def test_missing_reopened_image_falls_back_to_grid_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "missing-reopened-image.pdf")
    service = processor(tmp_path)
    real_get_objects = pdfium.PdfPage.get_objects

    def omit_filtered_objects(
        page: pdfium.PdfPage, *args: object, **kwargs: object
    ) -> object:
        if args or kwargs:
            return iter(())
        return real_get_objects(page)

    monkeypatch.setattr(
        "nplg_mcp.pdf.pdfium.PdfPage.get_objects", omit_filtered_objects
    )

    rendered = service.render_pages(source.path, pages=(1,), mode="native").pages[0]

    assert rendered.conversion_path == "native_grid_render"


@pytest.mark.parametrize("width_delta", [0, 1])
def test_visually_different_embedded_jpeg_falls_back_to_grid_render(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    width_delta: int,
) -> None:
    source = make_raster_pdf(
        tmp_path / "different-embedded-jpeg.pdf", width=120, height=80
    )
    service = processor(tmp_path)
    replacement = _solid_jpeg(source.width + width_delta, source.height)

    def different_data(_image: object, *_args: object, **_kwargs: object) -> bytes:
        return replacement

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfImage.get_data", different_data)

    page = service.render_pages(source.path, pages=(1,), mode="native").pages[0]

    assert page.conversion_path == "native_grid_render"


def test_native_raster_decode_failure_falls_back_to_grid_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(
        tmp_path / "native-decode-failure.pdf",
        image_format="PNG",
        width=120,
        height=80,
    )
    service = processor(tmp_path)

    def fail_bitmap(_image: object, *_args: object, **_kwargs: object) -> Never:
        msg = "bitmap decode failed"
        raise RuntimeError(msg)

    monkeypatch.setattr("nplg_mcp.pdf.pdfium.PdfImage.get_bitmap", fail_bitmap)

    page = service.render_pages(source.path, pages=(1,), mode="native").pages[0]

    assert page.conversion_path == "native_grid_render"


def test_total_pixel_limit_is_independent_of_per_page_limit(tmp_path: Path) -> None:
    source = make_vector_pdf(tmp_path / "aggregate-pixels.pdf")
    service = processor(
        tmp_path,
        max_page_pixels=200_000,
        max_render_pixels=100_000,
    )

    with pytest.raises(AppError) as raised:
        _ = service.render_pages(source, pages=(1,), mode="native")

    assert raised.value.code is ErrorCode.PDF_PROCESSING_FAILED
    assert raised.value.safe_details == {"pixels": 160_000, "maximum": 100_000}


def test_invalid_render_identifier_is_rejected(tmp_path: Path) -> None:
    service = processor(tmp_path)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest("not-a-render-id")

    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("render_id", 1),
        ("pages", "not-an-array"),
    ],
)
def test_render_manifest_rejects_wrong_top_level_field_types(
    tmp_path: Path, field: str, bad_value: JsonValue
) -> None:
    source = make_raster_pdf(tmp_path / "bad-top-level-manifest.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    payload[field] = bad_value
    _write_manifest_payload(path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("page_number", True),
        ("effective_dpi_x", "not-numeric"),
        ("resize_applied", 1),
    ],
)
def test_render_manifest_rejects_wrong_page_field_types(
    tmp_path: Path, field: str, bad_value: JsonValue
) -> None:
    source = make_raster_pdf(tmp_path / "bad-page-field-manifest.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    page = _first_object(payload["pages"], context="test page")
    page[field] = bad_value
    _write_manifest_payload(path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_render_manifest_rejects_missing_or_extra_page_fields(
    tmp_path: Path, mutation: str
) -> None:
    source = make_raster_pdf(tmp_path / "closed-page-manifest.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    page = _first_object(payload["pages"], context="test page")
    if mutation == "missing":
        _ = page.pop("classification")
    else:
        page["unexpected"] = "value"
    _write_manifest_payload(path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_manifest_rejects_missing_required_top_level_field(
    tmp_path: Path,
) -> None:
    source = make_raster_pdf(tmp_path / "missing-field-manifest.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    _ = payload.pop("mode")
    _write_manifest_payload(path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_manifest_rejects_invalid_json(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "invalid-json-manifest.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    path = service.store.resolve_asset(manifest.manifest_relative_path)
    _ = path.write_bytes(b"{not-json")

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_manifest_is_bound_to_requested_identifier(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "manifest-binding.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    payload["render_id"] = f"rnd_{'0' * 32}"
    _write_manifest_payload(path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_manifest_rejects_global_policy_mismatch(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "manifest-policy.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    payload["renderer_version"] = "untrusted-renderer"
    _write_manifest_payload(path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_manifest_rejects_invalid_page_binding(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "manifest-page-binding.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    page = _first_object(payload["pages"], context="test page")
    page["width"] = 0
    _write_manifest_payload(path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_manifest_rejects_corrupt_page_asset(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "manifest-integrity.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    page_path = service.store.resolve_asset(manifest.pages[0].relative_path)
    _ = page_path.write_bytes(b"corrupt")

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_render_manifest_normalizes_page_asset_read_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "manifest-read-race.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    page_relative_path = manifest.pages[0].relative_path
    real_resolve = service.store.resolve_asset

    def remove_after_resolve(relative_path: str) -> Path:
        path = real_resolve(relative_path)
        if relative_path == page_relative_path:
            path.unlink()
        return path

    monkeypatch.setattr(service.store, "resolve_asset", remove_after_resolve)

    with pytest.raises(AppError) as raised:
        _ = service.get_manifest(manifest.render_id)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_cached_manifest_mismatch_rebuilds_render(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "cached-request-mismatch.pdf")
    service = processor(tmp_path)
    first = service.render_pages(source.path, pages=(1,), mode="native")
    path, payload = _manifest_payload(service, first.manifest_relative_path)
    payload["source_sha256"] = "0" * 64
    _write_manifest_payload(path, payload)

    rebuilt = service.render_pages(source.path, pages=(1,), mode="native")

    assert rebuilt == first


def test_wrong_render_manifest_write_path_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "wrong-manifest-path.pdf")
    service = processor(tmp_path)
    real_put = service.store.put_render_bytes

    def wrong_manifest_path(relative_path: str, data: bytes) -> tuple[str, str]:
        written, digest = real_put(relative_path, data)
        if relative_path.endswith("/manifest.json"):
            return f"{written}.wrong", digest
        return written, digest

    monkeypatch.setattr(service.store, "put_render_bytes", wrong_manifest_path)

    with pytest.raises(AppError) as raised:
        _ = service.render_pages(source.path, pages=(1,), mode="native")

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert not any((service.store.root / "renders").rglob("manifest.json"))


def test_render_tiles_rejects_page_absent_from_render(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "missing-render-page.pdf")
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")

    with pytest.raises(AppError) as raised:
        _ = service.render_tiles(manifest.render_id, page_number=2)

    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize("mutation", ["schema", "binding", "tile"])
def test_corrupt_cached_tile_manifest_is_rebuilt(tmp_path: Path, mutation: str) -> None:
    source = make_raster_pdf(
        tmp_path / "corrupt-tile-manifest.pdf", width=120, height=80
    )
    service = processor(tmp_path)
    pages = service.render_pages(source.path, pages=(1,), mode="native")
    first = service.render_tiles(pages.render_id, page_number=1)
    path, payload = _manifest_payload(service, first.manifest_relative_path)
    if mutation == "schema":
        payload["tiles"] = "not-an-array"
    elif mutation == "binding":
        payload["overlap"] = first.overlap + 1
    else:
        tile = _first_object(payload["tiles"], context="test tile")
        tile["tile_id"] = "wrong"
    _write_manifest_payload(path, payload)

    rebuilt = service.render_tiles(pages.render_id, page_number=1)

    assert rebuilt == first


def test_tile_manifest_asset_read_race_is_rebuilt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "tile-read-race.pdf", width=120, height=80)
    service = processor(tmp_path)
    pages = service.render_pages(source.path, pages=(1,), mode="native")
    first = service.render_tiles(pages.render_id, page_number=1)
    tile_relative_path = first.tiles[0].relative_path
    real_resolve = service.store.resolve_asset

    def remove_after_resolve(relative_path: str) -> Path:
        path = real_resolve(relative_path)
        if relative_path == tile_relative_path:
            path.unlink()
        return path

    monkeypatch.setattr(service.store, "resolve_asset", remove_after_resolve)

    rebuilt = service.render_tiles(pages.render_id, page_number=1)

    assert rebuilt == first


def test_tile_source_dimensions_must_match_render_manifest(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "tile-source-size.pdf", width=120, height=80)
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    page_path = service.store.resolve_asset(manifest.pages[0].relative_path)
    replacement = _solid_jpeg(60, 40)
    _ = page_path.write_bytes(replacement)
    manifest_path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    page = _first_object(payload["pages"], context="test page")
    page["sha256"] = hashlib.sha256(replacement).hexdigest()
    _write_manifest_payload(manifest_path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.render_tiles(manifest.render_id, page_number=1)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_invalid_cached_page_image_is_normalized_during_tiling(tmp_path: Path) -> None:
    source = make_raster_pdf(tmp_path / "invalid-tile-source.pdf", width=120, height=80)
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    page_path = service.store.resolve_asset(manifest.pages[0].relative_path)
    replacement = b"not an image"
    _ = page_path.write_bytes(replacement)
    manifest_path, payload = _manifest_payload(service, manifest.manifest_relative_path)
    page = _first_object(payload["pages"], context="test page")
    page["sha256"] = hashlib.sha256(replacement).hexdigest()
    _write_manifest_payload(manifest_path, payload)

    with pytest.raises(AppError) as raised:
        _ = service.render_tiles(manifest.render_id, page_number=1)

    assert raised.value.code is ErrorCode.PDF_PROCESSING_FAILED


def test_tile_crop_must_preserve_requested_dimensions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "bad-tile-crop.pdf", width=120, height=80)
    service = processor(tmp_path)
    manifest = service.render_pages(source.path, pages=(1,), mode="native")
    real_crop = Image.Image.crop

    def undersized_crop(
        image: Image.Image, box: tuple[int, int, int, int] | None = None
    ) -> Image.Image:
        cropped = real_crop(image, box)
        return real_crop(cropped, (0, 0, max(1, cropped.width - 1), cropped.height))

    monkeypatch.setattr(Image.Image, "crop", undersized_crop)

    with pytest.raises(AppError) as raised:
        _ = service.render_tiles(manifest.render_id, page_number=1)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR


def test_wrong_tile_manifest_write_path_rolls_back_only_tiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_raster_pdf(tmp_path / "wrong-tile-manifest-path.pdf", width=120)
    service = processor(tmp_path)
    pages = service.render_pages(source.path, pages=(1,), mode="native")
    real_put = service.store.put_render_bytes

    def wrong_manifest_path(relative_path: str, data: bytes) -> tuple[str, str]:
        written, digest = real_put(relative_path, data)
        if "/tiles/" in relative_path and relative_path.endswith("/manifest.json"):
            return f"{written}.wrong", digest
        return written, digest

    monkeypatch.setattr(service.store, "put_render_bytes", wrong_manifest_path)

    with pytest.raises(AppError) as raised:
        _ = service.render_tiles(pages.render_id, page_number=1)

    assert raised.value.code is ErrorCode.INTERNAL_ERROR
    assert service.store.resolve_asset(pages.pages[0].relative_path).is_file()
