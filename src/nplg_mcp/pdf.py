from __future__ import annotations

import hashlib
import io
import json
import math
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

import pypdfium2 as pdfium
from PIL import Image, ImageChops, ImageStat, UnidentifiedImageError
from PIL import __version__ as PILLOW_VERSION
from pypdfium2 import raw as pdfium_c

from .config import HARD_MAX_TILE_DIMENSION, HARD_MAX_TILE_OVERLAP
from .errors import AppError, ErrorCode
from .storage import ContentAddressedStore

_RENDER_ID_RE = re.compile(r"^rnd_[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RENDERER_VERSION = (
    f"pdfium-{pdfium.PDFIUM_INFO}_"
    f"pypdfium2-{pdfium.PYPDFIUM_INFO}_"
    f"pillow-{PILLOW_VERSION}"
)
_DOMINANT_COVERAGE = 0.98
_MIN_EFFECTIVE_DPI = 50.0
_MAX_EFFECTIVE_DPI = 2400.0


@dataclass(frozen=True, slots=True)
class TileBox:
    x: int
    y: int
    width: int
    height: int


@dataclass(frozen=True, slots=True)
class PageInspection:
    page_number: int
    width_points: float
    height_points: float
    rotation: int
    classification: str
    image_count: int
    has_text: bool
    has_drawings: bool
    crop_applied: bool
    dominant_image_index: int | None
    dominant_extension: str | None
    dominant_coverage: float | None
    native_width: int | None
    native_height: int | None
    effective_dpi_x: float | None
    effective_dpi_y: float | None
    direct_jpeg_eligible: bool
    native_raster_extract_eligible: bool


@dataclass(frozen=True, slots=True)
class PdfInspection:
    source_sha256: str
    page_count: int
    renderer_version: str
    pages: tuple[PageInspection, ...]


@dataclass(frozen=True, slots=True)
class RenderedPage:
    page_number: int
    width: int
    height: int
    rotation: int
    classification: str
    effective_dpi_x: float
    effective_dpi_y: float
    resolution_source: str
    conversion_path: str
    relative_path: str
    sha256: str
    media_type: str
    resize_applied: bool
    pixel_dimensions_preserved: bool
    renderer_resampling: str
    reencoded: bool
    lossy_conversion: bool


@dataclass(frozen=True, slots=True)
class RenderManifest:
    render_id: str
    source_sha256: str
    renderer_version: str
    mode: str
    pages: tuple[RenderedPage, ...]
    manifest_relative_path: str


@dataclass(frozen=True, slots=True)
class RenderedTile:
    tile_id: str
    page_number: int
    x: int
    y: int
    width: int
    height: int
    full_page_width: int
    full_page_height: int
    overlap: int
    relative_path: str
    sha256: str
    media_type: str
    resize_applied: bool = False
    pixel_dimensions_preserved: bool = True
    renderer_resampling: str = "none"
    reencoded: bool = True
    lossy_conversion: bool = True


@dataclass(frozen=True, slots=True)
class TileManifest:
    render_id: str
    page_number: int
    page_sha256: str
    tile_width: int
    tile_height: int
    overlap: int
    tiles: tuple[RenderedTile, ...]
    manifest_relative_path: str


@dataclass(frozen=True, slots=True)
class _ImageCandidate:
    image_index: int
    width: int
    height: int
    extension: str
    bounds: tuple[float, float, float, float]
    coverage: float


def _tile_layout(
    width: int,
    height: int,
    *,
    tile_width: int,
    tile_height: int,
    overlap: int,
) -> tuple[int, int, int]:
    values = (width, height, tile_width, tile_height, overlap)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        raise AppError(ErrorCode.INVALID_INPUT, "Tile geometry must use integer pixel values.")
    if width <= 0 or height <= 0 or tile_width <= 0 or tile_height <= 0 or overlap < 0:
        raise AppError(ErrorCode.INVALID_INPUT, "Tile geometry must be positive and overlap must be non-negative.")
    if tile_width > HARD_MAX_TILE_DIMENSION or tile_height > HARD_MAX_TILE_DIMENSION:
        raise AppError(ErrorCode.INVALID_INPUT, "Tile dimensions exceed the compiled safety ceiling.")
    if overlap > HARD_MAX_TILE_OVERLAP:
        raise AppError(ErrorCode.INVALID_INPUT, "Tile overlap exceeds the compiled safety ceiling.")
    if overlap >= tile_width or overlap >= tile_height:
        raise AppError(ErrorCode.INVALID_INPUT, "Tile overlap must be smaller than both tile dimensions.")
    stride_x = tile_width - overlap
    stride_y = tile_height - overlap
    columns = ((width - 1) // stride_x) + 1
    rows = ((height - 1) // stride_y) + 1
    return stride_x, stride_y, columns * rows


def tile_boxes(
    width: int,
    height: int,
    *,
    tile_width: int,
    tile_height: int,
    overlap: int,
) -> tuple[TileBox, ...]:
    stride_x, stride_y, _ = _tile_layout(
        width,
        height,
        tile_width=tile_width,
        tile_height=tile_height,
        overlap=overlap,
    )
    return tuple(
        TileBox(
            x=x,
            y=y,
            width=min(tile_width, width - x),
            height=min(tile_height, height - y),
        )
        for y in range(0, height, stride_y)
        for x in range(0, width, stride_x)
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=4096)
def _sha256_for_fingerprint(
    path_value: str,
    device: int,
    inode: int,
    size: int,
    mtime_ns: int,
    ctime_ns: int,
) -> str:
    del device, inode, size, mtime_ns, ctime_ns
    return _sha256_file(Path(path_value))


def _verified_sha256(path: Path) -> str:
    metadata = path.stat()
    return _sha256_for_fingerprint(
        str(path),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _rect_equal(
    first: tuple[float, float, float, float],
    second: tuple[float, float, float, float],
    *,
    tolerance: float = 0.01,
) -> bool:
    return all(abs(a - b) <= tolerance for a, b in zip(first, second, strict=True))


def _rect_width(rect: tuple[float, float, float, float]) -> float:
    return max(0.0, float(rect[2] - rect[0]))


def _rect_height(rect: tuple[float, float, float, float]) -> float:
    return max(0.0, float(rect[3] - rect[1]))


def _intersection_area(
    first: tuple[float, float, float, float],
    second: tuple[float, float, float, float],
) -> float:
    left = max(first[0], second[0])
    bottom = max(first[1], second[1])
    right = min(first[2], second[2])
    top = min(first[3], second[3])
    if right <= left or top <= bottom:
        return 0.0
    return float((right - left) * (top - bottom))


def _jpeg_bytes(image: Image.Image, *, dpi_x: float | None = None, dpi_y: float | None = None) -> bytes:
    output = io.BytesIO()
    converted = image if image.mode == "RGB" else image.convert("RGB")
    kwargs: dict[str, Any] = {
        "format": "JPEG",
        "quality": 100,
        "subsampling": 0,
        "progressive": False,
        "optimize": False,
    }
    if dpi_x and dpi_y:
        kwargs["dpi"] = (round(dpi_x), round(dpi_y))
    converted.save(output, **kwargs)
    return output.getvalue()


def _decode_image(data: bytes) -> Image.Image:
    try:
        with Image.open(io.BytesIO(data)) as opened:
            opened.load()
            return opened.convert("RGB")
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise AppError(ErrorCode.PDF_PROCESSING_FAILED, "An embedded page image could not be decoded.", http_status=422) from exc


def _bitmap_image(bitmap: Any) -> Image.Image:
    try:
        # pypdfium2's PIL adapter may expose the native bitmap buffer directly.
        # Copy before closing the PDFium bitmap so the returned image owns bytes.
        return bitmap.to_pil().convert("RGB").copy()
    finally:
        bitmap.close()


def _render_scale(page: Any, width: int, height: int) -> float:
    page_width, page_height = (float(value) for value in page.get_size())
    if page_width <= 0 or page_height <= 0:
        raise AppError(ErrorCode.INVALID_DOCUMENT, "The PDF page has invalid dimensions.", http_status=422)

    # PdfPage.render() uses ceil(page_dimension * scale). Find a single scale
    # lying in both exact-output intervals. This avoids any post-render resize.
    lower = max((width - 1) / page_width, (height - 1) / page_height)
    upper = min(width / page_width, height / page_height)
    scale = math.nextafter(upper, 0.0)
    if not math.isfinite(scale) or scale <= 0 or scale <= lower:
        raise AppError(
            ErrorCode.PDF_PROCESSING_FAILED,
            "The PDF renderer could not map the page onto the requested exact pixel grid without resizing.",
            http_status=422,
            safe_details={"requested": [width, height]},
        )
    return scale


def _page_image(page: Any, width: int, height: int) -> Image.Image:
    try:
        bitmap = page.render(
            scale=_render_scale(page, width, height),
            rev_byteorder=True,
            fill_color=(255, 255, 255, 255),
            draw_annots=True,
        )
    except (pdfium.PdfiumError, RuntimeError, ValueError, OSError) as exc:
        raise AppError(ErrorCode.PDF_PROCESSING_FAILED, "The PDF page could not be rendered.", http_status=422) from exc
    if bitmap.width != width or bitmap.height != height:
        actual = [int(bitmap.width), int(bitmap.height)]
        bitmap.close()
        raise AppError(
            ErrorCode.PDF_PROCESSING_FAILED,
            "The PDF renderer could not produce the requested exact pixel grid without resizing.",
            http_status=422,
            safe_details={"requested": [width, height], "actual": actual},
        )
    return _bitmap_image(bitmap)


def _images_visually_equivalent(source: Image.Image, rendered: Image.Image) -> bool:
    if source.size != rendered.size:
        return False
    difference = ImageChops.difference(source.convert("RGB"), rendered.convert("RGB"))
    if difference.getbbox() is None:
        return True
    extrema = difference.getextrema()
    maximum = max(channel[1] for channel in extrema)
    mean = max(ImageStat.Stat(difference).mean)
    # PDFium and Pillow can differ by a few decoder/color-rounding levels for
    # the same DCT stream. Geometry is independently constrained before this
    # check, so this tolerance is only a conservative equivalence guard.
    return maximum <= 8 and mean <= 1.0


def _visually_equivalent(extracted: bytes, page: Any, width: int, height: int) -> bool:
    try:
        source = _decode_image(extracted)
        return _images_visually_equivalent(source, _page_image(page, width, height))
    except AppError:
        return False


def _open_document(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise AppError(ErrorCode.INVALID_DOCUMENT, "The cached PDF does not identify a regular file.", http_status=422)
    try:
        document = pdfium.PdfDocument(path)
    except (pdfium.PdfiumError, RuntimeError, TypeError, ValueError, OSError) as exc:
        # PDFium intentionally does not expose a stable, portable distinction
        # between malformed and password-protected load failures here. Both
        # are rejected without attempting passwords or recovery.
        raise AppError(ErrorCode.INVALID_DOCUMENT, "The PDF is malformed, encrypted, or unsupported.", http_status=422) from exc
    if len(document) <= 0:
        document.close()
        raise AppError(ErrorCode.INVALID_DOCUMENT, "The PDF contains no pages.", http_status=422)
    return document


def _image_extension(filters: tuple[str, ...]) -> str:
    if "DCTDecode" in filters:
        return "jpeg"
    if "JPXDecode" in filters:
        return "jp2"
    return "raster"


def _page_objects(page: Any) -> tuple[tuple[_ImageCandidate, ...], bool]:
    cropbox = tuple(float(value) for value in page.get_cropbox())
    page_area = _rect_width(cropbox) * _rect_height(cropbox)
    if page_area <= 0:
        return (), True

    candidates: list[_ImageCandidate] = []
    has_drawings = False
    image_index = 0
    try:
        for obj in page.get_objects():
            object_type = int(obj.type)
            if object_type == pdfium_c.FPDF_PAGEOBJ_IMAGE:
                width, height = (int(value) for value in obj.get_px_size())
                bounds = tuple(float(value) for value in obj.get_bounds())
                filters = tuple(str(value) for value in obj.get_filters())
                if width > 0 and height > 0:
                    coverage = min(1.0, _intersection_area(bounds, cropbox) / page_area)
                    candidates.append(
                        _ImageCandidate(
                            image_index=image_index,
                            width=width,
                            height=height,
                            extension=_image_extension(filters),
                            bounds=bounds,
                            coverage=coverage,
                        )
                    )
                image_index += 1
            elif object_type != pdfium_c.FPDF_PAGEOBJ_TEXT:
                # Paths, shadings, forms and unsupported object types are
                # overlays for conservative scan classification purposes.
                has_drawings = True
    except (pdfium.PdfiumError, RuntimeError, TypeError, ValueError):
        return (), True
    return tuple(sorted(candidates, key=lambda item: (-item.coverage, item.image_index))), has_drawings


def _page_has_text(page: Any) -> bool:
    textpage = None
    try:
        textpage = page.get_textpage()
        return bool(textpage.count_chars() and textpage.get_text_range().strip())
    except (pdfium.PdfiumError, RuntimeError, TypeError, ValueError):
        # Failure to prove absence of text must disable direct extraction.
        return True
    finally:
        if textpage is not None:
            textpage.close()


def _inspect_page(page: Any, page_number: int) -> PageInspection:
    candidates, has_drawings = _page_objects(page)
    meaningful = tuple(candidate for candidate in candidates if candidate.coverage >= 0.05)
    dominant = candidates[0] if candidates and candidates[0].coverage >= _DOMINANT_COVERAGE else None
    has_text = _page_has_text(page)
    cropbox = tuple(float(value) for value in page.get_cropbox())
    mediabox = tuple(float(value) for value in page.get_mediabox())
    crop_applied = not _rect_equal(cropbox, mediabox)
    rotation = int(page.get_rotation())
    width_points, height_points = (float(value) for value in page.get_size())

    native_width: int | None = None
    native_height: int | None = None
    dpi_x: float | None = None
    dpi_y: float | None = None
    direct_eligible = False
    raster_extract_eligible = False

    if dominant is None:
        classification = "vector" if not meaningful else "mixed"
    else:
        bounds_width = _rect_width(dominant.bounds)
        bounds_height = _rect_height(dominant.bounds)
        dpi_x = dominant.width * 72.0 / bounds_width if bounds_width else None
        dpi_y = dominant.height * 72.0 / bounds_height if bounds_height else None
        plausible_dpi = bool(
            dpi_x is not None
            and dpi_y is not None
            and _MIN_EFFECTIVE_DPI <= dpi_x <= _MAX_EFFECTIVE_DPI
            and _MIN_EFFECTIVE_DPI <= dpi_y <= _MAX_EFFECTIVE_DPI
        )
        unrotated_width = max(1, round(_rect_width(cropbox) * dominant.width / bounds_width))
        unrotated_height = max(1, round(_rect_height(cropbox) * dominant.height / bounds_height))
        if rotation in {90, 270}:
            native_width, native_height = unrotated_height, unrotated_width
            dpi_x, dpi_y = dpi_y, dpi_x
        else:
            native_width, native_height = unrotated_width, unrotated_height
        overlays = has_text or has_drawings or len(meaningful) > 1
        if overlays:
            classification = "raster_with_overlay" if len(meaningful) == 1 else "mixed"
        elif dominant.extension == "jpeg":
            classification = "single_raster_jpeg"
        else:
            classification = "single_raster_other"

        exact_geometry = (
            plausible_dpi
            and len(meaningful) == 1
            and rotation == 0
            and not crop_applied
            and _rect_equal(dominant.bounds, cropbox)
            and native_width == dominant.width
            and native_height == dominant.height
        )
        direct_eligible = bool(classification == "single_raster_jpeg" and exact_geometry)
        raster_extract_eligible = bool(classification == "single_raster_other" and exact_geometry)

    return PageInspection(
        page_number=page_number,
        width_points=round(width_points, 6),
        height_points=round(height_points, 6),
        rotation=rotation,
        classification=classification,
        image_count=len(meaningful),
        has_text=has_text,
        has_drawings=has_drawings,
        crop_applied=crop_applied,
        dominant_image_index=dominant.image_index if dominant else None,
        dominant_extension=dominant.extension if dominant else None,
        dominant_coverage=round(dominant.coverage, 6) if dominant else None,
        native_width=native_width,
        native_height=native_height,
        effective_dpi_x=round(dpi_x, 6) if dpi_x is not None else None,
        effective_dpi_y=round(dpi_y, 6) if dpi_y is not None else None,
        direct_jpeg_eligible=direct_eligible,
        native_raster_extract_eligible=raster_extract_eligible,
    )


def _page_image_object(page: Any, image_index: int) -> Any:
    images = tuple(page.get_objects(filter=[pdfium_c.FPDF_PAGEOBJ_IMAGE]))
    if image_index < 0 or image_index >= len(images):
        raise AppError(ErrorCode.PDF_PROCESSING_FAILED, "The dominant embedded image could not be reopened.", http_status=422)
    return images[image_index]


def _raw_jpeg_bytes(page: Any, image_index: int) -> bytes:
    image = _page_image_object(page, image_index)
    filters = tuple(str(value) for value in image.get_filters())
    # Decode transport/simple filters (for example ASCII85) while preserving
    # the terminal DCT stream byte-for-byte.
    data = bytes(image.get_data(decode_simple=True))
    if not filters or filters[-1] != "DCTDecode" or not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
        raise AppError(ErrorCode.PDF_PROCESSING_FAILED, "The embedded JPEG stream could not be extracted losslessly.", http_status=422)
    return data


def _native_image(page: Any, image_index: int) -> Image.Image:
    image = _page_image_object(page, image_index)
    try:
        return _bitmap_image(image.get_bitmap(render=False))
    except (pdfium.PdfiumError, RuntimeError, TypeError, ValueError, OSError) as exc:
        raise AppError(ErrorCode.PDF_PROCESSING_FAILED, "The embedded page image could not be decoded.", http_status=422) from exc


class PdfProcessor:
    def __init__(
        self,
        *,
        store: ContentAddressedStore,
        max_pages_per_render: int = 8,
        max_page_pixels: int = 120_000_000,
        max_render_pixels: int = 480_000_000,
        fallback_dpi: int = 400,
        tile_width: int = 2048,
        tile_height: int = 2048,
        tile_overlap: int = 128,
        max_tiles_per_page: int = 100,
        max_document_pages: int = 2000,
    ) -> None:
        self.store = store
        self.max_pages_per_render = max_pages_per_render
        self.max_page_pixels = max_page_pixels
        self.max_render_pixels = max_render_pixels
        self.fallback_dpi = fallback_dpi
        self.tile_width = tile_width
        self.tile_height = tile_height
        self.tile_overlap = tile_overlap
        self.max_tiles_per_page = max_tiles_per_page
        self.max_document_pages = max_document_pages
        if not 1 <= max_pages_per_render <= 64:
            raise ValueError("max_pages_per_render must be between 1 and 64")
        if max_page_pixels <= 0 or max_render_pixels <= 0:
            raise ValueError("pixel limits must be positive")
        if not 72 <= fallback_dpi <= 1200:
            raise ValueError("fallback_dpi must be between 72 and 1200")
        if max_tiles_per_page <= 0:
            raise ValueError("max_tiles_per_page must be positive")
        tile_boxes(1, 1, tile_width=tile_width, tile_height=tile_height, overlap=tile_overlap)

    def inspect(self, pdf_path: Path | str) -> PdfInspection:
        path = Path(pdf_path).resolve()
        source_sha256 = _verified_sha256(path) if path.is_file() else ""
        document = _open_document(path)
        try:
            page_count = len(document)
            if page_count > self.max_document_pages:
                raise AppError(
                    ErrorCode.PDF_PROCESSING_FAILED,
                    "The PDF exceeds the maximum supported page count.",
                    http_status=422,
                    safe_details={"page_count": page_count, "maximum": self.max_document_pages},
                )
            inspected: list[PageInspection] = []
            for index in range(page_count):
                page = document[index]
                try:
                    inspected.append(_inspect_page(page, index + 1))
                finally:
                    page.close()
            return PdfInspection(
                source_sha256=source_sha256,
                page_count=page_count,
                renderer_version=_RENDERER_VERSION,
                pages=tuple(inspected),
            )
        finally:
            document.close()

    def _render_id(self, source_sha256: str, pages: tuple[int, ...], mode: str) -> str:
        key = {
            "fallback_dpi": self.fallback_dpi,
            "mode": mode,
            "pages": list(pages),
            "renderer_version": _RENDERER_VERSION,
            "source_sha256": source_sha256,
        }
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        return f"rnd_{digest[:32]}"

    @staticmethod
    def _validate_render_id(render_id: str) -> str:
        if not _RENDER_ID_RE.fullmatch(render_id):
            raise AppError(ErrorCode.INVALID_INPUT, "Render identifier is invalid.")
        return render_id

    def _write_render_asset(self, render_id: str, relative_name: str, data: bytes) -> tuple[str, str]:
        self._validate_render_id(render_id)
        pure = PurePosixPath(relative_name)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts) or "\\" in relative_name:
            raise AppError(ErrorCode.INVALID_INPUT, "Render asset name is invalid.")
        render_root = (self.store.root / "renders" / render_id).resolve()
        destination = (render_root / Path(*pure.parts)).resolve()
        try:
            destination.relative_to(render_root)
        except ValueError as exc:
            raise AppError(ErrorCode.INVALID_INPUT, "Render asset path escapes its render directory.") from exc
        relative_path = destination.relative_to(self.store.root).as_posix()
        return self.store.put_render_bytes(relative_path, data)

    def _manifest_from_dict(self, payload: dict[str, Any]) -> RenderManifest:
        try:
            pages = tuple(RenderedPage(**item) for item in payload["pages"])
            return RenderManifest(
                render_id=str(payload["render_id"]),
                source_sha256=str(payload["source_sha256"]),
                renderer_version=str(payload["renderer_version"]),
                mode=str(payload["mode"]),
                pages=pages,
                manifest_relative_path=str(payload["manifest_relative_path"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached render manifest is invalid.", http_status=500) from exc

    def _validate_manifest_assets(self, manifest: RenderManifest) -> None:
        if (
            not _SHA256_RE.fullmatch(manifest.source_sha256)
            or manifest.renderer_version != _RENDERER_VERSION
            or manifest.mode != "native"
            or not manifest.pages
        ):
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached render manifest is invalid.", http_status=500)
        seen_pages: set[int] = set()
        try:
            for page in manifest.pages:
                expected_path = f"renders/{manifest.render_id}/page-{page.page_number:04d}.jpg"
                if (
                    isinstance(page.page_number, bool)
                    or page.page_number < 1
                    or page.page_number in seen_pages
                    or page.width < 1
                    or page.height < 1
                    or page.relative_path != expected_path
                    or page.media_type != "image/jpeg"
                    or not _SHA256_RE.fullmatch(page.sha256)
                ):
                    raise AppError(ErrorCode.INTERNAL_ERROR, "The cached render manifest is invalid.", http_status=500)
                path = self.store.resolve_asset(page.relative_path)
                if _verified_sha256(path) != page.sha256:
                    raise AppError(ErrorCode.INTERNAL_ERROR, "A cached render asset failed integrity validation.", http_status=500)
                seen_pages.add(page.page_number)
        except (OSError, TypeError, ValueError) as exc:
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached render manifest is invalid.", http_status=500) from exc

    def _read_tile_manifest(
        self,
        relative_path: str,
        *,
        render_id: str,
        page_number: int,
        tile_width: int,
        tile_height: int,
        overlap: int,
        page: RenderedPage,
        boxes: tuple[TileBox, ...],
        tile_root: str,
    ) -> TileManifest:
        path = self.store.resolve_asset(relative_path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("tile manifest root must be an object")
            manifest = TileManifest(
                render_id=str(payload["render_id"]),
                page_number=int(payload["page_number"]),
                page_sha256=str(payload["page_sha256"]),
                tile_width=int(payload["tile_width"]),
                tile_height=int(payload["tile_height"]),
                overlap=int(payload["overlap"]),
                tiles=tuple(RenderedTile(**item) for item in payload["tiles"]),
                manifest_relative_path=str(payload["manifest_relative_path"]),
            )
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached tile manifest is invalid.", http_status=500) from exc
        if (
            manifest.render_id != render_id
            or manifest.page_number != page_number
            or manifest.tile_width != tile_width
            or manifest.tile_height != tile_height
            or manifest.overlap != overlap
            or manifest.manifest_relative_path != relative_path
            or manifest.page_sha256 != page.sha256
            or len(manifest.tiles) != len(boxes)
        ):
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached tile manifest is not bound to its request.", http_status=500)
        try:
            for index, (tile, box) in enumerate(zip(manifest.tiles, boxes, strict=True), start=1):
                expected_id = f"p{page_number:04d}_w{tile_width:04d}-h{tile_height:04d}-o{overlap:03d}_x{box.x:06d}_y{box.y:06d}"
                expected_path = f"renders/{render_id}/{tile_root}/{expected_id}.jpg"
                if (
                    tile.tile_id != expected_id
                    or tile.page_number != page_number
                    or (tile.x, tile.y, tile.width, tile.height) != (box.x, box.y, box.width, box.height)
                    or (tile.full_page_width, tile.full_page_height) != (page.width, page.height)
                    or tile.overlap != overlap
                    or tile.relative_path != expected_path
                    or tile.media_type != "image/jpeg"
                    or not _SHA256_RE.fullmatch(tile.sha256)
                ):
                    raise AppError(ErrorCode.INTERNAL_ERROR, "The cached tile manifest is invalid.", http_status=500)
                path = self.store.resolve_asset(tile.relative_path)
                if _verified_sha256(path) != tile.sha256:
                    raise AppError(ErrorCode.INTERNAL_ERROR, "A cached tile failed integrity validation.", http_status=500)
        except (OSError, TypeError, ValueError) as exc:
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached tile manifest is invalid.", http_status=500) from exc
        return manifest

    def get_manifest(self, render_id: str) -> RenderManifest:
        render_id = self._validate_render_id(render_id)
        relative_path = f"renders/{render_id}/manifest.json"
        path = self.store.resolve_asset(relative_path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached render manifest could not be read.", http_status=500) from exc
        if not isinstance(payload, dict):
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached render manifest is invalid.", http_status=500)
        manifest = self._manifest_from_dict(payload)
        if manifest.render_id != render_id or manifest.manifest_relative_path != relative_path:
            raise AppError(ErrorCode.INTERNAL_ERROR, "The cached render manifest is not bound to its render identifier.", http_status=500)
        self._validate_manifest_assets(manifest)
        return manifest

    def _validate_page_selection(self, pages: Iterable[int], page_count: int) -> tuple[int, ...]:
        selected = tuple(pages)
        if not selected or len(selected) > self.max_pages_per_render:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                f"Select between 1 and {self.max_pages_per_render} pages per render request.",
            )
        if len(set(selected)) != len(selected):
            raise AppError(ErrorCode.INVALID_INPUT, "Page selection must not contain duplicates.")
        if any(not isinstance(page, int) or isinstance(page, bool) or page < 1 or page > page_count for page in selected):
            raise AppError(ErrorCode.INVALID_INPUT, "Page numbers are one-based and must exist in the PDF.")
        return selected

    def _target_grid(self, inspection: PageInspection) -> tuple[int, int, float, float, str]:
        if inspection.classification in {"single_raster_jpeg", "single_raster_other", "raster_with_overlay"} and inspection.native_width and inspection.native_height:
            width = inspection.native_width
            height = inspection.native_height
            dpi_x = inspection.effective_dpi_x or width * 72.0 / inspection.width_points
            dpi_y = inspection.effective_dpi_y or height * 72.0 / inspection.height_points
            return width, height, dpi_x, dpi_y, "embedded_scan"
        width = max(1, round(inspection.width_points * self.fallback_dpi / 72.0))
        height = max(1, round(inspection.height_points * self.fallback_dpi / 72.0))
        return width, height, float(self.fallback_dpi), float(self.fallback_dpi), "fallback_400_dpi"

    def render_pages(self, pdf_path: Path | str, *, pages: Iterable[int], mode: str = "native") -> RenderManifest:
        if mode != "native":
            raise AppError(ErrorCode.INVALID_INPUT, "Only native rendering mode is supported in the MVP.")
        path = Path(pdf_path).resolve()
        source_sha256 = _verified_sha256(path) if path.is_file() else ""
        document = _open_document(path)
        transaction = None
        try:
            page_count = len(document)
            if page_count > self.max_document_pages:
                raise AppError(ErrorCode.PDF_PROCESSING_FAILED, "The PDF exceeds the maximum supported page count.", http_status=422)
            selected = self._validate_page_selection(pages, page_count)
            render_id = self._render_id(source_sha256, selected, mode)
            transaction = self.store.begin_render_transaction(
                f"renders/{render_id}",
                completion_file="manifest.json",
            )
            if transaction.complete:
                try:
                    cached = self.get_manifest(render_id)
                    if (
                        cached.source_sha256 != source_sha256
                        or cached.mode != mode
                        or tuple(page.page_number for page in cached.pages) != selected
                    ):
                        raise AppError(ErrorCode.INTERNAL_ERROR, "The cached render is not bound to its request.", http_status=500)
                except AppError:
                    transaction.reset()
                else:
                    transaction.commit()
                    return cached

            inspections: dict[int, PageInspection] = {}
            for page_number in selected:
                page = document[page_number - 1]
                try:
                    inspections[page_number] = _inspect_page(page, page_number)
                finally:
                    page.close()

            grids: dict[int, tuple[int, int, float, float, str]] = {}
            total_pixels = 0
            for page_number, inspection in inspections.items():
                grid = self._target_grid(inspection)
                pixels = grid[0] * grid[1]
                if pixels > self.max_page_pixels:
                    raise AppError(
                        ErrorCode.PDF_PROCESSING_FAILED,
                        "A rendered page would exceed the configured pixel limit.",
                        http_status=422,
                        safe_details={"page": page_number, "pixels": pixels, "maximum": self.max_page_pixels},
                    )
                total_pixels += pixels
                grids[page_number] = grid
            if total_pixels > self.max_render_pixels:
                raise AppError(
                    ErrorCode.PDF_PROCESSING_FAILED,
                    "The render request would exceed the configured total pixel limit.",
                    http_status=422,
                    safe_details={"pixels": total_pixels, "maximum": self.max_render_pixels},
                )

            rendered_pages: list[RenderedPage] = []
            for page_number in selected:
                page = document[page_number - 1]
                try:
                    inspection = inspections[page_number]
                    width, height, dpi_x, dpi_y, resolution_source = grids[page_number]
                    image_bytes: bytes
                    conversion_path: str
                    resampling: str
                    reencoded: bool
                    lossy: bool

                    if inspection.direct_jpeg_eligible and inspection.dominant_image_index is not None:
                        try:
                            extracted = _raw_jpeg_bytes(page, inspection.dominant_image_index)
                        except AppError:
                            extracted = b""
                        if extracted and _visually_equivalent(extracted, page, width, height):
                            image_bytes = extracted
                            conversion_path = "direct_extract"
                            resampling = "none"
                            reencoded = False
                            lossy = False
                        else:
                            image_bytes = _jpeg_bytes(_page_image(page, width, height), dpi_x=dpi_x, dpi_y=dpi_y)
                            conversion_path = "native_grid_render"
                            resampling = "possible"
                            reencoded = True
                            lossy = True
                    elif inspection.native_raster_extract_eligible and inspection.dominant_image_index is not None:
                        rendered = _page_image(page, width, height)
                        try:
                            decoded = _native_image(page, inspection.dominant_image_index)
                        except AppError:
                            decoded = None
                        if decoded is not None and decoded.size == (width, height) and _images_visually_equivalent(decoded, rendered):
                            image_bytes = _jpeg_bytes(decoded, dpi_x=dpi_x, dpi_y=dpi_y)
                            conversion_path = "native_raster_reencode"
                            resampling = "none"
                        else:
                            image_bytes = _jpeg_bytes(rendered, dpi_x=dpi_x, dpi_y=dpi_y)
                            conversion_path = "native_grid_render"
                            resampling = "possible"
                        reencoded = True
                        lossy = True
                    else:
                        image_bytes = _jpeg_bytes(_page_image(page, width, height), dpi_x=dpi_x, dpi_y=dpi_y)
                        if resolution_source == "fallback_400_dpi":
                            conversion_path = "fallback_400dpi"
                        else:
                            conversion_path = "native_grid_render"
                        resampling = "possible"
                        reencoded = True
                        lossy = True
                finally:
                    page.close()

                relative_path, output_sha = self._write_render_asset(render_id, f"page-{page_number:04d}.jpg", image_bytes)
                rendered_pages.append(
                    RenderedPage(
                        page_number=page_number,
                        width=width,
                        height=height,
                        rotation=inspection.rotation,
                        classification=inspection.classification,
                        effective_dpi_x=round(dpi_x, 6),
                        effective_dpi_y=round(dpi_y, 6),
                        resolution_source=resolution_source,
                        conversion_path=conversion_path,
                        relative_path=relative_path,
                        sha256=output_sha,
                        media_type="image/jpeg",
                        resize_applied=False,
                        pixel_dimensions_preserved=resolution_source == "embedded_scan",
                        renderer_resampling=resampling,
                        reencoded=reencoded,
                        lossy_conversion=lossy,
                    )
                )

            manifest_relative_path = f"renders/{render_id}/manifest.json"
            manifest = RenderManifest(
                render_id=render_id,
                source_sha256=source_sha256,
                renderer_version=_RENDERER_VERSION,
                mode=mode,
                pages=tuple(rendered_pages),
                manifest_relative_path=manifest_relative_path,
            )
            payload = json.dumps(asdict(manifest), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            written_path, _ = self._write_render_asset(render_id, "manifest.json", payload)
            if written_path != manifest_relative_path:
                raise AppError(ErrorCode.INTERNAL_ERROR, "Render manifest path mismatch.", http_status=500)
            transaction.commit()
            return manifest
        except AppError:
            raise
        except (pdfium.PdfiumError, RuntimeError, TypeError, ValueError, OSError) as exc:
            raise AppError(ErrorCode.PDF_PROCESSING_FAILED, "The PDF renderer failed safely.", http_status=422) from exc
        finally:
            if transaction is not None:
                transaction.rollback()
            document.close()

    def render_tiles(
        self,
        render_id: str,
        *,
        page_number: int,
        tile_width: int | None = None,
        tile_height: int | None = None,
        overlap: int | None = None,
    ) -> TileManifest:
        manifest = self.get_manifest(render_id)
        page = next((item for item in manifest.pages if item.page_number == page_number), None)
        if page is None:
            raise AppError(ErrorCode.INVALID_INPUT, "The selected page is not present in this render.")
        width = self.tile_width if tile_width is None else tile_width
        height = self.tile_height if tile_height is None else tile_height
        applied_overlap = self.tile_overlap if overlap is None else overlap
        _, _, tile_count = _tile_layout(
            page.width,
            page.height,
            tile_width=width,
            tile_height=height,
            overlap=applied_overlap,
        )
        if tile_count > self.max_tiles_per_page:
            raise AppError(
                ErrorCode.PDF_PROCESSING_FAILED,
                "The requested tile geometry would exceed the tile-count limit.",
                http_status=422,
                safe_details={"tiles": tile_count, "maximum": self.max_tiles_per_page},
            )
        boxes = tile_boxes(page.width, page.height, tile_width=width, tile_height=height, overlap=applied_overlap)
        geometry_key = f"w{width:04d}-h{height:04d}-o{applied_overlap:03d}"
        tile_root = f"tiles/page-{page_number:04d}/{geometry_key}"
        source_path = self.store.resolve_asset(page.relative_path)
        tile_manifest_path = f"renders/{render_id}/{tile_root}/manifest.json"
        transaction = self.store.begin_render_transaction(
            f"renders/{render_id}/{tile_root}",
            completion_file="manifest.json",
        )
        if transaction.complete:
            try:
                cached = self._read_tile_manifest(
                    tile_manifest_path,
                    render_id=render_id,
                    page_number=page_number,
                    tile_width=width,
                    tile_height=height,
                    overlap=applied_overlap,
                    page=page,
                    boxes=boxes,
                    tile_root=tile_root,
                )
                transaction.commit()
                return cached
            except AppError:
                transaction.reset()
            except BaseException:
                transaction.rollback()
                raise
        try:
            with Image.open(source_path) as source:
                source.load()
                if source.size != (page.width, page.height):
                    raise AppError(ErrorCode.INTERNAL_ERROR, "The cached page dimensions do not match its manifest.", http_status=500)
                tiles: list[RenderedTile] = []
                for index, box in enumerate(boxes, start=1):
                    tile_id = f"p{page_number:04d}_{geometry_key}_x{box.x:06d}_y{box.y:06d}"
                    cropped = source.crop((box.x, box.y, box.x + box.width, box.y + box.height))
                    if cropped.size != (box.width, box.height):
                        raise AppError(ErrorCode.INTERNAL_ERROR, "A tile crop did not preserve the requested pixel rectangle.", http_status=500)
                    data = _jpeg_bytes(cropped, dpi_x=page.effective_dpi_x, dpi_y=page.effective_dpi_y)
                    relative_path, sha256 = self._write_render_asset(
                        render_id,
                        f"{tile_root}/{tile_id}.jpg",
                        data,
                    )
                    tiles.append(
                        RenderedTile(
                            tile_id=tile_id,
                            page_number=page_number,
                            x=box.x,
                            y=box.y,
                            width=box.width,
                            height=box.height,
                            full_page_width=page.width,
                            full_page_height=page.height,
                            overlap=applied_overlap,
                            relative_path=relative_path,
                            sha256=sha256,
                            media_type="image/jpeg",
                        )
                    )
        except AppError:
            transaction.rollback()
            raise
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            transaction.rollback()
            raise AppError(ErrorCode.PDF_PROCESSING_FAILED, "The rendered page could not be tiled.", http_status=422) from exc
        except BaseException:
            transaction.rollback()
            raise

        try:
            result = TileManifest(
                render_id=render_id,
                page_number=page_number,
                page_sha256=page.sha256,
                tile_width=width,
                tile_height=height,
                overlap=applied_overlap,
                tiles=tuple(tiles),
                manifest_relative_path=tile_manifest_path,
            )
            payload = json.dumps(asdict(result), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self._write_render_asset(render_id, f"{tile_root}/manifest.json", payload)
            transaction.commit()
            return result
        except BaseException:
            transaction.rollback()
            raise

    def delete_render(self, render_id: str) -> bool:
        render_id = self._validate_render_id(render_id)
        return self.store.delete_render_subtree(f"renders/{render_id}")
