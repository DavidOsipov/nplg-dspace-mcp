# Copyright (c) 2026 David Osipov
"""Deterministic PDF test collaborators."""

from __future__ import annotations

import hashlib
import io
import operator
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from PIL import Image, ImageDraw
from pypdf import PdfReader, PdfWriter
from pypdf.constants import UserAccessPermissions
from pypdf.generic import NameObject, RectangleObject
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import BinaryIO, TypedDict, Unpack

    class RasterPdfOptions(TypedDict, total=False):
        """Typed optional arguments accepted by ``make_raster_pdf``."""

        width: int
        height: int
        dpi: int
        image_format: str
        overlay: str | None
        invisible_overlay: bool
        rotation: int
        crop_fraction: float | None

    type _DrawImage = Callable[
        [ImageReader, float, float, float, float, str],
        object,
    ]
    type _DrawImageGetter = Callable[[canvas.Canvas], _DrawImage]
    type _WritePdf = Callable[[BinaryIO], tuple[bool, BinaryIO]]


RASTER_OPTION_NAMES = frozenset(
    {
        "crop_fraction",
        "dpi",
        "height",
        "image_format",
        "invisible_overlay",
        "overlay",
        "rotation",
        "width",
    }
)


@dataclass(frozen=True, slots=True)
class RasterPdf:
    """Generated PDF path and its exact embedded raster source."""

    path: Path
    image_bytes: bytes
    width: int
    height: int
    image_format: str


def patterned_image_bytes(
    width: int, height: int, *, image_format: str = "JPEG"
) -> bytes:
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width // 2 - 1, height - 1), fill=(180, 30, 30))
    draw.rectangle((width // 2, 0, width - 1, height - 1), fill=(30, 60, 180))
    draw.rectangle(
        (width // 4, height // 4, 3 * width // 4, 3 * height // 4),
        outline=(0, 0, 0),
        width=max(1, width // 200),
    )
    output = io.BytesIO()
    if image_format.upper() == "JPEG":
        image.save(output, format="JPEG", quality=95, subsampling=0, progressive=False)
    elif image_format.upper() == "PNG":
        image.save(output, format="PNG", optimize=False)
    else:
        raise ValueError(image_format)
    return output.getvalue()


def _rewrite_page_geometry(
    path: Path,
    *,
    rotation: int,
    crop_fraction: float | None,
    page_width: float,
    page_height: float,
) -> None:
    if not rotation and crop_fraction is None:
        return
    reader = PdfReader(path)
    writer = PdfWriter()
    for source_page in reader.pages:
        page = source_page
        if crop_fraction is not None:
            page[NameObject("/CropBox")] = RectangleObject(
                (0.0, 0.0, page_width * crop_fraction, page_height),
            )
        if rotation:
            _ = page.rotate(rotation)
        _ = writer.add_page(page)
    with path.open("wb") as stream:
        write_pdf = cast("_WritePdf", writer.write)
        _ = write_pdf(stream)


def _draw_image(
    pdf: canvas.Canvas,
    image: ImageReader,
    position: tuple[float, float],
    size: tuple[float, float],
) -> None:
    getter = cast("_DrawImageGetter", operator.attrgetter("drawImage"))
    draw_image = getter(pdf)
    _ = draw_image(
        image,
        *position,
        *size,
        "auto",
    )


def make_raster_pdf(
    path: Path,
    **options: Unpack[RasterPdfOptions],
) -> RasterPdf:
    unexpected = set(options) - RASTER_OPTION_NAMES
    if unexpected:
        msg = f"unsupported raster PDF options: {sorted(unexpected)}"
        raise TypeError(msg)
    width = options.get("width", 1200)
    height = options.get("height", 800)
    dpi = options.get("dpi", 200)
    image_format = options.get("image_format", "JPEG")
    overlay = options.get("overlay")
    invisible_overlay = options.get("invisible_overlay", False)
    rotation = options.get("rotation", 0)
    crop_fraction = options.get("crop_fraction")
    image_bytes = patterned_image_bytes(width, height, image_format=image_format)
    page_width = width * 72 / dpi
    page_height = height * 72 / dpi
    pdf = canvas.Canvas(
        str(path), pagesize=(page_width, page_height), pageCompression=1, invariant=1
    )
    _draw_image(
        pdf,
        ImageReader(io.BytesIO(image_bytes)),
        (0, 0),
        (page_width, page_height),
    )
    if overlay is not None:
        text = pdf.beginText(10, page_height - 24)
        text.setFont("Helvetica", 14)
        if invisible_overlay:
            text.setTextRenderMode(3)
        text.textLine(overlay)
        pdf.drawText(text)
    pdf.showPage()
    pdf.save()
    _rewrite_page_geometry(
        path,
        rotation=rotation,
        crop_fraction=crop_fraction,
        page_width=page_width,
        page_height=page_height,
    )
    return RasterPdf(
        path=path,
        image_bytes=image_bytes,
        width=width,
        height=height,
        image_format=image_format.upper(),
    )


def make_vector_pdf(path: Path, *, page_points: int = 72) -> Path:
    pdf = canvas.Canvas(
        str(path), pagesize=(page_points, page_points), pageCompression=1, invariant=1
    )
    pdf.setFillColorRGB(1, 1, 1)
    pdf.setStrokeColorRGB(0, 0, 0)
    pdf.rect(0, 0, page_points, page_points, stroke=1, fill=1)
    pdf.setFillColorRGB(1, 0.8, 0.8)
    pdf.setStrokeColorRGB(1, 0, 0)
    pdf.circle(page_points / 2, page_points / 2, page_points / 4, stroke=1, fill=1)
    pdf.setFillColorRGB(0, 0, 0)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(6, 6, "vector")
    pdf.showPage()
    pdf.save()
    return path


def make_mixed_pdf(
    path: Path, *, width: int = 1200, height: int = 800, dpi: int = 200
) -> Path:
    left = patterned_image_bytes(width // 2, height, image_format="JPEG")
    right = patterned_image_bytes(width // 2, height, image_format="PNG")
    page_width = width * 72 / dpi
    page_height = height * 72 / dpi
    pdf = canvas.Canvas(
        str(path), pagesize=(page_width, page_height), pageCompression=1, invariant=1
    )
    _draw_image(
        pdf,
        ImageReader(io.BytesIO(left)),
        (0, 0),
        (page_width / 2, page_height),
    )
    _draw_image(
        pdf,
        ImageReader(io.BytesIO(right)),
        (page_width / 2, 0),
        (page_width / 2, page_height),
    )
    pdf.showPage()
    pdf.save()
    return path


def make_encrypted_pdf(path: Path) -> Path:
    plain = path.with_suffix(".plain.pdf")
    pdf = canvas.Canvas(str(plain), pagesize=(72, 72), pageCompression=1, invariant=1)
    pdf.setFont("Helvetica", 10)
    pdf.drawString(10, 36, "secret")
    pdf.showPage()
    pdf.save()

    reader = PdfReader(plain)
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)
    writer.encrypt(
        user_password=_fixture_credential("user"),
        owner_password=_fixture_credential("owner"),
        permissions_flag=UserAccessPermissions(0),
        # The fixture only needs password protection; RC4 keeps this test
        # independent of pypdf's optional cryptography extra.
        algorithm="RC4-128",
    )
    with path.open("wb") as stream:
        write_pdf = cast("_WritePdf", writer.write)
        _ = write_pdf(stream)
    plain.unlink()
    return path


def _fixture_credential(role: str) -> str:
    return hashlib.sha256(f"nplg-pdf-fixture:{role}".encode()).hexdigest()
