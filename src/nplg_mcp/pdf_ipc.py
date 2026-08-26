# Copyright (c) 2026 David Osipov
"""Strict, bounded messages for the private PDF worker transport."""

from __future__ import annotations

import json
import math
import re
from pathlib import PurePosixPath
from typing import Annotated, Literal, cast, override
from uuid import UUID  # noqa: TC003 - Pydantic resolves this runtime field type.

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
)

from .config import (
    HARD_MAX_TILE_DIMENSION,
    HARD_MAX_TILE_OVERLAP,
    HARD_MAX_TILES_PER_PAGE,
)
from .errors import ErrorCode  # noqa: TC001 - Pydantic resolves the enum at runtime.
from .pdf_identity import (
    PDF_PIPELINE_VERSIONS,
    SemanticVersion,
)

MAX_COMMAND_FRAME_BYTES = 65_536
MAX_RESULT_FRAME_BYTES = 4_194_304
MAX_JSON_DEPTH = 64
MAX_JSON_VALUES = 32_768
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_SAFE_PATH_LENGTH = 512
_ASCII_CONTROL_END = 0x20
_ASCII_DELETE = 0x7F


class PdfIpcError(ValueError):
    """Reject malformed, ambiguous, or out-of-policy worker messages."""


def validate_safe_relative_path(value: str) -> str:
    """Return one canonical portable path confined to a worker job root."""
    pure = PurePosixPath(value)
    if (
        not value
        or len(value) > _MAX_SAFE_PATH_LENGTH
        or pure.is_absolute()
        or "\\" in value
        or "\x00" in value
        or pure.as_posix() != value
        or any(
            part in {"", ".", ".."}
            or _SAFE_SEGMENT.fullmatch(part) is None
            or any(
                ord(character) < _ASCII_CONTROL_END or ord(character) == _ASCII_DELETE
                for character in part
            )
            for part in value.split("/")
        )
    ):
        message = "worker relative path is invalid"
        raise ValueError(message)
    return value


SafeRelativePath = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=512),
    AfterValidator(validate_safe_relative_path),
]
Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
RenderId = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^rnd_[0-9a-f]{32}$"),
]
PageNumber = Annotated[int, Field(strict=True, ge=1, le=10_000)]
PageSelection = Annotated[tuple[PageNumber, ...], Field(min_length=1, max_length=8)]
TileDimension = Annotated[
    int,
    Field(strict=True, ge=256, le=HARD_MAX_TILE_DIMENSION),
]
TileOverlap = Annotated[
    int,
    Field(strict=True, ge=0, le=HARD_MAX_TILE_OVERLAP),
]
PdfOperation = Literal["inspect", "render_pages", "render_tiles", "manifest"]


class StrictModel(BaseModel):
    """Closed and immutable worker boundary model."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class PdfPipelineVersionOutput(StrictModel):
    """Required semantic identities for persisted PDF derivatives."""

    manifest_schema_version: SemanticVersion
    render_pipeline_version: SemanticVersion
    classification_algorithm_version: SemanticVersion
    tile_pipeline_version: SemanticVersion

    @override
    def model_post_init(self, _context: object) -> None:
        """Fail closed when a worker advertises non-current derivative semantics."""
        expected = PDF_PIPELINE_VERSIONS
        if (
            self.manifest_schema_version != expected.manifest_schema_version
            or self.render_pipeline_version != expected.render_pipeline_version
            or self.classification_algorithm_version
            != expected.classification_algorithm_version
            or self.tile_pipeline_version != expected.tile_pipeline_version
        ):
            message = "PDF worker pipeline version drift"
            raise ValueError(message)


class InspectParams(StrictModel):
    """Parameters for an inspection operation."""


class RenderPagesParams(StrictModel):
    """Parameters for a page-render operation."""

    pages: PageSelection
    mode: Literal["native"] = "native"


class RenderTilesParams(StrictModel):
    """Parameters for a tile-render operation."""

    render_id: RenderId
    page_number: PageNumber
    tile_width: TileDimension | None = None
    tile_height: TileDimension | None = None
    overlap: TileOverlap | None = None

    @override
    def model_post_init(self, _context: object) -> None:
        """Reject overlap that consumes an explicitly selected tile."""
        if self.overlap is None:
            return
        if self.tile_width is not None and self.overlap >= self.tile_width:
            message = "overlap must be smaller than tile_width"
            raise ValueError(message)
        if self.tile_height is not None and self.overlap >= self.tile_height:
            message = "overlap must be smaller than tile_height"
            raise ValueError(message)


class ManifestParams(StrictModel):
    """Parameters for a manifest-read operation."""

    render_id: RenderId


class InspectCommand(StrictModel):
    """Inspect one staged PDF."""

    request_id: UUID
    operation: Literal["inspect"]
    source_relative_path: SafeRelativePath
    parameters: InspectParams


class RenderPagesCommand(StrictModel):
    """Render pages from one staged PDF."""

    request_id: UUID
    operation: Literal["render_pages"]
    source_relative_path: SafeRelativePath
    parameters: RenderPagesParams


class RenderTilesCommand(StrictModel):
    """Create tiles from one staged render tree."""

    request_id: UUID
    operation: Literal["render_tiles"]
    parameters: RenderTilesParams


class ManifestCommand(StrictModel):
    """Read one staged render manifest."""

    request_id: UUID
    operation: Literal["manifest"]
    parameters: ManifestParams


PdfCommand = Annotated[
    InspectCommand | RenderPagesCommand | RenderTilesCommand | ManifestCommand,
    Field(discriminator="operation"),
]


class PageInspectionOutput(StrictModel):
    """Strict wire form of one inspected page."""

    page_number: PageNumber
    width_points: Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)]
    height_points: Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)]
    rotation: Annotated[int, Field(strict=True, ge=0, le=359)]
    classification: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=64)
    ]
    image_count: Annotated[int, Field(strict=True, ge=0, le=100_000)]
    has_text: bool
    has_drawings: bool
    crop_applied: bool
    dominant_image_index: Annotated[int, Field(strict=True, ge=0, le=100_000)] | None
    dominant_extension: (
        Annotated[str, StringConstraints(strict=True, min_length=1, max_length=32)]
        | None
    )
    dominant_coverage: (
        Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)] | None
    )
    native_width: Annotated[int, Field(strict=True, ge=1)] | None
    native_height: Annotated[int, Field(strict=True, ge=1)] | None
    effective_dpi_x: (
        Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)] | None
    )
    effective_dpi_y: (
        Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)] | None
    )
    direct_jpeg_eligible: bool
    native_raster_extract_eligible: bool


class PdfInspectionOutput(StrictModel):
    """Strict wire form of a complete inspection."""

    source_sha256: Sha256
    page_count: Annotated[int, Field(strict=True, ge=0, le=10_000)]
    renderer_version: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=256)
    ]
    pages: Annotated[tuple[PageInspectionOutput, ...], Field(max_length=10_000)]


class RenderedPageOutput(StrictModel):
    """Strict wire form of one rendered page."""

    page_number: PageNumber
    width: Annotated[int, Field(strict=True, ge=1)]
    height: Annotated[int, Field(strict=True, ge=1)]
    rotation: Annotated[int, Field(strict=True, ge=0, le=359)]
    classification: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=64)
    ]
    effective_dpi_x: Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)]
    effective_dpi_y: Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)]
    resolution_source: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=64)
    ]
    conversion_path: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=64)
    ]
    relative_path: SafeRelativePath
    sha256: Sha256
    media_type: Literal["image/jpeg"]
    resize_applied: bool
    pixel_dimensions_preserved: bool
    renderer_resampling: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=64)
    ]
    reencoded: bool
    lossy_conversion: bool


class RenderPagesOutput(PdfPipelineVersionOutput):
    """Strict wire form of a page-render manifest."""

    render_id: RenderId
    source_sha256: Sha256
    renderer_version: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=256)
    ]
    mode: Literal["native"]
    pages: Annotated[tuple[RenderedPageOutput, ...], Field(min_length=1, max_length=8)]
    manifest_relative_path: SafeRelativePath


class RenderedTileOutput(StrictModel):
    """Strict wire form of one rendered tile."""

    tile_id: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=128)
    ]
    page_number: PageNumber
    x: Annotated[int, Field(strict=True, ge=0)]
    y: Annotated[int, Field(strict=True, ge=0)]
    width: Annotated[int, Field(strict=True, ge=1)]
    height: Annotated[int, Field(strict=True, ge=1)]
    full_page_width: Annotated[int, Field(strict=True, ge=1)]
    full_page_height: Annotated[int, Field(strict=True, ge=1)]
    overlap: TileOverlap
    relative_path: SafeRelativePath
    sha256: Sha256
    media_type: Literal["image/jpeg"]
    resize_applied: Literal[False]
    pixel_dimensions_preserved: Literal[True]
    renderer_resampling: Literal["none"]
    reencoded: Literal[True]
    lossy_conversion: Literal[True]


class RenderTilesOutput(PdfPipelineVersionOutput):
    """Strict wire form of a tile manifest."""

    render_id: RenderId
    page_number: PageNumber
    page_sha256: Sha256
    tile_width: TileDimension
    tile_height: TileDimension
    overlap: TileOverlap
    tiles: Annotated[
        tuple[RenderedTileOutput, ...],
        Field(min_length=1, max_length=HARD_MAX_TILES_PER_PAGE),
    ]
    manifest_relative_path: SafeRelativePath


class InspectPayload(StrictModel):
    """Successful inspect payload."""

    operation: Literal["inspect"]
    value: PdfInspectionOutput


class RenderPagesPayload(StrictModel):
    """Successful render-pages payload."""

    operation: Literal["render_pages"]
    value: RenderPagesOutput


class RenderTilesPayload(StrictModel):
    """Successful render-tiles payload."""

    operation: Literal["render_tiles"]
    value: RenderTilesOutput


class ManifestPayload(StrictModel):
    """Successful manifest payload."""

    operation: Literal["manifest"]
    value: RenderPagesOutput


PdfPayload = Annotated[
    InspectPayload | RenderPagesPayload | RenderTilesPayload | ManifestPayload,
    Field(discriminator="operation"),
]


class PublicWorkerError(StrictModel):
    """Bounded public failure returned by the worker."""

    code: ErrorCode
    message: Annotated[
        str, StringConstraints(strict=True, min_length=1, max_length=512)
    ]


class PdfSuccess(StrictModel):
    """Successful worker result."""

    request_id: UUID
    status: Literal["ok"]
    payload: PdfPayload


class PdfFailure(StrictModel):
    """Expected worker failure."""

    request_id: UUID
    status: Literal["error"]
    operation: PdfOperation
    payload: PublicWorkerError


PdfResult = Annotated[PdfSuccess | PdfFailure, Field(discriminator="status")]

_COMMAND_ADAPTER: TypeAdapter[PdfCommand] = TypeAdapter(PdfCommand)
_RESULT_ADAPTER: TypeAdapter[PdfResult] = TypeAdapter(PdfResult)


def _reject_constant(value: str) -> None:
    message = f"non-finite JSON constant is forbidden: {value}"
    raise PdfIpcError(message)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            message = "duplicate JSON object key is forbidden"
            raise PdfIpcError(message)
        value[key] = item
    return value


def _preflight_json(frame: bytes, *, maximum: int) -> None:
    if not frame or len(frame) > maximum:
        message = "worker frame length is outside the allowed range"
        raise PdfIpcError(message)
    if frame.startswith(b"\xef\xbb\xbf"):
        message = "worker frame must not contain a UTF-8 BOM"
        raise PdfIpcError(message)
    try:
        text = frame.decode("utf-8", errors="strict")
        value: object = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        message = "worker frame is not canonical UTF-8 JSON"
        raise PdfIpcError(message) from exc
    stack: list[tuple[object, int]] = [(value, 1)]
    visited = 0
    while stack:
        item, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_VALUES or depth > MAX_JSON_DEPTH:
            message = "worker JSON structure exceeds its limit"
            raise PdfIpcError(message)
        if type(item) is float and not math.isfinite(item):
            message = "worker JSON numbers must be finite"
            raise PdfIpcError(message)
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in cast("list[object]", item))
        elif isinstance(item, dict):
            stack.extend(
                (child, depth + 1) for child in cast("dict[str, object]", item).values()
            )


def parse_command_frame(frame: bytes) -> PdfCommand:
    """Validate one unprefixed command JSON frame without coercion."""
    _preflight_json(frame, maximum=MAX_COMMAND_FRAME_BYTES)
    return _COMMAND_ADAPTER.validate_json(frame, strict=True)


def parse_result_frame(frame: bytes) -> PdfResult:
    """Validate one unprefixed result JSON frame without coercion."""
    _preflight_json(frame, maximum=MAX_RESULT_FRAME_BYTES)
    return _RESULT_ADAPTER.validate_json(frame, strict=True)


def encode_frame(model: BaseModel, *, maximum: int) -> bytes:
    """Encode one model with the fixed four-byte length prefix."""
    body = model.model_dump_json().encode("utf-8")
    if not body or len(body) > maximum:
        message = "worker frame length is outside the allowed range"
        raise PdfIpcError(message)
    return len(body).to_bytes(4, "big") + body
