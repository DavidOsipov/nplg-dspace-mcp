# Copyright (c) 2026 David Osipov
"""Strict, closed, bounded output contracts for every NPLG MCP tool."""

from __future__ import annotations

from typing import Annotated, Literal

from annotated_types import Ge, Le, MaxLen, MinLen
from pydantic import AfterValidator, Field, StringConstraints

from nplg_mcp.config import HARD_MAX_TILE_DIMENSION, HARD_MAX_TILE_OVERLAP
from nplg_mcp.pdf_ipc import validate_safe_relative_path

from .base import (
    MAX_SAFE_INTEGER,
    OWN_SEQUENCE_VALIDATOR,
    SAFE_INTEGER_VALIDATOR,
    SAFE_TEXT_PATTERN,
    FrozenSequence,
    StrictOutput,
    reject_unsafe_text,
)

Text64 = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=64,
        pattern=SAFE_TEXT_PATTERN,
    ),
    AfterValidator(reject_unsafe_text),
]
Text128 = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=SAFE_TEXT_PATTERN,
    ),
    AfterValidator(reject_unsafe_text),
]
Text256 = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=256,
        pattern=SAFE_TEXT_PATTERN,
    ),
    AfterValidator(reject_unsafe_text),
]
Text1024 = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=1_024,
        pattern=SAFE_TEXT_PATTERN,
    ),
    AfterValidator(reject_unsafe_text),
]
Text8192 = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=8192,
        pattern=SAFE_TEXT_PATTERN,
    ),
    AfterValidator(reject_unsafe_text),
]
Handle = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=r"^[1-9][0-9]{0,31}\/[1-9][0-9]{0,31}$",
    ),
]
Sha256 = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"),
]
ArtifactId = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^doc_[0-9a-f]{64}$"),
]
RenderId = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^rnd_[0-9a-f]{32}$"),
]
HttpUrl = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=8,
        max_length=4096,
        pattern=r"^https?:\/\/[!-~]{1,4088}$",
    ),
]
_SAFE_RELATIVE_PATH_PATTERN = (
    r"^([A-Za-z0-9_-][A-Za-z0-9._-]{0,255}|\.[A-Za-z0-9_-]"
    r"[A-Za-z0-9._-]{0,255}|\.\.[A-Za-z0-9_-][A-Za-z0-9._-]{0,255})"
    r"(\/([A-Za-z0-9_-][A-Za-z0-9._-]{0,255}|\.[A-Za-z0-9_-]"
    r"[A-Za-z0-9._-]{0,255}|\.\.[A-Za-z0-9_-][A-Za-z0-9._-]{0,255})){0,15}$"
)
_ARTIFACT_RESOURCE_URI_PATTERN = r"^nplg:\/\/artifact\/doc_[0-9a-f]{64}$"
_RENDER_MANIFEST_RESOURCE_URI_PATTERN = r"^nplg:\/\/render\/rnd_[0-9a-f]{32}\/manifest$"

RelativePath = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=1024,
        pattern=_SAFE_RELATIVE_PATH_PATTERN,
    ),
    AfterValidator(validate_safe_relative_path),
]
ArtifactResourceUri = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=512,
        pattern=_ARTIFACT_RESOURCE_URI_PATTERN,
    ),
]
RenderManifestResourceUri = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=512,
        pattern=_RENDER_MANIFEST_RESOURCE_URI_PATTERN,
    ),
]
PageNumber = Annotated[int, Ge(1), Le(10_000), SAFE_INTEGER_VALIDATOR]
NonnegativeInteger = Annotated[
    int,
    Ge(0),
    Le(MAX_SAFE_INTEGER),
    SAFE_INTEGER_VALIDATOR,
]
PositiveInteger = Annotated[
    int,
    Ge(1),
    Le(MAX_SAFE_INTEGER),
    SAFE_INTEGER_VALIDATOR,
]
Rotation = Annotated[int, Ge(0), Le(359), SAFE_INTEGER_VALIDATOR]
ImageCount = Annotated[int, Ge(0), Le(100_000), SAFE_INTEGER_VALIDATOR]
PageCount = Annotated[int, Ge(0), Le(10_000), SAFE_INTEGER_VALIDATOR]
TileDimension = Annotated[
    int,
    Ge(256),
    Le(HARD_MAX_TILE_DIMENSION),
    SAFE_INTEGER_VALIDATOR,
]
TileOverlap = Annotated[
    int,
    Ge(0),
    Le(HARD_MAX_TILE_OVERLAP),
    SAFE_INTEGER_VALIDATOR,
]
FinitePositive = Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)]
FiniteRatio = Annotated[
    float,
    Field(strict=True, ge=0, le=1, allow_inf_nan=False),
]


class SearchDocumentRecord(StrictOutput):
    """One bounded repository search result."""

    handle: Handle
    canonical_url: HttpUrl
    title: Text8192
    issue_date: Text64 | None = None
    authors: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()


class SearchDocumentsOutput(StrictOutput):
    """One bounded search page with an opaque continuation cursor."""

    items: Annotated[
        FrozenSequence[SearchDocumentRecord],
        MaxLen(50),
        OWN_SEQUENCE_VALIDATOR,
    ]
    total: NonnegativeInteger
    next_offset: NonnegativeInteger | None
    source_url: HttpUrl
    next_cursor: Text1024 | None = None


class RawMetadataFieldOutput(StrictOutput):
    """One inert normalized metadata field with explicit provenance key."""

    key: Text256
    value: Text8192
    language: Text64 | None = None


class DocumentFileRecord(StrictOutput):
    """One file discovered on a canonical item page."""

    bitstream_id: Text128
    handle: Handle
    filename: Text8192
    source_url: HttpUrl
    reported_size: NonnegativeInteger | None = None
    reported_format: Text256 | None = None
    description: Text8192 | None = None
    access_status: Text64


class DocumentMetadataOutput(StrictOutput):
    """Bounded normalized metadata for one NPLG item."""

    handle: Handle
    canonical_url: HttpUrl
    title: Text8192
    issue_date: Text64 | None = None
    creators: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    contributors: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    publishers: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    descriptions: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    subjects: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    languages: Annotated[
        FrozenSequence[Text64], MaxLen(128), OWN_SEQUENCE_VALIDATOR
    ] = ()
    identifiers: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    rights: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    owners: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    collections: Annotated[
        FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ] = ()
    types: Annotated[FrozenSequence[Text8192], MaxLen(512), OWN_SEQUENCE_VALIDATOR] = ()
    raw_fields: Annotated[
        FrozenSequence[RawMetadataFieldOutput],
        MaxLen(4096),
        OWN_SEQUENCE_VALIDATOR,
    ] = ()
    bitstreams: Annotated[
        FrozenSequence[DocumentFileRecord],
        MaxLen(512),
        OWN_SEQUENCE_VALIDATOR,
    ] = ()
    restricted: bool = False
    restriction_reason: Text8192 | None = None
    metadata_source: Text64


class DocumentFilesOutput(StrictOutput):
    """Bounded file inventory for one canonical item."""

    handle: Handle
    files: Annotated[
        FrozenSequence[DocumentFileRecord], MaxLen(512), OWN_SEQUENCE_VALIDATOR
    ]


class DownloadDocumentOutput(StrictOutput):
    """Content-addressed result of one bounded public download."""

    artifact_id: ArtifactId
    sha256: Sha256
    size: NonnegativeInteger
    media_type: Literal["application/pdf"]
    relative_path: RelativePath
    asset_url: HttpUrl
    resource_uri: ArtifactResourceUri
    source_bitstream_id: Text128
    source_url: HttpUrl
    bytes_downloaded: NonnegativeInteger


class PageInspectionRecord(StrictOutput):
    """Bounded public inspection data for one PDF page."""

    page_number: PageNumber
    width_points: FinitePositive
    height_points: FinitePositive
    rotation: Rotation
    classification: Text64
    image_count: ImageCount
    has_text: bool
    has_drawings: bool
    crop_applied: bool
    dominant_image_index: ImageCount | None
    dominant_extension: Text64 | None
    dominant_coverage: FiniteRatio | None
    native_width: PositiveInteger | None
    native_height: PositiveInteger | None
    effective_dpi_x: FinitePositive | None
    effective_dpi_y: FinitePositive | None
    direct_jpeg_eligible: bool
    native_raster_extract_eligible: bool


class PdfInspectionOutput(StrictOutput):
    """Strict public result of inspecting one PDF."""

    artifact_id: ArtifactId
    source_sha256: Sha256
    page_count: PageCount
    renderer_version: Text256
    pages: Annotated[
        FrozenSequence[PageInspectionRecord],
        MaxLen(10_000),
        OWN_SEQUENCE_VALIDATOR,
    ]
    resource_uri: ArtifactResourceUri


class RenderedPageRecord(StrictOutput):
    """One bounded rendered JPEG page and its provenance."""

    page_number: PageNumber
    width: PositiveInteger
    height: PositiveInteger
    rotation: Rotation
    classification: Text64
    effective_dpi_x: FinitePositive
    effective_dpi_y: FinitePositive
    resolution_source: Text64
    conversion_path: Text64
    relative_path: RelativePath
    sha256: Sha256
    media_type: Literal["image/jpeg"]
    resize_applied: bool
    pixel_dimensions_preserved: bool
    renderer_resampling: Text64
    reencoded: bool
    lossy_conversion: bool
    asset_url: HttpUrl
    resource_uri: ArtifactResourceUri


class RenderManifestOutput(StrictOutput):
    """Strict public page-render manifest."""

    render_id: RenderId
    source_sha256: Sha256
    renderer_version: Text256
    mode: Literal["native"]
    pages: Annotated[
        FrozenSequence[RenderedPageRecord],
        MinLen(1),
        MaxLen(8),
        OWN_SEQUENCE_VALIDATOR,
    ]
    manifest_relative_path: RelativePath
    manifest_asset_url: HttpUrl
    resource_uri: RenderManifestResourceUri


class RenderPagesOutput(RenderManifestOutput):
    """Strict public render result bound to its source artifact."""

    artifact_id: ArtifactId


class RenderedTileRecord(StrictOutput):
    """One bounded crop-only JPEG tile and its provenance."""

    tile_id: Text128
    page_number: PageNumber
    x: NonnegativeInteger
    y: NonnegativeInteger
    width: PositiveInteger
    height: PositiveInteger
    full_page_width: PositiveInteger
    full_page_height: PositiveInteger
    overlap: TileOverlap
    relative_path: RelativePath
    sha256: Sha256
    media_type: Literal["image/jpeg"]
    resize_applied: Literal[False]
    pixel_dimensions_preserved: Literal[True]
    renderer_resampling: Literal["none"]
    reencoded: Literal[True]
    lossy_conversion: Literal[True]
    asset_url: HttpUrl
    resource_uri: ArtifactResourceUri


class RenderTilesOutput(StrictOutput):
    """Strict public crop-only tile manifest."""

    render_id: RenderId
    page_number: PageNumber
    page_sha256: Sha256
    tile_width: TileDimension
    tile_height: TileDimension
    overlap: TileOverlap
    tiles: Annotated[
        FrozenSequence[RenderedTileRecord],
        MinLen(1),
        MaxLen(4096),
        OWN_SEQUENCE_VALIDATOR,
    ]
    manifest_relative_path: RelativePath
    manifest_asset_url: HttpUrl
    resource_uri: ArtifactResourceUri
