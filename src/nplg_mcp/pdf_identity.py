# Copyright (c) 2026 David Osipov
"""Pure deterministic identities shared by the PDF parent and worker."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

_SEMANTIC_VERSION_PATTERN = (
    r"^[1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})$"
)
SemanticVersion = Annotated[
    str,
    StringConstraints(
        min_length=5,
        max_length=11,
        pattern=_SEMANTIC_VERSION_PATTERN,
        strip_whitespace=False,
    ),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
PageNumber = Annotated[int, Field(strict=True, ge=1, le=100_000)]
PageSelection = Annotated[tuple[PageNumber, ...], Field(min_length=1, max_length=64)]
RendererVersion = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=256,
        pattern=r"^[\x21-\x7e]+$",
        strip_whitespace=False,
    ),
]
FallbackDpi = Annotated[int, Field(strict=True, ge=72, le=1_200)]
TileDimension = Annotated[int, Field(strict=True, ge=1, le=65_535)]
TileOverlap = Annotated[int, Field(strict=True, ge=0, le=65_535)]


class PdfPipelineVersions(BaseModel):
    """Closed semantic versions that invalidate persisted PDF derivatives."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    manifest_schema_version: SemanticVersion
    render_pipeline_version: SemanticVersion
    classification_algorithm_version: SemanticVersion
    tile_pipeline_version: SemanticVersion


PDF_PIPELINE_VERSIONS = PdfPipelineVersions(
    manifest_schema_version="1.0.0",
    render_pipeline_version="1.0.0",
    classification_algorithm_version="1.0.0",
    tile_pipeline_version="1.0.0",
)


class RenderIdentityRequest(BaseModel):
    """Closed input bundle for one deterministic render identity."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )

    source_sha256: Sha256
    pages: PageSelection
    mode: Literal["native"]
    renderer_version: RendererVersion
    fallback_dpi: FallbackDpi
    pipeline_versions: PdfPipelineVersions = PDF_PIPELINE_VERSIONS


def render_identifier(request: RenderIdentityRequest) -> str:
    """Bind one render root to its complete deterministic request identity."""
    validated = RenderIdentityRequest.model_validate_json(
        request.model_dump_json(),
        strict=True,
    )
    pipeline_versions = validated.pipeline_versions
    key = {
        "classification_algorithm_version": (
            pipeline_versions.classification_algorithm_version
        ),
        "fallback_dpi": validated.fallback_dpi,
        "manifest_schema_version": pipeline_versions.manifest_schema_version,
        "mode": validated.mode,
        "pages": list(validated.pages),
        "render_pipeline_version": pipeline_versions.render_pipeline_version,
        "renderer_version": validated.renderer_version,
        "source_sha256": validated.source_sha256,
        "tile_pipeline_version": pipeline_versions.tile_pipeline_version,
    }
    digest = hashlib.sha256(
        json.dumps(
            key,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return f"rnd_{digest[:32]}"


class TileGeometryRequest(BaseModel):
    """Closed input bundle for one deterministic tile geometry key."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )

    width: TileDimension
    height: TileDimension
    overlap: TileOverlap
    pipeline_versions: PdfPipelineVersions = PDF_PIPELINE_VERSIONS


def tile_geometry_identifier(request: TileGeometryRequest) -> str:
    """Return the closed, path-safe tile geometry and semantic cache key."""
    validated = TileGeometryRequest.model_validate_json(
        request.model_dump_json(),
        strict=True,
    )
    semantic_version = validated.pipeline_versions.tile_pipeline_version.replace(
        ".", "-"
    )
    return (
        f"tpv{semantic_version}-w{validated.width:04d}"
        f"-h{validated.height:04d}-o{validated.overlap:03d}"
    )
