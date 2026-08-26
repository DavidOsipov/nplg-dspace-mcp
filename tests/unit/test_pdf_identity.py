# Copyright (c) 2026 David Osipov
"""Tests for explicit PDF pipeline-semantic cache identities."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nplg_mcp.pdf_identity import (
    PDF_PIPELINE_VERSIONS,
    PdfPipelineVersions,
    RenderIdentityRequest,
    TileGeometryRequest,
    render_identifier,
    tile_geometry_identifier,
)


def _pipeline_payload() -> dict[str, object]:
    return {
        "manifest_schema_version": (PDF_PIPELINE_VERSIONS.manifest_schema_version),
        "render_pipeline_version": PDF_PIPELINE_VERSIONS.render_pipeline_version,
        "classification_algorithm_version": (
            PDF_PIPELINE_VERSIONS.classification_algorithm_version
        ),
        "tile_pipeline_version": PDF_PIPELINE_VERSIONS.tile_pipeline_version,
    }


def _render_id(versions: PdfPipelineVersions) -> str:
    return render_identifier(
        RenderIdentityRequest(
            source_sha256="a" * 64,
            pages=(1, 3),
            mode="native",
            renderer_version="renderer-1",
            fallback_dpi=400,
            pipeline_versions=versions,
        )
    )


@pytest.mark.parametrize(
    "field",
    [
        "manifest_schema_version",
        "render_pipeline_version",
        "classification_algorithm_version",
        "tile_pipeline_version",
    ],
)
def test_every_pdf_semantic_version_changes_the_render_identity(field: str) -> None:
    changed = _pipeline_payload()
    changed[field] = "2.0.0"
    changed_versions = PdfPipelineVersions.model_validate(changed, strict=True)

    assert _render_id(changed_versions) != _render_id(PDF_PIPELINE_VERSIONS)


def test_tile_semantic_version_changes_the_geometry_cache_identity() -> None:
    changed = PdfPipelineVersions(
        manifest_schema_version="1.0.0",
        render_pipeline_version="1.0.0",
        classification_algorithm_version="1.0.0",
        tile_pipeline_version="2.0.0",
    )

    assert tile_geometry_identifier(
        TileGeometryRequest(
            width=2048,
            height=1024,
            overlap=128,
            pipeline_versions=changed,
        )
    ) != tile_geometry_identifier(
        TileGeometryRequest(
            width=2048,
            height=1024,
            overlap=128,
            pipeline_versions=PDF_PIPELINE_VERSIONS,
        )
    )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("manifest_schema_version", 1),
        ("render_pipeline_version", "v1"),
        ("classification_algorithm_version", "01.0.0"),
        ("tile_pipeline_version", "1.0.0 "),
    ],
)
def test_pdf_semantic_versions_reject_coercion_and_noncanonical_values(
    field: str,
    bad_value: object,
) -> None:
    payload = _pipeline_payload()
    payload[field] = bad_value

    with pytest.raises(ValidationError):
        _ = PdfPipelineVersions.model_validate(payload, strict=True)


def test_pdf_semantic_versions_reject_unknown_fields() -> None:
    payload = _pipeline_payload()
    payload["unreviewed_pipeline"] = "1.0.0"

    with pytest.raises(ValidationError):
        _ = PdfPipelineVersions.model_validate(payload, strict=True)
