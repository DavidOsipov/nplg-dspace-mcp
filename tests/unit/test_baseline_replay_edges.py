# Copyright (c) 2026 David Osipov
"""Adversarial identity-boundary tests for frozen baseline replay."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Literal, Protocol, cast

import pytest

from nplg_mcp.pdf_identity import TileGeometryRequest, tile_geometry_identifier
from scripts import baseline_capture_io, baseline_replay

if TYPE_CHECKING:
    from pathlib import Path


class _ValidateSetupAllocation(Protocol):
    def __call__(
        self,
        root: Path,
        setup: (
            baseline_replay.EmptyReplaySetup
            | baseline_replay.DocumentReplaySetup
            | baseline_replay.RenderReplaySetup
        ),
        *,
        live_render_id: str | None = None,
    ) -> None: ...


class _NormalizeToolRenderIdentity(Protocol):
    def __call__(
        self,
        copied: baseline_replay.ReplayJsonObject,
        *,
        name: object,
        live: bool,
        expected_live_render_id: str | None,
    ) -> baseline_replay.ReplayJsonObject: ...


class _RenderIdentityFromResult(Protocol):
    def __call__(self, copied: baseline_replay.ReplayJsonObject) -> str: ...


class _NormalizeTileGeometryIdentity(Protocol):
    def __call__(
        self,
        copied: baseline_replay.ReplayJsonObject,
        *,
        live: bool,
    ) -> baseline_replay.ReplayJsonObject: ...


class _MatchesRenderResource(Protocol):
    def __call__(self, live_contents: object, frozen_contents: object) -> bool: ...


def _private(name: str) -> object:
    """Resolve a deliberately pressure-tested private replay boundary."""
    return cast(
        "object",
        object.__getattribute__(baseline_replay, f"_{name}"),
    )


def _render_setup() -> baseline_replay.RenderReplaySetup:
    return baseline_replay.RenderReplaySetup(
        kind="render",
        handle="1234/560449",
        bitstream_id="bs_public",
        artifact_id=baseline_replay.FIXED_ARTIFACT_ID,
        render_id=baseline_replay.FIXED_RENDER_ID,
        pages=(1,),
        mode="native",
    )


def _valid_live_tile_result() -> baseline_replay.ReplayJsonObject:
    width = 512
    height = 384
    overlap = 8
    geometry = tile_geometry_identifier(
        TileGeometryRequest(width=width, height=height, overlap=overlap),
    )
    return {
        "tile_width": width,
        "tile_height": height,
        "overlap": overlap,
        "manifest_relative_path": f"renders/current/{geometry}/manifest.json",
        "tiles": [
            {
                "tile_id": f"page-1/{geometry}/0-0",
                "relative_path": f"renders/current/{geometry}/tile-0-0.jpg",
            },
        ],
    }


def test_setup_allocation_requires_render_identity_only_for_render_cases(
    tmp_path: Path,
) -> None:
    validate = cast(
        "_ValidateSetupAllocation",
        _private("validate_setup_allocation"),
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="omitted its live version-bound identity",
    ):
        validate(tmp_path, _render_setup())

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="non-render replay setup",
    ):
        validate(
            tmp_path,
            baseline_replay.EmptyReplaySetup(kind="empty"),
            live_render_id="rnd_" + ("1" * 32),
        )


def test_render_normalization_requires_strict_render_id() -> None:
    normalize = cast(
        "_NormalizeToolRenderIdentity",
        _private("normalize_tool_render_identity"),
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="omitted its strict identity",
    ):
        _ = normalize(
            {},
            name="render_pdf_pages",
            live=True,
            expected_live_render_id="rnd_" + ("1" * 32),
        )


@pytest.mark.parametrize(
    ("mode", "render_id", "expected", "message"),
    [
        (
            "live",
            "rnd_" + ("1" * 32),
            "rnd_" + ("2" * 32),
            "live render result changed",
        ),
        (
            "frozen",
            "rnd_" + ("1" * 32),
            None,
            "frozen render oracle changed",
        ),
    ],
)
def test_render_normalization_rejects_live_and_frozen_identity_drift(
    mode: Literal["live", "frozen"],
    render_id: str,
    expected: str | None,
    message: str,
) -> None:
    normalize = cast(
        "_NormalizeToolRenderIdentity",
        _private("normalize_tool_render_identity"),
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match=message):
        _ = normalize(
            {"render_id": render_id},
            name="render_pdf_pages",
            live=mode == "live",
            expected_live_render_id=expected,
        )


def test_render_normalization_fails_closed_if_internal_replacement_loses_object_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalize = cast(
        "_NormalizeToolRenderIdentity",
        _private("normalize_tool_render_identity"),
    )

    def non_object_replacement(
        _value: baseline_replay.ReplayJsonValue,
        *,
        render_id: str,
    ) -> baseline_replay.ReplayJsonValue:
        del render_id
        return []

    monkeypatch.setattr(
        baseline_replay,
        "_replace_render_identifier",
        non_object_replacement,
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="normalized render result is not an object",
    ):
        _ = normalize(
            {"render_id": baseline_replay.FIXED_RENDER_ID},
            name="render_pdf_pages",
            live=False,
            expected_live_render_id=None,
        )


def test_render_identity_rejects_incomplete_public_result() -> None:
    derive = cast(
        "_RenderIdentityFromResult",
        _private("render_identity_from_result"),
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="cannot establish",
    ):
        _ = derive({"pages": "not-a-list"})


@pytest.mark.parametrize(
    "pages",
    [
        ["not-an-object"],
        [{"page_number": True}],
    ],
)
def test_render_identity_rejects_nonobject_and_coerced_page_numbers(
    pages: list[baseline_replay.ReplayJsonValue],
) -> None:
    derive = cast(
        "_RenderIdentityFromResult",
        _private("render_identity_from_result"),
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="invalid identity input",
    ):
        _ = derive(
            {
                "pages": pages,
                "source_sha256": "a" * 64,
                "mode": "native",
                "renderer_version": "test-renderer/1.0",
            },
        )


def test_tile_normalization_requires_noncoerced_geometry() -> None:
    normalize = cast(
        "_NormalizeTileGeometryIdentity",
        _private("normalize_tile_geometry_identity"),
    )
    result = _valid_live_tile_result()
    result["tile_width"] = True

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="strict geometry",
    ):
        _ = normalize(result, live=True)


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("manifest", "geometry-bound manifest path"),
        ("record", "invalid tile record"),
        ("identity", "geometry-bound tile identity"),
    ],
)
def test_tile_normalization_rejects_unbound_manifest_and_tile_records(
    fault: str,
    message: str,
) -> None:
    normalize = cast(
        "_NormalizeTileGeometryIdentity",
        _private("normalize_tile_geometry_identity"),
    )
    result = _valid_live_tile_result()
    if fault == "manifest":
        result["manifest_relative_path"] = "renders/unbound/manifest.json"
    elif fault == "record":
        result["tiles"] = ["not-an-object"]
    else:
        result["tiles"] = [{"tile_id": "unbound", "relative_path": "unbound"}]

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match=message):
        _ = normalize(result, live=True)


def test_tile_normalization_fails_closed_if_internal_replacement_loses_object_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalize = cast(
        "_NormalizeTileGeometryIdentity",
        _private("normalize_tile_geometry_identity"),
    )

    def non_object_replacement(
        _value: baseline_replay.ReplayJsonValue,
        *,
        old: str,
        new: str,
    ) -> baseline_replay.ReplayJsonValue:
        del old, new
        return []

    monkeypatch.setattr(
        baseline_replay,
        "_replace_json_string_token",
        non_object_replacement,
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="normalized tile result is not an object",
    ):
        _ = normalize(_valid_live_tile_result(), live=True)


def test_render_resource_comparison_rejects_non_version_bound_live_identity() -> None:
    matches = cast(
        "_MatchesRenderResource",
        _private("matches_render_resource"),
    )
    page_digest = "b" * 64
    live_page: baseline_replay.ReplayJsonObject = {
        "page_number": 1,
        "sha256": page_digest,
        "resource_uri": f"nplg://artifact/doc_{page_digest}",
    }
    frozen_page: baseline_replay.ReplayJsonObject = {
        "page_number": 1,
        "sha256": page_digest,
    }
    live_render_id = "rnd_" + ("0" * 32)
    live_manifest: baseline_replay.ReplayJsonObject = {
        "render_id": live_render_id,
        "pages": [live_page],
        "source_sha256": "a" * 64,
        "mode": "native",
        "renderer_version": "test-renderer/1.0",
    }
    frozen_manifest: baseline_replay.ReplayJsonObject = {
        "render_id": baseline_replay.FIXED_RENDER_ID,
        "pages": [frozen_page],
        "source_sha256": "a" * 64,
        "mode": "native",
        "renderer_version": "test-renderer/1.0",
    }
    live_contents: list[baseline_replay.ReplayJsonValue] = [
        {
            "uri": f"nplg://render/{live_render_id}/manifest",
            "mimeType": "application/json",
            "text": json.dumps(live_manifest, sort_keys=True),
        },
    ]
    frozen_contents: list[baseline_replay.ReplayJsonValue] = [
        {
            "uri": f"nplg://render/{baseline_replay.FIXED_RENDER_ID}/manifest",
            "mimeType": "application/json",
            "text": json.dumps(frozen_manifest, sort_keys=True),
        },
    ]

    assert not matches(live_contents, frozen_contents)
