# Copyright (c) 2026 David Osipov
"""Property tests for the closed PDF worker message grammar."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast
from uuid import UUID

import pytest
from hypothesis import given
from hypothesis import strategies as st

from nplg_mcp.pdf_ipc import (
    MAX_COMMAND_FRAME_BYTES,
    InspectCommand,
    InspectParams,
    PdfIpcError,
    RenderTilesParams,
    encode_frame,
    parse_command_frame,
    parse_result_frame,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from hypothesis.strategies import SearchStrategy


_ARBITRARY_FRAME_STRATEGY: SearchStrategy[bytes] = st.binary(max_size=1_024)
_GIVEN_ARBITRARY_FRAME = cast(
    "Callable[[Callable[[bytes], None]], Callable[[], None]]",
    given(frame=_ARBITRARY_FRAME_STRATEGY),
)


@_GIVEN_ARBITRARY_FRAME
def test_command_decoder_is_total_for_bounded_arbitrary_bytes(frame: bytes) -> None:
    """An arbitrary bounded frame must validate or fail with a safe exception."""
    try:
        result = parse_command_frame(frame)
    except (PdfIpcError, ValueError):
        return
    assert result.operation in {"inspect", "manifest", "render_pages", "render_tiles"}


@pytest.mark.parametrize(
    "path",
    [
        "../secret.pdf",
        "a/../../secret.pdf",
        "/absolute.pdf",
        "a\\b.pdf",
        "./source.pdf",
        "a//source.pdf",
        "a/source.pdf/",
        "%2e%2e/secret.pdf",
        "a/\x00.pdf",
        "a/line\nbreak.pdf",
    ],
)
def test_command_decoder_rejects_each_noncanonical_path(path: str) -> None:
    payload: dict[str, object] = {
        "request_id": "00000000-0000-4000-8000-000000000010",
        "operation": "inspect",
        "source_relative_path": path,
        "parameters": {},
    }
    frame = json.dumps(payload, separators=(",", ":")).encode()

    with pytest.raises(ValueError, match="relative path"):
        _ = parse_command_frame(frame)


def test_command_decoder_rejects_duplicate_keys_and_nonfinite_numbers() -> None:
    duplicate = (
        b'{"request_id":"00000000-0000-4000-8000-000000000011",'
        b'"operation":"inspect","operation":"render_pages",'
        b'"source_relative_path":"documents/source.pdf","parameters":{}}'
    )
    nonfinite = (
        b'{"request_id":"00000000-0000-4000-8000-000000000011",'
        b'"operation":"inspect","source_relative_path":"documents/source.pdf",'
        b'"parameters":{},"value":NaN}'
    )

    with pytest.raises(PdfIpcError, match="duplicate"):
        _ = parse_command_frame(duplicate)
    with pytest.raises(PdfIpcError, match="non-finite"):
        _ = parse_command_frame(nonfinite)


@pytest.mark.parametrize(
    ("tile_width", "tile_height", "overlap", "field"),
    [(256, None, 256, "tile_width"), (None, 256, 256, "tile_height")],
)
def test_tile_parameters_reject_overlap_consuming_an_explicit_dimension(
    tile_width: int | None,
    tile_height: int | None,
    overlap: int,
    field: str,
) -> None:
    with pytest.raises(ValueError, match=field):
        _ = RenderTilesParams(
            render_id="rnd_" + "0" * 32,
            page_number=1,
            tile_width=tile_width,
            tile_height=tile_height,
            overlap=overlap,
        )


@pytest.mark.parametrize(
    ("frame", "message"),
    [
        (b"\xef\xbb\xbf{}", "UTF-8 BOM"),
        (b"[" * 65 + b"0" + b"]" * 65, "structure exceeds"),
        (b"1e9999", "numbers must be finite"),
    ],
)
def test_command_decoder_rejects_bom_excessive_depth_and_infinite_exponents(
    frame: bytes,
    message: str,
) -> None:
    with pytest.raises(PdfIpcError, match=message):
        _ = parse_command_frame(frame)


def test_valid_command_round_trips_through_the_length_prefixed_encoding() -> None:
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000012"),
        operation="inspect",
        source_relative_path="documents/doc_" + "0" * 64 + "/source.pdf",
        parameters=InspectParams(),
    )

    frame = encode_frame(command, maximum=MAX_COMMAND_FRAME_BYTES)
    size = int.from_bytes(frame[:4], "big")

    assert size == len(frame) - 4
    assert parse_command_frame(frame[4:]) == command


def test_encoder_rejects_a_model_larger_than_its_explicit_frame_budget() -> None:
    command = InspectCommand(
        request_id=UUID("00000000-0000-4000-8000-000000000013"),
        operation="inspect",
        source_relative_path="documents/source.pdf",
        parameters=InspectParams(),
    )

    with pytest.raises(PdfIpcError, match="frame length"):
        _ = encode_frame(command, maximum=1)


@pytest.mark.parametrize(
    "frame",
    [
        (
            b'{"request_id":"00000000-0000-4000-8000-000000000016",'
            b'"operation":"inspect","source_relative_path":"documents/source.pdf",'
            b'"parameters":{"pages":[1],"mode":"native"}}'
        ),
        (
            b'{"request_id":"00000000-0000-4000-8000-000000000016",'
            b'"operation":"manifest","source_relative_path":"documents/source.pdf",'
            b'"parameters":{"render_id":"rnd_00000000000000000000000000000000"}}'
        ),
    ],
)
def test_command_decoder_rejects_impossible_operation_parameter_pairs(
    frame: bytes,
) -> None:
    """A discriminator must never accept another operation's fields."""
    with pytest.raises(ValueError, match="validation error"):
        _ = parse_command_frame(frame)


@pytest.mark.parametrize(
    "frame",
    [
        (
            b'{"request_id":"00000000-0000-4000-8000-000000000017",'
            b'"status":"ok","operation":"inspect","payload":{}}'
        ),
        (
            b'{"request_id":"00000000-0000-4000-8000-000000000017",'
            b'"status":"error","payload":{"operation":"inspect"}}'
        ),
    ],
)
def test_result_decoder_rejects_impossible_status_payload_pairs(frame: bytes) -> None:
    """Success and failure envelopes cannot be cross-wired."""
    with pytest.raises(ValueError, match="validation error"):
        _ = parse_result_frame(frame)
