# Copyright (c) 2026 David Osipov
"""Unit tests for PDF tile geometry."""

import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.pdf import tile_boxes

_PAGE_WIDTH = 5000
_PAGE_HEIGHT = 3300
_TILE_STRIDE = 1920
_LAST_TILE_X = 3840
_LAST_TILE_WIDTH = 1160
_LAST_TILE_HEIGHT = 1380


def test_tiles_are_row_major_crop_only_and_cover_every_pixel() -> None:
    boxes = tile_boxes(
        _PAGE_WIDTH,
        _PAGE_HEIGHT,
        tile_width=2048,
        tile_height=2048,
        overlap=128,
    )

    assert [(box.x, box.y) for box in boxes[:3]] == [
        (0, 0),
        (_TILE_STRIDE, 0),
        (_LAST_TILE_X, 0),
    ]
    assert boxes[-1].x == _LAST_TILE_X
    assert boxes[-1].y == _TILE_STRIDE
    assert boxes[-1].width == _LAST_TILE_WIDTH
    assert boxes[-1].height == _LAST_TILE_HEIGHT
    assert all(box.x >= 0 and box.y >= 0 for box in boxes)
    assert all(
        box.x + box.width <= _PAGE_WIDTH and box.y + box.height <= _PAGE_HEIGHT
        for box in boxes
    )

    covered = bytearray(_PAGE_WIDTH * _PAGE_HEIGHT)
    for box in boxes:
        for y in range(box.y, box.y + box.height):
            start = y * _PAGE_WIDTH + box.x
            covered[start : start + box.width] = b"\x01" * box.width
    assert all(covered)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"width": 0, "height": 100, "tile_width": 10, "tile_height": 10, "overlap": 0},
        {
            "width": 100,
            "height": 100,
            "tile_width": 10,
            "tile_height": 10,
            "overlap": 10,
        },
        {
            "width": 100,
            "height": 100,
            "tile_width": -1,
            "tile_height": 10,
            "overlap": 0,
        },
        {
            "width": 5000,
            "height": 5000,
            "tile_width": 4097,
            "tile_height": 2048,
            "overlap": 0,
        },
        {
            "width": 5000,
            "height": 5000,
            "tile_width": 2048,
            "tile_height": 2048,
            "overlap": 513,
        },
    ],
)
def test_invalid_tile_geometry_fails_closed(kwargs: dict[str, int]) -> None:
    with pytest.raises(AppError) as raised:
        _ = tile_boxes(**kwargs)
    assert raised.value.code is ErrorCode.INVALID_INPUT
