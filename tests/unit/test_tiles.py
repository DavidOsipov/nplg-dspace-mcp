import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.pdf import tile_boxes


def test_tiles_are_row_major_crop_only_and_cover_every_pixel() -> None:
    boxes = tile_boxes(5000, 3300, tile_width=2048, tile_height=2048, overlap=128)

    assert [(box.x, box.y) for box in boxes[:3]] == [(0, 0), (1920, 0), (3840, 0)]
    assert boxes[-1].x == 3840
    assert boxes[-1].y == 1920
    assert boxes[-1].width == 1160
    assert boxes[-1].height == 1380
    assert all(box.x >= 0 and box.y >= 0 for box in boxes)
    assert all(box.x + box.width <= 5000 and box.y + box.height <= 3300 for box in boxes)

    covered = bytearray(5000 * 3300)
    for box in boxes:
        for y in range(box.y, box.y + box.height):
            start = y * 5000 + box.x
            covered[start : start + box.width] = b"\x01" * box.width
    assert all(covered)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"width": 0, "height": 100, "tile_width": 10, "tile_height": 10, "overlap": 0},
        {"width": 100, "height": 100, "tile_width": 10, "tile_height": 10, "overlap": 10},
        {"width": 100, "height": 100, "tile_width": -1, "tile_height": 10, "overlap": 0},
        {"width": 5000, "height": 5000, "tile_width": 4097, "tile_height": 2048, "overlap": 0},
        {"width": 5000, "height": 5000, "tile_width": 2048, "tile_height": 2048, "overlap": 513},
    ],
)
def test_invalid_tile_geometry_fails_closed(kwargs: dict[str, int]) -> None:
    with pytest.raises(AppError) as raised:
        tile_boxes(**kwargs)
    assert raised.value.code is ErrorCode.INVALID_INPUT
