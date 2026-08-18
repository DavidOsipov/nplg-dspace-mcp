# Copyright (c) 2026 David Osipov
from collections.abc import Buffer, Iterator, Sequence
from pathlib import Path
from typing import Protocol, Self, TypedDict, Unpack, runtime_checkable

from PIL.Image import Image

PDFIUM_INFO: object
PYPDFIUM_INFO: object

class PdfiumError(Exception): ...

class PdfBitmap(Protocol):
    width: int
    height: int

    def to_pil(self) -> Image: ...
    def close(self, _by_parent: bool = False) -> bool: ...

class PdfTextPage(Protocol):
    def count_chars(self) -> int: ...
    def get_text_range(
        self, index: int = 0, count: int = -1, errors: str = "ignore"
    ) -> str: ...
    def close(self, _by_parent: bool = False) -> bool: ...

@runtime_checkable
class PdfObject(Protocol):
    type: int

    def get_bounds(self) -> tuple[float, float, float, float]: ...
    def close(self, _by_parent: bool = False) -> bool: ...

@runtime_checkable
class PdfImage(PdfObject, Protocol):
    def get_px_size(self) -> tuple[int, int]: ...
    def get_filters(self, skip_simple: bool = False) -> list[str]: ...
    def get_data(self, decode_simple: bool = False) -> Buffer: ...
    def get_bitmap(
        self, render: bool = False, scale_to_original: bool = True
    ) -> PdfBitmap: ...

class _RenderKwargs(TypedDict, total=False):
    rev_byteorder: bool
    fill_color: tuple[int, int, int, int] | None
    draw_annots: bool

class PdfPage(Protocol):
    def get_size(self) -> tuple[float, float]: ...
    def get_cropbox(
        self, fallback_ok: bool = True
    ) -> tuple[float, float, float, float]: ...
    def get_mediabox(
        self, fallback_ok: bool = True
    ) -> tuple[float, float, float, float]: ...
    def get_rotation(self) -> int: ...
    def get_objects(
        self,
        # pypdfium2 5.8.0 exposes `filter`; renaming it would break keyword parity.
        filter: Sequence[int] | None = None,  # noqa: A002
        max_depth: int = 15,
        form: PdfObject | None = None,
        level: int = 0,
        textpage: PdfTextPage | None = None,
    ) -> Iterator[PdfObject]: ...
    def get_textpage(self) -> PdfTextPage: ...
    def render(
        self,
        scale: float = 1,
        rotation: int = 0,
        crop: Sequence[float] = (0, 0, 0, 0),
        may_draw_forms: bool = True,
        bitmap_maker: object = ...,
        color_scheme: object | None = None,
        fill_to_stroke: bool = False,
        **kwargs: Unpack[_RenderKwargs],
    ) -> PdfBitmap: ...
    def close(self, _by_parent: bool = False) -> bool: ...

class PdfDocument:
    def __init__(
        self,
        # pypdfium2 5.8.0 exposes `input`; renaming it would break keyword parity.
        input: str | Path | bytes,  # noqa: A002
        password: str | bytes | None = None,
        autoclose: bool = False,
    ) -> None: ...
    def __len__(self) -> int: ...
    def __getitem__(self, i: int) -> PdfPage: ...
    def close(self, _by_parent: bool = False) -> bool: ...
    def __enter__(self) -> Self: ...
    def __exit__(self, *_: object) -> None: ...
