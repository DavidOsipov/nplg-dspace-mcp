# Copyright (c) 2026 David Osipov
"""Lightweight structural contract for bounded PDF postprocessing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from contextlib import AbstractAsyncContextManager

MAX_RENDER_RESOURCE_INDEX_BYTES = 4096


@runtime_checkable
class PdfPostprocessingReservationAuthority(Protocol):
    """Typed capability for one bounded post-render publication window."""

    def reserve_postprocessing_publication(
        self,
        *,
        maximum_index_files: int,
    ) -> AbstractAsyncContextManager[None]:
        """Reserve index capacity before dispatch through final validation."""
        ...
