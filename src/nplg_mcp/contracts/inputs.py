# Copyright (c) 2026 David Osipov
"""Strict public input contracts for every NPLG MCP tool."""

from __future__ import annotations

from typing import Annotated, Literal, LiteralString

from annotated_types import Ge, Le
from pydantic import (
    AfterValidator,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
)
from pydantic_core import PydanticCustomError

from nplg_mcp.config import HARD_MAX_TILE_DIMENSION, HARD_MAX_TILE_OVERLAP

from .base import (
    NON_BLANK_SAFE_TEXT_PATTERN,
    OWN_SEQUENCE_VALIDATOR,
    SAFE_INTEGER_VALIDATOR,
    ContractText,
    FrozenSequence,
    StrictInput,
    reject_unsafe_text,
)

_MIN_RENDER_PAGES = 1
_MAX_RENDER_PAGES = 8
_MIN_TILE_DIMENSION = 256

Handle = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=128,
        pattern=r"^[1-9][0-9]{0,31}\/[1-9][0-9]{0,31}$",
    ),
    Field(description="Canonical NPLG DSpace handle."),
]
BitstreamId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._~-]{1,128}$",
    ),
]
ArtifactId = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^doc_[0-9a-f]{64}$"),
]
RenderId = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^rnd_[0-9a-f]{32}$"),
]
PageNumber = Annotated[int, Ge(1), Le(10_000), SAFE_INTEGER_VALIDATOR]
PageSize = Annotated[int, Ge(1), Le(50), SAFE_INTEGER_VALIDATOR]
TileDimension = Annotated[
    int,
    Ge(_MIN_TILE_DIMENSION),
    Le(HARD_MAX_TILE_DIMENSION),
    SAFE_INTEGER_VALIDATOR,
]
TileOverlap = Annotated[
    int,
    Ge(0),
    Le(HARD_MAX_TILE_OVERLAP),
    SAFE_INTEGER_VALIDATOR,
]


def _validate_page_selection_length(
    value: FrozenSequence[PageNumber],
) -> FrozenSequence[PageNumber]:
    """Enforce the bounded page count after every page itself is valid."""
    if len(value) < _MIN_RENDER_PAGES:
        error_type = "too_short"
        too_short_message = "Tuple should have at least 1 item after validation, not 0"
        raise PydanticCustomError(error_type, too_short_message)
    if len(value) > _MAX_RENDER_PAGES:
        error_type = "too_long"
        too_long_message: LiteralString = (
            "Tuple should have at most 8 items after validation"
        )
        raise PydanticCustomError(error_type, too_long_message)
    return value


PageSelection = Annotated[
    FrozenSequence[PageNumber],
    OWN_SEQUENCE_VALIDATOR,
    AfterValidator(_validate_page_selection_length),
    WithJsonSchema(
        {
            "items": {"maximum": 10_000, "minimum": 1, "type": "integer"},
            "maxItems": _MAX_RENDER_PAGES,
            "minItems": _MIN_RENDER_PAGES,
            "type": "array",
        }
    ),
]


class SearchDocumentsInput(StrictInput):
    """Validated input for repository search."""

    query: Annotated[
        str,
        StringConstraints(
            strict=True,
            min_length=1,
            max_length=500,
            pattern=NON_BLANK_SAFE_TEXT_PATTERN,
        ),
        AfterValidator(reject_unsafe_text),
        Field(description="Search terms sent to the NPLG repository."),
    ]
    cursor: Annotated[
        Annotated[
            ContractText,
            StringConstraints(min_length=0, max_length=1_024),
        ]
        | None,
        Field(
            description=(
                "Opaque continuation cursor returned by a previous identical search."
            )
        ),
    ] = None
    page_size: Annotated[
        PageSize,
        Field(description="Maximum number of results to return, from 1 through 50."),
    ] = 20
    scope_handle: Annotated[
        Handle | None,
        Field(
            description=(
                "Optional canonical NPLG collection or community handle that limits "
                "the search."
            )
        ),
    ] = None

    @field_validator("query")
    @classmethod
    def non_blank_query(cls, value: str) -> str:
        """Reject an empty search query without transforming repository input."""
        if not value.strip():
            message = "query must contain non-whitespace characters"
            raise ValueError(message)
        return reject_unsafe_text(value)


class HandleInput(StrictInput):
    """Validated canonical-handle input."""

    handle: Handle


class DownloadDocumentInput(HandleInput):
    """Validated input for one discovered document bitstream."""

    bitstream_id: BitstreamId


class ArtifactInput(StrictInput):
    """Validated content-addressed document identifier."""

    artifact_id: ArtifactId


class RenderPagesInput(ArtifactInput):
    """Validated page-render request."""

    pages: PageSelection
    mode: Literal["native"] = "native"


class RenderTilesInput(StrictInput):
    """Validated crop-only tile request."""

    render_id: RenderId
    page_number: PageNumber
    tile_width: TileDimension | None = None
    tile_height: TileDimension | None = None
    overlap: TileOverlap | None = None


class RenderIdInput(StrictInput):
    """Validated deterministic render identifier."""

    render_id: RenderId
