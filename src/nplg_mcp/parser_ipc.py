# Copyright (c) 2026 David Osipov
"""Strict, bounded messages for disposable metadata-parser processes."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID  # noqa: TC003 - Pydantic resolves this runtime field type.

from pydantic import Field, StringConstraints, TypeAdapter

from .contracts import StrictModel
from .errors import ErrorCode  # noqa: TC001 - Pydantic resolves the runtime enum.
from .json_preflight import JsonPreflightLimits, preflight_json
from .parsers import (  # noqa: TC001 - Pydantic resolves runtime dataclass fields.
    DocumentRecord,
    SearchPage,
)

MAX_PARSER_COMMAND_BYTES = 4 * 1024 * 1024
MAX_PARSER_RESULT_BYTES = 4 * 1024 * 1024
_MAX_ERROR_MESSAGE_CODE_POINTS = 512

type ParserOperation = Literal[
    "search",
    "search_version",
    "item",
    "metadata_formats",
    "oai_record",
]

Markup = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=MAX_PARSER_COMMAND_BYTES,
    ),
]
SourceUrl = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=2_048),
]
Handle = Annotated[
    str,
    StringConstraints(strict=True, min_length=3, max_length=256),
]
MetadataPrefix = Literal["dim", "oai_dc"]
SearchVersion = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=10,
        max_length=10,
        pattern=r"^ex[0-9]{8}$",
    ),
]


class ParserIpcError(ValueError):
    """Reject malformed, ambiguous, or out-of-policy parser messages."""


class SearchCommand(StrictModel):
    """Parse one bounded repository-search HTML response."""

    request_id: UUID
    operation: Literal["search"]
    markup: Markup
    source_url: SourceUrl
    page_size: Annotated[int, Field(strict=True, ge=1, le=50)]


class SearchVersionCommand(StrictModel):
    """Parse one bounded queryless repository-search HTML response."""

    request_id: UUID
    operation: Literal["search_version"]
    markup: Markup
    source_url: SourceUrl


class ItemCommand(StrictModel):
    """Parse one bounded repository-item HTML response."""

    request_id: UUID
    operation: Literal["item"]
    markup: Markup
    expected_handle: Handle
    source_url: SourceUrl


class MetadataFormatsCommand(StrictModel):
    """Parse one bounded OAI-PMH metadata-format response."""

    request_id: UUID
    operation: Literal["metadata_formats"]
    markup: Markup


class OaiRecordCommand(StrictModel):
    """Parse one bounded OAI-PMH record response."""

    request_id: UUID
    operation: Literal["oai_record"]
    markup: Markup
    expected_handle: Handle
    metadata_prefix: MetadataPrefix


type ParserCommand = Annotated[
    SearchCommand
    | SearchVersionCommand
    | ItemCommand
    | MetadataFormatsCommand
    | OaiRecordCommand,
    Field(discriminator="operation"),
]


class SearchPayload(StrictModel):
    """Successful repository-search parse result."""

    operation: Literal["search"]
    value: SearchPage


class SearchVersionPayload(StrictModel):
    """Successful repository search-version parse result."""

    operation: Literal["search_version"]
    value: SearchVersion


class ItemPayload(StrictModel):
    """Successful repository-item parse result."""

    operation: Literal["item"]
    value: DocumentRecord


class MetadataFormatsPayload(StrictModel):
    """Successful OAI-PMH format-discovery parse result."""

    operation: Literal["metadata_formats"]
    value: Annotated[tuple[str, ...], Field(min_length=1, max_length=64)]


class OaiRecordPayload(StrictModel):
    """Successful OAI-PMH record parse result."""

    operation: Literal["oai_record"]
    value: DocumentRecord


type ParserPayload = Annotated[
    SearchPayload
    | SearchVersionPayload
    | ItemPayload
    | MetadataFormatsPayload
    | OaiRecordPayload,
    Field(discriminator="operation"),
]


class ParserErrorDetails(StrictModel):
    """Closed set of public parser details allowed across the process boundary."""

    source_url: SourceUrl | None = None
    oai_error: Annotated[
        str | None,
        StringConstraints(strict=True, min_length=1, max_length=128),
    ] = None
    metadata_prefix: Annotated[
        str | None,
        StringConstraints(strict=True, min_length=1, max_length=64),
    ] = None

    def as_public_mapping(self) -> dict[str, str]:
        """Return only populated, schema-owned public detail fields."""
        result: dict[str, str] = {}
        if self.source_url is not None:
            result["source_url"] = self.source_url
        if self.oai_error is not None:
            result["oai_error"] = self.oai_error
        if self.metadata_prefix is not None:
            result["metadata_prefix"] = self.metadata_prefix
        return result


class ParserPublicError(StrictModel):
    """Bounded expected failure emitted by the disposable parser."""

    code: ErrorCode
    message: Annotated[
        str,
        StringConstraints(
            strict=True,
            min_length=1,
            max_length=_MAX_ERROR_MESSAGE_CODE_POINTS,
        ),
    ]
    http_status: Annotated[int, Field(strict=True, ge=400, le=599)]
    details: ParserErrorDetails | None = None


class ParserSuccess(StrictModel):
    """Successful parser-process result."""

    request_id: UUID
    status: Literal["ok"]
    payload: ParserPayload


class ParserFailure(StrictModel):
    """Expected parser-process failure."""

    request_id: UUID
    status: Literal["error"]
    operation: ParserOperation
    payload: ParserPublicError


type ParserResult = Annotated[
    ParserSuccess | ParserFailure,
    Field(discriminator="status"),
]

_COMMAND_ADAPTER: TypeAdapter[ParserCommand] = TypeAdapter(ParserCommand)
_RESULT_ADAPTER: TypeAdapter[ParserResult] = TypeAdapter(ParserResult)


def _preflight_frame(frame: bytes, *, maximum: int) -> None:
    if not frame or len(frame) > maximum:
        message = "parser frame length is outside the allowed range"
        raise ParserIpcError(message)
    try:
        preflight_json(
            frame,
            limits=JsonPreflightLimits(
                max_body_bytes=maximum,
                max_depth=64,
                max_object_members=64,
                max_array_items=4_096,
                max_tokens=100_000,
                max_key_bytes=128,
                max_scalar_bytes=maximum,
                max_integer_digits=32,
                max_exponent_magnitude=0,
            ),
        )
    except ValueError as exc:
        message = "parser frame is not valid bounded JSON"
        raise ParserIpcError(message) from exc


def encode_parser_frame(model: StrictModel, *, maximum: int) -> bytes:
    """Encode one strict model as canonical bounded UTF-8 JSON."""
    frame = model.model_dump_json().encode("utf-8")
    if not frame or len(frame) > maximum:
        message = "parser frame length is outside the allowed range"
        raise ParserIpcError(message)
    return frame


def parse_command_frame(frame: bytes) -> ParserCommand:
    """Validate one canonical parser command without coercion."""
    _preflight_frame(frame, maximum=MAX_PARSER_COMMAND_BYTES)
    try:
        command = _COMMAND_ADAPTER.validate_json(frame, strict=True)
    except ValueError as exc:
        message = "parser command failed strict validation"
        raise ParserIpcError(message) from exc
    if _COMMAND_ADAPTER.dump_json(command) != frame:
        message = "parser command is not canonical"
        raise ParserIpcError(message)
    return command


def parse_result_frame(frame: bytes) -> ParserResult:
    """Validate one canonical parser result without coercion."""
    _preflight_frame(frame, maximum=MAX_PARSER_RESULT_BYTES)
    try:
        result = _RESULT_ADAPTER.validate_json(frame, strict=True)
    except ValueError as exc:
        message = "parser result failed strict validation"
        raise ParserIpcError(message) from exc
    if _RESULT_ADAPTER.dump_json(result) != frame:
        message = "parser result is not canonical"
        raise ParserIpcError(message)
    return result
