# Copyright (c) 2026 David Osipov
"""Typed public error values and safe serialization."""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from .agent_workflow import AGENT_WORKFLOW_URI

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .json_types import JsonObject, JsonValue

_MAX_PUBLIC_DETAIL_DEPTH = 32
_MAX_PUBLIC_DETAIL_VALUES = 4_096
_MAX_PUBLIC_DETAIL_STRING_CODE_POINTS = 65_536
_MAX_PUBLIC_DETAIL_INTEGER_BITS = 256
_MAX_RESOURCE_URI_CODE_POINTS = 512
_CANONICAL_ARTIFACT_URI = re.compile(r"^nplg://artifact/doc_[0-9a-f]{64}$")
_CANONICAL_RENDER_MANIFEST_URI = re.compile(
    r"^nplg://render/rnd_[0-9a-f]{32}/manifest$"
)


class ErrorCode(StrEnum):
    """Stable machine-readable public error codes."""

    INVALID_INPUT = "INVALID_INPUT"
    NOT_FOUND = "NOT_FOUND"
    RESTRICTED = "RESTRICTED"
    UPSTREAM_FAILURE = "UPSTREAM_FAILURE"
    DOWNLOAD_TOO_LARGE = "DOWNLOAD_TOO_LARGE"
    INVALID_DOCUMENT = "INVALID_DOCUMENT"
    PDF_PROCESSING_FAILED = "PDF_PROCESSING_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    CACHE_FULL = "CACHE_FULL"
    UNAUTHORIZED = "UNAUTHORIZED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(slots=True)
class AppError(Exception):
    """Expected application failure with separate public and private context."""

    code: ErrorCode
    message: str
    http_status: int = 400
    safe_details: Mapping[str, object] | None = None
    internal_details: Mapping[str, object] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Initialize the base exception with the safe message."""
        Exception.__init__(self, self.message)


class _InvalidPublicDetailsError(ValueError):
    pass


class InvalidResourceUriError(ValueError):
    """A resource URI is not one of the bounded canonical project forms."""


def validate_resource_uri(uri: str) -> str:
    """Return one syntactically valid bounded canonical project resource URI."""
    if not 0 < len(uri) <= _MAX_RESOURCE_URI_CODE_POINTS:
        raise InvalidResourceUriError
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in uri):
        raise InvalidResourceUriError
    if (
        uri in {"nplg://about", AGENT_WORKFLOW_URI}
        or _CANONICAL_ARTIFACT_URI.fullmatch(uri) is not None
        or _CANONICAL_RENDER_MANIFEST_URI.fullmatch(uri) is not None
    ):
        return uri
    raise InvalidResourceUriError


@dataclass(slots=True)
class _SnapshotFrame:
    entries: tuple[tuple[object, object], ...]
    target: JsonObject | list[JsonValue]
    source_identity: int
    depth: int
    index: int = 0


def _internal_public_error() -> JsonObject:
    return {
        "code": ErrorCode.INTERNAL_ERROR.value,
        "message": "The server could not complete the request.",
    }


def _snapshot_frame(
    source: object,
    target: JsonObject | list[JsonValue],
    *,
    depth: int,
    remaining_values: int,
) -> _SnapshotFrame:
    if type(source) is dict:
        source_dict = cast("dict[object, object]", source)
        if len(source_dict) > remaining_values:
            raise _InvalidPublicDetailsError
        stable_dict = source_dict.copy()
        if len(stable_dict) > remaining_values:
            raise _InvalidPublicDetailsError
        entries = tuple(stable_dict.items())
        source_identity = id(source_dict)
    elif type(source) is list:
        source_list = cast("list[object]", source)
        if len(source_list) > remaining_values:
            raise _InvalidPublicDetailsError
        stable_list = source_list.copy()
        if len(stable_list) > remaining_values:
            raise _InvalidPublicDetailsError
        entries = tuple(enumerate(stable_list))
        source_identity = id(source_list)
    else:
        raise _InvalidPublicDetailsError
    return _SnapshotFrame(
        entries=entries,
        target=target,
        source_identity=source_identity,
        depth=depth,
    )


def _checked_string_total(current: int, value: str) -> int:
    updated = current + str.__len__(value)
    if updated > _MAX_PUBLIC_DETAIL_STRING_CODE_POINTS:
        raise _InvalidPublicDetailsError
    return updated


def _consume_public_detail_value(current: int) -> int:
    updated = current + 1
    if updated > _MAX_PUBLIC_DETAIL_VALUES:
        raise _InvalidPublicDetailsError
    return updated


def _snapshot_scalar(value: object, string_total: int) -> tuple[JsonValue, int]:
    if value is None:
        return None, string_total
    if type(value) is bool:
        return value, string_total
    if type(value) is int:
        integer = value
        if int.bit_length(integer) > _MAX_PUBLIC_DETAIL_INTEGER_BITS:
            raise _InvalidPublicDetailsError
        return integer, string_total
    if type(value) is float:
        number = value
        if not math.isfinite(number):
            raise _InvalidPublicDetailsError
        return number, string_total
    if type(value) is str:
        text = value
        return text, _checked_string_total(string_total, text)
    raise _InvalidPublicDetailsError


def _store_snapshot(
    target: JsonObject | list[JsonValue],
    key: object,
    value: JsonValue,
) -> None:
    if isinstance(target, list):
        target.append(value)
        return
    if type(key) is not str:
        raise _InvalidPublicDetailsError
    target[key] = value


def _snapshot_public_details(value: object) -> JsonObject:
    if type(value) is not dict:
        raise _InvalidPublicDetailsError
    source = cast("dict[object, object]", value)
    result: JsonObject = {}
    total_values = 1
    string_total = 0
    stack = [
        _snapshot_frame(
            source,
            result,
            depth=0,
            remaining_values=_MAX_PUBLIC_DETAIL_VALUES - total_values,
        )
    ]
    active_containers = {id(source)}
    while stack:
        frame = stack[-1]
        if frame.index >= len(frame.entries):
            active_containers.remove(frame.source_identity)
            _ = stack.pop()
            continue
        key, item = frame.entries[frame.index]
        frame.index += 1
        if type(frame.target) is dict:
            if type(key) is not str:
                raise _InvalidPublicDetailsError
            string_total = _checked_string_total(string_total, key)
        total_values = _consume_public_detail_value(total_values)
        if type(item) in {dict, list}:
            child_source = cast("dict[object, object] | list[object]", item)
            child_depth = frame.depth + 1
            if child_depth > _MAX_PUBLIC_DETAIL_DEPTH:
                raise _InvalidPublicDetailsError
            child_identity = id(child_source)
            if child_identity in active_containers:
                raise _InvalidPublicDetailsError
            child_target: JsonObject | list[JsonValue] = (
                {} if type(item) is dict else []
            )
            _store_snapshot(frame.target, key, child_target)
            child_frame = _snapshot_frame(
                child_source,
                child_target,
                depth=child_depth,
                remaining_values=_MAX_PUBLIC_DETAIL_VALUES - total_values,
            )
            active_containers.add(child_identity)
            stack.append(child_frame)
            continue
        snapshot, string_total = _snapshot_scalar(item, string_total)
        _store_snapshot(frame.target, key, snapshot)
    return result


def to_public_error(error: BaseException) -> JsonObject:
    """Return a strict JSON error while redacting private or invalid context."""
    if isinstance(error, AppError):
        result: JsonObject = {
            "code": error.code.value,
            "message": error.message,
        }
        if error.safe_details is not None:
            try:
                details = _snapshot_public_details(error.safe_details)
            except _InvalidPublicDetailsError:
                return _internal_public_error()
            if details:
                result["details"] = details
        return result
    return _internal_public_error()
