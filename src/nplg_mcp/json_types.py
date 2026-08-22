# Copyright (c) 2026 David Osipov
"""Closed JSON value types used at protocol and serialization boundaries."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import asdict
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing import TypeGuard

    from _typeshed import DataclassInstance

type JsonPrimitive = bool | int | float | str | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
type JsonObjectHook = Callable[[list[tuple[str, object]]], JsonObject]
type JsonConstantHook = Callable[[str], None]
type JsonFloatHook = Callable[[str], float]


def is_json_value(value: object) -> TypeGuard[JsonValue]:
    """Return whether *value* is composed only of JSON-compatible values."""
    if value is None or type(value) in {bool, int, str}:
        return True
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, list):
        items = cast("list[object]", value)
        return all(is_json_value(item) for item in items)
    if isinstance(value, dict):
        entries = cast("dict[object, object]", value)
        return all(
            type(key) is str and is_json_value(item) for key, item in entries.items()
        )
    return False


def require_json_object(value: object, *, context: str) -> JsonObject:
    """Validate and return a JSON object without coercing its values."""
    if not is_json_value(value) or not isinstance(value, dict):
        error_message = f"{context} must be a JSON object"
        raise TypeError(error_message)
    return cast("JsonObject", value)


def load_json_value(
    payload: str | bytes,
    *,
    object_pairs_hook: JsonObjectHook | None = None,
    parse_constant: JsonConstantHook | None = None,
    parse_float: JsonFloatHook | None = None,
) -> JsonValue:
    """Load JSON and validate the complete recursive value shape."""
    value: object = json.loads(
        payload,
        object_pairs_hook=object_pairs_hook,
        parse_constant=parse_constant,
        parse_float=parse_float,
    )
    if not is_json_value(value):
        error_message = "JSON decoder returned a non-JSON value"
        raise TypeError(error_message)
    return value


def dump_json(value: JsonValue, *, sort_keys: bool = False) -> str:
    """Serialize a validated JSON value with the project defaults."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=sort_keys,
        separators=(",", ":"),
    )


def dataclass_to_json(value: object, *, context: str) -> JsonObject:
    """Serialize a project-owned dataclass and validate its JSON shape."""
    try:
        payload: object = asdict(cast("DataclassInstance", value))
    except TypeError as exc:
        error_message = f"{context} must be a dataclass instance"
        raise TypeError(error_message) from exc
    return require_json_object(_json_compatible(payload), context=context)


def _json_compatible(value: object) -> JsonValue:
    """Convert dataclass containers to JSON containers without coercion."""
    if value is None or type(value) in {bool, int, str}:
        return cast("JsonPrimitive", value)
    if type(value) is float:
        if not math.isfinite(value):
            error_message = "JSON values must contain finite numbers"
            raise TypeError(error_message)
        return value
    if isinstance(value, (list, tuple)):
        items = cast("list[object] | tuple[object, ...]", value)
        return [_json_compatible(item) for item in items]
    if isinstance(value, Mapping):
        entries = cast("Mapping[object, object]", value)
        result: JsonObject = {}
        for key, item in entries.items():
            if type(key) is not str:
                error_message = "JSON object keys must be strings"
                raise TypeError(error_message)
            result[key] = _json_compatible(item)
        return result
    error_message = "dataclass contains a non-JSON value"
    raise TypeError(error_message)


def validation_details(raw: object) -> list[JsonObject]:
    """Convert a validator's heterogeneous error records to safe JSON."""
    if not isinstance(raw, list):
        error_message = "validation errors must be a list"
        raise TypeError(error_message)
    details: list[JsonObject] = []
    entries = cast("list[object]", raw)
    for entry in entries:
        if not isinstance(entry, Mapping):
            error_message = "validation error must be an object"
            raise TypeError(error_message)
        fields = cast("Mapping[object, object]", entry)
        location = fields.get("loc")
        message = fields.get("msg")
        error_type = fields.get("type")
        if not isinstance(location, tuple):
            error_message = "validation error location is invalid"
            raise TypeError(error_message)
        location_parts = cast("tuple[object, ...]", location)
        if not all(
            type(part) in {str, int} and not isinstance(part, bool)
            for part in location_parts
        ):
            error_message = "validation error location is invalid"
            raise TypeError(error_message)
        if not isinstance(message, str) or not isinstance(error_type, str):
            error_message = "validation error text is invalid"
            raise TypeError(error_message)
        details.append(
            {
                "location": ".".join(str(part) for part in location_parts),
                "message": message,
                "type": error_type,
            }
        )
    return details
