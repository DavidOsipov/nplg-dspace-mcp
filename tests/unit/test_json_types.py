# Copyright (c) 2026 David Osipov
"""Fault-boundary tests for the closed JSON conversion helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest

from nplg_mcp.json_types import (
    JsonObject,
    dataclass_to_json,
    is_json_value,
    load_json_value,
    require_json_object,
    validation_details,
)


@dataclass(frozen=True)
class _Payload:
    value: object


def test_json_value_and_object_boundaries_reject_non_json_values() -> None:
    assert is_json_value(object()) is False
    with pytest.raises(TypeError, match="must be a JSON object"):
        _ = require_json_object([], context="fixture")

    def invalid_hook(_pairs: list[tuple[str, object]]) -> JsonObject:
        return cast("JsonObject", {"bad": object()})

    with pytest.raises(TypeError, match="non-JSON value"):
        _ = load_json_value("{}", object_pairs_hook=invalid_hook)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (float("inf"), "finite numbers"),
        ({1: "value"}, "keys must be strings"),
        (object(), "non-JSON value"),
    ],
)
def test_dataclass_json_conversion_rejects_invalid_values(
    value: object,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        _ = dataclass_to_json(_Payload(value), context="fixture")


def test_dataclass_json_conversion_rejects_non_dataclass() -> None:
    with pytest.raises(TypeError, match="dataclass instance"):
        _ = dataclass_to_json(object(), context="fixture")


@pytest.mark.parametrize(
    "value",
    [
        {},
        [object()],
        [{"loc": [], "msg": "message", "type": "value_error"}],
        [{"loc": (True,), "msg": "message", "type": "value_error"}],
        [{"loc": ("field",), "msg": 1, "type": "value_error"}],
    ],
)
def test_validation_details_rejects_malformed_records(value: object) -> None:
    with pytest.raises(TypeError):
        _ = validation_details(value)
