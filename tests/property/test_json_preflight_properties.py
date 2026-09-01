# Copyright (c) 2026 David Osipov
"""Adversarial properties for JSON lexical preflight."""
# mypy: disable-error-code=misc
# Hypothesis 6.167.1's decorators are dynamically typed at this boundary.

from __future__ import annotations

import json
import math
from typing import NoReturn

from hypothesis import given, settings
from hypothesis import strategies as st

from nplg_mcp.json_preflight import (
    JsonPreflightError,
    JsonPreflightLimits,
    preflight_json,
)


def _error_message(payload: bytes) -> str | None:
    """Return the sole accepted error without asserting inside an except block."""
    try:
        preflight_json(payload, limits=JsonPreflightLimits(max_body_bytes=4096))
    except JsonPreflightError as exc:
        return str(exc)
    return None


@given(st.binary(max_size=4096))
@settings(max_examples=200, deadline=250)
def test_preflight_never_leaks_parser_or_recursion_errors(payload: bytes) -> None:
    """Every arbitrary bounded byte sequence is accepted or gets the same safe error."""
    assert _error_message(payload) in {None, "Invalid JSON request body"}


def _reject_named_constant(value: str) -> NoReturn:
    """Make Python's opt-in NaN/Infinity extension unavailable downstream."""
    raise ValueError(value)


def _strict_float(value: str) -> float:
    """Reject downstream float overflow as the lexical preflight does."""
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(value)
    return parsed


@given(st.binary(min_size=1, max_size=4096))
@settings(max_examples=500, deadline=250)
def test_every_accepted_payload_is_accepted_by_strict_downstream_json(
    payload: bytes,
) -> None:
    """Preflight acceptance is a subset of strict downstream JSON acceptance."""
    try:
        preflight_json(payload, limits=JsonPreflightLimits(max_body_bytes=4096))
    except JsonPreflightError:
        return

    _ = json.loads(
        payload,
        parse_constant=_reject_named_constant,
        parse_float=_strict_float,
    )
