# Copyright (c) 2026 David Osipov
"""Unit tests for the bounded JSON lexical preflight firewall."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

import nplg_mcp.json_preflight as json_preflight_module
from nplg_mcp.json_preflight import (
    JsonPreflightError,
    JsonPreflightLimits,
    preflight_json,
)


def test_accepts_valid_json_without_normalizing_the_input() -> None:
    """Valid nested JSON is accepted without allocating a decoded value tree."""
    payload = b'{"a":[true,null,-12.3e+2,"text"]}'

    preflight_json(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":1,"\\u0061":2}',
        b'{"a":1} trailing',
        b'{"a":"\xff"}',
        b'{"a":NaN}',
        b'{"a":1e9999}',
        b'{"a":01}',
        b'{"a":"\\uD800"}',
    ],
)
def test_rejects_ambiguous_or_non_json_lexical_forms(payload: bytes) -> None:
    """Unsafe JSON forms fail with one bounded non-reflective public error."""
    with pytest.raises(JsonPreflightError, match="Invalid JSON request body") as raised:
        preflight_json(payload)

    assert payload.decode("ascii", errors="ignore") not in str(raised.value)


def test_enforces_bounded_frames_tokens_and_scalar_limits() -> None:
    """Configured resource limits apply before the MCP SDK allocates JSON values."""
    limits = JsonPreflightLimits(
        max_array_items=1,
        max_depth=2,
        max_scalar_bytes=3,
        max_tokens=4,
    )

    for payload in (b"[1,2]", b"[[[1]]]", b'{"a":"four"}', b"[1,2,3,4,5]"):
        with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
            preflight_json(payload, limits=limits)


def test_strict_pydantic_limits_reject_boolean_and_out_of_policy_values() -> None:
    """Security-limit configuration never coerces booleans or body-size overages."""
    with pytest.raises(ValidationError):
        _ = JsonPreflightLimits(max_depth=True)
    with pytest.raises(ValidationError):
        _ = JsonPreflightLimits(max_body_bytes=4 * 1024 * 1024 + 1)


@pytest.mark.parametrize("payload", [b"[1,]", b'{"a":1,}'])
def test_rejects_trailing_container_commas(payload: bytes) -> None:
    """A separator must be followed by another value or object key."""
    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        preflight_json(payload)


def test_rejects_at_first_raw_key_byte_excess() -> None:
    """The configured key ceiling counts bytes between quotes exactly."""
    limits = JsonPreflightLimits(max_key_bytes=1)

    preflight_json(b'{"a":0}', limits=limits)
    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        preflight_json(b'{"ab":0}', limits=limits)


def test_rejects_nonfinite_and_overflow_numbers() -> None:
    """JSON number spelling is insufficient when conversion would be non-finite."""
    preflight_json(b"1.7e308")

    for payload in (b"NaN", b"Infinity", b"-Infinity", b"9e308", b"1e9999"):
        with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
            preflight_json(payload)


@pytest.mark.parametrize(
    ("limits", "at_limit", "first_excess"),
    [
        (JsonPreflightLimits(max_body_bytes=1), b"0", b"0 "),
        (JsonPreflightLimits(max_depth=1), b"[]", b"[[]]"),
        (
            JsonPreflightLimits(max_object_members=1),
            b'{"a":0}',
            b'{"a":0,"b":0}',
        ),
        (JsonPreflightLimits(max_array_items=1), b"[0]", b"[0,1]"),
        (JsonPreflightLimits(max_tokens=2), b"[0]", b"[0,1]"),
        (JsonPreflightLimits(max_key_bytes=1), b'{"a":0}', b'{"ab":0}'),
        (JsonPreflightLimits(max_scalar_bytes=1), b'"a"', b'"ab"'),
        (JsonPreflightLimits(max_integer_digits=1), b"9", b"10"),
        (JsonPreflightLimits(max_exponent_magnitude=1), b"1e1", b"1e2"),
    ],
    ids=[
        "body-bytes",
        "depth",
        "object-members",
        "array-items",
        "tokens",
        "key-bytes",
        "scalar-bytes",
        "integer-digits",
        "exponent-magnitude",
    ],
)
def test_each_structural_ceiling_rejects_its_first_excess(
    limits: JsonPreflightLimits,
    at_limit: bytes,
    first_excess: bytes,
) -> None:
    """Each resource limit admits its exact boundary and rejects one-unit excess."""
    preflight_json(at_limit, limits=limits)

    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        preflight_json(first_excess, limits=limits)


def test_preflight_never_invokes_standard_decoded_tree_constructors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lexical firewall returns None without delegating to a JSON tree decoder."""

    def decoded_tree_forbidden(*_args: object, **_kwargs: object) -> object:
        msg = "preflight attempted to construct a decoded JSON tree"
        raise AssertionError(msg)

    monkeypatch.setattr(json, "loads", decoded_tree_forbidden)

    preflight_json(b'{"a":[true,null,-12.3e+2,"text"]}')


@pytest.mark.parametrize(
    "payload",
    [b"[0:1]", b'{"a" 0}', b'{"a":0:"b":1}'],
    ids=["array-separator", "object-colon", "object-separator"],
)
def test_rejects_invalid_container_delimiters(payload: bytes) -> None:
    """Each container delimiter state fails closed on an unexpected byte."""
    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        preflight_json(payload)


def test_string_consumer_defensively_requires_an_opening_quote() -> None:
    """The low-level string guard remains fail-closed if its caller regresses."""
    parser = json_preflight_module._JsonPreflightParser(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        b"x", JsonPreflightLimits()
    )

    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        _ = parser._consume_string(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            max_bytes=1
        )


def test_escaped_scalar_limit_counts_raw_escape_bytes() -> None:
    """A two-byte escape is rejected at the first byte beyond a one-byte ceiling."""
    limits = JsonPreflightLimits(max_scalar_bytes=1)

    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        preflight_json(b'"\\n"', limits=limits)


@pytest.mark.parametrize(
    "payload",
    [b'"\\', b'"\\x"'],
    ids=["truncated", "unknown"],
)
def test_rejects_truncated_or_unknown_string_escapes(payload: bytes) -> None:
    """An escape must contain one complete JSON escape spelling."""
    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        preflight_json(payload)


def test_accepts_simple_escapes_in_values_and_retained_keys() -> None:
    """Simple escapes work both without retention and in duplicate-key tracking."""
    preflight_json(b'["\\n",{"\\t":0}]')


@pytest.mark.parametrize(
    "payload",
    [b'"\\uD800\\u0041"', b'"\\uDC00"', b'"\\u12xz"'],
    ids=["high-followed-by-non-low", "lone-low", "invalid-code-unit"],
)
def test_rejects_invalid_unicode_escape_combinations(payload: bytes) -> None:
    """Malformed code units and unpaired surrogates are never accepted."""
    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        preflight_json(payload)


def test_accepts_a_complete_unicode_surrogate_pair() -> None:
    """A high surrogate followed by one low surrogate is valid JSON."""
    preflight_json(b'"\\uD83D\\uDE00"')


def test_number_scalar_limit_rejects_its_first_excess() -> None:
    """The scalar-byte ceiling applies to numbers after lexical consumption."""
    limits = JsonPreflightLimits(max_scalar_bytes=1)

    preflight_json(b"9", limits=limits)
    with pytest.raises(JsonPreflightError, match="Invalid JSON request body"):
        preflight_json(b"10", limits=limits)
