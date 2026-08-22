# Copyright (c) 2026 David Osipov
"""Property tests for strict cross-language runtime contracts."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from nplg_mcp.contracts import MonotonicDeadline, SafeInteger, StrictInput

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_DEADLINE_BUDGET = 60.0
_NONFINITE_VALUES = (math.nan, math.inf, -math.inf)

if TYPE_CHECKING:
    from collections.abc import Callable

    from hypothesis.strategies import SearchStrategy


def _given_one[ValueT](
    strategy: SearchStrategy[ValueT],
) -> Callable[[Callable[[ValueT], None]], Callable[[], None]]:
    """Narrow Hypothesis's decorator edge without propagating `Any`."""
    return cast(
        "Callable[[Callable[[ValueT], None]], Callable[[], None]]",
        given(strategy),
    )


def _given_two[ValueT, OtherT](
    first: SearchStrategy[ValueT],
    second: SearchStrategy[OtherT],
) -> Callable[[Callable[[ValueT, OtherT], None]], Callable[[], None]]:
    """Narrow a two-argument Hypothesis decorator without `Any`."""
    return cast(
        "Callable[[Callable[[ValueT, OtherT], None]], Callable[[], None]]",
        given(first, second),
    )


class SafeIntegerProbe(StrictInput):
    """Property-test probe for the shared JSON integer alias."""

    value: SafeInteger


def _safe_integer_probe(value: object) -> SafeIntegerProbe:
    payload: dict[str, object] = {"value": value}
    return SafeIntegerProbe.model_validate(payload, strict=True)


def _is_integral(value: float) -> bool:
    return value.is_integer()


def _is_fractional(value: float) -> bool:
    return not value.is_integer()


@_given_one(st.integers(min_value=-_MAX_SAFE_INTEGER, max_value=_MAX_SAFE_INTEGER))
def test_every_exact_safe_integer_round_trips(value: int) -> None:
    validated = _safe_integer_probe(value)
    assert validated.value == value
    dumped = cast("dict[str, object]", validated.model_dump(mode="json"))
    assert dumped == {"value": value}


@_given_one(
    st.floats(
        min_value=-_MAX_SAFE_INTEGER,
        max_value=_MAX_SAFE_INTEGER,
        allow_nan=False,
        allow_infinity=False,
    ).filter(_is_integral)
)
def test_every_integral_finite_float_canonicalizes_to_integer(value: float) -> None:
    assert _safe_integer_probe(value).value == int(value)


@_given_one(
    st.one_of(
        st.floats(allow_nan=False, allow_infinity=False).filter(_is_fractional),
        st.integers(max_value=-_MAX_SAFE_INTEGER - 1),
        st.integers(min_value=_MAX_SAFE_INTEGER + 1),
    ),
)
def test_every_non_integral_or_out_of_range_number_is_rejected(
    value: float,
) -> None:
    with pytest.raises(ValidationError):
        _ = _safe_integer_probe(value)


@_given_two(
    st.floats(
        min_value=0.0,
        max_value=1_000_000.0,
        allow_nan=False,
        allow_infinity=False,
    ),
    st.floats(
        min_value=0.0,
        max_value=60.0,
        allow_nan=False,
        allow_infinity=False,
    ),
)
def test_deadline_remaining_is_bounded_and_monotonic(
    created_at: float,
    budget: float,
) -> None:
    deadline = MonotonicDeadline.after(budget, clock=lambda: created_at)
    midpoint = created_at + (budget / 2.0)
    assert 0.0 <= deadline.remaining(now=midpoint) <= _MAX_DEADLINE_BUDGET
    assert deadline.remaining(now=deadline.expires_at) == 0.0
    assert deadline.remaining(now=deadline.expires_at + 1.0) == 0.0


@_given_one(st.sampled_from(_NONFINITE_VALUES))
def test_deadline_rejects_every_nonfinite_clock_value(value: float) -> None:
    with pytest.raises(ValueError, match="created_at"):
        _ = MonotonicDeadline.after(1.0, clock=lambda: value)
