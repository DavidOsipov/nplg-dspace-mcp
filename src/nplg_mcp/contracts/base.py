# Copyright (c) 2026 David Osipov
"""Shared strict primitives for every public MCP contract."""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, cast

from annotated_types import Ge, Le
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    StringConstraints,
)
from pydantic_core import PydanticCustomError

if TYPE_CHECKING:
    from collections.abc import Callable

MIN_SAFE_INTEGER = -9_007_199_254_740_991
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_DEADLINE_BUDGET_SECONDS = 60.0
_UNSAFE_TEXT_RANGES = (
    "\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0605\u061c\u06dd\u070f"
    "\u0890-\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    "\u2066-\u206f\ufeff\ufff9-\ufffb\U000110bd\U000110cd"
    "\U00013430-\U0001343f\U0001bca0-\U0001bca3"
    "\U0001d173-\U0001d17a\U000e0001\U000e0020-\U000e007f"
)
_UNICODE_WHITESPACE = " \u00a0\u1680\u2000-\u200a\\u2028-\\u2029\u202f\u205f\u3000"
SAFE_TEXT_PATTERN = f"^[^{_UNSAFE_TEXT_RANGES}]*$"
NON_BLANK_SAFE_TEXT_PATTERN = (
    f"^[^{_UNSAFE_TEXT_RANGES}]*"
    f"[^{_UNSAFE_TEXT_RANGES}{_UNICODE_WHITESPACE}]"
    f"[^{_UNSAFE_TEXT_RANGES}]*$"
)


def _validate_safe_integer(value: object) -> int:
    """Canonicalize only exact finite JSON integers in JavaScript's safe range."""
    if type(value) is int:
        integer = value
    elif type(value) is float and math.isfinite(value) and value.is_integer():
        integer = int(value)
    else:
        error_type = "int_type"
        message = "Input should be a valid integer"
        raise PydanticCustomError(error_type, message)
    if not MIN_SAFE_INTEGER <= integer <= MAX_SAFE_INTEGER:
        message = "integer must be within the JavaScript safe range"
        raise ValueError(message)
    return integer


SafeInteger = Annotated[
    int,
    Ge(MIN_SAFE_INTEGER),
    Le(MAX_SAFE_INTEGER),
    BeforeValidator(_validate_safe_integer),
]

SAFE_INTEGER_VALIDATOR = BeforeValidator(_validate_safe_integer)


def _own_sequence(value: object) -> object:
    """Convert a JSON array to an immutable tuple without accepting iterables."""
    if type(value) is list:
        items = cast("list[object]", value)
        return tuple(items)
    return value


type FrozenSequence[T] = tuple[T, ...]

OWN_SEQUENCE_VALIDATOR = BeforeValidator(_own_sequence)


def reject_unsafe_text(value: str) -> str:
    """Reject control and formatting code points at every public text boundary."""
    for character in value:
        if unicodedata.category(character) in {"Cc", "Cf"}:
            message = "text contains a prohibited control or bidi character"
            raise ValueError(message)
    return value


ContractText = Annotated[
    str,
    StringConstraints(pattern=SAFE_TEXT_PATTERN),
    AfterValidator(reject_unsafe_text),
]


class StrictModel(BaseModel):
    """Closed, immutable, non-coercing base for public MCP contracts."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        validate_default=True,
        hide_input_in_errors=True,
        frozen=True,
        json_schema_serialization_defaults_required=True,
        regex_engine="rust-regex",
    )


class StrictInput(StrictModel):
    """Marker base for public tool inputs."""


class StrictOutput(StrictModel):
    """Marker base for public tool outputs."""


@dataclass(frozen=True, slots=True)
class MonotonicDeadline:
    """One bounded absolute deadline derived only from an injected clock."""

    created_at: float
    expires_at: float

    def __post_init__(self) -> None:
        """Reject malformed endpoints and budgets outside the shared ceiling."""
        for field_name, value in (
            ("created_at", self.created_at),
            ("expires_at", self.expires_at),
        ):
            if type(value) is not float or not math.isfinite(value) or value < 0.0:
                message = f"{field_name} must be a finite nonnegative float"
                raise ValueError(message)
        budget = self.expires_at - self.created_at
        if budget < 0.0 or budget > MAX_DEADLINE_BUDGET_SECONDS:
            message = "deadline budget must be between 0 and 60 seconds"
            raise ValueError(message)

    @classmethod
    def after(
        cls,
        budget_seconds: float,
        *,
        clock: Callable[[], float],
    ) -> MonotonicDeadline:
        """Create a deadline from one strict bounded budget and monotonic clock."""
        if (
            type(budget_seconds) is not float
            or not math.isfinite(budget_seconds)
            or not 0.0 <= budget_seconds <= MAX_DEADLINE_BUDGET_SECONDS
        ):
            message = "budget_seconds must be a finite float from 0 to 60"
            raise ValueError(message)
        created_at = clock()
        return cls(created_at=created_at, expires_at=created_at + budget_seconds)

    def remaining(self, *, now: float) -> float:
        """Return a clamped remainder while rejecting invalid clock samples."""
        if type(now) is not float or not math.isfinite(now) or now < 0.0:
            message = "now must be a finite nonnegative float"
            raise ValueError(message)
        if now < self.created_at:
            message = "monotonic clock moved backwards"
            raise ValueError(message)
        return max(0.0, self.expires_at - now)
