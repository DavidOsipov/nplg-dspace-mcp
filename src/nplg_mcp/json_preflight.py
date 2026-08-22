# Copyright (c) 2026 David Osipov
"""Bounded, allocation-resistant lexical validation for JSON request bodies."""

from __future__ import annotations

import codecs
import math
from dataclasses import dataclass, field
from typing import Annotated, Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field

_MAX_BODY_BYTES = 4 * 1024 * 1024
_JSON_WHITESPACE = frozenset({0x09, 0x0A, 0x0D, 0x20})
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
_CONTROL_BYTE_MAX = 0x1F
_HIGH_SURROGATE_MIN = 0xD800
_HIGH_SURROGATE_MAX = 0xDBFF
_LOW_SURROGATE_MIN = 0xDC00
_LOW_SURROGATE_MAX = 0xDFFF
_UNICODE_CODE_UNIT_LENGTH = 4
_SIMPLE_ESCAPES = {
    ord('"'): b'"',
    ord("/"): b"/",
    ord("\\"): b"\\",
    ord("b"): b"\b",
    ord("f"): b"\f",
    ord("n"): b"\n",
    ord("r"): b"\r",
    ord("t"): b"\t",
}


class JsonPreflightError(ValueError):
    """Safe public error for malformed or resource-exhausting JSON bytes."""

    def __init__(self) -> None:
        """Initialize the single non-reflective public validation error."""
        super().__init__("Invalid JSON request body")


class JsonPreflightLimits(BaseModel):
    """Strict, immutable limits applied before the SDK decodes a request."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, validate_default=True
    )

    max_body_bytes: Annotated[int, Field(ge=1, le=_MAX_BODY_BYTES)] = _MAX_BODY_BYTES
    max_depth: Annotated[int, Field(ge=1, le=128)] = 64
    max_object_members: Annotated[int, Field(ge=1, le=65_536)] = 4096
    max_array_items: Annotated[int, Field(ge=1, le=65_536)] = 4096
    max_tokens: Annotated[int, Field(ge=1, le=1_000_000)] = 100_000
    max_key_bytes: Annotated[int, Field(ge=1, le=65_536)] = 4096
    max_scalar_bytes: Annotated[int, Field(ge=1, le=_MAX_BODY_BYTES)] = _MAX_BODY_BYTES
    max_integer_digits: Annotated[int, Field(ge=1, le=65_536)] = 1024
    max_exponent_magnitude: Annotated[int, Field(ge=0, le=1_000_000)] = 308


_DEFAULT_LIMITS = JsonPreflightLimits()


def _empty_key_set() -> set[str]:
    """Create one precisely typed mutable key set for a container frame."""
    return set()


@dataclass(slots=True)
class _Frame:
    """One bounded non-recursive JSON container frame."""

    kind: Literal["array", "object"]
    state: Literal[
        "array_value_or_end",
        "array_after_value",
        "object_key_or_end",
        "object_value",
        "object_after_value",
    ]
    members: int = 0
    keys: set[str] = field(default_factory=_empty_key_set)
    allow_end: bool = True


class _JsonPreflightParser:
    """Validate syntax and limits while retaining only active object keys."""

    def __init__(self, payload: bytes, limits: JsonPreflightLimits) -> None:
        super().__init__()
        self._payload = payload
        self._limits = limits
        self._index = 0
        self._tokens = 0
        self._frames: list[_Frame] = []
        self._root_complete = False

    def validate(self) -> None:
        """Consume exactly one valid JSON text without recursive descent."""
        if not self._payload or len(self._payload) > self._limits.max_body_bytes:
            self._fail()

        while not self._root_complete:
            self._skip_whitespace()
            if not self._frames:
                self._begin_value()
                continue

            frame = self._frames[-1]
            if frame.state == "array_value_or_end":
                if frame.allow_end and self._consume_byte(ord("]")):
                    self._finish_container()
                else:
                    self._increment_array_item(frame)
                    frame.state = "array_after_value"
                    self._begin_value()
            elif frame.state == "array_after_value":
                self._consume_array_separator(frame)
            elif frame.state == "object_key_or_end":
                self._consume_object_key(frame)
            elif frame.state == "object_value":
                self._increment_object_member(frame)
                frame.state = "object_after_value"
                self._begin_value()
            else:
                self._consume_object_separator(frame)

        self._skip_whitespace()
        if self._index != len(self._payload):
            self._fail()

    def _begin_value(self) -> None:
        self._count_token()
        value = self._peek_byte()
        if value == ord("{"):
            self._index += 1
            self._push_container("object")
        elif value == ord("["):
            self._index += 1
            self._push_container("array")
        elif value == ord('"'):
            _ = self._consume_string(max_bytes=self._limits.max_scalar_bytes)
            self._finish_scalar()
        elif value == ord("-") or self._is_digit(value):
            self._consume_number()
            self._finish_scalar()
        elif self._payload.startswith(b"true", self._index):
            self._index += len(b"true")
            self._finish_scalar()
        elif self._payload.startswith(b"false", self._index):
            self._index += len(b"false")
            self._finish_scalar()
        elif self._payload.startswith(b"null", self._index):
            self._index += len(b"null")
            self._finish_scalar()
        else:
            self._fail()

    def _push_container(self, kind: Literal["array", "object"]) -> None:
        if len(self._frames) >= self._limits.max_depth:
            self._fail()
        state: Literal["array_value_or_end", "object_key_or_end"] = (
            "array_value_or_end" if kind == "array" else "object_key_or_end"
        )
        self._frames.append(_Frame(kind=kind, state=state))

    def _finish_scalar(self) -> None:
        if not self._frames:
            self._root_complete = True

    def _finish_container(self) -> None:
        _ = self._frames.pop()
        if not self._frames:
            self._root_complete = True

    def _consume_array_separator(self, frame: _Frame) -> None:
        if self._consume_byte(ord(",")):
            frame.state = "array_value_or_end"
            frame.allow_end = False
        elif self._consume_byte(ord("]")):
            self._finish_container()
        else:
            self._fail()

    def _consume_object_key(self, frame: _Frame) -> None:
        if frame.allow_end and self._consume_byte(ord("}")):
            self._finish_container()
            return
        if self._peek_byte() != ord('"'):
            self._fail()
        key = self._consume_string(max_bytes=self._limits.max_key_bytes, retain=True)
        if key is None or key in frame.keys:
            self._fail()
        frame.keys.add(key)
        self._skip_whitespace()
        if not self._consume_byte(ord(":")):
            self._fail()
        frame.state = "object_value"

    def _consume_object_separator(self, frame: _Frame) -> None:
        if self._consume_byte(ord(",")):
            frame.state = "object_key_or_end"
            frame.allow_end = False
        elif self._consume_byte(ord("}")):
            self._finish_container()
        else:
            self._fail()

    def _increment_array_item(self, frame: _Frame) -> None:
        frame.members += 1
        if frame.members > self._limits.max_array_items:
            self._fail()

    def _increment_object_member(self, frame: _Frame) -> None:
        frame.members += 1
        if frame.members > self._limits.max_object_members:
            self._fail()

    def _consume_string(  # noqa: C901, PLR0912
        self, *, max_bytes: int, retain: bool = False
    ) -> str | None:
        if not self._consume_byte(ord('"')):
            self._fail()
        content_start = self._index
        decoded = bytearray() if retain else None
        decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        while True:
            if self._index >= len(self._payload):
                self._fail()
            value = self._payload[self._index]
            if value == ord('"'):
                try:
                    _ = decoder.decode(b"", final=True)
                except UnicodeDecodeError:
                    self._fail()
                self._index += 1
                break
            if self._index - content_start >= max_bytes:
                self._fail()
            self._index += 1
            if value <= _CONTROL_BYTE_MAX:
                self._fail()
            if value != ord("\\"):
                try:
                    _ = decoder.decode(bytes((value,)), final=False)
                except UnicodeDecodeError:
                    self._fail()
                if decoded is not None:
                    decoded.append(value)
                continue
            try:
                _ = decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                self._fail()
            decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
            self._consume_escape(decoded)
            if self._index - content_start > max_bytes:
                self._fail()

        if decoded is None:
            return None
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            self._fail()
        return text

    def _consume_escape(self, decoded: bytearray | None) -> None:
        if self._index >= len(self._payload):
            self._fail()
        escaped = self._payload[self._index]
        self._index += 1
        simple = _SIMPLE_ESCAPES.get(escaped)
        if simple is not None:
            if decoded is not None:
                decoded.extend(simple)
            return
        if escaped != ord("u"):
            self._fail()
        codepoint = self._consume_unicode_code_unit()
        if _HIGH_SURROGATE_MIN <= codepoint <= _HIGH_SURROGATE_MAX:
            if not self._payload.startswith(b"\\u", self._index):
                self._fail()
            self._index += len(b"\\u")
            low_surrogate = self._consume_unicode_code_unit()
            if not _LOW_SURROGATE_MIN <= low_surrogate <= _LOW_SURROGATE_MAX:
                self._fail()
            codepoint = (
                0x10000
                + ((codepoint - _HIGH_SURROGATE_MIN) << 10)
                + (low_surrogate - _LOW_SURROGATE_MIN)
            )
        elif _LOW_SURROGATE_MIN <= codepoint <= _LOW_SURROGATE_MAX:
            self._fail()
        if decoded is not None:
            decoded.extend(chr(codepoint).encode("utf-8"))

    def _consume_unicode_code_unit(self) -> int:
        end = self._index + _UNICODE_CODE_UNIT_LENGTH
        digits = self._payload[self._index : end]
        if len(digits) != _UNICODE_CODE_UNIT_LENGTH or any(
            digit not in _HEX_DIGITS for digit in digits
        ):
            self._fail()
        self._index = end
        return int(digits.decode("ascii"), 16)

    def _consume_number(self) -> None:
        start = self._index
        self._consume_sign()
        self._consume_integer()
        self._consume_fraction()
        self._consume_exponent()
        if self._index - start > self._limits.max_scalar_bytes:
            self._fail()
        try:
            finite = math.isfinite(float(self._payload[start : self._index]))
        except (OverflowError, ValueError):
            self._fail()
        if not finite:
            self._fail()

    def _consume_sign(self) -> None:
        if self._consume_byte(ord("-")) and self._index >= len(self._payload):
            self._fail()

    def _consume_integer(self) -> None:
        if self._consume_byte(ord("0")):
            if self._is_digit(self._peek_byte()):
                self._fail()
            return
        if not self._is_nonzero_digit(self._peek_byte()):
            self._fail()
        digits = self._consume_one_or_more_digits()
        if digits > self._limits.max_integer_digits:
            self._fail()

    def _consume_fraction(self) -> None:
        if self._consume_byte(ord(".")):
            _ = self._consume_one_or_more_digits()

    def _consume_exponent(self) -> None:
        if self._peek_byte() not in {ord("e"), ord("E")}:
            return
        self._index += 1
        if self._peek_byte() in {ord("+"), ord("-")}:
            self._index += 1
        exponent = self._consume_one_or_more_digits(
            limit=self._limits.max_exponent_magnitude
        )
        if exponent > self._limits.max_exponent_magnitude:
            self._fail()

    def _consume_one_or_more_digits(self, *, limit: int | None = None) -> int:
        digits = 0
        value = 0
        while self._is_digit(self._peek_byte()):
            digits += 1
            if limit is not None and value <= limit:
                value = value * 10 + self._payload[self._index] - ord("0")
            self._index += 1
        if digits == 0:
            self._fail()
        return digits if limit is None else value

    def _count_token(self) -> None:
        self._tokens += 1
        if self._tokens > self._limits.max_tokens:
            self._fail()

    def _skip_whitespace(self) -> None:
        while self._peek_byte() in _JSON_WHITESPACE:
            self._index += 1

    def _consume_byte(self, expected: int) -> bool:
        if self._peek_byte() != expected:
            return False
        self._index += 1
        return True

    def _peek_byte(self) -> int | None:
        if self._index >= len(self._payload):
            return None
        return self._payload[self._index]

    @staticmethod
    def _is_digit(value: int | None) -> bool:
        return value is not None and ord("0") <= value <= ord("9")

    @staticmethod
    def _is_nonzero_digit(value: int | None) -> bool:
        return value is not None and ord("1") <= value <= ord("9")

    @staticmethod
    def _fail() -> NoReturn:
        raise JsonPreflightError


def preflight_json(
    payload: bytes, *, limits: JsonPreflightLimits | None = None
) -> None:
    """Validate JSON bytes without constructing their mapping or list value tree."""
    selected_limits = limits or _DEFAULT_LIMITS
    try:
        _JsonPreflightParser(payload, selected_limits).validate()
    except JsonPreflightError:
        raise
    except (IndexError, OverflowError, UnicodeError, ValueError) as exc:
        raise JsonPreflightError from exc
