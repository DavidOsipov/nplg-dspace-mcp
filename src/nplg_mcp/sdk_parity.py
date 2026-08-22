# Copyright (c) 2026 David Osipov
"""Semantic normalization seams for legacy-to-official MCP SDK comparisons."""

from __future__ import annotations

import json
from typing import Protocol, cast, runtime_checkable

from .json_types import JsonObject, load_json_value, require_json_object


class SdkParityNormalizationError(ValueError):
    """Raised when an untrusted parity input cannot be normalized safely."""

    def __init__(self, *, context: str, reason: str) -> None:
        """Build one bounded diagnostic without retaining untrusted value content."""
        super().__init__(f"{context}: {reason}")


@runtime_checkable
class _JsonModel(Protocol):
    """The narrow Pydantic serialization seam permitted at the SDK boundary."""

    def model_dump(
        self,
        *,
        mode: str,
        by_alias: bool,
        exclude_none: bool,
    ) -> object:
        """Return a JSON-mode model projection."""
        ...


def _json_object(value: object, *, context: str) -> JsonObject:
    """Copy one model or JSON object through the strict JSON parser."""
    candidate = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, _JsonModel)
        else value
    )
    try:
        encoded = json.dumps(
            candidate,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return require_json_object(load_json_value(encoded), context=context)
    except (TypeError, ValueError) as exc:
        raise SdkParityNormalizationError(
            context=context,
            reason="is not valid JSON",
        ) from exc


def _json_sequence(value: object, *, context: str) -> tuple[object, ...]:
    """Reject non-array catalog inputs before normalizing individual entries."""
    if type(value) is not list:
        raise SdkParityNormalizationError(
            context=context,
            reason="must be a JSON array",
        )
    return tuple(cast("list[object]", value))


def _catalog_name(tool: JsonObject) -> bytes:
    """Return the validated UTF-8 sort key for one normalized catalog entry."""
    name = tool.get("name")
    if type(name) is not str:
        raise SdkParityNormalizationError(
            context="tool catalog entry name",
            reason="is invalid",
        )
    return name.encode("utf-8")


def normalize_tool_catalog(value: object) -> tuple[JsonObject, ...]:
    """Normalize stable catalog metadata after separately ledgering schema drift."""
    tools = tuple(
        _json_object(tool, context="tool catalog entry")
        for tool in _json_sequence(value, context="tool catalog")
    )
    names = tuple(_catalog_name(tool) for tool in tools)
    if len(names) != len(set(names)):
        raise SdkParityNormalizationError(
            context="tool catalog",
            reason="has duplicate names",
        )
    normalized: list[JsonObject] = []
    for tool in tools:
        try:
            normalized.append(
                {
                    "annotations": tool["annotations"],
                    "description": tool["description"],
                    "name": tool["name"],
                    "title": tool["title"],
                }
            )
        except KeyError as exc:
            raise SdkParityNormalizationError(
                context="tool catalog entry",
                reason="is missing stable metadata",
            ) from exc
    return tuple(sorted(normalized, key=_catalog_name))


def normalize_tool_result(value: object) -> JsonObject:
    """Normalize one successful tool result without duplicate textual summaries."""
    result = _json_object(value, context="tool result")
    structured = result.get("structuredContent")
    if structured is None:
        structured = result.get("structured_content")
    if structured is None:
        raise SdkParityNormalizationError(
            context="tool result",
            reason="has no structured content",
        )
    try:
        encoded = json.dumps(
            structured,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        normalized = load_json_value(encoded)
    except (TypeError, ValueError) as exc:
        raise SdkParityNormalizationError(
            context="tool structured content",
            reason="is not valid JSON",
        ) from exc
    if type(normalized) is not dict:
        raise SdkParityNormalizationError(
            context="tool structured content",
            reason="is not an object",
        )
    return normalized


def normalize_public_error(value: object) -> JsonObject:
    """Normalize a bounded public JSON-RPC error without unsafe details."""
    error = _json_object(value, context="public error")
    code = error.get("code")
    if type(code) is not int or type(code) is bool:
        raise SdkParityNormalizationError(
            context="public error code",
            reason="is invalid",
        )
    return {"code": code}
