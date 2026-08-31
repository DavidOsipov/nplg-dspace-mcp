# Copyright (c) 2026 David Osipov
"""Deterministic Draft 2020-12 export for the closed tool-contract catalog."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

import pydantic

from nplg_mcp.json_types import (
    JsonObject,
    JsonValue,
    is_json_value,
    require_json_object,
)

from .base import StrictInput, StrictOutput
from .tool_models import tool_model_bindings

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pydantic import BaseModel

__all__ = (
    "CONTRACT_SCHEMA_ID",
    "DRAFT_2020_12",
    "EXPORTER_VERSION",
    "ContractModel",
    "JsonObject",
    "JsonValue",
    "aggregate_contract_schema",
    "canonical_json_bytes",
    "contract_models",
    "export_contract_schemas",
    "normalized_schema",
    "schema_manifest",
)

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
CONTRACT_SCHEMA_ID = "https://nplg-dspace-mcp.invalid/contracts/tool-contracts/v1"
EXPORTER_VERSION = "1.0.0-title-strip-codepoint-v1"
ZOD_VERSION = "4.5.4"

_SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "anyOf",
        "const",
        "default",
        "description",
        "exclusiveMinimum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "pattern",
        "properties",
        "required",
        "title",
        "type",
    }
)
_SCHEMA_TYPES = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)
_FORBIDDEN_PATTERN_FRAGMENTS = (
    "(?",
    "\\1",
    "\\2",
    "\\3",
    "\\p",
    "\\P",
    "\\u",
    "\\x",
)
_MAX_SCHEMA_DEPTH = 64
_MAX_SCHEMA_NODES = 100_000


@dataclass(frozen=True, slots=True)
class ContractModel:
    """One unique root model and its JSON Schema direction."""

    direction: Literal["input", "output"]
    model: type[BaseModel]

    @property
    def key(self) -> str:
        """Return the stable aggregate definition key."""
        return f"{self.direction}.{self.model.__name__}"


def contract_models() -> tuple[ContractModel, ...]:
    """Return the exact sorted unique contract-model inventory."""
    bindings = tool_model_bindings()
    tool_names = tuple(binding.name for binding in bindings)
    if len(tool_names) != len(set(tool_names)):
        message = "contract model authority contains duplicate tool names"
        raise ValueError(message)
    models = tuple(
        {ContractModel("input", binding.input_model) for binding in bindings}
        | {ContractModel("output", binding.output_model) for binding in bindings}
    )
    keys = tuple(item.key for item in models)
    if len(keys) != len(set(keys)):
        message = "contract model inventory contains duplicate keys"
        raise ValueError(message)
    for item in models:
        expected_base = StrictInput if item.direction == "input" else StrictOutput
        if not issubclass(item.model, expected_base):
            message = "contract model direction does not match its strict base"
            raise TypeError(message)
    return tuple(sorted(models, key=_contract_model_key))


def _contract_model_key(item: ContractModel) -> bytes:
    return item.key.encode("utf-8")


def _utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


def _validate_pattern(pattern: object) -> None:
    if type(pattern) is not str:
        message = "contract pattern must be a string"
        raise TypeError(message)
    if not pattern.startswith("^") or not pattern.endswith("$"):
        message = "contract pattern must use explicit full anchors"
        raise ValueError(message)
    audited_pattern = pattern.replace(r"\u2028", "").replace(r"\u2029", "")
    if any(fragment in audited_pattern for fragment in _FORBIDDEN_PATTERN_FRAGMENTS):
        message = "contract pattern is outside the audited regex intersection"
        raise ValueError(message)
    try:
        compiled: re.Pattern[str] = re.compile(pattern, flags=re.ASCII)
        _ = compiled
    except re.error as exc:
        message = "contract pattern is invalid"
        raise ValueError(message) from exc


def _validate_required(value: object) -> None:
    if not isinstance(value, list):
        message = "required must be an array"
        raise TypeError(message)
    items = cast("list[object]", value)
    if any(type(item) is not str for item in items) or len(items) != len(set(items)):
        message = "required must contain unique string field names"
        raise ValueError(message)


def _validate_node_identity(
    node: JsonObject,
    *,
    is_root: bool,
    allow_root_identity: bool,
) -> None:
    if frozenset(node) - _SUPPORTED_SCHEMA_KEYWORDS:
        message = "contract schema contains an unsupported keyword"
        raise ValueError(message)
    has_identity = "$schema" in node or "$id" in node
    if not is_root and has_identity:
        message = "embedded contract schemas cannot rebase the schema resource"
        raise ValueError(message)
    if is_root and not allow_root_identity and has_identity:
        message = "individual contract schemas cannot declare resource identity"
        raise ValueError(message)


def _validate_numeric_bounds(node: JsonObject) -> None:
    cardinality_keywords = ("maxItems", "maxLength", "minItems", "minLength")
    for keyword in cardinality_keywords:
        value = node.get(keyword)
        if value is not None and (type(value) is not int or value < 0):
            message = "contract schema cardinality must be a nonnegative integer"
            raise ValueError(message)
    keywords = (
        "exclusiveMinimum",
        "maximum",
        "minimum",
    )
    for keyword in keywords:
        value = node.get(keyword)
        if value is not None and (
            type(value) not in {int, float}
            or not math.isfinite(cast("int | float", value))
        ):
            message = "contract schema contains a malformed numeric bound"
            raise ValueError(message)


def _validate_node_values(node: JsonObject) -> None:
    schema_type = node.get("type")
    if schema_type is not None and (
        type(schema_type) is not str or schema_type not in _SCHEMA_TYPES
    ):
        message = "contract schema type is unsupported"
        raise ValueError(message)
    if schema_type == "object" and node.get("additionalProperties") is not False:
        message = "contract object schemas must be recursively closed"
        raise ValueError(message)
    reference = node.get("$ref")
    if reference is not None and (
        type(reference) is not str or not reference.startswith("#/$defs/")
    ):
        message = "contract schema references must be root-local"
        raise ValueError(message)
    if "pattern" in node:
        _validate_pattern(node["pattern"])
    if "format" in node:
        message = "contract schema contains an unknown format"
        raise ValueError(message)
    if "required" in node:
        _validate_required(node["required"])
    _validate_numeric_bounds(node)


def _child_schemas(node: JsonObject) -> list[JsonObject]:
    children: list[JsonObject] = []
    for keyword in ("$defs", "properties"):
        container = node.get(keyword)
        if container is None:
            continue
        child_map = require_json_object(
            container,
            context=f"contract schema {keyword}",
        )
        children.extend(
            require_json_object(child, context="embedded contract schema")
            for child in child_map.values()
        )
    items = node.get("items")
    if items is not None:
        children.append(
            require_json_object(items, context="contract array item schema")
        )
    alternatives = node.get("anyOf")
    if alternatives is None:
        return children
    if not isinstance(alternatives, list) or not alternatives:
        message = "contract anyOf must contain schemas"
        raise ValueError(message)
    children.extend(
        require_json_object(alternative, context="contract alternative schema")
        for alternative in cast("list[object]", alternatives)
    )
    return children


def _validate_schema(
    schema: JsonObject,
    *,
    allow_root_identity: bool,
) -> None:
    visited = 0
    pending: list[tuple[JsonObject, int, bool]] = [(schema, 0, True)]
    while pending:
        node, depth, is_root = pending.pop()
        visited += 1
        if visited > _MAX_SCHEMA_NODES or depth > _MAX_SCHEMA_DEPTH:
            message = "contract schema exceeds structural limits"
            raise ValueError(message)
        _validate_node_identity(
            node,
            is_root=is_root,
            allow_root_identity=allow_root_identity,
        )
        _validate_node_values(node)
        pending.extend((child, depth + 1, False) for child in _child_schemas(node))


def _model_schema(item: ContractModel) -> JsonObject:
    mode: Literal["validation", "serialization"] = (
        "validation" if item.direction == "input" else "serialization"
    )
    raw: object = item.model.model_json_schema(mode=mode)
    schema = copy.deepcopy(require_json_object(raw, context=item.key))
    _validate_schema(schema, allow_root_identity=False)
    return schema


def export_contract_schemas() -> dict[str, JsonObject]:
    """Export every unique catalog root through its normative Pydantic mode."""
    result = {item.key: _model_schema(item) for item in contract_models()}
    if tuple(result) != tuple(sorted(result, key=_utf8_key)):
        message = "contract schemas are not UTF-8-key sorted"
        raise ValueError(message)
    return result


def _rewrite_references(value: JsonValue, *, direction: str) -> JsonValue:
    if isinstance(value, list):
        return [_rewrite_references(item, direction=direction) for item in value]
    if isinstance(value, dict):
        rewritten: JsonObject = {}
        for key, item in value.items():
            if key == "$ref":
                if type(item) is not str or not item.startswith("#/$defs/"):
                    message = "contract schema contains a non-local reference"
                    raise ValueError(message)
                rewritten[key] = item.replace(
                    "#/$defs/",
                    f"#/$defs/{direction}.",
                    1,
                )
            else:
                rewritten[key] = _rewrite_references(item, direction=direction)
        return rewritten
    return value


def aggregate_contract_schema(
    schemas: Mapping[str, JsonObject] | None = None,
) -> JsonObject:
    """Build one root resource with namespaced root-local definitions."""
    source = export_contract_schemas() if schemas is None else dict(schemas)
    expected = tuple(item.key for item in contract_models())
    if tuple(sorted(source, key=_utf8_key)) != expected:
        message = "contract schema inventory does not match the catalog"
        raise ValueError(message)
    definitions: JsonObject = {}
    for key in expected:
        direction, separator, model_name = key.partition(".")
        if separator != "." or not model_name:
            message = "contract schema key is malformed"
            raise ValueError(message)
        schema = copy.deepcopy(source[key])
        nested_value = schema.pop("$defs", {})
        nested = require_json_object(nested_value, context=f"{key} definitions")
        rewritten_root = require_json_object(
            _rewrite_references(schema, direction=direction),
            context=f"rewritten {key}",
        )
        if key in definitions:
            message = "duplicate aggregate contract definition"
            raise ValueError(message)
        definitions[key] = rewritten_root
        for nested_name, nested_schema in nested.items():
            nested_key = f"{direction}.{nested_name}"
            rewritten_nested = require_json_object(
                _rewrite_references(nested_schema, direction=direction),
                context=f"rewritten {nested_key}",
            )
            prior = definitions.get(nested_key)
            if prior is not None and prior != rewritten_nested:
                message = "conflicting aggregate contract definition"
                raise ValueError(message)
            definitions[nested_key] = rewritten_nested
    aggregate: JsonObject = {
        "$defs": {key: definitions[key] for key in sorted(definitions, key=_utf8_key)},
        "$id": CONTRACT_SCHEMA_ID,
        "$schema": DRAFT_2020_12,
        "description": "NPLG MCP strict tool input and output contracts.",
    }
    _validate_schema(aggregate, allow_root_identity=True)
    return aggregate


def normalized_schema(schema: JsonObject) -> JsonObject:
    """Remove only presentation titles and recursively sort UTF-8 keys."""

    def normalize(value: JsonValue) -> JsonValue:
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, dict):
            return {
                key: normalize(value[key])
                for key in sorted(value, key=_utf8_key)
                if key != "title"
            }
        return value

    normalized = normalize(schema)
    return require_json_object(normalized, context="normalized contract schema")


def canonical_json_bytes(value: JsonValue) -> bytes:
    """Encode deterministic UTF-8 JSON without Unicode normalization."""
    if not is_json_value(value):
        message = "canonical JSON input contains a non-JSON value"
        raise TypeError(message)
    rendered = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (rendered + "\n").encode("utf-8")


def schema_manifest(schemas: Mapping[str, JsonObject] | None = None) -> JsonObject:
    """Build the strict digest manifest for every root contract schema."""
    source = export_contract_schemas() if schemas is None else dict(schemas)
    aggregate = aggregate_contract_schema(source)
    records: list[JsonValue] = []
    for item in contract_models():
        schema = normalized_schema(source[item.key])
        records.append(
            {
                "$id": CONTRACT_SCHEMA_ID,
                "exporter_version": EXPORTER_VERSION,
                "json_pointer": f"#/$defs/{item.key}",
                "key": item.key,
                "normalized_sha256": hashlib.sha256(
                    canonical_json_bytes(schema)
                ).hexdigest(),
                "pydantic_version": pydantic.__version__,
                "zod_version": ZOD_VERSION,
            }
        )
    return {
        "aggregate_sha256": hashlib.sha256(canonical_json_bytes(aggregate)).hexdigest(),
        "exporter_version": EXPORTER_VERSION,
        "schema_id": CONTRACT_SCHEMA_ID,
        "schemas": records,
        "version": 1,
    }
