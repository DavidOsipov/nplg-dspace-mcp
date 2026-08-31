# Copyright (c) 2026 David Osipov
"""Cross-language contract-schema and frozen-corpus oracle tests."""
# ruff: noqa: SLF001

from __future__ import annotations

import base64
import copy
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Annotated, Literal, cast

import pytest
from annotated_types import Ge, Le
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, StringConstraints, TypeAdapter, ValidationError
from referencing import Registry, Resource

import nplg_mcp.contracts.schema as schema_module
import scripts.export_contracts as exporter_module
from nplg_mcp.contracts import (
    SafeInteger,
    StrictInput,
    StrictOutput,
)
from nplg_mcp.contracts import (
    SearchDocumentsInput as OriginalSearchDocumentsInput,
)
from nplg_mcp.contracts.base import SAFE_INTEGER_VALIDATOR
from nplg_mcp.contracts.schema import (
    CONTRACT_SCHEMA_ID,
    DRAFT_2020_12,
    aggregate_contract_schema,
    canonical_json_bytes,
    contract_models,
    export_contract_schemas,
    normalized_schema,
    schema_manifest,
)
from nplg_mcp.contracts.tool_models import tool_model_bindings
from nplg_mcp.json_types import (
    JsonObject,
    JsonValue,
    is_json_value,
    load_json_value,
    require_json_object,
)
from scripts.export_contracts import ExportError, ExportRequest, export_contracts

ROOT = Path(__file__).resolve().parents[2]
GENERATED = ROOT / "contracts" / "generated"
CORPUS = ROOT / "contracts" / "tool-contracts.corpus.json"
NODE_ORACLE = ROOT / "contracts" / "zod" / "contract.test.ts"
_MAX_ORACLE_BYTES = 4 * 1024 * 1024
_MAX_ORACLE_RESULTS = 512
_MAX_ORACLE_ERROR_CLASS_LENGTH = 128
_MAX_CORPUS_ENTRIES = 512
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 100_000
_MAX_REQUIREMENT_ID_LENGTH = 64
_MAX_SCHEMA_KEY_LENGTH = 128
_MAX_RAW_JSON_BYTES = 65_536
_MAX_KEYWORD_LENGTH = 64
_CONTRACT_MODEL_COUNT = 15
_ALLOWED_FORMATS: tuple[str, ...] = ()
_CORPUS_FIELDS = frozenset(
    {
        "error_class",
        "expected",
        "keyword",
        "mode",
        "normalized",
        "parsed",
        "raw_json",
        "requirement_id",
        "schema_key",
        "value",
    }
)
_CODE_POINT_TWO: TypeAdapter[str] = TypeAdapter(
    Annotated[str, StringConstraints(strict=True, min_length=1, max_length=2)]
)
_SAFE_INTEGER: TypeAdapter[int] = TypeAdapter(SafeInteger)


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    """One bounded, closed cross-language corpus case."""

    requirement_id: str
    schema_key: str
    mode: Literal["input", "output"]
    raw_json: str
    parsed: bool
    value: JsonValue
    expected: Literal["accept", "reject"]
    normalized: JsonValue
    error_class: str | None
    keyword: str


@dataclass(frozen=True, slots=True)
class AuthorityVerdict:
    """One validator authority's normalized decision."""

    accepted: bool
    normalized: JsonValue
    error_class: str | None


def _load_object(path: Path) -> JsonObject:
    value: object = load_json_value(
        path.read_bytes(),
        object_pairs_hook=_closed_pairs,
    )
    return require_json_object(value, context=path.name)


def _closed_pairs(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            msg = "JSON object contains a duplicate member"
            raise ValueError(msg)
        if not is_json_value(value):
            msg = "JSON object contains a non-JSON value"
            raise TypeError(msg)
        result[key] = value
    return result


def _strict_member(value: object, *, field: str, expected_type: type[object]) -> object:
    if type(value) is not expected_type:
        msg = f"corpus field {field} has an invalid runtime type"
        raise TypeError(msg)
    return value


def _parse_corpus_entry(value: object) -> CorpusEntry:
    raw = require_json_object(value, context="contract corpus entry")
    if frozenset(raw) != _CORPUS_FIELDS:
        msg = "contract corpus entry fields do not match the closed format"
        raise ValueError(msg)
    requirement_id = cast(
        "str",
        _strict_member(
            raw["requirement_id"],
            field="requirement_id",
            expected_type=str,
        ),
    )
    schema_key = cast(
        "str", _strict_member(raw["schema_key"], field="schema_key", expected_type=str)
    )
    mode = cast("str", _strict_member(raw["mode"], field="mode", expected_type=str))
    expected = cast(
        "str", _strict_member(raw["expected"], field="expected", expected_type=str)
    )
    raw_json = cast(
        "str", _strict_member(raw["raw_json"], field="raw_json", expected_type=str)
    )
    parsed = cast(
        "bool", _strict_member(raw["parsed"], field="parsed", expected_type=bool)
    )
    keyword = cast(
        "str", _strict_member(raw["keyword"], field="keyword", expected_type=str)
    )
    error_value = raw["error_class"]
    if error_value is not None and type(error_value) is not str:
        msg = "corpus field error_class has an invalid runtime type"
        raise TypeError(msg)
    if (
        not requirement_id
        or len(requirement_id) > _MAX_REQUIREMENT_ID_LENGTH
        or not schema_key
        or len(schema_key) > _MAX_SCHEMA_KEY_LENGTH
        or mode not in {"input", "output"}
        or expected not in {"accept", "reject"}
        or not raw_json
        or len(raw_json.encode("utf-8")) > _MAX_RAW_JSON_BYTES
        or not keyword
        or len(keyword) > _MAX_KEYWORD_LENGTH
        or (
            type(error_value) is str
            and len(error_value) > _MAX_ORACLE_ERROR_CLASS_LENGTH
        )
    ):
        msg = "contract corpus entry contains an invalid bounded value"
        raise ValueError(msg)
    expected_mode = "output" if schema_key.startswith("output.") else "input"
    if mode != expected_mode:
        msg = "contract corpus mode does not match its schema direction"
        raise ValueError(msg)
    verdict_is_complete = (expected == "accept" and error_value is None) or (
        expected == "reject"
        and type(error_value) is str
        and bool(error_value)
        and raw["normalized"] is None
    )
    if not verdict_is_complete:
        msg = "contract corpus verdict metadata is incomplete"
        raise ValueError(msg)
    return CorpusEntry(
        requirement_id=requirement_id,
        schema_key=schema_key,
        mode=cast("Literal['input', 'output']", mode),
        raw_json=raw_json,
        parsed=parsed,
        value=raw["value"],
        expected=cast("Literal['accept', 'reject']", expected),
        normalized=raw["normalized"],
        error_class=error_value,
        keyword=keyword,
    )


def _load_corpus() -> tuple[CorpusEntry, ...]:
    document = _load_object(CORPUS)
    if (
        frozenset(document) != frozenset({"entries", "version"})
        or document["version"] != 1
    ):
        msg = "contract corpus root does not match version 1"
        raise ValueError(msg)
    entries_value = document["entries"]
    if (
        not isinstance(entries_value, list)
        or not 1 <= len(entries_value) <= _MAX_CORPUS_ENTRIES
    ):
        msg = "contract corpus entry inventory is empty or oversized"
        raise ValueError(msg)
    entries = tuple(_parse_corpus_entry(value) for value in entries_value)
    identifiers = tuple(entry.requirement_id for entry in entries)
    if len(identifiers) != len(set(identifiers)):
        msg = "contract corpus requirement IDs are duplicated"
        raise ValueError(msg)
    return entries


def _model_inventory() -> dict[str, type[StrictInput | StrictOutput]]:
    return {
        item.key: cast("type[StrictInput | StrictOutput]", item.model)
        for item in contract_models()
    }


def _reject_nonfinite_constant(_value: str) -> None:
    msg = "non-finite JSON number"
    raise ValueError(msg)


def _json_shape_is_bounded(value: JsonValue) -> bool:
    visited = 0
    pending: list[tuple[JsonValue, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        visited += 1
        if visited > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            return False
        if isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
        elif isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
    return True


def _decode_raw(entry: CorpusEntry) -> tuple[bool, JsonValue]:
    try:
        value = load_json_value(
            entry.raw_json,
            object_pairs_hook=_closed_pairs,
            parse_constant=_reject_nonfinite_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        return False, None
    if not _json_shape_is_bounded(value):
        return False, None
    return True, value


def _primitive_pydantic_verdict(
    schema_key: str,
    value: JsonValue,
) -> AuthorityVerdict | None:
    try:
        if schema_key == "primitive.CodePoint2":
            normalized: object = _CODE_POINT_TWO.validate_python(value, strict=True)
        elif schema_key == "primitive.SafeInteger":
            normalized = _SAFE_INTEGER.validate_python(value, strict=True)
        else:
            return None
    except ValidationError:
        return AuthorityVerdict(
            accepted=False,
            normalized=None,
            error_class="validation_error",
        )
    if not is_json_value(normalized):
        msg = "Pydantic primitive normalization returned a non-JSON value"
        raise TypeError(msg)
    if type(normalized) is float and normalized == 0:
        normalized = 0
    return AuthorityVerdict(
        accepted=True,
        normalized=normalized,
        error_class=None,
    )


def _pydantic_verdict(entry: CorpusEntry) -> AuthorityVerdict:
    decoded, value = _decode_raw(entry)
    if not decoded:
        return AuthorityVerdict(
            accepted=False,
            normalized=None,
            error_class="invalid_json",
        )
    primitive = _primitive_pydantic_verdict(entry.schema_key, value)
    if primitive is not None:
        return primitive
    model = _model_inventory().get(entry.schema_key)
    if model is None:
        msg = "contract corpus refers to an unknown schema"
        raise ValueError(msg)
    try:
        result = model.model_validate(value, strict=True)
    except ValidationError:
        return AuthorityVerdict(
            accepted=False,
            normalized=None,
            error_class="validation_error",
        )
    normalized = cast("object", result.model_dump(mode="json", by_alias=True))
    if not is_json_value(normalized):
        msg = "Pydantic contract serialization returned a non-JSON value"
        raise TypeError(msg)
    return AuthorityVerdict(
        accepted=True,
        normalized=normalized,
        error_class=None,
    )


def _root_schema(aggregate: JsonObject, schema_key: str) -> JsonObject:
    _ = aggregate
    return {"$ref": f"{CONTRACT_SCHEMA_ID}#/$defs/{schema_key}"}


def _refuse_retrieval(uri: str) -> Resource[JsonObject]:
    msg = f"external schema retrieval is forbidden: {uri}"
    raise RuntimeError(msg)


def _schema_registry(aggregate: JsonObject) -> Registry[JsonObject]:
    resource = Resource[JsonObject].from_contents(aggregate)
    return Registry[JsonObject](retrieve=_refuse_retrieval).with_resource(
        CONTRACT_SCHEMA_ID,
        resource,
    )


def _format_checker() -> FormatChecker:
    return FormatChecker(formats=_ALLOWED_FORMATS)


def _nested_definition_sentinels() -> dict[str, JsonValue]:
    sha256 = "0" * 64
    text128_array = (
        "output.FrozenSequence_Annotated_str__StringConstraints__AfterValidator___"
        "MaxLen_max_length_128_"
    )
    text512_array = (
        "output.FrozenSequence_Annotated_str__StringConstraints__AfterValidator___"
        "MaxLen_max_length_512_"
    )
    rendered_page_array = (
        "output.FrozenSequence_RenderedPageRecord__MinLen_min_length_1__"
        "MaxLen_max_length_8_"
    )
    rendered_tile_array = (
        "output.FrozenSequence_RenderedTileRecord__MinLen_min_length_1__"
        "MaxLen_max_length_4096_"
    )
    rendered_page: JsonObject = {
        "asset_url": "https://example.invalid/x.jpg",
        "classification": "text",
        "conversion_path": "direct",
        "effective_dpi_x": 72.0,
        "effective_dpi_y": 72.0,
        "height": 1,
        "lossy_conversion": True,
        "media_type": "image/jpeg",
        "page_number": 1,
        "pixel_dimensions_preserved": True,
        "reencoded": True,
        "relative_path": "renders/x.jpg",
        "renderer_resampling": "none",
        "resolution_source": "native",
        "resize_applied": False,
        "resource_uri": f"nplg://artifact/doc_{sha256}",
        "rotation": 0,
        "sha256": sha256,
        "width": 1,
    }
    rendered_tile: JsonObject = {
        "asset_url": "https://example.invalid/t0.jpg",
        "full_page_height": 256,
        "full_page_width": 256,
        "height": 256,
        "lossy_conversion": True,
        "media_type": "image/jpeg",
        "overlap": 0,
        "page_number": 1,
        "pixel_dimensions_preserved": True,
        "reencoded": True,
        "relative_path": "tiles/t0.jpg",
        "renderer_resampling": "none",
        "resize_applied": False,
        "resource_uri": f"nplg://artifact/doc_{sha256}",
        "sha256": sha256,
        "tile_id": "t0",
        "width": 256,
        "x": 0,
        "y": 0,
    }
    return {
        "output.DocumentFileRecord": {
            "access_status": "public",
            "bitstream_id": "bs_public",
            "description": None,
            "filename": "fixture.pdf",
            "handle": "1234/560449",
            "reported_format": None,
            "reported_size": None,
            "source_url": "https://example.invalid/fixture.pdf",
        },
        text128_array: [],
        text512_array: [],
        "output.FrozenSequence_DocumentFileRecord__MaxLen_max_length_512_": [],
        "output.FrozenSequence_PageInspectionRecord__MaxLen_max_length_10000_": [],
        "output.FrozenSequence_RawMetadataFieldOutput__MaxLen_max_length_4096_": [],
        rendered_page_array: [rendered_page],
        rendered_tile_array: [rendered_tile],
        "output.FrozenSequence_SearchDocumentRecord__MaxLen_max_length_50_": [],
        "output.PageInspectionRecord": {
            "classification": "text",
            "crop_applied": False,
            "direct_jpeg_eligible": False,
            "dominant_coverage": None,
            "dominant_extension": None,
            "dominant_image_index": None,
            "effective_dpi_x": None,
            "effective_dpi_y": None,
            "has_drawings": False,
            "has_text": True,
            "height_points": 1.0,
            "image_count": 0,
            "native_height": None,
            "native_raster_extract_eligible": False,
            "native_width": None,
            "page_number": 1,
            "rotation": 0,
            "width_points": 1.0,
        },
        "output.RawMetadataFieldOutput": {
            "key": "dc.title",
            "language": None,
            "value": "Fixture",
        },
        "output.RenderedPageRecord": rendered_page,
        "output.RenderedTileRecord": rendered_tile,
        "output.SearchDocumentRecord": {
            "authors": [],
            "canonical_url": "https://example.invalid/handle/1234/560449",
            "handle": "1234/560449",
            "issue_date": None,
            "title": "Fixture",
        },
    }


def _json_schema_verdict(
    entry: CorpusEntry,
    *,
    schema_document: JsonObject | None = None,
) -> AuthorityVerdict:
    decoded, value = _decode_raw(entry)
    if not decoded:
        return AuthorityVerdict(
            accepted=False,
            normalized=None,
            error_class="invalid_json",
        )
    aggregate = (
        aggregate_contract_schema() if schema_document is None else schema_document
    )
    if entry.schema_key == "primitive.CodePoint2":
        schema: JsonObject = {"maxLength": 2, "minLength": 1, "type": "string"}
        validator = Draft202012Validator(schema, format_checker=_format_checker())
    elif entry.schema_key == "primitive.SafeInteger":
        schema = {
            "maximum": 9_007_199_254_740_991,
            "minimum": -9_007_199_254_740_991,
            "type": "integer",
        }
        validator = Draft202012Validator(schema, format_checker=_format_checker())
    else:
        if entry.schema_key not in _model_inventory():
            msg = "contract corpus refers to an unknown schema"
            raise ValueError(msg)
        root = _root_schema(aggregate, entry.schema_key)
        validator = Draft202012Validator(
            root,
            registry=_schema_registry(aggregate),
            format_checker=_format_checker(),
        )
    try:
        validator.validate(value)
    except JsonSchemaValidationError:
        return AuthorityVerdict(
            accepted=False,
            normalized=None,
            error_class="validation_error",
        )
    normalized = 0 if type(value) is float and value == 0 else value
    return AuthorityVerdict(
        accepted=True,
        normalized=normalized,
        error_class=None,
    )


def _node_executable() -> Path:
    configured = os.environ.get("NPLG_REVIEWED_NODE")
    candidate = configured if configured is not None else shutil.which("node")
    if candidate is None:
        msg = "reviewed Node executable is unavailable"
        raise RuntimeError(msg)
    return Path(candidate).resolve(strict=True)


def _python_only_contract_gate() -> bool:
    value = os.environ.get("NPLG_PYTHON_ONLY_CONTRACT_GATE")
    if value not in {None, "1"}:
        msg = "Python-only contract gate marker is malformed"
        raise RuntimeError(msg)
    return value == "1"


def _run_process(
    command: tuple[str, ...],
    *,
    timeout_seconds: float,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        command,
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout_seconds,
        env=environment,
    )


def _run_zod_oracle(
    *extra: str,
    timeout_seconds: float = 30.0,
) -> JsonObject:
    result = _run_process(
        (_node_executable().as_posix(), NODE_ORACLE.as_posix(), "--oracle", *extra),
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0 or result.stderr or not result.stdout:
        msg = "Zod oracle process failed"
        raise RuntimeError(msg)
    if len(result.stdout) > _MAX_ORACLE_BYTES:
        msg = "Zod oracle output is oversized"
        raise RuntimeError(msg)
    value = load_json_value(
        result.stdout,
        object_pairs_hook=_closed_pairs,
        parse_constant=_reject_nonfinite_constant,
    )
    return require_json_object(value, context="Zod oracle result")


def _run_private_zod_source_mutant(
    temporary_root: Path,
    *,
    target: str,
    replacement: str,
) -> JsonObject:
    mutant_root = temporary_root / "private-mutant"
    mutant_contracts = mutant_root / "contracts"
    mutant_zod = mutant_contracts / "zod"
    mutant_zod.mkdir(parents=True)
    zod_uri = (ROOT / "node_modules" / "zod" / "index.js").as_uri()
    for source_path in (
        ROOT / "contracts" / "zod" / "models.ts",
        NODE_ORACLE,
    ):
        source = source_path.read_text(encoding="utf-8").replace(
            'from "zod";',
            f'from "{zod_uri}";',
        )
        if source_path.name == "models.ts":
            if source.count(target) != 1:
                msg = "Zod source mutant target is not unique"
                raise AssertionError(msg)
            source = source.replace(target, replacement)
        _ = (mutant_zod / source_path.name).write_text(source, encoding="utf-8")
    _ = (mutant_contracts / CORPUS.name).write_bytes(CORPUS.read_bytes())
    result = _run_process(
        (
            _node_executable().as_posix(),
            (mutant_zod / NODE_ORACLE.name).as_posix(),
            "--oracle",
        ),
        timeout_seconds=30.0,
    )
    if result.returncode != 0 or result.stderr or not result.stdout:
        detail = (result.stderr or result.stdout)[:1024].decode(
            "utf-8",
            errors="replace",
        )
        msg = f"private Zod source mutant did not produce an oracle document: {detail}"
        raise RuntimeError(msg)
    value = load_json_value(
        result.stdout,
        object_pairs_hook=_closed_pairs,
        parse_constant=_reject_nonfinite_constant,
    )
    return require_json_object(value, context="private Zod source mutant")


def _validated_zod_schemas(document: JsonObject) -> JsonObject:
    schemas = require_json_object(document["schemas"], context="Zod schemas")
    if frozenset(schemas) != frozenset(_model_inventory()):
        msg = "Zod oracle schema inventory does not match the closed catalog"
        raise ValueError(msg)
    for key, value in schemas.items():
        schema = require_json_object(value, context=f"Zod schema {key}")
        if not _json_shape_is_bounded(schema):
            msg = "Zod oracle schema exceeds structural limits"
            raise ValueError(msg)
    return schemas


def _zod_results(document: JsonObject) -> dict[str, AuthorityVerdict]:
    if frozenset(document) != frozenset(
        {"protocol_version", "results", "schemas", "zod_version"}
    ):
        msg = "Zod oracle result fields do not match the protocol"
        raise ValueError(msg)
    if document["protocol_version"] != 1 or document["zod_version"] != "4.5.4":
        msg = "Zod oracle protocol or dependency version is unexpected"
        raise ValueError(msg)
    _ = _validated_zod_schemas(document)
    raw_results = document["results"]
    if (
        not isinstance(raw_results, list)
        or not 1 <= len(raw_results) <= _MAX_ORACLE_RESULTS
    ):
        msg = "Zod oracle results must be a bounded nonempty array"
        raise TypeError(msg)
    results: dict[str, AuthorityVerdict] = {}
    for value in raw_results:
        item = require_json_object(value, context="Zod oracle verdict")
        if frozenset(item) != frozenset(
            {
                "accepted",
                "error_class",
                "normalized",
                "requirement_id",
            }
        ):
            msg = "Zod oracle verdict fields do not match the protocol"
            raise ValueError(msg)
        identifier = item["requirement_id"]
        accepted = item["accepted"]
        error_class = item["error_class"]
        if (
            type(identifier) is not str
            or type(accepted) is not bool
            or (error_class is not None and type(error_class) is not str)
            or (
                type(error_class) is str
                and len(error_class) > _MAX_ORACLE_ERROR_CLASS_LENGTH
            )
            or not identifier
            or len(identifier) > _MAX_REQUIREMENT_ID_LENGTH
            or identifier in results
        ):
            msg = "Zod oracle verdict contains malformed or duplicate data"
            raise ValueError(msg)
        normalized = item["normalized"]
        if not _json_shape_is_bounded(normalized):
            msg = "Zod oracle normalization exceeds structural limits"
            raise ValueError(msg)
        verdict_is_complete = (accepted and error_class is None) or (
            not accepted
            and normalized is None
            and type(error_class) is str
            and bool(error_class)
        )
        if not verdict_is_complete:
            msg = "Zod oracle verdict invariant is contradictory"
            raise ValueError(msg)
        results[identifier] = AuthorityVerdict(
            accepted=accepted,
            normalized=normalized,
            error_class=error_class,
        )
    return results


def test_generated_contract_schema_matches_the_pydantic_authority() -> None:
    expected_schema = aggregate_contract_schema()
    expected_manifest = schema_manifest()
    assert (GENERATED / "tool-contracts.schema.json").read_bytes() == (
        canonical_json_bytes(expected_schema)
    )
    assert (GENERATED / "schema-manifest.json").read_bytes() == (
        canonical_json_bytes(expected_manifest)
    )


def test_every_contract_schema_is_closed_and_uses_root_local_references() -> None:
    aggregate = aggregate_contract_schema()
    assert aggregate["$schema"] == DRAFT_2020_12
    Draft202012Validator.check_schema(aggregate)
    pending: list[object] = [aggregate]
    while pending:
        current = pending.pop()
        if isinstance(current, list):
            pending.extend(cast("list[object]", current))
        elif isinstance(current, dict):
            node = cast("dict[object, object]", current)
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
            reference = node.get("$ref")
            if reference is not None:
                assert isinstance(reference, str)
                assert reference.startswith("#/$defs/")
            pending.extend(node.values())

    definitions = require_json_object(aggregate["$defs"], context="aggregate $defs")
    registry = _schema_registry(aggregate)
    for key in definitions:
        validator = Draft202012Validator(
            _root_schema(aggregate, key),
            registry=registry,
            format_checker=_format_checker(),
        )
        first_error = next(validator.iter_errors(None), None)
        assert first_error is None or isinstance(
            first_error,
            JsonSchemaValidationError,
        )


def test_every_definition_pointer_has_closed_positive_and_negative_sentinels() -> None:
    aggregate = aggregate_contract_schema()
    definitions = require_json_object(aggregate["$defs"], context="aggregate $defs")
    sentinels = _nested_definition_sentinels()
    for entry in _load_corpus():
        if entry.expected != "accept" or entry.schema_key not in definitions:
            continue
        decoded, value = _decode_raw(entry)
        assert decoded
        _ = sentinels.setdefault(entry.schema_key, value)
    assert frozenset(sentinels) == frozenset(definitions)

    registry = _schema_registry(aggregate)
    for key, sentinel in sentinels.items():
        validator = Draft202012Validator(
            _root_schema(aggregate, key),
            registry=registry,
            format_checker=_format_checker(),
        )
        validator.validate(sentinel)
        if isinstance(sentinel, dict):
            negative: JsonValue = {**copy.deepcopy(sentinel), "unexpected": True}
        else:
            negative = {"not": "an array"}
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(negative)


def run_contract_oracle(
    document: JsonObject,
    *,
    advertised_schemas: JsonObject | None = None,
    draft_schema: JsonObject | None = None,
) -> None:
    """Run the reusable independent corpus and schema comparison authority."""
    corpus = _load_corpus()
    aggregate = aggregate_contract_schema()
    _require_single_dialect(aggregate)
    registry = _schema_registry(aggregate)
    zod_results = _zod_results(document)
    zod_schemas = require_json_object(document["schemas"], context="Zod schemas")
    pydantic_schemas = export_contract_schemas()
    assert frozenset(zod_schemas) == frozenset(pydantic_schemas)
    for key, pydantic_schema in pydantic_schemas.items():
        zod_schema = require_json_object(zod_schemas[key], context=f"Zod {key}")
        assert normalized_schema(zod_schema) == normalized_schema(pydantic_schema), (
            f"{key}: Zod schema parity"
        )

    if advertised_schemas is not None:
        if frozenset(advertised_schemas) != frozenset(pydantic_schemas):
            msg = "advertised schema inventory does not match the closed catalog"
            raise AssertionError(msg)
        for key, pydantic_schema in pydantic_schemas.items():
            advertised = require_json_object(
                advertised_schemas[key],
                context=f"advertised {key}",
            )
            assert normalized_schema(advertised) == normalized_schema(
                pydantic_schema
            ), f"{key}: advertised schema parity"

    assert frozenset(zod_results) == {entry.requirement_id for entry in corpus}
    for entry in corpus:
        decoded, value = _decode_raw(entry)
        assert decoded is entry.parsed, entry.requirement_id
        if decoded:
            assert value == entry.value, entry.requirement_id
        expected = entry.expected == "accept"
        pydantic_result = _pydantic_verdict(entry)
        zod_result = zod_results[entry.requirement_id]
        json_schema_result = _json_schema_verdict(
            entry,
            schema_document=draft_schema,
        )
        assert pydantic_result.accepted is expected, (
            f"{entry.requirement_id}: Pydantic verdict"
        )
        assert zod_result.accepted is expected, f"{entry.requirement_id}: Zod verdict"
        assert json_schema_result.accepted is expected, (
            f"{entry.requirement_id}: Draft 2020-12 verdict"
        )
        if expected:
            assert pydantic_result.normalized == entry.normalized, entry.requirement_id
            assert zod_result.normalized == entry.normalized, entry.requirement_id
            if entry.mode == "output":
                Draft202012Validator(
                    _root_schema(aggregate, entry.schema_key),
                    registry=registry,
                    format_checker=_format_checker(),
                ).validate(pydantic_result.normalized)
        else:
            assert entry.error_class is not None
            assert pydantic_result.error_class is not None
            assert zod_result.error_class is not None
            assert json_schema_result.error_class is not None


def test_pydantic_zod_and_draft_validator_match_the_frozen_corpus() -> None:
    if _python_only_contract_gate():
        return
    oracle = _run_zod_oracle()
    schemas = require_json_object(oracle["schemas"], context="Zod schemas")
    run_contract_oracle(oracle, advertised_schemas=schemas)


def test_output_schema_requires_fields_materialized_by_default_serialization() -> None:
    schemas = export_contract_schemas()
    search = schemas["output.SearchDocumentsOutput"]
    required = search["required"]
    assert isinstance(required, list)
    assert "next_cursor" in required
    metadata = schemas["output.DocumentMetadataOutput"]
    metadata_required = metadata["required"]
    assert isinstance(metadata_required, list)
    assert "restricted" in metadata_required
    assert "raw_fields" in metadata_required


def test_catalog_has_no_unreviewed_serialization_or_alias_hooks() -> None:
    for item in contract_models():
        decorators = item.model.__pydantic_decorators__
        assert not decorators.field_serializers, item.key
        assert not decorators.model_serializers, item.key
        assert not decorators.computed_fields, item.key
        for name, field in item.model.model_fields.items():
            assert field.alias is None, f"{item.key}.{name}"
            assert field.validation_alias is None, f"{item.key}.{name}"
            assert field.serialization_alias is None, f"{item.key}.{name}"

    zod_source = (ROOT / "contracts" / "zod" / "models.ts").read_text(encoding="utf-8")
    for forbidden in (
        ".catch(",
        ".pipe(",
        ".transform(",
        "z.coerce.",
        "z.preprocess(",
    ):
        assert forbidden not in zod_source


def test_corpus_metadata_is_directional_and_verdict_complete() -> None:
    baseline = _load_corpus()[0]
    raw: JsonObject = {
        "error_class": baseline.error_class,
        "expected": baseline.expected,
        "keyword": baseline.keyword,
        "mode": baseline.mode,
        "normalized": baseline.normalized,
        "parsed": baseline.parsed,
        "raw_json": baseline.raw_json,
        "requirement_id": baseline.requirement_id,
        "schema_key": baseline.schema_key,
        "value": baseline.value,
    }
    wrong_mode = {**raw, "mode": "output" if baseline.mode == "input" else "input"}
    with pytest.raises(ValueError, match="mode"):
        _ = _parse_corpus_entry(wrong_mode)

    with pytest.raises(ValueError, match="verdict"):
        _ = _parse_corpus_entry({**raw, "error_class": "validation_error"})
    with pytest.raises(ValueError, match="verdict"):
        _ = _parse_corpus_entry(
            {
                **raw,
                "error_class": None,
                "expected": "reject",
                "normalized": None,
            }
        )


def test_normative_corpus_contains_code_point_and_common_mode_boundaries() -> None:
    entries = {entry.requirement_id: entry for entry in _load_corpus()}
    expected_cases = {
        "CP-BMP-N-1": ('"a"', True),
        "CP-BMP-N": ('"ab"', True),
        "CP-BMP-N+1": ('"abc"', False),
        "CP-ASTRAL-N-1": ('"😀"', True),
        "CP-ASTRAL-N": ('"😀😀"', True),
        "CP-ASTRAL-N+1": ('"😀😀😀"', False),
        "CP-COMBINING-N-1": ('"́"', True),
        "CP-COMBINING-N": ('"é"', True),
        "CP-COMBINING-N+1": ('"éx"', False),
        "CP-GRAPHEME-N-1": ('"✈"', True),
        "CP-GRAPHEME-N": ('"✈️"', True),
        "CP-GRAPHEME-N+1": ('"✈️x"', False),
        "BOUND-PAGE-SIZE-MAX": ('{"query":"x","page_size":50}', True),
        "BOUND-PAGE-SIZE-MAX+1": ('{"query":"x","page_size":51}', False),
    }
    assert expected_cases.keys() <= entries.keys()
    for identifier, (raw_json, accepted) in expected_cases.items():
        entry = entries[identifier]
        assert entry.raw_json == raw_json
        assert (entry.expected == "accept") is accepted


def test_normative_corpus_rejects_every_legacy_render_resource_uri() -> None:
    """Keep the removed page, tile, and tile-manifest URI grammar dead."""
    entries = {entry.requirement_id: entry for entry in _load_corpus()}
    expected = {
        "URI-LEGACY-PAGE": "/page/1",
        "URI-LEGACY-TILE": "/page/1/tile/t0",
        "URI-LEGACY-TILE-MANIFEST": "/page/1/tiles",
    }
    assert expected.keys() <= entries.keys()
    for requirement_id, legacy_suffix in expected.items():
        entry = entries[requirement_id]
        assert entry.mode == "output"
        assert entry.expected == "reject"
        assert entry.error_class == "validation_error"
        assert legacy_suffix in entry.raw_json


def test_schema_dialect_and_format_inventory_are_closed() -> None:
    aggregate = aggregate_contract_schema()
    assert aggregate["$schema"] == DRAFT_2020_12
    pending: list[tuple[object, bool]] = [(aggregate, True)]
    formats: set[str] = set()
    while pending:
        value, root = pending.pop()
        if isinstance(value, list):
            pending.extend((item, False) for item in cast("list[object]", value))
        elif isinstance(value, dict):
            node = cast("dict[object, object]", value)
            if not root:
                assert "$schema" not in node
                assert "$id" not in node
            format_value = node.get("format")
            if format_value is not None:
                assert isinstance(format_value, str)
                formats.add(format_value)
            pending.extend((item, False) for item in node.values())
    assert formats == set()


@pytest.mark.parametrize(
    "mutation",
    [
        "absent",
        "alternate",
        "nested",
    ],
)
def test_schema_dialect_mutations_are_rejected(mutation: str) -> None:
    aggregate = aggregate_contract_schema()
    if mutation == "absent":
        _ = aggregate.pop("$schema")
    elif mutation == "alternate":
        aggregate["$schema"] = "https://json-schema.org/draft/2019-09/schema"
    else:
        definitions = require_json_object(aggregate["$defs"], context="$defs")
        first = require_json_object(
            next(iter(definitions.values())),
            context="definition",
        )
        first["$schema"] = DRAFT_2020_12
    with pytest.raises(ValueError, match="dialect"):
        _require_single_dialect(aggregate)


@pytest.mark.parametrize(
    ("schema", "expected_type", "expected_message"),
    [
        ({"pattern": 1}, TypeError, "pattern must be a string"),
        ({"pattern": "x"}, ValueError, "full anchors"),
        ({"pattern": "^(?=x)x$"}, ValueError, "regex intersection"),
        ({"pattern": "^[a-$"}, ValueError, "pattern is invalid"),
        ({"required": "x"}, TypeError, "required must be an array"),
        ({"required": [1]}, ValueError, "unique string"),
        ({"required": ["x", "x"]}, ValueError, "unique string"),
        ({"unreviewed": True}, ValueError, "unsupported keyword"),
        ({"$id": "urn:test"}, ValueError, "cannot declare resource identity"),
        (
            {"type": "array", "items": {"$id": "urn:test"}},
            ValueError,
            "cannot rebase",
        ),
        ({"maximum": "1"}, ValueError, "malformed numeric bound"),
        ({"maximum": float("inf")}, ValueError, "malformed numeric bound"),
        ({"type": 1}, ValueError, "type is unsupported"),
        ({"type": "integerish"}, ValueError, "type is unsupported"),
        ({"type": "object"}, ValueError, "recursively closed"),
        ({"$ref": 1}, ValueError, "references must be root-local"),
        ({"$ref": "https://example.invalid/schema"}, ValueError, "root-local"),
        ({"format": "uri"}, ValueError, "unknown format"),
        ({"properties": []}, TypeError, "properties must be a JSON object"),
        ({"items": []}, TypeError, "array item schema must be a JSON object"),
        ({"anyOf": "x"}, ValueError, "anyOf must contain schemas"),
        ({"anyOf": []}, ValueError, "anyOf must contain schemas"),
        ({"anyOf": [1]}, TypeError, "alternative schema must be a JSON object"),
    ],
)
def test_schema_validator_rejects_adversarial_node_shapes(
    schema: JsonObject,
    expected_type: type[Exception],
    expected_message: str,
) -> None:
    with pytest.raises(expected_type, match=expected_message):
        schema_module._validate_schema(  # pyright: ignore[reportPrivateUsage]
            schema,
            allow_root_identity=False,
        )


@pytest.mark.parametrize("keyword", ["maxItems", "maxLength", "minItems", "minLength"])
@pytest.mark.parametrize("value", [-1, 1.5, True])
def test_schema_guard_rejects_invalid_cardinality_before_metaschema(
    keyword: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="nonnegative integer"):
        schema_module._validate_schema(  # pyright: ignore[reportPrivateUsage]
            cast("JsonObject", {keyword: value}),
            allow_root_identity=False,
        )


def test_schema_validator_rejects_excessive_nesting() -> None:
    schema: JsonObject = {}
    for _index in range(_MAX_JSON_DEPTH + 2):
        schema = {"items": schema}

    with pytest.raises(ValueError, match="structural limits"):
        schema_module._validate_schema(  # pyright: ignore[reportPrivateUsage]
            schema,
            allow_root_identity=False,
        )


def test_canonical_json_rejects_non_json_runtime_values() -> None:
    with pytest.raises(TypeError, match="non-JSON"):
        _ = canonical_json_bytes(cast("JsonValue", {"not", "json"}))


def test_schema_export_rejects_unsorted_contract_model_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    models = contract_models()
    monkeypatch.setattr(
        schema_module,
        "contract_models",
        lambda: tuple(reversed(models)),
    )

    with pytest.raises(ValueError, match="UTF-8-key sorted"):
        _ = export_contract_schemas()


def test_reference_rewriter_rejects_nonlocal_reference() -> None:
    with pytest.raises(ValueError, match="non-local reference"):
        _ = schema_module._rewrite_references(  # pyright: ignore[reportPrivateUsage]
            {"$ref": "https://example.invalid/schema"},
            direction="input",
        )


def test_aggregate_rejects_malformed_and_colliding_definition_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MalformedContract:
        key = "malformed"

    with monkeypatch.context() as scoped:
        scoped.setattr(
            schema_module,
            "contract_models",
            lambda: (MalformedContract(),),
        )
        with pytest.raises(ValueError, match="key is malformed"):
            _ = aggregate_contract_schema({"malformed": {}})

    class A(StrictInput):
        value: str

    class B(StrictInput):
        value: str

    models = (
        schema_module.ContractModel(direction="input", model=A),
        schema_module.ContractModel(direction="input", model=B),
    )
    with monkeypatch.context() as scoped:
        scoped.setattr(schema_module, "contract_models", lambda: models)
        with pytest.raises(ValueError, match="duplicate aggregate"):
            _ = aggregate_contract_schema(
                {
                    "input.A": {"$defs": {"B": {"type": "string"}}},
                    "input.B": {"type": "string"},
                }
            )
        with pytest.raises(ValueError, match="conflicting aggregate"):
            _ = aggregate_contract_schema(
                {
                    "input.A": {"$defs": {"Shared": {"type": "string"}}},
                    "input.B": {"$defs": {"Shared": {"type": "integer"}}},
                }
            )


def _require_single_dialect(aggregate: JsonObject) -> None:
    if aggregate.get("$schema") != DRAFT_2020_12:
        msg = "root dialect mismatch"
        raise ValueError(msg)
    pending: list[tuple[object, bool]] = [(aggregate, True)]
    while pending:
        value, root = pending.pop()
        if isinstance(value, dict):
            node = cast("dict[object, object]", value)
            if not root and "$schema" in node:
                msg = "nested dialect is forbidden"
                raise ValueError(msg)
            pending.extend((child, False) for child in node.values())
        elif isinstance(value, list):
            pending.extend((child, False) for child in cast("list[object]", value))


def test_oracle_protocol_rejects_malformed_and_duplicate_results() -> None:
    if _python_only_contract_gate():
        return
    valid = _run_zod_oracle()
    for field in ("protocol_version", "zod_version", "schemas"):
        malformed = dict(valid)
        _ = malformed.pop(field)
        with pytest.raises(ValueError, match="protocol"):
            _ = _zod_results(malformed)
    wrong_version = dict(valid)
    wrong_version["protocol_version"] = 2
    with pytest.raises(ValueError, match="protocol"):
        _ = _zod_results(wrong_version)
    duplicate = dict(valid)
    results = duplicate["results"]
    assert isinstance(results, list)
    duplicate["results"] = [*results, results[0]]
    with pytest.raises(ValueError, match="duplicate"):
        _ = _zod_results(duplicate)
    oversized = dict(valid)
    oversized["results"] = [*results] * (_MAX_ORACLE_RESULTS + 1)
    with pytest.raises(TypeError, match="bounded"):
        _ = _zod_results(oversized)

    malformed_schema = copy.deepcopy(valid)
    malformed_schemas = require_json_object(
        malformed_schema["schemas"],
        context="mutated Zod schemas",
    )
    malformed_schemas[next(iter(malformed_schemas))] = None
    with pytest.raises(TypeError, match="schema"):
        _ = _zod_results(malformed_schema)

    excessive_normalization = copy.deepcopy(valid)
    excessive_results = excessive_normalization["results"]
    assert isinstance(excessive_results, list)
    first_result = require_json_object(
        excessive_results[0],
        context="mutated Zod result",
    )
    nested: JsonValue = None
    for _index in range(_MAX_JSON_DEPTH + 2):
        nested = {"nested": nested}
    first_result["normalized"] = nested
    with pytest.raises(ValueError, match="structural"):
        _ = _zod_results(excessive_normalization)


@pytest.mark.parametrize(
    ("accepted", "normalized", "error_class"),
    [
        (True, {}, "validation_error"),
        (False, {}, "validation_error"),
        (False, None, None),
        (False, None, ""),
    ],
)
def test_reusable_oracle_rejects_contradictory_verdict_envelopes(
    *,
    accepted: bool,
    normalized: JsonValue,
    error_class: str | None,
) -> None:
    if _python_only_contract_gate():
        return
    mutant = copy.deepcopy(_run_zod_oracle())
    raw_results = mutant["results"]
    assert isinstance(raw_results, list)
    result = require_json_object(raw_results[0], context="mutated Zod result")
    result["accepted"] = accepted
    result["normalized"] = normalized
    result["error_class"] = error_class

    with pytest.raises(ValueError, match="verdict invariant"):
        run_contract_oracle(mutant)


def test_oracle_launcher_fails_closed_on_process_and_protocol_faults() -> None:
    if _python_only_contract_gate():
        return
    with pytest.raises(subprocess.TimeoutExpired):
        _ = _run_zod_oracle("--self-test-delay", timeout_seconds=0.01)
    with pytest.raises(RuntimeError, match="process failed"):
        _ = _run_zod_oracle("--self-test-nonzero")
    with pytest.raises(json.JSONDecodeError):
        _ = _run_zod_oracle("--self-test-malformed")
    with pytest.raises(ValueError, match="duplicate"):
        _ = _run_zod_oracle("--self-test-duplicate-schema")
    for fault in ("--self-test-missing-schema", "--self-test-extra-schema"):
        with pytest.raises(ValueError, match="schema inventory"):
            _ = _zod_results(_run_zod_oracle(fault))


@pytest.mark.parametrize(
    ("name", "target", "replacement", "reason"),
    [
        (
            "strict-object",
            "export const handleInput = z.strictObject({",
            "export const handleInput = z.object({",
            "input.HandleInput: Zod schema parity",
        ),
        (
            "required-field",
            ("export const handleInput = z.strictObject({\n  handle: inputHandle,"),
            (
                "export const handleInput = z.strictObject({\n"
                "  handle: inputHandle.optional(),"
            ),
            "input.HandleInput: Zod schema parity",
        ),
        (
            "bound",
            "page_size: safeInteger.gte(1).lte(50).default(20),",
            "page_size: safeInteger.gte(1).lte(51).default(20),",
            "input.SearchDocumentsInput: Zod schema parity",
        ),
        (
            "field-alias",
            (
                "export const artifactInput = z.strictObject({\n"
                "  artifact_id: artifactId,"
            ),
            (
                "export const artifactInput = z.strictObject({\n"
                "  artifact_alias: artifactId,"
            ),
            "input.ArtifactInput: Zod schema parity",
        ),
        (
            "safe-integer",
            (
                "const safeInteger = z.number().int().gte(MIN_SAFE_INTEGER)"
                ".lte(MAX_SAFE_INTEGER);"
            ),
            "const safeInteger = z.number();",
            "input.RenderPagesInput: Zod schema parity",
        ),
        (
            "code-point-runtime",
            (
                "const length = Array.from(value).length;\n"
                "    if (length < minimum || length > maximum) {"
            ),
            ("const length = Array.from(value).length;\n    if (length < minimum) {"),
            "CP-003: Zod verdict",
        ),
        (
            "text64-runtime-registry-drift",
            "const text64 = inertText(CODE_POINT_LIMITS.text64);",
            ("const text64 = inertText(Object.freeze({ minimum: 1, maximum: 65 }));"),
            "CP-FIELD-TEXT64-N+1: Zod verdict",
        ),
        (
            "text64-registry-runtime-drift",
            (
                '"output.DocumentFilesOutput": [\n'
                '    bound("/$defs/DocumentFileRecord/properties/access_status", '
                "CODE_POINT_LIMITS.text64),"
            ),
            (
                '"output.DocumentFilesOutput": [\n'
                '    bound("/$defs/DocumentFileRecord/properties/access_status", '
                "CODE_POINT_LIMITS.text128),"
            ),
            "output.DocumentFilesOutput: Zod schema parity",
        ),
        (
            "injected-code-point-keywords",
            "injectCodePointBounds(converted, codePointBounds[key]);",
            "void codePointBounds[key];",
            "input.DownloadDocumentInput: Zod schema parity",
        ),
        (
            "input-output-mode",
            "io: direction,",
            'io: "input",',
            "output.DocumentFilesOutput: Zod schema parity",
        ),
    ],
)
def test_private_zod_source_mutants_are_killed_for_named_reasons(
    tmp_path: Path,
    name: str,
    target: str,
    replacement: str,
    reason: str,
) -> None:
    if _python_only_contract_gate():
        return
    document = _run_private_zod_source_mutant(
        tmp_path / name,
        target=target,
        replacement=replacement,
    )
    with pytest.raises(AssertionError, match=re.escape(reason)):
        run_contract_oracle(document)


def test_private_root_dialect_mutant_is_killed_for_the_named_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if _python_only_contract_gate():
        return
    mutant = aggregate_contract_schema()
    _ = mutant.pop("$schema")
    mutant_path = tmp_path / "tool-contracts.schema.json"
    _ = mutant_path.write_bytes(canonical_json_bytes(mutant))
    private_mutant = require_json_object(
        load_json_value(mutant_path.read_bytes()),
        context="private root-dialect mutant",
    )
    monkeypatch.setattr(
        f"{__name__}.aggregate_contract_schema",
        lambda: private_mutant,
    )

    with pytest.raises(ValueError, match="root dialect mismatch"):
        run_contract_oracle(_run_zod_oracle())


def test_common_mode_bound_mutation_is_still_killed_by_normative_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if _python_only_contract_gate():
        return

    class SearchDocumentsInput(OriginalSearchDocumentsInput):
        """Validated input for repository search."""

        page_size: Annotated[
            int,
            Ge(1),
            Le(51),
            SAFE_INTEGER_VALIDATOR,
        ] = 20

    original_bindings = tool_model_bindings()
    monkeypatch.setattr(
        schema_module,
        "tool_model_bindings",
        lambda: tuple(
            replace(binding, input_model=SearchDocumentsInput)
            if binding.input_model is OriginalSearchDocumentsInput
            else binding
            for binding in original_bindings
        ),
    )
    document = _run_private_zod_source_mutant(
        tmp_path,
        target="page_size: safeInteger.gte(1).lte(50).default(20),",
        replacement="page_size: safeInteger.gte(1).lte(51).default(20),",
    )
    with pytest.raises(
        AssertionError,
        match=r"BOUND\-PAGE\-SIZE\-MAX\+1: Pydantic verdict",
    ):
        run_contract_oracle(document)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "renamed", "keyword", "format"],
)
def test_aggregate_export_rejects_inventory_and_vocabulary_drift(
    mutation: str,
) -> None:
    schemas = export_contract_schemas()
    first_key = next(iter(schemas))
    if mutation == "missing":
        _ = schemas.pop(first_key)
    elif mutation == "extra":
        schemas["input.UnreviewedInput"] = {"type": "string"}
    elif mutation == "renamed":
        schema = schemas.pop(first_key)
        schemas["input.RenamedInput"] = schema
    elif mutation == "keyword":
        schemas[first_key]["unevaluatedProperties"] = False
    else:
        schemas[first_key]["format"] = "uri"
    expected = "format" if mutation == "format" else "inventory|keyword"
    with pytest.raises(ValueError, match=expected):
        _ = aggregate_contract_schema(schemas)


def test_contract_model_inventory_rejects_duplicates_and_non_strict_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bindings = tool_model_bindings()
    monkeypatch.setattr(
        schema_module,
        "tool_model_bindings",
        lambda: (*bindings, bindings[0]),
    )
    with pytest.raises(ValueError, match="duplicate"):
        _ = contract_models()

    class UnreviewedModel(BaseModel):
        value: str

    monkeypatch.setattr(
        schema_module,
        "tool_model_bindings",
        lambda: (
            replace(
                bindings[0],
                input_model=cast("type[StrictInput]", UnreviewedModel),
            ),
        ),
    )
    with pytest.raises(TypeError, match="strict base"):
        _ = contract_models()


def test_exporter_fails_closed_on_extra_and_stale_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "generated"
    monkeypatch.setattr(exporter_module, "_OUTPUT", output)
    export_contracts(ExportRequest(check=False))
    export_contracts(ExportRequest(check=True))

    unexpected = output / "unexpected.json"
    _ = unexpected.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ExportError, match="inventory"):
        export_contracts(ExportRequest(check=True))
    unexpected.unlink()

    schema_path = output / "tool-contracts.schema.json"
    _ = schema_path.write_bytes(schema_path.read_bytes() + b" ")
    with pytest.raises(ExportError, match="stale"):
        export_contracts(ExportRequest(check=True))


def test_exporter_rejects_internal_inventory_and_size_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as scoped:
        scoped.setattr(exporter_module, "_EXPECTED_FILES", frozenset[str]())
        with pytest.raises(ExportError, match="unexpected artifact inventory"):
            _ = exporter_module._artifacts()  # pyright: ignore[reportPrivateUsage]
    with monkeypatch.context() as scoped:
        scoped.setattr(exporter_module, "_MAX_ARTIFACT_BYTES", 1)
        with pytest.raises(ExportError, match="empty or oversized"):
            _ = exporter_module._artifacts()  # pyright: ignore[reportPrivateUsage]


def test_exporter_rejects_unavailable_and_non_directory_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    monkeypatch.setattr(exporter_module, "_OUTPUT", missing)
    with pytest.raises(ExportError, match="directory is unavailable"):
        _ = exporter_module._validated_output_directory(  # pyright: ignore[reportPrivateUsage]
            create=False
        )

    output_file = tmp_path / "not-a-directory"
    _ = output_file.write_text("x", encoding="utf-8")
    monkeypatch.setattr(exporter_module, "_OUTPUT", output_file)
    with pytest.raises(ExportError, match="real directory"):
        _ = exporter_module._validated_output_directory(  # pyright: ignore[reportPrivateUsage]
            create=False
        )


def test_exporter_rejects_unreadable_or_nonregular_inventory_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "generated"
    output.mkdir()
    (output / "nested").mkdir()
    with pytest.raises(ExportError, match="non-regular"):
        _ = exporter_module._inventory(output)  # pyright: ignore[reportPrivateUsage]

    def fail_inventory(_path: Path) -> tuple[Path, ...]:
        raise OSError

    monkeypatch.setattr(Path, "iterdir", fail_inventory)
    with pytest.raises(ExportError, match="inventory is unavailable"):
        _ = exporter_module._inventory(output)  # pyright: ignore[reportPrivateUsage]


def test_exporter_rejects_missing_empty_and_unreadable_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(ExportError, match="artifact is missing"):
        _ = exporter_module._read_artifact(  # pyright: ignore[reportPrivateUsage]
            missing
        )

    empty = tmp_path / "empty.json"
    _ = empty.write_bytes(b"")
    with pytest.raises(ExportError, match="bounded regular file"):
        _ = exporter_module._read_artifact(  # pyright: ignore[reportPrivateUsage]
            empty
        )

    artifact = tmp_path / "artifact.json"
    _ = artifact.write_bytes(b"{}\n")

    def fail_read(_path: Path) -> bytes:
        raise OSError

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    with pytest.raises(ExportError, match="could not be read"):
        _ = exporter_module._read_artifact(  # pyright: ignore[reportPrivateUsage]
            artifact
        )


def test_exporter_cleans_temporary_file_after_incomplete_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def incomplete_write(_descriptor: int, _payload: object) -> int:
        return 0

    monkeypatch.setattr(os, "write", incomplete_write)
    with pytest.raises(ExportError, match="write was incomplete"):
        exporter_module._write_artifact(  # pyright: ignore[reportPrivateUsage]
            tmp_path / "artifact.json",
            b"{}\n",
        )
    assert tuple(tmp_path.iterdir()) == ()


def test_exporter_rejects_replace_and_post_write_inventory_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_replace(_source: Path, _target: Path) -> Path:
        raise OSError

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "replace", fail_replace)
        with pytest.raises(ExportError, match="could not be replaced"):
            exporter_module._write_artifact(  # pyright: ignore[reportPrivateUsage]
                tmp_path / "artifact.json",
                b"{}\n",
            )
    assert tuple(tmp_path.iterdir()) == ()

    output = tmp_path / "generated"
    monkeypatch.setattr(exporter_module, "_OUTPUT", output)
    inventories: list[frozenset[str]] = [frozenset(), frozenset()]

    def next_inventory(_path: Path) -> frozenset[str]:
        return inventories.pop(0)

    monkeypatch.setattr(exporter_module, "_inventory", next_inventory)
    with pytest.raises(ExportError, match="inventory changed"):
        export_contracts(ExportRequest(check=False))


def test_exporter_create_mode_rejects_preexisting_unknown_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "generated"
    output.mkdir()
    _ = (output / "unexpected.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(exporter_module, "_OUTPUT", output)

    with pytest.raises(ExportError, match="unexpected artifact"):
        export_contracts(ExportRequest(check=False))


def test_exporter_cli_returns_bounded_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_export(_request: ExportRequest) -> None:
        message = "canary"
        raise ExportError(message)

    monkeypatch.setattr(exporter_module, "export_contracts", fail_export)
    assert exporter_module.cli(["--check"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "contract export failed: canary\n"


def test_schema_and_manifest_are_deterministic_across_order_hash_locale_and_tz() -> (
    None
):
    schemas = export_contract_schemas()
    reversed_schemas = dict(reversed(tuple(schemas.items())))
    assert canonical_json_bytes(aggregate_contract_schema(schemas)) == (
        canonical_json_bytes(aggregate_contract_schema(reversed_schemas))
    )
    assert canonical_json_bytes(schema_manifest(schemas)) == canonical_json_bytes(
        schema_manifest(reversed_schemas)
    )

    probe = (
        "import base64,json,os;"
        "import nplg_mcp.contracts.schema as s;"
        "from nplg_mcp.contracts import DeploymentProfile,ToolAnnotations,"
        "ToolCatalog,ToolDefinition;"
        "from nplg_mcp.contracts.tool_models import tool_model_bindings;"
        "bindings=tool_model_bindings();"
        "annotations=ToolAnnotations(read_only_hint=True,destructive_hint=False,"
        "idempotent_hint=True,open_world_hint=False);"
        "definitions=tuple(ToolDefinition(name=b.name,title='Contract',"
        "description='Determinism registration',input_model=b.input_model,"
        "output_model=b.output_model,handler=lambda _value:None,"
        "annotations=annotations,profiles=frozenset({DeploymentProfile.PRIVATE_FULL}))"
        " for b in bindings);"
        "catalog=ToolCatalog(tuple(reversed(definitions)) "
        "if os.environ['NPLG_PERMUTE_CATALOG']=='1' else definitions);"
        "by_name={b.name:b for b in bindings};"
        "s.tool_model_bindings=lambda:tuple(by_name[d.name] for d in "
        "catalog.definitions);"
        "artifacts={'schema':s.canonical_json_bytes(s.aggregate_contract_schema()),"
        "'manifest':s.canonical_json_bytes(s.schema_manifest())};"
        "print(json.dumps({k:base64.b64encode(v).decode('ascii') "
        "for k,v in artifacts.items()},sort_keys=True,separators=(',',':')))"
    )
    observations: list[dict[str, bytes]] = []
    for seed, timezone, permutation in (
        ("1", "UTC", "0"),
        ("997", "Pacific/Kiritimati", "1"),
    ):
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NPLG_PERMUTE_CATALOG": permutation,
            "PYTHONHASHSEED": seed,
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": (ROOT / "src").as_posix(),
            "TZ": timezone,
        }
        result = _run_process(
            (Path(sys.executable).as_posix(), "-c", probe),
            timeout_seconds=10,
            environment=environment,
        )
        assert result.returncode == 0
        assert result.stderr == b""
        encoded = require_json_object(
            load_json_value(result.stdout),
            context="determinism probe",
        )
        observations.append(
            {
                key: base64.b64decode(cast("str", value), validate=True)
                for key, value in encoded.items()
            }
        )
    assert observations[0] == observations[1]
    assert observations[0] == {
        "manifest": canonical_json_bytes(schema_manifest()),
        "schema": canonical_json_bytes(aggregate_contract_schema()),
    }


@pytest.mark.parametrize(
    ("unit", "count"),
    [
        ("a", 1),
        ("😀", 1),
        ("e\u0301", 2),
        ("👨\u200d👩\u200d👧", 5),
    ],
)
def test_python_code_point_boundaries_do_not_count_utf16_or_graphemes(
    unit: str,
    count: int,
) -> None:
    adapter: TypeAdapter[str] = TypeAdapter(
        Annotated[
            str,
            StringConstraints(strict=True, min_length=count - 1, max_length=count),
        ]
    )
    points = tuple(unit)
    assert len(points) == count
    _ = adapter.validate_python("".join(points[:-1]), strict=True)
    assert adapter.validate_python(unit, strict=True) == unit
    with pytest.raises(ValidationError):
        _ = adapter.validate_python(unit + "x", strict=True)


def test_generated_inventory_has_no_unreviewed_artifacts() -> None:
    assert {path.name for path in GENERATED.iterdir()} == {
        "schema-manifest.json",
        "tool-contracts.schema.json",
    }
    assert _load_object(GENERATED / "tool-contracts.schema.json")
    assert _load_object(GENERATED / "schema-manifest.json")
    assert len(export_contract_schemas()) == _CONTRACT_MODEL_COUNT
