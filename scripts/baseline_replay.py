# Copyright (c) 2026 David Osipov
"""Strict, deterministic behavior capture and replay for the frozen baseline."""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import hashlib
import importlib
import json
import logging
import math
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from nplg_mcp.protocol import McpProtocol, ProtocolResponse
from scripts.baseline_capture_io import (
    BASELINE_FILES,
    MAX_CANONICAL_JSON_BYTES,
    MAX_CANONICAL_JSON_DEPTH,
    BaselineCaptureError,
    BaselineFileName,
    canonical_json_bytes,
    validate_json_depth,
    write_staged_file,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import Protocol

    from nplg_mcp.tools import ToolService

    class _AppFactoryModule(Protocol):
        def make_tool_service(
            self,
            root: Path,
            *,
            fault_mode: CaseFaultMode,
        ) -> ToolService: ...


MAX_REPLAY_REQUEST_BYTES = 64 * 1024
MAX_REPLAY_HEADERS = 8
MAX_REPLAY_HEADER_VALUE_LENGTH = 4096
MAX_JAVASCRIPT_SAFE_INTEGER = (2**53) - 1
BEHAVIOR_CASE_COUNT = 66
PRIVATE_DIRECTORY_MODE = 0o700
JSONRPC_INTERNAL_ERROR = -32603
HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
type ReplayJsonValue = (
    bool | int | float | str | list[ReplayJsonValue] | dict[str, ReplayJsonValue] | None
)
type ReplayJsonObject = dict[str, ReplayJsonValue]
type ReplayProfile = Literal["legacy", "modern"]
type ToolName = Literal[
    "download_document_file",
    "get_document_metadata",
    "get_render_manifest",
    "inspect_pdf",
    "list_document_files",
    "render_pdf_page_tiles",
    "render_pdf_pages",
    "search_documents",
]
type ReplayFixtureName = Literal[
    "resources.json",
    "result-cases.json",
    "error-cases.json",
]
type ReplayScenario = Literal[
    "tool.success",
    "tool.strict-extra",
    "tool.strict-type",
    "resource.list",
    "resource.read-about",
    "resource.read-artifact",
    "resource.read-render",
    "error.app-canary",
    "error.generic-canary",
    "protocol.initialize",
    "protocol.server-discover",
    "protocol.tools-list",
    "protocol.method-unknown",
    "protocol.header-mismatch",
]
type ReplayOutcome = Literal[
    "tool-success",
    "strict-error",
    "resource-list",
    "resource-read",
    "app-error",
    "generic-error",
    "protocol-success",
    "protocol-error",
]
type CaseFaultMode = Literal["none", "app_error", "generic_error"]
type ResourceOperation = Literal["list", "read-about", "read-artifact", "read-render"]
type FailureSuffix = Literal["extra", "type"]
type SanitizerKind = Literal["app-canary", "generic-canary"]
FIXTURE_HANDLE: Literal["1234/560449"] = "1234/560449"
FIXTURE_BITSTREAM_ID: Literal["bs_public"] = "bs_public"
FIXED_ARTIFACT_ID = (
    "doc_379d908b524eceb9ab54a87b8347e11637efa642660c3d9d840438d8c5fd101f"
)
FIXED_RENDER_ID = "rnd_e152c1535869cb3e01ed289c7daac9ad"
ZERO_ARTIFACT_ID = f"doc_{'0' * 64}"
ZERO_RENDER_ID = f"rnd_{'0' * 32}"
FIXTURE_ERROR_CANARY = "nplg-baseline-private-canary"
EXPECTED_TOOL_NAMES: frozenset[ToolName] = frozenset(
    {
        "download_document_file",
        "get_document_metadata",
        "get_render_manifest",
        "inspect_pdf",
        "list_document_files",
        "render_pdf_page_tiles",
        "render_pdf_pages",
        "search_documents",
    },
)
REPLAY_PROFILES: tuple[ReplayProfile, ...] = ("legacy", "modern")
REPLAY_FIXTURE_NAMES: tuple[ReplayFixtureName, ...] = (
    "resources.json",
    "result-cases.json",
    "error-cases.json",
)
RESOURCE_OPERATIONS: tuple[ResourceOperation, ...] = (
    "list",
    "read-about",
    "read-artifact",
    "read-render",
)


class _ReplayModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
    )


class EmptyReplaySetup(_ReplayModel):
    """A replay case that allocates no document or render setup state."""

    kind: Literal["empty"]


class DocumentReplaySetup(_ReplayModel):
    """A replay case with one exactly reproduced document artifact."""

    kind: Literal["document"]
    handle: Literal["1234/560449"]
    bitstream_id: Literal["bs_public"]
    artifact_id: Annotated[
        str,
        StringConstraints(pattern=r"^doc_[0-9a-f]{64}$"),
    ]


class RenderReplaySetup(_ReplayModel):
    """A replay case with one exactly reproduced document and render."""

    kind: Literal["render"]
    handle: Literal["1234/560449"]
    bitstream_id: Literal["bs_public"]
    artifact_id: Annotated[
        str,
        StringConstraints(pattern=r"^doc_[0-9a-f]{64}$"),
    ]
    render_id: Annotated[
        str,
        StringConstraints(pattern=r"^rnd_[0-9a-f]{32}$"),
    ]
    pages: Annotated[tuple[Literal[1], ...], Field(min_length=1, max_length=1)]
    mode: Literal["native"]


ReplaySetup = Annotated[
    EmptyReplaySetup | DocumentReplaySetup | RenderReplaySetup,
    Field(discriminator="kind"),
]


class ReplayHeader(_ReplayModel):
    """One exact ordered request-header field."""

    name: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=128,
            pattern=r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$",
        ),
    ]
    value: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=MAX_REPLAY_HEADER_VALUE_LENGTH,
            pattern=r"^[^\r\n]+$",
        ),
    ]


class ReplayRequest(_ReplayModel):
    """Exact request bytes plus their ordered, case-preserving headers."""

    body_base64: Annotated[
        str,
        StringConstraints(
            min_length=4,
            max_length=((MAX_REPLAY_REQUEST_BYTES + 2) // 3) * 4,
            pattern=r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
        ),
    ]
    body_sha256: HexDigest
    headers: Annotated[
        tuple[ReplayHeader, ...],
        Field(min_length=0, max_length=MAX_REPLAY_HEADERS),
    ]

    @model_validator(mode="after")
    def exact_body_and_unique_headers(self) -> ReplayRequest:
        """Reject noncanonical Base64, digest drift, and duplicate headers."""
        try:
            raw = base64.b64decode(self.body_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            msg = "replay request body is not canonical Base64"
            raise ValueError(msg) from exc
        if (
            len(raw) > MAX_REPLAY_REQUEST_BYTES
            or base64.b64encode(raw).decode("ascii") != self.body_base64
        ):
            msg = "replay request body is not bounded canonical Base64"
            raise ValueError(msg)
        if hashlib.sha256(raw).hexdigest() != self.body_sha256:
            msg = "replay request body digest mismatch"
            raise ValueError(msg)
        lowered = tuple(header.name.lower() for header in self.headers)
        if len(set(lowered)) != len(lowered):
            msg = "replay request headers must be case-insensitively unique"
            raise ValueError(msg)
        return self

    def body_bytes(self) -> bytes:
        """Decode the already-validated exact request body."""
        return base64.b64decode(self.body_base64, validate=True)

    def header_mapping(self) -> dict[str, str]:
        """Return the exact header names and values without normalization."""
        return {header.name: header.value for header in self.headers}


class ReplayExpected(_ReplayModel):
    """One complete normalized protocol outcome."""

    status: Annotated[int, Field(ge=100, le=599)]
    payload: ReplayJsonObject | None

    @field_validator("payload", mode="before")
    @classmethod
    def payload_has_only_stored_response_numbers(cls, value: object) -> object:
        """Reject number representations that are valid only before normalization."""
        if value is not None:
            _validate_stored_response_value(value)
        return value

    @model_validator(mode="after")
    def normalized_and_bounded(self) -> ReplayExpected:
        """Require response numbers to already use the versioned semantic form."""
        if self.payload is None:
            return self
        normalized = normalize_response_numbers(self.payload)
        if not isinstance(normalized, dict) or not _json_values_identical(
            normalized,
            self.payload,
        ):
            msg = "replay response is not semantically number-normalized"
            raise ValueError(msg)
        validate_json_depth(self.payload)
        if len(canonical_json_bytes(self.payload)) > MAX_CANONICAL_JSON_BYTES:
            msg = "replay response exceeds the canonical JSON byte limit"
            raise ValueError(msg)
        return self


class ReplayRecord(_ReplayModel):
    """One strict, immutable, executable frozen behavior case."""

    profile: ReplayProfile
    scenario: ReplayScenario
    setup: ReplaySetup
    request: ReplayRequest
    expected: ReplayExpected

    @model_validator(mode="after")
    def profile_headers_are_consistent(self) -> ReplayRecord:
        """Bind each profile to its exact protocol-version header family."""
        headers = self.request.header_mapping()
        version = headers.get("MCP-Protocol-Version")
        if self.profile == "modern":
            if version != "2026-07-28" or "Mcp-Method" not in headers:
                msg = "modern replay requests require exact modern MCP headers"
                raise ValueError(msg)
        elif version not in {None, "2025-11-25"} or "Mcp-Method" in headers:
            msg = "legacy replay requests contain modern or mismatched MCP headers"
            raise ValueError(msg)
        return self


@dataclass(frozen=True, slots=True)
class _BehaviorCase:
    """One internal independently checked behavior-capture definition."""

    case_id: str
    fixture: ReplayFixtureName
    profile: ReplayProfile
    scenario: ReplayScenario
    setup: EmptyReplaySetup | DocumentReplaySetup | RenderReplaySetup
    method: str
    params: ReplayJsonObject
    name_header: str | None
    expected_status: int
    outcome: ReplayOutcome
    fault_mode: CaseFaultMode = "none"
    method_header_override: str | None = None


def normalize_response_numbers(value: object) -> ReplayJsonValue:
    """Return the closed v1 response-number form without changing other values."""
    if value is None or type(value) in {bool, str}:
        return cast("bool | str | None", value)
    if type(value) is int:
        integer = value
        if not -MAX_JAVASCRIPT_SAFE_INTEGER <= integer <= MAX_JAVASCRIPT_SAFE_INTEGER:
            msg = "response integer is outside the JavaScript safe range"
            raise BaselineCaptureError(msg)
        return integer
    if type(value) is float:
        number = value
        if (
            not math.isfinite(number)
            or not number.is_integer()
            or not -MAX_JAVASCRIPT_SAFE_INTEGER <= number <= MAX_JAVASCRIPT_SAFE_INTEGER
        ):
            msg = "response float is not a finite JavaScript-safe integer"
            raise BaselineCaptureError(msg)
        return int(number)
    if type(value) is list:
        return [
            normalize_response_numbers(item) for item in cast("list[object]", value)
        ]
    if type(value) is dict:
        mapping = cast("dict[object, object]", value)
        normalized: ReplayJsonObject = {}
        for key, item in mapping.items():
            if type(key) is not str:
                msg = "response object keys must be strings"
                raise BaselineCaptureError(msg)
            normalized[key] = normalize_response_numbers(item)
        return normalized
    msg = "response contains a non-JSON value"
    raise BaselineCaptureError(msg)


def _validate_stored_response_value(value: object, *, depth: int = 0) -> None:
    """Validate the exact, post-normalization JSON representation for fixtures."""
    if depth > MAX_CANONICAL_JSON_DEPTH:
        msg = "stored replay response JSON nesting is too deep"
        raise ValueError(msg)
    if value is None or type(value) in {bool, str}:
        return
    if type(value) is int:
        integer = value
        if not -MAX_JAVASCRIPT_SAFE_INTEGER <= integer <= MAX_JAVASCRIPT_SAFE_INTEGER:
            msg = "stored replay response integer is outside the JavaScript safe range"
            raise ValueError(msg)
        return
    if type(value) is float:
        msg = "stored replay response must not contain floating-point numbers"
        raise ValueError(msg)
    if type(value) in {list, dict}:
        _validate_stored_response_collection(value, depth=depth)
        return
    msg = "stored replay response contains a non-JSON value"
    raise ValueError(msg)


def _validate_stored_response_collection(value: object, *, depth: int) -> None:
    if type(value) is list:
        for item in cast("list[object]", value):
            _validate_stored_response_value(item, depth=depth + 1)
        return
    mapping = cast("dict[object, object]", value)
    for key, item in mapping.items():
        if type(key) is not str:
            msg = "stored replay response object keys must be strings"
            raise ValueError(msg)
        _validate_stored_response_value(item, depth=depth + 1)


def _json_values_identical(left: object, right: object) -> bool:
    """Compare JSON recursively without Python's bool/int/float equality aliases."""
    if type(left) is not type(right):
        return False
    if type(left) is list:
        left_items = cast("list[object]", left)
        right_items = cast("list[object]", right)
        return len(left_items) == len(right_items) and all(
            _json_values_identical(left_item, right_item)
            for left_item, right_item in zip(left_items, right_items, strict=True)
        )
    if type(left) is dict:
        left_mapping = cast("dict[object, object]", left)
        right_mapping = cast("dict[object, object]", right)
        if set(left_mapping) != set(right_mapping):
            return False
        return all(
            _json_values_identical(left_mapping[key], right_mapping[key])
            for key in left_mapping
        )
    return bool(left == right)


def _response(value: ProtocolResponse) -> ReplayExpected:
    normalized = normalize_response_numbers(value.payload)
    if normalized is not None and not isinstance(normalized, dict):
        msg = "protocol response payload must be an object or null"
        raise BaselineCaptureError(msg)
    return ReplayExpected(status=value.status, payload=normalized)


def _replay_record(
    *,
    case: _BehaviorCase,
    request: ReplayRequest,
    expected: ReplayExpected,
) -> dict[str, object]:
    record = ReplayRecord(
        profile=case.profile,
        scenario=case.scenario,
        setup=case.setup,
        request=request,
        expected=expected,
    )
    raw = canonical_json_bytes(cast("object", record.model_dump(mode="json")))
    try:
        validated = ReplayRecord.model_validate_json(raw, strict=True)
    except ValidationError as exc:
        msg = f"captured replay record is invalid: {case.case_id}"
        raise BaselineCaptureError(msg) from exc
    return cast("dict[str, object]", validated.model_dump(mode="json"))


def _empty_setup() -> EmptyReplaySetup:
    return EmptyReplaySetup(kind="empty")


def _document_setup() -> DocumentReplaySetup:
    return DocumentReplaySetup(
        kind="document",
        handle=FIXTURE_HANDLE,
        bitstream_id=FIXTURE_BITSTREAM_ID,
        artifact_id=FIXED_ARTIFACT_ID,
    )


def _render_setup() -> RenderReplaySetup:
    return RenderReplaySetup(
        kind="render",
        handle=FIXTURE_HANDLE,
        bitstream_id=FIXTURE_BITSTREAM_ID,
        artifact_id=FIXED_ARTIFACT_ID,
        pages=(1,),
        mode="native",
        render_id=FIXED_RENDER_ID,
    )


def _tool_setup(
    tool_name: ToolName,
) -> EmptyReplaySetup | DocumentReplaySetup | RenderReplaySetup:
    if tool_name in {"inspect_pdf", "render_pdf_pages"}:
        return _document_setup()
    if tool_name in {"get_render_manifest", "render_pdf_page_tiles"}:
        return _render_setup()
    return _empty_setup()


def _tool_success_arguments() -> dict[ToolName, ReplayJsonObject]:
    return {
        "download_document_file": {
            "handle": FIXTURE_HANDLE,
            "bitstream_id": FIXTURE_BITSTREAM_ID,
        },
        "get_document_metadata": {"handle": FIXTURE_HANDLE},
        "get_render_manifest": {"render_id": FIXED_RENDER_ID},
        "inspect_pdf": {"artifact_id": FIXED_ARTIFACT_ID},
        "list_document_files": {"handle": FIXTURE_HANDLE},
        "render_pdf_page_tiles": {
            "render_id": FIXED_RENDER_ID,
            "page_number": 1,
            "tile_width": 256,
            "tile_height": 256,
            "overlap": 32,
        },
        "render_pdf_pages": {
            "artifact_id": FIXED_ARTIFACT_ID,
            "pages": [1],
            "mode": "native",
        },
        "search_documents": {"query": "fixture"},
    }


def _tool_type_arguments() -> dict[ToolName, ReplayJsonObject]:
    return {
        "download_document_file": {
            "handle": FIXTURE_HANDLE,
            "bitstream_id": 1,
        },
        "get_document_metadata": {"handle": 1},
        "get_render_manifest": {"render_id": 1},
        "inspect_pdf": {"artifact_id": 1},
        "list_document_files": {"handle": 1},
        "render_pdf_page_tiles": {
            "render_id": ZERO_RENDER_ID,
            "page_number": "1",
            "tile_width": 256,
            "tile_height": 256,
            "overlap": 32,
        },
        "render_pdf_pages": {
            "artifact_id": ZERO_ARTIFACT_ID,
            "pages": ["1"],
            "mode": "native",
        },
        "search_documents": {"query": 1},
    }


def _extra_arguments(arguments: ReplayJsonObject) -> ReplayJsonObject:
    result = dict(arguments)
    if "artifact_id" in result:
        result["artifact_id"] = ZERO_ARTIFACT_ID
    if "render_id" in result:
        result["render_id"] = ZERO_RENDER_ID
    result["unexpected"] = True
    return result


def _tool_cases() -> list[_BehaviorCase]:
    cases: list[_BehaviorCase] = []
    success_arguments = _tool_success_arguments()
    type_arguments = _tool_type_arguments()
    for tool_name in sorted(EXPECTED_TOOL_NAMES):
        for profile in REPLAY_PROFILES:
            cases.append(
                _BehaviorCase(
                    case_id=f"tool.{tool_name}.{profile}.success",
                    fixture="result-cases.json",
                    profile=profile,
                    scenario="tool.success",
                    setup=_tool_setup(tool_name),
                    method="tools/call",
                    params={
                        "name": tool_name,
                        "arguments": success_arguments[tool_name],
                    },
                    name_header=tool_name,
                    expected_status=200,
                    outcome="tool-success",
                )
            )
            failures: tuple[
                tuple[FailureSuffix, ReplayScenario, ReplayJsonObject], ...
            ] = (
                (
                    "extra",
                    "tool.strict-extra",
                    _extra_arguments(success_arguments[tool_name]),
                ),
                ("type", "tool.strict-type", type_arguments[tool_name]),
            )
            cases.extend(
                _BehaviorCase(
                    case_id=f"tool.{tool_name}.{profile}.{suffix}",
                    fixture="error-cases.json",
                    profile=profile,
                    scenario=scenario,
                    setup=_empty_setup(),
                    method="tools/call",
                    params={"name": tool_name, "arguments": arguments},
                    name_header=tool_name,
                    expected_status=200,
                    outcome="strict-error",
                )
                for suffix, scenario, arguments in failures
            )
    return cases


def _resource_case(
    operation: ResourceOperation,
    profile: ReplayProfile,
) -> _BehaviorCase:
    scenario_by_operation: Mapping[ResourceOperation, ReplayScenario] = {
        "list": "resource.list",
        "read-about": "resource.read-about",
        "read-artifact": "resource.read-artifact",
        "read-render": "resource.read-render",
    }
    setup: EmptyReplaySetup | DocumentReplaySetup | RenderReplaySetup
    if operation == "list":
        method = "resources/list"
        params: ReplayJsonObject = {}
        name_header = None
        setup = _empty_setup()
        outcome: ReplayOutcome = "resource-list"
    else:
        method = "resources/read"
        outcome = "resource-read"
        if operation == "read-about":
            uri = "nplg://about"
            setup = _empty_setup()
        elif operation == "read-artifact":
            uri = f"nplg://artifact/{FIXED_ARTIFACT_ID}"
            setup = _document_setup()
        else:
            uri = f"nplg://render/{FIXED_RENDER_ID}/manifest"
            setup = _render_setup()
        params = {"uri": uri}
        name_header = uri
    return _BehaviorCase(
        case_id=f"resource.{operation}.{profile}",
        fixture="resources.json",
        profile=profile,
        scenario=scenario_by_operation[operation],
        setup=setup,
        method=method,
        params=params,
        name_header=name_header,
        expected_status=200,
        outcome=outcome,
    )


def _resource_cases() -> list[_BehaviorCase]:
    return [
        _resource_case(operation, profile)
        for operation in RESOURCE_OPERATIONS
        for profile in REPLAY_PROFILES
    ]


def _sanitizer_cases() -> list[_BehaviorCase]:
    specifications: tuple[
        tuple[
            SanitizerKind,
            ReplayScenario,
            CaseFaultMode,
            ReplayOutcome,
            int,
        ],
        ...,
    ] = (
        ("app-canary", "error.app-canary", "app_error", "app-error", 200),
        (
            "generic-canary",
            "error.generic-canary",
            "generic_error",
            "generic-error",
            500,
        ),
    )
    return [
        _BehaviorCase(
            case_id=f"error.{kind}.{profile}",
            fixture="error-cases.json",
            profile=profile,
            scenario=scenario,
            setup=_empty_setup(),
            method="tools/call",
            params={
                "name": "search_documents",
                "arguments": {"query": "fixture"},
            },
            name_header="search_documents",
            expected_status=status,
            outcome=outcome,
            fault_mode=fault_mode,
        )
        for kind, scenario, fault_mode, outcome, status in specifications
        for profile in REPLAY_PROFILES
    ]


def _protocol_cases() -> tuple[_BehaviorCase, ...]:
    return (
        _BehaviorCase(
            case_id="protocol.initialize.legacy.success",
            fixture="result-cases.json",
            profile="legacy",
            scenario="protocol.initialize",
            setup=_empty_setup(),
            method="initialize",
            params={"protocolVersion": "2025-11-25"},
            name_header=None,
            expected_status=200,
            outcome="protocol-success",
        ),
        _BehaviorCase(
            case_id="protocol.server-discover.modern.success",
            fixture="result-cases.json",
            profile="modern",
            scenario="protocol.server-discover",
            setup=_empty_setup(),
            method="server/discover",
            params={},
            name_header=None,
            expected_status=200,
            outcome="protocol-success",
        ),
        _BehaviorCase(
            case_id="protocol.tools-list.legacy.success",
            fixture="result-cases.json",
            profile="legacy",
            scenario="protocol.tools-list",
            setup=_empty_setup(),
            method="tools/list",
            params={},
            name_header=None,
            expected_status=200,
            outcome="protocol-success",
        ),
        _BehaviorCase(
            case_id="protocol.tools-list.modern.success",
            fixture="result-cases.json",
            profile="modern",
            scenario="protocol.tools-list",
            setup=_empty_setup(),
            method="tools/list",
            params={},
            name_header=None,
            expected_status=200,
            outcome="protocol-success",
        ),
        _BehaviorCase(
            case_id="protocol.method-unknown.legacy.error",
            fixture="error-cases.json",
            profile="legacy",
            scenario="protocol.method-unknown",
            setup=_empty_setup(),
            method="unknown/method",
            params={},
            name_header=None,
            expected_status=404,
            outcome="protocol-error",
        ),
        _BehaviorCase(
            case_id="protocol.header-mismatch.modern.error",
            fixture="error-cases.json",
            profile="modern",
            scenario="protocol.header-mismatch",
            setup=_empty_setup(),
            method="server/discover",
            params={},
            name_header=None,
            expected_status=400,
            outcome="protocol-error",
            method_header_override="tools/list",
        ),
    )


def _behavior_case_id(case: _BehaviorCase) -> str:
    return case.case_id


def _case_definitions() -> tuple[_BehaviorCase, ...]:
    cases = [
        *_tool_cases(),
        *_resource_cases(),
        *_sanitizer_cases(),
        *_protocol_cases(),
    ]
    ordered = tuple(sorted(cases, key=_behavior_case_id))
    if (
        len(ordered) != BEHAVIOR_CASE_COUNT
        or len({case.case_id for case in ordered}) != BEHAVIOR_CASE_COUNT
    ):
        msg = "behavior capture matrix must contain exactly 66 unique cases"
        raise BaselineCaptureError(msg)
    allocation: dict[ReplayFixtureName, int] = {
        fixture: sum(case.fixture == fixture for case in ordered)
        for fixture in REPLAY_FIXTURE_NAMES
    }
    expected_allocation: dict[ReplayFixtureName, int] = {
        "result-cases.json": 20,
        "error-cases.json": 38,
        "resources.json": 8,
    }
    if allocation != expected_allocation:
        msg = "behavior capture matrix has an invalid fixture allocation"
        raise BaselineCaptureError(msg)
    return ordered


def _request_for_case(case: _BehaviorCase) -> ReplayRequest:
    params = dict(case.params)
    if case.profile == "modern":
        params["_meta"] = {
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "fixture-client",
                "version": "1.0.0",
            },
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        }
    payload: ReplayJsonObject = {
        "id": case.case_id,
        "jsonrpc": "2.0",
        "method": case.method,
        "params": params,
    }
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    headers: list[ReplayHeader] = []
    if case.method != "initialize":
        version = "2025-11-25" if case.profile == "legacy" else "2026-07-28"
        headers.append(
            ReplayHeader(name="MCP-Protocol-Version", value=version),
        )
    if case.profile == "modern":
        headers.append(
            ReplayHeader(
                name="Mcp-Method",
                value=case.method_header_override or case.method,
            ),
        )
        if case.name_header is not None:
            headers.append(ReplayHeader(name="Mcp-Name", value=case.name_header))
    return ReplayRequest(
        body_base64=base64.b64encode(raw).decode("ascii"),
        body_sha256=hashlib.sha256(raw).hexdigest(),
        headers=tuple(headers),
    )


async def _apply_replay_setup(
    tools: ToolService,
    setup: EmptyReplaySetup | DocumentReplaySetup | RenderReplaySetup,
) -> None:
    if isinstance(setup, EmptyReplaySetup):
        return
    downloaded = await tools.call(
        "download_document_file",
        {"handle": setup.handle, "bitstream_id": setup.bitstream_id},
    )
    if downloaded.get("artifact_id") != setup.artifact_id:
        msg = "document setup did not reproduce the exact frozen artifact ID"
        raise BaselineCaptureError(msg)
    if isinstance(setup, RenderReplaySetup):
        rendered = await tools.call(
            "render_pdf_pages",
            {
                "artifact_id": setup.artifact_id,
                "pages": list(setup.pages),
                "mode": setup.mode,
            },
        )
        if rendered.get("render_id") != setup.render_id:
            msg = "render setup did not reproduce the exact frozen render ID"
            raise BaselineCaptureError(msg)


def _validate_setup_allocation(
    root: Path,
    setup: EmptyReplaySetup | DocumentReplaySetup | RenderReplaySetup,
) -> None:
    expected = {".staging", "documents", "fixture-source.pdf", "renders"}
    if isinstance(setup, (DocumentReplaySetup, RenderReplaySetup)):
        expected.update(
            {
                f"documents/{setup.artifact_id}",
                f"documents/{setup.artifact_id}/source.pdf",
            }
        )
    if isinstance(setup, RenderReplaySetup):
        expected.update(
            {
                f"renders/{setup.render_id}",
                f"renders/{setup.render_id}/manifest.json",
                f"renders/{setup.render_id}/page-0001.jpg",
            }
        )
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*")}
    if actual != expected:
        msg = "replay setup allocated an unexpected file or directory"
        raise BaselineCaptureError(msg)
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            msg = "replay setup contains a link or special file"
            raise BaselineCaptureError(msg)
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            msg = "replay setup contains a multiply linked file"
            raise BaselineCaptureError(msg)


def _payload_result(expected: ReplayExpected) -> ReplayJsonObject:
    payload = expected.payload
    if payload is None:
        msg = "behavior case unexpectedly returned an empty payload"
        raise BaselineCaptureError(msg)
    result = payload.get("result")
    if not isinstance(result, dict):
        msg = "behavior case did not return a JSON-RPC result object"
        raise BaselineCaptureError(msg)
    return result


def _validate_tool_outcome(case: _BehaviorCase, expected: ReplayExpected) -> None:
    result = _payload_result(expected)
    wanted_error = case.outcome != "tool-success"
    if result.get("isError") is not wanted_error:
        msg = f"tool outcome envelope drifted: {case.case_id}"
        raise BaselineCaptureError(msg)
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        msg = f"tool outcome lacks structured content: {case.case_id}"
        raise BaselineCaptureError(msg)
    if case.outcome == "strict-error" and structured.get("code") != "INVALID_INPUT":
        msg = f"strict tool rejection drifted: {case.case_id}"
        raise BaselineCaptureError(msg)
    if case.outcome == "app-error" and structured.get("code") != "UPSTREAM_FAILURE":
        msg = f"application-error sanitization drifted: {case.case_id}"
        raise BaselineCaptureError(msg)


def _validate_generic_error(case: _BehaviorCase, expected: ReplayExpected) -> None:
    payload = expected.payload
    error = None if payload is None else payload.get("error")
    if not isinstance(error, dict) or error.get("code") != JSONRPC_INTERNAL_ERROR:
        msg = f"generic-error sanitization drifted: {case.case_id}"
        raise BaselineCaptureError(msg)


def _validate_resource_list(case: _BehaviorCase, expected: ReplayExpected) -> None:
    resources = _payload_result(expected).get("resources")
    if (
        not isinstance(resources, list)
        or len(resources) != 1
        or not isinstance(resources[0], dict)
        or resources[0].get("uri") != "nplg://about"
    ):
        msg = f"resource listing is not about-only: {case.case_id}"
        raise BaselineCaptureError(msg)


def _validate_resource_read(case: _BehaviorCase, expected: ReplayExpected) -> None:
    contents = _payload_result(expected).get("contents")
    if not isinstance(contents, list) or len(contents) != 1:
        msg = f"resource read did not return exactly one content: {case.case_id}"
        raise BaselineCaptureError(msg)


def _validate_protocol_error(case: _BehaviorCase, expected: ReplayExpected) -> None:
    payload = expected.payload
    error = None if payload is None else payload.get("error")
    wanted = -32601 if "method-unknown" in case.case_id else -32020
    if not isinstance(error, dict) or error.get("code") != wanted:
        msg = f"protocol error outcome drifted: {case.case_id}"
        raise BaselineCaptureError(msg)


def _validate_behavior_outcome(case: _BehaviorCase, expected: ReplayExpected) -> None:
    if expected.status != case.expected_status:
        msg = f"behavior case returned an unexpected status: {case.case_id}"
        raise BaselineCaptureError(msg)
    raw = canonical_json_bytes(cast("object", expected.model_dump(mode="json")))
    if FIXTURE_ERROR_CANARY.encode("utf-8") in raw:
        msg = f"behavior case exposed the private error canary: {case.case_id}"
        raise BaselineCaptureError(msg)
    if case.outcome in {"tool-success", "strict-error", "app-error"}:
        _validate_tool_outcome(case, expected)
    elif case.outcome == "generic-error":
        _validate_generic_error(case, expected)
    elif case.outcome == "resource-list":
        _validate_resource_list(case, expected)
    elif case.outcome == "resource-read":
        _validate_resource_read(case, expected)
    elif case.outcome == "protocol-error":
        _validate_protocol_error(case, expected)
    else:
        _ = _payload_result(expected)


def _tool_catalog(tools: ToolService) -> dict[str, object]:
    catalog: dict[str, object] = {}
    for tool in tools.list_tools():
        name = tool.get("name")
        if not isinstance(name, str) or not name or name in catalog:
            msg = "tool catalog contains an invalid or duplicate name"
            raise BaselineCaptureError(msg)
        catalog[name] = tool
    if frozenset(catalog) != EXPECTED_TOOL_NAMES:
        msg = "tool catalog does not contain the exact eight tools"
        raise BaselineCaptureError(msg)
    return catalog


def _make_tool_service(root: Path, *, fault_mode: CaseFaultMode) -> ToolService:
    module = cast(
        "_AppFactoryModule",
        importlib.import_module("tests.helpers.app_factory"),
    )
    return module.make_tool_service(root, fault_mode=fault_mode)


def _require_empty_directory(root: Path, *, context: str) -> None:
    if any(root.iterdir()):
        raise BaselineCaptureError(context)


def _prepare_case_root(parent: Path, case_id: str, *, context: str) -> Path:
    root_name = hashlib.sha256(case_id.encode("utf-8")).hexdigest()
    root = parent / root_name
    root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or (
        stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
    ):
        raise BaselineCaptureError(context)
    return root


def _directory_entry_names(root: Path) -> set[str]:
    return {path.name for path in root.iterdir()}


async def capture_behavior_matrix(
    tmp_path: Path,
) -> dict[BaselineFileName, dict[str, object]]:
    """Capture all 66 cases with one fresh deterministic service per case."""
    await asyncio.to_thread(
        _require_empty_directory,
        tmp_path,
        context="behavior capture root must be empty",
    )
    fixtures: dict[BaselineFileName, dict[str, object]] = {
        "tool-catalog.json": {},
        "resources.json": {},
        "result-cases.json": {},
        "error-cases.json": {},
    }
    catalog_bytes: bytes | None = None
    for case in _case_definitions():
        root = await asyncio.to_thread(
            _prepare_case_root,
            tmp_path,
            case.case_id,
            context="behavior case root is not a private directory",
        )
        tools = await asyncio.to_thread(
            _make_tool_service,
            root,
            fault_mode=case.fault_mode,
        )
        candidate_catalog = _tool_catalog(tools)
        candidate_catalog_bytes = canonical_json_bytes(candidate_catalog)
        if catalog_bytes is None:
            catalog_bytes = candidate_catalog_bytes
            fixtures["tool-catalog.json"] = candidate_catalog
        elif candidate_catalog_bytes != catalog_bytes:
            msg = "tool catalog changed between fresh replay services"
            raise BaselineCaptureError(msg)
        await _apply_replay_setup(tools, case.setup)
        await asyncio.to_thread(_validate_setup_allocation, root, case.setup)
        request = _request_for_case(case)
        payload = McpProtocol.parse_json(request.body_bytes())
        response = await McpProtocol(tools).handle(payload, request.header_mapping())
        expected = _response(response)
        _validate_behavior_outcome(case, expected)
        fixtures[case.fixture][case.case_id] = _replay_record(
            case=case,
            request=request,
            expected=expected,
        )
    return fixtures


def _validate_fixture_allocation(
    fixtures: Mapping[BaselineFileName, Mapping[str, object]],
    definitions: tuple[_BehaviorCase, ...],
) -> Mapping[str, object]:
    if set(fixtures) != set(BASELINE_FILES):
        msg = "replay fixture mapping has an unknown or missing file"
        raise BaselineCaptureError(msg)
    expected_by_fixture: dict[ReplayFixtureName, set[str]] = {
        fixture: {case.case_id for case in definitions if case.fixture == fixture}
        for fixture in REPLAY_FIXTURE_NAMES
    }
    seen: set[str] = set()
    for fixture, expected_ids in expected_by_fixture.items():
        actual_ids = set(fixtures[fixture])
        if actual_ids != expected_ids:
            msg = f"replay fixture has an unknown or missing case: {fixture}"
            raise BaselineCaptureError(msg)
        if seen & actual_ids:
            msg = "replay fixture repeats a case ID across files"
            raise BaselineCaptureError(msg)
        seen.update(actual_ids)

    supplied_catalog = fixtures["tool-catalog.json"]
    if frozenset(supplied_catalog) != EXPECTED_TOOL_NAMES:
        msg = "replay fixture tool catalog is incomplete"
        raise BaselineCaptureError(msg)
    return supplied_catalog


def _validated_fixture_record(case: _BehaviorCase, raw_value: object) -> ReplayRecord:
    try:
        record = ReplayRecord.model_validate_json(
            canonical_json_bytes(raw_value),
            strict=True,
        )
    except (ValidationError, TypeError, ValueError) as exc:
        msg = f"replay fixture record is invalid: {case.case_id}"
        raise BaselineCaptureError(msg) from exc
    normative_request = _request_for_case(case)
    if (
        record.profile != case.profile
        or record.scenario != case.scenario
        or record.setup != case.setup
        or record.request != normative_request
        or record.expected.status != case.expected_status
    ):
        msg = f"replay fixture disagrees with the closed case oracle: {case.case_id}"
        raise BaselineCaptureError(msg)
    return record


def _require_expected_response(
    case: _BehaviorCase,
    actual: ReplayExpected,
    expected: ReplayExpected,
) -> None:
    if actual.status != expected.status or not _json_values_identical(
        actual.payload,
        expected.payload,
    ):
        msg = f"replay fixture expected response drifted: {case.case_id}"
        raise BaselineCaptureError(msg)


async def _verify_replay_case(
    case: _BehaviorCase,
    raw_value: object,
    tmp_path: Path,
    supplied_catalog_bytes: bytes,
    previous_catalog_bytes: bytes | None,
) -> bytes:
    record = _validated_fixture_record(case, raw_value)
    root = await asyncio.to_thread(
        _prepare_case_root,
        tmp_path,
        case.case_id,
        context="replay verification case root is not private",
    )
    tools = await asyncio.to_thread(
        _make_tool_service,
        root,
        fault_mode=case.fault_mode,
    )
    live_catalog_bytes = canonical_json_bytes(_tool_catalog(tools))
    if live_catalog_bytes != supplied_catalog_bytes:
        msg = "replay fixture tool catalog does not match the live service"
        raise BaselineCaptureError(msg)
    if (
        previous_catalog_bytes is not None
        and live_catalog_bytes != previous_catalog_bytes
    ):
        msg = "tool catalog changed between replay services"
        raise BaselineCaptureError(msg)
    await _apply_replay_setup(tools, case.setup)
    await asyncio.to_thread(_validate_setup_allocation, root, case.setup)
    payload = McpProtocol.parse_json(record.request.body_bytes())
    response = await McpProtocol(tools).handle(
        payload,
        record.request.header_mapping(),
    )
    actual = _response(response)
    _validate_behavior_outcome(case, actual)
    _require_expected_response(case, actual, record.expected)
    return live_catalog_bytes


async def verify_replay_fixture_records(
    fixtures: Mapping[BaselineFileName, Mapping[str, object]],
    tmp_path: Path,
) -> None:
    """Reexecute a closed fixture matrix against fresh deterministic services."""
    await asyncio.to_thread(
        _require_empty_directory,
        tmp_path,
        context="replay verification root must be empty",
    )
    definitions = _case_definitions()
    supplied_catalog = _validate_fixture_allocation(fixtures, definitions)
    supplied_catalog_bytes = canonical_json_bytes(supplied_catalog)
    previous_catalog_bytes: bytes | None = None
    for case in definitions:
        previous_catalog_bytes = await _verify_replay_case(
            case,
            fixtures[case.fixture][case.case_id],
            tmp_path,
            supplied_catalog_bytes,
            previous_catalog_bytes,
        )
    expected_roots = {
        hashlib.sha256(case.case_id.encode("utf-8")).hexdigest() for case in definitions
    }
    actual_roots = await asyncio.to_thread(_directory_entry_names, tmp_path)
    if actual_roots != expected_roots:
        msg = "replay verification did not allocate exactly one root per case"
        raise BaselineCaptureError(msg)


def _internal_capture(output: Path) -> None:
    """Capture the matrix in a private runtime directory and write exact bytes."""
    output = output.absolute()
    if output.exists() or output.is_symlink():
        msg = "internal capture output must not already exist"
        raise BaselineCaptureError(msg)
    previous_logging_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        with tempfile.TemporaryDirectory(prefix="nplg-baseline-runtime-") as temporary:
            values = asyncio.run(capture_behavior_matrix(Path(temporary)))
    finally:
        logging.disable(previous_logging_disable)
    write_staged_file(output, canonical_json_bytes(values))


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.baseline_replay",
        description=(
            "Capture the frozen MCP behavior matrix inside a materialized tree."
        ),
    )
    _ = parser.add_argument("--internal-output", required=True, type=Path)
    return parser


class _Arguments(argparse.Namespace):
    internal_output: Path = Path()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the internal materialized-tree behavior capture."""
    arguments = cast("_Arguments", _argument_parser().parse_args(argv))
    try:
        _internal_capture(arguments.internal_output)
    except BaselineCaptureError as exc:
        parser = _argument_parser()
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
