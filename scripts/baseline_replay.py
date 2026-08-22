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
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast, runtime_checkable

import httpx
from mcp import Client
from mcp.shared.exceptions import MCPError
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from nplg_mcp.contracts import DownloadDocumentOutput, RenderPagesOutput
from nplg_mcp.errors import AppError
from nplg_mcp.mcp_server import create_mcp_server
from nplg_mcp.profiles import DeploymentProfile
from nplg_mcp.sdk_parity import (
    normalize_public_error,
    normalize_tool_catalog,
    normalize_tool_result,
)
from nplg_mcp.services import FullServiceComposition
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

    from mcp.server import Server

    from nplg_mcp.tools import ToolService

    class _AppFactoryModule(Protocol):
        def make_tool_service(
            self,
            root: Path,
            *,
            fault_mode: CaseFaultMode,
        ) -> ToolService: ...


class _TypedMcpError(Exception):
    """Strict local view of the SDK's currently untyped public exception."""

    error: object = None


_MCP_ERROR_TYPE = cast("type[_TypedMcpError]", MCPError)


@runtime_checkable
class _SdkJsonModel(Protocol):
    """Narrow official-SDK result serialization seam."""

    def model_dump(
        self,
        *,
        mode: str,
        by_alias: bool,
        exclude_none: bool,
    ) -> object:
        """Return one JSON-mode result projection."""
        ...


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
FIXED_PAGE_ARTIFACT_ID = (
    "doc_772f5ebc6bd5cbe2805c1033edde11b86c029fce7922ba3315cae15db7b07e00"
)
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
    if not isinstance(downloaded, DownloadDocumentOutput):
        msg = "document setup returned the wrong strict output model"
        raise BaselineCaptureError(msg)
    if downloaded.artifact_id != setup.artifact_id:
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
        if not isinstance(rendered, RenderPagesOutput):
            msg = "render setup returned the wrong strict output model"
            raise BaselineCaptureError(msg)
        if rendered.render_id != setup.render_id:
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
                f"renders/{setup.render_id}/resources",
                f"renders/{setup.render_id}/resources/{FIXED_PAGE_ARTIFACT_ID}",
                (
                    f"renders/{setup.render_id}/resources/"
                    f"{FIXED_PAGE_ARTIFACT_ID}/index.json"
                ),
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
    fixtures = _load_frozen_fixtures()
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
        elif candidate_catalog_bytes != catalog_bytes:
            msg = "tool catalog changed between fresh replay services"
            raise BaselineCaptureError(msg)
        await _apply_replay_setup(tools, case.setup)
        await asyncio.to_thread(_validate_setup_allocation, root, case.setup)
    return fixtures


def _load_frozen_fixtures() -> dict[BaselineFileName, dict[str, object]]:
    """Load the immutable Task-1 fixture set without executing a legacy server."""
    baseline_root = Path(__file__).resolve().parents[1] / "contracts" / "baseline"
    fixtures: dict[BaselineFileName, dict[str, object]] = {}
    for name in BASELINE_FILES:
        raw: object = json.loads((baseline_root / name).read_bytes())
        if not isinstance(raw, dict):
            msg = f"frozen replay fixture must be an object: {name}"
            raise BaselineCaptureError(msg)
        fixtures[name] = cast("dict[str, object]", raw)
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
    _validate_behavior_outcome(case, record.expected)
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


def _stable_catalog_bytes(catalog: Mapping[str, object]) -> bytes:
    """Project frozen stable metadata while intentionally excluding SDK schemas."""
    projected: dict[str, object] = {}
    for name, raw in catalog.items():
        if not isinstance(raw, dict):
            msg = "replay fixture tool catalog entry is invalid"
            raise BaselineCaptureError(msg)
        entry = cast("dict[str, object]", raw)
        try:
            projected[name] = {
                "annotations": entry["annotations"],
                "description": entry["description"],
                "name": entry["name"],
                "title": entry["title"],
            }
        except KeyError as exc:
            msg = "replay fixture tool catalog entry is incomplete"
            raise BaselineCaptureError(msg) from exc
    return canonical_json_bytes(projected)


def _frozen_result_object(
    fixtures: Mapping[BaselineFileName, Mapping[str, object]],
    fixture: ReplayFixtureName,
    case_id: str,
) -> ReplayJsonObject:
    record_value: object = fixtures[fixture].get(case_id)
    record = (
        cast("dict[str, object]", record_value)
        if isinstance(record_value, dict)
        else None
    )
    expected_value: object = record.get("expected") if record is not None else None
    expected = (
        cast("dict[str, object]", expected_value)
        if isinstance(expected_value, dict)
        else None
    )
    payload_value: object = expected.get("payload") if expected is not None else None
    payload = (
        cast("dict[str, object]", payload_value)
        if isinstance(payload_value, dict)
        else None
    )
    result_value: object = payload.get("result") if payload is not None else None
    if not isinstance(result_value, dict):
        msg = f"live official SDK oracle fixture is invalid: {case_id}"
        raise BaselineCaptureError(msg)
    return cast("ReplayJsonObject", result_value)


def _frozen_error_object(
    fixtures: Mapping[BaselineFileName, Mapping[str, object]],
    case_id: str,
) -> ReplayJsonObject:
    record_value: object = fixtures["error-cases.json"].get(case_id)
    record = (
        cast("dict[str, object]", record_value)
        if isinstance(record_value, dict)
        else None
    )
    expected_value: object = record.get("expected") if record is not None else None
    expected = (
        cast("dict[str, object]", expected_value)
        if isinstance(expected_value, dict)
        else None
    )
    payload_value: object = expected.get("payload") if expected is not None else None
    payload = (
        cast("dict[str, object]", payload_value)
        if isinstance(payload_value, dict)
        else None
    )
    error_value: object = payload.get("error") if payload is not None else None
    if not isinstance(error_value, dict):
        msg = f"live official SDK oracle fixture is invalid: {case_id}"
        raise BaselineCaptureError(msg)
    return cast("ReplayJsonObject", error_value)


def _sdk_object(value: object, *, context: str) -> ReplayJsonObject:
    if not isinstance(value, _SdkJsonModel):
        msg = f"live official SDK returned an untyped {context}"
        raise BaselineCaptureError(msg)
    try:
        normalized = normalize_response_numbers(
            value.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
    except (TypeError, ValueError) as exc:
        msg = f"live official SDK returned an invalid {context}"
        raise BaselineCaptureError(msg) from exc
    if not isinstance(normalized, dict):
        msg = f"live official SDK returned a non-object {context}"
        raise BaselineCaptureError(msg)
    return normalized


def _sdk_error(exc: _TypedMcpError) -> ReplayJsonObject:
    error = _sdk_object(exc.error, context="public error")
    if FIXTURE_ERROR_CANARY.encode("utf-8") in canonical_json_bytes(error):
        msg = "live official SDK exposed the private error canary"
        raise BaselineCaptureError(msg)
    return error


def _normalize_render_collection(
    copied: ReplayJsonObject,
    collection_key: Literal["pages", "tiles"] | None,
    *,
    live: bool,
) -> None:
    collection = copied.get(collection_key) if collection_key is not None else None
    if not isinstance(collection, list):
        return
    for item in collection:
        if not isinstance(item, dict):
            msg = "live official SDK render collection is invalid"
            raise BaselineCaptureError(msg)
        digest = item.get("sha256")
        if live and item.get("resource_uri") != f"nplg://artifact/doc_{digest}":
            msg = "live official SDK render artifact URI is not canonical"
            raise BaselineCaptureError(msg)
        _ = item.pop("asset_url", None)
        _ = item.pop("resource_uri", None)


def _replay_tool_result(
    case: _BehaviorCase,
    value: object,
    *,
    live: bool,
    expected_tile_manifest_uri: str | None = None,
) -> ReplayJsonObject:
    normalized = normalize_tool_result(value)
    copied_value = cast(
        "object",
        json.loads(
            json.dumps(
                normalized,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        ),
    )
    if not isinstance(copied_value, dict):
        msg = "live official SDK tool result is not an object"
        raise BaselineCaptureError(msg)
    copied = cast("ReplayJsonObject", copied_value)
    _ = copied.pop("asset_url", None)
    _ = copied.pop("manifest_asset_url", None)
    name = case.params.get("name")
    collection_key: Literal["pages", "tiles"] | None = None
    if name in {"get_render_manifest", "render_pdf_pages"}:
        collection_key = "pages"
    if name == "render_pdf_page_tiles":
        collection_key = "tiles"
        resource_uri = copied.get("resource_uri")
        uri_is_canonical = isinstance(resource_uri, str) and re.fullmatch(
            r"nplg://artifact/doc_[0-9a-f]{64}",
            resource_uri,
        )
        if live and (
            not uri_is_canonical
            or (
                expected_tile_manifest_uri is not None
                and resource_uri != expected_tile_manifest_uri
            )
        ):
            msg = "live official SDK tile manifest URI is not canonical"
            raise BaselineCaptureError(msg)
        _ = copied.pop("resource_uri", None)
    _normalize_render_collection(copied, collection_key, live=live)
    return copied


def _persisted_tile_manifest_uri(tools: ToolService, value: object) -> str:
    """Bind a live tile result to the exact persisted manifest bytes it names."""
    try:
        normalized = normalize_tool_result(value)
        relative_path = normalized.get("manifest_relative_path")
        if not isinstance(relative_path, str):
            msg = "live official SDK tile manifest path is invalid"
            raise BaselineCaptureError(msg)
        manifest_path = tools.store.resolve_asset(relative_path)
        manifest_bytes = manifest_path.read_bytes()
    except (AppError, OSError, TypeError, ValueError) as exc:
        msg = "live official SDK tile manifest persistence is invalid"
        raise BaselineCaptureError(msg) from exc
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    return f"nplg://artifact/doc_{digest}"


async def _live_protocol_error(
    case: _BehaviorCase,
    server: Server[None],
) -> tuple[int, ReplayJsonObject]:
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        host="mcp.example.test",
    )
    request = _request_for_case(case)
    headers = {header.name: header.value for header in request.headers}
    headers.update(
        {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Origin": "https://mcp.example.test",
        }
    )
    try:
        body = base64.b64decode(request.body_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = "live official SDK protocol request is invalid"
        raise BaselineCaptureError(msg) from exc
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        response = await client.post("/mcp", content=body, headers=headers)
    try:
        payload_value = cast("object", response.json())
    except ValueError as exc:
        msg = "live official SDK protocol error is not JSON"
        raise BaselineCaptureError(msg) from exc
    if not isinstance(payload_value, dict):
        msg = "live official SDK protocol error is not an object"
        raise BaselineCaptureError(msg)
    error_value = cast("dict[str, object]", payload_value).get("error")
    if not isinstance(error_value, dict):
        msg = "live official SDK protocol error is missing"
        raise BaselineCaptureError(msg)
    return response.status_code, cast("ReplayJsonObject", error_value)


def _live_client_mode(case: _BehaviorCase) -> Literal["legacy", "auto", "2026-07-28"]:
    if case.scenario == "protocol.initialize":
        return "legacy"
    if case.scenario == "protocol.server-discover":
        return "auto"
    if case.outcome in {"app-error", "generic-error"}:
        return "2026-07-28"
    return "legacy" if case.profile == "legacy" else "2026-07-28"


async def _execute_live_sdk_case(
    case: _BehaviorCase,
    server: Server[None],
) -> tuple[object | None, ReplayJsonObject | None]:
    live_result: object | None = None
    live_error: ReplayJsonObject | None = None
    async with Client(server, mode=_live_client_mode(case)) as client:
        if case.method == "tools/call":
            name = case.params.get("name")
            arguments = case.params.get("arguments")
            if not isinstance(name, str) or not isinstance(arguments, dict):
                msg = "live official SDK tool case is invalid"
                raise BaselineCaptureError(msg)
            try:
                live_result = await client.call_tool(name, arguments)
            except _MCP_ERROR_TYPE as exc:
                live_error = _sdk_error(exc)
        elif case.method == "resources/list":
            live_result = await client.list_resources()
        elif case.method == "resources/read":
            uri = case.params.get("uri")
            if not isinstance(uri, str):
                msg = "live official SDK resource case is invalid"
                raise BaselineCaptureError(msg)
            live_result = await client.read_resource(uri)
        elif case.scenario == "protocol.initialize":
            live_result = await client.session.initialize()
        elif case.scenario == "protocol.server-discover":
            live_result = await client.session.discover()
        elif case.scenario == "protocol.tools-list":
            live_result = await client.list_tools()
        else:
            msg = "live official SDK case has no executable behavior"
            raise BaselineCaptureError(msg)
    return live_result, live_error


def _single_resource_content(value: object) -> ReplayJsonObject | None:
    if not isinstance(value, list):
        return None
    items = cast("list[object]", value)
    if len(items) != 1 or not isinstance(items[0], dict):
        return None
    return cast("ReplayJsonObject", items[0])


def _matches_artifact_resource(
    live_contents: object,
    frozen_contents: object,
) -> bool:
    live_content = _single_resource_content(live_contents)
    frozen_content = _single_resource_content(frozen_contents)
    if live_content is None or frozen_content is None:
        return False
    live_blob = live_content.get("blob")
    live_meta = live_content.get("_meta")
    frozen_text = frozen_content.get("text")
    frozen_identity = (
        normalize_response_numbers(cast("object", json.loads(frozen_text)))
        if isinstance(frozen_text, str)
        else None
    )
    try:
        live_bytes = (
            base64.b64decode(live_blob, validate=True)
            if isinstance(live_blob, str)
            else None
        )
    except (binascii.Error, ValueError):
        return False
    digest = FIXED_ARTIFACT_ID.removeprefix("doc_")
    return (
        live_content.get("uri") == frozen_content.get("uri")
        and live_content.get("mimeType") == "application/pdf"
        and isinstance(live_meta, dict)
        and live_meta.get("sha256") == digest
        and live_bytes is not None
        and live_meta.get("size") == len(live_bytes)
        and hashlib.sha256(live_bytes).hexdigest() == digest
        and isinstance(frozen_identity, dict)
        and frozen_identity.get("artifact_id") == FIXED_ARTIFACT_ID
        and frozen_identity.get("sha256") == digest
    )


def _normalized_render_pages(
    live_pages: object,
    frozen_pages: object,
) -> tuple[list[object], list[object]] | None:
    if not isinstance(live_pages, list) or not isinstance(frozen_pages, list):
        return None
    typed_live_pages = cast("list[object]", live_pages)
    typed_frozen_pages = cast("list[object]", frozen_pages)
    normalized_live: list[object] = []
    normalized_frozen: list[object] = []
    for live_page, frozen_page in zip(
        typed_live_pages,
        typed_frozen_pages,
        strict=True,
    ):
        if not isinstance(live_page, dict) or not isinstance(frozen_page, dict):
            return None
        typed_live_page = cast("ReplayJsonObject", live_page)
        typed_frozen_page = cast("ReplayJsonObject", frozen_page)
        digest = typed_live_page.get("sha256")
        if typed_live_page.get("resource_uri") != f"nplg://artifact/doc_{digest}":
            return None
        normalized_live.append(
            {
                key: value
                for key, value in typed_live_page.items()
                if key not in {"asset_url", "resource_uri"}
            }
        )
        normalized_frozen.append(
            {
                key: value
                for key, value in typed_frozen_page.items()
                if key not in {"asset_url", "resource_uri"}
            }
        )
    return normalized_live, normalized_frozen


def _matches_render_resource(
    live_contents: object,
    frozen_contents: object,
) -> bool:
    live_content = _single_resource_content(live_contents)
    frozen_content = _single_resource_content(frozen_contents)
    if live_content is None or frozen_content is None:
        return False
    live_text = live_content.get("text")
    frozen_text = frozen_content.get("text")
    live_manifest = (
        normalize_response_numbers(cast("object", json.loads(live_text)))
        if isinstance(live_text, str)
        else None
    )
    frozen_manifest = (
        normalize_response_numbers(cast("object", json.loads(frozen_text)))
        if isinstance(frozen_text, str)
        else None
    )
    if not isinstance(live_manifest, dict) or not isinstance(frozen_manifest, dict):
        return False
    pages = _normalized_render_pages(
        live_manifest.get("pages"),
        frozen_manifest.get("pages"),
    )
    if pages is None:
        return False
    manifest_keys = {
        "manifest_relative_path",
        "mode",
        "render_id",
        "renderer_version",
        "resource_uri",
        "source_sha256",
    }
    return (
        live_content.get("uri") == frozen_content.get("uri")
        and live_content.get("mimeType") == frozen_content.get("mimeType")
        and {key: live_manifest.get(key) for key in manifest_keys}
        == {key: frozen_manifest.get(key) for key in manifest_keys}
        and pages[0] == pages[1]
    )


def _matches_resource_read(
    case: _BehaviorCase,
    live_result: object,
    frozen_result: ReplayJsonObject,
) -> bool:
    live_contents = _sdk_object(live_result, context="resource read").get("contents")
    frozen_contents = frozen_result.get("contents")
    if case.scenario == "resource.read-artifact":
        return _matches_artifact_resource(live_contents, frozen_contents)
    if case.scenario == "resource.read-render":
        return _matches_render_resource(live_contents, frozen_contents)
    return live_contents == frozen_contents


def _core_server_info(value: object) -> ReplayJsonObject | None:
    if not isinstance(value, dict):
        return None
    typed_value = cast("ReplayJsonObject", value)
    return {key: typed_value.get(key) for key in ("name", "title", "version")}


def _matches_initialize(live_result: object, frozen: ReplayJsonObject) -> bool:
    live = _sdk_object(live_result, context="initialize result")
    capabilities = live.get("capabilities")
    return (
        live.get("protocolVersion") == frozen.get("protocolVersion")
        and _core_server_info(live.get("serverInfo"))
        == _core_server_info(frozen.get("serverInfo"))
        and isinstance(capabilities, dict)
        and {"resources", "tools"}.issubset(capabilities)
    )


def _matches_discover(live_result: object, frozen: ReplayJsonObject) -> bool:
    live = _sdk_object(live_result, context="discover result")
    live_meta = live.get("_meta")
    frozen_meta = frozen.get("_meta")
    live_info = (
        live_meta.get("io.modelcontextprotocol/serverInfo")
        if isinstance(live_meta, dict)
        else None
    )
    frozen_info = (
        frozen_meta.get("io.modelcontextprotocol/serverInfo")
        if isinstance(frozen_meta, dict)
        else None
    )
    versions = live.get("supportedVersions")
    frozen_versions = frozen.get("supportedVersions")
    capabilities = live.get("capabilities")
    return (
        live.get("resultType") == "complete"
        and live.get("cacheScope") == frozen.get("cacheScope")
        and isinstance(versions, list)
        and isinstance(frozen_versions, list)
        and all(version in frozen_versions for version in versions)
        and "2026-07-28" in versions
        and _core_server_info(live_info) == _core_server_info(frozen_info)
        and isinstance(capabilities, dict)
        and {"resources", "tools"}.issubset(capabilities)
    )


def _matches_live_sdk_case(
    case: _BehaviorCase,
    live_result: object,
    live_error: ReplayJsonObject | None,
    frozen_result: ReplayJsonObject,
    frozen_error: ReplayJsonObject | None,
) -> bool:
    if case.outcome == "tool-success":
        matches = live_error is None and _replay_tool_result(
            case,
            live_result,
            live=True,
        ) == _replay_tool_result(case, frozen_result, live=False)
    elif case.outcome == "strict-error":
        matches = live_error is not None and normalize_public_error(live_error) == {
            "code": -32602
        }
    elif case.outcome == "app-error":
        matches = live_error is not None and normalize_public_error(live_error) == {
            "code": JSONRPC_INTERNAL_ERROR
        }
    elif case.outcome == "generic-error":
        matches = (
            live_error is not None
            and frozen_error is not None
            and normalize_public_error(live_error)
            == normalize_public_error(frozen_error)
        )
    elif case.outcome == "resource-list":
        matches = _sdk_object(live_result, context="resource listing").get(
            "resources"
        ) == frozen_result.get("resources")
    elif case.outcome == "resource-read":
        matches = _matches_resource_read(case, live_result, frozen_result)
    elif case.scenario == "protocol.tools-list":
        live_tools = _sdk_object(live_result, context="tool listing").get("tools")
        matches = normalize_tool_catalog(live_tools) == normalize_tool_catalog(
            frozen_result.get("tools")
        )
    elif case.scenario == "protocol.initialize":
        matches = _matches_initialize(live_result, frozen_result)
    elif case.scenario == "protocol.server-discover":
        matches = _matches_discover(live_result, frozen_result)
    else:
        matches = _sdk_object(live_result, context="protocol result") == frozen_result
    return matches


async def _verify_live_official_sdk_oracle(
    case: _BehaviorCase,
    server: Server[None],
    frozen_oracle: ReplayJsonObject,
    tools: ToolService,
) -> None:
    """Execute one semantically equivalent official-SDK case before comparison."""
    is_error_case = case.outcome in {"generic-error", "protocol-error"}
    frozen_error = frozen_oracle if is_error_case else None
    if case.outcome == "protocol-error":
        status, protocol_error = await _live_protocol_error(case, server)
        wanted_status = 400 if "header-mismatch" in case.case_id else 200
        matches = (
            status == wanted_status
            and frozen_error is not None
            and normalize_public_error(protocol_error)
            == normalize_public_error(frozen_error)
        )
    else:
        frozen_result = {} if is_error_case else frozen_oracle
        live_result, client_error = await _execute_live_sdk_case(case, server)
        expected_tile_manifest_uri = (
            _persisted_tile_manifest_uri(tools, live_result)
            if case.outcome == "tool-success"
            and case.params.get("name") == "render_pdf_page_tiles"
            else None
        )
        try:
            if expected_tile_manifest_uri is not None:
                _ = _replay_tool_result(
                    case,
                    live_result,
                    live=True,
                    expected_tile_manifest_uri=expected_tile_manifest_uri,
                )
            matches = _matches_live_sdk_case(
                case,
                live_result,
                client_error,
                frozen_result,
                frozen_error,
            )
        except (KeyError, TypeError, ValueError) as exc:
            msg = (
                "live official SDK behavior does not match the immutable replay oracle"
            )
            raise BaselineCaptureError(msg) from exc
    if not matches:
        msg = "live official SDK behavior does not match the immutable replay oracle"
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
    supplied_catalog = cast(
        "Mapping[str, object]",
        json.loads(supplied_catalog_bytes),
    )
    live_catalog = _tool_catalog(tools)
    if _stable_catalog_bytes(live_catalog) != _stable_catalog_bytes(supplied_catalog):
        msg = "replay fixture tool catalog does not match the live official SDK service"
        raise BaselineCaptureError(msg)
    if (
        previous_catalog_bytes is not None
        and live_catalog_bytes != previous_catalog_bytes
    ):
        msg = "tool catalog changed between replay services"
        raise BaselineCaptureError(msg)
    await _apply_replay_setup(tools, case.setup)
    await asyncio.to_thread(_validate_setup_allocation, root, case.setup)
    frozen = _load_frozen_fixtures()
    frozen_record = _validated_fixture_record(
        case,
        frozen[case.fixture][case.case_id],
    )
    frozen_oracle = (
        _frozen_error_object(frozen, case.case_id)
        if case.outcome in {"generic-error", "protocol-error"}
        else _frozen_result_object(frozen, case.fixture, case.case_id)
    )
    services = FullServiceComposition(tools=tools, store=tools.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)
    await _verify_live_official_sdk_oracle(case, server, frozen_oracle, tools)
    _require_expected_response(case, record.expected, frozen_record.expected)
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
