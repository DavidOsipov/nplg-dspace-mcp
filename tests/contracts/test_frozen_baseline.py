# Copyright (c) 2026 David Osipov
"""Digest-bound tests for the frozen behavioral baseline."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import io
import json
import logging
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast

import pytest
from mypy.config_parser import parse_mypy_comments
from mypy.options import Options
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from nplg_mcp.contracts import (
    DocumentMetadataOutput,
    DownloadDocumentOutput,
    PdfInspectionOutput,
    RenderPagesOutput,
    RenderTilesOutput,
    SearchDocumentsOutput,
    StrictOutput,
)
from nplg_mcp.json_types import (
    JsonObject,
    JsonValue,
    load_json_value,
    require_json_object,
)
from scripts import baseline_capture_io, baseline_replay, capture_baseline
from tests.helpers import pdf_factory
from tests.helpers.app_factory import make_tool_service

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping
    from typing import Self, TypedDict

    from nplg_mcp.tools import ToolService

    class CapturePolicyValues(TypedDict):
        """Mutable keyword values accepted by the strict capture policy model."""

        audit_commit: str
        audit_tree: str
        audit_src_tree: str
        base_commit: str
        base_tree: str
        index_transition: baseline_capture_io.IndexTransitionIdentity
        included_untracked_paths: baseline_capture_io.IncludedUntrackedPaths

    class ReplayBehaviorCase(Protocol):
        """Narrow immutable behavior-case view required by fault tests."""

        case_id: str
        expected_status: int
        fixture: str
        outcome: str
        setup: object

    class ReplayPrivateCallable(Protocol):
        """Private synchronous replay seam under adversarial test."""

        def __call__(self, *args: object, **kwargs: object) -> object: ...

    class AsyncReplayPrivateCallable(Protocol):
        """Private asynchronous replay seam under adversarial test."""

        def __call__(self, *args: object) -> Awaitable[None]: ...


BASELINE_DIR = Path("contracts/baseline")
type BaselineFileName = Literal[
    "tool-catalog.json",
    "resources.json",
    "result-cases.json",
    "error-cases.json",
]
HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitObjectId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
CaseId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")]
PROFILE_MARKER = "nplg-release-profile:v1"
PROFILE_PREIMAGE = '{"profile":"alpic-metadata","schema_version":1}\n'
PROFILE_DIGEST = "b064e1d16fca1c4f86f9d8c2a5f1053cd25d50f88c169505eb79464d49c259cb"
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
type ReplayProfile = Literal["legacy", "modern"]
type ResourceOperation = Literal["list", "read-about", "read-artifact", "read-render"]
type IdentityTreeField = Literal["audit_tree", "base_tree"]
type BaselineFixtures = dict[BaselineFileName, JsonObject]
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


def _replay_private(name: str) -> object:
    """Resolve one deliberately tested private replay seam without static coupling."""
    return cast("object", object.__getattribute__(baseline_replay, f"_{name}"))


_CASE_DEFINITIONS = cast(
    "Callable[[], tuple[ReplayBehaviorCase, ...]]",
    _replay_private("case_definitions"),
)
_RESOURCE_CASES = cast(
    "Callable[[], list[ReplayBehaviorCase]]",
    _replay_private("resource_cases"),
)
_PRIVATE_REPLAY_CALLS = {
    name: cast("ReplayPrivateCallable", _replay_private(name.removeprefix("_")))
    for name in (
        "_empty_setup",
        "_frozen_error_object",
        "_frozen_result_object",
        "_load_frozen_fixtures",
        "_payload_result",
        "_core_server_info",
        "_matches_artifact_resource",
        "_matches_live_sdk_case",
        "_matches_render_resource",
        "_normalize_render_collection",
        "_normalized_render_pages",
        "_replay_tool_result",
        "_sdk_error",
        "_sdk_object",
        "_single_resource_content",
        "_stable_catalog_bytes",
        "_validate_behavior_outcome",
        "_validate_fixture_allocation",
        "_validate_generic_error",
        "_validate_protocol_error",
        "_validate_resource_list",
        "_validate_resource_read",
        "_validate_setup_allocation",
        "_validate_tool_outcome",
    )
}
_APPLY_REPLAY_SETUP = cast(
    "AsyncReplayPrivateCallable",
    _replay_private("apply_replay_setup"),
)


def _replay_case(outcome: str) -> ReplayBehaviorCase:
    """Return one immutable production case for a requested outcome branch."""
    return next(case for case in _CASE_DEFINITIONS() if case.outcome == outcome)


def _replay_expected(
    payload: JsonObject | None,
    *,
    status: int = 200,
) -> baseline_replay.ReplayExpected:
    """Construct a bounded outcome fixture for direct fail-closed validation."""
    return baseline_replay.ReplayExpected.model_construct(
        status=status,
        payload=payload,
    )


def test_replay_expected_rejects_semantically_unnormalized_numbers() -> None:
    expected = _replay_expected({"value": 1.0})
    validate = cast(
        "Callable[[], baseline_replay.ReplayExpected]",
        object.__getattribute__(expected, "normalized_and_bounded"),
    )
    with pytest.raises(ValueError, match="semantically number-normalized"):
        _ = validate()


def test_replay_case_matrix_rejects_wrong_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(baseline_replay, "BEHAVIOR_CASE_COUNT", 0)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="66 unique"):
        _ = _CASE_DEFINITIONS()


def test_replay_case_matrix_rejects_wrong_fixture_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resource_case_count = len(_RESOURCE_CASES())
    monkeypatch.setattr(baseline_replay, "_resource_cases", lambda: ())
    monkeypatch.setattr(
        baseline_replay,
        "BEHAVIOR_CASE_COUNT",
        baseline_replay.BEHAVIOR_CASE_COUNT - resource_case_count,
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="fixture allocation",
    ):
        _ = _CASE_DEFINITIONS()


def test_replay_setup_allocation_rejects_unexpected_tree(tmp_path: Path) -> None:
    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="unexpected file or directory",
    ):
        _ = _PRIVATE_REPLAY_CALLS["_validate_setup_allocation"](
            tmp_path,
            _PRIVATE_REPLAY_CALLS["_empty_setup"](),
        )


@pytest.mark.parametrize("payload", [None, {"wrong": {}}])
def test_replay_payload_result_rejects_missing_result(
    payload: JsonObject | None,
) -> None:
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="behavior case"):
        _ = _PRIVATE_REPLAY_CALLS["_payload_result"](_replay_expected(payload))


@pytest.mark.parametrize(
    ("outcome", "result", "message"),
    [
        ("tool-success", {"isError": True, "structuredContent": {}}, "envelope"),
        ("tool-success", {"isError": False}, "structured content"),
        (
            "strict-error",
            {"isError": True, "structuredContent": {"code": "OTHER"}},
            "strict tool rejection",
        ),
        (
            "app-error",
            {"isError": True, "structuredContent": {"code": "OTHER"}},
            "application-error sanitization",
        ),
    ],
)
def test_replay_tool_outcome_rejects_semantic_drift(
    outcome: str,
    result: JsonObject,
    message: str,
) -> None:
    case = _replay_case(outcome)
    expected = _replay_expected({"result": result}, status=case.expected_status)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match=message):
        _ = _PRIVATE_REPLAY_CALLS["_validate_tool_outcome"](case, expected)


def test_replay_generic_error_rejects_wrong_code() -> None:
    case = _replay_case("generic-error")
    expected = _replay_expected(
        {"error": {"code": -32602}},
        status=case.expected_status,
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="generic-error"):
        _ = _PRIVATE_REPLAY_CALLS["_validate_generic_error"](case, expected)


def test_replay_resource_list_rejects_non_about_catalog() -> None:
    case = _replay_case("resource-list")
    expected = _replay_expected(
        {"result": {"resources": []}},
        status=case.expected_status,
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="about-only"):
        _ = _PRIVATE_REPLAY_CALLS["_validate_resource_list"](case, expected)


def test_replay_resource_read_rejects_multiple_contents() -> None:
    case = _replay_case("resource-read")
    expected = _replay_expected(
        {"result": {"contents": [{}, {}]}},
        status=case.expected_status,
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="exactly one"):
        _ = _PRIVATE_REPLAY_CALLS["_validate_resource_read"](case, expected)


def test_replay_protocol_error_rejects_wrong_code() -> None:
    case = _replay_case("protocol-error")
    expected = _replay_expected(
        {"error": {"code": 0}},
        status=case.expected_status,
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError, match="protocol error"
    ):
        _ = _PRIVATE_REPLAY_CALLS["_validate_protocol_error"](case, expected)


def test_replay_behavior_rejects_status_drift() -> None:
    case = _replay_case("tool-success")
    expected = _replay_expected(None, status=case.expected_status + 1)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="status"):
        _ = _PRIVATE_REPLAY_CALLS["_validate_behavior_outcome"](case, expected)


def test_replay_behavior_rejects_private_canary() -> None:
    case = _replay_case("tool-success")
    expected = _replay_expected(
        {
            "result": {
                "isError": False,
                "structuredContent": {
                    "value": baseline_replay.FIXTURE_ERROR_CANARY,
                },
            }
        },
        status=case.expected_status,
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="canary"):
        _ = _PRIVATE_REPLAY_CALLS["_validate_behavior_outcome"](case, expected)


def test_frozen_fixture_loader_rejects_non_object_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def non_object_fixture(_path: Path) -> bytes:
        return b"[]"

    monkeypatch.setattr(Path, "read_bytes", non_object_fixture)

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError, match="must be an object"
    ):
        _ = _PRIVATE_REPLAY_CALLS["_load_frozen_fixtures"]()


def test_fixture_allocation_rejects_cross_file_case_reuse() -> None:
    first = _replay_case("tool-success")
    duplicate = copy.copy(first)
    object.__setattr__(duplicate, "fixture", "error-cases.json")
    fixtures: dict[BaselineFileName, dict[str, object]] = {
        "tool-catalog.json": {},
        "resources.json": {},
        "result-cases.json": {first.case_id: {}},
        "error-cases.json": {first.case_id: {}},
    }

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError, match="repeats a case ID"
    ):
        _ = _PRIVATE_REPLAY_CALLS["_validate_fixture_allocation"](
            fixtures,
            (first, duplicate),
        )


def test_stable_catalog_projection_rejects_non_object_entry() -> None:
    catalog: dict[str, object] = {"bad": []}
    with pytest.raises(
        baseline_capture_io.BaselineCaptureError, match="entry is invalid"
    ):
        _ = _PRIVATE_REPLAY_CALLS["_stable_catalog_bytes"](catalog)


@pytest.mark.parametrize("kind", ["result", "error"])
def test_live_oracle_fixture_helpers_reject_missing_object(kind: str) -> None:
    fixtures: dict[BaselineFileName, dict[str, object]] = {
        "tool-catalog.json": {},
        "resources.json": {},
        "result-cases.json": {},
        "error-cases.json": {},
    }

    def action() -> object:
        if kind == "result":
            return _PRIVATE_REPLAY_CALLS["_frozen_result_object"](
                fixtures,
                "result-cases.json",
                "missing",
            )
        return _PRIVATE_REPLAY_CALLS["_frozen_error_object"](fixtures, "missing")

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError, match="fixture is invalid"
    ):
        _ = action()


class _SdkProjection:
    def __init__(self, value: object) -> None:
        super().__init__()
        self.value = value

    def model_dump(
        self,
        *,
        mode: str,
        by_alias: bool,
        exclude_none: bool,
    ) -> object:
        assert (mode, by_alias, exclude_none) == ("json", True, True)
        return self.value


class _SdkProjectionError(Exception):
    def __init__(self, error: object) -> None:
        super().__init__("sdk error projection")
        self.error = error


@pytest.mark.parametrize("value", [object(), _SdkProjection([])])
def test_live_sdk_object_requires_a_typed_object_projection(value: object) -> None:
    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="live official SDK returned",
    ):
        _ = _PRIVATE_REPLAY_CALLS["_sdk_object"](value, context="sentinel")


@pytest.mark.parametrize(
    "collection",
    [["not-an-object"], [{"sha256": "a" * 64, "resource_uri": "mutant"}]],
)
def test_live_render_collection_rejects_invalid_items_and_mutant_uris(
    collection: list[object],
) -> None:
    payload: JsonObject = {"pages": cast("list[JsonValue]", collection)}
    with pytest.raises(baseline_capture_io.BaselineCaptureError):
        _ = _PRIVATE_REPLAY_CALLS["_normalize_render_collection"](
            payload,
            "pages",
            live=True,
        )


def test_live_resource_normalizers_reject_noncanonical_shapes() -> None:
    multiple_contents: list[JsonValue] = [{}, {}]
    invalid_pages: list[JsonValue] = [1]
    mutant_pages: list[JsonValue] = [{"sha256": "a" * 64, "resource_uri": "mutant"}]
    empty_page: list[JsonValue] = [{}]
    assert _PRIVATE_REPLAY_CALLS["_single_resource_content"]({}) is None
    assert _PRIVATE_REPLAY_CALLS["_single_resource_content"](multiple_contents) is None
    assert _PRIVATE_REPLAY_CALLS["_normalized_render_pages"]({}, []) is None
    assert (
        _PRIVATE_REPLAY_CALLS["_normalized_render_pages"](
            invalid_pages,
            invalid_pages,
        )
        is None
    )
    assert (
        _PRIVATE_REPLAY_CALLS["_normalized_render_pages"](
            mutant_pages,
            empty_page,
        )
        is None
    )
    assert _PRIVATE_REPLAY_CALLS["_core_server_info"]([]) is None


def test_live_sdk_error_rejects_private_canary() -> None:
    error = _SdkProjectionError(
        _SdkProjection(
            {"code": -32603, "message": baseline_replay.FIXTURE_ERROR_CANARY}
        )
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="private error canary",
    ):
        _ = _PRIVATE_REPLAY_CALLS["_sdk_error"](error)


def test_live_tile_manifest_rejects_mutant_top_level_uri() -> None:
    case = next(
        item
        for item in _CASE_DEFINITIONS()
        if item.case_id == "tool.render_pdf_page_tiles.modern.success"
    )
    result: JsonObject = {"structuredContent": {"resource_uri": "mutant", "tiles": []}}

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="tile manifest URI is not canonical",
    ):
        _ = _PRIVATE_REPLAY_CALLS["_replay_tool_result"](case, result, live=True)


def test_live_resource_matchers_reject_missing_and_malformed_content() -> None:
    assert _PRIVATE_REPLAY_CALLS["_matches_artifact_resource"]({}, []) is False
    assert _PRIVATE_REPLAY_CALLS["_matches_render_resource"]({}, []) is False
    malformed_content: list[JsonValue] = [{"text": "[]"}]
    assert (
        _PRIVATE_REPLAY_CALLS["_matches_render_resource"](
            malformed_content,
            malformed_content,
        )
        is False
    )
    invalid_pages_content: list[JsonValue] = [{"text": '{"pages":{}}'}]
    assert (
        _PRIVATE_REPLAY_CALLS["_matches_render_resource"](
            invalid_pages_content,
            invalid_pages_content,
        )
        is False
    )


def test_live_case_matcher_executes_default_protocol_comparison() -> None:
    case = copy.copy(_replay_case("tool-success"))
    object.__setattr__(case, "outcome", "unknown")
    object.__setattr__(case, "scenario", "unknown")

    assert (
        _PRIVATE_REPLAY_CALLS["_matches_live_sdk_case"](
            case,
            _SdkProjection({}),
            None,
            {},
            None,
        )
        is True
    )


INCLUDED_UNTRACKED_PATHS: baseline_capture_io.IncludedUntrackedPaths = (
    "contracts/zod/asvs-evidence-contracts.mjs",
    "contracts/zod/baseline-contracts.mjs",
    "docs/security/threat-model.json",
    "eslint.config.mjs",
    "scripts/baseline_capture_io.py",
    "scripts/baseline_replay.py",
    "tests/contracts/zod_asvs_evidence_contracts.test.mjs",
    "tests/contracts/zod_baseline_contracts.test.mjs",
    "tests/property/test_asvs_evidence.py",
    "tests/unit/test_build_asvs_matrix.py",
    "tsconfig.contracts.json",
)
INCLUDED_UNTRACKED_BYTES: dict[str, bytes] = {
    "contracts/zod/asvs-evidence-contracts.mjs": (
        b"export const asvsFixture = 'zod';\n"
    ),
    "contracts/zod/baseline-contracts.mjs": (
        b"export const baselineFixture = 'zod';\n"
    ),
    "docs/security/threat-model.json": b'{"schema_version":1}\n',
    "eslint.config.mjs": b"export default [];\n",
    "scripts/baseline_capture_io.py": b"IO_VALUE = 1\n",
    "scripts/baseline_replay.py": b"REPLAY_VALUE = 1\n",
    "tests/contracts/zod_asvs_evidence_contracts.test.mjs": (
        b"export const asvsTestFixture = 'test';\n"
    ),
    "tests/contracts/zod_baseline_contracts.test.mjs": (
        b"export const baselineTestFixture = 'test';\n"
    ),
    "tests/property/test_asvs_evidence.py": b"PROPERTY_VALUE = 1\n",
    "tests/unit/test_build_asvs_matrix.py": b"UNIT_VALUE = 1\n",
    "tsconfig.contracts.json": b'{"compilerOptions":{"checkJs":true}}\n',
}
EXPECTED_PROFILES: tuple[ReplayProfile, ...] = ("legacy", "modern")
EXPECTED_SUCCESS_CASE_IDS = frozenset(
    f"tool.{name}.{profile}.success"
    for name in EXPECTED_TOOL_NAMES
    for profile in EXPECTED_PROFILES
)
EXPECTED_STRICT_CASE_IDS = frozenset(
    f"tool.{name}.{profile}.{scenario}"
    for name in EXPECTED_TOOL_NAMES
    for profile in EXPECTED_PROFILES
    for scenario in ("extra", "type")
)
EXPECTED_RESOURCE_CASE_IDS = frozenset(
    f"resource.{operation}.{profile}"
    for operation in ("list", "read-about", "read-artifact", "read-render")
    for profile in EXPECTED_PROFILES
)
EXPECTED_SANITIZER_CASE_IDS = frozenset(
    f"error.{kind}.{profile}"
    for kind in ("app-canary", "generic-canary")
    for profile in EXPECTED_PROFILES
)
EXPECTED_LEGACY_PROTOCOL_CASE_IDS = frozenset(
    {
        "protocol.initialize.legacy.success",
        "protocol.server-discover.modern.success",
        "protocol.tools-list.legacy.success",
        "protocol.tools-list.modern.success",
        "protocol.method-unknown.legacy.error",
        "protocol.header-mismatch.modern.error",
    },
)
EXPECTED_CASE_ID_GROUPS = (
    EXPECTED_SUCCESS_CASE_IDS,
    EXPECTED_STRICT_CASE_IDS,
    EXPECTED_RESOURCE_CASE_IDS,
    EXPECTED_SANITIZER_CASE_IDS,
    EXPECTED_LEGACY_PROTOCOL_CASE_IDS,
)
FIXED_ARTIFACT_ID = (
    "doc_379d908b524eceb9ab54a87b8347e11637efa642660c3d9d840438d8c5fd101f"
)
FIXED_RENDER_ID = "rnd_e152c1535869cb3e01ed289c7daac9ad"
ZERO_ARTIFACT_ID = f"doc_{'0' * 64}"
ZERO_RENDER_ID = f"rnd_{'0' * 32}"
FIXTURE_ERROR_CANARY = "nplg-baseline-private-canary"
BASELINE_FILE_NAMES: tuple[BaselineFileName, ...] = (
    "tool-catalog.json",
    "resources.json",
    "result-cases.json",
    "error-cases.json",
)
EXPECTED_SCHEMA_VERSION = 3
INDEX_TRANSITION_ID: Literal["phase-1-reviewed-index-transition-v1"] = (
    "phase-1-reviewed-index-transition-v1"
)
IMPORTED_INDEX_TREE = "6cb461d986c21e4cb2852a07b06f75812ec27bbb"
IMPORTED_STAGED_ENTRIES_SHA256 = (
    "fcfe06d851c83040d860f9f887efe18bde9dbe46c4eeb1aaa3f68b3af8f3ccaf"
)
CANDIDATE_INDEX_TREE = "55691718dade75b44a8ed025fcf48dabf87a7969"
CANDIDATE_STAGED_ENTRIES_SHA256 = (
    "9426ba909728d29d2009607264a9ffb1c028c4c645bbacd72f98867132e24f68"
)
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
REVIEWED_SOURCE_FILE_MODE = 0o644
EXPECTED_CLI_ERROR_EXIT = 2
INJECTED_FAILURE_CALL = 3
EXPECTED_BEHAVIOR_CASES = 66
EXPECTED_RESULT_CASES = 20
EXPECTED_ERROR_CASES = 38
EXPECTED_RESOURCE_CASES = 8
EXPECTED_REVIEWED_ADD_CALLS = 2
SECOND_SERVICE_CALL = 2
INJECTED_CHILD_EXIT = 7
GIT_EXECUTABLE = Path(shutil.which("git", path=os.defpath) or "/usr/bin/git")

type ReplayFixtureName = Literal[
    "resources.json",
    "result-cases.json",
    "error-cases.json",
]
type ReplaySetupKind = Literal["empty", "document", "render"]
type ReplayOutcomeKind = Literal[
    "tool-success",
    "strict-error",
    "resource-list",
    "resource-read",
    "app-error",
    "generic-error",
    "protocol-success",
    "protocol-error",
]


@dataclass(frozen=True, slots=True)
class NormativeReplayCase:
    """One fixture-independent frozen-case oracle."""

    case_id: str
    fixture: ReplayFixtureName
    profile: ReplayProfile
    scenario: str
    setup_kind: ReplaySetupKind
    request_body: bytes
    headers: tuple[tuple[str, str], ...]
    status: int
    outcome: ReplayOutcomeKind


@dataclass(frozen=True, slots=True)
class NormativeProtocolDefinition:
    """One independently specified non-tool protocol case."""

    case_id: str
    fixture: ReplayFixtureName
    profile: ReplayProfile
    scenario: str
    method: str
    params: JsonObject
    status: int
    outcome: ReplayOutcomeKind


class MutableReplayRecord(Protocol):
    """Writable view used solely to exercise Pydantic frozen assignment."""

    profile: ReplayProfile


class BaselineModel(BaseModel):
    """Strict immutable base for independently parsed manifest records."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
    )


class BaselineEntry(BaselineModel):
    """One digest-bound baseline fixture."""

    path: BaselineFileName
    sha256: HexDigest


class GitSourceIdentity(BaselineModel):
    """Audited Git source identity."""

    commit: GitObjectId
    tree: GitObjectId
    src_tree: GitObjectId


class RecoveryIdentity(BaselineModel):
    """One-time staged-recovery identity."""

    base_commit: GitObjectId
    base_tree: GitObjectId
    imported_index_tree: GitObjectId


class IndexTransitionIdentity(BaselineModel):
    """Reviewed historical-import to candidate-index admission."""

    transition_id: Literal["phase-1-reviewed-index-transition-v1"]
    imported_index_tree: GitObjectId
    imported_staged_entries_sha256: HexDigest
    candidate_index_tree: GitObjectId
    candidate_staged_entries_sha256: HexDigest


class CaptureInputIdentity(BaselineModel):
    """Repeated synthetic capture-input identity."""

    tree_before: GitObjectId
    tree_after: GitObjectId
    src_tree: GitObjectId
    git_object_format: Literal["sha1"]
    excluded_output_paths: Annotated[tuple[str, ...], Field(min_length=5, max_length=5)]
    included_untracked_paths: tuple[
        Literal["contracts/zod/asvs-evidence-contracts.mjs"],
        Literal["contracts/zod/baseline-contracts.mjs"],
        Literal["docs/security/threat-model.json"],
        Literal["eslint.config.mjs"],
        Literal["scripts/baseline_capture_io.py"],
        Literal["scripts/baseline_replay.py"],
        Literal["tests/contracts/zod_asvs_evidence_contracts.test.mjs"],
        Literal["tests/contracts/zod_baseline_contracts.test.mjs"],
        Literal["tests/property/test_asvs_evidence.py"],
        Literal["tests/unit/test_build_asvs_matrix.py"],
        Literal["tsconfig.contracts.json"],
    ]


class GeneratorIdentity(BaselineModel):
    """Generator blob and content digest."""

    path: Literal["scripts/capture_baseline.py"]
    version: Literal["3"]
    blob: GitObjectId
    sha256: HexDigest


class BaselineManifest(BaselineModel):
    """Independent closed schema for baseline manifest v3."""

    schema_version: Literal[3]
    capture_mode: Literal["synthetic-index-staged-recovery"]
    audit: GitSourceIdentity
    recovery: RecoveryIdentity
    index_transition: IndexTransitionIdentity
    input: CaptureInputIdentity
    generator: GeneratorIdentity
    canonicalization: Literal["nplg-json-sort-utf8-lf-v1"]
    response_canonicalization: Literal["nplg-response-semantic-numbers-v1"]
    entries: Annotated[tuple[BaselineEntry, ...], Field(min_length=4, max_length=4)]
    required_tool_names: Annotated[
        tuple[CaseId, ...],
        Field(min_length=8, max_length=8),
    ]
    required_case_ids: Annotated[
        tuple[CaseId, ...],
        Field(min_length=1, max_length=512),
    ]
    release_eligible: Literal[False]
    release_blockers: tuple[Literal["BASELINE_CAPTURE_NOT_COMMIT_REACHABLE"]]

    @model_validator(mode="after")
    def require_historical_import_identity(self) -> Self:
        if (
            self.recovery.imported_index_tree
            != self.index_transition.imported_index_tree
        ):
            message = "recovery and transition imported trees differ"
            raise ValueError(message)
        return self


class HistoricalManifestIdentity(BaselineModel):
    """Digest identity for the preserved one-time recovery manifest."""

    path: Literal["historical-manifest-v3.json"]
    schema_version: Literal[3]
    sha256: HexDigest


class AttestationPolicy(BaselineModel):
    """Closed policy for the commit that attests a clean candidate."""

    scheme: Literal["current-head-single-parent-manifest-delta-v1"]
    allowed_paths: tuple[
        Literal["contracts/baseline/manifest.json"],
        Literal["contracts/baseline/historical-manifest-v3.json"],
    ]


class CommittedBaselineManifest(BaselineModel):
    """Independent closed schema for the post-recovery manifest v4."""

    schema_version: Literal[4]
    capture_mode: Literal["committed-candidate-attestation"]
    candidate: GitSourceIdentity
    historical_provenance: HistoricalManifestIdentity
    attestation: AttestationPolicy
    canonicalization: Literal["nplg-json-sort-utf8-lf-v1"]
    response_canonicalization: Literal["nplg-response-semantic-numbers-v1"]
    entries: Annotated[tuple[BaselineEntry, ...], Field(min_length=4, max_length=4)]
    required_tool_names: Annotated[
        tuple[CaseId, ...],
        Field(min_length=8, max_length=8),
    ]
    required_case_ids: Annotated[
        tuple[CaseId, ...],
        Field(min_length=1, max_length=512),
    ]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_rev_parse(object_spec: str) -> str:
    # Security rationale: GIT_EXECUTABLE is absolute; fixed rev-parse --verify flags
    # receive the sole caller's validated SHA-1 tree plus :src as one argv item.
    # No shell is used; see https://github.com/astral-sh/ruff/issues/4045.
    result: subprocess.CompletedProcess[str] = subprocess.run(  # noqa: S603
        [str(GIT_EXECUTABLE), "rev-parse", "--verify", object_spec],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def require_test_object(value: object, *, context: str) -> JsonObject:
    """Return an exact JSON object or fail the test with useful context."""
    try:
        return require_json_object(value, context=context)
    except TypeError as exc:
        raise AssertionError(str(exc)) from exc


def require_test_array(value: object, *, context: str) -> list[JsonValue]:
    """Return an exact JSON array or fail the test with useful context."""
    if not isinstance(value, list):
        msg = f"{context} must be a JSON array"
        raise TypeError(msg)
    return cast("list[JsonValue]", value)


def clone_test_object(value: JsonObject) -> JsonObject:
    """Clone a JSON object without crossing an untyped decoder boundary."""
    return copy.deepcopy(value)


def directory_children(path: Path) -> tuple[Path, ...]:
    """List a directory through a synchronous helper for async tests."""
    return tuple(path.iterdir())


def path_mode(path: Path) -> int:
    """Read one mode through a synchronous helper for async tests."""
    return stat.S_IMODE(path.stat().st_mode)


def load_fixture_index(path: BaselineFileName) -> JsonObject:
    value = load_json_value((BASELINE_DIR / path).read_bytes())
    return require_test_object(value, context=path)


def frozen_tool_names() -> set[str]:
    return set(load_fixture_index("tool-catalog.json"))


def frozen_case_ids() -> set[str]:
    case_ids: set[str] = set()
    for path in ("resources.json", "result-cases.json", "error-cases.json"):
        case_ids.update(load_fixture_index(path))
    return case_ids


def canonical_test_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def canonical_request_bytes(value: object) -> bytes:
    """Encode the fixture-independent exact request body (without file LF)."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def normative_setup(kind: ReplaySetupKind) -> JsonObject:
    """Return the exact declarative state required before one request."""
    if kind == "empty":
        return {"kind": "empty"}
    if kind == "document":
        return {
            "kind": "document",
            "handle": "1234/560449",
            "bitstream_id": "bs_public",
            "artifact_id": FIXED_ARTIFACT_ID,
        }
    return {
        "kind": "render",
        "handle": "1234/560449",
        "bitstream_id": "bs_public",
        "artifact_id": FIXED_ARTIFACT_ID,
        "pages": [1],
        "mode": "native",
        "render_id": FIXED_RENDER_ID,
    }


def normative_request(
    *,
    request_id: str,
    profile: ReplayProfile,
    method: str,
    params: Mapping[str, object],
    name_header: str | None = None,
) -> tuple[bytes, tuple[tuple[str, str], ...]]:
    """Build exact request bytes/headers independently of the capture script."""
    request_params = dict(params)
    if profile == "modern":
        request_params["_meta"] = {
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "fixture-client",
                "version": "1.0.0",
            },
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        }
    payload = {
        "id": request_id,
        "jsonrpc": "2.0",
        "method": method,
        "params": request_params,
    }
    if method == "initialize":
        headers: tuple[tuple[str, str], ...] = ()
    elif profile == "legacy":
        headers = (("MCP-Protocol-Version", "2025-11-25"),)
    else:
        modern_headers = [
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", method),
        ]
        if name_header is not None:
            modern_headers.append(("Mcp-Name", name_header))
        headers = tuple(modern_headers)
    return canonical_request_bytes(payload), headers


def _tool_setup_kind(tool_name: ToolName) -> ReplaySetupKind:
    if tool_name in {"inspect_pdf", "render_pdf_pages"}:
        return "document"
    if tool_name in {"get_render_manifest", "render_pdf_page_tiles"}:
        return "render"
    return "empty"


def _tool_success_arguments() -> dict[ToolName, dict[str, object]]:
    return {
        "download_document_file": {
            "handle": "1234/560449",
            "bitstream_id": "bs_public",
        },
        "get_document_metadata": {"handle": "1234/560449"},
        "get_render_manifest": {"render_id": FIXED_RENDER_ID},
        "inspect_pdf": {"artifact_id": FIXED_ARTIFACT_ID},
        "list_document_files": {"handle": "1234/560449"},
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


def _tool_type_arguments() -> dict[ToolName, dict[str, object]]:
    return {
        "download_document_file": {
            "handle": "1234/560449",
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


def _normative_tool_cases() -> tuple[NormativeReplayCase, ...]:
    cases: list[NormativeReplayCase] = []
    success_arguments = _tool_success_arguments()
    type_arguments = _tool_type_arguments()
    for tool_name in sorted(EXPECTED_TOOL_NAMES):
        for profile in EXPECTED_PROFILES:
            success_case_id = f"tool.{tool_name}.{profile}.success"
            success_body, success_headers = normative_request(
                request_id=success_case_id,
                profile=profile,
                method="tools/call",
                params={"name": tool_name, "arguments": success_arguments[tool_name]},
                name_header=tool_name,
            )
            cases.append(
                NormativeReplayCase(
                    case_id=success_case_id,
                    fixture="result-cases.json",
                    profile=profile,
                    scenario="tool.success",
                    setup_kind=_tool_setup_kind(tool_name),
                    request_body=success_body,
                    headers=success_headers,
                    status=200,
                    outcome="tool-success",
                )
            )
            extra_arguments = dict(success_arguments[tool_name])
            if "artifact_id" in extra_arguments:
                extra_arguments["artifact_id"] = ZERO_ARTIFACT_ID
            if "render_id" in extra_arguments:
                extra_arguments["render_id"] = ZERO_RENDER_ID
            extra_arguments["unexpected"] = True
            failure_values: tuple[tuple[str, str, dict[str, object]], ...] = (
                ("extra", "tool.strict-extra", extra_arguments),
                ("type", "tool.strict-type", type_arguments[tool_name]),
            )
            for suffix, scenario, arguments in failure_values:
                case_id = f"tool.{tool_name}.{profile}.{suffix}"
                body, headers = normative_request(
                    request_id=case_id,
                    profile=profile,
                    method="tools/call",
                    params={"name": tool_name, "arguments": arguments},
                    name_header=tool_name,
                )
                cases.append(
                    NormativeReplayCase(
                        case_id=case_id,
                        fixture="error-cases.json",
                        profile=profile,
                        scenario=scenario,
                        setup_kind="empty",
                        request_body=body,
                        headers=headers,
                        status=200,
                        outcome="strict-error",
                    )
                )
    return tuple(cases)


def _normative_resource_cases() -> tuple[NormativeReplayCase, ...]:
    cases: list[NormativeReplayCase] = []
    operations: tuple[ResourceOperation, ...] = (
        "list",
        "read-about",
        "read-artifact",
        "read-render",
    )
    for operation in operations:
        for profile in EXPECTED_PROFILES:
            case_id = f"resource.{operation}.{profile}"
            setup_kind: ReplaySetupKind = "empty"
            if operation == "list":
                method = "resources/list"
                params: dict[str, object] = {}
                name_header = None
                outcome: ReplayOutcomeKind = "resource-list"
            else:
                method = "resources/read"
                outcome = "resource-read"
                if operation == "read-about":
                    uri = "nplg://about"
                elif operation == "read-artifact":
                    setup_kind = "document"
                    uri = f"nplg://artifact/{FIXED_ARTIFACT_ID}"
                else:
                    setup_kind = "render"
                    uri = f"nplg://render/{FIXED_RENDER_ID}/manifest"
                params = {"uri": uri}
                name_header = uri
            body, headers = normative_request(
                request_id=case_id,
                profile=profile,
                method=method,
                params=params,
                name_header=name_header,
            )
            cases.append(
                NormativeReplayCase(
                    case_id=case_id,
                    fixture="resources.json",
                    profile=profile,
                    scenario=f"resource.{operation}",
                    setup_kind=setup_kind,
                    request_body=body,
                    headers=headers,
                    status=200,
                    outcome=outcome,
                )
            )
    return tuple(cases)


def _normative_sanitizer_cases() -> tuple[NormativeReplayCase, ...]:
    cases: list[NormativeReplayCase] = []
    sanitizer_values: tuple[tuple[str, str, ReplayOutcomeKind, int], ...] = (
        ("app-canary", "error.app-canary", "app-error", 200),
        ("generic-canary", "error.generic-canary", "generic-error", 500),
    )
    for kind, scenario, outcome, status in sanitizer_values:
        for profile in EXPECTED_PROFILES:
            case_id = f"error.{kind}.{profile}"
            body, headers = normative_request(
                request_id=case_id,
                profile=profile,
                method="tools/call",
                params={
                    "name": "search_documents",
                    "arguments": {"query": "fixture"},
                },
                name_header="search_documents",
            )
            cases.append(
                NormativeReplayCase(
                    case_id=case_id,
                    fixture="error-cases.json",
                    profile=profile,
                    scenario=scenario,
                    setup_kind="empty",
                    request_body=body,
                    headers=headers,
                    status=status,
                    outcome=outcome,
                )
            )
    return tuple(cases)


def _normative_protocol_cases() -> tuple[NormativeReplayCase, ...]:
    definitions = (
        NormativeProtocolDefinition(
            case_id="protocol.initialize.legacy.success",
            fixture="result-cases.json",
            profile="legacy",
            scenario="protocol.initialize",
            method="initialize",
            params={"protocolVersion": "2025-11-25"},
            status=200,
            outcome="protocol-success",
        ),
        NormativeProtocolDefinition(
            case_id="protocol.server-discover.modern.success",
            fixture="result-cases.json",
            profile="modern",
            scenario="protocol.server-discover",
            method="server/discover",
            params={},
            status=200,
            outcome="protocol-success",
        ),
        NormativeProtocolDefinition(
            case_id="protocol.tools-list.legacy.success",
            fixture="result-cases.json",
            profile="legacy",
            scenario="protocol.tools-list",
            method="tools/list",
            params={},
            status=200,
            outcome="protocol-success",
        ),
        NormativeProtocolDefinition(
            case_id="protocol.tools-list.modern.success",
            fixture="result-cases.json",
            profile="modern",
            scenario="protocol.tools-list",
            method="tools/list",
            params={},
            status=200,
            outcome="protocol-success",
        ),
        NormativeProtocolDefinition(
            case_id="protocol.method-unknown.legacy.error",
            fixture="error-cases.json",
            profile="legacy",
            scenario="protocol.method-unknown",
            method="unknown/method",
            params={},
            status=404,
            outcome="protocol-error",
        ),
        NormativeProtocolDefinition(
            case_id="protocol.header-mismatch.modern.error",
            fixture="error-cases.json",
            profile="modern",
            scenario="protocol.header-mismatch",
            method="server/discover",
            params={},
            status=400,
            outcome="protocol-error",
        ),
    )
    cases: list[NormativeReplayCase] = []
    for definition in definitions:
        body, headers = normative_request(
            request_id=definition.case_id,
            profile=definition.profile,
            method=definition.method,
            params=definition.params,
            name_header=None,
        )
        if definition.case_id == "protocol.header-mismatch.modern.error":
            headers = tuple(
                (name, "tools/list" if name == "Mcp-Method" else value)
                for name, value in headers
            )
        cases.append(
            NormativeReplayCase(
                case_id=definition.case_id,
                fixture=definition.fixture,
                profile=definition.profile,
                scenario=definition.scenario,
                setup_kind="empty",
                request_body=body,
                headers=headers,
                status=definition.status,
                outcome=definition.outcome,
            )
        )
    return tuple(cases)


def normative_replay_cases() -> tuple[NormativeReplayCase, ...]:
    """Return the exact 66-case oracle without reading fixtures or manifests."""
    cases = (
        *_normative_tool_cases(),
        *_normative_resource_cases(),
        *_normative_sanitizer_cases(),
        *_normative_protocol_cases(),
    )
    return tuple(sorted(cases, key=_normative_case_id))


def _normative_case_id(case: NormativeReplayCase) -> str:
    return case.case_id


def write_valid_infrastructure_fixture(
    root: Path,
    *,
    marker: str | None = None,
) -> dict[str, object]:
    marker_record: dict[str, str] = {} if marker is None else {"marker": marker}
    values: dict[BaselineFileName, object] = {
        "tool-catalog.json": {
            name: dict(marker_record) for name in sorted(EXPECTED_TOOL_NAMES)
        },
        "resources.json": {"resource.one": dict(marker_record)},
        "result-cases.json": {"case.one": dict(marker_record)},
        "error-cases.json": {"error.one": dict(marker_record)},
    }
    entries: list[dict[str, str]] = []
    root.mkdir(mode=0o700)
    for name in BASELINE_FILE_NAMES:
        raw = canonical_test_bytes(values[name])
        _ = (root / name).write_bytes(raw)
        entries.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest()})
    manifest: dict[str, object] = {
        "schema_version": 3,
        "capture_mode": "synthetic-index-staged-recovery",
        "audit": {
            "commit": "2ba5dc18385747aa5d12a3b560eaab2ab97b7a40",
            "tree": "b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8",
            "src_tree": "fcd9debdb533498486a2bbeaf909ea5bfb95b52c",
        },
        "recovery": {
            "base_commit": "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
            "base_tree": "2464df5aa1880e99168ce07c23d891ab66ed3959",
            "imported_index_tree": IMPORTED_INDEX_TREE,
        },
        "index_transition": {
            "transition_id": INDEX_TRANSITION_ID,
            "imported_index_tree": IMPORTED_INDEX_TREE,
            "imported_staged_entries_sha256": IMPORTED_STAGED_ENTRIES_SHA256,
            "candidate_index_tree": CANDIDATE_INDEX_TREE,
            "candidate_staged_entries_sha256": CANDIDATE_STAGED_ENTRIES_SHA256,
        },
        "input": {
            "tree_before": "7" * 40,
            "tree_after": "7" * 40,
            "src_tree": "8" * 40,
            "git_object_format": "sha1",
            "excluded_output_paths": [
                f"contracts/baseline/{name}"
                for name in (*BASELINE_FILE_NAMES, "manifest.json")
            ],
            "included_untracked_paths": list(INCLUDED_UNTRACKED_PATHS),
        },
        "generator": {
            "path": "scripts/capture_baseline.py",
            "version": "3",
            "blob": "9" * 40,
            "sha256": "a" * 64,
        },
        "canonicalization": "nplg-json-sort-utf8-lf-v1",
        "response_canonicalization": "nplg-response-semantic-numbers-v1",
        "entries": entries,
        "required_tool_names": sorted(EXPECTED_TOOL_NAMES),
        "required_case_ids": ["case.one", "error.one", "resource.one"],
        "release_eligible": False,
        "release_blockers": ["BASELINE_CAPTURE_NOT_COMMIT_REACHABLE"],
    }
    _ = (root / "manifest.json").write_bytes(canonical_test_bytes(manifest))
    return manifest


def run_test_git(
    root: Path,
    *arguments: str,
) -> str:
    absolute_root = root.absolute()
    with tempfile.TemporaryDirectory(prefix="nplg-test-git-environment-") as temporary:
        private_root = Path(temporary).absolute()
        private_root.chmod(0o700)
        home = private_root / "home"
        home.mkdir(mode=0o700)
        xdg = private_root / "xdg"
        xdg.mkdir(mode=0o700)
        environment = {
            "GIT_ASKPASS": "/bin/false",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_AUTHOR_EMAIL": "baseline@example.invalid",
            "GIT_AUTHOR_NAME": "Baseline Test",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_COMMITTER_EMAIL": "baseline@example.invalid",
            "GIT_COMMITTER_NAME": "Baseline Test",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_EDITOR": "/bin/false",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_SEQUENCE_EDITOR": "/bin/false",
            "GIT_SSH": "/bin/false",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PAGER": "cat",
            "PATH": os.defpath,
            "SSH_ASKPASS": "/bin/false",
            "TERM": "dumb",
            "TZ": "UTC",
            "XDG_CONFIG_HOME": str(xdg),
        }
        command = (
            str(GIT_EXECUTABLE),
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=/bin/false",
            "-c",
            "gpg.program=/bin/false",
            "-C",
            str(absolute_root),
            *arguments,
        )
        try:
            result = baseline_capture_io.run_bounded_process(
                command,
                cwd=absolute_root,
                environment=environment,
                limits=baseline_capture_io.ProcessLimits(
                    timeout_seconds=5.0,
                    stdout_bytes=1024 * 1024,
                    stderr_bytes=64 * 1024,
                ),
            )
        except capture_baseline.BaselineCaptureError as exc:
            raise AssertionError(str(exc)) from exc
    try:
        stdout = result.stdout.decode("utf-8", errors="strict")
        stderr = result.stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        msg = "test Git output is not valid UTF-8"
        raise AssertionError(msg) from exc
    if result.returncode != 0:
        msg = f"test Git command failed with status {result.returncode}: {stderr}"
        raise AssertionError(msg)
    if stderr:
        msg = f"test Git command returned unexpected stderr: {stderr}"
        raise AssertionError(msg)
    return stdout.strip()


def run_test_git_no_output(root: Path, *arguments: str) -> None:
    """Run a fixture Git command whose success has no meaningful stdout."""
    _ = run_test_git(root, *arguments)


def git_blob_object_id(raw: bytes) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def make_capture_git_repository(root: Path) -> CapturePolicyValues:
    _ = run_test_git(root.parent, "init", "--quiet", str(root))
    _ = run_test_git(root, "config", "user.name", "Baseline Test")
    _ = run_test_git(root, "config", "user.email", "baseline@example.invalid")
    (root / "src").mkdir()
    _ = (root / "src" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "scripts").mkdir()
    _ = (root / "scripts" / "capture_baseline.py").write_text(
        "print('committed')\n",
        encoding="utf-8",
    )
    _ = (root / ".gitignore").write_text("ignored-untracked.txt\n", encoding="utf-8")
    helper = root / "tests" / "helpers" / "fixture_helper.py"
    helper.parent.mkdir(parents=True)
    _ = helper.write_text("VALUE = 1\n", encoding="utf-8")
    baseline = root / "contracts" / "baseline"
    baseline.mkdir(parents=True)
    for name in (*BASELINE_FILE_NAMES, "manifest.json"):
        _ = (baseline / name).write_bytes(b"{}\n")
    _ = run_test_git(root, "add", "--", ".")
    _ = run_test_git(root, "commit", "--quiet", "-m", "fixture")
    commit = run_test_git(root, "rev-parse", "HEAD")
    for relative_path, raw in INCLUDED_UNTRACKED_BYTES.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_bytes(raw)
        path.chmod(0o644)
    index_tree = run_test_git(root, "write-tree")
    staged_entries_sha256 = hashlib.sha256(
        baseline_capture_io.git_bytes(root, ("ls-files", "--stage", "-z"))
    ).hexdigest()
    return {
        "audit_commit": commit,
        "audit_tree": run_test_git(root, "rev-parse", "HEAD^{tree}"),
        "audit_src_tree": run_test_git(root, "rev-parse", "HEAD:src"),
        "base_commit": commit,
        "base_tree": run_test_git(root, "rev-parse", "HEAD^{tree}"),
        "index_transition": baseline_capture_io.IndexTransitionIdentity(
            transition_id=INDEX_TRANSITION_ID,
            imported_index_tree=index_tree,
            imported_staged_entries_sha256=staged_entries_sha256,
            candidate_index_tree=index_tree,
            candidate_staged_entries_sha256=staged_entries_sha256,
        ),
        "included_untracked_paths": INCLUDED_UNTRACKED_PATHS,
    }


def make_clean_committed_baseline_repository(root: Path) -> str:
    """Create a clean committed candidate carrying the historical v3 baseline."""
    _ = make_capture_git_repository(root)
    baseline_root = root / "contracts" / "baseline"
    for path in baseline_root.iterdir():
        path.unlink()
    baseline_root.rmdir()
    _ = write_valid_infrastructure_fixture(baseline_root)
    run_test_git_no_output(
        root,
        "add",
        "--",
        "contracts/baseline",
        *INCLUDED_UNTRACKED_PATHS,
    )
    run_test_git_no_output(root, "commit", "--quiet", "-m", "candidate")
    return run_test_git(root, "rev-parse", "HEAD")


def make_unattested_committed_baseline_directory(root: Path) -> Path:
    """Create a valid v4 directory without committing the attestation."""
    repository = root / "repository"
    _ = make_clean_committed_baseline_repository(repository)
    capture_baseline.write_committed_candidate_manifest(repository)
    return repository / "contracts" / "baseline"


def test_temp_git_runner_uses_exact_closed_environment_argv_and_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = False

    def bounded_process(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: baseline_capture_io.ProcessLimits,
    ) -> baseline_capture_io.ChildResult:
        nonlocal observed
        observed = True
        assert command == (
            str(GIT_EXECUTABLE),
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=/bin/false",
            "-c",
            "gpg.program=/bin/false",
            "-C",
            str(tmp_path.absolute()),
            "version",
        )
        assert cwd == tmp_path.absolute()
        assert limits == baseline_capture_io.ProcessLimits(
            timeout_seconds=5.0,
            stdout_bytes=1024 * 1024,
            stderr_bytes=64 * 1024,
        )
        expected_environment = {
            "GIT_ASKPASS": "/bin/false",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_AUTHOR_EMAIL": "baseline@example.invalid",
            "GIT_AUTHOR_NAME": "Baseline Test",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_COMMITTER_EMAIL": "baseline@example.invalid",
            "GIT_COMMITTER_NAME": "Baseline Test",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_EDITOR": "/bin/false",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_SEQUENCE_EDITOR": "/bin/false",
            "GIT_SSH": "/bin/false",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PAGER": "cat",
            "PATH": os.defpath,
            "SSH_ASKPASS": "/bin/false",
            "TERM": "dumb",
            "TZ": "UTC",
        }
        assert set(environment) == {*expected_environment, "HOME", "XDG_CONFIG_HOME"}
        assert {
            key: environment[key] for key in expected_environment
        } == expected_environment
        for key in ("HOME", "XDG_CONFIG_HOME"):
            private_directory = Path(environment[key])
            assert private_directory.is_dir()
            assert (
                stat.S_IMODE(private_directory.stat().st_mode) == PRIVATE_DIRECTORY_MODE
            )
            assert private_directory != Path(os.environ.get(key, ""))
        return baseline_capture_io.ChildResult(
            returncode=0,
            stdout=b"git version bounded-test\n",
            stderr=b"",
        )

    monkeypatch.setattr(baseline_capture_io, "run_bounded_process", bounded_process)

    assert run_test_git(tmp_path, "version") == "git version bounded-test"
    assert observed


@pytest.mark.parametrize(
    "failure",
    [
        "bounded child process timed out",
        "bounded child stdout output limit exceeded",
        "bounded child stderr output limit exceeded",
    ],
)
def test_temp_git_runner_maps_bounded_process_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    def fail_bounded_process(
        _command: tuple[str, ...],
        **_kwargs: object,
    ) -> baseline_capture_io.ChildResult:
        raise capture_baseline.BaselineCaptureError(failure)

    monkeypatch.setattr(
        baseline_capture_io, "run_bounded_process", fail_bounded_process
    )

    with pytest.raises(AssertionError, match=re.escape(failure)):
        _ = run_test_git(tmp_path, "version")


def test_temp_git_fixture_cannot_inherit_supplied_global_signing_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = tmp_path / "ambient-signing-helper-executed"
    helper = tmp_path / "ambient-signing-helper"
    _ = helper.write_text(
        f"#!/bin/sh\n: > '{sentinel}'\nexit 1\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    supplied_global = tmp_path / "ambient-global.gitconfig"
    _ = supplied_global.write_text(
        "".join(
            (
                "[commit]\n",
                "\tgpgSign = true\n",
                "[gpg]\n",
                f'\tprogram = "{helper}"\n',
                "[user]\n",
                "\tsigningKey = fixture-key\n",
            ),
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(supplied_global))
    repository = tmp_path / "repository"

    _ = make_capture_git_repository(repository)

    assert not sentinel.exists()


def git_object_inventory(root: Path) -> dict[str, str]:
    objects = Path(run_test_git(root, "rev-parse", "--git-path", "objects"))
    if not objects.is_absolute():
        objects = root / objects
    return {
        str(path.relative_to(objects)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(objects.rglob("*"))
        if path.is_file()
    }


def git_object_metadata_inventory(
    root: Path,
) -> dict[str, tuple[int, int, int, int, str | None]]:
    """Independently bind object names, bytes, sizes, modes, links, and mtimes."""
    objects = Path(run_test_git(root, "rev-parse", "--git-path", "objects"))
    if not objects.is_absolute():
        objects = root / objects
    inventory: dict[str, tuple[int, int, int, int, str | None]] = {}
    for path in sorted(objects.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(objects).as_posix()
        digest = (
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        )
        inventory[relative] = (
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            digest,
        )
    return inventory


def capture_policy_values(
    policy: baseline_capture_io.CapturePolicy,
) -> CapturePolicyValues:
    """Expose the exact typed policy fields without an untyped model dump."""
    return {
        "audit_commit": policy.audit_commit,
        "audit_tree": policy.audit_tree,
        "audit_src_tree": policy.audit_src_tree,
        "base_commit": policy.base_commit,
        "base_tree": policy.base_tree,
        "index_transition": policy.index_transition,
        "included_untracked_paths": policy.included_untracked_paths,
    }


def replace_index_transition(
    transition: baseline_capture_io.IndexTransitionIdentity,
    *,
    imported_staged_entries_sha256: str | None = None,
    candidate_index_tree: str | None = None,
    candidate_staged_entries_sha256: str | None = None,
) -> baseline_capture_io.IndexTransitionIdentity:
    """Return one transition with only the named test identity replaced."""
    return baseline_capture_io.IndexTransitionIdentity(
        transition_id=transition.transition_id,
        imported_index_tree=transition.imported_index_tree,
        imported_staged_entries_sha256=(
            transition.imported_staged_entries_sha256
            if imported_staged_entries_sha256 is None
            else imported_staged_entries_sha256
        ),
        candidate_index_tree=(
            transition.candidate_index_tree
            if candidate_index_tree is None
            else candidate_index_tree
        ),
        candidate_staged_entries_sha256=(
            transition.candidate_staged_entries_sha256
            if candidate_staged_entries_sha256 is None
            else candidate_staged_entries_sha256
        ),
    )


def current_recovery_policy() -> baseline_capture_io.CapturePolicy:
    return baseline_capture_io.CapturePolicy(
        audit_commit="2ba5dc18385747aa5d12a3b560eaab2ab97b7a40",
        audit_tree="b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8",
        audit_src_tree="fcd9debdb533498486a2bbeaf909ea5bfb95b52c",
        base_commit="da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
        base_tree="2464df5aa1880e99168ce07c23d891ab66ed3959",
        index_transition=baseline_capture_io.IndexTransitionIdentity(
            transition_id=INDEX_TRANSITION_ID,
            imported_index_tree=IMPORTED_INDEX_TREE,
            imported_staged_entries_sha256=IMPORTED_STAGED_ENTRIES_SHA256,
            candidate_index_tree=CANDIDATE_INDEX_TREE,
            candidate_staged_entries_sha256=CANDIDATE_STAGED_ENTRIES_SHA256,
        ),
        included_untracked_paths=INCLUDED_UNTRACKED_PATHS,
    )


def test_frozen_case_matrix_is_hard_coded_independently_of_manifest() -> None:
    assert frozen_tool_names() == EXPECTED_TOOL_NAMES
    case_ids = frozen_case_ids()
    assert [len(group) for group in EXPECTED_CASE_ID_GROUPS] == [16, 32, 8, 4, 6]
    for index, group in enumerate(EXPECTED_CASE_ID_GROUPS):
        for other in EXPECTED_CASE_ID_GROUPS[index + 1 :]:
            assert group.isdisjoint(other)
    expected = frozenset[str]().union(*EXPECTED_CASE_ID_GROUPS)
    assert len(expected) == EXPECTED_BEHAVIOR_CASES
    assert case_ids == expected


def test_manifest_binds_the_versioned_response_number_canonicalization() -> None:
    manifest = BaselineManifest.model_validate_json(
        (BASELINE_DIR / "manifest.json").read_bytes(),
        strict=True,
    )
    assert manifest.response_canonicalization == "nplg-response-semantic-numbers-v1"


def test_normative_replay_oracle_has_exact_closed_allocation() -> None:
    cases = normative_replay_cases()
    assert len(cases) == EXPECTED_BEHAVIOR_CASES
    assert len({case.case_id for case in cases}) == EXPECTED_BEHAVIOR_CASES
    assert {case.case_id for case in cases} == frozenset().union(
        *EXPECTED_CASE_ID_GROUPS
    )
    assert (
        sum(case.fixture == "result-cases.json" for case in cases)
        == EXPECTED_RESULT_CASES
    )
    assert (
        sum(case.fixture == "error-cases.json" for case in cases)
        == EXPECTED_ERROR_CASES
    )
    assert (
        sum(case.fixture == "resources.json" for case in cases)
        == EXPECTED_RESOURCE_CASES
    )


@pytest.mark.asyncio
async def test_capture_matrix_uses_one_digest_derived_private_root_per_case(
    tmp_path: Path,
) -> None:
    fixtures = await baseline_replay.capture_behavior_matrix(tmp_path)
    cases = normative_replay_cases()
    assert set(fixtures["result-cases.json"]) == {
        case.case_id for case in cases if case.fixture == "result-cases.json"
    }
    assert set(fixtures["error-cases.json"]) == {
        case.case_id for case in cases if case.fixture == "error-cases.json"
    }
    assert set(fixtures["resources.json"]) == {
        case.case_id for case in cases if case.fixture == "resources.json"
    }
    expected_roots = {
        hashlib.sha256(case.case_id.encode("utf-8")).hexdigest() for case in cases
    }
    roots = await asyncio.to_thread(directory_children, tmp_path)
    assert {path.name for path in roots} == expected_roots
    for root in roots:
        assert root.is_dir()
        assert not root.is_symlink()
        assert stat.S_IMODE(root.stat().st_mode) == PRIVATE_DIRECTORY_MODE


@pytest.mark.asyncio
async def test_generated_matrix_reexecutes_through_the_public_replay_verifier(
    tmp_path: Path,
) -> None:
    capture_root = tmp_path / "capture"
    capture_root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    fixtures = await baseline_replay.capture_behavior_matrix(capture_root)
    replay_root = tmp_path / "replay"
    replay_root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    await baseline_replay.verify_replay_fixture_records(fixtures, replay_root)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["capture", "verify"])
async def test_replay_operations_reject_a_nonempty_runtime_root(
    tmp_path: Path,
    operation: str,
) -> None:
    _ = (tmp_path / "residue").write_bytes(b"residue")
    action: Awaitable[object]
    if operation == "capture":
        action = baseline_replay.capture_behavior_matrix(tmp_path)
    else:
        empty_fixtures: BaselineFixtures = {}
        action = baseline_replay.verify_replay_fixture_records(empty_fixtures, tmp_path)

    with pytest.raises(capture_baseline.BaselineCaptureError, match="must be empty"):
        await action


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["missing-file", "incomplete-catalog"])
async def test_replay_verifier_rejects_incomplete_fixture_allocation(
    tmp_path: Path,
    fault: str,
) -> None:
    fixtures: BaselineFixtures = {
        name: load_fixture_index(name) for name in BASELINE_FILE_NAMES
    }
    if fault == "missing-file":
        del fixtures["error-cases.json"]
    else:
        _ = fixtures["tool-catalog.json"].pop("search_documents")

    with pytest.raises(capture_baseline.BaselineCaptureError):
        await baseline_replay.verify_replay_fixture_records(fixtures, tmp_path)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["symlink", "hardlink"])
async def test_replay_capture_rejects_unsafe_service_allocations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    def unsafe_service(
        root: Path,
        *,
        fault_mode: baseline_replay.CaseFaultMode,
    ) -> ToolService:
        service = make_tool_service(root, fault_mode=fault_mode, frozen_origin=True)
        target = root / "fixture-source.pdf"
        outside = root.parent / f"outside-{root.name}"
        _ = outside.write_bytes(target.read_bytes())
        target.unlink()
        if fault == "symlink":
            target.symlink_to(outside)
        else:
            os.link(outside, target)
        return service

    monkeypatch.setattr("tests.helpers.app_factory.make_tool_service", unsafe_service)

    with pytest.raises(capture_baseline.BaselineCaptureError, match="link"):
        _ = await baseline_replay.capture_behavior_matrix(tmp_path)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["invalid-name", "missing-tool", "catalog-drift"])
async def test_replay_capture_rejects_invalid_or_unstable_tool_catalogs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    service_count = 0

    def faulty_catalog_service(
        root: Path,
        *,
        fault_mode: baseline_replay.CaseFaultMode,
    ) -> ToolService:
        nonlocal service_count
        service_count += 1
        service = make_tool_service(root, fault_mode=fault_mode, frozen_origin=True)
        catalog = service.list_tools()
        if fault == "invalid-name":
            catalog[0]["name"] = ""
        elif fault == "missing-tool":
            _ = catalog.pop()
        elif service_count == SECOND_SERVICE_CALL:
            catalog[0]["description"] = "drifted"
        monkeypatch.setattr(service, "list_tools", lambda: catalog)
        return service

    monkeypatch.setattr(
        "tests.helpers.app_factory.make_tool_service",
        faulty_catalog_service,
    )

    with pytest.raises(capture_baseline.BaselineCaptureError, match="catalog"):
        _ = await baseline_replay.capture_behavior_matrix(tmp_path)


@pytest.mark.asyncio
async def test_replay_verifier_rejects_catalog_drift_from_the_supplied_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixtures: BaselineFixtures = {
        name: load_fixture_index(name) for name in BASELINE_FILE_NAMES
    }

    def drifted_catalog_service(
        root: Path,
        *,
        fault_mode: baseline_replay.CaseFaultMode,
    ) -> ToolService:
        service = make_tool_service(root, fault_mode=fault_mode, frozen_origin=True)
        catalog = service.list_tools()
        catalog[0]["description"] = "drifted"
        monkeypatch.setattr(service, "list_tools", lambda: catalog)
        return service

    monkeypatch.setattr(
        "tests.helpers.app_factory.make_tool_service",
        drifted_catalog_service,
    )

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="live official SDK",
    ):
        await baseline_replay.verify_replay_fixture_records(fixtures, tmp_path)


@pytest.mark.asyncio
async def test_replay_verifier_rejects_live_official_tool_result_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fixture-only replay cannot conceal drift in the live official SDK path."""
    fixtures: BaselineFixtures = {
        name: load_fixture_index(name) for name in BASELINE_FILE_NAMES
    }

    def mutant_service(
        root: Path,
        *,
        fault_mode: baseline_replay.CaseFaultMode,
    ) -> ToolService:
        service = make_tool_service(root, fault_mode=fault_mode, frozen_origin=True)
        live_call = service.call

        async def mutant_call(name: str, arguments: JsonObject) -> StrictOutput:
            result = await live_call(name, arguments)
            if name == "search_documents":
                assert isinstance(result, SearchDocumentsOutput)
                object.__setattr__(result.items[0], "title", "live-mutant-title")
            return result

        monkeypatch.setattr(service, "call", mutant_call)
        return service

    monkeypatch.setattr(
        "tests.helpers.app_factory.make_tool_service",
        mutant_service,
    )

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="live official SDK",
    ):
        await baseline_replay.verify_replay_fixture_records(fixtures, tmp_path)


@pytest.mark.asyncio
async def test_replay_verifier_rejects_live_metadata_behavior_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every frozen tool case must execute its equivalent live SDK behavior."""
    fixtures: BaselineFixtures = {
        name: load_fixture_index(name) for name in BASELINE_FILE_NAMES
    }

    def mutant_service(
        root: Path,
        *,
        fault_mode: baseline_replay.CaseFaultMode,
    ) -> ToolService:
        service = make_tool_service(root, fault_mode=fault_mode, frozen_origin=True)
        live_call = service.call

        async def mutant_call(name: str, arguments: JsonObject) -> StrictOutput:
            result = await live_call(name, arguments)
            if name == "get_document_metadata":
                assert isinstance(result, DocumentMetadataOutput)
                object.__setattr__(result, "title", "live-mutant-title")
            return result

        monkeypatch.setattr(service, "call", mutant_call)
        return service

    monkeypatch.setattr(
        "tests.helpers.app_factory.make_tool_service",
        mutant_service,
    )

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="live official SDK",
    ):
        await baseline_replay.verify_replay_fixture_records(fixtures, tmp_path)


@pytest.mark.asyncio
async def test_replay_verifier_binds_tile_uri_to_persisted_manifest_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixtures: BaselineFixtures = {
        name: load_fixture_index(name) for name in BASELINE_FILE_NAMES
    }

    def mutant_service(
        root: Path,
        *,
        fault_mode: baseline_replay.CaseFaultMode,
    ) -> ToolService:
        service = make_tool_service(root, fault_mode=fault_mode, frozen_origin=True)
        live_call = service.call

        async def mutant_call(name: str, arguments: JsonObject) -> StrictOutput:
            result = await live_call(name, arguments)
            if name == "render_pdf_page_tiles":
                assert isinstance(result, RenderTilesOutput)
                object.__setattr__(
                    result,
                    "resource_uri",
                    "nplg://artifact/doc_" + "0" * 64,
                )
            return result

        monkeypatch.setattr(service, "call", mutant_call)
        return service

    monkeypatch.setattr(
        "tests.helpers.app_factory.make_tool_service",
        mutant_service,
    )

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="tile manifest URI",
    ):
        await baseline_replay.verify_replay_fixture_records(fixtures, tmp_path)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["document-id", "render-id"])
async def test_replay_capture_rejects_nonreproducible_setup_identifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    def faulty_setup_service(
        root: Path,
        *,
        fault_mode: baseline_replay.CaseFaultMode,
    ) -> ToolService:
        service = make_tool_service(root, fault_mode=fault_mode, frozen_origin=True)
        call = service.call

        async def faulty_call(name: str, arguments: JsonObject) -> StrictOutput:
            result = await call(name, arguments)
            if (
                fault == "document-id"
                and name == "download_document_file"
                and isinstance(result, DownloadDocumentOutput)
            ):
                object.__setattr__(result, "artifact_id", ZERO_ARTIFACT_ID)
                return result
            if (
                fault == "render-id"
                and name == "render_pdf_pages"
                and isinstance(result, RenderPagesOutput)
            ):
                object.__setattr__(result, "render_id", ZERO_RENDER_ID)
                return result
            return result

        monkeypatch.setattr(service, "call", faulty_call)
        return service

    monkeypatch.setattr(
        "tests.helpers.app_factory.make_tool_service",
        faulty_setup_service,
    )

    with pytest.raises(capture_baseline.BaselineCaptureError, match="setup"):
        _ = await baseline_replay.capture_behavior_matrix(tmp_path)


def test_internal_replay_main_rejects_an_existing_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "capture.json"
    _ = output.write_bytes(b"preserve")

    with pytest.raises(SystemExit) as raised:
        _ = baseline_replay.main(["--internal-output", str(output)])

    assert raised.value.code == EXPECTED_CLI_ERROR_EXIT
    assert "must not already exist" in capsys.readouterr().err
    assert output.read_bytes() == b"preserve"


@pytest.mark.parametrize("result_kind", ["success", "failure"])
def test_internal_replay_main_restores_logging_and_writes_only_on_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    result_kind: str,
) -> None:
    output = tmp_path / "capture.json"
    before_disable = logging.root.manager.disable
    fixtures: BaselineFixtures = {name: {} for name in BASELINE_FILE_NAMES}

    async def controlled_capture(_root: Path) -> BaselineFixtures:
        if result_kind == "failure":
            msg = "controlled capture failure"
            raise capture_baseline.BaselineCaptureError(msg)
        return fixtures

    monkeypatch.setattr(baseline_replay, "capture_behavior_matrix", controlled_capture)

    if result_kind == "failure":
        with pytest.raises(SystemExit) as raised:
            _ = baseline_replay.main(["--internal-output", str(output)])
        assert raised.value.code == EXPECTED_CLI_ERROR_EXIT
        assert "controlled capture failure" in capsys.readouterr().err
        assert not output.exists()
    else:
        assert baseline_replay.main(["--internal-output", str(output)]) == 0
        assert output.read_bytes() == canonical_test_bytes(fixtures)
        assert stat.S_IMODE(output.stat().st_mode) == REVIEWED_SOURCE_FILE_MODE
    assert logging.root.manager.disable == before_disable


@pytest.mark.parametrize(
    "field",
    ["expected", "status", "setup", "profile", "scenario", "header", "request"],
)
async def test_replay_verifier_rejects_redigested_semantic_mutations(
    tmp_path: Path,
    field: str,
) -> None:
    capture_root = tmp_path / "capture"
    capture_root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    original = await baseline_replay.capture_behavior_matrix(capture_root)
    fixtures: BaselineFixtures = {
        name: clone_test_object(
            require_test_object(fixture, context=f"{name} fixture"),
        )
        for name, fixture in original.items()
    }
    record = require_test_object(
        fixtures["result-cases.json"]["protocol.tools-list.modern.success"],
        context="replay record",
    )
    if field == "expected":
        expected = require_test_object(record["expected"], context="expected")
        payload = require_test_object(expected["payload"], context="payload")
        payload["forged"] = True
    elif field == "status":
        expected = require_test_object(record["expected"], context="expected")
        expected["status"] = 201
    elif field == "setup":
        record["setup"] = normative_setup("document")
    elif field == "profile":
        record["profile"] = "legacy"
    elif field == "scenario":
        record["scenario"] = "tool.success"
    elif field == "header":
        request = require_test_object(record["request"], context="request")
        headers = require_test_array(request["headers"], context="headers")
        next(
            header
            for value in headers
            if (header := require_test_object(value, context="header"))["name"]
            == "Mcp-Method"
        )["value"] = "server/discover"
    else:
        request = require_test_object(record["request"], context="request")
        encoded_body = request["body_base64"]
        assert isinstance(encoded_body, str)
        body = base64.b64decode(encoded_body, validate=True)
        payload = require_test_object(load_json_value(body), context="request body")
        payload["id"] = "forged.request"
        forged = canonical_request_bytes(payload)
        request["body_base64"] = base64.b64encode(forged).decode("ascii")
        request["body_sha256"] = hashlib.sha256(forged).hexdigest()
    fixture_raw = canonical_test_bytes(fixtures["result-cases.json"])
    recomputed_digest = hashlib.sha256(fixture_raw).hexdigest()
    assert (
        recomputed_digest
        != hashlib.sha256(
            canonical_test_bytes(original["result-cases.json"])
        ).hexdigest()
    )
    replay_root = tmp_path / "replay"
    replay_root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    with pytest.raises(capture_baseline.BaselineCaptureError):
        await baseline_replay.verify_replay_fixture_records(fixtures, replay_root)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["unknown", "missing", "cross-file-duplicate"])
async def test_replay_verifier_rejects_unknown_missing_or_duplicate_cases(
    tmp_path: Path,
    mutation: str,
) -> None:
    capture_root = tmp_path / "capture"
    capture_root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    fixtures = await baseline_replay.capture_behavior_matrix(capture_root)
    if mutation == "unknown":
        fixtures["result-cases.json"]["unknown.case"] = next(
            iter(fixtures["result-cases.json"].values())
        )
    elif mutation == "missing":
        _ = fixtures["result-cases.json"].pop("protocol.tools-list.modern.success")
    else:
        fixtures["error-cases.json"]["protocol.tools-list.modern.success"] = fixtures[
            "result-cases.json"
        ]["protocol.tools-list.modern.success"]
    replay_root = tmp_path / "replay"
    replay_root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    with pytest.raises(capture_baseline.BaselineCaptureError):
        await baseline_replay.verify_replay_fixture_records(fixtures, replay_root)


async def apply_normative_replay_setup(
    service: ToolService,
    setup_kind: ReplaySetupKind,
) -> None:
    """Apply setup from the independent oracle and verify exact reproduced IDs."""
    if setup_kind == "empty":
        return
    downloaded = await service.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )
    assert isinstance(downloaded, DownloadDocumentOutput)
    assert downloaded.artifact_id == FIXED_ARTIFACT_ID
    if setup_kind == "render":
        rendered = await service.call(
            "render_pdf_pages",
            {
                "artifact_id": FIXED_ARTIFACT_ID,
                "pages": [1],
                "mode": "native",
            },
        )
        assert isinstance(rendered, RenderPagesOutput)
        assert rendered.render_id == FIXED_RENDER_ID


def _assert_tool_outcome(case: NormativeReplayCase, payload: JsonObject) -> None:
    result = require_test_object(payload.get("result"), context="tool result")
    assert result.get("isError") is (case.outcome != "tool-success")
    structured = require_test_object(
        result.get("structuredContent"),
        context="structured tool result",
    )
    if case.outcome == "strict-error":
        assert structured.get("code") == "INVALID_INPUT"
    elif case.outcome == "app-error":
        assert structured.get("code") == "UPSTREAM_FAILURE"


def _assert_resource_outcome(case: NormativeReplayCase, payload: JsonObject) -> None:
    result = require_test_object(payload.get("result"), context="resource result")
    if case.outcome == "resource-list":
        resources = require_test_array(result.get("resources"), context="resources")
        assert len(resources) == 1
        resource = require_test_object(resources[0], context="resource")
        assert resource.get("uri") == "nplg://about"
        return
    contents = require_test_array(result.get("contents"), context="contents")
    assert len(contents) == 1
    content = require_test_object(contents[0], context="resource content")
    if "read-about" in case.case_id:
        assert content.get("uri") == "nplg://about"
    elif "read-artifact" in case.case_id:
        assert content.get("uri") == f"nplg://artifact/{FIXED_ARTIFACT_ID}"
    else:
        assert content.get("uri") == f"nplg://render/{FIXED_RENDER_ID}/manifest"


def _assert_error_outcome(case: NormativeReplayCase, payload: JsonObject) -> None:
    error = require_test_object(payload.get("error"), context="protocol error")
    if case.outcome == "generic-error":
        assert error == {"code": -32603, "message": "Internal error"}
        return
    assert error.get("code") == (-32601 if "method-unknown" in case.case_id else -32020)


def assert_normative_replay_outcome(
    case: NormativeReplayCase,
    *,
    status: int,
    payload: object,
) -> None:
    """Check semantic status/outcome without consulting captured expected data."""
    assert status == case.status
    payload_object = require_test_object(payload, context="protocol payload")
    assert payload_object.get("id") == case.case_id
    serialized = json.dumps(payload_object, ensure_ascii=False, sort_keys=True)
    assert FIXTURE_ERROR_CANARY not in serialized
    if case.outcome in {"tool-success", "strict-error", "app-error"}:
        _assert_tool_outcome(case, payload_object)
    elif case.outcome in {"resource-list", "resource-read"}:
        _assert_resource_outcome(case, payload_object)
    elif case.outcome in {"generic-error", "protocol-error"}:
        _assert_error_outcome(case, payload_object)
    else:
        _ = require_test_object(
            payload_object.get("result"),
            context="protocol result",
        )
    if case.profile == "modern" and case.outcome not in {
        "generic-error",
        "protocol-error",
    }:
        result = require_test_object(payload_object.get("result"), context="result")
        assert result.get("resultType") == "complete"


@pytest.mark.parametrize(
    "case",
    normative_replay_cases(),
    ids=_normative_case_id,
)
def test_frozen_case_matches_digest_bound_independent_oracle(
    case: NormativeReplayCase,
) -> None:
    fixture = load_fixture_index(case.fixture)
    assert case.case_id in fixture
    raw_record = fixture[case.case_id]
    record = baseline_replay.ReplayRecord.model_validate_json(
        canonical_test_bytes(raw_record), strict=True
    )
    assert record.profile == case.profile
    assert record.scenario == case.scenario
    serialized_setup = load_json_value(record.setup.model_dump_json())
    assert serialized_setup == normative_setup(case.setup_kind)
    assert record.request.body_bytes() == case.request_body
    assert (
        tuple((header.name, header.value) for header in record.request.headers)
        == case.headers
    )
    assert record.expected.status == case.status

    normalized_payload = baseline_replay.normalize_response_numbers(
        record.expected.payload
    )
    assert_normative_replay_outcome(
        case,
        status=record.expected.status,
        payload=normalized_payload,
    )
    assert canonical_test_bytes(normalized_payload) == canonical_test_bytes(
        record.expected.payload,
    )


def test_response_semantic_number_normalization_is_versioned_and_closed() -> None:
    value = {
        "boolean": True,
        "negative_zero": -0.0,
        "nested": [1.0, {"safe": 9_007_199_254_740_991.0}],
    }
    assert baseline_replay.normalize_response_numbers(value) == {
        "boolean": True,
        "negative_zero": 0,
        "nested": [1, {"safe": 9_007_199_254_740_991}],
    }
    assert (
        capture_baseline.RESPONSE_NUMBER_CANONICALIZATION
        == "nplg-response-semantic-numbers-v1"
    )
    for invalid in (
        0.5,
        math.nan,
        math.inf,
        -math.inf,
        9_007_199_254_740_992.0,
        -9_007_199_254_740_992.0,
    ):
        with pytest.raises(capture_baseline.BaselineCaptureError):
            _ = baseline_replay.normalize_response_numbers({"invalid": invalid})


def test_replay_models_are_strict_frozen_bounded_and_digest_bound() -> None:
    body = b'{"id":1,"jsonrpc":"2.0","method":"tools/list","params":{}}'
    value: JsonObject = {
        "profile": "legacy",
        "scenario": "protocol.tools-list",
        "setup": {"kind": "empty"},
        "request": {
            "body_base64": base64.b64encode(body).decode("ascii"),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "headers": [{"name": "MCP-Protocol-Version", "value": "2025-11-25"}],
        },
        "expected": {
            "status": 200,
            "payload": {"id": 1, "jsonrpc": "2.0", "result": {"tools": []}},
        },
    }
    record = baseline_replay.ReplayRecord.model_validate_json(
        canonical_test_bytes(value), strict=True
    )
    assert record.profile == "legacy"
    mutable_record = cast("MutableReplayRecord", record)
    with pytest.raises(ValidationError):
        mutable_record.profile = "modern"

    for path in ("record", "setup", "request", "header", "expected"):
        mutated = clone_test_object(value)
        request = require_test_object(mutated["request"], context="request")
        if path == "record":
            target = mutated
        elif path == "setup":
            target = require_test_object(mutated["setup"], context="setup")
        elif path == "request":
            target = request
        elif path == "header":
            headers = require_test_array(request["headers"], context="headers")
            target = require_test_object(headers[0], context="header")
        else:
            target = require_test_object(mutated["expected"], context="expected")
        target["unexpected"] = True
        with pytest.raises(ValidationError):
            _ = baseline_replay.ReplayRecord.model_validate_json(
                canonical_test_bytes(mutated), strict=True
            )

    wrong_digest = clone_test_object(value)
    wrong_request = require_test_object(wrong_digest["request"], context="request")
    wrong_request["body_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        _ = baseline_replay.ReplayRecord.model_validate_json(
            canonical_test_bytes(wrong_digest), strict=True
        )

    coerced_status = clone_test_object(value)
    coerced_expected = require_test_object(
        coerced_status["expected"],
        context="expected",
    )
    coerced_expected["status"] = True
    with pytest.raises(ValidationError):
        _ = baseline_replay.ReplayRecord.model_validate_json(
            canonical_test_bytes(coerced_status), strict=True
        )


def test_replay_models_reject_canonicalization_and_payload_boundary_faults() -> None:
    raw = b"\0"
    digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValidationError, match="bounded canonical Base64"):
        _ = baseline_replay.ReplayRequest(
            body_base64="AB==",
            body_sha256=digest,
            headers=(),
        )

    duplicate_headers = (
        baseline_replay.ReplayHeader(name="Mcp-Method", value="tools/list"),
        baseline_replay.ReplayHeader(name="mcp-method", value="tools/call"),
    )
    with pytest.raises(ValidationError, match="case-insensitively unique"):
        _ = baseline_replay.ReplayRequest(
            body_base64=base64.b64encode(raw).decode("ascii"),
            body_sha256=digest,
            headers=duplicate_headers,
        )

    assert baseline_replay.ReplayExpected(status=204, payload=None).payload is None
    too_deep: object = None
    for _ in range(baseline_capture_io.MAX_CANONICAL_JSON_DEPTH + 2):
        too_deep = [too_deep]
    invalid_payloads: tuple[object, ...] = (
        {"too_deep": too_deep},
        {"non_json": object()},
        {1: "non-string-key"},
        {"oversized": "x" * baseline_capture_io.MAX_CANONICAL_JSON_BYTES},
    )
    for payload in invalid_payloads:
        candidate: dict[str, object] = {"status": 200, "payload": payload}
        with pytest.raises(ValidationError):
            _ = baseline_replay.ReplayExpected.model_validate(
                candidate,
                strict=True,
            )

    for value in (
        baseline_replay.MAX_JAVASCRIPT_SAFE_INTEGER + 1,
        {1: "non-string-key"},
        object(),
    ):
        with pytest.raises(capture_baseline.BaselineCaptureError):
            _ = baseline_replay.normalize_response_numbers(value)


def test_modern_replay_record_requires_the_complete_modern_header_family() -> None:
    raw = b'{"id":1,"jsonrpc":"2.0","method":"tools/list","params":{}}'
    request = baseline_replay.ReplayRequest(
        body_base64=base64.b64encode(raw).decode("ascii"),
        body_sha256=hashlib.sha256(raw).hexdigest(),
        headers=(),
    )

    with pytest.raises(ValidationError, match="exact modern MCP headers"):
        _ = baseline_replay.ReplayRecord(
            profile="modern",
            scenario="protocol.tools-list",
            setup=baseline_replay.EmptyReplaySetup(kind="empty"),
            request=request,
            expected=baseline_replay.ReplayExpected(status=200, payload=None),
        )


@pytest.mark.parametrize("entrypoint", ["python", "json"])
@pytest.mark.parametrize(
    "invalid_number",
    [
        300_000.0,
        -0.0,
        0.5,
        math.nan,
        math.inf,
        -math.inf,
        9_007_199_254_740_992,
        -9_007_199_254_740_992,
        9_007_199_254_740_992.0,
        -9_007_199_254_740_992.0,
    ],
)
def test_replay_record_rejects_non_normalized_numbers_at_every_payload_depth(
    entrypoint: str,
    invalid_number: float,
) -> None:
    original = require_test_object(
        load_fixture_index("result-cases.json")["protocol.tools-list.legacy.success"],
        context="replay record",
    )
    payloads: tuple[JsonObject, ...] = (
        {"value": invalid_number},
        {"items": [invalid_number]},
        {"outer": [{"inner": invalid_number}]},
    )
    for payload in payloads:
        record: dict[str, object] = dict(clone_test_object(original))
        request: dict[str, object] = dict(
            require_test_object(record["request"], context="request"),
        )
        request["headers"] = tuple(
            require_test_array(request["headers"], context="headers"),
        )
        record["request"] = request
        expected = dict(
            require_test_object(record["expected"], context="expected"),
        )
        expected["payload"] = payload
        record["expected"] = expected
        expected_errors = (ValidationError, capture_baseline.BaselineCaptureError)
        if entrypoint == "python":
            with pytest.raises(expected_errors):
                _ = baseline_replay.ReplayRecord.model_validate(record, strict=True)
            continue
        if not math.isfinite(invalid_number):
            raw = (
                json.dumps(
                    record,
                    allow_nan=True,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            if math.isnan(invalid_number):
                token = b"NaN"
            elif invalid_number > 0:
                token = b"Infinity"
            else:
                token = b"-Infinity"
            assert raw.count(token) == 1
        else:
            raw = canonical_test_bytes(record)
        with pytest.raises(expected_errors):
            _ = baseline_replay.ReplayRecord.model_validate_json(raw, strict=True)


@pytest.mark.parametrize("entrypoint", ["python", "json"])
def test_replay_record_preserves_boolean_and_integer_types_without_coercion(
    entrypoint: str,
) -> None:
    original = require_test_object(
        load_fixture_index("result-cases.json")["protocol.tools-list.legacy.success"],
        context="replay record",
    )
    value: dict[str, object] = dict(clone_test_object(original))
    request: dict[str, object] = dict(
        require_test_object(value["request"], context="request"),
    )
    request["headers"] = tuple(
        require_test_array(request["headers"], context="headers"),
    )
    value["request"] = request
    expected = dict(require_test_object(value["expected"], context="expected"))
    expected["payload"] = {"nested": [{"boolean": True, "integer": 1}]}
    value["expected"] = expected

    if entrypoint == "python":
        record = baseline_replay.ReplayRecord.model_validate(value, strict=True)
    else:
        record = baseline_replay.ReplayRecord.model_validate_json(
            canonical_test_bytes(value),
            strict=True,
        )
    assert record.expected.payload is not None
    nested = cast("list[object]", record.expected.payload["nested"])
    leaf = cast("dict[str, object]", nested[0])
    assert type(leaf["boolean"]) is bool
    assert type(leaf["integer"]) is int


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "integral-float",
        "negative-zero",
        "bool-for-int",
        "int-for-bool",
        "fractional",
        "nonfinite",
        "out-of-range",
    ],
)
async def test_public_replay_verifier_rejects_numeric_representation_mutations(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixtures: BaselineFixtures = {
        name: load_fixture_index(name) for name in BASELINE_FILE_NAMES
    }
    record = require_test_object(
        fixtures["result-cases.json"]["protocol.tools-list.legacy.success"],
        context="replay record",
    )
    expected = require_test_object(record["expected"], context="expected")
    payload = require_test_object(expected["payload"], context="payload")
    result = require_test_object(payload["result"], context="result")
    tools = require_test_array(result["tools"], context="tools")
    tool = require_test_object(tools[5], context="tool")
    input_schema = require_test_object(tool["inputSchema"], context="input schema")
    properties = require_test_object(
        input_schema["properties"],
        context="properties",
    )
    overlap = require_test_object(properties["overlap"], context="overlap")
    any_of = require_test_array(overlap["anyOf"], context="anyOf")
    integer_schema = require_test_object(any_of[0], context="integer schema")
    before = (
        json.dumps(
            fixtures["result-cases.json"],
            allow_nan=True,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if mutation == "integral-float":
        integer_schema["minimum"] = 0.0
    elif mutation == "negative-zero":
        integer_schema["minimum"] = -0.0
    elif mutation == "bool-for-int":
        integer_schema["minimum"] = False
    elif mutation == "int-for-bool":
        input_schema["additionalProperties"] = 0
    elif mutation == "fractional":
        integer_schema["minimum"] = 0.5
    elif mutation == "nonfinite":
        integer_schema["minimum"] = math.nan
    else:
        integer_schema["minimum"] = 9_007_199_254_740_992
    after = (
        json.dumps(
            fixtures["result-cases.json"],
            allow_nan=True,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    assert hashlib.sha256(after).digest() != hashlib.sha256(before).digest()

    replay_root = tmp_path / "replay"
    replay_root.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    with pytest.raises(capture_baseline.BaselineCaptureError):
        await baseline_replay.verify_replay_fixture_records(fixtures, replay_root)


def test_every_frozen_case_contains_an_executable_replay_record() -> None:
    paths: tuple[ReplayFixtureName, ...] = (
        "resources.json",
        "result-cases.json",
        "error-cases.json",
    )
    for path in paths:
        fixture = load_fixture_index(path)
        for case_id, value in fixture.items():
            record = require_test_object(value, context=case_id)
            assert set(record) == {
                "profile",
                "scenario",
                "setup",
                "request",
                "expected",
            }, case_id
            _ = baseline_replay.ReplayRecord.model_validate_json(
                canonical_test_bytes(record), strict=True
            )


@pytest.mark.live
def test_capture_check_mode_fails_closed_until_attestation_without_rewriting() -> None:
    before = {
        path.name: (path.stat().st_mtime_ns, path.read_bytes())
        for path in sorted(BASELINE_DIR.glob("*.json"))
    }
    result = subprocess.run(
        [sys.executable, "scripts/capture_baseline.py", "--check"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    after = {
        path.name: (path.stat().st_mtime_ns, path.read_bytes())
        for path in sorted(BASELINE_DIR.glob("*.json"))
    }
    assert result.returncode == capture_baseline.BASELINE_FAILURE_STATUS
    assert result.stdout == ""
    assert result.stderr == (
        "baseline capture failed: committed baseline attestation required\n"
    )
    assert after == before


def test_capture_exposes_a_strict_bounded_canonical_loader(tmp_path: Path) -> None:
    path = tmp_path / "fixture.json"
    _ = path.write_text('{"value":1}\n', encoding="utf-8")
    assert capture_baseline.load_canonical_json(path) == {"value": 1}


@pytest.mark.parametrize(
    "raw",
    [
        b'{"outer":{"value":1,"value":2}}\n',
        b'\xef\xbb\xbf{"value":1}\n',
        b'{"value": 1}\n',
        b'{"z":0,"a":1}\n',
        b'{"value":NaN}\n',
        b'{"value":Infinity}\n',
        b'{"value":1.5}\n',
        b'{"value":9223372036854775808}\n',
        (b"[" * 65) + b"0" + (b"]" * 65) + b"\n",
    ],
)
def test_canonical_loader_rejects_ambiguous_or_unbounded_json(
    tmp_path: Path,
    raw: bytes,
) -> None:
    path = tmp_path / "fixture.json"
    _ = path.write_bytes(raw)
    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.load_canonical_json(path)


def test_canonical_loader_rejects_oversized_input(tmp_path: Path) -> None:
    path = tmp_path / "fixture.json"
    _ = path.write_bytes(b'{"value":1}\n')
    with pytest.raises(capture_baseline.BaselineCaptureError, match="exceeds"):
        _ = capture_baseline.load_canonical_json(path, max_bytes=4)


def test_canonical_loader_rejects_symlink_and_special_file(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    _ = target.write_bytes(b'{"value":1}\n')
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(target)
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)

    for path in (symlink, fifo):
        with pytest.raises(capture_baseline.BaselineCaptureError, match="regular"):
            _ = capture_baseline.load_canonical_json(path)


def test_canonical_loader_rejects_invalid_configuration_and_encoding(
    tmp_path: Path,
) -> None:
    path = tmp_path / "fixture.json"
    _ = path.write_bytes(b"\xff\n")

    with pytest.raises(ValueError, match="max_bytes must be positive"):
        _ = capture_baseline.load_canonical_json(path, max_bytes=0)
    with pytest.raises(
        capture_baseline.BaselineCaptureError, match="invalid canonical"
    ):
        _ = capture_baseline.load_canonical_json(path)


@pytest.mark.parametrize("value", [[], {1: "value"}])
def test_string_object_boundary_rejects_nonobject_or_nonstring_keys(
    value: object,
) -> None:
    with pytest.raises(capture_baseline.BaselineCaptureError, match="fixture"):
        _ = baseline_capture_io.require_string_object(value, context="fixture")


def test_baseline_directory_loader_accepts_only_closed_manifest_v3(
    tmp_path: Path,
) -> None:
    baseline_dir = tmp_path / "baseline"
    _ = write_valid_infrastructure_fixture(baseline_dir)

    manifest = capture_baseline.validate_baseline_directory(baseline_dir)

    assert manifest.schema_version == EXPECTED_SCHEMA_VERSION
    assert manifest.capture_mode == "synthetic-index-staged-recovery"
    assert manifest.input.git_object_format == "sha1"
    assert manifest.input.excluded_output_paths == tuple(
        f"contracts/baseline/{name}" for name in (*BASELINE_FILE_NAMES, "manifest.json")
    )
    assert manifest.input.included_untracked_paths == INCLUDED_UNTRACKED_PATHS


def test_baseline_directory_rejects_a_nondirectory_root(tmp_path: Path) -> None:
    root = tmp_path / "baseline"
    _ = root.write_bytes(b"not-a-directory")

    with pytest.raises(
        capture_baseline.BaselineCaptureError, match="must be a directory"
    ):
        _ = capture_baseline.validate_baseline_directory(root)


def test_capture_policy_accepts_only_the_exact_reviewed_untracked_paths() -> None:
    values = capture_policy_values(baseline_capture_io.DEFAULT_CAPTURE_POLICY)

    policy = baseline_capture_io.CapturePolicy.model_validate(values, strict=True)

    assert policy.included_untracked_paths == INCLUDED_UNTRACKED_PATHS
    invalid_values: tuple[tuple[str, ...], ...] = (
        (),
        ("contracts/zod/baseline-contracts.mjs",),
        tuple(reversed(INCLUDED_UNTRACKED_PATHS)),
        (INCLUDED_UNTRACKED_PATHS[0], INCLUDED_UNTRACKED_PATHS[0]),
        (*INCLUDED_UNTRACKED_PATHS, "unrelated.txt"),
    )
    for included_paths in invalid_values:
        invalid_policy: dict[str, object] = dict(values)
        invalid_policy["included_untracked_paths"] = included_paths
        with pytest.raises(ValidationError):
            _ = baseline_capture_io.CapturePolicy.model_validate(
                invalid_policy,
                strict=True,
            )


@pytest.mark.parametrize(
    "included_paths",
    [
        [],
        [INCLUDED_UNTRACKED_PATHS[0]],
        list(reversed(INCLUDED_UNTRACKED_PATHS)),
        [INCLUDED_UNTRACKED_PATHS[0], INCLUDED_UNTRACKED_PATHS[0]],
        [*INCLUDED_UNTRACKED_PATHS, "unrelated.txt"],
    ],
)
def test_baseline_manifest_rejects_nonexact_reviewed_untracked_paths(
    tmp_path: Path,
    included_paths: list[str],
) -> None:
    baseline_dir = tmp_path / "baseline"
    manifest = write_valid_infrastructure_fixture(baseline_dir)
    input_identity = cast("dict[str, object]", manifest["input"])
    input_identity["included_untracked_paths"] = included_paths
    _ = (baseline_dir / "manifest.json").write_bytes(canonical_test_bytes(manifest))

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.validate_baseline_directory(baseline_dir)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "unknown", "coerced-version", "traversal", "duplicate-entry"],
)
def test_baseline_directory_loader_rejects_malformed_manifest(
    tmp_path: Path,
    mutation: str,
) -> None:
    baseline_dir = tmp_path / "baseline"
    manifest = write_valid_infrastructure_fixture(baseline_dir)
    if mutation == "missing":
        del manifest["generator"]
    elif mutation == "unknown":
        manifest["unexpected"] = True
    elif mutation == "coerced-version":
        manifest["schema_version"] = "3"
    else:
        raw_entries = manifest["entries"]
        assert isinstance(raw_entries, list)
        entries = cast("list[dict[str, str]]", raw_entries)
        if mutation == "traversal":
            entries[0]["path"] = "../tool-catalog.json"
        else:
            entries[1]["path"] = entries[0]["path"]
    _ = (baseline_dir / "manifest.json").write_bytes(canonical_test_bytes(manifest))

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.validate_baseline_directory(baseline_dir)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "malformed", "recovery-mismatch"],
)
def test_baseline_manifest_rejects_invalid_index_transition(
    tmp_path: Path,
    mutation: str,
) -> None:
    baseline_dir = tmp_path / "baseline"
    manifest = write_valid_infrastructure_fixture(baseline_dir)
    transition = cast("dict[str, object]", manifest["index_transition"])
    if mutation == "missing":
        del transition["candidate_index_tree"]
    elif mutation == "extra":
        transition["unexpected"] = True
    elif mutation == "malformed":
        transition["candidate_staged_entries_sha256"] = "not-a-digest"
    else:
        recovery = cast("dict[str, object]", manifest["recovery"])
        recovery["imported_index_tree"] = "0" * 40
    _ = (baseline_dir / "manifest.json").write_bytes(canonical_test_bytes(manifest))

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.validate_baseline_directory(baseline_dir)


@pytest.mark.parametrize(
    "mutation",
    ["object-format", "missing-exclusion", "duplicate-exclusion", "traversal"],
)
def test_baseline_manifest_rejects_ambiguous_input_inventory(
    tmp_path: Path,
    mutation: str,
) -> None:
    baseline_dir = tmp_path / "baseline"
    manifest = write_valid_infrastructure_fixture(baseline_dir)
    input_identity = cast("dict[str, object]", manifest["input"])
    exclusions = cast("list[str]", input_identity["excluded_output_paths"])
    if mutation == "object-format":
        input_identity["git_object_format"] = "sha256"
    elif mutation == "missing-exclusion":
        _ = exclusions.pop()
    elif mutation == "duplicate-exclusion":
        exclusions[-1] = exclusions[0]
    else:
        exclusions[-1] = "contracts/baseline/../manifest.json"
    _ = (baseline_dir / "manifest.json").write_bytes(canonical_test_bytes(manifest))

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.validate_baseline_directory(baseline_dir)


def test_baseline_manifest_rejects_case_id_reused_across_fixture_files(
    tmp_path: Path,
) -> None:
    baseline_dir = tmp_path / "baseline"
    manifest = write_valid_infrastructure_fixture(baseline_dir)
    resources: JsonObject = {"case.one": {}}
    resources_raw = canonical_test_bytes(resources)
    _ = (baseline_dir / "resources.json").write_bytes(resources_raw)
    entries = cast("list[dict[str, str]]", manifest["entries"])
    for entry in entries:
        if entry["path"] == "resources.json":
            entry["sha256"] = hashlib.sha256(resources_raw).hexdigest()
    manifest["required_case_ids"] = ["case.one", "error.one"]
    _ = (baseline_dir / "manifest.json").write_bytes(canonical_test_bytes(manifest))

    with pytest.raises(
        capture_baseline.BaselineCaptureError, match="duplicate case ID"
    ):
        _ = capture_baseline.validate_baseline_directory(baseline_dir)


@pytest.mark.parametrize(
    "mutation",
    [
        "tree-drift",
        "required-tools",
        "unsorted-case-ids",
        "tool-catalog",
        "case-inventory",
        "fixture-digest",
    ],
)
def test_baseline_directory_rejects_semantic_manifest_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    baseline_dir = tmp_path / "baseline"
    manifest = write_valid_infrastructure_fixture(baseline_dir)
    if mutation == "tree-drift":
        input_identity = cast("dict[str, object]", manifest["input"])
        input_identity["tree_after"] = "6" * 40
    elif mutation == "required-tools":
        required_tools = cast("list[str]", manifest["required_tool_names"])
        required_tools[-1] = "unknown_tool"
        required_tools.sort()
    elif mutation == "unsorted-case-ids":
        required_case_ids = cast("list[str]", manifest["required_case_ids"])
        required_case_ids.reverse()
    elif mutation == "tool-catalog":
        catalog: JsonObject = {
            **{
                name: {}
                for name in sorted(EXPECTED_TOOL_NAMES)
                if name != "search_documents"
            },
            "unknown_tool": {},
        }
        raw = canonical_test_bytes(catalog)
        _ = (baseline_dir / "tool-catalog.json").write_bytes(raw)
        entries = cast("list[dict[str, str]]", manifest["entries"])
        next(entry for entry in entries if entry["path"] == "tool-catalog.json")[
            "sha256"
        ] = hashlib.sha256(raw).hexdigest()
    elif mutation == "case-inventory":
        manifest["required_case_ids"] = ["case.one", "error.one"]
    else:
        _ = (baseline_dir / "resources.json").write_bytes(
            canonical_test_bytes({"resource.one": {"changed": True}}),
        )
    _ = (baseline_dir / "manifest.json").write_bytes(canonical_test_bytes(manifest))

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.validate_baseline_directory(baseline_dir)


@pytest.mark.parametrize("mutation", ["extra", "missing", "symlink"])
def test_baseline_directory_loader_rejects_unclosed_file_inventory(
    tmp_path: Path,
    mutation: str,
) -> None:
    baseline_dir = tmp_path / "baseline"
    _ = write_valid_infrastructure_fixture(baseline_dir)
    if mutation == "extra":
        _ = (baseline_dir / "unexpected.json").write_bytes(b"{}\n")
    elif mutation == "missing":
        (baseline_dir / "resources.json").unlink()
    else:
        target = tmp_path / "replacement.json"
        _ = target.write_bytes(b"{}\n")
        path = baseline_dir / "resources.json"
        path.unlink()
        path.symlink_to(target)

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.validate_baseline_directory(baseline_dir)


def test_synthetic_input_is_exact_materialized_and_check_uses_ephemeral_objects(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    generator = repository / "scripts" / "capture_baseline.py"
    _ = generator.write_text("print('working-tree')\n", encoding="utf-8")
    _ = (repository / "contracts" / "baseline" / "result-cases.json").write_bytes(
        b'{"stale":true}\n',
    )
    object_inventory_before = git_object_inventory(repository)
    index_tree_before = run_test_git(repository, "write-tree")

    with baseline_capture_io.materialize_synthetic_input(
        repository,
        policy=policy,
        persist_objects=False,
    ) as snapshot:
        assert snapshot.root.is_absolute()
        assert snapshot.root.stat().st_mode & 0o777 == PRIVATE_DIRECTORY_MODE
        assert (snapshot.root / "scripts" / "capture_baseline.py").read_bytes() == (
            generator.read_bytes()
        )
        assert not (snapshot.root / "contracts" / "baseline").exists()
        assert snapshot.identity.tree_before == snapshot.identity.tree_after
        assert (
            snapshot.generator.sha256
            == hashlib.sha256(generator.read_bytes()).hexdigest()
        )

    assert run_test_git(repository, "write-tree") == index_tree_before
    assert git_object_inventory(repository) == object_inventory_before


@pytest.mark.parametrize(
    "fault",
    ["missing-git", "linked-git", "malformed-head", "unsafe-ref", "head-mismatch"],
)
def test_synthetic_input_rejects_untrusted_git_metadata_shapes(
    tmp_path: Path,
    fault: str,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    dot_git = repository / ".git"
    if fault == "missing-git":
        _ = dot_git.rename(tmp_path / "detached-git")
    elif fault == "linked-git":
        moved = dot_git.rename(tmp_path / "linked-git")
        dot_git.symlink_to(moved, target_is_directory=True)
    elif fault == "malformed-head":
        _ = (dot_git / "HEAD").write_bytes(b"not-an-object-id\n")
    elif fault == "unsafe-ref":
        _ = (dot_git / "HEAD").write_bytes(b"ref: refs/heads/../unsafe\n")
    else:
        _ = (dot_git / "HEAD").write_bytes(b"0" * 40 + b"\n")

    with (
        pytest.raises(capture_baseline.BaselineCaptureError),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("untrusted Git metadata reached materialization")


@pytest.mark.parametrize("head_mode", ["detached", "packed-ref"])
def test_synthetic_input_accepts_equivalent_detached_or_packed_head_metadata(
    tmp_path: Path,
    head_mode: str,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    if head_mode == "detached":
        _ = (repository / ".git" / "HEAD").write_text(
            f"{policy.base_commit}\n",
            encoding="ascii",
        )
    else:
        run_test_git_no_output(repository, "pack-refs", "--all", "--prune")

    with baseline_capture_io.materialize_synthetic_input(
        repository,
        policy=policy,
        persist_objects=False,
    ) as snapshot:
        assert snapshot.identity.tree_before == snapshot.identity.tree_after
        assert (snapshot.root / INCLUDED_UNTRACKED_PATHS[0]).is_file()


def test_synthetic_input_rejects_malformed_packed_head_metadata(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    run_test_git_no_output(repository, "pack-refs", "--all", "--prune")
    _ = (repository / ".git" / "packed-refs").write_bytes(b"malformed\n")

    with (
        pytest.raises(capture_baseline.BaselineCaptureError),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("malformed packed refs reached materialization")


def test_synthetic_input_rejects_a_valid_object_with_the_wrong_required_type(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    identity["audit_tree"] = identity["audit_commit"]
    policy = capture_baseline.CapturePolicy(**identity)

    with (
        pytest.raises(capture_baseline.BaselineCaptureError, match="type mismatch"),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("wrong Git object type reached materialization")


def test_synthetic_tree_includes_only_the_exact_reviewed_untracked_inputs(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    _ = (repository / "unrelated-untracked.txt").write_bytes(b"unrelated\n")
    _ = (repository / "ignored-untracked.txt").write_bytes(b"ignored\n")
    index_path = Path(run_test_git(repository, "rev-parse", "--git-path", "index"))
    if not index_path.is_absolute():
        index_path = repository / index_path
    index_before = index_path.read_bytes()

    with baseline_capture_io.materialize_synthetic_input(
        repository,
        policy=policy,
        persist_objects=True,
    ) as snapshot:
        tree = snapshot.identity.tree_before
        assert snapshot.identity.included_untracked_paths == INCLUDED_UNTRACKED_PATHS
        for relative_path, expected_bytes in INCLUDED_UNTRACKED_BYTES.items():
            materialized = snapshot.root / relative_path
            assert materialized.read_bytes() == expected_bytes
            assert (
                stat.S_IMODE(materialized.stat().st_mode) == REVIEWED_SOURCE_FILE_MODE
            )
        assert not (snapshot.root / "unrelated-untracked.txt").exists()
        assert not (snapshot.root / "ignored-untracked.txt").exists()

    inventory: dict[str, tuple[str, str, int]] = {}
    for line in run_test_git(repository, "ls-tree", "-r", "--long", tree).splitlines():
        metadata, relative_path = line.split("\t", maxsplit=1)
        mode, object_type, object_id, size = metadata.split()
        inventory[relative_path] = (mode, object_id, int(size))
        assert object_type == "blob"
    for relative_path, expected_bytes in INCLUDED_UNTRACKED_BYTES.items():
        assert inventory[relative_path] == (
            "100644",
            git_blob_object_id(expected_bytes),
            len(expected_bytes),
        )
    assert "unrelated-untracked.txt" not in inventory
    assert "ignored-untracked.txt" not in inventory
    assert not any(path.startswith("contracts/baseline/") for path in inventory)
    assert index_path.read_bytes() == index_before


def test_synthetic_tree_uses_only_literal_reviewed_git_add_pathspecs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    observed_adds: list[tuple[str, ...]] = []
    git_no_output = baseline_capture_io.git_no_output

    def observe_git_add(
        root: Path,
        *arguments: str,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if arguments and arguments[0] == "add":
            observed_adds.append(arguments)
        git_no_output(root, *arguments, environment=environment)

    monkeypatch.setattr(baseline_capture_io, "git_no_output", observe_git_add)

    with baseline_capture_io.materialize_synthetic_input(
        repository,
        policy=policy,
        persist_objects=False,
    ):
        pass

    assert observed_adds
    assert set(observed_adds) == {
        ("add", "-u", "--", "."),
        ("add", "--", *INCLUDED_UNTRACKED_PATHS),
    }
    assert (
        observed_adds.count(("add", "--", *INCLUDED_UNTRACKED_PATHS))
        == EXPECTED_REVIEWED_ADD_CALLS
    )


@pytest.mark.parametrize(
    "mutation",
    ["missing", "symlink", "symlink-parent", "fifo", "hardlink", "oversize", "mode"],
)
def test_synthetic_tree_rejects_unsafe_reviewed_untracked_inputs_without_side_effects(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    target = repository / INCLUDED_UNTRACKED_PATHS[0]
    outside = tmp_path / "outside"
    if mutation == "missing":
        target.unlink()
    elif mutation == "symlink":
        _ = outside.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(outside)
    elif mutation == "symlink-parent":
        moved_parent = tmp_path / "outside-zod"
        _ = target.parent.rename(moved_parent)
        target.parent.symlink_to(moved_parent, target_is_directory=True)
    elif mutation == "fifo":
        target.unlink()
        os.mkfifo(target)
    elif mutation == "hardlink":
        _ = outside.write_bytes(target.read_bytes())
        target.unlink()
        os.link(outside, target)
    elif mutation == "oversize":
        _ = target.write_bytes(
            b"x" * (baseline_capture_io.MAX_MATERIALIZED_FILE_BYTES + 1),
        )
    else:
        target.chmod(0o600)
    baseline = baseline_bytes_from(repository / "contracts" / "baseline")
    objects_before = git_object_inventory(repository)
    index_path = Path(run_test_git(repository, "rev-parse", "--git-path", "index"))
    if not index_path.is_absolute():
        index_path = repository / index_path
    index_before = index_path.read_bytes()

    with (
        pytest.raises(capture_baseline.BaselineCaptureError),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("unsafe reviewed input reached materialization")

    assert baseline_bytes_from(repository / "contracts" / "baseline") == baseline
    assert git_object_inventory(repository) == objects_before
    assert index_path.read_bytes() == index_before


@pytest.mark.parametrize("mutation", ["content", "identical-replacement"])
def test_synthetic_tree_rejects_reviewed_untracked_input_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    target = repository / INCLUDED_UNTRACKED_PATHS[0]
    baseline = baseline_bytes_from(repository / "contracts" / "baseline")
    objects_before = git_object_inventory(repository)
    git_no_output = baseline_capture_io.git_no_output
    mutated = False

    def race_exact_add(
        root: Path,
        *arguments: str,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        nonlocal mutated
        if arguments == ("add", "--", *INCLUDED_UNTRACKED_PATHS) and not mutated:
            if mutation == "content":
                _ = target.write_bytes(b"raced content\n")
            else:
                replacement = target.with_name("replacement.mjs")
                _ = replacement.write_bytes(target.read_bytes())
                _ = replacement.replace(target)
            mutated = True
        git_no_output(root, *arguments, environment=environment)

    monkeypatch.setattr(baseline_capture_io, "git_no_output", race_exact_add)

    with (
        pytest.raises(
            capture_baseline.BaselineCaptureError,
            match=r"changed|reviewed",
        ),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("raced reviewed input reached materialization")

    assert mutated
    assert baseline_bytes_from(repository / "contracts" / "baseline") == baseline
    assert git_object_inventory(repository) == objects_before


@pytest.mark.parametrize("field", ["audit_tree", "base_tree"])
def test_synthetic_input_rejects_fixed_identity_drift_before_materialization(
    tmp_path: Path,
    field: IdentityTreeField,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    identity[field] = "0" * 40
    policy = capture_baseline.CapturePolicy(**identity)

    with (
        pytest.raises(capture_baseline.BaselineCaptureError),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("identity drift reached materialization")


@pytest.mark.parametrize(
    "field",
    ["candidate_index_tree", "candidate_staged_entries_sha256"],
)
def test_synthetic_input_rejects_candidate_index_identity_mismatch(
    tmp_path: Path,
    field: str,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    transition = identity["index_transition"]
    identity["index_transition"] = (
        replace_index_transition(transition, candidate_index_tree="0" * 40)
        if field == "candidate_index_tree"
        else replace_index_transition(
            transition,
            candidate_staged_entries_sha256="0" * 64,
        )
    )
    policy = capture_baseline.CapturePolicy(**identity)

    with (
        pytest.raises(capture_baseline.BaselineCaptureError, match="candidate"),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("candidate index mismatch reached materialization")


def test_synthetic_input_rejects_live_index_drift_from_reviewed_candidate(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    _ = (repository / "src" / "module.py").write_text("VALUE = 2\n", encoding="utf-8")
    run_test_git_no_output(repository, "add", "-u", "--", ".")

    with (
        pytest.raises(capture_baseline.BaselineCaptureError, match="candidate"),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("live candidate-index drift reached materialization")


def test_synthetic_input_rejects_imported_staged_entry_digest_mismatch(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    identity["index_transition"] = replace_index_transition(
        identity["index_transition"],
        imported_staged_entries_sha256="0" * 64,
    )
    policy = capture_baseline.CapturePolicy(**identity)

    with (
        pytest.raises(capture_baseline.BaselineCaptureError, match="imported"),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
        ),
    ):
        pytest.fail("imported staged-entry digest mismatch reached materialization")


def test_capture_rejects_before_after_tree_drift_without_touching_outputs(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    outputs = {
        path.name: path.read_bytes()
        for path in (repository / "contracts" / "baseline").iterdir()
    }

    def drifting_collector(_materialized_root: Path) -> BaselineFixtures:
        _ = (repository / "src" / "module.py").write_text(
            "VALUE = 2\n",
            encoding="utf-8",
        )
        return {name: {} for name in BASELINE_FILE_NAMES}

    with pytest.raises(capture_baseline.BaselineCaptureError, match="changed"):
        _ = baseline_capture_io.collect_from_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
            collector=drifting_collector,
        )

    assert {
        path.name: path.read_bytes()
        for path in (repository / "contracts" / "baseline").iterdir()
    } == outputs


@pytest.mark.parametrize(
    "relative_path",
    [
        "src/module.py",
        "tests/helpers/fixture_helper.py",
        "scripts/capture_baseline.py",
    ],
)
def test_capture_rejects_materialized_input_content_drift(
    tmp_path: Path,
    relative_path: str,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)

    def drifting_collector(materialized_root: Path) -> BaselineFixtures:
        _ = (materialized_root / relative_path).write_text(
            "VALUE = 999\n",
            encoding="utf-8",
        )
        return {name: {} for name in BASELINE_FILE_NAMES}

    with pytest.raises(capture_baseline.BaselineCaptureError, match="materialized"):
        _ = baseline_capture_io.collect_from_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
            collector=drifting_collector,
        )


@pytest.mark.parametrize(
    "mutation",
    ["symlink", "fifo", "hardlink", "identical-replacement", "extra-file", "mode"],
)
def test_capture_rejects_materialized_input_metadata_or_inventory_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)

    def drifting_collector(materialized_root: Path) -> BaselineFixtures:
        target = materialized_root / "src" / "module.py"
        original = target.read_bytes()
        outside = tmp_path / "outside.py"
        _ = outside.write_bytes(original)
        if mutation == "symlink":
            target.unlink()
            target.symlink_to(outside)
        elif mutation == "fifo":
            target.unlink()
            os.mkfifo(target)
        elif mutation == "hardlink":
            target.unlink()
            os.link(outside, target)
        elif mutation == "identical-replacement":
            _ = outside.replace(target)
        elif mutation == "extra-file":
            _ = (materialized_root / "src" / "unexpected.py").write_bytes(original)
        else:
            target.chmod(0o600)
        return {name: {} for name in BASELINE_FILE_NAMES}

    with pytest.raises(capture_baseline.BaselineCaptureError, match="materialized"):
        _ = baseline_capture_io.collect_from_synthetic_input(
            repository,
            policy=policy,
            persist_objects=False,
            collector=drifting_collector,
        )


def test_capture_does_not_execute_repository_local_clean_filter(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    sentinel = tmp_path / "clean-filter-executed"
    filter_program = tmp_path / "clean-filter"
    _ = filter_program.write_text(
        f"#!/bin/sh\n: > {sentinel}\ncat\n",
        encoding="utf-8",
    )
    filter_program.chmod(0o700)
    info_attributes = repository / ".git" / "info" / "attributes"
    _ = info_attributes.write_text("src/module.py filter=evil\n", encoding="utf-8")
    _ = run_test_git(repository, "config", "filter.evil.clean", str(filter_program))
    _ = run_test_git(repository, "config", "filter.evil.smudge", "cat")
    _ = run_test_git(repository, "config", "filter.evil.required", "true")
    _ = (repository / "src" / "module.py").write_text("VALUE = 2\n", encoding="utf-8")

    with baseline_capture_io.materialize_synthetic_input(
        repository,
        policy=policy,
        persist_objects=False,
    ):
        pass

    assert not sentinel.exists()


def test_bounded_child_timeout_is_reported_as_a_closed_error(tmp_path: Path) -> None:
    with pytest.raises(capture_baseline.BaselineCaptureError, match="timed out"):
        _ = baseline_capture_io.run_bounded_process(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            cwd=tmp_path,
            environment={},
            limits=baseline_capture_io.ProcessLimits(0.05, 128, 128),
        )


@pytest.mark.parametrize(
    "limits",
    [
        baseline_capture_io.ProcessLimits(0, 1, 1),
        baseline_capture_io.ProcessLimits(1, -1, 1),
        baseline_capture_io.ProcessLimits(1, 1, -1),
    ],
)
def test_bounded_child_rejects_invalid_limits_before_start(
    tmp_path: Path,
    limits: baseline_capture_io.ProcessLimits,
) -> None:
    with pytest.raises(ValueError, match="limits are invalid"):
        _ = baseline_capture_io.run_bounded_process(
            (sys.executable, "-c", "raise SystemExit(0)"),
            cwd=tmp_path,
            environment={},
            limits=limits,
        )


@pytest.mark.parametrize("command", [(), ("python",)])
def test_bounded_child_rejects_empty_or_relative_commands(
    tmp_path: Path,
    command: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="configuration is invalid"):
        _ = baseline_capture_io.run_bounded_process(
            command,
            cwd=tmp_path,
            environment={},
            limits=baseline_capture_io.ProcessLimits(1, 1, 1),
        )


def test_bounded_child_reports_an_absolute_executable_start_failure(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="could not be started",
    ):
        _ = baseline_capture_io.run_bounded_process(
            (str(tmp_path / "missing-executable"),),
            cwd=tmp_path,
            environment={},
            limits=baseline_capture_io.ProcessLimits(1, 1, 1),
        )


def test_bounded_child_uses_blocking_output_and_drains_to_eof(tmp_path: Path) -> None:
    payload_size = 64 * 1024
    child_code = (
        "import os,sys; "
        "assert os.get_blocking(sys.stdout.fileno()); "
        f"sys.stdout.buffer.write(b'x' * {payload_size}); "
        "sys.stdout.buffer.flush()"
    )

    result = baseline_capture_io.run_bounded_process(
        (sys.executable, "-c", child_code),
        cwd=tmp_path,
        environment={},
        limits=baseline_capture_io.ProcessLimits(2, payload_size, 128),
    )

    assert result.returncode == 0
    assert result.stdout == b"x" * payload_size
    assert result.stderr == b""


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_git_capture_rejects_oversized_output(
    tmp_path: Path,
    stream: str,
) -> None:
    limit = 128
    descriptor = "sys.stdout.buffer" if stream == "stdout" else "sys.stderr.buffer"

    with pytest.raises(capture_baseline.BaselineCaptureError, match="output limit"):
        _ = baseline_capture_io.run_bounded_process(
            (
                sys.executable,
                "-c",
                f"import sys; {descriptor}.write(b'x' * {limit + 1})",
            ),
            cwd=tmp_path,
            environment={},
            limits=baseline_capture_io.ProcessLimits(2, limit, limit),
        )


def test_bounded_child_timeout_kills_the_entire_process_group(tmp_path: Path) -> None:
    sentinel = tmp_path / "orphan-wrote-output"
    child_code = (
        "import pathlib,time; time.sleep(0.3); "
        f"pathlib.Path({str(sentinel)!r}).write_text('unsafe')"
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); time.sleep(5)"
    )

    with pytest.raises(capture_baseline.BaselineCaptureError, match="timed out"):
        _ = baseline_capture_io.run_bounded_process(
            (sys.executable, "-c", parent_code),
            cwd=tmp_path,
            environment={},
            limits=baseline_capture_io.ProcessLimits(0.05, 128, 128),
        )
    time.sleep(0.5)

    assert not sentinel.exists()


def run_leader_with_closed_stdio_descendant(
    tmp_path: Path,
    *,
    returncode: int,
    leader_output: bytes,
) -> tuple[baseline_capture_io.ChildResult, int]:
    descendant_pid_path = tmp_path / "descendant.pid"
    survivor_sentinel = tmp_path / "descendant-survived"
    descendant_code = (
        "import os,pathlib,time; "
        f"pathlib.Path({str(descendant_pid_path)!r}).write_text(str(os.getpid())); "
        "time.sleep(5); "
        f"pathlib.Path({str(survivor_sentinel)!r}).write_text('unsafe')"
    )
    leader_code = (
        "import pathlib,subprocess,sys,time; "
        f"pid_path=pathlib.Path({str(descendant_pid_path)!r}); "
        f"subprocess.Popen([sys.executable,'-c',{descendant_code!r}],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
        "stderr=subprocess.DEVNULL); "
        "deadline=time.monotonic()+2; "
        "\nwhile not pid_path.exists():\n"
        "  assert time.monotonic() < deadline\n"
        "  time.sleep(0.005)\n"
        f"sys.stdout.buffer.write({leader_output!r}); "
        f"raise SystemExit({returncode})"
    )
    result = baseline_capture_io.run_bounded_process(
        (sys.executable, "-c", leader_code),
        cwd=tmp_path,
        environment={},
        limits=baseline_capture_io.ProcessLimits(3, 128, 128),
    )
    return result, int(descendant_pid_path.read_text(encoding="ascii"))


def process_exists(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.mark.parametrize("leader_output", [b"", b"leader-output\n"])
def test_bounded_child_success_cleans_closed_stdio_descendants_before_return(
    tmp_path: Path,
    leader_output: bytes,
) -> None:
    result, descendant_pid = run_leader_with_closed_stdio_descendant(
        tmp_path,
        returncode=0,
        leader_output=leader_output,
    )
    try:
        assert result.returncode == 0
        assert result.stdout == leader_output
        assert result.stderr == b""
        assert not process_exists(descendant_pid)
    finally:
        if process_exists(descendant_pid):
            os.kill(descendant_pid, signal.SIGKILL)


def test_bounded_child_nonzero_exit_cleans_closed_stdio_descendant(
    tmp_path: Path,
) -> None:
    result, descendant_pid = run_leader_with_closed_stdio_descendant(
        tmp_path,
        returncode=7,
        leader_output=b"failed\n",
    )
    try:
        assert result.returncode == INJECTED_CHILD_EXIT
        assert result.stdout == b"failed\n"
        assert not process_exists(descendant_pid)
    finally:
        if process_exists(descendant_pid):
            os.kill(descendant_pid, signal.SIGKILL)


def test_bounded_child_cleanup_does_not_kill_an_unrelated_process_group(
    tmp_path: Path,
) -> None:
    unrelated = subprocess.Popen(
        (sys.executable, "-c", "import time; time.sleep(5)"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    descendant_pid = 0
    try:
        result, descendant_pid = run_leader_with_closed_stdio_descendant(
            tmp_path,
            returncode=0,
            leader_output=b"",
        )
        assert result.returncode == 0
        assert not process_exists(descendant_pid)
        assert unrelated.poll() is None
    finally:
        if descendant_pid and process_exists(descendant_pid):
            os.kill(descendant_pid, signal.SIGKILL)
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGKILL)
        _ = unrelated.wait(timeout=1)


@pytest.mark.parametrize(
    "records",
    [
        b"100644 blob zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz 1\tsrc/a.py\0",
        (
            b"100644 blob 1111111111111111111111111111111111111111 1\tsrc/a.py\0"
            b"100644 blob 2222222222222222222222222222222222222222 1\tsrc/a.py\0"
        ),
        b"100644 blob 1111111111111111111111111111111111111111 01\tsrc/a.py\0",
        b"100644 blob 1111111111111111111111111111111111111111 1\t../a.py\0",
        b"100644 blob 1111111111111111111111111111111111111111 1\tsrc/\xff.py\0",
        b"100644 blob 1111111111111111111111111111111111111111 1\tsrc/a.py",
    ],
)
def test_tree_inventory_rejects_malformed_git_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    records: bytes,
) -> None:
    def malformed_git_bytes(
        _repository: Path,
        _arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str] | None = None,
    ) -> bytes:
        _ = environment
        return records

    monkeypatch.setattr(baseline_capture_io, "git_bytes", malformed_git_bytes)

    with pytest.raises(capture_baseline.BaselineCaptureError, match="malformed"):
        _ = baseline_capture_io.validate_tree_modes(
            tmp_path,
            "1" * 40,
            environment={},
        )


@pytest.mark.parametrize(
    "raw",
    [b"a" * 40, b"a" * 40 + b"\nextra\n", b"\xff\n", b"\n"],
)
def test_git_identity_parser_rejects_malformed_text_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
) -> None:
    def malformed_git_bytes(
        _repository: Path,
        _arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str] | None = None,
    ) -> bytes:
        _ = environment
        return raw

    monkeypatch.setattr(baseline_capture_io, "git_bytes", malformed_git_bytes)

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = baseline_capture_io.git_object_id(
            tmp_path,
            "rev-parse",
            "HEAD",
            environment={},
        )


@pytest.mark.parametrize(
    ("operation", "raw"),
    [
        ("git-text", b"\xff\n"),
        ("git-no-output", b"unexpected\n"),
        ("git-object-id", b"z" * 40 + b"\n"),
    ],
)
def test_git_output_parsers_reject_well_framed_semantic_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    raw: bytes,
) -> None:
    def controlled_git_bytes(
        _repository: Path,
        _arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str] | None = None,
    ) -> bytes:
        _ = environment
        return raw

    monkeypatch.setattr(baseline_capture_io, "git_bytes", controlled_git_bytes)

    def parse_fault() -> object:
        if operation == "git-text":
            return baseline_capture_io.git_text(tmp_path, "rev-parse")
        if operation == "git-no-output":
            baseline_capture_io.git_no_output(tmp_path, "update-index")
            return None
        return baseline_capture_io.git_object_id(
            tmp_path,
            "rev-parse",
            "HEAD",
            environment={},
        )

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = parse_fault()


def test_git_runner_requires_an_absolute_system_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_git(
        _command: str,
        mode: int = os.F_OK,
        path: str | None = None,
    ) -> None:
        _ = (mode, path)

    monkeypatch.setattr(shutil, "which", missing_git)

    with pytest.raises(
        capture_baseline.BaselineCaptureError, match="absolute system Git"
    ):
        _ = baseline_capture_io.git_bytes(tmp_path, ("status",))


@pytest.mark.parametrize(
    "result",
    [
        baseline_capture_io.ChildResult(returncode=1, stdout=b"", stderr=b""),
        baseline_capture_io.ChildResult(returncode=0, stdout=b"", stderr=b"warning\n"),
    ],
)
def test_git_runner_rejects_unexpected_status_or_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: baseline_capture_io.ChildResult,
) -> None:
    def bounded_result(
        _command: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: baseline_capture_io.ProcessLimits,
    ) -> baseline_capture_io.ChildResult:
        _ = (cwd, environment, limits)
        return result

    monkeypatch.setattr(
        baseline_capture_io,
        "run_bounded_process",
        bounded_result,
    )

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = baseline_capture_io.git_bytes(tmp_path, ("status",))


def baseline_bytes_from(root: Path) -> dict[str, bytes]:
    return {
        name: (root / name).read_bytes()
        for name in (*BASELINE_FILE_NAMES, "manifest.json")
    }


def run_capture_cli(
    cwd: Path,
    *,
    module: bool,
    arguments: tuple[str, ...],
) -> subprocess.CompletedProcess[str]:
    repository = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        (str(repository / "src"), str(repository)),
    )
    command = (
        [sys.executable, "-m", "scripts.capture_baseline"]
        if module
        else [sys.executable, str(repository / "scripts" / "capture_baseline.py")]
    )
    # Security rationale: sys.executable launches only the fixed module or absolute
    # reviewed capture_baseline.py; remaining argv is test-owned and shell=False.
    # Ruff cannot infer these invariants; see https://github.com/astral-sh/ruff/issues/4045.
    return subprocess.run(  # noqa: S603
        [*command, *arguments],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


@pytest.mark.parametrize("invocation", ["module", "script"])
def test_capture_cli_help_supports_module_and_direct_invocation_without_writes(
    tmp_path: Path,
    invocation: Literal["module", "script"],
) -> None:
    result = run_capture_cli(
        tmp_path,
        module=invocation == "module",
        arguments=("--help",),
    )

    assert result.returncode == 0
    assert "--check" in result.stdout
    assert "--write" in result.stdout
    assert not (tmp_path / "contracts").exists()


@pytest.mark.parametrize("invocation", ["module", "script"])
def test_capture_cli_requires_an_explicit_mode_without_writes(
    tmp_path: Path,
    invocation: Literal["module", "script"],
) -> None:
    result = run_capture_cli(
        tmp_path,
        module=invocation == "module",
        arguments=(),
    )

    assert result.returncode == EXPECTED_CLI_ERROR_EXIT
    assert "required" in result.stderr
    assert not (tmp_path / "contracts").exists()


@pytest.mark.parametrize("invalid", ["file", "generator-directory", "replay-directory"])
def test_materialized_capture_rejects_invalid_root_or_generator_files(
    tmp_path: Path,
    invalid: str,
) -> None:
    root = tmp_path / "materialized"
    if invalid == "file":
        _ = root.write_bytes(b"not-a-directory")
    else:
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        generator = scripts / "capture_baseline.py"
        replay = scripts / "baseline_replay.py"
        if invalid == "generator-directory":
            generator.mkdir()
            _ = replay.write_bytes(b"pass\n")
        else:
            _ = generator.write_bytes(b"pass\n")
            replay.mkdir()

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match=r"regular|directory",
    ):
        _ = capture_baseline.capture_from_materialized_root(root)


def test_materialized_capture_rejects_an_unavailable_python_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "materialized"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    _ = (scripts / "capture_baseline.py").write_bytes(b"pass\n")
    _ = (scripts / "baseline_replay.py").write_bytes(b"pass\n")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "missing"))

    with pytest.raises(
        capture_baseline.BaselineCaptureError, match="Python executable"
    ):
        _ = capture_baseline.capture_from_materialized_root(root)


@pytest.mark.parametrize(
    "child_result",
    [
        baseline_capture_io.ChildResult(1, b"", b""),
        baseline_capture_io.ChildResult(0, b"unexpected", b""),
        baseline_capture_io.ChildResult(0, b"", b"unexpected"),
    ],
)
def test_materialized_capture_rejects_child_process_failure_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    child_result: baseline_capture_io.ChildResult,
) -> None:
    root = tmp_path / "materialized"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    _ = (scripts / "capture_baseline.py").write_bytes(b"pass\n")
    _ = (scripts / "baseline_replay.py").write_bytes(b"pass\n")

    def child_failure(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: baseline_capture_io.ProcessLimits,
    ) -> baseline_capture_io.ChildResult:
        _ = (command, cwd, environment, limits)
        return child_result

    monkeypatch.setattr(baseline_capture_io, "run_bounded_process", child_failure)

    with pytest.raises(capture_baseline.BaselineCaptureError, match="child failed"):
        _ = capture_baseline.capture_from_materialized_root(root)


@pytest.mark.parametrize("result_kind", ["unknown-fixture", "nonobject", "success"])
def test_materialized_capture_parses_only_the_closed_child_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result_kind: str,
) -> None:
    root = tmp_path / "materialized"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    _ = (scripts / "capture_baseline.py").write_bytes(b"pass\n")
    _ = (scripts / "baseline_replay.py").write_bytes(b"pass\n")

    def child_output(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        limits: baseline_capture_io.ProcessLimits,
    ) -> baseline_capture_io.ChildResult:
        _ = (cwd, environment, limits)
        values: dict[str, object] = {name: {} for name in BASELINE_FILE_NAMES}
        if result_kind == "unknown-fixture":
            values["unknown.json"] = values.pop("resources.json")
        elif result_kind == "nonobject":
            values["resources.json"] = []
        _ = Path(command[-1]).write_bytes(canonical_test_bytes(values))
        return baseline_capture_io.ChildResult(0, b"", b"")

    monkeypatch.setattr(baseline_capture_io, "run_bounded_process", child_output)

    if result_kind == "success":
        assert capture_baseline.capture_from_materialized_root(root) == {
            name: {} for name in BASELINE_FILE_NAMES
        }
    else:
        with pytest.raises(capture_baseline.BaselineCaptureError):
            _ = capture_baseline.capture_from_materialized_root(root)


@pytest.mark.parametrize("result_kind", ["success", "failure"])
def test_capture_main_returns_closed_status_for_success_or_capture_failure(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    result_kind: str,
) -> None:
    def verify_attestation(
        repository: Path,
    ) -> capture_baseline.CommittedBaselineManifest:
        _ = repository
        if result_kind == "failure":
            msg = "closed-test-failure"
            raise capture_baseline.BaselineCaptureError(msg)
        return cast("capture_baseline.CommittedBaselineManifest", object())

    monkeypatch.setattr(
        capture_baseline,
        "verify_committed_candidate_attestation",
        verify_attestation,
    )

    failed = result_kind == "failure"
    expected_status = capture_baseline.BASELINE_FAILURE_STATUS if failed else 0
    assert capture_baseline.main(["--check"]) == expected_status
    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "baseline capture failed: closed-test-failure\n" if failed else ""
    )


def test_capture_main_dispatches_explicit_write_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[Path] = []

    def write_manifest(repository: Path) -> None:
        observed.append(repository)

    monkeypatch.setattr(
        capture_baseline,
        "write_committed_candidate_manifest",
        write_manifest,
    )

    assert capture_baseline.main(["--write"]) == 0
    assert observed == [Path(capture_baseline.__file__).resolve().parents[1]]


@pytest.mark.live
def test_historical_capture_rejects_a_non_recovery_head_without_writes() -> None:
    repository = Path(__file__).resolve().parents[2]
    before = baseline_bytes_from(repository / "contracts" / "baseline")

    with (
        pytest.raises(
            capture_baseline.BaselineCaptureError,
            match="fixed recovery base",
        ),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=current_recovery_policy(),
            persist_objects=False,
        ),
    ):
        pass

    assert baseline_bytes_from(repository / "contracts" / "baseline") == before


@pytest.mark.live
def test_rejected_historical_capture_does_not_freshen_git_metadata() -> None:
    repository = Path(__file__).resolve().parents[2]
    before = git_object_metadata_inventory(repository)

    with (
        pytest.raises(
            capture_baseline.BaselineCaptureError,
            match="fixed recovery base",
        ),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=current_recovery_policy(),
            persist_objects=False,
        ),
    ):
        pass

    assert git_object_metadata_inventory(repository) == before


def test_check_capture_uses_a_complete_private_object_store_without_alternates(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)

    with baseline_capture_io.synthetic_workspace(
        repository,
        policy=policy,
        persist_objects=False,
    ) as workspace:
        private_objects = workspace.root.parent / "git" / "objects"
        base_commit = policy.base_commit
        assert (private_objects / base_commit[:2] / base_commit[2:]).is_file()
        assert not (private_objects / "info" / "alternates").exists()
        assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in workspace.git_environment


def test_private_object_snapshot_copies_loose_pack_and_info_files_without_links(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    for directory in (source, source / "aa", source / "pack", source / "info"):
        directory.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    source_files = {
        "aa/11111111111111111111111111111111111111": b"loose-object",
        "pack/pack-1111111111111111111111111111111111111111.pack": b"pack",
        "pack/pack-1111111111111111111111111111111111111111.idx": b"index",
        "info/commit-graph": b"commit-graph",
    }
    for relative_path, raw in source_files.items():
        path = source / relative_path
        _ = path.write_bytes(raw)
        path.chmod(0o440)
    expected = baseline_capture_io.object_database_inventory(source)

    copied = baseline_capture_io.copy_object_database_snapshot(
        source,
        destination,
        expected,
    )

    assert baseline_capture_io.object_database_inventory(source) == expected
    assert {
        (entry.relative_path, entry.kind, entry.size, entry.sha256) for entry in copied
    } == {
        (entry.relative_path, entry.kind, entry.size, entry.sha256)
        for entry in expected
    }
    for entry in copied:
        assert stat.S_IMODE(entry.mode) == (
            0o700 if entry.kind == "directory" else 0o600
        )
    for relative_path, raw in source_files.items():
        source_path = source / relative_path
        copied_path = destination / relative_path
        assert copied_path.read_bytes() == raw
        assert stat.S_IMODE(copied_path.stat().st_mode) == PRIVATE_FILE_MODE
        assert copied_path.stat().st_mtime_ns == source_path.stat().st_mtime_ns
        assert (copied_path.stat().st_dev, copied_path.stat().st_ino) != (
            source_path.stat().st_dev,
            source_path.stat().st_ino,
        )
        assert copied_path.stat().st_nlink == 1


@pytest.mark.parametrize("root_kind", ["missing", "file"])
def test_object_inventory_rejects_missing_or_nondirectory_roots(
    tmp_path: Path,
    root_kind: str,
) -> None:
    root = tmp_path / "objects"
    if root_kind == "file":
        _ = root.write_bytes(b"not-a-directory")

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = baseline_capture_io.object_database_inventory(root)


def test_object_inventory_rejects_control_and_non_utf8_names(tmp_path: Path) -> None:
    for raw_name in (b"control\nname", b"non-utf8-\xff"):
        root = tmp_path / hashlib.sha256(raw_name).hexdigest()
        root.mkdir()
        descriptor = os.open(
            os.fsencode(root) + b"/" + raw_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        os.close(descriptor)
        with pytest.raises(capture_baseline.BaselineCaptureError):
            _ = baseline_capture_io.object_database_inventory(root)


def test_object_inventory_rejects_one_file_over_the_total_byte_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "objects"
    root.mkdir()
    _ = (root / "object").write_bytes(b"1234")
    monkeypatch.setattr(baseline_capture_io, "MAX_REAL_OBJECT_DATABASE_BYTES", 3)

    with pytest.raises(capture_baseline.BaselineCaptureError, match="bound"):
        _ = baseline_capture_io.object_database_inventory(root)


@pytest.mark.parametrize("destination_kind", ["file", "nonempty-directory"])
def test_object_snapshot_rejects_nonempty_or_nondirectory_destination(
    tmp_path: Path,
    destination_kind: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _ = (source / "object").write_bytes(b"object")
    destination = tmp_path / "destination"
    if destination_kind == "file":
        _ = destination.write_bytes(b"not-a-directory")
    else:
        destination.mkdir()
        _ = (destination / "residue").write_bytes(b"residue")

    with pytest.raises(capture_baseline.BaselineCaptureError, match="empty directory"):
        _ = baseline_capture_io.copy_object_database_snapshot(
            source,
            destination,
            baseline_capture_io.object_database_inventory(source),
        )


@pytest.mark.parametrize("writer", ["private", "staged"])
def test_atomic_writers_remove_partial_files_after_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    writer: str,
) -> None:
    path = tmp_path / "output"

    def fail_fsync(_descriptor: int) -> None:
        msg = "controlled fsync failure"
        raise OSError(msg)

    monkeypatch.setattr(os, "fsync", fail_fsync)
    write = (
        baseline_capture_io.write_private_file
        if writer == "private"
        else baseline_capture_io.write_staged_file
    )

    with pytest.raises(OSError, match="controlled fsync failure"):
        write(path, b"content")
    assert not path.exists()


@pytest.mark.parametrize("fault", ["symlink", "oversized"])
def test_regular_destination_reader_rejects_links_and_oversized_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    target = tmp_path / "target"
    _ = target.write_bytes(b"content")
    path = tmp_path / "destination"
    if fault == "symlink":
        path.symlink_to(target)
    else:
        _ = path.write_bytes(b"content")
        monkeypatch.setattr(baseline_capture_io, "MAX_CANONICAL_JSON_BYTES", 3)

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = baseline_capture_io.read_regular_bytes(path)


@pytest.mark.parametrize("mutation", ["symlink", "fifo", "hardlink"])
def test_object_snapshot_rejects_links_and_special_files(
    tmp_path: Path,
    mutation: str,
) -> None:
    source = tmp_path / "objects"
    source.mkdir(mode=0o700)
    target = source / "entry"
    outside = tmp_path / "outside"
    _ = outside.write_bytes(b"object")
    if mutation == "symlink":
        target.symlink_to(outside)
    elif mutation == "fifo":
        os.mkfifo(target)
    else:
        os.link(outside, target)

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = baseline_capture_io.object_database_inventory(source)


@pytest.mark.parametrize("name", ["alternates", "http-alternates"])
def test_object_snapshot_rejects_alternate_object_store_records(
    tmp_path: Path,
    name: str,
) -> None:
    source = tmp_path / "objects"
    info = source / "info"
    info.mkdir(parents=True, mode=0o700)
    _ = (info / name).write_text("/untrusted/objects\n", encoding="utf-8")

    with pytest.raises(capture_baseline.BaselineCaptureError, match="alternate"):
        _ = baseline_capture_io.object_database_inventory(source)


def test_object_snapshot_enforces_total_size_and_entry_count_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "objects"
    source.mkdir(mode=0o700)
    _ = (source / "one").write_bytes(b"12")
    _ = (source / "two").write_bytes(b"34")

    monkeypatch.setattr(baseline_capture_io, "MAX_REAL_OBJECT_DATABASE_BYTES", 3)
    with pytest.raises(capture_baseline.BaselineCaptureError, match="bound"):
        _ = baseline_capture_io.object_database_inventory(source)

    monkeypatch.setattr(baseline_capture_io, "MAX_REAL_OBJECT_DATABASE_BYTES", 4)
    monkeypatch.setattr(
        baseline_capture_io,
        "MAX_REAL_OBJECT_DATABASE_ENTRIES",
        1,
    )
    with pytest.raises(capture_baseline.BaselineCaptureError, match="entries"):
        _ = baseline_capture_io.object_database_inventory(source)


def test_object_snapshot_enforces_directory_depth_bound(tmp_path: Path) -> None:
    source = tmp_path / "objects"
    source.mkdir(mode=0o700)
    nested = source
    for position in range(baseline_capture_io.MAX_CANONICAL_JSON_DEPTH + 2):
        nested /= f"d{position}"
        nested.mkdir(mode=0o700)

    with pytest.raises(capture_baseline.BaselineCaptureError, match="depth"):
        _ = baseline_capture_io.object_database_inventory(source)


@pytest.mark.parametrize("mutation", ["content", "touch", "replacement"])
def test_private_object_snapshot_rejects_source_mutation_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    source_file = source / "object"
    _ = source_file.write_bytes(b"before")
    expected = baseline_capture_io.object_database_inventory(source)
    write_private_file = baseline_capture_io.write_private_file
    mutated = False

    def mutate_after_copy(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
        nonlocal mutated
        write_private_file(path, raw, mode=mode)
        if not mutated:
            if mutation == "content":
                _ = source_file.write_bytes(b"after")
            elif mutation == "touch":
                metadata = source_file.stat()
                os.utime(
                    source_file,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1),
                )
            else:
                replacement = source / "replacement"
                _ = replacement.write_bytes(b"before")
                _ = replacement.replace(source_file)
            mutated = True

    monkeypatch.setattr(baseline_capture_io, "write_private_file", mutate_after_copy)

    with pytest.raises(capture_baseline.BaselineCaptureError, match="changed"):
        _ = baseline_capture_io.copy_object_database_snapshot(
            source,
            destination,
            expected,
        )


@pytest.mark.parametrize("failure", ["raise", "truncate"])
def test_private_object_snapshot_fails_closed_on_copy_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    _ = (source / "object").write_bytes(b"object")
    expected = baseline_capture_io.object_database_inventory(source)

    write_private_file = baseline_capture_io.write_private_file

    def fail_copy(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
        if failure == "raise":
            msg = "injected object snapshot copy failure"
            raise OSError(msg)
        write_private_file(path, raw[:-1], mode=mode)

    monkeypatch.setattr(baseline_capture_io, "write_private_file", fail_copy)

    with pytest.raises(capture_baseline.BaselineCaptureError, match=r"copy|match"):
        _ = baseline_capture_io.copy_object_database_snapshot(
            source,
            destination,
            expected,
        )
    assert baseline_capture_io.object_database_inventory(source) == expected


def test_private_object_snapshot_never_uses_link_or_fast_copy_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    _ = (source / "object").write_bytes(b"object")
    expected = baseline_capture_io.object_database_inventory(source)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("object snapshot used a linking or fast-copy API")

    monkeypatch.setattr(os, "link", forbidden)
    monkeypatch.setattr(shutil, "copyfile", forbidden)
    monkeypatch.setattr(shutil, "copy2", forbidden)
    if hasattr(os, "copy_file_range"):
        monkeypatch.setattr(os, "copy_file_range", forbidden)
    if hasattr(os, "sendfile"):
        monkeypatch.setattr(os, "sendfile", forbidden)

    _ = baseline_capture_io.copy_object_database_snapshot(
        source,
        destination,
        expected,
    )


def test_check_capture_operates_from_a_private_packed_object_store(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    _ = run_test_git(repository, "repack", "-ad")
    _ = run_test_git(repository, "prune-packed")
    _ = run_test_git(repository, "update-server-info")
    objects = Path(run_test_git(repository, "rev-parse", "--git-path", "objects"))
    if not objects.is_absolute():
        objects = repository / objects
    assert list((objects / "pack").glob("*.pack"))
    assert list((objects / "pack").glob("*.idx"))
    assert (objects / "info" / "packs").is_file()
    before = git_object_metadata_inventory(repository)

    with baseline_capture_io.synthetic_workspace(
        repository,
        policy=policy,
        persist_objects=False,
    ) as workspace:
        assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in workspace.git_environment
        baseline_capture_io.git_no_output(
            repository,
            "cat-file",
            "-e",
            f"{policy.base_commit}^{{commit}}",
            environment=workspace.git_environment,
        )
        copied_objects = workspace.root.parent / "git" / "objects"
        assert {path.name for path in (copied_objects / "pack").glob("*.pack")} == {
            path.name for path in (objects / "pack").glob("*.pack")
        }
        assert {path.name for path in (copied_objects / "pack").glob("*.idx")} == {
            path.name for path in (objects / "pack").glob("*.idx")
        }
        assert (copied_objects / "info" / "packs").read_bytes() == (
            objects / "info" / "packs"
        ).read_bytes()

    assert git_object_metadata_inventory(repository) == before


def test_capture_write_and_check_are_stable_and_check_is_side_effect_free(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    index_path = Path(run_test_git(repository, "rev-parse", "--git-path", "index"))
    if not index_path.is_absolute():
        index_path = repository / index_path

    def index_state() -> tuple[int, int, int, int, bytes]:
        index_stat = index_path.stat()
        return (
            index_stat.st_dev,
            index_stat.st_ino,
            index_stat.st_mode,
            index_stat.st_mtime_ns,
            index_path.read_bytes(),
        )

    index_before = index_state()
    objects_before = git_object_inventory(repository)

    def collector(_materialized_root: Path) -> BaselineFixtures:
        return {
            "tool-catalog.json": {
                name: {"name": name} for name in sorted(EXPECTED_TOOL_NAMES)
            },
            "resources.json": {},
            "result-cases.json": {"case.one": {}},
            "error-cases.json": {},
        }

    capture_baseline.run_capture_mode(
        repository,
        policy=policy,
        write=True,
        collector=collector,
    )
    baseline = repository / "contracts" / "baseline"
    manifest = capture_baseline.validate_baseline_directory(baseline)
    assert manifest.input.tree_before == manifest.input.tree_after
    assert (
        manifest.generator.sha256
        == hashlib.sha256(
            (repository / "scripts" / "capture_baseline.py").read_bytes(),
        ).hexdigest()
    )
    assert (
        run_test_git(
            repository,
            "cat-file",
            "-t",
            manifest.input.tree_before,
        )
        == "tree"
    )
    assert index_state() == index_before
    objects_after_write = git_object_inventory(repository)
    assert objects_after_write != objects_before
    assert set(objects_before).issubset(objects_after_write)
    assert all(
        objects_after_write[relative_path] == digest
        for relative_path, digest in objects_before.items()
    )
    before = {
        path.name: (path.stat().st_mtime_ns, path.read_bytes())
        for path in baseline.iterdir()
    }

    capture_baseline.run_capture_mode(
        repository,
        policy=policy,
        write=False,
        collector=collector,
    )

    assert {
        path.name: (path.stat().st_mtime_ns, path.read_bytes())
        for path in baseline.iterdir()
    } == before
    assert index_state() == index_before
    assert git_object_inventory(repository) == objects_after_write


@pytest.mark.parametrize(
    "mutation",
    [
        "committed-schema",
        "historical-schema",
        "historical-case-inventory",
        "entry-order",
        "tool-inventory",
        "case-inventory",
        "historical-digest",
        "fixture-digest",
    ],
)
def test_committed_baseline_rejects_adversarial_bundle_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    baseline = make_unattested_committed_baseline_directory(tmp_path)
    manifest_path = baseline / "manifest.json"
    historical_path = baseline / "historical-manifest-v3.json"
    manifest = require_test_object(
        load_json_value(manifest_path.read_bytes()),
        context="committed manifest",
    )
    historical = require_test_object(
        load_json_value(historical_path.read_bytes()),
        context="historical manifest",
    )
    target_path = manifest_path
    target = manifest

    if mutation == "committed-schema":
        manifest["schema_version"] = 5
    elif mutation == "historical-schema":
        historical["schema_version"] = 2
        target_path = historical_path
        target = historical
    elif mutation == "historical-case-inventory":
        resources_path = baseline / "resources.json"
        resources = require_test_object(
            load_json_value(resources_path.read_bytes()),
            context="resources fixture",
        )
        resources["unlisted.case"] = {}
        resources_raw = canonical_test_bytes(resources)
        _ = resources_path.write_bytes(resources_raw)
        for raw_entry in require_test_array(
            historical["entries"],
            context="historical entries",
        ):
            entry = require_test_object(raw_entry, context="historical entry")
            if entry.get("path") == "resources.json":
                entry["sha256"] = hashlib.sha256(resources_raw).hexdigest()
        target_path = historical_path
        target = historical
    elif mutation == "entry-order":
        entries = require_test_array(manifest["entries"], context="committed entries")
        manifest["entries"] = list(reversed(entries))
    elif mutation == "tool-inventory":
        tools = require_test_array(
            manifest["required_tool_names"],
            context="committed tool inventory",
        )
        tools[-1] = "unknown_tool"
    elif mutation == "case-inventory":
        manifest["required_case_ids"] = ["case.one", "error.one"]
    elif mutation == "historical-digest":
        provenance = require_test_object(
            manifest["historical_provenance"],
            context="historical provenance",
        )
        provenance["sha256"] = "0" * 64
    else:
        entries = require_test_array(manifest["entries"], context="committed entries")
        entry = require_test_object(entries[0], context="committed entry")
        entry["sha256"] = "0" * 64

    _ = target_path.write_bytes(canonical_test_bytes(target))

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.validate_committed_baseline_directory(baseline)


@pytest.mark.parametrize("mutation", ["non-directory", "unexpected-entry"])
def test_committed_baseline_rejects_unclosed_root_boundary(
    tmp_path: Path,
    mutation: str,
) -> None:
    if mutation == "non-directory":
        baseline = tmp_path / "baseline"
        _ = baseline.write_bytes(b"not-a-directory\n")
    else:
        baseline = make_unattested_committed_baseline_directory(tmp_path)
        _ = (baseline / "unexpected.json").write_bytes(b"{}\n")

    with pytest.raises(capture_baseline.BaselineCaptureError):
        _ = capture_baseline.validate_committed_baseline_directory(baseline)


def test_committed_baseline_writer_rejects_symlinked_repository(
    tmp_path: Path,
) -> None:
    target = tmp_path / "repository-target"
    target.mkdir()
    repository = tmp_path / "repository-link"
    repository.symlink_to(target, target_is_directory=True)

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="absolute non-symlink directory",
    ):
        capture_baseline.write_committed_candidate_manifest(repository)


def test_committed_checker_requires_v4_before_git_attestation(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _ = make_clean_committed_baseline_repository(repository)

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="committed baseline attestation required",
    ):
        _ = capture_baseline.verify_committed_candidate_attestation(repository)


def test_committed_manifest_writer_derives_candidate_and_preserves_fixtures(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    candidate_commit = make_clean_committed_baseline_repository(repository)
    baseline = repository / "contracts" / "baseline"
    historical_manifest = (baseline / "manifest.json").read_bytes()
    fixture_bytes = {
        name: (baseline / name).read_bytes() for name in BASELINE_FILE_NAMES
    }

    capture_baseline.write_committed_candidate_manifest(repository)

    assert {
        name: (baseline / name).read_bytes() for name in BASELINE_FILE_NAMES
    } == fixture_bytes
    assert (
        baseline / "historical-manifest-v3.json"
    ).read_bytes() == historical_manifest
    manifest = CommittedBaselineManifest.model_validate_json(
        (baseline / "manifest.json").read_bytes(),
        strict=True,
    )
    assert manifest.candidate == GitSourceIdentity(
        commit=candidate_commit,
        tree=run_test_git(repository, "rev-parse", "HEAD^{tree}"),
        src_tree=run_test_git(repository, "rev-parse", "HEAD:src"),
    )
    assert (
        manifest.historical_provenance.sha256
        == hashlib.sha256(
            historical_manifest,
        ).hexdigest()
    )
    assert run_test_git(repository, "status", "--short") == (
        "M contracts/baseline/manifest.json\n"
        "?? contracts/baseline/historical-manifest-v3.json"
    )

    run_test_git_no_output(
        repository,
        "add",
        "--",
        "contracts/baseline/manifest.json",
        "contracts/baseline/historical-manifest-v3.json",
    )
    run_test_git_no_output(repository, "commit", "--quiet", "-m", "attest baseline")

    verified = capture_baseline.verify_committed_candidate_attestation(repository)
    assert verified.candidate.commit == candidate_commit


def test_committed_manifest_writer_rejects_a_dirty_candidate_without_writes(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _ = make_clean_committed_baseline_repository(repository)
    baseline = repository / "contracts" / "baseline"
    before = baseline_bytes_from(baseline)
    _ = (repository / "src" / "module.py").write_text(
        "VALUE = 2\n",
        encoding="utf-8",
    )

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="candidate worktree must be clean",
    ):
        capture_baseline.write_committed_candidate_manifest(repository)

    assert baseline_bytes_from(baseline) == before


def test_committed_manifest_checker_rejects_uncommitted_provenance(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _ = make_clean_committed_baseline_repository(repository)
    capture_baseline.write_committed_candidate_manifest(repository)

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="attestation worktree must be clean",
    ):
        _ = capture_baseline.verify_committed_candidate_attestation(repository)


def test_committed_manifest_checker_rejects_an_unrelated_attestation_delta(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    _ = make_clean_committed_baseline_repository(repository)
    capture_baseline.write_committed_candidate_manifest(repository)
    _ = (repository / "src" / "module.py").write_text(
        "VALUE = 2\n",
        encoding="utf-8",
    )
    run_test_git_no_output(
        repository,
        "add",
        "--",
        "contracts/baseline/manifest.json",
        "contracts/baseline/historical-manifest-v3.json",
        "src/module.py",
    )
    run_test_git_no_output(repository, "commit", "--quiet", "-m", "forged attestation")

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="attestation commit changes an unauthorized path",
    ):
        _ = capture_baseline.verify_committed_candidate_attestation(repository)


@pytest.mark.parametrize("fault", ["tool-catalog", "duplicate-case"])
def test_capture_mode_rejects_semantically_invalid_collector_output(
    tmp_path: Path,
    fault: str,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    before = baseline_bytes_from(repository / "contracts" / "baseline")

    def invalid_collector(_materialized_root: Path) -> BaselineFixtures:
        catalog: JsonObject = {
            name: {"name": name} for name in sorted(EXPECTED_TOOL_NAMES)
        }
        result_cases: JsonObject = {"case.one": {}}
        error_cases: JsonObject = {}
        if fault == "tool-catalog":
            _ = catalog.pop("search_documents")
        else:
            error_cases["case.one"] = {}
        return {
            "tool-catalog.json": catalog,
            "resources.json": {},
            "result-cases.json": result_cases,
            "error-cases.json": error_cases,
        }

    with pytest.raises(capture_baseline.BaselineCaptureError):
        capture_baseline.run_capture_mode(
            repository,
            policy=policy,
            write=False,
            collector=invalid_collector,
        )

    assert baseline_bytes_from(repository / "contracts" / "baseline") == before


def test_capture_check_rejects_regenerated_byte_drift_without_rewriting(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    identity = make_capture_git_repository(repository)
    policy = capture_baseline.CapturePolicy(**identity)
    marker = "first"

    def collector(_materialized_root: Path) -> BaselineFixtures:
        return {
            "tool-catalog.json": {
                name: {"marker": marker} for name in sorted(EXPECTED_TOOL_NAMES)
            },
            "resources.json": {},
            "result-cases.json": {"case.one": {"marker": marker}},
            "error-cases.json": {},
        }

    capture_baseline.run_capture_mode(
        repository,
        policy=policy,
        write=True,
        collector=collector,
    )
    before = baseline_bytes_from(repository / "contracts" / "baseline")
    marker = "second"

    with pytest.raises(capture_baseline.BaselineCaptureError, match="differs"):
        capture_baseline.run_capture_mode(
            repository,
            policy=policy,
            write=False,
            collector=collector,
        )

    assert baseline_bytes_from(repository / "contracts" / "baseline") == before


def test_baseline_publication_orders_manifest_last(tmp_path: Path) -> None:
    destination = tmp_path / "destination"
    source = tmp_path / "source"
    _ = write_valid_infrastructure_fixture(destination)
    _ = write_valid_infrastructure_fixture(source)
    outputs = baseline_bytes_from(source)
    destinations: list[str] = []

    def observed_replace(source_path: Path, destination_path: Path) -> None:
        destinations.append(destination_path.name)
        _ = source_path.replace(destination_path)

    capture_baseline.publish_output_bytes(
        destination,
        outputs,
        replace=observed_replace,
    )

    assert destinations[-1] == "manifest.json"
    assert destinations[:4] == list(BASELINE_FILE_NAMES)
    assert baseline_bytes_from(destination) == outputs


@pytest.mark.parametrize("failure", ["stage", "rename"])
def test_baseline_publication_fault_restores_every_output(
    tmp_path: Path,
    failure: str,
) -> None:
    destination = tmp_path / "destination"
    source = tmp_path / "source"
    _ = write_valid_infrastructure_fixture(destination, marker="old")
    _ = write_valid_infrastructure_fixture(source, marker="new")
    for position, name in enumerate((*BASELINE_FILE_NAMES, "manifest.json")):
        (destination / name).chmod(0o600 | (position % 2) * 0o040)
    outputs = baseline_bytes_from(source)
    before = baseline_bytes_from(destination)
    before_modes = {
        path.name: stat.S_IMODE(path.stat().st_mode) for path in destination.iterdir()
    }
    assert all(outputs[name] != before[name] for name in outputs)
    stage_calls = 0
    replace_calls = 0

    def failing_stage(path: Path, raw: bytes) -> None:
        nonlocal stage_calls
        stage_calls += 1
        if failure == "stage" and stage_calls == INJECTED_FAILURE_CALL:
            msg = "injected partial-write failure"
            raise OSError(msg)
        baseline_capture_io.write_staged_file(path, raw)

    def failing_replace(source_path: Path, destination_path: Path) -> None:
        nonlocal replace_calls
        replace_calls += 1
        if failure == "rename" and replace_calls == INJECTED_FAILURE_CALL:
            msg = "injected rename failure"
            raise OSError(msg)
        _ = source_path.replace(destination_path)

    with pytest.raises(capture_baseline.BaselineCaptureError):
        capture_baseline.publish_output_bytes(
            destination,
            outputs,
            replace=failing_replace,
            stage=failing_stage,
        )

    assert baseline_bytes_from(destination) == before
    assert {
        path.name: stat.S_IMODE(path.stat().st_mode) for path in destination.iterdir()
    } == before_modes
    assert sorted(path.name for path in destination.iterdir()) == sorted(before)
    assert not list(tmp_path.glob(".baseline-publish-*"))


def test_baseline_publication_rollback_restores_a_missing_destination(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "destination"
    source = tmp_path / "source"
    _ = write_valid_infrastructure_fixture(destination, marker="old")
    _ = write_valid_infrastructure_fixture(source, marker="new")
    missing = destination / "tool-catalog.json"
    missing.unlink()
    before = {
        name: (destination / name).read_bytes()
        for name in (*BASELINE_FILE_NAMES[1:], "manifest.json")
    }
    replace_calls = 0

    def failing_replace(source_path: Path, destination_path: Path) -> None:
        nonlocal replace_calls
        replace_calls += 1
        if replace_calls == INJECTED_FAILURE_CALL:
            msg = "injected rename failure"
            raise OSError(msg)
        _ = source_path.replace(destination_path)

    with pytest.raises(capture_baseline.BaselineCaptureError):
        capture_baseline.publish_output_bytes(
            destination,
            baseline_bytes_from(source),
            replace=failing_replace,
        )

    assert not missing.exists()
    assert {
        name: (destination / name).read_bytes()
        for name in (*BASELINE_FILE_NAMES[1:], "manifest.json")
    } == before
    assert not list(tmp_path.glob(".baseline-publish-*"))


def test_baseline_publication_reports_rollback_failure_and_removes_residue(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "destination"
    source = tmp_path / "source"
    _ = write_valid_infrastructure_fixture(destination, marker="old")
    _ = write_valid_infrastructure_fixture(source, marker="new")
    outputs = baseline_bytes_from(source)
    original_replace = os.replace
    publish_calls = 0
    rollback_attempts: list[str] = []

    def failing_publish(source_path: Path, destination_path: Path) -> None:
        nonlocal publish_calls
        publish_calls += 1
        if publish_calls == INJECTED_FAILURE_CALL:
            msg = "injected publication failure"
            raise OSError(msg)
        original_replace(source_path, destination_path)

    def failing_rollback(source_path: Path, destination_path: Path) -> None:
        if source_path.parent.name == "backups":
            rollback_attempts.append(destination_path.name)
            if destination_path.name == "resources.json":
                msg = "injected rollback failure"
                raise OSError(msg)
        original_replace(source_path, destination_path)

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match="rollback could not be completed",
    ):
        capture_baseline.publish_output_bytes(
            destination,
            outputs,
            replace=failing_publish,
            rollback=failing_rollback,
        )

    assert set(rollback_attempts) == {"tool-catalog.json", "resources.json"}
    assert not list(tmp_path.glob(".baseline-publish-*"))


def test_baseline_publication_rejects_symlink_destination_without_changes(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "destination"
    source = tmp_path / "source"
    _ = write_valid_infrastructure_fixture(destination)
    _ = write_valid_infrastructure_fixture(source)
    target = tmp_path / "outside.json"
    _ = target.write_bytes(b'{"outside":true}\n')
    path = destination / "resources.json"
    path.unlink()
    path.symlink_to(target)
    before_target = target.read_bytes()

    with pytest.raises(capture_baseline.BaselineCaptureError):
        capture_baseline.publish_output_bytes(destination, baseline_bytes_from(source))

    assert path.is_symlink()
    assert target.read_bytes() == before_target


@pytest.mark.parametrize("fault", ["root-file", "incomplete", "unexpected-file"])
def test_baseline_publication_rejects_invalid_root_or_output_inventory(
    tmp_path: Path,
    fault: str,
) -> None:
    root = tmp_path / "baseline"
    source = tmp_path / "source"
    _ = write_valid_infrastructure_fixture(source)
    outputs = baseline_bytes_from(source)
    if fault == "root-file":
        _ = root.write_bytes(b"not-a-directory")
    else:
        _ = write_valid_infrastructure_fixture(root)
        if fault == "incomplete":
            del outputs["resources.json"]
        else:
            _ = (root / "unexpected.json").write_bytes(b"{}\n")

    with pytest.raises(capture_baseline.BaselineCaptureError):
        capture_baseline.publish_output_bytes(root, outputs)


def test_baseline_publication_rejects_output_over_the_byte_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "baseline"
    source = tmp_path / "source"
    _ = write_valid_infrastructure_fixture(root)
    _ = write_valid_infrastructure_fixture(source)
    outputs = baseline_bytes_from(source)
    monkeypatch.setattr(baseline_capture_io, "MAX_CANONICAL_JSON_BYTES", 1)

    with pytest.raises(capture_baseline.BaselineCaptureError, match="oversized"):
        capture_baseline.publish_output_bytes(root, outputs)


@pytest.mark.parametrize("race", ["appeared", "replaced"])
def test_baseline_publication_rejects_destination_identity_races(
    tmp_path: Path,
    race: str,
) -> None:
    root = tmp_path / "baseline"
    source = tmp_path / "source"
    _ = write_valid_infrastructure_fixture(root, marker="old")
    _ = write_valid_infrastructure_fixture(source, marker="new")
    outputs = baseline_bytes_from(source)
    destination = root / "tool-catalog.json"
    if race == "appeared":
        destination.unlink()

    def racing_stage(path: Path, raw: bytes) -> None:
        baseline_capture_io.write_staged_file(path, raw)
        if path.name != "tool-catalog.json":
            return
        replacement = tmp_path / "racing-destination"
        _ = replacement.write_bytes(b"racer")
        _ = replacement.replace(destination)

    with pytest.raises(
        capture_baseline.BaselineCaptureError,
        match=r"appeared|changed",
    ):
        capture_baseline.publish_output_bytes(root, outputs, stage=racing_stage)

    assert destination.read_bytes() == b"racer"


@pytest.mark.asyncio
async def test_fixture_factory_downloads_a_real_inspectable_pdf(tmp_path: Path) -> None:
    service = make_tool_service(tmp_path, frozen_origin=True)
    downloaded = await service.call(
        "download_document_file",
        {"handle": "1234/560449", "bitstream_id": "bs_public"},
    )
    assert isinstance(downloaded, DownloadDocumentOutput)
    artifact_id = downloaded.artifact_id
    inspected = await service.call("inspect_pdf", {"artifact_id": artifact_id})
    assert isinstance(inspected, PdfInspectionOutput)
    assert inspected.page_count == 1


def test_frozen_baseline_is_complete_and_digest_bound(
    tool_service: ToolService,
) -> None:
    manifest = BaselineManifest.model_validate_json(
        Path("contracts/baseline/manifest.json").read_text(encoding="utf-8"),
        strict=True,
    )
    assert manifest.audit.commit == "2ba5dc18385747aa5d12a3b560eaab2ab97b7a40"
    assert manifest.audit.tree == "b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8"
    assert manifest.audit.src_tree == "fcd9debdb533498486a2bbeaf909ea5bfb95b52c"
    assert manifest.recovery.base_commit == ("da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0")
    assert manifest.recovery.base_tree == ("2464df5aa1880e99168ce07c23d891ab66ed3959")
    assert manifest.recovery.imported_index_tree == (
        "6cb461d986c21e4cb2852a07b06f75812ec27bbb"
    )
    assert manifest.input.tree_before == manifest.input.tree_after
    assert manifest.input.src_tree == git_rev_parse(f"{manifest.input.tree_before}:src")
    assert {entry.path for entry in manifest.entries} == {
        "tool-catalog.json",
        "resources.json",
        "result-cases.json",
        "error-cases.json",
    }
    assert len({entry.path for entry in manifest.entries}) == len(manifest.entries)
    assert len(set(manifest.required_case_ids)) == len(manifest.required_case_ids)
    assert all(
        entry.sha256 == sha256_file(BASELINE_DIR / entry.path)
        for entry in manifest.entries
    )
    live_tool_names: set[str] = set()
    for tool in tool_service.list_tools():
        name = tool["name"]
        assert isinstance(name, str)
        live_tool_names.add(name)
    assert frozen_tool_names() == live_tool_names
    assert frozen_case_ids() == set(manifest.required_case_ids)


def test_normative_task1_plan_requires_private_object_copy_without_alternates() -> None:
    plan = Path(
        "docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md"
    ).read_text(encoding="utf-8")
    task_one = plan.split("### Task 1: Freeze current behavior", maxsplit=1)[1].split(
        "### Task 1A:",
        maxsplit=1,
    )[0]

    assert "real objects only as alternates" not in task_one
    assert "`GIT_ALTERNATE_OBJECT_DIRECTORIES` is absent" in task_one
    assert "bounded no-follow private object" in task_one
    assert "rejects `info/alternates` and `info/http-alternates`" in task_one
    assert "append-only real object destination" in task_one


def _normative_task1_plan() -> str:
    plan = Path(
        "docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md"
    ).read_text(encoding="utf-8")
    return plan.split("### Task 1: Freeze current behavior", maxsplit=1)[1].split(
        "### Task 1A:",
        maxsplit=1,
    )[0]


def _regex_capture_values(pattern: re.Pattern[str], source: str) -> tuple[str, ...]:
    return tuple(cast("str", match.group(1)) for match in pattern.finditer(source))


def test_normative_task1_plan_schema_binds_exact_untracked_path_tuple() -> None:
    task_one = _normative_task1_plan()
    literal_path_pattern: re.Pattern[str] = re.compile(
        r'Literal\["([^"]+)"\]',
    )
    schema_match = re.search(
        r"    included_untracked_paths: tuple\[\n(?P<body>.*?)\n    \]\n",
        task_one,
        flags=re.DOTALL,
    )

    assert schema_match is not None
    assert (
        _regex_capture_values(
            literal_path_pattern,
            cast("str", schema_match.group("body")),
        )
        == INCLUDED_UNTRACKED_PATHS
    )


def test_normative_task1_plan_step3_adds_exact_untracked_path_tuple() -> None:
    task_one = _normative_task1_plan()
    git_add_pattern: re.Pattern[str] = re.compile(r"`git add -- ([^`\n]+)`")

    assert _regex_capture_values(git_add_pattern, task_one) == (
        " ".join(INCLUDED_UNTRACKED_PATHS),
    )
    assert "all eleven declared paths" in task_one
    assert "all eleven exact declared entries" in task_one
    assert "both declared paths" not in task_one
    assert "both exact declared entries" not in task_one


def test_normative_task1_plan_prose_binds_exact_untracked_path_tuple() -> None:
    task_one = _normative_task1_plan()
    inline_path_pattern: re.Pattern[str] = re.compile(r"`([^`]+)`")
    prose_prefix = r"exact sorted eleven-path `included_untracked_paths` tuple "
    prose_suffix = r"\((?P<body>[^)]+)\)"
    prose_pattern = f"{prose_prefix}{prose_suffix}"
    prose_match = re.search(prose_pattern, task_one)

    assert prose_match is not None
    assert (
        _regex_capture_values(
            inline_path_pattern,
            cast("str", prose_match.group("body")),
        )
        == INCLUDED_UNTRACKED_PATHS
    )


def test_release_profile_is_single_canonical_digest_bound_record() -> None:
    marker = re.compile(rf"<!-- {re.escape(PROFILE_MARKER)}\n(?P<body>[^\n]+)\n-->")
    for path in (
        Path("SPEC.md"),
        Path("docs/architecture/2026-08-14-official-python-sdk-adr.md"),
    ):
        text = path.read_text(encoding="utf-8")
        matches = tuple(marker.finditer(text))
        assert len(matches) == 1
        body = cast("str", matches[0].group("body"))
        value = require_test_object(
            load_json_value(body),
            context=f"release profile in {path}",
        )
        assert value == {
            "decision_sha256": PROFILE_DIGEST,
            "first_release_profile": "alpic-metadata",
            "schema_version": 1,
        }
        expected_body = "".join(
            (
                f'{{"decision_sha256":"{PROFILE_DIGEST}",',
                '"first_release_profile":"alpic-metadata","schema_version":1}',
            ),
        )
        assert body == expected_body
        assert (
            hashlib.sha256(PROFILE_PREIMAGE.encode("utf-8")).hexdigest()
            == value["decision_sha256"]
        )


type DeterministicPdfCase = Literal[
    "encrypted",
    "mixed",
    "raster-default",
    "raster-rotation-crop",
    "vector",
]


def _make_deterministic_pdf(path: Path, pdf_case: DeterministicPdfCase) -> Path:
    match pdf_case:
        case "encrypted":
            return pdf_factory.make_encrypted_pdf(path)
        case "mixed":
            return pdf_factory.make_mixed_pdf(path)
        case "raster-default":
            return pdf_factory.make_raster_pdf(path).path
        case "raster-rotation-crop":
            return pdf_factory.make_raster_pdf(
                path,
                rotation=90,
                crop_fraction=0.5,
            ).path
        case "vector":
            return pdf_factory.make_vector_pdf(path)


@pytest.mark.parametrize(
    "pdf_case",
    [
        "raster-default",
        "raster-rotation-crop",
        "vector",
        "mixed",
        "encrypted",
    ],
)
def test_pdf_factories_are_byte_identical_across_distinct_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pdf_case: DeterministicPdfCase,
) -> None:
    """Freeze byte determinism independently of ambient build timestamps."""
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    first = _make_deterministic_pdf(tmp_path / f"first-{pdf_case}.pdf", pdf_case)
    second = _make_deterministic_pdf(
        tmp_path / f"second-{pdf_case}.pdf",
        pdf_case,
    )

    assert first != second
    first_bytes = first.read_bytes()
    second_bytes = second.read_bytes()
    assert first_bytes.startswith(b"%PDF-")
    assert second_bytes.startswith(b"%PDF-")
    assert first_bytes == second_bytes


TASK1_OWNED_PYTHON_FILES = (
    "scripts/capture_baseline.py",
    "scripts/baseline_capture_io.py",
    "scripts/baseline_replay.py",
    "scripts/bootstrap_toolchain.py",
    "tests/contracts/test_frozen_baseline.py",
    "tests/helpers/pdf_factory.py",
)
PYRIGHT_DIRECTIVE_PREFIX_PATTERN = re.compile(r"#\s*pyright:\s*")
PYRIGHT_CONFIGURATION_ASSIGNMENT_PATTERN = re.compile(
    r"\A(?P<name>[A-Za-z][A-Za-z0-9]*)\s*=\s*(?P<value>[A-Za-z]+)\Z",
)
PYRIGHT_MODES = frozenset({"basic", "standard", "strict"})
PYRIGHT_BOOLEAN_CONFIGURATION_RULES = frozenset(
    {
        "analyzeUnannotatedFunctions",
        "deprecateTypingAliases",
        "disableBytesTypePromotions",
        "enableExperimentalFeatures",
        "strictDictionaryInference",
        "strictListInference",
        "strictParameterNoneValue",
        "strictSetInference",
    },
)
PYRIGHT_DIAGNOSTIC_RULES = frozenset(
    {
        "reportAbstractUsage",
        "reportArgumentType",
        "reportAssertAlwaysTrue",
        "reportAssertTypeFailure",
        "reportAssignmentType",
        "reportAttributeAccessIssue",
        "reportCallInDefaultInitializer",
        "reportCallIssue",
        "reportConstantRedefinition",
        "reportDeprecated",
        "reportDuplicateImport",
        "reportFunctionMemberAccess",
        "reportGeneralTypeIssues",
        "reportImplicitOverride",
        "reportImplicitStringConcatenation",
        "reportIncompatibleMethodOverride",
        "reportIncompatibleVariableOverride",
        "reportImportCycles",
        "reportIncompleteStub",
        "reportInconsistentConstructor",
        "reportInconsistentOverload",
        "reportIndexIssue",
        "reportInvalidStringEscapeSequence",
        "reportInvalidStubStatement",
        "reportInvalidTypeArguments",
        "reportInvalidTypeForm",
        "reportInvalidTypeVarUse",
        "reportMatchNotExhaustive",
        "reportMissingImports",
        "reportMissingModuleSource",
        "reportMissingParameterType",
        "reportMissingSuperCall",
        "reportMissingTypeArgument",
        "reportMissingTypeStubs",
        "reportNoOverloadImplementation",
        "reportOperatorIssue",
        "reportOptionalCall",
        "reportOptionalContextManager",
        "reportOptionalIterable",
        "reportOptionalMemberAccess",
        "reportOptionalOperand",
        "reportOptionalSubscript",
        "reportOverlappingOverload",
        "reportPossiblyUnboundVariable",
        "reportPrivateImportUsage",
        "reportPrivateUsage",
        "reportPropertyTypeMismatch",
        "reportRedeclaration",
        "reportReturnType",
        "reportSelfClsParameterName",
        "reportTypedDictNotRequiredAccess",
        "reportTypeCommentUsage",
        "reportUnboundVariable",
        "reportUndefinedVariable",
        "reportUnhashable",
        "reportUnknownArgumentType",
        "reportUnknownLambdaType",
        "reportUnknownMemberType",
        "reportUnknownParameterType",
        "reportUnknownVariableType",
        "reportUnnecessaryCast",
        "reportUnnecessaryComparison",
        "reportUnnecessaryContains",
        "reportUnnecessaryIsInstance",
        "reportUnnecessaryTypeIgnoreComment",
        "reportUninitializedInstanceVariable",
        "reportUnreachable",
        "reportUnsupportedDunderAll",
        "reportUntypedBaseClass",
        "reportUntypedClassDecorator",
        "reportUntypedFunctionDecorator",
        "reportUntypedNamedTuple",
        "reportUnusedCallResult",
        "reportUnusedClass",
        "reportUnusedCoroutine",
        "reportUnusedExcept",
        "reportUnusedExpression",
        "reportUnusedFunction",
        "reportUnusedImport",
        "reportUnusedVariable",
        "reportWildcardImportFromLibrary",
    },
)
PYRIGHT_BOOLEAN_VALUES = frozenset({"false", "true"})
PYRIGHT_SEVERITY_VALUES = frozenset(
    {"error", "false", "information", "none", "true", "warning"},
)
PYRIGHT_IGNORE_BRACKET_CONTENT_PATTERN = re.compile(
    r"\A[A-Za-z0-9_,\t \-]*\Z",
)
MYPY_DIRECTIVE_PREFIX = "# mypy: "
MYPY_DEFAULT_SECTION_NAMES = frozenset({"disable_error_code", "enable_error_code"})
LOWERCASE_COVERAGE_PREFIX = "# pragma:"
UPPERCASE_COVERAGE_PREFIX = "# PRAGMA"
COVERAGE_CONTROL_PATTERN = re.compile(
    r"""
    (?:\A \# | \#) \s* (?:pragma | PRAGMA) [: \s]? \s*
    (?:no | NO) \s* (?:cover | COVER | branch | BRANCH)
    """,
    flags=re.VERBOSE,
)
TASK1_STATIC_DIRECTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:\A#|#)\s*(?i:noqa)(?=\s|:|$)"),
    re.compile(r"#\s*(?:ruff|flake8)\s*:\s*(?i:noqa)(?=\s|:|$)"),
    re.compile(r"(?:\A#|#)\s*ruff\s*:\s*ignore\s*\["),
    re.compile(r"#\s*ruff\s*:\s*file-ignore\s*\["),
    re.compile(r"#\s*ruff\s*:\s*(?:disable|enable)\s*\["),
    re.compile(r"\A#\s*(?:ruff\s*:\s*)?fmt\s*:\s*(?:off|on)\s*\Z"),
    re.compile(
        r"""
        \A \# \s* (?:ruff \s* : \s*)? isort \s* : \s*
        (?:
            on | off | skip_file | split |
            dont-add-imports (?:\s* : \s* \[[^\]\r\n]*\])?
        )
        \s* \Z
        """,
        flags=re.VERBOSE,
    ),
    re.compile(r"\A#\s*yapf\s*:\s*(?:disable|enable)\s*\Z"),
    re.compile(r"\A#\s*type\s*:\s*ignore(?=\s*(?:\[|#|$))"),
    re.compile(r"(?:\A#|#)\s*nosec"),
    re.compile(r"(?:\A#|#)\s*nosemgrep(?=\s|:|$)"),
)
TASK1_INLINE_STATIC_DIRECTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"#\s*(?:ruff\s*:\s*)?fmt\s*:\s*skip(?=\s|$)"),
    re.compile(r"#\s*(?:ruff\s*:\s*)?isort\s*:\s*skip"),
)
FIRST_LINE_WITH_SUPPRESSION_RATIONALE = 4


@dataclass(frozen=True, slots=True)
class SuppressionOccurrence:
    """One explicitly reviewed local static-analysis suppression."""

    path: str
    line: int
    rationale: tuple[str, str, str]
    directive: str


EXPECTED_TASK1_SUPPRESSIONS = (
    SuppressionOccurrence(
        path="scripts/baseline_capture_io.py",
        line=1349,
        rationale=(
            "# Security rationale: command[0] is an absolute reviewed executable.",
            (
                "# Callers pass tuple argv and a closed environment; "
                "output/time are bounded."
            ),
            (
                "# shell=False/new session are enforced; see "
                "https://github.com/astral-sh/ruff/issues/4045."
            ),
        ),
        directive="# noqa: S603",
    ),
    SuppressionOccurrence(
        path="scripts/bootstrap_toolchain.py",
        line=624,
        rationale=(
            (
                "# Security rationale: urlsplit above requires HTTPS and rejects "
                "credentials."
            ),
            "# No proxy/redirect handler is installed; reads stop at max_bytes + 1.",
            "# Ruff cannot infer these checks; S310 is limited to the next statement.",
        ),
        directive="# noqa: S310",
    ),
    SuppressionOccurrence(
        path="scripts/bootstrap_toolchain.py",
        line=985,
        rationale=(
            ("# Security rationale: argv is rendered from the reviewed, digest-pinned"),
            "# extracted artifact; shell=False and a fixed timeout are mandatory.",
            "# Ruff cannot infer these checks; S603 is limited to the next statement.",
        ),
        directive="# noqa: S603",
    ),
    SuppressionOccurrence(
        path="scripts/bootstrap_toolchain.py",
        line=1135,
        rationale=(
            (
                "# Security rationale: the executable is absolute, regular, and "
                "executable,"
            ),
            "# SHA-256 pinned, shell=False, and constrained by a fixed timeout.",
            "# Ruff cannot infer these checks; S603 is limited to the next statement.",
        ),
        directive="# noqa: S603",
    ),
    SuppressionOccurrence(
        path="scripts/bootstrap_toolchain.py",
        line=1342,
        rationale=(
            "# Compatibility rationale: selection and trust seams remain explicit.",
            "# Bundling or typed kwargs could hide misspelled security controls.",
            "# PLR0913 is limited to this stable, closed install boundary.",
        ),
        directive="# noqa: PLR0913",
    ),
    SuppressionOccurrence(
        path="tests/contracts/test_frozen_baseline.py",
        line=887,
        rationale=(
            (
                "# Security rationale: GIT_EXECUTABLE is absolute; fixed "
                "rev-parse --verify flags"
            ),
            (
                "# receive the sole caller's validated SHA-1 tree plus :src "
                "as one argv item."
            ),
            "# No shell is used; see https://github.com/astral-sh/ruff/issues/4045.",
        ),
        directive="# noqa: S603",
    ),
    SuppressionOccurrence(
        path="tests/contracts/test_frozen_baseline.py",
        line=4186,
        rationale=(
            (
                "# Security rationale: sys.executable launches only the "
                "fixed module or absolute"
            ),
            (
                "# reviewed capture_baseline.py; remaining argv is test-owned "
                "and shell=False."
            ),
            (
                "# Ruff cannot infer these invariants; see "
                "https://github.com/astral-sh/ruff/issues/4045."
            ),
        ),
        directive="# noqa: S603",
    ),
)


def _pyright_ignore_disposition(
    body: str,
) -> Literal["active", "inactive", "retry"]:
    prefix = "ignore"
    if not body.startswith(prefix):
        return "retry"
    remainder = body[len(prefix) :]
    if not remainder:
        return "active"
    if remainder[0] not in " \t[":
        return "retry"
    return _pyright_bracket_disposition(remainder.lstrip(" \t"))


def _pyright_bracket_disposition(
    remainder: str,
) -> Literal["active", "inactive", "retry"]:
    if not remainder or not remainder.startswith("["):
        return "active"
    closing_bracket = remainder.find("]")
    if closing_bracket < 0:
        return "retry"
    bracket_content = remainder[1:closing_bracket]
    if PYRIGHT_IGNORE_BRACKET_CONTENT_PATTERN.fullmatch(bracket_content) is None:
        return "retry"
    rules = tuple(item.strip() for item in bracket_content.split(","))
    if any(rule in PYRIGHT_DIAGNOSTIC_RULES for rule in rules):
        return "active"
    return "inactive"


def _is_pyright_configuration_item(item: str) -> bool:
    if item in PYRIGHT_MODES:
        return True
    match = PYRIGHT_CONFIGURATION_ASSIGNMENT_PATTERN.fullmatch(item)
    if match is None:
        return False
    name = cast("str", match.group("name"))
    value = cast("str", match.group("value"))
    if name in PYRIGHT_BOOLEAN_CONFIGURATION_RULES:
        return value in PYRIGHT_BOOLEAN_VALUES
    return name in PYRIGHT_DIAGNOSTIC_RULES and value in PYRIGHT_SEVERITY_VALUES


def _is_pyright_control_directive(comment: str) -> bool:
    for match in PYRIGHT_DIRECTIVE_PREFIX_PATTERN.finditer(comment):
        body = comment[match.end() :].strip()
        disposition = _pyright_ignore_disposition(body)
        if disposition == "active":
            return True
        if disposition == "inactive":
            return False

    configuration_match = PYRIGHT_DIRECTIVE_PREFIX_PATTERN.match(comment)
    if configuration_match is None:
        return False
    body = comment[configuration_match.end() :].strip()
    if body.startswith("ignore"):
        return False
    items = tuple(item.strip() for item in body.split(","))
    return bool(items) and any(_is_pyright_configuration_item(item) for item in items)


def _is_mypy_control_directive(comment: str, *, source_prefix: str) -> bool:
    if source_prefix or not comment.startswith(MYPY_DIRECTIVE_PREFIX):
        return False
    sections, _errors = parse_mypy_comments(
        [(1, comment.removeprefix(MYPY_DIRECTIVE_PREFIX))],
        Options(),
    )
    return any(
        name not in MYPY_DEFAULT_SECTION_NAMES or bool(value)
        for name, value in sections.items()
    )


def _is_task1_static_directive(comment: str, *, source_prefix: str) -> bool:
    return (
        _is_pyright_control_directive(comment)
        or _is_mypy_control_directive(comment, source_prefix=source_prefix)
        or any(
            pattern.search(comment) is not None
            for pattern in TASK1_STATIC_DIRECTIVE_PATTERNS
        )
        or (
            bool(source_prefix.strip())
            and any(
                pattern.search(comment) is not None
                for pattern in TASK1_INLINE_STATIC_DIRECTIVE_PATTERNS
            )
        )
    )


def _task1_suppression_inventory() -> tuple[SuppressionOccurrence, ...]:
    repository = Path(__file__).resolve().parents[2]
    occurrences: list[SuppressionOccurrence] = []
    for relative_path in TASK1_OWNED_PYTHON_FILES:
        source = (repository / relative_path).read_bytes()
        source_lines = source.decode("utf-8").splitlines()
        for token in tokenize.tokenize(io.BytesIO(source).readline):
            if token.type != tokenize.COMMENT:
                continue
            line = token.start[0]
            source_prefix = source_lines[line - 1][: token.start[1]]
            if not _is_task1_static_directive(
                token.string,
                source_prefix=source_prefix,
            ):
                continue
            if line < FIRST_LINE_WITH_SUPPRESSION_RATIONALE:
                rationale = ("", "", "")
            else:
                rationale = (
                    source_lines[line - 4].strip(),
                    source_lines[line - 3].strip(),
                    source_lines[line - 2].strip(),
                )
            occurrences.append(
                SuppressionOccurrence(
                    path=relative_path,
                    line=line,
                    rationale=rationale,
                    directive=token.string,
                ),
            )
        for line, source_line in enumerate(source_lines, start=1):
            match = COVERAGE_CONTROL_PATTERN.search(source_line)
            if match is None:
                continue
            if line < FIRST_LINE_WITH_SUPPRESSION_RATIONALE:
                rationale = ("", "", "")
            else:
                rationale = (
                    source_lines[line - 4].strip(),
                    source_lines[line - 3].strip(),
                    source_lines[line - 2].strip(),
                )
            occurrences.append(
                SuppressionOccurrence(
                    path=relative_path,
                    line=line,
                    rationale=rationale,
                    directive=match.group(0),
                ),
            )
    return tuple(occurrences)


def test_task1_owned_python_suppressions_match_closed_inventory() -> None:
    """Reject every unreviewed, moved, or altered Task-1 suppression."""
    assert _task1_suppression_inventory() == EXPECTED_TASK1_SUPPRESSIONS


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            (
                "# Security rationale: urlsplit above requires HTTPS and rejects "
                "credentials."
            ),
            "# Security rationale: altered",
        ),
        ("# noqa: S310", "# noqa: S310, S603"),
        ("# noqa: S603", "# noqa: S603\n# noqa: S603"),
        ("# noqa: PLR0913", ""),
        (
            "# Copyright (c) 2026 David Osipov",
            "\n# Copyright (c) 2026 David Osipov",
        ),
        ("# noqa: PLR0913", "# noqa: PLR0913\n# noqa: S310"),
    ],
    ids=(
        "changed-rationale",
        "multi-rule",
        "duplicate",
        "missing",
        "moved",
        "fifth",
    ),
)
def test_bootstrap_suppression_inventory_rejects_mutants(
    monkeypatch: pytest.MonkeyPatch,
    old: str,
    new: str,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    target = (repository / "scripts/bootstrap_toolchain.py").resolve(strict=True)
    original_read_bytes = Path.read_bytes
    original_source = original_read_bytes(target).decode("utf-8")
    assert old in original_source
    mutated_source = original_source.replace(old, new, 1).encode()

    def read_bytes_with_bootstrap_mutant(path: Path) -> bytes:
        if path.resolve(strict=True) == target:
            return mutated_source
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes_with_bootstrap_mutant)
    assert _task1_suppression_inventory() != EXPECTED_TASK1_SUPPRESSIONS


def _inventory_with_injected_source(
    monkeypatch: pytest.MonkeyPatch,
    injected_source: str,
) -> tuple[SuppressionOccurrence, ...]:
    repository = Path(__file__).resolve().parents[2]
    target = (repository / "scripts/capture_baseline.py").resolve(strict=True)
    original_read_bytes = Path.read_bytes

    def read_bytes_with_injected_source(path: Path) -> bytes:
        source = original_read_bytes(path)
        if path.resolve(strict=True) == target:
            return injected_source.encode("utf-8") + source
        return source

    monkeypatch.setattr(Path, "read_bytes", read_bytes_with_injected_source)
    return _task1_suppression_inventory()


def _inventory_with_injected_comment(
    monkeypatch: pytest.MonkeyPatch,
    comment: str,
) -> tuple[SuppressionOccurrence, ...]:
    return _inventory_with_injected_source(monkeypatch, f"{comment}\n")


PINNED_PYRIGHT_1_1_413_DIAGNOSTIC_RULES = (
    "reportGeneralTypeIssues",
    "reportPropertyTypeMismatch",
    "reportFunctionMemberAccess",
    "reportMissingImports",
    "reportMissingModuleSource",
    "reportInvalidTypeForm",
    "reportMissingTypeStubs",
    "reportImportCycles",
    "reportUnusedImport",
    "reportUnusedClass",
    "reportUnusedFunction",
    "reportUnusedVariable",
    "reportDuplicateImport",
    "reportWildcardImportFromLibrary",
    "reportAbstractUsage",
    "reportArgumentType",
    "reportAssertTypeFailure",
    "reportAssignmentType",
    "reportAttributeAccessIssue",
    "reportCallIssue",
    "reportInconsistentOverload",
    "reportIndexIssue",
    "reportInvalidTypeArguments",
    "reportNoOverloadImplementation",
    "reportOperatorIssue",
    "reportOptionalSubscript",
    "reportOptionalMemberAccess",
    "reportOptionalCall",
    "reportOptionalIterable",
    "reportOptionalContextManager",
    "reportOptionalOperand",
    "reportRedeclaration",
    "reportReturnType",
    "reportTypedDictNotRequiredAccess",
    "reportUntypedFunctionDecorator",
    "reportUntypedClassDecorator",
    "reportUntypedBaseClass",
    "reportUntypedNamedTuple",
    "reportPrivateUsage",
    "reportTypeCommentUsage",
    "reportPrivateImportUsage",
    "reportConstantRedefinition",
    "reportDeprecated",
    "reportIncompatibleMethodOverride",
    "reportIncompatibleVariableOverride",
    "reportInconsistentConstructor",
    "reportOverlappingOverload",
    "reportPossiblyUnboundVariable",
    "reportMissingSuperCall",
    "reportUninitializedInstanceVariable",
    "reportInvalidStringEscapeSequence",
    "reportUnknownParameterType",
    "reportUnknownArgumentType",
    "reportUnknownLambdaType",
    "reportUnknownVariableType",
    "reportUnknownMemberType",
    "reportMissingParameterType",
    "reportMissingTypeArgument",
    "reportInvalidTypeVarUse",
    "reportCallInDefaultInitializer",
    "reportUnnecessaryIsInstance",
    "reportUnnecessaryCast",
    "reportUnnecessaryComparison",
    "reportUnnecessaryContains",
    "reportAssertAlwaysTrue",
    "reportSelfClsParameterName",
    "reportImplicitStringConcatenation",
    "reportUndefinedVariable",
    "reportUnhashable",
    "reportUnboundVariable",
    "reportInvalidStubStatement",
    "reportIncompleteStub",
    "reportUnsupportedDunderAll",
    "reportUnusedCallResult",
    "reportUnusedCoroutine",
    "reportUnusedExcept",
    "reportUnusedExpression",
    "reportUnnecessaryTypeIgnoreComment",
    "reportMatchNotExhaustive",
    "reportUnreachable",
    "reportImplicitOverride",
)
PINNED_PYRIGHT_DIAGNOSTIC_RULE_COUNT = 81


def test_task1_inventory_binds_exact_pinned_pyright_diagnostic_rule_set() -> None:
    assert (
        len(PINNED_PYRIGHT_1_1_413_DIAGNOSTIC_RULES)
        == PINNED_PYRIGHT_DIAGNOSTIC_RULE_COUNT
    )
    assert (
        len(frozenset(PINNED_PYRIGHT_1_1_413_DIAGNOSTIC_RULES))
        == PINNED_PYRIGHT_DIAGNOSTIC_RULE_COUNT
    )
    assert (
        frozenset(
            PINNED_PYRIGHT_1_1_413_DIAGNOSTIC_RULES,
        )
        == PYRIGHT_DIAGNOSTIC_RULES
    )


@pytest.mark.parametrize(
    "comment",
    [
        "# pyright: basic",
        "# pyright: standard",
        "# pyright: strict",
        "# pyright: reportUninitializedInstanceVariable=false",
        "# pyright: reportMissingImports=none",
        "# pyright: reportUnknownVariableType=warning",
        "# pyright: basic, reportMissingImports=false",
        "# pyright: strictListInference=false",
        "# pyright: analyzeUnannotatedFunctions=false",
        "# pyright: strictListInference=false, invalid prose",
        "# pyright: ignore",
        "# pyright: ignore because this assignment is reviewed",
        "# pyright: ignore[reportArgumentType]",
        "# pyright: ignore[reportArgumentType] because this call is reviewed",
        "# pyright: ignore [reportArgumentType] because this call is reviewed",
        "# pyright: ignore[reportArgumentType]suffix",
        "# pyright: ignore[reportAssignmentType,]",
        "# pyright: ignore[,reportAssignmentType]",
        "# pyright: ignore[reportAssignmentType,,reportArgumentType]",
        "# pyright: ignore[reportAssignmentType,bogus]",
        "# documentation # pyright: ignore[reportAssignmentType]",
        "# pyright: ignore[bad # pyright: ignore[reportAssignmentType]",
        "# pyright: ignoreXYZ # pyright: ignore[reportAssignmentType]",
        "# pyright: ignore[reportIncompatibleMethodOverride]",
        "# pyright: ignore[reportIncompatibleVariableOverride]",
        "# pyright: reportIncompatibleMethodOverride=false",
        "# pyright: reportIncompatibleVariableOverride=none",
    ],
)
def test_task1_inventory_rejects_pyright_control_directives(
    monkeypatch: pytest.MonkeyPatch,
    comment: str,
) -> None:
    assert (
        _inventory_with_injected_comment(
            monkeypatch,
            comment,
        )
        != EXPECTED_TASK1_SUPPRESSIONS
    )


@pytest.mark.parametrize(
    "comment",
    [
        "# mypy: disable-error-code=ignore-without-code",
        "# mypy: enable-error-code=attr-defined",
        "# mypy: allow-untyped-defs",
        "# mypy: allow-redefinition",
        "# mypy: ignore-errors",
        "# mypy: warn-unused-ignores = False",
        "# mypy: disallow_any_expr = False",
        "# mypy: disable_error_code = attr-defined",
        '# mypy: disable-error-code="assignment,return-value"',
        "# mypy: IGNORE_ERRORS = True",
        "# mypy: ALLOW_UNTYPED_DEFS",
        "# mypy: DISABLE_ERROR_CODE=assignment",
        "# mypy: ignore-errors,",
        "# mypy: allow-untyped-defs,",
        "# mypy: IGNORE_ERRORS,",
        "# mypy: always-false=TYPE_CHECKING",
        "# mypy: ignore-errors,,",
        "# mypy: ,ignore-errors",
        "# mypy: ignore-errors,,allow-untyped-defs",
        '# mypy: "ignore-errors"',
        '# mypy: i"gnore"-errors',
        '# mypy: ""ignore-errors',
        '# mypy: ignore-errors,""',
        '# mypy: ignore-errors, ""',
        '# mypy: "disable-error-code=assignment"',
        '# mypy: disable-"error-code"=assignment',
        '# mypy: "ignore-errors","allow-untyped-defs"',
        '# mypy: ignore-errors,"',
        "# mypy: ignore-errors, arbitrary prose",
    ],
)
def test_task1_inventory_rejects_mypy_control_directives(
    monkeypatch: pytest.MonkeyPatch,
    comment: str,
) -> None:
    assert (
        _inventory_with_injected_comment(
            monkeypatch,
            comment,
        )
        != EXPECTED_TASK1_SUPPRESSIONS
    )


@pytest.mark.parametrize(
    "comment",
    [
        "# fmt: off",
        "# fmt: on",
        "# ruff: fmt: off",
        "# ruff: fmt: on",
        "# noqa",
        "# noqa: E501",
        "# ruff: noqa",
        "# ruff: noqa: E501",
        "# documentation # ruff: noqa",
        "# flake8: noqa",
        "# NOQA: E501",
        "# ruff: ignore[F401]",
        "# ruff: ignore [F401] because this is reviewed",
        "# ruff: file-ignore[F821]",
        "# ruff: file-ignore [F821]",
        "# ruff:file-ignore[F821]",
        "# ruff: disable[F821]",
        "# ruff:disable [F821]",
        "# ruff: enable[F821]",
        "# isort: off",
        "# isort: on",
        "# isort: skip_file",
        "# isort: split",
        "# isort: dont-add-imports",
        "# yapf: disable",
        "# yapf: enable",
    ],
)
def test_task1_inventory_rejects_linter_formatter_and_import_sort_directives(
    monkeypatch: pytest.MonkeyPatch,
    comment: str,
) -> None:
    assert (
        _inventory_with_injected_comment(
            monkeypatch,
            comment,
        )
        != EXPECTED_TASK1_SUPPRESSIONS
    )


@pytest.mark.parametrize(
    "comment",
    [
        "# type: ignore",
        "# type: ignore[attr-defined]",
        "# type: ignore [attr-defined, assignment]",
        "# nosec",
        "# nosec B603, B607",
        "# nosec: B603",
        "# nosecurity scanner is configured elsewhere.",
        "# nosemgrep",
        "# nosemgrep: python.lang.security.audit.subprocess-shell-true",
        f"{LOWERCASE_COVERAGE_PREFIX} no cover",
        f"{LOWERCASE_COVERAGE_PREFIX} no branch",
        f"{LOWERCASE_COVERAGE_PREFIX} no coverage",
        f"{UPPERCASE_COVERAGE_PREFIX}: NO COVER",
        f"{UPPERCASE_COVERAGE_PREFIX} NO BRANCH",
    ],
)
def test_task1_inventory_rejects_type_security_and_coverage_directives(
    monkeypatch: pytest.MonkeyPatch,
    comment: str,
) -> None:
    assert (
        _inventory_with_injected_comment(
            monkeypatch,
            comment,
        )
        != EXPECTED_TASK1_SUPPRESSIONS
    )


@pytest.mark.parametrize(
    "comment",
    [
        "# This prose says noqa without being a directive.",
        '# This prose mentions "pyright: basic".',
        '# This prose mentions "mypy: disable-error-code".',
        "# fmt: offshore",
        "# pragma: coverage is discussed.",
        "# The security scanner is configured elsewhere.",
        '# This prose mentions "type: ignore".',
        "# ruff: format is discussed, not disabled.",
        "# isort: sorted imports are documented.",
        "# Pyright: basic",
        "# pyright: ignore[]",
        "# pyright: ignore[,]",
        "# pyright: ignore[invalidRule]",
        "# pyright: ignore[reportBogus]",
        "# pyright: reportBogus=false",
        "# pyright: ignoreXYZ, reportAssignmentType=false",
        "# MYPY: ignore-errors",
        "# mypy:ignore-errors",
        "# mypy:\tignore-errors",
        "#  mypy: ignore-errors",
        "# mypy: ignore-errors = true trailing prose",
        "# fmt: skip",
        "# ruff: fmt: skip",
        "# documentation # fmt: skip",
        "# isort: skip",
        "# isort: skip because this import order is reviewed",
        "# ruff: isort: skip because this import order is reviewed",
        "# documentation # isort: skipper",
        "# isort: skip_file because this prose is not a directive",
        "# ruff: isort: skip_file because this prose is not a directive",
        "# RUFF: noqa",
    ],
)
def test_task1_inventory_permits_benign_comment_near_matches(
    monkeypatch: pytest.MonkeyPatch,
    comment: str,
) -> None:
    assert (
        _inventory_with_injected_comment(monkeypatch, comment)
        == EXPECTED_TASK1_SUPPRESSIONS
    )


@pytest.mark.parametrize(
    "injected_source",
    [
        'TEXT = "# pyright: basic"\n',
        'TEXT = "# mypy: ignore-errors"\n',
        'TEXT = "# noqa: S603"\n',
    ],
)
def test_task1_inventory_ignores_directive_text_inside_string_tokens(
    monkeypatch: pytest.MonkeyPatch,
    injected_source: str,
) -> None:
    assert (
        _inventory_with_injected_source(monkeypatch, injected_source)
        == EXPECTED_TASK1_SUPPRESSIONS
    )


@pytest.mark.parametrize(
    "injected_source",
    [
        f'TEXT = "{LOWERCASE_COVERAGE_PREFIX} no cover"\n',
        f'TEXT = "{LOWERCASE_COVERAGE_PREFIX} no coverage"\n',
        f'TEXT = "documentation {LOWERCASE_COVERAGE_PREFIX} no cover"\n',
        f'if "{LOWERCASE_COVERAGE_PREFIX} no branch":\n    pass\n',
        f'if "{LOWERCASE_COVERAGE_PREFIX} no branching":\n    pass\n',
    ],
)
def test_task1_inventory_rejects_raw_coverage_directives_in_strings(
    monkeypatch: pytest.MonkeyPatch,
    injected_source: str,
) -> None:
    assert (
        _inventory_with_injected_source(monkeypatch, injected_source)
        != EXPECTED_TASK1_SUPPRESSIONS
    )


@pytest.mark.parametrize(
    "injected_source",
    [
        "    # mypy: ignore-errors\n",
        "value = object()  # mypy: ignore-errors\n",
    ],
)
def test_task1_inventory_permits_mypy_directives_outside_column_zero(
    monkeypatch: pytest.MonkeyPatch,
    injected_source: str,
) -> None:
    assert (
        _inventory_with_injected_source(monkeypatch, injected_source)
        == EXPECTED_TASK1_SUPPRESSIONS
    )


@pytest.mark.parametrize(
    "injected_source",
    [
        "value = object()  # pyright: ignore[reportAssignmentType]\n",
        "import os  # ruff: ignore[F401]\n",
        "value    =    1  # documentation # fmt: skip\n",
        "import zlib  # isort: skip\nimport os\n",
        "import zlib  # isort: skip because reviewed\nimport os\n",
        "import zlib  # ruff: isort: skipper\nimport os\n",
        "value = object()  # type: ignore[assignment]\n",
        "value = object()  # nosec B101\n",
    ],
)
def test_task1_inventory_rejects_active_inline_comment_directives(
    monkeypatch: pytest.MonkeyPatch,
    injected_source: str,
) -> None:
    assert (
        _inventory_with_injected_source(monkeypatch, injected_source)
        != EXPECTED_TASK1_SUPPRESSIONS
    )


class _WrongDownloadSetupTools:
    """Return the wrong strict model at the replay setup boundary."""

    async def call(self, _name: str, _arguments: JsonObject) -> JsonObject:
        return {}


@pytest.mark.asyncio
async def test_replay_setup_rejects_wrong_download_output_model() -> None:
    setup = next(
        case.setup
        for case in _CASE_DEFINITIONS()
        if isinstance(case.setup, baseline_replay.DocumentReplaySetup)
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="document setup returned the wrong strict output model",
    ):
        await _APPLY_REPLAY_SETUP(
            cast("ToolService", _WrongDownloadSetupTools()),
            setup,
        )


@pytest.mark.asyncio
async def test_replay_setup_rejects_wrong_render_output_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = make_tool_service(tmp_path)
    setup = next(
        case.setup
        for case in _CASE_DEFINITIONS()
        if isinstance(case.setup, baseline_replay.RenderReplaySetup)
    )
    original_call = type(tools).call

    async def wrong_render_call(
        service: ToolService,
        name: str,
        arguments: JsonObject,
    ) -> StrictOutput:
        if name == "render_pdf_pages":
            return cast("StrictOutput", {})
        return await original_call(service, name, arguments)

    monkeypatch.setattr(type(tools), "call", wrong_render_call)

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="render setup returned the wrong strict output model",
    ):
        await _APPLY_REPLAY_SETUP(tools, setup)
