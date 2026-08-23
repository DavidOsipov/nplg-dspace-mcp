# Copyright (c) 2026 David Osipov
"""Externally contained release-quality coverage and diff authority."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import math
import os
import re
import shutil
import stat
import sys
import sysconfig
import tempfile
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal, NoReturn, Protocol, TextIO, cast
from xml.etree.ElementTree import Element, ParseError

if __name__ == "__main__" and not __package__:
    script_package_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, script_package_root.as_posix())
    __package__ = "scripts"

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from scripts.baseline_capture_io import (
    BaselineCaptureError,
    ObjectDatabaseEntry,
    ProcessLimits,
    object_database_inventory,
    run_bounded_process,
)
from scripts.run_quality_gate import GateError as QualityGateError
from scripts.run_quality_gate import parse_registered_worktrees

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from types import ModuleType

_MAX_POLICY_BYTES = 64 * 1024
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 4096
_MAX_REPORT_JSON_NODES = 2_000_000
_MAX_REPORT_JSON_DEPTH = 64
_MAX_XML_ELEMENTS = 2_000_000
_MAX_RELATIVE_NAME = 4096
_CONTROL_CHARACTER_LIMIT = 32
_DELETE_CHARACTER = 127
_PERCENT_SCALE = 100
_MAX_RATE_CHARACTERS = 64
_BRANCH_PAIR_LENGTH = 2
_MAX_PACKAGE_FILE_BYTES = 16 * 1024 * 1024
_MAX_PACKAGE_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_PACKAGE_MANIFEST_BYTES = 4 * 1024 * 1024
_PACKAGE_READ_CHUNK_BYTES = 64 * 1024
_MAX_FILE_MODE = 0o777
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_DIFF_HUNK_PATTERN = re.compile(
    rb"^@@ -[0-9]+(?:,[0-9]+)? \+(?P<start>[0-9]+)(?:,(?P<count>[0-9]+))? @@"
)
_MAX_GIT_OUTPUT_BYTES = 32 * 1024 * 1024
_MAX_SNAPSHOT_FILE_BYTES = 64 * 1024 * 1024
_MAX_SNAPSHOT_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_SNAPSHOT_ENTRIES = 100_000
_MAX_COLLECTED_NODES = 100_000
_MAX_NODE_ID_BYTES = 16 * 1024
_MAX_GIT_REF_BYTES = 1024
_TRACKED_FIELD_COUNT = 3
_ENVIRONMENT_PAIR_LENGTH = 2
_PYTEST_CALL_FIELD_COUNT = 2
_PRIVATE_DIRECTORY_MODE = 0o700
_MAX_PROCESS_ARGUMENT_BYTES = 1024 * 1024
_MAX_PROCESS_TIMEOUT_SECONDS = 86_400.0
_MAX_PROCESS_STREAM_BYTES = 64 * 1024 * 1024
_PYTEST_NO_TESTS_COLLECTED = 5
_SUCCESS_RETURN_CODES = frozenset({0})
_GIT_EXECUTABLE = "/usr/bin/git"
_SUPPORTED_PYTHON_VERSIONS = frozenset({(3, 12), (3, 13), (3, 14)})
_PINNED_RUNTIME_DISTRIBUTIONS = (
    ("coverage", "7.15.4"),
    ("diff-cover", "10.5.0"),
    ("hypothesis", "6.165.9"),
    ("pytest", "9.1.1"),
)
_TRUSTED_TOOL_MODULES = (
    ("coverage", "coverage", "7.15.4"),
    ("diff_cover", "diff-cover", "10.5.0"),
    ("pytest", "pytest", "9.1.1"),
)
_MUTATION_TRUSTED_TOOL_MODULES = (
    ("mutmut", "mutmut", "3.7.0"),
    ("pytest", "pytest", "9.1.1"),
    ("coverage", "coverage", "7.15.4"),
)
_TRUSTED_TOOL_SHADOWS = (
    "coverage.py",
    "coverage/",
    "diff_cover.py",
    "diff_cover/",
    "pytest.py",
    "pytest/",
    "sitecustomize.py",
    "usercustomize.py",
)
_MUTATION_TOOL_SHADOWS = (
    "mutmut.py",
    "mutmut/",
    "pytest.py",
    "pytest/",
    "coverage.py",
    "coverage/",
    "sitecustomize.py",
    "usercustomize.py",
)
type _TrustedPythonMode = Literal[
    "coverage",
    "coverage-pytest",
    "coverage-pytest-installed",
    "diff-cover",
    "mutmut",
    "pytest",
]
_TRUSTED_TOOL_DRIVER = """
import importlib
import importlib.util
from importlib import metadata
import json
import os
from pathlib import Path
import sys

mode = sys.argv[1]
roots = json.loads(sys.argv[2])
proof = json.loads(sys.argv[3])
raw_package_root = json.loads(sys.argv[4])
if type(roots) is not list or not all(type(item) is str for item in roots):
    raise SystemExit(97)
if type(proof) is not list:
    raise SystemExit(97)
if raw_package_root is not None and type(raw_package_root) is not str:
    raise SystemExit(97)
loaded = {}
application_package = None
for item in proof:
    if type(item) is not list or len(item) != 4:
        raise SystemExit(97)
    module_name, distribution, expected_version, expected_origin = item
    module = importlib.import_module(module_name)
    actual_origin = Path(module.__file__).resolve(strict=True).as_posix()
    if (
        metadata.version(distribution) != expected_version
        or actual_origin != expected_origin
    ):
        raise SystemExit(97)
    loaded[module_name] = module

mutation_main = None
mutation_main_origin = None
mutation_cli = None
if mode == "mutmut":
    mutmut_package = loaded.get("mutmut")
    if mutmut_package is None:
        raise SystemExit(97)
    mutation_main = importlib.import_module("mutmut.__main__")
    raw_package_origin = getattr(mutmut_package, "__file__", None)
    raw_main_origin = getattr(mutation_main, "__file__", None)
    mutation_cli = getattr(mutation_main, "cli", None)
    if (
        type(raw_package_origin) is not str
        or type(raw_main_origin) is not str
        or mutation_cli is None
    ):
        raise SystemExit(97)
    package_origin = Path(raw_package_origin).resolve(strict=True)
    mutation_main_origin = Path(raw_main_origin).resolve(strict=True)
    if (
        mutation_main_origin.parent != package_origin.parent
        or mutation_main_origin.name != "__main__.py"
    ):
        raise SystemExit(97)

def verify_loaded_tools():
    for item in proof:
        module_name, distribution, expected_version, expected_origin = item
        module = loaded[module_name]
        actual_origin = Path(module.__file__).resolve(strict=True).as_posix()
        if (
            metadata.version(distribution) != expected_version
            or actual_origin != expected_origin
        ):
            raise SystemExit(97)
    if mutation_main is not None:
        raw_main_origin = getattr(mutation_main, "__file__", None)
        if (
            sys.modules.get("mutmut.__main__") is not mutation_main
            or type(raw_main_origin) is not str
            or Path(raw_main_origin).resolve(strict=True) != mutation_main_origin
            or getattr(mutation_main, "cli", None) is not mutation_cli
        ):
            raise SystemExit(97)
    if application_package is not None:
        package, expected_package_root = application_package
        if sys.modules.get("nplg_mcp") is not package:
            raise SystemExit(97)
        package_root = Path(package.__file__).resolve(strict=True).parent
        package_paths = tuple(
            Path(value).resolve(strict=True) for value in package.__path__
        )
        if package_root != expected_package_root or package_paths != (
            expected_package_root,
        ):
            raise SystemExit(97)
        for module_name, module in tuple(sys.modules.items()):
            if module_name == "nplg_mcp" or module_name.startswith("nplg_mcp."):
                origin = getattr(module, "__file__", None)
                if type(origin) is not str:
                    raise SystemExit(97)
                resolved = Path(origin).resolve(strict=True)
                if expected_package_root not in resolved.parents:
                    raise SystemExit(97)

for root in roots:
    sys.path.append(root)
os.environ["PYTHONPATH"] = os.pathsep.join(roots)
if raw_package_root is not None:
    expected_package_root = Path(raw_package_root)
    package_init = expected_package_root / "__init__.py"
    if (
        not expected_package_root.is_absolute()
        or expected_package_root.resolve(strict=True) != expected_package_root
        or not expected_package_root.is_dir()
        or package_init.resolve(strict=True) != package_init
        or not package_init.is_file()
        or "nplg_mcp" in sys.modules
    ):
        raise SystemExit(97)
    specification = importlib.util.spec_from_file_location(
        "nplg_mcp",
        package_init,
        submodule_search_locations=[expected_package_root.as_posix()],
    )
    if specification is None or specification.loader is None:
        raise SystemExit(97)
    package = importlib.util.module_from_spec(specification)
    sys.modules["nplg_mcp"] = package
    specification.loader.exec_module(package)
    application_package = (package, expected_package_root)
verify_loaded_tools()
arguments = sys.argv[5:]
if mode == "mutmut":
    if application_package is not None or mutation_cli is None:
        raise SystemExit(97)
    returncode = mutation_cli.main(
        args=arguments,
        prog_name="mutmut",
        standalone_mode=False,
    )
    verify_loaded_tools()
    if returncode is None:
        returncode = 0
    if type(returncode) is not int:
        raise SystemExit(97)
    raise SystemExit(returncode)
if mode == "pytest":
    returncode = loaded["pytest"].main(arguments)
    verify_loaded_tools()
    raise SystemExit(returncode)
if mode == "coverage-pytest-installed":
    if application_package is None:
        raise SystemExit(97)
    mode = "coverage-pytest"
if mode == "coverage-pytest":
    rcfile = arguments.pop(0)
    audit_path = Path(arguments.pop(0))
    if arguments.pop(0) != "run":
        raise SystemExit(97)

    class AuditPlugin:
        def __init__(self):
            self.collected = []
            self.collected_set = set()
            self.deselected = []
            self.calls = []

        def pytest_collection_finish(self, session):
            self.collected = [item.nodeid for item in session.items]
            self.collected_set = set(self.collected)

        def pytest_deselected(self, items):
            self.deselected.extend(item.nodeid for item in items)

        def pytest_runtest_logreport(self, report):
            if report.when == "call" and report.nodeid in self.collected_set:
                self.calls.append([report.nodeid, report.outcome])

        def pytest_sessionfinish(self, session):
            document = {
                "version": 1,
                "collected": self.collected,
                "deselected": self.deselected,
                "calls": self.calls,
            }
            payload = json.dumps(
                document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode() + b"\\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            descriptor = os.open(audit_path, flags, 0o600)
            try:
                view = memoryview(payload)
                written = 0
                while written < len(view):
                    count = os.write(descriptor, view[written:])
                    if count <= 0:
                        raise SystemExit(97)
                    written += count
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)

    audit = AuditPlugin()
    coverage = loaded["coverage"].Coverage(config_file=rcfile)
    coverage.start()
    try:
        returncode = loaded["pytest"].main(arguments, plugins=[audit])
    finally:
        coverage.stop()
        coverage.save()
    verify_loaded_tools()
    raise SystemExit(returncode)
if mode == "coverage":
    command = importlib.import_module("coverage.cmdline")
    returncode = command.main(arguments)
    verify_loaded_tools()
    raise SystemExit(returncode)
if mode == "diff-cover":
    command = importlib.import_module("diff_cover.diff_cover_tool")
    returncode = command.main(["diff-cover", *arguments])
    verify_loaded_tools()
    raise SystemExit(returncode)
raise SystemExit(97)
"""
_ALLOWED_UNTRACKED_PREFIXES = (
    ".github/",
    "contracts/",
    "docs/",
    "scripts/",
    "security/",
    "src/",
    "tests/",
    "typings/",
)
_ALLOWED_UNTRACKED_ROOTS = frozenset(
    {
        ".gitignore",
        ".markdownlint-cli2.mjs",
        ".env.example",
        "SECURITY.md",
        "SPEC.md",
        "eslint.config.mjs",
        "package-lock.json",
        "package.json",
        "pyproject.toml",
        "pyrightconfig.json",
        "quality-baseline.json",
        "requirements-dev.in",
        "requirements-dev.lock",
        "requirements-security.lock",
        "requirements.in",
        "requirements.lock",
        "tsconfig.contracts.json",
        "uv.lock",
    }
)
_GENERATED_DIRECTORY_NAMES = frozenset(
    {
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
    }
)
_MEASURED_ROOTS = ("src/nplg_mcp", "scripts")
_DECISION_MODULES = (
    "src/nplg_mcp/admission.py",
    "src/nplg_mcp/errors.py",
    "src/nplg_mcp/http_security.py",
    "src/nplg_mcp/json_preflight.py",
    "src/nplg_mcp/network.py",
    "src/nplg_mcp/resilience.py",
    "src/nplg_mcp/pdf_executor.py",
    "src/nplg_mcp/pdf_ipc.py",
    "src/nplg_mcp/rate_limit.py",
    "src/nplg_mcp/sdk_boundary.py",
    "src/nplg_mcp/security.py",
    "src/nplg_mcp/tokens.py",
    "scripts/delete_render.py",
    "scripts/run_live_nplg_canary.py",
    "scripts/smoke_live.py",
    "scripts/run_quality_gate.py",
    "scripts/run_test_gate.py",
    "scripts/run_mutation_gate.py",
    "scripts/verify_release.py",
    "scripts/bootstrap_external_tools.py",
    "scripts/pyright_identity.py",
)
_POLICY_KEYS = frozenset(
    {
        "version",
        "project_branch_floor",
        "diff_line_floor",
        "diff_branch_arc_floor",
        "decision_module_branch_floor",
        "measured_roots",
        "decision_modules",
    }
)
_CONDITION_COVERAGE = re.compile(
    r"^(?P<percent>[0-9]{1,3})% \((?P<covered>[0-9]+)/(?P<total>[0-9]+)\)$"
)
_COVERAGE_META_KEYS = frozenset(
    {"format", "version", "timestamp", "branch_coverage", "show_contexts"}
)
_COVERAGE_SUMMARY_KEYS = frozenset(
    {
        "covered_lines",
        "num_statements",
        "percent_covered",
        "percent_covered_display",
        "missing_lines",
        "excluded_lines",
        "percent_statements_covered",
        "percent_statements_covered_display",
        "num_branches",
        "num_partial_branches",
        "covered_branches",
        "missing_branches",
        "percent_branches_covered",
        "percent_branches_covered_display",
    }
)
_COVERAGE_FILE_KEYS = frozenset(
    {
        "executed_lines",
        "summary",
        "missing_lines",
        "excluded_lines",
        "executed_branches",
        "missing_branches",
        "functions",
        "classes",
    }
)


class TestGateError(RuntimeError):
    """Raised when test-gate evidence is absent, malformed, or unstable."""


def _fail(message: str) -> NoReturn:
    raise TestGateError(message)


def _fail_from(message: str, cause: BaseException) -> NoReturn:
    raise TestGateError(message) from cause


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON object contains a duplicate key")
        result[key] = value
    return result


def _reject_json_number(_value: str) -> NoReturn:
    _fail("floating-point and non-finite JSON numbers are forbidden")


def _bounded_json_integer(value: str) -> int:
    parsed = int(value, 10)
    if not -(2**63) <= parsed < 2**63:
        _fail("JSON integer is outside the signed 64-bit range")
    return parsed


def _validate_json_shape(
    value: object,
    *,
    max_nodes: int = _MAX_JSON_NODES,
    max_depth: int = _MAX_JSON_DEPTH,
) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            _fail("JSON structure exceeds the closed resource bounds")
        if type(current) is dict:
            stack.extend(
                (item, depth + 1)
                for item in cast("dict[str, object]", current).values()
            )
        elif type(current) is list:
            stack.extend((item, depth + 1) for item in cast("list[object]", current))


def _load_closed_json(
    payload: bytes,
    *,
    max_bytes: int = _MAX_POLICY_BYTES,
    max_nodes: int = _MAX_JSON_NODES,
    max_depth: int = _MAX_JSON_DEPTH,
) -> object:
    if type(payload) is not bytes or not payload or len(payload) > max_bytes:
        _fail("JSON input is empty, oversized, or has an invalid runtime type")
    try:
        value = cast(
            "object",
            json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=_closed_object,
                parse_constant=_reject_json_number,
                parse_float=_reject_json_number,
                parse_int=_bounded_json_integer,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        _fail_from("JSON input is malformed", exc)
    _validate_json_shape(value, max_nodes=max_nodes, max_depth=max_depth)
    return value


def _bounded_coverage_float(value: str) -> Decimal:
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        _fail_from("coverage JSON number is malformed", exc)


def _load_coverage_json(payload: bytes) -> object:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_REPORT_BYTES:
        _fail("coverage JSON is empty, oversized, or has an invalid runtime type")
    try:
        value = cast(
            "object",
            json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=_closed_object,
                parse_constant=_reject_json_number,
                parse_float=_bounded_coverage_float,
                parse_int=_bounded_json_integer,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        _fail_from("coverage JSON is malformed", exc)
    _validate_json_shape(
        value,
        max_nodes=_MAX_REPORT_JSON_NODES,
        max_depth=_MAX_REPORT_JSON_DEPTH,
    )
    return value


def _require_object(value: object, *, context: str) -> dict[str, object]:
    if type(value) is not dict:
        _fail(f"{context} must be a JSON object")
    return cast("dict[str, object]", value)


def _require_exact_integer(value: object, *, expected: int, field: str) -> int:
    if type(value) is not int or value != expected:
        _fail(f"{field} must be the exact integer {expected}")
    return value


def _require_string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if type(value) is not list:
        _fail(f"{field} must be an array")
    items = cast("list[object]", value)
    if any(type(item) is not str for item in items):
        _fail(f"{field} entries must be strings")
    result = tuple(cast("list[str]", items))
    if len(result) != len(set(result)):
        _fail(f"{field} entries must be unique")
    return result


@dataclass(frozen=True, slots=True)
class CommandRequest:
    """One shell-free command with a closed execution envelope."""

    argv: tuple[str, ...]
    cwd: Path
    environment: tuple[tuple[str, str], ...] = ()
    timeout_seconds: float = 300.0
    stdout_limit_bytes: int = 4 * 1024 * 1024
    stderr_limit_bytes: int = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CommandResult:
    """A complete bounded child-process result."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


class Executor(Protocol):
    """Injected shell-free process boundary."""

    def __call__(self, request: CommandRequest) -> CommandResult:
        """Execute one reviewed request."""
        ...


class Clock(Protocol):
    """Injected monotonic clock."""

    def monotonic(self) -> float:
        """Return monotonic seconds."""
        ...


class Filesystem(Protocol):
    """Injected read-only filesystem seam used by pure orchestration tests."""

    def read_bytes(self, path: Path) -> bytes:
        """Read one reviewed regular file."""
        ...


class Git(Protocol):
    """Injected bounded Git seam."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> CommandResult:
        """Run one reviewed Git argv."""
        ...


@dataclass(frozen=True, slots=True)
class CoveragePolicy:
    """Closed version-1 coverage policy."""

    version: int
    project_branch_floor: int
    diff_line_floor: int
    diff_branch_arc_floor: int
    decision_module_branch_floor: int
    measured_roots: tuple[str, ...]
    decision_modules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExternalGate:
    """One exact pytest node delegated to a named external class."""

    kind: Literal["live", "staging", "container"]
    node_id: str
    gate_id: str | None = None
    command_id: str | None = None
    profiles: tuple[str, ...] = ()
    mode: str | None = None
    protected_command: tuple[str, ...] = ()
    protected_cwd: str | None = None
    broker_kind: str | None = None
    authority: str | None = None
    timeout_seconds: int | None = None
    result_schema: str | None = None
    signed_proof_schema: str | None = None


@dataclass(frozen=True, slots=True)
class ExternalGateRegistry:
    """Closed version-1 external-gate registry."""

    version: int
    gates: tuple[ExternalGate, ...]


@dataclass(frozen=True, slots=True)
class CoverageReportResult:
    """Validated XML/JSON coverage measurements for one snapshot."""

    project_branch_percent: float
    diff_line_percent: float
    diff_branch_arc_percent: float
    decision_module_branch_percent: tuple[tuple[str, float], ...]


@dataclass(frozen=True, slots=True)
class _XmlFileCoverage:
    covered_branches: int
    total_branches: int
    branch_lines: frozenset[int]


@dataclass(frozen=True, slots=True)
class _JsonFileCoverage:
    covered_branches: int
    total_branches: int
    executed_lines: frozenset[int]
    missing_lines: frozenset[int]
    executed_branches: frozenset[tuple[int, int]]
    missing_branches: frozenset[tuple[int, int]]


class _CoverageStaticParser(Protocol):
    def parse_source(self) -> None: ...

    def exit_counts(self) -> dict[int, int]: ...


class _CoverageStaticParserFactory(Protocol):
    def __call__(
        self,
        text: str | None = None,
        filename: str | None = None,
        exclude: str | None = None,
    ) -> _CoverageStaticParser: ...


class _CoverageRegexJoiner(Protocol):
    def __call__(self, regexes: Sequence[str]) -> str: ...


@dataclass(frozen=True, slots=True)
class TestGateRequest:
    """Immutable developer or release test-gate request."""

    worktree: Path
    compare_branch: str
    output_dir: Path | None = None
    require_clean: bool = False
    candidate: str | None = None
    installed_package_root: Path | None = None
    package_manifest: Path | None = None


@dataclass(frozen=True, slots=True)
class TestGateResult:
    """Paths and measurements emitted by one successful test gate."""

    coverage_xml: Path
    coverage_json: Path
    measurements: CoverageReportResult


@dataclass(frozen=True, slots=True)
class InstalledFileRecord:
    """One manifest-bound installed package file."""

    path: str
    mode: int
    sha256: str


@dataclass(frozen=True, slots=True)
class InstalledPackageProof:
    """Synthetic or release inventory proof used to authorize a coverage alias."""

    source_package_root: Path
    installed_package_root: Path
    files: tuple[InstalledFileRecord, ...]
    coverage_paths_configuration: bytes


@dataclass(frozen=True, slots=True)
class _InstalledManifest:
    declared_package_data: tuple[str, ...]
    files: tuple[InstalledFileRecord, ...]


@dataclass(frozen=True, slots=True)
class _RepositoryEvidence:
    head: str
    staged_sha256: str
    refs_sha256: str
    status_sha256: str
    clean: bool


@dataclass(frozen=True, slots=True)
class _RawFileEvidence:
    path: str
    identity: tuple[int, ...]
    sha256: str


@dataclass(frozen=True, slots=True)
class _ReleaseGitEvidence:
    commit: str
    tree: str
    worktree_git_directory: Path
    common_git_directory: Path
    head: _RawFileEvidence
    index: _RawFileEvidence
    packed_refs: _RawFileEvidence | None
    refs: tuple[ObjectDatabaseEntry, ...]
    objects: tuple[ObjectDatabaseEntry, ...]


@dataclass(frozen=True, slots=True)
class _SnapshotFile:
    path: str
    mode: int
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class _SourceSnapshot:
    files: tuple[_SnapshotFile, ...]
    deleted: tuple[str, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class _MaterializedSnapshot:
    root: Path
    merge_base: str
    candidate_commit: str
    changed_lines: dict[str, frozenset[int]]


@dataclass(frozen=True, slots=True)
class _CommandEvidence:
    argv: tuple[str, ...]
    returncode: int
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str
    duration_seconds: float


@dataclass(slots=True)
class _CommandRuntime:
    executor: Executor
    clock: Clock
    environment: tuple[tuple[str, str], ...]
    evidence: list[_CommandEvidence]


@dataclass(frozen=True, slots=True)
class _ExternalSnapshotBinding:
    repository: _RepositoryEvidence
    tree: str
    copied_inputs: tuple[_SnapshotFile, ...]


@dataclass(frozen=True, slots=True)
class _GateExecution:
    request: TestGateRequest
    root: Path
    comparison_ref: str
    before: _RepositoryEvidence
    release_before: _ReleaseGitEvidence | None
    output: Path
    executor: Executor
    clock: Clock
    filesystem: Filesystem
    git: Git


@dataclass(frozen=True, slots=True)
class _InstalledRuntimeEvidence:
    manifest_payload: bytes
    discovered_package_roots: tuple[Path, ...]
    proof: InstalledPackageProof


@dataclass(frozen=True, slots=True)
class _FinalGateEvidence:
    runtime: _CommandRuntime
    source_snapshot: _SourceSnapshot
    materialized: _MaterializedSnapshot
    installed: _InstalledRuntimeEvidence | None
    external_before: _ExternalSnapshotBinding
    captured_artifacts: tuple[_SnapshotFile, ...]


def parse_coverage_policy(payload: bytes, *, root: Path) -> CoveragePolicy:
    """Parse and close the version-1 coverage policy."""
    value = _require_object(_load_closed_json(payload), context="coverage policy")
    if frozenset(value) != _POLICY_KEYS:
        _fail("coverage policy fields do not match version 1")
    canonical_root = root.resolve(strict=True)
    measured_roots = _require_string_tuple(
        value["measured_roots"],
        field="measured_roots",
    )
    decision_modules = _require_string_tuple(
        value["decision_modules"],
        field="decision_modules",
    )
    if measured_roots != _MEASURED_ROOTS:
        _fail("coverage measured roots do not match the closed policy")
    if decision_modules != _DECISION_MODULES:
        _fail("coverage decision modules do not match the closed policy")
    for relative in decision_modules:
        path = canonical_root / relative
        try:
            metadata = path.lstat()
        except OSError as exc:
            _fail_from("coverage decision module is absent", exc)
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            _fail("coverage decision module must be a regular non-symlink file")
    return CoveragePolicy(
        version=_require_exact_integer(value["version"], expected=1, field="version"),
        project_branch_floor=_require_exact_integer(
            value["project_branch_floor"],
            expected=95,
            field="project_branch_floor",
        ),
        diff_line_floor=_require_exact_integer(
            value["diff_line_floor"],
            expected=95,
            field="diff_line_floor",
        ),
        diff_branch_arc_floor=_require_exact_integer(
            value["diff_branch_arc_floor"],
            expected=95,
            field="diff_branch_arc_floor",
        ),
        decision_module_branch_floor=_require_exact_integer(
            value["decision_module_branch_floor"],
            expected=100,
            field="decision_module_branch_floor",
        ),
        measured_roots=measured_roots,
        decision_modules=decision_modules,
    )


def parse_external_gate_registry(payload: bytes) -> ExternalGateRegistry:
    """Parse the exact empty or Phase 1 provenance registry."""
    value = _require_object(
        _load_closed_json(payload),
        context="external gate registry",
    )
    if set(value) != {"version", "gates"}:
        _fail("external gate registry fields do not match version 1")
    version = _require_exact_integer(value["version"], expected=1, field="version")
    expected = [
        {
            "kind": "live",
            "node_id": (
                "tests/contracts/test_frozen_baseline.py::"
                "test_capture_check_mode_fails_closed_until_attestation_without_rewriting"
            ),
        },
        {
            "kind": "live",
            "node_id": (
                "tests/contracts/test_frozen_baseline.py::"
                "test_historical_capture_rejects_a_non_recovery_head_without_writes"
            ),
        },
        {
            "kind": "live",
            "node_id": (
                "tests/contracts/test_frozen_baseline.py::"
                "test_rejected_historical_capture_does_not_freshen_git_metadata"
            ),
        },
        {
            "kind": "live",
            "node_id": (
                "tests/integration/test_repository.py::"
                "test_live_nplg_canary_uses_bound_public_endpoint"
            ),
            "gate_id": "common.nplg-live-canary",
            "command_id": "live.nplg-bound-endpoint.v2",
            "profiles": ["alpic-metadata", "private-full"],
            "mode": "preexecuted-operational",
            "protected_command": [
                "nplg-release-controller",
                "external-gate",
                "--gate-id",
                "common.nplg-live-canary",
                "--candidate-battery-json",
                "BATTERY",
                "--controller-policy",
                "EXPECTED_POLICY",
                "--network-broker-descriptor",
                "BROKER",
                "--result-json",
                "RESULT_JSON",
            ],
            "protected_cwd": "protected-controller-root",
            "broker_kind": "one-operation-exact-nplg-origin",
            "authority": "protected-controller-network-broker",
            "timeout_seconds": 60,
            "result_schema": "nplg-live-canary.v2",
            "signed_proof_schema": "nplg-live-canary.v2",
        },
    ]
    gates = value["gates"]
    if gates == []:
        return ExternalGateRegistry(version=version, gates=())
    if gates != expected:
        _fail("external gate registry does not match the reviewed Phase 1 nodes")
    parsed: list[ExternalGate] = []
    for raw_gate in expected:
        gate = cast("dict[str, object]", raw_gate)
        parsed.append(
            ExternalGate(
                kind=cast("Literal['live', 'staging', 'container']", gate["kind"]),
                node_id=cast("str", gate["node_id"]),
                gate_id=cast("str | None", gate.get("gate_id")),
                command_id=cast("str | None", gate.get("command_id")),
                profiles=tuple(cast("list[str]", gate.get("profiles", []))),
                mode=cast("str | None", gate.get("mode")),
                protected_command=tuple(
                    cast("list[str]", gate.get("protected_command", []))
                ),
                protected_cwd=cast("str | None", gate.get("protected_cwd")),
                broker_kind=cast("str | None", gate.get("broker_kind")),
                authority=cast("str | None", gate.get("authority")),
                timeout_seconds=cast("int | None", gate.get("timeout_seconds")),
                result_schema=cast("str | None", gate.get("result_schema")),
                signed_proof_schema=cast("str | None", gate.get("signed_proof_schema")),
            )
        )
    return ExternalGateRegistry(version=version, gates=tuple(parsed))


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _canonical_measured_name(name: object, policy: CoveragePolicy) -> str:
    if type(name) is not str or not name or len(name) > _MAX_RELATIVE_NAME:
        _fail("coverage file name is empty, oversized, or not a string")
    value = name
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or "." in pure.parts
        or ".." in pure.parts
        or "\\" in value
        or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value)
        or not value.endswith(".py")
        or not any(
            value == measured or value.startswith(f"{measured}/")
            for measured in policy.measured_roots
        )
    ):
        _fail("coverage file name escapes the measured roots")
    return value


def _require_regular_snapshot_file(path: Path, *, snapshot_root: Path) -> None:
    current = snapshot_root
    metadata = snapshot_root.lstat()
    for part in path.relative_to(snapshot_root).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            _fail_from("coverage file is absent from the snapshot", exc)
        if stat.S_ISLNK(metadata.st_mode):
            _fail("coverage file traverses a symlink")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        _fail("coverage file must be a single-link regular file")


def _parse_nonnegative_integer(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        _fail(f"{field} must be a nonnegative integer")
    return value


def _parse_xml_integer(value: str | None, *, field: str) -> int:
    if value is None or not value.isascii() or not value.isdecimal():
        _fail(f"{field} must be a nonnegative decimal integer")
    return int(value, 10)


def _parse_percent(value: object, *, field: str) -> Decimal:
    if type(value) is int:
        result = Decimal(value)
    elif type(value) is Decimal:
        result = value
    else:
        _fail(f"{field} must be a finite JSON number")
    if not result.is_finite() or result < 0 or result > _PERCENT_SCALE:
        _fail(f"{field} is outside the closed percentage range")
    return result


def _parse_rate(value: str | None, *, field: str) -> Decimal:
    if value is None or len(value) > _MAX_RATE_CHARACTERS:
        _fail(f"{field} is absent or oversized")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        _fail_from(f"{field} is malformed", exc)
    if not result.is_finite() or result < 0 or result > 1:
        _fail(f"{field} is outside the closed rate range")
    return result


def _validate_rate(
    rate: Decimal,
    *,
    covered: int,
    total: int,
    field: str,
) -> None:
    if covered > total:
        _fail(f"{field} counters are impossible")
    if total == 0:
        if rate != 1:
            _fail(f"{field} must be 1 when no branches exist")
        return
    exact = Decimal(covered) / Decimal(total)
    if (covered == total and rate != 1) or abs(rate - exact) > Decimal("0.0001"):
        _fail(f"{field} disagrees with its branch counters")


def _xml_sources(root: Element, *, snapshot_root: Path) -> tuple[Path, ...]:
    source_nodes = root.findall("./sources/source")
    if not source_nodes:
        _fail("coverage XML has no source roots")
    sources: list[Path] = []
    for node in source_nodes:
        text = node.text
        if text is None or text != text.strip() or not text:
            _fail("coverage XML source root is empty or noncanonical")
        source = Path(text)
        if not source.is_absolute():
            _fail("coverage XML source root must be absolute")
        try:
            canonical = source.resolve(strict=True)
        except OSError as exc:
            _fail_from("coverage XML source root is absent", exc)
        if not canonical.is_dir() or not _is_within(canonical, snapshot_root):
            _fail("coverage XML source root escapes the snapshot")
        if canonical in sources:
            _fail("coverage XML source roots are duplicated")
        sources.append(canonical)
    return tuple(sources)


def _resolve_xml_filename(
    raw_name: str | None,
    *,
    sources: tuple[Path, ...],
    snapshot_root: Path,
    policy: CoveragePolicy,
) -> str:
    if raw_name is None or not raw_name or len(raw_name) > _MAX_RELATIVE_NAME:
        _fail("coverage XML class has no bounded filename")
    pure = PurePosixPath(raw_name)
    if (
        pure.is_absolute()
        or pure.as_posix() != raw_name
        or "." in pure.parts
        or ".." in pure.parts
        or "\\" in raw_name
        or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in raw_name)
    ):
        _fail("coverage XML class filename is noncanonical")
    matches: set[Path] = set()
    for source in sources:
        candidate = source.joinpath(*pure.parts)
        try:
            canonical = candidate.resolve(strict=True)
        except OSError:
            continue
        _require_regular_snapshot_file(canonical, snapshot_root=snapshot_root)
        matches.add(canonical)
    if len(matches) != 1:
        _fail("coverage XML class filename is absent or ambiguous")
    resolved = matches.pop().relative_to(snapshot_root).as_posix()
    return _canonical_measured_name(resolved, policy)


def _parse_xml_file_counts(
    class_node: Element,
    *,
    filename: str,
) -> _XmlFileCoverage:
    covered = 0
    total = 0
    branch_lines: set[int] = set()
    for line in class_node.findall("./lines/line"):
        branch = line.get("branch")
        if branch not in {None, "false", "true"}:
            _fail(f"coverage XML branch flag is malformed for {filename}")
        if branch != "true":
            continue
        line_number = _parse_xml_integer(
            line.get("number"),
            field=f"XML branch line for {filename}",
        )
        if line_number < 1 or line_number in branch_lines:
            _fail(f"coverage XML branch line is invalid for {filename}")
        branch_lines.add(line_number)
        condition = line.get("condition-coverage")
        match = _CONDITION_COVERAGE.fullmatch(condition or "")
        if match is None:
            _fail(f"coverage XML branch evidence is malformed for {filename}")
        condition_covered = int(match.group("covered"), 10)
        condition_total = int(match.group("total"), 10)
        displayed = int(match.group("percent"), 10)
        if (
            condition_total < 1
            or condition_covered > condition_total
            or displayed > _PERCENT_SCALE
            or abs(
                Decimal(displayed)
                - (
                    Decimal(condition_covered)
                    * _PERCENT_SCALE
                    / Decimal(condition_total)
                )
            )
            > 1
        ):
            _fail(f"coverage XML branch evidence is inconsistent for {filename}")
        covered += condition_covered
        total += condition_total
    rate = _parse_rate(
        class_node.get("branch-rate"),
        field=f"XML branch rate for {filename}",
    )
    _validate_rate(
        rate, covered=covered, total=total, field=f"XML branch rate for {filename}"
    )
    return _XmlFileCoverage(
        covered_branches=covered,
        total_branches=total,
        branch_lines=frozenset(branch_lines),
    )


def _parse_coverage_xml(
    payload: bytes,
    *,
    snapshot_root: Path,
    policy: CoveragePolicy,
) -> tuple[dict[str, _XmlFileCoverage], int, int]:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_REPORT_BYTES:
        _fail("coverage XML is empty, oversized, or has an invalid runtime type")
    try:
        root = SafeElementTree.fromstring(
            payload,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ParseError, DefusedXmlException) as exc:
        _fail_from("coverage XML is malformed or unsafe", exc)
    if root.tag != "coverage":
        _fail("coverage XML root is not coverage")
    if sum(1 for _ in root.iter()) > _MAX_XML_ELEMENTS:
        _fail("coverage XML exceeds the closed element bound")
    sources = _xml_sources(root, snapshot_root=snapshot_root)
    files: dict[str, _XmlFileCoverage] = {}
    class_nodes = root.findall("./packages/package/classes/class")
    if not class_nodes:
        _fail("coverage XML contains no measured classes")
    for class_node in class_nodes:
        filename = _resolve_xml_filename(
            class_node.get("filename"),
            sources=sources,
            snapshot_root=snapshot_root,
            policy=policy,
        )
        if filename in files:
            _fail("coverage XML contains a duplicate measured file")
        files[filename] = _parse_xml_file_counts(class_node, filename=filename)
    root_covered = _parse_xml_integer(
        root.get("branches-covered"),
        field="coverage XML branches-covered",
    )
    root_total = _parse_xml_integer(
        root.get("branches-valid"),
        field="coverage XML branches-valid",
    )
    _validate_rate(
        _parse_rate(root.get("branch-rate"), field="coverage XML branch-rate"),
        covered=root_covered,
        total=root_total,
        field="coverage XML branch-rate",
    )
    if (
        sum(item.covered_branches for item in files.values()) != root_covered
        or sum(item.total_branches for item in files.values()) != root_total
    ):
        _fail("coverage XML class counters disagree with project counters")
    return files, root_covered, root_total


def _parse_line_set(value: object, *, field: str) -> frozenset[int]:
    if type(value) is not list:
        _fail(f"{field} must be an array")
    values = cast("list[object]", value)
    if any(type(item) is not int or item < 1 for item in values):
        _fail(f"{field} must contain positive integer line numbers")
    result = frozenset(cast("list[int]", values))
    if len(result) != len(values):
        _fail(f"{field} contains a duplicate line number")
    return result


def _parse_branch_set(value: object, *, field: str) -> frozenset[tuple[int, int]]:
    if type(value) is not list:
        _fail(f"{field} must be an array")
    result: set[tuple[int, int]] = set()
    for raw_pair in cast("list[object]", value):
        if (
            type(raw_pair) is not list
            or len(cast("list[object]", raw_pair)) != _BRANCH_PAIR_LENGTH
        ):
            _fail(f"{field} must contain source-destination pairs")
        source, destination = cast("list[object]", raw_pair)
        if (
            type(source) is not int
            or source < 1
            or type(destination) is not int
            or destination == 0
        ):
            _fail(f"{field} contains a malformed branch pair")
        pair = (source, destination)
        if pair in result:
            _fail(f"{field} contains a duplicate branch pair")
        result.add(pair)
    return frozenset(result)


def _parse_json_file(
    value: object,
    *,
    filename: str,
) -> _JsonFileCoverage:
    record = _require_object(value, context=f"coverage JSON file {filename}")
    required = {
        "executed_lines",
        "missing_lines",
        "excluded_lines",
        "executed_branches",
        "missing_branches",
        "summary",
    }
    if not required <= set(record) or not set(record) <= _COVERAGE_FILE_KEYS:
        _fail(f"coverage JSON file fields are malformed for {filename}")
    executed_lines = _parse_line_set(
        record["executed_lines"],
        field=f"executed lines for {filename}",
    )
    missing_lines = _parse_line_set(
        record["missing_lines"],
        field=f"missing lines for {filename}",
    )
    _ = _parse_line_set(
        record["excluded_lines"], field=f"excluded lines for {filename}"
    )
    if executed_lines & missing_lines:
        _fail(f"coverage JSON line evidence overlaps for {filename}")
    executed_branches = _parse_branch_set(
        record["executed_branches"],
        field=f"executed branches for {filename}",
    )
    missing_branches = _parse_branch_set(
        record["missing_branches"],
        field=f"missing branches for {filename}",
    )
    if executed_branches & missing_branches:
        _fail(f"coverage JSON branch evidence overlaps for {filename}")
    summary = _require_object(
        record["summary"], context=f"coverage summary for {filename}"
    )
    required_summary = {
        "percent_covered",
        "num_branches",
        "covered_branches",
        "missing_branches",
    }
    if (
        not required_summary <= set(summary)
        or not set(summary) <= _COVERAGE_SUMMARY_KEYS
    ):
        _fail(f"coverage JSON summary fields are malformed for {filename}")
    _ = _parse_percent(
        summary["percent_covered"], field=f"coverage percent for {filename}"
    )
    total = _parse_nonnegative_integer(
        summary["num_branches"],
        field=f"branch total for {filename}",
    )
    covered = _parse_nonnegative_integer(
        summary["covered_branches"],
        field=f"covered branches for {filename}",
    )
    missing = _parse_nonnegative_integer(
        summary["missing_branches"],
        field=f"missing branches for {filename}",
    )
    if (
        covered + missing != total
        or len(executed_branches) != covered
        or len(missing_branches) != missing
    ):
        _fail(f"coverage JSON branch counters disagree for {filename}")
    if "percent_branches_covered" in summary:
        branch_percent = _parse_percent(
            summary["percent_branches_covered"],
            field=f"branch percent for {filename}",
        )
        expected = (
            Decimal(_PERCENT_SCALE)
            if total == 0
            else Decimal(covered) * _PERCENT_SCALE / Decimal(total)
        )
        if abs(branch_percent - expected) > Decimal("0.000000001"):
            _fail(f"coverage JSON branch percentage disagrees for {filename}")
    return _JsonFileCoverage(
        covered_branches=covered,
        total_branches=total,
        executed_lines=executed_lines,
        missing_lines=missing_lines,
        executed_branches=executed_branches,
        missing_branches=missing_branches,
    )


def _parse_coverage_json(
    payload: bytes,
    *,
    snapshot_root: Path,
    policy: CoveragePolicy,
) -> tuple[dict[str, _JsonFileCoverage], int, int]:
    document = _require_object(_load_coverage_json(payload), context="coverage JSON")
    if set(document) != {"meta", "files", "totals"}:
        _fail("coverage JSON top-level fields are malformed")
    meta = _require_object(document["meta"], context="coverage JSON metadata")
    if (
        "branch_coverage" not in meta
        or not set(meta) <= _COVERAGE_META_KEYS
        or meta["branch_coverage"] is not True
    ):
        _fail("coverage JSON does not prove branch measurement")
    totals = _require_object(document["totals"], context="coverage JSON totals")
    required_summary = {
        "percent_covered",
        "num_branches",
        "covered_branches",
        "missing_branches",
    }
    if not required_summary <= set(totals) or not set(totals) <= _COVERAGE_SUMMARY_KEYS:
        _fail("coverage JSON total fields are malformed")
    _ = _parse_percent(totals["percent_covered"], field="project coverage percent")
    total = _parse_nonnegative_integer(totals["num_branches"], field="project branches")
    covered = _parse_nonnegative_integer(
        totals["covered_branches"],
        field="project covered branches",
    )
    missing = _parse_nonnegative_integer(
        totals["missing_branches"],
        field="project missing branches",
    )
    if covered + missing != total:
        _fail("coverage JSON project branch counters are inconsistent")
    raw_files = _require_object(document["files"], context="coverage JSON files")
    if not raw_files:
        _fail("coverage JSON contains no measured files")
    files: dict[str, _JsonFileCoverage] = {}
    for raw_name, raw_value in raw_files.items():
        filename = _canonical_measured_name(raw_name, policy)
        path = snapshot_root.joinpath(*PurePosixPath(filename).parts)
        _require_regular_snapshot_file(path, snapshot_root=snapshot_root)
        files[filename] = _parse_json_file(raw_value, filename=filename)
    if (
        sum(item.covered_branches for item in files.values()) != covered
        or sum(item.total_branches for item in files.values()) != total
    ):
        _fail("coverage JSON file counters disagree with project counters")
    if "percent_branches_covered" in totals:
        branch_percent = _parse_percent(
            totals["percent_branches_covered"],
            field="project branch percent",
        )
        expected = (
            Decimal(_PERCENT_SCALE)
            if total == 0
            else Decimal(covered) * _PERCENT_SCALE / Decimal(total)
        )
        if abs(branch_percent - expected) > Decimal("0.000000001"):
            _fail("coverage JSON project branch percentage disagrees")
    return files, covered, total


def _validated_snapshot_root(snapshot_root: Path) -> Path:
    try:
        canonical = snapshot_root.resolve(strict=True)
    except OSError as exc:
        _fail_from("coverage snapshot root is absent", exc)
    if not canonical.is_dir():
        _fail("coverage snapshot root is not a directory")
    return canonical


def _validate_paired_reports(
    xml_report: tuple[dict[str, _XmlFileCoverage], int, int],
    json_report: tuple[dict[str, _JsonFileCoverage], int, int],
) -> None:
    xml_files, xml_covered, xml_total = xml_report
    json_files, json_covered, json_total = json_report
    if (
        xml_covered != json_covered
        or xml_total != json_total
        or set(xml_files) != set(json_files)
    ):
        _fail("coverage XML and JSON subjects or project counters disagree")
    for filename, xml_file in xml_files.items():
        json_file = json_files[filename]
        if (
            xml_file.covered_branches != json_file.covered_branches
            or xml_file.total_branches != json_file.total_branches
            or xml_file.branch_lines
            != frozenset(
                source
                for source, _destination in (
                    json_file.executed_branches | json_file.missing_branches
                )
            )
        ):
            _fail(f"coverage XML and JSON counters disagree for {filename}")


def _decision_module_percentages(
    files: dict[str, _JsonFileCoverage],
    *,
    policy: CoveragePolicy,
) -> tuple[tuple[str, float], ...]:
    percentages: list[tuple[str, float]] = []
    for filename in policy.decision_modules:
        record = files.get(filename)
        if record is None or record.total_branches < 1:
            _fail(f"decision module {filename} has no branch evidence")
        percent = record.covered_branches * _PERCENT_SCALE / record.total_branches
        if percent < policy.decision_module_branch_floor:
            _fail(f"decision module {filename} is below its branch floor")
        percentages.append((filename, percent))
    return tuple(percentages)


def _validated_trusted_module_origin(module: ModuleType, *, expected: Path) -> None:
    specification = module.__spec__
    raw_origin = cast("str | None", getattr(module, "__file__", None))
    if specification is None or specification.origin is None or raw_origin is None:
        _fail("trusted Coverage module has no import origin")
    try:
        origin = Path(raw_origin).resolve(strict=True)
        specification_origin = Path(specification.origin).resolve(strict=True)
        metadata = origin.lstat()
    except (OSError, TypeError) as exc:
        _fail_from("trusted Coverage module import origin is unavailable", exc)
    if (
        origin != expected
        or specification_origin != expected
        or not stat.S_ISREG(metadata.st_mode)
    ):
        _fail("trusted Coverage module import origin is invalid")


def _trusted_coverage_package(expected_origin: Path) -> ModuleType:
    existing = sys.modules.get("coverage")
    if existing is not None:
        _validated_trusted_module_origin(existing, expected=expected_origin)
        return existing
    if any(name.startswith("coverage.") for name in sys.modules):
        _fail("trusted Coverage package has an orphaned module binding")
    package_root = expected_origin.parent
    specification = importlib.util.spec_from_file_location(
        "coverage",
        expected_origin,
        submodule_search_locations=[package_root.as_posix()],
    )
    specification = cast("importlib.machinery.ModuleSpec", specification)
    loader = cast("importlib.machinery.SourceFileLoader", specification.loader)
    package = importlib.util.module_from_spec(specification)
    previous_modules = frozenset(sys.modules)
    sys.modules["coverage"] = package
    try:
        loader.exec_module(package)
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError) as exc:
        for name in tuple(sys.modules):
            if name not in previous_modules and (
                name == "coverage" or name.startswith("coverage.")
            ):
                del sys.modules[name]
        _fail_from("trusted Coverage package could not be loaded", exc)
    _validated_trusted_module_origin(package, expected=expected_origin)
    return package


def _trusted_coverage_submodule(package_root: Path, name: str) -> ModuleType:
    qualified = f"coverage.{name}"
    expected = package_root.joinpath(f"{name}.py").resolve(strict=True)
    module = sys.modules[qualified]
    _validated_trusted_module_origin(module, expected=expected)
    return module


def _trusted_coverage_components() -> tuple[
    _CoverageStaticParserFactory,
    _CoverageRegexJoiner,
    tuple[str, ...],
    type[BaseException],
]:
    expected_origin = Path(_trusted_tool_proof()[0][3])
    package = _trusted_coverage_package(expected_origin)
    package_root = expected_origin.parent
    parser_module = _trusted_coverage_submodule(package_root, "parser")
    config_module = _trusted_coverage_submodule(package_root, "config")
    misc_module = _trusted_coverage_submodule(package_root, "misc")
    exceptions_module = _trusted_coverage_submodule(package_root, "exceptions")
    parser_namespace = cast("dict[str, object]", vars(parser_module))
    config_namespace = cast("dict[str, object]", vars(config_module))
    misc_namespace = cast("dict[str, object]", vars(misc_module))
    exceptions_namespace = cast("dict[str, object]", vars(exceptions_module))
    parser_member = cast(
        "_CoverageStaticParserFactory",
        parser_namespace["PythonParser"],
    )
    joiner_member = cast(
        "_CoverageRegexJoiner",
        misc_namespace["join_regex"],
    )
    error_type = cast(
        "type[BaseException]",
        exceptions_namespace["NotPython"],
    )
    exclusions = cast("list[str]", config_namespace["DEFAULT_EXCLUDE"])
    _validated_trusted_module_origin(package, expected=expected_origin)
    return (
        parser_member,
        joiner_member,
        tuple(exclusions),
        error_type,
    )


def _coverage_branch_sources(payload: bytes, *, filename: str) -> frozenset[int]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        _fail_from(f"changed source is not UTF-8 for {filename}", exc)
    parser_factory, join_regex, exclusions, parser_error = (
        _trusted_coverage_components()
    )
    parser = parser_factory(
        text=text,
        filename=filename,
        exclude=join_regex(exclusions),
    )
    try:
        parser.parse_source()
        exit_counts = parser.exit_counts()
    except parser_error as exc:
        _fail_from(f"changed source syntax is invalid for {filename}", exc)
    return frozenset(line for line, count in exit_counts.items() if count > 1)


def _changed_coverage_percentages(
    files: dict[str, _JsonFileCoverage],
    *,
    changed_lines: dict[str, frozenset[int]],
    policy: CoveragePolicy,
    snapshot_root: Path,
) -> tuple[float, float]:
    if type(changed_lines) is not dict:
        _fail("changed-line evidence must be a mapping")
    covered_lines = 0
    total_lines = 0
    covered_arcs = 0
    total_arcs = 0
    for raw_name, raw_lines in changed_lines.items():
        filename = _canonical_measured_name(raw_name, policy)
        if type(raw_lines) is not frozenset or any(
            type(line) is not int or line < 1 for line in raw_lines
        ):
            _fail("changed-line evidence contains malformed line numbers")
        record = files.get(filename)
        if record is None:
            _fail(f"changed file {filename} is absent from coverage evidence")
        executable = record.executed_lines | record.missing_lines
        relevant_lines = raw_lines & executable
        total_lines += len(relevant_lines)
        covered_lines += len(relevant_lines - record.missing_lines)
        relevant_executed_arcs = frozenset(
            pair for pair in record.executed_branches if pair[0] in raw_lines
        )
        relevant_missing_arcs = frozenset(
            pair for pair in record.missing_branches if pair[0] in raw_lines
        )
        covered_arcs += len(relevant_executed_arcs)
        total_arcs += len(relevant_executed_arcs | relevant_missing_arcs)
        _, payload = _read_bound_regular_file(
            snapshot_root,
            filename,
            max_bytes=_MAX_SNAPSHOT_FILE_BYTES,
        )
        changed_branch_sources = raw_lines & _coverage_branch_sources(
            payload,
            filename=filename,
        )
        branch_sources = frozenset(
            source
            for source, _destination in (
                record.executed_branches | record.missing_branches
            )
        )
        if not changed_branch_sources <= branch_sources:
            _fail(f"changed static branch has no coverage evidence in {filename}")
    line_percent = (
        float(_PERCENT_SCALE)
        if total_lines == 0
        else covered_lines * _PERCENT_SCALE / total_lines
    )
    arc_percent = (
        float(_PERCENT_SCALE)
        if total_arcs == 0
        else covered_arcs * _PERCENT_SCALE / total_arcs
    )
    if line_percent < policy.diff_line_floor:
        _fail("changed executable line coverage is below policy")
    if arc_percent < policy.diff_branch_arc_floor:
        _fail("changed branch arc coverage is below policy")
    return line_percent, arc_percent


def parse_coverage_reports(
    *,
    xml_payload: bytes,
    json_payload: bytes,
    policy: CoveragePolicy,
    snapshot_root: Path,
    changed_lines: dict[str, frozenset[int]],
) -> CoverageReportResult:
    """Validate paired Coverage.py XML/JSON reports and changed arcs."""
    canonical_root = _validated_snapshot_root(snapshot_root)
    xml_report = _parse_coverage_xml(
        xml_payload,
        snapshot_root=canonical_root,
        policy=policy,
    )
    json_report = _parse_coverage_json(
        json_payload,
        snapshot_root=canonical_root,
        policy=policy,
    )
    _validate_paired_reports(xml_report, json_report)
    json_files, json_covered, json_total = json_report
    if json_total < 1:
        _fail("coverage reports contain no project branch evidence")
    project_percent = json_covered * _PERCENT_SCALE / json_total
    if project_percent < policy.project_branch_floor:
        _fail("project branch coverage is below policy")

    decision_percentages = _decision_module_percentages(json_files, policy=policy)
    diff_line_percent, diff_arc_percent = _changed_coverage_percentages(
        json_files,
        changed_lines=changed_lines,
        policy=policy,
        snapshot_root=canonical_root,
    )
    return CoverageReportResult(
        project_branch_percent=project_percent,
        diff_line_percent=diff_line_percent,
        diff_branch_arc_percent=diff_arc_percent,
        decision_module_branch_percent=decision_percentages,
    )


def _canonical_package_relative_path(value: object, *, field: str) -> str:
    if type(value) is not str or not value or len(value) > _MAX_RELATIVE_NAME:
        _fail(f"{field} is empty, oversized, or not a string")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "\\" in value
        or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value)
    ):
        _fail(f"{field} is not a canonical package-relative path")
    return value


def _parse_installed_record(
    raw_record: object,
    *,
    declared_package_data: tuple[str, ...],
) -> InstalledFileRecord:
    record = _require_object(raw_record, context="package manifest file")
    if set(record) != {"path", "mode", "sha256"}:
        _fail("package manifest file fields are malformed")
    path = _canonical_package_relative_path(
        record["path"],
        field="package manifest file path",
    )
    mode = record["mode"]
    if type(mode) is not int or not 0 <= mode <= _MAX_FILE_MODE:
        _fail("package manifest file mode is malformed")
    digest = record["sha256"]
    if type(digest) is not str or _SHA256_PATTERN.fullmatch(digest) is None:
        _fail("package manifest file digest is malformed")
    if not (
        path.endswith(".py") or path == "py.typed" or path in declared_package_data
    ):
        _fail("package manifest contains undeclared package data")
    return InstalledFileRecord(path=path, mode=mode, sha256=digest)


def _parse_installed_manifest(payload: bytes) -> _InstalledManifest:
    document = _require_object(_load_closed_json(payload), context="package manifest")
    if set(document) != {
        "version",
        "package",
        "declared_package_data",
        "files",
    }:
        _fail("package manifest fields do not match version 1")
    _ = _require_exact_integer(document["version"], expected=1, field="version")
    if document["package"] != "nplg_mcp":
        _fail("package manifest names the wrong package")
    declared = _require_string_tuple(
        document["declared_package_data"],
        field="declared_package_data",
    )
    canonical_declared = tuple(
        _canonical_package_relative_path(item, field="declared package data")
        for item in declared
    )
    if canonical_declared != tuple(sorted(canonical_declared)):
        _fail("declared package data must be in canonical order")
    if any(path.endswith(".py") or path == "py.typed" for path in canonical_declared):
        _fail("Python and py.typed files must not be declared as package data")
    raw_files = document["files"]
    if type(raw_files) is not list or not raw_files:
        _fail("package manifest file inventory is empty or malformed")
    raw_file_records = cast("list[object]", raw_files)
    records = [
        _parse_installed_record(
            raw_record,
            declared_package_data=canonical_declared,
        )
        for raw_record in raw_file_records
    ]
    paths = tuple(record.path for record in records)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        _fail("package manifest file inventory is unordered or duplicated")
    if "__init__.py" not in paths:
        _fail("package manifest does not contain the package initializer")
    if not set(canonical_declared) <= set(paths):
        _fail("declared package data is absent from the manifest inventory")
    return _InstalledManifest(
        declared_package_data=canonical_declared,
        files=tuple(records),
    )


def _canonical_package_root(path: Path, *, boundary: str) -> Path:
    if not path.is_absolute() or path.name != "nplg_mcp":
        _fail(f"{boundary} must be an absolute nplg_mcp package root")
    if any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in path.as_posix()):
        _fail(f"{boundary} contains a control character")
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        _fail_from(f"{boundary} is absent", exc)
    if canonical != path or not canonical.is_dir():
        _fail(f"{boundary} must be a canonical directory")
    return canonical


def _stable_installed_record(
    parent: int,
    name: str,
    *,
    expected: os.stat_result,
    relative: str,
) -> InstalledFileRecord:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        path_before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        _fail_from("package inventory file could not be opened safely", exc)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _filesystem_identity(expected) != _filesystem_identity(path_before)
            or _filesystem_identity(path_before) != _filesystem_identity(before)
            or before.st_size > _MAX_PACKAGE_FILE_BYTES
        ):
            _fail("package inventory entry is not a bounded single-link file")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, _PACKAGE_READ_CHUNK_BYTES))
            if not chunk:
                _fail("package inventory file was truncated while reading")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(
            name,
            dir_fd=parent,
            follow_symlinks=False,
        )
        if _filesystem_identity(before) != _filesystem_identity(
            after
        ) or _filesystem_identity(after) != _filesystem_identity(path_after):
            _fail("package inventory file changed while being read")
        return InstalledFileRecord(
            path=relative,
            mode=stat.S_IMODE(before.st_mode),
            sha256=digest.hexdigest(),
        )
    finally:
        os.close(descriptor)


def _inventory_package(
    root: Path,
    *,
    expected_files: tuple[InstalledFileRecord, ...],
) -> tuple[InstalledFileRecord, ...]:
    expected_paths = frozenset(record.path for record in expected_files)
    expected_directories = frozenset(
        parent.as_posix()
        for path in expected_paths
        for parent in PurePosixPath(path).parents
        if parent.as_posix() != "."
    )
    records: list[InstalledFileRecord] = []
    total_bytes = 0
    pending = [(_open_root_directory(root), "")]
    try:
        while pending:
            directory_descriptor, prefix = pending.pop()
            try:
                for entry in sorted(
                    _descriptor_entries(directory_descriptor),
                    key=_directory_entry_name,
                ):
                    metadata = _validated_source_entry(
                        directory_descriptor,
                        entry,
                    )
                    relative = f"{prefix}/{entry.name}" if prefix else entry.name
                    canonical = _canonical_package_relative_path(
                        relative,
                        field="package inventory path",
                    )
                    if stat.S_ISDIR(metadata.st_mode):
                        if canonical not in expected_directories:
                            _fail("unexpected package inventory entry")
                        pending.append(
                            (
                                _open_child_directory(
                                    directory_descriptor,
                                    entry.name,
                                    expected=metadata,
                                ),
                                canonical,
                            )
                        )
                        continue
                    if canonical not in expected_paths:
                        _fail("unexpected package inventory entry")
                    total_bytes += metadata.st_size
                    if total_bytes > _MAX_PACKAGE_TOTAL_BYTES:
                        _fail("package inventory exceeds its total byte bound")
                    records.append(
                        _stable_installed_record(
                            directory_descriptor,
                            entry.name,
                            expected=metadata,
                            relative=canonical,
                        )
                    )
            finally:
                os.close(directory_descriptor)
    finally:
        for descriptor, _prefix in pending:
            os.close(descriptor)
    if not records:
        _fail("package inventory is empty")
    return tuple(sorted(records, key=_installed_record_path))


def _installed_record_path(record: InstalledFileRecord) -> str:
    return record.path


def _directory_entry_name(entry: os.DirEntry[str]) -> str:
    return entry.name


def verify_installed_package(
    *,
    installed_package_root: Path,
    source_package_root: Path,
    manifest_payload: bytes,
    discovered_package_roots: tuple[Path, ...],
) -> InstalledPackageProof:
    """Prove wheel/source byte identity before emitting a Coverage.py alias."""
    manifest = _parse_installed_manifest(manifest_payload)
    source = _canonical_package_root(
        source_package_root,
        boundary="source package root",
    )
    installed = _canonical_package_root(
        installed_package_root,
        boundary="installed package root",
    )
    if source.parent.name != "src":
        _fail("source package root is not the candidate src/nplg_mcp directory")
    if installed.parent.name not in {"site-packages", "dist-packages"}:
        _fail("installed package root is not under a site-packages directory")
    if _is_within(source, installed) or _is_within(installed, source):
        _fail("installed and source package roots overlap")
    discovered = tuple(
        _canonical_package_root(path, boundary="discovered package root")
        for path in discovered_package_roots
    )
    if discovered != (installed,):
        _fail("runtime package discovery is missing, duplicated, or source-bound")
    source_records = _inventory_package(
        source,
        expected_files=manifest.files,
    )
    installed_records = _inventory_package(
        installed,
        expected_files=manifest.files,
    )
    if source_records != manifest.files or installed_records != manifest.files:
        _fail("installed, source, and manifest package inventories disagree")
    configuration = (
        f"[paths]\nnplg_mcp =\n    {source.as_posix()}\n    {installed.as_posix()}\n"
    ).encode()
    return InstalledPackageProof(
        source_package_root=source,
        installed_package_root=installed,
        files=manifest.files,
        coverage_paths_configuration=configuration,
    )


def _read_stable_package_manifest(
    filesystem: Filesystem,
    path: Path,
) -> bytes:
    if not path.is_absolute():
        _fail("installed-package manifest path must be absolute")
    try:
        canonical = path.resolve(strict=True)
        before = path.lstat()
    except OSError as exc:
        _fail_from("installed-package manifest is unavailable", exc)
    if (
        canonical != path
        or not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > _MAX_PACKAGE_MANIFEST_BYTES
    ):
        _fail("installed-package manifest is not a bounded canonical regular file")
    try:
        payload = filesystem.read_bytes(path)
        after = path.lstat()
    except OSError as exc:
        _fail_from("installed-package manifest could not be read stably", exc)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if (
        type(payload) is not bytes
        or len(payload) != before.st_size
        or identity_after != identity_before
    ):
        _fail("installed-package manifest changed while being read")
    return payload


def _discover_runtime_package_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    for entry in sys.path:
        if type(entry) is not str or "\0" in entry:
            _fail("runtime import path contains a malformed entry")
        raw_base = Path.cwd() if not entry else Path(entry)
        if not raw_base.is_absolute():
            raw_base = Path.cwd() / raw_base
        try:
            base = raw_base.resolve(strict=True)
        except FileNotFoundError:
            continue
        except OSError as exc:
            _fail_from("runtime import path could not be resolved", exc)
        candidate = base / "nplg_mcp"
        if os.path.lexists(candidate):
            roots.append(candidate)
    return tuple(roots)


def _prepare_installed_runtime(
    execution: _GateExecution,
    *,
    materialized_root: Path,
) -> _InstalledRuntimeEvidence | None:
    installed = execution.request.installed_package_root
    manifest = execution.request.package_manifest
    if installed is None:
        return None
    _validate_generated_configuration_path(installed)
    manifest_path = cast("Path", manifest)
    payload = _read_stable_package_manifest(execution.filesystem, manifest_path)
    discovered = _discover_runtime_package_roots()
    proof = verify_installed_package(
        installed_package_root=installed,
        source_package_root=materialized_root / "src" / "nplg_mcp",
        manifest_payload=payload,
        discovered_package_roots=discovered,
    )
    return _InstalledRuntimeEvidence(
        manifest_payload=payload,
        discovered_package_roots=discovered,
        proof=proof,
    )


def _verify_installed_runtime_unchanged(
    execution: _GateExecution,
    evidence: _InstalledRuntimeEvidence | None,
) -> None:
    if evidence is None:
        return
    manifest_path = cast("Path", execution.request.package_manifest)
    if (
        _read_stable_package_manifest(execution.filesystem, manifest_path)
        != evidence.manifest_payload
        or _discover_runtime_package_roots() != evidence.discovered_package_roots
    ):
        _fail("installed-package manifest or runtime discovery changed during testing")
    _ = verify_installed_package(
        installed_package_root=evidence.proof.installed_package_root,
        source_package_root=evidence.proof.source_package_root,
        manifest_payload=evidence.manifest_payload,
        discovered_package_roots=evidence.discovered_package_roots,
    )


def _checked_git(
    git: Git,
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
) -> CommandResult:
    argv = (_GIT_EXECUTABLE, *arguments)
    try:
        result = git.run(
            argv,
            cwd=cwd,
            environment=environment or {"GIT_OPTIONAL_LOCKS": "0"},
        )
    except QualityGateError as exc:
        _fail_from("Git evidence or external snapshot command failed", exc)
    if (
        result.argv != argv
        or type(result.returncode) is not int
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > _MAX_GIT_OUTPUT_BYTES
        or len(result.stderr) > _MAX_GIT_OUTPUT_BYTES
        or result.stderr
    ):
        _fail("Git command evidence is incomplete or unsuccessful")
    return result


def _git_object(payload: bytes, *, boundary: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").removesuffix("\n")
    except UnicodeDecodeError as exc:
        _fail_from(f"{boundary} is not ASCII", exc)
    if _GIT_OBJECT_PATTERN.fullmatch(value) is None:
        _fail(f"{boundary} is malformed")
    return value


def _canonical_comparison_ref(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_GIT_REF_BYTES
        or value.startswith(("-", "/"))
        or value.endswith(("/", "."))
        or ".." in value
        or "@{" in value
        or "//" in value
        or "\\" in value
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value) is None
    ):
        _fail("comparison ref is not a closed Git reference name")
    return value


def _repository_evidence(git: Git, *, root: Path) -> _RepositoryEvidence:
    head = _git_object(
        _checked_git(git, ("rev-parse", "--verify", "HEAD"), cwd=root).stdout,
        boundary="Git HEAD",
    )
    staged = _checked_git(git, ("ls-files", "--stage", "-z"), cwd=root).stdout
    refs = _checked_git(
        git,
        ("show-ref", "--head", "--dereference"),
        cwd=root,
    ).stdout
    status = _checked_git(
        git,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        cwd=root,
    ).stdout
    return _RepositoryEvidence(
        head=head,
        staged_sha256=hashlib.sha256(staged).hexdigest(),
        refs_sha256=hashlib.sha256(refs).hexdigest(),
        status_sha256=hashlib.sha256(status).hexdigest(),
        clean=not status,
    )


def _canonical_git_directory(payload: bytes, *, boundary: str) -> Path:
    try:
        value = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        _fail_from(f"{boundary} is not UTF-8", exc)
    if (
        not value.endswith("\n")
        or value.count("\n") != 1
        or "\0" in value
        or "\r" in value
    ):
        _fail(f"{boundary} path is malformed")
    path = Path(value.removesuffix("\n"))
    if not path.is_absolute():
        _fail(f"{boundary} path is not absolute")
    try:
        canonical = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        _fail_from(f"{boundary} path is unavailable", exc)
    if (
        canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        _fail(f"{boundary} path is not an owned canonical directory")
    return path


def _raw_git_file(root: Path, relative: str) -> _RawFileEvidence:
    metadata, payload = _read_bound_regular_file(
        root,
        relative,
        max_bytes=_MAX_SNAPSHOT_FILE_BYTES,
    )
    return _RawFileEvidence(
        path=relative,
        identity=_filesystem_identity(metadata),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _optional_raw_git_file(
    root: Path,
    relative: str,
) -> _RawFileEvidence | None:
    parent = _open_relative_parent(root, relative, create=False)
    try:
        try:
            _ = os.stat(
                PurePosixPath(relative).parts[-1],
                dir_fd=parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
    finally:
        os.close(parent)
    return _raw_git_file(root, relative)


def _raw_directory_inventory(
    root: Path,
    *,
    boundary: str,
) -> tuple[ObjectDatabaseEntry, ...]:
    try:
        return object_database_inventory(root)
    except BaselineCaptureError as exc:
        _fail_from(f"{boundary} inventory is unavailable or unstable", exc)


def _release_git_evidence(git: Git, *, root: Path) -> _ReleaseGitEvidence:
    worktree_git_directory = _canonical_git_directory(
        _checked_git(
            git,
            ("rev-parse", "--path-format=absolute", "--git-dir"),
            cwd=root,
        ).stdout,
        boundary="release worktree Git directory",
    )
    common_git_directory = _canonical_git_directory(
        _checked_git(
            git,
            ("rev-parse", "--path-format=absolute", "--git-common-dir"),
            cwd=root,
        ).stdout,
        boundary="release common Git directory",
    )
    commit = _git_object(
        _checked_git(git, ("rev-parse", "--verify", "HEAD"), cwd=root).stdout,
        boundary="release Git HEAD",
    )
    tree = _git_object(
        _checked_git(
            git,
            ("rev-parse", "--verify", "HEAD^{tree}"),
            cwd=root,
        ).stdout,
        boundary="release Git tree",
    )
    return _ReleaseGitEvidence(
        commit=commit,
        tree=tree,
        worktree_git_directory=worktree_git_directory,
        common_git_directory=common_git_directory,
        head=_raw_git_file(worktree_git_directory, "HEAD"),
        index=_raw_git_file(worktree_git_directory, "index"),
        packed_refs=_optional_raw_git_file(common_git_directory, "packed-refs"),
        refs=_raw_directory_inventory(
            common_git_directory / "refs",
            boundary="release raw refs",
        ),
        objects=_raw_directory_inventory(
            common_git_directory / "objects",
            boundary="release raw objects",
        ),
    )


def _registered_worktrees(git: Git, *, root: Path) -> tuple[Path, ...]:
    payload = _checked_git(
        git,
        ("worktree", "list", "--porcelain", "-z"),
        cwd=root,
    ).stdout
    try:
        return parse_registered_worktrees(payload, current_root=root)
    except QualityGateError as exc:
        _fail_from("registered Git worktree evidence is malformed", exc)


def _comparison_base(git: Git, *, root: Path, ref: str, head: str) -> str:
    shallow = _checked_git(
        git,
        ("rev-parse", "--is-shallow-repository"),
        cwd=root,
    ).stdout
    if shallow != b"false\n":
        _fail("comparison requires a complete non-shallow repository")
    comparison = _git_object(
        _checked_git(
            git,
            ("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"),
            cwd=root,
        ).stdout,
        boundary="comparison ref",
    )
    return _git_object(
        _checked_git(git, ("merge-base", comparison, head), cwd=root).stdout,
        boundary="comparison merge base",
    )


def _canonical_repository_path(payload: bytes, *, boundary: str) -> str:
    try:
        value = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        _fail_from(f"{boundary} is not UTF-8", exc)
    pure = PurePosixPath(value)
    if (
        not value
        or len(payload) > _MAX_RELATIVE_NAME
        or pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {"", ".", "..", ".git"} for part in pure.parts)
        or "\\" in value
        or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value)
    ):
        _fail(f"{boundary} is not a canonical repository path")
    return value


def _tracked_paths(payload: bytes) -> tuple[str, ...]:
    if payload and not payload.endswith(b"\0"):
        _fail("tracked Git inventory is truncated")
    paths: list[str] = []
    for raw_entry in payload.removesuffix(b"\0").split(b"\0") if payload else ():
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        fields = metadata.split(b" ")
        if separator != b"\t" or len(fields) != _TRACKED_FIELD_COUNT:
            _fail("tracked Git inventory entry is malformed")
        mode, object_name, stage = fields
        if (
            mode not in {b"100644", b"100755"}
            or _GIT_OBJECT_PATTERN.fullmatch(
                object_name.decode("ascii", errors="ignore")
            )
            is None
            or stage != b"0"
        ):
            _fail("tracked Git inventory contains an unsupported entry")
        paths.append(
            _canonical_repository_path(raw_path, boundary="tracked repository path")
        )
    if len(paths) != len(set(paths)):
        _fail("tracked Git inventory contains duplicate paths")
    return tuple(paths)


def _untracked_paths(payload: bytes) -> tuple[str, ...]:
    if payload and not payload.endswith(b"\0"):
        _fail("untracked Git inventory is truncated")
    paths = tuple(
        _canonical_repository_path(raw, boundary="untracked repository path")
        for raw in (payload.removesuffix(b"\0").split(b"\0") if payload else ())
    )
    if len(paths) != len(set(paths)):
        _fail("untracked Git inventory contains duplicate paths")
    for path in paths:
        if path not in _ALLOWED_UNTRACKED_ROOTS and not path.startswith(
            _ALLOWED_UNTRACKED_PREFIXES
        ):
            _fail("untracked repository path is outside the reviewed input policy")
    return paths


def _filesystem_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_root_directory(root: Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        before = root.lstat()
        descriptor = os.open(root, flags)
    except OSError as exc:
        _fail_from("snapshot root could not be opened safely", exc)
    try:
        opened = os.fstat(descriptor)
        after = root.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _filesystem_identity(before) != _filesystem_identity(opened)
            or _filesystem_identity(opened) != _filesystem_identity(after)
        ):
            _fail("snapshot root changed during descriptor binding")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_child_directory(
    parent: int,
    name: str,
    *,
    expected: os.stat_result | None = None,
) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        child = os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        _fail_from("snapshot parent could not be opened safely", exc)
    try:
        opened = os.fstat(child)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (
                expected is not None
                and _filesystem_identity(expected) != _filesystem_identity(opened)
            )
            or _filesystem_identity(before) != _filesystem_identity(opened)
            or _filesystem_identity(opened) != _filesystem_identity(after)
        ):
            _fail("snapshot parent changed during descriptor traversal")
    except BaseException:
        os.close(child)
        raise
    return child


def _open_relative_parent(root: Path, relative: str, *, create: bool) -> int:
    parts = PurePosixPath(relative).parts
    descriptor = _open_root_directory(root)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, mode=_PRIVATE_DIRECTORY_MODE, dir_fd=descriptor)
                except FileExistsError:
                    pass
                except OSError as exc:
                    _fail_from("snapshot parent could not be created safely", exc)
            child = _open_child_directory(descriptor, part)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _read_bound_regular_file(
    root: Path,
    relative: str,
    *,
    max_bytes: int,
) -> tuple[os.stat_result, bytes]:
    parts = PurePosixPath(relative).parts
    parent = _open_relative_parent(root, relative, create=False)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        path_before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(parts[-1], flags, dir_fd=parent)
    except OSError as exc:
        os.close(parent)
        _fail_from("repository input could not be opened safely", exc)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or before.st_nlink != 1
            or before.st_dev != path_before.st_dev
            or before.st_ino != path_before.st_ino
            or before.st_size > max_bytes
        ):
            _fail("repository input is not a bounded single-link regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, _PACKAGE_READ_CHUNK_BYTES))
            if not chunk:
                _fail("repository input was truncated while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(
            parts[-1],
            dir_fd=parent,
            follow_symlinks=False,
        )
        if _filesystem_identity(before) != _filesystem_identity(
            after
        ) or _filesystem_identity(after) != _filesystem_identity(path_after):
            _fail("repository input changed while being read")
        return before, b"".join(chunks)
    finally:
        os.close(descriptor)
        os.close(parent)


def _stable_snapshot_file(root: Path, relative: str) -> _SnapshotFile:
    metadata, payload = _read_bound_regular_file(
        root,
        relative,
        max_bytes=_MAX_SNAPSHOT_FILE_BYTES,
    )
    return _SnapshotFile(
        path=relative,
        mode=stat.S_IMODE(metadata.st_mode),
        payload=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _snapshot_digest(
    files: tuple[_SnapshotFile, ...],
    deleted: tuple[str, ...],
) -> str:
    digest = hashlib.sha256(b"nplg-test-snapshot-v1\0")
    for record in files:
        digest.update(record.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(record.mode).encode("ascii"))
        digest.update(b"\0")
        digest.update(record.sha256.encode("ascii"))
        digest.update(b"\0")
    for path in deleted:
        digest.update(b"deleted\0")
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _capture_source_snapshot(git: Git, *, root: Path) -> _SourceSnapshot:
    reviewed = _reviewed_source_paths(root)
    tracked = _tracked_paths(
        _checked_git(git, ("ls-files", "--stage", "-z"), cwd=root).stdout
    )
    untracked = _untracked_paths(
        _checked_git(
            git,
            ("ls-files", "--others", "--exclude-standard", "-z"),
            cwd=root,
        ).stdout
    )
    if set(tracked) & set(untracked):
        _fail("tracked and untracked repository inventories overlap")
    records: list[_SnapshotFile] = []
    deleted: list[str] = []
    total_bytes = 0
    inventory = tuple(sorted(set(tracked) | set(untracked) | set(reviewed)))
    for relative in inventory:
        path = root.joinpath(*PurePosixPath(relative).parts)
        if relative in tracked and not os.path.lexists(path):
            deleted.append(relative)
            continue
        record = _stable_snapshot_file(root, relative)
        total_bytes += len(record.payload)
        if total_bytes > _MAX_SNAPSHOT_TOTAL_BYTES:
            _fail("repository snapshot exceeds its total byte bound")
        records.append(record)
    files = tuple(records)
    missing = tuple(sorted(deleted))
    return _SourceSnapshot(
        files=files,
        deleted=missing,
        digest=_snapshot_digest(files, missing),
    )


def _open_optional_reviewed_root(root: Path, prefix: str) -> int | None:
    root_descriptor = _open_root_directory(root)
    try:
        try:
            expected = os.stat(
                prefix,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        return _open_child_directory(
            root_descriptor,
            prefix,
            expected=expected,
        )
    finally:
        os.close(root_descriptor)


def _descriptor_entries(descriptor: int) -> tuple[os.DirEntry[str], ...]:
    try:
        iterator = os.scandir(descriptor)
    except OSError as exc:
        _fail_from("reviewed repository input root could not be scanned", exc)
    try:
        return tuple(cast("Iterator[os.DirEntry[str]]", iterator))
    except OSError as exc:
        _fail_from("reviewed repository input changed during scan", exc)
    finally:
        iterator.close()


def _scan_reviewed_directories(root: Path) -> set[str]:
    pending = [
        (descriptor, prefix)
        for raw_prefix in _ALLOWED_UNTRACKED_PREFIXES
        if (
            descriptor := _open_optional_reviewed_root(
                root,
                prefix := raw_prefix.removesuffix("/"),
            )
        )
        is not None
    ]
    files: set[str] = set()
    visited = 0
    try:
        while pending:
            directory_descriptor, prefix = pending.pop()
            try:
                for entry in _descriptor_entries(directory_descriptor):
                    visited += 1
                    if visited > _MAX_SNAPSHOT_ENTRIES:
                        _fail("reviewed repository input scan exceeds its entry bound")
                    metadata = _validated_source_entry(
                        directory_descriptor,
                        entry,
                    )
                    relative = f"{prefix}/{entry.name}"
                    if stat.S_ISREG(metadata.st_mode):
                        files.add(relative)
                    elif entry.name not in _GENERATED_DIRECTORY_NAMES:
                        pending.append(
                            (
                                _open_child_directory(
                                    directory_descriptor,
                                    entry.name,
                                    expected=metadata,
                                ),
                                relative,
                            )
                        )
            finally:
                os.close(directory_descriptor)
    finally:
        for descriptor, _prefix in pending:
            os.close(descriptor)
    return files


def _reviewed_root_files(root: Path) -> set[str]:
    files: set[str] = set()
    root_descriptor = _open_root_directory(root)
    try:
        for relative in _ALLOWED_UNTRACKED_ROOTS:
            try:
                metadata = os.stat(
                    relative,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                _fail_from("reviewed root input changed during scan", exc)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                _fail("reviewed root input is not a regular file")
            files.add(relative)
    finally:
        os.close(root_descriptor)
    return files


def _reviewed_source_paths(root: Path) -> tuple[str, ...]:
    return tuple(sorted(_scan_reviewed_directories(root) | _reviewed_root_files(root)))


def _validated_source_entry(
    parent: int,
    entry: os.DirEntry[str],
) -> os.stat_result:
    if (
        not entry.name
        or entry.name in {".", ".."}
        or "/" in entry.name
        or "\\" in entry.name
        or any(
            ord(character) < _CONTROL_CHARACTER_LIMIT
            or ord(character) == _DELETE_CHARACTER
            for character in entry.name
        )
    ):
        _fail("reviewed repository input contains an unsafe entry name")
    try:
        metadata = entry.stat(follow_symlinks=False)
        linked = os.stat(entry.name, dir_fd=parent, follow_symlinks=False)
        if _filesystem_identity(metadata) != _filesystem_identity(linked):
            _fail("reviewed repository input changed during scan")
        if stat.S_ISLNK(metadata.st_mode):
            _fail("reviewed repository input contains a symlink")
        if not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(metadata.st_mode):
            _fail("reviewed repository input contains a special file")
    except OSError as exc:
        _fail_from("reviewed repository input changed during scan", exc)
    return metadata


def _paths_intersect(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _validate_generated_configuration_path(path: Path) -> None:
    rendered = path.as_posix()
    if "%" in rendered or any(
        ord(character) < _CONTROL_CHARACTER_LIMIT or ord(character) == _DELETE_CHARACTER
        for character in rendered
    ):
        _fail("test-gate output path is unsafe for generated configuration")


def _create_external_output(
    requested: Path | None,
    *,
    registered_worktrees: tuple[Path, ...],
) -> tuple[Path, bool]:
    temporary = requested is None
    if requested is None:
        output = Path(tempfile.mkdtemp(prefix="nplg-test-gate-")).resolve(strict=True)
        output.chmod(_PRIVATE_DIRECTORY_MODE)
    else:
        _validate_generated_configuration_path(requested)
        if not requested.is_absolute() or os.path.lexists(requested):
            _fail("explicit test-gate output must be absolute and absent")
        try:
            parent = requested.parent.resolve(strict=True)
        except OSError as exc:
            _fail_from("test-gate output parent is unavailable", exc)
        if parent != requested.parent or not parent.is_dir():
            _fail("test-gate output parent must be canonical")
        output = parent / requested.name
        try:
            output.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            output.chmod(_PRIVATE_DIRECTORY_MODE)
        except OSError as exc:
            _fail_from("test-gate output could not be created", exc)
    try:
        metadata = output.lstat()
        canonical = output.resolve(strict=True)
    except OSError as exc:
        if temporary:
            shutil.rmtree(output, ignore_errors=True)
        _fail_from("test-gate output is unavailable after creation", exc)
    if (
        canonical != output
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
        or any(_paths_intersect(output, worktree) for worktree in registered_worktrees)
    ):
        shutil.rmtree(output, ignore_errors=True)
        _fail("test-gate output is not a private external directory")
    return output, temporary


def _write_snapshot_file(root: Path, record: _SnapshotFile) -> None:
    parts = PurePosixPath(record.path).parts
    parent = _open_relative_parent(root, record.path, create=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(parts[-1], flags, record.mode, dir_fd=parent)
    except OSError as exc:
        os.close(parent)
        _fail_from("external snapshot file could not be created", exc)
    try:
        view = memoryview(record.payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                _fail("external snapshot file write was incomplete")
            written += count
        os.fchmod(descriptor, record.mode)
        opened = os.fstat(descriptor)
        linked = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != len(record.payload)
            or _filesystem_identity(opened) != _filesystem_identity(linked)
        ):
            _fail("external snapshot file changed during materialization")
    finally:
        os.close(descriptor)
        os.close(parent)


def _materialize_snapshot(
    source: Path,
    snapshot: _SourceSnapshot,
    *,
    merge_base: str,
    output: Path,
    git: Git,
) -> _MaterializedSnapshot:
    destination = output / "snapshot"
    _ = _checked_git(
        git,
        (
            "-c",
            "protocol.file.allow=always",
            "clone",
            "-q",
            "--no-checkout",
            "--no-hardlinks",
            "--local",
            "--no-tags",
            source.as_posix(),
            destination.as_posix(),
        ),
        cwd=output,
    )
    try:
        root = destination.resolve(strict=True)
    except OSError as exc:
        _fail_from("external Git snapshot was not created", exc)
    if root != destination or not root.is_dir():
        _fail("external Git snapshot path is not canonical")
    for record in snapshot.files:
        _write_snapshot_file(root, record)
    _ = _checked_git(git, ("add", "--force", "--all"), cwd=root)
    tree = _git_object(
        _checked_git(git, ("write-tree",), cwd=root).stdout,
        boundary="external snapshot tree",
    )
    commit_environment = {
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    candidate = _git_object(
        _checked_git(
            git,
            (
                "-c",
                "user.name=NPLG Test Gate",
                "-c",
                "user.email=nplg-test-gate.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit-tree",
                tree,
                "-p",
                merge_base,
                "-m",
                "deterministic external test snapshot",
            ),
            cwd=root,
            environment=commit_environment,
        ).stdout,
        boundary="external snapshot commit",
    )
    _ = _checked_git(
        git,
        ("symbolic-ref", "HEAD", "refs/heads/nplg-test-snapshot"),
        cwd=root,
    )
    _ = _checked_git(git, ("update-ref", "HEAD", candidate), cwd=root)
    changed_lines = _changed_python_lines(
        git,
        root=root,
        merge_base=merge_base,
        candidate=candidate,
    )
    return _MaterializedSnapshot(
        root=root,
        merge_base=merge_base,
        candidate_commit=candidate,
        changed_lines=changed_lines,
    )


def _bind_external_snapshot(
    git: Git,
    *,
    materialized: _MaterializedSnapshot,
    source_snapshot: _SourceSnapshot,
) -> _ExternalSnapshotBinding:
    copied: list[_SnapshotFile] = []
    for expected in source_snapshot.files:
        actual = _stable_snapshot_file(materialized.root, expected.path)
        if actual != expected:
            _fail("materialized input differs from the bound source snapshot")
        copied.append(actual)
    for relative in source_snapshot.deleted:
        if os.path.lexists(materialized.root.joinpath(*PurePosixPath(relative).parts)):
            _fail("materialized snapshot restored a deleted source input")
    head = _git_object(
        _checked_git(
            git,
            ("rev-parse", "--verify", "HEAD"),
            cwd=materialized.root,
        ).stdout,
        boundary="external snapshot HEAD",
    )
    tree = _git_object(
        _checked_git(
            git,
            ("rev-parse", "--verify", "HEAD^{tree}"),
            cwd=materialized.root,
        ).stdout,
        boundary="external snapshot tree",
    )
    if head != materialized.candidate_commit:
        _fail("external snapshot commit differs from the materialized candidate")
    return _ExternalSnapshotBinding(
        repository=_repository_evidence(git, root=materialized.root),
        tree=tree,
        copied_inputs=tuple(copied),
    )


# Narrow public sharing seam for the mutation authority. These are direct
# aliases so the reviewed implementations, signatures, and branch surface stay
# identical; descriptor-producing traversal helpers intentionally remain private.
RepositoryEvidence = _RepositoryEvidence
ReleaseGitEvidence = _ReleaseGitEvidence
SnapshotFile = _SnapshotFile
SourceSnapshot = _SourceSnapshot
MaterializedSnapshot = _MaterializedSnapshot
ExternalSnapshotBinding = _ExternalSnapshotBinding
repository_evidence = _repository_evidence
release_git_evidence = _release_git_evidence
registered_worktrees = _registered_worktrees
read_bound_regular_file = _read_bound_regular_file
stable_snapshot_file = _stable_snapshot_file
capture_source_snapshot = _capture_source_snapshot
create_external_output = _create_external_output
materialize_snapshot = _materialize_snapshot
bind_external_snapshot = _bind_external_snapshot


def _artifact_record(output: Path, name: str) -> _SnapshotFile:
    record = _stable_snapshot_file(output, name)
    if not record.payload:
        _fail("external test-gate artifact is empty")
    return record


def _authority_artifact_names(*, installed: bool) -> frozenset[str]:
    names = {
        "command-records.json",
        "coverage.json",
        "coverage.rc",
        "coverage.xml",
        "diff-cover.json",
        "pytest-audit.json",
        "pytest-junit.xml",
    }
    if installed:
        names.update(
            {
                "installed-coverage.json",
                "installed-coverage.rc",
                "installed-pytest-audit.json",
                "installed-pytest-junit.xml",
            }
        )
    return frozenset(names)


def _validate_external_output_layout(output: Path, *, installed: bool) -> None:
    authority = _authority_artifact_names(installed=installed)
    runtime_directories = {
        "home",
        "pycache",
        "pytest-cache",
        "pytest-tmp",
        "snapshot",
        "tmp",
    }
    if installed:
        runtime_directories.update({"installed-pytest-cache", "installed-pytest-tmp"})
    runtime_prefixes = (
        (".coverage", ".installed-coverage") if installed else (".coverage",)
    )
    found_authority: set[str] = set()
    descriptor = _open_root_directory(output)
    try:
        for entry in _descriptor_entries(descriptor):
            metadata = _validated_source_entry(descriptor, entry)
            if stat.S_ISDIR(metadata.st_mode):
                if entry.name not in runtime_directories:
                    _fail("external test-gate output has an unexpected directory")
                continue
            if metadata.st_nlink != 1:
                _fail("external test-gate output has a linked artifact")
            if entry.name in authority:
                found_authority.add(entry.name)
            elif not entry.name.startswith(runtime_prefixes):
                _fail("external test-gate output has an unexpected file")
    finally:
        os.close(descriptor)
    if frozenset(found_authority) != authority:
        _fail("external test-gate output authority inventory is incomplete")


def _changed_python_lines(
    git: Git,
    *,
    root: Path,
    merge_base: str,
    candidate: str,
) -> dict[str, frozenset[int]]:
    names_payload = _checked_git(
        git,
        (
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACMRTUXB",
            "--no-renames",
            merge_base,
            candidate,
            "--",
            *_MEASURED_ROOTS,
        ),
        cwd=root,
    ).stdout
    names = _parse_changed_paths(names_payload)
    changed: dict[str, frozenset[int]] = {}
    for name in names:
        if not name.endswith(".py") or not name.startswith(
            tuple(f"{measured}/" for measured in _MEASURED_ROOTS)
        ):
            continue
        diff = _checked_git(
            git,
            (
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                merge_base,
                candidate,
                "--",
                name,
            ),
            cwd=root,
        ).stdout
        changed[name] = _parse_changed_hunks(diff)
    return changed


def _parse_changed_paths(payload: bytes) -> tuple[str, ...]:
    if payload and not payload.endswith(b"\0"):
        _fail("changed-path Git evidence is truncated")
    names = tuple(
        _canonical_repository_path(raw, boundary="changed repository path")
        for raw in (payload.removesuffix(b"\0").split(b"\0") if payload else ())
    )
    if len(names) != len(set(names)):
        _fail("changed-path Git evidence is duplicated")
    return names


def _parse_changed_hunks(payload: bytes) -> frozenset[int]:
    diff_lines = payload.splitlines()
    if b"\0" in payload or any(
        line == b"GIT binary patch" or line.startswith(b"Binary files ")
        for line in diff_lines
    ):
        _fail("changed Python input has binary diff evidence")
    lines: set[int] = set()
    for line in diff_lines:
        if not line.startswith(b"@@"):
            continue
        match = _DIFF_HUNK_PATTERN.match(line)
        if match is None:
            _fail("changed-line Git hunk is malformed")
        start = int(match.group("start"), 10)
        raw_count = match.group("count")
        count = 1 if raw_count is None else int(raw_count, 10)
        if count:
            if start < 1:
                _fail("changed-line Git hunk has an invalid range")
            lines.update(range(start, start + count))
    return frozenset(lines)


def _command_environment(
    snapshot: Path, output: Path, rcfile: Path
) -> tuple[tuple[str, str], ...]:
    del snapshot
    values = {
        "COVERAGE_FILE": (output / ".coverage").as_posix(),
        "COVERAGE_PROCESS_START": rcfile.as_posix(),
        "FORCE_COLOR": "0",
        "HOME": (output / "home").as_posix(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "NPLG_PYTHON_ONLY_CONTRACT_GATE": "1",
        "PATH": os.pathsep.join(
            (Path(sys.executable).parent.as_posix(), "/usr/bin", "/bin")
        ),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPYCACHEPREFIX": (output / "pycache").as_posix(),
        "TEMP": (output / "tmp").as_posix(),
        "TMP": (output / "tmp").as_posix(),
        "TMPDIR": (output / "tmp").as_posix(),
    }
    return tuple(sorted(values.items()))


def _trusted_tool_proof(
    tool_modules: tuple[tuple[str, str, str], ...] = _TRUSTED_TOOL_MODULES,
) -> tuple[tuple[str, str, str, str], ...]:
    proof: list[tuple[str, str, str, str]] = []
    try:
        site_packages = Path(sysconfig.get_path("purelib")).resolve(strict=True)
    except (KeyError, OSError, TypeError) as exc:
        _fail_from("trusted site-packages root is unavailable", exc)
    for module_name, distribution, expected_version in tool_modules:
        try:
            installed_distribution = next(
                iter(
                    importlib.metadata.distributions(
                        name=distribution,
                        path=[site_packages.as_posix()],
                    )
                )
            )
            specification = importlib.machinery.PathFinder.find_spec(
                module_name,
                [site_packages.as_posix()],
            )
        except (ImportError, StopIteration) as exc:
            _fail_from("trusted test tool is unavailable", exc)
        if (
            installed_distribution.version != expected_version
            or specification is None
            or specification.origin is None
        ):
            _fail("trusted test tool version or import origin is invalid")
        try:
            origin = Path(specification.origin).resolve(strict=True)
            metadata = origin.lstat()
        except OSError as exc:
            _fail_from("trusted test tool import origin is unavailable", exc)
        if not stat.S_ISREG(metadata.st_mode) or site_packages not in origin.parents:
            _fail("trusted test tool import origin is not a regular file")
        proof.append((module_name, distribution, expected_version, origin.as_posix()))
    return tuple(proof)


def _trusted_python_command(
    mode: _TrustedPythonMode,
    *,
    import_roots: tuple[Path, ...],
    application_package_root: Path | None = None,
    arguments: tuple[str, ...],
    tool_modules: tuple[tuple[str, str, str], ...] = _TRUSTED_TOOL_MODULES,
) -> tuple[str, ...]:
    roots = tuple(root.as_posix() for root in import_roots)
    return (
        sys.executable,
        "-I",
        "-B",
        "-c",
        _TRUSTED_TOOL_DRIVER,
        mode,
        json.dumps(roots, ensure_ascii=True, separators=(",", ":")),
        json.dumps(
            _trusted_tool_proof(tool_modules),
            ensure_ascii=True,
            separators=(",", ":"),
        ),
        json.dumps(
            (
                None
                if application_package_root is None
                else application_package_root.as_posix()
            ),
            ensure_ascii=True,
            separators=(",", ":"),
        ),
        *arguments,
    )


def trusted_mutation_python_command(
    *,
    import_roots: tuple[Path, ...],
    arguments: tuple[str, ...],
) -> tuple[str, ...]:
    """Build the one isolated command admitted for the mutation authority."""
    return _trusted_python_command(
        "mutmut",
        import_roots=import_roots,
        arguments=arguments,
        tool_modules=_MUTATION_TRUSTED_TOOL_MODULES,
    )


def _run_command(
    executor: Executor,
    clock: Clock,
    request: CommandRequest,
    *,
    accepted_returncodes: frozenset[int] = _SUCCESS_RETURN_CODES,
) -> tuple[CommandResult, _CommandEvidence]:
    started = clock.monotonic()
    result = executor(request)
    completed = clock.monotonic()
    if (
        not math.isfinite(started)
        or not math.isfinite(completed)
        or completed < started
        or result.argv != request.argv
        or type(result.returncode) is not int
        or result.returncode < 0
        or result.returncode not in accepted_returncodes
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > request.stdout_limit_bytes
        or len(result.stderr) > request.stderr_limit_bytes
    ):
        _fail("test-gate command evidence is incomplete or unsuccessful")
    return result, _CommandEvidence(
        argv=result.argv,
        returncode=result.returncode,
        stdout_bytes=len(result.stdout),
        stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
        stderr_bytes=len(result.stderr),
        stderr_sha256=hashlib.sha256(result.stderr).hexdigest(),
        duration_seconds=completed - started,
    )


def _collected_nodes(payload: bytes, *, allow_empty: bool) -> tuple[str, ...]:
    nodes: list[str] = []
    total_bytes = 0
    for raw_line in payload.splitlines():
        if b"::" not in raw_line:
            continue
        try:
            node = raw_line.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            _fail_from("pytest node ID is not UTF-8", exc)
        if (
            not node.startswith("tests/")
            or len(raw_line) > _MAX_NODE_ID_BYTES
            or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in node)
        ):
            _fail("pytest node ID is outside the closed test inventory")
        total_bytes += len(raw_line)
        nodes.append(node)
    if (
        (not allow_empty and not nodes)
        or len(nodes) > _MAX_COLLECTED_NODES
        or total_bytes > _MAX_GIT_OUTPUT_BYTES
        or len(nodes) != len(set(nodes))
    ):
        _fail("pytest node inventory is empty, duplicated, or oversized")
    return tuple(nodes)


def _collect_deterministic_nodes(
    runtime: _CommandRuntime,
    *,
    snapshot: Path,
    registry: ExternalGateRegistry,
) -> tuple[str, ...]:
    common_arguments = (
        "--collect-only",
        "-q",
        "--strict-markers",
        "--import-mode=importlib",
        "--hypothesis-profile=ci",
    )
    import_roots = (snapshot / "src", snapshot)
    common = _trusted_python_command(
        "pytest",
        import_roots=import_roots,
        application_package_root=snapshot / "src" / "nplg_mcp",
        arguments=common_arguments,
    )
    complete_result, record = _run_command(
        runtime.executor,
        runtime.clock,
        CommandRequest(argv=common, cwd=snapshot, environment=runtime.environment),
    )
    runtime.evidence.append(record)
    complete = _collected_nodes(complete_result.stdout, allow_empty=False)
    external: set[str] = set()
    classified: set[tuple[str, str]] = set()
    for marker in ("live", "staging", "container"):
        result, record = _run_command(
            runtime.executor,
            runtime.clock,
            CommandRequest(
                argv=_trusted_python_command(
                    "pytest",
                    import_roots=import_roots,
                    application_package_root=snapshot / "src" / "nplg_mcp",
                    arguments=(*common_arguments, "-m", marker),
                ),
                cwd=snapshot,
                environment=runtime.environment,
            ),
            accepted_returncodes=frozenset({0, _PYTEST_NO_TESTS_COLLECTED}),
        )
        runtime.evidence.append(record)
        nodes = _collected_nodes(result.stdout, allow_empty=True)
        if result.returncode == _PYTEST_NO_TESTS_COLLECTED and nodes:
            _fail("pytest reported an empty marked collection with node IDs")
        if not set(nodes) <= set(complete) or external & set(nodes):
            _fail("external pytest node classification is inconsistent")
        external.update(nodes)
        classified.update((marker, node) for node in nodes)
    expected = {(gate.kind, gate.node_id) for gate in registry.gates}
    if classified != expected:
        _fail("external pytest nodes do not match the reviewed registry")
    return tuple(node for node in complete if node not in external)


def _coverage_configuration(
    output: Path,
    *,
    snapshot_root: Path,
    paths_configuration: bytes = b"",
) -> bytes:
    return (
        "[run]\n"
        "branch = true\n"
        "parallel = true\n"
        "relative_files = false\n"
        "patch = subprocess\n"
        "source =\n"
        f"    {snapshot_root.as_posix()}\n"
        "omit =\n"
        f"    {(snapshot_root / 'tests' / '*').as_posix()}\n"
        f"data_file = {(output / '.coverage').as_posix()}\n"
        "[report]\n"
        "fail_under = 95\n"
        "[xml]\n"
        f"output = {(output / 'coverage.xml').as_posix()}\n"
        "[json]\n"
        f"output = {(output / 'coverage.json').as_posix()}\n"
    ).encode() + paths_configuration


def _installed_coverage_configuration(
    output: Path,
    *,
    installed_package_root: Path,
) -> bytes:
    return (
        "[run]\n"
        "branch = true\n"
        "parallel = true\n"
        "relative_files = false\n"
        "patch = subprocess\n"
        f"source = {installed_package_root.as_posix()}\n"
        f"data_file = {(output / '.installed-coverage').as_posix()}\n"
        "[json]\n"
        f"output = {(output / 'installed-coverage.json').as_posix()}\n"
    ).encode()


def _write_private_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        _fail_from("external test-gate file could not be created", exc)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                _fail("external test-gate file write was incomplete")
            written += count
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _read_external_file(
    filesystem: Filesystem,
    output: Path,
    *,
    name: str,
    max_bytes: int,
) -> bytes:
    path = output / name
    try:
        before = path.lstat()
    except OSError as exc:
        _fail_from("external report is absent", exc)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > max_bytes
    ):
        _fail("external report is not a bounded single-link regular file")
    try:
        payload = filesystem.read_bytes(path)
        after = path.lstat()
    except OSError as exc:
        _fail_from("external report could not be read stably", exc)
    if (
        type(payload) is not bytes
        or len(payload) != before.st_size
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
    ):
        _fail("external report changed while being read")
    return payload


def _validate_junit(payload: bytes, *, expected_tests: int) -> None:
    try:
        root = SafeElementTree.fromstring(payload)
    except (ParseError, DefusedXmlException) as exc:
        _fail_from("pytest JUnit report is malformed or unsafe", exc)
    elements = tuple(root.iter())
    if len(elements) > _MAX_XML_ELEMENTS or root.tag not in {"testsuite", "testsuites"}:
        _fail("pytest JUnit report shape is invalid")
    testcases = tuple(element for element in elements if element.tag == "testcase")
    if len(testcases) != expected_tests:
        _fail("pytest JUnit test count disagrees with collection")
    for element in elements:
        if element.tag in {"failure", "error", "skipped"}:
            _fail("pytest JUnit report contains a non-passing test")
        if element.tag in {"testsuite", "testsuites"}:
            _validate_junit_summary(element)
    root_tests = root.attrib.get("tests")
    if root_tests is not None and (
        not root_tests.isascii()
        or not root_tests.isdecimal()
        or int(root_tests) != expected_tests
    ):
        _fail("pytest JUnit root count disagrees with collection")


def _validate_junit_summary(element: Element) -> None:
    for field in ("failures", "errors", "skipped"):
        raw_value = element.attrib.get(field, "0")
        if not raw_value.isascii() or not raw_value.isdecimal() or int(raw_value) != 0:
            _fail("pytest JUnit summary contains a non-passing test")


def _validate_pytest_audit(
    payload: bytes,
    *,
    expected_nodes: tuple[str, ...],
) -> None:
    document = _require_object(
        _load_closed_json(
            payload,
            max_bytes=_MAX_REPORT_BYTES,
            max_nodes=_MAX_REPORT_JSON_NODES,
            max_depth=_MAX_REPORT_JSON_DEPTH,
        ),
        context="pytest execution audit",
    )
    if set(document) != {"version", "collected", "deselected", "calls"}:
        _fail("pytest execution audit fields are malformed")
    if document["version"] != 1:
        _fail("pytest execution audit version is unsupported")
    collected = document["collected"]
    deselected = document["deselected"]
    calls = document["calls"]
    if (
        type(collected) is not list
        or collected != list(expected_nodes)
        or type(deselected) is not list
        or deselected
        or type(calls) is not list
    ):
        _fail("pytest execution audit proves omission, deselection, or non-pass")
    call_records = cast("list[object]", calls)
    if any(
        type(record) is not list
        or len(cast("list[object]", record)) != _PYTEST_CALL_FIELD_COUNT
        or type(cast("list[object]", record)[0]) is not str
        or cast("list[object]", record)[1] != "passed"
        for record in call_records
    ):
        _fail("pytest execution audit proves omission, deselection, or non-pass")
    called_nodes = {
        cast("str", cast("list[object]", record)[0]) for record in call_records
    }
    if called_nodes != set(expected_nodes):
        _fail("pytest execution audit proves omission, deselection, or non-pass")


def _installed_runtime_environment(
    runtime: _CommandRuntime,
    *,
    output: Path,
    rcfile: Path,
) -> tuple[tuple[str, str], ...]:
    values = dict(runtime.environment)
    values["COVERAGE_FILE"] = (output / ".installed-coverage").as_posix()
    values["COVERAGE_PROCESS_START"] = rcfile.as_posix()
    return tuple(sorted(values.items()))


def _validate_installed_coverage(
    filesystem: Filesystem,
    *,
    output: Path,
    proof: InstalledPackageProof,
) -> None:
    payload = _read_external_file(
        filesystem,
        output,
        name="installed-coverage.json",
        max_bytes=_MAX_REPORT_BYTES,
    )
    document = _load_coverage_json(payload)
    if type(document) is not dict:
        _fail("installed-package coverage report must be an object")
    files_value = cast("dict[str, object]", document).get("files")
    if type(files_value) is not dict or not files_value:
        _fail("installed-package coverage report has no measured files")
    files = cast("dict[object, object]", files_value)
    expected = {
        (proof.installed_package_root / record.path).resolve(strict=True)
        for record in proof.files
        if record.path.endswith(".py")
    }
    measured: set[Path] = set()
    executed = False
    for raw_path, raw_record in files.items():
        if type(raw_path) is not str or not Path(raw_path).is_absolute():
            _fail("installed-package coverage path is not absolute")
        try:
            path = Path(raw_path).resolve(strict=True)
        except OSError as exc:
            _fail_from("installed-package coverage path is unavailable", exc)
        if type(raw_record) is not dict:
            _fail("installed-package coverage file record is malformed")
        executed_lines = cast("dict[str, object]", raw_record).get("executed_lines")
        if type(executed_lines) is not list:
            _fail("installed-package coverage execution evidence is malformed")
        executed = executed or bool(cast("list[object]", executed_lines))
        measured.add(path)
    if measured != expected or not executed:
        _fail("installed-package suite did not execute the exact installed package")


def _run_installed_package_suite(
    execution: _GateExecution,
    runtime: _CommandRuntime,
    *,
    materialized: _MaterializedSnapshot,
    installed: _InstalledRuntimeEvidence,
    nodes: tuple[str, ...],
) -> tuple[_SnapshotFile, ...]:
    output = execution.output
    rcfile = output / "installed-coverage.rc"
    junit = output / "installed-pytest-junit.xml"
    audit = output / "installed-pytest-audit.json"
    report = output / "installed-coverage.json"
    _write_private_file(
        rcfile,
        _installed_coverage_configuration(
            output,
            installed_package_root=installed.proof.installed_package_root,
        ),
    )
    configuration = _artifact_record(output, "installed-coverage.rc")
    environment = _installed_runtime_environment(
        runtime,
        output=output,
        rcfile=rcfile,
    )
    import_roots = (
        installed.proof.installed_package_root.parent,
        materialized.root,
    )
    commands = (
        _trusted_python_command(
            "coverage-pytest-installed",
            import_roots=import_roots,
            application_package_root=installed.proof.installed_package_root,
            arguments=(
                rcfile.as_posix(),
                audit.as_posix(),
                "run",
                "-q",
                "--strict-markers",
                "--import-mode=importlib",
                "--hypothesis-profile=ci",
                "-o",
                "xfail_strict=true",
                "-o",
                f"cache_dir={(output / 'installed-pytest-cache').as_posix()}",
                f"--basetemp={(output / 'installed-pytest-tmp').as_posix()}",
                f"--junitxml={junit.as_posix()}",
                *nodes,
            ),
        ),
        _trusted_python_command(
            "coverage",
            import_roots=import_roots,
            arguments=("combine", f"--rcfile={rcfile.as_posix()}"),
        ),
        _trusted_python_command(
            "coverage",
            import_roots=import_roots,
            arguments=(
                "json",
                f"--rcfile={rcfile.as_posix()}",
                "-o",
                report.as_posix(),
            ),
        ),
    )
    for argv in commands:
        _, record = _run_command(
            runtime.executor,
            runtime.clock,
            CommandRequest(
                argv=argv,
                cwd=materialized.root,
                environment=environment,
                timeout_seconds=1800.0,
                stdout_limit_bytes=32 * 1024 * 1024,
                stderr_limit_bytes=32 * 1024 * 1024,
            ),
        )
        runtime.evidence.append(record)
    _validate_junit(
        _read_external_file(
            execution.filesystem,
            output,
            name="installed-pytest-junit.xml",
            max_bytes=_MAX_REPORT_BYTES,
        ),
        expected_tests=len(nodes),
    )
    _validate_pytest_audit(
        _read_external_file(
            execution.filesystem,
            output,
            name="installed-pytest-audit.json",
            max_bytes=_MAX_REPORT_BYTES,
        ),
        expected_nodes=nodes,
    )
    _validate_installed_coverage(
        execution.filesystem,
        output=output,
        proof=installed.proof,
    )
    return (
        configuration,
        _artifact_record(output, "installed-pytest-junit.xml"),
        _artifact_record(output, "installed-pytest-audit.json"),
        _artifact_record(output, "installed-coverage.json"),
    )


def _run_coverage_commands(
    runtime: _CommandRuntime,
    *,
    materialized: _MaterializedSnapshot,
    output: Path,
    nodes: tuple[str, ...],
) -> tuple[_SnapshotFile, ...]:
    rcfile = output / "coverage.rc"
    junit = output / "pytest-junit.xml"
    coverage_xml = output / "coverage.xml"
    coverage_json = output / "coverage.json"
    audit = output / "pytest-audit.json"
    import_roots = (materialized.root / "src", materialized.root)
    application_package_root = materialized.root / "src" / "nplg_mcp"
    commands = (
        _trusted_python_command(
            "coverage-pytest",
            import_roots=import_roots,
            application_package_root=application_package_root,
            arguments=(
                rcfile.as_posix(),
                audit.as_posix(),
                "run",
                "-q",
                "--strict-markers",
                "--import-mode=importlib",
                "--hypothesis-profile=ci",
                "-o",
                "xfail_strict=true",
                "-o",
                f"cache_dir={(output / 'pytest-cache').as_posix()}",
                f"--basetemp={(output / 'pytest-tmp').as_posix()}",
                f"--junitxml={junit.as_posix()}",
                *nodes,
            ),
        ),
        _trusted_python_command(
            "coverage",
            import_roots=import_roots,
            application_package_root=application_package_root,
            arguments=("combine", f"--rcfile={rcfile.as_posix()}"),
        ),
        _trusted_python_command(
            "coverage",
            import_roots=import_roots,
            application_package_root=application_package_root,
            arguments=(
                "xml",
                f"--rcfile={rcfile.as_posix()}",
                "-o",
                coverage_xml.as_posix(),
            ),
        ),
        _trusted_python_command(
            "coverage",
            import_roots=import_roots,
            application_package_root=application_package_root,
            arguments=(
                "json",
                f"--rcfile={rcfile.as_posix()}",
                "-o",
                coverage_json.as_posix(),
            ),
        ),
        _trusted_python_command(
            "diff-cover",
            import_roots=(),
            arguments=(
                coverage_xml.as_posix(),
                f"--compare-branch={materialized.merge_base}",
                "--fail-under=95",
                "--format",
                f"json:{(output / 'diff-cover.json').as_posix()}",
            ),
        ),
    )
    generated: list[_SnapshotFile] = []
    generated_by_index = {
        0: "pytest-junit.xml",
        2: "coverage.xml",
        3: "coverage.json",
        4: "diff-cover.json",
    }
    for index, argv in enumerate(commands):
        _, record = _run_command(
            runtime.executor,
            runtime.clock,
            CommandRequest(
                argv=argv,
                cwd=materialized.root,
                environment=runtime.environment,
                timeout_seconds=1800.0,
                stdout_limit_bytes=32 * 1024 * 1024,
                stderr_limit_bytes=32 * 1024 * 1024,
            ),
        )
        runtime.evidence.append(record)
        name = generated_by_index.get(index)
        if name is not None:
            generated.append(_artifact_record(output, name))
        if index == 0:
            generated.append(_artifact_record(output, "pytest-audit.json"))
    return tuple(generated)


def _write_command_evidence(output: Path, records: list[_CommandEvidence]) -> None:
    document = {
        "version": 1,
        "commands": [
            {
                "argv": list(record.argv),
                "returncode": record.returncode,
                "stdout_bytes": record.stdout_bytes,
                "stdout_sha256": record.stdout_sha256,
                "stderr_bytes": record.stderr_bytes,
                "stderr_sha256": record.stderr_sha256,
                "duration_seconds": record.duration_seconds,
            }
            for record in records
        ],
    }
    payload = (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    _write_private_file(output / "command-records.json", payload)


def _validated_gate_request(request: TestGateRequest) -> tuple[Path, str]:
    if not request.worktree.is_absolute():
        _fail("test-gate worktree must be absolute")
    try:
        root = request.worktree.resolve(strict=True)
    except OSError as exc:
        _fail_from("test-gate worktree is unavailable", exc)
    if root != request.worktree or not root.is_dir():
        _fail("test-gate worktree must be a canonical directory")
    comparison_ref = _canonical_comparison_ref(request.compare_branch)
    if request.require_clean != (request.candidate is not None):
        _fail("release mode requires both --require-clean and --candidate")
    if (request.installed_package_root is None) != (request.package_manifest is None):
        _fail("installed-wheel mode requires both package arguments")
    if request.installed_package_root is not None and not request.require_clean:
        _fail("installed-wheel runtime mode requires a clean release candidate")
    return root, comparison_ref


def _validate_release_state(
    request: TestGateRequest,
    evidence: _RepositoryEvidence,
) -> None:
    if not request.require_clean:
        return
    candidate = cast("str", request.candidate)
    if _GIT_OBJECT_PATTERN.fullmatch(candidate) is None or candidate != evidence.head:
        _fail("release candidate does not match exact clean HEAD")
    if not evidence.clean:
        _fail("release test gate requires a clean worktree")


def _snapshot_policies(
    source_snapshot: _SourceSnapshot,
    *,
    materialized_root: Path,
) -> tuple[CoveragePolicy, ExternalGateRegistry]:
    payload_by_path = {record.path: record.payload for record in source_snapshot.files}
    try:
        coverage_policy_payload = payload_by_path["security/coverage-policy.json"]
        registry_payload = payload_by_path["security/external-test-gates.json"]
    except KeyError as exc:
        _fail_from("test-gate policy input is absent from the source snapshot", exc)
    policy = parse_coverage_policy(coverage_policy_payload, root=materialized_root)
    registry = parse_external_gate_registry(registry_payload)
    return policy, registry


def _reject_tool_shadows(
    source_snapshot: _SourceSnapshot,
    *,
    shadows: tuple[str, ...],
    message: str,
) -> None:
    for record in source_snapshot.files:
        if any(
            record.path == f"{prefix}{shadow}"
            or (shadow.endswith("/") and record.path.startswith(f"{prefix}{shadow}"))
            for prefix in ("", "src/")
            for shadow in shadows
        ):
            _fail(message)


def _reject_candidate_tool_shadows(source_snapshot: _SourceSnapshot) -> None:
    _reject_tool_shadows(
        source_snapshot,
        shadows=_TRUSTED_TOOL_SHADOWS,
        message="candidate snapshot shadows a trusted test tool",
    )


def reject_mutation_tool_shadows(source_snapshot: _SourceSnapshot) -> None:
    """Reject every candidate path that could replace a mutation-process tool."""
    _reject_tool_shadows(
        source_snapshot,
        shadows=_MUTATION_TOOL_SHADOWS,
        message="candidate snapshot shadows a trusted mutation tool",
    )


def _prepare_command_runtime(
    execution: _GateExecution,
    *,
    snapshot_root: Path,
    installed: _InstalledRuntimeEvidence | None,
) -> _CommandRuntime:
    for directory in ("home", "tmp", "pycache"):
        (execution.output / directory).mkdir(mode=_PRIVATE_DIRECTORY_MODE)
    rcfile = execution.output / "coverage.rc"
    paths_configuration = (
        b"" if installed is None else installed.proof.coverage_paths_configuration
    )
    _write_private_file(
        rcfile,
        _coverage_configuration(
            execution.output,
            snapshot_root=snapshot_root,
            paths_configuration=paths_configuration,
        ),
    )
    return _CommandRuntime(
        executor=execution.executor,
        clock=execution.clock,
        environment=_command_environment(snapshot_root, execution.output, rcfile),
        evidence=[],
    )


def _validated_coverage_result(
    execution: _GateExecution,
    *,
    materialized: _MaterializedSnapshot,
    policy: CoveragePolicy,
    expected_nodes: tuple[str, ...],
) -> TestGateResult:
    junit_payload = _read_external_file(
        execution.filesystem,
        execution.output,
        name="pytest-junit.xml",
        max_bytes=_MAX_REPORT_BYTES,
    )
    _validate_junit(junit_payload, expected_tests=len(expected_nodes))
    _validate_pytest_audit(
        _read_external_file(
            execution.filesystem,
            execution.output,
            name="pytest-audit.json",
            max_bytes=_MAX_REPORT_BYTES,
        ),
        expected_nodes=expected_nodes,
    )
    coverage_xml = execution.output / "coverage.xml"
    coverage_json = execution.output / "coverage.json"
    measurements = parse_coverage_reports(
        xml_payload=_read_external_file(
            execution.filesystem,
            execution.output,
            name="coverage.xml",
            max_bytes=_MAX_REPORT_BYTES,
        ),
        json_payload=_read_external_file(
            execution.filesystem,
            execution.output,
            name="coverage.json",
            max_bytes=_MAX_REPORT_BYTES,
        ),
        policy=policy,
        snapshot_root=materialized.root,
        changed_lines=materialized.changed_lines,
    )
    return TestGateResult(
        coverage_xml=coverage_xml,
        coverage_json=coverage_json,
        measurements=measurements,
    )


def _finalize_test_gate(
    execution: _GateExecution,
    evidence: _FinalGateEvidence,
) -> None:
    if (
        _capture_source_snapshot(execution.git, root=execution.root)
        != evidence.source_snapshot
    ):
        _fail("source snapshot changed while the test gate ran")
    _verify_installed_runtime_unchanged(execution, evidence.installed)
    external_after = _bind_external_snapshot(
        execution.git,
        materialized=evidence.materialized,
        source_snapshot=evidence.source_snapshot,
    )
    if external_after != evidence.external_before:
        _fail("materialized snapshot commit, tree, index, refs, or inputs changed")
    after = _repository_evidence(execution.git, root=execution.root)
    if after != execution.before:
        _fail("test gate mutated source Git or worktree state")
    if (
        execution.release_before is not None
        and _release_git_evidence(
            execution.git,
            root=execution.root,
        )
        != execution.release_before
    ):
        _fail("release test gate changed raw Git tree, index, refs, HEAD, or objects")
    _write_command_evidence(execution.output, evidence.runtime.evidence)
    expected_artifacts = (
        *evidence.captured_artifacts,
        _artifact_record(execution.output, "command-records.json"),
    )
    _validate_external_output_layout(
        execution.output,
        installed=evidence.installed is not None,
    )
    for expected in expected_artifacts:
        if _artifact_record(execution.output, expected.path) != expected:
            _fail("external test-gate configuration or report changed")
    if (
        _bind_external_snapshot(
            execution.git,
            materialized=evidence.materialized,
            source_snapshot=evidence.source_snapshot,
        )
        != evidence.external_before
    ):
        _fail("materialized snapshot changed before test-gate success")


def _execute_test_gate(execution: _GateExecution) -> TestGateResult:
    source_snapshot = _capture_source_snapshot(execution.git, root=execution.root)
    _reject_candidate_tool_shadows(source_snapshot)
    merge_base = _comparison_base(
        execution.git,
        root=execution.root,
        ref=execution.comparison_ref,
        head=execution.before.head,
    )
    materialized = _materialize_snapshot(
        execution.root,
        source_snapshot,
        merge_base=merge_base,
        output=execution.output,
        git=execution.git,
    )
    if _capture_source_snapshot(execution.git, root=execution.root) != source_snapshot:
        _fail("source snapshot changed during external materialization")
    policy, registry = _snapshot_policies(
        source_snapshot,
        materialized_root=materialized.root,
    )
    installed = _prepare_installed_runtime(
        execution,
        materialized_root=materialized.root,
    )
    runtime = _prepare_command_runtime(
        execution,
        snapshot_root=materialized.root,
        installed=installed,
    )
    external_before = _bind_external_snapshot(
        execution.git,
        materialized=materialized,
        source_snapshot=source_snapshot,
    )
    if (
        execution.release_before is not None
        and execution.release_before.tree != external_before.tree
    ):
        _fail("release candidate tree differs from the materialized input tree")
    configuration_before = _artifact_record(execution.output, "coverage.rc")
    deterministic_nodes = _collect_deterministic_nodes(
        runtime,
        snapshot=materialized.root,
        registry=registry,
    )
    installed_artifacts: tuple[_SnapshotFile, ...] = ()
    if installed is not None:
        installed_artifacts = _run_installed_package_suite(
            execution,
            runtime,
            materialized=materialized,
            installed=installed,
            nodes=deterministic_nodes,
        )
    generated_artifacts = _run_coverage_commands(
        runtime,
        materialized=materialized,
        output=execution.output,
        nodes=deterministic_nodes,
    )
    result = _validated_coverage_result(
        execution,
        materialized=materialized,
        policy=policy,
        expected_nodes=deterministic_nodes,
    )
    _finalize_test_gate(
        execution,
        _FinalGateEvidence(
            runtime=runtime,
            source_snapshot=source_snapshot,
            materialized=materialized,
            installed=installed,
            external_before=external_before,
            captured_artifacts=(
                configuration_before,
                *installed_artifacts,
                *generated_artifacts,
            ),
        ),
    )
    return result


def run_test_gate(
    request: TestGateRequest,
    *,
    executor: Executor,
    clock: Clock,
    filesystem: Filesystem,
    git: Git,
) -> TestGateResult:
    """Run the externally contained release-quality test gate."""
    root, comparison_ref = _validated_gate_request(request)
    before = _repository_evidence(git, root=root)
    _validate_release_state(request, before)
    release_before = (
        _release_git_evidence(git, root=root) if request.require_clean else None
    )
    registered = _registered_worktrees(git, root=root)
    output, temporary = _create_external_output(
        request.output_dir,
        registered_worktrees=registered,
    )
    succeeded = False
    try:
        result = _execute_test_gate(
            _GateExecution(
                request=request,
                root=root,
                comparison_ref=comparison_ref,
                before=before,
                release_before=release_before,
                output=output,
                executor=executor,
                clock=clock,
                filesystem=filesystem,
                git=git,
            )
        )
        succeeded = True
        return result
    finally:
        if temporary or not succeeded:
            shutil.rmtree(output, ignore_errors=True)


def _validated_system_environment(
    pairs: object,
) -> dict[str, str]:
    if type(pairs) is not tuple:
        _fail("system command environment is malformed")
    environment: dict[str, str] = {}
    for raw_pair in cast("tuple[object, ...]", pairs):
        if type(raw_pair) is not tuple:
            _fail("system command environment is not a closed string mapping")
        pair = cast("tuple[object, ...]", raw_pair)
        if len(pair) != _ENVIRONMENT_PAIR_LENGTH:
            _fail("system command environment is not a closed string mapping")
        key, value = pair
        if (
            type(key) is not str
            or type(value) is not str
            or re.fullmatch(r"[A-Z_][A-Z0-9_]*", key) is None
            or "\0" in value
            or key in environment
        ):
            _fail("system command environment is not a closed string mapping")
        environment[key] = value
    return environment


def _system_executable_identity(executable: Path) -> tuple[int, ...]:
    try:
        link_metadata = executable.lstat()
        resolved = executable.resolve(strict=True)
        target_metadata = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        _fail_from("system command executable is unavailable", exc)
    if (
        not (stat.S_ISREG(link_metadata.st_mode) or stat.S_ISLNK(link_metadata.st_mode))
        or not stat.S_ISREG(target_metadata.st_mode)
        or not os.access(executable, os.X_OK)
    ):
        _fail("system command executable is not an executable regular file")
    return (
        link_metadata.st_dev,
        link_metadata.st_ino,
        link_metadata.st_mode,
        link_metadata.st_size,
        link_metadata.st_mtime_ns,
        link_metadata.st_ctime_ns,
        target_metadata.st_dev,
        target_metadata.st_ino,
        target_metadata.st_mode,
        target_metadata.st_size,
        target_metadata.st_mtime_ns,
        target_metadata.st_ctime_ns,
    )


def _validated_system_request(
    request: CommandRequest,
    *,
    allowed_executables: tuple[Path, ...],
) -> tuple[Path, dict[str, str], tuple[int, ...]]:
    if (
        type(request.argv) is not tuple
        or not request.argv
        or any(
            type(argument) is not str or not argument or "\0" in argument
            for argument in request.argv
        )
        or sum(len(argument.encode("utf-8")) for argument in request.argv)
        > _MAX_PROCESS_ARGUMENT_BYTES
    ):
        _fail("system command argv is empty, malformed, or oversized")
    if (
        type(request.timeout_seconds) not in {int, float}
        or not math.isfinite(request.timeout_seconds)
        or not 0 < request.timeout_seconds <= _MAX_PROCESS_TIMEOUT_SECONDS
        or type(request.stdout_limit_bytes) is not int
        or type(request.stderr_limit_bytes) is not int
        or not 0 < request.stdout_limit_bytes <= _MAX_PROCESS_STREAM_BYTES
        or not 0 < request.stderr_limit_bytes <= _MAX_PROCESS_STREAM_BYTES
    ):
        _fail("system command resource bounds are invalid")
    cwd_value = cast("object", request.cwd)
    if not isinstance(cwd_value, Path) or not cwd_value.is_absolute():
        _fail("system command working directory must be absolute")
    cwd = cwd_value
    try:
        root = cwd.resolve(strict=True)
        root_metadata = cwd.lstat()
    except OSError as exc:
        _fail_from("system command working directory is unavailable", exc)
    if root != cwd or not stat.S_ISDIR(root_metadata.st_mode):
        _fail("system command working directory is not canonical")

    environment = _validated_system_environment(request.environment)

    executable = Path(request.argv[0])
    if not executable.is_absolute() or executable not in allowed_executables:
        _fail("system command executable is outside the reviewed allowlist")
    identity = _system_executable_identity(executable)
    return executable, environment, identity


def _run_system_command(
    request: CommandRequest,
    *,
    allowed_executables: tuple[Path, ...],
) -> CommandResult:
    executable, environment, identity_before = _validated_system_request(
        request,
        allowed_executables=allowed_executables,
    )
    try:
        completed = run_bounded_process(
            request.argv,
            cwd=request.cwd,
            environment=environment,
            limits=ProcessLimits(
                timeout_seconds=request.timeout_seconds,
                stdout_bytes=request.stdout_limit_bytes,
                stderr_bytes=request.stderr_limit_bytes,
            ),
        )
    except (BaselineCaptureError, ValueError) as exc:
        _fail_from("bounded system command failed", exc)
    if _system_executable_identity(executable) != identity_before:
        _fail("system command executable changed during execution")
    return CommandResult(
        argv=request.argv,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


class SystemExecutor:
    """Bounded shell-free executor used by the command-line authority."""

    def __call__(self, request: CommandRequest) -> CommandResult:
        """Execute one reviewed test command."""
        return _run_system_command(
            request,
            allowed_executables=(
                Path(sys.executable),
                Path(sys.executable).parent / "diff-cover",
            ),
        )


class SystemClock:
    """Production monotonic-clock adapter."""

    def monotonic(self) -> float:
        """Return monotonic seconds."""
        return time.monotonic()


class SystemFilesystem:
    """Production bounded-file adapter."""

    def read_bytes(self, path: Path) -> bytes:
        """Read one already-validated report file."""
        return path.read_bytes()


class SystemGit:
    """Production bounded-Git adapter."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> CommandResult:
        """Run one reviewed absolute Git command."""
        return _run_system_command(
            CommandRequest(
                argv=argv,
                cwd=cwd,
                environment=tuple(sorted(environment.items())),
                timeout_seconds=60.0,
                stdout_limit_bytes=_MAX_GIT_OUTPUT_BYTES,
                stderr_limit_bytes=_MAX_GIT_OUTPUT_BYTES,
            ),
            allowed_executables=(Path(_GIT_EXECUTABLE),),
        )


def parse_arguments(argv: Sequence[str] | None = None) -> TestGateRequest:
    """Parse the closed test-gate command-line contract."""
    parser = argparse.ArgumentParser(
        description="Run the externally contained NPLG release-quality test gate.",
        allow_abbrev=False,
    )
    _ = parser.add_argument("--compare-branch", required=True)
    _ = parser.add_argument("--worktree", type=Path, default=Path.cwd())
    _ = parser.add_argument("--output-dir", type=Path)
    _ = parser.add_argument("--require-clean", action="store_true")
    _ = parser.add_argument("--candidate")
    _ = parser.add_argument("--installed-package-root", type=Path)
    _ = parser.add_argument("--package-manifest", type=Path)
    values = cast("dict[str, object]", vars(parser.parse_args(argv)))
    return TestGateRequest(
        worktree=cast("Path", values["worktree"]),
        compare_branch=cast("str", values["compare_branch"]),
        output_dir=cast("Path | None", values["output_dir"]),
        require_clean=cast("bool", values["require_clean"]),
        candidate=cast("str | None", values["candidate"]),
        installed_package_root=cast("Path | None", values["installed_package_root"]),
        package_manifest=cast("Path | None", values["package_manifest"]),
    )


def _verify_runtime_versions() -> None:
    python_version = (sys.version_info.major, sys.version_info.minor)
    if python_version not in _SUPPORTED_PYTHON_VERSIONS:
        _fail("test gate requires a reviewed Python 3.12, 3.13, or 3.14 runtime")
    try:
        root = Path.cwd().resolve(strict=True)
    except OSError as exc:
        _fail_from("test-gate current directory is unavailable", exc)
    for executable in (
        Path(sys.executable),
        Path(sys.executable).parent / "diff-cover",
    ):
        _ = _validated_system_request(
            CommandRequest(argv=(executable.as_posix(), "--version"), cwd=root),
            allowed_executables=(executable,),
        )
    for distribution, expected in _PINNED_RUNTIME_DISTRIBUTIONS:
        try:
            actual = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            _fail_from(f"required test tool {distribution} is not installed", exc)
        if actual != expected:
            _fail(f"required test tool {distribution} is not exactly {expected}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the test gate through its production adapters."""
    request = parse_arguments(argv)
    _verify_runtime_versions()
    result = run_test_gate(
        request,
        executor=SystemExecutor(),
        clock=SystemClock(),
        filesystem=SystemFilesystem(),
        git=SystemGit(),
    )
    measurements = result.measurements
    document = {
        "decision_module_branch_percent": [
            [path, percentage]
            for path, percentage in measurements.decision_module_branch_percent
        ],
        "diff_branch_arc_percent": measurements.diff_branch_arc_percent,
        "diff_line_percent": measurements.diff_line_percent,
        "project_branch_percent": measurements.project_branch_percent,
    }
    rendered = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    stdout = cast("TextIO", sys.stdout)
    _ = stdout.write(rendered + "\n")
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    """Render one bounded process-facing error without a traceback."""
    try:
        return main(argv)
    except TestGateError as error:
        rendered = "test gate failed: " + str(error) + "\n"
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write(rendered)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
