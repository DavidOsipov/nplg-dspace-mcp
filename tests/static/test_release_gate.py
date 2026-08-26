# Copyright (c) 2026 David Osipov
"""Static and adversarial tests for candidate-side release verification."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.metadata
import json
import os
import runpy
import sys
import sysconfig
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Protocol, cast

import pytest

import scripts.verify_release as release_module
from nplg_mcp.json_types import JsonValue, load_json_value, require_json_object
from scripts.baseline_capture_io import ChildResult, ProcessLimits, canonical_json_bytes
from scripts.run_test_gate import (
    CommandResult,
    SourceSnapshot,
    SystemGit,
    capture_source_snapshot,
    parse_external_gate_registry,
)
from scripts.verify_release import (
    GateCommand,
    LauncherCommandSpec,
    ReadOnlyUtilitySpec,
    ReleaseCommandManifest,
    ReleaseOperationSpec,
    ReleaseProfile,
    ReleaseVerificationError,
    candidate_release_status,
    load_release_command_manifest,
    release_command_manifest_digest,
    run_gate_battery,
    validate_candidate_contract_transcript,
)

SUBJECT_DIGEST = "sha256:" + "a" * 64
PYRIGHT_EVIDENCE = (
    "sha256:" + "c" * 64,
    "sha256:" + "d" * 64,
    "sha256:" + "e" * 64,
    "sha256:" + "f" * 64,
)
PROJECT_ROOT = Path(__file__).parents[2]
_CLI_FAILURE = 2
_SECOND_CAPTURE = 2
_TOOL_EVIDENCE_ITEMS = 2
_TRUSTED_DRIVER_REJECTION = 97
_EXPECTED_IDENTITY_VALIDATIONS = 3
_RECOVERY_RTO_OBJECTIVE_SECONDS = 900
_RECOVERY_POLICY_SHA256 = (
    "sha256:6a9f6786479f139129f57c95d18820f55dc192a44d7d32d6ce2a385fe325bbf3"
)
_RECOVERY_STATE_IDS = (
    "clock-high-water-and-boot-state",
    "insertion-high-water",
    "per-object-insertion-sequence-records",
    "orphan-staging-cleanup",
    "post-process-lease-reservation-reconciliation",
)
_RELEASE_COMMAND_MANIFEST = PROJECT_ROOT / "security/release-command-manifests.json"
_OPERATION_IDS = (
    "candidate-battery",
    "external-gate",
    "prepare",
    "staging-proof",
    "reconcile-staging",
    "finalize",
    "custody",
    "reconcile-custody",
    "attestation-workspace",
    "commit-attestation",
    "attest",
    "eligibility",
    "cleanup-run",
)
_LAUNCHER_IDS = (
    "initialize-run",
    "run-operation",
    "run-through",
    "resume-run",
)
_UTILITY_IDS = (
    "validate-output-parent",
    "validate-output-parents",
    "capture-alpic",
)
_COMMON_EXTERNAL_GATE = "common.nplg-live-canary"
_PRIVATE_EXTERNAL_GATES = (
    "private-full.edge-http",
    "private-full.pdf-worker-container",
    "private-full.pdf-worker-write-quota",
    "private-full.recovery-proof",
    "private-full.scanner-container",
)
_CASE_CLASSES = ("adversarial", "fault", "negative", "property", "recovery")


@dataclass(slots=True)
class _FakeRunner:
    returncodes: dict[str, int]
    calls: list[str] = field(default_factory=list[str])

    def __call__(self, command: GateCommand) -> ChildResult:
        self.calls.append(command.name)
        return ChildResult(
            returncode=self.returncodes[command.name],
            stdout=b"{}",
            stderr=b"",
        )


@dataclass(slots=True)
class _Clock:
    value: float = 0.0

    def __call__(self) -> float:
        self.value += 0.25
        return self.value


@dataclass(frozen=True, slots=True)
class _RuntimeIdentityFixture:
    offline_evidence: tuple[str, ...] = PYRIGHT_EVIDENCE


type _ReleaseToolMode = Literal["module", "console"]


class _TrustedReleaseToolView(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def module(self) -> str: ...

    @property
    def distribution(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def mode(self) -> _ReleaseToolMode: ...

    @property
    def entry_name(self) -> str | None: ...

    @property
    def entry_value(self) -> str | None: ...


class _TrustedReleaseToolProofResolver(Protocol):
    def __call__(self, tool: _TrustedReleaseToolView, /) -> object: ...


class _ClosedPythonToolValidator(Protocol):
    def __call__(
        self,
        command: GateCommand,
        completed: ChildResult,
        /,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class _TrustedReleaseToolFixture:
    name: str
    module: str
    distribution: str
    version: str
    mode: _ReleaseToolMode
    entry_name: str | None = None
    entry_value: str | None = None


@dataclass(frozen=True, slots=True)
class _ReleaseDistributionFixture:
    version: str
    entry_points: tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class _ReleaseSpecificationFixture:
    origin: str | None


@dataclass(frozen=True, slots=True)
class _EmptyEvidenceRunner:
    stdout: bytes = b""

    def __call__(self, command: GateCommand) -> ChildResult:
        del command
        return ChildResult(0, self.stdout, b"")


@dataclass(frozen=True, slots=True)
class _PayloadRunner:
    stdout: bytes
    stderr: bytes

    def __call__(self, command: GateCommand) -> ChildResult:
        del command
        return ChildResult(0, self.stdout, self.stderr)


def _trusted_release_tools() -> tuple[_TrustedReleaseToolView, ...]:
    return cast(
        "tuple[_TrustedReleaseToolView, ...]",
        object.__getattribute__(release_module, "_TRUSTED_RELEASE_TOOLS"),
    )


def _trusted_release_tool_proof_resolver() -> _TrustedReleaseToolProofResolver:
    return cast(
        "_TrustedReleaseToolProofResolver",
        object.__getattribute__(release_module, "_trusted_release_tool_proof"),
    )


def _closed_python_tool_validator() -> _ClosedPythonToolValidator:
    return cast(
        "_ClosedPythonToolValidator",
        object.__getattribute__(release_module, "_valid_closed_python_tool_success"),
    )


def _patch_release_tool_identity(
    monkeypatch: pytest.MonkeyPatch,
    *,
    purelib: Path,
    distributions: tuple[_ReleaseDistributionFixture, ...],
    specification: _ReleaseSpecificationFixture | None,
) -> None:
    """Install one closed import-identity fixture for verifier edge tests."""

    def selected_purelib(_name: str) -> str:
        return purelib.as_posix()

    def selected_distributions(
        *,
        name: str,
        path: list[str],
    ) -> tuple[_ReleaseDistributionFixture, ...]:
        _ = (name, path)
        return distributions

    def selected_specification(
        fullname: str,
        path: list[str] | None = None,
        target: object | None = None,
    ) -> _ReleaseSpecificationFixture | None:
        _ = (fullname, path, target)
        return specification

    monkeypatch.setattr(sysconfig, "get_path", selected_purelib)
    monkeypatch.setattr(
        importlib.metadata,
        "distributions",
        selected_distributions,
    )
    monkeypatch.setattr(
        importlib.machinery.PathFinder,
        "find_spec",
        selected_specification,
    )


def _bandit_success_bytes() -> bytes:
    metric: dict[str, JsonValue] = {
        "CONFIDENCE.HIGH": 0,
        "CONFIDENCE.LOW": 0,
        "CONFIDENCE.MEDIUM": 0,
        "CONFIDENCE.UNDEFINED": 0,
        "SEVERITY.HIGH": 0,
        "SEVERITY.LOW": 0,
        "SEVERITY.MEDIUM": 0,
        "SEVERITY.UNDEFINED": 0,
        "loc": 1,
        "nosec": 0,
        "skipped_tests": 0,
    }
    return canonical_json_bytes(
        {
            "errors": [],
            "generated_at": "2026-08-26T00:00:00Z",
            "metrics": {"_totals": metric},
            "results": [],
        }
    )


def _cyclonedx_success_payload() -> dict[str, JsonValue]:
    component: dict[str, JsonValue] = {}
    tool_component: dict[str, JsonValue] = {}
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "components": [component],
        "dependencies": [],
        "metadata": {
            "timestamp": "2026-08-26T00:00:00Z",
            "tools": {"components": [tool_component]},
        },
        "serialNumber": "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
        "specVersion": "1.6",
        "version": 1,
    }


def _cyclonedx_success_bytes() -> bytes:
    return canonical_json_bytes(_cyclonedx_success_payload())


class _PassingRunner:
    def __call__(self, command: GateCommand) -> ChildResult:
        stdout_by_name = {
            "bandit": _bandit_success_bytes(),
            "cyclonedx": _cyclonedx_success_bytes(),
            "mypy": b"",
            "pip-audit": canonical_json_bytes({"dependencies": [], "fixes": []}),
            "pyright": _pyright_stdout(),
            "ruff": b"[]",
        }
        return ChildResult(0, stdout_by_name.get(command.name, b"{}"), b"")


def _load_checked_in_release_command_manifest() -> ReleaseCommandManifest:
    assert _RELEASE_COMMAND_MANIFEST.is_file(), (
        "candidate release-command manifest is missing"
    )
    return load_release_command_manifest(_RELEASE_COMMAND_MANIFEST)


def _manifest_payload() -> dict[str, object]:
    assert _RELEASE_COMMAND_MANIFEST.is_file(), (
        "candidate release-command manifest is missing"
    )
    value = load_json_value(_RELEASE_COMMAND_MANIFEST.read_bytes())
    return cast(
        "dict[str, object]",
        require_json_object(value, context="release-command manifest fixture"),
    )


def test_release_command_manifest_accepts_json_arrays_and_rejects_duplicate_names(
    tmp_path: Path,
) -> None:
    """Mutation caught: Python-object strict parsing or duplicate-key acceptance."""
    raw = _RELEASE_COMMAND_MANIFEST.read_bytes()
    valid_path = tmp_path / "valid-release-command-manifest.json"
    _ = valid_path.write_bytes(raw)
    manifest = load_release_command_manifest(valid_path)
    assert tuple(item.operation_id for item in manifest.operations) == _OPERATION_IDS

    duplicate_path = tmp_path / "duplicate-release-command-manifest.json"
    duplicate = raw.replace(
        b'  "schema_version": 1,',
        b'  "schema_version": 1,\n  "schema_version": 1,',
        1,
    )
    _ = duplicate_path.write_bytes(duplicate)
    with pytest.raises(
        ReleaseVerificationError,
        match="release command manifest rejected",
    ) as captured:
        _ = load_release_command_manifest(duplicate_path)
    assert captured.value.__cause__ is not None
    assert "duplicate release-policy JSON name: schema_version" in str(
        captured.value.__cause__
    )


def _exception_chain_text(error: BaseException) -> str:
    """Render only the public exception chain asserted by loader boundary tests."""
    messages = [str(error)]
    cause = error.__cause__
    while cause is not None:
        messages.append(str(cause))
        cause = cause.__cause__
    return "\n".join(messages)


@pytest.mark.parametrize(
    ("case", "old", "new", "cause_fragment"),
    [
        (
            "nested-duplicate-name",
            (
                b'            "flag": "--operation",\n'
                b'            "value_kind": "literal",\n'
                b'            "literal_value": "candidate-battery"'
            ),
            (
                b'            "flag": "--operation",\n'
                b'            "value_kind": "literal",\n'
                b'            "literal_value": "candidate-battery",\n'
                b'            "literal_value": "candidate-battery"'
            ),
            "duplicate release-policy JSON name: literal_value",
        ),
        (
            "nan",
            b'  "schema_version": 1,',
            b'  "schema_version": NaN,',
            "unsupported release-policy JSON number: NaN",
        ),
        (
            "infinity",
            b'  "schema_version": 1,',
            b'  "schema_version": Infinity,',
            "unsupported release-policy JSON number: Infinity",
        ),
        (
            "coercible-schema-version",
            b'  "schema_version": 1,',
            b'  "schema_version": "1",',
            "release policy schema rejected",
        ),
        (
            "coercible-container-runtime-flag",
            b'      "container_runtime_required": false,',
            b'      "container_runtime_required": "false",',
            "release policy schema rejected",
        ),
        (
            "coercible-gate-timeout",
            b'      "timeout_seconds": 60,',
            b'      "timeout_seconds": "60",',
            "release policy schema rejected",
        ),
    ],
)
def test_release_command_manifest_rejects_nonfinite_and_coercible_json_values(
    tmp_path: Path,
    case: str,
    old: bytes,
    new: bytes,
    cause_fragment: str,
) -> None:
    """Mutation caught: parser precheck or strict JSON model validation is bypassed."""
    raw = _RELEASE_COMMAND_MANIFEST.read_bytes()
    assert raw.count(old) == 1, case
    path = tmp_path / f"{case}-release-command-manifest.json"
    _ = path.write_bytes(raw.replace(old, new, 1))

    with pytest.raises(
        ReleaseVerificationError,
        match="release command manifest rejected",
    ) as captured:
        _ = load_release_command_manifest(path)
    assert cause_fragment in _exception_chain_text(captured.value)


def _valid_contract_transcript(
    manifest: ReleaseCommandManifest,
) -> dict[str, object]:
    completed_at = datetime(2026, 8, 23, 10, tzinfo=UTC)
    expires_at = completed_at + timedelta(hours=1)

    def receipt(target_kind: str, target_id: str) -> dict[str, object]:
        return {
            "target_kind": target_kind,
            "target_id": target_id,
            "red_exit": 1,
            "green_exit": 0,
            "refactor_exit": 0,
            "collected_tests": [f"protected::{target_id}"],
            "case_classes": [
                "adversarial",
                "fault",
                "negative",
                "property",
                "recovery",
            ],
            "mutations_total": 1,
            "mutations_killed": 1,
            "source_diff_sha256": "sha256:" + "5" * 64,
            "integration_exit": 0,
            "protected_controller_signed": True,
            "candidate_generated": False,
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        }

    return {
        "schema_version": 1,
        "profile": "alpic-metadata",
        "manifest_digest": release_command_manifest_digest(manifest),
        "operation_receipts": [
            receipt("operation", operation_id) for operation_id in _OPERATION_IDS
        ],
        "launcher_receipts": [
            receipt("launcher", launcher_id) for launcher_id in _LAUNCHER_IDS
        ],
        "external_gate_ids": [_COMMON_EXTERNAL_GATE],
        "critical_suite": {
            "collected_tests": ["protected::candidate-battery"],
            "replaced_suite_detected": True,
            "empty_suite_detected": True,
            "always_pass_suite_detected": True,
            "source_mutation_detected": True,
            "changed_line_coverage_percent": 100,
            "changed_branch_coverage_percent": 100,
            "surviving_mutants": 0,
            "conditional_skips": 0,
            "evidence_location": "external-protected-custody",
        },
    }


def _pyright_stderr_runner(command: GateCommand) -> ChildResult:
    del command
    return ChildResult(0, _pyright_stdout(), b"warning\n")


def _stable_runtime_identity(
    root: Path,
    node_executable: Path,
    cache_dir: Path,
) -> _RuntimeIdentityFixture:
    del root, node_executable, cache_dir
    return _RuntimeIdentityFixture()


class _JsonArrayRunner:
    def __call__(self, command: GateCommand) -> ChildResult:
        del command
        return ChildResult(0, b"[]", b"")


def _command(tmp_path: Path, name: str) -> GateCommand:
    executable = Path("/reviewed") / name
    return GateCommand(
        name=name,
        executable=executable,
        version="1.0.0",
        argv=(executable.as_posix(), "--json", tmp_path.as_posix()),
        cwd=tmp_path,
        environment=(("LANG", "C.UTF-8"),),
        subject_kind="materialized_source",
        subject_digest=SUBJECT_DIGEST,
        timeout_seconds=30.0,
        stdout_limit_bytes=4096,
        stderr_limit_bytes=4096,
        finding_exit_codes=frozenset({1}),
        tool_error_exit_codes=frozenset({2}),
        result_schema="nplg.release.gate-result.v1",
        offline_evidence=("sha256:" + "b" * 64,),
    )


def _pyright_stdout(
    *,
    version: str = "1.1.413",
    diagnostics: list[JsonValue] | None = None,
    summary_overrides: dict[str, JsonValue] | None = None,
    extra: dict[str, JsonValue] | None = None,
) -> bytes:
    summary: dict[str, JsonValue] = {
        "filesAnalyzed": 88,
        "errorCount": 0,
        "warningCount": 0,
        "informationCount": 0,
        "timeInSec": 10.102,
    }
    if summary_overrides is not None:
        summary.update(summary_overrides)
    payload: dict[str, JsonValue] = {
        "version": version,
        "time": "1787217300753",
        "generalDiagnostics": [] if diagnostics is None else diagnostics,
        "summary": summary,
    }
    if extra is not None:
        payload.update(extra)
    return json.dumps(payload, separators=(",", ":")).encode()


def test_gate_battery_stops_after_first_nonpassing_result(tmp_path: Path) -> None:
    commands = tuple(_command(tmp_path, name) for name in ("first", "second", "third"))
    runner = _FakeRunner({"first": 0, "second": 1, "third": 0})

    results = run_gate_battery(commands, runner, monotonic=_Clock())

    assert runner.calls == ["first", "second"]
    assert tuple(result.verdict for result in results) == ("passed", "findings")


def test_system_command_runner_reuses_bounded_process_seam(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = _command(tmp_path, "scanner")
    observed: list[tuple[tuple[str, ...], Path, dict[str, str], ProcessLimits]] = []

    def bounded(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
        limits: ProcessLimits,
    ) -> ChildResult:
        observed.append((argv, cwd, environment, limits))
        return ChildResult(0, b"{}", b"")

    monkeypatch.setattr("scripts.verify_release.run_bounded_process", bounded)

    result = release_module.SystemCommandRunner()(command)

    assert result == ChildResult(0, b"{}", b"")
    assert observed[0][0] == command.argv
    assert observed[0][1] == command.cwd
    assert observed[0][2] == {"LANG": "C.UTF-8"}
    assert observed[0][3] == ProcessLimits(30.0, 4096, 4096)


def test_local_ruff_gate_cannot_be_forged_by_candidate_module_shadow(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    scripts = tmp_path / "scripts"
    source.mkdir()
    scripts.mkdir()
    _ = (source / "bad.py").write_text("import os\n", encoding="utf-8")
    sentinel = tmp_path / "candidate-shadow-executed"
    _ = (tmp_path / "ruff.py").write_text(
        """from pathlib import Path
Path('candidate-shadow-executed').write_text('forged')
print('[]')
""",
        encoding="utf-8",
    )
    request = release_module.LocalGatesRequest(
        worktree=tmp_path,
        output=tmp_path / "output",
        node_executable=Path(sys.executable),
        compare_branch="refs/heads/main",
    )
    command = release_module.local_gate_commands(
        request,
        SUBJECT_DIGEST,
        pyright_evidence=PYRIGHT_EVIDENCE,
    )[0]

    results = run_gate_battery(
        (command,),
        release_module.SystemCommandRunner(),
        monotonic=_Clock(),
    )

    assert not sentinel.exists()
    assert results[0].verdict == "findings"


def test_isolated_tool_driver_allows_only_the_proved_in_tree_purelib() -> None:
    request = release_module.LocalGatesRequest(
        worktree=PROJECT_ROOT,
        output=Path("/external/release-evidence"),
        node_executable=Path("/reviewed/node"),
        compare_branch="origin/main",
    )
    command = release_module.local_gate_commands(
        request,
        SUBJECT_DIGEST,
        pyright_evidence=PYRIGHT_EVIDENCE,
    )[0]

    completed = release_module.SystemCommandRunner()(command)

    assert completed.returncode != _TRUSTED_DRIVER_REJECTION


@pytest.mark.parametrize(
    ("command_name", "module_name", "forged_stdout", "expected_returncode"),
    [
        ("mypy", "mypy", "", 1),
        ("bandit", "bandit", "{}", 0),
        ("pip-audit", "pip_audit", "{}", 0),
        ("cyclonedx", "cyclonedx_py", "{}", 0),
    ],
)
def test_console_python_gate_cannot_be_forged_by_candidate_module_shadow(
    tmp_path: Path,
    command_name: str,
    module_name: str,
    forged_stdout: str,
    expected_returncode: int,
) -> None:
    source = tmp_path / "src"
    scripts = tmp_path / "scripts"
    source.mkdir()
    scripts.mkdir()
    _ = (scripts / "ok.py").write_text("value = 1\n", encoding="utf-8")
    _ = (source / "bad.py").write_text(
        """import subprocess
value: int = "not an integer"
subprocess.Popen("/bin/ls *", shell=True)
""",
        encoding="utf-8",
    )
    _ = (tmp_path / "requirements-dev.lock").write_text("", encoding="utf-8")
    sentinel = tmp_path / f"{module_name}-shadow-executed"
    _ = (tmp_path / f"{module_name}.py").write_text(
        "".join(
            (
                "from pathlib import Path\n",
                f"Path({sentinel.name!r}).write_text('forged')\n",
                f"print({forged_stdout!r})\n",
            )
        ),
        encoding="utf-8",
    )
    request = release_module.LocalGatesRequest(
        worktree=tmp_path,
        output=tmp_path / "output",
        node_executable=Path(sys.executable),
        compare_branch="refs/heads/main",
    )
    commands = release_module.local_gate_commands(
        request,
        SUBJECT_DIGEST,
        pyright_evidence=PYRIGHT_EVIDENCE,
    )
    command = next(item for item in commands if item.name == command_name)

    completed = release_module.SystemCommandRunner()(command)

    assert not sentinel.exists()
    assert completed.returncode == expected_returncode
    if expected_returncode == 0:
        results = run_gate_battery(
            (command,),
            _PayloadRunner(completed.stdout, completed.stderr),
            monotonic=_Clock(),
        )
        assert results[0].verdict == "passed"


def test_gate_battery_rejects_success_without_json_evidence(tmp_path: Path) -> None:
    command = _command(tmp_path, "scanner")

    result = run_gate_battery(
        (command,),
        _EmptyEvidenceRunner(),
        monotonic=_Clock(),
    )

    assert result[0].verdict == "tool_error"


def test_gate_battery_accepts_json_array_evidence(tmp_path: Path) -> None:
    command = _command(tmp_path, "scanner")

    result = run_gate_battery(
        (command,),
        _JsonArrayRunner(),
        monotonic=_Clock(),
    )

    assert result[0].verdict == "passed"


@pytest.mark.parametrize("name", ["ruff", "bandit", "pip-audit", "cyclonedx"])
def test_gate_battery_rejects_wrong_tool_specific_success_shape(
    tmp_path: Path,
    name: str,
) -> None:
    command = _command(tmp_path, name)

    result = run_gate_battery(
        (command,),
        _FakeRunner({name: 0}),
        monotonic=_Clock(),
    )

    assert result[0].verdict == "tool_error"


def test_gate_battery_rejects_bandit_metrics_without_totals(tmp_path: Path) -> None:
    """Bandit success evidence must retain its aggregate metrics binding."""
    stdout = _bandit_success_bytes().replace(b'"_totals"', b'"other"', 1)

    result = run_gate_battery(
        (_command(tmp_path, "bandit"),),
        _PayloadRunner(stdout, b""),
        monotonic=_Clock(),
    )

    assert result[0].verdict == "tool_error"


def test_closed_python_tool_validator_rejects_unknown_tool(tmp_path: Path) -> None:
    """The private validator fails closed outside its exact command allowlist."""
    assert not _closed_python_tool_validator()(
        _command(tmp_path, "unknown"),
        ChildResult(0, b"", b""),
    )


_TOOL_SPECIFIC_SUCCESS_CASES: tuple[tuple[str, JsonValue, bytes], ...] = (
    ("ruff", [], b""),
    (
        "bandit",
        {
            "errors": [],
            "generated_at": "2026-08-26T00:00:00Z",
            "metrics": {
                "_totals": {
                    "CONFIDENCE.HIGH": 0,
                    "CONFIDENCE.LOW": 0,
                    "CONFIDENCE.MEDIUM": 0,
                    "CONFIDENCE.UNDEFINED": 0,
                    "SEVERITY.HIGH": 0,
                    "SEVERITY.LOW": 0,
                    "SEVERITY.MEDIUM": 0,
                    "SEVERITY.UNDEFINED": 0,
                    "loc": 1,
                    "nosec": 0,
                    "skipped_tests": 0,
                }
            },
            "results": [],
        },
        b"progress is non-authoritative\n",
    ),
    ("pip-audit", {"dependencies": [], "fixes": []}, b""),
    ("cyclonedx", _cyclonedx_success_payload(), b""),
)


@pytest.mark.parametrize(
    ("name", "payload", "stderr"),
    _TOOL_SPECIFIC_SUCCESS_CASES,
)
def test_gate_battery_accepts_only_closed_tool_specific_success(
    tmp_path: Path,
    name: str,
    payload: JsonValue,
    stderr: bytes,
) -> None:
    command = _command(tmp_path, name)

    result = run_gate_battery(
        (command,),
        _PayloadRunner(canonical_json_bytes(payload), stderr),
        monotonic=_Clock(),
    )

    assert result[0].verdict == "passed"


@pytest.mark.parametrize("stdout", [b"", b"\n"])
def test_gate_battery_accepts_exact_mypy_empty_success(
    tmp_path: Path, stdout: bytes
) -> None:
    command = _command(tmp_path, "mypy")

    result = run_gate_battery(
        (command,),
        _EmptyEvidenceRunner(stdout),
        monotonic=_Clock(),
    )

    assert result[0].verdict == "passed"


def test_gate_battery_accepts_exact_clean_pyright_schema(tmp_path: Path) -> None:
    command = replace(
        _command(tmp_path, "pyright"),
        version="1.1.413",
    )

    result = run_gate_battery(
        (command,),
        _EmptyEvidenceRunner(_pyright_stdout()),
        monotonic=_Clock(),
    )

    assert result[0].verdict == "passed"


@pytest.mark.parametrize(
    "stdout",
    [
        b"{}",
        b"[]",
        _pyright_stdout(version="1.1.414"),
        _pyright_stdout(summary_overrides={"errorCount": 1}),
        _pyright_stdout(summary_overrides={"warningCount": 1}),
        _pyright_stdout(summary_overrides={"informationCount": 1}),
        _pyright_stdout(diagnostics=[{"severity": "error"}]),
        _pyright_stdout(extra={"unexpected": True}),
        _pyright_stdout(extra={"time": 1787217300753}),
        _pyright_stdout(summary_overrides={"filesAnalyzed": 0}),
    ],
)
def test_gate_battery_rejects_malformed_or_unclean_pyright_success(
    tmp_path: Path,
    stdout: bytes,
) -> None:
    command = replace(
        _command(tmp_path, "pyright"),
        version="1.1.413",
    )

    result = run_gate_battery(
        (command,),
        _EmptyEvidenceRunner(stdout),
        monotonic=_Clock(),
    )

    assert result[0].verdict == "tool_error"


def test_gate_battery_rejects_pyright_stderr_on_zero_exit(tmp_path: Path) -> None:
    command = replace(
        _command(tmp_path, "pyright"),
        version="1.1.413",
    )

    result = run_gate_battery(
        (command,),
        _pyright_stderr_runner,
        monotonic=_Clock(),
    )

    assert result[0].verdict == "tool_error"


def test_gate_command_rejects_finding_and_tool_error_conflation(
    tmp_path: Path,
) -> None:
    command = _command(tmp_path, "scanner")

    with pytest.raises(ReleaseVerificationError, match="exit semantics overlap"):
        _ = replace(command, tool_error_exit_codes=frozenset({1, 2}))


def _invalid_command_identity(command: GateCommand, case: str) -> GateCommand:
    if case == "executable":
        mutated = replace(command, executable=Path("relative-tool"))
    elif case == "argv":
        mutated = replace(command, argv=("/different", "--json"))
    elif case == "cwd":
        mutated = replace(command, cwd=Path("relative-worktree"))
    elif case == "version":
        mutated = replace(command, version="latest")
    elif case == "subject_kind":
        mutated = replace(command, subject_kind="unknown")
    elif case == "subject_digest":
        mutated = replace(command, subject_digest="sha256:abc")
    elif case == "timeout":
        mutated = replace(command, timeout_seconds=0.0)
    elif case == "schema":
        mutated = replace(command, result_schema="unknown")
    else:
        mutated = replace(command, offline_evidence=("sha256:abc",))
    return mutated


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("executable", "absolute executable"),
        ("argv", "argv executable"),
        ("cwd", "absolute working directory"),
        ("version", "exact tool version"),
        ("subject_kind", "subject kind"),
        ("subject_digest", "subject digest"),
        ("timeout", "execution limits"),
        ("schema", "result schema"),
        ("offline_evidence", "offline evidence"),
    ],
)
def test_gate_command_rejects_unbound_identity_or_limits(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    command = _command(tmp_path, "scanner")

    with pytest.raises(ReleaseVerificationError, match=message):
        _ = _invalid_command_identity(command, case)


def _invalid_command_configuration(command: GateCommand, case: str) -> GateCommand:
    if case == "proxy":
        return replace(command, environment=(("HTTP_PROXY", "http://proxy.invalid"),))
    if case == "duplicate_env":
        return replace(command, environment=(("LANG", "C"), ("LANG", "C.UTF-8")))
    if case == "exit_zero":
        return replace(command, argv=("/reviewed/scanner", "--json", "--exit-zero"))
    if case == "download":
        return replace(
            command,
            argv=("/reviewed/scanner", "--json", "--download-db-only"),
        )
    if case == "auto":
        return replace(command, argv=("/reviewed/scanner", "auto", "--json"))
    return replace(command, argv=("/reviewed/scanner", "--version"))


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("proxy", "ambient credential or network"),
        ("duplicate_env", "duplicate environment"),
        ("exit_zero", "unsafe scanner argument"),
        ("download", "unsafe scanner argument"),
        ("auto", "unsafe scanner argument"),
        ("version", "JSON result"),
    ],
)
def test_gate_command_rejects_ambient_or_bypass_configuration(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    command = _command(tmp_path, "scanner")

    with pytest.raises(ReleaseVerificationError, match=message):
        _ = _invalid_command_configuration(command, case)


def test_checked_in_release_policies_are_closed_and_fail_safe() -> None:
    policies = release_module.load_release_policies(PROJECT_ROOT / "security")

    assert (
        policies.dependency_risk.known_exploited.triage_hours,
        policies.dependency_risk.known_exploited.remediation_days,
    ) == (24, 7)
    assert (
        policies.dependency_risk.critical.triage_hours,
        policies.dependency_risk.critical.remediation_days,
    ) == (24, 7)
    assert (
        policies.dependency_risk.high.triage_hours,
        policies.dependency_risk.high.remediation_days,
    ) == (72, 30)
    assert (
        policies.dependency_risk.medium.triage_hours,
        policies.dependency_risk.medium.remediation_days,
    ) == (336, 90)
    assert (
        policies.dependency_risk.low.triage_hours,
        policies.dependency_risk.low.remediation_days,
    ) == (720, 180)
    assert policies.trusted_sources.python.index_url == "https://pypi.org/simple"
    assert policies.trusted_sources.npm.registry_url == "https://registry.npmjs.org/"
    assert policies.trusted_sources.acquisition.candidate_network == "offline"
    assert policies.controller.status == "external_authority_required"
    assert policies.controller.candidate_may_supply_controller is False
    assert policies.recovery.evidence.status == "external_authority_required"
    assert policies.recovery.policy_digest == _RECOVERY_POLICY_SHA256
    assert policies.recovery.rto.objective_seconds == _RECOVERY_RTO_OBJECTIVE_SECONDS
    assert (
        tuple(item.state_id for item in policies.recovery.state_inventory)
        == _RECOVERY_STATE_IDS
    )
    assert policies.recovery.state_inventory[-1].persistence == "never-persisted"
    assert policies.recovery.release_ready is False
    assert tuple(
        gate.gate_id for gate in policies.external_gate_registry.gates
    ) == tuple(gate.gate_id for gate in policies.commands.external_gates)


def test_release_loader_rejects_coherently_redigested_recovery_policy_drift(
    tmp_path: Path,
) -> None:
    """A self-consistent candidate policy cannot replace the reviewed release one."""
    for name in (
        "dependency-risk-policy.json",
        "trusted-package-sources.json",
        "release-controller-policy.json",
        "private-recovery-policy.json",
        "external-test-gates.json",
        "release-command-manifests.json",
    ):
        _ = (tmp_path / name).write_bytes(
            (PROJECT_ROOT / "security" / name).read_bytes()
        )
    policy = require_json_object(
        load_json_value((tmp_path / "private-recovery-policy.json").read_bytes()),
        context="private recovery policy fixture",
    )
    subjects = cast("list[JsonValue]", policy["subjects"])
    derived = cast("dict[str, JsonValue]", subjects[1])
    recipes = cast("list[JsonValue]", derived["regeneration_recipe_paths"])
    recipes.append("src/nplg_mcp/pdf_worker_main.py")
    unsigned = {key: value for key, value in policy.items() if key != "policy_digest"}
    policy["policy_digest"] = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    )
    _ = (tmp_path / "private-recovery-policy.json").write_bytes(
        canonical_json_bytes(policy)
    )

    with pytest.raises(ReleaseVerificationError, match="closed release binding"):
        _ = release_module.load_release_policies(tmp_path)


@pytest.mark.parametrize("mutation", ["missing", "extra", "command-drift"])
def test_release_policy_rejects_external_registry_manifest_join_drift(
    mutation: str,
) -> None:
    """The independently owned registry and release manifest must agree exactly."""
    registry = parse_external_gate_registry(
        (PROJECT_ROOT / "security" / "external-test-gates.json").read_bytes()
    )
    manifest = _load_checked_in_release_command_manifest()
    gates = list(registry.gates)
    if mutation == "missing":
        _ = gates.pop()
    elif mutation == "extra":
        gates.append(gates[-1])
    else:
        gates[-1] = replace(gates[-1], command_id="container.scanner.v3")
    drifted = replace(registry, gates=tuple(gates))

    with pytest.raises(
        ReleaseVerificationError,
        match="external gate registry differs from release command manifest",
    ):
        release_module.validate_external_gate_manifest_join(drifted, manifest)


def test_release_command_manifest_has_exact_candidate_side_contract() -> None:
    manifest = _load_checked_in_release_command_manifest()

    assert manifest.contract_id == "nplg.release-command-manifest.v1"
    assert manifest.controller_authority == "separately-protected-external"
    assert manifest.candidate_implements_controller is False
    assert tuple(item.operation_id for item in manifest.operations) == _OPERATION_IDS
    assert tuple(item.command_id for item in manifest.launcher_commands) == (
        _LAUNCHER_IDS
    )
    assert tuple(item.command_id for item in manifest.utilities) == _UTILITY_IDS
    assert tuple(item.gate_id for item in manifest.external_gates) == (
        _COMMON_EXTERNAL_GATE,
        *_PRIVATE_EXTERNAL_GATES,
    )
    assert manifest.missing_authority_status == (
        "PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE"
    )
    assert manifest.terminal_verdict == "do_not_release"


def test_release_manifest_has_structural_argv_payload_and_tool_lock_contracts() -> None:
    """Mutation caught: command labels replace closed executable contracts."""
    manifest = _load_checked_in_release_command_manifest()
    commands: tuple[
        ReleaseOperationSpec | LauncherCommandSpec | ReadOnlyUtilitySpec,
        ...,
    ] = (*manifest.operations, *manifest.launcher_commands, *manifest.utilities)

    assert len(commands) == (
        len(_OPERATION_IDS) + len(_LAUNCHER_IDS) + len(_UTILITY_IDS)
    )
    assert all(
        command.tool.tool_id == "nplg-release-controller" for command in commands
    )
    assert all(command.tool.interface_version == "2.0.0" for command in commands)
    assert all(command.tool.require_exact_lock_digest is True for command in commands)
    assert all(command.argv.allow_unknown_options is False for command in commands)
    assert all(command.argv.allow_passthrough is False for command in commands)
    assert all(command.argv.allow_shell is False for command in commands)
    assert all(
        command.input_contract.allow_unknown_fields is False for command in commands
    )
    assert all(
        command.output_contract.allow_unknown_fields is False for command in commands
    )
    assert all(
        command.output_contract.allow_digest_only is False for command in commands
    )

    eligibility = next(
        operation
        for operation in manifest.operations
        if operation.operation_id == "eligibility"
    )
    eligibility_flags = tuple(
        option.flag for option in eligibility.argv.required_options
    )
    assert "--require-eligible" in eligibility_flags
    assert "--require-asvs-l2" in eligibility_flags


@pytest.mark.parametrize(
    "mutation",
    [
        "literal-shape",
        "unsafe-literal",
        "duplicate-option",
        "unsafe-subcommand",
        "duplicate-input-field",
        "duplicate-output-schema",
        "case-class-drift",
    ],
)
def test_release_manifest_rejects_closed_command_contract_shape_mutants(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Every argv and payload grammar remains closed under adversarial drift."""
    payload = _manifest_payload()
    operations = cast("list[dict[str, object]]", payload["operations"])
    operation = operations[0]
    argv = cast("dict[str, object]", operation["argv"])
    options = cast("list[dict[str, object]]", argv["required_options"])
    input_contract = cast("dict[str, object]", operation["input_contract"])
    output_contract = cast("dict[str, object]", operation["output_contract"])
    sensitivity = cast("dict[str, object]", payload["sensitivity_policy"])
    if mutation == "literal-shape":
        options[0]["literal_value"] = "unexpected"
    elif mutation == "unsafe-literal":
        options[2]["literal_value"] = "candidate-battery;exec"
    elif mutation == "duplicate-option":
        options[1]["flag"] = options[0]["flag"]
    elif mutation == "unsafe-subcommand":
        argv["subcommand"] = "run-operation;exec"
    elif mutation == "duplicate-input-field":
        fields = cast("list[str]", input_contract["required_fields"])
        fields.append(fields[0])
    elif mutation == "duplicate-output-schema":
        schemas = cast("list[str]", output_contract["schema_ids"])
        schemas.append(schemas[0])
    else:
        case_classes = cast("list[str]", sensitivity["required_case_classes"])
        _ = case_classes.pop()
    path = tmp_path / f"{mutation}-release-command-manifests.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="command manifest"):
        _ = load_release_command_manifest(path)


def test_release_command_manifest_selects_exact_profile_contracts() -> None:
    manifest = _load_checked_in_release_command_manifest()
    by_profile = {profile.profile_id: profile for profile in manifest.profiles}

    metadata = by_profile["alpic-metadata"]
    assert metadata.operation_ids == _OPERATION_IDS
    assert metadata.external_gate_ids == (_COMMON_EXTERNAL_GATE,)
    assert metadata.subject_roles == (
        "alpic-deploy-pack",
        "python-sdist",
        "python-wheel",
    )
    assert metadata.task21_staging_imports == 1
    assert metadata.container_runtime_required is False
    assert metadata.private_nonconstruction_required is True
    assert metadata.finalize_inputs == (
        "common-live-plus-exactly-one-staging-or-reconciliation"
    )

    private = by_profile["private-full"]
    assert private.operation_ids == tuple(
        operation_id
        for operation_id in _OPERATION_IDS
        if operation_id not in {"staging-proof", "reconcile-staging"}
    )
    assert private.external_gate_ids == (
        _COMMON_EXTERNAL_GATE,
        *_PRIVATE_EXTERNAL_GATES,
    )
    assert private.subject_roles == (
        "pdf-worker-image",
        "private-app-image",
        "private-edge-image",
        "python-sdist",
        "python-wheel",
        "scanner-image",
    )
    assert private.task21_staging_imports == 0
    assert private.container_runtime_required is True
    assert private.private_nonconstruction_required is False
    assert private.finalize_inputs == "common-live-plus-five-private-proofs"


def _mutate_release_manifest_inventory(
    payload: dict[str, object],
    mutation: str,
) -> bool:
    operations = cast("list[dict[str, object]]", payload["operations"])
    launchers = cast("list[dict[str, object]]", payload["launcher_commands"])
    utilities = cast("list[dict[str, object]]", payload["utilities"])
    if mutation == "missing-operation":
        _ = operations.pop()
    elif mutation == "duplicate-operation":
        operations[-1] = deepcopy(operations[0])
    elif mutation == "operation-exit-drift":
        operations[0]["exit_codes"] = [0]
    elif mutation == "missing-launcher":
        _ = launchers.pop()
    elif mutation == "direct-operation-launcher":
        launchers[0]["command_id"] = "finalize"
    elif mutation == "stateful-utility":
        utilities[0]["read_only"] = False
    elif mutation == "undocumented-utility":
        utilities.append(deepcopy(utilities[0]))
        utilities[-1]["command_id"] = "candidate"
    else:
        return False
    return True


def _mutate_release_manifest_profile(
    payload: dict[str, object],
    mutation: str,
) -> None:
    profiles = cast("list[dict[str, object]]", payload["profiles"])
    utilities = cast("list[dict[str, object]]", payload["utilities"])
    if mutation == "metadata-extra-gate":
        cast("list[str]", profiles[0]["external_gate_ids"]).append(
            "private-full.edge-http"
        )
    elif mutation == "metadata-container":
        profiles[0]["container_runtime_required"] = True
    elif mutation == "second-staging-import":
        profiles[0]["task21_staging_imports"] = 2
    elif mutation == "private-missing-gate":
        _ = cast("list[str]", profiles[1]["external_gate_ids"]).pop()
    elif mutation == "shell-schema":
        utilities[2]["argv_schema"] = "sh -c ${ALPIC_API_KEY}"
    else:
        payload["unexpected"] = True


def _mutate_release_manifest(
    payload: dict[str, object],
    mutation: str,
) -> None:
    if not _mutate_release_manifest_inventory(payload, mutation):
        _mutate_release_manifest_profile(payload, mutation)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-operation",
        "duplicate-operation",
        "operation-exit-drift",
        "missing-launcher",
        "direct-operation-launcher",
        "stateful-utility",
        "undocumented-utility",
        "metadata-extra-gate",
        "metadata-container",
        "second-staging-import",
        "private-missing-gate",
        "shell-schema",
        "unknown-field",
    ],
)
def test_release_command_manifest_rejects_profile_and_runner_policy_mutants(
    tmp_path: Path,
    mutation: str,
) -> None:
    payload = _manifest_payload()
    _mutate_release_manifest(payload, mutation)
    path = tmp_path / "release-command-manifests.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="command manifest"):
        _ = load_release_command_manifest(path)


def _mutate_contract_receipt(payload: dict[str, object], mutation: str) -> bool:
    operations = cast("list[dict[str, object]]", payload["operation_receipts"])
    launchers = cast("list[dict[str, object]]", payload["launcher_receipts"])
    if mutation == "omitted-operation-receipt":
        _ = operations.pop()
    elif mutation == "omitted-launcher-receipt":
        _ = launchers.pop()
    elif mutation == "survived-operation-mutant":
        operations[0]["mutations_killed"] = 0
    elif mutation == "missing-case-class":
        operations[0]["case_classes"] = (
            "adversarial",
            "fault",
            "negative",
            "property",
        )
    elif mutation == "forged-controller-signature":
        operations[0]["protected_controller_signed"] = False
    elif mutation == "candidate-issued-receipt":
        operations[0]["candidate_generated"] = True
    elif mutation == "stale-receipt":
        operations[0]["expires_at"] = "2026-08-23T10:30:00Z"
    else:
        return False
    return True


def _mutate_contract_suite(payload: dict[str, object], mutation: str) -> None:
    suite = cast("dict[str, object]", payload["critical_suite"])
    if mutation == "empty-critical-suite":
        suite["collected_tests"] = []
    elif mutation == "replaced-suite-survives":
        suite["replaced_suite_detected"] = False
    elif mutation == "always-pass-survives":
        suite["always_pass_suite_detected"] = False
    elif mutation == "source-mutation-survives":
        suite["source_mutation_detected"] = False
    elif mutation == "shallow-diff":
        suite["changed_line_coverage_percent"] = 94
    elif mutation == "conditional-skip":
        suite["conditional_skips"] = 1
    elif mutation == "candidate-evidence":
        suite["evidence_location"] = "candidate-worktree"
    else:
        cast("list[str]", payload["external_gate_ids"]).append("private-full.edge-http")


def _mutate_contract_transcript(payload: dict[str, object], mutation: str) -> None:
    if mutation == "invalid-manifest-digest":
        payload["manifest_digest"] = "not-a-sha256"
    elif mutation == "duplicate-critical-test":
        suite = cast("dict[str, object]", payload["critical_suite"])
        tests = cast("list[str]", suite["collected_tests"])
        tests.append(tests[0])
    elif not _mutate_contract_receipt(payload, mutation):
        _mutate_contract_suite(payload, mutation)


def test_candidate_fake_contract_transcript_accepts_complete_sensitive_fixture() -> (
    None
):
    manifest = _load_checked_in_release_command_manifest()
    payload = _valid_contract_transcript(manifest)

    transcript = validate_candidate_contract_transcript(
        json.dumps(payload).encode(),
        manifest=manifest,
        now=datetime(2026, 8, 23, 10, 15, tzinfo=UTC),
    )

    assert transcript.profile == "alpic-metadata"
    assert tuple(item.target_id for item in transcript.operation_receipts) == (
        _OPERATION_IDS
    )
    assert tuple(item.target_id for item in transcript.launcher_receipts) == (
        _LAUNCHER_IDS
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "omitted-operation-receipt",
        "omitted-launcher-receipt",
        "survived-operation-mutant",
        "missing-case-class",
        "forged-controller-signature",
        "candidate-issued-receipt",
        "stale-receipt",
        "empty-critical-suite",
        "replaced-suite-survives",
        "always-pass-survives",
        "source-mutation-survives",
        "shallow-diff",
        "conditional-skip",
        "candidate-evidence",
        "profile-extra-gate",
        "invalid-manifest-digest",
        "duplicate-critical-test",
    ],
)
def test_candidate_fake_contract_transcript_rejects_incomplete_or_forged_pass(
    mutation: str,
) -> None:
    manifest = _load_checked_in_release_command_manifest()
    payload = deepcopy(_valid_contract_transcript(manifest))
    _mutate_contract_transcript(payload, mutation)

    with pytest.raises(ReleaseVerificationError, match="contract transcript"):
        _ = validate_candidate_contract_transcript(
            json.dumps(payload).encode(),
            manifest=manifest,
            now=datetime(2026, 8, 23, 11, tzinfo=UTC),
        )


def test_candidate_release_status_is_nonclosure_without_external_authority() -> None:
    status = candidate_release_status("alpic-metadata")

    assert status.local_status == "PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE"
    assert status.terminal_verdict == "do_not_release"
    assert status.release_ready is False
    assert status.release_authorized is False


def test_candidate_contract_rejects_non_utc_clock_and_unknown_profile() -> None:
    manifest = _load_checked_in_release_command_manifest()
    payload = _valid_contract_transcript(manifest)
    non_utc = datetime(2026, 8, 23, 11, tzinfo=timezone(timedelta(hours=1)))

    with pytest.raises(ReleaseVerificationError, match="contract transcript"):
        _ = validate_candidate_contract_transcript(
            json.dumps(payload).encode(),
            manifest=manifest,
            now=non_utc,
        )
    with pytest.raises(ReleaseVerificationError, match="closed manifest"):
        _ = candidate_release_status(cast("ReleaseProfile", "unknown-profile"))


def test_dependency_policy_rejects_unknown_source_and_type_coercion(
    tmp_path: Path,
) -> None:
    payload = require_json_object(
        load_json_value(
            (PROJECT_ROOT / "security" / "dependency-risk-policy.json").read_bytes()
        ),
        context="dependency policy fixture",
    )
    payload["review_cadence_days"] = "30"
    sources = payload["advisory_sources"]
    assert isinstance(sources, list)
    assert sources
    first_source = sources[0]
    assert isinstance(first_source, dict)
    first_source["source_id"] = "unreviewed"
    path = tmp_path / "dependency-risk-policy.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="schema rejected"):
        _ = release_module.load_dependency_risk_policy(path)


def test_controller_policy_rejects_candidate_selected_authority(
    tmp_path: Path,
) -> None:
    payload = require_json_object(
        load_json_value(
            (PROJECT_ROOT / "security" / "release-controller-policy.json").read_bytes()
        ),
        context="release controller fixture",
    )
    payload["candidate_selected_authority"] = "self"
    path = tmp_path / "release-controller-policy.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="schema rejected"):
        _ = release_module.load_release_controller_policy(path)


def test_trusted_sources_policy_rejects_duplicate_json_names(tmp_path: Path) -> None:
    path = tmp_path / "trusted-package-sources.json"
    _ = path.write_text(
        '{"schema_version":1,"schema_version":1}',
        encoding="utf-8",
    )

    with pytest.raises(ReleaseVerificationError, match=r"duplicate.*schema_version"):
        _ = release_module.load_trusted_package_sources_policy(path)


def _write_trivy_receipt(
    path: Path,
    *,
    acquired_at: str = "2026-08-17T12:00:00Z",
    signature_verified: bool = True,
    upstream_attested: bool = True,
) -> None:
    payload = {
        "schema_version": 1,
        "receipt_id": "receipt-20260817-001",
        "oci_subject_digest": "sha256:" + "1" * 64,
        "media_type": "application/vnd.oci.image.manifest.v1+json",
        "artifact_type": "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
        "signer_policy_digest": "sha256:" + "2" * 64,
        "authority_identity": "protected-trivy-db-prefetch",
        "acquired_at": acquired_at,
        "response_digest": "sha256:" + "3" * 64,
        "signature_verified": signature_verified,
        "upstream_attested": upstream_attested,
        "candidate_generated": False,
    }
    _ = path.write_text(json.dumps(payload), encoding="utf-8")


def test_trivy_database_receipt_accepts_signed_fresh_external_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trivy-receipt.json"
    _write_trivy_receipt(path)

    receipt = release_module.load_trivy_database_receipt(
        path,
        now=datetime(2026, 8, 17, 18, tzinfo=UTC),
        seen_receipt_ids=frozenset(),
        previous_acquired_at=None,
    )

    assert receipt.receipt_id == "receipt-20260817-001"
    assert receipt.oci_subject_digest == "sha256:" + "1" * 64


@pytest.mark.parametrize(
    ("acquired_at", "signature_verified", "upstream_attested"),
    [
        ("2026-08-16T17:59:59Z", True, True),
        ("2026-08-17T18:00:01Z", True, True),
        ("2026-08-17T12:00:00Z", False, True),
        ("2026-08-17T12:00:00Z", True, False),
    ],
)
def test_trivy_database_receipt_rejects_stale_future_or_unattested_evidence(
    tmp_path: Path,
    *,
    acquired_at: str,
    signature_verified: bool,
    upstream_attested: bool,
) -> None:
    path = tmp_path / "trivy-receipt.json"
    _write_trivy_receipt(
        path,
        acquired_at=acquired_at,
        signature_verified=signature_verified,
        upstream_attested=upstream_attested,
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="TRIVY_DB_UPSTREAM_PROVENANCE_UNATTESTED",
    ):
        _ = release_module.load_trivy_database_receipt(
            path,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


def test_trivy_database_receipt_rejects_replay_and_clock_rollback(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trivy-receipt.json"
    _write_trivy_receipt(path)

    with pytest.raises(ReleaseVerificationError, match="PROVENANCE_UNATTESTED"):
        _ = release_module.load_trivy_database_receipt(
            path,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset({"receipt-20260817-001"}),
            previous_acquired_at=None,
        )
    with pytest.raises(ReleaseVerificationError, match="PROVENANCE_UNATTESTED"):
        _ = release_module.load_trivy_database_receipt(
            path,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=datetime(2026, 8, 17, 13, tzinfo=UTC),
        )


def test_trivy_database_receipt_rejects_truncated_json(tmp_path: Path) -> None:
    path = tmp_path / "trivy-receipt.json"
    _ = path.write_bytes(b'{"schema_version":1')

    with pytest.raises(ReleaseVerificationError, match="PROVENANCE_UNATTESTED"):
        _ = release_module.load_trivy_database_receipt(
            path,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


def _dependency_evidence_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "receipt_id": "sca-20260817-001",
        "source_id": "osv",
        "acquired_at": "2026-08-17T12:00:00Z",
        "response_digest": "sha256:" + "4" * 64,
        "scanner_name": "pip-audit",
        "scanner_version": "2.10.0",
        "argv": ["/reviewed/pip-audit", "--format=json"],
        "lock_identities": ["sha256:" + "5" * 64],
        "raw_digest": "sha256:" + "6" * 64,
        "redacted_digest": "sha256:" + "7" * 64,
        "truncated": False,
        "findings": [],
    }


def test_dependency_evidence_accepts_fresh_digest_bound_receipt(
    tmp_path: Path,
) -> None:
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(
        json.dumps(_dependency_evidence_payload()),
        encoding="utf-8",
    )
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    evidence = release_module.load_dependency_evidence(
        path,
        policy=policy,
        now=datetime(2026, 8, 17, 18, tzinfo=UTC),
        seen_receipt_ids=frozenset(),
        previous_acquired_at=None,
    )

    assert evidence.receipt_id == "sca-20260817-001"
    assert evidence.source_id == "osv"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_id", "unknown-source"),
        ("acquired_at", "2026-08-16T17:59:59Z"),
        ("truncated", True),
    ],
)
def test_dependency_evidence_rejects_unknown_stale_or_truncated_receipt(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    payload = _dependency_evidence_payload()
    payload[field] = cast("JsonValue", value)
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    with pytest.raises(ReleaseVerificationError, match="DEPENDENCY_EVIDENCE_REJECTED"):
        _ = release_module.load_dependency_evidence(
            path,
            policy=policy,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


def test_dependency_evidence_rejects_replay_and_clock_rollback(
    tmp_path: Path,
) -> None:
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(
        json.dumps(_dependency_evidence_payload()),
        encoding="utf-8",
    )
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    with pytest.raises(ReleaseVerificationError, match="DEPENDENCY_EVIDENCE_REJECTED"):
        _ = release_module.load_dependency_evidence(
            path,
            policy=policy,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset({"sca-20260817-001"}),
            previous_acquired_at=None,
        )
    with pytest.raises(ReleaseVerificationError, match="DEPENDENCY_EVIDENCE_REJECTED"):
        _ = release_module.load_dependency_evidence(
            path,
            policy=policy,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=datetime(2026, 8, 17, 13, tzinfo=UTC),
        )


def _finding(*, severity: str, discovered_at: str) -> dict[str, object]:
    return {
        "finding_id": "OSV-CANARY-1",
        "package": "canary-package",
        "package_provenance_digest": "sha256:" + "8" * 64,
        "severity": severity,
        "discovered_at": discovered_at,
        "triaged_at": None,
        "remediated_at": None,
        "exception": None,
    }


@pytest.mark.parametrize(
    "finding",
    [
        _finding(severity="unrated", discovered_at="2026-08-17T17:00:00Z"),
        _finding(severity="high", discovered_at="2026-07-01T00:00:00Z"),
    ],
)
def test_dependency_evidence_rejects_unknown_severity_or_breached_package(
    tmp_path: Path,
    finding: dict[str, object],
) -> None:
    payload = _dependency_evidence_payload()
    payload["findings"] = [finding]
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    with pytest.raises(ReleaseVerificationError, match="DEPENDENCY_EVIDENCE_REJECTED"):
        _ = release_module.load_dependency_evidence(
            path,
            policy=policy,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


def test_dependency_evidence_rejects_expired_exception(tmp_path: Path) -> None:
    finding = _finding(severity="low", discovered_at="2026-08-17T17:00:00Z")
    finding["triaged_at"] = "2026-08-17T17:30:00Z"
    finding["exception"] = {
        "revision": "reviewed-revision",
        "subject_digest": "sha256:" + "5" * 64,
        "reachability_analysis_digest": "sha256:" + "9" * 64,
        "owner": "risk-owner",
        "compensating_controls": ["private-only"],
        "created_at": "2026-08-01T00:00:00Z",
        "expires_at": "2026-08-16T00:00:00Z",
        "risk_acceptance_digest": "sha256:" + "a" * 64,
        "scope": "named_non_public_staging_or_private",
        "terminal_recommendation": "do_not_release",
    }
    payload = _dependency_evidence_payload()
    payload["findings"] = [finding]
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    with pytest.raises(ReleaseVerificationError, match="DEPENDENCY_EVIDENCE_REJECTED"):
        _ = release_module.load_dependency_evidence(
            path,
            policy=policy,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


def test_source_snapshot_round_trip_includes_ignored_input_and_detects_change(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").mkdir()
    _ = (worktree / ".git" / "excluded").write_bytes(b"git")
    _ = (worktree / "tracked.txt").write_bytes(b"tracked")
    (worktree / ".cache").mkdir()
    _ = (worktree / ".cache" / "ignored.bin").write_bytes(b"ignored")
    linked_tool = tmp_path / "linked-tool"
    _ = linked_tool.write_bytes(b"tool")
    for root_name in (
        ".agents",
        ".codex",
        ".codex-request-fixture",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".serena",
        ".tools",
        ".venv",
        "node_modules",
    ):
        tool_root = worktree / root_name
        tool_root.mkdir()
        os.link(linked_tool, tool_root / "ignored-tool")
    (worktree / ".venv-notes").mkdir()
    _ = (worktree / ".venv-notes" / "included.txt").write_bytes(b"included")
    output = tmp_path / "snapshot.json"

    snapshot = release_module.write_source_snapshot(worktree, output)

    assert {entry.path for entry in snapshot.entries} == {
        ".cache",
        ".cache/ignored.bin",
        ".venv-notes",
        ".venv-notes/included.txt",
        "tracked.txt",
    }
    release_module.assert_source_snapshot(worktree, output)
    _ = (worktree / "tracked.txt").write_bytes(b"changed")
    with pytest.raises(ReleaseVerificationError, match="source snapshot changed"):
        release_module.assert_source_snapshot(worktree, output)


def test_local_gates_records_external_requirements_as_not_passed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    _ = (worktree / "input.py").write_text("value = 1\n", encoding="utf-8")
    output = tmp_path / "local-gates"
    request = release_module.LocalGatesRequest(
        worktree=worktree,
        output=output,
        node_executable=Path("/reviewed/node"),
        compare_branch="origin/main",
    )
    identity_calls: list[tuple[Path, Path, Path]] = []

    def validate_identity(
        root: Path,
        node: Path,
        cache: Path,
    ) -> _RuntimeIdentityFixture:
        identity_calls.append((root, node, cache))
        return _RuntimeIdentityFixture()

    monkeypatch.setattr(
        release_module,
        "_validate_pyright_runtime_identity",
        validate_identity,
        raising=False,
    )

    report = release_module.run_local_gates(
        request,
        runner=_PassingRunner(),
        monotonic=_Clock(),
    )

    assert report.local_status == "passed"
    assert report.terminal_verdict == "do_not_release"
    assert report.eligibility_reason == "external_authority_required"
    assert {item.status for item in report.external_requirements} == {"not_passed"}
    pyright = next(result for result in report.results if result.name == "pyright")
    assert pyright.offline_evidence == (pyright.subject_digest, *PYRIGHT_EVIDENCE)
    assert len(identity_calls) == _EXPECTED_IDENTITY_VALIDATIONS
    assert (output / "release-gate-results.json").is_file()


def test_local_gate_commands_bind_python_tools_to_the_isolated_driver() -> None:
    request = release_module.LocalGatesRequest(
        worktree=PROJECT_ROOT,
        output=Path("/external/release-evidence"),
        node_executable=Path("/reviewed/node"),
        compare_branch="origin/main",
    )

    commands = release_module.local_gate_commands(
        request,
        SUBJECT_DIGEST,
        pyright_evidence=PYRIGHT_EVIDENCE,
    )

    expected_modules = {
        "bandit": ("bandit", "bandit", "1.9.4"),
        "cyclonedx": ("cyclonedx_py", "cyclonedx-bom", "7.3.1"),
        "mypy": ("mypy", "mypy", "2.3.1"),
        "pip-audit": ("pip_audit", "pip-audit", "2.10.1"),
        "ruff": ("ruff", "ruff", "0.16.3"),
    }
    for name, (module, distribution, version) in expected_modules.items():
        command = next(item for item in commands if item.name == name)
        proof = cast("list[object]", json.loads(command.argv[6]))
        assert command.executable == Path(sys.executable)
        assert command.argv[:5] == (sys.executable, "-I", "-S", "-B", "-c")
        assert proof[1:4] == [module, distribution, version]
        assert Path(cast("str", proof[4])).is_absolute()
        assert command.offline_evidence[0] == SUBJECT_DIGEST
        assert len(command.offline_evidence) == _TOOL_EVIDENCE_ITEMS
    bandit = next(command for command in commands if command.name == "bandit")
    assert bandit.argv[7:10] == ("-ll", "-r", "src")
    pip_audit = next(command for command in commands if command.name == "pip-audit")
    assert pip_audit.argv[7:] == (
        "-r",
        "requirements-dev.lock",
        "--require-hashes",
        "--no-deps",
        "--format=json",
        "--progress-spinner",
        "off",
    )
    zizmor = next(command for command in commands if command.name == "zizmor")
    assert zizmor.executable == Path(sys.executable).parent / "zizmor"
    assert zizmor.argv[1:] == ("--offline", "--format=json", ".github/workflows")
    pyright = next(command for command in commands if command.name == "pyright")
    assert pyright.offline_evidence == (SUBJECT_DIGEST, *PYRIGHT_EVIDENCE)


def test_trusted_release_tool_rejects_non_string_purelib(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing interpreter purelib identity fails closed."""

    def missing_purelib(_name: str) -> None:
        return None

    monkeypatch.setattr(sysconfig, "get_path", missing_purelib)

    with pytest.raises(
        ReleaseVerificationError,
        match="trusted release tool root is unavailable",
    ):
        _ = _trusted_release_tool_proof_resolver()(_trusted_release_tools()[0])


def test_trusted_release_tool_rejects_missing_distribution_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tool without one exact pinned distribution cannot become authoritative."""
    _patch_release_tool_identity(
        monkeypatch,
        purelib=tmp_path,
        distributions=(),
        specification=None,
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="trusted release tool version or import origin is invalid",
    ):
        _ = _trusted_release_tool_proof_resolver()(_trusted_release_tools()[0])


def test_trusted_release_tool_rejects_nonregular_import_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory cannot impersonate a pinned tool's import module."""
    tool = _trusted_release_tools()[0]
    origin = tmp_path / "ruff"
    origin.mkdir()
    _patch_release_tool_identity(
        monkeypatch,
        purelib=tmp_path,
        distributions=(_ReleaseDistributionFixture(tool.version),),
        specification=_ReleaseSpecificationFixture(origin.as_posix()),
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="trusted release tool import origin is not a regular purelib file",
    ):
        _ = _trusted_release_tool_proof_resolver()(tool)


def test_trusted_release_console_tool_rejects_missing_entry_point(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Console tools require their exact pinned entry-point binding."""
    tool = _trusted_release_tools()[1]
    origin = tmp_path / "mypy.py"
    _ = origin.write_text("", encoding="utf-8")
    _patch_release_tool_identity(
        monkeypatch,
        purelib=tmp_path,
        distributions=(_ReleaseDistributionFixture(tool.version),),
        specification=_ReleaseSpecificationFixture(origin.as_posix()),
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="trusted release tool entry point is invalid",
    ):
        _ = _trusted_release_tool_proof_resolver()(tool)


def test_trusted_release_module_rejects_console_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Module-mode tools cannot carry a console entry-point identity."""
    base_tool = _trusted_release_tools()[0]
    tool = _TrustedReleaseToolFixture(
        name=base_tool.name,
        module=base_tool.module,
        distribution=base_tool.distribution,
        version=base_tool.version,
        mode=base_tool.mode,
        entry_name="ruff",
        entry_value="ruff:main",
    )
    origin = tmp_path / "ruff.py"
    _ = origin.write_text("", encoding="utf-8")
    _patch_release_tool_identity(
        monkeypatch,
        purelib=tmp_path,
        distributions=(_ReleaseDistributionFixture(tool.version),),
        specification=_ReleaseSpecificationFixture(origin.as_posix()),
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="trusted release module invocation is invalid",
    ):
        _ = _trusted_release_tool_proof_resolver()(tool)


@pytest.mark.parametrize(
    "verb",
    ["prepare", "finalize", "draft-attestation", "attest", "eligibility"],
)
def test_protected_verbs_fail_external_authority_required(
    verb: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert release_module.cli([verb]) == _CLI_FAILURE
    assert "external_authority_required" in capsys.readouterr().err


def test_materialize_source_cli_dispatches_exact_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    output = tmp_path / "materialized"
    observed: list[tuple[Path, Path]] = []

    def observe_materialize(root: Path, destination: Path) -> None:
        observed.append((root, destination))

    monkeypatch.setattr(release_module, "materialize_source", observe_materialize)

    assert (
        release_module.main(
            [
                "materialize-source",
                "--worktree",
                worktree.as_posix(),
                "--output",
                output.as_posix(),
            ]
        )
        == 0
    )
    assert observed == [(worktree, output)]


@pytest.mark.parametrize(
    ("field", "value"),
    [("owner", ""), ("review_cadence_days", 0)],
)
def test_dependency_policy_rejects_missing_identity_or_cadence(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    payload = require_json_object(
        load_json_value(
            (PROJECT_ROOT / "security" / "dependency-risk-policy.json").read_bytes()
        ),
        context="dependency policy fixture",
    )
    payload[field] = cast("JsonValue", value)
    path = tmp_path / "dependency-risk-policy.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="schema rejected"):
        _ = release_module.load_dependency_risk_policy(path)


@pytest.mark.parametrize("defect", ["order", "freshness"])
def test_dependency_policy_rejects_open_source_inventory(
    tmp_path: Path,
    defect: str,
) -> None:
    payload = require_json_object(
        load_json_value(
            (PROJECT_ROOT / "security" / "dependency-risk-policy.json").read_bytes()
        ),
        context="dependency policy fixture",
    )
    sources = payload["advisory_sources"]
    assert isinstance(sources, list)
    if defect == "order":
        sources.reverse()
    else:
        first = sources[0]
        assert isinstance(first, dict)
        first["max_age_hours"] = 0
    path = tmp_path / "dependency-risk-policy.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="schema rejected"):
        _ = release_module.load_dependency_risk_policy(path)


def test_risk_window_rejects_nonpositive_limits() -> None:
    with pytest.raises(ValueError, match="positive"):
        _ = release_module.RiskWindow(triage_hours=0, remediation_days=1)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("receipt_id", ""),
        ("oci_subject_digest", "sha256:invalid"),
        ("media_type", ""),
    ],
)
def test_trivy_receipt_rejects_incomplete_identity(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    path = tmp_path / "trivy-receipt.json"
    _write_trivy_receipt(path)
    payload = require_json_object(
        load_json_value(path.read_bytes()), context="Trivy receipt fixture"
    )
    payload[field] = cast("JsonValue", value)
    _ = path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="TRIVY_DB"):
        _ = release_module.load_trivy_database_receipt(
            path,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


@pytest.mark.parametrize("acquired_at", ["2026-08-17T12:00:00", "not-a-timeZ"])
def test_trivy_receipt_rejects_noncanonical_timestamp(
    tmp_path: Path,
    acquired_at: str,
) -> None:
    path = tmp_path / "trivy-receipt.json"
    _write_trivy_receipt(path, acquired_at=acquired_at)

    with pytest.raises(ReleaseVerificationError):
        _ = release_module.load_trivy_database_receipt(
            path,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


def test_release_receipts_reject_non_utc_validation_clocks(tmp_path: Path) -> None:
    naive_now = datetime(2026, 8, 17, 18, tzinfo=UTC).replace(tzinfo=None)
    trivy = tmp_path / "trivy-receipt.json"
    _write_trivy_receipt(trivy)
    with pytest.raises(ReleaseVerificationError, match="TRIVY_DB"):
        _ = release_module.load_trivy_database_receipt(
            trivy,
            now=naive_now,
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )

    dependency = tmp_path / "dependency-evidence.json"
    _ = dependency.write_text(
        json.dumps(_dependency_evidence_payload()), encoding="utf-8"
    )
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )
    with pytest.raises(ReleaseVerificationError, match="DEPENDENCY_EVIDENCE_REJECTED"):
        _ = release_module.load_dependency_evidence(
            dependency,
            policy=policy,
            now=naive_now,
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("receipt_id", ""),
        ("scanner_version", "latest"),
        ("argv", []),
        ("lock_identities", []),
        ("raw_digest", "sha256:invalid"),
    ],
)
def test_dependency_evidence_rejects_incomplete_identity(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    payload = _dependency_evidence_payload()
    payload[field] = cast("JsonValue", value)
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    with pytest.raises(ReleaseVerificationError, match="DEPENDENCY_EVIDENCE_REJECTED"):
        _ = release_module.load_dependency_evidence(
            path,
            policy=policy,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


@pytest.mark.parametrize(
    "finding",
    [
        {
            **_finding(severity="low", discovered_at="2026-08-17T17:00:00Z"),
            "finding_id": "",
        },
        {
            **_finding(severity="low", discovered_at="2026-01-01T00:00:00Z"),
            "triaged_at": "2026-01-01T01:00:00Z",
        },
    ],
)
def test_dependency_evidence_rejects_missing_provenance_or_remediation(
    tmp_path: Path,
    finding: dict[str, object],
) -> None:
    payload = _dependency_evidence_payload()
    payload["findings"] = [finding]
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    with pytest.raises(ReleaseVerificationError, match="DEPENDENCY_EVIDENCE_REJECTED"):
        _ = release_module.load_dependency_evidence(
            path,
            policy=policy,
            now=datetime(2026, 8, 17, 18, tzinfo=UTC),
            seen_receipt_ids=frozenset(),
            previous_acquired_at=None,
        )


def test_release_policy_loader_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "dependency-risk-policy.json"
    _ = path.write_text("[]", encoding="utf-8")
    with pytest.raises(ReleaseVerificationError, match="must be an object"):
        _ = release_module.load_dependency_risk_policy(path)


def test_source_snapshot_records_symlink_and_special_entries(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").mkdir()
    (worktree / "link").symlink_to("target")
    os.mkfifo(worktree / "pipe")

    snapshot = release_module.capture_source_descriptor_snapshot(worktree)

    kinds = {entry.path: entry.kind for entry in snapshot.entries}
    assert kinds == {"link": "symlink", "pipe": "special"}


@pytest.mark.parametrize("case", ["relative", "existing", "contained"])
def test_source_snapshot_rejects_unsafe_output(tmp_path: Path, case: str) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").mkdir()
    if case == "relative":
        output = Path("relative-source-snapshot.json")
    elif case == "existing":
        output = tmp_path / "existing.json"
        _ = output.write_bytes(b"existing")
    else:
        output = worktree / "snapshot.json"

    with pytest.raises(ReleaseVerificationError, match="output is unsafe"):
        _ = release_module.write_source_snapshot(worktree, output)


def test_source_snapshot_cli_routes_round_trip(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").mkdir()
    _ = (worktree / "source.txt").write_bytes(b"source")
    snapshot = tmp_path / "snapshot.json"

    assert (
        release_module.main(
            [
                "source-snapshot",
                "--worktree",
                worktree.as_posix(),
                "--output",
                snapshot.as_posix(),
            ]
        )
        == 0
    )
    assert (
        release_module.main(
            [
                "assert-source-snapshot",
                "--worktree",
                worktree.as_posix(),
                "--snapshot",
                snapshot.as_posix(),
            ]
        )
        == 0
    )


def test_verify_release_direct_script_help(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [(PROJECT_ROOT / "scripts" / "verify_release.py").as_posix(), "--help"],
    )
    with pytest.raises(SystemExit) as raised:
        _ = cast(
            "dict[str, object]",
            runpy.run_path(
                (PROJECT_ROOT / "scripts" / "verify_release.py").as_posix(),
                run_name="__main__",
            ),
        )
    assert raised.value.code == 0


def test_gate_command_rejects_empty_identity_or_exit_inventory(tmp_path: Path) -> None:
    command = _command(tmp_path, "scanner")
    with pytest.raises(ReleaseVerificationError):
        _ = replace(command, name="")
    with pytest.raises(ReleaseVerificationError):
        _ = replace(command, finding_exit_codes=frozenset())


def test_dependency_evidence_accepts_closed_finding_and_exception(
    tmp_path: Path,
) -> None:
    finding = _finding(severity="low", discovered_at="2026-08-17T17:00:00Z")
    finding["triaged_at"] = "2026-08-17T17:30:00Z"
    finding["remediated_at"] = "2026-08-17T17:45:00Z"
    finding["exception"] = {
        "revision": "reviewed-revision",
        "subject_digest": "sha256:" + "5" * 64,
        "reachability_analysis_digest": "sha256:" + "9" * 64,
        "owner": "risk-owner",
        "compensating_controls": ["private-only"],
        "created_at": "2026-08-17T17:00:00Z",
        "expires_at": "2026-08-18T17:00:00Z",
        "risk_acceptance_digest": "sha256:" + "a" * 64,
        "scope": "named_non_public_staging_or_private",
        "terminal_recommendation": "do_not_release",
    }
    payload = _dependency_evidence_payload()
    payload["findings"] = [finding]
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    evidence = release_module.load_dependency_evidence(
        path,
        policy=policy,
        now=datetime(2026, 8, 17, 18, tzinfo=UTC),
        seen_receipt_ids=frozenset(),
        previous_acquired_at=None,
    )

    assert len(evidence.findings) == 1


def test_dependency_evidence_accepts_remediated_finding_without_exception(
    tmp_path: Path,
) -> None:
    finding = _finding(severity="low", discovered_at="2026-08-17T17:00:00Z")
    finding["triaged_at"] = "2026-08-17T17:30:00Z"
    finding["remediated_at"] = "2026-08-17T17:45:00Z"
    payload = _dependency_evidence_payload()
    payload["findings"] = [finding]
    path = tmp_path / "dependency-evidence.json"
    _ = path.write_text(json.dumps(payload), encoding="utf-8")
    policy = release_module.load_dependency_risk_policy(
        PROJECT_ROOT / "security" / "dependency-risk-policy.json"
    )

    evidence = release_module.load_dependency_evidence(
        path,
        policy=policy,
        now=datetime(2026, 8, 17, 18, tzinfo=UTC),
        seen_receipt_ids=frozenset(),
        previous_acquired_at=None,
    )

    assert evidence.findings[0].exception is None


def test_source_snapshot_rejects_capture_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").mkdir()
    source = worktree / "source.txt"
    _ = source.write_bytes(b"before")
    before = release_module.capture_source_descriptor_snapshot(worktree)
    _ = source.write_bytes(b"after")
    after = release_module.capture_source_descriptor_snapshot(worktree)
    snapshots = iter((before, after))

    def capture(_worktree: Path) -> release_module.SourceSnapshotDocument:
        return next(snapshots)

    monkeypatch.setattr(release_module, "capture_source_descriptor_snapshot", capture)
    with pytest.raises(ReleaseVerificationError, match="changed during capture"):
        _ = release_module.write_source_snapshot(
            worktree,
            (tmp_path / "snapshot.json").resolve(),
        )


@pytest.mark.parametrize("case", ["relative", "existing"])
def test_materialize_source_rejects_unsafe_output(tmp_path: Path, case: str) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    if case == "relative":
        output = Path("relative-materialized-source")
    else:
        output = tmp_path / "existing"
        output.mkdir()

    with pytest.raises(ReleaseVerificationError, match="output is unsafe"):
        release_module.materialize_source(worktree, output)


def test_source_snapshot_rejects_symlinked_worktree(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(worktree, target_is_directory=True)

    with pytest.raises(ReleaseVerificationError, match="not canonical"):
        _ = release_module.capture_source_descriptor_snapshot(alias)


def test_materialize_source_real_clean_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    git_adapter = SystemGit()

    def git(*arguments: str) -> None:
        result = git_adapter.run(
            ("/usr/bin/git", *arguments),
            cwd=worktree,
            environment={"GIT_OPTIONAL_LOCKS": "0"},
        )
        assert result.returncode == 0

    git("init", "-q")
    _ = (worktree / "source.txt").write_bytes(b"source\n")
    git("add", "source.txt")
    git(
        "-c",
        "user.name=Phase One Test",
        "-c",
        "user.email=phase-one@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    output = (tmp_path / "materialized").resolve()

    release_module.materialize_source(worktree.resolve(), output)

    assert (output / "source.txt").read_bytes() == b"source\n"
    assert (output / ".git").is_dir()

    original_capture = capture_source_snapshot
    calls = 0

    def drifting_capture(
        git_adapter: SystemGit,
        *,
        root: Path,
    ) -> SourceSnapshot:
        nonlocal calls
        calls += 1
        snapshot = original_capture(git_adapter, root=root)
        return (
            replace(snapshot, digest="0" * 64) if calls == _SECOND_CAPTURE else snapshot
        )

    monkeypatch.setattr(release_module, "capture_source_snapshot", drifting_capture)
    with pytest.raises(
        ReleaseVerificationError, match="changed during materialization"
    ):
        release_module.materialize_source(
            worktree.resolve(),
            (tmp_path / "drifted-materialized").resolve(),
        )


def test_materialize_source_rejects_dirty_git_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    class DirtyGit:
        def run(
            self,
            argv: tuple[str, ...],
            *,
            cwd: Path,
            environment: dict[str, str],
        ) -> CommandResult:
            del cwd, environment
            return CommandResult(argv=argv, returncode=0, stdout=b"dirty", stderr=b"")

    monkeypatch.setattr(release_module, "SystemGit", DirtyGit)
    with pytest.raises(ReleaseVerificationError, match="clean candidate"):
        release_module.materialize_source(
            worktree.resolve(),
            (tmp_path / "materialized").resolve(),
        )


def test_local_gates_reject_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").mkdir()
    source = worktree / "source.txt"
    _ = source.write_bytes(b"before")

    class MutatingRunner:
        mutated = False

        def __call__(self, command: GateCommand) -> ChildResult:
            del command
            if not self.mutated:
                _ = source.write_bytes(b"after")
                self.mutated = True
            return ChildResult(0, b"{}", b"")

    monkeypatch.setattr(
        release_module,
        "_validate_pyright_runtime_identity",
        _stable_runtime_identity,
        raising=False,
    )

    with pytest.raises(ReleaseVerificationError, match="source changed"):
        _ = release_module.run_local_gates(
            release_module.LocalGatesRequest(
                worktree=worktree,
                output=(tmp_path / "external-output").resolve(),
                node_executable=Path(sys.executable).resolve(),
                compare_branch="origin/main",
            ),
            runner=MutatingRunner(),
            monotonic=_Clock(),
        )


def test_local_gates_rejects_pyright_identity_drift_while_tool_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    _ = (worktree / "source.txt").write_bytes(b"stable")
    identities = iter(
        (
            _RuntimeIdentityFixture(),
            _RuntimeIdentityFixture(),
            _RuntimeIdentityFixture(
                offline_evidence=(
                    "sha256:" + "1" * 64,
                    PYRIGHT_EVIDENCE[1],
                    PYRIGHT_EVIDENCE[2],
                    PYRIGHT_EVIDENCE[3],
                )
            ),
        )
    )

    def drifting_runtime_identity(
        root: Path,
        node_executable: Path,
        cache_dir: Path,
    ) -> _RuntimeIdentityFixture:
        del root, node_executable, cache_dir
        return next(identities)

    monkeypatch.setattr(
        release_module,
        "_validate_pyright_runtime_identity",
        drifting_runtime_identity,
        raising=False,
    )

    with pytest.raises(ReleaseVerificationError, match="Pyright identity changed"):
        _ = release_module.run_local_gates(
            release_module.LocalGatesRequest(
                worktree=worktree,
                output=(tmp_path / "external-output").resolve(),
                node_executable=Path("/reviewed/node"),
                compare_branch="origin/main",
            ),
            runner=_PassingRunner(),
            monotonic=_Clock(),
        )


def test_local_gates_rejects_pyright_identity_drift_before_tool_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    _ = (worktree / "source.txt").write_bytes(b"stable")
    identities = iter(
        (
            _RuntimeIdentityFixture(),
            _RuntimeIdentityFixture(
                offline_evidence=(
                    "sha256:" + "1" * 64,
                    PYRIGHT_EVIDENCE[1],
                    PYRIGHT_EVIDENCE[2],
                    PYRIGHT_EVIDENCE[3],
                )
            ),
        )
    )

    def drifting_runtime_identity(
        root: Path,
        node_executable: Path,
        cache_dir: Path,
    ) -> _RuntimeIdentityFixture:
        del root, node_executable, cache_dir
        return next(identities)

    monkeypatch.setattr(
        release_module,
        "_validate_pyright_runtime_identity",
        drifting_runtime_identity,
        raising=False,
    )

    with pytest.raises(ReleaseVerificationError, match="before execution"):
        _ = release_module.run_local_gates(
            release_module.LocalGatesRequest(
                worktree=worktree,
                output=(tmp_path / "external-output").resolve(),
                node_executable=Path("/reviewed/node"),
                compare_branch="origin/main",
            ),
            runner=_PassingRunner(),
            monotonic=_Clock(),
        )


def test_local_gates_cli_dispatches_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policies = release_module.load_release_policies(PROJECT_ROOT / "security")
    loaded_policy_roots: list[Path] = []
    report = release_module.LocalGatesReport(
        local_status="passed",
        results=(),
        external_requirements=(),
        terminal_verdict="do_not_release",
        eligibility_reason="external_authority_required",
    )

    def load_policies(root: Path) -> release_module.ReleasePolicies:
        loaded_policy_roots.append(root)
        return policies

    def run_local(
        request: release_module.LocalGatesRequest,
        *,
        runner: release_module.CommandRunner,
        monotonic: object,
    ) -> release_module.LocalGatesReport:
        del request, runner, monotonic
        return report

    monkeypatch.setattr(release_module, "run_local_gates", run_local)
    monkeypatch.setattr(release_module, "load_release_policies", load_policies)
    assert (
        release_module.main(
            [
                "local-gates",
                "--worktree",
                tmp_path.as_posix(),
                "--output",
                (tmp_path / "output").as_posix(),
                "--node-executable",
                Path(sys.executable).resolve().as_posix(),
                "--compare-branch",
                "origin/main",
            ]
        )
        == 0
    )
    assert loaded_policy_roots == [tmp_path / "security"]
