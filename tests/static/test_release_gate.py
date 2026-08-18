# Copyright (c) 2026 David Osipov
"""Static and adversarial tests for candidate-side release verification."""

from __future__ import annotations

import json
import os
import runpy
import sys
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

import scripts.verify_release as release_module
from nplg_mcp.json_types import JsonValue, load_json_value, require_json_object
from scripts.baseline_capture_io import ChildResult, ProcessLimits
from scripts.run_test_gate import (
    CommandResult,
    SourceSnapshot,
    SystemGit,
    capture_source_snapshot,
)
from scripts.verify_release import (
    GateCommand,
    ReleaseVerificationError,
    run_gate_battery,
)

SUBJECT_DIGEST = "sha256:" + "a" * 64
PROJECT_ROOT = Path(__file__).parents[2]
_CLI_FAILURE = 2
_SECOND_CAPTURE = 2


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
class _EmptyEvidenceRunner:
    stdout: bytes = b""

    def __call__(self, command: GateCommand) -> ChildResult:
        del command
        return ChildResult(0, self.stdout, b"")


class _PassingRunner:
    def __call__(self, command: GateCommand) -> ChildResult:
        del command
        return ChildResult(0, b"{}", b"")


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

    report = release_module.run_local_gates(
        request,
        runner=_PassingRunner(),
        monotonic=_Clock(),
    )

    assert report.local_status == "passed"
    assert report.terminal_verdict == "do_not_release"
    assert report.eligibility_reason == "external_authority_required"
    assert {item.status for item in report.external_requirements} == {"not_passed"}
    assert (output / "release-gate-results.json").is_file()


def test_local_gate_commands_preserve_the_venv_python_executable() -> None:
    request = release_module.LocalGatesRequest(
        worktree=PROJECT_ROOT,
        output=Path("/external/release-evidence"),
        node_executable=Path("/reviewed/node"),
        compare_branch="origin/main",
    )

    commands = release_module.local_gate_commands(request, SUBJECT_DIGEST)

    assert commands[0].executable == Path(sys.executable)
    assert commands[0].argv[0] == sys.executable
    bandit = next(command for command in commands if command.name == "bandit")
    assert bandit.argv[3:6] == ("-ll", "-r", "src")
    pip_audit = next(command for command in commands if command.name == "pip-audit")
    assert pip_audit.argv[3:] == (
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


def test_local_gates_reject_source_drift(tmp_path: Path) -> None:
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


def test_local_gates_cli_dispatches_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = release_module.LocalGatesReport(
        local_status="passed",
        results=(),
        external_requirements=(),
        terminal_verdict="do_not_release",
        eligibility_reason="external_authority_required",
    )

    def run_local(
        request: release_module.LocalGatesRequest,
        *,
        runner: release_module.CommandRunner,
        monotonic: object,
    ) -> release_module.LocalGatesReport:
        del request, runner, monotonic
        return report

    monkeypatch.setattr(release_module, "run_local_gates", run_local)
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
