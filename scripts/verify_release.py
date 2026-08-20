# Copyright (c) 2026 David Osipov
"""Candidate-side release evidence validation and local gate orchestration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NoReturn, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from typing import TextIO

if __name__ == "__main__" and not __package__:
    script_package_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, script_package_root.as_posix())
    __package__ = "scripts"

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from nplg_mcp.json_types import dataclass_to_json, load_json_value
from scripts.baseline_capture_io import (
    BaselineCaptureError,
    ChildResult,
    ProcessLimits,
    canonical_json_bytes,
    read_regular_bytes,
    run_bounded_process,
    write_private_file,
)
from scripts.pyright_identity import (
    PyrightIdentityError,
    PyrightPackageIdentity,
    stable_regular_file_sha256,
    validate_pyright_package,
)
from scripts.run_quality_gate import (
    GateError as QualityGateError,
)
from scripts.run_quality_gate import (
    validate_managed_node,
    verify_exact_version,
)
from scripts.run_test_gate import (
    SystemGit,
    TestGateError,
    bind_external_snapshot,
    capture_source_snapshot,
    create_external_output,
    materialize_snapshot,
    registered_worktrees,
    stable_snapshot_file,
)

type GateVerdict = Literal["passed", "findings", "tool_error"]


_MAX_PROCESS_EXIT_CODE = 255
_GIT_EXECUTABLE = "/usr/bin/git"
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EXACT_VERSION_PATTERN = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?\Z")
_SUBJECT_KINDS = frozenset(
    {
        "canonical_image",
        "git_history",
        "materialized_source",
        "package",
        "repository",
        "sbom",
        "workflow",
    }
)
_UNSAFE_ARGUMENTS = frozenset(
    {
        "--download-db-only",
        "--exit-zero",
        "--ignore-unfixed",
        "--no-fail",
        "--skip-update",
        "--update",
        "auto",
    }
)
_AMBIENT_NAME_PARTS = (
    "ACTIONS_ID_TOKEN",
    "CREDENTIAL",
    "GIT_CONFIG",
    "OIDC",
    "PROXY",
    "SECRET",
    "SSH_AUTH_SOCK",
    "TOKEN",
)
_SOURCE_SNAPSHOT_EXCLUDED_ROOTS = frozenset(
    {
        ".agents",
        ".codex",
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".serena",
        ".tools",
        ".venv",
        "node_modules",
    }
)


class ReleaseVerificationError(RuntimeError):
    """Raised when candidate-side release evidence fails closed."""


def _fail(message: str) -> NoReturn:
    raise ReleaseVerificationError(message)


def _fail_from(message: str, cause: BaseException) -> NoReturn:
    raise ReleaseVerificationError(message) from cause


class _StrictModel(BaseModel):
    """Closed, immutable, non-coercing release-policy boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _PyrightSummary(_StrictModel):
    """Exact zero-diagnostic summary emitted by the reviewed Pyright build."""

    files_analyzed: int = Field(alias="filesAnalyzed", ge=1)
    error_count: Literal[0] = Field(alias="errorCount")
    warning_count: Literal[0] = Field(alias="warningCount")
    information_count: Literal[0] = Field(alias="informationCount")
    time_in_seconds: float = Field(
        alias="timeInSec",
        ge=0.0,
        allow_inf_nan=False,
    )


class _PyrightSuccess(_StrictModel):
    """Closed success schema for Pyright 1.1.413 ``--outputjson`` output."""

    version: Literal["1.1.413"]
    time: str = Field(pattern=r"^[0-9]{13}$")
    general_diagnostics: tuple[object, ...] = Field(
        alias="generalDiagnostics",
        max_length=0,
    )
    summary: _PyrightSummary


class RiskWindow(_StrictModel):
    """Maximum triage and remediation delay for one finding class."""

    triage_hours: int
    remediation_days: int

    @model_validator(mode="after")
    def _positive_window(self) -> RiskWindow:
        if self.triage_hours <= 0 or self.remediation_days <= 0:
            msg = "dependency risk window must be positive"
            raise ValueError(msg)
        return self


class AdvisorySource(_StrictModel):
    """One approved, freshness-bound advisory identity."""

    source_id: Literal["npm-advisories", "osv", "trivy-db"]
    kind: Literal["https_snapshot", "oci_artifact"]
    locator: str
    max_age_hours: int
    require_digest: Literal[True]
    require_signature: bool


class DependencyExceptionPolicy(_StrictModel):
    """Fail-closed scope for a revision-bound dependency exception."""

    require_revision_and_subject: Literal[True]
    require_reachability_analysis: Literal[True]
    require_owner: Literal[True]
    require_compensating_controls: Literal[True]
    expiry_within_underlying_window: Literal[True]
    require_separate_verified_risk_acceptance: Literal[True]
    allowed_scope: Literal["named_non_public_staging_or_private"]
    terminal_recommendation: Literal["do_not_release"]
    permits_public_eligibility: Literal[False]
    permits_asvs_conformance: Literal[False]


class DependencyRiskPolicy(_StrictModel):
    """Closed dependency-evidence and remediation policy."""

    schema_version: Literal[1]
    owner: str
    review_cadence_days: int
    advisory_sources: tuple[AdvisorySource, ...]
    known_exploited: RiskWindow
    critical: RiskWindow
    high: RiskWindow
    medium: RiskWindow
    low: RiskWindow
    unknown_severity_action: Literal["block_release"]
    stale_or_unavailable_source_action: Literal["block_release"]
    missing_package_provenance_action: Literal["block_release"]
    breached_window_action: Literal["block_release"]
    exception_policy: DependencyExceptionPolicy

    @model_validator(mode="after")
    def _closed_sources(self) -> DependencyRiskPolicy:
        if self.review_cadence_days <= 0 or not self.owner:
            msg = "dependency policy owner and cadence are required"
            raise ValueError(msg)
        source_ids = tuple(source.source_id for source in self.advisory_sources)
        if source_ids != ("osv", "npm-advisories", "trivy-db"):
            msg = "dependency advisory source inventory is not closed"
            raise ValueError(msg)
        if any(source.max_age_hours <= 0 for source in self.advisory_sources):
            msg = "dependency advisory freshness must be positive"
            raise ValueError(msg)
        return self


class PythonPackageSources(_StrictModel):
    """Exact Python index and artifact acquisition policy."""

    index_url: Literal["https://pypi.org/simple"]
    artifact_hosts: tuple[Literal["files.pythonhosted.org"], ...]
    require_hashes: Literal[True]
    wheels_preferred: Literal[True]
    sdist_mode: Literal["isolated_no_secret_no_network"]


class NpmPackageSources(_StrictModel):
    """Exact npm registry and integrity policy."""

    registry_url: Literal["https://registry.npmjs.org/"]
    resolved_hosts: tuple[Literal["registry.npmjs.org"], ...]
    require_integrity: Literal[True]


class PackageAcquisitionPolicy(_StrictModel):
    """Offline candidate acquisition boundary."""

    cache_root: Literal["external_mode_0700"]
    candidate_network: Literal["offline"]
    ambient_extra_index: Literal[False]
    ambient_registry_override: Literal[False]
    ambient_proxy: Literal[False]
    ambient_credentials: Literal[False]
    verify_before_candidate_code: Literal[True]
    hostile_sdist_canary_required: Literal[True]
    sitecustomize_canary_required: Literal[True]


class TrustedPackageSourcesPolicy(_StrictModel):
    """Closed package-source trust policy."""

    schema_version: Literal[1]
    python: PythonPackageSources
    npm: NpmPackageSources
    acquisition: PackageAcquisitionPolicy
    unknown_host_action: Literal["fail_before_package_code"]


class ExpectedControllerIdentity(_StrictModel):
    """Unconfigured external controller bindings that candidate code cannot mint."""

    configured: Literal[False]
    artifact_digest: None
    revision: None
    policy_digest: None
    authority_identity: None
    dependency_lock_digest: None
    command_manifest_digest: None
    isolation_version: None
    credential_broker_identities: tuple[()]


class ProtectedAuthorityPolicy(_StrictModel):
    """Requirements for the separately governed controller authority."""

    required: Literal[True]
    same_repository_allowed: Literal[False]
    candidate_controlled_workflow_allowed: Literal[False]
    required_oidc_claims: tuple[str, ...]
    immutable_workflow_identity_required: Literal[True]


class ControllerIsolationPolicy(_StrictModel):
    """Candidate/controller credential and process isolation contract."""

    candidate_network: Literal["bounded_offline"]
    candidate_secrets: Literal["none"]
    helper_uids: Literal["distinct"]
    close_inherited_descriptors: Literal[True]
    same_uid_holds_both_credential_classes: Literal[False]
    proc_parent_environment_canary_required: Literal[True]
    proc_parent_fd_canary_required: Literal[True]


class ReleaseControllerPolicy(_StrictModel):
    """Candidate-side expected descriptor for an external release controller."""

    schema_version: Literal[1]
    status: Literal["external_authority_required"]
    candidate_may_supply_controller: Literal[False]
    expected_controller: ExpectedControllerIdentity
    protected_authority: ProtectedAuthorityPolicy
    isolation: ControllerIsolationPolicy
    required_credential_broker_classes: tuple[
        Literal["deployment_provider", "mcp"], ...
    ]
    allowed_outputs: tuple[str, ...]
    local_terminal_verdict: Literal["do_not_release"]
    local_error: Literal["external_authority_required"]


class TrivyDatabaseReceipt(_StrictModel):
    """Signed, fresh, independently acquired Trivy database receipt."""

    schema_version: Literal[1]
    receipt_id: str
    oci_subject_digest: str
    media_type: str
    artifact_type: str
    signer_policy_digest: str
    authority_identity: str
    acquired_at: str
    response_digest: str
    signature_verified: Literal[True]
    upstream_attested: Literal[True]
    candidate_generated: Literal[False]

    @model_validator(mode="after")
    def _bound_identity(self) -> TrivyDatabaseReceipt:
        if (
            not self.receipt_id
            or not self.media_type
            or not self.artifact_type
            or not self.authority_identity
            or _SHA256_PATTERN.fullmatch(self.oci_subject_digest) is None
            or _SHA256_PATTERN.fullmatch(self.signer_policy_digest) is None
            or _SHA256_PATTERN.fullmatch(self.response_digest) is None
        ):
            msg = "Trivy database receipt identity is incomplete"
            raise ValueError(msg)
        return self


class SourceInventoryEntry(_StrictModel):
    """One descriptor-observed non-.git source entry."""

    path: str
    kind: Literal["directory", "regular", "symlink", "special"]
    mode: int
    size: int
    sha256: str


class SourceSnapshotDocument(_StrictModel):
    """Stable descriptor inventory for all candidate source paths."""

    schema_version: Literal[1]
    worktree: str
    entries: tuple[SourceInventoryEntry, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class LocalGatesRequest:
    """Exact public local-gates request."""

    worktree: Path
    output: Path
    node_executable: Path
    compare_branch: str


@dataclass(frozen=True, slots=True)
class ExternalRequirementResult:
    """One required check that candidate-local execution cannot authorize."""

    name: str
    version: str
    status: Literal["not_passed"] = "not_passed"
    reason: Literal["external_authority_required"] = "external_authority_required"


@dataclass(frozen=True, slots=True)
class LocalGatesReport:
    """Closed local result plus explicitly unfulfilled external requirements."""

    local_status: Literal["passed", "failed"]
    results: tuple[GateResult, ...]
    external_requirements: tuple[ExternalRequirementResult, ...]
    terminal_verdict: Literal["do_not_release"]
    eligibility_reason: Literal["external_authority_required"]


class DependencyRiskException(_StrictModel):
    """One revision-bound, staging-only dependency risk exception."""

    revision: str
    subject_digest: str
    reachability_analysis_digest: str
    owner: str
    compensating_controls: tuple[str, ...]
    created_at: str
    expires_at: str
    risk_acceptance_digest: str
    scope: Literal["named_non_public_staging_or_private"]
    terminal_recommendation: Literal["do_not_release"]


class DependencyFinding(_StrictModel):
    """One dependency finding with independently bound package provenance."""

    finding_id: str
    package: str
    package_provenance_digest: str
    severity: str
    discovered_at: str
    triaged_at: str | None
    remediated_at: str | None
    exception: DependencyRiskException | None


class DependencyEvidence(_StrictModel):
    """One raw-to-redacted, lock-bound SCA evidence receipt."""

    schema_version: Literal[1]
    receipt_id: str
    source_id: Literal["npm-advisories", "osv", "trivy-db"]
    acquired_at: str
    response_digest: str
    scanner_name: str
    scanner_version: str
    argv: tuple[str, ...]
    lock_identities: tuple[str, ...]
    raw_digest: str
    redacted_digest: str
    truncated: Literal[False]
    findings: tuple[DependencyFinding, ...]

    @model_validator(mode="after")
    def _bound_evidence(self) -> DependencyEvidence:
        digests = (
            self.response_digest,
            self.raw_digest,
            self.redacted_digest,
            *self.lock_identities,
        )
        if (
            not self.receipt_id
            or not self.scanner_name
            or _EXACT_VERSION_PATTERN.fullmatch(self.scanner_version) is None
            or not self.argv
            or not self.lock_identities
            or any(_SHA256_PATTERN.fullmatch(item) is None for item in digests)
        ):
            msg = "dependency evidence identity is incomplete"
            raise ValueError(msg)
        return self


@dataclass(frozen=True, slots=True)
class ReleasePolicies:
    """The three independently parsed Task 8 candidate-side policies."""

    dependency_risk: DependencyRiskPolicy
    trusted_sources: TrustedPackageSourcesPolicy
    controller: ReleaseControllerPolicy


def _duplicate_json_name(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            msg = f"duplicate release-policy JSON name: {name}"
            raise ReleaseVerificationError(msg)
        value[name] = item
    return value


def _reject_json_number(value: str) -> NoReturn:
    msg = f"unsupported release-policy JSON number: {value}"
    raise ReleaseVerificationError(msg)


def _freeze_json_arrays(value: object) -> object:
    if type(value) is list:
        return tuple(_freeze_json_arrays(item) for item in cast("list[object]", value))
    if type(value) is dict:
        return {
            name: _freeze_json_arrays(item)
            for name, item in cast("dict[str, object]", value).items()
        }
    return value


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        raw = read_regular_bytes(path)
        parsed = cast(
            "object",
            json.loads(
                raw,
                object_pairs_hook=_duplicate_json_name,
                parse_constant=_reject_json_number,
                parse_float=_reject_json_number,
            ),
        )
    except (
        BaselineCaptureError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        msg = f"release policy is unreadable: {path.name}"
        raise ReleaseVerificationError(msg) from exc
    if type(parsed) is not dict:
        msg = f"release policy must be an object: {path.name}"
        raise ReleaseVerificationError(msg)
    return cast(
        "dict[str, object]",
        _freeze_json_arrays(cast("dict[str, object]", parsed)),
    )


def _load_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    try:
        return model.model_validate(_load_json_object(path), strict=True)
    except ValidationError as exc:
        msg = f"release policy schema rejected: {path.name}"
        raise ReleaseVerificationError(msg) from exc


def load_dependency_risk_policy(path: Path) -> DependencyRiskPolicy:
    """Load one strict dependency-risk policy."""
    return _load_model(path, DependencyRiskPolicy)


def load_trusted_package_sources_policy(path: Path) -> TrustedPackageSourcesPolicy:
    """Load one strict package-source policy."""
    return _load_model(path, TrustedPackageSourcesPolicy)


def load_release_controller_policy(path: Path) -> ReleaseControllerPolicy:
    """Load one strict external-controller expectation descriptor."""
    return _load_model(path, ReleaseControllerPolicy)


def _utc_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        msg = "external receipt timestamp must be canonical UTC"
        raise ReleaseVerificationError(msg)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        msg = "external receipt timestamp is invalid"
        raise ReleaseVerificationError(msg) from exc
    return parsed.astimezone(UTC)


def load_trivy_database_receipt(
    path: Path,
    *,
    now: datetime,
    seen_receipt_ids: frozenset[str],
    previous_acquired_at: datetime | None,
) -> TrivyDatabaseReceipt:
    """Validate external Trivy database provenance, freshness, and replay state."""
    try:
        receipt = _load_model(path, TrivyDatabaseReceipt)
        acquired_at = _utc_timestamp(receipt.acquired_at)
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            _fail("receipt validation clock is not UTC")
        age = now.astimezone(UTC) - acquired_at
        if age < timedelta(0) or age > timedelta(hours=24):
            _fail("external receipt is not fresh")
        if receipt.receipt_id in seen_receipt_ids:
            _fail("external receipt replay detected")
        if (
            previous_acquired_at is not None
            and acquired_at < previous_acquired_at.astimezone(UTC)
        ):
            _fail("external receipt clock rollback detected")
    except ReleaseVerificationError as exc:
        _fail_from("TRIVY_DB_UPSTREAM_PROVENANCE_UNATTESTED", exc)
    return receipt


def _dependency_window(
    policy: DependencyRiskPolicy,
    severity: str,
) -> RiskWindow:
    windows = {
        "known_exploited": policy.known_exploited,
        "critical": policy.critical,
        "high": policy.high,
        "medium": policy.medium,
        "low": policy.low,
    }
    try:
        return windows[severity.casefold()]
    except KeyError as exc:
        msg = "dependency finding severity is unknown"
        raise ReleaseVerificationError(msg) from exc


def _validate_dependency_exception(
    exception: DependencyRiskException,
    *,
    subject_digest: str,
    window: RiskWindow,
    now: datetime,
) -> None:
    created_at = _utc_timestamp(exception.created_at)
    expires_at = _utc_timestamp(exception.expires_at)
    if (
        exception.subject_digest != subject_digest
        or _SHA256_PATTERN.fullmatch(exception.subject_digest) is None
        or _SHA256_PATTERN.fullmatch(exception.reachability_analysis_digest) is None
        or _SHA256_PATTERN.fullmatch(exception.risk_acceptance_digest) is None
        or not exception.revision
        or not exception.owner
        or not exception.compensating_controls
        or expires_at <= created_at
        or expires_at > created_at + timedelta(days=window.remediation_days)
        or expires_at <= now
    ):
        msg = "dependency risk exception is invalid or expired"
        raise ReleaseVerificationError(msg)


def _validate_dependency_evidence_identity(
    evidence: DependencyEvidence,
    *,
    policy: DependencyRiskPolicy,
    now: datetime,
    seen_receipt_ids: frozenset[str],
    previous_acquired_at: datetime | None,
) -> None:
    acquired_at = _utc_timestamp(evidence.acquired_at)
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        _fail("dependency evidence clock is not UTC")
    sources = {source.source_id: source for source in policy.advisory_sources}
    try:
        source = sources[evidence.source_id]
    except KeyError as exc:
        _fail_from("dependency evidence source is unknown", exc)
    age = now.astimezone(UTC) - acquired_at
    if age < timedelta(0) or age > timedelta(hours=source.max_age_hours):
        _fail("dependency evidence source is stale")
    if evidence.receipt_id in seen_receipt_ids:
        _fail("dependency evidence replay detected")
    if (
        previous_acquired_at is not None
        and acquired_at < previous_acquired_at.astimezone(UTC)
    ):
        _fail("dependency evidence clock rollback detected")


def _validate_dependency_finding(
    finding: DependencyFinding,
    *,
    subject_digest: str,
    policy: DependencyRiskPolicy,
    now: datetime,
) -> None:
    window = _dependency_window(policy, finding.severity)
    if (
        _SHA256_PATTERN.fullmatch(finding.package_provenance_digest) is None
        or not finding.finding_id
        or not finding.package
    ):
        _fail("dependency package provenance is missing")
    discovered_at = _utc_timestamp(finding.discovered_at)
    if finding.triaged_at is None and now - discovered_at > timedelta(
        hours=window.triage_hours
    ):
        _fail("dependency triage window breached")
    if finding.remediated_at is None and now - discovered_at > timedelta(
        days=window.remediation_days
    ):
        _fail("dependency remediation window breached")
    if finding.exception is not None:
        _validate_dependency_exception(
            finding.exception,
            subject_digest=subject_digest,
            window=window,
            now=now,
        )


def load_dependency_evidence(
    path: Path,
    *,
    policy: DependencyRiskPolicy,
    now: datetime,
    seen_receipt_ids: frozenset[str],
    previous_acquired_at: datetime | None,
) -> DependencyEvidence:
    """Validate fresh SCA evidence and every finding's remediation window."""
    try:
        evidence = _load_model(path, DependencyEvidence)
        _validate_dependency_evidence_identity(
            evidence,
            policy=policy,
            now=now,
            seen_receipt_ids=seen_receipt_ids,
            previous_acquired_at=previous_acquired_at,
        )
        subject_digest = evidence.lock_identities[0]
        for finding in evidence.findings:
            _validate_dependency_finding(
                finding,
                subject_digest=subject_digest,
                policy=policy,
                now=now,
            )
    except ReleaseVerificationError as exc:
        _fail_from("DEPENDENCY_EVIDENCE_REJECTED", exc)
    return evidence


def _source_entry(
    root: Path, relative: str, metadata: os.stat_result
) -> SourceInventoryEntry:
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISREG(metadata.st_mode):
        record = stable_snapshot_file(root, relative)
        return SourceInventoryEntry(
            path=relative,
            kind="regular",
            mode=record.mode,
            size=len(record.payload),
            sha256="sha256:" + record.sha256,
        )
    if stat.S_ISDIR(metadata.st_mode):
        kind: Literal["directory", "regular", "symlink", "special"] = "directory"
        payload = b""
    elif stat.S_ISLNK(metadata.st_mode):
        kind = "symlink"
        payload = (
            (root / relative).readlink().as_posix().encode("utf-8", errors="strict")
        )
    else:
        kind = "special"
        payload = b""
    return SourceInventoryEntry(
        path=relative,
        kind=kind,
        mode=mode,
        size=metadata.st_size,
        sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
    )


def _dir_entry_name(entry: os.DirEntry[str]) -> str:
    return entry.name


def _source_entry_path(entry: SourceInventoryEntry) -> str:
    return entry.path


def capture_source_descriptor_snapshot(worktree: Path) -> SourceSnapshotDocument:
    """Descriptor-inventory candidate paths, including ignored inputs."""
    try:
        root = worktree.resolve(strict=True)
    except OSError as exc:
        _fail_from("source worktree is unavailable", exc)
    if root != worktree.absolute() or not root.is_dir():
        _fail("source worktree is not canonical")
    pending = [(root, "")]
    entries: list[SourceInventoryEntry] = []
    while pending:
        directory, prefix = pending.pop()
        try:
            children: tuple[os.DirEntry[str], ...] = tuple(
                os.scandir(directory.as_posix())
            )
        except OSError as exc:
            _fail_from("source inventory is unavailable", exc)
        for child in sorted(children, key=_dir_entry_name):
            if not prefix and (
                child.name in _SOURCE_SNAPSHOT_EXCLUDED_ROOTS
                or child.name.startswith(".codex-request-")
            ):
                continue
            relative = f"{prefix}/{child.name}" if prefix else child.name
            metadata = child.stat(follow_symlinks=False)
            entry = _source_entry(root, relative, metadata)
            entries.append(entry)
            if entry.kind == "directory":
                pending.append((root / relative, relative))
    ordered = tuple(sorted(entries, key=_source_entry_path))
    digest_payload = [load_json_value(entry.model_dump_json()) for entry in ordered]
    digest = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(digest_payload)).hexdigest()
    )
    return SourceSnapshotDocument(
        schema_version=1,
        worktree=root.as_posix(),
        entries=ordered,
        digest=digest,
    )


def write_source_snapshot(worktree: Path, output: Path) -> SourceSnapshotDocument:
    """Capture stable source bytes and publish one new external JSON document."""
    before = capture_source_descriptor_snapshot(worktree)
    after = capture_source_descriptor_snapshot(worktree)
    if before != after:
        _fail("source snapshot changed during capture")
    if (
        not output.is_absolute()
        or os.path.lexists(output)
        or output == worktree
        or worktree in output.parents
    ):
        _fail("source snapshot output is unsafe")
    write_private_file(
        output,
        canonical_json_bytes(load_json_value(before.model_dump_json())),
    )
    return before


def assert_source_snapshot(worktree: Path, snapshot: Path) -> None:
    """Require current descriptor inventory to equal a prior snapshot exactly."""
    expected = _load_model(snapshot, SourceSnapshotDocument)
    actual = capture_source_descriptor_snapshot(worktree)
    if actual != expected:
        _fail("source snapshot changed")


def materialize_source(worktree: Path, output: Path) -> None:
    """Materialize one clean candidate through the shared Task 7 snapshot seam."""
    root = worktree.resolve(strict=True)
    if not output.is_absolute() or os.path.lexists(output):
        _fail("materialized source output is unsafe")
    git = SystemGit()
    status = git.run(
        (
            _GIT_EXECUTABLE,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ),
        cwd=root,
        environment={"GIT_OPTIONAL_LOCKS": "0"},
    )
    if status.returncode != 0 or status.stdout or status.stderr:
        _fail("materialize-source requires a clean candidate")
    source = capture_source_snapshot(git, root=root)
    worktrees = registered_worktrees(git, root=root)
    stage_request = output.parent / f".{output.name}.nplg-stage"
    stage, _temporary = create_external_output(
        stage_request,
        registered_worktrees=worktrees,
    )
    materialized = materialize_snapshot(
        root,
        source,
        merge_base="HEAD",
        output=stage,
        git=git,
    )
    _ = bind_external_snapshot(
        git,
        materialized=materialized,
        source_snapshot=source,
    )
    if capture_source_snapshot(git, root=root) != source:
        _fail("source changed during materialization")
    materialized.root.chmod(0o700)
    _ = materialized.root.rename(output)
    stage.rmdir()


@dataclass(frozen=True, slots=True)
class _GateCommandContext:
    cwd: Path
    subject_digest: str


@dataclass(frozen=True, slots=True)
class _PyrightRuntimeIdentity:
    """Reviewed Node and package evidence used for one Pyright execution."""

    node_sha256: str
    package: PyrightPackageIdentity

    @property
    def offline_evidence(self) -> tuple[str, ...]:
        return (self.node_sha256, *self.package.offline_evidence)


def _gate_command(
    *,
    name: str,
    executable: Path,
    version: str,
    argv: tuple[str, ...],
    context: _GateCommandContext,
) -> GateCommand:
    return GateCommand(
        name=name,
        executable=executable,
        version=version,
        argv=argv,
        cwd=context.cwd,
        environment=(("LANG", "C.UTF-8"),),
        subject_kind="materialized_source",
        subject_digest=context.subject_digest,
        timeout_seconds=900.0,
        stdout_limit_bytes=16 * 1024 * 1024,
        stderr_limit_bytes=16 * 1024 * 1024,
        finding_exit_codes=frozenset({1}),
        tool_error_exit_codes=frozenset({2}),
        result_schema="nplg.release.gate-result.v1",
        offline_evidence=(context.subject_digest,),
    )


def local_gate_commands(
    request: LocalGatesRequest,
    subject_digest: str,
    *,
    pyright_evidence: tuple[str, ...],
) -> tuple[GateCommand, ...]:
    """Build the exact locally authoritative source/test command inventory."""
    python = Path(sys.executable)
    zizmor = python.parent / "zizmor"
    root = request.worktree.resolve(strict=True)
    node = request.node_executable
    context = _GateCommandContext(cwd=root, subject_digest=subject_digest)
    return (
        _gate_command(
            name="ruff",
            executable=python,
            version="0.16.3",
            argv=(
                python.as_posix(),
                "-m",
                "ruff",
                "check",
                "--output-format=json",
                "src",
                "scripts",
            ),
            context=context,
        ),
        _gate_command(
            name="mypy",
            executable=python,
            version="2.3.1",
            argv=(python.as_posix(), "-m", "mypy", "-O", "json", "src", "scripts"),
            context=context,
        ),
        replace(
            _gate_command(
                name="pyright",
                executable=node,
                version="1.1.413",
                argv=(
                    node.as_posix(),
                    (root / "node_modules/pyright/index.js").as_posix(),
                    "--outputjson",
                ),
                context=context,
            ),
            offline_evidence=(subject_digest, *pyright_evidence),
        ),
        _gate_command(
            name="test-gate",
            executable=python,
            version="1.0.0",
            argv=(
                python.as_posix(),
                "-m",
                "scripts.run_test_gate",
                "--worktree",
                root.as_posix(),
                "--compare-branch",
                request.compare_branch,
                "--output-dir",
                (request.output / "test-gate").as_posix(),
            ),
            context=context,
        ),
        _gate_command(
            name="bandit",
            executable=python,
            version="1.9.4",
            argv=(
                python.as_posix(),
                "-m",
                "bandit",
                "-ll",
                "-r",
                "src",
                "scripts",
                "-f",
                "json",
            ),
            context=context,
        ),
        _gate_command(
            name="pip-audit",
            executable=python,
            version="2.10.1",
            argv=(
                python.as_posix(),
                "-m",
                "pip_audit",
                "-r",
                "requirements-dev.lock",
                "--require-hashes",
                "--no-deps",
                "--format=json",
                "--progress-spinner",
                "off",
            ),
            context=context,
        ),
        _gate_command(
            name="cyclonedx",
            executable=python,
            version="7.3.1",
            argv=(
                python.as_posix(),
                "-m",
                "cyclonedx_py",
                "environment",
                "--output-format",
                "JSON",
            ),
            context=context,
        ),
        _gate_command(
            name="zizmor",
            executable=zizmor,
            version="1.29.0",
            argv=(
                zizmor.as_posix(),
                "--offline",
                "--format=json",
                ".github/workflows",
            ),
            context=context,
        ),
    )


def _external_requirements() -> tuple[ExternalRequirementResult, ...]:
    return tuple(
        ExternalRequirementResult(name, version)
        for name, version in (
            ("actionlint", "1.7.12"),
            ("semgrep", "1.173.0"),
            ("gitleaks-dir", "8.30.1"),
            ("gitleaks-history", "8.30.1"),
            ("trivy-filesystem", "0.74.0"),
            ("trivy-signed-fresh-db-receipt", "0.74.0"),
        )
    )


def _validate_pyright_runtime_identity(
    root: Path,
    node_executable: Path,
    cache_dir: Path,
) -> _PyrightRuntimeIdentity:
    """Prove the managed Node binary, Pyright package tree, and exact version."""
    try:
        reviewed_node = validate_managed_node(root, node_executable)
        package = validate_pyright_package(root)
        verify_exact_version(
            (
                reviewed_node.as_posix(),
                (root / "node_modules" / "pyright" / "index.js").as_posix(),
                "--version",
            ),
            expected_stdout=b"pyright 1.1.413\n",
            root=root,
            cache_dir=cache_dir,
        )
        node_sha256 = stable_regular_file_sha256(
            reviewed_node,
            max_bytes=256 * 1024 * 1024,
        )
    except (OSError, PyrightIdentityError, QualityGateError) as exc:
        _fail_from("reviewed Pyright runtime identity is invalid", exc)
    return _PyrightRuntimeIdentity(
        node_sha256=node_sha256,
        package=package,
    )


@dataclass(frozen=True, slots=True)
class _PyrightIdentityBoundRunner:
    """Recheck reviewed runtime bytes immediately around Pyright execution."""

    delegate: CommandRunner
    root: Path
    node_executable: Path
    cache_dir: Path
    expected_evidence: tuple[str, ...]

    def __call__(self, command: GateCommand) -> ChildResult:
        if command.name != "pyright":
            return self.delegate(command)
        before = _validate_pyright_runtime_identity(
            self.root,
            self.node_executable,
            self.cache_dir,
        )
        if before.offline_evidence != self.expected_evidence:
            _fail("Pyright identity changed before execution")
        completed = self.delegate(command)
        after = _validate_pyright_runtime_identity(
            self.root,
            self.node_executable,
            self.cache_dir,
        )
        if after.offline_evidence != self.expected_evidence:
            _fail("Pyright identity changed while Pyright ran")
        return completed


def run_local_gates(
    request: LocalGatesRequest,
    *,
    runner: CommandRunner,
    monotonic: Callable[[], float],
) -> LocalGatesReport:
    """Run local commands and record external requirements without fabricating PASS."""
    before = capture_source_descriptor_snapshot(request.worktree)
    output, _temporary = create_external_output(
        request.output,
        registered_worktrees=(request.worktree.resolve(strict=True),),
    )
    identity_cache = output / "pyright-identity-cache"
    identity_cache.mkdir(mode=0o700)
    root = request.worktree.resolve(strict=True)
    identity = _validate_pyright_runtime_identity(
        root,
        request.node_executable,
        identity_cache,
    )
    commands = local_gate_commands(
        request,
        before.digest,
        pyright_evidence=identity.offline_evidence,
    )
    bound_runner = _PyrightIdentityBoundRunner(
        delegate=runner,
        root=root,
        node_executable=request.node_executable,
        cache_dir=identity_cache,
        expected_evidence=identity.offline_evidence,
    )
    results = run_gate_battery(commands, bound_runner, monotonic=monotonic)
    local_status: Literal["passed", "failed"] = (
        "passed"
        if len(results) == len(commands)
        and all(item.verdict == "passed" for item in results)
        else "failed"
    )
    report = LocalGatesReport(
        local_status=local_status,
        results=results,
        external_requirements=_external_requirements(),
        terminal_verdict="do_not_release",
        eligibility_reason="external_authority_required",
    )
    write_private_file(
        output / "release-gate-results.json",
        canonical_json_bytes(dataclass_to_json(report, context="local gate report")),
    )
    if capture_source_descriptor_snapshot(request.worktree) != before:
        _fail("source changed while local gates ran")
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("source-snapshot", "assert-source-snapshot", "materialize-source"):
        command = subparsers.add_parser(name, allow_abbrev=False)
        _ = command.add_argument("--worktree", type=Path, required=True)
        if name == "assert-source-snapshot":
            _ = command.add_argument("--snapshot", type=Path, required=True)
        else:
            _ = command.add_argument("--output", type=Path, required=True)
    local = subparsers.add_parser("local-gates", allow_abbrev=False)
    _ = local.add_argument("--worktree", type=Path, required=True)
    _ = local.add_argument("--output", type=Path, required=True)
    _ = local.add_argument("--node-executable", type=Path, required=True)
    _ = local.add_argument("--compare-branch", required=True)
    for name in ("prepare", "finalize", "draft-attestation", "attest", "eligibility"):
        _ = subparsers.add_parser(name, allow_abbrev=False)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the closed candidate-side Task 8 command surface."""
    values = cast("dict[str, object]", vars(_parser().parse_args(argv)))
    command = cast("str", values["command"])
    if command in {"prepare", "finalize", "draft-attestation", "attest", "eligibility"}:
        _fail("external_authority_required")
    worktree = cast("Path", values["worktree"])
    if command == "source-snapshot":
        _ = write_source_snapshot(worktree, cast("Path", values["output"]))
        return 0
    if command == "assert-source-snapshot":
        assert_source_snapshot(worktree, cast("Path", values["snapshot"]))
        return 0
    if command == "materialize-source":
        materialize_source(worktree, cast("Path", values["output"]))
        return 0
    report = run_local_gates(
        LocalGatesRequest(
            worktree=worktree,
            output=cast("Path", values["output"]),
            node_executable=cast("Path", values["node_executable"]),
            compare_branch=cast("str", values["compare_branch"]),
        ),
        runner=SystemCommandRunner(),
        monotonic=time.monotonic,
    )
    return 0 if report.local_status == "passed" else 1


def cli(argv: Sequence[str] | None = None) -> int:
    """Render one bounded candidate-side failure without an internal traceback."""
    try:
        return main(argv)
    except (
        BaselineCaptureError,
        OSError,
        ReleaseVerificationError,
        TestGateError,
    ) as exc:
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write(f"release verification failed: {exc}\n")
        return 2


def load_release_policies(root: Path) -> ReleasePolicies:
    """Load the three closed candidate-side Task 8 policy descriptors."""
    return ReleasePolicies(
        dependency_risk=load_dependency_risk_policy(
            root / "dependency-risk-policy.json"
        ),
        trusted_sources=load_trusted_package_sources_policy(
            root / "trusted-package-sources.json"
        ),
        controller=load_release_controller_policy(
            root / "release-controller-policy.json"
        ),
    )


@dataclass(frozen=True, slots=True)
class GateCommand:
    """One exact shell-free release checker invocation."""

    name: str
    executable: Path
    version: str
    argv: tuple[str, ...]
    cwd: Path
    environment: tuple[tuple[str, str], ...]
    subject_kind: str
    subject_digest: str
    timeout_seconds: float
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    finding_exit_codes: frozenset[int]
    tool_error_exit_codes: frozenset[int]
    result_schema: str
    offline_evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject unbound identities, ambient state, and scanner bypasses."""
        self._validate_identity()
        self._validate_execution_policy()
        self._validate_environment()
        self._validate_arguments()

    def _validate_identity(self) -> None:
        if not self.name or self.name.strip() != self.name:
            msg = "gate command name is invalid"
            raise ReleaseVerificationError(msg)
        if not self.executable.is_absolute():
            msg = "gate command requires an absolute executable"
            raise ReleaseVerificationError(msg)
        if not self.argv or self.argv[0] != self.executable.as_posix():
            msg = "gate command argv executable does not match"
            raise ReleaseVerificationError(msg)
        if not self.cwd.is_absolute():
            msg = "gate command requires an absolute working directory"
            raise ReleaseVerificationError(msg)
        if _EXACT_VERSION_PATTERN.fullmatch(self.version) is None:
            msg = "gate command requires an exact tool version"
            raise ReleaseVerificationError(msg)
        if self.subject_kind not in _SUBJECT_KINDS:
            msg = "gate command subject kind is not closed"
            raise ReleaseVerificationError(msg)
        if _SHA256_PATTERN.fullmatch(self.subject_digest) is None:
            msg = "gate command subject digest is invalid"
            raise ReleaseVerificationError(msg)

    def _validate_execution_policy(self) -> None:
        if (
            self.timeout_seconds <= 0
            or self.stdout_limit_bytes <= 0
            or self.stderr_limit_bytes <= 0
        ):
            msg = "gate command execution limits are invalid"
            raise ReleaseVerificationError(msg)
        if self.finding_exit_codes & self.tool_error_exit_codes:
            msg = "gate command exit semantics overlap"
            raise ReleaseVerificationError(msg)
        if (
            not self.finding_exit_codes
            or not self.tool_error_exit_codes
            or 0 in self.finding_exit_codes
            or 0 in self.tool_error_exit_codes
            or any(
                code < 0 or code > _MAX_PROCESS_EXIT_CODE
                for code in self.finding_exit_codes | self.tool_error_exit_codes
            )
        ):
            msg = "gate command exit semantics are invalid"
            raise ReleaseVerificationError(msg)
        if self.result_schema != "nplg.release.gate-result.v1":
            msg = "gate command result schema is not accepted"
            raise ReleaseVerificationError(msg)
        if not self.offline_evidence or any(
            _SHA256_PATTERN.fullmatch(item) is None for item in self.offline_evidence
        ):
            msg = "gate command offline evidence is invalid"
            raise ReleaseVerificationError(msg)

    def _validate_environment(self) -> None:
        environment_names = tuple(name for name, _value in self.environment)
        if len(environment_names) != len(set(environment_names)):
            msg = "gate command has duplicate environment names"
            raise ReleaseVerificationError(msg)
        if any(
            any(part in name.upper() for part in _AMBIENT_NAME_PARTS)
            for name in environment_names
        ):
            msg = "gate command contains ambient credential or network state"
            raise ReleaseVerificationError(msg)

    def _validate_arguments(self) -> None:
        lowered = tuple(argument.casefold() for argument in self.argv[1:])
        if any(
            argument in _UNSAFE_ARGUMENTS
            or argument.startswith(("--exit-code=0", "--skip-rule", "--skip-check"))
            for argument in lowered
        ):
            msg = "gate command contains an unsafe scanner argument"
            raise ReleaseVerificationError(msg)
        if self.name != "test-gate" and not any(
            argument in {"--json", "json"} or argument.endswith(("=json", "json"))
            for argument in lowered
        ):
            msg = "gate command does not require a JSON result"
            raise ReleaseVerificationError(msg)


@dataclass(frozen=True, slots=True)
class GateResult:
    """Digest-bound result for one completed gate command."""

    name: str
    argv: tuple[str, ...]
    exit_code: int
    duration_seconds: float
    tool_version: str
    subject_digest: str
    offline_evidence: tuple[str, ...]
    stdout_sha256: str
    stderr_sha256: str
    evidence_digest: str
    verdict: GateVerdict


class CommandRunner(Protocol):
    """Injected boundary for an exact bounded gate command."""

    def __call__(self, command: GateCommand) -> ChildResult:
        """Execute one command without a shell and return bounded byte streams."""
        ...


class SystemCommandRunner:
    """Execute GateCommand values through the accepted bounded-process seam."""

    def __call__(self, command: GateCommand) -> ChildResult:
        """Run one closed command with bounded time and byte streams."""
        return run_bounded_process(
            command.argv,
            cwd=command.cwd,
            environment=dict(command.environment),
            limits=ProcessLimits(
                command.timeout_seconds,
                command.stdout_limit_bytes,
                command.stderr_limit_bytes,
            ),
        )


def _valid_success_evidence(command: GateCommand, completed: ChildResult) -> bool:
    """Validate a zero-exit tool result against its exact success contract."""
    if command.name == "mypy":
        valid = completed.stdout in (b"", b"\n") and completed.stderr == b""
    elif command.name == "pyright":
        valid = False
        if completed.stderr != b"":
            valid = False
        else:
            try:
                _ = _PyrightSuccess.model_validate_json(
                    completed.stdout,
                    strict=True,
                )
            except ValidationError:
                valid = False
            else:
                valid = True
    elif not completed.stdout:
        valid = False
    else:
        try:
            parsed = load_json_value(completed.stdout)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            valid = False
        else:
            valid = isinstance(parsed, (dict, list))
    return valid


def run_gate_battery(
    commands: Sequence[GateCommand],
    runner: CommandRunner,
    *,
    monotonic: Callable[[], float],
) -> tuple[GateResult, ...]:
    """Run the exact command battery in order, stopping at the first failure."""
    results: list[GateResult] = []
    for command in commands:
        started = monotonic()
        completed = runner(command)
        duration = monotonic() - started
        if completed.returncode == 0 and _valid_success_evidence(command, completed):
            verdict: GateVerdict = "passed"
        elif completed.returncode in command.finding_exit_codes:
            verdict = "findings"
        else:
            verdict = "tool_error"
        stdout_digest = hashlib.sha256(completed.stdout).hexdigest()
        stderr_digest = hashlib.sha256(completed.stderr).hexdigest()
        evidence = {
            "argv": list(command.argv),
            "duration_seconds": duration,
            "exit_code": completed.returncode,
            "name": command.name,
            "offline_evidence": list(command.offline_evidence),
            "stderr_sha256": stderr_digest,
            "stdout_sha256": stdout_digest,
            "subject_digest": command.subject_digest,
            "tool_version": command.version,
            "verdict": verdict,
        }
        evidence_digest = hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        results.append(
            GateResult(
                name=command.name,
                argv=command.argv,
                exit_code=completed.returncode,
                duration_seconds=duration,
                tool_version=command.version,
                subject_digest=command.subject_digest,
                offline_evidence=command.offline_evidence,
                stdout_sha256=stdout_digest,
                stderr_sha256=stderr_digest,
                evidence_digest=evidence_digest,
                verdict=verdict,
            )
        )
        if verdict != "passed":
            break
    return tuple(results)


if __name__ == "__main__":
    raise SystemExit(cli())
