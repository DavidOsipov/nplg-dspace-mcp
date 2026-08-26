# Copyright (c) 2026 David Osipov
"""Candidate-side release evidence validation and local gate orchestration."""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.metadata
import json
import os
import re
import stat
import sys
import sysconfig
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
from scripts.private_recovery_contract import (
    PrivateRecoveryPolicy,
    load_private_recovery_policy,
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
    ExternalGateRegistry,
    SystemGit,
    TestGateError,
    bind_external_snapshot,
    capture_source_snapshot,
    create_external_output,
    materialize_snapshot,
    parse_external_gate_registry,
    registered_worktrees,
    stable_snapshot_file,
)

type GateVerdict = Literal["passed", "findings", "tool_error"]


_MAX_PROCESS_EXIT_CODE = 255
_GIT_EXECUTABLE = "/usr/bin/git"
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EXACT_VERSION_PATTERN = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?\Z")
_EXPECTED_PRIVATE_RECOVERY_POLICY_SHA256 = (
    "sha256:6a9f6786479f139129f57c95d18820f55dc192a44d7d32d6ce2a385fe325bbf3"
)
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
_OPERATION_CONTRACT = (
    (
        "candidate-battery",
        ("alpic-metadata", "private-full"),
        "offline-candidate-execution",
        False,
        False,
        ("CandidateBatteryResult.v2",),
        (0, 64, 70, 75),
    ),
    (
        "external-gate",
        ("alpic-metadata", "private-full"),
        "brokered-external-proof",
        False,
        False,
        ("ExternalGateResult.v2",),
        (0, 64, 70, 75),
    ),
    (
        "prepare",
        ("alpic-metadata", "private-full"),
        "protected-ledger",
        False,
        False,
        ("CandidatePreparation.v2",),
        (0, 64, 70, 75),
    ),
    (
        "staging-proof",
        ("alpic-metadata",),
        "provider-staging-deployment",
        False,
        True,
        ("StagingProofResult.v2",),
        (0, 20, 21, 64, 70, 75),
    ),
    (
        "reconcile-staging",
        ("alpic-metadata",),
        "protected-ledger-reconciliation",
        True,
        True,
        ("StagingReconciliationResult.v2",),
        (0, 22, 23, 64, 70, 75),
    ),
    (
        "finalize",
        ("alpic-metadata", "private-full"),
        "protected-ledger-publication",
        False,
        False,
        ("CandidateEvidenceBundle.v2",),
        (0, 64, 70, 75),
    ),
    (
        "custody",
        ("alpic-metadata", "private-full"),
        "immutable-custody-upload",
        False,
        True,
        (
            "CustodyAttemptResult.v2",
            "CandidateBundleCustodyReceipt.v2",
            "FinalDecisionCustodyReceipt.v2",
        ),
        (0, 20, 21, 64, 70, 75),
    ),
    (
        "reconcile-custody",
        ("alpic-metadata", "private-full"),
        "protected-ledger-reconciliation",
        True,
        True,
        (
            "CustodyReconciliationResult.v2",
            "CandidateBundleCustodyReceipt.v2",
            "FinalDecisionCustodyReceipt.v2",
        ),
        (0, 22, 23, 64, 70, 75),
    ),
    (
        "attestation-workspace",
        ("alpic-metadata", "private-full"),
        "attestation-workspace-materialization",
        False,
        False,
        ("AttestationWorkspaceHandoff.v2",),
        (0, 64, 70, 75),
    ),
    (
        "commit-attestation",
        ("alpic-metadata", "private-full"),
        "git-attestation-commit",
        False,
        True,
        ("AttestationCommitResult.v2",),
        (0, 64, 70, 75),
    ),
    (
        "attest",
        ("alpic-metadata", "private-full"),
        "structural-attestation",
        False,
        False,
        ("AttestationVerdict.v2",),
        (0, 64, 70, 75),
    ),
    (
        "eligibility",
        ("alpic-metadata", "private-full"),
        "public-readiness-decision",
        False,
        False,
        (
            "ReleaseEligibilityVerdict.v2",
            "AsvsL2ConformanceVerdict.v2",
            "EligibilityGateRecord.v2",
        ),
        (0, 24, 64, 70, 75),
    ),
    (
        "cleanup-run",
        ("alpic-metadata", "private-full"),
        "scoped-destructive-cleanup",
        False,
        True,
        ("CleanupResult.v2",),
        (0, 64, 70, 75),
    ),
)
_LAUNCHER_CONTRACT = (
    (
        "initialize-run",
        "initialization-only",
        "RunDescriptor.v2",
        (0, 64, 70, 75),
    ),
    (
        "run-operation",
        "one-manifest-operation",
        "OperationResult.v2",
        (0, 20, 21, 22, 23, 24, 64, 70, 75),
    ),
    (
        "run-through",
        "contiguous-manifest-range",
        "ThroughResult.v2",
        (0, 20, 21, 22, 23, 24, 64, 70, 75),
    ),
    (
        "resume-run",
        "descriptor-selected-recovery",
        "ResumeResult.v2",
        (0, 20, 21, 22, 23, 24, 64, 70, 75),
    ),
)
_UTILITY_CONTRACT = (
    (
        "validate-output-parent",
        "--path ABSOLUTE_NEW_PATH --parent-mode 0700 --owner PROTECTED_UID",
        "validated-output-parent.v1",
        True,
    ),
    (
        "validate-output-parents",
        "--paths-json CLOSED_PATH_ARRAY --disjoint-from WORKTREE_SET",
        "validated-output-parents.v1",
        True,
    ),
    (
        "capture-alpic",
        (
            "--tool-root PATH --cwd VERIFIED_MINIMAL_DEPLOY_PACK --stdout PATH "
            "--stderr PATH --timeout-seconds N --max-output-bytes N -- ALPIC_ARGS"
        ),
        "bounded-alpic-capture.v1",
        True,
    ),
)
_EXIT_CONTRACT = (
    (0, "named-target-durably-complete"),
    (20, "external-delivery-unknown"),
    (21, "proved-pre-side-effect-failure"),
    (22, "reconciled-absent"),
    (23, "reconciliation-ambiguous"),
    (24, "gate-negative-chain-custodied"),
    (64, "pre-mutation-schema-authority-or-policy-rejection"),
    (70, "proved-pre-mutation-internal-failure"),
    (75, "durable-incomplete-recovery-required"),
)
_EXTERNAL_GATE_CONTRACT = (
    (
        "common.nplg-live-canary",
        "live.nplg-bound-endpoint.v2",
        ("alpic-metadata", "private-full"),
        "live",
        60,
        "nplg-live-canary.v2",
    ),
    (
        "private-full.edge-http",
        "staging.private-full-edge.v2",
        ("private-full",),
        "staging",
        1800,
        "private-edge-proof.v2",
    ),
    (
        "private-full.pdf-worker-container",
        "container.pdf-worker.v2",
        ("private-full",),
        "container",
        300,
        "container-proof.v2",
    ),
    (
        "private-full.pdf-worker-write-quota",
        "container.pdf-worker-quota.v2",
        ("private-full",),
        "container",
        300,
        "worker-quota-proof.v2",
    ),
    (
        "private-full.recovery-proof",
        "container.private-full-recovery.v2",
        ("private-full",),
        "container",
        900,
        "recovery-proof.v2",
    ),
    (
        "private-full.scanner-container",
        "container.scanner.v2",
        ("private-full",),
        "container",
        300,
        "container-proof.v2",
    ),
)
_METADATA_OPERATION_IDS = tuple(item[0] for item in _OPERATION_CONTRACT)
_PRIVATE_OPERATION_IDS = tuple(
    item[0]
    for item in _OPERATION_CONTRACT
    if item[0] not in {"staging-proof", "reconcile-staging"}
)
_PROFILE_CONTRACT = (
    (
        "alpic-metadata",
        _METADATA_OPERATION_IDS,
        ("common.nplg-live-canary",),
        ("alpic-deploy-pack", "python-sdist", "python-wheel"),
        "common-live-plus-exactly-one-staging-or-reconciliation",
        1,
        False,
        True,
    ),
    (
        "private-full",
        _PRIVATE_OPERATION_IDS,
        tuple(item[0] for item in _EXTERNAL_GATE_CONTRACT),
        (
            "pdf-worker-image",
            "private-app-image",
            "private-edge-image",
            "python-sdist",
            "python-wheel",
            "scanner-image",
        ),
        "common-live-plus-five-private-proofs",
        0,
        True,
        False,
    ),
)
_RECEIPT_CASE_CLASSES = ("adversarial", "fault", "negative", "property", "recovery")
_COMMON_BINDING_FIELDS = (
    "candidate_sha256",
    "candidate_tree_sha256",
    "run_id",
    "profile",
    "manifest_digest",
    "controller_authority_digest",
    "controller_revision",
    "controller_policy_digest",
    "controller_isolation_digest",
    "provisioning_receipt_digest",
)
_COMMON_OPERATION_OPTIONS = (
    ("--provisioning-receipt", "absolute-existing-file", None),
    ("--run-descriptor-json", "absolute-existing-file", None),
)
_OPERATION_EXTRA_OPTIONS = {
    "candidate-battery": (
        ("--candidate-battery-result-json", "absolute-new-file", None),
    ),
    "external-gate": (
        ("--external-gate-id", "identifier", None),
        ("--external-gate-result-json", "absolute-new-file", None),
    ),
    "prepare": (
        ("--candidate-battery-result-json", "absolute-existing-file", None),
        ("--candidate-preparation-json", "absolute-new-file", None),
    ),
    "staging-proof": (
        ("--candidate-preparation-json", "absolute-existing-file", None),
        ("--staging-proof-json", "absolute-new-file", None),
        ("--authorize-staging-deploy", "switch", None),
    ),
    "reconcile-staging": (
        ("--candidate-preparation-json", "absolute-existing-file", None),
        ("--staging-reconciliation-json", "absolute-new-file", None),
        ("--authorize-staging-read", "switch", None),
    ),
    "finalize": (
        ("--candidate-preparation-json", "absolute-existing-file", None),
        ("--candidate-bundle-json", "absolute-new-file", None),
    ),
    "custody": (
        ("--custody-attempt-json", "absolute-new-file", None),
        ("--custody-receipt-json", "absolute-new-file", None),
        ("--authorize-custody-upload", "switch", None),
    ),
    "reconcile-custody": (
        ("--custody-reconciliation-json", "absolute-new-file", None),
        ("--custody-receipt-json", "absolute-new-file", None),
        ("--authorize-custody-read", "switch", None),
    ),
    "attestation-workspace": (
        ("--attestation-handoff-json", "absolute-new-file", None),
    ),
    "commit-attestation": (
        ("--attestation-handoff-json", "absolute-existing-file", None),
        ("--message", "nonempty-text", None),
        ("--authorize-commit", "switch", None),
    ),
    "attest": (("--attestation-verdict-json", "absolute-new-file", None),),
    "eligibility": (
        ("--release-eligibility-verdict-json", "absolute-new-file", None),
        ("--asvs-l2-conformance-verdict-json", "absolute-new-file", None),
        ("--eligibility-gate-record-json", "absolute-new-file", None),
        ("--require-eligible", "switch", None),
        ("--require-asvs-l2", "switch", None),
    ),
    "cleanup-run": (
        ("--cleanup-journal-json", "absolute-new-file", None),
        ("--cleanup-result-json", "absolute-new-file", None),
        ("--authorize-cleanup", "switch", None),
    ),
}
_LAUNCHER_OPTIONS = {
    "initialize-run": (
        ("--provisioning-receipt", "absolute-existing-file", None),
        ("--controller-policy", "absolute-existing-file", None),
        ("--repository-root", "absolute-directory", None),
        ("--candidate", "git-object", None),
        ("--profile", "release-profile", None),
        ("--profile-inputs-json", "closed-json-object", None),
        ("--network-broker-descriptor", "absolute-existing-file", None),
        ("--custody-authority-descriptor", "absolute-existing-file", None),
        ("--run-parent", "absolute-directory", None),
        ("--initialization-journal-json", "absolute-new-file", None),
        ("--run-descriptor-json", "absolute-new-file", None),
        ("--authorize-run-root", "switch", None),
    ),
    "run-operation": (
        ("--provisioning-receipt", "absolute-existing-file", None),
        ("--run-descriptor-json", "absolute-existing-file", None),
        ("--operation-request-json", "closed-json-object", None),
    ),
    "run-through": (
        ("--provisioning-receipt", "absolute-existing-file", None),
        ("--run-descriptor-json", "absolute-existing-file", None),
        ("--range-request-json", "closed-json-object", None),
    ),
    "resume-run": (
        ("--provisioning-receipt", "absolute-existing-file", None),
        ("--run-descriptor-json", "absolute-existing-file", None),
        ("--resume-request-json", "closed-json-object", None),
    ),
}
_UTILITY_OPTIONS = {
    "validate-output-parent": (
        ("--path", "absolute-new-file", None),
        ("--parent-mode", "literal", "0700"),
        ("--owner", "identifier", None),
    ),
    "validate-output-parents": (
        ("--paths-json", "closed-json-array", None),
        ("--disjoint-from", "closed-json-array", None),
    ),
    "capture-alpic": (
        ("--tool-root", "absolute-directory", None),
        ("--cwd", "absolute-directory", None),
        ("--stdout", "absolute-new-file", None),
        ("--stderr", "absolute-new-file", None),
        ("--timeout-seconds", "positive-integer", None),
        ("--max-output-bytes", "positive-integer", None),
        ("--alpic-args-json", "closed-alpic-argv", None),
    ),
}
_OPERATION_INPUT_FIELDS = dict.fromkeys(
    _METADATA_OPERATION_IDS,
    (*_COMMON_BINDING_FIELDS, "operation_request"),
)
_LAUNCHER_INPUT_FIELDS = {
    launcher_id: (*_COMMON_BINDING_FIELDS, "launcher_request")
    for launcher_id, *_rest in _LAUNCHER_CONTRACT
}
_UTILITY_INPUT_FIELDS = {
    utility_id: (
        "controller_authority_digest",
        "controller_revision",
        "utility_request",
    )
    for utility_id, *_rest in _UTILITY_CONTRACT
}
_RESULT_FIELDS = (*_COMMON_BINDING_FIELDS, "result_payload", "result_digest")
_UTILITY_RESULT_FIELDS = (
    "controller_authority_digest",
    "controller_revision",
    "result_payload",
    "result_digest",
)


class ReleaseVerificationError(RuntimeError):
    """Raised when candidate-side release evidence fails closed."""


def _fail(message: str) -> NoReturn:
    raise ReleaseVerificationError(message)


def _fail_from(message: str, cause: BaseException) -> NoReturn:
    raise ReleaseVerificationError(message) from cause


def _unsafe_command_text(value: str) -> bool:
    return any(token in value for token in ("\x00", "\n", "\r", "$", "`", ";"))


class _StrictModel(BaseModel):
    """Closed, immutable, non-coercing release-policy boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


type ReleaseProfile = Literal["alpic-metadata", "private-full"]
type OperationId = Literal[
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
]
type LauncherId = Literal[
    "initialize-run",
    "run-operation",
    "run-through",
    "resume-run",
]


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


class _BanditMetric(_StrictModel):
    """Exact non-negative metric counters emitted by Bandit 1.9.4."""

    confidence_high: int = Field(alias="CONFIDENCE.HIGH", ge=0)
    confidence_low: int = Field(alias="CONFIDENCE.LOW", ge=0)
    confidence_medium: int = Field(alias="CONFIDENCE.MEDIUM", ge=0)
    confidence_undefined: int = Field(alias="CONFIDENCE.UNDEFINED", ge=0)
    severity_high: int = Field(alias="SEVERITY.HIGH", ge=0)
    severity_low: int = Field(alias="SEVERITY.LOW", ge=0)
    severity_medium: int = Field(alias="SEVERITY.MEDIUM", ge=0)
    severity_undefined: int = Field(alias="SEVERITY.UNDEFINED", ge=0)
    lines_of_code: int = Field(alias="loc", ge=0)
    nosec: int = Field(ge=0)
    skipped_tests: int = Field(ge=0)


class _BanditSuccess(_StrictModel):
    """Closed clean-result schema for Bandit 1.9.4 JSON output."""

    errors: tuple[object, ...] = Field(max_length=0)
    generated_at: str = Field(min_length=1, max_length=64)
    metrics: dict[str, _BanditMetric] = Field(min_length=1, max_length=100_001)
    results: tuple[object, ...] = Field(max_length=0)

    @model_validator(mode="after")
    def _requires_total_metrics(self) -> _BanditSuccess:
        if "_totals" not in self.metrics:
            msg = "Bandit success has no total metrics"
            raise ValueError(msg)
        return self


class _PipAuditDependency(_StrictModel):
    """One fully resolved dependency with no known vulnerabilities."""

    name: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=256)
    vulns: tuple[object, ...] = Field(max_length=0)


class _PipAuditSuccess(_StrictModel):
    """Closed clean-result schema for pip-audit 2.10.1 JSON output."""

    dependencies: tuple[_PipAuditDependency, ...] = Field(max_length=100_000)
    fixes: tuple[object, ...] = Field(max_length=0)


class _CycloneDxTools(_StrictModel):
    components: tuple[dict[str, object], ...] = Field(min_length=1, max_length=1024)


class _CycloneDxMetadata(_StrictModel):
    timestamp: str = Field(min_length=1, max_length=64)
    tools: _CycloneDxTools


class _CycloneDxSuccess(_StrictModel):
    """Closed top-level contract for CycloneDX 1.6 environment output."""

    schema_uri: Literal["http://cyclonedx.org/schema/bom-1.6.schema.json"] = Field(
        alias="$schema"
    )
    bom_format: Literal["CycloneDX"] = Field(alias="bomFormat")
    components: tuple[dict[str, object], ...] = Field(
        min_length=1,
        max_length=100_000,
    )
    dependencies: tuple[dict[str, object], ...] = Field(max_length=100_000)
    metadata: _CycloneDxMetadata
    serial_number: str = Field(
        alias="serialNumber",
        pattern=r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    spec_version: Literal["1.6"] = Field(alias="specVersion")
    version: Literal[1]


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


class CommandToolContract(_StrictModel):
    """Exact interface/version/lock fields for one protected command."""

    tool_id: Literal["nplg-release-controller"]
    interface_version: Literal["2.0.0"]
    version_probe: tuple[Literal["--version-json"]]
    version_output_schema: Literal["ProtectedControllerVersion.v2"]
    lock_digest_field: Literal["controller_dependency_lock_sha256"]
    lock_source: Literal["ProtectedControllerProvisioningReceipt.v2"]
    require_exact_lock_digest: Literal[True]


class ArgvOptionContract(_StrictModel):
    """One ordered, typed option in a shell-free command contract."""

    flag: str = Field(pattern=r"^--[a-z][a-z0-9-]{0,63}$")
    value_kind: Literal[
        "absolute-directory",
        "absolute-existing-file",
        "absolute-new-file",
        "closed-alpic-argv",
        "closed-json-array",
        "closed-json-object",
        "git-object",
        "identifier",
        "literal",
        "nonempty-text",
        "positive-integer",
        "release-profile",
        "switch",
    ]
    literal_value: str | None

    @model_validator(mode="after")
    def _literal_shape(self) -> ArgvOptionContract:
        if (self.value_kind == "literal") != (self.literal_value is not None):
            msg = "argv literal option shape is inconsistent"
            raise ValueError(msg)
        if self.literal_value is not None and (
            not self.literal_value or _unsafe_command_text(self.literal_value)
        ):
            msg = "argv literal option is unsafe"
            raise ValueError(msg)
        return self


class StructuredArgvContract(_StrictModel):
    """Closed ordered argv grammar with no shell or arbitrary passthrough."""

    contract_kind: Literal["operation", "launcher", "utility"]
    subcommand: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    required_options: tuple[ArgvOptionContract, ...] = Field(min_length=1)
    allow_unknown_options: Literal[False]
    allow_passthrough: Literal[False]
    allow_shell: Literal[False]

    @model_validator(mode="after")
    def _closed_options(self) -> StructuredArgvContract:
        flags = tuple(option.flag for option in self.required_options)
        if len(flags) != len(set(flags)):
            msg = "argv contract contains a duplicate option"
            raise ValueError(msg)
        return self


class InputPayloadContract(_StrictModel):
    """Closed input-payload expectation for one protected command."""

    contract_kind: Literal["input"]
    schema_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9.-]{0,127}$")
    schema_version: Literal["1.0", "2.0"]
    required_fields: tuple[str, ...] = Field(min_length=1)
    allow_unknown_fields: Literal[False]

    @model_validator(mode="after")
    def _unique_fields(self) -> InputPayloadContract:
        if len(self.required_fields) != len(set(self.required_fields)):
            msg = "input contract fields must be unique"
            raise ValueError(msg)
        return self


class OutputPayloadContract(_StrictModel):
    """Closed complete-result expectation; digests alone never satisfy it."""

    contract_kind: Literal["output"]
    schema_ids: tuple[str, ...] = Field(min_length=1)
    schema_version: Literal["1.0", "2.0"]
    required_fields: tuple[str, ...] = Field(min_length=1)
    allow_unknown_fields: Literal[False]
    allow_digest_only: Literal[False]

    @model_validator(mode="after")
    def _unique_output_shape(self) -> OutputPayloadContract:
        if (
            len(self.schema_ids) != len(set(self.schema_ids))
            or len(self.required_fields) != len(set(self.required_fields))
            or any(
                re.fullmatch(r"[A-Za-z][A-Za-z0-9.-]{0,127}", schema_id) is None
                for schema_id in self.schema_ids
            )
        ):
            msg = "output contract schemas and fields must be unique and valid"
            raise ValueError(msg)
        return self


class ReleaseOperationSpec(_StrictModel):
    """One expected protected operation interface, never its implementation."""

    operation_id: OperationId
    profiles: tuple[ReleaseProfile, ...]
    effect: Literal[
        "offline-candidate-execution",
        "brokered-external-proof",
        "protected-ledger",
        "provider-staging-deployment",
        "protected-ledger-reconciliation",
        "protected-ledger-publication",
        "immutable-custody-upload",
        "attestation-workspace-materialization",
        "git-attestation-commit",
        "structural-attestation",
        "public-readiness-decision",
        "scoped-destructive-cleanup",
    ]
    recovery_only: bool
    requires_explicit_authorization: bool
    result_schemas: tuple[str, ...]
    exit_codes: tuple[int, ...]
    tool: CommandToolContract
    argv: StructuredArgvContract
    input_contract: InputPayloadContract
    output_contract: OutputPayloadContract


class LauncherCommandSpec(_StrictModel):
    """One stateful top-level protected launcher command contract."""

    command_id: LauncherId
    dispatch: Literal[
        "initialization-only",
        "one-manifest-operation",
        "contiguous-manifest-range",
        "descriptor-selected-recovery",
    ]
    result_schema: str
    exit_codes: tuple[int, ...]
    tool: CommandToolContract
    argv: StructuredArgvContract
    input_contract: InputPayloadContract
    output_contract: OutputPayloadContract


class ReadOnlyUtilitySpec(_StrictModel):
    """One non-stateful helper/preflight utility contract."""

    command_id: Literal[
        "validate-output-parent",
        "validate-output-parents",
        "capture-alpic",
    ]
    argv_schema: str
    output_schema: str
    read_only: Literal[True]
    tool: CommandToolContract
    argv: StructuredArgvContract
    input_contract: InputPayloadContract
    output_contract: OutputPayloadContract


class LauncherExitSpec(_StrictModel):
    """One non-conflatable launcher exit meaning."""

    code: Literal[0, 20, 21, 22, 23, 24, 64, 70, 75]
    meaning: str


class ExternalGateSpec(_StrictModel):
    """One registry-owned protected operational discriminator."""

    gate_id: Literal[
        "common.nplg-live-canary",
        "private-full.edge-http",
        "private-full.pdf-worker-container",
        "private-full.pdf-worker-write-quota",
        "private-full.recovery-proof",
        "private-full.scanner-container",
    ]
    command_id: str
    profiles: tuple[ReleaseProfile, ...]
    kind: Literal["live", "staging", "container"]
    timeout_seconds: int = Field(gt=0)
    result_schema: str


class ReleaseProfileSpec(_StrictModel):
    """Exact operation, subject, and operational-proof selection for a profile."""

    profile_id: ReleaseProfile
    operation_ids: tuple[OperationId, ...]
    external_gate_ids: tuple[str, ...]
    subject_roles: tuple[str, ...]
    finalize_inputs: Literal[
        "common-live-plus-exactly-one-staging-or-reconciliation",
        "common-live-plus-five-private-proofs",
    ]
    task21_staging_imports: Literal[0, 1]
    container_runtime_required: bool
    private_nonconstruction_required: bool


class ContractSensitivityPolicy(_StrictModel):
    """Minimum candidate-side expectation for protected-controller TDD receipts."""

    candidate_battery_environment: Literal["offline-no-secret"]
    required_case_classes: tuple[
        Literal["adversarial", "fault", "negative", "property", "recovery"], ...
    ]
    replaced_suite_must_fail: Literal[True]
    empty_suite_must_fail: Literal[True]
    always_pass_suite_must_fail: Literal[True]
    source_mutation_must_fail: Literal[True]
    minimum_changed_line_coverage_percent: Literal[95]
    minimum_changed_branch_coverage_percent: Literal[95]
    surviving_mutants_allowed: Literal[0]
    conditional_skips_allowed: Literal[0]
    evidence_inside_candidate_allowed: Literal[False]

    @model_validator(mode="after")
    def _closed_case_classes(self) -> ContractSensitivityPolicy:
        if self.required_case_classes != _RECEIPT_CASE_CLASSES:
            msg = "release command manifest case classes are not closed"
            raise ValueError(msg)
        return self


class ReleaseCommandManifest(_StrictModel):
    """Candidate-side expected contract for an independently protected controller."""

    schema_version: Literal[1]
    contract_id: Literal["nplg.release-command-manifest.v1"]
    controller_authority: Literal["separately-protected-external"]
    candidate_implements_controller: Literal[False]
    operations: tuple[ReleaseOperationSpec, ...]
    launcher_commands: tuple[LauncherCommandSpec, ...]
    utilities: tuple[ReadOnlyUtilitySpec, ...]
    exit_semantics: tuple[LauncherExitSpec, ...]
    external_gates: tuple[ExternalGateSpec, ...]
    profiles: tuple[ReleaseProfileSpec, ...]
    sensitivity_policy: ContractSensitivityPolicy
    missing_authority_status: Literal["PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE"]
    terminal_verdict: Literal["do_not_release"]

    @model_validator(mode="after")
    def _closed_contract(self) -> ReleaseCommandManifest:
        operations = tuple(
            (
                item.operation_id,
                item.profiles,
                item.effect,
                item.recovery_only,
                item.requires_explicit_authorization,
                item.result_schemas,
                item.exit_codes,
            )
            for item in self.operations
        )
        launchers = tuple(
            (item.command_id, item.dispatch, item.result_schema, item.exit_codes)
            for item in self.launcher_commands
        )
        utilities = tuple(
            (item.command_id, item.argv_schema, item.output_schema, item.read_only)
            for item in self.utilities
        )
        exits = tuple((item.code, item.meaning) for item in self.exit_semantics)
        external_gates = tuple(
            (
                item.gate_id,
                item.command_id,
                item.profiles,
                item.kind,
                item.timeout_seconds,
                item.result_schema,
            )
            for item in self.external_gates
        )
        profiles = tuple(
            (
                item.profile_id,
                item.operation_ids,
                item.external_gate_ids,
                item.subject_roles,
                item.finalize_inputs,
                item.task21_staging_imports,
                item.container_runtime_required,
                item.private_nonconstruction_required,
            )
            for item in self.profiles
        )
        operation_shapes = tuple(
            (
                item.operation_id,
                item.argv.contract_kind,
                item.argv.subcommand,
                tuple(
                    (option.flag, option.value_kind, option.literal_value)
                    for option in item.argv.required_options
                ),
                item.input_contract.schema_id,
                item.input_contract.schema_version,
                item.input_contract.required_fields,
                item.output_contract.schema_ids,
                item.output_contract.schema_version,
                item.output_contract.required_fields,
            )
            for item in self.operations
        )
        expected_operation_shapes = tuple(
            (
                operation_id,
                "operation",
                "run-operation",
                (
                    *_COMMON_OPERATION_OPTIONS,
                    ("--operation", "literal", operation_id),
                    *_OPERATION_EXTRA_OPTIONS[operation_id],
                ),
                f"{operation_id}.input.v2",
                "2.0",
                _OPERATION_INPUT_FIELDS[operation_id],
                result_schemas,
                "2.0",
                _RESULT_FIELDS,
            )
            for (
                operation_id,
                *_middle,
                result_schemas,
                _exit_codes,
            ) in _OPERATION_CONTRACT
        )
        launcher_shapes = tuple(
            (
                item.command_id,
                item.argv.contract_kind,
                item.argv.subcommand,
                tuple(
                    (option.flag, option.value_kind, option.literal_value)
                    for option in item.argv.required_options
                ),
                item.input_contract.schema_id,
                item.input_contract.schema_version,
                item.input_contract.required_fields,
                item.output_contract.schema_ids,
                item.output_contract.schema_version,
                item.output_contract.required_fields,
            )
            for item in self.launcher_commands
        )
        expected_launcher_shapes = tuple(
            (
                launcher_id,
                "launcher",
                launcher_id,
                _LAUNCHER_OPTIONS[launcher_id],
                f"{launcher_id}.input.v2",
                "2.0",
                _LAUNCHER_INPUT_FIELDS[launcher_id],
                (result_schema,),
                "2.0",
                _RESULT_FIELDS,
            )
            for launcher_id, _dispatch, result_schema, _exit_codes in _LAUNCHER_CONTRACT
        )
        utility_shapes = tuple(
            (
                item.command_id,
                item.argv.contract_kind,
                item.argv.subcommand,
                tuple(
                    (option.flag, option.value_kind, option.literal_value)
                    for option in item.argv.required_options
                ),
                item.input_contract.schema_id,
                item.input_contract.schema_version,
                item.input_contract.required_fields,
                item.output_contract.schema_ids,
                item.output_contract.schema_version,
                item.output_contract.required_fields,
            )
            for item in self.utilities
        )
        expected_utility_shapes = tuple(
            (
                utility_id,
                "utility",
                utility_id,
                _UTILITY_OPTIONS[utility_id],
                f"{utility_id}.input.v1",
                "1.0",
                _UTILITY_INPUT_FIELDS[utility_id],
                (output_schema,),
                "1.0",
                _UTILITY_RESULT_FIELDS,
            )
            for utility_id, _argv_schema, output_schema, _read_only in _UTILITY_CONTRACT
        )
        if (
            operations != _OPERATION_CONTRACT
            or launchers != _LAUNCHER_CONTRACT
            or utilities != _UTILITY_CONTRACT
            or exits != _EXIT_CONTRACT
            or external_gates != _EXTERNAL_GATE_CONTRACT
            or profiles != _PROFILE_CONTRACT
            or operation_shapes != expected_operation_shapes
            or launcher_shapes != expected_launcher_shapes
            or utility_shapes != expected_utility_shapes
        ):
            msg = "release command manifest differs from the closed expected contract"
            raise ValueError(msg)
        return self


class FakeTddReceipt(_StrictModel):
    """Candidate-side fake of one externally signed TDD receipt summary."""

    target_kind: Literal["operation", "launcher"]
    target_id: str
    red_exit: Literal[1]
    green_exit: Literal[0]
    refactor_exit: Literal[0]
    collected_tests: tuple[str, ...] = Field(min_length=1)
    case_classes: tuple[
        Literal["adversarial", "fault", "negative", "property", "recovery"], ...
    ]
    mutations_total: int = Field(ge=1)
    mutations_killed: int = Field(ge=0)
    source_diff_sha256: str
    integration_exit: Literal[0]
    protected_controller_signed: Literal[True]
    candidate_generated: Literal[False]
    completed_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def _complete_sensitive_receipt(self) -> FakeTddReceipt:
        if (
            not self.target_id
            or len(self.collected_tests) != len(set(self.collected_tests))
            or self.case_classes != _RECEIPT_CASE_CLASSES
            or self.mutations_killed != self.mutations_total
            or _SHA256_PATTERN.fullmatch(self.source_diff_sha256) is None
            or self.completed_at.utcoffset() != timedelta(0)
            or self.expires_at.utcoffset() != timedelta(0)
            or self.expires_at <= self.completed_at
        ):
            msg = "TDD receipt is incomplete, insensitive, or stale"
            raise ValueError(msg)
        return self


class FakeCriticalSuiteResult(_StrictModel):
    """Candidate-side fake proving failure sensitivity of the critical battery."""

    collected_tests: tuple[str, ...] = Field(min_length=1)
    replaced_suite_detected: Literal[True]
    empty_suite_detected: Literal[True]
    always_pass_suite_detected: Literal[True]
    source_mutation_detected: Literal[True]
    changed_line_coverage_percent: int = Field(ge=95, le=100)
    changed_branch_coverage_percent: int = Field(ge=95, le=100)
    surviving_mutants: Literal[0]
    conditional_skips: Literal[0]
    evidence_location: Literal["external-protected-custody"]

    @model_validator(mode="after")
    def _unique_tests(self) -> FakeCriticalSuiteResult:
        if len(self.collected_tests) != len(set(self.collected_tests)):
            msg = "critical suite collection is not unique"
            raise ValueError(msg)
        return self


class CandidateContractTranscript(_StrictModel):
    """Strict candidate fake; it never substitutes for signed controller evidence."""

    schema_version: Literal[1]
    profile: ReleaseProfile
    manifest_digest: str
    operation_receipts: tuple[FakeTddReceipt, ...]
    launcher_receipts: tuple[FakeTddReceipt, ...]
    external_gate_ids: tuple[str, ...]
    critical_suite: FakeCriticalSuiteResult

    @model_validator(mode="after")
    def _valid_digest(self) -> CandidateContractTranscript:
        if _SHA256_PATTERN.fullmatch(self.manifest_digest) is None:
            msg = "candidate contract transcript manifest digest is invalid"
            raise ValueError(msg)
        return self


@dataclass(frozen=True, slots=True)
class CandidateReleaseStatus:
    """Non-authoritative status emitted while protected authority is absent."""

    profile: ReleaseProfile
    local_status: Literal["PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE"]
    terminal_verdict: Literal["do_not_release"]
    release_ready: Literal[False]
    release_authorized: Literal[False]


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
    """Independently parsed candidate-side policies and controller contract."""

    dependency_risk: DependencyRiskPolicy
    trusted_sources: TrustedPackageSourcesPolicy
    controller: ReleaseControllerPolicy
    recovery: PrivateRecoveryPolicy
    external_gate_registry: ExternalGateRegistry
    commands: ReleaseCommandManifest


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


def _load_json_object(path: Path) -> bytes:
    """Preparse a JSON object for duplicate names before strict model parsing."""
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
    return raw


def _load_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    try:
        return model.model_validate_json(_load_json_object(path), strict=True)
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


def load_release_command_manifest(path: Path) -> ReleaseCommandManifest:
    """Load the exact candidate-side expectation for the protected controller."""
    try:
        return _load_model(path, ReleaseCommandManifest)
    except ReleaseVerificationError as exc:
        _fail_from("release command manifest rejected", exc)


def validate_external_gate_manifest_join(
    registry: ExternalGateRegistry,
    manifest: ReleaseCommandManifest,
) -> None:
    """Require independent gate policies to describe one identical inventory."""
    registry_contract = tuple(
        (
            gate.gate_id,
            gate.command_id,
            gate.profiles,
            gate.kind,
            gate.timeout_seconds,
            gate.result_schema,
        )
        for gate in registry.gates
    )
    manifest_contract = tuple(
        (
            gate.gate_id,
            gate.command_id,
            gate.profiles,
            gate.kind,
            gate.timeout_seconds,
            gate.result_schema,
        )
        for gate in manifest.external_gates
    )
    registry_profiles = tuple(
        (
            profile.profile_id,
            tuple(
                gate.gate_id
                for gate in registry.gates
                if profile.profile_id in gate.profiles
            ),
        )
        for profile in manifest.profiles
    )
    manifest_profiles = tuple(
        (profile.profile_id, profile.external_gate_ids) for profile in manifest.profiles
    )
    if registry_contract != manifest_contract or registry_profiles != manifest_profiles:
        _fail("external gate registry differs from release command manifest")


def release_command_manifest_digest(manifest: ReleaseCommandManifest) -> str:
    """Digest the canonical expected contract for external equality checks."""
    value = load_json_value(manifest.model_dump_json())
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def validate_candidate_contract_transcript(
    payload: bytes,
    *,
    manifest: ReleaseCommandManifest,
    now: datetime,
) -> CandidateContractTranscript:
    """Validate a failure-sensitive fake without granting release authority."""
    try:
        transcript = CandidateContractTranscript.model_validate_json(
            payload,
            strict=True,
        )
        if now.utcoffset() != timedelta(0):
            _fail("candidate contract transcript clock is not UTC")
        operation_ids = tuple(
            receipt.target_id for receipt in transcript.operation_receipts
        )
        launcher_ids = tuple(
            receipt.target_id for receipt in transcript.launcher_receipts
        )
        if (
            operation_ids != _METADATA_OPERATION_IDS
            or launcher_ids != tuple(item[0] for item in _LAUNCHER_CONTRACT)
            or any(
                receipt.target_kind != "operation"
                for receipt in transcript.operation_receipts
            )
            or any(
                receipt.target_kind != "launcher"
                for receipt in transcript.launcher_receipts
            )
            or transcript.manifest_digest != release_command_manifest_digest(manifest)
        ):
            _fail("candidate contract transcript receipt inventory is incomplete")
        profile = next(
            item for item in manifest.profiles if item.profile_id == transcript.profile
        )
        if transcript.external_gate_ids != profile.external_gate_ids:
            _fail("candidate contract transcript external gates do not match profile")
        receipts = (*transcript.operation_receipts, *transcript.launcher_receipts)
        if any(
            receipt.completed_at > now or receipt.expires_at <= now
            for receipt in receipts
        ):
            _fail("candidate contract transcript contains stale evidence")
    except (StopIteration, ValidationError, ReleaseVerificationError) as exc:
        _fail_from("candidate contract transcript rejected", exc)
    return transcript


def candidate_release_status(profile: ReleaseProfile) -> CandidateReleaseStatus:
    """Return the only candidate-local status while authority is unavailable."""
    if profile not in {"alpic-metadata", "private-full"}:
        _fail("release profile is outside the closed manifest")
    return CandidateReleaseStatus(
        profile=profile,
        local_status="PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE",
        terminal_verdict="do_not_release",
        release_ready=False,
        release_authorized=False,
    )


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


type _TrustedReleaseToolMode = Literal["module", "console"]


@dataclass(frozen=True, slots=True)
class _TrustedReleaseTool:
    """Pinned Python tool identity and its reviewed invocation boundary."""

    name: str
    module: str
    distribution: str
    version: str
    mode: _TrustedReleaseToolMode
    entry_name: str | None = None
    entry_value: str | None = None


_TRUSTED_RELEASE_TOOLS = (
    _TrustedReleaseTool("ruff", "ruff", "ruff", "0.16.3", "module"),
    _TrustedReleaseTool(
        "mypy",
        "mypy",
        "mypy",
        "2.3.1",
        "console",
        "mypy",
        "mypy.__main__:console_entry",
    ),
    _TrustedReleaseTool(
        "bandit",
        "bandit",
        "bandit",
        "1.9.4",
        "console",
        "bandit",
        "bandit.cli.main:main",
    ),
    _TrustedReleaseTool(
        "pip-audit",
        "pip_audit",
        "pip-audit",
        "2.10.1",
        "console",
        "pip-audit",
        "pip_audit._cli:audit",
    ),
    _TrustedReleaseTool(
        "cyclonedx",
        "cyclonedx_py",
        "cyclonedx-bom",
        "7.3.1",
        "console",
        "cyclonedx-py",
        "cyclonedx_py._internal.cli:run",
    ),
)
_TRUSTED_RELEASE_TOOL_DRIVER = r"""
import importlib
from importlib import metadata
import json
from pathlib import Path
import runpy
import sys

proof = json.loads(sys.argv[1])
if type(proof) is not list or len(proof) != 8:
    raise SystemExit(97)
(
    mode,
    module_name,
    distribution_name,
    expected_version,
    raw_origin,
    raw_purelib,
    entry_name,
    entry_value,
) = proof
if (
    mode not in ("module", "console")
    or not all(
        type(value) is str
        for value in (
            module_name,
            distribution_name,
            expected_version,
            raw_origin,
            raw_purelib,
        )
    )
    or (entry_name is not None and type(entry_name) is not str)
    or (entry_value is not None and type(entry_value) is not str)
):
    raise SystemExit(97)
if mode == "module" and (entry_name is not None or entry_value is not None):
    raise SystemExit(97)
if mode == "console" and (entry_name is None or entry_value is None):
    raise SystemExit(97)

site_packages = Path(raw_purelib).resolve(strict=True)
expected_origin = Path(raw_origin).resolve(strict=True)
candidate_root = Path.cwd().resolve(strict=True)
if site_packages not in expected_origin.parents:
    raise SystemExit(97)

def is_unreviewed_candidate_path(path):
    inside_candidate = path == candidate_root or candidate_root in path.parents
    inside_reviewed_purelib = path == site_packages or site_packages in path.parents
    return inside_candidate and not inside_reviewed_purelib

for item in sys.path:
    if item == "":
        raise SystemExit(97)
    resolved = Path(item).resolve(strict=False)
    if is_unreviewed_candidate_path(resolved):
        raise SystemExit(97)
sys.path.insert(0, site_packages.as_posix())

def reviewed_distribution():
    matches = tuple(
        metadata.distributions(
            name=distribution_name,
            path=[site_packages.as_posix()],
        )
    )
    if len(matches) != 1 or matches[0].version != expected_version:
        raise SystemExit(97)
    return matches[0]

distribution = reviewed_distribution()
tool = importlib.import_module(module_name)
expected_package_root = expected_origin.parent

def verify_loaded_tool():
    if sys.modules.get(module_name) is not tool:
        raise SystemExit(97)
    raw_file = getattr(tool, "__file__", None)
    specification = getattr(tool, "__spec__", None)
    specification_origin = getattr(specification, "origin", None)
    if type(raw_file) is not str or type(specification_origin) is not str:
        raise SystemExit(97)
    if (
        Path(raw_file).resolve(strict=True) != expected_origin
        or Path(specification_origin).resolve(strict=True) != expected_origin
    ):
        raise SystemExit(97)
    reviewed_distribution()
    for loaded_name, loaded_module in tuple(sys.modules.items()):
        if not loaded_name.startswith(module_name + "."):
            continue
        loaded_file = getattr(loaded_module, "__file__", None)
        if type(loaded_file) is not str:
            raise SystemExit(97)
        loaded_origin = Path(loaded_file).resolve(strict=True)
        if expected_package_root not in loaded_origin.parents:
            raise SystemExit(97)

verify_loaded_tool()
baseline_modules = frozenset(sys.modules)
arguments = sys.argv[2:]
returncode = None
try:
    if mode == "module":
        sys.argv = [module_name, *arguments]
        runpy.run_module(module_name, run_name="__main__", alter_sys=True)
    else:
        entries = tuple(
            item
            for item in distribution.entry_points
            if item.group == "console_scripts" and item.name == entry_name
        )
        if len(entries) != 1 or entries[0].value != entry_value:
            raise SystemExit(97)
        entry = entries[0].load()
        if not callable(entry):
            raise SystemExit(97)
        sys.argv = [entry_name, *arguments]
        returncode = entry()
except SystemExit as exc:
    returncode = exc.code

verify_loaded_tool()
for loaded_name in frozenset(sys.modules).difference(baseline_modules):
    loaded_file = getattr(sys.modules[loaded_name], "__file__", None)
    if type(loaded_file) is not str:
        continue
    loaded_origin = Path(loaded_file).resolve(strict=True)
    if is_unreviewed_candidate_path(loaded_origin):
        raise SystemExit(97)
if returncode is None:
    returncode = 0
if type(returncode) is not int:
    raise SystemExit(97)
raise SystemExit(returncode)
"""


@dataclass(frozen=True, slots=True)
class _PyrightRuntimeIdentity:
    """Reviewed Node and package evidence used for one Pyright execution."""

    node_sha256: str
    package: PyrightPackageIdentity

    @property
    def offline_evidence(self) -> tuple[str, ...]:
        return (self.node_sha256, *self.package.offline_evidence)


type _TrustedReleaseToolProof = tuple[
    _TrustedReleaseToolMode,
    str,
    str,
    str,
    str,
    str,
    str | None,
    str | None,
]


def _trusted_release_tool_proof(
    tool: _TrustedReleaseTool,
) -> _TrustedReleaseToolProof:
    """Resolve one pinned tool only from this interpreter's reviewed purelib."""
    try:
        raw_purelib = cast("object", sysconfig.get_path("purelib"))
        if not isinstance(raw_purelib, str):
            _fail("trusted release tool root is unavailable")
        site_packages = Path(raw_purelib).resolve(strict=True)
        distributions = tuple(
            importlib.metadata.distributions(
                name=tool.distribution,
                path=[site_packages.as_posix()],
            )
        )
        specification = importlib.machinery.PathFinder.find_spec(
            tool.module,
            [site_packages.as_posix()],
        )
    except (ImportError, OSError, TypeError) as exc:
        _fail_from("trusted release tool identity is unavailable", exc)
    if (
        len(distributions) != 1
        or distributions[0].version != tool.version
        or specification is None
        or specification.origin is None
    ):
        _fail("trusted release tool version or import origin is invalid")
    try:
        origin = Path(specification.origin).resolve(strict=True)
        origin_metadata = origin.lstat()
    except OSError as exc:
        _fail_from("trusted release tool import origin is unavailable", exc)
    if not stat.S_ISREG(origin_metadata.st_mode) or site_packages not in origin.parents:
        _fail("trusted release tool import origin is not a regular purelib file")
    entries = tuple(
        item
        for item in distributions[0].entry_points
        if item.group == "console_scripts" and item.name == tool.entry_name
    )
    if tool.mode == "console":
        if len(entries) != 1 or entries[0].value != tool.entry_value:
            _fail("trusted release tool entry point is invalid")
    elif entries or tool.entry_name is not None or tool.entry_value is not None:
        _fail("trusted release module invocation is invalid")
    return (
        tool.mode,
        tool.module,
        tool.distribution,
        tool.version,
        origin.as_posix(),
        site_packages.as_posix(),
        tool.entry_name,
        tool.entry_value,
    )


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


def _trusted_python_gate_command(
    tool: _TrustedReleaseTool,
    *,
    arguments: tuple[str, ...],
    context: _GateCommandContext,
) -> GateCommand:
    """Bind one Python gate to an isolated, origin-proving child driver."""
    proof = _trusted_release_tool_proof(tool)
    encoded_proof = json.dumps(
        proof,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()
    proof_sha256 = f"sha256:{hashlib.sha256(encoded_proof).hexdigest()}"
    python = Path(sys.executable)
    command = _gate_command(
        name=tool.name,
        executable=python,
        version=tool.version,
        argv=(
            python.as_posix(),
            "-I",
            "-S",
            "-B",
            "-c",
            _TRUSTED_RELEASE_TOOL_DRIVER,
            encoded_proof.decode("ascii"),
            *arguments,
        ),
        context=context,
    )
    return replace(
        command,
        offline_evidence=(context.subject_digest, proof_sha256),
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
    trusted_tools = {tool.name: tool for tool in _TRUSTED_RELEASE_TOOLS}
    return (
        _trusted_python_gate_command(
            trusted_tools["ruff"],
            arguments=(
                "check",
                "--output-format=json",
                "src",
                "scripts",
            ),
            context=context,
        ),
        _trusted_python_gate_command(
            trusted_tools["mypy"],
            arguments=("-O", "json", "src", "scripts"),
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
        _trusted_python_gate_command(
            trusted_tools["bandit"],
            arguments=(
                "-ll",
                "-r",
                "src",
                "scripts",
                "-f",
                "json",
            ),
            context=context,
        ),
        _trusted_python_gate_command(
            trusted_tools["pip-audit"],
            arguments=(
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
        _trusted_python_gate_command(
            trusted_tools["cyclonedx"],
            arguments=(
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
    _ = load_release_policies(worktree / "security")
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
    """Load the closed candidate-side policy and expected-controller descriptors."""
    external_gate_registry = parse_external_gate_registry(
        (root / "external-test-gates.json").read_bytes()
    )
    commands = load_release_command_manifest(root / "release-command-manifests.json")
    validate_external_gate_manifest_join(external_gate_registry, commands)
    recovery = load_private_recovery_policy(root / "private-recovery-policy.json")
    if recovery.policy_digest != _EXPECTED_PRIVATE_RECOVERY_POLICY_SHA256:
        _fail("private recovery policy differs from the closed release binding")
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
        recovery=recovery,
        external_gate_registry=external_gate_registry,
        commands=commands,
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


def _valid_closed_python_tool_success(
    command: GateCommand,
    completed: ChildResult,
) -> bool:
    """Validate one pinned Python tool's exact zero-exit output contract."""
    try:
        if command.name == "ruff":
            parsed = load_json_value(completed.stdout)
            return parsed == [] and completed.stderr == b""
        if command.name == "bandit":
            _ = _BanditSuccess.model_validate_json(completed.stdout, strict=True)
            return True
        if command.name == "pip-audit":
            _ = _PipAuditSuccess.model_validate_json(completed.stdout, strict=True)
            return True
        if command.name == "cyclonedx":
            _ = _CycloneDxSuccess.model_validate_json(completed.stdout, strict=True)
            return completed.stderr == b""
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError, ValidationError):
        return False
    return False


def _valid_success_evidence(command: GateCommand, completed: ChildResult) -> bool:
    """Validate a zero-exit tool result against its exact success contract."""
    if command.name in {"bandit", "cyclonedx", "pip-audit", "ruff"}:
        valid = _valid_closed_python_tool_success(command, completed)
    elif command.name == "mypy":
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
