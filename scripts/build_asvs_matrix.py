# Copyright (c) 2026 David Osipov
"""Fetch the pinned ASVS release and build a fail-closed evidence matrix."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import select
import signal
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import date, datetime
from itertools import compress
from pathlib import Path, PurePosixPath
from typing import (
    TYPE_CHECKING,
    Annotated,
    Literal,
    NoReturn,
    Protocol,
    Self,
    TypedDict,
    TypeVar,
    Unpack,
    cast,
    override,
)

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

ASVS_COMMIT = "5cf9b032440be53ce345ab3c130fda46ba1ce7a2"
ASVS_RELEASE_REF = "refs/tags/v5.0.0_release"
ASVS_URL = (
    "https://raw.githubusercontent.com/OWASP/ASVS/"
    f"{ASVS_COMMIT}/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
)
ASVS_SHA256 = "bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35"
ASVS_SIZE = 149_407
EVIDENCE_REVISION = "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0"
CANDIDATE_TREE_SHA256 = (
    "f50987fe97ed12a0da3295929e2ef8dba94693389a0a3bec2b2458a9f87aa32c"
)
REVIEWED_THREAT_LEDGER_SHA256 = (
    "b9c996bdacb533df9ca94a032e6c5925b095d078dc91b7689d5d8de9fe8bfa45"
)
Profile = Literal["alpic-metadata", "private-full", "distributed-full"]
DeploymentProfile = Profile
AssessmentMode = Literal["bootstrap", "candidate"]
ClaimPurpose = Literal["implementation-proof", "absence-proof"]
EvidenceKind = Literal["design", "code_config", "test", "operational"]
LocalVerifierName = Literal[
    "sha256-file-v1", "json-record-v1", "test-report-v1", "config-symbol-v1"
]
PROFILES: tuple[Profile, Profile, Profile] = (
    "alpic-metadata",
    "private-full",
    "distributed-full",
)
PROFILE_ORDER: dict[Profile, int] = {
    "alpic-metadata": 0,
    "private-full": 1,
    "distributed-full": 2,
}
CONTROL_CHARACTER_CEILING = 0x20
HTTP_OK = 200
L2_MAX_LEVEL: Literal[2] = 2
L1_L2_REQUIREMENT_COUNT = 253
MIN_ABSOLUTE_PATH_PARTS = 2
SHA256_HEX_LENGTH = 64
MAX_HEADER_NAME_LENGTH = 128
MAX_HEADER_VALUE_LENGTH = 4_096
MAX_GIT_TIMEOUT_SECONDS = 30
MAX_GIT_OUTPUT_BYTES = 1_048_576
VERIFY_REF_OUTPUT_BYTES = 4_096
MAX_INVENTORY_ENTRIES = 16
MAX_ARTIFACT_URI_LENGTH = 4_096
EXPECTED_L1_REQUIREMENTS = 70
EXPECTED_L2_REQUIREMENTS = 183
ATTESTATION_ALLOWLIST = (
    "docs/security/asvs-evidence-policy.json",
    "docs/security/threat-model.json",
)

HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]
GitObjectId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$", strict=True)]
NonEmpty = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=8_192,
        pattern=r"^[^\x00-\x1f\x7f]+$",
        strict=True,
    ),
]
RequirementId = Annotated[
    str,
    StringConstraints(
        max_length=256,
        pattern=r"^v5\.0\.0-[A-Za-z0-9._-]+$",
        strict=True,
    ),
]
CaseId = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$", strict=True)
]


class AsvsError(ValueError):
    """Raised when pinned ASVS or evidence data cannot be trusted."""


class StrictModel(BaseModel):
    """Provide the frozen, non-coercing base for persisted contracts."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, hide_input_in_errors=True
    )


class GitCommit(StrictModel):
    """Bind a candidate revision to the exact tree assessed for release."""

    revision: GitObjectId
    tree_sha256: HexDigest


class AsvsRequirement(StrictModel):
    """Represent one requirement extracted from the pinned ASVS source."""

    identifier: RequirementId
    text: NonEmpty
    level: Literal[1, 2, 3]


def _profile_rank(profile: str) -> int:
    if profile == "alpic-metadata":
        return PROFILE_ORDER["alpic-metadata"]
    if profile == "private-full":
        return PROFILE_ORDER["private-full"]
    if profile == "distributed-full":
        return PROFILE_ORDER["distributed-full"]
    msg = "deployment profile is outside the closed inventory"
    raise AsvsError(msg)


def _claim_subject_sort_key(subject: tuple[str, str]) -> tuple[str, int]:
    return (subject[0], _profile_rank(subject[1]))


def _requirement_sort_key(requirement: AsvsRequirement) -> str:
    return requirement.identifier


def _policy_claim_sort_key(claim: ClaimPolicyRecord) -> tuple[str, int]:
    return (claim.requirement_id, _profile_rank(claim.profile))


class _EvidenceCommon(StrictModel):
    evidence_id: CaseId
    kind: EvidenceKind
    requirement_ids: Annotated[
        tuple[RequirementId, ...], Field(min_length=1, max_length=253)
    ]
    profiles: Annotated[tuple[Profile, ...], Field(min_length=1, max_length=3)]
    asserted_invariant: NonEmpty
    covered_surface: NonEmpty
    selectors: Annotated[tuple[NonEmpty, ...], Field(min_length=1, max_length=512)]
    sha256: HexDigest
    result: Literal["pass"]
    evidence_revision: GitObjectId
    candidate_tree_sha256: HexDigest
    deployment_id: NonEmpty | None
    image_digest: HexDigest | None
    collected_at: AwareDatetime
    reviewer: NonEmpty
    expires_at: AwareDatetime
    claim_purpose: ClaimPurpose | None = None

    @field_validator("requirement_ids", "profiles", "selectors")
    @classmethod
    def unique_claim_members(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject duplicate requirement, profile, or selector claims."""
        if len(value) != len(set(value)) or any(
            not item.strip() or item != item.strip() for item in value
        ):
            msg = "evidence claim members must be unique"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def validate_evidence_lifetime(self) -> _EvidenceCommon:
        """Require evidence to expire strictly after it was collected."""
        if self.expires_at <= self.collected_at:
            msg = "evidence expiry must be later than collection"
            raise ValueError(msg)
        return self


class LocalEvidenceReference(_EvidenceCommon):
    """Bind an evidence claim to a repository-contained local artifact."""

    storage: Literal["local"]
    artifact_path: Annotated[str, StringConstraints(max_length=4_096, strict=True)]
    verifier: LocalVerifierName

    @field_validator("artifact_path")
    @classmethod
    def safe_artifact_path(cls, value: str) -> str:
        """Require an unambiguous canonical repository-relative path."""
        if (
            not value
            or "\\" in value
            or "\x00" in value
            or any(ord(char) < CONTROL_CHARACTER_CEILING for char in value)
        ):
            msg = "artifact_path is not a safe repository-relative path"
            raise ValueError(msg)
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or not path.parts
            or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            msg = "artifact_path must be canonical and repository-relative"
            raise ValueError(msg)
        return value


class CustodiedEvidenceReference(_EvidenceCommon):
    """Bind an evidence claim to an immutable custodied artifact URI."""

    storage: Literal["custodied-uri"]
    immutable_artifact_uri: str
    artifact_object_version: NonEmpty
    custody_authority_id: CaseId
    custody_receipt_id: CaseId
    verifier: Literal["ci-custody-v1"]

    @field_validator("immutable_artifact_uri")
    @classmethod
    def safe_artifact_uri(cls, value: str) -> str:
        """Require a credential-free SHA-addressed public HTTPS URI."""
        parsed = urllib.parse.urlsplit(value)
        if (
            len(value) > MAX_ARTIFACT_URI_LENGTH
            or "%" in value
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or parsed.query
        ):
            msg = "immutable artifact URI must be credential-free HTTPS"
            raise ValueError(msg)
        try:
            port = parsed.port
        except ValueError:
            msg = "artifact_uri cannot contain an explicit or malformed port"
            raise ValueError(msg) from None
        try:
            _ = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            hostname = parsed.hostname.casefold().rstrip(".")
            if hostname in {
                "localhost",
                "metadata.google.internal",
            } or hostname.endswith((".localhost", ".local")):
                msg = "artifact_uri cannot target a local host"
                raise ValueError(msg) from None
        else:
            msg = "artifact_uri cannot use an IP-literal authority"
            raise ValueError(msg)
        if port is not None:
            msg = "artifact_uri cannot contain an explicit port"
            raise ValueError(msg)
        path = PurePosixPath(parsed.path)
        lowered_parts = {part.casefold() for part in path.parts}
        if (
            not path.is_absolute()
            or path.as_posix() != parsed.path
            or lowered_parts & {"latest", "current", "head"}
            or not any(
                len(part) == SHA256_HEX_LENGTH
                and all(character in "0123456789abcdef" for character in part)
                for part in path.parts
            )
        ):
            msg = "artifact URI must contain an immutable lowercase SHA-256 path"
            raise ValueError(msg)
        return value


type EvidenceReference = Annotated[
    LocalEvidenceReference | CustodiedEvidenceReference,
    Field(discriminator="storage"),
]


class _EvidenceRowCommon(StrictModel):
    asvs_version: Literal["5.0.0"]
    requirement_id: RequirementId
    level: Literal[1, 2]
    requirement_text: NonEmpty
    profile: Literal["alpic-metadata", "private-full", "distributed-full"]
    evidence_revision: GitObjectId
    invariant: NonEmpty
    threat_boundary: CaseId
    evidence_ids: Annotated[tuple[CaseId, ...], Field(max_length=128)]
    required_evidence_kinds: Annotated[tuple[EvidenceKind, ...], Field(max_length=4)]
    owner: CaseId
    target_phase: CaseId
    evidence_date: date

    @field_validator("evidence_ids", "required_evidence_kinds")
    @classmethod
    def require_unique_tuple_items(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject duplicate evidence identifiers and evidence kinds."""
        if len(value) != len(set(value)):
            msg = "evidence identifiers and kinds must be unique"
            raise ValueError(msg)
        return value


class ApplicableEvidenceRow(_EvidenceRowCommon):
    """Represent one applicable ASVS requirement and its verdict state."""

    applicability: Literal["applicable"]
    applicability_rationale: NonEmpty
    verdict: Literal["Pass", "Fail", "Partial", "Not assessed", "Risk accepted"]
    risk_id: CaseId | None = None
    risk_owner: NonEmpty | None = None
    risk_approver: NonEmpty | None = None
    residual_risk: NonEmpty | None = None
    compensating_controls: (
        Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)] | None
    ) = None
    risk_expiry: date | None = None
    release_approval_evidence_id: CaseId | None = None

    @model_validator(mode="after")
    def validate_risk_state(self) -> ApplicableEvidenceRow:
        """Enforce complete, mutually exclusive verdict state fields."""
        risk_fields = {
            "risk_id",
            "risk_owner",
            "risk_approver",
            "residual_risk",
            "compensating_controls",
            "risk_expiry",
            "release_approval_evidence_id",
        }
        supplied = self.model_fields_set & risk_fields
        risk_values = (
            self.risk_id,
            self.risk_owner,
            self.risk_approver,
            self.residual_risk,
            self.compensating_controls,
            self.risk_expiry,
            self.release_approval_evidence_id,
        )
        if self.verdict == "Risk accepted" and (
            supplied != risk_fields or not all(risk_values)
        ):
            msg = "Risk accepted requires every risk and external approval field"
            raise ValueError(msg)
        if (
            self.verdict == "Risk accepted"
            and self.risk_expiry is not None
            and self.risk_expiry <= self.evidence_date
        ):
            msg = "risk_expiry must be later than evidence_date"
            raise ValueError(msg)
        if self.verdict != "Risk accepted" and supplied:
            msg = "risk fields are structurally forbidden outside Risk accepted"
            raise ValueError(msg)
        if self.verdict == "Pass" and (
            not self.evidence_ids or not self.required_evidence_kinds
        ):
            msg = "Pass requires named evidence and required evidence kinds"
            raise ValueError(msg)
        return self


class NotApplicableEvidenceRow(_EvidenceRowCommon):
    """Represent a reviewed non-applicable requirement with absence proof."""

    applicability: Literal["not_applicable"]
    verdict: Literal["N/A"]
    applicability_rationale: NonEmpty
    applicability_reviewer: NonEmpty
    applicability_review_due: date
    absence_evidence_ids: Annotated[
        tuple[CaseId, ...], Field(min_length=1, max_length=128)
    ]

    @field_validator("absence_evidence_ids")
    @classmethod
    def require_unique_absence_evidence(
        cls,
        value: tuple[CaseId, ...],
    ) -> tuple[CaseId, ...]:
        """Reject duplicate absence-evidence identifiers."""
        if len(value) != len(set(value)):
            msg = "absence evidence identifiers must be unique"
            raise ValueError(msg)
        return value

    @field_validator("evidence_ids", "required_evidence_kinds")
    @classmethod
    def forbids_applicable_evidence[T](cls, value: tuple[T, ...]) -> tuple[T, ...]:
        """Forbid applicable evidence fields on a non-applicable row."""
        if value:
            msg = "N/A uses absence_evidence_ids only"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def validate_review_date(self) -> NotApplicableEvidenceRow:
        """Require the next applicability review after the evidence date."""
        if self.applicability_review_due <= self.evidence_date:
            msg = "applicability review must be later than the evidence date"
            raise ValueError(msg)
        return self


type EvidenceRow = Annotated[
    ApplicableEvidenceRow | NotApplicableEvidenceRow,
    Field(discriminator="applicability"),
]


class ClaimPolicyRecord(StrictModel):
    """Define eligibility policy for one requirement and profile claim."""

    requirement_id: RequirementId
    profile: Profile
    pass_required_kinds: (
        tuple[Literal["design", "code_config", "test", "operational"], ...] | None
    )
    na_absence_required: bool
    risk_acceptance_authority_id: CaseId | None

    @field_validator("pass_required_kinds")
    @classmethod
    def validate_pass_kinds(
        cls,
        value: tuple[str, ...] | None,
    ) -> tuple[str, ...] | None:
        """Require enabled Pass kinds to be nonempty, unique, and sorted."""
        if value is not None and (
            not value or len(value) != len(set(value)) or tuple(sorted(value)) != value
        ):
            msg = "eligible Pass evidence kinds must be nonempty, unique, and sorted"
            raise ValueError(msg)
        return value


class EvidencePolicy(StrictModel):
    """Define the independent closed policy for all 759 ASVS claims."""

    schema_version: Literal["2.0"]
    asvs_version: Literal["5.0.0"]
    asvs_source_commit: GitObjectId
    evidence_revision: GitObjectId
    candidate_tree_sha256: HexDigest
    attestation_allowlist: tuple[str, str]
    profiles: tuple[Profile, Profile, Profile]
    claims: Annotated[
        tuple[ClaimPolicyRecord, ...], Field(min_length=759, max_length=759)
    ]
    custody_authority_ids: Annotated[tuple[CaseId, ...], Field(max_length=128)]
    release_authority_ids: Annotated[tuple[CaseId, ...], Field(max_length=128)]

    @model_validator(mode="after")
    def validate_policy_product(self) -> EvidencePolicy:
        """Validate the exact ordered claim product and authority bindings."""
        if self.profiles != PROFILES:
            msg = "policy profiles must equal the exact reviewed profile order"
            raise ValueError(msg)
        if self.attestation_allowlist != ATTESTATION_ALLOWLIST:
            msg = "attestation allowlist must equal the exact reviewed path set"
            raise ValueError(msg)
        keys = tuple((claim.requirement_id, claim.profile) for claim in self.claims)
        expected_order = tuple(sorted(keys, key=_claim_subject_sort_key))
        if len(keys) != MATRIX_RECORDS or len(set(keys)) != len(keys):
            msg = "policy must contain 759 unique requirement/profile claims"
            raise ValueError(msg)
        if keys != expected_order:
            msg = "policy claims must use canonical requirement/profile order"
            raise ValueError(msg)
        if (
            len(set(self.custody_authority_ids)) != len(self.custody_authority_ids)
            or tuple(sorted(self.custody_authority_ids)) != self.custody_authority_ids
        ):
            msg = "custody authority identifiers must be unique and sorted"
            raise ValueError(msg)
        if (
            len(set(self.release_authority_ids)) != len(self.release_authority_ids)
            or tuple(sorted(self.release_authority_ids)) != self.release_authority_ids
        ):
            msg = "release authority identifiers must be unique and sorted"
            raise ValueError(msg)
        if any(
            claim.risk_acceptance_authority_id not in self.release_authority_ids
            for claim in self.claims
            if claim.risk_acceptance_authority_id is not None
        ):
            msg = "risk claim names an unapproved release authority"
            raise ValueError(msg)
        return self

    def claim_for(
        self,
        requirement_id: str,
        profile: Profile,
    ) -> ClaimPolicyRecord:
        """Return the exact policy claim or fail closed."""
        for claim in self.claims:
            if claim.requirement_id == requirement_id and claim.profile == profile:
                return claim
        msg = "evidence policy does not contain the requested claim"
        raise AsvsError(msg)


class CustodyReceipt(StrictModel):
    """Represent an authority receipt bound to one immutable evidence subject."""

    schema_version: Literal["1.0"]
    authority_id: CaseId
    receipt_id: CaseId
    nonce: CaseId
    immutable_artifact_uri: str
    artifact_object_version: NonEmpty
    artifact_sha256: HexDigest
    evidence_id: CaseId
    kind: EvidenceKind
    claim_purpose: Literal["positive-control", "absence-proof"]
    selectors: Annotated[tuple[NonEmpty, ...], Field(min_length=1, max_length=512)]
    reviewer: NonEmpty
    deployment_id: NonEmpty | None
    image_digest: HexDigest | None
    evidence_revision: GitObjectId
    candidate_tree_sha256: HexDigest
    requirement_id: RequirementId
    profile: Profile
    asserted_invariant: NonEmpty
    covered_surface: NonEmpty
    risk_id: CaseId | None
    candidate_bundle_sha256: HexDigest | None
    attestation_commit: GitObjectId | None
    approver_subject: NonEmpty | None
    decision: Literal["evidence_verified", "risk_approved"]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    proof_sha256: HexDigest

    @model_validator(mode="after")
    def validate_receipt_lifetime(self) -> CustodyReceipt:
        """Require a bounded lifetime and decision-specific approval subject."""
        if self.expires_at <= self.issued_at:
            msg = "custody receipt expiry must be later than issuance"
            raise ValueError(msg)
        approval_fields = (
            self.risk_id,
            self.candidate_bundle_sha256,
            self.attestation_commit,
            self.approver_subject,
        )
        if self.decision == "risk_approved" and not all(approval_fields):
            msg = "risk approval receipt requires its full external approval subject"
            raise ValueError(msg)
        if self.decision == "evidence_verified" and any(approval_fields):
            msg = "evidence receipt structurally forbids risk approval fields"
            raise ValueError(msg)
        return self


class ReleaseDecision(StrictModel):
    """Represent a fail-closed profile release eligibility decision."""

    profile: Profile
    decision: Literal["release", "do_not_release"]
    eligible: bool
    reason_codes: Annotated[tuple[CaseId, ...], Field(max_length=128)]

    @model_validator(mode="after")
    def validate_release_state(self) -> ReleaseDecision:
        """Reject contradictory eligibility, decision, or reason fields."""
        if self.eligible != (self.decision == "release"):
            msg = "release decision and eligibility contradict"
            raise ValueError(msg)
        if len(set(self.reason_codes)) != len(self.reason_codes):
            msg = "release reason codes must be unique"
            raise ValueError(msg)
        if self.eligible and self.reason_codes:
            msg = "eligible release cannot contain failure reasons"
            raise ValueError(msg)
        if not self.eligible and not self.reason_codes:
            msg = "ineligible release requires a bounded reason"
            raise ValueError(msg)
        return self


StrideCategory = Literal["S", "T", "R", "I", "D", "E"]
AbuseCategory = Literal[
    "token-session",
    "confused-deputy",
    "ssrf-dns-proxy",
    "parser-resource-exhaustion",
    "supply-chain-build-deploy",
    "logging-privacy",
]


class ThreatNode(StrictModel):
    """Represent one data-flow node and its trust-zone privileges."""

    node_id: CaseId
    node_kind: Literal["external", "service", "provider", "data-store", "worker"]
    trust_zone: CaseId
    privileges: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]
    data_classes: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]


class ThreatFlow(StrictModel):
    """Represent one typed flow across a named trust boundary."""

    flow_id: CaseId
    source: CaseId
    target: CaseId
    boundary_id: CaseId
    protocol: NonEmpty
    data_classes: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]


class ThreatEntryPoint(StrictModel):
    """Bind one trust-boundary flow to its exposed target and control class."""

    entry_point_id: CaseId
    flow_id: CaseId
    exposed_node_id: CaseId
    access_control: Literal[
        "application-enforced", "provider-mediated", "trusted-workload"
    ]
    affected_profiles: Annotated[tuple[Profile, ...], Field(min_length=1, max_length=3)]
    data_classes: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]


class ProviderAssumption(StrictModel):
    """Record an explicitly unverified external-provider control."""

    assumption_id: CaseId
    provider: CaseId
    control: NonEmpty
    owner: CaseId
    status: Literal["assumption-unverified"]
    invalidation_trigger: NonEmpty


class ThreatRecord(StrictModel):
    """Map one threat to flows, abuse cases, controls, and ASVS claims."""

    threat_id: CaseId
    title: NonEmpty
    flow_ids: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]
    boundary_ids: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]
    stride_categories: Annotated[
        tuple[StrideCategory, ...], Field(min_length=1, max_length=6)
    ]
    abuse_categories: Annotated[
        tuple[AbuseCategory, ...], Field(min_length=1, max_length=6)
    ]
    abuse_case: NonEmpty
    affected_profiles: Annotated[tuple[Profile, ...], Field(min_length=1, max_length=3)]
    mitigations: Annotated[tuple[NonEmpty, ...], Field(min_length=1, max_length=128)]
    verification_selectors: Annotated[
        tuple[NonEmpty, ...], Field(min_length=1, max_length=128)
    ]
    asvs_requirement_ids: Annotated[
        tuple[RequirementId, ...], Field(min_length=1, max_length=253)
    ]
    assumed_provider_control_ids: Annotated[tuple[CaseId, ...], Field(max_length=128)]
    residual_risk_id: CaseId
    owner: CaseId
    verification_status: Literal["not_assessed"]
    review_due: date
    invalidation_triggers: Annotated[
        tuple[NonEmpty, ...], Field(min_length=1, max_length=128)
    ]

    @model_validator(mode="after")
    def validate_unique_threat_mappings(self) -> ThreatRecord:
        """Reject ambiguous duplicate mappings within a threat record."""
        mappings = (
            self.flow_ids,
            self.boundary_ids,
            self.stride_categories,
            self.abuse_categories,
            self.affected_profiles,
            self.verification_selectors,
            self.asvs_requirement_ids,
            self.assumed_provider_control_ids,
            self.invalidation_triggers,
        )
        if any(len(values) != len(set(values)) for values in mappings):
            msg = "threat mappings must be unique"
            raise ValueError(msg)
        return self


class ResidualRiskRecord(StrictModel):
    """Record an owned unresolved risk that blocks release."""

    residual_risk_id: CaseId
    threat_ids: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]
    description: NonEmpty
    disposition: Literal["open-do-not-release"]
    owner: CaseId
    review_due: date


class ThreatLedger(StrictModel):
    """Define the canonical data-flow and threat-model authority."""

    schema_version: Literal["1.0"]
    evidence_revision: GitObjectId
    candidate_tree_sha256: HexDigest
    assets: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]
    data_classes: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]
    actors: Annotated[tuple[CaseId, ...], Field(min_length=1, max_length=128)]
    nodes: Annotated[tuple[ThreatNode, ...], Field(min_length=1, max_length=128)]
    flows: Annotated[tuple[ThreatFlow, ...], Field(min_length=1, max_length=128)]
    entry_points: Annotated[
        tuple[ThreatEntryPoint, ...], Field(min_length=1, max_length=128)
    ]
    provider_assumptions: Annotated[
        tuple[ProviderAssumption, ...], Field(min_length=1, max_length=128)
    ]
    threats: Annotated[tuple[ThreatRecord, ...], Field(min_length=1, max_length=128)]
    residual_risks: Annotated[
        tuple[ResidualRiskRecord, ...], Field(min_length=1, max_length=128)
    ]
    global_invalidation_triggers: Annotated[
        tuple[NonEmpty, ...], Field(min_length=1, max_length=128)
    ]
    release_status: Literal["do_not_release"]

    @model_validator(mode="after")
    def validate_complete_threat_ledger(self) -> ThreatLedger:
        """Validate complete topology, category, and residual-risk mappings."""
        _validate_threat_ledger_identifiers(self)
        _validate_threat_ledger_topology(self)
        _validate_threat_ledger_categories(self)
        _validate_threat_ledger_mappings(self)
        _validate_threat_ledger_inventory(self)
        return self


type ReviewedNodeMapping = tuple[
    str,
    str,
    str,
    tuple[str, ...],
    tuple[str, ...],
]
type ReviewedFlowMapping = tuple[
    str,
    str,
    str,
    str,
    str,
    tuple[str, ...],
]
type ReviewedEntryPointMapping = tuple[
    str,
    str,
    str,
    str,
    tuple[Profile, ...],
    tuple[str, ...],
]
type ReviewedThreatMapping = tuple[
    str,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[Profile, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    str,
    str,
    str,
]
type ReviewedResidualMapping = tuple[str, tuple[str, ...], str, str]

_REVIEWED_NODE_MAPPINGS: tuple[ReviewedNodeMapping, ...] = (
    (
        "alpic-edge",
        "provider",
        "edge-provider-zone",
        ("route-mcp-traffic",),
        ("access-tokens", "deployment-provenance", "mcp-envelopes"),
    ),
    (
        "audit-log-store",
        "data-store",
        "operations-zone",
        ("retain-audit-events",),
        ("audit-events",),
    ),
    (
        "ci-build",
        "service",
        "build-zone",
        ("publish-deployment-artifacts",),
        ("deployment-provenance",),
    ),
    (
        "content-store",
        "data-store",
        "content-zone",
        ("store-public-content",),
        ("public-content", "derived-images"),
    ),
    (
        "external-client",
        "external",
        "untrusted-client-zone",
        ("submit-mcp-request",),
        ("access-tokens", "mcp-envelopes"),
    ),
    (
        "jwks-provider",
        "provider",
        "identity-provider-zone",
        ("publish-verification-keys",),
        ("access-tokens",),
    ),
    (
        "nplg-api",
        "provider",
        "nplg-upstream-zone",
        ("serve-public-repository-content",),
        ("public-content", "repository-locators"),
    ),
    (
        "pdf-worker",
        "worker",
        "isolated-parser-zone",
        ("render-untrusted-pdf",),
        ("public-content", "derived-images"),
    ),
    (
        "python-backend",
        "service",
        "application-zone",
        ("authorize-and-dispatch", "fetch-public-content"),
        (
            "access-tokens",
            "audit-events",
            "mcp-envelopes",
            "public-content",
            "repository-locators",
        ),
    ),
    (
        "scanner",
        "worker",
        "isolated-scanner-zone",
        ("classify-untrusted-content",),
        ("public-content",),
    ),
)
_REVIEWED_FLOW_MAPPINGS: tuple[ReviewedFlowMapping, ...] = (
    (
        "flow-backend-jwks",
        "python-backend",
        "jwks-provider",
        "backend-to-nplg-jwks",
        "HTTPS JWKS retrieval",
        ("access-tokens",),
    ),
    (
        "flow-backend-log",
        "python-backend",
        "audit-log-store",
        "logging-privacy",
        "Structured audit event transport",
        ("audit-events",),
    ),
    (
        "flow-backend-nplg",
        "python-backend",
        "nplg-api",
        "backend-to-nplg-upstream",
        "Bounded HTTPS repository request",
        ("public-content", "repository-locators"),
    ),
    (
        "flow-ci-edge",
        "ci-build",
        "alpic-edge",
        "build-to-deploy",
        "Provider deployment publication",
        ("deployment-provenance",),
    ),
    (
        "flow-client-edge",
        "external-client",
        "alpic-edge",
        "client-to-alpic-edge",
        "MCP over HTTPS",
        ("access-tokens", "mcp-envelopes"),
    ),
    (
        "flow-content-pdf",
        "content-store",
        "pdf-worker",
        "scanner-to-pdf-worker",
        "Descriptor-bound worker input",
        ("public-content", "derived-images"),
    ),
    (
        "flow-edge-backend",
        "alpic-edge",
        "python-backend",
        "alpic-edge-to-backend",
        "Forwarded MCP request",
        ("access-tokens", "mcp-envelopes"),
    ),
    (
        "flow-scanner-content",
        "scanner",
        "content-store",
        "scanner-to-content-store",
        "Digest-bound scan verdict",
        ("public-content",),
    ),
)
_REVIEWED_ENTRY_POINT_MAPPINGS: tuple[ReviewedEntryPointMapping, ...] = (
    (
        "entry-alpic-forward",
        "flow-edge-backend",
        "python-backend",
        "application-enforced",
        PROFILES,
        ("access-tokens", "mcp-envelopes"),
    ),
    (
        "entry-audit-log-store",
        "flow-backend-log",
        "audit-log-store",
        "trusted-workload",
        PROFILES,
        ("audit-events",),
    ),
    (
        "entry-content-store",
        "flow-scanner-content",
        "content-store",
        "application-enforced",
        ("private-full", "distributed-full"),
        ("public-content",),
    ),
    (
        "entry-deployment-publication",
        "flow-ci-edge",
        "alpic-edge",
        "trusted-workload",
        PROFILES,
        ("deployment-provenance",),
    ),
    (
        "entry-jwks-provider",
        "flow-backend-jwks",
        "jwks-provider",
        "provider-mediated",
        PROFILES,
        ("access-tokens",),
    ),
    (
        "entry-nplg-repository-api",
        "flow-backend-nplg",
        "nplg-api",
        "provider-mediated",
        PROFILES,
        ("public-content", "repository-locators"),
    ),
    (
        "entry-pdf-worker",
        "flow-content-pdf",
        "pdf-worker",
        "application-enforced",
        ("private-full", "distributed-full"),
        ("public-content", "derived-images"),
    ),
    (
        "entry-public-mcp",
        "flow-client-edge",
        "alpic-edge",
        "provider-mediated",
        PROFILES,
        ("access-tokens", "mcp-envelopes"),
    ),
)
_REVIEWED_THREAT_MAPPINGS: tuple[ReviewedThreatMapping, ...] = (
    (
        "threat-auth-token-spoofing",
        ("flow-backend-jwks", "flow-edge-backend"),
        ("alpic-edge-to-backend", "backend-to-nplg-jwks"),
        ("S",),
        ("token-session",),
        PROFILES,
        ("oauth-provider-capability-contract", "sdk-authorization-capability-contract"),
        (
            "v5.0.0-V10.3.1",
            "v5.0.0-V6.8.2",
            "v5.0.0-V7.2.1",
            "v5.0.0-V9.2.2",
        ),
        ("alpic-routing-contract", "jwks-publication-contract"),
        "risk-auth-token-spoofing",
        "identity-owner",
        "2026-12-31",
    ),
    (
        "threat-confused-deputy",
        ("flow-client-edge", "flow-edge-backend"),
        ("alpic-edge-to-backend", "client-to-alpic-edge"),
        ("T",),
        ("confused-deputy",),
        PROFILES,
        ("alpic-oauth-discovery-contract", "mcp-tool-authorization-contract"),
        ("v5.0.0-V8.2.1", "v5.0.0-V8.2.2"),
        ("alpic-routing-contract",),
        "risk-confused-deputy",
        "application-security-owner",
        "2026-12-31",
    ),
    (
        "threat-log-repudiation",
        ("flow-backend-log",),
        ("logging-privacy",),
        ("R",),
        ("logging-privacy",),
        PROFILES,
        ("audit-event-schema", "credential-canary-log-test"),
        ("v5.0.0-V16.1.1", "v5.0.0-V16.2.5", "v5.0.0-V16.4.1"),
        ("audit-log-custody",),
        "risk-log-repudiation",
        "security-operations-owner",
        "2026-12-31",
    ),
    (
        "threat-parser-exhaustion",
        ("flow-content-pdf", "flow-scanner-content"),
        ("scanner-to-content-store", "scanner-to-pdf-worker"),
        ("D",),
        ("parser-resource-exhaustion",),
        ("private-full", "distributed-full"),
        ("pdf-worker-resource-fault-suite", "scanner-content-binding-suite"),
        (
            "v5.0.0-V5.1.1",
            "v5.0.0-V5.2.1",
            "v5.0.0-V5.2.3",
            "v5.0.0-V5.4.3",
        ),
        ("nplg-upstream-contract",),
        "risk-parser-exhaustion",
        "content-security-owner",
        "2026-12-31",
    ),
    (
        "threat-ssrf-proxy",
        ("flow-backend-nplg",),
        ("backend-to-nplg-upstream",),
        ("I",),
        ("ssrf-dns-proxy",),
        PROFILES,
        ("downloader-rebinding-fault-suite", "repository-origin-policy"),
        ("v5.0.0-V1.3.6", "v5.0.0-V13.2.4", "v5.0.0-V13.2.5"),
        ("nplg-upstream-contract",),
        "risk-ssrf-proxy",
        "network-security-owner",
        "2026-12-31",
    ),
    (
        "threat-supply-chain",
        ("flow-ci-edge",),
        ("build-to-deploy",),
        ("E",),
        ("supply-chain-build-deploy",),
        PROFILES,
        ("bootstrap-toolchain-fault-suite", "deployment-provenance-attestation"),
        ("v5.0.0-V15.1.1", "v5.0.0-V15.1.2", "v5.0.0-V15.2.1"),
        ("alpic-routing-contract", "build-runtime-custody"),
        "risk-supply-chain",
        "release-owner",
        "2026-12-31",
    ),
)
_REVIEWED_RESIDUAL_MAPPINGS: tuple[ReviewedResidualMapping, ...] = (
    (
        "risk-auth-token-spoofing",
        ("threat-auth-token-spoofing",),
        "identity-owner",
        "2026-12-31",
    ),
    (
        "risk-confused-deputy",
        ("threat-confused-deputy",),
        "application-security-owner",
        "2026-12-31",
    ),
    (
        "risk-log-repudiation",
        ("threat-log-repudiation",),
        "security-operations-owner",
        "2026-12-31",
    ),
    (
        "risk-parser-exhaustion",
        ("threat-parser-exhaustion",),
        "content-security-owner",
        "2026-12-31",
    ),
    (
        "risk-ssrf-proxy",
        ("threat-ssrf-proxy",),
        "network-security-owner",
        "2026-12-31",
    ),
    (
        "risk-supply-chain",
        ("threat-supply-chain",),
        "release-owner",
        "2026-12-31",
    ),
)


def _validate_threat_ledger_identifiers(ledger: ThreatLedger) -> None:
    node_ids = {node.node_id for node in ledger.nodes}
    flow_ids = {flow.flow_id for flow in ledger.flows}
    entry_point_ids = {entry.entry_point_id for entry in ledger.entry_points}
    provider_ids = {
        assumption.assumption_id for assumption in ledger.provider_assumptions
    }
    threat_ids = {threat.threat_id for threat in ledger.threats}
    residual_ids = {risk.residual_risk_id for risk in ledger.residual_risks}
    collections = (
        (len(set(ledger.assets)), len(ledger.assets)),
        (len(set(ledger.data_classes)), len(ledger.data_classes)),
        (len(set(ledger.actors)), len(ledger.actors)),
        (
            len(set(ledger.global_invalidation_triggers)),
            len(ledger.global_invalidation_triggers),
        ),
        (len(node_ids), len(ledger.nodes)),
        (len(flow_ids), len(ledger.flows)),
        (len(entry_point_ids), len(ledger.entry_points)),
        (len(provider_ids), len(ledger.provider_assumptions)),
        (len(threat_ids), len(ledger.threats)),
        (len(residual_ids), len(ledger.residual_risks)),
    )
    if any(unique != total for unique, total in collections):
        msg = "threat ledger identifiers must be unique"
        raise ValueError(msg)
    ordered_collections = (
        ledger.assets,
        ledger.data_classes,
        ledger.actors,
        tuple(node.node_id for node in ledger.nodes),
        tuple(flow.flow_id for flow in ledger.flows),
        tuple(entry.entry_point_id for entry in ledger.entry_points),
        tuple(item.assumption_id for item in ledger.provider_assumptions),
        tuple(threat.threat_id for threat in ledger.threats),
        tuple(risk.residual_risk_id for risk in ledger.residual_risks),
        ledger.global_invalidation_triggers,
    )
    if any(values != tuple(sorted(values)) for values in ordered_collections):
        msg = "threat ledger collections must use canonical identifier order"
        raise ValueError(msg)


def _validate_threat_ledger_topology(ledger: ThreatLedger) -> None:
    nodes_by_id = {node.node_id: node for node in ledger.nodes}
    node_ids = set(nodes_by_id)
    boundary_ids = {flow.boundary_id for flow in ledger.flows}
    required_boundaries = {
        "client-to-alpic-edge",
        "alpic-edge-to-backend",
        "backend-to-nplg-jwks",
        "scanner-to-content-store",
        "scanner-to-pdf-worker",
        "build-to-deploy",
        "logging-privacy",
    }
    if not required_boundaries <= boundary_ids:
        msg = "threat ledger omits a required trust boundary"
        raise ValueError(msg)
    required_pairs = {
        ("external-client", "alpic-edge"),
        ("alpic-edge", "python-backend"),
        ("python-backend", "nplg-api"),
        ("python-backend", "jwks-provider"),
        ("scanner", "content-store"),
        ("content-store", "pdf-worker"),
        ("ci-build", "alpic-edge"),
        ("python-backend", "audit-log-store"),
    }
    if not required_pairs <= {(flow.source, flow.target) for flow in ledger.flows}:
        msg = "threat ledger omits a required data-flow edge"
        raise ValueError(msg)
    if any(
        flow.source not in node_ids or flow.target not in node_ids
        for flow in ledger.flows
    ):
        msg = "threat flow references an unknown node"
        raise ValueError(msg)
    if any(
        not set(flow.data_classes) <= set(nodes_by_id[flow.source].data_classes)
        or not set(flow.data_classes) <= set(nodes_by_id[flow.target].data_classes)
        for flow in ledger.flows
    ):
        msg = "threat flow data classes are not carried by both endpoint nodes"
        raise ValueError(msg)
    declared_data_classes = set(ledger.data_classes)
    if any(
        not set(node.data_classes) <= declared_data_classes for node in ledger.nodes
    ) or any(
        not set(flow.data_classes) <= declared_data_classes for flow in ledger.flows
    ):
        msg = "node or flow references an undeclared data class"
        raise ValueError(msg)
    flows_by_id = {flow.flow_id: flow for flow in ledger.flows}
    if len(ledger.entry_points) != len(ledger.flows) or {
        entry.flow_id for entry in ledger.entry_points
    } != set(flows_by_id):
        msg = "entry-point inventory must cover every flow exactly once"
        raise ValueError(msg)
    if any(
        entry.exposed_node_id != flows_by_id[entry.flow_id].target
        or entry.data_classes != flows_by_id[entry.flow_id].data_classes
        or not set(entry.data_classes) <= declared_data_classes
        for entry in ledger.entry_points
    ):
        msg = "entry point is not bound to its flow target and data classes"
        raise ValueError(msg)


def _validate_threat_ledger_categories(ledger: ThreatLedger) -> None:
    stride = {
        category for threat in ledger.threats for category in threat.stride_categories
    }
    abuse = {
        category for threat in ledger.threats for category in threat.abuse_categories
    }
    if stride != {"S", "T", "R", "I", "D", "E"}:
        msg = "threat ledger must cover every STRIDE category"
        raise ValueError(msg)
    if abuse != {
        "token-session",
        "confused-deputy",
        "ssrf-dns-proxy",
        "parser-resource-exhaustion",
        "supply-chain-build-deploy",
        "logging-privacy",
    }:
        msg = "threat ledger must cover every required abuse category"
        raise ValueError(msg)


def _validate_threat_ledger_mappings(ledger: ThreatLedger) -> None:
    flow_ids = {flow.flow_id for flow in ledger.flows}
    boundary_ids = {flow.boundary_id for flow in ledger.flows}
    provider_ids = {
        assumption.assumption_id for assumption in ledger.provider_assumptions
    }
    threat_ids = {threat.threat_id for threat in ledger.threats}
    residual_by_id = {
        risk.residual_risk_id: risk.threat_ids for risk in ledger.residual_risks
    }
    if any(
        not set(threat.flow_ids) <= flow_ids
        or not set(threat.boundary_ids) <= boundary_ids
        or set(threat.boundary_ids)
        != {
            flow.boundary_id for flow in ledger.flows if flow.flow_id in threat.flow_ids
        }
        or not set(threat.assumed_provider_control_ids) <= provider_ids
        or threat.residual_risk_id not in residual_by_id
        or len(set(threat.verification_selectors)) != len(threat.verification_selectors)
        for threat in ledger.threats
    ):
        msg = "threat record contains an unbound mapping"
        raise ValueError(msg)
    if any(
        not set(residual.threat_ids) <= threat_ids for residual in ledger.residual_risks
    ):
        msg = "residual risk references an unknown threat"
        raise ValueError(msg)
    if any(
        threat.threat_id not in residual_by_id[threat.residual_risk_id]
        for threat in ledger.threats
    ):
        msg = "threat and residual-risk mappings are not reciprocal"
        raise ValueError(msg)


def _validate_threat_ledger_inventory(ledger: ThreatLedger) -> None:
    required_triggers = {
        "protocol-change",
        "auth-change",
        "dependency-change",
        "runtime-change",
        "storage-change",
        "deployment-change",
        "profile-or-boundary-change",
    }
    if set(ledger.global_invalidation_triggers) != required_triggers:
        msg = "threat ledger invalidation triggers are incomplete"
        raise ValueError(msg)
    if set(ledger.actors) != {
        "external-client",
        "malicious-client",
        "untrusted-upstream",
        "edge-provider",
        "supply-chain-adversary",
        "deployment-operator",
    }:
        msg = "threat ledger actor inventory is incomplete"
        raise ValueError(msg)
    affected_profiles = {
        profile for threat in ledger.threats for profile in threat.affected_profiles
    }
    if affected_profiles != set(PROFILES):
        msg = "threat ledger does not cover every deployment profile"
        raise ValueError(msg)
    provider_ids = {
        assumption.assumption_id for assumption in ledger.provider_assumptions
    }
    bound_provider_ids = {
        provider_id
        for threat in ledger.threats
        for provider_id in threat.assumed_provider_control_ids
    }
    if provider_ids != bound_provider_ids:
        msg = "provider assumptions must all be bound to a threat"
        raise ValueError(msg)
    required_entry_points = {
        "entry-alpic-forward",
        "entry-audit-log-store",
        "entry-content-store",
        "entry-deployment-publication",
        "entry-jwks-provider",
        "entry-nplg-repository-api",
        "entry-pdf-worker",
        "entry-public-mcp",
    }
    if {entry.entry_point_id for entry in ledger.entry_points} != required_entry_points:
        msg = "threat ledger entry-point inventory is incomplete"
        raise ValueError(msg)
    supply_chain = tuple(
        threat for threat in ledger.threats if threat.threat_id == "threat-supply-chain"
    )
    if len(supply_chain) != 1 or supply_chain[0].asvs_requirement_ids != (
        "v5.0.0-V15.1.1",
        "v5.0.0-V15.1.2",
        "v5.0.0-V15.2.1",
    ):
        msg = "supply-chain threat must map to the reviewed component controls"
        raise ValueError(msg)
    node_mappings: tuple[ReviewedNodeMapping, ...] = tuple(
        (
            node.node_id,
            node.node_kind,
            node.trust_zone,
            node.privileges,
            node.data_classes,
        )
        for node in ledger.nodes
    )
    flow_mappings: tuple[ReviewedFlowMapping, ...] = tuple(
        (
            flow.flow_id,
            flow.source,
            flow.target,
            flow.boundary_id,
            flow.protocol,
            flow.data_classes,
        )
        for flow in ledger.flows
    )
    entry_mappings: tuple[ReviewedEntryPointMapping, ...] = tuple(
        (
            entry.entry_point_id,
            entry.flow_id,
            entry.exposed_node_id,
            entry.access_control,
            entry.affected_profiles,
            entry.data_classes,
        )
        for entry in ledger.entry_points
    )
    threat_mappings: tuple[ReviewedThreatMapping, ...] = tuple(
        (
            threat.threat_id,
            threat.flow_ids,
            threat.boundary_ids,
            threat.stride_categories,
            threat.abuse_categories,
            threat.affected_profiles,
            threat.verification_selectors,
            threat.asvs_requirement_ids,
            threat.assumed_provider_control_ids,
            threat.residual_risk_id,
            threat.owner,
            threat.review_due.isoformat(),
        )
        for threat in ledger.threats
    )
    residual_mappings: tuple[ReviewedResidualMapping, ...] = tuple(
        (
            risk.residual_risk_id,
            risk.threat_ids,
            risk.owner,
            risk.review_due.isoformat(),
        )
        for risk in ledger.residual_risks
    )
    if (
        node_mappings != _REVIEWED_NODE_MAPPINGS
        or flow_mappings != _REVIEWED_FLOW_MAPPINGS
        or entry_mappings != _REVIEWED_ENTRY_POINT_MAPPINGS
        or threat_mappings != _REVIEWED_THREAT_MAPPINGS
        or residual_mappings != _REVIEWED_RESIDUAL_MAPPINGS
    ):
        msg = "threat ledger differs from the reviewed security mapping"
        raise ValueError(msg)
    reviewed_body = _canonical(cast("object", ledger.model_dump(mode="json")))
    if hashlib.sha256(reviewed_body).hexdigest() != REVIEWED_THREAT_LEDGER_SHA256:
        msg = "threat ledger security semantics differ from the reviewed authority"
        raise ValueError(msg)


class CustodyAuthority(Protocol):
    """Verify custodied evidence and return its bound receipt."""

    authority_id: str

    def verify_receipt(
        self,
        reference: CustodiedEvidenceReference,
    ) -> CustodyReceipt | None:
        """Return a verified receipt or fail closed with no receipt."""
        ...


class ReceiptReplayRegistry(Protocol):
    """Track receipt nonces without allowing cross-subject replay."""

    def accept(self, *, nonce: str, subject_sha256: str) -> bool:
        """Accept first use or idempotent reuse for the same subject."""
        ...


@dataclass(frozen=True, slots=True)
class EvidenceFileSnapshot:
    """Carry immutable descriptor-bound evidence bytes and file identity."""

    body: bytes
    complete: bool
    confined: bool
    stable: bool
    regular: bool
    single_link: bool
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    root_device: int = -1
    root_inode: int = 0


class EvidenceFileSystem(Protocol):
    """Read repository evidence through a bounded no-follow interface."""

    def read_bounded(
        self,
        root: Path,
        relative_path: str,
        *,
        max_bytes: int,
    ) -> EvidenceFileSnapshot:
        """Return one stable bounded snapshot for a relative artifact."""
        ...


class ReviewedSelectorBinding(StrictModel):
    """Bind one inert selector to a reviewed candidate artifact and claim."""

    selector: NonEmpty
    claim_purpose: Literal["positive-control", "absence-proof"]
    kind: EvidenceKind
    verifier: LocalVerifierName
    artifact_path: str
    artifact_sha256: HexDigest
    evidence_revision: GitObjectId
    candidate_tree_sha256: HexDigest
    requirement_id: RequirementId
    profile: Profile
    asserted_invariant: NonEmpty
    covered_surface: NonEmpty

    @field_validator("artifact_path")
    @classmethod
    def canonical_artifact_path(cls, value: str) -> str:
        """Require the same canonical path grammar as local references."""
        return LocalEvidenceReference.safe_artifact_path(value)


class VerifiedCandidateSnapshot(StrictModel):
    """Capture a clean repository identity returned by a trusted verifier."""

    root_device: Annotated[int, Field(ge=0)]
    root_inode: Annotated[int, Field(gt=0)]
    evidence_revision: GitObjectId
    candidate_tree_sha256: HexDigest
    clean: Literal[True]
    selector_bindings: tuple[ReviewedSelectorBinding, ...]

    @field_validator("selector_bindings")
    @classmethod
    def unique_selector_bindings(
        cls,
        value: tuple[ReviewedSelectorBinding, ...],
    ) -> tuple[ReviewedSelectorBinding, ...]:
        """Reject duplicate registry entries that could make dispatch ambiguous."""
        keys = tuple(
            (
                item.selector,
                item.requirement_id,
                item.profile,
                item.claim_purpose,
            )
            for item in value
        )
        if len(keys) != len(set(keys)):
            msg = "reviewed selector registry entries must be unique"
            raise ValueError(msg)
        return value


class CandidateRepositoryVerifier(Protocol):
    """Return the current clean candidate identity through a trusted boundary."""

    def snapshot(self, root: Path) -> VerifiedCandidateSnapshot:
        """Return a bounded repository snapshot or raise fail closed."""
        ...


@dataclass(frozen=True, slots=True)
class EvidenceVerificationContext:
    """Bind evidence verification to one candidate and claim subject."""

    root: Path
    evidence_revision: str
    candidate_tree_sha256: str
    requirement_id: str
    profile: Profile
    asserted_invariant: str
    covered_surface: str
    as_of: datetime
    claim_purpose: Literal["positive-control", "absence-proof"] = "positive-control"
    risk_id: str | None = None
    candidate_bundle_sha256: str | None = None
    attestation_commit: str | None = None
    approver_subject: str | None = None
    verified_candidate: VerifiedCandidateSnapshot | None = None
    authorities: tuple[CustodyAuthority, ...] = ()
    replay_registry: ReceiptReplayRegistry | None = None


def verify_claim_binding(
    row: ApplicableEvidenceRow | NotApplicableEvidenceRow,
    reference: LocalEvidenceReference | CustodiedEvidenceReference,
) -> bool:
    """Check exact row-to-reference subject and evidence-kind binding."""
    evidence_ids = (
        row.absence_evidence_ids
        if isinstance(row, NotApplicableEvidenceRow)
        else row.evidence_ids
    )
    if (
        reference.evidence_id not in evidence_ids
        or row.requirement_id not in reference.requirement_ids
        or row.profile not in reference.profiles
        or row.invariant != reference.asserted_invariant
        or row.evidence_revision != reference.evidence_revision
    ):
        return False
    if isinstance(row, NotApplicableEvidenceRow):
        return False
    if row.verdict == "Pass":
        return reference.kind in row.required_evidence_kinds
    return True


def verify_release_approval(
    row: ApplicableEvidenceRow,
    reference: LocalEvidenceReference | CustodiedEvidenceReference,
    *,
    policy: EvidencePolicy,
    context: EvidenceVerificationContext,
) -> bool:
    """Verify an external risk-approval receipt without releasing."""
    if row.verdict != "Risk accepted":
        return False
    if (
        row.release_approval_evidence_id is None
        or reference.evidence_id != row.release_approval_evidence_id
        or not isinstance(reference, CustodiedEvidenceReference)
    ):
        return False
    claim = policy.claim_for(row.requirement_id, row.profile)
    authority_id = claim.risk_acceptance_authority_id
    if (
        authority_id is None
        or authority_id not in policy.release_authority_ids
        or authority_id not in policy.custody_authority_ids
        or reference.custody_authority_id != authority_id
        or context.risk_id != row.risk_id
        or context.requirement_id != row.requirement_id
        or context.profile != row.profile
        or context.asserted_invariant != row.invariant
        or context.evidence_revision != row.evidence_revision
        or reference.kind != "operational"
        or not context.candidate_bundle_sha256
        or not context.attestation_commit
        or context.approver_subject != row.risk_approver
        or row.risk_expiry is None
        or context.as_of.date() >= row.risk_expiry
    ):
        return False
    return verify_evidence_reference(reference, context=context)


def _bootstrap_profile_release(
    profile: Profile,
    rows: tuple[ApplicableEvidenceRow | NotApplicableEvidenceRow, ...],
    manifest: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...],
) -> ReleaseDecision:
    """Preserve the bootstrap verdict path without candidate interpretation."""
    if manifest or rows != load_evidence_matrix():
        return ReleaseDecision(
            profile=profile,
            decision="do_not_release",
            eligible=False,
            reason_codes=("bootstrap-product-mismatch",),
        )
    return ReleaseDecision(
        profile=profile,
        decision="do_not_release",
        eligible=False,
        reason_codes=("not-assessed",),
    )


_APPROVED_ABSENCE_EVIDENCE_KINDS = frozenset({"design", "code_config", "test"})


@dataclass(frozen=True, slots=True)
class _CandidateAssessment:
    """Carry one immutable candidate and its independent verification inputs."""

    candidate: GitCommit
    as_of: datetime
    verification_context: EvidenceVerificationContext | None
    candidate_verifier: CandidateRepositoryVerifier | None


def _candidate_reference_blockers(
    row: ApplicableEvidenceRow | NotApplicableEvidenceRow,
    references: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...],
    assessment: _CandidateAssessment,
) -> tuple[str, ...]:
    """Return all independent-evidence failures for one candidate ASVS row."""

    def _candidate_reference_context(
        template: EvidenceVerificationContext,
        reference: LocalEvidenceReference | CustodiedEvidenceReference,
    ) -> EvidenceVerificationContext:
        purpose: Literal["positive-control", "absence-proof"] = (
            "absence-proof"
            if isinstance(row, NotApplicableEvidenceRow)
            else "positive-control"
        )
        return replace(
            template,
            evidence_revision=assessment.candidate.revision,
            candidate_tree_sha256=assessment.candidate.tree_sha256,
            requirement_id=row.requirement_id,
            profile=row.profile,
            asserted_invariant=row.invariant,
            covered_surface=reference.covered_surface,
            as_of=assessment.as_of,
            claim_purpose=purpose,
        )

    def _candidate_reference_binding_blockers(
        reference: LocalEvidenceReference | CustodiedEvidenceReference,
    ) -> tuple[str, ...]:
        reasons = (
            "candidate-binding-mismatch",
            "profile-binding-mismatch",
            "claim-binding-mismatch",
            "expired-evidence",
            "missing-claim-purpose",
        )
        failures = (
            reference.evidence_revision != assessment.candidate.revision
            or row.evidence_revision != assessment.candidate.revision
            or reference.candidate_tree_sha256 != assessment.candidate.tree_sha256,
            row.profile not in reference.profiles,
            row.requirement_id not in reference.requirement_ids
            or row.invariant != reference.asserted_invariant,
            reference.expires_at <= assessment.as_of,
            reference.claim_purpose is None,
        )
        return tuple(compress(reasons, failures))

    def _candidate_reference_is_independently_verified(
        reference: LocalEvidenceReference | CustodiedEvidenceReference,
    ) -> bool:
        context = assessment.verification_context
        return context is not None and verify_evidence_reference(
            reference,
            context=_candidate_reference_context(context, reference),
            candidate_verifier=assessment.candidate_verifier,
        )

    def _candidate_reference_governance_blockers(
        reference: LocalEvidenceReference | CustodiedEvidenceReference,
    ) -> tuple[str, ...]:
        absence_invalid = (
            reference.claim_purpose != "absence-proof"
            or not isinstance(reference, CustodiedEvidenceReference)
            or reference.kind not in _APPROVED_ABSENCE_EVIDENCE_KINDS
        )
        absence_blockers = ((), ("missing-absence-proof",))[absence_invalid]
        implementation_blockers = ((), ("wrong-claim-purpose",))[
            reference.claim_purpose != "implementation-proof"
        ]
        return (implementation_blockers, absence_blockers)[
            isinstance(row, NotApplicableEvidenceRow)
        ]

    def _candidate_required_evidence_blockers(
        indexed: dict[
            str,
            LocalEvidenceReference | CustodiedEvidenceReference,
        ],
    ) -> tuple[str, ...]:
        is_pass = isinstance(row, ApplicableEvidenceRow) and row.verdict == "Pass"
        evidence_ids = row.evidence_ids if is_pass else ()
        required_kinds = row.required_evidence_kinds if is_pass else ()
        kinds = {
            indexed[evidence_id].kind
            for evidence_id in evidence_ids
            if evidence_id in indexed
        }
        missing = (
            not evidence_ids
            or not required_kinds
            or any(kind not in kinds for kind in required_kinds)
        )
        return ((), ("missing-required-evidence",))[is_pass and missing]

    evidence_ids = (
        row.absence_evidence_ids
        if isinstance(row, NotApplicableEvidenceRow)
        else row.evidence_ids
    )
    indexed = {reference.evidence_id: reference for reference in references}
    blockers: list[str] = []
    if (
        isinstance(row, NotApplicableEvidenceRow)
        and row.applicability_review_due <= assessment.as_of.date()
    ):
        blockers.append("expired-na-review")
    for evidence_id in evidence_ids:
        reference = indexed.get(evidence_id)
        if reference is None:
            blockers.append(
                "missing-absence-proof"
                if isinstance(row, NotApplicableEvidenceRow)
                else "missing-evidence"
            )
            continue
        blockers.extend(_candidate_reference_binding_blockers(reference))
        if not _candidate_reference_is_independently_verified(reference):
            blockers.append("independent-evidence-unverified")
        blockers.extend(_candidate_reference_governance_blockers(reference))
    blockers.extend(_candidate_required_evidence_blockers(indexed))
    return tuple(blockers)


def _candidate_profile_release(
    profile: Profile,
    matrix: tuple[ApplicableEvidenceRow | NotApplicableEvidenceRow, ...],
    evidence: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...],
    assessment: _CandidateAssessment,
) -> ReleaseDecision:
    """Assess one exact L1/L2 Alpic candidate without accepting bootstrap state."""

    def _candidate_requirements() -> tuple[AsvsRequirement, ...]:
        return tuple(
            sorted(
                (
                    requirement
                    for requirement in load_pinned_asvs_requirements()
                    if requirement.level <= L2_MAX_LEVEL
                ),
                key=_requirement_sort_key,
            )
        )

    blockers: list[str] = []
    if profile != "alpic-metadata":
        blockers.append("candidate-profile-not-supported")
    selected = tuple(row for row in matrix if row.profile == profile)
    pinned_requirements = _candidate_requirements()
    pinned_by_id = {
        requirement.identifier: requirement for requirement in pinned_requirements
    }
    pinned_ids = tuple(requirement.identifier for requirement in pinned_requirements)
    selected_ids = tuple(row.requirement_id for row in selected)
    if (
        len(matrix) != L1_L2_REQUIREMENT_COUNT
        or len(selected) != L1_L2_REQUIREMENT_COUNT
        or frozenset(selected_ids) != frozenset(pinned_ids)
    ):
        blockers.append("pinned-requirement-set-mismatch")
    if selected_ids != pinned_ids or any(
        (expected := pinned_by_id.get(row.requirement_id)) is None
        or row.level != expected.level
        or row.requirement_text != expected.text
        for row in selected
    ):
        blockers.append("pinned-requirement-semantics-mismatch")
    evidence_ids = tuple(reference.evidence_id for reference in evidence)
    if len(evidence_ids) != len(set(evidence_ids)):
        blockers.append("duplicate-evidence-id")
    for row in selected:
        if isinstance(row, ApplicableEvidenceRow) and row.verdict != "Pass":
            blockers.append("candidate-row-not-pass")
        blockers.extend(
            _candidate_reference_blockers(
                row,
                evidence,
                assessment,
            )
        )
    reason_codes = tuple(cast("dict[str, None]", dict.fromkeys(blockers)))
    if reason_codes:
        return ReleaseDecision(
            profile=profile,
            decision="do_not_release",
            eligible=False,
            reason_codes=reason_codes,
        )
    return ReleaseDecision(
        profile=profile, decision="release", eligible=True, reason_codes=()
    )


class _ReleaseEvaluationOptions(TypedDict, total=False):
    """Define the closed mode-specific keyword surface for release evaluation."""

    policy: EvidencePolicy
    context: EvidenceVerificationContext
    assessment_mode: AssessmentMode
    candidate: GitCommit | dict[str, str]
    matrix: tuple[ApplicableEvidenceRow | NotApplicableEvidenceRow, ...]
    evidence: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...]
    as_of: datetime
    verification_context: EvidenceVerificationContext
    candidate_verifier: CandidateRepositoryVerifier


_RELEASE_EVALUATION_OPTION_NAMES = frozenset(_ReleaseEvaluationOptions.__annotations__)


def evaluate_profile_release(
    profile: Profile | None = None,
    rows: tuple[ApplicableEvidenceRow | NotApplicableEvidenceRow, ...] | None = None,
    manifest: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...]
    | None = None,
    **options: Unpack[_ReleaseEvaluationOptions],
) -> ReleaseDecision:
    """Evaluate immutable bootstrap inventory or one independent candidate product."""
    if not options.keys() <= _RELEASE_EVALUATION_OPTION_NAMES:
        msg = "release assessment contains an unknown option"
        raise AsvsError(msg)
    policy = options.get("policy")
    context = options.get("context")
    assessment_mode: object = options.get("assessment_mode", "bootstrap")
    candidate = options.get("candidate")
    matrix = options.get("matrix")
    evidence = options.get("evidence")
    as_of = options.get("as_of")
    verification_context = options.get("verification_context")
    candidate_verifier = options.get("candidate_verifier")
    if assessment_mode == "bootstrap":
        if (
            profile is None
            or rows is None
            or manifest is None
            or policy is None
            or context is None
        ):
            msg = "bootstrap assessment requires its complete legacy inputs"
            raise AsvsError(msg)
        if (
            candidate is not None
            or matrix is not None
            or evidence is not None
            or as_of is not None
            or verification_context is not None
            or candidate_verifier is not None
        ):
            msg = "bootstrap assessment forbids candidate inputs"
            raise AsvsError(msg)
        return _bootstrap_profile_release(profile, rows, manifest)
    if assessment_mode != "candidate":
        msg = "assessment mode is outside the closed inventory"
        raise AsvsError(msg)
    if (
        profile is None
        or candidate is None
        or matrix is None
        or evidence is None
        or as_of is None
        or rows is not None
        or manifest is not None
        or policy is not None
        or context is not None
    ):
        msg = "candidate assessment requires only its complete candidate inputs"
        raise AsvsError(msg)
    try:
        checked_candidate = GitCommit.model_validate(candidate, strict=True)
    except ValidationError as exc:
        msg = "candidate commit is not a strict revision/tree binding"
        raise AsvsError(msg) from exc
    return _candidate_profile_release(
        profile,
        matrix,
        evidence,
        _CandidateAssessment(
            candidate=checked_candidate,
            as_of=as_of,
            verification_context=verification_context,
            candidate_verifier=candidate_verifier,
        ),
    )


@dataclass(frozen=True, slots=True)
class HttpDownloadResult:
    """Capture a complete bounded HTTP representation and metadata."""

    requested_url: str
    final_url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    redirect_count: int
    complete: bool


class Downloader(Protocol):
    """Download one exact immutable URL within a byte ceiling."""

    def download(self, url: str, *, max_bytes: int) -> HttpDownloadResult:
        """Return a complete response representation or raise."""
        ...


class ArtifactPublisher(Protocol):
    """Publish an artifact pair without overwriting existing targets."""

    def publish_pair(
        self,
        first: tuple[Path, bytes],
        second: tuple[Path, bytes],
    ) -> None:
        """Publish both artifacts or leave neither target behind."""
        ...


class ExclusiveArtifactPublisher:
    """Publish two files with exclusive no-follow filesystem operations."""

    def publish_pair(
        self,
        first: tuple[Path, bytes],
        second: tuple[Path, bytes],
    ) -> None:
        """Publish both artifacts exclusively in one reviewed directory."""
        _publish_exclusive_pair(first, second)


@dataclass(frozen=True, slots=True)
class GitCommandResult:
    """Capture bounded raw Git process output and completion flags."""

    returncode: int
    stdout: bytes
    stderr: bytes
    complete: bool
    timed_out: bool
    stdout_overflow: bool
    stderr_overflow: bool


@dataclass(frozen=True, slots=True)
class GitCommandRequest:
    """Carry one immutable bounded Git execution request."""

    argv: tuple[str, ...]
    timeout_seconds: float
    max_stdout_bytes: int
    max_stderr_bytes: int
    env: tuple[tuple[str, str], ...]
    cwd: Path


class GitRunner(Protocol):
    """Execute one reviewed Git command with closed bounded inputs."""

    def run(self, request: GitCommandRequest) -> GitCommandResult:
        """Return bounded raw output and explicit completion flags."""
        ...


class _HttpResponse(Protocol):
    status: int
    headers: Mapping[str, str]

    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...
    def read(self, amount: int) -> bytes: ...
    def geturl(self) -> str: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    @override
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        msg_0 = "redirects are forbidden for ASVS fetches"
        raise AsvsError(msg_0)


class HttpsDownloader:
    """Fetch the exact pinned ASVS URL without proxies or redirects."""

    def download(self, url: str, *, max_bytes: int) -> HttpDownloadResult:
        """Return the exact identity-encoded ASVS response bytes."""
        parsed = urllib.parse.urlsplit(url)
        if (
            url != ASVS_URL
            or parsed.scheme != "https"
            or parsed.hostname != "raw.githubusercontent.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            msg = "ASVS URL is not the exact credential-free GitHub HTTPS source"
            raise AsvsError(msg)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler()
        )
        opener.addheaders = [("Accept-Encoding", "identity")]
        try:
            with cast("_HttpResponse", opener.open(ASVS_URL, timeout=30)) as response:
                if response.status != HTTP_OK or response.headers.get(
                    "Content-Encoding"
                ):
                    msg = "ASVS fetch returned an unexpected HTTP representation"
                    raise AsvsError(msg)
                length = response.headers.get("Content-Length")
                if length is None or not length.isdigit() or int(length) != max_bytes:
                    msg = "ASVS artifact exceeds the bounded size"
                    raise AsvsError(msg)
                chunks: list[bytes] = []
                remaining = max_bytes + 1
                complete = False
                while remaining > 0:
                    chunk = response.read(min(65_536, remaining))
                    if not chunk:
                        complete = True
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                body = b"".join(chunks)
                headers = tuple(
                    (key.lower(), value.strip())
                    for key, value in response.headers.items()
                )
                final_url = response.geturl()
        except (OSError, urllib.error.URLError) as exc:
            msg = "ASVS fetch failed"
            raise AsvsError(msg) from exc
        if len(body) > max_bytes:
            msg = "ASVS artifact exceeds the bounded size"
            raise AsvsError(msg)
        return HttpDownloadResult(
            requested_url=url,
            final_url=final_url,
            status=HTTP_OK,
            headers=headers,
            body=body,
            redirect_count=0,
            complete=complete,
        )


MAX_JSON_DEPTH = 32
MAX_JSON_MEMBERS = 100_000
MAX_JSON_STRING_BYTES = 65_536
MATRIX_MAX_BYTES = 2 * 1024 * 1024
MATRIX_MAX_LINE_BYTES = 16 * 1024
MATRIX_RECORDS = L1_L2_REQUIREMENT_COUNT * len(PROFILES)
MANIFEST_MAX_BYTES = 8 * 1024 * 1024
MANIFEST_MAX_LINE_BYTES = 64 * 1024
MANIFEST_MAX_RECORDS = 4_096
POLICY_MAX_BYTES = 2 * 1024 * 1024
THREAT_LEDGER_MAX_BYTES = 2 * 1024 * 1024
THREAT_MARKDOWN_MAX_BYTES = 2 * 1024 * 1024


class _DuplicateJsonKeyError(ValueError):
    """Internal marker for a duplicate JSON object member."""


def _reject_non_integer_number(_value: str) -> NoReturn:
    msg = "non-integer or non-finite JSON number"
    raise AsvsError(msg)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            msg = "duplicate JSON key"
            raise _DuplicateJsonKeyError(msg)
        result[key] = value
    return result


def _require_json_member_bound(members: int) -> None:
    if members > MAX_JSON_MEMBERS:
        msg = "JSON document exceeds the configured member bound"
        raise AsvsError(msg)


def _validate_json_sequence(value: list[object], depth: int) -> int:
    _require_json_member_bound(len(value))
    members = 1
    for item in value:
        members += _validate_json_shape(item, depth=depth + 1)
        _require_json_member_bound(members)
    return members


def _validate_json_mapping(value: dict[object, object], depth: int) -> int:
    _require_json_member_bound(len(value))
    members = 1
    for key, item in value.items():
        members += _validate_json_shape(key, depth=depth + 1)
        members += _validate_json_shape(item, depth=depth + 1)
        _require_json_member_bound(members)
    return members


def _validate_json_shape(value: object, *, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        msg = "JSON nesting exceeds the configured bound"
        raise AsvsError(msg)
    if value is None or isinstance(value, bool):
        return 1
    if type(value) is int:
        if abs(value) > (2**53 - 1):
            msg = "JSON integer exceeds the interoperable bound"
            raise AsvsError(msg)
        return 1
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_JSON_STRING_BYTES:
            msg = "JSON string exceeds the configured bound"
            raise AsvsError(msg)
        return 1
    if isinstance(value, list):
        return _validate_json_sequence(cast("list[object]", value), depth)
    if isinstance(value, dict):
        return _validate_json_mapping(cast("dict[object, object]", value), depth)
    msg = "JSON contains an unsupported value"
    raise AsvsError(msg)


def _parse_json_bytes(body: bytes) -> object:
    if body.startswith(b"\xef\xbb\xbf"):
        msg = "UTF-8 BOM is forbidden"
        raise AsvsError(msg)
    try:
        text = body.decode("utf-8", errors="strict")
        value = cast(
            "object",
            json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_integer_number,
                parse_float=_reject_non_integer_number,
            ),
        )
    except _DuplicateJsonKeyError as exc:
        msg = "duplicate JSON key"
        raise AsvsError(msg) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = "invalid UTF-8 JSON"
        raise AsvsError(msg) from exc
    try:
        _ = _validate_json_shape(value)
    except UnicodeEncodeError as exc:
        msg = "invalid UTF-8 JSON"
        raise AsvsError(msg) from exc
    return value


def _canonical_value(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        msg = "value cannot be serialized as canonical JSON"
        raise AsvsError(msg) from exc


def _canonical(value: object) -> bytes:
    return _canonical_value(value) + b"\n"


def _read_bounded_descriptor(
    descriptor: int,
    *,
    max_bytes: int,
) -> tuple[bytes, os.stat_result, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        msg = "artifact is not a regular single-link file"
        raise AsvsError(msg)
    if before.st_size > max_bytes:
        msg = "artifact exceeds the configured byte bound"
        raise AsvsError(msg)
    chunks: list[bytes] = []
    remaining = before.st_size
    while remaining > 0:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks), before, os.fstat(descriptor)


def _snapshot_bounded_regular_file(
    path: Path,
    *,
    max_bytes: int,
) -> EvidenceFileSnapshot:
    components = path.absolute().parts
    if len(components) < MIN_ABSOLUTE_PATH_PARTS or components[0] != os.sep:
        msg = "artifact path is invalid"
        raise AsvsError(msg)
    directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    file_fd: int | None = None
    try:
        for component in components[1:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            components[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        body, before, after = _read_bounded_descriptor(file_fd, max_bytes=max_bytes)
    except OSError as exc:
        msg = "artifact could not be opened securely"
        raise AsvsError(msg) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
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
    if identity_before != identity_after or len(body) != before.st_size:
        msg = "artifact identity changed while it was read"
        raise AsvsError(msg)
    return EvidenceFileSnapshot(
        body=body,
        complete=True,
        confined=True,
        stable=True,
        regular=True,
        single_link=True,
        device=before.st_dev,
        inode=before.st_ino,
        size=before.st_size,
        mtime_ns=before.st_mtime_ns,
        ctime_ns=before.st_ctime_ns,
    )


def _read_bounded_regular_file(path: Path, *, max_bytes: int) -> bytes:
    return _snapshot_bounded_regular_file(path, max_bytes=max_bytes).body


class DescriptorEvidenceFileSystem:
    """Read evidence beneath a root with a no-follow descriptor walk."""

    def read_bounded(
        self,
        root: Path,
        relative_path: str,
        *,
        max_bytes: int,
    ) -> EvidenceFileSnapshot:
        """Return a stable no-follow snapshot below the supplied root."""
        if not _safe_local_path(relative_path):
            msg = "evidence path is not canonical and repository-relative"
            raise AsvsError(msg)
        return _snapshot_bounded_beneath_root(
            root,
            PurePosixPath(relative_path),
            max_bytes=max_bytes,
        )


def _open_directory_no_follow(path: Path) -> int:
    components = path.absolute().parts
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in components[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as exc:
        os.close(descriptor)
        msg = "publication directory is not a no-follow directory"
        raise AsvsError(msg) from exc
    return descriptor


def _snapshot_bounded_beneath_root(
    root: Path,
    relative_path: PurePosixPath,
    *,
    max_bytes: int,
) -> EvidenceFileSnapshot:
    """Read a file beneath one opened root descriptor and retain root identity."""
    root_fd = _open_directory_no_follow(root)
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        root_before = os.fstat(root_fd)
        directory_fd = os.dup(root_fd)
        for component in relative_path.parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            relative_path.parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        body, before, after = _read_bounded_descriptor(file_fd, max_bytes=max_bytes)
        root_after = os.fstat(root_fd)
    except OSError as exc:
        msg = "evidence could not be opened beneath the reviewed root"
        raise AsvsError(msg) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(root_fd)
    file_identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    file_identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    root_identity_before = (
        root_before.st_dev,
        root_before.st_ino,
        root_before.st_mode,
        root_before.st_nlink,
        root_before.st_mtime_ns,
        root_before.st_ctime_ns,
    )
    root_identity_after = (
        root_after.st_dev,
        root_after.st_ino,
        root_after.st_mode,
        root_after.st_nlink,
        root_after.st_mtime_ns,
        root_after.st_ctime_ns,
    )
    if (
        file_identity_before != file_identity_after
        or root_identity_before != root_identity_after
        or len(body) != before.st_size
    ):
        msg = "evidence or reviewed-root identity changed while it was read"
        raise AsvsError(msg)
    return EvidenceFileSnapshot(
        body=body,
        complete=True,
        confined=True,
        stable=True,
        regular=True,
        single_link=True,
        device=before.st_dev,
        inode=before.st_ino,
        size=before.st_size,
        mtime_ns=before.st_mtime_ns,
        ctime_ns=before.st_ctime_ns,
        root_device=root_before.st_dev,
        root_inode=root_before.st_ino,
    )


def _write_all(descriptor: int, body: bytes) -> None:
    view = memoryview(body)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            msg = "artifact publication made no write progress"
            raise AsvsError(msg)
        written += count


def _validate_temporary_artifact(
    identity: os.stat_result,
    initial_identity: tuple[int, int],
    expected_size: int,
) -> None:
    if (
        not stat.S_ISREG(identity.st_mode)
        or identity.st_nlink != 1
        or identity.st_size != expected_size
        or initial_identity != (identity.st_dev, identity.st_ino)
    ):
        msg = "temporary publication artifact failed identity validation"
        raise AsvsError(msg)


def _unlink_if_same_inode(
    directory_fd: int,
    name: str,
    expected_device: int,
    expected_inode: int,
) -> None:
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        return
    if current.st_dev == expected_device and current.st_ino == expected_inode:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            return


def _unlink_expected_inode(
    directory_fd: int,
    name: str,
    expected_device: int,
    expected_inode: int,
) -> None:
    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (expected_device, expected_inode):
        msg = "publication artifact identity changed before cleanup"
        raise AsvsError(msg)
    os.unlink(name, dir_fd=directory_fd)


@dataclass(frozen=True, slots=True)
class _AbsentPublicationLock:
    state: Literal["absent"] = "absent"


@dataclass(frozen=True, slots=True)
class _OpenPublicationLock:
    descriptor: int
    device: int
    inode: int
    state: Literal["open"] = "open"


type _PublicationLockState = _AbsentPublicationLock | _OpenPublicationLock


@dataclass(frozen=True, slots=True)
class _StagedPublicationArtifact:
    temporary_name: str
    target_name: str
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _PublishedArtifact:
    target_name: str
    device: int
    inode: int


def _rollback_publication(
    directory_fd: int,
    staged: list[_StagedPublicationArtifact],
    published: list[_PublishedArtifact],
    lock: _PublicationLockState,
    lock_name: str,
) -> None:
    for published_artifact in published:
        _unlink_if_same_inode(
            directory_fd,
            published_artifact.target_name,
            published_artifact.device,
            published_artifact.inode,
        )
    for staged_artifact in staged:
        _unlink_if_same_inode(
            directory_fd,
            staged_artifact.temporary_name,
            staged_artifact.device,
            staged_artifact.inode,
        )
    if isinstance(lock, _OpenPublicationLock):
        _unlink_if_same_inode(directory_fd, lock_name, lock.device, lock.inode)
    with suppress(OSError):
        os.fsync(directory_fd)


def _remove_publication_lock(
    directory_fd: int,
    lock: _PublicationLockState,
    lock_name: str,
) -> None:
    if isinstance(lock, _AbsentPublicationLock):
        msg = "publication lock identity was not captured"
        raise AsvsError(msg)
    _unlink_expected_inode(directory_fd, lock_name, lock.device, lock.inode)


def _publish_exclusive_pair(
    first: tuple[Path, bytes],
    second: tuple[Path, bytes],
) -> None:
    first_path = first[0].absolute()
    second_path = second[0].absolute()
    if (
        first_path.parent != second_path.parent
        or first_path == second_path
        or first_path.name in {"", ".", ".."}
        or second_path.name in {"", ".", ".."}
    ):
        msg = "artifact pair must use distinct names in one directory"
        raise AsvsError(msg)
    directory_fd = _open_directory_no_follow(first_path.parent)
    lock_name = ".asvs-fetch.lock"
    token = secrets.token_hex(16)
    temporary_names = (
        f".asvs-fetch-{token}-first",
        f".asvs-fetch-{token}-second",
    )
    lock: _PublicationLockState = _AbsentPublicationLock()
    temporary_fds: list[int] = []
    staged: list[_StagedPublicationArtifact] = []
    published: list[_PublishedArtifact] = []
    try:
        lock_descriptor = os.open(
            lock_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        opened_lock = os.fstat(lock_descriptor)
        lock = _OpenPublicationLock(
            descriptor=lock_descriptor,
            device=opened_lock.st_dev,
            inode=opened_lock.st_ino,
        )
        os.fsync(lock.descriptor)
        for name, target, body in zip(
            temporary_names,
            (first_path.name, second_path.name),
            (first[1], second[1]),
            strict=True,
        ):
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
            temporary_fds.append(descriptor)
            initial_identity = os.fstat(descriptor)
            staged.append(
                _StagedPublicationArtifact(
                    temporary_name=name,
                    target_name=target,
                    device=initial_identity.st_dev,
                    inode=initial_identity.st_ino,
                )
            )
            _write_all(descriptor, body)
            os.fsync(descriptor)
            final_identity = os.fstat(descriptor)
            _validate_temporary_artifact(
                final_identity,
                (initial_identity.st_dev, initial_identity.st_ino),
                len(body),
            )
        for artifact in staged:
            os.link(
                artifact.temporary_name,
                artifact.target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            published.append(
                _PublishedArtifact(
                    target_name=artifact.target_name,
                    device=artifact.device,
                    inode=artifact.inode,
                )
            )
        os.fsync(directory_fd)
        for artifact in staged:
            _unlink_expected_inode(
                directory_fd,
                artifact.temporary_name,
                artifact.device,
                artifact.inode,
            )
        _remove_publication_lock(directory_fd, lock, lock_name)
        os.fsync(directory_fd)
    except (AsvsError, OSError) as exc:
        _rollback_publication(directory_fd, staged, published, lock, lock_name)
        msg = "exclusive artifact publication failed"
        raise AsvsError(msg) from exc
    finally:
        for descriptor in temporary_fds:
            os.close(descriptor)
        if isinstance(lock, _OpenPublicationLock):
            os.close(lock.descriptor)
        os.close(directory_fd)


def _atomic_write(path: Path, body: bytes) -> None:
    target = path.absolute()
    if target.name in {"", ".", ".."}:
        msg = "matrix output name is not canonical"
        raise AsvsError(msg)
    directory_fd = _open_directory_no_follow(target.parent)
    temporary_name = f".asvs-matrix-{secrets.token_hex(16)}"
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    published = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        initial = os.fstat(descriptor)
        identity = (initial.st_dev, initial.st_ino)
        _write_all(descriptor, body)
        os.fsync(descriptor)
        _validate_temporary_artifact(os.fstat(descriptor), identity, len(body))
        os.link(
            temporary_name,
            target.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        published = True
        os.fsync(directory_fd)
        _unlink_expected_inode(directory_fd, temporary_name, *identity)
        os.fsync(directory_fd)
    except (AsvsError, OSError) as exc:
        if published and identity is not None:
            _unlink_if_same_inode(directory_fd, target.name, *identity)
        if identity is not None:
            _unlink_if_same_inode(directory_fd, temporary_name, *identity)
        with suppress(OSError):
            os.fsync(directory_fd)
        msg = "exclusive matrix publication failed"
        raise AsvsError(msg) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _validated_download_body(result: HttpDownloadResult) -> bytes:
    if (
        result.requested_url != ASVS_URL
        or result.final_url != ASVS_URL
        or result.status != HTTP_OK
        or result.redirect_count != 0
        or not result.complete
    ):
        msg = "ASVS response metadata does not match the immutable request"
        raise AsvsError(msg)
    normalized_headers: dict[str, str] = {}
    for key, value in result.headers:
        normalized = key.casefold()
        if (
            not normalized
            or normalized in normalized_headers
            or len(normalized) > MAX_HEADER_NAME_LENGTH
            or len(value) > MAX_HEADER_VALUE_LENGTH
            or any(
                ord(character) < CONTROL_CHARACTER_CEILING for character in key + value
            )
        ):
            msg = "ASVS response headers are malformed or duplicated"
            raise AsvsError(msg)
        normalized_headers[normalized] = value
    if (
        normalized_headers.get("content-length") != str(ASVS_SIZE)
        or "content-encoding" in normalized_headers
        or "transfer-encoding" in normalized_headers
    ):
        msg = "ASVS response representation is not the reviewed identity body"
        raise AsvsError(msg)
    return result.body


def fetch_asvs(
    output: Path,
    *,
    downloader: Downloader | None = None,
    publisher: ArtifactPublisher | None = None,
) -> Path:
    """Fetch and exclusively publish the exact pinned ASVS source pair."""
    selected_downloader = downloader or HttpsDownloader()
    selected_publisher = publisher or ExclusiveArtifactPublisher()
    result = selected_downloader.download(ASVS_URL, max_bytes=ASVS_SIZE)
    body = _validated_download_body(result)
    if len(body) != ASVS_SIZE or hashlib.sha256(body).hexdigest() != ASVS_SHA256:
        msg = "ASVS artifact size or SHA-256 does not match the reviewed release"
        raise AsvsError(msg)
    payload = _parse_json_bytes(body)
    if not isinstance(payload, dict):
        msg = "ASVS artifact version is not 5.0.0"
        raise AsvsError(msg)
    payload_map = cast("dict[str, object]", payload)
    if payload_map.get("Version") != "5.0.0":
        msg = "ASVS artifact version is not 5.0.0"
        raise AsvsError(msg)
    selected_publisher.publish_pair(
        (output, body),
        (
            output.parent / "SHA256SUMS",
            f"{ASVS_SHA256}  {output.name}\n".encode("ascii"),
        ),
    )
    return output


def _walk_items(items: object) -> list[AsvsRequirement]:
    if not isinstance(items, list):
        msg = "ASVS Items must be an array"
        raise AsvsError(msg)
    found: list[AsvsRequirement] = []
    for item in cast("list[object]", items):
        if not isinstance(item, dict):
            msg = "ASVS item must be an object"
            raise AsvsError(msg)
        record = cast("dict[str, object]", item)
        if "Description" in record and "L" in record:
            shortcode = record.get("Shortcode")
            description = record.get("Description")
            level = record.get("L")
            level_numbers: dict[str, Literal[1, 2, 3]] = {"1": 1, "2": 2, "3": 3}
            if (
                type(shortcode) is not str
                or type(description) is not str
                or type(level) is not str
                or level not in level_numbers
            ):
                msg = "ASVS requirement has malformed fields"
                raise AsvsError(msg)
            found.append(
                AsvsRequirement(
                    identifier=f"v5.0.0-{shortcode}",
                    text=description,
                    level=level_numbers[level],
                ),
            )
        if "Items" in record:
            found.extend(_walk_items(record["Items"]))
    return found


def load_pinned_asvs_requirements(
    path: Path | None = None,
) -> tuple[AsvsRequirement, ...]:
    """Load the pinned ASVS source and extract its strict requirements."""
    selected_path = (
        path if path is not None else Path("security/asvs/requirements-5.0.0.json")
    )
    body = _read_bounded_regular_file(selected_path, max_bytes=ASVS_SIZE)
    if len(body) != ASVS_SIZE or hashlib.sha256(body).hexdigest() != ASVS_SHA256:
        msg = "checked-in ASVS artifact is not the reviewed immutable source"
        raise AsvsError(msg)
    payload = _parse_json_bytes(body)
    if not isinstance(payload, dict):
        msg = "checked-in ASVS artifact version is invalid"
        raise AsvsError(msg)
    payload_map = cast("dict[str, object]", payload)
    if payload_map.get("Version") != "5.0.0":
        msg = "checked-in ASVS artifact version is invalid"
        raise AsvsError(msg)
    requirements = tuple(_walk_items(payload_map.get("Requirements")))
    level_one = sum(requirement.level == 1 for requirement in requirements)
    level_two = sum(requirement.level == L2_MAX_LEVEL for requirement in requirements)
    if level_one != EXPECTED_L1_REQUIREMENTS or level_two != EXPECTED_L2_REQUIREMENTS:
        msg = "checked-in ASVS artifact did not yield the reviewed 70/183 levels"
        raise AsvsError(msg)
    if len({item.identifier for item in requirements}) != len(requirements):
        msg = "ASVS requirement identifiers are not unique"
        raise AsvsError(msg)
    return requirements


ModelT = TypeVar("ModelT")


@dataclass(frozen=True, slots=True)
class JsonLinesLimits:
    """Carry immutable byte, line, and record ceilings for one JSONL artifact."""

    max_bytes: int
    max_line_bytes: int
    max_records: int
    exact_records: int | None


def _parse_jsonl_record[ModelT](
    line: bytes,
    adapter: TypeAdapter[ModelT],
    limits: JsonLinesLimits,
) -> ModelT:
    if len(line) > limits.max_line_bytes:
        msg = "JSONL record exceeds the configured byte bound"
        raise AsvsError(msg)
    value = _parse_json_bytes(line)
    if _canonical_value(value) != line:
        msg = "JSONL record is not canonical"
        raise AsvsError(msg)
    try:
        return adapter.validate_json(line, strict=True)
    except ValidationError as exc:
        msg = "JSONL record does not match the strict schema"
        raise AsvsError(msg) from exc


def _load_jsonl[ModelT](
    path: Path,
    adapter: TypeAdapter[ModelT],
    limits: JsonLinesLimits,
) -> tuple[ModelT, ...]:
    body = _read_bounded_regular_file(path, max_bytes=limits.max_bytes)
    if not body:
        if limits.exact_records not in {None, 0}:
            msg = "JSONL record count does not match the required product"
            raise AsvsError(msg)
        return ()
    if b"\r" in body or not body.endswith(b"\n"):
        msg = "JSONL must use canonical LF records with a final LF"
        raise AsvsError(msg)
    raw_lines = body[:-1].split(b"\n")
    if any(not line for line in raw_lines):
        msg = "blank JSONL records are forbidden"
        raise AsvsError(msg)
    if len(raw_lines) > limits.max_records:
        msg = "JSONL record count exceeds the configured bound"
        raise AsvsError(msg)
    rows = [_parse_jsonl_record(line, adapter, limits) for line in raw_lines]
    if limits.exact_records is not None and len(rows) != limits.exact_records:
        msg = "JSONL record count does not match the required product"
        raise AsvsError(msg)
    return tuple(rows)


def _load_canonical_json[ModelT](
    path: Path,
    adapter: TypeAdapter[ModelT],
    *,
    max_bytes: int,
) -> ModelT:
    body = _read_bounded_regular_file(path, max_bytes=max_bytes)
    if not body or b"\r" in body or not body.endswith(b"\n"):
        msg = "canonical JSON must be nonempty and end in one LF"
        raise AsvsError(msg)
    value = _parse_json_bytes(body)
    if _canonical(value) != body:
        msg = "JSON artifact is not canonical"
        raise AsvsError(msg)
    try:
        return adapter.validate_json(body, strict=True)
    except ValidationError as exc:
        msg = "JSON artifact does not match the strict schema"
        raise AsvsError(msg) from exc


_EVIDENCE_ROW_ADAPTER: TypeAdapter[EvidenceRow] = TypeAdapter(EvidenceRow)
_EVIDENCE_REFERENCE_ADAPTER: TypeAdapter[EvidenceReference] = TypeAdapter(
    EvidenceReference
)
_EVIDENCE_POLICY_ADAPTER: TypeAdapter[EvidencePolicy] = TypeAdapter(EvidencePolicy)
_THREAT_LEDGER_ADAPTER: TypeAdapter[ThreatLedger] = TypeAdapter(ThreatLedger)


def _validate_matrix_product(rows: tuple[EvidenceRow, ...]) -> None:
    keys = tuple((row.requirement_id, row.profile) for row in rows)
    expected = tuple(sorted(keys, key=_claim_subject_sort_key))
    if len(set(keys)) != len(keys) or keys != expected:
        msg = "matrix claim keys must be unique and canonically ordered"
        raise AsvsError(msg)
    for offset in range(0, len(rows), len(PROFILES)):
        group = rows[offset : offset + len(PROFILES)]
        if (
            len(group) != len(PROFILES)
            or tuple(row.profile for row in group) != PROFILES
            or len({row.requirement_id for row in group}) != 1
            or len({(row.requirement_text, row.level) for row in group}) != 1
        ):
            msg = "matrix must contain one consistent row for every profile"
            raise AsvsError(msg)


def load_evidence_matrix(
    path: Path | None = None,
) -> tuple[EvidenceRow, ...]:
    """Load exactly 759 canonical evidence-matrix records."""
    selected_path = (
        path if path is not None else Path("docs/security/asvs-5.0.0-l2-matrix.jsonl")
    )
    rows = _load_jsonl(
        selected_path,
        _EVIDENCE_ROW_ADAPTER,
        JsonLinesLimits(
            max_bytes=MATRIX_MAX_BYTES,
            max_line_bytes=MATRIX_MAX_LINE_BYTES,
            max_records=MATRIX_RECORDS,
            exact_records=MATRIX_RECORDS,
        ),
    )
    _validate_matrix_product(rows)
    return rows


def load_evidence_manifest(
    path: Path | None = None,
) -> tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...]:
    """Load bounded canonical local and custodied evidence references."""
    selected_path = (
        path if path is not None else Path("docs/security/evidence-manifest.jsonl")
    )
    references = _load_jsonl(
        selected_path,
        _EVIDENCE_REFERENCE_ADAPTER,
        JsonLinesLimits(
            max_bytes=MANIFEST_MAX_BYTES,
            max_line_bytes=MANIFEST_MAX_LINE_BYTES,
            max_records=MANIFEST_MAX_RECORDS,
            exact_records=None,
        ),
    )
    evidence_ids = tuple(reference.evidence_id for reference in references)
    if len(evidence_ids) != len(set(evidence_ids)):
        msg = "evidence manifest identifiers must be globally unique"
        raise AsvsError(msg)
    return references


def load_independent_evidence_policy(path: Path | None = None) -> EvidencePolicy:
    """Load the canonical policy bound to the reviewed inventory subject."""
    selected_path = (
        path if path is not None else Path("docs/security/asvs-evidence-policy.json")
    )
    policy = _load_canonical_json(
        selected_path,
        _EVIDENCE_POLICY_ADAPTER,
        max_bytes=POLICY_MAX_BYTES,
    )
    if (
        policy.asvs_source_commit != ASVS_COMMIT
        or policy.evidence_revision != EVIDENCE_REVISION
        or policy.candidate_tree_sha256 != CANDIDATE_TREE_SHA256
    ):
        msg = "evidence policy provenance does not match the reviewed inventory"
        raise AsvsError(msg)
    return policy


def _safe_local_path(value: str) -> bool:
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or any(ord(char) < CONTROL_CHARACTER_CEILING for char in value)
    ):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and not any(
        part in {"", ".", ".."} for part in path.parts
    )


def _custody_subject_sha256(receipt: CustodyReceipt) -> str:
    subject = {
        "approver_subject": receipt.approver_subject,
        "artifact_object_version": receipt.artifact_object_version,
        "artifact_sha256": receipt.artifact_sha256,
        "asserted_invariant": receipt.asserted_invariant,
        "attestation_commit": receipt.attestation_commit,
        "authority_id": receipt.authority_id,
        "candidate_bundle_sha256": receipt.candidate_bundle_sha256,
        "candidate_tree_sha256": receipt.candidate_tree_sha256,
        "claim_purpose": receipt.claim_purpose,
        "covered_surface": receipt.covered_surface,
        "decision": receipt.decision,
        "deployment_id": receipt.deployment_id,
        "evidence_id": receipt.evidence_id,
        "evidence_revision": receipt.evidence_revision,
        "image_digest": receipt.image_digest,
        "immutable_artifact_uri": receipt.immutable_artifact_uri,
        "kind": receipt.kind,
        "profile": receipt.profile,
        "requirement_id": receipt.requirement_id,
        "reviewer": receipt.reviewer,
        "risk_id": receipt.risk_id,
        "selectors": receipt.selectors,
    }
    return hashlib.sha256(_canonical_value(subject)).hexdigest()


def _verify_custodied_evidence(
    reference: CustodiedEvidenceReference,
    context: EvidenceVerificationContext,
) -> bool:
    authorities = tuple(
        authority
        for authority in context.authorities
        if authority.authority_id == reference.custody_authority_id
    )
    if len(authorities) != 1 or context.replay_registry is None:
        return False
    try:
        receipt = authorities[0].verify_receipt(reference)
    except (AsvsError, OSError, ValidationError):
        return False
    if receipt is None:
        return False
    expected_decision = (
        "risk_approved" if context.risk_id is not None else "evidence_verified"
    )
    if (
        receipt.authority_id != reference.custody_authority_id
        or receipt.receipt_id != reference.custody_receipt_id
        or receipt.immutable_artifact_uri != reference.immutable_artifact_uri
        or receipt.artifact_object_version != reference.artifact_object_version
        or receipt.artifact_sha256 != reference.sha256
        or receipt.evidence_id != reference.evidence_id
        or receipt.kind != reference.kind
        or receipt.claim_purpose != context.claim_purpose
        or receipt.selectors != reference.selectors
        or receipt.reviewer != reference.reviewer
        or receipt.deployment_id != reference.deployment_id
        or receipt.image_digest != reference.image_digest
        or receipt.evidence_revision != context.evidence_revision
        or receipt.candidate_tree_sha256 != context.candidate_tree_sha256
        or receipt.requirement_id != context.requirement_id
        or receipt.profile != context.profile
        or receipt.asserted_invariant != context.asserted_invariant
        or receipt.covered_surface != context.covered_surface
        or receipt.risk_id != context.risk_id
        or receipt.candidate_bundle_sha256 != context.candidate_bundle_sha256
        or receipt.attestation_commit != context.attestation_commit
        or receipt.approver_subject != context.approver_subject
        or receipt.decision != expected_decision
        or receipt.issued_at > context.as_of
        or receipt.expires_at <= context.as_of
    ):
        return False
    return context.replay_registry.accept(
        nonce=receipt.nonce,
        subject_sha256=_custody_subject_sha256(receipt),
    )


def _candidate_binds_local_reference(
    snapshot: VerifiedCandidateSnapshot,
    reference: LocalEvidenceReference,
    context: EvidenceVerificationContext,
) -> bool:
    if (
        snapshot.evidence_revision != context.evidence_revision
        or snapshot.candidate_tree_sha256 != context.candidate_tree_sha256
    ):
        return False
    for selector in reference.selectors:
        matches = tuple(
            binding
            for binding in snapshot.selector_bindings
            if binding.selector == selector
            and binding.claim_purpose == context.claim_purpose
            and binding.kind == reference.kind
            and binding.verifier == reference.verifier
            and binding.artifact_path == reference.artifact_path
            and binding.artifact_sha256 == reference.sha256
            and binding.evidence_revision == reference.evidence_revision
            and binding.candidate_tree_sha256 == reference.candidate_tree_sha256
            and binding.requirement_id == context.requirement_id
            and binding.profile == context.profile
            and binding.asserted_invariant == context.asserted_invariant
            and binding.covered_surface == context.covered_surface
        )
        if len(matches) != 1:
            return False
    return True


def _evidence_reference_matches_context(
    reference: LocalEvidenceReference | CustodiedEvidenceReference,
    context: EvidenceVerificationContext,
) -> bool:
    return (
        reference.evidence_revision == context.evidence_revision
        and reference.candidate_tree_sha256 == context.candidate_tree_sha256
        and context.requirement_id in reference.requirement_ids
        and context.profile in reference.profiles
        and reference.asserted_invariant == context.asserted_invariant
        and reference.covered_surface == context.covered_surface
        and reference.collected_at <= context.as_of < reference.expires_at
    )


def _valid_evidence_snapshot(
    snapshot: EvidenceFileSnapshot,
    candidate: VerifiedCandidateSnapshot,
) -> bool:
    return (
        snapshot.complete
        and snapshot.confined
        and snapshot.stable
        and snapshot.regular
        and snapshot.single_link
        and snapshot.root_device == candidate.root_device
        and snapshot.root_inode == candidate.root_inode
        and snapshot.size == len(snapshot.body)
        and snapshot.size <= MANIFEST_MAX_BYTES
    )


def _verify_local_evidence_body(reference: LocalEvidenceReference, body: bytes) -> bool:
    if hashlib.sha256(body).hexdigest() != reference.sha256:
        return False
    if reference.verifier == "sha256-file-v1":
        return True
    if reference.verifier != "json-record-v1":
        return False
    try:
        parsed = _parse_json_bytes(body)
    except AsvsError:
        return False
    if not isinstance(parsed, dict):
        return False
    return _canonical(cast("dict[str, object]", parsed)) == body


def _candidate_snapshot(
    verifier: CandidateRepositoryVerifier,
    root: Path,
) -> VerifiedCandidateSnapshot | None:
    try:
        return verifier.snapshot(root)
    except (AsvsError, OSError, ValidationError):
        return None


def _local_evidence_snapshot(
    filesystem: EvidenceFileSystem,
    context: EvidenceVerificationContext,
    reference: LocalEvidenceReference,
) -> EvidenceFileSnapshot | None:
    try:
        return filesystem.read_bounded(
            context.root,
            reference.artifact_path,
            max_bytes=MANIFEST_MAX_BYTES,
        )
    except AsvsError:
        return None


def _verify_local_evidence(
    reference: LocalEvidenceReference,
    context: EvidenceVerificationContext,
    filesystem: EvidenceFileSystem | None,
    candidate_verifier: CandidateRepositoryVerifier | None,
) -> bool:
    if (
        not _safe_local_path(reference.artifact_path)
        or context.verified_candidate is None
        or candidate_verifier is None
    ):
        return False
    candidate_before = _candidate_snapshot(candidate_verifier, context.root)
    if (
        candidate_before is None
        or candidate_before != context.verified_candidate
        or not _candidate_binds_local_reference(candidate_before, reference, context)
    ):
        return False
    selected_filesystem = filesystem or DescriptorEvidenceFileSystem()
    snapshot = _local_evidence_snapshot(selected_filesystem, context, reference)
    if (
        snapshot is None
        or not _valid_evidence_snapshot(snapshot, candidate_before)
        or not _verify_local_evidence_body(reference, snapshot.body)
    ):
        return False
    candidate_after = _candidate_snapshot(candidate_verifier, context.root)
    return candidate_after == candidate_before


def verify_evidence_reference(
    reference: LocalEvidenceReference | CustodiedEvidenceReference,
    *,
    context: EvidenceVerificationContext,
    filesystem: EvidenceFileSystem | None = None,
    candidate_verifier: CandidateRepositoryVerifier | None = None,
) -> bool:
    """Verify one evidence reference without executing artifact text."""
    if not _evidence_reference_matches_context(reference, context):
        return False
    if isinstance(reference, CustodiedEvidenceReference):
        return _verify_custodied_evidence(reference, context)
    return _verify_local_evidence(
        reference,
        context,
        filesystem,
        candidate_verifier,
    )


class BoundedGitRunner:
    """Run reviewed Git commands with closed inputs and bounded output."""

    def run(self, request: GitCommandRequest) -> GitCommandResult:
        """Execute one Git request and terminate all remaining descendants."""
        return _run_bounded_git(request)


GIT_EXECUTABLE = Path("/usr/bin/git")
GIT_CLOSED_ENV: tuple[tuple[str, str], ...] = (
    ("GIT_ASKPASS", "/bin/false"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CEILING_DIRECTORIES", "/"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("HOME", "/nonexistent"),
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("SSH_ASKPASS", "/bin/false"),
)


def _terminate_git_process(process: subprocess.Popen[bytes]) -> int:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        returncode = process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        return process.wait()
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    return returncode


def _validate_git_execution_inputs(request: GitCommandRequest) -> dict[str, str]:
    argv = request.argv
    if (
        not argv
        or argv[0] != os.fspath(GIT_EXECUTABLE)
        or len(argv) > MAX_HEADER_NAME_LENGTH
        or any(
            not value or "\x00" in value or len(value) > MAX_HEADER_VALUE_LENGTH
            for value in argv
        )
    ):
        msg = "Git argv is not a bounded absolute reviewed command"
        raise AsvsError(msg)
    try:
        executable = GIT_EXECUTABLE.lstat()
        requested_identity = request.cwd.stat()
    except OSError as exc:
        msg = "Git execution identity cannot be verified"
        raise AsvsError(msg) from exc
    if (
        not stat.S_ISREG(executable.st_mode)
        or executable.st_nlink != 1
        or GIT_EXECUTABLE.is_symlink()
        or executable.st_uid != 0
        or executable.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or request.cwd != Path("/")
        or not stat.S_ISDIR(requested_identity.st_mode)
    ):
        msg = "Git executable or working directory is not the reviewed identity"
        raise AsvsError(msg)
    if (
        not 0 < request.timeout_seconds <= MAX_GIT_TIMEOUT_SECONDS
        or not 0 < request.max_stdout_bytes <= MAX_GIT_OUTPUT_BYTES
        or not 0 < request.max_stderr_bytes <= MAX_GIT_OUTPUT_BYTES
    ):
        msg = "Git execution limits are outside the reviewed bounds"
        raise AsvsError(msg)
    environment: dict[str, str] = {}
    for key, value in request.env:
        if (
            not key
            or key in environment
            or "=" in key
            or "\x00" in key + value
            or len(key) > MAX_HEADER_NAME_LENGTH
            or len(value) > MAX_HEADER_VALUE_LENGTH
        ):
            msg = "Git environment is malformed or duplicated"
            raise AsvsError(msg)
        environment[key] = value
    return environment


def _append_bounded_stream(
    target: bytearray,
    chunk: bytes,
    ceiling: int,
) -> bool:
    remaining = ceiling - len(target)
    if len(chunk) <= remaining:
        target.extend(chunk)
        return False
    if remaining > 0:
        target.extend(chunk[:remaining])
    return True


def _spawn_git_process(
    request: GitCommandRequest,
    environment: dict[str, str],
) -> tuple[subprocess.Popen[bytes], int, int]:
    stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
    stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
    try:
        # Security rationale: argv[0] is the immutable reviewed /usr/bin/git.
        # Tuple argv, cwd=/, closed env, no shell, output bounds, and timeout are
        # validated above; see https://github.com/astral-sh/ruff/issues/4045.
        process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603
            request.argv,
            executable=request.argv[0],
            stdin=subprocess.DEVNULL,
            stdout=stdout_write,
            stderr=stderr_write,
            cwd=request.cwd,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        os.close(stdout_read)
        os.close(stdout_write)
        os.close(stderr_read)
        os.close(stderr_write)
        msg = "Git process could not be started"
        raise AsvsError(msg) from exc
    os.close(stdout_write)
    os.close(stderr_write)
    os.set_blocking(stdout_read, False)
    os.set_blocking(stderr_read, False)
    return process, stdout_read, stderr_read


type _GitStreamName = Literal["stdout", "stderr"]


@dataclass(slots=True)
class _GitCaptureBuffers:
    descriptors: dict[int, _GitStreamName]
    poller: select.poll
    streams: dict[_GitStreamName, bytearray]
    overflow: dict[_GitStreamName, bool]


def _consume_git_event(
    descriptor: int,
    capture: _GitCaptureBuffers,
    request: GitCommandRequest,
) -> None:
    stream_name = capture.descriptors.get(descriptor)
    if stream_name is None:
        return
    try:
        chunk = os.read(descriptor, 65_536)
    except BlockingIOError:
        return
    if not chunk:
        capture.poller.unregister(descriptor)
        del capture.descriptors[descriptor]
        return
    ceiling = (
        request.max_stdout_bytes
        if stream_name == "stdout"
        else request.max_stderr_bytes
    )
    capture.overflow[stream_name] = _append_bounded_stream(
        capture.streams[stream_name],
        chunk,
        ceiling,
    )


def _capture_git_process(
    process: subprocess.Popen[bytes],
    stdout_read: int,
    stderr_read: int,
    request: GitCommandRequest,
) -> GitCommandResult:
    poller = select.poll()
    descriptors: dict[int, _GitStreamName] = {
        stdout_read: "stdout",
        stderr_read: "stderr",
    }
    for descriptor in descriptors:
        poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    streams: dict[_GitStreamName, bytearray] = {
        "stdout": bytearray(),
        "stderr": bytearray(),
    }
    overflow: dict[_GitStreamName, bool] = {"stdout": False, "stderr": False}
    capture = _GitCaptureBuffers(
        descriptors=descriptors,
        poller=poller,
        streams=streams,
        overflow=overflow,
    )
    timed_out = False
    deadline = time.monotonic() + request.timeout_seconds
    returncode: int | None = None
    try:
        while descriptors and not any(overflow.values()):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = poller.poll(max(1, int(remaining * 1_000)))
            if not events:
                timed_out = True
                break
            for descriptor, _event in events:
                _consume_git_event(
                    descriptor,
                    capture,
                    request,
                )
        if timed_out or any(overflow.values()):
            returncode = _terminate_git_process(process)
        else:
            returncode = process.wait()
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
    finally:
        if returncode is None:
            returncode = _terminate_git_process(process)
        os.close(stdout_read)
        os.close(stderr_read)
    return GitCommandResult(
        returncode=returncode,
        stdout=bytes(streams["stdout"]),
        stderr=bytes(streams["stderr"]),
        complete=not timed_out and not any(overflow.values()) and not descriptors,
        timed_out=timed_out,
        stdout_overflow=overflow["stdout"],
        stderr_overflow=overflow["stderr"],
    )


def _run_bounded_git(request: GitCommandRequest) -> GitCommandResult:
    environment = _validate_git_execution_inputs(request)
    process, stdout_read, stderr_read = _spawn_git_process(request, environment)
    return _capture_git_process(process, stdout_read, stderr_read, request)


def verify_ref(runner: GitRunner | None = None) -> bool:
    """Verify the immutable ASVS tag mapping through the bounded Git seam."""
    selected_runner = runner or BoundedGitRunner()
    try:
        executable_stat = GIT_EXECUTABLE.lstat()
    except OSError:
        return False
    if (
        not GIT_EXECUTABLE.is_absolute()
        or not stat.S_ISREG(executable_stat.st_mode)
        or executable_stat.st_nlink != 1
        or GIT_EXECUTABLE.is_symlink()
    ):
        return False
    try:
        result = selected_runner.run(
            GitCommandRequest(
                argv=(
                    os.fspath(GIT_EXECUTABLE),
                    "ls-remote",
                    "--refs",
                    "https://github.com/OWASP/ASVS.git",
                    ASVS_RELEASE_REF,
                ),
                timeout_seconds=30,
                max_stdout_bytes=4_096,
                max_stderr_bytes=4_096,
                env=GIT_CLOSED_ENV,
                cwd=Path("/"),
            )
        )
    except (AsvsError, OSError, subprocess.SubprocessError):
        return False
    if (
        result.returncode != 0
        or result.stderr
        or not result.complete
        or result.timed_out
        or result.stdout_overflow
        or result.stderr_overflow
        or len(result.stdout) > VERIFY_REF_OUTPUT_BYTES
    ):
        return False
    return result.stdout == f"{ASVS_COMMIT}\t{ASVS_RELEASE_REF}\n".encode("ascii")


def build_matrix(
    output: Path | None = None,
    *,
    requirements_path: Path | None = None,
) -> Path:
    """Build a new matrix file from the exact pinned requirement source."""
    selected_output = (
        output
        if output is not None
        else Path("docs/security/asvs-5.0.0-l2-matrix.jsonl")
    )
    requirements = load_pinned_asvs_requirements(requirements_path)
    _atomic_write(selected_output, render_evidence_matrix(requirements))
    return selected_output


def render_evidence_matrix(
    requirements: tuple[AsvsRequirement, ...],
) -> bytes:
    """Render the exact canonical 253-by-three unassessed matrix."""
    selected_requirements = tuple(
        sorted(
            (
                requirement
                for requirement in requirements
                if requirement.level <= L2_MAX_LEVEL
            ),
            key=_requirement_sort_key,
        )
    )
    if (
        len(selected_requirements) != L1_L2_REQUIREMENT_COUNT
        or len({item.identifier for item in selected_requirements})
        != L1_L2_REQUIREMENT_COUNT
    ):
        msg = "matrix generation requires exactly 253 unique L1/L2 requirements"
        raise AsvsError(msg)
    boundaries: dict[Profile, CaseId] = {
        "alpic-metadata": "client-to-alpic-edge",
        "private-full": "backend-to-nplg-jwks",
        "distributed-full": "scanner-to-pdf-worker",
    }
    rows: list[bytes] = []
    for requirement in selected_requirements:
        matrix_level = cast("Literal[1, 2]", requirement.level)
        for profile in PROFILES:
            row = ApplicableEvidenceRow(
                asvs_version="5.0.0",
                requirement_id=requirement.identifier,
                level=matrix_level,
                requirement_text=requirement.text,
                profile=profile,
                evidence_revision=EVIDENCE_REVISION,
                invariant=(
                    f"Evidence for {requirement.identifier} remains unassessed for "
                    f"the {profile} profile."
                ),
                threat_boundary=boundaries[profile],
                evidence_ids=(),
                required_evidence_kinds=(),
                owner="security-team",
                target_phase="phase-0",
                evidence_date=date(2026, 8, 16),
                applicability="applicable",
                applicability_rationale=(
                    "The requirement remains conservatively applicable until a "
                    "profile-specific review proves otherwise."
                ),
                verdict="Not assessed",
            )
            rows.append(
                _canonical(
                    cast(
                        "object",
                        row.model_dump(mode="json", exclude_none=True),
                    )
                )
            )
    return b"".join(rows)


def render_evidence_policy(
    requirements: tuple[AsvsRequirement, ...],
) -> bytes:
    """Render the canonical independent policy for all matrix claims."""
    claims = tuple(
        sorted(
            (
                ClaimPolicyRecord(
                    requirement_id=requirement.identifier,
                    profile=profile,
                    pass_required_kinds=None,
                    na_absence_required=False,
                    risk_acceptance_authority_id=None,
                )
                for requirement in requirements
                if requirement.level <= L2_MAX_LEVEL
                for profile in PROFILES
            ),
            key=_policy_claim_sort_key,
        )
    )
    policy = EvidencePolicy(
        schema_version="2.0",
        asvs_version="5.0.0",
        asvs_source_commit=ASVS_COMMIT,
        evidence_revision=EVIDENCE_REVISION,
        candidate_tree_sha256=CANDIDATE_TREE_SHA256,
        attestation_allowlist=ATTESTATION_ALLOWLIST,
        profiles=PROFILES,
        claims=claims,
        custody_authority_ids=(),
        release_authority_ids=(),
    )
    return _canonical(cast("object", policy.model_dump(mode="json")))


def _joined_text(*parts: str) -> str:
    return "".join(parts)


def render_threat_ledger() -> bytes:
    """Render the canonical unresolved threat ledger as JSON."""
    review_due = date(2026, 12, 31)
    nodes = (
        ThreatNode(
            node_id="alpic-edge",
            node_kind="provider",
            trust_zone="edge-provider-zone",
            privileges=("route-mcp-traffic",),
            data_classes=(
                "access-tokens",
                "deployment-provenance",
                "mcp-envelopes",
            ),
        ),
        ThreatNode(
            node_id="audit-log-store",
            node_kind="data-store",
            trust_zone="operations-zone",
            privileges=("retain-audit-events",),
            data_classes=("audit-events",),
        ),
        ThreatNode(
            node_id="ci-build",
            node_kind="service",
            trust_zone="build-zone",
            privileges=("publish-deployment-artifacts",),
            data_classes=("deployment-provenance",),
        ),
        ThreatNode(
            node_id="content-store",
            node_kind="data-store",
            trust_zone="content-zone",
            privileges=("store-public-content",),
            data_classes=("public-content", "derived-images"),
        ),
        ThreatNode(
            node_id="external-client",
            node_kind="external",
            trust_zone="untrusted-client-zone",
            privileges=("submit-mcp-request",),
            data_classes=("access-tokens", "mcp-envelopes"),
        ),
        ThreatNode(
            node_id="jwks-provider",
            node_kind="provider",
            trust_zone="identity-provider-zone",
            privileges=("publish-verification-keys",),
            data_classes=("access-tokens",),
        ),
        ThreatNode(
            node_id="nplg-api",
            node_kind="provider",
            trust_zone="nplg-upstream-zone",
            privileges=("serve-public-repository-content",),
            data_classes=("public-content", "repository-locators"),
        ),
        ThreatNode(
            node_id="pdf-worker",
            node_kind="worker",
            trust_zone="isolated-parser-zone",
            privileges=("render-untrusted-pdf",),
            data_classes=("public-content", "derived-images"),
        ),
        ThreatNode(
            node_id="python-backend",
            node_kind="service",
            trust_zone="application-zone",
            privileges=("authorize-and-dispatch", "fetch-public-content"),
            data_classes=(
                "access-tokens",
                "audit-events",
                "mcp-envelopes",
                "public-content",
                "repository-locators",
            ),
        ),
        ThreatNode(
            node_id="scanner",
            node_kind="worker",
            trust_zone="isolated-scanner-zone",
            privileges=("classify-untrusted-content",),
            data_classes=("public-content",),
        ),
    )
    flows = (
        ThreatFlow(
            flow_id="flow-backend-jwks",
            source="python-backend",
            target="jwks-provider",
            boundary_id="backend-to-nplg-jwks",
            protocol="HTTPS JWKS retrieval",
            data_classes=("access-tokens",),
        ),
        ThreatFlow(
            flow_id="flow-backend-log",
            source="python-backend",
            target="audit-log-store",
            boundary_id="logging-privacy",
            protocol="Structured audit event transport",
            data_classes=("audit-events",),
        ),
        ThreatFlow(
            flow_id="flow-backend-nplg",
            source="python-backend",
            target="nplg-api",
            boundary_id="backend-to-nplg-upstream",
            protocol="Bounded HTTPS repository request",
            data_classes=("public-content", "repository-locators"),
        ),
        ThreatFlow(
            flow_id="flow-ci-edge",
            source="ci-build",
            target="alpic-edge",
            boundary_id="build-to-deploy",
            protocol="Provider deployment publication",
            data_classes=("deployment-provenance",),
        ),
        ThreatFlow(
            flow_id="flow-client-edge",
            source="external-client",
            target="alpic-edge",
            boundary_id="client-to-alpic-edge",
            protocol="MCP over HTTPS",
            data_classes=("access-tokens", "mcp-envelopes"),
        ),
        ThreatFlow(
            flow_id="flow-content-pdf",
            source="content-store",
            target="pdf-worker",
            boundary_id="scanner-to-pdf-worker",
            protocol="Descriptor-bound worker input",
            data_classes=("public-content", "derived-images"),
        ),
        ThreatFlow(
            flow_id="flow-edge-backend",
            source="alpic-edge",
            target="python-backend",
            boundary_id="alpic-edge-to-backend",
            protocol="Forwarded MCP request",
            data_classes=("access-tokens", "mcp-envelopes"),
        ),
        ThreatFlow(
            flow_id="flow-scanner-content",
            source="scanner",
            target="content-store",
            boundary_id="scanner-to-content-store",
            protocol="Digest-bound scan verdict",
            data_classes=("public-content",),
        ),
    )
    entry_points = (
        ThreatEntryPoint(
            entry_point_id="entry-alpic-forward",
            flow_id="flow-edge-backend",
            exposed_node_id="python-backend",
            access_control="application-enforced",
            affected_profiles=PROFILES,
            data_classes=("access-tokens", "mcp-envelopes"),
        ),
        ThreatEntryPoint(
            entry_point_id="entry-audit-log-store",
            flow_id="flow-backend-log",
            exposed_node_id="audit-log-store",
            access_control="trusted-workload",
            affected_profiles=PROFILES,
            data_classes=("audit-events",),
        ),
        ThreatEntryPoint(
            entry_point_id="entry-content-store",
            flow_id="flow-scanner-content",
            exposed_node_id="content-store",
            access_control="application-enforced",
            affected_profiles=("private-full", "distributed-full"),
            data_classes=("public-content",),
        ),
        ThreatEntryPoint(
            entry_point_id="entry-deployment-publication",
            flow_id="flow-ci-edge",
            exposed_node_id="alpic-edge",
            access_control="trusted-workload",
            affected_profiles=PROFILES,
            data_classes=("deployment-provenance",),
        ),
        ThreatEntryPoint(
            entry_point_id="entry-jwks-provider",
            flow_id="flow-backend-jwks",
            exposed_node_id="jwks-provider",
            access_control="provider-mediated",
            affected_profiles=PROFILES,
            data_classes=("access-tokens",),
        ),
        ThreatEntryPoint(
            entry_point_id="entry-nplg-repository-api",
            flow_id="flow-backend-nplg",
            exposed_node_id="nplg-api",
            access_control="provider-mediated",
            affected_profiles=PROFILES,
            data_classes=("public-content", "repository-locators"),
        ),
        ThreatEntryPoint(
            entry_point_id="entry-pdf-worker",
            flow_id="flow-content-pdf",
            exposed_node_id="pdf-worker",
            access_control="application-enforced",
            affected_profiles=("private-full", "distributed-full"),
            data_classes=("public-content", "derived-images"),
        ),
        ThreatEntryPoint(
            entry_point_id="entry-public-mcp",
            flow_id="flow-client-edge",
            exposed_node_id="alpic-edge",
            access_control="provider-mediated",
            affected_profiles=PROFILES,
            data_classes=("access-tokens", "mcp-envelopes"),
        ),
    )
    provider_assumptions = (
        ProviderAssumption(
            assumption_id="alpic-routing-contract",
            provider="alpic",
            control=(
                "Assumption only: the edge preserves the reviewed MCP route and "
                "authorization context; no provider evidence currently verifies it."
            ),
            owner="platform-owner",
            status="assumption-unverified",
            invalidation_trigger="deployment-change",
        ),
        ProviderAssumption(
            assumption_id="audit-log-custody",
            provider="operations-platform",
            control=(
                "Assumption only: audit storage enforces access, retention, and "
                "integrity policy; no operational evidence currently verifies it."
            ),
            owner="security-operations-owner",
            status="assumption-unverified",
            invalidation_trigger="storage-change",
        ),
        ProviderAssumption(
            assumption_id="build-runtime-custody",
            provider="ci-and-alpic",
            control=(
                "Assumption only: build and deployment identities preserve the "
                "reviewed artifact; no external attestation currently verifies it."
            ),
            owner="release-owner",
            status="assumption-unverified",
            invalidation_trigger="dependency-change",
        ),
        ProviderAssumption(
            assumption_id="jwks-publication-contract",
            provider="identity-provider",
            control=(
                "Assumption only: the selected issuer publishes authentic, timely "
                "verification keys; no provider has been selected or verified."
            ),
            owner="identity-owner",
            status="assumption-unverified",
            invalidation_trigger="auth-change",
        ),
        ProviderAssumption(
            assumption_id="nplg-upstream-contract",
            provider="nplg",
            control=(
                "Assumption only: the configured NPLG origin serves the intended "
                "public repository representation; live provenance is unverified."
            ),
            owner="repository-owner",
            status="assumption-unverified",
            invalidation_trigger="protocol-change",
        ),
    )
    threats = (
        ThreatRecord(
            threat_id="threat-auth-token-spoofing",
            title="Spoofed or replayed authorization token",
            flow_ids=("flow-backend-jwks", "flow-edge-backend"),
            boundary_ids=("alpic-edge-to-backend", "backend-to-nplg-jwks"),
            stride_categories=("S",),
            abuse_categories=("token-session",),
            abuse_case=(
                "An attacker submits a token with an invalid signature, issuer, type, "
                "audience, lifetime, or replay context and attempts privileged use."
            ),
            affected_profiles=PROFILES,
            mitigations=(
                _joined_text(
                    "Required control: validate signature, issuer, type, audience, ",
                    "and time claims in a trusted backend.",
                ),
                _joined_text(
                    "Required control: bind session and token context to the ",
                    "selected provider contract; evidence remains Not assessed.",
                ),
            ),
            verification_selectors=(
                "oauth-provider-capability-contract",
                "sdk-authorization-capability-contract",
            ),
            asvs_requirement_ids=(
                "v5.0.0-V10.3.1",
                "v5.0.0-V6.8.2",
                "v5.0.0-V7.2.1",
                "v5.0.0-V9.2.2",
            ),
            assumed_provider_control_ids=(
                "alpic-routing-contract",
                "jwks-publication-contract",
            ),
            residual_risk_id="risk-auth-token-spoofing",
            owner="identity-owner",
            verification_status="not_assessed",
            review_due=review_due,
            invalidation_triggers=("auth-change", "deployment-change"),
        ),
        ThreatRecord(
            threat_id="threat-confused-deputy",
            title="Edge or backend acts with authority not granted to the caller",
            flow_ids=("flow-client-edge", "flow-edge-backend"),
            boundary_ids=("alpic-edge-to-backend", "client-to-alpic-edge"),
            stride_categories=("T",),
            abuse_categories=("confused-deputy",),
            abuse_case=(
                "An attacker manipulates forwarded routing or authorization context so "
                "that a more privileged component performs an unauthorized operation."
            ),
            affected_profiles=PROFILES,
            mitigations=(
                _joined_text(
                    "Required control: authorize each tool and object action against ",
                    "explicit caller permissions.",
                ),
                _joined_text(
                    "Required control: validate edge forwarding and ",
                    "protected-resource contracts; evidence remains Not assessed.",
                ),
            ),
            verification_selectors=(
                "alpic-oauth-discovery-contract",
                "mcp-tool-authorization-contract",
            ),
            asvs_requirement_ids=("v5.0.0-V8.2.1", "v5.0.0-V8.2.2"),
            assumed_provider_control_ids=("alpic-routing-contract",),
            residual_risk_id="risk-confused-deputy",
            owner="application-security-owner",
            verification_status="not_assessed",
            review_due=review_due,
            invalidation_triggers=(
                "auth-change",
                "profile-or-boundary-change",
                "protocol-change",
            ),
        ),
        ThreatRecord(
            threat_id="threat-log-repudiation",
            title="Sensitive, forgeable, or incomplete security audit trail",
            flow_ids=("flow-backend-log",),
            boundary_ids=("logging-privacy",),
            stride_categories=("R",),
            abuse_categories=("logging-privacy",),
            abuse_case=(
                "An attacker injects misleading log data, causes security events to be "
                "omitted, or causes credentials and personal data to enter logs."
            ),
            affected_profiles=PROFILES,
            mitigations=(
                _joined_text(
                    "Required control: maintain a field-level logging inventory and ",
                    "encode untrusted values.",
                ),
                _joined_text(
                    "Required control: exclude or irreversibly mask credentials and ",
                    "tokens; operational evidence remains Not assessed.",
                ),
            ),
            verification_selectors=(
                "audit-event-schema",
                "credential-canary-log-test",
            ),
            asvs_requirement_ids=(
                "v5.0.0-V16.1.1",
                "v5.0.0-V16.2.5",
                "v5.0.0-V16.4.1",
            ),
            assumed_provider_control_ids=("audit-log-custody",),
            residual_risk_id="risk-log-repudiation",
            owner="security-operations-owner",
            verification_status="not_assessed",
            review_due=review_due,
            invalidation_triggers=("runtime-change", "storage-change"),
        ),
        ThreatRecord(
            threat_id="threat-parser-exhaustion",
            title="Untrusted document exhausts scanner or PDF worker resources",
            flow_ids=("flow-content-pdf", "flow-scanner-content"),
            boundary_ids=("scanner-to-content-store", "scanner-to-pdf-worker"),
            stride_categories=("D",),
            abuse_categories=("parser-resource-exhaustion",),
            abuse_case=(
                "A malicious or pathological document consumes excessive bytes, files, "
                "pages, CPU, memory, descriptors, or worker lifetime."
            ),
            affected_profiles=("private-full", "distributed-full"),
            mitigations=(
                _joined_text(
                    "Required control: enforce pre-dispatch size, count, page, ",
                    "timeout, and quota ceilings.",
                ),
                _joined_text(
                    "Required control: isolate scanning and rendering and reject ",
                    "unverifiable scan state; evidence remains Not assessed.",
                ),
            ),
            verification_selectors=(
                "pdf-worker-resource-fault-suite",
                "scanner-content-binding-suite",
            ),
            asvs_requirement_ids=(
                "v5.0.0-V5.1.1",
                "v5.0.0-V5.2.1",
                "v5.0.0-V5.2.3",
                "v5.0.0-V5.4.3",
            ),
            assumed_provider_control_ids=("nplg-upstream-contract",),
            residual_risk_id="risk-parser-exhaustion",
            owner="content-security-owner",
            verification_status="not_assessed",
            review_due=review_due,
            invalidation_triggers=(
                "dependency-change",
                "runtime-change",
                "storage-change",
            ),
        ),
        ThreatRecord(
            threat_id="threat-ssrf-proxy",
            title="Repository locator becomes an SSRF, DNS, redirect, or proxy pivot",
            flow_ids=("flow-backend-nplg",),
            boundary_ids=("backend-to-nplg-upstream",),
            stride_categories=("I",),
            abuse_categories=("ssrf-dns-proxy",),
            abuse_case=(
                "An attacker supplies or influences a locator that reaches a private, "
                "rebinding, redirected, or ambient-proxy destination."
            ),
            affected_profiles=PROFILES,
            mitigations=(
                _joined_text(
                    "Required control: allowlist origin, scheme, port, and path and ",
                    "bind every connection to reviewed addresses.",
                ),
                _joined_text(
                    "Required control: disable ambient proxies and credentials and ",
                    "revalidate redirects; evidence remains Not assessed.",
                ),
            ),
            verification_selectors=(
                "downloader-rebinding-fault-suite",
                "repository-origin-policy",
            ),
            asvs_requirement_ids=(
                "v5.0.0-V1.3.6",
                "v5.0.0-V13.2.4",
                "v5.0.0-V13.2.5",
            ),
            assumed_provider_control_ids=("nplg-upstream-contract",),
            residual_risk_id="risk-ssrf-proxy",
            owner="network-security-owner",
            verification_status="not_assessed",
            review_due=review_due,
            invalidation_triggers=("protocol-change", "runtime-change"),
        ),
        ThreatRecord(
            threat_id="threat-supply-chain",
            title="Build or deployment provenance is substituted",
            flow_ids=("flow-ci-edge",),
            boundary_ids=("build-to-deploy",),
            stride_categories=("E",),
            abuse_categories=("supply-chain-build-deploy",),
            abuse_case=(
                "A compromised dependency, build runner, artifact mirror, or provider "
                "publishes code or configuration outside the reviewed candidate."
            ),
            affected_profiles=PROFILES,
            mitigations=(
                _joined_text(
                    "Required control: verify exact lock identities and an SBOM ",
                    "against resolved components from trusted repositories, ",
                    "including component freshness, with bounded bootstrap ",
                    "verification and atomic publication.",
                ),
                _joined_text(
                    "Required control: apply documented, risk-ranked remediation ",
                    "timeframes to known-vulnerable and outdated components before ",
                    "release.",
                ),
                _joined_text(
                    "Required control: bind provider deployment identity to an ",
                    "external attestation; evidence remains Not assessed.",
                ),
            ),
            verification_selectors=(
                "bootstrap-toolchain-fault-suite",
                "deployment-provenance-attestation",
            ),
            asvs_requirement_ids=(
                "v5.0.0-V15.1.1",
                "v5.0.0-V15.1.2",
                "v5.0.0-V15.2.1",
            ),
            assumed_provider_control_ids=(
                "alpic-routing-contract",
                "build-runtime-custody",
            ),
            residual_risk_id="risk-supply-chain",
            owner="release-owner",
            verification_status="not_assessed",
            review_due=review_due,
            invalidation_triggers=("dependency-change", "deployment-change"),
        ),
    )
    residual_risks = (
        ResidualRiskRecord(
            residual_risk_id="risk-auth-token-spoofing",
            threat_ids=("threat-auth-token-spoofing",),
            description=(
                "Issuer, key-rotation, audience, and replay behavior remain unverified "
                "until a provider is selected and externally evidenced."
            ),
            disposition="open-do-not-release",
            owner="identity-owner",
            review_due=review_due,
        ),
        ResidualRiskRecord(
            residual_risk_id="risk-confused-deputy",
            threat_ids=("threat-confused-deputy",),
            description=(
                "The exact edge rewrite and authorization propagation contract remains "
                "unverified for every deployment profile."
            ),
            disposition="open-do-not-release",
            owner="application-security-owner",
            review_due=review_due,
        ),
        ResidualRiskRecord(
            residual_risk_id="risk-log-repudiation",
            threat_ids=("threat-log-repudiation",),
            description=(
                "Operational log custody, retention, access, redaction, and integrity "
                "have no approved evidence artifact."
            ),
            disposition="open-do-not-release",
            owner="security-operations-owner",
            review_due=review_due,
        ),
        ResidualRiskRecord(
            residual_risk_id="risk-parser-exhaustion",
            threat_ids=("threat-parser-exhaustion",),
            description=(
                "Effective scanner and PDF-worker kernel limits are not yet evidenced "
                "against hostile full-profile workloads."
            ),
            disposition="open-do-not-release",
            owner="content-security-owner",
            review_due=review_due,
        ),
        ResidualRiskRecord(
            residual_risk_id="risk-ssrf-proxy",
            threat_ids=("threat-ssrf-proxy",),
            description=_joined_text(
                "Live DNS, peer-address, redirect, TLS, and proxy behavior has not ",
                "been verified in each target runtime.",
            ),
            disposition="open-do-not-release",
            owner="network-security-owner",
            review_due=review_due,
        ),
        ResidualRiskRecord(
            residual_risk_id="risk-supply-chain",
            threat_ids=("threat-supply-chain",),
            description=(
                "No approved external release attestation currently binds the reviewed "
                "candidate to a provider deployment identity."
            ),
            disposition="open-do-not-release",
            owner="release-owner",
            review_due=review_due,
        ),
    )
    ledger = ThreatLedger(
        schema_version="1.0",
        evidence_revision=EVIDENCE_REVISION,
        candidate_tree_sha256=CANDIDATE_TREE_SHA256,
        assets=(
            "audit-evidence",
            "content-artifacts",
            "credentials-and-signing-material",
            "deployment-artifacts",
            "mcp-protocol-state",
            "public-repository-metadata",
        ),
        data_classes=(
            "access-tokens",
            "audit-events",
            "deployment-provenance",
            "derived-images",
            "mcp-envelopes",
            "public-content",
            "repository-locators",
        ),
        actors=(
            "deployment-operator",
            "edge-provider",
            "external-client",
            "malicious-client",
            "supply-chain-adversary",
            "untrusted-upstream",
        ),
        nodes=nodes,
        flows=flows,
        entry_points=entry_points,
        provider_assumptions=provider_assumptions,
        threats=threats,
        residual_risks=residual_risks,
        global_invalidation_triggers=(
            "auth-change",
            "dependency-change",
            "deployment-change",
            "profile-or-boundary-change",
            "protocol-change",
            "runtime-change",
            "storage-change",
        ),
        release_status="do_not_release",
    )
    return _canonical(cast("object", ledger.model_dump(mode="json")))


def render_threat_model_markdown(ledger: ThreatLedger) -> bytes:
    """Derive the human-readable threat model from its strict ledger."""

    def markdown_cell(value: str) -> str:
        return (
            value.replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    def joined(values: tuple[str, ...]) -> str:
        return markdown_cell(", ".join(values))

    def mermaid_identifier(value: str) -> str:
        return "node_" + hashlib.sha256(value.encode("ascii")).hexdigest()[:12]

    lines = [
        "# Phase 0-1 threat model",
        "",
        _joined_text(
            "This document is derived deterministically from `threat-model.json`. ",
            "It records required controls and unverified assumptions. It does not ",
            "claim that any ASVS requirement has passed, and the release status is ",
            "`do_not_release`.",
        ),
        "",
        "## Provenance and status",
        "",
        f"- Evidence revision: `{ledger.evidence_revision}`",
        f"- Candidate tree SHA-256: `{ledger.candidate_tree_sha256}`",
        f"- Release status: `{ledger.release_status}`",
        "- Threat verification status: `not_assessed`",
        "- Provider-control status: `assumption-unverified`",
        "",
        "## Assets",
        "",
        *(f"- `{item}`" for item in ledger.assets),
        "",
        "## Data classes",
        "",
        *(f"- `{item}`" for item in ledger.data_classes),
        "",
        "## Actors",
        "",
        *(f"- `{item}`" for item in ledger.actors),
        "",
        "## Nodes and privileges",
        "",
        "| Node | Kind | Trust zone | Privileges | Data classes |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines.extend(
        "| "
        + " | ".join(
            (
                markdown_cell(node.node_id),
                node.node_kind,
                markdown_cell(node.trust_zone),
                joined(node.privileges),
                joined(node.data_classes),
            )
        )
        + " |"
        for node in ledger.nodes
    )
    lines.extend(
        (
            "",
            "## Entry points",
            "",
            _joined_text(
                "| Entry point | Flow | Exposed node | Access control | Profiles | ",
                "Data classes |",
            ),
            "| --- | --- | --- | --- | --- | --- |",
        )
    )
    lines.extend(
        "| "
        + " | ".join(
            (
                markdown_cell(entry.entry_point_id),
                markdown_cell(entry.flow_id),
                markdown_cell(entry.exposed_node_id),
                entry.access_control,
                joined(entry.affected_profiles),
                joined(entry.data_classes),
            )
        )
        + " |"
        for entry in ledger.entry_points
    )
    lines.extend(
        (
            "",
            "## Data-flow diagram",
            "",
            "```mermaid",
            "flowchart LR",
        )
    )
    lines.extend(
        f'    {mermaid_identifier(node.node_id)}["{node.node_id}"]'
        for node in ledger.nodes
    )
    lines.extend(
        _joined_text(
            "    ",
            f'{mermaid_identifier(flow.source)} -->|"{flow.flow_id} / ',
            f'{flow.boundary_id}"| {mermaid_identifier(flow.target)}',
        )
        for flow in ledger.flows
    )
    lines.extend(
        (
            "```",
            "",
            "## Trust boundaries and flows",
            "",
            "| Flow | Source | Target | Boundary | Protocol | Data classes |",
            "| --- | --- | --- | --- | --- | --- |",
        )
    )
    lines.extend(
        "| "
        + " | ".join(
            (
                markdown_cell(flow.flow_id),
                markdown_cell(flow.source),
                markdown_cell(flow.target),
                markdown_cell(flow.boundary_id),
                markdown_cell(flow.protocol),
                joined(flow.data_classes),
            )
        )
        + " |"
        for flow in ledger.flows
    )
    lines.extend(
        (
            "",
            "## Provider assumptions",
            "",
            _joined_text(
                "| ID | Provider | Unverified control assumption | Owner | Status | ",
                "Invalidation trigger |",
            ),
            "| --- | --- | --- | --- | --- | --- |",
        )
    )
    lines.extend(
        "| "
        + " | ".join(
            (
                markdown_cell(item.assumption_id),
                markdown_cell(item.provider),
                markdown_cell(item.control),
                markdown_cell(item.owner),
                item.status,
                markdown_cell(item.invalidation_trigger),
            )
        )
        + " |"
        for item in ledger.provider_assumptions
    )
    lines.extend(
        (
            "",
            "## Threat ledger",
            "",
            _joined_text(
                "| ID | STRIDE | Abuse case | Boundaries | Required mitigations | ",
                "ASVS mappings | Verifier mappings | Provider assumptions | Owner | ",
                "Status |",
            ),
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        )
    )
    lines.extend(
        "| "
        + " | ".join(
            (
                markdown_cell(threat.threat_id),
                joined(threat.stride_categories),
                markdown_cell(threat.abuse_case),
                joined(threat.boundary_ids),
                joined(threat.mitigations),
                joined(threat.asvs_requirement_ids),
                joined(threat.verification_selectors),
                joined(threat.assumed_provider_control_ids),
                markdown_cell(threat.owner),
                threat.verification_status,
            )
        )
        + " |"
        for threat in ledger.threats
    )
    lines.extend(
        (
            "",
            "## Residual risks",
            "",
            "| ID | Threats | Description | Owner | Review due | Disposition |",
            "| --- | --- | --- | --- | --- | --- |",
        )
    )
    lines.extend(
        "| "
        + " | ".join(
            (
                markdown_cell(risk.residual_risk_id),
                joined(risk.threat_ids),
                markdown_cell(risk.description),
                markdown_cell(risk.owner),
                risk.review_due.isoformat(),
                risk.disposition,
            )
        )
        + " |"
        for risk in ledger.residual_risks
    )
    lines.extend(
        (
            "",
            "## Invalidation triggers",
            "",
            *(f"- `{item}`" for item in ledger.global_invalidation_triggers),
            "",
        )
    )
    rendered = "\n".join(lines).encode("utf-8")
    if len(rendered) > THREAT_MARKDOWN_MAX_BYTES:
        msg = "rendered threat model exceeds the configured byte bound"
        raise AsvsError(msg)
    return rendered


def load_threat_ledger(
    path: Path | None = None,
    *,
    requirements_path: Path | None = None,
) -> ThreatLedger:
    """Load and validate the canonical threat ledger and ASVS mappings."""
    selected_path = (
        path if path is not None else Path("docs/security/threat-model.json")
    )
    ledger = _load_canonical_json(
        selected_path,
        _THREAT_LEDGER_ADAPTER,
        max_bytes=THREAT_LEDGER_MAX_BYTES,
    )
    if (
        ledger.evidence_revision != EVIDENCE_REVISION
        or ledger.candidate_tree_sha256 != CANDIDATE_TREE_SHA256
        or ledger.release_status != "do_not_release"
    ):
        msg = "threat ledger provenance or release status is not reviewed"
        raise AsvsError(msg)
    official_ids = {
        requirement.identifier
        for requirement in load_pinned_asvs_requirements(requirements_path)
        if requirement.level <= L2_MAX_LEVEL
    }
    mapped_ids = {
        requirement_id
        for threat in ledger.threats
        for requirement_id in threat.asvs_requirement_ids
    }
    if not mapped_ids <= official_ids:
        msg = "threat ledger contains an unknown ASVS mapping"
        raise AsvsError(msg)
    return ledger


def _descriptor_entry_names(descriptor: int) -> tuple[str, ...]:
    with os.scandir(descriptor) as entries:
        return tuple(sorted(entry.name for entry in entries))


def _inventory_entry_identities(
    descriptor: int,
    names: tuple[str, ...],
) -> tuple[tuple[str, int, int, int, int, int, int, int], ...]:
    identities: list[tuple[str, int, int, int, int, int, int, int]] = []
    for name in names:
        identity = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
            msg = "ASVS inventory entry is not a regular single-link file"
            raise AsvsError(msg)
        identities.append(
            (
                name,
                identity.st_dev,
                identity.st_ino,
                identity.st_mode,
                identity.st_size,
                identity.st_mtime_ns,
                identity.st_ctime_ns,
                identity.st_nlink,
            )
        )
    return tuple(identities)


def _validate_inventory_directory(path: Path, expected_names: frozenset[str]) -> None:
    descriptor = _open_directory_no_follow(path)
    try:
        before = os.fstat(descriptor)
        names = _descriptor_entry_names(descriptor)
        if len(names) > MAX_INVENTORY_ENTRIES or frozenset(names) != expected_names:
            msg = "ASVS inventory directory contains an unexpected entry"
            raise AsvsError(msg)
        entry_identities = _inventory_entry_identities(descriptor, names)
        after_names = _descriptor_entry_names(descriptor)
        after_entry_identities = _inventory_entry_identities(descriptor, after_names)
        after = os.fstat(descriptor)
        if (
            names != after_names
            or entry_identities != after_entry_identities
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            msg = "ASVS inventory directory changed while it was inspected"
            raise AsvsError(msg)
    except OSError as exc:
        msg = "ASVS inventory directory could not be inspected"
        raise AsvsError(msg) from exc
    finally:
        os.close(descriptor)


def _require_repository_invariant(message: str, *, condition: bool) -> None:
    if not condition:
        raise AsvsError(message)


def _validate_unassessed_threat_claims(
    matrix: tuple[EvidenceRow, ...],
    policy: EvidencePolicy,
    ledger: ThreatLedger,
) -> None:
    matrix_claims = {(row.requirement_id, row.profile): row for row in matrix}
    for threat in ledger.threats:
        for requirement_id in threat.asvs_requirement_ids:
            for profile in threat.affected_profiles:
                row = matrix_claims.get((requirement_id, profile))
                claim = policy.claim_for(requirement_id, profile)
                _require_repository_invariant(
                    "threat mapping overclaims an unverified ASVS claim",
                    condition=(
                        isinstance(row, ApplicableEvidenceRow)
                        and row.verdict == "Not assessed"
                        and claim.pass_required_kinds is None
                        and not claim.na_absence_required
                        and claim.risk_acceptance_authority_id is None
                    ),
                )


def _check_repository_strict(selected_root: Path) -> None:
    source_inventory = frozenset({"SHA256SUMS", "requirements-5.0.0.json"})
    evidence_inventory = frozenset(
        {
            "asvs-5.0.0-l2-matrix.jsonl",
            "asvs-5.0.0-l2-method.md",
            "asvs-evidence-policy.json",
            "evidence-manifest.jsonl",
            "threat-model.json",
            "threat-model.md",
        }
    )
    _validate_inventory_directory(selected_root / "security/asvs", source_inventory)
    _validate_inventory_directory(selected_root / "docs/security", evidence_inventory)
    source_path = selected_root / "security/asvs/requirements-5.0.0.json"
    _require_repository_invariant(
        "ASVS source publication lock remains present",
        condition=not (source_path.parent / ".asvs-fetch.lock").exists(),
    )
    requirements = load_pinned_asvs_requirements(source_path)
    checksum = _read_bounded_regular_file(
        selected_root / "security/asvs/SHA256SUMS",
        max_bytes=256,
    )
    _require_repository_invariant(
        "ASVS checksum inventory does not match the pinned source",
        condition=(
            checksum == f"{ASVS_SHA256}  requirements-5.0.0.json\n".encode("ascii")
        ),
    )
    matrix_path = selected_root / "docs/security/asvs-5.0.0-l2-matrix.jsonl"
    matrix_body = _read_bounded_regular_file(matrix_path, max_bytes=MATRIX_MAX_BYTES)
    _require_repository_invariant(
        "ASVS matrix differs from deterministic rendering",
        condition=matrix_body == render_evidence_matrix(requirements),
    )
    matrix = load_evidence_matrix(matrix_path)
    policy_path = selected_root / "docs/security/asvs-evidence-policy.json"
    policy_body = _read_bounded_regular_file(policy_path, max_bytes=POLICY_MAX_BYTES)
    _require_repository_invariant(
        "ASVS policy differs from deterministic rendering",
        condition=policy_body == render_evidence_policy(requirements),
    )
    policy = load_independent_evidence_policy(policy_path)
    manifest = load_evidence_manifest(
        selected_root / "docs/security/evidence-manifest.jsonl"
    )
    _require_repository_invariant(
        "evidence manifest must remain empty",
        condition=not manifest,
    )
    threat_path = selected_root / "docs/security/threat-model.json"
    threat_body = _read_bounded_regular_file(
        threat_path,
        max_bytes=THREAT_LEDGER_MAX_BYTES,
    )
    _require_repository_invariant(
        "threat ledger differs from deterministic rendering",
        condition=threat_body == render_threat_ledger(),
    )
    ledger = load_threat_ledger(threat_path, requirements_path=source_path)
    threat_markdown = _read_bounded_regular_file(
        selected_root / "docs/security/threat-model.md",
        max_bytes=THREAT_MARKDOWN_MAX_BYTES,
    )
    _require_repository_invariant(
        "threat-model Markdown differs from deterministic rendering",
        condition=threat_markdown == render_threat_model_markdown(ledger),
    )
    _validate_unassessed_threat_claims(matrix, policy, ledger)
    _validate_inventory_directory(selected_root / "security/asvs", source_inventory)
    _validate_inventory_directory(selected_root / "docs/security", evidence_inventory)


def check_repository(root: Path | None = None) -> bool:
    """Check the complete Task 2 inventory without mutating repository state."""
    selected_root = root if root is not None else Path.cwd()
    try:
        _check_repository_strict(selected_root)
    except (AsvsError, OSError, ValidationError):
        return False
    return True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--check", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=False)
    fetch = subparsers.add_parser("fetch")
    _ = fetch.add_argument("--output", type=Path, required=True)
    _ = subparsers.add_parser("verify-ref")
    matrix = subparsers.add_parser("matrix")
    _ = matrix.add_argument(
        "--output", type=Path, default=Path("docs/security/asvs-5.0.0-l2-matrix.jsonl")
    )
    _ = matrix.add_argument(
        "--requirements",
        type=Path,
        default=Path("security/asvs/requirements-5.0.0.json"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the bounded Task 2 fetch, ref, matrix, or check command."""
    arguments = cast("dict[str, object]", vars(_parser().parse_args(argv)))
    check = cast("bool", arguments["check"])
    command_value = arguments["command"]
    if check:
        if command_value is not None:
            return 2
        return 0 if check_repository() else 1
    if type(command_value) is not str:
        return 2
    command = command_value
    if command == "fetch":
        _ = fetch_asvs(cast("Path", arguments["output"]))
        return 0
    if command == "verify-ref":
        return 0 if verify_ref() else 1
    _ = build_matrix(
        cast("Path", arguments["output"]),
        requirements_path=cast("Path", arguments["requirements"]),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
