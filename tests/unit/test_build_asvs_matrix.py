# Copyright (c) 2026 David Osipov
"""Adversarial unit tests for the ASVS inventory trust boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import select
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal, Self, cast

import pytest
from pydantic import ValidationError

import scripts.build_asvs_matrix as asvs_matrix
from scripts.build_asvs_matrix import (
    ASVS_COMMIT,
    PROFILES,
    AbuseCategory,
    ApplicableEvidenceRow,
    AsvsError,
    AsvsRequirement,
    BoundedGitRunner,
    ClaimPolicyRecord,
    CustodiedEvidenceReference,
    CustodyReceipt,
    DescriptorEvidenceFileSystem,
    EvidenceFileSnapshot,
    EvidencePolicy,
    EvidenceVerificationContext,
    ExclusiveArtifactPublisher,
    GitCommandRequest,
    GitCommandResult,
    HttpDownloadResult,
    HttpsDownloader,
    LocalEvidenceReference,
    NotApplicableEvidenceRow,
    Profile,
    ProviderAssumption,
    ReleaseDecision,
    ResidualRiskRecord,
    ReviewedSelectorBinding,
    ThreatEntryPoint,
    ThreatFlow,
    ThreatLedger,
    ThreatNode,
    ThreatRecord,
    VerifiedCandidateSnapshot,
    build_matrix,
    check_repository,
    evaluate_profile_release,
    fetch_asvs,
    load_evidence_manifest,
    load_evidence_matrix,
    load_independent_evidence_policy,
    load_pinned_asvs_requirements,
    load_threat_ledger,
    main,
    render_evidence_matrix,
    render_evidence_policy,
    render_threat_ledger,
    render_threat_model_markdown,
    verify_claim_binding,
    verify_evidence_reference,
    verify_ref,
    verify_release_approval,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Protocol

    class _UncheckedReleaseEvaluator(Protocol):
        def __call__(self, **options: object) -> ReleaseDecision:
            """Call the runtime boundary with deliberately malformed options."""
            ...


L2_LEVEL = 2
MATRIX_RECORDS = 759
CANDIDATE_RECORDS = 253
CANDIDATE_AS_OF = datetime(2026, 8, 23, tzinfo=UTC)
CANDIDATE_REVIEW_DUE = date(2026, 12, 31)
GIT_TIMEOUT_SECONDS = 30
GIT_OUTPUT_BYTES = 4_096
OVERFLOW_OUTPUT_BYTES = 32
SECOND_WRITE_CALL = 2
HTTP_TIMEOUT_SECONDS = 30
HTTP_HANDLER_COUNT = 2
DIRECTORY_FSYNC_CALL = 4
FIRST_TEMPORARY_FINAL_STAT_CALL = 3
INVALID_CLI_USAGE = 2
RECEIPT_EXPIRY = datetime(2026, 12, 31, tzinfo=UTC)
CANDIDATE_REVISION = "a" * 40
CANDIDATE_TREE_SHA256 = "b" * 64
PROFILE_ORDER: dict[Profile, int] = {
    "alpic-metadata": 0,
    "private-full": 1,
    "distributed-full": 2,
}


def _applicable_row() -> dict[str, object]:
    return {
        "applicability": "applicable",
        "applicability_rationale": "The profile exposes the assessed surface.",
        "asvs_version": "5.0.0",
        "evidence_date": date(2026, 8, 16),
        "evidence_ids": (),
        "evidence_revision": "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
        "invariant": "The requirement remains unclaimed until evidence is verified.",
        "level": 1,
        "owner": "security-owner",
        "profile": "alpic-metadata",
        "required_evidence_kinds": (),
        "requirement_id": "v5.0.0-V1.1.1",
        "requirement_text": "Fixture requirement.",
        "target_phase": "phase-0",
        "threat_boundary": "client-to-alpic-edge",
        "verdict": "Not assessed",
    }


def _canonical_json_line(value: dict[str, object]) -> bytes:
    serializable = {
        key: item.isoformat() if isinstance(item, date) else item
        for key, item in value.items()
    }
    return (
        json.dumps(
            serializable,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def _not_applicable_row() -> dict[str, object]:
    return _applicable_row() | {
        "absence_evidence_ids": ("absence.fixture",),
        "applicability": "not_applicable",
        "applicability_rationale": "The capability is absent from this profile.",
        "applicability_review_due": date(2026, 12, 31),
        "applicability_reviewer": "reviewer-subject",
        "evidence_ids": (),
        "required_evidence_kinds": (),
        "verdict": "N/A",
    }


def _local_evidence() -> dict[str, object]:
    return {
        "artifact_path": "evidence/test-report.json",
        "asserted_invariant": "The exact requirement/profile claim was tested.",
        "candidate_tree_sha256": "1" * 64,
        "collected_at": datetime(2026, 8, 16, 8, tzinfo=UTC),
        "covered_surface": "src/nplg_mcp",
        "deployment_id": None,
        "evidence_id": "ev.fixture",
        "evidence_revision": "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
        "expires_at": datetime(2026, 12, 31, tzinfo=UTC),
        "image_digest": None,
        "kind": "test",
        "profiles": ("alpic-metadata",),
        "requirement_ids": ("v5.0.0-V1.1.1",),
        "result": "pass",
        "reviewer": "reviewer-subject",
        "selectors": ("tests/unit/test_fixture.py::test_claim",),
        "sha256": "2" * 64,
        "storage": "local",
        "verifier": "test-report-v1",
    }


def _custodied_evidence() -> dict[str, object]:
    local = _local_evidence()
    _ = local.pop("artifact_path")
    local.update(
        {
            "artifact_object_version": "3" * 64,
            "custody_authority_id": "ci.example",
            "custody_receipt_id": "receipt.fixture",
            "immutable_artifact_uri": (
                "https://evidence.example.invalid/objects/sha256/" + "2" * 64
            ),
            "storage": "custodied-uri",
            "verifier": "ci-custody-v1",
        }
    )
    return local


def _claim_policy_sort_key(item: ClaimPolicyRecord) -> tuple[str, int]:
    return (item.requirement_id, PROFILE_ORDER[item.profile])


def _prepend_blank_record(body: bytes) -> bytes:
    return b"\n" + body


def _replace_lf_with_crlf(body: bytes) -> bytes:
    return body.replace(b"\n", b"\r\n")


def _remove_final_lf(body: bytes) -> bytes:
    return body.removesuffix(b"\n")


def _make_json_noncanonical(body: bytes) -> bytes:
    return body.replace(b'"level":1', b'"level": 1')


def _prepend_utf8_bom(body: bytes) -> bytes:
    return b"\xef\xbb\xbf" + body


def _append_invalid_utf8(body: bytes) -> bytes:
    return body[:-1] + b"\xff"


def _claim_policy_records() -> tuple[ClaimPolicyRecord, ...]:
    records = (
        ClaimPolicyRecord(
            requirement_id=requirement.identifier,
            profile=profile,
            pass_required_kinds=None,
            na_absence_required=False,
            risk_acceptance_authority_id=None,
        )
        for requirement in load_pinned_asvs_requirements()
        if requirement.level <= L2_LEVEL
        for profile in PROFILES
    )
    return tuple(
        sorted(
            records,
            key=_claim_policy_sort_key,
        )
    )


def _evidence_policy() -> EvidencePolicy:
    return EvidencePolicy(
        schema_version="2.0",
        asvs_version="5.0.0",
        asvs_source_commit=ASVS_COMMIT,
        evidence_revision="da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
        candidate_tree_sha256="1" * 64,
        attestation_allowlist=asvs_matrix.ATTESTATION_ALLOWLIST,
        profiles=PROFILES,
        claims=_claim_policy_records(),
        custody_authority_ids=(),
        release_authority_ids=(),
    )


def _verification_context() -> EvidenceVerificationContext:
    return EvidenceVerificationContext(
        root=Path.cwd(),
        evidence_revision="da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
        candidate_tree_sha256="1" * 64,
        requirement_id="v5.0.0-V1.1.1",
        profile="alpic-metadata",
        asserted_invariant="The exact requirement/profile claim was tested.",
        covered_surface="src/nplg_mcp",
        as_of=datetime(2026, 8, 17, tzinfo=UTC),
    )


def _verified_candidate(
    root: Path,
    reference: LocalEvidenceReference,
    *,
    include_selectors: bool = True,
) -> VerifiedCandidateSnapshot:
    identity = root.stat()
    bindings = (
        tuple(
            ReviewedSelectorBinding(
                selector=selector,
                claim_purpose="positive-control",
                kind=reference.kind,
                verifier=reference.verifier,
                artifact_path=reference.artifact_path,
                artifact_sha256=reference.sha256,
                evidence_revision=reference.evidence_revision,
                candidate_tree_sha256=reference.candidate_tree_sha256,
                requirement_id="v5.0.0-V1.1.1",
                profile="alpic-metadata",
                asserted_invariant=reference.asserted_invariant,
                covered_surface=reference.covered_surface,
            )
            for selector in reference.selectors
        )
        if include_selectors
        else ()
    )
    return VerifiedCandidateSnapshot(
        root_device=identity.st_dev,
        root_inode=identity.st_ino,
        evidence_revision=reference.evidence_revision,
        candidate_tree_sha256=reference.candidate_tree_sha256,
        clean=True,
        selector_bindings=bindings,
    )


class _StaticCandidateVerifier:
    def __init__(self, snapshot: VerifiedCandidateSnapshot) -> None:
        super().__init__()
        self.snapshot_result = snapshot

    def snapshot(self, root: Path) -> VerifiedCandidateSnapshot:
        del root
        return self.snapshot_result


def _custody_receipt(
    *,
    profile: Profile = "alpic-metadata",
    expires_at: datetime = RECEIPT_EXPIRY,
    risk_id: str | None = None,
    reference: CustodiedEvidenceReference | None = None,
    candidate_tree_sha256: str | None = None,
) -> CustodyReceipt:
    selected_reference = reference or CustodiedEvidenceReference.model_validate(
        _custodied_evidence()
    )
    return CustodyReceipt(
        schema_version="1.0",
        authority_id=selected_reference.custody_authority_id,
        receipt_id=selected_reference.custody_receipt_id,
        nonce="nonce.fixture",
        immutable_artifact_uri=selected_reference.immutable_artifact_uri,
        artifact_object_version=selected_reference.artifact_object_version,
        artifact_sha256=selected_reference.sha256,
        evidence_id=selected_reference.evidence_id,
        kind=selected_reference.kind,
        claim_purpose="positive-control",
        selectors=selected_reference.selectors,
        reviewer=selected_reference.reviewer,
        deployment_id=selected_reference.deployment_id,
        image_digest=selected_reference.image_digest,
        evidence_revision=selected_reference.evidence_revision,
        candidate_tree_sha256=(
            candidate_tree_sha256 or selected_reference.candidate_tree_sha256
        ),
        requirement_id="v5.0.0-V1.1.1",
        profile=profile,
        asserted_invariant=selected_reference.asserted_invariant,
        covered_surface=selected_reference.covered_surface,
        risk_id=risk_id,
        candidate_bundle_sha256="5" * 64 if risk_id is not None else None,
        attestation_commit="6" * 40 if risk_id is not None else None,
        approver_subject="approver-subject" if risk_id is not None else None,
        decision="risk_approved" if risk_id is not None else "evidence_verified",
        issued_at=datetime(2026, 8, 16, tzinfo=UTC),
        expires_at=expires_at,
        proof_sha256="4" * 64,
    )


def test_matrix_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "matrix.jsonl"
    body = _canonical_json_line(_applicable_row())
    duplicate = body[:-2] + b',"verdict":"Pass"}\n'
    _ = path.write_bytes(duplicate)

    with pytest.raises(AsvsError, match="duplicate JSON key"):
        _ = load_evidence_matrix(path)


@pytest.mark.parametrize(
    "mutator",
    [
        _prepend_blank_record,
        _replace_lf_with_crlf,
        _remove_final_lf,
        _make_json_noncanonical,
        _prepend_utf8_bom,
        _append_invalid_utf8,
    ],
    ids=("blank-record", "crlf", "missing-final-lf", "noncanonical", "bom", "utf8"),
)
def test_matrix_loader_rejects_noncanonical_bytes(
    tmp_path: Path,
    mutator: Callable[[bytes], bytes],
) -> None:
    path = tmp_path / "matrix.jsonl"
    _ = path.write_bytes(mutator(_canonical_json_line(_applicable_row())))

    with pytest.raises(AsvsError):
        _ = load_evidence_matrix(path)


def test_matrix_loader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    _ = target.write_bytes(_canonical_json_line(_applicable_row()))
    link = tmp_path / "matrix.jsonl"
    link.symlink_to(target)

    with pytest.raises(AsvsError):
        _ = load_evidence_matrix(link)


@pytest.mark.parametrize("mutation", ["duplicate", "unsorted"])
def test_matrix_loader_rejects_noncanonical_claim_product(
    tmp_path: Path,
    mutation: str,
) -> None:
    lines = (
        Path("docs/security/asvs-5.0.0-l2-matrix.jsonl")
        .read_bytes()
        .splitlines(keepends=True)
    )
    if mutation == "duplicate":
        lines[1] = lines[0]
    else:
        lines[0], lines[1] = lines[1], lines[0]
    path = tmp_path / "matrix.jsonl"
    _ = path.write_bytes(b"".join(lines))

    with pytest.raises(AsvsError):
        _ = load_evidence_matrix(path)


def test_applicable_row_requires_complete_common_fields() -> None:
    incomplete = _applicable_row()
    del incomplete["threat_boundary"]

    with pytest.raises(ValidationError):
        _ = ApplicableEvidenceRow.model_validate(incomplete)


def test_complete_not_assessed_state_is_accepted() -> None:
    row = ApplicableEvidenceRow.model_validate(_applicable_row())

    assert row.verdict == "Not assessed"


def test_matrix_row_bounds_match_the_l1_l2_persisted_contract() -> None:
    maximum_ids = tuple(f"ev.{index:03d}" for index in range(128))
    accepted = ApplicableEvidenceRow.model_validate(
        _applicable_row() | {"evidence_ids": maximum_ids}
    )

    assert accepted.evidence_ids == maximum_ids
    with pytest.raises(ValidationError):
        _ = ApplicableEvidenceRow.model_validate(
            _applicable_row() | {"evidence_ids": (*maximum_ids, "ev.128")}
        )
    with pytest.raises(ValidationError):
        _ = ApplicableEvidenceRow.model_validate(_applicable_row() | {"level": 3})
    not_applicable = NotApplicableEvidenceRow.model_validate(
        _not_applicable_row() | {"absence_evidence_ids": maximum_ids}
    )
    assert not_applicable.absence_evidence_ids == maximum_ids
    with pytest.raises(ValidationError):
        _ = NotApplicableEvidenceRow.model_validate(
            _not_applicable_row() | {"absence_evidence_ids": (*maximum_ids, "ev.128")}
        )


def test_risk_accepted_requires_complete_external_approval_fields() -> None:
    incomplete = _applicable_row() | {
        "verdict": "Risk accepted",
        "risk_id": "risk.fixture",
        "risk_owner": "risk-owner",
        "risk_approver": "approver-subject",
    }

    with pytest.raises(ValidationError):
        _ = ApplicableEvidenceRow.model_validate(incomplete)


def test_complete_risk_accepted_state_is_accepted() -> None:
    complete = _applicable_row() | {
        "compensating_controls": ("control.fixture",),
        "release_approval_evidence_id": "approval.fixture",
        "residual_risk": "Residual risk remains explicitly bounded.",
        "risk_approver": "approver-subject",
        "risk_expiry": date(2026, 12, 31),
        "risk_id": "risk.fixture",
        "risk_owner": "risk-owner",
        "verdict": "Risk accepted",
    }

    row = ApplicableEvidenceRow.model_validate(complete)

    assert row.risk_expiry == date(2026, 12, 31)


def test_not_applicable_structurally_forbids_risk_fields() -> None:
    candidate = _applicable_row()
    _ = candidate.pop("applicability_rationale")
    candidate.update(
        {
            "absence_evidence_ids": ("absence.fixture",),
            "applicability": "not_applicable",
            "applicability_rationale": "The capability is absent from this profile.",
            "applicability_review_due": date(2026, 12, 31),
            "applicability_reviewer": "reviewer-subject",
            "evidence_ids": (),
            "risk_id": None,
            "verdict": "N/A",
        }
    )

    with pytest.raises(ValidationError):
        _ = NotApplicableEvidenceRow.model_validate(candidate)


def test_pass_requires_named_evidence_and_kinds() -> None:
    candidate = _applicable_row() | {"verdict": "Pass"}

    with pytest.raises(ValidationError):
        _ = ApplicableEvidenceRow.model_validate(candidate)


def test_not_applicable_requires_unique_absence_evidence() -> None:
    candidate = _applicable_row() | {
        "absence_evidence_ids": ("absence.fixture", "absence.fixture"),
        "applicability": "not_applicable",
        "applicability_review_due": date(2026, 12, 31),
        "applicability_reviewer": "reviewer-subject",
        "evidence_ids": (),
        "required_evidence_kinds": (),
        "verdict": "N/A",
    }

    with pytest.raises(ValidationError):
        _ = NotApplicableEvidenceRow.model_validate(candidate)


@pytest.mark.parametrize(
    ("applicability", "verdict"),
    [
        ("applicable", "N/A"),
        ("not_applicable", "Not assessed"),
        ("not_applicable", "Fail"),
        ("not_applicable", "Partial"),
        ("not_applicable", "Pass"),
        ("not_applicable", "Risk accepted"),
    ],
)
def test_illegal_applicability_verdict_pairs_are_rejected(
    applicability: str,
    verdict: str,
) -> None:
    candidate = (
        _applicable_row() if applicability == "applicable" else _not_applicable_row()
    )
    candidate["verdict"] = verdict

    with pytest.raises(ValidationError):
        _ = (
            ApplicableEvidenceRow.model_validate(candidate)
            if applicability == "applicable"
            else NotApplicableEvidenceRow.model_validate(candidate)
        )


def test_complete_local_evidence_reference_is_accepted() -> None:
    reference = LocalEvidenceReference.model_validate(_local_evidence())

    assert reference.result == "pass"


def test_manifest_loader_returns_strict_reference_records(tmp_path: Path) -> None:
    path = tmp_path / "evidence-manifest.jsonl"
    _ = path.write_bytes(_canonical_json_line(_local_evidence()))

    references = load_evidence_manifest(path)

    assert len(references) == 1
    assert isinstance(references[0], LocalEvidenceReference)


def test_manifest_loader_rejects_duplicate_evidence_identifiers(tmp_path: Path) -> None:
    first = _local_evidence()
    second = _local_evidence() | {
        "artifact_path": "evidence/other-report.json",
        "selectors": ("tests/unit/test_other.py::test_claim",),
    }
    path = tmp_path / "evidence-manifest.jsonl"
    _ = path.write_bytes(_canonical_json_line(first) + _canonical_json_line(second))

    with pytest.raises(AsvsError):
        _ = load_evidence_manifest(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_path", "."),
        ("selectors", ()),
        ("requirement_ids", ()),
        ("profiles", ()),
        ("result", "FAIL"),
    ],
)
def test_local_evidence_rejects_unverifiable_claim_shape(
    field: str,
    value: object,
) -> None:
    candidate = _local_evidence()
    candidate[field] = value

    with pytest.raises(ValidationError):
        _ = LocalEvidenceReference.model_validate(candidate)


def test_complete_custodied_evidence_reference_is_accepted() -> None:
    reference = CustodiedEvidenceReference.model_validate(_custodied_evidence())

    assert reference.storage == "custodied-uri"


@pytest.mark.parametrize(
    "uri",
    [
        "http://evidence.example.invalid/object/immutable",
        "https://user@evidence.example.invalid/object/immutable",
        "https://127.0.0.1/object/immutable",
        "https://evidence.example.invalid/latest",
        "https://evidence.example.invalid/object/immutable?version=1",
        "https://evidence.example.invalid/object/immutable#fragment",
    ],
)
def test_custodied_evidence_rejects_mutable_or_unsafe_uri(uri: str) -> None:
    candidate = _custodied_evidence()
    candidate["immutable_artifact_uri"] = uri

    with pytest.raises(ValidationError):
        _ = CustodiedEvidenceReference.model_validate(candidate)


@pytest.mark.parametrize(
    "hostname",
    ["evidence.local", "foo.localhost", "localhost.", "metadata.google.internal."],
)
def test_custodied_evidence_rejects_local_hostname_variants(hostname: str) -> None:
    candidate = _custodied_evidence()
    candidate["immutable_artifact_uri"] = (
        f"https://{hostname}/objects/sha256/" + "2" * 64
    )

    with pytest.raises(ValidationError):
        _ = CustodiedEvidenceReference.model_validate(candidate)


@pytest.mark.parametrize(
    "uri",
    [
        "https://evidence.example.invalid:8443/objects/sha256/" + "2" * 64,
        "https://evidence.example.invalid:bad/objects/sha256/" + "2" * 64,
        "https://93.184.216.34/objects/sha256/" + "2" * 64,
        "https://evidence.example.invalid/objects/%61/sha256/" + "2" * 64,
    ],
)
def test_custodied_evidence_uri_matches_closed_zod_authority_policy(uri: str) -> None:
    candidate = _custodied_evidence()
    candidate["immutable_artifact_uri"] = uri

    with pytest.raises(ValidationError):
        _ = CustodiedEvidenceReference.model_validate(candidate)


def test_policy_requires_exact_sorted_requirement_profile_product() -> None:
    policy = _evidence_policy()

    with pytest.raises(ValidationError):
        _ = EvidencePolicy(
            schema_version=policy.schema_version,
            asvs_version=policy.asvs_version,
            asvs_source_commit=policy.asvs_source_commit,
            evidence_revision=policy.evidence_revision,
            candidate_tree_sha256=policy.candidate_tree_sha256,
            attestation_allowlist=policy.attestation_allowlist,
            profiles=policy.profiles,
            claims=(*policy.claims[:-1], policy.claims[0]),
            custody_authority_ids=policy.custody_authority_ids,
            release_authority_ids=policy.release_authority_ids,
        )


def test_policy_authority_identifiers_must_be_canonically_sorted() -> None:
    policy = _evidence_policy()

    with pytest.raises(ValidationError):
        _ = EvidencePolicy(
            schema_version=policy.schema_version,
            asvs_version=policy.asvs_version,
            asvs_source_commit=policy.asvs_source_commit,
            evidence_revision=policy.evidence_revision,
            candidate_tree_sha256=policy.candidate_tree_sha256,
            attestation_allowlist=policy.attestation_allowlist,
            profiles=policy.profiles,
            claims=policy.claims,
            custody_authority_ids=("z-authority", "a-authority"),
            release_authority_ids=(),
        )


@pytest.mark.parametrize(
    "fault",
    ["missing", "reordered", "substituted", "extra"],
)
def test_policy_requires_the_explicit_exact_attestation_allowlist(fault: str) -> None:
    """The protected path set is required input, not a Pydantic default."""
    candidate: dict[str, object] = _evidence_policy().model_dump()
    allowlist = asvs_matrix.ATTESTATION_ALLOWLIST
    if fault == "missing":
        _ = candidate.pop("attestation_allowlist")
    elif fault == "reordered":
        candidate["attestation_allowlist"] = tuple(reversed(allowlist))
    elif fault == "substituted":
        candidate["attestation_allowlist"] = (allowlist[0], "docs/security/other.json")
    else:
        candidate["attestation_allowlist"] = (*allowlist, "docs/security/extra.json")

    with pytest.raises(ValidationError):
        _ = EvidencePolicy.model_validate(candidate, strict=True)


def test_policy_lookup_returns_exact_claim() -> None:
    claim = _evidence_policy().claim_for("v5.0.0-V1.1.1", "alpic-metadata")

    assert claim.pass_required_kinds is None
    assert claim.na_absence_required is False


def test_claim_binding_rejects_cross_profile_and_invariant_reuse() -> None:
    row = ApplicableEvidenceRow.model_validate(
        _applicable_row()
        | {
            "evidence_ids": ("ev.fixture",),
            "invariant": "The exact requirement/profile claim was tested.",
            "required_evidence_kinds": ("test",),
            "verdict": "Pass",
        }
    )
    reference = LocalEvidenceReference.model_validate(_local_evidence())
    wrong_profile_data = _local_evidence()
    wrong_profile_data["profiles"] = ("private-full",)
    wrong_profile = LocalEvidenceReference.model_validate(wrong_profile_data)
    wrong_invariant_data = _local_evidence()
    wrong_invariant_data["asserted_invariant"] = "different"
    wrong_invariant = LocalEvidenceReference.model_validate(wrong_invariant_data)

    assert verify_claim_binding(row, reference) is True
    assert verify_claim_binding(row, wrong_profile) is False
    assert verify_claim_binding(row, wrong_invariant) is False


def test_na_claim_binding_rejects_a_generic_design_reference() -> None:
    """Arbitrary hashed bytes cannot establish absence of a capability."""
    row = NotApplicableEvidenceRow.model_validate(_not_applicable_row())
    reference = LocalEvidenceReference.model_validate(
        _local_evidence()
        | {
            "asserted_invariant": row.invariant,
            "evidence_id": "absence.fixture",
            "kind": "design",
            "selectors": ("not-an-absence-probe",),
            "verifier": "sha256-file-v1",
        }
    )

    assert verify_claim_binding(row, reference) is False


def test_custody_receipt_rejects_expired_lifetime() -> None:
    reference = CustodiedEvidenceReference.model_validate(_custodied_evidence())
    with pytest.raises(ValidationError):
        _ = CustodyReceipt(
            schema_version="1.0",
            authority_id="ci.example",
            receipt_id="receipt.fixture",
            nonce="nonce.fixture",
            immutable_artifact_uri=reference.immutable_artifact_uri,
            artifact_object_version="3" * 64,
            artifact_sha256="2" * 64,
            evidence_id="ev.fixture",
            kind="operational",
            claim_purpose="positive-control",
            selectors=("operations/approval.fixture",),
            reviewer="reviewer-subject",
            deployment_id="deployment.fixture",
            image_digest=None,
            evidence_revision="da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
            candidate_tree_sha256="1" * 64,
            requirement_id="v5.0.0-V1.1.1",
            profile="alpic-metadata",
            asserted_invariant="The exact requirement/profile claim was tested.",
            covered_surface="src/nplg_mcp",
            risk_id="risk.fixture",
            candidate_bundle_sha256="5" * 64,
            attestation_commit="6" * 40,
            approver_subject="approver-subject",
            decision="risk_approved",
            issued_at=datetime(2026, 8, 16, tzinfo=UTC),
            expires_at=datetime(2026, 8, 16, tzinfo=UTC),
            proof_sha256="4" * 64,
        )


def test_no_release_authority_keeps_risk_acceptance_ineligible() -> None:
    row = ApplicableEvidenceRow.model_validate(
        _applicable_row()
        | {
            "compensating_controls": ("control.fixture",),
            "invariant": "The exact requirement/profile claim was tested.",
            "release_approval_evidence_id": "ev.fixture",
            "residual_risk": "Residual risk remains bounded.",
            "risk_approver": "approver-subject",
            "risk_expiry": date(2026, 12, 31),
            "risk_id": "risk.fixture",
            "risk_owner": "risk-owner",
            "verdict": "Risk accepted",
        }
    )
    reference = LocalEvidenceReference.model_validate(_local_evidence())

    assert (
        verify_release_approval(
            row,
            reference,
            policy=_evidence_policy(),
            context=_verification_context(),
        )
        is False
    )


def test_bootstrap_rejects_a_risk_accepted_nonhistorical_product() -> None:
    row = ApplicableEvidenceRow.model_validate(
        _applicable_row()
        | {
            "compensating_controls": ("control.fixture",),
            "release_approval_evidence_id": "ev.fixture",
            "residual_risk": "Residual risk remains bounded.",
            "risk_approver": "approver-subject",
            "risk_expiry": date(2026, 12, 31),
            "risk_id": "risk.fixture",
            "risk_owner": "risk-owner",
            "verdict": "Risk accepted",
        }
    )

    decision: ReleaseDecision = evaluate_profile_release(
        "alpic-metadata",
        (row,),
        (),
        policy=_evidence_policy(),
        context=_verification_context(),
    )

    assert decision == ReleaseDecision(
        profile="alpic-metadata",
        decision="do_not_release",
        eligible=False,
        reason_codes=("bootstrap-product-mismatch",),
    )


def test_local_evidence_verifies_same_descriptor_and_candidate(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.bin"
    body = b"bounded evidence\n"
    _ = artifact.write_bytes(body)
    reference = LocalEvidenceReference.model_validate(
        _local_evidence()
        | {
            "artifact_path": "evidence.bin",
            "sha256": hashlib.sha256(body).hexdigest(),
            "verifier": "sha256-file-v1",
        }
    )
    candidate = _verified_candidate(tmp_path, reference)
    context = replace(
        _verification_context(),
        root=tmp_path,
        verified_candidate=candidate,
    )
    verifier = _StaticCandidateVerifier(candidate)

    assert (
        verify_evidence_reference(
            reference,
            context=context,
            candidate_verifier=verifier,
        )
        is True
    )
    assert (
        verify_evidence_reference(
            reference,
            context=replace(context, evidence_revision="0" * 40),
            candidate_verifier=verifier,
        )
        is False
    )
    assert (
        verify_evidence_reference(
            reference,
            context=replace(context, candidate_tree_sha256="0" * 64),
            candidate_verifier=verifier,
        )
        is False
    )


def test_local_evidence_rejects_a_context_root_with_another_inode(
    tmp_path: Path,
) -> None:
    reviewed_root = tmp_path / "reviewed"
    supplied_root = tmp_path / "supplied"
    reviewed_root.mkdir()
    supplied_root.mkdir()
    body = b"bounded evidence\n"
    _ = (supplied_root / "evidence.bin").write_bytes(body)
    reference = LocalEvidenceReference.model_validate(
        _local_evidence()
        | {
            "artifact_path": "evidence.bin",
            "sha256": hashlib.sha256(body).hexdigest(),
            "verifier": "sha256-file-v1",
        }
    )
    reviewed_candidate = _verified_candidate(reviewed_root, reference)

    assert (
        verify_evidence_reference(
            reference,
            context=replace(
                _verification_context(),
                root=supplied_root,
                verified_candidate=reviewed_candidate,
            ),
            candidate_verifier=_StaticCandidateVerifier(reviewed_candidate),
        )
        is False
    )


def test_local_json_evidence_rejects_an_unreviewed_selector(tmp_path: Path) -> None:
    """A self-describing JSON object is not an independent selector authority."""
    body = b'{"ok":true}\n'
    artifact = tmp_path / "threat-model.json"
    _ = artifact.write_bytes(body)
    reference = LocalEvidenceReference.model_validate(
        _local_evidence()
        | {
            "artifact_path": artifact.name,
            "selectors": ("tests/does_not_exist.py::test_never_ran",),
            "sha256": hashlib.sha256(body).hexdigest(),
            "verifier": "json-record-v1",
        }
    )
    candidate = _verified_candidate(tmp_path, reference, include_selectors=False)

    assert (
        verify_evidence_reference(
            reference,
            context=replace(
                _verification_context(),
                root=tmp_path,
                verified_candidate=candidate,
            ),
            candidate_verifier=_StaticCandidateVerifier(candidate),
        )
        is False
    )


def test_local_evidence_rejects_intermediate_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    body = b"outside evidence\n"
    _ = (outside / "evidence.bin").write_bytes(body)
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    reference = LocalEvidenceReference.model_validate(
        _local_evidence()
        | {
            "artifact_path": "link/evidence.bin",
            "sha256": hashlib.sha256(body).hexdigest(),
            "verifier": "sha256-file-v1",
        }
    )
    candidate = _verified_candidate(root, reference)

    assert (
        verify_evidence_reference(
            reference,
            context=replace(
                _verification_context(),
                root=root,
                verified_candidate=candidate,
            ),
            candidate_verifier=_StaticCandidateVerifier(candidate),
        )
        is False
    )


@pytest.mark.parametrize(
    "mutation",
    ["incomplete", "unconfined", "unstable", "special", "hard-link", "wrong-size"],
)
def test_local_evidence_rejects_injected_file_identity_races(
    tmp_path: Path,
    mutation: str,
) -> None:
    body = b"bounded evidence\n"
    reference = LocalEvidenceReference.model_validate(
        _local_evidence()
        | {
            "artifact_path": "evidence.bin",
            "sha256": hashlib.sha256(body).hexdigest(),
            "verifier": "sha256-file-v1",
        }
    )
    snapshot = EvidenceFileSnapshot(
        body=body,
        complete=True,
        confined=True,
        stable=True,
        regular=True,
        single_link=True,
        device=1,
        inode=2,
        size=len(body),
        mtime_ns=3,
        ctime_ns=4,
    )
    if mutation == "incomplete":
        snapshot = replace(snapshot, complete=False)
    elif mutation == "unconfined":
        snapshot = replace(snapshot, confined=False)
    elif mutation == "unstable":
        snapshot = replace(snapshot, stable=False)
    elif mutation == "special":
        snapshot = replace(snapshot, regular=False)
    elif mutation == "hard-link":
        snapshot = replace(snapshot, single_link=False)
    else:
        snapshot = replace(snapshot, size=len(body) + 1)
    candidate = _verified_candidate(tmp_path, reference)

    class FakeFileSystem:
        def read_bounded(
            self,
            root: Path,
            relative_path: str,
            *,
            max_bytes: int,
        ) -> EvidenceFileSnapshot:
            del root, relative_path, max_bytes
            return snapshot

    assert (
        verify_evidence_reference(
            reference,
            context=replace(
                _verification_context(),
                root=tmp_path,
                verified_candidate=candidate,
            ),
            filesystem=FakeFileSystem(),
            candidate_verifier=_StaticCandidateVerifier(candidate),
        )
        is False
    )


def test_custodied_evidence_uses_injected_allowlisted_authority() -> None:
    reference = CustodiedEvidenceReference.model_validate(_custodied_evidence())
    receipt = _custody_receipt()

    class Authority:
        authority_id = "ci.example"

        def verify_receipt(
            self,
            candidate: CustodiedEvidenceReference,
        ) -> CustodyReceipt | None:
            assert candidate is reference
            return receipt

    class ReplayRegistry:
        def __init__(self) -> None:
            super().__init__()
            self.subjects: dict[str, str] = {}

        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            previous = self.subjects.setdefault(nonce, subject_sha256)
            return previous == subject_sha256

    context = replace(
        _verification_context(),
        authorities=(Authority(),),
        replay_registry=ReplayRegistry(),
    )

    assert verify_evidence_reference(reference, context=context) is True


def test_custody_receipt_cannot_be_relabelled_across_claim_purposes() -> None:
    reference = CustodiedEvidenceReference.model_validate(_custodied_evidence())
    receipt = _custody_receipt()

    class Authority:
        authority_id = "ci.example"

        def verify_receipt(
            self,
            candidate: CustodiedEvidenceReference,
        ) -> CustodyReceipt | None:
            assert candidate is reference
            return receipt

    class ReplayRegistry:
        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            return bool(nonce and subject_sha256)

    positive_context = replace(
        _verification_context(),
        claim_purpose="positive-control",
        authorities=(Authority(),),
        replay_registry=ReplayRegistry(),
    )

    assert verify_evidence_reference(reference, context=positive_context) is True
    assert (
        verify_evidence_reference(
            reference,
            context=replace(positive_context, claim_purpose="absence-proof"),
        )
        is False
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_id", "ev.relabelled"),
        ("kind", "operational"),
        ("selectors", ("operations/never-collected",)),
        ("reviewer", "different-reviewer"),
        ("deployment_id", "different-deployment"),
    ],
)
def test_custody_receipt_rejects_reference_relabelling(
    field: str,
    value: object,
) -> None:
    """A receipt must bind every security-relevant evidence subject field."""
    receipt = _custody_receipt()
    candidate_data = _custodied_evidence()
    candidate_data[field] = value
    candidate = CustodiedEvidenceReference.model_validate(candidate_data)

    class Authority:
        authority_id = "ci.example"

        def verify_receipt(
            self,
            reference: CustodiedEvidenceReference,
        ) -> CustodyReceipt | None:
            del reference
            return receipt

    class ReplayRegistry:
        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            return bool(nonce and subject_sha256)

    context = replace(
        _verification_context(),
        authorities=(Authority(),),
        replay_registry=ReplayRegistry(),
    )

    assert verify_evidence_reference(candidate, context=context) is False


def test_custodied_evidence_rejects_unknown_wrong_or_expired_receipt() -> None:
    reference = CustodiedEvidenceReference.model_validate(_custodied_evidence())

    class Authority:
        authority_id = "ci.example"

        def __init__(self, receipt: CustodyReceipt) -> None:
            super().__init__()
            self.receipt = receipt

        def verify_receipt(
            self,
            candidate: CustodiedEvidenceReference,
        ) -> CustodyReceipt | None:
            del candidate
            return self.receipt

    base = _verification_context()
    wrong = _custody_receipt(candidate_tree_sha256="9" * 64)
    expired = _custody_receipt(expires_at=datetime(2026, 8, 16, 12, tzinfo=UTC))
    assert verify_evidence_reference(reference, context=base) is False
    assert (
        verify_evidence_reference(
            reference,
            context=replace(base, authorities=(Authority(wrong),)),
        )
        is False
    )
    assert (
        verify_evidence_reference(
            reference,
            context=replace(base, authorities=(Authority(expired),)),
        )
        is False
    )


def test_custody_nonce_replay_across_profiles_is_rejected() -> None:
    metadata = CustodiedEvidenceReference.model_validate(_custodied_evidence())
    private_data = _custodied_evidence()
    private_data["profiles"] = ("private-full",)
    private = CustodiedEvidenceReference.model_validate(private_data)
    receipts = {
        "alpic-metadata": _custody_receipt(profile="alpic-metadata"),
        "private-full": _custody_receipt(profile="private-full"),
    }

    class Authority:
        authority_id = "ci.example"

        def verify_receipt(
            self,
            candidate: CustodiedEvidenceReference,
        ) -> CustodyReceipt | None:
            return receipts[candidate.profiles[0]]

    class ReplayRegistry:
        def __init__(self) -> None:
            super().__init__()
            self.subjects: dict[str, str] = {}

        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            previous = self.subjects.setdefault(nonce, subject_sha256)
            return previous == subject_sha256

    authority = Authority()
    registry = ReplayRegistry()
    metadata_context = replace(
        _verification_context(),
        authorities=(authority,),
        replay_registry=registry,
    )
    private_context = replace(metadata_context, profile="private-full")

    assert verify_evidence_reference(metadata, context=metadata_context) is True
    assert verify_evidence_reference(private, context=private_context) is False


def test_external_authority_can_verify_but_not_release_risk_acceptance() -> None:
    row = ApplicableEvidenceRow.model_validate(
        _applicable_row()
        | {
            "compensating_controls": ("control.fixture",),
            "invariant": "The exact requirement/profile claim was tested.",
            "release_approval_evidence_id": "ev.fixture",
            "residual_risk": "Residual risk remains bounded.",
            "risk_approver": "approver-subject",
            "risk_expiry": date(2026, 12, 31),
            "risk_id": "risk.fixture",
            "risk_owner": "risk-owner",
            "verdict": "Risk accepted",
        }
    )
    reference = CustodiedEvidenceReference.model_validate(
        _custodied_evidence() | {"kind": "operational"}
    )
    receipt = _custody_receipt(risk_id="risk.fixture", reference=reference)

    class Authority:
        authority_id = "ci.example"

        def verify_receipt(
            self,
            candidate: CustodiedEvidenceReference,
        ) -> CustodyReceipt | None:
            assert candidate is reference
            return receipt

    class ReplayRegistry:
        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            return bool(nonce and subject_sha256)

    base_policy = _evidence_policy()
    claim = base_policy.claim_for(row.requirement_id, row.profile)
    amended_claim = ClaimPolicyRecord(
        requirement_id=claim.requirement_id,
        profile=claim.profile,
        pass_required_kinds=claim.pass_required_kinds,
        na_absence_required=claim.na_absence_required,
        risk_acceptance_authority_id="ci.example",
    )
    claims = tuple(
        amended_claim if candidate == claim else candidate
        for candidate in base_policy.claims
    )
    policy = EvidencePolicy(
        schema_version=base_policy.schema_version,
        asvs_version=base_policy.asvs_version,
        asvs_source_commit=base_policy.asvs_source_commit,
        evidence_revision=base_policy.evidence_revision,
        candidate_tree_sha256=base_policy.candidate_tree_sha256,
        attestation_allowlist=base_policy.attestation_allowlist,
        profiles=base_policy.profiles,
        claims=claims,
        custody_authority_ids=("ci.example",),
        release_authority_ids=("ci.example",),
    )
    context = replace(
        _verification_context(),
        risk_id="risk.fixture",
        candidate_bundle_sha256="5" * 64,
        attestation_commit="6" * 40,
        approver_subject="approver-subject",
        authorities=(Authority(),),
        replay_registry=ReplayRegistry(),
    )

    assert verify_release_approval(row, reference, policy=policy, context=context)
    assert evaluate_profile_release(
        "alpic-metadata",
        (row,),
        (reference,),
        policy=policy,
        context=context,
    ).reason_codes == ("bootstrap-product-mismatch",)


def test_fetch_accepts_only_complete_exact_immutable_response(tmp_path: Path) -> None:
    body = Path("security/asvs/requirements-5.0.0.json").read_bytes()
    result = HttpDownloadResult(
        requested_url=(
            "https://raw.githubusercontent.com/OWASP/ASVS/"
            f"{ASVS_COMMIT}/5.0/docs_en/"
            "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
        ),
        final_url=(
            "https://raw.githubusercontent.com/OWASP/ASVS/"
            f"{ASVS_COMMIT}/5.0/docs_en/"
            "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
        ),
        status=200,
        headers=(("content-length", str(len(body))),),
        body=body,
        redirect_count=0,
        complete=True,
    )

    class FakeDownloader:
        def download(self, url: str, *, max_bytes: int) -> HttpDownloadResult:
            assert url == result.requested_url
            assert max_bytes == len(body)
            return result

    class FakePublisher:
        def __init__(self) -> None:
            super().__init__()
            self.publications: list[tuple[tuple[Path, bytes], tuple[Path, bytes]]] = []

        def publish_pair(
            self,
            first: tuple[Path, bytes],
            second: tuple[Path, bytes],
        ) -> None:
            self.publications.append((first, second))

    publisher = FakePublisher()
    output = tmp_path / "requirements.json"

    assert (
        fetch_asvs(output, downloader=FakeDownloader(), publisher=publisher) == output
    )
    assert publisher.publications == [
        (
            (output, body),
            (
                tmp_path / "SHA256SUMS",
                (
                    b"bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35"
                    b"  requirements.json\n"
                ),
            ),
        )
    ]


def test_https_downloader_reads_the_exact_bounded_identity_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = Path("security/asvs/requirements-5.0.0.json").read_bytes()
    exact_url = (
        "https://raw.githubusercontent.com/OWASP/ASVS/"
        f"{ASVS_COMMIT}/5.0/docs_en/"
        "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
    )

    class Response:
        status = 200

        def __init__(self) -> None:
            super().__init__()
            self.offset = 0
            self.headers: dict[str, str] = {"Content-Length": str(len(body))}

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def read(self, amount: int) -> bytes:
            chunk = body[self.offset : self.offset + amount]
            self.offset += len(chunk)
            return chunk

        def geturl(self) -> str:
            return exact_url

    class Opener:
        def __init__(self) -> None:
            super().__init__()
            self.addheaders: list[tuple[str, str]] = []

        def open(self, url: str, *, timeout: int) -> Response:
            assert url == exact_url
            assert timeout == HTTP_TIMEOUT_SECONDS
            return Response()

    opener = Opener()

    def build_opener(*handlers: object) -> Opener:
        assert len(handlers) == HTTP_HANDLER_COUNT
        return opener

    monkeypatch.setattr("urllib.request.build_opener", build_opener)
    result = HttpsDownloader().download(exact_url, max_bytes=len(body))

    assert result.body == body
    assert result.complete is True
    assert result.final_url == exact_url
    assert opener.addheaders == [("Accept-Encoding", "identity")]


def test_https_downloader_rejects_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = Path("security/asvs/requirements-5.0.0.json").read_bytes()
    exact_url = (
        "https://raw.githubusercontent.com/OWASP/ASVS/"
        f"{ASVS_COMMIT}/5.0/docs_en/"
        "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
    )

    class OverflowResponse:
        status = 200

        def __init__(self) -> None:
            super().__init__()
            self.payload = body + b"x"
            self.offset = 0
            self.headers: dict[str, str] = {"Content-Length": str(len(body))}

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def read(self, amount: int) -> bytes:
            chunk = self.payload[self.offset : self.offset + amount]
            self.offset += len(chunk)
            return chunk

        def geturl(self) -> str:
            return exact_url

    class OverflowOpener:
        def __init__(self) -> None:
            super().__init__()
            self.addheaders: list[tuple[str, str]] = []

        def open(self, url: str, *, timeout: int) -> OverflowResponse:
            del url, timeout
            return OverflowResponse()

    def overflow_opener(*handlers: object) -> OverflowOpener:
        del handlers
        return OverflowOpener()

    monkeypatch.setattr("urllib.request.build_opener", overflow_opener)
    with pytest.raises(AsvsError, match="bounded size"):
        _ = HttpsDownloader().download(exact_url, max_bytes=len(body))


def test_https_downloader_sanitizes_transport_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = Path("security/asvs/requirements-5.0.0.json").read_bytes()
    exact_url = (
        "https://raw.githubusercontent.com/OWASP/ASVS/"
        f"{ASVS_COMMIT}/5.0/docs_en/"
        "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
    )

    class ErrorOpener:
        def __init__(self) -> None:
            super().__init__()
            self.addheaders: list[tuple[str, str]] = []

        def open(self, url: str, *, timeout: int) -> None:
            del url, timeout
            msg = "TASK2_SECRET_CANARY"
            raise OSError(msg)

    def error_opener(*handlers: object) -> ErrorOpener:
        del handlers
        return ErrorOpener()

    monkeypatch.setattr("urllib.request.build_opener", error_opener)
    with pytest.raises(AsvsError) as captured:
        _ = HttpsDownloader().download(exact_url, max_bytes=len(body))
    assert "TASK2_SECRET_CANARY" not in str(captured.value)


@pytest.mark.parametrize(
    "mutation",
    [
        "request-url",
        "final-url",
        "status",
        "redirect",
        "incomplete",
        "encoding",
        "transfer-encoding",
        "length",
        "duplicate-header",
        "body",
    ],
)
def test_fetch_rejects_response_mutations_without_publication(
    tmp_path: Path,
    mutation: str,
) -> None:
    body = Path("security/asvs/requirements-5.0.0.json").read_bytes()
    exact_url = (
        "https://raw.githubusercontent.com/OWASP/ASVS/"
        f"{ASVS_COMMIT}/5.0/docs_en/"
        "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
    )
    result = HttpDownloadResult(
        requested_url=exact_url,
        final_url=exact_url,
        status=200,
        headers=(("content-length", str(len(body))),),
        body=body,
        redirect_count=0,
        complete=True,
    )
    mutations = {
        "request-url": replace(result, requested_url=exact_url + "?mutable=1"),
        "final-url": replace(result, final_url=exact_url + "?redirected=1"),
        "status": replace(result, status=206),
        "redirect": replace(result, redirect_count=1),
        "incomplete": replace(result, complete=False),
        "encoding": replace(
            result,
            headers=(*result.headers, ("content-encoding", "gzip")),
        ),
        "transfer-encoding": replace(
            result,
            headers=(*result.headers, ("transfer-encoding", "chunked")),
        ),
        "length": replace(result, headers=(("content-length", "1"),)),
        "duplicate-header": replace(
            result,
            headers=(*result.headers, ("Content-Length", str(len(body)))),
        ),
        "body": replace(result, body=body[:-1] + b"x"),
    }
    result = mutations[mutation]

    class FakeDownloader:
        def download(self, url: str, *, max_bytes: int) -> HttpDownloadResult:
            del url, max_bytes
            return result

    class FakePublisher:
        def __init__(self) -> None:
            super().__init__()
            self.called = False

        def publish_pair(
            self,
            first: tuple[Path, bytes],
            second: tuple[Path, bytes],
        ) -> None:
            del first, second
            self.called = True

    publisher = FakePublisher()
    with pytest.raises(AsvsError):
        _ = fetch_asvs(
            tmp_path / "requirements.json",
            downloader=FakeDownloader(),
            publisher=publisher,
        )
    assert publisher.called is False


def test_verify_ref_uses_exact_absolute_git_and_closed_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TASK2_SECRET_CANARY", "must-not-cross-boundary")

    class Runner:
        def __init__(self) -> None:
            super().__init__()
            self.argv: tuple[str, ...] | None = None
            self.env: tuple[tuple[str, str], ...] | None = None

        def run(self, request: GitCommandRequest) -> GitCommandResult:
            self.argv = request.argv
            self.env = request.env
            assert request.timeout_seconds == GIT_TIMEOUT_SECONDS
            assert request.max_stdout_bytes == GIT_OUTPUT_BYTES
            assert request.max_stderr_bytes == GIT_OUTPUT_BYTES
            assert request.cwd == Path("/")
            return GitCommandResult(
                returncode=0,
                stdout=f"{ASVS_COMMIT}\trefs/tags/v5.0.0_release\n".encode(),
                stderr=b"",
                complete=True,
                timed_out=False,
                stdout_overflow=False,
                stderr_overflow=False,
            )

    runner = Runner()
    assert verify_ref(runner)
    assert runner.argv == (
        "/usr/bin/git",
        "ls-remote",
        "--refs",
        "https://github.com/OWASP/ASVS.git",
        "refs/tags/v5.0.0_release",
    )
    assert runner.env is not None
    assert "TASK2_SECRET_CANARY" not in dict(runner.env)


def test_verify_ref_does_not_run_beneath_repository_local_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A candidate-controlled .git/config must never mediate ref verification."""
    git_directory = tmp_path / ".git"
    git_directory.mkdir()
    _ = (git_directory / "config").write_text(
        '[url "https://attacker.invalid/"]\n\tinsteadOf = https://github.com/\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    class Runner:
        def run(self, request: GitCommandRequest) -> GitCommandResult:
            influenced = (request.cwd / ".git/config").exists()
            return GitCommandResult(
                returncode=0 if influenced else 2,
                stdout=(
                    f"{ASVS_COMMIT}\trefs/tags/v5.0.0_release\n".encode()
                    if influenced
                    else b""
                ),
                stderr=b"",
                complete=True,
                timed_out=False,
                stdout_overflow=False,
                stderr_overflow=False,
            )

    assert verify_ref(Runner()) is False


def test_exclusive_publisher_creates_both_artifacts_without_residue(
    tmp_path: Path,
) -> None:
    first = tmp_path / "requirements.json"
    second = tmp_path / "SHA256SUMS"

    ExclusiveArtifactPublisher().publish_pair(
        (first, b"first\n"),
        (second, b"second\n"),
    )

    assert first.read_bytes() == b"first\n"
    assert second.read_bytes() == b"second\n"
    assert tuple(tmp_path.glob(".*asvs*")) == ()


@pytest.mark.parametrize("existing", ["first", "second", "symlink"])
def test_exclusive_publisher_never_overwrites_and_rolls_back(
    tmp_path: Path,
    existing: str,
) -> None:
    first = tmp_path / "requirements.json"
    second = tmp_path / "SHA256SUMS"
    target = first if existing in {"first", "symlink"} else second
    original = b"user-owned\n"
    if existing == "symlink":
        outside = tmp_path / "outside"
        _ = outside.write_bytes(original)
        target.symlink_to(outside)
    else:
        _ = target.write_bytes(original)

    with pytest.raises(AsvsError):
        ExclusiveArtifactPublisher().publish_pair(
            (first, b"first\n"),
            (second, b"second\n"),
        )

    assert target.read_bytes() == original
    if existing == "second":
        assert first.exists() is False
    else:
        assert second.exists() is False


def test_exclusive_publisher_zero_write_leaves_no_partial_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    real_write = os.write

    def zero_after_first_write(descriptor: int, body: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == SECOND_WRITE_CALL:
            return 0
        return real_write(descriptor, body)

    monkeypatch.setattr(os, "write", zero_after_first_write)
    first = tmp_path / "requirements.json"
    second = tmp_path / "SHA256SUMS"

    with pytest.raises(AsvsError):
        ExclusiveArtifactPublisher().publish_pair(
            (first, b"first\n"),
            (second, b"second\n"),
        )

    assert first.exists() is False
    assert second.exists() is False


def test_exclusive_publisher_rolls_back_when_success_cleanup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failure after target linking must still roll back the full transaction."""
    real_unlink = os.unlink
    rejected_once = False

    def reject_first_lock_cleanup(
        path: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal rejected_once
        if path == ".asvs-fetch.lock" and not rejected_once:
            rejected_once = True
            msg = "injected lock cleanup failure"
            raise OSError(msg)
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", reject_first_lock_cleanup)
    first = tmp_path / "requirements.json"
    second = tmp_path / "SHA256SUMS"

    with pytest.raises(AsvsError, match="publication failed"):
        ExclusiveArtifactPublisher().publish_pair(
            (first, b"first\n"),
            (second, b"second\n"),
        )

    assert first.exists() is False
    assert second.exists() is False
    assert (tmp_path / ".asvs-fetch.lock").exists() is False


def test_exclusive_publisher_rolls_back_a_second_link_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_link = os.link
    calls = 0

    def fail_second_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == SECOND_WRITE_CALL:
            msg = "injected link failure"
            raise OSError(msg)
        real_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(os, "link", fail_second_link)
    first = tmp_path / "requirements.json"
    second = tmp_path / "SHA256SUMS"

    with pytest.raises(AsvsError, match="publication failed"):
        ExclusiveArtifactPublisher().publish_pair(
            (first, b"first\n"),
            (second, b"second\n"),
        )

    assert first.exists() is False
    assert second.exists() is False
    assert tuple(tmp_path.iterdir()) == ()


def test_exclusive_publisher_rolls_back_a_directory_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fsync = os.fsync
    calls = 0

    def fail_first_directory_sync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == DIRECTORY_FSYNC_CALL:
            msg = "injected directory fsync failure"
            raise OSError(msg)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_first_directory_sync)
    first = tmp_path / "requirements.json"
    second = tmp_path / "SHA256SUMS"

    with pytest.raises(AsvsError, match="publication failed"):
        ExclusiveArtifactPublisher().publish_pair(
            (first, b"first\n"),
            (second, b"second\n"),
        )

    assert first.exists() is False
    assert second.exists() is False
    assert tuple(tmp_path.iterdir()) == ()


def test_bounded_git_runner_captures_complete_raw_bytes() -> None:
    result = BoundedGitRunner().run(
        GitCommandRequest(
            argv=("/usr/bin/git", "--version"),
            timeout_seconds=2,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            env=(("LANG", "C"), ("LC_ALL", "C")),
            cwd=Path("/"),
        )
    )

    assert result.returncode == 0
    assert result.stdout.startswith(b"git version ")
    assert result.stderr == b""
    assert result.complete is True
    assert result.timed_out is False
    assert result.stdout_overflow is False
    assert result.stderr_overflow is False


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_bounded_git_runner_marks_overflow_and_kills_process_group(
    stream: str,
) -> None:
    alias = (
        "alias.spam=!/usr/bin/yes"
        if stream == "stdout"
        else "alias.spam=!/usr/bin/yes error >&2"
    )
    result = BoundedGitRunner().run(
        GitCommandRequest(
            argv=("/usr/bin/git", "-c", alias, "spam"),
            timeout_seconds=2,
            max_stdout_bytes=OVERFLOW_OUTPUT_BYTES,
            max_stderr_bytes=OVERFLOW_OUTPUT_BYTES,
            env=(("LANG", "C"), ("LC_ALL", "C")),
            cwd=Path("/"),
        )
    )

    assert result.complete is False
    assert result.timed_out is False
    assert (
        result.stdout_overflow if stream == "stdout" else result.stderr_overflow
    ) is True
    assert len(result.stdout) <= OVERFLOW_OUTPUT_BYTES
    assert len(result.stderr) <= OVERFLOW_OUTPUT_BYTES


def test_bounded_git_runner_timeout_kills_descendant(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived"
    alias = "alias.pause=!/usr/bin/sleep 0.2 && /usr/bin/touch " + marker.as_posix()
    result = BoundedGitRunner().run(
        GitCommandRequest(
            argv=("/usr/bin/git", "-c", alias, "pause"),
            timeout_seconds=0.05,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            env=(("LANG", "C"), ("LC_ALL", "C")),
            cwd=Path("/"),
        )
    )
    time.sleep(0.3)

    assert result.complete is False
    assert result.timed_out is True
    assert marker.exists() is False


def test_matrix_and_policy_render_exact_759_claim_product(tmp_path: Path) -> None:
    requirements = load_pinned_asvs_requirements()
    first_matrix = render_evidence_matrix(requirements)
    second_matrix = render_evidence_matrix(requirements)
    policy_body = render_evidence_policy(requirements)
    matrix_path = tmp_path / "matrix.jsonl"
    policy_path = tmp_path / "policy.json"
    _ = matrix_path.write_bytes(first_matrix)
    _ = policy_path.write_bytes(policy_body)

    assert first_matrix == second_matrix
    matrix = load_evidence_matrix(matrix_path)
    policy = load_independent_evidence_policy(policy_path)
    assert len(matrix) == MATRIX_RECORDS
    assert len(policy.claims) == MATRIX_RECORDS
    assert all(
        isinstance(row, ApplicableEvidenceRow) and row.verdict == "Not assessed"
        for row in matrix
    )
    assert all(claim.pass_required_kinds is None for claim in policy.claims)
    assert all(claim.na_absence_required is False for claim in policy.claims)
    assert policy.custody_authority_ids == ()
    assert policy.release_authority_ids == ()


def _artifact_state(
    path: Path,
) -> tuple[Path, bool, bytes | None, tuple[int, ...] | None]:
    if not path.exists():
        return (path, False, None, None)
    identity = path.stat()
    return (
        path,
        True,
        path.read_bytes(),
        (
            identity.st_dev,
            identity.st_ino,
            identity.st_mode,
            identity.st_nlink,
            identity.st_size,
            identity.st_mtime_ns,
            identity.st_ctime_ns,
        ),
    )


def test_check_mode_is_deterministic_and_side_effect_free() -> None:
    paths = (
        Path("security/asvs/requirements-5.0.0.json"),
        Path("security/asvs/SHA256SUMS"),
        Path("docs/security/asvs-5.0.0-l2-method.md"),
        Path("docs/security/asvs-evidence-policy.json"),
        Path("docs/security/asvs-5.0.0-l2-matrix.jsonl"),
        Path("docs/security/evidence-manifest.jsonl"),
        Path("docs/security/threat-model.json"),
        Path("docs/security/threat-model.md"),
    )
    before = tuple(_artifact_state(path) for path in paths)

    assert check_repository(Path.cwd()) is True
    assert main(["--check"]) == 0

    after = tuple(_artifact_state(path) for path in paths)
    assert after == before


def test_threat_ledger_covers_required_flows_stride_and_abuse(tmp_path: Path) -> None:
    body = render_threat_ledger()
    path = tmp_path / "threat-model.json"
    _ = path.write_bytes(body)
    ledger = load_threat_ledger(path)
    boundaries = {flow.boundary_id for flow in ledger.flows}
    stride = {
        category for threat in ledger.threats for category in threat.stride_categories
    }
    abuse = {
        category for threat in ledger.threats for category in threat.abuse_categories
    }

    assert boundaries >= {
        "client-to-alpic-edge",
        "alpic-edge-to-backend",
        "backend-to-nplg-jwks",
        "scanner-to-content-store",
        "scanner-to-pdf-worker",
        "build-to-deploy",
        "logging-privacy",
    }
    assert stride == {"S", "T", "R", "I", "D", "E"}
    assert abuse == {
        "token-session",
        "confused-deputy",
        "ssrf-dns-proxy",
        "parser-resource-exhaustion",
        "supply-chain-build-deploy",
        "logging-privacy",
    }
    assert all(threat.owner for threat in ledger.threats)
    assert all(threat.asvs_requirement_ids for threat in ledger.threats)
    assert all(threat.verification_selectors for threat in ledger.threats)
    assert all(
        threat.verification_status == "not_assessed" for threat in ledger.threats
    )
    assert all(
        assumption.status == "assumption-unverified"
        for assumption in ledger.provider_assumptions
    )
    assert ledger.release_status == "do_not_release"
    assert all(
        risk.disposition == "open-do-not-release" for risk in ledger.residual_risks
    )
    markdown = render_threat_model_markdown(ledger)
    assert b"```mermaid" in markdown
    assert b"## Threat ledger" in markdown
    assert b"## Residual risks" in markdown
    assert b"does not claim that any ASVS requirement has passed" in markdown
    assert markdown == render_threat_model_markdown(ledger)


def test_threat_ledger_declares_entry_points_and_supply_chain_controls() -> None:
    ledger = load_threat_ledger(Path("docs/security/threat-model.json"))
    entry_point_ids = {entry.entry_point_id for entry in ledger.entry_points}
    supply_chain = next(
        threat for threat in ledger.threats if threat.threat_id == "threat-supply-chain"
    )
    markdown = render_threat_model_markdown(ledger)

    assert entry_point_ids == {
        "entry-alpic-forward",
        "entry-audit-log-store",
        "entry-content-store",
        "entry-deployment-publication",
        "entry-jwks-provider",
        "entry-nplg-repository-api",
        "entry-pdf-worker",
        "entry-public-mcp",
    }
    assert supply_chain.asvs_requirement_ids == (
        "v5.0.0-V15.1.1",
        "v5.0.0-V15.1.2",
        "v5.0.0-V15.2.1",
    )
    supply_mitigations = " ".join(supply_chain.mitigations)
    assert "SBOM" in supply_mitigations
    assert "trusted repositories" in supply_mitigations
    assert "component freshness" in supply_mitigations
    assert "remediation timeframes" in supply_mitigations
    assert b"## Entry points" in markdown
    assert b"## Nodes and privileges" in markdown
    assert b"Trust zone" in markdown


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            b'"entry_point_id":"entry-alpic-forward","exposed_node_id":"python-backend"',
            b'"entry_point_id":"entry-alpic-forward","exposed_node_id":"alpic-edge"',
        ),
        (b"v5.0.0-V15.1.1", b"v5.0.0-V11.2.1"),
    ],
    ids=["entry-target", "supply-chain-mapping"],
)
def test_threat_ledger_rejects_entry_point_or_mapping_drift(
    tmp_path: Path,
    needle: bytes,
    replacement: bytes,
) -> None:
    body = render_threat_ledger()
    assert body.count(needle) == 1
    path = tmp_path / "threat-model.json"
    _ = path.write_bytes(body.replace(needle, replacement, 1))

    with pytest.raises(AsvsError):
        _ = load_threat_ledger(path)


@dataclass(frozen=True, slots=True)
class _ThreatMappingChanges:
    flow_ids: tuple[str, ...] | None = None
    boundary_ids: tuple[str, ...] | None = None
    abuse_categories: tuple[AbuseCategory, ...] | None = None
    affected_profiles: tuple[Profile, ...] | None = None
    verification_selectors: tuple[str, ...] | None = None
    asvs_requirement_ids: tuple[str, ...] | None = None
    residual_risk_id: str | None = None


def _threat_with_mappings(
    threat: ThreatRecord,
    changes: _ThreatMappingChanges,
) -> ThreatRecord:
    return ThreatRecord(
        threat_id=threat.threat_id,
        title=threat.title,
        flow_ids=changes.flow_ids or threat.flow_ids,
        boundary_ids=changes.boundary_ids or threat.boundary_ids,
        stride_categories=threat.stride_categories,
        abuse_categories=changes.abuse_categories or threat.abuse_categories,
        abuse_case=threat.abuse_case,
        affected_profiles=changes.affected_profiles or threat.affected_profiles,
        mitigations=threat.mitigations,
        verification_selectors=(
            changes.verification_selectors or threat.verification_selectors
        ),
        asvs_requirement_ids=(
            changes.asvs_requirement_ids or threat.asvs_requirement_ids
        ),
        assumed_provider_control_ids=threat.assumed_provider_control_ids,
        residual_risk_id=changes.residual_risk_id or threat.residual_risk_id,
        owner=threat.owner,
        verification_status=threat.verification_status,
        review_due=threat.review_due,
        invalidation_triggers=threat.invalidation_triggers,
    )


def _ledger_with_threats(
    ledger: ThreatLedger,
    threats: tuple[ThreatRecord, ...],
) -> ThreatLedger:
    return _ledger_with_topology(ledger, threats=threats)


def _ledger_with_topology(
    ledger: ThreatLedger,
    *,
    flows: tuple[ThreatFlow, ...] | None = None,
    entry_points: tuple[ThreatEntryPoint, ...] | None = None,
    threats: tuple[ThreatRecord, ...] | None = None,
    residual_risks: tuple[ResidualRiskRecord, ...] | None = None,
) -> ThreatLedger:
    return ThreatLedger(
        schema_version=ledger.schema_version,
        evidence_revision=ledger.evidence_revision,
        candidate_tree_sha256=ledger.candidate_tree_sha256,
        assets=ledger.assets,
        data_classes=ledger.data_classes,
        actors=ledger.actors,
        nodes=ledger.nodes,
        flows=flows or ledger.flows,
        entry_points=entry_points or ledger.entry_points,
        provider_assumptions=ledger.provider_assumptions,
        threats=threats or ledger.threats,
        residual_risks=residual_risks or ledger.residual_risks,
        global_invalidation_triggers=ledger.global_invalidation_triggers,
        release_status=ledger.release_status,
    )


def _flow_with_mapping(
    flow: ThreatFlow,
    *,
    boundary_id: str | None = None,
    data_classes: tuple[str, ...] | None = None,
) -> ThreatFlow:
    return ThreatFlow(
        flow_id=flow.flow_id,
        source=flow.source,
        target=flow.target,
        boundary_id=boundary_id or flow.boundary_id,
        protocol=flow.protocol,
        data_classes=data_classes or flow.data_classes,
    )


def _entry_with_mapping(
    entry: ThreatEntryPoint,
    *,
    entry_point_id: str | None = None,
    data_classes: tuple[str, ...] | None = None,
) -> ThreatEntryPoint:
    return ThreatEntryPoint(
        entry_point_id=entry_point_id or entry.entry_point_id,
        flow_id=entry.flow_id,
        exposed_node_id=entry.exposed_node_id,
        access_control=entry.access_control,
        affected_profiles=entry.affected_profiles,
        data_classes=data_classes or entry.data_classes,
    )


def _entry_sort_key(entry: ThreatEntryPoint) -> str:
    return entry.entry_point_id


def test_threat_ledger_rejects_coordinated_entry_point_identifier_swap() -> None:
    ledger = load_threat_ledger(Path("docs/security/threat-model.json"))
    first, second, *remaining = ledger.entry_points
    swapped = tuple(
        sorted(
            (
                _entry_with_mapping(first, entry_point_id=second.entry_point_id),
                _entry_with_mapping(second, entry_point_id=first.entry_point_id),
                *remaining,
            ),
            key=_entry_sort_key,
        )
    )

    with pytest.raises(ValidationError):
        _ = _ledger_with_topology(ledger, entry_points=swapped)


def test_threat_ledger_rejects_coordinated_flow_boundary_swap() -> None:
    ledger = load_threat_ledger(Path("docs/security/threat-model.json"))
    first, second, *remaining = ledger.flows
    flows = (
        _flow_with_mapping(first, boundary_id=second.boundary_id),
        _flow_with_mapping(second, boundary_id=first.boundary_id),
        *remaining,
    )
    boundaries = {flow.flow_id: flow.boundary_id for flow in flows}
    threats = tuple(
        _threat_with_mappings(
            threat,
            _ThreatMappingChanges(
                boundary_ids=tuple(sorted(boundaries[item] for item in threat.flow_ids))
            ),
        )
        for threat in ledger.threats
    )

    with pytest.raises(ValidationError):
        _ = _ledger_with_topology(ledger, flows=flows, threats=threats)


def test_threat_ledger_rejects_coordinated_flow_data_class_relabel() -> None:
    ledger = load_threat_ledger(Path("docs/security/threat-model.json"))
    flows = tuple(
        _flow_with_mapping(flow, data_classes=("access-tokens",))
        if flow.flow_id == "flow-backend-nplg"
        else flow
        for flow in ledger.flows
    )
    entries = tuple(
        _entry_with_mapping(entry, data_classes=("access-tokens",))
        if entry.flow_id == "flow-backend-nplg"
        else entry
        for entry in ledger.entry_points
    )

    with pytest.raises(ValidationError):
        _ = _ledger_with_topology(ledger, flows=flows, entry_points=entries)


def test_threat_ledger_rejects_profile_selector_and_asvs_relabelling() -> None:
    ledger = load_threat_ledger(Path("docs/security/threat-model.json"))
    parser = next(
        threat
        for threat in ledger.threats
        if threat.threat_id == "threat-parser-exhaustion"
    )
    auth = next(
        threat
        for threat in ledger.threats
        if threat.threat_id == "threat-auth-token-spoofing"
    )
    mutants = (
        _threat_with_mappings(
            parser,
            _ThreatMappingChanges(affected_profiles=PROFILES),
        ),
        _threat_with_mappings(
            parser,
            _ThreatMappingChanges(verification_selectors=("$(touch owned)",)),
        ),
        _threat_with_mappings(
            auth,
            _ThreatMappingChanges(asvs_requirement_ids=("v5.0.0-V11.2.1",)),
        ),
    )
    for mutant in mutants:
        threats = tuple(
            mutant if threat.threat_id == mutant.threat_id else threat
            for threat in ledger.threats
        )
        with pytest.raises(ValidationError):
            _ = _ledger_with_threats(ledger, threats)


def test_threat_ledger_rejects_one_way_residual_risk_edge() -> None:
    ledger = load_threat_ledger(Path("docs/security/threat-model.json"))
    first, second, *remaining = ledger.residual_risks
    widened = ResidualRiskRecord(
        residual_risk_id=first.residual_risk_id,
        threat_ids=(first.threat_ids[0], second.threat_ids[0]),
        description=first.description,
        disposition=first.disposition,
        owner=first.owner,
        review_due=first.review_due,
    )

    with pytest.raises(ValidationError):
        _ = _ledger_with_topology(
            ledger,
            residual_risks=(widened, second, *remaining),
        )


def test_threat_ledger_rejects_missing_required_category(tmp_path: Path) -> None:
    body = render_threat_ledger()
    path = Path("docs/security/threat-model.json")
    if path.exists():
        ledger = load_threat_ledger(path)
    else:
        temporary = tmp_path / "threat-model.json"
        _ = temporary.write_bytes(body)
        ledger = load_threat_ledger(temporary)
    with pytest.raises(ValidationError):
        _ = _ledger_with_threats(ledger, ledger.threats[:-1])


def test_threat_mapping_binds_boundaries_to_its_selected_flows() -> None:
    """A globally valid boundary cannot be relabelled onto unrelated flows."""
    ledger = load_threat_ledger(Path("docs/security/threat-model.json"))
    first = _threat_with_mappings(
        ledger.threats[0],
        _ThreatMappingChanges(boundary_ids=("logging-privacy",)),
    )

    with pytest.raises(ValidationError):
        _ = _ledger_with_threats(ledger, (first, *ledger.threats[1:]))


def test_threat_loader_rejects_unknown_asvs_mapping(tmp_path: Path) -> None:
    body = render_threat_ledger()
    path = tmp_path / "threat-model.json"
    _ = path.write_bytes(body)
    ledger = load_threat_ledger(path)
    known_identifier = ledger.threats[0].asvs_requirement_ids[0].encode("ascii")
    unknown_identifier = b"v5.0.0-V999.999.999"
    malformed = body.replace(known_identifier, unknown_identifier, 1)
    _ = path.write_bytes(malformed)

    with pytest.raises(AsvsError):
        _ = load_threat_ledger(path)


def test_check_mode_rejects_threat_markdown_drift(tmp_path: Path) -> None:
    inventory_paths = (
        "security/asvs/requirements-5.0.0.json",
        "security/asvs/SHA256SUMS",
        "docs/security/asvs-evidence-policy.json",
        "docs/security/asvs-5.0.0-l2-matrix.jsonl",
        "docs/security/asvs-5.0.0-l2-method.md",
        "docs/security/evidence-manifest.jsonl",
        "docs/security/threat-model.json",
        "docs/security/threat-model.md",
    )
    for relative in inventory_paths:
        source = Path(relative)
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.name == "threat-model.json" and not source.exists():
            _ = target.write_bytes(render_threat_ledger())
        elif source.name == "threat-model.md":
            _ = target.write_bytes(
                render_threat_model_markdown(
                    load_threat_ledger(tmp_path / "docs/security/threat-model.json")
                )
            )
        else:
            _ = target.write_bytes(source.read_bytes())

    assert check_repository(tmp_path) is True
    threat_markdown = tmp_path / "docs/security/threat-model.md"
    _ = threat_markdown.write_bytes(threat_markdown.read_bytes() + b"drift\n")
    assert check_repository(tmp_path) is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("selectors", ("tests/test_claim.py::test_it", "tests/test_claim.py::test_it")),
        ("selectors", (" tests/test_claim.py::test_it",)),
        ("requirement_ids", ("v5.0.0-V1.1.1", "v5.0.0-V1.1.1")),
        ("profiles", ("alpic-metadata", "alpic-metadata")),
    ],
    ids=(
        "duplicate-selector",
        "whitespace-selector",
        "duplicate-claim",
        "duplicate-profile",
    ),
)
def test_evidence_reference_rejects_ambiguous_claim_members(
    field: str,
    value: object,
) -> None:
    candidate = _local_evidence()
    candidate[field] = value

    with pytest.raises(ValidationError, match="claim members must be unique"):
        _ = LocalEvidenceReference.model_validate(candidate)


def test_evidence_reference_requires_strictly_later_expiry() -> None:
    candidate = _local_evidence()
    candidate["expires_at"] = candidate["collected_at"]

    with pytest.raises(ValidationError, match="expiry must be later"):
        _ = LocalEvidenceReference.model_validate(candidate)


@pytest.mark.parametrize(
    "artifact_path",
    ["", "evidence\\report.json", "evidence/\x01.json"],
)
def test_local_evidence_rejects_unsafe_path_octets(artifact_path: str) -> None:
    candidate = _local_evidence()
    candidate["artifact_path"] = artifact_path

    with pytest.raises(ValidationError, match="safe repository-relative path"):
        _ = LocalEvidenceReference.model_validate(candidate)


def test_applicable_and_na_rows_reject_structurally_invalid_state() -> None:
    duplicate_evidence = _applicable_row() | {
        "evidence_ids": ("ev.fixture", "ev.fixture")
    }
    non_risk_with_risk_field = _applicable_row() | {"risk_id": "risk.fixture"}
    expired_risk = _applicable_row() | {
        "compensating_controls": ("control.fixture",),
        "release_approval_evidence_id": "approval.fixture",
        "residual_risk": "Residual risk remains explicitly bounded.",
        "risk_approver": "approver-subject",
        "risk_expiry": date(2026, 8, 16),
        "risk_id": "risk.fixture",
        "risk_owner": "risk-owner",
        "verdict": "Risk accepted",
    }
    na_with_applicable_evidence = _not_applicable_row() | {
        "evidence_ids": ("ev.fixture",)
    }
    expired_na_review = _not_applicable_row() | {
        "applicability_review_due": date(2026, 8, 16)
    }

    for candidate in (duplicate_evidence, non_risk_with_risk_field, expired_risk):
        with pytest.raises(ValidationError):
            _ = ApplicableEvidenceRow.model_validate(candidate)
    for candidate in (na_with_applicable_evidence, expired_na_review):
        with pytest.raises(ValidationError):
            _ = NotApplicableEvidenceRow.model_validate(candidate)


@pytest.mark.parametrize(
    "pass_required_kinds",
    [(), ("test", "test"), ("test", "design")],
    ids=("empty", "duplicate", "unsorted"),
)
def test_claim_policy_rejects_ambiguous_pass_kinds(
    pass_required_kinds: tuple[str, ...],
) -> None:
    candidate: dict[str, object] = {
        "requirement_id": "v5.0.0-V1.1.1",
        "profile": "alpic-metadata",
        "pass_required_kinds": pass_required_kinds,
        "na_absence_required": False,
        "risk_acceptance_authority_id": None,
    }
    with pytest.raises(ValidationError, match="Pass evidence kinds"):
        _ = ClaimPolicyRecord.model_validate(candidate)


def test_evidence_policy_rejects_profile_order_claim_order_and_authority() -> None:
    policy = _evidence_policy()
    with pytest.raises(ValidationError, match="exact reviewed profile order"):
        _ = EvidencePolicy(
            schema_version=policy.schema_version,
            asvs_version=policy.asvs_version,
            asvs_source_commit=policy.asvs_source_commit,
            evidence_revision=policy.evidence_revision,
            candidate_tree_sha256=policy.candidate_tree_sha256,
            attestation_allowlist=policy.attestation_allowlist,
            profiles=("distributed-full", "private-full", "alpic-metadata"),
            claims=policy.claims,
            custody_authority_ids=(),
            release_authority_ids=(),
        )

    claims = list(policy.claims)
    claims[0], claims[1] = claims[1], claims[0]
    with pytest.raises(ValidationError, match="canonical requirement/profile order"):
        _ = EvidencePolicy(
            schema_version=policy.schema_version,
            asvs_version=policy.asvs_version,
            asvs_source_commit=policy.asvs_source_commit,
            evidence_revision=policy.evidence_revision,
            candidate_tree_sha256=policy.candidate_tree_sha256,
            attestation_allowlist=policy.attestation_allowlist,
            profiles=policy.profiles,
            claims=tuple(claims),
            custody_authority_ids=(),
            release_authority_ids=(),
        )

    with pytest.raises(ValidationError, match="release authority identifiers"):
        _ = EvidencePolicy(
            schema_version=policy.schema_version,
            asvs_version=policy.asvs_version,
            asvs_source_commit=policy.asvs_source_commit,
            evidence_revision=policy.evidence_revision,
            candidate_tree_sha256=policy.candidate_tree_sha256,
            attestation_allowlist=policy.attestation_allowlist,
            profiles=policy.profiles,
            claims=policy.claims,
            custody_authority_ids=(),
            release_authority_ids=("z-authority", "a-authority"),
        )

    amended = ClaimPolicyRecord(
        requirement_id=policy.claims[0].requirement_id,
        profile=policy.claims[0].profile,
        pass_required_kinds=None,
        na_absence_required=False,
        risk_acceptance_authority_id="unapproved-authority",
    )
    with pytest.raises(ValidationError, match="unapproved release authority"):
        _ = EvidencePolicy(
            schema_version=policy.schema_version,
            asvs_version=policy.asvs_version,
            asvs_source_commit=policy.asvs_source_commit,
            evidence_revision=policy.evidence_revision,
            candidate_tree_sha256=policy.candidate_tree_sha256,
            attestation_allowlist=policy.attestation_allowlist,
            profiles=policy.profiles,
            claims=(amended, *policy.claims[1:]),
            custody_authority_ids=(),
            release_authority_ids=(),
        )


def test_evidence_policy_lookup_fails_closed_for_an_unknown_claim() -> None:
    with pytest.raises(AsvsError, match="does not contain"):
        _ = _evidence_policy().claim_for("v5.0.0-V99.99.99", "alpic-metadata")


def test_receipt_and_release_decision_reject_contradictory_states() -> None:
    risk_receipt = _custody_receipt(risk_id="risk.fixture")
    receipt_json = risk_receipt.model_dump_json()
    missing_approval = receipt_json.replace(
        '"approver_subject":"approver-subject"',
        '"approver_subject":null',
    )
    with pytest.raises(ValidationError, match="full external approval subject"):
        _ = CustodyReceipt.model_validate_json(missing_approval)

    generic_with_risk = receipt_json.replace(
        '"decision":"risk_approved"',
        '"decision":"evidence_verified"',
    )
    with pytest.raises(ValidationError, match="forbids risk approval fields"):
        _ = CustodyReceipt.model_validate_json(generic_with_risk)

    invalid_decisions = (
        {
            "profile": "alpic-metadata",
            "decision": "do_not_release",
            "eligible": True,
            "reason_codes": (),
        },
        {
            "profile": "alpic-metadata",
            "decision": "do_not_release",
            "eligible": False,
            "reason_codes": ("failed", "failed"),
        },
        {
            "profile": "alpic-metadata",
            "decision": "release",
            "eligible": True,
            "reason_codes": ("failed",),
        },
        {
            "profile": "alpic-metadata",
            "decision": "do_not_release",
            "eligible": False,
            "reason_codes": (),
        },
    )
    for candidate in invalid_decisions:
        with pytest.raises(ValidationError):
            _ = ReleaseDecision.model_validate(candidate)


def test_verified_candidate_rejects_duplicate_selector_claim_bindings() -> None:
    reference = LocalEvidenceReference.model_validate(_local_evidence())
    binding = ReviewedSelectorBinding(
        selector=reference.selectors[0],
        claim_purpose="positive-control",
        kind=reference.kind,
        verifier=reference.verifier,
        artifact_path=reference.artifact_path,
        artifact_sha256=reference.sha256,
        evidence_revision=reference.evidence_revision,
        candidate_tree_sha256=reference.candidate_tree_sha256,
        requirement_id="v5.0.0-V1.1.1",
        profile="alpic-metadata",
        asserted_invariant=reference.asserted_invariant,
        covered_surface=reference.covered_surface,
    )

    with pytest.raises(ValidationError, match="selector registry entries"):
        _ = VerifiedCandidateSnapshot(
            root_device=1,
            root_inode=1,
            evidence_revision=reference.evidence_revision,
            candidate_tree_sha256=reference.candidate_tree_sha256,
            clean=True,
            selector_bindings=(binding, binding),
        )


def test_claim_binding_accepts_a_bound_non_pass_reference() -> None:
    row = ApplicableEvidenceRow.model_validate(
        _applicable_row()
        | {
            "evidence_ids": ("ev.fixture",),
            "invariant": "The exact requirement/profile claim was tested.",
        }
    )
    reference = LocalEvidenceReference.model_validate(_local_evidence())

    assert verify_claim_binding(row, reference) is True


def _applicable_with_verdict(
    row: ApplicableEvidenceRow,
    verdict: Literal["Pass", "Fail", "Partial", "Not assessed"],
    *,
    evidence_id: str | None = None,
    evidence_revision: str | None = None,
) -> ApplicableEvidenceRow:
    return ApplicableEvidenceRow(
        asvs_version=row.asvs_version,
        requirement_id=row.requirement_id,
        level=row.level,
        requirement_text=row.requirement_text,
        profile=row.profile,
        evidence_revision=(
            row.evidence_revision if evidence_revision is None else evidence_revision
        ),
        invariant=row.invariant,
        threat_boundary=row.threat_boundary,
        evidence_ids=(evidence_id,) if evidence_id is not None else (),
        required_evidence_kinds=("test",) if evidence_id is not None else (),
        owner=row.owner,
        target_phase=row.target_phase,
        evidence_date=row.evidence_date,
        applicability="applicable",
        applicability_rationale=row.applicability_rationale,
        verdict=verdict,
    )


def _updated_applicable_row(
    row: ApplicableEvidenceRow,
    updates: dict[str, object],
) -> ApplicableEvidenceRow:
    return ApplicableEvidenceRow.model_validate(
        cast("dict[str, object]", row.model_dump(exclude_none=True)) | updates
    )


def _updated_not_applicable_row(
    row: ApplicableEvidenceRow,
    updates: dict[str, object],
) -> NotApplicableEvidenceRow:
    return NotApplicableEvidenceRow.model_validate(
        cast("dict[str, object]", row.model_dump(exclude_none=True)) | updates
    )


def _updated_custody_receipt(
    receipt: CustodyReceipt,
    updates: dict[str, object],
) -> CustodyReceipt:
    return CustodyReceipt.model_validate(
        cast("dict[str, object]", receipt.model_dump()) | updates
    )


def _updated_custodied_evidence(
    reference: CustodiedEvidenceReference,
    updates: dict[str, object],
) -> CustodiedEvidenceReference:
    return CustodiedEvidenceReference.model_validate(
        cast("dict[str, object]", reference.model_dump()) | updates
    )


def _updated_evidence(
    reference: LocalEvidenceReference | CustodiedEvidenceReference,
    updates: dict[str, object],
) -> LocalEvidenceReference | CustodiedEvidenceReference:
    if isinstance(reference, LocalEvidenceReference):
        return LocalEvidenceReference.model_validate(
            cast("dict[str, object]", reference.model_dump()) | updates
        )
    return _updated_custodied_evidence(reference, updates)


def _candidate_pass_product(
    *,
    storage: Literal["local", "custodied-uri"] = "local",
) -> tuple[
    tuple[ApplicableEvidenceRow, ...],
    tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...],
]:
    selected = tuple(
        row
        for row in load_evidence_matrix()
        if isinstance(row, ApplicableEvidenceRow) and row.profile == "alpic-metadata"
    )
    rows = tuple(
        _applicable_with_verdict(
            row,
            "Pass",
            evidence_id=f"ev.{index:03d}",
            evidence_revision=CANDIDATE_REVISION,
        )
        for index, row in enumerate(selected)
    )
    evidence_data = tuple(
        (_custodied_evidence() if storage == "custodied-uri" else _local_evidence())
        | {
            "candidate_tree_sha256": CANDIDATE_TREE_SHA256,
            "claim_purpose": "implementation-proof",
            "evidence_id": f"ev.{index:03d}",
            "evidence_revision": CANDIDATE_REVISION,
            "requirement_ids": (row.requirement_id,),
            "asserted_invariant": row.invariant,
        }
        for index, row in enumerate(rows)
    )
    if storage == "custodied-uri":
        evidence: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...] = (
            tuple(
                CustodiedEvidenceReference.model_validate(item)
                for item in evidence_data
            )
        )
    else:
        evidence = tuple(
            LocalEvidenceReference.model_validate(item) for item in evidence_data
        )
    return rows, evidence


def _governed_candidate_na(
    row: ApplicableEvidenceRow,
    index: int,
    *,
    review_due: date = CANDIDATE_REVIEW_DUE,
) -> NotApplicableEvidenceRow:
    return _updated_not_applicable_row(
        row,
        {
            "absence_evidence_ids": (f"absence.{index:03d}",),
            "applicability": "not_applicable",
            "applicability_rationale": (
                "Independent review confirms the candidate omits this capability."
            ),
            "applicability_review_due": review_due,
            "applicability_reviewer": "independent-security-reviewer",
            "evidence_ids": (),
            "required_evidence_kinds": (),
            "verdict": "N/A",
        },
    )


def _candidate_absence_evidence(
    row: NotApplicableEvidenceRow,
    index: int,
) -> CustodiedEvidenceReference:
    return CustodiedEvidenceReference.model_validate(
        _custodied_evidence()
        | {
            "asserted_invariant": row.invariant,
            "candidate_tree_sha256": CANDIDATE_TREE_SHA256,
            "claim_purpose": "absence-proof",
            "custody_receipt_id": f"receipt.absence.{index:03d}",
            "evidence_id": f"absence.{index:03d}",
            "evidence_revision": CANDIDATE_REVISION,
            "kind": "design",
            "requirement_ids": (row.requirement_id,),
        }
    )


def _verified_candidate_release(
    rows: tuple[ApplicableEvidenceRow | NotApplicableEvidenceRow, ...],
    evidence: tuple[CustodiedEvidenceReference, ...],
    *,
    as_of: datetime = CANDIDATE_AS_OF,
) -> ReleaseDecision:
    receipts = {
        reference.evidence_id: _updated_custody_receipt(
            _custody_receipt(reference=reference),
            {
                "claim_purpose": (
                    "absence-proof"
                    if isinstance(row, NotApplicableEvidenceRow)
                    else "positive-control"
                ),
                "nonce": f"nonce.{index}",
                "requirement_id": row.requirement_id,
            },
        )
        for index, (row, reference) in enumerate(zip(rows, evidence, strict=True))
    }

    class Authority:
        authority_id = "ci.example"

        def verify_receipt(
            self, reference: CustodiedEvidenceReference
        ) -> CustodyReceipt | None:
            return receipts.get(reference.evidence_id)

    class ReplayRegistry:
        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            return bool(nonce and subject_sha256)

    return evaluate_profile_release(
        profile="alpic-metadata",
        candidate={
            "revision": CANDIDATE_REVISION,
            "tree_sha256": CANDIDATE_TREE_SHA256,
        },
        matrix=rows,
        evidence=evidence,
        assessment_mode="candidate",
        as_of=as_of,
        verification_context=replace(
            _verification_context(),
            authorities=(Authority(),),
            replay_registry=ReplayRegistry(),
        ),
    )


def test_release_assessment_rejects_closed_mode_boundary_faults() -> None:
    """Every malformed mode tuple fails before candidate evidence is trusted."""
    candidate_rows, candidate_evidence = _candidate_pass_product()
    unchecked_evaluate = cast(
        "_UncheckedReleaseEvaluator",
        cast("object", evaluate_profile_release),
    )
    invalid_calls: tuple[tuple[str, Callable[[], ReleaseDecision]], ...] = (
        (
            "unknown option",
            lambda: unchecked_evaluate(unknown_option=True),
        ),
        (
            "complete legacy inputs",
            evaluate_profile_release,
        ),
        (
            "forbids candidate inputs",
            lambda: evaluate_profile_release(
                profile="alpic-metadata",
                rows=load_evidence_matrix(),
                manifest=load_evidence_manifest(),
                policy=load_independent_evidence_policy(),
                context=_verification_context(),
                candidate={
                    "revision": CANDIDATE_REVISION,
                    "tree_sha256": CANDIDATE_TREE_SHA256,
                },
            ),
        ),
        (
            "outside the closed inventory",
            lambda: unchecked_evaluate(assessment_mode="preview"),
        ),
        (
            "complete candidate inputs",
            lambda: evaluate_profile_release(
                profile="alpic-metadata",
                assessment_mode="candidate",
            ),
        ),
        (
            "strict revision/tree binding",
            lambda: unchecked_evaluate(
                profile="alpic-metadata",
                candidate={"revision": 7},
                matrix=candidate_rows,
                evidence=candidate_evidence,
                assessment_mode="candidate",
                as_of=CANDIDATE_AS_OF,
            ),
        ),
    )

    for expected, evaluate in invalid_calls:
        with pytest.raises(AsvsError, match=expected):
            _ = evaluate()


def test_candidate_assessment_rejects_profile_and_nonpass_row() -> None:
    """Unsupported profiles and non-Pass applicable rows remain release blockers."""
    rows, evidence = _candidate_pass_product()
    candidate = {
        "revision": CANDIDATE_REVISION,
        "tree_sha256": CANDIDATE_TREE_SHA256,
    }

    unsupported = evaluate_profile_release(
        profile="private-full",
        candidate=candidate,
        matrix=rows,
        evidence=evidence,
        assessment_mode="candidate",
        as_of=CANDIDATE_AS_OF,
    )
    failed = evaluate_profile_release(
        profile="alpic-metadata",
        candidate=candidate,
        matrix=(
            _updated_applicable_row(rows[0], {"verdict": "Fail"}),
            *rows[1:],
        ),
        evidence=evidence,
        assessment_mode="candidate",
        as_of=CANDIDATE_AS_OF,
    )

    assert "candidate-profile-not-supported" in unsupported.reason_codes
    assert "candidate-row-not-pass" in failed.reason_codes


@pytest.mark.parametrize(
    "verdict",
    ["Not assessed", "Fail", "Partial"],
)
def test_bootstrap_rejects_every_nonhistorical_status_product(
    verdict: Literal["Fail", "Partial", "Not assessed"],
) -> None:
    selected = tuple(
        row
        for row in load_evidence_matrix()
        if isinstance(row, ApplicableEvidenceRow) and row.profile == "alpic-metadata"
    )
    rows = tuple(_applicable_with_verdict(row, verdict) for row in selected)

    decision = evaluate_profile_release(
        "alpic-metadata",
        rows,
        (),
        policy=_evidence_policy(),
        context=_verification_context(),
    )

    assert decision.reason_codes == ("bootstrap-product-mismatch",)


def test_profile_release_rejects_incomplete_and_unverified_pass_products() -> None:
    incomplete = evaluate_profile_release(
        "alpic-metadata",
        (),
        (),
        policy=_evidence_policy(),
        context=_verification_context(),
    )
    selected = tuple(
        row
        for row in load_evidence_matrix()
        if isinstance(row, ApplicableEvidenceRow) and row.profile == "alpic-metadata"
    )
    pass_rows = tuple(
        _applicable_with_verdict(
            row,
            "Pass",
            evidence_id=f"ev.{offset:03d}",
        )
        for offset, row in enumerate(selected)
    )
    unverified = evaluate_profile_release(
        "alpic-metadata",
        pass_rows,
        (),
        policy=_evidence_policy(),
        context=_verification_context(),
    )

    assert incomplete.reason_codes == ("bootstrap-product-mismatch",)
    assert unverified.reason_codes == ("bootstrap-product-mismatch",)


def test_candidate_assessment_accepts_a_complete_independently_bound_pass_product() -> (
    None
):
    """Mutation caught: candidate mode never permits an evidenced Pass product."""
    rows, references = _candidate_pass_product(storage="custodied-uri")
    evidence = tuple(cast("CustodiedEvidenceReference", item) for item in references)
    receipts = {
        reference.evidence_id: _updated_custody_receipt(
            _custody_receipt(reference=reference),
            {"nonce": f"nonce.{index}", "requirement_id": row.requirement_id},
        )
        for index, (row, reference) in enumerate(zip(rows, evidence, strict=True))
    }

    class Authority:
        authority_id = "ci.example"

        def verify_receipt(
            self, reference: CustodiedEvidenceReference
        ) -> CustodyReceipt | None:
            return receipts[reference.evidence_id]

    class ReplayRegistry:
        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            return bool(nonce and subject_sha256)

    verdict = evaluate_profile_release(
        profile="alpic-metadata",
        candidate={
            "revision": CANDIDATE_REVISION,
            "tree_sha256": CANDIDATE_TREE_SHA256,
        },
        matrix=rows,
        evidence=evidence,
        assessment_mode="candidate",
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
        verification_context=replace(
            _verification_context(),
            authorities=(Authority(),),
            replay_registry=ReplayRegistry(),
        ),
    )

    assert verdict.decision == "release"
    assert verdict.reason_codes == ()


def test_candidate_assessment_accepts_one_governed_na_in_the_exact_product() -> None:
    """Mutation caught: governed N/A can never survive full-product evaluation."""
    pass_rows, pass_references = _candidate_pass_product(storage="custodied-uri")
    na_row = _governed_candidate_na(pass_rows[0], 0)
    rows: tuple[ApplicableEvidenceRow | NotApplicableEvidenceRow, ...] = (
        na_row,
        *pass_rows[1:],
    )
    absence_reference = _candidate_absence_evidence(na_row, 0)
    evidence = (
        absence_reference,
        *(cast("CustodiedEvidenceReference", item) for item in pass_references[1:]),
    )
    receipts = {
        reference.evidence_id: _updated_custody_receipt(
            _custody_receipt(reference=reference),
            {
                "claim_purpose": (
                    "absence-proof"
                    if isinstance(row, NotApplicableEvidenceRow)
                    else "positive-control"
                ),
                "nonce": f"nonce.{index}",
                "requirement_id": row.requirement_id,
            },
        )
        for index, (row, reference) in enumerate(zip(rows, evidence, strict=True))
    }

    class Authority:
        authority_id = "ci.example"

        def verify_receipt(
            self, reference: CustodiedEvidenceReference
        ) -> CustodyReceipt | None:
            return receipts[reference.evidence_id]

    class ReplayRegistry:
        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            return bool(nonce and subject_sha256)

    verdict = evaluate_profile_release(
        profile="alpic-metadata",
        candidate={
            "revision": CANDIDATE_REVISION,
            "tree_sha256": CANDIDATE_TREE_SHA256,
        },
        matrix=rows,
        evidence=evidence,
        assessment_mode="candidate",
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
        verification_context=replace(
            _verification_context(),
            authorities=(Authority(),),
            replay_registry=ReplayRegistry(),
        ),
    )

    assert len({row.requirement_id for row in rows}) == CANDIDATE_RECORDS
    assert verdict.decision == "release"
    assert verdict.reason_codes == ()


@pytest.mark.parametrize(
    "fault",
    ["requirement-id", "level", "requirement-text"],
)
def test_candidate_assessment_rejects_pinned_source_semantic_substitutions(
    fault: str,
) -> None:
    """Matching evidence and custody cannot rescue altered official controls."""
    pass_rows, pass_references = _candidate_pass_product(storage="custodied-uri")
    rows = list(pass_rows)
    evidence = [cast("CustodiedEvidenceReference", item) for item in pass_references]
    first = rows[0]
    if fault == "requirement-id":
        second = rows[1]
        rows[0] = _updated_applicable_row(
            first, {"requirement_id": second.requirement_id}
        )
        rows[1] = _updated_applicable_row(
            second, {"requirement_id": first.requirement_id}
        )
        evidence[0] = _updated_custodied_evidence(
            evidence[0], {"requirement_ids": (rows[0].requirement_id,)}
        )
        evidence[1] = _updated_custodied_evidence(
            evidence[1], {"requirement_ids": (rows[1].requirement_id,)}
        )
    elif fault == "level":
        rows[0] = _updated_applicable_row(
            first, {"level": 2 if first.level == 1 else 1}
        )
    else:
        rows[0] = _updated_applicable_row(
            first, {"requirement_text": f"{first.requirement_text} Altered."}
        )

    verdict = _verified_candidate_release(tuple(rows), tuple(evidence))

    assert "pinned-requirement-semantics-mismatch" in verdict.reason_codes


@pytest.mark.parametrize(
    ("review_due", "eligible"),
    [
        (date(2026, 8, 22), False),
        (date(2026, 8, 23), False),
        (date(2026, 8, 24), True),
    ],
    ids=("before", "equal", "after"),
)
def test_candidate_na_review_must_outlive_the_full_assessment(
    review_due: date,
    *,
    eligible: bool,
) -> None:
    """An otherwise valid 253-row product cannot use a stale N/A review."""
    pass_rows, pass_references = _candidate_pass_product(storage="custodied-uri")
    na_row = _governed_candidate_na(pass_rows[0], 0, review_due=review_due)
    rows: tuple[ApplicableEvidenceRow | NotApplicableEvidenceRow, ...] = (
        na_row,
        *pass_rows[1:],
    )
    evidence = (
        _candidate_absence_evidence(na_row, 0),
        *(cast("CustodiedEvidenceReference", item) for item in pass_references[1:]),
    )

    verdict = _verified_candidate_release(rows, evidence)

    assert verdict.eligible is eligible
    if eligible:
        assert verdict.reason_codes == ()
    else:
        assert "expired-na-review" in verdict.reason_codes


@pytest.mark.parametrize(
    ("collected_at", "expires_at", "eligible"),
    [
        (
            datetime(2026, 8, 23, tzinfo=UTC),
            datetime(2026, 8, 24, tzinfo=UTC),
            True,
        ),
        (
            datetime(2026, 8, 23, 0, 1, tzinfo=UTC),
            datetime(2026, 8, 24, tzinfo=UTC),
            False,
        ),
        (
            datetime(2026, 8, 16, tzinfo=UTC),
            datetime(2026, 8, 23, tzinfo=UTC),
            False,
        ),
    ],
    ids=("collected-at-boundary", "future-collected", "expiry-boundary"),
)
def test_candidate_evidence_uses_the_same_instant_window_as_verification(
    collected_at: datetime,
    expires_at: datetime,
    *,
    eligible: bool,
) -> None:
    """Candidate evidence is current exactly when collected <= as_of < expiry."""
    rows, pass_references = _candidate_pass_product(storage="custodied-uri")
    evidence = tuple(
        cast("CustodiedEvidenceReference", item) for item in pass_references
    )
    evidence = (
        _updated_custodied_evidence(
            evidence[0], {"collected_at": collected_at, "expires_at": expires_at}
        ),
        *evidence[1:],
    )

    verdict = _verified_candidate_release(rows, evidence)

    assert verdict.eligible is eligible


def test_candidate_assessment_rejects_substituted_and_extra_profile_rows() -> None:
    """Mutation caught: candidate selection accepts arbitrary or ignored matrix rows."""
    candidate = "a" * 40
    tree = "b" * 64
    selected = tuple(
        row
        for row in load_evidence_matrix()
        if isinstance(row, ApplicableEvidenceRow) and row.profile == "alpic-metadata"
    )
    rows = tuple(
        _applicable_with_verdict(
            row,
            "Pass",
            evidence_id=f"ev.{index:03d}",
            evidence_revision=candidate,
        )
        for index, row in enumerate(selected)
    )
    evidence = tuple(
        LocalEvidenceReference.model_validate(
            _local_evidence()
            | {
                "candidate_tree_sha256": tree,
                "claim_purpose": "implementation-proof",
                "evidence_id": f"ev.{index:03d}",
                "evidence_revision": candidate,
                "requirement_ids": (row.requirement_id,),
                "asserted_invariant": row.invariant,
            }
        )
        for index, row in enumerate(rows)
    )
    substituted = (
        *rows[:-1],
        _updated_applicable_row(rows[-1], {"requirement_id": "v5.0.0-V99.9.9"}),
    )
    extra = (*rows, load_evidence_matrix()[1])

    matrices: tuple[
        tuple[ApplicableEvidenceRow | NotApplicableEvidenceRow, ...], ...
    ] = (substituted, rows[:-1], extra)
    for matrix in matrices:
        verdict = evaluate_profile_release(
            profile="alpic-metadata",
            candidate={"revision": candidate, "tree_sha256": tree},
            matrix=matrix,
            evidence=evidence,
            assessment_mode="candidate",
            as_of=datetime(2026, 8, 23, tzinfo=UTC),
        )

        assert "pinned-requirement-set-mismatch" in verdict.reason_codes


@pytest.mark.parametrize(
    ("fault", "expected"),
    [
        ("revision-mismatch", "candidate-binding-mismatch"),
        ("wrong-claim-purpose", "wrong-claim-purpose"),
        ("missing-required-kind", "missing-required-evidence"),
    ],
)
def test_candidate_assessment_rejects_complete_pass_product_faults(
    fault: str,
    expected: str,
) -> None:
    """Mutation caught: complete selected products can bypass claim governance."""
    rows, evidence = _candidate_pass_product()
    if fault == "revision-mismatch":
        evidence = (
            _updated_evidence(evidence[0], {"evidence_revision": "c" * 40}),
            *evidence[1:],
        )
    elif fault == "wrong-claim-purpose":
        evidence = (
            _updated_evidence(evidence[0], {"claim_purpose": "absence-proof"}),
            *evidence[1:],
        )
    else:
        rows = (
            _updated_applicable_row(rows[0], {"required_evidence_kinds": ("design",)}),
            *rows[1:],
        )

    verdict = evaluate_profile_release(
        profile="alpic-metadata",
        candidate={
            "revision": CANDIDATE_REVISION,
            "tree_sha256": CANDIDATE_TREE_SHA256,
        },
        matrix=rows,
        evidence=evidence,
        assessment_mode="candidate",
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    )

    assert "pinned-requirement-set-mismatch" not in verdict.reason_codes
    assert expected in verdict.reason_codes


def test_candidate_bulk_na_conversion_reaches_absence_governance() -> None:
    """Mutation caught: bulk N/A conversion evades per-row absence governance."""
    pass_rows, _ = _candidate_pass_product()
    rows = tuple(
        _governed_candidate_na(row, index) for index, row in enumerate(pass_rows)
    )

    verdict = evaluate_profile_release(
        profile="alpic-metadata",
        candidate={
            "revision": CANDIDATE_REVISION,
            "tree_sha256": CANDIDATE_TREE_SHA256,
        },
        matrix=rows,
        evidence=(),
        assessment_mode="candidate",
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    )

    assert len({row.requirement_id for row in rows}) == CANDIDATE_RECORDS
    assert "pinned-requirement-set-mismatch" not in verdict.reason_codes
    assert verdict.reason_codes == ("missing-absence-proof",)


def test_candidate_assessment_requires_independent_verification_context() -> None:
    """Mutation caught: self-asserted candidate evidence can produce release."""
    candidate = "a" * 40
    tree = "b" * 64
    selected = tuple(
        row
        for row in load_evidence_matrix()
        if isinstance(row, ApplicableEvidenceRow) and row.profile == "alpic-metadata"
    )
    rows = tuple(
        _applicable_with_verdict(
            row,
            "Pass",
            evidence_id=f"ev.{index:03d}",
            evidence_revision=candidate,
        )
        for index, row in enumerate(selected)
    )
    evidence = tuple(
        LocalEvidenceReference.model_validate(
            _local_evidence()
            | {
                "candidate_tree_sha256": tree,
                "claim_purpose": "implementation-proof",
                "evidence_id": f"ev.{index:03d}",
                "evidence_revision": candidate,
                "requirement_ids": (row.requirement_id,),
                "asserted_invariant": row.invariant,
            }
        )
        for index, row in enumerate(rows)
    )

    verdict = evaluate_profile_release(
        profile="alpic-metadata",
        candidate={"revision": candidate, "tree_sha256": tree},
        matrix=rows,
        evidence=evidence,
        assessment_mode="candidate",
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    )

    assert "independent-evidence-unverified" in verdict.reason_codes


@pytest.mark.parametrize(
    ("fault", "expected"),
    [
        ("missing-absence-proof", "missing-absence-proof"),
        ("wrong-candidate", "candidate-binding-mismatch"),
        ("wrong-profile", "profile-binding-mismatch"),
        ("expired", "expired-evidence"),
        ("duplicate", "duplicate-evidence-id"),
    ],
)
def test_candidate_assessment_rejects_governance_and_binding_faults(
    fault: str,
    expected: str,
) -> None:
    """Mutation caught: candidate mode omits N/A governance or binding checks."""
    candidate = "a" * 40
    tree = "b" * 64
    row = NotApplicableEvidenceRow.model_validate(
        _not_applicable_row()
        | {
            "evidence_revision": candidate,
            "absence_evidence_ids": ("absence.001",),
            "invariant": "The capability is absent from this profile.",
        }
    )
    custodied_reference = CustodiedEvidenceReference.model_validate(
        _custodied_evidence()
        | {
            "candidate_tree_sha256": tree,
            "claim_purpose": "absence-proof",
            "evidence_id": "absence.001",
            "evidence_revision": candidate,
            "kind": "design",
            "requirement_ids": (row.requirement_id,),
            "profiles": ("alpic-metadata",),
            "asserted_invariant": row.invariant,
        }
    )
    reference: LocalEvidenceReference | CustodiedEvidenceReference
    if fault == "missing-absence-proof":
        reference = LocalEvidenceReference.model_validate(
            _local_evidence()
            | {
                "candidate_tree_sha256": tree,
                "claim_purpose": "implementation-proof",
                "evidence_id": "absence.001",
                "evidence_revision": candidate,
                "requirement_ids": (row.requirement_id,),
                "asserted_invariant": row.invariant,
            }
        )
    elif fault == "wrong-candidate":
        reference = _updated_custodied_evidence(
            custodied_reference, {"evidence_revision": "c" * 40}
        )
    elif fault == "wrong-profile":
        reference = _updated_custodied_evidence(
            custodied_reference, {"profiles": ("private-full",)}
        )
    elif fault == "expired":
        reference = _updated_custodied_evidence(
            custodied_reference,
            {"expires_at": datetime(2026, 8, 22, tzinfo=UTC)},
        )
    else:
        reference = custodied_reference
    evidence = (reference, reference) if fault == "duplicate" else (reference,)

    verdict = evaluate_profile_release(
        profile="alpic-metadata",
        candidate={"revision": candidate, "tree_sha256": tree},
        matrix=(row,) * 253,
        evidence=evidence,
        assessment_mode="candidate",
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    )

    assert expected in verdict.reason_codes


def test_candidate_mode_preserves_bootstrap_rows_and_output() -> None:
    """Mutation caught: candidate selection converts the bootstrap inventory."""
    before = Path("docs/security/asvs-5.0.0-l2-matrix.jsonl").read_bytes()
    bootstrap_rows = load_evidence_matrix()
    bootstrap_manifest = load_evidence_manifest()
    bootstrap = evaluate_profile_release(
        "alpic-metadata",
        bootstrap_rows,
        bootstrap_manifest,
        policy=load_independent_evidence_policy(),
        context=_verification_context(),
    )

    assert len(bootstrap_rows) == MATRIX_RECORDS
    assert bootstrap_manifest == ()
    assert all(
        isinstance(row, ApplicableEvidenceRow) and row.verdict == "Not assessed"
        for row in bootstrap_rows
    )
    assert render_evidence_matrix(load_pinned_asvs_requirements()) == before
    assert bootstrap.reason_codes == ("not-assessed",)
    assert Path("docs/security/asvs-5.0.0-l2-matrix.jsonl").read_bytes() == before


@pytest.mark.parametrize(
    "fault",
    ["missing-row", "changed-row", "nonempty-evidence"],
)
def test_direct_bootstrap_evaluation_requires_the_exact_historical_product(
    fault: str,
) -> None:
    """Bootstrap accepts only 759 Not assessed rows and an empty manifest."""
    rows = load_evidence_matrix()
    evidence: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...] = ()
    if fault == "missing-row":
        rows = rows[:-1]
    elif fault == "changed-row":
        first = rows[0]
        assert isinstance(first, ApplicableEvidenceRow)
        rows = (
            _applicable_with_verdict(first, "Pass", evidence_id="bootstrap.invalid"),
            *rows[1:],
        )
    else:
        evidence = (LocalEvidenceReference.model_validate(_local_evidence()),)

    verdict = evaluate_profile_release(
        "alpic-metadata",
        rows,
        evidence,
        policy=load_independent_evidence_policy(),
        context=_verification_context(),
    )

    assert verdict.reason_codes == ("bootstrap-product-mismatch",)


def test_build_matrix_publishes_atomically_and_never_overwrites(tmp_path: Path) -> None:
    output = tmp_path / "matrix.jsonl"

    assert build_matrix(output) == output
    expected = render_evidence_matrix(load_pinned_asvs_requirements())
    assert output.read_bytes() == expected
    assert not tuple(tmp_path.glob(".asvs-matrix-*"))

    with pytest.raises(AsvsError, match="exclusive matrix publication failed"):
        _ = build_matrix(output)
    assert output.read_bytes() == expected
    assert not tuple(tmp_path.glob(".asvs-matrix-*"))


def test_build_matrix_rolls_back_a_post_link_sync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fsync = os.fsync
    calls = 0

    def fail_directory_sync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == SECOND_WRITE_CALL:
            msg = "injected directory sync failure"
            raise OSError(msg)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory_sync)
    output = tmp_path / "matrix.jsonl"

    with pytest.raises(AsvsError, match="exclusive matrix publication failed"):
        _ = build_matrix(output)

    assert output.exists() is False
    assert tuple(tmp_path.iterdir()) == ()


def test_exclusive_publisher_rejects_invalid_pairs_and_active_lock(
    tmp_path: Path,
) -> None:
    publisher = ExclusiveArtifactPublisher()
    first = tmp_path / "first"
    other = tmp_path / "other"
    other.mkdir()

    with pytest.raises(AsvsError, match="distinct names in one directory"):
        publisher.publish_pair((first, b"first"), (first, b"second"))
    with pytest.raises(AsvsError, match="distinct names in one directory"):
        publisher.publish_pair((first, b"first"), (other / "second", b"second"))

    lock = tmp_path / ".asvs-fetch.lock"
    _ = lock.write_bytes(b"active\n")
    with pytest.raises(AsvsError, match="exclusive artifact publication failed"):
        publisher.publish_pair((first, b"first"), (tmp_path / "second", b"second"))
    assert lock.read_bytes() == b"active\n"
    assert first.exists() is False


def test_descriptor_filesystem_rejects_unsafe_root_and_hardlinked_evidence(
    tmp_path: Path,
) -> None:
    filesystem = DescriptorEvidenceFileSystem()
    with pytest.raises(AsvsError, match="canonical and repository-relative"):
        _ = filesystem.read_bounded(tmp_path, "../escape", max_bytes=32)

    real_root = tmp_path / "real"
    real_root.mkdir()
    evidence = real_root / "evidence.json"
    _ = evidence.write_bytes(b"{}\n")
    hardlink = real_root / "evidence-link.json"
    hardlink.hardlink_to(evidence)
    with pytest.raises(AsvsError, match="regular single-link"):
        _ = filesystem.read_bounded(real_root, "evidence.json", max_bytes=32)

    root_link = tmp_path / "root-link"
    root_link.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(AsvsError, match="no-follow directory"):
        _ = filesystem.read_bounded(root_link, "evidence.json", max_bytes=32)


@pytest.mark.parametrize(
    "body",
    [
        b'{"storage":1.5}\n',
        b"[" * 34 + b"0" + b"]" * 34 + b"\n",
        b'"' + b"x" * 65_537 + b'"\n',
    ],
    ids=("float", "deep", "oversized-string"),
)
def test_manifest_loader_rejects_bounded_json_shape_attacks(
    tmp_path: Path,
    body: bytes,
) -> None:
    path = tmp_path / "manifest.jsonl"
    _ = path.write_bytes(body)

    with pytest.raises(AsvsError):
        _ = load_evidence_manifest(path)


def test_manifest_loader_rejects_an_escaped_lone_surrogate_as_bounded_error(
    tmp_path: Path,
) -> None:
    """Catch mutation: remove lone-surrogate rejection from shape validation."""
    payload = _local_evidence() | {"asserted_invariant": "\ud800"}
    serializable = {
        key: item.isoformat() if isinstance(item, date) else item
        for key, item in payload.items()
    }
    body = (
        json.dumps(
            serializable,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    path = tmp_path / "manifest.jsonl"
    _ = path.write_bytes(body)

    with pytest.raises(AsvsError) as captured:
        _ = load_evidence_manifest(path)
    assert str(captured.value) == "invalid UTF-8 JSON"


def test_manifest_loader_preserves_canonical_astral_unicode(tmp_path: Path) -> None:
    """Catch mutation: reject non-ASCII strings before UTF-8 byte accounting."""
    payload = _local_evidence() | {"asserted_invariant": "Astral Unicode: \U0001f600"}
    path = tmp_path / "manifest.jsonl"
    _ = path.write_bytes(_canonical_json_line(payload))

    references = load_evidence_manifest(path)

    assert references[0].asserted_invariant == "Astral Unicode: \U0001f600"


def test_manifest_loader_rejects_invalid_schema_line_and_record_bounds(
    tmp_path: Path,
) -> None:
    invalid_schema = tmp_path / "invalid-schema.jsonl"
    _ = invalid_schema.write_bytes(b"{}\n")
    with pytest.raises(AsvsError, match="strict schema"):
        _ = load_evidence_manifest(invalid_schema)

    oversized_line = tmp_path / "oversized-line.jsonl"
    _ = oversized_line.write_bytes(b'"' + b"x" * 65_537 + b'"\n')
    with pytest.raises(AsvsError, match="record exceeds"):
        _ = load_evidence_manifest(oversized_line)

    excess_records = tmp_path / "excess-records.jsonl"
    _ = excess_records.write_bytes(b"{}\n" * 4_097)
    with pytest.raises(AsvsError, match="record count exceeds"):
        _ = load_evidence_manifest(excess_records)


def test_matrix_loader_rejects_empty_or_oversized_products(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    _ = empty.write_bytes(b"")
    with pytest.raises(AsvsError, match="record count"):
        _ = load_evidence_matrix(empty)

    oversized = tmp_path / "oversized.jsonl"
    _ = oversized.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(AsvsError, match="byte bound"):
        _ = load_evidence_matrix(oversized)


def test_policy_loader_rejects_noncanonical_schema_and_provenance(
    tmp_path: Path,
) -> None:
    valid_body = render_evidence_policy(load_pinned_asvs_requirements())
    malformed = (
        b"",
        valid_body.replace(b'"schema_version":"2.0"', b'"schema_version": "2.0"'),
        b"{}\n",
    )
    for offset, body in enumerate(malformed):
        path = tmp_path / f"policy-{offset}.json"
        _ = path.write_bytes(body)
        with pytest.raises(AsvsError):
            _ = load_independent_evidence_policy(path)

    payload = cast("dict[str, object]", json.loads(valid_body))
    payload["evidence_revision"] = "0" * 40
    drift = tmp_path / "policy-drift.json"
    _ = drift.write_bytes(_canonical_json_line(payload))
    with pytest.raises(AsvsError, match="provenance"):
        _ = load_independent_evidence_policy(drift)


@pytest.mark.parametrize(
    "url",
    [
        "http://raw.githubusercontent.com/OWASP/ASVS/source.json",
        "https://user@raw.githubusercontent.com/OWASP/ASVS/source.json",
        "https://raw.githubusercontent.com/OWASP/ASVS/source.json?mutable=1",
    ],
)
def test_https_downloader_rejects_any_nonexact_source_url(url: str) -> None:
    with pytest.raises(AsvsError, match="exact credential-free"):
        _ = HttpsDownloader().download(url, max_bytes=1)


@pytest.mark.parametrize(
    ("status", "headers", "message"),
    [
        (206, {"Content-Length": "1"}, "unexpected HTTP representation"),
        (
            200,
            {"Content-Length": "1", "Content-Encoding": "gzip"},
            "unexpected HTTP representation",
        ),
        (200, {}, "bounded size"),
        (200, {"Content-Length": "not-a-number"}, "bounded size"),
    ],
)
def test_https_downloader_rejects_response_metadata_before_reading(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    headers: dict[str, str],
    message: str,
) -> None:
    exact_url = (
        "https://raw.githubusercontent.com/OWASP/ASVS/"
        f"{ASVS_COMMIT}/5.0/docs_en/"
        "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
    )

    class Response:
        def __init__(self) -> None:
            super().__init__()
            self.status = status
            self.headers = headers

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def read(self, amount: int) -> bytes:
            del amount
            pytest.fail("invalid response metadata must prevent body reads")

        def geturl(self) -> str:
            return exact_url

    class Opener:
        def __init__(self) -> None:
            super().__init__()
            self.addheaders: list[tuple[str, str]] = []

        def open(self, url: str, *, timeout: int) -> Response:
            del url, timeout
            return Response()

    def build_opener(*handlers: object) -> Opener:
        del handlers
        return Opener()

    monkeypatch.setattr("urllib.request.build_opener", build_opener)
    with pytest.raises(AsvsError, match=message):
        _ = HttpsDownloader().download(exact_url, max_bytes=1)


@pytest.mark.parametrize(
    "command_request",
    [
        GitCommandRequest((), 1, 32, 32, (), Path("/")),
        GitCommandRequest(("git", "--version"), 1, 32, 32, (), Path("/")),
        GitCommandRequest(("/usr/bin/git", "--version"), 1, 32, 32, (), Path("/dev")),
        GitCommandRequest(("/usr/bin/git", "--version"), 0, 32, 32, (), Path("/")),
        GitCommandRequest(("/usr/bin/git", "--version"), 1, 0, 32, (), Path("/")),
        GitCommandRequest(
            ("/usr/bin/git", "--version"),
            1,
            32,
            32,
            (("LANG", "C"), ("LANG", "C")),
            Path("/"),
        ),
    ],
    ids=(
        "empty-argv",
        "relative-git",
        "unreviewed-cwd",
        "timeout",
        "stdout",
        "duplicate-env",
    ),
)
def test_bounded_git_runner_rejects_unreviewed_execution_inputs(
    command_request: GitCommandRequest,
) -> None:
    with pytest.raises(AsvsError):
        _ = BoundedGitRunner().run(command_request)


def test_bounded_git_runner_sanitizes_process_spawn_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_spawn(*args: object, **kwargs: object) -> None:
        del args, kwargs
        msg = "TASK2_SPAWN_SECRET"
        raise OSError(msg)

    monkeypatch.setattr(subprocess, "Popen", reject_spawn)
    request = GitCommandRequest(
        argv=("/usr/bin/git", "--version"),
        timeout_seconds=1,
        max_stdout_bytes=32,
        max_stderr_bytes=32,
        env=(("LANG", "C"),),
        cwd=Path("/"),
    )

    with pytest.raises(AsvsError) as captured:
        _ = BoundedGitRunner().run(request)
    assert "TASK2_SPAWN_SECRET" not in str(captured.value)


def test_verify_ref_fails_closed_when_the_runner_or_executable_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingRunner:
        def run(self, request: GitCommandRequest) -> GitCommandResult:
            del request
            msg = "injected runner failure"
            raise AsvsError(msg)

    assert verify_ref(FailingRunner()) is False
    monkeypatch.setattr(asvs_matrix, "GIT_EXECUTABLE", tmp_path / "missing-git")
    assert verify_ref(FailingRunner()) is False


def test_main_dispatches_only_bounded_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, Path | None]] = []

    def fake_check(root: Path | None = None) -> bool:
        calls.append(("check", root))
        return True

    def fake_fetch(output: Path, **options: object) -> Path:
        del options
        calls.append(("fetch", output))
        return output

    def fake_verify_ref(runner: object | None = None) -> bool:
        del runner
        calls.append(("verify-ref", None))
        return True

    def fake_build_matrix(
        output: Path | None = None,
        *,
        requirements_path: Path | None = None,
    ) -> Path:
        calls.append(("matrix", requirements_path))
        return output or tmp_path / "default.jsonl"

    monkeypatch.setattr(asvs_matrix, "check_repository", fake_check)
    monkeypatch.setattr(asvs_matrix, "fetch_asvs", fake_fetch)
    monkeypatch.setattr(asvs_matrix, "verify_ref", fake_verify_ref)
    monkeypatch.setattr(asvs_matrix, "build_matrix", fake_build_matrix)
    output = tmp_path / "requirements.json"
    matrix = tmp_path / "matrix.jsonl"
    requirements = tmp_path / "requirements-source.json"

    assert main([]) == INVALID_CLI_USAGE
    assert main(["--check", "verify-ref"]) == INVALID_CLI_USAGE
    assert main(["--check"]) == 0
    assert main(["fetch", "--output", os.fspath(output)]) == 0
    assert main(["verify-ref"]) == 0
    assert (
        main(
            [
                "matrix",
                "--output",
                os.fspath(matrix),
                "--requirements",
                os.fspath(requirements),
            ]
        )
        == 0
    )
    assert calls == [
        ("check", None),
        ("fetch", output),
        ("verify-ref", None),
        ("matrix", requirements),
    ]


def _revalidate_threat_ledger(
    ledger: ThreatLedger,
    **changes: object,
) -> ThreatLedger:
    candidate = ledger.model_copy(update=changes)
    return ThreatLedger.model_validate_json(candidate.model_dump_json())


def test_threat_record_rejects_duplicate_internal_mappings() -> None:
    threat = load_threat_ledger().threats[0]

    with pytest.raises(ValidationError, match="threat mappings must be unique"):
        _ = _threat_with_mappings(
            threat,
            _ThreatMappingChanges(flow_ids=(threat.flow_ids[0], threat.flow_ids[0])),
        )


def test_threat_ledger_rejects_duplicate_and_noncanonical_identifiers() -> None:
    ledger = load_threat_ledger()

    with pytest.raises(ValidationError, match="identifiers must be unique"):
        _ = _revalidate_threat_ledger(
            ledger,
            assets=(ledger.assets[0], *ledger.assets),
        )
    with pytest.raises(ValidationError, match="canonical identifier order"):
        _ = _revalidate_threat_ledger(
            ledger,
            assets=tuple(reversed(ledger.assets)),
        )


def test_threat_ledger_requires_every_reviewed_boundary_and_flow_pair() -> None:
    ledger = load_threat_ledger()
    without_build_boundary = tuple(
        flow for flow in ledger.flows if flow.boundary_id != "build-to-deploy"
    )
    with pytest.raises(ValidationError, match="required trust boundary"):
        _ = _revalidate_threat_ledger(ledger, flows=without_build_boundary)

    ci_flow = next(flow for flow in ledger.flows if flow.flow_id == "flow-ci-edge")
    relabelled = ThreatFlow(
        flow_id=ci_flow.flow_id,
        source="external-client",
        target=ci_flow.target,
        boundary_id=ci_flow.boundary_id,
        protocol=ci_flow.protocol,
        data_classes=ci_flow.data_classes,
    )
    flows = tuple(relabelled if flow == ci_flow else flow for flow in ledger.flows)
    with pytest.raises(ValidationError, match="required data-flow edge"):
        _ = _revalidate_threat_ledger(ledger, flows=flows)


def test_threat_ledger_rejects_unknown_nodes_and_undeclared_data_classes() -> None:
    ledger = load_threat_ledger()
    unknown_flow = ThreatFlow(
        flow_id="flow-z-unknown-node",
        source="unknown-node",
        target="audit-log-store",
        boundary_id="logging-privacy",
        protocol="Injected invalid flow",
        data_classes=("audit-events",),
    )
    with pytest.raises(ValidationError, match="unknown node"):
        _ = _revalidate_threat_ledger(
            ledger,
            flows=(*ledger.flows, unknown_flow),
        )

    node = ledger.nodes[0]
    mutated_node = ThreatNode(
        node_id=node.node_id,
        node_kind=node.node_kind,
        trust_zone=node.trust_zone,
        privileges=node.privileges,
        data_classes=(*node.data_classes, "undeclared-class"),
    )
    nodes = tuple(
        mutated_node if candidate == node else candidate for candidate in ledger.nodes
    )
    with pytest.raises(ValidationError, match="undeclared data class"):
        _ = _revalidate_threat_ledger(ledger, nodes=nodes)


def test_threat_ledger_requires_exact_flow_entry_coverage() -> None:
    ledger = load_threat_ledger()

    with pytest.raises(ValidationError, match="cover every flow exactly once"):
        _ = _revalidate_threat_ledger(
            ledger,
            entry_points=ledger.entry_points[:-1],
        )


def test_threat_ledger_requires_every_abuse_category() -> None:
    ledger = load_threat_ledger()
    logging_threat = next(
        threat
        for threat in ledger.threats
        if threat.abuse_categories == ("logging-privacy",)
    )
    replacement = _threat_with_mappings(
        logging_threat,
        _ThreatMappingChanges(abuse_categories=("token-session",)),
    )
    threats = tuple(
        replacement if threat == logging_threat else threat for threat in ledger.threats
    )

    with pytest.raises(ValidationError, match="required abuse category"):
        _ = _revalidate_threat_ledger(ledger, threats=threats)


def test_threat_ledger_requires_known_reciprocal_residual_risks() -> None:
    ledger = load_threat_ledger()
    first = ledger.residual_risks[0]
    unknown = ResidualRiskRecord(
        residual_risk_id=first.residual_risk_id,
        threat_ids=("threat-unknown",),
        description=first.description,
        disposition=first.disposition,
        owner=first.owner,
        review_due=first.review_due,
    )
    with pytest.raises(ValidationError, match="unknown threat"):
        _ = _revalidate_threat_ledger(
            ledger,
            residual_risks=(unknown, *ledger.residual_risks[1:]),
        )

    nonreciprocal = ResidualRiskRecord(
        residual_risk_id=first.residual_risk_id,
        threat_ids=ledger.residual_risks[1].threat_ids,
        description=first.description,
        disposition=first.disposition,
        owner=first.owner,
        review_due=first.review_due,
    )
    with pytest.raises(ValidationError, match="not reciprocal"):
        _ = _revalidate_threat_ledger(
            ledger,
            residual_risks=(nonreciprocal, *ledger.residual_risks[1:]),
        )


def test_threat_ledger_requires_complete_reviewed_inventory_sets() -> None:
    ledger = load_threat_ledger()
    with pytest.raises(ValidationError, match="invalidation triggers are incomplete"):
        _ = _revalidate_threat_ledger(
            ledger,
            global_invalidation_triggers=ledger.global_invalidation_triggers[:-1],
        )
    with pytest.raises(ValidationError, match="actor inventory is incomplete"):
        _ = _revalidate_threat_ledger(ledger, actors=ledger.actors[:-1])

    threats_without_distributed = tuple(
        _threat_with_mappings(
            threat,
            _ThreatMappingChanges(affected_profiles=("alpic-metadata", "private-full")),
        )
        for threat in ledger.threats
    )
    with pytest.raises(ValidationError, match="every deployment profile"):
        _ = _revalidate_threat_ledger(
            ledger,
            threats=threats_without_distributed,
        )


def test_threat_ledger_rejects_unbound_provider_and_renamed_entry_point() -> None:
    ledger = load_threat_ledger()
    extra_provider = ProviderAssumption(
        assumption_id="zz-unbound-provider-contract",
        provider="unreviewed-provider",
        control="An injected assumption has no bound threat.",
        owner="security-owner",
        status="assumption-unverified",
        invalidation_trigger="provider-contract-change",
    )
    with pytest.raises(ValidationError, match="all be bound to a threat"):
        _ = _revalidate_threat_ledger(
            ledger,
            provider_assumptions=(*ledger.provider_assumptions, extra_provider),
        )

    last = ledger.entry_points[-1]
    renamed = ThreatEntryPoint(
        entry_point_id="entry-z-renamed-public-mcp",
        flow_id=last.flow_id,
        exposed_node_id=last.exposed_node_id,
        access_control=last.access_control,
        affected_profiles=last.affected_profiles,
        data_classes=last.data_classes,
    )
    with pytest.raises(ValidationError, match="entry-point inventory is incomplete"):
        _ = _revalidate_threat_ledger(
            ledger,
            entry_points=(*ledger.entry_points[:-1], renamed),
        )


def test_release_approval_rejects_non_risk_and_unconfigured_authority() -> None:
    local_reference = LocalEvidenceReference.model_validate(_local_evidence())
    assert (
        verify_release_approval(
            ApplicableEvidenceRow.model_validate(_applicable_row()),
            local_reference,
            policy=_evidence_policy(),
            context=_verification_context(),
        )
        is False
    )

    row = ApplicableEvidenceRow.model_validate(
        _applicable_row()
        | {
            "compensating_controls": ("control.fixture",),
            "invariant": "The exact requirement/profile claim was tested.",
            "release_approval_evidence_id": "ev.fixture",
            "residual_risk": "Residual risk remains explicitly bounded.",
            "risk_approver": "approver-subject",
            "risk_expiry": date(2026, 12, 31),
            "risk_id": "risk.fixture",
            "risk_owner": "risk-owner",
            "verdict": "Risk accepted",
        }
    )
    custodied = CustodiedEvidenceReference.model_validate(
        _custodied_evidence() | {"kind": "operational"}
    )
    assert (
        verify_release_approval(
            row,
            custodied,
            policy=_evidence_policy(),
            context=replace(_verification_context(), risk_id="risk.fixture"),
        )
        is False
    )


def test_custodied_evidence_rejects_authority_failure_and_missing_receipt() -> None:
    reference = CustodiedEvidenceReference.model_validate(_custodied_evidence())

    class FailingAuthority:
        authority_id = "ci.example"

        def verify_receipt(
            self,
            candidate: CustodiedEvidenceReference,
        ) -> CustodyReceipt | None:
            del candidate
            msg = "injected custody failure"
            raise AsvsError(msg)

    class MissingAuthority:
        authority_id = "ci.example"

        def verify_receipt(
            self,
            candidate: CustodiedEvidenceReference,
        ) -> CustodyReceipt | None:
            del candidate
            return None

    class ReplayRegistry:
        def accept(self, *, nonce: str, subject_sha256: str) -> bool:
            del nonce, subject_sha256
            pytest.fail("an absent or failed receipt must not reach replay admission")

    context = replace(_verification_context(), replay_registry=ReplayRegistry())
    for authority in (FailingAuthority(), MissingAuthority()):
        assert (
            verify_evidence_reference(
                reference,
                context=replace(context, authorities=(authority,)),
            )
            is False
        )


def test_local_evidence_rejects_candidate_faults_and_unverified_context(
    tmp_path: Path,
) -> None:
    body = b"bounded evidence\n"
    reference = LocalEvidenceReference.model_validate(
        _local_evidence()
        | {
            "artifact_path": "evidence.bin",
            "sha256": hashlib.sha256(body).hexdigest(),
            "verifier": "sha256-file-v1",
        }
    )
    candidate = _verified_candidate(tmp_path, reference)
    context = replace(
        _verification_context(),
        root=tmp_path,
        verified_candidate=candidate,
    )

    class FailingVerifier:
        def snapshot(self, root: Path) -> VerifiedCandidateSnapshot:
            del root
            msg = "injected candidate failure"
            raise AsvsError(msg)

    assert (
        verify_evidence_reference(reference, context=_verification_context()) is False
    )
    assert (
        verify_evidence_reference(
            reference,
            context=context,
            candidate_verifier=FailingVerifier(),
        )
        is False
    )

    mismatched = VerifiedCandidateSnapshot(
        root_device=candidate.root_device,
        root_inode=candidate.root_inode,
        evidence_revision="0" * 40,
        candidate_tree_sha256=candidate.candidate_tree_sha256,
        clean=True,
        selector_bindings=candidate.selector_bindings,
    )
    assert (
        verify_evidence_reference(
            reference,
            context=replace(context, verified_candidate=mismatched),
            candidate_verifier=_StaticCandidateVerifier(mismatched),
        )
        is False
    )


@pytest.mark.parametrize(
    ("verifier", "body"),
    [
        ("sha256-file-v1", b"wrong digest\n"),
        ("test-report-v1", b"opaque report\n"),
        ("json-record-v1", b"{\n"),
        ("json-record-v1", b"[]\n"),
        ("json-record-v1", b'{"ok": true}\n'),
    ],
    ids=(
        "digest",
        "unsupported-verifier",
        "invalid-json",
        "non-object",
        "noncanonical-json",
    ),
)
def test_local_evidence_body_verification_fails_closed(
    tmp_path: Path,
    verifier: str,
    body: bytes,
) -> None:
    expected_body = b"different body\n" if verifier == "sha256-file-v1" else body
    reference = LocalEvidenceReference.model_validate(
        _local_evidence()
        | {
            "artifact_path": "evidence.bin",
            "sha256": hashlib.sha256(expected_body).hexdigest(),
            "verifier": verifier,
        }
    )
    candidate = _verified_candidate(tmp_path, reference)
    snapshot = EvidenceFileSnapshot(
        body=body,
        complete=True,
        confined=True,
        stable=True,
        regular=True,
        single_link=True,
        device=1,
        inode=2,
        size=len(body),
        mtime_ns=3,
        ctime_ns=4,
        root_device=candidate.root_device,
        root_inode=candidate.root_inode,
    )

    class StaticFileSystem:
        def read_bounded(
            self,
            root: Path,
            relative_path: str,
            *,
            max_bytes: int,
        ) -> EvidenceFileSnapshot:
            del root, relative_path, max_bytes
            return snapshot

    assert (
        verify_evidence_reference(
            reference,
            context=replace(
                _verification_context(),
                root=tmp_path,
                verified_candidate=candidate,
            ),
            filesystem=StaticFileSystem(),
            candidate_verifier=_StaticCandidateVerifier(candidate),
        )
        is False
    )


@pytest.mark.parametrize(
    "body",
    [
        b'{"value":9007199254740992}\n',
        b"{\n",
    ],
    ids=("interoperability-integer", "invalid-json"),
)
def test_manifest_loader_rejects_numeric_and_syntax_attacks(
    tmp_path: Path,
    body: bytes,
) -> None:
    path = tmp_path / "manifest.jsonl"
    _ = path.write_bytes(body)
    with pytest.raises(AsvsError):
        _ = load_evidence_manifest(path)


def test_policy_loader_enforces_json_member_and_string_bounds(tmp_path: Path) -> None:
    too_many_members = tmp_path / "too-many-members.json"
    _ = too_many_members.write_bytes(b"[" + b"null," * 100_000 + b"null]\n")
    with pytest.raises(AsvsError, match="member bound"):
        _ = load_independent_evidence_policy(too_many_members)

    oversized_string = tmp_path / "oversized-string.json"
    _ = oversized_string.write_bytes(b'"' + b"x" * 65_537 + b'"\n')
    with pytest.raises(AsvsError, match="string exceeds"):
        _ = load_independent_evidence_policy(oversized_string)


def test_matrix_loader_rejects_wrong_exact_count_and_inconsistent_group(
    tmp_path: Path,
) -> None:
    one_row = tmp_path / "one-row.jsonl"
    _ = one_row.write_bytes(_canonical_json_line(_applicable_row()))
    with pytest.raises(AsvsError, match="record count"):
        _ = load_evidence_matrix(one_row)

    lines = (
        Path("docs/security/asvs-5.0.0-l2-matrix.jsonl")
        .read_bytes()
        .splitlines(keepends=True)
    )
    second = cast("dict[str, object]", json.loads(lines[1]))
    second["requirement_text"] = "A conflicting description for the same claim."
    lines[1] = _canonical_json_line(second)
    inconsistent = tmp_path / "inconsistent.jsonl"
    _ = inconsistent.write_bytes(b"".join(lines))
    with pytest.raises(AsvsError, match="one consistent row"):
        _ = load_evidence_matrix(inconsistent)


def test_pinned_asvs_loader_rejects_unreviewed_bytes_and_invalid_path(
    tmp_path: Path,
) -> None:
    source = Path("security/asvs/requirements-5.0.0.json").read_bytes()
    altered = tmp_path / "requirements.json"
    _ = altered.write_bytes(source[:-1] + bytes((source[-1] ^ 1,)))
    with pytest.raises(AsvsError, match="immutable source"):
        _ = load_pinned_asvs_requirements(altered)
    with pytest.raises(AsvsError, match="artifact path is invalid"):
        _ = load_pinned_asvs_requirements(Path("/"))


def test_descriptor_filesystem_reads_nested_evidence_beneath_one_root(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "evidence" / "nested"
    nested.mkdir(parents=True)
    body = b"nested evidence\n"
    _ = (nested / "report.bin").write_bytes(body)

    snapshot = DescriptorEvidenceFileSystem().read_bounded(
        tmp_path,
        "evidence/nested/report.bin",
        max_bytes=len(body),
    )

    assert snapshot.body == body
    assert snapshot.root_inode == tmp_path.stat().st_ino


def test_atomic_publishers_reject_invalid_target_and_temporary_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(AsvsError, match="matrix output name is not canonical"):
        _ = build_matrix(Path("/"))

    real_fstat = os.fstat
    calls = 0

    def corrupt_first_temporary_final_identity(descriptor: int) -> os.stat_result:
        nonlocal calls
        identity = real_fstat(descriptor)
        calls += 1
        if calls == FIRST_TEMPORARY_FINAL_STAT_CALL:
            values = list(identity)
            values[3] = 2
            return os.stat_result(values)
        return identity

    monkeypatch.setattr(os, "fstat", corrupt_first_temporary_final_identity)
    first = tmp_path / "first"
    second = tmp_path / "second"
    with pytest.raises(AsvsError, match="exclusive artifact publication failed"):
        ExclusiveArtifactPublisher().publish_pair(
            (first, b"first\n"),
            (second, b"second\n"),
        )
    assert tuple(tmp_path.iterdir()) == ()


def test_exclusive_publisher_rolls_back_inode_replacement_before_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_stat = os.stat
    injected = False

    def replace_first_cleanup_identity(
        path: str | bytes | int | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal injected
        identity = real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        if isinstance(path, str) and path.startswith(".asvs-fetch-") and not injected:
            injected = True
            values = list(identity)
            values[1] += 1
            return os.stat_result(values)
        return identity

    monkeypatch.setattr(os, "stat", replace_first_cleanup_identity)
    with pytest.raises(AsvsError, match="exclusive artifact publication failed"):
        ExclusiveArtifactPublisher().publish_pair(
            (tmp_path / "first", b"first\n"),
            (tmp_path / "second", b"second\n"),
        )
    assert tuple(tmp_path.iterdir()) == ()


def test_bounded_git_runner_fails_closed_on_missing_reviewed_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing-git"
    monkeypatch.setattr(asvs_matrix, "GIT_EXECUTABLE", missing)
    request = GitCommandRequest(
        argv=(os.fspath(missing), "--version"),
        timeout_seconds=1,
        max_stdout_bytes=32,
        max_stderr_bytes=32,
        env=(("LANG", "C"),),
        cwd=Path("/"),
    )
    with pytest.raises(AsvsError, match="identity cannot be verified"):
        _ = BoundedGitRunner().run(request)


def test_verify_ref_rejects_a_symlinked_git_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symlink = tmp_path / "git"
    symlink.symlink_to("/usr/bin/git")
    monkeypatch.setattr(asvs_matrix, "GIT_EXECUTABLE", symlink)

    class UnexpectedRunner:
        def run(self, request: GitCommandRequest) -> GitCommandResult:
            del request
            pytest.fail("a symlinked Git executable must be rejected before execution")

    assert verify_ref(UnexpectedRunner()) is False


def test_render_matrix_requires_the_exact_reviewed_requirement_product() -> None:
    with pytest.raises(AsvsError, match="exactly 253 unique"):
        _ = render_evidence_matrix(())


def test_repository_inventory_rejects_hardlinks_and_unexpected_entries(
    tmp_path: Path,
) -> None:
    hardlink_root = tmp_path / "hardlink"
    source_dir = hardlink_root / "security/asvs"
    source_dir.mkdir(parents=True)
    _ = (source_dir / "SHA256SUMS").write_bytes(
        Path("security/asvs/SHA256SUMS").read_bytes()
    )
    original = hardlink_root / "original-requirements.json"
    _ = original.write_bytes(Path("security/asvs/requirements-5.0.0.json").read_bytes())
    (source_dir / "requirements-5.0.0.json").hardlink_to(original)
    assert check_repository(hardlink_root) is False

    extra_root = tmp_path / "extra"
    extra_source = extra_root / "security/asvs"
    extra_source.mkdir(parents=True)
    for name in ("SHA256SUMS", "requirements-5.0.0.json", "unexpected"):
        _ = (extra_source / name).write_bytes(b"fixture\n")
    assert check_repository(extra_root) is False


def test_regular_file_loader_rejects_an_identity_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "manifest.jsonl"
    _ = path.write_bytes(_canonical_json_line(_local_evidence()))
    real_fstat = os.fstat
    calls = 0

    def replace_after_read_identity(descriptor: int) -> os.stat_result:
        nonlocal calls
        identity = real_fstat(descriptor)
        calls += 1
        if calls == SECOND_WRITE_CALL:
            values = list(identity)
            values[1] += 1
            return os.stat_result(values)
        return identity

    monkeypatch.setattr(os, "fstat", replace_after_read_identity)
    with pytest.raises(AsvsError, match="identity changed while it was read"):
        _ = load_evidence_manifest(path)


def test_descriptor_filesystem_rejects_a_root_identity_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"bounded evidence\n"
    _ = (tmp_path / "evidence.bin").write_bytes(body)
    real_fstat = os.fstat
    calls = 0

    def replace_root_after_read_identity(descriptor: int) -> os.stat_result:
        nonlocal calls
        identity = real_fstat(descriptor)
        calls += 1
        if calls == DIRECTORY_FSYNC_CALL:
            values = list(identity)
            values[1] += 1
            return os.stat_result(values)
        return identity

    monkeypatch.setattr(os, "fstat", replace_root_after_read_identity)
    with pytest.raises(AsvsError, match="reviewed-root identity changed"):
        _ = DescriptorEvidenceFileSystem().read_bounded(
            tmp_path,
            "evidence.bin",
            max_bytes=len(body),
        )


def test_repository_inventory_rejects_inspection_races_and_io_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    race_root = tmp_path / "race"
    race_source = race_root / "security/asvs"
    race_source.mkdir(parents=True)
    for name in ("SHA256SUMS", "requirements-5.0.0.json"):
        _ = (race_source / name).write_bytes(b"fixture\n")

    real_fstat = os.fstat
    fstat_calls = 0

    def replace_directory_after_identity(descriptor: int) -> os.stat_result:
        nonlocal fstat_calls
        identity = real_fstat(descriptor)
        fstat_calls += 1
        if fstat_calls == SECOND_WRITE_CALL:
            values = list(identity)
            values[1] += 1
            return os.stat_result(values)
        return identity

    monkeypatch.setattr(os, "fstat", replace_directory_after_identity)
    assert check_repository(race_root) is False

    monkeypatch.setattr(os, "fstat", real_fstat)
    failure_root = tmp_path / "failure"
    failure_source = failure_root / "security/asvs"
    failure_source.mkdir(parents=True)
    for name in ("SHA256SUMS", "requirements-5.0.0.json"):
        _ = (failure_source / name).write_bytes(b"fixture\n")
    real_stat = os.stat
    injected = False

    def fail_first_entry_stat(
        path: str | bytes | int | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal injected
        if dir_fd is not None and not injected:
            injected = True
            msg = "injected inventory stat failure"
            raise OSError(msg)
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", fail_first_entry_stat)
    assert check_repository(failure_root) is False


def test_internal_closed_inventory_and_shape_guards() -> None:
    with pytest.raises(AsvsError, match="closed inventory"):
        _ = asvs_matrix._profile_rank("unknown")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(AsvsError, match="unsupported value"):
        _ = asvs_matrix._validate_json_shape(object())  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    assert asvs_matrix._safe_local_path("") is False  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    target = bytearray(b"full")
    assert asvs_matrix._append_bounded_stream(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        target,
        b"overflow",
        len(target),
    )
    assert target == b"full"


def test_threat_ledger_semantic_digest_is_independently_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = load_threat_ledger()
    monkeypatch.setattr(asvs_matrix, "REVIEWED_THREAT_LEDGER_SHA256", "0" * 64)

    with pytest.raises(ValueError, match="security semantics"):
        asvs_matrix._validate_threat_ledger_inventory(ledger)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("fault", ["provenance", "mapping"])
def test_threat_ledger_loader_rejects_post_schema_trust_faults(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    ledger = load_threat_ledger()
    candidate: ThreatLedger = ledger.model_copy()
    expected = "provenance or release status"
    if fault == "provenance":
        object.__setattr__(candidate, "evidence_revision", "f" * 40)
    else:
        threat: ThreatRecord = ledger.threats[0].model_copy()
        object.__setattr__(
            threat,
            "asvs_requirement_ids",
            ("v5.0.0-V99.9.9",),
        )
        remaining_threats: tuple[ThreatRecord, ...] = tuple(ledger.threats[1:])
        replacement_threats: tuple[ThreatRecord, ...] = (
            threat,
            *remaining_threats,
        )
        object.__setattr__(candidate, "threats", replacement_threats)
        expected = "unknown ASVS mapping"

    def load_candidate(*_args: object, **_kwargs: object) -> ThreatLedger:
        return candidate

    monkeypatch.setattr(asvs_matrix, "_load_canonical_json", load_candidate)
    with pytest.raises(AsvsError, match=expected):
        _ = load_threat_ledger()


def test_threat_markdown_rejects_rendered_size_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = load_threat_ledger()
    monkeypatch.setattr(asvs_matrix, "THREAT_MARKDOWN_MAX_BYTES", 1)

    with pytest.raises(AsvsError, match="configured byte bound"):
        _ = render_threat_model_markdown(ledger)


def test_descriptor_helpers_cover_zero_remaining_and_pre_dup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    _ = artifact.write_bytes(b"x")
    descriptor = os.open(artifact, os.O_RDONLY)
    try:
        body, _before, _after = asvs_matrix._read_bounded_descriptor(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            descriptor,
            max_bytes=1,
        )
    finally:
        os.close(descriptor)
    assert body == b"x"

    early_eof_fd = os.open(artifact, os.O_RDONLY)

    def early_eof(_descriptor: int, _amount: int) -> bytes:
        return b""

    monkeypatch.setattr(os, "read", early_eof)
    try:
        empty_body, _before, _after = asvs_matrix._read_bounded_descriptor(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            early_eof_fd,
            max_bytes=1,
        )
    finally:
        os.close(early_eof_fd)
    assert empty_body == b""

    root_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)

    def open_root(_path: Path) -> int:
        return os.dup(root_descriptor)

    def reject_fstat(_descriptor: int) -> os.stat_result:
        msg = "injected root identity failure"
        raise OSError(msg)

    monkeypatch.setattr(asvs_matrix, "_open_directory_no_follow", open_root)
    monkeypatch.setattr(os, "fstat", reject_fstat)
    try:
        with pytest.raises(AsvsError, match="opened beneath"):
            _ = asvs_matrix._snapshot_bounded_beneath_root(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                tmp_path,
                PurePosixPath("artifact.bin"),
                max_bytes=1,
            )
    finally:
        os.close(root_descriptor)


def test_publication_cleanup_rejects_absent_lock_and_preserves_other_inode(
    tmp_path: Path,
) -> None:
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        artifact = tmp_path / "artifact"
        _ = artifact.write_bytes(b"fixture")
        identity = artifact.stat()
        asvs_matrix._unlink_if_same_inode(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            directory_fd,
            artifact.name,
            identity.st_dev,
            identity.st_ino + 1,
        )
        assert artifact.read_bytes() == b"fixture"

        with pytest.raises(AsvsError, match="identity was not captured"):
            asvs_matrix._remove_publication_lock(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                directory_fd,
                asvs_matrix._AbsentPublicationLock(),  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                ".lock",
            )
    finally:
        os.close(directory_fd)


def test_atomic_publication_closes_directory_after_pre_identity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)

    def open_directory(_path: Path) -> int:
        return os.dup(base_fd)

    def reject_artifact_open(*_args: object, **_kwargs: object) -> int:
        msg = "injected artifact open failure"
        raise OSError(msg)

    monkeypatch.setattr(asvs_matrix, "_open_directory_no_follow", open_directory)
    monkeypatch.setattr(os, "open", reject_artifact_open)
    try:
        with pytest.raises(AsvsError, match="publication failed"):
            asvs_matrix._atomic_write(tmp_path / "matrix.jsonl", b"fixture\n")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(base_fd)


@pytest.mark.parametrize("payload", [[], {"Version": "4.0.0"}])
def test_fetch_rejects_post_digest_json_shape_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    body = Path("security/asvs/requirements-5.0.0.json").read_bytes()
    result = HttpDownloadResult(
        requested_url=asvs_matrix.ASVS_URL,
        final_url=asvs_matrix.ASVS_URL,
        status=200,
        headers=(("content-length", str(len(body))),),
        body=body,
        redirect_count=0,
        complete=True,
    )

    class Downloader:
        def download(self, url: str, *, max_bytes: int) -> HttpDownloadResult:
            assert url == asvs_matrix.ASVS_URL
            assert max_bytes == len(body)
            return result

    class Publisher:
        def publish_pair(
            self,
            first: tuple[Path, bytes],
            second: tuple[Path, bytes],
        ) -> None:
            del first, second
            pytest.fail("invalid ASVS JSON must not be published")

    def parse_payload(_body: bytes) -> object:
        return payload

    monkeypatch.setattr(asvs_matrix, "_parse_json_bytes", parse_payload)
    with pytest.raises(AsvsError, match=r"version is not 5\.0\.0"):
        _ = fetch_asvs(
            tmp_path / "requirements.json",
            downloader=Downloader(),
            publisher=Publisher(),
        )


@pytest.mark.parametrize(
    "items",
    [None, [1], [{"Description": "invalid", "L": "9", "Shortcode": "V1"}]],
)
def test_asvs_item_walk_rejects_malformed_recursive_shapes(items: object) -> None:
    with pytest.raises(AsvsError):
        _ = asvs_matrix._walk_items(items)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("fault", ["shape", "version", "count", "duplicate"])
def test_pinned_asvs_loader_rejects_post_digest_semantic_faults(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    body = Path("security/asvs/requirements-5.0.0.json").read_bytes()
    reviewed = load_pinned_asvs_requirements()

    def read_reviewed(_path: Path, *, max_bytes: int) -> bytes:
        assert max_bytes == len(body)
        return body

    monkeypatch.setattr(asvs_matrix, "_read_bounded_regular_file", read_reviewed)
    if fault in {"shape", "version"}:
        payload: object = [] if fault == "shape" else {"Version": "4.0.0"}

        def parse_payload(_body: bytes) -> object:
            return payload

        monkeypatch.setattr(asvs_matrix, "_parse_json_bytes", parse_payload)
    else:
        requirements = reviewed[:-1]
        if fault == "duplicate":
            last = reviewed[-1]
            requirements = (
                *reviewed[:-1],
                AsvsRequirement(
                    identifier=reviewed[-2].identifier,
                    text=last.text,
                    level=last.level,
                ),
            )

        def walk_items(_items: object) -> list[AsvsRequirement]:
            return list(requirements)

        monkeypatch.setattr(asvs_matrix, "_walk_items", walk_items)

    with pytest.raises(AsvsError):
        _ = load_pinned_asvs_requirements()


def _branch_git_request() -> GitCommandRequest:
    return GitCommandRequest(
        argv=("/usr/bin/git", "--version"),
        timeout_seconds=1,
        max_stdout_bytes=32,
        max_stderr_bytes=32,
        env=(("LANG", "C"),),
        cwd=Path("/"),
    )


def test_git_event_consumer_ignores_unknown_and_temporarily_blocked_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poller = select.poll()
    capture = asvs_matrix._GitCaptureBuffers(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        descriptors={},
        poller=poller,
        streams={"stdout": bytearray(), "stderr": bytearray()},
        overflow={"stdout": False, "stderr": False},
    )
    asvs_matrix._consume_git_event(999, capture, _branch_git_request())  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    read_fd, write_fd = os.pipe()
    capture.descriptors[read_fd] = "stdout"

    def temporarily_blocked(_descriptor: int, _amount: int) -> bytes:
        raise BlockingIOError

    monkeypatch.setattr(os, "read", temporarily_blocked)
    try:
        asvs_matrix._consume_git_event(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            read_fd,
            capture,
            _branch_git_request(),
        )
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_git_capture_charges_an_expired_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Poller:
        def register(self, descriptor: int, event_mask: int) -> None:
            del descriptor, event_mask

        def poll(self, timeout: int) -> list[tuple[int, int]]:
            del timeout
            pytest.fail("an expired deadline must not poll")

    class Process:
        pid = os.getpid()

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

    values = iter((0.0, 2.0))

    def monotonic() -> float:
        return next(values)

    def terminate(_process: subprocess.Popen[bytes]) -> int:
        return 0

    monkeypatch.setattr(select, "poll", Poller)
    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(asvs_matrix, "_terminate_git_process", terminate)
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    try:
        result = asvs_matrix._capture_git_process(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            cast("subprocess.Popen[bytes]", cast("object", Process())),
            stdout_read,
            stderr_read,
            _branch_git_request(),
        )
    finally:
        os.close(stdout_write)
        os.close(stderr_write)
    assert result.timed_out is True


def test_git_capture_terminates_if_polling_raises_before_a_returncode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Poller:
        def register(self, descriptor: int, event_mask: int) -> None:
            del descriptor, event_mask

        def poll(self, timeout: int) -> list[tuple[int, int]]:
            del timeout
            msg = "injected poll failure"
            raise RuntimeError(msg)

    class Process:
        pid = os.getpid()

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

    terminations = 0

    def terminate(_process: subprocess.Popen[bytes]) -> int:
        nonlocal terminations
        terminations += 1
        return 0

    monkeypatch.setattr(select, "poll", Poller)
    monkeypatch.setattr(asvs_matrix, "_terminate_git_process", terminate)
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    try:
        with pytest.raises(RuntimeError, match="poll failure"):
            _ = asvs_matrix._capture_git_process(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                cast("subprocess.Popen[bytes]", cast("object", Process())),
                stdout_read,
                stderr_read,
                _branch_git_request(),
            )
    finally:
        os.close(stdout_write)
        os.close(stderr_write)
    assert terminations == 1


def test_script_main_guard_dispatches_the_real_check_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["build_asvs_matrix.py", "--check"])

    with pytest.raises(SystemExit) as raised:
        _ = cast(
            "object",
            runpy.run_path("scripts/build_asvs_matrix.py", run_name="__main__"),
        )

    assert raised.value.code == 0
