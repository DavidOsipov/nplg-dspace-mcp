# Copyright (c) 2026 David Osipov
"""Static conformance tests for the pinned ASVS evidence inventory."""

from __future__ import annotations

import ast
import os
import re
import tokenize
from dataclasses import replace
from datetime import UTC, date, datetime
from io import BytesIO
from pathlib import Path

import pytest
from pydantic import ValidationError

from scripts.build_asvs_matrix import (
    ASVS_COMMIT,
    ASVS_RELEASE_REF,
    ASVS_SHA256,
    ASVS_SIZE,
    GIT_CLOSED_ENV,
    ApplicableEvidenceRow,
    AsvsRequirement,
    ClaimPolicyRecord,
    CustodiedEvidenceReference,
    GitCommandRequest,
    GitCommandResult,
    LocalEvidenceReference,
    NotApplicableEvidenceRow,
    load_evidence_manifest,
    load_evidence_matrix,
    load_independent_evidence_policy,
    load_pinned_asvs_requirements,
    verify_ref,
)

L1_LEVEL = 1
L2_LEVEL = 2
L1_COUNT = 70
L2_COUNT = 183
L1_L2_COUNT = L1_COUNT + L2_COUNT
PROFILE_COUNT = 3
EXPECTED_ROWS = L1_L2_COUNT * PROFILE_COUNT
GIT_TIMEOUT_SECONDS = 30
GIT_OUTPUT_BYTES = 4_096
TASK2_SOURCE = Path("scripts/build_asvs_matrix.py")
TASK2_S603_LINE = 3_479
TASK2_S603_RATIONALE = (
    "        # Security rationale: argv[0] is the immutable reviewed /usr/bin/git.",
    "        # Tuple argv, cwd=/, closed env, no shell, output bounds, and timeout are",
    ("        # validated above; see https://github.com/astral-sh/ruff/issues/4045."),
)
STATIC_DIRECTIVE_PATTERN = re.compile(
    r"""
    \A \# \s*
    (?:
        (?:ruff|flake8) \s* : |
        (?:noqa|nosec|nosemgrep) \b |
        type \s* : \s* ignore \b |
        pyright \s* : |
        mypy \s* : |
        (?:ruff \s* : \s*)? fmt \s* : |
        (?:ruff \s* : \s*)? isort \s* : |
        yapf \s* : |
        pragma \s* : \s* no \s* (?:cover|branch) \b
    )
    """,
    flags=re.IGNORECASE | re.VERBOSE,
)
_DEFAULT_REFERENCE_EXPIRY = datetime(2027, 1, 1, tzinfo=UTC)


class _InjectedGitRunner:
    def __init__(self, result: GitCommandResult) -> None:
        super().__init__()
        self.result = result
        self.request: GitCommandRequest | None = None

    def run(self, request: GitCommandRequest) -> GitCommandResult:
        self.request = request
        return self.result


def _task2_suppression_inventory(source: str) -> tuple[tuple[int, str], ...]:
    comments = (
        (token.start[0], token.string)
        for token in tokenize.tokenize(BytesIO(source.encode("utf-8")).readline)
        if token.type == tokenize.COMMENT
    )
    return tuple(
        (line, comment)
        for line, comment in comments
        if STATIC_DIRECTIVE_PATTERN.search(comment) is not None
    )


def _valid_task2_s603_inventory(source: str) -> bool:
    lines = source.splitlines()
    if _task2_suppression_inventory(source) != ((TASK2_S603_LINE, "# noqa: S603"),):
        return False
    line_offset = TASK2_S603_LINE - 1
    return tuple(
        lines[line_offset - len(TASK2_S603_RATIONALE) : line_offset]
    ) == TASK2_S603_RATIONALE and lines[line_offset].endswith(
        "subprocess.Popen(  # noqa: S603"
    )


def test_candidate_mutation_logic_is_nested_under_closed_function_inventory() -> None:
    """Mutmut must group every candidate-only helper under a reviewed function."""
    module = ast.parse(TASK2_SOURCE.read_text(encoding="utf-8"))
    top_level_functions = {
        node.name for node in module.body if isinstance(node, ast.FunctionDef)
    }

    assert top_level_functions.isdisjoint(
        {
            "_candidate_requirements",
            "_candidate_requirement_ids",
            "_candidate_reference_context",
            "_candidate_reference_binding_blockers",
            "_candidate_reference_is_independently_verified",
            "_candidate_reference_governance_blockers",
            "_candidate_required_evidence_blockers",
        }
    )


def _mutate_task2_suppression(source: str, mutation: str) -> str:
    directive = "# noqa: S603"
    appended = {
        "mypy-file-ignore": "# mypy: ignore-errors",
        "isort-file-ignore": "# isort: skip_file",
        "coverage-ignore": "# pragma: no cover",
    }.get(mutation)
    if appended is not None:
        return f"{source}\n{appended}\n"
    if mutation == "missing":
        return source.replace(directive, "", 1)
    if mutation == "broadened":
        return source.replace(directive, "# noqa: S603, S607", 1)
    if mutation == "extra":
        return source + "\n# noqa: S603\n"
    without_original = source.replace(directive, "", 1)
    return without_original.replace(
        "            request.argv,",
        f"            request.argv,  {directive}",
        1,
    )


def _applicable_row_data() -> dict[str, object]:
    return {
        "applicability": "applicable",
        "applicability_rationale": "The surface remains conservatively applicable.",
        "asvs_version": "5.0.0",
        "evidence_date": date(2026, 8, 16),
        "evidence_ids": (),
        "evidence_revision": "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
        "invariant": "The claim remains unassessed.",
        "level": L2_LEVEL,
        "owner": "security-owner",
        "profile": "alpic-metadata",
        "required_evidence_kinds": (),
        "requirement_id": "v5.0.0-V1.1.1",
        "requirement_text": "Fixture requirement.",
        "target_phase": "phase-0",
        "threat_boundary": "client-to-alpic-edge",
        "verdict": "Not assessed",
    }


def _claim_policy(
    *,
    pass_required_kinds: tuple[str, ...] | None = None,
    na_absence_required: bool = False,
) -> ClaimPolicyRecord:
    payload: dict[str, object] = {
        "requirement_id": "v5.0.0-V1.1.1",
        "profile": "alpic-metadata",
        "pass_required_kinds": pass_required_kinds,
        "na_absence_required": na_absence_required,
        "risk_acceptance_authority_id": None,
    }
    return ClaimPolicyRecord.model_validate(payload)


def _local_reference(
    *,
    evidence_id: str = "ev.fixture",
    kind: str = "test",
    expires_at: datetime = _DEFAULT_REFERENCE_EXPIRY,
) -> LocalEvidenceReference:
    payload: dict[str, object] = {
        "artifact_path": "evidence/fixture.json",
        "asserted_invariant": "The claim remains unassessed.",
        "candidate_tree_sha256": "1" * 64,
        "collected_at": datetime(2026, 8, 16, tzinfo=UTC),
        "covered_surface": "src/nplg_mcp",
        "deployment_id": None,
        "evidence_id": evidence_id,
        "evidence_revision": "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
        "expires_at": expires_at,
        "image_digest": None,
        "kind": kind,
        "profiles": ("alpic-metadata",),
        "requirement_ids": ("v5.0.0-V1.1.1",),
        "result": "pass",
        "reviewer": "reviewer-subject",
        "selectors": ("tests/unit/test_fixture.py::test_claim",),
        "sha256": "2" * 64,
        "storage": "local",
        "verifier": "test-report-v1",
    }
    return LocalEvidenceReference.model_validate(payload)


def _applicable_release_blockers(
    row: ApplicableEvidenceRow,
    claim: ClaimPolicyRecord,
    references: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...],
    *,
    as_of: datetime,
) -> tuple[str, ...]:
    blockers: list[str] = []
    if row.verdict == "Risk accepted":
        reason = (
            "expired-risk-acceptance"
            if row.risk_expiry is not None and as_of.date() >= row.risk_expiry
            else "risk-accepted-publicly-ineligible"
        )
        blockers.append(reason)
    else:
        verdict_reason = {
            "Not assessed": "not-assessed",
            "Fail": "failed",
            "Partial": "partial",
        }.get(row.verdict)
        if verdict_reason is not None:
            blockers.append(verdict_reason)
        elif (
            claim.pass_required_kinds is None
            or row.required_evidence_kinds != claim.pass_required_kinds
        ):
            blockers.append("pass-policy-not-closed")
        else:
            matching = tuple(
                reference
                for reference in references
                if reference.evidence_id in row.evidence_ids
                and row.requirement_id in reference.requirement_ids
                and row.profile in reference.profiles
                and row.evidence_revision == reference.evidence_revision
                and row.invariant == reference.asserted_invariant
            )
            if any(reference.expires_at <= as_of for reference in matching):
                blockers.append("expired-evidence")
            elif any(
                not any(reference.kind == kind for reference in matching)
                for kind in claim.pass_required_kinds
            ):
                blockers.append("missing-required-evidence")
    return tuple(blockers)


def _not_applicable_release_blockers(
    row: NotApplicableEvidenceRow,
    claim: ClaimPolicyRecord,
    references: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...],
    *,
    as_of: datetime,
) -> tuple[str, ...]:
    blockers: list[str] = []
    matching_absence = tuple(
        reference
        for reference in references
        if reference.evidence_id in row.absence_evidence_ids
        and row.requirement_id in reference.requirement_ids
        and row.profile in reference.profiles
        and row.evidence_revision == reference.evidence_revision
        and row.invariant == reference.asserted_invariant
    )
    if row.applicability_review_due <= as_of.date():
        blockers.append("expired-na-review")
    elif not claim.na_absence_required:
        blockers.append("unjustified-na")
    elif any(reference.expires_at <= as_of for reference in matching_absence):
        blockers.append("expired-absence-evidence")
    elif not matching_absence:
        blockers.append("missing-absence-evidence")
    return tuple(blockers)


def _row_release_blockers(
    row: ApplicableEvidenceRow | NotApplicableEvidenceRow,
    claim: ClaimPolicyRecord,
    references: tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...],
    *,
    as_of: datetime,
) -> tuple[str, ...]:
    if row.evidence_revision != "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0":
        return ("evidence-revision-mismatch",)
    if isinstance(row, ApplicableEvidenceRow):
        return _applicable_release_blockers(
            row,
            claim,
            references,
            as_of=as_of,
        )
    return _not_applicable_release_blockers(
        row,
        claim,
        references,
        as_of=as_of,
    )


def _profile_release_blockers(
    profile: str,
    *,
    as_of: datetime,
) -> tuple[str, ...]:
    rows = tuple(row for row in load_evidence_matrix() if row.profile == profile)
    manifest = load_evidence_manifest()
    policy = load_independent_evidence_policy()
    claims = tuple(claim for claim in policy.claims if claim.profile == profile)
    row_ids = tuple(row.requirement_id for row in rows)
    claim_ids = tuple(claim.requirement_id for claim in claims)
    if row_ids != claim_ids or len(rows) != L1_L2_COUNT:
        return ("profile:incomplete-product",)
    by_requirement = {claim.requirement_id: claim for claim in claims}
    blockers: list[str] = []
    for row in rows:
        blockers.extend(
            f"{row.requirement_id}:{reason}"
            for reason in _row_release_blockers(
                row,
                by_requirement[row.requirement_id],
                manifest,
                as_of=as_of,
            )
        )
    return tuple(blockers)


def test_task2_subprocess_suppression_has_exact_closed_inventory() -> None:
    source = TASK2_SOURCE.read_text(encoding="utf-8")

    assert _valid_task2_s603_inventory(source)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "moved",
        "broadened",
        "extra",
        "mypy-file-ignore",
        "isort-file-ignore",
        "coverage-ignore",
    ],
)
def test_task2_subprocess_suppression_inventory_rejects_mutants(
    mutation: str,
) -> None:
    source = TASK2_SOURCE.read_text(encoding="utf-8")

    assert not _valid_task2_s603_inventory(_mutate_task2_suppression(source, mutation))


def test_pinned_asvs_matrix_has_exact_official_profile_product() -> None:
    requirements = load_pinned_asvs_requirements()
    official = {
        requirement.identifier: requirement
        for requirement in requirements
        if requirement.level <= L2_LEVEL
    }
    matrix = load_evidence_matrix()
    actual = tuple((row.requirement_id, row.profile) for row in matrix)

    assert sum(item.level == L1_LEVEL for item in requirements) == L1_COUNT
    assert sum(item.level == L2_LEVEL for item in requirements) == L2_COUNT
    assert len(official) == L1_L2_COUNT
    assert len(actual) == EXPECTED_ROWS
    assert len(actual) == len(set(actual))
    assert all(
        (row.requirement_text, row.level)
        == (official[row.requirement_id].text, official[row.requirement_id].level)
        for row in matrix
    )


def test_initial_inventory_cannot_overclaim_evidence_or_authority() -> None:
    matrix = load_evidence_matrix()
    manifest = load_evidence_manifest()
    policy = load_independent_evidence_policy()

    assert manifest == ()
    assert all(
        isinstance(row, ApplicableEvidenceRow) and row.verdict == "Not assessed"
        for row in matrix
    )
    assert all(claim.pass_required_kinds is None for claim in policy.claims)
    assert all(not claim.na_absence_required for claim in policy.claims)
    assert policy.custody_authority_ids == ()
    assert policy.release_authority_ids == ()


def test_evidence_discriminator_rejects_illegal_conditional_states() -> None:
    applicable = _applicable_row_data()
    applicable["verdict"] = "N/A"
    not_applicable = _applicable_row_data() | {
        "absence_evidence_ids": ("absence.fixture",),
        "applicability": "not_applicable",
        "applicability_review_due": date(2026, 12, 31),
        "applicability_reviewer": "reviewer-subject",
        "risk_id": "forbidden-risk",
        "verdict": "N/A",
    }

    with pytest.raises(ValidationError):
        _ = ApplicableEvidenceRow.model_validate(applicable)
    with pytest.raises(ValidationError):
        _ = NotApplicableEvidenceRow.model_validate(not_applicable)


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        ("Not assessed", "not-assessed"),
        ("Fail", "failed"),
        ("Partial", "partial"),
    ],
)
def test_public_release_readiness_rejects_every_incomplete_applicable_verdict(
    verdict: str,
    expected: str,
) -> None:
    payload = _applicable_row_data()
    payload["verdict"] = verdict
    row = ApplicableEvidenceRow.model_validate(payload)

    assert _row_release_blockers(
        row,
        _claim_policy(),
        (),
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    ) == (expected,)


@pytest.mark.parametrize(
    ("risk_expiry", "expected"),
    [
        (date(2026, 8, 24), "risk-accepted-publicly-ineligible"),
        (date(2026, 8, 22), "expired-risk-acceptance"),
    ],
)
def test_public_release_readiness_never_accepts_risk_acceptance(
    risk_expiry: date,
    expected: str,
) -> None:
    payload = _applicable_row_data() | {
        "compensating_controls": ("control.fixture",),
        "release_approval_evidence_id": "approval.fixture",
        "residual_risk": "A named residual risk remains.",
        "risk_approver": "independent-approver",
        "risk_expiry": risk_expiry,
        "risk_id": "risk.fixture",
        "risk_owner": "risk-owner",
        "verdict": "Risk accepted",
    }
    row = ApplicableEvidenceRow.model_validate(payload)

    assert _row_release_blockers(
        row,
        _claim_policy(),
        (),
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    ) == (expected,)


def test_public_release_readiness_accepts_only_policy_bound_pass_evidence() -> None:
    payload = _applicable_row_data() | {
        "evidence_ids": ("ev.fixture",),
        "required_evidence_kinds": ("test",),
        "verdict": "Pass",
    }
    row = ApplicableEvidenceRow.model_validate(payload)
    reference = _local_reference()

    assert (
        _row_release_blockers(
            row,
            _claim_policy(pass_required_kinds=("test",)),
            (reference,),
            as_of=datetime(2026, 8, 23, tzinfo=UTC),
        )
        == ()
    )
    assert _row_release_blockers(
        row,
        _claim_policy(),
        (reference,),
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    ) == ("pass-policy-not-closed",)
    assert _row_release_blockers(
        row,
        _claim_policy(pass_required_kinds=("test",)),
        (),
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    ) == ("missing-required-evidence",)


@pytest.mark.parametrize(
    ("review_due", "governance", "expected"),
    [
        (date(2026, 8, 23), "governed", "expired-na-review"),
        (date(2026, 8, 24), "ungoverned", "unjustified-na"),
        (date(2026, 8, 24), "governed", "missing-absence-evidence"),
    ],
)
def test_public_release_readiness_rejects_expired_or_ungoverned_na(
    review_due: date,
    governance: str,
    expected: str,
) -> None:
    payload = _applicable_row_data() | {
        "absence_evidence_ids": ("absence.fixture",),
        "applicability": "not_applicable",
        "applicability_review_due": review_due,
        "applicability_reviewer": "independent-reviewer",
        "verdict": "N/A",
    }
    row = NotApplicableEvidenceRow.model_validate(payload)

    assert _row_release_blockers(
        row,
        _claim_policy(na_absence_required=governance == "governed"),
        (),
        as_of=datetime(2026, 8, 23, tzinfo=UTC),
    ) == (expected,)


def test_public_release_readiness_rejects_missing_evidence_revision() -> None:
    payload = _applicable_row_data()
    del payload["evidence_revision"]

    with pytest.raises(ValidationError):
        _ = ApplicableEvidenceRow.model_validate(payload)


def test_selected_profile_release_eligibility_is_an_explicit_closure_gate() -> None:
    if os.environ.get("REQUIRE_RELEASE_ELIGIBILITY") != "1":
        return
    profile = os.environ.get("RELEASE_PROFILE")
    assert profile in {"alpic-metadata", "private-full"}

    blockers = _profile_release_blockers(
        profile,
        as_of=datetime.now(tz=UTC),
    )

    assert not blockers, (
        f"{profile} release eligibility blocked by {len(blockers)} ASVS rows: "
        + ", ".join(blockers)
    )


def test_local_reference_rejects_traversal_and_unknown_fields() -> None:
    reference: dict[str, object] = {
        "artifact_path": "../evidence.json",
        "asserted_invariant": "The exact claim was tested.",
        "candidate_tree_sha256": "1" * 64,
        "collected_at": datetime(2026, 8, 16, tzinfo=UTC),
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
        "unexpected": True,
        "verifier": "test-report-v1",
    }

    with pytest.raises(ValidationError):
        _ = LocalEvidenceReference.model_validate(reference)


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "malformed",
        "abbreviated",
        "changed",
        "multiple",
        "stderr",
        "timeout",
        "nonzero",
        "overflow",
    ],
)
def test_verify_ref_rejects_every_nonexact_runner_result(mutation: str) -> None:
    exact = GitCommandResult(
        returncode=0,
        stdout=f"{ASVS_COMMIT}\t{ASVS_RELEASE_REF}\n".encode("ascii"),
        stderr=b"",
        complete=True,
        timed_out=False,
        stdout_overflow=False,
        stderr_overflow=False,
    )
    if mutation == "empty":
        result = replace(exact, stdout=b"")
    elif mutation == "malformed":
        result = replace(exact, stdout=b"not-a-git-ref\n")
    elif mutation == "abbreviated":
        result = replace(
            exact, stdout=f"{ASVS_COMMIT[:12]}\t{ASVS_RELEASE_REF}\n".encode()
        )
    elif mutation == "changed":
        result = replace(exact, stdout=f"{'0' * 40}\t{ASVS_RELEASE_REF}\n".encode())
    elif mutation == "multiple":
        result = replace(exact, stdout=exact.stdout + exact.stdout)
    elif mutation == "stderr":
        result = replace(exact, stderr=b"canary")
    elif mutation == "timeout":
        result = replace(exact, complete=False, timed_out=True)
    elif mutation == "nonzero":
        result = replace(exact, returncode=2)
    else:
        result = replace(exact, complete=False, stdout_overflow=True)

    assert verify_ref(_InjectedGitRunner(result)) is False


def test_verify_ref_uses_the_exact_bounded_closed_request() -> None:
    result = GitCommandResult(
        returncode=0,
        stdout=f"{ASVS_COMMIT}\t{ASVS_RELEASE_REF}\n".encode("ascii"),
        stderr=b"",
        complete=True,
        timed_out=False,
        stdout_overflow=False,
        stderr_overflow=False,
    )
    runner = _InjectedGitRunner(result)

    assert verify_ref(runner) is True
    assert runner.request == GitCommandRequest(
        argv=(
            "/usr/bin/git",
            "ls-remote",
            "--refs",
            "https://github.com/OWASP/ASVS.git",
            ASVS_RELEASE_REF,
        ),
        timeout_seconds=GIT_TIMEOUT_SECONDS,
        max_stdout_bytes=GIT_OUTPUT_BYTES,
        max_stderr_bytes=GIT_OUTPUT_BYTES,
        env=GIT_CLOSED_ENV,
        cwd=Path("/"),
    )


def test_pinned_source_identity_is_literal_and_model_is_extra_forbid() -> None:
    source = Path("security/asvs/requirements-5.0.0.json")

    assert source.stat().st_size == ASVS_SIZE
    assert ASVS_SHA256 == (
        "bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35"
    )
    malformed: dict[str, object] = {
        "identifier": "v5.0.0-V1.1.1",
        "level": L2_LEVEL,
        "text": "fixture",
        "unexpected": True,
    }
    with pytest.raises(ValidationError):
        _ = AsvsRequirement.model_validate(malformed)
