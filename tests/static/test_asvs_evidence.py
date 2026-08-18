# Copyright (c) 2026 David Osipov
"""Static conformance tests for the pinned ASVS evidence inventory."""

from __future__ import annotations

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
TASK2_S603_LINE = 3_192
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
