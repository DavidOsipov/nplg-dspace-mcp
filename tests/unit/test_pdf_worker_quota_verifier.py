# Copyright (c) 2026 David Osipov
"""Quota proof schedule and authority regression tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from scripts import verify_pdf_worker_quota as subject
from scripts.verification_envelope import (
    ArgvExecutor,
    CommandOutcome,
    ControllerBinding,
    ProbePlan,
    VerificationError,
    VerificationProof,
    VerificationRequest,
    VerifierPolicy,
)

if TYPE_CHECKING:
    from pathlib import Path

_CANDIDATE_ID = "phase4-candidate-0001"
_TREE = "a" * 40
_IMAGE = "registry.example/nplg@sha256:" + "b" * 64


def test_quota_schedule_covers_kernel_enforced_overruns() -> None:
    assert subject.PROBES == (
        "image.identity",
        "quota.supported",
        "quota.exact-byte-accepted",
        "quota.n-plus-one-byte-denied",
        "quota.exact-inode-accepted",
        "quota.n-plus-one-file-denied",
        "quota.n-plus-one-directory-denied",
        "quota.zero-byte-flood-denied",
        "quota.sparse-blocks-bounded",
        "quota.concurrent-overrun-denied",
        "process.overrun-killed",
        "cleanup.root-removed",
        "headroom.restored",
    )


def test_quota_verifier_rejects_authority_confusion_before_delegate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wrapper itself must bind its verifier name before generic validation."""
    commands = tuple(("controller-probe", probe) for probe in subject.PROBES)
    request = VerificationRequest(
        version=1,
        verifier="scanner-container",
        candidate_id=_CANDIDATE_ID,
        candidate_tree=_TREE,
        image_subjects=(_IMAGE,),
        probes=tuple(
            ProbePlan(probe_id=name, argv=argv)
            for name, argv in zip(subject.PROBES, commands, strict=True)
        ),
    )

    def executor(argv: tuple[str, ...]) -> CommandOutcome:
        pytest.fail(f"authority-confused request executed: {argv!r}")

    def permissive_delegate(
        candidate: VerificationRequest,
        *,
        policy: VerifierPolicy,
        executor: ArgvExecutor,
        proof_path: Path,
    ) -> VerificationProof:
        _ = (policy, executor, proof_path)
        return VerificationProof(
            version=1,
            verifier=candidate.verifier,
            candidate_id=candidate.candidate_id,
            candidate_tree=candidate.candidate_tree,
            image_subjects=candidate.image_subjects,
            probe_ids=tuple(plan.probe_id for plan in candidate.probes),
        )

    monkeypatch.setattr(subject, "verify_request", permissive_delegate)
    binding = ControllerBinding(
        candidate_id=_CANDIDATE_ID,
        candidate_tree=_TREE,
        image_subjects=(_IMAGE,),
        commands=commands,
        executor=executor,
        proof_path=tmp_path / "proof.json",
    )

    with pytest.raises(VerificationError, match="verifier authority mismatch"):
        _ = subject.verify(request, binding=binding)

    accepted = VerificationRequest(
        version=1,
        verifier="pdf-worker-quota",
        candidate_id=request.candidate_id,
        candidate_tree=request.candidate_tree,
        image_subjects=request.image_subjects,
        probes=request.probes,
    )
    assert subject.verify(accepted, binding=binding).verifier == "pdf-worker-quota"
