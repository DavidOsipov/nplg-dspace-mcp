# Copyright (c) 2026 David Osipov
"""Adversarial tests for the injected PDF-worker proof verifier."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

import pytest

from scripts import verify_pdf_worker_container as subject
from scripts.verification_envelope import (
    CommandOutcome,
    ControllerBinding,
    ProbePlan,
    VerificationError,
    VerificationRequest,
)

if TYPE_CHECKING:
    from pathlib import Path

_CANDIDATE_ID = "phase4-candidate-0001"
_TREE = "a" * 40
_IMAGE = "registry.example/nplg@sha256:" + "b" * 64


def _commands() -> tuple[tuple[str, ...], ...]:
    return tuple(("controller-probe", name) for name in subject.PROBES)


def test_pdf_worker_schedule_matches_the_reviewed_container_battery() -> None:
    """The local fixture must not silently weaken the external-gate battery."""
    assert subject.PROBES == (
        "image.identity",
        "network.dns-denied",
        "network.ipv4-denied",
        "network.ipv6-denied",
        "network.netlink-denied",
        "secrets.unavailable",
        "filesystem.root-read-only",
        "filesystem.staging-only-write",
        "process.pid-ceiling",
        "process.deadline-kill",
        "ipc.peer-credentials",
        "ipc.nonce-replay-denied",
        "corpus.complete",
        "cleanup.complete",
    )


def _request(commands: tuple[tuple[str, ...], ...]) -> VerificationRequest:
    return VerificationRequest(
        version=1,
        verifier="pdf-worker-container",
        candidate_id=_CANDIDATE_ID,
        candidate_tree=_TREE,
        image_subjects=(_IMAGE,),
        probes=tuple(
            ProbePlan(probe_id=name, argv=argv)
            for name, argv in zip(subject.PROBES, commands, strict=True)
        ),
    )


def test_pdf_worker_verifier_binds_exact_probes_and_writes_once(tmp_path: Path) -> None:
    """Missing/reordered probes, a build command, or a preexisting proof fail closed."""
    commands = _commands()
    request = _request(commands)
    observed: list[tuple[str, ...]] = []

    def executor(argv: tuple[str, ...]) -> CommandOutcome:
        observed.append(argv)
        return CommandOutcome(
            argv=argv,
            returncode=0,
            timed_out=False,
            stdout=b"ok",
            stderr=b"",
        )

    proof_path = tmp_path / "proof.json"
    proof = subject.verify(
        request,
        binding=ControllerBinding(
            candidate_id=_CANDIDATE_ID,
            candidate_tree=_TREE,
            image_subjects=(_IMAGE,),
            commands=commands,
            executor=executor,
            proof_path=proof_path,
        ),
    )

    assert observed == list(commands)
    assert proof.probe_ids == subject.PROBES
    proof_document = cast(
        "dict[str, object]", json.loads(proof_path.read_text(encoding="utf-8"))
    )
    assert proof_document["candidate_tree"] == _TREE

    with pytest.raises(VerificationError):
        _ = subject.verify(
            _request(tuple(reversed(commands))),
            binding=ControllerBinding(
                candidate_id=_CANDIDATE_ID,
                candidate_tree=_TREE,
                image_subjects=(_IMAGE,),
                commands=commands,
                executor=executor,
                proof_path=tmp_path / "second" / "proof.json",
            ),
        )
    build_commands = (("controller-probe", "build"), *commands[1:])
    with pytest.raises(VerificationError):
        _ = subject.verify(
            _request(build_commands),
            binding=ControllerBinding(
                candidate_id=_CANDIDATE_ID,
                candidate_tree=_TREE,
                image_subjects=(_IMAGE,),
                commands=build_commands,
                executor=executor,
                proof_path=tmp_path / "proof.json",
            ),
        )
    with pytest.raises(VerificationError):
        _ = subject.verify(
            request,
            binding=ControllerBinding(
                candidate_id=_CANDIDATE_ID,
                candidate_tree=_TREE,
                image_subjects=(_IMAGE,),
                commands=commands,
                executor=executor,
                proof_path=proof_path,
            ),
        )
