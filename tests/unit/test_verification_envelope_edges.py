# Copyright (c) 2026 David Osipov
"""Adversarial branch tests for the shared verification-result envelope."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Never

import pytest

from nplg_mcp.contracts import StrictModel
from scripts import verification_envelope as envelope


class _FixtureProof(StrictModel):
    value: str


def _request_and_policy() -> tuple[
    envelope.VerificationRequest,
    envelope.VerifierPolicy,
]:
    probe = envelope.ProbePlan(probe_id="probe", argv=("probe",))
    request = envelope.VerificationRequest(
        version=1,
        verifier="fixture",
        candidate_id="fixture-candidate",
        candidate_tree="a" * 40,
        image_subjects=("registry.example/image@sha256:" + "b" * 64,),
        probes=(probe,),
    )
    return request, envelope.VerifierPolicy(
        verifier=request.verifier,
        candidate_id=request.candidate_id,
        candidate_tree=request.candidate_tree,
        image_subjects=request.image_subjects,
        probes=request.probes,
    )


def test_proof_descriptor_guards_reject_mismatched_object_types(tmp_path: Path) -> None:
    regular = tmp_path / "regular"
    _ = regular.write_bytes(b"payload")
    regular_descriptor = os.open(regular, os.O_RDONLY | os.O_CLOEXEC)
    directory_descriptor = os.open(
        tmp_path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
    )
    try:
        with pytest.raises(
            envelope.VerificationError,
            match="verification proof directory is invalid",
        ):
            envelope._require_directory_descriptor(regular_descriptor)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(
            envelope.VerificationError,
            match="verification proof cannot be written exclusively",
        ):
            envelope._require_private_regular_file(directory_descriptor)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(directory_descriptor)
        os.close(regular_descriptor)


def test_proof_writer_rejects_a_zero_progress_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact"
    descriptor = os.open(artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    def zero_write(_descriptor: int, _encoded: bytes) -> int:
        return 0

    monkeypatch.setattr(os, "write", zero_write)
    try:
        with pytest.raises(
            envelope.VerificationError,
            match="verification proof cannot be written exclusively",
        ):
            envelope._write_all(descriptor, b"payload")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(descriptor)
    assert artifact.read_bytes() == b""


def test_proof_parent_rejects_a_relative_output_before_opening() -> None:
    with pytest.raises(
        envelope.VerificationError,
        match="verification proof path is invalid",
    ):
        _ = envelope._open_proof_parent(Path("proof.json"))  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_proof_publication_fails_closed_without_nofollow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_directory = tmp_path / "proofs"
    proof_directory.mkdir(mode=0o700)
    proof_path = proof_directory / "proof.json"
    monkeypatch.delattr(os, "O_NOFOLLOW")

    with pytest.raises(
        envelope.VerificationError,
        match="verification proof cannot be written exclusively",
    ):
        envelope.write_verification_result(proof_path, _FixtureProof(value="safe"))

    assert not proof_path.exists()


def test_proof_publication_closes_and_unlinks_after_post_open_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_directory = tmp_path / "proofs"
    proof_directory.mkdir(mode=0o700)
    proof_path = proof_directory / "proof.json"
    real_open = os.open
    opened_proofs: list[int] = []

    def recording_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if os.fsdecode(path) == proof_path.name:
            opened_proofs.append(descriptor)
        return descriptor

    def failing_fchmod(_descriptor: int, _mode: int) -> Never:
        message = "simulated proof mode failure"
        raise OSError(message)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "fchmod", failing_fchmod)

    with pytest.raises(OSError, match="simulated proof mode failure"):
        envelope.write_verification_result(proof_path, _FixtureProof(value="safe"))

    assert len(opened_proofs) == 1
    with pytest.raises(OSError, match="Bad file descriptor"):
        _ = os.fstat(opened_proofs[0])
    assert not proof_path.exists()


@pytest.mark.parametrize("maximum", [True, 0, 64 * 1024 + 1])
def test_probe_runner_rejects_nonexact_or_out_of_range_output_bounds(
    maximum: int,
) -> None:
    request, policy = _request_and_policy()

    def forbidden_executor(argv: tuple[str, ...]) -> Never:
        del argv
        message = "executor must not run for an invalid output bound"
        raise AssertionError(message)

    with pytest.raises(
        envelope.VerificationError,
        match="trusted verifier policy is invalid",
    ):
        _ = envelope.run_verified_probes(
            request,
            policy=policy,
            executor=forbidden_executor,
            max_output_bytes=maximum,
        )
