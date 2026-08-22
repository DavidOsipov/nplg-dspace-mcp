#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Strict injected-executor contract for non-authoritative deployment proofs."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast

from pydantic import Field, StringConstraints, model_validator

from nplg_mcp.contracts import StrictModel

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Self

_MAX_OUTPUT_BYTES = 4096
_CANARY = b"NPLG_SECRET_CANARY"
_ERR_POLICY = "trusted verifier policy is invalid"
_ERR_AUTHORITY = "verification authority does not match the request"
_ERR_IDENTITY = "verification candidate identity does not match"
_ERR_IMAGES = "verification image subjects do not match"
_ERR_PROBES = "verification probes are missing, reordered, or altered"
_ERR_EXECUTOR = "verification executor returned an invalid result"
_ERR_OUTCOME = "verification probe did not complete safely"
_ERR_SCHEDULE = "verification probe schedule is incomplete"
_ERR_SCHEDULE_TYPE = "verification probe schedule is invalid"
_ERR_PROOF_PATH = "verification proof path is invalid"
_ERR_PROOF_DIRECTORY = "verification proof directory is unavailable"
_ERR_PROOF_DIRECTORY_TYPE = "verification proof directory is invalid"
_ERR_PROOF_WRITE = "verification proof cannot be written exclusively"
_ERR_COMMAND = "verification command is not diagnostic-only"
_ERR_EXECUTION = "verification executor failed"

CandidateId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=16,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    ),
]
GitIdentity = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{40}$"),
]
ImageDigest = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$"),
]
ProbeId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=96,
        pattern=r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$",
    ),
]
ArgvItem = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=1024,
        pattern=r"^[^\x00\r\n]+$",
    ),
]


class VerificationError(RuntimeError):
    """A safe rejection of untrusted candidate verification material."""


class ProbePlan(StrictModel):
    """One controller-authorized probe and its exact argv vector."""

    probe_id: ProbeId
    argv: Annotated[tuple[ArgvItem, ...], Field(min_length=1, max_length=32)]


class VerificationRequest(StrictModel):
    """Candidate description accepted only when a controller binds every field."""

    version: Literal[1]
    verifier: Annotated[
        str,
        StringConstraints(
            strict=True, min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$"
        ),
    ]
    candidate_id: CandidateId
    candidate_tree: GitIdentity
    image_subjects: Annotated[
        tuple[ImageDigest, ...], Field(min_length=1, max_length=8)
    ]
    probes: Annotated[tuple[ProbePlan, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def require_unique_ordered_subjects(self) -> Self:
        """Reject duplicate image and probe aliases before any command runs."""
        if len(set(self.image_subjects)) != len(self.image_subjects):
            message = "verification image subjects must be unique"
            raise ValueError(message)
        probe_ids = tuple(item.probe_id for item in self.probes)
        if len(set(probe_ids)) != len(probe_ids):
            message = "verification probe identifiers must be unique"
            raise ValueError(message)
        return self


class VerificationProof(StrictModel):
    """Small controller-bound success record; command output is never persisted."""

    version: Literal[1]
    verifier: str
    candidate_id: CandidateId
    candidate_tree: GitIdentity
    image_subjects: tuple[ImageDigest, ...]
    probe_ids: tuple[ProbeId, ...]


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    """Bounded result returned by the independently controlled executor."""

    argv: tuple[str, ...]
    returncode: int
    timed_out: bool
    stdout: bytes
    stderr: bytes


class ArgvExecutor(Protocol):
    """Protected controller-owned command authority injected into a verifier."""

    def __call__(self, argv: tuple[str, ...]) -> CommandOutcome:
        """Execute an already validated exact argv without a shell."""
        ...


@dataclass(frozen=True, slots=True)
class VerifierPolicy:
    """Trusted expected identities and a complete ordered probe schedule."""

    verifier: str
    candidate_id: str
    candidate_tree: str
    image_subjects: tuple[str, ...]
    probes: tuple[ProbePlan, ...]


@dataclass(frozen=True, slots=True)
class ControllerBinding:
    """Protected-controller inputs that candidate proof code cannot derive."""

    candidate_id: str
    candidate_tree: str
    image_subjects: tuple[str, ...]
    commands: tuple[tuple[str, ...], ...]
    executor: ArgvExecutor
    proof_path: Path


def _validate_policy(policy: VerifierPolicy) -> None:
    try:
        _ = VerificationRequest(
            version=1,
            verifier=policy.verifier,
            candidate_id=policy.candidate_id,
            candidate_tree=policy.candidate_tree,
            image_subjects=policy.image_subjects,
            probes=policy.probes,
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(_ERR_POLICY) from exc


def _validate_request(request: VerificationRequest, policy: VerifierPolicy) -> None:
    if request.verifier != policy.verifier:
        raise VerificationError(_ERR_AUTHORITY)
    if (
        request.candidate_id != policy.candidate_id
        or request.candidate_tree != policy.candidate_tree
    ):
        raise VerificationError(_ERR_IDENTITY)
    if request.image_subjects != policy.image_subjects:
        raise VerificationError(_ERR_IMAGES)
    if request.probes != policy.probes:
        raise VerificationError(_ERR_PROBES)


def _validate_outcome(outcome: object, expected_argv: tuple[str, ...]) -> None:
    if type(outcome) is not CommandOutcome:
        raise VerificationError(_ERR_EXECUTOR)
    result = outcome
    if (
        result.argv != expected_argv
        or type(result.returncode) is not int
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or result.timed_out is not False
        or result.returncode != 0
        or len(result.stdout) > _MAX_OUTPUT_BYTES
        or len(result.stderr) > _MAX_OUTPUT_BYTES
        or _CANARY in result.stdout
        or _CANARY in result.stderr
    ):
        raise VerificationError(_ERR_OUTCOME)


def ordered_probe_plan(
    names: tuple[str, ...],
    commands: tuple[tuple[str, ...], ...],
) -> tuple[ProbePlan, ...]:
    """Reject a missing or extra controller command before any command executes."""
    if len(commands) != len(names):
        raise VerificationError(_ERR_SCHEDULE)
    try:
        return tuple(
            ProbePlan(probe_id=name, argv=argv)
            for name, argv in zip(names, commands, strict=True)
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(_ERR_SCHEDULE_TYPE) from exc


def controller_policy(
    verifier: str,
    probe_names: tuple[str, ...],
    binding: ControllerBinding,
) -> VerifierPolicy:
    """Combine a reviewed verifier name with one protected controller binding."""
    return VerifierPolicy(
        verifier=verifier,
        candidate_id=binding.candidate_id,
        candidate_tree=binding.candidate_tree,
        image_subjects=binding.image_subjects,
        probes=ordered_probe_plan(probe_names, binding.commands),
    )


def _exclusive_write(path: Path, proof: VerificationProof) -> None:
    if not path.is_absolute() or path.name != "proof.json":
        raise VerificationError(_ERR_PROOF_PATH)
    parents = (path.parent, *path.parent.parents)
    for directory in parents:
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise VerificationError(_ERR_PROOF_DIRECTORY) from exc
        if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise VerificationError(_ERR_PROOF_DIRECTORY_TYPE)
    proof_payload = cast("dict[str, object]", proof.model_dump(mode="json"))
    proof_json = json.dumps(proof_payload, sort_keys=True) + "\n"
    encoded = proof_json.encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise VerificationError(_ERR_PROOF_WRITE) from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def verify_request(
    request: VerificationRequest,
    *,
    policy: VerifierPolicy,
    executor: ArgvExecutor,
    proof_path: Path,
) -> VerificationProof:
    """Run only pre-authorized probes and publish a non-overwritable proof."""
    _validate_policy(policy)
    _validate_request(request, policy)
    for probe in request.probes:
        forbidden = {"build", "pull"}.intersection(probe.argv)
        if forbidden:
            raise VerificationError(_ERR_COMMAND)
        try:
            outcome = executor(probe.argv)
        except Exception as exc:
            raise VerificationError(_ERR_EXECUTION) from exc
        _validate_outcome(outcome, probe.argv)
    proof = VerificationProof(
        version=1,
        verifier=request.verifier,
        candidate_id=request.candidate_id,
        candidate_tree=request.candidate_tree,
        image_subjects=request.image_subjects,
        probe_ids=tuple(item.probe_id for item in request.probes),
    )
    _exclusive_write(proof_path, proof)
    return proof
