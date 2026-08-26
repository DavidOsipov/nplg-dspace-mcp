#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Validate a controller-injected, non-authoritative private recovery diagnostic.

This module deliberately does not parse or mint ``recovery-proof.v2``. That
signed proof belongs to the independently protected release controller. A
successful local execution only records that a bounded synthetic diagnostic
receipt was internally consistent; its terminal verdict remains fail-closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Annotated, Literal, NoReturn, Self, cast

from pydantic import Field, StringConstraints, ValidationError, model_validator

from nplg_mcp.contracts import StrictModel
from scripts.baseline_capture_io import canonical_json_bytes
from scripts.private_recovery_contract import (
    DerivedRenderSubject,
    PrivateRecoveryPolicy,
    UniqueSourcePdfSubject,
)

from .verification_envelope import (
    CandidateId,
    ControllerBinding,
    GitIdentity,
    ImageDigest,
    ProbeId,
    VerificationError,
    VerificationRequest,
    controller_policy,
    run_verified_probes,
    write_verification_result,
)

PROBES = (
    "subjects.identity",
    "volume.complete-loss",
    "backup.restore-or-derived-regeneration",
    "content.digest",
    "filesystem.owner-mode",
    "high-water.restore",
    "clock-anomaly.closed",
    "leases.restore",
    "reservations.restore",
    "corrupt-state.closed",
    "partial-restore.cleaned",
    "rto.measured-within-policy",
    "subjects.unchanged",
    "cleanup.complete",
)

_MAX_RECEIPT_BYTES = 8 * 1024
_MAX_SAFE_COUNT = 9_007_199_254_740_991
_ERR_RECEIPT = "private recovery receipt rejected"

Sha256Digest = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^sha256:[0-9a-f]{64}$"),
]
StrictZero = Annotated[int, Field(strict=True, ge=0, le=0)]
StrictPositiveCount = Annotated[
    int,
    Field(strict=True, ge=1, le=_MAX_SAFE_COUNT),
]
StrictMilliseconds = Annotated[
    int,
    Field(strict=True, ge=0, le=_MAX_SAFE_COUNT),
]
StateInventory = tuple[
    Literal["clock-high-water-and-boot-state"],
    Literal["insertion-high-water"],
    Literal["per-object-insertion-sequence-records"],
    Literal["orphan-staging-cleanup"],
    Literal["post-process-lease-reservation-reconciliation"],
]


class RecoverySubjectReceipt(StrictModel):
    """Digest-bound restore and deterministic-regeneration observations."""

    source_subject_id: Literal["source-pdfs"]
    source_recovery_strategy: Literal["immutable-backup-and-restore"]
    source_before_sha256: Sha256Digest
    source_backup_sha256: Sha256Digest
    source_after_sha256: Sha256Digest
    derived_subject_id: Literal["derived-renders"]
    derived_recovery_strategy: Literal["bounded-cold-regeneration"]
    regeneration_recipe_sha256: Sha256Digest
    derived_expected_sha256: Sha256Digest
    derived_after_sha256: Sha256Digest

    @model_validator(mode="after")
    def _require_identity_preservation(self) -> Self:
        if not (
            self.source_before_sha256
            == self.source_backup_sha256
            == self.source_after_sha256
        ):
            message = "source restore digest drifted"
            raise ValueError(message)
        if self.derived_expected_sha256 != self.derived_after_sha256:
            message = "derived regeneration digest drifted"
            raise ValueError(message)
        return self


class RecoveryFilesystemReceipt(StrictModel):
    """Exact recovered ownership, mode, link, and content observations."""

    owner_uid: Annotated[int, Field(strict=True, ge=0, le=4_294_967_295)]
    owner_gid: Annotated[int, Field(strict=True, ge=0, le=4_294_967_295)]
    directory_mode: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^0[0-7]{3}$"),
    ]
    regular_file_mode: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^0[0-7]{3}$"),
    ]
    symlinks_observed: bool
    hardlinks_observed: bool
    content_sha256: Sha256Digest
    ownership_sha256: Sha256Digest
    mode_sha256: Sha256Digest


class RecoveryStateReceipt(StrictModel):
    """Before/after persistent state and truthful process-state reconstruction."""

    state_ids: StateInventory
    clock_high_water_before_sha256: Sha256Digest
    clock_high_water_after_sha256: Sha256Digest
    insertion_high_water_before_sha256: Sha256Digest
    insertion_high_water_after_sha256: Sha256Digest
    insertion_sequence_reconciliation_sha256: Sha256Digest
    orphan_staging_entries_after: StrictZero
    process_state_persisted: Literal[False]
    active_leases_before_worker_termination: StrictPositiveCount
    active_leases_after_worker_termination: StrictZero
    staging_reservations_before_worker_termination: StrictPositiveCount
    staging_reservations_after_worker_termination: StrictZero
    publication_reservations_before_worker_termination: StrictPositiveCount
    publication_reservations_after_worker_termination: StrictZero
    reserved_bytes_after_reconstruction: StrictZero
    reserved_objects_after_reconstruction: StrictZero
    reserved_inodes_after_reconstruction: StrictZero
    clock_anomaly_new_ingest_closed: Literal[True]
    corrupt_state_new_ingest_closed: Literal[True]
    restart_reconstruction_semantics: Literal[
        "start-ledgers-empty-after-staging-cleanup-and-committed-object-scan"
    ]

    @model_validator(mode="after")
    def _require_high_water_identity(self) -> Self:
        if self.clock_high_water_before_sha256 != self.clock_high_water_after_sha256:
            message = "clock high-water digest drifted"
            raise ValueError(message)
        if (
            self.insertion_high_water_before_sha256
            != self.insertion_high_water_after_sha256
        ):
            message = "insertion high-water digest drifted"
            raise ValueError(message)
        return self


class RecoveryRtoReceipt(StrictModel):
    """One protected-controller monotonic RTO measurement."""

    objective_milliseconds: StrictMilliseconds
    measured_milliseconds: StrictMilliseconds
    clock: Literal["protected-controller-monotonic"]
    within_objective: Literal[True]

    @model_validator(mode="after")
    def _require_measured_objective(self) -> Self:
        if self.measured_milliseconds > self.objective_milliseconds:
            message = "measured recovery exceeded the objective"
            raise ValueError(message)
        return self


class RecoveryExecutionReceipt(StrictModel):
    """Closed supplemental diagnostic receipt emitted by an injected executor."""

    schema_version: Literal[1]
    schema_id: Literal["recovery-diagnostic-receipt.v1"]
    gate_id: Literal["private-full.recovery-proof"]
    command_id: Literal["container.private-full-recovery.v2"]
    scope: Literal["controller-created-synthetic-disposable-volumes-only"]
    release_authoritative: Literal[False]
    candidate_id: CandidateId
    candidate_tree: GitIdentity
    image_subjects_before: Annotated[
        tuple[ImageDigest, ...],
        Field(min_length=1, max_length=8),
    ]
    image_subjects_after: Annotated[
        tuple[ImageDigest, ...],
        Field(min_length=1, max_length=8),
    ]
    candidate_config_before_sha256: Sha256Digest
    candidate_config_after_sha256: Sha256Digest
    recovery_policy_sha256: Sha256Digest
    required_probe_ids: Annotated[
        tuple[ProbeId, ...],
        Field(min_length=len(PROBES), max_length=len(PROBES)),
    ]
    observed_probe_ids: Annotated[
        tuple[ProbeId, ...],
        Field(min_length=len(PROBES), max_length=len(PROBES)),
    ]
    subjects: RecoverySubjectReceipt
    filesystem: RecoveryFilesystemReceipt
    state: RecoveryStateReceipt
    rto: RecoveryRtoReceipt
    volume_complete_loss_confirmed: Literal[True]
    partial_restore_cleaned: Literal[True]
    cleanup_complete: Literal[True]
    receipt_sha256: Sha256Digest

    @model_validator(mode="after")
    def _require_internal_identity(self) -> Self:
        if len(set(self.image_subjects_before)) != len(self.image_subjects_before):
            message = "recovery image subjects must be unique"
            raise ValueError(message)
        if self.image_subjects_before != self.image_subjects_after:
            message = "recovery image subjects drifted"
            raise ValueError(message)
        if self.candidate_config_before_sha256 != self.candidate_config_after_sha256:
            message = "candidate configuration drifted"
            raise ValueError(message)
        if len(set(self.required_probe_ids)) != len(self.required_probe_ids):
            message = "required recovery probes must be unique"
            raise ValueError(message)
        if self.required_probe_ids != self.observed_probe_ids:
            message = "observed recovery probes drifted"
            raise ValueError(message)
        return self


class RecoveryDiagnosticResult(StrictModel):
    """Fail-closed result that cannot stand in for protected recovery proof."""

    schema_version: Literal[1]
    schema_id: Literal["recovery-diagnostic-result.v1"]
    verifier: Literal["private-recovery"]
    gate_id: Literal["private-full.recovery-proof"]
    command_id: Literal["container.private-full-recovery.v2"]
    candidate_id: CandidateId
    candidate_tree: GitIdentity
    image_subjects: tuple[ImageDigest, ...]
    recovery_policy_sha256: Sha256Digest
    receipt_sha256: Sha256Digest
    probe_ids: tuple[ProbeId, ...]
    measured_rto_milliseconds: StrictMilliseconds
    authority_status: Literal["external_authority_required"]
    release_authoritative: Literal[False]
    protected_proof_accepted: Literal[False]
    release_ready: Literal[False]
    terminal_verdict: Literal["do_not_release"]


def _reject_duplicate_names(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            message = "duplicate recovery receipt name"
            raise ValueError(message)
        value[name] = item
    return value


def _reject_noninteger_number(value: str) -> NoReturn:
    message = f"unsupported recovery receipt number: {value}"
    raise ValueError(message)


def _bounded_json_integer(value: str) -> int:
    parsed = int(value, 10)
    if not -(2**63) <= parsed <= (2**63) - 1:
        message = "recovery receipt integer is out of range"
        raise ValueError(message)
    return parsed


def _require_canonical_receipt(parsed: object, raw: bytes) -> None:
    if type(parsed) is not dict:
        message = "recovery receipt is not canonical"
        raise ValueError(message)
    parsed_object = cast("dict[str, object]", parsed)
    if canonical_json_bytes(parsed_object) != raw:
        message = "recovery receipt is not canonical"
        raise ValueError(message)


def _require_receipt_digest(receipt: RecoveryExecutionReceipt) -> None:
    unsigned = cast(
        "dict[str, object]",
        receipt.model_dump(mode="json", exclude={"receipt_sha256"}),
    )
    expected_digest = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    )
    if not hmac.compare_digest(receipt.receipt_sha256, expected_digest):
        message = "recovery receipt digest does not match"
        raise ValueError(message)


def _parse_recovery_receipt(raw: bytes) -> RecoveryExecutionReceipt:
    """Require canonical duplicate-free integer-only JSON and a self digest."""
    try:
        parsed = cast(
            "object",
            json.loads(
                raw.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_names,
                parse_constant=_reject_noninteger_number,
                parse_float=_reject_noninteger_number,
                parse_int=_bounded_json_integer,
            ),
        )
        _require_canonical_receipt(parsed, raw)
        receipt = RecoveryExecutionReceipt.model_validate_json(raw, strict=True)
        _require_receipt_digest(receipt)
    except (
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise VerificationError(_ERR_RECEIPT) from exc
    return receipt


def _validated_policy(policy: PrivateRecoveryPolicy) -> PrivateRecoveryPolicy:
    if type(policy) is not PrivateRecoveryPolicy:
        raise VerificationError(_ERR_RECEIPT)
    try:
        payload = cast("dict[str, object]", policy.model_dump(mode="json"))
        raw = canonical_json_bytes(payload)
        return PrivateRecoveryPolicy.model_validate_json(raw, strict=True)
    except (TypeError, ValueError, ValidationError) as exc:
        raise VerificationError(_ERR_RECEIPT) from exc


def _bind_receipt(
    receipt: RecoveryExecutionReceipt,
    *,
    request: VerificationRequest,
    recovery_policy: PrivateRecoveryPolicy,
) -> None:
    """Bind every diagnostic observation to trusted request and policy input."""
    source = cast("UniqueSourcePdfSubject", recovery_policy.subjects[0])
    derived = cast("DerivedRenderSubject", recovery_policy.subjects[1])
    filesystem = recovery_policy.filesystem_expectations
    state_ids = tuple(item.state_id for item in recovery_policy.state_inventory)
    objective_milliseconds = recovery_policy.rto.objective_seconds * 1000
    observed_subject_binding: tuple[object, ...] = (
        receipt.subjects.source_subject_id,
        receipt.subjects.source_recovery_strategy,
        receipt.subjects.derived_subject_id,
        receipt.subjects.derived_recovery_strategy,
    )
    expected_subject_binding: tuple[object, ...] = (
        source.subject_id,
        source.recovery_strategy,
        derived.subject_id,
        derived.recovery_strategy,
    )
    if (
        receipt.candidate_id != request.candidate_id
        or receipt.candidate_tree != request.candidate_tree
        or receipt.image_subjects_before != request.image_subjects
        or receipt.image_subjects_after != request.image_subjects
        or receipt.recovery_policy_sha256 != recovery_policy.policy_digest
        or receipt.required_probe_ids != PROBES
        or receipt.observed_probe_ids != PROBES
        or observed_subject_binding != expected_subject_binding
        or receipt.filesystem.owner_uid != filesystem.owner_uid
        or receipt.filesystem.owner_gid != filesystem.owner_gid
        or receipt.filesystem.directory_mode != filesystem.directory_mode
        or receipt.filesystem.regular_file_mode != filesystem.regular_file_mode
        or receipt.filesystem.symlinks_observed is not filesystem.symlinks_permitted
        or receipt.filesystem.hardlinks_observed is not filesystem.hardlinks_permitted
        or receipt.state.state_ids != state_ids
        or receipt.rto.objective_milliseconds != objective_milliseconds
        or receipt.rto.clock != recovery_policy.rto.clock
    ):
        raise VerificationError(_ERR_RECEIPT)


def verify(
    request: VerificationRequest,
    *,
    binding: ControllerBinding,
    recovery_policy: PrivateRecoveryPolicy,
) -> RecoveryDiagnosticResult:
    """Run an injected synthetic diagnostic and retain a do-not-release verdict."""
    policy = _validated_policy(recovery_policy)
    outcomes = run_verified_probes(
        request,
        policy=controller_policy("private-recovery", PROBES, binding),
        executor=binding.executor,
        max_output_bytes=_MAX_RECEIPT_BYTES,
    )
    if (
        not outcomes
        or any(outcome.stderr for outcome in outcomes)
        or any(outcome.stdout for outcome in outcomes[:-1])
        or not outcomes[-1].stdout
    ):
        raise VerificationError(_ERR_RECEIPT)
    receipt = _parse_recovery_receipt(outcomes[-1].stdout)
    _bind_receipt(receipt, request=request, recovery_policy=policy)
    result = RecoveryDiagnosticResult(
        schema_version=1,
        schema_id="recovery-diagnostic-result.v1",
        verifier="private-recovery",
        gate_id="private-full.recovery-proof",
        command_id="container.private-full-recovery.v2",
        candidate_id=request.candidate_id,
        candidate_tree=request.candidate_tree,
        image_subjects=request.image_subjects,
        recovery_policy_sha256=policy.policy_digest,
        receipt_sha256=receipt.receipt_sha256,
        probe_ids=PROBES,
        measured_rto_milliseconds=receipt.rto.measured_milliseconds,
        authority_status="external_authority_required",
        release_authoritative=False,
        protected_proof_accepted=False,
        release_ready=False,
        terminal_verdict="do_not_release",
    )
    write_verification_result(binding.proof_path, result)
    return result
