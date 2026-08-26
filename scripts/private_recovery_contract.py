# Copyright (c) 2026 David Osipov
"""Strict candidate-side contract for private-full recovery policy."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal, NoReturn, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from scripts.baseline_capture_io import (
    BaselineCaptureError,
    canonical_json_bytes,
    read_regular_bytes,
)

type PolicyId = Literal["nplg.private-full.artifact-recovery.v1"]
type SubjectId = Literal["source-pdfs", "derived-renders"]
type CanonicalRelativePath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512, strict=True),
]
type Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$", strict=True),
]
type ExactZero = Annotated[int, Field(strict=True, ge=0, le=0)]
type PrivateRuntimeId = Annotated[int, Field(strict=True, ge=10_001, le=10_001)]

# Keep this candidate-side raw-policy ceiling identical to the independent Zod oracle.
MAX_RAW_POLICY_BYTES: Final = 65_536
_MIN_VISIBLE_ASCII_CODE_POINT = 0x21
_MAX_VISIBLE_ASCII_CODE_POINT = 0x7E


class RecoveryPolicyError(ValueError):
    """Raised when candidate recovery policy data is not trustworthy."""


class _StrictModel(BaseModel):
    """Closed, immutable, non-coercing recovery-policy boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RecoveryTimeObjective(_StrictModel):
    """Objective for the protected destructive recovery exercise."""

    objective_seconds: Literal[900]
    clock: Literal["protected-controller-monotonic"]
    starts_at: Literal["synthetic-volume-loss-confirmed"]
    ends_at: Literal["recovery-integrity-verified"]
    over_objective_action: Literal["block_release"]

    @field_validator("objective_seconds", mode="before")
    @classmethod
    def _require_json_integer(cls, value: object) -> object:
        if type(value) is not int:
            message = "recovery RTO objective must be a JSON integer"
            raise ValueError(message)
        return value


class UniqueSourcePdfSubject(_StrictModel):
    """Unique source PDFs that require immutable backup and restore proof."""

    subject_id: Literal["source-pdfs"]
    namespace: Literal["documents"]
    classification: Literal["unique"]
    recovery_strategy: Literal["immutable-backup-and-restore"]
    backup_required: Literal[True]
    cold_regeneration_permitted: Literal[False]
    identity_check: Literal["sha256-content-address"]
    required_proof: Literal["protected-immutable-backup-restore"]


class DerivedRenderSubject(_StrictModel):
    """Derived render trees that must be reproducible from restored sources."""

    subject_id: Literal["derived-renders"]
    namespace: Literal["renders"]
    classification: Literal["derived"]
    recovery_strategy: Literal["bounded-cold-regeneration"]
    backup_required: Literal[False]
    cold_regeneration_required: Literal[True]
    source_subject_id: Literal["source-pdfs"]
    regeneration_recipe_paths: Annotated[
        tuple[CanonicalRelativePath, ...],
        Field(min_length=1, max_length=8),
    ]
    identity_check: Literal["sha256-manifest-and-assets"]
    required_proof: Literal["protected-bounded-cold-regeneration"]

    @field_validator("regeneration_recipe_paths")
    @classmethod
    def _canonical_repository_paths(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            message = "recovery recipe paths must be unique"
            raise ValueError(message)
        for item in value:
            path = PurePosixPath(item)
            if (
                "\\" in item
                or "\x00" in item
                or any(
                    not _MIN_VISIBLE_ASCII_CODE_POINT
                    <= ord(character)
                    <= _MAX_VISIBLE_ASCII_CODE_POINT
                    for character in item
                )
                or path.is_absolute()
                or path.as_posix() != item
                or not path.parts
                or path.parts[0] != "src"
                or any(part in {"", ".", ".."} for part in path.parts)
                or path.suffix != ".py"
            ):
                message = (
                    "recovery recipe path must be canonical and repository-relative"
                )
                raise ValueError(message)
        return value


type RecoverySubject = Annotated[
    UniqueSourcePdfSubject | DerivedRenderSubject,
    Field(discriminator="classification"),
]


class PrivateFilesystemExpectations(_StrictModel):
    """Exact private-full ownership and modes expected by protected recovery."""

    owner_uid: PrivateRuntimeId
    owner_gid: PrivateRuntimeId
    directory_mode: Literal["0700"]
    regular_file_mode: Literal["0600"]
    symlinks_permitted: Literal[False]
    hardlinks_permitted: Literal[False]
    applies_to: tuple[
        Literal["subjects"],
        Literal["lifecycle-state"],
        Literal["staging-reconstruction"],
    ]


class ClockHighWaterState(_StrictModel):
    """Restart-stable clock record that safely re-baselines without backup claims."""

    state_id: Literal["clock-high-water-and-boot-state"]
    classification: Literal["reconstructible-safety-state"]
    persistence: Literal["fsynced-private-record"]
    location: Literal[".retention-clock-high-water.json"]
    schema_version: Literal["1.0"]
    identity_check: Literal["record-digest-and-boot-id"]
    recovery_strategy: Literal["fail-closed-baseline-then-healthy-window"]
    missing_or_corrupt_semantics: Literal[
        "rewrite-untrusted-baseline-and-close-age-deletion-and-new-ingest"
    ]
    post_termination_semantics: Literal[
        "persisted-record-revalidated-against-current-boot"
    ]
    backup_required: Literal[False]
    required_proof: Literal["protected-high-water-recovery-and-clock-anomaly-closure"]


class InsertionHighWaterState(_StrictModel):
    """Unique monotonic allocator state that must be restored when records exist."""

    state_id: Literal["insertion-high-water"]
    classification: Literal["unique-ordering-state"]
    persistence: Literal["fsynced-private-record"]
    location: Literal[".lifecycle-insertion-high-water.json"]
    schema_version: Literal["1.0"]
    identity_check: Literal["record-digest"]
    recovery_strategy: Literal["restore-or-initialize-only-without-sequence-records"]
    missing_or_corrupt_semantics: Literal[
        "reject-when-sequence-records-exist-otherwise-initialize-at-one"
    ]
    post_termination_semantics: Literal["load-before-per-object-reconciliation"]
    backup_required: Literal[True]
    required_proof: Literal["protected-insertion-high-water-restore"]


class PerObjectInsertionSequenceState(_StrictModel):
    """Digest-bound object order records reconstructed only from valid high-water."""

    state_id: Literal["per-object-insertion-sequence-records"]
    classification: Literal["reconstructible-object-ordering-state"]
    persistence: Literal["fsynced-per-object-private-record"]
    location_patterns: tuple[
        Literal["documents/*/.lifecycle-insertion-sequence.json"],
        Literal["renders/*/.lifecycle-insertion-sequence.json"],
    ]
    schema_version: Literal["1.0"]
    identity_check: Literal["record-digest-object-key-and-high-water-bound"]
    recovery_strategy: Literal[
        "validate-existing-or-allocate-from-persisted-high-water"
    ]
    missing_or_corrupt_semantics: Literal[
        "allocate-missing-from-high-water-and-reject-invalid-or-duplicate"
    ]
    post_termination_semantics: Literal[
        "validate-every-record-and-bind-below-high-water"
    ]
    backup_required: Literal[False]
    required_proof: Literal["protected-insertion-sequence-reconciliation"]


class OrphanStagingState(_StrictModel):
    """Non-authoritative staging state that is discarded before accounting."""

    state_id: Literal["orphan-staging-cleanup"]
    classification: Literal["ephemeral-transaction-state"]
    persistence: Literal["uncommitted-filesystem-state"]
    location: Literal[".staging"]
    identity_check: Literal["not-authoritative"]
    recovery_strategy: Literal["delete-entire-inventory-before-accounting"]
    missing_or_corrupt_semantics: Literal[
        "absence-is-valid-and-every-entry-is-discarded"
    ]
    post_termination_semantics: Literal["empty-before-committed-object-scan"]
    backup_required: Literal[False]
    expected_post_reconstruction_entries: ExactZero
    required_proof: Literal["protected-partial-restore-cleanup"]


class PostProcessLeaseReservationState(_StrictModel):
    """Process-only ledgers that must never be represented as persisted state."""

    state_id: Literal["post-process-lease-reservation-reconciliation"]
    classification: Literal["process-local-ephemeral-state"]
    persistence: Literal["never-persisted"]
    components: tuple[
        Literal["asset-leases"],
        Literal["staging-byte-reservations"],
        Literal["publication-reservations"],
        Literal["publication-reserved-bytes"],
        Literal["publication-reserved-objects"],
        Literal["publication-reserved-inodes"],
    ]
    identity_check: Literal["exact-empty-ledgers-and-recomputed-committed-usage"]
    recovery_strategy: Literal[
        "release-or-abort-on-worker-exit-then-reconstruct-empty-on-restart"
    ]
    post_termination_semantics: Literal[
        "dead-process-leases-and-reservations-are-not-restored"
    ]
    worker_termination_semantics: Literal[
        "release-or-abort-worker-owned-leases-and-reservations"
    ]
    restart_reconstruction_semantics: Literal[
        "start-ledgers-empty-after-staging-cleanup-and-committed-object-scan"
    ]
    committed_usage_reconciliation: Literal[
        "rescan-documents-and-renders-excluding-sequence-records"
    ]
    backup_required: Literal[False]
    expected_active_leases: ExactZero
    expected_staging_reservations: ExactZero
    expected_publication_reservations: ExactZero
    expected_reserved_bytes: ExactZero
    expected_reserved_objects: ExactZero
    expected_reserved_inodes: ExactZero
    required_proof: Literal["protected-empty-lease-reservation-reconciliation"]


class UnprovenRecoveryEvidence(_StrictModel):
    """Candidate-visible state while protected recovery evidence is absent."""

    status: Literal["external_authority_required"]
    gate_id: Literal["private-full.recovery-proof"]
    command_id: Literal["container.private-full-recovery.v2"]
    signed_proof_schema: Literal["recovery-proof.v2"]
    candidate_generated: Literal[False]
    measured_rto_seconds: None
    source_backup_restore_proof_sha256: None
    derived_regeneration_proof_sha256: None
    state_reconstruction_proof_sha256: None
    controller_receipt_sha256: None
    blockers: tuple[
        Literal["UNIQUE_SOURCE_BACKUP_RESTORE_PROOF_REQUIRED"],
        Literal["DERIVED_RENDER_REGENERATION_PROOF_REQUIRED"],
        Literal["PERSISTENT_STATE_RECONSTRUCTION_PROOF_REQUIRED"],
        Literal["MEASURED_RTO_PROOF_REQUIRED"],
        Literal["PROTECTED_RECOVERY_AUTHORITY_REQUIRED"],
    ]


class PrivateRecoveryPolicy(_StrictModel):
    """Closed candidate policy that deliberately cannot assert recovery success."""

    schema_version: Literal[1]
    policy_id: PolicyId
    profile: Literal["private-full"]
    owner: Literal["NPLG private storage operator"]
    rto: RecoveryTimeObjective
    subjects: Annotated[
        tuple[RecoverySubject, ...],
        Field(min_length=2, max_length=2),
    ]
    filesystem_expectations: PrivateFilesystemExpectations
    state_inventory: tuple[
        ClockHighWaterState,
        InsertionHighWaterState,
        PerObjectInsertionSequenceState,
        OrphanStagingState,
        PostProcessLeaseReservationState,
    ]
    evidence: UnprovenRecoveryEvidence
    terminal_verdict: Literal["do_not_release"]
    release_ready: Literal[False]
    policy_digest: Sha256Digest

    @model_validator(mode="after")
    def _exact_subject_inventory(self) -> Self:
        if tuple(subject.subject_id for subject in self.subjects) != (
            "source-pdfs",
            "derived-renders",
        ):
            message = "recovery subject inventory must be exact and ordered"
            raise ValueError(message)
        payload = cast(
            "dict[str, object]",
            self.model_dump(mode="json", exclude={"policy_digest"}),
        )
        expected = "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        if not hmac.compare_digest(self.policy_digest, expected):
            message = "private recovery policy digest does not match its content"
            raise ValueError(message)
        return self


def _reject_duplicate_names(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            message = f"duplicate private-recovery JSON name: {name}"
            raise RecoveryPolicyError(message)
        value[name] = item
    return value


def _reject_noninteger_number(value: str) -> NoReturn:
    message = f"unsupported private-recovery JSON number: {value}"
    raise RecoveryPolicyError(message)


def _require_bounded_raw_policy(raw: bytes) -> bytes:
    if len(raw) > MAX_RAW_POLICY_BYTES:
        message = "private recovery policy exceeds the raw-byte limit"
        raise RecoveryPolicyError(message)
    return raw


def load_private_recovery_policy(path: Path) -> PrivateRecoveryPolicy:
    """Read at most 65,536 raw bytes and parse a strict fail-closed policy."""
    try:
        raw = _require_bounded_raw_policy(read_regular_bytes(path))
        parsed = cast(
            "object",
            json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_names,
                parse_constant=_reject_noninteger_number,
                parse_float=_reject_noninteger_number,
            ),
        )
    except (
        BaselineCaptureError,
        json.JSONDecodeError,
        OSError,
        RecoveryPolicyError,
        UnicodeError,
    ) as exc:
        message = "private recovery policy rejected"
        raise RecoveryPolicyError(message) from exc
    if type(parsed) is not dict:
        cause = TypeError("private recovery policy must be a JSON object")
        message = "private recovery policy rejected"
        raise RecoveryPolicyError(message) from cause
    try:
        return PrivateRecoveryPolicy.model_validate_json(raw, strict=True)
    except ValidationError as exc:
        message = "private recovery policy rejected"
        raise RecoveryPolicyError(message) from exc
