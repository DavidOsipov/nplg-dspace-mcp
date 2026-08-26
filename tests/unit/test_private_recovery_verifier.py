# Copyright (c) 2026 David Osipov
"""Adversarial tests for the candidate-side private recovery verifier."""

from __future__ import annotations

import hashlib
import json
import stat
from copy import deepcopy
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from scripts import verify_private_recovery as subject
from scripts.baseline_capture_io import canonical_json_bytes
from scripts.private_recovery_contract import (
    PrivateRecoveryPolicy,
    load_private_recovery_policy,
)

if TYPE_CHECKING:
    from nplg_mcp.json_types import JsonObject, JsonValue
from scripts.verification_envelope import (
    ArgvExecutor,
    CommandOutcome,
    ControllerBinding,
    ProbePlan,
    VerificationError,
    VerificationRequest,
)

PROJECT_ROOT = Path(__file__).parents[2]
POLICY_PATH = PROJECT_ROOT / "security/private-recovery-policy.json"
_CANDIDATE_ID = "phase4-recovery-candidate-0001"
_TREE = "a" * 40
_IMAGE = "registry.example/nplg-private@sha256:" + "b" * 64
_OTHER_IMAGE = "registry.example/nplg-private@sha256:" + "c" * 64
_DIGESTS = tuple("sha256:" + character * 64 for character in "def0123456789")
_RTO_OBJECTIVE_MILLISECONDS = 900_000
_PRIVATE_FILE_MODE = 0o600
_MUTATION_ASSIGNMENTS: dict[str, tuple[str, str, JsonValue]] = {
    "source-restore": ("subjects", "source_after_sha256", _DIGESTS[10]),
    "derived-regeneration": ("subjects", "derived_after_sha256", _DIGESTS[10]),
    "policy-digest": ("receipt", "recovery_policy_sha256", _DIGESTS[10]),
    "rto-over": (
        "rto",
        "measured_milliseconds",
        _RTO_OBJECTIVE_MILLISECONDS + 1,
    ),
    "rto-unmeasured": ("rto", "measured_milliseconds", None),
    "rto-coerced": ("rto", "measured_milliseconds", "1"),
    "clock-high-water": (
        "state",
        "clock_high_water_after_sha256",
        _DIGESTS[10],
    ),
    "insertion-high-water": (
        "state",
        "insertion_high_water_after_sha256",
        _DIGESTS[10],
    ),
    "orphan-staging": ("state", "orphan_staging_entries_after", 1),
    "invented-process-persistence": ("state", "process_state_persisted", True),
    "lease-not-reconciled": (
        "state",
        "active_leases_after_worker_termination",
        1,
    ),
    "staging-reservation-not-reconciled": (
        "state",
        "staging_reservations_after_worker_termination",
        1,
    ),
    "publication-reservation-not-reconciled": (
        "state",
        "publication_reservations_after_worker_termination",
        1,
    ),
    "reserved-bytes-not-reconciled": (
        "state",
        "reserved_bytes_after_reconstruction",
        1,
    ),
    "clock-anomaly-open": ("state", "clock_anomaly_new_ingest_closed", False),
    "corrupt-state-open": ("state", "corrupt_state_new_ingest_closed", False),
    "owner": ("filesystem", "owner_uid", 0),
    "directory-mode": ("filesystem", "directory_mode", "0755"),
    "regular-mode": ("filesystem", "regular_file_mode", "0644"),
    "symlink": ("filesystem", "symlinks_observed", True),
    "image-drift": ("receipt", "image_subjects_after", [_OTHER_IMAGE]),
    "config-drift": (
        "receipt",
        "candidate_config_after_sha256",
        _DIGESTS[10],
    ),
    "incomplete-loss": ("receipt", "volume_complete_loss_confirmed", False),
    "partial-restore": ("receipt", "partial_restore_cleaned", False),
    "cleanup": ("receipt", "cleanup_complete", False),
    "invented-authority": ("receipt", "release_authoritative", True),
    "extra-field": ("receipt", "candidate_claimed_restore", True),
}


def _commands() -> tuple[tuple[str, ...], ...]:
    return tuple(("controller-recovery-probe", name) for name in subject.PROBES)


def _request(commands: tuple[tuple[str, ...], ...]) -> VerificationRequest:
    return VerificationRequest(
        version=1,
        verifier="private-recovery",
        candidate_id=_CANDIDATE_ID,
        candidate_tree=_TREE,
        image_subjects=(_IMAGE,),
        probes=tuple(
            ProbePlan(probe_id=name, argv=argv)
            for name, argv in zip(subject.PROBES, commands, strict=True)
        ),
    )


def _policy() -> PrivateRecoveryPolicy:
    return load_private_recovery_policy(POLICY_PATH)


def _receipt(policy: PrivateRecoveryPolicy) -> JsonObject:
    state_ids: list[JsonValue] = [item.state_id for item in policy.state_inventory]
    value: JsonObject = {
        "schema_version": 1,
        "schema_id": "recovery-diagnostic-receipt.v1",
        "gate_id": "private-full.recovery-proof",
        "command_id": "container.private-full-recovery.v2",
        "scope": "controller-created-synthetic-disposable-volumes-only",
        "release_authoritative": False,
        "candidate_id": _CANDIDATE_ID,
        "candidate_tree": _TREE,
        "image_subjects_before": [_IMAGE],
        "image_subjects_after": [_IMAGE],
        "candidate_config_before_sha256": _DIGESTS[0],
        "candidate_config_after_sha256": _DIGESTS[0],
        "recovery_policy_sha256": policy.policy_digest,
        "required_probe_ids": list(subject.PROBES),
        "observed_probe_ids": list(subject.PROBES),
        "subjects": {
            "source_subject_id": "source-pdfs",
            "source_recovery_strategy": "immutable-backup-and-restore",
            "source_before_sha256": _DIGESTS[1],
            "source_backup_sha256": _DIGESTS[1],
            "source_after_sha256": _DIGESTS[1],
            "derived_subject_id": "derived-renders",
            "derived_recovery_strategy": "bounded-cold-regeneration",
            "regeneration_recipe_sha256": _DIGESTS[2],
            "derived_expected_sha256": _DIGESTS[3],
            "derived_after_sha256": _DIGESTS[3],
        },
        "filesystem": {
            "owner_uid": 10001,
            "owner_gid": 10001,
            "directory_mode": "0700",
            "regular_file_mode": "0600",
            "symlinks_observed": False,
            "hardlinks_observed": False,
            "content_sha256": _DIGESTS[4],
            "ownership_sha256": _DIGESTS[5],
            "mode_sha256": _DIGESTS[6],
        },
        "state": {
            "state_ids": state_ids,
            "clock_high_water_before_sha256": _DIGESTS[7],
            "clock_high_water_after_sha256": _DIGESTS[7],
            "insertion_high_water_before_sha256": _DIGESTS[8],
            "insertion_high_water_after_sha256": _DIGESTS[8],
            "insertion_sequence_reconciliation_sha256": _DIGESTS[9],
            "orphan_staging_entries_after": 0,
            "process_state_persisted": False,
            "active_leases_before_worker_termination": 1,
            "active_leases_after_worker_termination": 0,
            "staging_reservations_before_worker_termination": 1,
            "staging_reservations_after_worker_termination": 0,
            "publication_reservations_before_worker_termination": 1,
            "publication_reservations_after_worker_termination": 0,
            "reserved_bytes_after_reconstruction": 0,
            "reserved_objects_after_reconstruction": 0,
            "reserved_inodes_after_reconstruction": 0,
            "clock_anomaly_new_ingest_closed": True,
            "corrupt_state_new_ingest_closed": True,
            "restart_reconstruction_semantics": (
                "start-ledgers-empty-after-staging-cleanup-and-committed-object-scan"
            ),
        },
        "rto": {
            "objective_milliseconds": _RTO_OBJECTIVE_MILLISECONDS,
            "measured_milliseconds": _RTO_OBJECTIVE_MILLISECONDS - 1,
            "clock": "protected-controller-monotonic",
            "within_objective": True,
        },
        "volume_complete_loss_confirmed": True,
        "partial_restore_cleaned": True,
        "cleanup_complete": True,
        "receipt_sha256": "sha256:" + "0" * 64,
    }
    _redigest(value)
    return value


def _redigest(receipt: JsonObject) -> None:
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    )


def _receipt_bytes(receipt: JsonObject) -> bytes:
    return canonical_json_bytes(receipt)


def _binding(
    *,
    commands: tuple[tuple[str, ...], ...],
    executor: ArgvExecutor,
    proof_path: Path,
) -> ControllerBinding:
    return ControllerBinding(
        candidate_id=_CANDIDATE_ID,
        candidate_tree=_TREE,
        image_subjects=(_IMAGE,),
        commands=commands,
        executor=executor,
        proof_path=proof_path,
    )


def _executor(
    commands: tuple[tuple[str, ...], ...],
    receipt_raw: bytes,
    *,
    observed: list[tuple[str, ...]] | None = None,
    final_stderr: bytes = b"",
) -> ArgvExecutor:
    def execute(argv: tuple[str, ...]) -> CommandOutcome:
        if observed is not None:
            observed.append(argv)
        return CommandOutcome(
            argv=argv,
            returncode=0,
            timed_out=False,
            stdout=receipt_raw if argv == commands[-1] else b"",
            stderr=final_stderr if argv == commands[-1] else b"",
        )

    return execute


def test_recovery_schedule_covers_state_integrity_and_rto() -> None:
    assert subject.PROBES == (
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


def test_recovery_verifier_accepts_only_a_non_authoritative_bound_diagnostic(
    tmp_path: Path,
) -> None:
    """A complete fake receipt remains do-not-release without protected evidence."""
    policy = _policy()
    commands = _commands()
    observed: list[tuple[str, ...]] = []
    proof_path = tmp_path / "proof.json"

    result = subject.verify(
        _request(commands),
        binding=_binding(
            commands=commands,
            executor=_executor(
                commands,
                _receipt_bytes(_receipt(policy)),
                observed=observed,
            ),
            proof_path=proof_path,
        ),
        recovery_policy=policy,
    )

    assert observed == list(commands)
    assert result.authority_status == "external_authority_required"
    assert result.release_authoritative is False
    assert result.protected_proof_accepted is False
    assert result.release_ready is False
    assert result.terminal_verdict == "do_not_release"
    assert result.recovery_policy_sha256 == policy.policy_digest
    assert result.probe_ids == subject.PROBES
    assert stat.S_IMODE(proof_path.stat().st_mode) == _PRIVATE_FILE_MODE
    persisted = cast(
        "JsonObject",
        json.loads(proof_path.read_text(encoding="utf-8")),
    )
    assert persisted["terminal_verdict"] == "do_not_release"
    assert persisted["release_authoritative"] is False


def _mutate_receipt(receipt: JsonObject, mutation: str) -> bool:
    subjects = cast("JsonObject", receipt["subjects"])
    filesystem = cast("JsonObject", receipt["filesystem"])
    state = cast("JsonObject", receipt["state"])
    rto = cast("JsonObject", receipt["rto"])
    if mutation == "duplicate-image":
        receipt["image_subjects_before"] = [_IMAGE, _IMAGE]
        receipt["image_subjects_after"] = [_IMAGE, _IMAGE]
    elif mutation == "duplicate-required-probe":
        probes = cast("list[JsonValue]", receipt["required_probe_ids"])
        probes[-1] = probes[0]
        receipt["observed_probe_ids"] = list(probes)
    elif mutation == "probe-order":
        cast("list[JsonValue]", receipt["observed_probe_ids"]).reverse()
    elif mutation == "state-missing":
        _ = cast("list[JsonValue]", state["state_ids"]).pop()
    elif mutation == "state-order":
        cast("list[JsonValue]", state["state_ids"]).reverse()
    elif mutation == "receipt-digest":
        receipt["receipt_sha256"] = _DIGESTS[10]
        return False
    else:
        targets = {
            "receipt": receipt,
            "subjects": subjects,
            "filesystem": filesystem,
            "state": state,
            "rto": rto,
        }
        target_name, field_name, value = _MUTATION_ASSIGNMENTS[mutation]
        targets[target_name][field_name] = value
    return True


@pytest.mark.parametrize(
    "mutation",
    [
        "source-restore",
        "derived-regeneration",
        "policy-digest",
        "rto-over",
        "rto-unmeasured",
        "rto-coerced",
        "duplicate-image",
        "duplicate-required-probe",
        "probe-order",
        "state-missing",
        "state-order",
        "clock-high-water",
        "insertion-high-water",
        "orphan-staging",
        "invented-process-persistence",
        "lease-not-reconciled",
        "staging-reservation-not-reconciled",
        "publication-reservation-not-reconciled",
        "reserved-bytes-not-reconciled",
        "clock-anomaly-open",
        "corrupt-state-open",
        "owner",
        "directory-mode",
        "regular-mode",
        "symlink",
        "image-drift",
        "config-drift",
        "incomplete-loss",
        "partial-restore",
        "cleanup",
        "invented-authority",
        "extra-field",
        "receipt-digest",
    ],
)
def test_recovery_verifier_rejects_restore_rto_and_reconstruction_receipt_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    """A redigested semantic lie cannot become a recovery diagnostic success."""
    policy = _policy()
    receipt = deepcopy(_receipt(policy))
    if _mutate_receipt(receipt, mutation):
        _redigest(receipt)
    commands = _commands()
    proof_path = tmp_path / "proof.json"

    with pytest.raises(VerificationError, match="recovery receipt rejected"):
        _ = subject.verify(
            _request(commands),
            binding=_binding(
                commands=commands,
                executor=_executor(commands, _receipt_bytes(receipt)),
                proof_path=proof_path,
            ),
            recovery_policy=policy,
        )

    assert not proof_path.exists()


@pytest.mark.parametrize(
    "raw_mutation",
    ["duplicate", "noncanonical", "float", "integer-overflow", "nonobject"],
)
def test_recovery_verifier_rejects_ambiguous_receipt_json(
    tmp_path: Path,
    raw_mutation: str,
) -> None:
    policy = _policy()
    raw = _receipt_bytes(_receipt(policy))
    if raw_mutation == "duplicate":
        raw = raw.replace(
            b'"schema_version":1',
            b'"schema_version":1,"schema_version":1',
            1,
        )
    elif raw_mutation == "noncanonical":
        raw += b" "
    elif raw_mutation == "float":
        raw = raw.replace(
            b'"objective_milliseconds":900000',
            b'"objective_milliseconds":900000.0',
            1,
        )
    elif raw_mutation == "integer-overflow":
        raw = raw.replace(
            b'"schema_version":1',
            b'"schema_version":9223372036854775808',
            1,
        )
    else:
        raw = b"[]"
    commands = _commands()

    with pytest.raises(VerificationError, match="recovery receipt rejected"):
        _ = subject.verify(
            _request(commands),
            binding=_binding(
                commands=commands,
                executor=_executor(commands, raw),
                proof_path=tmp_path / "proof.json",
            ),
            recovery_policy=policy,
        )


@pytest.mark.parametrize("defect", ["wrong-type", "invalid-instance"])
def test_recovery_verifier_revalidates_the_trusted_policy_before_execution(
    tmp_path: Path,
    defect: str,
) -> None:
    policy = _policy()
    if defect == "wrong-type":
        supplied = cast("PrivateRecoveryPolicy", object())
    else:
        object.__setattr__(policy, "policy_digest", _DIGESTS[10])
        supplied = policy
    commands = _commands()
    observed: list[tuple[str, ...]] = []

    with pytest.raises(VerificationError, match="recovery receipt rejected"):
        _ = subject.verify(
            _request(commands),
            binding=_binding(
                commands=commands,
                executor=_executor(
                    commands,
                    _receipt_bytes(_receipt(policy)),
                    observed=observed,
                ),
                proof_path=tmp_path / "proof.json",
            ),
            recovery_policy=supplied,
        )

    assert observed == []


def test_recovery_verifier_rejects_schedule_and_privileged_command_drift(
    tmp_path: Path,
) -> None:
    policy = _policy()
    commands = _commands()
    receipt_raw = _receipt_bytes(_receipt(policy))
    observed: list[tuple[str, ...]] = []

    with pytest.raises(VerificationError):
        _ = subject.verify(
            _request(tuple(reversed(commands))),
            binding=_binding(
                commands=commands,
                executor=_executor(commands, receipt_raw, observed=observed),
                proof_path=tmp_path / "reordered" / "proof.json",
            ),
            recovery_policy=policy,
        )
    assert observed == []

    with pytest.raises(VerificationError):
        _ = subject.verify(
            _request(commands),
            binding=_binding(
                commands=commands[:-1],
                executor=_executor(commands, receipt_raw, observed=observed),
                proof_path=tmp_path / "missing" / "proof.json",
            ),
            recovery_policy=policy,
        )
    assert observed == []

    create_commands = (("controller-recovery-probe", "create"), *commands[1:])
    with pytest.raises(VerificationError):
        _ = subject.verify(
            _request(create_commands),
            binding=_binding(
                commands=create_commands,
                executor=_executor(create_commands, receipt_raw, observed=observed),
                proof_path=tmp_path / "create" / "proof.json",
            ),
            recovery_policy=policy,
        )
    assert observed == []


@pytest.mark.parametrize("defect", ["nonzero", "timeout", "secret", "stderr"])
def test_recovery_verifier_rejects_unsafe_executor_outcomes(
    tmp_path: Path,
    defect: str,
) -> None:
    policy = _policy()
    commands = _commands()
    receipt_raw = _receipt_bytes(_receipt(policy))

    def executor(argv: tuple[str, ...]) -> CommandOutcome:
        final = argv == commands[-1]
        return CommandOutcome(
            argv=argv,
            returncode=1 if defect == "nonzero" and final else 0,
            timed_out=defect == "timeout" and final,
            stdout=(
                b"NPLG_SECRET_CANARY"
                if defect == "secret" and final
                else receipt_raw
                if final
                else b""
            ),
            stderr=b"unexpected" if defect == "stderr" and final else b"",
        )

    with pytest.raises(VerificationError):
        _ = subject.verify(
            _request(commands),
            binding=_binding(
                commands=commands,
                executor=executor,
                proof_path=tmp_path / "proof.json",
            ),
            recovery_policy=policy,
        )

    assert not (tmp_path / "proof.json").exists()
