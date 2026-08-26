# Copyright (c) 2026 David Osipov
"""Strict private-full recovery policy contract tests."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from nplg_mcp.json_types import (
    JsonObject,
    JsonValue,
    load_json_value,
    require_json_object,
)
from scripts.private_recovery_contract import (
    MAX_RAW_POLICY_BYTES,
    RecoveryPolicyError,
    load_private_recovery_policy,
)

PROJECT_ROOT = Path(__file__).parents[2]
POLICY_PATH = PROJECT_ROOT / "security/private-recovery-policy.json"
EXPECTED_RTO_OBJECTIVE_SECONDS = 900
EXPECTED_STATE_IDS = (
    "clock-high-water-and-boot-state",
    "insertion-high-water",
    "per-object-insertion-sequence-records",
    "orphan-staging-cleanup",
    "post-process-lease-reservation-reconciliation",
)


def _policy_payload() -> JsonObject:
    return require_json_object(
        load_json_value(POLICY_PATH.read_bytes()),
        context="private recovery policy fixture",
    )


def _redigest(payload: JsonObject) -> None:
    unsigned = {key: value for key, value in payload.items() if key != "policy_digest"}
    canonical = (
        json.dumps(
            unsigned,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    payload["policy_digest"] = "sha256:" + hashlib.sha256(canonical).hexdigest()


def _write_policy(path: Path, payload: JsonObject) -> None:
    _ = path.write_text(
        json.dumps(payload, allow_nan=False, ensure_ascii=False),
        encoding="utf-8",
    )


def _state_inventory(payload: JsonObject) -> list[JsonObject]:
    return cast("list[JsonObject]", payload["state_inventory"])


def test_checked_in_recovery_policy_classifies_state_without_claiming_proof() -> None:
    """Mutation caught: unique state marked regenerable or local proof invented."""
    policy = load_private_recovery_policy(POLICY_PATH)

    unique, derived = policy.subjects
    assert (
        unique.subject_id,
        unique.classification,
        unique.recovery_strategy,
        unique.backup_required,
    ) == (
        "source-pdfs",
        "unique",
        "immutable-backup-and-restore",
        True,
    )
    assert (
        derived.subject_id,
        derived.classification,
        derived.recovery_strategy,
        derived.backup_required,
    ) == (
        "derived-renders",
        "derived",
        "bounded-cold-regeneration",
        False,
    )
    assert policy.rto.objective_seconds == EXPECTED_RTO_OBJECTIVE_SECONDS
    assert policy.evidence.status == "external_authority_required"
    assert policy.evidence.measured_rto_seconds is None
    assert policy.evidence.state_reconstruction_proof_sha256 is None
    assert policy.release_ready is False
    assert policy.terminal_verdict == "do_not_release"


def test_checked_in_recovery_policy_binds_exact_lifecycle_state_inventory() -> None:
    """Mutation caught: recovery omits or misstates persisted/rebuilt state."""
    policy = load_private_recovery_policy(POLICY_PATH)

    assert tuple(item.state_id for item in policy.state_inventory) == EXPECTED_STATE_IDS
    clock, high_water, sequences, staging, process_state = policy.state_inventory
    assert (
        clock.location,
        clock.recovery_strategy,
        clock.post_termination_semantics,
        clock.backup_required,
    ) == (
        ".retention-clock-high-water.json",
        "fail-closed-baseline-then-healthy-window",
        "persisted-record-revalidated-against-current-boot",
        False,
    )
    assert (
        high_water.location,
        high_water.recovery_strategy,
        high_water.backup_required,
    ) == (
        ".lifecycle-insertion-high-water.json",
        "restore-or-initialize-only-without-sequence-records",
        True,
    )
    assert (
        sequences.location_patterns,
        sequences.recovery_strategy,
        sequences.backup_required,
    ) == (
        (
            "documents/*/.lifecycle-insertion-sequence.json",
            "renders/*/.lifecycle-insertion-sequence.json",
        ),
        "validate-existing-or-allocate-from-persisted-high-water",
        False,
    )
    assert (
        staging.location,
        staging.recovery_strategy,
        staging.expected_post_reconstruction_entries,
    ) == (
        ".staging",
        "delete-entire-inventory-before-accounting",
        0,
    )
    assert process_state.persistence == "never-persisted"
    assert process_state.worker_termination_semantics == (
        "release-or-abort-worker-owned-leases-and-reservations"
    )
    assert process_state.restart_reconstruction_semantics == (
        "start-ledgers-empty-after-staging-cleanup-and-committed-object-scan"
    )
    assert (
        process_state.expected_active_leases,
        process_state.expected_staging_reservations,
        process_state.expected_publication_reservations,
        process_state.expected_reserved_bytes,
        process_state.expected_reserved_objects,
        process_state.expected_reserved_inodes,
    ) == (0, 0, 0, 0, 0, 0)


def test_checked_in_recovery_policy_binds_private_owner_and_modes() -> None:
    """Mutation caught: recovery accepts ownership or private-mode drift."""
    policy = load_private_recovery_policy(POLICY_PATH)

    assert (
        policy.filesystem_expectations.owner_uid,
        policy.filesystem_expectations.owner_gid,
        policy.filesystem_expectations.directory_mode,
        policy.filesystem_expectations.regular_file_mode,
        policy.filesystem_expectations.symlinks_permitted,
        policy.filesystem_expectations.hardlinks_permitted,
        policy.filesystem_expectations.applies_to,
    ) == (
        10001,
        10001,
        "0700",
        "0600",
        False,
        False,
        ("subjects", "lifecycle-state", "staging-reconstruction"),
    )


@pytest.mark.parametrize(
    "recipe_path",
    [
        "../src/nplg_mcp/pdf.py",
        "/src/nplg_mcp/pdf.py",
        "src/nplg_mcp/../secrets.py",
        "src\\nplg_mcp\\pdf.py",
        "src/nplg_mcp/pdf.py\x00ignored",
        "src//nplg_mcp/pdf.py",
        "src/nplg_mcp/récipe.py",
    ],
)
def test_recovery_policy_rejects_noncanonical_recipe_paths(
    tmp_path: Path,
    recipe_path: str,
) -> None:
    """Mutation caught: attacker-controlled recipe path escapes the repository."""
    payload = deepcopy(_policy_payload())
    subjects = cast("list[JsonObject]", payload["subjects"])
    subjects[1]["regeneration_recipe_paths"] = [recipe_path]
    _redigest(payload)
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_recipe_path_grammar_matches_zod(tmp_path: Path) -> None:
    """Differential case: printable path grammar excludes ASCII space."""
    payload = deepcopy(_policy_payload())
    subjects = cast("list[JsonObject]", payload["subjects"])
    subjects[1]["regeneration_recipe_paths"] = ["src/nplg_mcp/pdf recipe.py"]
    _redigest(payload)
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_rejects_duplicate_recipe_paths(tmp_path: Path) -> None:
    """Mutation caught: duplicate recipe paths weaken the bound source set."""
    payload = deepcopy(_policy_payload())
    subjects = cast("list[JsonObject]", payload["subjects"])
    recipe_paths = cast("list[str]", subjects[1]["regeneration_recipe_paths"])
    subjects[1]["regeneration_recipe_paths"] = [recipe_paths[0], recipe_paths[0]]
    _redigest(payload)
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_rejects_reordered_subjects(tmp_path: Path) -> None:
    """Mutation caught: subject order cannot change semantic identities."""
    payload = deepcopy(_policy_payload())
    subjects = cast("list[JsonObject]", payload["subjects"])
    subjects.reverse()
    _redigest(payload)
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_rejects_non_object_document(tmp_path: Path) -> None:
    """Mutation caught: a valid JSON array cannot enter the object contract."""
    path = tmp_path / "private-recovery-policy.json"
    _ = path.write_bytes(b"[]\n")

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_raw_byte_limit_matches_zod(tmp_path: Path) -> None:
    """Differential case: digest-valid JSON is bounded before parsing."""
    raw = POLICY_PATH.read_bytes()
    assert len(raw) < MAX_RAW_POLICY_BYTES
    exact_limit = raw + (b" " * (MAX_RAW_POLICY_BYTES - len(raw)))
    path = tmp_path / "private-recovery-policy.json"
    _ = path.write_bytes(exact_limit)

    _ = load_private_recovery_policy(path)

    _ = path.write_bytes(exact_limit + b" ")
    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_rejects_digest_drift(tmp_path: Path) -> None:
    """Mutation caught: artifact content changes without a matching digest."""
    payload = deepcopy(_policy_payload())
    subjects = cast("list[JsonObject]", payload["subjects"])
    recipe_paths = cast("list[str]", subjects[1]["regeneration_recipe_paths"])
    subjects[1]["regeneration_recipe_paths"] = list(reversed(recipe_paths))
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_rejects_candidate_invented_authority(tmp_path: Path) -> None:
    """Mutation caught: candidate-local JSON claims protected recovery success."""
    payload = deepcopy(_policy_payload())
    evidence = cast("JsonObject", payload["evidence"])
    evidence["status"] = "verified"
    evidence["candidate_generated"] = True
    evidence["measured_rto_seconds"] = 1
    evidence["controller_receipt_sha256"] = "sha256:" + "a" * 64
    evidence["blockers"] = []
    payload["release_ready"] = True
    payload["terminal_verdict"] = "release"
    _redigest(payload)
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


@pytest.mark.parametrize(
    "mutation",
    [
        "omitted",
        "extra",
        "duplicate",
        "reordered",
        "coerced",
        "incorrect-strategy",
        "invented-persistence",
        "path-traversal",
    ],
)
def test_recovery_policy_rejects_state_inventory_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Mutation caught: digest-valid state inventory weakens restart safety."""
    payload = deepcopy(_policy_payload())
    inventory = _state_inventory(payload)
    if mutation == "omitted":
        _ = inventory.pop(2)
    elif mutation == "extra":
        invented = deepcopy(inventory[-1])
        invented["state_id"] = "candidate-claimed-backup-authority"
        inventory.append(invented)
    elif mutation == "duplicate":
        inventory.append(deepcopy(inventory[0]))
    elif mutation == "reordered":
        inventory[0], inventory[1] = inventory[1], inventory[0]
    elif mutation == "coerced":
        inventory[-1]["expected_active_leases"] = True
    elif mutation == "incorrect-strategy":
        inventory[1]["recovery_strategy"] = "reconstruct-from-object-mtimes"
    elif mutation == "invented-persistence":
        inventory[-1]["persistence"] = "protected-controller-persisted"
    else:
        inventory[0]["location"] = "../.retention-clock-high-water.json"
    _redigest(payload)
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner_uid", 0),
        ("owner_gid", True),
        ("directory_mode", "0755"),
        ("regular_file_mode", "0644"),
        ("symlinks_permitted", True),
        ("hardlinks_permitted", True),
        ("applies_to", ["subjects", "lifecycle-state"]),
    ],
)
def test_recovery_policy_rejects_owner_mode_expectation_drift(
    tmp_path: Path,
    field: str,
    value: JsonValue,
) -> None:
    """Mutation caught: valid redigest weakens private filesystem expectations."""
    payload = deepcopy(_policy_payload())
    expectations = cast("JsonObject", payload["filesystem_expectations"])
    expectations[field] = value
    _redigest(payload)
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_rejects_duplicate_json_names(tmp_path: Path) -> None:
    """Mutation caught: duplicate names exploit parser last-value behavior."""
    raw = POLICY_PATH.read_bytes().replace(
        b'  "schema_version": 1,',
        b'  "schema_version": 1,\n  "schema_version": 1,',
        1,
    )
    path = tmp_path / "private-recovery-policy.json"
    _ = path.write_bytes(raw)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


@pytest.mark.parametrize("coercible", [True, 900.0, "900"])
def test_recovery_policy_rejects_coercible_rto_values(
    tmp_path: Path,
    coercible: object,
) -> None:
    """Mutation caught: JSON coercion changes the numeric RTO contract."""
    payload = deepcopy(_policy_payload())
    rto = cast("JsonObject", payload["rto"])
    rto["objective_seconds"] = cast("JsonValue", coercible)
    _redigest(payload)
    path = tmp_path / "private-recovery-policy.json"
    _write_policy(path, payload)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)


def test_recovery_policy_rejects_symlink_artifact(
    tmp_path: Path,
) -> None:
    """Mutation caught: policy loading follows an attacker-replaced symlink."""
    path = tmp_path / "private-recovery-policy.json"
    path.symlink_to(POLICY_PATH)

    with pytest.raises(RecoveryPolicyError, match="policy rejected"):
        _ = load_private_recovery_policy(path)
