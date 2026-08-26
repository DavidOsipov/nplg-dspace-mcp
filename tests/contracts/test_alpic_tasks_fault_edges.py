# Copyright (c) 2026 David Osipov
"""Fault-oriented changed-branch tests for strict capability provenance."""

from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from nplg_mcp import capabilities

_PROJECT_ROOT = Path(__file__).parents[2]
_SOURCE_EVIDENCE = _PROJECT_ROOT / "contracts" / "alpic-tasks-source-evidence.json"
_OVERSIZED_CONTRACT_BYTES = 2_097_153


def _canonical_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _unsupported_payload() -> dict[str, object]:
    return capabilities.canonical_model_json(
        capabilities.probe_alpic_tasks_capability()
    )


def _redigest_verdict(value: dict[str, object]) -> bytes:
    value["verdict_digest"] = capabilities.canonical_json_sha256(
        {key: item for key, item in value.items() if key != "verdict_digest"}
    )
    return _canonical_bytes(value)


def _source_evidence_payload() -> dict[str, object]:
    return capabilities.canonical_model_json(
        capabilities.load_alpic_tasks_source_evidence(_SOURCE_EVIDENCE)
    )


def _source_records(value: dict[str, object]) -> list[dict[str, object]]:
    records = value["sources"]
    assert isinstance(records, list)
    return cast("list[dict[str, object]]", records)


def _redigest_source_evidence(value: dict[str, object]) -> bytes:
    value["evidence_digest"] = capabilities.canonical_json_sha256(
        {key: item for key, item in value.items() if key != "evidence_digest"}
    )
    return _canonical_bytes(value)


def test_unselected_oauth_provider_requires_the_selected_dcr_topology() -> None:
    payload = capabilities.canonical_model_json(capabilities.probe_oauth_provider())
    payload["registration_modes"] = ["preregistered"]
    payload["verdict_digest"] = capabilities.canonical_json_sha256(
        {key: item for key, item in payload.items() if key != "verdict_digest"}
    )

    with pytest.raises(ValidationError, match="requires DCR registration"):
        _ = capabilities.OAuthProviderCapabilityVerdict.model_validate_json(
            _canonical_bytes(payload)
        )


def test_negative_tasks_blockers_follow_only_the_remaining_unproven_state() -> None:
    payload = _unsupported_payload()
    payload.update(
        {
            "extension_revision_state": "stable",
            "sdk_server_support": "supported",
            "sdk_client_support": "supported",
        }
    )
    raw_blockers = payload["blockers"]
    assert isinstance(raw_blockers, list)
    blockers = cast("list[str]", raw_blockers)
    resolved = {
        "MCP_TASKS_REVISION_UNFROZEN",
        "PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE",
        "PYTHON_SDK_TASKS_CLIENT_UNAVAILABLE",
    }
    payload["blockers"] = [blocker for blocker in blockers if blocker not in resolved]

    verdict = capabilities.validate_alpic_tasks_verdict_json(_redigest_verdict(payload))

    assert verdict.supported is False
    assert not resolved.intersection(verdict.blockers)
    assert verdict.blockers


def test_source_evidence_rejects_allowlisted_records_in_the_wrong_order() -> None:
    payload = _source_evidence_payload()
    records = _source_records(payload)
    records[0], records[1] = records[1], records[0]

    with pytest.raises(ValidationError, match="unexpected source, URL, or observation"):
        _ = capabilities.AlpicTasksSourceEvidence.model_validate_json(
            _redigest_source_evidence(payload)
        )


def test_source_evidence_rejects_an_allowlisted_but_wrong_media_type() -> None:
    payload = _source_evidence_payload()
    _source_records(payload)[0]["media_type"] = "text/plain"

    with pytest.raises(ValidationError, match="unexpected media type"):
        _ = capabilities.AlpicTasksSourceEvidence.model_validate_json(
            _redigest_source_evidence(payload)
        )


def test_source_evidence_rejects_a_forged_canonical_digest() -> None:
    payload = _source_evidence_payload()
    payload["evidence_digest"] = "0" * 64

    with pytest.raises(ValidationError, match="evidence_digest does not match"):
        _ = capabilities.AlpicTasksSourceEvidence.model_validate_json(
            _canonical_bytes(payload)
        )


def test_source_record_translates_a_malformed_authority_url() -> None:
    payload = _source_evidence_payload()
    record = _source_records(payload)[0]
    record["url"] = "https://[malformed"
    record["final_url"] = "https://[malformed"

    with pytest.raises(ValidationError, match="source URL is malformed"):
        _ = capabilities.AlpicTasksSourceEvidence.model_validate_json(
            _canonical_bytes(payload)
        )


@pytest.mark.parametrize(
    ("distribution_name", "expected_message"),
    [
        ("mcp", "installed mcp version differs"),
        ("mcp-types", "installed mcp-types version differs"),
    ],
)
def test_negative_verdict_rejects_installed_distribution_version_drift(
    distribution_name: str,
    expected_message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _unsupported_payload()
    actual_version = importlib.metadata.version

    def drifted_version(candidate: str) -> str:
        if candidate == distribution_name:
            return "999.0.0"
        return actual_version(candidate)

    monkeypatch.setattr(importlib.metadata, "version", drifted_version)

    with pytest.raises(ValidationError, match=expected_message):
        _ = capabilities.validate_alpic_tasks_verdict_json(_canonical_bytes(payload))


@pytest.mark.parametrize(
    ("field", "forged_value", "expected_message"),
    [
        (
            "source_evidence_digest",
            "0" * 64,
            "not bound to the reviewed source evidence",
        ),
        (
            "installed_sdk_tree_sha256",
            "0" * 64,
            "installed SDK package tree differs",
        ),
        (
            "documentation_provenance",
            "forged documentation provenance",
            "provenance differs",
        ),
        ("reviewed_date", "2026-08-25", "provenance differs"),
    ],
)
def test_negative_verdict_rejects_redigested_provenance_forgery(
    field: str,
    forged_value: str,
    expected_message: str,
) -> None:
    payload = _unsupported_payload()
    payload[field] = forged_value

    with pytest.raises(ValidationError, match=expected_message):
        _ = capabilities.validate_alpic_tasks_verdict_json(_redigest_verdict(payload))


def test_synthetic_positive_validator_rejects_a_negative_union_member() -> None:
    with pytest.raises(
        capabilities.CapabilityContractError,
        match="requires supported=true",
    ):
        _ = capabilities.validate_synthetic_alpic_tasks_verdict(_unsupported_payload())


def test_tasks_loader_rejects_oversized_and_nonobject_contracts(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "oversized-tasks.json"
    _ = oversized.write_bytes(b" " * _OVERSIZED_CONTRACT_BYTES)
    with pytest.raises(
        capabilities.CapabilityContractError,
        match="exceeds the raw-byte limit",
    ):
        _ = capabilities.load_alpic_tasks_verdict(oversized)

    nonobject = tmp_path / "nonobject-tasks.json"
    _ = nonobject.write_bytes(b"[]\n")
    with pytest.raises(
        capabilities.CapabilityContractError,
        match="must be a JSON object",
    ):
        _ = capabilities.load_alpic_tasks_verdict(nonobject)
