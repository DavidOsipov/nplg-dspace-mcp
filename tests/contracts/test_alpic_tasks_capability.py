# Copyright (c) 2026 David Osipov
"""Contract tests for the fail-closed Alpic Tasks capability assessment."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

import nplg_mcp.capabilities as capabilities  # noqa: PLR0402

CONTRACT = Path(__file__).parents[2] / "contracts" / "alpic-tasks-capability.json"
SOURCE_EVIDENCE = (
    Path(__file__).parents[2] / "contracts" / "alpic-tasks-source-evidence.json"
)
IMMUTABLE_SDK_ROADMAP = (
    "https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/"
    "959569ba1505897bd8d824a1bf22800672f7cf14/ROADMAP.md"
)


def _synthetic_supported_payload() -> dict[str, object]:
    """Build schema-reachability data that is explicitly not provider evidence."""
    payload = capabilities.canonical_model_json(
        capabilities.probe_alpic_tasks_capability()
    )
    payload.update(
        {
            "extension_revision_state": "stable",
            "mcp_version": "2.1.0",
            "mcp_types_version": "2.1.0",
            "installed_sdk_tree_sha256": "1" * 64,
            "sdk_server_support": "supported",
            "sdk_client_support": "supported",
            "source_evidence_digest": "2" * 64,
            "provider_integration": "proven",
            "task_creation_durability": "proven",
            "restart_recovery": "proven",
            "cancellation": "proven",
            "isolation": "proven",
            "retention": "proven",
            "artifact_delivery": "proven",
            "client_support": "proven",
            "documentation_provenance": (
                "Synthetic schema-reachability fixture; not operational evidence."
            ),
            "supported": True,
            "blockers": [],
            "reviewed_date": "2026-08-25",
            "live_evidence": {
                "environment_id": "synthetic-environment",
                "deployment_id": "synthetic-deployment",
                "pack_sha256": "3" * 64,
                "sdk_wheel_sha256": "4" * 64,
                "protocol_revision_sha256": "5" * 64,
                "client_identities_sha256": "6" * 64,
                "evidence_digest": "7" * 64,
                "observed_at": "2026-08-25T00:00:00Z",
            },
        }
    )
    payload["verdict_digest"] = capabilities.canonical_json_sha256(
        {key: value for key, value in payload.items() if key != "verdict_digest"}
    )
    return payload


def _source_record_json(
    source: capabilities.AlpicTasksSourceRecord,
    *,
    final_url: str,
) -> dict[str, object]:
    """Build a typed JSON-like source record without invoking Pydantic copying."""
    return {
        "source_id": source.source_id,
        "url": source.url,
        "final_url": final_url,
        "retrieved_at": source.retrieved_at,
        "status_code": source.status_code,
        "media_type": source.media_type,
        "content_length_bytes": source.content_length_bytes,
        "content_sha256": source.content_sha256,
        "observation": source.observation,
    }


def test_pinned_sdk_produces_canonical_unsupported_alpic_tasks_verdict() -> None:
    """Mutation caught: missing SDK Tasks support enables the profile by accident."""
    verdict = capabilities.probe_alpic_tasks_capability()

    assert verdict.provider == "alpic"
    assert verdict.extension_identifier == "io.modelcontextprotocol/tasks"
    assert verdict.extension_revision_state == "draft"
    assert verdict.sdk_server_support == "unsupported"
    assert verdict.sdk_client_support == "unsupported"
    assert verdict.supported is False
    assert verdict.blockers == (
        "MCP_TASKS_REVISION_UNFROZEN",
        "PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE",
        "PYTHON_SDK_TASKS_CLIENT_UNAVAILABLE",
        "ALPIC_TASKS_PYTHON_INTEGRATION_UNPROVEN",
        "ALPIC_TASK_CREATION_DURABILITY_UNPROVEN",
        "ALPIC_TASK_RESTART_RECOVERY_UNPROVEN",
        "ALPIC_TASK_CANCELLATION_UNPROVEN",
        "ALPIC_TASK_ISOLATION_UNPROVEN",
        "ALPIC_TASK_RETENTION_UNPROVEN",
        "ALPIC_TASK_ARTIFACT_DELIVERY_UNPROVEN",
        "ALPIC_TASK_CLIENT_SUPPORT_UNPROVEN",
    )


def test_checked_in_alpic_tasks_contract_round_trips_through_the_strict_loader() -> (
    None
):
    """Mutation caught: a stale or altered contract changes the assessed verdict."""
    assert CONTRACT.is_file()

    assert capabilities.load_alpic_tasks_verdict(CONTRACT) == (
        capabilities.probe_alpic_tasks_capability()
    )


def test_alpic_tasks_source_evidence_is_strict_and_bound_to_the_verdict() -> None:
    """Mutation caught: mutable documentation or a source swap becomes proof."""
    assert SOURCE_EVIDENCE.is_file()
    evidence = capabilities.load_alpic_tasks_source_evidence(SOURCE_EVIDENCE)
    verdict = capabilities.load_alpic_tasks_verdict(CONTRACT)

    assert tuple(record.source_id for record in evidence.sources) == (
        "alpic_tasks_docs",
        "python_sdk_roadmap",
        "mcp_tasks_spec",
    )
    assert verdict.source_evidence_digest == evidence.evidence_digest


def test_alpic_tasks_source_evidence_rejects_redirection_and_digest_forgery() -> None:
    """Mutation caught: a source swap can be redigested into trusted evidence."""
    evidence = capabilities.load_alpic_tasks_source_evidence(SOURCE_EVIDENCE)
    source_payload: dict[str, object] = {
        "schema_version": evidence.schema_version,
        "sources": [
            _source_record_json(
                evidence.sources[0],
                final_url="https://attacker.example/tasks",
            ),
            *[
                _source_record_json(source, final_url=source.final_url)
                for source in evidence.sources[1:]
            ],
        ],
    }
    source_payload["evidence_digest"] = capabilities.canonical_json_sha256(
        {
            key: value
            for key, value in source_payload.items()
            if key != "evidence_digest"
        }
    )

    with pytest.raises(ValidationError, match="must not follow redirects"):
        _ = capabilities.AlpicTasksSourceEvidence.model_validate_json(
            json.dumps(source_payload)
        )


def test_alpic_tasks_source_record_accepts_commit_pinned_raw_roadmap() -> None:
    evidence = capabilities.load_alpic_tasks_source_evidence(SOURCE_EVIDENCE)
    payload = capabilities.canonical_model_json(evidence.sources[1])
    payload["url"] = IMMUTABLE_SDK_ROADMAP
    payload["final_url"] = IMMUTABLE_SDK_ROADMAP
    payload["media_type"] = "text/plain"

    record = capabilities.AlpicTasksSourceRecord.model_validate(payload)

    assert record.url == IMMUTABLE_SDK_ROADMAP
    assert record.media_type == "text/plain"


def test_alpic_tasks_source_record_rejects_mutable_vcs_branch_url() -> None:
    evidence = capabilities.load_alpic_tasks_source_evidence(SOURCE_EVIDENCE)
    payload = capabilities.canonical_model_json(evidence.sources[1])
    mutable = "https://github.com/modelcontextprotocol/python-sdk/blob/main/ROADMAP.md"
    payload["url"] = mutable
    payload["final_url"] = mutable

    with pytest.raises(ValidationError, match="immutable commit"):
        _ = capabilities.AlpicTasksSourceRecord.model_validate(payload)


def test_alpic_tasks_model_rejects_redigested_provider_and_blocker_forgeries() -> None:
    """Mutation caught: rehashing cannot turn unassessed facts into approval."""
    payload = capabilities.canonical_model_json(
        capabilities.probe_alpic_tasks_capability()
    )

    provider_forgery = deepcopy(payload)
    provider_forgery["provider_integration"] = "proven"
    provider_forgery["verdict_digest"] = capabilities.canonical_json_sha256(
        {
            key: value
            for key, value in provider_forgery.items()
            if key != "verdict_digest"
        }
    )
    with pytest.raises(ValidationError, match="unauthorized provider claims"):
        _ = capabilities.validate_alpic_tasks_verdict_json(json.dumps(provider_forgery))

    reordered_blockers = deepcopy(payload)
    blockers = reordered_blockers["blockers"]
    assert isinstance(blockers, list)
    blockers.reverse()
    reordered_blockers["verdict_digest"] = capabilities.canonical_json_sha256(
        {
            key: value
            for key, value in reordered_blockers.items()
            if key != "verdict_digest"
        }
    )
    with pytest.raises(ValidationError, match="preserve every blocker"):
        _ = capabilities.validate_alpic_tasks_verdict_json(
            json.dumps(reordered_blockers)
        )


def test_alpic_tasks_supported_branch_is_synthetic_schema_reachability_only(
    tmp_path: Path,
) -> None:
    """A positive shape is reachable but cannot become runtime/provider proof."""
    payload = _synthetic_supported_payload()

    verdict = capabilities.validate_synthetic_alpic_tasks_verdict(payload)

    assert isinstance(verdict, capabilities.SupportedAlpicTasksCapabilityVerdict)
    assert verdict.supported is True
    assert verdict.blockers == ()
    candidate = tmp_path / "synthetic-supported-alpic-tasks.json"
    _ = candidate.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        capabilities.CapabilityContractError,
        match="protected operational validation",
    ):
        _ = capabilities.load_alpic_tasks_verdict(candidate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extension_revision_state", "draft"),
        ("sdk_server_support", "unsupported"),
        ("provider_integration", "not_assessed"),
        ("blockers", ["MCP_TASKS_REVISION_UNFROZEN"]),
        ("mcp_version", "not-a-version"),
    ],
)
def test_alpic_tasks_supported_branch_rejects_inconsistent_state(
    field: str,
    value: object,
) -> None:
    payload = _synthetic_supported_payload()
    payload[field] = value
    payload["verdict_digest"] = capabilities.canonical_json_sha256(
        {key: item for key, item in payload.items() if key != "verdict_digest"}
    )

    with pytest.raises(ValidationError):
        _ = capabilities.validate_synthetic_alpic_tasks_verdict(payload)


def test_alpic_tasks_supported_branch_requires_live_evidence_identity() -> None:
    payload = _synthetic_supported_payload()
    del payload["live_evidence"]
    payload["verdict_digest"] = capabilities.canonical_json_sha256(
        {key: value for key, value in payload.items() if key != "verdict_digest"}
    )

    with pytest.raises(ValidationError):
        _ = capabilities.validate_synthetic_alpic_tasks_verdict(payload)


def test_alpic_tasks_probe_fails_closed_when_the_sdk_surface_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: a future SDK upgrade cannot silently retain this verdict."""
    monkeypatch.setattr(capabilities, "_sdk_tasks_public_api_available", lambda: True)

    with pytest.raises(
        capabilities.CapabilityContractError,
        match="SDK Tasks surface changed",
    ):
        _ = capabilities.probe_alpic_tasks_capability()


def test_alpic_tasks_loader_rejects_noncanonical_bytes(tmp_path: Path) -> None:
    """Mutation caught: whitespace-only contract rewrites bypass canonical review."""
    candidate = tmp_path / "alpic-tasks-capability.json"
    malformed = CONTRACT.read_text(encoding="utf-8").replace("{", "{\n", 1)
    _ = candidate.write_text(malformed, encoding="utf-8")

    with pytest.raises(capabilities.CapabilityContractError, match="not canonical"):
        _ = capabilities.load_alpic_tasks_verdict(candidate)
