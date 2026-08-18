# Copyright (c) 2026 David Osipov
"""Property tests for the Task 2 ASVS evidence trust boundaries."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from scripts.build_asvs_matrix import (
    AsvsError,
    CustodiedEvidenceReference,
    LocalEvidenceReference,
    load_evidence_manifest,
    load_threat_ledger,
    render_threat_ledger,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from hypothesis.strategies import SearchStrategy


def _local_reference_data() -> dict[str, object]:
    return {
        "artifact_path": "evidence/test-report.json",
        "asserted_invariant": "The exact requirement/profile claim was tested.",
        "candidate_tree_sha256": "1" * 64,
        "collected_at": datetime(2026, 8, 16, 8, tzinfo=UTC),
        "covered_surface": "src/nplg_mcp",
        "deployment_id": None,
        "evidence_id": "ev.property",
        "evidence_revision": "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
        "expires_at": datetime(2026, 12, 31, tzinfo=UTC),
        "image_digest": None,
        "kind": "test",
        "profiles": ("alpic-metadata",),
        "requirement_ids": ("v5.0.0-V1.1.1",),
        "result": "pass",
        "reviewer": "reviewer-subject",
        "selectors": ("tests/unit/test_fixture.py::test_claim",),
        "sha256": "2" * 64,
        "storage": "local",
        "verifier": "test-report-v1",
    }


def _custodied_reference_data() -> dict[str, object]:
    local = _local_reference_data()
    _ = local.pop("artifact_path")
    local.update(
        {
            "artifact_object_version": "3" * 64,
            "custody_authority_id": "ci.example",
            "custody_receipt_id": "receipt.property",
            "immutable_artifact_uri": (
                "https://evidence.example.invalid/objects/sha256/" + "2" * 64
            ),
            "storage": "custodied-uri",
            "verifier": "ci-custody-v1",
        }
    )
    return local


def _canonical_json_line(value: dict[str, object]) -> bytes:
    serializable = {
        key: item.isoformat().replace("+00:00", "Z")
        if isinstance(item, datetime)
        else item
        for key, item in value.items()
    }
    return (
        json.dumps(
            serializable,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _control_path(code_point: int) -> str:
    return f"evidence/{chr(code_point)}record.json"


def _dotdot_path(segment: str) -> str:
    return f"evidence/{segment}/../record.json"


def _private_host(octets: tuple[int, int, int]) -> str:
    return f"10.{octets[0]}.{octets[1]}.{octets[2]}"


SAFE_SEGMENT_STRATEGY: SearchStrategy[str] = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz",
    min_size=1,
    max_size=16,
)
UNSAFE_PATH_STRATEGY: SearchStrategy[str] = st.one_of(
    st.sampled_from(("../outside", "/absolute", "evidence\\record", ".", "a//b")),
    st.integers(min_value=0, max_value=31).map(_control_path),
    SAFE_SEGMENT_STRATEGY.map(_dotdot_path),
)
PRIVATE_HOST_STRATEGY: SearchStrategy[str] = st.tuples(
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
).map(_private_host)
REFERENCE_FIELD_STRATEGY: SearchStrategy[str] = st.sampled_from(
    tuple(_local_reference_data())
)
NONPOSITIVE_LIFETIME_STRATEGY: SearchStrategy[int] = st.integers(
    min_value=-86_400,
    max_value=0,
)
ENTRY_POINT_INDEX_STRATEGY: SearchStrategy[int] = st.integers(min_value=0, max_value=7)


_GIVEN_UNSAFE_PATH = cast(
    "Callable[[Callable[[str], None]], Callable[[], None]]",
    given(path=UNSAFE_PATH_STRATEGY),
)


@_GIVEN_UNSAFE_PATH
def test_every_generated_ambiguous_or_control_path_is_rejected(path: str) -> None:
    candidate = _local_reference_data()
    candidate["artifact_path"] = path

    with pytest.raises(ValidationError):
        _ = LocalEvidenceReference.model_validate(candidate)


_GIVEN_PRIVATE_HOST = cast(
    "Callable[[Callable[[str], None]], Callable[[], None]]",
    given(host=PRIVATE_HOST_STRATEGY),
)


@_GIVEN_PRIVATE_HOST
def test_every_generated_private_ipv4_custody_host_is_rejected(host: str) -> None:
    candidate = _custodied_reference_data()
    candidate["immutable_artifact_uri"] = f"https://{host}/objects/sha256/" + "2" * 64

    with pytest.raises(ValidationError):
        _ = CustodiedEvidenceReference.model_validate(candidate)


_GIVEN_REFERENCE_FIELD = cast(
    "Callable[[Callable[[str], None]], Callable[[], None]]",
    given(field=REFERENCE_FIELD_STRATEGY),
)


@_GIVEN_REFERENCE_FIELD
def test_duplicate_key_for_every_manifest_field_is_rejected(
    field: str,
) -> None:
    candidate = _local_reference_data()
    body = _canonical_json_line(candidate)
    serializable_value = candidate[field]
    if isinstance(serializable_value, datetime):
        serializable_value = serializable_value.isoformat().replace("+00:00", "Z")
    duplicate = (
        body[:-2]
        + b","
        + json.dumps(field).encode("utf-8")
        + b":"
        + json.dumps(serializable_value, separators=(",", ":")).encode("utf-8")
        + b"}\n"
    )
    with TemporaryDirectory(prefix="nplg-asvs-manifest-") as directory:
        path = Path(directory) / "manifest.jsonl"
        _ = path.write_bytes(duplicate)

        with pytest.raises(AsvsError, match="duplicate JSON key"):
            _ = load_evidence_manifest(path)


_GIVEN_NONPOSITIVE_LIFETIME = cast(
    "Callable[[Callable[[int], None]], Callable[[], None]]",
    given(offset_seconds=NONPOSITIVE_LIFETIME_STRATEGY),
)


@_GIVEN_NONPOSITIVE_LIFETIME
def test_nonpositive_evidence_lifetime_is_always_rejected(offset_seconds: int) -> None:
    candidate = _local_reference_data()
    collected_at = datetime(2026, 8, 16, 8, tzinfo=UTC)
    candidate["collected_at"] = collected_at
    candidate["expires_at"] = collected_at + timedelta(seconds=offset_seconds)

    with pytest.raises(ValidationError):
        _ = LocalEvidenceReference.model_validate(candidate)


_GIVEN_ENTRY_POINT_INDEX = cast(
    "Callable[[Callable[[int], None]], Callable[[], None]]",
    given(index=ENTRY_POINT_INDEX_STRATEGY),
)


@_GIVEN_ENTRY_POINT_INDEX
def test_every_entry_point_rejects_source_for_target_relabelling(
    index: int,
) -> None:
    body = render_threat_ledger()
    with TemporaryDirectory(prefix="nplg-asvs-threat-") as directory:
        root = Path(directory)
        ledger_path = root / "source-threat-model.json"
        _ = ledger_path.write_bytes(body)
        ledger = load_threat_ledger(ledger_path)
        entry = ledger.entry_points[index]
        flow = next(item for item in ledger.flows if item.flow_id == entry.flow_id)
        needle = (
            f'"entry_point_id":"{entry.entry_point_id}",'
            f'"exposed_node_id":"{entry.exposed_node_id}"'
        ).encode("ascii")
        replacement = (
            f'"entry_point_id":"{entry.entry_point_id}",'
            f'"exposed_node_id":"{flow.source}"'
        ).encode("ascii")
        assert body.count(needle) == 1
        malformed_path = root / "malformed-threat-model.json"
        _ = malformed_path.write_bytes(body.replace(needle, replacement, 1))

        with pytest.raises(AsvsError):
            _ = load_threat_ledger(malformed_path)
