# Copyright (c) 2026 David Osipov
"""Contract tests for Alpic OAuth discovery evidence."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from nplg_mcp.capabilities import (
    AlpicOAuthDiscoveryCapabilityVerdict,
    CapabilityContractError,
    load_alpic_verdict,
    probe_alpic_oauth_discovery,
)

CONTRACT = (
    Path(__file__).parents[2] / "contracts" / "alpic-oauth-discovery-capability.json"
)
UNAUTHORIZED = 401


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _redigest(value: dict[str, object]) -> bytes:
    payload = dict(value)
    _ = payload.pop("verdict_digest", None)
    value["verdict_digest"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return _canonical(value)


def _redigest_http(value: dict[str, object]) -> None:
    body = base64.b64decode(cast("str", value["body_base64"]), validate=True)
    value["body_sha256"] = hashlib.sha256(body).hexdigest()


def _redigest_observation(value: dict[str, object]) -> None:
    _redigest_http(cast("dict[str, object]", value["request"]))
    _redigest_http(cast("dict[str, object]", value["response"]))


def _redigest_alpic(value: dict[str, object]) -> bytes:
    bounded = cast("dict[str, object]", value["bounded_request_fixture"])
    local = cast("dict[str, object]", value["local_sdk_observation"])
    _redigest_http(bounded)
    _redigest_observation(local)
    vendor = value["vendor_raw_observation"]
    if isinstance(vendor, dict):
        _redigest_http(cast("dict[str, object]", vendor["request"]))
        _redigest_http(cast("dict[str, object]", vendor["response"]))
    value["request_digest"] = hashlib.sha256(_canonical(bounded)).hexdigest()
    value["local_observation_digest"] = hashlib.sha256(
        _canonical(local),
    ).hexdigest()
    return _redigest(value)


def _load_contract() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        json.loads(CONTRACT.read_text(encoding="utf-8")),
    )


def test_alpic_probe_preserves_bounded_approximation_blockers() -> None:
    verdict = probe_alpic_oauth_discovery()
    assert verdict.detector_contract_source == "bounded_documented_approximation"
    assert verdict.exact_detector_fixture_supported is False
    assert "ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN" in verdict.blockers
    assert verdict.vendor_raw_observation is None
    assert verdict.local_sdk_observation.response.status_code == UNAUTHORIZED
    assert verdict.local_sdk_observation.verifier_calls == 0
    assert verdict.local_sdk_observation.downstream_dispatch_count == 0
    assert verdict.authenticates_before_modern_only_routing_guard is None
    assert verdict.dispatch_counts is None


def test_alpic_contract_rejects_redigested_supported_promotion() -> None:
    raw = _load_contract()
    raw["supported"] = True

    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


def test_alpic_contract_rejects_redigested_route_binding_drift() -> None:
    raw = _load_contract()
    bindings = cast("dict[str, object]", raw["route_bindings"])
    bindings["backend_resource_server_url"] = "https://attacker.example"

    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


def test_alpic_contract_rejects_redigested_rewrite_forgery() -> None:
    raw = _load_contract()
    raw["rewrite_mapping"] = {
        "observed": True,
        "entries": [{"public_path": "/mcp", "backend_path": "/internal"}],
    }

    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


def test_alpic_contract_rejects_redigested_sdk_identity_drift() -> None:
    raw = _load_contract()
    raw["installed_sdk_tree_sha256"] = "0" * 64

    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


def test_alpic_contract_rejects_redigested_non_bearer_challenge() -> None:
    raw = _load_contract()
    local = cast("dict[str, object]", raw["local_sdk_observation"])
    response = cast("dict[str, object]", local["response"])
    headers = cast("list[dict[str, str]]", response["headers"])
    for header in headers:
        if header["name"] == "www-authenticate":
            header["value"] = 'Basic realm="forged"'

    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


def test_alpic_contract_rejects_request_fixture_not_locally_exercised() -> None:
    raw = _load_contract()
    bounded = cast("dict[str, object]", raw["bounded_request_fixture"])
    bounded["body_base64"] = base64.b64encode(
        b'{"id":2,"jsonrpc":"2.0","method":"initialize","params":{}}',
    ).decode("ascii")

    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


def test_alpic_contract_rejects_oversized_persisted_provenance() -> None:
    raw = _load_contract()
    raw["detector_contract_provenance"] = "x" * 4097

    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("detector_contract_provenance", "forged"),
        ("reviewed_date", "2026-08-14"),
    ],
)
def test_alpic_contract_rejects_redigested_provenance_drift(
    field: str,
    value: str,
) -> None:
    raw = _load_contract()
    raw[field] = value

    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


def test_alpic_canonical_contract_round_trips_and_rejects_mutations() -> None:
    verdict = load_alpic_verdict(CONTRACT)
    assert verdict == probe_alpic_oauth_discovery()

    raw = _load_contract()
    raw["detector_contract_source"] = "vendor_fixture"
    raw["exact_detector_fixture_supported"] = True
    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )

    raw = _load_contract()
    raw["dispatch_counts"] = {
        "sdk_authentication": 0,
        "legacy": 0,
        "session_manager": 0,
        "handler": 0,
        "second_token_verifier": 0,
    }
    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )

    raw = _load_contract()
    local = cast("dict[str, object]", raw["local_sdk_observation"])
    response = cast("dict[str, object]", local["response"])
    response["status_code"] = 403
    with pytest.raises(ValidationError):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(
            _redigest_alpic(raw),
        )


def test_alpic_contract_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    raw = CONTRACT.read_bytes()
    duplicate = raw.replace(
        b'{"authenticates_before_modern_only_routing_guard":',
        b'{"schema_version":"2.0","authenticates_before_modern_only_routing_guard":',
        1,
    )
    path = tmp_path / "duplicate-alpic-capability.json"
    _ = path.write_bytes(duplicate)

    with pytest.raises(CapabilityContractError, match="invalid capability JSON"):
        _ = load_alpic_verdict(path)
