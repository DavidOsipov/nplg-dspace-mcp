# Copyright (c) 2026 David Osipov
"""Contract tests for SDK authorization feasibility evidence."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from nplg_mcp.capabilities import (
    CapabilityContractError,
    RewriteMapping,
    RouteRewrite,
    SdkAuthorizationCapabilityVerdict,
    load_sdk_verdict,
    probe_sdk_authorization,
)

CONTRACT = Path(__file__).parents[2] / "contracts" / "sdk-authorization-capability.json"
UNAUTHORIZED = 401
FORBIDDEN = 403
OBSERVATION_FIELDS = (
    "missing_authorization_observation",
    "basic_authorization_observation",
    "invalid_bearer_observation",
    "expired_bearer_observation",
    "weak_scope_observation",
    "weak_scope_alternate_tool_observation",
    "sufficient_scope_control",
    "duplicate_authorization_observation",
)


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


def _redigest_sdk(value: dict[str, object]) -> bytes:
    observations = [
        cast("dict[str, object]", value[field]) for field in OBSERVATION_FIELDS
    ]
    for observation in observations:
        _redigest_observation(observation)
    value["asgi_case_digest"] = hashlib.sha256(
        _canonical(
            {
                "requests": [
                    cast("dict[str, object]", observation["request"])
                    for observation in observations
                ],
            },
        ),
    ).hexdigest()
    value["asgi_observation_digest"] = hashlib.sha256(
        _canonical({"observations": observations}),
    ).hexdigest()
    return _redigest(value)


def _load_contract() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        json.loads(CONTRACT.read_text(encoding="utf-8")),
    )


def test_sdk_probe_is_a_strict_unsupported_v2_contract() -> None:
    verdict = probe_sdk_authorization()
    assert verdict.supported is False
    assert verdict.blockers == (
        "MCP_DYNAMIC_SCOPE_403_UNSUPPORTED",
        "SDK_DUPLICATE_AUTHORIZATION_REQUIRES_OUTER_REJECTION",
    )
    assert verdict.mcp_version == "2.0.0"
    assert verdict.mcp_types_version == "2.0.0"
    assert verdict.protocol_revision == "MCP-2026-07-28"
    assert verdict.upstream_commit is None
    assert verdict.upstream_commit_unavailable_reason
    assert verdict.observation_source == "official_sdk_public_asgi"
    assert verdict.scope_challenge.status_code == FORBIDDEN
    assert verdict.scope_challenge.required_scope == "nplg:search"
    assert verdict.scope_challenge.advertised_scope is None
    assert verdict.scope_challenge.header_value == (
        'Bearer error="insufficient_scope", '
        'error_description="Required scope: nplg:search", '
        'resource_metadata="https://mcp.example.test/'
        '.well-known/oauth-protected-resource"'
    )
    assert verdict.weak_scope_observation.verifier_calls == 1
    assert verdict.weak_scope_observation.response.status_code == FORBIDDEN
    assert verdict.duplicate_authorization_observation.verifier_tokens == (
        "weak-fixture-token",
    )
    assert verdict.duplicate_authorization_observation.verifier_calls == 1


def test_sdk_probe_observes_credential_failures_without_fabricated_dispatch() -> None:
    verdict = probe_sdk_authorization()

    assert (
        verdict.missing_authorization_observation.response.status_code == UNAUTHORIZED
    )
    assert verdict.missing_authorization_observation.verifier_calls == 0
    assert verdict.basic_authorization_observation.response.status_code == UNAUTHORIZED
    assert verdict.basic_authorization_observation.verifier_calls == 0
    assert verdict.invalid_bearer_observation.response.status_code == UNAUTHORIZED
    assert verdict.invalid_bearer_observation.verifier_calls == 1
    assert verdict.expired_bearer_observation.response.status_code == UNAUTHORIZED
    assert verdict.expired_bearer_observation.verifier_calls == 1
    assert verdict.weak_scope_observation.downstream_dispatch_count == 0
    assert verdict.sufficient_scope_control.downstream_dispatch_count == 1


@pytest.mark.parametrize(
    ("field", "mutation"),
    [
        (
            "sdk_extension_point",
            "parsed_operation_http_response",
        ),
        (
            "parsed_operation_identity_at_http_auth_boundary",
            True,
        ),
    ],
)
def test_sdk_contract_rejects_redigested_semantic_flag_forgery(
    field: str,
    mutation: object,
) -> None:
    raw = _load_contract()
    raw[field] = mutation

    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


@pytest.mark.parametrize(
    "field",
    ["upstream_commit_unavailable_reason", "reason", "reviewed_date"],
)
def test_sdk_contract_rejects_redigested_provenance_drift(field: str) -> None:
    raw = _load_contract()
    raw[field] = "2026-08-14" if field == "reviewed_date" else "forged"

    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_contract_rejects_redigested_dispatch_counter_forgery() -> None:
    raw = _load_contract()
    invalid = cast("dict[str, object]", raw["invalid_bearer_observation"])
    invalid["downstream_dispatch_count"] = 1

    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_contract_rejects_redigested_verifier_sequence_forgery() -> None:
    raw = _load_contract()
    duplicate = cast(
        "dict[str, object]",
        raw["duplicate_authorization_observation"],
    )
    duplicate["verifier_tokens"] = ["strong-fixture-token"]

    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_contract_rejects_redigested_duplicate_header_value_forgery() -> None:
    raw = _load_contract()
    duplicate = cast(
        "dict[str, object]",
        raw["duplicate_authorization_observation"],
    )
    request = cast("dict[str, object]", duplicate["request"])
    headers = cast("list[dict[str, str]]", request["headers"])
    for header in headers:
        if header == {
            "name": "authorization",
            "value": "Bearer weak-fixture-token",
        }:
            header["value"] = "Bearer strong-fixture-token"

    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_contract_rejects_redigested_forged_shared_challenge() -> None:
    raw = _load_contract()
    forged = 'Basic realm="forged"'
    challenge = cast("dict[str, object]", raw["scope_challenge"])
    challenge["header_value"] = forged
    for field in (
        "weak_scope_observation",
        "weak_scope_alternate_tool_observation",
    ):
        observation = cast("dict[str, object]", raw[field])
        response = cast("dict[str, object]", observation["response"])
        headers = cast("list[dict[str, str]]", response["headers"])
        for header in headers:
            if header["name"] == "www-authenticate":
                header["value"] = forged

    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_contract_rejects_redigested_invalid_token_body_forgery() -> None:
    raw = _load_contract()
    forged = base64.b64encode(b'{"error":"forged"}').decode("ascii")
    for field in (
        "missing_authorization_observation",
        "basic_authorization_observation",
        "invalid_bearer_observation",
        "expired_bearer_observation",
    ):
        observation = cast("dict[str, object]", raw[field])
        response = cast("dict[str, object]", observation["response"])
        response["body_base64"] = forged

    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_contract_rejects_redigested_case_request_forgery() -> None:
    raw = _load_contract()
    weak = cast("dict[str, object]", raw["weak_scope_observation"])
    request = cast("dict[str, object]", weak["request"])
    forged_body = b"".join(
        (
            b'{"id":1,"jsonrpc":"2.0","method":"tools/call",',
            b'"params":{"arguments":{},"name":"forged"}}',
        ),
    )
    request["body_base64"] = base64.b64encode(forged_body).decode("ascii")

    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_persisted_capability_strings_and_tuples_are_bounded() -> None:
    raw = _load_contract()
    raw["reason"] = "x" * 4097
    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )

    with pytest.raises(ValidationError):
        _ = RouteRewrite(public_path="/" + ("x" * 1024), backend_path="/mcp")

    entries = tuple(
        RouteRewrite(public_path=f"/{index}", backend_path="/mcp")
        for index in range(33)
    )
    with pytest.raises(ValidationError):
        _ = RewriteMapping(observed=False, entries=entries)


def test_sdk_canonical_contract_round_trips_and_rejects_mutations() -> None:
    verdict = load_sdk_verdict(CONTRACT)
    assert verdict == probe_sdk_authorization()

    raw = _load_contract()
    raw["supported"] = True
    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )

    raw = _load_contract()
    raw["installed_package_tree_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )

    raw = _load_contract()
    duplicate = cast(
        "dict[str, object]",
        raw["duplicate_authorization_observation"],
    )
    request = cast("dict[str, object]", duplicate["request"])
    request["headers"] = [
        header
        for header in cast("list[dict[str, str]]", request["headers"])
        if not (
            header["name"] == "authorization"
            and header["value"] == "Bearer strong-fixture-token"
        )
    ]
    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_contract_rejects_extra_fields() -> None:
    raw = _load_contract()
    raw["unexpected"] = "must fail"
    with pytest.raises(ValidationError):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(_canonical(raw))


def test_sdk_contract_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    raw = CONTRACT.read_bytes()
    duplicate = raw.replace(
        b'{"asgi_case_digest":',
        b'{"schema_version":"2.0","asgi_case_digest":',
        1,
    )
    path = tmp_path / "duplicate-sdk-capability.json"
    _ = path.write_bytes(duplicate)

    with pytest.raises(CapabilityContractError, match="invalid capability JSON"):
        _ = load_sdk_verdict(path)


def test_sdk_contract_loader_bounds_raw_input_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "oversized-sdk-capability.json"
    _ = path.write_bytes(b" " * 2_097_153)

    with pytest.raises(CapabilityContractError, match="raw-byte limit"):
        _ = load_sdk_verdict(path)
