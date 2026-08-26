# Copyright (c) 2026 David Osipov
"""Contract tests for provider capability evidence."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from nplg_mcp.capabilities import (
    AlpicOAuthDiscoveryCapabilityVerdict,
    CapabilityContractError,
    OAuthProviderCapabilityVerdict,
    RawHttpRequest,
    RawHttpResponse,
    SdkAuthorizationCapabilityVerdict,
    SdkHttpObservation,
    load_alpic_verdict,
    load_provider_verdict,
    load_sdk_verdict,
    probe_oauth_provider,
)
from nplg_mcp.json_types import load_json_value, require_json_object

CONTRACT = Path(__file__).parents[2] / "contracts" / "oauth-provider-capability.json"
SDK_CONTRACT = (
    Path(__file__).parents[2] / "contracts" / "sdk-authorization-capability.json"
)
ALPIC_CONTRACT = (
    Path(__file__).parents[2] / "contracts" / "alpic-oauth-discovery-capability.json"
)
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
SIGNED_FORMAT = "signed_jwt"


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _load_contract(path: Path) -> dict[str, object]:
    return cast(
        "dict[str, object]",
        json.loads(path.read_text(encoding="utf-8")),
    )


def _redigest(value: dict[str, object]) -> bytes:
    payload = dict(value)
    _ = payload.pop("verdict_digest", None)
    value["verdict_digest"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return _canonical(value)


def _redigest_sdk(value: dict[str, object]) -> bytes:
    observations = [
        cast("dict[str, object]", value[field]) for field in OBSERVATION_FIELDS
    ]
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


def _supported_provider_record() -> dict[str, object]:
    value = _load_contract(CONTRACT)
    value.update(
        {
            "selected_issuer": "https://issuer.example.test",
            "discovery_issuer": "https://issuer.example.test",
            "authorization_endpoint": "https://issuer.example.test/authorize",
            "token_endpoint": "https://issuer.example.test/token",
            "jwks_uri": "https://issuer.example.test/jwks.json",
            "introspection_endpoint": None,
            "access_token_format": "signed_jwt",
            "resource": "https://mcp.example.test",
            "audience": "https://mcp.example.test",
            "access_token_purpose_claim": "resource",
            "client_identity_claim": "client_id",
            "pkce_method": "S256",
            "authorization_response_issuer": "observed",
            "scopes": ["nplg:search"],
            "token_lifetime_seconds": 3600,
            "revocation": "supported",
            "registration_modes": ["preregistered"],
            "evidence_source": "witnessed provider discovery and token flow",
            "evidence_digest": "1" * 64,
            "supported": True,
            "blockers": [],
        },
    )
    return value


def test_provider_probe_is_unselected_and_fail_closed() -> None:
    verdict = probe_oauth_provider()
    assert verdict.supported is False
    assert verdict.selected_issuer is None
    assert verdict.access_token_format is None
    assert verdict.registration_modes == ("dcr",)
    assert verdict.blockers == (
        "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
        "ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN",
        "OAUTH_END_TO_END_FLOW_UNPROVEN",
    )


def test_provider_canonical_contract_round_trips_and_rejects_mutations() -> None:
    verdict = load_provider_verdict(CONTRACT)
    assert verdict == probe_oauth_provider()

    raw = require_json_object(
        load_json_value(CONTRACT.read_text(encoding="utf-8")),
        context="OAuth provider capability",
    )
    raw["supported"] = True
    with pytest.raises((CapabilityContractError, ValidationError)):
        _ = OAuthProviderCapabilityVerdict.model_validate(raw)

    raw = require_json_object(
        load_json_value(CONTRACT.read_text(encoding="utf-8")),
        context="OAuth provider capability",
    )
    raw["registration_modes"] = ["dcr"]
    with pytest.raises((CapabilityContractError, ValidationError)):
        _ = OAuthProviderCapabilityVerdict.model_validate(raw)


@pytest.mark.parametrize(
    "missing_field",
    ["selected_issuer", "access_token_format", "evidence_digest"],
)
def test_supported_provider_requires_selected_evidenced_capabilities(
    missing_field: str,
) -> None:
    raw = _supported_provider_record()
    raw[missing_field] = None

    with pytest.raises(
        ValidationError,
        match="requires selected, evidenced capabilities",
    ):
        _ = OAuthProviderCapabilityVerdict.model_validate_json(_redigest(raw))


def test_supported_provider_requires_a_registration_mode() -> None:
    raw = _supported_provider_record()
    raw["registration_modes"] = []

    with pytest.raises(ValidationError, match="requires a registration mode"):
        _ = OAuthProviderCapabilityVerdict.model_validate_json(_redigest(raw))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("selected_issuer", "https://issuer.example.test"),
        ("discovery_issuer", "https://issuer.example.test"),
        ("access_token_format", "opaque"),
        ("evidence_digest", "1" * 64),
    ],
)
def test_unselected_provider_rejects_selected_or_evidenced_state(
    field: str,
    value: str,
) -> None:
    raw = _load_contract(CONTRACT)
    raw[field] = value

    with pytest.raises(ValidationError, match="unselected provider verdict cannot"):
        _ = OAuthProviderCapabilityVerdict.model_validate_json(_redigest(raw))


def test_unselected_provider_preserves_its_stable_blocker() -> None:
    raw = _load_contract(CONTRACT)
    raw["blockers"] = ["OAUTH_END_TO_END_FLOW_UNPROVEN"]

    with pytest.raises(
        ValidationError,
        match="must preserve OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
    ):
        _ = OAuthProviderCapabilityVerdict.model_validate_json(_redigest(raw))


@pytest.mark.parametrize(
    "blockers",
    [
        [
            "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
            "OAUTH_END_TO_END_FLOW_UNPROVEN",
        ],
        [
            "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
            "ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN",
        ],
    ],
)
def test_unselected_provider_preserves_every_selected_topology_blocker(
    blockers: list[str],
) -> None:
    raw = _load_contract(CONTRACT)
    raw["blockers"] = blockers

    with pytest.raises(
        ValidationError,
        match="must preserve every selected Auth0/Alpic DCR blocker",
    ):
        _ = OAuthProviderCapabilityVerdict.model_validate_json(_redigest(raw))


def test_complete_supported_provider_state_is_accepted() -> None:
    verdict = OAuthProviderCapabilityVerdict.model_validate_json(
        _redigest(_supported_provider_record()),
    )

    assert verdict.supported is True
    assert verdict.selected_issuer == "https://issuer.example.test"
    assert verdict.access_token_format == SIGNED_FORMAT
    assert verdict.registration_modes == ("preregistered",)
    assert verdict.blockers == ()


def test_provider_model_rejects_a_tampered_canonical_verdict_digest() -> None:
    raw = _load_contract(CONTRACT)
    raw["evidence_source"] = "tampered provider evidence"

    with pytest.raises(ValidationError, match="verdict_digest does not match"):
        _ = OAuthProviderCapabilityVerdict.model_validate_json(_canonical(raw))


def test_public_http_evidence_models_reject_body_digest_drift() -> None:
    raw = _load_contract(SDK_CONTRACT)
    weak = cast("dict[str, object]", raw["weak_scope_observation"])
    request = cast("dict[str, object]", weak["request"])
    response = cast("dict[str, object]", weak["response"])
    request["body_sha256"] = "0" * 64
    response["body_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="request body_sha256"):
        _ = RawHttpRequest.model_validate_json(_canonical(request))
    with pytest.raises(ValidationError, match="response body_sha256"):
        _ = RawHttpResponse.model_validate_json(_canonical(response))


def test_public_sdk_observation_rejects_counter_token_disagreement() -> None:
    raw = _load_contract(SDK_CONTRACT)
    weak = cast("dict[str, object]", raw["weak_scope_observation"])
    weak["verifier_calls"] = 0

    with pytest.raises(ValidationError, match="verifier_calls must equal"):
        _ = SdkHttpObservation.model_validate_json(_canonical(weak))


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        (
            "blockers",
            [
                "SDK_DUPLICATE_AUTHORIZATION_REQUIRES_OUTER_REJECTION",
                "MCP_DYNAMIC_SCOPE_403_UNSUPPORTED",
            ],
            "preserve its stable blocker",
        ),
        (
            "upstream_commit",
            "a" * 40,
            "does not publish a verified upstream commit",
        ),
        (
            "locked_artifact_sha256s",
            [
                "1cb4c75d2d2c7b8c1d756355e5d82a39f2822cc7f13e22a2051d7ca3592349d6",
                "0f440e735c13ece8bb19bc62cf0b86f4313448432fbb77d35e14034f4e050728",
            ],
            "artifact digests differ",
        ),
        (
            "sdk_boundary_file_sha256",
            "0" * 64,
            "authorization boundary differs",
        ),
        (
            "asgi_case_digest",
            "0" * 64,
            "does not bind the observed requests",
        ),
        (
            "asgi_observation_digest",
            "0" * 64,
            "does not bind the observations",
        ),
    ],
)
def test_sdk_public_model_rejects_independently_redigested_identity_drift(
    field: str,
    value: object,
    expected: str,
) -> None:
    raw = _load_contract(SDK_CONTRACT)
    raw[field] = value

    with pytest.raises(ValidationError, match=expected):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(_redigest(raw))


def test_sdk_public_model_rejects_sufficient_scope_dispatch_drift() -> None:
    raw = _load_contract(SDK_CONTRACT)
    sufficient = cast("dict[str, object]", raw["sufficient_scope_control"])
    sufficient["downstream_dispatch_count"] = 0

    with pytest.raises(ValidationError, match="sufficient-scope control"):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


@pytest.mark.parametrize("distribution", ["mcp", "mcp-types"])
def test_sdk_public_model_rejects_installed_distribution_version_drift(
    monkeypatch: pytest.MonkeyPatch,
    distribution: str,
) -> None:
    raw = _load_contract(SDK_CONTRACT)

    def installed_version(name: str) -> str:
        if name == distribution:
            return "9.9.9"
        return "2.0.0"

    monkeypatch.setattr(importlib.metadata, "version", installed_version)

    with pytest.raises(ValidationError, match=r"installed .* version differs"):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(_redigest(raw))


def test_sdk_public_model_rejects_case_matrix_identity_drift() -> None:
    raw = _load_contract(SDK_CONTRACT)
    missing = cast("dict[str, object]", raw["missing_authorization_observation"])
    missing["case_id"] = "authorization.basic"

    with pytest.raises(ValidationError, match="closed reviewed case matrix"):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_public_model_rejects_duplicate_header_dispatch_forgery() -> None:
    raw = _load_contract(SDK_CONTRACT)
    duplicate = cast(
        "dict[str, object]",
        raw["duplicate_authorization_observation"],
    )
    duplicate["downstream_dispatch_count"] = 1

    with pytest.raises(ValidationError, match="duplicate Authorization must preserve"):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(
            _redigest_sdk(raw),
        )


def test_sdk_public_model_binds_scope_challenge_to_observed_header() -> None:
    raw = _load_contract(SDK_CONTRACT)
    challenge = cast("dict[str, object]", raw["scope_challenge"])
    challenge["header_value"] = 'Bearer error="insufficient_scope"'

    with pytest.raises(ValidationError, match="scope challenge does not match"):
        _ = SdkAuthorizationCapabilityVerdict.model_validate_json(_redigest(raw))


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("request_digest", "0" * 64, "does not bind the bounded request"),
        (
            "local_observation_digest",
            "0" * 64,
            "does not bind the SDK observation",
        ),
        (
            "blockers",
            [
                "ALPIC_OAUTH_DISCOVERY_ORDERING_UNPROVEN",
                "ALPIC_PRM_ROUTE_COMPATIBILITY_UNPROVEN",
                "ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN",
            ],
            "preserve every stable blocker",
        ),
    ],
)
def test_alpic_public_model_rejects_independently_redigested_state_drift(
    field: str,
    value: object,
    expected: str,
) -> None:
    raw = _load_contract(ALPIC_CONTRACT)
    raw[field] = value

    with pytest.raises(ValidationError, match=expected):
        _ = AlpicOAuthDiscoveryCapabilityVerdict.model_validate_json(_redigest(raw))


def test_public_capability_loaders_bind_bearer_challenges_to_one_resource() -> None:
    sdk = load_sdk_verdict(SDK_CONTRACT)
    alpic = load_alpic_verdict(ALPIC_CONTRACT)
    alpic_challenges = tuple(
        header.value
        for header in alpic.local_sdk_observation.response.headers
        if header.name.lower() == "www-authenticate"
    )

    assert sdk.scope_challenge.header_value == (
        'Bearer error="insufficient_scope", '
        'error_description="Required scope: nplg:search", '
        'resource_metadata="https://mcp.example.test/'
        '.well-known/oauth-protected-resource"'
    )
    assert alpic_challenges == (
        (
            'Bearer error="invalid_token", '
            'error_description="Authentication required", '
            'resource_metadata="https://mcp.example.test/'
            '.well-known/oauth-protected-resource"'
        ),
    )


def test_provider_loader_rejects_nonobject_invalid_and_noncanonical_json(
    tmp_path: Path,
) -> None:
    cases: tuple[tuple[str, bytes, str], ...] = (
        ("non-object", b"[]\n", "must be a JSON object"),
        (
            "invalid-model",
            _canonical({"schema_version": "1.0"}) + b"\n",
            "failed validation",
        ),
        (
            "noncanonical",
            b" " + CONTRACT.read_bytes(),
            "not canonical JSON",
        ),
    )
    for name, payload, expected in cases:
        path = tmp_path / f"{name}.json"
        _ = path.write_bytes(payload)
        with pytest.raises(CapabilityContractError, match=expected):
            _ = load_provider_verdict(path)
