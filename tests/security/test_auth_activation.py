# Copyright (c) 2026 David Osipov
"""Fail-closed activation tests for the selected production OAuth profile."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import nplg_mcp.app as app_module
from nplg_mcp import capabilities
from nplg_mcp.config import load_config

if TYPE_CHECKING:
    from collections.abc import Mapping

_CREDENTIAL_CANARY = "phase-six-static-credential-canary-" + ("x" * 32)
_DEPENDENCY_TOUCH_MESSAGE = "runtime dependency constructed before OAuth gate"


def _production_metadata_environment(
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = {
        "NODE_ENV": "production",
        "DEPLOYMENT_PROFILE": "alpic-metadata",
        "PUBLIC_BASE_URL": "https://mcp.example.test",
        "CURSOR_SIGNING_SECRET": "c" * 32,
        "ALLOW_ANONYMOUS": "false",
    }
    if overrides is not None:
        environment.update(overrides)
    return environment


def _synthetic_supported_provider() -> capabilities.OAuthProviderCapabilityVerdict:
    """Build schema-valid synthetic evidence without claiming operational proof."""
    verdict = capabilities.probe_oauth_provider()
    supported_values: dict[str, object] = {
        "selected_issuer": "https://issuer.example.test",
        "discovery_issuer": "https://issuer.example.test",
        "authorization_endpoint": "https://issuer.example.test/authorize",
        "token_endpoint": "https://issuer.example.test/token",
        "jwks_uri": "https://issuer.example.test/jwks.json",
        "access_token_format": "signed_jwt",
        "resource": "https://mcp.example.test",
        "audience": "https://mcp.example.test",
        "access_token_purpose_claim": "resource",
        "client_identity_claim": "client_id",
        "pkce_method": "S256",
        "authorization_response_issuer": "observed",
        "scopes": ("nplg:connect",),
        "token_lifetime_seconds": 300,
        "revocation": "supported",
        "registration_modes": ("preregistered",),
        "evidence_source": "Synthetic schema reachability; not operational evidence.",
        "evidence_digest": "1" * 64,
        "supported": True,
        "blockers": (),
    }
    for name, value in supported_values.items():
        object.__setattr__(verdict, name, value)
    payload = capabilities.canonical_model_json(verdict)
    _ = payload.pop("verdict_digest")
    object.__setattr__(
        verdict,
        "verdict_digest",
        capabilities.canonical_json_sha256(payload),
    )
    return capabilities.OAuthProviderCapabilityVerdict.model_validate_json(
        verdict.model_dump_json()
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        pytest.param("API_BEARER_TOKEN", _CREDENTIAL_CANARY, id="legacy-bearer"),
        pytest.param("API_KEY", _CREDENTIAL_CANARY, id="legacy-api-key"),
        pytest.param(
            "API_PRINCIPALS_JSON",
            (
                '[{"principal_id":"legacy-client","api_key":"'
                + _CREDENTIAL_CANARY
                + '"}]'
            ),
            id="static-principal-registry",
        ),
        pytest.param(
            "NPLG_PRIVATE_STATIC_TOKEN",
            _CREDENTIAL_CANARY,
            id="private-static-token",
        ),
        pytest.param("X_API_KEY", _CREDENTIAL_CANARY, id="underscore-api-key"),
        pytest.param("X-API-Key", _CREDENTIAL_CANARY, id="header-shaped-api-key"),
    ],
)
def test_selected_production_profile_rejects_every_static_credential_key(
    name: str,
    value: str,
) -> None:
    """Never let an unsupported OAuth profile fall back to a shared secret."""
    with pytest.raises(
        ValueError,
        match=r"static authentication.*production",
    ) as caught:
        _ = load_config(_production_metadata_environment({name: value}))

    assert _CREDENTIAL_CANARY not in str(caught.value)


def test_selected_production_profile_parses_without_a_fallback_credential() -> None:
    """Keep capability assessment reachable without enabling anonymous access."""
    config = load_config(_production_metadata_environment())

    assert config.environment == "production"
    assert config.deployment_profile == "alpic-metadata"
    assert config.allow_anonymous is False
    assert config.api_bearer_token is None
    assert config.api_key is None
    assert config.api_principals == ()


def test_unsupported_provider_blocks_before_runtime_dependency_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pinned negative provider verdict is an activation stop, not a fallback."""
    config = load_config(_production_metadata_environment())
    verdict = capabilities.probe_oauth_provider()
    assert verdict.supported is False
    touched = False

    def fail_on_dependency_construction(*_args: object, **_kwargs: object) -> None:
        nonlocal touched
        touched = True
        raise AssertionError(_DEPENDENCY_TOUCH_MESSAGE)

    monkeypatch.setattr(
        app_module,
        "_runtime_services",
        fail_on_dependency_construction,
    )
    monkeypatch.setattr(app_module, "probe_oauth_provider", lambda: verdict)

    with pytest.raises(ValueError, match="OAuth provider capability is unsupported"):
        _ = app_module.create_app(config)

    assert touched is False


def test_anonymous_production_metadata_starts_without_oauth_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public metadata profile must not need a deferred OAuth contract."""
    config = load_config(_production_metadata_environment({"ALLOW_ANONYMOUS": "true"}))

    def fail_probe() -> capabilities.OAuthProviderCapabilityVerdict:
        msg = "anonymous metadata unexpectedly consulted OAuth capability"
        raise AssertionError(msg)

    monkeypatch.setattr(app_module, "probe_oauth_provider", fail_probe)

    application = app_module.create_app(config)

    assert application.title == "NPLG DSpace MCP"


def test_provider_contract_error_blocks_before_runtime_dependency_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capability parsing failure must not silently select the shared-key stack."""
    config = load_config(_production_metadata_environment())
    touched = False

    def fail_probe() -> capabilities.OAuthProviderCapabilityVerdict:
        msg = "synthetic provider contract drift"
        raise capabilities.CapabilityContractError(msg)

    def fail_on_dependency_construction(*_args: object, **_kwargs: object) -> None:
        nonlocal touched
        touched = True
        raise AssertionError(_DEPENDENCY_TOUCH_MESSAGE)

    monkeypatch.setattr(app_module, "probe_oauth_provider", fail_probe)
    monkeypatch.setattr(
        app_module,
        "_runtime_services",
        fail_on_dependency_construction,
    )

    with pytest.raises(ValueError, match="assessment failed closed"):
        _ = app_module.create_app(config)

    assert touched is False


def test_supported_provider_still_requires_an_implemented_oauth_stack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capability evidence alone must not activate behavior that is not implemented."""
    config = load_config(_production_metadata_environment())
    verdict = _synthetic_supported_provider()
    touched = False

    def fail_on_dependency_construction(*_args: object, **_kwargs: object) -> None:
        nonlocal touched
        touched = True
        raise AssertionError(_DEPENDENCY_TOUCH_MESSAGE)

    monkeypatch.setattr(app_module, "probe_oauth_provider", lambda: verdict)
    monkeypatch.setattr(
        app_module,
        "_runtime_services",
        fail_on_dependency_construction,
    )

    with pytest.raises(ValueError, match="separately approved implementation"):
        _ = app_module.create_app(config)

    assert touched is False


def test_unvalidated_blocker_drift_cannot_cross_the_activation_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revalidate even a Pydantic object constructed through the unsafe escape hatch."""
    config = load_config(_production_metadata_environment())
    drifted = capabilities.probe_oauth_provider()
    object.__setattr__(
        drifted,
        "blockers",
        ("OAUTH_PROVIDER_CAPABILITY_UNPROVEN",),
    )
    touched = False

    def fail_on_dependency_construction(*_args: object, **_kwargs: object) -> None:
        nonlocal touched
        touched = True
        raise AssertionError(_DEPENDENCY_TOUCH_MESSAGE)

    monkeypatch.setattr(app_module, "probe_oauth_provider", lambda: drifted)
    monkeypatch.setattr(
        app_module,
        "_runtime_services",
        fail_on_dependency_construction,
    )

    with pytest.raises(ValueError, match="assessment failed closed"):
        _ = app_module.create_app(config)

    assert touched is False


@pytest.mark.parametrize("profile", ["alpic-metadata", "private-full"])
def test_local_test_profiles_keep_explicit_static_auth_fixture_support(
    profile: str,
) -> None:
    """Local auth fixtures remain available without becoming production fallback."""
    environment = {
        "NODE_ENV": "test",
        "DEPLOYMENT_PROFILE": profile,
        "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
        "CURSOR_SIGNING_SECRET": "c" * 32,
        "ALLOW_ANONYMOUS": "false",
        "API_KEY": _CREDENTIAL_CANARY,
    }
    if profile == "private-full":
        environment["ASSET_SIGNING_SECRET"] = "s" * 32

    config = load_config(environment)

    assert config.environment == "test"
    assert config.deployment_profile == profile
    assert config.api_key == _CREDENTIAL_CANARY
