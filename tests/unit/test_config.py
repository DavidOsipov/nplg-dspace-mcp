# Copyright (c) 2026 David Osipov
"""Unit tests for strict application configuration."""

from ipaddress import ip_address
from pathlib import Path

import pytest
from pydantic import SecretStr

from nplg_mcp.config import (
    HARD_MAX_DOWNLOAD_BYTES,
    PDF_WORKER_SLOT_POLICY_PATH,
    PDF_WORKER_SLOT_ROOT,
    ApiPrincipalCredential,
    AppConfig,
    load_config,
)
from nplg_mcp.http_security import build_transport_security_settings
from tests.helpers.app_factory import base_environment

_TEST_CACHE_DIR = Path("/", "tmp", "nplg-test-cache")
_ALPIC_CACHE_DIR = Path("/", "tmp", "nplg-dspace-mcp-cache")
_EXPECTED_MAX_RENDER_PAGES = 8
_EXPECTED_MAX_PAGE_PIXELS = 120_000_000
_EXPECTED_MAX_RENDER_PIXELS = 480_000_000
_EXPECTED_TILE_DIMENSION = 2048
_EXPECTED_TILE_OVERLAP = 128
_EXPECTED_MCP_CONCURRENCY = 16
_EXPECTED_ASSET_CONCURRENCY = 8
_EXPECTED_HTTP_CONCURRENCY = 128
_EXPECTED_REQUEST_BODY_TIMEOUT_SECONDS = 10.0
_EXPECTED_ASSET_STREAM_IDLE_TIMEOUT_SECONDS = 10.0
_EXPECTED_ASSET_STREAM_TOTAL_TIMEOUT_SECONDS = 120.0
_ALL_INTERFACES_HOST = str(ip_address(0))


def base_env(**overrides: str) -> dict[str, str]:
    env = {
        "NODE_ENV": "test",
        "ASSET_SIGNING_SECRET": "s" * 32,
        "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
        "ALLOW_ANONYMOUS": "true",
        "CACHE_DIR": str(_TEST_CACHE_DIR),
    }
    env.update(overrides)
    return env


def test_defaults_are_bounded_and_point_only_to_nplg() -> None:
    config = load_config(base_env())

    assert isinstance(config, AppConfig)
    assert config.nplg_base_url == "https://dspace.nplg.gov.ge/"
    assert config.max_download_bytes == HARD_MAX_DOWNLOAD_BYTES
    assert config.max_render_pages == _EXPECTED_MAX_RENDER_PAGES
    assert config.max_page_pixels == _EXPECTED_MAX_PAGE_PIXELS
    assert config.max_render_pixels == _EXPECTED_MAX_RENDER_PIXELS
    assert config.tile_width == _EXPECTED_TILE_DIMENSION
    assert config.tile_height == _EXPECTED_TILE_DIMENSION
    assert config.tile_overlap == _EXPECTED_TILE_OVERLAP
    assert config.cache_dir == _TEST_CACHE_DIR
    assert config.max_concurrent_mcp_requests == _EXPECTED_MCP_CONCURRENCY
    assert config.max_concurrent_asset_streams == _EXPECTED_ASSET_CONCURRENCY
    assert config.max_concurrent_http_requests == _EXPECTED_HTTP_CONCURRENCY
    assert config.cache_max_bytes == 20 * 1024 * 1024 * 1024
    assert config.request_body_timeout_seconds == _EXPECTED_REQUEST_BODY_TIMEOUT_SECONDS
    assert (
        config.asset_stream_idle_timeout_seconds
        == _EXPECTED_ASSET_STREAM_IDLE_TIMEOUT_SECONDS
    )
    assert (
        config.asset_stream_total_timeout_seconds
        == _EXPECTED_ASSET_STREAM_TOTAL_TIMEOUT_SECONDS
    )
    assert config.deployment_profile == "private-full"


def test_unix_pdf_worker_is_private_full_only_and_required_in_production() -> None:
    """Reject a local executor where the selected profile needs OS isolation."""
    private_test_config = load_config(
        base_env(
            DEPLOYMENT_PROFILE="private-full",
            PDF_EXECUTOR="unix-worker",
        )
    )

    assert private_test_config.pdf_executor == "unix-worker"

    with pytest.raises(ValueError, match="PDF_EXECUTOR"):
        _ = load_config(
            base_env(
                DEPLOYMENT_PROFILE="alpic-metadata",
                PDF_EXECUTOR="unix-worker",
            )
        )

    with pytest.raises(ValueError, match="PDF_EXECUTOR"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "DEPLOYMENT_PROFILE": "private-full",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
                "API_PRINCIPALS_JSON": (
                    '[{"principal_id":"operator","bearer_token":"' + ("t" * 32) + '"}]'
                ),
                "ALLOW_ANONYMOUS": "false",
                "PDF_EXECUTOR": "serialized",
            }
        )


def test_pdf_worker_slot_paths_are_fixed_for_the_private_profile() -> None:
    """Catch an environment override that redirects the isolated worker slot."""
    config = load_config(base_env(PDF_EXECUTOR="unix-worker"))

    assert config.pdf_worker_slot_root == PDF_WORKER_SLOT_ROOT
    assert config.pdf_worker_slot_policy_path == PDF_WORKER_SLOT_POLICY_PATH

    with pytest.raises(ValueError, match="PDF_WORKER_SLOT_ROOT"):
        _ = load_config(
            base_env(
                PDF_EXECUTOR="unix-worker",
                PDF_WORKER_SLOT_ROOT="/var/lib/nplg/attacker-slot",
            )
        )


def test_private_edge_tls_is_explicit_and_limited_to_private_full() -> None:
    """Do not permit an accidental plaintext origin in the private profile."""
    config = load_config(
        base_env(
            DEPLOYMENT_PROFILE="private-full",
            PRIVATE_EDGE_TLS="true",
        )
    )

    assert config.private_edge_tls is True

    with pytest.raises(ValueError, match="PRIVATE_EDGE_TLS"):
        _ = load_config(
            base_env(
                DEPLOYMENT_PROFILE="alpic-metadata",
                PRIVATE_EDGE_TLS="true",
            )
        )

    with pytest.raises(ValueError, match="PRIVATE_EDGE_TLS"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "DEPLOYMENT_PROFILE": "private-full",
                "PDF_EXECUTOR": "unix-worker",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
                "API_PRINCIPALS_JSON": (
                    '[{"principal_id":"operator","bearer_token":"' + ("t" * 32) + '"}]'
                ),
                "ALLOW_ANONYMOUS": "false",
            }
        )


def test_foreign_repository_base_url_is_rejected() -> None:
    with pytest.raises(ValueError, match="NPLG_BASE_URL"):
        _ = load_config(base_env(NPLG_BASE_URL="https://example.com/"))


def test_download_limit_cannot_exceed_compiled_ceiling() -> None:
    with pytest.raises(ValueError, match="MAX_DOWNLOAD_BYTES"):
        _ = load_config(base_env(MAX_DOWNLOAD_BYTES=str(HARD_MAX_DOWNLOAD_BYTES + 1)))


def test_tile_overlap_must_leave_positive_stride() -> None:
    with pytest.raises(ValueError, match="TILE_OVERLAP"):
        _ = load_config(
            base_env(TILE_WIDTH="512", TILE_HEIGHT="512", TILE_OVERLAP="512")
        )


def test_tile_geometry_cannot_exceed_compiled_ceilings() -> None:
    with pytest.raises(ValueError, match="TILE_WIDTH"):
        _ = load_config(base_env(TILE_WIDTH="4097"))
    with pytest.raises(ValueError, match="TILE_HEIGHT"):
        _ = load_config(base_env(TILE_HEIGHT="4097"))
    with pytest.raises(ValueError, match="TILE_OVERLAP"):
        _ = load_config(base_env(TILE_OVERLAP="513"))


def test_production_requires_stable_public_url_and_strong_secret() -> None:
    with pytest.raises(ValueError, match="ASSET_SIGNING_SECRET"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "PUBLIC_BASE_URL": "https://mcp.example.net",
                "ALLOW_ANONYMOUS": "true",
            }
        )

    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "DEPLOYMENT_PROFILE": "alpic-metadata",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "http://mcp.example.net",
                "ALLOW_ANONYMOUS": "true",
            }
        )


def test_public_base_url_must_be_an_origin_without_path() -> None:
    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        _ = load_config(base_env(PUBLIC_BASE_URL="https://mcp.example.net/prefix"))


def test_production_rejects_anonymous_mode_even_when_explicit() -> None:
    with pytest.raises(ValueError, match="API_BEARER_TOKEN"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "DEPLOYMENT_PROFILE": "alpic-metadata",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
            }
        )

    with pytest.raises(ValueError, match="ALLOW_ANONYMOUS"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "DEPLOYMENT_PROFILE": "alpic-metadata",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
                "ALLOW_ANONYMOUS": "true",
            }
        )


def test_production_requires_a_named_principal_registry() -> None:
    with pytest.raises(ValueError, match="API_PRINCIPALS_JSON"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "DEPLOYMENT_PROFILE": "alpic-metadata",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
                "API_KEY": "k" * 32,
                "ALLOW_ANONYMOUS": "false",
            }
        )


def test_named_principal_registry_is_strict_closed_and_secret_safe() -> None:
    token = "t" * 32
    config = load_config(
        {
            "NODE_ENV": "production",
            "DEPLOYMENT_PROFILE": "alpic-metadata",
            "ASSET_SIGNING_SECRET": "s" * 32,
            "PUBLIC_BASE_URL": "https://mcp.example.net",
            "API_PRINCIPALS_JSON": (
                '[{"principal_id":"researcher-a","bearer_token":"' + token + '"}]'
            ),
            "ALLOW_ANONYMOUS": "false",
        }
    )

    assert config.api_principals == (
        ApiPrincipalCredential(
            principal_id="researcher-a",
            bearer_token=SecretStr(token),
        ),
    )
    assert token not in repr(config.api_principals)


@pytest.mark.parametrize(
    ("credential", "message"),
    [
        pytest.param(
            "replace-with-at-least-32-random-characters",
            "documented placeholder",
            id="placeholder",
        ),
        pytest.param(
            ("x" * 31) + "\n",
            "control delimiters",
            id="newline",
        ),
        pytest.param(
            ("x" * 31) + "\x00",
            "control delimiters",
            id="nul",
        ),
    ],
)
def test_principal_credential_rejects_placeholder_and_control_delimiters(
    credential: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _ = ApiPrincipalCredential(
            principal_id="researcher",
            bearer_token=SecretStr(credential),
        )


def test_principal_credential_invariant_fails_closed_after_unsafe_construction() -> (
    None
):
    credential = ApiPrincipalCredential.model_construct(
        principal_id="researcher",
        bearer_token=None,
        api_key=None,
    )

    with pytest.raises(RuntimeError, match="invariant was violated"):
        _ = credential.credential_value()


@pytest.mark.parametrize(
    "principals_json",
    [
        pytest.param(
            '[{"principal_id":1,"bearer_token":"' + ("t" * 32) + '"}]',
            id="coercive-principal-id",
        ),
        pytest.param(
            '[{"principal_id":"researcher","bearer_token":"'
            + ("t" * 32)
            + '","unexpected":true}]',
            id="unknown-field",
        ),
        pytest.param(
            '[{"principal_id":"researcher","bearer_token":"'
            + ("t" * 32)
            + '","api_key":"'
            + ("k" * 32)
            + '"}]',
            id="ambiguous-credential",
        ),
        pytest.param(
            '[{"principal_id":"researcher","principal_id":"other","bearer_token":"'
            + ("t" * 32)
            + '"}]',
            id="duplicate-json-key",
        ),
        pytest.param("{}", id="top-level-object"),
        pytest.param("[]", id="empty-registry"),
        pytest.param(
            '[{"principal_id":"anonymous","bearer_token":"' + ("t" * 32) + '"}]',
            id="reserved-principal-id",
        ),
        pytest.param(
            '[{"principal_id":"researcher","bearer_token":"short"}]',
            id="short-credential",
        ),
        pytest.param(
            '[{"principal_id":"researcher","bearer_token":"'
            + ("t" * 32)
            + '"},{"principal_id":"researcher","api_key":"'
            + ("k" * 32)
            + '"}]',
            id="duplicate-principal-id",
        ),
        pytest.param(
            '[{"principal_id":"researcher-a","bearer_token":"'
            + ("t" * 32)
            + '"},{"principal_id":"researcher-b","bearer_token":"'
            + ("t" * 32)
            + '"}]',
            id="duplicate-credential",
        ),
    ],
)
def test_named_principal_registry_rejects_adversarial_json(
    principals_json: str,
) -> None:
    with pytest.raises(ValueError, match="API_PRINCIPALS_JSON"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "DEPLOYMENT_PROFILE": "alpic-metadata",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
                "API_PRINCIPALS_JSON": principals_json,
                "ALLOW_ANONYMOUS": "false",
            }
        )


def test_production_principal_limit_reserves_global_capacity() -> None:
    with pytest.raises(
        ValueError,
        match="MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL",
    ):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "DEPLOYMENT_PROFILE": "alpic-metadata",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
                "API_PRINCIPALS_JSON": (
                    '[{"principal_id":"researcher","api_key":"' + ("k" * 32) + '"}]'
                ),
                "MAX_CONCURRENT_MCP_REQUESTS": "4",
                "MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL": "4",
                "ALLOW_ANONYMOUS": "false",
            }
        )


def test_named_principal_registry_rejects_legacy_credential_ambiguity() -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        _ = load_config(
            base_env(
                ALLOW_ANONYMOUS="false",
                API_BEARER_TOKEN="b" * 32,
                API_PRINCIPALS_JSON=(
                    '[{"principal_id":"researcher","api_key":"' + ("k" * 32) + '"}]'
                ),
            )
        )


def test_alpic_host_does_not_select_a_deployment_profile() -> None:
    config = load_config(
        {
            "NODE_ENV": "production",
            "ALPIC_HOST": "mcp.example.net",
            "ASSET_SIGNING_SECRET": "s" * 32,
            "API_PRINCIPALS_JSON": (
                '[{"principal_id":"researcher","api_key":"' + ("k" * 32) + '"}]'
            ),
            "ALLOW_ANONYMOUS": "false",
            "DEPLOYMENT_PROFILE": "private-full",
            "PDF_EXECUTOR": "unix-worker",
            "PRIVATE_EDGE_TLS": "true",
        }
    )

    assert config.deployment_profile == "private-full"


def test_alpic_host_requires_explicit_production_security_settings() -> None:
    with pytest.raises(ValueError, match=r"ALPIC_HOST.*NODE_ENV=production"):
        _ = load_config(
            {
                "ALPIC_HOST": "audit.example",
                "ASSET_SIGNING_SECRET": "s" * 32,
            }
        )


def test_anonymous_access_requires_an_explicit_opt_in() -> None:
    with pytest.raises(ValueError, match="API_BEARER_TOKEN or API_KEY"):
        _ = load_config(
            {
                "NODE_ENV": "test",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
            }
        )


@pytest.mark.parametrize(
    ("public_base_url", "host"),
    [
        pytest.param("https://mcp.example.net", "127.0.0.1", id="public-origin"),
        pytest.param("http://127.0.0.1:8000", _ALL_INTERFACES_HOST, id="wildcard-bind"),
        pytest.param("http://127.0.0.1:8000", "192.0.2.1", id="public-bind"),
    ],
)
def test_anonymous_access_rejects_non_loopback_network_scope(
    public_base_url: str,
    host: str,
) -> None:
    with pytest.raises(ValueError, match=r"ALLOW_ANONYMOUS.*loopback"):
        _ = load_config(
            base_env(
                PUBLIC_BASE_URL=public_base_url,
                HOST=host,
            )
        )


@pytest.mark.parametrize(
    ("public_base_url", "host"),
    [
        pytest.param("http://127.0.0.1:8000", "127.0.0.1", id="ipv4"),
        pytest.param("http://[::1]:8000", "::1", id="ipv6"),
        pytest.param("http://localhost:8000", "localhost", id="localhost"),
    ],
)
def test_explicit_anonymous_development_accepts_only_loopback_network_scope(
    public_base_url: str,
    host: str,
) -> None:
    config = load_config(
        base_env(
            PUBLIC_BASE_URL=public_base_url,
            HOST=host,
        )
    )

    assert config.allow_anonymous is True


@pytest.mark.parametrize("credential_name", ["API_BEARER_TOKEN", "API_KEY"])
def test_signing_secret_must_not_be_reused_as_an_api_credential(
    credential_name: str,
) -> None:
    shared_secret = "z" * 32

    with pytest.raises(ValueError, match=f"ASSET_SIGNING_SECRET.*{credential_name}"):
        _ = load_config(
            base_env(
                ASSET_SIGNING_SECRET=shared_secret,
                ALLOW_ANONYMOUS="false",
                **{credential_name: shared_secret},
            )
        )


def test_production_requires_an_explicit_deployment_profile() -> None:
    with pytest.raises(ValueError, match="DEPLOYMENT_PROFILE"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
                "API_BEARER_TOKEN": "t" * 32,
                "ALLOW_ANONYMOUS": "false",
            }
        )


@pytest.mark.parametrize(
    "profile",
    ["alpic-metadata", "distributed-full", "private-full"],
)
def test_deployment_profile_accepts_only_closed_values(profile: str) -> None:
    config = load_config(base_env(DEPLOYMENT_PROFILE=profile))

    assert config.deployment_profile == profile

    with pytest.raises(ValueError, match="DEPLOYMENT_PROFILE"):
        _ = load_config(base_env(DEPLOYMENT_PROFILE=f"{profile}-suffix"))


@pytest.mark.parametrize("environment", ["development", "test", "production"])
def test_protected_mode_always_requires_a_bearer_token(environment: str) -> None:
    public_url = (
        "https://mcp.example.net"
        if environment == "production"
        else "http://testserver"
    )
    with pytest.raises(ValueError, match="API_BEARER_TOKEN"):
        _ = load_config(
            {
                "NODE_ENV": environment,
                "DEPLOYMENT_PROFILE": "alpic-metadata",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": public_url,
                "ALLOW_ANONYMOUS": "false",
            }
        )


def test_protected_mode_accepts_a_strong_api_key_without_a_bearer_token() -> None:
    config = load_config(base_env(ALLOW_ANONYMOUS="false", API_KEY="k" * 32))

    assert config.allow_anonymous is False
    assert config.api_bearer_token is None
    assert config.api_key == "k" * 32


def test_api_key_must_be_strong_when_configured() -> None:
    with pytest.raises(ValueError, match="API_KEY"):
        _ = load_config(base_env(API_KEY="short"))


def test_unknown_boolean_is_rejected_instead_of_treated_as_false() -> None:
    with pytest.raises(ValueError, match="ALLOW_ANONYMOUS"):
        _ = load_config(base_env(ALLOW_ANONYMOUS="sometimes"))


def test_pdf_worker_concurrency_is_bounded() -> None:
    config = load_config(base_env())

    assert config.pdf_executor == "serialized"
    assert config.max_concurrent_pdf_jobs == 1

    with pytest.raises(ValueError, match="must equal 1"):
        _ = load_config(
            base_env(PDF_EXECUTOR="serialized", MAX_CONCURRENT_PDF_JOBS="2")
        )

    with pytest.raises(ValueError, match="MAX_CONCURRENT_PDF_JOBS"):
        _ = load_config(base_env(MAX_CONCURRENT_PDF_JOBS="0"))
    with pytest.raises(ValueError, match="MAX_CONCURRENT_PDF_JOBS"):
        _ = load_config(base_env(MAX_CONCURRENT_PDF_JOBS="9"))


def test_serialized_pdf_backend_rejects_parallelism() -> None:
    env = base_environment(
        MAX_CONCURRENT_PDF_JOBS="2",
        PDF_EXECUTOR="serialized",
    )

    with pytest.raises(ValueError, match="must equal 1"):
        _ = load_config(env)


@pytest.mark.parametrize("value", ["0", "65"])
def test_mcp_request_concurrency_is_bounded(value: str) -> None:
    with pytest.raises(ValueError, match="MAX_CONCURRENT_MCP_REQUESTS"):
        _ = load_config(base_env(MAX_CONCURRENT_MCP_REQUESTS=value))


@pytest.mark.parametrize("value", ["0", "65"])
def test_per_principal_request_concurrency_is_bounded(value: str) -> None:
    with pytest.raises(
        ValueError,
        match="MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL",
    ):
        _ = load_config(base_env(MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL=value))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MAX_CONCURRENT_ASSET_STREAMS", "0"),
        ("MAX_CONCURRENT_ASSET_STREAMS", "65"),
        ("MAX_CONCURRENT_HTTP_REQUESTS", "0"),
        ("MAX_CONCURRENT_HTTP_REQUESTS", "1025"),
    ],
)
def test_http_and_asset_concurrency_are_bounded(name: str, value: str) -> None:
    with pytest.raises(ValueError, match=name):
        _ = load_config(base_env(**{name: value}))


def test_cache_quota_must_be_positive() -> None:
    with pytest.raises(ValueError, match="CACHE_MAX_BYTES"):
        _ = load_config(base_env(CACHE_MAX_BYTES="0"))


@pytest.mark.parametrize("value", ["0", "61"])
def test_request_body_timeout_is_bounded(value: str) -> None:
    with pytest.raises(ValueError, match="REQUEST_BODY_TIMEOUT_SECONDS"):
        _ = load_config(base_env(REQUEST_BODY_TIMEOUT_SECONDS=value))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ASSET_STREAM_IDLE_TIMEOUT_SECONDS", "0"),
        ("ASSET_STREAM_IDLE_TIMEOUT_SECONDS", "61"),
        ("ASSET_STREAM_TOTAL_TIMEOUT_SECONDS", "0"),
        ("ASSET_STREAM_TOTAL_TIMEOUT_SECONDS", "601"),
    ],
)
def test_asset_stream_timeouts_are_bounded(name: str, value: str) -> None:
    with pytest.raises(ValueError, match=name):
        _ = load_config(base_env(**{name: value}))


def test_asset_stream_total_timeout_cannot_be_shorter_than_idle_timeout() -> None:
    with pytest.raises(ValueError, match="ASSET_STREAM_TOTAL_TIMEOUT_SECONDS"):
        _ = load_config(
            base_env(
                ASSET_STREAM_IDLE_TIMEOUT_SECONDS="30",
                ASSET_STREAM_TOTAL_TIMEOUT_SECONDS="20",
            )
        )


@pytest.mark.parametrize(
    "field", ["ASSET_SIGNING_SECRET", "API_BEARER_TOKEN", "API_KEY"]
)
def test_production_rejects_documented_placeholder_secrets(field: str) -> None:
    placeholder = "replace-with-at-least-32-random-characters"
    env = {
        "NODE_ENV": "production",
        "DEPLOYMENT_PROFILE": "alpic-metadata",
        "ASSET_SIGNING_SECRET": "s" * 32,
        "API_BEARER_TOKEN": "t" * 32,
        "API_KEY": "k" * 32,
        "PUBLIC_BASE_URL": "https://mcp.example.net",
        "ALLOW_ANONYMOUS": "false",
    }
    env[field] = placeholder

    with pytest.raises(ValueError, match=field):
        _ = load_config(env)


def test_alpic_host_supplies_public_origin_and_ephemeral_cache_defaults() -> None:
    config = load_config(
        {
            "NODE_ENV": "production",
            "ALPIC_HOST": "nplg-dspace-mcp-abc123.alpic.live",
            "ASSET_SIGNING_SECRET": "s" * 32,
            "API_PRINCIPALS_JSON": (
                '[{"principal_id":"researcher","api_key":"' + ("k" * 32) + '"}]'
            ),
            "ALLOW_ANONYMOUS": "false",
            "DEPLOYMENT_PROFILE": "alpic-metadata",
        }
    )

    assert config.public_base_url == "https://nplg-dspace-mcp-abc123.alpic.live"
    assert config.cache_dir == _ALPIC_CACHE_DIR
    assert config.api_principals[0].api_key_value() == "k" * 32


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("MAX_RENDER_PAGES", "not-an-integer", "must be an integer"),
        ("UPSTREAM_TIMEOUT_SECONDS", "not-a-number", "must be a number"),
    ],
)
def test_non_numeric_limit_text_is_rejected(
    name: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _ = load_config(base_env(**{name: value}))


def test_only_the_serialized_pdf_executor_is_accepted() -> None:
    with pytest.raises(ValueError, match="PDF_EXECUTOR must be serialized"):
        _ = load_config(base_env(PDF_EXECUTOR="threaded"))


@pytest.mark.parametrize(
    "public_base_url",
    [
        "https://user@mcp.example.net",
        "https://mcp.example.net?credential=secret",
        "https://mcp.example.net#fragment",
    ],
)
def test_public_base_url_rejects_credential_and_request_components(
    public_base_url: str,
) -> None:
    with pytest.raises(ValueError, match="origin without credentials"):
        _ = load_config(base_env(PUBLIC_BASE_URL=public_base_url))


def test_public_base_url_requires_a_hostname() -> None:
    with pytest.raises(ValueError, match="include a hostname"):
        _ = load_config(base_env(PUBLIC_BASE_URL="https://"))


def test_unknown_environment_is_rejected_before_environment_specific_defaults() -> None:
    with pytest.raises(ValueError, match="NODE_ENV"):
        _ = load_config(base_env(NODE_ENV="staging"))


def test_configured_bearer_token_must_be_strong() -> None:
    with pytest.raises(ValueError, match="API_BEARER_TOKEN must be at least"):
        _ = load_config(
            base_env(
                ALLOW_ANONYMOUS="false",
                API_BEARER_TOKEN=str(0),
            )
        )


def test_mcp_allowed_hosts_are_strict_canonical_values() -> None:
    """The transport receives only the exact canonical host authorities."""
    configured = load_config(
        base_env(NPLG_MCP_ALLOWED_HOSTS_JSON='["127.0.0.1:9000","mcp.example.test"]')
    )

    assert configured.mcp_allowed_hosts == (
        "127.0.0.1:9000",
        "mcp.example.test",
    )

    for value in (
        "*.example.test",
        "MCP.example.test",
        "mcp.example.test/",
        "mcp.example.test:08000",
        "user@mcp.example.test",
        "[fe80::1%25eth0]",
    ):
        with pytest.raises(ValueError, match="MCP allowed host"):
            _ = load_config(base_env(NPLG_MCP_ALLOWED_HOSTS_JSON=f'["{value}"]'))


def test_mcp_allowed_hosts_reject_duplicates_and_empty_lists() -> None:
    """The Host allowlist is nonempty and duplicate aliases are never collapsed."""
    with pytest.raises(ValueError, match="must not be empty"):
        _ = load_config(base_env(NPLG_MCP_ALLOWED_HOSTS_JSON="[]"))
    with pytest.raises(ValueError, match="duplicates"):
        _ = load_config(
            base_env(
                NPLG_MCP_ALLOWED_HOSTS_JSON=('["mcp.example.test","mcp.example.test"]')
            )
        )


def test_mcp_allowed_origins_are_strict_canonical_values() -> None:
    """Only exact HTTPS origins or explicit development loopback HTTP are admitted."""
    configured = load_config(
        base_env(
            NPLG_MCP_ALLOWED_ORIGINS_JSON=(
                '["https://mcp.example.test","http://127.0.0.1:9000"]'
            )
        )
    )
    assert configured.mcp_allowed_origins == (
        "https://mcp.example.test",
        "http://127.0.0.1:9000",
    )

    for value in (
        "https://user@mcp.example.test",
        "https://mcp.example.test/",
        "https://mcp.example.test?x=1",
        "https://MCP.example.test",
        "http://mcp.example.test",
    ):
        with pytest.raises(ValueError, match="MCP allowed origin"):
            _ = load_config(base_env(NPLG_MCP_ALLOWED_ORIGINS_JSON=f'["{value}"]'))


def test_mcp_allowed_origins_reject_duplicates() -> None:
    """Duplicate exact origins are rejected rather than silently deduplicated."""
    with pytest.raises(ValueError, match="duplicates"):
        _ = load_config(
            base_env(
                NPLG_MCP_ALLOWED_ORIGINS_JSON=(
                    '["https://mcp.example.test","https://mcp.example.test"]'
                )
            )
        )


def test_transport_security_settings_exactly_match_config() -> None:
    """SDK DNS-rebinding policy is built from the same immutable allowlists."""
    configured = load_config(
        base_env(
            NPLG_MCP_ALLOWED_HOSTS_JSON='["mcp.example.test"]',
            NPLG_MCP_ALLOWED_ORIGINS_JSON='["https://mcp.example.test"]',
        )
    )

    settings = build_transport_security_settings(configured)

    assert settings.enable_dns_rebinding_protection is True
    assert settings.allowed_hosts == ["mcp.example.test"]
    assert settings.allowed_origins == ["https://mcp.example.test"]
