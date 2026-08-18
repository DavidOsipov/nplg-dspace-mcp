# Copyright (c) 2026 David Osipov
"""Unit tests for strict application configuration."""

from pathlib import Path

import pytest

from nplg_mcp.config import HARD_MAX_DOWNLOAD_BYTES, AppConfig, load_config
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


def base_env(**overrides: str) -> dict[str, str]:
    env = {
        "NODE_ENV": "test",
        "ASSET_SIGNING_SECRET": "s" * 32,
        "PUBLIC_BASE_URL": "http://testserver",
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
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "http://mcp.example.net",
                "ALLOW_ANONYMOUS": "true",
            }
        )


def test_public_base_url_must_be_an_origin_without_path() -> None:
    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        _ = load_config(base_env(PUBLIC_BASE_URL="https://mcp.example.net/prefix"))


def test_production_requires_bearer_token_unless_anonymous_is_explicit() -> None:
    with pytest.raises(ValueError, match="API_BEARER_TOKEN"):
        _ = load_config(
            {
                "NODE_ENV": "production",
                "ASSET_SIGNING_SECRET": "s" * 32,
                "PUBLIC_BASE_URL": "https://mcp.example.net",
            }
        )

    config = load_config(
        {
            "NODE_ENV": "production",
            "ASSET_SIGNING_SECRET": "s" * 32,
            "PUBLIC_BASE_URL": "https://mcp.example.net",
            "ALLOW_ANONYMOUS": "true",
        }
    )
    assert config.allow_anonymous is True
    assert config.api_bearer_token is None


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
    "field", ["ASSET_SIGNING_SECRET", "API_BEARER_TOKEN", "API_KEY"]
)
def test_production_rejects_documented_placeholder_secrets(field: str) -> None:
    placeholder = "replace-with-at-least-32-random-characters"
    env = {
        "NODE_ENV": "production",
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
            "API_KEY": "k" * 32,
            "ALLOW_ANONYMOUS": "false",
        }
    )

    assert config.public_base_url == "https://nplg-dspace-mcp-abc123.alpic.live"
    assert config.cache_dir == _ALPIC_CACHE_DIR
    assert config.api_key == "k" * 32


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
