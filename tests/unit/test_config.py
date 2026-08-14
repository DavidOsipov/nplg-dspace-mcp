from pathlib import Path

import pytest

from nplg_mcp.config import HARD_MAX_DOWNLOAD_BYTES, AppConfig, load_config


def base_env(**overrides: str) -> dict[str, str]:
    env = {
        "NODE_ENV": "test",
        "ASSET_SIGNING_SECRET": "s" * 32,
        "PUBLIC_BASE_URL": "http://testserver",
        "ALLOW_ANONYMOUS": "true",
        "CACHE_DIR": "/tmp/nplg-test-cache",
    }
    env.update(overrides)
    return env


def test_defaults_are_bounded_and_point_only_to_nplg() -> None:
    config = load_config(base_env())

    assert isinstance(config, AppConfig)
    assert config.nplg_base_url == "https://dspace.nplg.gov.ge/"
    assert config.max_download_bytes == HARD_MAX_DOWNLOAD_BYTES
    assert config.max_render_pages == 8
    assert config.max_page_pixels == 120_000_000
    assert config.max_render_pixels == 480_000_000
    assert config.tile_width == 2048
    assert config.tile_height == 2048
    assert config.tile_overlap == 128
    assert config.cache_dir == Path("/tmp/nplg-test-cache")
    assert config.max_concurrent_mcp_requests == 16
    assert config.max_concurrent_asset_streams == 8
    assert config.max_concurrent_http_requests == 128
    assert config.cache_max_bytes == 20 * 1024 * 1024 * 1024
    assert config.request_body_timeout_seconds == 10.0


def test_foreign_repository_base_url_is_rejected() -> None:
    with pytest.raises(ValueError, match="NPLG_BASE_URL"):
        load_config(base_env(NPLG_BASE_URL="https://example.com/"))


def test_download_limit_cannot_exceed_compiled_ceiling() -> None:
    with pytest.raises(ValueError, match="MAX_DOWNLOAD_BYTES"):
        load_config(base_env(MAX_DOWNLOAD_BYTES=str(HARD_MAX_DOWNLOAD_BYTES + 1)))


def test_tile_overlap_must_leave_positive_stride() -> None:
    with pytest.raises(ValueError, match="TILE_OVERLAP"):
        load_config(base_env(TILE_WIDTH="512", TILE_HEIGHT="512", TILE_OVERLAP="512"))


def test_tile_geometry_cannot_exceed_compiled_ceilings() -> None:
    with pytest.raises(ValueError, match="TILE_WIDTH"):
        load_config(base_env(TILE_WIDTH="4097"))
    with pytest.raises(ValueError, match="TILE_HEIGHT"):
        load_config(base_env(TILE_HEIGHT="4097"))
    with pytest.raises(ValueError, match="TILE_OVERLAP"):
        load_config(base_env(TILE_OVERLAP="513"))


def test_production_requires_stable_public_url_and_strong_secret() -> None:
    with pytest.raises(ValueError, match="ASSET_SIGNING_SECRET"):
        load_config({
            "NODE_ENV": "production",
            "PUBLIC_BASE_URL": "https://mcp.example.net",
            "ALLOW_ANONYMOUS": "true",
        })

    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        load_config({
            "NODE_ENV": "production",
            "ASSET_SIGNING_SECRET": "s" * 32,
            "PUBLIC_BASE_URL": "http://mcp.example.net",
            "ALLOW_ANONYMOUS": "true",
        })



def test_public_base_url_must_be_an_origin_without_path() -> None:
    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        load_config(base_env(PUBLIC_BASE_URL="https://mcp.example.net/prefix"))

def test_production_requires_bearer_token_unless_anonymous_is_explicit() -> None:
    with pytest.raises(ValueError, match="API_BEARER_TOKEN"):
        load_config({
            "NODE_ENV": "production",
            "ASSET_SIGNING_SECRET": "s" * 32,
            "PUBLIC_BASE_URL": "https://mcp.example.net",
        })

    config = load_config({
        "NODE_ENV": "production",
        "ASSET_SIGNING_SECRET": "s" * 32,
        "PUBLIC_BASE_URL": "https://mcp.example.net",
        "ALLOW_ANONYMOUS": "true",
    })
    assert config.allow_anonymous is True
    assert config.api_bearer_token is None


@pytest.mark.parametrize("environment", ["development", "test", "production"])
def test_protected_mode_always_requires_a_bearer_token(environment: str) -> None:
    public_url = "https://mcp.example.net" if environment == "production" else "http://testserver"
    with pytest.raises(ValueError, match="API_BEARER_TOKEN"):
        load_config(
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
        load_config(base_env(API_KEY="short"))


def test_unknown_boolean_is_rejected_instead_of_treated_as_false() -> None:
    with pytest.raises(ValueError, match="ALLOW_ANONYMOUS"):
        load_config(base_env(ALLOW_ANONYMOUS="sometimes"))


def test_pdf_worker_concurrency_is_bounded() -> None:
    assert load_config(base_env()).max_concurrent_pdf_jobs == 2

    with pytest.raises(ValueError, match="MAX_CONCURRENT_PDF_JOBS"):
        load_config(base_env(MAX_CONCURRENT_PDF_JOBS="0"))
    with pytest.raises(ValueError, match="MAX_CONCURRENT_PDF_JOBS"):
        load_config(base_env(MAX_CONCURRENT_PDF_JOBS="9"))


@pytest.mark.parametrize("value", ["0", "65"])
def test_mcp_request_concurrency_is_bounded(value: str) -> None:
    with pytest.raises(ValueError, match="MAX_CONCURRENT_MCP_REQUESTS"):
        load_config(base_env(MAX_CONCURRENT_MCP_REQUESTS=value))


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
        load_config(base_env(**{name: value}))


def test_cache_quota_must_be_positive() -> None:
    with pytest.raises(ValueError, match="CACHE_MAX_BYTES"):
        load_config(base_env(CACHE_MAX_BYTES="0"))


@pytest.mark.parametrize("value", ["0", "61"])
def test_request_body_timeout_is_bounded(value: str) -> None:
    with pytest.raises(ValueError, match="REQUEST_BODY_TIMEOUT_SECONDS"):
        load_config(base_env(REQUEST_BODY_TIMEOUT_SECONDS=value))

@pytest.mark.parametrize("field", ["ASSET_SIGNING_SECRET", "API_BEARER_TOKEN", "API_KEY"])
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
        load_config(env)


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
    assert config.cache_dir == Path("/tmp/nplg-dspace-mcp-cache")
    assert config.api_key == "k" * 32
