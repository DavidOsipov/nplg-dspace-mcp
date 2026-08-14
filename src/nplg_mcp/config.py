from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

NPLG_BASE_URL = "https://dspace.nplg.gov.ge/"
HARD_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
HARD_MAX_RENDER_PAGES = 8
HARD_MAX_PAGE_PIXELS = 120_000_000
HARD_MAX_RENDER_PIXELS = 480_000_000
HARD_MAX_REQUEST_BODY_BYTES = 1_048_576
DEFAULT_CACHE_MAX_BYTES = 20 * 1024 * 1024 * 1024
HARD_MAX_CACHE_BYTES = 1024 * 1024 * 1024 * 1024
HARD_MAX_TILE_DIMENSION = 4096
HARD_MAX_TILE_OVERLAP = 512
_DOCUMENTED_PLACEHOLDER = "replace-with-at-least-32-random-characters"


@dataclass(frozen=True, slots=True)
class AppConfig:
    environment: str
    nplg_base_url: str
    cache_dir: Path
    public_base_url: str
    asset_signing_secret: bytes
    api_bearer_token: str | None
    api_key: str | None
    allow_anonymous: bool
    max_download_bytes: int
    max_render_pages: int
    max_page_pixels: int
    max_render_pixels: int
    max_request_body_bytes: int
    tile_width: int
    tile_height: int
    tile_overlap: int
    asset_ttl_seconds: int
    upstream_timeout_seconds: float
    upstream_rate_per_second: float
    max_redirects: int
    max_concurrent_pdf_jobs: int = 2
    max_concurrent_mcp_requests: int = 16
    max_concurrent_asset_streams: int = 8
    max_concurrent_http_requests: int = 128
    cache_max_bytes: int = DEFAULT_CACHE_MAX_BYTES
    request_body_timeout_seconds: float = 10.0


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _int(
    env: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = env.get(name)
    try:
        value = default if raw is None else int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _float(
    env: Mapping[str, str],
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    raw = env.get(name)
    try:
        value = default if raw is None else float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _normalize_public_base_url(value: str, *, production: bool) -> str:
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("PUBLIC_BASE_URL must be an origin without credentials, query, or fragment")
    if parsed.scheme not in ({"https"} if production else {"http", "https"}):
        raise ValueError("PUBLIC_BASE_URL must use HTTPS in production")
    if not parsed.hostname:
        raise ValueError("PUBLIC_BASE_URL must include a hostname")
    if parsed.path not in {"", "/"}:
        raise ValueError("PUBLIC_BASE_URL must be an origin without a path")
    return f"{parsed.scheme}://{parsed.netloc}"


def load_config(env: Mapping[str, str]) -> AppConfig:
    environment = env.get("NODE_ENV", env.get("ENVIRONMENT", "development")).strip().lower()
    if environment not in {"development", "test", "production"}:
        raise ValueError("NODE_ENV must be development, test, or production")
    production = environment == "production"

    nplg_base_url = env.get("NPLG_BASE_URL", NPLG_BASE_URL)
    if nplg_base_url != NPLG_BASE_URL:
        raise ValueError(f"NPLG_BASE_URL must be exactly {NPLG_BASE_URL}")

    secret = env.get("ASSET_SIGNING_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("ASSET_SIGNING_SECRET must be at least 32 bytes")
    if production and secret == _DOCUMENTED_PLACEHOLDER:
        raise ValueError("ASSET_SIGNING_SECRET must be replaced before production deployment")

    configured_public_base_url = env.get("PUBLIC_BASE_URL")
    alpic_host = env.get("ALPIC_HOST", "").strip()
    if configured_public_base_url is None and alpic_host:
        configured_public_base_url = alpic_host if "://" in alpic_host else f"https://{alpic_host}"
    public_base_url = _normalize_public_base_url(
        configured_public_base_url or "http://127.0.0.1:8000",
        production=production,
    )
    allow_anonymous = _bool(env, "ALLOW_ANONYMOUS", not production)
    api_bearer_token = env.get("API_BEARER_TOKEN") or None
    if api_bearer_token is not None and len(api_bearer_token.encode("utf-8")) < 32:
        raise ValueError("API_BEARER_TOKEN must be at least 32 bytes")
    if production and api_bearer_token == _DOCUMENTED_PLACEHOLDER:
        raise ValueError("API_BEARER_TOKEN must be replaced before production deployment")
    api_key = env.get("API_KEY") or None
    if api_key is not None and len(api_key.encode("utf-8")) < 32:
        raise ValueError("API_KEY must be at least 32 bytes")
    if production and api_key == _DOCUMENTED_PLACEHOLDER:
        raise ValueError("API_KEY must be replaced before production deployment")
    if not allow_anonymous and api_bearer_token is None and api_key is None:
        raise ValueError("API_BEARER_TOKEN or API_KEY is required unless ALLOW_ANONYMOUS=true")

    tile_width = _int(env, "TILE_WIDTH", 2048, minimum=256, maximum=HARD_MAX_TILE_DIMENSION)
    tile_height = _int(env, "TILE_HEIGHT", 2048, minimum=256, maximum=HARD_MAX_TILE_DIMENSION)
    tile_overlap = _int(env, "TILE_OVERLAP", 128, minimum=0, maximum=HARD_MAX_TILE_OVERLAP)
    if tile_overlap >= min(tile_width, tile_height):
        raise ValueError("TILE_OVERLAP must be smaller than both tile dimensions")

    return AppConfig(
        environment=environment,
        nplg_base_url=nplg_base_url,
        cache_dir=Path(
            env.get(
                "CACHE_DIR",
                "/tmp/nplg-dspace-mcp-cache" if alpic_host else ".data/cache",
            )
        ),
        public_base_url=public_base_url,
        asset_signing_secret=secret.encode("utf-8"),
        api_bearer_token=api_bearer_token,
        api_key=api_key,
        allow_anonymous=allow_anonymous,
        max_download_bytes=_int(
            env,
            "MAX_DOWNLOAD_BYTES",
            HARD_MAX_DOWNLOAD_BYTES,
            minimum=1_048_576,
            maximum=HARD_MAX_DOWNLOAD_BYTES,
        ),
        max_render_pages=_int(
            env,
            "MAX_RENDER_PAGES",
            HARD_MAX_RENDER_PAGES,
            minimum=1,
            maximum=HARD_MAX_RENDER_PAGES,
        ),
        max_page_pixels=_int(
            env,
            "MAX_PAGE_PIXELS",
            HARD_MAX_PAGE_PIXELS,
            minimum=1_000_000,
            maximum=HARD_MAX_PAGE_PIXELS,
        ),
        max_render_pixels=_int(
            env,
            "MAX_RENDER_PIXELS",
            HARD_MAX_RENDER_PIXELS,
            minimum=1_000_000,
            maximum=HARD_MAX_RENDER_PIXELS,
        ),
        max_request_body_bytes=_int(
            env,
            "MAX_REQUEST_BODY_BYTES",
            HARD_MAX_REQUEST_BODY_BYTES,
            minimum=1024,
            maximum=HARD_MAX_REQUEST_BODY_BYTES,
        ),
        tile_width=tile_width,
        tile_height=tile_height,
        tile_overlap=tile_overlap,
        asset_ttl_seconds=_int(env, "ASSET_TTL_SECONDS", 3600, minimum=60, maximum=86_400),
        upstream_timeout_seconds=_float(
            env,
            "UPSTREAM_TIMEOUT_SECONDS",
            30.0,
            minimum=1.0,
            maximum=120.0,
        ),
        upstream_rate_per_second=_float(
            env,
            "UPSTREAM_RATE_PER_SECOND",
            1.0,
            minimum=0.1,
            maximum=5.0,
        ),
        max_redirects=_int(env, "MAX_REDIRECTS", 3, minimum=0, maximum=5),
        max_concurrent_pdf_jobs=_int(
            env,
            "MAX_CONCURRENT_PDF_JOBS",
            2,
            minimum=1,
            maximum=4,
        ),
        max_concurrent_mcp_requests=_int(
            env,
            "MAX_CONCURRENT_MCP_REQUESTS",
            16,
            minimum=1,
            maximum=64,
        ),
        max_concurrent_asset_streams=_int(
            env,
            "MAX_CONCURRENT_ASSET_STREAMS",
            8,
            minimum=1,
            maximum=64,
        ),
        max_concurrent_http_requests=_int(
            env,
            "MAX_CONCURRENT_HTTP_REQUESTS",
            128,
            minimum=1,
            maximum=1024,
        ),
        cache_max_bytes=_int(
            env,
            "CACHE_MAX_BYTES",
            DEFAULT_CACHE_MAX_BYTES,
            minimum=1,
            maximum=HARD_MAX_CACHE_BYTES,
        ),
        request_body_timeout_seconds=_float(
            env,
            "REQUEST_BODY_TIMEOUT_SECONDS",
            10.0,
            minimum=1.0,
            maximum=60.0,
        ),
    )
