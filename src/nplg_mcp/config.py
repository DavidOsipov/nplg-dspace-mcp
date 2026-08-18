# Copyright (c) 2026 David Osipov
"""Strict environment-backed application configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping

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
_MIN_CREDENTIAL_BYTES = 32
PdfExecutor = Literal["serialized"]


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Validated application settings derived from environment text."""

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
    pdf_executor: PdfExecutor = "serialized"
    max_concurrent_pdf_jobs: int = 1
    max_concurrent_mcp_requests: int = 16
    max_concurrent_asset_streams: int = 8
    max_concurrent_http_requests: int = 128
    cache_max_bytes: int = DEFAULT_CACHE_MAX_BYTES
    request_body_timeout_seconds: float = 10.0


def _bool(env: Mapping[str, str], name: str, *, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    msg = f"{name} must be a boolean"
    raise ValueError(msg)


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
        msg = f"{name} must be an integer"
        raise ValueError(msg) from exc
    if not minimum <= value <= maximum:
        msg = f"{name} must be between {minimum} and {maximum}"
        raise ValueError(msg)
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
        msg = f"{name} must be a number"
        raise ValueError(msg) from exc
    if not minimum <= value <= maximum:
        msg = f"{name} must be between {minimum} and {maximum}"
        raise ValueError(msg)
    return value


def _pdf_executor(env: Mapping[str, str]) -> PdfExecutor:
    value = env.get("PDF_EXECUTOR", "serialized").strip().lower()
    if value != "serialized":
        msg = "PDF_EXECUTOR must be serialized"
        raise ValueError(msg)
    return "serialized"


def _normalize_public_base_url(value: str, *, production: bool) -> str:
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        msg = (
            "PUBLIC_BASE_URL must be an origin without credentials, query, or fragment"
        )
        raise ValueError(msg)
    if parsed.scheme not in ({"https"} if production else {"http", "https"}):
        msg = "PUBLIC_BASE_URL must use HTTPS in production"
        raise ValueError(msg)
    if not parsed.hostname:
        msg = "PUBLIC_BASE_URL must include a hostname"
        raise ValueError(msg)
    if parsed.path not in {"", "/"}:
        msg = "PUBLIC_BASE_URL must be an origin without a path"
        raise ValueError(msg)
    return f"{parsed.scheme}://{parsed.netloc}"


def _environment(env: Mapping[str, str]) -> str:
    environment = (
        env.get("NODE_ENV", env.get("ENVIRONMENT", "development")).strip().lower()
    )
    if environment not in {"development", "test", "production"}:
        msg = "NODE_ENV must be development, test, or production"
        raise ValueError(msg)
    return environment


def _signing_secret(env: Mapping[str, str], *, production: bool) -> bytes:
    secret = env.get("ASSET_SIGNING_SECRET", "")
    secret_bytes = secret.encode("utf-8")
    if len(secret_bytes) < _MIN_CREDENTIAL_BYTES:
        msg = "ASSET_SIGNING_SECRET must be at least 32 bytes"
        raise ValueError(msg)
    if production and secret == _DOCUMENTED_PLACEHOLDER:
        msg = "ASSET_SIGNING_SECRET must be replaced before production deployment"
        raise ValueError(msg)
    return secret_bytes


def _authorization(
    env: Mapping[str, str],
    *,
    production: bool,
) -> tuple[str | None, str | None, bool]:
    allow_anonymous = _bool(
        env,
        "ALLOW_ANONYMOUS",
        default=not production,
    )
    api_bearer_token = env.get("API_BEARER_TOKEN") or None
    if (
        api_bearer_token is not None
        and len(api_bearer_token.encode("utf-8")) < _MIN_CREDENTIAL_BYTES
    ):
        msg = "API_BEARER_TOKEN must be at least 32 bytes"
        raise ValueError(msg)
    if production and api_bearer_token == _DOCUMENTED_PLACEHOLDER:
        msg = "API_BEARER_TOKEN must be replaced before production deployment"
        raise ValueError(msg)
    api_key = env.get("API_KEY") or None
    if api_key is not None and len(api_key.encode("utf-8")) < _MIN_CREDENTIAL_BYTES:
        msg = "API_KEY must be at least 32 bytes"
        raise ValueError(msg)
    if production and api_key == _DOCUMENTED_PLACEHOLDER:
        msg = "API_KEY must be replaced before production deployment"
        raise ValueError(msg)
    if not allow_anonymous and api_bearer_token is None and api_key is None:
        msg = "API_BEARER_TOKEN or API_KEY is required unless ALLOW_ANONYMOUS=true"
        raise ValueError(msg)
    return api_bearer_token, api_key, allow_anonymous


def _tile_geometry(env: Mapping[str, str]) -> tuple[int, int, int]:
    tile_width = _int(
        env, "TILE_WIDTH", 2048, minimum=256, maximum=HARD_MAX_TILE_DIMENSION
    )
    tile_height = _int(
        env, "TILE_HEIGHT", 2048, minimum=256, maximum=HARD_MAX_TILE_DIMENSION
    )
    tile_overlap = _int(
        env, "TILE_OVERLAP", 128, minimum=0, maximum=HARD_MAX_TILE_OVERLAP
    )
    if tile_overlap >= min(tile_width, tile_height):
        msg = "TILE_OVERLAP must be smaller than both tile dimensions"
        raise ValueError(msg)
    return tile_width, tile_height, tile_overlap


def _pdf_settings(env: Mapping[str, str]) -> tuple[PdfExecutor, int]:
    pdf_executor = _pdf_executor(env)
    max_concurrent_pdf_jobs = _int(
        env,
        "MAX_CONCURRENT_PDF_JOBS",
        1,
        minimum=1,
        maximum=4,
    )
    if max_concurrent_pdf_jobs != 1:
        msg = "MAX_CONCURRENT_PDF_JOBS must equal 1 for serialized PDF_EXECUTOR"
        raise ValueError(msg)
    return pdf_executor, max_concurrent_pdf_jobs


def load_config(env: Mapping[str, str]) -> AppConfig:
    """Parse and validate a complete application configuration."""
    environment = _environment(env)
    production = environment == "production"

    nplg_base_url = env.get("NPLG_BASE_URL", NPLG_BASE_URL)
    if nplg_base_url != NPLG_BASE_URL:
        msg = f"NPLG_BASE_URL must be exactly {NPLG_BASE_URL}"
        raise ValueError(msg)
    secret = _signing_secret(env, production=production)

    configured_public_base_url = env.get("PUBLIC_BASE_URL")
    alpic_host = env.get("ALPIC_HOST", "").strip()
    if configured_public_base_url is None and alpic_host:
        configured_public_base_url = (
            alpic_host if "://" in alpic_host else f"https://{alpic_host}"
        )
    public_base_url = _normalize_public_base_url(
        configured_public_base_url or "http://127.0.0.1:8000",
        production=production,
    )
    api_bearer_token, api_key, allow_anonymous = _authorization(
        env,
        production=production,
    )
    tile_width, tile_height, tile_overlap = _tile_geometry(env)
    pdf_executor, max_concurrent_pdf_jobs = _pdf_settings(env)

    return AppConfig(
        environment=environment,
        nplg_base_url=nplg_base_url,
        cache_dir=Path(
            env.get(
                "CACHE_DIR",
                str(Path("/", "tmp", "nplg-dspace-mcp-cache"))
                if alpic_host
                else ".data/cache",
            )
        ),
        public_base_url=public_base_url,
        asset_signing_secret=secret,
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
        asset_ttl_seconds=_int(
            env, "ASSET_TTL_SECONDS", 3600, minimum=60, maximum=86_400
        ),
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
        pdf_executor=pdf_executor,
        max_concurrent_pdf_jobs=max_concurrent_pdf_jobs,
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
