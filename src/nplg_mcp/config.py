# Copyright (c) 2026 David Osipov
"""Strict environment-backed application configuration."""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, NewType, cast
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    SecretStr,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

NPLG_BASE_URL = "https://dspace.nplg.gov.ge/"
HARD_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
HARD_MAX_RENDER_PAGES = 8
HARD_MAX_PAGE_PIXELS = 120_000_000
HARD_MAX_RENDER_PIXELS = 480_000_000
HARD_MAX_REQUEST_BODY_BYTES = 1_048_576
HARD_MAX_INLINE_RESOURCE_BYTES = 4 * 1024 * 1024
DEFAULT_CACHE_MAX_BYTES = 20 * 1024 * 1024 * 1024
HARD_MAX_CACHE_BYTES = 1024 * 1024 * 1024 * 1024
DEFAULT_RETENTION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
DEFAULT_RETENTION_MAX_OBJECTS = 100_000
DEFAULT_RETENTION_MIN_FREE_BYTES = 64 * 1024 * 1024
DEFAULT_RETENTION_MIN_FREE_INODES = 128
DEFAULT_RETENTION_HEALTHY_WINDOW_SECONDS = 60
DEFAULT_RETENTION_MAX_FORWARD_SLEW_SECONDS = 5
HARD_MAX_TILE_DIMENSION = 4096
HARD_MAX_TILE_OVERLAP = 512
HARD_MAX_TILES_PER_PAGE = 100
PDF_WORKER_SOCKET_PATH = Path("/run/nplg-pdf-worker/worker.sock")
SCANNER_SOCKET_PATH = Path("/run/nplg-scanner/clamd.sock")
PDF_WORKER_SLOT_ROOT = Path("/var/lib/nplg/pdf-worker-slot")
PDF_WORKER_SLOT_POLICY_PATH = Path("/etc/nplg/pdf-worker-slot-policy.json")
_DOCUMENTED_PLACEHOLDER = "replace-with-at-least-32-random-characters"
_MIN_CREDENTIAL_BYTES = 32
_MAX_CREDENTIAL_BYTES = 512
_MAX_API_PRINCIPALS = 64
PdfExecutor = Literal["serialized", "unix-worker"]
DeploymentProfile = Literal["alpic-metadata", "distributed-full", "private-full"]
CanonicalHost = NewType("CanonicalHost", str)
CanonicalOrigin = NewType("CanonicalOrigin", str)
PrincipalId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]{0,63}$",
    ),
]


class ApiPrincipalCredential(BaseModel):
    """One closed, secret-safe API credential bound to a stable principal."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    principal_id: PrincipalId
    bearer_token: SecretStr | None = None
    api_key: SecretStr | None = None

    def bearer_value(self) -> str | None:
        """Return the bearer value only at the authentication boundary."""
        secret = self.bearer_token
        return None if secret is None else secret.get_secret_value()

    def api_key_value(self) -> str | None:
        """Return the API-key value only at the authentication boundary."""
        secret = self.api_key
        return None if secret is None else secret.get_secret_value()

    def credential_value(self) -> str:
        """Return the model-validated credential for invariant checks."""
        bearer = self.bearer_value()
        if bearer is not None:
            return bearer
        api_key = self.api_key_value()
        if api_key is None:
            msg = "API principal credential invariant was violated"
            raise RuntimeError(msg)
        return api_key

    @model_validator(mode="after")
    def _validate_credential(self) -> ApiPrincipalCredential:
        credentials = tuple(
            value for value in (self.bearer_token, self.api_key) if value is not None
        )
        if len(credentials) != 1:
            msg = "each API principal must define exactly one credential"
            raise ValueError(msg)
        raw = credentials[0].get_secret_value()
        byte_length = len(raw.encode("utf-8"))
        if not _MIN_CREDENTIAL_BYTES <= byte_length <= _MAX_CREDENTIAL_BYTES:
            msg = "API principal credentials must be between 32 and 512 bytes"
            raise ValueError(msg)
        if raw == _DOCUMENTED_PLACEHOLDER:
            msg = "API principal credentials must replace the documented placeholder"
            raise ValueError(msg)
        if any(character in raw for character in ("\r", "\n", "\x00")):
            msg = "API principal credentials must not contain control delimiters"
            raise ValueError(msg)
        return self


_API_PRINCIPALS_ADAPTER = TypeAdapter(list[ApiPrincipalCredential])
_RESERVED_PRINCIPAL_IDS = frozenset({"anonymous", "legacy-api-key", "legacy-bearer"})
_PRODUCTION_STATIC_AUTH_KEYS = frozenset(
    {
        "API_BEARER_TOKEN",
        "API_KEY",
        "API_PRINCIPALS_JSON",
        "NPLG_PRIVATE_STATIC_TOKEN",
        "X_API_KEY",
        "X-API-Key",
    }
)


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Validated application settings derived from environment text."""

    environment: str
    nplg_base_url: str
    cache_dir: Path
    public_base_url: str
    asset_signing_secret: bytes | None
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
    cursor_signing_secret: bytes
    pdf_executor: PdfExecutor = "serialized"
    pdf_worker_socket_path: Path = PDF_WORKER_SOCKET_PATH
    pdf_worker_slot_root: Path = PDF_WORKER_SLOT_ROOT
    pdf_worker_slot_policy_path: Path = PDF_WORKER_SLOT_POLICY_PATH
    scanner_socket_path: Path = SCANNER_SOCKET_PATH
    private_edge_tls: bool = False
    max_concurrent_pdf_jobs: int = 1
    max_concurrent_mcp_requests: int = 16
    max_concurrent_asset_streams: int = 8
    max_concurrent_http_requests: int = 128
    cache_max_bytes: int = DEFAULT_CACHE_MAX_BYTES
    retention_max_age_seconds: int = DEFAULT_RETENTION_MAX_AGE_SECONDS
    retention_max_objects: int = DEFAULT_RETENTION_MAX_OBJECTS
    retention_min_free_bytes: int = DEFAULT_RETENTION_MIN_FREE_BYTES
    retention_min_free_inodes: int = DEFAULT_RETENTION_MIN_FREE_INODES
    retention_healthy_window_seconds: int = DEFAULT_RETENTION_HEALTHY_WINDOW_SECONDS
    retention_max_forward_slew_seconds: int = DEFAULT_RETENTION_MAX_FORWARD_SLEW_SECONDS
    retention_clock_synchronized: bool = False
    request_body_timeout_seconds: float = 10.0
    asset_stream_idle_timeout_seconds: float = 10.0
    asset_stream_total_timeout_seconds: float = 120.0
    deployment_profile: DeploymentProfile = "private-full"
    api_principals: tuple[ApiPrincipalCredential, ...] = ()
    max_concurrent_mcp_requests_per_principal: int = 4
    mcp_allowed_hosts: tuple[CanonicalHost, ...] = (CanonicalHost("127.0.0.1:8000"),)
    mcp_allowed_origins: tuple[CanonicalOrigin, ...] = ()
    mcp_application_deadline_seconds: float = 20.0

    @property
    def mcp_max_body_bytes(self) -> int:
        """Expose the single project body ceiling at the SDK transport seam."""
        return self.max_request_body_bytes

    def require_asset_signing_secret(self) -> bytes:
        """Return the private-full asset-token root or reject the absent capability."""
        secret = self.asset_signing_secret
        if secret is None:
            msg = "asset signing is unavailable in the metadata-only profile"
            raise ValueError(msg)
        return secret


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_CANONICAL_HOST_BYTES = 253
_ASCII_SPACE = 0x20
_ASCII_DELETE = 0x7F
_IPV4_VERSION = 4
_IPV6_VERSION = 6
_MAX_PORT = 65_535


def _canonical_host(  # noqa: C901, PLR0912, PLR0915
    value: object, *, default_port: int | None
) -> CanonicalHost:
    """Validate one exact lower-case ASCII host authority without aliases."""
    if type(value) is not str or not value or len(value) > _MAX_CANONICAL_HOST_BYTES:
        msg = "MCP allowed host must be a nonempty canonical string"
        raise ValueError(msg)
    try:
        _ = value.encode("ascii")
    except UnicodeEncodeError as exc:
        msg = "MCP allowed host must be ASCII"
        raise ValueError(msg) from exc
    if (
        value != value.lower()
        or any(
            ord(character) <= _ASCII_SPACE or ord(character) == _ASCII_DELETE
            for character in value
        )
        or any(marker in value for marker in ("*", "%", "\\", "@", "/", "?", "#"))
    ):
        msg = "MCP allowed host is not canonical"
        raise ValueError(msg)

    host = value
    port_text: str | None = None
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            msg = "MCP allowed host has an invalid IP literal"
            raise ValueError(msg)
        host = value[1:closing]
        suffix = value[closing + 1 :]
        if suffix:
            if not suffix.startswith(":"):
                msg = "MCP allowed host has an invalid authority"
                raise ValueError(msg)
            port_text = suffix[1:]
        try:
            parsed_ip = ip_address(host)
        except ValueError as exc:
            msg = "MCP allowed host has an invalid IP literal"
            raise ValueError(msg) from exc
        if parsed_ip.version != _IPV6_VERSION or parsed_ip.compressed != host:
            msg = "MCP allowed host IP literal is not canonical"
            raise ValueError(msg)
    else:
        if value.count(":") > 1:
            msg = "MCP allowed IPv6 hosts must be bracketed"
            raise ValueError(msg)
        if ":" in value:
            host, port_text = value.rsplit(":", 1)
        try:
            parsed_ip = ip_address(host)
        except ValueError:
            labels = host.split(".")
            if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
                msg = "MCP allowed DNS host is not canonical"
                raise ValueError(msg) from None
        else:
            if parsed_ip.version != _IPV4_VERSION or str(parsed_ip) != host:
                msg = "MCP allowed host IP literal is not canonical"
                raise ValueError(msg)

    if port_text is not None:
        if (
            not port_text
            or not port_text.isascii()
            or not port_text.isdecimal()
            or (len(port_text) > 1 and port_text.startswith("0"))
        ):
            msg = "MCP allowed host port is not canonical"
            raise ValueError(msg)
        port = int(port_text)
        if not 1 <= port <= _MAX_PORT or port == default_port:
            msg = "MCP allowed host port is not canonical"
            raise ValueError(msg)
    return CanonicalHost(value)


def _canonical_origin(value: object, *, production: bool) -> CanonicalOrigin:
    """Validate one exact canonical HTTPS origin or development loopback HTTP."""
    if type(value) is not str or not value:
        msg = "MCP allowed origin must be a nonempty canonical string"
        raise ValueError(msg)
    try:
        _ = value.encode("ascii")
    except UnicodeEncodeError as exc:
        msg = "MCP allowed origin must be ASCII"
        raise ValueError(msg) from exc
    if any(
        ord(character) <= _ASCII_SPACE or ord(character) == _ASCII_DELETE
        for character in value
    ):
        msg = "MCP allowed origin contains unsafe bytes"
        raise ValueError(msg)
    parsed = urlsplit(value)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
    ):
        msg = "MCP allowed origin is not an exact origin"
        raise ValueError(msg)
    if production and parsed.scheme != "https":
        msg = "MCP allowed origins must use HTTPS in production"
        raise ValueError(msg)
    if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
        msg = "MCP allowed origin HTTP values are restricted to loopback development"
        raise ValueError(msg)
    default_port = 443 if parsed.scheme == "https" else 80
    try:
        host = _canonical_host(parsed.netloc, default_port=default_port)
    except ValueError as exc:
        msg = "MCP allowed origin is not canonical"
        raise ValueError(msg) from exc
    rendered = f"{parsed.scheme}://{host}"
    if value != rendered:
        msg = "MCP allowed origin is not canonical"
        raise ValueError(msg)
    return CanonicalOrigin(value)


def _strict_json_string_list(env: Mapping[str, str], name: str) -> list[object] | None:
    raw = env.get(name)
    if raw is None:
        return None
    try:
        value = cast("object", json.loads(raw))
    except (TypeError, ValueError) as exc:
        msg = f"{name} must be a strict JSON string array"
        raise ValueError(msg) from exc
    if not isinstance(value, list):
        msg = f"{name} must be a strict JSON string array"
        raise ValueError(msg)  # noqa: TRY004 - config errors are ValueError.
    items = cast("list[object]", value)
    if any(type(item) is not str for item in items):
        msg = f"{name} must be a strict JSON string array"
        raise ValueError(msg)
    return items


def _mcp_transport_allowlists(
    env: Mapping[str, str],
    *,
    public_base_url: str,
    production: bool,
) -> tuple[tuple[CanonicalHost, ...], tuple[CanonicalOrigin, ...]]:
    parsed_public = urlsplit(public_base_url)
    default_port = 443 if parsed_public.scheme == "https" else 80
    default_host = parsed_public.netloc
    raw_hosts = _strict_json_string_list(env, "NPLG_MCP_ALLOWED_HOSTS_JSON")
    raw_origins = _strict_json_string_list(env, "NPLG_MCP_ALLOWED_ORIGINS_JSON")
    host_values = [default_host] if raw_hosts is None else raw_hosts
    origin_values = [public_base_url] if raw_origins is None else raw_origins
    hosts = tuple(
        _canonical_host(value, default_port=default_port) for value in host_values
    )
    origins = tuple(
        _canonical_origin(value, production=production) for value in origin_values
    )
    if not hosts:
        msg = "NPLG_MCP_ALLOWED_HOSTS_JSON must not be empty"
        raise ValueError(msg)
    if len(set(hosts)) != len(hosts):
        msg = "NPLG_MCP_ALLOWED_HOSTS_JSON contains duplicates"
        raise ValueError(msg)
    if len(set(origins)) != len(origins):
        msg = "NPLG_MCP_ALLOWED_ORIGINS_JSON contains duplicates"
        raise ValueError(msg)
    return hosts, origins


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
    if value not in {"serialized", "unix-worker"}:
        msg = "PDF_EXECUTOR must be serialized or unix-worker"
        raise ValueError(msg)
    return cast("PdfExecutor", value)


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


def _is_loopback_host(value: str) -> bool:
    normalized = value.strip().rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _deployment_profile(
    env: Mapping[str, str],
    *,
    production: bool,
) -> DeploymentProfile:
    configured = env.get("DEPLOYMENT_PROFILE")
    if configured is None:
        if production:
            msg = "DEPLOYMENT_PROFILE is required in production"
            raise ValueError(msg)
        return "private-full"
    return validate_deployment_profile(configured.strip())


def validate_deployment_profile(value: object) -> DeploymentProfile:
    """Validate one exact deployment profile without string coercion."""
    if type(value) is str and value == "alpic-metadata":
        return "alpic-metadata"
    if type(value) is str and value == "distributed-full":
        return "distributed-full"
    if type(value) is str and value == "private-full":
        return "private-full"
    msg = "DEPLOYMENT_PROFILE must be alpic-metadata, distributed-full, or private-full"
    raise ValueError(msg)


def _signing_secret(
    env: Mapping[str, str],
    *,
    name: str,
    production: bool,
) -> bytes:
    secret = env.get(name, "")
    secret_bytes = secret.encode("utf-8")
    if len(secret_bytes) < _MIN_CREDENTIAL_BYTES:
        msg = f"{name} must be at least 32 bytes"
        raise ValueError(msg)
    if production and secret == _DOCUMENTED_PLACEHOLDER:
        msg = f"{name} must be replaced before production deployment"
        raise ValueError(msg)
    return secret_bytes


def _authorization(
    env: Mapping[str, str],
    *,
    production: bool,
) -> tuple[
    str | None,
    str | None,
    bool,
    tuple[ApiPrincipalCredential, ...],
]:
    if production and not _PRODUCTION_STATIC_AUTH_KEYS.isdisjoint(env):
        msg = (
            "static authentication configuration is forbidden in production; "
            "the selected OAuth capability must activate successfully"
        )
        raise ValueError(msg)
    allow_anonymous = _bool(
        env,
        "ALLOW_ANONYMOUS",
        default=False,
    )
    if production:
        return None, None, allow_anonymous, ()
    api_bearer_token = env.get("API_BEARER_TOKEN") or None
    if (
        api_bearer_token is not None
        and len(api_bearer_token.encode("utf-8")) < _MIN_CREDENTIAL_BYTES
    ):
        msg = "API_BEARER_TOKEN must be at least 32 bytes"
        raise ValueError(msg)
    api_key = env.get("API_KEY") or None
    if api_key is not None and len(api_key.encode("utf-8")) < _MIN_CREDENTIAL_BYTES:
        msg = "API_KEY must be at least 32 bytes"
        raise ValueError(msg)
    api_principals = _api_principal_registry(env)
    if api_principals and (api_bearer_token is not None or api_key is not None):
        msg = "API_PRINCIPALS_JSON cannot be combined with API_BEARER_TOKEN or API_KEY"
        raise ValueError(msg)
    if (
        not allow_anonymous
        and not api_principals
        and api_bearer_token is None
        and api_key is None
    ):
        msg = (
            "API_BEARER_TOKEN or API_KEY, or API_PRINCIPALS_JSON, is required unless "
            "ALLOW_ANONYMOUS=true"
        )
        raise ValueError(msg)
    return api_bearer_token, api_key, allow_anonymous, api_principals


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            msg = f"duplicate JSON key: {key}"
            raise ValueError(msg)
        result[key] = value
    return result


def _api_principal_registry(
    env: Mapping[str, str],
) -> tuple[ApiPrincipalCredential, ...]:
    raw = env.get("API_PRINCIPALS_JSON")
    if raw is None:
        return ()
    try:
        decoded = cast(
            "object",
            json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys),
        )
        principals = _API_PRINCIPALS_ADAPTER.validate_python(decoded, strict=True)
    except (TypeError, ValueError, ValidationError) as exc:
        msg = "API_PRINCIPALS_JSON must be a strict closed JSON array"
        raise ValueError(msg) from exc
    if not 1 <= len(principals) <= _MAX_API_PRINCIPALS:
        msg = f"API_PRINCIPALS_JSON must contain 1 to {_MAX_API_PRINCIPALS} principals"
        raise ValueError(msg)
    principal_ids = [principal.principal_id for principal in principals]
    if len(set(principal_ids)) != len(principal_ids):
        msg = "API_PRINCIPALS_JSON principal_id values must be unique"
        raise ValueError(msg)
    if _RESERVED_PRINCIPAL_IDS.intersection(principal_ids):
        msg = "API_PRINCIPALS_JSON uses a reserved principal_id"
        raise ValueError(msg)
    credentials = [principal.credential_value() for principal in principals]
    if len(set(credentials)) != len(credentials):
        msg = "API_PRINCIPALS_JSON credentials must be unique"
        raise ValueError(msg)
    return tuple(principals)


def _validate_anonymous_scope(
    env: Mapping[str, str],
    *,
    deployment_profile: DeploymentProfile,
    production: bool,
    public_base_url: str,
    allow_anonymous: bool,
) -> None:
    if not allow_anonymous:
        return
    if production:
        if deployment_profile == "alpic-metadata":
            return
        msg = "anonymous production access is limited to alpic-metadata"
        raise ValueError(msg)
    public_host = urlsplit(public_base_url).hostname
    bind_host = env.get("HOST", "127.0.0.1")
    if (
        public_host is None
        or not _is_loopback_host(public_host)
        or not _is_loopback_host(bind_host)
    ):
        msg = "ALLOW_ANONYMOUS requires loopback-only HOST and PUBLIC_BASE_URL"
        raise ValueError(msg)


def _validate_credential_separation(
    secret: bytes,
    *,
    label: str,
    api_bearer_token: str | None,
    api_key: str | None,
    api_principals: tuple[ApiPrincipalCredential, ...],
) -> None:
    credentials: list[tuple[str, str | None]] = [
        ("API_BEARER_TOKEN", api_bearer_token),
        ("API_KEY", api_key),
    ]
    credentials.extend(
        (
            f"API_PRINCIPALS_JSON[{principal.principal_id}]",
            principal.credential_value(),
        )
        for principal in api_principals
    )
    for name, credential in credentials:
        if credential is not None and hmac.compare_digest(
            secret,
            credential.encode("utf-8"),
        ):
            msg = f"{label} and {name} must differ"
            raise ValueError(msg)


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


def _pdf_settings(
    env: Mapping[str, str],
    *,
    deployment_profile: DeploymentProfile,
    production: bool,
) -> tuple[PdfExecutor, int]:
    pdf_executor = _pdf_executor(env)
    max_concurrent_pdf_jobs = _int(
        env,
        "MAX_CONCURRENT_PDF_JOBS",
        1,
        minimum=1,
        maximum=4,
    )
    if max_concurrent_pdf_jobs != 1:
        msg = "MAX_CONCURRENT_PDF_JOBS must equal 1 for PDF_EXECUTOR"
        raise ValueError(msg)
    if pdf_executor == "unix-worker" and deployment_profile != "private-full":
        msg = "PDF_EXECUTOR=unix-worker requires DEPLOYMENT_PROFILE=private-full"
        raise ValueError(msg)
    if (
        production
        and deployment_profile == "private-full"
        and pdf_executor != "unix-worker"
    ):
        msg = "PDF_EXECUTOR=unix-worker is required for private-full production"
        raise ValueError(msg)
    return pdf_executor, max_concurrent_pdf_jobs


def _pdf_worker_socket_path(env: Mapping[str, str]) -> Path:
    """Accept only the reviewed private AF_UNIX endpoint path."""
    value = env.get("PDF_WORKER_SOCKET", str(PDF_WORKER_SOCKET_PATH))
    if value != str(PDF_WORKER_SOCKET_PATH):
        msg = "PDF_WORKER_SOCKET must use the reviewed private socket path"
        raise ValueError(msg)
    return PDF_WORKER_SOCKET_PATH


def _scanner_socket_path(env: Mapping[str, str]) -> Path:
    """Accept only the reviewed private ClamAV AF_UNIX endpoint path."""
    value = env.get("SCANNER_SOCKET", str(SCANNER_SOCKET_PATH))
    if value != str(SCANNER_SOCKET_PATH):
        msg = "SCANNER_SOCKET must use the reviewed private socket path"
        raise ValueError(msg)
    return SCANNER_SOCKET_PATH


def _pdf_worker_slot_paths(env: Mapping[str, str]) -> tuple[Path, Path]:
    """Reject environment-selected writable roots or policy documents."""
    root = env.get("PDF_WORKER_SLOT_ROOT", str(PDF_WORKER_SLOT_ROOT))
    if root != str(PDF_WORKER_SLOT_ROOT):
        msg = "PDF_WORKER_SLOT_ROOT must use the reviewed dedicated slot root"
        raise ValueError(msg)
    policy = env.get("PDF_WORKER_SLOT_POLICY", str(PDF_WORKER_SLOT_POLICY_PATH))
    if policy != str(PDF_WORKER_SLOT_POLICY_PATH):
        msg = "PDF_WORKER_SLOT_POLICY must use the reviewed slot policy path"
        raise ValueError(msg)
    return PDF_WORKER_SLOT_ROOT, PDF_WORKER_SLOT_POLICY_PATH


def load_config(env: Mapping[str, str]) -> AppConfig:
    """Parse and validate a complete application configuration."""
    environment = _environment(env)
    production = environment == "production"

    nplg_base_url = env.get("NPLG_BASE_URL", NPLG_BASE_URL)
    if nplg_base_url != NPLG_BASE_URL:
        msg = f"NPLG_BASE_URL must be exactly {NPLG_BASE_URL}"
        raise ValueError(msg)
    configured_public_base_url = env.get("PUBLIC_BASE_URL")
    alpic_host = env.get("ALPIC_HOST", "").strip()
    if alpic_host and not production:
        msg = "ALPIC_HOST requires explicit NODE_ENV=production"
        raise ValueError(msg)
    if configured_public_base_url is None and alpic_host:
        configured_public_base_url = (
            alpic_host if "://" in alpic_host else f"https://{alpic_host}"
        )
    public_base_url = _normalize_public_base_url(
        configured_public_base_url or "http://127.0.0.1:8000",
        production=production,
    )
    deployment_profile = _deployment_profile(env, production=production)
    api_bearer_token, api_key, allow_anonymous, api_principals = _authorization(
        env,
        production=production,
    )
    mcp_allowed_hosts, mcp_allowed_origins = _mcp_transport_allowlists(
        env,
        public_base_url=public_base_url,
        production=production,
    )
    _validate_anonymous_scope(
        env,
        deployment_profile=deployment_profile,
        production=production,
        public_base_url=public_base_url,
        allow_anonymous=allow_anonymous,
    )
    tile_width, tile_height, tile_overlap = _tile_geometry(env)
    pdf_executor, max_concurrent_pdf_jobs = _pdf_settings(
        env,
        deployment_profile=deployment_profile,
        production=production,
    )
    pdf_worker_socket_path = _pdf_worker_socket_path(env)
    _ = _pdf_worker_slot_paths(env)
    scanner_socket_path = _scanner_socket_path(env)
    private_edge_tls = _bool(env, "PRIVATE_EDGE_TLS", default=False)
    if private_edge_tls and deployment_profile != "private-full":
        msg = "PRIVATE_EDGE_TLS requires DEPLOYMENT_PROFILE=private-full"
        raise ValueError(msg)
    if production and deployment_profile == "private-full" and not private_edge_tls:
        msg = "PRIVATE_EDGE_TLS=true is required for private-full production"
        raise ValueError(msg)
    asset_stream_idle_timeout_seconds = _float(
        env,
        "ASSET_STREAM_IDLE_TIMEOUT_SECONDS",
        10.0,
        minimum=1.0,
        maximum=60.0,
    )
    asset_stream_total_timeout_seconds = _float(
        env,
        "ASSET_STREAM_TOTAL_TIMEOUT_SECONDS",
        120.0,
        minimum=1.0,
        maximum=600.0,
    )
    if asset_stream_total_timeout_seconds < asset_stream_idle_timeout_seconds:
        msg = (
            "ASSET_STREAM_TOTAL_TIMEOUT_SECONDS must be greater than or equal to "
            "ASSET_STREAM_IDLE_TIMEOUT_SECONDS"
        )
        raise ValueError(msg)
    max_concurrent_mcp_requests = _int(
        env,
        "MAX_CONCURRENT_MCP_REQUESTS",
        16,
        minimum=1,
        maximum=64,
    )
    max_concurrent_mcp_requests_per_principal = _int(
        env,
        "MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL",
        4,
        minimum=1,
        maximum=64,
    )
    if (
        production
        and max_concurrent_mcp_requests_per_principal >= max_concurrent_mcp_requests
    ):
        msg = (
            "MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL must be smaller than "
            "MAX_CONCURRENT_MCP_REQUESTS in production"
        )
        raise ValueError(msg)
    cursor_signing_secret = _signing_secret(
        env,
        name="CURSOR_SIGNING_SECRET",
        production=production,
    )
    asset_signing_secret = (
        None
        if deployment_profile == "alpic-metadata"
        else _signing_secret(
            env,
            name="ASSET_SIGNING_SECRET",
            production=production,
        )
    )
    _validate_credential_separation(
        cursor_signing_secret,
        label="CURSOR_SIGNING_SECRET",
        api_bearer_token=api_bearer_token,
        api_key=api_key,
        api_principals=api_principals,
    )
    if asset_signing_secret is not None:
        _validate_credential_separation(
            asset_signing_secret,
            label="ASSET_SIGNING_SECRET",
            api_bearer_token=api_bearer_token,
            api_key=api_key,
            api_principals=api_principals,
        )

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
        asset_signing_secret=asset_signing_secret,
        api_bearer_token=api_bearer_token,
        api_key=api_key,
        allow_anonymous=allow_anonymous,
        api_principals=api_principals,
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
        cursor_signing_secret=cursor_signing_secret,
        pdf_executor=pdf_executor,
        pdf_worker_socket_path=pdf_worker_socket_path,
        scanner_socket_path=scanner_socket_path,
        private_edge_tls=private_edge_tls,
        max_concurrent_pdf_jobs=max_concurrent_pdf_jobs,
        max_concurrent_mcp_requests=max_concurrent_mcp_requests,
        max_concurrent_mcp_requests_per_principal=(
            max_concurrent_mcp_requests_per_principal
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
        retention_max_age_seconds=_int(
            env,
            "RETENTION_MAX_AGE_SECONDS",
            DEFAULT_RETENTION_MAX_AGE_SECONDS,
            minimum=60,
            maximum=31_536_000,
        ),
        retention_max_objects=_int(
            env,
            "RETENTION_MAX_OBJECTS",
            DEFAULT_RETENTION_MAX_OBJECTS,
            minimum=1,
            maximum=10_000_000,
        ),
        retention_min_free_bytes=_int(
            env,
            "RETENTION_MIN_FREE_BYTES",
            DEFAULT_RETENTION_MIN_FREE_BYTES,
            minimum=DEFAULT_RETENTION_MIN_FREE_BYTES,
            maximum=HARD_MAX_CACHE_BYTES,
        ),
        retention_min_free_inodes=_int(
            env,
            "RETENTION_MIN_FREE_INODES",
            DEFAULT_RETENTION_MIN_FREE_INODES,
            minimum=DEFAULT_RETENTION_MIN_FREE_INODES,
            maximum=10_000_000,
        ),
        retention_healthy_window_seconds=_int(
            env,
            "RETENTION_HEALTHY_WINDOW_SECONDS",
            DEFAULT_RETENTION_HEALTHY_WINDOW_SECONDS,
            minimum=0,
            maximum=3600,
        ),
        retention_max_forward_slew_seconds=_int(
            env,
            "RETENTION_MAX_FORWARD_SLEW_SECONDS",
            DEFAULT_RETENTION_MAX_FORWARD_SLEW_SECONDS,
            minimum=0,
            maximum=60,
        ),
        retention_clock_synchronized=_bool(
            env,
            "RETENTION_CLOCK_SYNCHRONIZED",
            default=False,
        ),
        request_body_timeout_seconds=_float(
            env,
            "REQUEST_BODY_TIMEOUT_SECONDS",
            10.0,
            minimum=1.0,
            maximum=60.0,
        ),
        asset_stream_idle_timeout_seconds=asset_stream_idle_timeout_seconds,
        asset_stream_total_timeout_seconds=asset_stream_total_timeout_seconds,
        deployment_profile=deployment_profile,
        mcp_allowed_hosts=mcp_allowed_hosts,
        mcp_allowed_origins=mcp_allowed_origins,
    )
