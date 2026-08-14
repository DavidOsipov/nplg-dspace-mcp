from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable
from urllib.parse import parse_qs, unquote_to_bytes, urlsplit

from .errors import AppError, ErrorCode

NPLG_HOST = "dspace.nplg.gov.ge"
NPLG_ORIGIN = f"https://{NPLG_HOST}"
_HANDLE_RE = re.compile(r"^(?P<prefix>[1-9]\d*)/(?P<suffix>[1-9]\d*)$")
_ITEM_PATH_RE = re.compile(r"^/handle/(?P<handle>[1-9]\d*/[1-9]\d*)$")
_ALLOWED_PATHS = (
    re.compile(r"^/simple-search$"),
    re.compile(r"^/oai/request$"),
    re.compile(r"^/community-list$"),
    re.compile(r"^/handle/[1-9]\d*/[1-9]\d*$"),
    re.compile(r"^/handle/[1-9]\d*/[1-9]\d*/simple-search$"),
    re.compile(r"^/bitstream/[1-9]\d*/[1-9]\d*/.+$"),
)


def _invalid(message: str, **details: object) -> AppError:
    return AppError(
        ErrorCode.INVALID_INPUT,
        message,
        http_status=400,
        safe_details=details or None,
    )


def _validate_origin(parts, *, field: str = "URL") -> None:
    raw_netloc = parts.netloc
    if "%" in raw_netloc or "\\" in raw_netloc:
        raise _invalid(f"{field} contains an unsafe host encoding")
    if parts.scheme != "https":
        raise _invalid(f"{field} must use HTTPS")
    if parts.username is not None or parts.password is not None:
        raise _invalid(f"{field} must not contain credentials")
    try:
        port = parts.port
    except ValueError as exc:
        raise _invalid(f"{field} contains an invalid port") from exc
    if (parts.hostname or "").lower() != NPLG_HOST or port not in {None, 443}:
        raise _invalid(f"{field} must use the exact NPLG origin")
    if parts.fragment:
        raise _invalid(f"{field} must not contain a fragment")


def parse_handle_input(value: str) -> str:
    candidate = value.strip()
    if _HANDLE_RE.fullmatch(candidate):
        return candidate

    if candidate.startswith("/handle/"):
        parts = urlsplit(candidate)
        if parts.scheme or parts.netloc:
            raise _invalid("Handle path is malformed")
    elif candidate.startswith("https://"):
        parts = urlsplit(candidate)
        _validate_origin(parts, field="Handle URL")
    else:
        raise _invalid("Handle must be in the form 1234/567 or a canonical NPLG item URL")

    match = _ITEM_PATH_RE.fullmatch(parts.path)
    if match is None:
        raise _invalid("Handle URL does not identify a canonical NPLG item")
    query = parse_qs(parts.query, keep_blank_values=True)
    if query and query != {"mode": ["full"]}:
        raise _invalid("Handle URL contains unsupported query parameters")
    return match.group("handle")


def build_item_url(handle: str, *, full: bool = False) -> str:
    canonical = parse_handle_input(handle)
    url = f"{NPLG_ORIGIN}/handle/{canonical}"
    return f"{url}?mode=full" if full else url


def validate_upstream_url(url: str) -> str:
    if url != url.strip() or "\\" in url or any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
        raise _invalid("Upstream URL contains unsafe characters")
    parts = urlsplit(url)
    _validate_origin(parts, field="Upstream URL")
    if re.search(r"%(?![0-9A-Fa-f]{2})", parts.path):
        raise _invalid("Upstream URL path contains invalid percent encoding")
    for raw_segment in parts.path.split("/"):
        decoded_segment = unquote_to_bytes(raw_segment)
        if (
            decoded_segment in {b".", b".."}
            or b"/" in decoded_segment
            or b"\\" in decoded_segment
            or b"%" in decoded_segment
            or any(value < 0x20 or value == 0x7F for value in decoded_segment)
        ):
            raise _invalid("Upstream URL path is not canonical")
    if not any(pattern.fullmatch(parts.path) for pattern in _ALLOWED_PATHS):
        raise _invalid("Upstream URL path is not permitted", path=parts.path)
    return url


def is_forbidden_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not address.is_global


Resolver = Callable[..., list[tuple[object, object, object, str, tuple[object, ...]]]]


def resolve_approved_addresses(
    host: str,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> tuple[str, ...]:
    if host.lower() != NPLG_HOST:
        raise _invalid("DNS resolution is allowed only for the NPLG host")
    try:
        answers = resolver(
            host,
            443,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise AppError(
            ErrorCode.UPSTREAM_FAILURE,
            "The repository hostname could not be resolved.",
            http_status=502,
            internal_details={"cause": repr(exc)},
        ) from exc
    addresses: list[str] = []
    for answer in answers:
        sockaddr = answer[4]
        if not sockaddr:
            continue
        raw = str(sockaddr[0])
        try:
            parsed = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned an invalid network address.",
                http_status=502,
                internal_details={"address": raw},
            ) from exc
        if is_forbidden_address(parsed):
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository hostname resolved to a non-public address.",
                http_status=502,
                internal_details={"address": raw},
            )
        normalized = str(parsed)
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise AppError(
            ErrorCode.UPSTREAM_FAILURE,
            "The repository hostname returned no usable addresses.",
            http_status=502,
        )
    return tuple(addresses)
