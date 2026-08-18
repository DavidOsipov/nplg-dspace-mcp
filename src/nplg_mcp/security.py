# Copyright (c) 2026 David Osipov
"""Network-admission and request-security primitives."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Protocol, TypedDict, Unpack
from urllib.parse import SplitResult, parse_qs, unquote_to_bytes, urlsplit

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
_DEPRECATED_IPV6_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")
_C0_CONTROL_END = 0x20
_DELETE_CHARACTER = 0x7F


def _invalid(message: str, **details: object) -> AppError:
    return AppError(
        ErrorCode.INVALID_INPUT,
        message,
        http_status=400,
        safe_details=details or None,
    )


def _validate_origin(parts: SplitResult, *, field: str = "URL") -> None:
    raw_netloc = parts.netloc
    if "%" in raw_netloc or "\\" in raw_netloc:
        msg = f"{field} contains an unsafe host encoding"
        raise _invalid(msg)
    if parts.scheme != "https":
        msg = f"{field} must use HTTPS"
        raise _invalid(msg)
    if parts.username is not None or parts.password is not None:
        msg = f"{field} must not contain credentials"
        raise _invalid(msg)
    try:
        port = parts.port
    except ValueError as exc:
        msg = f"{field} contains an invalid port"
        raise _invalid(msg) from exc
    if (parts.hostname or "").lower() != NPLG_HOST or port not in {None, 443}:
        msg = f"{field} must use the exact NPLG origin"
        raise _invalid(msg)
    if parts.fragment:
        msg = f"{field} must not contain a fragment"
        raise _invalid(msg)


def parse_handle_input(value: str) -> str:
    """Return a canonical handle from an accepted handle or NPLG item URL."""
    candidate = value.strip()
    if _HANDLE_RE.fullmatch(candidate):
        return candidate

    if candidate.startswith("/handle/"):
        parts = urlsplit(candidate)
        if parts.scheme or parts.netloc:
            msg = "Handle path is malformed"
            raise _invalid(msg)
    elif candidate.startswith("https://"):
        parts = urlsplit(candidate)
        _validate_origin(parts, field="Handle URL")
    else:
        msg = "Handle must be in the form 1234/567 or a canonical NPLG item URL"
        raise _invalid(msg)

    match = _ITEM_PATH_RE.fullmatch(parts.path)
    if match is None:
        msg = "Handle URL does not identify a canonical NPLG item"
        raise _invalid(msg)
    query = parse_qs(parts.query, keep_blank_values=True)
    if query and query != {"mode": ["full"]}:
        msg = "Handle URL contains unsupported query parameters"
        raise _invalid(msg)
    return match.group("handle")


def build_item_url(handle: str, *, full: bool = False) -> str:
    """Build an exact-origin NPLG item URL for a canonical handle."""
    canonical = parse_handle_input(handle)
    url = f"{NPLG_ORIGIN}/handle/{canonical}"
    return f"{url}?mode=full" if full else url


def validate_upstream_url(url: str) -> str:
    """Return an exact-origin upstream URL only when its path is canonical."""
    if (
        url != url.strip()
        or "\\" in url
        or any(
            ord(character) < _C0_CONTROL_END or ord(character) == _DELETE_CHARACTER
            for character in url
        )
    ):
        msg = "Upstream URL contains unsafe characters"
        raise _invalid(msg)
    parts = urlsplit(url)
    _validate_origin(parts, field="Upstream URL")
    if re.search(r"%(?![0-9A-Fa-f]{2})", parts.path):
        msg = "Upstream URL path contains invalid percent encoding"
        raise _invalid(msg)
    for raw_segment in parts.path.split("/"):
        decoded_segment = unquote_to_bytes(raw_segment)
        if (
            decoded_segment in {b".", b".."}
            or b"/" in decoded_segment
            or b"\\" in decoded_segment
            or b"%" in decoded_segment
            or any(
                value < _C0_CONTROL_END or value == _DELETE_CHARACTER
                for value in decoded_segment
            )
        ):
            msg = "Upstream URL path is not canonical"
            raise _invalid(msg)
    if not any(pattern.fullmatch(parts.path) for pattern in _ALLOWED_PATHS):
        msg = "Upstream URL path is not permitted"
        raise _invalid(msg, path=parts.path)
    return url


def is_forbidden_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return whether an address is ineligible for upstream connections."""
    return not address.is_global or (
        isinstance(address, ipaddress.IPv6Address)
        and address in _DEPRECATED_IPV6_SITE_LOCAL
    )


SocketAddress = tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes]
DnsAnswer = tuple[socket.AddressFamily, socket.SocketKind, int, str, SocketAddress]


class ResolverOptions(TypedDict):
    """Required keyword options for stream-oriented TCP resolution."""

    type: int
    proto: int


class Resolver(Protocol):
    """Typed DNS-resolution seam matching the options used by this module."""

    def __call__(
        self, host: str, port: int, **options: Unpack[ResolverOptions]
    ) -> list[DnsAnswer]:
        """Resolve a host and service to concrete socket addresses."""
        ...


def _default_resolver(
    host: str, port: int, **options: Unpack[ResolverOptions]
) -> list[DnsAnswer]:
    return socket.getaddrinfo(
        host,
        port,
        type=options["type"],
        proto=options["proto"],
    )


def resolve_approved_addresses(
    host: str,
    *,
    resolver: Resolver = _default_resolver,
) -> tuple[str, ...]:
    """Resolve the NPLG host and reject the full answer set if any IP is unsafe."""
    if host.lower() != NPLG_HOST:
        msg = "DNS resolution is allowed only for the NPLG host"
        raise _invalid(msg)
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
