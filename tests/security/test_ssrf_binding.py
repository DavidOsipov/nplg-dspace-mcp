# Copyright (c) 2026 David Osipov
"""Task 17 adversarial contracts for DNS-to-socket binding."""

from __future__ import annotations

import inspect
import ipaddress
import math
from collections.abc import Iterable
from typing import cast, get_type_hints, override

import httpcore
import pytest

from nplg_mcp.network import (
    SOCKET_OPTION,
    BoundAsyncNetworkBackend,
    ResolvedEndpoint,
    create_resolved_endpoint,
)
from nplg_mcp.security import (
    NPLG_HOST,
    OutboundPurpose,
    build_outbound_headers,
)

_UNEXPECTED_UNIX = "Unix delegate must not be reached"


class _Stream(httpcore.AsyncNetworkStream):
    def __init__(self, peer: tuple[str, int]) -> None:
        super().__init__()
        self.peer = peer

    @override
    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del max_bytes, timeout
        return b""

    @override
    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del buffer, timeout

    @override
    async def aclose(self) -> None:
        return

    @override
    async def start_tls(
        self,
        ssl_context: object,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del ssl_context, server_hostname, timeout
        return self

    @override
    def get_extra_info(self, info: str) -> object | None:
        return self.peer if info == "server_addr" else None


class _Backend(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, int, float | None, tuple[SOCKET_OPTION, ...]]] = []
        self.sleeps: list[float] = []

    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del local_address
        options = tuple(socket_options or ())
        self.calls.append((host, port, timeout, options))
        return _Stream((host, port))

    @override
    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise AssertionError(_UNEXPECTED_UNIX)

    @override
    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


async def _public(host: str) -> ResolvedEndpoint:
    return create_resolved_endpoint(
        hostname=host,
        port=443,
        addresses=("1.1.1.1",),
        ttl_seconds=60.0,
        clock=lambda: 10.0,
    )


def test_httpcore_backend_signature_preserves_the_complete_external_protocol() -> None:
    """Mutation caught: narrowing the pinned httpcore timeout/options signature."""
    signature = inspect.signature(BoundAsyncNetworkBackend.connect_tcp)
    hints = cast(
        "dict[str, object]",
        get_type_hints(BoundAsyncNetworkBackend.connect_tcp),
    )

    assert tuple(signature.parameters) == (
        "self",
        "host",
        "port",
        "timeout",
        "local_address",
        "socket_options",
    )
    assert hints["timeout"] == float | None
    assert hints["socket_options"] == Iterable[SOCKET_OPTION] | None
    assert hints["return"] is httpcore.AsyncNetworkStream


@pytest.mark.parametrize(
    "raw_timeout",
    [None, True, 1, "1", -1.0, 0.0, math.nan, math.inf, 60.000_001],
)
@pytest.mark.asyncio
async def test_tcp_rejects_every_non_exact_or_unbounded_timeout_before_socket_work(
    raw_timeout: object,
) -> None:
    """Mutation caught: passing a coercive, absent, or over-ceiling TCP timeout."""
    delegate = _Backend()
    resolver_calls = 0

    async def resolver(host: str) -> ResolvedEndpoint:
        nonlocal resolver_calls
        resolver_calls += 1
        return await _public(host)

    backend = BoundAsyncNetworkBackend(
        delegate=delegate, resolver=resolver, clock=lambda: 10.0
    )

    with pytest.raises((ValueError, httpcore.ConnectError), match="timeout"):
        _ = await backend.connect_tcp(
            NPLG_HOST,
            443,
            timeout=cast("float | None", raw_timeout),
        )

    assert resolver_calls == 0
    assert delegate.calls == []


@pytest.mark.parametrize(
    "raw_timeout",
    [None, True, 1, "1", -1.0, 0.0, math.nan, math.inf, 60.000_001],
)
@pytest.mark.asyncio
async def test_unix_and_sleep_reject_complete_invalid_timeout_matrix(
    raw_timeout: object,
) -> None:
    """Mutation caught: Unix/sleep accepting a timeout rejected by TCP."""
    delegate = _Backend()
    backend = BoundAsyncNetworkBackend(delegate=delegate, resolver=_public)

    with pytest.raises((ValueError, httpcore.ConnectError), match="timeout"):
        _ = await backend.connect_unix_socket(
            "/forbidden.sock",
            timeout=cast("float | None", raw_timeout),
        )
    with pytest.raises(ValueError, match="timeout"):
        await backend.sleep(cast("float", raw_timeout))

    assert delegate.sleeps == []


@pytest.mark.asyncio
async def test_tcp_round_trips_every_socket_option_variant_to_the_validated_ip() -> (
    None
):
    """Mutation caught: dropping the bytes, bytearray, or four-item None option."""
    delegate = _Backend()
    backend = BoundAsyncNetworkBackend(
        delegate=delegate, resolver=_public, clock=lambda: 10.0
    )
    options: tuple[SOCKET_OPTION, ...] = (
        (1, 2, 3),
        (1, 2, b"value"),
        (1, 2, bytearray(b"mutable")),
        (1, 2, None, 4),
    )

    _ = await backend.connect_tcp(
        NPLG_HOST,
        443,
        timeout=5.0,
        socket_options=options,
    )

    assert delegate.calls == [("1.1.1.1", 443, 5.0, options)]


@pytest.mark.parametrize("ttl", [0.1, 1.0, 30.0, 60.0, 600.0])
def test_resolved_endpoint_clamps_dns_ttl_to_the_closed_validity_window(
    ttl: float,
) -> None:
    """Mutation caught: accepting resolver TTLs below 1 or above 60 seconds."""
    endpoint = create_resolved_endpoint(
        hostname=NPLG_HOST,
        port=443,
        addresses=("1.1.1.1", "2606:4700:4700::1111"),
        ttl_seconds=ttl,
        clock=lambda: 10.0,
    )

    assert isinstance(endpoint, ResolvedEndpoint)
    assert endpoint.validity.expires_at - endpoint.validity.created_at == min(
        60.0, max(1.0, ttl)
    )
    assert endpoint.addresses == (
        ipaddress.ip_address("1.1.1.1"),
        ipaddress.ip_address("2606:4700:4700::1111"),
    )


@pytest.mark.parametrize(
    "addresses",
    [
        ("1.1.1.1", "127.0.0.1"),
        ("fec0::1",),
        ("1.1.1.1", "fec0::1"),
        ("1.1.1.1", "::ffff:127.0.0.1"),
        ("::ffff:8.8.8.8",),
        ("1.1.1.1", "::ffff:8.8.8.8"),
        ("fe80::1%eth0",),
        ("2606:4700:4700::1111%eth0",),
        ("1.1.1.1", "2606:4700:4700::1111%eth0"),
        ("0177.0.0.1",),
        (),
    ],
)
def test_resolved_endpoint_rejects_the_complete_answer_when_any_ip_is_unsafe(
    addresses: tuple[str, ...],
) -> None:
    """Mutation caught: filtering unsafe answers instead of rejecting the set."""
    with pytest.raises(ValueError, match="address"):
        _ = create_resolved_endpoint(
            hostname=NPLG_HOST,
            port=443,
            addresses=addresses,
            ttl_seconds=30.0,
            clock=lambda: 10.0,
        )


def test_outbound_headers_are_purpose_specific_and_never_copy_inbound_secrets() -> None:
    """Mutation caught: forwarding bearer, cookie, proxy, or forwarding headers."""
    inbound = {
        "Authorization": "Bearer task17-secret-canary",
        "Cookie": "session=task17-secret-canary",
        "Forwarded": "for=127.0.0.1",
        "X-Forwarded-For": "127.0.0.1",
        "Proxy-Authorization": "Basic task17-secret-canary",
        "X-MCP-Metadata": "task17-secret-canary",
    }

    metadata = build_outbound_headers(OutboundPurpose.METADATA, inbound_headers=inbound)
    download = build_outbound_headers(OutboundPurpose.DOWNLOAD, inbound_headers=inbound)

    serialized = repr((metadata, download)).lower()
    assert "task17-secret-canary" not in serialized
    assert "authorization" not in serialized
    assert "cookie" not in serialized
    assert "forward" not in serialized
    assert metadata["Accept"] != download["Accept"]


def test_outbound_headers_reject_a_forged_purpose_before_reading_inbound_data() -> None:
    """Mutation caught: coercing a caller-controlled outbound header purpose."""
    with pytest.raises(ValueError, match="purpose"):
        _ = build_outbound_headers(
            cast("OutboundPurpose", "metadata"),
            inbound_headers={"Authorization": "Bearer task17-secret"},
        )
