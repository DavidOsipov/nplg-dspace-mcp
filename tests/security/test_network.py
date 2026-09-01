# Copyright (c) 2026 David Osipov
# pyright: reportPrivateUsage=false
"""Adversarial tests for DNS-to-socket binding."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, override

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import httpcore
import httpx
import pytest

from nplg_mcp import network as network_module
from nplg_mcp.app import create_app
from nplg_mcp.bounded_work import DNS_WORK
from nplg_mcp.config import load_config
from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.network import (
    BoundAsyncHTTPTransport,
    BoundAsyncNetworkBackend,
    BoundNetworkObservation,
    ResolvedEndpoint,
    SocketOption,
    create_bound_http_transport,
    create_observed_bound_http_transport,
    create_resolved_endpoint,
    resolve_addresses_with_ttl,
    resolve_approved_addresses_async,
)
from nplg_mcp.repository import NplgRepository
from nplg_mcp.resilience import Closed, Open, UpstreamGuard, UpstreamGuardPolicy
from nplg_mcp.security import NPLG_HOST
from tests.helpers.app_factory import base_environment

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from nplg_mcp.tools import ToolService

_HTTPS_PORT = 443
_UNEXPECTED_PORT = "unexpected port"
_UNEXPECTED_UNIX = "Unix sockets are not expected"
_FIRST_CONNECT_FAILED = "first connection failed"
_CNAME_TTL = 2.0
_EXPECTED_TTL = 5.0
_EXPECTED_DISCOVERY_AND_SEARCH_CONNECTIONS = 2
_FORGED_BOOLEAN: object = True
_NETWORK_NAMESPACE = cast(
    "dict[str, object]",
    cast("object", network_module.__dict__),
)
_DNS_REJECTION = cast(
    "type[Exception]",
    _NETWORK_NAMESPACE["_DnsPolicyRejectionError"],
)


class _CnameChainParser(Protocol):
    def __call__(
        self,
        answer: dns.resolver.Answer,
        *,
        host: str,
    ) -> tuple[str, ...]: ...


_CNAME_CHAIN = cast(
    "_CnameChainParser",
    _NETWORK_NAMESPACE["_canonical_cname_chain"],
)


def _dns_runner_became_idle() -> bool:
    deadline = time.monotonic() + 1.0
    while DNS_WORK.active != 0 and time.monotonic() < deadline:
        time.sleep(0.001)
    return DNS_WORK.active == 0


@pytest.mark.asyncio
async def test_cancelled_dns_job_retains_resolver_capacity_until_worker_exits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def blocked_resolver(_host: str) -> tuple[tuple[str, ...], float]:
        started.set()
        try:
            assert release.wait(timeout=2.0)
            return ("93.184.216.34",), 5.0
        finally:
            finished.set()

    monkeypatch.setattr(
        "nplg_mcp.network.resolve_addresses_with_ttl",
        blocked_resolver,
    )
    first = asyncio.create_task(
        asyncio.wait_for(resolve_approved_addresses_async(NPLG_HOST), timeout=0.01)
    )
    try:
        assert await asyncio.to_thread(started.wait, 1.0)
        with pytest.raises(TimeoutError):
            _ = await first
        with pytest.raises(httpcore.ConnectError, match="resolver capacity"):
            _ = await resolve_approved_addresses_async(NPLG_HOST)
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 1.0)
        assert await asyncio.to_thread(_dns_runner_became_idle)

    endpoint = await resolve_approved_addresses_async(NPLG_HOST)
    assert tuple(str(address) for address in endpoint.addresses) == ("93.184.216.34",)


@pytest.mark.asyncio
async def test_ttl_bearing_dns_answer_creates_clamped_production_endpoint() -> None:
    """Mutation caught: discarding resolver TTL evidence or skipping its clamp."""
    now = 20.0

    def resolve_with_ttl(_host: str) -> tuple[tuple[str, ...], float]:
        return ("1.1.1.1",), 0.25

    endpoint = await resolve_approved_addresses_async(
        NPLG_HOST,
        ttl_resolver=resolve_with_ttl,
        clock=lambda: now,
    )

    assert endpoint.addresses == (ipaddress.ip_address("1.1.1.1"),)
    assert endpoint.validity.created_at == now
    assert endpoint.validity.expires_at == now + 1.0


def _dns_answer(
    host: str,
    record_type: str,
    ttl: int,
    *addresses: str,
) -> dns.resolver.Answer:
    absolute_host = f"{host}."
    query = dns.message.make_query(absolute_host, record_type)
    response = cast("dns.message.QueryMessage", dns.message.make_response(query))
    response.answer.append(
        dns.rrset.from_text(absolute_host, ttl, "IN", record_type, *addresses)
    )
    response = cast(
        "dns.message.QueryMessage",
        dns.message.from_wire(response.to_wire()),
    )
    return dns.resolver.Answer(
        dns.name.from_text(host, dns.name.root),
        dns.rdatatype.from_text(record_type),
        dns.rdataclass.IN,
        response,
    )


def _empty_dns_answer(host: str, record_type: str) -> dns.resolver.Answer:
    absolute_host = f"{host}."
    response = cast(
        "dns.message.QueryMessage",
        dns.message.make_response(dns.message.make_query(absolute_host, record_type)),
    )
    return dns.resolver.Answer(
        dns.name.from_text(host, dns.name.root),
        dns.rdatatype.from_text(record_type),
        dns.rdataclass.IN,
        response,
    )


def _cname_dns_answer(host: str) -> dns.resolver.Answer:
    absolute_host = f"{host}."
    alias = "nplg-edge.example."
    response = cast(
        "dns.message.QueryMessage",
        dns.message.make_response(dns.message.make_query(absolute_host, "A")),
    )
    response.answer.extend(
        (
            dns.rrset.from_text(absolute_host, 2, "IN", "CNAME", alias),
            dns.rrset.from_text(alias, 30, "IN", "A", "1.1.1.1"),
        )
    )
    response = cast(
        "dns.message.QueryMessage",
        dns.message.from_wire(response.to_wire()),
    )
    return dns.resolver.Answer(
        dns.name.from_text(host, dns.name.root),
        dns.rdatatype.A,
        dns.rdataclass.IN,
        response,
    )


def _cname_chain_dns_answer(
    host: str,
    record_type: str,
    *,
    aliases: tuple[str, ...],
    address: str | None,
) -> dns.resolver.Answer:
    absolute_host = f"{host}."
    response = cast(
        "dns.message.QueryMessage",
        dns.message.make_response(dns.message.make_query(absolute_host, record_type)),
    )
    owner = absolute_host
    for alias in aliases:
        response.answer.append(dns.rrset.from_text(owner, 20, "IN", "CNAME", alias))
        owner = alias
    if address is not None:
        response.answer.append(
            dns.rrset.from_text(owner, 30, "IN", record_type, address)
        )
    response = cast(
        "dns.message.QueryMessage",
        dns.message.from_wire(response.to_wire()),
    )
    return dns.resolver.Answer(
        dns.name.from_text(host, dns.name.root),
        dns.rdatatype.from_text(record_type),
        dns.rdataclass.IN,
        response,
    )


@dataclass(frozen=True, slots=True)
class _ForgedRecord:
    value: str

    def to_text(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class _ForgedChainingResult:
    canonical_name: dns.name.Name
    minimum_ttl: int


@dataclass(slots=True)
class _ForgedResponse:
    answer: list[dns.rrset.RRset]


@dataclass(slots=True)
class _ForgedAnswer:
    response: _ForgedResponse
    chaining_result: _ForgedChainingResult
    rrset: tuple[_ForgedRecord, ...]


def _forged_dns_answer(
    *,
    answer_rrsets: tuple[dns.rrset.RRset, ...] = (),
    canonical_name: str,
    records: tuple[str, ...] = (),
) -> dns.resolver.Answer:
    """Build only the resolver surface needed for adversarial parser tests."""
    value = _ForgedAnswer(
        response=_ForgedResponse(answer=list(answer_rrsets)),
        chaining_result=_ForgedChainingResult(
            canonical_name=dns.name.from_text(canonical_name),
            minimum_ttl=30,
        ),
        rrset=tuple(_ForgedRecord(value=record) for record in records),
    )
    return cast("dns.resolver.Answer", cast("object", value))


class _ForgedCnameRrset:
    """Minimal deliberately invalid multi-record CNAME RRset."""

    rdtype = dns.rdatatype.CNAME

    def __init__(self, owner: str, targets: tuple[str, ...]) -> None:
        super().__init__()
        self.name = dns.name.from_text(owner)
        self._targets = targets

    def __iter__(self) -> Iterator[_ForgedRecord]:
        return iter(tuple(_ForgedRecord(value=target) for target in self._targets))


def test_dns_cname_parser_rejects_ambiguous_duplicate_cyclic_and_unrelated_data() -> (
    None
):
    """Malformed resolver answers must fail closed before address authorization."""
    host = f"{NPLG_HOST}."
    edge = "edge.example."
    other = "other.example."
    ambiguous = cast(
        "dns.rrset.RRset",
        _ForgedCnameRrset(host, (edge, other)),
    )
    with pytest.raises(
        _DNS_REJECTION,
        match="ambiguous",
    ):
        _ = _CNAME_CHAIN(
            _forged_dns_answer(
                answer_rrsets=(ambiguous,),
                canonical_name=edge,
            ),
            host=NPLG_HOST,
        )

    duplicate_owner = (
        dns.rrset.from_text(host, 20, "IN", "CNAME", edge),
        dns.rrset.from_text(host, 20, "IN", "CNAME", other),
    )
    with pytest.raises(
        _DNS_REJECTION,
        match="duplicate owners",
    ):
        _ = _CNAME_CHAIN(
            _forged_dns_answer(
                answer_rrsets=duplicate_owner,
                canonical_name=edge,
            ),
            host=NPLG_HOST,
        )

    cycle = (
        dns.rrset.from_text(host, 20, "IN", "CNAME", edge),
        dns.rrset.from_text(edge, 20, "IN", "CNAME", host),
    )
    with pytest.raises(
        _DNS_REJECTION,
        match="cycle",
    ):
        _ = _CNAME_CHAIN(
            _forged_dns_answer(answer_rrsets=cycle, canonical_name=host),
            host=NPLG_HOST,
        )

    unrelated = (
        dns.rrset.from_text(host, 20, "IN", "CNAME", edge),
        dns.rrset.from_text(other, 20, "IN", "CNAME", "elsewhere.example."),
    )
    with pytest.raises(
        _DNS_REJECTION,
        match="unrelated chain",
    ):
        _ = _CNAME_CHAIN(
            _forged_dns_answer(answer_rrsets=unrelated, canonical_name=edge),
            host=NPLG_HOST,
        )

    changed = (dns.rrset.from_text(host, 20, "IN", "CNAME", edge),)
    with pytest.raises(
        _DNS_REJECTION,
        match="changed during resolution",
    ):
        _ = _CNAME_CHAIN(
            _forged_dns_answer(answer_rrsets=changed, canonical_name=other),
            host=NPLG_HOST,
        )


def test_dns_resolution_deduplicates_hostile_repeated_record_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated resolver records cannot inflate the authorized address set."""

    def resolve(
        _resolver: dns.resolver.Resolver,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        **_options: object,
    ) -> dns.resolver.Answer:
        del rdtype
        host = str(qname).removesuffix(".")
        return _forged_dns_answer(
            canonical_name=f"{host}.",
            records=("1.1.1.1", "1.1.1.1"),
        )

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)

    assert resolve_addresses_with_ttl(NPLG_HOST) == (("1.1.1.1",), 30.0)


def test_transport_classifier_rejects_unknown_exception_types() -> None:
    """Only the explicitly reviewed transport classes enter circuit accounting."""
    with pytest.raises(TypeError, match="outside the reviewed classifier"):
        _ = network_module.classify_transport_failure(RuntimeError("unexpected"))


@pytest.mark.asyncio
async def test_production_dns_layer_uses_minimum_ttl_and_rejects_mixed_private_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: fabricated TTL or partial acceptance of a mixed DNS set."""

    def resolve(
        _resolver: dns.resolver.Resolver,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        **_options: object,
    ) -> dns.resolver.Answer:
        host = str(qname).removesuffix(".")
        if str(rdtype) == "A":
            return _dns_answer(host, "A", 1, "1.1.1.1", "127.0.0.1")
        return _dns_answer(host, "AAAA", 90, "2606:4700:4700::1111")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)

    addresses, ttl = resolve_addresses_with_ttl(NPLG_HOST)
    assert set(addresses) == {"1.1.1.1", "127.0.0.1", "2606:4700:4700::1111"}
    assert ttl == 1.0
    with pytest.raises(httpcore.ConnectError, match="outbound policy"):
        _ = await resolve_approved_addresses_async(NPLG_HOST)


def test_production_dns_timeout_is_sanitized_as_transient_connect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: leaking resolver internals or treating timeout as success."""
    sensitive_marker = "task17-resolver-sensitive-marker"

    class ResolverTimeoutError(dns.resolver.LifetimeTimeout):
        def __init__(self, message: str) -> None:
            Exception.__init__(self, message)

    def timeout(
        _resolver: dns.resolver.Resolver,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        **_options: object,
    ) -> dns.resolver.Answer:
        del qname, rdtype
        raise ResolverTimeoutError(sensitive_marker)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", timeout)

    with pytest.raises(
        httpcore.ConnectError,
        match="DNS resolution failed",
    ) as captured:
        _ = resolve_addresses_with_ttl(NPLG_HOST)
    assert sensitive_marker not in str(captured.value)


def test_production_dns_layer_uses_cname_chain_minimum_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: ignoring a shorter CNAME TTL than the terminal A RRset."""

    def resolve(
        _resolver: dns.resolver.Resolver,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        **_options: object,
    ) -> dns.resolver.Answer:
        host = str(qname).removesuffix(".")
        if str(rdtype) == "A":
            return _cname_dns_answer(host)
        return _cname_chain_dns_answer(
            host,
            "AAAA",
            aliases=("nplg-edge.example.",),
            address=None,
        )

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)

    addresses, ttl = resolve_addresses_with_ttl(NPLG_HOST)
    assert addresses == ("1.1.1.1",)
    assert ttl == _CNAME_TTL


@pytest.mark.parametrize(
    ("a_aliases", "aaaa_aliases"),
    [
        (("edge-a.example.",), ("edge-b.example.",)),
        (
            ("edge-a.example.", "shared-edge.example."),
            ("edge-b.example.", "shared-edge.example."),
        ),
    ],
)
def test_production_dns_rejects_divergent_a_and_aaaa_cname_chains(
    monkeypatch: pytest.MonkeyPatch,
    a_aliases: tuple[str, ...],
    aaaa_aliases: tuple[str, ...],
) -> None:
    """Mutation caught: accepting DNS families with different canonical chains."""

    def resolve(
        _resolver: dns.resolver.Resolver,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        **_options: object,
    ) -> dns.resolver.Answer:
        host = str(qname).removesuffix(".")
        if str(rdtype) == "A":
            return _cname_chain_dns_answer(
                host,
                "A",
                aliases=a_aliases,
                address="1.1.1.1",
            )
        return _cname_chain_dns_answer(
            host,
            "AAAA",
            aliases=aaaa_aliases,
            address="2606:4700:4700::1111",
        )

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)

    with pytest.raises(httpcore.ConnectError, match="outbound policy"):
        _ = resolve_addresses_with_ttl(NPLG_HOST)


class _PeerStream(httpcore.AsyncNetworkStream):
    def __init__(self, peer: object) -> None:
        super().__init__()
        self.peer = peer
        self.closed = False

    @override
    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del max_bytes, timeout
        return b""

    @override
    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del buffer, timeout

    @override
    async def aclose(self) -> None:
        self.closed = True

    @override
    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del ssl_context, server_hostname, timeout
        return self

    @override
    def get_extra_info(self, info: str) -> object | None:
        return self.peer if info == "server_addr" else None


class _DriftingBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, *, peer: object) -> None:
        super().__init__()
        self.peer = peer
        self.connect_hosts: list[str] = []
        self.streams: list[_PeerStream] = []

    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        self.connect_hosts.append(host)
        if port != _HTTPS_PORT:
            raise AssertionError(_UNEXPECTED_PORT)
        if host == NPLG_HOST:
            return _PeerStream(("127.0.0.1", 443))
        stream = _PeerStream(self.peer)
        self.streams.append(stream)
        return stream

    @override
    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise AssertionError(_UNEXPECTED_UNIX)

    @override
    async def sleep(self, seconds: float) -> None:
        del seconds


class _HttpStream(_PeerStream):
    def __init__(self, peer: object, response: bytes) -> None:
        super().__init__(peer)
        self._response = response
        self.writes: list[bytes] = []
        self.server_hostnames: list[str | None] = []

    @override
    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del max_bytes, timeout
        response, self._response = self._response, b""
        return response

    @override
    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout
        self.writes.append(buffer)

    @override
    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del ssl_context, timeout
        self.server_hostnames.append(server_hostname)
        return self


class _HttpBackend(_DriftingBackend):
    def __init__(self) -> None:
        super().__init__(peer=("1.1.1.1", 443))
        self.http_stream = _HttpStream(
            ("1.1.1.1", 443),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
        )

    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        self.connect_hosts.append(host)
        if port != _HTTPS_PORT:
            raise AssertionError(_UNEXPECTED_PORT)
        return self.http_stream


class _RetryBackend(_DriftingBackend):
    def __init__(self) -> None:
        super().__init__(peer=("8.8.8.8", _HTTPS_PORT))
        self.http_stream = _HttpStream(
            ("8.8.8.8", _HTTPS_PORT),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
        )

    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        self.connect_hosts.append(host)
        if port != _HTTPS_PORT:
            raise AssertionError(_UNEXPECTED_PORT)
        if len(self.connect_hosts) == 1:
            raise httpcore.ConnectError(_FIRST_CONNECT_FAILED)
        return self.http_stream


async def _approved_cloudflare(host: str) -> ResolvedEndpoint:
    return create_resolved_endpoint(
        hostname=host,
        port=443,
        addresses=("1.1.1.1",),
        ttl_seconds=60.0,
        clock=time.monotonic,
    )


async def _empty_approved_set(_host: str) -> ResolvedEndpoint:
    return cast("ResolvedEndpoint", ())


async def _unexpected_resolver_failure(_host: str) -> ResolvedEndpoint:
    message = "unexpected resolver failure"
    raise RuntimeError(message)


@pytest.mark.asyncio
async def test_backend_connects_to_approved_literal_when_hostname_answer_drifts() -> (
    None
):
    delegate = _DriftingBackend(peer=("1.1.1.1", 443))
    backend = BoundAsyncNetworkBackend(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    stream = await backend.connect_tcp(NPLG_HOST, 443, timeout=5.0)

    assert delegate.connect_hosts == ["1.1.1.1"]
    assert stream is delegate.streams[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reported_peer",
    [
        None,
        ("8.8.8.8", 443),
        ("1.1.1.1", 80),
        ("1.1.1.1",),
        (1, 443),
        ("not-an-ip", 443),
    ],
)
async def test_backend_closes_connection_when_peer_is_not_approved(
    reported_peer: object,
) -> None:
    delegate = _DriftingBackend(peer=reported_peer)
    backend = BoundAsyncNetworkBackend(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    with pytest.raises(httpcore.ConnectError, match="connected peer is not approved"):
        _ = await backend.connect_tcp(NPLG_HOST, 443, timeout=5.0)

    assert delegate.streams[0].closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "port"),
    [("example.test", _HTTPS_PORT), (NPLG_HOST, 80)],
)
async def test_backend_rejects_every_noncanonical_connect_target(
    host: str,
    port: int,
) -> None:
    delegate = _DriftingBackend(peer=("1.1.1.1", _HTTPS_PORT))
    backend = BoundAsyncNetworkBackend(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    with pytest.raises(httpcore.ConnectError, match="target is not approved"):
        _ = await backend.connect_tcp(host, port, timeout=5.0)

    assert delegate.connect_hosts == []


@pytest.mark.asyncio
async def test_backend_rejects_an_empty_fresh_dns_answer() -> None:
    delegate = _DriftingBackend(peer=("1.1.1.1", _HTTPS_PORT))
    backend = BoundAsyncNetworkBackend(
        delegate=delegate,
        resolver=_empty_approved_set,
    )

    with pytest.raises(httpcore.ConnectError, match="address set is empty"):
        _ = await backend.connect_tcp(NPLG_HOST, _HTTPS_PORT, timeout=5.0)

    assert delegate.connect_hosts == []


@pytest.mark.asyncio
async def test_backend_rejects_unix_socket_bypass(tmp_path: Path) -> None:
    delegate = _DriftingBackend(peer=("1.1.1.1", 443))
    backend = BoundAsyncNetworkBackend(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    with pytest.raises(httpcore.ConnectError, match="Unix sockets are not permitted"):
        _ = await backend.connect_unix_socket(
            str(tmp_path / "upstream.sock"), timeout=5.0
        )


@pytest.mark.asyncio
async def test_transport_preserves_hostname_for_url_host_header_and_tls() -> None:
    delegate = _HttpBackend()
    transport = BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    async with httpx.AsyncClient(
        transport=transport,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = await client.get(f"https://{NPLG_HOST}/simple-search")

    request_bytes = b"".join(delegate.http_stream.writes)
    assert response.text == "OK"
    assert str(response.request.url) == f"https://{NPLG_HOST}/simple-search"
    assert delegate.connect_hosts == ["1.1.1.1"]
    assert b"Host: dspace.nplg.gov.ge\r\n" in request_bytes
    assert delegate.http_stream.server_hostnames == [NPLG_HOST]


@pytest.mark.asyncio
async def test_sequential_same_origin_hops_reconnect_to_fresh_dns_answer() -> None:
    """Mutation caught: keep-alive reuse bypassing redirect-hop DNS revalidation."""
    answers = iter(("1.1.1.1", "8.8.8.8"))

    async def resolve(host: str) -> ResolvedEndpoint:
        return create_resolved_endpoint(
            hostname=host,
            port=443,
            addresses=(next(answers),),
            ttl_seconds=60.0,
            clock=time.monotonic,
        )

    class FreshBackend(_DriftingBackend):
        @override
        async def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: Iterable[SocketOption] | None = None,
        ) -> httpcore.AsyncNetworkStream:
            del timeout, local_address, socket_options
            self.connect_hosts.append(host)
            return _HttpStream(
                (host, port),
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            )

    delegate = FreshBackend(peer=("1.1.1.1", 443))
    transport = BoundAsyncHTTPTransport(delegate=delegate, resolver=resolve)
    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        first = await client.get(f"https://{NPLG_HOST}/simple-search")
        second = await client.get(f"https://{NPLG_HOST}/simple-search?start=1")

    assert first.text == second.text == "OK"
    assert delegate.connect_hosts == ["1.1.1.1", "8.8.8.8"]


@pytest.mark.asyncio
async def test_observed_transport_derives_proof_from_bound_tls_lifecycle() -> None:
    """Mutation caught: accepting synthetic network proof outside the transport."""
    delegate = _HttpBackend()
    observed = create_observed_bound_http_transport(
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    async with httpx.AsyncClient(
        transport=observed.transport,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = await client.get(f"https://{NPLG_HOST}/simple-search")
        assert await response.aread() == b"OK"

    proof = observed.authority.finalize()
    assert proof.canonical_hostname == NPLG_HOST
    assert proof.host_header == NPLG_HOST
    assert proof.tls_sni_hostname == NPLG_HOST
    assert proof.certificate_hostname == NPLG_HOST
    assert tuple(str(address) for address in proof.validated_addresses) == ("1.1.1.1",)
    assert str(proof.selected_address) == "1.1.1.1"
    assert proof.actual_peer == proof.selected_address
    assert proof.request_count == 1


@pytest.mark.asyncio
async def test_observed_transport_rejects_missing_or_duplicate_probe_transcript() -> (
    None
):
    """Mutation caught: finalizing zero or multiple canary request sequences."""
    skipped = create_observed_bound_http_transport(
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        delegate=_HttpBackend(),
        resolver=_approved_cloudflare,
    )
    with pytest.raises(RuntimeError, match="incomplete"):
        _ = skipped.authority.finalize()

    duplicate = create_observed_bound_http_transport(
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        delegate=_HttpBackend(),
        resolver=_approved_cloudflare,
    )
    async with httpx.AsyncClient(
        transport=duplicate.transport,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        first = await client.get(f"https://{NPLG_HOST}/simple-search")
        assert await first.aread() == b"OK"
        with pytest.raises(httpx.LocalProtocolError, match="sequence"):
            _ = await client.get(f"https://{NPLG_HOST}/simple-search")
    with pytest.raises(RuntimeError, match="incomplete"):
        _ = duplicate.authority.finalize()


@pytest.mark.asyncio
async def test_transport_maps_peer_rejection_to_httpx_request_error() -> None:
    delegate = _DriftingBackend(peer=("8.8.8.8", 443))
    transport = BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        with pytest.raises(network_module.TransportPolicyError):
            _ = await client.get(f"https://{NPLG_HOST}/simple-search")

    assert delegate.streams[0].closed is True


@pytest.mark.asyncio
async def test_transport_does_not_reclassify_an_unknown_connector_failure() -> None:
    delegate = _DriftingBackend(peer=("1.1.1.1", _HTTPS_PORT))
    transport = BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=_unexpected_resolver_failure,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        with pytest.raises(RuntimeError, match="unexpected resolver failure"):
            _ = await client.get(f"https://{NPLG_HOST}/simple-search")

    assert delegate.connect_hosts == []


@pytest.mark.asyncio
async def test_transport_resolves_fresh_approved_address_for_connect_retry() -> None:
    answers = iter(("1.1.1.1", "8.8.8.8"))

    async def resolve(host: str) -> ResolvedEndpoint:
        return create_resolved_endpoint(
            hostname=host,
            port=443,
            addresses=(next(answers),),
            ttl_seconds=60.0,
            clock=time.monotonic,
        )

    delegate = _RetryBackend()
    backend = BoundAsyncNetworkBackend(
        delegate=delegate,
        resolver=resolve,
    )

    with pytest.raises(httpcore.ConnectError, match="first connection failed"):
        _ = await backend.connect_tcp(NPLG_HOST, 443, timeout=5.0)
    stream = await backend.connect_tcp(NPLG_HOST, 443, timeout=5.0)

    assert stream is delegate.http_stream
    assert delegate.connect_hosts == ["1.1.1.1", "8.8.8.8"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        f"http://{NPLG_HOST}:443/simple-search",
        "https://example.test/simple-search",
        f"https://{NPLG_HOST}:444/simple-search",
    ],
)
async def test_transport_rejects_noncanonical_origin_before_connect(url: str) -> None:
    delegate = _HttpBackend()
    transport = BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        with pytest.raises(httpx.LocalProtocolError, match="not approved"):
            _ = await client.get(url)

    assert delegate.connect_hosts == []


@pytest.mark.asyncio
async def test_transport_rejects_request_controlled_sni_before_connect() -> None:
    delegate = _HttpBackend()
    transport = BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )
    extensions: dict[str, object] = {"sni_hostname": "attacker.example"}
    request = httpx.Request(
        "GET",
        f"https://{NPLG_HOST}/simple-search",
        extensions=extensions,
    )

    with pytest.raises(httpx.LocalProtocolError, match="SNI override"):
        _ = await transport.handle_async_request(request)

    assert delegate.connect_hosts == []


@pytest.mark.asyncio
async def test_transport_rejects_request_controlled_host_before_connect() -> None:
    delegate = _HttpBackend()
    transport = BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )
    request = httpx.Request(
        "GET",
        f"https://{NPLG_HOST}/simple-search",
        headers={"Host": "attacker.example"},
    )

    with pytest.raises(httpx.LocalProtocolError, match="Host header"):
        _ = await transport.handle_async_request(request)

    assert delegate.connect_hosts == []


@pytest.mark.asyncio
async def test_runtime_client_binds_repository_connection_to_approved_literal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mutation caught: enabling ambient proxy routing in the production client."""
    body = (Path(__file__).parents[1] / "fixtures" / "search_results.html").read_bytes()
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    streams: list[_HttpStream] = []
    connected_hosts: list[str] = []

    async def connect_tcp(
        _backend: httpcore.AnyIOBackend,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - protocol signature.
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        connected_hosts.append(host)
        if port != _HTTPS_PORT:
            raise AssertionError(_UNEXPECTED_PORT)
        stream = _HttpStream(("1.1.1.1", 443), response)
        streams.append(stream)
        return stream

    def resolve(_host: str) -> tuple[str, ...]:
        return ("1.1.1.1",)

    def resolve_dns(
        _resolver: dns.resolver.Resolver,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        **_options: object,
    ) -> dns.resolver.Answer:
        host = str(qname).removesuffix(".")
        if str(rdtype) == "A":
            return _dns_answer(host, "A", 60, "1.1.1.1")
        return _empty_dns_answer(host, "AAAA")

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect_tcp)
    monkeypatch.setattr("nplg_mcp.repository.resolve_approved_addresses", resolve)
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve_dns)
    monkeypatch.setenv("HTTP_PROXY", "http://proxy-http.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy-https.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://proxy-all.invalid:1080")
    monkeypatch.setenv("NO_PROXY", "")
    config = load_config(base_environment(CACHE_DIR=str(tmp_path)))
    application = create_app(config)
    services = application.services
    assert services is not None
    try:
        tools = cast("ToolService", services.tools)
        repository = cast("NplgRepository", tools.repository)
        client = cast("httpx.AsyncClient", services.http_client)
        assert client._trust_env is False  # noqa: SLF001
        _ = await repository.search("test", page_size=2)
    finally:
        if services.http_client is not None:
            await services.http_client.aclose()

    assert connected_hosts == ["1.1.1.1"] * _EXPECTED_DISCOVERY_AND_SEARCH_CONNECTIONS
    assert all(stream.server_hostnames == [NPLG_HOST] for stream in streams)


@pytest.mark.asyncio
async def test_production_resolver_policy_rejection_is_excluded_but_timeout_opens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: collapsing DNS policy rejection into transient connect error."""
    mode = "policy"

    class ResolverTimeoutError(dns.resolver.LifetimeTimeout):
        def __init__(self) -> None:
            Exception.__init__(self, "synthetic resolver timeout")

    def resolve_dns(
        _resolver: dns.resolver.Resolver,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        **_options: object,
    ) -> dns.resolver.Answer:
        host = str(qname).removesuffix(".")
        if mode == "timeout":
            raise ResolverTimeoutError
        if str(rdtype) == "A":
            return _dns_answer(host, "A", 30, "1.1.1.1", "127.0.0.1")
        return _empty_dns_answer(host, "AAAA")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve_dns)
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        random=lambda: 0.5,
    )
    transport = create_bound_http_transport(limits=httpx.Limits(max_connections=1))
    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            guard=guard,
        )
        with pytest.raises(AppError) as rejected:
            _ = await repository.search("test")
        assert rejected.value.code is ErrorCode.UPSTREAM_FAILURE
        after_rejection: object = guard.state
        assert isinstance(after_rejection, Closed)

        mode = "timeout"
        with pytest.raises(AppError) as timed_out:
            _ = await repository.search("test")
        assert timed_out.value.code is ErrorCode.UPSTREAM_FAILURE
        after_timeout: object = guard.state
        assert isinstance(after_timeout, Open)


def test_endpoint_and_observation_models_reject_forged_boundary_values() -> None:
    """Mutation caught: trusting mutable, noncanonical, private, or mismatched proof."""
    validity = MonotonicDeadline(created_at=0.0, expires_at=1.0)
    invalid_endpoints: tuple[dict[str, object], ...] = (
        {
            "hostname": "NPLG.example",
            "port": 443,
            "addresses": (ipaddress.ip_address("1.1.1.1"),),
            "validity": validity,
        },
        {
            "hostname": "nplg.\udcff",
            "port": 443,
            "addresses": (ipaddress.ip_address("1.1.1.1"),),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": cast("int", _FORGED_BOOLEAN),
            "addresses": (ipaddress.ip_address("1.1.1.1"),),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": (),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": cast("tuple[ipaddress.IPv4Address]", ("1.1.1.1",)),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": (ipaddress.ip_address("127.0.0.1"),),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": (ipaddress.ip_address("::ffff:8.8.8.8"),),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": (ipaddress.ip_address("2606:4700:4700::1111%eth0"),),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": (
                ipaddress.ip_address("1.1.1.1"),
                ipaddress.ip_address("::ffff:8.8.8.8"),
            ),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": (
                ipaddress.ip_address("1.1.1.1"),
                ipaddress.ip_address("2606:4700:4700::1111%eth0"),
            ),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": (
                ipaddress.ip_address("1.1.1.1"),
                ipaddress.ip_address("1.1.1.1"),
            ),
            "validity": validity,
        },
        {
            "hostname": "nplg.example",
            "port": 443,
            "addresses": (ipaddress.ip_address("1.1.1.1"),),
            "validity": cast("MonotonicDeadline", object()),
        },
    )
    for endpoint_values in invalid_endpoints:
        with pytest.raises(ValueError, match="endpoint"):
            _ = ResolvedEndpoint(**endpoint_values)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]

    valid = {
        "canonical_hostname": NPLG_HOST,
        "host_header": NPLG_HOST,
        "tls_sni_hostname": NPLG_HOST,
        "certificate_hostname": NPLG_HOST,
        "validated_addresses": (ipaddress.ip_address("1.1.1.1"),),
        "selected_address": ipaddress.ip_address("1.1.1.1"),
        "actual_peer": ipaddress.ip_address("1.1.1.1"),
        "request_count": 1,
    }
    mutations: tuple[dict[str, object], ...] = (
        {"host_header": "attacker.example"},
        {"validated_addresses": ()},
        {
            "validated_addresses": (
                ipaddress.ip_address("1.1.1.1"),
                ipaddress.ip_address("1.1.1.1"),
            )
        },
        {"validated_addresses": cast("tuple[ipaddress.IPv4Address]", ("1.1.1.1",))},
        {"validated_addresses": (ipaddress.ip_address("127.0.0.1"),)},
        {"validated_addresses": (ipaddress.ip_address("::ffff:8.8.8.8"),)},
        {"validated_addresses": (ipaddress.ip_address("2606:4700:4700::1111%eth0"),)},
        {
            "validated_addresses": (
                ipaddress.ip_address("1.1.1.1"),
                ipaddress.ip_address("::ffff:8.8.8.8"),
            )
        },
        {
            "validated_addresses": (
                ipaddress.ip_address("1.1.1.1"),
                ipaddress.ip_address("2606:4700:4700::1111%eth0"),
            )
        },
        {"selected_address": ipaddress.ip_address("8.8.8.8")},
        {"actual_peer": ipaddress.ip_address("8.8.8.8")},
        {"request_count": cast("int", _FORGED_BOOLEAN)},
    )
    for mutation in mutations:
        observation_values: dict[str, object] = dict(valid)
        observation_values.update(mutation)
        with pytest.raises(ValueError, match="network observation"):
            _ = BoundNetworkObservation(**observation_values)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


def test_endpoint_factory_rejects_invalid_identity_port_ttl_and_deduplicates() -> None:
    """Reject coercive resolver identity/TTL and retain no duplicate answers."""
    base: dict[str, object] = {
        "hostname": NPLG_HOST,
        "port": 443,
        "addresses": ("1.1.1.1",),
        "ttl_seconds": 5.0,
        "clock": lambda: 0.0,
    }
    mutations: tuple[dict[str, object], ...] = (
        {"hostname": cast("str", _FORGED_BOOLEAN)},
        {"hostname": "\udcff"},
        {"port": cast("int", _FORGED_BOOLEAN)},
        {"ttl_seconds": cast("float", _FORGED_BOOLEAN)},
        {"ttl_seconds": float("nan")},
    )
    for mutation in mutations:
        values = dict(base)
        values.update(mutation)
        with pytest.raises(ValueError, match=r"endpoint|TTL"):
            _ = create_resolved_endpoint(**values)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]

    endpoint = create_resolved_endpoint(
        hostname=NPLG_HOST,
        port=443,
        addresses=("1.1.1.1", "1.1.1.1"),
        ttl_seconds=5.0,
        clock=lambda: 0.0,
    )
    assert endpoint.addresses == (ipaddress.ip_address("1.1.1.1"),)


def test_production_dns_rejects_wrong_host_and_empty_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: resolving another host or accepting zero DNS evidence."""
    with pytest.raises(httpcore.ConnectError, match="not approved"):
        _ = resolve_addresses_with_ttl("attacker.example")

    def empty_answer(
        _resolver: dns.resolver.Resolver,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        **_options: object,
    ) -> dns.resolver.Answer:
        del qname, rdtype
        return _empty_dns_answer(NPLG_HOST, "A")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", empty_answer)
    with pytest.raises(httpcore.ConnectError, match="DNS resolution failed"):
        _ = resolve_addresses_with_ttl(NPLG_HOST)


def test_observation_transcript_rejects_duplicate_mismatch_and_invalid_tls() -> None:
    """Mutation caught: finalizing duplicated or identity-mismatched socket evidence."""
    endpoint = create_resolved_endpoint(
        hostname=NPLG_HOST,
        port=443,
        addresses=("1.1.1.1",),
        ttl_seconds=5.0,
        clock=lambda: 0.0,
    )
    transcript = network_module._BoundNetworkTranscript()  # noqa: SLF001
    transcript.record_request(NPLG_HOST)
    with pytest.raises(httpx.LocalProtocolError, match="sequence"):
        transcript.record_request(NPLG_HOST)

    mismatch = network_module._BoundNetworkTranscript()  # noqa: SLF001
    with pytest.raises(httpcore.ConnectError, match="peer"):
        mismatch.record_connection(
            endpoint=endpoint, selected="1.1.1.1", peer="8.8.8.8"
        )

    duplicate = network_module._BoundNetworkTranscript()  # noqa: SLF001
    duplicate.record_connection(endpoint=endpoint, selected="1.1.1.1", peer="1.1.1.1")
    with pytest.raises(httpcore.ConnectError, match="sequence"):
        duplicate.record_connection(
            endpoint=endpoint, selected="1.1.1.1", peer="1.1.1.1"
        )

    invalid_tls = network_module._BoundNetworkTranscript()  # noqa: SLF001
    context = ssl.create_default_context()
    context.check_hostname = False
    with pytest.raises(httpcore.ConnectError, match="TLS identity"):
        invalid_tls.record_tls(ssl_context=context, server_hostname=NPLG_HOST)

    complete = network_module._BoundNetworkTranscript()  # noqa: SLF001
    complete.record_request(NPLG_HOST)
    complete.record_connection(endpoint=endpoint, selected="1.1.1.1", peer="1.1.1.1")
    complete.record_tls(
        ssl_context=ssl.create_default_context(), server_hostname=NPLG_HOST
    )
    _ = complete.finalize()
    with pytest.raises(RuntimeError, match="already finalized"):
        _ = complete.finalize()


@pytest.mark.asyncio
async def test_tls_failure_closes_stream_and_forged_endpoint_is_rejected() -> None:
    """Reject a leaked TLS stream or post-validation endpoint forgery."""
    stream = _PeerStream(("1.1.1.1", 443))
    transcript = network_module._BoundNetworkTranscript()  # noqa: SLF001
    observed_stream = network_module._ObservedAsyncNetworkStream(stream, transcript)  # noqa: SLF001
    context = ssl.create_default_context()
    context.check_hostname = False
    with pytest.raises(httpcore.ConnectError, match="TLS identity"):
        _ = await observed_stream.start_tls(
            context, server_hostname=NPLG_HOST, timeout=1.0
        )
    assert stream.closed is True

    forged = create_resolved_endpoint(
        hostname=NPLG_HOST,
        port=443,
        addresses=("1.1.1.1",),
        ttl_seconds=5.0,
        clock=lambda: 0.0,
    )
    object.__setattr__(forged, "addresses", ())

    async def forged_resolver(_host: str) -> ResolvedEndpoint:
        return forged

    delegate = _DriftingBackend(peer=("1.1.1.1", 443))
    backend = BoundAsyncNetworkBackend(
        delegate=delegate, resolver=forged_resolver, clock=lambda: 0.0
    )
    with pytest.raises(httpcore.ConnectError, match="address set"):
        _ = await backend.connect_tcp(NPLG_HOST, 443, timeout=1.0)


@pytest.mark.asyncio
async def test_backend_rejects_mismatched_or_expired_endpoint_and_expired_sleep() -> (
    None
):
    """Mutation caught: using wrong-host/expired DNS proof or sleeping past deadline."""

    async def mismatched(_host: str) -> ResolvedEndpoint:
        return create_resolved_endpoint(
            hostname="example.test",
            port=443,
            addresses=("1.1.1.1",),
            ttl_seconds=5.0,
            clock=lambda: 0.0,
        )

    delegate = _DriftingBackend(peer=("1.1.1.1", 443))
    wrong = BoundAsyncNetworkBackend(
        delegate=delegate, resolver=mismatched, clock=lambda: 0.0
    )
    with pytest.raises(httpcore.ConnectError, match="address set"):
        _ = await wrong.connect_tcp(NPLG_HOST, 443, timeout=1.0)

    async def expired(host: str) -> ResolvedEndpoint:
        return create_resolved_endpoint(
            hostname=host,
            port=443,
            addresses=("1.1.1.1",),
            ttl_seconds=1.0,
            clock=lambda: 0.0,
        )

    stale = BoundAsyncNetworkBackend(
        delegate=delegate, resolver=expired, clock=lambda: 2.0
    )
    with pytest.raises(httpcore.ConnectTimeout, match="expired"):
        _ = await stale.connect_tcp(NPLG_HOST, 443, timeout=1.0)

    values = iter((0.0, 61.0))
    sleeper = BoundAsyncNetworkBackend(
        delegate=delegate, resolver=expired, clock=lambda: next(values)
    )
    with pytest.raises(ValueError, match="expired"):
        await sleeper.sleep(1.0)

    slept: list[float] = []

    class _SleepBackend(_DriftingBackend):
        @override
        async def sleep(self, seconds: float) -> None:
            slept.append(seconds)

    successful_sleep = BoundAsyncNetworkBackend(
        delegate=_SleepBackend(peer=("1.1.1.1", 443)),
        resolver=expired,
        clock=lambda: 0.0,
    )
    await successful_sleep.sleep(1.0)
    assert slept == [1.0]
