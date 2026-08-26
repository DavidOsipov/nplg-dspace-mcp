# Copyright (c) 2026 David Osipov
"""Bound outbound networking for the NPLG repository."""

from __future__ import annotations

import ipaddress
import math
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Literal, NewType, Protocol, cast, override

import dns.name
import dns.rdata
import dns.rdatatype
import dns.resolver
import httpcore
import httpx

from .bounded_work import DNS_WORK, BlockingWorkCapacityError
from .contracts import MonotonicDeadline
from .security import NPLG_HOST, is_forbidden_address

CanonicalHostname = NewType("CanonicalHostname", str)
Port = NewType("Port", int)
SOCKET_OPTION = (
    tuple[int, int, int]
    | tuple[int, int, bytes | bytearray]
    | tuple[int, int, None, int]
)
SocketOption = SOCKET_OPTION
_MAX_PORT = 65_535
_MAX_NETWORK_TIMEOUT_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    """Immutable all-public DNS answer bound to a monotonic validity window."""

    hostname: CanonicalHostname
    port: Port
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    validity: MonotonicDeadline

    def __post_init__(self) -> None:
        """Reject forged endpoint objects at the network boundary."""
        hostname = self.hostname
        if (
            type(hostname) is not str
            or not hostname
            or hostname != hostname.lower()
            or hostname.endswith(".")
        ):
            message = "endpoint hostname is not canonical"
            raise ValueError(message)
        try:
            _ = hostname.encode("ascii").decode("ascii")
        except UnicodeError as exc:
            message = "endpoint hostname is not canonical ASCII"
            raise ValueError(message) from exc
        if type(self.port) is not int or not 1 <= self.port <= _MAX_PORT:
            message = "endpoint port is invalid"
            raise ValueError(message)
        if type(self.addresses) is not tuple or not self.addresses:
            message = "endpoint address set is empty or mutable"
            raise ValueError(message)
        seen: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for address in self.addresses:
            if type(address) not in {ipaddress.IPv4Address, ipaddress.IPv6Address}:
                message = "endpoint address is invalid"
                raise ValueError(message)
            if address in seen or is_forbidden_address(address):
                message = "endpoint address set is duplicate or non-public"
                raise ValueError(message)
            seen.add(address)
        if type(self.validity) is not MonotonicDeadline:
            message = "endpoint validity is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class BoundNetworkObservation:
    """Complete facts derived from one bound HTTP/TLS connection lifecycle."""

    canonical_hostname: CanonicalHostname
    host_header: CanonicalHostname
    tls_sni_hostname: CanonicalHostname
    certificate_hostname: CanonicalHostname
    validated_addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    selected_address: ipaddress.IPv4Address | ipaddress.IPv6Address
    actual_peer: ipaddress.IPv4Address | ipaddress.IPv6Address
    request_count: int

    def __post_init__(self) -> None:
        """Reject incomplete, mutable, noncanonical, or non-public evidence."""
        names = (
            self.canonical_hostname,
            self.host_header,
            self.tls_sni_hostname,
            self.certificate_hostname,
        )
        if any(type(name) is not str or name != NPLG_HOST for name in names):
            message = "network observation hostname is invalid"
            raise ValueError(message)
        if type(self.validated_addresses) is not tuple or not self.validated_addresses:
            message = "network observation address set is invalid"
            raise ValueError(message)
        if len(set(self.validated_addresses)) != len(self.validated_addresses):
            message = "network observation address set is invalid"
            raise ValueError(message)
        for address in self.validated_addresses:
            if type(address) not in {
                ipaddress.IPv4Address,
                ipaddress.IPv6Address,
            } or is_forbidden_address(address):
                message = "network observation address set is invalid"
                raise ValueError(message)
        if (
            self.selected_address not in self.validated_addresses
            or self.actual_peer != self.selected_address
            or type(self.request_count) is not int
            or self.request_count != 1
        ):
            message = "network observation is incomplete"
            raise ValueError(message)


class _BoundNetworkTranscript:
    """Private mutable transcript populated only by the bound transport."""

    def __init__(self) -> None:
        super().__init__()
        self._host_header: CanonicalHostname | None = None
        self._endpoint: ResolvedEndpoint | None = None
        self._selected: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        self._peer: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        self._tls_sni: CanonicalHostname | None = None
        self._certificate_hostname: CanonicalHostname | None = None
        self._request_count = 0
        self._connection_count = 0
        self._tls_count = 0
        self._finalized = False

    def record_request(self, host_header: str) -> None:
        self._request_count += 1
        if self._request_count != 1 or host_header != NPLG_HOST:
            message = "observed transport request sequence is invalid"
            raise httpx.LocalProtocolError(message)
        self._host_header = CanonicalHostname(host_header)

    def record_connection(
        self,
        *,
        endpoint: ResolvedEndpoint,
        selected: str,
        peer: str,
    ) -> None:
        self._connection_count += 1
        if self._connection_count != 1:
            message = "observed transport connection sequence is invalid"
            raise httpcore.ConnectError(message)
        selected_address = ipaddress.ip_address(selected)
        peer_address = ipaddress.ip_address(peer)
        if (
            selected_address not in endpoint.addresses
            or peer_address != selected_address
        ):
            raise httpcore.ConnectError(_PEER_REJECTED)
        self._endpoint = endpoint
        self._selected = selected_address
        self._peer = peer_address

    def record_tls(
        self,
        *,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None,
    ) -> None:
        self._tls_count += 1
        if (
            self._tls_count != 1
            or server_hostname != NPLG_HOST
            or not ssl_context.check_hostname
            or ssl_context.verify_mode != ssl.CERT_REQUIRED
        ):
            message = "observed TLS identity is invalid"
            raise httpcore.ConnectError(message)
        self._tls_sni = CanonicalHostname(server_hostname)
        self._certificate_hostname = CanonicalHostname(server_hostname)

    def finalize(self) -> BoundNetworkObservation:
        if self._finalized:
            message = "network observation was already finalized"
            raise RuntimeError(message)
        self._finalized = True
        endpoint = self._endpoint
        if (
            self._request_count != 1
            or self._connection_count != 1
            or self._tls_count != 1
            or self._host_header is None
            or endpoint is None
            or self._selected is None
            or self._peer is None
            or self._tls_sni is None
            or self._certificate_hostname is None
        ):
            message = "network observation transcript is incomplete"
            raise RuntimeError(message)
        return BoundNetworkObservation(
            canonical_hostname=endpoint.hostname,
            host_header=self._host_header,
            tls_sni_hostname=self._tls_sni,
            certificate_hostname=self._certificate_hostname,
            validated_addresses=endpoint.addresses,
            selected_address=self._selected,
            actual_peer=self._peer,
            request_count=self._request_count,
        )


class NetworkObservationAuthority:
    """Typed trusted capability for consuming transport-derived proof once."""

    __slots__ = ("__transcript",)

    def __init__(self, transcript: _BoundNetworkTranscript) -> None:
        """Bind this capability to one private transport transcript."""
        super().__init__()
        self.__transcript = transcript

    def finalize(self) -> BoundNetworkObservation:
        """Return proof only after the instrumented lifecycle is complete."""
        return self.__transcript.finalize()


ApprovedAddressResolver = Callable[[str], Awaitable[ResolvedEndpoint]]
DnsTtlResolver = Callable[[str], tuple[tuple[str, ...], float]]
_HTTPS_PORT = 443
_TARGET_REJECTED = "outbound connection target is not approved"
_EMPTY_ADDRESS_SET = "approved address set is empty"
_PEER_REJECTED = "connected peer is not approved"
_UNIX_REJECTED = "Unix sockets are not permitted"
_ORIGIN_REJECTED = "outbound request origin is not approved"
_SNI_REJECTED = "request-controlled SNI override is not permitted"
_HOST_REJECTED = "outbound request Host header is not approved"
_DNS_CAPACITY_EXHAUSTED = "DNS resolver capacity is exhausted"
_DNS_LOOKUP_FAILED = "DNS resolution failed"
_DNS_POLICY_REJECTED = "DNS answer rejected by outbound policy"
_POLICY_MESSAGES = frozenset(
    {
        _TARGET_REJECTED,
        _EMPTY_ADDRESS_SET,
        _PEER_REJECTED,
        _UNIX_REJECTED,
        _ORIGIN_REJECTED,
        _SNI_REJECTED,
        _HOST_REJECTED,
        _DNS_POLICY_REJECTED,
    }
)
_GENERIC_POLICY_REJECTION = "Outbound transport policy rejected the request."


class _HttpcoreTransportPolicyError(httpcore.ConnectError):
    """Internal typed signal for a rejected bound-transport policy decision."""


class _DnsPolicyRejectionError(ValueError):
    """Internal typed signal for inconsistent canonical DNS evidence."""


class TransportPolicyError(httpx.LocalProtocolError):
    """Sanitized non-transient rejection from the bound outbound transport."""

    def __init__(self, internal_message: str = _GENERIC_POLICY_REJECTION) -> None:
        """Retain only one closed low-cardinality policy message."""
        message = (
            internal_message
            if internal_message in _POLICY_MESSAGES
            else _GENERIC_POLICY_REJECTION
        )
        super().__init__(message)


def classify_transport_failure(
    error: BaseException,
) -> Literal["transient", "excluded"]:
    """Classify only reviewed HTTP transport outcomes for circuit accounting."""
    if isinstance(error, TransportPolicyError):
        return "excluded"
    if isinstance(error, (TimeoutError, httpx.RequestError)):
        return "transient"
    message = "transport failure is outside the reviewed classifier"
    raise TypeError(message)


_HTTPCORE_EXCEPTIONS: tuple[tuple[type[Exception], type[httpx.HTTPError]], ...] = (
    (_HttpcoreTransportPolicyError, TransportPolicyError),
    (httpcore.ConnectTimeout, httpx.ConnectTimeout),
    (httpcore.ReadTimeout, httpx.ReadTimeout),
    (httpcore.WriteTimeout, httpx.WriteTimeout),
    (httpcore.PoolTimeout, httpx.PoolTimeout),
    (httpcore.ConnectError, httpx.ConnectError),
    (httpcore.ReadError, httpx.ReadError),
    (httpcore.WriteError, httpx.WriteError),
    (httpcore.ProxyError, httpx.ProxyError),
    (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
    (httpcore.LocalProtocolError, httpx.LocalProtocolError),
    (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
    (httpcore.TimeoutException, httpx.TimeoutException),
    (httpcore.NetworkError, httpx.NetworkError),
    (httpcore.ProtocolError, httpx.ProtocolError),
)


def create_resolved_endpoint(
    *,
    hostname: str,
    port: int,
    addresses: Iterable[str],
    ttl_seconds: float,
    clock: Callable[[], float],
) -> ResolvedEndpoint:
    """Create one validated endpoint from a complete DNS answer."""
    if type(hostname) is not str or not hostname:
        message = "endpoint hostname is invalid"
        raise ValueError(message)
    try:
        canonical_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        message = "endpoint hostname is invalid"
        raise ValueError(message) from exc
    canonical_hostname = canonical_hostname.removesuffix(".")
    if type(port) is not int or not 1 <= port <= _MAX_PORT:
        message = "endpoint port is invalid"
        raise ValueError(message)
    if type(ttl_seconds) is not float or not math.isfinite(ttl_seconds):
        message = "resolver TTL is invalid"
        raise ValueError(message)
    parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw_address in addresses:
        if type(raw_address) is not str or not raw_address or "%" in raw_address:
            message = "resolver address is invalid"
            raise _DnsPolicyRejectionError(message)
        try:
            parsed = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            message = "resolver address is invalid"
            raise ValueError(message) from exc
        if raw_address != str(parsed) or is_forbidden_address(parsed):
            message = "resolver address is noncanonical or non-public"
            raise _DnsPolicyRejectionError(message)
        if parsed in parsed_addresses:
            continue
        parsed_addresses.append(parsed)
    validity = MonotonicDeadline.after(
        min(60.0, max(1.0, ttl_seconds)),
        clock=clock,
    )
    return ResolvedEndpoint(
        hostname=CanonicalHostname(canonical_hostname),
        port=Port(port),
        addresses=tuple(parsed_addresses),
        validity=validity,
    )


def _canonical_cname_chain(
    answer: dns.resolver.Answer,
    *,
    host: str,
) -> tuple[str, ...]:
    links: dict[str, str] = {}
    for rrset in answer.response.answer:
        if rrset.rdtype != dns.rdatatype.CNAME:
            continue
        records = tuple(cast("Iterable[dns.rdata.Rdata]", rrset))
        if len(records) != 1:
            message = "DNS CNAME chain is ambiguous"
            raise _DnsPolicyRejectionError(message)
        owner = rrset.name.canonicalize().to_text()
        target = dns.name.from_text(records[0].to_text()).canonicalize().to_text()
        if owner in links:
            message = "DNS CNAME chain contains duplicate owners"
            raise _DnsPolicyRejectionError(message)
        links[owner] = target

    current = dns.name.from_text(host).canonicalize().to_text()
    chain: list[str] = []
    visited: set[str] = set()
    while current in links:
        if current in visited:
            message = "DNS CNAME chain contains a cycle"
            raise _DnsPolicyRejectionError(message)
        visited.add(current)
        current = links[current]
        chain.append(current)
    if len(visited) != len(links):
        message = "DNS CNAME answer contains an unrelated chain"
        raise _DnsPolicyRejectionError(message)
    canonical_name = answer.chaining_result.canonical_name.canonicalize().to_text()
    if current != canonical_name:
        message = "DNS CNAME chain changed during resolution"
        raise _DnsPolicyRejectionError(message)
    return tuple(chain)


def _consistent_cname_chain(
    expected: tuple[str, ...] | None,
    observed: tuple[str, ...],
) -> tuple[str, ...]:
    if expected is not None and observed != expected:
        message = "DNS CNAME chain changed across address families"
        raise _DnsPolicyRejectionError(message)
    return observed


def resolve_addresses_with_ttl(host: str) -> tuple[tuple[str, ...], float]:
    """Resolve the complete A/AAAA answer with authoritative TTL evidence."""
    if host.lower() != NPLG_HOST:
        raise _HttpcoreTransportPolicyError(_TARGET_REJECTED)
    resolver = dns.resolver.Resolver(configure=True)
    addresses: list[str] = []
    ttls: list[float] = []
    canonical_chain: tuple[str, ...] | None = None
    try:
        for record_type in ("A", "AAAA"):
            answer = resolver.resolve(
                host,
                record_type,
                raise_on_no_answer=False,
                lifetime=5.0,
                search=False,
            )
            observed_chain = _canonical_cname_chain(answer, host=host)
            canonical_chain = _consistent_cname_chain(
                canonical_chain,
                observed_chain,
            )
            if answer.rrset is None:
                continue
            ttl = float(answer.chaining_result.minimum_ttl)
            ttls.append(ttl)
            records = cast("Iterable[dns.rdata.Rdata]", answer.rrset)
            for record in records:
                address = record.to_text()
                if address not in addresses:
                    addresses.append(address)
    except _DnsPolicyRejectionError as exc:
        raise _HttpcoreTransportPolicyError(_DNS_POLICY_REJECTED) from exc
    except Exception as exc:
        raise httpcore.ConnectError(_DNS_LOOKUP_FAILED) from exc
    if not addresses or not ttls:
        raise httpcore.ConnectError(_DNS_LOOKUP_FAILED)
    return tuple(addresses), min(ttls)


async def resolve_approved_addresses_async(
    host: str,
    *,
    ttl_resolver: DnsTtlResolver | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> ResolvedEndpoint:
    """Resolve one complete approved endpoint without blocking the event loop."""
    actual_resolver = ttl_resolver or resolve_addresses_with_ttl

    def resolve() -> ResolvedEndpoint:
        addresses, ttl_seconds = actual_resolver(host)
        return create_resolved_endpoint(
            hostname=host,
            port=_HTTPS_PORT,
            addresses=addresses,
            ttl_seconds=ttl_seconds,
            clock=clock,
        )

    try:
        return await DNS_WORK.run(resolve)
    except BlockingWorkCapacityError as exc:
        raise httpcore.ConnectError(_DNS_CAPACITY_EXHAUSTED) from exc
    except ValueError as exc:
        raise _HttpcoreTransportPolicyError(_DNS_POLICY_REJECTED) from exc


class _CoreAsyncStream(Protocol):
    def __aiter__(self) -> AsyncIterator[bytes]: ...

    async def aclose(self) -> None: ...


class _RequestExtensions(Protocol):
    @property
    def extensions(self) -> dict[str, object]: ...


@contextmanager
def _map_httpcore_exceptions() -> Generator[None, None, None]:
    try:
        yield
    except Exception as exc:
        for source, target in _HTTPCORE_EXCEPTIONS:
            if isinstance(exc, source):
                raise target(str(exc)) from exc
        raise


class _AsyncResponseStream(httpx.AsyncByteStream):
    def __init__(
        self,
        stream: _CoreAsyncStream,
        pool: httpcore.AsyncConnectionPool,
    ) -> None:
        super().__init__()
        self._stream = stream
        self._pool = pool

    @override
    async def __aiter__(self) -> AsyncIterator[bytes]:
        with _map_httpcore_exceptions():
            async for chunk in self._stream:
                yield chunk

    @override
    async def aclose(self) -> None:
        with _map_httpcore_exceptions():
            try:
                await self._stream.aclose()
            finally:
                await self._pool.aclose()


def _normalized_peer(peer: object) -> tuple[str, int] | None:
    if not isinstance(peer, tuple):
        return None
    values = cast("tuple[object, ...]", peer)
    if len(values) not in {2, 4}:
        return None
    raw_address, raw_port = values[0], values[1]
    if not isinstance(raw_address, str) or type(raw_port) is not int:
        return None
    try:
        address = str(ipaddress.ip_address(raw_address))
    except ValueError:
        return None
    return address, raw_port


class _ObservedAsyncNetworkStream(httpcore.AsyncNetworkStream):
    """Delegate stream that records the successful TLS verification lifecycle."""

    def __init__(
        self,
        delegate: httpcore.AsyncNetworkStream,
        transcript: _BoundNetworkTranscript,
    ) -> None:
        super().__init__()
        self._delegate = delegate
        self._transcript = transcript

    @override
    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._delegate.read(max_bytes, timeout=timeout)

    @override
    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._delegate.write(buffer, timeout=timeout)

    @override
    async def aclose(self) -> None:
        await self._delegate.aclose()

    @override
    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._delegate.start_tls(
            ssl_context,
            server_hostname=server_hostname,
            timeout=timeout,
        )
        try:
            self._transcript.record_tls(
                ssl_context=ssl_context,
                server_hostname=server_hostname,
            )
        except BaseException:
            await stream.aclose()
            raise
        return _ObservedAsyncNetworkStream(stream, self._transcript)

    @override
    def get_extra_info(self, info: str) -> object | None:
        return cast("object | None", self._delegate.get_extra_info(info))


class BoundAsyncNetworkBackend(httpcore.AsyncNetworkBackend):
    """Network backend that will bind NPLG DNS approval to TCP connects."""

    def __init__(
        self,
        *,
        delegate: httpcore.AsyncNetworkBackend,
        resolver: ApprovedAddressResolver,
        clock: Callable[[], float] = time.monotonic,
        observation: _BoundNetworkTranscript | None = None,
    ) -> None:
        """Bind the approved-address resolver to a concrete network backend."""
        super().__init__()
        self._delegate = delegate
        self._resolver = resolver
        self._clock = clock
        self._observation = observation

    def _deadline(self, timeout: float | None) -> MonotonicDeadline:
        if (
            type(timeout) is not float
            or not math.isfinite(timeout)
            or not 0.0 < timeout <= _MAX_NETWORK_TIMEOUT_SECONDS
        ):
            message = "network timeout must be an exact finite float from 0 to 60"
            raise ValueError(message)
        return MonotonicDeadline.after(timeout, clock=self._clock)

    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        request_deadline = self._deadline(timeout)
        if (
            type(host) is not str
            or host != NPLG_HOST
            or type(port) is not int
            or port != _HTTPS_PORT
        ):
            raise _HttpcoreTransportPolicyError(_TARGET_REJECTED)
        endpoint = await self._resolver(host)
        if type(endpoint) is not ResolvedEndpoint:
            raise _HttpcoreTransportPolicyError(_EMPTY_ADDRESS_SET)
        try:
            endpoint = ResolvedEndpoint(
                hostname=endpoint.hostname,
                port=endpoint.port,
                addresses=endpoint.addresses,
                validity=endpoint.validity,
            )
        except ValueError as exc:
            raise _HttpcoreTransportPolicyError(_EMPTY_ADDRESS_SET) from exc
        if (
            endpoint.hostname != NPLG_HOST
            or endpoint.port != _HTTPS_PORT
            or not endpoint.addresses
        ):
            raise _HttpcoreTransportPolicyError(_EMPTY_ADDRESS_SET)
        now = self._clock()
        remaining = min(
            request_deadline.remaining(now=now),
            endpoint.validity.remaining(now=now),
        )
        if remaining <= 0.0:
            message = "validated endpoint or request timeout expired"
            raise httpcore.ConnectTimeout(message)
        selected = str(endpoint.addresses[0])
        stream = await self._delegate.connect_tcp(
            selected,
            port,
            timeout=remaining,
            local_address=local_address,
            socket_options=socket_options,
        )
        peer = cast("object", stream.get_extra_info("server_addr"))
        normalized_peer = _normalized_peer(peer)
        if normalized_peer is None or normalized_peer != (selected, port):
            await stream.aclose()
            raise _HttpcoreTransportPolicyError(_PEER_REJECTED)
        if self._observation is not None:
            self._observation.record_connection(
                endpoint=endpoint,
                selected=selected,
                peer=normalized_peer[0],
            )
            stream = _ObservedAsyncNetworkStream(stream, self._observation)
        return stream

    @override
    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        _ = self._deadline(timeout)
        del path, socket_options
        raise _HttpcoreTransportPolicyError(_UNIX_REJECTED)

    @override
    async def sleep(self, seconds: float) -> None:
        deadline = self._deadline(seconds)
        remaining = deadline.remaining(now=self._clock())
        if remaining <= 0.0:
            message = "network timeout expired"
            raise ValueError(message)
        await self._delegate.sleep(remaining)


class BoundAsyncHTTPTransport(httpx.AsyncBaseTransport):
    """HTTPX transport backed by a repository-controlled network backend."""

    def __init__(  # noqa: PLR0913 - protocol wiring requires independent seams.
        self,
        *,
        delegate: httpcore.AsyncNetworkBackend,
        resolver: ApprovedAddressResolver,
        limits: httpx.Limits | None = None,
        retries: int = 0,
        clock: Callable[[], float] = time.monotonic,
        observation: _BoundNetworkTranscript | None = None,
    ) -> None:
        """Construct a direct connection pool with no proxy configuration."""
        super().__init__()
        actual_limits = limits or httpx.Limits()
        self._backend = BoundAsyncNetworkBackend(
            delegate=delegate,
            resolver=resolver,
            clock=clock,
            observation=observation,
        )
        self._limits = actual_limits
        self._retries = retries
        self._observation = observation

    def _new_pool(self) -> httpcore.AsyncConnectionPool:
        return httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
            max_connections=self._limits.max_connections,
            max_keepalive_connections=0,
            keepalive_expiry=0.0,
            retries=self._retries,
            network_backend=self._backend,
        )

    @override
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        extensions = cast("_RequestExtensions", request).extensions
        if (
            request.url.raw_scheme != b"https"
            or request.url.raw_host.lower() != NPLG_HOST.encode("ascii")
            or request.url.port not in {None, _HTTPS_PORT}
        ):
            raise TransportPolicyError(_ORIGIN_REJECTED)
        if "sni_hostname" in extensions:
            raise TransportPolicyError(_SNI_REJECTED)
        if request.headers.get_list("host") != [NPLG_HOST]:
            raise TransportPolicyError(_HOST_REJECTED)
        if self._observation is not None:
            self._observation.record_request(request.headers["host"])
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=extensions,
        )
        pool = self._new_pool()
        try:
            with _map_httpcore_exceptions():
                response = await pool.handle_async_request(core_request)
        except BaseException:
            await pool.aclose()
            raise
        response_extensions = cast("_RequestExtensions", response).extensions
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_AsyncResponseStream(
                cast("_CoreAsyncStream", response.stream),
                pool,
            ),
            extensions=response_extensions,
        )

    @override
    async def aclose(self) -> None:
        return


def create_bound_http_transport(
    *, limits: httpx.Limits, retries: int = 0
) -> BoundAsyncHTTPTransport:
    """Create the direct, no-proxy production transport."""
    delegate = cast("httpcore.AsyncNetworkBackend", httpcore.AnyIOBackend())
    return BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=resolve_approved_addresses_async,
        limits=limits,
        retries=retries,
    )


@dataclass(frozen=True, slots=True)
class ObservedBoundHTTPTransport:
    """Instrumented transport paired with its one-use trusted proof capability."""

    transport: BoundAsyncHTTPTransport
    authority: NetworkObservationAuthority


def create_observed_bound_http_transport(
    *,
    limits: httpx.Limits,
    retries: int = 0,
    delegate: httpcore.AsyncNetworkBackend | None = None,
    resolver: ApprovedAddressResolver | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> ObservedBoundHTTPTransport:
    """Create one transcript-bound transport for the fixed live canary."""
    transcript = _BoundNetworkTranscript()
    actual_delegate = delegate or cast(
        "httpcore.AsyncNetworkBackend", httpcore.AnyIOBackend()
    )
    transport = BoundAsyncHTTPTransport(
        delegate=actual_delegate,
        resolver=resolver or resolve_approved_addresses_async,
        limits=limits,
        retries=retries,
        clock=clock,
        observation=transcript,
    )
    return ObservedBoundHTTPTransport(
        transport=transport,
        authority=NetworkObservationAuthority(transcript),
    )
