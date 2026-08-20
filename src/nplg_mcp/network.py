# Copyright (c) 2026 David Osipov
"""Bound outbound networking for the NPLG repository."""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator, Awaitable, Callable, Generator, Iterable
from contextlib import contextmanager
from functools import partial
from typing import Protocol, cast, override

import httpcore
import httpx

from .bounded_work import DNS_WORK, BlockingWorkCapacityError
from .security import NPLG_HOST, resolve_approved_addresses

SocketOption = (
    tuple[int, int, int]
    | tuple[int, int, bytes | bytearray]
    | tuple[int, int, None, int]
)
ApprovedAddressResolver = Callable[[str], Awaitable[tuple[str, ...]]]
_HTTPS_PORT = 443
_TARGET_REJECTED = "outbound connection target is not approved"
_EMPTY_ADDRESS_SET = "approved address set is empty"
_PEER_REJECTED = "connected peer is not approved"
_UNIX_REJECTED = "Unix sockets are not permitted"
_ORIGIN_REJECTED = "outbound request origin is not approved"
_SNI_REJECTED = "request-controlled SNI override is not permitted"
_HOST_REJECTED = "outbound request Host header is not approved"
_DNS_CAPACITY_EXHAUSTED = "DNS resolver capacity is exhausted"
_HTTPCORE_EXCEPTIONS: tuple[tuple[type[Exception], type[httpx.HTTPError]], ...] = (
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


async def resolve_approved_addresses_async(host: str) -> tuple[str, ...]:
    """Resolve approved addresses without blocking the event loop."""
    try:
        return await DNS_WORK.run(partial(resolve_approved_addresses, host))
    except BlockingWorkCapacityError as exc:
        raise httpcore.ConnectError(_DNS_CAPACITY_EXHAUSTED) from exc


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
    def __init__(self, stream: _CoreAsyncStream) -> None:
        super().__init__()
        self._stream = stream

    @override
    async def __aiter__(self) -> AsyncIterator[bytes]:
        with _map_httpcore_exceptions():
            async for chunk in self._stream:
                yield chunk

    @override
    async def aclose(self) -> None:
        with _map_httpcore_exceptions():
            await self._stream.aclose()


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


class BoundAsyncNetworkBackend(httpcore.AsyncNetworkBackend):
    """Network backend that will bind NPLG DNS approval to TCP connects."""

    def __init__(
        self,
        *,
        delegate: httpcore.AsyncNetworkBackend,
        resolver: ApprovedAddressResolver,
    ) -> None:
        """Bind the approved-address resolver to a concrete network backend."""
        super().__init__()
        self._delegate = delegate
        self._resolver = resolver

    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.lower() != NPLG_HOST or port != _HTTPS_PORT:
            raise httpcore.ConnectError(_TARGET_REJECTED)
        addresses = await self._resolver(host)
        if not addresses:
            raise httpcore.ConnectError(_EMPTY_ADDRESS_SET)
        selected = str(ipaddress.ip_address(addresses[0]))
        stream = await self._delegate.connect_tcp(
            selected,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        peer = cast("object", stream.get_extra_info("server_addr"))
        if _normalized_peer(peer) != (selected, port):
            await stream.aclose()
            raise httpcore.ConnectError(_PEER_REJECTED)
        return stream

    @override
    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise httpcore.ConnectError(_UNIX_REJECTED)

    @override
    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class BoundAsyncHTTPTransport(httpx.AsyncBaseTransport):
    """HTTPX transport backed by a repository-controlled network backend."""

    def __init__(
        self,
        *,
        delegate: httpcore.AsyncNetworkBackend,
        resolver: ApprovedAddressResolver,
        limits: httpx.Limits | None = None,
        retries: int = 0,
    ) -> None:
        """Construct a direct connection pool with no proxy configuration."""
        super().__init__()
        actual_limits = limits or httpx.Limits()
        backend = BoundAsyncNetworkBackend(delegate=delegate, resolver=resolver)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
            max_connections=actual_limits.max_connections,
            max_keepalive_connections=actual_limits.max_keepalive_connections,
            keepalive_expiry=actual_limits.keepalive_expiry,
            retries=retries,
            network_backend=backend,
        )

    @override
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        extensions = cast("_RequestExtensions", request).extensions
        if (
            request.url.raw_scheme != b"https"
            or request.url.raw_host.lower() != NPLG_HOST.encode("ascii")
            or request.url.port not in {None, _HTTPS_PORT}
        ):
            raise httpx.LocalProtocolError(_ORIGIN_REJECTED)
        if "sni_hostname" in extensions:
            raise httpx.LocalProtocolError(_SNI_REJECTED)
        if request.headers.get_list("host") != [NPLG_HOST]:
            raise httpx.LocalProtocolError(_HOST_REJECTED)
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
        with _map_httpcore_exceptions():
            response = await self._pool.handle_async_request(core_request)
        response_extensions = cast("_RequestExtensions", response).extensions
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_AsyncResponseStream(cast("_CoreAsyncStream", response.stream)),
            extensions=response_extensions,
        )

    @override
    async def aclose(self) -> None:
        await self._pool.aclose()


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
