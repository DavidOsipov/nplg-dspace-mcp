# Copyright (c) 2026 David Osipov
"""Adversarial tests for DNS-to-socket binding."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

import httpcore
import httpx
import pytest

from nplg_mcp.app import create_app
from nplg_mcp.bounded_work import DNS_WORK
from nplg_mcp.config import load_config
from nplg_mcp.network import (
    BoundAsyncHTTPTransport,
    BoundAsyncNetworkBackend,
    SocketOption,
    resolve_approved_addresses_async,
)
from nplg_mcp.security import NPLG_HOST
from tests.helpers.app_factory import base_environment

if TYPE_CHECKING:
    import ssl
    from collections.abc import Iterable

    from nplg_mcp.repository import NplgRepository
    from nplg_mcp.tools import ToolService

_HTTPS_PORT = 443
_UNEXPECTED_PORT = "unexpected port"
_UNEXPECTED_UNIX = "Unix sockets are not expected"
_FIRST_CONNECT_FAILED = "first connection failed"


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

    def blocked_resolver(_host: str) -> tuple[str, ...]:
        started.set()
        try:
            assert release.wait(timeout=2.0)
            return ("93.184.216.34",)
        finally:
            finished.set()

    monkeypatch.setattr(
        "nplg_mcp.network.resolve_approved_addresses",
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

    assert await resolve_approved_addresses_async(NPLG_HOST) == ("93.184.216.34",)


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


async def _approved_cloudflare(_host: str) -> tuple[str, ...]:
    return ("1.1.1.1",)


async def _empty_approved_set(_host: str) -> tuple[str, ...]:
    return ()


async def _unexpected_resolver_failure(_host: str) -> tuple[str, ...]:
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

    stream = await backend.connect_tcp(NPLG_HOST, 443)

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
        _ = await backend.connect_tcp(NPLG_HOST, 443)

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
        _ = await backend.connect_tcp(host, port)

    assert delegate.connect_hosts == []


@pytest.mark.asyncio
async def test_backend_rejects_an_empty_fresh_dns_answer() -> None:
    delegate = _DriftingBackend(peer=("1.1.1.1", _HTTPS_PORT))
    backend = BoundAsyncNetworkBackend(
        delegate=delegate,
        resolver=_empty_approved_set,
    )

    with pytest.raises(httpcore.ConnectError, match="address set is empty"):
        _ = await backend.connect_tcp(NPLG_HOST, _HTTPS_PORT)

    assert delegate.connect_hosts == []


@pytest.mark.asyncio
async def test_backend_rejects_unix_socket_bypass(tmp_path: Path) -> None:
    delegate = _DriftingBackend(peer=("1.1.1.1", 443))
    backend = BoundAsyncNetworkBackend(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    with pytest.raises(httpcore.ConnectError, match="Unix sockets are not permitted"):
        _ = await backend.connect_unix_socket(str(tmp_path / "upstream.sock"))


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
async def test_transport_maps_peer_rejection_to_httpx_request_error() -> None:
    delegate = _DriftingBackend(peer=("8.8.8.8", 443))
    transport = BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=_approved_cloudflare,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        with pytest.raises(httpx.ConnectError):
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
    answers = iter((("1.1.1.1",), ("8.8.8.8",)))

    async def resolve(_host: str) -> tuple[str, ...]:
        return next(answers)

    delegate = _RetryBackend()
    transport = BoundAsyncHTTPTransport(
        delegate=delegate,
        resolver=resolve,
        retries=1,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.get(f"https://{NPLG_HOST}/simple-search")

    assert response.text == "OK"
    assert delegate.connect_hosts == ["1.1.1.1", "8.8.8.8"]
    assert delegate.http_stream.server_hostnames == [NPLG_HOST]


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
    body = (Path(__file__).parents[1] / "fixtures" / "search_results.html").read_bytes()
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    stream = _HttpStream(("1.1.1.1", 443), response)
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
        return stream

    def resolve(_host: str) -> tuple[str, ...]:
        return ("1.1.1.1",)

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect_tcp)
    monkeypatch.setattr("nplg_mcp.repository.resolve_approved_addresses", resolve)
    monkeypatch.setattr("nplg_mcp.network.resolve_approved_addresses", resolve)
    config = load_config(base_environment(CACHE_DIR=str(tmp_path)))
    application = create_app(config)
    services = application.services
    assert services is not None
    try:
        tools = cast("ToolService", services.tools)
        repository = cast("NplgRepository", tools.repository)
        _ = await repository.search("test", page_size=2)
    finally:
        if services.http_client is not None:
            await services.http_client.aclose()

    assert connected_hosts == ["1.1.1.1"]
