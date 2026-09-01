# Copyright (c) 2026 David Osipov
"""Integration tests for repository transport and parsing."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, get_type_hints, override
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

import nplg_mcp.network as network_module
from nplg_mcp import repository as repository_module
from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.http_types import HttpClientProtocol, HttpResponseProtocol
from nplg_mcp.network import create_bound_http_transport
from nplg_mcp.parser_executor import SubprocessParserExecutor
from nplg_mcp.repository import NplgRepository, decode_cursor, encode_cursor
from nplg_mcp.resilience import (
    AttemptPermit,
    Closed,
    Open,
    UpstreamGuard,
    UpstreamGuardPolicy,
)
from nplg_mcp.security import DnsTransientError
from nplg_mcp.tokens import derive_cursor_signing_key
from scripts.run_live_nplg_canary import execute_canary_probe

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

FIXTURES = Path(__file__).parents[1] / "fixtures"
_EXPECTED_PAGE_SIZE = 2
_METADATA_BYTE_LIMIT = 10
_HTTP_FORBIDDEN = 403
_HTTP_BAD_GATEWAY = 502
_SYNTHETIC_BODY_FAILURE = "synthetic body failure"
_CURSOR_SECRET = b"c" * 32
_CURSOR_NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
_EXPECTED_DISCOVERY_REQUESTS = 2


class _WriteCountingCache(dict[str, object]):
    writes: int = 0

    @override
    def __setitem__(self, key: str, value: object) -> None:
        self.writes += 1
        super().__setitem__(key, value)


class _ReadOnlyPropertyDescriptor(Protocol):
    @property
    def fget(self) -> Callable[[object], object] | None: ...

    @property
    def fset(self) -> None: ...


def _read_only_property_getter(member: object) -> Callable[[object], object]:
    assert type(member).__module__ == "builtins"
    assert type(member).__qualname__ == "property"
    descriptor = cast("_ReadOnlyPropertyDescriptor", member)
    assert descriptor.fset is None
    assert descriptor.fget is not None
    return descriptor.fget


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _resign_cursor_payload(token: str, updates: dict[str, object]) -> str:
    encoded_payload, _ = token.split(".", 1)
    padded = encoded_payload + "=" * (-len(encoded_payload) % 4)
    payload = cast(
        "dict[str, object]",
        json.loads(base64.urlsafe_b64decode(padded)),
    )
    assert isinstance(payload, dict)
    payload.update(updates)
    replaced = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=")
    signature = hmac.new(
        derive_cursor_signing_key(_CURSOR_SECRET),
        replaced,
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return f"{replaced.decode('ascii')}.{encoded_signature.decode('ascii')}"


def test_http_protocol_annotations_are_runtime_resolvable() -> None:
    response_hints: object = get_type_hints(HttpResponseProtocol.aiter_bytes)
    client_hints: object = get_type_hints(HttpClientProtocol.stream)
    repository_hints: object = get_type_hints(NplgRepository)
    assert isinstance(response_hints, dict)
    assert isinstance(client_hints, dict)
    assert isinstance(repository_hints, dict)
    assert repository_hints["client"] is HttpClientProtocol


def test_http_response_protocol_has_runtime_read_only_property_contract() -> None:
    class_hints: Mapping[str, object] = get_type_hints(HttpResponseProtocol)
    expected_returns: tuple[tuple[str, object], ...] = (
        ("status_code", int),
        ("headers", Mapping[str, str]),
        ("charset_encoding", str | None),
    )

    assert class_hints == {}
    members: Mapping[str, object] = HttpResponseProtocol.__dict__
    for name, expected_return in expected_returns:
        getter = _read_only_property_getter(members[name])
        getter_hints: Mapping[str, object] = get_type_hints(getter)
        assert getter_hints == {"return": expected_return}


@pytest.mark.asyncio
async def test_search_builds_bounded_dspace_request_and_opaque_cursor() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html; charset=utf-8"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            cursor_signing_secret=_CURSOR_SECRET,
            cursor_clock=lambda: _CURSOR_NOW,
        )
        page = await repository.search("ივერია", page_size=2)

    assert len(seen) == 1
    query = parse_qs(urlsplit(str(seen[0].url)).query)
    assert query["query"] == ["ივერია"]
    assert query["rpp"] == ["2"]
    assert query["start"] == ["0"]
    assert page.next_cursor is not None
    assert (
        decode_cursor(
            page.next_cursor,
            secret=_CURSOR_SECRET,
            normalized_query="ივერია",
            scope_handle=None,
            page_size=2,
            now=_CURSOR_NOW,
        )
        == _EXPECTED_PAGE_SIZE
    )


@pytest.mark.asyncio
async def test_search_endpoint_404_is_upstream_failure_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Treat a missing search route as an upstream failure, never a missing item."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            404,
            text="sensitive Apache route detail",
            headers={"content-type": "text/html; charset=iso-8859-1"},
        )

    async def forbidden_parser(*_args: object, **_kwargs: object) -> object:
        message = "search parser must not run after an upstream 404"
        raise AssertionError(message)

    monkeypatch.setattr(SubprocessParserExecutor, "parse_search", forbidden_parser)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as captured:
            _ = await repository.search("test", page_size=1)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert captured.value.http_status == _HTTP_BAD_GATEWAY
    assert captured.value.message == "The repository search service is unavailable."
    assert captured.value.internal_details is None
    assert len(seen) == 1
    assert seen[0].method == "GET"
    assert seen[0].url.host == "dspace.nplg.gov.ge"
    assert seen[0].url.path == "/simple-search"


@pytest.mark.asyncio
async def test_search_normalizes_once_and_reuses_the_exact_canonical_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_queries: list[str] = []
    upstream_queries: list[str] = []
    canonicalize = repository_module._canonical_search_query  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def observed_canonicalize(value: str) -> str:
        raw_queries.append(value)
        return canonicalize(value)

    def handler(request: httpx.Request) -> httpx.Response:
        request_query = parse_qs(urlsplit(str(request.url)).query)
        query = request_query["query"][0]
        upstream_queries.append(query)
        response_text = fixture("search_results.html")
        if request_query.get("start") == ["2"]:
            response_text = response_text.replace(
                "Results 1-2",
                "Results 3-4",
                1,
            ).replace("start=2", "start=4", 1)
        return httpx.Response(
            200,
            text=response_text,
            headers={"content-type": "text/html"},
        )

    monkeypatch.setattr(
        repository_module,
        "_canonical_search_query",
        observed_canonicalize,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            cursor_signing_secret=_CURSOR_SECRET,
            cursor_clock=lambda: _CURSOR_NOW,
        )
        first = await repository.search("ივერია  გაზეთი", page_size=2)
        assert first.next_cursor is not None
        _ = await repository.search(
            "ივერია გაზეთი",
            page_size=2,
            cursor=first.next_cursor,
        )

    assert raw_queries == ["ივერია  გაზეთი", "ივერია გაზეთი"]
    assert upstream_queries == ["ივერია გაზეთი", "ივერია გაზეთი"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("replayed_query", "replayed_scope", "replayed_page_size"),
    [
        pytest.param("another query", None, 2, id="query"),
        pytest.param("ივერიელი", "1234/2", 2, id="scope"),
        pytest.param("ივერიელი", None, 3, id="page-size"),
    ],
)
async def test_search_cursor_replay_is_bound_to_every_pagination_context(
    replayed_query: str,
    replayed_scope: str | None,
    replayed_page_size: int,
) -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html; charset=utf-8"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        first = await repository.search("ივერიელი", page_size=2)
        assert first.next_cursor is not None

        with pytest.raises(AppError) as captured:
            _ = await repository.search(
                replayed_query,
                scope_handle=replayed_scope,
                page_size=replayed_page_size,
                cursor=first.next_cursor,
            )

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert requests == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "updates",
    [
        pytest.param({"version": 2}, id="version"),
        pytest.param({"algorithm": "none"}, id="algorithm"),
    ],
)
async def test_search_rejects_validly_signed_cursor_confusion_before_network(
    updates: dict[str, object],
) -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            cursor_signing_secret=_CURSOR_SECRET,
            cursor_clock=lambda: _CURSOR_NOW,
        )
        first = await repository.search("ივერიელი", page_size=2)
        assert first.next_cursor is not None
        confused = _resign_cursor_payload(first.next_cursor, updates)

        with pytest.raises(AppError) as captured:
            _ = await repository.search("ივერიელი", page_size=2, cursor=confused)

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert requests == 1


@pytest.mark.asyncio
async def test_search_rejects_expired_cursor_before_network() -> None:
    requests = 0
    times = iter((_CURSOR_NOW, _CURSOR_NOW + timedelta(seconds=901)))

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            cursor_signing_secret=_CURSOR_SECRET,
            cursor_clock=lambda: next(times),
        )
        first = await repository.search("ივერიელი", page_size=2)
        assert first.next_cursor is not None

        with pytest.raises(AppError) as captured:
            _ = await repository.search(
                "ივერიელი", page_size=2, cursor=first.next_cursor
            )

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert requests == 1


@pytest.mark.asyncio
async def test_scoped_search_uses_only_a_canonical_collection_handle() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        _ = await repository.search("გაზეთი", scope_handle="1234/2", page_size=2)

    assert urlsplit(seen[0]).path == "/handle/1234/2/simple-search"


@pytest.mark.asyncio
async def test_repository_rejects_search_page_size_above_fifty_without_network() -> (
    None
):
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as raised:
            _ = await repository.search("ივერია", page_size=51)

    assert raised.value.code is ErrorCode.INVALID_INPUT
    assert calls == 0


@pytest.mark.asyncio
async def test_metadata_prefers_discovered_dim_and_falls_back_to_full_html() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        query = parse_qs(urlsplit(url).query)
        if query.get("verb") == ["ListMetadataFormats"]:
            return httpx.Response(
                200,
                text=fixture("oai_formats.xml"),
                headers={"content-type": "text/xml"},
            )
        if query.get("verb") == ["GetRecord"]:
            return httpx.Response(
                200, text=fixture("oai_error.xml"), headers={"content-type": "text/xml"}
            )
        if urlsplit(url).path == "/handle/1234/560449":
            return httpx.Response(
                200,
                text=fixture("item_full.html"),
                headers={"content-type": "text/html"},
            )
        raise AssertionError(url)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        record = await repository.get_metadata("1234/560449")

    assert record.title == "ბორჯომი N34"
    assert record.metadata_source == "jspui_full"
    assert any("metadataPrefix=dim" in url for url in calls)
    assert calls[-1].endswith("/handle/1234/560449?mode=full")


@pytest.mark.asyncio
async def test_file_inventory_is_bound_to_item_page() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=fixture("item_summary_public.html"),
            headers={"content-type": "text/html"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        files = await repository.list_files("1234/499564")

    assert len(files) == 1
    assert files[0].handle == "1234/499564"
    assert files[0].source_url.startswith("https://dspace.nplg.gov.ge/bitstream/")


@pytest.mark.asyncio
async def test_repository_acquires_shared_rate_limiter_before_upstream_request() -> (
    None
):
    class CountingLimiter:
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        async def acquire(self) -> None:
            self.calls += 1

    limiter = CountingLimiter()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False, limiter=limiter)
        _ = await repository.search("ივერია", page_size=2)

    assert limiter.calls == 1


@pytest.mark.asyncio
async def test_metadata_response_is_stream_bounded_before_full_body_is_buffered() -> (
    None
):
    class CountingStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            super().__init__()
            self.yielded = 0

        @override
        async def __aiter__(self) -> AsyncIterator[bytes]:
            for chunk in (b"a" * 8, b"b" * 8, b"c" * 8):
                self.yielded += 1
                yield chunk

    stream = CountingStream()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/html; charset=utf-8"}, stream=stream
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            max_metadata_bytes=_METADATA_BYTE_LIMIT,
        )
        with pytest.raises(AppError) as raised:
            _ = await repository.search("ივერია", page_size=2)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE
    assert stream.yielded == _EXPECTED_PAGE_SIZE


@pytest.mark.asyncio
async def test_post_header_body_transport_failure_counts_as_transient() -> None:
    """Mutation caught: recording success before a 200 response body completes."""

    class BrokenStream(httpx.AsyncByteStream):
        @override
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"<html>"
            raise httpx.ReadError(_SYNTHETIC_BODY_FAILURE)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            stream=BrokenStream(),
        )

    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        random=lambda: 0.5,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            guard=guard,
        )
        with pytest.raises(AppError):
            _ = await repository.search("test")

    assert isinstance(guard.state, Open)


@pytest.mark.asyncio
async def test_repository_excludes_transport_policy_rejection_but_counts_timeout() -> (
    None
):
    """Mutation caught: poisoning the circuit with a bound-transport rejection."""
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise network_module.TransportPolicyError
        message = "synthetic connection timeout"
        raise httpx.ConnectTimeout(message, request=request)

    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        random=lambda: 0.5,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            guard=guard,
        )
        with pytest.raises(AppError) as rejected:
            _ = await repository.search("test")
        assert rejected.value.code is ErrorCode.UPSTREAM_FAILURE
        closed: object = guard.state
        assert isinstance(closed, Closed)

        with pytest.raises(AppError) as timed_out:
            _ = await repository.search("test")
        assert timed_out.value.code is ErrorCode.UPSTREAM_FAILURE
        opened: object = guard.state
        assert isinstance(opened, Open)


@pytest.mark.asyncio
async def test_open_circuit_fails_before_dns_or_rate_limiter_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: DNS/global work consumed before circuit admission."""
    calls = 0

    def resolve(_host: str) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        return ("1.1.1.1",)

    monkeypatch.setattr("nplg_mcp.repository.resolve_approved_addresses", resolve)
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        random=lambda: 0.5,
    )
    async with guard.acquire(
        MonotonicDeadline.after(30.0, clock=time.monotonic)
    ) as failed:
        await failed.record_transient_failure()

    def unexpected_request(_request: httpx.Request) -> httpx.Response:
        message = "open circuit reached HTTP transport"
        raise AssertionError(message)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(unexpected_request)
    ) as client:
        repository = NplgRepository(client=client, guard=guard)
        with pytest.raises(AppError) as captured:
            _ = await repository.search("test")

    assert captured.value.code is ErrorCode.RATE_LIMITED
    assert calls == 0


@pytest.mark.asyncio
async def test_metadata_limit_is_checked_before_overflow_chunk_is_appended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class GuardedBuffer:
        def __init__(self) -> None:
            super().__init__()
            self.value = bytearray()

        def __len__(self) -> int:
            return len(self.value)

        def extend(self, chunk: bytes) -> None:
            if len(self.value) + len(chunk) > _METADATA_BYTE_LIMIT:
                msg = "overflow chunk was appended before the limit check"
                raise AssertionError(msg)
            self.value.extend(chunk)

        def __bytes__(self) -> bytes:
            return bytes(self.value)

    class StreamingBody(httpx.AsyncByteStream):
        @override
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"a" * 8
            yield b"b" * 8

    monkeypatch.setattr("nplg_mcp.repository.bytearray", GuardedBuffer, raising=False)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            stream=StreamingBody(),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            max_metadata_bytes=_METADATA_BYTE_LIMIT,
        )
        with pytest.raises(AppError) as raised:
            _ = await repository.search("ივერია", page_size=2)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_repository_maps_upstream_access_denial_to_restricted(
    status: int,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, text="restricted", headers={"content-type": "text/html"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as raised:
            _ = await repository.get_item("1234/499564")

    assert raised.value.code is ErrorCode.RESTRICTED
    assert raised.value.http_status == _HTTP_FORBIDDEN


@pytest.mark.asyncio
async def test_repository_revalidates_dns_for_each_redirect_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolutions = 0
    requests = 0

    def resolve(_host: str) -> tuple[str, ...]:
        nonlocal resolutions
        resolutions += 1
        return ("1.1.1.1",)

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return httpx.Response(
                302, headers={"location": "/simple-search?query=test&rpp=2&start=0"}
            )
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html"},
        )

    monkeypatch.setattr("nplg_mcp.repository.resolve_approved_addresses", resolve)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client)
        _ = await repository.search("test", page_size=2)

    assert requests == _EXPECTED_PAGE_SIZE
    assert resolutions == _EXPECTED_PAGE_SIZE


@pytest.mark.asyncio
async def test_repository_enforces_total_response_deadline() -> None:
    class NeverEndingBody(httpx.AsyncByteStream):
        @override
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"<html>"
            _ = await asyncio.Event().wait()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, stream=NeverEndingBody(), headers={"content-type": "text/html"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client, validate_dns=False, total_timeout_seconds=0.01
        )
        with pytest.raises(AppError) as captured:
            _ = await repository.search("test", page_size=2)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert captured.value.http_status == _HTTP_BAD_GATEWAY


@pytest.mark.asyncio
async def test_repository_rejects_compressed_metadata_before_decoding() -> None:
    class ForbiddenIterator:
        def __aiter__(self) -> AsyncIterator[bytes]:
            return self

        async def __anext__(self) -> bytes:
            msg = "compressed body must not be decoded"
            raise AssertionError(msg)

    class ForbiddenBody(httpx.AsyncByteStream):
        @override
        def __aiter__(self) -> AsyncIterator[bytes]:
            return ForbiddenIterator()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=ForbiddenBody(),
            headers={"content-type": "text/html", "content-encoding": "gzip"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as captured:
            _ = await repository.search("test", page_size=2)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE


def test_repository_rejects_a_nonpositive_request_deadline() -> None:
    with pytest.raises(ValueError, match="total_timeout_seconds"):
        _ = NplgRepository(
            client=cast("HttpClientProtocol", object()),
            total_timeout_seconds=0,
        )


@pytest.mark.parametrize("offset", [-1, 10_000_001, True])
def test_cursor_encoder_rejects_non_integer_and_out_of_range_offsets(
    offset: int,
) -> None:
    with pytest.raises(AppError) as captured:
        _ = encode_cursor(
            offset,
            secret=_CURSOR_SECRET,
            normalized_query="query",
            scope_handle=None,
            page_size=2,
            now=_CURSOR_NOW,
        )

    assert captured.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "cursor",
    [
        "",
        "x" * 129,
        "not-json",
        "eyJ2IjoyLCJvZmZzZXQiOjB9",
        "eyJ2IjoxLCJvZmZzZXQiOi0xfQ",
        "eyJ2IjoxLCJvZmZzZXQiOiIwIn0",
    ],
)
def test_cursor_decoder_rejects_malformed_versioned_or_unbounded_payloads(
    cursor: str,
) -> None:
    with pytest.raises(AppError) as captured:
        _ = decode_cursor(
            cursor,
            secret=_CURSOR_SECRET,
            normalized_query="query",
            scope_handle=None,
            page_size=2,
            now=_CURSOR_NOW,
        )

    assert captured.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["", " \t\n ", "x" * 501])
async def test_search_rejects_empty_or_overlong_queries_without_network(
    query: str,
) -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as captured:
            _ = await repository.search(query)

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert requests == 0


@pytest.mark.asyncio
async def test_repository_rejects_an_upstream_page_larger_than_requested() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError, match="search item limit") as captured:
            _ = await repository.search("ივერია", page_size=1)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.asyncio
async def test_repository_total_deadline_includes_response_parsing(
    tmp_path: Path,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=fixture("search_results.html"),
            headers={"content-type": "text/html"},
        )

    parser_executor = SubprocessParserExecutor(
        worker_argv=(
            sys.executable,
            str(FIXTURES / "parser_worker_hang.py"),
            str(tmp_path / "deadline-parser.txt"),
        )
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            total_timeout_seconds=0.25,
            parser_executor=parser_executor,
        )
        with pytest.raises(AppError, match="deadline") as captured:
            _ = await repository.search("ივერია", page_size=2)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert parser_executor.active == 0


@pytest.mark.asyncio
async def test_timed_out_parser_releases_capacity_after_process_cleanup(
    tmp_path: Path,
) -> None:
    executor = SubprocessParserExecutor(
        worker_argv=(
            sys.executable,
            str(FIXTURES / "parser_worker_hang.py"),
            str(tmp_path / "capacity-parser.txt"),
        )
    )

    for _ in range(2):
        with pytest.raises(TimeoutError):
            _ = await executor.parse_metadata_formats(
                "<OAI-PMH/>",
                deadline=asyncio.get_running_loop().time() + 0.2,
            )
        assert executor.active == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("location", "max_redirects", "expected_code"),
    [
        ("/simple-search?query=test", 0, ErrorCode.UPSTREAM_FAILURE),
        (None, 3, ErrorCode.UPSTREAM_FAILURE),
    ],
)
async def test_repository_redirect_faults_fail_before_body_parsing(
    location: str | None,
    max_redirects: int,
    expected_code: ErrorCode,
) -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        headers = {} if location is None else {"location": location}
        return httpx.Response(302, headers=headers)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            max_redirects=max_redirects,
        )
        with pytest.raises(AppError) as captured:
            _ = await repository.search("test")

    assert captured.value.code is expected_code
    assert requests == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected_code"),
    [
        (404, ErrorCode.NOT_FOUND),
        (429, ErrorCode.RATE_LIMITED),
        (500, ErrorCode.UPSTREAM_FAILURE),
    ],
)
async def test_repository_maps_unsuccessful_status_before_metadata_parsing(
    status: int,
    expected_code: ErrorCode,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            text="not metadata",
            headers={"content-type": "application/json"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as captured:
            _ = await repository.get_item("1234/499564")

    assert captured.value.code is expected_code


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "body", "max_metadata_bytes"),
    [
        (
            {"content-type": "text/html", "content-length": "invalid"},
            b"body",
            10,
        ),
        ({"content-type": "text/html", "content-length": "-1"}, b"body", 10),
        ({"content-type": "text/html", "content-length": "11"}, b"body", 10),
        ({"content-type": "application/json"}, b"body", 10),
        ({"content-type": "text/html; charset=no-such-codec"}, b"body", 10),
    ],
)
async def test_repository_rejects_invalid_headers_sizes_and_text_encoding(
    headers: dict[str, str],
    body: bytes,
    max_metadata_bytes: int,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers=headers)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            max_metadata_bytes=max_metadata_bytes,
        )
        with pytest.raises(AppError) as captured:
            _ = await repository.search("test")

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE


def _metadata_formats_document(prefix: str) -> str:
    return (
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
        "<ListMetadataFormats><metadataFormat>"
        f"<metadataPrefix>{prefix}</metadataPrefix>"
        "</metadataFormat></ListMetadataFormats></OAI-PMH>"
    )


def _xml_document(*parts: str) -> str:
    return "".join(parts)


_OAI_DC_RECORD = (
    '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" '
    'xmlns:oai_dc="http://www.openarchives.org/OAI/2.0/oai_dc/" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/">'
    "<GetRecord><record><header>"
    "<identifier>oai:dspace.nplg.gov.ge:1234/560975</identifier>"
    "</header><metadata><oai_dc:dc>"
    "<dc:title>OAI DC title</dc:title>"
    "</oai_dc:dc></metadata></record></GetRecord></OAI-PMH>"
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("prefix", "record_body", "content_type", "expected_title", "expected_source"),
    [
        (
            "dim",
            fixture("oai_dim_record.xml"),
            "text/xml",
            "რეზონანსი N164",
            "oai_dim",
        ),
        (
            "oai_dc",
            _OAI_DC_RECORD,
            "application/oai+xml",
            "OAI DC title",
            "oai_dc",
        ),
    ],
)
async def test_metadata_uses_the_discovered_supported_oai_parser(
    prefix: str,
    record_body: str,
    content_type: str,
    expected_title: str,
    expected_source: str,
) -> None:
    verbs: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        query = parse_qs(urlsplit(str(request.url)).query)
        verb = query["verb"][0]
        verbs.append(verb)
        if verb == "ListMetadataFormats":
            return httpx.Response(
                200,
                text=_metadata_formats_document(prefix),
                headers={"content-type": content_type},
            )
        assert verb == "GetRecord"
        assert query["metadataPrefix"] == [prefix]
        return httpx.Response(
            200,
            text=record_body,
            headers={"content-type": content_type},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        record = await NplgRepository(client=client, validate_dns=False).get_metadata(
            "1234/560975"
        )

    assert verbs == ["ListMetadataFormats", "GetRecord"]
    assert record.title == expected_title
    assert record.metadata_source == expected_source


@pytest.mark.asyncio
async def test_successful_oai_format_discovery_is_cached_by_upstream_origin() -> None:
    verbs: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        query = parse_qs(urlsplit(str(request.url)).query)
        verb = query["verb"][0]
        verbs.append(verb)
        if verb == "ListMetadataFormats":
            return httpx.Response(
                200,
                text=_metadata_formats_document("oai_dc"),
                headers={"content-type": "text/xml"},
            )
        identifier = query["identifier"][0]
        handle = identifier.rsplit(":", 1)[-1]
        record = _OAI_DC_RECORD.replace("1234/560975", handle)
        return httpx.Response(
            200,
            text=record,
            headers={"content-type": "text/xml"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        first = await repository.get_metadata("1234/560975")
        second = await repository.get_metadata("1234/560976")

    assert first.handle == "1234/560975"
    assert second.handle == "1234/560976"
    assert verbs == ["ListMetadataFormats", "GetRecord", "GetRecord"]


@pytest.mark.asyncio
async def test_oai_discovery_cache_expires_at_the_exact_monotonic_boundary() -> None:
    requests = 0
    samples = iter((0.0, 0.0, 299.0, 300.0, 300.0))

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            text=_metadata_formats_document("dim"),
            headers={"content-type": "text/xml"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            cache_clock=lambda: next(samples),
        )
        deadline = asyncio.get_running_loop().time() + 5.0
        assert await repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            deadline=deadline
        ) == ("dim",)
        assert await repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            deadline=deadline
        ) == ("dim",)
        assert await repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            deadline=deadline
        ) == ("dim",)

    assert requests == _EXPECTED_DISCOVERY_REQUESTS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body"),
    [
        pytest.param(200, "<not-closed>", id="malformed"),
        pytest.param(403, "denied", id="access-denial"),
        pytest.param(200, "x" * 2_097_153, id="over-markup-budget"),
        pytest.param(
            200,
            _xml_document(
                "<Envelope><ListMetadataFormats><metadataFormat>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></Envelope>",
            ),
            id="wrong-root",
        ),
        pytest.param(
            200,
            _xml_document(
                "<OAI-PMH><wrapper><ListMetadataFormats><metadataFormat>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></wrapper></OAI-PMH>",
            ),
            id="wrapped-list",
        ),
        pytest.param(
            200,
            _xml_document(
                "<OAI-PMH><ListMetadataFormats><wrapper><metadataFormat>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></wrapper></ListMetadataFormats></OAI-PMH>",
            ),
            id="wrapped-format",
        ),
        pytest.param(
            200,
            _xml_document(
                "<OAI-PMH><ListMetadataFormats><metadataFormat><wrapper>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</wrapper></metadataFormat></ListMetadataFormats></OAI-PMH>",
            ),
            id="nested-prefix",
        ),
        pytest.param(
            200,
            _xml_document(
                "<OAI-PMH><ListMetadataFormats>",
                "<metadataPrefix>misowned</metadataPrefix>",
                "<metadataFormat><metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></OAI-PMH>",
            ),
            id="misowned-prefix",
        ),
        pytest.param(
            200,
            _xml_document(
                '<evil:OAI-PMH xmlns:evil="urn:evil">',
                "<evil:ListMetadataFormats><evil:metadataFormat>",
                "<evil:metadataPrefix>dim</evil:metadataPrefix>",
                "</evil:metadataFormat></evil:ListMetadataFormats>",
                "</evil:OAI-PMH>",
            ),
            id="wrong-root-namespace",
        ),
        pytest.param(
            200,
            _xml_document(
                '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" ',
                'xmlns:evil="urn:evil"><evil:ListMetadataFormats>',
                "<evil:metadataFormat><evil:metadataPrefix>dim</evil:metadataPrefix>",
                "</evil:metadataFormat></evil:ListMetadataFormats></OAI-PMH>",
            ),
            id="wrong-list-namespace",
        ),
        pytest.param(
            200,
            _xml_document(
                '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" ',
                'xmlns:evil="urn:evil"><ListMetadataFormats>',
                "<evil:metadataFormat><evil:metadataPrefix>dim</evil:metadataPrefix>",
                "</evil:metadataFormat></ListMetadataFormats></OAI-PMH>",
            ),
            id="wrong-format-namespace",
        ),
        pytest.param(
            200,
            _xml_document(
                '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" ',
                'xmlns:evil="urn:evil"><ListMetadataFormats><metadataFormat>',
                "<evil:metadataPrefix>dim</evil:metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></OAI-PMH>",
            ),
            id="wrong-prefix-namespace",
        ),
    ],
)
async def test_oai_discovery_failure_is_never_cached_before_validation(
    status: int,
    body: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            status,
            text=body,
            headers={"content-type": "text/xml"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        writes = _WriteCountingCache()
        monkeypatch.setattr(repository, "_metadata_format_cache", writes)
        deadline = asyncio.get_running_loop().time() + 5.0
        for _ in range(2):
            with pytest.raises(AppError):
                _ = await repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                    deadline=deadline
                )
            assert repository._metadata_format_cache == {}  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    assert requests == _EXPECTED_DISCOVERY_REQUESTS
    assert writes.writes == 0


@pytest.mark.asyncio
async def test_concurrent_cold_oai_discovery_uses_exactly_one_upstream_request() -> (
    None
):
    requests = 0
    request_started = asyncio.Event()
    release_response = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        request_started.set()
        _ = await release_response.wait()
        return httpx.Response(
            200,
            text=_metadata_formats_document("dim"),
            headers={"content-type": "text/xml"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        deadline = asyncio.get_running_loop().time() + 5.0
        first = asyncio.create_task(
            repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                deadline=deadline
            )
        )
        second = asyncio.create_task(
            repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                deadline=deadline
            )
        )
        _ = await request_started.wait()
        await asyncio.sleep(0)
        release_response.set()
        results = await asyncio.gather(first, second)
        assert results[0] == ("dim",)
        assert results[1] == ("dim",)

    assert requests == 1


@pytest.mark.asyncio
async def test_backward_cache_clock_invalidates_then_recovery_refetches() -> None:
    requests = 0
    samples = iter((10.0, 10.0, 5.0, 20.0, 20.0))

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            text=_metadata_formats_document("dim"),
            headers={"content-type": "text/xml"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            cache_clock=lambda: next(samples),
        )
        deadline = asyncio.get_running_loop().time() + 5.0
        assert await repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            deadline=deadline
        ) == ("dim",)
        with pytest.raises(RuntimeError, match="moved backwards"):
            _ = await repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                deadline=deadline
            )
        assert repository._metadata_format_cache == {}  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert await repository._metadata_formats(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            deadline=deadline
        ) == ("dim",)

    assert requests == _EXPECTED_DISCOVERY_REQUESTS


def test_malformed_cursor_signature_is_invalid_input() -> None:
    with pytest.raises(AppError) as raised:
        _ = decode_cursor(
            "payload.%%%",
            secret=_CURSOR_SECRET,
            normalized_query="query",
            scope_handle=None,
            page_size=2,
            now=_CURSOR_NOW,
        )

    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_unsupported_oai_formats_fall_back_to_bound_full_item_html() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(urlsplit(str(request.url)).path)
        if paths[-1] == "/oai/request":
            return httpx.Response(
                200,
                text=_metadata_formats_document("mods"),
                headers={"content-type": "text/xml"},
            )
        return httpx.Response(
            200,
            text=fixture("item_full.html"),
            headers={"content-type": "text/html"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        record = await NplgRepository(client=client, validate_dns=False).get_metadata(
            "1234/560449"
        )

    assert paths == ["/oai/request", "/handle/1234/560449"]
    assert record.metadata_source == "jspui_full"


@pytest.mark.asyncio
async def test_oai_security_rejection_is_not_downgraded_to_html_fallback() -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            302,
            headers={"location": "https://example.com/oai/request"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as captured:
            _ = await repository.get_metadata("1234/560449")

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert requests == 1


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_nplg_canary_uses_bound_public_endpoint() -> None:
    """Classify the single protected Task 17 live-oracle node."""
    if os.environ.get("NPLG_ALLOW_LIVE_TESTS") != "1":
        pytest.skip("NPLG live-test authority is absent")
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)
    async with httpx.AsyncClient(
        transport=create_bound_http_transport(limits=limits),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        await execute_canary_probe(client, timeout_seconds=15.0)


class _RecordingDnsPermit:
    def __init__(self) -> None:
        super().__init__()
        self.outcomes: list[str] = []

    async def record_transient_failure(self) -> None:
        self.outcomes.append("transient")

    async def record_excluded_failure(self) -> None:
        self.outcomes.append("excluded")


@pytest.mark.asyncio
async def test_repository_dns_errors_have_exact_circuit_classification() -> None:
    """Mutation caught: security/local DNS rejection poisoning availability state."""
    transient = _RecordingDnsPermit()
    excluded = _RecordingDnsPermit()
    await repository_module._record_dns_app_error(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast("AttemptPermit", transient),
        DnsTransientError(
            ErrorCode.UPSTREAM_FAILURE,
            "The DNS lookup failed.",
            http_status=502,
        ),
    )
    await repository_module._record_dns_app_error(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast("AttemptPermit", excluded),
        AppError(ErrorCode.INVALID_INPUT, "The DNS answer was rejected."),
    )
    assert transient.outcomes == ["transient"]
    assert excluded.outcomes == ["excluded"]


def test_repository_rejects_a_forged_guard() -> None:
    """Mutation caught: accepting a caller-controlled circuit implementation."""
    with pytest.raises(TypeError, match="UpstreamGuard"):
        _ = NplgRepository(
            client=cast("HttpClientProtocol", object()),
            guard=cast("UpstreamGuard", object()),
        )


@pytest.mark.asyncio
async def test_repository_dependency_error_is_classified_before_reraise() -> None:
    """Mutation caught: DNS AppError escaping without finalizing its permit."""

    class _FailingDnsRepository(NplgRepository):
        @override
        async def _ensure_dns(self) -> None:
            raise AppError(ErrorCode.INVALID_INPUT, "DNS security rejection")

    permit = _RecordingDnsPermit()
    repository = _FailingDnsRepository(
        client=cast("HttpClientProtocol", object()),
    )
    with pytest.raises(AppError, match="DNS security rejection"):
        await repository._admit_dependencies(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            cast("AttemptPermit", permit)
        )
    assert permit.outcomes == ["excluded"]


@pytest.mark.asyncio
async def test_repository_rejects_deadline_before_and_after_guard_admission() -> None:
    """Mutation caught: starting network work outside either deadline boundary."""
    before = NplgRepository(
        client=cast("HttpClientProtocol", object()),
        validate_dns=False,
        guard=UpstreamGuard(clock=lambda: 0.0),
        clock=lambda: 1.0,
    )
    with pytest.raises(TimeoutError):
        _ = await before._get_text_within_deadline(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            "https://dspace.nplg.gov.ge/simple-search",
            accepted_types=("text/html",),
            deadline=0.0,
        )

    after_times = iter((0.0, 2.0))
    after = NplgRepository(
        client=cast("HttpClientProtocol", object()),
        validate_dns=False,
        guard=UpstreamGuard(clock=lambda: 0.0),
        clock=lambda: next(after_times),
    )
    with pytest.raises(TimeoutError):
        _ = await after._get_text_within_deadline(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            "https://dspace.nplg.gov.ge/simple-search",
            accepted_types=("text/html",),
            deadline=1.0,
        )
