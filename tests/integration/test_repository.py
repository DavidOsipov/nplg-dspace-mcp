# Copyright (c) 2026 David Osipov
"""Integration tests for repository transport and parsing."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, get_type_hints, override
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.http_types import HttpClientProtocol, HttpResponseProtocol
from nplg_mcp.repository import NplgRepository, decode_cursor, encode_cursor

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

FIXTURES = Path(__file__).parents[1] / "fixtures"
_EXPECTED_PAGE_SIZE = 2
_METADATA_BYTE_LIMIT = 10
_HTTP_FORBIDDEN = 403
_HTTP_BAD_GATEWAY = 502


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
        repository = NplgRepository(client=client, validate_dns=False)
        page = await repository.search("ივერია", page_size=2)

    assert len(seen) == 1
    query = parse_qs(urlsplit(str(seen[0].url)).query)
    assert query["query"] == ["ივერია"]
    assert query["rpp"] == ["2"]
    assert query["start"] == ["0"]
    assert page.next_cursor is not None
    assert decode_cursor(page.next_cursor) == _EXPECTED_PAGE_SIZE


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
    assert record.metadata_source == "xmlui_full"
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
        _ = encode_cursor(offset)

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
        _ = decode_cursor(cursor)

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
        "<OAI-PMH><ListMetadataFormats><metadataFormat>"
        f"<metadataPrefix>{prefix}</metadataPrefix>"
        "</metadataFormat></ListMetadataFormats></OAI-PMH>"
    )


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
    assert record.metadata_source == "xmlui_full"


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
