from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.repository import NplgRepository, decode_cursor

FIXTURES = Path(__file__).parents[1] / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_search_builds_bounded_dspace_request_and_opaque_cursor() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text=fixture("search_results.html"), headers={"content-type": "text/html; charset=utf-8"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        page = await repository.search("ივერია", page_size=2)

    assert len(seen) == 1
    query = parse_qs(urlsplit(str(seen[0].url)).query)
    assert query["query"] == ["ივერია"]
    assert query["rpp"] == ["2"]
    assert query["start"] == ["0"]
    assert page.next_cursor is not None
    assert decode_cursor(page.next_cursor) == 2


@pytest.mark.asyncio
async def test_scoped_search_uses_only_a_canonical_collection_handle() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text=fixture("search_results.html"), headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        await repository.search("გაზეთი", scope_handle="1234/2", page_size=2)

    assert urlsplit(seen[0]).path == "/handle/1234/2/simple-search"


@pytest.mark.asyncio
async def test_repository_rejects_search_page_size_above_fifty_without_network() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as raised:
            await repository.search("ივერია", page_size=51)

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
            return httpx.Response(200, text=fixture("oai_formats.xml"), headers={"content-type": "text/xml"})
        if query.get("verb") == ["GetRecord"]:
            return httpx.Response(200, text=fixture("oai_error.xml"), headers={"content-type": "text/xml"})
        if urlsplit(url).path == "/handle/1234/560449":
            return httpx.Response(200, text=fixture("item_full.html"), headers={"content-type": "text/html"})
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
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=fixture("item_summary_public.html"), headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        files = await repository.list_files("1234/499564")

    assert len(files) == 1
    assert files[0].handle == "1234/499564"
    assert files[0].source_url.startswith("https://dspace.nplg.gov.ge/bitstream/")


@pytest.mark.asyncio
async def test_repository_acquires_shared_rate_limiter_before_upstream_request() -> None:
    class CountingLimiter:
        def __init__(self) -> None:
            self.calls = 0

        async def acquire(self) -> None:
            self.calls += 1

    limiter = CountingLimiter()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=fixture("search_results.html"), headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False, limiter=limiter)
        await repository.search("ივერია", page_size=2)

    assert limiter.calls == 1

@pytest.mark.asyncio
async def test_metadata_response_is_stream_bounded_before_full_body_is_buffered() -> None:
    class CountingStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.yielded = 0

        async def __aiter__(self):  # type: ignore[override]
            for chunk in (b"a" * 8, b"b" * 8, b"c" * 8):
                self.yielded += 1
                yield chunk

    stream = CountingStream()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, stream=stream)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False, max_metadata_bytes=10)
        with pytest.raises(AppError) as raised:
            await repository.search("ივერია", page_size=2)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE
    assert stream.yielded == 2


@pytest.mark.asyncio
async def test_metadata_limit_is_checked_before_overflow_chunk_is_appended(monkeypatch) -> None:
    class GuardedBuffer:
        def __init__(self) -> None:
            self.value = bytearray()

        def __len__(self) -> int:
            return len(self.value)

        def extend(self, chunk: bytes) -> None:
            if len(self.value) + len(chunk) > 10:
                raise AssertionError("overflow chunk was appended before the limit check")
            self.value.extend(chunk)

        def __bytes__(self) -> bytes:
            return bytes(self.value)

    class StreamingBody(httpx.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[override]
            yield b"a" * 8
            yield b"b" * 8

    monkeypatch.setattr("nplg_mcp.repository.bytearray", GuardedBuffer, raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            stream=StreamingBody(),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False, max_metadata_bytes=10)
        with pytest.raises(AppError) as raised:
            await repository.search("ივერია", page_size=2)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_repository_maps_upstream_access_denial_to_restricted(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text="restricted", headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as raised:
            await repository.get_item("1234/499564")

    assert raised.value.code is ErrorCode.RESTRICTED
    assert raised.value.http_status == 403


@pytest.mark.asyncio
async def test_repository_revalidates_dns_for_each_redirect_hop(monkeypatch: pytest.MonkeyPatch) -> None:
    resolutions = 0
    requests = 0

    def resolve(host: str) -> tuple[str, ...]:
        nonlocal resolutions
        resolutions += 1
        return ("1.1.1.1",)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return httpx.Response(302, headers={"location": "/simple-search?query=test&rpp=2&start=0"})
        return httpx.Response(200, text=fixture("search_results.html"), headers={"content-type": "text/html"})

    monkeypatch.setattr("nplg_mcp.repository.resolve_approved_addresses", resolve)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client)
        await repository.search("test", page_size=2)

    assert requests == 2
    assert resolutions == 2


@pytest.mark.asyncio
async def test_repository_enforces_total_response_deadline() -> None:
    class NeverEndingBody(httpx.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[override]
            import asyncio

            yield b"<html>"
            await asyncio.Event().wait()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=NeverEndingBody(), headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False, total_timeout_seconds=0.01)
        with pytest.raises(AppError) as captured:
            await repository.search("test", page_size=2)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert captured.value.http_status == 502


@pytest.mark.asyncio
async def test_repository_rejects_compressed_metadata_before_decoding() -> None:
    class ForbiddenBody(httpx.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[override]
            raise AssertionError("compressed body must not be decoded")
            yield b""  # pragma: no cover

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=ForbiddenBody(),
            headers={"content-type": "text/html", "content-encoding": "gzip"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(client=client, validate_dns=False)
        with pytest.raises(AppError) as captured:
            await repository.search("test", page_size=2)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
