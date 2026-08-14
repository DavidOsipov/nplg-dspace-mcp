from pathlib import Path

import httpx
import pytest

from nplg_mcp.downloader import DocumentDownloader
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parsers import Bitstream
from nplg_mcp.storage import ContentAddressedStore


def bitstream(**overrides: object) -> Bitstream:
    values: dict[str, object] = {
        "bitstream_id": "bit_test",
        "handle": "1234/499564",
        "filename": "Iveria_1898_N161.pdf",
        "source_url": "https://dspace.nplg.gov.ge/bitstream/1234/499564/1/Iveria_1898_N161.pdf",
        "reported_size": None,
        "reported_format": "Adobe PDF",
        "description": None,
        "access_status": "public",
    }
    values.update(overrides)
    return Bitstream(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_valid_public_pdf_is_streamed_to_content_addressed_storage(tmp_path: Path) -> None:
    body = b"%PDF-1.7\nsynthetic"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept"].startswith("application/pdf")
        return httpx.Response(200, content=body, headers={"content-type": "application/pdf", "content-length": str(len(body))})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        ).download(bitstream())

    assert result.artifact.absolute_path.read_bytes() == body
    assert result.artifact.media_type == "application/pdf"
    assert result.source_bitstream_id == "bit_test"
    assert result.bytes_downloaded == len(body)


@pytest.mark.asyncio
async def test_declared_content_length_is_rejected_before_body_download(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"%PDF-1.7\nbody", headers={"content-type": "application/pdf", "content-length": "4096"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(client=client, store=ContentAddressedStore(tmp_path), max_bytes=128, validate_dns=False)
        with pytest.raises(AppError) as raised:
            await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.DOWNLOAD_TOO_LARGE
    assert list((tmp_path / "documents").glob("**/*")) == []


@pytest.mark.asyncio
async def test_streaming_limit_is_enforced_without_content_length(tmp_path: Path) -> None:
    class StreamingBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"%PDF-1.7\n"
            yield b"x" * 256

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=StreamingBody(), headers={"content-type": "application/pdf"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(client=client, store=ContentAddressedStore(tmp_path), max_bytes=64, validate_dns=False)
        with pytest.raises(AppError) as raised:
            await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.DOWNLOAD_TOO_LARGE
    assert list((tmp_path / ".staging").iterdir()) == []


@pytest.mark.asyncio
async def test_html_disguised_as_pdf_is_rejected_and_removed(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<!doctype html><title>login</title>", headers={"content-type": "application/pdf"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(client=client, store=ContentAddressedStore(tmp_path), max_bytes=1024, validate_dns=False)
        with pytest.raises(AppError) as raised:
            await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.INVALID_DOCUMENT
    assert list((tmp_path / ".staging").iterdir()) == []


@pytest.mark.asyncio
async def test_foreign_redirect_is_rejected(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/document.pdf"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(client=client, store=ContentAddressedStore(tmp_path), max_bytes=1024, validate_dns=False)
        with pytest.raises(AppError) as raised:
            await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_bitstream_must_be_public_and_bound_to_its_handle(tmp_path: Path) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(500))) as client:
        downloader = DocumentDownloader(client=client, store=ContentAddressedStore(tmp_path), max_bytes=1024, validate_dns=False)

        with pytest.raises(AppError) as restricted:
            await downloader.download(bitstream(access_status="restricted"))
        assert restricted.value.code is ErrorCode.RESTRICTED

        with pytest.raises(AppError) as mismatched:
            await downloader.download(bitstream(source_url="https://dspace.nplg.gov.ge/bitstream/1234/999/1/file.pdf"))
        assert mismatched.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_reported_size_above_limit_is_rejected_without_network_call(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"%PDF-1.7")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(client=client, store=ContentAddressedStore(tmp_path), max_bytes=1024, validate_dns=False)
        with pytest.raises(AppError) as raised:
            await downloader.download(bitstream(reported_size=1025))

    assert raised.value.code is ErrorCode.DOWNLOAD_TOO_LARGE
    assert calls == 0


@pytest.mark.asyncio
async def test_downloader_acquires_shared_rate_limiter_before_upstream_request(tmp_path: Path) -> None:
    class CountingLimiter:
        def __init__(self) -> None:
            self.calls = 0

        async def acquire(self) -> None:
            self.calls += 1

    limiter = CountingLimiter()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"%PDF-1.7\nbody", headers={"content-type": "application/pdf"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
            limiter=limiter,
        )
        await downloader.download(bitstream())

    assert limiter.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_downloader_maps_upstream_access_denial_to_restricted(tmp_path: Path, status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=b"restricted", headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as raised:
            await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.RESTRICTED
    assert raised.value.http_status == 403


@pytest.mark.asyncio
async def test_download_stops_before_exceeding_aggregate_cache_quota(tmp_path: Path) -> None:
    body = b"%PDF-1.7\nbody"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "application/pdf"})

    store = ContentAddressedStore(tmp_path, max_bytes=8)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(client=client, store=store, max_bytes=1024, validate_dns=False)
        with pytest.raises(AppError) as captured:
            await downloader.download(bitstream())

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0
    assert list((tmp_path / ".staging").iterdir()) == []
    assert list((tmp_path / "documents").iterdir()) == []


@pytest.mark.asyncio
async def test_downloader_revalidates_dns_for_each_redirect_hop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
            return httpx.Response(302, headers={"location": bitstream().source_url})
        return httpx.Response(200, content=b"%PDF-1.7\nbody", headers={"content-type": "application/pdf"})

    monkeypatch.setattr("nplg_mcp.downloader.resolve_approved_addresses", resolve)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(client=client, store=ContentAddressedStore(tmp_path), max_bytes=1024)
        await downloader.download(bitstream())

    assert requests == 2
    assert resolutions == 2


@pytest.mark.asyncio
async def test_downloader_enforces_total_response_deadline(tmp_path: Path) -> None:
    class NeverEndingBody(httpx.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[override]
            import asyncio

            yield b"%PDF-1.7\n"
            await asyncio.Event().wait()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=NeverEndingBody(), headers={"content-type": "application/pdf"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
            total_timeout_seconds=0.01,
        )
        with pytest.raises(AppError) as captured:
            await downloader.download(bitstream())

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert captured.value.http_status == 502
    assert list((tmp_path / ".staging").iterdir()) == []


@pytest.mark.asyncio
async def test_downloader_rejects_compressed_pdf_before_decoding(tmp_path: Path) -> None:
    class ForbiddenBody(httpx.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[override]
            raise AssertionError("compressed body must not be decoded")
            yield b""  # pragma: no cover

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=ForbiddenBody(),
            headers={"content-type": "application/pdf", "content-encoding": "gzip"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(client=client, store=ContentAddressedStore(tmp_path), max_bytes=1024, validate_dns=False)
        with pytest.raises(AppError) as captured:
            await downloader.download(bitstream())

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert list((tmp_path / ".staging").iterdir()) == []
