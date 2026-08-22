# Copyright (c) 2026 David Osipov
"""Adversarial tests for bounded downloader behavior."""

from __future__ import annotations

import asyncio
import hashlib
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast, get_type_hints, override

import httpx
import pytest

from nplg_mcp.downloader import DocumentDownloader
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.http_types import HttpClientProtocol
from nplg_mcp.malware import ScanResult, ScanVerdict
from nplg_mcp.parsers import Bitstream
from nplg_mcp.storage import ContentAddressedStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Generator
    from pathlib import Path

_DEFAULT_SOURCE_URL = (
    "https://dspace.nplg.gov.ge/bitstream/1234/499564/1/Iveria_1898_N161.pdf"
)
_EXPECTED_REDIRECT_HOPS = 2
_HTTP_FORBIDDEN = 403
_HTTP_BAD_GATEWAY = 502


def bitstream(
    *,
    source_url: str = _DEFAULT_SOURCE_URL,
    reported_size: int | None = None,
    access_status: str = "public",
) -> Bitstream:
    return Bitstream(
        bitstream_id="bit_test",
        handle="1234/499564",
        filename="Iveria_1898_N161.pdf",
        source_url=source_url,
        reported_size=reported_size,
        reported_format="Adobe PDF",
        description=None,
        access_status=access_status,
    )


def test_downloader_protocol_annotation_is_runtime_resolvable() -> None:
    hints: object = get_type_hints(DocumentDownloader)

    assert isinstance(hints, dict)
    assert hints["client"] is HttpClientProtocol


@pytest.mark.asyncio
async def test_scanner_verdict_is_required_before_a_download_is_published(
    tmp_path: Path,
) -> None:
    """A scanner failure must not leave an unscanned document in the cache."""

    class InfectedScanner:
        async def scan(
            self,
            path: Path,
            *,
            expected_sha256: str,
            deadline: object,
        ) -> ScanResult:
            del deadline
            assert await asyncio.to_thread(path.is_file)
            scanned_bytes = await asyncio.to_thread(path.read_bytes)
            assert hashlib.sha256(scanned_bytes).hexdigest() == expected_sha256
            return ScanResult(
                verdict=ScanVerdict.INFECTED,
                scanned_sha256=expected_sha256,
                engine_version="clamav-1.4.3",
                signature_version="daily-28123",
                signatures_updated_at=datetime(2026, 8, 22, tzinfo=UTC),
            )

    body = b"%PDF-1.7\nmalware-fixture"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=body, headers={"content-type": "application/pdf"}
        )

    store = ContentAddressedStore(tmp_path)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=store,
            max_bytes=1024,
            validate_dns=False,
            scanner=InfectedScanner(),
            scan_now=lambda: datetime(2026, 8, 22, 1, tzinfo=UTC),
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream())

    assert captured.value.code is ErrorCode.INVALID_DOCUMENT
    assert list((tmp_path / "documents").rglob("*")) == []
    assert list((tmp_path / ".staging").iterdir()) == []


@pytest.mark.asyncio
async def test_valid_public_pdf_is_streamed_to_content_addressed_storage(
    tmp_path: Path,
) -> None:
    body = b"%PDF-1.7\nsynthetic"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept"].startswith("application/pdf")
        return httpx.Response(
            200,
            content=body,
            headers={
                "content-type": "application/pdf",
                "content-length": str(len(body)),
            },
        )

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
async def test_declared_content_length_is_rejected_before_body_download(
    tmp_path: Path,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"%PDF-1.7\nbody",
            headers={"content-type": "application/pdf", "content-length": "4096"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=128,
            validate_dns=False,
        )
        with pytest.raises(AppError) as raised:
            _ = await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.DOWNLOAD_TOO_LARGE
    assert list((tmp_path / "documents").glob("**/*")) == []


@pytest.mark.asyncio
async def test_streaming_limit_is_enforced_without_content_length(
    tmp_path: Path,
) -> None:
    class StreamingBody(httpx.AsyncByteStream):
        @override
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"%PDF-1.7\n"
            yield b"x" * 256

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, stream=StreamingBody(), headers={"content-type": "application/pdf"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=64,
            validate_dns=False,
        )
        with pytest.raises(AppError) as raised:
            _ = await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.DOWNLOAD_TOO_LARGE
    assert list((tmp_path / ".staging").iterdir()) == []


@pytest.mark.asyncio
async def test_html_disguised_as_pdf_is_rejected_and_removed(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"<!doctype html><title>login</title>",
            headers={"content-type": "application/pdf"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as raised:
            _ = await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.INVALID_DOCUMENT
    assert list((tmp_path / ".staging").iterdir()) == []


@pytest.mark.asyncio
async def test_foreign_redirect_is_rejected(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"location": "https://evil.example/document.pdf"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as raised:
            _ = await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_bitstream_must_be_public_and_bound_to_its_handle(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )

        with pytest.raises(AppError) as restricted:
            _ = await downloader.download(bitstream(access_status="restricted"))
        assert restricted.value.code is ErrorCode.RESTRICTED

        with pytest.raises(AppError) as mismatched:
            _ = await downloader.download(
                bitstream(
                    source_url="https://dspace.nplg.gov.ge/bitstream/1234/999/1/file.pdf"
                )
            )
        assert mismatched.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.asyncio
async def test_reported_size_above_limit_is_rejected_without_network_call(
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"%PDF-1.7")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as raised:
            _ = await downloader.download(bitstream(reported_size=1025))

    assert raised.value.code is ErrorCode.DOWNLOAD_TOO_LARGE
    assert calls == 0


@pytest.mark.asyncio
async def test_downloader_acquires_shared_rate_limiter_before_upstream_request(
    tmp_path: Path,
) -> None:
    class CountingLimiter:
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        async def acquire(self) -> None:
            self.calls += 1

    limiter = CountingLimiter()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"%PDF-1.7\nbody", headers={"content-type": "application/pdf"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
            limiter=limiter,
        )
        _ = await downloader.download(bitstream())

    assert limiter.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_downloader_maps_upstream_access_denial_to_restricted(
    tmp_path: Path, status: int
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, content=b"restricted", headers={"content-type": "text/html"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as raised:
            _ = await downloader.download(bitstream())

    assert raised.value.code is ErrorCode.RESTRICTED
    assert raised.value.http_status == _HTTP_FORBIDDEN


@pytest.mark.asyncio
async def test_download_stops_before_exceeding_aggregate_cache_quota(
    tmp_path: Path,
) -> None:
    body = b"%PDF-1.7\nbody"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=body, headers={"content-type": "application/pdf"}
        )

    store = ContentAddressedStore(tmp_path, max_bytes=8)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client, store=store, max_bytes=1024, validate_dns=False
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream())

    assert captured.value.code is ErrorCode.CACHE_FULL
    assert store.used_bytes == 0
    assert store.reserved_bytes == 0
    assert list((tmp_path / ".staging").iterdir()) == []
    assert list((tmp_path / "documents").iterdir()) == []


@pytest.mark.asyncio
async def test_downloader_revalidates_dns_for_each_redirect_hop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
            return httpx.Response(302, headers={"location": bitstream().source_url})
        return httpx.Response(
            200, content=b"%PDF-1.7\nbody", headers={"content-type": "application/pdf"}
        )

    monkeypatch.setattr("nplg_mcp.downloader.resolve_approved_addresses", resolve)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client, store=ContentAddressedStore(tmp_path), max_bytes=1024
        )
        _ = await downloader.download(bitstream())

    assert requests == _EXPECTED_REDIRECT_HOPS
    assert resolutions == _EXPECTED_REDIRECT_HOPS


@pytest.mark.asyncio
async def test_downloader_enforces_total_response_deadline(tmp_path: Path) -> None:
    class NeverEndingBody(httpx.AsyncByteStream):
        @override
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"%PDF-1.7\n"
            _ = await asyncio.Event().wait()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, stream=NeverEndingBody(), headers={"content-type": "application/pdf"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
            total_timeout_seconds=0.01,
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream())

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert captured.value.http_status == _HTTP_BAD_GATEWAY
    assert list((tmp_path / ".staging").iterdir()) == []


@pytest.mark.asyncio
async def test_slow_storage_write_does_not_block_the_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"%PDF-1.7\nevent-loop-storage",
            headers={"content-type": "application/pdf"},
        )

    store = ContentAddressedStore(tmp_path)
    real_stage = store.stage
    heartbeat = asyncio.Event()
    loop = asyncio.get_running_loop()
    heartbeat_seen_during_write = False

    @contextmanager
    def delayed_stage(*, suffix: str = "") -> Generator[object, None, None]:
        with real_stage(suffix=suffix) as destination:

            class DelayedWriter:
                def write(self, data: bytes) -> int:
                    nonlocal heartbeat_seen_during_write
                    _ = loop.call_soon_threadsafe(heartbeat.set)
                    time.sleep(0.2)
                    heartbeat_seen_during_write = heartbeat.is_set()
                    return destination.write(data)

                def commit(
                    self,
                    *,
                    namespace: str,
                    filename: str,
                    media_type: str,
                ) -> object:
                    return destination.commit(
                        namespace=namespace,
                        filename=filename,
                        media_type=media_type,
                    )

            yield DelayedWriter()

    monkeypatch.setattr(store, "stage", delayed_stage)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=store,
            max_bytes=1024,
            validate_dns=False,
        )
        result = await downloader.download(bitstream())

    assert result.bytes_downloaded > 0
    assert heartbeat_seen_during_write is True


@pytest.mark.asyncio
async def test_downloader_rejects_compressed_pdf_before_decoding(
    tmp_path: Path,
) -> None:
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
            headers={"content-type": "application/pdf", "content-encoding": "gzip"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream())

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert list((tmp_path / ".staging").iterdir()) == []


@pytest.mark.parametrize(
    ("max_bytes", "max_redirects", "total_timeout_seconds", "message"),
    [
        (0, 3, 120.0, "max_bytes"),
        (1024, -1, 120.0, "max_redirects"),
        (1024, 6, 120.0, "max_redirects"),
        (1024, 3, 0.0, "total_timeout_seconds"),
    ],
)
def test_downloader_rejects_invalid_resource_limits(
    tmp_path: Path,
    max_bytes: int,
    max_redirects: int,
    total_timeout_seconds: float,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _ = DocumentDownloader(
            client=cast("HttpClientProtocol", object()),
            store=ContentAddressedStore(tmp_path),
            max_bytes=max_bytes,
            max_redirects=max_redirects,
            total_timeout_seconds=total_timeout_seconds,
        )


@pytest.mark.asyncio
async def test_negative_reported_size_is_rejected_before_network(
    tmp_path: Path,
) -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream(reported_size=-1))

    assert captured.value.code is ErrorCode.INVALID_INPUT
    assert requests == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("location", "max_redirects", "expected_code"),
    [
        (_DEFAULT_SOURCE_URL, 0, ErrorCode.UPSTREAM_FAILURE),
        (None, 3, ErrorCode.UPSTREAM_FAILURE),
        (
            "https://dspace.nplg.gov.ge/bitstream/1234/999/1/file.pdf",
            3,
            ErrorCode.INVALID_INPUT,
        ),
    ],
)
async def test_redirect_faults_fail_before_body_or_storage(
    tmp_path: Path,
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
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
            max_redirects=max_redirects,
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream())

    assert captured.value.code is expected_code
    assert requests == 1
    assert not tuple((tmp_path / ".staging").iterdir())
    assert not tuple((tmp_path / "documents").iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected_code"),
    [
        (404, ErrorCode.NOT_FOUND),
        (429, ErrorCode.RATE_LIMITED),
        (500, ErrorCode.UPSTREAM_FAILURE),
    ],
)
async def test_downloader_maps_unsuccessful_status_before_body_read(
    tmp_path: Path,
    status: int,
    expected_code: ErrorCode,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            content=b"not a PDF",
            headers={"content-type": "text/plain"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream())

    assert captured.value.code is expected_code
    assert not tuple((tmp_path / ".staging").iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "expected_code"),
    [
        ({"content-type": "text/plain"}, ErrorCode.INVALID_DOCUMENT),
        (
            {"content-type": "application/pdf", "content-length": "invalid"},
            ErrorCode.UPSTREAM_FAILURE,
        ),
        (
            {"content-type": "application/pdf", "content-length": "-1"},
            ErrorCode.UPSTREAM_FAILURE,
        ),
    ],
)
async def test_downloader_rejects_invalid_response_headers_before_staging(
    tmp_path: Path,
    headers: dict[str, str],
    expected_code: ErrorCode,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"%PDF-1.7\nbody", headers=headers)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream())

    assert captured.value.code is expected_code
    assert not tuple((tmp_path / ".staging").iterdir())


@pytest.mark.asyncio
async def test_multiple_stream_chunks_preserve_the_pdf_and_digest(
    tmp_path: Path,
) -> None:
    chunks = (b"%PDF-1.7\n", b"body")

    class StreamingBody(httpx.AsyncByteStream):
        @override
        async def __aiter__(self) -> AsyncIterator[bytes]:
            for chunk in chunks:
                yield chunk

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=StreamingBody(),
            headers={"content-type": "application/pdf"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
        ).download(bitstream())

    assert result.artifact.absolute_path.read_bytes() == b"%PDF-1.7\nbody"
    assert result.bytes_downloaded == len(b"%PDF-1.7\nbody")
