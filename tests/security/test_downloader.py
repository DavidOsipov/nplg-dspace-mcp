# Copyright (c) 2026 David Osipov
# pyright: reportPrivateUsage=false
"""Adversarial tests for bounded downloader behavior."""

from __future__ import annotations

import asyncio
import hashlib
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast, get_type_hints, override

import httpx
import pytest

import nplg_mcp.network as network_module
from nplg_mcp import downloader as downloader_module
from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.downloader import DocumentDownloader
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.http_types import HttpClientProtocol
from nplg_mcp.malware import ScanResult, ScanVerdict
from nplg_mcp.parsers import Bitstream
from nplg_mcp.resilience import (
    AttemptPermit,
    Closed,
    Open,
    UpstreamGuard,
    UpstreamGuardPolicy,
)
from nplg_mcp.security import DnsTransientError
from nplg_mcp.storage import ContentAddressedStore, StoreLifecycleConfiguration
from nplg_mcp.storage_lifecycle import (
    ClockHighWater,
    PublicationBlocker,
    PublicationReservationError,
    RetentionClockSample,
    RetentionPolicy,
    StorageCapacity,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator, Generator
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
async def test_download_reserves_unknown_length_before_network_or_staging(
    tmp_path: Path,
) -> None:
    network_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return httpx.Response(
            200,
            content=b"%PDF-1.7\nbody",
            headers={"content-type": "application/pdf"},
        )

    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=10,
        maximum_objects=2,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    now = datetime.now(UTC)
    first = RetentionClockSample(
        utc_now=now,
        monotonic_now=0.0,
        boot_id="test-boot",
        synchronized=True,
    )
    current = RetentionClockSample(
        utc_now=now,
        monotonic_now=1.0,
        boot_id="test-boot",
        synchronized=True,
    )
    clock_guard = ClockHighWater(
        tmp_path / ".retention-clock.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    _ = clock_guard.observe(first)
    assert clock_guard.observe(first).trusted is True
    capacity = StorageCapacity(
        total_bytes=128 * 1024 * 1024,
        available_bytes=128 * 1024 * 1024,
        total_inodes=1000,
        available_inodes=1000,
    )
    store = ContentAddressedStore(
        tmp_path,
        max_bytes=10,
        lifecycle=StoreLifecycleConfiguration(
            policy=policy,
            capacity_sampler=lambda: capacity,
            clock_high_water=clock_guard,
            clock_sampler=lambda: current,
        ),
    )
    _ = store.put_bytes(
        b"123456",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=store,
            max_bytes=6,
            validate_dns=False,
            retention_policy=policy,
            retention_clock=lambda: current,
        )
        with pytest.raises(PublicationReservationError) as raised:
            _ = await downloader.download(bitstream())

    assert raised.value.blocker is PublicationBlocker.BYTE_BUDGET
    assert network_calls == 0
    assert tuple(store.staging_dir.iterdir()) == ()


@pytest.mark.asyncio
async def test_download_reserves_lifecycle_metadata_inode_before_network(
    tmp_path: Path,
) -> None:
    network_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal network_calls
        network_calls += 1
        return httpx.Response(
            200,
            content=b"%PDF-1.7\nbody",
            headers={"content-type": "application/pdf"},
        )

    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=1024,
        maximum_objects=2,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )
    now = datetime.now(UTC)
    initial = RetentionClockSample(
        utc_now=now,
        monotonic_now=0.0,
        boot_id="test-boot",
        synchronized=True,
    )
    current = RetentionClockSample(
        utc_now=now,
        monotonic_now=1.0,
        boot_id="test-boot",
        synchronized=True,
    )
    clock_guard = ClockHighWater(
        tmp_path / ".retention-clock.json",
        healthy_window_seconds=0,
        maximum_forward_slew_seconds=5,
    )
    _ = clock_guard.observe(initial)
    assert clock_guard.observe(initial).trusted is True
    capacity = StorageCapacity(
        total_bytes=128 * 1024 * 1024,
        available_bytes=128 * 1024 * 1024,
        total_inodes=1000,
        available_inodes=130,
    )
    store = ContentAddressedStore(
        tmp_path,
        max_bytes=1024,
        lifecycle=StoreLifecycleConfiguration(
            policy=policy,
            capacity_sampler=lambda: capacity,
            clock_high_water=clock_guard,
            clock_sampler=lambda: current,
        ),
    )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=store,
            max_bytes=128,
            validate_dns=False,
            retention_policy=policy,
            retention_clock=lambda: current,
        )
        with pytest.raises(PublicationReservationError) as raised:
            _ = await downloader.download(bitstream())

    assert raised.value.blocker is PublicationBlocker.INODE_HEADROOM
    assert network_calls == 0
    assert tuple(store.staging_dir.iterdir()) == ()


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


class _RecordingPermit:
    def __init__(self) -> None:
        super().__init__()
        self.outcomes: list[str] = []

    async def record_transient_failure(self) -> None:
        self.outcomes.append("transient")

    async def record_excluded_failure(self) -> None:
        self.outcomes.append("excluded")


@pytest.mark.asyncio
async def test_downloader_dns_errors_have_exact_circuit_classification() -> None:
    """Mutation caught: security/local DNS rejection poisoning availability state."""
    transient = _RecordingPermit()
    excluded = _RecordingPermit()
    await downloader_module._record_dns_app_error(  # noqa: SLF001
        cast("AttemptPermit", transient),
        DnsTransientError(
            ErrorCode.UPSTREAM_FAILURE,
            "The DNS lookup failed.",
            http_status=502,
        ),
    )
    await downloader_module._record_dns_app_error(  # noqa: SLF001
        cast("AttemptPermit", excluded),
        AppError(ErrorCode.INVALID_INPUT, "The DNS answer was rejected."),
    )
    assert transient.outcomes == ["transient"]
    assert excluded.outcomes == ["excluded"]


def test_downloader_rejects_a_forged_guard(tmp_path: Path) -> None:
    """Mutation caught: accepting a caller-controlled circuit implementation."""
    with pytest.raises(TypeError, match="UpstreamGuard"):
        _ = DocumentDownloader(
            client=cast("HttpClientProtocol", object()),
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            guard=cast("UpstreamGuard", object()),
        )


@pytest.mark.asyncio
async def test_downloader_dependency_error_is_classified_before_reraise(
    tmp_path: Path,
) -> None:
    """Mutation caught: DNS AppError escaping without finalizing its permit."""

    class _FailingDnsDownloader(DocumentDownloader):
        @override
        async def _ensure_dns(self) -> None:
            raise AppError(ErrorCode.INVALID_INPUT, "DNS security rejection")

    permit = _RecordingPermit()
    downloader = _FailingDnsDownloader(
        client=cast("HttpClientProtocol", object()),
        store=ContentAddressedStore(tmp_path),
        max_bytes=1024,
    )
    with pytest.raises(AppError, match="DNS security rejection"):
        await downloader._admit_dependencies(cast("AttemptPermit", permit))  # noqa: SLF001
    assert permit.outcomes == ["excluded"]


@pytest.mark.asyncio
async def test_downloader_maps_open_guard_before_transport(tmp_path: Path) -> None:
    """Mutation caught: leaking UpstreamUnavailableError through public download."""
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        clock=lambda: 0.0,
        random=lambda: 0.5,
    )
    permit = await guard.admit(MonotonicDeadline(created_at=0.0, expires_at=10.0))
    await permit.record_transient_failure()
    assert isinstance(guard.state, Open)
    downloader = DocumentDownloader(
        client=cast("HttpClientProtocol", object()),
        store=ContentAddressedStore(tmp_path),
        max_bytes=1024,
        validate_dns=False,
        guard=guard,
        clock=lambda: 0.0,
    )
    with pytest.raises(AppError) as captured:
        _ = await downloader.download(bitstream())
    assert captured.value.code is ErrorCode.RATE_LIMITED


@pytest.mark.asyncio
async def test_downloader_rejects_expired_attempt_before_transport(
    tmp_path: Path,
) -> None:
    """Mutation caught: starting a request after its admitted deadline expired."""
    guard = UpstreamGuard(clock=lambda: 0.0)
    downloader = DocumentDownloader(
        client=cast("HttpClientProtocol", object()),
        store=ContentAddressedStore(tmp_path),
        max_bytes=1024,
        validate_dns=False,
        guard=guard,
        clock=lambda: 2.0,
    )
    with pytest.raises(TimeoutError):
        _ = await downloader._download_within_deadline(  # noqa: SLF001
            bitstream(),
            deadline=MonotonicDeadline(created_at=0.0, expires_at=1.0),
        )


@pytest.mark.asyncio
async def test_downloader_transport_error_finalizes_transient_before_mapping(
    tmp_path: Path,
) -> None:
    """Mutation caught: post-admission transport error releasing as excluded."""
    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        random=lambda: 0.5,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        message = "synthetic transport failure"
        raise httpx.ConnectError(message, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
            guard=guard,
        )
        with pytest.raises(AppError) as captured:
            _ = await downloader.download(bitstream())
    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert isinstance(guard.state, Open)


@pytest.mark.asyncio
async def test_downloader_excludes_transport_policy_rejection_but_counts_timeout(
    tmp_path: Path,
) -> None:
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
        downloader = DocumentDownloader(
            client=client,
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            validate_dns=False,
            guard=guard,
        )
        with pytest.raises(AppError) as rejected:
            _ = await downloader.download(bitstream())
        assert rejected.value.code is ErrorCode.UPSTREAM_FAILURE
        closed: object = guard.state
        assert isinstance(closed, Closed)

        with pytest.raises(AppError) as timed_out:
            _ = await downloader.download(bitstream())
        assert timed_out.value.code is ErrorCode.UPSTREAM_FAILURE
        opened: object = guard.state
        assert isinstance(opened, Open)


@pytest.mark.asyncio
async def test_downloader_preserves_transport_error_from_successful_response_teardown(
    tmp_path: Path,
) -> None:
    """Mutation caught: double-finalizing success and masking teardown failure."""
    teardown_message = "synthetic response teardown failure"

    response = httpx.Response(
        200,
        headers={"content-type": "application/pdf"},
        content=b"%PDF-1.7\nvalid synthetic body",
    )

    class TeardownFailureClient:
        @asynccontextmanager
        async def stream(
            self,
            method: str,
            url: str,
            *,
            headers: object = None,
            follow_redirects: bool = False,
            timeout: float,  # noqa: ASYNC109 - required client protocol signature.
        ) -> AsyncGenerator[httpx.Response]:
            del method, url, headers, follow_redirects, timeout
            yield response
            raise httpx.ReadError(teardown_message)

        async def aclose(self) -> None:
            return

    guard = UpstreamGuard(
        policy=UpstreamGuardPolicy(failure_threshold=1),
        random=lambda: 0.5,
    )
    downloader = DocumentDownloader(
        client=cast("HttpClientProtocol", TeardownFailureClient()),
        store=ContentAddressedStore(tmp_path),
        max_bytes=1024,
        validate_dns=False,
        guard=guard,
    )
    with pytest.raises(AppError) as captured:
        _ = await downloader.download(bitstream())

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert isinstance(captured.value.__cause__, httpx.ReadError)
    assert teardown_message in str(captured.value.__cause__)
    assert isinstance(guard.state, Closed)
