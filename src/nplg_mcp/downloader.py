# Copyright (c) 2026 David Osipov
"""Bounded asynchronous HTTP download and URL validation helpers."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Protocol, cast
from urllib.parse import urljoin, urlsplit

import httpx

from .bounded_work import DNS_WORK, STORAGE_WORK, BlockingWorkCapacityError
from .contracts import MonotonicDeadline
from .errors import AppError, ErrorCode
from .http_types import HttpClientProtocol, HttpResponseProtocol
from .malware import MalwareScanError, MalwareScanner, validate_clean_scan_result
from .network import classify_transport_failure
from .parsers import Bitstream
from .rate_limit import RateLimiter
from .resilience import AttemptPermit, UpstreamGuard, UpstreamUnavailableError
from .security import (
    NPLG_HOST,
    DnsTransientError,
    OutboundPurpose,
    build_outbound_headers,
    parse_handle_input,
    resolve_approved_addresses,
    validate_upstream_url,
)
from .storage import ContentAddressedStore, StoredArtifact
from .storage_lifecycle import RetentionClockSample, RetentionPolicy

_RUNTIME_ANNOTATION_TYPES = (
    HttpClientProtocol,
    HttpResponseProtocol,
    Bitstream,
    RateLimiter,
    ContentAddressedStore,
    StoredArtifact,
    RetentionClockSample,
    RetentionPolicy,
    Callable,
)

_ALLOWED_PDF_TYPES = {
    "application/pdf",
    "application/octet-stream",
    "binary/octet-stream",
    "",
}
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_RESTRICTED_STATUSES = frozenset({401, 403})
_HTTP_OK_MIN = 200
_HTTP_REDIRECT_MIN = 300
_HTTP_NOT_FOUND = 404
_HTTP_TOO_MANY_REQUESTS = 429
_HTTP_SERVER_ERROR_MIN = 500
_MAX_UPSTREAM_TIMEOUT_SECONDS = 120.0
_MAX_CONFIGURED_REDIRECTS = 5
_PDF_SIGNATURE_LENGTH = 8
_DOCUMENT_PUBLICATION_INODES = 3
_DOWNLOAD_DEADLINE_MESSAGE = (
    "The repository download did not complete within the configured deadline."
)


async def _record_dns_app_error(permit: AttemptPermit, error: AppError) -> None:
    if isinstance(error, DnsTransientError) or error.code is ErrorCode.RATE_LIMITED:
        await permit.record_transient_failure()
    else:
        await permit.record_excluded_failure()


async def _record_transport_error(
    permit: AttemptPermit,
    error: TimeoutError | httpx.RequestError,
) -> None:
    if classify_transport_failure(error) == "transient":
        await permit.record_transient_failure()
    else:
        await permit.record_excluded_failure()


_STREAM_LIMIT_MESSAGE = (
    "The repository file exceeded the configured download limit while streaming."
)


class ScanClock(Protocol):
    """Supply a UTC observation used to evaluate scanner signature freshness."""

    def __call__(self) -> datetime:
        """Return one timezone-aware UTC clock observation."""
        raise NotImplementedError


def _system_scan_now() -> datetime:
    """Return the authoritative UTC wall-clock sample for verdict freshness."""
    return datetime.now(tz=UTC)


def _validate_nplg_dns() -> None:
    _ = resolve_approved_addresses(NPLG_HOST)


async def _run_storage_write(operation: Callable[[], int]) -> int:
    try:
        return await STORAGE_WORK.run_to_completion(operation)
    except BlockingWorkCapacityError as exc:
        raise AppError(
            ErrorCode.RATE_LIMITED,
            "The artifact storage service is at capacity.",
            http_status=503,
        ) from exc


async def _run_storage_commit(
    operation: Callable[[], StoredArtifact],
) -> StoredArtifact:
    try:
        return await STORAGE_WORK.run_to_completion(operation)
    except BlockingWorkCapacityError as exc:
        raise AppError(
            ErrorCode.RATE_LIMITED,
            "The artifact storage service is at capacity.",
            http_status=503,
        ) from exc


@dataclass(frozen=True, slots=True)
class DownloadResult:
    """Describe one content-addressed upstream download."""

    artifact: StoredArtifact
    source_bitstream_id: str
    source_url: str
    bytes_downloaded: int


@dataclass(slots=True)
class DocumentDownloader:
    """Download one discovered public bitstream under fixed resource limits."""

    client: HttpClientProtocol
    store: ContentAddressedStore
    max_bytes: int
    validate_dns: bool = True
    max_redirects: int = 3
    limiter: RateLimiter | None = None
    total_timeout_seconds: float = 120.0
    scanner: MalwareScanner | None = None
    scan_now: ScanClock = _system_scan_now
    require_scanner: bool = False
    guard: UpstreamGuard = field(default_factory=UpstreamGuard)
    clock: Callable[[], float] = time.monotonic
    retention_policy: RetentionPolicy | None = None
    retention_clock: Callable[[], RetentionClockSample] | None = None

    def __post_init__(self) -> None:
        """Reject invalid downloader limits before any upstream operation."""
        if type(self.max_bytes) is not int or self.max_bytes <= 0:
            msg = "max_bytes must be a positive integer"
            raise ValueError(msg)
        if not 0 <= self.max_redirects <= _MAX_CONFIGURED_REDIRECTS:
            msg = "max_redirects must be between 0 and 5"
            raise ValueError(msg)
        if (
            type(self.total_timeout_seconds) is not float
            or not math.isfinite(self.total_timeout_seconds)
            or self.total_timeout_seconds <= 0
            or self.total_timeout_seconds > _MAX_UPSTREAM_TIMEOUT_SECONDS
        ):
            msg = "total_timeout_seconds must be positive"
            raise ValueError(msg)
        guard = cast("object", self.guard)
        if not isinstance(guard, UpstreamGuard):
            msg = "guard must be an UpstreamGuard"
            raise TypeError(msg)
        require_scanner = cast("object", self.require_scanner)
        if type(require_scanner) is not bool:
            msg = "require_scanner must be a boolean"
            raise ValueError(msg)
        if self.require_scanner and self.scanner is None:
            msg = "private-full downloads require a malware scanner"
            raise ValueError(msg)
        if (self.retention_policy is None) != (self.retention_clock is None):
            msg = "retention policy and clock authority must be configured together"
            raise ValueError(msg)

    async def _ensure_dns(self) -> None:
        if self.validate_dns:
            try:
                await DNS_WORK.run(_validate_nplg_dns)
            except BlockingWorkCapacityError as exc:
                raise AppError(
                    ErrorCode.RATE_LIMITED,
                    "The DNS resolver is at capacity.",
                    http_status=503,
                ) from exc

    async def _admit_dependencies(self, permit: AttemptPermit) -> None:
        try:
            await self._ensure_dns()
        except AppError as exc:
            await _record_dns_app_error(permit, exc)
            raise
        if self.limiter is not None:
            await self.limiter.acquire()

    @staticmethod
    def _validate_bitstream(bitstream: Bitstream) -> str:
        if bitstream.access_status != "public":
            raise AppError(
                ErrorCode.RESTRICTED,
                "The repository file is not publicly downloadable.",
                http_status=403,
            )
        handle = parse_handle_input(bitstream.handle)
        url = validate_upstream_url(bitstream.source_url)
        path = urlsplit(url).path
        if not path.startswith(f"/bitstream/{handle}/"):
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "The bitstream URL is not bound to the requested item.",
            )
        if bitstream.reported_size is not None and bitstream.reported_size < 0:
            raise AppError(
                ErrorCode.INVALID_INPUT, "The bitstream reported an invalid size."
            )
        return url

    def _preflight_bitstream(self, bitstream: Bitstream) -> str:
        source_url = self._validate_bitstream(bitstream)
        if (
            bitstream.reported_size is not None
            and bitstream.reported_size > self.max_bytes
        ):
            raise AppError(
                ErrorCode.DOWNLOAD_TOO_LARGE,
                "The repository file exceeds the configured download limit.",
                http_status=413,
                safe_details={
                    "reported_size": bitstream.reported_size,
                    "max_bytes": self.max_bytes,
                },
            )
        return source_url

    async def download(self, bitstream: Bitstream) -> DownloadResult:
        """Download and publish a validated public PDF bitstream."""
        _ = self._preflight_bitstream(bitstream)
        deadline = MonotonicDeadline.after(
            min(self.total_timeout_seconds, 59.0),
            clock=self.clock,
        )
        try:
            if self.retention_policy is None or self.retention_clock is None:
                async with asyncio.timeout(self.total_timeout_seconds):
                    return await self._download_within_deadline(
                        bitstream,
                        deadline=deadline,
                    )
            async with self.store.reserve_publication(
                self.retention_policy,
                maximum_new_bytes=self.max_bytes,
                maximum_new_objects=1,
                # Object directory, source PDF, and lifecycle insertion record.
                maximum_new_inodes=_DOCUMENT_PUBLICATION_INODES,
                clock=self.retention_clock(),
            ) as reservation:
                async with asyncio.timeout(self.total_timeout_seconds):
                    result = await self._download_within_deadline(
                        bitstream,
                        deadline=deadline,
                    )
                await reservation.commit(
                    actual_bytes=result.artifact.size,
                    actual_objects=1,
                    actual_inodes=_DOCUMENT_PUBLICATION_INODES,
                )
                return result
        except UpstreamUnavailableError as exc:
            raise AppError(
                ErrorCode.RATE_LIMITED,
                "The repository is temporarily unavailable.",
                http_status=503,
                safe_details={"retry_after": exc.retry_after_seconds},
            ) from exc
        except (TimeoutError, httpx.RequestError) as exc:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                _DOWNLOAD_DEADLINE_MESSAGE,
                http_status=502,
            ) from exc

    def _redirect_target(
        self,
        response: HttpResponseProtocol,
        *,
        current: str,
        bitstream: Bitstream,
        redirect_index: int,
    ) -> str | None:
        if response.status_code not in _REDIRECT_STATUSES:
            return None
        if redirect_index >= self.max_redirects:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned too many download redirects.",
                http_status=502,
            )
        location = response.headers.get("location")
        if not location:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned an incomplete download redirect.",
                http_status=502,
            )
        target = validate_upstream_url(urljoin(current, location))
        handle = parse_handle_input(bitstream.handle)
        if not urlsplit(target).path.startswith(f"/bitstream/{handle}/"):
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "The download redirect escaped the discovered bitstream.",
            )
        return target

    @staticmethod
    def _validate_response_status(response: HttpResponseProtocol) -> None:
        status = response.status_code
        if status == _HTTP_NOT_FOUND:
            raise AppError(
                ErrorCode.NOT_FOUND,
                "The repository file was not found.",
                http_status=404,
            )
        if status in _RESTRICTED_STATUSES:
            raise AppError(
                ErrorCode.RESTRICTED,
                "The repository file is not publicly downloadable.",
                http_status=403,
            )
        if status == _HTTP_TOO_MANY_REQUESTS:
            raise AppError(
                ErrorCode.RATE_LIMITED,
                "The repository is rate limiting file downloads.",
                http_status=503,
            )
        if status < _HTTP_OK_MIN or status >= _HTTP_REDIRECT_MIN:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned an unsuccessful download response.",
                http_status=502,
                safe_details={"upstream_status": status},
            )

    def _validate_response_headers(self, response: HttpResponseProtocol) -> None:
        content_encoding = response.headers.get("content-encoding", "").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned unsupported content encoding.",
                http_status=502,
            )
        content_length = response.headers.get("content-length")
        if content_length:
            self._validate_content_length(content_length)
        content_type = (
            response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        )
        if content_type not in _ALLOWED_PDF_TYPES:
            raise AppError(
                ErrorCode.INVALID_DOCUMENT,
                "The repository response is not a supported PDF document.",
                http_status=422,
                safe_details={"content_type": content_type or None},
            )

    def _validate_content_length(self, content_length: str) -> None:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned an invalid Content-Length.",
                http_status=502,
            ) from exc
        if declared < 0:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned an invalid Content-Length.",
                http_status=502,
            )
        if declared > self.max_bytes:
            raise AppError(
                ErrorCode.DOWNLOAD_TOO_LARGE,
                "The repository file exceeds the configured download limit.",
                http_status=413,
                safe_details={
                    "content_length": declared,
                    "max_bytes": self.max_bytes,
                },
            )

    async def _store_response(
        self,
        response: HttpResponseProtocol,
        *,
        bitstream: Bitstream,
        source_url: str,
    ) -> DownloadResult:
        downloaded = 0
        prefix = bytearray()
        with self.store.stage(suffix=".pdf") as destination:
            async for chunk in response.aiter_bytes():
                if not chunk:
                    continue
                downloaded += len(chunk)
                if downloaded > self.max_bytes:
                    raise AppError(
                        ErrorCode.DOWNLOAD_TOO_LARGE,
                        _STREAM_LIMIT_MESSAGE,
                        http_status=413,
                        safe_details={"max_bytes": self.max_bytes},
                    )
                if len(prefix) < _PDF_SIGNATURE_LENGTH:
                    remaining = _PDF_SIGNATURE_LENGTH - len(prefix)
                    prefix.extend(chunk[:remaining])
                write_chunk: Callable[[], int] = partial(destination.write, chunk)
                _ = await _run_storage_write(write_chunk)
            if downloaded == 0 or not bytes(prefix).startswith(b"%PDF-"):
                raise AppError(
                    ErrorCode.INVALID_DOCUMENT,
                    "The repository response did not contain a valid PDF signature.",
                    http_status=422,
                )
            if self.scanner is not None:
                path, expected_sha256 = destination.prepare_for_scan()
                try:
                    result = await self.scanner.scan(
                        path,
                        expected_sha256=expected_sha256,
                        deadline=MonotonicDeadline.after(
                            min(self.total_timeout_seconds, 60.0),
                            clock=time.monotonic,
                        ),
                    )
                    validate_clean_scan_result(
                        path,
                        expected_sha256=expected_sha256,
                        result=result,
                        now=self.scan_now(),
                    )
                except (MalwareScanError, OSError, TimeoutError, ValueError) as exc:
                    raise AppError(
                        ErrorCode.INVALID_DOCUMENT,
                        "The downloaded document did not pass security scanning.",
                        http_status=422,
                    ) from exc
            artifact = await _run_storage_commit(
                partial(
                    destination.commit,
                    namespace="documents",
                    filename="source.pdf",
                    media_type="application/pdf",
                )
            )
            return DownloadResult(
                artifact=artifact,
                source_bitstream_id=bitstream.bitstream_id,
                source_url=source_url,
                bytes_downloaded=downloaded,
            )

    async def _download_within_deadline(
        self,
        bitstream: Bitstream,
        *,
        deadline: MonotonicDeadline,
    ) -> DownloadResult:
        current = self._preflight_bitstream(bitstream)
        for redirect_index in range(self.max_redirects + 1):
            async with self.guard.acquire(deadline) as permit:
                await self._admit_dependencies(permit)
                timeout = permit.deadline.remaining(now=self.clock())
                if timeout <= 0.0:
                    raise TimeoutError
                try:
                    async with self.client.stream(
                        "GET",
                        current,
                        headers=build_outbound_headers(OutboundPurpose.DOWNLOAD),
                        follow_redirects=False,
                        timeout=timeout,
                    ) as response:
                        status = response.status_code
                        transient = (
                            status == _HTTP_TOO_MANY_REQUESTS
                            or status >= _HTTP_SERVER_ERROR_MIN
                        )
                        redirect = self._redirect_target(
                            response,
                            current=current,
                            bitstream=bitstream,
                            redirect_index=redirect_index,
                        )
                        if redirect is not None:
                            await permit.record_success()
                            current = redirect
                            continue
                        if transient:
                            await permit.record_transient_failure()
                        elif status < _HTTP_OK_MIN or status >= _HTTP_REDIRECT_MIN:
                            await permit.record_excluded_failure()
                        self._validate_response_status(response)
                        self._validate_response_headers(response)
                        result = await self._store_response(
                            response,
                            bitstream=bitstream,
                            source_url=current,
                        )
                        await permit.record_success()
                        return result
                except (TimeoutError, httpx.RequestError) as exc:
                    if not permit.finalized:
                        await _record_transport_error(permit, exc)
                    raise
        msg = "unreachable"
        raise AssertionError(msg)
