# Copyright (c) 2026 David Osipov
"""Bounded asynchronous HTTP download and URL validation helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from .errors import AppError, ErrorCode
from .http_types import HttpClientProtocol, HttpResponseProtocol
from .parsers import Bitstream
from .rate_limit import RateLimiter
from .security import (
    NPLG_HOST,
    parse_handle_input,
    resolve_approved_addresses,
    validate_upstream_url,
)
from .storage import ContentAddressedStore, StoredArtifact

_RUNTIME_ANNOTATION_TYPES = (
    HttpClientProtocol,
    HttpResponseProtocol,
    Bitstream,
    RateLimiter,
    ContentAddressedStore,
    StoredArtifact,
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
_MAX_CONFIGURED_REDIRECTS = 5
_PDF_SIGNATURE_LENGTH = 8
_DOWNLOAD_DEADLINE_MESSAGE = (
    "The repository download did not complete within the configured deadline."
)
_STREAM_LIMIT_MESSAGE = (
    "The repository file exceeded the configured download limit while streaming."
)


def _validate_nplg_dns() -> None:
    _ = resolve_approved_addresses(NPLG_HOST)


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

    def __post_init__(self) -> None:
        """Reject invalid downloader limits before any upstream operation."""
        if type(self.max_bytes) is not int or self.max_bytes <= 0:
            msg = "max_bytes must be a positive integer"
            raise ValueError(msg)
        if not 0 <= self.max_redirects <= _MAX_CONFIGURED_REDIRECTS:
            msg = "max_redirects must be between 0 and 5"
            raise ValueError(msg)
        if self.total_timeout_seconds <= 0:
            msg = "total_timeout_seconds must be positive"
            raise ValueError(msg)

    async def _ensure_dns(self) -> None:
        if self.validate_dns:
            await asyncio.to_thread(_validate_nplg_dns)

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

    async def download(self, bitstream: Bitstream) -> DownloadResult:
        """Download and publish a validated public PDF bitstream."""
        try:
            async with asyncio.timeout(self.total_timeout_seconds):
                return await self._download_within_deadline(bitstream)
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
                _ = destination.write(chunk)
            if downloaded == 0 or not bytes(prefix).startswith(b"%PDF-"):
                raise AppError(
                    ErrorCode.INVALID_DOCUMENT,
                    "The repository response did not contain a valid PDF signature.",
                    http_status=422,
                )
            artifact = destination.commit(
                namespace="documents",
                filename="source.pdf",
                media_type="application/pdf",
            )
            return DownloadResult(
                artifact=artifact,
                source_bitstream_id=bitstream.bitstream_id,
                source_url=source_url,
                bytes_downloaded=downloaded,
            )

    async def _download_within_deadline(self, bitstream: Bitstream) -> DownloadResult:
        current = self._validate_bitstream(bitstream)
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
        for redirect_index in range(self.max_redirects + 1):
            await self._ensure_dns()
            if self.limiter is not None:
                await self.limiter.acquire()
            async with self.client.stream(
                "GET",
                current,
                headers={"accept": "application/pdf, application/octet-stream;q=0.8"},
                follow_redirects=False,
            ) as response:
                redirect = self._redirect_target(
                    response,
                    current=current,
                    bitstream=bitstream,
                    redirect_index=redirect_index,
                )
                if redirect is not None:
                    current = redirect
                    continue
                self._validate_response_status(response)
                self._validate_response_headers(response)
                return await self._store_response(
                    response, bitstream=bitstream, source_url=current
                )
        msg = "unreachable"
        raise AssertionError(msg)
