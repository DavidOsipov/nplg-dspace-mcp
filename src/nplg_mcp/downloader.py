from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from .errors import AppError, ErrorCode
from .parsers import Bitstream
from .rate_limit import RateLimiter
from .security import (
    NPLG_HOST,
    parse_handle_input,
    resolve_approved_addresses,
    validate_upstream_url,
)
from .storage import ContentAddressedStore, StoredArtifact

_ALLOWED_PDF_TYPES = {"application/pdf", "application/octet-stream", "binary/octet-stream", ""}


@dataclass(frozen=True, slots=True)
class DownloadResult:
    artifact: StoredArtifact
    source_bitstream_id: str
    source_url: str
    bytes_downloaded: int


@dataclass(slots=True)
class DocumentDownloader:
    client: httpx.AsyncClient
    store: ContentAddressedStore
    max_bytes: int
    validate_dns: bool = True
    max_redirects: int = 3
    limiter: RateLimiter | None = None
    total_timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        if not isinstance(self.max_bytes, int) or isinstance(self.max_bytes, bool) or self.max_bytes <= 0:
            raise ValueError("max_bytes must be a positive integer")
        if not 0 <= self.max_redirects <= 5:
            raise ValueError("max_redirects must be between 0 and 5")
        if self.total_timeout_seconds <= 0:
            raise ValueError("total_timeout_seconds must be positive")

    async def _ensure_dns(self) -> None:
        if self.validate_dns:
            await asyncio.to_thread(resolve_approved_addresses, NPLG_HOST)

    @staticmethod
    def _validate_bitstream(bitstream: Bitstream) -> str:
        if bitstream.access_status != "public":
            raise AppError(ErrorCode.RESTRICTED, "The repository file is not publicly downloadable.", http_status=403)
        handle = parse_handle_input(bitstream.handle)
        url = validate_upstream_url(bitstream.source_url)
        path = urlsplit(url).path
        if not path.startswith(f"/bitstream/{handle}/"):
            raise AppError(ErrorCode.INVALID_INPUT, "The bitstream URL is not bound to the requested item.")
        if bitstream.reported_size is not None and bitstream.reported_size < 0:
            raise AppError(ErrorCode.INVALID_INPUT, "The bitstream reported an invalid size.")
        return url

    async def download(self, bitstream: Bitstream) -> DownloadResult:
        try:
            async with asyncio.timeout(self.total_timeout_seconds):
                return await self._download_within_deadline(bitstream)
        except (TimeoutError, httpx.RequestError) as exc:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository download did not complete within the configured deadline.",
                http_status=502,
            ) from exc

    async def _download_within_deadline(self, bitstream: Bitstream) -> DownloadResult:
        current = self._validate_bitstream(bitstream)
        if bitstream.reported_size is not None and bitstream.reported_size > self.max_bytes:
            raise AppError(
                ErrorCode.DOWNLOAD_TOO_LARGE,
                "The repository file exceeds the configured download limit.",
                http_status=413,
                safe_details={"reported_size": bitstream.reported_size, "max_bytes": self.max_bytes},
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
                if response.status_code in {301, 302, 303, 307, 308}:
                    if redirect_index >= self.max_redirects:
                        raise AppError(ErrorCode.UPSTREAM_FAILURE, "The repository returned too many download redirects.", http_status=502)
                    location = response.headers.get("location")
                    if not location:
                        raise AppError(ErrorCode.UPSTREAM_FAILURE, "The repository returned an incomplete download redirect.", http_status=502)
                    current = validate_upstream_url(urljoin(current, location))
                    if not urlsplit(current).path.startswith(f"/bitstream/{parse_handle_input(bitstream.handle)}/"):
                        raise AppError(ErrorCode.INVALID_INPUT, "The download redirect escaped the discovered bitstream.")
                    continue
                if response.status_code == 404:
                    raise AppError(ErrorCode.NOT_FOUND, "The repository file was not found.", http_status=404)
                if response.status_code in {401, 403}:
                    raise AppError(
                        ErrorCode.RESTRICTED,
                        "The repository file is not publicly downloadable.",
                        http_status=403,
                    )
                if response.status_code == 429:
                    raise AppError(ErrorCode.RATE_LIMITED, "The repository is rate limiting file downloads.", http_status=503)
                if response.status_code < 200 or response.status_code >= 300:
                    raise AppError(
                        ErrorCode.UPSTREAM_FAILURE,
                        "The repository returned an unsuccessful download response.",
                        http_status=502,
                        safe_details={"upstream_status": response.status_code},
                    )
                content_encoding = response.headers.get("content-encoding", "").strip().lower()
                if content_encoding not in {"", "identity"}:
                    raise AppError(
                        ErrorCode.UPSTREAM_FAILURE,
                        "The repository returned unsupported content encoding.",
                        http_status=502,
                    )
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        declared = int(content_length)
                    except ValueError as exc:
                        raise AppError(ErrorCode.UPSTREAM_FAILURE, "The repository returned an invalid Content-Length.", http_status=502) from exc
                    if declared < 0:
                        raise AppError(ErrorCode.UPSTREAM_FAILURE, "The repository returned an invalid Content-Length.", http_status=502)
                    if declared > self.max_bytes:
                        raise AppError(
                            ErrorCode.DOWNLOAD_TOO_LARGE,
                            "The repository file exceeds the configured download limit.",
                            http_status=413,
                            safe_details={"content_length": declared, "max_bytes": self.max_bytes},
                        )
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type not in _ALLOWED_PDF_TYPES:
                    raise AppError(
                        ErrorCode.INVALID_DOCUMENT,
                        "The repository response is not a supported PDF document.",
                        http_status=422,
                        safe_details={"content_type": content_type or None},
                    )

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
                                "The repository file exceeded the configured download limit while streaming.",
                                http_status=413,
                                safe_details={"max_bytes": self.max_bytes},
                            )
                        if len(prefix) < 8:
                            prefix.extend(chunk[: 8 - len(prefix)])
                        destination.write(chunk)
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
                        source_url=current,
                        bytes_downloaded=downloaded,
                    )
        raise AssertionError("unreachable")
