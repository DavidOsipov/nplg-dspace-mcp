# Copyright (c) 2026 David Osipov
"""Bounded read-only NPLG repository access."""

from __future__ import annotations

import asyncio
import math
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, TypeVar, cast
from urllib.parse import urljoin

import httpx

from .bounded_work import DNS_WORK, BlockingWorkCapacityError
from .contracts import MonotonicDeadline
from .errors import AppError, ErrorCode
from .http_types import HttpClientProtocol, HttpResponseProtocol
from .network import classify_transport_failure
from .parser_executor import ParserExecutor, ParserWorkerError, SubprocessParserExecutor
from .parsers import (  # noqa: TC001 - get_type_hints is a tested runtime contract.
    Bitstream,
    DocumentRecord,
    SearchPage,
)
from .rate_limit import RateLimiter
from .resilience import AttemptPermit, UpstreamGuard, UpstreamUnavailableError
from .security import (
    NPLG_HOST,
    NPLG_ORIGIN,
    DnsTransientError,
    build_item_url,
    parse_handle_input,
    resolve_approved_addresses,
    validate_upstream_url,
)
from .tokens import (
    CURSOR_KEY_ID,
    DEFAULT_CURSOR_TTL_SECONDS,
    CursorV1,
    cursor_query_hash,
    derive_cursor_signing_key,
    sign_cursor,
    verify_cursor,
)

_RUNTIME_ANNOTATION_TYPES = (
    HttpClientProtocol,
    HttpResponseProtocol,
    RateLimiter,
    Callable,
)

_MAX_METADATA_BYTES = 10 * 1024 * 1024
_MAX_SEARCH_PAGE_SIZE = 50
_MAX_QUERY_LENGTH = 500
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_RESTRICTED_STATUSES = frozenset({401, 403})
_HTTP_OK_MIN = 200
_HTTP_REDIRECT_MIN = 300
_HTTP_NOT_FOUND = 404
_HTTP_TOO_MANY_REQUESTS = 429
_HTTP_SERVER_ERROR_MIN = 500
_MAX_UPSTREAM_TIMEOUT_SECONDS = 120.0
_OAI_DISCOVERY_CACHE_TTL_SECONDS = 300.0
_MAX_OAI_DISCOVERY_CACHE_ENTRIES = 8
_REQUEST_DEADLINE_MESSAGE = (
    "The repository request did not complete within the configured deadline."
)


def _empty_oai_format_cache() -> dict[str, _OaiFormatCacheEntry]:
    return {}


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


_ParsedT = TypeVar("_ParsedT")


@dataclass(frozen=True, slots=True)
class _OaiFormatCacheEntry:
    formats: tuple[str, ...]
    created_at: float
    expires_at: float

    def __post_init__(self) -> None:
        if (
            type(self.created_at) is not float
            or type(self.expires_at) is not float
            or not math.isfinite(self.created_at)
            or not math.isfinite(self.expires_at)
            or self.created_at < 0.0
            or not 0.0
            < self.expires_at - self.created_at
            <= _OAI_DISCOVERY_CACHE_TTL_SECONDS
        ):
            msg = "OAI discovery cache expiry is invalid"
            raise ValueError(msg)


def _publish_metadata_formats(
    cache: dict[str, _OaiFormatCacheEntry],
    *,
    origin: str,
    formats: tuple[str, ...],
    stored_at: float,
) -> None:
    expired_origins = [
        key for key, entry in cache.items() if entry.expires_at <= stored_at
    ]
    for key in expired_origins:
        del cache[key]
    if len(cache) >= _MAX_OAI_DISCOVERY_CACHE_ENTRIES:

        def cache_expiry(cache_key: str) -> float:
            return cache[cache_key].expires_at

        oldest = min(cache, key=cache_expiry)
        del cache[oldest]
    cache[origin] = _OaiFormatCacheEntry(
        formats=formats,
        created_at=stored_at,
        expires_at=stored_at + _OAI_DISCOVERY_CACHE_TTL_SECONDS,
    )


def _validate_nplg_dns() -> None:
    _ = resolve_approved_addresses(NPLG_HOST)


def _canonical_search_query(query: str) -> str:
    if type(query) is not str:
        raise AppError(ErrorCode.INVALID_INPUT, "Search query must be text.")
    return " ".join(query.split())


def encode_cursor(  # noqa: PLR0913 - explicit authenticated context
    offset: int,
    *,
    secret: bytes,
    normalized_query: str,
    scope_handle: str | None,
    page_size: int,
    now: datetime,
) -> str:
    """Encode an authenticated cursor bound to every search context value."""
    try:
        payload = CursorV1(
            version=1,
            key_id=CURSOR_KEY_ID,
            query_hash=cursor_query_hash(normalized_query),
            scope_handle=scope_handle,
            offset=offset,
            page_size=page_size,
            issued_at=now,
            expires_at=now + timedelta(seconds=DEFAULT_CURSOR_TTL_SECONDS),
        )
    except ValueError as exc:
        raise AppError(
            ErrorCode.INVALID_INPUT, "Cursor offset is outside the supported range."
        ) from exc
    return sign_cursor(secret, payload)


def decode_cursor(  # noqa: PLR0913 - explicit authenticated context
    cursor: str,
    *,
    secret: bytes,
    normalized_query: str,
    scope_handle: str | None,
    page_size: int,
    now: datetime,
) -> int:
    """Decode an authenticated cursor only in its original search context."""
    return verify_cursor(
        secret,
        cursor,
        normalized_query=normalized_query,
        scope_handle=scope_handle,
        page_size=page_size,
        now=now,
    ).offset


@dataclass(slots=True)
class NplgRepository:
    """Read bounded public metadata from the NPLG DSpace repository."""

    client: HttpClientProtocol
    validate_dns: bool = True
    max_redirects: int = 3
    max_metadata_bytes: int = _MAX_METADATA_BYTES
    limiter: RateLimiter | None = None
    total_timeout_seconds: float = 120.0
    guard: UpstreamGuard = field(default_factory=UpstreamGuard)
    clock: Callable[[], float] = time.monotonic
    cursor_signing_secret: bytes = field(
        default_factory=lambda: secrets.token_bytes(32), repr=False
    )
    cursor_clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    cache_clock: Callable[[], float] = time.monotonic
    parser_executor: ParserExecutor = field(default_factory=SubprocessParserExecutor)
    _metadata_format_cache: dict[str, _OaiFormatCacheEntry] = field(
        default_factory=_empty_oai_format_cache,
        init=False,
        repr=False,
    )
    _metadata_format_lock: asyncio.Lock = field(
        default_factory=asyncio.Lock,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Reject an invalid total request deadline."""
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
        parser_executor = cast("object", self.parser_executor)
        if not isinstance(parser_executor, ParserExecutor):
            msg = "parser_executor must implement the strict parser protocol"
            raise TypeError(msg)
        _ = derive_cursor_signing_key(self.cursor_signing_secret)

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

    async def _get_text(
        self,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        accepted_types: tuple[str, ...],
        deadline: float | None = None,
    ) -> tuple[str, str]:
        effective_deadline = (
            asyncio.get_running_loop().time() + self.total_timeout_seconds
            if deadline is None
            else deadline
        )
        try:
            async with asyncio.timeout_at(effective_deadline):
                return await self._get_text_within_deadline(
                    url,
                    params=params,
                    accepted_types=accepted_types,
                    deadline=effective_deadline,
                )
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
                _REQUEST_DEADLINE_MESSAGE,
                http_status=502,
            ) from exc

    def _new_deadline(self) -> float:
        return asyncio.get_running_loop().time() + self.total_timeout_seconds

    async def _parse_within_deadline(
        self,
        parser: Awaitable[_ParsedT],
    ) -> _ParsedT:
        try:
            return await parser
        except BlockingWorkCapacityError as exc:
            raise AppError(
                ErrorCode.RATE_LIMITED,
                "The metadata parser is at parser capacity.",
                http_status=503,
            ) from exc
        except TimeoutError as exc:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                _REQUEST_DEADLINE_MESSAGE,
                http_status=502,
            ) from exc
        except ParserWorkerError as exc:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository response could not be parsed safely.",
                http_status=502,
            ) from exc

    def _redirect_target(
        self,
        response: HttpResponseProtocol,
        *,
        current: str,
        redirect_index: int,
    ) -> str | None:
        if response.status_code not in _REDIRECT_STATUSES:
            return None
        if redirect_index >= self.max_redirects:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned too many redirects.",
                http_status=502,
            )
        location = response.headers.get("location")
        if not location:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned an incomplete redirect.",
                http_status=502,
            )
        return validate_upstream_url(urljoin(current, location))

    @staticmethod
    def _validate_response_status(response: HttpResponseProtocol) -> None:
        status = response.status_code
        if status == _HTTP_NOT_FOUND:
            raise AppError(
                ErrorCode.NOT_FOUND,
                "The requested repository item was not found.",
                http_status=404,
            )
        if status in _RESTRICTED_STATUSES:
            raise AppError(
                ErrorCode.RESTRICTED,
                "The requested repository item is not publicly accessible.",
                http_status=403,
            )
        if status == _HTTP_TOO_MANY_REQUESTS:
            raise AppError(
                ErrorCode.RATE_LIMITED,
                "The repository is temporarily rate limiting requests.",
                http_status=503,
            )
        if status < _HTTP_OK_MIN or status >= _HTTP_REDIRECT_MIN:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned an unsuccessful response.",
                http_status=502,
                safe_details={"upstream_status": status},
            )

    def _response_encoding(self, response: HttpResponseProtocol) -> str:
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
        return response.charset_encoding or "utf-8"

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
        if declared > self.max_metadata_bytes:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository metadata response was unexpectedly large.",
                http_status=502,
            )

    @staticmethod
    def _validate_content_type(
        response: HttpResponseProtocol, accepted_types: tuple[str, ...]
    ) -> None:
        content_type = (
            response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        )
        if content_type and not any(
            content_type == item or content_type.endswith(f"+{item.split('/')[-1]}")
            for item in accepted_types
        ):
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned an unexpected metadata content type.",
                http_status=502,
                safe_details={"content_type": content_type},
            )

    async def _read_response_text(
        self, response: HttpResponseProtocol, *, encoding: str
    ) -> str:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if not chunk:
                continue
            if len(chunk) > self.max_metadata_bytes - len(body):
                raise AppError(
                    ErrorCode.UPSTREAM_FAILURE,
                    "The repository metadata response was unexpectedly large.",
                    http_status=502,
                )
            body.extend(chunk)
        try:
            return bytes(body).decode(encoding)
        except (LookupError, UnicodeDecodeError) as exc:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository returned undecodable metadata.",
                http_status=502,
            ) from exc

    async def _get_text_within_deadline(
        self,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        accepted_types: tuple[str, ...],
        deadline: float,
    ) -> tuple[str, str]:
        request_url = (
            httpx.URL(url) if params is None else httpx.URL(url, params=params)
        )
        current = validate_upstream_url(str(request_url))
        for redirect_index in range(self.max_redirects + 1):
            now = self.clock()
            remaining = deadline - now
            if remaining <= 0.0:
                raise TimeoutError
            request_deadline = MonotonicDeadline(
                created_at=now,
                expires_at=now + min(remaining, 59.0),
            )
            async with self.guard.acquire(request_deadline) as permit:
                await self._admit_dependencies(permit)
                timeout = permit.deadline.remaining(now=self.clock())
                if timeout <= 0.0:
                    raise TimeoutError
                try:
                    async with self.client.stream(
                        "GET",
                        current,
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
                        encoding = self._response_encoding(response)
                        self._validate_content_type(response, accepted_types)
                        text = await self._read_response_text(
                            response, encoding=encoding
                        )
                        await permit.record_success()
                        return text, current
                except (TimeoutError, httpx.RequestError) as exc:
                    if not permit.finalized:
                        await _record_transport_error(permit, exc)
                    raise
        msg = "unreachable"
        raise AssertionError(msg)

    async def search(
        self,
        query: str,
        *,
        page_size: int = 20,
        scope_handle: str | None = None,
        cursor: str | None = None,
    ) -> SearchPage:
        """Search public NPLG records with an opaque bounded cursor."""
        deadline = self._new_deadline()
        normalized_query = _canonical_search_query(query)
        if not normalized_query or len(normalized_query) > _MAX_QUERY_LENGTH:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                f"Search query must contain 1 to {_MAX_QUERY_LENGTH} characters.",
            )
        if type(page_size) is not int or not 1 <= page_size <= _MAX_SEARCH_PAGE_SIZE:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                f"page_size must be between 1 and {_MAX_SEARCH_PAGE_SIZE}.",
            )
        if scope_handle is None:
            scope = None
            url = f"{NPLG_ORIGIN}/simple-search"
        else:
            scope = parse_handle_input(scope_handle)
            url = f"{NPLG_ORIGIN}/handle/{scope}/simple-search"
        cursor_now = self.cursor_clock()
        offset = (
            decode_cursor(
                cursor,
                secret=self.cursor_signing_secret,
                normalized_query=normalized_query,
                scope_handle=scope,
                page_size=page_size,
                now=cursor_now,
            )
            if cursor is not None
            else 0
        )
        text, final_url = await self._get_text(
            url,
            params={"query": normalized_query, "rpp": page_size, "start": offset},
            accepted_types=("text/html", "application/xhtml+xml"),
            deadline=deadline,
        )
        page = await self._parse_within_deadline(
            self.parser_executor.parse_search(
                text,
                source_url=final_url,
                page_size=page_size,
                deadline=deadline,
            ),
        )
        return page.with_cursor(
            encode_cursor(
                page.next_offset,
                secret=self.cursor_signing_secret,
                normalized_query=normalized_query,
                scope_handle=scope,
                page_size=page_size,
                now=cursor_now,
            )
            if page.next_offset is not None
            else None
        )

    async def get_item(self, handle: str) -> DocumentRecord:
        """Return one validated public HTML item record."""
        deadline = self._new_deadline()
        canonical = parse_handle_input(handle)
        url = build_item_url(canonical)
        text, final_url = await self._get_text(
            url,
            accepted_types=("text/html", "application/xhtml+xml"),
            deadline=deadline,
        )
        return await self._parse_within_deadline(
            self.parser_executor.parse_item(
                text,
                expected_handle=canonical,
                source_url=final_url,
                deadline=deadline,
            ),
        )

    async def list_files(self, handle: str) -> tuple[Bitstream, ...]:
        """List public files discovered on a validated item page."""
        return (await self.get_item(handle)).bitstreams

    async def _metadata_formats(self, *, deadline: float) -> tuple[str, ...]:
        async with self._metadata_format_lock:
            origin = NPLG_ORIGIN
            now = self.cache_clock()
            cached = self._metadata_format_cache.get(origin)
            if cached is not None:
                if now < cached.created_at:
                    del self._metadata_format_cache[origin]
                    msg = "monotonic cache clock moved backwards"
                    raise RuntimeError(msg)
                if now < cached.expires_at:
                    return cached.formats
                del self._metadata_format_cache[origin]
            text, _ = await self._get_text(
                f"{origin}/oai/request",
                params={"verb": "ListMetadataFormats"},
                accepted_types=("text/xml", "application/xml"),
                deadline=deadline,
            )
            formats = await self._parse_within_deadline(
                self.parser_executor.parse_metadata_formats(text, deadline=deadline),
            )
            stored_at = self.cache_clock()
            if stored_at < now:
                if origin in self._metadata_format_cache:
                    del self._metadata_format_cache[origin]
                msg = "monotonic cache clock moved backwards"
                raise RuntimeError(msg)
            _publish_metadata_formats(
                self._metadata_format_cache,
                origin=origin,
                formats=formats,
                stored_at=stored_at,
            )
            return formats

    async def get_metadata(self, handle: str) -> DocumentRecord:
        """Return OAI-PMH metadata with a validated full-HTML fallback."""
        deadline = self._new_deadline()
        canonical = parse_handle_input(handle)
        try:
            formats = await self._metadata_formats(deadline=deadline)
            prefix = _require_metadata_prefix(formats)
            text, _ = await self._get_text(
                f"{NPLG_ORIGIN}/oai/request",
                params={
                    "verb": "GetRecord",
                    "metadataPrefix": prefix,
                    "identifier": f"oai:dspace.nplg.gov.ge:{canonical}",
                },
                accepted_types=("text/xml", "application/xml"),
                deadline=deadline,
            )
            return await self._parse_within_deadline(
                self.parser_executor.parse_oai_record(
                    text,
                    expected_handle=canonical,
                    metadata_prefix=prefix,
                    deadline=deadline,
                ),
            )
        except AppError as error:
            if error.code not in {ErrorCode.UPSTREAM_FAILURE, ErrorCode.NOT_FOUND}:
                raise
        url = build_item_url(canonical, full=True)
        text, final_url = await self._get_text(
            url,
            accepted_types=("text/html", "application/xhtml+xml"),
            deadline=deadline,
        )
        return await self._parse_within_deadline(
            self.parser_executor.parse_item(
                text,
                expected_handle=canonical,
                source_url=final_url,
                deadline=deadline,
            ),
        )


def _require_metadata_prefix(
    formats: tuple[str, ...],
) -> Literal["dim", "oai_dc"]:
    if "dim" in formats:
        return "dim"
    if "oai_dc" in formats:
        return "oai_dc"
    raise AppError(
        ErrorCode.UPSTREAM_FAILURE,
        "The repository did not expose a supported OAI-PMH metadata format.",
        http_status=502,
    )
