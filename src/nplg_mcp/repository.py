# Copyright (c) 2026 David Osipov
"""Bounded read-only NPLG repository access."""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar
from urllib.parse import urljoin

import httpx

from .bounded_work import DNS_WORK, PARSER_WORK, BlockingWorkCapacityError
from .errors import AppError, ErrorCode
from .http_types import HttpClientProtocol, HttpResponseProtocol
from .json_types import JsonObject, dump_json, load_json_value, require_json_object
from .parsers import (
    Bitstream,
    DocumentRecord,
    SearchPage,
    parse_item_page,
    parse_metadata_formats,
    parse_oai_record,
    parse_search_results,
)
from .rate_limit import RateLimiter
from .security import (
    NPLG_HOST,
    NPLG_ORIGIN,
    build_item_url,
    parse_handle_input,
    resolve_approved_addresses,
    validate_upstream_url,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_RUNTIME_ANNOTATION_TYPES = (
    HttpClientProtocol,
    HttpResponseProtocol,
    RateLimiter,
)

_MAX_METADATA_BYTES = 10 * 1024 * 1024
_MAX_SEARCH_PAGE_SIZE = 50
_MAX_QUERY_LENGTH = 500
_MAX_CURSOR_OFFSET = 10_000_000
_MAX_CURSOR_LENGTH = 128
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_RESTRICTED_STATUSES = frozenset({401, 403})
_HTTP_OK_MIN = 200
_HTTP_REDIRECT_MIN = 300
_HTTP_NOT_FOUND = 404
_HTTP_TOO_MANY_REQUESTS = 429
_REQUEST_DEADLINE_MESSAGE = (
    "The repository request did not complete within the configured deadline."
)
_ParsedT = TypeVar("_ParsedT")


def _validate_nplg_dns() -> None:
    _ = resolve_approved_addresses(NPLG_HOST)


def encode_cursor(offset: int) -> str:
    """Encode a bounded nonnegative repository result offset."""
    if type(offset) is not int or offset < 0 or offset > _MAX_CURSOR_OFFSET:
        raise AppError(
            ErrorCode.INVALID_INPUT, "Cursor offset is outside the supported range."
        )
    payload: JsonObject = {"v": 1, "offset": offset}
    encoded_payload = dump_json(payload, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(encoded_payload).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> int:
    """Decode and validate an opaque repository result cursor."""
    if type(cursor) is not str or not cursor or len(cursor) > _MAX_CURSOR_LENGTH:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor is malformed.")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = require_json_object(
            load_json_value(decoded.decode("utf-8")), context="cursor payload"
        )
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor is malformed.") from exc
    if payload.get("v") != 1:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor version is unsupported.")
    offset = payload.get("offset")
    if type(offset) is not int or offset < 0 or offset > _MAX_CURSOR_OFFSET:
        raise AppError(
            ErrorCode.INVALID_INPUT, "Cursor offset is outside the supported range."
        )
    return offset


@dataclass(slots=True)
class NplgRepository:
    """Read bounded public metadata from the NPLG DSpace repository."""

    client: HttpClientProtocol
    validate_dns: bool = True
    max_redirects: int = 3
    max_metadata_bytes: int = _MAX_METADATA_BYTES
    limiter: RateLimiter | None = None
    total_timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        """Reject an invalid total request deadline."""
        if self.total_timeout_seconds <= 0:
            msg = "total_timeout_seconds must be positive"
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
                )
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
        parser: Callable[[], _ParsedT],
        *,
        deadline: float,
    ) -> _ParsedT:
        try:
            async with asyncio.timeout_at(deadline):
                return await PARSER_WORK.run(parser)
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
    ) -> tuple[str, str]:
        request_url = (
            httpx.URL(url) if params is None else httpx.URL(url, params=params)
        )
        current = validate_upstream_url(str(request_url))
        for redirect_index in range(self.max_redirects + 1):
            await self._ensure_dns()
            if self.limiter is not None:
                await self.limiter.acquire()
            async with self.client.stream(
                "GET", current, follow_redirects=False
            ) as response:
                redirect = self._redirect_target(
                    response, current=current, redirect_index=redirect_index
                )
                if redirect is not None:
                    current = redirect
                    continue
                self._validate_response_status(response)
                encoding = self._response_encoding(response)
                self._validate_content_type(response, accepted_types)
                return await self._read_response_text(
                    response, encoding=encoding
                ), current
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
        normalized_query = " ".join(query.split())
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
        offset = decode_cursor(cursor) if cursor is not None else 0
        if scope_handle is None:
            url = f"{NPLG_ORIGIN}/simple-search"
        else:
            scope = parse_handle_input(scope_handle)
            url = f"{NPLG_ORIGIN}/handle/{scope}/simple-search"
        text, final_url = await self._get_text(
            url,
            params={"query": normalized_query, "rpp": page_size, "start": offset},
            accepted_types=("text/html", "application/xhtml+xml"),
            deadline=deadline,
        )
        page = await self._parse_within_deadline(
            lambda: parse_search_results(
                text,
                source_url=final_url,
                page_size=page_size,
            ),
            deadline=deadline,
        )
        return page.with_cursor(
            encode_cursor(page.next_offset) if page.next_offset is not None else None
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
            lambda: parse_item_page(
                text,
                expected_handle=canonical,
                source_url=final_url,
            ),
            deadline=deadline,
        )

    async def list_files(self, handle: str) -> tuple[Bitstream, ...]:
        """List public files discovered on a validated item page."""
        return (await self.get_item(handle)).bitstreams

    async def _metadata_formats(self, *, deadline: float) -> tuple[str, ...]:
        text, _ = await self._get_text(
            f"{NPLG_ORIGIN}/oai/request",
            params={"verb": "ListMetadataFormats"},
            accepted_types=("text/xml", "application/xml"),
            deadline=deadline,
        )
        return await self._parse_within_deadline(
            lambda: parse_metadata_formats(text),
            deadline=deadline,
        )

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
                lambda: parse_oai_record(
                    text,
                    expected_handle=canonical,
                    metadata_prefix=prefix,
                ),
                deadline=deadline,
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
            lambda: parse_item_page(
                text,
                expected_handle=canonical,
                source_url=final_url,
            ),
            deadline=deadline,
        )


def _require_metadata_prefix(formats: tuple[str, ...]) -> str:
    prefix = "dim" if "dim" in formats else "oai_dc" if "oai_dc" in formats else None
    if prefix is None:
        raise AppError(
            ErrorCode.UPSTREAM_FAILURE,
            "The repository did not expose a supported OAI-PMH metadata format.",
            http_status=502,
        )
    return prefix
