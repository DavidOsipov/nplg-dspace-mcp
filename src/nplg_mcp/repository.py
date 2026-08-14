from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .errors import AppError, ErrorCode
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

_MAX_METADATA_BYTES = 10 * 1024 * 1024
_MAX_SEARCH_PAGE_SIZE = 50
_MAX_QUERY_LENGTH = 500


def encode_cursor(offset: int) -> str:
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > 10_000_000:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor offset is outside the supported range.")
    payload = json.dumps({"v": 1, "offset": offset}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> int:
    if not isinstance(cursor, str) or not cursor or len(cursor) > 128:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor is malformed.")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor is malformed.") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor version is unsupported.")
    offset = payload.get("offset")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > 10_000_000:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor offset is outside the supported range.")
    return offset


@dataclass(slots=True)
class NplgRepository:
    client: httpx.AsyncClient
    validate_dns: bool = True
    max_redirects: int = 3
    max_metadata_bytes: int = _MAX_METADATA_BYTES
    limiter: RateLimiter | None = None
    total_timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        if self.total_timeout_seconds <= 0:
            raise ValueError("total_timeout_seconds must be positive")

    async def _ensure_dns(self) -> None:
        if self.validate_dns:
            await asyncio.to_thread(resolve_approved_addresses, NPLG_HOST)

    async def _get_text(
        self,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        accepted_types: tuple[str, ...],
    ) -> tuple[str, str]:
        try:
            async with asyncio.timeout(self.total_timeout_seconds):
                return await self._get_text_within_deadline(
                    url,
                    params=params,
                    accepted_types=accepted_types,
                )
        except (TimeoutError, httpx.RequestError) as exc:
            raise AppError(
                ErrorCode.UPSTREAM_FAILURE,
                "The repository request did not complete within the configured deadline.",
                http_status=502,
            ) from exc

    async def _get_text_within_deadline(
        self,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        accepted_types: tuple[str, ...],
    ) -> tuple[str, str]:
        request_url = httpx.URL(url) if params is None else httpx.URL(url, params=params)
        current = validate_upstream_url(str(request_url))
        for redirect_index in range(self.max_redirects + 1):
            await self._ensure_dns()
            if self.limiter is not None:
                await self.limiter.acquire()
            async with self.client.stream("GET", current, follow_redirects=False) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    if redirect_index >= self.max_redirects:
                        raise AppError(ErrorCode.UPSTREAM_FAILURE, "The repository returned too many redirects.", http_status=502)
                    location = response.headers.get("location")
                    if not location:
                        raise AppError(ErrorCode.UPSTREAM_FAILURE, "The repository returned an incomplete redirect.", http_status=502)
                    current = validate_upstream_url(urljoin(current, location))
                    continue
                if response.status_code == 404:
                    raise AppError(ErrorCode.NOT_FOUND, "The requested repository item was not found.", http_status=404)
                if response.status_code in {401, 403}:
                    raise AppError(
                        ErrorCode.RESTRICTED,
                        "The requested repository item is not publicly accessible.",
                        http_status=403,
                    )
                if response.status_code == 429:
                    raise AppError(ErrorCode.RATE_LIMITED, "The repository is temporarily rate limiting requests.", http_status=503)
                if response.status_code < 200 or response.status_code >= 300:
                    raise AppError(
                        ErrorCode.UPSTREAM_FAILURE,
                        "The repository returned an unsuccessful response.",
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

                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
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
                encoding = response.charset_encoding or "utf-8"
                try:
                    return bytes(body).decode(encoding), current
                except (LookupError, UnicodeDecodeError) as exc:
                    raise AppError(
                        ErrorCode.UPSTREAM_FAILURE,
                        "The repository returned undecodable metadata.",
                        http_status=502,
                    ) from exc
        raise AssertionError("unreachable")

    async def search(
        self,
        query: str,
        *,
        page_size: int = 20,
        scope_handle: str | None = None,
        cursor: str | None = None,
    ) -> SearchPage:
        normalized_query = " ".join(query.split())
        if not normalized_query or len(normalized_query) > _MAX_QUERY_LENGTH:
            raise AppError(ErrorCode.INVALID_INPUT, f"Search query must contain 1 to {_MAX_QUERY_LENGTH} characters.")
        if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= _MAX_SEARCH_PAGE_SIZE:
            raise AppError(ErrorCode.INVALID_INPUT, f"page_size must be between 1 and {_MAX_SEARCH_PAGE_SIZE}.")
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
        )
        page = parse_search_results(text, source_url=final_url)
        return page.with_cursor(encode_cursor(page.next_offset) if page.next_offset is not None else None)

    async def get_item(self, handle: str) -> DocumentRecord:
        canonical = parse_handle_input(handle)
        url = build_item_url(canonical)
        text, final_url = await self._get_text(url, accepted_types=("text/html", "application/xhtml+xml"))
        return parse_item_page(text, expected_handle=canonical, source_url=final_url)

    async def list_files(self, handle: str) -> tuple[Bitstream, ...]:
        return (await self.get_item(handle)).bitstreams

    async def _metadata_formats(self) -> tuple[str, ...]:
        text, _ = await self._get_text(
            f"{NPLG_ORIGIN}/oai/request",
            params={"verb": "ListMetadataFormats"},
            accepted_types=("text/xml", "application/xml"),
        )
        return parse_metadata_formats(text)

    async def get_metadata(self, handle: str) -> DocumentRecord:
        canonical = parse_handle_input(handle)
        try:
            formats = await self._metadata_formats()
            prefix = "dim" if "dim" in formats else "oai_dc" if "oai_dc" in formats else None
            if prefix is None:
                raise AppError(ErrorCode.UPSTREAM_FAILURE, "The repository did not expose a supported OAI-PMH metadata format.", http_status=502)
            text, _ = await self._get_text(
                f"{NPLG_ORIGIN}/oai/request",
                params={
                    "verb": "GetRecord",
                    "metadataPrefix": prefix,
                    "identifier": f"oai:dspace.nplg.gov.ge:{canonical}",
                },
                accepted_types=("text/xml", "application/xml"),
            )
            return parse_oai_record(text, expected_handle=canonical, metadata_prefix=prefix)
        except AppError as error:
            if error.code not in {ErrorCode.UPSTREAM_FAILURE, ErrorCode.NOT_FOUND}:
                raise
        url = build_item_url(canonical, full=True)
        text, final_url = await self._get_text(url, accepted_types=("text/html", "application/xhtml+xml"))
        return parse_item_page(text, expected_handle=canonical, source_url=final_url)
