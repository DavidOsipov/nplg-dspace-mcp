# Copyright (c) 2026 David Osipov
"""Bounded HTML and XML parsers for repository responses."""

from __future__ import annotations

import hashlib
import io
import re
import unicodedata
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import TYPE_CHECKING, cast, override
from urllib.parse import parse_qs, urljoin, urlsplit

from bs4 import BeautifulSoup, Tag
from defusedxml import ElementTree as DefusedElementTree

from .errors import AppError, ErrorCode
from .security import NPLG_ORIGIN, parse_handle_input, validate_upstream_url

if TYPE_CHECKING:
    from collections.abc import Iterable
    from xml.etree.ElementTree import Element

    from bs4.element import NavigableString

_TOTAL_RE = re.compile(r"\bof\s+([\d,]+)\b", re.IGNORECASE)
_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B)\s*$", re.IGNORECASE)
_DC_KEY_RE = re.compile(r"^dc(?:\.[A-Za-z0-9_-]+)+$")
_RESTRICTED_MARKERS = (
    "only available in the library's internal network",
    "only be accessed from the national library's building",
    "must sign in or visit the library building",
    "not allowed to print or copy",
    "internal network",
    "შიდა ქსელ",
    "ბიბლიოთეკის შენობიდან",
)
_MIN_METADATA_CELLS = 2
_SIZE_CELL_INDEX = 2
_LANGUAGE_CELL_INDEX = 2
_FORMAT_CELL_INDEX = 3
_MAX_SEARCH_ITEMS = 50
_MAX_HTML_ELEMENTS = 20_000
_MAX_XML_ELEMENTS = 10_000
_MAX_TREE_DEPTH = 128
_MAX_AGGREGATE_TEXT_CODE_POINTS = 1_000_000
_MAX_METADATA_FIELDS = 512
_MAX_BITSTREAMS = 256
_MAX_METADATA_FORMATS = 64
_MAX_COLLECTIONS = 256
_VOID_HTML_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


@dataclass(frozen=True, slots=True)
class RawMetadataField:
    """Preserve one normalized qualified metadata value."""

    key: str
    value: str
    language: str | None = None


@dataclass(frozen=True, slots=True)
class SearchItem:
    """Represent one normalized item from a DSpace search page."""

    handle: str
    canonical_url: str
    title: str
    issue_date: str | None = None
    authors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Bitstream:
    """Describe one validated bitstream discovered on an item page."""

    bitstream_id: str
    handle: str
    filename: str
    source_url: str
    reported_size: int | None = None
    reported_format: str | None = None
    description: str | None = None
    access_status: str = "public"


@dataclass(frozen=True, slots=True)
class DocumentRecord:
    """Represent normalized metadata and public files for one NPLG item."""

    handle: str
    canonical_url: str
    title: str
    issue_date: str | None = None
    creators: tuple[str, ...] = ()
    contributors: tuple[str, ...] = ()
    publishers: tuple[str, ...] = ()
    descriptions: tuple[str, ...] = ()
    subjects: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    identifiers: tuple[str, ...] = ()
    rights: tuple[str, ...] = ()
    owners: tuple[str, ...] = ()
    collections: tuple[str, ...] = ()
    types: tuple[str, ...] = ()
    raw_fields: tuple[RawMetadataField, ...] = ()
    bitstreams: tuple[Bitstream, ...] = ()
    restricted: bool = False
    restriction_reason: str | None = None
    metadata_source: str = "xmlui_summary"


@dataclass(frozen=True, slots=True)
class SearchPage:
    """Represent one bounded page of normalized search results."""

    items: tuple[SearchItem, ...]
    total: int
    next_offset: int | None
    source_url: str
    next_cursor: str | None = None

    def with_cursor(self, cursor: str | None) -> SearchPage:
        """Return this page with its opaque continuation cursor attached."""
        return replace(self, next_cursor=cursor)


@dataclass(frozen=True, slots=True)
class _SearchColumns:
    title: int
    date: int | None
    author: int | None


@dataclass(frozen=True, slots=True)
class _RecordContext:
    metadata_source: str
    collections: tuple[str, ...] = ()
    bitstreams: tuple[Bitstream, ...] = ()
    restricted: bool = False
    restriction_reason: str | None = None
    fallback_title: str | None = None


def _normalize(value: str) -> str:
    return unicodedata.normalize("NFC", " ".join(value.split())).strip()


def _unique(values: Iterable[str | None]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        normalized = _normalize(value)
        if not normalized or normalized in seen or normalized == "-":
            continue
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


def _upstream_failure(
    message: str, *, source_url: str | None = None, cause: BaseException | None = None
) -> AppError:
    details = {"source_url": source_url} if source_url else None
    internal = {"cause": repr(cause)} if cause else None
    return AppError(
        ErrorCode.UPSTREAM_FAILURE,
        message,
        http_status=502,
        safe_details=details,
        internal_details=internal,
    )


def _validate_text_budget(
    current: int,
    value: str | None,
    *,
    source_url: str | None = None,
) -> int:
    updated = current + (len(value) if value is not None else 0)
    if updated > _MAX_AGGREGATE_TEXT_CODE_POINTS:
        msg = "The repository response exceeded the aggregate text limit."
        raise _upstream_failure(msg, source_url=source_url)
    return updated


class _HtmlBudgetParser(HTMLParser):
    """Reject excessive HTML structure before a complete tree is allocated."""

    def __init__(self, *, source_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._elements = 0
        self._open_elements: list[str] = []
        self._source_url = source_url
        self._text_code_points = 0

    def _add_element(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._elements += 1
        if self._elements > _MAX_HTML_ELEMENTS:
            msg = "The repository response exceeded the HTML element limit."
            raise _upstream_failure(msg, source_url=self._source_url)
        for key, value in attrs:
            self._text_code_points = _validate_text_budget(
                self._text_code_points,
                key,
                source_url=self._source_url,
            )
            self._text_code_points = _validate_text_budget(
                self._text_code_points,
                value,
                source_url=self._source_url,
            )
        if tag not in _VOID_HTML_ELEMENTS:
            self._open_elements.append(tag)
            if len(self._open_elements) > _MAX_TREE_DEPTH:
                msg = "The repository response exceeded the tree depth limit."
                raise _upstream_failure(msg, source_url=self._source_url)

    @override
    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self._add_element(tag, attrs)

    @override
    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del tag
        self._elements += 1
        if self._elements > _MAX_HTML_ELEMENTS:
            msg = "The repository response exceeded the HTML element limit."
            raise _upstream_failure(msg, source_url=self._source_url)
        for key, value in attrs:
            self._text_code_points = _validate_text_budget(
                self._text_code_points,
                key,
                source_url=self._source_url,
            )
            self._text_code_points = _validate_text_budget(
                self._text_code_points,
                value,
                source_url=self._source_url,
            )

    @override
    def handle_endtag(self, tag: str) -> None:
        if tag not in self._open_elements:
            return
        while self._open_elements[-1] != tag:
            _ = self._open_elements.pop()
        _ = self._open_elements.pop()

    @override
    def handle_data(self, data: str) -> None:
        self._text_code_points = _validate_text_budget(
            self._text_code_points,
            data,
            source_url=self._source_url,
        )

    @override
    def handle_comment(self, data: str) -> None:
        self.handle_data(data)


def _preflight_html(html: str, *, source_url: str) -> None:
    parser = _HtmlBudgetParser(source_url=source_url)
    try:
        parser.feed(html)
        parser.close()
    except AppError:
        raise
    except (AssertionError, ValueError) as exc:
        msg = "The repository returned malformed HTML."
        raise _upstream_failure(msg, source_url=source_url, cause=exc) from exc


def _preflight_xml(xml: str) -> None:
    elements = 0
    depth = 0
    text_code_points = 0
    try:
        parsed_events = cast(
            "Iterable[tuple[str, Element]]",
            DefusedElementTree.iterparse(
                io.StringIO(xml),
                events=("start", "end"),
            ),
        )
        for event, current in parsed_events:
            if event == "start":
                depth += 1
                elements += 1
                if depth > _MAX_TREE_DEPTH:
                    msg = "The repository response exceeded the tree depth limit."
                    raise _upstream_failure(msg)
                if elements > _MAX_XML_ELEMENTS:
                    msg = "The repository response exceeded the XML element limit."
                    raise _upstream_failure(msg)
                for key, value in current.attrib.items():
                    text_code_points = _validate_text_budget(text_code_points, key)
                    text_code_points = _validate_text_budget(text_code_points, value)
            else:
                text_code_points = _validate_text_budget(
                    text_code_points,
                    current.text,
                )
                text_code_points = _validate_text_budget(
                    text_code_points,
                    current.tail,
                )
                current.clear()
                depth -= 1
    except AppError:
        raise
    except (DefusedElementTree.ParseError, ValueError) as exc:
        msg = "The repository returned malformed OAI-PMH XML."
        raise _upstream_failure(msg, cause=exc) from exc


def _validate_html_tree(soup: BeautifulSoup, *, source_url: str) -> None:
    elements = 0
    text_code_points = 0
    stack: list[tuple[Tag, int]] = [(soup, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_TREE_DEPTH:
            msg = "The repository response exceeded the tree depth limit."
            raise _upstream_failure(msg, source_url=source_url)
        elements += 1
        if elements > _MAX_HTML_ELEMENTS:
            msg = "The repository response exceeded the HTML element limit."
            raise _upstream_failure(msg, source_url=source_url)
        for child in current.children:
            if isinstance(child, Tag):
                stack.append((child, depth + 1))
            else:
                text = cast("NavigableString", child)
                text_code_points = _validate_text_budget(
                    text_code_points,
                    str(text),
                    source_url=source_url,
                )


def _validate_xml_tree(root: Element) -> None:
    elements = 0
    text_code_points = 0
    stack: list[tuple[Element, int]] = [(root, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_TREE_DEPTH:
            msg = "The repository response exceeded the tree depth limit."
            raise _upstream_failure(msg)
        elements += 1
        if elements > _MAX_XML_ELEMENTS:
            msg = "The repository response exceeded the XML element limit."
            raise _upstream_failure(msg)
        text_code_points = _validate_text_budget(text_code_points, current.text)
        text_code_points = _validate_text_budget(text_code_points, current.tail)
        for key, value in current.attrib.items():
            text_code_points = _validate_text_budget(text_code_points, key)
            text_code_points = _validate_text_budget(text_code_points, value)
        stack.extend((child, depth + 1) for child in current)


def _tag_text(tag: Tag | None) -> str:
    return _normalize(tag.get_text(" ", strip=True)) if tag is not None else ""


def _tag_attribute(tag: Tag, name: str, default: str = "") -> str:
    value: object = tag.get(name, default)
    return value if isinstance(value, str) else default


def _class_contains(value: object, expected: str) -> bool:
    return isinstance(value, str) and expected in value


def _has_search_results_class(value: object) -> bool:
    return _class_contains(value, "search-results")


def _has_next_page_class(value: object) -> bool:
    return _class_contains(value, "next-page-link")


def _has_full_metadata_text(value: object) -> bool:
    return isinstance(value, str) and "full metadata record" in value.lower()


def _match_group(match: re.Match[str], index: int) -> str:
    return match.group(index)


def _canonical_item_from_href(href: str, *, source_url: str) -> tuple[str, str]:
    absolute = urljoin(source_url, href)
    _ = validate_upstream_url(absolute)
    parts = urlsplit(absolute)
    handle = parse_handle_input(parts.path)
    return handle, f"{NPLG_ORIGIN}/handle/{handle}"


def _normalize_date(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = _normalize(value)
    if not normalized or normalized == "-":
        return None
    for fmt in ("%d-%b-%Y", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            parsed = datetime.strptime(normalized, fmt).replace(tzinfo=UTC)
            return parsed.date().isoformat()
        except ValueError:
            pass
    return normalized


def _search_columns(table: Tag, *, source_url: str) -> _SearchColumns:
    header_cells = [_tag_text(cell).lower() for cell in table.select("thead th")]
    try:
        title_index = next(
            index for index, text in enumerate(header_cells) if text == "title"
        )
    except StopIteration as exc:
        msg = "The repository search table did not contain a title column."
        raise _upstream_failure(
            msg,
            source_url=source_url,
        ) from exc
    return _SearchColumns(
        title=title_index,
        date=next(
            (index for index, text in enumerate(header_cells) if "date" in text),
            None,
        ),
        author=next(
            (index for index, text in enumerate(header_cells) if "author" in text),
            None,
        ),
    )


def _search_items(
    table: Tag,
    *,
    columns: _SearchColumns,
    source_url: str,
    maximum_items: int,
) -> tuple[SearchItem, ...]:
    items: list[SearchItem] = []
    rows = table.select("tbody tr")
    if len(rows) > maximum_items:
        msg = "The repository search response exceeded the search item limit."
        raise _upstream_failure(msg, source_url=source_url)
    for row in rows:
        cells = row.find_all("td", recursive=False)
        if columns.title >= len(cells):
            continue
        title_cell = cells[columns.title]
        link = title_cell.find("a", href=True)
        if not isinstance(link, Tag):
            continue
        try:
            handle, canonical_url = _canonical_item_from_href(
                _tag_attribute(link, "href"), source_url=source_url
            )
        except AppError as exc:
            msg = "The repository returned an unsafe or malformed item link."
            raise _upstream_failure(
                msg,
                source_url=source_url,
                cause=exc,
            ) from exc
        title = _tag_text(link)
        if not title:
            msg = "The repository returned a search item without a title."
            raise _upstream_failure(
                msg,
                source_url=source_url,
            )
        issue_date = _normalize_date(
            _tag_text(cells[columns.date])
            if columns.date is not None and columns.date < len(cells)
            else None
        )
        authors_text = (
            _tag_text(cells[columns.author])
            if columns.author is not None and columns.author < len(cells)
            else ""
        )
        authors = _unique(piece for piece in authors_text.split(";") if piece.strip())
        items.append(
            SearchItem(
                handle=handle,
                canonical_url=canonical_url,
                title=title,
                issue_date=issue_date,
                authors=authors,
            )
        )
    return tuple(items)


def _search_total(container: Tag, *, item_count: int) -> int:
    context_text = _tag_text(container)
    total_match = _TOTAL_RE.search(context_text)
    return (
        item_count
        if total_match is None
        else int(_match_group(total_match, 1).replace(",", ""))
    )


def _next_search_offset(container: Tag, *, source_url: str) -> int | None:
    next_link = container.find("a", class_=_has_next_page_class, href=True)
    if not isinstance(next_link, Tag):
        next_link = next(
            (
                a
                for a in container.find_all("a", href=True)
                if _tag_text(a).lower() in {"next", "next page", ">"}
            ),
            None,
        )
    if not isinstance(next_link, Tag):
        return None
    absolute = urljoin(source_url, _tag_attribute(next_link, "href"))
    try:
        _ = validate_upstream_url(absolute)
    except AppError as exc:
        msg = "The repository returned an unsafe pagination link."
        raise _upstream_failure(
            msg,
            source_url=source_url,
            cause=exc,
        ) from exc
    raw_start = parse_qs(urlsplit(absolute).query).get("start", [None])[0]
    if raw_start is None:
        return None
    try:
        parsed_offset = int(raw_start)
    except ValueError as exc:
        msg = "The repository returned an invalid pagination offset."
        raise _upstream_failure(
            msg,
            source_url=source_url,
            cause=exc,
        ) from exc
    if parsed_offset < 0:
        msg = "The repository returned a negative pagination offset."
        raise _upstream_failure(
            msg,
            source_url=source_url,
        )
    return parsed_offset


def parse_search_results(
    html: str,
    *,
    source_url: str,
    page_size: int = _MAX_SEARCH_ITEMS,
) -> SearchPage:
    """Parse one bounded DSpace search response into normalized records."""
    if type(page_size) is not int or not 1 <= page_size <= _MAX_SEARCH_ITEMS:
        raise AppError(
            ErrorCode.INVALID_INPUT,
            f"page_size must be between 1 and {_MAX_SEARCH_ITEMS}.",
        )
    _preflight_html(html, source_url=source_url)
    soup = BeautifulSoup(html, "lxml")
    _validate_html_tree(soup, source_url=source_url)
    container = soup.find(id="aspect_discovery_SimpleSearch_div_search-results")
    if not isinstance(container, Tag):
        msg = (
            "The repository search response did not match the expected DSpace contract."
        )
        raise _upstream_failure(
            msg,
            source_url=source_url,
        )

    table = container.find("table", class_=_has_search_results_class)
    if not isinstance(table, Tag):
        msg = "The repository search response did not contain a results table."
        raise _upstream_failure(
            msg,
            source_url=source_url,
        )

    columns = _search_columns(table, source_url=source_url)
    items = _search_items(
        table,
        columns=columns,
        source_url=source_url,
        maximum_items=page_size,
    )

    return SearchPage(
        items=items,
        total=_search_total(container, item_count=len(items)),
        next_offset=_next_search_offset(container, source_url=source_url),
        source_url=source_url,
    )


def _parse_size(value: str) -> int | None:
    normalized = _normalize(value)
    match = _SIZE_RE.fullmatch(normalized)
    if match is None:
        return None
    amount = float(_match_group(match, 1))
    unit = _match_group(match, 2).upper()
    multiplier = {
        "B": 1,
        "KB": 1_000,
        "MB": 1_000_000,
        "GB": 1_000_000_000,
        "TB": 1_000_000_000_000,
    }[unit]
    return int(amount * multiplier)


def _bitstream_id(handle: str, source_url: str) -> str:
    digest = hashlib.sha256(f"{handle}\n{source_url}".encode()).hexdigest()
    return f"bit_{digest[:24]}"


def _parse_bitstreams(
    soup: BeautifulSoup, *, handle: str, source_url: str, restricted: bool
) -> tuple[Bitstream, ...]:
    if restricted:
        return ()
    result: list[Bitstream] = []
    seen_urls: set[str] = set()
    for link in soup.select('a[href*="/bitstream/"]'):
        href = _tag_attribute(link, "href")
        absolute = urljoin(source_url, href)
        try:
            _ = validate_upstream_url(absolute)
        except AppError as exc:
            msg = "The item page returned an unsafe bitstream link."
            raise _upstream_failure(
                msg,
                source_url=source_url,
                cause=exc,
            ) from exc
        expected_prefix = f"/bitstream/{handle}/"
        if not urlsplit(absolute).path.startswith(expected_prefix):
            msg = "The item page returned a bitstream bound to another handle."
            raise _upstream_failure(
                msg,
                source_url=source_url,
            )
        if absolute in seen_urls:
            continue
        if len(result) >= _MAX_BITSTREAMS:
            msg = "The item response exceeded the bitstream limit."
            raise _upstream_failure(msg, source_url=source_url)
        row = link.find_parent("tr")
        cells = (
            cast("list[Tag]", row.find_all("td", recursive=False))
            if isinstance(row, Tag)
            else []
        )
        filename = _tag_text(link) or urlsplit(absolute).path.rsplit("/", 1)[-1]
        description = _tag_text(cells[1]) if len(cells) >= _MIN_METADATA_CELLS else None
        size = (
            _parse_size(_tag_text(cells[_SIZE_CELL_INDEX]))
            if len(cells) > _SIZE_CELL_INDEX
            else None
        )
        reported_format = (
            _tag_text(cells[_FORMAT_CELL_INDEX])
            if len(cells) > _FORMAT_CELL_INDEX
            else None
        )
        result.append(
            Bitstream(
                bitstream_id=_bitstream_id(handle, absolute),
                handle=handle,
                filename=filename,
                source_url=absolute,
                reported_size=size,
                reported_format=reported_format or None,
                description=description or None,
            )
        )
        seen_urls.add(absolute)
    return tuple(result)


def _field_values(
    fields: tuple[RawMetadataField, ...], *keys: str, prefixes: tuple[str, ...] = ()
) -> tuple[str, ...]:
    return _unique(
        field.value
        for field in fields
        if field.key in keys or any(field.key.startswith(prefix) for prefix in prefixes)
    )


def _record_from_fields(
    *,
    handle: str,
    fields: tuple[RawMetadataField, ...],
    context: _RecordContext,
) -> DocumentRecord:
    titles = _field_values(fields, "dc.title")
    title = (
        titles[0] if titles else (_normalize(context.fallback_title or "") or handle)
    )
    issue_dates = _field_values(fields, "dc.date.issued")
    creators = _field_values(fields, "dc.creator")
    contributors = _field_values(fields, prefixes=("dc.contributor",))
    publishers = _field_values(fields, "dc.publisher")
    descriptions = _field_values(
        fields, "dc.description", prefixes=("dc.description.",)
    )
    subjects = _field_values(fields, "dc.subject", prefixes=("dc.subject.",))
    languages = _field_values(
        fields, "dc.language", "dc.language.iso", prefixes=("dc.language.",)
    )
    identifiers = _field_values(fields, "dc.identifier", prefixes=("dc.identifier.",))
    rights = _field_values(fields, "dc.rights", prefixes=("dc.rights.",))
    owners = _field_values(fields, "dc.rights.holder")
    types = _field_values(fields, "dc.type", prefixes=("dc.type.",))
    return DocumentRecord(
        handle=handle,
        canonical_url=f"{NPLG_ORIGIN}/handle/{handle}",
        title=title,
        issue_date=_normalize_date(issue_dates[0] if issue_dates else None),
        creators=creators,
        contributors=contributors,
        publishers=publishers,
        descriptions=descriptions,
        subjects=subjects,
        languages=languages,
        identifiers=identifiers,
        rights=rights,
        owners=owners,
        collections=context.collections,
        types=types,
        raw_fields=fields,
        bitstreams=context.bitstreams,
        restricted=context.restricted,
        restriction_reason=context.restriction_reason,
        metadata_source=context.metadata_source,
    )


def _extract_handle(soup: BeautifulSoup) -> str | None:
    for code in soup.find_all("code"):
        text = _tag_text(code)
        try:
            return parse_handle_input(text)
        except AppError:
            continue
    for link in soup.find_all("a", href=True):
        href = _tag_attribute(link, "href")
        if "/handle/" not in href:
            continue
        try:
            return parse_handle_input(urljoin(NPLG_ORIGIN, href))
        except AppError:
            continue
    return None


def _summary_fields(soup: BeautifulSoup) -> tuple[RawMetadataField, ...]:
    mapping = {
        "title": "dc.title",
        "issue date": "dc.date.issued",
        "publisher": "dc.publisher",
        "description": "dc.description",
        "owner": "dc.rights.holder",
        "author": "dc.contributor.author",
        "authors": "dc.contributor.author",
        "subject": "dc.subject",
        "language": "dc.language.iso",
        "type": "dc.type",
    }
    fields: list[RawMetadataField] = []
    for row in soup.select("table.itemDisplayTable tr"):
        cells = row.find_all("td", recursive=False)
        if len(cells) < _MIN_METADATA_CELLS:
            continue
        label = _tag_text(cells[0]).rstrip(":").strip().lower()
        key = mapping.get(label)
        if key is None:
            continue
        value = _tag_text(cells[1])
        if value:
            if len(fields) >= _MAX_METADATA_FIELDS:
                msg = "The item response exceeded the metadata field limit."
                raise _upstream_failure(msg)
            fields.append(RawMetadataField(key=key, value=value))
    return tuple(fields)


def _full_fields(soup: BeautifulSoup) -> tuple[RawMetadataField, ...]:
    fields: list[RawMetadataField] = []
    for row in soup.select("table.itemDisplayTable tr"):
        cells = row.find_all("td", recursive=False)
        if len(cells) < _MIN_METADATA_CELLS:
            continue
        key = _tag_text(cells[0])
        if not _DC_KEY_RE.fullmatch(key):
            continue
        value = _tag_text(cells[1])
        language = (
            _tag_text(cells[_LANGUAGE_CELL_INDEX])
            if len(cells) > _LANGUAGE_CELL_INDEX
            else ""
        )
        if not value:
            continue
        if len(fields) >= _MAX_METADATA_FIELDS:
            msg = "The item response exceeded the metadata field limit."
            raise _upstream_failure(msg)
        fields.append(
            RawMetadataField(
                key=key,
                value=value,
                language=None if language in {"", "-"} else language,
            )
        )
    return tuple(fields)


def _collections(soup: BeautifulSoup) -> tuple[str, ...]:
    values: list[str] = []
    for row in soup.select("table.itemDisplayTable tr"):
        cells = row.find_all("td", recursive=False)
        if (
            len(cells) >= _MIN_METADATA_CELLS
            and _tag_text(cells[0]).rstrip(":").lower() == "appears in collections"
        ):
            links = [_tag_text(link) for link in cells[1].find_all("a")]
            values.extend(links or [_tag_text(cells[1])])
    if not values:
        for paragraph in soup.find_all(["p", "div"]):
            text = _tag_text(paragraph)
            if text.lower().startswith("appears in collections:"):
                links = [_tag_text(link) for link in paragraph.find_all("a")]
                values.extend(links or [text.split(":", 1)[1]])
                break
    collections = _unique(values)
    if len(collections) > _MAX_COLLECTIONS:
        msg = "The item response exceeded the collection limit."
        raise _upstream_failure(msg)
    return collections


def parse_item_page(
    html: str, *, expected_handle: str, source_url: str
) -> DocumentRecord:
    """Parse one validated DSpace item HTML response."""
    expected = parse_handle_input(expected_handle)
    _preflight_html(html, source_url=source_url)
    soup = BeautifulSoup(html, "lxml")
    _validate_html_tree(soup, source_url=source_url)
    container = soup.find(id="aspect_artifactbrowser_ItemViewer_div_item-view")
    if not isinstance(container, Tag):
        msg = "The item response did not match the expected DSpace contract."
        raise _upstream_failure(
            msg,
            source_url=source_url,
        )
    actual = _extract_handle(soup)
    if actual is None or actual != expected:
        msg = "The item response did not match the requested handle."
        raise _upstream_failure(
            msg,
            source_url=source_url,
        )

    page_text = _tag_text(soup).lower()
    matching_restrictions = [
        marker for marker in _RESTRICTED_MARKERS if marker in page_text
    ]
    restricted = bool(matching_restrictions)
    restriction_reason = (
        "Access is limited to the library's internal network or building."
        if restricted
        else None
    )

    is_full = bool(soup.find(string=_has_full_metadata_text)) or any(
        _DC_KEY_RE.fullmatch(_tag_text(cell)) is not None
        for cell in soup.select("table.itemDisplayTable td:first-child")
    )
    fields = _full_fields(soup) if is_full else _summary_fields(soup)
    if not fields:
        msg = "The item response did not contain recognizable metadata."
        raise _upstream_failure(
            msg,
            source_url=source_url,
        )

    collections = _collections(soup)
    bitstreams = _parse_bitstreams(
        soup, handle=expected, source_url=source_url, restricted=restricted
    )
    title_tag = soup.find("title")
    fallback_title = (
        _tag_text(title_tag).removeprefix("Iverieli:").strip()
        if isinstance(title_tag, Tag)
        else expected
    )
    return _record_from_fields(
        handle=expected,
        fields=fields,
        context=_RecordContext(
            collections=collections,
            bitstreams=bitstreams,
            restricted=restricted,
            restriction_reason=restriction_reason,
            metadata_source="xmlui_full" if is_full else "xmlui_summary",
            fallback_title=fallback_title,
        ),
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml(xml: str) -> Element:
    _preflight_xml(xml)
    try:
        root = DefusedElementTree.fromstring(xml)
    except (DefusedElementTree.ParseError, ValueError) as exc:
        msg = "The repository returned malformed OAI-PMH XML."
        raise _upstream_failure(msg, cause=exc) from exc
    _validate_xml_tree(root)
    return root


def _first_descendant(root: Element, name: str) -> Element | None:
    return next(
        (element for element in root.iter() if _local_name(element.tag) == name), None
    )


def parse_metadata_formats(xml: str) -> tuple[str, ...]:
    """Parse supported metadata prefixes from an OAI-PMH response."""
    root = _parse_xml(xml)
    error = _first_descendant(root, "error")
    if error is not None:
        msg = "The repository rejected the OAI-PMH metadata format request."
        raise _upstream_failure(msg)
    formats = _unique(
        element.text
        for element in root.iter()
        if _local_name(element.tag) == "metadataPrefix"
    )
    if len(formats) > _MAX_METADATA_FORMATS:
        msg = "The repository response exceeded the metadata format limit."
        raise _upstream_failure(msg)
    if not formats:
        msg = "The repository returned no OAI-PMH metadata formats."
        raise _upstream_failure(msg)
    return formats


def _raise_for_oai_error(root: Element) -> None:
    error = _first_descendant(root, "error")
    if error is not None:
        code = error.attrib.get("code", "unknown")
        raise AppError(
            ErrorCode.UPSTREAM_FAILURE,
            "The repository could not return the requested OAI-PMH record.",
            http_status=502,
            safe_details={"oai_error": code},
        )


def _validate_oai_identifier(root: Element, *, expected: str) -> None:
    identifier_element = _first_descendant(root, "identifier")
    if identifier_element is None or not identifier_element.text:
        msg = "The OAI-PMH record did not contain an identifier."
        raise _upstream_failure(msg)
    identifier_text = _normalize(identifier_element.text)
    if not identifier_text.endswith(f":{expected}"):
        msg = "The OAI-PMH record did not match the requested handle."
        raise _upstream_failure(msg)


def _dim_fields(root: Element) -> tuple[RawMetadataField, ...]:
    fields: list[RawMetadataField] = []
    for element in root.iter():
        if _local_name(element.tag) != "field":
            continue
        schema = element.attrib.get("mdschema", "dc")
        field_element = element.attrib.get("element")
        if not field_element:
            continue
        qualifier = element.attrib.get("qualifier")
        key = f"{schema}.{field_element}" + (f".{qualifier}" if qualifier else "")
        value = _normalize(element.text or "")
        if value:
            if len(fields) >= _MAX_METADATA_FIELDS:
                msg = "The OAI-PMH record exceeded the metadata field limit."
                raise _upstream_failure(msg)
            fields.append(
                RawMetadataField(
                    key=key, value=value, language=element.attrib.get("lang")
                )
            )
    return tuple(fields)


def _dc_fields(root: Element) -> tuple[RawMetadataField, ...]:
    metadata = _first_descendant(root, "metadata")
    if metadata is None:
        msg = "The OAI-PMH record did not contain metadata."
        raise _upstream_failure(msg)
    fields: list[RawMetadataField] = []
    for element in metadata.iter():
        name = _local_name(element.tag)
        if name in {"metadata", "dc"}:
            continue
        value = _normalize(element.text or "")
        if value:
            if len(fields) >= _MAX_METADATA_FIELDS:
                msg = "The OAI-PMH record exceeded the metadata field limit."
                raise _upstream_failure(msg)
            fields.append(
                RawMetadataField(
                    key=f"dc.{name}",
                    value=value,
                    language=element.attrib.get(
                        "{http://www.w3.org/XML/1998/namespace}lang"
                    ),
                )
            )
    return tuple(fields)


def _oai_fields(
    root: Element, *, metadata_prefix: str
) -> tuple[tuple[RawMetadataField, ...], str]:
    prefix = metadata_prefix.strip()
    if prefix == "dim":
        return _dim_fields(root), "oai_dim"
    if prefix == "oai_dc":
        return _dc_fields(root), "oai_dc"
    raise AppError(
        ErrorCode.INVALID_INPUT,
        "Unsupported OAI-PMH metadata format.",
        safe_details={"metadata_prefix": prefix},
    )


def parse_oai_record(
    xml: str, *, expected_handle: str, metadata_prefix: str
) -> DocumentRecord:
    """Parse one validated DIM or Dublin Core OAI-PMH record."""
    expected = parse_handle_input(expected_handle)
    root = _parse_xml(xml)
    _raise_for_oai_error(root)
    _validate_oai_identifier(root, expected=expected)
    fields, source = _oai_fields(root, metadata_prefix=metadata_prefix)

    if not fields:
        msg = "The OAI-PMH record did not contain usable metadata fields."
        raise _upstream_failure(msg)
    return _record_from_fields(
        handle=expected,
        fields=fields,
        context=_RecordContext(metadata_source=source),
    )
