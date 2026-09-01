# Copyright (c) 2026 David Osipov
"""Bounded HTML and XML parsers for repository responses."""

from __future__ import annotations

import hashlib
import io
import re
import time
import unicodedata
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Literal, cast, override
from urllib.parse import parse_qs, urljoin, urlsplit

from bs4 import BeautifulSoup, Tag
from bs4.element import Comment, Declaration, Doctype, NavigableString
from defusedxml import ElementTree as DefusedElementTree

from .contracts import MAX_SAFE_INTEGER, StrictModel
from .errors import AppError, ErrorCode
from .security import NPLG_HOST, NPLG_ORIGIN, parse_handle_input, validate_upstream_url
from .tokens import MAX_CURSOR_OFFSET

if TYPE_CHECKING:
    from collections.abc import Iterable
    from xml.etree.ElementTree import Element

_TOTAL_RE = re.compile(r"\bof\s+([\d,]+)\b", re.IGNORECASE)
_JSPUI_RANGE_PREFIX = r"\bშედეგის\s+ჩვენება\s+([\d,]+)\s*[-\u2013]\s*დან\s+"
_JSPUI_RANGE_SUFFIX = (
    r"([\d,]+)\s*[-\u2013]\s*მდე\s+სულ\s*[-\u2013]\s*([\d,]+)(?![\d,])"
)
_JSPUI_RANGE_RE = re.compile(f"{_JSPUI_RANGE_PREFIX}{_JSPUI_RANGE_SUFFIX}")
_JSPUI_ENGLISH_RANGE_RE = re.compile(
    r"""
    \bResults\s+([\d,]+)\s*[-\u2013]\s*([\d,]+)\s+of\s+([\d,]+)(?![\d,])
    \s+\(Search\ time:\s+[0-9]+(?:\.[0-9]+)?\s+seconds\)\.
    """,
    re.VERBOSE,
)
_SEARCH_INTEGER_RE = re.compile(r"(?:[0-9]+|[1-9][0-9]{0,2}(?:,[0-9]{3})+)")
_SEARCH_VERSION_RE = re.compile(r"ex[0-9]{8}")
_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B)\s*$", re.IGNORECASE)
_DC_KEY_RE = re.compile(r"^dc(?:\.[A-Za-z0-9_-]+)+$")
_WHITESPACE_RUN_RE = re.compile(r"\s+")
_RESTRICTED_MARKERS = (
    "only available in the library's internal network",
    "only be accessed from the national library's building",
    "must sign in or visit the library building",
    "not allowed to print or copy",
    "internal network",
    "შიდა ქსელ",
    "ბიბლიოთეკის შენობიდან",
)
_JSPUI_IDENTIFIER_LEAD_IN = "Please use this identifier to cite or link to this item:"
_JSPUI_SEARCH_TABLE_SUMMARY = "This table browses all dspace content"
_MIN_METADATA_CELLS = 2
_SIZE_CELL_INDEX = 2
_LANGUAGE_CELL_INDEX = 2
_FORMAT_CELL_INDEX = 3
_MAX_SEARCH_ITEMS = 50
_MAX_BITSTREAMS = 256
_MAX_METADATA_FORMATS = 64
_MAX_COLLECTIONS = 256
_OAI_NAMESPACE = "http://www.openarchives.org/OAI/2.0/"
_OAI_ROOT_TAG = f"{{{_OAI_NAMESPACE}}}OAI-PMH"
_OAI_LIST_METADATA_FORMATS_TAG = f"{{{_OAI_NAMESPACE}}}ListMetadataFormats"
_OAI_METADATA_FORMAT_TAG = f"{{{_OAI_NAMESPACE}}}metadataFormat"
_OAI_METADATA_PREFIX_TAG = f"{{{_OAI_NAMESPACE}}}metadataPrefix"
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


class ParserLimits(StrictModel):
    """Immutable reviewed maxima for untrusted HTML and XML metadata."""

    markup_bytes: Literal[2_097_152] = 2_097_152
    max_depth: Literal[64] = 64
    max_nodes: Literal[50_000] = 50_000
    max_attributes_per_node: Literal[64] = 64
    max_total_attributes: Literal[100_000] = 100_000
    max_field_code_points: Literal[65_536] = 65_536
    max_total_text_code_points: Literal[1_048_576] = 1_048_576
    max_metadata_fields: Literal[2_048] = 2_048
    max_records: Literal[1_000] = 1_000
    parse_deadline_ms: Literal[2_000] = 2_000


PARSER_LIMITS = ParserLimits()
_parser_clock = time.monotonic


@dataclass(frozen=True, slots=True)
class _MarkupCounts:
    nodes: int
    total_attributes: int
    total_text_code_points: int
    semantic_total_text_code_points: int
    metadata_fields: int
    records: int
    max_field_code_points: int
    semantic_max_field_code_points: int


@dataclass(slots=True)
class _CanonicalTextCounter:
    """Track raw limits and whitespace-normalized parser agreement separately."""

    code_points: int = 0
    semantic_code_points: int = 0
    in_whitespace: bool = False

    def add(self, value: str | None) -> None:
        if value is None:
            return
        self.code_points = _saturating_increment(
            self.code_points,
            len(value),
            maximum=PARSER_LIMITS.max_total_text_code_points,
        )
        if not value:
            return
        if _WHITESPACE_RUN_RE.search(value) is None:
            semantic_increment = len(value)
        else:
            semantic_increment = len(_WHITESPACE_RUN_RE.sub(" ", value))
        if self.in_whitespace and value[0].isspace():
            semantic_increment -= 1
        self.semantic_code_points = _saturating_increment(
            self.semantic_code_points,
            semantic_increment,
            maximum=PARSER_LIMITS.max_total_text_code_points,
        )
        self.in_whitespace = value[-1].isspace()


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
    cell_count: int
    header_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _SearchContract:
    container: Tag
    table: Tag
    variant: Literal["xmlui", "jspui"]


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
    if updated > PARSER_LIMITS.max_total_text_code_points:
        msg = "The repository response exceeded the aggregate text limit."
        raise _upstream_failure(msg, source_url=source_url)
    return updated


def _saturating_increment(current: int, increment: int, *, maximum: int) -> int:
    """Increment a non-negative counter, saturating at one past its ceiling."""
    if increment > maximum - current:
        return maximum + 1
    return current + increment


class _HtmlBudgetParser(HTMLParser):
    """Reject excessive HTML structure before a complete tree is allocated."""

    def __init__(self, *, source_url: str, started_at: float) -> None:
        super().__init__(convert_charrefs=True)
        self._elements = 0
        self._open_elements: list[str] = []
        self._source_url = source_url
        self._text_counter = _CanonicalTextCounter()
        self._total_attributes = 0
        self._started_at = started_at
        self._contexts: list[str | None] = []
        self._field_counters: list[_CanonicalTextCounter | None] = []
        self._metadata_fields = 0
        self._records = 0
        self._max_field_code_points = 0
        self._semantic_max_field_code_points = 0
        self.check_deadline()

    @property
    def counts(self) -> _MarkupCounts:
        return _MarkupCounts(
            nodes=self._elements,
            total_attributes=self._total_attributes,
            total_text_code_points=self._text_counter.code_points,
            semantic_total_text_code_points=self._text_counter.semantic_code_points,
            metadata_fields=self._metadata_fields,
            records=self._records,
            max_field_code_points=self._max_field_code_points,
            semantic_max_field_code_points=self._semantic_max_field_code_points,
        )

    def check_deadline(self) -> None:
        if _parser_clock() - self._started_at > PARSER_LIMITS.parse_deadline_ms / 1_000:
            msg = "The repository response exceeded the parse deadline."
            raise _upstream_failure(msg, source_url=self._source_url)

    def _add_attributes(self, attrs: list[tuple[str, str | None]]) -> None:
        if len(attrs) > PARSER_LIMITS.max_attributes_per_node:
            msg = "The repository response exceeded the per-node attribute limit."
            raise _upstream_failure(msg, source_url=self._source_url)
        if len(attrs) > PARSER_LIMITS.max_total_attributes - self._total_attributes:
            msg = "The repository response exceeded the aggregate attribute limit."
            raise _upstream_failure(msg, source_url=self._source_url)
        self._total_attributes = _saturating_increment(
            self._total_attributes,
            len(attrs),
            maximum=PARSER_LIMITS.max_total_attributes,
        )
        for key, value in attrs:
            self._add_text(key)
            self._add_text(value)

    def _add_text(self, value: str | None) -> None:
        self._text_counter.add(value)
        if self._text_counter.code_points > PARSER_LIMITS.max_total_text_code_points:
            msg = "The repository response exceeded the aggregate text limit."
            raise _upstream_failure(msg, source_url=self._source_url)

    def _add_element(  # noqa: C901 - bounded lexical state machine
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self.check_deadline()
        self._elements = _saturating_increment(
            self._elements,
            1,
            maximum=PARSER_LIMITS.max_nodes,
        )
        if self._elements > PARSER_LIMITS.max_nodes:
            msg = "The repository response exceeded the HTML element limit."
            raise _upstream_failure(msg, source_url=self._source_url)
        self._add_attributes(attrs)
        if tag not in _VOID_HTML_ELEMENTS:
            context = self._contexts[-1] if self._contexts else None
            if tag == "table":
                class_value = next(
                    (value for key, value in attrs if key == "class"), None
                )
                if class_value is not None and "search-results" in class_value:
                    context = "search"
                elif class_value is not None and "itemDisplayTable" in class_value:
                    context = "metadata"
            if tag == "tr" and context == "metadata":
                self._metadata_fields = _saturating_increment(
                    self._metadata_fields,
                    1,
                    maximum=PARSER_LIMITS.max_metadata_fields,
                )
                if self._metadata_fields > PARSER_LIMITS.max_metadata_fields:
                    msg = "The repository response exceeded the metadata field limit."
                    raise _upstream_failure(msg, source_url=self._source_url)
            if tag == "tr" and context == "search" and "tbody" in self._open_elements:
                self._records = _saturating_increment(
                    self._records,
                    1,
                    maximum=PARSER_LIMITS.max_records,
                )
                if self._records > PARSER_LIMITS.max_records:
                    msg = "The repository response exceeded the record limit."
                    raise _upstream_failure(msg, source_url=self._source_url)
            self._open_elements.append(tag)
            self._contexts.append(context)
            self._field_counters.append(
                _CanonicalTextCounter() if tag == "td" else None
            )
            if len(self._open_elements) > PARSER_LIMITS.max_depth:
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
        self.check_deadline()
        self._elements = _saturating_increment(
            self._elements,
            1,
            maximum=PARSER_LIMITS.max_nodes,
        )
        if self._elements > PARSER_LIMITS.max_nodes:
            msg = "The repository response exceeded the HTML element limit."
            raise _upstream_failure(msg, source_url=self._source_url)
        self._add_attributes(attrs)

    @override
    def handle_endtag(self, tag: str) -> None:
        if tag not in self._open_elements:
            return
        while self._open_elements[-1] != tag:
            _ = self._open_elements.pop()
            _ = self._contexts.pop()
            _ = self._field_counters.pop()
        _ = self._open_elements.pop()
        _ = self._contexts.pop()
        _ = self._field_counters.pop()

    @override
    def handle_data(self, data: str) -> None:
        self.check_deadline()
        for current in self._field_counters:
            if current is None:
                continue
            current.add(data)
            if current.code_points > PARSER_LIMITS.max_field_code_points:
                msg = "The repository response exceeded the field code-point limit."
                raise _upstream_failure(msg, source_url=self._source_url)
            self._max_field_code_points = max(
                self._max_field_code_points,
                current.code_points,
            )
            self._semantic_max_field_code_points = max(
                self._semantic_max_field_code_points,
                current.semantic_code_points,
            )
        self._add_text(data)


def _preflight_html(html: str, *, source_url: str) -> _MarkupCounts:
    started_at = _parser_clock()
    if len(html.encode("utf-8")) > PARSER_LIMITS.markup_bytes:
        msg = "The repository response exceeded the markup byte limit."
        raise _upstream_failure(msg, source_url=source_url)
    parser = _HtmlBudgetParser(source_url=source_url, started_at=started_at)
    try:
        parser.feed(html)
        parser.close()
        parser.check_deadline()
        return parser.counts  # noqa: TRY300
    except AppError:
        raise
    except (AssertionError, ValueError) as exc:
        msg = "The repository returned malformed HTML."
        raise _upstream_failure(msg, source_url=source_url, cause=exc) from exc


def _preflight_xml(  # noqa: C901, PLR0912, PLR0915 - bounded event state machine
    xml: str,
) -> _MarkupCounts:
    started_at = _parser_clock()
    if len(xml.encode("utf-8")) > PARSER_LIMITS.markup_bytes:
        msg = "The repository response exceeded the markup byte limit."
        raise _upstream_failure(msg)
    elements = 0
    depth = 0
    text_code_points = 0
    total_attributes = 0
    element_names: list[str] = []
    field_elements: list[bool] = []
    metadata_fields = 0
    records = 0
    max_field_code_points = 0
    try:
        parsed_events = cast(
            "Iterable[tuple[str, Element]]",
            DefusedElementTree.iterparse(
                io.StringIO(xml),
                events=("start", "end"),
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            ),
        )
        for event, current in parsed_events:
            if _parser_clock() - started_at > PARSER_LIMITS.parse_deadline_ms / 1_000:
                msg = "The repository response exceeded the parse deadline."
                raise _upstream_failure(msg)
            if event == "start":
                name = _local_name(current.tag)
                parent_name = element_names[-1] if element_names else None
                depth = _saturating_increment(
                    depth,
                    1,
                    maximum=PARSER_LIMITS.max_depth,
                )
                elements = _saturating_increment(
                    elements,
                    1,
                    maximum=PARSER_LIMITS.max_nodes,
                )
                if depth > PARSER_LIMITS.max_depth:
                    msg = "The repository response exceeded the tree depth limit."
                    raise _upstream_failure(msg)
                if elements > PARSER_LIMITS.max_nodes:
                    msg = "The repository response exceeded the XML element limit."
                    raise _upstream_failure(msg)
                attribute_count = len(current.attrib)
                if attribute_count > PARSER_LIMITS.max_attributes_per_node:
                    msg = (
                        "The repository response exceeded the per-node attribute limit."
                    )
                    raise _upstream_failure(msg)
                if (
                    attribute_count
                    > PARSER_LIMITS.max_total_attributes - total_attributes
                ):
                    msg = (
                        "The repository response exceeded the aggregate "
                        "attribute limit."
                    )
                    raise _upstream_failure(msg)
                total_attributes = _saturating_increment(
                    total_attributes,
                    attribute_count,
                    maximum=PARSER_LIMITS.max_total_attributes,
                )
                is_field = name == "field" or parent_name == "dc"
                if is_field:
                    metadata_fields = _saturating_increment(
                        metadata_fields,
                        1,
                        maximum=PARSER_LIMITS.max_metadata_fields,
                    )
                    if metadata_fields > PARSER_LIMITS.max_metadata_fields:
                        msg = (
                            "The repository response exceeded the metadata field limit."
                        )
                        raise _upstream_failure(msg)
                if name == "record":
                    records = _saturating_increment(
                        records,
                        1,
                        maximum=PARSER_LIMITS.max_records,
                    )
                    if records > PARSER_LIMITS.max_records:
                        msg = "The repository response exceeded the record limit."
                        raise _upstream_failure(msg)
                element_names.append(name)
                field_elements.append(is_field)
                for key, value in current.attrib.items():
                    text_code_points = _validate_text_budget(text_code_points, key)
                    text_code_points = _validate_text_budget(text_code_points, value)
            else:
                if field_elements[-1] and len(current.text or "") > (
                    PARSER_LIMITS.max_field_code_points
                ):
                    msg = "The repository response exceeded the field code-point limit."
                    raise _upstream_failure(msg)
                if field_elements[-1]:
                    max_field_code_points = max(
                        max_field_code_points,
                        min(
                            len(current.text or ""),
                            PARSER_LIMITS.max_field_code_points + 1,
                        ),
                    )
                text_code_points = _validate_text_budget(
                    text_code_points,
                    current.text,
                )
                text_code_points = _validate_text_budget(
                    text_code_points,
                    current.tail,
                )
                current.clear()
                _ = element_names.pop()
                _ = field_elements.pop()
                depth -= 1
        return _MarkupCounts(
            nodes=elements,
            total_attributes=total_attributes,
            total_text_code_points=text_code_points,
            semantic_total_text_code_points=text_code_points,
            metadata_fields=metadata_fields,
            records=records,
            max_field_code_points=max_field_code_points,
            semantic_max_field_code_points=max_field_code_points,
        )
    except AppError:
        raise
    except (DefusedElementTree.ParseError, ValueError) as exc:
        msg = "The repository returned malformed OAI-PMH XML."
        raise _upstream_failure(msg, cause=exc) from exc


def _html_attribute_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        items = cast("list[object]", value)
        return " ".join(str(item) for item in items)
    return str(value)


def _html_field_code_point_counts(field: Tag) -> tuple[int, int]:
    counter = _CanonicalTextCounter()
    for current in field.descendants:
        if isinstance(current, NavigableString) and not isinstance(
            current, (Comment, Declaration, Doctype)
        ):
            counter.add(str(current))
    return counter.code_points, counter.semantic_code_points


def _validate_html_tree(  # noqa: C901, PLR0912, PLR0915 - bounded DOM recount
    soup: BeautifulSoup, *, source_url: str
) -> _MarkupCounts:
    elements = 0
    total_attributes = 0
    metadata_fields = 0
    records = 0
    max_field_code_points = 0
    semantic_max_field_code_points = 0
    text_counter = _CanonicalTextCounter()
    stack: list[tuple[object, int, str | None, bool]] = [(soup, 1, None, False)]
    while stack:
        current, depth, context, in_search_body = stack.pop()
        if not isinstance(current, Tag):
            if not isinstance(current, (Comment, Declaration, Doctype)):
                text_counter.add(str(current))
            continue
        if depth > PARSER_LIMITS.max_depth + 3:
            msg = "The repository response exceeded the tree depth limit."
            raise _upstream_failure(msg, source_url=source_url)
        elements = _saturating_increment(
            elements,
            1,
            maximum=PARSER_LIMITS.max_nodes + 3,
        )
        if elements > PARSER_LIMITS.max_nodes + 3:
            msg = "The repository response exceeded the HTML element limit."
            raise _upstream_failure(msg, source_url=source_url)
        attribute_count = len(current.attrs)
        if attribute_count > PARSER_LIMITS.max_attributes_per_node:
            msg = "The repository response exceeded the per-node attribute limit."
            raise _upstream_failure(msg, source_url=source_url)
        if attribute_count > PARSER_LIMITS.max_total_attributes - total_attributes:
            msg = "The repository response exceeded the aggregate attribute limit."
            raise _upstream_failure(msg, source_url=source_url)
        total_attributes = _saturating_increment(
            total_attributes,
            attribute_count,
            maximum=PARSER_LIMITS.max_total_attributes,
        )
        for key, value in current.attrs.items():
            text_counter.add(key)
            text_counter.add(_html_attribute_text(value))
        if current.name == "tr" and context == "metadata":
            metadata_fields = _saturating_increment(
                metadata_fields,
                1,
                maximum=PARSER_LIMITS.max_metadata_fields,
            )
        if current.name == "tr" and context == "search" and in_search_body:
            records = _saturating_increment(
                records,
                1,
                maximum=PARSER_LIMITS.max_records,
            )
        if current.name == "td":
            field_code_points, semantic_field_code_points = (
                _html_field_code_point_counts(current)
            )
            if field_code_points > PARSER_LIMITS.max_field_code_points:
                msg = "The repository response exceeded the field code-point limit."
                raise _upstream_failure(msg, source_url=source_url)
            max_field_code_points = max(max_field_code_points, field_code_points)
            semantic_max_field_code_points = max(
                semantic_max_field_code_points,
                semantic_field_code_points,
            )
        for child in reversed(current.contents):
            child_context = context
            if isinstance(child, Tag):
                if child.name == "table":
                    class_value = _html_attribute_text(child.get("class", ""))
                    if "search-results" in class_value:
                        child_context = "search"
                    elif "itemDisplayTable" in class_value:
                        child_context = "metadata"
                child_in_search_body = in_search_body or (
                    child_context == "search" and child.name == "tbody"
                )
            else:
                child_in_search_body = in_search_body
            stack.append((child, depth + 1, child_context, child_in_search_body))
    if text_counter.code_points > PARSER_LIMITS.max_total_text_code_points:
        msg = "The repository response exceeded the aggregate text limit."
        raise _upstream_failure(msg, source_url=source_url)
    return _MarkupCounts(
        nodes=elements,
        total_attributes=total_attributes,
        total_text_code_points=text_counter.code_points,
        semantic_total_text_code_points=text_counter.semantic_code_points,
        metadata_fields=metadata_fields,
        records=records,
        max_field_code_points=max_field_code_points,
        semantic_max_field_code_points=semantic_max_field_code_points,
    )


def _validate_xml_tree(root: Element) -> _MarkupCounts:
    elements = 0
    text_code_points = 0
    total_attributes = 0
    metadata_fields = 0
    records = 0
    max_field_code_points = 0
    stack: list[tuple[Element, int, str | None]] = [(root, 1, None)]
    while stack:
        current, depth, parent_name = stack.pop()
        name = _local_name(current.tag)
        if depth > PARSER_LIMITS.max_depth:
            msg = "The repository response exceeded the tree depth limit."
            raise _upstream_failure(msg)
        elements = _saturating_increment(
            elements,
            1,
            maximum=PARSER_LIMITS.max_nodes,
        )
        if elements > PARSER_LIMITS.max_nodes:
            msg = "The repository response exceeded the XML element limit."
            raise _upstream_failure(msg)
        attribute_count = len(current.attrib)
        if attribute_count > PARSER_LIMITS.max_attributes_per_node:
            msg = "The repository response exceeded the per-node attribute limit."
            raise _upstream_failure(msg)
        if attribute_count > PARSER_LIMITS.max_total_attributes - total_attributes:
            msg = "The repository response exceeded the aggregate attribute limit."
            raise _upstream_failure(msg)
        total_attributes = _saturating_increment(
            total_attributes,
            attribute_count,
            maximum=PARSER_LIMITS.max_total_attributes,
        )
        is_field = name == "field" or parent_name == "dc"
        if is_field:
            metadata_fields = _saturating_increment(
                metadata_fields,
                1,
                maximum=PARSER_LIMITS.max_metadata_fields,
            )
            max_field_code_points = max(
                max_field_code_points,
                len(current.text or ""),
            )
        if name == "record":
            records = _saturating_increment(
                records,
                1,
                maximum=PARSER_LIMITS.max_records,
            )
        text_code_points = _validate_text_budget(text_code_points, current.text)
        text_code_points = _validate_text_budget(text_code_points, current.tail)
        for key, value in current.attrib.items():
            text_code_points = _validate_text_budget(text_code_points, key)
            text_code_points = _validate_text_budget(text_code_points, value)
        stack.extend((child, depth + 1, name) for child in current)
    return _MarkupCounts(
        nodes=elements,
        total_attributes=total_attributes,
        total_text_code_points=text_code_points,
        semantic_total_text_code_points=text_code_points,
        metadata_fields=metadata_fields,
        records=records,
        max_field_code_points=max_field_code_points,
        semantic_max_field_code_points=max_field_code_points,
    )


def _require_preflight_agreement(
    preflight: _MarkupCounts,
    constructed: _MarkupCounts,
    *,
    compare_nodes: bool,
    source_url: str | None = None,
) -> None:
    matching = (
        preflight.total_attributes == constructed.total_attributes
        and preflight.total_text_code_points >= constructed.total_text_code_points
        and (
            preflight.semantic_total_text_code_points
            == constructed.semantic_total_text_code_points
        )
        and preflight.metadata_fields == constructed.metadata_fields
        and preflight.records == constructed.records
        and preflight.max_field_code_points >= constructed.max_field_code_points
        and (
            preflight.semantic_max_field_code_points
            == constructed.semantic_max_field_code_points
        )
        and (not compare_nodes or preflight.nodes == constructed.nodes)
    )
    if not matching:
        msg = "The repository parser detected a preflight disagreement."
        raise _upstream_failure(msg, source_url=source_url)


def _tag_text(tag: Tag | None) -> str:
    return _normalize(tag.get_text(" ", strip=True)) if tag is not None else ""


def _tag_attribute(tag: Tag, name: str, default: str = "") -> str:
    value: object = tag.get(name, default)
    return value if isinstance(value, str) else default


def _single_token_attribute(tag: Tag, name: str) -> str | None:
    """Return one exact HTML token from string or parser token-list storage."""
    raw: object = tag.get(name)
    if isinstance(raw, str):
        token = raw
    elif isinstance(raw, list):
        values = cast("list[object]", raw)
        if len(values) != 1 or not isinstance(values[0], str):
            return None
        token = values[0]
    else:
        return None
    if not token or token != token.strip() or len(token.split()) != 1:
        return None
    return token


def _class_contains(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return expected in value.split()
    if isinstance(value, list):
        return expected in value
    return False


def _has_search_results_class(value: object) -> bool:
    return _class_contains(value, "search-results")


def _has_jspui_results_panel_class(value: object) -> bool:
    return _class_contains(value, "panel") and _class_contains(value, "panel-info")


def _has_next_page_class(value: object) -> bool:
    return _class_contains(value, "next-page-link")


def _has_full_metadata_text(value: object) -> bool:
    return isinstance(value, str) and "full metadata record" in value.lower()


def _has_bitstream_href(value: object) -> bool:
    return isinstance(value, str) and "/bitstream/" in value


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


def _search_contract(soup: BeautifulSoup, *, source_url: str) -> _SearchContract:
    xmlui_containers = soup.find_all(
        id="aspect_discovery_SimpleSearch_div_search-results", limit=2
    )
    jspui_results = soup.find_all("div", class_="discovery-result-results", limit=2)
    jspui_pagination = soup.find_all(
        "div", class_="discovery-result-pagination", limit=2
    )
    jspui_tables = soup.find_all(
        "table",
        attrs={"summary": _JSPUI_SEARCH_TABLE_SUMMARY},
        limit=2,
    )
    has_xmlui_markers = bool(xmlui_containers)
    has_jspui_markers = bool(jspui_results or jspui_pagination or jspui_tables)
    if has_xmlui_markers and has_jspui_markers:
        msg = (
            "The repository search response had an invalid contract marker cardinality."
        )
        raise _upstream_failure(msg, source_url=source_url)

    if has_xmlui_markers:
        if len(xmlui_containers) != 1:
            msg = (
                "The repository search response had an invalid contract marker "
                "cardinality."
            )
            raise _upstream_failure(msg, source_url=source_url)
        container = xmlui_containers[0]
        table = container.find("table", class_=_has_search_results_class)
        if not isinstance(table, Tag):
            msg = "The repository search response did not contain a results table."
            raise _upstream_failure(msg, source_url=source_url)
        return _SearchContract(container=container, table=table, variant="xmlui")

    if len(jspui_results) != 1 or len(jspui_pagination) != 1 or len(jspui_tables) != 1:
        msg = (
            "The repository search response had an invalid contract marker cardinality."
        )
        raise _upstream_failure(msg, source_url=source_url)
    results = jspui_results[0]
    pagination = jspui_pagination[0]
    table = results.find(
        "table",
        attrs={"summary": _JSPUI_SEARCH_TABLE_SUMMARY},
        recursive=False,
    )
    if table is None:
        panels = results.find_all(
            "div",
            class_=_has_jspui_results_panel_class,
            recursive=False,
            limit=2,
        )
        if len(panels) == 1:
            table = panels[0].find(
                "table",
                attrs={"summary": _JSPUI_SEARCH_TABLE_SUMMARY},
                recursive=False,
            )
    if table is not jspui_tables[0] or results.parent is not pagination.parent:
        msg = (
            "The repository search response had an invalid contract marker cardinality."
        )
        raise _upstream_failure(msg, source_url=source_url)
    return _SearchContract(
        container=pagination,
        table=jspui_tables[0],
        variant="jspui",
    )


def _is_recognized_search_column(
    text: str,
    *,
    kind: Literal["title", "date", "author"],
    variant: Literal["xmlui", "jspui"],
) -> bool:
    """Match one exact reviewed XMLUI/JSPUI search-column label."""
    if variant == "jspui":
        return (
            text
            in {
                "title": {"title", "სათაური"},
                "date": {"issue date", "გამოცემის თარიღი"},
                "author": {"author(s)", "ავტორი / ავტორები"},
            }[kind]
        )
    if kind == "title":
        return text in {"title", "სათაური"}
    if kind == "date":
        return "date" in text or "თარიღ" in text
    return "author" in text or "ავტორ" in text


def _search_column_index(
    header_cells: list[str],
    *,
    source_url: str,
    kind: Literal["title", "date", "author"],
    variant: Literal["xmlui", "jspui"],
    required: bool = False,
) -> int | None:
    """Resolve one recognized column without first-match ambiguity."""
    matches = [
        index
        for index, text in enumerate(header_cells)
        if _is_recognized_search_column(text, kind=kind, variant=variant)
    ]
    if len(matches) > 1 or (required and len(matches) != 1):
        msg = f"The repository search table had invalid {kind} column cardinality."
        raise _upstream_failure(msg, source_url=source_url)
    return matches[0] if matches else None


def _search_columns(
    table: Tag,
    *,
    source_url: str,
    variant: Literal["xmlui", "jspui"],
) -> _SearchColumns:
    if variant == "xmlui":
        header_tags: list[Tag] = list(table.select("thead th"))
        header_ids: tuple[str, ...] = ()
    else:
        rows = table.find_all("tr", recursive=False, limit=1)
        header_tags = rows[0].find_all("th", recursive=False) if rows else []
        header_values = tuple(
            _single_token_attribute(cell, "id") for cell in header_tags
        )
        if any(value is None for value in header_values):
            msg = "The repository search table had invalid header bindings."
            raise _upstream_failure(msg, source_url=source_url)
        header_ids = cast("tuple[str, ...]", header_values)
        if len(set(header_ids)) != len(header_ids):
            msg = "The repository search table had invalid header bindings."
            raise _upstream_failure(msg, source_url=source_url)
    header_cells = [_tag_text(cell).lower() for cell in header_tags]
    title_index = _search_column_index(
        header_cells,
        source_url=source_url,
        kind="title",
        variant=variant,
        required=True,
    )
    if title_index is None:
        msg = "The repository search table did not contain a title column."
        raise _upstream_failure(msg, source_url=source_url)
    return _SearchColumns(
        title=title_index,
        date=_search_column_index(
            header_cells,
            source_url=source_url,
            kind="date",
            variant=variant,
            required=variant == "jspui",
        ),
        author=_search_column_index(
            header_cells,
            source_url=source_url,
            kind="author",
            variant=variant,
            required=variant == "jspui",
        ),
        cell_count=len(header_cells),
        header_ids=header_ids,
    )


def _search_items(
    table: Tag,
    *,
    columns: _SearchColumns,
    source_url: str,
    maximum_items: int,
    variant: Literal["xmlui", "jspui"],
) -> tuple[SearchItem, ...]:
    items: list[SearchItem] = []
    seen_handles: set[str] = set()
    rows = (
        table.select("tbody tr")
        if variant == "xmlui"
        else table.find_all("tr", recursive=False)[1:]
    )
    if len(rows) > maximum_items:
        msg = "The repository search response exceeded the search item limit."
        raise _upstream_failure(msg, source_url=source_url)
    for row in rows:
        parsed_row = _search_row_cells_and_link(
            row,
            columns=columns,
            source_url=source_url,
            variant=variant,
        )
        if parsed_row is None:
            continue
        cells, link = parsed_row
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
        if variant == "jspui" and handle in seen_handles:
            msg = "The repository returned a duplicate search item."
            raise _upstream_failure(msg, source_url=source_url)
        seen_handles.add(handle)
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


def _search_row_cells_and_link(
    row: Tag,
    *,
    columns: _SearchColumns,
    source_url: str,
    variant: Literal["xmlui", "jspui"],
) -> tuple[list[Tag], Tag] | None:
    """Return one strict JSPUI row or one optional legacy XMLUI row."""
    cells = row.find_all("td", recursive=False)
    malformed = columns.title >= len(cells) or (
        variant == "jspui" and len(cells) != columns.cell_count
    )
    if malformed:
        if variant == "jspui":
            msg = "The repository returned a malformed search row."
            raise _upstream_failure(msg, source_url=source_url)
        return None
    if variant == "jspui" and any(
        _single_token_attribute(cell, "headers") != expected
        for cell, expected in zip(cells, columns.header_ids, strict=True)
    ):
        msg = "The repository returned a malformed search row."
        raise _upstream_failure(msg, source_url=source_url)
    links = cells[columns.title].find_all("a", href=True, limit=2)
    if len(links) > 1:
        msg = "The repository search row had invalid item link cardinality."
        raise _upstream_failure(msg, source_url=source_url)
    if not links:
        if variant == "jspui":
            msg = "The repository returned a malformed search row."
            raise _upstream_failure(msg, source_url=source_url)
        return None
    return cells, links[0]


def _search_total(
    container: Tag,
    *,
    item_count: int,
    current_offset: int,
    source_url: str,
    variant: Literal["xmlui", "jspui"],
) -> int:
    minimum_total = current_offset + item_count
    context_text = _tag_text(container)
    if variant == "xmlui":
        total_match = _TOTAL_RE.search(context_text)
        if total_match is None:
            return minimum_total
        raw_total = _match_group(total_match, 1)
    else:
        range_matches = [
            match
            for pattern in (_JSPUI_RANGE_RE, _JSPUI_ENGLISH_RANGE_RE)
            for match in pattern.finditer(context_text)
        ]
        if len(range_matches) != 1:
            msg = (
                "The repository search response had an invalid range marker "
                "cardinality."
            )
            raise _upstream_failure(msg, source_url=source_url)
        range_match = range_matches[0]
        displayed_first = _bounded_search_integer(
            _match_group(range_match, 1),
            maximum=MAX_SAFE_INTEGER,
            context="search range",
            source_url=source_url,
        )
        displayed_end = _bounded_search_integer(
            _match_group(range_match, 2),
            maximum=MAX_SAFE_INTEGER,
            context="search range",
            source_url=source_url,
        )
        if (
            displayed_first != current_offset + 1
            or displayed_end < displayed_first
            or item_count != displayed_end - displayed_first + 1
        ):
            msg = "The repository returned an invalid search range."
            raise _upstream_failure(msg, source_url=source_url)
        raw_total = _match_group(range_match, 3)
    total = _bounded_search_integer(
        raw_total,
        maximum=MAX_SAFE_INTEGER,
        context="search total",
        source_url=source_url,
    )
    if total < max(item_count, minimum_total):
        msg = "The repository returned an invalid search total."
        raise _upstream_failure(msg, source_url=source_url)
    return total


def _bounded_search_integer(
    raw_value: str,
    *,
    maximum: int,
    context: str,
    source_url: str,
) -> int:
    """Parse one untrusted bounded ASCII integer into an upstream value."""
    if _SEARCH_INTEGER_RE.fullmatch(raw_value) is None:
        msg = f"The repository returned an invalid {context}."
        raise _upstream_failure(msg, source_url=source_url)
    normalized = raw_value.replace(",", "")
    if (
        not normalized
        or not normalized.isascii()
        or not normalized.isdigit()
        or len(normalized) > len(str(maximum))
    ):
        msg = f"The repository returned an invalid {context}."
        raise _upstream_failure(msg, source_url=source_url)
    parsed = int(normalized)
    if parsed > maximum:
        msg = f"The repository returned an invalid {context}."
        raise _upstream_failure(msg, source_url=source_url)
    return parsed


def _current_search_offset(*, source_url: str) -> int:
    """Extract one bounded current offset from the final upstream URL."""
    raw_offsets = parse_qs(
        urlsplit(source_url).query,
        keep_blank_values=True,
    ).get("start", [])
    if not raw_offsets:
        return 0
    if len(raw_offsets) != 1:
        msg = "The repository returned an invalid pagination offset."
        raise _upstream_failure(msg, source_url=source_url)
    return _bounded_search_integer(
        raw_offsets[0],
        maximum=MAX_CURSOR_OFFSET,
        context="pagination offset",
        source_url=source_url,
    )


def _next_search_offset(
    container: Tag,
    *,
    source_url: str,
    current_offset: int,
    maximum_total: int | None,
) -> int | None:
    candidates = [
        link
        for link in container.find_all("a", href=True)
        if _has_next_page_class(link.get("class"))
        or _tag_text(link).lower() in {"next", "next page", ">", "მომდევნო"}
    ]
    if len(candidates) > 1:
        msg = "The repository search response had invalid pagination link cardinality."
        raise _upstream_failure(msg, source_url=source_url)
    if not candidates:
        return None
    next_link = candidates[0]
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
    raw_offsets = parse_qs(
        urlsplit(absolute).query,
        keep_blank_values=True,
    ).get("start", [])
    if not raw_offsets:
        msg = "The repository returned an invalid pagination offset."
        raise _upstream_failure(msg, source_url=source_url)
    if len(raw_offsets) != 1:
        msg = "The repository returned an invalid pagination offset."
        raise _upstream_failure(msg, source_url=source_url)
    parsed_offset = _bounded_search_integer(
        raw_offsets[0],
        maximum=MAX_CURSOR_OFFSET,
        context="pagination offset",
        source_url=source_url,
    )
    if parsed_offset <= current_offset or (
        maximum_total is not None and parsed_offset >= maximum_total
    ):
        msg = "The repository returned an invalid pagination offset."
        raise _upstream_failure(msg, source_url=source_url)
    return parsed_offset


def parse_search_version(html: str, *, source_url: str) -> str:
    """Extract one bounded NPLG search-version marker from public HTML."""
    preflight = _preflight_html(html, source_url=source_url)
    soup = BeautifulSoup(html, "lxml")
    constructed = _validate_html_tree(soup, source_url=source_url)
    _require_preflight_agreement(
        preflight,
        constructed,
        compare_nodes=False,
        source_url=source_url,
    )
    heads = soup.find_all("head")
    if len(heads) != 1:
        msg = "The repository returned an invalid search-version marker."
        raise _upstream_failure(msg, source_url=source_url)
    markers = [
        tag
        for tag in heads[0].find_all("meta", recursive=False)
        if _tag_attribute(tag, "name") == "sourcefv"
    ]
    if len(markers) != 1:
        msg = "The repository returned an invalid search-version marker."
        raise _upstream_failure(msg, source_url=source_url)
    marker = _tag_attribute(markers[0], "content")
    if _SEARCH_VERSION_RE.fullmatch(marker) is None:
        msg = "The repository returned an invalid search-version marker."
        raise _upstream_failure(msg, source_url=source_url)
    return marker


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
    preflight = _preflight_html(html, source_url=source_url)
    soup = BeautifulSoup(html, "lxml")
    constructed = _validate_html_tree(soup, source_url=source_url)
    _require_preflight_agreement(
        preflight,
        constructed,
        compare_nodes=False,
        source_url=source_url,
    )
    contract = _search_contract(soup, source_url=source_url)
    columns = _search_columns(
        contract.table,
        source_url=source_url,
        variant=contract.variant,
    )
    items = _search_items(
        contract.table,
        columns=columns,
        source_url=source_url,
        maximum_items=page_size,
        variant=contract.variant,
    )
    current_offset = _current_search_offset(source_url=source_url)
    total = _search_total(
        contract.container,
        item_count=len(items),
        current_offset=current_offset,
        source_url=source_url,
        variant=contract.variant,
    )
    next_offset = _next_search_offset(
        contract.container,
        source_url=source_url,
        current_offset=current_offset,
        maximum_total=total if contract.variant == "jspui" else None,
    )
    if contract.variant == "jspui":
        expected_next = current_offset + len(items)
        if (expected_next < total and next_offset != expected_next) or (
            expected_next >= total and next_offset is not None
        ):
            msg = "The repository returned an invalid pagination offset."
            raise _upstream_failure(msg, source_url=source_url)

    return SearchPage(
        items=items,
        total=total,
        next_offset=next_offset,
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
    links: tuple[Tag, ...], *, handle: str, source_url: str, restricted: bool
) -> tuple[Bitstream, ...]:
    if restricted:
        return ()
    result: list[Bitstream] = []
    seen_urls: set[str] = set()
    for link in links:
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


def _extract_handle(container: Tag) -> str | None:
    for code in container.find_all("code"):
        text = _tag_text(code)
        try:
            return parse_handle_input(text)
        except AppError:
            continue
    for link in container.find_all("a", href=True):
        href = _tag_attribute(link, "href")
        if "/handle/" not in href:
            continue
        try:
            return parse_handle_input(urljoin(NPLG_ORIGIN, href))
        except AppError:
            continue
    return None


def _item_container(
    soup: BeautifulSoup, *, source_url: str
) -> tuple[Tag, Literal["xmlui", "jspui"], Tag | None]:
    """Resolve one legacy XMLUI or current JSPUI item-content container."""
    xmlui = soup.find_all(
        id="aspect_artifactbrowser_ItemViewer_div_item-view",
        limit=2,
    )
    jspui: list[tuple[Tag, Tag]] = []
    for main in soup.find_all("main", id="content", attrs={"role": "main"}):
        for container in main.find_all("div", class_="container", recursive=False):
            wells = container.find_all(
                "div",
                class_="well",
                recursive=False,
                limit=2,
            )
            if not wells:
                continue
            if len(wells) != 1:
                msg = "The item response had an invalid contract marker cardinality."
                raise _upstream_failure(msg, source_url=source_url)
            well = wells[0]
            codes = well.find_all("code", recursive=False, limit=2)
            if len(codes) != 1 or not _tag_text(well).startswith(
                _JSPUI_IDENTIFIER_LEAD_IN
            ):
                msg = "The item response had an invalid contract marker cardinality."
                raise _upstream_failure(msg, source_url=source_url)
            jspui.append((container, codes[0]))

    if len(xmlui) == 1 and not jspui:
        return xmlui[0], "xmlui", None
    if not xmlui and len(jspui) == 1:
        container, identity = jspui[0]
        return container, "jspui", identity
    msg = "The item response had an invalid contract marker cardinality."
    raise _upstream_failure(msg, source_url=source_url)


type _MetadataRow = tuple[Tag, tuple[Tag, ...]]


def _metadata_rows(container: Tag) -> tuple[_MetadataRow, ...]:
    """Select metadata rows once and retain their direct data cells."""
    rows: list[_MetadataRow] = []
    seen: set[int] = set()
    for table in container.find_all("table", class_="itemDisplayTable"):
        for row in table.find_all("tr"):
            identity = id(row)
            if identity in seen:
                continue
            seen.add(identity)
            cells = tuple(
                child
                for child in row.children
                if isinstance(child, Tag) and child.name == "td"
            )
            rows.append((row, cells))
    return tuple(rows)


def _summary_fields(rows: tuple[_MetadataRow, ...]) -> tuple[RawMetadataField, ...]:
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
    for _, cells in rows:
        if len(cells) < _MIN_METADATA_CELLS:
            continue
        label = _tag_text(cells[0]).rstrip(":").strip().lower()
        key = mapping.get(label)
        if key is None:
            continue
        value = _tag_text(cells[1])
        if value:
            if len(fields) >= PARSER_LIMITS.max_metadata_fields:
                msg = "The item response exceeded the metadata field limit."
                raise _upstream_failure(msg)
            fields.append(RawMetadataField(key=key, value=value))
    return tuple(fields)


def _full_fields(rows: tuple[_MetadataRow, ...]) -> tuple[RawMetadataField, ...]:
    fields: list[RawMetadataField] = []
    for _, cells in rows:
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
        if len(fields) >= PARSER_LIMITS.max_metadata_fields:
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


def _collections(
    container: Tag,
    rows: tuple[_MetadataRow, ...],
) -> tuple[str, ...]:
    values: list[str] = []
    for _, cells in rows:
        if (
            len(cells) >= _MIN_METADATA_CELLS
            and _tag_text(cells[0]).rstrip(":").lower() == "appears in collections"
        ):
            links = [_tag_text(link) for link in cells[1].find_all("a")]
            values.extend(links or [_tag_text(cells[1])])
    if not values:
        for paragraph in container.find_all(["p", "div"]):
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
    preflight = _preflight_html(html, source_url=source_url)
    soup = BeautifulSoup(html, "lxml")
    constructed = _validate_html_tree(soup, source_url=source_url)
    _require_preflight_agreement(
        preflight,
        constructed,
        compare_nodes=False,
        source_url=source_url,
    )
    container, variant, jspui_identity = _item_container(
        soup,
        source_url=source_url,
    )
    if jspui_identity is None:
        actual = _extract_handle(container)
    else:
        try:
            actual = parse_handle_input(_tag_text(jspui_identity))
        except AppError:
            actual = None
    if actual is None or actual != expected:
        msg = "The item response did not match the requested handle."
        raise _upstream_failure(
            msg,
            source_url=source_url,
        )

    page_text = _tag_text(container).lower()
    matching_restrictions = [
        marker for marker in _RESTRICTED_MARKERS if marker in page_text
    ]
    restricted = bool(matching_restrictions)
    bitstream_links = tuple(container.find_all("a", href=_has_bitstream_href))
    if restricted and bitstream_links:
        msg = "The item response contained ambiguous access markers."
        raise _upstream_failure(msg, source_url=source_url)
    restriction_reason = (
        "Access is limited to the library's internal network or building."
        if restricted
        else None
    )

    metadata_rows = _metadata_rows(container)
    is_full = any(
        cells
        and next(
            (child for child in row.children if isinstance(child, Tag)),
            None,
        )
        is cells[0]
        and _DC_KEY_RE.fullmatch(_tag_text(cells[0])) is not None
        for row, cells in metadata_rows
    ) or bool(container.find(string=_has_full_metadata_text))
    fields = _full_fields(metadata_rows) if is_full else _summary_fields(metadata_rows)
    if not fields:
        msg = "The item response did not contain recognizable metadata."
        raise _upstream_failure(
            msg,
            source_url=source_url,
        )

    collections = _collections(container, metadata_rows)
    bitstreams = _parse_bitstreams(
        bitstream_links,
        handle=expected,
        source_url=source_url,
        restricted=restricted,
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
            metadata_source=f"{variant}_{'full' if is_full else 'summary'}",
            fallback_title=fallback_title,
        ),
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml(xml: str) -> Element:
    preflight = _preflight_xml(xml)
    try:
        root = DefusedElementTree.fromstring(
            xml,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DefusedElementTree.ParseError, ValueError) as exc:
        msg = "The repository returned malformed OAI-PMH XML."
        raise _upstream_failure(msg, cause=exc) from exc
    constructed = _validate_xml_tree(root)
    _require_preflight_agreement(preflight, constructed, compare_nodes=True)
    return root


def _first_descendant(root: Element, name: str) -> Element | None:
    return next(
        (element for element in root.iter() if _local_name(element.tag) == name), None
    )


def _require_exact_owned_child(
    scope: Element,
    owner: Element,
    name: str,
    *,
    required_tag: str | None = None,
) -> Element:
    direct = (
        [child for child in owner if child.tag == required_tag]
        if required_tag is not None
        else [child for child in owner if _local_name(child.tag) == name]
    )
    matches = [element for element in scope.iter() if _local_name(element.tag) == name]
    if len(direct) != 1 or len(matches) != 1 or direct[0] is not matches[0]:
        msg = "The OAI-PMH response had invalid contract marker structural ownership."
        raise _upstream_failure(msg)
    return direct[0]


def parse_metadata_formats(xml: str) -> tuple[str, ...]:
    """Parse supported metadata prefixes from an OAI-PMH response."""
    root = _parse_xml(xml)
    if root.tag != _OAI_ROOT_TAG:
        msg = "The OAI-PMH response had invalid contract marker structural ownership."
        raise _upstream_failure(msg)
    error = _first_descendant(root, "error")
    if error is not None:
        msg = "The repository rejected the OAI-PMH metadata format request."
        raise _upstream_failure(msg)
    direct_containers = [
        child for child in root if child.tag == _OAI_LIST_METADATA_FORMATS_TAG
    ]
    all_containers = [
        element
        for element in root.iter()
        if _local_name(element.tag) == "ListMetadataFormats"
    ]
    if (
        len(direct_containers) != 1
        or len(all_containers) != 1
        or direct_containers[0] is not all_containers[0]
    ):
        msg = "The OAI-PMH response had invalid contract marker structural ownership."
        raise _upstream_failure(msg)
    container = direct_containers[0]
    metadata_formats = [
        child for child in container if child.tag == _OAI_METADATA_FORMAT_TAG
    ]
    all_metadata_formats = [
        element
        for element in root.iter()
        if _local_name(element.tag) == "metadataFormat"
    ]
    if len(metadata_formats) != len(all_metadata_formats) or any(
        direct is not discovered
        for direct, discovered in zip(
            metadata_formats,
            all_metadata_formats,
            strict=True,
        )
    ):
        msg = "The OAI-PMH response had invalid contract marker structural ownership."
        raise _upstream_failure(msg)
    prefixes: list[str | None] = []
    prefix_elements: list[Element] = []
    for metadata_format in metadata_formats:
        direct_prefixes = [
            child for child in metadata_format if child.tag == _OAI_METADATA_PREFIX_TAG
        ]
        if len(direct_prefixes) != 1:
            msg = (
                "The OAI-PMH response had invalid contract marker structural ownership."
            )
            raise _upstream_failure(msg)
        prefix = direct_prefixes[0]
        prefix_elements.append(prefix)
        prefixes.append(prefix.text)
    all_prefix_elements = [
        element
        for element in root.iter()
        if _local_name(element.tag) == "metadataPrefix"
    ]
    if len(prefix_elements) != len(all_prefix_elements) or any(
        direct is not discovered
        for direct, discovered in zip(
            prefix_elements,
            all_prefix_elements,
            strict=True,
        )
    ):
        msg = "The OAI-PMH response had invalid contract marker structural ownership."
        raise _upstream_failure(msg)
    formats = _unique(prefixes)
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


def _validate_oai_identifier(identifier_element: Element, *, expected: str) -> None:
    if not identifier_element.text:
        msg = "The OAI-PMH record did not contain an identifier."
        raise _upstream_failure(msg)
    identifier_text = _normalize(identifier_element.text)
    if identifier_text != f"oai:{NPLG_HOST}:{expected}":
        msg = "The OAI-PMH record did not match the requested handle."
        raise _upstream_failure(msg)


def _dim_fields(
    record: Element,
    metadata: Element,
) -> tuple[RawMetadataField, ...]:
    container = _require_exact_owned_child(record, metadata, "dim")
    if len(metadata) != 1:
        msg = "The OAI-PMH response had invalid DIM metadata ownership."
        raise _upstream_failure(msg)
    approved = [child for child in container if _local_name(child.tag) == "field"]
    discovered = [
        element for element in record.iter() if _local_name(element.tag) == "field"
    ]
    if len(approved) != len(container) or approved != discovered:
        msg = "The OAI-PMH response had invalid DIM field ownership."
        raise _upstream_failure(msg)
    fields: list[RawMetadataField] = []
    for element in approved:
        schema = element.attrib.get("mdschema", "dc")
        field_element = element.attrib.get("element")
        if not field_element:
            continue
        qualifier = element.attrib.get("qualifier")
        key = f"{schema}.{field_element}" + (f".{qualifier}" if qualifier else "")
        value = _normalize(element.text or "")
        if value:
            if len(fields) >= PARSER_LIMITS.max_metadata_fields:
                msg = "The OAI-PMH record exceeded the metadata field limit."
                raise _upstream_failure(msg)
            fields.append(
                RawMetadataField(
                    key=key, value=value, language=element.attrib.get("lang")
                )
            )
    return tuple(fields)


def _dc_fields(record: Element, metadata: Element) -> tuple[RawMetadataField, ...]:
    container = _require_exact_owned_child(record, metadata, "dc")
    if len(metadata) != 1 or any(len(element) != 0 for element in container):
        msg = "The OAI-PMH response had invalid Dublin Core field ownership."
        raise _upstream_failure(msg)
    fields: list[RawMetadataField] = []
    for element in container:
        name = _local_name(element.tag)
        value = _normalize(element.text or "")
        if value:
            if len(fields) >= PARSER_LIMITS.max_metadata_fields:
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
    record: Element,
    metadata: Element,
    *,
    metadata_prefix: str,
) -> tuple[tuple[RawMetadataField, ...], str]:
    prefix = metadata_prefix.strip()
    if prefix == "dim":
        return _dim_fields(record, metadata), "oai_dim"
    if prefix == "oai_dc":
        return _dc_fields(record, metadata), "oai_dc"
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
    if root.tag != _OAI_ROOT_TAG:
        msg = "The OAI-PMH response had an invalid root element."
        raise _upstream_failure(msg)
    get_record = _require_exact_owned_child(
        root,
        root,
        "GetRecord",
        required_tag=f"{{{_OAI_NAMESPACE}}}GetRecord",
    )
    record = _require_exact_owned_child(
        root,
        get_record,
        "record",
        required_tag=f"{{{_OAI_NAMESPACE}}}record",
    )
    header = _require_exact_owned_child(
        record,
        record,
        "header",
        required_tag=f"{{{_OAI_NAMESPACE}}}header",
    )
    metadata = _require_exact_owned_child(
        record,
        record,
        "metadata",
        required_tag=f"{{{_OAI_NAMESPACE}}}metadata",
    )
    identifier = _require_exact_owned_child(
        record,
        header,
        "identifier",
        required_tag=f"{{{_OAI_NAMESPACE}}}identifier",
    )
    if any(
        child.tag
        not in {
            f"{{{_OAI_NAMESPACE}}}header",
            f"{{{_OAI_NAMESPACE}}}metadata",
            f"{{{_OAI_NAMESPACE}}}about",
        }
        for child in record
    ) or any(
        child.tag
        not in {
            f"{{{_OAI_NAMESPACE}}}identifier",
            f"{{{_OAI_NAMESPACE}}}datestamp",
            f"{{{_OAI_NAMESPACE}}}setSpec",
        }
        for child in header
    ):
        msg = "The OAI-PMH response had invalid record child ownership."
        raise _upstream_failure(msg)
    _validate_oai_identifier(identifier, expected=expected)
    fields, source = _oai_fields(
        record,
        metadata,
        metadata_prefix=metadata_prefix,
    )

    if not fields:
        msg = "The OAI-PMH record did not contain usable metadata fields."
        raise _upstream_failure(msg)
    return _record_from_fields(
        handle=expected,
        fields=fields,
        context=_RecordContext(metadata_source=source),
    )
