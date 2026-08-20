# Copyright (c) 2026 David Osipov
"""Bounded properties for the public repository parser seams."""

from __future__ import annotations

import html
import unicodedata
from typing import TYPE_CHECKING, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parsers import parse_metadata_formats, parse_search_results

if TYPE_CHECKING:
    from collections.abc import Callable

    from hypothesis.strategies import SearchStrategy

_SEARCH_SOURCE = "https://dspace.nplg.gov.ge/simple-search?query=property"
_DISPLAY_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ"
    "\u0301"
)
_MAX_GENERATED_ROWS = 16


def _join_display_parts(parts: list[str]) -> str:
    return " \t\n ".join(parts)


def _decorate_prefix(prefix: str) -> str:
    return f" \n{prefix}\t "


def _normalize_display(value: str) -> str:
    return unicodedata.normalize("NFC", " ".join(value.split())).strip()


def _normalized_unique(values: list[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        normalized = _normalize_display(value)
        if normalized and normalized != "-" and normalized not in result:
            result.append(normalized)
    return tuple(result)


def _search_document(*, rows: str) -> str:
    return (
        '<div id="aspect_discovery_SimpleSearch_div_search-results">'
        '<table class="search-results"><thead><tr>'
        "<th>Title</th><th>Author</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _search_row(*, handle: str, title: str, authors: list[str]) -> str:
    author_cell = " ; ".join(html.escape(value) for value in authors)
    return (
        f'<tr><td><a href="/handle/{handle}">{html.escape(title)}</a></td>'
        f"<td>{author_cell}</td></tr>"
    )


def _metadata_format_entry(prefix: str) -> str:
    return "".join(
        (
            "<metadataFormat><metadataPrefix>",
            html.escape(prefix),
            "</metadataPrefix></metadataFormat>",
        )
    )


def _metadata_formats_document(prefixes: list[str]) -> str:
    entries = "".join(_metadata_format_entry(prefix) for prefix in prefixes)
    return f"<OAI-PMH><ListMetadataFormats>{entries}</ListMetadataFormats></OAI-PMH>"


_DISPLAY_PART_STRATEGY: SearchStrategy[str] = st.text(
    alphabet=_DISPLAY_ALPHABET,
    min_size=1,
    max_size=12,
)
_DISPLAY_TEXT_STRATEGY: SearchStrategy[str] = st.lists(
    _DISPLAY_PART_STRATEGY,
    min_size=1,
    max_size=4,
).map(_join_display_parts)
_AUTHORS_STRATEGY: SearchStrategy[list[str]] = st.lists(
    _DISPLAY_TEXT_STRATEGY,
    max_size=5,
)
_HANDLE_PART_STRATEGY: SearchStrategy[int] = st.integers(
    min_value=1,
    max_value=999_999,
)
_ROW_COUNT_STRATEGY: SearchStrategy[int] = st.integers(
    min_value=0,
    max_value=_MAX_GENERATED_ROWS,
)
_PREFIX_STRATEGY: SearchStrategy[str] = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz_",
    min_size=1,
    max_size=16,
).map(_decorate_prefix)
_PREFIXES_STRATEGY: SearchStrategy[list[str]] = st.lists(
    _PREFIX_STRATEGY,
    min_size=1,
    max_size=12,
)
_UNTRUSTED_TEXT_STRATEGY: SearchStrategy[str] = st.text(max_size=256)
_XML_TAG_STRATEGY: SearchStrategy[str] = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz",
    min_size=1,
    max_size=12,
)

_GIVEN_SEARCH_RECORD = cast(
    "Callable[[Callable[[str, list[str], int, int], None]], Callable[[], None]]",
    given(
        title=_DISPLAY_TEXT_STRATEGY,
        authors=_AUTHORS_STRATEGY,
        owner=_HANDLE_PART_STRATEGY,
        item=_HANDLE_PART_STRATEGY,
    ),
)


@_GIVEN_SEARCH_RECORD
def test_search_parser_is_deterministic_and_normalizes_display_values(
    title: str,
    authors: list[str],
    owner: int,
    item: int,
) -> None:
    handle = f"{owner}/{item}"
    document = _search_document(
        rows=_search_row(handle=handle, title=title, authors=authors)
    )

    first = parse_search_results(document, source_url=_SEARCH_SOURCE)
    second = parse_search_results(document, source_url=_SEARCH_SOURCE)

    assert first == second
    assert len(first.items) == 1
    parsed = first.items[0]
    assert parsed.handle == handle
    assert parsed.title == _normalize_display(title)
    assert parsed.authors == _normalized_unique(authors)
    assert unicodedata.is_normalized("NFC", parsed.title)
    assert all(unicodedata.is_normalized("NFC", author) for author in parsed.authors)


_GIVEN_ROW_COUNT = cast(
    "Callable[[Callable[[int], None]], Callable[[], None]]",
    given(row_count=_ROW_COUNT_STRATEGY),
)

_GIVEN_ROW_COUNT_AND_PAGE_SIZE = cast(
    "Callable[[Callable[[int, int], None]], Callable[[], None]]",
    given(
        row_count=_ROW_COUNT_STRATEGY,
        page_size=st.integers(min_value=1, max_value=_MAX_GENERATED_ROWS),
    ),
)


@_GIVEN_ROW_COUNT
def test_search_result_cardinality_is_bounded_by_generated_rows(
    row_count: int,
) -> None:
    rows = "".join(
        _search_row(handle=f"1234/{index + 1}", title="Title", authors=[])
        for index in range(row_count)
    )

    page = parse_search_results(
        _search_document(rows=rows),
        source_url=_SEARCH_SOURCE,
    )

    assert len(page.items) == row_count
    assert page.total == row_count
    assert len(page.items) <= _MAX_GENERATED_ROWS


@_GIVEN_ROW_COUNT_AND_PAGE_SIZE
def test_search_result_cardinality_never_exceeds_requested_page_size(
    row_count: int,
    page_size: int,
) -> None:
    rows = "".join(
        _search_row(handle=f"1234/{index + 1}", title="Title", authors=[])
        for index in range(row_count)
    )
    document = _search_document(rows=rows)

    if row_count > page_size:
        with pytest.raises(AppError) as captured:
            _ = parse_search_results(
                document,
                source_url=_SEARCH_SOURCE,
                page_size=page_size,
            )
        assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
        return

    page = parse_search_results(
        document,
        source_url=_SEARCH_SOURCE,
        page_size=page_size,
    )
    assert len(page.items) == row_count


_GIVEN_PREFIXES = cast(
    "Callable[[Callable[[list[str]], None]], Callable[[], None]]",
    given(prefixes=_PREFIXES_STRATEGY),
)


@_GIVEN_PREFIXES
def test_metadata_formats_are_deterministic_normalized_and_cardinality_bounded(
    prefixes: list[str],
) -> None:
    document = _metadata_formats_document(prefixes)

    first = parse_metadata_formats(document)
    second = parse_metadata_formats(document)

    assert first == second
    assert first == _normalized_unique(prefixes)
    assert len(first) <= len(prefixes)


_GIVEN_UNTRUSTED_HTML = cast(
    "Callable[[Callable[[str], None]], Callable[[], None]]",
    given(payload=_UNTRUSTED_TEXT_STRATEGY),
)


@_GIVEN_UNTRUSTED_HTML
def test_search_parser_fails_closed_without_the_contract_marker(payload: str) -> None:
    document = f"<html><body>{html.escape(payload)}</body></html>"

    with pytest.raises(AppError) as captured:
        _ = parse_search_results(document, source_url=_SEARCH_SOURCE)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE


_GIVEN_MALFORMED_XML = cast(
    "Callable[[Callable[[str, str], None]], Callable[[], None]]",
    given(tag=_XML_TAG_STRATEGY, payload=_UNTRUSTED_TEXT_STRATEGY),
)


@_GIVEN_MALFORMED_XML
def test_metadata_parser_fails_closed_for_bounded_malformed_xml(
    tag: str,
    payload: str,
) -> None:
    document = f"<root><{tag}>{html.escape(payload)}</root>"

    with pytest.raises(AppError) as captured:
        _ = parse_metadata_formats(document)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
