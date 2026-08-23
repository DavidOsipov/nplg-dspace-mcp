# Copyright (c) 2026 David Osipov
"""Bounded properties for the public repository parser seams."""

from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from nplg_mcp import parsers as parser_module
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.json_types import load_json_value, require_json_object
from nplg_mcp.parsers import (
    parse_item_page,
    parse_metadata_formats,
    parse_oai_record,
    parse_search_results,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from hypothesis.strategies import SearchStrategy

    type _BehavioralLimitDecorator = Callable[
        [Callable[[str, str, int, pytest.MonkeyPatch], None]],
        Callable[[], None],
    ]


_SEARCH_SOURCE = "https://dspace.nplg.gov.ge/simple-search?query=property"
_ITEM_HANDLE = "1234/499564"
_ITEM_SOURCE = f"https://dspace.nplg.gov.ge/handle/{_ITEM_HANDLE}"
_DISPLAY_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ"
    "\u0301"
)
_MAX_GENERATED_ROWS = 16
_PARSER_LIMIT_DEFAULTS = {
    "markup_bytes": 2_097_152,
    "max_depth": 64,
    "max_nodes": 50_000,
    "max_attributes_per_node": 64,
    "max_total_attributes": 100_000,
    "max_field_code_points": 65_536,
    "max_total_text_code_points": 1_048_576,
    "max_metadata_fields": 2_048,
    "max_records": 1_000,
    "parse_deadline_ms": 2_000,
}
_MAX_PARSER_RSS_KIB = 256 * 1_024
_PARSER_WALL_SECONDS = 2.0
_EXPECTED_RESOURCE_CORPUS = [
    "html-bytes",
    "html-aggregate-text",
    "html-depth",
    "html-nodes",
    "html-per-node-attributes",
    "html-total-attributes",
    "html-field-size",
    "html-metadata-fields",
    "html-records",
    "xml-bytes",
    "xml-aggregate-text",
    "xml-depth",
    "xml-nodes",
    "xml-per-node-attributes",
    "xml-total-attributes",
    "xml-field-size",
    "xml-metadata-fields",
    "xml-records",
]
_TASK_EIGHTEEN_ASVS_DEFINITIONS = {
    "V2.1.3": (
        "Verify that expectations for business logic limits and validations are "
        "documented, including both per-user and globally across the application."
    ),
    "V2.2.1": (
        "Verify that input is validated to enforce business or functional "
        "expectations for that input. This should either use positive validation "
        "against an allow list of values, patterns, and ranges, or be based on "
        "comparing the input to an expected structure and logical limits according "
        "to predefined rules. For L1, this can focus on input which is used to make "
        "specific business or security decisions. For L2 and up, this should apply "
        "to all input."
    ),
    "V2.3.2": (
        "Verify that business logic limits are implemented per the application's "
        "documentation to avoid business logic flaws being exploited."
    ),
    "V15.1.3": (
        "Verify that the application documentation identifies functionality which "
        "is time-consuming or resource-demanding. This must include how to prevent "
        "a loss of availability due to overusing this functionality and how to "
        "avoid a situation where building a response takes longer than the "
        "consumer's timeout. Potential defenses may include asynchronous "
        "processing, using queues, and limiting parallel processes per user and per "
        "application."
    ),
    "V15.2.2": (
        "Verify that the application has implemented defenses against loss of "
        "availability due to functionality which is time-consuming or "
        "resource-demanding, based on the documented security decisions and "
        "strategies for this."
    ),
}


def _run_controlled_parser_resource_child(
    script: str,
    *,
    wall_timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONHASHSEED"] = "0"
    command = (sys.executable, "-c", script)
    return subprocess.run(  # noqa: S603
        command,
        check=False,
        capture_output=True,
        cwd=Path(__file__).parents[2],
        env=environment,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=wall_timeout_seconds,
    )


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
    return (
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
        f"<ListMetadataFormats>{entries}</ListMetadataFormats></OAI-PMH>"
    )


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


_LIMIT_CASES = tuple(
    (field, delta) for field in _PARSER_LIMIT_DEFAULTS for delta in (-1, 0, 1)
)
_PARAMETRIZE_LIMIT_CASES = cast(
    "Callable[[Callable[[str, int], None]], Callable[[str, int], None]]",
    pytest.mark.parametrize(("field", "delta"), _LIMIT_CASES),
)

_BEHAVIORAL_LIMIT_CASES = tuple(
    (kind, field, delta)
    for kind in ("html", "xml")
    for field in _PARSER_LIMIT_DEFAULTS
    for delta in (-1, 0, 1)
)
_PARAMETRIZE_BEHAVIORAL_LIMIT_CASES = cast(
    "_BehavioralLimitDecorator",
    pytest.mark.parametrize(
        ("kind", "field", "delta"),
        _BEHAVIORAL_LIMIT_CASES,
    ),
)


def _attribute_text(count: int) -> str:
    return " ".join(f'a{index}=""' for index in range(count))


def _aggregate_attribute_elements(count: int) -> str:
    complete, remainder = divmod(count, 64)
    complete_attributes = _attribute_text(64)
    elements = [f"<n {complete_attributes}/>" for _ in range(complete)]
    if remainder:
        elements.append(f"<n {_attribute_text(remainder)}/>")
    return "".join(elements)


def _public_item_document(*, rows: str, extra: str = "") -> str:
    return (
        '<div id="aspect_artifactbrowser_ItemViewer_div_item-view">'
        f"<code>{_ITEM_HANDLE}</code>"
        f'<table class="itemDisplayTable">{rows}</table>{extra}</div>'
    )


def _public_formats_document(*, extra: str = "") -> str:
    return (
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
        "<ListMetadataFormats><metadataFormat>"
        "<metadataPrefix>dim</metadataPrefix>"
        f"</metadataFormat></ListMetadataFormats>{extra}</OAI-PMH>"
    )


def _public_oai_record(metadata: str) -> str:
    return (
        "<OAI-PMH><GetRecord><record><header><identifier>"
        f"oai:dspace:{_ITEM_HANDLE}</identifier></header>{metadata}"
        "</record></GetRecord></OAI-PMH>"
    )


def _behavioral_limit_document(  # noqa: C901, PLR0911, PLR0912 - closed fixture router
    *, kind: str, field: str, target: int
) -> str:
    title_row = "<tr><td>Title:</td><td>Title</td></tr>"
    if field == "markup_bytes":
        document = (
            _public_item_document(rows=title_row, extra="<!---->")
            if kind == "html"
            else _public_formats_document(extra="<!---->")
        )
        filler = target - len(document.encode("utf-8"))
        return document.replace("<!---->", f"<!--{'x' * filler}-->")
    if field == "max_depth":
        nested = ("<n>" * (target - 1)) + ("</n>" * (target - 1))
        return (
            _public_item_document(rows=title_row, extra=nested)
            if kind == "html"
            else _public_formats_document(extra=nested)
        )
    if field == "max_nodes":
        return (
            _public_item_document(rows=title_row, extra="<n/>" * (target - 6))
            if kind == "html"
            else _public_formats_document(extra="<n/>" * (target - 4))
        )
    if field == "max_attributes_per_node":
        extra = f"<n {_attribute_text(target)}/>"
        return (
            _public_item_document(rows=title_row, extra=extra)
            if kind == "html"
            else _public_formats_document(extra=extra)
        )
    if field == "max_total_attributes":
        base_attributes = 2 if kind == "html" else 0
        extra = _aggregate_attribute_elements(target - base_attributes)
        return (
            _public_item_document(rows=title_row, extra=extra)
            if kind == "html"
            else _public_formats_document(extra=extra)
        )
    if field == "max_field_code_points":
        if kind == "html":
            return _public_item_document(
                rows=(
                    "<tr><td>dc.title</td><td>Title</td></tr>"
                    f"<tr><td>dc.subject</td><td>{'x' * target}</td></tr>"
                ),
                extra="Show full metadata record",
            )
        return _public_oai_record(
            "".join(
                (
                    "<metadata><dim>",
                    '<field mdschema="dc" element="title">Title</field>',
                    f'<field mdschema="dc" element="subject">{"x" * target}</field>',
                    "</dim></metadata>",
                )
            )
        )
    if field == "max_total_text_code_points":
        if kind == "html":
            return _public_item_document(
                rows=title_row,
                extra=f"<p>{'x' * (target - 92)}</p>",
            )
        return _public_formats_document(extra=f"<n>{'x' * (target - 3)}</n>")
    if field == "max_metadata_fields":
        if kind == "html":
            rows = (
                "<tr><td>dc.title</td><td>Title</td></tr>"
                + "<tr><td>dc.subject</td><td>x</td></tr>" * (target - 1)
            )
            return _public_item_document(
                rows=rows,
                extra="Show full metadata record",
            )
        fields = (
            '<field mdschema="dc" element="title">Title</field>'
            + '<field mdschema="dc" element="subject">x</field>' * (target - 1)
        )
        return _public_oai_record(f"<metadata><dim>{fields}</dim></metadata>")
    if field == "max_records":
        if kind == "html":
            extra = (
                '<table class="search-results"><tbody>'
                f"{'<tr></tr>' * target}</tbody></table>"
            )
            return _public_item_document(rows=title_row, extra=extra)
        return _public_formats_document(
            extra=f"<records>{'<record/>' * target}</records>"
        )
    if field == "parse_deadline_ms":
        return (
            _public_item_document(rows=title_row)
            if kind == "html"
            else _public_formats_document()
        )
    raise AssertionError(field)


def _run_public_limit_parser(kind: str, field: str, document: str) -> object:
    if kind == "html":
        return parse_item_page(
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )
    if field in {"max_field_code_points", "max_metadata_fields"}:
        return parse_oai_record(
            document,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )
    return parse_metadata_formats(document)


_LIMIT_ERROR_PATTERNS = {
    "markup_bytes": "markup byte limit",
    "max_depth": "tree depth limit",
    "max_nodes": "element limit",
    "max_attributes_per_node": "per-node attribute limit",
    "max_total_attributes": "aggregate attribute limit",
    "max_field_code_points": "field code-point limit",
    "max_total_text_code_points": "aggregate text limit",
    "max_metadata_fields": "metadata field limit",
    "max_records": "record limit",
    "parse_deadline_ms": "parse deadline",
}


@_PARAMETRIZE_BEHAVIORAL_LIMIT_CASES
def test_every_parser_limit_has_behavioral_n_minus_one_n_and_n_plus_one(
    kind: str,
    field: str,
    delta: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(parser_module, "_parser_clock", lambda: 0.0)
    maximum = _PARSER_LIMIT_DEFAULTS[field]
    target = maximum + delta
    document = _behavioral_limit_document(kind=kind, field=field, target=target)
    if field == "markup_bytes":
        assert len(document.encode("utf-8")) == target
    if field == "parse_deadline_ms":
        calls = 0

        def boundary_clock() -> float:
            nonlocal calls
            calls += 1
            return 0.0 if calls == 1 else target / 1_000

        monkeypatch.setattr(parser_module, "_parser_clock", boundary_clock)

    if delta == 1:
        if kind == "html":

            def fail_html_dom(*_args: object, **_kwargs: object) -> object:
                pytest.fail("N+1 HTML input reached DOM construction")

            monkeypatch.setattr(
                parser_module,
                "BeautifulSoup",
                fail_html_dom,
            )
        else:

            def fail_xml_dom(*_args: object, **_kwargs: object) -> object:
                pytest.fail("N+1 XML input reached DOM construction")

            monkeypatch.setattr(
                "nplg_mcp.parsers.DefusedElementTree.fromstring",
                fail_xml_dom,
            )
        with pytest.raises(AppError, match=_LIMIT_ERROR_PATTERNS[field]):
            _ = _run_public_limit_parser(kind, field, document)
        return

    result = _run_public_limit_parser(kind, field, document)
    assert result is not None


@_PARAMETRIZE_LIMIT_CASES
def test_every_parser_limit_is_a_literal_reviewed_boundary(
    field: str,
    delta: int,
) -> None:
    payload = dict(_PARSER_LIMIT_DEFAULTS)
    payload[field] += delta
    if delta == 0:
        validated = parser_module.ParserLimits.model_validate(payload)
        dumped = cast(
            "dict[str, object]",
            validated.model_dump(),
        )
        assert dumped == payload
        return
    with pytest.raises(ValidationError):
        _ = parser_module.ParserLimits.model_validate(payload)


def test_resource_child_charges_pre_ready_setup_to_the_absolute_wall_budget() -> None:
    """Mutation caught: allowing pre-READY setup to evade the absolute deadline."""
    script = """
import time

time.sleep(2.05)
print("READY", flush=True)
"""

    with pytest.raises(subprocess.TimeoutExpired):
        _ = _run_controlled_parser_resource_child(
            script,
            wall_timeout_seconds=_PARSER_WALL_SECONDS,
        )


def test_resource_child_kills_an_absolute_wall_overrun() -> None:
    """Mutation caught: dropping the absolute child wall timeout."""
    script = """
import time

time.sleep(0.05)
"""

    with pytest.raises(subprocess.TimeoutExpired):
        _ = _run_controlled_parser_resource_child(
            script,
            wall_timeout_seconds=0.01,
        )


def test_accepted_worst_case_parser_corpus_stays_within_linux_resource_budget() -> None:
    assert sys.platform == "linux", "the pinned parser resource gate requires Linux"
    script = """
import json
import time
from nplg_mcp.parsers import parse_item_page, parse_metadata_formats, parse_oai_record

handle = "1234/499564"
source = f"https://dspace.nplg.gov.ge/handle/{handle}"
title_row = "<tr><td>Title:</td><td>Title</td></tr>"
corpus = []

def accept(label, operation):
    operation()
    corpus.append(label)

def accept_many(labels, operation):
    operation()
    corpus.extend(labels)

def item(rows=title_row, extra=""):
    return (
        '<div id="aspect_artifactbrowser_ItemViewer_div_item-view">'
        f'<code>{handle}</code><table class="itemDisplayTable">'
        f"{rows}</table>{extra}</div>"
    )

def formats(extra=""):
    return (
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
        "<ListMetadataFormats><metadataFormat>"
        "<metadataPrefix>dim</metadataPrefix>"
        f"</metadataFormat></ListMetadataFormats>{extra}</OAI-PMH>"
    )

def oai_record(metadata):
    return (
        "<OAI-PMH><GetRecord><record><header><identifier>"
        f"oai:dspace:{handle}</identifier></header>{metadata}"
        "</record></GetRecord></OAI-PMH>"
    )

def html_parse(document):
    return parse_item_page(document, expected_handle=handle, source_url=source)

def xml_record_parse(document):
    return parse_oai_record(document, expected_handle=handle, metadata_prefix="dim")

def attributes(count):
    return " ".join(f'a{index}=""' for index in range(count))

def aggregate_attributes(count):
    complete, remainder = divmod(count, 64)
    full = attributes(64)
    elements = [f"<n {full}/>" for _ in range(complete)]
    if remainder:
        elements.append(f"<n {attributes(remainder)}/>")
    return "".join(elements)

def exact_bytes(document):
    filler = 2_097_152 - len(document.encode("utf-8"))
    return document.replace("<!---->", f"<!--{'x' * filler}-->")

html_metadata_fields = (
    "<tr><td>dc.title</td><td>Title</td></tr>"
    + f'<tr><td>dc.subject</td><td>{"x" * 65_536}</td></tr>'
    + '<tr><td>dc.subject</td><td>x</td></tr>' * 2_046
)
xml_metadata_fields = (
    '<field mdschema="dc" element="title">Title</field>'
    + f'<field mdschema="dc" element="subject">{"x" * 65_536}</field>'
    + '<field mdschema="dc" element="subject">x</field>' * 2_046
)
html_attribute_text = 89 + 1_562 * 182 + 77
html_existing_text = 11 + 13 + 65_546 + 22_506 + 25 + html_attribute_text
html_text_filler = 1_048_576 - html_existing_text
html_structure = item(
    rows=html_metadata_fields,
    extra=(
        "Show full metadata record"
        + '<table class="search-results"><tbody>'
        + "<tr></tr>" * 1_000
        + "</tbody></table>"
        + "<n>" * 63
        + "</n>" * 63
        + aggregate_attributes(99_997)
        + f"<p>{'x' * html_text_filler}</p>"
        + "<n/>" * 41_224
    ),
)
xml_attribute_text = 1_562 * 182 + 86
xml_text_filler = 1_048_576 - 3 - xml_attribute_text
xml_structure = formats(
    "<records>"
    + "<record/>" * 1_000
    + "</records>"
    + "<n>" * 63
    + "</n>" * 63
    + aggregate_attributes(100_000)
    + f"<p>{'x' * xml_text_filler}</p>"
    + "<n/>" * 47_368
)

started = time.monotonic()
record = html_parse(exact_bytes(html_structure + "<!---->"))
corpus.extend([
    "html-bytes",
    "html-aggregate-text",
    "html-depth",
    "html-nodes",
    "html-per-node-attributes",
    "html-total-attributes",
    "html-field-size",
    "html-metadata-fields",
    "html-records",
])
parse_metadata_formats(exact_bytes(xml_structure + "<!---->"))
xml_record_parse(
    oai_record(f"<metadata><dim>{xml_metadata_fields}</dim></metadata>")
)
corpus.extend([
    "xml-bytes",
    "xml-aggregate-text",
    "xml-depth",
    "xml-nodes",
    "xml-per-node-attributes",
    "xml-total-attributes",
    "xml-field-size",
    "xml-metadata-fields",
    "xml-records",
])
elapsed = time.monotonic() - started
status_lines = open("/proc/self/status", encoding="utf-8").read().splitlines()
rss_line = next(line for line in status_lines if line.startswith("VmHWM:"))
rss_kib = int(rss_line.split()[1])
print(json.dumps({
    "corpus": corpus,
    "elapsed": elapsed,
    "handle": record.handle,
    "rss_kib": rss_kib,
}))
"""
    try:
        completed = _run_controlled_parser_resource_child(
            script,
            wall_timeout_seconds=_PARSER_WALL_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"parser resource subprocess exceeded 2 seconds: {exc}")
    assert completed.returncode == 0, completed.stderr
    measurement = require_json_object(
        load_json_value(completed.stdout),
        context="parser resource measurement",
    )
    handle = measurement.get("handle")
    elapsed = measurement.get("elapsed")
    rss_kib = measurement.get("rss_kib")
    assert measurement.get("corpus") == _EXPECTED_RESOURCE_CORPUS
    assert handle == "1234/499564"
    assert isinstance(elapsed, (int, float))
    assert not isinstance(elapsed, bool)
    assert elapsed <= _PARSER_WALL_SECONDS
    assert type(rss_kib) is int
    assert rss_kib <= _MAX_PARSER_RSS_KIB


def test_task_eighteen_asvs_mapping_uses_pinned_definitions_without_authority() -> None:
    root = Path(__file__).parents[2]
    artifact_path = root / "security/task-18-asvs-evidence.json"
    pinned_path = root / "security/asvs/requirements-5.0.0.json"
    artifact = require_json_object(
        load_json_value(artifact_path.read_bytes()),
        context="Task 18 ASVS evidence",
    )
    assert artifact["asvs_source"] == {
        "commit": "5cf9b032440be53ce345ab3c130fda46ba1ce7a2",
        "sha256": "bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35",
        "version": "5.0.0",
    }
    assert artifact["matrix_verdict"] == "Not assessed"
    assert artifact["release_authority_ids"] == []
    assert artifact["custody_authority_ids"] == []

    pinned = cast("object", json.loads(pinned_path.read_text(encoding="utf-8")))
    definitions: dict[str, str] = {}
    pending = [pinned]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            item = cast("dict[object, object]", value)
            shortcode = item.get("Shortcode")
            description = item.get("Description")
            if type(shortcode) is str and type(description) is str:
                definitions[shortcode] = description
            pending.extend(item.values())
        elif isinstance(value, list):
            pending.extend(cast("list[object]", value))
    assert {
        requirement: definitions[requirement]
        for requirement in _TASK_EIGHTEEN_ASVS_DEFINITIONS
    } == _TASK_EIGHTEEN_ASVS_DEFINITIONS

    mappings = cast("list[object]", artifact["requirements"])
    assert {
        cast("dict[str, object]", mapping)["shortcode"] for mapping in mappings
    } == set(_TASK_EIGHTEEN_ASVS_DEFINITIONS)
    expected_evidence = {
        "V2.1.3": {
            ("src/nplg_mcp/parsers.py", "class ParserLimits"),
            (
                "tests/property/test_parser_properties.py",
                "test_every_parser_limit_has_behavioral_n_minus_one_n_and_n_plus_one",
            ),
        },
        "V2.2.1": {
            (
                "tests/property/test_parser_properties.py",
                "test_every_parser_limit_has_behavioral_n_minus_one_n_and_n_plus_one",
            ),
            (
                "tests/integration/test_repository.py",
                "test_malformed_cursor_signature_is_invalid_input",
            ),
            (
                "tests/unit/test_parsers.py",
                "test_oai_record_rejects_non_direct_structural_ownership",
            ),
        },
        "V2.3.2": {
            ("src/nplg_mcp/parsers.py", "def _saturating_increment"),
            (
                "tests/property/test_parser_properties.py",
                "test_every_parser_limit_has_behavioral_n_minus_one_n_and_n_plus_one",
            ),
            (
                "tests/integration/test_repository.py",
                "test_oai_discovery_failure_is_never_cached_before_validation",
            ),
        },
        "V15.1.3": {
            (
                "tests/property/test_parser_properties.py",
                "test_accepted_worst_case_parser_corpus_stays_within_linux_resource_budget",
            ),
            (
                "tests/integration/test_repository.py",
                "test_concurrent_cold_oai_discovery_uses_exactly_one_upstream_request",
            ),
        },
        "V15.2.2": {
            (
                "tests/property/test_parser_properties.py",
                "test_every_parser_limit_has_behavioral_n_minus_one_n_and_n_plus_one",
            ),
            (
                "tests/property/test_parser_properties.py",
                "test_accepted_worst_case_parser_corpus_stays_within_linux_resource_budget",
            ),
            (
                "tests/integration/test_repository.py",
                "test_concurrent_cold_oai_discovery_uses_exactly_one_upstream_request",
            ),
        },
    }
    assert {
        cast("str", mapping["shortcode"]): {
            (cast("str", evidence["path"]), cast("str", evidence["selector"]))
            for raw_evidence in cast("list[object]", mapping["evidence"])
            for evidence in (cast("dict[str, object]", raw_evidence),)
        }
        for raw_mapping in mappings
        for mapping in (cast("dict[str, object]", raw_mapping),)
    } == expected_evidence
    for raw_mapping in mappings:
        mapping = cast("dict[str, object]", raw_mapping)
        shortcode = cast("str", mapping["shortcode"])
        assert mapping["requirement_text"] == _TASK_EIGHTEEN_ASVS_DEFINITIONS[shortcode]
        for raw_evidence in cast("list[object]", mapping["evidence"]):
            evidence = cast("dict[str, object]", raw_evidence)
            relative = cast("str", evidence["path"])
            selector = cast("str", evidence["selector"])
            evidence_path = (root / relative).resolve(strict=True)
            assert root in evidence_path.parents
            assert selector in evidence_path.read_text(encoding="utf-8")


@_GIVEN_MALFORMED_XML
def test_metadata_parser_fails_closed_for_bounded_malformed_xml(
    tag: str,
    payload: str,
) -> None:
    document = f"<root><{tag}>{html.escape(payload)}</root>"

    with pytest.raises(AppError) as captured:
        _ = parse_metadata_formats(document)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
