# Copyright (c) 2026 David Osipov
"""Unit tests for bounded repository parsers."""

from pathlib import Path

import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parsers import (
    parse_item_page,
    parse_metadata_formats,
    parse_oai_record,
    parse_search_results,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"
_EXPECTED_SEARCH_TOTAL = 42
_EXPECTED_NEXT_OFFSET = 2
_EXPECTED_REPORTED_SIZE = 13_900_000
_SEARCH_SOURCE = "https://dspace.nplg.gov.ge/simple-search?query=test"
_ITEM_HANDLE = "1234/499564"
_ITEM_SOURCE = f"https://dspace.nplg.gov.ge/handle/{_ITEM_HANDLE}"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_search_parser_preserves_georgian_and_canonical_handles() -> None:
    page = parse_search_results(
        fixture("search_results.html"),
        source_url="https://dspace.nplg.gov.ge/simple-search?query=ივერია&rpp=2",
    )
    assert page.total == _EXPECTED_SEARCH_TOTAL
    assert page.next_offset == _EXPECTED_NEXT_OFFSET
    assert [item.handle for item in page.items] == ["1234/499564", "1234/560975"]
    assert page.items[0].title == "ივერია N161"
    assert page.items[1].authors == ("გაგუა, მალხაზ", "სხვა, ავტორი")


@pytest.mark.parametrize(
    "offset_date", ["2025-01-01T23:30:00+04:00", "2025-01-01T23:30:00+0400"]
)
def test_search_parser_preserves_unsupported_offset_dates(offset_date: str) -> None:
    html = fixture("search_results.html").replace("27-Aug-2025", offset_date)

    page = parse_search_results(
        html,
        source_url="https://dspace.nplg.gov.ge/simple-search?query=ივერია&rpp=2",
    )

    assert page.items[1].issue_date == offset_date


@pytest.mark.parametrize(
    ("accepted_date", "normalized_date"),
    [
        ("7-Aug-2025", "2025-08-07"),
        ("2025-8-7", "2025-08-07"),
        ("2025-08-27t23:30:00z", "2025-08-27"),
    ],
)
def test_search_parser_preserves_baseline_strptime_date_language(
    accepted_date: str, normalized_date: str
) -> None:
    html = fixture("search_results.html").replace("27-Aug-2025", accepted_date)

    page = parse_search_results(
        html,
        source_url="https://dspace.nplg.gov.ge/simple-search?query=ივერია&rpp=2",
    )

    assert page.items[1].issue_date == normalized_date


def test_search_parser_fails_closed_when_contract_marker_is_missing() -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_search_results(
            "<html><body>not a DSpace result page</body></html>",
            source_url="https://dspace.nplg.gov.ge/simple-search",
        )
    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_public_item_parser_extracts_metadata_and_validated_bitstream() -> None:
    item = parse_item_page(
        fixture("item_summary_public.html"),
        expected_handle="1234/499564",
        source_url="https://dspace.nplg.gov.ge/handle/1234/499564",
    )
    assert item.handle == "1234/499564"
    assert item.title == "ივერია N161"
    assert item.restricted is False
    assert item.collections == ("ივერია",)
    assert len(item.bitstreams) == 1
    bitstream = item.bitstreams[0]
    assert bitstream.filename == "Iveria_1898_N161.pdf"
    assert bitstream.reported_size == _EXPECTED_REPORTED_SIZE
    assert (
        bitstream.source_url
        == "https://dspace.nplg.gov.ge/bitstream/1234/499564/1/Iveria_1898_N161.pdf"
    )
    assert bitstream.bitstream_id.startswith("bit_")


def test_restricted_item_is_explicit_and_has_no_downloadable_files() -> None:
    item = parse_item_page(
        fixture("item_summary_restricted.html"),
        expected_handle="1234/777777",
        source_url="https://dspace.nplg.gov.ge/handle/1234/777777",
    )
    assert item.restricted is True
    assert item.bitstreams == ()
    assert "internal network" in (item.restriction_reason or "")


def test_full_item_parser_returns_raw_qualified_metadata() -> None:
    item = parse_item_page(
        fixture("item_full.html"),
        expected_handle="1234/560449",
        source_url="https://dspace.nplg.gov.ge/handle/1234/560449?mode=full",
    )
    assert item.title == "ბორჯომი N34"
    assert item.metadata_source == "xmlui_full"
    assert any(
        field.key == "dc.language.iso" and field.value == "ka"
        for field in item.raw_fields
    )
    assert item.languages == ("ka",)
    assert item.owners == ("საქართველოს ეროვნული ბიბლიოთეკა",)


def test_oai_formats_are_discovered() -> None:
    assert parse_metadata_formats(fixture("oai_formats.xml")) == ("oai_dc", "dim")


def test_dim_oai_record_is_normalized_without_translation() -> None:
    record = parse_oai_record(
        fixture("oai_dim_record.xml"),
        expected_handle="1234/560975",
        metadata_prefix="dim",
    )
    assert record.handle == "1234/560975"
    assert record.title == "რეზონანსი N164"
    assert record.issue_date == "2025-08-27"
    assert record.contributors == ("გაგუა, მალხაზ",)
    assert record.subjects == ("პოლიტიკა",)
    assert record.languages == ("ka",)
    assert record.metadata_source == "oai_dim"


def test_oai_error_is_a_stable_upstream_failure() -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_oai_record(
            fixture("oai_error.xml"),
            expected_handle="1234/560975",
            metadata_prefix="dim",
        )
    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def _search_document(
    *,
    headers: str = "<th>Title</th><th>Issue Date</th><th>Author</th>",
    rows: str = (
        '<tr><td><a href="/handle/1234/499564">Title</a></td>'
        "<td>7-Aug-2025</td><td>Author</td></tr>"
    ),
    pagination: str = "",
) -> str:
    return (
        '<div id="aspect_discovery_SimpleSearch_div_search-results">'
        '<table class="search-results"><thead><tr>'
        f"{headers}</tr></thead><tbody>{rows}</tbody></table>{pagination}</div>"
    )


def _item_document(
    *,
    identity: str = f"<code>{_ITEM_HANDLE}</code>",
    rows: str = "<tr><td>Title:</td><td>Title</td></tr>",
    extra: str = "",
) -> str:
    return (
        '<div id="aspect_artifactbrowser_ItemViewer_div_item-view">'
        f'{identity}<table class="itemDisplayTable">{rows}</table>{extra}</div>'
    )


def _oai_document(*, identifier: str, metadata: str) -> str:
    return (
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
        "<GetRecord><record><header>"
        f"<identifier>{identifier}</identifier></header>{metadata}"
        "</record></GetRecord></OAI-PMH>"
    )


def test_search_page_attaches_an_opaque_cursor_without_changing_results() -> None:
    page = parse_search_results(_search_document(), source_url=_SEARCH_SOURCE)

    with_cursor = page.with_cursor("opaque-cursor")

    assert with_cursor.next_cursor == "opaque-cursor"
    assert with_cursor.items == page.items
    assert with_cursor.source_url == page.source_url


def test_search_parser_tolerates_missing_optional_values_and_malformed_rows() -> None:
    rows = (
        "<tr><td>not enough cells</td></tr>"
        "<tr><td>missing link</td><td>-</td><td>-</td></tr>"
        '<tr><td><a href="/handle/1234/499564">Title</a></td>'
        "<td>-</td><td> - ; Author ; Author </td></tr>"
    )

    page = parse_search_results(
        _search_document(rows=rows),
        source_url=_SEARCH_SOURCE,
    )

    assert page.total == 1
    assert page.next_offset is None
    assert page.items[0].issue_date is None
    assert page.items[0].authors == ("Author",)


def test_search_parser_rejects_a_table_without_a_title_column() -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_search_results(
            _search_document(headers="<th>Author</th>"),
            source_url=_SEARCH_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_search_parser_skips_a_row_shorter_than_the_title_column() -> None:
    rows = (
        "<tr><td>author only</td></tr>"
        '<tr><td>Author</td><td><a href="/handle/1234/499564">Title</a></td></tr>'
    )

    page = parse_search_results(
        _search_document(headers="<th>Author</th><th>Title</th>", rows=rows),
        source_url=_SEARCH_SOURCE,
    )

    assert [item.title for item in page.items] == ["Title"]


@pytest.mark.parametrize(
    "rows",
    [
        (
            '<tr><td><a href="https://example.com/handle/1234/499564">'
            "Title</a></td><td></td><td></td></tr>"
        ),
        ('<tr><td><a href="/handle/1234/499564"></a></td><td></td><td></td></tr>'),
    ],
)
def test_search_parser_rejects_unsafe_or_untitled_items(rows: str) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_search_results(
            _search_document(rows=rows),
            source_url=_SEARCH_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    ("pagination", "expected_offset"),
    [
        ('<a href="?start=5">Next</a>', 5),
        ('<a class="next-page-link" href="?query=test">Next</a>', None),
    ],
)
def test_search_parser_supports_fallback_and_absent_pagination_offsets(
    pagination: str,
    expected_offset: int | None,
) -> None:
    page = parse_search_results(
        _search_document(pagination=pagination),
        source_url=_SEARCH_SOURCE,
    )

    assert page.next_offset == expected_offset


@pytest.mark.parametrize(
    "pagination",
    [
        '<a class="next-page-link" href="https://example.com/?start=2">Next</a>',
        '<a class="next-page-link" href="?start=not-an-integer">Next</a>',
        '<a class="next-page-link" href="?start=-1">Next</a>',
    ],
)
def test_search_parser_rejects_unsafe_or_invalid_pagination(
    pagination: str,
) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_search_results(
            _search_document(pagination=pagination),
            source_url=_SEARCH_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_search_parser_rejects_a_contract_without_a_results_table() -> None:
    html = '<div id="aspect_discovery_SimpleSearch_div_search-results"></div>'

    with pytest.raises(AppError) as raised:
        _ = parse_search_results(html, source_url=_SEARCH_SOURCE)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    "href",
    [
        "https://example.com/bitstream/1234/499564/1/file.pdf",
        "/bitstream/1234/560975/1/file.pdf",
    ],
)
def test_item_parser_rejects_unbound_bitstream_links(href: str) -> None:
    extra = f'<a href="{href}">file.pdf</a>'

    with pytest.raises(AppError) as raised:
        _ = parse_item_page(
            _item_document(extra=extra),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_skips_duplicate_view_open_link_and_unknown_size() -> None:
    rows = (
        "<tr><td>Title:</td><td>Title</td></tr>"
        '<tr><td><a href="/bitstream/1234/499564/1/file.pdf">file.pdf</a>'
        '<a href="/bitstream/1234/499564/1/file.pdf">View/Open</a></td>'
        "<td>Description</td><td>unknown</td><td>PDF</td></tr>"
    )

    item = parse_item_page(
        _item_document(rows=rows),
        expected_handle=_ITEM_HANDLE,
        source_url=_ITEM_SOURCE,
    )

    assert len(item.bitstreams) == 1
    assert item.bitstreams[0].filename == "file.pdf"
    assert item.bitstreams[0].reported_size is None


def test_item_parser_falls_back_from_invalid_code_to_handle_link() -> None:
    identity = (
        "<code>not-a-handle</code>"
        '<a href="/discover">Ignore unrelated link</a>'
        '<a href="/handle/not-a-handle">Ignore</a>'
        '<a href="/handle/1234/499564">Canonical item</a>'
    )

    item = parse_item_page(
        _item_document(identity=identity),
        expected_handle=_ITEM_HANDLE,
        source_url=_ITEM_SOURCE,
    )

    assert item.handle == _ITEM_HANDLE


def test_summary_item_parser_skips_short_and_empty_metadata_rows() -> None:
    rows = (
        "<tr><td>short row</td></tr>"
        "<tr><td>Title:</td><td></td></tr>"
        "<tr><td>Title:</td><td>Title</td></tr>"
    )

    item = parse_item_page(
        _item_document(rows=rows),
        expected_handle=_ITEM_HANDLE,
        source_url=_ITEM_SOURCE,
    )

    assert item.title == "Title"


@pytest.mark.parametrize(
    ("html", "expected_handle"),
    [
        ("<html></html>", _ITEM_HANDLE),
        (_item_document(identity=""), _ITEM_HANDLE),
        (_item_document(), "1234/560975"),
        (_item_document(rows="<tr><td>Unknown</td><td>value</td></tr>"), _ITEM_HANDLE),
    ],
)
def test_item_parser_rejects_missing_contract_identity_or_metadata(
    html: str,
    expected_handle: str,
) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_item_page(
            html,
            expected_handle=expected_handle,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_full_item_parser_skips_invalid_rows_and_finds_collection_text() -> None:
    rows = (
        "<tr><td>not a dc key</td><td>ignored</td></tr>"
        "<tr><td>dc.title</td><td></td></tr>"
        "<tr><td>dc.title</td><td>Title</td><td>-</td></tr>"
        "<tr><td>short row</td></tr>"
    )
    extra = "<p>Appears in Collections: Collection A</p>Show full metadata record"

    item = parse_item_page(
        _item_document(rows=rows, extra=extra),
        expected_handle=_ITEM_HANDLE,
        source_url=_ITEM_SOURCE,
    )

    assert item.title == "Title"
    assert item.collections == ("Collection A",)


@pytest.mark.parametrize(
    "xml",
    [
        "<not-closed>",
        "<!DOCTYPE foo [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><foo>&x;</foo>",
    ],
)
def test_oai_parsers_reject_malformed_or_forbidden_xml(xml: str) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_metadata_formats(xml)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    "xml",
    [
        '<OAI-PMH><error code="badArgument">bad</error></OAI-PMH>',
        "<OAI-PMH><ListMetadataFormats /></OAI-PMH>",
    ],
)
def test_metadata_format_parser_rejects_error_or_empty_responses(xml: str) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_metadata_formats(xml)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_metadata_format_parser_ignores_empty_and_duplicate_prefixes() -> None:
    xml = (
        "<OAI-PMH><ListMetadataFormats>"
        "<metadataFormat><metadataPrefix /></metadataFormat>"
        "<metadataFormat><metadataPrefix>dim</metadataPrefix></metadataFormat>"
        "<metadataFormat><metadataPrefix>dim</metadataPrefix></metadataFormat>"
        "</ListMetadataFormats></OAI-PMH>"
    )

    assert parse_metadata_formats(xml) == ("dim",)


@pytest.mark.parametrize(
    "xml",
    [
        "<OAI-PMH><GetRecord /></OAI-PMH>",
        _oai_document(
            identifier="oai:dspace:1234/other",
            metadata=(
                '<metadata><field mdschema="dc" element="title">'
                "Title</field></metadata>"
            ),
        ),
    ],
)
def test_oai_record_rejects_missing_or_mismatched_identifier(xml: str) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_dim_record_skips_invalid_fields_and_rejects_empty_metadata() -> None:
    metadata = (
        "<metadata>"
        '<field mdschema="dc">ignored</field>'
        '<field mdschema="dc" element="title"></field>'
        "</metadata>"
    )
    xml = _oai_document(
        identifier=f"oai:dspace:{_ITEM_HANDLE}",
        metadata=metadata,
    )

    with pytest.raises(AppError) as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_oai_dc_record_preserves_language_and_ignores_empty_fields() -> None:
    metadata = (
        '<metadata><dc xmlns="http://www.openarchives.org/OAI/2.0/oai_dc/" '
        'xmlns:terms="http://purl.org/dc/elements/1.1/">'
        '<terms:title xml:lang="ka">Title</terms:title>'
        "<terms:subject></terms:subject></dc></metadata>"
    )
    xml = _oai_document(
        identifier=f"oai:dspace:{_ITEM_HANDLE}",
        metadata=metadata,
    )

    record = parse_oai_record(
        xml,
        expected_handle=_ITEM_HANDLE,
        metadata_prefix="oai_dc",
    )

    assert record.title == "Title"
    assert record.raw_fields[0].language == "ka"
    assert record.metadata_source == "oai_dc"


@pytest.mark.parametrize(
    ("metadata", "metadata_prefix", "expected_code"),
    [
        ("", "oai_dc", ErrorCode.UPSTREAM_FAILURE),
        (
            '<metadata><field mdschema="dc" element="title">Title</field></metadata>',
            "unsupported",
            ErrorCode.INVALID_INPUT,
        ),
    ],
)
def test_oai_record_rejects_missing_dc_metadata_or_unsupported_prefix(
    metadata: str,
    metadata_prefix: str,
    expected_code: ErrorCode,
) -> None:
    xml = _oai_document(
        identifier=f"oai:dspace:{_ITEM_HANDLE}",
        metadata=metadata,
    )

    with pytest.raises(AppError) as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix=metadata_prefix,
        )

    assert raised.value.code is expected_code
