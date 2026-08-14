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


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_search_parser_preserves_georgian_and_canonical_handles() -> None:
    page = parse_search_results(
        fixture("search_results.html"),
        source_url="https://dspace.nplg.gov.ge/simple-search?query=ივერია&rpp=2",
    )
    assert page.total == 42
    assert page.next_offset == 2
    assert [item.handle for item in page.items] == ["1234/499564", "1234/560975"]
    assert page.items[0].title == "ივერია N161"
    assert page.items[1].authors == ("გაგუა, მალხაზ", "სხვა, ავტორი")


def test_search_parser_fails_closed_when_contract_marker_is_missing() -> None:
    with pytest.raises(AppError) as raised:
        parse_search_results("<html><body>not a DSpace result page</body></html>", source_url="https://dspace.nplg.gov.ge/simple-search")
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
    assert bitstream.reported_size == 13_900_000
    assert bitstream.source_url == "https://dspace.nplg.gov.ge/bitstream/1234/499564/1/Iveria_1898_N161.pdf"
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
    assert any(field.key == "dc.language.iso" and field.value == "ka" for field in item.raw_fields)
    assert item.languages == ("ka",)
    assert item.owners == ("საქართველოს ეროვნული ბიბლიოთეკა",)


def test_oai_formats_are_discovered() -> None:
    assert parse_metadata_formats(fixture("oai_formats.xml")) == ("oai_dc", "dim")


def test_dim_oai_record_is_normalized_without_translation() -> None:
    record = parse_oai_record(fixture("oai_dim_record.xml"), expected_handle="1234/560975", metadata_prefix="dim")
    assert record.handle == "1234/560975"
    assert record.title == "რეზონანსი N164"
    assert record.issue_date == "2025-08-27"
    assert record.contributors == ("გაგუა, მალხაზ",)
    assert record.subjects == ("პოლიტიკა",)
    assert record.languages == ("ka",)
    assert record.metadata_source == "oai_dim"


def test_oai_error_is_a_stable_upstream_failure() -> None:
    with pytest.raises(AppError) as raised:
        parse_oai_record(fixture("oai_error.xml"), expected_handle="1234/560975", metadata_prefix="dim")
    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE
