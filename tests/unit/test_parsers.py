# Copyright (c) 2026 David Osipov
"""Unit tests for bounded repository parsers."""

import re
from collections.abc import Callable  # noqa: TC003 - runtime local annotation
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn, Protocol, cast

import pytest
from bs4 import BeautifulSoup, Tag
from defusedxml import ElementTree as DefusedElementTree
from pydantic import ValidationError

from nplg_mcp import parsers as parser_module
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parsers import (
    parse_item_page,
    parse_metadata_formats,
    parse_oai_record,
    parse_search_results,
)
from nplg_mcp.security import NPLG_HOST

FIXTURES = Path(__file__).parents[1] / "fixtures"
_EXPECTED_SEARCH_TOTAL = 42
_EXPECTED_NEXT_OFFSET = 2
_EXPECTED_REPORTED_SIZE = 13_900_000
_SEARCH_SOURCE = "https://dspace.nplg.gov.ge/simple-search?query=test"
_ITEM_HANDLE = "1234/499564"
_ITEM_SOURCE = f"https://dspace.nplg.gov.ge/handle/{_ITEM_HANDLE}"


class _DefusedIterparse(Protocol):
    def __call__(
        self,
        source: object,
        events: object = None,
        *,
        forbid_dtd: bool = False,
        forbid_entities: bool = True,
        forbid_external: bool = True,
    ) -> object: ...


class _DefusedFromstring(Protocol):
    def __call__(
        self,
        text: str,
        *,
        forbid_dtd: bool = False,
        forbid_entities: bool = True,
        forbid_external: bool = True,
    ) -> object: ...


_EXCESSIVE_SEARCH_ROWS = 51
_EXCESSIVE_METADATA_FIELDS = 2_049
_EXCESSIVE_BITSTREAMS = 257
_EXCESSIVE_METADATA_FORMATS = 65
_EXCESSIVE_TEXT_CODE_POINTS = 1_048_577
_EXCESSIVE_FIELD_CODE_POINTS = 65_537
_EXCESSIVE_TREE_DEPTH = 65
_EXCESSIVE_HTML_ELEMENTS = 50_001
_EXCESSIVE_XML_ELEMENTS = 50_001
_EXCESSIVE_COLLECTIONS = 257
_EXPECTED_NESTED_HTML_RAW_TEXT_CODE_POINTS = 37
_EXPECTED_NESTED_HTML_SEMANTIC_TEXT_CODE_POINTS = 34


class _WhitespaceRunProbe:
    """Record canonicalization calls while retaining the compiled-regex behavior."""

    def __init__(self, expression: re.Pattern[str]) -> None:
        super().__init__()
        self._expression = expression
        self.calls: list[str] = []

    def sub(self, replacement: str, value: str) -> str:
        self.calls.append(value)
        return self._expression.sub(replacement, value)

    def search(self, value: str) -> re.Match[str] | None:
        return self._expression.search(value)


class _CanonicalTextCounterProtocol(Protocol):
    code_points: int
    semantic_code_points: int
    in_whitespace: bool

    def add(self, value: str | None) -> None: ...


class _HtmlTextCountsProtocol(Protocol):
    total_text_code_points: int
    semantic_total_text_code_points: int


class _HtmlTreeValidator(Protocol):
    def __call__(
        self,
        soup: BeautifulSoup,
        *,
        source_url: str,
    ) -> _HtmlTextCountsProtocol: ...


class _TextBudgetValidator(Protocol):
    def __call__(
        self,
        current: int,
        value: str | None,
        *,
        source_url: str | None = None,
    ) -> int: ...


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _forbidden(message: str) -> NoReturn:
    raise AssertionError(message)


def _document(*parts: str) -> str:
    return "".join(parts)


@pytest.fixture(autouse=True)
def freeze_parser_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parser_module, "_parser_clock", lambda: 10.0)


def test_parser_limits_are_the_exact_immutable_reviewed_policy() -> None:
    limits = parser_module.ParserLimits()
    dumped = cast("dict[str, object]", limits.model_dump())
    assert dumped == {
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
    with pytest.raises(ValidationError, match="frozen"):
        setattr(limits, "max_depth", 65)  # noqa: B010 - exercise frozen runtime


def test_html_markup_byte_overflow_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _item_document(extra="<!-- -->")
    target_bytes = 2_097_153
    fixed_bytes = len(base.encode("utf-8"))
    filler_bytes = target_bytes - fixed_bytes + 1
    georgian_count, ascii_count = divmod(filler_bytes, 3)
    document = base.replace(
        "<!-- -->", f"<!--{'ა' * georgian_count}{'x' * ascii_count}-->"
    )
    assert len(document.encode("utf-8")) == target_bytes

    def forbidden_tree_builder(*_args: object, **_kwargs: object) -> object:
        _forbidden("markup byte preflight was bypassed")

    monkeypatch.setattr(parser_module, "BeautifulSoup", forbidden_tree_builder)
    with pytest.raises(AppError, match="markup byte limit"):
        _ = parse_item_page(
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )


def test_html_per_node_attribute_overflow_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attributes = " ".join(f'data-{index}="x"' for index in range(65))
    document = _item_document(extra=f"<span {attributes}>payload</span>")

    def forbidden_tree_builder(*_args: object, **_kwargs: object) -> object:
        _forbidden("attribute preflight was bypassed")

    monkeypatch.setattr(parser_module, "BeautifulSoup", forbidden_tree_builder)
    with pytest.raises(AppError, match="attribute limit"):
        _ = parse_item_page(
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )


def test_html_deadline_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    samples = iter((10.0, 12.001))
    monkeypatch.setattr(
        parser_module, "_parser_clock", lambda: next(samples), raising=False
    )

    def forbidden_tree_builder(*_args: object, **_kwargs: object) -> object:
        _forbidden("deadline preflight was bypassed")

    monkeypatch.setattr(parser_module, "BeautifulSoup", forbidden_tree_builder)
    with pytest.raises(AppError, match="parse deadline"):
        _ = parse_item_page(
            _item_document(),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )


def test_xml_markup_byte_overflow_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = (
        "<OAI-PMH><!-- --><ListMetadataFormats><metadataFormat>"
        "<metadataPrefix>dim</metadataPrefix></metadataFormat>"
        "</ListMetadataFormats></OAI-PMH>"
    )
    target_bytes = 2_097_153
    filler_bytes = target_bytes - len(base.encode("utf-8")) + 1
    georgian_count, ascii_count = divmod(filler_bytes, 3)
    document = base.replace(
        "<!-- -->", f"<!--{'ა' * georgian_count}{'x' * ascii_count}-->"
    )
    assert len(document.encode("utf-8")) == target_bytes

    def forbidden_tree_builder(_xml: str) -> object:
        _forbidden("XML markup byte preflight was bypassed")

    monkeypatch.setattr(DefusedElementTree, "fromstring", forbidden_tree_builder)
    with pytest.raises(AppError, match="markup byte limit"):
        _ = parse_metadata_formats(document)


def test_xml_per_node_attribute_overflow_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attributes = " ".join(f'data-{index}="x"' for index in range(65))
    document = (
        f"<OAI-PMH {attributes}><ListMetadataFormats><metadataFormat>"
        "<metadataPrefix>dim</metadataPrefix>"
        "</metadataFormat></ListMetadataFormats></OAI-PMH>"
    )

    def forbidden_tree_builder(_xml: str) -> object:
        _forbidden("XML attribute preflight was bypassed")

    monkeypatch.setattr(DefusedElementTree, "fromstring", forbidden_tree_builder)
    with pytest.raises(AppError, match="attribute limit"):
        _ = parse_metadata_formats(document)


@pytest.mark.parametrize("kind", ["html", "xml"])
def test_aggregate_attribute_overflow_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    attributes = " ".join(f'data-{index}="x"' for index in range(64))
    elements = "".join(f"<entry {attributes} />" for _ in range(1_563))
    parse: Callable[[], object]
    if kind == "html":
        document = _item_document(extra=elements)

        def forbidden_html(*_args: object, **_kwargs: object) -> object:
            _forbidden("HTML aggregate-attribute preflight was bypassed")

        monkeypatch.setattr(parser_module, "BeautifulSoup", forbidden_html)
        parse = lambda: parse_item_page(  # noqa: E731
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )
    else:
        document = (
            f"<OAI-PMH><ListMetadataFormats>{elements}</ListMetadataFormats></OAI-PMH>"
        )

        def forbidden_xml(_xml: str) -> object:
            _forbidden("XML aggregate-attribute preflight was bypassed")

        monkeypatch.setattr(DefusedElementTree, "fromstring", forbidden_xml)
        parse = lambda: parse_metadata_formats(document)  # noqa: E731

    with pytest.raises(AppError, match="aggregate attribute limit"):
        _ = parse()


@pytest.mark.parametrize("kind", ["html", "xml"])
def test_aggregate_text_overflow_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    elements = "".join(f"<entry>{'x' * 65_000}</entry>" for _ in range(17))
    parse: Callable[[], object]
    if kind == "html":
        document = _item_document(extra=elements)

        def forbidden_html(*_args: object, **_kwargs: object) -> object:
            _forbidden("HTML aggregate-text preflight was bypassed")

        monkeypatch.setattr(parser_module, "BeautifulSoup", forbidden_html)
        parse = lambda: parse_item_page(  # noqa: E731
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )
    else:
        document = (
            f"<OAI-PMH><ListMetadataFormats>{elements}</ListMetadataFormats></OAI-PMH>"
        )

        def forbidden_xml(_xml: str) -> object:
            _forbidden("XML aggregate-text preflight was bypassed")

        monkeypatch.setattr(DefusedElementTree, "fromstring", forbidden_xml)
        parse = lambda: parse_metadata_formats(document)  # noqa: E731

    with pytest.raises(AppError, match="aggregate text limit"):
        _ = parse()


def test_xml_deadline_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    samples = iter((10.0, 12.001))
    monkeypatch.setattr(parser_module, "_parser_clock", lambda: next(samples))

    def forbidden_tree_builder(_xml: str) -> object:
        _forbidden("XML deadline preflight was bypassed")

    monkeypatch.setattr(DefusedElementTree, "fromstring", forbidden_tree_builder)
    with pytest.raises(AppError, match="parse deadline"):
        _ = parse_metadata_formats(
            _document(
                "<OAI-PMH><ListMetadataFormats><metadataFormat>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></OAI-PMH>",
            )
        )


@pytest.mark.parametrize("kind", ["html", "xml"])
def test_oversized_single_field_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    value = "x" * 65_537
    parse: Callable[[], object]
    if kind == "html":
        document = _item_document(rows=f"<tr><td>Title:</td><td>{value}</td></tr>")

        def forbidden_html(*_args: object, **_kwargs: object) -> object:
            _forbidden("HTML field preflight was bypassed")

        monkeypatch.setattr(parser_module, "BeautifulSoup", forbidden_html)
        parse = lambda: parse_item_page(  # noqa: E731
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )
    else:
        document = _oai_document(
            identifier=f"oai:dspace:{_ITEM_HANDLE}",
            metadata=(
                '<metadata><field mdschema="dc" element="title">'
                f"{value}</field></metadata>"
            ),
        )

        def forbidden_xml(_xml: str) -> object:
            _forbidden("XML field preflight was bypassed")

        monkeypatch.setattr(DefusedElementTree, "fromstring", forbidden_xml)
        parse = lambda: parse_oai_record(  # noqa: E731
            document,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )

    with pytest.raises(AppError, match="field code-point limit"):
        _ = parse()


@pytest.mark.parametrize("kind", ["html", "xml"])
def test_metadata_field_overflow_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    parse: Callable[[], object]
    if kind == "html":
        fields = "".join(
            f"<tr><td>Subject:</td><td>{index}</td></tr>" for index in range(2_049)
        )
        document = _item_document(rows=fields)

        def forbidden_html(*_args: object, **_kwargs: object) -> object:
            _forbidden("HTML metadata-field preflight was bypassed")

        monkeypatch.setattr(parser_module, "BeautifulSoup", forbidden_html)
        parse = lambda: parse_item_page(  # noqa: E731
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )
    else:
        fields = "".join(
            f'<field mdschema="dc" element="subject">{index}</field>'
            for index in range(2_049)
        )
        document = _oai_document(
            identifier=f"oai:dspace:{_ITEM_HANDLE}",
            metadata=f"<metadata>{fields}</metadata>",
        )

        def forbidden_xml(_xml: str) -> object:
            _forbidden("XML metadata-field preflight was bypassed")

        monkeypatch.setattr(DefusedElementTree, "fromstring", forbidden_xml)
        parse = lambda: parse_oai_record(  # noqa: E731
            document,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )

    with pytest.raises(AppError, match="metadata field limit"):
        _ = parse()


@pytest.mark.parametrize("kind", ["html", "xml"])
def test_record_overflow_is_rejected_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    parse: Callable[[], object]
    if kind == "html":
        rows = "".join(
            f'<tr><td><a href="/handle/1234/{index + 1}">T</a></td></tr>'
            for index in range(1_001)
        )
        document = _search_document(headers="<th>Title</th>", rows=rows)

        def forbidden_html(*_args: object, **_kwargs: object) -> object:
            _forbidden("HTML record preflight was bypassed")

        monkeypatch.setattr(parser_module, "BeautifulSoup", forbidden_html)
        parse = lambda: parse_search_results(  # noqa: E731
            document,
            source_url=_SEARCH_SOURCE,
            page_size=50,
        )
    else:
        records = "".join("<record><header /></record>" for _ in range(1_001))
        document = f"<OAI-PMH><ListRecords>{records}</ListRecords></OAI-PMH>"

        def forbidden_xml(_xml: str) -> object:
            _forbidden("XML record preflight was bypassed")

        monkeypatch.setattr(DefusedElementTree, "fromstring", forbidden_xml)
        parse = lambda: parse_metadata_formats(document)  # noqa: E731

    with pytest.raises(AppError, match="record limit"):
        _ = parse()


@pytest.mark.parametrize("kind", ["html", "xml"])
def test_parser_rejects_preflight_and_dom_count_disagreement(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    parse: Callable[[], object]
    mismatched = SimpleNamespace(
        nodes=0,
        total_attributes=0,
        total_text_code_points=0,
        semantic_total_text_code_points=0,
        metadata_fields=0,
        records=0,
        max_field_code_points=0,
        semantic_max_field_code_points=0,
    )

    def mismatched_counts(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return mismatched

    if kind == "html":
        monkeypatch.setattr(parser_module, "_validate_html_tree", mismatched_counts)
        parse = lambda: parse_item_page(  # noqa: E731
            _item_document(),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )
    else:
        monkeypatch.setattr(parser_module, "_validate_xml_tree", mismatched_counts)
        parse = lambda: parse_metadata_formats(  # noqa: E731
            _document(
                "<OAI-PMH><ListMetadataFormats><metadataFormat>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></OAI-PMH>",
            )
        )

    with pytest.raises(AppError, match="preflight disagreement"):
        _ = parse()


def test_html_parser_rejects_aggregate_text_only_recount_disagreement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validate_tree = parser_module._validate_html_tree  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def mismatched_text(soup: BeautifulSoup, *, source_url: str) -> object:
        counts = validate_tree(soup, source_url=source_url)
        return replace(
            counts,
            total_text_code_points=counts.total_text_code_points + 1,
        )

    monkeypatch.setattr(parser_module, "_validate_html_tree", mismatched_text)

    with pytest.raises(AppError, match="preflight disagreement"):
        _ = parse_item_page(
            _item_document(),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )


def test_html_tree_validation_counts_ordered_nested_text_without_second_recount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: the validation walk owns the preflight-agreement text totals."""
    soup = BeautifulSoup(
        "<div data-note='alpha  beta'>top <span> middle\t</span> tail</div>",
        "lxml",
    )

    def forbidden_second_recount(*_args: object, **_kwargs: object) -> NoReturn:
        _forbidden("validated tree must not start a second text recount")

    monkeypatch.setattr(
        parser_module,
        "_html_text_code_point_counts",
        forbidden_second_recount,
        raising=False,
    )
    parser_values = cast("dict[str, object]", vars(parser_module))
    validate_tree = cast("_HtmlTreeValidator", parser_values["_validate_html_tree"])

    counts = validate_tree(soup, source_url=_ITEM_SOURCE)

    assert counts.total_text_code_points == _EXPECTED_NESTED_HTML_RAW_TEXT_CODE_POINTS
    assert (
        counts.semantic_total_text_code_points
        == _EXPECTED_NESTED_HTML_SEMANTIC_TEXT_CODE_POINTS
    )


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


def test_search_parser_rejects_duplicate_contract_markers() -> None:
    document = _search_document() + _search_document()

    with pytest.raises(AppError, match="contract marker"):
        _ = parse_search_results(document, source_url=_SEARCH_SOURCE)


def test_item_parser_rejects_duplicate_contract_markers() -> None:
    document = _item_document() + _item_document()

    with pytest.raises(AppError, match="contract marker"):
        _ = parse_item_page(
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )


def test_item_parser_rejects_footer_handle_from_another_record() -> None:
    """Mutation caught: accepting an expected handle outside the item container."""
    document = f"<footer><code>{_ITEM_HANDLE}</code></footer>" + _item_document(
        identity="<code>777/42</code>",
        rows="<tr><td>Title:</td><td>Other record</td></tr>",
    )

    with pytest.raises(AppError, match="did not match the requested handle") as raised:
        _ = parse_item_page(
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_rejects_ambiguous_restricted_and_public_markers() -> None:
    document = _item_document(
        extra=(
            "This item is only available in the library's internal network."
            f'<a href="/bitstream/{_ITEM_HANDLE}/1/file.pdf">file.pdf</a>'
        )
    )

    with pytest.raises(AppError, match="ambiguous access markers"):
        _ = parse_item_page(
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )


def test_oai_parsers_reject_duplicate_contract_markers() -> None:
    formats = (
        "<ListMetadataFormats><metadataFormat><metadataPrefix>dim</metadataPrefix>"
        "</metadataFormat></ListMetadataFormats>"
    )
    with pytest.raises(AppError, match="contract marker"):
        _ = parse_metadata_formats(f"<OAI-PMH>{formats}{formats}</OAI-PMH>")

    record = (
        "<record><header><identifier>"
        f"oai:{NPLG_HOST}:{_ITEM_HANDLE}</identifier></header>"
        '<metadata><field mdschema="dc" element="title">Title</field></metadata>'
        "</record>"
    )
    with pytest.raises(AppError, match="contract marker"):
        _ = parse_oai_record(
            (
                '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
                f"<GetRecord>{record}{record}</GetRecord></OAI-PMH>"
            ),
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )


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


def test_item_parser_preserves_nested_metadata_row_order_without_duplicates() -> None:
    document = (
        '<div id="aspect_artifactbrowser_ItemViewer_div_item-view">'
        f"<code>{_ITEM_HANDLE}</code>"
        '<table class="outer itemDisplayTable">'
        "<tr><td>dc.description</td><td>Outer"
        '<table class="itemDisplayTable nested">'
        "<tr><td>dc.title</td><td>Nested title</td><td>-</td></tr>"
        "</table></td><td>-</td></tr></table>"
        '<table class="itemDisplayTable sibling">'
        "<tr><td>dc.subject</td><td>Sibling subject</td><td>-</td></tr>"
        "</table>Show full metadata record</div>"
    )

    item = parse_item_page(
        document,
        expected_handle=_ITEM_HANDLE,
        source_url=_ITEM_SOURCE,
    )

    assert tuple(field.key for field in item.raw_fields) == (
        "dc.description",
        "dc.title",
        "dc.subject",
    )
    assert item.title == "Nested title"
    assert item.subjects == ("Sibling subject",)


def test_item_parser_ignores_empty_or_absent_hrefs_during_bitstream_walk() -> None:
    extra = (
        '<a href="">empty</a><a>absent</a>'
        f'<a href="/bitstream/{_ITEM_HANDLE}/1/file.pdf">file.pdf</a>'
    )

    item = parse_item_page(
        _item_document(extra=extra),
        expected_handle=_ITEM_HANDLE,
        source_url=_ITEM_SOURCE,
    )

    assert len(item.bitstreams) == 1
    assert item.bitstreams[0].filename == "file.pdf"


def _oai_document(*, identifier: str, metadata: str) -> str:
    return (
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
        "<GetRecord><record><header>"
        f"<identifier>{identifier}</identifier></header>{metadata}"
        "</record></GetRecord></OAI-PMH>"
    )


def _dim_metadata(value: str = "Title") -> str:
    return (
        '<metadata><dim xmlns="http://www.dspace.org/xmlns/dspace/dim">'
        f'<field mdschema="dc" element="title">{value}</field>'
        "</dim></metadata>"
    )


def _dc_metadata(value: str = "Title") -> str:
    return (
        '<metadata><dc xmlns="http://www.openarchives.org/OAI/2.0/oai_dc/" '
        'xmlns:terms="http://purl.org/dc/elements/1.1/">'
        f"<terms:title>{value}</terms:title></dc></metadata>"
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


def test_metadata_rows_keeps_only_ordered_direct_cells_without_row_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: nested table cells cannot become outer metadata cells."""
    soup = BeautifulSoup(
        """\
<table class='itemDisplayTable'><tr id='outer'>
<td id='direct-key'>Title:</td>
<td id='direct-value'>Title<table><tr><td id='nested-key'>Nested</td>
<td id='nested-value'>Ignored</td></tr></table></td>
<td id='direct-tail'>Tail</td></tr></table>""",
        "html.parser",
    )
    outer = soup.find("tr", id="outer")
    assert isinstance(outer, Tag)

    def forbidden_row_search(*_args: object, **_kwargs: object) -> NoReturn:
        _forbidden("metadata rows must iterate direct cells without Tag.find_all")

    monkeypatch.setattr(outer, "find_all", forbidden_row_search)
    parser_values = cast("dict[str, object]", vars(parser_module))
    metadata_rows = cast(
        "Callable[[BeautifulSoup], tuple[tuple[Tag, tuple[Tag, ...]], ...]]",
        parser_values["_metadata_rows"],
    )

    rows = metadata_rows(soup)
    outer_cells = next(cells for row, cells in rows if row is outer)

    assert [cell.get("id") for cell in outer_cells] == [
        "direct-key",
        "direct-value",
        "direct-tail",
    ]


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


@pytest.mark.parametrize("parser_kind", ["metadata-formats", "record"])
@pytest.mark.parametrize(
    "declaration",
    [
        pytest.param("<!DOCTYPE OAI-PMH>", id="dtd"),
        pytest.param(
            '<!DOCTYPE OAI-PMH [<!ENTITY external SYSTEM "file:///etc/passwd">]>',
            id="external-entity",
        ),
    ],
)
def test_oai_parsers_reject_dtd_and_entities_on_otherwise_valid_responses(
    parser_kind: str,
    declaration: str,
) -> None:
    parse: Callable[[], object]
    if parser_kind == "metadata-formats":
        body = (
            "<OAI-PMH><ListMetadataFormats><metadataFormat>"
            "<metadataPrefix>dim</metadataPrefix>"
            "</metadataFormat></ListMetadataFormats></OAI-PMH>"
        )
        parse = lambda: parse_metadata_formats(declaration + body)  # noqa: E731
    else:
        body = _oai_document(
            identifier=f"oai:dspace:{_ITEM_HANDLE}",
            metadata=_dim_metadata(
                "Title" if declaration == "<!DOCTYPE OAI-PMH>" else "&external;"
            ),
        )
        parse = lambda: parse_oai_record(  # noqa: E731
            declaration + body,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )

    with pytest.raises(AppError) as raised:
        _ = parse()

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_both_defused_xml_paths_receive_every_hardening_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_iterparse = cast("_DefusedIterparse", DefusedElementTree.iterparse)
    real_fromstring = cast("_DefusedFromstring", DefusedElementTree.fromstring)
    observed: dict[str, dict[str, object]] = {}

    def observed_iterparse(
        source: object,
        events: object = None,
        *,
        forbid_dtd: bool = False,
        forbid_entities: bool = True,
        forbid_external: bool = True,
    ) -> object:
        observed["iterparse"] = {
            "events": events,
            "forbid_dtd": forbid_dtd,
            "forbid_entities": forbid_entities,
            "forbid_external": forbid_external,
        }
        return real_iterparse(
            source,
            events,
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )

    def observed_fromstring(
        text: str,
        *,
        forbid_dtd: bool = False,
        forbid_entities: bool = True,
        forbid_external: bool = True,
    ) -> object:
        observed["fromstring"] = {
            "forbid_dtd": forbid_dtd,
            "forbid_entities": forbid_entities,
            "forbid_external": forbid_external,
        }
        return real_fromstring(
            text,
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )

    monkeypatch.setattr(DefusedElementTree, "iterparse", observed_iterparse)
    monkeypatch.setattr(DefusedElementTree, "fromstring", observed_fromstring)
    assert parse_metadata_formats(fixture("oai_formats.xml")) == ("oai_dc", "dim")
    expected = {
        "forbid_dtd": True,
        "forbid_entities": True,
        "forbid_external": True,
    }
    assert {
        name: {key: values[key] for key in expected}
        for name, values in observed.items()
    } == {
        "iterparse": expected,
        "fromstring": expected,
    }


@pytest.mark.parametrize(
    "xml",
    [
        pytest.param("<!DOCTYPE OAI-PMH><OAI-PMH />", id="dtd"),
        pytest.param(
            _document(
                "<!DOCTYPE OAI-PMH [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>",
                "<OAI-PMH>&x;</OAI-PMH>",
            ),
            id="local-external-entity",
        ),
        pytest.param(
            _document(
                "<!DOCTYPE OAI-PMH [<!ENTITY x SYSTEM 'https://example.com/x'>]>",
                "<OAI-PMH>&x;</OAI-PMH>",
            ),
            id="network-external-entity",
        ),
        pytest.param(
            "".join(
                (
                    "<!DOCTYPE OAI-PMH [<!ENTITY a '1234567890'>]>",
                    "<OAI-PMH>",
                    "&a;" * 10_000,
                    "</OAI-PMH>",
                )
            ),
            id="quadratic-entity-expansion",
        ),
        pytest.param(
            _document(
                "<!DOCTYPE OAI-PMH [",
                "<!ENTITY a 'ha'>",
                "<!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>",
                "<!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'>",
                "<!ENTITY d '&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;'>",
                "]><OAI-PMH>&d;</OAI-PMH>",
            ),
            id="exponential-entity-expansion",
        ),
    ],
)
def test_hardened_xml_rejects_every_dtd_and_entity_form(xml: str) -> None:
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
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
        "<ListMetadataFormats>"
        "<metadataFormat><metadataPrefix /></metadataFormat>"
        "<metadataFormat><metadataPrefix>dim</metadataPrefix></metadataFormat>"
        "<metadataFormat><metadataPrefix>dim</metadataPrefix></metadataFormat>"
        "</ListMetadataFormats></OAI-PMH>"
    )

    assert parse_metadata_formats(xml) == ("dim",)


@pytest.mark.parametrize(
    "xml",
    [
        pytest.param(
            _document(
                '<evil:OAI-PMH xmlns:evil="urn:evil">',
                "<evil:ListMetadataFormats><evil:metadataFormat>",
                "<evil:metadataPrefix>dim</evil:metadataPrefix>",
                "</evil:metadataFormat></evil:ListMetadataFormats></evil:OAI-PMH>",
            ),
            id="wrong-root-namespace",
        ),
        pytest.param(
            _document(
                '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" ',
                'xmlns:evil="urn:evil"><evil:ListMetadataFormats>',
                "<evil:metadataFormat><evil:metadataPrefix>dim</evil:metadataPrefix>",
                "</evil:metadataFormat></evil:ListMetadataFormats></OAI-PMH>",
            ),
            id="wrong-list-namespace",
        ),
        pytest.param(
            _document(
                '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" ',
                'xmlns:evil="urn:evil"><ListMetadataFormats>',
                "<evil:metadataFormat><evil:metadataPrefix>dim</evil:metadataPrefix>",
                "</evil:metadataFormat></ListMetadataFormats></OAI-PMH>",
            ),
            id="wrong-format-namespace",
        ),
        pytest.param(
            _document(
                '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" ',
                'xmlns:evil="urn:evil"><ListMetadataFormats><metadataFormat>',
                "<evil:metadataPrefix>dim</evil:metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></OAI-PMH>",
            ),
            id="wrong-prefix-namespace",
        ),
    ],
)
def test_metadata_formats_require_the_reviewed_oai_namespace(xml: str) -> None:
    """Mutation caught: accepting OAI contract markers by local name alone."""
    with pytest.raises(AppError) as raised:
        _ = parse_metadata_formats(xml)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    "xml",
    [
        pytest.param(
            _document(
                "<Envelope><ListMetadataFormats><metadataFormat>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></Envelope>",
            ),
            id="wrong-root",
        ),
        pytest.param(
            _document(
                "<OAI-PMH><wrapper><ListMetadataFormats><metadataFormat>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></wrapper></OAI-PMH>",
            ),
            id="wrapped-list",
        ),
        pytest.param(
            _document(
                "<OAI-PMH><ListMetadataFormats><wrapper><metadataFormat>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></wrapper></ListMetadataFormats></OAI-PMH>",
            ),
            id="wrapped-format",
        ),
        pytest.param(
            _document(
                "<OAI-PMH><ListMetadataFormats><metadataFormat><wrapper>",
                "<metadataPrefix>dim</metadataPrefix>",
                "</wrapper></metadataFormat></ListMetadataFormats></OAI-PMH>",
            ),
            id="nested-prefix",
        ),
        pytest.param(
            _document(
                "<OAI-PMH><ListMetadataFormats>",
                "<metadataPrefix>misowned</metadataPrefix>",
                "<metadataFormat><metadataPrefix>dim</metadataPrefix>",
                "</metadataFormat></ListMetadataFormats></OAI-PMH>",
            ),
            id="misowned-prefix",
        ),
    ],
)
def test_metadata_formats_require_exact_direct_oai_ownership(xml: str) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_metadata_formats(xml)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


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


def test_oai_record_rejects_arbitrary_namespace_contract_markers() -> None:
    """Mutation caught: matching the OAI required hierarchy by local name alone."""
    xml = _document(
        '<evil:OAI-PMH xmlns:evil="urn:attacker" ',
        'xmlns:dim="http://www.dspace.org/xmlns/dspace/dim">',
        "<evil:GetRecord><evil:record><evil:header><evil:identifier>",
        f"oai:dspace.nplg.gov.ge:{_ITEM_HANDLE}",
        "</evil:identifier></evil:header><evil:metadata>",
        '<dim:dim><dim:field mdschema="dc" element="title">',
        "Title</dim:field></dim:dim>",
        "</evil:metadata></evil:record></evil:GetRecord></evil:OAI-PMH>",
    )

    with pytest.raises(AppError, match="invalid root element") as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_oai_record_rejects_untrusted_identifier_namespace() -> None:
    """Mutation caught: accepting an attacker-controlled identifier prefix."""
    xml = _document(
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" ',
        'xmlns:dim="http://www.dspace.org/xmlns/dspace/dim">',
        "<GetRecord><record><header><identifier>",
        f"oai:untrusted.example:{_ITEM_HANDLE}",
        "</identifier></header><metadata>",
        '<dim:dim><dim:field mdschema="dc" element="title">',
        "Title</dim:field></dim:dim>",
        "</metadata></record></GetRecord></OAI-PMH>",
    )

    with pytest.raises(AppError, match="did not match the requested handle") as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix="dim",
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize("metadata_prefix", ["dim", "oai_dc"])
def test_oai_record_rejects_identifier_and_metadata_injected_outside_record(
    metadata_prefix: str,
) -> None:
    if metadata_prefix == "dim":
        injected_metadata = (
            '<metadata><field mdschema="dc" element="title">'
            "Injected title</field></metadata>"
        )
    else:
        injected_metadata = (
            '<metadata><dc xmlns="http://www.openarchives.org/OAI/2.0/oai_dc/" '
            'xmlns:terms="http://purl.org/dc/elements/1.1/">'
            "<terms:title>Injected title</terms:title></dc></metadata>"
        )
    xml = _document(
        "<OAI-PMH>",
        f"<identifier>oai:dspace:{_ITEM_HANDLE}</identifier>",
        injected_metadata,
        "<GetRecord><record><header /></record></GetRecord>",
        "</OAI-PMH>",
    )

    with pytest.raises(AppError) as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix=metadata_prefix,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    ("metadata_prefix", "xml"),
    [
        pytest.param(
            "dim",
            _document(
                "<Envelope><GetRecord><record><header><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                "</identifier></header>",
                _dim_metadata(),
                "</record></GetRecord></Envelope>",
            ),
            id="wrong-root",
        ),
        pytest.param(
            "dim",
            _document(
                "<OAI-PMH><wrapper><GetRecord><record><header><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                "</identifier></header>",
                _dim_metadata(),
                "</record></GetRecord></wrapper></OAI-PMH>",
            ),
            id="wrapped-get-record",
        ),
        pytest.param(
            "dim",
            _document(
                "<OAI-PMH><GetRecord><wrapper><record><header><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                "</identifier></header>",
                _dim_metadata(),
                "</record></wrapper></GetRecord></OAI-PMH>",
            ),
            id="wrapped-record",
        ),
        pytest.param(
            "dim",
            _document(
                "<OAI-PMH><GetRecord><record><wrapper><header><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                "</identifier></header></wrapper>",
                _dim_metadata(),
                "</record></GetRecord></OAI-PMH>",
            ),
            id="wrapped-header",
        ),
        pytest.param(
            "dim",
            _document(
                "<OAI-PMH><GetRecord><record><header><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                "</identifier></header><wrapper>",
                _dim_metadata(),
                "</wrapper></record></GetRecord></OAI-PMH>",
            ),
            id="wrapped-metadata",
        ),
        pytest.param(
            "dim",
            _document(
                "<OAI-PMH><GetRecord><record><header><wrapper><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                "</identifier></wrapper></header>",
                _dim_metadata(),
                "</record></GetRecord></OAI-PMH>",
            ),
            id="wrapped-identifier",
        ),
        pytest.param(
            "dim",
            _document(
                "<OAI-PMH><GetRecord><record><header />",
                "<metadata><identifier>oai:dspace:",
                _ITEM_HANDLE,
                '</identifier><dim><field mdschema="dc" element="title">',
                "Title</field></dim></metadata>",
                "</record></GetRecord></OAI-PMH>",
            ),
            id="identifier-under-metadata",
        ),
        pytest.param(
            "dim",
            _document(
                "<OAI-PMH><GetRecord><record><header><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                '</identifier><field mdschema="dc" element="title">',
                "Header title</field></header>",
                _dim_metadata(),
                "</record></GetRecord></OAI-PMH>",
            ),
            id="field-under-header",
        ),
        pytest.param(
            "dim",
            _document(
                "<OAI-PMH><GetRecord><record><header><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                "</identifier></header><metadata><dim><wrapper>",
                '<field mdschema="dc" element="title">Title</field>',
                "</wrapper></dim></metadata></record></GetRecord></OAI-PMH>",
            ),
            id="wrapped-dim-field",
        ),
        pytest.param(
            "oai_dc",
            _document(
                "<OAI-PMH><GetRecord><record><header><identifier>",
                f"oai:dspace:{_ITEM_HANDLE}",
                "</identifier></header><metadata><dc><wrapper>",
                "<title>Title</title></wrapper></dc></metadata>",
                "</record></GetRecord></OAI-PMH>",
            ),
            id="wrapped-dc-field",
        ),
    ],
)
def test_oai_record_rejects_non_direct_structural_ownership(
    metadata_prefix: str,
    xml: str,
) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix=metadata_prefix,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    "duplicate",
    [
        "header",
        "metadata",
        "identifier",
        "dim-container",
        "dc-container",
    ],
)
def test_oai_record_rejects_duplicate_owned_markers(duplicate: str) -> None:
    identifier = f"<identifier>oai:dspace:{_ITEM_HANDLE}</identifier>"
    header = f"<header>{identifier}</header>"
    metadata_prefix = "dim"
    metadata = _dim_metadata()
    if duplicate == "header":
        header += f"<header>{identifier}</header>"
    elif duplicate == "metadata":
        metadata += _dim_metadata("Second")
    elif duplicate == "identifier":
        header = f"<header>{identifier}{identifier}</header>"
    elif duplicate == "dim-container":
        metadata = (
            "<metadata><dim>"
            '<field mdschema="dc" element="title">Title</field>'
            '</dim><dim><field mdschema="dc" element="title">Second</field>'
            "</dim></metadata>"
        )
    else:
        metadata_prefix = "oai_dc"
        metadata = (
            "<metadata><dc><title>Title</title></dc>"
            "<dc><title>Second</title></dc></metadata>"
        )
    xml = (
        f"<OAI-PMH><GetRecord><record>{header}{metadata}</record></GetRecord></OAI-PMH>"
    )

    with pytest.raises(AppError) as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix=metadata_prefix,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    ("metadata_prefix", "metadata"),
    [("dim", _dim_metadata()), ("oai_dc", _dc_metadata())],
)
def test_oai_record_accepts_only_approved_direct_metadata_hierarchy(
    metadata_prefix: str,
    metadata: str,
) -> None:
    record = parse_oai_record(
        _oai_document(
            identifier=f"oai:dspace.nplg.gov.ge:{_ITEM_HANDLE}",
            metadata=metadata,
        ),
        expected_handle=_ITEM_HANDLE,
        metadata_prefix=metadata_prefix,
    )

    assert record.title == "Title"


def test_parser_counter_increment_saturates_at_one_past_the_limit() -> None:
    maximum = parser_module.PARSER_LIMITS.max_total_text_code_points

    assert (
        parser_module._saturating_increment(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            maximum,
            10**100,
            maximum=maximum,
        )
        == maximum + 1
    )


def test_xml_text_budget_keeps_exact_boundary_without_generic_saturation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: XML text accounting has its own exact fail-closed boundary."""
    parser_values = cast("dict[str, object]", vars(parser_module))
    validate_text_budget = cast(
        "_TextBudgetValidator", parser_values["_validate_text_budget"]
    )

    def forbidden_saturation(*_args: object, **_kwargs: object) -> int:
        _forbidden("XML text accounting must not invoke generic saturation")

    monkeypatch.setattr(parser_module, "_saturating_increment", forbidden_saturation)
    maximum = parser_module.PARSER_LIMITS.max_total_text_code_points

    assert validate_text_budget(0, None, source_url=_ITEM_SOURCE) == 0
    assert validate_text_budget(maximum, "", source_url=_ITEM_SOURCE) == maximum
    with pytest.raises(AppError, match="aggregate text limit") as raised:
        _ = validate_text_budget(maximum, "x", source_url=_ITEM_SOURCE)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE
    assert raised.value.safe_details == {"source_url": _ITEM_SOURCE}


def test_canonical_text_counter_keeps_chunked_semantics_without_unneeded_substitutions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: whitespace-free chunks preserve exact canonical text semantics."""
    parser_values = cast("dict[str, object]", vars(parser_module))
    expression = cast("re.Pattern[str]", parser_values["_WHITESPACE_RUN_RE"])
    counter_factory = cast(
        "Callable[[], _CanonicalTextCounterProtocol]",
        parser_values["_CanonicalTextCounter"],
    )
    probe = _WhitespaceRunProbe(expression)
    monkeypatch.setattr(parser_module, "_WHITESPACE_RUN_RE", probe)
    counter = counter_factory()

    chunks = ("alpha", "  ", "beta", "\n\t", "gamma")
    for chunk in chunks:
        counter.add(chunk)

    assert counter.code_points == sum(map(len, chunks))
    assert counter.semantic_code_points == len("alpha beta gamma")
    assert counter.in_whitespace is False
    assert probe.calls == ["  ", "\n\t"]


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
        identifier=f"oai:dspace.nplg.gov.ge:{_ITEM_HANDLE}",
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
        identifier=f"oai:{NPLG_HOST}:{_ITEM_HANDLE}",
        metadata=metadata,
    )

    with pytest.raises(AppError) as raised:
        _ = parse_oai_record(
            xml,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix=metadata_prefix,
        )

    assert raised.value.code is expected_code


def test_search_parser_rejects_more_items_than_the_requested_page_size() -> None:
    rows = "".join(
        (
            f'<tr><td><a href="/handle/1234/{index + 1}">Title {index}</a></td>'
            "<td></td><td></td></tr>"
        )
        for index in range(_EXCESSIVE_SEARCH_ROWS)
    )

    with pytest.raises(AppError, match="search item limit") as raised:
        _ = parse_search_results(
            _search_document(rows=rows),
            source_url=_SEARCH_SOURCE,
            page_size=_EXCESSIVE_SEARCH_ROWS - 1,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_full_item_parser_rejects_excessive_metadata_cardinality() -> None:
    rows = "".join(
        f"<tr><td>dc.subject</td><td>Subject {index}</td></tr>"
        for index in range(_EXCESSIVE_METADATA_FIELDS)
    )

    with pytest.raises(AppError, match="metadata field limit") as raised:
        _ = parse_item_page(
            _item_document(rows=rows, extra="Show full metadata record"),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_rejects_excessive_bitstream_cardinality() -> None:
    links = "".join(
        (
            f'<a href="/bitstream/{_ITEM_HANDLE}/{index}/file-{index}.pdf">'
            f"file-{index}.pdf</a>"
        )
        for index in range(_EXCESSIVE_BITSTREAMS)
    )

    with pytest.raises(AppError, match="bitstream limit") as raised:
        _ = parse_item_page(
            _item_document(extra=links),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_metadata_format_parser_rejects_excessive_cardinality() -> None:
    formats = "".join(
        (
            "<metadataFormat><metadataPrefix>"
            f"format_{index}"
            "</metadataPrefix></metadataFormat>"
        )
        for index in range(_EXCESSIVE_METADATA_FORMATS)
    )
    document = (
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/">'
        f"<ListMetadataFormats>{formats}</ListMetadataFormats></OAI-PMH>"
    )

    with pytest.raises(AppError, match="metadata format limit") as raised:
        _ = parse_metadata_formats(document)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_rejects_excessive_aggregate_text() -> None:
    rows = "".join(
        f"<tr><td>Subject:</td><td>{'x' * 65_000}</td></tr>" for _ in range(17)
    )

    with pytest.raises(AppError, match="aggregate text limit") as raised:
        _ = parse_item_page(
            _item_document(rows=rows),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_counts_all_whitespace_toward_the_aggregate_text_limit() -> None:
    """Mutation caught: collapsing a whitespace run before enforcing its budget."""
    document = _item_document(extra=f"<p>{' ' * _EXCESSIVE_TEXT_CODE_POINTS}</p>")

    with pytest.raises(AppError, match="aggregate text limit") as raised:
        _ = parse_item_page(
            document,
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_counts_whitespace_only_field_toward_field_limit() -> None:
    """Mutation caught: treating a whitespace-only metadata field as one character."""
    rows = (
        "<tr><td>Title:</td><td>Title</td></tr>"
        f"<tr><td>Subject:</td><td>{' ' * _EXCESSIVE_FIELD_CODE_POINTS}</td></tr>"
    )

    with pytest.raises(AppError, match="field code-point limit") as raised:
        _ = parse_item_page(
            _item_document(rows=rows),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_accepts_indented_markup_within_raw_text_limit() -> None:
    """Regression: normal DOM whitespace normalization is not parser drift."""
    document = _item_document(
        identity=f"\n  <code>{_ITEM_HANDLE}</code>\n",
        rows=("\n    <tr>\n      <td>Title:</td>\n      <td>Title</td>\n    </tr>\n"),
        extra="\n  <p>Formatting whitespace is valid.</p>\n",
    )

    item = parse_item_page(
        document,
        expected_handle=_ITEM_HANDLE,
        source_url=_ITEM_SOURCE,
    )

    assert item.title == "Title"


def test_item_parser_rejects_excessive_tree_depth() -> None:
    nested = (
        "<div>" * _EXCESSIVE_TREE_DEPTH + "payload" + "</div>" * _EXCESSIVE_TREE_DEPTH
    )

    with pytest.raises(AppError, match="tree depth limit") as raised:
        _ = parse_item_page(
            _item_document(extra=nested),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_html_preflight_handles_self_closing_comments_and_mismatched_end_tags() -> None:
    extra = (
        '<custom data-key="value" /></not-open><!--budgeted-comment--><div><span></div>'
    )

    item = parse_item_page(
        _item_document(extra=extra),
        expected_handle=_ITEM_HANDLE,
        source_url=_ITEM_SOURCE,
    )

    assert item.handle == _ITEM_HANDLE


def test_html_preflight_rejects_excessive_self_closing_elements_before_tree_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elements = "<custom />" * _EXCESSIVE_HTML_ELEMENTS

    def forbidden_tree_builder(*_args: object, **_kwargs: object) -> object:
        msg = "unbounded HTML tree construction was reached"
        raise AssertionError(msg)

    monkeypatch.setattr("nplg_mcp.parsers.BeautifulSoup", forbidden_tree_builder)

    with pytest.raises(AppError, match="HTML element limit") as raised:
        _ = parse_item_page(
            _item_document(extra=elements),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_rejects_excessive_html_element_count_before_tree_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elements = "<span></span>" * _EXCESSIVE_HTML_ELEMENTS

    def forbidden_tree_builder(*_args: object, **_kwargs: object) -> object:
        msg = "unbounded HTML tree construction was reached"
        raise AssertionError(msg)

    monkeypatch.setattr("nplg_mcp.parsers.BeautifulSoup", forbidden_tree_builder)

    with pytest.raises(AppError, match="HTML element limit") as raised:
        _ = parse_item_page(
            _item_document(extra=elements),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param(
            "<div>" * _EXCESSIVE_TREE_DEPTH
            + "payload"
            + "</div>" * _EXCESSIVE_TREE_DEPTH,
            id="depth",
        ),
        pytest.param(
            "<span></span>" * _EXCESSIVE_HTML_ELEMENTS,
            id="elements",
        ),
    ],
)
def test_html_post_parse_budget_remains_a_defense_in_depth_check(
    monkeypatch: pytest.MonkeyPatch,
    extra: str,
) -> None:
    def skip_preflight(_html: str, *, source_url: str) -> None:
        del source_url

    monkeypatch.setattr("nplg_mcp.parsers._preflight_html", skip_preflight)

    with pytest.raises(AppError, match=r"tree depth limit|HTML element limit"):
        _ = parse_item_page(
            _item_document(extra=extra),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )


def test_metadata_parser_rejects_excessive_xml_element_count_before_tree_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elements = "<entry />" * _EXCESSIVE_XML_ELEMENTS
    document = (
        f"<OAI-PMH><ListMetadataFormats>{elements}</ListMetadataFormats></OAI-PMH>"
    )

    def forbidden_tree_builder(_xml: str) -> object:
        msg = "unbounded XML tree construction was reached"
        raise AssertionError(msg)

    monkeypatch.setattr(
        "nplg_mcp.parsers.DefusedElementTree.fromstring",
        forbidden_tree_builder,
    )

    with pytest.raises(AppError, match="XML element limit") as raised:
        _ = parse_metadata_formats(document)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_metadata_parser_rejects_excessive_xml_tree_depth() -> None:
    nested = "<wrapper>" * _EXCESSIVE_TREE_DEPTH
    closing = "</wrapper>" * _EXCESSIVE_TREE_DEPTH
    document = (
        f"<OAI-PMH>{nested}<metadataPrefix>dim</metadataPrefix>{closing}</OAI-PMH>"
    )

    with pytest.raises(AppError, match="tree depth limit") as raised:
        _ = parse_metadata_formats(document)

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(
            "<OAI-PMH>"
            + "<wrapper>" * _EXCESSIVE_TREE_DEPTH
            + "<metadataPrefix>dim</metadataPrefix>"
            + "</wrapper>" * _EXCESSIVE_TREE_DEPTH
            + "</OAI-PMH>",
            id="depth",
        ),
        pytest.param(
            "<OAI-PMH><ListMetadataFormats>"
            + "<entry />" * _EXCESSIVE_XML_ELEMENTS
            + "</ListMetadataFormats></OAI-PMH>",
            id="elements",
        ),
    ],
)
def test_xml_post_parse_budget_remains_a_defense_in_depth_check(
    monkeypatch: pytest.MonkeyPatch,
    document: str,
) -> None:
    def skip_preflight(_xml: str) -> None:
        return

    monkeypatch.setattr("nplg_mcp.parsers._preflight_xml", skip_preflight)

    with pytest.raises(AppError, match=r"tree depth limit|XML element limit"):
        _ = parse_metadata_formats(document)


def test_summary_item_parser_rejects_excessive_metadata_cardinality() -> None:
    rows = "".join(
        f"<tr><td>Subject:</td><td>Subject {index}</td></tr>"
        for index in range(_EXCESSIVE_METADATA_FIELDS)
    )

    with pytest.raises(AppError, match="metadata field limit") as raised:
        _ = parse_item_page(
            _item_document(rows=rows),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


def test_item_parser_rejects_excessive_collection_cardinality() -> None:
    links = "".join(
        f'<a href="/handle/1234/{index + 1}">Collection {index}</a>'
        for index in range(_EXCESSIVE_COLLECTIONS)
    )
    rows = (
        "<tr><td>Title:</td><td>Title</td></tr>"
        f"<tr><td>Appears in Collections:</td><td>{links}</td></tr>"
    )

    with pytest.raises(AppError, match="collection limit") as raised:
        _ = parse_item_page(
            _item_document(rows=rows),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize("metadata_prefix", ["dim", "oai_dc"])
def test_oai_parser_rejects_excessive_metadata_cardinality(
    metadata_prefix: str,
) -> None:
    if metadata_prefix == "dim":
        fields = "".join(
            f'<field mdschema="dc" element="subject">Subject {index}</field>'
            for index in range(_EXCESSIVE_METADATA_FIELDS)
        )
        metadata = f"<metadata>{fields}</metadata>"
    else:
        fields = "".join(
            f"<terms:subject>Subject {index}</terms:subject>"
            for index in range(_EXCESSIVE_METADATA_FIELDS)
        )
        metadata = (
            '<metadata><dc xmlns="http://www.openarchives.org/OAI/2.0/oai_dc/" '
            'xmlns:terms="http://purl.org/dc/elements/1.1/">'
            f"{fields}</dc></metadata>"
        )
    document = _oai_document(
        identifier=f"oai:dspace:{_ITEM_HANDLE}",
        metadata=metadata,
    )

    with pytest.raises(AppError, match="metadata field limit") as raised:
        _ = parse_oai_record(
            document,
            expected_handle=_ITEM_HANDLE,
            metadata_prefix=metadata_prefix,
        )

    assert raised.value.code is ErrorCode.UPSTREAM_FAILURE


@pytest.mark.parametrize("page_size", [0, 51, True, 1.0])
def test_search_parser_rejects_invalid_page_size_types_and_bounds(
    page_size: object,
) -> None:
    with pytest.raises(AppError, match="page_size") as raised:
        _ = parse_search_results(
            _search_document(),
            source_url=_SEARCH_SOURCE,
            page_size=cast("int", page_size),
        )

    assert raised.value.code is ErrorCode.INVALID_INPUT
