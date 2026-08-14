from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Iterable
from urllib.parse import parse_qs, urljoin, urlsplit

from bs4 import BeautifulSoup, Tag
from defusedxml import ElementTree as DefusedElementTree

from .errors import AppError, ErrorCode
from .security import NPLG_ORIGIN, parse_handle_input, validate_upstream_url

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


@dataclass(frozen=True, slots=True)
class RawMetadataField:
    key: str
    value: str
    language: str | None = None


@dataclass(frozen=True, slots=True)
class SearchItem:
    handle: str
    canonical_url: str
    title: str
    issue_date: str | None = None
    authors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Bitstream:
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
    items: tuple[SearchItem, ...]
    total: int
    next_offset: int | None
    source_url: str
    next_cursor: str | None = None

    def with_cursor(self, cursor: str | None) -> "SearchPage":
        return replace(self, next_cursor=cursor)


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


def _upstream_failure(message: str, *, source_url: str | None = None, cause: BaseException | None = None) -> AppError:
    details = {"source_url": source_url} if source_url else None
    internal = {"cause": repr(cause)} if cause else None
    return AppError(
        ErrorCode.UPSTREAM_FAILURE,
        message,
        http_status=502,
        safe_details=details,
        internal_details=internal,
    )


def _tag_text(tag: Tag | None) -> str:
    return _normalize(tag.get_text(" ", strip=True)) if tag is not None else ""


def _canonical_item_from_href(href: str, *, source_url: str) -> tuple[str, str]:
    absolute = urljoin(source_url, href)
    validate_upstream_url(absolute)
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
            return datetime.strptime(normalized, fmt).date().isoformat()
        except ValueError:
            pass
    return normalized


def parse_search_results(html: str, *, source_url: str) -> SearchPage:
    soup = BeautifulSoup(html, "lxml")
    container = soup.find(id="aspect_discovery_SimpleSearch_div_search-results")
    if not isinstance(container, Tag):
        raise _upstream_failure("The repository search response did not match the expected DSpace contract.", source_url=source_url)

    table = container.find("table", class_=lambda value: value and "search-results" in value)
    if not isinstance(table, Tag):
        raise _upstream_failure("The repository search response did not contain a results table.", source_url=source_url)

    header_cells = [_tag_text(cell).lower() for cell in table.select("thead th")]
    try:
        title_index = next(index for index, text in enumerate(header_cells) if text == "title")
    except StopIteration as exc:
        raise _upstream_failure("The repository search table did not contain a title column.", source_url=source_url) from exc
    date_index = next((index for index, text in enumerate(header_cells) if "date" in text), None)
    author_index = next((index for index, text in enumerate(header_cells) if "author" in text), None)

    items: list[SearchItem] = []
    for row in table.select("tbody tr"):
        cells = row.find_all("td", recursive=False)
        if title_index >= len(cells):
            continue
        title_cell = cells[title_index]
        link = title_cell.find("a", href=True)
        if not isinstance(link, Tag):
            continue
        try:
            handle, canonical_url = _canonical_item_from_href(str(link["href"]), source_url=source_url)
        except AppError as exc:
            raise _upstream_failure("The repository returned an unsafe or malformed item link.", source_url=source_url, cause=exc) from exc
        title = _tag_text(link)
        if not title:
            raise _upstream_failure("The repository returned a search item without a title.", source_url=source_url)
        issue_date = _normalize_date(_tag_text(cells[date_index]) if date_index is not None and date_index < len(cells) else None)
        authors_text = _tag_text(cells[author_index]) if author_index is not None and author_index < len(cells) else ""
        authors = _unique(piece for piece in authors_text.split(";") if piece.strip())
        items.append(SearchItem(handle=handle, canonical_url=canonical_url, title=title, issue_date=issue_date, authors=authors))

    context_text = _tag_text(container)
    total_match = _TOTAL_RE.search(context_text)
    if total_match is None:
        total = len(items)
    else:
        total = int(total_match.group(1).replace(",", ""))

    next_offset: int | None = None
    next_link = container.find("a", class_=lambda value: value and "next-page-link" in value, href=True)
    if not isinstance(next_link, Tag):
        next_link = next((a for a in container.find_all("a", href=True) if _tag_text(a).lower() in {"next", "next page", ">"}), None)
    if isinstance(next_link, Tag):
        absolute = urljoin(source_url, str(next_link["href"]))
        try:
            validate_upstream_url(absolute)
        except AppError as exc:
            raise _upstream_failure("The repository returned an unsafe pagination link.", source_url=source_url, cause=exc) from exc
        raw_start = parse_qs(urlsplit(absolute).query).get("start", [None])[0]
        if raw_start is not None:
            try:
                parsed_offset = int(raw_start)
            except ValueError as exc:
                raise _upstream_failure("The repository returned an invalid pagination offset.", source_url=source_url, cause=exc) from exc
            if parsed_offset < 0:
                raise _upstream_failure("The repository returned a negative pagination offset.", source_url=source_url)
            next_offset = parsed_offset

    return SearchPage(items=tuple(items), total=total, next_offset=next_offset, source_url=source_url)


def _parse_size(value: str) -> int | None:
    normalized = _normalize(value)
    match = _SIZE_RE.fullmatch(normalized)
    if match is None:
        return None
    amount = float(match.group(1))
    unit = match.group(2).upper()
    multiplier = {"B": 1, "KB": 1_000, "MB": 1_000_000, "GB": 1_000_000_000, "TB": 1_000_000_000_000}[unit]
    return int(amount * multiplier)


def _bitstream_id(handle: str, source_url: str) -> str:
    digest = hashlib.sha256(f"{handle}\n{source_url}".encode("utf-8")).hexdigest()
    return f"bit_{digest[:24]}"


def _parse_bitstreams(soup: BeautifulSoup, *, handle: str, source_url: str, restricted: bool) -> tuple[Bitstream, ...]:
    if restricted:
        return ()
    result: list[Bitstream] = []
    seen_urls: set[str] = set()
    for link in soup.select('a[href*="/bitstream/"]'):
        if not isinstance(link, Tag):
            continue
        href = str(link.get("href", ""))
        absolute = urljoin(source_url, href)
        try:
            validate_upstream_url(absolute)
        except AppError as exc:
            raise _upstream_failure("The item page returned an unsafe bitstream link.", source_url=source_url, cause=exc) from exc
        expected_prefix = f"/bitstream/{handle}/"
        if not urlsplit(absolute).path.startswith(expected_prefix):
            raise _upstream_failure("The item page returned a bitstream bound to another handle.", source_url=source_url)
        if absolute in seen_urls:
            continue
        row = link.find_parent("tr")
        cells = row.find_all("td", recursive=False) if isinstance(row, Tag) else []
        filename = _tag_text(link) or urlsplit(absolute).path.rsplit("/", 1)[-1]
        # The View/Open link duplicates the file link. Ignore it when another link in the row carries the filename.
        if filename.lower() in {"view/open", "open", "view"} and isinstance(row, Tag):
            first = row.find("a", href=href)
            if isinstance(first, Tag) and first is not link:
                continue
        description = _tag_text(cells[1]) if len(cells) > 1 else None
        size = _parse_size(_tag_text(cells[2])) if len(cells) > 2 else None
        reported_format = _tag_text(cells[3]) if len(cells) > 3 else None
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


def _field_values(fields: tuple[RawMetadataField, ...], *keys: str, prefixes: tuple[str, ...] = ()) -> tuple[str, ...]:
    return _unique(
        field.value
        for field in fields
        if field.key in keys or any(field.key.startswith(prefix) for prefix in prefixes)
    )


def _record_from_fields(
    *,
    handle: str,
    fields: tuple[RawMetadataField, ...],
    collections: tuple[str, ...] = (),
    bitstreams: tuple[Bitstream, ...] = (),
    restricted: bool = False,
    restriction_reason: str | None = None,
    metadata_source: str,
    fallback_title: str | None = None,
) -> DocumentRecord:
    titles = _field_values(fields, "dc.title")
    title = titles[0] if titles else (_normalize(fallback_title or "") or handle)
    issue_dates = _field_values(fields, "dc.date.issued")
    creators = _field_values(fields, "dc.creator")
    contributors = _field_values(fields, prefixes=("dc.contributor",))
    publishers = _field_values(fields, "dc.publisher")
    descriptions = _field_values(fields, "dc.description", prefixes=("dc.description.",))
    subjects = _field_values(fields, "dc.subject", prefixes=("dc.subject.",))
    languages = _field_values(fields, "dc.language", "dc.language.iso", prefixes=("dc.language.",))
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
        collections=collections,
        types=types,
        raw_fields=fields,
        bitstreams=bitstreams,
        restricted=restricted,
        restriction_reason=restriction_reason,
        metadata_source=metadata_source,
    )


def _extract_handle(soup: BeautifulSoup) -> str | None:
    for code in soup.find_all("code"):
        text = _tag_text(code)
        try:
            return parse_handle_input(text)
        except AppError:
            continue
    for link in soup.find_all("a", href=True):
        href = str(link["href"])
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
        if len(cells) < 2:
            continue
        label = _tag_text(cells[0]).rstrip(":").strip().lower()
        key = mapping.get(label)
        if key is None:
            continue
        value = _tag_text(cells[1])
        if value:
            fields.append(RawMetadataField(key=key, value=value))
    return tuple(fields)


def _full_fields(soup: BeautifulSoup) -> tuple[RawMetadataField, ...]:
    fields: list[RawMetadataField] = []
    for row in soup.select("table.itemDisplayTable tr"):
        cells = row.find_all("td", recursive=False)
        if len(cells) < 2:
            continue
        key = _tag_text(cells[0])
        if not _DC_KEY_RE.fullmatch(key):
            continue
        value = _tag_text(cells[1])
        language = _tag_text(cells[2]) if len(cells) > 2 else ""
        if not value:
            continue
        fields.append(RawMetadataField(key=key, value=value, language=None if language in {"", "-"} else language))
    return tuple(fields)


def _collections(soup: BeautifulSoup) -> tuple[str, ...]:
    values: list[str] = []
    for row in soup.select("table.itemDisplayTable tr"):
        cells = row.find_all("td", recursive=False)
        if len(cells) >= 2 and _tag_text(cells[0]).rstrip(":").lower() == "appears in collections":
            links = [_tag_text(link) for link in cells[1].find_all("a")]
            values.extend(links or [_tag_text(cells[1])])
    if not values:
        for paragraph in soup.find_all(["p", "div"]):
            text = _tag_text(paragraph)
            if text.lower().startswith("appears in collections:"):
                links = [_tag_text(link) for link in paragraph.find_all("a")]
                values.extend(links or [text.split(":", 1)[1]])
                break
    return _unique(values)


def parse_item_page(html: str, *, expected_handle: str, source_url: str) -> DocumentRecord:
    expected = parse_handle_input(expected_handle)
    soup = BeautifulSoup(html, "lxml")
    container = soup.find(id="aspect_artifactbrowser_ItemViewer_div_item-view")
    if not isinstance(container, Tag):
        raise _upstream_failure("The item response did not match the expected DSpace contract.", source_url=source_url)
    actual = _extract_handle(soup)
    if actual is None or actual != expected:
        raise _upstream_failure("The item response did not match the requested handle.", source_url=source_url)

    page_text = _tag_text(soup).lower()
    matching_restrictions = [marker for marker in _RESTRICTED_MARKERS if marker in page_text]
    restricted = bool(matching_restrictions)
    restriction_reason = "Access is limited to the library's internal network or building." if restricted else None

    is_full = bool(soup.find(string=lambda value: isinstance(value, str) and "full metadata record" in value.lower())) or any(
        _DC_KEY_RE.fullmatch(_tag_text(cell)) is not None for cell in soup.select("table.itemDisplayTable td:first-child")
    )
    fields = _full_fields(soup) if is_full else _summary_fields(soup)
    if not fields:
        raise _upstream_failure("The item response did not contain recognizable metadata.", source_url=source_url)

    collections = _collections(soup)
    bitstreams = _parse_bitstreams(soup, handle=expected, source_url=source_url, restricted=restricted)
    title_tag = soup.find("title")
    fallback_title = _tag_text(title_tag).removeprefix("Iverieli:").strip() if isinstance(title_tag, Tag) else expected
    return _record_from_fields(
        handle=expected,
        fields=fields,
        collections=collections,
        bitstreams=bitstreams,
        restricted=restricted,
        restriction_reason=restriction_reason,
        metadata_source="xmlui_full" if is_full else "xmlui_summary",
        fallback_title=fallback_title,
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml(xml: str):
    try:
        return DefusedElementTree.fromstring(xml)
    except (DefusedElementTree.ParseError, ValueError) as exc:
        raise _upstream_failure("The repository returned malformed OAI-PMH XML.", cause=exc) from exc


def _first_descendant(root, name: str):
    return next((element for element in root.iter() if _local_name(element.tag) == name), None)


def parse_metadata_formats(xml: str) -> tuple[str, ...]:
    root = _parse_xml(xml)
    error = _first_descendant(root, "error")
    if error is not None:
        raise _upstream_failure("The repository rejected the OAI-PMH metadata format request.")
    formats = _unique(element.text for element in root.iter() if _local_name(element.tag) == "metadataPrefix")
    if not formats:
        raise _upstream_failure("The repository returned no OAI-PMH metadata formats.")
    return formats


def parse_oai_record(xml: str, *, expected_handle: str, metadata_prefix: str) -> DocumentRecord:
    expected = parse_handle_input(expected_handle)
    root = _parse_xml(xml)
    error = _first_descendant(root, "error")
    if error is not None:
        code = error.attrib.get("code", "unknown")
        raise AppError(
            ErrorCode.UPSTREAM_FAILURE,
            "The repository could not return the requested OAI-PMH record.",
            http_status=502,
            safe_details={"oai_error": code},
        )

    identifier_element = _first_descendant(root, "identifier")
    if identifier_element is None or not identifier_element.text:
        raise _upstream_failure("The OAI-PMH record did not contain an identifier.")
    identifier_text = _normalize(identifier_element.text)
    if not identifier_text.endswith(f":{expected}"):
        raise _upstream_failure("The OAI-PMH record did not match the requested handle.")

    prefix = metadata_prefix.strip()
    fields: list[RawMetadataField] = []
    if prefix == "dim":
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
                fields.append(RawMetadataField(key=key, value=value, language=element.attrib.get("lang")))
        source = "oai_dim"
    elif prefix == "oai_dc":
        metadata = _first_descendant(root, "metadata")
        if metadata is None:
            raise _upstream_failure("The OAI-PMH record did not contain metadata.")
        for element in metadata.iter():
            name = _local_name(element.tag)
            if name in {"metadata", "dc"}:
                continue
            value = _normalize(element.text or "")
            if value:
                fields.append(RawMetadataField(key=f"dc.{name}", value=value, language=element.attrib.get("{http://www.w3.org/XML/1998/namespace}lang")))
        source = "oai_dc"
    else:
        raise AppError(ErrorCode.INVALID_INPUT, "Unsupported OAI-PMH metadata format.", safe_details={"metadata_prefix": prefix})

    if not fields:
        raise _upstream_failure("The OAI-PMH record did not contain usable metadata fields.")
    return _record_from_fields(handle=expected, fields=tuple(fields), metadata_source=source)
