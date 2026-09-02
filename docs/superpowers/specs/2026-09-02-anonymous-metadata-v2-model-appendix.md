# NPLG Anonymous Metadata v2 — Proposed Normative Model Appendix

**Status:** DRAFT / NON-EXECUTABLE — exact breaking-contract approval required

**Date:** 2026-09-02

**Parent contract:**
[`2026-09-02-anonymous-metadata-v2-contract.md`](2026-09-02-anonymous-metadata-v2-contract.md)

This appendix gives the complete proposed wire shapes. It is jointly normative
with the parent contract only after explicit approval. It authorizes no source,
dependency, lock, Git, hosted, staging, or production change.

The metadata-key inventory in the parent contract remains a prerequisite to
approval. The exact draft below proposes destinations for citation,
series/report, ISMN, sponsors, `isPartOf`, and `isFormatOf`; inventory evidence
may remove or revise them only through another reviewed schema diff. There are
no implicit or placeholder response fields.

## 1. Contract authority and serialization

Pydantic 2.13.5 is the sole runtime and semantic authority for this proposal.
After approval, the project generates Draft 2020-12 JSON Schema with
`model_json_schema(mode="serialization")`. Every model recursively uses:

```python
class StrictWireModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_default=True,
        frozen=True,
    )
```

The declarations below are normative model fragments. `Field(max_length=N)`
means JSON Schema `maxItems` on an array and `maxLength` on a string. Every
custom scalar validator named below is defined by the parent contract; it
checks the stated UTF-8 and semantic constraints in Python and is not
duplicated in JavaScript.

### 1.1 Required, default, null, and ownership rules

- Every response-model field is required and has no Pydantic default.
- A nullable response field is always present and serializes as JSON `null`
  when it has no value.
- Every response array is always present, including when it is an empty JSON
  array.
- Each response array is an immutable owned tuple inside the application and
  serializes as a JSON array. No output tuple aliases an input JSON list.
- At the decoded MCP argument boundary, `filters` accepts an exact JSON list
  and copies it to a tuple; JSON cannot carry a tuple. Model-internal tuples
  and the tuple default remain valid, while null, sets, mappings, strings, and
  arbitrary iterables are rejected.
- Wire discriminants, fields, operators, sort values, and order values are
  `Literal[...]`, not strict `StrEnum` instances. Internal enums may be created
  only after public validation.
- Omitted input fields receive the defaults stated in section 2. JSON `null`
  is accepted only where the annotation is explicitly nullable. For global
  search, null `sort` or `order` is the documented unspecified sentinel and
  resolves exactly like omission; section 2 defines that sole nullable-default
  exception.

The exact ownership adapter is:

```python
def own_json_array(value: object) -> object:
    if type(value) is list:
        return tuple(value)
    return value
```

Array fields use this metadata order, which is significant under the locked
Pydantic version:

```python
OwnedFilters8 = Annotated[
    tuple[SearchTextFilterV2 | IssuedYearRangeFilterV2, ...],
    Field(max_length=8),
    BeforeValidator(own_json_array),
]
```

The same `Field(...), BeforeValidator(...)` order applies to all owned tuple
aliases below.

### 1.2 Scalar aliases

| Alias | JSON shape and bound | Python-only semantic rule |
| --- | --- | --- |
| `Handle` | string, 3–65 ASCII chars, `^[1-9][0-9]{0,31}/[1-9][0-9]{0,31}$` | canonical handle |
| `RepositoryRootUrl` | literal `https://dspace.nplg.gov.ge` | none |
| `CanonicalItemUrl` | string, at most 256 ASCII chars | exact fixed-origin `/handle/{handle}` URL; no userinfo, port, query, or fragment |
| `CanonicalDirectBitstreamUrl` | string, at most 2,048 ASCII chars | fixed-origin canonical direct-bitstream URL; no userinfo, port, query, or fragment; handle equals the containing record handle |
| `QueryText500` | non-empty string, at most 500 scalars and 2,048 UTF-8 bytes | common scalar policy plus basic-query policy |
| `SearchFilterText256` | non-empty string, at most 256 scalars and 1,024 UTF-8 bytes | common scalar policy and raw-range rejection |
| `MetadataText8192` | non-empty string, at most 8,192 scalars and 32,768 UTF-8 bytes | common scalar policy |
| `SearchName256` | non-empty string, at most 256 scalars and 1,024 UTF-8 bytes | common scalar policy |
| `Text64` | non-empty string, at most 64 scalars and 256 UTF-8 bytes | common scalar policy |
| `Text256` | non-empty string, at most 256 scalars and 1,024 UTF-8 bytes | common scalar policy |
| `Filename1024` | non-empty string, at most 1,024 scalars and 4,096 UTF-8 bytes | common scalar policy; basename only |
| `CursorText1024` | string, 1–1,024 ASCII chars | opaque signed-cursor syntax |
| `SafeNonnegativeInteger` | integer, 0–9,007,199,254,740,991 | exact JSON integer; booleans/floats rejected |
| `PageSize` | integer, 1–50 | exact JSON integer |
| `Year` | integer, 1–9,999 | exact JSON integer |

String lengths in JSON Schema cover scalar length. The named Python validators
add UTF-8 and project-specific checks that JSON Schema cannot express.

## 2. Exact tool inputs

The two handle-only tools have no defaults:

```python
class GetDocumentMetadataInputV2(StrictWireModel):
    handle: Handle


class ListDocumentFilesInputV2(StrictWireModel):
    handle: Handle
```

### 2.1 Exact `search_documents` input

```python
SearchTextFieldV2 = Literal[
    "title",
    "author_index",
    "subject",
    "type",
    "language",
]
SearchTextOperatorV2 = Literal["equals", "contains"]
SearchSortV2 = Literal["relevance", "title", "issued_date"]
SearchOrderV2 = Literal["asc", "desc"]


class SearchTextFilterV2(StrictWireModel):
    kind: Literal["text"]
    field: SearchTextFieldV2
    operator: SearchTextOperatorV2
    value: SearchFilterText256


class IssuedYearRangeFilterV2(StrictWireModel):
    kind: Literal["issued_year_range"]
    from_year: Year
    to_year: Year


SearchFilterV2 = Annotated[
    SearchTextFilterV2 | IssuedYearRangeFilterV2,
    Field(discriminator="kind"),
]

OwnedFilters8 = Annotated[
    tuple[SearchFilterV2, ...],
    Field(max_length=8),
    BeforeValidator(own_json_array),
]


class SearchDocumentsInputV2(StrictWireModel):
    query: QueryText500 | None = None
    filters: OwnedFilters8 = ()
    sort: SearchSortV2 | None = None
    order: SearchOrderV2 | None = None
    page_size: PageSize = 20
    scope_handle: Handle | None = None
    cursor: CursorText1024 | None = None
```

Semantic validation is exact:

1. `query` is non-null or `filters` is non-empty.
2. Filters are unique after validation; order remains significant.
3. Each issued-year range satisfies `from_year <= to_year`.
4. `sort="relevance"` requires a non-null query.
5. `order` without `sort` is invalid.
6. With non-null `scope_handle`, `query` is non-null, `filters == ()`, and both
   `sort` and `order` are null, whether omitted or explicitly null. Scoped typed
   controls are not in this profile.
7. In global search, explicit null `sort` or `order` means unspecified and is
   resolved exactly as an omitted field: query-plus-null-sort becomes
   relevance/descending; filter-only-plus-null-sort becomes
   issued-date/descending; explicit title-plus-null-order becomes ascending;
   and any other explicit sort plus null order becomes descending.
8. The parent contract's deterministic rules therefore produce non-null
   resolved sort and order in every successful response.
9. `filters: null` is invalid. Omitted `filters` and `filters: []` both produce
   a newly owned empty tuple.

A normal decoded JSON object containing string values and a filter list is the
required boundary case; callers never need to construct Python enums or
tuples.

## 3. Shared warning and coverage vocabulary

```python
WarningCodeV2 = Literal[
    "TECHNICAL_PROVENANCE_OMITTED",
    "FIELD_SPECIFIC_CONTACT_OMITTED",
    "OVERSIZE_VALUE_OMITTED",
    "DESTINATION_CARDINALITY_LIMIT_APPLIED",
    "METADATA_AGGREGATE_BUDGET_APPLIED",
    "SEARCH_AGGREGATE_BUDGET_APPLIED",
    "FILE_AGGREGATE_BUDGET_APPLIED",
    "TOOL_OUTPUT_BUDGET_APPLIED",
]
```

Warnings are unique and sorted in exactly the order above. Coverage causes are
unique and retain the same relative order. They contain codes only: never a
source value, field value, URL, query fragment, exception, or free-form detail.

Technical provenance is outside the eligible public evidence universe, so its
unconditional removal emits a warning but does not make coverage partial.
Unreviewed keys are also outside that universe and emit neither a warning nor
a partial-coverage claim. All other omission codes describe loss from an
otherwise eligible public projection and therefore affect the corresponding
coverage dimension.

## 4. Exact `get_document_metadata` output

```python
SchemaVersionV2 = Literal["2"]

MetadataOmissionCauseV2 = Literal[
    "FIELD_SPECIFIC_CONTACT_OMITTED",
    "OVERSIZE_VALUE_OMITTED",
    "DESTINATION_CARDINALITY_LIMIT_APPLIED",
    "METADATA_AGGREGATE_BUDGET_APPLIED",
    "TOOL_OUTPUT_BUDGET_APPLIED",
]

MetadataWarningCodeV2 = Literal[
    "TECHNICAL_PROVENANCE_OMITTED",
    "FIELD_SPECIFIC_CONTACT_OMITTED",
    "OVERSIZE_VALUE_OMITTED",
    "DESTINATION_CARDINALITY_LIMIT_APPLIED",
    "METADATA_AGGREGATE_BUDGET_APPLIED",
    "TOOL_OUTPUT_BUDGET_APPLIED",
]


class MetadataCoverageV2(StrictWireModel):
    state: Literal["complete", "partial"]
    omission_causes: Annotated[
        tuple[MetadataOmissionCauseV2, ...],
        Field(max_length=5),
        BeforeValidator(own_json_array),
    ]


class MetadataAccessV2(StrictWireModel):
    record_state: Literal["anonymous_metadata_visible"]
    file_state: Literal["not_assessed"]


class BibliographicAgentV2(StrictWireModel):
    name: MetadataText8192
    role: Literal["creator", "author", "editor", "advisor", "contributor"]


class BibliographicIdentifierV2(StrictWireModel):
    kind: Literal["uri", "isbn", "issn", "ismn", "other"]
    value: MetadataText8192


class SeriesReportV2(StrictWireModel):
    title: MetadataText8192 | None
    number: MetadataText8192 | None


class BibliographicRelationV2(StrictWireModel):
    kind: Literal["is_part_of", "is_format_of"]
    value: MetadataText8192


class DocumentMetadataOutput(StrictWireModel):
    schema_version: SchemaVersionV2
    handle: Handle
    item_url: CanonicalItemUrl
    title: MetadataText8192 | None
    issued_date: Text64 | None
    alternative_titles: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=32),
        BeforeValidator(own_json_array),
    ]
    agents: Annotated[
        tuple[BibliographicAgentV2, ...],
        Field(max_length=128),
        BeforeValidator(own_json_array),
    ]
    publishers: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=32),
        BeforeValidator(own_json_array),
    ]
    abstracts: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=16),
        BeforeValidator(own_json_array),
    ]
    descriptions: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=64),
        BeforeValidator(own_json_array),
    ]
    tables_of_contents: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=8),
        BeforeValidator(own_json_array),
    ]
    bibliographic_citations: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=32),
        BeforeValidator(own_json_array),
    ]
    series_reports: Annotated[
        tuple[SeriesReportV2, ...],
        Field(max_length=32),
        BeforeValidator(own_json_array),
    ]
    sponsors: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=32),
        BeforeValidator(own_json_array),
    ]
    subjects: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=256),
        BeforeValidator(own_json_array),
    ]
    languages: Annotated[
        tuple[Text64, ...],
        Field(max_length=64),
        BeforeValidator(own_json_array),
    ]
    types: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=64),
        BeforeValidator(own_json_array),
    ]
    identifiers: Annotated[
        tuple[BibliographicIdentifierV2, ...],
        Field(max_length=128),
        BeforeValidator(own_json_array),
    ]
    relations: Annotated[
        tuple[BibliographicRelationV2, ...],
        Field(max_length=64),
        BeforeValidator(own_json_array),
    ]
    rights_statements: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=64),
        BeforeValidator(own_json_array),
    ]
    rights_holders: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=64),
        BeforeValidator(own_json_array),
    ]
    licenses: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=32),
        BeforeValidator(own_json_array),
    ]
    collections: Annotated[
        tuple[MetadataText8192, ...],
        Field(max_length=128),
        BeforeValidator(own_json_array),
    ]
    bibliographic_source: Literal["oai_dim", "oai_dc", "jspui_item"]
    access: MetadataAccessV2
    coverage: MetadataCoverageV2
    warnings: Annotated[
        tuple[MetadataWarningCodeV2, ...],
        Field(max_length=6),
        BeforeValidator(own_json_array),
    ]
```

`bibliographic_source` records the single source used by the retained current
fallback order: DIM first, then OAI DC, then the validated JSPUI item page. It
does not claim equivalent richness. Each source has its own closed reviewed
mapping; values are not blended across fallbacks, and a fallback cannot create
a role or destination it does not source-qualify. Changing that priority is the
deferred cross-format study, not part of this contract.

`SeriesReportV2` requires at least one non-null member. `issued_date` is sourced
only from the reviewed issued-date key for the selected source; null is absence
or bounded omission, never an inferred date. `dc.creator` maps only to
`role="creator"`. A handle is never used as a title. `licenses` contains only
reviewed public reuse-licence source keys; a DSpace deposit licence is
ineligible. Access is an independent factual state and is not derived from
coverage, rights, or licence.

`bibliographic_citations` contains only verbatim values from an approved
citation source key. It is not generated citation text. Series/report,
sponsor, relation, and identifier kinds likewise require the inventory's exact
source-key mapping; the field names alone are not permission to infer them.

Every nested metadata object is an atomic destination entry. A source-absent
`SeriesReportV2` member remains null, but the projector MUST NOT null a
source-present member to make the entry fit. If any present member of a
`SeriesReportV2`, `BibliographicAgentV2`, `BibliographicIdentifierV2`, or
`BibliographicRelationV2` candidate is oversize or the complete object cannot
fit the applicable aggregate/final budget, the whole candidate is omitted with
the first applicable cause. This preserves the at-least-one-member invariant
and makes nested-object fitting deterministic.

All bibliographic arrays are exact-de-duplicated in source order. The total
number of eligible destination entries admitted before final result fitting is
at most 512.

The metadata model validator requires `coverage.state="complete"` exactly when
`coverage.omission_causes` is empty, and `partial` exactly when it is non-empty.
`coverage.omission_causes` equals `warnings` after removing only
`TECHNICAL_PROVENANCE_OMITTED`; no other warning may be coverage-neutral and no
coverage cause may be absent from `warnings`.

It also requires `item_url == canonical_item_url(handle)`; a different valid
NPLG item URL is not accepted.

Metadata coverage is limited to eligible values observed in the selected
`bibliographic_source`. `complete` never claims equality with every repository
format, hidden field, restricted record, or unobserved value.

## 5. Exact `search_documents` output

```python
QueryKindV2 = Literal["plain_text", "simple_quoted_phrase"]
VisibleMatchFieldV2 = Literal["title", "attributed_names"]
DisplayFieldV2 = Literal["title", "attributed_names", "issued_date"]

SearchOmissionCauseV2 = Literal[
    "OVERSIZE_VALUE_OMITTED",
    "DESTINATION_CARDINALITY_LIMIT_APPLIED",
    "SEARCH_AGGREGATE_BUDGET_APPLIED",
    "TOOL_OUTPUT_BUDGET_APPLIED",
]


class SearchQueryV2(StrictWireModel):
    submitted_query: QueryText500
    kind: QueryKindV2


class MatchEvidenceV2(StrictWireModel):
    kind: Literal[
        "visible_fields",
        "match_source_not_exposed",
        "no_main_query",
    ]
    fields: Annotated[
        tuple[VisibleMatchFieldV2, ...],
        Field(max_length=2),
        BeforeValidator(own_json_array),
    ]


class SearchDocumentRowV2(StrictWireModel):
    handle: Handle
    item_url: CanonicalItemUrl
    title: MetadataText8192 | None
    attributed_names: Annotated[
        tuple[SearchName256, ...],
        Field(max_length=16),
        BeforeValidator(own_json_array),
    ]
    issued_date: Text64 | None
    match_evidence: MatchEvidenceV2
    omitted_display_fields: Annotated[
        tuple[DisplayFieldV2, ...],
        Field(max_length=3),
        BeforeValidator(own_json_array),
    ]


class SearchCoverageV2(StrictWireModel):
    identity_state: Literal["complete_for_returned_page"]
    display_state: Literal["complete", "partial"]
    display_omission_causes: Annotated[
        tuple[SearchOmissionCauseV2, ...],
        Field(max_length=4),
        BeforeValidator(own_json_array),
    ]


class SearchDocumentsOutput(StrictWireModel):
    schema_version: SchemaVersionV2
    repository_url: RepositoryRootUrl
    query: SearchQueryV2 | None
    filters: Annotated[
        tuple[SearchFilterV2, ...],
        Field(max_length=8),
        BeforeValidator(own_json_array),
    ]
    sort: SearchSortV2
    order: SearchOrderV2
    scope_handle: Handle | None
    page_size: PageSize
    page_start: SafeNonnegativeInteger
    items: Annotated[
        tuple[SearchDocumentRowV2, ...],
        Field(max_length=50),
        BeforeValidator(own_json_array),
    ]
    upstream_total: SafeNonnegativeInteger
    next_cursor: CursorText1024 | None
    coverage: SearchCoverageV2
    warnings: Annotated[
        tuple[SearchOmissionCauseV2, ...],
        Field(max_length=4),
        BeforeValidator(own_json_array),
    ]
```

The output contains the resolved request state. It never contains `envfv`, raw
DSpace names, `location`, an upstream request URL, or facets.

Search coverage concerns identity and optional display projection for this one
accepted upstream page only. It makes no repository-wide, index-wide, or
anonymous-access completeness claim.

For global filter-only search, `query` is null and the omitted-sort default is
serialized as `sort="issued_date", order="desc"`. For allowed scoped search,
`scope_handle` is non-null, `filters` is empty, and the reflected reviewed
default is serialized as `sort="relevance", order="desc"`; any incompatible
scoped reflection fails rather than changing that public contract.

The semantic invariants are:

- Every row satisfies `item_url == canonical_item_url(handle)`.
- `visible_fields` has a non-empty, unique `fields` tuple in canonical order
  `title`, `attributed_names`.
- `match_source_not_exposed` and `no_main_query` both require `fields == ()`.
- `query is None` exactly when the resolved request has no main query. In that
  state every returned row has `kind="no_main_query"` and empty fields.
- A non-null `query` forbids `no_main_query` on every returned row.
- For an empty page, the top-level query state remains authoritative; the
  universal row condition is not misused as a vacuous reverse implication.
- If an affirmative display field is omitted, match evidence is recomputed
  from the final returned fields. If no affirmative field remains, the kind is
  `match_source_not_exposed`.
- `omitted_display_fields` contains only fields that had an otherwise eligible
  upstream value but were omitted. Upstream absence alone is not an omission.
- `omitted_display_fields` is unique and uses canonical order `title`,
  `attributed_names`, `issued_date`.
- Every unambiguous upstream row on the accepted page retains its `handle` and
  canonical `item_url`, in source order. No budget policy drops or
  reorders a row. If that mandatory identity skeleton cannot fit, the tool
  fails with fixed `INTERNAL_ERROR` rather than returning partial identities.
- `upstream_total` is only the upstream-reported count in the current anonymous
  request context. It is not repository size or a completeness guarantee.

For `visible_fields`, the comparator uses only the parent contract's
ASCII-delimiter collapse and ASCII `A`–`Z` to `a`–`z` mapping. It applies no
Unicode normalization, locale transform, or Unicode case folding. The whole
plain-text query, or the whole simple phrase after removing its outer quote
pair for comparison only, must occur as a contiguous code-point substring of
the comparison-only view of a returned title or individual attributed name.
The output string and `submitted_query` remain byte-for-byte unchanged by this
comparison.

For every row with a non-null top-level query, the model validator computes the
canonical matching-field tuple from the final returned display values. If it
is non-empty, `kind` is exactly `visible_fields` and `fields` exactly equals
that tuple. If it is empty, `kind` is exactly `match_source_not_exposed` and
`fields == ()`. A filter-only row instead uses exactly `no_main_query` and an
empty tuple without running the comparator.

The search model validator requires `warnings ==
coverage.display_omission_causes`. `display_state="complete"` exactly when that
tuple is empty, and `partial` exactly when it is non-empty. An empty cause tuple
requires every row's `omitted_display_fields` to be empty; a non-empty cause
tuple requires at least one row to name an omitted display field. Each named
scalar field is null in that row after final projection;
`attributed_names` may retain a source-order prefix when only some names were
omitted. Every such omission contributes its first applicable cause to the
top-level ordered tuple.

The same validator also enforces the complete resolved context:

- the query is non-null or filters are non-empty;
- filters are unique in their retained order and every year range satisfies
  `from_year <= to_year`;
- null query requires global scope, at least one filter, and a non-relevance
  sort;
- non-null scope requires a non-null query, empty filters,
  `sort="relevance"`, and `order="desc"`; and
- `len(items) <= page_size`.

The adapter MUST fail with non-retryable `UPSTREAM_INCOMPATIBLE` if the
accepted result container exposes more than `page_size` rows or any discernible
row lacks an unambiguous canonical identity. It never discards such a row to
make the output validator pass; fewer rows remain valid at the end of a result
set.

`SearchQueryV2.kind` must exactly match the admitted shape of
`submitted_query`; the model cannot label plain text as a quoted phrase or the
reverse.

## 6. Exact `list_document_files` output

```python
FileAccessStateV2 = Literal["public_direct", "not_publicly_resolvable"]
FileOptionalFieldV2 = Literal[
    "reported_size_bytes",
    "reported_media_type",
    "description",
]
FileOmissionCauseV2 = Literal[
    "OVERSIZE_VALUE_OMITTED",
    "DESTINATION_CARDINALITY_LIMIT_APPLIED",
    "FILE_AGGREGATE_BUDGET_APPLIED",
    "TOOL_OUTPUT_BUDGET_APPLIED",
]
FileDetailOmissionCauseV2 = Literal[
    "OVERSIZE_VALUE_OMITTED",
    "FILE_AGGREGATE_BUDGET_APPLIED",
    "TOOL_OUTPUT_BUDGET_APPLIED",
]


class DocumentFileRecordV2(StrictWireModel):
    filename: Filename1024
    source_url: CanonicalDirectBitstreamUrl | None
    reported_size_bytes: SafeNonnegativeInteger | None
    reported_media_type: Text256 | None
    description: MetadataText8192 | None
    access_state: FileAccessStateV2
    downloadable: bool
    omitted_fields: Annotated[
        tuple[FileOptionalFieldV2, ...],
        Field(max_length=3),
        BeforeValidator(own_json_array),
    ]


class FileInventoryCoverageV2(StrictWireModel):
    inventory_state: Literal["complete", "partial"]
    inventory_omission_causes: Annotated[
        tuple[FileOmissionCauseV2, ...],
        Field(max_length=4),
        BeforeValidator(own_json_array),
    ]
    detail_state: Literal["complete", "partial"]
    detail_omission_causes: Annotated[
        tuple[FileDetailOmissionCauseV2, ...],
        Field(max_length=3),
        BeforeValidator(own_json_array),
    ]
    upstream_visible_eligible_count: Annotated[int, Field(strict=True, ge=0, le=4_096)]
    returned_count: Annotated[int, Field(strict=True, ge=0, le=256)]


class DocumentFilesOutput(StrictWireModel):
    schema_version: SchemaVersionV2
    handle: Handle
    item_url: CanonicalItemUrl
    record_access_state: Literal["anonymous_item_visible"]
    files: Annotated[
        tuple[DocumentFileRecordV2, ...],
        Field(max_length=256),
        BeforeValidator(own_json_array),
    ]
    coverage: FileInventoryCoverageV2
    warnings: Annotated[
        tuple[FileOmissionCauseV2, ...],
        Field(max_length=4),
        BeforeValidator(own_json_array),
    ]
```

`returned_count == len(files)`. The public model deliberately has no synthetic
bitstream/file identifier; source order, filename, and any verified direct URL
are the only source-supported row identity. `access_state="public_direct"` and
`downloadable=true` are both valid if and only if `source_url` is non-null and
the parent validator has proved it is a query-free fixed-origin direct URL for
the output's exact handle. Otherwise `access_state` is
`not_publicly_resolvable`, `downloadable` is false, and `source_url` is null.
`downloadable=true` means only that the validated anonymous page exposed this
direct URL at response time; it is not a future-availability guarantee. These
fields make no rights or licence claim.

The outer file model requires `item_url == canonical_item_url(handle)`, and
every non-null file `source_url` must embed that same handle.

`inventory_state` is partial exactly when an otherwise eligible record was
omitted. `detail_state` is partial exactly when an optional field on a returned
record was omitted. Counts and both cause arrays must agree with those states;
complete means the corresponding cause tuple is empty. Record omissions retain
a deterministic source-order subsequence; final aggregate/output fitting drops
whole records from the end. Serialized JSON is never cut.

Required file-row values are never nulled to make a linked row fit. An oversize
`filename`, or an otherwise valid query-free same-handle `source_url` whose
canonical representation exceeds its wire bound, omits the whole record with
`OVERSIZE_VALUE_OMITTED` and makes inventory coverage partial. A source URL
with a wrong origin, handle, route, query, fragment, or ambiguous encoding is
instead `UPSTREAM_INCOMPATIBLE`; it is not converted to null or reported as a
successful partial inventory. Null `source_url` is reserved for an explicitly
unlinked eligible row.

The file model validator makes that agreement exact:

- `returned_count == len(files)`;
- inventory is complete exactly when
  `returned_count == upstream_visible_eligible_count` and
  `inventory_omission_causes == ()`; otherwise it is partial, the returned
  count is lower, and the cause tuple is non-empty;
- detail is complete exactly when every returned record has
  `omitted_fields == ()` and `detail_omission_causes == ()`; otherwise it is
  partial and both an omitted field and its first applicable cause exist;
- every `omitted_fields` tuple is unique and uses canonical order
  `reported_size_bytes`, `reported_media_type`, `description`;
- a cause belongs to `inventory_omission_causes` only if it omitted a whole
  eligible record, and belongs to `detail_omission_causes` only if it omitted
  an optional field on a returned record; and
- `warnings` is the unique canonical-order union of the two cause tuples.

`upstream_visible_eligible_count` is exact for an accepted bounded response.
It counts structurally valid eligible table rows after explicit bundle-class
exclusions and before any projection omission; it is never a de-duplicated
count. More than 4,096 eligible rows exceeds the adapter contract and fails
non-retryably as `UPSTREAM_INCOMPATIBLE`; the server never publishes a capped
number as though it were the exact upstream-visible count.

### 6.1 Exact file eligibility

For this release, the candidate universe is only rows in the unique,
unambiguous item-files table owned by the validated requested JSPUI item and
recognized by the reviewed DSpace 5.5 adapter. A candidate is eligible only if
its required row structure is valid and no explicit ineligible/non-`ORIGINAL`
classification applies. A per-row bundle label is not required. Stock DSpace
5.x's item renderer builds this table from `item.getBundles("ORIGINAL")`; that
is adapter evidence, not proof that NPLG runs an unmodified binary and not a
public per-row bundle claim.

The adapter:

1. ignores every generic `/bitstream/` anchor outside that owned table;
2. represents an explicitly unlinked eligible row with null `source_url` and
   `access_state="not_publicly_resolvable"`; a linked row becomes
   `public_direct` only after the canonical query-free same-handle direct-URL
   validator passes, while a contradictory/mismatched link fails closed;
3. does not ingest file rows from DIM, METS, XOAI, MODS, ORE, extracted-text
   panels, thumbnail panels, licence panels, or arbitrary page links;
4. excludes a row if the response explicitly identifies it as `TEXT`,
   `THUMBNAIL`, `LICENSE`, `CC-LICENSE`, metadata, administrative, unknown, or
   any class other than `ORIGINAL`; absence of a per-row label inside the
   recognized table is not treated as a missing class;
5. permits only an exact explicit `ORIGINAL` bundle if a structured source is
   approved in a future contract;
6. rejects duplicate normalized rows or contradictory duplicate links as
   ambiguous instead of de-duplicating them;
7. accepts an empty complete inventory only when the reviewed adapter finds an
   explicit, unambiguous no-visible-eligible-files state; and
8. maps missing, duplicate, contradictory, or ambiguous table ownership to
   non-retryable `UPSTREAM_INCOMPATIBLE`, not an empty successful inventory.

The public record deliberately has no `bundle="ORIGINAL"` field because the
current HTML row does not itself provide source-qualified bundle evidence.
Excluding ineligible bundle classes does not make coverage partial; omitting an
eligible table row because of size, cardinality, or aggregate/output budget
does.

## 7. Exact omission pipeline and budgets

The projector constructs a new validated object after every omission phase. It
never slices a string, tuple, serialized object, or already serialized JSON.
One value receives only its first applicable cause, while separate values may
produce separate warning codes.

The phase order is fixed:

1. apply the closed source-key eligibility and provenance/contact policies;
2. validate scalars and omit a whole otherwise eligible, omittable oversize
   value or file record;
3. exact-de-duplicate only bibliographic values within one destination and
   attributed names within one search row;
4. apply destination and file-record cardinalities;
5. apply the tool's aggregate untrusted-string-leaf budget;
6. starting from the mandatory skeleton plus reserved warning/coverage shell,
   consider each optional candidate in the tool-specific admission order and
   retain it only if the rebuilt complete MCP result remains within both caps;
7. build, validate, and remeasure the final complete MCP result; and
8. return fixed `INTERNAL_ERROR` if the mandatory skeleton cannot fit.

Required metadata/search identity is never treated as an omittable value. A
malformed, mismatched, or oversize upstream handle/item identity is
`UPSTREAM_INCOMPATIBLE`; failure of a locally derived canonical identity or a
mandatory-skeleton assertion is `INTERNAL_ERROR`. An oversize required filename
omits that whole file record and makes inventory coverage partial.

Trusted keys and fixed literals do not count against the leaf budget, but they
do count against the final serialized-result cap. Every untrusted string leaf
does count, including echoed query/filter values, metadata, names, filenames,
handles, and URLs.

| Tool result | Aggregate untrusted string leaves | Complete compact UTF-8 `CallToolResult` cap |
| --- | ---: | ---: |
| `get_document_metadata` | 131,072 bytes and 512 destination entries | 393,216 bytes |
| `search_documents` | 196,608 bytes | 524,288 bytes |
| `list_document_files` | 196,608 bytes | 655,360 bytes |
| Any tool error | not applicable | 4,096 bytes |

Every project cap is below the absolute 1,048,576-byte public tool-result
ceiling. The final project measurement covers the fully composed modern
application-hop `CallToolResult`, including fixed content, `structuredContent`
when present, `isError`, `resultType`, the bounded standard server-info stamp,
and project `_meta`; it excludes only the caller-controlled outer JSON-RPC
ID/envelope. The server composes the exact bounded server-info stamp before
measurement, and a locked-runner test proves its later idempotent stamping adds
or changes no byte. The largest project cap leaves an exact 393,216-byte margin
below 1 MiB for Alpic's external legacy-envelope transformation. Hosted staging
must measure that transformed result and fail release if the provider consumes
that margin. Provider-added bytes are not misrepresented as project-controlled
pre-serialization input.

A Streamable HTTP maximal-vector test must prove that the project measurement
agrees with the locked SDK's application-hop serialization. No optional value
is removed after serialization: candidates are admitted one at a time in the
priority order below, with the rebuilt complete result measured each time. An
unexpected final mismatch returns the already-bounded fixed `INTERNAL_ERROR`;
it does not cut or retroactively edit JSON. Startup validation bounds the
server-info name/version and standard stamp so the complete fixed error remains
within 4,096 bytes.

Deterministic fitting is tool-specific:

- Metadata admits destinations in model-field order and values in source
  order. Nullable scalars are considered at their model position. Omitted
  values set the applicable metadata coverage cause.
- Search first builds every returned row's handle and item URL. Optional
  display data is admitted in row order and, within each row, `title`,
  `attributed_names`, then `issued_date`. Names retain source order. Budget
  pressure may omit these display fields but never an item identity. Search
  rows themselves are never de-duplicated.
- Files retain eligible source order. Fitting is row-major: for each returned
  row in source order, optional details are considered in the order
  `reported_size_bytes`, `reported_media_type`, `description`. After optional
  details are removed, whole trailing records may be omitted and file inventory
  coverage becomes partial. File rows are never de-duplicated.

The projector reserves the maximal warning and coverage structure before it
admits optional values. Adding a required cause code therefore cannot itself
push the result over its cap.

### 7.1 Mandatory-skeleton bounds

Generated maximal-vector tests enforce these conservative encoded limits:

- metadata's handle, item URL, source/access, null scalars, empty arrays,
  maximal warning/coverage shell, and MCP envelope fit within 16,384 bytes;
- search's full resolved context (including eight maximally escaped filters),
  50 row identities, omission markers, maximal warning/coverage shell, cursor,
  and MCP envelope fit within 98,304 bytes; and
- the zero-record file result fits within 8,192 bytes, while one maximal
  required file record plus its envelope fits within 32,768 bytes.

For search, the conservative bound is `50 × 1,089 = 54,450` bytes for
identities and fixed row structure, plus 4,096 for the escaped query, 20,480
for eight escaped filters and their structure, 1,024 for the cursor, 65 for
scope, and 8,192 for the remaining envelope: 88,307 bytes, below the asserted
98,304-byte bound. The other asserted skeleton bounds are respectively below
the 393,216 and 655,360-byte caps. Search can therefore preserve all 50 row identities.
File inventory can always fall back to a valid partial zero-record result if a
required record cannot fit. A failing skeleton assertion is a closed failure,
not permission to truncate JSON.

### 7.2 Exact warning-cause effects

| Cause | Warning code | Coverage effect |
| --- | --- | --- |
| Observed technical-provenance source key | `TECHNICAL_PROVENANCE_OMITTED` | no partial state; the source class is outside the public evidence universe |
| Evidence-backed administrative contact in a specifically reviewed field | `FIELD_SPECIFIC_CONTACT_OMITTED` | metadata coverage partial |
| Otherwise eligible, omittable scalar exceeds its scalar or UTF-8 limit | `OVERSIZE_VALUE_OMITTED` | metadata partial; search display partial; file inventory partial when the whole file record is omitted, or file detail partial for an optional field |
| Destination limit, attributed-name limit, or eligible-file limit | `DESTINATION_CARDINALITY_LIMIT_APPLIED` | metadata partial; search display partial; file inventory partial |
| Metadata 512-entry or 131,072-byte leaf limit | `METADATA_AGGREGATE_BUDGET_APPLIED` | metadata coverage partial |
| Search 196,608-byte leaf limit | `SEARCH_AGGREGATE_BUDGET_APPLIED` | search display partial; identities remain complete |
| File 196,608-byte leaf limit | `FILE_AGGREGATE_BUDGET_APPLIED` | file detail and/or inventory partial according to whether optional fields, whole records, or both were omitted |
| Complete per-tool serialized-result cap | `TOOL_OUTPUT_BUDGET_APPLIED` | metadata partial; search display partial with identities complete; file detail and/or inventory partial according to what was omitted |

## 8. Exact public tool error and MCP envelopes

```python
PublicErrorCodeV1 = Literal[
    "INVALID_INPUT",
    "NOT_FOUND",
    "ACCESS_UNAVAILABLE",
    "RATE_LIMITED",
    "UPSTREAM_TIMEOUT",
    "TEMPORARILY_UNAVAILABLE",
    "UPSTREAM_INCOMPATIBLE",
    "UPSTREAM_FAILURE",
    "INTERNAL_ERROR",
]

FixedPublicMessageV1 = Literal[
    "The request is invalid.",
    "The requested repository record was not found.",
    "The requested public content is unavailable.",
    "Too many requests. Try again later.",
    "The repository did not respond in time.",
    "The service is temporarily unavailable.",
    "The repository interface is incompatible with this service.",
    "The repository request failed.",
    "The request could not be completed.",
]


class PublicToolErrorV1(StrictWireModel):
    schema_version: Literal["1"]
    code: PublicErrorCodeV1
    message: FixedPublicMessageV1
    retryable: bool
    retry_after_seconds: Annotated[
        int,
        Field(strict=True, ge=1, le=3_600),
    ] | None
```

All five fields are required. A model validator enforces the exact mapping:

| Code | Message | `retryable` | `retry_after_seconds` |
| --- | --- | --- | --- |
| `INVALID_INPUT` | The request is invalid. | false | null |
| `NOT_FOUND` | The requested repository record was not found. | false | null |
| `ACCESS_UNAVAILABLE` | The requested public content is unavailable. | false | null |
| `RATE_LIMITED` | Too many requests. Try again later. | true | null or 1–3,600 when the enforcing admission control supplies it |
| `UPSTREAM_TIMEOUT` | The repository did not respond in time. | true | null |
| `TEMPORARILY_UNAVAILABLE` | The service is temporarily unavailable. | true | null or 1–3,600 when a bounded recovery time is known |
| `UPSTREAM_INCOMPATIBLE` | The repository interface is incompatible with this service. | false | null |
| `UPSTREAM_FAILURE` | The repository request failed. | false | null |
| `INTERNAL_ERROR` | The request could not be completed. | false | null |

No arbitrary `AppError.message` is projected. The internal-error disposition in
the parent contract is exhaustive at profile composition.

Each tool advertises only its generated success model as `outputSchema`.
`PublicToolErrorV1` is generated as a separate schema and does not weaken the
success schema into a success/error union.

| Tool | Exact successful `structuredContent` / `outputSchema` root |
| --- | --- |
| `search_documents` | `SearchDocumentsOutput` |
| `get_document_metadata` | `DocumentMetadataOutput` |
| `list_document_files` | `DocumentFilesOutput` |

### 8.1 Protocol and gateway envelope boundary

The normative external Alpic profile negotiates MCP `2025-11-25`. The
application origin remains modern-only MCP `2026-07-28`; Alpic owns the public
legacy initialize/session lifecycle and translates that hop. The locked MCP
2.1.1 per-version serializer was probed with the exact fields below: for
`2025-11-25` it preserves `_meta`, `content`, `structuredContent`, and
`isError`, and removes the modern-only `resultType`; for `2026-07-28` it
preserves `resultType="complete"`.

Therefore the exact public envelopes in this section intentionally omit
`resultType`. The fully composed application-hop object contains
`resultType="complete"` and the bounded standard server-info `_meta` stamp
before budget measurement. Hosted staging MUST prove that the Alpic public hop
preserves the project error/build-identity metadata and the success/error
semantics shown here. A different negotiated public protocol, a dropped
project metadata key, or a changed semantic field is an incompatible adapter
change requiring review before release; it is not accepted through inference.

A public success has exactly one constant summary `TextContent`, the exact
output model in `structuredContent`, and `isError=false`:

```json
{
  "content": [
    {"type": "text", "text": "Tool completed successfully."}
  ],
  "structuredContent": {"schema_version": "2"},
  "isError": false
}
```

The abbreviated `structuredContent` above shows the discriminant; at runtime
it is the complete corresponding success object, with every required field.
The fixed summary avoids serializing the same untrusted result a second time.

An application/tool error has `isError=true`, exactly one `TextContent` whose
text is the fixed mapped message, no
`structuredContent` key, and the validated machine-readable error under the
exact result metadata key
`io.github.davidosipov/nplgPublicToolError`:

```json
{
  "_meta": {
    "io.github.davidosipov/nplgPublicToolError": {
      "schema_version": "1",
      "code": "UPSTREAM_TIMEOUT",
      "message": "The repository did not respond in time.",
      "retryable": true,
      "retry_after_seconds": null
    }
  },
  "content": [
    {"type": "text", "text": "The repository did not respond in time."}
  ],
  "isError": true
}
```

Other standard or provider-owned namespaced `_meta` entries may coexist; they
cannot alter or collide with the project namespace. They are part of the
separately measured Alpic envelope margin in section 7, not unbounded input to
the projector. Unknown tools and malformed JSON-RPC envelopes remain protocol
errors rather than `PublicToolErrorV1`.

## 9. MCP-visible build identity

The public `/healthz` route is not an external provenance surface. It remains
an internal status probe and contains no release attestation claim.

The standard initialization `serverInfo` carries the installed distribution
name and version. The server also exposes this required, non-sensitive object
on the `tools/list` result under
`io.github.davidosipov/nplgBuildIdentity`:

```python
class PublicBuildIdentityV1(StrictWireModel):
    schema_version: Literal["1"]
    version: Text64
    git_commit: Annotated[
        str,
        Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"),
    ]
    requirements_lock_sha256: Annotated[
        str,
        Field(pattern=r"^sha256:[0-9a-f]{64}$"),
    ]
    build_config_sha256: Annotated[
        str,
        Field(pattern=r"^sha256:[0-9a-f]{64}$"),
    ]
    deployment_profile: Literal["alpic-metadata"]
```

`version` comes from installed package metadata.
`requirements_lock_sha256` is the SHA-256 of the exact core
`requirements.lock` bytes, and `build_config_sha256` is the SHA-256 of the exact
`alpic.json` bytes. They are computed from the bounded deployed files when
those bytes are present; otherwise they come from an immutable manifest
packaged into the distribution from those exact build-context bytes. Mutable
user environment variables are not their sole authority. The source commit may
need to be embedded at build time because Alpic documents no runtime commit
variable.

This object and standard `serverInfo` are application self-reports, not an
attestation or proof of running bytes. Release verification correlates the
self-reported commit with the independently retrieved Alpic deployment ID and
provider-reported `sourceCommitId`, and separately treats the GitHub-attested
wheel/sdist as a different evidence subject.

## 10. Locked boundary evidence and remaining approval gate

A read-only 2026-09-02 probe used the repository's locked Python 3.14.5,
Pydantic 2.13.5, MCP 2.1.1 request models, and real `SdkHandlers.on_call_tool`
boundary. The decoded JSON types were `dict`, `list`, and strings for field,
operator, sort, and order.

The same ordinary argument object produced:

```text
strict StrEnum plus plain tuple: REJECT
  filters: tuple_type
  sort: is_instance_of
  order: is_instance_of
Literal plus exact-list ownership: ACCEPT
  internal filters type: tuple; sort and order remain admitted strings
  mutating the decoded source list afterward does not change the owned tuple
generated filters schema: type=array, maxItems=8
real SDK handler: is_error=false, structuredContent validated
```

The existing focused SDK-boundary command also passed:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/contracts/test_sdk_boundary.py::test_sdk_boundary_rejects_bad_raw_arguments_before_tool_entry
3 passed in 0.65s
```

This proves the decoded handler seam used here; it is not a substitute for the
required full Streamable HTTP serialization test after an approved
implementation exists.

Exact contract approval remains blocked on review of this appendix, the
read-only metadata-key inventory, and any resulting schema diff. Nothing in
this appendix approves implementation or a dependency-lock change.
