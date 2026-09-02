# NPLG Anonymous Metadata v2 Wire Contract

**Status:** DRAFT / NON-EXECUTABLE — explicit breaking-contract approval required

**Date:** 2026-09-02

**Profile:** `alpic-metadata`

**Implementation plan:**
[`../plans/2026-09-02-verifiable-research-results.md`](../plans/2026-09-02-verifiable-research-results.md)

**Query decision:**
[`../../architecture/2026-09-02-basic-query-no-lucene-parser-adr.md`](../../architecture/2026-09-02-basic-query-no-lucene-parser-adr.md)

**Proposed normative model appendix:**
[`2026-09-02-anonymous-metadata-v2-model-appendix.md`](2026-09-02-anonymous-metadata-v2-model-appendix.md)

This is the proposed v2 contract. It does not supersede the current root
`SPEC.md`, authorize implementation, or change the deployed service until the
user explicitly approves the breaking contract.

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 1. Public boundary

The anonymous, upstream-read-only, fixed-origin profile exposes exactly these
tools:

1. `search_documents`
2. `get_document_metadata`
3. `list_document_files`

It also exposes the existing fixed, non-templated workflow resource:

```text
nplg://skills/georgian-newspaper-visual-analysis
```

The profile MUST NOT add another tool, arbitrary URL input, raw metadata,
`raw_fields`, a downloader, server-side document reading, PDF rendering, OCR,
translation, embeddings, a mutable repository operation, or a new
authentication/authorization authority. PDF retrieval and OCR remain in the
client environment and do not expand the Alpic runtime.

Every query, metadata value, filename, count, facet, HTML/XML field, and OAI
value is untrusted data, never an instruction. The service MUST NOT fabricate
snippets, page numbers, OCR confidence, relevance scores, contributor roles,
dates, rights, licences, access, or completeness.

## 2. Contract authority and versioning

Pydantic is the sole runtime and semantic contract authority. All public
inputs, outputs, cursor claims, compiler inputs, and public errors derive from
strict models equivalent to:

```python
class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_default=True,
        frozen=True,
    )
```

The exact proposed input/output models, required/default/null rules, owned-array
semantics, MCP result envelopes, and budgets are in the model appendix. After
approval, the project MUST generate and check in Draft 2020-12 JSON Schema from
those exact Pydantic models. A schema-visible breaking change requires:

1. an explicit schema-version increment;
2. regenerated JSON Schema;
3. a reviewed deterministic synthetic golden-fixture diff;
4. green CI against the approved snapshots.

There is no independently authored Zod semantic twin. If a real independently
released JavaScript client later needs structural validation, it MAY use Ajv
against the generated schema for object shape, required and additional
properties, primitives, enums, simple patterns, and string/array bounds. It
MUST NOT duplicate Python-only source mapping, omission causality, aggregate
budgets, cursor signatures, same-handle URL equality, query policy, or warning
semantics.

## 3. Common bounds and scalar policy

Public strings MUST be strict strings; bytes, numbers, containers, and implicit
coercions are invalid. The server MUST bound both Unicode scalar count and
UTF-8 byte count before network I/O.

The shared scalar policy MUST:

- reject surrogate code points U+D800–U+DFFF;
- reject U+0000–U+0008, U+000B–U+000C, U+000E–U+001F, U+007F, and
  U+0080–U+009F;
- reject U+061C, U+200E, U+200F, U+202A–U+202E, and U+2066–U+2069;
- treat only TAB, LF, CR, and ASCII SPACE as delimiters where whitespace
  canonicalization is specified;
- avoid runtime Unicode letter categories and ambient `isspace` behavior.

This fixed scalar/delimiter rule supports Georgian, Russian, English, and
supplementary-plane text without relying on Python or Node Unicode database
versions.

## 4. Initial search syntax profile: basic query plus typed positive filters

The product MUST be described as **basic query plus typed positive filters**.
It is not advertised as a complete Lucene query interface.

### 4.1 Input model

The complete proposed input is defined in the model appendix. Its relevant
wire shape is:

```python
class SearchTextFilter(StrictModel):
    kind: Literal["text"]
    field: Literal["title", "author_index", "subject", "type", "language"]
    operator: Literal["equals", "contains"]
    value: SearchFilterText


class IssuedYearRangeFilter(StrictModel):
    kind: Literal["issued_year_range"]
    from_year: Year
    to_year: Year


class SearchDocumentsInput(StrictModel):
    query: QueryText500 | None = None
    filters: Annotated[
        tuple[SearchTextFilter | IssuedYearRangeFilter, ...],
        Field(max_length=8),
        BeforeValidator(own_json_array),
    ] = ()
    sort: Literal["relevance", "title", "issued_date"] | None = None
    order: Literal["asc", "desc"] | None = None
    page_size: PageSize = 20
    scope_handle: Handle | None = None
    cursor: CursorText1024 | None = None
```

`own_json_array` copies only an exact decoded JSON list to a tuple. Null and
other containers remain invalid. A read-only probe against locked Pydantic
2.13.5 and MCP 2.1.1 confirmed that the real SDK boundary decodes the normal
wire object as dict/list/string values: strict `StrEnum` and a plain tuple
reject it, while `Literal` plus the list-to-owned-tuple validator accepts it
and generates `type: array` with `maxItems: 8`. The appendix records the exact
receipt and limitation. This wire contract therefore does not require Python
enum or tuple objects from an MCP client.

Public facets are absent from the initial search syntax profile, so there is no
facet input or cursor field.

### 4.2 Basic-query admission

There is no Lucene parser, AST, inspection query, AST node allowlist, or AST
renderer. The AST-node set is empty.

`submitted_query` is created by:

1. accepting a strict string with at most 500 scalars and 2,048 UTF-8 bytes;
2. applying the common scalar policy;
3. trimming and collapsing only TAB, LF, CR, and ASCII SPACE to one ASCII
   SPACE;
4. rechecking that the result is non-empty and within both limits;
5. validating one of the two admitted shapes below.

The only admitted shapes are:

- `plain_text`: no ASCII quote and no forbidden syntax marker;
- `simple_quoted_phrase`: one ASCII double-quote pair spanning the whole
  canonical value, non-empty inner text, and no inner quote.

For `plain_text`, the validator MUST:

- accept ordinary text such as `C++`, `COVID-19`, `NOTHING`, and
  `Georgia: History and Culture`;
- reject backslash, asterisk, question mark, tilde, caret, square or curly
  brackets, parentheses, slash, exclamation mark, `&&`, and `||`;
- reject standalone uppercase tokens `AND`, `OR`, and `NOT`;
- reject `+` or `-` at the start or immediately after ASCII SPACE while
  allowing internal punctuation in `C++` and `COVID-19`;
- accept a colon only when it is immediately followed by ASCII SPACE; reject
  `title:value`, trailing colon, and other no-space colon forms.

For `simple_quoted_phrase`, the outer quotes are upstream phrase syntax and
MUST remain in `submitted_query`. The inner text MUST contain a non-space
scalar and MUST reject backslash, quote, asterisk, question mark, tilde, caret,
square/curly brackets, parentheses, slash, and exclamation mark.

The server MUST send the exact validated `submitted_query`; it MUST NOT escape,
render, reconstruct, or otherwise rewrite it. Outer phrase quotes MAY be
removed only for affirmative visible-text comparison, never for submission,
logging, or cursor binding.

Any rejection returns the fixed `INVALID_INPUT` error before NPLG network I/O.
No query value enters logs. A rejected query, query fragment, parser-style
diagnostic, or exception text MUST NOT enter public error output. An accepted,
canonical `submitted_query` MAY appear only in the typed success output defined
by the model appendix.

### 4.3 Query approval corpus

The following accept/reject decisions are part of breaking-contract approval:

| Input | Initial-profile decision | Reason |
| --- | --- | --- |
| `C++` | accept `plain_text` | internal plus punctuation |
| `COVID-19` | accept `plain_text` | internal hyphen punctuation |
| `Georgia: History and Culture` | accept `plain_text` | colon followed by space |
| `NOTHING` | accept `plain_text` | not the standalone `NOT` token |
| `"Georgia history"` | accept `simple_quoted_phrase` | one whole phrase |
| `NOT term` | reject | Boolean syntax deferred |
| `term AND other` | reject | Boolean syntax deferred |
| `+term`, `-term` | reject | unary syntax deferred |
| `term*`, `*term`, `te*rm` | reject | wildcard syntax deferred |
| `title:value` | reject | client field syntax forbidden |
| `[1900 TO 1910]`, `{1900 TO 1910}` | reject | raw ranges forbidden |
| `foo~2`, `foo^3`, `/regex/` | reject | fuzzy, boost, and regex forbidden |
| `AC/DC` | reject | slash is deliberately over-restricted initially |
| `What happened?` | reject | question-mark wildcard ambiguity |
| `Georgia (1918–1921)` | reject | grouping punctuation ambiguity |
| `Question!` | reject | exclamation/operator ambiguity |
| `A/B testing` | reject | slash is deliberately over-restricted initially |

The five final rows are ordinary-language false negatives accepted as an
initial-profile trade-off. They are not claimed to be NPLG limitations.
Boolean, grouping, unary, wildcard, and more punctuation-compatible admission
remain a separate post-stability decision.

### 4.4 Positive filters and sorting

The request MUST contain a non-empty query or at least one positive filter.
It accepts at most eight ordered filters. Exact duplicates after validation are
invalid. Filter order remains cursor-significant.

Text-filter values are strict, non-empty, at most 256 scalars and 1,024 UTF-8
bytes, and use the common scalar policy. They MUST reject any bracketed or
braced segment containing a standalone case-insensitive ASCII `TO` token. Only
`IssuedYearRangeFilter` can compile a range.

`Year` is a strict integer from 1 through 9,999. `from_year` MUST be less than
or equal to `to_year`; both endpoints compile as four digits.

`page_size` is 1–50. `location`, `envfv`, raw upstream fields/operators/ranges,
`owner`, authority IDs, negative filters, and autocomplete parameters are not
public inputs.

Typed filters and explicit sort/order are global-scope features in the initial
profile. When `scope_handle` is non-null, `query` MUST be non-null, `filters`
MUST be empty, and `sort` and `order` MUST both be null (whether omitted or
explicitly null). A violation is
`INVALID_INPUT` before network I/O. Scoped search therefore supports only a
basic main query, page size, and cursor under the scoped page's reflected
default relevance-descending controls. Extending typed controls to scoped
search requires a separately reviewed advertised-capability intersection; it
is not implicit in the static allowlist.

The closed compiler mapping is:

| Public value | Private DSpace constant |
| --- | --- |
| `title` | filter field `title` |
| `author_index` | filter field `author` |
| `subject` | filter field `subject` |
| `type` | filter field `type` |
| `language` | filter field `language` |
| `issued_year_range` | `[YYYY TO YYYY]`, field `dateIssued`, operator `equals` |
| `relevance` | sort field `score` |
| title sort | sort field `dc.title_sort` |
| `issued_date` | sort field `dc.date.issued_dt` |

The public name is `author_index`, not `author`, because the upstream index may
combine `dc.contributor.author`, `dc.creator`, and local mappings. DSpace
`contains` means analyzed Discovery-field matching; it is not a literal
substring guarantee.

Filters compile to contiguous, numbered, ordered field/type/value triplets and
combine conjunctively. The complete percent-encoded upstream path and query
MUST be at most 8,192 ASCII bytes before network I/O.

Resolved sort behavior is exact:

- in global search, null has the same documented unspecified meaning as
  omission for `sort` and `order`;
- query present and sort omitted/null: relevance descending;
- filter-only and sort omitted/null: issued date descending;
- explicit relevance without a query: invalid;
- order without sort: invalid;
- explicit title sort with omitted/null order: ascending;
- other explicit sort with omitted/null order: descending.

### 4.5 Search result semantics

Search rows expose `attributed_names`, not unsourced `authors`. A specific role
appears only when a reviewed role-bearing source key supports it.

Visible substring matching is affirmative evidence only. A row without a
visible title/name match uses `match_source_not_exposed`; the match may have
occurred in an abstract, series, sponsor, identifier, or indexed full text.
The service does not explain ranking or claim why an item matched.

The display comparator is deliberately exact and conservative. It creates a
comparison-only view of the submitted needle and each returned title/name by
trimming and collapsing only TAB, LF, CR, and ASCII SPACE, then mapping ASCII
`A`–`Z` to `a`–`z`. It performs no Unicode normalization, locale transform, or
Unicode case folding; every non-ASCII scalar is compared unchanged. For a
simple quoted phrase, only the one pair of outer ASCII quotes is removed from
the comparison needle. For plain text, the complete canonical query is the
needle. `visible_fields` is emitted only when that complete needle is a
contiguous code-point substring of the comparison view of the returned field.
This comparison never changes the submitted query or returned display value
and deliberately permits false negatives rather than asserting uncertain
evidence.

A filter-only request has top-level `query=null`. Every returned row then uses
`match_evidence.kind=no_main_query` with an empty `fields` tuple. Conversely, a
non-null top-level query forbids `no_main_query`. For an empty result page the
top-level resolved query state is authoritative; the reverse implication is
not inferred vacuously from an empty row array.

`upstream_total` is the count reported for the current anonymous and possibly
scoped request. It is not repository size or a completeness statement. The
response includes only the fixed query-free repository URL and canonical,
query-free handle URLs, never the internal search request URL.

### 4.6 Cursor context

The signed, expiring cursor binds a canonical representation of:

- `submitted_query` or null;
- ordered typed filters;
- resolved sort and order;
- scope handle or null;
- page size;
- schema and cursor versions;
- next offset and expiry.

Tampering, expiry, unknown version, or any cross-context change MUST fail
before NPLG network I/O. Cursor errors expose no claim, signature, key ID,
query, or context value.

### 4.7 DSpace adapter boundary

Product documentation calls the interface **DSpace Discovery backed by Solr**,
not “Jakarta Lucene”. NPLG's JSPUI self-identifies as DSpace 5.5, but the
service MUST NOT claim every deployed component is an unmodified stock binary.

The adapter uses a reviewed static allowlist. Global search obtains `envfv`
from the global search page; scoped basic search obtains it from the exact
canonical scoped search page. The marker is internal, bounded, dynamically
discovered/refreshed, never hard-coded, never client-controlled, and not a
credential. The implementation may retain only the existing small
marker/generation state needed for stale-marker recovery; it MUST NOT add a
general capability LRU. A stale-marker 404 permits one rediscovery and one
exact replay within the original total deadline; this is protocol recovery,
not a generic retry.

The adapter MUST validate response media type, bounded body size, record
identity, anonymous scope, pagination bounds/links, and material echoed query,
filters, sort, order, page size, and start offset. A dropped or changed
condition, malformed or unsupported result structure, or ambiguous parse maps
to non-retryable `UPSTREAM_INCOMPATIBLE`.

Semantic reflection and pagination are long-lived invariants. CSS selectors,
Bootstrap classes, localized labels, direct-child topology, and duplicate
pagination placement are versioned adapter details. A harmless layout change
does not fail a still-unambiguous parse; ambiguity fails closed. Reflected form
controls and returned state are consistency evidence only: they do not prove
that Solr applied a condition or reveal hidden configured defaults.

The service MUST NOT forward client cookies, authorization, browser user-agent,
Referer, `Sec-Fetch-*`, client hints, `Forwarded`, or `X-Forwarded-*` headers to
NPLG. It MUST use the fixed NPLG origin and the existing DNS/TLS/actual-peer
binding transport. The unavailable optional DSpace 5 REST routes and incomplete
OpenSearch description are not project APIs.

## 5. Metadata projection and file records

### 5.1 Vocabulary freeze gate

`ReviewedSourceKey` MUST NOT be frozen until a read-only inventory:

1. extracts qualified key names and occurrence counts, but no values, from
   sanitized DIM/XOAI samples;
2. reconciles them with official NPLG help;
3. resolves citation, series/report title and number, ISMN, sponsors,
   `dc.relation.IsPartOf`, and `dc.relation.IsFormatOf`, recording exact
   observed casing;
4. marks every candidate key `expose`, `map`, `suppress`, or `defer` with a
   reason;
5. receives review before the public schema is frozen.

This inventory is not the deferred DIM/METS/XOAI/MODS/ORE source-priority
study. DIM remains the primary source-qualified bibliographic format. The
current bounded OAI DC and validated JSPUI-item fallbacks remain explicitly
identified fallbacks with separate closed mappings; they cannot infer a role,
issued date, or destination whose exact source semantics they do not preserve.
XOAI is never exposed or logged raw.

### 5.2 Source-bound semantics

The projection MUST:

- use a closed public source-key allowlist;
- unconditionally suppress `dc.description.provenance`;
- expose no `raw_fields` or raw-metadata escape hatch;
- map `dc.creator` to an agent with role `creator`, never `author`;
- expose author, editor, advisor, and other roles only from reviewed
  role-bearing keys;
- keep `title` nullable and never substitute the handle;
- use only `dc.date.issued` as the issued date;
- keep record/file access, rights statements, rights holders, and reuse
  licences separate;
- never interpret a DSpace deposit licence as a public reuse licence;
- avoid a generic email/PII classifier.

If a reviewed public metadata field later demonstrates administrative-contact
leakage, a source-key-specific rule and fixture are required before suppression.

### 5.3 Projection bounds and warnings

The model appendix defines every destination cardinality and these exact,
mathematically compatible result budgets:

| Tool | Untrusted string-leaf budget | Complete serialized `CallToolResult` cap |
| --- | ---: | ---: |
| `get_document_metadata` | 131,072 bytes and 512 entries | 393,216 bytes |
| `search_documents` | 196,608 bytes | 524,288 bytes |
| `list_document_files` | 196,608 bytes | 655,360 bytes |
| any tool error | not applicable | 4,096 bytes |

All project caps are below the absolute 1,048,576-byte public result ceiling.
The complete, fully composed MCP `2026-07-28` application-hop result is measured
as compact UTF-8 before return, including its bounded server-info stamp; the
locked runner MUST add or change nothing afterward. The largest project cap
leaves the model appendix's exact margin for Alpic's MCP `2025-11-25` public
envelope transformation, which is measured in hosted staging. The projector
starts from the mandatory skeleton and admits only whole eligible values,
optional display fields, or whole file records in the appendix's deterministic
priority order, constructing and validating a new model for each decision. It
MUST NOT cut or truncate serialized JSON. Search preserves every returned row
identity; if its mandatory identity skeleton cannot fit, the request fails
closed. An omitted eligible file record makes file-inventory coverage partial.

The deterministic value-free codes are:

- `TECHNICAL_PROVENANCE_OMITTED`
- `FIELD_SPECIFIC_CONTACT_OMITTED`
- `OVERSIZE_VALUE_OMITTED`
- `DESTINATION_CARDINALITY_LIMIT_APPLIED`
- `METADATA_AGGREGATE_BUDGET_APPLIED`
- `SEARCH_AGGREGATE_BUDGET_APPLIED`
- `FILE_AGGREGATE_BUDGET_APPLIED`
- `TOOL_OUTPUT_BUDGET_APPLIED`

Technical-provenance removal is an intentional source-policy exclusion and
does not make public evidence coverage partial. Field-specific contact,
oversize, destination-cardinality, aggregate-budget, and final-result-budget
omissions affect the exact coverage dimension in the appendix's cause table.
Evidence coverage remains independent of record/file access. A file access
state does not imply partial bibliographic evidence, and partial projection
does not imply restricted access.

### 5.4 File URLs and access

For each `DocumentFilesOutput`, `item_url` identifies the validated requested
item. For every public file record within that output:

- `source_url` is either a validated, query-free, same-handle direct bitstream
  URL or null;
- the enclosing `item_url` is the separate validated, query-free NPLG item URL;
- public direct-file access requires non-null `source_url` plus the public
  access state;
- `downloadable` never implies openly licensed;
- the public model makes no per-row bundle claim not present in source evidence.

The repository root MUST NOT be used as a sentinel `source_url`.
`repository_url` is reserved for the fixed repository root in search output;
record links consistently use `item_url`.

Eligibility is exact for this release: parse only the unique, unambiguous
item-files table owned by the validated requested JSPUI item; accept linked
rows only after same-handle direct-URL validation; and ignore generic bitstream
anchors elsewhere. Do not ingest DIM/METS/XOAI/MODS/ORE file rows. `TEXT`,
`THUMBNAIL`, `LICENSE`, `CC-LICENSE`, metadata, administrative, unknown, and
explicit non-`ORIGINAL` bundle classes are ineligible. The reviewed table is
the initial eligibility source, so absence of a per-row bundle label inside it
does not create a public bundle claim or make the row ineligible. If a future
structured source is approved, only exact explicit `ORIGINAL` is eligible. An empty complete inventory
requires a reviewed explicit no-visible-eligible-files state. Otherwise
missing, duplicate, contradictory, or ambiguous table ownership is
non-retryable `UPSTREAM_INCOMPATIBLE`, not an empty success. Excluding
ineligible classes is not partial coverage; omitting an eligible row for a
projection limit is.

## 6. Public errors

The appendix defines the complete required `PublicToolErrorV1`, including the
literal schema version, fixed message union, required nullable
`retry_after_seconds`, and exact MCP error envelope. Every public code maps to
one literal message and retryability value. Arbitrary
`AppError.message`, query/metadata/URL/path content, parser details, exception
representations, and tracebacks MUST NOT be projected.

| Public code | Fixed public message | Retryable |
| --- | --- | --- |
| `INVALID_INPUT` | The request is invalid. | false |
| `NOT_FOUND` | The requested repository record was not found. | false |
| `ACCESS_UNAVAILABLE` | The requested public content is unavailable. | false |
| `RATE_LIMITED` | Too many requests. Try again later. | true |
| `UPSTREAM_TIMEOUT` | The repository did not respond in time. | true |
| `TEMPORARILY_UNAVAILABLE` | The service is temporarily unavailable. | true |
| `UPSTREAM_INCOMPATIBLE` | The repository interface is incompatible with this service. | false |
| `UPSTREAM_FAILURE` | The repository request failed. | false |
| `INTERNAL_ERROR` | The request could not be completed. | false |

Classification is causal:

- an upstream connect/read/total timeout becomes `UPSTREAM_TIMEOUT`;
- an open circuit, confirmed upstream throttling, or positively classified
  transient outage becomes `TEMPORARILY_UNAVAILABLE`;
- malformed/unsupported JSPUI, material echo drift, or ambiguous result or
  pagination state becomes `UPSTREAM_INCOMPATIBLE`;
- a non-timeout upstream request/status failure not positively classified as
  transient becomes `UPSTREAM_FAILURE`;
- bounded local admission refusal becomes `RATE_LIMITED`.

`retry_after_seconds` is always present. It is null or a strict integer from 1
through 3,600 and may be non-null only for `RATE_LIMITED` and
`TEMPORARILY_UNAVAILABLE`.

The implementation MUST maintain a total profile-composition disposition for
the current internal `ErrorCode` enum:

| Current internal code | `alpic-metadata` disposition |
| --- | --- |
| `INVALID_INPUT` | map to `INVALID_INPUT` |
| `NOT_FOUND` | map to `NOT_FOUND` |
| `RESTRICTED` | map to `ACCESS_UNAVAILABLE` |
| `UPSTREAM_FAILURE` | map to `UPSTREAM_FAILURE` only after the producer excludes timeout, incompatibility, and transient unavailability |
| `DOWNLOAD_TOO_LARGE` | prove unreachable in this profile |
| `INVALID_DOCUMENT` | prove unreachable in this profile |
| `PDF_PROCESSING_FAILED` | prove unreachable in this profile |
| `RATE_LIMITED` | map only bounded local admission to `RATE_LIMITED`; upstream throttling becomes `TEMPORARILY_UNAVAILABLE` |
| `REQUEST_TIMEOUT` | map an application deadline to `TEMPORARILY_UNAVAILABLE`; an upstream deadline is `UPSTREAM_TIMEOUT` |
| `CACHE_FULL` | prove unreachable in this profile |
| `UNAUTHORIZED` | prove unreachable inside anonymous tool composition; transport rejection remains outside the tool result |
| `INTERNAL_ERROR` | map to `INTERNAL_ERROR` |

Timeout, transient-unavailability, and incompatibility producers MUST use a
closed typed internal cause (or an explicitly revised `ErrorCode` enum) before
public projection. That cause set is subject to the same total mapping test;
raw HTTP/parser exceptions are not public error selectors.

A closed test MUST prove:

```text
set(ErrorCode) == mapped_internal_codes | profile_unreachable_codes
```

Adding an internal code without a fixed mapping or profile-unreachable proof
MUST fail CI. Unexpected exceptions map only to fixed `INTERNAL_ERROR`.

## 7. Regression and evidence semantics

Golden fixtures are deterministic and synthetic. `pytest-regressions` or an
equivalent small snapshot mechanism records reviewed outputs; Git history and
PR review provide lineage. CI checks equality and never regenerates snapshots.

Live NPLG counts, ordering, availability, `envfv`, and facets are canaries only.
They MUST NOT become deterministic golden assertions.

## 8. Deferred contract surface

The first production release defers:

- public facets;
- Boolean, grouping, unary, and wildcard main-query syntax;
- authority and negative filters;
- autocomplete;
- server-side retries beyond one stale-`envfv` recovery;
- source-priority changes among DIM, METS, XOAI, MODS, ORE, and item HTML;
- citation generation, morphology, transliteration, and alias expansion;
- public `TEXT`, `THUMBNAIL`, and `LICENSE` bundle exposure;
- server-side PDF/OCR/translation/embedding work.

## 9. Approval gate

Exact contract approval means joint approval of this file and the linked model
appendix after the metadata-key inventory and any resulting schema diff. It
includes the deliberately rejected punctuation rows. Approval is not itself
permission to change production code, dependencies, locks, Git refs, hosted
systems, staging, or production. Those actions remain governed by the three
authority levels in the implementation plan.

After approval and before production implementation, Authority A MUST replace
the root `SPEC.md` with an authoritative pointer to this file (or merge this
contract into it) and mark the old phase-0/1 independent-Zod statements
superseded. There MUST be exactly one active wire-contract source of truth.
