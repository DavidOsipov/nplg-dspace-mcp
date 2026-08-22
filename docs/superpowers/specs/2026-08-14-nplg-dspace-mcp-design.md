# NPLG Iverieli DSpace MCP Server — Historical Design Specification

> **Superseded for the official-SDK migration:** `SPEC.md` and
> `docs/architecture/2026-08-14-official-python-sdk-adr.md` are the current
> phase 0–1 sources of truth. This document remains historical evidence.

**Status:** Approved design, awaiting written-spec review  
**Date:** 2026-08-14  
**Project:** `nplg-dspace-mcp`  
**Service identifier:** `nplg_dspace`  
**Owner:** David Osipov  
**Transport:** Streamable HTTP only  
**Default authentication:** None  
**License:** MIT  

## 1. Executive summary

Build a read-only Model Context Protocol server for the National Parliamentary Library of Georgia's Iverieli repository at `https://dspace.nplg.gov.ge/`.

The server will let an AI agent:

1. search public repository records;
2. retrieve normalized and raw document metadata;
3. enumerate and download public document files;
4. inspect PDF structure;
5. convert selected PDF pages to full-resolution JPEG images without resizing;
6. create overlapping JPEG tiles from those pages, also without resizing, so small Georgian newspaper type remains legible to a vision model;
7. retrieve cached PDFs, page images, tile images, and provenance manifests as MCP resources or short-lived HTTPS asset links.

The server will not perform OCR in the MVP. Existing OCR or text layers are reported as untrusted auxiliary data, and the companion agent skill instructs agents to verify Georgian newspaper content visually from page images and tiles.

The repository appears to use the DSpace 5.5-era XMLUI/Manakin interface rather than the modern DSpace 7 REST API. The integration therefore uses a dedicated adapter built from public XMLUI pages, OAI-PMH metadata, and public bitstream URLs. It must fail closed if the upstream layout or capabilities change.

## 2. Verified upstream characteristics

The design is based on the following observed or externally reported characteristics as of 2026-08-14:

- The public repository homepage is `https://dspace.nplg.gov.ge/`.
- The repository exposes DSpace communities and collections, including a large newspapers community.
- Public item pages use persistent handles such as `1234/499564` and URLs such as `https://dspace.nplg.gov.ge/handle/1234/499564`.
- Public item pages expose a file table and bitstream links such as `/bitstream/1234/499564/1/Iveria_1898_N161.pdf`.
- Full item metadata is available through the XMLUI/Manakin full-record view, conventionally `?mode=full`.
- The repository is externally reported as DSpace 5.5 and advertises an OAI-PMH base URL at `https://dspace.nplg.gov.ge/oai/request`.
- Some collections are available only from the library's internal network and must not be copied. The MCP server must report these records as restricted and must never attempt to bypass the restriction.

These are integration assumptions, not permanent guarantees. The server performs capability probes and parser-contract checks instead of trusting a fixed version string.

## 3. Goals

### 3.1 Functional goals

- Provide reliable Georgian-, Russian-, and English-language search against public Iverieli records.
- Preserve original Unicode values and field names; do not transliterate or translate metadata implicitly.
- Return both a normalized metadata view and the original qualified metadata fields when available.
- Download only public files belonging to validated Iverieli item records.
- Preserve the original PDF bytes and calculate SHA-256 provenance.
- Produce full-page JPEG images without pixel resizing.
- Extract an embedded page JPEG byte-for-byte when it is safe and visually equivalent to the rendered page.
- Create 2048 × 2048 JPEG tiles with 128-pixel overlap by cropping only, never resizing.
- Expose deterministic manifests recording page number, source PDF hash, dimensions, effective DPI, conversion path, lossiness, and tile coordinates.
- Use a single remote Streamable HTTP endpoint at `/mcp`.
- Remain usable without OAuth or another mandatory authentication flow.

### 3.2 Quality goals

- Fail closed when the upstream HTML, OAI output, redirects, MIME type, or file signature differs from expectations.
- Keep tools narrowly scoped and machine-readable.
- Make every downloaded or rendered artifact traceable to a stable handle, bitstream source URL, fetch time, and SHA-256 hash.
- Bound network, CPU, memory, disk, page count, pixel count, and execution time.
- Make parser and rendering behavior deterministic and regression-tested with pinned fixtures.

## 4. Non-goals

The MVP will not:

- authenticate to Iverieli or access internal-only collections;
- bypass access controls, geographic/network restrictions, PDF permissions, or copyright restrictions;
- upload, edit, delete, or otherwise mutate DSpace content;
- crawl or mirror the whole repository;
- provide arbitrary URL-to-PDF conversion;
- run OCR, handwriting recognition, machine translation, or automatic transcription;
- provide a general-purpose web browser;
- build a local full-text index of the corpus;
- use the DSpace 7 REST API unless future capability probing proves that the site exposes a compatible endpoint;
- provide stdio transport.

## 5. Technology and protocol baseline

### 5.1 Runtime

- TypeScript with strict compiler options.
- Node.js 22.x, pinned in the project and container image.
- ECMAScript modules.
- `pnpm` with an exact lockfile and package-manager version pinned through Corepack.
- Exact dependency versions; no floating ranges in production manifests.

### 5.2 MCP

Use the following initial production dependency baseline, subject to the mandatory package-artifact and transitive-dependency audit before installation:

- `@modelcontextprotocol/server@2.0.0`;
- `@modelcontextprotocol/node@2.0.0` for Node HTTP adaptation;
- `zod@4.4.3` for input and output schema validation;
- `sharp@0.35.3` for raster decoding, JPEG encoding, and crop-only tiling.

Every accepted package is recorded as an exact version in `package.json` and an integrity-pinned `pnpm-lock.yaml`.

The server targets MCP protocol revision `2026-07-28` and uses the SDK's stateless per-request handler factory. The official SDK's stateless legacy-compatibility mode is enabled by default for older clients. The implementation never reuses a connected server or transport instance across unrelated requests.

### 5.3 HTTP surface

- `POST /mcp` — Streamable HTTP MCP endpoint.
- `GET /healthz` — process liveness only.
- `GET /readyz` — dependency and writable-cache readiness.
- `GET /assets/:token` — short-lived signed retrieval of cached PDFs, page JPEGs, tile JPEGs, and JSON manifests.

The MCP endpoint is stateless. Artifact state is addressed explicitly through `artifact_id`, `render_id`, and `asset_id`, not through protocol sessions.

## 6. High-level architecture

```text
MCP client
   |
   | POST /mcp
   v
MCP HTTP adapter
   |
   +--> Tool layer
   |      |
   |      +--> Repository service
   |      |      +--> XMLUI search adapter
   |      |      +--> OAI-PMH metadata adapter
   |      |      +--> XMLUI item/bitstream adapter
   |      |
   |      +--> Artifact service
   |      |      +--> validated downloader
   |      |      +--> content-addressed cache
   |      |
   |      +--> PDF service
   |             +--> inspector
   |             +--> native-image classifier
   |             +--> sandboxed renderer
   |             +--> JPEG encoder
   |             +--> tile generator
   |
   +--> Resource layer
   |      +--> metadata JSON
   |      +--> original PDF
   |      +--> render manifest
   |      +--> full-page JPEG
   |      +--> tile JPEG
   |
   +--> Signed asset HTTP handler
```

Each component has one responsibility and an explicit interface. Upstream parsing, file acquisition, PDF analysis, rendering, storage, and MCP presentation remain independently testable.

## 7. Repository adapter

### 7.1 Capability discovery

At startup and then at a bounded interval, the server probes:

- repository homepage reachability;
- expected handle URL behavior;
- OAI-PMH `Identify` and `ListMetadataFormats` responses;
- supported OAI metadata prefixes;
- expected XMLUI search form and result markers;
- expected item-page file table markers.

The probe result is cached for six hours. A failed probe does not silently select a looser parser. Affected tools return `UPSTREAM_CHANGED` with a concise diagnostic and the failed capability name.

### 7.2 Search strategy

Search uses the public XMLUI/Manakin `/simple-search` interface because OAI-PMH is a harvesting protocol, not a relevance-search API.

Inputs:

- `query` — required Unicode string, 1–500 characters;
- `scope_handle` — optional validated community or collection handle;
- `syntax` — `literal` by default, or `dspace` for explicit Lucene-style syntax;
- `page_size` — 1–50, default 20;
- `cursor` — opaque server cursor;
- `sort` — `relevance`, `date_asc`, `date_desc`, or `title_asc`.

Literal mode escapes DSpace/Lucene control characters. DSpace mode preserves supported phrase, wildcard, Boolean, and grouping syntax but still enforces the length and character policy.

The parser returns only records with a valid Iverieli handle. It preserves Georgian text as UTF-8 normalized to NFC while retaining the original display value where normalization changes code points.

### 7.3 Metadata strategy

Preferred order:

1. OAI-PMH `GetRecord` with `dim` when the capability probe reports that prefix;
2. OAI-PMH `GetRecord` with `oai_dc` when `dim` is unavailable or fails schema validation;
3. XMLUI full item record (`?mode=full`);
4. XMLUI summary item page.

The normalized record contains:

- handle and canonical URL;
- titles;
- creators/contributors;
- issue dates;
- publishers;
- descriptions;
- subjects;
- languages;
- identifiers;
- rights and owners;
- collection membership;
- raw metadata fields with schema, element, qualifier, language, and value;
- metadata source and fetch timestamp.

No value is silently translated, inferred, or deduplicated across materially different source fields.

### 7.4 Bitstream strategy

The item page is parsed for its file table. A bitstream entry contains:

- stable server-generated `bitstream_id`;
- item handle;
- display filename;
- validated source URL;
- sequence where derivable;
- reported size;
- reported format;
- discovered MIME type after download;
- access status: `public`, `restricted`, `missing`, or `unknown`.

Only `https://dspace.nplg.gov.ge/bitstream/...` URLs obtained from a validated item page are downloadable. The server never accepts an arbitrary remote URL as a download target.

## 8. MCP tools

All tools return structured content validated against explicit output schemas. Errors use stable machine-readable codes.

### 8.1 `search_documents`

Search public repository records.

Returns:

- parsed result records;
- canonical handles and URLs;
- compact metadata;
- opaque `next_cursor` when another page exists;
- provenance for the search response.

### 8.2 `get_document_metadata`

Retrieve full normalized and raw metadata for one handle or canonical Iverieli item URL.

Inputs do not permit an arbitrary host. URL input is normalized to a handle before any upstream request.

### 8.3 `list_document_files`

List public and restricted bitstreams for one item. This tool does not download content.

### 8.4 `download_document_file`

Download a selected public bitstream into the content-addressed cache.

Inputs:

- `handle`;
- `bitstream_id` returned by `list_document_files`.

Returns:

- `artifact_id`;
- resource link;
- short-lived signed HTTPS asset link;
- source URL;
- original display filename;
- MIME type;
- byte size;
- SHA-256;
- fetch timestamp;
- access and rights metadata known from the item.

### 8.5 `inspect_pdf`

Inspect a cached PDF or download a selected public PDF and inspect it in one call.

Returns document-level and page-level information:

- page count;
- encryption and permission status;
- MediaBox and CropBox;
- rotation;
- embedded image inventory;
- image dimensions, encoding, color space, and effective DPI;
- detected text layer;
- page classification;
- eligible native-render path;
- safety-limit decisions.

### 8.6 `render_pdf_pages`

Render selected pages to full-size JPEG images.

Default input:

```json
{
  "artifact_id": "art_...",
  "pages": [1],
  "mode": "native",
  "format": "jpeg",
  "jpeg_quality": 100
}
```

Limits:

- maximum eight pages per call;
- no duplicate page numbers;
- page numbers must exist;
- total pixel and output-byte budgets apply.

Returns a render manifest and resource links, not a large array of base64 images.

### 8.7 `render_pdf_page_tiles`

Create tiles from one already-rendered full page.

Defaults:

```json
{
  "tile_width": 2048,
  "tile_height": 2048,
  "overlap": 128,
  "format": "jpeg",
  "jpeg_quality": 100
}
```

The operation uses crop only. It never resizes the page or a tile. Edge tiles are smaller than 2048 pixels when the remaining page region is smaller.

### 8.8 `get_render_manifest`

Return a previously generated deterministic manifest without rerendering.

### 8.9 `get_rendered_image`

Return one page or tile as MCP image content when the encoded image is within the configured inline limit. Otherwise return resource and signed HTTPS links.

### 8.10 `delete_render`

Delete one render's cached derivative files before their normal expiry. The original downloaded PDF remains independently cached according to its own policy.

### 8.11 `get_repository_capabilities`

Return the current adapter capability state, metadata formats, parser profile, limits, and last successful probe time. This is diagnostic and helps an agent distinguish a repository outage from a malformed query.

## 9. MCP resources

Canonical resource URI templates:

```text
nplg://item/{percent_encoded_handle}
nplg://artifact/{artifact_id}
nplg://render/{render_id}/manifest
nplg://render/{render_id}/page/{page_number}
nplg://render/{render_id}/page/{page_number}/tile/{tile_id}
```

Metadata and manifests are returned as JSON text resources. PDF and JPEG resources are returned as binary blobs only when they fit configured MCP payload limits; otherwise the resource response contains a signed HTTPS retrieval link and complete provenance.

Signed asset URLs:

- contain an opaque HMAC token, never a filesystem path;
- expire after 15 minutes by default;
- authorize one immutable content-addressed object only;
- are safe for repeated GET requests until expiry;
- set an explicit `Content-Type`, bounded `Content-Length`, and safe `Content-Disposition`.

## 10. PDF inspection and native-resolution rules

### 10.1 Definition of "without changing resolution"

The invariant is pixel preservation, not merely a DPI metadata value:

- no resize operation is applied to a raster source;
- output width and height match the selected native page raster dimensions;
- tiles are rectangular crops from those page pixels;
- if a page has no native raster dimensions because it is vector or mixed content, the server uses an explicit fallback resolution and labels it as such;
- manifests distinguish `resize_applied` from `renderer_resampling`: matching the native pixel grid proves that no resize was requested, but a PDF compositor can still interpolate a transformed image, which is reported separately.

### 10.2 Page classifications

- `single_raster_jpeg` — one dominant DCT/JPEG image represents the page.
- `single_raster_other` — one dominant non-JPEG raster represents the page.
- `raster_with_overlay` — a dominant scan plus text or graphical overlays.
- `mixed` — multiple meaningful rasters and/or vector content.
- `vector` — no meaningful page-sized raster.
- `unsupported` — malformed, encrypted, over limits, or otherwise unsafe.

A dominant raster must cover at least 98% of the effective CropBox area after rotation and must have plausible page-scale effective DPI.

### 10.3 Direct JPEG extraction

The server exposes the original embedded JPEG bytes without re-encoding only when all of the following hold:

1. the page has exactly one dominant DCT/JPEG image candidate;
2. its orientation and pixel dimensions correspond to the effective page;
3. a lossless reference render at those dimensions is visually equivalent within a strict tolerance;
4. no visible overlay materially changes the page;
5. the extracted stream decodes successfully and passes image limits.

When direct extraction is used:

- `resize_applied` is `false`;
- `pixel_dimensions_preserved` is `true`;
- `renderer_resampling` is `none`;
- `reencoded` is `false`;
- `lossy_conversion` is `false` for this operation;
- output SHA-256 is the SHA-256 of the original embedded JPEG bytes.

The equivalence check is deliberately conservative. Any uncertainty selects a render path instead of claiming native byte identity.

### 10.4 Non-JPEG native raster

For a single dominant PNG, TIFF, CCITT, JBIG2, JPEG 2000, or other supported raster:

- decode the raster;
- preserve exact width and height;
- encode JPEG with quality 100 and 4:4:4 chroma sampling;
- do not invoke resize or interpolation;
- mark `resize_applied: false`, `pixel_dimensions_preserved: true`, and `renderer_resampling: "none"`;
- mark `reencoded: true` and `lossy_conversion: true`.

### 10.5 Raster with overlay

For a dominant scan plus a visible or uncertain overlay:

- render the full page at exactly the dominant scan's width and height;
- preserve CropBox and rotation semantics;
- encode to JPEG at quality 100, 4:4:4;
- report `resolution_source: "embedded_scan"`;
- report `resize_applied: false` and `pixel_dimensions_preserved: true`;
- report `renderer_resampling: "possible"`, because PDF compositing can interpolate even when the output grid exactly matches the dominant scan dimensions;
- report `reencoded: true` and `lossy_conversion: true`.

### 10.6 Vector or mixed fallback

When no defensible native raster grid exists:

- render at 400 DPI;
- preserve the page aspect ratio, CropBox, and rotation;
- label `resolution_source: "fallback_400_dpi"`;
- never describe the result as native resolution.

### 10.7 JPEG encoding

For every required JPEG re-encode:

```text
quality = 100
chroma subsampling = 4:4:4
progressive = false
resize = prohibited
orientation = physically applied and recorded
ICC profile = preserved when valid and safe
```

Quality 100 JPEG is still lossy. The manifest must state this explicitly.

## 11. Tiling rules

Default tile geometry:

- width: 2048 pixels;
- height: 2048 pixels;
- overlap: 128 pixels on each advancing axis;
- origin: top-left of the physically oriented full-page image;
- traversal order: row-major, top-to-bottom and left-to-right.

Each tile records:

- page number;
- tile identifier;
- `x`, `y`, `width`, and `height` in source-page pixels;
- overlap configuration;
- full-page dimensions;
- page asset SHA-256;
- tile SHA-256;
- `resize_applied: false`;
- `pixel_dimensions_preserved: true`;
- `renderer_resampling: "none"`;
- `reencoded` and `lossy_conversion` flags.

The tile set must cover every page pixel. Coordinates must permit deterministic reconstruction. No whitespace padding is added to edge tiles.

## 12. Artifact identifiers, storage, and caching

### 12.1 Content addressing

Original files are keyed by SHA-256. Derived artifacts use a deterministic key:

```text
SHA256(
  source_pdf_sha256
  + selected_pages
  + crop_box_policy
  + rotation_policy
  + render_mode
  + output_format
  + jpeg_parameters
  + tile_parameters
  + renderer_version
)
```

Public identifiers are opaque prefixed IDs:

- `art_...` — downloaded source artifact;
- `rnd_...` — render operation;
- `ast_...` — individual page, tile, PDF, or manifest asset.

### 12.2 Storage

MVP storage is a local content-addressed filesystem cache suitable for one server instance.

- Original PDF default retention: 24 hours after last access.
- Render derivative default retention: 6 hours after last access.
- Signed URL lifetime: 15 minutes.
- Cleanup: opportunistic on access plus a bounded periodic sweep.
- Maximum cache size: configurable; least-recently-used eviction above the high-water mark.

Object storage and multi-node cache coordination are deferred until there is an actual scaling requirement.

## 13. Security model

### 13.1 Outbound request policy

- HTTPS only.
- Exact hostname allowlist: `dspace.nplg.gov.ge`.
- Port 443 only.
- Path allowlist for repository pages, OAI, handles, search, and bitstreams.
- Resolve and reject loopback, link-local, private, multicast, documentation, and otherwise non-public addresses.
- Revalidate every redirect target; maximum three redirects.
- Reject userinfo, fragments, alternate ports, mixed-scheme redirects, and ambiguous URL encodings.
- Apply connect, first-byte, total-body, and idle timeouts.
- Use bounded per-origin concurrency and request rate.

### 13.2 Download validation

- Require a bitstream discovered on a validated item page.
- Enforce `Content-Length` when present and a streaming byte counter always.
- Validate PDF magic bytes and MIME type.
- Sanitize display filenames but store only under internal hashes.
- Reject HTML login/error pages masquerading as PDFs.
- Never send credentials or ambient cookies upstream.

### 13.3 PDF execution sandbox

Untrusted PDF tools run through argument-array process spawning with no shell.

Production rendering requires a sandbox wrapper that:

- runs as a dedicated unprivileged user;
- creates a new network namespace with no network access;
- mounts only the source PDF read-only and an empty output directory writable;
- uses a read-only root filesystem;
- applies CPU, address-space, file-size, process-count, and wall-clock limits;
- removes Linux capabilities;
- applies the deployment seccomp profile;
- kills the complete process group on timeout or client cancellation.

The Linux wrapper is Bubblewrap with `--unshare-net`. If the required isolation cannot be established in production mode, PDF inspection/render tools return `SANDBOX_UNAVAILABLE`; they do not silently execute unsandboxed. Unsandboxed local execution is permitted only when both `NODE_ENV` is not `production` and `PRODUCTION_SANDBOX_REQUIRED=false` are set explicitly.

### 13.4 Application and transport controls

- Fresh MCP handler/server context per stateless request.
- Strict JSON body and schema size limits.
- Host-header validation.
- Origin allowlist; absent `Origin` remains valid for server-to-server clients.
- No wildcard CORS in production.
- No mandatory authentication by default.
- Configurable IP rate limits and concurrent-render quotas.
- Optional static bearer token may be enabled by the operator; OAuth is not required for the MVP.
- Logs never include file bytes, signed tokens, cookies, authorization headers, or full binary paths.

### 13.5 Default hard limits

- Maximum source download: 512 MiB.
- Maximum PDF pages: 2,000.
- Maximum pages rendered per tool call: 8.
- Maximum page pixels: 120 megapixels.
- Maximum total rendered pixels per call: 480 megapixels.
- Maximum tiles per page: 100.
- Tile dimensions: 512–4096 pixels.
- Tile overlap: 0–512 pixels and smaller than both tile dimensions.
- Maximum inline MCP image payload: 10 MiB.
- Download timeout: 120 seconds.
- Inspect timeout: 60 seconds.
- Render timeout: 180 seconds per request.

All limits are configurable downward. Production configuration cannot exceed compiled absolute ceilings without a code change and test update.

## 14. Access restrictions and rights

The server treats upstream access control as authoritative.

A bitstream or item is `restricted` when, for example:

- the collection description states that it is available only inside the library;
- the bitstream request returns 401 or 403;
- the response redirects to login or produces a login page;
- the item page exposes no public bitstream for an otherwise known record.

For restricted content the server returns metadata and the restriction reason when publicly visible, but no file retrieval or rendering tool proceeds.

The server does not infer that public technical accessibility means public-domain status. It surfaces rights and owner metadata and preserves the repository's copyright notice in provenance.

## 15. Error model

Stable error codes:

- `INVALID_INPUT`
- `INVALID_HANDLE`
- `NOT_FOUND`
- `RESTRICTED`
- `UPSTREAM_UNAVAILABLE`
- `UPSTREAM_RATE_LIMITED`
- `UPSTREAM_CHANGED`
- `UNEXPECTED_CONTENT_TYPE`
- `DOWNLOAD_LIMIT_EXCEEDED`
- `UNSUPPORTED_FILE`
- `PDF_ENCRYPTED`
- `PDF_MALFORMED`
- `PDF_LIMIT_EXCEEDED`
- `RENDER_LIMIT_EXCEEDED`
- `SANDBOX_UNAVAILABLE`
- `TIMEOUT`
- `CACHE_MISS`
- `ASSET_EXPIRED`
- `INTERNAL_ERROR`

Errors include:

- human-readable summary;
- retryability;
- upstream status when safe;
- relevant handle, artifact, or render identifier;
- no internal stack trace or local path.

## 16. Companion agent skill

The repository includes:

```text
skills/georgian-newspaper-visual-analysis/SKILL.md
```

The skill instructs an AI agent to:

1. search and select a record;
2. retrieve full metadata and file inventory;
3. download only a public PDF;
4. call `inspect_pdf` before visual analysis;
5. treat Georgian OCR/text layers as untrusted unless visually verified;
6. call `render_pdf_pages` in `native` mode;
7. view the full page first to understand layout and column order;
8. call `render_pdf_page_tiles` for small newspaper type;
9. inspect tiles in deterministic row-major order while accounting for overlap;
10. record handle, bitstream filename, PDF SHA-256, page number, and tile coordinates in notes and citations;
11. label uncertain readings rather than inventing characters;
12. avoid rerunning OCR automatically.

The skill is documentation and orchestration guidance. The actual PDF-to-JPEG capability remains implemented as MCP tools and resources so it is enforceable and testable.

## 17. Observability

- Structured JSON logs.
- Request correlation ID and MCP request ID where available.
- Metrics for tool calls, upstream latency, parser failures, cache hits, download bytes, render duration, pixel counts, sandbox failures, and rate-limit decisions.
- Upstream query text is excluded from default logs; a normalized query hash is logged for cache diagnostics.
- Health endpoints disclose no secrets, filesystem paths, or upstream response bodies.

## 18. Testing strategy

Implementation follows test-driven development. Behavior is not considered complete from source inspection alone.

### 18.1 Parser fixtures

Pinned, sanitized fixtures for:

- homepage/community page;
- collection result page;
- simple-search results;
- item summary page;
- full metadata page;
- OAI `Identify`;
- OAI metadata-format list;
- OAI `GetRecord` in `dim` and `oai_dc`;
- public bitstream table;
- restricted collection and login/error response.

Fixtures retain enough original Georgian text and HTML structure to detect encoding and selector regressions.

### 18.2 Synthetic PDF corpus

Generate deterministic PDFs covering:

- one embedded JPEG page;
- embedded JPEG plus invisible OCR text;
- embedded JPEG plus visible overlay;
- CCITT monochrome scan;
- JPEG 2000 scan;
- rotated page;
- non-default CropBox;
- multiple page images;
- vector-only page;
- mixed vector/raster page;
- encrypted PDF;
- malformed/truncated PDF;
- decompression and pixel-limit adversarial cases.

### 18.3 Rendering invariants

Tests prove:

- directly extracted JPEG bytes are byte-identical to the embedded source;
- native-raster conversions preserve exact width and height;
- no resize function is invoked in native and tile paths;
- fallback pages are labeled `fallback_400_dpi`;
- every tile coordinate lies within the page;
- the tile set covers every source pixel;
- overlap and edge-tile dimensions are exact;
- manifests are deterministic for identical inputs and renderer versions.

### 18.4 Security tests

Include negative tests for:

- arbitrary hosts and schemes;
- encoded and Unicode hostname confusion;
- redirects to private IP space;
- path traversal and malicious filenames;
- HTML masquerading as PDF;
- oversized declared and chunked bodies;
- shell metacharacters in all user-visible strings;
- sandbox absence;
- process timeout, crash, fork attempt, and output flood;
- signed-token tampering and expiry;
- concurrent request isolation;
- cache eviction during reads.

### 18.5 MCP conformance

- Tool and resource schema snapshot tests.
- Streamable HTTP request/response tests against the official SDK client.
- MCP Inspector smoke test from a fresh server process.
- Protocol `2026-07-28` tests.
- Legacy stateless compatibility test where enabled by the SDK.
- Cancellation test proving renderer process-group termination.
- No cross-request server or transport reuse.

### 18.6 Live tests

Live Iverieli tests are opt-in, low-frequency, read-only, and rate-limited. They verify one known public item and one known restricted collection. CI does not repeatedly harvest or bulk-search the repository.

## 19. Deployment

### 19.1 Container

- Multi-stage Docker build.
- Pinned digest for the Node base image.
- Non-root runtime user.
- Read-only root filesystem.
- Writable tmpfs for short-lived renderer work.
- Dedicated cache volume.
- No additional Linux capabilities.
- Health check against `/healthz`.
- PDFium via a pinned pypdfium2 wheel and required shared libraries pinned by the image build.

### 19.2 Network

- TLS terminates at a trusted reverse proxy or managed ingress.
- Public route exposes `/mcp` and signed `/assets` only.
- Administrative metrics are private.
- Egress is restricted to DNS resolution and `dspace.nplg.gov.ge:443` as far as the deployment platform permits.
- Reverse proxy applies request-body limits, connection limits, and rate limiting before Node.

### 19.3 Configuration

Primary environment variables:

```text
NPLG_BASE_URL=https://dspace.nplg.gov.ge
MCP_PATH=/mcp
CACHE_DIR=/data/cache
CACHE_MAX_BYTES=21474836480
SOURCE_TTL_SECONDS=86400
RENDER_TTL_SECONDS=21600
ASSET_TOKEN_TTL_SECONDS=900
MAX_DOWNLOAD_BYTES=536870912
MAX_PAGE_PIXELS=120000000
MAX_RENDER_PAGES=8
MAX_RENDER_TOTAL_PIXELS=480000000
INLINE_IMAGE_MAX_BYTES=10485760
UPSTREAM_MAX_CONCURRENCY=2
UPSTREAM_REQUESTS_PER_SECOND=1
ALLOWED_ORIGINS=
OPTIONAL_BEARER_TOKEN=
PRODUCTION_SANDBOX_REQUIRED=true
```

Secrets are never committed. `OPTIONAL_BEARER_TOKEN` is empty by default.

## 20. Repository layout

```text
nplg-dspace-mcp/
  src/
    app/
      http.ts
      mcp.ts
      config.ts
    tools/
      search-documents.ts
      get-document-metadata.ts
      list-document-files.ts
      download-document-file.ts
      inspect-pdf.ts
      render-pdf-pages.ts
      render-pdf-page-tiles.ts
      get-render-manifest.ts
      get-rendered-image.ts
      delete-render.ts
      get-repository-capabilities.ts
    resources/
      register-resources.ts
      signed-assets.ts
    repository/
      capabilities.ts
      handle.ts
      search-adapter.ts
      item-adapter.ts
      oai-adapter.ts
      bitstream-adapter.ts
      parsers/
    artifacts/
      artifact-store.ts
      content-addressing.ts
      downloader.ts
      manifests.ts
    pdf/
      inspector.ts
      classifier.ts
      renderer.ts
      jpeg.ts
      tiles.ts
      sandbox.ts
      commands.ts
    security/
      outbound-policy.ts
      redirect-policy.ts
      limits.ts
      tokens.ts
    domain/
      schemas.ts
      errors.ts
      types.ts
    observability/
      logger.ts
      metrics.ts
  skills/
    georgian-newspaper-visual-analysis/
      SKILL.md
  test/
    fixtures/
    unit/
    integration/
    security/
    conformance/
    live/
  docs/
    superpowers/specs/
  Dockerfile
  compose.yaml
  package.json
  pnpm-lock.yaml
  tsconfig.json
  README.md
  LICENSE
```

## 21. Acceptance criteria

The MVP is accepted only when all of the following are demonstrated from a fresh build:

1. A client connects to `POST /mcp` using Streamable HTTP.
2. `search_documents` returns valid Iverieli handles for Georgian and Russian queries.
3. `get_document_metadata` returns normalized and raw metadata for a known public record.
4. `list_document_files` identifies the public PDF for handle `1234/499564` without accepting a caller-supplied arbitrary URL.
5. `download_document_file` caches that PDF, returns a stable SHA-256, and exposes a bounded resource or signed link.
6. A known restricted collection is reported as `RESTRICTED`, with no attempted bypass.
7. `inspect_pdf` reports page count, boxes, rotation, raster inventory, and classification.
8. A synthetic single-JPEG PDF produces byte-identical direct JPEG extraction.
9. A non-JPEG scan produces a JPEG with identical pixel dimensions and `lossy_conversion: true`.
10. A vector page produces a correctly labeled 400-DPI fallback.
11. Full-page output and 2048 × 2048 / 128-overlap tiles contain no resize operation and pass coverage tests.
12. All tools enforce hard limits and terminate sandboxed processes on timeout or cancellation.
13. SSRF, redirect, path traversal, content spoofing, and cross-request isolation tests pass.
14. MCP conformance and fresh-process Inspector smoke tests pass.
15. The companion skill successfully guides an agent through full-page and tile-based analysis while preserving provenance.

## 22. Source references

- Iverieli repository: <https://dspace.nplg.gov.ge/>
- Iverieli help/search behavior: <https://dspace.nplg.gov.ge/help/index.html>
- Example public item: <https://dspace.nplg.gov.ge/handle/1234/499564>
- Repository registry record and reported DSpace/OAI characteristics: <https://ird.coar-repositories.org/systems/65ead5c9-a630-444b-b77e-ced5b9b0fd9c?lang=en>
- MCP Streamable HTTP specification: <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>
- MCP TypeScript SDK: <https://github.com/modelcontextprotocol/typescript-sdk>
- pypdfium2/PDFium: <https://github.com/pypdfium2-team/pypdfium2>
- Poppler `pdfimages`: <https://manpages.debian.org/unstable/poppler-utils/pdfimages.1.en.html>
- Sharp JPEG options: <https://sharp.pixelplumbing.com/api-output/>
- Zod releases: <https://github.com/colinhacks/zod/releases>
