# NPLG DSpace MCP

Upstream-read-only Streamable HTTP MCP server for the National Parliamentary Library of Georgia's Iverieli repository (`dspace.nplg.gov.ge`). Its public Alpic profile exposes archive search and returns metadata plus public bitstream URLs. `search_documents` fails closed with `UPSTREAM_FAILURE` when NPLG's search route is unavailable; it does not use an unapproved fallback scraper. The separate private profile can download validated PDFs and render historical Georgian newspapers as full-page JPEGs plus overlapping crop-only tiles.

## What is implemented

- The direct/private application endpoint is sessionless MCP `2026-07-28` over `POST /mcp` and uses `server/discover`. Alpic's hosted gateway separately owns the public legacy `initialize` lifecycle, currently negotiates `2025-11-25`, requires `notifications/initialized`, and may issue an `Mcp-Session-Id` that must be reused; a passing candidate-bound hosted verification proves that lifecycle is terminated or translated at the gateway rather than forwarded to the modern-only application process.
- NPLG-specific current JSPUI, legacy DSpace 5.5 XMLUI/Manakin, and OAI-PMH adapters; this is intentionally not a generic DSpace scraper.
- Exact-origin, canonical-handle, DNS/IP, redirect, MIME, signature, streaming-size, and path controls.
- Rich Dublin Core metadata with OAI-DIM preference and bounded JSPUI/XMLUI repository-HTML fallback.
- Content-addressed public PDF storage, signed expiring asset URLs, and canonical MCP resource reads for authorized PDFs, manifests, page JPEGs, and tiles in the private profile.
- Conservative PDFium-based page classification:
  - byte-identical extraction for eligible single embedded JPEG pages;
  - native embedded-scan pixel-grid rendering where defensible;
  - explicitly labelled `fallback_400_dpi` for vector or mixed pages.
- JPEG pages with no post-render resize.
- Default 2048×2048 crop-only tiles with 128-pixel overlap.
- Shared upstream request pacing plus fail-fast MCP, asset-stream, server-wide, and PDF-job concurrency bounds.
- The public `alpic-metadata` profile is anonymous and exposes only three metadata tools; static bearer/API-key configuration remains forbidden in production.
- Docker Compose + Caddy deployment assets and post-deploy verification scripts.

The server performs no OCR. The public profile exposes the companion workflow
as a static MCP resource; it tells resource-capable agents to retrieve an
explicitly public PDF URL and preserve evidence while inspecting the document
locally. MCP does not require every client to discover or execute that workflow.
No MCP tool mutates the upstream NPLG archive and render deletion remains
operator-only. The three private tools that populate the local download/render
cache are accurately
marked as cache-writing in their MCP annotations.

## MCP tools

`alpic-metadata` exposes exactly the first three tools. The five PDF and render
tools are available only in `private-full`.

| Tool | Purpose |
| --- | --- |
| `search_documents` | Search Iverieli, optionally within a collection handle. |
| `get_document_metadata` | Read rich metadata for a canonical handle. |
| `list_document_files` | List public and restricted bitstreams attached to an item. |
| `download_document_file` | Download a discovered public PDF only. |
| `inspect_pdf` | Classify pages and report scan geometry and text overlays. |
| `render_pdf_pages` | Create full-page JPEGs on the native scan grid or labelled fallback grid. |
| `render_pdf_page_tiles` | Create overlapping crop-only tiles without resize. |
| `get_render_manifest` | Refresh structured render metadata and signed links. |

## MCP resources

The public `alpic-metadata` profile advertises exactly one non-templated,
read-only `text/markdown` resource:

- `nplg://skills/georgian-newspaper-visual-analysis` contains bounded
  instructions for selecting a public bitstream and performing PDF inspection
  in the client environment. It performs no server-side download, parsing,
  rendering, caching, or deletion.

The `private-full` profile advertises one fixed resource and two canonical
templates:

- `nplg://about` describes the server's read-only scope and provenance rules.
- `nplg://artifact/{artifact_id}` reads an authorized content-addressed PDF,
  rendered JPEG, or tile manifest. A concrete artifact identifier is `doc_`
  followed by exactly 64 lowercase hexadecimal SHA-256 characters.
- `nplg://render/{render_id}/manifest` reads an authorized bounded render
  manifest. A concrete render identifier is `rnd_` followed by exactly 32
  lowercase hexadecimal characters.

Clients resolve those canonical URIs through `resources/read`. Successful tool
calls put their strictly validated Pydantic result in `structuredContent`; the
SDK `content` array carries one bounded human summary. Expected tool execution
errors set `isError: true`, return one sanitized text message, and omit
`structuredContent` so clients do not validate an error against the advertised
success schema. Tool result `resource_uri` fields identify resources that may be
read through the protocol after the same authorization and expiry checks. The
`alpic-metadata` profile does not register resource templates or advertise local
storage, PDF processing, or asset routes.

## Local development

The supported Python range is `>=3.12,<3.15`. The reviewed bootstrap lock is
for `uv 0.12.5`, Node `24.19.0`, npm `11.18.0`, and the x86_64 Linux target;
runtime downloads only immutable direct artifacts and authenticates them with
the repository-pinned SHA-256 after accepted upstream-evidence review. Runtime
and development dependencies are hash-pinned.

`requirements-security.in` is intentionally separate from
`requirements-dev.in`: Semgrep `1.175.0` hard-pins `mcp==1.29.0`, which is
incompatible with the required official `mcp==2.1.1`. Combining those inputs
would produce an unsatisfiable lock rather than a stricter environment.

```bash
set -euo pipefail

# Choose an absolute path outside this checkout. The caller creates and owns it.
TOOL_ROOT=/absolute/external/path/nplg-toolchain
mkdir -m 0700 "$TOOL_ROOT"

python3 scripts/bootstrap_toolchain.py \
  --lock security/bootstrap-toolchain-lock.json \
  --tool uv \
  --target x86_64-unknown-linux-gnu \
  --destination "$TOOL_ROOT/uv"
python3 scripts/bootstrap_toolchain.py \
  --lock security/bootstrap-toolchain-lock.json \
  --tool node \
  --target x86_64-unknown-linux-gnu \
  --destination "$TOOL_ROOT/node"
python3 scripts/bootstrap_toolchain.py \
  --lock security/bootstrap-toolchain-lock.json \
  --tool npm \
  --target x86_64-unknown-linux-gnu \
  --destination "$TOOL_ROOT/npm" \
  --dependency "node=$TOOL_ROOT/node"

UV_BIN="$TOOL_ROOT/uv/uv-0.12.5.data/scripts"
NODE_BIN="$TOOL_ROOT/node/node-v24.19.0-linux-x64/bin"
NPM_BIN="$TOOL_ROOT/npm/bin"
export PATH="$UV_BIN:$NPM_BIN:$NODE_BIN:/usr/bin:/bin"

test "$(uv --version)" = "uv 0.12.5 (x86_64-unknown-linux-gnu)"
test "$(node --version)" = "v24.19.0"
test "$(npm --version)" = "11.18.0"

uv venv --python "$(uv python find 3.13.15)" .venv
uv pip sync --python .venv/bin/python --require-hashes requirements-dev.lock
npm ci --ignore-scripts
test "$(.venv/bin/python -c 'import platform; print(platform.python_version())')" = "3.13.15"
test "$(npm exec --offline -- pyright --version)" = "pyright 1.1.413"
```

The exact Python `3.13.15` claim is established only after the checks above
pass. Do not substitute an ambient package installer or editable checkout.

Start the local service from the synchronized environment:

```bash
set -euo pipefail

export NODE_ENV=development
export DEPLOYMENT_PROFILE=private-full
export CURSOR_SIGNING_SECRET="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
export ASSET_SIGNING_SECRET="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
export ALLOW_ANONYMOUS=true
export PUBLIC_BASE_URL=http://127.0.0.1:8000
.venv/bin/python -m nplg_mcp
```

In another shell:

```bash
.venv/bin/python scripts/verify_deploy.py \
  --base-url http://127.0.0.1:8000 \
  --profile private-full
```

From the shell where the reviewed toolchain variables above were set, run
tests:

```bash
NPLG_REVIEWED_NODE="$NODE_BIN/node" .venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q src scripts
```

Offline tests use pinned HTML/OAI fixtures and a synthetic PDF corpus. Live NPLG checks are deliberately opt-in.

The phase 0–1 capability records under `contracts/` are negative evidence,
not OAuth support: dynamic operation-scope 403, exact Alpic detector replay,
route compatibility, provider selection, DCR issuer semantics, and the witnessed
end-to-end flow remain deferred work. The public `alpic-metadata` profile does
not consume that verdict; it still refuses all static bearer/API-key fallback.

## Production deployment

The current candidate remains `do_not_release` until its candidate and protected release gates are complete. The public `alpic-metadata` profile does not require OAuth, but Alpic's serverless runtime, 30-second tool limit, and static `/assets/` handling do not provide a full-fidelity target for the current multi-call rendering workflow. See [`deploy/ALPIC.md`](deploy/ALPIC.md) for the restricted metadata deployment.

The checked-in Docker Compose path selects `private-full`; it is not a
Docker/VPS substitute for the anonymous metadata deployment and correctly
fails closed with the metadata profile's anonymous settings. Follow
[`deploy/ALPIC.md`](deploy/ALPIC.md) for the restricted `alpic-metadata`
deployment. A future authenticated full-profile deployment requires its own
approved runtime and release contract.

When reviewing that deferred Compose configuration, validate it without
printing the rendered environment, which can contain secrets:

```bash
docker compose --env-file .env config --quiet
```

## Design, review, and agent workflow

- Approved design: `docs/superpowers/specs/2026-08-14-nplg-dspace-mcp-design.md`
- Implementation plan: `docs/superpowers/plans/2026-08-14-nplg-dspace-mcp-implementation.md`
- Critical review: `docs/reviews/2026-08-14-critical-review.md`
- Georgian visual-analysis skill: `skills/georgian-newspaper-visual-analysis/SKILL.md`
- Current security-repair verification: `docs/verification/2026-08-14-security-repair-report.md`
- Historical verification snapshot: `docs/verification/2026-08-14-verification-report.md`

## Explicit limitations

- Live JSPUI/XMLUI/OAI compatibility must be rechecked after deployment because upstream HTML can change.
- The server uses the official MCP Python SDK behind project-owned HTTP admission
  and bounded JSON preflight controls; those controls cover only this server's
  supported profiles.
- Hosted SDK interoperability and Inspector checks remain part of the
  separately governed post-deploy evidence, not local release authority.
- PDF work is bounded inside a hardened container but not inside a separately verified nested sandbox.
- The cache is single-node filesystem storage and is not horizontally coordinated or automatically pruned. A process-local logical-byte quota rejects new cache writes at `CACHE_MAX_BYTES`; retain a filesystem/inode limit and disk alerts as independent controls.
- Process-local admission limits bound work inside one server process; they are not per-client rate limits. Internet deployments still need a trusted edge policy for client-aware abuse controls.
- Public download access does not establish public-domain status; rights metadata remains part of the evidence record.

## License

The project-authored source is MIT. Runtime and development dependencies retain their own licenses; see `THIRD_PARTY_NOTICES.md`. The production image uses permissively licensed pypdfium2/PDFium, and synthetic fixtures use permissively licensed ReportLab and pypdf.
