# NPLG DSpace MCP

Upstream-read-only Streamable HTTP MCP server for the National Parliamentary Library of Georgia's Iverieli repository (`dspace.nplg.gov.ge`). It lets an agent search the archive, read rich document metadata, list and download validated public PDF bitstreams, and inspect historical Georgian newspapers as full-page JPEGs plus overlapping crop-only tiles.

## What is implemented

- Sessionless MCP `2026-07-28` over `POST /mcp`, with a compatibility path for `2025-11-25` clients.
- NPLG-specific DSpace 5.5 XMLUI/Manakin and OAI-PMH adapter; this is intentionally not a generic DSpace scraper.
- Exact-origin, canonical-handle, DNS/IP, redirect, MIME, signature, streaming-size, and path controls.
- Rich Dublin Core metadata with OAI-DIM preference and bounded XMLUI fallback.
- Content-addressed public PDF storage, signed expiring asset URLs, and standard MCP `resource_link` content blocks for PDFs, manifests, page JPEGs, and tiles.
- Conservative PDFium-based page classification:
  - byte-identical extraction for eligible single embedded JPEG pages;
  - native embedded-scan pixel-grid rendering where defensible;
  - explicitly labelled `fallback_400_dpi` for vector or mixed pages.
- JPEG pages with no post-render resize.
- Default 2048×2048 crop-only tiles with 128-pixel overlap.
- Shared upstream request pacing plus fail-fast MCP, asset-stream, server-wide, and PDF-job concurrency bounds.
- Bearer authentication by default in production.
- Docker Compose + Caddy deployment assets and post-deploy verification scripts.

No OCR is performed. The companion skill tells agents to verify Georgian text visually and preserve page/tile provenance. No MCP tool mutates the upstream NPLG archive and render deletion remains operator-only. The three tools that populate the local download/render cache are accurately marked as cache-writing in their MCP annotations.

## MCP tools

| Tool | Purpose |
|---|---|
| `search_documents` | Search Iverieli, optionally within a collection handle. |
| `get_document_metadata` | Read rich metadata for a canonical handle. |
| `list_document_files` | List public and restricted bitstreams attached to an item. |
| `download_document_file` | Download a discovered public PDF only. |
| `inspect_pdf` | Classify pages and report scan geometry and text overlays. |
| `render_pdf_pages` | Create full-page JPEGs on the native scan grid or labelled fallback grid. |
| `render_pdf_page_tiles` | Create overlapping crop-only tiles without resize. |
| `get_render_manifest` | Refresh structured render metadata and signed links. |

## Local development

The supported Python range is `>=3.12,<3.15`. The reviewed bootstrap lock is
for `uv 0.12.5`, Node `24.19.0`, npm `11.18.0`, and the x86_64 Linux target;
runtime downloads only immutable direct artifacts and authenticates them with
the repository-pinned SHA-256 after accepted upstream-evidence review. Runtime
and development dependencies are hash-pinned.

`requirements-security.in` is intentionally separate from
`requirements-dev.in`: Semgrep `1.173.0` hard-pins `mcp==1.29.0`, which is
incompatible with the required official `mcp==2.0.0`. Combining those inputs
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
export ASSET_SIGNING_SECRET="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
export ALLOW_ANONYMOUS=true
export PUBLIC_BASE_URL=http://127.0.0.1:8000
.venv/bin/python -m nplg_mcp
```

In another shell:

```bash
.venv/bin/python scripts/verify_deploy.py --base-url http://127.0.0.1:8000
```

Run tests:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q src scripts
```

Offline tests use pinned HTML/OAI fixtures and a synthetic PDF corpus. Live NPLG checks are deliberately opt-in.

The phase 0–1 capability records under `contracts/` are negative evidence,
not OAuth support: dynamic operation-scope 403, exact Alpic detector replay,
route compatibility, and provider selection remain explicit blockers.

## Production deployment

Use the reviewed Docker Compose + Caddy procedure in [`deploy/README.md`](deploy/README.md) for the complete download and PDF-rendering pipeline. Alpic users must read [`deploy/ALPIC.md`](deploy/ALPIC.md): the platform can host the search/metadata surface, but its serverless runtime, 30-second tool limit, and static `/assets/` handling do not provide a full-fidelity target for the current multi-call rendering workflow.

The minimum Docker/VPS operational sequence is:

```bash
cp .env.example .env
# replace domain and both secrets
docker compose --env-file .env config --quiet
docker compose build --pull
docker compose up -d
set -a; . ./.env; set +a
python scripts/verify_deploy.py --base-url https://mcp.example.com
python scripts/smoke_live.py --base-url https://mcp.example.com --query 'ივერია'
```

## Design, review, and agent workflow

- Approved design: `docs/superpowers/specs/2026-08-14-nplg-dspace-mcp-design.md`
- Implementation plan: `docs/superpowers/plans/2026-08-14-nplg-dspace-mcp-implementation.md`
- Critical review: `docs/reviews/2026-08-14-critical-review.md`
- Georgian visual-analysis skill: `skills/georgian-newspaper-visual-analysis/SKILL.md`
- Current security-repair verification: `docs/verification/2026-08-14-security-repair-report.md`
- Historical verification snapshot: `docs/verification/2026-08-14-verification-report.md`

## Explicit limitations

- Live XMLUI/OAI compatibility must be rechecked after deployment because upstream HTML can change.
- The custom MCP wire layer covers only this server's methods; it is not a replacement for the full official SDK.
- The build environment used for this release could not install or run the official MCP SDK/Inspector, so those remain external post-deploy checks.
- PDF work is bounded inside a hardened container but not inside a separately verified nested sandbox.
- The cache is single-node filesystem storage and is not horizontally coordinated or automatically pruned. A process-local logical-byte quota rejects new cache writes at `CACHE_MAX_BYTES`; retain a filesystem/inode limit and disk alerts as independent controls.
- Process-local admission limits bound work inside one server process; they are not per-client rate limits. Internet deployments still need a trusted edge policy for client-aware abuse controls.
- Public download access does not establish public-domain status; rights metadata remains part of the evidence record.

## License

The project-authored source is MIT. Runtime and development dependencies retain their own licenses; see `THIRD_PARTY_NOTICES.md`. The production image uses permissively licensed pypdfium2/PDFium, and synthetic fixtures use permissively licensed ReportLab and pypdf.
