# NPLG DSpace MCP Implementation Plan

> **Historical plan:** this document records the original implementation sequence and dependency choices. Security repairs made after that sequence supersede its version list and some operational details; use `pyproject.toml`, `requirements.in`, `requirements.lock`, and the current security-repair verification report as the release sources of truth.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a deployable, read-only Streamable HTTP MCP server for NPLG Iverieli that searches records, returns metadata, downloads validated public PDFs, and renders full-page JPEGs plus crop-only tiles without post-render resizing.

**Architecture:** A small FastAPI JSON-RPC transport delegates to independently testable repository, security, artifact, and PDF services. Repository access is limited to canonical NPLG resources. Files and renders are content-addressed on a persistent volume. MCP 2026-07-28 is sessionless; a legacy 2025-11-25 initialize path is retained for clients that have not migrated.

**Tech Stack:** Python 3.13, FastAPI 0.128, Pydantic 2.13, HTTPX 0.28, Beautiful Soup 4.14, defusedxml 0.7, pypdfium2 5.8/PDFium, Pillow 12.3, pytest 9, ReportLab 4.4 and pypdf 5.9 for fixtures, Uvicorn 0.48, Docker Compose, Caddy.

## Global Constraints

- Streamable HTTP endpoint: `POST /mcp`; no standalone SSE endpoint.
- Supported protocol versions: `2026-07-28` and `2025-11-25` compatibility mode.
- Exact upstream origin: `https://dspace.nplg.gov.ge:443`.
- Arbitrary download URLs are forbidden; a file must be discovered from a validated item page.
- Default source limit: 512 MiB; default render limit: 8 pages; maximum page: 120 megapixels; maximum render request: 480 megapixels.
- Default tiles: 2048 × 2048 with 128-pixel overlap; crop only, never resize.
- No OCR in MVP.
- Production requires bearer authentication unless anonymous access is explicitly enabled.
- Tests are deterministic and offline by default; live NPLG tests are opt-in.

---

### Task 1: Foundation, configuration, and public errors

**Files:** `pyproject.toml`, `src/nplg_mcp/config.py`, `src/nplg_mcp/errors.py`, `tests/unit/test_config.py`, `tests/unit/test_errors.py`

- [ ] Write failing tests for strict environment parsing, production secrets, ceilings, and error redaction.
- [ ] Run focused tests and verify expected import failures.
- [ ] Implement configuration and error modules.
- [ ] Run focused tests and static compilation.
- [ ] Commit.

### Task 2: Handles, outbound policy, and signed assets

**Files:** `src/nplg_mcp/security.py`, `src/nplg_mcp/tokens.py`, `tests/security/test_security.py`, `tests/security/test_tokens.py`

- [ ] Write failing tests for handle canonicalization, exact-host URLs, encoded-host confusion, ports, redirect validation, forbidden IP classes, tampering, expiry, and object binding.
- [ ] Verify RED, implement minimal security primitives, verify GREEN, commit.

### Task 3: NPLG parsers and repository service

**Files:** `src/nplg_mcp/parsers.py`, `src/nplg_mcp/repository.py`, `tests/fixtures/*`, `tests/unit/test_parsers.py`, `tests/integration/test_repository.py`

- [ ] Write fixture-driven tests for search, public/restricted item pages, bitstreams, full metadata, OAI formats, rich metadata, and fallback behavior.
- [ ] Verify RED, implement bounded parsers and injected HTTP transport, verify GREEN, commit.

### Task 4: Content-addressed artifacts and validated downloads

**Files:** `src/nplg_mcp/storage.py`, `src/nplg_mcp/downloader.py`, `tests/unit/test_storage.py`, `tests/security/test_downloader.py`

- [ ] Test SHA-256 IDs, atomic writes, deduplication, traversal resistance, MIME/magic checks, and streaming limits.
- [ ] Verify RED, implement, verify GREEN, commit.

### Task 5: PDF inspection, native-grid rendering, and tiling

**Files:** `src/nplg_mcp/pdf.py`, `tests/helpers/pdf_factory.py`, `tests/integration/test_pdf.py`, `tests/unit/test_tiles.py`

- [ ] Generate synthetic raster, overlay, vector, rotated, cropped, encrypted, and malformed PDFs.
- [ ] Test conservative classification, exact output dimensions, direct JPEG extraction, labelled 400-DPI fallback, deterministic manifests, and crop-only tile coverage.
- [ ] Verify RED, implement with pypdfium2/PDFium/Pillow, verify GREEN, commit.

### Task 6: Tool service and MCP Streamable HTTP surface

**Files:** `src/nplg_mcp/tools.py`, `src/nplg_mcp/protocol.py`, `src/nplg_mcp/app.py`, `tests/unit/test_tools.py`, `tests/conformance/test_mcp_http.py`

- [ ] Test tool schemas/results, `server/discover`, legacy initialize, required 2026 metadata/headers, JSON-RPC errors, bearer auth, health/readiness, resources, and signed asset delivery.
- [ ] Verify RED, implement, verify GREEN, commit.

### Task 7: Agent skill and deployment assets

**Files:** `skills/georgian-newspaper-visual-analysis/SKILL.md`, `.env.example`, `Dockerfile`, `compose.yaml`, `deploy/Caddyfile`, `deploy/README.md`, `scripts/smoke_live.py`, `scripts/verify_deploy.py`, `tests/static/test_deployment.py`, `tests/static/test_skill.py`

- [ ] Test required visual-analysis sequence and deployment hardening properties.
- [ ] Verify RED, implement deployment and operator documentation, verify GREEN, commit.

### Task 8: Full verification and release packaging

**Files:** `docs/verification/2026-08-14-verification-report.md`

- [ ] Run all unit/integration/security/conformance/static tests.
- [ ] Run Python compile/import checks and local HTTP smoke tests.
- [ ] Run container/config validation where supported; document environmental limitations exactly.
- [ ] Review acceptance criteria and record pass/conditional/deferred status.
- [ ] Build and inspect release ZIP and Git bundle.
- [ ] Commit the verification report.
