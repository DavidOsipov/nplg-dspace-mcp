# NPLG DSpace MCP - Verification Report

**Verification date:** 2026-08-14  
**Branch:** `feature/python-implementation`  
**Verified implementation commit:** `2f18947`  
**Release classification:** deployable release candidate; production approval remains conditional on connected-host gates

> **Historical snapshot:** this report records evidence for commit `2f18947`; that object is not present in this repository, so the snapshot cannot be independently reconstructed here. It is not verification of the later recovered and security-hardened working tree. Preserve the results below as historical evidence and use the [security-repair verification report](2026-08-14-security-repair-report.md) for current evidence.

## Scope

This report covers the read-only Streamable HTTP MCP implementation for NPLG Iverieli: repository search, metadata, bitstream inventory, validated public PDF download, PDF inspection, full-page JPEG rendering, crop-only tiling, signed asset delivery, operator-only render cleanup, and Docker Compose/Caddy deployment assets.

It does not claim that the live NPLG site, Docker images, official MCP SDK/Inspector, or ChatGPT custom-app integration were exercised in the isolated build environment.

## Critical corrections incorporated

- Corrected the upstream UI model from JSPUI to DSpace XMLUI/Manakin plus OAI-PMH.
- Replaced PyMuPDF/MuPDF with pypdfium2/PDFium in production and ReportLab/pypdf in test fixtures, removing an unacknowledged AGPL/commercial-license dependency from the MIT project.
- Kept the public MCP catalog strictly read-only; render deletion is an operator CLI operation.
- Added exact-origin, Host, Origin, canonical handle, DNS/global-address, redirect, MIME, PDF-signature, streaming-size, content-addressing, and signed-token controls.
- Corrected the MCP unsupported-version error payload to return both `requested` and `supported`.
- Accepted HTTP optional whitespace around standard MCP header values while retaining control-character and encoding checks.
- Restored the approved search result limit of 50 records rather than 100.
- Moved metadata overflow checks ahead of buffer extension, so an oversized chunk is rejected before it is appended.
- Mapped upstream HTTP 401/403 responses to the stable `RESTRICTED` domain error rather than a generic gateway failure.
- Made asset tokens invalid at their exact expiry second.

## Automated verification

### Test suite

Command:

```bash
python -m pytest -q
```

Result:

```text
175 passed in 1.88s
```

The new regression tests were first run against the pre-fix code and failed for the intended reasons. The target red run produced ten failures covering protocol error data, HTTP OWS, search limits, pre-buffer overflow enforcement, upstream 401/403 handling, and exact token expiry. The same target set passed after the minimal fixes.

### Branch coverage

Commands:

```bash
python -m coverage run -m pytest -q
python -m coverage report -m
```

Result:

```text
175 passed in 2.15s
TOTAL 2208 statements, 329 missed, 644 branches, 155 partial branches, 81% coverage
```

The configured coverage floor is 80%.

### Bytecode compilation

Command:

```bash
python -m compileall -q src scripts tests
```

Result: exit status 0.

### Locked dependency consistency

Every package in `requirements.lock` was compared with the installed verification environment. All 23 exact runtime versions matched, with zero mismatches.

### Wheel build and contents

Command:

```bash
python -m pip wheel --no-deps --no-build-isolation . -w dist
```

Artifact:

```text
nplg_dspace_mcp-0.1.0-py3-none-any.whl
SHA-256: 92570d28ab08a84638d1d388806d4e3a76737fa85ef323d4b94868791497e9af
```

The wheel was inspected as a ZIP archive. It contains the package source, `LICENSE`, and `THIRD_PARTY_NOTICES.md`.

### Installed-wheel process smoke test

The wheel was installed into a separate target directory and imported from that directory rather than from the source tree. A standalone Uvicorn process was started on localhost and checked with `scripts/verify_deploy.py`.

Result:

```json
{
  "health": {"status": "ok"},
  "protocol": "2026-07-28",
  "ready": {"status": "ready"},
  "sessionless": true,
  "status": "pass",
  "tool_count": 8
}
```

The verifier confirmed the exact eight-tool read-only catalog, modern discovery, `nplg://about`, health/readiness, private cache metadata, and absence of `Mcp-Session-Id`.

### PDF/JPEG visual smoke test

A deterministic 3000 x 2200 pixel synthetic scanned page with an invisible text overlay was generated. The installed wheel classified and rendered it as follows:

```json
{
  "classification": "raster_with_overlay",
  "conversion_path": "native_grid_render",
  "resolution_source": "embedded_scan",
  "resize_applied": false,
  "page_manifest_size": [3000, 2200],
  "page_image_size": [3000, 2200],
  "tile_count": 4,
  "edge_tile_box": [1920, 1920, 1080, 280],
  "edge_tile_image_size": [1080, 280]
}
```

The full page and edge tile were also inspected visually. Their geometry and crop content were consistent with the manifest; no resize was applied.

### Operator cleanup smoke test

The operator-only cleanup command deleted a generated render on the first call and returned an idempotent non-deletion result on the second call:

```json
{"deleted": true, "render_id": "rnd_33b056ea9c0966458e220df0aa186add"}
{"deleted": false, "render_id": "rnd_33b056ea9c0966458e220df0aa186add"}
```

## Unverified external release gates

The following were not executable in the isolated build environment and therefore remain mandatory before Internet exposure:

1. Build and validate `docker compose` on the target Docker host.
2. Scan the exact application and Caddy image digests; retain full HIGH/CRITICAL reports and triage every remaining finding.
3. Run `scripts/smoke_live.py` against the current NPLG XMLUI/OAI service, first without download and then against one small public PDF.
4. Verify effective container egress restrictions from inside the running application container.
5. Run the official MCP Inspector or current official SDK client against `/mcp` and call at least one tool.
6. Connect the target ChatGPT/OpenAI client, scan all eight tools, and follow at least one returned `resource_link`.
7. Confirm Caddy certificate issuance, signed asset retrieval, disk alerts, backup/restore, and restart behavior on the real host.

## Confidence assessment

- **Deterministic core behavior:** approximately 90% confidence. The parser fixtures, protocol tests, security boundaries, storage, rendering invariants, wheel process smoke, and visual geometry are directly exercised.
- **Live NPLG compatibility:** approximately 70% confidence until the post-deploy smoke test runs. XMLUI markup and access policy are external and can change.
- **Production readiness:** approximately 65% confidence before the external gates, rising materially only after Docker build/scan, live NPLG, official MCP client, and target ChatGPT/OpenAI integration all pass.

The correct operational status is **release candidate**, not “fully production verified.”
