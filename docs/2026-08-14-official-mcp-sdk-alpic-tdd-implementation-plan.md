# NPLG DSpace MCP Official Python SDK and Alpic Audit-ready Staging/Release-decision Implementation Plan

> **Implementation audit note (2026-08-15):** The requested single
> development lock cannot contain both `mcp==2.0.0` and `semgrep==1.173.0`:
> Semgrep declares a hard dependency on `mcp==1.29.0`. This implementation
> keeps the official SDK in `requirements-dev.lock` and isolates Semgrep in
> `requirements-security.lock`; merging them would be unsatisfiable. The
> configured uv index also does not provide CPython `3.13.15`, so local
> verification uses `3.13.13` without claiming the exact patch. These are
> release blockers, not silently substituted pins.
> **Phase 0-1 execution reconciliation (2026-08-16):** Work advanced beyond
> the requested audit boundary before the user stopped execution. The review
> below retains only changes with independently reproduced security,
> behavioral, provenance, or strict-static value; it does not authorize Phase
> 2 or later implementation. “Locally complete” means the named local task
> gates and independent review passed. It does not mean committed, pushed,
> protected-branch verified, deployed, ASVS-conformant, or release-eligible.
>
> | Task | Reconciled local status | Binding limitation / next action |
> | --- | --- | --- |
> | 0 | Locally complete; retain | Bootstrap and locks are reproducible, but remote registry/CI/release proof remains external. |
> | 1 | Locally complete; retain | Frozen behavior/provenance is local dirty-candidate evidence, not publication proof. |
> | 1A | Locally complete; retain | PDFium access is serialized, not process-isolated. |
> | 1B | Locally complete; retain | Exact touched legacy slice is clean; this only partially discharges Task 6B. |
> | 2 | Locally complete; retain | All 759 rows remain `Not assessed`, evidence manifest/authorities are empty, and the decision is `do_not_release`. |
> | 3 | Locally complete; retain temporarily | The ratchet prevents regression while inherited diagnostics exist and must be deleted at Task 6C zero. |
> | 4 | Locally complete; retain | The PDFium stub edit is provisional and earns no Task 6A runtime-contract credit. |
> | 5 | Locally complete; retain | DNS-answer-to-TCP binding remains Task 17 work. |
> | 6 | Locally complete; retain | Full regression, provenance refresh, and independent review are recorded locally; publication evidence remains external. |
> | 6A | Locally complete; retain | The exact pinned-wheel reflection contract is implemented and verified locally. |
> | 6B | Locally complete; retain | The literal source, unit, integration, security, and conformance scope is strict-gate clean. |
> | 6C | Locally complete; retain | All operational CLIs are complete and the temporary ratchet/baseline is removed. |
> | 7 | Locally complete; retain | The authoritative branch/diff and mutation gates meet their reviewed local floors. |
> | 8 | Locally complete; external authority required | Local CI/security policy and release-controller interfaces fail closed; protected CI, custody, scanning, signing, publication, and deployment evidence remain external. |
>
> The Phase 1 aggregate status is therefore **LOCALLY COMPLETE / not release-ready**.
> Existing unchecked task boxes remain unchecked because checkpoint commits,
> remote controls, and later external gates were not performed. Durable task
> reports hold volatile hashes, counts, temporary paths, and review-round
> evidence; those values must not be copied into this normative plan.
> **For agentic workers:** REQUIRED SUB-SKILLS: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` task-by-task, use `superpowers:test-driven-development` for every behavioral/security change, and use `superpowers:verification-before-completion` at every phase gate. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the existing NPLG DSpace server to the official MCP Python SDK, make every public boundary strictly typed and independently contract-tested, isolate untrusted PDF processing, and produce an evidence-backed Alpic metadata staging candidate plus a falsifiable release decision aligned with OWASP ASVS 5.0.0 Level 2. A public release is conditional on the separately governed issuer, provider, protected release-controller, and operational evidence named below; this plan may correctly end with `do not release` and must not relabel a staging result as production eligibility.

**Architecture:** Keep the proven Python repository, parser, downloader, storage, and PDF semantics; replace only the hand-written MCP control plane after differential tests prove parity. Pydantic is the runtime source of truth, Zod is a pinned development-only cross-language oracle, and PDFium moves behind a killable process boundary. The first Alpic profile exposes only search, metadata, and file inventory; a full PDF profile remains on Docker/VPS or an external worker until durable storage and a supported long-running mechanism are proven.

**Tech Stack:** CPython 3.12-3.14 (3.13 production), `mcp==2.0.0`, `mcp-types==2.0.0`, Pydantic 2.13.4, Starlette/FastAPI, `httpx2` for the official SDK client transport plus HTTPX/httpcore for project upstream I/O, conditional signed-JWT access-token verification with `PyJWT[crypto]==2.13.0` and `cryptography==50.0.0` only after the selected issuer capability record proves that token format (an opaque-token issuer requires a separately designed and locked RFC 7662 introspection branch), pypdfium2/PDFium, Pillow, `pytest==9.1.1`, `pytest-asyncio==1.4.0`, `hypothesis==6.165.9`, `coverage==7.15.4`, `build==1.5.0`, `setuptools==84.0.0`, `wheel==0.48.0`, Ruff 0.16.3, official npm `pyright@1.1.413` strict, `mypy==2.3.1` strict with the Pydantic plugin, Bandit, Semgrep, pip-audit, CycloneDX, Trivy, Node 24 for development/contract tests only, `typescript@6.0.3`, `eslint@10.8.1`, `@eslint/js@10.0.1`, `typescript-eslint@8.67.0`, `@types/node@24.13.3`, `zod@4.4.3`, the reviewed pre-release `@modelcontextprotocol/conformance@0.2.0-alpha.11`, and operational CLI/SDK/contracts `alpic@1.167.1`/`@alpic-ai/sdk@1.167.1`/`@alpic-ai/api@1.167.1`. TypeScript 7 is deliberately not used until the selected type-aware ESLint stack declares support.

**Phase 6 provider/client-registration decision (2026-08-24):** The first protected `alpic-metadata` staging target is **Auth0 OIDC as the upstream identity provider plus Alpic's DCR proxy as the MCP client-registration compatibility layer**. Alpic's current documentation explicitly names Auth0 among providers without native DCR, lists its OIDC discovery endpoint template, and documents the DCR proxy/client-pool flow. This selects an integration topology, not a proven tenant or token-verification branch. The backend metadata must satisfy Alpic's documented DCR-pool precondition by referencing the server itself as issuer and omitting `registration_endpoint`; the public edge is expected to advertise Alpic's registration endpoint and proxy token requests through one upstream Auth0 client. The exact Auth0 token issuer, public/backend authorization-server metadata, registration/token endpoint rewrites, resource/audience, callback URI, scopes, token format, client identity, subject stability, and lifecycle behavior remain evidence-bound fields. Until a named Auth0 tenant and named Alpic environment witness that complete mapping, retain `OAUTH_PROVIDER_CAPABILITY_UNPROVEN`, `ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN`, and `OAUTH_END_TO_END_FLOW_UNPROVEN`; neither the provider directory nor this decision permits installing the JWT branch or deploying.

**Phase 7 Alpic Tasks decision correction (2026-08-24):** Alpic is the
selected hosting and control-plane provider for the `distributed-full`
compatibility assessment. Alpic's current troubleshooting documentation
advertises a separate long-running Tasks compute path with a default TTL of
up to six hours, so the earlier claim that the platform exposed no
long-running mechanism is superseded. This is a provider claim, not yet a
version-matched Python integration or durability proof. The installed and
pinned `mcp==2.0.0` package exports no SEP-2663 Tasks models or handlers, and
the official Python SDK roadmap says the Tasks extension was deferred from
2.0. Phase 7 is therefore revised below into an executable, expected-negative
Alpic capability/conformance assessment. It must not enable
`distributed-full`, invent a private Tasks wire implementation, or treat a
six-hour TTL as proof of restart recovery, cross-principal isolation,
artifact storage, retention, purge, or backup/restore.

## Global Constraints

- Use the official [Model Context Protocol Python SDK](https://github.com/modelcontextprotocol/python-sdk); do not retain a private MCP wire implementation after parity cutover.
- Let the official SDK own MCP parsing, modern-version metadata/body validation, authentication, and dispatch at the Python backend after a project-owned bounded framing/Host/Origin/admission gate. A narrowly reviewed version-routing guard rejects absent/unsafe/duplicate/handshake-era headers solely to prevent the pinned SDK's legacy path, passes supported and bounded safe unsupported modern tokens unchanged, and never parses or reimplements JSON-RPC/MCP semantics. On protected `/mcp`, that guard may run only after the SDK has produced the credentialless/invalid-token `401` challenge and authenticated an otherwise admissible request exactly once; it must not preempt Alpic's documented unauthenticated `initialize` OAuth detector or allow that detector to reach legacy dispatch. Task 0 must prove a supported public SDK/vendor composition, the selected issuer/token-validation/client-registration capabilities, and the exact protected-resource-metadata route; Task 21 must prove the deployed environment is classified `Protected`. Otherwise stable blockers `ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN`, `ALPIC_OAUTH_DISCOVERY_ORDERING_UNPROVEN`, `ALPIC_PRM_ROUTE_COMPATIBILITY_UNPROVEN`, `ALPIC_PROTECTED_CLASSIFICATION_UNPROVEN`, `ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN`, `OAUTH_PROVIDER_CAPABILITY_UNPROVEN`, and `OAUTH_END_TO_END_FLOW_UNPROVEN` remain. For Alpic, model the separate client-to-Alpic and Alpic-to-backend MCP hops explicitly: Alpic owns the public-edge MCP exchange and may translate protocol versions, rewrite its documented backend-local metadata coordinates to public coordinates, or normalize messages, but every such transformation must be observed and bound rather than assumed.
- Pin reviewed runtime and development dependencies exactly and regenerate `requirements.lock` with hashes atomically.
- Bootstrap development from an explicit CPython 3.13/hash-locked procedure before invoking `.venv/bin/*`; a machine-local environment is never an undocumented prerequisite.
- Pydantic is the Python runtime authority. All boundary models use strict types, explicit bounds, `extra="forbid"`, and validated outputs.
- Zod is test-only. Pin stable `zod@4.4.3`, use `z.strictObject()`, target JSON Schema Draft 2020-12, and do not use experimental `z.fromJSONSchema()` as a production authority.
- Target OWASP ASVS `v5.0.0` Level 2. Do not claim compliance until every applicable L1/L2 row has all evidence kinds required by the independent row/profile evidence policy. Runtime controls require code/config and test evidence; deployment-dependent controls additionally require operational evidence; documentation-only rows must not receive fabricated code or operational references.
- A public/business release recommendation always requires ASVS L2 closure: `Pass` for every applicable row and governed `N/A` for genuinely absent controls. An explicitly approved, unexpired risk acceptance may close only a named non-public staging/private audit whose terminal recommendation is `do not release`; it never satisfies public eligibility or an ASVS L2 claim.
- Follow red–green–refactor TDD for every behavioral or security change: focused failing test, observed relevant failure, minimal repair, focused green test, broader regression suite.
- For lint/type-only cleanup, the checker diagnostic is the RED gate and existing behavioral tests must be green before and after. If a cleanup needs any runtime behavior change, stop that cleanup and start a separate focused behavioral RED test first.
- Every security fix includes negative and adversarial cases. Parsing, URL, cursor, schema, IPC, and state-machine boundaries also receive property tests.
- End-state gates are zero Ruff diagnostics under `select = ["ALL"]` with only documented incompatibility/test exceptions, zero Pyright strict errors, zero mypy strict errors, at least 95% branch-enabled project coverage, at least 95% changed-line coverage, and at least 95% changed branch-arc coverage.
- Strict gates cover `src`, `tests`, `scripts`, and project-owned `typings/**/*.pyi`; test and stub code is not exempt from type checking, package-boundary checks, formatting, notice checks, or linting except for the exact documented `S101`, `D102`, and `D103` allowances under `tests/**/*.py`.
- Every Python or Python-stub file created by this plan starts with the exact reviewed notice `# Copyright (c) 2026 David Osipov` (second line only when an executable shebang must remain first), followed in Ruff-compatible order by its module docstring/imports, and is Ruff/Pyright/mypy-clean at creation. This applies immediately to Task 0's `tests/conftest.py`, `tests/helpers/app_factory.py`, and `tests/unit/test_test_factories.py`, Task 1's `tests/contracts/test_frozen_baseline.py`, and Task 2's `scripts/build_asvs_matrix.py` and `tests/static/test_asvs_evidence.py`; later create-lists inherit the same rule. Task 3 statically verifies those pre-tooling files and its package markers, and Task 6C verifies the complete tracked `src`/`tests`/`scripts` Python plus `typings/**/*.pyi` inventory. A task may not defer a new file's `CPY001`, docstring, annotation, or formatting diagnostics to the legacy ratchet.
- A coverage percentage, scanner result, passing test suite, or Alpic audit is evidence, not by itself proof of ASVS L2 conformance.
- Treat NPLG metadata, HTML, XML, filenames, PDFs, image contents, and MCP arguments as untrusted.
- Preserve canonical-handle enforcement, bounded streaming, redirect validation, MIME/magic validation, content addressing, symlink defenses, atomic publication, and deterministic render semantics.
- Do not run PDFium concurrently in Python threads. The immediate compatibility backend is serialized; the production full-fidelity backend is killable and OS-isolated.
- Do not invent an MCP Tasks protocol. Python SDK 2.0.0 does not implement SEP-2663 Tasks. Alpic's advertised Tasks compute path is provider capability evidence, not a substitute for a version-matched stable Python API, strict wire models, official-client support, or staging conformance.
- The first Alpic release profile is `alpic-metadata` and exposes exactly `search_documents`, `get_document_metadata`, and `list_document_files`.
- The `alpic-metadata` profile must not rely on cross-invocation local filesystem state, runtime-generated `/assets` routes, or custom public health/metrics routes.
- Keep ordinary Alpic tool execution below a 20-second local deadline, leaving at least 10 seconds of headroom under Alpic's documented 30-second ceiling.
- Public multi-user publication requires identity-aware authentication, scopes, per-principal limits, and attributable audit events. Neither selected MCP profile permits shared/static API-key authentication; an Alpic provider-admin key exists only inside the isolated protected staging helper and is never an application/client credential.
- Deployment, DNS, registry publication, branch protection changes, commits, pushes, and secret configuration require explicit user authorization at execution time.
- Preserve unrelated work. At this audit, `docs/nplg-dspace-mcp-architecture-handoff-2026-08-14.md` is user-owned staged state; never clean, reset, restage, or absorb it into a task commit. Treat any user-owned untracked path discovered at execution the same way rather than encoding an ephemeral scratch-path prerequisite.
- The 2026-08-16 user-authorized transfer into the primary checkout supersedes
  the earlier prohibition on writing there only for the already named Phase
  0-1 files. The primary checkout remains a dirty development candidate: do
  not stage, commit, push, deploy, change refs, or describe it as clean/release
  evidence without fresh explicit authorization.
- Before Task 0 executes, require the recorded commit/tree identity or explicitly revise and re-review this plan; do not silently generate a baseline from a different source revision.
- Commit commands below are execution checkpoints, not authorization to commit. Stage only the paths named by the current task.
- No Rust rewrite is in scope. Re-evaluate Rust only after the Python production profile has measured evidence that Python is the limiting factor.

---

## 1. Evidence Baseline and Scope Decision

The plan is grounded in repository identity:

- Commit: `2ba5dc18385747aa5d12a3b560eaab2ab97b7a40`
- Tree: `b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8`
- Reviewed docs-only execution candidate commit:
  `da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0`.
- Reviewed docs-only execution candidate tree:
  `2464df5aa1880e99168ce07c23d891ab66ed3959`. These candidate values are
  recorded as execution provenance; they do not relabel the original audit
  commit/tree.
- The Task 0 preflight admits only the exact audit commit/tree above with an
  empty audit-to-HEAD changed-path set, or the exact reviewed candidate
  commit/tree above with exactly the implementation plan and architecture
  handoff as its audit-to-HEAD changed-path set. The audit commit must be an
  ancestor and `HEAD:src` must be exactly
  `fcd9debdb533498486a2bbeaf909ea5bfb95b52c` in both cases.
- Recorded Python 3.13.13 baseline at the frozen commit: 254 tests passed.
- Recorded branch-enabled coverage baseline: 82%, with the existing floor at 80%.
- Historical discovery used Pyright 1.1.412 and recorded 539 strict errors across 40 files. The reviewed pin is now 1.1.413; Task 3 must recapture diagnostic identities from scratch and must not reuse the 1.1.412 count as a ratchet baseline.
- Reproduced Ruff 0.16.3 `select ALL` discovery baseline: 2,377 diagnostics across 67 rules; this includes mutually incompatible docstring rules and test-only `assert` findings, so the final configuration must use narrow, explained exceptions rather than blindly accepting noise.
- Historical pre-execution caveat: the audited checkout initially had no
  `.venv`; the baseline numbers in this subsection describe discovery, not the
  current working tree. Task reports contain the later locked-tool executions.
- Current MCP entry point: `src/nplg_mcp/app.py:create_app` instantiates `src/nplg_mcp/protocol.py:McpProtocol`.
- Current tool input base: `src/nplg_mcp/tools.py:StrictInput` already uses strict Pydantic validation.
- Current tool handlers return `dict[str, Any]` and publish no declared output schemas.
- Historical pre-Task-1A PDF execution used `asyncio.to_thread()` with two
  jobs by default. Task 1A now serializes the compatibility backend; it does
  not provide the process isolation required by Tasks 15-16A.

This plan supersedes the runtime direction in `docs/superpowers/specs/2026-08-14-nplg-dspace-mcp-design.md` and the completed historical plan in `docs/superpowers/plans/2026-08-14-nplg-dspace-mcp-implementation.md` wherever they prescribe a hand-written MCP transport or a TypeScript runtime. Their NPLG, provenance, PDF, and read-only behavioral invariants remain inputs to the frozen contract.

### Deployment profiles

| Profile | First release? | Tool surface | Persistence | Long-running work |
| --- | ---: | --- | --- | --- |
| `alpic-metadata` | Yes | Search, metadata, file inventory | No correctness dependency on local disk | Forbidden; 20-second local deadline |
| `private-full` | Existing capability, hardened before release | Current full catalog | Persistent local volume | Isolated PDF worker |
| `distributed-full` | Compatibility assessment only | No public surface until a later approved implementation plan | Alpic Tasks state plus artifact-store durability must be independently proven | Alpic Tasks control plane plus an isolated worker, both unproven |

The metadata-first choice is confirmed by Task 1 and its accepted ADR:
`alpic-metadata` is the only first-release Alpic profile. Alpic is selected as
the Phase 7 provider, but that selection does not prove that Alpic Tasks owns
the application job database, private artifact store, worker isolation, or
recovery controls. Phase 7 may now execute its typed compatibility assessment;
full-fidelity implementation remains blocked until the official Python SDK and
an authorized Alpic staging environment prove the same Tasks revision and a
separate approved plan freezes every remaining job/artifact decision.

## 2. Phase Dependency Graph

```text
Task 0: reproducible development bootstrap and baseline revalidation
  └── Task 1: frozen contract
        └── Task 1A: immediate serialized PDF safety repair
              └── Task 1B: touched legacy static closure
                    └── Task 2: ASVS/threat-model evidence inventory
                          └── Tasks 3 → 4 → 5 → 6 → 6A → residual 6B → 6C → 7 → 8
                                └── Phase 2: strict Pydantic outputs and Zod oracle
                                      ├── Phase 3: official MCP SDK adapter and wire cutover
                                      ├── Phase 4 Tasks 15–16A: PDF process isolation/scanning
                                      └── Phase 5: upstream SSRF/parser/cursor hardening

Phase 1 + Phase 3 + Phase 5
  └── Phase 6 Tasks 19–20: profile isolation and identity/audit controls
        └── Task 21: authenticated Alpic metadata staging/release

Phase 6 + the pinned official Python SDK
  └── Phase 7 Task 21A: typed Alpic Tasks capability/conformance assessment
        └── supported verdict: separate full-fidelity implementation plan
        └── unsupported verdict: retain the startup error and blocker ledger

All selected phases
  └── Phase 8: ASVS evidence closure and release decision
```

The phases have independent deliverables and rollback boundaries, but their shared legacy modules make concurrent worktrees unsafe. Serialize Phase 1 before feature phases. After Task 9 creates strict shared models, the SDK, PDF, and upstream branches may be developed independently only when their write sets do not overlap; merge and rebase one branch at a time. Phase 6 does not depend on the PDF phases. Phase 7 does not block the metadata release.

## 3. Target File Structure

### Files created

- `SPEC.md` — root normative product/scope ledger required before MCP implementation work.
- `tests/conftest.py`, `tests/helpers/app_factory.py` — typed, shared service/config factories used by plan tests.
- `contracts/baseline/manifest.json` — complete fixture inventory and SHA-256 digests.
- `src/nplg_mcp/contracts/__init__.py` — exports stable public input/output types.
- `src/nplg_mcp/contracts/base.py` — strict Pydantic base models and constrained aliases.
- `src/nplg_mcp/contracts/inputs.py` — tool input models moved from `tools.py`.
- `src/nplg_mcp/contracts/outputs.py` — typed tool, resource, artifact, page, tile, and error outputs.
- `src/nplg_mcp/contracts/catalog.py` — typed `ToolDefinition` registry.
- `src/nplg_mcp/contracts/schema.py` — deterministic Draft 2020-12 schema export and normalization.
- `src/nplg_mcp/py.typed` — PEP 561 marker for the exported typed distribution.
- `src/nplg_mcp/services.py` — acyclic typed metadata/full service composition contracts.
- `src/nplg_mcp/mcp_server.py` — `create_mcp_server(services, profile) -> Server[None]` and official low-level SDK handler registration.
- `src/nplg_mcp/sdk_boundary.py` — typed low-level SDK handlers with strict argument validation, exact catalog schemas, and bounded result/error normalization.
- `src/nplg_mcp/http_security.py` — Host, Origin, profile/path-specific authentication hooks, content-encoding/body, response, and admission middleware around the official SDK ASGI app.
- `src/nplg_mcp/json_preflight.py` — bounded byte-level JSON lexical/structural preflight without decoded-tree construction.
- `src/nplg_mcp/network.py` — resolver-to-socket binding and canonical-host TLS policy.
- `src/nplg_mcp/resilience.py` — typed NPLG bulkhead and monotonic circuit-breaker state machine.
- `src/nplg_mcp/profiles.py` — `DeploymentProfile` and profile-specific tool exposure.
- `src/nplg_mcp/pdf_executor.py` — `PdfExecutor` protocol and serialized compatibility executor.
- `src/nplg_mcp/pdf_worker_client.py` — killable local subprocess client and private-full Unix-socket client.
- `src/nplg_mcp/pdf_worker_main.py` — worker entry point with strict IPC validation.
- `src/nplg_mcp/pdf_ipc.py` — discriminated request/result models and size ceilings.
- `src/nplg_mcp/malware.py` — fail-closed scanner protocol, verdicts, quarantine, and signature-freshness policy.
- `src/nplg_mcp/auth.py` — principal, scope, and verifier interfaces.
- `src/nplg_mcp/audit.py` — bounded structured security-event schema and emitter.
- `contracts/baseline/*.json` — frozen tool, resource, error, and result fixtures.
- `contracts/accepted-sdk-differences.json` — reviewed protocol-standard differences without mutating the baseline oracle.
- `contracts/sdk-authorization-capability.json` — machine-readable, digest-bound Phase 0 verdict for the pinned SDK's parsed-operation HTTP-403 capability.
- `contracts/alpic-oauth-discovery-capability.json` — machine-readable, digest-bound Phase 0 verdict for Alpic detector provenance, auth ordering, and the backend/public protected-resource tuple.
- `contracts/oauth-provider-capability.json` — machine-readable, digest-bound Auth0 tenant issuer, access-token-validation, resource/audience, and Alpic-DCR client-registration capability verdict selected before auth implementation.
- `contracts/generated/tool-contracts.schema.json` — the one deterministic, closed-inventory Pydantic JSON Schema bundle.
- `contracts/zod/*.ts` — independent strict Zod definitions and fixture runner.
- `tests/contracts/test_frozen_baseline.py` — baseline completeness and determinism.
- `tests/contracts/test_pydantic_contracts.py` — positive, boundary, negative, and adversarial runtime cases.
- `tests/contracts/test_sdk_parity.py` — custom-versus-official differential tests during migration.
- `tests/contracts/test_sdk_client.py` — official in-memory `Client` tests for modern and legacy modes.
- `tests/contracts/test_sdk_boundary.py` — in-memory pre-dispatch strict-argument and secret-canary error tests.
- `tests/conformance/official_fixture_server.py` — test-only auth-disabled prescribed server-role conformance fixture, forbidden from every release subject.
- `tests/contracts/test_zod_contracts.py` — Python launcher and result check for the Node oracle.
- `tests/security/test_pdf_worker.py` — crash, timeout, cancellation, IPC, output, and cleanup attacks.
- `tests/unit/test_pdf_worker_quota_verifier.py` — injected command/proof tests for continuous worker block/inode quota enforcement.
- `tests/unit/test_pdf_worker_container_verifier.py`, `tests/unit/test_scanner_container_verifier.py` — injected closed-probe container-proof tests.
- `tests/security/test_malware.py` — infected, unavailable, stale-signature, race, and quarantine behavior.
- `tests/security/test_auth.py` — OIDC/JWKS, scope, lifetime, revocation-window, and artifact authorization attacks.
- `tests/security/test_audit.py` — security-event completeness and secret-redaction tests.
- `tests/property/test_auth_properties.py`, `tests/property/test_deployment_evidence_properties.py` — bounded hostile auth/JWT/JWK/config and provider/manifest/path/evidence properties.
- `tests/security/test_ssrf_binding.py` — DNS rebinding and connection-binding tests.
- `tests/unit/test_upstream_resilience.py` — deterministic NPLG bulkhead/circuit outage and recovery tests.
- `tests/unit/test_live_nplg_canary.py` — injected strict-record tests for the separately authorized live NPLG canary.
- `tests/unit/test_delete_render.py`, `tests/unit/test_smoke_live.py` — injected destructive/network CLI boundary tests.
- `tests/property/test_pdf_ipc_properties.py` — impossible-state and bounded-frame IPC properties.
- `tests/unit/test_app_lifespan.py`, `tests/unit/test_json_preflight.py`, `tests/property/test_json_preflight_properties.py` — SDK lifecycle and bounded JSON-preflight regressions.
- `tests/integration/test_profiles.py` — exact tool surfaces and persistence assumptions.
- `tests/property/test_contract_properties.py`, `test_parser_properties.py`, `test_storage_properties.py` — bounded property/adversarial strategies.
- `tests/deployment/test_edge_http.py` — real Caddy/Alpic TLS, framing, header, and distributed-quota proof.
- `tests/static/test_quality_policy.py` — enforce tool versions and strict configuration.
- `tests/static/test_release_gate.py` — execute and test the release-orchestrator contract.
- `tests/static/test_asvs_evidence.py` — enforce ASVS inventory and evidence rules.
- `scripts/export_contracts.py` — deterministic schema export.
- `scripts/build_asvs_matrix.py` — generate complete L1/L2 rows from the pinned official JSON.
- `scripts/quality_ratchet.py` — temporary no-new-diagnostics gate removed when global zero is reached.
- `scripts/run_quality_gate.py` — one exact scoped/global Ruff, Pyright, and mypy entry point.
- `scripts/run_test_gate.py` — deterministic branch-coverage/changed-line gate with exact mapping to separate external suites.
- `scripts/run_mutation_gate.py` — deterministic mutation-policy runner for security decision code.
- `scripts/run_live_nplg_canary.py` — bounded developer/injected NPLG probe fixture; it cannot emit release-authoritative evidence.
- `scripts/run_alpic_staging_proof.py` — unprivileged typed staging/evidence orchestration fixture with an injected executor; never a release authority.
- `scripts/capture_alpic_deployment.ts` — no-secret injected-provider-JSON/Zod contract fixture; the protected controller owns the real SDK capture.
- `scripts/bootstrap_external_tools.py` — digest-verified, traversal-safe installer for enumerated non-Python quality binaries.
- `scripts/verify_pdf_worker_container.py`, `scripts/verify_pdf_worker_quota.py`, `scripts/verify_scanner_container.py` — deterministic developer/injected attack-gate fixtures; protected controller-owned harnesses produce release-authoritative container/quota evidence.
- `scripts/verify_release.py` — candidate-side schema/fixture and non-authoritative diagnostic implementation of the release contract; the independently protected controller owns every release-usable battery, custody, verdict, and eligibility operation.
- `quality-baseline.json` — temporary audited diagnostic baseline removed with the ratchet.
- `security/asvs/requirements-5.0.0.json` — unmodified official machine-readable ASVS source.
- `security/asvs/SHA256SUMS` — digest of the pinned ASVS source.
- `security/semgrep/rules.yml`, `security/semgrep/SHA256SUMS` — reviewed local rules and source digest; CI never uses mutable `auto` rules.
- `security/toolchain-lock.json` — exact platform artifact URLs, versions, and digests for external quality binaries.
- `security/external-test-gates.json` — closed owner/profile/authority registry for every live, staging, and container node/command.
- `security/release-command-manifests.json` — schema-validated common and profile-specific release commands/evidence requirements.
- `docs/security/asvs-5.0.0-l2-method.md` — applicability and evidence method.
- `docs/security/asvs-evidence-policy.json` — independently governed minimum evidence kinds.
- `docs/security/asvs-5.0.0-l2-matrix.jsonl` — profile-specific applicability and verdict matrix.
- `docs/security/evidence-manifest.jsonl` — typed, digest-bound evidence references used by matrix rows.
- `docs/security/threat-model.md` — assets, actors, trust boundaries, and abuse cases.
- `docs/security/data-inventory.md` — profile-specific sensitive-data classification and lifecycle.
- `docs/security/cryptographic-inventory.json`, `security/crypto-policy.json` — closed cryptographic-material lifecycle and algorithm/strength policy.
- `docs/security/logging-inventory.json` — closed per-layer event, destination, access, retention, time, correlation, and redaction inventory.
- `docs/architecture/2026-08-14-official-python-sdk-adr.md` — normative architecture decision.
- `docs/verification/2026-08-14-alpic-metadata-staging.md` — authorized, redacted real-edge evidence.
- `docs/verification/2026-08-14-release-candidate.md` — candidate-bundle and containing-attestation-bound release/ASVS decisions.
- `pyrightconfig.json` — project-wide strict Pyright configuration.
- `requirements-dev.in`, `requirements-dev.lock` — exact hash-locked quality/test tools.
- `package.json`, `package-lock.json`, `tsconfig.contracts.json`, `eslint.config.mjs`, `.markdownlint-cli2.mjs` — locked official Pyright, Zod/TypeScript, type-aware ESLint, Markdown lint, and operational Alpic CLI toolchain.
- `scripts/run_mcp_conformance.py`, `tests/unit/test_run_mcp_conformance.py` — typed, fail-closed orchestration for the pinned official MCP server-role harness and its process/result policy.
- `tests/fixtures/pdf/adversarial/manifest.json` — digest/provenance/expected-verdict inventory for the bounded hostile PDF corpus.
- `deploy/pdf-worker-seccomp.json` — deny-by-default PDF worker syscall policy.
- `deploy/alpic-audit-dispositions.json` — exact reviewed dispositions for version-pinned Alpic audit warning/skip IDs.
- `deploy/alpic-runtime-manifest.json` — closed minimal production deploy closure, excluding tests, docs, fixtures, and development/release tooling.
- `deploy/alpic-environment-manifest.json` — closed literal runtime environment-key/type/secrecy/size and provider-observation contract.
- `deploy/alpic-submission-versions.json` — environment/URL/catalog-digest ledger and breaking-schema migration policy for host submissions.
- `security/release-controller-policy.json` — candidate-side expected descriptor for the independently governed controller authority/artifact/revision/command/isolation digest contract; the candidate cannot supply or replace the actual controller/policy.
- `security/dependency-risk-policy.json` — closed SCA source, freshness, severity, remediation-window, ownership, and exception policy.
- `.github/workflows/ci.yml` — required test/type/lint/contract/build gate.
- `.github/workflows/security.yml` — SAST, SCA, SBOM, secret, and image checks.
- `.github/dependabot.yml` — reviewed update cadence for Python, npm, and Actions.
- `SECURITY.md` — supported versions, reporting, response, and evidence policy.

### Existing files modified

- `pyproject.toml`, `requirements.in`, `requirements.lock` — exact SDK, quality, security, and test dependencies.
- `src/nplg_mcp/tools.py` — consume typed definitions, validate outputs, and delegate PDF work through `PdfExecutor`.
- `src/nplg_mcp/app.py` — compose the official SDK ASGI app and security middleware.
- `src/nplg_mcp/config.py` — deployment profile, deadlines, identity, worker, and fail-closed settings.
- `src/nplg_mcp/errors.py` — bounded SDK-safe error conversion.
- `src/nplg_mcp/repository.py` and `src/nplg_mcp/downloader.py` — socket-bound upstream policy plus bulkhead/circuit integration.
- `src/nplg_mcp/pdf.py` and `src/nplg_mcp/storage.py` — worker-safe, typed boundaries without changing deterministic output semantics.
- `src/nplg_mcp/tokens.py` — versioned capabilities during transition, then removal from public asset URLs.
- `src/nplg_mcp/__main__.py` — official SDK/ASGI startup and worker entry points.
- `tests/conformance/test_mcp_http.py` — official SDK wire conformance and retained security cases.
- Existing unit, integration, security, and static tests — strict annotations and new regressions.
- `Dockerfile`, `compose.yaml`, `deploy/README.md` — isolated PDF worker and hardened full profile.
- `alpic.json`, `deploy/ALPIC.md`, `.env.example`, `README.md` — exact metadata-only profile and non-overclaiming guidance.
- `THIRD_PARTY_NOTICES.md` — provenance/license notices for vendored security rules and added dependencies.
- `.gitignore` — exact local external-tool/build-output exclusions plus the provider-local `/.alpic/` rule, without broad executable/archive patterns.

### File removed only after the cutover gate

- `src/nplg_mcp/protocol.py` — delete after official-client, HTTP, differential, and frozen-contract suites are green.

## 4. Project-wide TDD and Review Protocol

For every task:

1. Record `git status --short --branch` and confirm unrelated paths are untouched.
2. Add exactly one focused regression or static policy invariant.
3. Run only that test node and record the exact command, exit `1`, failing assertion/message, and why it is the intended behavioral RED rather than an import, fixture, collection, executable, lock, or environment failure.
4. Add the smallest implementation/configuration that satisfies the test.
5. Rerun the exact node and record exit `0`.
6. Make an explicit REFACTOR/no-refactor decision; if refactoring, change no behavior and rerun the focused node before continuing.
7. Prove failure sensitivity with the task's named mutation/deliberate-fault case, then run the owning test module and every exact phase-gate command.
8. Inspect `git diff --check` and the scoped diff.
9. Request review; commit only after user authorization.

Ordinarily execute implementation in a dedicated worktree whose index starts
empty. The sole current exception is the user-authorized 2026-08-16 Phase 0-1
transfer/reconciliation described above and in Task 0's historical recovery
note. In that dirty primary checkout, preserve every pre-existing logical
staged entry and unrelated path byte-for-byte; never stash, reset, stage,
commit, clean, push, deploy, or run work outside the exact reviewed Phase 0-1
scopes. This exception ends with the reconciliation and is not precedent for
Phase 2 or later work. Outside that exception, never run plan builds in a dirty
primary checkout. Before every authorized task staging step, require
`git diff --cached --quiet`; after staging, compare the NUL-delimited cached
path set with that task's exact declared allowlist and abort on any
missing/extra path before `git commit`. A commit checkpoint never authorizes
creating the commit, using the shared primary index, or including an earlier
staged path; each still requires explicit user authorization.

Every later “Stage … then commit” sentence is declarative shorthand for this mandatory protocol, never a bare `git add`/`git commit`. Before staging, expand that task's `Files` section into a literal Bash `task_paths=(...)` array: one repository-relative element per exact Create/Modify/Delete path, no directory, glob, category, substitution, or omitted test. Use a validated external mode-`0700` `CHECKPOINT_TMP_PARENT`, then run the following only after the task's explicit commit authorization; preserve the resulting comparison files as checkpoint evidence:

```bash
set -euo pipefail
test "${#task_paths[@]}" -gt 0
test -z "$(git diff --cached --name-only)"
CHECKPOINT_TMP_PARENT="$(realpath -e -- "${CHECKPOINT_TMP_PARENT:?set private external parent}")"
test -d "$CHECKPOINT_TMP_PARENT"
test "$(stat -c '%a' "$CHECKPOINT_TMP_PARENT")" = "700"
checkpoint_dir="$(mktemp -d -p "$CHECKPOINT_TMP_PARENT" task-checkpoint.XXXXXXXX)"
chmod 700 "$checkpoint_dir"
printf '%s\0' "${task_paths[@]}" | LC_ALL=C sort -z >"$checkpoint_dir/expected.zlist"
git add -A -- "${task_paths[@]}"
git diff --cached --name-only -z | LC_ALL=C sort -z >"$checkpoint_dir/staged.zlist"
cmp "$checkpoint_dir/expected.zlist" "$checkpoint_dir/staged.zlist"
git diff --cached --check
git -c core.hooksPath=/dev/null -c commit.gpgSign=false commit -m "$TASK_COMMIT_MESSAGE"
git diff-tree --no-commit-id --name-only -z -r HEAD | LC_ALL=C sort -z >"$checkpoint_dir/committed.zlist"
cmp "$checkpoint_dir/expected.zlist" "$checkpoint_dir/committed.zlist"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

The task's static plan test extracts every `Files` list and rejects a wildcard, directory-only entry, prose category, duplicate, or path that cannot populate a literal execution-time `task_paths` array. For the ordinary one-checkpoint task, that array equals the complete expanded `Files` inventory. A task with multiple explicitly named checkpoints (notably Tasks 21–22) must tag every file path with exactly one checkpoint or conditional operational output, prove the disjoint partitions cover the inventory, and select only the active partition; an optional/unauthorized partition is absent rather than staged as an empty placeholder. The later “Stage …” sentence is human-readable scope shorthand, not a second machine allowlist; at execution the generated literal array and NUL-delimited staged/committed comparisons are authoritative. A hook/signing configuration cannot mutate the staged tree because hooks and ambient signing are disabled for this mechanical checkpoint; any post-commit delta mismatch is a hard stop for human recovery, never permission to amend/reset automatically.

The first executable command in a fresh checkout is Task 0. A proposed RED is invalid if it fails because `.venv`, a fixture, an import, generated data, or another prerequisite is missing. All plan-supplied examples use the typed factories created in Task 0; task-local fixtures must be declared in that task. Static cleanup uses `scripts/run_quality_gate.py` so every command is exact and repeatable. No task may replace a named executable gate with “run the same checks” or an equivalent prose placeholder.

When a task introduces a new importable module/interface or third-party package, Step 1 first adds only the exact dependency pin and a typed, behavior-free scaffold whose target call raises `NotImplementedError`; then `pytest --collect-only` must pass before the focused test runs. This bootstrap is not GREEN. The observed RED must reach the intended call/assertion and may not be an import, collection, fixture, executable, lock, or generated-file setup failure. Static artifact tests may fail on the intentional absence/content of the named artifact itself.

Tasks with multiple adversarial cases are delivery groupings, not permission to batch implementation. A paragraph or parameter table naming many cases is only a backlog. Execute each independently rejectable invariant as its own microcycle: record the exact test node and expected failing assertion; observe exit `1` at that assertion; change the minimum named symbol/configuration; observe focused exit `0`; record the REFACTOR/no-refactor decision and rerun after any refactor; then run its named mutation/deliberate-fault sensitivity check before proceeding. Preserve this per-invariant ledger in the task's external command evidence. An aggregate RED that fails only at a scaffold does not establish RED for later cases. Only after all microcycles pass may the task's aggregate commands run. A prose phase exit gate is satisfied only by the exact preceding commands with checked exit `0`; it is never an additional unverifiable assertion.

Security test naming must identify the prohibited behavior, for example `test_sdk_validation_error_does_not_echo_argument_values` rather than `test_bad_input`. Use deterministic clocks, resolvers, object stores, and workers. Network-dependent canaries remain marked `live` and never replace fixture-based tests.

---

## Phase 0 — Normative Baseline, Immediate Safety Guard, and Evidence Inventory

### Task 0: Bootstrap a reproducible development environment and revalidate the baseline

#### Files

- Modify: `.gitignore`, `requirements.in`, `requirements.lock`
- Create: `requirements-dev.in`, `requirements-dev.lock`
- Create: `requirements-security.in`, `requirements-security.lock`
- Create: `package.json`, `package-lock.json`
- Create: `security/bootstrap-toolchain-lock.json`, `scripts/bootstrap_toolchain.py`, `tests/unit/test_bootstrap_toolchain.py`
- Create: `tests/conftest.py`, `tests/helpers/app_factory.py`, `tests/unit/test_test_factories.py`, `tests/contracts/test_sdk_auth_feasibility.py`, `tests/contracts/test_alpic_oauth_discovery.py`, `tests/contracts/test_oauth_provider_capability.py`, `contracts/sdk-authorization-capability.json`, `contracts/alpic-oauth-discovery-capability.json`, `contracts/oauth-provider-capability.json`
- Modify: `pyproject.toml`, `README.md`

`requirements*.lock` and `package-lock.json` are the authoritative dependency
locks. A second generated `uv.lock` is deliberately out of scope and must
remain absent unless a future task first replaces, rather than duplicates, an
existing lock authority.

#### Interfaces

- Produces typed `base_environment(**overrides: str) -> dict[str, str]`, `make_tool_service(tmp_path: Path, *, pdf_processor: PdfProcessor | None = None) -> ToolService`, and `make_app_services(tmp_path: Path) -> AppServices` factories plus fixtures named `tool_service` and `app_services`.
- Establishes verified local/bootstrap versions `uv==0.12.5`, CPython 3.12.14/3.13.15/3.14.7 (3.13.15 local production candidate), Node 24.19.0, and npm 11.18.0; `package-lock.json` initially pins the official npm `pyright@1.1.413` package. The universal Python lock remains a 3.12-3.14 compatibility candidate until Task 8 proves same-lock sync, imports, and tests on all three exact patches.
- Narrows package metadata to `requires-python = ">=3.12,<3.15"`; the lock is resolved universally from the lowest supported Python 3.12, and static/wheel tests reject either bound drifting from the closed support claim.
- Produces a closed, platform-keyed `security/bootstrap-toolchain-lock.json` for each supported developer/CI Linux target. Each entry records tool, exact version, upstream publisher, immutable HTTPS artifact/checksum/signature URLs, SHA-256, signer/key fingerprint where upstream signatures exist, archive format, allowed top-level entries, embedded-version command, current registry/upstream version at review time, chosen version, and hold rationale. `scripts/bootstrap_toolchain.py` requires only a documented system Python 3.12+ and OS trust store, accepts a caller-created external mode-`0700` tool root, disables ambient proxies, forbids redirects/credentials/symlinks/special files/path traversal, verifies digest/signature before safe extraction, and atomically installs without executing a remote installer. Unknown target, missing signature/digest, unexpected archive entry, embedded-version mismatch, or current/chosen ledger drift fails closed. This checked-in lock is the supply-chain trust root; Task 0 does not claim a bare host without the documented system-Python/CA prerequisite.
- Produces a strict `SdkAuthorizationCapabilityVerdict` and canonical `contracts/sdk-authorization-capability.json` from one minimal raw-wire feasibility test against the exact installed MCP SDK: whether a supported public extension point can consume the SDK-parsed method/tool/resource identity and still return operation-specific transport HTTP 403 with the exact RFC 9728 minimum-scope challenge, without trusting routing headers or reparsing MCP. The record binds schema version, `mcp`/`mcp-types` versions, upstream tag/commit and installed-file digest, protocol revision, raw-wire case/observation digest, `supported`, stable blocker/reason, and reviewed date; generation/check is deterministic and SPEC/ADR/release manifests freeze its digest. SDK v2.0.0 is expected to report `supported=false`: its bearer middleware applies one static scope list before parsing, while parsed-operation handlers return MCP results rather than ASGI responses. True/false, SDK-file, challenge, case, and blocker mutations must fail. This negative verdict is valid evidence and creates stable blocker `MCP_DYNAMIC_SCOPE_403_UNSUPPORTED`; a reviewed upstream SDK release/adapter or explicit user-approved coarse-scope/header-binding design is required to clear it.
- Produces a separate strict `AlpicOAuthDiscoveryCapabilityVerdict` and canonical `contracts/alpic-oauth-discovery-capability.json`. Alpic's public documentation states only that deployment sends an unauthenticated MCP `initialize` and requires HTTP 401 plus a root `/.well-known/oauth-protected-resource` challenge; it does not publish the detector's HTTP method, backend path, JSON-RPC ID/body/protocol version, `Accept`/`Content-Type`, `MCP-Protocol-Version`, Host/Origin, response-body contract, or tolerance for additional challenge parameters. The record therefore includes `detector_contract_source: Literal["vendor_fixture", "bounded_documented_approximation"]`, the complete bounded request fixture, its provenance/digest, and `exact_detector_fixture_supported`; absent a versioned raw vendor fixture preserves `ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN` and no local request may be called an exact replay. The local raw-wire matrix does not assume a modern protocol-version header and requires an SDK-owned HTTP 401 with exactly one syntactically valid `WWW-Authenticate: Bearer` challenge, zero legacy/session-manager/handler entry, and no second token verifier. It separately freezes the backend-local `AuthSettings.resource_server_url`, challenge `resource_metadata` URI, local metadata route/document `resource`, public MCP transport endpoint, public OAuth resource/audience, any observed Alpic rewrite mapping, SDK source digest, request/response digest, and whether a supported public composition authenticates before the modern-only routing guard. Do not assume the `/mcp` transport URL is also the OAuth resource: MCP 2026-07-28 permits both root and path-specific protected-resource discovery, while SDK v2.0.0 derives a root route for an origin resource and a path-qualified route for a `/mcp` resource. Test and freeze the one issuer/client/provider-compatible tuple. Any unresolved route/resource/rewrite mismatch is `ALPIC_PRM_ROUTE_COMPATIBILITY_UNPROVEN`; any private/internal SDK seam, duplicate verifier, legacy dispatch, or pre-auth 400 is `ALPIC_OAUTH_DISCOVERY_ORDERING_UNPROVEN`. A locally positive approximation is necessary but cannot clear the detector-fixture or protected-classification blockers; only vendor evidence can clear the former and Task 21's deployment-bound provider observation can clear the latter. Verdict, route, resource, rewrite, challenge, source, request, dispatch-count, and blocker mutations must fail.
- Produces a strict `OAuthProviderCapabilityVerdict` and canonical `contracts/oauth-provider-capability.json` before choosing a verifier implementation. For the selected first target it fixes `provider="auth0"` and `client_registration_mode="alpic_dcr_proxy"`, then binds one named Auth0 tenant/custom domain and its byte-exact OIDC discovery issuer string; authorization/token/JWKS or RFC 7662 introspection endpoints; access-token format `Literal["signed_jwt", "opaque"]`; exact resource/audience issuance semantics; access-token-purpose and client-identity claims; PKCE S256; RFC 9207 authorization-response issuer behavior; scopes; token lifetime/revocation; and the Alpic client-pool environment. It separately models the upstream Auth0 token issuer, the backend self-issuer metadata required to enable Alpic's DCR pool, and the public-edge authorization/registration/token endpoints observed by clients; equality is forbidden unless the witnessed contract requires it. Alpic's Auth0 directory entry, the documented DCR proxy shape, or a synthetic token proves topology compatibility only, never tenant capability. No automatic JWT/opaque fallback is allowed: only a proven signed-JWT verdict selects the plan's PyJWT branch; an opaque verdict requires a separately reviewed introspection design, client-auth secret lifecycle, dependency/egress model, and TDD ledger. Missing or negative evidence preserves `OAUTH_PROVIDER_CAPABILITY_UNPROVEN`; an unproven registration mode additionally preserves `OAUTH_END_TO_END_FLOW_UNPROVEN`. The backend must reference itself as issuer and omit `registration_endpoint` before DCR-pool creation, while the observed public edge must advertise Alpic's registration endpoint after pool creation. A versioned vendor contract plus witnessed before/after discovery and authorization flow must reconcile that self-versus-Auth0 issuer topology; otherwise preserve `ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN`. Field, provider, tenant, endpoint, token-format, issuer-role, resource, registration-mode, client-pool-environment, evidence-digest, and blocker mutations must fail.

- [ ] **Step 1: Create the lock inputs before invoking `.venv`**

Before creating or regenerating any file, installing anything, or invoking
npm/uv resolution, enter a dedicated clean Git worktree for the implementation
and run this fail-stop preflight. HEAD must be exactly either the original
audit commit/tree or the specifically reviewed docs-only candidate commit/tree;
no later descendant is admitted. The plan may be read from the primary
checkout, but Task 0 never writes there:

```bash
set -euo pipefail
audit_commit=2ba5dc18385747aa5d12a3b560eaab2ab97b7a40
audit_tree=b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8
audit_src_tree=fcd9debdb533498486a2bbeaf909ea5bfb95b52c
reviewed_candidate_commit=da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0
reviewed_candidate_tree=2464df5aa1880e99168ce07c23d891ab66ed3959
candidate_commit=$(git rev-parse HEAD)
candidate_tree=$(git rev-parse 'HEAD^{tree}')
git merge-base --is-ancestor "$audit_commit" "$candidate_commit"
test "$(git rev-parse HEAD:src)" = "$audit_src_tree"

require_empty_changed_paths() {
  local changed_path
  if IFS= read -r -d '' changed_path; then
    printf 'unexpected changed path for audit identity: %s\n' "$changed_path" >&2
    return 1
  fi
}

require_reviewed_changed_paths() {
  local changed_path
  IFS= read -r -d '' changed_path || return 1
  test "$changed_path" = \
    docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md
  IFS= read -r -d '' changed_path || return 1
  test "$changed_path" = \
    docs/nplg-dspace-mcp-architecture-handoff-2026-08-14.md
  if IFS= read -r -d '' changed_path; then
    printf 'unexpected additional reviewed-candidate path: %s\n' \
      "$changed_path" >&2
    return 1
  fi
}

if test "$candidate_commit" = "$audit_commit" &&
   test "$candidate_tree" = "$audit_tree"; then
  git diff --name-only -z "$audit_commit..$candidate_commit" \
    | LC_ALL=C sort -z | require_empty_changed_paths
elif test "$candidate_commit" = "$reviewed_candidate_commit" &&
     test "$candidate_tree" = "$reviewed_candidate_tree"; then
  git diff --name-only -z "$audit_commit..$candidate_commit" \
    | LC_ALL=C sort -z | require_reviewed_changed_paths
else
  printf 'unreviewed Task 0 identity: commit=%s tree=%s\n' \
    "$candidate_commit" "$candidate_tree" >&2
  exit 1
fi
test -z "$(git status --porcelain=v1 --untracked-files=all --ignored=matching)"
printf 'candidate_commit=%s\ncandidate_tree=%s\naudit_src_tree=%s\n' \
  "$candidate_commit" "$candidate_tree" "$audit_src_tree"
```

Record the actual `candidate_commit` and `candidate_tree` in execution evidence;
never substitute them for or relabel the original audit commit/tree. If the
exact approved commit/tree identity, ancestor, exact `HEAD:src`,
identity-specific changed-path set, or cleanliness assertion fails, stop before
side effects and explicitly revise/re-review the baseline. Never point Task 0
at the dirty primary checkout or silently recapture another revision.

#### Historical staged-recovery exception

Phase 0-1 began in an explicitly authorized isolated worktree whose imported
index and empty working tree were recorded before implementation. That
one-time evidence is preserved in the Task 0 report; its temporary path and
shell transcript are intentionally not normative plan requirements. It is not
a reusable recovery mode and does not establish current cleanliness.

On 2026-08-16 the user explicitly authorized transferring and continuing the
named Phase 0-1 work in the primary checkout. That later direction supersedes
the historical primary-write prohibition only for the reviewed file scopes.
The protected imported staged entries remain user state: compare their logical
entry digest, never rewrite them, and do not stage, commit, reset, push,
deploy, or claim a clean release candidate without new authorization.

Before any network access or managed tool exists, create `scripts/bootstrap_toolchain.py` as a behavior-free typed scaffold and `tests/unit/test_bootstrap_toolchain.py` as a standard-library-only `unittest` module using injected local fake archives, lock records, downloader, signature verifier, and filesystem. Verify the documented system prerequisite with `python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 12))'`, run `python3 -m unittest tests.unit.test_bootstrap_toolchain`, and require the intended RED to reach `NotImplementedError`. Implement only digest/signature verification, traversal-safe extraction, exact embedded-version checking, and atomic installation; rerun the same command to GREEN, record the no-refactor/refactor decision, and run deliberate wrong-digest, symlink-entry, current/chosen-drift, and partial-publication faults before allowing the real bootstrap. Missing `unittest`, a Python below the documented prerequisite, or any network-dependent test is a bootstrap failure, not RED.

List every current test dependency and every Phase 0/1 development tool at an exact version in `requirements-dev.in`. The primary-registry pins revalidated on 2026-08-15 are `pytest==9.1.1`, `pytest-asyncio==1.4.0`, `pytest-cov==7.1.0`, `coverage==7.15.4`, `hypothesis==6.165.9`, `ruff==0.16.3`, `mypy==2.3.1`, `bandit==1.9.4`, `semgrep==1.173.0`, `pip-audit==2.10.1`, `diff-cover==10.5.0`, `mutmut==3.7.0`, `build==1.5.0`, `setuptools==84.0.0`, `wheel==0.48.0`, `check-wheel-contents==0.6.3`, `cyclonedx-bom==7.3.1`, `zizmor==1.29.0`, `check-jsonschema==0.38.0`, and `codespell==2.4.3`. Add the exact MCP v2 feasibility stack to this development lock now—`mcp==2.0.0`, `mcp-types==2.0.0`, `httpx2==2.9.0`, `httpcore2==2.9.0`, `truststore==0.10.4`, and compatible `idna==3.18`—so Task 0's architecture spike is lock-bound; Task 11 later promotes the same reviewed set to runtime requirements without re-resolving versions. Retain exact compatible pins for the existing `jsonschema`, PyYAML, pypdf, and reportlab test dependencies. The Pydantic mypy plugin ships with the pinned Pydantic dependency; do not add an unrelated plugin package.

Keep the overlapping `[project.optional-dependencies].test` pins in `pyproject.toml` byte-for-byte version-aligned and add a Task 3 policy assertion that rejects drift between the two declarations. Pin `[build-system].requires` exactly to `setuptools==84.0.0` and `wheel==0.48.0`, list both directly in the hash-locked development input, and require all package/release builds to use `python -m build --no-isolation` from an environment synchronized from that lock. Isolated PEP 517 resolution or an unpinned `setuptools>=...` backend is forbidden because it can change the built subject without changing the candidate revision. Include `-r requirements.in`; never use an editable local install in a `--require-hashes` lock. Revalidate all pins' declared Python 3.12-3.14 compatibility from primary registries immediately before lock regeneration; a newer release changes the reviewed inputs and requires the Task 3 policy/compatibility tests rather than an automatic upgrade. Registry classifiers are discovery evidence, not runtime proof; only the Task 8 three-minor matrix closes that claim.

Add exact hash-locked typing distributions `types-PyYAML==6.0.12.20260724`, `types-reportlab==4.4.9.20260215`, and `types-defusedxml==0.7.0.20260504` to both development declarations. `types-PyYAML` and `types-defusedxml` are the non-yanked current releases revalidated on 2026-08-15. Retain `types-reportlab==4.4.9.20260215` as an explicit compatibility hold against runtime `reportlab==4.4.9` rather than silently taking current `types-reportlab==4.5.1.20260807`; record latest/chosen/rationale and upgrade/test runtime plus stub together. All three pins remain subject to the execution-time registry check; Task 3 rejects their absence/version drift and imports their target modules under both strict checkers. `pypdfium2` has no accepted complete upstream stub for the used surface, so Task 6A creates and owns a narrow checked `typings/pypdfium2/__init__.pyi` plus `typings/pypdfium2/raw.pyi`, configures that one project stub root in Pyright/mypy, and runtime-contract-tests every declared symbol/signature against the exact pinned package. Blanket `ignore_missing_imports`, `follow_untyped_imports`, `Any`, or a package-wide diagnostic suppression remains forbidden; stub drift fails before PDF behavior changes.

Create and review the bootstrap lock and now-GREEN bootstrap implementation before using the managed tools; after bootstrapping into the external tool root, prepend only its verified `bin` directories to a closed `PATH`. Create `package.json` with `"private": true`, exact `"packageManager": "npm@11.18.0"`, `engines.node` restricted to the reviewed Node 24 line, no lifecycle scripts, and `pyright@1.1.413` as its sole initial development dependency. Generate and review the project locks and npm metadata with:

```bash
set -euo pipefail
read -r uv_name uv_version uv_target uv_extra <<< "$(uv --version)"
test "$uv_name" = "uv"
test "$uv_version" = "0.12.5"
case "$uv_target" in \(*-*-*\)) ;; *) exit 1 ;; esac
test -z "$uv_extra"
test "$(node --version)" = "v24.19.0"
test "$(npm --version)" = "11.18.0"
uv pip compile --python-version 3.12 --generate-hashes --universal \
  requirements-dev.in -o requirements-dev.lock
npm install --package-lock-only --ignore-scripts --save-dev --save-exact \
  pyright@1.1.413
```

Expected: both locks contain exact resolved versions and integrity data; npm lifecycle scripts do not execute.

- [ ] **Step 2: Create the environment from the locks**

```bash
set -euo pipefail
read -r uv_name uv_version uv_target uv_extra <<< "$(uv --version)"
test "$uv_name" = "uv"
test "$uv_version" = "0.12.5"
case "$uv_target" in \(*-*-*\)) ;; *) exit 1 ;; esac
test -z "$uv_extra"
test "$(node --version)" = "v24.19.0"
test "$(npm --version)" = "11.18.0"
uv venv --python "$(uv python find 3.13.15)" .venv
uv pip sync --python .venv/bin/python --require-hashes requirements-dev.lock
npm ci --ignore-scripts
.venv/bin/python -VV
test "$(.venv/bin/python -c 'import platform; print(platform.python_version())')" = "3.13.15"
test "$(npm exec --offline -- pyright --version)" = "pyright 1.1.413"
test "$(.venv/bin/python -c 'import importlib.metadata as m; print(m.version("setuptools"))')" = "84.0.0"
test "$(.venv/bin/python -c 'import importlib.metadata as m; print(m.version("wheel"))')" = "0.48.0"
```

Expected: bootstrap lock verification, uv name/version and a single parenthesized target triplet, Node, npm, Python, and Pyright pass the exact checks above; record the platform-specific uv triplet separately rather than comparing the whole display string. Task 3 policy cases accept `uv 0.12.5 (x86_64-unknown-linux-gnu)` and an equivalent explicitly locked target, but reject wrong/missing versions, malformed/missing/multiple target fields, trailing material, unlisted platform artifacts, or current/chosen/rationale drift. If an exact bootstrap/runtime version is unavailable, stop and review the pin; do not silently substitute another version or install an unverified bootstrap script. Do not claim Python 3.12/3.14 runtime compatibility from this local 3.13 bootstrap.

Now collect `tests/contracts/test_sdk_auth_feasibility.py`, `tests/contracts/test_alpic_oauth_discovery.py`, and `tests/contracts/test_oauth_provider_capability.py`; run each exact capability node against its behavior-free probe and witness `NotImplementedError` as RED. Implement only the three deterministic probes/validators and canonical verdict writers, rerun all three files to GREEN, and preserve truthful `supported=false` results as blockers rather than test failures. The provider verdict may initially be a strict unsupported/unselected record; it must not make authenticated network/admin calls or invent capabilities. Flip the expected SDK seam/challenge/installed-file digest; the Alpic detector provenance/request/header/status/challenge/backend/public resource/rewrite/verifier-count/legacy-dispatch fields; and the provider issuer/token-format/resource/audience/registration-mode/evidence fields in separate deliberate-fault fixtures. Every mutation must fail. If an observation differs from the reviewed SDK v2.0.0, current public Alpic contract, or selected provider evidence, stop and re-review the exact installed source/API and primary documentation rather than silently selecting an authorization or routing architecture.

- [ ] **Step 3: Add and prove typed shared test factories**

Move only deterministic construction logic from the existing `tests/unit/test_config.py:base_env` and `tests/unit/test_tools.py` helpers into `tests/helpers/app_factory.py`; do not change production behavior. `tests/conftest.py` exposes the exact `tool_service` and `app_services` fixtures used below. Write `test_shared_factories_reproduce_current_service_defaults`, then run:

```bash
.venv/bin/python -m pytest tests/unit/test_test_factories.py -q
```

Expected: PASS against the current implementation, proving that later RED tests cannot fail from missing fixtures.

- [ ] **Step 4: Revalidate the frozen-revision baseline before feature work**

```bash
set -euo pipefail
audit_commit=2ba5dc18385747aa5d12a3b560eaab2ab97b7a40
audit_tree=b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8
audit_src_tree=fcd9debdb533498486a2bbeaf909ea5bfb95b52c
reviewed_candidate_commit=da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0
reviewed_candidate_tree=2464df5aa1880e99168ce07c23d891ab66ed3959
candidate_commit=$(git rev-parse HEAD)
candidate_tree=$(git rev-parse 'HEAD^{tree}')
git merge-base --is-ancestor "$audit_commit" "$candidate_commit"
test "$(git rev-parse HEAD:src)" = "$audit_src_tree"

require_empty_changed_paths() {
  local changed_path
  if IFS= read -r -d '' changed_path; then
    printf 'unexpected changed path for audit identity: %s\n' "$changed_path" >&2
    return 1
  fi
}

require_reviewed_changed_paths() {
  local changed_path
  IFS= read -r -d '' changed_path || return 1
  test "$changed_path" = \
    docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md
  IFS= read -r -d '' changed_path || return 1
  test "$changed_path" = \
    docs/nplg-dspace-mcp-architecture-handoff-2026-08-14.md
  if IFS= read -r -d '' changed_path; then
    printf 'unexpected additional reviewed-candidate path: %s\n' \
      "$changed_path" >&2
    return 1
  fi
}

if test "$candidate_commit" = "$audit_commit" &&
   test "$candidate_tree" = "$audit_tree"; then
  git diff --name-only -z "$audit_commit..$candidate_commit" \
    | LC_ALL=C sort -z | require_empty_changed_paths
elif test "$candidate_commit" = "$reviewed_candidate_commit" &&
     test "$candidate_tree" = "$reviewed_candidate_tree"; then
  git diff --name-only -z "$audit_commit..$candidate_commit" \
    | LC_ALL=C sort -z | require_reviewed_changed_paths
else
  printf 'unreviewed Task 0 identity: commit=%s tree=%s\n' \
    "$candidate_commit" "$candidate_tree" >&2
  exit 1
fi
printf 'candidate_commit=%s\ncandidate_tree=%s\n' \
  "$candidate_commit" "$candidate_tree"
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest --cov=nplg_mcp --cov-branch \
  --cov-report=term-missing --cov-fail-under=80 -q
ruff_status=0
.venv/bin/ruff check --select ALL src tests scripts --statistics || ruff_status=$?
test "$ruff_status" -eq 1
```

Expected: the 254 frozen legacy tests plus the new factory test PASS (255 or more total), branch coverage remains at the recorded 82% absent an explained measurement-only delta, and Ruff's legacy inventory reconciles to the audited 2,377 diagnostics across 67 rules after accounting for the newly added clean files/package markers. Ruff's discovery exit must be exactly 1 for findings; exit 0 would contradict the frozen inventory and exit 2 would indicate a tool failure. Inspect its statistics rather than treating any nonzero status as success. Record and review every variance before changing the oracle, and do not write into, delete, or repurpose any unrelated untracked path recorded by the Task 0 Git-state snapshot.

- [ ] **Step 5: Commit checkpoint**

After explicit authorization, stage only `pyproject.toml`, the named locks, shared test infrastructure, and README bootstrap instructions; then: `git commit -m "chore: make development bootstrap reproducible"`.

### Task 1: Freeze current behavior and write the normative ADR

#### Files

- Create: `SPEC.md`
- Create: `docs/architecture/2026-08-14-official-python-sdk-adr.md`
- Create: `contracts/baseline/tool-catalog.json`
- Create: `contracts/baseline/resources.json`
- Create: `contracts/baseline/result-cases.json`
- Create: `contracts/baseline/error-cases.json`
- Create: `contracts/baseline/manifest.json`
- Create: `contracts/zod/capability-contracts.mjs`
- Create: `contracts/zod/baseline-contracts.mjs`
- Create: `scripts/capture_baseline.py`
- Create: `scripts/baseline_capture_io.py`
- Create: `scripts/baseline_replay.py`
- Create: `tests/contracts/test_frozen_baseline.py`
- Create: `tests/contracts/zod_contracts.test.mjs`
- Create: `tests/contracts/zod_baseline_contracts.test.mjs`
- Create: `eslint.config.mjs`
- Create: `tsconfig.contracts.json`
- Modify: `tests/helpers/app_factory.py`
- Modify: `tests/helpers/pdf_factory.py` for strict typed deterministic PDF
  fixture construction without semantic byte drift
- Modify: `package.json`, `package-lock.json` only for the exact Task-1-owned
  baseline Zod lint/typecheck commands and exact reviewed development pins
- Modify: `tests/static/test_quality_policy.py` only when executable static
  policy assertions are required for the Task-1-owned Python/JavaScript scope
- Modify: `tests/static/test_deployment.py` only to keep its exact Node
  development-dependency inventory synchronized with the Task-1-owned pinned
  TypeScript and ESLint toolchain
- Modify: `src/nplg_mcp/tools.py` only for an injected, timezone-aware UTC clock seam used by deterministic signed-asset fixture replay
- Modify: `src/nplg_mcp/protocol.py` only for RED-proven closed JSON-RPC envelope and method-parameter validation; the frozen oracle must not preserve permissive unknown-field acceptance
- Modify: `docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md`
- Modify: `docs/superpowers/specs/2026-08-14-nplg-dspace-mcp-design.md`
- Modify: `docs/superpowers/plans/2026-08-14-nplg-dspace-mcp-implementation.md`

#### Interfaces

- Consumes: `ToolService.list_tools()`, `ToolService.call(name, arguments)`, `McpProtocol.handle(payload, headers)`.
- Produces: immutable JSON fixtures keyed by tool name and case ID; strict frozen
  Pydantic replay/setup/request/expected models; an independent pinned-Zod
  baseline schema/oracle; and ADR decision `ADR-001` declaring Python SDK
  migration and `alpic-metadata` first release. Request JSON bytes and headers
  remain exact and are never normalized. Response comparison alone uses the
  versioned semantic-number rule: preserve booleans, map finite mathematically
  integral floats within the JavaScript safe-integer range to integers (including
  negative zero to zero), and reject fractional, non-finite, or out-of-range
  values.

Task 1 also owns strict static closure for
`scripts/capture_baseline.py`, `scripts/baseline_capture_io.py`,
`scripts/baseline_replay.py`, `tests/contracts/test_frozen_baseline.py`, and
`tests/helpers/pdf_factory.py`, plus type-aware ESLint/checkJs closure for the
two baseline Zod `.mjs` files. The Python split preserves all frozen behavior,
provenance, no-follow/bounds/race/process-group guarantees, and exposes only
typed public test seams. New local modules/configuration are admitted to the
synthetic index only through the exact reviewed `included_untracked_paths`
tuple; broad untracked discovery remains forbidden. Strict configuration and
source-wide ignores are forbidden. A narrowly reviewed local suppression is
permitted only where the secure implementation inherently triggers a tool rule,
such as the one audited no-shell absolute-executable subprocess boundary or the
last-resort sanitizer wrapper; each suppression must name one exact rule at the
smallest statement and remain mutation-tested. Blanket ignores, per-file
ignores, `type: ignore`/`Any`, disable directives, and syntactic evasions are not
acceptable static closure.

The Task-1-owned Python suppression inventory tokenizes comment-oriented
controls and separately applies Coverage.py's pinned raw-source expressions;
it uses closed source-derived grammars rather than substring guesses. After
Task 6C, its closed accepted output is exactly nine reviewed statement-local
records: five `S603`, one `S310`, one `PLR0913`, one `BLE001`, and one `TRY400`;
no other suppression is accepted. Against the pinned analyzers it must detect file-level and inline
Pyright modes, ignores, severity toggles over the exact pinned diagnostic-rule
tuple, and the exact accepted boolean-rule tuple; mypy controls only at the
literal, case-sensitive, column-zero # mypy:  prefix; Ruff/Flake8 lint,
file-ignore, block disable/enable, file-noqa, and formatter controls;
import-sorter, security-scanner, Coverage.py exclusion/partial-branch, and coded
or blanket type-ignore forms.

A count is not proof of the Pyright rule boundary: an independent literal
81-entry oracle extracted from pinned 1.1.413 must be duplicate-free and exactly
set-equal to the classifier tuple. Dedicated ignore and severity mutations for
every review-discovered missing name fail independently before that tuple may be
called complete.

The grammar mirrors pinned quirks that are security relevant. Pyright retries a
later candidate after a malformed `pyright:` marker, treats trailing prose
after a blanket ignore and arbitrary suffix text after a closed rule bracket as
active, drops empty/unknown comma-list companions while retaining an effective
known rule, and stops after a syntactically valid but ineffective first bracket.
Its configuration parser accepts only the exact pinned modes, boolean rules,
diagnostic names, cases, and values. Mypy removes double quotes and concatenates
quoted/unquoted fragments while splitting only commas outside quotes; preserves
leading/interior empty items; drops a final item only when its final buffer is
empty; retains already parsed items after an unmatched quote; converts hyphens
to underscores; and case-folds option names through `RawConfigParser`. A valid
control remains inventoried when an empty, malformed, or prose companion emits
a configuration diagnostic, because an effective `ignore_errors` can suppress
that diagnostic. A malformed item with no applied configuration remains a
benign negative control.

Ruff finds later `# noqa`, `# ruff: noqa`, `# ruff: ignore[...]`,
`# ruff: file-ignore[...]`, block `# ruff: disable[...]`/`enable[...]`, later-hash
`# fmt: skip`, and context-valid import-sorter controls. Bandit treats the
`nosec` prefix as blanket suppression. Coverage.py applies its documented
all-lowercase or all-uppercase `pragma`/`no`/`cover|branch` expressions over raw
source rather than Python COMMENT tokens, so matching text inside a literal is
inventoried and `coverage`/`branching` suffixes remain active. Literal strings
for token-based tools, ordinary prose, invalid placements, ineffective unknown
rules, malformed values, and case/spacing variants the pinned analyzers do not
consume remain absent. Persistent source-derived differential tables exercise
every forbidden family and benign near-match so a missing branch, failed retry,
or conservative false positive fails independently.

For the two baseline JavaScript files, the resolved ESLint configuration is
strictly parsed and binds `linterOptions.noInlineConfig === true` plus
`reportUnusedDisableDirectives === "error"` (resolved severity `2`). Real
`ESLint.lintText` calls use
both configured file paths and prove an inline `eslint-disable` attack cannot
silence the forbidden JSDoc-any rule; a deliberately weakened in-memory config
with `noInlineConfig=false` must demonstrate that the same attack would
otherwise become message-free. The package policy freezes the exact
`contracts:baseline-static` command including `--max-warnings 0`, preserves the
capability and dedicated baseline Zod scripts, and binds the aggregate script
to both suites.

- [ ] **Step 1: Write the failing completeness test**

```python
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


BASELINE_DIR = Path("contracts/baseline")
BaselineFileName = Literal[
    "tool-catalog.json",
    "resources.json",
    "result-cases.json",
    "error-cases.json",
]
HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitObjectId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
CaseId = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"),
]


class BaselineModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
    )


class BaselineEntry(BaselineModel):
    path: BaselineFileName
    sha256: HexDigest


class GitSourceIdentity(BaselineModel):
    commit: GitObjectId
    tree: GitObjectId
    src_tree: GitObjectId


class RecoveryIdentity(BaselineModel):
    base_commit: GitObjectId
    base_tree: GitObjectId
    imported_index_tree: GitObjectId


class IndexTransitionIdentity(BaselineModel):
    transition_id: Literal["phase-1-reviewed-index-transition-v1"]
    imported_index_tree: Literal[
        "6cb461d986c21e4cb2852a07b06f75812ec27bbb"
    ]
    imported_staged_entries_sha256: Literal[
        "fcfe06d851c83040d860f9f887efe18bde9dbe46c4eeb1aaa3f68b3af8f3ccaf"
    ]
    candidate_index_tree: Literal[
        "55691718dade75b44a8ed025fcf48dabf87a7969"
    ]
    candidate_staged_entries_sha256: Literal[
        "9426ba909728d29d2009607264a9ffb1c028c4c645bbacd72f98867132e24f68"
    ]


class CaptureInputIdentity(BaselineModel):
    tree_before: GitObjectId
    tree_after: GitObjectId
    src_tree: GitObjectId
    git_object_format: Literal["sha1"]
    excluded_output_paths: Annotated[
        tuple[
            Literal[
                "contracts/baseline/tool-catalog.json",
                "contracts/baseline/resources.json",
                "contracts/baseline/result-cases.json",
                "contracts/baseline/error-cases.json",
                "contracts/baseline/manifest.json",
            ],
            ...,
        ],
        Field(min_length=5, max_length=5),
    ]
    included_untracked_paths: tuple[
        Literal["contracts/zod/asvs-evidence-contracts.mjs"],
        Literal["contracts/zod/baseline-contracts.mjs"],
        Literal["docs/security/threat-model.json"],
        Literal["eslint.config.mjs"],
        Literal["scripts/baseline_capture_io.py"],
        Literal["scripts/baseline_replay.py"],
        Literal["tests/contracts/zod_asvs_evidence_contracts.test.mjs"],
        Literal["tests/contracts/zod_baseline_contracts.test.mjs"],
        Literal["tests/property/test_asvs_evidence.py"],
        Literal["tests/unit/test_build_asvs_matrix.py"],
        Literal["tsconfig.contracts.json"],
    ]


class GeneratorIdentity(BaselineModel):
    path: Literal["scripts/capture_baseline.py"]
    version: Literal["3"]
    blob: GitObjectId
    sha256: HexDigest


class BaselineManifest(BaselineModel):
    schema_version: Literal[3]
    capture_mode: Literal["synthetic-index-staged-recovery"]
    audit: GitSourceIdentity
    recovery: RecoveryIdentity
    index_transition: IndexTransitionIdentity
    input: CaptureInputIdentity
    generator: GeneratorIdentity
    canonicalization: Literal["nplg-json-sort-utf8-lf-v1"]
    response_canonicalization: Literal[
        "nplg-response-semantic-numbers-v1"
    ]
    entries: Annotated[
        tuple[BaselineEntry, ...],
        Field(min_length=4, max_length=4),
    ]
    required_tool_names: Annotated[
        tuple[CaseId, ...],
        Field(min_length=8, max_length=8),
    ]
    required_case_ids: Annotated[
        tuple[CaseId, ...],
        Field(min_length=1, max_length=512),
    ]
    release_eligible: Literal[False]
    release_blockers: tuple[
        Literal["BASELINE_CAPTURE_NOT_COMMIT_REACHABLE"]
    ]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_rev_parse(object_spec: str) -> str:
    result: subprocess.CompletedProcess[str] = subprocess.run(
        ["git", "rev-parse", "--verify", object_spec],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def load_fixture_index(path: BaselineFileName) -> dict[str, object]:
    value = cast(
        object,
        json.loads((BASELINE_DIR / path).read_text(encoding="utf-8")),
    )
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise AssertionError(f"{path} must be a string-keyed JSON object")
    return cast(dict[str, object], value)


def frozen_tool_names() -> set[str]:
    return set(load_fixture_index("tool-catalog.json"))


def frozen_case_ids() -> set[str]:
    case_ids: set[str] = set()
    paths: tuple[BaselineFileName, ...] = (
        "resources.json",
        "result-cases.json",
        "error-cases.json",
    )
    for path in paths:
        case_ids.update(load_fixture_index(path))
    return case_ids


def test_frozen_baseline_is_complete_and_digest_bound(
    tool_service: ToolService,
) -> None:
    manifest = BaselineManifest.model_validate_json(
        Path("contracts/baseline/manifest.json").read_text(encoding="utf-8"),
        strict=True,
    )
    assert manifest.audit.commit == "2ba5dc18385747aa5d12a3b560eaab2ab97b7a40"
    assert manifest.audit.tree == "b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8"
    assert manifest.audit.src_tree == "fcd9debdb533498486a2bbeaf909ea5bfb95b52c"
    assert manifest.recovery.base_commit == (
        "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0"
    )
    assert manifest.recovery.base_tree == (
        "2464df5aa1880e99168ce07c23d891ab66ed3959"
    )
    assert manifest.recovery.imported_index_tree == (
        "6cb461d986c21e4cb2852a07b06f75812ec27bbb"
    )
    assert manifest.index_transition.imported_index_tree == (
        manifest.recovery.imported_index_tree
    )
    assert manifest.index_transition.candidate_index_tree == (
        "55691718dade75b44a8ed025fcf48dabf87a7969"
    )
    assert manifest.index_transition.imported_staged_entries_sha256 == (
        "fcfe06d851c83040d860f9f887efe18bde9dbe46c4eeb1aaa3f68b3af8f3ccaf"
    )
    assert manifest.index_transition.candidate_staged_entries_sha256 == (
        "9426ba909728d29d2009607264a9ffb1c028c4c645bbacd72f98867132e24f68"
    )
    assert manifest.input.tree_before == manifest.input.tree_after
    assert manifest.input.git_object_format == "sha1"
    assert manifest.input.excluded_output_paths == (
        "contracts/baseline/tool-catalog.json",
        "contracts/baseline/resources.json",
        "contracts/baseline/result-cases.json",
        "contracts/baseline/error-cases.json",
        "contracts/baseline/manifest.json",
    )
    assert manifest.input.src_tree == git_rev_parse(
        f"{manifest.input.tree_before}:src"
    )
    assert {entry.path for entry in manifest.entries} == {
        "tool-catalog.json",
        "resources.json",
        "result-cases.json",
        "error-cases.json",
    }
    assert len({entry.path for entry in manifest.entries}) == len(manifest.entries)
    assert set(manifest.required_tool_names) == frozen_tool_names()
    assert len(set(manifest.required_case_ids)) == len(manifest.required_case_ids)
    assert all(
        entry.sha256 == sha256_file(BASELINE_DIR / entry.path)
        for entry in manifest.entries
    )
    assert frozen_tool_names() == {
        tool["name"] for tool in tool_service.list_tools()
    }
    assert frozen_case_ids() == set(manifest.required_case_ids)
```

Add the shown helpers and imports directly to `tests/contracts/test_frozen_baseline.py`, plus an explicit `ToolService` import. Their definitions are collection-safe and perform no fixture reads until the test body; therefore the first behavioral RED is the missing manifest file, not a missing symbol or fixture.

- [ ] **Step 2: Run the focused test and observe RED**

Run: `.venv/bin/python -m pytest tests/contracts/test_frozen_baseline.py -q`
Expected: collection/imports PASS; the test FAILS on the intentional absence of `contracts/baseline/manifest.json`, not on `tool_service` setup.

- [ ] **Step 3: Capture deterministic fixtures and the ADR**

Store canonical sorted UTF-8 JSON with no timestamps, floats, duplicate keys,
BOM, alternate whitespace, or missing final LF. For this one authorized recovery,
derive a fresh capture input from an absolute temporary index seeded with exact
tree `6cb461d986c21e4cb2852a07b06f75812ec27bbb`: run only
`git add -u -- .`, remove the literal four fixture paths plus `manifest.json`,
then, inside the same closed private Git boundary, add only the exact reviewed,
sorted untracked tuple using the literal argv
`git add -- contracts/zod/asvs-evidence-contracts.mjs contracts/zod/baseline-contracts.mjs docs/security/threat-model.json eslint.config.mjs scripts/baseline_capture_io.py scripts/baseline_replay.py tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_baseline_contracts.test.mjs tests/property/test_asvs_evidence.py tests/unit/test_build_asvs_matrix.py tsconfig.contracts.json`
before writing the synthetic input tree. Never use `git add -A`, a bare
`git add`, a wildcard, or any other untracked-path discovery. Before and after
that exact add, bounded no-follow reads must prove all eleven declared paths are
single-link mode-`0644` regular files with unchanged identity, size, bytes, and
independently computed blob IDs; missing, symlink, special, hard-linked,
oversized, or raced declared inputs fail closed. The written tree must contain
all eleven exact declared entries and blobs, while unrelated untracked and ignored
paths remain absent. Validate the exact audit commit/tree/`src`,
reviewed base commit/tree, real imported-index tree, object types, and ancestry
before capture. Reject symlink/special tree entries, materialize that exact tree
into a private mode-`0700` root, and run its generator in a fresh `python -P`
child whose `PYTHONPATH` names only the materialized `src` and root. Repeat the
synthetic-index derivation after collection and reject any tree, `src`, generator
blob, or generator-digest drift before outputs are touched.

Manifest schema v3 records the closed audit and recovery identities, the exact
reviewed historical-import-to-candidate transition and both canonical staged-entry
digests, identical
`input.tree_before`/`tree_after`, derived input `src` tree, generator path/version/
blob/SHA-256, exact four fixture digests, exact eight tool names, sorted unique
case IDs, canonicalization ID, `release_eligible=false`, and sole blocker
`BASELINE_CAPTURE_NOT_COMMIT_REACHABLE`. `--check` uses a temporary object
database populated by a bounded no-follow private object byte copy; it rejects `info/alternates` and `info/http-alternates`, and
`GIT_ALTERNATE_OBJECT_DIRECTORIES` is absent. It computes every output in
memory, compares exact bytes, and leaves the real index and the complete real
object inventory unchanged, including names, bytes, modes, link counts, sizes,
mtimes, ctimes, and inodes. `--write` uses an append-only real object destination:
it may add immutable objects and Git may refresh metadata for pre-existing
objects, but it must preserve their bytes, modes, sizes, and object identities as
well as refs and real-index bytes. It stages and fsyncs all five outputs on the
same filesystem, validates them, publishes the four fixtures first and manifest
last, and rolls back caught write/rename faults. This is fail-closed manifest-last
publication, not cross-file crash atomicity.

All capture Git operations run with an absolute system Git executable against a
fresh private `GIT_DIR`, copied temporary index, empty hooks/info directories,
and a closed prompt/credential/config environment. Check mode uses only the
verified private object copy; write mode uses the explicit append-only real
object destination. Repository-local filters, hooks, config, and
`info/attributes` are therefore outside the execution boundary. Every Git child
has a fixed deadline, bounded stdout/stderr, whole-process-group termination,
exact status/UTF-8/record parsing, and no shell. The manifest binds literal
`git_object_format="sha1"`
and both the ordered five-path exclusion tuple and exact sorted eleven-path `included_untracked_paths` tuple (`contracts/zod/asvs-evidence-contracts.mjs`, `contracts/zod/baseline-contracts.mjs`, `docs/security/threat-model.json`, `eslint.config.mjs`, `scripts/baseline_capture_io.py`, `scripts/baseline_replay.py`, `tests/contracts/zod_asvs_evidence_contracts.test.mjs`, `tests/contracts/zod_baseline_contracts.test.mjs`, `tests/property/test_asvs_evidence.py`, `tests/unit/test_build_asvs_matrix.py`, `tsconfig.contracts.json`). Before and after the capture child,
validate the complete materialized relative-path inventory, regular-file modes,
single-link/inode state, sizes, and independently computed Git blob IDs against
the synthetic tree; reject links, special files, extra paths, content changes,
and identical-byte replacements. Case IDs must be unique across all three case
fixture files, not merely unique within each file or after set union.

Every Task 1 temporary-repository Git setup/probe uses an equally closed
test-only command seam: absolute system Git and exact literal argv, disabled
system/global configuration, private mode-`0700` `HOME`/`XDG_CONFIG_HOME`,
fixed locale/path/timezone and author/committer identity/date, disabled prompts,
askpass, editors, pagers, SSH, credentials, and optional locks, plus explicit
`commit.gpgSign=false` and `tag.gpgSign=false` command configuration. Each child
runs without a shell through the bounded process-group runner with a five-second
deadline, 1-MiB stdout and 64-KiB stderr ceilings, strict UTF-8/status handling,
and closed failure mapping. Tests inject ambient global signing configuration
and a helper canary without changing real global configuration; the helper must
never execute. Exact environment, argv, deadline, ceilings, timeout/output-limit
mapping, and use by every temporary Git setup call are executable assertions.

Include all eight current tools, modern and legacy success/error envelopes,
resource listings/reads, strict input rejection, sanitized public errors, and
representative PDF manifests generated by existing deterministic factories.
Freeze intended domain semantics, not vulnerabilities: if the current server
leaks a canary, coerces a forbidden value, accepts unsafe framing, or violates
another new security invariant, record that input as a negative regression and
mark the current result as a defect rather than an accepted oracle value. The
root `SPEC.md` is the normative product/scope ledger, links the approved design
and ADR, and records the user-confirmed value, core actions, data boundaries,
and one machine-readable closed `first_release_profile` field plus the digest of
that profile decision. Stop after the draft if that product/profile decision is
not explicitly approved. The ADR records:

The machine-readable record is the sole line between literal markers `<!-- nplg-release-profile:v1` and `-->`, contains the canonical RFC 8785-compatible UTF-8 JSON object `{"decision_sha256":"b064e1d16fca1c4f86f9d8c2a5f1053cd25d50f88c169505eb79464d49c259cb","first_release_profile":"alpic-metadata","schema_version":1}`, and has no duplicate/unknown keys or alternate record. `decision_sha256` is SHA-256 over the exact UTF-8 preimage `{"profile":"alpic-metadata","schema_version":1}\n`; it is not a digest of its own enclosing object. The schema permits only the closed profile enum `alpic-metadata | private-full | distributed-full`, but this approved record fixes `alpic-metadata`. Static tests parse marker bytes, canonicalize/recompute the preimage, and reject missing/duplicate/malformed/stale/extra fields, alternate Unicode/newline serialization, or disagreement with the ADR and baseline manifest. Task 22 derives the selected profile from this verified record; an ambient requested profile can only be compared with it, never override it.

- official `mcp==2.0.0` is mandatory;
- current domain semantics are preserved until differential proof passes;
- Zod is an independent test oracle only;
- metadata-first Alpic is the explicitly confirmed first-release scope;
- Rust and a private Tasks protocol are rejected;
- the old plan/spec are historical, via a one-line supersession notice at the top of each file.
- baseline fixtures are immutable after this task; accepted SDK-standard differences belong in `contracts/accepted-sdk-differences.json` and may not rewrite the oracle.

- [ ] **Step 4: Run focused and full baseline tests**

Run: `.venv/bin/python -m pytest tests/contracts/test_frozen_baseline.py tests/unit/test_tools.py tests/conformance/test_mcp_http.py -q`
Expected: PASS with byte-stable sorted fixtures.

- [ ] **Step 5: Commit checkpoint**

After explicit authorization, use the mandatory checkpoint protocol with a literal `task_paths=(...)` containing every exact Task 1 `Create`/`Modify` path and `TASK_COMMIT_MESSAGE="test: freeze MCP behavioral contract"`; directory entries and bare `git add`/`git commit` commands are forbidden.

### Task 1A: Serialize the compatibility PDF backend immediately

#### Files

- Modify: `src/nplg_mcp/config.py`, `src/nplg_mcp/tools.py`
- Modify: `tests/unit/test_config.py`, `tests/unit/test_tools.py`
- Modify: `.env.example`, `deploy/README.md`

#### Interfaces

- Produces `PDF_EXECUTOR=serialized` with `MAX_CONCURRENT_PDF_JOBS=1`; startup rejects a higher value for this backend.

- [ ] **Step 1: Write the failing concurrency test**

```python
class ObservedPdfJobLimiter:
    def __init__(self, delegate: asyncio.Semaphore) -> None:
        self._delegate = delegate
        self._acquire_attempts = 0
        self.second_acquire_attempted = asyncio.Event()
        self.second_attempt_found_locked: bool | None = None

    async def acquire(self) -> None:
        self._acquire_attempts += 1
        if self._acquire_attempts == 2:
            self.second_attempt_found_locked = self._delegate.locked()
            self.second_acquire_attempted.set()
        await self._delegate.acquire()

    def release(self) -> None:
        self._delegate.release()


class ControlledPdfProcessor(FakePdfProcessor):
    def __init__(self, store: ContentAddressedStore) -> None:
        super().__init__(store)
        self.first_entered = threading.Event()
        self.first_completed = threading.Event()
        self.second_entered = threading.Event()
        self._release_first = threading.Event()
        self._lock = threading.Lock()
        self._entry_count = 0
        self._active_calls = 0
        self.maximum_simultaneous_calls = 0

    def inspect(self, pdf_path: Path) -> PdfInspection:
        with self._lock:
            self._entry_count += 1
            entry_number = self._entry_count
            self._active_calls += 1
            self.maximum_simultaneous_calls = max(
                self.maximum_simultaneous_calls,
                self._active_calls,
            )
            if entry_number == 1:
                self.first_entered.set()
            elif entry_number == 2:
                self.second_entered.set()
        try:
            if entry_number == 1 and not self._release_first.wait(timeout=5):
                raise TimeoutError("test-controlled PDF worker did not receive release")
            return super().inspect(pdf_path)
        finally:
            with self._lock:
                self._active_calls -= 1
            if entry_number == 1:
                self.first_completed.set()

    def release_first_call(self) -> None:
        self._release_first.set()


def test_serialized_pdf_backend_rejects_parallelism() -> None:
    env = base_environment(
        MAX_CONCURRENT_PDF_JOBS="2",
        PDF_EXECUTOR="serialized",
    )
    with pytest.raises(ValueError, match="must equal 1"):
        load_config(env)

@pytest.mark.asyncio
async def test_serialized_pdf_backend_never_enters_pdfium_concurrently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    probe = ControlledPdfProcessor(store)
    real_semaphore = asyncio.Semaphore
    configured_limiter: ObservedPdfJobLimiter | None = None

    def observed_semaphore(capacity: int = 1) -> ObservedPdfJobLimiter:
        nonlocal configured_limiter
        configured_limiter = ObservedPdfJobLimiter(real_semaphore(capacity))
        return configured_limiter

    with monkeypatch.context() as constructor_patch:
        constructor_patch.setattr(asyncio, "Semaphore", observed_semaphore)
        tool_service = ToolService(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=probe,
            store=store,
            config=config(tmp_path),
        )
    assert configured_limiter is not None
    limiter = configured_limiter
    first = asyncio.create_task(
        tool_service.call("inspect_pdf", {"artifact_id": artifact.object_id})
    )
    second: asyncio.Task[dict[str, object]] | None = None
    try:
        assert await asyncio.to_thread(probe.first_entered.wait, 2)
        second = asyncio.create_task(
            tool_service.call("inspect_pdf", {"artifact_id": artifact.object_id})
        )
        await asyncio.wait_for(limiter.second_acquire_attempted.wait(), timeout=2)
        assert limiter.second_attempt_found_locked is True
        assert not second.done()
        assert not probe.second_entered.is_set()
        assert probe.maximum_simultaneous_calls == 1
    finally:
        probe.release_first_call()
        pending = (first,) if second is None else (first, second)
        await asyncio.wait_for(
            asyncio.gather(*pending, return_exceptions=True),
            timeout=2,
        )
    assert second is not None
    assert first.exception() is None
    assert second.exception() is None
    assert probe.maximum_simultaneous_calls == 1


@pytest.mark.asyncio
async def test_cancelled_pdf_request_holds_permit_until_native_worker_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedStore(tmp_path)
    artifact = store.put_bytes(
        b"%PDF-1.7\nfixture",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    probe = ControlledPdfProcessor(store)
    real_semaphore = asyncio.Semaphore
    configured_limiter: ObservedPdfJobLimiter | None = None

    def observed_semaphore(capacity: int = 1) -> ObservedPdfJobLimiter:
        nonlocal configured_limiter
        configured_limiter = ObservedPdfJobLimiter(real_semaphore(capacity))
        return configured_limiter

    with monkeypatch.context() as constructor_patch:
        constructor_patch.setattr(asyncio, "Semaphore", observed_semaphore)
        tool_service = ToolService(
            repository=FakeRepository(),
            downloader=FakeDownloader(store),
            pdf=probe,
            store=store,
            config=config(tmp_path),
        )
    assert configured_limiter is not None
    limiter = configured_limiter
    first = asyncio.create_task(
        tool_service.call("inspect_pdf", {"artifact_id": artifact.object_id})
    )
    second: asyncio.Task[dict[str, object]] | None = None
    try:
        assert await asyncio.to_thread(probe.first_entered.wait, 2)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        second = asyncio.create_task(
            tool_service.call("inspect_pdf", {"artifact_id": artifact.object_id})
        )
        await asyncio.wait_for(limiter.second_acquire_attempted.wait(), timeout=2)
        assert limiter.second_attempt_found_locked is True
        assert not probe.first_completed.is_set()
        assert not probe.second_entered.is_set()
        assert not second.done()
    finally:
        probe.release_first_call()
        assert await asyncio.to_thread(probe.first_completed.wait, 2)
        if second is not None:
            await asyncio.wait_for(
                asyncio.gather(second, return_exceptions=True),
                timeout=2,
            )
    assert second is not None
    assert second.exception() is None
    assert probe.maximum_simultaneous_calls == 1
```

In `tests/unit/test_config.py`, explicitly import Task 0's `base_environment` from `tests.helpers.app_factory`. Define both shown helpers directly in `tests/unit/test_tools.py` before the test and add explicit module-level `import asyncio` and `import threading`; do not rely on imports local to older test functions. `ObservedPdfJobLimiter` has the exact typed `async acquire() -> None`/`release() -> None` shape consumed by `_run_pdf_job`. The scoped constructor patch wraps the production semaphore at its actual configured capacity and is restored before either request starts, so the test cannot force the desired capacity or add a production callback before RED. The five-second worker wait is a deadlock watchdog, not the negative assertion. Reuse the already defined `FakeRepository`, `FakeDownloader`, `FakePdfProcessor`, `config`, and real content-addressed fixture construction shown above; do not introduce unnamed fixtures or helper modules.

The second shown regression replaces the live test's timing-only negative observation. It cancels the first awaiting task after its worker enters, proves the second call remains queued while the shielded first worker is still blocked, releases that worker, waits for the independently observable `first_completed`, and then proves the second completes. Never make the first worker wait for a second processor entry; correct serialization would deadlock that test by construction.

- [ ] **Step 2: Observe RED**

Run these exact nodes separately and retain three distinct ledger rows before changing production code:

1. `.venv/bin/python -m pytest tests/unit/test_config.py::test_serialized_pdf_backend_rejects_parallelism -q`
2. `.venv/bin/python -m pytest tests/unit/test_tools.py::test_serialized_pdf_backend_never_enters_pdfium_concurrently -q`
3. `.venv/bin/python -m pytest tests/unit/test_tools.py::test_cancelled_pdf_request_holds_permit_until_native_worker_exits -q`

Expected: the configuration node FAILS because an explicit capacity of two is accepted; the parallel-entry node reaches `second_attempt_found_locked is True` and FAILS because the live two-permit limiter is not locked; the cancellation node FAILS because cancellation releases the permit before the native worker's independently observed completion. Neither may fail from missing fixtures or imports. `second_acquire_attempted` deterministically proves the second caller reached the actual production admission boundary before the immediate negative assertions; timeouts are setup/deadlock watchdogs only, and every blocked worker has an explicit test-controlled release in `finally` cleanup.

- [ ] **Step 3: Add the fail-closed clamp**

Complete three explicit minimal GREEN substeps without batching their evidence. First reject an explicit serialized/thread capacity above one without changing the existing default, then rerun only node 1. Second change the serialized default and actual limiter construction to one, then rerun only node 2. Third retain the permit until the native worker has independently finished even when its awaiting task is cancelled, then rerun only node 3. Record a no-refactor/refactor decision after each substep. Deliberate faults that accept capacity `2`, construct the live semaphore with `2`, or release the permit on waiter cancellation before `first_completed` must each fail its owning node. Document that serialization is a temporary risk reduction—not worker isolation.

- [ ] **Step 4: Run config, tools, and PDF tests**

Run: `.venv/bin/python -m pytest tests/unit/test_{config,tools}.py tests/integration/test_pdf.py -q`
Run: `.venv/bin/python -m pytest -q`
Expected: both the focused group and complete pre-Task-7 baseline PASS after the three named fault-sensitivity checks; record the explicit final refactor/no-refactor decision.

- [ ] **Step 5: Commit checkpoint**

Stage named files, then: `git commit -m "fix: serialize compatibility PDF execution"`.

### Task 1B: Close the touched legacy service/static surface before ratchet capture

This audit-remediation task executes before Task 2 and supersedes the later
Task 6B file ordering only for the exact paths named here. It does not widen
the official-SDK cutover, change a public wire result, or authorize a commit.

#### Files

- Modify: `src/nplg_mcp/protocol.py`, `src/nplg_mcp/tools.py`,
  `src/nplg_mcp/app.py`
- Create: `src/nplg_mcp/json_types.py` as the closed typed JSON boundary
  shared by this cleanup and later named tasks
- Modify: `tests/helpers/app_factory.py`, `tests/unit/test_tools.py`
- Modify: `tests/contracts/test_frozen_baseline.py` only for the closed
  suppression inventory and provenance assertions
- Modify: `contracts/baseline/manifest.json` only for a tested provenance
  refresh; `tool-catalog.json`, `resources.json`, `result-cases.json`, and
  `error-cases.json` must remain byte-identical
- Modify: `quality-baseline.json` only through the reviewed version-2 capture
  command when exact diagnostic identities change
- Modify: this implementation plan
- Create (ignored evidence):
  `.superpowers/sdd/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan/task-1-legacy-static-report.md`

No other source, test, quality-policy, baseline-payload, lock, package, CI, or
deployment path is authorized by Task 1B. If a direct caller outside this list
requires a change, stop and amend/re-review this file list first.

#### Interfaces and invariants

- Produce a frozen, slotted `ToolServiceDependencies` dataclass containing the
  repository, downloader, PDF, and store collaborators. `ToolService` consumes
  that bundle plus `AppConfig` and the optional typed UTC clock. The bundle is
  an internal object graph, not an untrusted serialization boundary, so it must
  not weaken Pydantic with `arbitrary_types_allowed=True`.
- Preserve the existing keyword-only construction semantics at every direct
  caller, the exact eight-tool catalog, all 66 replay outcomes, JSON-RPC status
  and error envelopes, resource-link order/deduplication, and the serialized
  PDF concurrency/cancellation behavior.
- Ruff-required Pydantic model docstrings must not add class-derived top-level
  `description` or `title` members to exported `inputSchema`. Remove only those
  two top-level presentation keys after `model_json_schema()` and prove the
  frozen catalog bytes remain unchanged; retain all field descriptions,
  constraints, and `additionalProperties: false` semantics.
- Rename the internal exception class to `ProtocolError` for `N818`, while
  retaining `ProtocolFailure = ProtocolError` as a compatibility alias until
  Task 14 deletes the custom protocol.
- The final JSON-RPC sanitizer deliberately catches `Exception` and deliberately
  uses `logger.error`, not `logger.exception`. Exactly two inline suppressions
  are permitted there: `BLE001` for the final fail-closed boundary and `TRY400`
  because exception messages/tracebacks can contain untrusted archival or
  application data. Each directive requires a three-line adjacent rationale,
  checker code, official Ruff rule URL, and exact closed-inventory entry.
  Moving, adding, removing, or changing either directive fails the inventory.
- Every touched Python file must finish with zero direct Ruff `ALL`
  diagnostics, Ruff-format clean, zero mypy strict diagnostics, and zero
  Pyright strict diagnostics. Do not hide inherited caller diagnostics by
  checking only the three leaf files, changing thresholds, adding another
  suppression, routing parameters through untyped `**kwargs`, or relying on a
  generated constructor solely to evade `PLR0913`.

- [ ] **Step 1: Record independent static and behavior RED evidence**

Run direct Ruff JSON, Ruff format, mypy, and Pyright commands over the exact
five-file source/test scope before editing production code. Record per-file and
per-rule counts and exact tool versions. Then run:

```bash
.venv/bin/python -m pytest -p no:cacheprovider \
  tests/unit/test_tools.py \
  tests/conformance/test_mcp_http.py \
  tests/unit/test_test_factories.py -q
```

The static commands must be RED for the recorded legacy diagnostics while the
behavior group is green. A parser/tool/environment failure is not an accepted
RED.

- [ ] **Step 2: Apply behavior-neutral mechanical cleanup**

One checker invariant at a time, add public docstrings, named exception
messages and printable-range constants; wrap long strings without changing
runtime bytes; encode the multiplication sign without changing the catalog;
use a project-relative non-temporary default in the test environment; and run
Ruff format. Add the top-level schema `description` removal in the same GREEN
slice as the Pydantic docstrings. A deliberate fault that omits that removal
must fail the byte-bound catalog assertion.

- [ ] **Step 3: Introduce the typed dependency bundle**

Add `ToolServiceDependencies`, update every direct caller in the authorized
files, and retain the clock/config behavior. Run the constructor/config/PDF
tests plus direct mypy and Pyright. As a temporary deliberate fault, cross-wire
the PDF and downloader fields in the otherwise type-clean runtime caller;
both type checkers must reject it. Restore the fault and rerun GREEN.

- [ ] **Step 4: Reduce protocol complexity incrementally**

Extract resource-link candidate construction/traversal, modern header versus
metadata validation, and method-specific dispatch as three separate refactors.
After each extraction, run its focused conformance nodes and the 66-case replay
before continuing. Do not change fixture payloads to accommodate a refactor.

- [ ] **Step 5: Inventory the intentional sanitizer suppressions**

Add only the reviewed `BLE001` and `TRY400` directives and extend the closed
tokenized suppression inventory. Run the existing unexpected-tool-error node.
Then temporarily replace `logger.error` with `logger.exception`; the sensitive
fixture canary must appear and the node must fail. Restore the secure call and
prove GREEN. Never retain the deliberate fault or a traceback-bearing log.

- [ ] **Step 6: Run layered static and behavioral proof**

Run direct Ruff `ALL`, Ruff format, mypy strict, and Pyright strict over every
touched Python file and require zero diagnostics. Then run the focused service,
conformance, shared-factory, frozen-baseline, complete Python, capability-Zod,
and baseline-Zod suites. Record exact commands, exit statuses, and counts.

- [ ] **Step 7: Reconcile the actual eight-command quality ratchet**

Run the repository's real eight-command quality gate without suppressing,
truncating, or treating parser failure as success. If line/path identities
changed, use only the reviewed version-2 capture path to refresh
`quality-baseline.json`; rerun the exact eight commands and record every
remaining inherited diagnostic rather than claiming project-wide zero.

- [ ] **Step 8: Refresh provenance last and review**

After all code, tests, plan, policy, and report text are final, run one tested
baseline `--write`, then repeated module and direct-script `--check` paths.
Require the four behavior payload files and the eight-tool catalog to remain
byte-identical while `manifest.json` changes only for the new input identity.
Verify the logical staged-entry digest and refs are unchanged, inspect the
scoped diff, write the ignored report, and request independent review. Do not
stage or commit without separate user authorization.

### Task 2: Generate the complete ASVS 5.0.0 L2 applicability matrix

#### Files

- Modify: `security/asvs/requirements-5.0.0.json` (transferred pinned source; bytes remain unchanged unless strict regeneration proves byte identity)
- Modify: `security/asvs/SHA256SUMS` (transferred pinned digest; bytes remain unchanged unless strict regeneration proves byte identity)
- Modify: `scripts/build_asvs_matrix.py`
- Modify: `docs/security/asvs-5.0.0-l2-method.md`
- Modify: `docs/security/asvs-evidence-policy.json`
- Modify: `docs/security/asvs-5.0.0-l2-matrix.jsonl`
- Modify: `docs/security/evidence-manifest.jsonl`
- Create: `docs/security/threat-model.json` (strict machine-readable threat ledger and render source)
- Modify: `docs/security/threat-model.md`
- Modify: `tests/static/test_asvs_evidence.py`
- Create: `tests/unit/test_build_asvs_matrix.py`
- Create: `tests/property/test_asvs_evidence.py`
- Create: `contracts/zod/asvs-evidence-contracts.mjs`
- Create: `tests/contracts/zod_asvs_evidence_contracts.test.mjs`
- Modify: `tests/contracts/zod_baseline_contracts.test.mjs` (exact package-script policy only, so the existing closed schema admits and mutation-tests the three Task 2 contract entrypoints)
- Modify: `scripts/baseline_capture_io.py`, `tests/contracts/test_frozen_baseline.py`, `contracts/zod/baseline-contracts.mjs` (bounded provenance repair only: expand Task 1's exact reviewed-untracked-input tuple from eight to thirteen paths so the five new Task 2 truth inputs are blob-bound)
- Modify: `package.json`, `tsconfig.contracts.json`, `eslint.config.mjs` (only as required to run the independent Zod 4.4.3 oracle)
- Create: `.superpowers/sdd/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan/task-2-report.md`
- Modify after every Task 2 source/config artifact is frozen: `contracts/baseline/manifest.json` (the Task 1 provenance manifest used by the live capture/check tooling), root `quality-baseline.json`

#### Interfaces

- Consumes: official ASVS JSON from immutable release tag `v5.0.0_release` at commit `5cf9b032440be53ce345ab3c130fda46ba1ce7a2`; the reviewed 149,407-byte artifact SHA-256 is `bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35`.
- Produces: `build_asvs_matrix.py fetch --output security/asvs/requirements-5.0.0.json`, a fail-closed fetcher whose URL contains that full commit rather than a tag. It permits HTTPS only, rejects redirects, credentials, proxies, non-GitHub hosts, non-200 status, compressed/deceptive transfer, and bodies outside the exact reviewed size; it verifies the reviewed SHA-256 before exclusively publishing a new no-symlink output and matching `SHA256SUMS` entry under one reader-visible transaction lock. No command reports success or leaves either new artifact behind unless both publications and the containing-directory sync succeed; rollback removes only the exact inode published by that transaction. The downloader and filesystem operations are injected in tests, so RED/GREEN never require the network.
- Produces: `build_asvs_matrix.py verify-ref`, which invokes exact argv `git ls-remote --refs https://github.com/OWASP/ASVS.git refs/tags/v5.0.0_release` with hooks, prompts, credentials, proxies, and user/system Git config disabled, a 30-second timeout, and a 4 KiB output ceiling; the sole accepted record is `5cf9b032440be53ce345ab3c130fda46ba1ce7a2\trefs/tags/v5.0.0_release`. The injected-runner tests reject no/multiple/malformed/abbreviated/changed refs, stderr, timeout, and nonzero exit.
- The fetch, Git, filesystem, custody, and approval boundaries return frozen typed results. Production Git uses one reviewed absolute regular executable, exact argv, an allowlisted environment rather than a filtered ambient environment, bounded byte capture with explicit completeness flags, timeout/cancellation and process-group/descendant cleanup. The fetch result binds the exact requested/final URL, status, headers, redirect count, body length, completion flag, and body bytes. Tests inject every boundary and remain offline until the adversarial suite is green.
- Every persisted Task 2 JSON/JSONL loader consumes bounded raw bytes and rejects non-bytes, invalid UTF-8, BOM, duplicate keys at any depth, non-finite numbers, unknown fields, noncanonical JSON bytes, blank JSONL records, CRLF, a missing final LF, excess line/record/file size, symlinks, special files, hard links, intermediate-directory escapes, and before/after descriptor identity change. Exact byte ceilings are: pinned source 149,407 bytes, `SHA256SUMS` 256 bytes, policy 2 MiB, matrix 2 MiB with exactly 759 records and at most 16 KiB per record, manifest 8 MiB with at most 4,096 records and 64 KiB per record, and threat-ledger JSON/Markdown 2 MiB each. Model fields additionally impose explicit tuple, string, nesting, selector, and identifier bounds. Local files are opened by descriptor through a no-follow walk beneath an already verified candidate root and are never reopened by pathname. Publication is exclusive and fail-closed; a typed injected transaction proves short-write, collision, link/rename, fsync, rollback, and identity-race behavior without overwriting an existing artifact.
- Produces: `load_pinned_asvs_requirements() -> tuple[AsvsRequirement, ...]`, `load_evidence_matrix() -> tuple[EvidenceRow, ...]`, `load_evidence_manifest() -> tuple[LocalEvidenceReference | CustodiedEvidenceReference, ...]`, `verify_evidence_reference(reference, *, context: EvidenceVerificationContext) -> bool`, and exactly 253 L1+L2 rows for each deployment profile. The frozen context is produced only after the candidate revision/tree/root identity has been verified; callers cannot supply an unbound revision string as sufficient authority.
- `asvs_source_commit` names only the pinned OWASP source revision. `evidence_revision` names the assessed NPLG candidate and is paired with its independently verified candidate tree/projection identity; neither value may stand in for the other. Local evidence verification binds the open descriptor, digest, selectors, candidate revision/tree, requirement, profile, invariant, and covered surface before and after verification. Verifier text is inert data selected only through a closed typed registry.
- The initial all-`Not assessed` inventory records the pre-Task-2 assessment baseline commit `da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0` and SHA-256 of its canonical `git ls-tree -rz --full-tree` bytes, `f50987fe97ed12a0da3295929e2ef8dba94693389a0a3bec2b2458a9f87aa32c`. These immutable audit-subject values are not compared to a future live HEAD and are not release evidence; any future evidence-bearing assessment must deliberately regenerate against its separately verified candidate revision/tree.
- `EvidenceRow` is the strict discriminator `ApplicableEvidenceRow | NotApplicableEvidenceRow`, keyed by `applicability`; it is never two independent applicability/verdict strings. Shared fields are `asvs_version, requirement_id, level, requirement_text, profile, invariant, threat_boundary, required_evidence_kinds, evidence_ids, owner, target_phase, evidence_revision, evidence_date`. `ApplicableEvidenceRow(applicability=Literal["applicable"], applicability_rationale, verdict=Literal["Not assessed", "Fail", "Partial", "Pass", "Risk accepted"], ...)` forbids `N/A` and permits risk fields only for `Risk accepted`. `NotApplicableEvidenceRow(applicability=Literal["not_applicable"], verdict=Literal["N/A"], applicability_rationale, applicability_reviewer, applicability_review_due, absence_evidence_ids)` requires revision/profile-bound absence evidence and structurally forbids every risk/compensating-control/release-approval field. Unknown or contradictory states cannot be loaded or serialized.
- Evidence is a strict discriminated union, never a bag-shaped path-or-URI plus executable text. Shared fields are `evidence_id, kind, requirement_ids, profiles, asserted_invariant, covered_surface, selectors, sha256, result, evidence_revision, candidate_tree_sha256, deployment_id, image_digest, collected_at, reviewer, expires_at`. `LocalEvidenceReference(storage="local", artifact_path: CanonicalRepoRelativePath, verifier: Literal["sha256-file-v1", "json-record-v1", "test-report-v1", "config-symbol-v1"])` resolves only beneath the verified expected revision by descriptor, rejects absolute/empty/dot-dot/backslash/control paths, symlinks/specials/hard-link replacement and before/after inode/digest change, and never reopens by name after validation. `CustodiedEvidenceReference(storage="custodied-uri", immutable_artifact_uri: ApprovedImmutableArtifactUri, artifact_object_version, custody_receipt_id, verifier: Literal["ci-custody-v1"])` is verified only through Task 22's trusted receipt/authority registry; the matrix verifier never fetches an arbitrary URI. Allowed kinds are `design`, `code_config`, `test`, and `operational`; `selectors` are exact test node IDs, configuration/code symbols, or operation/evidence record IDs rather than prose-only labels. Verifier values dispatch through one closed function registry and are never shell, module, URL, or expression text.
- The independently loaded evidence policy contains one exact, canonically sorted strict record for every one of the 759 requirement/profile claims; a matrix row may never weaken its required kinds or absence proof. Each record explicitly declares whether `Pass`, `N/A`, or `Risk accepted` is eligible. Initially none is eligible and all rows remain `Not assessed`, avoiding fabricated evidence-kind assignments. Custody receipts bind an allowlisted authority, immutable URI and object version, proof digest, exact candidate/profile/requirement/risk subject, issuance/expiry and nonce. Reverification of the identical immutable subject may be idempotent; nonce reuse for any different subject is replay and fails. Unknown authorities, mutable/rebound subjects, redirects, or locally self-authored approval artifacts fail without URI retrieval.
- Task 2 expands Task 1's exact reviewed-untracked-input admission tuple from eight to thirteen paths by adding only `contracts/zod/asvs-evidence-contracts.mjs`, `docs/security/threat-model.json`, `tests/contracts/zod_asvs_evidence_contracts.test.mjs`, `tests/property/test_asvs_evidence.py`, and `tests/unit/test_build_asvs_matrix.py`. Python and independent Zod require this exact canonically sorted tuple and prove every declared file's mode, identity, size, bytes, and Git blob in the synthetic input tree; unrelated untracked discovery remains forbidden. The Task 2 report is deliberately excluded because it records the resulting manifest identity and including it would make that provenance claim self-referential.
- `ReleaseDecision` is a strict typed result. A public decision requires every applicable row to be independently verified `Pass` and every N/A row to have valid absence evidence. A private/staging decision containing `Risk accepted` can only be `do_not_release`; it still requires an externally approved immutable authority artifact. The repository configures no authority in Task 2, so every risk acceptance and release decision remains externally ineligible.
- The independent Zod 4.4.3 oracle reads raw bytes separately from Python and enforces the same discriminators, exact fields, canonical encodings, ordering, uniqueness, product counts, policy bindings, custody shapes, and release-ineligibility defaults. Python-produced schemas are not imported or translated into the Zod oracle.
- `docs/security/threat-model.json` is a strict, canonical, bounded ledger with stable threat IDs, DFD nodes and directed edges, trust-boundary crossings, privileges, assets/data classes, every STRIDE category, abuse/misuse cases, affected profiles, mitigations, verification selectors, mapped ASVS requirement IDs, assumed provider controls, residual-risk owner, review date, and invalidation triggers. `threat-model.md` is deterministically rendered from that ledger; tests reject missing required flows/categories/owners/mappings and any render drift.

- [ ] **Step 1: Write the failing matrix-policy tests**

```python
def test_every_l1_l2_requirement_exists_for_every_profile() -> None:
    requirements = load_pinned_asvs_requirements()
    matrix = load_evidence_matrix()
    expected = {
        (item.identifier, profile)
        for item in requirements
        if item.level <= 2
        for profile in ("alpic-metadata", "private-full", "distributed-full")
    }
    actual = [(row.requirement_id, row.profile) for row in matrix]
    assert len(actual) == 253 * 3
    assert len(actual) == len(set(actual))
    assert set(actual) == expected
    assert all(row.asvs_version == "5.0.0" for row in matrix)
    assert all(row.requirement_id.startswith("v5.0.0-") for row in matrix)

def test_na_and_pass_verdicts_have_required_evidence() -> None:
    official = {item.identifier: item for item in load_pinned_asvs_requirements()}
    manifest = load_evidence_manifest()
    evidence = {item.evidence_id: item for item in manifest}
    assert len(evidence) == len(manifest)
    policy = load_independent_evidence_policy()
    for row in load_evidence_matrix():
        source = official[row.requirement_id]
        assert (row.requirement_text, row.level) == (source.text, source.level)
        if row.verdict == "Pass":
            references = [evidence[evidence_id] for evidence_id in row.evidence_ids]
            required = policy.required_kinds(row.requirement_id, row.profile)
            assert set(row.required_evidence_kinds) == required
            assert {item.kind for item in references} >= required
            assert all(row.requirement_id in item.requirement_ids for item in references)
            assert all(row.profile in item.profiles for item in references)
            assert all(item.asserted_invariant == row.invariant for item in references)
            assert all(item.selectors for item in references)
            assert all(policy.verify_claim_binding(row, item) for item in references)
            assert all(verify_evidence_reference(item, expected_revision=row.evidence_revision) for item in references)
        if row.verdict == "N/A":
            assert row.applicability_rationale
            assert row.applicability_reviewer
            assert row.applicability_review_due
            assert policy.verify_absence_evidence(row, evidence)
            assert row.risk_id is None
        if row.verdict == "Risk accepted":
            assert all(
                (
                    row.risk_id,
                    row.risk_owner,
                    row.risk_approver,
                    row.residual_risk,
                    row.compensating_controls,
                    row.risk_expiry,
                    row.release_approval_evidence_id,
                )
            )
            assert policy.verify_release_approval(
                row,
                evidence[row.release_approval_evidence_id],
            )
```

Add a table-driven legal-state test over the full Cartesian product of both `applicability` values and every verdict. It must accept only the union branches above; reject `applicable + N/A`, `not_applicable + Pass|Fail|Partial|Not assessed|Risk accepted`, risk fields on `N/A`, N/A-review/absence fields on applicable rows, missing absence evidence, expired review, unknown fields, and serialization that drops the discriminator. Mutate the discriminator, verdict, and conditional field-forbidding validators independently and require every mutant to fail.

Add unit cases for the fetch and ref-verification subcommands using injected responses/runners: exact artifact/ref succeeds; tag/mutable URL, changed/multiple/malformed ref, redirect, proxy use, wrong host/status/length/digest, oversized/chunk-overflow body, preexisting/symlink output, partial write, link/fsync/cleanup failure, and inode replacement all fail without publishing either artifact. A static assertion fixes the full-commit URL, byte length, reviewed digest, and exact tag record above.

Add evidence-reference adversarial cases independently: local absolute/dot-dot/empty/control/backslash paths, symlink/hard-link/special file, descriptor/path swap, digest/expected-revision drift, unknown verifier, and verifier strings containing shell/module syntax all fail without executing text. Custodied references reject `file:`, `data:`, plain HTTP, userinfo, fragments, private/loopback/link-local hosts, redirects/rebinding, mutable URLs, missing/wrong object versions, unknown authority, replayed/wrong-subject receipts, and attempts to downgrade them to local verification. A positive URI case verifies a signed/versioned receipt through an injected allowlisted authority without network access in the unit test.

The behavior-free scaffold and its initial `NotImplementedError` RED occurred before the Task 2 snapshot was transferred into MAIN. Do not destroy working transferred artifacts to replay that historical chronology. In MAIN, first characterize the live snapshot, preserve the correct 759 all-`Not assessed` rows and pinned source bytes, and persist one adversarial RED per reproduced boundary before changing its production implementation.

- [ ] **Step 2: Run the policy tests and observe RED**

Run: `.venv/bin/python -m pytest --collect-only tests/static/test_asvs_evidence.py -q`
Run: `.venv/bin/python -m pytest tests/static/test_asvs_evidence.py -q`
Expected for the transferred MAIN snapshot: collection/imports PASS; the first audit records substantive behavior/policy failures rather than missing imports. The observed starting snapshot had the correct pinned source and 759 all-`Not assessed` rows, but `--check` was absent, evidence-policy tests were vacuous, and direct Task 2 static gates were nonzero. Each subsequent local/custody/root-binding, downloader/Git/publication, canonical-loader, threat-semantic, Python/Zod-parity, and suppression-inventory defect must be reproduced by a persistent focused test before its GREEN. A missing module/import/fixture/executable remains the wrong RED.

- [ ] **Step 3: Pin the primary source and generate non-overclaiming rows**

Run the tested exact tag-to-commit check, then fetch only [the official machine-readable ASVS 5.0.0 release JSON at the immutable commit](https://raw.githubusercontent.com/OWASP/ASVS/5cf9b032440be53ce345ab3c130fda46ba1ce7a2/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json) through the tested subcommand. Do not compute a new digest and treat it as trust; require the pre-reviewed byte length and SHA-256 declared in the interface before checking both files in. Assert the source contains exactly 70 L1 plus 183 L2 requirements before generating the three profile matrices. Initialize applicable rows to `Not assessed` or `Fail`; never turn missing work into `N/A`.

Create a separately reviewed evidence-policy map that matrix rows cannot weaken: implemented runtime controls require code/config and test evidence, deployment-dependent controls also require operational evidence, and `N/A` requires revision/profile-bound proof that the route, capability, component, or data class is absent. Evidence IDs must be globally unique. Every reference must bind the exact requirement ID, deployment profile, asserted invariant, covered surface, and executable test/config/operation selectors; the verifier rejects cross-row/profile reuse unless the reference explicitly names each claim and independently satisfies each row. References must exist, match their digest, report a successful verification result, align with the row's immutable revision, and resolve selectors against collected test node IDs, named source/config symbols, or typed operational records. Documentation-only requirements declare only evidence kinds that genuinely apply; they do not receive fabricated code links. Document invalidation triggers for protocol, auth, dependency, runtime, storage, or deployment changes.

`verify_release_approval` never accepts a truthy matrix field or a locally authored report as authority. It requires a distinct operational evidence reference whose typed artifact is bound to the exact risk IDs, profile, candidate commit/tree, candidate-bundle digest, attestation commit, decision, approver authority/subject, unique nonce, issuance/expiry, and proof digest, and whose configured external verification method proves that authority. This plan deliberately selects no signing/protected-environment authority on the user's behalf: until a separately approved authority/verifier policy and immutable approval artifact exist, every `Risk accepted` row remains ineligible. Even a verified approval artifact is evidence consumed by the local eligibility gate, not permission for Codex or the script to deploy/release.

The threat model inventories assets/data classes, actors, entry points, privileges, and trust boundaries for external client → Alpic edge → Python backend → NPLG/JWKS and, in full profile, scanner → content store → PDF worker. Include data-flow diagrams, STRIDE-style threats plus abuse/misuse cases, token/session/confused-deputy paths, SSRF/DNS/proxy paths, parser/resource-exhaustion paths, supply-chain/build/deploy paths, logging/privacy risks, assumed provider controls, and residual-risk owners. Map each mitigation and verification to ASVS rows and update the model when a boundary/profile changes.

- [ ] **Step 4: Run generation and integrity checks**

Run: `.venv/bin/python scripts/build_asvs_matrix.py verify-ref`
Run: `.venv/bin/python scripts/build_asvs_matrix.py --check`
Run: `.venv/bin/python -m pytest tests/static/test_asvs_evidence.py -q`
Run: `.venv/bin/ruff check scripts/build_asvs_matrix.py tests/static/test_asvs_evidence.py tests/unit/test_build_asvs_matrix.py tests/property/test_asvs_evidence.py`
Run: `.venv/bin/ruff format --check scripts/build_asvs_matrix.py tests/static/test_asvs_evidence.py tests/unit/test_build_asvs_matrix.py tests/property/test_asvs_evidence.py`
Run: `.venv/bin/mypy --strict scripts/build_asvs_matrix.py tests/static/test_asvs_evidence.py tests/unit/test_build_asvs_matrix.py tests/property/test_asvs_evidence.py`
Run: `.venv/bin/pyright scripts/build_asvs_matrix.py tests/static/test_asvs_evidence.py tests/unit/test_build_asvs_matrix.py tests/property/test_asvs_evidence.py`
Run: `npm run test:contracts:asvs && npm run typecheck:contracts && npm run lint:contracts`
Expected: all PASS with zero Task 2 diagnostics. The exclusive `fetch` publication occurred exactly once in Step 3; `--check` revalidates the checked-in source length/digest, policy, manifest, threat ledger/render, and regenerates the matrix in memory, proving byte identity without trying to overwrite the deliberately preexisting pinned source. Capture before/after hashes for every Task 2 artifact and prove `--check` performs zero writes. Remove all Task 2 identities from the quality baseline rather than rebaselining those diagnostics.

- [ ] **Step 5: Commit checkpoint**

After explicit authorization, use the mandatory checkpoint protocol with a literal `task_paths=(...)` containing every exact Task 2 `Create`/`Modify` path and `TASK_COMMIT_MESSAGE="docs: establish ASVS L2 evidence inventory"`; directory entries and bare `git add`/`git commit` commands are forbidden.

**Phase 0 exit gate:** frozen fixtures are deterministic, the ADR is normative, compatibility PDF execution is serialized, all ASVS L1/L2 rows exist for every profile, and no row overclaims `Pass`.

---

## Phase 1 — Strict Quality Gates and CI

### Task 3: Add exact-pinned strict tooling with a temporary no-regression ratchet

#### Files

- Modify: `.gitignore`
- Modify: `pyproject.toml`
- Modify: `tests/conftest.py`, `tests/unit/test_quality_gate.py`
- Modify: `requirements-dev.in`, `requirements-dev.lock`, `package.json`, `package-lock.json`
- Create: `pyrightconfig.json`
- Create: `quality-baseline.json`
- Modify: `scripts/bootstrap_toolchain.py` (strict-type spillover only: the
  quality runner imports its lock validator, so mypy must traverse this module;
  no bootstrap behavior or accepted lock semantics may change)
- Create: `scripts/quality_ratchet.py`, `scripts/run_quality_gate.py`
- Create: `scripts/__init__.py`
- Create: `tests/unit/test_quality_ratchet.py`, `tests/unit/test_quality_gate.py`
- Create: `tests/property/test_quality_ratchet.py`
- Create: `tests/static/test_quality_policy.py`
- Create: `contracts/zod/quality-baseline-contracts.mjs`, `tests/contracts/zod_quality_baseline_contracts.test.mjs`
- Modify: `eslint.config.mjs`, `tsconfig.contracts.json`
- Modify: `tests/__init__.py`, `tests/helpers/__init__.py`
- Create: `tests/conformance/__init__.py`, `tests/contracts/__init__.py`, `tests/deployment/__init__.py`, `tests/integration/__init__.py`, `tests/property/__init__.py`, `tests/security/__init__.py`, `tests/static/__init__.py`, `tests/unit/__init__.py`
- Create: `.github/workflows/ci.yml`
- Modify: `scripts/baseline_capture_io.py`, `tests/contracts/test_frozen_baseline.py`, `contracts/baseline/manifest.json`
- Modify, format-only to close the non-baselinable Ruff precheck:
  `src/nplg_mcp/capabilities.py`, `src/nplg_mcp/protocol.py`,
  `tests/unit/test_bootstrap_toolchain.py`, `tests/unit/test_tools.py`
- Create: `.superpowers/sdd/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan/task-3-quality-ratchet-report.md`

The 2026-08-16 repair of this already-partial Task 3 is limited to the paths
listed above plus this plan and `quality-baseline.json`. The newly listed
`scripts/bootstrap_toolchain.py` scope is limited to the nine strict-mypy
diagnostics reached through the runner's existing lock-validator import. It
must not clean or
rebaseline unrelated legacy diagnostics. Adding the two dedicated quality
baseline Zod files expanded Task 1's closed synthetic-index admission contract
from six to the then-current exact sorted eight-path tuple; Task 2 subsequently
expands it to the normative thirteen-path tuple stated in Task 1. No wildcard
or other untracked discovery is authorized. Because these inputs change the frozen
capture tree, the final green repair must refresh only provenance-bound baseline
artifacts using the tested Task 1 writer/checker and must preserve fixture
payloads, staged entries, refs, and pre-existing object bytes.
The first real eight-command capture reproduced four pre-existing Ruff-format
failures in the exact files named above. Because format failures cannot be
represented safely as diagnostic identities, this repair may apply only Ruff's
deterministic formatter to those four paths, prove their behavior unchanged,
and refresh provenance again; no lint/type finding in them is otherwise in
scope for cleanup.

#### Interfaces

- Produces: `quality_ratchet.py check --base quality-baseline.json --input current-diagnostics.json`, returning non-zero for a new diagnostic or a higher exact identity count, and `run_quality_gate.py --node-executable ABSOLUTE [--ratchet BASELINE | --write-baseline BASELINE] [--worktree ROOT --cache-dir EXTERNAL_DIR] [--self-test] [PATH ...]`, the only scoped/global Ruff, format, Pyright, and mypy entry point. The Node argument is mandatory for a real gate run, must resolve to the exact regular executable and SHA-256 recorded by the accepted platform entry in `security/bootstrap-toolchain-lock.json`, and must report exactly `v24.19.0`; the runner invokes the repository's regular `node_modules/pyright/index.js` through that executable instead of trusting the package's `#!/usr/bin/env node` launcher or ambient `PATH`. Omitting the standalone ratchet input, supplying an empty diagnostics input after a diagnostic tool exit, or allowing a baseline filename to be consumed as a positional source path fails closed. In ordinary developer mode it permits a dirty but stable worktree, fingerprints every checked source/config byte before and after, uses a private external temporary cache root, and fails on source mutation. Release mode requires `--worktree`, a new canonical external cache directory outside every registered worktree, `--require-clean`, and `--candidate COMMIT`; it verifies exact HEAD/cleanliness and routes Ruff, mypy, Pyright, Python bytecode, and temporary output outside source. Baseline capture is a developer publication step: combining `--write-baseline` with release mode fails during argument validation, before any Git query, tool execution, or filesystem publication, so a tracked baseline cannot be written after the final clean-state check. Tests cover relative/preexisting/symlink/contained caches, dirty-release rejection, release/capture option permutations, source mutation, and tool cache leakage.

Cache admission obtains the complete registered set with the reviewed absolute
Git executable and bounded `git worktree list --porcelain -z` bytes before
creating the cache. Its strict parser accepts only the documented NUL-delimited
records, rejects malformed/duplicate/missing/noncanonical worktree paths, and
rejects lexical or canonical cache containment/aliasing against every listed
root, including sibling worktrees.

Release cleanliness is an inner execution invariant, not only an outer CLI
preflight. The validated clean-status evidence is rechecked immediately before
tool execution and after every tool returns; an unstaged or untracked race after
the outer check, or tool-created dirt outside the selected source paths, fails
even when `HEAD`, index entries, refs, and selected-byte fingerprints remain
unchanged.

The diagnostic boundary is machine data only: Ruff 0.16.3 uses one bounded
UTF-8 JSON array from `--output-format json`; Pyright 1.1.413 uses one bounded
UTF-8 JSON object from `--outputjson`; mypy 2.3.1 uses bounded UTF-8 JSON Lines
from `--output json --no-error-summary`. Duplicate object keys, duplicate
diagnostic identities, invalid UTF-8, extra/missing fields, malformed/truncated
records, noncanonical severity/code/location values, output overflow, timeout,
signal exit, and exit/status/count/summary disagreement all fail. Ruff and mypy
must emit zero stderr bytes; the pinned Pyright may emit only bounded ASCII
whitespace and no other stderr byte. Strict frozen Pydantic models with
`extra="forbid"` validate the exact observed record/envelope shapes, and an
independent Zod 4.4.3 oracle rejects the same adversarial corpus.

`quality-baseline.json` schema version 2 contains an exact ordered scope, the
exact ordered Python-target tuple `("3.12", "3.13", "3.14")`, tool name and exact version, config and lock paths plus SHA-256,
capture provenance, and a list of positive-count diagnostic records. Each
diagnostic identity is exactly `(tool, version, python_target, rule, path, line,
normalized_message_sha256)`; arbitrary string keys, zero/negative counts,
duplicates, missing version metadata, and stale config/lock/generator hashes
fail. A tracked baseline may not require live equality with the commit or full
index that contains that same baseline: such provenance is self-referential and
cannot survive staging or publication. The runner retains exact full
`HEAD`/index/ref snapshots for release validation and before/after mutation
detection, while persisted baseline provenance binds a canonical staged-entry
projection that excludes only `quality-baseline.json`, records that closed
policy as the exact one-element tuple
`staged_entries_projection_excluded_paths=["quality-baseline.json"]`, and binds
the exact source/config/lock/generator fingerprint. Python/Pydantic and the
independent Zod oracle reject an empty tuple, a different path, or any second
excluded path. Copying a baseline between materially different staged/source
states therefore fails without making the artifact impossible to commit. Tests
simulate replacing/staging the baseline blob and prove the excluded projection
is stable, while a staged source-entry mutation fails. Commit/ref identity
belongs to an external post-commit release
attestation, not this self-contained tracked artifact. The immutable runner
invokes only reviewed absolute executables without a
shell, uses a closed environment, fixed deadline and byte ceilings, and kills
and reaps the whole process group including descendants on every timeout,
overflow, cancellation, or parser failure. Its self-test uses only external
temporary files/caches, proves a Ruff-only false-green and a strict-type
false-green are rejected, removes its temporary state, and proves checked
repository bytes did not change.

No baseline write is permitted until the parser, executor, schema, property,
Zod, CLI, and self-test RED cases are green. `--write-baseline` then writes one
canonical schema-v2 baseline from the same validated machine records; it never
copies a prior total or accepts an unparsed diagnostic. Baseline capture and
ratchet comparison share the same parser and identity constructor.
Because `quality-baseline.json` is itself part of Task 1's synthetic-index input
tree, publishing schema v2 intentionally makes the earlier Task 1 manifest
provenance stale. After the quality artifact passes its independent Zod oracle
and an immediate ratchet replay, perform one final Task 1 provenance-only
refresh with the fixture/index/ref/pre-existing-object preservation proof, then
rerun both baseline check modes, all Zod tests, and the quality ratchet. This
final refresh changes no quality-runner source/config/lock input and therefore
must not invalidate the captured quality baseline.

- [ ] **Step 1: Write the failing policy test**

First create typed behavior-free ratchet/quality-runner scaffolds with immutable command/result records, injected argv executor, filesystem/snapshot/cache protocols, and parser seams. Their target check/run methods deliberately raise `NotImplementedError`; importing the modules has no execution side effects. Independent unit tests cover malformed/duplicate baseline entries, normalized-diagnostic identity drift, new/higher/removed diagnostics, tool nonzero/timeout/signal/output overflow, wrong tool version, cache path relative/preexisting/symlink/contained under any NUL-enumerated worktree, dirty release candidate, candidate/HEAD mismatch, source/ignored-cache mutation, cleanup/partial output, and exact propagation/order of Ruff format/check, Pyright, and mypy. The runners' own `--self-test` is diagnostic convenience, never their authority.

```python
def test_quality_configuration_is_maximally_strict() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    pyright = json.loads(Path("pyrightconfig.json").read_text(encoding="utf-8"))
    assert pyproject["tool"]["ruff"]["lint"]["select"] == ["ALL"]
    assert pyproject["tool"]["ruff"]["lint"]["flake8-copyright"] == {
        "notice-rgx": r"Copyright \(c\) 2026 David Osipov",
        "min-file-size": 0,
    }
    assert pyproject["tool"]["ruff"]["lint"]["per-file-ignores"] == {
        "tests/**/*.py": ["D102", "D103", "S101"],
    }
    assert pyright["typeCheckingMode"] == "strict"
    for diagnostic in (
        "reportCallInDefaultInitializer",
        "reportImplicitOverride",
        "reportImplicitStringConcatenation",
        "reportImportCycles",
        "reportMissingModuleSource",
        "reportMissingSuperCall",
        "reportPropertyTypeMismatch",
        "reportUninitializedInstanceVariable",
        "reportUnnecessaryTypeIgnoreComment",
        "reportUnreachable",
        "reportUnusedCallResult",
    ):
        assert pyright[diagnostic] == "error"
    assert pyproject["tool"]["mypy"]["strict"] is True
    for option in (
        "disallow_any_decorated",
        "disallow_any_explicit",
        "disallow_any_expr",
        "disallow_any_unimported",
    ):
        assert pyproject["tool"]["mypy"][option] is True
    assert set(pyproject["tool"]["mypy"]["enable_error_code"]) == {
        "comparison-overlap",
        "deprecated",
        "exhaustive-match",
        "explicit-any",
        "explicit-override",
        "ignore-without-code",
        "mutable-override",
        "no-any-return",
        "no-any-unimported",
        "no-untyped-call",
        "no-untyped-def",
        "possibly-undefined",
        "redundant-cast",
        "redundant-expr",
        "redundant-self",
        "truthy-bool",
        "truthy-iterable",
        "type-arg",
        "unimported-reveal",
        "unreachable",
        "untyped-decorator",
        "unused-awaitable",
        "unused-ignore",
    }
    assert pyproject["tool"]["mypy"]["plugins"] == ["pydantic.mypy"]
    assert pyproject["tool"]["pydantic-mypy"] == {
        "init_forbid_extra": True,
        "init_typed": True,
        "warn_required_dynamic_aliases": True,
    }
    assert pyright["include"] == ["src", "tests", "scripts", "typings"]
    assert pyproject["tool"]["coverage"]["run"]["branch"] is True
    assert pyproject["tool"]["coverage"]["report"]["fail_under"] == 95
```

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest --collect-only tests/unit/test_quality_ratchet.py tests/unit/test_quality_gate.py tests/static/test_quality_policy.py -q`
Run: `.venv/bin/python -m pytest tests/unit/test_quality_ratchet.py tests/unit/test_quality_gate.py tests/static/test_quality_policy.py -q`
Expected: collection/imports PASS. Unit cases reach deliberate `NotImplementedError`, while the static test fails because Ruff, Pyright, mypy, and the 95% floor are not configured; no missing module/fixture/tool is accepted as RED.

- [ ] **Step 3: Add strict configurations and locked tools**

Configure Ruff for the lowest supported Python, `target-version = "py312"`, and `select = ["ALL"]`. Configure `[tool.ruff.lint.flake8-copyright]` with `notice-rgx = "Copyright \\(c\\) 2026 David Osipov"` and `min-file-size = 0`; `test_quality_policy.py` asserts that exact configuration, the exact header position, and the complete pre-Task-3 new-file/package-marker inventory named above. Ignore only mutually exclusive docstring rules plus Ruff 0.16.3's documented formatter conflicts: `COM812`, `COM819`, `D203`, `D213`, `D206`, `D300`, `E111`, `E114`, `E117`, `Q000`, `Q001`, `Q002`, `Q003`, `Q004`, and `W191`; every ignore is asserted and explained in `test_quality_policy.py`. Keep both `ISC001` and `ISC002` enabled and retain the default compatible implicit-concatenation setting; if the pinned formatter emits a conflict warning, stop and review rather than silently enlarging the ignore list. `run_quality_gate.py` treats any Ruff stdout/stderr warning as failure and proves `ruff format --check` is warning-free. The sole per-file mapping is `tests/**/*.py = ["D102", "D103", "S101"]`: pytest assertions are the test oracle, and exact descriptive test node names/parameter IDs replace formulaic method/function docstrings. `D100`, `D101`, `D104`, `PLR2004`, complexity rules, and `SLF001` remain enforced in tests; replace magic values with named constants, split complex tests, and expose a narrow test seam instead of accessing private members. No per-line suppression is accepted without its rule code, reason, and a static inventory assertion. Add the eight package markers named above so `INP001` is solved structurally. Give all ten test-package markers—including the existing empty `tests/__init__.py` and `tests/helpers/__init__.py`—a real module docstring and the exact reviewed notice so `D104` and `CPY001` are fixed rather than baselined; `test_quality_policy.py` asserts the exact marker inventory and notice format.

Configure Pyright `typeCheckingMode = "strict"`, `pythonVersion = "3.12"`, `include = ["src", "tests", "scripts", "typings"]`, `stubPath = "typings"`, `enableTypeIgnoreComments = false`, `reportMissingTypeStubs = "error"`, and no blanket ignore patterns. Strict mode is a preset, not a maximal guarantee: promote every non-error diagnostic in Pyright 1.1.413's official strict table—`reportMissingModuleSource`, `reportCallInDefaultInitializer`, `reportImplicitOverride`, `reportImplicitStringConcatenation`, `reportImportCycles`, `reportMissingSuperCall`, `reportPropertyTypeMismatch`, `reportUninitializedInstanceVariable`, `reportUnnecessaryTypeIgnoreComment`, `reportUnreachable`, and `reportUnusedCallResult`—to `"error"`. The static policy freezes that complete set and fails when a future Pyright version adds or changes a non-error strict diagnostic until it is reviewed. Use only official npm `pyright@1.1.413`; do not install or invoke the independently versioned PyPI wrapper.

Configure mypy `python_version = "3.12"`, `strict = true`, `extra_checks = true`, `strict_equality_for_none = true`, `strict_bytes = true`, `warn_unreachable = true`, `warn_unused_configs = true`, `incremental = false`, `disallow_any_generics = true`, `disallow_any_explicit = true`, `disallow_any_unimported = true`, `disallow_any_decorated = true`, `disallow_any_expr = true`, `plugins = ["pydantic.mypy"]`, and an exact `mypy_path = "typings:src"`. Freeze the complete mypy 2.3.1 optional-check catalogue, including checks already activated indirectly by `strict`, in `enable_error_code`: `comparison-overlap`, `deprecated`, `exhaustive-match`, `explicit-any`, `explicit-override`, `ignore-without-code`, `mutable-override`, `no-any-return`, `no-any-unimported`, `no-untyped-call`, `no-untyped-def`, `possibly-undefined`, `redundant-cast`, `redundant-expr`, `redundant-self`, `truthy-bool`, `truthy-iterable`, `type-arg`, `unimported-reveal`, `unreachable`, `untyped-decorator`, `unused-awaitable`, and `unused-ignore`; an unknown/removed code or a new catalogue code fails configuration review rather than being ignored. `[tool.pydantic-mypy]` enables `init_forbid_extra`, `init_typed`, and `warn_required_dynamic_aliases`. Ruff, Pyright, and mypy must receive or automatically add the `typings` root on every repository-wide invocation; mypy additionally retains `src` in its module search path, and a gate that omits either root fails its own static policy test. No `Any` annotation, alias, local, imported/decorated escape, `cast(Any, ...)`, or untyped adapter is permitted outside one exact AST-inventoried interoperability boundary with a typed `object` input and immediate strict validation; the preferred inventory is empty.

The quality runner executes both checkers against Python 3.12, 3.13, and 3.14 using generated external exact configs/CLI overrides while preserving every base rule; it fails if a version-specific branch or typeshed signature is unchecked. Negative fixtures prove missing module source, a call in a default initializer, implicit string concatenation, a missing super call, import cycles, implicit overrides, uninitialized attributes, unreachable or redundant expressions, redundant casts and `Self`, discarded awaitables, unused call results, unimported `reveal_type`, explicit/aliased/imported/decorated `Any`, `cast(Any, ...)`, non-exhaustive matches, unsafe mutable overrides, possibly undefined names, truthy-only protocols, a misspelled/unused mypy override, `# type: ignore` without a code, an unnecessary coded ignore, and `# pyright: ignore` cannot silently bypass the gate. Any narrowly unavoidable suppression must name its checker code, rationale, upstream issue, and exact path/line in one closed static inventory; an uninventoryed, moved, unnecessary, or blanket suppression fails. Regenerate the exact/hash-locked Python and npm locks after every input change.

Re-run the exact pinned tools and record the diagnostic identity `(tool, version, rule/code, path, line, normalized message digest)` in `quality-baseline.json`, not only aggregate counts. The frozen checkout's discovery numbers are 2,377 Ruff and a historical Pyright 1.1.412 count of 539 errors; the 1.1.413 pin, stricter diagnostics, Task 0 files, and package markers require a fresh baseline, not a numerical delta assumption. Every changed diagnostic requires an explicit disposition and newly created files must be clean. Never copy the old totals to manufacture a matching baseline. The ratchet may suppress only individually recorded legacy diagnostics and is deleted in Task 6C.

Create bootstrap `ci.yml` with least-privilege permissions, full-SHA Action pins, hash-locked installation, the unchanged 254-test baseline, frozen-contract checks, and `quality_ratchet.py`. Before Task 4 begins, obtain authorization to push this workflow and configure it as a required protected-`main` check; if that external gate cannot be established, stop broad refactoring.

- [ ] **Step 4: Verify policy and ratchet behavior**

Run: `.venv/bin/python -m pytest tests/unit/test_quality_ratchet.py tests/unit/test_quality_gate.py tests/static/test_quality_policy.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" --ratchet quality-baseline.json src tests scripts typings`
Run: `.venv/bin/python -m pytest tests/contracts/test_frozen_baseline.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" --self-test`
Expected: PASS. The self-test creates its own temporary, non-repository Python file containing one Ruff and one strict type diagnostic and proves both the ratchet and final-mode paths exit non-zero; it then deletes the temporary directory. The authorized remote required check passes before Task 4.

- [ ] **Step 5: Commit checkpoint**

Instantiate the mandatory NUL-safe checkpoint protocol with every exact Task 3 `Files` path—including `tests/unit/test_quality_ratchet.py` and `tests/unit/test_quality_gate.py`—and `TASK_COMMIT_MESSAGE="chore: add strict quality ratchet"`.

### Task 4: Make configuration and startup modules lint- and type-clean

#### Files

- Modify: `src/nplg_mcp/__init__.py`, `src/nplg_mcp/__main__.py`, `src/nplg_mcp/config.py`
- Modify: `tests/unit/test_config.py`, `tests/unit/test_main.py`
- Modify: `typings/pypdfium2/__init__.pyi`

#### Interfaces

- Preserves configuration defaults/startup behavior; produces fully typed environment parsing and a checked `main() -> int` boundary.
- The Task 4 edit to `typings/pypdfium2/__init__.pyi` is only the minimum
  provisional surface needed by this scoped gate. It does not satisfy or
  receive credit for Task 6A's exact pinned-wheel reflection contract.

- [ ] **Step 1: Run strict gates and record the expected RED diagnostics**

Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src/nplg_mcp/__init__.py src/nplg_mcp/__main__.py src/nplg_mcp/config.py tests/unit/test_config.py tests/unit/test_main.py`
Expected: non-zero with the audited legacy findings; save the rule/file inventory in the task notes.

- [ ] **Step 2: Add precise annotations and narrow boundary types**

Resolve every Ruff, format, Pyright, and mypy diagnostic in the named cluster, not only annotation findings. Type environment input as `Mapping[str, str]`, keep every numeric/bool bound explicit, make `build_default_app` and CLI exit types concrete, and reject unknown environment values exactly as the existing tests require. Do not add `type: ignore` unless it names a specific checker rule and has a linked upstream issue. If any repair would alter runtime behavior, add and observe a focused behavioral RED before that repair.

- [ ] **Step 3: Run focused behavior and strict checks**

Run: `.venv/bin/python -m pytest tests/unit/test_{config,main}.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src/nplg_mcp/__init__.py src/nplg_mcp/__main__.py src/nplg_mcp/config.py tests/unit/test_config.py tests/unit/test_main.py`
Expected: all PASS/exit 0 for the cluster.

- [ ] **Step 4: Run the full regression suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 254 or more tests PASS.

- [ ] **Step 5: Commit checkpoint**

Stage only this task's named source and test files, then: `git commit -m "refactor: type configuration and startup"`.

### Task 5: Make security primitives lint- and type-clean

#### Files

- Modify: `src/nplg_mcp/admission.py`, `src/nplg_mcp/errors.py`, `src/nplg_mcp/rate_limit.py`, `src/nplg_mcp/security.py`, `src/nplg_mcp/tokens.py`
- Modify: `tests/unit/test_admission.py`, `tests/unit/test_errors.py`, `tests/unit/test_rate_limit.py`
- Modify: `tests/security/test_security.py`, `tests/security/test_tokens.py`

#### Interfaces

- Preserves constant-time comparisons, token format, public errors, and admission behavior while eliminating unknown values and untyped decorators.
- Reject deprecated IPv6 site-local addresses in `fec0::/10` explicitly; Python
  3.13 can classify those reserved addresses as globally reachable.
- If an `AppError.safe_details` mapping contains a non-JSON value, a nonfinite
  number, or otherwise fails strict JSON validation, `to_public_error()` must
  fail closed to the stable generic `INTERNAL_ERROR` public value. It must not
  raise or expose the invalid details.
- Public-detail publication accepts only an exact built-in `dict` root, exact
  built-in `dict`/`list` containers, and exact `None`/`bool`/`int`/finite
  `float`/`str` scalars. It takes a detached, non-recursive snapshot without
  invoking user-defined mapping/container truth, iteration, item access, or
  serialization behavior. Reject cycles, container depth above 32 (root depth
  zero), more than 4,096 total values including the root, more than 65,536
  aggregate string code points including object keys, or integers above 256
  bits. Shared acyclic containers remain valid and are copied by value at each
  occurrence. Any rejection returns the exact generic `INTERNAL_ERROR`; an
  empty exact dictionary retains the existing omission of `details`.
- DNS-answer-to-TCP-connection pinning is not part of this task's file scope.
  Treat it as a Task 17 dependency requiring repository/downloader transport
  scope and dedicated connection-binding tests; pre-check-only DNS
  validation must not be represented as connection pinning.

- [ ] **Step 1: Run cluster strict gates and observe RED**

Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src/nplg_mcp/admission.py src/nplg_mcp/errors.py src/nplg_mcp/rate_limit.py src/nplg_mcp/security.py src/nplg_mcp/tokens.py tests/unit/test_admission.py tests/unit/test_errors.py tests/unit/test_rate_limit.py tests/security/test_security.py tests/security/test_tokens.py`
Expected: non-zero from existing diagnostics.

- [ ] **Step 2: Repair types without changing behavior**

Use `Mapping[str, object]` plus type guards for public details, concrete validator signatures for token claims, and typed async context-manager/admission results. Preserve safe error text and reject rather than coerce ambiguous values.

Before either reviewed behavioral security fix, add and observe its focused RED:
an adversarial resolver case for `fec0::/10`, and invalid `safe_details` cases
covering non-JSON values and nonfinite numbers. Apply the smallest repair only
after the corresponding RED fails for the intended reason. Preserve every
existing valid public error and valid public-details serialization.

Before hardening the complete `safe_details` boundary, add and observe focused
REDs for a cyclic exact container, depth/value/string/integer bound exhaustion,
a hostile top-level `Mapping`, a hostile nested container subclass, and a
shared acyclic container. Seed private exception sentinels and prove they never
escape or appear in the public result. Implement the bounded exact-built-in
snapshot directly; do not substitute a broad exception catch or checker
suppression.

- [ ] **Step 3: Run focused tests and strict gates**

Run: `.venv/bin/python -m pytest tests/unit/test_{admission,errors,rate_limit}.py tests/security/test_{security,tokens}.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src/nplg_mcp/admission.py src/nplg_mcp/errors.py src/nplg_mcp/rate_limit.py src/nplg_mcp/security.py src/nplg_mcp/tokens.py tests/unit/test_admission.py tests/unit/test_errors.py tests/unit/test_rate_limit.py tests/security/test_security.py tests/security/test_tokens.py`
Expected: PASS, followed by zero cluster lint/type/format diagnostics. Any runtime-affecting repair first receives its own focused behavioral RED.

- [ ] **Step 4: Run frozen-contract and full regressions**

Run: `.venv/bin/python -m pytest tests/contracts/test_frozen_baseline.py -q`
Run: `.venv/bin/python -m pytest -q`
Expected: PASS with unchanged baseline fixtures.

- [ ] **Step 5: Commit checkpoint**

Stage only the listed files, then: `git commit -m "refactor: type security primitives"`.

### Task 6: Make upstream parser and downloader modules lint- and type-clean

#### Files

- Modify: `src/nplg_mcp/downloader.py`, `src/nplg_mcp/http_types.py`, `src/nplg_mcp/parsers.py`, `src/nplg_mcp/repository.py`
- Modify: `tests/integration/test_repository.py`, `tests/security/test_downloader.py`, `tests/unit/test_parsers.py`

#### Interfaces

- Preserves bounded upstream behavior and parser outputs while making HTML/XML/HTTP boundaries project-typed.
- Preserves the pre-refactor accepted date language exactly: after whitespace
  normalization, dates accepted by `datetime.strptime` against
  `%d-%b-%Y`, `%Y-%m-%d`, or `%Y-%m-%dT%H:%M:%SZ` are normalized. Do not add a
  regex/full-match gate. This retains the interpreter's existing
  case-insensitive alphabetic matching and variable-width numeric directives,
  including `7-Aug-2025`, `2025-8-7`, and `2025-08-27t23:30:00z`.
  Offset-bearing timestamps remain unchanged unless a later behavioral task
  deliberately expands that contract.
- Public HTTP Protocol annotations remain runtime-resolvable through
  `typing.get_type_hints`; type-checker cleanup must not hide their referenced
  names behind `TYPE_CHECKING`. `HttpResponseProtocol` deliberately models the
  consumed response fields as read-only `property` descriptors: each getter's
  return annotation, together with the streaming method annotations, is the
  reflection contract. The class-level `get_type_hints(HttpResponseProtocol)`
  mapping is intentionally empty for this property-based contract; tests must
  assert descriptor kind and each getter's resolved return type rather than
  reconstructing writable data-member annotations.
- Type-clean HTTP client protocols do not bind a validated DNS answer to the
  TCP connection. Task 17 owns that transport behavior and its adversarial
  connection-binding proof; Task 6 must not claim it.
- Reconciliation retained this refactor because focused baseline/current
  behavior is equivalent and the seven-file strict gate is zero after the
  date/introspection repairs. Task 6 remains partial until the full regression,
  frozen provenance refresh, and independent final review are complete.

- [ ] **Step 1: Run the global strict commands and observe RED**

Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src/nplg_mcp/downloader.py src/nplg_mcp/http_types.py src/nplg_mcp/parsers.py src/nplg_mcp/repository.py tests/integration/test_repository.py tests/security/test_downloader.py tests/unit/test_parsers.py`

Expected: non-zero from existing upstream/parser diagnostics.

- [ ] **Step 2: Resolve every remaining finding**

Add the minimum typed `Protocol` boundary for HTTP response streaming and
typed parsed NPLG records; do not introduce an otherwise unused resolver
Protocol solely to satisfy a checker. Narrow Beautiful Soup/XML values before
use; preserve existing byte/text/node ceilings, accepted date formats, private
helper exception types, and error mapping.

- [ ] **Step 3: Run all strict gates**

Run: `.venv/bin/python -m pytest tests/unit/test_parsers.py tests/integration/test_repository.py tests/security/test_downloader.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src/nplg_mcp/downloader.py src/nplg_mcp/http_types.py src/nplg_mcp/parsers.py src/nplg_mcp/repository.py tests/integration/test_repository.py tests/security/test_downloader.py tests/unit/test_parsers.py`
Expected: PASS with zero diagnostics for this cluster.

- [ ] **Step 4: Run all tests**

Run: `.venv/bin/python -m pytest tests/contracts/test_frozen_baseline.py -q`
Run: `.venv/bin/python -m pytest -q`
Expected: all tests PASS and baseline results remain unchanged.

- [ ] **Step 5: Commit checkpoint**

Stage only the named upstream source/tests, then: `git commit -m "refactor: type upstream boundaries"`.

### Task 6A: Make storage and PDF modules lint- and type-clean

#### Files

- Modify: `src/nplg_mcp/storage.py`, `src/nplg_mcp/pdf.py`
- Modify: `pyproject.toml`, `pyrightconfig.json`
- Modify: `typings/pypdfium2/__init__.pyi`, `typings/pypdfium2/raw.pyi`
- Delete: `tests/unit/test_pdfium_stubs.py` after its replacement contract is
  observed RED and collects successfully
- Create: `tests/unit/test_pdfium_stub_contract.py`
- Modify: `tests/integration/test_pdf.py`, `tests/unit/test_storage.py`, `tests/unit/test_tiles.py`, `tests/helpers/pdf_factory.py`

#### Interfaces

- Preserves content IDs, atomic publication, render IDs, page classifications, dimensions, and manifest serialization.
- Produces the smallest exact project-owned `pypdfium2` stub surface used by `pdf.py`; every public stub symbol, callable parameter name/kind/default, return protocol, constant type, context/close behavior, page/object iteration, rendering, bitmap/Pillow conversion, and raised `PdfiumError` is runtime-reflection/smoke-tested against the exact pinned wheel without rewriting either compared signature. No uncalled vendor API is declared.
- Preserves the explicit keyword-only `PdfProcessor.__init__` compatibility
  signature used by `src/nplg_mcp/app.py`, `tests/helpers/app_factory.py`,
  `tests/integration/test_pdf.py`, and `scripts/delete_render.py`. Exactly one
  statement-local `# noqa: PLR0913` is authorized on that constructor, with an
  adjacent rationale naming these four surfaces: replacing the signature with
  a real immutable limits bundle is deferred because it crosses Task 6A and
  Task 6C scope. The pinned vendor signatures also require the builtin-shadowing
  public parameter names `PdfDocument(input=...)` and
  `PdfPage.get_objects(filter=...)`; renaming either is forbidden because it
  makes valid keyword calls lie. Exactly two statement-local `# noqa: A002`
  directives are authorized on those stub methods with adjacent pinned-vendor
  rationale. An executable regression fixes the exact parameter/default
  surfaces and rejects the prior `path` and `**kwargs` mutants. A closed
  inventory over every named Task 6A Python/stub file permits exactly these
  three directives, their owning methods, and rationales; any extra, moved,
  broadened, type-checker/security ignore, or formatter-disable directive is
  rejected.

- [ ] **Step 1: Run scoped strict gates and observe RED**

Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable /tmp/nplg-phase1-toolchain.sNv6IL/node/node-v24.19.0-linux-x64/bin/node src/nplg_mcp/storage.py src/nplg_mcp/pdf.py tests/integration/test_pdf.py tests/unit/test_storage.py tests/unit/test_tiles.py tests/helpers/pdf_factory.py`
Run: `.venv/bin/python -m pytest --collect-only tests/unit/test_pdfium_stub_contract.py -q`
Run: `.venv/bin/python -m pytest tests/unit/test_pdfium_stub_contract.py -q`
Expected: collection PASS; the stub-contract assertion and scoped strict gate
fail against the provisional/lying stub surface, not from an absent file,
untyped import, or setup failure. The old `test_pdfium_stubs.py` existence
smoke is insufficient and is removed only after this replacement RED exists.

- [ ] **Step 2: Add project-owned PDFium and filesystem boundary types**

Replace and narrow the provisional declarations in the two exact checked stub
files, plus typed PDFium adapter protocols at the import boundary, configure
only `typings/` as the Pyright `stubPath` and mypy path, narrow optional library
values, check every filesystem return, and retain existing dataclass output
types and limits. Delete `tests/unit/test_pdfium_stubs.py` only after the
replacement contract has collected successfully and its targeted behavioral
RED has been observed. The runtime contract test rejects a
lying/widened/stale stub before the type checker may trust it. Preserve the
explicit `PdfProcessor` constructor under the authorized PLR0913 compatibility
exception. Preserve the exact pinned-vendor `input` and `filter` names under
the two authorized A002 exceptions, and make the exact-signature/default,
unknown-keyword, prior-mutant, and closed suppression-inventory regressions
pass.

- [ ] **Step 3: Run focused tests and strict gates**

Run: `.venv/bin/python -m pytest tests/unit/test_pdfium_stub_contract.py tests/unit/test_storage.py tests/unit/test_tiles.py tests/integration/test_pdf.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable /tmp/nplg-phase1-toolchain.sNv6IL/node/node-v24.19.0-linux-x64/bin/node src/nplg_mcp/storage.py src/nplg_mcp/pdf.py tests/unit/test_pdfium_stub_contract.py tests/integration/test_pdf.py tests/unit/test_storage.py tests/unit/test_tiles.py tests/helpers/pdf_factory.py`
The gate appends the complete `typings/` root itself. Do not also pass
`typings/pypdfium2`: overlapping roots make mypy report the same stub module
twice and exit with configuration status 2 rather than running the gate.
Expected: PASS and zero scoped diagnostics.

- [ ] **Step 4: Run frozen and full regressions**

Run: `.venv/bin/python -m pytest tests/contracts/test_frozen_baseline.py -q`
Run: `.venv/bin/python -m pytest -q`
Expected: PASS with deterministic IDs/manifests unchanged.

- [ ] **Step 5: Commit checkpoint**

Stage only the named storage/PDF files, `pyproject.toml`, `pyrightconfig.json`, exact two stub files, stub-contract test, and other named tests, then: `git commit -m "refactor: type storage and PDF boundaries"`.

### Task 6B: Make service and custom transport modules lint- and type-clean

#### Files

- Verify only; modify only if the literal scoped gate reports a diagnostic:
  `src/nplg_mcp/tools.py`, `src/nplg_mcp/protocol.py`, `src/nplg_mcp/app.py`,
  `tests/unit/test_tools.py`
- Modify: `tests/conformance/test_mcp_http.py`

#### Interfaces

- Preserves the frozen tool catalog, wire cases, public errors, and application routes until the official SDK cutover.
- Task 1B already closed the direct static debt in `tools.py`, `protocol.py`,
  `app.py`, and `test_tools.py`. Task 6B is now a residual verification task:
  rerun the complete literal scope and change only files that still produce
  diagnostics. A green full-scope gate closes the task without further
  production edits.
- For this execution, set `REVIEWED_NODE` to
  `/tmp/nplg-phase1-toolchain.sNv6IL/node/node-v24.19.0-linux-x64/bin/node`.
  Before either strict gate, require version `v24.19.0` and SHA-256
  `bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12`;
  do not substitute an ambient `node` from `PATH`.

- [ ] **Step 1: Run scoped strict gates and observe RED**

Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$REVIEWED_NODE" src/nplg_mcp/tools.py src/nplg_mcp/protocol.py src/nplg_mcp/app.py tests/unit/test_tools.py tests/conformance/test_mcp_http.py`
Expected: record the actual residual diagnostics from the complete scope; do
not manufacture the historical `Any`/ignored-return RED. Current audit
evidence places remaining debt in `tests/conformance/test_mcp_http.py`, while
direct source/unit checks were already closed by Task 1B. If the full gate is
already green, record that result and proceed without a source edit.

- [ ] **Step 2: Narrow raw JSON and ASGI boundaries**

If residual diagnostics remain, keep `object`/`Mapping[str, object]` only at
JSON/ASGI entry points, add explicit type guards, and change only
`tests/conformance/test_mcp_http.py` unless the literal gate reports a
diagnostic elsewhere. Preserve private-boundary coverage through public
behavior rather than widening production APIs or adding suppressions. Do not
refactor already-green production files merely to replay the original ordering.

- [ ] **Step 3: Run focused tests and strict gates**

Run: `.venv/bin/python -m pytest tests/unit/test_tools.py tests/conformance/test_mcp_http.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$REVIEWED_NODE" src/nplg_mcp/tools.py src/nplg_mcp/protocol.py src/nplg_mcp/app.py tests/unit/test_tools.py tests/conformance/test_mcp_http.py`
Expected: PASS and zero scoped diagnostics.

- [ ] **Step 4: Run frozen and full regressions**

Run: `.venv/bin/python -m pytest tests/contracts/test_frozen_baseline.py -q`
Run: `.venv/bin/python -m pytest -q`
Expected: PASS with no baseline edits.

- [ ] **Step 5: Commit checkpoint**

Stage only service/transport/app and their tests, then: `git commit -m "refactor: type service and transport boundaries"`.

### Task 6C: Make scripts/static tests globally clean and remove the ratchet

#### Files

- Modify: `scripts/delete_render.py`, `scripts/smoke_live.py`, `scripts/verify_deploy.py`
- Modify: `tests/static/test_deployment.py`, `tests/static/test_skill.py`, `tests/unit/test_verify_deploy.py`
- Create: `tests/unit/test_delete_render.py`, `tests/unit/test_smoke_live.py`
- Modify, as proved by the fresh repository-wide direct gate: `src/nplg_mcp/json_types.py`, `scripts/bootstrap_toolchain.py`, `tests/unit/test_bootstrap_toolchain.py`, `tests/contracts/test_oauth_provider_capability.py`, `tests/conftest.py`
- Modify: `scripts/run_quality_gate.py`, `tests/unit/test_quality_gate.py`
- Delete: `quality-baseline.json`, `scripts/quality_ratchet.py`, `tests/unit/test_quality_ratchet.py`, `tests/property/test_quality_ratchet.py`
- Delete: `contracts/zod/quality-baseline-contracts.mjs`, `tests/contracts/zod_quality_baseline_contracts.test.mjs`
- Modify: `pyproject.toml`, `package.json`, `eslint.config.mjs`, `tsconfig.contracts.json`
- Modify: `tests/static/test_quality_policy.py`, `.github/workflows/ci.yml`
- Modify: `scripts/baseline_capture_io.py`, `scripts/capture_baseline.py`, `tests/contracts/test_frozen_baseline.py`
- Modify: `contracts/zod/baseline-contracts.mjs`, `tests/contracts/zod_baseline_contracts.test.mjs`
- Regenerate through the tested writer: `contracts/baseline/manifest.json`

#### Interfaces

- Produces a repository-wide zero-diagnostic gate with no baseline suppression.
  `delete_render.py`, `smoke_live.py`, and `verify_deploy.py` preserve their
  existing success JSON, sanitized failure stderr, and exit codes while
  exposing typed `main(argv: Sequence[str], *, dependencies: CliDependencies)
  -> int` boundaries with injected clients, clocks, output sinks, and exit
  handling; importing a module has no side effects.
- The 2026-08-16 reconciliation already restored the three accidentally
  removed output seams and added focused `verify_deploy.main()` output tests.
  That repair does not complete this task's dependency injection, exhaustive
  CLI falsification, global-zero gate, or ratchet deletion.
- Strict Python/Node gates use reviewed Node v24.19.0 only, at
  `/tmp/nplg-phase1-toolchain.sNv6IL/node/node-v24.19.0-linux-x64/bin/node`.
  Removing the ratchet is a coordinated deletion: the runner modes and models,
  Python unit/property tests, Zod contract/test, package aggregates,
  ESLint/TypeScript inventories, CI/static-policy assertions, and frozen
  capture inventories are all direct dependants and must close together.

#### Reviewed schema-v3 historical-import to candidate transition

- Preserve `recovery.imported_index_tree` as the historical import
  `6cb461d986c21e4cb2852a07b06f75812ec27bbb`; never relabel it and never use
  the candidate as the private materialization seed.
- Set manifest `schema_version` and generator version to `3`, retain
  `capture_mode: "synthetic-index-staged-recovery"`, and admit exactly:

```json
{
  "transition_id": "phase-1-reviewed-index-transition-v1",
  "imported_index_tree": "6cb461d986c21e4cb2852a07b06f75812ec27bbb",
  "imported_staged_entries_sha256": "fcfe06d851c83040d860f9f887efe18bde9dbe46c4eeb1aaa3f68b3af8f3ccaf",
  "candidate_index_tree": "55691718dade75b44a8ed025fcf48dabf87a7969",
  "candidate_staged_entries_sha256": "9426ba909728d29d2009607264a9ffb1c028c4c645bbacd72f98867132e24f68"
}
```

- Require `recovery.imported_index_tree ==
  index_transition.imported_index_tree`. Validate the copied live index's
  candidate tree and canonical staged-entry digest before private
  materialization; after private `read-tree 6cb461d...`, validate the imported
  staged-entry digest. Materialization then continues from that historical
  seed with `git add -u -- .`, exact reviewed untracked additions, and the
  existing output removal/preservation checks.
- Do not retain the former baseline-excluding projections `b019...` or
  `d89c...`, add a redundant changed-path/delta digest, write the real index,
  or mutate refs. Missing, extra, malformed, mismatched, candidate-drift, and
  imported-digest cases are Python/Zod REDs before implementation.

- [x] **Step 1: Establish the three CLI seams and observe intentional RED**

Add only per-script typed dependency records and
`main(argv: Sequence[str], *, dependencies: CliDependencies) -> int` seams;
do not add a shared CLI framework. The new seams deliberately raise
`NotImplementedError` while the existing CLI entry remains unchanged. Prove
collection, then run one named real-risk case for each CLI. Import, tool,
network, or fixture failures are invalid REDs.

Run: `.venv/bin/python -m pytest --collect-only tests/unit/test_delete_render.py tests/unit/test_smoke_live.py tests/unit/test_verify_deploy.py -q`
Run: `.venv/bin/python -m pytest tests/unit/test_delete_render.py tests/unit/test_smoke_live.py tests/unit/test_verify_deploy.py -q`

- [x] **Step 2: Run the global direct gate and close CLI/static diagnostics**

```bash
.venv/bin/python scripts/run_quality_gate.py --node-executable /tmp/nplg-phase1-toolchain.sNv6IL/node/node-v24.19.0-linux-x64/bin/node src tests scripts typings
```

For each independently rejectable CLI invariant below, add one named case, observe its focused RED, make the smallest implementation change, and rerun focused GREEN before adding the next case.

Type CLI argument/result objects, validate subprocess results, and make
static-test parsers concrete. Add only applicable injected cases across the
three operational scripts: argument/help errors, absent/ambiguous target,
identifier/path confusion, confirmation mismatch, noninteractive refusal,
upstream timeout/nonzero/malformed/oversized response, cancellation,
redaction, idempotent not-found, output failure, success JSON, sanitized
failure stderr, and exact exit-code propagation. The live smoke tests never
use the network; they prove request count/deadline/output bounds and that
credentials, response bodies, and query values cannot enter diagnostics.
Extend `test_quality_policy.py` to enumerate every tracked regular `*.py` file
under `src`, `tests`, and `scripts` plus every tracked regular `*.pyi` under
`typings` with NUL-safe Git output and require the exact reviewed notice at the
first line or immediately after an executable shebang; symlinks, special
files, omissions, and any alternate notice fail.

The Task 6C bootstrap cleanup must preserve the Task 0 downloader and process
trust contracts instead of replacing them to satisfy syntax-only analysis.
Exactly four statement-local Ruff suppressions are authorized in
`scripts/bootstrap_toolchain.py`: one `S310` on the already HTTPS-only,
credential-free, no-proxy, no-redirect, bounded urllib request/open boundary;
two `S603`
directives on executable launches whose argv/executable are respectively
closed by extracted-artifact policy or absolute regular-file, executable-bit,
SHA-256, and exact-version validation; and one `PLR0913` on
`install_from_lock`, whose tool/target/destination and downloader,
version-checker, and dependency-root trust seams must remain explicit. Each
directive has an adjacent three-line security/compatibility rationale and is
added to the tokenized closed suppression inventory. Persistent mutants must
reject a missing/changed rationale, a changed/multi-rule directive, a moved or
duplicated directive, and any fifth bootstrap suppression. No per-file ignore,
configuration relaxation, `Any`, typed-kwargs concealment, downloader rewrite,
or checksum-manifest activation/deletion is authorized. Genuine complexity is
still split along review-policy, record-validation, archive-validation,
dependency-validation, and publication boundaries while preserving error
order and focused behavior.

- [x] **Step 3: Prove literal global zero, then remove the ratchet**

Do not edit or delete ratchet infrastructure until the literal direct gate
above exits zero. Then add persistent REDs that reject `--ratchet`,
`--write-baseline`, baseline fields/models, Zod/package/config/CI references,
and baseline-excluding staged projections. Simplify `run_quality_gate.py` to
direct zero while retaining bounded execution, repository snapshot/mutation
checks, release identity validation, and the adversarial real-tool self-test.
Delete every ratchet/baseline artefact named in Files only after those REDs.

- [x] **Step 4: Implement schema v3 and regenerate the frozen manifest**

Add Python and Zod REDs for missing/extra/malformed transition fields,
recovery/import mismatch, candidate tree/digest mismatch, live-index drift,
and imported digest mismatch. Implement the two-identity validation order
above. After all source/config tests are frozen and no concurrent writer is
active, regenerate the manifest only through the tested writer while proving
the four behavior fixtures, real index, refs, and pre-existing object bytes
remain unchanged.

- [x] **Step 5: Run all strict gates and tests**

Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable /tmp/nplg-phase1-toolchain.sNv6IL/node/node-v24.19.0-linux-x64/bin/node src tests scripts typings`
Run: `.venv/bin/python -m pytest tests/unit/test_delete_render.py tests/unit/test_smoke_live.py tests/unit/test_verify_deploy.py -q`
Run the focused frozen Python/Node contract suites and manifest check mode.
Run: `.venv/bin/python -m pytest -q`
Expected: zero diagnostics, no formatting diff, and all tests PASS. Stop before
Task 7. This task does not authorize stage, reset, index/ref write, commit,
push, deploy, install, or network activity.

- [x] **Step 6: Close the scoped Task 6C runtime-review findings**

Keep argument validation and canonical-output caps local to `smoke_live.py`
and `verify_deploy.py`; do not add a shared CLI/JSON framework or change the
existing `json_types.py` API. Validate all numeric arguments before
constructing an injected/default client. Accept the current CLI timeout contract exactly:
every finite value greater than zero, with no invented upper bound, and pass
the value to the injected client unchanged. The smoke CLI additionally accepts
only search page sizes `1..50`, matching `SearchDocumentsInput` and the
repository hard maximum, and every render-page number greater than or equal to
`1`, matching the current public tool schema. Do not expose the processor's
internal 2000-page default as a caller contract or preempt Task 15's later
reviewed 10,000-page bound.

Retain the verify adapter's `1_048_576`-byte raw-response limit; that existing
body ceiling is the parser's resource bound. Before either CLI writes a
successful canonical JSON document, require its UTF-8 encoding (including the
terminal newline) to be at most `65_536` bytes; this reuses the public
error-value aggregate string budget as a conservative operator-output ceiling
and rejects rather than truncates oversized success. Translate the JSON
decoder's `ValueError` and `RecursionError` paths, including recursive shape
validation, to the existing fixed malformed-response failure. Do not invent
independent depth/node/string/integer policies that could reject a response
accepted by the current MCP contract.

Add persistent focused REDs before implementation for the review
reproductions: a roughly 200-kilobyte canonical output; smoke page sizes `0`
and `-1`; zero, negative, `nan`, and `inf` timeouts; deployment
responses with 1500 nested arrays and a 5000-digit integer; and
`delete_render` cancellation raised by interactive `stdin.readline()`.
Retain high-positive render-page and high-finite timeout compatibility controls
that prove no arbitrary Task 6C maximum was introduced. The deployment cases
must prove the response
and connection close on every path and that secrets do not enter diagnostics;
the delete cancellation returns `130` with a sanitized failure and never
constructs the processor. Translate only expected Unicode/JSON syntax,
recursion, and numeric-conversion failures. Do not add a broad
catch, truncate output as success, alter provenance/schema semantics, or
recapture the manifest until all tracked runtime/tests/docs changes are
frozen. Correct `_PipeState`'s stale nonblocking docstring.

Run the focused three-CLI matrix, the direct global quality gate and its
self-test, then the full Python suite. Because this plan, scripts, and tests
are manifest inputs, perform exactly one final controlled schema-v3 manifest
refresh through the tested writer, preserving the reviewed transition, live
index, refs, behavior fixtures, and pre-existing object bytes. Rerun manifest
check mode, frozen Python/Node contracts, and the direct global gate, then
freeze for scoped re-review and stop before Task 7.

#### Phase 1 temporary-infrastructure exit gate

Before Task 7, stop and review complexity as a first-class acceptance gate:

- Delete `quality-baseline.json` and `scripts/quality_ratchet.py` once the
  repository-wide direct gate is zero; they are migration scaffolding, not a
  permanent quality architecture.
- Retain the four frozen public-behavior fixtures and deterministic replay.
  After the first clean committed candidate exists, replace the dirty-tree
  synthetic-index/private-object-database preservation machinery with the
  smallest digest manifest/checker that still proves those fixtures. This
  requires its own RED/GREEN review and must not weaken behavior parity.
- Retain the pinned ASVS source, exact 759-row inventory, threat model, and
  `do_not_release`. Do not extend inactive custody, authority, risk-acceptance,
  or transactional-publication machinery until a real approved authority and
  evidence source exist.
- If canonical-file, bounded-process, Git-snapshot, or atomic-publication
  primitives remain necessary in more than one script, consolidate the
  existing implementations rather than adding another custom framework.

No Phase 2 work begins until this exit gate and the Phase 1 status ledger are
reviewed again.

### Task 7: Raise coverage and adversarial test depth

#### Files

- Modify: `.gitignore`
- Modify: `pyproject.toml`
- Modify: `src/nplg_mcp/parsers.py`, `scripts/run_quality_gate.py`
- Modify: `tests/conftest.py`, `tests/contracts/test_frozen_baseline.py`, `tests/contracts/test_oauth_provider_capability.py`
- Modify: `tests/conformance/test_mcp_http.py`
- Modify: `tests/integration/test_pdf.py`, `tests/integration/test_repository.py`
- Modify: `tests/security/test_downloader.py`, `tests/security/test_security.py`, `tests/security/test_tokens.py`
- Modify: `tests/unit/test_admission.py`, `tests/unit/test_bootstrap_toolchain.py`, `tests/unit/test_build_asvs_matrix.py`, `tests/unit/test_config.py`, `tests/unit/test_errors.py`, `tests/unit/test_main.py`, `tests/unit/test_parsers.py`, `tests/unit/test_quality_gate.py`, `tests/unit/test_rate_limit.py`, `tests/unit/test_storage.py`, `tests/unit/test_tiles.py`, `tests/unit/test_tools.py`, `tests/unit/test_verify_deploy.py`
- Modify: `tests/unit/test_delete_render.py`, `tests/unit/test_smoke_live.py`
- Create: `tests/property/test_parser_properties.py`
- Create: `tests/property/test_storage_properties.py`
- Create: `scripts/run_mutation_gate.py`, `tests/unit/test_mutation_gate.py`
- Create: `scripts/run_test_gate.py`, `tests/unit/test_test_gate.py`
- Create: `security/coverage-policy.json`
- Create: `security/external-test-gates.json`

#### Interfaces

- Alongside the 95% changed-line `diff-cover` gate below, `run_test_gate.py` enforces at least 95% changed branch-arc coverage from a fresh externally contained Coverage JSON report. Set `diff_branch_arc_floor: 95` in `security/coverage-policy.json`. Intersect Coverage JSON's source-destination `executed_branches`/`missing_branches` pairs with branch-source lines added or modified relative to the verified merge base; a new file treats every arc as changed, and rename/copy classification cannot make an arc disappear. XML and JSON subject/file/counter disagreement or an unmeasured changed file/branch source fails closed; measured changed-line and changed-arc percentages must each meet their 95% floor.

- Produces deterministic Hypothesis strategies for bounded JSON, handles, redirects, filenames, paths, cursors, page selections, and tile geometry.
- Release installed-wheel mode extends `run_test_gate.py` with required `--installed-package-root ABSOLUTE_SITE_PACKAGES_NPLG_MCP --package-manifest VERIFIED_JSON`. Before coverage starts, the runner descriptor-inventories the canonical wheel's installed `nplg_mcp` regular files and the candidate's `src/nplg_mcp` files, applies only reviewed wheel transformation rules (`*.py`, `py.typed`, and declared package data; no generated/rewritten Python), and requires a one-to-one path/mode/byte-digest match recorded in `VERIFIED_JSON`. Only then may it generate an external Coverage.py `[paths]` alias mapping that exact site-packages root to the exact candidate source root for report combination. Missing/extra/transformed files, namespace/path escape, editable/source import, symlink, duplicate alias, a second site-packages package, source spoof, coverage outside `src/nplg_mcp`/`scripts`, or a mapping without the manifest equality proof fails. Unit tests prove a covered installed-wheel line maps to its candidate line and that every escape/spoof/mismatch fails; installed-wheel runtime proof and source-bound branch/diff coverage remain separate recorded gates even though the latter consumes the verified alias. Task 7 implements and locally unit-tests this inventory, equality, and alias boundary with synthetic installed roots; a real canonical-wheel runtime proof requires the protected release environment and is not a local Task 7 completion claim.
- Produces `run_test_gate.py --compare-branch REF [--worktree ROOT --output-dir EXTERNAL_DIR] [--require-clean --candidate COMMIT]`, the sole post-Task-7 **release-quality branch/diff authority**: all non-network/non-container tests with subprocess-aware XML coverage and a 95% floor, the versioned per-module branch policy below, followed by `diff-cover` at 95%; focused RED/GREEN commands remain permitted for implementation and diagnosis. It rejects missing/shallow refs and propagates any failure. Coverage's exact measured roots are `["src/nplg_mcp", "scripts"]`; tests are not in the coverage denominator, but every project script is. Developer mode permits the task's intentionally dirty but stable named worktree: it records HEAD plus a digest of every tracked/untracked test/source/config byte and the merge-base diff before execution, repeats those digests afterward, and measures/diff-covers exactly that snapshot. It materializes the stable tracked-plus-untracked source snapshot in an external temporary Git repository/index, creates a deterministic ephemeral snapshot commit there, and compares that snapshot with the materialized merge-base tree; it never commits to or changes the index of the user's repository. Thus every line in a new untracked Python source or script is part of the changed-line denominator. Release mode requires both `--require-clean` and `--candidate COMMIT`, then requires clean exact HEAD before and after. An explicit output directory must not exist, is atomically created mode `0700`, must resolve outside every registered worktree, and contains coverage data/XML/JSON, pytest cache/base temp, diff-cover output, and bounded command records. When the external arguments are omitted for an ordinary developer run, the runner uses and removes a private system temporary directory outside the current worktree; it never writes `coverage.xml`, `.coverage*`, `.pytest_cache`, or temp files into source. Tests requiring explicit network, staging, or container authority are never silently skipped: collection must map each exact node ID to the separate external-gate registry below, and an unclassified deselection fails. Task 7 implements the local hard check for a usable comparison ref; Task 8 owns CI checkout depth, explicit base-ref acquisition, and workflow invocation.
- The final Task 7 adversarial review adds ten mandatory corrections before `run_test_gate.py` may be called an authority. Candidate bytes must not shadow `pytest`, `coverage`, or `diff-cover`: resolve reviewed absolute tool entry points, verify exact pinned versions and import origins in both the parent and every child-side invocation, keep trusted tool imports isolated from candidate import roots, and fail on a candidate `pytest.py`, `coverage.py`, `diff_cover.py`, or equivalent package. Every output-derived Coverage/pytest configuration value must use an injection-safe representation and reject control/newline, interpolation, or section-breaking path bytes. Installed-wheel mode must execute a separately recorded deterministic package suite against the exact verified installed root with snapshot `src` excluded from package resolution; its result is distinct from the source-bound scripts/branch/diff run and remains synthetic locally unless a protected canonical wheel is supplied. Bind and reverify the materialized snapshot commit/tree, every copied input and generated configuration, and the exact external report inventory/bytes before accepting results. This is checkpoint-bound tamper detection in one local user context, not isolation from malicious same-UID tests; stronger isolation and canonical-wheel authority remain protected-environment responsibilities. The owned source/test/config inventory must include ignored regular files under the reviewed roots, excluding only the closed generated/cache set; Git ignored status is not permission to omit executable input. A changed conditional source line with no Coverage branch-pair evidence fails rather than receiving an inferred 100%, and any collection or execution deselection fails even if JUnit totals otherwise agree. Materialization and verification use descriptor-relative no-follow traversal, not repeated pathname parent traversal. In release mode, one `GIT_OPTIONAL_LOCKS=0` evidence bracket must preserve exact candidate commit/tree, raw index bytes, HEAD/symbolic-or-detached state, ref bytes, and object inventory before/after. At least one successful real temporary-repository CLI integration must invoke the pinned pytest/Coverage/diff-cover stack and prove these bindings; injected fakes remain necessary but are not sufficient. Reuse the existing descriptor and bounded-process primitives, delete redundant checks where equivalence is proved, and add no third framework or lint/type suppression.
- Final re-review adds two further authority blockers before acceptance. Paired XML/JSON agreement is not proof of completeness: descriptor-read the already bound snapshot source without importing or executing candidate code, then use only the exact-origin/version-verified pinned Coverage 7.15.4 `PythonParser(text=..., filename=...)`, `parse_source()`, and `exit_counts()` API to derive every static branch source with more than one exit. Every such source line that intersects the changed-line set must appear in the reports' equal branch-source-line set; jointly omitted changed `if`, loop, or non-irrefutable `match` branches fail even when another line supplies internally consistent branch data and both computed diff percentages would otherwise be 100%. Do not hand-maintain an AST node list or trust an ambient/candidate-shadowable Coverage import. Source and installed-package inventory must bind the canonical package root once, enumerate every directory through descriptor-relative no-follow traversal, and open/stat/read every descendant relative to its already validated parent descriptor; `Path.rglob`, full-path `lstat`, or full-path reopen is not release evidence. Separate public regressions must first expose joint branch-source omission and a parent-component symlink swap, then the smallest GREEN must reuse the exact trusted parser and existing descriptor traversal rather than create another framework.
- Literal runner self-coverage for that repair must remain public and failure-sensitive rather than fabricate Coverage internals. Exercise the real pinned Coverage cold-load success path, hostile preloaded/orphaned origin rejection, one real cold-load failure with complete `coverage*` binding cleanup, non-UTF-8 and invalid-Python candidate source rejection, and descriptor cleanup after a natural nested-package failure only through `parse_coverage_reports`, `verify_installed_package`, or the public gate. Remove or consolidate guards that can fire only after inventing malformed members or returns from the exact pinned private Coverage API; do not test them with fake modules or parser objects. Installed inventory is closed against the manifest's exact file paths and their directory prefixes, so an unexpected entry fails immediately; this exact closure replaces a separate 100,001-entry branch whose only practical unit test would mutate a private bound.
- Produces schema-validated `security/coverage-policy.json` version 1 with `project_branch_floor: 95`, `diff_line_floor: 95`, `diff_branch_arc_floor: 95`, `decision_module_branch_floor: 100`, exact `measured_roots: ["src/nplg_mcp", "scripts"]`, and initial exact `decision_modules` paths `src/nplg_mcp/admission.py`, `src/nplg_mcp/errors.py`, `src/nplg_mcp/rate_limit.py`, `src/nplg_mcp/security.py`, `src/nplg_mcp/tokens.py`, `scripts/delete_render.py`, `scripts/smoke_live.py`, `scripts/run_quality_gate.py`, `scripts/run_test_gate.py`, and `scripts/run_mutation_gate.py`. Missing, duplicate, nonexistent, renamed, unmeasured, or outside-root paths fail. Tasks 8, 11, 13, 15, 16, 16A, 17, 19, 20, and 21 expand the same closed list respectively with `scripts/verify_release.py`/`scripts/bootstrap_external_tools.py`; `mcp_server.py`/`sdk_boundary.py`; `http_security.py`/`json_preflight.py`; `pdf_executor.py`/`pdf_ipc.py`; `scripts/verify_pdf_worker_container.py`/`scripts/verify_private_edge.py`; `malware.py`/`pdf_worker_client.py`/`storage.py`/`scripts/verify_scanner_container.py`/`scripts/verify_pdf_worker_quota.py`/`scripts/verify_private_recovery.py`; `network.py`/`resilience.py`/`scripts/run_live_nplg_canary.py`; `profiles.py`; `auth.py`/`audit.py`; and `scripts/verify_deploy.py`/`scripts/run_alpic_staging_proof.py`. Relative names in this sentence are under `src/nplg_mcp/` unless prefixed `scripts/`. Removing a path requires a reviewed deletion/rename in the same task.
- Produces strict version-1 `security/external-test-gates.json`, independent of the later release manifest. Task 7 owns only the audited empty registry, exactly `{"version":1,"gates":[]}`, and its closed parser/classification tests; a nonempty entry is rejected in Task 7. The detailed entry, protected-controller, command-record, and signed-proof schemas below are future contracts owned by Tasks 16, 16A, 17, and 21, which must amend this reviewed registry/parser before adding their exact rows. Any other task that later adds an external gate must first amend this reviewed inventory. Task 22 requires the selected profile manifest to account exactly once for every applicable registry entry in its declared mode, but ordinary developer gates do not depend on a file that Task 22 has not created yet.

| Owner | `gate_id` / `command_id` | Kind / profiles / mode | Nodes or command | Authority environment / runtime bindings | Timeout / evidence schema |
| --- | --- | --- | --- | --- | --- |
| Task 16 | `private-full.pdf-worker-container` / `container.pdf-worker.v2` | `container` / `private-full` / `preexecuted-operational` | protected `nplg-release-controller external-gate --gate-id private-full.pdf-worker-container --candidate-battery-json BATTERY --controller-policy EXPECTED_POLICY --runtime-broker-descriptor BROKER --result-json RESULT_JSON`; the controller-owned signed adversarial corpus and harness consume the candidate Compose/policy as untrusted data | cwd `protected-controller-root`; brokered one-operation authority to a disposable rootless daemon/VM; no candidate process can access the daemon socket, host slot, controller, or result writer | 300 s / signed `container-proof.v2` plus complete command record |
| Task 16 | `private-full.edge-http` / `staging.private-full-edge.v2` | `staging` / `private-full` / `preexecuted-operational` | protected `nplg-release-controller external-gate --gate-id private-full.edge-http --candidate-battery-json BATTERY --controller-policy EXPECTED_POLICY --network-broker-descriptor BROKER --target-descriptor TARGET --result-json RESULT_JSON`; the controller-owned harness treats Caddy/app configuration and images as untrusted candidate data and probes only the named non-production deployment | cwd `protected-controller-root`; one-operation bounded network authority to the exact private staging edge and separately authenticated origin observation; no candidate process sees target credentials, network broker, or result writer | 1,800 s / signed `private-edge-proof.v2` plus complete command record |
| Task 16A | `private-full.scanner-container` / `container.scanner.v2` | `container` / `private-full` / `preexecuted-operational` | protected `nplg-release-controller external-gate --gate-id private-full.scanner-container --candidate-battery-json BATTERY --controller-policy EXPECTED_POLICY --runtime-broker-descriptor BROKER --result-json RESULT_JSON`; protected corpus/harness verify the immutable scanner image and candidate Compose as data | cwd `protected-controller-root`; brokered one-operation disposable rootless runtime, verified fresh signature source, no host socket or candidate result authority | 300 s / signed `container-proof.v2` plus complete command record |
| Task 16A | `private-full.pdf-worker-write-quota` / `container.pdf-worker-quota.v2` | `container` / `private-full` / `preexecuted-operational` | protected `nplg-release-controller external-gate --gate-id private-full.pdf-worker-write-quota --candidate-battery-json BATTERY --controller-policy EXPECTED_POLICY --runtime-broker-descriptor BROKER --slot-descriptor SLOT --result-json RESULT_JSON`; protected harness owns quota probes and treats candidate slot policy as untrusted input | cwd `protected-controller-root`; brokered disposable rootless runtime plus a controller-validated bounded slot; candidate code cannot see the raw host path, runtime socket, or result writer | 300 s / signed `worker-quota-proof.v2` plus complete command record |
| Task 16A | `private-full.recovery-proof` / `container.private-full-recovery.v2` | `container` / `private-full` / `preexecuted-operational` | protected `nplg-release-controller external-gate --gate-id private-full.recovery-proof --candidate-battery-json BATTERY --controller-policy EXPECTED_POLICY --runtime-broker-descriptor BROKER --slot-descriptor SLOT --result-json RESULT_JSON`; protected harness owns destructive disposable volume-loss/corruption/restore/regeneration probes and treats candidate recovery code/policy as untrusted input | cwd `protected-controller-root`; brokered disposable rootless runtime and controller-created bounded volumes containing synthetic non-sensitive state only; candidate code cannot see the host path, runtime socket, or result writer | 900 s / signed `recovery-proof.v2` plus complete command record |
| Task 17 | `common.nplg-live-canary` / `live.nplg-bound-endpoint.v2` | `live` / `alpic-metadata`, `private-full` / `preexecuted-operational` | classification node `tests/integration/test_repository.py::test_live_nplg_canary_uses_bound_public_endpoint`; protected `nplg-release-controller external-gate --gate-id common.nplg-live-canary --candidate-battery-json BATTERY --controller-policy EXPECTED_POLICY --network-broker-descriptor BROKER --result-json RESULT_JSON`; protected oracle/harness owns the request and result | cwd `protected-controller-root`; one-operation egress is pinned to exact `https://dspace.nplg.gov.ge/`; no candidate executable, proxy environment, network authority, or result writer | 60 s / signed `nplg-live-canary.v2` plus complete command record |
| Task 21 | `alpic-metadata.staging-proof` / `staging.alpic-metadata.v2` | `staging` / `alpic-metadata` / `preexecuted-operational` | the six exact `tests/deployment/test_edge_http.py` nodes; protected `nplg-release-controller staging-proof` with fixed flags for `CandidateBatteryResult`, preparation, controller policy, broker descriptor, project/environment/base/MCP IDs, external outputs, and authorization | cwd `protected-controller-root`; non-secret authority bindings `ALPIC_PROJECT_ID`, `ALPIC_STAGING_ENVIRONMENT_ID`, `ALPIC_STAGING_BASE_URL`, `ALPIC_STAGING_MCP_URL`, `NPLG_CREDENTIAL_BROKER_DESCRIPTOR`; credential union from the capability record: unsupported means one access-token broker handle and required blocker, supported means access plus insufficient-scope handles and 403 probe; raw credentials are never environment bindings | 1,800 s; fresh through 3,600 s after aware-UTC `completed_at` with at most 60 s future skew / `alpic-staging-proof.v2` plus complete `staging-command-record.v2` |

`container-proof.v2` and `worker-quota-proof.v2` are closed signed Pydantic records, not aliases for exit code zero. Each binds the protected controller authority/artifact/revision/policy/isolation and broker/runtime identities, `schema_id`, exact `gate_id`/`command_id`, candidate commit/tree/battery, command-policy and Compose-file digests, the expected canonical image digest, aware-UTC start/completion, the exact ordered `required_probe_ids`, an equal-length ordered tuple of strict `ProbeResult`, and a canonical record SHA-256. `worker-quota-proof.v2` additionally binds the slot-policy digest and a sanitized descriptor-derived mount identity digest (device, filesystem type, mount ID/options, block/inode limits), never a raw host path. `ProbeResult` contains only a bounded probe ID, `Literal["passed", "failed"]` status, strict `0..255` exit code, optional strict positive signal number, `timed_out: bool`, strict finite nonnegative `started_offset_ms` and `completed_offset_ms` plus bounded derived duration, the image ID observed immediately before and after that probe, and bounded command/observation digests—never raw stdout, paths, environment, secrets, or payloads. An acceptable proof has byte-for-byte equality between required and observed probe IDs, all `passed`, exit zero, no signal/timeout, identical expected/before/after image IDs for every probe, `0 <= started_offset_ms <= completed_offset_ms` with each next start no earlier than the prior completion and all offsets inside the registered timeout/record interval, and valid record/envelope signatures. Empty, skipped, duplicate, extra, reordered, unknown, partially written, candidate-authored, or wrong-controller probe results are invalid even if a process exits zero.

`private-edge-proof.v2` adds exact Caddy/app image and configuration digests, public and origin endpoint identities, public certificate chain/cipher observations, internal mTLS peer certificate identities, backend-auth result, origin-bypass result, and before/after deployed-subject observations. `recovery-proof.v2` adds slot/recovery-policy digests, synthetic state-class inventory, backup or deterministic-regeneration subject digest, measured RTO milliseconds, recovered ownership/mode/content digests, and before/after persistent high-water/lease/reservation state. Both use the same strict probe completeness, timing, controller signature, freshness, and no-secret rules as the container records; a developer fixture or candidate-authored result is never release evidence.

The closed ordered probe inventories are:

- `private-full.pdf-worker-container`: `image.identity`, `network.dns-denied`, `network.ipv4-denied`, `network.ipv6-denied`, `network.netlink-denied`, `secrets.unavailable`, `filesystem.root-read-only`, `filesystem.staging-only-write`, `process.pid-ceiling`, `process.deadline-kill`, `ipc.peer-credentials`, `ipc.nonce-replay-denied`, `corpus.complete`, `cleanup.complete`.
- `private-full.edge-http`: `subjects.identity`, `public.tls-chain-hostname`, `public.tls12-policy`, `public.tls13-policy`, `public.headers-framing`, `public.slow-client-bounded`, `public.body-header-deadline-concurrency`, `public.auth-negative`, `origin.not-publicly-bypassable`, `origin.mtls-server-auth`, `origin.mtls-client-auth`, `origin.host-origin-policy`, `origin.plaintext-denied`, `logs.no-secret`, `subjects.unchanged`, `cleanup.complete`.
- `private-full.scanner-container`: `image.identity`, `network.dns-denied`, `network.ipv4-denied`, `network.ipv6-denied`, `secrets.unavailable`, `filesystem.root-read-only`, `signatures.authentic-and-fresh`, `sample.clean-accepted`, `sample.eicar-rejected`, `archive-bomb.bounded`, `process.deadline-kill`, `cleanup.complete`.
- `private-full.pdf-worker-write-quota`: `image.identity`, `quota.supported`, `quota.exact-byte-accepted`, `quota.n-plus-one-byte-denied`, `quota.exact-inode-accepted`, `quota.n-plus-one-file-denied`, `quota.n-plus-one-directory-denied`, `quota.zero-byte-flood-denied`, `quota.sparse-blocks-bounded`, `quota.concurrent-overrun-denied`, `process.overrun-killed`, `cleanup.root-removed`, `headroom.restored`.
- `private-full.recovery-proof`: `subjects.identity`, `volume.complete-loss`, `backup.restore-or-derived-regeneration`, `content.digest`, `filesystem.owner-mode`, `high-water.restore`, `clock-anomaly.closed`, `leases.restore`, `reservations.restore`, `corrupt-state.closed`, `partial-restore.cleaned`, `rto.measured-within-policy`, `subjects.unchanged`, `cleanup.complete`.

The verifiers resolve and compare the immutable image ID before **every** probe and once after final cleanup, forbid build/pull/create-from-tag operations, and write the strict proof only through an exclusive external no-symlink mode-`0600` path. Their injected-runner unit tests prove every envelope, probe-completeness, process, timeout, overflow, image-TOCTOU, output-publication, and secret-redaction rejection; their decision paths are in the 100%-branch and mutation policies.

The Task 21 `pytest_node_ids` are exactly `test_edge_rfc9728_and_route_ownership`, `test_edge_rejects_framing_encoding_and_trace`, `test_edge_tls_http_redirect_and_all_response_headers`, `test_edge_origin_is_not_publicly_bypassable`, `test_edge_runtime_subject_privacy_and_submission_version`, and `test_edge_classifies_multi_instance_principal_limit_evidence`, each under `tests/deployment/test_edge_http.py`. Nodes pass only after binding verified enforcement evidence or the exact stable unsupported-provider blocker where the requirement is operationally unobservable; a blocker is never enforcement evidence. The command spec executes only the protected controller artifact with the exact ordered v2 flags above. Static tests compare controller identity, fixed argv/nodes/non-secret env names, credential union, timeout, and schemas byte-for-byte; a changed gate contract requires review.

- [ ] **Step 1: Observe the already-configured coverage floor RED**

First create typed behavior-free `run_test_gate.py` and `run_mutation_gate.py` scaffolds with immutable policy/command/result records and narrow injected executor/clock/filesystem/Git protocols. The XML/JSON/result parser entrypoints and target methods deliberately raise `NotImplementedError`; implement none of those behaviors before their focused RED. Prove both unit modules collect, then run their focused fake/XML/temp-repository cases and observe those deliberate behavioral REDs before implementing either authority:

Run: `.venv/bin/python -m pytest --collect-only tests/unit/test_mutation_gate.py tests/unit/test_test_gate.py -q`
Run: `.venv/bin/python -m pytest tests/unit/test_mutation_gate.py tests/unit/test_test_gate.py -q`
Expected: collection/imports PASS and focused cases reach `NotImplementedError`; a missing executable, source ref, module, fixture, or pre-created output is the wrong RED.

Task 3 already installed and statically asserted `fail_under = 95` with branch measurement. Do not edit that threshold in this task. The prior coverage artifacts are not authoritative because they omit `scripts`; create a fresh absolute external diagnostic root and measure both required roots without writing caches, bytecode, or coverage data into the checkout:

```bash
TASK7_RED_OUTPUT="$(mktemp -d /tmp/nplg-task7-red.XXXXXX)"
COVERAGE_FILE="$TASK7_RED_OUTPUT/.coverage" \
PYTHONPYCACHEPREFIX="$TASK7_RED_OUTPUT/pycache" \
.venv/bin/python -m pytest \
  -o "cache_dir=$TASK7_RED_OUTPUT/pytest-cache" \
  --basetemp="$TASK7_RED_OUTPUT/pytest-tmp" \
  --hypothesis-profile=ci \
  --cov=nplg_mcp --cov=scripts --cov-branch \
  --cov-report=term-missing --cov-fail-under=95 -q
```

Expected: FAIL below 95%; record the fresh combined result rather than comparing it with the stale source-only 63%, 76%, or 82% observations.

- [ ] **Step 2: Add missing negative and boundary tests**

Cover every public error branch, timeout, cancellation cleanup, malformed/oversized body, duplicate/non-finite JSON, parser drift, redirect denial, MIME mismatch, quota boundary, symlink race, corrupt/encrypted PDF, page/tile ceiling, token expiry boundary, and authentication ambiguity. Freeze secure XML behavior with DTD, external/local/network entity, quadratic, and exponential-expansion rejection cases. Configure the CI Hypothesis profile with `derandomize=True`, `database=None`, `deadline=None`, `max_examples=200`, and `print_blob=True`. Archive the exact Hypothesis version, minimized falsifying example, and `@reproduce_failure` blob; do not promise a seed when deterministic mode did not use one. If a replay job supplies an explicit `--hypothesis-seed`, record that seed and state that it supersedes `derandomize`. Developers may use Hypothesis's local example database, but `.hypothesis/` is never checked in and CI never depends on it.

Configure Coverage.py for spawned workers with subprocess patching, parallel data files, and `coverage combine`; add a canary subprocess test that fails if child-process lines are absent from the report. Unit-test `run_test_gate.py` with synthetic coverage XML proving that 99.99% for any named decision module, an absent module, or a report with no branch data fails even when project and diff floors pass. The 95% project floor does not replace the policy's 100% branch floor for the exact small allow/deny, authentication, schema-validation, and public-error decision modules.

Also unit-test the changed-arc gate with synthetic Coverage JSON. A deliberate fixture executes a changed `if` line but only one destination: the changed-line metric must pass and the independent arc gate must fail whenever that omission takes changed branch-arc coverage below 95%. Reject JSON/XML disagreement, new-file arc omission, rename/copy evasion, a source line outside the verified diff, and a report with line data but no branch-pair data. Require exact changed-arc accounting and the executable 95% floor in addition to the 100% closed decision-module policy.

Add real temporary-repository tests in which a newly created, untracked Python module and a separate untracked Python script each have an executable uncovered line: developer mode must report each line as changed and fail the 95% changed-line gate. Then cover the lines and prove GREEN. Also test rename/delete/binary/untracked-test cases, unstable bytes between the two snapshots, symlink/special-file input, ignored generated files, merge-base absence, and that neither the source repository's index nor refs change.

- [ ] **Step 3: Add mutation checks for decision functions**

Implement and unit-test `scripts/run_mutation_gate.py [--worktree ROOT --output-dir EXTERNAL_DIR] [--require-clean --candidate COMMIT] --targets ...` as a fail-closed wrapper around the exact-pinned `mutmut`. The runner snapshots source/config/test bytes, copies the required tracked tree without symlink traversal into a new external disposable mutation workspace, runs mutmut/cache/results only there, and byte-verifies the original worktree afterward. Developer mode permits a stable dirty snapshot; release mode requires clean exact `COMMIT`. Relative/preexisting/contained/symlink output, a copied-input mismatch, candidate mutation, or cache/output in the source worktree fails. Configure the exact eight initial targets; Task 22 reruns the gate for its expanded target set. Mutation evidence supplements the unchanged 95% project, changed-line, and changed-arc authorities: require the closed status inventory and at least 65% actual test-failure kills, not a literal zero-survivor target that incentivizes coverage-only tests.

Pinned `mutmut==3.7.0` evidence is limited to mutants the tool actually generates. Require exact nonempty per-target/per-required-function inventory and only raw statuses `1` (actual test-failure kill), `0` (survived), `33` (no associated test), or `-24` (bounded timeout). Unknown, null, skipped, interrupted, suspicious, internal-error, type-check-only, or incomplete statuses fail. Exact status `1` must cover at least 65% of all generated mutants; every other accepted status, including a timeout, counts against the floor. Mutmut 3.7.0 skips decorated classes, so the audited downloader proof remains limited to its two module-level DNS mutants; retain direct adversarial and 100% decision-branch evidence for skipped methods. Do not refactor production or invent a harness to manufacture mutant coverage.

This 65% policy supersedes the older exact-status-`1` sentence embedded in the
function-inventory paragraph below; the function and target set-equality oracle
remains unchanged.

Storage's current generated method names are `_cache_full`,
`_cleanup_incomplete_renders`, and `_cleanup_stale_staging`; these exact names
supersede the three former non-underscored spellings in that paragraph.

- The Task 7 mutation authority uses the exact ordered eight targets already named above and the following exact generated-function set—no missing or extra function is acceptable: `security.py`: `_default_resolver`, `_invalid`, `_validate_origin`, `build_item_url`, `is_forbidden_address`, `parse_handle_input`, `resolve_approved_addresses`, `validate_upstream_url`; `tokens.py`: `_b64decode`, `_b64encode`, `_validate_asset_claims`, `_validate_path`, `sign_asset_token`, `verify_asset_token`; `downloader.py`: `_validate_nplg_dns` only; `storage.py`: `_cleanup_render_tiles`, `_cleanup_tile_page`, `_fsync_directory`, `_remove_storage_path`, `_render_completion_exists`, `_sha256_path`, every listed `ContentAddressedStore` method (`__init__`, `cache_full`, `cleanup_incomplete_renders`, `cleanup_stale_staging`, `_commit_staged_file`, `_commit_staged_render`, `_delete_render_subtree_locked`, `_discard_staged_file`, `_is_render_id`, `_release_staging_bytes`, `_render_lock_for`, `_render_tree_bytes`, `_reserve_staging_bytes`, `_scan_existing_bytes`, `_validate_filename`, `_validate_media_type`, `_validate_namespace`, `_validate_staged_identity`, `_validated_render_subtree`, `begin_render_transaction`, `delete_render_subtree`, `put_bytes`, `put_render_bytes`, `resolve_asset`, `stage`), `_RenderTransaction.__init__/commit/reset/rollback`, and `_StagedWriter.__enter__/__exit__/__init__/_snapshot/commit/commit_render/write`; `errors.py`: `_checked_string_total`, `_consume_public_detail_value`, `_internal_public_error`, `_snapshot_frame`, `_snapshot_public_details`, `_snapshot_scalar`, `_store_snapshot`, `to_public_error`; `delete_render.py`: `_confirm`, `_default_dependencies`, `_default_processor_factory`, `_delete`, `_parse_arguments`, `_parser`, `_write_failure`, `_write_result`, `main`; `smoke_live.py`: `_add_download_output`, `_add_render_output`, `_argument_failure`, `_arguments_from_values`, `_default_client_factory`, `_default_dependencies`, `_default_verifier`, `_object_list`, `_optional_string`, `_parse_args`, `_parser`, `_required_string`, `_run_smoke`, `_selected_handle`, `_write_failure`, `_write_output`, `first_public_pdf`, `main`; and `run_quality_gate.py`: `_canonical_existing_worktree`, `_canonical_new_cache`, `_canonical_registered_worktrees`, `_checked_paths`, `_closed_environment`, `_consume_pipe_event`, `_decode_bounded_git_field`, `_expand`, `_expand_directory`, `_fail`, `_fingerprint_file`, `_inventory_files`, `_kill_process_group`, `_parse_registered_worktree_block`, `_parser`, `_paths_intersect`, `_read_bounded_streams`, `_resolve_inventory_input`, `_run_quality_commands`, `_selected_paths`, `_stable_regular_file_sha256`, `_stream_evidence`, `_validate_worktree_branch`, `_validate_worktree_optional_fields`, `_validated_executable`, `_validated_git_relative_path`, `_verify_versions`, `cli`, `command_plan`, `fingerprint_paths`, `freeze_input_inventory`, `git_snapshot`, `main`, `parse_arguments`, `parse_porcelain_status`, `parse_registered_worktrees`, `registered_worktree_roots`, `run_bounded_command`, `run_quality_gate`, `run_self_test`, `validate_external_cache`, `validate_managed_node`, `validate_release_arguments`, `validate_release_state`, `verify_exact_version`, `version_probes`. Mutmut keys retain their pinned `x_`/`xǁClassǁ` encoding; tests compare this literal oracle independently rather than deriving expectations from the implementation. In particular, any generated decorated-class downloader function is an unexpected extra and fails rather than silently widening the proof claim. Every `exit_code_by_key` value must be the exact integer `1`; a test fixture must use a canonical valid mutant name so status rejection is not accidentally proved by name rejection. Separately, the outer `mutmut run` process must be healthy exit `0`, within the declared deadline, with bounded complete process evidence; individual mutant code `1` never licenses a nonzero outer command.
- The mutation CLI reuses the already independently reviewed test-gate evidence implementation through a deliberately narrow public seam rather than copying it. `scripts/run_test_gate.py` exposes direct public aliases of the existing repository, raw-release, registered-worktree, descriptor-bound read/snapshot, external-output, Git-backed materialization, and post-materialization binding functions and their immutable evidence types; identical signatures are aliases, not branch-bearing wrappers, and raw file-descriptor traversal helpers remain private. Mutation-specific `setup.cfg` publication may keep its existing descriptor-safe writer, so the shared seam does not export a generic writer unless a persistent public RED proves that necessary. The trusted isolated child driver gains only one fixed `mutmut` mode and an explicit proof tuple for `mutmut==3.7.0`, `pytest==9.1.1`, and `coverage==7.15.4`; it imports and verifies every trusted tool before appending candidate roots, dispatches only the reviewed mutmut entry point under `-I -B`, and re-verifies exact versions/origins afterward. Legacy test-gate command behavior must remain regression-proven even if the shared driver bytes change. Candidate file/package shadows for mutmut, pytest, Coverage, `sitecustomize`, or `usercustomize`, or a wrong parent/child version or origin, fail. Do not add a second trusted-driver implementation, command-record schema, mutation-summary schema, process framework, suppression, or unrelated refactor. Before the mutation CLI consumes this seam, persistent tests must RED, the full test-gate focused/static/literal-self-coverage proof must return to its accepted state, and the narrow shared change must pass independent re-review.
- The mutation CLI is exactly `run_mutation_gate.py [--worktree ROOT --output-dir EXTERNAL_DIR] [--require-clean --candidate COMMIT] --targets ...` with real local adapters. It reuses `baseline_capture_io.run_bounded_process` for process containment and the already reviewed test-gate descriptor traversal, trusted-tool proof/isolated driver, external-output binding, and raw release Git/index/HEAD/ref/object evidence rather than creating a third framework. Parent and child must prove exact `mutmut==3.7.0` distribution/version/import origin, reject candidate `mutmut.py`/`mutmut/`/customizer shadows, and invoke the trusted module without candidate-first import resolution. Descriptor-relative no-follow materialization/inventory must bind and reverify the copied workspace, generated configuration, exact meta set and bytes, and closed external output before success. Release mode uses the same `GIT_OPTIONAL_LOCKS=0` raw-evidence bracket and candidate tree binding as the accepted test gate. Public CLI/adversarial/fault tests and literal 100% line/branch self-coverage are required; fake private objects, a second subprocess framework, or lint/type suppressions are not.

Implement and unit-test `run_test_gate.py` with injected command execution before using it. It invokes pytest and `diff-cover` as argv arrays with closed timeouts/output bounds, always writes a fresh externally contained `coverage.xml`, sets `COVERAGE_FILE`, pytest `cache_dir`, `PYTHONPYCACHEPREFIX`, and `--basetemp` into the same output root, verifies the report belongs to the externally materialized named source snapshot/commit, parses branch counters for every exact path in `security/coverage-policy.json`, and fails if the policy/report is malformed or `origin/main` is absent, shallow, or not an ancestor/merge-base suitable for changed-line measurement. The copy uses descriptor-relative no-follow traversal and an explicit include policy; compare the source snapshot digest before/after copying and testing, synthesize the external merge-base/snapshot commits without hooks, signing, credentials, or user Git configuration, and include regular untracked source/test/config files while rejecting symlinks/special files and excluding only reviewed generated/cache paths. Reject relative output paths, preexisting paths, symlinks, aliases/containment under any `git worktree list --porcelain` path, source writes or snapshot drift, and a report whose measured files escape the named root. It first collects the complete suite, classifies every node as deterministic or as an exact `live`, `staging`, or `container` gate ID, validates external nodes against `security/external-test-gates.json`, then runs the deterministic set with no skips/xfails; unknown markers, dynamic deselection, or an absent registry entry fails policy. No later task may substitute a focused suite for this post-task regression gate.

The same invocation must also write fresh `coverage.json`, verify XML/JSON snapshot identity and counters agree, and derive the changed branch arcs from the verified merge-base diff plus Coverage's branch-pair data. `coverage.xml` remains the input to `diff-cover`; it is not an arc oracle. Both reports and every cache/output stay in the one external output root.

- [ ] **Step 4: Run coverage and property suites**

Run: `.venv/bin/python -m pytest tests/property -q`
Run: `.venv/bin/python -m pytest tests/unit/test_mutation_gate.py tests/unit/test_test_gate.py -q`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/security.py src/nplg_mcp/tokens.py src/nplg_mcp/downloader.py src/nplg_mcp/storage.py src/nplg_mcp/errors.py scripts/delete_render.py scripts/smoke_live.py scripts/run_quality_gate.py`
Expected: PASS at 95% or higher for combined branch measurement, changed lines, and changed branch arcs, with at least 65% exact test-failure mutation kills over the closed generated inventory. Every closed decision module separately retains 100% branch coverage. An absent/shallow comparison base is a hard local failure; Task 8 separately wires sufficient CI history and the explicit base ref.

Phase 1 sequencing correction: Task 7 and Task 8 intentionally modify tracked
inputs covered by the frozen schema-v3 baseline manifest. Do not publish an
intermediate manifest merely to make it stale again. Before Task 8, require the
Task 7 property/unit suites, the real mutation gate, and their independent
reviews to pass. The only permitted deferred Task 7 result is the integrated
test gate failing solely at the exact frozen-manifest check; defer that test
gate and its branch/diff report to the one final post-Task-8 capture below. Any
other Task 7 failure remains a hard stop.

- [ ] **Step 5: Prepare checkpoint evidence**

Do not stage or commit in this implementation session. Record the exact changed-file inventory and fresh focused/integrated evidence for review while preserving the pre-existing index, refs, object database, and unrelated dirty work.

### Task 8: Add mandatory CI, supply-chain, and release evidence gates

#### Files

- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/security.yml`
- Create: `.github/dependabot.yml`
- Create: `SECURITY.md`
- Modify: `deploy/README.md`
- Create: `security/semgrep/rules.yml`, `security/semgrep/SHA256SUMS`
- Create: `security/toolchain-lock.json`
- Create: `security/dependency-risk-policy.json`
- Create: `security/trusted-package-sources.json`, `security/release-controller-policy.json`
- Modify: `security/coverage-policy.json`
- Modify: `tests/static/test_deployment.py`
- Modify: `tests/static/test_quality_policy.py`
- Create: `scripts/verify_release.py`, `tests/static/test_release_gate.py`
- Create: `scripts/bootstrap_external_tools.py`, `tests/unit/test_bootstrap_external_tools.py`
- Verify only: `.gitignore`, `pyproject.toml`, `requirements.in`, `requirements.lock`, `requirements-dev.in`, `requirements-dev.lock`, `requirements-security.in`, `requirements-security.lock`, `package.json`, `package-lock.json`, `security/bootstrap-toolchain-lock.json`
- Verify only unless Task 8 actually vendors new material: `THIRD_PARTY_NOTICES.md`

#### Entry gate

Task 8 source or test work starts only after the Task 7 property/unit suites,
real mutation evidence, and independent reviews are recorded in the status
ledger. Fresh integrated branch/diff evidence is also required unless its sole
blocker is the expected stale schema-v3 manifest described above; in that one
case it is deferred to the final Phase 1 capture and is not reported as passed.
Any other open Task 7 blocker stops Task 8 implementation.

#### Interfaces

- Produces CI jobs `lint`, `types`, `tests`, `contracts`, `package`, `sast`, `sca`, `sbom`, `secrets`, and `container` with uploaded digest-bound evidence artifacts. Produces typed `verify_release.py prepare ...`, `finalize ...`, `draft-attestation ...`, `attest ...`, and `eligibility ...` command scaffolds. The fail-fast orchestrator records every gate's argv, exit, duration, tool version, subject digest, and evidence digest without invoking deployment/signing/publication; Task 22 supplies the final profile manifests, one-use preparation challenge, operational import, and two-revision choreography. Every preparation, staging, custody, and verdict record includes the separately protected release-controller artifact/revision/policy digest; a candidate copy of `verify_release.py`, staging orchestration, or policy is untrusted input and can never be the privileged controller.
- Produces `verify_release.py source-snapshot --worktree ROOT --output NEW_JSON`, `assert-source-snapshot --worktree ROOT --snapshot JSON`, and `materialize-source --worktree ROOT --output NEW_DIR`. Snapshot modes descriptor-inventory every candidate path, including ignored/untracked entries, with type/mode/size/digest, while excluding only the closed tool/generated roots `.git`, `.venv`, `node_modules`, `.tools`, `.agents`, `.codex`, `.serena`, `.hypothesis`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, and root names beginning `.codex-request-`; near-miss names and ignored files elsewhere remain included. Materialization NUL-reads the clean candidate's regular tracked tree, rejects symlinks/submodules/specials, descriptor-copies it into a new external mode-`0700` directory, and verifies mode/blob/complete-inventory equality before atomic publication. All three reject traversal, malformed input, partial publication, or before/after change; their fake-filesystem tests are part of the Task 8 RED/GREEN microcycle. Package backends run only in that external materialized source, because `build --outdir` alone does not prevent backend `build/` or `*.egg-info` writes beside source.

`GateCommand`/`GateResult` plus the injected `CommandRunner` are the sole Task 8 execution seam. They reuse `baseline_capture_io.run_bounded_process` and the Task 7 snapshot/output primitives; no direct scanner shell command, candidate-controlled subprocess path, or third evidence/materialization framework is permitted.

#### Six bounded TDD batches

1. Static workflow/policy RED, including the exact pinned-Node quality-gate invocation and corrected file dispositions.
2. Thin external-tool adapter reusing `bootstrap_toolchain.install_from_lock`; prove archive/version/platform failures without network access.
3. Strict dependency, controller, scanner, and signed/fresh external-receipt models with adversarial parser tests.
4. Typed release runner reusing the accepted bounded-process and Task 7 snapshot/output seams; every checker is a `GateCommand`.
5. Workflows and `deploy/README.md`; protected-authority verbs remain scaffolds that fail `external_authority_required` locally.
6. Fresh integrated local gates plus independent review; record external requirements separately and stop before Phase 2.

#### Detailed acceptance criteria: static RED

Assert that candidate CI pins every third-party Action to a full peeled commit SHA and runs exact CPython patches 3.12.14, 3.13.15, and 3.14.7. `actions/checkout` always uses `persist-credentials: false`; repository-code jobs have no `id-token: write`, `ACTIONS_ID_TOKEN_REQUEST_*`, persisted `http.*.extraheader`, credential helper/token/file, or other GitHub credential. If provenance/custody needs OIDC, grant it only after candidate execution to an immutable reusable workflow/controller outside the candidate repository, protected environment/ref, and candidate-controlled YAML/scripts; issuer policy pins the exact `job_workflow_ref`, workflow commit/digest, repository owner, ref/environment, audience, and subject, and the candidate artifact is data only. A same-repository “separate job” is not a protected authority. Canary candidates prove they cannot request OIDC or read Git config/environment/credential files, and receipts bind the external workflow identity. Every patch must create a fresh environment, sync the identical 3.12-lower-bound universal `requirements-dev.lock` with `--require-hashes`, import every direct runtime/test dependency, install the once-built canonical wheel, assert its `Requires-Python` is `>=3.12,<3.15`, run its CLI smoke, and execute the suite; a resolution/import/test failure on any patch invalidates the compatibility claim. A separate scheduled non-release job may float to the latest 3.12/3.13/3.14 patches to warn about drift, but its result never substitutes for candidate evidence and any discovered newer patch requires a reviewed bootstrap/CI-lock update. CI also executes all strict gates, verifies at least 95% project branch, changed-line, and changed branch-arc coverage plus 100% branch coverage for every closed decision module, builds exactly one quarantined comparison wheel/sdist plus one canonical wheel/sdist, requires their reproducibility comparison before canonical digest selection, and preserves canonical test reports/SBOMs/provenance. Static policy rejects any build-system specifier/range, requires exact `setuptools==84.0.0` and `wheel==0.48.0` in both `[build-system].requires` and the hash lock, and rejects a package/release invocation missing `--no-isolation`. Require every exact development-tool pin to map to an executed local, CI, or release-manifest command; an installed-but-unused checker is a policy failure. Reject Semgrep `auto`, mutable registry aliases, an unverified rules digest, shallow history that makes diff coverage indeterminate, or any unexecuted required job. Test `verify_release.py` with injected fake runners: one failing command must stop the battery and no absent/skipped command may be reported as passed.

Before the behavior assertion, create typed, behavior-free release-runner and external-bootstrap scaffolds. The former exposes immutable `GateCommand`/`GateResult` values and an injected `CommandRunner` protocol; its execution method deliberately raises `NotImplementedError`. The bootstrap is only a thin adapter over `bootstrap_toolchain.install_from_lock`, not a second downloader/extractor. Prove both new test files collect before asserting behavior. Test the adapter with local fake archives for digest mismatch, archive traversal/symlink entries, wrong embedded version, unsupported platform, partial download, and atomic replacement; tests never need the network. Verify that `.gitignore` already excludes exactly `/.tools/`; do not rewrite it or add broad executable/archive ignores.

#### Required RED observation

Run: `.venv/bin/python -m pytest --collect-only tests/static/test_release_gate.py tests/unit/test_bootstrap_external_tools.py -q`
Run: `.venv/bin/python -m pytest tests/static/test_quality_policy.py tests/static/test_deployment.py tests/static/test_release_gate.py tests/unit/test_bootstrap_external_tools.py -q`
Expected: collection/imports PASS; focused assertions FAIL because required workflows/`SECURITY.md` are absent and the release runner is deliberately unimplemented, not because a tool or fixture cannot import.

#### Detailed workflow and security contract

Use least-privilege workflow permissions, concurrency cancellation, no pull-request secret exposure, immutable evidence retention, and this closed full-SHA Action inventory: `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1), `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` (v7.0.0), `actions/setup-node@820762786026740c76f36085b0efc47a31fe5020` (v7.0.0), `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (v7.0.1), `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` (v8.0.1), and `github/codeql-action@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd` (v4.37.7 peeled commit). `test_quality_policy.py` rejects an unlisted Action, a tag, annotated-tag object, short SHA, or name/SHA/version/peeled-identity mismatch; every listed Action must occur in a workflow.

Run actionlint plus zizmor workflow analysis, pip-audit, Bandit, exact-pinned Semgrep, gitleaks, CycloneDX, and Trivy. `security/toolchain-lock.json` is a closed schema with the following literal platform records (URL, SHA-256, checksum-manifest URL, checksum-manifest SHA-256):

Represent every scanner as a typed shell-free `GateCommand` with exact executable/version, argv, subject kind/digest, timeout/output ceiling, finding-versus-tool-error exit semantics, redacted JSON result schema, and offline advisory/rules/database identity. Bandit scans `src` and `scripts`; Semgrep scans the same roots using only the digest-verified local rule file; Gitleaks runs both `dir` on the exact materialized candidate and `git --log-opts=--all` on the verified full-history candidate repository; Trivy runs `filesystem` on the materialized source/SBOM and later `image` on each canonical digest with rebuild/pull disabled. Version-only, empty-subject, `--exit-zero`, skipped-rule, shallow-history, online-update, missing JSON, or finding/tool-error conflation is a policy failure. Controlled disposable canaries for Bandit shell execution, every local Semgrep rule ID, a synthetic Gitleaks credential, a known pinned vulnerable-package SBOM, a Trivy misconfiguration, and a canonical-image finding must make the owning gate fail; removing/replacing any scanner invocation must fail the static command inventory.

| Tool/platform | Exact official release URL | Artifact SHA-256 | Exact checksum manifest and SHA-256 |
| --- | --- | --- | --- |
| actionlint 1.7.12 Linux amd64 | `https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz` | `8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8` | `https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_checksums.txt`; `433028cf0ba3c42163ea1a668dedce30fcdbe84fe912b1a5e288c006eab8a4f5` |
| actionlint 1.7.12 Linux arm64 | `https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_arm64.tar.gz` | `325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6` | same manifest and digest |
| gitleaks 8.30.1 Linux x64 | `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` | `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt`; `061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae` |
| gitleaks 8.30.1 Linux arm64 | `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz` | `e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080` | same manifest and digest |
| Trivy 0.74.0 Linux 64-bit | `https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz` | `2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a` | `https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_checksums.txt`; `bc701c3c3ee8b9acbea2c23257e41381e3854888f51281616a6ba5dc96963821` |
| Trivy 0.74.0 Linux ARM64 | `https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz` | `b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5` | same manifest and digest |

No template URL or inferred asset name is permitted. The reviewed 2026-08-15 Trivy DB digest `sha256:6c572fd3cd13d8a53dd77769bae83f0e3d01845478d39ce2bf8c163bf01ec5f6` is retained only as stale historical audit evidence and is not an executable pin. A scan may consume only an externally acquired cache plus an independently signed receipt binding the immutable OCI digest, media/artifact types, signer policy, acquisition time, response digest, and a verified age of at most 24 hours. Candidate code cannot mint or refresh that receipt. Missing, stale, unsigned, or upstream-unattested evidence returns `TRIVY_DB_UPSTREAM_PROVENANCE_UNATTESTED` and the terminal verdict `do_not_release`; tag-only, auto-update, or network-during-scan behavior fails.

`bootstrap_external_tools.py` selects only an enumerated OS/architecture and delegates exact-host, digest, traversal, version, and atomic-install enforcement to `bootstrap_toolchain.install_from_lock`; unsupported platforms stop. Never execute a mutable download script, install Action wrapper, or PATH-global fallback. Semgrep runs only from the verify-only `requirements-security.lock` environment: `semgrep==1.173.0` with its required `mcp==1.29.0`, isolated from the main `mcp==2.0.0` environment, with interpreter/package origins and versions verified before and after execution. `security/semgrep/rules.yml` is a project-owned closed rule set with exact IDs `nplg.no-subprocess-shell`, `nplg.no-unverified-tls`, `nplg.no-unbounded-http-client`, `nplg.no-path-reopen-after-validation`, `nplg.no-secret-in-log`, and `nplg.strict-pydantic-boundary`; `security/semgrep/SHA256SUMS` records its digest and `test_quality_policy.py` rejects missing/extra IDs or digest drift. Updating rules is a reviewed code/policy change, not an implicit registry pull. The image scan fails on every applicable High/Critical finding regardless of fix availability unless revision-bound reachability analysis and a time-bounded reviewed exception with compensating controls exist in the ASVS matrix.

`security/dependency-risk-policy.json` is strict and versioned. It names approved advisory sources, snapshot/digest/freshness rules, owner and review cadence, and maximum triage/remediation windows: known-exploited or Critical findings 24 hours/7 days, High 3/30 days, Medium 14/90 days, and Low 30/180 days. Unknown severity, stale/unavailable source, package without provenance, or finding beyond its window is a release blocker. An exception requires a revision/subject-bound reachability analysis, owner, compensating controls, creation/expiry no longer than the underlying window, and separate verified risk acceptance; it can support only a named non-public staging/private `Risk accepted` verdict whose terminal recommendation is `do not release`, never public eligibility or ASVS L2 conformance. Candidate SCA captures exact pip/npm/Trivy source URL or OCI subject, acquisition time, response/database digest, scanner version/argv, package-lock identities, and raw-to-redacted evidence binding. Tests inject stale, truncated, replayed, unknown-source/severity, breached-package, expired-exception, and clock-rollback records and prove fail-closed behavior. `SECURITY.md` states these windows and the response/notification path; Dependabot is only discovery and never evidence that a finding was assessed or remediated.

`security/trusted-package-sources.json` closes dependency acquisition to exact approved identities: `https://pypi.org/simple` plus reviewed `files.pythonhosted.org` artifacts (or one separately named immutable mirror) and `https://registry.npmjs.org/`, with no ambient extra index, proxy, credential, registry override, or lock `resolved` host. Record Python wheel/sdist URL, hash, source/provenance, and npm resolved URL/integrity; unknown hosts/configuration fail before package code runs. A trusted prefetch step populates an external digest-verified wheel/npm cache, then every candidate build/test/install runs offline. Prefer wheels only; any unavoidable sdist builds in a separate no-secret/no-network sandbox before candidate execution, and hostile sdist plus `.pth`/`sitecustomize` canaries prove no credential visibility.

`security/release-controller-policy.json` is only the candidate's expected descriptor for an independently protected controller: exact controller artifact/revision/digest, protected authority, minimal independent dependency lock, closed command manifest, policy digest, isolation version, credential broker identities, and allowed outputs. Tests require the actual controller to be supplied from that protected authority and match the descriptor; repository code cannot select or replace it. The controller treats the candidate and its scripts as data, executes candidate build/tests with no deployment/OIDC/signing secrets and bounded/offline network, and loads short-lived least-privilege provider and MCP credentials only inside separately isolated trusted helper UIDs/containers. No parent or same-UID process visible to candidate code ever holds both credential classes; close inherited descriptors and test `/proc` parent-environment/FD access. A hostile candidate replacing `verify_release.py`/staging code, adding an sdist/`.pth`, or trying to emit a fabricated PASS must neither see secrets nor control the controller's verdict.

The final release runner performs source-only lint/type/schema checks first, then creates one noncanonical comparison build and one canonical package/image build from the same clean candidate commit in independent fresh external directories, each synchronized from the same preverified offline caches and hash locks and built with `python -m build --no-isolation`. Both builds use `SOURCE_DATE_EPOCH` equal to the candidate commit timestamp, `TZ=UTC`, a fixed UTF-8 locale, `PYTHONHASHSEED=0`, mode-`022` umask, a closed no-secret environment, and materialized tracked-file mtimes normalized to that epoch. The runner records raw artifact digests and separately compares a specified canonical archive-entry view; “normalized equality” without the exact algorithm is forbidden. It requires raw equality unless a reviewed format limitation names the permitted metadata normalization, then quarantines comparison artifacts from every scan, deploy, sign, SBOM, and provenance input. A mismatch fails before the canonical subject digest is selected. Only the canonical build is subsequently installed, scanned, deployed, signed, or attested, so no subject is rebuilt after digest selection. The runner creates a fresh test environment outside the checkout, syncs the hash-locked test dependencies, installs the canonical wheel with no editable/source install, clears `PYTHONPATH`, overrides the repository's pytest `pythonpath` setting to empty, and asserts `nplg_mcp.__file__` resolves inside that environment before running the applicable full/coverage suites. Scan, generate SBOMs for, and attest the exact canonical wheel/image digests. Container attack tests receive the already-built canonical image digest and run with `--no-build`; a Compose rebuild is a failure. Record both build environments/results, commit/tree, lock/source/controller-policy digests, workflow file digest, CI run/attempt, builder identity, canonical artifact digest, and provenance-attestation identity. Where the deployment provider exposes an immutable subject binding, the deployed digest must equal the tested/attested subject; otherwise the report must state that equality is unproven and cannot use it as ASVS evidence. Signing, registry publication, and production deployment remain separately authorized external actions.

#### Integrated local proof

Create a new external mode-`0700` output directory before running any build/report command; the directory must be outside every registered worktree and byte-snapshot the candidate before/after. All build, wheel-check, SBOM, cache, and report outputs below live there, never under `dist/`, the repository root, or an ignored source path.

After Task 8 source, tests, policies, workflows, and documentation are frozen,
run exactly one controlled `python -m scripts.capture_baseline --write` using
the already-tested preservation bracket. Then require
`python -m scripts.capture_baseline --check` and the deferred Task 7
`run_test_gate.py --compare-branch origin/main` invocation to pass on those
final Phase 1 bytes. Do not recapture again in this phase.

Run:

```bash
set -euo pipefail
set -o noclobber
export TASK8_OUTPUT_PARENT="$(realpath -e -- "${TASK8_OUTPUT_PARENT:?set a pre-created external mode-0700 parent}")"
test -d "$TASK8_OUTPUT_PARENT"
test "$(stat -c '%a' "$TASK8_OUTPUT_PARENT")" = "700"
while IFS= read -r -d '' worktree_record; do
  case "$worktree_record" in "worktree "*) registered_worktree="${worktree_record#worktree }" ;; *) continue ;; esac
  canonical_worktree="$(realpath -e -- "$registered_worktree")"
  case "$TASK8_OUTPUT_PARENT/" in "$canonical_worktree/"*) exit 1 ;; esac
done < <(git worktree list --porcelain -z)
export TASK8_OUTPUT="$(mktemp -d -p "$TASK8_OUTPUT_PARENT" nplg-task8.XXXXXXXX)"
chmod 700 "$TASK8_OUTPUT"
mkdir -m 700 "$TASK8_OUTPUT/build"
export REVIEWED_NODE="$(realpath -e -- "${REVIEWED_NODE:?set the Task 0-verified Node v24.19.0 executable}")"
.venv/bin/python -m pytest tests/static/test_quality_policy.py tests/static/test_deployment.py tests/static/test_release_gate.py tests/unit/test_bootstrap_external_tools.py -q
.venv/bin/python scripts/verify_release.py local-gates --worktree . --output "$TASK8_OUTPUT/run" --node-executable "$REVIEWED_NODE" --compare-branch origin/main
```

The typed runner asserts exact actionlint 1.7.12, gitleaks 8.30.1, Trivy 0.74.0, and hash-locked Bandit/Semgrep versions and origins. It accepts Trivy data only from an external cache matching the signed/fresh receipt and then scans offline. CI adds full-history Gitleaks; Task 22 later adds digest-only image scans under the same command policy. Verify the existing `/.tools/` ignore and exact zizmor lock pin without modifying either. `deploy/README.md` must describe immutable-digest/offline scans and the external receipt, and remove connected/tag-only/`--ignore-unfixed` guidance. The output inventory and candidate-byte invariants remain mandatory.

Expected locally: all locally authoritative checks PASS, while eligibility remains `do_not_release` with `external_authority_required` until exact-three-minor CI, protected required-check evidence, a signed/fresh Trivy DB receipt, and protected-controller/OIDC custody evidence are supplied. No local command may report those absent checks as passed.

#### Authorized future checkpoint

After explicit authorization, stage only the Task 8 workflow/policy files, `deploy/README.md`, pinned Semgrep rules/digest, `security/coverage-policy.json`, external-tool adapter/tests, `scripts/verify_release.py`, and static-test paths. Do not stage `.tools/`, verify-only locks/manifests, `.gitignore`, or `THIRD_PARTY_NOTICES.md` unless actual vendoring changed its inventory. Then: `git commit -m "ci: enforce strict release evidence"`.

**Phase 1 local exit gate:** full repository Ruff/Pyright/mypy gates are clean, branch-enabled project, changed-line, and changed branch-arc coverage are each at least 95%, every closed decision module has 100% branch coverage, and the CI/security workflow and policy files pass their local static/adversarial checks. Protected required-check state, exact-three-minor CI results, signed/fresh Trivy DB custody, protected-controller/OIDC evidence, signing, publication, deployment, and ASVS closure remain external authority and keep release eligibility `do_not_release`; Phase 2 does not begin as part of this task.

---

## Phase 2 — Strict Runtime and Cross-language Contracts

> **Phase 2 audit reconciliation (2026-08-21):** The Task 9–10 implementation,
> including the TDD repairs identified during its review rounds, was independently
> reassessed against the current staged sources. Focused contract and schema-oracle
> suites, the repository test/coverage gate, documentation lint, and both targeted
> mutation gates passed without changing the staged index. The required exact full
> quality gate and full installed-wheel PEP 561 consumer gate remain unverified in
> this environment because the locked Node v24.19.0 executable is absent; the
> available v24.18.0 executable is correctly rejected by the digest check. Treat
> Phase 2 as implemented but not fully verification-closed, do not mark its exit
> gate satisfied, and do not use it as a Phase 3 predecessor until the locked
> toolchain gates are rerun. Historical RED command output also remains a
> provenance limitation; current mutation/fault evidence does not replace it.

### Task 9: Add strict input/output models and a typed tool catalog

#### Files

- Create: `src/nplg_mcp/contracts/__init__.py`, `src/nplg_mcp/contracts/base.py`, `src/nplg_mcp/contracts/inputs.py`, `src/nplg_mcp/contracts/outputs.py`, `src/nplg_mcp/contracts/catalog.py`, `src/nplg_mcp/py.typed`
- Modify: `pyproject.toml`
- Create: `src/nplg_mcp/services.py`
- Create: `src/nplg_mcp/profiles.py`
- Modify: `src/nplg_mcp/tools.py`
- Modify: `src/nplg_mcp/protocol.py` during the compatibility period
- Modify: `tests/conftest.py`, `tests/helpers/app_factory.py`
- Create: `tests/contracts/test_pydantic_contracts.py`
- Create: `tests/property/test_contract_properties.py`
- Modify: `tests/unit/test_tools.py`

#### Interfaces

- Produces:

```python
@dataclass(frozen=True, slots=True)
class MonotonicDeadline:
    created_at: float
    expires_at: float

    def __post_init__(self) -> None:
        for field_name, value in (
            ("created_at", self.created_at),
            ("expires_at", self.expires_at),
        ):
            if type(value) is not float or not math.isfinite(value) or value < 0.0:
                raise ValueError(f"{field_name} must be a finite nonnegative float")
        budget = self.expires_at - self.created_at
        if budget < 0.0 or budget > 60.0:
            raise ValueError("deadline budget must be between 0 and 60 seconds")

    @classmethod
    def after(
        cls,
        budget_seconds: float,
        *,
        clock: Callable[[], float],
    ) -> Self:
        if (
            type(budget_seconds) is not float
            or not math.isfinite(budget_seconds)
            or not 0.0 <= budget_seconds <= 60.0
        ):
            raise ValueError("budget_seconds must be a finite float from 0 to 60")
        created_at = clock()
        return cls(created_at=created_at, expires_at=created_at + budget_seconds)

    def remaining(self, *, now: float) -> float:
        if type(now) is not float or not math.isfinite(now) or now < 0.0:
            raise ValueError("now must be a finite nonnegative float")
        if now < self.created_at:
            raise ValueError("monotonic clock moved backwards")
        return max(0.0, self.expires_at - now)

class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
        revalidate_instances="always",
        validate_default=True,
        hide_input_in_errors=True,
        frozen=True,
    )

class StrictInput(StrictModel): ...
class StrictOutput(StrictModel): ...

class DeploymentProfile(StrEnum):
    ALPIC_METADATA = "alpic-metadata"
    PRIVATE_FULL = "private-full"
    DISTRIBUTED_FULL = "distributed-full"

class ToolAnnotations(StrictModel):
    read_only_hint: bool
    destructive_hint: bool
    idempotent_hint: bool
    open_world_hint: bool

@dataclass(frozen=True, slots=True)
class ToolDefinition[InputT: StrictInput, OutputT: StrictOutput]:
    name: str
    title: str
    description: str
    input_model: type[InputT]
    output_model: type[OutputT]
    handler: Callable[[InputT], Awaitable[OutputT]]
    annotations: ToolAnnotations
    profiles: frozenset[DeploymentProfile]

    async def invoke(self, arguments: Mapping[str, object]) -> OutputT:
        parsed = self.input_model.model_validate(dict(arguments), strict=True)
        untrusted_output = await self.handler(parsed)
        return self.output_model.model_validate(untrusted_output, strict=True)

class RegisteredTool(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def input_model(self) -> type[StrictInput]: ...

    @property
    def output_model(self) -> type[StrictOutput]: ...

    async def invoke(self, arguments: Mapping[str, object]) -> StrictOutput: ...

class ToolCatalog:
    def __init__(self, definitions: tuple[RegisteredTool, ...]) -> None: ...
    async def call(self, name: str, arguments: Mapping[str, object]) -> StrictOutput: ...
```

`ToolDefinition.invoke` is the only generic-erasure boundary: it strictly validates an untouched argument mapping into `InputT`, invokes the typed handler, and revalidates the untrusted runtime return into `OutputT`. The heterogeneous `RegisteredTool` view exposes its model members as read-only properties, so specific `type[InputT]`/`type[OutputT]` members satisfy Pyright and mypy covariance rules without writable-protocol unsoundness or `Any` casts.

Every timeout-bearing runtime protocol imports `MonotonicDeadline` from `contracts.base`; raw floats never cross executor, scanner, upstream-guard, or audit-sink interfaces. Construct it only from an injected monotonic clock and a strict 0-60 second budget. At every ingress, compute `remaining(now=clock())`, reject zero/expired before side effects, and pass only that bounded remainder to the underlying timeout primitive. Table/property tests reject bool, int, string, negative, NaN, both infinities, over-60-second budgets, nonmonotonic endpoints, invalid clocks, and prove exact zero/60-second plus just-expired behavior.

`services.py` owns `MetadataServices` and `FullServices` protocols plus their concrete composition records; neither `app.py` nor `mcp_server.py` owns the shared service type. Metadata composition has no optional PDF/store hole, and full composition requires those services. This prevents the SDK/app import cycle and makes Task 19's non-construction guarantee type-checkable.

Declare the distribution PEP 561 typed: package the exact zero-byte `src/nplg_mcp/py.typed` marker, require it in sdist/wheel inventories, and reject duplicate/misplaced markers. In a clean external consumer project with no source checkout on `PYTHONPATH`, install the canonical wheel and type-check representative public contract/catalog imports under both Pyright and mypy; delete a public annotation or the marker in deliberate-fault copies and prove each consumer gate fails.

- Output models: `SearchDocumentsOutput`, `DocumentMetadataOutput`, `DocumentFilesOutput`, `DownloadDocumentOutput`, `PdfInspectionOutput`, `RenderPagesOutput`, `RenderTilesOutput`, `RenderManifestOutput`, plus strictly typed nested record/file/page/tile/provenance models.
- `ToolService.call(name: str, arguments: Mapping[str, object]) -> StrictOutput` validates both arguments and handler output.

- [ ] **Step 1: Write the failing catalog tests**

```python
from collections.abc import Awaitable, Callable
from typing import Annotated, cast

from pydantic import Field, ValidationError


class FiniteScoreOutput(StrictOutput):
    score: Annotated[
        float,
        Field(strict=True, allow_inf_nan=False, ge=0.0, le=1.0),
    ]


def _search_catalog(
    handler: Callable[[SearchDocumentsInput], Awaitable[SearchDocumentsOutput]],
) -> ToolCatalog:
    definition = ToolDefinition[SearchDocumentsInput, SearchDocumentsOutput](
        name="search_documents",
        title="Search",
        description="Search fixture",
        input_model=SearchDocumentsInput,
        output_model=SearchDocumentsOutput,
        handler=handler,
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=True,
        ),
        profiles=frozenset({DeploymentProfile.ALPIC_METADATA}),
    )
    return ToolCatalog((definition,))


def test_every_tool_declares_closed_input_and_output_schemas(
    tool_service: ToolService,
) -> None:
    for tool in tool_service.list_tools():
        assert tool["inputSchema"]["additionalProperties"] is False
        assert tool["outputSchema"]["additionalProperties"] is False


async def test_invalid_handler_output_is_rejected_without_leaking_values() -> None:
    async def invalid_handler(_: SearchDocumentsInput) -> SearchDocumentsOutput:
        return cast(SearchDocumentsOutput, {"unexpected": "secret-value"})

    catalog = _search_catalog(invalid_handler)
    with pytest.raises(AppError) as raised:
        await catalog.call("search_documents", {"query": "x"})
    assert "secret-value" not in str(to_public_error(raised.value))


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_output_is_rejected(value: float) -> None:
    with pytest.raises(ValidationError):
        FiniteScoreOutput(score=value)


async def test_constructed_or_nested_invalid_model_is_revalidated() -> None:
    invalid = SearchDocumentsOutput.model_construct(results=[{"unexpected": "canary"}])

    async def constructed_handler(_: SearchDocumentsInput) -> SearchDocumentsOutput:
        return invalid

    with pytest.raises(AppError) as raised:
        await _search_catalog(constructed_handler).call(
            "search_documents",
            {"query": "x"},
        )
    assert "canary" not in str(to_public_error(raised.value))
```

Add the shown imports to `tests/contracts/test_pydantic_contracts.py` together with explicit imports for `math`, `pytest`, and every referenced project symbol; no fixture or helper is implicit. Task 9 updates the Task 0 shared factory so `app_services` is annotated as the concrete metadata composition satisfying `MetadataServices`, while `tool_service` is annotated as `ToolService`.

Freeze one public JSON-integer policy before modelling fields. All contract integers are bounded to JavaScript's exact safe range `[-9007199254740991, 9007199254740991]`; bool and strings always fail. Because JSON Schema and JavaScript treat `1`, `1.0`, and `1e0` as the same mathematical integer while strict Pydantic distinguishes their Python decoder types, use one narrow audited pre-validator for the shared safe-integer alias that accepts only finite `int` or mathematically integral `float` values in range and canonicalizes them to `int`. It accepts `-0`/`-0.0` as canonical zero and rejects fractional, non-finite, bool, string, and out-of-range values. Add raw-wire and direct-model cases for `1`, `1.0`, `1e0`, `-0`, `-0.0`, `true`, `"1"`, and every value at/around `±(2^53-1)`, `±2^53`, and `±(2^53+1)`; Pydantic, Draft 2020-12 validation, Zod, SDK HTTP, and canonical serialization must agree. Larger integer identities use bounded canonical decimal strings, never JSON numbers.

Prove that `frozen=True` is only the outer guard: pass caller-owned nested lists/mappings into validation, retain aliases in a malicious handler, mutate them before and after return, and assert the validated/canonical serialized response never changes. Contract collections use tuples/frozensets and one immutable mapping representation where semantics allow; otherwise the boundary makes a deep JSON-owned snapshot immediately after validation. Every nested model must inherit `StrictModel`, and no mutable reference from raw arguments or handler output may survive into catalog state or a response.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/contracts/test_pydantic_contracts.py tests/unit/test_tools.py -q`
Expected: collection/imports PASS through the typed scaffolds; the focused assertions FAIL because the current handlers return dictionaries and the scaffold has no validated output contract.

- [ ] **Step 3: Move inputs and model every frozen output**

Derive field names and bounds from the frozen fixtures, not from convenience. Use constrained strings for IDs, handles, media types, resource URIs, hashes, and relative paths; use the safe-integer alias above for every public integer; reject non-finite floats; cap collection sizes, string sizes, and nested diagnostic counts. Apply the strict config to every nested contract model. Set Pydantic's regex engine explicitly and restrict every cross-language pattern to a statically enforced audited intersection: ASCII character classes, explicit full anchors, bounded quantifiers, and no lookaround, backreferences, engine-specific Unicode modes, catastrophic ambiguity, or unsupported escapes. Run every pattern's positive/negative boundary corpus through Pydantic/Rust regex, JavaScript/Zod, and Draft 2020-12 validation. Treat upstream metadata as inert data: prohibit control/bidi characters not explicitly allowed by field policy, never interpolate it into tool descriptions, headers, errors, or URIs, and preserve source/provenance labels. Validate every handler return through the declared `output_model.model_validate(result, strict=True)` even when it is already a model instance; immediately take the deep owned immutable/canonical snapshot, then serialize it with `model_dump(mode="json", by_alias=True)` and a JSON encoder configured with `allow_nan=False`, depth/member/byte ceilings, and no custom lossy fallback.

- [ ] **Step 4: Run contract, service, and baseline suites**

Run: `.venv/bin/python -m pytest tests/contracts/test_pydantic_contracts.py tests/property/test_contract_properties.py tests/unit/test_tools.py tests/contracts/test_frozen_baseline.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/contracts/base.py src/nplg_mcp/contracts/inputs.py src/nplg_mcp/contracts/outputs.py src/nplg_mcp/contracts/catalog.py src/nplg_mcp/tools.py`
Expected: PASS; schemas include closed output definitions and frozen semantic values are unchanged.

- [ ] **Step 5: Commit checkpoint**

Stage contracts, `services.py`, `profiles.py`, `tools.py`, compatibility `protocol.py`, the shared typed factories, and tests, then: `git commit -m "feat: validate strict tool outputs"`.

### Task 10: Export deterministic JSON Schema and add the Zod 4 oracle

#### Files

- Create: `src/nplg_mcp/contracts/schema.py`
- Create: `scripts/export_contracts.py`
- Create: `contracts/generated/tool-contracts.schema.json`
- Create: `contracts/generated/schema-manifest.json`
- Create: `contracts/zod/models.ts`
- Create: `contracts/zod/contract.test.ts`
- Modify: `package.json`, `package-lock.json`
- Modify: `tsconfig.contracts.json`, `eslint.config.mjs` (created and initially
  owned by Task 1's baseline-only strict closure)
- Create: `.markdownlint-cli2.mjs`
- Create: `tests/contracts/test_zod_contracts.py`
- Modify: `.github/workflows/ci.yml`, `.github/workflows/security.yml`
- Modify: `tests/static/test_quality_policy.py`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-14-nplg-dspace-mcp-implementation.md`
- Modify: `docs/superpowers/specs/2026-08-14-nplg-dspace-mcp-design.md`

#### Interfaces

- Produces: recursive aliases `JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]` and `JsonObject = dict[str, JsonValue]`, `export_contract_schemas() -> dict[str, JsonObject]`, the exact aggregate file `contracts/generated/tool-contracts.schema.json`, `contracts/generated/schema-manifest.json`, and Node commands `npm run contracts:lint`, `npm run contracts:typecheck`, `npm run contracts:test`, and `npm run docs:lint`. The aggregate is one Draft 2020-12 schema resource with one versioned top-level `$id`, separate root-local `input` and `output` `$defs`, and an exact sorted key for every `ToolCatalog` model; embedded definitions must not declare nested `$id` values that rebase local `$ref`s. The exporter fails on a missing, extra, duplicate, renamed, non-`StrictInput`/`StrictOutput` model, unsupported keyword, unknown format, or any other file below `contracts/generated/`.

- The aggregate root contains exactly one `"$schema": "https://json-schema.org/draft/2020-12/schema"`; no embedded `$defs` node may redeclare `$schema`. The dialect URI, location, and value participate in canonical bytes and the manifest digest. Tests reject an absent, duplicate, nested, alternate, normalized-away, or post-digest dialect marker before any forced local validator is allowed to count as evidence.
- Produces one audited TypeScript `codePointString(minimum, maximum)` builder. Runtime acceptance uses only an `Array.from(value).length` code-point refinement; project-owned contract models statically forbid native Zod string `.min()`, `.max()`, and `.length()` because Zod 4.4.3 counts UTF-16 code units. A closed exporter registry records the builder's exact schema pointer and injects only its reviewed `minLength`/`maxLength` integers after Zod conversion and before canonicalization. Unknown pointers, duplicate/conflicting keywords, a native Zod length check, or runtime/exported-bound disagreement fails.

- [ ] **Step 1: Write failing semantic-parity tests**

First add `zod@4.4.3`, `typescript@6.0.3`, `eslint@10.8.1`, `@eslint/js@10.0.1`, `typescript-eslint@8.67.0`, `@types/node@24.13.3`, and `markdownlint-cli2@0.23.2` as exact development pins, regenerate `package-lock.json`, run `npm ci --ignore-scripts`, and add only type-checkable exporter/oracle scaffolds. Prove `npm run contracts:typecheck` and Python `--collect-only` succeed before the semantic assertion runs.

Make `npm run docs:lint` invoke locked markdownlint-cli2 over the exact repository-owned roots `*.md`, `docs/**/*.md`, `deploy/**/*.md`, and `skills/**/*.md`. The static policy compares those globs with NUL-safe `git ls-files -z --cached --others --exclude-standard -- '*.md'` in the isolated task worktree and fails if any first-party Markdown is omitted; only the exact reviewed third-party/generated notice paths may be excluded. It therefore ignores ambient ignored tool state such as `.serena/` without creating a broad repository exemption. If the user-owned staged architecture handoff has since entered the task's committed base, stop and add it to a separately reviewed write set—never edit or restage the current primary-checkout copy implicitly.

Freeze the shared corpus before implementing either model. Every versioned entry records a requirement ID, mode (`input` or `output`), raw lexical JSON when lexical distinctions matter, parsed value, normative expected accept/reject verdict, expected normalized value or bounded error class, and the exact bound/keyword exercised. It contains valid minimum/maximum values and invalid unknown fields, coercions, blank/normalization-confusable Unicode, disallowed bidi/control characters, overlong strings/arrays, duplicate IDs, the complete safe-integer lexical/boundary set from Task 9, NaN/Infinity/overflow encodings, deep nesting, and oversized diagnostic lists. Add BMP, one/multiple astral-code-point, combining-mark, and grapheme-cluster boundaries at `N-1`, `N`, `N+1`; validate them through `codePointString` and its injected JSON Schema keywords, never a native Zod string length check. Pydantic, Zod runtime, and the closed Draft 2020-12 validator must each match the frozen expected result independently before their results are compared. Agreement alone is not an oracle.

Recursively assert that every intended object node has `additionalProperties: false` and every `$ref` is root-local. `Draft202012Validator.check_schema` is metaschema proof only. Build a closed `referencing.Registry` containing the one aggregate resource, refuse all retrieval callbacks/network access, and validate named positive and negative sentinels through the root and every `$defs` pointer. Inventory every emitted `format`; instantiate an explicit allowlisted `FormatChecker`, require its implementation/dependency pin, reject unknown/unavailable formats, and add at least one negative instance per format. A security property must use an explicit project validator/pattern rather than depend solely on optional `format` behavior. Expose the corpus comparison as a reusable test runner so Tasks 11 and 22 can feed it exact in-memory and deployed `Client.list_tools()` schemas after the SDK exists.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/contracts/test_zod_contracts.py -q`
Run: `npm run docs:lint`
Expected: Python and Node collection/type loading PASS through behavior-free scaffolds; the focused semantic-parity assertion FAILS because no exported schema/oracle result exists. Independently, docs lint reaches the intended audited content RED: `README.md` fails `MD060`, the historical plan fails `MD028`, and the historical design fails `MD034`; an install/glob/config error is the wrong RED.

- [ ] **Step 3: Complete the locked test-only TypeScript project**

Pin `zod@4.4.3`, `typescript@6.0.3`, `eslint@10.8.1`, `@eslint/js@10.0.1`, `typescript-eslint@8.67.0`, `@types/node@24.13.3`, and `markdownlint-cli2@0.23.2` exactly with `package-lock.json`. TypeScript 7.0.2 is newer but outside `typescript-eslint@8.67.0`'s supported `<6.1.0` range, so using it would make the strict type-aware linter gate unsupported. Revalidate this compatibility boundary when any pin changes.

Set `module = "NodeNext"`, `moduleResolution = "NodeNext"`, `noEmit = true`, `verbatimModuleSyntax = true`, `noUncheckedSideEffectImports = true`, `forceConsistentCasingInFileNames = true`, `types = ["node"]`, and enable `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `noImplicitReturns`, `noFallthroughCasesInSwitch`, `noPropertyAccessFromIndexSignature`, and `useUnknownInCatchVariables`. Keep `package.json` at `"type": "module"`, use an exact `files`/`include` inventory limited to the contract project, and pin ESLint `tsconfigRootDir` to the repository root. Negative fixtures for an unresolved side-effect import, wrong-case path, accidental emit, ambient type, and unlisted source must fail. Configure ESLint's flat config with `strictTypeChecked` and `stylisticTypeChecked`, project service/type information, zero warnings, and all `no-unsafe-*`, promise, exhaustiveness, and unnecessary-condition rules; every exception is narrow, explained, and asserted by the static policy test.

Explicitly require `@typescript-eslint/no-explicit-any = "error"` and `@typescript-eslint/no-unsafe-type-assertion = "error"` in addition to the presets. Negative fixtures for an explicit/aliased `any`, unsafe assertion, double assertion through `unknown`, unchecked parsed JSON, and an unhandled discriminated-union member must fail typecheck/lint; an empty or broad ESLint override is a policy failure.

Configure markdownlint-cli2 with all stable default rules, sibling-aware repeated-heading checks, fenced-code language/style checks, and no broad directory bypass. Disable only `MD013` because long source links/commands are not safely reflowable; exclude generated schemas and third-party/vendored notices by exact path, and assert those exceptions in the static policy test.

Repair the three named existing Markdown files mechanically: normalize the README table separator, remove the blank blockquote split without changing its text, and wrap each historical-design bare URL as an equivalent autolink or descriptive link. Run the focused Markdown gate immediately after this formatting-only RED/GREEN microcycle and inspect the semantic diff. Do not reword historical decisions or absorb the staged architecture handoff.

Define models with `z.strictObject()` independently from Pydantic. Export separate Pydantic Draft 2020-12 input schemas with `mode="validation"` and output schemas with `mode="serialization"`; compare them respectively with Zod `io: "input"` and default output conversion. General schema “semantic equality” is not an executable oracle. Define a closed supported-keyword vocabulary and one exact canonicalization algorithm: UTF-8 without Unicode normalization, recursively sorted keys, fixed separators, `allow_nan=False`, final LF, and only an enumerated removal of presentation-only `title` keys. Reject every unknown keyword/transformation, require byte-exact equality of the resulting canonical structures plus bidirectional corpus decisions, and write for each schema `(top-level $id, JSON pointer, normalized SHA-256, Pydantic version, Zod version, exporter version)` to the strict sorted manifest. Configure Zod JSON Schema conversion for Draft 2020-12 with unrepresentable types and cycles set to throw; a lossy conversion is a failed gate. Validate the actual `model_dump(mode="json", by_alias=True)` value against the advertised output schema. Forbid untested serializers, transforms, coercion, computed fields, and defaults that make input/output semantics diverge.

The sole additional post-conversion transformation is the closed `codePointString` registry's insertion of integer `minLength`/`maxLength` at its predeclared pointers. Perform and validate that injection before the presentation-only `title` removal; include both operations in the exporter version and canonical manifest. No metadata object, arbitrary callback, or unregistered schema pointer may add a keyword.

Self-test the independent oracle rather than trusting agreement: in private temporary copies, deterministically remove one `z.strictObject`, required field, bound, alias, safe-integer check, code-point runtime refinement, injected `minLength`/`maxLength`, root `$schema`, and input/output mode selection; each mutation must make the Python launcher fail for the named reason. Add a common-mode mutant that changes the same Pydantic and Zod bound to the same wrong value; the frozen normative corpus must still fail it. Also reject malformed runner JSON, wrong protocol version, timeout, nonzero exit, missing/extra tool, and duplicate schema key. Export twice in clean subprocesses with different `PYTHONHASHSEED`, locale/TZ, and permuted catalog-registration order; byte-compare both schema and manifest outputs. Extend the existing CI `contracts` job to install locked Node 24, run all four Node gates, and upload the generated-schema/manifest diff evidence; extend SCA/SBOM coverage to `package-lock.json`.

- [ ] **Step 4: Run both authorities**

Run: `npm ci --ignore-scripts`
Run: `npm run contracts:lint`
Run: `npm run contracts:typecheck`
Run: `npm run contracts:test`
Run: `npm run docs:lint`
Run: `.venv/bin/python scripts/export_contracts.py --check`
Run: `.venv/bin/check-jsonschema --check-metaschema contracts/generated/tool-contracts.schema.json`
Run: `.venv/bin/python -m pytest tests/contracts/test_zod_contracts.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/contracts/schema.py scripts/export_contracts.py`
Expected: all PASS; generated Pydantic and independent Zod schemas agree semantically; all closed object nodes remain closed; npm is absent from runtime/image dependencies.

- [ ] **Step 5: Commit checkpoint**

Stage the schema code, exact `contracts/generated/tool-contracts.schema.json`, locked Node files, CI/security workflow changes, static policy, the three explicitly owned Markdown repairs, and tests, then: `git commit -m "test: add Zod 4 contract oracle"`.

**Phase 2 exit gate:** every tool has closed input and output schemas, every runtime result is Pydantic-validated, and independent Zod/Pydantic fixture decisions match.

---

## Phase 3 — Official MCP Python SDK and Wire Cutover

### Task 11: Pin the official SDK and register the typed server

#### Files

- Modify: `pyproject.toml`, `requirements.in`, `requirements.lock`
- Create: `src/nplg_mcp/mcp_server.py`, `src/nplg_mcp/sdk_boundary.py`
- Modify: `security/coverage-policy.json`
- Create: `tests/contracts/test_sdk_client.py`, `tests/contracts/test_sdk_boundary.py`

#### Interfaces

- Produces: `create_mcp_server(services: MetadataServices | FullServices, profile: DeploymentProfile) -> Server[None]`; service protocols come only from `services.py`, and the explicit server lifespan yields `None` because the outer application owns service lifetime.
- Uses the official `from mcp.server import Server` low-level API with constructor-supplied `on_list_tools`, `on_call_tool`, `on_list_resources`, `on_list_resource_templates`, and `on_read_resource` handlers. Resource handlers return the exact official `ListResourcesResult`, `ListResourceTemplatesResult`, and `ReadResourceResult` models. This is the documented SDK seam for exact schemas and exact result objects; do not use decorator-derived argument models or provisional `ServerMiddleware` as a correctness/security boundary.
- Freezes the first-release cache policy for every complete discovery/list/read result at `ttlMs: 0` and `cacheScope: "private"`; no result is shareable across principals, and no intermediary freshness assumption is implicit.
- Produces a closed `SdkHandlers` object whose callables use `ServerRequestContext[None]` plus the exact official request/result types. `on_call_tool` reads `CallToolRequestParams.name` and the untouched `arguments` mapping, selects the catalog input model by exact tool name, and calls `model_validate(arguments, strict=True)` before handler entry. `on_list_tools` projects the immutable catalog's canonical input/output schemas into explicit official `Tool` result models. Resource/list/template/read projection is likewise constructor-bound and returns explicit `ListResourcesResult`, `ListResourceTemplatesResult`, and `ReadResourceResult`; a static/mutation test rejects any decorator registration or omitted constructor handler. The low-level SDK intentionally advertises but does not apply `Tool.input_schema`, so handler-side Pydantic validation and output revalidation are mandatory and tested. Official protocol models are the only permitted untyped edge; prohibit `Any` from project-owned models and service handlers, and isolate any unavoidable checker suppression to one documented adapter declaration with an upstream link.
- Removes the low-level `Server` constructor's default `OpenTelemetryMiddleware` immediately and statically asserts the complete SDK middleware tuple is empty for the first release. The pinned default can record `str(exception)` and accept ambient trace context, so it is not an approved audit/telemetry channel. A future project-owned sanitized tracing layer requires its own threat model and TDD task; do not inherit ambient OTel exporters or configuration.

- [ ] **Step 1: Write the failing official-client test**

First pin `mcp==2.0.0` and its matching `mcp-types==2.0.0`. Reconcile the SDK's separate transport stack explicitly: update the incompatible existing `idna==3.17` pin to reviewed `idna==3.18`, add exact `httpx2==2.9.0`, `httpcore2==2.9.0`, and `truststore==0.10.4`, and represent every remaining environment-marked `mcp`/`mcp-types` `Requires-Dist` dependency as an exact compatible hash-locked entry. Preserve the separate `httpx==0.28.1`/`httpcore==1.0.9`/certifi project-upstream stack. Regenerate/sync the 3.12-lower-bound universal hash lock, then add only the typed `services.py`-based `create_mcp_server`/`SdkHandlers` scaffolds. Prove `.venv/bin/python -m pytest tests/contracts/test_sdk_client.py --collect-only -q` succeeds before running the behavioral test.

Add a metadata policy test that reads the installed distributions' `Requires-Dist`, evaluates every marker for the supported 3.12/3.13/3.14/platform matrix, and proves each selected SDK dependency has exactly one compatible lock entry and hash. Forbid `httpx2.alias_httpx()` and any `sys.modules` aliasing. In both import orders, prove `httpx` and `httpx2` module identities, client/transport classes, exception hierarchies, and monkeypatch targets remain distinct. Run one minimal-container TLS request through the official SDK client to prove HTTPX2's OS trust-store behavior; no project `certifi` success may be misreported as that proof.

```python
@pytest.mark.asyncio
async def test_official_client_lists_strict_metadata_tools(
    app_services: MetadataServices,
) -> None:
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)
    async with Client(server, mode="2026-07-28") as client:
        result = await client.list_tools()
    assert [tool.name for tool in result.tools] == [
        "get_document_metadata",
        "list_document_files",
        "search_documents",
    ]
    assert all(tool.output_schema is not None for tool in result.tools)
    wire = result.model_dump(mode="json", by_alias=True)
    assert wire["ttlMs"] == 0
    assert wire["cacheScope"] == "private"
```

Add one default `Client(server)` test that exercises `server/discover` and asserts a nonempty `client.session.discover_result`; a client pinned to `mode="2026-07-28"` deliberately skips discovery and cannot prove it. Add separate forced `mode="2026-07-28"` and `mode="legacy"` cases—`mode="2025-11-25"` is not a supported SDK selector. Send an unknown top-level key, a misspelled key, stringified JSON for a non-string parameter, a boolean where an integer is required, and a nested unknown key. Each must be rejected before handler entry. Seed argument and exception canaries and assert no `CallToolResult` content contains either value. Assert every complete modern discovery/list result serializes explicit `ttlMs` and `cacheScope`, with the frozen `0/private` policy, and paginated results never change scope between pages. Feed the exact `Client.list_tools()` schemas from modern and legacy modes into Task 10's independent Zod runner. Task 13 must repeat these cases over real Streamable HTTP because in-memory `Client(server)` does not prove JSON framing or ASGI behavior.

These Task 11 in-memory clients are explicitly auth-disabled catalog/serialization fixtures; they prove no authenticated production behavior and must not call `get_access_token()`. Task 20 replaces the construction seam with an explicit, no-default principal source: production uses only the SDK request context over the real Streamable HTTP application, while the in-memory catalog fixture receives a governed test-only principal source that is excluded from every wheel/deploy pack. No direct `Client(server)` result may be cited as authentication, scope, request-context, or transport evidence.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/contracts/test_sdk_client.py -q`
Expected: the newly pinned SDK imports and test collection PASS; the focused call reaches the typed `create_mcp_server` scaffold and FAILS with its deliberate `NotImplementedError`.

- [ ] **Step 3: Add explicit registrations**

Verify the Step 1 lock resolves `mcp-types==2.0.0` and passes the Pydantic compatibility spike. Construct the low-level `Server[None]` with `SdkHandlers`; do not assume the high-level decorator's generated argument model is strict because SDK 2.0.0 can ignore unknown argument keys and pre-parse stringified JSON. For a known tool with invalid arguments, return a constant-message official `CallToolResult(is_error=True)` with one bounded sanitized `TextContent` message and no `structured_content`, and prove the service handler is never entered. Reserve `MCPError`/`ErrorData` for protocol failures. An unknown tool name must raise exactly `MCPError(-32602, "Unknown tool.", {"code": "UNKNOWN_TOOL"})`, enter no service handler, and serialize the same sanitized Invalid Params envelope in both in-memory and raw HTTP tests; do not echo the attacker-controlled name. Keep an unknown JSON-RPC method distinct as `-32601`/HTTP 404 under the transport contract. Add a deliberate METHOD_NOT_FOUND/INVALID_PARAMS channel-conflation mutant that the focused tests kill. Malformed MCP requests use their exact registered protocol error. Never copy Pydantic `input` values or raw exception strings into either error channel.

After constructing `Server`, clear the default middleware and assert `tuple(server.middleware) == ()`; never mutate that list later from configuration. `base_environment`/startup rejects or strips every `OTEL_*` exporter, endpoint, header, propagator, resource, and baggage setting before importing/constructing the SDK. Tests install a canary exporter and send malicious `traceparent`/`tracestate`/`baggage`, trigger SDK/internal exceptions containing argument/token/path canaries, simulate exporter outage/backpressure, and prove zero spans/egress plus no canary in logs/results. Alpic CLI's `ALPIC_TELEMETRY_DISABLED` is a separate control and cannot satisfy this application-SDK assertion.

Build every advertised `Tool` explicitly from the typed catalog with the exact closed `input_schema` and `output_schema`; the official low-level SDK must put those dictionaries on the wire unchanged. Each `on_call_tool` branch delegates to the typed `ToolService`. Return an explicit official `CallToolResult` whose `structured_content` is the already revalidated/serialized strict output and whose `content` contains one bounded `TextContent` human summary. Record this deliberate departure from the protocol's backward-compatibility `SHOULD` to duplicate the complete serialized JSON in text, prove the supported legacy client still consumes structured content, and use MCP resources for large payloads.

Every low-level tool handler catches expected actionable `AppError` values and converts them to `CallToolResult(is_error=True)` with one bounded sanitized `TextContent` message and no `structured_content`, re-raises cancellation, and converts every other `Exception` into sanitized `MCPError(-32603, "Internal tool error.")` after emitting only the sanitized request ID/error class to the private audit path. Official v2.0.0 `MCPError` accepts `(code, message, data)`, not an `ErrorData` positional object; a focused fault test proves the invalid one-object construction raises rather than silently becoming evidence. Unknown/malformed protocol requests likewise use their exact JSON-RPC protocol-error channel; never swap a tool execution error into JSON-RPC or an internal/protocol error into an HTTP-200 tool result. Add in-memory and raw-HTTP RED/GREEN cases for the exact result/error envelopes, cancellation, and canary absence, plus deliberate channel-swap mutations that must fail. Do not let an exception escape merely to obtain SDK conversion: high-level SDK tool conversion can place `str(exception)` in model-visible result text. Project `tools/list` through the typed catalog so the schema the client receives—not merely an exported file—is flat, canonical, and recursively closed. If this cannot be done using official SDK low-level request/result models, stop and open an upstream compatibility issue rather than weakening the contract or reintroducing a private protocol.

- [ ] **Step 4: Run modern and legacy in-memory clients**

Run: `.venv/bin/python -m pytest tests/contracts/test_sdk_client.py tests/contracts/test_sdk_boundary.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/mcp_server.py src/nplg_mcp/sdk_boundary.py src/nplg_mcp/errors.py`
Expected: PASS for list, successful call, strict raw-argument rejection, unknown tool, resource read, cancellation, project-owned unexpected-exception sanitization, and exact-client-schema Zod parity; neither canary reaches the client.

- [ ] **Step 5: Commit checkpoint**

Stage dependency files, `mcp_server.py`, `sdk_boundary.py`, `security/coverage-policy.json`, and the official-client/boundary tests, then: `git commit -m "feat: add official MCP SDK server"`.

### Task 12: Prove differential parity before changing HTTP routing

#### Files

- Create: `tests/contracts/test_sdk_parity.py`
- Create: `contracts/accepted-sdk-differences.json`
- Modify: `docs/architecture/2026-08-14-official-python-sdk-adr.md`
- Modify: `src/nplg_mcp/errors.py`

#### Interfaces

- Consumes: frozen custom-protocol cases and official `Client` results.
- Produces: normalized comparison functions `normalize_tool_catalog`, `normalize_tool_result`, `normalize_public_error`.

- [ ] **Step 1: Write failing differential tests**

Compare every tool catalog entry, annotation, input/output schema, successful result, domain error, validation error, resource, and cancellation behavior. Add a canary value resembling a token and an upstream URL; assert neither appears in SDK validation/error text.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/contracts/test_sdk_parity.py -q`
Expected: collection/imports PASS through typed normalizer scaffolds; the focused comparison FAILS at the unimplemented normalization/difference-ledger assertion. Output schemas already exist from Task 9, so their absence is not a valid RED here.

- [ ] **Step 3: Add bounded normalization and error mapping**

Keep semantic parity, not private envelope quirks. Preserve MCP-standard codes and the project's stable public `ErrorCode` values. Validation details contain only bounded location, safe message, and type—never argument values, URLs, filesystem paths, tracebacks, or Pydantic `input` fragments. Record each intentional difference as a typed entry containing case ID, frozen value digest, official-SDK value digest, normative source URL/section, rationale, reviewer, and approval date. Add a test that fails if any file under `contracts/baseline/` changes after Task 1's recorded digest manifest.

- [ ] **Step 4: Run differential and official-client suites**

Run: `.venv/bin/python -m pytest tests/contracts/test_{sdk_parity,sdk_client,frozen_baseline,pydantic_contracts}.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/errors.py`
Expected: PASS; any accepted difference is named and justified in `ADR-001`.

- [ ] **Step 5: Commit checkpoint**

Stage parity tests, error mapping, the separate difference map, and ADR changes; do not stage baseline files. Then: `git commit -m "test: prove official SDK parity"`.

### Task 13: Mount the official Streamable HTTP app behind retained security controls

#### Files

- Create: `src/nplg_mcp/http_security.py`
- Create: `src/nplg_mcp/json_preflight.py`
- Modify: `security/coverage-policy.json`
- Modify: `src/nplg_mcp/config.py`, `tests/unit/test_config.py`
- Modify: `src/nplg_mcp/sdk_boundary.py`
- Modify: `src/nplg_mcp/app.py`
- Modify: `src/nplg_mcp/__main__.py`
- Modify: `tests/conformance/test_mcp_http.py`
- Modify: `package.json`, `package-lock.json`
- Create: `scripts/run_mcp_conformance.py`, `tests/conformance/official_fixture_server.py`, `tests/unit/test_run_mcp_conformance.py`
- Create: `tests/unit/test_app_lifespan.py`, `tests/unit/test_json_preflight.py`, `tests/property/test_json_preflight_properties.py`

#### Interfaces

- Produces: `create_app(config, services) -> FastAPI`, retaining the existing outer application, mounting the SDK-provided Starlette app once at outer path `/` while its own `streamable_http_path="/mcp"` exposes `/mcp` exactly once, and composing the SDK session manager into the outer application's lifespan.
- Produces: `McpSecurityMiddleware` enforcing an exact configured Host allowlist, exact Origin allowlist when an `Origin` header is present, profile/path-specific authentication admission, rejection of every non-identity request `Content-Encoding`, a 4 MiB-or-lower project body limit, body timeout, duplicate singleton headers, generic JSON lexical validity, admission limits before SDK dispatch, and one immutable response-policy function applied to `/mcp` plus protected-resource metadata. In the explicitly auth-disabled Task 13 fixture, it requires exactly one bounded byte-canonical safe-ASCII `MCP-Protocol-Version` token (1-32 bytes; no whitespace/control/non-ASCII/comma/obs-fold), rejects absence/duplication and the exact handshake-era values `2025-03-26`, `2025-06-18`, and `2025-11-25` before session-manager/handler entry, and passes other bounded tokens unchanged. In protected production, the Task-20-proven SDK authentication composition runs before that version decision: credentialless/invalid-token requests receive SDK 401/challenge with zero version/session/handler entry, while an authenticated request is verified exactly once and then the same modern-only guard returns the project 400 for absent/duplicate/handshake-era values before session/handler entry or passes the token unchanged to the modern SDK validator. Literal `2026-07-28` is the sole supported value; one safe non-handshake value such as conformance sentinel `v999.0.0` must reach the SDK so agreed header/body input receives `-32022` and mismatched input receives `-32020`. This routing gate is required because pinned SDK 2.0.0 otherwise sends an absent or handshake-era value into its born-ready legacy stateless handler; it must not preempt the modern SDK's structured unsupported-version oracle. An absent `Origin` remains valid for non-browser MCP clients. The public protected-resource metadata route is deliberately unauthenticated; `/mcp` bearer verification is owned exactly once by the SDK in Task 20.
- Produces: `preflight_json(body: bytes, limits: JsonStructuralLimits) -> None`, a bounded, byte-oriented, single-pass JSON tokenizer/structural validator that never constructs the decoded request tree and returns no normalized value.
- Produces strict immutable config fields `mcp_allowed_hosts: tuple[CanonicalHost, ...]` (nonempty) and `mcp_allowed_origins: tuple[CanonicalOrigin, ...]` (possibly empty when browser origins are forbidden), with duplicate rejection. `CanonicalHost` accepts only one canonical lower-case ASCII DNS name or bracketed IP literal plus an optional decimal port; `CanonicalOrigin` accepts exact `https://host[:port]` in production and loopback HTTP only in explicit development. Both reject credentials, whitespace/control bytes, wildcards/globs, paths/query/fragments, zone IDs, noncanonical/default-port aliases, and empty values.
- Produces `build_transport_security_settings(config: AppConfig) -> TransportSecuritySettings`, returning exactly `TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=list(config.mcp_allowed_hosts), allowed_origins=list(config.mcp_allowed_origins))`. The same immutable tuples feed `McpSecurityMiddleware`; production never relies on SDK localhost defaults, a wildcard, forwarded headers, or a separately parsed allowlist.
- The backend response policy is exact and table-tested: `Content-Security-Policy: default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store, no-transform` on every authenticated, challenge, error, metadata, JSON, and SSE response. SSE additionally preserves exactly one `X-Accel-Buffering: no` and emits the SDK's bounded 15-second comment keepalive on a controlled silent stream; the outer policy cannot strip either. Emit no permissive CORS header; if a later browser client is approved, derive exact `Access-Control-Allow-Origin`/methods/headers from the same origin allowlist, never `*` with credentials. Preserve the SDK-required MCP media type and UTF-8 bytes; include a charset only where the registered media type permits it. Protocol `ttlMs`/`cacheScope` is not HTTP cache policy. HSTS is asserted only at the real HTTPS public hop, where `Strict-Transport-Security` must contain `max-age` of at least 31,536,000 seconds and `includeSubDomains`.

- [ ] **Step 1: Rewrite one HTTP conformance test against the SDK mount**

Create the typed `json_preflight.py` interface and app-lifespan composition seam first with behavior-free implementations; the preflight deliberately raises `NotImplementedError`. Prove every new test module collects before running the focused behavioral assertions.

Treat the aggregate commands in Step 2 as bootstrap/collection diagnostics only. Before any Step 3 GREEN paragraph, materialize the global per-invariant ledger with one exact node ID, intended assertion/message, minimum production symbol/configuration, refactor decision, and named fault/mutant for every independently rejectable framing, JSON, Host/Origin, response-policy, lifespan, version-routing, SDK-envelope, cancellation, and conformance-runner invariant. Each row must witness its own intended RED and focused GREEN; a single `NotImplementedError`, old-app mismatch, or aggregate failure cannot witness the remaining rows.

Start with `test_official_sdk_backend_is_reachable_only_at_mcp` and retain host/origin/auth assertions. Add config/builder tables proving exact SDK field equality, duplicate/noncanonical/wildcard rejection, absent Origin acceptance, present unlisted Origin rejection, and that outer/SDK decisions agree for every configured Host/Origin. Add exact response-policy cases for success, 400/401/403/404/405/413/429/500, protected-resource metadata, JSON, and SSE; inject duplicate/conflicting downstream headers and prove the outer policy emits one canonical value rather than appending. Repeat Task 11's unknown/misspelled/stringified/coerced/nested-unknown argument and secret-canary cases through the Streamable HTTP client. Add invalid UTF-8, malformed JSON, duplicate JSON keys at every nesting depth (including escaped-equivalent keys), named and overflow-to-nonfinite numbers including `1e9999`, oversized/chunked bodies, depth/member/token/key/scalar/integer-digit/exponent ceilings, conflicting `Content-Length`/`Transfer-Encoding`, duplicate singleton headers, absent/present Origin, disconnect, and cancellation cases. Reject `gzip`, `br`, `deflate`, duplicate/comma-separated/obs-folded encodings, and compressed-bomb bodies before buffering or SDK dispatch; only absent or one canonical `identity` is accepted, and staging must prove Alpic has not transparently decompressed/recompressed the backend request. Prove `TRACE` is disabled at the backend. Include a real socket-level disconnect test rather than relying only on an in-process ASGI transport. Differential/property-test the bounded preflight corpus against Python's strict JSON grammar: every accepted input must be accepted by the downstream parser, every configured ceiling must reject at the first excess token, and the validator must return no decoded tree or transformed bytes.

Add real lifespan tests that start the outer FastAPI application, make first and repeated `/mcp` requests, and shut it down. Enter service/network resources first and the SDK session manager last; assert its task group is initialized before the mount receives traffic and, on reverse-order shutdown, rejects new traffic and cancels/drains an in-flight blocked handler before any service dependency closes. Prove no handler observes a closed service, each context exits exactly once, startup failure at each entry unwinds only already-entered contexts, and requests before startup/after shutdown cannot reuse the manager. This is a behavioral RED: a mounted sub-application's lifespan is not assumed to run automatically.

Add a table-driven MCP 2026-07-28 backend-wire suite for JSON/SSE `Accept`, `MCP-Protocol-Version`, `Mcp-Method`, conditional `Mcp-Name`, request-body metadata agreement, duplicate/missing/malformed/mismatched metadata headers, Base64 sentinels and invalid encodings, used `Mcp-Param-*`/`x-mcp-header` cases, unsupported-version HTTP 400, unknown-method HTTP 404/JSON-RPC `-32601`, and SSE close/cancellation. Split the oracles at the real routing boundary. In this explicitly auth-disabled Task 13 fixture only, absent/duplicate/unsafe/unbounded protocol-version and the exact three handshake-era values receive the bounded project-owned HTTP 400 with zero session-manager/handler entry; never label that response `-32020`, and never cite it as production auth-order evidence. Literal `2026-07-28` plus correct metadata reaches normal dispatch. Safe non-handshake sentinel `v999.0.0` must traverse the same outer/ASGI composition unchanged: agreed header/body version receives the exact SDK HTTP 400/JSON-RPC `-32022` unsupported-version envelope, while disagreement receives exact `-32020`; neither enters a handler. With the supported modern version present, missing/malformed/mismatched `Mcp-Method` or conditional `Mcp-Name` likewise receives HTTP 400 with the exact SDK `-32020` `HeaderMismatch` envelope, bounded `id`/`data`/message, correct Base64-sentinel decoding, and zero handler entry. Duplicate headers are rejected before dispatch and can never be collapsed into apparent agreement. Do not use one generic “notifications” expectation: the 2026 HTTP core has no client-to-server notification request, HTTP cancellation closes the SSE stream, and legacy/stdio notification behavior belongs in separately labelled cases. Add deliberate outer-gate mutants that admit an authenticated absent/legacy version to legacy dispatch, reject the safe unsupported sentinel before SDK validation, or mislabel the generic 400 as SDK validation; all must fail. Task 20 must replace the provisional auth-disabled ordering with the Task-0-proven auth-before-version composition: credentialless/invalid-token detector requests get the SDK 401/challenge with zero version/session/handler entry, while an authenticated request is version-guarded after exactly one verifier call. At this stage, prove spoofed or mismatched `Mcp-Method`/`Mcp-Name` headers neither change official-SDK dispatch nor the parsed operation identity exposed to the typed boundary. Task 20 also owns the separate capability verdict for any later fine-grained transport authorization.

Pin `@modelcontextprotocol/conformance@0.2.0-alpha.11` exactly; it is the reviewed current alpha that contains the frozen `--requirements 2025-11-25` and `--requirements 2026-07-28` sets. Bind the review to upstream commit `c321dd32035556e6769d3724a8ee97d87c3faaac`, npm SHA-512 integrity `sha512-imPK9tx5gQsL6ZKQq4MrsyDYfSaIwpRmX6+ogjbeAXs9LGvxkBxWcY7KcS7TvwaBk/ZiVWl6b/naF4q83UwDRA==`, and the package-lock integrity; revalidate all three before Task 13 and change them only together through review. Do not use `latest`, `alpha`, `npx --yes`, a network install, or an unreviewed expected-failures baseline in a conformance claim. The upstream harness prescribes fixture tool/resource/prompt names and payloads, so it cannot run its full requirements set against the exact three-tool production catalog. Create a loopback-only, auth-disabled test fixture under `tests/conformance/` that implements the harness-prescribed surface through the same project low-level `Server` adapter and ASGI/transport-security composition, except for the explicitly omitted production bearer-auth layer. The alpha.11 server CLI has no bearer-token/header injection option; a protected fixture would merely return 401, while a token-injecting proxy would add another trusted protocol component. Static packaging tests must prove this fixture is absent from wheels/sdists, production imports, profile catalogs, Docker contexts, and Alpic upload manifests. A fixture pass is unauthenticated SDK/transport-integration evidence only—never evidence that the production application's three-tool behavior, authentication, or authorization conforms.

Test a typed runner that uses only the locked local binary with offline npm execution, a fresh mode-`0700` result directory outside the source tree, a loopback-only fresh fixture-server process, bounded readiness and termination, and exact subprocess argv. It must fail on a stale/occupied listener, early server exit, timeout, missing/malformed/stale `checks.json`, a harness error, any scored failed check, unexpected result directories, or an attempt to combine `--requirements` with suite/scenario/version selectors. Preserve each wire-schema check and distinguish official fixture-harness output, project-local `tests/conformance` evidence, and deployed application evidence as three different proof classes.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest --collect-only tests/conformance/test_mcp_http.py tests/unit/test_app_lifespan.py tests/unit/test_json_preflight.py tests/unit/test_run_mcp_conformance.py tests/property/test_json_preflight_properties.py -q`
Run: `.venv/bin/python -m pytest tests/conformance/test_mcp_http.py tests/unit/test_app_lifespan.py tests/unit/test_json_preflight.py tests/unit/test_run_mcp_conformance.py tests/property/test_json_preflight_properties.py -q`
Expected: collection/imports PASS; focused behavior FAILS because `create_app` still invokes `McpProtocol`, the SDK session manager is not composed into the outer lifespan, and the typed JSON preflight is deliberately unimplemented.

This aggregate result is not authorization to implement all listed behavior. Execute Step 3 only through the completed per-invariant ledger above; preserve each focused RED/GREEN/fault result before running the aggregate module commands again.

- [ ] **Step 3: Extract middleware and mount the SDK app**

For JSON-bearing Streamable HTTP `POST` requests, validate the media type, read and cap the body before dispatch, and run `preflight_json` before the SDK allocates the decoded request tree. Implement the preflight as a deterministic byte-oriented state machine over the already capped bytes, with only a bounded container-frame stack and bounded per-object decoded-key sets; do not call `json.loads`, build a generic mapping/list tree, or retain scalar values. Decode a key only after its raw byte ceiling is satisfied so escaped-equivalent duplicates are rejected. Enforce maximum nesting depth, object members, array items, total tokens, key/scalar bytes, integer digits, and exponent magnitude while lexing; validate UTF-8, escape/surrogate pairs, JSON number grammar, delimiters, and trailing data; reject `NaN`, `Infinity`, `-Infinity`, overflow forms such as `1e9999`, and `RecursionError`/unexpected parser exceptions with one bounded public error. The limits cap the SDK's later allocation; the raw 4 MiB-or-lower body limit independently caps a single lexical token.

Reject nonempty bodies on methods that do not define them. Do not impose MCP method or JSON-RPC shape rules in this layer. The preflight must not normalize or rebuild the request: on the directly tested backend hop, replay the original bounded bytes exactly once to the official SDK, which remains the sole MCP/JSON-RPC parser and dispatcher. Preserve `Retry-After` on admission denial and reject ambiguous framing before body replay.

Build `transport_security = build_transport_security_settings(config)`, then build the provisional auth-disabled SDK app with `Server.streamable_http_app(streamable_http_path="/mcp", stateless_http=True, json_response=False, max_request_body_size=config.mcp_max_body_bytes, transport_security=transport_security)` and mount that SDK app once at outer FastAPI path `/`, after any explicitly permitted outer routes. In SDK 2.0.0 the 2026 transport is always sessionless, while `stateless_http=True` makes the legacy handler born-ready rather than disabling it; therefore a version-routing guard—not this SDK flag—is required for modern-only dispatch. Static composition and raw-wire tests must prove the auth-disabled fixture stops absent/handshake-era versions before the manager, one bounded safe unsupported sentinel reaches modern validation, and disabling/broadening the guard admits a legacy request and fails the suite. This is not the final production middleware order: Task 20 must consume `contracts/alpic-oauth-discovery-capability.json`, pass auth settings/verifier exactly once, and place the guard at the supported post-auth/pre-dispatch seam so Alpic discovery receives SDK 401 rather than this provisional 400. If no public SDK seam or documented vendor adapter can do that without duplicate verification/private MCP parsing, production Alpic remains blocked. A separate bounded local fixture may set `stateless_http=False` to measure 2025-11-25 compatibility, but that is not deployed evidence: public legacy support remains blocked until a supported public SDK seam provides a bounded session lifetime and Alpic proves compatible routing/reconnect behavior. Do not turn a local legacy pass into a production claim.

A mounted sub-application's lifespan is not run by Starlette automatically: use one outer `asynccontextmanager`/`AsyncExitStack` lifespan to enter every service/network dependency first and `mcp_server.session_manager.run()` last before accepting traffic, then unwind them in reverse order so the manager stops/drains before dependencies close. Never create a second session manager or start it lazily on the first request. This avoids both an uninitialized task group and `/mcp/mcp`, preserves root well-known auth metadata added in Task 20, and must be proven for startup failure, in-flight shutdown, exact trailing-slash/404 behavior, and clean shutdown. The SSE-capable response path is selected because SDK 2.0.0's modern JSON-only path has no equivalent explicit disconnect watcher. Retain the independent 20-second application deadline even when disconnect cancellation works. Configure SDK and outer middleware body/Host/Origin policy from the same immutable settings and probe Alpic staging for the actual backend `Host` and optional `Origin` values before release; an undocumented proxy value is a failed deployment gate, not a reason to add a wildcard.

Implement `run_mcp_conformance.py` as orchestration only: it starts only the explicit auth-disabled test fixture backed by the candidate's installed low-level server/ASGI/transport-security composition, invokes the locked official harness without a shell, validates every emitted result/check record, records the harness package/version/integrity and exact revision selectors, and cleans up in `finally`. It must refuse a production profile, production entry point, bearer credential, non-loopback bind, or forwarding proxy. At this phase intentionally run only the named developmental `server-stateless` scenario for `2026-07-28`; alpha.11 also accepts server `--suite core` as an alias for `active`, but that broader alias is not used as the focused RED. This one scenario is not a complete conformance claim. Task 20 reruns the frozen full server-leg `--requirements 2026-07-28` fixture set as regression evidence but derives every authentication/403 conclusion exclusively from project raw-wire tests; Task 22 reruns that exact fixture integration set against the candidate. The production app remains covered by exact three-tool official-client, project wire, schema, auth, and deployed-edge tests; never register a harness-prescribed tool in a release profile.

- [ ] **Step 4: Run HTTP, differential, and full tests**

Run: `.venv/bin/python -m pytest tests/conformance/test_mcp_http.py tests/contracts/test_sdk_parity.py tests/unit/test_app_lifespan.py tests/unit/test_json_preflight.py tests/unit/test_run_mcp_conformance.py tests/property/test_json_preflight_properties.py -q`
Run: `.venv/bin/python scripts/run_mcp_conformance.py --scenario server-stateless --spec-version 2026-07-28`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/sdk_boundary.py src/nplg_mcp/http_security.py src/nplg_mcp/json_preflight.py src/nplg_mcp/config.py src/nplg_mcp/app.py src/nplg_mcp/__main__.py`
Expected: PASS; the SDK session manager is live before the first request and cleanly stopped, malformed/ambiguous inputs never reach SDK dispatch, bounded preflight never constructs a decoded request tree, strict invalid tool arguments never reach handlers, valid original bytes reach the official SDK unchanged, and a real disconnect either cancels promptly through the SSE path or remains bounded by the 20-second deadline with the limitation documented.

- [ ] **Step 5: Commit checkpoint**

Stage the new middleware, app/startup changes, `security/coverage-policy.json`, and conformance tests, then: `git commit -m "feat: serve MCP through official SDK"`.

### Task 14: Make resources/results consistent and delete the custom protocol

#### Files

- Modify: `src/nplg_mcp/mcp_server.py`, `src/nplg_mcp/tools.py`
- Modify: `src/nplg_mcp/sdk_boundary.py`, `src/nplg_mcp/errors.py`, `security/coverage-policy.json`
- Modify: `src/nplg_mcp/app.py`, `src/nplg_mcp/__main__.py`
- Modify: `tests/contracts/test_sdk_client.py`, `tests/contracts/test_sdk_parity.py`, `tests/contracts/test_frozen_baseline.py`, `tests/conformance/test_mcp_http.py`
- Delete: `src/nplg_mcp/protocol.py`

#### Interfaces

- Produces official resources/templates for `nplg://about`, `nplg://artifact/{artifact_id}`, and `nplg://render/{render_id}/manifest` when enabled by profile. In `private-full`, every page/tile binary referenced by a render result is assigned an `artifact_id` and emitted only as canonical `nplg://artifact/{artifact_id}`; the existing unregistered `nplg://render/{render_id}/page/{n}` and `/tile/{tile_id}` forms are removed rather than advertised. `alpic-metadata` registers no local artifact/render resources and emits none of those URIs.
- Produces structured results without duplicating large manifests or binary payloads into text content.
- Produces one typed resource-error adapter: a syntactically valid, authorized but nonexistent canonical resource raises official JSON-RPC `-32602` with bounded message `Resource not found` and, only after existence-disclosure policy permits it, the already validated canonical URI in bounded data; malformed identifiers/URIs are also `-32602` without handler entry; unexpected internal failures become sanitized `-32603`. A missing resource must never be represented by an empty successful `contents` list, and the legacy `-32002` code is accepted only from a pinned legacy client fixture—not emitted by this server.

- [ ] **Step 1: Write failing consistency tests**

Start with one RED per currently emitted render URI: each legacy page/tile `nplg://render/.../page/...` or `/tile/...` link is presently unregistered/unreadable and must fail for that exact reason, not on fixture setup. GREEN replaces each with a canonical `nplg://artifact/{artifact_id}` link and proves the linked resource returns the exact expected digest, bounded size, approved MIME type, and principal/render ownership. Add malformed ID, unknown artifact, cross-render, cross-principal, expired, swapped digest/MIME, and concurrent deletion cases, plus a deliberate mutant that emits any unregistered URI. Assert every readable dynamic URI is represented by a resource or resource template; every listed template resolves only canonical project IDs; metadata-profile results contain no local asset URL; and large structured results are not copied verbatim into text content. On raw modern responses, require explicit `ttlMs: 0` and `cacheScope: "private"` for every complete resources/templates list and resource read, including empty/final pages; scope cannot change across cursors or authorization contexts. Legacy responses follow only the pinned legacy contract and must not acquire an unsafe shared-cache translation.

Execute separate resource-error microcycles, not one table-only GREEN: valid-but-absent `nplg://` URI yields exact `-32602`/bounded `Resource not found`; malformed/unknown-template/overlong/control-containing URI yields `-32602` before repository/service entry; injected internal lookup failure yields constant `-32603` with no exception/path/token canary; and no missing case returns HTTP/JSON-RPC success with empty `contents`. Authorization-specific non-disclosure belongs to Task 20: only a future supported dynamic-scope branch may demand a per-resource transport 403; with the pinned unsupported verdict, `private-full` requires a coarse endpoint connection scope or remains blocked and this task does not invent an operation-level result.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/contracts/test_sdk_client.py tests/conformance/test_mcp_http.py -q`
Expected: FAIL on the still-unimplemented dynamic resource/template listing; the bounded non-duplication behavior established in Task 11 remains a green regression and is not claimed as this task's RED.

- [ ] **Step 3: Register official resource templates and remove `McpProtocol`**

Use the constructor-supplied official `on_list_resources`, `on_list_resource_templates`, and `on_read_resource` handlers and exact `ListResourcesResult`, `ListResourceTemplatesResult`, and `ReadResourceResult` types; validate identifiers through strict models and preserve provenance. Do not invent a tool-like human-summary sidecar on these resource result models: place bounded human descriptions only in each official `Resource`/`ResourceTemplate`, and return actual text or binary resource content only through the official `TextResourceContents`/`BlobResourceContents` union inside `ReadResourceResult.contents`. Convert every page/tile result reference to the canonical artifact template before it can leave the typed service boundary and statically reject the two removed URI forms. Implement the exact resource-error adapter before any lookup exception can escape the low-level handler; never rely on generic SDK exception conversion for not-found semantics. Emit the explicit `0/private` cache policy through supported official result models; if the SDK cannot express the current protocol fields, stop for an upstream compatibility disposition rather than hand-serializing MCP. Any later positive TTL or public scope is a separately reviewed privacy/cache-invalidation change with cross-principal tests. Before deletion, change `test_frozen_baseline.py` and `test_sdk_parity.py` so the frozen/custom side reads only Task 1's immutable digest-verified JSON fixtures and normalized expected values; neither test may import, instantiate, or call `McpProtocol`. Prove those tests still detect a deliberately altered fixture/result, then delete every custom JSON-RPC parser/dispatcher import and the file itself.

- [ ] **Step 4: Run all protocol and strict gates**

Run: `.venv/bin/python -m pytest tests/contracts/test_sdk_client.py tests/contracts/test_sdk_parity.py tests/contracts/test_frozen_baseline.py tests/conformance/test_mcp_http.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/mcp_server.py src/nplg_mcp/sdk_boundary.py src/nplg_mcp/errors.py`
Run: `rg -n "McpProtocol|from .*protocol" src tests`
Expected: pytest and the quality runner exit 0; `rg` returns no output and exit 1, its documented no-match status.

- [ ] **Step 5: Commit checkpoint**

Stage SDK/tool changes, both migrated fixture/parity tests, conformance tests, and `git rm src/nplg_mcp/protocol.py`, then: `git commit -m "refactor: remove custom MCP protocol"`.

**Phase 3 exit gate:** after bounded HTTP/JSON screening and the narrow absent/handshake-era legacy-routing guard, `mcp==2.0.0` exclusively owns MCP parsing, structured supported/unsupported modern-version validation, and dispatch; the official modern production client passes, the separately labelled local-only legacy fixture passes its non-release diagnostics, and no deployed legacy-support claim is made; the custom protocol is gone; strict raw arguments, bounded public errors, cancellation, and retained security controls are proven on wire.

---

## Phase 4 — Killable and Isolated PDF Execution

### Task 15: Define strict PDF IPC and a killable executor

#### Files

- Create: `src/nplg_mcp/pdf_executor.py`
- Create: `src/nplg_mcp/pdf_ipc.py`
- Modify: `security/coverage-policy.json`
- Create: `src/nplg_mcp/pdf_worker_client.py`
- Create: `src/nplg_mcp/pdf_worker_main.py`
- Modify: `src/nplg_mcp/tools.py`, `src/nplg_mcp/pdf.py`
- Create: `tests/security/test_pdf_worker.py`
- Create: `tests/property/test_pdf_ipc_properties.py`

#### Interfaces

- Produces:

```python
class PdfExecutor(Protocol):
    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult: ...

PdfOperation = Literal["inspect", "render_pages", "render_tiles", "manifest"]
PageNumber = Annotated[int, Field(strict=True, ge=1, le=10_000)]
PageSelection = Annotated[tuple[PageNumber, ...], Field(min_length=1, max_length=8)]
TileDimension = Annotated[
    int,
    Field(strict=True, ge=256, le=HARD_MAX_TILE_DIMENSION),
]
TileOverlap = Annotated[
    int,
    Field(strict=True, ge=0, le=HARD_MAX_TILE_OVERLAP),
]
RenderId = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^rnd_[0-9a-f]{32}$"),
]

class InspectParams(StrictModel):
    pass

class RenderPagesParams(StrictModel):
    pages: PageSelection
    mode: Literal["native"] = "native"

class RenderTilesParams(StrictModel):
    render_id: RenderId
    page_number: PageNumber
    tile_width: TileDimension | None = None
    tile_height: TileDimension | None = None
    overlap: TileOverlap | None = None

    @model_validator(mode="after")
    def overlap_fits_explicit_geometry(self) -> Self:
        if self.overlap is not None:
            if self.tile_width is not None and self.overlap >= self.tile_width:
                raise ValueError("overlap must be smaller than tile_width")
            if self.tile_height is not None and self.overlap >= self.tile_height:
                raise ValueError("overlap must be smaller than tile_height")
        return self

class ManifestParams(StrictModel):
    render_id: RenderId

class InspectCommand(StrictModel):
    request_id: UUID
    operation: Literal["inspect"]
    source_relative_path: SafeRelativePath
    parameters: InspectParams

class RenderPagesCommand(StrictModel):
    request_id: UUID
    operation: Literal["render_pages"]
    source_relative_path: SafeRelativePath
    parameters: RenderPagesParams

class RenderTilesCommand(StrictModel):
    request_id: UUID
    operation: Literal["render_tiles"]
    parameters: RenderTilesParams

class ManifestCommand(StrictModel):
    request_id: UUID
    operation: Literal["manifest"]
    parameters: ManifestParams

PdfCommand = Annotated[
    InspectCommand | RenderPagesCommand | RenderTilesCommand | ManifestCommand,
    Field(discriminator="operation"),
]

class InspectPayload(StrictModel):
    operation: Literal["inspect"]
    value: PdfInspectionOutput

class RenderPagesPayload(StrictModel):
    operation: Literal["render_pages"]
    value: RenderPagesOutput

class RenderTilesPayload(StrictModel):
    operation: Literal["render_tiles"]
    value: RenderTilesOutput

class ManifestPayload(StrictModel):
    operation: Literal["manifest"]
    value: RenderManifestOutput

PdfPayload = Annotated[
    InspectPayload | RenderPagesPayload | RenderTilesPayload | ManifestPayload,
    Field(discriminator="operation"),
]

class PdfSuccess(StrictModel):
    request_id: UUID
    status: Literal["ok"]
    payload: PdfPayload

class PdfFailure(StrictModel):
    request_id: UUID
    status: Literal["error"]
    operation: PdfOperation
    payload: PublicWorkerError

PdfResult = Annotated[PdfSuccess | PdfFailure, Field(discriminator="status")]
```

`SafeRelativePath` is `Annotated[str, StringConstraints(strict=True, min_length=1, max_length=512), AfterValidator(validate_safe_relative_path)]`; do not express traversal rejection with regex lookaheads. `validate_safe_relative_path` accepts ASCII path segments matching `[A-Za-z0-9._-]+` only, rejects backslashes, absolute paths, empty/`.`/`..` segments, duplicate/trailing separators, NUL/control characters, and any value whose `PurePosixPath(value).as_posix()` is not byte-for-byte equal to the input. Tiles/manifest commands carry only `RenderId`; the parent derives the single canonical `renders/<render_id>` location from that typed ID and opens it descriptor-relatively under the held render-root descriptor, so an attacker cannot cross-wire a path and ID. Each command/result variant is a strict model carrying only its operation's frozen bounded fields; payload variants reuse the exact Task 9 strict output models. After validation, `SubprocessPdfExecutor` requires exact request-ID equality, requires a success payload's or failure envelope's operation to equal the command operation, and for render-ID-bearing operations requires every result render ID to equal the command parameter before accepting it. Decode raw frames only after Task 13's byte preflight rejects duplicate keys, invalid UTF-8/BOM, non-finite literals, and structural-limit violations, then use `TypeAdapter(PdfCommand).validate_json(frame, strict=True)` and `TypeAdapter(PdfResult).validate_json(frame, strict=True)` so impossible operation/parameter and status/payload combinations are unrepresentable.

- Task 15's local compatibility transport is exactly one four-byte unsigned big-endian length prefix plus one UTF-8 JSON body in each direction over private stdin/stdout: one request of 1-65,536 bytes and one result of 1-4,194,304 bytes. Use bounded `readexactly` for prefix/body, reject zero/oversize before allocation, reject truncation and any trailing stdout byte, and never scan for delimiters. `SubprocessPdfExecutor` owns this transport and never accepts a network address.

- [ ] **Step 1: Write failing parity and termination tests**

Test inspect/render parity against existing deterministic PDFs. Add timeout, parent cancellation, child crash, non-zero exit, invalid/truncated/oversized JSON, every mismatched operation/parameter and status/payload pair, wrong request ID, mismatched result render ID, unexpected output path, symlink output, excessive file size, and orphan-process checks. Exercise `../secret.pdf`, `a/../../secret.pdf`, absolute paths, backslashes, `./`, duplicate/trailing separators, percent-lookalikes, NUL/control bytes, noncanonical names, intermediate/final symlinks, and a rename/symlink swap between validation and open. Property tests generate bounded frames and prove validation is total, deterministic, and never accepts impossible variants.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/security/test_pdf_worker.py -q`
Expected: collection/imports PASS through typed IPC/executor scaffolds; the focused execution reaches the scaffold and FAILS with deliberate `NotImplementedError` before any PDF subprocess starts.

- [ ] **Step 3: Add the minimal worker boundary**

Spawn a new process group, close inherited file descriptors, clear proxy/environment credentials, set a minimal allowlist environment, use a private `0700` per-request work directory, apply CPU/address-space/file-size/open-file/process limits on Linux, and kill the entire process group on deadline or cancellation. Resolve source/output paths from a held per-request directory descriptor using Linux `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, or a separately tested component-by-component `openat(..., O_NOFOLLOW)` fallback that holds every parent descriptor; reject unsupported safe-open primitives rather than falling back to string-prefix containment. Require regular files, compare descriptor metadata rather than re-resolving names, and never reopen a validated pathname. The parent validates the strict result, recomputes hashes/sizes through held descriptors, verifies outputs remain under the staged directory, and publishes atomically only after validation.

- [ ] **Step 4: Run focused, PDF, and cancellation suites**

Run: `.venv/bin/python -m pytest tests/security/test_pdf_worker.py tests/property/test_pdf_ipc_properties.py tests/integration/test_pdf.py tests/unit/test_tools.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/pdf_executor.py src/nplg_mcp/pdf_ipc.py`
Expected: PASS; timeout/cancellation tests observe the worker PID no longer exists.

- [ ] **Step 5: Commit checkpoint**

Stage executor, IPC, worker, tool/PDF changes, `security/coverage-policy.json`, and tests, then: `git commit -m "feat: isolate PDF work in killable process"`.

### Task 16: Enforce OS-level no-network isolation and an authenticated private edge

#### Files

- Modify: `security/coverage-policy.json`
- Modify: `security/external-test-gates.json`
- Modify: `Dockerfile`, `compose.yaml`, `deploy/Caddyfile`, `deploy/README.md`
- Create: `deploy/pdf-worker-seccomp.json`
- Modify: `src/nplg_mcp/pdf_executor.py`, `src/nplg_mcp/pdf_worker_client.py`, `src/nplg_mcp/pdf_worker_main.py`, `src/nplg_mcp/pdf_ipc.py`
- Modify: `src/nplg_mcp/config.py`, `src/nplg_mcp/tools.py`, `src/nplg_mcp/app.py`
- Modify: `tests/static/test_deployment.py`
- Modify: `tests/security/test_pdf_worker.py`
- Create: `tests/fixtures/pdf/adversarial/manifest.json`
- Create: `scripts/verify_pdf_worker_container.py`
- Create: `tests/unit/test_pdf_worker_container_verifier.py`
- Create: `scripts/verify_private_edge.py`, `tests/unit/test_private_edge_verifier.py`

#### Interfaces

- Produces `UnixSocketPdfExecutor` selected only by `PDF_EXECUTOR=unix-worker` and a `pdf-worker` service using an authenticated, `0600` shared Unix socket and private artifact staging volume, `network_mode: none`, read-only root, dropped capabilities, no-new-privileges, PID/memory/CPU/file limits, and a syscall policy that permits only the required `AF_UNIX` IPC while denying `AF_INET`, `AF_INET6`, `AF_NETLINK`, packet, and other network socket families.
- Produces a private-profile Caddy edge whose only app upstream is authenticated encrypted TLS, never plaintext `http://app:8000`. A deployment-specific private CA issues distinct server/client certificates; Caddy verifies the app certificate/hostname and the app requires/verifies the Caddy client certificate. Keys/certificates are read-only mounted secrets, never image layers, ordinary environment values, or Compose plaintext. The app port is internal-only with no host publication, plaintext origin listeners are absent, Caddy and app image/config/certificate-policy digests are release subjects, and the PDF/scanner networks remain disjoint from the edge. Map the authenticated encrypted internal hop and operational proof explicitly to ASVS 12.3.3.

- [ ] **Step 1: Write failing deployment and network tests**

Create a behavior-free verifier scaffold with an injected argv executor and exclusive proof writer, and prove `tests/unit/test_pdf_worker_container_verifier.py` collects before the behavioral RED. Assert the worker cannot resolve DNS, open IPv4/IPv6 sockets, read control-plane secrets, write outside its staging volume, spawn beyond its PID limit, or survive a hard deadline. Verifier cases reject a missing, duplicate, reordered, skipped, or unknown probe; wrong candidate/tree/image/command; build or pull; image drift before any probe; nonzero exit, signal, timeout, output overflow, malformed proof, secret canary, and partial/symlink/preexisting output.

Create the independent behavior-free private-edge result verifier and collect it before RED. Deterministic tests reject plaintext Caddy-to-app proxying, a host-published app port, shared edge/worker network, absent/mismatched CA or peer identity, permissive verification, key material in source/env/image, wrong Caddy/app image or config digest, missing/extra/reordered edge probes, origin bypass, stale target identity, and candidate-authored proof. The controller-owned live harness—not the candidate verifier—owns bounded TLS/cipher/certificate, backend-mTLS, origin-bypass, framing/header, slow-client, size/deadline/concurrency, auth-negative, log-canary, and subject-TOCTOU probes.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest --collect-only tests/unit/test_pdf_worker_container_verifier.py tests/unit/test_private_edge_verifier.py tests/static/test_deployment.py tests/security/test_pdf_worker.py -q`
Run: `.venv/bin/python -m pytest tests/unit/test_pdf_worker_container_verifier.py tests/unit/test_private_edge_verifier.py tests/static/test_deployment.py tests/security/test_pdf_worker.py -k "container or network or deadline or peer or edge or mtls or origin" -q`
Expected: FAIL because the worker service/security profile and authenticated encrypted edge-to-origin channel are absent.

- [ ] **Step 3: Add the worker container and Unix-socket transport**

Implement `UnixSocketPdfExecutor` using the same strict length-prefixed `PdfCommand`/`PdfResult` frames, per-request nonces, peer-credential checks, request deadlines, and bounded reads. Keep only AF_UNIX IPC. Mount source artifacts read-only and staging outputs read-write. Do not mount the Docker socket, host root, application environment file, or cloud credentials. Parent-side publication remains in the control plane. Production `private-full` startup rejects `PDF_EXECUTOR=serialized`; the in-process serialized executor is development/compatibility-only after this task.

Configure Caddy to proxy only `https://app.internal:8443` (or the exact reviewed internal DNS identity) with the mounted client certificate and pinned private CA; configure the app listener to require the corresponding client CA and expose no plaintext/host-bound port. Fail startup on missing, expired, wrong-EKU/SAN, weak-key/algorithm, world-readable, reused, or mismatched peer material. Prove certificate rotation overlap and old-peer rejection in deterministic fixtures; actual issuance/rotation/storage remains an operational authority, not candidate code. Add exactly the Task 16 `private-full.pdf-worker-container` and `private-full.edge-http` rows from Task 7 to `security/external-test-gates.json` and no other external gate.

- [ ] **Step 4: Run deterministic adversarial and verifier tests**

Create only small, redistributable synthetic fixtures with deterministic generators. The strict manifest records fixture ID, generator/source provenance, license, SHA-256, size, expected verdict, and limits exercised; tests fail on unlisted or digest-mismatched corpus files. Test malformed, encrypted, deeply nested, huge-page, high-object-count, truncated, crash-inducing, decompression-bomb-like, timeout, and concurrent inputs. Verify resource ceilings and cleanup after worker restart.

Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/pdf_worker_client.py src/nplg_mcp/pdf_worker_main.py src/nplg_mcp/pdf_ipc.py scripts/verify_pdf_worker_container.py scripts/verify_private_edge.py`

Expected: PASS through fake/injected verifier authorities. No release-registered container command runs against the dirty pre-checkpoint source.

- [ ] **Step 5: Commit checkpoint**

Stage deployment/Caddy, seccomp, executor/client/worker/IPC/config/tool/app changes, `security/coverage-policy.json`, `security/external-test-gates.json`, both verifier scripts/unit tests, docs, and tests, then: `git commit -m "security: confine the PDF worker and private edge"`.

- [ ] **Step 6: Register the protected operational proof; optionally run a non-authoritative developer diagnostic**

The Task 16 checkpoint adds the candidate Compose/Caddy/policy/corpus and injected result verifiers, but it does not execute candidate-owned code with release authority. The release-usable `private-full.pdf-worker-container` and `private-full.edge-http` proofs are deferred until Task 22 has produced an immutable `CandidateBatteryResult`; only the independently protected controller may run `container.pdf-worker.v2` in a disposable rootless daemon/VM and `staging.private-full-edge.v2` against the exact authorized non-production edge. A developer may run either candidate verifier only as a clearly labelled supplemental diagnostic in a no-secret disposable sandbox with no host daemon socket, host mounts, target credentials, cloud/Git credentials, or release-result writer. Its output cannot satisfy the external-gate registry. Until both protected results are imported, the rows are incomplete and `private-full` release eligibility remains blocked.

### Task 16A: Fail closed on malware scanning and enforce local artifact lifecycle

#### Files

- Create: `src/nplg_mcp/malware.py`
- Modify: `src/nplg_mcp/downloader.py`, `src/nplg_mcp/storage.py`, `src/nplg_mcp/config.py`, `src/nplg_mcp/tools.py`
- Modify: `src/nplg_mcp/pdf_executor.py`, `src/nplg_mcp/pdf_worker_client.py`, `src/nplg_mcp/pdf_worker_main.py`
- Modify: `security/coverage-policy.json`
- Modify: `security/external-test-gates.json`
- Modify: `Dockerfile`, `compose.yaml`, `deploy/README.md`, `.env.example`
- Create: `deploy/pdf-worker-slot-policy.json`
- Create: `tests/security/test_malware.py`
- Modify: `tests/security/test_downloader.py`, `tests/security/test_pdf_worker.py`, `tests/unit/test_storage.py`, `tests/integration/test_pdf.py`, `tests/static/test_deployment.py`
- Create: `scripts/verify_scanner_container.py`, `scripts/verify_pdf_worker_quota.py`
- Create: `tests/unit/test_scanner_container_verifier.py`, `tests/unit/test_pdf_worker_quota_verifier.py`
- Create: `scripts/verify_private_recovery.py`, `tests/unit/test_private_recovery_verifier.py`

#### Interfaces

- Produces a strict recovery policy that classifies every persistent object/state item as `unique` or `derived`, names the immutable backup subject or deterministic regeneration recipe, fixes ownership/mode/content-digest expectations, preserves the high-water/boot/clock state plus leases and reservations, and sets a measured private-profile recovery-time objective. Candidate unit tests may use fake filesystems, but only the registered destructive disposable `private-full.recovery-proof` can establish operational recovery acceptance.

```python
class ScanVerdict(StrEnum):
    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"
    SIGNATURES_STALE = "signatures_stale"

class MalwareScanner(Protocol):
    async def scan(
        self,
        path: Path,
        *,
        expected_sha256: Sha256,
        deadline: MonotonicDeadline,
    ) -> ScanResult: ...

class ScanResult(StrictModel):
    verdict: ScanVerdict
    scanned_sha256: Sha256
    engine_version: BoundedVersion
    signature_version: BoundedVersion
    signatures_updated_at: AwareDatetime

StoredByteCount = Annotated[
    int,
    Field(strict=True, ge=0, le=1_099_511_627_776),  # HARD_MAX_CACHE_BYTES
]
StoredObjectCount = Annotated[
    int,
    Field(strict=True, ge=0, le=10_000_000),
]
FilesystemCount = Annotated[
    int,
    Field(strict=True, ge=0, le=9_223_372_036_854_775_807),
]

class StorageCapacity(StrictModel):
    total_bytes: FilesystemCount
    available_bytes: FilesystemCount
    total_inodes: FilesystemCount
    available_inodes: FilesystemCount

class PruneBlocker(StrEnum):
    LEASED_OBJECTS = "leased_objects"
    BYTE_HEADROOM = "byte_headroom"
    INODE_HEADROOM = "inode_headroom"
    CLOCK_ANOMALY = "clock_anomaly"

class SatisfiedPruneReport(StrictModel):
    status: Literal["satisfied"]
    freed_bytes: StoredByteCount
    freed_objects: StoredObjectCount
    retained_leased_objects: StoredObjectCount
    post_stored_bytes: StoredByteCount
    post_stored_objects: StoredObjectCount
    post_available_bytes: FilesystemCount
    post_available_inodes: FilesystemCount

class UnsatisfiedPruneReport(StrictModel):
    status: Literal["unsatisfied"]
    blockers: Annotated[
        tuple[PruneBlocker, ...],
        Field(min_length=1, max_length=4),
    ]
    freed_bytes: StoredByteCount
    freed_objects: StoredObjectCount
    retained_leased_objects: StoredObjectCount
    post_stored_bytes: StoredByteCount
    post_stored_objects: StoredObjectCount
    post_available_bytes: FilesystemCount
    post_available_inodes: FilesystemCount

PruneReport = Annotated[
    SatisfiedPruneReport | UnsatisfiedPruneReport,
    Field(discriminator="status"),
]

RetentionAgeSeconds = Annotated[
    int,
    Field(strict=True, ge=60, le=31_536_000),
]
RetentionByteBudget = Annotated[
    int,
    Field(strict=True, ge=1, le=1_099_511_627_776),  # HARD_MAX_CACHE_BYTES
]
RetentionObjectBudget = Annotated[
    int,
    Field(strict=True, ge=1, le=10_000_000),
]
MinimumFreeBytes = Annotated[
    int,
    Field(strict=True, ge=67_108_864, le=1_099_511_627_776),  # 64 MiB..1 TiB
]
MinimumFreeInodes = Annotated[
    int,
    Field(strict=True, ge=128, le=10_000_000),
]

class RetentionPolicy(StrictModel):
    maximum_age_seconds: RetentionAgeSeconds
    maximum_bytes: RetentionByteBudget
    maximum_objects: RetentionObjectBudget
    minimum_free_bytes: MinimumFreeBytes
    minimum_free_inodes: MinimumFreeInodes

class RetentionClockSample(StrictModel):
    utc_now: AwareDatetime
    monotonic_now: Annotated[
        float,
        Field(strict=True, ge=0.0, allow_inf_nan=False),
    ]
    boot_id: Annotated[
        str,
        StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
    ]
    synchronized: bool

class PublicationBlocker(StrEnum):
    BYTE_BUDGET = "byte_budget"
    OBJECT_BUDGET = "object_budget"
    BYTE_HEADROOM = "byte_headroom"
    INODE_HEADROOM = "inode_headroom"
    CLOCK_ANOMALY = "clock_anomaly"

class PublicationReservation(Protocol):
    reserved_bytes: StoredByteCount
    reserved_objects: StoredObjectCount
    reserved_inodes: StoredObjectCount

    async def commit(
        self,
        *,
        actual_bytes: StoredByteCount,
        actual_objects: StoredObjectCount,
        actual_inodes: StoredObjectCount,
    ) -> None: ...
    async def abort(self) -> None: ...

ConfiguredAbsoluteDirectory = Annotated[
    Path,
    Field(strict=True),
    AfterValidator(validate_configured_absolute_directory),
]
SafePathSegment = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128),
    AfterValidator(validate_safe_path_segment),
]

@dataclass(frozen=True, slots=True, init=False)
class DirectoryFd:
    _value: int

    def fileno(self) -> int: ...

def open_configured_root_fd(path: ConfiguredAbsoluteDirectory) -> DirectoryFd: ...
def open_child_directory_fd(
    parent: DirectoryFd,
    segment: SafePathSegment,
) -> DirectoryFd: ...

class QuotaBoundStagingRoot(Protocol):
    @property
    def directory_fd(self) -> DirectoryFd: ...
    @property
    def effective_hard_bytes(self) -> StoredByteCount: ...
    @property
    def effective_hard_inodes(self) -> StoredObjectCount: ...

class WorkerStagingQuota(Protocol):
    def open_quota_root(
        self,
        *,
        request_id: UUID,
        hard_bytes: StoredByteCount,
        hard_inodes: StoredObjectCount,
    ) -> AbstractAsyncContextManager[QuotaBoundStagingRoot]: ...
```

- `validate_retention_capacity(policy: RetentionPolicy, *, configured_cache_max_bytes: int, capacity: StorageCapacity) -> None` requires `policy.maximum_bytes <= configured_cache_max_bytes <= HARD_MAX_CACHE_BYTES`, `policy.maximum_bytes + policy.minimum_free_bytes <= capacity.total_bytes`, `policy.minimum_free_inodes < capacity.total_inodes`, and every available count to be no greater than its total. Startup fails on an impossible configured capacity rather than accepting a policy the filesystem can never satisfy.
- `ContentAddressedStore.prune(policy: RetentionPolicy, *, clock: RetentionClockSample) -> PruneReport` never deletes leased/in-use objects, requires `utc_now` to be timezone-aware and exactly UTC, samples byte/inode capacity from the held store-root descriptor before and after pruning, and returns a discriminated satisfied/unsatisfied post-state without exposing names or metadata. `satisfied` is legal only when stored bytes/objects and post-prune byte/inode reserves all meet the policy and the retention clock is trustworthy; every other post-state is `unsatisfied` with the exact low-cardinality blocker set.
- `ContentAddressedStore.reserve_publication(policy: RetentionPolicy, *, maximum_new_bytes: StoredByteCount, maximum_new_objects: StoredObjectCount, maximum_new_inodes: StoredObjectCount, clock: RetentionClockSample) -> AsyncContextManager[PublicationReservation]` acquires the store's atomic accounting/admission lock before any download, worker dispatch, or staging-file creation. All requested maxima must be positive exact integers within the global ceilings. Under that lock it counts committed unique bytes/logical objects plus every in-flight reservation and requires `stored + reserved + requested <= policy.maximum_bytes/maximum_objects`, the clock to be trustworthy, and the prospective destination and staging-filesystem byte/inode reserves to remain above policy. An unknown-length download reserves the configured per-download maximum and its worst-case staging/final inode footprint up front; streaming can never grow beyond it. A PDF render command derives and reserves the complete worst-case aggregate from its already validated page/tile count, per-file byte ceilings, manifest, temporary/publication duplication, and filesystem topology **before** worker dispatch (up to the bounded 8-page-plus-manifest or 100-tile-plus-manifest tree), never one file at a time after rendering. Completion rechecks actual aggregate bytes/objects/inodes, capacity, clock, policy totals, and content-addressed deduplication under the same lock, then atomically converts or releases the one tree reservation. Cancellation, timeout, infected input, duplicate digest/tree, partial output, and every failure release it exactly once; restart recovery accounts for/removes bounded orphan staging trees before reopening admission. Rejection carries only a stable `PublicationBlocker`, never paths or usage details.
- `validate_configured_absolute_directory` accepts only an already-absolute, existing configured directory without `.`/`..`, symlink, control, or normalization ambiguity; `validate_safe_path_segment` accepts one ASCII `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` segment and additionally rejects `.`/`..`. `WorkerStagingQuota` is the enforcement counterpart to accounting: before dispatch, the trusted parent leases the one pre-provisioned bounded worker slot, reserves that slot's entire verified byte/inode capacity (not merely estimated output), verifies those effective limits through the descriptor-bound `QuotaBoundStagingRoot`, and exposes only that root to the untrusted worker. `DirectoryFd` is an opaque `init=False` owner, never a `NewType`: only `open_configured_root_fd` and descriptor-relative `open_child_directory_fd` may instantiate it. They require `type(raw_fd) is int`, reject negative/closed/inheritable descriptors, verify `fstat` is a directory on the expected device/mount, use no-follow safe-open primitives, and close on every failed check; a static AST test rejects `object.__new__(DirectoryFd)` or direct `_value` assignment anywhere else. The selected Linux backend is exactly one host-provisioned ext4 filesystem mounted at configured `PDF_WORKER_SLOT_ROOT` with a fixed reviewed block count and inode count, mount options `rw,nodev,nosuid,noexec`, a device distinct from the shared store/staging filesystem, no nested mounts, and one serialized worker job. A strict checked-in slot policy fixes expected filesystem type, maximum total/available bytes and inodes, mount options, concurrency `1`, and root identity; startup descriptor-parses `/proc/self/mountinfo`, cross-checks `fstat`/`statvfs` device, blocks, fragment size, inodes, ownership, emptiness, and mount flags, and rejects overlay/tmpfs/bind/loop aliases, larger/unknown capacity, shared device, submounts, symlinks, or drift. Host provisioning/mounting is an explicit operational prerequisite outside the process; the application and worker receive no mount/quota capability and cannot resize or remount it. The reservation rounds up to the slot's full hard byte/inode capacity, so the kernel's filesystem boundary is never larger than the accounting reservation. If the exact ext4 slot cannot make an N+1 byte or inode allocation fail with `ENOSPC`, `private-full` startup fails—project-quota alternatives, post-hoc counting, `RLIMIT_FSIZE`, open-file limits, and cooperative filenames are not accepted by this plan. Cleanup kills the worker first, descriptor-removes only entries beneath the exact held mount root, fsyncs, proves the slot is empty and capacity restored, and rechecks global headroom before releasing the full-slot publication reservation.
- `deploy/pdf-worker-slot-policy.json` is exactly `{"concurrency":1,"filesystem_type":"ext4","maximum_total_bytes":1073741824,"maximum_total_inodes":65536,"minimum_available_bytes":805306368,"minimum_available_inodes":32768,"mount_options":["nodev","noexec","nosuid","rw"],"root":"/var/lib/nplg/pdf-worker-slot","version":1}` in canonical-key form. The root-bound 1 GiB/65,536-inode policy is the reviewed upper bound, and its 768 MiB/32,768-inode minimum available headroom must still be present at startup and before dispatch. The static policy and runtime reject missing/extra/reordered option values, coercion, an alternate filesystem/backend, a larger capacity, insufficient headroom, a different root, or concurrency other than one. `PDF_WORKER_SLOT_ROOT` must equal the root bound into the policy; no device, mount, size, option, or alternate root is attacker/runtime configurable. The deployment guide provides bounded host-provisioning and destructive teardown procedures but labels them operator-authorized prerequisites, never commands the implementation agent may execute implicitly.

- [ ] **Step 1: Write failing scan/lifecycle tests**

Before the behavioral RED, create typed, behavior-free scaffolds for the malware models/scanner, retention/prune/reservation/quota/recovery interfaces, ToolService/worker-client wiring, and all three new verifier scripts; every target operation deliberately raises `NotImplementedError`, while every focused module collects. Give all three verifiers injected argv executors. Fake quota-runner cases reject a missing/wrong image digest, wrong service, a build attempt, absent quota feature, malformed/unbounded output, a survived N+1 write/create, missing termination/cleanup, lost headroom, timeout, and any skipped probe. Descriptor-factory cases reject bool, float, string, negative, closed, regular-file, socket, symlink-reopened, inheritable, wrong-device/mount, `.`/`..`, non-ASCII/control, and normalization-ambiguous inputs, prove failed construction closes newly opened descriptors, and statically forbid direct opaque-wrapper construction/field writes. Use the standard antivirus test signature in a synthetic file and test clean, infected, scanner unavailable, scan timeout, stale signatures, hash change between scan and publication, quarantine cleanup, retention expiry, byte/object/inode pressure, leased-object protection, concurrent prune, crash recovery, and cold regeneration of derived artifacts after complete volume loss. Add table/property cases at each retention bound and immediately below/above it; reject negative, zero where positive is required, bool-as-int, float/string coercion, and values over every reviewed ceiling. Add deterministic fake-filesystem cases for an undersized volume, an impossible cache/reserve sum, zero byte/inode reserve, all objects leased, filesystem shrink after startup, free-byte recovery without inode recovery, free-inode recovery without byte recovery, and exact post-state boundaries. Prove single and concurrent reservations at one byte/object/inode below, exactly at, and one above every policy/reserve boundary; include configured cache max greater than policy max, two downloads that individually fit but collectively do not, unknown-length worst-case reservation, content-addressed duplicate release, cancellation/timeout/infection cleanup, filesystem shrink between reserve/commit, orphan restart recovery, and no staging/network side effect on rejection. Add page-render and 100-tile-render aggregate cases for exact calculated bytes/logical objects/physical inodes, manifest inclusion, temporary/publication duplication, partial-tree abort, and concurrent download plus render where each fits alone but the atomic total does not; assert rejection occurs before worker dispatch. Against the real quota backend, have a hostile worker attempt the exact limit, N+1 byte, N+1 file, N+1 directory, many sequential zero-byte files, sparse-file/block-accounting abuse, and two concurrent overruns; prove the kernel denies every overrun before global reserved headroom is consumed, the process group is terminated, the exact quota root is cleaned, and another admitted job can proceed. Missing/ineffective quota support must fail startup. Add naive/non-UTC/unsynchronized clock samples, bool/int/nonfinite monotonic values, same-boot wall rollback, excessive forward step relative to monotonic elapsed time, a changed boot ID, corrupt/missing persisted high-water state, future object timestamps, and crash/restart cases. Each impossible startup invariant fails configuration; each runtime-unsatisfied result closes new-ingest/publication admission and alerts without deleting a lease. Task 19, not this optional private-full task, owns the metadata-profile non-construction assertion.

The scanner verifier's dedicated injected-executor cases reject missing, duplicate, reordered, skipped, or unknown probes; missing/stale signatures; wrong candidate/tree/image/service; build or pull; image drift before any probe; nonzero exit, signal, timeout, output overflow, secret canary, malformed proof, TOCTOU replacement, and partial/symlink/preexisting output. The quota verifier applies the same envelope, process, subject, image, and exclusive-output cases in addition to the quota attacks above.

The recovery verifier applies the same envelope/process/subject/exclusive-output cases and rejects a missing state classification, unbound backup/regeneration subject, incomplete volume loss, corrupt/partial restore reported as success, wrong content/owner/mode, omitted high-water/lease/reservation state, clock anomaly reopened, unmeasured or over-policy RTO, before/after image/config drift, missing cleanup, candidate-authored proof, and any skipped/reordered recovery probe. The protected fixture destroys only controller-created synthetic disposable volumes; no task command may target an operator or production volume.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest --collect-only tests/unit/test_scanner_container_verifier.py tests/unit/test_pdf_worker_quota_verifier.py tests/unit/test_private_recovery_verifier.py tests/security/test_malware.py tests/security/test_downloader.py tests/security/test_pdf_worker.py tests/unit/test_storage.py tests/integration/test_pdf.py tests/static/test_deployment.py -q`
Expected: collection PASS through the behavior-free verifier scaffold.
Run: `.venv/bin/python -m pytest tests/unit/test_scanner_container_verifier.py tests/unit/test_pdf_worker_quota_verifier.py tests/unit/test_private_recovery_verifier.py tests/security/test_malware.py tests/security/test_downloader.py tests/security/test_pdf_worker.py tests/unit/test_storage.py tests/integration/test_pdf.py tests/static/test_deployment.py -q`
Expected: collection/imports PASS and the focused cases FAIL because scanning, lifecycle accounting, enforced worker write quotas, and a verifiable recovery contract do not exist.

- [ ] **Step 3: Add a fail-closed scanner and bounded pruning**

Use a digest-pinned ClamAV service for `private-full`. Treat the scanner as another untrusted parser: run it unprivileged, capability-dropped, secret-free, read-only except for private database/tmp paths, no-network, and with explicit file/archive/recursion/decompression/object/time/memory/process limits. Run signature updates in a separate least-privilege updater with restricted egress and signature verification; the PDF worker and scanner remain no-network. Test decompression bombs, scanner crash/hang, corrupt or unverifiable signatures, and cleanup.

Reserve the prospective worst-case byte/logical-object/physical-inode budget atomically before a download, PDF worker dispatch, or staging-tree creation. Before handing any writable descriptor/mount to a PDF worker, provision and verify the per-request hard block/inode quota from that reservation; never give the worker the shared staging root directly. Scan a fully downloaded staged input before content-addressed publication or PDF parsing, bind the clean verdict to SHA-256, and convert the reservation only after the final under-lock capacity/policy recheck; quarantine/delete infected input and release its reservation. For render/page/tile publication, reserve and commit/abort the complete validated output tree as one unit. Treat unavailable/timed-out/stale-signature results as a bounded public failure. Add restart-stable conservative retention/pruning with byte, object, inode/free-space, lease, in-flight reservation, and concurrency safeguards. Persist an atomically replaced/fsynced UTC high-water record containing the last same-boot UTC/monotonic sample and boot ID. Within one boot, reject wall rollback or a forward wall step beyond the reviewed monotonic slew allowance. After restart, corrupt/missing state, changed boot ID, unsynchronized time, or future object timestamps disable age-based deletion until a bounded healthy-synchronization observation window completes; quota eviction may use only a persisted monotonic insertion sequence, and new-ingest admission remains closed during a clock anomaly. Never infer persisted-object age from process monotonic time alone. An unsatisfied prune, rejected reservation, or reserve lost before commit rejects publication/new ingest with a stable bounded error, emits one low-cardinality alert/metric, and remains closed until a later synchronized prune/capacity sample proves `satisfied`. Existing safe reads may continue; no lease is broken to regain capacity. Classify every persisted object as unique or derived; back up and restore any unique state, and for derived content prove bounded cold regeneration plus the documented recovery-time objective instead of claiming a backup that is unnecessary. Add exactly the Task 16A `private-full.scanner-container`, `private-full.pdf-worker-write-quota`, and `private-full.recovery-proof` rows from Task 7 to `security/external-test-gates.json`.

- [ ] **Step 4: Run deterministic adversarial, storage, and verifier tests**

Run: `.venv/bin/python -m pytest tests/unit/test_scanner_container_verifier.py tests/unit/test_pdf_worker_quota_verifier.py tests/unit/test_private_recovery_verifier.py tests/security/test_malware.py tests/security/test_downloader.py tests/security/test_pdf_worker.py tests/unit/test_storage.py tests/integration/test_pdf.py tests/static/test_deployment.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/malware.py src/nplg_mcp/downloader.py src/nplg_mcp/storage.py src/nplg_mcp/tools.py src/nplg_mcp/pdf_worker_client.py scripts/verify_scanner_container.py scripts/verify_pdf_worker_quota.py scripts/verify_private_recovery.py`
Expected: PASS through deterministic and injected/fake verifier authorities; infected or unscanned files never reach publication/PDFium, stale definitions alert and fail closed, pruning never removes a leased object, and unresolved byte/inode pressure cannot be reported as success or admit new ingest. No release-registered container command runs against dirty pre-checkpoint source.

- [ ] **Step 5: Commit checkpoint**

Stage scanner/storage/downloader/config/tool/PDF-executor/worker/deployment/recovery changes, exact `deploy/pdf-worker-slot-policy.json`, `security/coverage-policy.json`, `security/external-test-gates.json`, the named security/storage/integration/static tests, all three verifier scripts/unit tests, then: `git commit -m "security: scan, recover, and expire untrusted artifacts"`.

- [ ] **Step 6: Register the protected scanner/quota/recovery proofs; optionally run non-authoritative developer diagnostics**

The Task 16A checkpoint adds candidate scanner/worker/recovery configuration, slot policy, and injected result verifiers, but it grants no candidate process container-runtime, host-slot, destructive-volume, or result-writer authority. Release-usable `container.scanner.v2`, `container.pdf-worker-quota.v2`, and `container.private-full-recovery.v2` executions are deferred to Task 22 after the immutable battery exists. The protected controller alone brokers a disposable rootless daemon/VM and controller-created bounded synthetic volumes/slots, owns the signed attack/recovery corpus and oracles, prevents candidate access to the daemon socket/raw host path/result writer, and emits signed controller-bound results. Developer runs of the candidate verifier scripts are supplemental no-secret diagnostics only and can never satisfy the registry. Unsupported quota/recovery enforcement, missing protected authority, or any absent signed proof keeps `private-full` blocked.

**Phase 4 exit gate:** no release profile invokes PDFium concurrently in Python threads; full-fidelity PDF work is killable, resource-limited, parent-validated, operationally no-network, scanned with fresh signatures, and governed by tested retention/quota policies.

---

## Phase 5 — Upstream, Parser, Cursor, and Cache Hardening

### Task 17: Bind validated DNS results and bound upstream failure amplification

#### Files

- Create: `src/nplg_mcp/network.py`
- Create: `src/nplg_mcp/resilience.py`
- Modify: `security/coverage-policy.json`
- Modify: `security/external-test-gates.json`
- Modify: `src/nplg_mcp/app.py`, `src/nplg_mcp/http_types.py`, `src/nplg_mcp/security.py`, `src/nplg_mcp/repository.py`, `src/nplg_mcp/downloader.py`
- Modify: `.env.example`
- Create: `tests/security/test_ssrf_binding.py`
- Create: `tests/unit/test_upstream_resilience.py`
- Create: `scripts/run_live_nplg_canary.py`, `tests/unit/test_live_nplg_canary.py`
- Modify: `tests/security/test_downloader.py`, `tests/integration/test_repository.py`
- Modify: `tests/conformance/test_mcp_http.py` for application-assembly proof

#### Interfaces

- Produces immutable `ResolvedEndpoint(hostname: CanonicalHostname, port: Port, addresses: tuple[IPv4Address | IPv6Address, ...], validity: MonotonicDeadline)` with resolver TTL clamped to 1.0-60.0 seconds, and a complete `httpcore.AsyncNetworkBackend` implementation. Its pinned 1.0.9 external-protocol method is exactly `async connect_tcp(host: str, port: int, timeout: float | None = None, local_address: str | None = None, socket_options: Iterable[SOCKET_OPTION] | None = None) -> httpcore.AsyncNetworkStream`, where the project alias exactly mirrors upstream `SOCKET_OPTION = tuple[int, int, int] | tuple[int, int, bytes | bytearray] | tuple[int, int, None, int]`; `AsyncHTTPConnection` decodes the origin host to canonical ASCII text before invoking the backend. Despite the upstream-compatible optional timeout annotation, the implementation requires `type(timeout) is float`, rejects `None`, bool, int, string, negative, zero, NaN, infinite, or over-60-second values before socket work, and converts the accepted value through `MonotonicDeadline.after`. Every project-owned caller derives and passes the active request deadline's positive bounded remainder; an absent timeout is never interpreted as unbounded. `connect_unix_socket` and `sleep` retain their exact upstream protocol signatures but apply the same exact-float/finite/positive/bounded rule. A runtime signature/spy contract must prove the backend receives the canonical hostname as `str`, the complete socket-option union round-trips without narrowing, and no project-owned boundary accepts or returns an unvalidated timeout/transport value.
- TLS retains the canonical hostname for SNI/certificate verification while the TCP connection uses only a validated public IP.
- Produces a per-upstream `UpstreamGuard` with a bounded concurrency bulkhead and typed `Closed | Open | HalfOpen` circuit state driven only by an injected monotonic clock; `acquire(deadline: MonotonicDeadline) -> AsyncContextManager[AttemptPermit]` rejects expired deadlines before mutation, admits a bounded probe, or returns a sanitized retry decision without consuming all request capacity.

- [ ] **Step 1: Write failing DNS rebinding tests**

Create type-checkable, behavior-free `network.py`/`resilience.py` interfaces first and prove the focused modules collect; production methods deliberately raise `NotImplementedError` until the RED is observed.

Create a typed behavior-free `run_live_nplg_canary.py` scaffold with injected client, clock, and exclusive writer, then prove its unit module collects before the behavioral RED. Its strict `NplgLiveCanaryRecord` contains schema/gate version, candidate commit/tree, canonical endpoint-origin digest, aware-UTC start/completion, exact bounded request count, success/failure counts, duration bounds, sanitized outcome/blocker, command-policy digest, and record digest—never response bodies, queries, credentials, or raw metadata. It writes only to a new no-symlink mode-`0600` `--result-json` below a validated external mode-`0700` parent. Unit tests cover missing authority/URL, private/non-HTTPS/rebound URL, wrong candidate/tree, missing/duplicate/skipped probe, timeout/cancellation/output overflow, clock rollback, secret canaries, preexisting/symlink/contained output, partial-write cleanup, and digest tampering.

The live oracle is exactly one ordered probe, `nplg.simple-search.bound-origin.v1`. It performs exactly one `GET` to canonical origin `https://dspace.nplg.gov.ge`, path `/simple-search`, with the fixed encoded parameters `query=ივერია`, `rpp=1`, and `start=0`; forbids credentials, proxies, fragments, userinfo, and every redirect; requires status 200, a final URL at the same canonical origin/path, `text/html` with an explicitly accepted UTF-8-compatible charset, a body of 1..1,048,576 bytes, and successful bounded `parse_search_results` parsing. The parsed page must contain exactly one item for `rpp=1`, report `total >= 1`, and expose a nonempty canonical handle and bounded nonblank title for that item; a structurally valid empty result table is an explicit negative case and cannot satisfy the canary. Before recording success, the instrumented pinned backend must prove the canonical hostname was used for HTTP Host, TLS SNI, and certificate hostname validation; the actual TCP peer equals the selected address in the one validated all-public DNS answer set; and no system/proxy re-resolution occurred. The strict record stores only the fixed probe ID, bounded outcome counters, endpoint-origin and network-observation digests, and timing—not the query, IP set, URL, body, or headers. Zero, extra, duplicate, reordered, redirected, differently parameterized, empty-result, semantically unparsed, or merely HTTP-successful requests fail the oracle.

Cover mixed public/private A and AAAA answers, CNAME changes, address changes between validation and connect, redirects to a second host, IPv4-mapped IPv6, zone identifiers, proxy environment variables, resolver timeout, TTL below/at/above the 1-60-second clamp, raw timeout `None`/bool/int/string/negative/zero/NaN/infinity/over-ceiling values for TCP, Unix sockets, and sleep, expired validity, clock regression, and every unusual/noncanonical IP text form. Seed an inbound bearer-token canary and prove the generic purpose-specific outbound-header builder and actual NPLG client never forward it or any client-supplied proxy/forwarding header. Task 20 repeats the proof for its later JWKS consumer; Tasks 15/16A own worker/scanner secret/environment/IPC isolation when the optional private-full branch is selected.

Add the exact conformance assembly node
`tests/conformance/test_mcp_http.py::test_application_assembles_nplg_client_with_pinned_transport`
proving the application constructs the NPLG client with the pinned backend and
`trust_env=False`; isolated backend tests do not prove that the production
application uses the secure transport.

Add the one separately authorized classification node with the exact name `tests/integration/test_repository.py::test_live_nplg_canary_uses_bound_public_endpoint`; it exercises the same injected canary operation, requires `NPLG_ALLOW_LIVE_TESTS=1`, and is the only Task 17 node the deterministic gate deselects. Candidate pytest progress/stdout and `run_live_nplg_canary.py` output are non-authoritative developer diagnostics. Release evidence comes only from the registered protected-controller `live.nplg-bound-endpoint.v2` command and its signed controller/broker/candidate-bound result.

With injected fake clock/randomness and scripted NPLG responses, test bulkhead saturation, timeout/connection error/429/5xx thresholds, excluded caller 4xx and validation failures, open-state fail-fast behavior, bounded/jittered `Retry-After`, exactly one bounded half-open probe, concurrent recovery races, failed-probe backoff, successful recovery, cancellation cleanup, and independent state for unrelated upstreams. A sustained outage must not occupy all global admission slots or create a half-open stampede; metrics/logs must not contain queries, tokens, or response bodies.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest --collect-only tests/unit/test_live_nplg_canary.py tests/security/test_ssrf_binding.py tests/unit/test_upstream_resilience.py tests/conformance/test_mcp_http.py::test_application_assembles_nplg_client_with_pinned_transport -q`
Expected: collection PASS through the typed behavior-free scaffolds.
Run: `.venv/bin/python -m pytest tests/unit/test_live_nplg_canary.py tests/security/test_ssrf_binding.py tests/unit/test_upstream_resilience.py tests/conformance/test_mcp_http.py::test_application_assembles_nplg_client_with_pinned_transport -q`
Expected: collection/imports PASS through typed scaffolds; focused tests FAIL because validation and HTTPX connection resolution are separate and no upstream bulkhead/circuit policy exists.

- [ ] **Step 3: Add a pinned httpcore network backend**

Resolve once per connection attempt, reject the entire answer set if any address is unsafe, pass a selected validated IP to TCP connect, retain the original canonical host for HTTP Host and TLS SNI, and set `trust_env=False`. Re-admit and re-resolve/revalidate every redirect hop before following it. A same-origin redirected request may reuse an existing keep-alive connection only when its pinned peer belongs to the hop's newly validated all-public answer set and the endpoint validity has not expired; otherwise it must establish a new pinned connection. Do not represent keep-alive reuse as a new TCP connection or silently reuse an expired/unmatched peer. Build each downstream header set from a closed purpose-specific allowlist; never copy the inbound `Authorization`, cookie, forwarding, MCP metadata, or arbitrary request headers. Do not fall back to the system resolver after validation failure.

Wrap NPLG calls in a separate, small concurrency bulkhead and monotonic circuit breaker. Count only classified transient failures (timeouts, connection failures, 429, and reviewed 5xx); do not let caller errors, local validation, cancellations, or security rejections poison the circuit. Use bounded exponential open intervals with capped jitter, one half-open probe per instance, atomic state transitions, a maximum attempt deadline below the tool deadline, and guaranteed permit release. Emit only low-cardinality state/transition metrics. Fail fast with a stable public upstream-unavailable code and sanitized capped `Retry-After`; never replay non-idempotent work. Document that state is instance-local and do not present it as a distributed quota.

- [ ] **Step 4: Run deterministic security and repository tests**

Run: `.venv/bin/python -m pytest -m 'not live' tests/security/test_ssrf_binding.py tests/unit/test_upstream_resilience.py tests/unit/test_live_nplg_canary.py tests/security/test_downloader.py tests/integration/test_repository.py tests/conformance/test_mcp_http.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/app.py src/nplg_mcp/http_types.py src/nplg_mcp/security.py src/nplg_mcp/network.py src/nplg_mcp/resilience.py src/nplg_mcp/downloader.py scripts/run_live_nplg_canary.py`
Expected: all deterministic suites, strict gates, and mutation targets PASS. No live command runs from the dirty pre-checkpoint worktree.

- [ ] **Step 5: Commit checkpoint**

Stage app/HTTP/network/security/repository/downloader files, `.env.example`, `security/coverage-policy.json`, `security/external-test-gates.json`, `scripts/run_live_nplg_canary.py`, `tests/unit/test_live_nplg_canary.py`, and the named security, unit, integration, and conformance tests, then: `git commit -m "security: bind outbound connections to validated DNS"`.

- [ ] **Step 6: Register the protected live oracle; optionally run a non-authoritative developer diagnostic**

The Task 17 checkpoint contains the deterministic injected oracle fixture but receives no release network authority. The release-usable `live.nplg-bound-endpoint.v2` execution is deferred to Task 22 after the immutable battery exists and is performed only by the independently protected controller in a no-secret, proxy-free, DNS/IP-pinned helper whose egress is restricted to the exact NPLG origin. Candidate code cannot access the network broker or result writer. A local run of `scripts/run_live_nplg_canary.py` is a clearly labelled developer diagnostic only, must use an OS-enforced disposable egress sandbox, and cannot satisfy the registry. Missing protected network authority or an absent signed proof leaves the row incomplete.

### Task 18: Add parser drift, cursor binding, and metadata-discovery cache tests

#### Files

- Modify: `src/nplg_mcp/parsers.py`, `src/nplg_mcp/repository.py`, `src/nplg_mcp/tokens.py`
- Modify: `tests/unit/test_parsers.py`, `tests/integration/test_repository.py`
- Modify: `tests/property/test_parser_properties.py`

#### Interfaces

- Produces strict versioned cursor payload `CursorV1(version: Literal[1], key_id: BoundedKeyId, query_hash: Sha256, scope_handle: CanonicalHandle | None, offset: NonNegativeInt, page_size: PageSize, issued_at: AwareDatetime, expires_at: AwareDatetime)` authenticated with a purpose-specific key and algorithm fixed outside attacker-controlled data.
- Produces bounded OAI format discovery cache entries keyed by canonical upstream origin with explicit monotonic expiry.
- Produces immutable `ParserLimits` with literal reviewed defaults: `markup_bytes=2_097_152`, `max_depth=64`, `max_nodes=50_000`, `max_attributes_per_node=64`, `max_total_attributes=100_000`, `max_field_code_points=65_536`, `max_total_text_code_points=1_048_576`, `max_metadata_fields=2_048`, `max_records=1_000`, and `parse_deadline_ms=2_000`. Binary artifact downloads keep their separately governed streaming limit; the existing 10 MiB repository response ceiling is not permission to feed 10 MiB to an HTML/XML DOM parser. These values are configuration maxima, not caller inputs, and changing one requires a reviewed corpus/performance record and matching policy revision.

- [ ] **Step 1: Write failing replay/drift/property tests**

Reject a cursor replayed with another query, scope, or page size; reject version/algorithm confusion; detect missing/duplicate contract markers; fail closed on ambiguous restriction/public markers. For every `ParserLimits` field, add `N-1`, `N`, and `N+1` fixtures plus deep, wide, many-attribute, one-large-field, aggregate-text, metadata-field, and record-count adversaries for both Beautiful Soup and defused XML paths. A lexical/streaming preflight must enforce byte/depth/node/attribute/text/record ceilings before DOM/model construction or cache insertion; tests instrument constructors and cache writes to prove zero entry on rejection. Freeze the current hardened XML invariant with explicit DTD, external/local/network entity, quadratic, and exponential-entity-expansion rejection tests. In a pinned controlled Linux subprocess, assert the accepted worst-case corpus remains within a 2-second wall budget and 256 MiB peak RSS; kill on timeout and treat a timeout/measurement failure as RED, never as a skip. Deliberate removed-byte/depth/node/deadline/cache-before-validate mutants must fail.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest -m 'not live' tests/unit/test_parsers.py tests/integration/test_repository.py tests/property/test_parser_properties.py -q`
Expected: FAIL on context-free cursor replay and missing cache semantics.

- [ ] **Step 3: Add versioned cursor binding and bounded cache**

Normalize the query exactly once, hash its canonical UTF-8 form, bind all pagination context, use independent key derivation/purpose labels, compare signatures in constant time, and cap TTL. Implement one streaming markup preflight that counts encoded bytes, syntactic nesting, nodes, per-node/aggregate attributes, decoded text code points, metadata fields, records, and monotonic elapsed time with saturating counters before invoking the existing HTML/XML parser. Recheck aggregate text/field/record counts while constructing strict models, reject if the two passes disagree, and publish/cache only after every bound and contract marker passes. Cache only successful, schema-valid OAI format discovery; never cache access denial, partial results, over-budget input, or malformed content. Map the exact limits and resource-regression evidence to ASVS 2.1.3, 2.2.1, 2.3.2, 15.1.3, and 15.2.2.

- [ ] **Step 4: Run unit, property, and integration suites**

Run: `.venv/bin/python -m pytest -m 'not live' tests/unit/test_parsers.py tests/integration/test_repository.py tests/property/test_parser_properties.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/parsers.py src/nplg_mcp/repository.py src/nplg_mcp/tokens.py`
Expected: focused, global strict, branch/diff-coverage, and decision-module mutation gates PASS with deterministic clocks, hardened XML parsing, and no external network.

- [ ] **Step 5: Commit checkpoint**

Stage parser/repository/token changes and tests, then: `git commit -m "security: bind cursors and detect parser drift"`.

**Phase 5 exit gate:** the validated DNS address is the connected address, proxies cannot bypass policy, redirect hops revalidate, cursors are query-bound, and parser/cache limits are property-tested.

---

## Phase 6 — Identity, Auditability, and Alpic Metadata Release

### Task 19: Add deployment profiles and exact metadata-only tool exposure

#### Files

- Modify: `src/nplg_mcp/profiles.py`, `src/nplg_mcp/services.py`, `src/nplg_mcp/config.py`, `src/nplg_mcp/mcp_server.py`, `src/nplg_mcp/tools.py`, `src/nplg_mcp/app.py`
- Modify: `security/coverage-policy.json`
- Create: `tests/integration/test_profiles.py`
- Modify: `tests/unit/test_config.py`

#### Interfaces

```python
class DeploymentProfile(StrEnum):
    ALPIC_METADATA = "alpic-metadata"
    PRIVATE_FULL = "private-full"
    DISTRIBUTED_FULL = "distributed-full"

PROFILE_TOOLS: Final[Mapping[DeploymentProfile, frozenset[str]]] = {
    DeploymentProfile.ALPIC_METADATA: frozenset(
        {"search_documents", "get_document_metadata", "list_document_files"}
    ),
    DeploymentProfile.PRIVATE_FULL: frozenset(
        {
            "download_document_file",
            "get_document_metadata",
            "get_render_manifest",
            "inspect_pdf",
            "list_document_files",
            "render_pdf_page_tiles",
            "render_pdf_pages",
            "search_documents",
        }
    ),
}
```

- [ ] **Step 1: Write failing profile-isolation tests**

Retain Task 11's exact three-tool catalog assertion, then add the still-unimplemented composition invariant: `alpic-metadata` startup does not construct or import PDF/store/scanner services, never emits `asset_url` or local `resource_uri` values, and rejects full-profile tool names as unknown. Inject constructors that fail if touched; do not infer non-construction only from a filtered catalog.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/integration/test_profiles.py -q`
Expected: FAIL specifically because metadata startup still constructs full-profile services; an already-correct three-tool listing is not a relevant RED.

- [ ] **Step 3: Add fail-closed profile composition**

Parse one exact profile enum at startup, instantiate only required services, and filter registrations at server creation. Unknown profiles fail startup. `distributed-full` fails startup throughout this plan. Phase 7 may prove provider compatibility, but even a supported capability verdict cannot enable the profile without the later approved implementation plan. The metadata profile uses no artifact signing secret and no correctness dependency on cache persistence.

- [ ] **Step 4: Run profile, official-client, and configuration suites**

Run: `.venv/bin/python -m pytest tests/integration/test_profiles.py tests/contracts/test_sdk_client.py tests/unit/test_config.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/profiles.py`
Expected: PASS with exact catalog snapshots for both executable profiles plus the exact `distributed-full` startup-rejection, no-service-construction, and no-method/catalog proof.

- [ ] **Step 5: Commit checkpoint**

Stage profile/config/server/tool/app changes, `security/coverage-policy.json`, and tests, then: `git commit -m "feat: add isolated deployment profiles"`.

### Task 20: Add principal-aware authentication, authorization, quotas, and safe audit events

#### Files

- Create: `src/nplg_mcp/auth.py`, `src/nplg_mcp/audit.py`
- Modify: `security/coverage-policy.json`
- Modify: `pyproject.toml`, `requirements.in`, `requirements.lock`
- Modify: `src/nplg_mcp/mcp_server.py`, `src/nplg_mcp/sdk_boundary.py`, `src/nplg_mcp/http_security.py`, `src/nplg_mcp/config.py`, `src/nplg_mcp/admission.py`, `src/nplg_mcp/errors.py`, `src/nplg_mcp/tokens.py`, `src/nplg_mcp/app.py`
- Create: `tests/security/test_auth.py`, `tests/security/test_audit.py`
- Create: `tests/property/test_auth_properties.py`
- Create: `tests/fixtures/sdk_principal.py`
- Modify: `tests/contracts/test_sdk_client.py`, `tests/contracts/test_sdk_boundary.py`, `tests/conformance/test_mcp_http.py`, `tests/unit/test_admission.py`, `tests/security/test_tokens.py`
- Modify: `SECURITY.md`, `docs/security/threat-model.md`
- Create: `docs/security/data-inventory.md`, `docs/security/cryptographic-inventory.json`, `docs/security/logging-inventory.json`, `security/crypto-policy.json`
- Create: `contracts/oidc-subject-capability.json`

#### Interfaces

- Conditionally produces `OidcJwtTokenVerifier(TokenVerifier)` with `async def verify_token(token: str) -> AccessToken | None` using the official SDK's `mcp.server.auth.provider.TokenVerifier` and `AccessToken` only when `contracts/oauth-provider-capability.json` names the selected Auth0 tenant and Alpic environment, selects `client_registration_mode="alpic_dcr_proxy"`, and proves `access_token_format="signed_jwt"`. There is no token-shape sniffing, JWT/opaque fallback, acceptance of an ID token, or inference from Auth0's general product behavior. If that tenant issues opaque access tokens or the DCR issuer-role mapping is unproven, Task 20 stops with `OAUTH_PROVIDER_CAPABILITY_UNPROVEN` and/or `ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN` until the corresponding reviewed verifier/topology design and TDD ledger exist.
- Produces `Principal(subject: StableSubject, client_id: OAuthClientId, issuer: HttpsIssuer, audience: CanonicalResource, scopes: frozenset[Scope], auth_method: AuthMethod, authorization_details: tuple[AuthorizationDetail, ...])` and rejects `authorization_details` entirely until a selected issuer-specific policy models and enforces every detail. The issuer contract requires one unambiguous signed client identity through `client_id` or one reviewed `azp` mapping; absent, array-valued, duplicate, or disagreeing client claims fail closed. `StableSubject` is not established by syntax or signature alone: strict `contracts/oidc-subject-capability.json` binds the selected issuer/tenant, subject type (`public` or `pairwise`), sector/mapping policy, machine-bound evidence that an `iss + sub` pair is immutable and never recycled/reassigned, migration behavior, reviewer, observation digest/date, and `supported`. Missing evidence creates `OIDC_SUBJECT_NON_REASSIGNMENT_UNPROVEN`; no public profile may use issuer+subject for ownership, quotas, pseudonyms, or release eligibility while that blocker remains.
- Produces `AuditEvent(event_type, outcome, principal_pseudonym, client_id, issuer_id, auth_method, request_id, parsed_method, tool_or_resource, required_scopes, policy_decision, trusted_source_context, deployment_id, instance_id, latency_ms, error_code, occurred_at)` and `async AuditSink.emit(event: AuditEvent, *, deadline: MonotonicDeadline) -> EmitResult`; an expired deadline records the bounded loss/backpressure outcome without attempting delivery. `principal_pseudonym` is a versioned, purpose-specific HMAC over canonical `issuer || "\x00" || sub`, never a plain hash; `client_id` is separately bounded and retained for accountability even if an explicitly documented quota/artifact policy keys on the human subject.
- Extends `create_mcp_server(...)` with a required, no-default `PrincipalSource` and a closed `OperationAuthorizationPolicy`; `create_app(...)` passes the production `SdkAuthContextPrincipalSource`, explicit `TokenVerifier`, and `AuthSettings` to `Server.streamable_http_app(...)`. `SdkAuthContextPrincipalSource.current()` calls `mcp.server.auth.middleware.auth_context.get_access_token()` exactly once, rejects a missing context, and copies only validated safe fields. The only direct `Client(server)` construction uses `tests/fixtures/sdk_principal.py::FixedTestPrincipalSource` for auth-disabled catalog/serialization contracts; that fixture cannot be imported by production code or included in a wheel/deploy pack and is never authentication evidence. The low-level handlers and any supported transport authorization extension use the same immutable operation-to-scope map, with no route-header-derived identity.
- Global SDK scope: `nplg:connect`. Desired operation scopes are `nplg:search` for search, `nplg:metadata:read` for metadata/file inventory, and `nplg:artifact:read` for private-full artifact/resource reads, but public eligibility requires the Phase 0 `SdkAuthorizationCapabilityVerdict` to prove a supported parsed-operation-to-HTTP-403 seam. The static SDK middleware alone must never be represented as fine-grained enforcement or as advertising these operation scopes.
- Produces one closed OIDC configuration for both selected profiles: non-secret `DEPLOYMENT_PROFILE`, literal `NPLG_AUTH_MODE=oidc`, `NPLG_CANONICAL_MCP_URL` (the public `/mcp` transport endpoint), `NPLG_BACKEND_RESOURCE_SERVER_URL` (the exact backend-local value passed to `AuthSettings.resource_server_url`), `NPLG_PUBLIC_OAUTH_RESOURCE_URL` (the exact client-facing OAuth `resource` identifier), `NPLG_MCP_ALLOWED_HOSTS_JSON`, `NPLG_MCP_ALLOWED_ORIGINS_JSON`, `NPLG_OIDC_ISSUER_URL`, `NPLG_OIDC_JWKS_URL`, `NPLG_OIDC_AUDIENCES_JSON`, `NPLG_OIDC_ALGORITHMS_JSON`, derived/frozen `NPLG_OIDC_REQUIRED_SCOPES_JSON`, `NPLG_JWKS_TIMEOUT_MS=3000`, `NPLG_AUTH_CLOCK_SKEW_SECONDS=60`, and `NPLG_ACCESS_TOKEN_MAX_LIFETIME_SECONDS=300`. The provider and Alpic capability records bind the exact transport/backend-resource/public-resource/token-audience relationship; equality is required only where the selected provider/edge contract requires it, and no URL is silently derived from another. Pass the issuer's byte-exact configured string through `AuthSettings.model_validate`; do not preconstruct, strip, append a slash to, case-fold, default-port-normalize, or percent-normalize it because issuer comparisons are exact. JSON list fields are strict arrays, with only an explicit empty Origin array allowed as a default. Reject missing/extra/duplicate/unknown keys, every static/private credential key including `NPLG_PRIVATE_STATIC_TOKEN`, and legacy `API_BEARER_TOKEN`/`API_KEY`/`X-API-Key`; an environment without the governed issuer contract remains staging-blocked rather than selecting a second authentication stack. Provider read-only `ALPIC_HOST` and comma-separated `ALPIC_CUSTOM_DOMAINS` are observed facts only: strictly parse/canonicalize/duplicate-check and compare them with the explicit URL/JSON allowlist; they never derive a resource, audience, issuer, or policy.

- [ ] **Step 1: Write failing auth/audit tests**

First generate and verify the selected Auth0-tenant/Alpic-DCR capability record. Its RED matrix must reject the generic `{tenant}.us.auth0.com` template, an unbound custom domain, tenant/issuer mismatch, an Auth0 discovery document without evidence of the requested API audience, a missing or unexpected token format, conflated backend-self/token/public-edge issuer roles, a backend `registration_endpoint`, a missing post-pool Alpic `registration_endpoint`, and a pool bound to the wrong Alpic environment. Only a proven `signed_jwt` result permits adding `PyJWT[crypto]==2.13.0` and `cryptography==50.0.0`, regenerating/syncing the hash lock, and adding typed behavior-free JWT auth/audit interfaces; an opaque or unselected result is an observed stop, not permission to guess a token format. Prove the focused modules collect before running any case.

Cover missing, expired, not-yet-valid, overlong-lifetime, wrong issuer, single/wrong/ambiguous multiple audiences, wrong algorithm, ID-token or token-purpose substitution, missing scope, unexpected `authorization_details`, ambiguous credentials, quota exhaustion, reconnect, and cross-principal request/session IDs. Require a bounded signed `client_id` or the one configured `azp` mapping and distinguish two OAuth clients sharing the same issuer/subject; reject missing, duplicate, array-valued, or disagreeing client claims. Prove exact `AccessToken(token=raw_token, client_id=..., scopes=[...], expires_at=..., resource=..., subject=..., claims={"iss": ...})` construction with canonical bounded values. The base SDK model's repr includes its required token, so project code must never repr/log/serialize/persist the model; canary tests instrument every logging/error boundary and prove only a copied safe `Principal` escapes request scope. In the production modern/stateless configuration, the trusted outer middleware explicitly rejects any `Mcp-Session-Id` header before SDK dispatch; test single/duplicate/empty/overlong/legacy-looking values, exact bounded error, zero verifier/handler entry, and a mutation that merely lets the pinned SDK ignore the header. Assert the server issues no session ID and no principal state survives a request. In the separate non-production legacy stateful fixture, prove the pinned SDK binds each session identifier to authenticated issuer+subject+client identity and rejects reuse after any identity change; never trust `_meta.clientInfo`, MCP metadata headers, forwarding headers, or request IDs as principal identity, and never report that fixture as deployed legacy support. Add strict configuration tables for every declared environment key, secret classification, unknown/duplicate key, missing/inconsistent base/resource/path value, `ALPIC_HOST` versus custom domain, and rejection of every static/legacy credential configuration.

Add issuer-capability cases for account deletion/recreation, tenant migration, pairwise/public-subject mode or sector-identifier change, issuer/tenant drift, subject reuse, immutable mapping lookup failure, ownership migration, and two clients sharing one human account. A local synthetic issuer can prove parser behavior only; public closure requires the selected issuer's machine-bound non-reassignment evidence. Mutating `supported`, issuer/tenant/subject type, evidence digest, review date, or blocker must fail and cross-map to ASVS 10.3.3 plus every ownership-dependent authorization row.

Consume the Task 0 Alpic OAuth-discovery verdict in a dedicated raw-wire matrix. No credential and a syntactically valid but unverifiable token, each combined with absent or handshake-era protocol version, must reach SDK authentication and return 401 with the frozen challenge before any version/session/handler entry. A valid token with absent/handshake-era version must invoke the verifier exactly once, then receive the bounded project 400 with zero session/handler entry. A valid token with `2026-07-28` reaches dispatch; duplicate/ambiguous authorization framing is rejected before verification. Freeze the public transport URL, backend-local `AuthSettings.resource_server_url`, challenge `resource_metadata`, GET route reached by that URI, backend metadata document's `resource`, public OAuth resource, accepted token audience, and any Alpic rewrite as one typed relationship. Exercise both RFC-permitted root-resource and path-specific-resource candidates before selecting one; never equate `/mcp` transport with OAuth resource by convention. A root-versus-path or local-versus-public mismatch without a documented and witnessed mapping is a stop/go blocker, never permission to add an ungoverned alias or rewrite. If the detector fixture is only a bounded approximation, preserve `ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN` even when every local case passes.

Split the test evidence boundary explicitly. `tests/contracts/test_sdk_client.py` uses only the governed fixed test principal to exercise catalogs, strict argument/output projection, resource serialization, and legacy/modern client compatibility; assert that it cannot import the production auth-context source and label its report `auth_evidence=false`. Every authenticated production positive/negative—including missing auth context, valid identity, two concurrent principals, cancellation, verifier failure, context reset, coarse-scope denial, and handler-entry count—runs through the real Streamable HTTP ASGI application in `tests/security/test_auth.py`/`tests/conformance/test_mcp_http.py`. A deliberate production mutation that substitutes the fixed source or permits a missing SDK auth context must fail.

Attack JWKS handling with timeout, oversized/key-flood responses, duplicate `kid`, wrong key type/size/use, redirects, private/rebound addresses, stale keys, and unknown-`kid` refresh storms. Reject token-controlled JOSE trust sources `jku`, `x5u`, `jwk`, and `x5c`, plus unsupported `crit`, `b64`, and `zip`, before any outbound request; add raw compact-JWT cases for duplicate JOSE/claim keys, invalid base64url/UTF-8, wrong segment count, and configured-JWKS lookup isolation. Freeze at least 128-bit cryptographic security: RSA is 3072 bits minimum with a reviewed finite maximum, ES256 is canonical P-256 only, purpose-specific HMAC roots are at least 256 random CSPRNG bits, and hashes are SHA-256 or stronger. Test RSA 2048/3071/3072/maximum/maximum+1, malformed/noncanonical JWK coordinates/integers, and bounded verification CPU. Prove the inbound bearer-token canary is absent from all NPLG/JWKS/scanner/worker calls. Flood invalid tokens and unknown keys to prove a cheap pre-auth connection/request/body budget runs before JWT crypto/JWKS work, and prove client-controlled forwarding headers cannot select its identity bucket.

`tests/property/test_auth_properties.py` generates bounded arbitrary compact-JWT segments, JOSE headers, claims, JWK sets, scope/client identities, and configuration-union shapes. Each example either yields one strict safe value or a bounded rejection, never crashes, leaks, fetches an attacker URI, creates an unbounded refresh, or bypasses policy. Preserve failing examples/seeds in the adversarial corpus and prove deliberate duplicate-key/trust-source/scope/config acceptance mutants are killed.

For `private-full`, remove the HTTP asset route and expose files only through authenticated MCP resources; prove resource access requires its selected profile scope, cross-principal access is denied, legacy query-token/bearer-capability URLs are rejected, and neither catalog nor result contains credential material. Freeze the RFC 9728 protected-resource metadata document with canonical `resource`, exact `authorization_servers`, and minimal `scopes_supported` without `offline_access`. The metadata route is unauthenticated `GET` (and only explicitly supported `HEAD`/`OPTIONS`) but retains Host/Origin/admission/response policy. Because SDK AuthenticationMiddleware otherwise processes bearer headers across the whole app, the trusted outer middleware removes `Authorization` only on this exact well-known route after rejecting duplicate/invalid header framing; tests cover absent/malformed/duplicate/valid credentials, unchanged body/response, zero `TokenVerifier`/handler call, and a mutation that fails if stripping broadens to `/mcp`. Wrong method/body returns exact 405/400. `/mcp` alone requires the SDK bearer backend. Freeze raw 401 and conditional supported-seam 403 challenges separately. Reject query credentials, `X-API-Key`, multiple/ambiguous `Authorization`, and prove exactly one SDK verifier call with no token copied downstream. Assert logs never contain bearer/API keys, signed URLs, query text, metadata values, filenames, PDF contents, filesystem paths, or tracebacks.

Consume the Phase 0 `SdkAuthorizationCapabilityVerdict` before implementation. Its raw-wire regression authenticates a token with only `nplg:connect`, requests a known operation requiring one additional scope, and requires SDK-parsed identity to produce HTTP 403 plus a syntactically valid `WWW-Authenticate: Bearer` challenge containing the exact `resource_metadata` URL, `error="insufficient_scope"`, and only that minimum `scope`. It proves the decision does not come from `Mcp-Method`/`Mcp-Name` headers or a second private JSON-RPC parse and that a sufficient token reaches the handler once. For pinned SDK 2.0.0 the expected reviewed result is `unsupported`: its static `RequireAuthMiddleware` runs before MCP parsing and there is no public parsed-operation HTTP-response seam. Preserve that result as release blocker `MCP_DYNAMIC_SCOPE_403_UNSUPPORTED`; continue coarse-auth/audit staging work, but do not advertise operation scopes or substitute an HTTP-200 tool error, spoofable edge header, private reparsing, or late plan stop. A future supported upstream callback or separately reviewed adapter must rerun the same RED/GREEN/failure-sensitivity proof before this blocker can close.

Freeze the separately executable static-scope 403: a valid token missing `nplg:connect` is rejected before handler entry with SDK HTTP 403 and exact `error="insufficient_scope"`/`resource_metadata`, but pinned v2.0.0 omits the MCP-recommended minimum `scope` challenge parameter. Record that byte-exact behavior in `contracts/accepted-sdk-differences.json`, the ADR, and the capability record with upstream source/issue and stable finding `MCP_STATIC_SCOPE_CHALLENGE_OMITS_SCOPE`; never assert the missing parameter exists. Public eligibility keeps the finding open unless a supported SDK fix/adapter passes the raw-wire test or a separately reviewed protocol-deviation policy explicitly determines the SHOULD is non-blocking without weakening ASVS claims.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/security/test_auth.py tests/security/test_audit.py tests/conformance/test_mcp_http.py tests/unit/test_admission.py -q`
Expected: FAIL because current credentials identify no principal and logs have no typed security-event contract.

- [ ] **Step 3: Add profile-specific verification**

For a provider verdict selecting `signed_jwt`, verify the Step 1 lock contains `PyJWT[crypto]==2.13.0` and `cryptography==50.0.0` with hashes. Construct `OidcJwtTokenVerifier` and profile-specific `AuthSettings`: metadata freezes `required_scopes=["nplg:connect"]`; while dynamic authorization is unsupported, private-full either freezes coarse `required_scopes=["nplg:connect", "nplg:artifact:read"]` for every `/mcp` call (documenting the least-privilege trade-off) or carries `PRIVATE_FULL_FINE_GRAINED_SCOPE_UNSUPPORTED` and is not release-eligible. `NPLG_OIDC_REQUIRED_SCOPES_JSON` must exactly equal this derived profile tuple and cannot choose policy. Consume all three Task 0 capability records before composing the route. Pass the exact configured issuer string and backend-local resource-server URL through one `AuthSettings`, and pass one verifier through a supported public SDK/vendor composition that produces the credentialless/invalid-token challenge before the modern-only version guard and still reaches the session manager only after that guard; passing a verifier without `AuthSettings`, using a private SDK member, constructing an independently parsing/static-auth stack, or registering two verifiers is a deliberate fault that must fail. The verifier validates the separately frozen public resource/audience relationship from the provider/Alpic records. The public outer middleware performs framing, Host/Origin, cheap admission, exact metadata-route credential stripping, and response policy only; it cannot make a pre-auth protocol-version decision. If any capability record is negative or the exact backend/public metadata/resource/rewrite tuple cannot satisfy RFC 9728, the selected issuer, the documented Alpic detector, and tested clients, fail protected-profile startup and preserve the stable blockers pending a reviewed SDK/vendor adapter. Consume the dynamic-scope verdict, do not advertise unsupported operation scopes, and retain its public blocker. Production configuration fixes an HTTPS issuer, public OAuth resource, and JWKS URL; the backend-local resource is HTTPS or exact loopback HTTP only when the Alpic capability record proves that documented internal hop and its public rewrite. It also fixes an unambiguous audience, RS256/PS256/ES256 allowlist, access-token purpose/client identity, and rejects ID tokens, JOSE key locations, symmetric/none algorithms, and unsupported authorization details.

Inside each official low-level handler, call the injected `PrincipalSource.current()` exactly once and never parse `Authorization` again. The production source alone obtains the verified SDK request identity through `get_access_token()`, immediately copies only validated bounded fields into the project `Principal`, and fails closed when the context is absent; the fixed test source is permitted only in the explicitly auth-disabled in-memory contract suite. Concurrent/cancelled real-HTTP request tests prove the SDK ContextVar resets after each request and never bleeds token/principal state across tasks, reconnects, exceptions, or post-request callbacks; handler code never stores the SDK `AccessToken` object.

Fetch JWKS through Task 17's pinned no-proxy network backend with certificate/hostname verification, no redirects, a three-second deadline, a 1 MiB body limit, bounded key count, unique `kid`, and strict JWK type/use/curve/key-size validation governed by `security/crypto-policy.json`. Validate token length, signature, `kid`, issuer, audience/resource, nonempty stable `sub`, unambiguous client identity, `exp`, `nbf`, `iat`, scopes, key type/size, a maximum five-minute token lifetime, and at most 60 seconds of skew only for future-facing `nbf`/`iat`; apply zero post-expiry leeway. Cache JWKS for 5–60 minutes, refresh once on an unknown `kid` with single-flight/rate limiting, and reject unknown keys immediately. A separately approved stale-known-key grace may be no longer than the token-lifetime bound, must emit alerts, and must fail closed afterward; document its compromised-key/availability trade-off. Document the five-minute maximum revocation window and require a staging identity-disable drill: the issuer stops minting tokens immediately and every already-issued token is rejected no later than its bounded expiry. If the selected issuer cannot meet that contract, public release stops and a provider-specific introspection/revocation design is required.

Use the same governed OIDC verifier for `private-full`; if the issuer cannot supply that profile's frozen coarse connection scopes, keep the profile blocked instead of introducing static authentication. Apply cheap global/pre-auth admission before JWT/JWKS work and local per-principal concurrency/rate defense before handlers, but label the latter honestly as instance-local. Only a future `supported=true` capability record may enable and advertise tool/resource-specific scope enforcement through the official SDK's parsed method/tool/resource identity. Under the pinned expected `supported=false` branch, enforce only the profile-wide SDK `required_scopes` plus principal ownership/non-disclosure decisions before repository/service access, preserve both fine-grained-scope blockers, and never describe a tool/resource result or domain denial as the missing transport HTTP 403. Trust source identity only from an authenticated, explicitly configured edge hop; otherwise key the pre-auth defense to connection-level data and ignore forwarded headers. A public horizontally scaled Alpic release additionally requires a documented identity-aware gateway limit or a separately approved shared atomic rate-limit store; a one-instance test cannot satisfy that gate.

Remove public asset capability tokens and the private HTTP asset route; private-full artifact delivery uses only the authenticated MCP resource path with principal/scope checks before existence disclosure. Preserve only cursor-signing responsibilities in `tokens.py`. Emit length-bounded canonical UTF-8 JSON Lines events through a bounded asynchronous queue/spool with a short enqueue deadline, delivery/loss counters, alert thresholds, and explicit backpressure behavior: one input event serializes to exactly one strict JSON object plus one terminal LF, with no raw CR/LF/NUL outside JSON escaping and no nonfinite/invalid-Unicode value. Independently RED/GREEN CR, LF, CRLF, NUL/C0, bidi/delimiter injection, lone surrogate/invalid UTF-8, oversized field, exception-text canary, queue-full, sink-timeout, disk-full, partial-write, crash/restart replay, duplicate replay, truncated/corrupt spool recovery, acknowledgement loss, and shutdown drain through emit, spool, replay, export, and alert parsing. Parse every emitted record back through the strict model and prove one event yields exactly one downstream record; deliberate raw-string interpolation, dropped-event, multi-record, truncation, and unsanitized-exception faults must fail. Do not automatically turn a low-risk read-only metadata request into a service-wide denial on sink outage; fail closed only where the profile's threat model justifies it, and preserve a durable local/spooled signal. Map the one-event/one-record encoding and downstream parser proof explicitly to ASVS 16.4.1. Treat Alpic durable/tamper-resistant log export as a provider-capability spike, not an assumed feature: before public release, prove its contract or approve a separate append-only collector design with UTC synchronization, retention, access control, alerting, acknowledgement, and outage behavior.

Create a profile-specific data inventory covering bearer/JWT claims, issuer+subject+client identity, trusted source context, queries, metadata, filenames, quarantine, caches, artifacts, audit spools, cryptographic material, and deployment evidence. For each class record sensitivity/protection level, confidentiality and integrity requirements, encryption at rest/in transit, exact key-inventory reference, approved secret-manager location, allowed storage/transit/logging, cache headers, access, owner, retention/purge/destruction, backup/recovery, and invalidation triggers. HMAC roots, signing keys, and credentials never live in plain environment files or build artifacts; absent verifiable provider secret storage/access evidence is a blocker.

Create a strict cryptographic inventory covering cursor and audit HMAC roots, JWT/JWKS verification keys, TLS certificates, evidence/custody signing keys, algorithms, strength, purpose, first-release Ed25519 evidence/custody key material and canonical public-key encoding, key ID, owner/source, approved storage, active/retired/revoked state, creation/rotation/overlap/destruction/compromise procedure, and dependent records. Prove active/retired/unknown IDs, bounded rotation overlap, compromised/revoked/unavailable key fail-closed behavior, versioned audit pseudonyms, and no cross-purpose key reuse. Create a separately strict logging inventory for application/SDK (OTel explicitly off), ASGI/Uvicorn, Alpic edge, provider CLI/audit, auth/JWKS, scanner/worker/container, and release tooling: exact event classes, format, destination/exporter/handler, use, access, retention, time source/synchronization, correlation, and redaction. Static/runtime tests compare the configured logger/handler/sink set exactly; an unknown exporter/handler or absent provider fact remains `Not assessed`.

- [ ] **Step 4: Run security and conformance suites**

Run: `.venv/bin/python -m pytest tests/security/test_auth.py tests/security/test_audit.py tests/security/test_tokens.py tests/property/test_auth_properties.py tests/conformance/test_mcp_http.py tests/unit/test_admission.py tests/contracts/test_sdk_client.py -q`
Run: `.venv/bin/python scripts/run_mcp_conformance.py --requirements 2026-07-28`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/auth.py src/nplg_mcp/audit.py src/nplg_mcp/http_security.py src/nplg_mcp/admission.py src/nplg_mcp/tokens.py src/nplg_mcp/mcp_server.py src/nplg_mcp/sdk_boundary.py src/nplg_mcp/config.py src/nplg_mcp/errors.py src/nplg_mcp/app.py`
Expected: PASS for profile-specific coarse OIDC connection authentication, identity, audit, configuration, and unauthenticated metadata routing; every static/legacy credential configuration is rejected, and captured logs contain required event fields and none of the seeded secrets/content. The official conformance result is labelled unauthenticated fixture/SDK integration only. The expected unsupported dynamic-scope capability record is also GREEN as a truthful structural verdict and keeps `MCP_DYNAMIC_SCOPE_403_UNSUPPORTED` open; this task does not require or pretend that an operation-level 403 succeeded.

- [ ] **Step 5: Commit checkpoint**

Stage `pyproject.toml`, `requirements.in`, `requirements.lock`, auth/audit, `mcp_server.py`, SDK boundary, middleware/config/admission/error/token/app, `security/coverage-policy.json`, docs, and the named tests, then: `git commit -m "security: add principal-aware access controls"`.

### Task 21: Make Alpic configuration and staging verification truthful

#### Files

- Modify: `alpic.json`, `deploy/ALPIC.md`, `README.md`, `.env.example`
- Modify: `.gitignore`, `security/external-test-gates.json`, `security/toolchain-lock.json`
- Modify: `package.json`, `package-lock.json`
- Create: `scripts/capture_alpic_deployment.ts`, `scripts/capture_alpic_deployment.test.ts`, `tsconfig.tools.json` (no-secret contract fixture only; not the operational provider adapter)
- Modify: `eslint.config.mjs`
- Create: `deploy/alpic-audit-dispositions.json`
- Create: `deploy/alpic-runtime-manifest.json`, `deploy/alpic-environment-manifest.json`, `deploy/alpic-submission-versions.json`
- Modify: `scripts/verify_deploy.py`
- Create: `scripts/run_alpic_staging_proof.py` (unprivileged orchestration library/test double only; never the credential-bearing release controller)
- Modify: `tests/unit/test_verify_deploy.py`
- Create: `tests/unit/test_run_alpic_staging_proof.py`
- Modify: `tests/static/test_deployment.py`
- Create: `tests/deployment/test_edge_http.py`
- Create: `tests/property/test_deployment_evidence_properties.py`
- Create after authorized staging: `docs/verification/2026-08-14-alpic-metadata-staging.md`

#### Interfaces

- Produces an Alpic Python 3.13 build that starts the `alpic-metadata` profile and a verifier that measures both distinct MCP hops: external client to Alpic edge, and Alpic client to the official Python SDK backend. `verify_deploy.py identify-deployment` parses bounded pinned-format pre-list, deploy, and post-list captures; it emits one deployment ID only when exactly one new deployment belongs to the named project/environment and completed successfully—zero, multiple, stale, failed, or ambiguous candidates fail closed. Human-readable `alpic deployment inspect` is secondary configuration evidence only: pinned 1.167.1 deliberately renders `sourceCommitId.slice(0, 7)`, so it can never prove full commit equality.
- Produces protected-helper operation `capture-alpic --tool-root PATH --cwd VERIFIED_MINIMAL_DEPLOY_PACK --stdout PATH --stderr PATH --timeout-seconds N --max-output-bytes N -- ALPIC_ARGS...`. It accepts no candidate-supplied executable, verifies the protected tool root/package lock/integrity, resolves only the reviewed Alpic/Node entry point, and constructs argv from a closed grammar. The provider helper alone receives a short-lived `ALPIC_API_KEY`; the separate MCP helper receives one access-token handle and, only for a `supported=true` capability record, one insufficient-scope-token handle. The unsupported variant rejects the extra handle and emits the required blocker; neither helper can read the other's credential or any ambient config/proxy/npm/Node/telemetry state. The outer wrapper invokes no shell, but honestly confines the pinned SDK's internal fixed-string `execSync` calls to a verified shell/Git/container/PATH/TMPDIR policy. Both helpers use isolated UIDs/namespaces/process groups, umask `077`, exclusive mode-`0600` outputs, bounded channels, and checked exit. Timeout, overflow, path/package/policy mismatch, mutation, or nonzero status kills the group and fails without rewriting prior evidence.
- Because pinned Alpic archive construction invokes ambient `git` through Node `execSync(string)` and creates `alpic-deploy-*` beneath `tmpdir()`, the trusted provider helper supplies a minimal `PATH` whose `git` resolves to the separately locked/versioned/digest-verified binary, a digest-verified confined `/bin/sh` policy with no startup configuration, and a fresh external mode-`0700` `TMPDIR` beneath its isolated run root. Fake/path-shadow Git, fake/wrong-digest shell, shell startup environment, wrong binary/version, malicious `post-checkout` hook, smudge/process filter, `working-tree-encoding`/`ident`, and temp-cleanup/recovery cases must fail without execution or leakage. Prefer raw Git blob/descriptor materialization; every unavoidable Git operation disables system/global/repository config, hooks, prompting, credentials, proxies, filters, and content-affecting attributes, then hashes raw blobs with filters disabled.
- Produces a Node-24-only candidate `capture_alpic_deployment.ts` contract fixture that normalizes injected, already captured provider JSON through the pinned `@alpic-ai/api`/Zod schema and never imports `new Alpic()`, reads credentials, or performs network I/O. It emits exactly one strict object with schema/provider/SDK version, bounded deployment ID, deployed status, environment identity, and discriminated `source_binding = {"kind":"provider-bound","sha40": LowerHexSha40} | {"kind":"unavailable","blocker":"SOURCE_COMMIT_BINDING_UNPROVEN"}`. The official response's nullable `sourceCommitId` maps to `unavailable`, not schema failure or equality; seven-character/uppercase/nonhex/non-40 values are invalid. Runtime/deploy-pack fields are forbidden here and belong to separate typed observations. Negative tests cover every malformed/extra/canary case. This proves candidate-side schema agreement only.
- The independently protected controller owns the real provider SDK adapter and its separate protected dependency lock. It calls pinned `new Alpic().api.deployments.get.v1({deploymentId})` only inside the provider helper and validates only the fields that response actually exposes, including the unique deployment/source/environment identity; it must not infer runtime configuration or a deploy-pack/canonical-wheel digest from that GET. Runtime is a separately authenticated provider-configuration observation plus active runtime probe, and subject binding is a separately captured upload-manifest/runtime-filesystem/process/import/provenance observation. The controller joins those records only when their immutable deployment/environment identities agree; any absent or non-machine-bindable runtime/subject field preserves `MINIMAL_DEPLOY_SUBJECT_UNPROVEN`. Candidate `capture_alpic_deployment.ts`/`verify_deploy.py` cannot run with provider authority or supply the accepted operational binding; a replaced candidate adapter/fabricated response must not affect the controller result.
- Produces `verify_deploy.py prepare-tool-root --candidate COMMIT --worktree ROOT --output-dir PATH`. It requires a clean detached `ROOT` at exactly `COMMIT`, requires the new canonical absolute output to be outside every registered worktree, reads the candidate's NUL-delimited Git tree, rejects submodules/symlinks/special entries, copies every regular tracked blob without following paths, verifies mode/blob digest and a complete manifest, and atomically publishes a mode-`0700` external source snapshot. This is the only directory in which staging `npm ci`, Node tests, or npm caches run.
- Produces `verify_deploy.py snapshot-worktree --worktree ROOT --output PATH` and `assert-worktree-unchanged --worktree ROOT --snapshot PATH` for the immutable controller. The snapshot uses descriptor-relative no-follow traversal, excludes only the validated `.git` administrative file/directory, and records every other path—including ignored/untracked entries—with type, mode, size, and digest. The assertion repeats that inventory after all validation commands and fails on any addition, deletion, type/mode/content change, so `git status` cannot hide ignored cache/output pollution.
- Produces `verify_deploy.py build-deploy-pack --candidate COMMIT --canonical-wheel WHEEL --manifest deploy/alpic-runtime-manifest.json --output NEW_EXTERNAL_DIR` and `verify-deploy-pack --pack PACK --manifest MANIFEST`. The closed manifest permits only the exact canonical wheel digest, minimal runtime lock/config/start stub, and an exact pack-local `.gitignore` whose sole line is `/.alpic/`; tests, docs, `.github`, security/release scripts, adversarial fixtures, Node/dev dependencies, and every harness-only tool are forbidden. Descriptor/raw-blob materialization rejects symlinks/submodules/specials and binds modes/digests without running checkout hooks or content filters. Before invoking Alpic, the isolated provider helper rejects any preexisting `.git`, then uses the digest-verified Git binary with closed configuration/hooks/credentials/filters to initialize a fresh controller-owned administrative repository and stage exactly the manifest file set; this prevents the SDK's no-repository fallback from creating an uncontrolled repo. Intercept and verify the actual selected file list and tar entries equal the manifest and exclude both `.git/**` and `.alpic/project.json`. The fresh `.git/**` tree and pinned Alpic's one private, bounded, strict-schema, canary-free `.alpic/project.json` are the only typed provider-local non-subject deltas. Descriptor-verifiable cleanup removes both on success, failure, signal/kill recovery, and controller restart; every other delta or residue fails. Later prove the runtime filesystem/process/import inventory excludes every development/test entry. If Alpic can only upload the full source tree or cannot bind the running subject to this closure, staging may proceed as explicitly non-release evidence but production eligibility is blocked by `MINIMAL_DEPLOY_SUBJECT_UNPROVEN`.
- Produces an unprivileged `run_alpic_staging_proof.py` orchestration library and fixtures, while release-usable `staging-proof` is one of the thirteen protected operation IDs and is dispatchable only by the four-command launcher from a signed descriptor—never as a top-level controller command. Its closed internal operation record binds the candidate battery/preparation, controller policy, credential-broker descriptor, project/environment/base/MCP identities, controller-created run/evidence roots, exclusive redacted-report/operational-bundle/result outputs, and explicit staging-deploy authorization established by `initialize-run`; callers cannot pass arbitrary operation argv later. The protected controller verifies the immutable `CandidateBatteryResult`, preparation, candidate/tree/pack/lock/source-gate identities, expiry, and its own authority/artifact/revision/policy/isolation digests, then CAS-reserves the signed challenge/run ledger; a racing second run fails. Before any provider call it durably writes and fsyncs an `attempting` intent containing the run/attempt ID, exact provider-operation/request/command fingerprints, expected environment/pack, and reconciliation key. A failure proved before that intent may become terminal `aborted`, and an unreserved expired challenge becomes `expired`; neither state is reusable. Candidate code never owns this ledger. Separate brokered trusted helpers/UIDs or containers load only the provider credential or only the MCP probe credentials, close inherited FDs, and prevent `/proc`/same-UID parent-environment access; no process visible to candidate code holds either class. A missing protected controller/broker yields stable `PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE`/`CREDENTIAL_BROKER_UNAVAILABLE` before side effects, and credential values never enter argv, captures, reports, exception text, metrics, or digests. `StagingProofResult` is a strict version-2 signed object containing controller authority/artifact/revision/policy/isolation digests, `run_id`, preparation/signature/key/ledger binding, profile, candidate/tree/deploy-pack and canonical-wheel digests, timestamps, deployment outcome, runtime/environment/URL/catalog identity, evidence/report/bundle and command-graph digests, and sorted blocker IDs. Definite success atomically publishes the result and transitions `attempting -> staged`. Timeout, process death, restart, or any surviving `attempting` intent is conservatively CAS-classified `delivery_unknown` even when no result file was published; it cannot be finalized or retried. The only recovery is the protected externally read-only but ledger-state-changing `reconcile-staging` operation whose closed internal record binds preparation, policy, broker, exclusive result, and explicit provider-read authorization; it resolves the authority ledger by the preparation's run/attempt identity and emits signed `StagingReconciliationResult(outcome="accepted" | "absent" | "ambiguous", ...)` without requiring `StagingProofResult`. An exact unique accepted deployment transitions to `reconciled_present`, a bounded inventory proof of absence transitions to terminal `reconciled_absent`, and ambiguity remains `delivery_unknown` with a blocker. Only `staged` or `reconciled_present` may enter Task 22 finalization; `reconciled_absent` requires a separately authorized fresh preparation. `staging-proof` exits 0 only after durable `staged` result publication, exits 20 only after durable `delivery_unknown` classification (the result file may be absent), exits 21 for a proved pre-side-effect abort/expiry, and every other nonzero follows the launcher table. `reconcile-staging` exits 0 only for accepted/finalizable, 22 for absent, and 23 for ambiguous. Remote exactly-once is claimed only with a proven provider idempotency key. Fault tests send SIGKILL before/after intent fsync, provider request/response, result temp write/fsync/rename, parent fsync, and ledger CAS; restart always yields one recoverable state and at most one local attempt. Unit tests also attack a fake candidate that replaces every candidate-side release script, reads environment/`/proc`/FDs, fabricates PASS, installs `.pth`/sdist hooks, or mutates policy; none can see secrets or control the trusted result.

- [ ] **Step 1: Write failing static and budget tests**

Assert the Alpic command selects `DEPLOYMENT_PROFILE=alpic-metadata`, installs exact hashes, starts within the platform window, and has no custom health/metrics, PDF, or runtime-asset payload claims. Keep separate route inventories: the backend application exposes `/mcp` plus its exact SDK-generated RFC 9728 route; the public Alpic edge may own `/`, `/mcp`, always-present `/assets`, optional `/try`, and conditional authentication/DCR routes. Every observed edge route must be classified as platform-owned, backend-proxied, or unexpected; disable Playground for production unless explicitly approved. Do not demand absence of documented platform routes.

Add the Task-0-frozen Alpic OAuth detector fixture as a first-class deployment node, not an incidental missing-token case. A vendor-supplied versioned raw fixture is the exact case; without one, run the bounded documented approximation matrix and preserve `ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN` rather than relabeling it exact. The direct backend and public edge must return SDK-owned 401 plus the frozen challenge for every applicable unauthenticated `initialize`, the challenged URI must GET the exact strict protected-resource document, and neither request may reach version routing, legacy dispatch, the session manager, or a tool handler. Freeze the complete public-transport/backend-resource/challenge URI/metadata route/backend document resource/public OAuth resource/token audience/provider rewrite tuple. Reject an unobserved or unbound alias/rewrite; an Alpic-owned backend-local-to-public rewrite is accepted only when the deployment observation captures its exact before/after values and binds them to the named environment. The protected provider observation must expose a strict `oauth_classification=Literal["Protected", "Public", "Unknown"]`; only exact `Protected`, bound to the named deployment/environment and detector observation digest, clears `ALPIC_PROTECTED_CLASSIFICATION_UNPROVEN`.

Pin `alpic@1.167.1`, `@alpic-ai/sdk@1.167.1`, and `@alpic-ai/api@1.167.1` as direct development-only dependencies with reviewed integrity and reject an unpinned/global CLI or a hoist/transitive-only contract import in verification scripts. Add the typed behavior-free evidence helper and its injected-API test seam first. `tsconfig.tools.json` extends the Task 10 strict settings, enables `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `noPropertyAccessFromIndexSignature`, `useUnknownInCatchVariables`, `verbatimModuleSyntax`, and `erasableSyntaxOnly`, emits nothing, and includes only the helper/test; Node 24 executes only erasable TypeScript. Add deterministic Zod/helper cases for a provider-bound full SHA, conforming null-to-`SOURCE_COMMIT_BINDING_UNPROVEN`, seven-character/uppercase/nonhex/non-40 commit rejection, wrong ID/environment, non-deployed status, forbidden runtime/pack or extra normalized key, provider-contract rejection, and credential/error canaries. Add deterministic provider-binding/deployment-identification tests for exact argv, unique before/after ID, strict validation, output bounds, cleanup, no-symlink files, secret non-logging, and every ambiguous/failure outcome. The isolated-helper tests prove telemetry is disabled, config/TMP roots are fresh external mode `0700`, ambient Alpic/npm/proxy/Node/shell variables are absent, and fake telemetry/Git/shell executables are rejected. A discriminated credential-union test proves `supported=false` supplies exactly one MCP access-token handle plus the blocker, while `supported=true` requires the second insufficient-scope handle and 403 probe; missing or extra handles fail before deployment, and no secret crosses helpers or enters a digest. Add a separate named `prepare-tool-root` microcycle whose initial typed scaffold deliberately raises `NotImplementedError`; test wrong/dirty commit, relative/preexisting/contained/symlink output, submodule/symlink/special Git entries, mode/blob/manifest mismatch, partial-copy cleanup, and atomic publication. Test the protected controller snapshot/policy against ignored-file creation, symlink/type/mode/content changes, `.git` lookalikes, traversal races, malformed snapshots, and partial output.

Add a separate minimal `build-deploy-pack`/`verify-deploy-pack` microcycle. Positive fixtures contain only the canonical wheel, exact runtime lock/config/start stub, and sole-line `/.alpic/` pack `.gitignore` declared by `deploy/alpic-runtime-manifest.json`; negative fixtures inject tests, docs, `.github`, security/release tooling, conformance fixtures, dev/Node dependencies, a second wheel, broader ignore, symlink/special/submodule, mode/digest drift, filtered path, ignored sibling, extra `.alpic` state, runtime import, or TOCTOU replacement. Prove the actual selected list/tar equals the closed subject, permits only the typed controller-owned `.git/**` and provider-owned `.alpic/project.json` administrative deltas, excludes both from upload, validates the saved Alpic JSON schema/canary absence, and descriptor-cleans all administrative state on success, failure, kill between `git init`/index/archive phases, and controller restart. Reject a preexisting/symlink/special `.git`, malicious local config/hooks/attributes, unexpected ref/object, partial cleanup, or any other before/after delta. Prove the runtime inventory contains no forbidden entry. If provider source detection is unavoidable, confine it to `release_usable=false`. Add a protected-controller runner microcycle covering controller/policy mismatch, candidate replacement, hostile install hooks, Git/shell/filter attacks, wrong PATH/TMPDIR, `/proc`/FD access, wrong subject/result, omission/reorder/partial failure, and version-2 blocker binding. Test freshness, challenge races, delivery-unknown reconciliation, no output before validation, and 20-second cancellation.

`tests/property/test_deployment_evidence_properties.py` generates bounded provider/capture JSON, command records, minimal-pack manifests, Git-path bytes, environment unions, and signed state transitions; each example yields one strict normalized result or bounded rejection with no write/exec/credential access. Preserve shrunk failures/replay seeds and kill deliberate parser/manifest/path/ledger acceptance mutations. The TypeScript suite also mutates private copies to remove `z.strictObject`, full-SHA/deployed/ID/environment checks, and canary redaction; configuration mutants remove `DEPLOYMENT_PROFILE`, broaden `.gitignore`, or omit actual file-list/tar verification, and every mutant must make a named gate fail.

Define exact public-edge tests for RFC 9728 discovery, framing/duplicate headers, non-identity `Content-Encoding` and compressed bombs, HTTP/2-to-HTTP/1 translation, and `TRACE` rejection. For `/mcp`, metadata, every challenge/error, and every classified provider route, byte-assert applicable CSP, `nosniff`, `Referrer-Policy`, CORS, `Cache-Control: no-store, no-transform`, content type/charset, and HSTS `max-age>=31536000; includeSubDomains`; SSE also preserves one `X-Accel-Buffering: no` and a controlled comment keepalive. Probe plain HTTP without credentials and require no transparent 30x-to-HTTPS. Add the immutable `testssl.sh` v3.2.4 record to `security/toolchain-lock.json`: annotated tag object `ae939a9faa19e2e603673eb954ca0b2900b0798a`, peeled commit `97763a411c525720a5f9bd9d2cded416b10f210a`, pinned signer fingerprint `D8342DA2F5041387E17F4CA14D9CA7F2E2FA20B3`, canonical archive `https://codeload.github.com/testssl/testssl.sh/tar.gz/refs/tags/v3.2.4`, exact size `6,997,454`, and SHA-256 `98528f8a0ac07f1e226efaa8ead438247df8efcb8fee4e056a937ab82a305490`. Cryptographically verify the annotated tag against that full fingerprint and record the signing-time/current-expiry disposition; GitHub UI “verified” is not the verifier. Prove the traversal-safe extracted archive inventory/tree matches the pinned tag tree. On the protected Linux x86_64 controller, also pin `bin/openssl.Linux.x86_64` size `4,459,984`, SHA-256 `e2e993074c87e8df4ab8271185f9789b1dfb9f20d5dfe331824282af34902543`, and exact first version line `OpenSSL 1.0.2-bad (1.0.2k-dev)`; unsupported architectures remain an explicit operational blocker rather than falling back to ambient OpenSSL. The protected controller bootstraps it like other external tools and records the full offered/negotiated suite matrix. Active negative handshakes reject TLS 1.0/1.1 and prove the approved TLS 1.2/1.3/cipher/hostname/chain policy; provider configuration evidence and edge-to-origin encryption are separately bound. Unknown tool/OpenSSL identity or incomplete TLS 1.3 evidence remains `Not assessed`.

Add pre-ASGI provider/Uvicorn controls and bounded live negatives for request-line/URL length, header count, per-header/aggregate bytes, header-read/idle timeout, connection concurrency, HTTP/2 SETTINGS/stream ceilings, slow headers/readers, and rapid-reset patterns; use a controller-owned rate-capped probe and never an unbounded load generator. From an untrusted network the origin is unreachable while Alpic succeeds through mTLS/provider identity or equivalent; spoofed edge headers fail and RFC 9728 audience names only the public URL. Test multi-instance principal limits and actual Host/Origin. Require a deployment-bound provider SBOM or signed base OS/Python/edge/proxy/installed-component inventory plus patch SLA; absent managed-runtime evidence blocks ASVS V15.1.2. `tests/deployment/test_edge_http.py` registers exact nodes; unsupported origin, transport-limit, TLS/header/SSE, managed-runtime, distributed-quota, or dynamic-scope evidence becomes a stable blocker rather than PASS.

Before Step 2, expand every independently rejectable invariant in Step 1 into the global external TDD ledger: exact node, intended failing assertion, minimum symbol/configuration, refactor decision, and named fault/mutant. This includes provider JSON normalization, source/deploy-pack binding, helper isolation, Git/shell/archive behavior, every edge control, OAuth detector/challenge/metadata tuple, protected classification, environment closure, credential separation, and crash reconciliation. The aggregate old-configuration/unimplemented-helper failure below is bootstrap evidence only and cannot witness any later row.

- [ ] **Step 2: Observe RED**

Run: `.venv/bin/python -m pytest tests/static/test_deployment.py tests/integration/test_profiles.py tests/unit/test_verify_deploy.py tests/unit/test_run_alpic_staging_proof.py tests/property/test_deployment_evidence_properties.py -q`
Run: `npm ci --ignore-scripts`
Run: `npm run deployment:evidence:typecheck`
Run: `npm run deployment:evidence:test`
Expected: Python/TypeScript collection and type checking PASS; focused assertions FAIL because current Alpic configuration still initializes full local artifact settings and the bounded capture/unique-deployment/full-binding behavior is deliberately unimplemented.

Do not proceed with a grouped GREEN from this aggregate failure. Execute Step 3 only one completed ledger row at a time, observing its focused RED/GREEN/refactor/fault sequence before the aggregate commands are rerun.

- [ ] **Step 3: Update build/start/docs/verifier**

Add exactly `/.alpic/` to `.gitignore`; reject `.alpic`, `.alpic*`, `**/.alpic/**`, or any broader rule. This is a provider-local state exclusion, not permission to ignore arbitrary generated files. Pin the Alpic 1.167.1 saved configuration to a strict bounded JSON object with required `projectId`, `teamId`, `projectName`, `environmentId`, and `environmentName`, optional `teamName`, and no other keys; every value is a bounded identifier/name, the requested project/environment IDs must match exactly, and no value may equal or contain any secret canary.

Before relying on source detection, perform a stop/go build/auth-capability spike for this exact official SDK low-level `Server.streamable_http_app()` nested in a FastAPI/Uvicorn entry point. Archive the linked project's supported transport setting and complete successful build/start log, then invoke the vendor-supplied detector fixture or the explicitly labelled bounded documented approximation matrix and fetch every challenge's protected-resource metadata URI. Require SDK 401/challenge before the modern-only guard, tuple equality with `contracts/alpic-oauth-discovery-capability.json`, zero legacy/handler entry, and provider classification `Protected`. An approximation never clears `ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN`. Alpic documents detection through its own recognized MCP entry patterns, so if a dashboard transport/start/auth override is required, record it as immutable deployment configuration. A modern-header assumption, unbound root-versus-path or backend-versus-public resource mismatch, `Public`/unknown classification, unsupported app pattern, or missing machine-readable classification is a stop for vendor confirmation or a documented adapter; never add dead-code detector markers, an ungoverned metadata alias, or an anonymous legacy exception.

Treat Auth0 application and Alpic DCR-pool configuration as a separate protected operational node, not as part of source deployment. After the named environment is detected as `Protected`, require an authority-signed receipt for: the exact Auth0 tenant/application ID; the exact callback URL displayed by Alpic and registered in Auth0; least-privilege scopes; the Alpic team/project/environment and DCR-pool identity; proof that backend authorization-server metadata referenced itself as issuer and omitted `registration_endpoint` before pool creation; and proof that the public edge advertised the expected Alpic `registration_endpoint` afterwards. The controller may consume only a short-lived broker handle for the upstream client secret and must never place that secret in argv, source, ordinary environment evidence, logs, or the MCP probe process. Rotation updates the existing pool and proves existing dynamic registrations still work; deletion is forbidden for an environment with issued clients and is allowed only under a separately approved decommission/native-DCR migration procedure. Missing feature entitlement, callback binding, redacted pool observation, or before/after discovery evidence preserves `OAUTH_END_TO_END_FLOW_UNPROVEN` and `ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN`.

Keep total environment key/value material under 4 KiB, secrets outside source/build artifacts, anonymous access off, and all upstream timeouts below the local deadline. `.env.example` and strict `deploy/alpic-environment-manifest.json` enumerate every Task 20 non-secret runtime key plus blank secret names; bind its byte count/digest to environment and deployment evidence and reject missing, duplicate, unknown, legacy-auth, or inconsistent base/MCP/issuer/JWKS/Host/Origin values. Provider and MCP credentials are never loaded together: `ALPIC_API_KEY` exists only inside the isolated trusted provider helper, `ALPIC_STAGING_ACCESS_TOKEN` only inside the isolated MCP probe helper, and an operation-insufficient-scope token exists only when a supported dynamic-403 capability verdict requires it. No real value is committed. Store Alpic credentials and cryptographic roots only in verified environment secret-manager controls with least privilege; document inventory, owner, creation, rotation, revocation/destruction, and access review. Docker uses mounted secrets rather than image layers, Compose plaintext, or ordinary env files.

With a fresh pre-issued staging access token, the verifier tests resource-server discovery, list, each metadata tool, missing-token unauthorized, malformed current-protocol requests, stateless reconnect/no-session-ID behavior, strict raw arguments, client/audience/purpose, and token-secret redaction. Only a later `supported=true` dynamic-scope verdict adds an insufficient-scope token and exact deployed 403/minimum-scope challenge; while the pinned verdict is unsupported, the runner omits that probe and carries `MCP_DYNAMIC_SCOPE_403_UNSUPPORTED`. It exports the exact current-protocol `Client.list_tools()` schemas and compares them with the Pydantic/Zod corpus; recursively closed schemas may not become open after deployment. A separate local legacy fixture result is diagnostic only and must not appear in Alpic deployed-support evidence. These tokens do **not** prove authorization-code issuance. A complete real-edge flow requires the separately governed Auth0/Alpic client-registration manifest and authority and executes RFC 9728 plus AS/OIDC discovery, Alpic DCR registration, PKCE S256, OAuth `resource`, RFC 9207 issuer response, least-privilege initial/step-up scope, final client/audience/purpose, missing/wrong/replayed `state`, duplicate callback parameters, authorization-code replay, redirect-URI mismatch/open redirect, PKCE-verifier mismatch, issuer mix-up, and scope escalation/downgrade cases. PKCE is not a substitute for `state`. The first `alpic-metadata` target must exercise Auth0 OIDC plus Alpic DCR proxy; preregistration, CIMD, native DCR, or a different IdP is a new reviewed plan input, not equivalent evidence. Prove the proxy behavior, exact Auth0-token/backend-self/public-edge issuer roles, callback URI, client-pool update semantics, feature availability in the named environment, and a deliberately isolated decommission-only deletion rule. Until this proof exists, emit `OAUTH_END_TO_END_FLOW_UNPROVEN` and `ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN`; do not manufacture a browser/admin flow from prose. Alpic's provider directory and generic Auth0 discovery template alone are topology evidence, not tenant capability evidence.

Before obtaining a staging access token, the protected verifier performs the credentialless detector/challenge/metadata/classification proof with no credential in its process or parent-visible environment. A separate MCP helper with the fresh token then tests authenticated absent/handshake-era version rejection after exactly one verifier call in addition to the current-protocol client suite. The credentialless proof and authenticated proof have disjoint process/command records; neither may infer the other's result.

The trusted MCP probe uses the exact SDK v2 lifecycle: create one externally owned `httpx2.AsyncClient(headers={"Authorization": "Bearer …"}, trust_env=False, timeout=...)`, pass it as `http_client` to `streamable_http_client(mcp_url, http_client=...)`, then construct `Client(transport)` inside nested async contexts and close in reverse order. Do not use `Client(url)` or a removed `headers=` transport argument. Canary tests prove the header exists only in that client, is never redirected/cross-origin copied or logged, and cleanup occurs on connect, protocol, timeout, and cancellation failures.

Before deployment, query and strictly validate the existing Alpic project's runtime, build/start command, transport, environment identity, and public URL; reject anything other than the reviewed Python 3.13/minimal-pack configuration. In pinned CLI 1.167.1 `--runtime` affects new-project creation and is ignored on the explicit existing-project/environment path, so it is forbidden in that deploy argv and never accepted as evidence. Recheck the same fields after deploy to detect TOCTOU drift.

Bind `deploy/alpic-submission-versions.json` to a closed `unsubmitted | submitted_pending | accepted | retired` state machine plus host, exact canonical scheme/host, versioned path prefix, environment mapping, public URL, host/listing version, exact `tools/list` catalog/schema digest, timestamps, actor/authority, and immutable host/provider-admin evidence reference. Candidate/staging code may create only `unsubmitted`; transitions require separate explicit submission authority and versioned host evidence, and unknown historical state blocks URL/environment reuse. For hosts such as ChatGPT that require domain continuity, every successor retains the exact submitted scheme/host while a distinct reviewed path prefix maps to its dedicated environment; environment reassignment, prefix/domain collision, aliasing, rollback, or provider-routing TOCTOU fails. Absent machine-bound domain/path/environment proof emits `HOST_VERSION_DOMAIN_CONTINUITY_UNPROVEN`. An accepted/submitted environment is never reused for a breaking change; new required parameters/tightened constraints require a dedicated versioned environment/URL, additive parameters remain optional until resubmission, and removed parameters/tools survive a two-step migration. Static/staging tests classify deltas and block fabricated transitions, incompatible reuse, collision, reassignment, and pre/post-routing drift. Also capture per-environment analytics privacy: session replay, request/response payload, user-data, and error-message collection are OFF unless separately approved; inventory unavoidable service metadata and a discriminated identity observation `{"identity_resolved": false, "user_hash_present": false} | {"identity_resolved": true, "user_hash_present": true, "hash_scheme": ..., "retention": ...}`. Raw user identity is always forbidden; a hash is recorded only when the provider resolves identity. Record plan, controller, purpose/legal basis, retention, and evidence digest. The pinned CLI/SDK exposes no privacy-settings getter/setter, and the documented paid-environment default may collect error messages, so this proof requires a separately approved protected dashboard/provider-admin evidence adapter with a strict environment-bound capture schema and only synthetic non-PII canary probes. Without that authority and machine-bound evidence, emit `ALPIC_PRIVACY_SETTINGS_UNVERIFIED`; neither manual prose nor `ALPIC_TELEMETRY_DISABLED`/CLI telemetry flags satisfy this gate.

Run: `.venv/bin/python -m pytest tests/static/test_deployment.py tests/integration/test_profiles.py tests/unit/test_verify_deploy.py tests/unit/test_run_alpic_staging_proof.py tests/property/test_deployment_evidence_properties.py -q`
Run: `npm run deployment:evidence:lint`
Run: `npm run deployment:evidence:typecheck`
Run: `npm run deployment:evidence:test`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets scripts/verify_deploy.py scripts/run_alpic_staging_proof.py`
Expected: all deterministic deployment, profile, Python/TypeScript strict, branch/diff-coverage, and verifier/orchestrator mutation gates PASS. After explicit commit authorization, stage only Alpic config/docs, `.gitignore`, `security/external-test-gates.json`, the Task-21 update to `security/toolchain-lock.json`, locked package files (including the direct `@alpic-ai/api` pin), the typed provider-binding helper/config/test, `deploy/alpic-audit-dispositions.json`, `deploy/alpic-runtime-manifest.json`, `deploy/alpic-environment-manifest.json`, `deploy/alpic-submission-versions.json`, verifier/orchestrator and their tests, `tests/property/test_deployment_evidence_properties.py`, and static/edge tests, then commit `deploy: prepare authenticated Alpic metadata candidate`. Do not create or stage the staging report yet.

- [ ] **Step 4: Perform staging proof only after explicit authorization**

The protected controller receives the signed `CandidateBatteryResult` and fresh `CandidatePreparation` as data, validates their canonical wheel, locks, trusted-source/cache receipts, and minimal deploy-pack manifest, then performs no candidate-controlled build/test work in the credentialed staging phase. It materializes the already battery-built deploy pack from its bound raw subjects into a fresh external mode-`0700` provider-helper root and proves its upload set/modes/digests equal only that closed minimal pack before and after each CLI call. It never uses the repository tree, candidate verifier, tests, docs, harness fixture, dev tools, or a Git checkout as the deploy subject. The verified Alpic CLI runs only in its isolated trusted provider helper with a minimal verified `PATH`, private `TMPDIR`/global config, and short-lived provider credential; no `node_modules`, cache, report, or provider state enters candidate or evidence worktrees.

Require explicit project, staging-environment, base-URL, and MCP-URL identifiers; no command may infer a linked/default production environment or prompt. Before deployment, capture and validate the existing project's Python 3.13 runtime, build/start command, transport, environment, URLs, and—only through the separately approved provider-admin authority—analytics/privacy settings. Snapshot deployments, then execute exactly `deploy --non-interactive --project-id ID --environment-id ID` through the closed wrapper; do not pass `--runtime`, because pinned 1.167.1 ignores it for an existing project. Revalidate the minimal upload manifest and project configuration after link/config creation and deploy, re-inspect runtime fields and independently recapture privacy settings when the authority exists, and derive the unique new deployment ID. Absent privacy authority preserves `ALPIC_PRIVACY_SETTINGS_UNVERIFIED`; the public CLI/SDK cannot be made to fabricate the observation. Capture the deployment through the pinned SDK's strict machine response and bind the full source commit plus deploy-pack/canonical-wheel digest only when their separate provider observations expose and machine-bind them; a null or seven-character display value is never a SHA and yields `SOURCE_COMMIT_BINDING_UNPROVEN`. If an immutable runtime subject/provenance binding is unavailable, retain `MINIMAL_DEPLOY_SUBJECT_UNPROVEN` and do not use source/artifact equality as ASVS evidence. Deploy to authenticated staging and prove the exact Host/Origin policy, edge-to-origin encrypted/authenticated hop, origin non-bypassability, and multi-instance principal throttling when provider mechanisms exist. Wildcards, public origin bypass, spoofable edge identity, or missing shared enforcement remain public blockers.

Release-usable execution is owned by Task 22 after its secret-free protected battery emits `CandidateBatteryResult` and protected `prepare` binds it in `CANDIDATE_PREPARATION_JSON`. Task 21 supplies and tests the unprivileged library, schemas, and command contract; it never grants credentials to candidate code. An engineering-only earlier run uses a separate `release_usable=false` battery/preparation/result and cannot satisfy release import. The caller supplies only canonical external battery/preparation/controller-policy paths and two disjoint pre-created mode-`0700` output parents. The caller environment must contain no Alpic API key, MCP bearer token, signing key, or credential-file path. The protected controller validates all paths/identities before creating output, then obtains short-lived credentials through its separately protected broker only inside the isolated provider or MCP helper.

```bash
set -euo pipefail
set -o noclobber
: "${NPLG_PROTECTED_LAUNCHER:?supply the absolute digest-verified protected launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?supply the externally signed provisioning receipt}"
: "${NPLG_RELEASE_CONTROLLER_POLICY:?supply the protected controller policy}"
: "${NPLG_CREDENTIAL_BROKER_DESCRIPTOR:?supply the non-secret protected broker descriptor}"
: "${CANDIDATE_BATTERY_JSON:?supply the immutable candidate battery result}"
: "${CANDIDATE_PREPARATION_JSON:?supply the fresh protected preparation record}"
: "${ALPIC_RUN_PARENT:?supply a pre-created private external run parent}"
: "${ALPIC_EVIDENCE_PARENT:?supply a disjoint pre-created private evidence parent}"
: "${ALPIC_INITIALIZATION_JOURNAL_JSON:?supply a new initialization-journal path outside both output roots}"
: "${ALPIC_RUN_DESCRIPTOR_JSON:?supply a new descriptor path outside both output roots}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
test -x "$NPLG_PROTECTED_LAUNCHER"
for forbidden_name in ALPIC_API_KEY ALPIC_STAGING_ACCESS_TOKEN ALPIC_STAGING_INSUFFICIENT_SCOPE_TOKEN; do
  test -z "${!forbidden_name:-}"
done
"$NPLG_PROTECTED_LAUNCHER" initialize-run \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --mode alpic-staging-proof \
  --candidate-battery-json "$CANDIDATE_BATTERY_JSON" \
  --candidate-preparation-json "$CANDIDATE_PREPARATION_JSON" \
  --controller-policy "$NPLG_RELEASE_CONTROLLER_POLICY" \
  --credential-broker-descriptor "$NPLG_CREDENTIAL_BROKER_DESCRIPTOR" \
  --project-id "$ALPIC_PROJECT_ID" \
  --environment-id "$ALPIC_STAGING_ENVIRONMENT_ID" \
  --base-url "$ALPIC_STAGING_BASE_URL" \
  --mcp-url "$ALPIC_STAGING_MCP_URL" \
  --run-parent "$ALPIC_RUN_PARENT" \
  --evidence-parent "$ALPIC_EVIDENCE_PARENT" \
  --initialization-journal-json "$ALPIC_INITIALIZATION_JOURNAL_JSON" \
  --run-descriptor-json "$ALPIC_RUN_DESCRIPTOR_JSON" \
  --authorize-staging-deploy
"$NPLG_PROTECTED_LAUNCHER" run-through \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$ALPIC_RUN_DESCRIPTOR_JSON" \
  --through staging-proof
```

The launcher is an absolute protected-environment entry point bound by the provisioning receipt; it performs environment clearing, descriptor-safe canonicalization, mode/owner/device checks, executable/policy/broker verification, and controller invocation internally without resolving caller `PATH`, `env`, `realpath`, `stat`, `mktemp`, `chmod`, `mkdir`, or candidate code. Before creating a root, reserving a ledger entry, or invoking a broker, `initialize-run` exclusively and durably publishes outside both roots a signed `InitializationIntent` keyed by random run ID plus the exclusive descriptor path and binding every canonical immutable input, intended root name, exact future operation argv, provisioning-receipt digest, and initialization state; publication is temp-write/fsync/rename/parent-fsync. It then creates and fsyncs the roots and atomically emits a signed `AlpicRunDescriptor` outside both roots. A crash does not magically record state: if the descriptor is absent, the only continuation is `"$NPLG_PROTECTED_LAUNCHER" initialize-run --resume --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" --initialization-journal-json "$ALPIC_INITIALIZATION_JOURNAL_JSON" --run-descriptor-json "$ALPIC_RUN_DESCRIPTOR_JSON"`, which may complete or roll back only that intent; after the descriptor exists, exit 20, exit 75, or process death continues only with `resume-run ... --through staging-proof`. Retrying without the same intent, allocating a second root/run, or changing an input is forbidden. Fault injection before/after intent temp write, file fsync, rename, parent fsync, each root creation/root fsync, initial ledger CAS, and descriptor temp write/fsync/rename/parent-fsync proves one intent, one root set, one descriptor, and no untracked authority-owned residue. `initialize-run` exit 0 means only that the descriptor is durably ready; it is never staging evidence. The following `run-through --through staging-proof` exits 0 only when that target operation is durably complete and propagates delivery-unknown, durable-incomplete, or other registered operation codes unchanged. Fake caller `env`/coreutils/PATH entries, symlink/TOCTOU roots, a changed launcher, and missing/stale provisioning receipt fail before output or authority use.

The protected controller revalidates that both output roots are disjoint from each other and every worktree, that its executable/policy/broker/controller dependency identities match the preparation, and that its minimal `PATH` resolves only the reviewed shell, Git, Node, Python, and provider CLI. Because pinned Alpic internally uses Node `execSync(string)`, the helper does not falsely claim to disable the shell: it confines a digest-verified `/bin/sh` in the isolated provider container, supplies fixed non-interpolated upstream command strings and a minimal environment/PATH, disables shell startup configuration, and tests fake-shell/path-shadow attacks. It binds a fresh private `TMPDIR`, removes temporary archives on success/failure/restart, and never creates a candidate checkout or executes candidate hooks/filters. The controller writes only exclusive redacted/digest-bound evidence, verifies the named non-production environment and minimal runtime subject, and requires an exact disposition for every audit warning/skip. Raw captures remain in protected custody until their redacted evidence is uploaded and digest-verified. Playground is staging-only when separately approved; Beacon's protected-server 401 skip is never protocol/security evidence.
The protected controller/helper writes only redacted/digest-bound evidence, refuses credential arguments, verifies inspected URLs/IDs identify the named non-production environment, binds the full source commit plus minimal-pack/canonical-wheel identity where provider evidence permits, and requires an exact disposition for every audit warning/skip; unknown, missing, or stale IDs fail. Candidate `verify_deploy.py` output is diagnostic input only and cannot establish these privileged facts. Raw captures remain in protected custody until redacted evidence is uploaded and digest-verified. Use Playground only in authorized staging and disable it for production. Beacon's protected-server 401 skip is not protocol/security evidence; an anonymous audit deployment is outside scope and needs separate authorization.

Record a two-hop translation matrix for request protocol version, method/name/parameter metadata headers, Base64 sentinel handling, JSON/SSE negotiation, authentication/challenges, malformed/duplicate inputs, errors/statuses, notifications, reconnect/session behavior, cancellation, `ttlMs`/`cacheScope` on every cacheable result/page, and response headers. At both the direct backend and public edge, the credentialless Alpic detector and a syntactically valid invalid token combined with absent/handshake-era version must receive SDK 401/challenge with zero version/session/handler entry. A valid token combined with absent/duplicate/unsafe/unbounded or handshake-era `MCP-Protocol-Version` must be verified exactly once and then receive the project-owned bounded HTTP 400 with zero session/handler entry; literal `2026-07-28` reaches normal modern validation; safe sentinel `v999.0.0` reaches the SDK and preserves its exact agreed `-32022` versus mismatched `-32020` distinction. A provider that inserts, removes, rewrites, or collapses this header or changes the auth-before-version matrix is a release blocker. Require `private` scope for every principal- or artifact-dependent result and the first-release `0/private` policy to survive both hops. Compare direct backend observations with public-edge observations and classify every difference as documented platform translation, accepted/version-bound behavior, or release blocker. Never claim the external client's original bytes reached the backend.

The isolated trusted MCP helper obtains the Task-20-selected staging access token only from its short-lived broker handle and can prove the authenticated client flow, missing-token denial, exact deployed schema oracle, real-edge HTTP cases, and the three bounded tools. It records the sample plan and upstream rate budget before any canary. For deterministic local/server-only performance it runs at least 1,000 warm fixture invocations per tool and reports `N`, p50, p95, p99, maximum, and failure count. When explicit NPLG canary authority is separately brokered, it runs exactly 20 rate-limited warm calls per tool and 10 separately labelled cold-start samples, preserves every timing, and reports only minimum, median, maximum, and failures—never p95/p99 or an SLA inference from that small sample.

This plan does **not** invent issuer-admin, provider log-query, retention-policy, instance-selector, or credential-rotation APIs. Therefore credential rotation/old-key rejection, identity disable/no-new-token/revocation-window behavior, issuer subject non-reassignment/account-recreation behavior, log destination/retention/access, secret access review, and multi-instance per-principal throttling remain typed `Not assessed` operational blockers unless a separately reviewed provider/issuer-specific command manifest, evidence schema, authority boundary, and destructive-action approval are supplied. Missing subject evidence emits `OIDC_SUBJECT_NON_REASSIGNMENT_UNPROVEN` and cannot be inferred from a syntactically stable token claim. The protected controller—not candidate `run_alpic_staging_proof.py`—emits stable blocker IDs for every absent capability in `StagingProofResult` and the operational bundle; prose/manual observation is never PASS. Task 22 imports and preserves every blocker through structural finalize/attest, while its public `eligibility --require-eligible --require-asvs-l2` gate rejects every blocker. Record deployment/runtime/pack identity, OAuth `Protected` classification and challenged metadata tuple, exact commands/exits, TLS/framing/header/origin results, auth negatives actually executed, startup time, analytics settings, and limitations. Do not publish to a registry or production in this task.

Expected: the executable deployment/binding/two-hop checks PASS or fail with exact command evidence; unsupported provider/issuer operational claims are explicit blockers rather than false PASS results. If Playground was separately authorized and enabled for staging, record its bounded result separately. The audit JSON has an explicit disposition for every warning/skip and is never counted as independent conformance evidence. A Task 21 result with blocker IDs is a valid truthful staging attestation but cannot authorize public release.

- [ ] **Step 5: Defer any engineering-only staging-report commit**

The release-usable Task 21 result remains external input to Task 22 and is not committed here. This plan deliberately provides no engineering-only attestation-workspace, one-path commit, custody, or cleanup branch: Task 22's protected DAG permits those operations only for a finalized and custodied release-decision run, and reusing it here would violate its path allowlist and custody prerequisites. If an engineering-only staging report must later be committed, write a separate Superpowers TDD plan with its own closed descriptor discriminator, literal path allowlist, custody/cleanup state machine, protected operation/launcher receipts, exact argv/exits, crash recovery, adversarial tests, and proof that its artifacts can never satisfy Task 22 release import. Until then, keep the redacted Task 21 result in the separately governed evidence store and do not create a Git attestation commit or invoke release cleanup for it.

**Phase 6 exit gate:** the Alpic build exposes only three bounded metadata tools, every executable authenticated official-client/negative-auth case passes, deployed schemas match the strict oracle, no local artifact route/state is required, every staging audit warning/skip is dispositioned, and no full-fidelity claim is made. A truthful result may contain named provider/issuer operational blockers. A public candidate additionally requires zero blocker IDs, including provider-specific credential rotation/revocation, log access/retention, secret review, and real multi-instance per-principal throttling proof; otherwise the outcome is staging/private only.

---

## Phase 7 — Alpic Tasks Compatibility Proof and Conditional Distributed Profile

Alpic is selected as the provider for this assessment. The current provider
documentation says ordinary tool calls have a 30-second limit and recommends
MCP Tasks on a separate compute path, with a default TTL of up to six hours,
for longer work. The provider's July 2026 protocol announcement also describes
Tasks as supported on Alpic. These statements justify a bounded proof phase;
they do not prove the exact extension revision, Python SDK integration,
durable state semantics, worker termination, private artifact delivery, or
client interoperability required by this application.

### Task 21A: Produce a typed Alpic Tasks capability verdict without enabling the profile

#### Files

- Create: `contracts/alpic-tasks-capability.json`
- Create: `contracts/alpic-tasks-source-evidence.json`
- Modify: `src/nplg_mcp/capabilities.py`
- Modify: `contracts/zod/capability-contracts.mjs`, `contracts/zod/models.ts`
- Create: `scripts/probe_alpic_tasks_capability.py`
- Create: `tests/contracts/test_alpic_tasks_capability.py`
- Create: `tests/unit/test_probe_alpic_tasks_capability.py`
- Modify: `tests/contracts/zod_contracts.test.mjs`
- Modify: `tests/static/test_deployment.py`, `security/coverage-policy.json`

#### Interfaces

Add one strict Pydantic `AlpicTasksCapabilityVerdict` and an independently
written Zod 4.4.3 oracle. Both schemas use `extra="forbid"`/
`z.strictObject()`, bounded strings and arrays, exact literals, Draft 2020-12
JSON Schema, and a discriminated `supported: Literal[True] |
Literal[False]` state. The verdict records:

- exact extension identifier and revision/source digest;
- installed Python SDK package/version and an executable public-API probe;
- Alpic documentation URL, retrieval timestamp, final URL, content digest,
  advertised compute path, timeout, and maximum advertised TTL;
- separate `proven`, `unsupported`, or `not_assessed` states for SDK server
  support, SDK client support, Alpic Python integration, task creation
  durability, restart/reconnect recovery, cancellation semantics, tenant and
  principal isolation, retention/purge, artifact delivery, and client support;
- the exact staging environment/deployment/pack identities when live evidence
  exists; and
- `supported`, a bounded blocker tuple, and a reviewed date.

The blocker vocabulary is closed to
`MCP_TASKS_REVISION_UNFROZEN`,
`PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE`,
`PYTHON_SDK_TASKS_CLIENT_UNAVAILABLE`,
`ALPIC_TASKS_PYTHON_INTEGRATION_UNPROVEN`,
`ALPIC_TASK_CREATION_DURABILITY_UNPROVEN`,
`ALPIC_TASK_RESTART_RECOVERY_UNPROVEN`,
`ALPIC_TASK_CANCELLATION_UNPROVEN`,
`ALPIC_TASK_ISOLATION_UNPROVEN`,
`ALPIC_TASK_RETENTION_UNPROVEN`,
`ALPIC_TASK_ARTIFACT_DELIVERY_UNPROVEN`, and
`ALPIC_TASK_CLIENT_SUPPORT_UNPROVEN`.

`supported=true` is valid only when the exact stable extension revision is
digest-bound, both official Python SDK directions expose that revision through
public APIs, every provider state above is `proven`, every required live
evidence identity/digest is present, and `blockers` is empty. The negative
branch requires at least one blocker and forbids fields that would imply an
unperformed live probe. It is valid evidence closure, never profile enablement.

- [ ] **Step 1: Write strict Pydantic and Zod RED tests**

Write table-driven tests for the current evidence: Alpic selected, a documented
30-second ordinary-call ceiling, advertised separate Tasks compute, advertised
TTL no greater than 21,600 seconds, installed `mcp==2.0.0`, no public SDK Tasks
server/client API, `supported=false`, and the exact SDK/provider blocker set.
Add positive synthetic fixtures only for schema reachability; label them
synthetic and forbid their use as operational evidence. Reject unknown fields,
string-to-boolean/number coercion, duplicate blockers, unsupported blocker
strings, inconsistent supported states, missing/changed digests, mutable or
credential-bearing URLs, non-UTC timestamps, TTL overflow, a live claim
without deployment identity, and a supported verdict with any unproven field.
Independently mutate each discriminator and conditional validator and require
the Pydantic and Zod suites to reject every mutant.

- [ ] **Step 2: Observe contract RED**

Run: `.venv/bin/python -m pytest tests/contracts/test_alpic_tasks_capability.py -q`
Run: `npm run contracts:zod:all`
Expected: FAIL because the strict capability model, canonical contract, and
independent Zod branch do not exist. A failure caused only by a missing fixture
path is not a relevant RED; the tests must reach the absent model/schema seam.

- [ ] **Step 3: Implement the minimal typed negative verdict**

Add the strict model, canonical serialization/digest validation, Zod oracle,
one bounded source-evidence record, and one canonical current negative
contract. The Python SDK probe uses public
imports and a minimal in-memory server/client registration attempt; it does
not grep installed source, accept private symbols, monkeypatch SDK internals,
or hand-write Tasks JSON-RPC. The current verdict must retain at least
`PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE`,
`PYTHON_SDK_TASKS_CLIENT_UNAVAILABLE`, and every provider behavior not proven
by a live authorized test. A provider marketing statement or mutable docs page
may establish `advertised`, never `proven`.

- [ ] **Step 4: Observe focused GREEN and mutation resistance**

Run: `.venv/bin/python -m pytest tests/contracts/test_alpic_tasks_capability.py tests/contracts/test_zod_contracts.py -q`
Run: `npm run contracts:zod:all && npm run contracts:baseline-static`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets src/nplg_mcp/capabilities.py`
Expected: PASS with the exact negative canonical verdict and every malformed,
adversarial, and cross-language mutant rejected.

- [ ] **Step 5: Add a fail-closed probe command**

Implement `scripts/probe_alpic_tasks_capability.py` with no ambient proxy,
credential, Git, shell, or deployment authority. Its default offline mode
validates the pinned SDK public API and the strict
`contracts/alpic-tasks-source-evidence.json` record, then atomically writes
only the strict verdict. A separate `capture-sources` mode fetches only the
allowlisted HTTPS Alpic documentation, official SDK roadmap, and Tasks
specification hosts with ambient proxies, redirects, credentials, cookies,
and content encodings disabled; enforces exact status/media type and bounded
streamed bytes; and atomically emits URL, final URL, retrieval time, digest,
and closed observations without copying third-party prose. Tests cover wrong
host/status/media type, redirects, proxy variables, credential-bearing URLs,
oversize/chunk overflow, duplicate observations, response mutation, symlink/
hard-link/special-file outputs, inode replacement, interrupted writes, and
cleanup failure. Exit 0 means
`supported=true`; exit 24 means a valid, canonical/digest-bound unsupported
verdict; malformed evidence, source drift, unexpected SDK behavior, symlink or
replacement output, or an unregistered blocker is an ordinary nonzero tool
failure and publishes nothing. The current expected result is exit 24 before
any Alpic deployment command can run.

The future live mode is available only through the protected Task 21
controller and a separately authorized non-production Alpic environment. It
must bind environment, deployment, pack, SDK wheel, protocol revision, and
client identities; verify extension negotiation and per-request capability
checks; create a task before returning its handle; reconnect and poll it;
exercise unknown/cross-principal task IDs; request cancellation without
claiming worker termination; cross a cold start/redeployment only when the
provider documents that test as safe; and retrieve an authenticated artifact
without credentials in a URL. Raw evidence remains in protected custody.

- [ ] **Step 6: Prove that unsupported evidence cannot enable the profile**

Add tests that inject every negative or `not_assessed` verdict into startup,
catalog generation, deployment verification, and release-manifest selection.
Each must preserve the existing `distributed-full` startup error, advertise no
Tasks extension or methods, construct no PDF/job/artifact services, issue no
provider command, and reject release evidence that imports the verdict as a
PASS. Mutate each guard independently and require at least one test to fail.

Run: `.venv/bin/python -m pytest tests/integration/test_profiles.py tests/static/test_deployment.py tests/unit/test_probe_alpic_tasks_capability.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Expected: PASS locally while the capability command truthfully exits 24 and
`distributed-full` remains unreachable.

- [ ] **Step 7: Freeze the follow-up implementation boundary**

If and only if a later capability verdict is `supported=true`, write and obtain
approval for a separate Superpowers design and TDD implementation plan before
changing production registration. That plan must freeze the Phase 4 worker
contract and the public job-tool surface; name the durable job and artifact
stores; specify migrations, idempotency keys, compare-and-set transitions,
leases, retry/dead-letter policy, restart recovery, cross-principal denial,
retention/purge, authenticated artifact delivery without URL credentials,
quota/cost/SLOs, backup/restore, chaos tests, rollback, and operational
evidence. Alpic remains the selected provider, but any behavior that Alpic does
not prove must be supplied by a named external component rather than inferred.

**Phase 7 assessment exit gate:** a canonical Pydantic/Zod-validated Alpic
Tasks verdict is produced from current source evidence, the fail-closed guard
tests pass, and either (a) the current expected-negative verdict preserves the
startup error with exact blockers or (b) a future supported verdict triggers a
separately approved implementation plan. Phase 7 assessment completion does
not make `distributed-full` implemented, deployable, or release-eligible.

---

## Phase 8 — ASVS Evidence Closure and Release Decision

### Task 22: Close the selected profile's evidence and issue a falsifiable release report

#### Files

- Attestation checkpoint modify: `docs/security/asvs-5.0.0-l2-matrix.jsonl`
- Attestation checkpoint modify: `docs/security/evidence-manifest.jsonl`
- Attestation checkpoint modify: `docs/security/threat-model.md`, `SECURITY.md`
- Attestation checkpoint create: `docs/verification/2026-08-14-release-candidate.md`
- Machinery checkpoint create: `security/release-command-manifests.json`
- Machinery checkpoint modify: `scripts/verify_release.py`, `tests/static/test_release_gate.py`, `tests/static/test_asvs_evidence.py`

**External authority prerequisite (not produced or trusted from this candidate repository):** before Step 5, an organization-controlled `nplg-release-controller` repository must have its own separately reviewed Superpowers TDD implementation plan, protected branch/environment, immutable source commit/tree, exact dependency/OS/tool lock, reproducible build and provenance, signing/verification policy, isolated installation procedure, broker adapters, and controller-owned adversarial corpora. That external plan must split the thirteen evidence operations and four launcher commands below into focused implementation tasks; for every operation/launcher command it must record the exact implementation files and test nodes, an observed relevant RED (not setup failure), minimal GREEN, explicit REFACTOR/no-refactor decision plus rerun, property/negative/adversarial/fault/recovery cases, and mutation or deliberate-fault sensitivity before its end-to-end gate. This candidate plan defines and tests only the expected contract/fakes. It cannot create, sign, provision, or prove its own release authority.

#### Interfaces

- For an attestation that provisionally recommends public release, the `eligibility` operation always produces strict, separate signed `ReleaseEligibilityVerdict` and `AsvsL2ConformanceVerdict` envelopes binding profile, candidate/tree, attestation, subjects, operational identity, evidence manifest, SDK-capability record, minimal deploy/submission identity where applicable, and protected controller authority/artifact/revision/policy/isolation digests. `subjects` is a sorted unique tuple of closed SHA-256 roles: metadata requires exactly canonical `python-wheel`, `python-sdist`, and `alpic-deploy-pack`; private-full requires wheel/sdist plus canonical `private-app-image`, `private-edge-image`, `pdf-worker-image`, and `scanner-image` roles. The operational union distinguishes the full Alpic environment/deployment/runtime/catalog/provider-binding identity from the complete private edge, worker, scanner, quota, and recovery proofs. No verdict can be eligible/conformant with blockers/failures, identity drift, missing role, or mismatched operational variant. A third closed signed `EligibilityGateRecord` is the mandatory join/final-decision node: its payload contains the exact complete-envelope digests of both verdicts plus their shared attestation/run/profile/candidate/subject identity, `passed`, and `decision="release_recommended" | "do_not_release"`. It may say `passed=true`/`release_recommended` only when both selected envelopes are positive; otherwise it must say `passed=false`/`do_not_release` with the exact blocker/failure IDs. It cannot replace or embed an unverifiable summary of either verdict. An attestation already saying `do not release` forbids all three eligibility nodes; a provisional release recommendation requires all three even when the independent gate overturns it.
- Consumes a signed `ProtectedControllerProvisioningReceipt` from that external authority. Its closed payload binds controller repository/ref/commit/tree, source and reproducible binary/package/image digests, dependency/tool/OS lock and SBOM/provenance digests, policy/isolation/trust-root identities, protected workflow/environment identity, install root/device/mode/owner, broker-adapter identities, one `OperationTddReceipt` for each of the thirteen exact operation IDs, and one `LauncherTddReceipt` for each of the four exact launcher command IDs. Every receipt binds focused RED/GREEN/refactor commands and exits, exact collected tests, property/fault/recovery corpus, implementation mutation/fault score, source diff, and final integration result. The candidate expected-manifest digest must agree, but candidate code cannot issue or satisfy this receipt. Missing/invalid/stale/self-issued/candidate-controlled authority is terminal `PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE` before any broker, credential, deployment, custody, commit, or cleanup action.
- Produces closed `SignedEnvelope[T] = {"protected": ProtectedHeader, "payload": T, "signature": Base64UrlSignature}` records for `CandidatePreparationPayload` and `EvidenceCustodyReceiptPayload`. `ProtectedHeader` fixes envelope type/version, issuer, signing key ID, literal signature algorithm `Ed25519`, controller authority/artifact/revision/policy/isolation digests, and literal canonicalization ID `RFC8785-v1`; the 64-byte signature is canonical unpadded Base64url and every other algorithm/encoding fails. The independently protected controller policy pins the canonicalizer implementation/source/revision/dependency-lock digest and runs the official RFC 8785 vectors plus UTF-16 property-order, numeric edge, negative-zero, invalid Unicode/nonfinite, and duplicate-key preparse negatives. The signature input is the exact domain-separated bytes `b"NPLG-RELEASE\x00" + envelope_type + b"\x00v2\x00" + RFC8785(protected) + b"\x00" + RFC8785(payload)`; `signature` is excluded and JSON duplicate/unknown keys, alternate encodings, algorithm/key downgrade, cross-type/profile substitution, and replay fail. The preparation payload binds run ID, random 256-bit challenge, initial `issued` ledger state, profile, candidate/tree, battery/capability/manifest/lock/trusted-source/source-gate digests, the sorted exact pre-staging external-result envelope digests, and timestamps; its lifetime is at most 60 minutes because it is issued after the long battery and those gates. The custody payload binds profile, candidate/tree/final bundle, workflow repository/ref/SHA, immutable protected `job_workflow_ref` and workflow digest outside candidate control, run/attempt/builder, versioned artifact URI/object version, time, proof kind/digest. Key rotation/revocation/overlap follows the crypto inventory and tests active/retired/revoked/unknown keys. The authority-owned preparation ledger has the closed states `issued`, `reserved`, `attempting`, `staged`, `delivery_unknown`, `reconciled_present`, `reconciled_absent`, `committing`, `consumed`, `aborted`, and `expired`. `finalize` first CAS-transitions an eligible `staged`/`reconciled_present` entry (or a validated `issued -> reserved` entry for private-full) to `committing` while durably journaling the exact canonical bundle bytes, digest, intended exclusive path, and upstream envelope digests; it writes a same-filesystem temporary file, fsyncs it, atomically renames it, fsyncs the parent, reopens/verifies the bytes, and only then CAS-transitions to `consumed` with a pointer to that exact durable bundle. `finalize --resume` is idempotent from `committing`; every consumed entry must resolve to the exact verified bundle, so a crash can neither burn the challenge without a bundle nor produce two bundles. Missing/invalid authority is `UNTRUSTED_LOCAL_BUNDLE`, never a candidate-generated receipt.
- Produces a candidate-side expected `security/release-command-manifests.json` plus a separately protected controller manifest with identical digest. The thirteen closed evidence-state operations are `candidate-battery`, `external-gate`, `prepare`, `staging-proof` (metadata only), `reconcile-staging` (metadata recovery only), `finalize`, `custody`, `reconcile-custody` (recovery only), `attestation-workspace`, `commit-attestation`, `attest`, `eligibility`, and `cleanup-run`. The only read-only helper/preflight utilities are the literal `validate-output-parent`, `validate-output-parents`, and `capture-alpic` commands with the exact argv/output schemas specified in Tasks 21-22; reconciliation is externally read-only but deliberately state-changing in the protected ledger, cleanup is destructive and separately authorized, and neither is a vague helper side effect. There is no undocumented `candidate`/state-changing utility mode. `candidate-battery` executes candidate-controlled code only in a no-secret offline sandbox and emits provisional command evidence. Each `external-gate` runs one exact registry-owned live/container/quota proof through a separately brokered protected helper after the battery exists. For metadata, `staging-proof` imports the exact battery-built minimal pack through `reserved -> attempting -> staged|delivery_unknown`; successful `finalize` follows the crash-atomic `staged|reconciled_present -> committing -> consumed` publication. For private-full, where no staging side effect exists, `finalize` validates the entire external-result tuple and follows `issued -> reserved -> committing -> consumed`. `custody` is a strict discriminated operation invoked first with `subject_kind="candidate-bundle"` for the exact bundle and later with `subject_kind="final-decision-chain"` for canonical bytes containing the signed `AttestationCommitResult`, signed `AttestationVerdict`, and, only for a public recommendation, the complete signed `ReleaseEligibilityVerdict`, complete signed `AsvsL2ConformanceVerdict`, and signed `EligibilityGateRecord` join node. Each upload uses an immutable versioned object through the independently pinned protected workflow; ambiguous delivery must use `reconcile-custody` for the same subject kind before a receipt exists. `attestation-workspace` materializes a no-secret review workspace from raw candidate blobs and custodied evidence; after human review/edits and explicit commit authorization, `commit-attestation` permits only the five exact attestation paths and emits a signed commit result. `attest` emits truthful positive or negative typed verdicts without calling the attestation revision product code. `eligibility --require-eligible --require-asvs-l2` is mandatory for every public release recommendation; risk-accepted/nonconformant results may close only a named staging/private audit with `do not release`. Before deletion, `cleanup-run` must durably journal outside the target root the verified root identity, exact deletion inventory, and complete bytes/digests of both custody receipts plus the final attestation/eligibility chain; its exact normal/resume argv is frozen in Step 7. It refuses a symlink/mount/worktree/parent/unknown path and emits one signed `CleanupResult` outside the deleted root. None of these operations authorizes deployment/publication beyond the separately authorized staging action.
- `attestation-workspace` CAS-publishes a signed `workspace_materializing` intent before its first filesystem write, binding raw candidate/custody inputs, exact external root/inode policy, literal materialization inventory, and intended handoff path. It publishes the signed handoff only after read-back verification; `resume-run --through attestation-workspace` idempotently completes the inventory or descriptor-safely removes only its recorded partial residue. Before any Git object or ref mutation, `commit-attestation` publishes a signed `attestation_committing` intent and descriptor state binding the handoff, exact five-path NUL-delimited inventory, complete index/tree bytes and digests, parent/ref, author/committer identities/times, message, one-time protected human-authorization nonce, intended commit object ID, and ref CAS old/new values. It writes/reads back the exact objects, CAS-updates the one ref, verifies ref/commit/tree/parent, and only then publishes `AttestationCommitResult` and advances the descriptor. `resume-run --through commit-attestation` consumes the unchanged intent and nonce to recognize the exact already-created commit or complete its pending CAS; it never requests new authority or makes another commit. Divergent HEAD/ref/tree/index/edit/parent, lost or changed authorization, duplicate commit, or ambiguous ref state is a blocker. Fault injection covers every workspace intent/write/handoff/cleanup boundary and every commit intent/index/object/ref/reflog/result/descriptor write/fsync/rename/CAS boundary, including SIGKILL immediately after ref update; deliberate duplicate-commit, wrong-parent/ref, changed-human-edit, and renewed-authorization mutants must fail.
- The protected launcher has exactly four stateful top-level commands, distinct from the thirteen operation IDs and three read-only utilities: `initialize-run`, `run-operation`, `run-through`, and `resume-run`. `initialize-run` validates the provisioning receipt and immutable inputs, publishes the signed external initialization intent, creates only the declared roots/initial ledger state, and publishes the first signed descriptor; it cannot execute an evidence operation. `run-operation` dispatches exactly one operation ID permitted as the descriptor's next DAG node, with no arbitrary argv passthrough. `run-through` executes only a manifest-defined contiguous legal DAG segment and normally stops on the first nonzero/unknown state. `resume-run` follows only the one legal recovery edge selected by the signed descriptor, initialization intent, and protected ledger; it cannot create a new attempt or alter argv. The closed launcher exit table is: 0 means only the named initializer/node/through-target is durably complete; 64 means schema/argv/authority/policy rejection before durable mutation; 70 means an internal failure proven to precede any durable mutation; 75 means a caught post-mutation failure has first durably published the exact incomplete state and legal same-intent/descriptor recovery edge and therefore requires `initialize-run --resume` or `resume-run`; 20 is reserved exclusively for an externally delivery-unknown side effect; 21/22/23 retain their registered proved-pre-side-effect/reconciled-absent/ambiguous meanings; and 24 is the non-error policy result `gate_negative`, emitted only after both eligibility verdicts plus their `passed=false` join are durable. `initialize-run` cannot emit an operation code. `run-operation` propagates its selected operation's registered 20/21/22/23/24 or common 64/70/75 unchanged. `run-through` normally stops at and propagates the first registered nonzero code; the sole exception is eligibility 24 within `--through final-decision-custody`, where it records final `do_not_release`, must continue only through mandatory custody of the complete negative chain, and then returns 24 after the receipt is durable. `resume-run` preserves those same target semantics after a crash/75. A caught failure after mutation may never return 64/70, and no command may return 75 before its recovery descriptor/intent is durable. Process death has no invented exit and is recovered from the intent/descriptor. No caller may interpret initializer 0 as evidence completion or collapse 20/21/22/23/24/64/70/75 into generic failure/success. Every descriptor version contains run ID, monotonic version, previous-descriptor digest, provisioning-receipt digest, immutable input/output map, ledger state, legal next operations, and is published by exclusive atomic CAS; rollback, fork, replay, concurrent advance, skipped/reordered range, direct operation-name top-level command, unknown command/operation, privilege crossover, arbitrary extra flag, or changed receipt/input fails. Each launcher command has its own externally signed `LauncherTddReceipt`, and the external controller plan exercises crashes and caught I/O faults at every intent/descriptor/CAS boundary plus deliberate dispatcher/range/authorization and 0/20/24/64/70/75 conflation mutants before provisioning.
- `CandidateBatteryResult`, each discriminated `ExternalGateResult`, `StagingProofResult`, `StagingReconciliationResult`, `CandidateEvidenceBundle`, subject-discriminated `CustodyAttemptResult`, `CustodyReconciliationResult`, `CandidateBundleCustodyReceipt`, `AttestationCommitResult`, `ReleaseEligibilityVerdict`, `AsvsL2ConformanceVerdict`, `AttestationVerdict`, conditionally required `EligibilityGateRecord`, and `FinalDecisionCustodyReceipt` use the same closed `SignedEnvelope` mechanism and form a typed evidence DAG rather than falsely requiring a file that a hard crash may prevent. Metadata finalization has the exclusive predecessor union `StagingProofResult(outcome="success", ledger_state="staged") | StagingReconciliationResult(outcome="accepted", ledger_state="reconciled_present")`; the accepted reconciliation binds directly to the durable attempt-intent digest and carries the complete deployment/evidence identity even when no staging-result envelope exists. Each subject-specific custody receipt has the exclusive predecessor union `CustodyAttemptResult(outcome="verified") | CustodyReconciliationResult(outcome="accepted", intent_digest=..., optional_attempt_digest=...)`. Downstream nodes consume the selected predecessor plus all other required parent digests, each protected header fixes its distinct envelope type, and the controller verifies the complete selected branch before emitting the next node. When `AttestationVerdict` is provisionally release-recommended, `EligibilityGateRecord` consumes the exact two verdict-envelope digests and final-decision custody preserves the complete canonical bytes of both verdict envelopes and the join record whether `passed` is true or false; when attestation already says `do_not_release`, all three eligibility nodes are forbidden. Tests cover either or both eligibility verdicts negative, required negative-chain custody, omitted/substituted/cross-run/cross-profile verdicts, a mutated join digest, result-less hard-crash reconciliation through finalize/receipt, one-bit payload/signature/digest drift, both-or-neither predecessor, missing intent, wrong branch/order/profile/subject/controller, replay, retired/revoked key, and partial/cross-envelope splice.
- For `alpic-metadata`, protected `finalize` requires exactly the common live-oracle result plus either one fresh successful Task 21 v2 `StagingProofResult` or one fresh accepted intent-bound `StagingReconciliationResult`; it never requires both and rejects `delivery_unknown`, `reconciled_absent`, ambiguous state, or an accepted reconciliation lacking complete deployment/runtime/environment/public-URL/catalog/submission/privacy/evidence identity. It validates controller/preparation/ledger, candidate/tree/deploy-pack/wheel, registered argv/non-secret environment/credential union, timeout/exits, evidence digests, command graph, freshness, and blocker IDs. Missing, extra, stale, replayed, copied, partially recorded, second staging, or source/subject mismatch fails. `private-full` requires exactly the common live result plus its five separately registered signed PDF-worker, private-edge, scanner, quota, and recovery proofs, rejects the metadata staging/reconciliation variants, and uses the same crash-atomic bundle publication.

- [ ] **Step 1: Write failing profile-manifest and runner-policy tests**

Define the public release-eligibility/ASVS-closure cases now, but keep the explicit eligibility-assertion RED for Step 4 and every operational side effect for Step 5. Public eligibility rejects `Not assessed`, `Fail`, `Partial`, `Risk accepted`, expired risk/N/A review, missing evidence revision, omitted requirement, or unjustified `N/A`; every applicable row is `Pass` and every `N/A` satisfies independent applicability governance. A fully evidenced risk acceptance may be recorded only in a named non-public staging/private audit whose terminal recommendation remains `do not release`. Extend protected-controller and candidate-side fake tests so omitted/skipped gates, survived mutants, replaced/empty/always-pass critical suites, shallow diff, stale operational evidence, subject/identity mismatch, source mutation, evidence inside candidate, or candidate/attestation confusion fails. Test forged/replayed custody and controller/preparation/ledger records, hostile hooks/filters/credentials, missing protected workflow, and invalid run roots before side effects.

Candidate-side tests enumerate all thirteen operation schemas, all four launcher-command schemas/exit transcripts, fake-runner outcomes, and expected-manifest entries separately, including every `external-gate` registry discriminator, both recovery-only reconciliation operations, `custody`, workspace materialization, the authorized literal-path attestation commit, scoped cleanup, initialization-intent recovery, one-node dispatch, legal-range dispatch, and descriptor-only resume; these tests prove contract sensitivity only. The external `OperationTddReceipt` and `LauncherTddReceipt` sets must prove the corresponding protected implementations. They demonstrate that the secret-free battery emits the immutable provisional result; selected-profile external gates consume that result through protected brokers; prepare validates/binds it and issues the challenge; metadata staging reserves it once; and finalize accepts only that battery plus the exact fresh bound operational-result tuple and crash-atomically seals the final bundle. A well-formed evidence set with blockers makes finalize/attest structurally valid and causes `attest` to exit 0 with `eligible=false`; public `eligibility --require-eligible --require-asvs-l2` exits nonzero with exactly those blockers/failures. Risk acceptance never makes public eligibility green. The protected receipts must cover every legal and illegal transition among `issued`, `reserved`, `attempting`, `staged`, `delivery_unknown`, `reconciled_present`, `reconciled_absent`, `committing`, `consumed`, `aborted`, and `expired`; signed-envelope canonical bytes; exclusive no-symlink outputs; complete controller/workflow/subject binding; and absence of release authorization. They inject a crash or I/O error before/after every journal write/fsync, temp write/fsync, rename, parent fsync, reopen/verify, and ledger CAS for both profiles. `finalize --resume` must converge to one exact bundle, while every `consumed` record must resolve to its bound durable digest; a deliberate consume-before-publication or second-bundle mutant must fail. Cleanup coverage includes wrong/parent/worktree/mount/symlink roots, unknown children, incomplete custody, preexisting result, interruption/resume, descriptor-race attempts, and a mutant that broadens the deletion target. Candidate fake transcripts must reject any omitted receipt/case/mutation or forged PASS, but cannot replace execution in the protected repository.

Give `custody` and `reconcile-custody` separate privileged-side-effect microcycles. The command-like signatures in this paragraph name internal protected operation-handler test inputs, never additional top-level launcher commands. RED first on a protected fake authority that has no immutable/versioned upload implementation. Before any upload, GREEN `custody --candidate-bundle-json BUNDLE --controller-policy POLICY --custody-authority-descriptor AUTHORITY --attempt-json NEW_FILE --custody-receipt-json NEW_FILE` CAS-creates and fsyncs one authority-owned intent keyed by bundle digest, immutable destination namespace, attempt ID, uploader/workflow identity, and exact request fingerprint; a concurrent second initial attempt fails. It then performs one bounded upload, obtains the immutable object version, reads the object back through the authority, verifies exact length and SHA-256 against the finalized bundle, durably emits signed `CustodyAttemptResult`, and only then signs/publishes the receipt. Tests cover wrong/mutable URI, object-version substitution, wrong digest/length, credential crossover, timeout before acceptance, timeout/connection loss after possible acceptance, partial upload, duplicate/replayed request, concurrent invocation, retry with and without a proven provider idempotency key, deletion/overwrite attempt, and receipt-writer failure. A process death/restart or surviving in-flight intent is conservatively `delivery_unknown` even if no attempt file exists, and emits no receipt. Only `reconcile-custody --candidate-bundle-json BUNDLE --controller-policy POLICY --custody-authority-descriptor AUTHORITY --reconciliation-json NEW_FILE --custody-receipt-json NEW_FILE --authorize-custody-read` may resolve that intent from the protected ledger: exact present/read-back-verified bytes emit signed `CustodyReconciliationResult(outcome="accepted")` and then the receipt; proven absence emits signed `CustodyReconciliationResult(outcome="absent")`; ambiguity emits `outcome="ambiguous"`, no receipt, and a blocker. The reconciliation envelope binds the durable intent digest and, when present, the attempt-envelope digest, preserving the chain without requiring a post-crash file. `custody` exits 0 only after receipt publication, 20 after durable delivery-unknown classification, and 21 only after durably publishing signed `CustodyAttemptResult(outcome="pre_upload_failed")`; `reconcile-custody` exits 0 only for accepted/receipt, 22 only after publishing the signed absent result, and 23 for ambiguous. After 21 or 22, the sole new-upload edge is the separately authorized launcher command `run-operation --operation custody --new-attempt-after SIGNED_PREDECESSOR_DIGEST --authorize-custody-upload`: the predecessor must be the exact same-run/profile/subject/destination `pre_upload_failed` attempt or `absent` reconciliation selected by the current descriptor. The controller CAS-transitions that terminal attempt state to one new `attempting` record with incremented attempt number and a fresh request fingerprint; stale/cross-subject predecessors, duplicate authorization, concurrent retries, a second active attempt, or changed authority/destination fail. Its exit/output semantics are the ordinary `custody` codes and it atomically advances the descriptor. Fault tests SIGKILL before/after intent fsync, upload request/response, attempt temp/fsync/rename, read-back, receipt temp/fsync/rename, the new-attempt CAS, and every ledger CAS for both custody subject kinds. Candidate code never sees custody credentials or controls the uploader/verifier. A deliberate always-success uploader, skipped read-after-write, receipt-before-verification, ambiguous-to-accepted, or retry-without-the-exact-signed-predecessor mutant must fail before the broader gate reruns.

Repeat the custody/reconciliation crash and mutation matrix for both discriminators. `candidate-bundle` accepts only the finalized bundle and emits `CandidateBundleCustodyReceipt`. `final-decision-chain` accepts exactly the signed commit result and attestation verdict plus, if and only if the verdict recommends public release, both complete signed eligibility/conformance verdicts and their signed `EligibilityGateRecord` join node; it canonicalizes and uploads all complete envelope bytes, emits `FinalDecisionCustodyReceipt`, and rejects digest-only summaries, omitted/substituted verdicts, an extra/missing join or verdict envelope, join-digest drift, or any cross-run/profile splice. Cleanup remains blocked until both subject-specific receipts read back successfully.

Test manifest selection exhaustively. `alpic-metadata` requires metadata-profile non-construction/absence tests, its reachable SDK/HTTP/auth/network/profile mutation targets, and exactly one strict import of the registered Task 21 operational result, but forbids a second staging deployment, private edge/app/PDF/scanner image builds, PDF IPC, container attack suites, and a container-runtime prerequisite. `private-full` requires all five private edge/worker/scanner/quota/recovery gates and exact already-built app/edge/PDF-worker/scanner image digests in addition to the common set. Unknown commands, duplicate IDs, execute-and-import mode confusion, reused run IDs, shell strings/interpolation, conditional skips, missing tool versions, and a selected profile's extra or missing gate all fail schema/policy validation. `distributed-full` must fail before command execution.

- [ ] **Step 2: Observe RED**

Run: `RELEASE_PROFILE=alpic-metadata .venv/bin/python -m pytest tests/static/test_release_gate.py tests/static/test_asvs_evidence.py -q`
Run: `RELEASE_PROFILE=private-full .venv/bin/python -m pytest tests/static/test_release_gate.py tests/static/test_asvs_evidence.py -q`
Expected: FAIL on the missing profile-manifest and candidate-side expected thirteen-operation/four-launcher contract; ordinary inventory/schema/digest/claim-binding assertions remain GREEN and do not claim release closure or protected-controller implementation. Do not set `REQUIRE_RELEASE_ELIGIBILITY` in this microcycle.

- [ ] **Step 3: Implement and commit the profile-aware verification machinery**

Implement only the candidate-side strict schema/fixture helpers and expected thirteen-operation/four-launcher manifests under the still-incomplete matrix; release authority and every protected implementation reside in the independently pinned controller/workflow, not `scripts/verify_release.py`. The externally provisioned controller's common battery directly executes controller-owned offline critical gates and supplemental candidate suites in a no-secret sandbox, then performs exactly two independent offline no-isolation builds from immutable raw materialized candidate blobs and locks: one quarantined comparison wheel/sdist and one canonical wheel/sdist. It does not grant live-network, provider, container-daemon, or host-slot authority to candidate code. It compares exact reviewed archive views before selecting subjects; only canonical subjects proceed to installed-wheel tests, scans, SBOM, provenance, protected external gates, deployment, or attestation and are never rebuilt. The controller verifies exact test/case inventory, selected mutation targets, modern official-client/direct-backend suites, the pinned auth-disabled official fixture harness, locked Node/Zod/lint/type/schema/docs gates, SCA/SAST/secrets/package/filesystem scans, and trusted-source receipts. It proves the harness fixture cannot enter a wheel or minimal deploy pack and labels harness/legacy evidence narrowly. After the battery exists, the protected external-gate ledger accounts each selected operational entry once and rejects omissions/mode drift.

The metadata manifest additionally consumes the authorized Task 21 staging/two-hop evidence and proves private edge/app/PDF/store/scanner non-construction. It does not require Tasks 15-16A or a container runtime. The private-full manifest additionally requires Task 15-16A code/evidence and performs one quarantined comparison build plus one canonical build for each app, Caddy edge, PDF-worker, and scanner image from the same immutable context, exact base-image digests, locked builder, and reproducibility inputs. It requires the reviewed reproducibility comparison before selecting each canonical image ID/digest; comparison images never reach scans, tests, deployment, SBOM, provenance, or any external proof. Every Trivy and attack-suite invocation then receives only the canonical digest with rebuild disabled. Edge/recovery proofs must observe those exact subjects before and after their probes. If a provider cannot bind the deployed runtime to the tested subject digest, the manifest records an unproven control rather than asserting equality.

Run: `.venv/bin/python -m pytest tests/static/test_release_gate.py tests/static/test_asvs_evidence.py -q`
Run: `.venv/bin/python scripts/run_quality_gate.py --node-executable "$(command -v node)" src tests scripts`
Run: `.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main`
Run: `.venv/bin/python scripts/run_mutation_gate.py --targets scripts/verify_release.py`
Expected: all verification-machinery, integrity, global strict, branch/diff coverage, and mutation gates PASS in non-closure mode. Then, after explicit commit authorization, stage only `security/release-command-manifests.json`, `scripts/verify_release.py`, and their tests and commit `test: add profile-aware release verification`. The resulting clean commit may become the candidate; evidence rows remain incomplete at this point.

- [ ] **Step 4: Observe the separate selected-profile closure RED**

Run exactly one command for the Task 1-approved profile:

- `RELEASE_PROFILE=alpic-metadata REQUIRE_RELEASE_ELIGIBILITY=1 .venv/bin/python -m pytest tests/static/test_asvs_evidence.py -q`
- `RELEASE_PROFILE=private-full REQUIRE_RELEASE_ELIGIBILITY=1 .venv/bin/python -m pytest tests/static/test_asvs_evidence.py -q`
Expected: the implemented inventory/schema/digest/claim-binding machinery runs, and only the explicitly identified incomplete/failed/expired applicable rows make the release-eligibility assertion RED. A runner/import/manifest/schema error is the wrong RED. Only `eligibility --require-eligible` sets the equivalent closure flag; structural `attest` is statically forbidden from setting it. The flag asserts readiness, not authority.

- [ ] **Step 5: Run the protected battery, prepare, operational proof, and finalize sequence**

**Hard stop before any Step 5 command:** require the externally signed `ProtectedControllerProvisioningReceipt`, absolute protected launcher, all thirteen `OperationTddReceipt` values, and all four `LauncherTddReceipt` values described above. If any is unavailable, stale, self-issued, candidate-controlled, or mismatched, stop this plan after Step 4 with local diagnostic `PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE` and terminal `do not release`; do not create a run root, contact a broker/provider, or pretend a candidate-signed blocker is protected evidence. The commands below are the integration contract only after that independent prerequisite exists.

Choose one immutable candidate after prerequisite commits. The independently protected controller owns the critical gate implementations and signed case inventories; candidate tests/wrappers are supplemental inputs. It first runs the complete `candidate-battery` in a no-secret offline sandbox, directly invokes pinned linters/type checkers/scanners/contract/adversarial suites, verifies exact collected node/case inventories, and proves sensitivity with replaced-test, empty-collection, and always-PASS faults. Container/runtime probes use controller-owned harnesses against a disposable rootless daemon/VM with a fixed OCI API/mount allowlist; candidate code cannot access the host socket, controller, or slot outside the disposable root. This emits an immutable `CandidateBatteryResult`, not a final bundle.

After that potentially long battery completes, the controller runs the exact selected-profile `external-gate` rows: the common protected NPLG live oracle for both profiles and, only for `private-full`, the five protected PDF-worker, private-edge, scanner, quota, and recovery proofs. Candidate code never receives their network/runtime/slot/target/destructive-volume authority. All broker, slot, target, and recovery-volume descriptors for the selected profile are validated before the first external gate. Protected `prepare` then validates and binds the battery plus completed external-result tuple and issues the short-lived signed challenge. For metadata, `staging-proof` follows `issued -> reserved -> attempting -> staged|delivery_unknown`, deploys exactly the battery's minimal pack, and emits `StagingProofResult` only when publication succeeds; an unknown delivery must complete `reconcile-staging` before finalization even if that file is absent. For private-full, `finalize` reserves only after validating all six external results (one common plus five private). In either branch, `finalize` follows the durable `staged|reconciled_present -> committing -> consumed` protocol (or `issued -> reserved -> committing -> consumed` for private-full), and `finalize --resume` recovers a crash without issuing a second bundle. It seals `CandidateEvidenceBundle` over the exact profile-specific operational tuple. Persist every signed state externally and reverify authority, signature, freshness, ledger state, and subject digests between operations; an interruption does not authorize reconstruction from ambient state.

```bash
set -euo pipefail
set -o noclobber
: "${NPLG_PROTECTED_LAUNCHER:?supply the absolute digest-verified protected launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?supply the externally signed provisioning receipt}"
: "${NPLG_RELEASE_CONTROLLER_POLICY:?supply the protected controller policy}"
: "${SOURCE_REPOSITORY:?supply the repository/worktree root as untrusted data}"
: "${CANDIDATE_COMMIT:?supply the full immutable candidate commit}"
: "${RELEASE_PROFILE:?set the Task 1-approved profile}"
: "${NPLG_NETWORK_BROKER_DESCRIPTOR:?supply the non-secret network broker descriptor}"
: "${NPLG_CUSTODY_AUTHORITY_DESCRIPTOR:?supply the protected custody authority descriptor}"
: "${RELEASE_RUN_PARENT:?supply a pre-created private external run parent}"
: "${RELEASE_INITIALIZATION_JOURNAL_JSON:?supply a new initialization-journal path outside the run parent}"
: "${RELEASE_RUN_DESCRIPTOR_JSON:?supply a new signed run-descriptor path outside the run parent}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
test -x "$NPLG_PROTECTED_LAUNCHER"
for forbidden_name in ALPIC_API_KEY ALPIC_STAGING_ACCESS_TOKEN ALPIC_STAGING_INSUFFICIENT_SCOPE_TOKEN; do
  test -z "${!forbidden_name:-}"
done
declare -a PROFILE_INPUT_ARGS=()
case "$RELEASE_PROFILE" in
  alpic-metadata)
    : "${NPLG_CREDENTIAL_BROKER_DESCRIPTOR:?supply the non-secret staging-credential broker descriptor}"
    : "${ALPIC_PROJECT_ID:?supply the non-production project ID}"
    : "${ALPIC_STAGING_ENVIRONMENT_ID:?supply the non-production environment ID}"
    : "${ALPIC_STAGING_BASE_URL:?supply the canonical HTTPS base URL}"
    : "${ALPIC_STAGING_MCP_URL:?supply the canonical HTTPS MCP URL}"
    test -z "${NPLG_RUNTIME_BROKER_DESCRIPTOR:-}${NPLG_SLOT_DESCRIPTOR:-}"
    PROFILE_INPUT_ARGS+=(
      --credential-broker-descriptor "$NPLG_CREDENTIAL_BROKER_DESCRIPTOR"
      --project-id "$ALPIC_PROJECT_ID"
      --environment-id "$ALPIC_STAGING_ENVIRONMENT_ID"
      --base-url "$ALPIC_STAGING_BASE_URL"
      --mcp-url "$ALPIC_STAGING_MCP_URL"
    )
    ;;
  private-full)
    : "${NPLG_RUNTIME_BROKER_DESCRIPTOR:?supply the non-secret disposable-runtime broker descriptor}"
    : "${NPLG_SLOT_DESCRIPTOR:?supply the non-secret bounded-slot descriptor}"
    test -z "${NPLG_CREDENTIAL_BROKER_DESCRIPTOR:-}"
    test -z "${ALPIC_PROJECT_ID:-}${ALPIC_STAGING_ENVIRONMENT_ID:-}${ALPIC_STAGING_BASE_URL:-}${ALPIC_STAGING_MCP_URL:-}"
    PROFILE_INPUT_ARGS+=(
      --runtime-broker-descriptor "$NPLG_RUNTIME_BROKER_DESCRIPTOR"
      --slot-descriptor "$NPLG_SLOT_DESCRIPTOR"
    )
    ;;
  *) exit 1 ;;
esac
"$NPLG_PROTECTED_LAUNCHER" initialize-run \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --controller-policy "$NPLG_RELEASE_CONTROLLER_POLICY" \
  --repository-root "$SOURCE_REPOSITORY" \
  --candidate "$CANDIDATE_COMMIT" \
  --profile "$RELEASE_PROFILE" \
  --network-broker-descriptor "$NPLG_NETWORK_BROKER_DESCRIPTOR" \
  --custody-authority-descriptor "$NPLG_CUSTODY_AUTHORITY_DESCRIPTOR" \
  --run-parent "$RELEASE_RUN_PARENT" \
  "${PROFILE_INPUT_ARGS[@]}" \
  --initialization-journal-json "$RELEASE_INITIALIZATION_JOURNAL_JSON" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --authorize-run-root
"$NPLG_PROTECTED_LAUNCHER" run-through \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --through candidate-bundle-custody
```

`initialize-run` must durably publish the signed external `InitializationIntent` before its first run-root creation or ledger mutation. If it is interrupted or returns 75 before the signed descriptor is durably published, start a fresh process with only `"$NPLG_PROTECTED_LAUNCHER" initialize-run --resume --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" --initialization-journal-json "$RELEASE_INITIALIZATION_JOURNAL_JSON" --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON"`; it completes or rolls back that one frozen intent and cannot allocate a second run. The first `run-through` is only the unambiguous-success path. Its frozen exit semantics stop and propagate the first registered nonzero result while atomically advancing the signed descriptor whenever a durable state exists. After the descriptor exists, from a fresh process after any exit 20 or 75, SIGKILL, or `finalize` `committing` crash, the only continuation is:

```bash
set -euo pipefail
: "${NPLG_PROTECTED_LAUNCHER:?use the provisioned absolute launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?use the same provisioning receipt}"
: "${RELEASE_RUN_DESCRIPTOR_JSON:?use the signed descriptor from initialize-run}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
"$NPLG_PROTECTED_LAUNCHER" resume-run \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --through candidate-bundle-custody
```

`resume-run` derives the exact profile-specific operational tuple and next legal action only from the verified descriptor plus protected ledger: it may run `reconcile-staging`, resume `finalize`, or run/reconcile candidate-bundle custody as required. It never reconstructs `FINALIZE_OPERATIONAL_ARGS` or paths from shell state, and it rejects absent/ambiguous reconciliation, a changed descriptor/input/controller, or an unauthorized new attempt. Tests start a clean process after SIGKILL at every staging/result/finalize/custody boundary and prove convergence to one exact candidate-bundle custody receipt or a stable blocker without duplicate side effects.

Only when that protected recovery durably returns custody exit 21 with a signed same-subject `pre_upload_failed` attempt or exit 22 with a signed same-subject `absent` reconciliation may a separately authorized fresh upload attempt run:

```bash
set -euo pipefail
: "${NPLG_PROTECTED_LAUNCHER:?use the provisioned absolute launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?use the same provisioning receipt}"
: "${RELEASE_RUN_DESCRIPTOR_JSON:?use the atomically advanced signed descriptor}"
: "${CUSTODY_RETRY_PREDECESSOR_DIGEST:?use the exact selected signed predecessor digest}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
"$NPLG_PROTECTED_LAUNCHER" run-operation \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --operation custody \
  --new-attempt-after "$CUSTODY_RETRY_PREDECESSOR_DIGEST" \
  --authorize-custody-upload
```

The descriptor selects `candidate-bundle` here and later selects `final-decision-chain`; the caller cannot choose or change the subject/destination. Exit 23/ambiguous is terminal pending external resolution and never reaches this command. Tests cover both subject kinds, exit 21 and 22, stale/cross-run/cross-subject predecessors, reused authorization, concurrent retry, crash on retry CAS, and a mutant that treats 23 as retryable.

`initialize-run` validates the provisioning receipt's external signature/trust root, freshness, protected workflow/environment, launcher/controller binary and source digests, installation identity, policy/isolation/broker bindings, expected candidate-manifest digest, all thirteen `OperationTddReceipt` entries, and all four `LauncherTddReceipt` entries before it creates any path or grants authority. It binds the receipt digest into the signed initialization intent, run descriptor, `CandidateBatteryResult`, every downstream protected header, ledger intent/state, custody object, verdict, and cleanup journal. Absent, one-bit-changed, stale, self-issued, cross-controller, candidate-signed, wrong-installation, or TOCTOU-replaced receipt/launcher/policy cases fail before output/broker use; every later command reopens the protected descriptor and revalidates the same digest. Fault injection covers every initialization-intent write/fsync/rename/parent-fsync, root creation/root fsync, first ledger CAS, and descriptor write/fsync/rename/parent-fsync boundary and proves exactly one recoverable intent, root set, and descriptor with no orphaned authority-owned state.

Using only its digest-verified Git binary and closed configuration, the controller treats `--repository-root` as untrusted data, resolves and cross-checks absolute `--show-toplevel` and `--git-common-dir`, and then materializes raw Git blobs with system/global/repository configuration, hooks, credentials, filters, attributes, proxies, and prompting disabled; it never performs a candidate-controlled checkout. Tests cover a primary `.git` directory, a linked-worktree `.git` file, alternates, symlink/malformed gitfiles, object-store escape, and caller/controller root disagreement. Dependency acquisition/build occurs from previously verified offline caches before any broker use. `CandidateBatteryResult`, preparation, operational results, reconciliation records, final bundle, custody records, commit result, and verdicts bind the protected controller/workflow identities and exact canonical wheel/image/deploy-pack/SBOM/provenance digests. An Alpic timeout/crash after possible provider acceptance records `deployment_outcome=unknown` and ledger state `delivery_unknown`; only `reconcile-staging` may move it to `reconciled_present` or terminal `reconciled_absent`, while ambiguity remains blocked. The plan claims at most one local attempt—not remote exactly-once—unless Alpic supplies a proven idempotency key. Custody uncertainty follows its separate attempt/reconciliation states and never emits a receipt speculatively. Missing tools, stale evidence, profile/subject mismatch, shallow refs, unavailable controller/broker, or unproven provider subject remains a stable failure/blocker, never a skip.

Expected: all protected candidate commands exit 0 against one immutable candidate and exact subjects; the resulting sealed bundle may still contain truthful blockers, and the checked-in ASVS verdict is unchanged by this read-only candidate run.

- [ ] **Step 6: Create and commit a separate no-secret evidence attestation**

Use the protected controller's no-secret attestation-workspace operation to materialize raw candidate blobs into a new external branch/workspace while disabling system/global/repository Git config, hooks, prompting, credentials, proxies, filters, textconv, content-affecting attributes, and checkout transforms. The protected preflight rejects any candidate `.gitattributes` directive that could transform/execute content. For each selected-profile row, attach unique typed evidence IDs for the independently required kinds/selectors; copy only reviewed redacted evidence and otherwise reference versioned immutable custody objects. Bind every row/report to candidate/tree, final bundle, protected controller/workflow, canonical subjects, locks/SBOM/provenance, operational identity, capability/catalog/submission/privacy records, and evidence date. Reclassify only on evidence.

Create the workspace with one exact no-secret protected operation before editing:

```bash
set -euo pipefail
: "${NPLG_PROTECTED_LAUNCHER:?use the provisioned absolute launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?use the same provisioning receipt}"
: "${RELEASE_RUN_DESCRIPTOR_JSON:?use the signed release-run descriptor}"
: "${ATTESTATION_HANDOFF_JSON:?supply a new signed handoff path outside the run root}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
"$NPLG_PROTECTED_LAUNCHER" run-operation \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --operation attestation-workspace \
  --attestation-handoff-json "$ATTESTATION_HANDOFF_JSON"
```

If the process stops or returns 75 after the signed `workspace_materializing` intent but before a verified handoff, start a fresh process and run exactly `"$NPLG_PROTECTED_LAUNCHER" resume-run --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" --through attestation-workspace`; it uses the intent's frozen handoff path and either completes one byte-identical workspace or cleans only its recorded partial residue. Do not edit until the signed handoff exists.

The report says `release recommended` or `do not release`, never `release authorized`. After human review and explicit commit authorization, the protected no-secret commit helper stages exactly `SECURITY.md`, the matrix, evidence manifest, threat model, and release report, disables hooks/signing/credentials, compares the literal NUL-delimited allowlist before and after commit, and returns the clean `ATTESTATION_COMMIT`. Hostile post-checkout/pre-commit/commit-msg hooks, filters, textconv, credential helpers, and altered attributes must never execute. Do not amend or relabel the tested candidate.

After the reviewer has edited only those five paths and explicitly authorized this one commit, run:

```bash
set -euo pipefail
: "${NPLG_PROTECTED_LAUNCHER:?use the provisioned absolute launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?use the same provisioning receipt}"
: "${RELEASE_RUN_DESCRIPTOR_JSON:?use the signed release-run descriptor}"
: "${ATTESTATION_HANDOFF_JSON:?use the signed workspace handoff}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
"$NPLG_PROTECTED_LAUNCHER" run-operation \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --operation commit-attestation \
  --attestation-handoff-json "$ATTESTATION_HANDOFF_JSON" \
  --message "docs: attest release evidence" \
  --authorize-commit
```

If the process stops or returns 75 after `attestation_committing` is durable, including immediately after the protected ref CAS, start a fresh process and run exactly `"$NPLG_PROTECTED_LAUNCHER" resume-run --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" --through commit-attestation`. It consumes the unchanged one-time authorization already bound in the intent, read-back-recognizes or finishes the one intended commit/ref update, and emits one `AttestationCommitResult`; do not rerun `run-operation`, edit the workspace, or grant a second authorization.

- [ ] **Step 7: Verify attestation and enforce ASVS L2 for any public recommendation**

Run only the absolute protected launcher and signed run descriptor, never the attestation revision's `scripts/verify_release.py`, ambient coreutils, or reconstructed in-root paths:

```bash
set -euo pipefail
: "${NPLG_PROTECTED_LAUNCHER:?use the provisioned absolute launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?use the same provisioning receipt}"
: "${RELEASE_RUN_DESCRIPTOR_JSON:?use the signed release-run descriptor}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
"$NPLG_PROTECTED_LAUNCHER" run-through \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --from attest \
  --through final-decision-custody
```

`run-through` requires the descriptor's signed `AttestationCommitResult`, runs structural `attest`, and derives the provisional discriminator from the resulting signed verdict. An initial `do not release` verdict forbids both eligibility verdict envelopes and their join node. A provisional `release recommended` verdict requires `eligibility --require-eligible --require-asvs-l2` always to durably emit signed `ReleaseEligibilityVerdict` and `AsvsL2ConformanceVerdict` envelopes plus their signed `EligibilityGateRecord` join: both positive returns 0 and preserves `release_recommended`; either negative returns registered 24 and atomically changes the final decision to `do_not_release`. In both cases it then invokes the `final-decision-chain` custody variant over the complete canonical commit-result, attestation-verdict, and two verdict envelopes plus join record, read-back-verifies the immutable object, and advances the signed descriptor only after `FinalDecisionCustodyReceipt` publication; after a negative gate the enclosing `run-through` returns 24 only after that custody is durable. A raw commit SHA, re-read report, digest-only summary, omitted/substituted/cross-run verdict, mutated join digest, optional ASVS flag, caller-selected discriminator, negative-to-positive relabel, or skipped negative custody fails. Neither verdict grants release authority.

After exit 20 or 75, or process death at attestation, eligibility, final-decision upload/read-back/receipt, start a fresh process and run only:

```bash
set -euo pipefail
: "${NPLG_PROTECTED_LAUNCHER:?use the provisioned absolute launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?use the same provisioning receipt}"
: "${RELEASE_RUN_DESCRIPTOR_JSON:?use the signed release-run descriptor}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
"$NPLG_PROTECTED_LAUNCHER" resume-run \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --through final-decision-custody
```

The launcher selects the next legal branch from the signed descriptor/protected ledger, runs `reconcile-custody` when required, and never needs a vanished attempt file or caller array. If and only if this final-decision custody recovery durably returns 21 or 22, use the exact separately authorized `run-operation --operation custody --new-attempt-after ... --authorize-custody-upload` command from Step 5; the descriptor now fixes `subject_kind="final-decision-chain"`. Exit 23 remains blocked. Tests start from a clean process at every boundary and require one exact final-decision receipt or one stable blocker.

Only after both custody receipts, completed attestation, and separate destructive cleanup authorization may the launcher remove the exact run root. The caller supplies new journal/result paths outside that root; the launcher validates and journals the verified root device/inode/path, complete literal deletion inventory, both custody-receipt envelope bytes/digests, final-decision bytes/digests, provisioning/policy identity, and intended result before deleting anything:

```bash
set -euo pipefail
: "${NPLG_PROTECTED_LAUNCHER:?use the provisioned absolute launcher}"
: "${NPLG_CONTROLLER_PROVISIONING_RECEIPT:?use the same provisioning receipt}"
: "${RELEASE_RUN_DESCRIPTOR_JSON:?use the signed release-run descriptor}"
: "${CLEANUP_JOURNAL_JSON:?supply a new protected journal path outside the run root}"
: "${CLEANUP_RESULT_JSON:?supply a new protected result path outside the run root}"
case "$NPLG_PROTECTED_LAUNCHER" in /*) ;; *) exit 1 ;; esac
"$NPLG_PROTECTED_LAUNCHER" run-operation \
  --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" \
  --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" \
  --operation cleanup-run \
  --cleanup-journal-json "$CLEANUP_JOURNAL_JSON" \
  --cleanup-result-json "$CLEANUP_RESULT_JSON" \
  --authorize-cleanup
```

After cleanup exit 75 or process interruption, a fresh process runs `"$NPLG_PROTECTED_LAUNCHER" resume-run --provisioning-receipt "$NPLG_CONTROLLER_PROVISIONING_RECEIPT" --run-descriptor-json "$RELEASE_RUN_DESCRIPTOR_JSON" --through cleanup-run --cleanup-journal-json "$CLEANUP_JOURNAL_JSON" --cleanup-result-json "$CLEANUP_RESULT_JSON"`. It consumes no deleted in-root input. Fault injection covers before/after journal temp write/fsync/rename/parent-fsync, every descriptor-relative deletion class, root removal, result temp/fsync/rename, and final ledger CAS. Resume preserves the journal's exact target/inventory, never broadens deletion, and publishes exactly one signed `CleanupResult`.
Expected: structural attestation emits truthful typed verdicts and the complete final decision envelope chain is read-back-verified in its own immutable custody object before any cleanup. Every public release recommendation additionally has an exit-0 `passed=true` eligibility join with zero blockers, every applicable ASVS L2 row `Pass`, and every `N/A` independently governed. A truthful gate-negative result returns 24 only after the signed negative verdicts/join and final `do_not_release` chain are custodied; it is successful negative audit closure, not a release recommendation or tool failure. Neither operation grants release authority.
**Phase 8 evidence-decision exit gate:** the protected complete battery has run against one immutable candidate/exact subjects, any metadata staging proof is finalized through the signed crash-recoverable state machine, and a separate clean attestation revision structurally verifies its binding and emits `release recommended` or `do not release`. Both the candidate bundle and complete final decision chain have immutable, read-back-verified custody receipts; cleanup, if separately authorized, is journaled and resumable without in-root proof inputs. A negative verdict is valid audit closure. Every public recommendation requires `eligibility --require-eligible --require-asvs-l2` with zero blockers, every applicable ASVS L2 row `Pass`, and independently governed `N/A`; metadata also requires explicit non-construction/minimal-deploy proof. Risk acceptance may close only a named staging/private `do not release` audit. Actual release/deploy/publication remains blocked until the user or organizational authority separately approves that exact bundle/action.

---

## 5. Acceptance Criteria by Release Profile

### `alpic-metadata` production candidate

- At the Python backend hop, the trusted outer boundary performs bounded framing/Host/Origin/admission, then the supported official SDK/vendor composition returns SDK-owned 401/challenge for credentialless or invalid-token requests before the modern-only routing guard. After exactly one successful token verification, that guard rejects absent/unsafe/duplicate and exact handshake-era protocol versions while passing literal `2026-07-28` and bounded safe unsupported sentinels unchanged to SDK modern validation; no detector request reaches legacy dispatch. Official `mcp==2.0.0` exclusively owns MCP parsing, structured current/unsupported-version metadata/body validation, authentication context, and dispatch. At the public hop Alpic is separately treated and tested as an MCP server/client translator.
- The production/stateless `2026-07-28` official-client and project wire suites pass against exactly three authenticated tools. Separately, the pinned official server-role `--requirements 2026-07-28` harness passes with no scored failure or expected-failure baseline against its auth-disabled test-only prescribed fixture, and the report labels that result unauthenticated SDK/transport-integration evidence rather than application/auth conformance. Static/build/deployment proof shows no fixture surface enters a release subject. Any local `2025-11-25` stateful compatibility result is labelled non-deployed evidence and cannot satisfy a production legacy-support claim.
- Exactly three tools are listed and callable.
- Every untouched raw argument object and every output is strictly Pydantic-validated before handler entry/client return and has a recursively closed schema.
- Zod 4.4.3 independently agrees on the shared adversarial corpus and the exact in-memory/deployed `Client.list_tools()` schemas.
- Host, present Origin, authentication, authorization, body, pre-allocation JSON structural/lexical limits, concurrency, and deadline controls fail closed; absent Origin remains supported for non-browser clients.
- Socket-bound SSRF protection or independently proven egress confinement covers every upstream connection; the NPLG bulkhead/circuit breaker prevents a sustained upstream outage from consuming all admission capacity.
- Every current-protocol cacheable response/page explicitly preserves the reviewed `ttlMs: 0` and `cacheScope: "private"` policy through both backend and Alpic hops.
- No tool result depends on local artifact persistence or emits runtime `/assets` URLs.
- Worst observed staging duration is below 20 seconds and startup meets the platform window.
- Required CI and protected-branch gates pass, and the metadata profile's command manifest passes without requiring PDF/scanner code or a container runtime.
- Public multi-instance deployment has documented and measured per-principal throttling; instance-local counters alone are insufficient.
- The `alpic-metadata` ASVS matrix has no `Not assessed`, `Fail`, `Partial`, `Risk accepted`, or unjustified `N/A` rows before any ASVS L2 claim.
- Alpic audit warnings/skips, any separately authorized Playground check, authenticated official-client, negative-auth, and reconnect evidence is bound to the immutable candidate; an audit authentication skip is not protocol evidence.
- A versioned vendor-supplied unauthenticated deploy-time detector fixture receives 401 with the frozen `WWW-Authenticate` challenge, the challenged URI returns the exact RFC 9728 document/resource tuple, and machine-bound provider evidence classifies the named environment `Protected`. If Alpic does not supply that fixture, the bounded documented approximation may support staging diagnostics but `ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN` remains; root-versus-path or backend-versus-public resource ambiguity, `Public`/unknown classification, or an unbound rewrite is a release blocker.
- A two-hop translation matrix dispositions every observed edge/backend version, metadata-header, auth/challenge, route, error/status, notification, reconnect, cancellation, and cache-hint difference; the plan never claims public request bytes are preserved through Alpic.
- A separate clean attestation commit verifies evidence and verdict binding to the tested candidate; neither revision is mislabeled as the other. If Alpic cannot expose immutable deployed-subject provenance, exact byte identity is explicitly unproven and cannot close a requirement that demands it.

### `private-full` production candidate

- All profile-neutral security, strict-contract, official-client, evidence-binding, and release-versus-conformance criteria from `alpic-metadata` pass. Metadata-only surface clauses—exactly three tools, no local artifact state/routes, Alpic edge routing/time limits, non-construction of PDF/scanner services, and the metadata manifest's explicit exclusion of container gates—do not apply to and cannot be copied into `private-full` evidence.
- PDFium runs only in the isolated worker profile.
- Production `private-full` rejects the serialized in-process compatibility executor at startup.
- Timeout/cancellation kills the worker process group and cleanup is proven.
- The worker has OS-level no-network enforcement and resource ceilings.
- The public Caddy edge is the only reachable ingress; Caddy-to-app traffic uses mutually authenticated encrypted TLS with exact peer identities, the app has no plaintext/host-published origin, and the signed private-edge proof covers TLS/ciphers/certificates, backend auth, origin bypass, Host/Origin/framing/slow-client/deadline/concurrency negatives, logs, and subject digests.
- Safe relative paths are canonicalized by typed component validation and opened descriptor-relative with beneath/no-symlink enforcement; traversal and rename/symlink races are rejected.
- Untrusted files have digest-bound fresh malware verdicts from the confined scanner before publication or PDF parsing.
- Parent validation proves every output's path, type, dimensions, size, and digest before publication.
- Artifact access is authenticated without bearer capabilities in URLs.
- Retention, quota, purge, and crash recovery are operationally proven by the signed destructive disposable recovery gate; unique state has content/owner/mode-bound backup/restore proof, while derived state has bounded regeneration/RTO proof, and high-water/clock/lease/reservation state survives or fails closed.
- The `private-full` ASVS matrix satisfies the same release-versus-conformance decision rules as `alpic-metadata`; evidence for one profile cannot close another.
- The private-full command manifest imports exactly the common live proof plus the five private edge/worker/scanner/quota/recovery proofs and tests already-built app/edge/PDF-worker/scanner image digests with rebuild disabled; these gates are never injected into metadata-only release criteria.

### `distributed-full` production candidate

This candidate remains outside the executable implementation scope of this plan. Phase 7 now permits only the typed Alpic compatibility assessment and may close truthfully with an unsupported verdict. A later implementation plan must restate all `private-full` criteria, durable job/artifact tests, provider identity/rotation proof, the supported Tasks verdict, and full `distributed-full` matrix closure. No checkbox in this plan can authorize or certify that profile.

## 6. Rollback Boundaries

- Phase 1 is primarily quality/configuration refactoring but includes the
  explicitly reviewed Task 5 security hardening. Preserve those TDD-backed
  behavior changes and their adversarial tests; revert only unintended frozen
  contract drift or a refactor that cannot reproduce its prior public
  behavior.
- Phase 2 can revert to frozen dictionary serialization while retaining its tests.
- Phase 3 keeps the custom protocol until Task 13 is green; cutover rollback is one commit until Task 14 deletes it.
- Phase 4 retains `PDF_EXECUTOR=serialized` only for development/compatibility. Production rollback disables PDF tools or returns to `alpic-metadata`; it never moves untrusted PDFium back into the credential-bearing control plane and never returns to parallel `to_thread()` execution.
- Phase 5 can disable live traffic if socket binding cannot be proven; do not silently use pre-check-only DNS.
- Phase 6 can disable the Alpic project or return to authenticated staging without affecting Docker/VPS.
- Phase 7 may add only typed capability contracts, offline/protected probe machinery, and negative guard tests. Rollback removes that assessment machinery while retaining the fail-closed `distributed-full` startup error; Phase 7 cannot alter `alpic-metadata` tool registration, and a supported verdict still requires a separately approved implementation plan.

## 7. Primary Sources and Version Revalidation

Recheck these primary sources at the start of the task that consumes them; exact pins change only through a reviewed dependency task. For normative MCP/ASVS evidence, record the source repository commit and content digest so a version-labelled but mutable web rendering cannot silently alter the evidence basis. For live Alpic provider-contract pages, record retrieval time, final canonical URL, response/content digest, and an immutable archived custody reference; drift is a review blocker, not permission to reuse stale assumptions:

- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [MCP Python SDK v2.0.0 release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0)
- [MCP Python SDK v2 changes](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/docs/whats-new.md)
- [MCP Python SDK v2.0.0 tool execution and error conversion](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/mcpserver/tools/base.py#L111-L164)
- [MCP Python SDK v2.0.0 call-tool response conversion](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/mcpserver/server.py#L389-L398)
- [MCP Python SDK v2.0.0 generated argument behavior](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/mcpserver/utilities/func_metadata.py)
- [MCP Python SDK issue 3067: strict decorator-argument validation gap](https://github.com/modelcontextprotocol/python-sdk/issues/3067)
- [MCP Python SDK v2.0.0 documented low-level `Server` API](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/docs/advanced/low-level-server.md)
- [MCP Python SDK v2.0.0 low-level `Server` implementation](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/lowlevel/server.py)
- [MCP Python SDK roadmap and deferred SEP-2663 Tasks status](https://github.com/modelcontextprotocol/python-sdk/blob/main/ROADMAP.md)
- [MCP Python SDK SEP-2663 implementation tracker](https://github.com/modelcontextprotocol/python-sdk/issues/2806)
- [MCP Python SDK v2.0.0 auth context](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/auth/middleware/auth_context.py), [bearer middleware](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/auth/middleware/bearer_auth.py), and [token provider models](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/auth/provider.py)
- [MCP Python SDK v2.0.0 protected-resource route builder](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/auth/routes.py)
- [MCP Python SDK v2.0.0 `MCPError` constructor](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/shared/exceptions.py)
- [MCP Python SDK v2.0.0 modern Streamable HTTP implementation](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/_streamable_http_modern.py#L315-L400)
- [MCP Python SDK v2.0.0 modern-versus-legacy Streamable HTTP routing](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp/server/streamable_http_manager.py#L176-L204)
- [MCP Python SDK v2.0.0 ASGI and transport-security guidance](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/docs/run/asgi.md)
- [MCP official conformance framework](https://github.com/modelcontextprotocol/conformance)
- [MCP Python SDK v2.0.0 pinned official conformance workflow](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/.github/workflows/conformance.yml)
- [MCP 2026-07-28 tool specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP 2026-07-28 resource specification](https://modelcontextprotocol.io/specification/2026-07-28/server/resources)
- [MCP 2026-07-28 Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP 2026-07-28 authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP 2026-07-28 authorization-server discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
- [MCP 2026-07-28 client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)
- [MCP 2026-07-28 authorization security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [MCP 2026-07-28 caching requirements](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching)
- [MCP 2026-07-28 security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [RFC 9728 OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
- [RFC 8725 JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 9700 OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [Experimental Tasks extension](https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks)
- [Zod 4.4.3 release](https://github.com/colinhacks/zod/releases/tag/v4.4.3)
- [Zod JSON Schema documentation](https://zod.dev/json-schema)
- [Zod 4.4.3 string-length checks](https://github.com/colinhacks/zod/blob/v4.4.3/packages/zod/src/v4/core/checks.ts) and [JSON Schema length conversion](https://github.com/colinhacks/zod/blob/v4.4.3/packages/zod/src/v4/core/json-schema-processors.ts)
- [JSON Schema Draft 2020-12 Core `$schema` dialect requirement](https://json-schema.org/draft/2020-12/json-schema-core#name-the-schema-keyword)
- [Pydantic model configuration](https://docs.pydantic.dev/latest/api/config/)
- [Pydantic JSON Schema modes](https://docs.pydantic.dev/latest/concepts/json_schema/)
- [Pydantic mypy plugin](https://docs.pydantic.dev/latest/integrations/mypy/)
- [Pydantic 2.13.4 release](https://github.com/pydantic/pydantic/releases/tag/v2.13.4)
- [PyJWT registry metadata](https://pypi.org/project/PyJWT/)
- [cryptography registry metadata](https://pypi.org/project/cryptography/)
- [pytest registry metadata](https://pypi.org/project/pytest/), [pytest-asyncio](https://pypi.org/project/pytest-asyncio/), [pytest-cov](https://pypi.org/project/pytest-cov/), [Coverage.py](https://pypi.org/project/coverage/), and [Hypothesis](https://pypi.org/project/hypothesis/)
- [mypy registry metadata](https://pypi.org/project/mypy/), [Ruff](https://pypi.org/project/ruff/), [Bandit](https://pypi.org/project/bandit/), [Semgrep](https://pypi.org/project/semgrep/), [pip-audit](https://pypi.org/project/pip-audit/), [diff-cover](https://pypi.org/project/diff-cover/), [mutmut](https://pypi.org/project/mutmut/), [CycloneDX](https://pypi.org/project/cyclonedx-bom/), and [zizmor](https://pypi.org/project/zizmor/)
- [mypy dynamic-typing configuration](https://mypy.readthedocs.io/en/stable/config_file.html#disallow-dynamic-typing), [Pyright diagnostic configuration](https://github.com/microsoft/pyright/blob/1.1.413/docs/configuration.md), and [Ruff `Any` rule scope](https://docs.astral.sh/ruff/rules/any-type/)
- [Coverage.py branch-pair model](https://coverage.readthedocs.io/en/7.15.4/branch.html) and [diff-cover changed-line model](https://github.com/Bachmann1234/diff_cover)
- [typescript-eslint supported dependency versions](https://typescript-eslint.io/users/dependency-versions/)
- [Ruff formatter/linter incompatibilities](https://docs.astral.sh/ruff/formatter/#conflicting-lint-rules)
- [actionlint v1.7.12 release and checksums](https://github.com/rhysd/actionlint/releases/tag/v1.7.12)
- [OWASP ASVS project](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP ASVS v5.0.0 release-tagged machine-readable requirements](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json)
- [OWASP ASVS v5.0.0 V10 OAuth/OIDC](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/5.0/en/0x19-V10-OAuth-and-OIDC.md), [V12 Secure Communication](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/5.0/en/0x21-V12-Secure-Communication.md), and [V16 Security Logging](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
- [Alpic endpoint model](https://docs.alpic.ai/build-deploy/endpoints)
- [Alpic asset model](https://docs.alpic.ai/build-deploy/assets)
- [Alpic build detection](https://docs.alpic.ai/build-deploy/builds)
- [Alpic compatibility and Playground controls](https://docs.alpic.ai/compatibility)
- [Alpic authentication overview](https://docs.alpic.ai/secure/auth/overview)
- [Alpic OAuth setup](https://docs.alpic.ai/secure/auth/oauth-setup)
- [Alpic Dynamic Client Registration proxy](https://docs.alpic.ai/secure/auth/dcr-proxy)
- [Alpic OAuth provider endpoint directory](https://docs.alpic.ai/secure/auth/oauth-providers)
- [Alpic troubleshooting, deploy-time OAuth detection, protected-resource path, and 30-second tool limit](https://docs.alpic.ai/troubleshooting)
- [Alpic 2026-07-28 protocol and Tasks support announcement](https://alpic.ai/blog/mcp-2026-07-28-makes-the-protocol-stateless-and-the-app-extensions-official)
- [Alpic audit behavior and JSON output](https://docs.alpic.ai/cli/audit)
- [Alpic noninteractive deploy command and existing-project flag behavior](https://docs.alpic.ai/cli/deploy)
- [Alpic project inspection](https://docs.alpic.ai/cli/project-inspect), [environment inspection](https://docs.alpic.ai/cli/environment-inspect), and [deployment inspection](https://docs.alpic.ai/cli/deployment-inspect)
- [Alpic submission/versioning model](https://docs.alpic.ai/distribution/versioning.md)
- [Alpic analytics privacy controls](https://docs.alpic.ai/analytics/privacy.md)
- [Alpic environments](https://docs.alpic.ai/build-deploy/environments.md) and [runtime environment variables](https://docs.alpic.ai/build-deploy/env-variables.md)
- [Alpic CLI 1.167.1 registry metadata](https://registry.npmjs.org/alpic/1.167.1)
- [`@alpic-ai/sdk` 1.167.1 registry metadata](https://registry.npmjs.org/@alpic-ai/sdk/1.167.1) and [`@alpic-ai/api` 1.167.1 registry metadata](https://registry.npmjs.org/@alpic-ai/api/1.167.1)
- [testssl.sh v3.2.4 official release](https://github.com/testssl/testssl.sh/releases/tag/v3.2.4)

## 8. Execution Order

Recommended execution uses `superpowers:subagent-driven-development` with a fresh implementation worker and two-stage review per task:

1. Task 0 creates the reproducible environment/typed test fixtures and revalidates the frozen-revision baseline; no later RED runs before it passes.
2. Task 1 freezes the complete digest-bound oracle, root `SPEC.md`, and ADR
   after explicit profile confirmation.
3. Task 1A lands immediately as the first production-code repair, followed by
   the explicitly scoped Task 1B legacy-static closure.
4. Task 2 creates the evidence inventory, then Task 3 installs the temporary
   CI/ratchet gate before broad cleanup.
5. Tasks 4, 5, 6, 6A, residual 6B, 6C, 7, and 8 run sequentially because they
   share modules and quality configuration. Apply the Phase 1
   temporary-infrastructure exit gate before Task 7. The 2026-08-16
   reconciliation stops at the Phase 0-1 audit boundary; continuing beyond it
   requires a new user direction.
6. Tasks 9–10 establish strict contracts and the cross-language oracle.
7. Tasks 11–14 perform the official SDK cutover. Task 13's auth-disabled version ordering is provisional; before any protected deployment, Task 20 must consume the Task 0 Alpic capability record and prove one supported auth-before-version composition or stop with the named blockers.
8. Tasks 15, 16, and 16A run only after Task 9 and follow the dependency chain Task 15 → Task 16 → Task 16A. Tasks 17–18 also require Task 9. These branches may proceed alongside SDK work only when their declared write sets do not overlap; integrate one branch at a time.
9. Tasks 19–21 produce the first authenticated Alpic metadata candidate after Phases 1, 3, and 5 are green. Task 21 may proceed past its build/auth spike only when the exact detector challenge/metadata tuple is compatible and the named environment is machine-classified `Protected`; a `Public`/unknown result is a stop, not a staging success.
10. Phase 7 Task 21A may run after Phase 6's local profile guards and the pinned SDK environment exist. It produces a typed Alpic Tasks capability verdict and is expected to close negatively while `mcp==2.0.0` lacks the extension. It never enables the profile or blocks the metadata release.
11. A `supported=true` Phase 7 verdict starts a new approval gate for the separate full-fidelity implementation plan; an unsupported verdict preserves the blocker ledger and startup error without making Phase 7 assessment incomplete.
12. Task 22 starts after every selected-profile code/offline dependency is committed; it then creates the immutable battery, runs the protected selected-profile external gates, and, for metadata, obtains the one preparation-bound Task 21 staging result inside its own state machine. No prior metadata staging result is a prerequisite or reusable input, and metadata does not wait for Tasks 15-16A or Task 21A. Zero blockers/all required results green is required only by the separate release-eligibility gate, not by a truthful `do not release` evidence closure; actual release authority remains external.

Enforce stop gates only along the selected profile's executable dependency DAG. `alpic-metadata` does not traverse Phase 4 or require the Phase 7 assessment; `private-full` does traverse Phase 4. If any boundary selected by that DAG is unmet, stop—never reinterpret its red gate as documentation debt. Phase 7 may assess Alpic Tasks compatibility, but entering `distributed-full` implementation always stops unless a supported verdict and the separately approved implementation plan both exist.
