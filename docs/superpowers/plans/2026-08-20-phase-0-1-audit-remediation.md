# Phase 0-1 Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every locally remediable Phase 0-1 audit defect while preserving fail-closed release authority for controls that require external infrastructure or attestations.

**Architecture:** Repair public configuration and token boundaries first, then restore independent Python/Zod and release-registry gates, then harden the PDF execution lifecycle and resource ceilings. Each behavioral change follows a witnessed RED/GREEN cycle and is verified at its public seam; ASVS, deployment isolation, and toolchain-provenance claims remain blocked unless fresh authoritative evidence exists.

**Tech Stack:** Python 3.13, Pydantic 2 strict models, Starlette/official MCP SDK, Zod 4.4.3, Node checkJs TypeScript, ESLint flat config, pytest/Hypothesis, Ruff, Pyright strict, mypy strict, coverage/diff-cover, mutmut, Bandit, pip-audit, Zizmor.

**Spec:** `docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md`

## Global Constraints

- Preserve the existing 49-path staged candidate byte-for-byte; all remediation remains unstaged unless the user separately authorizes staging.
- Do not commit, push, deploy, publish, sign, or manufacture ASVS/release evidence.
- New behavior requires a focused test that is observed failing for the audited reason before production code changes.
- All Python boundaries remain strict Pydantic/type checked; all JavaScript contract files and tests are covered by Zod 4.4.3 runtime tests, `checkJs`, and zero-warning ESLint.
- Public or non-loopback deployment is authenticated and fail-closed; anonymous development requires an explicit opt-in and loopback-only origin and bind host.
- Untrusted native PDF work must never publish bytes that differ from the worker-bound digest, and every local lifecycle cleanup path must be exercised.
- OWASP ASVS 5.0.0 L2 rows are marked passed only by evidence accepted by the existing evidence contract and release controller.
- Local success does not override `external_authority_required` or any deployment/isolation blocker that this checkout cannot prove.

---

### Task 1: Public configuration and token boundaries

**Files:**

- Modify: `src/nplg_mcp/config.py`
- Modify: `src/nplg_mcp/tokens.py`
- Modify: `src/nplg_mcp/app.py`
- Test: `tests/unit/test_config.py`
- Test: `tests/security/test_tokens.py`
- Test: `tests/conformance/test_mcp_http.py`

**Interfaces:**

- Consumes: `load_config(env: Mapping[str, str]) -> AppConfig`, `verify_asset_token(...) -> AssetGrant`.
- Produces: an explicit loopback-only anonymous-development invariant, credential-domain separation, and maximum signed-asset lifetime enforcement.

- [x] **Step 1: Write failing configuration tests**

  Add table-driven cases proving that `ALPIC_HOST` with omitted security variables fails, non-loopback `HOST` or `PUBLIC_BASE_URL` rejects `ALLOW_ANONYMOUS=true`, and anonymous development succeeds only when explicitly opted in with loopback bind/origin values.

- [x] **Step 2: Verify configuration RED**

  Run: `.venv/bin/pytest -q tests/unit/test_config.py -k 'alpic or anonymous or loopback or credential_reuse'`

  Expected: failures show the current implicit development/private-full/anonymous defaults and accepted key reuse.

- [x] **Step 3: Implement the minimal configuration invariant**

  Make anonymous access default to false, parse and validate bind/public hosts with IP/hostname loopback semantics, reject public Alpic configuration without explicit production/authentication settings, and compare signing/API credentials with constant-time byte equality.

- [x] **Step 4: Write and verify signed-token lifetime RED**

  Add a token whose authenticated `exp` exceeds the configured maximum TTL and prove the asset route currently accepts it.

  Run: `.venv/bin/pytest -q tests/security/test_tokens.py tests/conformance/test_mcp_http.py -k 'ttl or future or expiry'`

- [x] **Step 5: Enforce and verify maximum lifetime**

  Extend `verify_asset_token` with a positive maximum lifetime and reject authenticated tokens whose expiry exceeds `now + maximum`; pass `config.asset_ttl_seconds` at the asset route.

  Run: `.venv/bin/pytest -q tests/unit/test_config.py tests/security/test_tokens.py tests/conformance/test_mcp_http.py`

---

### Task 2: Release registry and strict Zod oracle closure

**Files:**

- Modify: `security/external-test-gates.json`
- Modify: `scripts/run_test_gate.py`
- Modify: `tests/unit/test_test_gate.py`
- Modify: `contracts/zod/baseline-contracts.mjs`
- Modify: `tests/contracts/zod_baseline_contracts.test.mjs`
- Modify: `package.json`
- Modify: `tsconfig.contracts.json`
- Modify: `eslint.config.mjs`
- Test: `tests/contracts/zod_contracts.test.mjs`

**Interfaces:**

- Consumes: live pytest node IDs and Pydantic `ReplayHeader` code-point length semantics.
- Produces: an exact test registry and a Zod oracle with Unicode code-point, not UTF-16 code-unit, bounds under every strict static gate.

- [x] **Step 1: Write registry and static-scope RED checks**

  Change the unit expectation to the three live frozen-baseline test IDs and require capability contracts/tests in the contract typecheck and lint commands.

  Run: `.venv/bin/pytest -q tests/unit/test_test_gate.py -k 'external and registry'`

  Expected: stale registry mismatch.

- [x] **Step 2: Update the authoritative registry and verify GREEN**

  Replace only the three obsolete node names with the current collected node IDs, retaining the exact-set fail-closed behavior.

  Run: `.venv/bin/pytest -q tests/unit/test_test_gate.py -k 'external and registry'`

- [x] **Step 3: Write Unicode differential RED tests**

  Add literal boundaries proving 4096 Unicode scalar values are accepted and 4097 rejected even when astral characters occupy two UTF-16 code units.

  Run: `npm run test:contracts`

  Expected: Zod rejects a Pydantic-valid astral boundary.

- [x] **Step 4: Add a reusable code-point string schema and close static scope**

  Implement bounds using `Array.from(value).length` in a typed Zod refinement, use it for replay-header values, and include `capability-contracts.mjs` plus `zod_contracts.test.mjs` in checkJs and ESLint inputs.

- [x] **Step 5: Verify runtime and static contract GREEN**

  Run: `npm run test:contracts && npm run contracts:baseline-static && npm run lint:contracts`

---

### Task 3: PDF writable topology and deterministic cancellation readiness

**Files:**

- Modify: `src/nplg_mcp/pdf_worker_client.py`
- Modify: `tests/fixtures/pdf_worker_hang.py`
- Modify: `tests/security/test_pdf_worker.py`
- Modify: `tests/static/test_deployment.py`
- Modify if required by the executable topology test: `compose.yaml`

**Interfaces:**

- Consumes: `AssetStore.root` as the declared writable cache mount.
- Produces: private mode job directories inside an explicitly writable, private subtree and atomically published PID readiness data.

- [x] **Step 1: Write writable-topology RED**

  Exercise job creation with the cache root writable and its parent read-only; assert the worker job lives below the cache root and is removed after success/failure.

- [x] **Step 2: Verify topology RED**

  Run: `.venv/bin/pytest -q tests/security/test_pdf_worker.py tests/static/test_deployment.py -k 'work or compose or writable'`

  Expected: current `store.root.parent` placement violates the invariant.

- [x] **Step 3: Place jobs in a private cache subtree**

  Create the job parent under `AssetStore.root`, reject symlink/special-file aliases, apply restrictive permissions, and retain unconditional cleanup.

- [x] **Step 4: Write cancellation-readiness RED and publish PID data atomically**

  Make the fixture write a complete two-line payload to a sibling temporary file and replace the readiness path atomically; make the test validate exactly two positive PIDs before cancellation.

- [x] **Step 5: Verify GREEN and stress the cancellation seam**

  Run: `.venv/bin/pytest -q tests/security/test_pdf_worker.py tests/static/test_deployment.py`

  Then repeat the focused cancellation test under load and require zero retries/failures.

---

### Task 4: PDF absolute deadline, cleanup, and digest-bound publication

**Files:**

- Modify: `src/nplg_mcp/tools.py`
- Modify: `src/nplg_mcp/pdf_worker_client.py`
- Test: `tests/unit/test_tools.py`
- Test: `tests/security/test_pdf_worker.py`
- Test: `tests/property/test_pdf_ipc_properties.py`

**Interfaces:**

- Consumes: one `MonotonicDeadline` created before PDF queue admission and worker-declared output SHA-256 values.
- Produces: bounded queue wait, deadline checks across parent phases, unconditional process-group cleanup, and publication that hashes the reopened descriptor before cache commit.

- [x] **Step 1: Write queue/deadline RED tests**

  Hold the PDF semaphore, advance a controlled monotonic clock beyond the absolute deadline, and prove the call returns the stable overload/timeout error without invoking the executor.

- [x] **Step 2: Verify queue/deadline RED**

  Run: `.venv/bin/pytest -q tests/unit/test_tools.py -k 'pdf and (queue or deadline or capacity)'`

- [x] **Step 3: Apply one absolute deadline**

  Construct the deadline before PDF admission, bound semaphore acquisition with its remaining time, release only after successful acquisition, and check the same deadline before/after each blocking staging, validation, and publication phase.

- [x] **Step 4: Write descendant-success and output-race RED tests**

  Prove cleanup is attempted after a leader exits successfully, and replace a validated output before publication with same-size hostile bytes whose digest differs from the worker-bound result.

- [x] **Step 5: Close local lifecycle and publication integrity**

  Always terminate the original process group in `finally`; pass expected size/digest into publication; hash bytes read from the reopened descriptor; compare in constant time before committing the staged cache entry; discard on mismatch.

- [x] **Step 6: Verify PDF GREEN**

  Run: `.venv/bin/pytest -q tests/unit/test_tools.py tests/security/test_pdf_worker.py tests/property/test_pdf_ipc_properties.py`

---

### Task 5: Metadata/result and asset-stream resource ceilings

**Files:**

- Modify: `src/nplg_mcp/repository.py`
- Modify: `src/nplg_mcp/tools.py`
- Modify: `src/nplg_mcp/app.py`
- Modify: `src/nplg_mcp/config.py`
- Test: `tests/integration/test_repository.py`
- Test: `tests/unit/test_parsers.py`
- Test: `tests/property/test_parser_properties.py`
- Test: `tests/unit/test_tools.py`
- Test: `tests/conformance/test_mcp_http.py`

**Interfaces:**

- Consumes: request `page_size`, configured upstream byte/deadline ceilings, ASGI send operations.
- Produces: parser cardinality/aggregate-text ceilings, rejection of oversized search pages, bounded serialization, and per-write/total asset-stream timeouts.

- [x] **Step 1: Write post-parse amplification RED tests**

  Add literal adversarial fixtures for more rows than requested, excessive metadata/bitstream cardinality, excessive aggregate text, and excessive nesting; assert stable bounded errors.

- [x] **Step 2: Verify parser RED**

  Run: `.venv/bin/pytest -q tests/integration/test_repository.py tests/unit/test_parsers.py tests/property/test_parser_properties.py tests/unit/test_tools.py -k 'limit or amplification or page_size or metadata'`

- [x] **Step 3: Enforce parser/result ceilings**

  Count parsed objects and Unicode scalar text under explicit constants, reject rows beyond requested `page_size`, and bound the serialized tool payload before duplicating it into text and structured content.

- [x] **Step 4: Write slow-reader RED tests**

  Use a controlled ASGI sender that never completes and assert signed-asset delivery terminates within the configured idle/total ceiling and releases its permit.

- [x] **Step 5: Enforce stream timeouts and verify GREEN**

  Wrap each ASGI send with an idle timeout and the response with one absolute total deadline; preserve disconnect behavior and cleanup.

  Run: `.venv/bin/pytest -q tests/integration/test_repository.py tests/unit/test_parsers.py tests/property/test_parser_properties.py tests/unit/test_tools.py tests/conformance/test_mcp_http.py`

---

### Task 6: Integrated evidence and residual blocker classification

**Files:**

- Modify only if executable evidence exists: `docs/security/asvs-5.0.0-l2-matrix.jsonl`
- Modify only if executable evidence exists: `docs/security/evidence-manifest.jsonl`
- Modify: `docs/superpowers/plans/2026-08-20-phase-0-1-audit-remediation.md` checkbox status only during execution.

**Interfaces:**

- Consumes: fresh local gate outputs and externally controlled receipt requirements.
- Produces: a custody-preserving fixed/unfixed finding map and an exact fail-closed release decision.

- [x] **Step 1: Run focused strict gates**

  Run Ruff format/check, mypy strict, Pyright strict, contract runtime/typecheck/lint, Bandit, pip-audit, and Zizmor with repository-pinned commands.

- [x] **Step 2: Run comprehensive test and coverage gates**

  Run the exact test registry gate, direct full pytest, project branch coverage, changed-line coverage, changed-branch-arc coverage, and mutation gate. Require every local threshold; a passing subset is not aggregate success.

- [x] **Step 3: Run release decision and dependency evidence**

  Run `scripts/verify_release.py` in the documented local-gates mode and retain `do_not_release / external_authority_required` unless protected controller, deployment, custody, ASVS, and scanner receipts are genuinely present.

- [x] **Step 4: Re-audit every finding**

  Classify F-01 through F-15 as fixed, partially fixed, externally blocked, or still failing with exact file/test evidence. Specifically retain blockers for separate native-worker authority, persistent-cache tenancy/eviction, byte-bound analyzer images, ASVS L2 assessment, and Python 3.13.15 runtime proof unless this execution produces direct evidence.

- [x] **Step 5: Verify custody**

  Recompute the staged binary-diff SHA-256 and require `8b612e255840cb28bde5502209d7012d2bf896e63b099c4211a740a6199b415d`; list only the new unstaged remediation files/changes.
