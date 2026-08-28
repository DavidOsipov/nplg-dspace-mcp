# Lean Alpic MCP Release Finalization Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing public, anonymous `alpic-metadata` MCP candidate
genuinely release-ready, then obtain a truthful, evidence-backed release
decision without redesigning the release controller or broadening the deployed
product.

**Architecture:** Preserve the implemented Phase 0-8 architecture and the
existing 13-operation protected-controller contract. The controller is a
release-authority boundary, not end-user authentication for the MCP. Close only
two real gaps: candidate-mode ASVS assessment and anonymous Alpic hosted
evidence. Freeze one candidate and use the existing protected workflow for
staging, custody, attestation, and eligibility; actual Production deployment
remains a separately authorized external action.

**Tech Stack:** CPython 3.12-3.14, `mcp==2.0.0`, strict Pydantic,
TypeScript 6.0.3, Zod 4.4.3, Node 24.19.0, pytest, Hypothesis, Ruff, mypy,
Pyright, ESLint, mutmut, Bandit, Semgrep, pip-audit, CycloneDX, and Trivy.

**Spec:** `docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md`

**Scope precedence:** For this first release only, the approved anonymous
boundary in Task 2 supersedes the Spec's identity-aware authentication and
protected OAuth/Auth0/DCR activation requirements for `alpic-metadata`. It does
not delete or satisfy those deferred requirements, and this release must not
claim OAuth support or Alpic `Protected` classification.

**Alpic references:** [builds](https://docs.alpic.ai/build-deploy/builds),
[audit/Beacon](https://docs.alpic.ai/testing/beacon), and
[endpoints](https://docs.alpic.ai/build-deploy/endpoints).

## Global Constraints

- Release only `DeploymentProfile.ALPIC_METADATA` with exactly
  `search_documents`, `get_document_metadata`, and `list_document_files`.
- Keep `private-full`, `distributed-full`, MCP Tasks, PDF execution, resource
  templates, every MCP resource except the exact fixed client workflow,
  application-owned dynamic asset routes or private artifact bytes, and custom
  application data APIs out of this release.
  Treat `/healthz`, `/readyz`, `/metrics`, and provider-reserved `/assets/*` as
  separately inventoried operational/platform surfaces, not MCP capabilities.
- Reuse the existing 13 protected operation IDs and four launcher commands.
  Do not add a second command grammar or extend the controller in this plan.
- Candidate code may validate evidence; it may not hold provider credentials,
  grant approval, sign evidence, deploy, publish, or create custody authority.
- Runtime models use strict/frozen Pydantic with `extra="forbid"`; JSON input
  rejects duplicate keys, non-finite numbers, malformed UTF-8, invalid Unicode,
  coercion, unknown fields, and unbounded collections.
- Cross-language contracts use Zod 4.4.3 strict objects and the same positive
  and negative corpus as Pydantic.
- Keep TypeScript at 6.0.3. Do not add Alpic provider SDK packages for this
  anonymous slice.
- Declare `"transportType": "streamablehttp"` in `alpic.json`; the current
  low-level `Server.streamable_http_app(...)` integration is not a documented
  auto-detection case.
- Do not add OAuth/JWT/DCR activation, token-shape inference, static production
  credentials, arbitrary JWKS fetching, raw argv passthrough, or secret-bearing
  evidence. Existing OAuth capability records remain truthful negative evidence
  for future work; do not rewrite them as supported.
- Preserve the current Git index. Do not stage, unstage, commit, reset, stash,
  clean, push, deploy, change Alpic configuration, sign, or publish
  without the exact authorization named below.
- Every implementation task follows witnessed RED, minimal GREEN, focused
  rerun, adversarial/property coverage, mutation testing for decision logic,
  and an explicit no-refactor/refactor decision.
- An interrupted, timed-out, or missing authoritative command is incomplete,
  not PASS.

## Explicit Non-goals

- No new release-command request family.
- No expansion from 13 to 27 controller operations.
- No OAuth, Auth0, DCR, JWT verifier, or Alpic `Protected` classification in
  this anonymous first release. That is separately planned future work.
- No MCP Registry publication; that is an optional later plan.
- No production rollback platform or generic release orchestrator in this
  repository.
- No upgrade to TypeScript 7 or unrelated dependencies.
- No claim that local tests, staging, or `release_recommended` equals external
  Production authorization.

## Current Release Blockers

| Blocker | Closure in this plan |
| --- | --- |
| ASVS tooling accepts only the bootstrap/unassessed state | Task 1 |
| Anonymous runtime, catalog, and verifier behavior is incomplete | Task 2 |
| Alpic deploy-pack and anonymous hosted evidence are incomplete | Task 4 |
| The immutable candidate battery has no complete authoritative rerun | Task 3 |
| Protected controller, custody, attestation, and Production authority are external | Task 4 |

---

### Task 1: Enable a Real ASVS L2 Candidate Assessment

**Files:**

- Modify: `docs/security/asvs-5.0.0-l2-method.md`
- Modify: `docs/security/asvs-evidence-policy.json`
- Modify: `scripts/build_asvs_matrix.py`
- Modify: `contracts/zod/asvs-evidence-contracts.mjs`
- Modify: `tests/unit/test_build_asvs_matrix.py`
- Modify: `tests/property/test_asvs_evidence.py`
- Modify: `tests/static/test_asvs_evidence.py`
- Modify: `tests/contracts/zod_asvs_evidence_contracts.test.mjs`
- Modify: `scripts/run_mutation_gate.py`
- Modify: `tests/unit/test_mutation_gate.py`
- Modify: `security/coverage-policy.json`

**Interfaces:**

```python
AssessmentMode = Literal["bootstrap", "candidate"]
ClaimPurpose = Literal["implementation-proof", "absence-proof"]

def evaluate_profile_release(
    *,
    profile: DeploymentProfile,
    candidate: GitCommit,
    matrix: tuple[AsvsRow, ...],
    evidence: tuple[EvidenceClaim, ...],
) -> AsvsL2ConformanceVerdict: ...
```

- `bootstrap` remains byte-for-byte strict and accepts only the deterministic
  759-row `Not assessed` inventory with an empty evidence manifest.
- `candidate` verifies all 253 selected `alpic-metadata` rows and accepts only
  independently evidenced `Pass` or governed `N/A`.
- `N/A` requires `claim_purpose="absence-proof"`, an approved evidence kind,
  candidate/profile binding, reviewer identity, freshness, and custody.
- The attestation allowlist includes `docs/security/asvs-evidence-policy.json`
  and `docs/security/threat-model.json`.

- [ ] **Step 1: Write failing candidate-mode tests**

Add cases for one valid `Pass`, one governed `N/A`, missing absence proof,
wrong candidate/profile, expired evidence, duplicate evidence ID, bulk status
conversion, and unchanged bootstrap output. Register the exact one-target ASVS
mutation policy and reject reordered, missing, or extra targets.

- [ ] **Step 2: Observe RED**

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider \
  tests/unit/test_build_asvs_matrix.py \
  tests/property/test_asvs_evidence.py \
  tests/static/test_asvs_evidence.py \
  tests/unit/test_mutation_gate.py -q
npm run test:contracts:asvs
```

Expected: the new candidate/N/A cases fail because only bootstrap assessment is
currently accepted; existing bootstrap cases remain GREEN.

- [ ] **Step 3: Implement the separate candidate branch**

Keep bootstrap and candidate evaluation as separate strict paths. Do not add a
permissive shared default or automatically convert any row. Add the exact
`("scripts/build_asvs_matrix.py",)` mutation policy with its focused tests and
closed required-function inventory; do not add wildcard targets.

- [ ] **Step 4: Observe GREEN and mutation sensitivity**

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider \
  tests/unit/test_build_asvs_matrix.py \
  tests/property/test_asvs_evidence.py \
  tests/static/test_asvs_evidence.py \
  tests/unit/test_mutation_gate.py -q
npm run test:contracts:asvs
.venv/bin/python scripts/run_mutation_gate.py \
  --targets scripts/build_asvs_matrix.py
```

Expected: all focused tests pass and mutations in mode selection, N/A
governance, candidate binding, expiry, or blocker aggregation are killed.

- [ ] **Step 5: Refactor only if the two modes are not independently reviewable**

Rerun Step 4 after any refactor. Leave all edits unstaged.

### Task 2: Complete the Anonymous Three-tool Alpic Metadata Slice

This task implements the approved first runtime/candidate boundary: anonymous,
sessionless Streamable HTTP for the public `alpic-metadata` profile only.
OAuth, Auth0, DCR, protected provider custody, and private profiles remain
explicitly deferred. Their absence is not an authentication vulnerability in
this public metadata-only slice. This task does not establish a hosted
deployment, deploy pack, custody, or release authority.

**Files:**

- Modify: `alpic.json`, `.env.example`, `README.md`, `deploy/ALPIC.md`
- Modify: `src/nplg_mcp/config.py`, `src/nplg_mcp/app.py`
- Modify: `scripts/verify_deploy.py`
- Modify: `tests/unit/test_config.py`
- Modify: `tests/integration/test_profiles.py`
- Modify: `tests/security/test_auth_activation.py`
- Modify: `tests/conformance/test_mcp_http.py`
- Modify: `tests/static/test_deployment.py`
- Modify: `tests/unit/test_verify_deploy.py`

The exact skill/package/resource files and their focused gates are specified by
`docs/superpowers/plans/2026-08-28-alpic-client-pdf-skill-resource.md`; that
bounded companion plan is part of this Task 2 implementation contract.

**Interfaces and invariants:**

- `alpic.json` uses `transportType: "streamablehttp"`; the application
  serves the official MCP Streamable HTTP endpoint at `POST /mcp`.
- Production anonymous access is valid only when
  `DEPLOYMENT_PROFILE=alpic-metadata` and `ALLOW_ANONYMOUS=true`.
- The profile exposes exactly `search_documents`,
  `get_document_metadata`, and `list_document_files`.
- It registers exactly one fixed `text/markdown` MCP resource at
  `nplg://skills/georgian-newspaper-visual-analysis`, no resource templates,
  and initializes no asset route, downloader, content store, scanner, PDF
  runtime, or rendering service. The resource is an instruction-only client
  workflow, not server-side PDF execution.
- Production static bearer tokens, API keys, and private static credentials
  remain forbidden. `private-full` and `distributed-full` fail closed.
- Host, Origin, JSON framing, protocol-version, request-size, body-time,
  application-deadline, and concurrency controls remain active.
- `verify_deploy.py` verifies only the methods implemented by the selected
  profile. For `alpic-metadata` it requests `resources/list` and
  `resources/read` only for the exact client workflow; `private-full` retains
  its separate `nplg://about` verification.
- OAuth/Auth0/DCR capability records remain negative evidence for future work
  and cannot be represented as support, a shared-secret substitute, or a
  prerequisite for this anonymous profile.

- [ ] **Step 1: Write focused RED tests**

Add or retain tests proving:

- production anonymous metadata configuration is accepted;
- anonymous production for every other profile is rejected;
- all production static credential combinations are rejected;
- the public catalog has exactly three tools, one exact static workflow
  resource, no resource templates or private resources, and no asset route;
- malformed Host, Origin, headers, JSON, duplicate keys, bodies, and protocol
  inputs fail closed at their existing bounds;
- the deployment verifier issues `server/discover`, `tools/list`,
  `resources/list`, and one exact `resources/read` for `alpic-metadata`, while
  `private-full` still verifies `nplg://about`;
- unknown profiles, extra tools, annotation drift, session creation, and
  malformed private resource responses are rejected.

- [ ] **Step 2: Observe RED**

Run only the focused cases introduced in Step 1 and confirm each fails for the
missing or stale profile behavior, not for an import, fixture, or environment
error. Preserve the command, exit status, and expected failure.

- [ ] **Step 3: Implement the minimum anonymous slice**

Reuse the existing official MCP server and metadata service composition. Add
only the profile-scoped startup exception and profile-aware verifier behavior
required by Step 1. Do not add OAuth code, provider SDK packages, deployment
pack builders, audit subsystems, dynamic/private resource shims, or a second
transport. The one fixed client-workflow resource is the only added resource
surface.

- [ ] **Step 4: Observe focused GREEN**

```bash
PYTHONPATH=src .venv/bin/python -m pytest \
  tests/static/test_deployment.py \
  tests/unit/test_config.py \
  tests/integration/test_profiles.py \
  tests/security/test_auth_activation.py \
  tests/conformance/test_mcp_http.py \
  tests/unit/test_verify_deploy.py -q
```

Expected: the focused suites pass with no skips or warnings that hide missing
coverage. The verifier must retain distinct negative cases for metadata and
private resource behavior.

- [ ] **Step 5: Run the existing exact catalog mutation gate**

```bash
.venv/bin/python scripts/run_mutation_gate.py \
  --targets src/nplg_mcp/profiles.py
```

This gate proves mutation sensitivity for the exact three-tool profile
inventory only. Do not represent it as mutation coverage for configuration,
HTTP admission, or deployment verification. Any broader Task 2 mutation policy
requires a separate reviewed closed tuple and focused-test mapping; do not
resurrect the obsolete OAuth/audit/deploy-pack tuple.

- [ ] **Step 6: Reconcile deployment guidance and refactor only while GREEN**

`README.md` and `deploy/ALPIC.md` must describe the same anonymous-first
boundary and keep provider deployment/custody/release authority separate from
local runtime correctness. Rerun Step 4, Step 5, and the strict quality gate
after any refactor. Leave all edits unstaged.

### Task 3: Freeze and Qualify One Immutable Candidate

**Files:**

- Modify only when a gate exposes a concrete defect: that source file and its
  focused test.
- Create only as ignored local evidence:
  `.superpowers/sdd/2026-08-26-alpic-mcp-release-finalization/`

**Interfaces:**

- Produces one clean candidate commit/tree, wheel, sdist, local gate report,
  and exact subject digests. Provider deployment packaging and the
  `alpic-deploy-pack` remain outside Task 3 authority; only the externally
  provisioned protected workflow's `candidate-battery` in Task 4 may build and
  bind the pack.
- Local qualification cannot grant provider, custody, release, or publication
  authority.

- [ ] **Step 1: Record the Git and tool baseline**

Record branch, HEAD, staged/unstaged/untracked paths, index digest, Python/Node
executables, and tool versions. Abort on unexplained drift. Never reset, stash,
clean, or broadly stage.

- [ ] **Step 2: Run the focused and full overlay gates**

```bash
.venv/bin/python scripts/run_quality_gate.py \
  --node-executable "$(command -v node)" src tests scripts
.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main
.venv/bin/python scripts/run_mutation_gate.py \
  --targets scripts/build_asvs_matrix.py
.venv/bin/python scripts/run_mutation_gate.py \
  --targets src/nplg_mcp/profiles.py
```

Expected: every command returns an authoritative zero. Timeout, interruption,
or an incomplete mutation report is not GREEN.

- [ ] **Step 3: Request exact Git authorization**

Present the precise diff, paths, gate receipts, proposed message, and subject
digests. Stage and commit only the approved paths after explicit authorization.

- [ ] **Step 4: Re-run release-mode gates on the clean commit**

```bash
set -euo pipefail
CANDIDATE_COMMIT="$(git rev-parse HEAD)"
test -z "$(git status --porcelain=v1)"
NPLG_CANDIDATE_TMP_DIR="$(mktemp -d)"
test "$NPLG_CANDIDATE_TMP_DIR" != "${NPLG_CANDIDATE_TMP_DIR#/}"
QUALITY_CACHE="$NPLG_CANDIDATE_TMP_DIR/quality-cache"
TEST_OUTPUT="$NPLG_CANDIDATE_TMP_DIR/test-output"
ASVS_MUTATION_OUTPUT="$NPLG_CANDIDATE_TMP_DIR/asvs-mutation-output"
METADATA_MUTATION_OUTPUT="$NPLG_CANDIDATE_TMP_DIR/metadata-mutation-output"
LOCAL_GATES="$NPLG_CANDIDATE_TMP_DIR/local-gates.json"
DIST_DIR="$NPLG_CANDIDATE_TMP_DIR/dist"
test ! -e "$QUALITY_CACHE"
test ! -e "$TEST_OUTPUT"
test ! -e "$ASVS_MUTATION_OUTPUT"
test ! -e "$METADATA_MUTATION_OUTPUT"
test ! -e "$LOCAL_GATES"
test ! -e "$DIST_DIR"
.venv/bin/python scripts/run_quality_gate.py \
  --worktree "$PWD" --require-clean --candidate "$CANDIDATE_COMMIT" \
  --cache-dir "$QUALITY_CACHE" \
  --node-executable "$(command -v node)" src tests scripts
.venv/bin/python scripts/run_test_gate.py \
  --worktree "$PWD" --require-clean --candidate "$CANDIDATE_COMMIT" \
  --compare-branch origin/main --output-dir "$TEST_OUTPUT"
.venv/bin/python scripts/run_mutation_gate.py \
  --worktree "$PWD" --require-clean --candidate "$CANDIDATE_COMMIT" \
  --output-dir "$ASVS_MUTATION_OUTPUT" \
  --targets scripts/build_asvs_matrix.py
.venv/bin/python scripts/run_mutation_gate.py \
  --worktree "$PWD" --require-clean --candidate "$CANDIDATE_COMMIT" \
  --output-dir "$METADATA_MUTATION_OUTPUT" \
  --targets src/nplg_mcp/profiles.py
.venv/bin/python scripts/verify_release.py local-gates \
  --worktree "$PWD" --output "$LOCAL_GATES" \
  --node-executable "$(command -v node)" --compare-branch origin/main
.venv/bin/python -m build --outdir "$DIST_DIR"
```

Expected: all receipts and artifacts bind the same clean commit/tree. Any drift
returns the candidate to `do_not_release`.

### Task 4: Use the Existing Protected Workflow for Anonymous Hosted Evidence

Obtain the release decision without adding end-user authentication. Here,
`protected` describes the external release-controller authority and custody
boundary; the deployed MCP remains deliberately anonymous.

No application or release-command code is added in this task.

**Files:**

- Modify only in the protected attestation workspace:
  `docs/security/asvs-5.0.0-l2-matrix.jsonl`
- Modify only in the protected attestation workspace:
  `docs/security/evidence-manifest.jsonl`
- Modify only in the protected attestation workspace:
  `docs/security/threat-model.json`, `docs/security/threat-model.md`
- Modify only in the protected attestation workspace: `SECURITY.md`
- Create only from signed evidence:
  `docs/verification/2026-08-26-alpic-release-candidate.md`

**External prerequisites:**

- Signed `ProtectedControllerProvisioningReceipt.v2` covering all existing 13
  operations and four launcher commands.
- Absolute digest-verified protected launcher, policy, trust root, both frozen
  credential-broker class descriptors (`deployment_provider` and `mcp`),
  network broker, and custody authority.
- The provisioned controller's existing `StagingProofResult.v2` path accepts an
  anonymous `alpic-metadata` operation request without requiring OAuth-specific
  fields or changing the checked-in manifest, operation IDs, or schemas.
- Signed controller evidence preserves both broker classes while the anonymous
  operation requests, receives, and uses zero MCP credential handles. Provider
  deployment credentials remain confined to the `deployment_provider` broker.
  If the existing controller requires an MCP access-token handle, stop at
  `do_not_release`.
- Authorized Alpic staging configuration with exact project, environment,
  canonical base URL, MCP URL, `transportType="streamablehttp"`, approved
  runtime-secret injection, and `ALLOW_ANONYMOUS=true`.
- Separate authorization for staging deployment, attestation commit, custody,
  cleanup, and any Production deployment.

If any prerequisite is missing or mismatched, stop with
`PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE` or the exact signed
controller/provider blocker. Do not replace it with candidate code or weaken
the release manifest.

- [ ] **Step 1: Run the existing candidate-to-staging DAG**

Use only the checked-in launcher contracts:

- `initialize-run` requires `--provisioning-receipt`, `--controller-policy`,
  `--repository-root`, `--candidate`, `--profile`,
  `--profile-inputs-json`, `--network-broker-descriptor`,
  `--custody-authority-descriptor`, `--run-parent`,
  `--initialization-journal-json`, `--run-descriptor-json`, and
  `--authorize-run-root`;
- `run-through` requires `--provisioning-receipt`, `--run-descriptor-json`, and
  `--range-request-json`;
- descriptor-selected recovery through `resume-run` requires
  `--provisioning-receipt`, `--run-descriptor-json`, and
  `--resume-request-json`.

The protected controller must produce and validate each closed JSON request and
bind it to the exact candidate, profile, manifest, and run descriptor. Unknown
options, passthrough, shell reconstruction, the obsolete `--through` shorthand,
and recovery inferred from shell state are forbidden. If the existing closed
profile-input contract cannot express the approved anonymous mode, stop at
`do_not_release`; do not change the command grammar or operation IDs here.

The protected staging proof must bind the exact candidate, source tree, wheel,
sdist, protected-workflow battery-built deploy pack, environment, deployment,
runtime, canonical URLs, and a canonical `tools/list` digest covering the exact
three names, schemas, and annotations. It must prove credential-free,
sessionless Streamable HTTP behavior; the exact digest-bound client-workflow
resource; absence of resource templates, prompts, subscriptions, private or
dynamic resources, application-owned dynamic asset routes or private artifact
bytes, custom application data APIs, and private-profile composition;
Host/Origin, method,
content-type, framing, and protocol admission; bounded
malformed/unmatched-credential rejection; and enforcement of the exact
configured request-size, body-time, application-deadline, global concurrency,
and anonymous-principal concurrency limits through captured negative probes.
It must also bind Alpic audit/Beacon dispositions, privacy settings, and final
environment recapture.
It must separately inventory provider-owned `/assets/*` and the application
probe routes `/healthz`, `/readyz`, and `/metrics`, proving that each is either
intentionally admitted or not publicly routed and that `/metrics` remains 404
for this credential-free configuration. An unknown or unexpectedly public
route blocks release. A missing full `sourceCommitId` remains an explicit
blocker unless the protected upload receipt and runtime identity independently
bind the exact pack.

The protected result uses the existing `StagingProofResult.v2` envelope and
must remain bound to the exact candidate and staging identity. The negative
`OAuthProviderCapabilityVerdict` and other OAuth/Auth0/DCR capability records
remain unchanged future-work evidence; they are neither support claims nor
eligibility inputs for this anonymous release. If the external controller
cannot preserve that separation, stop at `do_not_release` and require a
separately authorized controller-owner plan.

- [ ] **Step 2: Independently assess all 253 selected ASVS rows**

Use `Pass` only with current candidate-bound evidence and governed `N/A` only
with reviewed absence proof. `Not assessed`, `Fail`, `Partial`, expired
evidence, or ungoverned `N/A` prevents a positive recommendation.
Authentication requirements may be `N/A` only when reviewed evidence proves
that the requirement does not apply to the deliberately public, read-only
metadata surface and that no restricted data or action is exposed. Anonymous
operation alone is not sufficient absence proof.

Run after each review batch:

```bash
RELEASE_PROFILE=alpic-metadata \
  .venv/bin/python -m pytest \
  tests/static/test_asvs_evidence.py \
  tests/property/test_asvs_evidence.py -q
npm run test:contracts:asvs
```

- [ ] **Step 3: Commit and verify the attestation through the existing DAG**

After exact-path Git authorization, use the existing
`attestation-workspace`, `commit-attestation`, `attest`, `eligibility`, final
decision custody, and cleanup operations. A negative eligibility result is
valid audit closure only after its signed `do_not_release` chain is custodied.

Expected positive local/external outcome: a signed, read-back-verified
`release_recommended` decision with zero blockers and ASVS L2 conformance. It
is not Production authority.

- [ ] **Step 4: Obtain the separately authorized Production result**

The organizational release owner—not this repository—must deploy the exact
custodied pack without rebuilding it and return signed evidence binding the
Production project/environment/deployment, candidate/tree/pack, anonymous
Streamable HTTP configuration, three-tool catalog, absent private surfaces,
audit/privacy checks, post-deploy health, rollback target, and approval
identity.

If that authority or evidence contract is unavailable, stop at
`release_recommended`; do not add controller operations here. Only a verified
positive Production receipt may change the externally reported status to
`released`.

Registry publication is intentionally excluded. If later requested, write a
small separate plan for the one authorized publication action and verification.

## Completion Gate

The anonymous `alpic-metadata` MCP is release-ready only when Tasks 1-3 pass for
one immutable candidate and Task 4 produces a signed, custodied, blocker-free
recommendation for that exact anonymous profile. Deferred negative OAuth/Auth0/
DCR capability records remain truthful future-work evidence; they are neither
cleared nor joined into this profile's eligibility decision. The MCP is
actually `released` only after the separate Production authority returns and
the release owner verifies the positive Production receipt. Until then, report
the exact truthful state—`do_not_release` or `release_recommended`—without
claiming publication.
