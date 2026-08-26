# Lean Alpic MCP Release Finalization Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing `alpic-metadata` MCP candidate genuinely
release-ready, then obtain a truthful, evidence-backed release decision without
redesigning the release controller or broadening the deployed product.

**Architecture:** Preserve the implemented Phase 0-8 architecture and the
existing 13-operation protected-controller contract. Close only three real
gaps: candidate-mode ASVS assessment, provider-bound OAuth for the three-tool
metadata profile, and Alpic deployment evidence. Freeze one candidate and use
the existing protected workflow for staging, custody, attestation, and
eligibility; actual Production deployment remains a separately authorized
external action.

**Tech Stack:** CPython 3.12-3.14, `mcp==2.0.0`, strict Pydantic,
TypeScript 6.0.3, Zod 4.4.3, Node 24.19.0, pytest, Hypothesis, Ruff, mypy,
Pyright, ESLint, mutmut, Bandit, Semgrep, pip-audit, CycloneDX, Trivy, and the
Alpic CLI/SDK/API 1.169.1 family.

**Spec:** `docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md`

**Alpic references:** [builds](https://docs.alpic.ai/build-deploy/builds),
[OAuth setup](https://docs.alpic.ai/secure/auth/oauth-setup),
[DCR proxy](https://docs.alpic.ai/secure/auth/dcr-proxy),
[audit/Beacon](https://docs.alpic.ai/testing/beacon), and
[endpoints](https://docs.alpic.ai/build-deploy/endpoints).

## Global Constraints

- Release only `DeploymentProfile.ALPIC_METADATA` with exactly
  `search_documents`, `get_document_metadata`, and `list_document_files`.
- Keep `private-full`, `distributed-full`, MCP Tasks, PDF execution, resources,
  assets, and custom REST endpoints out of this release.
- Reuse the existing 13 protected operation IDs and four launcher commands.
  Do not add a second command grammar or extend the controller in this plan.
- Candidate code may validate evidence; it may not hold provider credentials,
  grant approval, sign evidence, deploy, publish, or create custody authority.
- Runtime models use strict/frozen Pydantic with `extra="forbid"`; JSON input
  rejects duplicate keys, non-finite numbers, malformed UTF-8, invalid Unicode,
  coercion, unknown fields, and unbounded collections.
- Cross-language contracts use Zod 4.4.3 strict objects and the same positive
  and negative corpus as Pydantic.
- Keep TypeScript at 6.0.3. Pin `alpic`, `@alpic-ai/sdk`, and
  `@alpic-ai/api` together at 1.169.1 after one registry recheck.
- Declare `"transportType": "streamablehttp"` in `alpic.json`; the current
  low-level `Server.streamable_http_app(...)` integration is not a documented
  auto-detection case.
- Do not accept opaque access tokens, ID tokens, token-shape inference, static
  production credentials, arbitrary JWKS fetching, raw argv passthrough, or
  secret-bearing evidence.
- Use coarse `nplg:connect` only after explicit user approval of the documented
  SDK limitation. Otherwise retain `do_not_release`.
- Preserve the current Git index. Do not stage, unstage, commit, reset, stash,
  clean, push, deploy, change Auth0/Alpic configuration, sign, or publish
  without the exact authorization named below.
- Every implementation task follows witnessed RED, minimal GREEN, focused
  rerun, adversarial/property coverage, mutation testing for decision logic,
  and an explicit no-refactor/refactor decision.
- An interrupted, timed-out, or missing authoritative command is incomplete,
  not PASS.

## Explicit Non-goals

- No new release-command request family.
- No expansion from 13 to 27 controller operations.
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
| Auth0/Alpic provider capability is unsupported | Task 2 |
| Alpic transport/build/hosted evidence is incomplete | Task 2 and Task 4 |
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

### Task 2: Complete the Protected Three-tool Alpic Vertical Slice

This task combines configuration, OAuth, audit, and deployment evidence because
they form one deployable security boundary. It does not implement another
profile or release system.

**Files:**

- Modify: `alpic.json`, `package.json`, `package-lock.json`
- Modify: `requirements.in`, `requirements.lock`, `pyproject.toml`
- Modify: `security/toolchain-lock.json`, `deploy/ALPIC.md`, `.env.example`
- Modify: `security/coverage-policy.json`
- Create: `deploy/alpic-runtime-manifest.json`
- Create: `deploy/alpic-environment-manifest.json`
- Create: `deploy/alpic-audit-dispositions.json`
- Create: `deploy/alpic-submission-versions.json`
- Modify: `contracts/oauth-provider-capability.json`
- Modify: `contracts/alpic-oauth-discovery-capability.json`
- Create: `contracts/alpic-dcr-flow-capability.json`
- Create: `contracts/oidc-subject-capability.json`
- Modify: `contracts/sdk-authorization-capability.json`
- Modify: `contracts/accepted-sdk-differences.json`
- Modify: `contracts/zod/capability-contracts.mjs`
- Create: `src/nplg_mcp/auth.py`, `src/nplg_mcp/audit.py`
- Modify: `src/nplg_mcp/capabilities.py`, `src/nplg_mcp/config.py`
- Modify: `src/nplg_mcp/app.py`, `src/nplg_mcp/http_security.py`
- Modify: `src/nplg_mcp/network.py`, `src/nplg_mcp/mcp_server.py`
- Modify: `src/nplg_mcp/sdk_boundary.py`, `src/nplg_mcp/admission.py`
- Modify: `src/nplg_mcp/errors.py`
- Create: `security/crypto-policy.json`
- Create: `docs/security/data-inventory.md`
- Create: `docs/security/cryptographic-inventory.json`
- Create: `docs/security/logging-inventory.json`
- Create: `tsconfig.tools.json`
- Create: `scripts/capture_alpic_deployment.ts`
- Create: `scripts/capture_alpic_deployment.test.ts`
- Create: `scripts/build_alpic_deploy_pack.py`
- Modify: `scripts/verify_deploy.py`
- Create: `scripts/run_alpic_staging_proof.py`
- Create: `tests/security/test_auth.py`, `tests/security/test_audit.py`
- Create: `tests/property/test_auth_properties.py`
- Modify: `tests/security/test_auth_activation.py`
- Modify: `tests/security/test_network.py`
- Modify: `tests/conformance/test_mcp_http.py`
- Modify: `tests/unit/test_config.py`, `tests/unit/test_admission.py`
- Modify: `tests/contracts/test_oauth_provider_capability.py`
- Modify: `tests/contracts/test_alpic_oauth_discovery.py`
- Create: `tests/contracts/test_alpic_dcr_flow_capability.py`
- Modify: `tests/static/test_deployment.py`
- Modify: `tests/unit/test_verify_deploy.py`
- Create: `tests/unit/test_build_alpic_deploy_pack.py`
- Create: `tests/unit/test_run_alpic_staging_proof.py`
- Create: `tests/property/test_deployment_evidence_properties.py`
- Modify: `scripts/run_mutation_gate.py`
- Modify: `tests/unit/test_mutation_gate.py`

**Interfaces:**

```python
OAuthProviderCapabilityVerdict = Annotated[
    UnsupportedAuth0ProviderVerdict | SupportedAuth0SignedJwtVerdict,
    Field(discriminator="supported"),
]

AlpicHostedOAuthVerdict = Annotated[
    UnsupportedAlpicDcrFlowVerdict | SupportedAlpicDcrFlowVerdict,
    Field(discriminator="supported"),
]


class OidcAuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    issuer: ExactHttpsUrl
    jwks_url: ExactHttpsUrl
    backend_resource_server_url: ExactHttpsUrl
    public_mcp_transport_endpoint: ExactHttpsUrl
    public_oauth_resource_url: ExactHttpsUrl
    audiences: Annotated[tuple[Audience, ...], Field(min_length=1, max_length=8)]
    algorithms: Annotated[
        tuple[Literal["RS256", "PS256", "ES256"], ...],
        Field(min_length=1, max_length=3),
    ]
    allowed_hosts: Annotated[
        tuple[CanonicalHost, ...], Field(min_length=1, max_length=16)
    ]
    allowed_origins: Annotated[
        tuple[CanonicalOrigin, ...], Field(max_length=16)
    ]
    required_scopes: tuple[Literal["nplg:connect"]]
    jwks_timeout_ms: Literal[3000]
    clock_skew_seconds: Literal[60]
    access_token_max_lifetime_seconds: Literal[300]


class OidcJwtTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None: ...


def build_auth_settings(config: OidcAuthConfig) -> AuthSettings: ...


class SdkAuthContextPrincipalSource:
    def current(self) -> Principal: ...


def build_minimal_deploy_pack(
    *, worktree: Path, candidate: GitCommit, output_dir: Path
) -> MinimalDeployPackManifest: ...
def verify_alpic_deployment(
    capture: bytes, *, expected: AlpicDeploymentSelector
) -> AlpicDeploymentEvidence: ...
```

`build_auth_settings()` passes the byte-exact issuer,
`backend_resource_server_url`, and `required_scopes` to MCP 2.0
`AuthSettings`. The public MCP/resource URLs are separate explicit route and
challenge bindings; none is derived from `Host` or another configured URL.

The two verdicts are not interchangeable. Exact Auth0 signed-JWT evidence may
enable local/runtime construction, but `AlpicHostedOAuthVerdict` stays
unsupported until Task 4 witnesses the deployed public/backend issuer mapping,
DCR registration, callback, and authorization-code/PKCE flow. Task 2 cannot
clear `OAUTH_END_TO_END_FLOW_UNPROVEN`.

- [ ] **Step 1: Satisfy the external fact gate before positive activation**

Obtain authorized evidence for the exact Auth0 tenant/application, byte-exact
issuer, authorization/token/JWKS endpoints, audience/resource, signed-JWT
access-token format, accepted algorithms, client identity claim, stable subject,
scope, token lifetime, and PKCE S256. Obtain explicit approval for coarse
`nplg:connect`. If either is absent, keep the capability unsupported and stop
this task without guessing from generic documentation. This gate supports only
the Auth0 signed-JWT provider branch; keep the checked-in hosted DCR verdict
negative until Task 4.

- [ ] **Step 2: Write strict capability/configuration RED tests**

Reject templates, opaque tokens, ID tokens, wrong issuer/audience, unbounded
lists, unknown fields, coercion, duplicate JSON keys, unknown algorithms,
`offline_access`, callback/origin/Host drift, and any secret in configuration or
evidence. Add identical Pydantic/Zod corpus cases. Prove that a supported
pre-deploy provider plus an unsupported hosted-DCR verdict can construct local
auth but cannot satisfy release eligibility. Add a failing mutation-policy test
for the exact Task 2 tuple and reject target reordering, omission, or extras.

- [ ] **Step 3: Write runtime OAuth and audit RED tests**

Cover malformed JWT/JWK encodings, duplicate JOSE or claim keys, `alg=none`,
algorithm confusion, token-controlled key URLs, wrong key type/use/size/curve,
unknown/duplicate `kid`, JWKS redirect/private-IP/rebinding/timeout/oversize,
wrong issuer/audience/scope/client/subject, expired/not-yet-valid/overlong token,
`authorization_details`, concurrent requests, cancellation, and raw-token or
claim leakage in logs.

Run:

```bash
.venv/bin/python -m pytest \
  tests/contracts/test_oauth_provider_capability.py \
  tests/contracts/test_alpic_oauth_discovery.py \
  tests/contracts/test_alpic_dcr_flow_capability.py \
  tests/security/test_auth.py \
  tests/security/test_audit.py \
  tests/security/test_auth_activation.py \
  tests/security/test_network.py \
  tests/property/test_auth_properties.py \
  tests/conformance/test_mcp_http.py \
  tests/unit/test_config.py \
  tests/unit/test_admission.py \
  tests/unit/test_mutation_gate.py -q
npm run contracts:zod:all
```

Expected: new positive-provider and runtime cases fail while the current
unsupported fail-closed path remains GREEN.

- [ ] **Step 4: Implement the minimum signed-JWT metadata path**

Use the existing official SDK OAuth integration. Fetch JWKS only through the
repository's bounded HTTPS/DNS/IP-pinned network boundary. Construct the SDK
principal only after signature, issuer, audience, lifetime, scope, client, and
subject validation. Audit only pseudonymous identity and bounded method/tool/
outcome fields; never retain the raw token or claims.

- [ ] **Step 5: Write Alpic build/evidence RED tests**

Test exact `transportType`, exact 1.169.1 package pins, a minimal allowlisted
deploy pack, symlink/path traversal and secret-file rejection, strict injected
deployment JSON, zero/multiple/wrong/stale deployments, provider
`sourceCommitId` as exact SHA-40 or truthful `unavailable`, warning/skip
dispositions, three-tool catalog identity, and environment drift.

- [ ] **Step 6: Observe the Alpic evidence RED**

```bash
.venv/bin/python -m pytest \
  tests/static/test_deployment.py \
  tests/unit/test_verify_deploy.py \
  tests/unit/test_build_alpic_deploy_pack.py \
  tests/unit/test_run_alpic_staging_proof.py \
  tests/property/test_deployment_evidence_properties.py -q
npm run deployment:evidence:typecheck
npm run deployment:evidence:lint
npm run deployment:evidence:test
```

Expected: the new transport, pack, capture, and drift cases fail because the
candidate-safe evidence tooling is absent.

- [ ] **Step 7: Implement only candidate-safe Alpic tooling**

Generate the exact lock update without lifecycle scripts:

```bash
npm install --package-lock-only --ignore-scripts --save-dev --save-exact \
  alpic@1.169.1 @alpic-ai/sdk@1.169.1 @alpic-ai/api@1.169.1
```

Implement only the allowlisted pack builder and injected-evidence parsers.
They perform no network access and execute no Alpic command. Register the exact
Task 2 mutation tuple and its focused test paths/functions in
`run_mutation_gate.py`; do not add wildcard or caller-selected targets.

- [ ] **Step 8: Observe focused GREEN and mutation sensitivity**

```bash
.venv/bin/python -m pytest \
  tests/contracts/test_oauth_provider_capability.py \
  tests/contracts/test_alpic_oauth_discovery.py \
  tests/contracts/test_alpic_dcr_flow_capability.py \
  tests/security/test_auth.py \
  tests/security/test_audit.py \
  tests/security/test_auth_activation.py \
  tests/security/test_network.py \
  tests/property/test_auth_properties.py \
  tests/conformance/test_mcp_http.py \
  tests/unit/test_config.py \
  tests/unit/test_admission.py \
  tests/static/test_deployment.py \
  tests/unit/test_verify_deploy.py \
  tests/unit/test_build_alpic_deploy_pack.py \
  tests/unit/test_run_alpic_staging_proof.py \
  tests/property/test_deployment_evidence_properties.py \
  tests/unit/test_mutation_gate.py -q
npm run contracts:zod:all
npm run deployment:evidence:typecheck
npm run deployment:evidence:lint
npm run deployment:evidence:test
.venv/bin/python scripts/run_mutation_gate.py \
  --targets src/nplg_mcp/auth.py src/nplg_mcp/audit.py \
  scripts/build_alpic_deploy_pack.py scripts/verify_deploy.py \
  scripts/run_alpic_staging_proof.py
```

Expected: focused suites pass and mutations in auth decisions, redaction,
deployment identity, source-identity honesty, or blocker propagation are
killed. Document provider-owned `/`, `/mcp`, `/try`, `/assets`, and OAuth/DCR
routes separately from application-owned handlers.

- [ ] **Step 9: Refactor only within the vertical-slice boundaries**

Keep token verification, audit serialization, deployment parsing, and pack
construction separately reviewable. Rerun Step 8 and leave edits unstaged.

### Task 3: Freeze and Qualify One Immutable Candidate

**Files:**

- Modify only when a gate exposes a concrete defect: that source file and its
  focused test.
- Create only as ignored local evidence:
  `.superpowers/sdd/2026-08-26-alpic-release-finalization/`

**Interfaces:**

- Produces one clean candidate commit/tree, wheel, sdist, minimal Alpic deploy
  pack, local gate report, and exact subject digests.
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
  --targets src/nplg_mcp/auth.py src/nplg_mcp/audit.py \
  scripts/build_alpic_deploy_pack.py scripts/verify_deploy.py \
  scripts/run_alpic_staging_proof.py
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
ALPIC_MUTATION_OUTPUT="$NPLG_CANDIDATE_TMP_DIR/alpic-mutation-output"
LOCAL_GATES="$NPLG_CANDIDATE_TMP_DIR/local-gates.json"
DIST_DIR="$NPLG_CANDIDATE_TMP_DIR/dist"
DEPLOY_PACK="$NPLG_CANDIDATE_TMP_DIR/deploy-pack"
test ! -e "$QUALITY_CACHE"
test ! -e "$TEST_OUTPUT"
test ! -e "$ASVS_MUTATION_OUTPUT"
test ! -e "$ALPIC_MUTATION_OUTPUT"
test ! -e "$LOCAL_GATES"
test ! -e "$DIST_DIR"
test ! -e "$DEPLOY_PACK"
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
  --output-dir "$ALPIC_MUTATION_OUTPUT" \
  --targets src/nplg_mcp/auth.py src/nplg_mcp/audit.py \
  scripts/build_alpic_deploy_pack.py scripts/verify_deploy.py \
  scripts/run_alpic_staging_proof.py
.venv/bin/python scripts/verify_release.py local-gates \
  --worktree "$PWD" --output "$LOCAL_GATES" \
  --node-executable "$(command -v node)" --compare-branch origin/main
.venv/bin/python -m build --outdir "$DIST_DIR"
.venv/bin/python scripts/build_alpic_deploy_pack.py \
  --worktree "$PWD" --candidate "$CANDIDATE_COMMIT" \
  --output-dir "$DEPLOY_PACK"
```

Expected: all receipts and artifacts bind the same clean commit/tree. Any drift
returns the candidate to `do_not_release`.

### Task 4: Use the Existing Protected Workflow and Obtain the Release Decision

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

- Signed `ProtectedControllerProvisioningReceipt` covering all existing 13
  operations and four launcher commands.
- Absolute digest-verified protected launcher, policy, trust root, credential
  broker, network broker, and custody authority.
- Authorized Auth0/Alpic staging configuration with exact project,
  environment, callback, DCR pool, canonical base URL, and MCP URL.
- Separate authorization for staging deployment, attestation commit, custody,
  cleanup, and any Production deployment.

If any prerequisite is missing or mismatched, stop with
`PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE` or the exact provider blocker. Do
not replace it with candidate code.

- [ ] **Step 1: Run the existing candidate-to-staging DAG**

Use the exact `initialize-run`, `run-through --through
candidate-bundle-custody`, and descriptor-selected `resume-run` commands already
specified in Phase 8 / Task 22. Do not change operation IDs or reconstruct a
recovery action from shell state.

The protected staging proof must bind the exact deploy pack, environment,
deployment, runtime, three-tool catalog, OAuth Protected classification,
complete DCR authorization-code/PKCE flow, Host/Origin behavior, negative auth
cases, Alpic audit/Beacon dispositions, privacy settings, and final environment
recapture. A missing full `sourceCommitId` remains an explicit blocker unless
the protected upload receipt and runtime identity independently bind the exact
pack.

The protected result must emit a supported `AlpicHostedOAuthVerdict` bound to
the exact candidate, staging environment, callback, pool, public/backend issuer
routes, and flow transcript. Eligibility joins that result with the pre-deploy
`OAuthProviderCapabilityVerdict`; either unsupported branch preserves
`OAUTH_END_TO_END_FLOW_UNPROVEN` and blocks recommendation.

- [ ] **Step 2: Independently assess all 253 selected ASVS rows**

Use `Pass` only with current candidate-bound evidence and governed `N/A` only
with reviewed absence proof. `Not assessed`, `Fail`, `Partial`, expired
evidence, or ungoverned `N/A` prevents a positive recommendation.

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
Production project/environment/deployment, candidate/tree/pack, OAuth/DCR
result, three-tool catalog, audit/privacy checks, post-deploy health, rollback
target, and approval identity.

If that authority or evidence contract is unavailable, stop at
`release_recommended`; do not add controller operations here. Only a verified
positive Production receipt may change the externally reported status to
`released`.

Registry publication is intentionally excluded. If later requested, write a
small separate plan for the one authorized publication action and verification.

## Completion Gate

The MCP is release-ready only when Tasks 1-3 pass for one immutable candidate
and Task 4 produces a signed, custodied, blocker-free recommendation. It is
actually `released` only after the separate Production authority returns and
the release owner verifies the positive Production receipt. Until then, report
the exact truthful state—`do_not_release` or `release_recommended`—without
claiming publication.
