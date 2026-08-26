# Alpic MCP Release Finalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the `alpic-metadata` MCP profile from a truthful
`do_not_release` candidate into a strictly typed, OWASP ASVS 5.0.0 Level 2,
evidence-backed Alpic release without weakening a gate or fabricating external
authority.

**Architecture:** Keep the implemented Phase 0-8 application architecture and
finish only the missing release path. First repair the candidate-side ASVS and
release-command contracts, then make the Alpic build/evidence boundary
deterministic, activate provider-bound OAuth only after exact Auth0/Alpic
evidence exists, freeze one immutable candidate, and hand that candidate to a
separately protected controller for deployment, custody, attestation, and the
final decision. Candidate code may validate evidence and request structures;
it may never grant itself credentials, approval, custody, or release status.

**Tech Stack:** CPython 3.12-3.14 with Python 3.13 on Alpic,
`mcp==2.0.0`, Pydantic 2.13.4 strict models, PyJWT 2.13.0 and
cryptography 50.0.0 only after the signed-JWT provider gate passes, Node
24.19.0, TypeScript 6.0.3, Zod 4.4.3, ESLint 10, Ruff, strict mypy, strict
Pyright, pytest, Hypothesis, mutmut, Bandit, Semgrep, pip-audit, CycloneDX,
Trivy, and the Alpic CLI/SDK/API 1.169.1 tool family.

**Spec:** `docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md`

**Successor scope:** This plan supersedes only the unfinished and internally
inconsistent release-closure portions of Tasks 20-22. It does not reopen the
completed application migration, parser, downloader, storage, PDF, profile, or
MCP contract work.

## Global Constraints

- Release target: `DeploymentProfile.ALPIC_METADATA` only.
- Application-owned MCP surface: `search_documents`,
  `get_document_metadata`, and `list_document_files`; the application registers
  no MCP resources, asset handler, PDF execution, artifact persistence, or
  custom REST endpoint in this profile. Separately inventory Alpic-owned `/`,
  `/mcp`, `/try`, `/assets`, and conditional OAuth/DCR routes rather than
  treating provider-owned routes as application handlers.
- `private-full` is not an Alpic release target in this plan.
- `distributed-full` and the experimental MCP Tasks extension remain startup
  blocked; this plan does not implement or advertise Tasks.
- Runtime validation is Pydantic with
  `ConfigDict(extra="forbid", frozen=True, strict=True)` and strict JSON
  validation after duplicate-key, non-finite-number, malformed UTF-8, and
  invalid-Unicode rejection.
- Cross-language validation is Zod 4.4.3 using `z.strictObject`, closed enums,
  `z.discriminatedUnion`, code-point-aware string bounds, and the same accepted
  and rejected corpus as Pydantic.
- Do not use `Any`, coercive parsing, unbounded strings or arrays, raw argv
  passthrough, arbitrary environment injection, shell execution, unknown
  options, token-shape sniffing, ID-token acceptance, or opaque-token fallback.
- Keep TypeScript at 6.0.3. TypeScript 7 and unrelated dependency upgrades are
  outside this plan.
- Pin `alpic`, `@alpic-ai/sdk`, and `@alpic-ai/api` to exactly 1.169.1, the
  registry versions observed on 2026-08-26. Re-check those three versions as
  one atomic family immediately before implementation; any change requires an
  explicit plan amendment and lock review.
- Keep Zod at exactly 4.4.3, the latest registry version observed on
  2026-08-26.
- Treat Auth0 plus the Alpic DCR proxy as the selected first-release topology.
  Record CIMD/DCR behavior as observed evidence; do not infer it from generic
  provider documentation.
- Never put an API key, bearer token, OAuth client secret, signing key, raw JWT,
  credential-file path, or secret value in Git, argv, request JSON, evidence,
  logs, test output, or the candidate process environment.
- Runtime Alpic environment changes invalidate the captured environment proof.
  Recapture immediately before finalization and redeploy whenever the current
  platform behavior requires it.
- A passing candidate-side validator is not protected-controller,
  provider-hosted, ASVS-review, custody, deployment, publication, or release
  evidence.
- Preserve the existing Git index. Do not stage, unstage, reset, stash, clean,
  commit, push, deploy, change an Alpic/Auth0 setting, publish, sign, or invoke a
  protected controller without the separate explicit authorization named by
  the applicable step.
- Implementation work stays unstaged until the user explicitly authorizes a
  precise staging or commit operation.
- Every code task follows witnessed RED, minimal GREEN, explicit REFACTOR or
  no-refactor decision, focused rerun, adversarial/property coverage, and the
  applicable mutation gate.
- An interrupted, timed-out, truncated, or missing authoritative command has
  status `incomplete`; it is never counted as PASS.
- The release verdict stays `do_not_release` whenever any required local,
  provider, controller, hosted, custody, ASVS, production, or authorization
  gate is missing. If a remote write has already occurred, also report its
  exact observed/reconciliation state; a negative verdict does not erase the
  external fact.

## Planning Baseline

The read-only planning snapshot before this file was created was:

```text
branch: main
HEAD: 377e70203de8ef5706664bd305d43680451aa744
staged paths: 152
unstaged paths: 0
untracked paths: 0
staged diff bytes: 2349825
staged diff SHA-256: 7c15bfb5b2bcedc614407bdd3384b702ac1a6e09fc6c73ede4691849eec1a5e2
```

The new plan file itself is intentionally left unstaged. At execution start,
record a fresh status and index digest; do not require the planning hash to
remain current and do not alter pre-existing staged entries.

## Authoritative Alpic Inputs

- [Build configuration and transport detection](https://docs.alpic.ai/build-deploy/builds)
- [Live `alpic.json` schema](https://assets.alpic.ai/alpic.json)
- [Deployment troubleshooting and OAuth classification](https://docs.alpic.ai/troubleshooting)
- [OAuth setup](https://docs.alpic.ai/secure/auth/oauth-setup)
- [OAuth providers](https://docs.alpic.ai/secure/auth/oauth-providers)
- [Alpic DCR proxy](https://docs.alpic.ai/secure/auth/dcr-proxy)
- [Environments and environment variables](https://docs.alpic.ai/build-deploy/environments)
- [Audit and Beacon](https://docs.alpic.ai/testing/beacon)
- [Endpoint shapes](https://docs.alpic.ai/build-deploy/endpoints)
- [Submitted-version behavior](https://docs.alpic.ai/distribution/versioning)
- [MCP Registry publication](https://docs.alpic.ai/distribution/registry)

The live schema reviewed on 2026-08-26 has
`additionalProperties: false` and explicitly permits
`transportType` values `stdio`, `sse`, and `streamablehttp`. The current
project uses the low-level `Server.streamable_http_app(...)`, which is not one
of Alpic's documented Python auto-detection examples. Therefore the candidate
must declare `"transportType": "streamablehttp"` explicitly.

## Release State Machine

| State | Entry condition | Permitted next state |
| --- | --- | --- |
| `do_not_release` | Default; any gate missing | `candidate_qualified` |
| `candidate_qualified` | Immutable clean commit and all local gates PASS | `staging_proven` |
| `staging_proven` | Protected non-production Alpic proof is complete and custodied | `release_authorized` |
| `release_authorized` | Independent ASVS L2 review and signed eligibility are positive | `released` |
| `released` | Exact candidate is deployed to Production and post-deploy checks PASS | `published` or remain `released` |
| `published` | Separately authorized MCP Registry publication is verified | terminal |

Any drift, expiry, failed check, ambiguous evidence, or subject mismatch moves
the decision back to `do_not_release`. Candidate code cannot write a positive
transition.

## Authority Matrix

| Action | Authority required |
| --- | --- |
| Edit and test candidate files locally | Approval to execute this plan |
| Stage or commit any path | Separate explicit Git authorization with exact paths |
| Read a named Auth0 tenant or Alpic environment | Authorized account access and exact target confirmation |
| Change Auth0/Alpic configuration or secrets | Separate explicit configuration authorization |
| Deploy to non-production Alpic | Separate explicit staging-deploy authorization |
| Run the protected controller or upload custody evidence | Protected authority plus operation-specific approval |
| Deploy to Production | Separate explicit production-deploy authorization |
| Publish to the MCP Registry | Separate explicit publication authorization |

## File Responsibility Map

| Responsibility | Files |
| --- | --- |
| ASVS assessment and release evaluation | `scripts/build_asvs_matrix.py`, `docs/security/asvs-evidence-policy.json`, `contracts/zod/asvs-evidence-contracts.mjs` |
| Candidate-side protected-command expectation | `scripts/verify_release.py`, `security/release-command-manifests.json`, `contracts/zod/release-command-contracts.mjs` |
| Alpic build contract and tool locks | `alpic.json`, `package.json`, `package-lock.json`, `security/toolchain-lock.json`, `deploy/alpic-runtime-manifest.json` |
| Candidate-safe Alpic evidence parsing | `scripts/capture_alpic_deployment.ts`, `scripts/verify_deploy.py`, `scripts/run_alpic_staging_proof.py` |
| Provider capability | `contracts/oauth-provider-capability.json`, `contracts/alpic-oauth-discovery-capability.json`, `contracts/alpic-dcr-flow-capability.json`, `contracts/oidc-subject-capability.json`, `src/nplg_mcp/capabilities.py` |
| Runtime OAuth and audit | `src/nplg_mcp/auth.py`, `src/nplg_mcp/audit.py`, `src/nplg_mcp/config.py`, `src/nplg_mcp/app.py`, `src/nplg_mcp/http_security.py` |
| Hosted evidence descriptors | `deploy/alpic-environment-manifest.json`, `deploy/alpic-audit-dispositions.json`, `deploy/alpic-submission-versions.json` |
| Independent attestation | `docs/security/asvs-5.0.0-l2-matrix.jsonl`, `docs/security/evidence-manifest.jsonl`, `docs/security/threat-model.json`, `docs/verification/2026-08-26-alpic-release-candidate.md` |

---

### Task 1: Make ASVS L2 Assessment Structurally Possible

The current checker correctly validates the bootstrap inventory but cannot
accept a completed assessment: it requires the unassessed matrix and empty
evidence manifest, and `verify_claim_binding()` rejects every N/A absence
proof. Repair this before collecting release evidence.

**Files:**

- Modify: `docs/security/asvs-5.0.0-l2-method.md`
- Modify: `docs/security/asvs-evidence-policy.json`
- Modify: `scripts/build_asvs_matrix.py:1592`
- Modify: `scripts/build_asvs_matrix.py:3391`
- Modify: `scripts/build_asvs_matrix.py:4505`
- Modify: `contracts/zod/asvs-evidence-contracts.mjs`
- Modify: `tests/unit/test_build_asvs_matrix.py`
- Modify: `tests/property/test_asvs_evidence.py`
- Modify: `tests/static/test_asvs_evidence.py`
- Modify: `tests/contracts/zod_asvs_evidence_contracts.test.mjs`
- Modify if required by the exact mutation inventory:
  `scripts/run_mutation_gate.py`, `tests/unit/test_mutation_gate.py`

**Interfaces:**

- Consumes: the existing deterministic 759-row ASVS 5.0.0 L2 inventory,
  evidence policy, canonical evidence manifest, and candidate identity types.
- Produces:

```python
AssessmentMode = Literal["bootstrap", "candidate"]
ClaimPurpose = Literal["implementation-proof", "absence-proof"]

def verify_claim_binding(
    claim: AsvsClaim,
    evidence: tuple[EvidenceRecord, ...],
    *,
    mode: AssessmentMode,
) -> None: ...

def evaluate_profile_release(
    rows: tuple[AsvsMatrixRow, ...],
    evidence: tuple[EvidenceRecord, ...],
    *,
    profile: Literal["alpic-metadata"],
    candidate: CandidateIdentity,
) -> ProfileReleaseVerdict: ...
```

- `bootstrap` accepts only the exact deterministic `Not assessed` inventory
  and empty evidence manifest.
- `candidate` requires every one of the 253 `alpic-metadata` rows to be
  candidate-bound and independently verified as `Pass` or governed `N/A`.
- `N/A` is accepted only with `claim_purpose="absence-proof"`, an approved
  applicability authority, and evidence that proves non-construction or
  non-applicability for the exact candidate.
- `Fail`, `Partial`, `Risk accepted`, `Not assessed`, expired evidence,
  ungoverned N/A, missing selectors, replay, wrong candidate, and wrong profile
  always make the release verdict negative.
- The protected attestation allowlist includes
  `docs/security/asvs-evidence-policy.json` and
  `docs/security/threat-model.json` in addition to the matrix, evidence
  manifest, Markdown threat model, SECURITY file, and release-candidate report.

- [ ] **Step 1: Write the failing Python and Zod tests**

Add focused cases equivalent to:

```python
def test_candidate_mode_accepts_only_verified_pass_or_governed_na() -> None:
    rows, evidence, candidate = assessed_metadata_fixture()
    verdict = evaluate_profile_release(
        rows,
        evidence,
        profile="alpic-metadata",
        candidate=candidate,
    )
    assert verdict.passed is True
    assert verdict.blockers == ()


def test_na_without_absence_proof_is_rejected() -> None:
    rows, evidence, candidate = ungoverned_na_fixture()
    with pytest.raises(AsvsEvidenceError, match="absence-proof"):
        evaluate_profile_release(
            rows,
            evidence,
            profile="alpic-metadata",
            candidate=candidate,
        )
```

Add Zod parity cases for valid `Pass`, valid governed `N/A`, unknown fields,
duplicate keys, non-finite numbers, wrong candidate/profile, expired evidence,
reordered evidence, duplicate evidence IDs, and unsupported verdict strings.

- [ ] **Step 2: Observe the relevant RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider \
  tests/static/test_asvs_evidence.py \
  tests/property/test_asvs_evidence.py \
  tests/unit/test_build_asvs_matrix.py -q
npm run test:contracts:asvs
```

Expected: collection succeeds; the new candidate-assessment and governed-N/A
tests fail because only bootstrap mode is accepted. A missing fixture, import
error, or test setup failure is not the required RED.

- [ ] **Step 3: Implement the two-mode contract minimally**

Keep the bootstrap branch byte-for-byte strict. Add a separately selected
candidate branch, strict Pydantic and Zod discriminators, exact candidate and
profile joins, evidence expiry/custody checks, and governed absence-proof
handling. Do not add a permissive shared branch or default assessment mode.

- [ ] **Step 4: Observe focused GREEN**

Run the Step 2 commands again.

Expected: all focused Python and Zod cases PASS; bootstrap output remains the
same; candidate evaluation is positive only for the fully bound fixture.

- [ ] **Step 5: Prove adversarial and mutation sensitivity**

Add Hypothesis coverage for evidence ordering, duplicate IDs, boundary dates,
profile/candidate swaps, Unicode identifiers, and arbitrary extra fields. Add
the exact new decision functions to the governed mutation inventory rather
than broadening the target implicitly.

Run:

```bash
.venv/bin/python scripts/run_mutation_gate.py \
  --targets scripts/build_asvs_matrix.py
.venv/bin/python scripts/run_quality_gate.py \
  --node-executable "$(command -v node)" \
  scripts/build_asvs_matrix.py tests contracts/zod
```

Expected: the registered mutations for mode selection, N/A governance,
candidate/profile binding, expiry, and blocker aggregation are killed; strict
Ruff, mypy, Pyright, ESLint, and TypeScript checks PASS.

- [ ] **Step 6: Record the no-refactor or refactor decision**

If the bootstrap and candidate branches cannot be reviewed independently,
extract focused pure evaluators without changing their public contracts. Run
Steps 2, 4, and 5 again. Leave every edit unstaged.

### Task 2: Replace Conflicting Release CLI Grammars with One Typed Request Family

The manifest currently describes four launcher JSON options while each of the
thirteen staging-era operations describes a different expanded argv shape. It
also has no production or publication operations, and the plan contains a
legacy Alpic passthrough form. Replace those competing grammars with one
request-file family, expand the closed DAG to the twenty-seven operations needed
through optional publication, and make authorization and recovery timing
explicit.

**Files:**

- Modify: `scripts/verify_release.py:981`
- Modify: `scripts/verify_release.py:1549`
- Modify: `scripts/verify_release.py:2653`
- Modify: `security/release-command-manifests.json`
- Create: `contracts/zod/release-command-contracts.mjs`
- Create: `tests/contracts/zod_release_command_contracts.test.mjs`
- Modify: `tests/static/test_release_gate.py`
- Modify: `package.json`
- Modify: `tsconfig.contracts.json`
- Modify: `eslint.config.mjs`
- Modify: `scripts/run_mutation_gate.py`
- Modify: `tests/unit/test_mutation_gate.py`
- Modify: `deploy/ALPIC.md`
- Modify: `docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md`
  only to add the successor pointer and remove the superseded Task 21-22 CLI
  examples; do not rewrite completed phases.

**Interfaces:**

- Consumes: `ReleaseCommandManifest`, `ExternalGateRegistry`, the existing
  duplicate-key/non-finite JSON precheck, and immutable candidate/controller
  digests.
- Produces:

```python
AuthorizationTiming = Literal[
    "not-required",
    "run-initialization",
    "fresh-human-action",
    "descriptor-selected-recovery-with-fresh-read-approval",
]

ReleaseCommandRequest = Annotated[
    InitializeRunRequest
    | RunOperationRequest
    | RunThroughRequest
    | ResumeRunRequest
    | ValidateOutputParentRequest
    | ValidateOutputParentsRequest
    | CaptureAlpicRequest,
    Field(discriminator="request_type"),
]

def parse_release_command_request(
    payload: bytes,
    *,
    manifest: ReleaseCommandManifest,
    registry: ExternalGateRegistry,
) -> ReleaseCommandRequest: ...

def validate_release_command_request(
    request: ReleaseCommandRequest,
    *,
    manifest: ReleaseCommandManifest,
    registry: ExternalGateRegistry,
) -> None: ...
```

- Every request has `schema_id="nplg.release-command-request.v1"`, a literal
  `request_type`, release profile, candidate commit, candidate tree digest,
  command-manifest digest, controller-policy digest, and run identifier.
- `RunOperationRequest.operation` is a discriminated union on the exact
  twenty-seven operation IDs. Operation payloads contain only closed logical
  artifact identifiers and digests; they contain no executable, argv,
  environment, credential, signature, secret, or arbitrary object.
- `RunThroughRequest` names a manifest-defined contiguous start/end pair and
  must stop before every `fresh-human-action` node.
- `custody` accepts only the closed subject kinds `candidate-bundle`,
  `final-decision-chain`, `production-release-chain`, and `publication-chain`;
  each request binds the exact predecessor and inventory digest.
- `ResumeRunRequest` carries only the signed descriptor/recovery references.
  The caller cannot select an operation, output path, new payload, or new
  attempt.
- `CaptureAlpicRequest` uses a reviewed logical action selector, protected tool
  descriptor digest, bounded timeout, bounded output size, and logical output
  IDs. It has no raw `ALPIC_ARGS`, passthrough tail, shell fragment, environment
  object, or secret-bearing option.
- Each external-gate request resolves to exactly one existing
  read-only `security/external-test-gates.json` entry; do not duplicate the
  registry into another hard-coded list. The registry marks
  `alpic-metadata.oauth-dcr-flow` as side-effecting, so the generic variant
  rejects it and only `dcr-flow-proof` may resolve that entry.
- The candidate CLI adds only:

```text
verify_release.py validate-command-request --worktree PATH --request PATH
```

  This command is read-only, executes no controller or Alpic command, writes no
  artifact, and cannot return release authorization.

- Expected external launcher commands and read-only utilities accept one
  `--request PATH`. A separately protected `--approval-receipt PATH` is
  required only at the authorization edge selected below; it is never embedded
  in candidate JSON.

The exact operation inventory is:

```text
candidate-battery
external-gate
prepare
staging-deploy
reconcile-staging-deploy
auth-provision
reconcile-auth-provision
dcr-flow-proof
reconcile-dcr-flow
staging-proof
finalize
custody
reconcile-custody
attestation-workspace
commit-attestation
attest
eligibility
production-deploy
reconcile-production
production-proof
rollback-production
reconcile-rollback
release-decision
publish-registry
reconcile-publication
cleanup-run
reconcile-cleanup
```

Authorization timing is fixed as follows:

| Command or operation | Timing |
| --- | --- |
| `initialize-run` | `run-initialization` |
| `candidate-battery`, `prepare`, `finalize`, `attestation-workspace`, `attest`, `eligibility` | `not-required` |
| `external-gate`, `staging-deploy`, `auth-provision`, `dcr-flow-proof`, `staging-proof`, `custody`, `commit-attestation`, `production-deploy`, `production-proof`, `rollback-production`, `release-decision`, `publish-registry`, `cleanup-run` | `fresh-human-action` |
| `reconcile-staging-deploy`, `reconcile-auth-provision`, `reconcile-dcr-flow`, `reconcile-custody`, `reconcile-production`, `reconcile-rollback`, `reconcile-publication`, `reconcile-cleanup` | `descriptor-selected-recovery-with-fresh-read-approval` |

Exit 20, exit 75, or a process death after a durably published attempt intent
selects only the descriptor-declared reconciliation operation. Reconciliation
still requires a fresh, operation-specific read approval; the caller cannot
alter the intent. Exits 21 and 22 prove pre-side-effect failure or reconciled
absence and permit only a separately approved new attempt bound to the signed
predecessor. Exit 23 is terminal for retry purposes and never grants authority.

The added auth, production, release, and publication operations have exact
result schemas:

```text
AuthProvisionResult.v1
AuthProvisionReconciliationResult.v1
DcrFlowProofResult.v1
DcrFlowReconciliationResult.v1
StagingDeploymentResult.v1
StagingDeploymentReconciliationResult.v1
StagingProofResult.v1
ProductionDeploymentResult.v1
ProductionReconciliationResult.v1
ProductionProofResult.v1
ProductionRollbackResult.v1
ProductionRollbackReconciliationResult.v1
RegistryPublicationResult.v1
RegistryPublicationReconciliationResult.v1
ReleaseDecisionResult.v1
CleanupResult.v1
CleanupReconciliationResult.v1
```

`production-deploy`, `rollback-production`, and `publish-registry` may emit
delivery-unknown state only after durably recording the matching reconciliation
edge. `production-proof` is read-only but requires explicit production-test
authorization. Rollback is never inferred from a failed proof; it requires its
own exact target and fresh approval.

`dcr-flow-proof` is explicitly side-effecting. Before registration it durably
records environment, pool, callback, candidate, correlation/idempotency
material, bounded client count, and lifecycle policy. Its result identifies
every created registration without exposing a secret. Exit 20, exit 75, or
process death selects only `reconcile-dcr-flow`, which uses protected
provider/Auth0 read authority and the durable broker journal to prove issued,
absent, or still ambiguous state. Ambiguity is terminal and forbids blind
retry. The operation creates at most one test registration; rotation is proven
from separately authorized lifecycle evidence, not by spraying clients.

`cleanup-run` acts only on the descriptor's closed ephemeral inventory and
cannot delete an active Production deployment, provider configuration, release
evidence, or custody object. Delivery-unknown cleanup selects only
`reconcile-cleanup`; retained provider objects require exact owner, expiry, and
disposition or remain release blockers.

- [ ] **Step 1: Write Python RED tests for the request family**

Add cases equivalent to:

```python
def test_operation_request_rejects_raw_argv() -> None:
    payload = valid_operation_request() | {"argv": ["alpic", "publish"]}
    with pytest.raises(ReleaseVerificationError):
        parse_release_command_request(
            canonical_json_bytes(payload),
            manifest=manifest(),
            registry=registry(),
        )


def test_resume_cannot_select_a_new_operation() -> None:
    payload = valid_resume_request() | {"operation_id": "staging-deploy"}
    with pytest.raises(ReleaseVerificationError):
        parse_release_command_request(
            canonical_json_bytes(payload),
            manifest=manifest(),
            registry=registry(),
        )
```

Cover all seven request variants, twenty-seven operations, four launcher
commands, three utilities, and every registered external gate through its exact
read-only or DCR operation kind. Reject duplicate
keys, `NaN`/`Infinity`, floats in integer fields, coercion, unknown fields,
unknown discriminators, malformed UTF-8, unpaired surrogates, reordered or
duplicate inventories, cross-profile requests, candidate/tree/manifest/policy
mismatches, raw paths in operation payloads, stale/reused approval references,
concurrent retries, and wrong result schema IDs.

For every configuration, DCR registration, deployment, custody, rollback,
decision, publication, and cleanup operation, inject failure before intent,
after durable intent but before provider call, delivery-unknown, reconciled
absence, reconciled success, conflicting read-back, approval expiry/reuse, and
process death. The tests must prove the exact 20/21/22/23/24/75 semantics and
that no recovery edge silently becomes new write authority.

- [ ] **Step 2: Write the Zod parity RED corpus**

Create strict schemas and a table-driven corpus that feeds identical bytes to
Pydantic and Zod. Every case must yield the same accept/reject result and the
same normalized non-secret JSON for accepted cases.

Add scripts:

```json
{
  "contracts:release-command-zod": "node --test tests/contracts/zod_release_command_contracts.test.mjs"
}
```

Include the new files in `contracts:zod:all`, `contracts:lint`,
`contracts:typecheck`, and `contracts:baseline-static`.

- [ ] **Step 3: Observe the relevant RED**

Run:

```bash
.venv/bin/python -m pytest \
  tests/static/test_release_gate.py \
  tests/unit/test_mutation_gate.py -q
npm run contracts:release-command-zod
npm run contracts:typecheck
npm run contracts:lint
```

Expected: collection and existing cases PASS; the new request-model, parser,
approval-timing, and Zod cases fail because the family is absent. A protected
command must not run.

- [ ] **Step 4: Implement the minimal closed models and manifest join**

Use the existing byte precheck, then:

```python
adapter = TypeAdapter(ReleaseCommandRequest)
request = adapter.validate_json(payload, strict=True)
validate_release_command_request(
    request,
    manifest=manifest,
    registry=registry,
)
```

Add `request_family` to the manifest with the literal schema ID,
`executor="separately-protected-external"`, and
`candidate_execution=false`. Remove every conflicting expanded public argv
contract and the legacy `--alpic-args-json` passthrough shape. Replace the
superseded examples in the old plan with the exact request-file commands from
this task so the repository contains no second operational grammar.

- [ ] **Step 5: Observe focused GREEN and mutation sensitivity**

Run:

```bash
.venv/bin/python -m pytest \
  tests/static/test_release_gate.py \
  tests/unit/test_mutation_gate.py -q
npm run contracts:release-command-zod
npm run contracts:zod:all
npm run contracts:typecheck
npm run contracts:lint
npm run contracts:baseline-static
.venv/bin/python scripts/run_mutation_gate.py \
  --targets scripts/verify_release.py
```

Expected: all request, parity, recovery, approval, and mutation gates PASS;
the manifest terminal verdict remains `do_not_release` and the external
controller remains unconfigured.

- [ ] **Step 6: Refactor only if the request variants cannot be reviewed alone**

Extract private pure validators without moving the public request family out of
`scripts/verify_release.py`, preserving the existing mutation target. Rerun
Step 5 and leave all edits unstaged.

### Task 3: Make the Alpic Build and Toolchain Contract Deterministic

**Files:**

- Modify: `alpic.json`
- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `security/toolchain-lock.json`
- Create: `tsconfig.tools.json`
- Modify: `eslint.config.mjs`
- Create: `deploy/alpic-runtime-manifest.json`
- Modify: `tests/static/test_deployment.py`
- Modify: `deploy/ALPIC.md`
- Modify: `README.md`

**Interfaces:**

- `alpic.json` has exactly the reviewed schema, install, build, start, and
  `transportType` keys; `transportType` is the literal `streamablehttp`.
- `package.json` directly pins `alpic`, `@alpic-ai/sdk`, and
  `@alpic-ai/api` at 1.169.1. The lock records their exact resolved artifacts
  and integrity values.
- `deploy/alpic-runtime-manifest.json` is a strict, duplicate-key-free,
  non-secret record binding Python 3.13, Streamable HTTP, `/mcp`, the install,
  build, and start commands, package-lock digest, toolchain-lock digest, and
  minimal deploy-pack policy.
- `tsconfig.tools.json` includes only the candidate-safe Alpic evidence parser
  and its test. It uses strictest compiler flags and emits no operational CLI.

- [ ] **Step 1: Write the transport and tool-lock RED tests**

Add assertions equivalent to:

```python
def test_alpic_transport_is_explicit_streamable_http() -> None:
    config = load_json(PROJECT_ROOT / "alpic.json")
    assert config["transportType"] == "streamablehttp"
    assert set(config) == {
        "$schema",
        "installCommand",
        "buildCommand",
        "startCommand",
        "transportType",
    }


def test_alpic_tool_family_is_one_exact_version() -> None:
    package = load_json(PROJECT_ROOT / "package.json")
    assert package["devDependencies"]["alpic"] == "1.169.1"
    assert package["devDependencies"]["@alpic-ai/sdk"] == "1.169.1"
    assert package["devDependencies"]["@alpic-ai/api"] == "1.169.1"
```

Also reject command strings over the live schema's 256-character maximum,
unreviewed keys, mismatched Alpic package versions, missing integrity entries,
secret-looking manifest values, and an Alpic `publish` command in the build or
test configuration.

- [ ] **Step 2: Observe RED**

Run:

```bash
.venv/bin/python -m pytest tests/static/test_deployment.py -q
```

Expected: the transport and direct-tool-lock tests fail; existing deployment
tests continue to collect and run.

- [ ] **Step 3: Apply the minimal build-contract change**

The final `alpic.json` shape is:

```json
{
  "$schema": "https://assets.alpic.ai/alpic.json",
  "installCommand": "uv venv --python python3 .venv && uv pip install --python .venv/bin/python --require-hashes --no-deps --only-binary=:all: -r requirements.lock",
  "buildCommand": ".venv/bin/python -m compileall -q src scripts",
  "startCommand": "HOST=0.0.0.0 PYTHONPATH=src .venv/bin/python -m nplg_mcp",
  "transportType": "streamablehttp"
}
```

Add only the three Alpic packages and scripts needed by Task 4. Do not upgrade
TypeScript, ESLint, Node types, Zod, or unrelated dependencies.

Regenerate the npm lock without lifecycle scripts:

```bash
npm install --package-lock-only --ignore-scripts --save-dev --save-exact \
  alpic@1.169.1 @alpic-ai/sdk@1.169.1 @alpic-ai/api@1.169.1
```

- [ ] **Step 4: Install without lifecycle scripts and observe GREEN**

Run:

```bash
npm ci --ignore-scripts
.venv/bin/python -m pytest tests/static/test_deployment.py -q
npm run contracts:lint
npm run contracts:typecheck
.venv/bin/python scripts/run_quality_gate.py \
  --node-executable "$(command -v node)" \
  src tests scripts
```

Expected: exact transport, runtime, package-family, integrity, strict type, and
lint checks PASS. No Alpic command executes.

- [ ] **Step 5: Review generated lock changes and leave them unstaged**

Prove the lock changes contain only the intended Alpic dependency closure and
no lifecycle-script execution. Record the registry queries and version review
date in `security/toolchain-lock.json`. Do not stage or commit.

### Task 4: Complete Candidate-Safe Alpic Evidence Tooling

**Files:**

- Create: `scripts/capture_alpic_deployment.ts`
- Create: `scripts/capture_alpic_deployment.test.ts`
- Create: `scripts/build_alpic_deploy_pack.py`
- Modify: `scripts/verify_deploy.py`
- Create: `scripts/run_alpic_staging_proof.py`
- Modify: `tests/unit/test_verify_deploy.py`
- Create: `tests/unit/test_build_alpic_deploy_pack.py`
- Create: `tests/unit/test_run_alpic_staging_proof.py`
- Create: `tests/deployment/test_edge_http.py`
- Create: `tests/property/test_deployment_evidence_properties.py`
- Create: `deploy/alpic-audit-dispositions.json`
- Create: `deploy/alpic-environment-manifest.json`
- Create: `deploy/alpic-submission-versions.json`
- Modify: `security/external-test-gates.json` only if a genuinely new observed
  gate is required; do not duplicate existing gate facts.
- Modify: `security/coverage-policy.json`
- Modify: `scripts/run_mutation_gate.py`
- Modify: `tests/unit/test_mutation_gate.py`

**Interfaces:**

```typescript
export function parseAlpicDeploymentCapture(
  input: Uint8Array,
): AlpicDeploymentCapture;

export function identifyUniqueDeployment(
  before: AlpicDeploymentCapture,
  after: AlpicDeploymentCapture,
  expected: DeploymentSelector,
): DeploymentIdentity;
```

```python
def build_minimal_deploy_pack(
    *,
    worktree: Path,
    candidate: GitCommit,
    output_dir: Path,
) -> MinimalDeployPackManifest: ...


def verify_runtime_manifest(path: Path) -> AlpicRuntimeManifest: ...

def verify_environment_snapshot(
    path: Path,
    *,
    expected: AlpicDeploymentIdentity,
) -> AlpicEnvironmentManifest: ...

def build_staging_deployment_result(
    inputs: StagingDeploymentInputs,
) -> StagingDeploymentResult: ...

def build_staging_proof(
    inputs: StagingProofInputs,
) -> StagingProofResult: ...
```

The builder CLI is fixed and writes only to an absolute, previously absent
directory:

```text
build_alpic_deploy_pack.py --worktree PATH --candidate SHA40 --output-dir PATH
```

- TypeScript parses only injected, bounded, pinned-format JSON captures. It
  performs no network access, reads no ambient credential, and executes no
  Alpic command.
- A deployment identity is accepted only when exactly one new successful
  deployment belongs to the exact project and environment. Provider
  `sourceCommitId` is modeled as either an exact provider-bound SHA-40 or
  `unavailable`; the human inspect command's truncated identifier is never
  upgraded to proof. `unavailable` preserves
  `SOURCE_COMMIT_BINDING_UNPROVEN` until the protected upload receipt,
  creation correlation, and runtime manifest independently bind the exact
  minimal deploy-pack digest and deployment ID. Zero, multiple, stale, failed,
  truncated-as-full, or ambiguous candidates fail closed.
- The minimal deploy-pack builder materializes only the clean committed tree,
  includes an explicit allowlist, rejects symlinks and secret/config artifacts,
  and emits canonical file/digest/mode metadata. It executes no project code,
  package manager, network, or Alpic command.
- `AlpicEnvironmentManifest` stores key names, secret/non-secret classification,
  presence, project/environment/deployment IDs, capture time, and source
  identity; it never stores values or unkeyed secret-value hashes. The
  protected authority signs one canonical redacted-manifest commitment. The
  protected capture supplies the exact aggregate encoded-byte count, and the
  verifier rejects an environment over Alpic's documented 4 KiB total.
- `AlpicAuditDisposition` binds every error, warning, and skip by stable check
  ID to `fixed`, `governed-exception`, or `release-blocker`. A zero audit exit
  does not erase warnings or skips.
- `AlpicSubmissionVersion` binds environment URL, deployment ID, candidate,
  `tools/list` digest, and submission/version identity so host caching cannot
  silently mix schemas.
- `StagingDeploymentResult` joins only upload, runtime, environment, deployment,
  and source-binding evidence. The `staging-deploy` operation produces it
  before OAuth provisioning and it cannot set `staging_proven`.
- `StagingProofResult` is a distinct post-provision result produced by the later
  `staging-proof` operation. It joins the deployment result with signed Auth0,
  staging discovery/DCR, endpoint, audit, version, negative-test, and blocker
  evidence. It cannot be positive if an input is missing or if the final
  environment recapture differs from the pre-deploy snapshot.

- [ ] **Step 1: Write parser, identity, drift, and secret RED tests**

Cover valid captures plus duplicate keys, non-finite values, invalid UTF-8,
oversize output, truncation, unknown fields, multiple deployments, wrong
project/environment, exact SHA-40 and unavailable source IDs, truncated IDs
misrepresented as full proof, stale deployment, clock rollback, future
timestamps, repeated audit IDs, missing dispositions, env-value material,
unkeyed secret commitments, secret-shaped strings, deploy-pack path traversal,
symlinks, unexpected files/modes, and post-deploy environment drift.

Add a TypeScript case equivalent to:

```typescript
assert.throws(
  () => parseAlpicDeploymentCapture(
    new TextEncoder().encode('{"deployments":[],"deployments":[]}'),
  ),
  /duplicate/i,
);
```

- [ ] **Step 2: Observe RED**

Run:

```bash
.venv/bin/python -m pytest \
  tests/unit/test_verify_deploy.py \
  tests/unit/test_build_alpic_deploy_pack.py \
  tests/unit/test_run_alpic_staging_proof.py \
  tests/static/test_deployment.py \
  tests/deployment/test_edge_http.py \
  tests/property/test_deployment_evidence_properties.py -q
npm run deployment:evidence:typecheck
npm run deployment:evidence:test
```

Expected: collection and type checking succeed after minimal test scaffolding;
the parser, unique-deployment, manifest-join, and drift assertions fail because
their implementations are absent. No network or Alpic command runs.

- [ ] **Step 3: Implement bounded parsing and deterministic joins**

Add npm scripts:

```json
{
  "deployment:evidence:lint": "eslint --max-warnings 0 scripts/capture_alpic_deployment.ts scripts/capture_alpic_deployment.test.ts",
  "deployment:evidence:typecheck": "tsc --project tsconfig.tools.json --noEmit",
  "deployment:evidence:test": "node --test scripts/capture_alpic_deployment.test.ts"
}
```

Use strict Pydantic models in Python and strict Zod schemas in TypeScript.
Bound capture size before parsing, use full identifiers, sort only where the
contract declares order-insensitivity, and preserve every blocker.

- [ ] **Step 4: Observe focused GREEN**

Run the Step 2 commands plus:

```bash
npm run deployment:evidence:lint
```

Expected: deterministic parser, identity, manifest, edge fixture, drift, and
negative cases PASS without network access.

- [ ] **Step 5: Prove properties and mutations**

Run:

```bash
.venv/bin/python scripts/run_mutation_gate.py \
  --targets scripts/build_alpic_deploy_pack.py scripts/verify_deploy.py \
  scripts/run_alpic_staging_proof.py
.venv/bin/python scripts/run_quality_gate.py \
  --node-executable "$(command -v node)" src tests scripts
```

Expected: mutations in uniqueness, project/environment binding, honest
source-identity handling, secret rejection, warning disposition, final
recapture, and blocker propagation are killed; strict Python and TypeScript
gates PASS.

- [ ] **Step 6: Document the operator boundary**

Update `deploy/ALPIC.md` to state that these modules parse injected evidence
only. The protected controller owns the exact logical Alpic action vocabulary,
the vetted 1.169.1 argv mapping, credentials, network, environment changes,
deployment, and capture. Leave edits unstaged.

### Task 5: Bind the Auth0 Tenant and Activate Minimal Metadata OAuth

**Pre-deploy evidence prerequisite:** Do not write the positive runtime branch
until authorized, candidate-independent Auth0 evidence names the exact tenant
and API and proves byte-exact issuer/discovery, authorization/token endpoints,
JWKS URL, resource/audience, signed-JWT access-token format, algorithm set,
token-purpose and client-identity claims, stable subject semantics, scopes,
token lifetime, and PKCE S256. Generic Auth0 or Alpic documentation is not
that evidence. This pre-deploy capability intentionally does not claim an
Alpic environment, DCR pool, callback, public-edge rewrite, or completed MCP
authorization flow.

The Alpic discovery and DCR-flow contracts remain strict unsupported verdicts
through local runtime implementation. They can become supported only after
Task 7 deploys a server, Alpic classifies it as Protected, an explicitly
authorized operator configures the environment-specific DCR pool and callback,
and the protected controller witnesses the complete flow. If the Auth0
provider remains unsupported or uses an opaque token, stop before runtime
implementation. If hosted DCR or public/backend issuer semantics remain
ambiguous, local runtime tests may pass but staging/release remains
`do_not_release`.

**Files:**

- Modify after the prerequisite passes:
  `contracts/oauth-provider-capability.json`
- Modify schema/tests but retain a negative checked-in verdict until Task 7:
  `contracts/alpic-oauth-discovery-capability.json`
- Create with a negative checked-in verdict:
  `contracts/alpic-dcr-flow-capability.json`
- Create: `contracts/oidc-subject-capability.json`
- Modify: `contracts/sdk-authorization-capability.json`
- Modify after explicit coarse-scope policy approval:
  `contracts/accepted-sdk-differences.json`
- Modify: `src/nplg_mcp/capabilities.py`
- Create: `src/nplg_mcp/auth.py`
- Create: `src/nplg_mcp/audit.py`
- Modify: `src/nplg_mcp/config.py`
- Modify: `src/nplg_mcp/app.py`
- Modify: `src/nplg_mcp/http_security.py`
- Modify: `src/nplg_mcp/network.py`
- Modify: `src/nplg_mcp/mcp_server.py`
- Modify: `src/nplg_mcp/sdk_boundary.py`
- Modify: `src/nplg_mcp/admission.py`
- Modify: `src/nplg_mcp/errors.py`
- Modify: `.env.example`
- Modify: `requirements.in`, `requirements.lock`, `pyproject.toml`
- Create: `security/crypto-policy.json`
- Create: `docs/security/data-inventory.md`
- Create: `docs/security/cryptographic-inventory.json`
- Create: `docs/security/logging-inventory.json`
- Modify after explicit coarse-scope policy approval:
  `docs/architecture/2026-08-14-official-python-sdk-adr.md`
- Modify after explicit coarse-scope policy approval:
  `docs/security/threat-model.json`, `docs/security/threat-model.md`
- Create: `tests/security/test_auth.py`
- Create: `tests/security/test_audit.py`
- Create: `tests/property/test_auth_properties.py`
- Create: `tests/fixtures/sdk_principal.py`
- Modify: `tests/unit/test_config.py`
- Modify: `tests/security/test_auth_activation.py`
- Modify: `tests/security/test_network.py`
- Modify: `tests/contracts/test_oauth_provider_capability.py`
- Modify: `tests/contracts/test_alpic_oauth_discovery.py`
- Create: `tests/contracts/test_alpic_dcr_flow_capability.py`
- Modify: `tests/conformance/test_mcp_http.py`
- Modify: `tests/unit/test_admission.py`
- Modify: `contracts/zod/capability-contracts.mjs`
- Modify: `tests/contracts/zod_contracts.test.mjs`
- Modify: `security/coverage-policy.json`
- Modify: `security/external-test-gates.json` to add the exact
  `alpic-metadata.oauth-dcr-flow` hosted gate; the side-effecting gate is
  executable only through `dcr-flow-proof`, never the generic external-gate
  path.

**Interfaces:**

```python
OAuthProviderCapabilityVerdict = Annotated[
    UnsupportedAuth0SignedJwtVerdict | SupportedAuth0SignedJwtVerdict,
    Field(discriminator="supported"),
]

AlpicOAuthDiscoveryCapabilityVerdict = Annotated[
    UnsupportedAlpicOAuthDiscoveryVerdict
    | SupportedAlpicOAuthDiscoveryVerdict,
    Field(discriminator="supported"),
]

AlpicDcrFlowCapabilityVerdict = Annotated[
    UnsupportedAlpicDcrFlowVerdict | SupportedAlpicDcrFlowVerdict,
    Field(discriminator="supported"),
]


class OidcAuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    issuer: ExactIssuer
    jwks_url: ExactHttpsUrl
    canonical_mcp_url: ExactHttpsUrl
    backend_resource_server_url: ExactHttpsUrl
    public_oauth_resource_url: ExactHttpsUrl
    allowed_hosts: Annotated[
        tuple[CanonicalHost, ...], Field(min_length=1, max_length=16)
    ]
    allowed_origins: Annotated[
        tuple[CanonicalOrigin, ...], Field(max_length=16)
    ]
    audiences: Annotated[
        tuple[Audience, ...], Field(min_length=1, max_length=8)
    ]
    algorithms: Annotated[
        tuple[Literal["RS256", "PS256", "ES256"], ...],
        Field(min_length=1, max_length=3),
    ]
    required_scopes: tuple[Literal["nplg:connect"]]
    jwks_timeout_ms: Literal[3000]
    clock_skew_seconds: Literal[60]
    access_token_max_lifetime_seconds: Literal[300]


class JwksSource(Protocol):
    async def get_signing_key(
        self,
        *,
        kid: JwtKeyId,
        algorithm: JwtAlgorithm,
        deadline: MonotonicDeadline,
    ) -> PyJWK | None: ...


class OidcJwtTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None: ...


class PrincipalSource(Protocol):
    def current(self) -> Principal: ...


class SdkAuthContextPrincipalSource:
    def current(self) -> Principal: ...


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    subject: StableSubject
    client_id: OAuthClientId
    issuer: HttpsIssuer
    audience: CanonicalResource
    scopes: Annotated[
        frozenset[Scope], Field(min_length=1, max_length=8)
    ]
    auth_method: Literal["oidc-signed-jwt"]
    authorization_details: tuple[()] = ()


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    event_type: AuditEventType
    outcome: AuditOutcome
    principal_pseudonym: Pseudonym
    client_id: OAuthClientId
    request_id: RequestId
    parsed_method: McpMethod
    tool_name: MetadataToolName | None
    policy_decision: PolicyDecision
    deployment_id: DeploymentId
    latency_ms: NonNegativeInt
    error_code: PublicErrorCode | None
    occurred_at: AwareDatetime
```

- The provider capability is not a loose boolean model. Its unsupported branch
  upgrades to `schema_version="2.0"` and fixes `provider="auth0"`,
  `client_registration_mode="alpic_dcr_proxy"`, null Auth0/token bindings, and
  the exact ordered current blockers. Its pre-deploy supported branch requires
  bounded Auth0 tenant/application IDs, byte-exact issuer and discovery,
  authorization/token/JWKS URLs, `access_token_format="signed_jwt"`, witnessed
  `RS256`/`PS256`/`ES256` algorithms, bounded audiences, token-purpose
  claim/value, unambiguous `client_id` or reviewed `azp`, PKCE S256, stable
  subject semantics, scopes containing `nplg:connect` and excluding
  `offline_access`, maximum 300-second access-token lifetime, rotation
  behavior, and authority/discovery/token evidence digests. It contains no
  Alpic project, environment, DCR-pool, callback, or end-to-end-flow claim.
- The discovery and DCR verdicts have separate strict supported and unsupported
  Pydantic/Zod branches. A supported DCR result binds exactly one
  `environment_kind` (`staging` or `production`), bounded Alpic
  team/project/environment/DCR-pool IDs, public and backend issuer/resource
  routes, the public registration endpoint, exact callback, deployment and
  deploy-pack identity, observed authorization-response issuer, PKCE S256,
  lifecycle/rotation outcomes, test transcript digest, capture time, and
  protected authority. One signed result cannot satisfy both environments.
  The protected evidence set requires distinct `staging` and `production`
  keys and rejects duplicated or cross-bound environment identities.
- The checked-in discovery and DCR records remain truthful unsupported
  bootstrap facts. Candidate code defines and validates the positive result
  schemas, while the protected controller produces candidate- and
  environment-bound signed results in Tasks 7 and 9. Candidate files are not
  edited during a deployment to manufacture a positive result.
- `preregistered`, native DCR, CIMD, another provider, and opaque-token
  introspection are rejected by this activation union. Each requires a
  separate reviewed design rather than an automatic fallback.
- Exact issuer strings are validated without normalization and are passed
  unchanged to `AuthSettings.model_validate(...)`.
- Production `create_app()` passes the verifier and `AuthSettings` to the
  official SDK's `Server.streamable_http_app(...)`.
- Unauthenticated `/mcp` initialization returns 401 with exactly one valid
  Bearer challenge and the configured protected-resource metadata URL before
  session or handler entry. The unauthenticated protected-resource metadata
  route exposes the exact configured resource and authorization server.
- The proposed first release uses only the coarse SDK connection scope
  `nplg:connect`. This is not silently accepted: implementation stops until
  the user explicitly approves the profile-specific coarse-scope policy
  amendment. That amendment must update the SDK capability and accepted
  difference, ADR, threat model, applicable ASVS rows, and hosted tests while
  preserving `MCP_DYNAMIC_SCOPE_403_UNSUPPORTED` and
  `MCP_STATIC_SCOPE_CHALLENGE_OMITS_SCOPE` as named governed limitations. If
  approval is withheld, the terminal result remains `do_not_release`.
- Exact non-secret configuration keys are
  `DEPLOYMENT_PROFILE=alpic-metadata`, `NPLG_AUTH_MODE=oidc`,
  `NPLG_CANONICAL_MCP_URL`, `NPLG_BACKEND_RESOURCE_SERVER_URL`,
  `NPLG_PUBLIC_OAUTH_RESOURCE_URL`, `NPLG_MCP_ALLOWED_HOSTS_JSON`,
  `NPLG_MCP_ALLOWED_ORIGINS_JSON`, `NPLG_OIDC_ISSUER_URL`,
  `NPLG_OIDC_JWKS_URL`, `NPLG_OIDC_AUDIENCES_JSON`,
  `NPLG_OIDC_ALGORITHMS_JSON`,
  `NPLG_OIDC_REQUIRED_SCOPES_JSON=["nplg:connect"]`,
  `NPLG_JWKS_TIMEOUT_MS=3000`, `NPLG_AUTH_CLOCK_SKEW_SECONDS=60`, and
  `NPLG_ACCESS_TOKEN_MAX_LIFETIME_SECONDS=300`.
- No URL is derived from `Host`, another configured URL, an Auth0 template, or
  `ALPIC_HOST`; every relationship is checked against the capability record.
- JWKS retrieval is HTTPS-only, no-proxy, no-redirect, DNS/IP-policy checked,
  bounded to 3 seconds and 1 MiB, bounded in key count, and single-flight on an
  unknown `kid`.
- Refactor the existing DSpace-only network boundary into an exact-origin
  policy that reuses its DNS resolution, selected-IP pinning, TLS hostname,
  peer-address, redirect, rebinding, proxy, and size/deadline controls. Do not
  add an unrestricted `httpx` or PyJWT-owned network client, and do not use
  synchronous `PyJWKClient`.
- The outer middleware keeps Host/Origin, framing/body, duplicate credential,
  cheap admission, stateless-session, and response-header defenses, but a
  missing or syntactically valid single Bearer credential reaches SDK OAuth
  before protocol-version routing. Static credentials remain test-profile
  only and cannot preempt the production SDK challenge. The exact metadata
  route is unauthenticated after malformed/duplicate credential framing is
  rejected.
- `SdkAuthContextPrincipalSource.current()` calls the SDK auth context exactly
  once and copies only validated safe fields; it never retains or serializes
  the SDK `AccessToken`, which contains the raw token.
- Reject any `authorization_details` access-token claim before constructing a
  `Principal`; the empty-tuple field is an invariant, not a permissive parser
  for Rich Authorization Requests.
- Audit events contain no raw token, claim set, query, metadata body, filename,
  secret, or authorization header. Principal pseudonyms use a purpose-specific
  versioned HMAC key, not a plain hash.

- [ ] **Step 1: Turn provider and hosted-flow observations into strict REDs**

For the pre-deploy provider verdict, add positive-record tests that reject a
tenant template, issuer/discovery mismatch, absent or excessive audiences,
opaque or unknown token format, unapproved algorithm, ambiguous client
identity, unstable subject evidence, excessive token lifetime, and
stale/evidence-digest mismatch. Separately test the supported/unsupported
discovery and DCR result schemas, including wrong environment or DCR pool,
preregistered/native-DCR/CIMD modes, wrong DCR issuer role, backend
`registration_endpoint`, absent public registration endpoint, callback drift,
staging/production cross-binding, and one record reused for both environments.
Run:

```bash
.venv/bin/python -m pytest \
  tests/contracts/test_oauth_provider_capability.py \
  tests/contracts/test_alpic_oauth_discovery.py \
  tests/contracts/test_alpic_dcr_flow_capability.py -q
npm run contracts:zod:all
```

Expected: the provider supported fixture fails until all exact pre-deploy facts
and digests are represented. The checked-in discovery/DCR negative verdicts
remain valid fail-closed results; synthetic positive schemas may pass, but do
not count as hosted evidence.

- [ ] **Step 2: Obtain the coarse-scope policy decision**

Stop and present the exact `alpic-metadata` authorization surface and the two
SDK limitations. Continue only after the user explicitly approves coarse
`nplg:connect` for this release profile. Record the decision in
`contracts/sdk-authorization-capability.json`,
`contracts/accepted-sdk-differences.json`, the SDK ADR, threat model, selected
ASVS claims, and matching tests. Approval accepts only the documented SDK
limitations; it does not waive issuer, audience, token, tool-profile, or
hosted-flow checks. Without approval, retain the blocker IDs and stop.

- [ ] **Step 3: Write runtime auth and audit RED tests**

Cover missing/duplicate authorization, malformed compact JWT, invalid
base64url/UTF-8, duplicate JOSE or claim keys, `alg=none`, algorithm confusion,
token-controlled `jku`/`x5u`/`jwk`/`x5c`, unsupported `crit`/`b64`/`zip`, wrong
issuer/audience/resource, ID-token substitution, missing scope, missing or
ambiguous `client_id`/`azp`, empty or unstable subject, expired/not-yet-valid/
overlong tokens, any `authorization_details` claim, key type/use/size/curve
mismatch, duplicate `kid`, key flood,
JWKS redirect/private-IP/rebind/timeout/oversize, unknown-`kid` refresh storm,
concurrent principals, reconnect, cancellation, context reset, quota denial,
and audit redaction.

The 401 detector test must assert zero verifier/handler calls for a missing
credential and exactly one verifier call for a presented credential.

- [ ] **Step 4: Observe runtime RED**

Run:

```bash
.venv/bin/python -m pytest \
  tests/security/test_auth.py \
  tests/security/test_audit.py \
  tests/security/test_auth_activation.py \
  tests/security/test_network.py \
  tests/property/test_auth_properties.py \
  tests/conformance/test_mcp_http.py \
  tests/unit/test_config.py \
  tests/unit/test_admission.py -q
```

Expected: new runtime tests fail because production still deliberately stops
before dependency construction. The unsupported-capability activation tests
remain GREEN.

- [ ] **Step 5: Implement only the signed-JWT metadata branch**

Use PyJWT only after the capability verdict selects `signed_jwt`; do not infer
token format from token bytes. Construct the official SDK `AccessToken` only
after signature, issuer, audience/resource, lifetime, scope, subject, and
client identity validation. Keep the current fail-closed startup path for an
unsupported or inconsistent record.

- [ ] **Step 6: Observe GREEN, properties, and mutations**

Run:

```bash
.venv/bin/python -m pytest \
  tests/security/test_auth.py \
  tests/security/test_audit.py \
  tests/security/test_auth_activation.py \
  tests/security/test_tokens.py \
  tests/security/test_network.py \
  tests/property/test_auth_properties.py \
  tests/conformance/test_mcp_http.py \
  tests/contracts/test_sdk_client.py \
  tests/contracts/test_sdk_boundary.py \
  tests/unit/test_config.py -q
.venv/bin/python scripts/run_mcp_conformance.py --requirements 2026-07-28
.venv/bin/python scripts/run_mutation_gate.py \
  --targets src/nplg_mcp/auth.py src/nplg_mcp/audit.py \
  src/nplg_mcp/http_security.py src/nplg_mcp/network.py \
  src/nplg_mcp/config.py src/nplg_mcp/app.py
.venv/bin/python scripts/run_quality_gate.py \
  --node-executable "$(command -v node)" src tests scripts
```

Expected: local synthetic provider and real ASGI security cases PASS; the
conformance result is labelled local/fixture evidence, not Auth0/Alpic proof.
Every deliberate issuer/audience/algorithm/lifetime/scope/client/JWKS/redaction
mutant is killed.

- [ ] **Step 7: Refactor and re-run without broadening the profile**

Keep token verification, principal construction, audit serialization, and app
wiring in separate reviewable modules. Do not add private-full or Tasks code.
Rerun Step 6 and leave edits unstaged.

### Task 6: Qualify and Freeze One Immutable Candidate

**Files:**

- Modify only if a gate finds a real defect: the exact file and its focused
  test; do not expand scope.
- Create as ignored local evidence:
  `.superpowers/sdd/2026-08-26-alpic-release-finalization/`
- No tracked attestation or release report is written in this task.

**Interfaces:**

- Produces one `CandidateBatteryResult`, source snapshot, wheel, sdist, minimal
  Alpic deploy pack, dependency/SBOM/scanner receipts, and exact digests bound
  to a clean commit and tree.
- Local qualification may set `candidate_qualified`; it cannot set
  `staging_proven`, `release_authorized`, `released`, or `published`.

- [ ] **Step 1: Capture the execution baseline without changing the index**

Record branch, HEAD, staged/unstaged/untracked paths, index digest, tool
versions, and the exact Node executable. Abort on unexpected overlay drift;
never reset, stash, clean, or broadly stage.

- [ ] **Step 2: Run focused release-critical gates first**

Run:

```bash
.venv/bin/python -m pytest \
  tests/static/test_asvs_evidence.py \
  tests/static/test_release_gate.py \
  tests/static/test_deployment.py \
  tests/security/test_auth.py \
  tests/security/test_audit.py \
  tests/contracts/test_oauth_provider_capability.py \
  tests/contracts/test_alpic_oauth_discovery.py \
  tests/contracts/test_alpic_dcr_flow_capability.py \
  tests/unit/test_build_alpic_deploy_pack.py \
  tests/unit/test_verify_deploy.py \
  tests/unit/test_run_alpic_staging_proof.py -q
npm run contracts:zod:all
npm run deployment:evidence:lint
npm run deployment:evidence:typecheck
npm run deployment:evidence:test
```

Expected: PASS with authoritative exit statuses.

- [ ] **Step 3: Run preliminary full local gates on the reviewed overlay**

Run each command separately and preserve its exit status:

```bash
.venv/bin/python scripts/run_quality_gate.py \
  --node-executable "$(command -v node)" src tests scripts
.venv/bin/python scripts/run_test_gate.py --compare-branch origin/main
.venv/bin/python scripts/run_mutation_gate.py \
  --targets scripts/build_asvs_matrix.py scripts/verify_release.py \
  scripts/build_alpic_deploy_pack.py scripts/verify_deploy.py \
  scripts/run_alpic_staging_proof.py \
  src/nplg_mcp/auth.py src/nplg_mcp/audit.py \
  src/nplg_mcp/http_security.py src/nplg_mcp/network.py \
  src/nplg_mcp/config.py src/nplg_mcp/app.py
```

Expected: quality, coverage, branch/diff coverage, security, contract, and
registered mutation gates PASS for the reviewed overlay. These are preliminary
results because the candidate does not exist until the authorized freeze in
Step 6. A timeout or interrupted wrapper is `incomplete`, not GREEN.

- [ ] **Step 4: Build and verify release subjects**

Run:

```bash
.venv/bin/python -m build
NPLG_RELEASE_TMP_DIR="$(mktemp -d)"
test "$NPLG_RELEASE_TMP_DIR" != "${NPLG_RELEASE_TMP_DIR#/}"
ABSENT_LOCAL_GATE_RESULT="$NPLG_RELEASE_TMP_DIR/local-gates.json"
test ! -e "$ABSENT_LOCAL_GATE_RESULT"
.venv/bin/python scripts/verify_release.py local-gates \
  --worktree "$PWD" \
  --output "$ABSENT_LOCAL_GATE_RESULT" \
  --node-executable "$(command -v node)" \
  --compare-branch origin/main
```

Expected: `python -m build` produces a provisional wheel and sdist, and
`local-gates` produces the local gate report, including its configured SBOM and
scanner command evidence. No command is credited for an artifact it does not
build. Each output path is absolute and absent before execution. The minimal
deploy pack cannot be built before the clean candidate exists; all overlay
subjects are provisional rather than candidate-bound.

- [ ] **Step 5: Resolve whitespace without altering adversarial bytes**

Run `git diff --check` against the reviewed candidate. Replace Markdown hard
break spaces with explicit markup where needed. Represent intentional
fixed-width PDF/xref fixture spaces with explicit byte escapes or concatenation
and prove the fixture digest/behavior is unchanged; never trim fixture bytes
mechanically or suppress all whitespace checks for Python source.

- [ ] **Step 6: Request exact Git authorization for candidate freeze**

Stop and present the exact paths, diff, gate receipts, proposed commit message,
and candidate subject digests. Only after explicit authorization may the
approved paths be staged and committed. Do not include unrelated pre-existing
user work.

- [ ] **Step 7: Re-run candidate release gates on the clean commit**

After an authorized commit, set `CANDIDATE_COMMIT` to the full new commit ID,
prove `HEAD` and the tree are clean, create fresh absent output directories,
and run the release-mode commands separately:

```bash
CANDIDATE_COMMIT="$(git rev-parse HEAD)"
test -z "$(git status --porcelain=v1)"
NPLG_CANDIDATE_TMP_DIR="$(mktemp -d)"
test "$NPLG_CANDIDATE_TMP_DIR" != "${NPLG_CANDIDATE_TMP_DIR#/}"
ABSENT_CANDIDATE_LOCAL_GATE_RESULT="$NPLG_CANDIDATE_TMP_DIR/local-gates.json"
ABSENT_PYTHON_DIST_DIR="$NPLG_CANDIDATE_TMP_DIR/python-dist"
ABSENT_CANDIDATE_DEPLOY_PACK="$NPLG_CANDIDATE_TMP_DIR/alpic-deploy-pack"
ABSENT_QUALITY_CACHE="$NPLG_CANDIDATE_TMP_DIR/quality-cache"
test ! -e "$ABSENT_CANDIDATE_LOCAL_GATE_RESULT"
test ! -e "$ABSENT_PYTHON_DIST_DIR"
test ! -e "$ABSENT_CANDIDATE_DEPLOY_PACK"
test ! -e "$ABSENT_QUALITY_CACHE"
.venv/bin/python scripts/run_quality_gate.py \
  --worktree "$PWD" --require-clean --candidate "$CANDIDATE_COMMIT" \
  --cache-dir "$ABSENT_QUALITY_CACHE" \
  --node-executable "$(command -v node)" src tests scripts
.venv/bin/python scripts/run_test_gate.py \
  --worktree "$PWD" --require-clean --candidate "$CANDIDATE_COMMIT" \
  --compare-branch origin/main
.venv/bin/python scripts/run_mutation_gate.py \
  --worktree "$PWD" --require-clean --candidate "$CANDIDATE_COMMIT" \
  --targets scripts/build_asvs_matrix.py scripts/verify_release.py \
  scripts/build_alpic_deploy_pack.py scripts/verify_deploy.py \
  scripts/run_alpic_staging_proof.py src/nplg_mcp/auth.py \
  src/nplg_mcp/audit.py src/nplg_mcp/http_security.py \
  src/nplg_mcp/network.py src/nplg_mcp/config.py src/nplg_mcp/app.py
.venv/bin/python scripts/verify_release.py local-gates \
  --worktree "$PWD" \
  --output "$ABSENT_CANDIDATE_LOCAL_GATE_RESULT" \
  --node-executable "$(command -v node)" \
  --compare-branch origin/main
.venv/bin/python -m build --outdir "$ABSENT_PYTHON_DIST_DIR"
.venv/bin/python scripts/build_alpic_deploy_pack.py \
  --worktree "$PWD" --candidate "$CANDIDATE_COMMIT" \
  --output-dir "$ABSENT_CANDIDATE_DEPLOY_PACK"
```

Expected: all authoritative exits PASS and every receipt/artifact is bound to
the same clean commit and tree. If the tree is dirty, an output path exists, a
command is interrupted, or any output changes unexpectedly, return to
`do_not_release`. Verify each CLI signature in its focused tests before relying
on this command block; do not weaken a gate merely to fit the plan.

### Task 7: Provision the External Controller and Prove Non-production Alpic Staging

This task is impossible in the candidate repository alone. The external
`nplg-release-controller` must have its own reviewed TDD plan, protected branch
and environment, reproducible build, exact tool/OS/dependency locks, isolated
installation, credential and network brokers, signing policy, immutable
custody, and adversarial/fault/recovery tests for all twenty-seven operations and
four launcher commands.

**External inputs:**

- Signed `ProtectedControllerProvisioningReceipt`
- Absolute digest-verified protected launcher
- Twenty-seven `OperationTddReceipt` records
- Four `LauncherTddReceipt` records
- Protected controller policy and trust root
- Network, runtime, Auth0, Alpic, and custody broker descriptors
- Closed logical Alpic action vocabulary mapped to the pinned 1.169.1 CLI
- Operation-specific approval receipts supplied only at their action edges

**Candidate files read but not modified:**

- `security/release-command-manifests.json`
- `security/release-controller-policy.json`
- `security/external-test-gates.json`
- Task 6 candidate battery and subject descriptors

- [ ] **Step 1: Validate the provisioning receipt and exact request family**

Run the candidate-safe validator against every request file before transferring
it to the protected boundary:

```bash
.venv/bin/python scripts/verify_release.py validate-command-request \
  --worktree "$PWD" \
  --request "$REQUEST_PATH"
```

Expected: structural PASS only. If controller revision, manifest digest,
candidate/tree, profile, request schema, operation inventory, approval timing,
or broker identity differs, stop with
`PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE` and retain `do_not_release`.

- [ ] **Step 2: Initialize the protected run after explicit approval**

After separate authorization, execute only the digest-verified launcher:

```bash
"$NPLG_PROTECTED_LAUNCHER" initialize-run \
  --request "$INITIALIZE_REQUEST" \
  --approval-receipt "$INITIALIZE_APPROVAL_RECEIPT"
```

Expected: a signed descriptor and initialization journal are durably published;
no evidence operation, deployment, or candidate-controlled command runs.

- [ ] **Step 3: Run the offline battery, pre-deploy gates, and preparation**

Use one validated request file per node. Candidate-controlled code runs only in
the secret-free offline battery. Run only gates whose subjects already exist;
the `alpic-metadata.oauth-dcr-flow` gate is deliberately deferred until the
staging deployment is classified `Protected` and Step 5 provisions its
staging-specific pool, and only the typed `dcr-flow-proof` operation may resolve
it. Other external gates run through their dedicated protected
brokers and each requires its own fresh test authorization. Stop on any
nonzero, unknown, or incomplete result.

- [ ] **Step 4: Deploy only to the named non-production environment**

After separate staging-deploy authorization:

```bash
"$NPLG_PROTECTED_LAUNCHER" run-operation \
  --request "$STAGING_DEPLOY_REQUEST" \
  --approval-receipt "$STAGING_DEPLOY_APPROVAL_RECEIPT"
```

The protected provider helper binds `environment_kind="staging"`, sets required
environment variables without exposing values, uploads only the verified
minimal deploy pack, and invokes only the reviewed Alpic action mapping. It
never invokes `alpic publish`. A provider `sourceCommitId="unavailable"` does
not fabricate a SHA-40: retain `SOURCE_COMMIT_BINDING_UNPROVEN` and bind the
runtime subject independently through the protected upload receipt, creation
correlation, deploy-pack digest, deployment ID, and runtime manifest.

If exit 20, exit 75, or process death occurs after durable deployment intent,
invoke only `reconcile-staging-deploy` with a fresh read approval. Exits 21/22
permit a newly approved attempt only after reconciled absence; exit 23 is
terminal.

- [ ] **Step 5: Provision staging OAuth after `Protected` classification**

After Alpic reports that the exact staging deployment is `Protected`, obtain a
fresh configuration approval and invoke the typed `auth-provision` operation.
It configures only the named staging DCR pool and staging callback. Its signed
result binds Auth0 tenant/application, Alpic team/project/staging environment,
DCR-pool ID, callback, public/backend issuer/resource routes, deployment,
candidate, and predecessor intent. It cannot be reused for Production.

If exit 20, exit 75, or process death occurs after durable intent, invoke only
`reconcile-auth-provision` with a fresh read approval. Exits 21/22 permit a new
separately approved attempt after reconciled absence; exit 23 is terminal.

- [ ] **Step 6: Prove the staging DCR flow and hosted boundary**

After its own fresh test authorization, run the protected
`dcr-flow-proof` operation, which resolves the registered
`alpic-metadata.oauth-dcr-flow` gate against the exact staging binding. Witness
actual dynamic client registration and one
authorization-code flow with PKCE S256. Test redirect mismatch, issuer mix-up,
scope escalation and downgrade, authorization-state reuse, authorization-code
replay, lifecycle evidence, and stale/cross-environment bindings.
Do not require ordinary signed bearer JWT replay rejection without a separately
designed DPoP or replay-cache contract.

The operation creates at most one bounded test registration. If exit 20, exit
75, or process death follows durable intent, run only `reconcile-dcr-flow` with
a fresh provider-read approval. It must identify and disposition the exact
registration from protected Auth0/Alpic evidence; an ambiguous result blocks
retry and release. Exits 21/22 permit a new separately approved attempt only
after reconciled absence; exit 23 is terminal.

Capture and bind all of the following:

- full project, environment, deployment, runtime, and tool identities, plus
  exact source identity when exposed and the named blocker when unavailable;
- explicit Streamable HTTP detection and successful `/mcp` health;
- a route inventory that distinguishes provider-owned `/`, `/mcp`, `/try`,
  `/assets`, and conditional OAuth/DCR routes from the application-owned MCP
  surface, plus proof that the application registered no asset or custom REST
  handler;
- OAuth `Protected` classification;
- unauthenticated initialize 401 challenge and protected-resource metadata;
- authenticated initialize, `tools/list`, and all three metadata tools;
- completion of each ordinary request inside Alpic's 30-second request limit,
  with no Tasks-based timeout bypass;
- expired, wrong issuer, wrong audience, wrong scope, malformed,
  authorization-state reuse, authorization-code replay, redirect mismatch,
  issuer mix-up, duplicate-header, wrong Host, and wrong Origin negatives;
- no handler entry for rejected requests and no credential/content leakage;
- Alpic audit JSON with every error/warning/skip disposition;
- Beacon outcome labelled accurately when protected-server checks are skipped;
- privacy, analytics, logs, retention, and environment settings;
- exact `tools/list` digest and dedicated submitted-version environment;
- final environment recapture immediately before finalization.

If the final environment snapshot differs, invalidate the staging proof and
repeat the affected deploy/provision/proof cycle. Produce separate signed
`SupportedAlpicOAuthDiscoveryVerdict` and staging
`SupportedAlpicDcrFlowVerdict` results. A manual screenshot or prose claim is
not machine-bound evidence.

Only after all items above exist, obtain fresh staging-test authorization and
invoke the distinct `staging-proof` join. It consumes the immutable
`StagingDeploymentResult`, Auth0 capability, staging discovery/DCR result,
hosted negatives, audit/version evidence, and final environment recapture to
produce `StagingProofResult`. This is the only node that may satisfy the
staging-proof prerequisite of `finalize`.

- [ ] **Step 7: Finalize and custody without publication**

Run the descriptor-permitted finalize and custody nodes. Custody upload needs a
fresh explicit approval. Read back the immutable object and verify its digest,
signature, candidate, profile, controller, and evidence inventory. A truthful
bundle may still contain blockers; such a bundle remains `do_not_release`.

### Task 8: Perform Independent ASVS Review and Attestation

**Files:**

- Modify: `docs/security/asvs-5.0.0-l2-matrix.jsonl`
- Modify: `docs/security/asvs-evidence-policy.json`
- Modify: `docs/security/evidence-manifest.jsonl`
- Modify: `docs/security/threat-model.json`
- Modify: `docs/security/threat-model.md`
- Modify: `SECURITY.md`
- Create: `docs/verification/2026-08-26-alpic-release-candidate.md`
- Modify: `tests/static/test_asvs_evidence.py`
- Modify: `tests/property/test_asvs_evidence.py`
- Modify: `tests/contracts/zod_asvs_evidence_contracts.test.mjs`

**Interfaces:**

- Consumes: the exact custodied Task 7 bundle and immutable candidate.
- Produces: independently reviewed row verdicts, evidence-manifest entries,
  `AttestationVerdict`, `AsvsL2ConformanceVerdict`,
  `ReleaseEligibilityVerdict`, and `EligibilityGateRecord`.
- Every applicable row is `Pass` or governed `N/A`; no automated bulk
  conversion from `Not assessed` is permitted.

- [ ] **Step 1: Observe the selected-profile closure RED**

Run:

```bash
RELEASE_PROFILE=alpic-metadata REQUIRE_RELEASE_ELIGIBILITY=1 \
  .venv/bin/python -m pytest \
  tests/static/test_asvs_evidence.py \
  tests/property/test_asvs_evidence.py -q
npm run test:contracts:asvs
```

Expected: the machinery and schemas PASS; eligibility fails only with exact
unassessed, failed, expired, or ungoverned row blocker IDs. A schema, runner,
manifest, or candidate-binding error is the wrong RED and must be fixed before
review continues.

- [ ] **Step 2: Review all 253 selected-profile rows independently**

For each row, bind primary evidence, candidate/profile selectors, evidence
kind, date/expiry, owner, reviewer, custody object, and rationale. Use governed
N/A only for proven non-construction/non-applicability. Preserve every open
provider, operations, retention, recovery, logging, or authority gap as a
blocker.

- [ ] **Step 3: Validate each review batch**

After each bounded batch, run the Step 1 commands without
`REQUIRE_RELEASE_ELIGIBILITY=1`. Expected: structural PASS and a shrinking,
exact blocker set. Do not weaken schema or policy to accept a row.

- [ ] **Step 4: Observe final eligibility GREEN**

Run Step 1 unchanged.

Expected: PASS only when all 253 rows are verified, all evidence is current and
custodied, and there are zero blockers. Confidence in a positive result must
come from exact joins, not row counts alone.

- [ ] **Step 5: Request separate attestation-commit authorization**

Present the exact attestation-only diff and signed handoff. After explicit
authorization, Step 6's `commit-attestation` operation may materialize and
commit only the listed attestation paths. No commit occurs in this approval
step.

- [ ] **Step 6: Build, decide, and custody the final-decision chain**

Validate a separate typed request for every node, then execute this exact
protected sequence:

```text
attestation-workspace
commit-attestation       # fresh exact-path Git approval
attest
eligibility
custody                  # subject_kind="final-decision-chain" and fresh upload approval
```

The chain binds the deployable candidate commit/tree and artifacts, the
attestation commit/tree, all 253 row verdicts, evidence inventory, staging
bundle, provider/DCR results, controller/policy/trust-root identities, and every
gate exit. Read the custody object back and verify canonical digest, signature,
subject joins, inventory, and decision before accepting it.

After `commit-attestation`, rerun the full Task 6 gates on that clean commit and
prove that the deployable candidate artifacts are unchanged and the attestation
commit references them exactly before invoking `attest`.

If eligibility is negative, the protected sequence must still custody the
signed `do_not_release` final-decision chain before returning exit 24. If
custody returns exit 20, exit 75, or the process dies after durable intent, run
only `reconcile-custody` with a fresh read approval and verify read-back. Exits
21/22 allow only a new, separately approved custody attempt after reconciled
absence; exit 23 is terminal. Only a positive, read-back-verified chain enters
`release_authorized`.

### Task 9: Authorize Production Release and Keep Publication Separate

**Prerequisites:** Tasks 1-8 are complete; the exact candidate and attestation
commits are immutable; the protected, custodied eligibility chain is positive;
all evidence remains current; and a separate production-deploy authorization
names the exact Alpic project, Production environment, deploy-pack digest, and
candidate. The staging OAuth/DCR result does not authorize or satisfy
Production.

**Files:**

- Create after successful production proof:
  `docs/verification/2026-08-26-alpic-production-release.md`
- Modify after successful production proof:
  `deploy/alpic-submission-versions.json`
- Do not modify source, contracts, schemas, or dependencies during promotion.

- [ ] **Step 1: Revalidate freshness immediately before production**

The protected controller rechecks candidate/tree, attestation, toolchain,
provider capability, Auth0 tenant, Alpic project/environment, environment
snapshot, controller policy, custody, evidence expiry, and approval receipt.
Any mismatch returns to `do_not_release`.

- [ ] **Step 2: Deploy the exact candidate through `production-deploy`**

After fresh production approval, submit the validated
`production-deploy` request to the protected launcher. Use the already verified
deploy pack; do not rebuild from a mutable worktree. Capture the previous
Production deployment/version as the only eligible rollback target.

If exit 20, exit 75, or process death follows durable intent, invoke only
`reconcile-production` with a fresh read approval. Exits 21/22 allow a new,
separately approved deployment attempt after reconciled absence; exit 23 is
terminal. No ambiguous result may advance release state.

After a successful Production deployment, every subsequent blocker before the
positive production chain is custodied—including classification timeout,
environment drift, auth provisioning failure, DCR failure/ambiguity,
Production proof failure, or cleanup failure—selects the same explicit rollback
decision point. Rollback is never automatic: it requires a fresh approval for
the previously captured exact target and follows the `rollback-production` /
`reconcile-rollback` rules in Step 4.

- [ ] **Step 3: Provision a distinct Production OAuth/DCR binding**

Wait for Alpic to classify the exact Production deployment as `Protected`.
After a fresh configuration approval, invoke `auth-provision` with
`environment_kind="production"`, the Production callback, and the exact
Production pool. Reuse of the staging pool, callback, environment ID, evidence
digest, or approval is rejected. Apply the same
`reconcile-auth-provision`/exit rules as Task 7.

- [ ] **Step 4: Prove Production DCR, then run read-only production proof**

After a fresh DCR-test authorization, run `dcr-flow-proof`, which resolves the
exact `alpic-metadata.oauth-dcr-flow` gate against the Production binding. It
uses the Task 7 durable-intent, one-registration, lifecycle, reconciliation,
and no-blind-retry contract. Produce a Production-specific signed
discovery/DCR result; the staging result remains a separate required subject.

Only after that succeeds, obtain fresh production-test authorization and run
the read-only `production-proof`. Repeat Task 7's application/provider route
inventory, state/code replay and issuer/redirect/scope negatives, tool catalog
digest, all three tools, logs/privacy settings, audit dispositions, version
binding, and final environment recapture. Do not send destructive or
privacy-sensitive test data.

On any post-deploy failure named above, the new candidate remains
`do_not_release`. If rollback is approved, invoke only the typed
`rollback-production` operation. Delivery-unknown rollback state selects only
`reconcile-rollback` with a fresh read approval; exits 21/22 permit a newly
approved attempt after reconciled absence, and exit 23 is terminal. Verify the
restored deployment/version before closing the incident.

- [ ] **Step 5: Clean the bounded pre-release test inventory**

After positive Production proof, obtain fresh cleanup approval and invoke
`cleanup-run` with `cleanup_phase="pre-release"`. It disposes or records the
governed expiry/owner of every DCR test registration and other descriptor-owned
ephemeral object, while preserving the active deployment/configuration and all
evidence/custody subjects. Retained objects without an accepted lifecycle are
release blockers.

Exit 20, exit 75, or process death selects only `reconcile-cleanup` with a
fresh read approval. Exits 21/22 permit a newly approved cleanup attempt after
reconciled absence; exit 23 is terminal. Cleanup failure enters the Step 4
rollback decision point.

- [ ] **Step 6: Sign and custody the `released` decision**

After the positive proof and cleanup, obtain a fresh release-decision approval
and execute `release-decision`, binding the positive pre-release cleanup
result. Then obtain a separate custody-upload approval and execute `custody` with
`subject_kind="production-release-chain"`. The signed chain
binds exact deployment/version/candidate/attestation/controller identities,
separate staging and Production DCR results, all command exits, residual
limitations, rollback target, and evidence/custody references. Apply Task 8's
custody reconciliation rules and verify immutable read-back before transitioning
from `release_authorized` to `released`. The released-without-publication branch
terminates here with the cleanup receipt already in custody.

Create the production report and submission-version update only from this
read-back-verified chain. Any Git staging or commit for those documentation
paths requires a new exact-path authorization and is not production authority.

- [ ] **Step 7: Keep publication in a separately initialized run**

Registry publication is optional. If the user later authorizes it, initialize a
new protected publication run bound to the custodied `released` chain.
Revalidate Production, title, description, domain, project, catalog digest, and
version; then submit the typed `publish-registry` request. If delivery is
unknown, use only `reconcile-publication` with a fresh read approval and the
standard exit semantics. Verify the registry entry.

Before publication custody, obtain fresh cleanup approval and execute
`cleanup-run` with `cleanup_phase="post-publication"`; apply
`reconcile-cleanup` on delivery-unknown state. Then custody the signed
publication chain with `subject_kind="publication-chain"` and a separate upload
approval. Only the verified registry entry plus successful cleanup plus
read-back custody may transition `released` to `published`. If external
publication is observed but cleanup/custody is incomplete, record that exact
externally visible state and blocker rather than claiming the internal
`published` transition.

## Final Completion Gate

This plan is complete only when all of the following are true for one exact
candidate:

- every local focused, full, strict quality, coverage, contract, property,
  adversarial, and registered mutation gate has an authoritative PASS;
- Alpic transport and the 1.169.1 tool family are explicit and locked;
- the pre-deploy provider capability is supported by exact Auth0 evidence;
- the user-approved coarse-scope policy and both named SDK limitations are
  reflected consistently in capability, accepted-difference, ADR, threat-model,
  ASVS, and hosted evidence;
- production OAuth and audit behavior pass local and hosted negative tests;
- the external controller is independently provisioned and its request family
  matches byte-for-byte;
- non-production and Production Alpic evidence, including distinct DCR pools,
  callbacks, and signed flow results, is complete, current, candidate-bound,
  and immutably custodied;
- every DCR write is durably journaled and either reconciled or unambiguous,
  and the applicable pre-release/post-publication cleanup receipt is positive;
- all 253 applicable ASVS L2 rows are independently verified as `Pass` or
  governed `N/A`;
- release eligibility and production post-deploy verdicts are signed,
  positive, and read-back verified;
- the exact production release was explicitly authorized; and
- the repository truthfully records `released` without claiming `published`
  unless publication received its own authorization and verification.

Before an authorized external side effect, the correct terminal status is
`do_not_release` with the exact remaining blocker IDs. After an external
deployment or publication is observed, report that fact plus the exact blocked
internal transition; never erase an irreversible external fact by relabelling
it as merely not released.
