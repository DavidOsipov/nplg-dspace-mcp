# NPLG DSpace MCP — Lean Production Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`
> after the required contract and authority approvals. Use ordinary TDD and
> preserve unrelated worktree/index changes.

**Status:** A0 AUTHORIZED AFTER THIS DOCUMENT DIFF IS RETURNED; v2 remains
NON-EXECUTABLE

**Date:** 2026-09-02

**Goal:** deliver a production-ready anonymous, read-only, fixed-origin,
three-tool NPLG MCP without a bespoke assurance framework.

**Architecture:** Pydantic owns the public contract and generates Draft
2020-12 JSON Schema. Project-specific code enforces NPLG origin/URL,
bibliographic projection, bounded output, fixed errors, and signed cursors;
standard test and supply-chain tools cover generic concerns. Alpic builds the
Git branch tracked by the target environment; deployment is accepted only
after the provider record is correlated with the approved revision. GitHub
release artifacts remain a separate attested evidence subject.

**Tech stack:** Python 3.12–3.14, Pydantic, HTTPX/httpcore, official Python MCP
SDK, pytest, locked uv/npm commands, GitHub Actions, and Alpic.

**Proposed wire contract:**
[`../specs/2026-09-02-anonymous-metadata-v2-contract.md`](../specs/2026-09-02-anonymous-metadata-v2-contract.md)

**Proposed exact model appendix:**
[`../specs/2026-09-02-anonymous-metadata-v2-model-appendix.md`](../specs/2026-09-02-anonymous-metadata-v2-model-appendix.md)

**Query ADR:**
[`../../architecture/2026-09-02-basic-query-no-lucene-parser-adr.md`](../../architecture/2026-09-02-basic-query-no-lucene-parser-adr.md)

The current root `SPEC.md` remains authoritative until the proposed breaking
contract is explicitly approved. The old release-provenance proposal is
replaced by a
[`SUPERSEDED / NON-EXECUTABLE` tombstone](2026-09-02-release-provenance.md).

## Fixed product boundary

The `alpic-metadata` inventory remains exactly:

1. `search_documents`
2. `get_document_metadata`
3. `list_document_files`

The static `nplg://skills/georgian-newspaper-visual-analysis` resource and the
client-side PDF/OCR boundary remain unchanged. No workstream adds a fourth
tool, arbitrary URL input, raw metadata, server-side document reading,
rendering, OCR, translation, embeddings, mutable repository operation, or new
authentication authority.

## Changed assumptions

| Previous plan assumption | Revised decision |
| --- | --- |
| Full two-identity release plan remains under an active path | Replace it with a command-free superseded tombstone; Git history is the archive |
| An exact wheel/OCI digest is necessarily the Alpic deployment subject | GitHub artifact and Alpic source deployment are distinct subjects |
| Alpic release blocks without digest promotion | Require approved source commit correlation through deployment ID and `sourceCommitId`; exact provider artifact digest is conditional |
| Trustworthy per-client edge limiting is always available | It is a SHOULD only when Alpic or another trusted edge documents a spoof-resistant key/control |
| All upstream failures are retryable | Timeout/transient availability are retryable; incompatibility and unclassified upstream failure are not |
| Initial search exposes a free-form Lucene subset | Initial search is basic query plus typed positive filters; no Luqum or AST |
| Strict `StrEnum` and tuple annotations necessarily accept decoded MCP JSON | Locked real-SDK probing rejects that shape; use wire `Literal` values and exact-list-to-owned-tuple validation |
| One nominal 1 MiB cap makes declared field maxima safe | Use exact per-tool leaf and complete-result caps plus whole-value omission and generated skeleton bounds |
| Typed Discovery controls can be assumed in every scope | Initial typed filters/sorts are global-only; scoped search is basic-query-only pending separate evidence |
| `/healthz` is the public deployment-identity proof | Keep it internal; expose a namespaced MCP self-report and correlate it with the Alpic deployment record |
| Authority B may push any reviewed ref | B cannot move a production-deploying branch or final public tag; only C can do so |
| Approval is split across many index/commit transitions | Three authority levels cover local, hosted/staging, and production actions |
| RESPX can be locked from paper evaluation | Run an isolated compatibility spike against the injected HTTPX seam first |
| The implementation plan carries the entire wire contract | Normative semantics live in the proposed SPEC and query ADR |
| A rough deletion estimate is acceptance evidence | Omit it unless a later generated path-level inventory supports it |

## Dependency decisions

No dependency or lock change is authorized by this document revision.

- Retain Pydantic as sole runtime/semantic authority and generate Draft
  2020-12 JSON Schema.
- Retain HTTPX/httpcore and the custom fixed-origin DNS/TLS/actual-peer
  transport.
- Retain the official Python MCP SDK and currently locked conformance suite;
  do not refresh them as part of the contract change.
- Propose `pytest-regressions` and `hypothesis-jsonschema` as development-only
  dependencies after exact review.
- Treat RESPX 0.23.1 as a provisional development-only candidate until
  Workstream D's isolated seam spike and dependency review pass; only then may
  an exact pin and lock diff be proposed.
- Do not add Luqum, PLY, another Lucene parser, Ajv, a full Zod twin, a generic
  PII/URL/SSRF/retry/rate-limit/circuit-breaker framework, or unrelated
  dependency updates.
- Keep `pydantic-settings` and broad AnyIO refactors post-release.

## Authority model

There are exactly three execution-authority levels. Each grant names a reviewed
scope; once granted, it covers the listed transitions within that scope without
separate approval for every Git-index operation.

### Authority A — local

Permits reviewed local branch/worktree changes, tests, explicitly approved lock
updates, staging/index updates, and local commits. It does not permit a push,
hosted workflow, staging deployment, publication, or production action.

### Authority B — hosted and staging

Permits pushing the exact reviewed refs, running hosted CI/attestation, and
deploying/verifying staging. It does not permit production publication,
deployment, rollback, emergency production restriction, movement of a branch
tracked by production, or creation/push of a final public release tag. The
staging environment tracks a dedicated `staging` branch; branch protection and
credentials MUST prevent Authority B from updating the production-tracked
`production` branch.

### Authority C — production

Permits the reviewed final signed release tag, movement of the protected
production-tracked branch, production deployment/publication, and an actual
production rollback or emergency restriction action.

Authority A may create a local candidate tag. Authority B may push only an
explicit `vX.Y.Z-rc.N` candidate tag after its reviewed scope is granted. A
final signed `vX.Y.Z` tag is created and pushed only under Authority C, after
green hosted CI and accepted staging evidence.

Product decisions remain distinct from execution authority. In particular,
the breaking v2 wire contract and each new dependency pin require explicit
approval before their Authority-A implementation scope begins.

## Execution order

1. After this documentation diff is returned, use the granted Authority A for
   A0 to restore the current baseline without changing the wire contract or
   dependency graph.
2. Run the read-only metadata-key inventory. A later reviewed Authority-A scope
   may run the disposable RESPX compatibility spike; reconcile the proposed
   SPEC without changing a lock.
3. Approve the exact v2 contract and proposed development dependencies,
   including RESPX only if the spike passed.
4. Make the approved contract the sole active SPEC, then complete the remaining
   Authority-A implementation and local verification.
5. Grant Authority B for push, hosted CI/attestation, and staging.
6. Grant Authority C only after staging evidence is reviewed.

## Workstream A — CI and immutable build evidence

**Purpose:** establish a green, reproducible local base, then replace bespoke
build/recovery machinery with standard locked commands.

### A0: current baseline repair

Under the Authority-A grant that becomes effective after this documentation
diff is returned:

1. Record `HEAD`, branch, staged/unstaged/untracked paths, toolchain versions,
   and hashes of the current canonical artifacts. Preserve the primary
   checkout's unrelated overlay.
2. Work on an isolated local branch/worktree at the approved base so tests and
   commits cannot absorb unrelated staged changes.
3. Reproduce the current CI and Security failures with their existing locked
   commands. Do not alter the wire contract, dependency inputs/locks, frozen
   outputs, or public trust boundary.
4. Use ordinary TDD to make only the smallest baseline repairs. Do not add a
   wrapper abstraction, receipt format, migration layer, or successor protocol
   around wrappers and baseline machinery already designated for retirement.
5. Run the complete local equivalents of current CI and Security workflows.
6. Build the current canonical wheel and sdist twice in independent clean
   directories using the same locked inputs and deterministic environment;
   compare their standard filenames, hashes, and archive member listings with
   direct commands. Do not create a new artifact-comparison framework.
7. Return the exact local diff and ordinary command/build results. A local A0
   commit is allowed by the same Authority-A grant; no additional index
   approval is required.

**A0 gate:** current CI/Security commands are green, the canonical artifact
comparison is reproducible, no unrelated primary-checkout bytes changed, and no
wire/dependency change occurred. Stop and report if any condition is false.

### A1: standardize the build after contract approval

1. Remove obsolete recovery workflows and baseline-successor/historical
   manifest machinery after confirming no retained private-profile consumer.
2. Replace ordinary quality/test/build wrappers with direct locked uv, npm, and
   GitHub Actions commands. CI never regenerates locks or snapshots.
3. Audit imports from the actual `alpic-metadata` entry point. Keep the public
   core minimal. Current evidence identifies Pillow and pypdfium2 as the
   private PDF/image dependencies to move to a `private-full` extra with its
   own lock; do not invent a separate storage dependency, and account for any
   further package only when the import graph demonstrates it is private-only.
   Reconcile `pyproject.toml`, the core/dev input and lock files, new
   private-full input/lock files, `Dockerfile`, `compose.yaml`, static
   deployment/lock tests, and deploy documentation. The private-full
   Docker/Compose build must select the new private-full lock, while
   `alpic.json` continues to select only the core `requirements.lock`.
4. Build deterministic wheel and sdist release subjects from the approved
   source commit, reviewed lockfiles, and tracked build configuration. The Git
   commit binds the complete tracked source tree; do not create a custom
   build-input manifest.
5. Generate a standard SBOM. Keep `/healthz` internal and status-only. Put the
   installed distribution name/version in standard MCP `serverInfo`, and expose
   version, source commit, lock digest, build-config digest, and deployment
   profile under the model appendix's namespaced `tools/list` `_meta` key. This
   is explicitly a self-report, not attestation. Derive lock/config hashes from
   bounded deployed files or an immutable package manifest generated from
   those bytes, not solely from mutable user environment variables.

**A1 gate:** the public installation lacks the Pillow and pypdfium2
distributions and `import PIL`/`import pypdfium2` fail, while the private
installation imports both; release artifacts reproduce from the reviewed
commit, lockfiles, and tracked build configuration; the MCP-visible identity is
derived and serialized as specified, with `/healthz` remaining internal; direct
gates remain green.

## Workstream B — Metadata projection and bibliographic semantics

**Purpose:** make anonymous metadata useful without exposing raw or technical
source data.

1. After A0, perform the value-free DIM/XOAI qualified-key inventory specified
   by the proposed contract. Retain key names/counts only in sanitized evidence.
2. Reconcile citation, series/report title and number, ISMN, sponsors,
   `dc.relation.IsPartOf`, and `dc.relation.IsFormatOf` with official NPLG help.
3. Mark candidate source keys expose/map/suppress/defer, revise the SPEC, and
   obtain exact contract approval before freezing `ReviewedSourceKey`.
4. Replace the root `SPEC.md` with a short authoritative pointer to the approved
   contract and mark its old phase-0/1 Zod-oracle statements superseded.
5. Write semantic/privacy tests first, then implement the approved closed
   allowlist, source-bound roles/dates/rights/licences, nullable title, and
   `dc.creator` to role `creator` mapping.
6. Remove technical provenance and public raw fields. Do not add a general PII
   classifier without field-specific evidence.
7. Enforce destination cardinalities, the global pre-serialization budget,
   exact per-tool aggregate and complete-result bounds, value-free warning
   causes, and coverage/access separation. Use only whole-value,
   whole-optional-field, or whole-file-record omission; never cut serialized
   JSON. Mark an omitted eligible file record as partial inventory coverage.
8. Make file `source_url` nullable and direct-only; keep `repository_url`
   reserved for the repository root, expose the canonical record as `item_url`,
   and require a non-null verified same-handle `source_url` for public access.
9. Restrict eligible files to the unique reviewed JSPUI item-files table. Ignore
   generic links elsewhere and exclude `TEXT`, `THUMBNAIL`, `LICENSE`,
   `CC-LICENSE`, metadata, administrative, unknown, and explicit non-`ORIGINAL`
   bundle classes; do not publish an `ORIGINAL` label that the row itself does
   not evidence.
10. Generate Draft 2020-12 JSON Schema from Pydantic and approve deterministic
   synthetic `pytest-regressions` snapshots through ordinary Git diff review.

**Gate:** adversarial fixtures expose no technical provenance or raw metadata;
roles, dates, rights, licences, and identifiers remain source-bound; all limits
and omission causes match the approved SPEC.

## Workstream C — Search and cursor

**Purpose:** implement the initial search syntax profile as basic query plus
typed positive filters, without raw DSpace syntax or a parser dependency.

1. Implement the approved no-AST Pydantic query admission corpus. The exact
   canonical `submitted_query` is never reconstructed before upstream use.
2. Add typed positive `equals`/`contains` filters for title, `author_index`,
   subject, type, and language; add the separate typed issue-year range.
3. Add typed relevance/title/issued-date sorting and deterministic filter-only
   defaults. Compile only reviewed private DSpace constants.
4. Keep `envfv` internal and permit one stale-marker rediscovery/replay inside
   the original deadline.
5. Bind cursor v2 to the complete resolved request context and reject tamper,
   expiry, version mismatch, and replay before network I/O.
6. Parse result records and pagination resiliently; validate material echoed
   state without making Bootstrap classes or exact DOM topology public
   invariants.
7. Restrict typed filters and explicit sorting to global scope in the initial
   profile. Scoped search accepts only a non-null basic query, empty filters,
   and null/omitted sort/order; obtain `envfv` from that exact scoped page and treat
   its reflected default controls only as consistency evidence. Do not add a
   capability LRU or claim that reflected HTML proves Solr application.
8. Return `attributed_names`, `match_source_not_exposed`, and
   `no_main_query`. A filter-only response has top-level `query=null` and every
   row has `no_main_query` with empty match fields; do not invent snippets,
   scores, or match explanations. Preserve every accepted page-row handle and
   canonical item URL under all success-budget outcomes.
9. Implement the proposed fixed public error table and causal split:
   `UPSTREAM_TIMEOUT` and `TEMPORARILY_UNAVAILABLE` are retryable;
   `UPSTREAM_INCOMPATIBLE` and `UPSTREAM_FAILURE` are not.
10. Make the current internal `ErrorCode`/profile disposition exhaustive: every
   value is mapped to a fixed public error or proven unreachable in
   `alpic-metadata` composition.

**Gate:** the approved query corpus is stable; forbidden inputs make no network
call; compiled ordered parameters are exact; cursor replay fails before I/O;
malformed, drifted, or ambiguous JSPUI state fails non-retryably.

## Workstream D — Verification and operations

**Purpose:** use standard test tooling and provide bounded, observable
operation without assuming undocumented Alpic controls.

1. Before any RESPX lock change, run an Authority-A disposable compatibility
   spike against the actual `NplgRepository.client` injection seam in an
   ignored disposable environment. Instantiate an explicit
   `respx.Router(assert_all_called=True, assert_all_mocked=True)`, pass
   `router.async_handler` to `httpx.MockTransport`, and inject that client into
   `NplgRepository(..., validate_dns=False)`; do not globally patch HTTPX or
   alter production composition.
2. At that repository seam, inspect the captured HTTPX request objects for the
   exact `request.url.raw_path`, `request.url.query`, ordered query parameters,
   and request sequence; exercise stale-`envfv` refresh, synthetic status/
   stream/timeout behavior, and malformed responses; then call
   `router.assert_all_called()`. This is request-object/response-behavior
   evidence, not raw-wire evidence, and it supplies no evidence about real DNS,
   TLS/certificate/SNI, actual-peer equality, connect/read timeout enforcement,
   proxy exclusion, or production client composition.
3. Test fixed outbound headers, `trust_env=False`, and suppression of inbound
   client headers, cookies, authorization, forwarding headers, and browser
   headers at `build_outbound_headers` plus `create_app`/runtime composition,
   not by attributing those properties to `NplgRepository` or RESPX.
4. If the spike cannot exercise the repository seam without distorting
   production code, or adds no material value over the existing native
   `MockTransport` suite, do not add RESPX. Prove the spike changes no project
   manifest, lock, or Git layer. Only after review may RESPX be proposed as an
   exact development-only pin and integrated into repository HTTP tests.
5. Keep `tests/security/test_network.py` and
   `tests/security/test_ssrf_binding.py` independent of RESPX. They continue to
   exercise `BoundAsyncHTTPTransport`, deterministic DNS selection,
   hostname/SNI policy, and transport-reported peer equality directly;
   production composition tests retain the `trust_env`, proxy/certificate-
   environment, cookie, and header-policy checks.
6. Use pytest, schema-derived Hypothesis generation for representable shape,
   hand-authored semantic/security cases, and reviewed synthetic regression
   fixtures. Live counts/order remain canaries only.
7. Add maximal-vector tests for the exact metadata, search, file, and error
   budgets. Compose the bounded modern server-info stamp before measurement and
   prove the locked runner adds or changes nothing afterward. Exercise the
   complete MCP `2026-07-28` application result and Streamable HTTP
   serialization, plus the Alpic `2025-11-25` public transformation and its
   reserved envelope margin; no serialized bytes are ever sliced.
8. Invoke the already locked official MCP conformance suite directly for
   applicable initialization, tools, resources, JSON-RPC, and Streamable HTTP
   behavior. Retain only focused NPLG protocol/profile tests.
9. Restrict mutation testing to fixed-origin/URL policy, cursor verification,
   and metadata privacy projection.
10. Require bounded request/body/tool admission and concurrency, connect/read/
   total deadlines, the existing small circuit breaker, the documented monthly
   Alpic plan request allowance/billing quota, sanitized metrics/logs, alerts,
   and an emergency public restriction or disable path. The monthly allowance
   is not represented as abuse throttling.
11. Per-client edge limiting is a SHOULD only if the provider or a separately
   deployed trusted edge documents a spoof-resistant identity and control.
   Its absence is a recorded limitation, not by itself a release blocker.
12. Do not treat Alpic analytics identities as a rate-limit key without a
   documented enforcement contract, and do not add a process-local generic
   per-client limiter.
13. Run representative staging smoke tests against canary handles; never use
   live totals or ordering as golden expectations.

**Gate:** local suites and applicable conformance pass; focused mutations are
killed; bounded admission, deadlines, circuit behavior, metrics, alerts,
monthly plan allowance, emergency restriction, and rollback procedures are
observed in staging. Any provider-dependent edge limit is reported separately.

## Workstream E — Release

**Purpose:** preserve immutable release evidence while deploying through
Alpic's documented source-build model.

### Attested release-artifact subject

1. Approve the breaking schema and golden-fixture diff.
2. Under Authority A, create the reviewed local candidate commit and, if useful,
   a signed `vX.Y.Z-rc.N` candidate tag. Do not create a final release tag.
3. Under Authority B, push only the reviewed candidate/RC refs to the dedicated
   `staging` branch and require green hosted checks. Authority B cannot update
   `production` or push `vX.Y.Z`.
4. Build wheel and sdist from the candidate commit, reviewed lockfiles, and
   tracked build configuration; scan them, generate the SBOM, and create
   standard GitHub Artifact Attestations over their exact digests.

These attestations identify the GitHub-built wheel/sdist. They MUST NOT be
described as proof that Alpic executed those bytes.

### Alpic deployment subject

1. Use Git-backed branch deployment as the only normative Alpic path. The
   staging environment tracks only `staging`; production tracks only the
   protected `production` branch. Do not use or mix in CLI source-upload
   deployment while exact non-null `sourceCommitId` correlation is required.
2. Under Authority B, advance only `staging` to the approved candidate and
   observe the resulting staging deployment. Record its opaque Alpic deployment
   ID and poll that exact record. Require deployed status, the expected
   environment, and `isCurrent`.
3. In staging, first establish how Alpic represents a Git-backed
   `sourceCommitId`; then require it to be non-null and exactly equal to the
   approved full Git commit OID. Null, an unexpected representation, or a
   mismatch stops release. This is provider-reported control-plane source
   metadata, not proof of running bytes or artifact attestation.
4. After green hosted CI and accepted staging evidence, Authority C creates and
   pushes the final signed `vX.Y.Z` tag at that same commit, then advances the
   protected `production` branch to it and observes the production deployment.
   No Authority-B credential or workflow may move that branch or trigger this
   production environment.
5. Record the exact Git commit OID and prove every pushed RC tag, if any, and the
   final signed tag resolve to it. Separately record SHA-256 digests for the
   exported source archive, wheel/sdist, `pyproject.toml`, `requirements.lock`,
   and `alpic.json` in the approved commit. Snapshot mutable project settings;
   record provider defaults, toolchain, and base-image inputs that cannot be
   observed as reproducibility limitations. Do not claim a closed set of
   provider-consumed inputs.
6. Populate the namespaced MCP build-identity self-report from installed
   package metadata and bounded deployed/package bytes where possible. If the
   source commit must be embedded at build time, treat it as self-reported and
   corroborate it with the separately fetched Alpic deployment record; do not
   rely solely on mutable user environment variables for lock/config digests.
7. Verify exactly three tools, the static workflow resource, MCP-visible build
   identity, representative search/metadata/file calls, fixed errors,
   fixed-origin behavior, sanitized telemetry, and operational controls. Prove
   that the public Alpic hop negotiates `2025-11-25`, omits only the
   modern-only `resultType`, preserves project `_meta` and tool-result
   semantics, and stays inside the reserved public-envelope margin.
8. Retain the prior approved source/tag and deployment record. In staging,
   rehearse the proposed rollback runbook against a dedicated test branch. An
   actual production rollback is Authority C moving `production` to the exact
   prior approved commit, requiring the new provider-reported `sourceCommitId`
   to match that OID, and repeating post-deployment checks. This is a project
   runbook, not a documented native Alpic rollback-by-ID or rollback-by-digest
   feature.

If Alpic later documents and exposes promotion and runtime reporting of an
exact artifact/OCI digest, add digest equality as a preferred extra control.
It is not a release blocker under the currently documented source-build model.

Public Alpic evidence for this policy:

- [Environments track Git branches](https://docs.alpic.ai/build-deploy/environments)
- [Deployment records expose ID and nullable `sourceCommitId`](https://docs.alpic.ai/api-reference/deployments/get-a-deployment)
- [Documented system environment variables](https://docs.alpic.ai/build-deploy/env-variables)
- [Build configuration hierarchy](https://docs.alpic.ai/build-deploy/builds)
- [Plan request allowances](https://docs.alpic.ai/pricing/plans)
- [Anonymous traffic has no Alpic user identity](https://docs.alpic.ai/analytics/unique-users)

**Gate:** hosted evidence binds the artifact subjects to the approved commit and
locks; the Alpic deployment record provides separately qualified source
metadata for the accepted deployment; branch protection proves Authority B
cannot update the production-tracked branch; runtime and representative calls
match; the rollback runbook has staging evidence.

## Deferred work

- public facets, authority filters, negative filters, and autocomplete;
- Boolean, grouping, unary, wildcard, and broader punctuation support after the
  base service is stable;
- server-side retries beyond stale-`envfv` recovery;
- DIM/METS/XOAI/MODS/ORE source-priority comparison;
- citation generation, morphology, transliteration, and alias expansion;
- public `TEXT`, `THUMBNAIL`, or `LICENSE` bundles;
- full row-by-row ASVS L2 certification as a first-release blocker;
- formal release-provenance research or repair of the superseded plan.

## Production-readiness acceptance

Production-ready means all of the following are evidenced:

1. The exact three tools pass deterministic integration tests, and the one
   static resource remains available.
2. Deterministic fixed-origin DNS selection, TLS hostname/SNI policy, and
   transport-reported actual-peer equality tests pass independently of RESPX.
3. No technical provenance or raw metadata reaches anonymous output.
4. Roles, dates, rights, licences, identifiers, file access, and coverage remain
   source-bound and semantically separate.
5. Inputs, upstream responses, and public outputs have explicit byte and
   cardinality limits.
6. Basic-query admission matches the approved corpus and never reconstructs
   accepted `submitted_query`.
7. Cursor tampering, expiry, and cross-context replay fail before network I/O.
8. Public errors are fixed, exhaustive for the profile, and contain no raw
   query, metadata, URL, path, traceback, or internal exception detail.
9. Applicable official MCP conformance passes.
10. Dependency, SAST, secret, and release-artifact scans pass; wheel/sdist
    subjects have SBOM and GitHub attestations.
11. After staging verifies its representation, the Alpic deployment ID reports
    a non-null `sourceCommitId` equal to the approved full Git OID; this
    provider metadata is not described as runtime-byte attestation.
12. Standard MCP `serverInfo` and the namespaced MCP build identity match the
    installed/package/deployed-byte evidence and approved source/build values,
    with their self-report limitation documented and `/healthz` kept internal.
13. Bounded admission/concurrency, deadlines, circuit breaker, the monthly plan
    request allowance, monitoring, alerts, emergency restriction, and the
    staging-proven rollback runbook exist; billing quota is not abuse
    throttling.
14. Per-client edge limiting is verified when a trustworthy documented control
    exists, otherwise its absence is explicitly recorded.
15. Staging smoke tests pass and known limitations do not overstate search
    completeness, match explanation, rights, access, provider provenance, or
    upstream correctness.

## Remaining risks

- DSpace 5.5 is end-of-support and NPLG may have local modifications.
- Basic-query punctuation rejection creates deliberate false negatives; a
  colon-space query can still have upstream semantics the MCP cannot prove.
- Static allowlists and resilient parsing cannot prevent fail-closed outages
  after incompatible JSPUI changes.
- Anonymous totals, visibility, and file availability remain contextual.
- Source-class suppression addresses observed provenance leakage but cannot
  prove every future allowed value lacks administrative contact data.
- Cursor integrity depends on secret custody, rotation, clocks, and versioning.
- Instance-local circuit state is not a globally coordinated breaker.
- Current public Alpic documentation does not establish exact artifact
  promotion, provider-supplied runtime identity, or per-client anonymous rate
  limiting. The plan records those limits instead of inventing controls.

## Stop gate

This turn authorizes documentation changes only and MUST end after returning
their exact diff. Once that diff has been returned, the user's directive grants
Authority A only for the A0 scope above. A0 may then make its reviewed local
worktree/index changes, run tests, and create a local commit without a separate
approval for each Git-index transition. A0 still cannot change the wire
contract, dependency graph, locks, public trust boundary, or retiring tooling
beyond the smallest current-baseline repair.

No Authority B or C is granted. Do not push, invoke hosted CI, deploy staging,
move the production-tracked branch, create/push a final release tag, publish,
deploy production, restrict production, or execute a production rollback.

The v2 implementation, generated schema/golden updates, RESPX or other
dependency-lock changes, and A1–E source work remain blocked until A0 is green,
the metadata-key inventory is reviewed, and the exact contract plus dependency
pins are explicitly approved.
