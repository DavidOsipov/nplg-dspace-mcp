# Phase 0-1 Audit Remediation Report

**Date:** 2026-08-20
**Scope:** Implemented portions of `docs/2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md`, Phases 0-1
**Candidate HEAD:** `f5125720d1b67509ab2f15a50b710f10bb853924`
**Decision:** The local release battery passed; the fresh mutation rerun timed out; release remains prohibited.

## Executive result

The locally remediable configuration, token, schema, test-registry, PDF lifecycle, parser, result-size, deadline, and streaming defects identified as F-01 through F-15 were addressed with focused RED/GREEN tests. The authoritative test/coverage gate and the complete local release battery pass on the resulting unstaged working tree. A fresh run of the separate closed-target mutation gate exceeded its bounded 1,800-second process deadline and produced no valid current score.

This is not an OWASP ASVS L2 certification and it is not release authorization. Controls that require independent deployment authority, external scanner receipts, a completed ASVS assessment, byte-bound analyzer images, persistent-cache isolation, or exact CPython 3.13.15 evidence remain fail-closed. No ASVS matrix row or evidence-manifest entry was changed by this remediation.

## Finding disposition

| ID | Disposition | Current evidence and residual risk |
| --- | --- | --- |
| F-01 | Fixed locally | Anonymous access is opt-in and loopback-only; Alpic/public configuration requires production authentication. Negative configuration and HTTP tests cover omitted, contradictory, and public values. |
| F-02 | Production exposure closed; capability blocker remains | `private-full` now fails startup in production before runtime construction because the same-UID subprocess is not an independent native-code authority boundary. Enabling production PDF tools still requires a separately controlled worker identity/sandbox and deployment evidence. |
| F-03 | Fixed locally | PDF jobs are created beneath the writable private cache rather than an unwritable Compose parent. Static deployment tests exercise the reference layout. |
| F-04 | Fixed locally | The external test registry references the live frozen-baseline tests and rejects stale, renamed, or omitted allocations. |
| F-05 | Fixed locally | The final authoritative test gate reports 95.36106032906764% project branch coverage, 96.03809523809524% changed-line coverage, and 95.16129032258064% changed branch-arc coverage; all 16 decision modules are at 100%. |
| F-06 | Externally blocked | The ASVS matrix retains integrity checks but no completed independent L2 assessment/receipt was produced. No row was promoted by local inference. |
| F-07 | Fixed locally | The cancellation fixture publishes PID readiness atomically, eliminating the observed partial-file readiness race. |
| F-08 | Fixed locally | Zod string bounds count Unicode code points, matching Pydantic semantics; astral-plane boundary tests cover the prior UTF-16 mismatch. |
| F-09 | Fixed locally | Capability Zod schemas and tests are included in strict `checkJs` type checking and zero-warning ESLint, as well as runtime tests. |
| F-10 | Fixed for the supported production profile | Named credentials now bind stable principals and enforce per-principal plus global zero-waiter MCP admission. The production edge blocks public probes. Persistent-cache tenant quotas remain required before any full profile can be enabled; full profiles are currently unavailable in production. |
| F-11 | Production exposure closed; local-dev residual remains | Parent validation binds source digest, render ID, requested page set, page/aggregate pixel policy, tile page/geometry/root/metadata/count, JPEG header and complete-body validation, and descriptor-bound publication. Repeated cancellation cannot release PDF admission before process-group termination and private-job cleanup either completes or reports an operational failure. The same-UID escape residual is not production-reachable because F-02 fails closed. |
| F-12 | Fixed locally | Parsed object count, nesting, Unicode text, row count, result graph, and serialized JSON size have explicit ceilings with negative/adversarial tests. |
| F-13 | Fixed locally | API and signing credentials must be distinct, and signed-asset verification rejects authenticated expiries beyond the configured and hard maximum lifetime. |
| F-14 | Open assurance gap | Most local analyzers are not executed in immutable byte-bound images. Local pinning and scans do not substitute for digest-bound analyzer provenance. |
| F-15 | Open environment mismatch | The verified environment is CPython 3.13.13. `uv python find 3.13.15` found no interpreter, so the exact 3.13.15 compatibility claim remains unproved. |

## Post-audit security fixes

| Finding | Disposition |
| --- | --- |
| HTML/XML allocation and cancellation lifetime | Streaming preflight budgets now reject excessive elements, depth, text, and attributes before full tree construction. Parsing uses a dedicated bounded worker whose permit is released by the underlying worker completion, not by cancellation of the awaiting request. |
| Synchronous storage publication on the event loop | Download writes, flush/fsync, hashing, deduplication, PDF staging, output publication, and readiness storage checks run through a bounded storage worker. Cancellation is deferred until the real storage operation completes. |
| Shared credential and global-only admission | Strict frozen Pydantic principal credentials are loaded from duplicate-key-rejecting `API_PRINCIPALS_JSON`; production requires named principals and reserves global capacity above each principal's cap. |
| DNS work surviving cancellation | Resolution uses a dedicated capacity-one worker and retains its capacity permit until the underlying `getaddrinfo` job actually completes, including after caller cancellation. |
| PDF worker shares the application authority | Production `private-full` is disabled before service construction until an OS-isolated worker backend exists. Metadata-only production remains supported. |
| Weak worker-output binding | The parent recomputes render identity and validates the exact page set, tile identity/geometry/source, complete JPEG body, and manifest/output tree before publication. |
| Production verifier/profile drift | Public verification defaults to the exact three-tool `alpic-metadata` contract and does not query Caddy-blocked probes. Probe checks are opt-in only through a canonical-origin-distinct loopback HTTP `--probe-base-url`; `private-full` verification must be selected explicitly. |
| Parent PDF pixel and tile-grid trust | The parent rejects page-count, per-page, aggregate-render, staged-manifest, JPEG-header, and tile-count excesses before image decode or expected-grid allocation, even when a malicious worker's claims and JPEG body agree. |
| PDF cleanup under cancellation, storage saturation, or hostile permissions | Process termination and private-job removal run as one shielded cleanup task. Repeated cancellation is deferred until it finishes, directory removal remains in a nested `finally` when termination reports failure or process creation fails, and the serialized executor owns reserved cleanup capacity independent of the fail-fast storage-publication pool. A mode-`000` worker tree receives one non-symlink directory-permission recovery retry; persistent deletion failure is surfaced as an operational error rather than suppressed. |
| Metadata resource-family routing | Metadata-only services return bounded `NOT_FOUND` errors for artifact and render URI families before touching unavailable private-full collaborators. |

## Executed evidence

- Focused remediation tests were observed RED for the audited defect before the corresponding implementation change, then GREEN.
- Authoritative contained suite: 2,655 JUnit cases, with zero failures, errors, or skips.
- Test/coverage gate: project branch 95.36106032906764%; changed lines 96.03809523809524%; changed branch arcs 95.16129032258064%; 16/16 decision modules at 100%.
- Fresh mutation gate: no valid score. The exact closed eight-target run exceeded the gate's bounded 1,800-second process deadline while still executing storage mutants and failed at the process boundary. Earlier mutation scores are not claimed as current evidence.
- Zod contracts: 9 capability, 160 baseline, and 14 ASVS runtime cases (183 total); strict TypeScript `checkJs` and ESLint with zero warnings passed.
- Python quality: the canonical quality gate passed on CPython 3.13.13 with Ruff, strict mypy, strict Pyright 1.1.413, bytecode compilation, and the SHA-256-locked Node 24.19.0 runtime. Cross-version 3.12/3.14 execution was not repeated in this remediation run.
- Security checks: Bandit reported no medium/high findings; pip-audit reported no known vulnerabilities in the hash-locked development requirements; offline Zizmor reported no findings after enforcing a seven-day Dependabot cooldown for pip, npm, and GitHub Actions.
- Schema runtime: Pydantic 2 strict/frozen/closed models and Zod 4.4.3 strict schemas remain independent validation oracles.
- Local release battery: Ruff, mypy, Pyright, test gate, Bandit, pip-audit, CycloneDX, and Zizmor all returned `passed` with exit code 0.

The final machine-readable local release result is retained at `/tmp/nplg-final-release.slK98v/output/release-gate-results.json` and records:

```text
local_status=passed
terminal_verdict=do_not_release
eligibility_reason=external_authority_required
```

The following externally governed requirements remain `not_passed`: actionlint, Semgrep, Gitleaks directory scan, Gitleaks history scan, Trivy filesystem scan, and a signed fresh Trivy database receipt.

## Custody

The pre-existing staged candidate remains 67 paths. Its binary diff SHA-256 after remediation is:

```text
9873fceb54a4c320b1cd5efe77caa7bfb7bcccf8591b4b5db1068df80f11df5d
```

All remediation changes remain unstaged. No commit, push, deployment, publication, signing action, ASVS attestation, or external receipt was created.
