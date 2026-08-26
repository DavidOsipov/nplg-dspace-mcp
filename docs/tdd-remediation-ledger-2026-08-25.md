# Phases 0–8 audit remediation TDD ledger

Date: 2026-08-25  
Baseline HEAD: `377e70203de8ef5706664bd305d43680451aa744`  
Preserved staged-diff SHA-256: `19b2538c773e43055fa248d72fb995abf4d6f83713f8539ebaa4bb70d30b716a`

This non-authoritative ledger records only remediation performed after the phases 0–8 audit. It
does not retroactively claim that earlier implementation was test-first. All
changes remain unstaged so the pre-existing staged candidate is preserved.

## M-01 — MCP server decision-module inventory

Root cause: profile-specific SDK resource registration introduced one branch
exit in `mcp_server.py`, while the closed 100% decision-module inventory still
treated the module as branchless. The branch itself is required so the
metadata-only profile does not advertise private resource methods.

- Initial reproduction (RED): the former branchless invariant failed with
  `assert 1 == 0` (`1 failed`).
- Behavioral test RED: the replacement test observed one branch and failed
  because `src/nplg_mcp/mcp_server.py` was absent from the parsed repository
  policy (`1 failed`).
- Minimal GREEN: register the module consistently in the closed runner,
  repository policy, and exact policy fixture; focused policy checks passed
  (`2 passed`).
- Branch proof: SDK boundary/client tests exercised both profiles and reported
  `mcp_server.py` at 19/19 statements and 2/2 branch exits (`39 passed`, 100%).

## M-07 — Deterministic baseline tests and external-gate registry

Root cause: three Git/filesystem-only baseline checks carried the `live` marker
and appeared in the external registry without any protected command or result
contract, so the authoritative deterministic suite excluded them.

- RED: a marker-contract test failed for each local check, and a registry
  contract test failed on the first entry without a `gate_id` (`4 failed`).
- Minimal GREEN: remove the three `live` markers and their pseudo-external
  entries while preserving the actual protected NPLG canary (`5 passed`).
- Candidate-selection proof: the three checks executed under
  `not live and not staging and not container` (`3 passed`).

## M-08 — Single Python resolution authority

Root cause: runtime, CI, and Alpic installation consume the three hash-pinned
`requirements*.lock` files, but an unused generated `uv.lock` remained tracked
as a second project-resolution authority.

- RED: the new repository lock-inventory test found `uv.lock` present
  (`1 failed`).
- Minimal GREEN: delete only the unused generated lock; the lock inventory,
  runtime-lock completeness, and Alpic hash-locked install tests passed
  (`3 passed`). The bootstrap `uv` executable pin remains unchanged.
- Evidence note: an initial neighboring-test command named a nonexistent test
  node and exited 4; it was discarded and replaced by the two actual deployment
  contract nodes above.

## M-04 — Auth0/Alpic DCR capability blocker drift

Root cause: the strict Pydantic and Zod schemas admitted the DCR-semantics
blocker, but the canonical negative producer still described no selected
topology, emitted no DCR registration mode, and preserved only two blockers.

- RED: Pydantic tests observed an empty registration-mode tuple and accepted
  two separate redigested blocker downgrades; independent Zod likewise accepted
  the first downgrade (`3 failed`, `1 failed`).
- Minimal GREEN: record only the selected Auth0/Alpic-DCR topology (not a tenant
  capability), require the exact three-blocker tuple and `dcr` mode in both
  validators, and regenerate the digest-bound negative contract.
- Focused proof: Python canonical/mutation cases passed (`6 passed`) and the
  independent Zod canonical plus downgrade tests passed (`2 passed`).

## M-02a — Distributed-profile catalog isolation

Root cause: startup rejected `distributed-full`, but the shared catalog helper
treated every non-metadata enum as `private-full` and returned eight tools.

- RED: a direct catalog call for `distributed-full` returned normally instead
  of raising (`1 failed`).
- Minimal GREEN: enumerate the two executable profiles and reject the third
  with the existing stable startup blocker.
- Focused proof: direct catalog denial, pre-service startup denial, and the
  metadata no-full-import invariant passed (`3 passed`).

## H-04a — Immutable Alpic Tasks source provenance

Root cause: the digest-bound Tasks evidence referenced the mutable Python SDK
`main` branch, and both runtime authorities required an HTML representation
rather than the commit-pinned raw roadmap bytes.

- RED: Pydantic rejected the desired `text/plain` commit capture and accepted
  the mutable VCS URL (`2 failed`); independent Zod rejected the desired
  immutable record (`1 failed`).
- Minimal GREEN: require the exact raw GitHub path shape with a 40-character
  commit, allow the source-specific media-type tuple, and update the probe's
  request/response contract.
- Primary-source capture: commit
  `959569ba1505897bd8d824a1bf22800672f7cf14` returned 2,178 bytes with SHA-256
  `0f0fe55860893d5ab638e898c02b2a44c676bc7d793f2aa24c134b44fe9a45f8`;
  the source-evidence and verdict digests were regenerated from canonical JSON.
- Focused proof: Python source, verdict, and probe tests passed (`27 passed`),
  and independent Zod source-splice, support-forgery, and immutable-provenance
  checks passed (`3 passed`).

## M-05 — PDF pipeline-semantic cache identity

Root cause: render identifiers, tile cache namespaces, and persisted manifests
bound dependency versions and geometry but omitted four semantic revisions, so
an algorithm-only change could reuse stale derivatives.

- RED 1: the new strict semantic-version contract could not be imported during
  collection (`1 error`).
- Minimal GREEN 1: add a frozen, extra-forbidden Pydantic model with canonical
  semantic-version strings and bind all four fields into the render digest and
  the tile geometry identifier (`10 passed`).
- RED 2: render/tile manifests exposed no version fields; four redigested render
  policy changes were accepted; a changed tile version remained cached
  (`6 failed`, with the existing renderer mismatch still passing).
- Minimal GREEN 2: serialize and strictly parse all four version fields, require
  their exact current values, and include the tile-pipeline version in every
  tile namespace and identifier (`17 passed`).
- Regression proof: the complete PDF integration module passed (`84 passed`).

## H-02b — Task 16A worker-slot policy authority alignment

Root cause: the executable checked-in policy bound the worker to the reviewed
1 GiB/65,536-inode root and minimum headroom, while the implementation plan
still named an obsolete 2 GiB schema without the root or headroom fields.

- RED: a new byte-exact static contract accepted the deployed canonical policy
  but failed because the Task 16A plan did not contain the same contract
  (`1 failed`).
- Minimal GREEN: replace only the stale policy sentence with the exact current
  canonical JSON and describe its root, upper bounds, and required available
  headroom; the contract passed (`1 passed`).
- Phase 6 ordering repair: the former production missing-policy test failed at
  the now-authoritative static-auth/OAuth stop before reaching the worker slot.
  Its missing-file assertion now exercises the explicit local loader seam;
  focused worker-slot and production OAuth tests passed (`23 passed`).
- Regression proof: deployment, configuration, worker-slot, OAuth-activation,
  and plan-policy suites passed together (`150 passed`); Ruff format/check,
  strict mypy, Pyright, and markdownlint all passed on the changed surfaces.

## H-02c — Task 16A retention runtime composition and trustworthy clock

Root cause: strict retention, reservation, and restart-state primitives existed,
but no bounded environment settings or private-full runtime composition selected
them. The runtime therefore constructed a legacy store and a downloader with no
retention authority.

- Configuration RED: the desired bounded defaults were absent and nine invalid
  values were accepted (`10 failed`). Minimal GREEN added exact integer/boolean
  parsing and closed limits (`10 passed`).
- Clock RED: the system sampler did not exist (`1 collection error`). An initial
  GREEN attempt exposed an over-strict concrete-`Path` check (`9 failed`);
  accepting platform `Path` subclasses while retaining non-following,
  descriptor-identity, ASCII, length, and canonical-ID checks passed all valid,
  malformed, oversized, invalid-UTF-8, and symlink cases (`9 passed`).
- Runtime RED: the private-full profile still produced a downloader whose
  `retention_policy` was `None` (`1 failed`). Minimal GREEN composes one strict
  policy, restart-stable `ClockHighWater`, kernel-backed clock sampler, lifecycle
  store, and downloader authority (`1 passed`). Production's verified worker
  slot additionally selects the aggregate PDF reservation wrapper.
- Documentation RED/GREEN: the strict environment example lacked all seven
  lifecycle controls (`1 failed`), then documented exact fail-closed values
  (`1 passed`). Clock synchronization deliberately defaults to `false` until a
  protected host supplies that operational fact.

## H-02d — Download publication inode under-reservation

Root cause: admission reserved two inodes for a downloaded object, but lifecycle
mode persists three: the object directory, source PDF, and insertion-sequence
record.

- RED: with exactly two inodes above the protected reserve, admission reached
  the network instead of failing (`1 failed`).
- Minimal GREEN: reserve and commit the exact three-inode topology; the same
  case now reports `inode_headroom` before network or staging (`1 passed`).
- Regression proof: configuration, lifecycle/storage properties, downloader,
  profile composition, deployment, worker-slot, and aggregate PDF reservation
  suites passed together (`344 passed`). Ruff and strict mypy passed on the
  complete slice; Pyright reported zero errors and zero warnings.

## M-06 — Private-profile frozen resource parity

Root cause: profile isolation correctly removed resource registration from
`alpic-metadata`, but the SDK differential test removed frozen resource
list/read comparison instead of relocating it to `private-full`.

- Structural RED: the live parity module loaded only tool/result fixtures and
  contained no `resources.json`, `list_resources`, or `read_resource` path,
  reproducing the audit's missing-assurance condition.
- Minimal GREEN: a private-full differential test now digest-verifies the
  frozen resource fixture and compares both the complete `nplg://about` catalog
  projection and its read contents against the official SDK (`1 passed`). No
  accepted-difference entry was added because the normalized values are equal.
- Regression proof: SDK parity, client resource behavior, and SDK boundary
  suites passed together (`51 passed`); Ruff, strict mypy, and Pyright passed.

## M-05b — PDF IPC semantic-version boundary parity

Root cause: persisted render and tile dataclasses serialized the four current
pipeline identities, but the private worker IPC models still treated them as
extras. The parent-side tile validator and adversarial worker fixtures also
reconstructed the obsolete unversioned identity shapes.

- RED 1: canonical page and tile IPC payloads failed because all four version
  fields were extra-forbidden (`2 failed`). Minimal GREEN made the fields
  required strict semantic versions on one shared immutable IPC base; missing,
  malformed, and extra metadata cases passed (`10 passed`).
- RED 2: every semantically valid `2.0.0` field mutation was accepted by both
  derivative schemas (`8 failed`). Minimal GREEN rejects any value different
  from the current frozen pipeline authority; the complete IPC property module
  passed with strict-type, non-ASCII, prerelease, zero-major, and coercion
  adversaries (`53 passed`).
- Downstream RED/GREEN: the unchanged public MCP output schemas rejected private
  IPC-only version metadata (`7 failed`). The explicit IPC-to-public adapter now
  removes exactly those four fields, and a named negative test proves none leak;
  the tool/profile slice passed (`125 passed`) and the MCP app/parity slice
  passed (`142 passed`). Private IPC and on-disk manifests retain the fields.
- Identity parity RED/GREEN: versioned render and tile identities initially
  short-circuited adversarial worker checks as stale render/tile IDs. Both the
  parent validator and fixtures now use the shared identity functions; all 25
  affected worker cases passed. PDF integration also passed (`84 passed`).
- Broader worker evidence: `93 passed, 2 failed`; the two failures are isolated
  to concurrent asset-lease error-precedence tests for malformed render roots
  without manifests, not semantic-version behavior, and are not represented as
  GREEN here.
- Static proof: Ruff passed on the owned semantic-version source/test fixtures,
  strict mypy passed on five core semantic-version files, and Pyright reported
  zero errors/warnings on the full touched slice. Full-slice Ruff/mypy remained
  blocked by separately owned concurrent lease changes and are not claimed.

## H-02e — Task 16A read, stream, and worker-staging leases

Root cause: lifecycle pruning protected render transactions but the HTTP asset
response, MCP resource readers/content hashers, and parent-side PDF input
staging resolved paths without holding the owning document/render object lease
for the complete operation. Pressure pruning could therefore remove an object
after resolution but before or during a read.

- HTTP RED: a real lifecycle store deleted an actively blocked response object,
  and its public lease acquire/release ledger remained `0/0` across success,
  send error, disconnect, and task cancellation (`4 failed`). Minimal GREEN
  defers file resolution to response execution, holds the lease across the
  disconnect-aware stream, and releases it in the response context on every
  terminal path (`4 passed`).
- Worker-staging RED: neither source-file nor render-tree staging entered the
  public store lease, so three barrier-controlled operations completed without
  a protected object (`3 failed`). Minimal GREEN leases the source during its
  identity-bound copy and leases a completed render through its root
  `manifest.json` while copying the complete tree; worker-error and cancellation
  paths balance the lease exactly once (`3 passed`).
- Error-precedence regression RED: leasing the completion manifest first made
  two malformed render trees report only `unavailable`, hiding the prior stable
  symlink/special-file classification (`2 failed`). The missing-manifest branch
  now performs a non-following, deadline-bounded diagnostic scan and still
  rejects before spawn without disclosing paths; the absent, directory-symlink,
  and file-symlink cases passed with the lease tests (`6 passed`).
- Tool/resource RED 1: document reads, render-content hashing, and integrity
  failure cleanup acquired no lease (`3 failed`). Minimal GREEN holds a real
  object lease across byte reads and the entire stat/open/digest sequence
  (`3 passed`).
- Tool/resource RED 2: registered render reads acquired no lease, while duplicate
  registration leased only its content-hash input and not the persisted index or
  representative verification reads (`2 failed`). Minimal GREEN leases each
  read; the duplicate path proves the exact page/index/page acquisition sequence
  and balanced `3/3` release ledger (`2 passed`).
- Regression proof: the complete MCP HTTP conformance plus tool unit suites
  passed (`200 passed`), and the complete parent-side PDF worker security suite
  passed (`95 passed`). Adjacent lifecycle and storage unit suites also passed
  on the integrated latch/recovery state (`132 passed`). The initially observed
  two tool regressions were corrected by restoring fail-closed invalid-index
  precedence and replacing an out-of-namespace test bypass with a real in-store
  digest mismatch before that final run.
- Static proof: Ruff check/format, strict mypy, and strict Pyright passed on all
  eight changed source/test surfaces. The staged-index digest remained
  `19b2538c773e43055fa248d72fb995abf4d6f83713f8539ebaa4bb70d30b716a`.
- Boundary: these are in-process operation leases. Process-death recovery and
  cross-process exclusion remain governed by the separate recovery/worker
  authority contracts and are not claimed by this evidence.

## H-02f — Closed-admission recovery latch and readiness reconciliation

Root cause: a rejected aggregate publication reservation or an unsatisfied
prune failed closed for that call, but the store did not retain an admission
blocker. A later request could retry without an explicit, observed lifecycle
reconciliation, and no bounded path-free alert marked the transition.

- RED 1: the strict lifecycle alert model was absent and repeated reservation
  attempts had no persistent closed-admission state. Minimal GREEN added strict
  enumerated blocker/event models, retained the first blocker, emitted exactly
  one low-cardinality alert for the transition, kept repeat denials silent, and
  reopened only after a satisfied prune (`2 passed`).
- RED 2: after a reservation denial and genuine capacity recovery,
  `ToolService.ensure_ready()` left lifecycle admission closed (`1 failed`).
  The first GREEN attempt correctly remained fail-closed because the fixture
  still contained a future-dated, unprunable render object; the test was fixed
  to model actual recovery rather than weaken the guard. Minimal GREEN now
  reconciles configured lifecycle storage during private-full readiness,
  returns a path-free 503 while pruning remains unsatisfied, and clears the
  latch only on a satisfied report (`1 passed`).
- Runtime telemetry uses only strict event and blocker values; observer failure
  cannot change lifecycle enforcement. Stores without lifecycle configuration
  retain their prior local-test behavior.
- Integrated storage, lifecycle, downloader, publication-reservation, and
  private-profile regression proof passed before the readiness hook (`211
  passed`). Full-suite and release-gate evidence is recorded separately and is
  not implied here.

## M-06b — Complete frozen resource/template differential coverage

Root cause: the relocated private-profile parity test consumed only the frozen
resource list and `nplg://about` case. The digest-verified artifact/render cases
and the official resource-template catalog had no differential assertion or
accepted-difference coverage.

- RED: the expanded parity test required the exact four modern frozen resource
  cases plus all two official templates and failed on three absent ledger
  records (`2 failed`).
- GREEN: list/about remain byte-semantically equal. The deliberate artifact
  binary-content transition, current version-bound render identity, and the two
  official private templates are each bound to reviewed frozen/current
  canonical digests in the closed difference ledger (`2 passed`). Duplicate,
  missing, or unknown difference case IDs now fail the test.
- Regression RED: the broader immutable-baseline suite exposed that the new
  render and tile identity algorithms were still compared to obsolete literal
  IDs before semantic normalization, and one suppression-inventory location
  was stale (`52 failed` in the first aggregate run).
- Regression GREEN: replay setup now validates the live render ID by
  recomputation, substitutes it only for live execution, validates the
  versioned tile-geometry key, and normalizes only those two reviewed identity
  tokens back to the immutable oracle. The baseline files were not changed.
  Frozen baseline, SDK parity, and SDK client suites passed (`570 passed`).
- Ruff, strict mypy, and strict Pyright passed on the replay/parity slice.

## H-02g — Held-root capacity authority and bounded orphan recovery

Root cause: lifecycle capacity sampling reopened the configured cache path for
each observation, so a root rename/replacement could redirect admission or
pruning to a different filesystem. Startup orphan cleanup also used an
unbounded `iterdir`/`shutil.rmtree` walk that silently deleted symlinks and
special files and did not bind inventory to deletion identities.

- Held-root RED 1: directory and symlink replacement both reached pruning
  without an identity error (`2 failed`). Minimal GREEN holds a non-inheritable
  `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` root descriptor plus device/inode identity,
  rejects a closed or drifted configured path, and samples production
  byte/inode capacity with `fstatvfs` on that descriptor (`2 passed`).
- Held-root RED 2: publication entry and commit reported downstream lifecycle
  blockers after root replacement instead of the bounded root-identity error
  (`1 failed` each). Both boundaries now verify the held/current identity before
  clock mutation, capacity sampling, inventory, reservation accounting, or
  staging effects (`1 passed` each). Pruning performs the same check before its
  pre-prune sample and the held descriptor supplies both pre/post samples.
- Secure-open RED: deleting `O_NOFOLLOW` support still allowed a store to start
  (`1 failed`). Startup now fails closed unless the secure directory descriptor
  flags exist (`1 passed`); regular orphan verification additionally requires
  Linux metadata-only `O_PATH|O_NOFOLLOW|O_CLOEXEC` opening.
- Orphan RED 1: symlink/FIFO entries and a 4,097-entry staging inventory were
  silently deleted, including partial cleanup risk (`3 failed`). Minimal GREEN
  inventories the complete tree before deletion, bounds it to 4,096 entries,
  eight directory levels, and `max_bytes`, restricts names, requires one device
  and single-link regular files, and rejects symlinks/special files (`5 passed`
  with the stale-regular positive case).
- Orphan RED 2: an over-deep/oversized tree was accepted (`1 failed`), and a
  deterministic regular-file-to-symlink swap before descriptor open was not
  observed (`1 failed`). Descriptor-relative stat/open/identity checks now
  reject both; deletion rechecks the inventoried identity, never follows the
  substituted path, and verifies that the held single-link inode reached link
  count zero (`1 passed` for the race plus the bounded suite above). The outside
  target remains unchanged.
- Restart acceptance: a second store removed a still-open crashed staging file
  and reconstructed staging and aggregate publication reservation counters as
  exact zero while the simulated crashed instance retained non-zero process-local
  ledgers (`1 passed`). Cleanup of the simulated old context then balanced its
  independent ledgers.
- Regression proof: storage, lifecycle, and aggregate PDF publication
  reservation modules passed together (`157 passed`). The canonical scoped
  `run_quality_gate.py` invocation passed with the locked Node 24.19.0/Pyright
  1.1.413 path; Ruff check/format, strict mypy, and strict Pyright independently
  passed on all five code/test surfaces (`0 errors`, `0 warnings`).
- Boundary: orphan recovery is a bounded local startup proof, not the protected
  process-kill recovery verifier or external worker/storage authority evidence.
  Those remain separate fail-closed release requirements and are not claimed by
  this cycle.

## H-02h — Strict private recovery policy and fail-closed diagnostic verifier

Root cause: the checked-in release registry named a protected recovery gate,
but candidate code had only an exit-zero schedule wrapper. It did not bind the
unique-source backup and derived-render regeneration subjects, persistent
high-water state, truthful process-ledger reconstruction, recovered ownership
and modes, or a measured RTO receipt. The exact Task 16A mutation and decision
coverage policies also omitted this verifier surface.

- Policy ownership/mode RED: the strict Python contract had no
  `filesystem_expectations`; seven drift cases and the positive expectation
  failed (`8 failed`). The independent Zod positive case also failed while its
  existing negative case passed (`1 failed, 1 passed`). Minimal GREEN binds UID
  and GID `10001`, directory mode `0700`, regular-file mode `0600`, forbids
  symlinks and hard links, and binds the exact subject/state/staging scope (`8
  passed`; independent Zod `2 passed`). The canonical policy digest is
  `sha256:6a9f6786479f139129f57c95d18820f55dc192a44d7d32d6ce2a385fe325bbf3`.
- Verifier RED: `.venv/bin/python -m pytest
  tests/unit/test_private_recovery_verifier.py -q` reached the intended missing
  API (`verify(..., recovery_policy=...)`) and produced `40 failed, 1 passed`.
  Minimal GREEN adds a strict canonical, duplicate-free, integer-only Pydantic
  diagnostic receipt, policy/request/digest binding, exact source restore and
  derived regeneration identities, the ordered five-item state inventory,
  high-water identity, empty post-termination lease/reservation ledgers,
  owner/mode/link/content observations, monotonic RTO, complete-loss and cleanup
  checks, and a descriptor-relative exclusive mode-`0600` result writer. The
  result is always `external_authority_required`, `release_authoritative=false`,
  and `do_not_release` (`46 passed`).
- Decision-coverage RED/GREEN: the first focused branch run passed all 41 then
  existing cases but failed the coverage gate at `94.16%`; duplicate
  image/probe, integer-overflow, and policy-revalidation cases plus removal of
  an unreachable post-validation subject-type branch produced `215` statements
  and `36` branches at exact `100%` (`46 passed`).
- Mutation-policy RED/GREEN: the documented eight-target Task 16A request first
  failed as outside the closed policy (`1 failed`). The exact target order,
  nine-test adversarial suite, module map, and required mutmut function
  inventory then passed (`1 passed`). An independent read-only mutmut `3.7.0`
  generation comparison matched every required function for all eight targets.
- Coverage-policy RED/GREEN: all six Task 16A decision modules were absent (`1
  failed`). The canonical policy, executable closed tuple, parser fixture, and
  inventory assertion now include malware, PDF worker client, storage, scanner
  verifier, quota verifier, and recovery verifier (`2 passed`).
- Release-binding RED/GREEN: a coherently changed and redigested recovery policy
  was accepted, and the executable local-gates path never loaded release
  policies (`2 failed`). `load_release_policies()` now requires the exact
  reviewed recovery-policy digest, and the CLI loads that binding before local
  gate execution; the checked-in policy still reports external authority
  required and the candidate release status remains `do_not_release` (`4
  passed`).
- Boundary: no real volume was destroyed, no backup or restoration was
  performed, no hosted RTO was measured, and no controller signature was
  created or accepted. Signed `recovery-proof.v2`, the privileged runtime/slot
  broker, and operational recovery acceptance remain exclusively external and
  unresolved; the candidate diagnostic can never satisfy that gate.

## H-02i — Runtime storage trust closure after independent falsification

Root cause: held-root lifecycle admission did not yet protect ordinary artifact
operations, path resolution still followed an internal symlink before checking
it, pre-existing modes and state files could be trusted or laundered, and the
full-runtime composition resolved a configured cache symlink before the store
could reject it.

- Monotonic-state RED: after a trusted observation window, a UTC rollback was
  rejected once but the previously trusted window could be reused on the next
  observation (`1 failed`). GREEN persists the untrusted observation, resets
  the healthy window, and preserves the UTC high-water mark (`1 passed`).
- Private-mode RED: permissive roots, wrong-owner namespaces, configured root
  symlinks, and default-mode object directories were accepted (`4 failed`).
  GREEN requires exact service ownership plus `0700` directories and `0600`
  single-link regular files; all newly created paths reach those modes even
  under a restrictive umask (`7 passed`).
- Complete-tree RED: permissive artifact directories/files, hard links, and an
  unreadable directory were accepted or silently skipped (`4 failed` across
  the two focused runs). GREEN replaces the path walk with a bounded,
  descriptor-relative, non-following inventory that validates ownership, exact
  modes, link counts, depth, entries, bytes, and identity before cleanup or
  accounting (`4 passed`).
- Lifecycle-state RED: a valid mode-`0666` high-water record was trusted and
  rewritten, while a restrictive umask produced a mode-`000` state file that
  failed only on the next read (`2 failed`). GREEN authenticates exact metadata
  before parsing, refuses to overwrite corrupt state, and enforces a `0600`
  postcondition on state writers (`2 passed`).
- Composition/path RED: full-runtime cache symlinks, a replaced configured
  root, and two same-root source aliases reached the store (`4 failed`). GREEN
  preserves the configured path for store validation, verifies held/current
  root identity at every staging/publication/render/resolve boundary, validates
  the parent chain, and walks assets from the held root descriptor without
  following intermediate or final symlinks (`4 passed` across the focused
  root/alias slice plus the runtime wrapper case).
- Compatibility RED/GREEN: the stricter render path initially mapped final
  destination symlink corruption to `INVALID_INPUT` instead of the established
  `INTERNAL_ERROR` contract (`2 failed`). Final symlinks now remain internal
  corruption while intermediate symlinks remain invalid input (`4 passed`),
  and storage, lifecycle, and full-runtime publication regressions passed
  together (`180 passed`).
- Boundary: returning a validated `Path` does not turn the caller's later file
  open into an independent cross-UID descriptor capability. The exact `0700`
  parent and namespace policy treats the service UID as the local trust domain;
  protected worker/controller isolation remains external.

## H-03b — Executed adversarial PDF corpus and private worker staging

Root cause: corpus hashes and manifest declarations were checked, but none of
the six non-inert fixtures were sent through the real disposable worker. The
strict store changes then exposed a latent worker bug: recursive parent creation
staged the `documents` namespace as `0755`, so the worker rejected every staged
cache before parsing the PDF.

- Behavioral RED: the manifest-partition test passed, but all six real worker
  cases returned the same generic internal failure (`6 failed, 1 passed`),
  including the valid reuse and bounded-metadata documents. This falsified a
  fixture-specific parser explanation.
- GREEN: worker staging now creates and verifies every job/cache namespace at
  exact service-owned `0700`, hardens the `mkdtemp` result under restrictive
  umasks, and preserves staged source files at `0600`. Three invalid fixtures
  return typed `INVALID_DOCUMENT`; two hostile declarations return finite,
  one-page strict metadata without a render allocation; and two concurrent
  calls reuse the valid fixture without changing its bytes, identity, mode, or
  link count (`7 passed`).
- Negative follow-up: inert crash/timeout labels are expressly excluded from
  execution evidence, restrictive-umask staging succeeds, permissive or
  symlinked pre-existing worker roots fail before spawn, missing secure-open
  primitives fail closed, and authoritative render symlinks retain bounded
  diagnostics (`14 passed` focused).
- Regression proof: the complete disposable-worker security suite plus the new
  corpus-worker suite passed (`105 passed`). The corpus does not claim protected
  process-kill, quota-controller, or hosted timeout/crash evidence; those labels
  remain non-evidentiary test selectors.

## H-02j — Lifecycle cleanup completeness and exact branch coverage

Root cause: the lifecycle policy did not enumerate every temporary-writer
function, two interrupted writers could leave orphan temporary files, and the
focused decision module was below the repository's exact branch-coverage
standard.

- Registry RED/GREEN: omitting a lifecycle writer from the closed mutation
  inventory failed (`1 failed`); the exact required inventory now contains all
  `34` lifecycle functions and the mutation-policy test passes (`1 passed`).
- Coverage RED/GREEN: the lifecycle module initially passed its behavioral
  suite but reached only `81.72%` branch coverage (`43 passed`). Adversarial
  boundary, rollback, corruption, ownership, mode, and cleanup cases now cover
  all `613/613` statements and `154/154` branches (`86 passed`, exact `100%`).
- Orphan-cleanup RED/GREEN: injected failures in the two atomic writers left
  temporary artifacts (`2 failed`). Both writers now remove their private
  temporary paths on every unsuccessful exit, and the same fault-injection pair
  passes (`2 passed`). An inverted `0600` postcondition mutant is killed by the
  focused suite.

## Strict analyzer closure — Typed PDF identity and persisted JSON

Root cause: strict full-tree analysis exposed call boundaries whose dynamic
argument and JSON access shapes admitted `Any`, even though focused runtime
tests passed.

- RED: the quality wrapper rejected a six-argument render identity boundary,
  unconstrained JSON dictionaries, and dynamic manifest attribute/value access;
  the final mypy reproduction reported two `Expression has type "Any"` errors.
- GREEN: strict frozen Pydantic request models now validate render and tile
  identity inputs; external JSON is narrowed before canonicalization; manifest
  assertions use explicit typed fields and runtime string narrowing. The
  focused manifest behavior passes (`1 passed`), and the complete fail-closed
  quality wrapper passes Ruff plus Pyright and mypy for Python `3.12`, `3.13`,
  and `3.14` without suppressions.

## H-02k — Sticky-parent storage admission compatibility

Root cause: parent admission treated a sticky shared directory such as `/tmp`
as equivalent to an unprotected world-writable directory. That rejected a
service-owned private cache before the disposable private-full PDF worker could
be composed.

- Integration RED: the gate-equivalent suite failed in
  `test_private_full_uses_the_disposable_pdf_executor_without_importing_pdfium`
  because a `tempfile` cache under `/tmp` raised `cache root parent must not be
  writable by another principal` (`1 failed`, after `985 passed`).
- Focused RED: a service-owned `0700` cache beneath a service-owned `01777`
  parent reproduced the rejection (`1 failed`).
- GREEN: a writable immediate parent is admitted only when it is owned by root
  or the service and its sticky bit protects the service-owned cache entry from
  replacement. Non-sticky writable parents and symlink aliases remain rejected;
  the new unit, both existing negative variants, and the private-full
  integration pass together (`4 passed`).

## ASVS closed-inventory preservation

- RED: the gate-equivalent suite reached `53%` and failed
  `test_check_mode_is_deterministic_and_side_effect_free` after `2076 passed`
  because this remediation ledger had been created inside the closed
  `docs/security` evidence-authority directory.
- GREEN: the non-authoritative TDD log now lives under ordinary `docs/`; the
  security inventory was not expanded, the deterministic ASVS check succeeds,
  and its focused side-effect/integrity test passes (`1 passed`).

## Task 18 — Deterministic two-second parser resource gate

Root cause: the accepted 50,000-node corpus repeatedly selected the same
metadata and bitstream structures with whole-DOM SoupSieve scans, leaving too
little headroom beneath the fixed two-second absolute process budget.

- RED: the gate-equivalent suite timed out after `1184 passed`; a quiescent
  five-run reproduction failed once, while profiling identified repeated
  metadata/bitstream selectors as avoidable work. The security budget was not
  raised or skipped.
- GREEN: metadata rows and direct cells are collected once with a de-duplicated
  native traversal; bitstream candidates are likewise collected once; the
  full-metadata check short-circuits on already collected rows. Public
  adversarial tests preserve multi-class/nested document order, prevent nested
  duplicates, and ignore empty or absent hrefs.
- Evidence: ten quiescent child runs completed in `1.57–1.83s`; measured parser
  work was `1.26–1.48s`, and peak RSS remained below `109 MiB`. The full parser
  unit/property slice passes (`238 passed`) with Ruff, mypy, and Pyright clean.

## Private namespace fixture and suppression-policy closure

- Fixture RED/GREEN: after `2272 passed`, the real render-deletion entrypoint
  fixture was rejected because it created `renders/` at default `0755`. The
  fixture now creates the production-required `0700` namespace; the complete
  CLI slice passes (`17 passed`). Production admission was not relaxed.
- Suppression RED: the closed compatibility inventory observed six suppressions
  instead of three, then four instead of three after the first cleanup.
- GREEN: descriptor-relative emptiness checks use `os.scandir(fd)` and the
  deliberately isolated alert observer uses `contextlib.suppress(Exception)`.
  No suppression was added to the reviewed Task 6A path inventory; its exact
  three compatibility exceptions plus the storage/lifecycle/publication slice
  pass (`225 passed`).

## Decision-module synthetic gate parity

- RED: the real-CLI positive coverage fixture failed because newly mandatory
  Task 16A modules, beginning with `malware.py`, had no branch evidence.
- GREEN: the synthetic repository now derives dotted imports and true/false
  executions from the same closed `decision_modules` policy. The complete case
  succeeds and the negative case still rejects the intentionally uncovered
  `errors.py` branch (`2 passed`); the remaining unit collection passes (`218
  passed`).

## Gate-order clock determinism and observable full-suite behavior

- RED: the first gate-equivalent run reached `3134 passed` before a lifecycle
  pruning test classified a freshly created leased tree as a future-clock
  anomaly. The module-level clock origin had been captured long before the
  delayed full-suite test created that tree. A second run exposed the same
  missing fixture precondition in the pressure variant.
- GREEN: every pruning fixture now sets its tree mtime relative to the explicit
  synthetic clock origin, including the render-transaction lease case. The
  complete lifecycle module passes (`86 passed`) independently of collection
  order.
- Observable full run: a fresh branch-measured invocation completed with
  `3809 passed, 1 skipped, 117 subtests passed`. The sole skip is the explicitly
  external live NPLG authority. This proves pytest behavior only; the subsequent
  project coverage decision remained a separate RED.

## M-01/L-01 — Exact decision coverage and project-floor closure

- Project RED: the authoritative runner's pytest command completed, but its
  post-test coverage command rejected the candidate. Fresh XML/JSON-compatible
  evidence measured the complete `src/nplg_mcp` plus `scripts` roots at roughly
  `93%`, below the fixed `95%` floor. Several registered decision modules also
  lacked exact branch evidence.
- Impossible-policy RED: `verify_scanner_container.py` and
  `verify_pdf_worker_quota.py` were in the closed `100%` decision inventory but
  contained zero branches. Permissive-delegate tests first showed that each
  wrapper could rely entirely on generic validation (`2 failed`). Each wrapper
  now binds its own verifier discriminator before delegation; confused requests
  fail closed, accepted requests delegate, and both modules have exact statement
  and branch coverage (`4 passed`).
- Root edge closure: adversarial DNS CNAME ambiguity/duplication/cycle/unrelated
  chain tests, repeated-record de-duplication, PDF publication under-reservation
  and nonpublication bypass, metadata-profile resource non-disclosure, strict
  cursor lifetime/key/query/JSON/signature/version tests, non-node pytest output,
  non-object recovery receipts, and release manifest/transcript mutants close
  all previously missing branches in their registered modules. A redundant
  release subcommand guard whose regex precondition made it unreachable was
  removed while the public unsafe-subcommand rejection remains tested.
- Storage RED/GREEN: the focused baseline passed `230` tests but measured only
  `85.30%`; fault injection then proved `_StagedWriter` construction could leak
  a zero-byte reservation. Failure cleanup now atomically removes that
  reservation. Descriptor-race, lifecycle, reservation, orphan-recovery, and
  accounting tests pass (`325 passed`), with `1542/1542` statements and
  `454/454` branches covered.
- Malware RED/GREEN: the baseline was `65.27%`; malformed `SO_PEERCRED` leaked a
  connection and valid ClamAV `stream: <detail> FOUND|ERROR` replies were
  rejected. Cleanup and reply parsing are corrected; `51` tests cover all
  `279/279` statements and `58/58` branches.
- PDF-worker client RED/GREEN: the initial focused slice passed `213` tests but
  left `70` statements and `29` branch arcs uncovered. Filesystem identity,
  manifest cross-wiring, process-group, Unix-peer, cancellation, staging, and
  quota edge tests now pass (`255 passed`) with all `799/799` statements and
  `238/238` branches covered; production behavior did not require a change.
- Pre-authoritative diagnostic union: the full observable run plus all focused
  GREEN evidence reaches `95.2376%` combined statement/branch coverage
  (`29297/30762`) and all `29` registered decision modules have exact branch
  coverage. This union is a diagnostic readiness check, not a substitute for
  one fresh authoritative gate run.

## Schema authority freshness

- Registry verification on 2026-08-25 reports Zod `4.4.3`; the installed
  `package-lock.json` authority is also exactly `4.4.3`.
- Runtime Python validation remains Pydantic `2.13.4`, identically pinned in all
  three reviewed Python lock authorities, with strict closed models at trust
  boundaries.

## Authoritative collection capacity and stable test identity

- RED: the authoritative collection preflight exceeded the bounded command's
  default `4 MiB` stdout ceiling (`4,645,280` bytes). The parser's closed
  inventory already permitted up to `32 MiB`, so both complete and marker
  collection requests now use that existing reviewed ceiling; the focused
  command-request regression passes.
- Second RED: one adversarial PDF-worker manifest parameter embedded its entire
  `4 MiB` payload into the pytest node ID, violating the existing `16 KiB`
  per-node limit. Stable semantic IDs (`invalid-json`, `oversized-json`) retain
  the payload without weakening the identity bound.
- GREEN: fresh collection reports `4,026` nodes, `450,948` stdout bytes, no
  malformed/out-of-prefix/oversized IDs, and a maximum node length of `4,180`
  bytes.

## PEP 561 snapshot TOCTOU and storage-test hygiene

- RED: the gate-equivalent suite failed at the PEP 561 artifact integration
  because `_tree_sha256` compared complete `stat_result` objects. A read-induced
  access-time update was therefore misclassified as source mutation. A focused
  regression first failed because no stable identity helper existed.
- GREEN: tree and single-file hashing now share an identity of device, inode,
  mode, link count, owner, size, mtime, and ctime while deliberately excluding
  atime. The test proves atime-only equality and real content-mutation
  inequality; the artifact-only PEP 561 integration passes.
- Hygiene RED: the new mode-`000` storage adversarial case left pytest unable to
  remove its own temporary directory. `try/finally` restores private directory
  and file modes. Two consecutive focused runs pass without cleanup warnings.
- Suppression RED: the Task 6A closed inventory rejected a new file-wide
  `SLF001` directive in `test_storage.py`. Public storage-contract tests remain
  in that suppression-free reviewed module; descriptor/race/recovery fault
  injection is isolated in `test_storage_internals.py`, whose explicit
  private-access directive is confined to white-box tests. The closed Task 6A
  inventory is again exact.
- GREEN: the reorganized four-file storage slice passes `325` tests with
  `storage.py` at `1542/1542` statements and `454/454` branches. The strict
  quality wrapper passes Ruff, mypy, and Pyright for Python 3.12, 3.13, and
  3.14. A fresh gate-equivalent behavioral run passes `4026` tests and `117`
  subtests; the single skip remains the absent live NPLG authority.

## Independent adversarial review and authoritative branch closure

- The first authoritative project run was RED at `6169/6594` branches
  (`93.5547467%`), below the exact `95%` project policy. Focused branch tracks
  therefore treated uncovered decisions as test deficits, not as permission to
  weaken the gate.
- Private TLS RED/GREEN: the initial edge slice covered only `30/60` branches.
  Thirty-nine focused tests now cover `201/201` statements and `60/60`
  branches without a production change.
- Baseline-capture RED/GREEN: the initial slice covered `1116/1275` statements
  and `272/330` branches. Five hundred ninety focused tests now cover all
  `1275/1275` statements and `330/330` branches without a production change.
- PDF-worker slot RED: a foreign quota could release a lease, a released lease
  could re-enter, and a Unix listener remained open when socket-mode setup
  failed. A first fix was deliberately rejected after independent review found
  that forged or stale same-quota leases could still free an active slot.
  GREEN: the quota now binds the exact issued live lease under its lock and
  retires only that identity; forged, foreign, stale, direct, and repeated
  release paths are adversarially exercised. The slot slice passes `63` tests
  with `378/378` statements and `100/100` branches; listener cleanup also
  closes, waits, and unlinks on every setup/serve exit.
- Storage review reopened three masked tests. Public-mode failures had hidden
  the intended symlink/FIFO cases; a no-`O_NOFOLLOW` test bypassed store-root
  identity verification; and a compound invalid-tile test hid private page-file
  acceptance. Isolated valid-private prerequisites first exposed the intended
  RED paths. Creation now fails closed unless an exact integer `O_NOFOLLOW` is
  available, and the separated page/geometry/link/incomplete cases preserve
  accounting. The final slice passes `331` tests with `1543/1543` statements
  and `454/454` branches.
- PEP 561 review found a real path-substitution window: the path could still
  name the original file before and after a read while an attacker-controlled
  descriptor supplied different bytes. Three regressions first read `EVIL`
  content through the digest, tree, and copy boundaries. All reads now use a
  bounded descriptor opened with `O_NOFOLLOW`, with pre/open/post descriptor
  identity and final path identity checks plus deterministic close. The unit
  slice passes `56` tests, and both artifact-only and external-consumer PEP 561
  integration checks pass.
- Mutation-policy RED: the Task 16A exact test inventory omitted six new
  adversarial storage/PDF/tool suites. The closed policy now names them; all
  `88` mutation-gate policy tests pass.
- The strict Python quality wrapper and all Node contract lint, typecheck, and
  Zod contract tests pass after these changes. The next authoritative run
  advanced past the project floor and was RED specifically at the changed-arc
  policy. A reproducible diagnostic union measured `818/882` changed arcs
  (`92.743764%`), exactly `20` arcs short of the `95%` floor.
- Private-recovery branch RED/GREEN: the focused baseline left three branches
  unexercised (`17/20`): duplicate recipe paths, reordered subject identities,
  and a non-object JSON document. Three adversarial tests now prove each input
  is rejected; the focused result is `37 passed`, `209/209` statements, and
  `20/20` branches.
- Baseline-replay changed-arc GREEN: fourteen focused edge tests cover exactly
  `15` previously missing changed arcs, moving the diagnostic union for that
  module from `336/362` to `351/362` branches. Ruff, strict mypy, and Pyright
  pass with no production edit or analyzer suppression.
- Alpic-capability/probe RED/GREEN: the first focused run passed `68` behavior
  tests while covering none of the `17` requested changed arcs. Fault-injection
  tests for topology, blockers, source ordering/media/digest/URL, installed SDK
  drift, provenance, review dates, loader bounds, and before/during-read inode
  substitution now pass (`84 passed`) and cover all `15/15` capability arcs and
  `2/2` probe arcs. The probe has exact `44/44` branch coverage; no production
  edit or analyzer suppression was required.
- Verification-envelope RED: when `O_NOFOLLOW` was absent, proof publication
  silently opened a symlink-following path instead of failing closed. Both
  directory and proof-file opens now require an exact integer `O_NOFOLLOW`
  before any publication attempt. Descriptor-type, zero-write, invalid-path,
  fchmod cleanup/unlink, output-bound, and PEP 561 descriptor-identity tests
  pass (`11 passed`) with `ResourceWarning` promoted to an error. The focused
  track executes all six requested PEP arcs and replaces the unsafe fallback
  with covered fail-closed outcomes; Ruff, strict mypy, and Pyright pass.
- Final four-module branch RED/GREEN: a fresh `386`-test slice confirmed all
  eight requested arcs were missing in asset-signing capability rejection,
  downloader retention/clock pairing, oversized parser-field handling, and
  tool lifecycle/profile/error mapping. Eight focused negative tests pass in a
  `394`-test rerun and add exactly those eight arcs with no losses or production
  edit (`685/738` focused branches). Ruff, strict mypy, and pinned Pyright pass.

## Fresh authoritative local gates

- The strict combined quality wrapper exits `0` after the final production and
  test changes, covering its configured Ruff, strict mypy, Python-version
  Pyright, and Node policy surface.
- The authoritative test gate against `origin/main` exits `0`. Its validated
  report records project branch coverage `97.01424674143679%`, changed branch
  arc coverage `100%`, changed-line coverage `99.28864569083447%`, and exact
  `100%` branch coverage for every one of the `29` registered decision modules.
  No threshold or inventory was relaxed to obtain this result.
- Fresh Node contract lint and TypeScript typecheck both exit `0`. The complete
  Zod contract run exits `0`: core `8/8`, capability `14/14`, frozen baseline
  and static-policy `206/206`, ASVS `14/14`, and recovery `12/12` tests pass.

## Post-gate independent review reopenings

- Lease-owner RED: the exact issued worker lease could be entered twice, and an
  inner exit released the slot while an outer holder remained active. Cross
  thread/task transfer could likewise enter or release it. Six regressions
  failed before the fix. Lease state is now exactly `ISSUED -> ENTERED ->
  released`, bound to the issuing thread object and async task under the quota
  lock. Duplicate/nested/foreign entry or release fails closed without freeing
  the slot. The focused result is `69 passed`, `413/413` statements and
  `108/108` branches; Ruff and strict mypy/Pyright for Python 3.12-3.14 pass.
- Socket-identity RED: a private-mode parent owned by another principal was
  accepted; path-based chmod followed a replacement symlink; and shutdown
  unlinked a replacement regular file. Four initial adversarial tests failed.
  The server now opens and identity-checks an exact owned `0700` parent with
  `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, binds through `/proc/self/fd` under a
  temporary `0177` umask, validates the bound `0600` socket identity, and only
  unlinks that captured inode. UID/GID/mode/link-count, missing flag, stat
  failure, bind failure, umask/descriptor cleanup, replacement inode, and
  symlink cases pass. The focused unit plus real socket run is `42 passed`; all
  newly introduced statements and branches execute, with Ruff, strict mypy,
  and Pyright clean.
- Storage atomicity RED: a deterministic barrier proved prune could delete a
  validated completed render before `begin_render_transaction` registered its
  lease (`freed_objects=1`). Completion validation and lease increment now
  share the global lock; incomplete recovery begins only after lease authority
  exists. The regression, nine-case recovery matrix, and `314`-test storage
  subsystem pass; the changed function has no missing line or branch and lock
  order remains render-lock then global-lock.
- PEP 561 authority RED: a symlinked `src/nplg_mcp` ancestor copied external
  bytes, and full mode emitted evidence for source bytes differing from the
  named commit. Both regressions initially failed with `DID NOT RAISE`.
  Snapshot traversal now anchors the worktree, `src`, and package directories
  with descriptor-relative `O_NOFOLLOW` opens and pre/open/post identities.
  Full mode derives the candidate tree and compares captured inventory, sizes,
  and SHA-256 values with exact Git blobs before build/tool execution;
  artifact-only mode retains `candidate_tree=null` and non-authoritative
  language. Fresh results are `63` unit tests, both integration paths, Ruff,
  strict mypy, and Pyright green; 64 fail-closed attempts keep descriptor count
  stable at `5 -> 5`.
- Socket-cancellation RED: deterministic cancellation after Unix bind but
  before endpoint-identity assignment left the socket path behind, leaked the
  listener descriptor, and still accepted a connection. The server now binds
  without serving, captures the endpoint identity synchronously before its
  first cancellable yield, and gives the existing identity-checked cleanup the
  sole unlink authority. On Python 3.13 and newer it explicitly disables the
  runtime's automatic socket cleanup; the Python 3.12 path remains compatible.
  The focused unit and real-socket suites pass `44` tests, including exact
  `2/2` coverage of the new version branches; Ruff, strict mypy, Pyright, and a
  system-Python 3.12 compatibility probe pass.
- Transaction-owner RED: foreign-thread `commit()`, `rollback()`, and
  exception-finally cleanup marked a live transaction closed and released its
  lease before the underlying `RLock` rejected release. That allowed pruning
  and stranded the stripe lock. Three deterministic regressions failed with
  `cannot release un-acquired lock`. Transactions now bind to the exact issuing
  `Thread` object and reject every active foreign terminal operation before
  filesystem, lease, closed-state, or lock mutation; the owner can recover and
  close normally. The three regressions and full `340`-test storage slice pass;
  the transaction region has no missing branch, with Ruff, strict mypy, and
  Pyright clean.
- Socket-validation cleanup RED: a real listener whose newly bound endpoint
  failed private-socket validation retained its socket pathname and blocked a
  clean restart. The server now records the observed bound identity before
  validation, so the existing exact-identity cleanup removes only the inode it
  created and preserves every replacement. The regression and complete worker
  edge slice pass `104` tests; Ruff, strict mypy, Python 3.12-3.14 Pyright, and
  the system-Python 3.12 deferred-listener probe pass.
- Storage lease/callback RED: three regressions proved an active reader lease
  did not block explicit deletion, replacement, or transaction reset. Three
  more proved foreign reset bypassed owner binding and lifecycle observers or
  injected capacity samplers deadlocked when they re-entered store properties
  under the non-reentrant accounting lock (`3 failed` in each RED slice).
  Reader and transaction leases now use distinct exact authorities; deletion,
  replacement, reset, and prune check them under one accounting lock. Reset is
  owner-bound, alerts are latched under lock and emitted afterward, and injected
  capacity probes run outside the lock with identity revalidation before state
  mutation. The six focused regressions pass.
- Async-owner/nesting RED: an exact sibling asyncio task on the issuing thread
  could reset a transaction, and the same owner could open a second live
  transaction for the same render through the reentrant stripe lock (`2
  failed`). Transactions now bind both the exact `Thread` and running asyncio
  `Task`, and one accounting-locked registration helper enforces exactly one
  token per render object. The owner retains recovery authority after both
  rejections, and the stripe is reusable after closure.
- Storage decision closure: adversarial tests cover capacity-authority rebinding
  during reservation begin, commit, and prune; independent clock-authority
  rebinding during commit; invalid locked reservation state; short deletion
  paths; and missing transaction tokens. The complete focused storage run is
  `458 passed`, with `storage.py` at `1652/1652` statements and `494/494`
  branches. Ruff, strict mypy, and strict Pyright for Python 3.12, 3.13, and
  3.14 pass on the changed storage surface.
- Mutation-policy RED: the extracted transaction-registration invariant was not
  yet part of Task 16A's closed function inventory, so the tightened policy
  assertion failed. The Task 16A target set now names the helper and retains the
  transaction-atomicity suite; the focused policy and behavior slice passes.

## Repository index integrity

- The real index was unintentionally overwritten during local verification.
  Before any further work, two independent reconstructions recovered the exact
  original staged tree `61c85c0e5a6bd373bafe06f62a05a6a69e6d454f` and the
  same `38` staged paths. The restored canonical staged-patch SHA-256 is
  `19b2538c773e43055fa248d72fb995abf4d6f83713f8539ebaa4bb70d30b716a`.
  The accidental index images remain in `/tmp` as recovery evidence; no staged
  user change was discarded.
