# Alpic MCP Task 4 Readiness Audit

**Date:** 2026-08-28
**Profile:** `alpic-metadata`
**Decision:** `do_not_release`
**Task 4 execution:** Blocked before `initialize-run`

## Executive conclusion

Task 4 cannot start from the current checkout. This conclusion is based on
three independently sufficient blockers:

1. Tasks 1-3 have not passed for one clean immutable candidate.
2. The required external protected controller and its signed provisioning
   evidence are unavailable locally.
3. All 253 selected `alpic-metadata` ASVS rows remain `Not assessed` with
   no evidence IDs.

The first anonymous release does not require OAuth/Auth0/DCR capability.
Those negative capability records remain truthful future-work evidence, but
removing them from this profile's eligibility join does not clear the candidate,
controller, custody, staging, or ASVS blockers.

## Governing scope

The reconciled
[release-finalization plan](../plans/2026-08-26-alpic-mcp-release-finalization.md)
keeps the existing generic protected workflow:

- exactly 13 release operations;
- exactly four launcher commands;
- both frozen credential-broker classes, `deployment_provider` and `mcp`;
- the existing `StagingProofResult.v2` envelope; and
- a separate Production authority after any local `release_recommended`
  result.

It narrows the hosted application proof to anonymous Streamable HTTP with
exactly three tools: `search_documents`, `get_document_metadata`, and
`list_document_files`. It makes no authentication-support claim.

## Live checkout evidence

The audited baseline was:

- HEAD `fd5e3a65ef146426c252e93191383c1dd1c17fb9`;
- HEAD tree `21252c8dfab8af844848dacdbab8e968196a3b94`;
- 29 staged paths and, before this report, zero unstaged or untracked paths;
- governing-plan index/worktree blob
  `5e10ec8f28a392b79696e2c83252de9514c019b1`; and
- staged binary-diff SHA-256
  `554613507eb93e9800cc0fd568c61ca66de988b37b59bff8f40b75254c7a8e06`.

Current Git proves that the plan is staged, but it cannot identify who staged
it. The audit-process ledger records that it became staged between turns and
that the auditing agent did not stage it; this is process-history evidence, not
a live-Git provenance claim. The complete index is therefore treated as
concurrent/user-owned state.

The retained Task 3 receipts are terminally nonzero:

- the exact parser mutation gate rejected malformed mutation-command evidence;
  and
- the full test gate rejected incomplete or unsuccessful test-gate evidence.

No qualification gate was rerun for this documentation correction. A rerun
cannot make a staged overlay immutable or replace the retained terminal
receipts.

## Protected-controller evidence

The checked-in controller policy:

- reports `external_authority_required`;
- forbids the candidate from supplying its own controller;
- marks the expected controller unconfigured; and
- terminates locally at `do_not_release`.

The checked-in manifest reports
`PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE`. The four expected local launcher
bindings were unset:

- `NPLG_PROTECTED_LAUNCHER`;
- `NPLG_CONTROLLER_PROVISIONING_RECEIPT`;
- `RELEASE_INITIALIZATION_JOURNAL_JSON`; and
- `RELEASE_RUN_DESCRIPTOR_JSON`.

No locally supplied evidence establishes a signed
`ProtectedControllerProvisioningReceipt.v2`, compatible anonymous controller,
zero MCP credential-handle use, authorized staging configuration,
candidate-bound staging proof, custody chain, or action authorization.
Repository contracts and local fixtures cannot substitute for that external
authority.

## ASVS evidence

The `alpic-metadata` slice of
`docs/security/asvs-5.0.0-l2-matrix.jsonl` contains exactly 253 selected rows.
All 253 have verdict `Not assessed`, and all have empty evidence-ID lists.

Authentication requirements may eventually receive governed `N/A` verdicts
only after reviewed absence proof establishes that they do not apply to this
deliberately public, read-only surface. Anonymous operation alone is not
absence proof.

## Preconditions for starting Task 4

Task 4 may start only after all of the following are supplied and verified:

1. one clean immutable candidate for which Tasks 1-3 are all green;
2. a signed, digest-verified controller provisioning receipt covering all
   13 operations and four launchers;
3. protected launcher, policy, trust-root, broker, network, and custody
   bindings;
4. external proof that the existing controller accepts the anonymous profile
   without OAuth-specific fields and uses zero MCP credential handles;
5. separately authorized staging, attestation, custody, and cleanup actions;
6. a compatible candidate-bound `StagingProofResult.v2`; and
7. independent closure of all 253 selected ASVS rows.

Until then, stop before `initialize-run` with
`CANDIDATE_NOT_CLEAN_OR_IMMUTABLE`,
`PROTECTED_RELEASE_CONTROLLER_UNAVAILABLE`, and `do_not_release`.

## Verification

After creating this repository-visible report:

- `npm run docs:lint` linted 21 files with zero issues;
- structural assertions confirmed all decision markers, the relative governing
  plan target, and a final newline;
- Git showed this report as the sole new untracked path;
- all 29 pre-existing staged paths remained staged;
- there were zero unstaged tracked paths and no other untracked paths; and
- the staged binary-diff SHA-256 remained
  `554613507eb93e9800cc0fd568c61ca66de988b37b59bff8f40b75254c7a8e06`.

## Actions not performed

This audit did not stage, unstage, commit, sign, deploy, publish, upload, clean,
or contact any controller, provider, broker, custody authority, or Production
system. It did not read or print secrets. No production source or test code was
changed, because the plan's mandatory external-prerequisite stop occurs before
a TDD implementation cycle.
