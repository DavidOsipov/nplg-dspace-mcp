# NPLG DSpace MCP — phase 0–1 release specification

**Status:** implementation source of truth for the official-SDK migration
**Date:** 2026-08-15
**First release profile:** `alpic-metadata`

## Scope

The migration preserves the reviewed read-only NPLG behavior while replacing
the handwritten protocol boundary with the official Python MCP SDK at the
earliest independently testable seam. Phase 0–1 freezes the current tool,
resource, result, and error surface; it does not advertise OAuth provider
support, operation-specific scopes, or a completed Alpic deployment.

Pydantic models are the Python runtime contract. Every external value is
strictly typed, rejects unknown fields, and is validated before it reaches a
repository, downloader, PDF worker, storage path, or transport response.
Zod schemas are an independent oracle in the later contract phase; they must
not be generated from Python models or treated as evidence in this phase.

## Security invariants

- The server remains upstream-read-only and accepts only canonical NPLG URLs.
- Authentication, authorization, routing, and protocol-version decisions are
  fail-closed; routing headers are never authorization evidence.
- Tool and resource fixtures are canonical JSON and digest-bound to the
  reviewed source checkpoint. A changed catalog or case requires a new audit.
- PDF work is serialized in the compatibility backend: `PDF_EXECUTOR=serialized`
  and `MAX_CONCURRENT_PDF_JOBS=1`. Cancellation cannot release the permit until
  the worker thread has completed.
- Bootstrap artifacts require HTTPS, publisher SHA-256 evidence, safe archive
  members, exact embedded versions, and atomic publication. Detached
  signatures are verified when the publisher supplies them; checksum-only
  records state that limitation explicitly.
- Secrets, bearer tokens, raw authorization headers, and untrusted archive
  content are excluded from fixtures and public errors.

## Evidence boundaries

The frozen baseline proves structural compatibility only. It is not proof of
ASVS closure, production deployment, vendor detector behavior, OAuth provider
capability, or a live Alpic runtime. Those claims require the later evidence
gates in the implementation plan.

The current capability records deliberately preserve these blockers:

- `MCP_DYNAMIC_SCOPE_403_UNSUPPORTED`
- `ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN`
- `ALPIC_PRM_ROUTE_COMPATIBILITY_UNPROVEN`
- `ALPIC_OAUTH_DISCOVERY_ORDERING_UNPROVEN`
- `OAUTH_PROVIDER_CAPABILITY_UNPROVEN`
- `OAUTH_END_TO_END_FLOW_UNPROVEN`

<!-- nplg-release-profile:v1
{"decision_sha256":"b064e1d16fca1c4f86f9d8c2a5f1053cd25d50f88c169505eb79464d49c259cb","first_release_profile":"alpic-metadata","schema_version":1}
-->
