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
- Production is limited to `alpic-metadata` until PDF/native-code execution is
  moved behind a separately deployed, least-privilege OS authority boundary.
  A same-container child process is a development compatibility boundary, not
  a production sandbox.
- The production `alpic-metadata` profile is anonymous and rejects credential
  configuration. Any future authenticated private production profile must use
  a closed, strict Pydantic principal registry; each authenticated request must
  consume both a principal-specific zero-waiter permit and the process-global
  emergency permit. Legacy shared bearer/API-key environment variables remain
  development-only compatibility inputs.
- DNS resolution, metadata parsing, and local storage publication use separate
  bounded executors. Cancellation does not return a permit while underlying
  blocking work remains live; parser structure budgets are enforced before a
  complete HTML/XML tree is constructed.
- Bootstrap artifacts require HTTPS, publisher SHA-256 evidence, safe archive
  members, exact embedded versions, and atomic publication. Detached
  signatures are verified when the publisher supplies them; checksum-only
  records state that limitation explicitly.
- Secrets, bearer tokens, raw authorization headers, and untrusted archive
  content are excluded from fixtures and public errors.

## Client-side PDF workflow resource

The public `alpic-metadata` profile keeps its exact three-tool catalog and does
not download, parse, render, cache, or delete PDFs. It additionally advertises
one fixed, non-templated, read-only MCP resource at
`nplg://skills/georgian-newspaper-visual-analysis`. The resource returns bounded
`text/markdown` instructions for a client agent to select a public bitstream
from `list_document_files`, retrieve only that returned `source_url`, and carry
out PDF inspection in the client's own environment.

The server's discovery instructions point clients to the resource. The profile
registers only `resources/list` and `resources/read`: it registers no resource
templates, prompts, subscriptions, asset route, downloader, content store,
scanner, or PDF runtime. An unknown or private resource URI fails closed and
never reaches a metadata service dependency.

The workflow is instruction-only. It cannot override client or user policy,
install software, grant filesystem or network authority, or guarantee that an
arbitrary MCP host will load or follow it. A compatible client must explicitly
support MCP resources and must keep downloaded documents and their contents in
the untrusted-data boundary. If it cannot enforce a bounded local download and
safe local PDF inspection, it stops at metadata rather than asking Alpic to do
the PDF work.

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
