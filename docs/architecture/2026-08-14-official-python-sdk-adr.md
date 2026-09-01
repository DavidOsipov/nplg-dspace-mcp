# ADR-001: Official Python MCP SDK with an `alpic-metadata` first release

**Status:** Accepted for phase 0–1 implementation
**Date:** 2026-08-15

## Decision

Adopt the pinned official Python MCP SDK (`mcp==2.0.0`, `mcp-types==2.0.0`)
as the target transport boundary. Keep the current repository and PDF
services behind typed adapters, and use the immutable baseline under
`contracts/baseline/` as the compatibility gate during the migration.

The first release profile is `alpic-metadata`: search, metadata, resource
discovery, and the reviewed read-only metadata surface are eligible for
Alpic-oriented deployment work. PDF rendering, durable storage, OAuth
provider selection, and operation-specific authorization remain separately
gated capabilities.

## Rationale

The handwritten JSON-RPC layer is an existing behavior surface, not a stable
security boundary. The official SDK gives the project a maintained protocol
implementation while Pydantic remains the runtime source of truth for local
inputs and outputs. The baseline prevents a migration from silently changing
tool names, schemas, resources, error cases, or protocol envelopes.

The phase-0 SDK feasibility record is intentionally unsupported:
`mcp==2.0.0` does not expose a public parsed-operation HTTP-response seam for
operation-specific 403 challenges. Therefore no operation-scope claim,
header-bound authorization shortcut, private MCP reparse, or HTTP-200 tool
error is permitted to close that gap.

## Consequences

- Python SDK and protocol facts are pinned and independently reviewed.
- The baseline must be regenerated and re-reviewed after any production-source
  change that affects the frozen surface.
- Zod schemas are deferred to the independent contract phase and must not be
  treated as generated mirrors of Pydantic.
- Alpic and OAuth records remain negative evidence until vendor/provider
  fixtures and end-to-end observations exist.

### Phase 3 local parity disposition

The digest-bound `metadata-tool-catalog-schema-projection` difference is
limited to the frozen custom-protocol advertisement. The official SDK projects
the complete current Pydantic input/output schemas, including four
client-visible search-parameter descriptions, and mirrors each human-readable
tool title in its annotations. Retained custom behavior continues to enforce
the same Pydantic models at runtime. The ledger is local implementation
evidence, not release approval, and the custom adapter is removed in Task 14.

Task 14 deliberately changes three `private-full` resource semantics and binds
each side to the accepted-difference ledger: canonical artifact resources now
return their immutable binary content instead of a JSON signed-URL locator;
render resources use the current pipeline-version-bound identity; and the
official SDK advertises the two canonical private resource templates that the
custom protocol did not expose. Frozen list/about behavior remains equal. These
records are local compatibility dispositions, not protected release approval.

## Rejected alternatives

- Continuing the custom protocol as the long-term transport implementation.
- Authorizing from `Mcp-Method`/`Mcp-Name` headers or reparsing MCP in a proxy.
- Selecting JWT versus opaque-token verification without a provider verdict.
- Treating a checksum manifest as a detached cryptographic signature.

<!-- nplg-release-profile:v1
{"decision_sha256":"b064e1d16fca1c4f86f9d8c2a5f1053cd25d50f88c169505eb79464d49c259cb","first_release_profile":"alpic-metadata","schema_version":1}
-->
