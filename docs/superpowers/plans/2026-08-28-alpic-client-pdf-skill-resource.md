# Alpic Client-side PDF Skill Resource Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Let resource-capable MCP clients retrieve a bounded visual-analysis workflow while the public Alpic server remains anonymous, sessionless Streamable HTTP with exactly three metadata tools and no server-side PDF processing.

**Architecture:** Package one immutable Markdown workflow with the Python distribution, expose it at the exact non-templated URI `nplg://skills/georgian-newspaper-visual-analysis`, and point server discovery instructions to it. The workflow tells the client to retrieve only an explicitly public `source_url` returned by `list_document_files` and to inspect the PDF in its own trusted environment. Unknown/private resource URIs fail closed before any metadata service dependency is called.

**Tech Stack:** Python 3.12+, MCP Python SDK 2.0.0, Pydantic 2 strict validation, pytest, Ruff, mypy, setuptools package data.

**Spec:** `SPEC.md`, section “Client-side PDF workflow resource”.

## Global constraints

- Preserve the current staged index. Do not stage, commit, reset, stash, clean, push, publish, or deploy.
- Follow witnessed RED -> GREEN -> REFACTOR TDD for each production behavior.
- Keep the `alpic-metadata` tool catalog exactly `get_document_metadata`, `list_document_files`, and `search_documents`.
- Add no prompts, resource templates, subscriptions, scripts, PDF assets, downloader, renderer, cache, or OAuth surface.
- State the interoperability limit honestly: MCP resources make the workflow retrievable, but arbitrary clients are not required to discover, read, or execute it.

## Task 1: Canonical client-side workflow

**Files:**

- Modify: `tests/static/test_skill.py`
- Modify: `skills/georgian-newspaper-visual-analysis/SKILL.md`
- Add: `src/nplg_mcp/agent_skills/georgian-newspaper-visual-analysis/SKILL.md`
- Add: `src/nplg_mcp/agent_workflow.py`
- Modify: `pyproject.toml`
- Modify: `tests/static/test_quality_policy.py`
- Modify: `scripts/verify_pep561.py`
- Modify: `tests/unit/test_pep561_gate.py`
- Modify: `tests/integration/test_pep561_distribution.py`
- Modify: `tests/unit/test_test_gate.py`

1. Replace the obsolete server-PDF skill assertions with tests requiring the exact three metadata tools, exact returned-URL use, public-access checks, bounded client-local retrieval, local PDF validation and SHA-256, untrusted-document handling, visual-evidence labels, safe stopping, and absence of every private PDF tool name.
2. Run the focused static skill test and record the expected failure against the old workflow.
3. Rewrite the repository skill, package an exact copy, add a bounded UTF-8 package-resource loader, and declare only that Markdown file as package data. Test that both copies are byte-identical and loadable from the installed package contract.
4. Extend the existing PEP 561/package-manifest gates to allow only the exact
   workflow path and to prove byte-identical inclusion in both sdist and wheel;
   keep arbitrary package data fail-closed.
5. Run the focused tests, Ruff, and mypy for the changed Python surface until green. Run the skill-creator validator against the repository skill directory.

## Task 2: Read-only MCP discovery and retrieval

**Files:**

- Modify: `tests/contracts/test_sdk_client.py`
- Modify: `tests/contracts/test_sdk_boundary.py`
- Modify: `tests/integration/test_profiles.py`
- Modify: `tests/unit/test_verify_deploy.py`
- Modify: `src/nplg_mcp/errors.py`
- Modify: `src/nplg_mcp/sdk_boundary.py`
- Modify: `src/nplg_mcp/mcp_server.py`
- Modify: `scripts/verify_deploy.py`
- Modify: `README.md`
- Modify: `deploy/ALPIC.md`
- Modify: `docs/superpowers/plans/2026-08-26-alpic-mcp-release-finalization.md`
- Modify: `tests/static/test_deployment.py`

1. Add failing contract and integration tests proving: one exact Markdown resource is listed/read; discovery points to it; resource templates remain unavailable; the tool catalog remains exact; malformed, unknown, and private URIs fail closed; and no metadata service resource method is entered.
2. Add failing verifier tests for the expected metadata resource list/read exchange and adversarial wrong URI, MIME type, content, cardinality, or template-capability responses.
3. Implement the exact URI admission, static SDK list/read responses, metadata resource-handler registration, concise discovery instructions, and verifier checks. Keep the private profile behavior unchanged.
4. Update deployment/user documentation to distinguish the retrievable client workflow from server-side PDF processing and from guaranteed client execution.
5. Run focused tests, the relevant strict static/type/lint/package gates, then the broad repository gate permitted by the current checkout. Obtain independent code review and forward-test the served workflow with a fresh agent.
