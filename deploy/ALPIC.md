# Alpic deployment profile

This repository contains enough build metadata for Alpic to identify and install the project as **Python 3.13** instead of Node.js. The initial Alpic deployment is a public, unauthenticated Streamable HTTP metadata MCP; it is not authorization to enable the private rendering profile.

## Required project settings

Create a new Alpic project with:

```text
Runtime: Python 3.13
Transport: Streamable HTTP
Branch: main
Root directory: <empty>
```

The runtime is a project-level setting. The install command explicitly reuses Alpic's `python3` binary, so `uv` does not attempt to download another interpreter. `alpic.json` enforces the checked-in SHA-256 hashes with `--require-hashes` in addition to exact versions and binary-only installation.

Add these environment variables:

```text
NODE_ENV=production
DEPLOYMENT_PROFILE=alpic-metadata
CURSOR_SIGNING_SECRET=<at least 32 random bytes>
ALLOW_ANONYMOUS=true
MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL=4
```

`DEPLOYMENT_PROFILE=alpic-metadata` is mandatory and exposes only `search_documents`, `get_document_metadata`, and `list_document_files`; it does not initialize the downloader, content store, scanner, or PDF runtime. `ALLOW_ANONYMOUS=true` is valid only for this profile. Alpic supplies `ALPIC_HOST`; the server derives `PUBLIC_BASE_URL=https://<ALPIC_HOST>` automatically, but `ALPIC_HOST` never selects a deployment profile. Do not add `PUBLIC_BASE_URL` unless a custom domain is already active.

Do not configure `API_PRINCIPALS_JSON`, `API_BEARER_TOKEN`, `API_KEY`, `NPLG_PRIVATE_STATIC_TOKEN`, or any `X-API-Key` equivalent. Static authentication is forbidden in production. OAuth/Auth0/DCR remains deferred work and must not be represented by a shared secret or enabled for this initial public profile.

## What this fixes

The failed deployment selected Node and executed `npm ci` because the tracked Git branch did not contain the Python source, `pyproject.toml`, or a Python lock/configuration surface. After the complete source tree is pushed, `.python-version`, `pyproject.toml`, `requirements.lock`, and `alpic.json` make the intended Python build explicit.

## Material platform limitations

Alpic uses a **serverless** MCP gateway. It documents a **30-second** limit for each tool invocation and reserves `/assets/*` for build-time static CDN files. This server currently generates dynamic `/assets/` URLs at runtime and relies on local filesystem artifacts across multiple calls (`download` → `inspect` → `render` → `tiles`). Therefore Alpic is **not a supported full-fidelity deployment target** for the document-download and visual-rendering pipeline in the current release.

Local metadata-profile compatibility already covered by offline tests:

- search;
- metadata retrieval;
- public/restricted bitstream inventory;
- MCP discovery and the exact three-tool listing;
- listing and reading the static client-side PDF workflow resource.

Not yet production-supported on Alpic:

- stable cross-invocation PDF artifacts;
- runtime-generated page or tile URLs under `/assets/`;
- large downloads or PDF renders that can exceed the 30-second invocation limit.

The current Docker Compose file selects `private-full` and is not an alternative
deployment path for this anonymous metadata profile. A future full profile
requires an object store, authenticated MCP-native binary resources, and a
separately deployed least-privilege worker for long-running PDF work.

## Protected staging prerequisite

Do not perform a public or staging deployment from this guide until the exact
candidate and local gates are complete and an authorized provider-side action
binds that candidate to the named Alpic environment. The hosted verification
must prove the public `/mcp` route, exact three-tool catalog, sessionless
behavior, effective Host and Origin values, the exact
`nplg://skills/georgian-newspaper-visual-analysis` Markdown resource, absence
of resource templates and private resources, and absence of asset routes.
OAuth/Auth0/DCR evidence is not a prerequisite for this anonymous metadata-only
profile. Resource availability proves retrieval only; arbitrary MCP clients are
not required to load or follow the workflow.

Until those candidate and provider records exist, `do_not_release` is the only
supported decision. Never place a provider or MCP credential in command
arguments, shell history, candidate-owned reports, or this environment file.
