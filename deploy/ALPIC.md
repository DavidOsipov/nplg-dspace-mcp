# Alpic deployment profile

This repository contains enough build metadata for Alpic to identify and install the project as **Python 3.13** instead of Node.js. That build compatibility is not production authorization. **Do not deploy the current candidate publicly:** the reviewed OAuth provider capability remains unsupported, and production startup deliberately fails closed before constructing network or application dependencies.

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
ALLOW_ANONYMOUS=false
MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL=4
```

`DEPLOYMENT_PROFILE=alpic-metadata` is mandatory and, in local test mode, exposes only `search_documents`, `get_document_metadata`, and `list_document_files`; it does not initialize the downloader, content store, scanner, or PDF runtime. Alpic supplies `ALPIC_HOST`; the server derives `PUBLIC_BASE_URL=https://<ALPIC_HOST>` automatically, but `ALPIC_HOST` never selects a deployment profile. Do not add `PUBLIC_BASE_URL` unless a custom domain is already active.

Do not configure `API_PRINCIPALS_JSON`, `API_BEARER_TOKEN`, `API_KEY`, `NPLG_PRIVATE_STATIC_TOKEN`, or any `X-API-Key` equivalent. Static authentication is forbidden for a production profile and cannot substitute for the selected Auth0/OIDC plus Alpic DCR contract. With the checked-in negative capability record, the expected startup result is `production OAuth provider capability is unsupported`. A supported provider record would still require the separately reviewed OIDC implementation; it is not itself an activation switch.

## What this fixes

The failed deployment selected Node and executed `npm ci` because the tracked Git branch did not contain the Python source, `pyproject.toml`, or a Python lock/configuration surface. After the complete source tree is pushed, `.python-version`, `pyproject.toml`, `requirements.lock`, and `alpic.json` make the intended Python build explicit.

## Material platform limitations

Alpic uses a **serverless** MCP gateway. It documents a **30-second** limit for each tool invocation and reserves `/assets/*` for build-time static CDN files. This server currently generates dynamic `/assets/` URLs at runtime and relies on local filesystem artifacts across multiple calls (`download` → `inspect` → `render` → `tiles`). Therefore Alpic is **not a supported full-fidelity deployment target** for the document-download and visual-rendering pipeline in the current release.

Local metadata-profile compatibility already covered by offline tests:

- search;
- metadata retrieval;
- public/restricted bitstream inventory;
- MCP discovery and tool listing.

Not yet production-supported on Alpic:

- stable cross-invocation PDF artifacts;
- runtime-generated page or tile URLs under `/assets/`;
- large downloads or PDF renders that can exceed the 30-second invocation limit.

The Docker/VPS production deployment is also metadata-only. A future full profile requires an object store, authenticated MCP-native binary resources, and a separately deployed least-privilege worker for long-running PDF work.

## Protected staging prerequisite

Do not perform a public or staging deployment from this guide while the provider verdict is unsupported. A future authorized staging run must bind a named Auth0 tenant and Alpic environment, preserve the backend-self/DCR/upstream-issuer distinction, prove the access-token format and resource/audience relationship, and run through the protected controller and credential broker.

Until those external-authority records exist, `do_not_release` is the only supported decision. Never place a provider or MCP credential in command arguments, shell history, candidate-owned reports, or this environment file.
