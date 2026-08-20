# Alpic deployment profile

This repository now contains enough build metadata for Alpic to identify and install the project as **Python 3.13** instead of Node.js. Select **Streamable HTTP** when importing the repository and keep the repository root directory empty (the project lives at the repository root).

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
ASSET_SIGNING_SECRET=<at least 32 random bytes>
API_PRINCIPALS_JSON=[{"principal_id":"alpic-client","api_key":"<at least 32 random bytes>"}]
ALLOW_ANONYMOUS=false
MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL=4
```

`DEPLOYMENT_PROFILE=alpic-metadata` is mandatory and exposes only `search_documents`, `get_document_metadata`, and `list_document_files`; it does not initialize the downloader, content store, scanner, or PDF runtime. Alpic supplies `ALPIC_HOST`; the server derives `PUBLIC_BASE_URL=https://<ALPIC_HOST>` automatically, but `ALPIC_HOST` never selects a deployment profile. Do not add `PUBLIC_BASE_URL` unless a custom domain is already active.

Configure the Alpic client/trusted-client policy to send the credential for its stable principal in the `x-api-key` request header. The server compares that header exactly and in constant time and applies both per-principal and global admission ceilings. Give other callers separate registry entries; do **not** enable anonymous access merely because this profile is not an OAuth protected-resource implementation. Static keys are not per-user OAuth, so rotate an entry if exposed and keep Alpic's trusted-client/IP controls enabled where available. Do not treat obscurity of the generated URL as access control.

## What this fixes

The failed deployment selected Node and executed `npm ci` because the tracked Git branch did not contain the Python source, `pyproject.toml`, or a Python lock/configuration surface. After the complete source tree is pushed, `.python-version`, `pyproject.toml`, `requirements.lock`, and `alpic.json` make the intended Python build explicit.

## Material platform limitations

Alpic uses a **serverless** MCP gateway. It documents a **30-second** limit for each tool invocation and reserves `/assets/*` for build-time static CDN files. This server currently generates dynamic `/assets/` URLs at runtime and relies on local filesystem artifacts across multiple calls (`download` → `inspect` → `render` → `tiles`). Therefore Alpic is **not a supported full-fidelity deployment target** for the document-download and visual-rendering pipeline in the current release.

Expected compatibility on Alpic:

- search;
- metadata retrieval;
- public/restricted bitstream inventory;
- MCP discovery and tool listing.

Not yet production-supported on Alpic:

- stable cross-invocation PDF artifacts;
- runtime-generated page or tile URLs under `/assets/`;
- large downloads or PDF renders that can exceed the 30-second invocation limit.

The Docker/VPS production deployment is also metadata-only. A future full profile requires an object store, authenticated MCP-native binary resources, and a separately deployed least-privilege worker for long-running PDF work.

## Post-deploy check

After Alpic reports a successful deployment, verify the public MCP endpoint with MCP Inspector or Alpic's playground. Test `tools/list`, `search_documents`, `get_document_metadata`, and `list_document_files`.

For the bundled verifier, read the key silently into the environment so it is neither placed in process arguments nor copied into shell history:

```bash
read -rsp 'Alpic principal API key: ' API_KEY
printf '\n'
export API_KEY
python scripts/verify_deploy.py --base-url "https://$ALPIC_HOST"
```

This public check validates the `alpic-metadata` MCP catalog and does not request health or readiness endpoints. The verifier accepts `--probe-base-url` only for a loopback HTTP origin, so omit it for an external Alpic deployment and verify private probes from the application network namespace instead.
