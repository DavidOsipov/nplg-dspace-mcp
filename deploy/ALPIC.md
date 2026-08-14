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
ASSET_SIGNING_SECRET=<at least 32 random bytes>
API_KEY=<at least 32 random bytes>
ALLOW_ANONYMOUS=false
```

Alpic supplies `ALPIC_HOST`; the server derives `PUBLIC_BASE_URL=https://<ALPIC_HOST>` automatically. Its cache defaults to `/tmp/nplg-dspace-mcp-cache` in this environment. Do not add `PUBLIC_BASE_URL` unless a custom domain is already active.

Configure the Alpic client/trusted-client policy to send the same secret in the `x-api-key` request header. The server compares that header exactly and in constant time. Do **not** enable anonymous access merely because this profile is not an OAuth protected-resource implementation. The API key is still a shared secret, not per-user OAuth; rotate it if exposed and keep Alpic's trusted-client/IP controls enabled where available. Do not treat obscurity of the generated URL as access control.

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

Use the Docker/VPS deployment in `deploy/README.md` for the complete server. A proper Alpic-native full profile would require an object store, MCP-native binary resources instead of runtime `/assets/` routes, and Tasks-based long-running PDF work.

## Post-deploy check

After Alpic reports a successful deployment, verify the public MCP endpoint with MCP Inspector or Alpic's playground. Test `tools/list`, `search_documents`, `get_document_metadata`, and `list_document_files` before attempting the PDF tools.

For the bundled verifier, read the key silently into the environment so it is neither placed in process arguments nor copied into shell history:

```bash
read -rsp 'Alpic API key: ' API_KEY
printf '\n'
export API_KEY
python scripts/verify_deploy.py --base-url "https://$ALPIC_HOST"
```
