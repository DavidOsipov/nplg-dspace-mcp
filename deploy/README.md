# Production deployment: Docker Compose + Caddy

This is the supported first deployment for the metadata-only NPLG DSpace MCP. It assumes a dedicated Linux VPS, a public DNS name, Docker Engine, and Docker Compose v2. Caddy terminates TLS and forwards only to the private application container.

## 1. Capacity and prerequisites

Recommended starting point for the default limits:

- 4 vCPU;
- 8 GiB RAM;
- 40 GiB SSD with free-space monitoring;
- Ubuntu 24.04+ or Debian 13;
- Docker Engine and the `docker compose` plugin;
- inbound TCP 80 and 443;
- outbound DNS and TCP 443 to `dspace.nplg.gov.ge`.

The application container is capped at 4 GiB. Production accepts only `DEPLOYMENT_PROFILE=alpic-metadata`; `private-full` remains disabled until PDF/native-code work is moved behind a separately deployed least-privilege OS authority. `MAX_CONCURRENT_MCP_REQUESTS` is a fail-fast global emergency ceiling (default 16), while `MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL` (default 4) prevents one configured credential from consuming every MCP permit. `MAX_CONCURRENT_HTTP_REQUESTS` supplies a larger Uvicorn-wide ceiling (default 128). Saturated gates return HTTP 503 instead of queueing unbounded work, and `REQUEST_BODY_TIMEOUT_SECONDS` (default 10) releases permits when a client stalls while uploading JSON.

Create an A and/or AAAA record for the MCP hostname and point it at the VPS before starting Caddy.

## 2. Configure secrets and domain

From the project directory. The standard `docker compose config` validation is shown with an explicit env file below. Its quiet mode validates without printing the fully rendered environment and secrets to the terminal or CI log:

```bash
cp .env.example .env
chmod 600 .env

python3 - <<'PY'
from pathlib import Path
import json
import secrets

path = Path('.env')
text = path.read_text()
text = text.replace('mcp.example.com', 'mcp.your-domain.example')
text = text.replace(
    'ASSET_SIGNING_SECRET=replace-with-at-least-32-random-characters',
    f'ASSET_SIGNING_SECRET={secrets.token_hex(32)}',
)
text = text.replace(
    'API_PRINCIPALS_JSON=[{"principal_id":"primary","bearer_token":"replace-with-at-least-32-random-characters"}]',
    'API_PRINCIPALS_JSON=' + json.dumps(
        [{"principal_id": "primary", "bearer_token": secrets.token_hex(32)}],
        separators=(",", ":"),
    ),
)
path.write_text(text)
PY
```

Review `.env`. `MCP_DOMAIN` must contain only the host name. `PUBLIC_BASE_URL` must be the matching HTTPS origin. Keep `DEPLOYMENT_PROFILE=alpic-metadata` and `ALLOW_ANONYMOUS=false` for this Internet deployment. Give each client or operator a distinct registry entry and credential. `private-full` and `distributed-full` fail production startup until their separate worker/storage authority boundaries are implemented.

Load the values into the current shell when running verification commands:

```bash
set -a
. ./.env
set +a
```

Never commit `.env`, expose a principal credential in shell history, share one credential across callers, or reuse `ASSET_SIGNING_SECRET` as an API credential.

## 3. Validate and start

```bash
docker compose --env-file .env config --quiet
docker compose build --pull
# Before promotion, resolve the canonical application and proxy subjects to
# immutable image digests and complete the offline scan procedure below.
docker compose up -d
docker compose ps
docker compose logs --tail=100 app caddy
```

Caddy obtains and renews certificates automatically. The application itself is not published on a host port; only Caddy exposes 80 and 443.

## 4. Verify protocol and live repository access

Run the deterministic deployment verifier first:

```bash
python3 scripts/verify_deploy.py \
  --base-url "$PUBLIC_BASE_URL"
```

It checks the sessionless MCP `2026-07-28` envelope, discovery, and the exact metadata-only tool catalog. It does not query the public probe paths because Caddy deliberately returns 404 for them. Before running it, export `API_BEARER_TOKEN` with the bearer value for one configured verification principal; this variable is a verifier input and is not present in the application container.

Probe verification is opt-in and accepts only a loopback HTTP URL, for example `--probe-base-url http://127.0.0.1:8000` when the verifier runs in the application network namespace. The verifier compares canonical origins, including default ports and host case, and rejects reuse of the public `--base-url` origin. The separate private-network commands in the operations section remain the default Docker procedure.

Then run a live, non-downloading NPLG smoke test:

```bash
python3 scripts/smoke_live.py \
  --base-url "$PUBLIC_BASE_URL" \
  --query "ივერია"
```

Download, render, tile, runtime asset, and persistent-cache checks do not apply to the production metadata profile and must not be used as release evidence for it.

## 5. Connect an MCP client

Use:

```text
Endpoint: https://mcp.your-domain.example/mcp
Transport: Streamable HTTP
Authorization: Bearer <credential for this client's principal_id>
```

The server is stateless and does not issue an `Mcp-Session-Id`. The production metadata profile has no downloadable runtime assets.

### ChatGPT developer mode

For ChatGPT developer mode, create a custom app and supply:

```text
Endpoint: https://mcp.your-domain.example/mcp
Transport: Streamable HTTP
Authentication: the supported mechanism matching your deployment
```

Then select **Scan Tools**. The public MCP catalog is read/fetch-style with respect to the upstream NPLG archive and exposes exactly search, metadata, and file inventory. It cannot mutate NPLG and does not construct the downloader, cache, scanner, or PDF runtime.

Before configuring ChatGPT Pro or the Responses API, verify that the selected client can send the required per-principal header; product support and authentication surfaces can change independently of this server.

This release implements a registry of static bearer/API-key credentials bound to stable principal IDs, not an OAuth authorization server. Issue a distinct credential to each caller and revoke/rotate that registry entry if exposed. Use `Authorization: Bearer <principal credential>` where the client can send custom headers.

The ChatGPT custom-app UI may require a different authentication mechanism. When that happens, place a reviewed OAuth gateway in front of `/mcp` or add standards-compliant OAuth resource-server support. The gateway must validate the user/access token and map it to a stable backend principal; it must not collapse all callers into one shared credential or forward arbitrary caller-supplied authorization headers. **Do not set `ALLOW_ANONYMOUS=true` merely to make ChatGPT connect.**

ChatGPT connects to remote MCP servers. For a private VPS or on-premises deployment, use OpenAI's Secure MCP Tunnel rather than publishing an anonymous endpoint. After every incompatible tool-schema change, rescan or republish the custom app because approved tool definitions may be snapshotted by the host.

## 6. Egress control and residual risk

Application checks enforce the exact NPLG origin, reject non-global DNS results, disable proxy inheritance, validate every redirect, and cap response sizes. Those controls do not eliminate DNS time-of-check/time-of-use risk inside a normal HTTP client.

Apply an infrastructure egress policy that permits the application container only:

- DNS to approved resolvers;
- TCP 443 to the currently resolved public addresses of `dspace.nplg.gov.ge`;
- no RFC1918, loopback, link-local, metadata-service, or other outbound destinations.

Reconcile the permitted addresses when NPLG DNS changes. A provider-level firewall, host `DOCKER-USER` rules, or a dedicated network-policy layer is preferable. **Docker may bypass UFW** rules that only cover the host input/output paths; verify effective rules from inside the running container.

PDF/native-code execution is not reachable in the production metadata profile. Production `private-full` deliberately fails startup until a separately deployed, no-network, least-privilege worker and its recovery evidence exist.

## 7. Operations

Health, readiness, and metrics are deliberately blocked at the public Caddy edge. Query them only on the private application network:

```bash
docker compose exec -T app python -c \
  'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=3).read().decode())'
docker compose exec -T app python -c \
  'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/readyz", timeout=3).read().decode())'
docker compose exec -T app python -c \
  'import json, os, urllib.parse, urllib.request; p=json.loads(os.environ["API_PRINCIPALS_JSON"])[0]; v=p.get("bearer_token"); h=urllib.parse.urlsplit(os.environ["PUBLIC_BASE_URL"]).netloc; headers={"Host":h, "Authorization":"Bearer "+v} if v else {"Host":h, "x-api-key":p["api_key"]}; r=urllib.request.Request("http://127.0.0.1:8000/metrics",headers=headers); print(urllib.request.urlopen(r,timeout=3).read().decode()[:2000])'
```

Metrics are not exposed through Caddy; probes are also private, and the raw metrics route returns 404 without a configured API credential. Caddy request access logs and Uvicorn access logs are disabled deliberately; this also prevents future signed asset tokens from entering routine log streams. Application and proxy process/error logs remain available. Use MCP counters plus infrastructure telemetry for monitoring; add a redacting log pipeline before enabling request logs.

Logs and resource use:

```bash
docker compose logs -f --tail=200 app caddy
docker stats
sudo du -sh /var/lib/docker/volumes/nplg-dspace-mcp_nplg_cache/_data
```

The cache does not automatically prune downloaded source PDFs. Instead, a process-local logical-byte budget rejects all new download/render bytes before `CACHE_MAX_BYTES` is crossed (20 GiB by default). The quota includes existing regular files and active staging reservations and is concurrency-safe within the single application process. It is not a filesystem-block or inode quota, and external writers are unsupported, so retain volume limits and disk alerts. Render deletion is operator-only. The cleanup helper opens the cache as a separate process and performs startup recovery, so stop the app first and guarantee its restart:

```bash
(
  set -e
  trap 'docker compose start app' EXIT
  docker compose stop app
  docker compose run --rm --no-deps app python scripts/delete_render.py rnd_REPLACE_WITH_32_HEX
)
```

Source artifacts are content-addressed and retained. Use an operator-approved retention procedure rather than deleting files while jobs are active. Restart the single app process after any other out-of-band cache maintenance so its conservative quota accounting is rebuilt from disk.

## 8. Backup and restore

The cache is reproducible from NPLG, but backing it up avoids re-downloading and re-rendering. Stop the app for a consistent backup:

```bash
(
  set -e
  trap 'docker compose start app' EXIT
  mkdir -p backups
  docker compose stop app
  backup_path="backups/nplg-cache-$(date +%Y%m%d-%H%M%S).tgz"
  docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges=true \
    --user 10001:10001 \
    -v nplg-dspace-mcp_nplg_cache:/source:ro \
    alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
    sh -c 'cd /source && tar -czf - .' > "$backup_path"
  sha256sum "$backup_path" > "$backup_path.sha256"
)
```

The helper has no network, writable root filesystem, Linux capabilities, or writable backup mount; it reads the cache as the application UID and streams the archive to the host shell. Treat the pinned Alpine digest as a reviewed dependency and refresh/scan it deliberately. Restore only into an empty cache volume, with the app stopped, after `sha256sum --check` succeeds, and verify ownership is UID/GID `10001:10001` afterward. Encrypt backups separately when their contents are sensitive.

## 9. Upgrade and rollback

```bash
git fetch --tags
git checkout <reviewed-tag-or-commit>
docker compose build --pull
docker compose up -d
python3 scripts/verify_deploy.py --base-url "$PUBLIC_BASE_URL"
```

Rollback by checking out the prior reviewed commit and rebuilding. Do not use a floating application image tag in production.

## Offline immutable-digest image scan and CVE triage

Digest pinning prevents silent image drift, but it does not make an image vulnerability-free. Scan only an immutable image digest selected from the canonical build; a mutable tag or a locally inferred Compose image name is not a release subject.

The Trivy cache must be externally acquired by a protected process. It must arrive with an independently signed receipt that binds the immutable database OCI digest, media and artifact types, signer policy, acquisition time, and response digest. Verify the signature and require the receipt to be no more than 24 hours old before candidate code runs. The candidate repository cannot mint, refresh, or replace that receipt. Missing, stale, unsigned, or upstream-unattested database evidence produces `TRIVY_DB_UPSTREAM_PROVENANCE_UNATTESTED` and keeps the terminal result `do_not_release`.

After those checks, perform an offline scan with Trivy's database updates disabled. Supply both values as protected-controller inputs, never as a tag resolved by the candidate:

```bash
export TRIVY_CACHE_DIR='/absolute/path/to/verified-external-cache'
export APPLICATION_IMAGE_DIGEST='registry.example/nplg@sha256:REPLACE_WITH_64_HEX'
export PROXY_IMAGE_DIGEST='caddy@sha256:REPLACE_WITH_64_HEX'

trivy image \
  --cache-dir "$TRIVY_CACHE_DIR" \
  --skip-db-update \
  --offline-scan \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  "$APPLICATION_IMAGE_DIGEST"

trivy image \
  --cache-dir "$TRIVY_CACHE_DIR" \
  --skip-db-update \
  --offline-scan \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  "$PROXY_IMAGE_DIGEST"
```

Keep the complete machine-readable reports, their SHA-256 digests, the verified database receipt, and an SBOM for each exact image digest. The gate includes unfixed findings: every applicable HIGH or CRITICAL result requires CVE triage against the actual attack surface and blocks release unless the revision-bound, time-bounded exception policy is satisfied.

The production wheel uses pypdfium2/PDFium and the synthetic test corpus uses ReportLab/pypdf; PyMuPDF/MuPDF is not a project dependency. Preserve the license files bundled in the pypdfium2 wheel and the repository's `THIRD_PARTY_NOTICES.md` when redistributing the image.

## Supply-chain limitations

The Python and Caddy base images are pinned by immutable multi-platform index digest. Treat digest changes as reviewed dependency upgrades: update the tag and digest together, rebuild, scan the resulting image, and rerun the complete verification suite before deployment.

`requirements.lock` pins every direct and transitive runtime package and includes mechanically generated SHA-256 hashes for the resolved distributions; the version/pin set was reviewed, not every distribution file represented by those hashes. Docker and Alpic install it with `--require-hashes --no-deps --only-binary=:all:`. Hash locking constrains package bytes; it does not replace registry-account security, dependency review, image signing, or deployment by immutable image digest.
