# Production deployment: Docker Compose + Caddy

This is the supported first deployment for the NPLG DSpace MCP. It assumes a dedicated Linux VPS, a public DNS name, Docker Engine, and Docker Compose v2. Caddy terminates TLS and forwards only to the private application container.

## 1. Capacity and prerequisites

Recommended starting point for the default limits:

- 4 vCPU;
- 8 GiB RAM;
- 40 GiB SSD with free-space monitoring;
- Ubuntu 24.04+ or Debian 13;
- Docker Engine and the `docker compose` plugin;
- inbound TCP 80 and 443;
- outbound DNS and TCP 443 to `dspace.nplg.gov.ge`.

The application container is capped at 4 GiB. Lower-memory hosts must also lower `MAX_PAGE_PIXELS`, `MAX_RENDER_PIXELS`, and `MAX_CONCURRENT_PDF_JOBS` rather than relying on the OOM killer. `MAX_CONCURRENT_MCP_REQUESTS` is a fail-fast, zero-queue MCP limit (default 16); `MAX_CONCURRENT_ASSET_STREAMS` separately holds permits for complete signed-file response lifecycles (default 8); and `MAX_CONCURRENT_HTTP_REQUESTS` supplies a larger Uvicorn-wide ceiling (default 128) for all HTTP work, including probes. Saturated gates return HTTP 503 rather than queueing unbounded work. `REQUEST_BODY_TIMEOUT_SECONDS` (default 10) releases an MCP permit when a client stalls while uploading JSON. These are process-capacity controls, not client-aware edge rate limits.

Create an A and/or AAAA record for the MCP hostname and point it at the VPS before starting Caddy.

## 2. Configure secrets and domain

From the project directory. The standard `docker compose config` validation is shown with an explicit env file below. Its quiet mode validates without printing the fully rendered environment and secrets to the terminal or CI log:

```bash
cp .env.example .env
chmod 600 .env

python3 - <<'PY'
from pathlib import Path
import secrets

path = Path('.env')
text = path.read_text()
text = text.replace('mcp.example.com', 'mcp.your-domain.example')
text = text.replace(
    'ASSET_SIGNING_SECRET=replace-with-at-least-32-random-characters',
    f'ASSET_SIGNING_SECRET={secrets.token_hex(32)}',
)
text = text.replace(
    'API_BEARER_TOKEN=replace-with-at-least-32-random-characters',
    f'API_BEARER_TOKEN={secrets.token_hex(32)}',
)
path.write_text(text)
PY
```

Review `.env`. `MCP_DOMAIN` must contain only the host name. `PUBLIC_BASE_URL` must be the matching HTTPS origin. Keep `ALLOW_ANONYMOUS=false` for Internet deployment.

Load the values into the current shell when running verification commands:

```bash
set -a
. ./.env
set +a
```

Never commit `.env`, expose the bearer token in shell history, or reuse `ASSET_SIGNING_SECRET` as the bearer token.

## 3. Validate and start

```bash
docker compose --env-file .env config --quiet
docker compose build --pull
# Before promotion, scan the exact built application image with your approved
# scanner (for example Trivy, Grype, or Docker Scout) and review every
# HIGH/CRITICAL result for exploitability.
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

It checks health, readiness, the sessionless MCP `2026-07-28` envelope, discovery, the exact tool catalog, cache metadata, and resources.

Then run a live, non-downloading NPLG smoke test:

```bash
python3 scripts/smoke_live.py \
  --base-url "$PUBLIC_BASE_URL" \
  --query "ივერია"
```

After choosing a known public and reasonably small issue, exercise download and visual rendering explicitly:

```bash
python3 scripts/smoke_live.py \
  --base-url "$PUBLIC_BASE_URL" \
  --handle '1234/REPLACE_ME' \
  --query "ივერია" \
  --download \
  --render-page 1 \
  --tiles
```

The second command can transfer a large PDF. Check available disk space first.

## 5. Connect an MCP client

Use:

```text
Endpoint: https://mcp.your-domain.example/mcp
Transport: Streamable HTTP
Authorization: Bearer <API_BEARER_TOKEN>
```

The server is stateless and does not issue an `Mcp-Session-Id`. The signed `/assets/...` URLs expire according to `ASSET_TTL_SECONDS`.

### ChatGPT developer mode

For ChatGPT developer mode, create a custom app and supply:

```text
Endpoint: https://mcp.your-domain.example/mcp
Transport: Streamable HTTP
Authentication: the supported mechanism matching your deployment
```

Then select **Scan Tools**. The public MCP catalog is read/fetch-style with respect to the upstream NPLG archive, and render cleanup is not exposed to the model. Three tools populate the server's local cache and therefore advertise `readOnlyHint=false`; they still cannot mutate NPLG. ChatGPT Pro currently supports custom MCPs with read/fetch permissions, which is the intended deployment profile for this server.

This release implements a static bearer token, not an OAuth authorization server. Use `Authorization: Bearer <API_BEARER_TOKEN>` where the client can send custom headers. The OpenAI Responses API supports custom HTTP headers for remote MCP authentication, so the same deployment can be used there without changing the server.

The ChatGPT custom-app UI may require an authentication mechanism different from a raw shared bearer token. When that happens, place a reviewed OAuth gateway in front of `/mcp` or add standards-compliant OAuth resource-server support. The gateway must validate the user/access token and inject the private upstream bearer token; it must not forward arbitrary caller-supplied authorization headers. **Do not set `ALLOW_ANONYMOUS=true` merely to make ChatGPT connect.**

ChatGPT connects to remote MCP servers. For a private VPS or on-premises deployment, use OpenAI's Secure MCP Tunnel rather than publishing an anonymous endpoint. After every incompatible tool-schema change, rescan or republish the custom app because approved tool definitions may be snapshotted by the host.

## 6. Egress control and residual risk

Application checks enforce the exact NPLG origin, reject non-global DNS results, disable proxy inheritance, validate every redirect, and cap response sizes. Those controls do not eliminate DNS time-of-check/time-of-use risk inside a normal HTTP client.

Apply an infrastructure egress policy that permits the application container only:

- DNS to approved resolvers;
- TCP 443 to the currently resolved public addresses of `dspace.nplg.gov.ge`;
- no RFC1918, loopback, link-local, metadata-service, or other outbound destinations.

Reconcile the permitted addresses when NPLG DNS changes. A provider-level firewall, host `DOCKER-USER` rules, or a dedicated network-policy layer is preferable. **Docker may bypass UFW** rules that only cover the host input/output paths; verify effective rules from inside the running container.

PDF parsing occurs in the non-root application container with a read-only root filesystem, dropped capabilities, `no-new-privileges`, PID, CPU, memory, page, pixel, file-size, and concurrency limits. There is no independently verified nested process sandbox. The container/VM boundary is therefore the principal isolation boundary. For hostile-document workloads, use a dedicated VPS with no cloud credentials or sensitive mounts.

This is the material residual risk: a memory-safety bug in PDFium/Pillow or a decompression-bomb class PDF may terminate the application container. Compose will restart it, but availability can still be affected.

## 7. Operations

Health and internal metrics:

```bash
curl -fsS "$PUBLIC_BASE_URL/healthz"
curl -fsS "$PUBLIC_BASE_URL/readyz"
docker compose exec -T app python -c \
  'import os, urllib.parse, urllib.request; h=urllib.parse.urlsplit(os.environ["PUBLIC_BASE_URL"]).netloc; r=urllib.request.Request("http://127.0.0.1:8000/metrics", headers={"Host": h, "Authorization": "Bearer " + os.environ["API_BEARER_TOKEN"]}); print(urllib.request.urlopen(r, timeout=3).read().decode()[:2000])'
```

Metrics are not exposed through Caddy, and the raw application route returns 404 without the configured API credential. Caddy request access logs and Uvicorn access logs are disabled deliberately because signed asset tokens are bearer capabilities embedded in `/assets/...` paths and must not be copied into routine log streams. Application and proxy process/error logs remain available. Use MCP counters plus infrastructure telemetry for monitoring; add a redacting log pipeline before enabling request logs.

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

## Connected image scan and CVE triage

Digest pinning prevents silent image drift, but it does not make an image vulnerability-free. Run a platform-specific scan after building and before exposing the service:

```bash
docker compose build --pull app
APP_IMAGE="$(docker compose images -q app)"
CADDY_IMAGE="$(docker compose images -q caddy)"

# Full HIGH/CRITICAL report, including unfixed findings. Keep as release evidence.
trivy image --severity HIGH,CRITICAL --exit-code 0 "$APP_IMAGE" | tee app-image-cves.txt
trivy image --severity HIGH,CRITICAL --exit-code 0 "$CADDY_IMAGE" | tee caddy-image-cves.txt

# Automated gate for findings for which a fixed package is available.
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$APP_IMAGE"
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$CADDY_IMAGE"
```

Do not treat `--ignore-unfixed` as acceptance. Every remaining HIGH or CRITICAL result still needs documented CVE triage against the actual attack surface, an explicit temporary exception with owner/expiry, or a different rebuilt base image. Generate an SBOM for the exact deployed digest and retain it with both scan reports.

The production wheel uses pypdfium2/PDFium and the synthetic test corpus uses ReportLab/pypdf; PyMuPDF/MuPDF is not a project dependency. Preserve the license files bundled in the pypdfium2 wheel and the repository's `THIRD_PARTY_NOTICES.md` when redistributing the image.

## Supply-chain limitations

The Python and Caddy base images are pinned by immutable multi-platform index digest. Treat digest changes as reviewed dependency upgrades: update the tag and digest together, rebuild, scan the resulting image, and rerun the complete verification suite before deployment.

`requirements.lock` pins every direct and transitive runtime package and includes mechanically generated SHA-256 hashes for the resolved distributions; the version/pin set was reviewed, not every distribution file represented by those hashes. Docker and Alpic install it with `--require-hashes --no-deps --only-binary=:all:`. Hash locking constrains package bytes; it does not replace registry-account security, dependency review, image signing, or deployment by immutable image digest.
