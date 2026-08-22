# NPLG DSpace MCP security-repair verification

**Verification date:** 2026-08-14  
**Status:** locally verified working tree; not committed, pushed, or deployed  
**Base commit:** `97606dbaf61a8a1896fa8e706c80466991bf5a4b` (`main` / `origin/main` in this checkout)  
**Recovery source ref:** `origin/restore-python-source-20260814` at `ebbe23608daef550b7c0dbd0f6e14cd8c3f771a3`  
**Recovered archive SHA-256:** `f5fd546b60aaec7865904a984d7713eabd99dd63c89ca9d8784241874667466b`

## Release decision

The repaired working tree passes the local source, dependency, protocol, storage, PDF, and container checks recorded below. It is **not yet a deployable Git revision**: the remote-tracking `main` still points to the incomplete recovery tree, while the complete application and repairs are uncommitted working-tree changes. A fresh clone of current `main` will therefore still be incomplete.

Do not deploy from GitHub until an operator reviews the diff, creates a normal commit containing the complete tree, pushes it without rewriting unrelated history, and verifies the resulting fresh clone. No commit, push, force-push, workflow execution, or deployment was performed during this audit.

## Source recovery and provenance

The earlier claim that `a3fae1c` was the current deployment revision was stale. In this checkout it is an ancestor of `97606db`, and neither revision contains the application source. The `.bootstrap` payload reachable from `main` is truncated and cannot reconstruct the project.

The newer recovery ref was used instead. Before extraction:

- all 36 Base64 chunks matched `PARTS.sha256`;
- the assembled archive matched the SHA-256 above;
- all 65 source files matched the final manifest;
- the archive contained only safe regular files and directories, with no absolute paths, traversal components, duplicate paths, links, or unusual file types;
- the supplied repair shell and PowerShell scripts were inspected but never executed.

The verified source was restored locally and the obsolete recovery payload/workflows were removed from the working tree. All NTFS `:Zone.Identifier` sidecar files under the repository were deleted; the final count is zero. The original `.tmp/` recovery-kit directory is no longer present in the final working tree. `.serena/` and `lancedb` remain present and untouched; all three paths are excluded from Git and Docker contexts if present.

## Confirmed findings and repairs

### Authentication and administrative exposure

- Protected mode now fails configuration loading unless at least one real credential is configured.
- The server accepts either one bearer token or one `x-api-key`, compares it in constant time, and rejects ambiguous multiple credentials.
- The documented Alpic profile uses `ALLOW_ANONYMOUS=false` with a strong API key. This remains shared-key authentication, not per-user OAuth.
- `/metrics` is hidden unless the caller supplies a configured API credential; mixed or invalid credentials do not reveal it.
- Host and Origin parsing rejects duplicates, credentials, controls, malformed ports, encoded ambiguity, and non-matching authorities.

### MCP and JSON boundary handling

- Malformed UTF-8/JSON, excessive integer conversion, recursion overflow, duplicate JSON object keys, `NaN`, infinities, and exponent overflow now return stable JSON-RPC parse errors instead of propagating exceptions.
- Parse errors include the JSON-RPC-required `"id": null` when no request identifier can be recovered.
- Duplicate singleton MCP headers are rejected, and non-initialize requests may not silently assume the newest protocol when the protocol-version header is absent.
- Legacy method routing is bound to the parsed request rather than an attacker-controlled metrics header.
- Modern `resources/read` responses include the required cache metadata.
- Tool/domain failures are recorded as metric failures even when MCP represents them inside an HTTP 200 tool result.

### Availability and resource exhaustion

- `MAX_CONCURRENT_MCP_REQUESTS` implements a process-wide, fail-fast, zero-waiter gate around complete MCP request handling.
- `REQUEST_BODY_TIMEOUT_SECONDS` prevents a stalled authenticated upload from retaining a permit indefinitely.
- `MAX_CONCURRENT_ASSET_STREAMS` holds a separate permit across the complete signed-file ASGI response and releases it on normal completion, cancellation, or send failure.
- Asset responses stop local file reads when the ASGI peer disconnects.
- `MAX_CONCURRENT_HTTP_REQUESTS` is passed to Uvicorn as a larger server-wide ceiling for non-MCP traffic and connection/task growth.
- PDF concurrency ownership now follows completion of the native worker thread even if the client request is cancelled.
- Tile counts are bounded mathematically before materializing tile objects, closing the overlap/stride memory-exhaustion path.
- `CACHE_MAX_BYTES` supplies atomic logical-byte reservation and fail-closed aggregate cache accounting.

### Cache, render, and filesystem integrity

- Downloads and renders use one quota-aware staged writer; direct production writes cannot bypass reservations.
- Staging uses exclusive, non-following file descriptors and verifies descriptor/path identity and content again before publication, including symlink swaps, regular-file replacement, and same-inode mutation.
- File and directory data is synchronized around atomic publication.
- Page/tile rendering is transactional: quota or processing failures roll back unpublished output, while geometry-specific paths prevent caller-controlled cache-key collisions.
- Cached manifests are accepted only after request/source binding plus referenced-file existence and SHA-256 checks. Missing or corrupt output is reset and rebuilt under the render lock.
- Startup removes abandoned staging files and incomplete render/tile subtrees; deletion reconciles quota accounting.
- Concurrent requests for one render produce one deterministic result under the documented single-process cache model.

### Upstream request security

- Only the configured HTTPS NPLG origin, canonical approved paths, and public DNS answers are accepted across initial and redirect requests.
- Controls reject encoded path separators, dot segments, double encoding, backslashes, credentials, fragments, unexpected compression, excessive redirects, and oversized streamed responses.
- DNS is revalidated for each attempt rather than cached forever.
- The shared HTTP client rejects all cookies, preventing upstream `Set-Cookie` state from crossing MCP callers.
- Repository and download operations have bounded total time budgets and upstream pacing.

### Asset tokens and MCP metadata

- Non-ASCII or otherwise malformed capability tokens return the same bounded unauthorized response as other invalid tokens.
- Asset capabilities bind the exact canonical path, media type, and expiry under HMAC; responses use `no-store`, `nosniff`, same-site resource policy, and a restrictive sandbox policy.
- Cache-populating tools no longer claim to be locally read-only/idempotent in host approval metadata.
- Tool descriptions explicitly treat repository text and document metadata as untrusted data rather than instructions.

### Dependencies, build, and deployment hygiene

- Runtime dependencies are exact-pinned in `requirements.in` and locked with 403 SHA-256 distribution hashes across 24 conditional requirement blocks.
- Runtime install commands require hashes, prohibit dependency re-resolution, and require binary wheels.
- FastAPI, Starlette, and Click were raised to explicit security floors (`0.133.0`, `1.3.1`, and `8.3.3`).
- Python 3.13 is the declared deployment runtime; compatibility was also exercised on Python 3.14.
- Production documentation no longer prints rendered secrets through `docker compose config`, recommends protected Alpic authentication, and hardens the pinned backup helper with no network, a read-only filesystem, no capabilities, and no-new-privileges.
- Git/Docker ignores cover recovery files, editor state, virtual environments, secret variants, backups, bytecode, and nested egg-info metadata.
- A container-only failure found during this audit was repaired: restrictive recovered source modes made `/app/src/nplg_mcp` unreadable by UID 10001. The Docker build now normalizes application source to root-owned, read-only/traversable modes, and the non-root runtime imports and starts successfully.

## Verification evidence

| Check | Result |
| --- | --- |
| Python 3.13.13 full suite | `254 passed in 7.76s` |
| Python 3.14.5 full suite | `254 passed in 8.05s` |
| Independent storage/PDF affected suite | `68 passed in 5.68s` |
| Hash-enforced, binary-only runtime install | 23 applicable Linux packages installed on both Python versions |
| `uv pip check` | clean on Python 3.13 and 3.14 |
| `pip-audit -r requirements.lock` | no known vulnerabilities |
| Ruff `F,I` rules | all checks passed |
| `compileall` | exit 0; all 19 project Python files compiled outside the tree |
| Local process deployment verifier | pass; protocol `2026-07-28`, sessionless, 8 tools |
| Compose parse with example interpolation | exit 0 using quiet/no-env-resolution validation |
| Docker build | pass; final local image `sha256:f0884968ef93a562b4045e9161a909afc13638f24304dcbd79924d3ea6176614` |
| Hardened non-root image smoke | pass under read-only root, dropped capabilities, no-new-privileges, and tmpfs cache |
| Deployment verifier against built container | pass; health, readiness, protocol, sessionlessness, and 8-tool catalog |
| Fresh read-only GitHub ref check | `main=97606db…`; recovery ref `ebbe236…` |
| Zone.Identifier inventory | zero files |

Semgrep completed with no scanner errors and two reviewed heuristic warnings: the operator verifier's dynamic `urlopen` call (its base URL is constrained to HTTP(S), with non-loopback HTTP forbidden) and mode `0700` on the private staging directory (the rule incorrectly recommends a more public mode). Bandit reported the same constrained `urlopen` call and the fixed `/tmp` cache default used only by the single-tenant Alpic profile. Neither warning represents a demonstrated attack path in the shipped configuration.

The formal Codex Security deep-scan orchestration could not start because the environment exposed `permission_profile: disabled`; three attempts failed at preflight. Parallel manual review, focused adversarial reproductions, regression tests, Semgrep, Bandit, and dependency auditing were used as compensating evidence. Trivy, Grype, and Docker Scout were not installed locally. Docker Hub's platform-dependent scanner for the pinned Python base reports `CVE-2026-12087` as critical in Debian Perl plus additional high-severity OS-package findings. Debian classifies the Trixie Socket issue as `no-dsa`/minor and says the affected path requires attacker-controlled input to a Perl function; this application does not invoke Perl, so direct reachability was not demonstrated. That analysis is not a substitute for a scan of the exact target-platform application image and an owned exception or base-image change before promotion.

## Residual risk and required operational controls

- **Git publication remains blocked:** the complete tree must be reviewed, committed, pushed, and verified from a fresh clone. Do not force-push the bundled recovery commit over `main`.
- **Container CVE approval remains blocked:** scan the exact target-platform application and Caddy images, triage every HIGH/CRITICAL result (including unfixed findings), and record an owned exception or choose a repaired base before production exposure.
- Authentication is a shared bearer/API key. Use an OAuth-capable gateway when per-user identity, revocation, consent, or authorization is required.
- DNS validation is check-then-connect, not IP pinning. Enforce outbound DNS/HTTPS policy at the container/host boundary and allow only the NPLG origin.
- Admission is process-local, not a per-client rate limiter. Apply trusted edge limits before exposing the service to mutually untrusted clients.
- PDFium/Pillow process untrusted document bytes inside the application container, not a separately killable parser sandbox. Native jobs have a two-job concurrency bound but no enforceable execution deadline because a Python worker thread cannot safely kill a hung native call. Keep container memory/PID/restart limits and use a deadline-controlled process-isolated worker for a higher-risk deployment.
- Cache quota counts logical payload bytes in one exclusive writer process; it is not an inode/filesystem quota, automatic retention policy, or cross-process coordinator. Keep volume limits, disk alerts, and stop the service before manual cache surgery.
- Asset URLs are replayable bearer capabilities until expiry. Keep them out of logs and shorten TTL where the client workflow allows it.
- A saturated server-wide Uvicorn ceiling can also reject readiness traffic. Keep liveness cheap, reserve edge capacity for probes, and monitor saturation.
- Alpic's serverless execution and static asset model are not a full-fidelity target for the multi-call persistent PDF-rendering workflow. Docker/VPS is the supported complete deployment profile.
- Live NPLG HTML/OAI behavior, the official MCP SDK/Inspector, ChatGPT custom-app integration, target-host container scanning, and a fresh GitHub clone were not exercised in this environment.

## Normative references checked

- [MCP 2026-07-28 schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts)
- [MCP Streamable HTTP transport](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx)
- [MCP tool annotations](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/server/tools.mdx)
- [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification)
- [Alpic API-key authentication](https://docs.alpic.ai/secure/auth/token-bearer-setup)
- [Alpic OAuth authentication](https://docs.alpic.ai/secure/auth/oauth-setup)
- [Docker Hub scanner for the pinned Python image index](https://hub.docker.com/layers/library/python/3.13-slim-trixie/images/sha256-d738f49cdc17947d3a92cfcd404e79286428af114252d6166775d79ff4c78b2a)
- [Debian tracker for CVE-2026-12087](https://security-tracker.debian.org/tracker/CVE-2026-12087)
