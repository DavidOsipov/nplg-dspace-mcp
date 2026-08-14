# Critical Review of the NPLG DSpace MCP Implementation

**Review date:** 2026-08-14  
**Verdict:** deployable release candidate; production approval is blocked on the external release gates below

## Corrections made before release

1. **Protocol status was rechecked.** MCP `2026-07-28` is a released, sessionless protocol revision, not merely the older release-candidate state found during the first pass. The server implements its per-request metadata and HTTP-header model and retains a narrow `2025-11-25` compatibility path.
2. **Python was chosen for the tested PDF stack.** Python 3.13, FastAPI, HTTPX, pypdfium2/PDFium, Pillow, Beautiful Soup, lxml, and defusedxml were exercised offline. The obsolete TypeScript scaffold was removed rather than shipping two runtimes. Synthetic PDFs are generated with ReportLab and pypdf; PyMuPDF/MuPDF is absent from both production and test dependencies.
3. **The official Python SDK was not falsely claimed as tested.** The current SDK v2 supports the modern protocol, but dependency installation was unavailable in this isolated environment. The project therefore uses a small custom JSON-RPC/HTTP layer with direct conformance tests. Official SDK/Inspector interoperability remains a post-deploy gate.
4. **This is an NPLG adapter, not a generic DSpace connector.** It accepts canonical NPLG handles and only bitstreams discovered from validated NPLG item pages. Parser drift fails closed.
5. **Metadata prefixes are discovered.** OAI-DIM is preferred, `oai_dc` is a fallback, and bounded full XMLUI metadata is the final fallback.
6. **Native resolution was narrowed to a defensible claim.** Eligible single JPEG pages can be extracted byte-for-byte. Raster pages with overlays are compositor-rendered on the source scan's pixel grid. Vector or mixed pages are labelled `fallback_400_dpi`.
7. **No post-render resize does not imply no interpolation.** Every manifest records conversion path, resolution source, output dimensions, whether bytes were re-encoded, and whether renderer resampling may have occurred.
8. **Application-only SSRF checks were treated as insufficient.** Exact origin, global-address DNS validation, manual redirects, disabled proxy inheritance, and response limits are implemented. The deployment guide still requires infrastructure egress controls because DNS time-of-check/time-of-use risk remains.
9. **Upstream rate limiting now exists in code.** One shared limiter paces metadata and download request starts, including redirects.
10. **PDF concurrency is bounded.** A process-wide semaphore caps simultaneous inspect/render/tile operations; the default is two and the compiled maximum is four.
11. **Anonymous rendering is disabled by default in production.** A strong configured bearer token or API key is required unless the operator explicitly opts into anonymous access.
12. **Container hardening replaced unverifiable Bubblewrap claims.** The supplied deployment runs non-root with a read-only root filesystem, dropped capabilities, `no-new-privileges`, PID/CPU/memory limits, a private app port, and persistent cache storage. It does not claim a nested process sandbox exists.
13. **Dependency bytes are now locked.** Runtime packages are fully and exactly pinned, every requirement carries mechanically generated SHA-256 hashes for resolved distributions, and Docker/Alpic enforce `--require-hashes --no-deps --only-binary=:all:`. The version/pin set was reviewed; the hundreds of represented distribution files were not independently audited. Image signing and immutable deployment digests remain recommended independent controls.
14. **Cache retention is bounded but not automatically pruned.** A concurrency-safe 20 GiB logical-byte quota rejects new download/render writes before capacity is crossed; downloaded source PDFs remain retained. Production still needs a filesystem/inode limit, disk monitoring, and an operator-approved retention procedure.
15. **Tool annotations now distinguish cache writes from upstream mutation.** No public tool mutates NPLG and destructive render deletion remains operator-only. The download/page-render/tile tools truthfully advertise `readOnlyHint=false` because they populate local persistent cache state.
16. **Binary outputs are standard MCP resources.** Signed PDF, manifest, full-page JPEG, and tile URLs are emitted as `resource_link` content blocks as well as structured JSON, avoiding client-specific parsing of nested URL fields.
17. **Known example secrets fail closed.** Production startup rejects the documented placeholder strings even though they satisfy the minimum length requirement.
18. **Metadata response limits are streaming limits.** XMLUI/OAI responses are consumed incrementally and aborted as soon as the configured byte limit is exceeded; an untrusted upstream cannot force a full oversized response into memory first.
19. **Unexpected failures are logged without exception messages.** The wire layer records only the MCP method and exception class, preventing upstream URLs, tokens, or parser details from leaking through routine error logs.
20. **ChatGPT authentication compatibility is conditional.** Static bearer and `x-api-key` authentication are directly usable by clients that support custom headers, but both are shared secrets rather than per-user authorization. ChatGPT custom-app deployment must be tested with its currently offered auth mechanisms; use an OAuth gateway rather than anonymous Internet exposure when raw-header configuration is unavailable.
21. **Container base images are immutable but not presumed safe.** The Python and Caddy images are pinned by multi-platform digest. Digest pinning prevents silent drift; it does not replace a fresh image vulnerability scan or an exploitability review.
22. **The AGPL production dependency was removed.** The first implementation used PyMuPDF while the project itself was labelled MIT. Critical review treated that mismatch as a release blocker, replaced the runtime renderer with pypdfium2 5.8.0/PDFium, and replaced the synthetic fixture generator with ReportLab/pypdf. The replacement passes the same PDF invariants. pypdfium2/PDFium license notices remain mandatory in binary redistribution.
23. **Current base-image scanner output is non-zero.** On 2026-08-14, Docker Hub's platform-dependent scanner for the pinned Python image reported `CVE-2026-12087` as critical in Debian Perl plus additional high-severity OS-package findings. Scanner counts and affected-platform lists changed during the review, so no fixed count is treated as release evidence. Debian's tracker classifies the Trixie issue as `no-dsa`/minor and notes that the vulnerable function requires an attacker-controlled argument from a Perl script; this Python service does not invoke Perl, so direct reachability was not demonstrated. The findings still prevent an honest “zero known critical CVEs” claim and require a target-platform scan plus an owned exploitability decision before production exposure.
24. **Release scanning is now operationalized.** The deployment guide records both all HIGH/CRITICAL results (including unfixed findings) and an automated gate for fixable HIGH/CRITICAL findings. Unfixed results still require an owned exception, a different base image, or a rebuild; `--ignore-unfixed` is not acceptance.
25. **Modern unsupported-version errors now match the released protocol shape.** The error data contains the requested version and the complete supported-version list rather than the earlier non-standard `supportedVersions` field.
26. **Standard MCP headers follow HTTP optional-whitespace semantics.** Leading and trailing SP/HTAB are normalized before comparison; embedded controls and unsafe unencoded values remain rejected.
27. **Repository limits now match the approved contract.** Search requests are capped at 50 results, and metadata chunk size is checked before buffer extension rather than after an oversized chunk is already resident.
28. **Access denial is a domain result.** Upstream 401/403 responses from item and bitstream requests now map to `RESTRICTED`, so an agent does not misclassify an access policy as an availability failure.
29. **Asset expiry is exclusive.** A signed asset capability is rejected at its exact expiration second rather than remaining usable for one additional second.

## Evidence-backed confidence

- **High confidence:** canonical handle/origin enforcement, redirect and path validation, signed-token integrity, streaming limits, content addressing, crop-only tiling, MCP envelopes, error codes, parser behavior against pinned fixtures, and configuration boundaries.
- **Moderate confidence:** PDF classification and native-grid rendering across the synthetic corpus. Complex real-world PDFs can expose structures absent from the corpus.
- **Conditional confidence:** current live NPLG XMLUI/OAI compatibility, public bitstream behavior, real-document throughput, Caddy certificate issuance, official SDK/Inspector interoperability, and effective provider/host egress enforcement.

## Residual risks

- NPLG can change XMLUI markup, OAI behavior, throttling, DNS, or access policy without notice.
- A malicious or pathological PDF can exploit a PDFium/Pillow defect or exhaust the bounded container and cause a restart.
- The custom wire implementation can drift from future MCP revisions; protocol upgrades require new conformance fixtures.
- A bearer token is shared-secret authentication, not per-user authorization or audit identity. A multi-user ChatGPT deployment should terminate OAuth/OIDC at a reviewed gateway or implement MCP authorization directly.
- Signed asset URLs are bearer capabilities until expiry and must not be logged or forwarded unnecessarily.
- Single-node filesystem storage is unsuitable for horizontal replicas without object storage and coordination.
- Public technical access does not determine copyright or reuse rights.

## Release gate

Promote to production only after:

1. all offline tests and compilation checks pass;
2. local HTTP verification passes;
3. Docker Compose configuration validates on a Docker host;
4. platform-specific app and Caddy image scans are retained, all fixable HIGH/CRITICAL findings are cleared, and every remaining HIGH/CRITICAL finding has documented exploitability triage or a time-bounded exception;
5. post-deploy `verify_deploy.py` passes;
6. `smoke_live.py` succeeds against a current public NPLG item;
7. an operator verifies effective egress policy from inside the container;
8. the official MCP SDK or Inspector successfully lists and calls at least one tool;
9. the target ChatGPT/OpenAI client scans all eight tools, preserves their individual annotations, and can follow at least one returned `resource_link`.
