# Security policy

## Supported versions

This repository is pre-release and has no supported public release yet. Security fixes are evaluated against the current `main` branch; that does not make `main` eligible for production deployment. When releases begin, this table will name each supported release line explicitly.

| Version | Security status |
| --- | --- |
| `main` | Pre-release fixes only; not a public-release claim |
| Tagged releases | None currently supported |

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/DavidOsipov/nplg-dspace-mcp/security/advisories/new). Do not open a public issue or include credentials, bearer tokens, private documents, or personal data in a report.

Include the affected revision, deployment profile, reproducible steps, impact, and any safe proof of concept. Maintainers will keep discussion and status updates in the private advisory until coordinated disclosure is appropriate.

## Response and remediation windows

The clock starts when a report or advisory source is authenticated and the affected package or revision is identified. These are maximum triage and remediation windows for a release candidate:

| Severity | Triage | Remediation |
| --- | ---: | ---: |
| Known exploited or Critical | 24 hours | 7 days |
| High | 3 days | 30 days |
| Medium | 14 days | 90 days |
| Low | 30 days | 180 days |

Unknown severity, unavailable or stale advisory evidence, unverifiable package provenance, and findings beyond the applicable window are each a release blocker. A time-bounded exception may support only a named non-public staging or private risk-accepted decision; it cannot establish public eligibility or ASVS conformance.

Maintainers will validate the report, identify affected supported revisions and profiles, prepare and verify a fix, notify the reporter through the private advisory, and coordinate any public advisory after users can obtain the fix.

## Dependency update evidence

Dependabot is discovery automation, not evidence that a finding was assessed, reachable, remediated, or safe to release. Release evidence must remain bound to the exact candidate revision, package identities, scanner inputs, and retained result digests.
