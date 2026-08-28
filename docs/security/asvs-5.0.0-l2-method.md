# ASVS 5.0.0 L2 matrix method

The checked-in source is the official English ASVS JSON at commit
`5cf9b032440be53ce345ab3c130fda46ba1ce7a2`. Its reviewed size is 149,407
bytes and its SHA-256 is recorded in `security/asvs/SHA256SUMS`.

`scripts/build_asvs_matrix.py fetch` accepts only the full immutable commit
URL, disables ambient proxies and redirects, enforces the reviewed byte
ceiling and exact digest, and atomically creates the source artifact. The
`verify-ref` command separately checks the full Git tag reference with Git
configuration, credential prompts, and proxy environment excluded.

The matrix contains every ASVS level-1 and level-2 requirement for each of
the three deployment profiles: `alpic-metadata`, `private-full`, and
`distributed-full`. The generated rows are currently `applicable` but
`Not assessed`; this is an honest implementation baseline, not a claim of
ASVS closure. A future `Pass` row must reference all policy-required evidence
kinds and bind each reference to the exact requirement, profile, invariant,
revision, and selector.

Applicability and verdict are a discriminated union. `N/A` requires explicit
absence evidence and a reviewer/review date. Risk acceptance requires a risk
identifier, owner, and approver. Local evidence is descriptor-bound and
path-safe; custodial evidence requires an allowlisted authority and a signed
versioned receipt in the later custody phase.

Assessment has two separate strict modes. `bootstrap` accepts only the
deterministic 759-row `Not assessed` inventory and empty evidence manifest.
`candidate` accepts exactly the 253 `alpic-metadata` rows bound to one commit
and tree: every row must be an independently evidenced `Pass` or a governed
`N/A`. A governed `N/A` requires fresh, reviewed, custodied
`claim_purpose="absence-proof"` evidence of an approved kind. Candidate mode
never converts, enriches, or otherwise relaxes the bootstrap inventory.
