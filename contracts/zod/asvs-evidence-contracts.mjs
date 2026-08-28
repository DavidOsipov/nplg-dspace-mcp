import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { z } from "zod";
import {
  parseCanonicalBaselineContract,
} from "./baseline-contracts.mjs";

/** @typedef {import("zod").RefinementCtx} RefinementContext */

const ASVS_COMMIT = "5cf9b032440be53ce345ab3c130fda46ba1ce7a2";
const ASVS_SOURCE_BYTES = 149407;
const ASVS_SOURCE_SHA256 = "bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35";
const EVIDENCE_REVISION = "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0";
const CANDIDATE_TREE_SHA256 = "f50987fe97ed12a0da3295929e2ef8dba94693389a0a3bec2b2458a9f87aa32c";
const REVIEWED_THREAT_LEDGER_SHA256 = "b9c996bdacb533df9ca94a032e6c5925b095d078dc91b7689d5d8de9fe8bfa45";
const MATRIX_MAX_BYTES = 2 * 1024 * 1024;
const MATRIX_MAX_LINE_BYTES = 16 * 1024;
const MATRIX_RECORDS = 253 * 3;
const MANIFEST_MAX_BYTES = 8 * 1024 * 1024;
const MANIFEST_MAX_LINE_BYTES = 64 * 1024;
const MANIFEST_MAX_RECORDS = 4096;
const POLICY_MAX_BYTES = 2 * 1024 * 1024;
const THREAT_MAX_BYTES = 2 * 1024 * 1024;
const profiles = ["alpic-metadata", "private-full", "distributed-full"];
const requiredActors = [
  "deployment-operator",
  "edge-provider",
  "external-client",
  "malicious-client",
  "supply-chain-adversary",
  "untrusted-upstream",
];
const requiredTriggers = [
  "auth-change",
  "dependency-change",
  "deployment-change",
  "profile-or-boundary-change",
  "protocol-change",
  "runtime-change",
  "storage-change",
];
const requiredBoundaries = new Set([
  "client-to-alpic-edge",
  "alpic-edge-to-backend",
  "backend-to-nplg-jwks",
  "scanner-to-content-store",
  "scanner-to-pdf-worker",
  "build-to-deploy",
  "logging-privacy",
]);
const requiredFlowPairs = new Set([
  "external-client\0alpic-edge",
  "alpic-edge\0python-backend",
  "python-backend\0nplg-api",
  "python-backend\0jwks-provider",
  "scanner\0content-store",
  "content-store\0pdf-worker",
  "ci-build\0alpic-edge",
  "python-backend\0audit-log-store",
]);
const requiredEntryPointIds = [
  "entry-alpic-forward",
  "entry-audit-log-store",
  "entry-content-store",
  "entry-deployment-publication",
  "entry-jwks-provider",
  "entry-nplg-repository-api",
  "entry-pdf-worker",
  "entry-public-mcp",
];
const requiredSupplyChainMappings = [
  "v5.0.0-V15.1.1",
  "v5.0.0-V15.1.2",
  "v5.0.0-V15.2.1",
];
const requiredReviewedThreatMappings = {
  nodes: [
    ["alpic-edge", "provider", "edge-provider-zone", ["route-mcp-traffic"], [
      "access-tokens", "deployment-provenance", "mcp-envelopes",
    ]],
    ["audit-log-store", "data-store", "operations-zone", ["retain-audit-events"], [
      "audit-events",
    ]],
    ["ci-build", "service", "build-zone", ["publish-deployment-artifacts"], [
      "deployment-provenance",
    ]],
    ["content-store", "data-store", "content-zone", ["store-public-content"], [
      "public-content", "derived-images",
    ]],
    ["external-client", "external", "untrusted-client-zone", ["submit-mcp-request"], [
      "access-tokens", "mcp-envelopes",
    ]],
    ["jwks-provider", "provider", "identity-provider-zone", ["publish-verification-keys"], [
      "access-tokens",
    ]],
    ["nplg-api", "provider", "nplg-upstream-zone", ["serve-public-repository-content"], [
      "public-content", "repository-locators",
    ]],
    ["pdf-worker", "worker", "isolated-parser-zone", ["render-untrusted-pdf"], [
      "public-content", "derived-images",
    ]],
    ["python-backend", "service", "application-zone", [
      "authorize-and-dispatch", "fetch-public-content",
    ], [
      "access-tokens", "audit-events", "mcp-envelopes", "public-content",
      "repository-locators",
    ]],
    ["scanner", "worker", "isolated-scanner-zone", ["classify-untrusted-content"], [
      "public-content",
    ]],
  ],
  flows: [
    ["flow-backend-jwks", "python-backend", "jwks-provider", "backend-to-nplg-jwks",
      "HTTPS JWKS retrieval", ["access-tokens"]],
    ["flow-backend-log", "python-backend", "audit-log-store", "logging-privacy",
      "Structured audit event transport", ["audit-events"]],
    ["flow-backend-nplg", "python-backend", "nplg-api", "backend-to-nplg-upstream",
      "Bounded HTTPS repository request", ["public-content", "repository-locators"]],
    ["flow-ci-edge", "ci-build", "alpic-edge", "build-to-deploy",
      "Provider deployment publication", ["deployment-provenance"]],
    ["flow-client-edge", "external-client", "alpic-edge", "client-to-alpic-edge",
      "MCP over HTTPS", ["access-tokens", "mcp-envelopes"]],
    ["flow-content-pdf", "content-store", "pdf-worker", "scanner-to-pdf-worker",
      "Descriptor-bound worker input", ["public-content", "derived-images"]],
    ["flow-edge-backend", "alpic-edge", "python-backend", "alpic-edge-to-backend",
      "Forwarded MCP request", ["access-tokens", "mcp-envelopes"]],
    ["flow-scanner-content", "scanner", "content-store", "scanner-to-content-store",
      "Digest-bound scan verdict", ["public-content"]],
  ],
  entryPoints: [
    ["entry-alpic-forward", "flow-edge-backend", "python-backend", "application-enforced",
      profiles, ["access-tokens", "mcp-envelopes"]],
    ["entry-audit-log-store", "flow-backend-log", "audit-log-store", "trusted-workload",
      profiles, ["audit-events"]],
    ["entry-content-store", "flow-scanner-content", "content-store", "application-enforced",
      ["private-full", "distributed-full"], ["public-content"]],
    ["entry-deployment-publication", "flow-ci-edge", "alpic-edge", "trusted-workload",
      profiles, ["deployment-provenance"]],
    ["entry-jwks-provider", "flow-backend-jwks", "jwks-provider", "provider-mediated",
      profiles, ["access-tokens"]],
    ["entry-nplg-repository-api", "flow-backend-nplg", "nplg-api", "provider-mediated",
      profiles, ["public-content", "repository-locators"]],
    ["entry-pdf-worker", "flow-content-pdf", "pdf-worker", "application-enforced",
      ["private-full", "distributed-full"], ["public-content", "derived-images"]],
    ["entry-public-mcp", "flow-client-edge", "alpic-edge", "provider-mediated",
      profiles, ["access-tokens", "mcp-envelopes"]],
  ],
  threats: [
    ["threat-auth-token-spoofing", ["flow-backend-jwks", "flow-edge-backend"],
      ["alpic-edge-to-backend", "backend-to-nplg-jwks"], ["S"], ["token-session"], profiles,
      ["oauth-provider-capability-contract", "sdk-authorization-capability-contract"],
      ["v5.0.0-V10.3.1", "v5.0.0-V6.8.2", "v5.0.0-V7.2.1", "v5.0.0-V9.2.2"],
      ["alpic-routing-contract", "jwks-publication-contract"], "risk-auth-token-spoofing",
      "identity-owner", "2026-12-31"],
    ["threat-confused-deputy", ["flow-client-edge", "flow-edge-backend"],
      ["alpic-edge-to-backend", "client-to-alpic-edge"], ["T"], ["confused-deputy"], profiles,
      ["alpic-oauth-discovery-contract", "mcp-tool-authorization-contract"],
      ["v5.0.0-V8.2.1", "v5.0.0-V8.2.2"], ["alpic-routing-contract"],
      "risk-confused-deputy", "application-security-owner", "2026-12-31"],
    ["threat-log-repudiation", ["flow-backend-log"], ["logging-privacy"], ["R"],
      ["logging-privacy"], profiles, ["audit-event-schema", "credential-canary-log-test"],
      ["v5.0.0-V16.1.1", "v5.0.0-V16.2.5", "v5.0.0-V16.4.1"],
      ["audit-log-custody"], "risk-log-repudiation", "security-operations-owner",
      "2026-12-31"],
    ["threat-parser-exhaustion", ["flow-content-pdf", "flow-scanner-content"],
      ["scanner-to-content-store", "scanner-to-pdf-worker"], ["D"],
      ["parser-resource-exhaustion"], ["private-full", "distributed-full"],
      ["pdf-worker-resource-fault-suite", "scanner-content-binding-suite"],
      ["v5.0.0-V5.1.1", "v5.0.0-V5.2.1", "v5.0.0-V5.2.3", "v5.0.0-V5.4.3"],
      ["nplg-upstream-contract"], "risk-parser-exhaustion", "content-security-owner",
      "2026-12-31"],
    ["threat-ssrf-proxy", ["flow-backend-nplg"], ["backend-to-nplg-upstream"], ["I"],
      ["ssrf-dns-proxy"], profiles,
      ["downloader-rebinding-fault-suite", "repository-origin-policy"],
      ["v5.0.0-V1.3.6", "v5.0.0-V13.2.4", "v5.0.0-V13.2.5"],
      ["nplg-upstream-contract"], "risk-ssrf-proxy", "network-security-owner", "2026-12-31"],
    ["threat-supply-chain", ["flow-ci-edge"], ["build-to-deploy"], ["E"],
      ["supply-chain-build-deploy"], profiles,
      ["bootstrap-toolchain-fault-suite", "deployment-provenance-attestation"],
      ["v5.0.0-V15.1.1", "v5.0.0-V15.1.2", "v5.0.0-V15.2.1"],
      ["alpic-routing-contract", "build-runtime-custody"], "risk-supply-chain",
      "release-owner", "2026-12-31"],
  ],
  residualRisks: [
    ["risk-auth-token-spoofing", ["threat-auth-token-spoofing"], "identity-owner", "2026-12-31"],
    ["risk-confused-deputy", ["threat-confused-deputy"], "application-security-owner",
      "2026-12-31"],
    ["risk-log-repudiation", ["threat-log-repudiation"], "security-operations-owner",
      "2026-12-31"],
    ["risk-parser-exhaustion", ["threat-parser-exhaustion"], "content-security-owner",
      "2026-12-31"],
    ["risk-ssrf-proxy", ["threat-ssrf-proxy"], "network-security-owner", "2026-12-31"],
    ["risk-supply-chain", ["threat-supply-chain"], "release-owner", "2026-12-31"],
  ],
};

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);
const caseIdSchema = z.string()
  .min(1)
  .max(128)
  .regex(/^[a-z0-9][a-z0-9._-]{0,127}$/u);
const gitRevisionSchema = z.string().regex(/^[0-9a-f]{40}$/u);
const requirementIdSchema = z.string()
  .max(256)
  .regex(/^v5\.0\.0-[A-Za-z0-9._-]+$/u);
const nonEmptySchema = z.string()
  .min(1)
  .max(8192)
  .refine((value) => {
    for (const character of value) {
      const codePoint = character.codePointAt(0);
      if (codePoint === undefined || codePoint < 0x20 || codePoint === 0x7f) {
        return false;
      }
    }
    return true;
  }, "string contains a forbidden control character");
const profileSchema = z.enum(profiles);
const evidenceKindSchema = z.enum(["design", "code_config", "test", "operational"]);
const dateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/u).refine((value) => {
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.valueOf())
    && parsed.toISOString().slice(0, 10) === value;
}, "date must be a real canonical calendar date");
const awareDatetimePattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:Z|[+-](\d{2}):(\d{2}))$/u;
const awareDatetimeSchema = z.string()
  .max(64)
  .regex(awareDatetimePattern)
  .refine((value) => {
    const match = awareDatetimePattern.exec(value);
    if (match === null) {
      return false;
    }
    const [, year, month, day, hour, minute, second, offsetHour, offsetMinute] = match;
    if (
      year === undefined
      || month === undefined
      || day === undefined
      || hour === undefined
      || minute === undefined
      || second === undefined
    ) {
      return false;
    }
    const parsedHour = Number.parseInt(hour, 10);
    const parsedMinute = Number.parseInt(minute, 10);
    const parsedSecond = Number.parseInt(second, 10);
    const offsetIsValid = (offsetHour === undefined && offsetMinute === undefined)
      || (
        offsetHour !== undefined
        && offsetMinute !== undefined
        && Number.parseInt(offsetHour, 10) <= 23
        && Number.parseInt(offsetMinute, 10) <= 59
      );
    return dateSchema.safeParse(`${year}-${month}-${day}`).success
      && parsedHour <= 23
      && parsedMinute <= 59
      && parsedSecond <= 59
      && offsetIsValid
      && Number.isFinite(Date.parse(value));
  }, "datetime must be valid");

/**
 * @param {RefinementContext} context
 * @param {readonly (string | number)[]} path
 * @param {string} message
 */
function issue(context, path, message) {
  context.addIssue({ code: "custom", path: [...path], message });
}

/**
 * @param {readonly string[]} values
 * @returns {boolean}
 */
function isUnique(values) {
  return new Set(values).size === values.length;
}

/**
 * @param {readonly string[]} values
 * @returns {boolean}
 */
function isSorted(values) {
  for (let index = 1; index < values.length; index += 1) {
    const previous = values[index - 1];
    const current = values[index];
    if (
      previous === undefined
      || current === undefined
      || Buffer.compare(Buffer.from(previous, "utf8"), Buffer.from(current, "utf8")) >= 0
    ) {
      return false;
    }
  }
  return true;
}

/**
 * @param {readonly string[]} left
 * @param {readonly string[]} right
 * @returns {boolean}
 */
function sameStrings(left, right) {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {readonly unknown[]} nodes
 * @param {Map<string, { text: string, level: 1 | 2 }>} requirements
 */
function collectOfficialRequirements(nodes, requirements) {
  for (const node of nodes) {
    if (!isRecord(node)) {
      throw new Error("pinned ASVS source contains a non-object requirement node");
    }
    if (Array.isArray(node["Items"])) {
      collectOfficialRequirements(node["Items"], requirements);
      continue;
    }
    if (
      typeof node["Shortcode"] !== "string"
      || typeof node["Description"] !== "string"
      || !["1", "2", "3"].includes(String(node["L"]))
    ) {
      throw new Error("pinned ASVS source contains a malformed requirement leaf");
    }
    if (node["L"] === "3") {
      continue;
    }
    const requirementId = `v5.0.0-${node["Shortcode"]}`;
    if (requirements.has(requirementId)) {
      throw new Error("pinned ASVS source contains a duplicate requirement");
    }
    requirements.set(requirementId, {
      level: node["L"] === "1" ? 1 : 2,
      text: node["Description"],
    });
  }
}

/**
 * @param {unknown} raw
 * @returns {Map<string, { text: string, level: 1 | 2 }>}
 */
function parsePinnedAsvsRequirements(raw) {
  if (!(raw instanceof Uint8Array)) {
    throw new Error("pinned ASVS source must be raw bytes");
  }
  const body = Buffer.from(raw);
  if (
    body.length !== ASVS_SOURCE_BYTES
    || createHash("sha256").update(body).digest("hex") !== ASVS_SOURCE_SHA256
  ) {
    throw new Error("pinned ASVS source does not match its reviewed identity");
  }
  /** @type {unknown} */
  const decoded = JSON.parse(body.toString("utf8"));
  if (
    !isRecord(decoded)
    || decoded["Version"] !== "5.0.0"
    || !Array.isArray(decoded["Requirements"])
  ) {
    throw new Error("pinned ASVS source envelope is malformed");
  }
  /** @type {Map<string, { text: string, level: 1 | 2 }>} */
  const requirements = new Map();
  collectOfficialRequirements(decoded["Requirements"], requirements);
  const levels = [...requirements.values()].reduce(
    (counts, requirement) => ({
      level1: counts.level1 + (requirement.level === 1 ? 1 : 0),
      level2: counts.level2 + (requirement.level === 2 ? 1 : 0),
    }),
    { level1: 0, level2: 0 },
  );
  if (requirements.size !== 253 || levels.level1 !== 70 || levels.level2 !== 183) {
    throw new Error("pinned ASVS source does not contain the reviewed L1/L2 product");
  }
  return requirements;
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function isCanonicalRelativePath(value) {
  return value.length > 0
    && value.length <= 4096
    && !value.startsWith("/")
    && !value.endsWith("/")
    && !value.includes("\\")
    && !value.includes("\0")
    && !value.includes("\r")
    && !value.includes("\n")
    && value.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function isImmutableEvidenceUri(value) {
  if (value.length > 4096 || value.includes("%")) {
    return false;
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.search !== ""
    || parsed.hash !== ""
    || parsed.port !== ""
    || parsed.href !== value
  ) {
    return false;
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.+$/u, "");
  if (
    hostname === "localhost"
    || hostname.endsWith(".localhost")
    || hostname.endsWith(".local")
    || hostname === "metadata.google.internal"
    || isIP(hostname) !== 0
  ) {
    return false;
  }
  const parts = parsed.pathname.split("/").filter((part) => part !== "");
  const mutableNames = new Set(["latest", "current", "head"]);
  return parsed.pathname.startsWith("/")
    && !parsed.pathname.endsWith("/")
    && parts.every((part) => !mutableNames.has(part.toLowerCase()))
    && parts.some((part) => /^[0-9a-f]{64}$/u.test(part));
}

const commonRowShape = {
  asvs_version: z.literal("5.0.0"),
  requirement_id: requirementIdSchema,
  level: z.union([z.literal(1), z.literal(2)]),
  requirement_text: nonEmptySchema,
  profile: profileSchema,
  evidence_revision: z.literal(EVIDENCE_REVISION),
  invariant: nonEmptySchema,
  threat_boundary: caseIdSchema,
  evidence_ids: z.array(caseIdSchema).max(128),
  required_evidence_kinds: z.array(evidenceKindSchema).max(4),
  owner: caseIdSchema,
  target_phase: caseIdSchema,
  evidence_date: dateSchema,
};

const applicableRowSchema = z.strictObject({
  ...commonRowShape,
  applicability: z.literal("applicable"),
  applicability_rationale: nonEmptySchema,
  verdict: z.enum(["Pass", "Fail", "Partial", "Not assessed", "Risk accepted"]),
  risk_id: caseIdSchema.nullable().optional(),
  risk_owner: nonEmptySchema.nullable().optional(),
  risk_approver: nonEmptySchema.nullable().optional(),
  residual_risk: nonEmptySchema.nullable().optional(),
  compensating_controls: z.array(caseIdSchema).max(128).nullable().optional(),
  risk_expiry: dateSchema.nullable().optional(),
  release_approval_evidence_id: caseIdSchema.nullable().optional(),
}).superRefine((value, context) => {
  if (!isUnique(value.evidence_ids) || !isUnique(value.required_evidence_kinds)) {
    issue(context, ["evidence_ids"], "row evidence identifiers and kinds must be unique");
  }
  const riskFields = [
    "risk_id",
    "risk_owner",
    "risk_approver",
    "residual_risk",
    "compensating_controls",
    "risk_expiry",
    "release_approval_evidence_id",
  ];
  const supplied = riskFields.filter((field) => Object.hasOwn(value, field));
  if (value.verdict === "Risk accepted") {
    if (
      supplied.length !== riskFields.length
      || value.risk_id == null
      || value.risk_owner == null
      || value.risk_approver == null
      || value.residual_risk == null
      || value.compensating_controls == null
      || value.compensating_controls.length === 0
      || !isUnique(value.compensating_controls)
      || value.risk_expiry == null
      || value.risk_expiry <= value.evidence_date
      || value.release_approval_evidence_id == null
    ) {
      issue(context, ["verdict"], "Risk accepted requires complete external approval fields");
    }
  } else if (supplied.length !== 0) {
    issue(context, ["verdict"], "risk fields are forbidden outside Risk accepted");
  }
  if (
    value.verdict === "Pass"
    && (value.evidence_ids.length === 0 || value.required_evidence_kinds.length === 0)
  ) {
    issue(context, ["verdict"], "Pass requires named evidence and evidence kinds");
  }
}).readonly();

const notApplicableRowSchema = z.strictObject({
  ...commonRowShape,
  applicability: z.literal("not_applicable"),
  verdict: z.literal("N/A"),
  applicability_rationale: nonEmptySchema,
  applicability_reviewer: nonEmptySchema,
  applicability_review_due: dateSchema,
  absence_evidence_ids: z.array(caseIdSchema).min(1).max(128),
}).superRefine((value, context) => {
  if (
    value.evidence_ids.length !== 0
    || value.required_evidence_kinds.length !== 0
    || !isUnique(value.absence_evidence_ids)
    || value.applicability_review_due <= value.evidence_date
  ) {
    issue(context, ["verdict"], "N/A state is incomplete or contradictory");
  }
}).readonly();

export const evidenceRowSchema = z.discriminatedUnion("applicability", [
  applicableRowSchema,
  notApplicableRowSchema,
]);

const claimPolicySchema = z.strictObject({
  requirement_id: requirementIdSchema,
  profile: profileSchema,
  pass_required_kinds: z.array(evidenceKindSchema).max(4).nullable(),
  na_absence_required: z.boolean(),
  risk_acceptance_authority_id: caseIdSchema.nullable(),
}).superRefine((value, context) => {
  if (
    value.pass_required_kinds !== null
    && (
      value.pass_required_kinds.length === 0
      || !isUnique(value.pass_required_kinds)
      || !isSorted(value.pass_required_kinds)
    )
  ) {
    issue(context, ["pass_required_kinds"], "Pass kinds must be nonempty, unique, and sorted");
  }
}).readonly();

export const evidencePolicySchema = z.strictObject({
  schema_version: z.literal("2.0"),
  asvs_version: z.literal("5.0.0"),
  asvs_source_commit: z.literal(ASVS_COMMIT),
  evidence_revision: z.literal(EVIDENCE_REVISION),
  candidate_tree_sha256: z.literal(CANDIDATE_TREE_SHA256),
  attestation_allowlist: z.tuple([
    z.literal("docs/security/asvs-evidence-policy.json"),
    z.literal("docs/security/threat-model.json"),
  ]),
  profiles: z.tuple([
    z.literal("alpic-metadata"),
    z.literal("private-full"),
    z.literal("distributed-full"),
  ]),
  claims: z.array(claimPolicySchema).length(MATRIX_RECORDS),
  custody_authority_ids: z.array(caseIdSchema).max(128),
  release_authority_ids: z.array(caseIdSchema).max(128),
}).superRefine((value, context) => {
  const keys = value.claims.map((claim) => `${claim.requirement_id}\0${claim.profile}`);
  if (!isUnique(keys)) {
    issue(context, ["claims"], "policy claim identities must be unique");
  }
  const sorted = [...value.claims].sort((left, right) => {
    const requirementComparison = Buffer.compare(
      Buffer.from(left.requirement_id, "utf8"),
      Buffer.from(right.requirement_id, "utf8"),
    );
    return requirementComparison !== 0
      ? requirementComparison
      : profiles.indexOf(left.profile) - profiles.indexOf(right.profile);
  });
  if (value.claims.some((claim, index) => claim !== sorted[index])) {
    issue(context, ["claims"], "policy claims are not canonically ordered");
  }
  if (
    !isUnique(value.custody_authority_ids)
    || !isSorted(value.custody_authority_ids)
    || !isUnique(value.release_authority_ids)
    || !isSorted(value.release_authority_ids)
  ) {
    issue(context, ["release_authority_ids"], "authority identifiers must be unique and sorted");
  }
  const releaseAuthorities = new Set(value.release_authority_ids);
  if (value.claims.some((claim) => (
    claim.risk_acceptance_authority_id !== null
    && !releaseAuthorities.has(claim.risk_acceptance_authority_id)
  ))) {
    issue(context, ["claims"], "risk claim names an unapproved release authority");
  }
}).readonly();

const evidenceCommonShape = {
  evidence_id: caseIdSchema,
  kind: evidenceKindSchema,
  requirement_ids: z.array(requirementIdSchema).min(1).max(253),
  profiles: z.array(profileSchema).min(1).max(3),
  asserted_invariant: nonEmptySchema,
  covered_surface: nonEmptySchema,
  selectors: z.array(nonEmptySchema).min(1).max(512),
  sha256: sha256Schema,
  result: z.literal("pass"),
  evidence_revision: z.literal(EVIDENCE_REVISION),
  candidate_tree_sha256: z.literal(CANDIDATE_TREE_SHA256),
  deployment_id: nonEmptySchema.nullable(),
  image_digest: sha256Schema.nullable(),
  collected_at: awareDatetimeSchema,
  reviewer: nonEmptySchema,
  expires_at: awareDatetimeSchema,
};

const localEvidenceSchema = z.strictObject({
  ...evidenceCommonShape,
  storage: z.literal("local"),
  artifact_path: z.string().refine(isCanonicalRelativePath, "artifact path is unsafe"),
  verifier: z.enum([
    "sha256-file-v1",
    "json-record-v1",
    "test-report-v1",
    "config-symbol-v1",
  ]),
}).superRefine(validateEvidenceReference).readonly();

const custodiedEvidenceSchema = z.strictObject({
  ...evidenceCommonShape,
  storage: z.literal("custodied-uri"),
  immutable_artifact_uri: z.string().refine(
    isImmutableEvidenceUri,
    "custodied evidence URI is not immutable and safe",
  ),
  artifact_object_version: nonEmptySchema,
  custody_authority_id: caseIdSchema,
  custody_receipt_id: caseIdSchema,
  verifier: z.literal("ci-custody-v1"),
}).superRefine(validateEvidenceReference).readonly();

/**
 * @param {{
 *   requirement_ids: readonly string[],
 *   profiles: readonly string[],
 *   selectors: readonly string[],
 *   expires_at: string,
 *   collected_at: string
 * }} value
 * @param {RefinementContext} context
 */
function validateEvidenceReference(value, context) {
  if (
    !isUnique(value.requirement_ids)
    || !isUnique(value.profiles)
    || !isUnique(value.selectors)
    || Date.parse(value.expires_at) <= Date.parse(value.collected_at)
  ) {
    issue(context, ["expires_at"], "evidence membership or lifetime is invalid");
  }
}

export const evidenceReferenceSchema = z.discriminatedUnion("storage", [
  localEvidenceSchema,
  custodiedEvidenceSchema,
]);

const threatNodeSchema = z.strictObject({
  node_id: caseIdSchema,
  node_kind: z.enum(["external", "service", "provider", "data-store", "worker"]),
  trust_zone: caseIdSchema,
  privileges: z.array(caseIdSchema).min(1).max(128),
  data_classes: z.array(caseIdSchema).min(1).max(128),
}).readonly();
const threatFlowSchema = z.strictObject({
  flow_id: caseIdSchema,
  source: caseIdSchema,
  target: caseIdSchema,
  boundary_id: caseIdSchema,
  protocol: nonEmptySchema,
  data_classes: z.array(caseIdSchema).min(1).max(128),
}).readonly();
const threatEntryPointSchema = z.strictObject({
  entry_point_id: caseIdSchema,
  flow_id: caseIdSchema,
  exposed_node_id: caseIdSchema,
  access_control: z.enum([
    "application-enforced",
    "provider-mediated",
    "trusted-workload",
  ]),
  affected_profiles: z.array(profileSchema).min(1).max(3),
  data_classes: z.array(caseIdSchema).min(1).max(128),
}).readonly();
const providerAssumptionSchema = z.strictObject({
  assumption_id: caseIdSchema,
  provider: caseIdSchema,
  control: nonEmptySchema,
  owner: caseIdSchema,
  status: z.literal("assumption-unverified"),
  invalidation_trigger: nonEmptySchema,
}).readonly();
const strideSchema = z.enum(["S", "T", "R", "I", "D", "E"]);
const abuseSchema = z.enum([
  "token-session",
  "confused-deputy",
  "ssrf-dns-proxy",
  "parser-resource-exhaustion",
  "supply-chain-build-deploy",
  "logging-privacy",
]);
const threatRecordSchema = z.strictObject({
  threat_id: caseIdSchema,
  title: nonEmptySchema,
  flow_ids: z.array(caseIdSchema).min(1).max(128),
  boundary_ids: z.array(caseIdSchema).min(1).max(128),
  stride_categories: z.array(strideSchema).min(1).max(6),
  abuse_categories: z.array(abuseSchema).min(1).max(6),
  abuse_case: nonEmptySchema,
  affected_profiles: z.array(profileSchema).min(1).max(3),
  mitigations: z.array(nonEmptySchema).min(1).max(128),
  verification_selectors: z.array(nonEmptySchema).min(1).max(128),
  asvs_requirement_ids: z.array(requirementIdSchema).min(1).max(253),
  assumed_provider_control_ids: z.array(caseIdSchema).max(128),
  residual_risk_id: caseIdSchema,
  owner: caseIdSchema,
  verification_status: z.literal("not_assessed"),
  review_due: dateSchema,
  invalidation_triggers: z.array(nonEmptySchema).min(1).max(128),
}).superRefine((value, context) => {
  const mappings = [
    value.flow_ids,
    value.boundary_ids,
    value.stride_categories,
    value.abuse_categories,
    value.affected_profiles,
    value.verification_selectors,
    value.asvs_requirement_ids,
    value.assumed_provider_control_ids,
    value.invalidation_triggers,
  ];
  if (mappings.some((mapping) => !isUnique(mapping))) {
    issue(context, ["threat_id"], "threat mappings must be unique");
  }
}).readonly();
const residualRiskSchema = z.strictObject({
  residual_risk_id: caseIdSchema,
  threat_ids: z.array(caseIdSchema).min(1).max(128),
  description: nonEmptySchema,
  disposition: z.literal("open-do-not-release"),
  owner: caseIdSchema,
  review_due: dateSchema,
}).readonly();

export const threatLedgerSchema = z.strictObject({
  schema_version: z.literal("1.0"),
  evidence_revision: z.literal(EVIDENCE_REVISION),
  candidate_tree_sha256: z.literal(CANDIDATE_TREE_SHA256),
  assets: z.array(caseIdSchema).min(1).max(128),
  data_classes: z.array(caseIdSchema).min(1).max(128),
  actors: z.array(caseIdSchema).min(1).max(128),
  nodes: z.array(threatNodeSchema).min(1).max(128),
  flows: z.array(threatFlowSchema).min(1).max(128),
  entry_points: z.array(threatEntryPointSchema).min(1).max(128),
  provider_assumptions: z.array(providerAssumptionSchema).min(1).max(128),
  threats: z.array(threatRecordSchema).min(1).max(128),
  residual_risks: z.array(residualRiskSchema).min(1).max(128),
  global_invalidation_triggers: z.array(nonEmptySchema).min(1).max(128),
  release_status: z.literal("do_not_release"),
}).superRefine((value, context) => {
  const orderedCollections = [
    value.assets,
    value.data_classes,
    value.actors,
    value.nodes.map(({ node_id: identifier }) => identifier),
    value.flows.map(({ flow_id: identifier }) => identifier),
    value.entry_points.map(({ entry_point_id: identifier }) => identifier),
    value.provider_assumptions.map(({ assumption_id: identifier }) => identifier),
    value.threats.map(({ threat_id: identifier }) => identifier),
    value.residual_risks.map(({ residual_risk_id: identifier }) => identifier),
    value.global_invalidation_triggers,
  ];
  if (orderedCollections.some((items) => !isUnique(items) || !isSorted(items))) {
    issue(context, [], "threat ledger identifiers must be unique and canonically ordered");
  }
  if (!sameStrings(value.actors, requiredActors)) {
    issue(context, ["actors"], "threat actor inventory is incomplete");
  }
  if (!sameStrings(value.global_invalidation_triggers, requiredTriggers)) {
    issue(context, ["global_invalidation_triggers"], "invalidation triggers are incomplete");
  }
  const nodeIds = new Set(value.nodes.map(({ node_id }) => node_id));
  const nodesById = new Map(value.nodes.map((node) => [node.node_id, node]));
  const flowIds = new Set(value.flows.map(({ flow_id }) => flow_id));
  const flowsById = new Map(value.flows.map((flow) => [flow.flow_id, flow]));
  const boundaryIds = new Set(value.flows.map(({ boundary_id }) => boundary_id));
  const providerIds = new Set(
    value.provider_assumptions.map(({ assumption_id }) => assumption_id),
  );
  const threatIds = new Set(value.threats.map(({ threat_id }) => threat_id));
  const residuals = new Map(
    value.residual_risks.map((risk) => [risk.residual_risk_id, risk]),
  );
  if ([...requiredBoundaries].some((boundary) => !boundaryIds.has(boundary))) {
    issue(context, ["flows"], "required trust boundary is absent");
  }
  const flowPairs = new Set(value.flows.map((flow) => `${flow.source}\0${flow.target}`));
  if ([...requiredFlowPairs].some((pair) => !flowPairs.has(pair))) {
    issue(context, ["flows"], "required data-flow edge is absent");
  }
  if (value.flows.some((flow) => !nodeIds.has(flow.source) || !nodeIds.has(flow.target))) {
    issue(context, ["flows"], "flow references an unknown node");
  }
  if (value.flows.some((flow) => {
    const source = nodesById.get(flow.source);
    const target = nodesById.get(flow.target);
    return source === undefined
      || target === undefined
      || flow.data_classes.some((item) => !source.data_classes.includes(item))
      || flow.data_classes.some((item) => !target.data_classes.includes(item));
  })) {
    issue(context, ["flows"], "flow data classes are not carried by both endpoint nodes");
  }
  const declaredDataClasses = new Set(value.data_classes);
  if (
    value.nodes.some((node) => node.data_classes.some((item) => !declaredDataClasses.has(item)))
    || value.flows.some((flow) => flow.data_classes.some(
      (item) => !declaredDataClasses.has(item)
    ))
    || value.entry_points.some((entry) => entry.data_classes.some(
      (item) => !declaredDataClasses.has(item)
    ))
  ) {
    issue(context, ["data_classes"], "topology references an undeclared data class");
  }
  const entryFlowIds = value.entry_points.map(({ flow_id }) => flow_id).sort();
  const sortedFlowIds = value.flows.map(({ flow_id }) => flow_id).sort();
  if (!sameStrings(entryFlowIds, sortedFlowIds)) {
    issue(context, ["entry_points"], "entry points must cover every flow exactly once");
  }
  for (const entry of value.entry_points) {
    const flow = flowsById.get(entry.flow_id);
    if (flow === undefined) {
      issue(context, ["entry_points"], "entry point references an unknown flow");
      continue;
    }
    if (
      entry.exposed_node_id !== flow.target
      || !sameStrings(entry.data_classes, flow.data_classes)
    ) {
      issue(context, ["entry_points"], "entry point is not bound to its flow target");
    }
  }
  const stride = new Set(value.threats.flatMap((threat) => threat.stride_categories));
  const abuse = new Set(value.threats.flatMap((threat) => threat.abuse_categories));
  if (!sameStrings([...stride].sort(), ["D", "E", "I", "R", "S", "T"])) {
    issue(context, ["threats"], "all STRIDE categories are required");
  }
  if (!sameStrings([...abuse].sort(), [
    "confused-deputy",
    "logging-privacy",
    "parser-resource-exhaustion",
    "ssrf-dns-proxy",
    "supply-chain-build-deploy",
    "token-session",
  ])) {
    issue(context, ["threats"], "all required abuse categories are required");
  }
  for (const threat of value.threats) {
    const residual = residuals.get(threat.residual_risk_id);
    const selectedBoundaries = value.flows
      .filter((flow) => threat.flow_ids.includes(flow.flow_id))
      .map((flow) => flow.boundary_id)
      .sort();
    if (
      threat.flow_ids.some((identifier) => !flowIds.has(identifier))
      || threat.boundary_ids.some((identifier) => !boundaryIds.has(identifier))
      || !sameStrings([...threat.boundary_ids].sort(), selectedBoundaries)
      || threat.assumed_provider_control_ids.some((identifier) => !providerIds.has(identifier))
      || !residual?.threat_ids.includes(threat.threat_id)
    ) {
      issue(context, ["threats"], "threat mapping is not fully bound");
    }
  }
  if (value.residual_risks.some((risk) => risk.threat_ids.some((id) => !threatIds.has(id)))) {
    issue(context, ["residual_risks"], "residual risk references an unknown threat");
  }
  const usedProviders = new Set(
    value.threats.flatMap((threat) => threat.assumed_provider_control_ids),
  );
  if ([...providerIds].some((identifier) => !usedProviders.has(identifier))) {
    issue(context, ["provider_assumptions"], "provider assumption is not bound to a threat");
  }
  const affectedProfiles = new Set(
    value.threats.flatMap((threat) => threat.affected_profiles),
  );
  if (profiles.some((profile) => !affectedProfiles.has(profile))) {
    issue(context, ["threats"], "threat ledger does not cover every profile");
  }
  if (!sameStrings(
    value.entry_points.map(({ entry_point_id }) => entry_point_id),
    requiredEntryPointIds,
  )) {
    issue(context, ["entry_points"], "entry-point inventory is incomplete");
  }
  const supplyChain = value.threats.filter(
    ({ threat_id: threatId }) => threatId === "threat-supply-chain",
  );
  if (
    supplyChain.length !== 1
    || !sameStrings(
      supplyChain[0]?.asvs_requirement_ids ?? [],
      requiredSupplyChainMappings,
    )
  ) {
    issue(context, ["threats"], "supply-chain mappings are incomplete");
  }
  const reviewedMappings = {
    nodes: value.nodes.map((node) => [
      node.node_id,
      node.node_kind,
      node.trust_zone,
      node.privileges,
      node.data_classes,
    ]),
    flows: value.flows.map((flow) => [
      flow.flow_id,
      flow.source,
      flow.target,
      flow.boundary_id,
      flow.protocol,
      flow.data_classes,
    ]),
    entryPoints: value.entry_points.map((entry) => [
      entry.entry_point_id,
      entry.flow_id,
      entry.exposed_node_id,
      entry.access_control,
      entry.affected_profiles,
      entry.data_classes,
    ]),
    threats: value.threats.map((threat) => [
      threat.threat_id,
      threat.flow_ids,
      threat.boundary_ids,
      threat.stride_categories,
      threat.abuse_categories,
      threat.affected_profiles,
      threat.verification_selectors,
      threat.asvs_requirement_ids,
      threat.assumed_provider_control_ids,
      threat.residual_risk_id,
      threat.owner,
      threat.review_due,
    ]),
    residualRisks: value.residual_risks.map((risk) => [
      risk.residual_risk_id,
      risk.threat_ids,
      risk.owner,
      risk.review_due,
    ]),
  };
  if (JSON.stringify(reviewedMappings) !== JSON.stringify(requiredReviewedThreatMappings)) {
    issue(context, [], "threat ledger differs from the reviewed security mapping");
  }
}).readonly();

/**
 * @template T
 * @param {unknown} raw
 * @param {import("zod").ZodType<T>} schema
 * @param {number} maxBytes
 * @returns {T}
 */
function parseCanonicalJson(raw, schema, maxBytes) {
  return parseCanonicalBaselineContract(raw, schema, maxBytes);
}

/**
 * @template T
 * @param {unknown} raw
 * @param {import("zod").ZodType<T>} schema
 * @param {{ maxBytes: number, maxLineBytes: number, maxRecords: number, exactRecords?: number }} limits
 * @returns {readonly T[]}
 */
function parseCanonicalJsonLines(raw, schema, limits) {
  if (!(raw instanceof Uint8Array)) {
    throw new TypeError("JSONL contract must be supplied as raw bytes");
  }
  if (raw.byteLength > limits.maxBytes) {
    throw new RangeError("JSONL contract exceeds its raw-byte limit");
  }
  const body = Buffer.from(raw);
  if (body.length === 0) {
    if (limits.exactRecords !== undefined && limits.exactRecords !== 0) {
      throw new SyntaxError("JSONL record count does not match the exact product");
    }
    return [];
  }
  if (body.includes(0x0d) || body.at(-1) !== 0x0a) {
    throw new SyntaxError("JSONL must use LF records and end in LF");
  }
  const lines = body.subarray(0, body.length - 1).toString("binary").split("\n");
  if (
    lines.length > limits.maxRecords
    || lines.some((line) => line.length === 0 || Buffer.byteLength(line, "binary") > limits.maxLineBytes)
  ) {
    throw new RangeError("JSONL record count or line size exceeds its bound");
  }
  if (limits.exactRecords !== undefined && lines.length !== limits.exactRecords) {
    throw new SyntaxError("JSONL record count does not match the exact product");
  }
  return lines.map((line) => parseCanonicalBaselineContract(
    Buffer.concat([Buffer.from(line, "binary"), Buffer.from("\n", "ascii")]),
    schema,
    limits.maxLineBytes + 1,
  ));
}

/**
 * @param {unknown} raw
 * @returns {readonly z.infer<typeof evidenceRowSchema>[]}
 */
export function parseCanonicalAsvsMatrix(raw) {
  const records = parseCanonicalJsonLines(raw, evidenceRowSchema, {
    maxBytes: MATRIX_MAX_BYTES,
    maxLineBytes: MATRIX_MAX_LINE_BYTES,
    maxRecords: MATRIX_RECORDS,
    exactRecords: MATRIX_RECORDS,
  });
  const keys = records.map((record) => `${record.requirement_id}\0${record.profile}`);
  if (!isUnique(keys)) {
    throw new Error("matrix requirement and profile identities are duplicated");
  }
  /** @type {Map<string, z.infer<typeof evidenceRowSchema>[]>} */
  const grouped = new Map();
  for (const record of records) {
    const group = grouped.get(record.requirement_id) ?? [];
    group.push(record);
    grouped.set(record.requirement_id, group);
  }
  if (grouped.size !== 253) {
    throw new Error("matrix must contain exactly 253 requirements");
  }
  for (const rows of grouped.values()) {
    const first = rows[0];
    if (
      first === undefined
      || rows.length !== 3
      || !sameStrings(rows.map(({ profile }) => profile), profiles)
      || rows.some((row) => (
        row.requirement_text !== first.requirement_text
        || row.level !== first.level
      ))
    ) {
      throw new Error("matrix requirement product is inconsistent");
    }
  }
  const sorted = [...records].sort((left, right) => {
    const requirementComparison = Buffer.compare(
      Buffer.from(left.requirement_id, "utf8"),
      Buffer.from(right.requirement_id, "utf8"),
    );
    return requirementComparison !== 0
      ? requirementComparison
      : profiles.indexOf(left.profile) - profiles.indexOf(right.profile);
  });
  if (records.some((record, index) => record !== sorted[index])) {
    throw new Error("matrix rows are not canonically ordered");
  }
  return records;
}

/**
 * @param {unknown} raw
 * @returns {readonly z.infer<typeof evidenceReferenceSchema>[]}
 */
export function parseCanonicalEvidenceManifest(raw) {
  const references = parseCanonicalJsonLines(raw, evidenceReferenceSchema, {
    maxBytes: MANIFEST_MAX_BYTES,
    maxLineBytes: MANIFEST_MAX_LINE_BYTES,
    maxRecords: MANIFEST_MAX_RECORDS,
  });
  if (!isUnique(references.map(({ evidence_id }) => evidence_id))) {
    throw new Error("evidence manifest identifiers must be unique");
  }
  return references;
}

const candidateAssessmentSchema = z.strictObject({
  mode: z.literal("candidate"),
  profile: z.literal("alpic-metadata"),
  revision: gitRevisionSchema,
  tree_sha256: sha256Schema,
  as_of: awareDatetimeSchema,
}).readonly();

const candidateCommonRowShape = {
  ...commonRowShape,
  evidence_revision: gitRevisionSchema,
};

const candidateApplicableRowSchema = z.strictObject({
  ...candidateCommonRowShape,
  applicability: z.literal("applicable"),
  applicability_rationale: nonEmptySchema,
  verdict: z.literal("Pass"),
}).superRefine((value, context) => {
  if (
    !isUnique(value.evidence_ids)
    || !isUnique(value.required_evidence_kinds)
    || value.evidence_ids.length === 0
    || value.required_evidence_kinds.length === 0
  ) {
    issue(context, ["verdict"], "candidate Pass requires unique named evidence and kinds");
  }
}).readonly();

const candidateNotApplicableRowSchema = z.strictObject({
  ...candidateCommonRowShape,
  applicability: z.literal("not_applicable"),
  verdict: z.literal("N/A"),
  applicability_rationale: nonEmptySchema,
  applicability_reviewer: nonEmptySchema,
  applicability_review_due: dateSchema,
  absence_evidence_ids: z.array(caseIdSchema).min(1).max(128),
}).superRefine((value, context) => {
  if (
    value.evidence_ids.length !== 0
    || value.required_evidence_kinds.length !== 0
    || !isUnique(value.absence_evidence_ids)
    || value.applicability_review_due <= value.evidence_date
  ) {
    issue(context, ["verdict"], "candidate N/A state is incomplete or contradictory");
  }
}).readonly();

const candidateEvidenceRowSchema = z.discriminatedUnion("applicability", [
  candidateApplicableRowSchema,
  candidateNotApplicableRowSchema,
]);

const candidateEvidenceCommonShape = {
  ...evidenceCommonShape,
  evidence_revision: gitRevisionSchema,
  candidate_tree_sha256: sha256Schema,
};

const candidateEvidenceSchema = z.discriminatedUnion("storage", [
  z.strictObject({
    ...candidateEvidenceCommonShape,
    claim_purpose: z.literal("implementation-proof"),
    storage: z.literal("local"),
    artifact_path: z.string().refine(isCanonicalRelativePath, "artifact path is unsafe"),
    verifier: z.enum(["sha256-file-v1", "json-record-v1", "test-report-v1", "config-symbol-v1"]),
  }).superRefine(validateEvidenceReference).readonly(),
  z.strictObject({
    ...candidateEvidenceCommonShape,
    claim_purpose: z.enum(["implementation-proof", "absence-proof"]),
    storage: z.literal("custodied-uri"),
    immutable_artifact_uri: z.string().refine(
      isImmutableEvidenceUri, "custodied evidence URI is not immutable and safe",
    ),
    artifact_object_version: nonEmptySchema,
    custody_authority_id: caseIdSchema,
    custody_receipt_id: caseIdSchema,
    verifier: z.literal("ci-custody-v1"),
  }).superRefine(validateEvidenceReference).readonly(),
]);

/**
 * Parse a closed candidate-only Alpic L2 assessment product.
 *
 * @param {unknown} rawArtifacts
 */
export function parseCanonicalCandidateAsvsArtifactSet(rawArtifacts) {
  const envelope = z.strictObject({
    assessment: candidateAssessmentSchema,
    manifest: z.instanceof(Uint8Array),
    matrix: z.instanceof(Uint8Array),
    requirements: z.instanceof(Uint8Array),
  }).parse(rawArtifacts);
  const matrix = parseCanonicalJsonLines(envelope.matrix, candidateEvidenceRowSchema, {
    maxBytes: MATRIX_MAX_BYTES,
    maxLineBytes: MATRIX_MAX_LINE_BYTES,
    maxRecords: 253,
    exactRecords: 253,
  });
  const evidence = parseCanonicalJsonLines(envelope.manifest, candidateEvidenceSchema, {
    maxBytes: MANIFEST_MAX_BYTES,
    maxLineBytes: MANIFEST_MAX_LINE_BYTES,
    maxRecords: MANIFEST_MAX_RECORDS,
  });
  const keys = matrix.map((row) => row.requirement_id);
  const requirements = parsePinnedAsvsRequirements(envelope.requirements);
  const selectedRequirementIds = [...requirements.entries()]
    .filter(([, requirement]) => requirement.level <= 2)
    .map(([requirementId]) => requirementId)
    .sort((left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")));
  if (
    !isUnique(keys)
    || matrix.some((row) => row.profile !== "alpic-metadata")
    || !sameStrings([...keys].sort((left, right) => Buffer.compare(
      Buffer.from(left, "utf8"), Buffer.from(right, "utf8"),
    )), selectedRequirementIds)
  ) {
    throw new Error("candidate matrix must contain exactly one Alpic row per requirement");
  }
  if (
    !sameStrings(keys, selectedRequirementIds)
    || matrix.some((row) => {
      const requirement = requirements.get(row.requirement_id);
      return row.level !== requirement?.level
        || row.requirement_text !== requirement.text;
    })
  ) {
    throw new Error("candidate row does not match pinned ASVS semantics");
  }
  if (!isUnique(evidence.map((reference) => reference.evidence_id))) {
    throw new Error("candidate evidence identifiers must be unique");
  }
  const references = new Map(evidence.map((reference) => [reference.evidence_id, reference]));
  const assessmentInstant = Date.parse(envelope.assessment.as_of);
  const assessmentDate = envelope.assessment.as_of.slice(0, 10);
  for (const row of matrix) {
    if (
      row.applicability === "not_applicable"
      && row.applicability_review_due <= assessmentDate
    ) {
      throw new Error("candidate N/A review is not current");
    }
    const ids = row.applicability === "not_applicable"
      ? row.absence_evidence_ids : row.evidence_ids;
    for (const id of ids) {
      const reference = references.get(id);
      if (
        reference === undefined
        || !reference.requirement_ids.includes(row.requirement_id)
        || !reference.profiles.includes("alpic-metadata")
        || reference.asserted_invariant !== row.invariant
        || reference.evidence_revision !== envelope.assessment.revision
        || reference.candidate_tree_sha256 !== envelope.assessment.tree_sha256
        || row.evidence_revision !== envelope.assessment.revision
      ) {
        throw new Error("candidate evidence is not fresh and bound to its assessed row");
      }
      const collectedInstant = Date.parse(reference.collected_at);
      const expiresInstant = Date.parse(reference.expires_at);
      if (!(collectedInstant <= assessmentInstant && assessmentInstant < expiresInstant)) {
        throw new Error("candidate evidence is not current at the assessment instant");
      }
      if (row.applicability === "not_applicable" && (
        reference.storage !== "custodied-uri"
        || reference.claim_purpose !== "absence-proof"
        || !["design", "code_config", "test"].includes(reference.kind)
      )) {
        throw new Error("candidate N/A requires approved custodied absence proof");
      }
      if (row.applicability === "applicable" && (
        reference.claim_purpose !== "implementation-proof"
        || !row.required_evidence_kinds.includes(reference.kind)
      )) {
        throw new Error("candidate Pass requires implementation proof of every named kind");
      }
    }
    if (row.applicability === "applicable") {
      const kinds = new Set(ids.map((id) => references.get(id)?.kind));
      if (
        row.required_evidence_kinds.length === 0
        || row.required_evidence_kinds.some((kind) => !kinds.has(kind))
      ) {
        throw new Error("candidate Pass is missing a required evidence kind");
      }
    }
  }
  return { assessment: envelope.assessment, matrix, evidence };
}

/**
 * @param {unknown} raw
 * @returns {z.infer<typeof evidencePolicySchema>}
 */
export function parseCanonicalEvidencePolicy(raw) {
  return parseCanonicalJson(raw, evidencePolicySchema, POLICY_MAX_BYTES);
}

/**
 * @param {unknown} raw
 * @returns {z.infer<typeof threatLedgerSchema>}
 */
export function parseCanonicalThreatLedger(raw) {
  const parsed = parseCanonicalJson(raw, threatLedgerSchema, THREAT_MAX_BYTES);
  if (
    !(raw instanceof Uint8Array)
    || createHash("sha256").update(raw).digest("hex") !== REVIEWED_THREAT_LEDGER_SHA256
  ) {
    throw new Error("threat ledger differs from the reviewed semantic authority");
  }
  return parsed;
}

export const asvsArtifactSetSchema = z.strictObject({
  manifest: z.instanceof(Uint8Array),
  matrix: z.instanceof(Uint8Array),
  policy: z.instanceof(Uint8Array),
  requirements: z.instanceof(Uint8Array),
  threatLedger: z.instanceof(Uint8Array),
}).readonly();

/**
 * @param {unknown} rawArtifacts
 * @returns {{
 *   manifest: readonly z.infer<typeof evidenceReferenceSchema>[],
 *   matrix: readonly z.infer<typeof evidenceRowSchema>[],
 *   policy: z.infer<typeof evidencePolicySchema>,
 *   requirements: Map<string, { text: string, level: 1 | 2 }>,
 *   threatLedger: z.infer<typeof threatLedgerSchema>
 * }}
 */
export function parseCanonicalAsvsArtifactSet(rawArtifacts) {
  const raw = asvsArtifactSetSchema.parse(rawArtifacts);
  const matrix = parseCanonicalAsvsMatrix(raw.matrix);
  const manifest = parseCanonicalEvidenceManifest(raw.manifest);
  const policy = parseCanonicalEvidencePolicy(raw.policy);
  const requirements = parsePinnedAsvsRequirements(raw.requirements);
  const threatLedger = parseCanonicalThreatLedger(raw.threatLedger);
  const rowsByKey = new Map(
    matrix.map((row) => [`${row.requirement_id}\0${row.profile}`, row]),
  );
  const claimsByKey = new Map(
    policy.claims.map((claim) => [`${claim.requirement_id}\0${claim.profile}`, claim]),
  );
  if (
    rowsByKey.size !== claimsByKey.size
    || [...rowsByKey.keys()].some((key) => !claimsByKey.has(key))
  ) {
    throw new Error("matrix and policy claim products do not match");
  }
  for (const row of matrix) {
    const official = requirements.get(row.requirement_id);
    if (official === undefined) {
      throw new Error("matrix row is absent from the pinned ASVS source");
    }
    if (
      official.level !== row.level
      || official.text !== row.requirement_text
    ) {
      throw new Error("matrix row does not match the pinned ASVS source");
    }
  }
  const referencesById = new Map(
    manifest.map((reference) => [reference.evidence_id, reference]),
  );
  const referencedEvidence = new Set();
  for (const row of matrix) {
    const key = `${row.requirement_id}\0${row.profile}`;
    const claim = claimsByKey.get(key);
    if (claim === undefined) {
      throw new Error("matrix row does not have a policy claim");
    }
    const evidenceIds = row.applicability === "not_applicable"
      ? row.absence_evidence_ids
      : row.evidence_ids;
    for (const evidenceId of evidenceIds) {
      const reference = referencesById.get(evidenceId);
      if (
        reference === undefined
        || !reference.requirement_ids.includes(row.requirement_id)
        || !reference.profiles.includes(row.profile)
        || reference.asserted_invariant !== row.invariant
      ) {
        throw new Error("matrix evidence claim is not bound to its reference");
      }
      referencedEvidence.add(evidenceId);
    }
    if (row.applicability === "not_applicable") {
      if (!claim.na_absence_required || row.absence_evidence_ids.length === 0) {
        throw new Error("N/A row is not enabled by evidence policy");
      }
      throw new Error("N/A claims have no approved absence-proof verifier");
    } else if (row.verdict === "Pass") {
      const referencedKinds = new Set(evidenceIds.map(
        (evidenceId) => referencesById.get(evidenceId)?.kind,
      ));
      if (
        claim.pass_required_kinds === null
        || !sameStrings(claim.pass_required_kinds, row.required_evidence_kinds)
        || row.required_evidence_kinds.some((kind) => !referencedKinds.has(kind))
      ) {
        throw new Error("Pass row is not enabled by evidence policy");
      }
    } else if (row.verdict === "Risk accepted") {
      throw new Error("risk acceptance lacks an externally verified authority artifact");
    } else if (
      claim.pass_required_kinds !== null
      || claim.na_absence_required
      || claim.risk_acceptance_authority_id !== null
    ) {
      throw new Error("unassessed row has an eligibility-bearing policy claim");
    }
  }
  if (manifest.some((reference) => !referencedEvidence.has(reference.evidence_id))) {
    throw new Error("evidence manifest contains an orphan reference");
  }
  if (
    policy.custody_authority_ids.length !== 0
    || policy.release_authority_ids.length !== 0
  ) {
    throw new Error("authority identifiers lack approved authority artifacts");
  }
  for (const threat of threatLedger.threats) {
    for (const requirementId of threat.asvs_requirement_ids) {
      for (const profile of threat.affected_profiles) {
        const key = `${requirementId}\0${profile}`;
        const row = rowsByKey.get(key);
        const claim = claimsByKey.get(key);
        if (
          row?.applicability !== "applicable"
          || row.verdict !== "Not assessed"
          || claim?.pass_required_kinds !== null
          || claim.na_absence_required
          || claim.risk_acceptance_authority_id !== null
        ) {
          throw new Error("threat mapping is not bound to an unassessed matrix claim");
        }
      }
    }
  }
  return { manifest, matrix, policy, requirements, threatLedger };
}
