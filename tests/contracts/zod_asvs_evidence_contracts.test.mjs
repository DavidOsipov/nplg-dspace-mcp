import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  parseCanonicalAsvsArtifactSet,
  parseCanonicalAsvsMatrix,
  parseCanonicalEvidenceManifest,
  parseCanonicalEvidencePolicy,
  parseCanonicalThreatLedger,
} from "../../contracts/zod/asvs-evidence-contracts.mjs";

const root = new URL("../../", import.meta.url);
const evidenceRevision = "da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0";
const candidateTree = "f50987fe97ed12a0da3295929e2ef8dba94693389a0a3bec2b2458a9f87aa32c";

function checkedArtifacts() {
  return {
    manifest: readFileSync(new URL("docs/security/evidence-manifest.jsonl", root)),
    matrix: readFileSync(new URL("docs/security/asvs-5.0.0-l2-matrix.jsonl", root)),
    policy: readFileSync(new URL("docs/security/asvs-evidence-policy.json", root)),
    requirements: readFileSync(new URL("security/asvs/requirements-5.0.0.json", root)),
    threatLedger: readFileSync(new URL("docs/security/threat-model.json", root)),
  };
}

/**
 * @param {unknown} value
 * @returns {Buffer}
 */
function canonicalBytes(value) {
  /**
   * @param {unknown} item
   * @returns {unknown}
   */
  function sortKeys(item) {
    if (Array.isArray(item)) {
      return item.map(sortKeys);
    }
    if (item !== null && typeof item === "object") {
      return Object.fromEntries(
        Object.entries(item)
          .sort(([left], [right]) => Buffer.compare(
            Buffer.from(left, "utf8"),
            Buffer.from(right, "utf8"),
          ))
          .map(([key, nested]) => [key, sortKeys(nested)]),
      );
    }
    return item;
  }
  return Buffer.from(`${JSON.stringify(sortKeys(value))}\n`, "utf8");
}

/**
 * @param {readonly unknown[]} values
 * @returns {Buffer}
 */
function canonicalLines(values) {
  return Buffer.concat(values.map((value) => canonicalBytes(value)));
}

const localEvidence = {
  artifact_path: "evidence/test-report.json",
  asserted_invariant: "The exact requirement and profile claim was tested.",
  candidate_tree_sha256: candidateTree,
  collected_at: "2026-08-16T08:00:00Z",
  covered_surface: "The named test and its reviewed configuration.",
  deployment_id: null,
  evidence_id: "evidence.test-report",
  evidence_revision: evidenceRevision,
  expires_at: "2026-09-16T08:00:00Z",
  image_digest: null,
  kind: "test",
  profiles: ["alpic-metadata"],
  requirement_ids: ["v5.0.0-V1.1.1"],
  result: "pass",
  reviewer: "security-reviewer",
  selectors: ["test-strict-canonical-input"],
  sha256: "1".repeat(64),
  storage: "local",
  verifier: "test-report-v1",
};

void test("Zod 4 parses the exact checked-in Task 2 artifact set", () => {
  const parsed = parseCanonicalAsvsArtifactSet(checkedArtifacts());

  assert.equal(parsed.matrix.length, 759);
  assert.equal(parsed.policy.claims.length, 759);
  assert.equal(parsed.manifest.length, 0);
  assert.equal(parsed.threatLedger.threats.length, 6);
  assert.equal(parsed.threatLedger.release_status, "do_not_release");
  assert.deepEqual(
    parsed.threatLedger.entry_points.map((entry) => entry.entry_point_id),
    [
      "entry-alpic-forward",
      "entry-audit-log-store",
      "entry-content-store",
      "entry-deployment-publication",
      "entry-jwks-provider",
      "entry-nplg-repository-api",
      "entry-pdf-worker",
      "entry-public-mcp",
    ],
  );
  const supplyChain = parsed.threatLedger.threats.find(
    (threat) => threat.threat_id === "threat-supply-chain",
  );
  assert.deepEqual(supplyChain?.asvs_requirement_ids, [
    "v5.0.0-V15.1.1",
    "v5.0.0-V15.1.2",
    "v5.0.0-V15.2.1",
  ]);
});

void test("independent schemas parse every checked-in Task 2 artifact", () => {
  const raw = checkedArtifacts();

  assert.equal(parseCanonicalAsvsMatrix(raw.matrix).length, 759);
  assert.equal(parseCanonicalEvidenceManifest(raw.manifest).length, 0);
  assert.equal(parseCanonicalEvidencePolicy(raw.policy).claims.length, 759);
  assert.equal(parseCanonicalThreatLedger(raw.threatLedger).threats.length, 6);
});

void test("raw loaders reject invalid UTF-8, BOM, duplicates, drift, and oversize", () => {
  const { matrix, threatLedger } = checkedArtifacts();
  const duplicateThreatKey = Buffer.from(
    threatLedger.toString("utf8").replace(
      '"schema_version":"1.0"',
      '"schema_version":"1.0","schema_version":"1.0"',
    ),
    "utf8",
  );
  const duplicateMatrixKey = Buffer.from(
    matrix.toString("utf8").replace(
      '"applicability":"applicable"',
      '"applicability":"applicable","applicability":"applicable"',
    ),
    "utf8",
  );
  const malformedThreats = [
    Buffer.from([0xff]),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), threatLedger]),
    duplicateThreatKey,
    Buffer.from(` ${threatLedger.toString("utf8")}`, "utf8"),
    Buffer.concat([threatLedger, Buffer.from("{}", "ascii")]),
    Buffer.alloc(1024 * 1024 + 1, 0x20),
  ];
  const malformedMatrices = [
    duplicateMatrixKey,
    Buffer.from(matrix.toString("utf8").replaceAll("\n", "\r\n"), "utf8"),
    matrix.subarray(0, matrix.length - 1),
    Buffer.concat([Buffer.from("\n", "ascii"), matrix]),
    Buffer.alloc(2 * 1024 * 1024 + 1, 0x20),
  ];

  for (const raw of malformedThreats) {
    assert.throws(() => parseCanonicalThreatLedger(raw));
  }
  for (const raw of malformedMatrices) {
    assert.throws(() => parseCanonicalAsvsMatrix(raw));
  }
  assert.throws(() => parseCanonicalThreatLedger("not raw bytes"));
});

void test("matrix discriminators reject illegal Pass and N/A states", () => {
  const { matrix } = checkedArtifacts();
  const passWithoutEvidence = Buffer.from(
    matrix.toString("utf8").replace(
      '"verdict":"Not assessed"',
      '"verdict":"Pass"',
    ),
    "utf8",
  );
  const incompleteNotApplicable = Buffer.from(
    matrix.toString("utf8").replace(
      '"applicability":"applicable"',
      '"applicability":"not_applicable"',
    ),
    "utf8",
  );

  assert.throws(() => parseCanonicalAsvsMatrix(passWithoutEvidence));
  assert.throws(() => parseCanonicalAsvsMatrix(incompleteNotApplicable));
});

void test("matrix identity bounds and L1/L2 levels match the Python contract", () => {
  const { matrix } = checkedArtifacts();
  const rows = parseCanonicalAsvsMatrix(matrix);
  const first = rows[0];
  if (first?.applicability !== "applicable") {
    throw new Error("matrix fixture is incomplete");
  }
  const maximumIds = Array.from({ length: 128 }, (_, index) => `ev.${String(index).padStart(3, "0")}`);
  const applicableAtMaximum = { ...first, evidence_ids: maximumIds };
  const applicableOverMaximum = { ...first, evidence_ids: [...maximumIds, "ev.128"] };
  const notApplicableAtMaximum = {
    ...first,
    absence_evidence_ids: maximumIds,
    applicability: "not_applicable",
    applicability_rationale: "The capability is asserted absent.",
    applicability_review_due: "2026-12-31",
    applicability_reviewer: "reviewer-subject",
    verdict: "N/A",
  };
  const notApplicableOverMaximum = {
    ...notApplicableAtMaximum,
    absence_evidence_ids: [...maximumIds, "ev.128"],
  };

  assert.doesNotThrow(() => parseCanonicalAsvsMatrix(canonicalLines([
    applicableAtMaximum,
    ...rows.slice(1),
  ])));
  assert.doesNotThrow(() => parseCanonicalAsvsMatrix(canonicalLines([
    notApplicableAtMaximum,
    ...rows.slice(1),
  ])));
  assert.throws(() => parseCanonicalAsvsMatrix(canonicalLines([
    applicableOverMaximum,
    ...rows.slice(1),
  ])));
  assert.throws(() => parseCanonicalAsvsMatrix(canonicalLines([
    notApplicableOverMaximum,
    ...rows.slice(1),
  ])));
  assert.throws(() => parseCanonicalAsvsMatrix(canonicalLines([
    { ...first, level: 3 },
    ...rows.slice(1),
  ])));
});

void test("manifest schemas accept a strict local reference and reject claim drift", () => {
  const valid = canonicalBytes(localEvidence);
  const invalidReferences = [
    { ...localEvidence, result: "FAIL" },
    { ...localEvidence, artifact_path: "../outside.json" },
    { ...localEvidence, profiles: [] },
    { ...localEvidence, selectors: [] },
    { ...localEvidence, unexpected: true },
  ];

  assert.equal(parseCanonicalEvidenceManifest(valid).length, 1);
  for (const reference of invalidReferences) {
    assert.throws(() => parseCanonicalEvidenceManifest(canonicalBytes(reference)));
  }
});

void test("policy and threat schemas reject authority and status mutants", () => {
  const { policy, threatLedger } = checkedArtifacts();
  const duplicatePolicyClaim = Buffer.from(
    policy.toString("utf8").replace(
      '"claims":[',
      '"claims":[{"na_absence_required":false,"pass_required_kinds":null,"profile":"alpic-metadata","requirement_id":"v5.0.0-V1.1.1","risk_acceptance_authority_id":null},',
    ),
    "utf8",
  );
  const verifiedThreat = Buffer.from(
    threatLedger.toString("utf8").replace(
      '"verification_status":"not_assessed"',
      '"verification_status":"verified"',
    ),
    "utf8",
  );
  const releaseThreat = Buffer.from(
    threatLedger.toString("utf8").replace(
      '"release_status":"do_not_release"',
      '"release_status":"release"',
    ),
    "utf8",
  );

  assert.throws(() => parseCanonicalEvidencePolicy(duplicatePolicyClaim));
  assert.throws(() => parseCanonicalThreatLedger(verifiedThreat));
  assert.throws(() => parseCanonicalThreatLedger(releaseThreat));
});

void test("cross-file validation binds matrix, policy, manifest, and threat claims", () => {
  const raw = checkedArtifacts();
  const unknownThreatMapping = Buffer.from(
    raw.threatLedger.toString("utf8").replace(
      "v5.0.0-V10.3.1",
      "v5.0.0-V99.9.9",
    ),
    "utf8",
  );
  const unknownPolicyClaim = Buffer.from(
    raw.policy.toString("utf8").replace(
      "v5.0.0-V1.1.1",
      "v5.0.0-V9.9.9",
    ),
    "utf8",
  );

  assert.throws(() => parseCanonicalAsvsArtifactSet({
    ...raw,
    threatLedger: unknownThreatMapping,
  }));
  assert.throws(() => parseCanonicalAsvsArtifactSet({
    ...raw,
    policy: unknownPolicyClaim,
  }));
  assert.throws(() => parseCanonicalAsvsArtifactSet({
    ...raw,
    manifest: canonicalBytes(localEvidence),
  }));
});

void test("Pass claims require references covering every required evidence kind", () => {
  const raw = checkedArtifacts();
  const matrix = [...parseCanonicalAsvsMatrix(raw.matrix)];
  const policy = parseCanonicalEvidencePolicy(raw.policy);
  const row = matrix[0];
  assert.notEqual(row, undefined);
  if (row?.applicability !== "applicable") {
    throw new Error("fixture row is not applicable");
  }
  const evidenceId = "evidence.wrong-kind";
  const reference = {
    ...localEvidence,
    asserted_invariant: row.invariant,
    evidence_id: evidenceId,
    kind: "design",
    profiles: [row.profile],
    requirement_ids: [row.requirement_id],
  };
  matrix[0] = {
    ...row,
    evidence_ids: [evidenceId],
    required_evidence_kinds: ["code_config", "test"],
    verdict: "Pass",
  };
  const claims = policy.claims.map((claim, index) => index === 0
    ? { ...claim, pass_required_kinds: ["code_config", "test"] }
    : claim);

  assert.throws(() => parseCanonicalAsvsArtifactSet({
    ...raw,
    manifest: canonicalBytes(reference),
    matrix: canonicalLines(matrix),
    policy: canonicalBytes({ ...policy, claims }),
  }));
});

void test("threats bind selected boundaries and data classes to selected flows", () => {
  const raw = checkedArtifacts();
  const ledger = parseCanonicalThreatLedger(raw.threatLedger);
  const first = ledger.threats[0];
  const firstFlow = ledger.flows[0];
  assert.notEqual(first, undefined);
  assert.notEqual(firstFlow, undefined);
  if (first === undefined || firstFlow === undefined) {
    throw new Error("threat fixture is incomplete");
  }
  const wrongBoundary = canonicalBytes({
    ...ledger,
    threats: [
      { ...first, boundary_ids: ["logging-privacy"] },
      ...ledger.threats.slice(1),
    ],
  });
  const unknownDataClass = canonicalBytes({
    ...ledger,
    flows: [
      { ...firstFlow, data_classes: ["unknown-data-class"] },
      ...ledger.flows.slice(1),
    ],
  });

  assert.throws(() => parseCanonicalThreatLedger(wrongBoundary));
  assert.throws(() => parseCanonicalThreatLedger(unknownDataClass));
});

void test("entry points and supply-chain mappings are relationship-bound", () => {
  const raw = checkedArtifacts();
  const ledger = parseCanonicalThreatLedger(raw.threatLedger);
  const firstEntry = ledger.entry_points[0];
  const supplyChain = ledger.threats.find(
    ({ threat_id: threatId }) => threatId === "threat-supply-chain",
  );
  if (firstEntry === undefined || supplyChain === undefined) {
    throw new Error("threat entry-point fixtures are incomplete");
  }
  const wrongTarget = canonicalBytes({
    ...ledger,
    entry_points: [
      { ...firstEntry, exposed_node_id: "alpic-edge" },
      ...ledger.entry_points.slice(1),
    ],
  });
  const weakSupplyMapping = canonicalBytes({
    ...ledger,
    threats: ledger.threats.map((threat) => threat.threat_id === "threat-supply-chain"
      ? { ...threat, asvs_requirement_ids: ["v5.0.0-V11.2.1"] }
      : threat),
  });

  assert.throws(() => parseCanonicalThreatLedger(wrongTarget));
  assert.throws(() => parseCanonicalThreatLedger(weakSupplyMapping));
});

void test("reviewed threat identifiers cannot be coordinately relabelled", () => {
  const raw = checkedArtifacts();
  const ledger = parseCanonicalThreatLedger(raw.threatLedger);
  const firstEntry = ledger.entry_points[0];
  const secondEntry = ledger.entry_points[1];
  const firstFlow = ledger.flows[0];
  const secondFlow = ledger.flows[1];
  if (
    firstEntry === undefined
    || secondEntry === undefined
    || firstFlow === undefined
    || secondFlow === undefined
  ) {
    throw new Error("threat topology fixtures are incomplete");
  }
  const swappedEntries = ledger.entry_points.map((entry) => {
    if (entry.entry_point_id === firstEntry.entry_point_id) {
      return { ...entry, entry_point_id: secondEntry.entry_point_id };
    }
    if (entry.entry_point_id === secondEntry.entry_point_id) {
      return { ...entry, entry_point_id: firstEntry.entry_point_id };
    }
    return entry;
  }).sort((left, right) => Buffer.compare(
    Buffer.from(left.entry_point_id, "utf8"),
    Buffer.from(right.entry_point_id, "utf8"),
  ));
  const swappedFlows = ledger.flows.map((flow) => {
    if (flow.flow_id === firstFlow.flow_id) {
      return { ...flow, boundary_id: secondFlow.boundary_id };
    }
    if (flow.flow_id === secondFlow.flow_id) {
      return { ...flow, boundary_id: firstFlow.boundary_id };
    }
    return flow;
  });
  const swappedBoundariesByFlow = new Map(
    swappedFlows.map((flow) => [flow.flow_id, flow.boundary_id]),
  );
  const threatsWithSwappedBoundaries = ledger.threats.map((threat) => ({
    ...threat,
    boundary_ids: threat.flow_ids
      .map((flowId) => swappedBoundariesByFlow.get(flowId))
      .filter((boundaryId) => boundaryId !== undefined)
      .sort(),
  }));
  const relabelledFlows = ledger.flows.map((flow) => flow.flow_id === "flow-backend-nplg"
    ? { ...flow, data_classes: ["access-tokens"] }
    : flow);
  const relabelledEntries = ledger.entry_points.map(
    (entry) => entry.flow_id === "flow-backend-nplg"
      ? { ...entry, data_classes: ["access-tokens"] }
      : entry,
  );
  const mappingMutants = [
    { ...ledger, entry_points: swappedEntries },
    { ...ledger, flows: swappedFlows, threats: threatsWithSwappedBoundaries },
    { ...ledger, flows: relabelledFlows, entry_points: relabelledEntries },
    {
      ...ledger,
      threats: ledger.threats.map((threat) => threat.threat_id === "threat-parser-exhaustion"
        ? { ...threat, affected_profiles: [
          "alpic-metadata",
          "private-full",
          "distributed-full",
        ] }
        : threat),
    },
    {
      ...ledger,
      threats: ledger.threats.map((threat) => threat.threat_id === "threat-parser-exhaustion"
        ? { ...threat, verification_selectors: ["$(touch owned)"] }
        : threat),
    },
    {
      ...ledger,
      threats: ledger.threats.map((threat) => threat.threat_id === "threat-auth-token-spoofing"
        ? { ...threat, asvs_requirement_ids: ["v5.0.0-V11.2.1"] }
        : threat),
    },
    {
      ...ledger,
      residual_risks: ledger.residual_risks.map((risk, index) => index === 0
        ? {
          ...risk,
          threat_ids: [risk.threat_ids[0], ledger.residual_risks[1]?.threat_ids[0]],
        }
        : risk),
    },
  ];

  for (const mutant of mappingMutants) {
    assert.throws(() => parseCanonicalThreatLedger(canonicalBytes(mutant)));
  }
});

void test("generic hashed design evidence cannot enable a coordinated N/A claim", () => {
  const raw = checkedArtifacts();
  const matrix = parseCanonicalAsvsMatrix(raw.matrix);
  const policy = parseCanonicalEvidencePolicy(raw.policy);
  const first = matrix[0];
  if (first?.applicability !== "applicable") {
    throw new Error("matrix fixture is incomplete");
  }
  const absenceEvidenceId = "absence.generic-design";
  const notApplicable = {
    ...first,
    absence_evidence_ids: [absenceEvidenceId],
    applicability: "not_applicable",
    applicability_rationale: "The capability is asserted absent.",
    applicability_review_due: "2026-12-31",
    applicability_reviewer: "reviewer-subject",
    verdict: "N/A",
  };
  const claims = policy.claims.map((claim, index) => index === 0
    ? { ...claim, na_absence_required: true }
    : claim);
  const genericDesignReference = {
    ...localEvidence,
    asserted_invariant: first.invariant,
    evidence_id: absenceEvidenceId,
    kind: "design",
    requirement_ids: [first.requirement_id],
    selectors: ["not-an-absence-probe"],
    verifier: "sha256-file-v1",
  };

  assert.throws(() => parseCanonicalAsvsArtifactSet({
    ...raw,
    manifest: canonicalBytes(genericDesignReference),
    matrix: canonicalLines([notApplicable, ...matrix.slice(1)]),
    policy: canonicalBytes({ ...policy, claims }),
  }));
});

void test("artifact-set rows are independently bound to the pinned ASVS source", () => {
  const raw = checkedArtifacts();
  assert.doesNotThrow(() => parseCanonicalAsvsArtifactSet(raw));
  const fabricatedId = "v5.0.0-V0.0.0";
  const matrix = parseCanonicalAsvsMatrix(raw.matrix).map((row, index) => index < 3
    ? { ...row, requirement_id: fabricatedId }
    : row);
  const policy = parseCanonicalEvidencePolicy(raw.policy);
  const claims = policy.claims.map((claim, index) => index < 3
    ? { ...claim, requirement_id: fabricatedId }
    : claim);

  assert.throws(() => parseCanonicalAsvsArtifactSet({
    ...raw,
    matrix: canonicalLines(matrix),
    policy: canonicalBytes({ ...policy, claims }),
  }));
});
