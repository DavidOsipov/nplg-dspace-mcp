import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { z } from "zod";

import {
  loadPrivateRecoveryPolicy,
  parsePrivateRecoveryPolicy,
  privateRecoveryPolicySchema,
} from "../../contracts/zod/recovery-contracts.mjs";

const mutableDerivedSubjectSchema = z.looseObject({
  classification: z.literal("derived"),
  regeneration_recipe_paths: z.array(z.string()),
});
const mutableUniqueSubjectSchema = z.looseObject({
  classification: z.literal("unique"),
});
const mutableSubjectSchema = z.discriminatedUnion("classification", [
  mutableUniqueSubjectSchema,
  mutableDerivedSubjectSchema,
]);
const mutableEvidenceSchema = z.looseObject({
  status: z.string(),
  candidate_generated: z.boolean(),
  measured_rto_seconds: z.number().nullable(),
  controller_receipt_sha256: z.string().nullable(),
  blockers: z.array(z.string()),
});
const mutableLifecycleStateSchema = z.looseObject({
  state_id: z.string(),
  persistence: z.string(),
  location: z.string().optional(),
  recovery_strategy: z.string(),
  expected_active_leases: z.number().optional(),
});
const mutablePolicySchema = z.looseObject({
  policy_digest: z.string(),
  subjects: z.array(mutableSubjectSchema),
  state_inventory: z.array(mutableLifecycleStateSchema),
  evidence: mutableEvidenceSchema,
  release_ready: z.boolean(),
  terminal_verdict: z.string(),
});
const MAX_RAW_POLICY_BYTES = 65_536;

/** @typedef {z.infer<typeof mutablePolicySchema>} MutablePolicy */

/**
 * @param {[string, unknown]} leftEntry
 * @param {[string, unknown]} rightEntry
 * @returns {number}
 */
function compareKeys([left], [right]) {
  if (left < right) {
    return -1;
  }
  return Number(left > right);
}

/**
 * @param {unknown} value
 * @returns {unknown}
 */
function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(compareKeys)
        .map(([key, item]) => [key, canonicalize(item)]),
    );
  }
  return value;
}

/**
 * @param {MutablePolicy} policy
 * @returns {void}
 */
function redigest(policy) {
  const { policy_digest: ignored, ...unsigned } = policy;
  assert.equal(typeof ignored, "string");
  policy.policy_digest = `sha256:${createHash("sha256")
    .update(`${JSON.stringify(canonicalize(unsigned))}\n`, "utf8")
    .digest("hex")}`;
}

void test("Zod independently validates the fail-closed recovery policy", async () => {
  const policy = await loadPrivateRecoveryPolicy();
  const [unique, derived] = policy.subjects;

  assert.equal(unique.classification, "unique");
  assert.equal(unique.recovery_strategy, "immutable-backup-and-restore");
  assert.equal(derived.classification, "derived");
  assert.equal(derived.recovery_strategy, "bounded-cold-regeneration");
  assert.equal(policy.rto.objective_seconds, 900);
  assert.equal(policy.evidence.status, "external_authority_required");
  assert.equal(policy.evidence.measured_rto_seconds, null);
  assert.equal(policy.evidence.state_reconstruction_proof_sha256, null);
  assert.equal(policy.release_ready, false);
  assert.equal(policy.terminal_verdict, "do_not_release");
});

void test("Zod binds the exact lifecycle recovery and reconstruction inventory", async () => {
  const policy = await loadPrivateRecoveryPolicy();

  assert.deepEqual(policy.state_inventory.map(({ state_id: stateId }) => stateId), [
    "clock-high-water-and-boot-state",
    "insertion-high-water",
    "per-object-insertion-sequence-records",
    "orphan-staging-cleanup",
    "post-process-lease-reservation-reconciliation",
  ]);
  const [clock, highWater, sequences, staging, processState] = policy.state_inventory;
  assert.equal(clock.location, ".retention-clock-high-water.json");
  assert.equal(clock.recovery_strategy, "fail-closed-baseline-then-healthy-window");
  assert.equal(highWater.backup_required, true);
  assert.equal(
    highWater.recovery_strategy,
    "restore-or-initialize-only-without-sequence-records",
  );
  assert.deepEqual(sequences.location_patterns, [
    "documents/*/.lifecycle-insertion-sequence.json",
    "renders/*/.lifecycle-insertion-sequence.json",
  ]);
  assert.equal(
    sequences.recovery_strategy,
    "validate-existing-or-allocate-from-persisted-high-water",
  );
  assert.equal(staging.expected_post_reconstruction_entries, 0);
  assert.equal(processState.persistence, "never-persisted");
  assert.equal(
    processState.restart_reconstruction_semantics,
    "start-ledgers-empty-after-staging-cleanup-and-committed-object-scan",
  );
  assert.deepEqual([
    processState.expected_active_leases,
    processState.expected_staging_reservations,
    processState.expected_publication_reservations,
    processState.expected_reserved_bytes,
    processState.expected_reserved_objects,
    processState.expected_reserved_inodes,
  ], [0, 0, 0, 0, 0, 0]);
});

void test("Zod binds exact private filesystem owner and mode expectations", async () => {
  const policy = await loadPrivateRecoveryPolicy();

  assert.deepEqual(policy.filesystem_expectations, {
    owner_uid: 10_001,
    owner_gid: 10_001,
    directory_mode: "0700",
    regular_file_mode: "0600",
    symlinks_permitted: false,
    hardlinks_permitted: false,
    applies_to: ["subjects", "lifecycle-state", "staging-reconstruction"],
  });
});

void test("Zod raw recovery loader rejects duplicate names and invalid bytes", async () => {
  const raw = await readFile(
    new URL("../../security/private-recovery-policy.json", import.meta.url),
  );
  assert.doesNotThrow(() => parsePrivateRecoveryPolicy(raw));

  const duplicate = Buffer.from(raw.toString("utf8").replace(
    '  "schema_version": 1,',
    '  "schema_version": 1,\n  "schema_version": 1,',
  ));
  assert.throws(() => parsePrivateRecoveryPolicy(duplicate), SyntaxError);
  assert.throws(
    () => parsePrivateRecoveryPolicy(Buffer.from([0xc3, 0x28])),
    SyntaxError,
  );
  assert.throws(
    () => parsePrivateRecoveryPolicy(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), raw])),
    SyntaxError,
  );
});

void test("Zod rejects ASCII spaces in recovery recipe paths", async () => {
  const policy = mutablePolicySchema.parse(await loadPrivateRecoveryPolicy());
  const derived = policy.subjects[1];
  assert.ok(derived !== undefined);
  assert.equal(derived.classification, "derived");
  derived.regeneration_recipe_paths = ["src/nplg_mcp/pdf recipe.py"];
  redigest(policy);

  assert.throws(() => privateRecoveryPolicySchema.parse(policy), { name: "ZodError" });
});

void test("Zod enforces the exact recovery policy raw-byte boundary", async () => {
  const raw = await readFile(
    new URL("../../security/private-recovery-policy.json", import.meta.url),
  );
  assert.ok(raw.byteLength < MAX_RAW_POLICY_BYTES);
  const exactLimit = Buffer.concat([
    raw,
    Buffer.alloc(MAX_RAW_POLICY_BYTES - raw.byteLength, 0x20),
  ]);

  assert.doesNotThrow(() => parsePrivateRecoveryPolicy(exactLimit));
  assert.throws(
    () => parsePrivateRecoveryPolicy(Buffer.concat([exactLimit, Buffer.from(" ")])),
    RangeError,
  );
});

void test("Zod rejects recovery recipe traversal after a valid redigest", async () => {
  const policy = mutablePolicySchema.parse(await loadPrivateRecoveryPolicy());
  const derived = policy.subjects[1];
  assert.ok(derived !== undefined);
  assert.equal(derived.classification, "derived");
  for (const path of [
    "../src/nplg_mcp/pdf.py",
    "src//nplg_mcp/pdf.py",
    "src/nplg_mcp/récipe.py",
  ]) {
    derived.regeneration_recipe_paths = [path];
    redigest(policy);
    assert.throws(() => privateRecoveryPolicySchema.parse(policy), { name: "ZodError" });
  }
});

void test(
  "Zod matches Pydantic by rejecting duplicate recovery recipe paths",
  async () => {
    const policy = mutablePolicySchema.parse(await loadPrivateRecoveryPolicy());
    const derived = policy.subjects[1];
    assert.ok(derived !== undefined);
    assert.equal(derived.classification, "derived");
    const recipePath = derived.regeneration_recipe_paths[0];
    assert.ok(recipePath !== undefined);
    derived.regeneration_recipe_paths = [recipePath, recipePath];
    redigest(policy);

    assert.doesNotThrow(() => mutablePolicySchema.parse(policy));
    assert.throws(() => privateRecoveryPolicySchema.parse(policy), { name: "ZodError" });
  },
);

void test("Zod rejects undigested recovery policy drift", async () => {
  const policy = mutablePolicySchema.parse(await loadPrivateRecoveryPolicy());
  const derived = policy.subjects[1];
  assert.ok(derived !== undefined);
  assert.equal(derived.classification, "derived");
  derived.regeneration_recipe_paths = [...derived.regeneration_recipe_paths].reverse();

  assert.throws(() => privateRecoveryPolicySchema.parse(policy), { name: "ZodError" });
});

void test("Zod rejects schema drift and candidate-invented recovery authority", async () => {
  const policy = mutablePolicySchema.parse(await loadPrivateRecoveryPolicy());
  const extra = structuredClone(policy);
  extra["unreviewed"] = true;
  redigest(extra);
  assert.throws(() => privateRecoveryPolicySchema.parse(extra), { name: "ZodError" });

  const invented = structuredClone(policy);
  invented.evidence.status = "verified";
  invented.evidence.candidate_generated = true;
  invented.evidence.measured_rto_seconds = 1;
  invented.evidence.controller_receipt_sha256 = `sha256:${"a".repeat(64)}`;
  invented.evidence.blockers = [];
  invented.release_ready = true;
  invented.terminal_verdict = "release";
  redigest(invented);
  assert.throws(() => privateRecoveryPolicySchema.parse(invented), { name: "ZodError" });
});

void test("Zod rejects digest-valid lifecycle state inventory drift", async () => {
  const base = mutablePolicySchema.parse(await loadPrivateRecoveryPolicy());
  const mutations = [
    /** @param {MutablePolicy} policy */
    (policy) => {
      policy.state_inventory.splice(2, 1);
    },
    /** @param {MutablePolicy} policy */
    (policy) => {
      const invented = structuredClone(policy.state_inventory.at(-1));
      assert.ok(invented !== undefined);
      invented.state_id = "candidate-claimed-backup-authority";
      policy.state_inventory.push(invented);
    },
    /** @param {MutablePolicy} policy */
    (policy) => {
      const duplicate = structuredClone(policy.state_inventory[0]);
      assert.ok(duplicate !== undefined);
      policy.state_inventory.push(duplicate);
    },
    /** @param {MutablePolicy} policy */
    (policy) => {
      policy.state_inventory.reverse();
    },
    /** @param {MutablePolicy} policy */
    (policy) => {
      const processState = policy.state_inventory.at(-1);
      assert.ok(processState !== undefined);
      Reflect.set(processState, "expected_active_leases", true);
    },
    /** @param {MutablePolicy} policy */
    (policy) => {
      const highWater = policy.state_inventory[1];
      assert.ok(highWater !== undefined);
      highWater.recovery_strategy = "reconstruct-from-object-mtimes";
    },
    /** @param {MutablePolicy} policy */
    (policy) => {
      const processState = policy.state_inventory.at(-1);
      assert.ok(processState !== undefined);
      processState.persistence = "protected-controller-persisted";
    },
    /** @param {MutablePolicy} policy */
    (policy) => {
      const clock = policy.state_inventory[0];
      assert.ok(clock !== undefined);
      clock.location = "../.retention-clock-high-water.json";
    },
  ];

  for (const mutate of mutations) {
    const policy = structuredClone(base);
    mutate(policy);
    redigest(policy);
    assert.throws(() => privateRecoveryPolicySchema.parse(policy), { name: "ZodError" });
  }
});

void test("Zod rejects digest-valid owner and mode expectation drift", async () => {
  const base = mutablePolicySchema.parse(await loadPrivateRecoveryPolicy());
  const mutations = [
    { owner_uid: 0 },
    { owner_gid: true },
    { directory_mode: "0755" },
    { regular_file_mode: "0644" },
    { symlinks_permitted: true },
    { hardlinks_permitted: true },
    { applies_to: ["subjects", "lifecycle-state"] },
  ];

  for (const mutation of mutations) {
    const policy = structuredClone(base);
    Reflect.set(policy, "filesystem_expectations", mutation);
    redigest(policy);
    assert.throws(() => privateRecoveryPolicySchema.parse(policy), { name: "ZodError" });
  }
});
