import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { z } from "zod";
import {
  parseJsonRejectingDuplicateKeys,
} from "./baseline-contracts.mjs";

const MAX_RAW_POLICY_BYTES = 65_536;

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
 * @param {{ policy_digest: string } & Record<string, unknown>} value
 * @returns {boolean}
 */
function policyDigestMatches(value) {
  const { policy_digest: policyDigest, ...unsigned } = value;
  const expected = `sha256:${createHash("sha256")
    .update(`${JSON.stringify(canonicalize(unsigned))}\n`, "utf8")
    .digest("hex")}`;
  return policyDigest === expected;
}

const canonicalRecipePath = z.string().min(1).max(512).refine((value) => {
  if (
    !/^[\x21-\x7e]+$/.test(value)
    || value.includes("\\")
    || value.startsWith("/")
    || !value.endsWith(".py")
  ) {
    return false;
  }
  const parts = value.split("/");
  return parts[0] === "src"
    && parts.every((part) => part !== "" && part !== "." && part !== "..")
    && parts.join("/") === value;
}, "recovery recipe path must be canonical and repository-relative");

const rtoSchema = z.strictObject({
  objective_seconds: z.literal(900),
  clock: z.literal("protected-controller-monotonic"),
  starts_at: z.literal("synthetic-volume-loss-confirmed"),
  ends_at: z.literal("recovery-integrity-verified"),
  over_objective_action: z.literal("block_release"),
});

const uniqueSourceSchema = z.strictObject({
  subject_id: z.literal("source-pdfs"),
  namespace: z.literal("documents"),
  classification: z.literal("unique"),
  recovery_strategy: z.literal("immutable-backup-and-restore"),
  backup_required: z.literal(true),
  cold_regeneration_permitted: z.literal(false),
  identity_check: z.literal("sha256-content-address"),
  required_proof: z.literal("protected-immutable-backup-restore"),
});

const derivedRenderSchema = z.strictObject({
  subject_id: z.literal("derived-renders"),
  namespace: z.literal("renders"),
  classification: z.literal("derived"),
  recovery_strategy: z.literal("bounded-cold-regeneration"),
  backup_required: z.literal(false),
  cold_regeneration_required: z.literal(true),
  source_subject_id: z.literal("source-pdfs"),
  regeneration_recipe_paths: z.array(canonicalRecipePath)
    .min(1)
    .max(8)
    .refine(
      (paths) => new Set(paths).size === paths.length,
      "recovery recipe paths must be unique",
    ),
  identity_check: z.literal("sha256-manifest-and-assets"),
  required_proof: z.literal("protected-bounded-cold-regeneration"),
});

const subjectSchema = z.discriminatedUnion("classification", [
  uniqueSourceSchema,
  derivedRenderSchema,
]);

const privateFilesystemExpectationsSchema = z.strictObject({
  owner_uid: z.literal(10_001),
  owner_gid: z.literal(10_001),
  directory_mode: z.literal("0700"),
  regular_file_mode: z.literal("0600"),
  symlinks_permitted: z.literal(false),
  hardlinks_permitted: z.literal(false),
  applies_to: z.tuple([
    z.literal("subjects"),
    z.literal("lifecycle-state"),
    z.literal("staging-reconstruction"),
  ]),
});

const clockHighWaterStateSchema = z.strictObject({
  state_id: z.literal("clock-high-water-and-boot-state"),
  classification: z.literal("reconstructible-safety-state"),
  persistence: z.literal("fsynced-private-record"),
  location: z.literal(".retention-clock-high-water.json"),
  schema_version: z.literal("1.0"),
  identity_check: z.literal("record-digest-and-boot-id"),
  recovery_strategy: z.literal("fail-closed-baseline-then-healthy-window"),
  missing_or_corrupt_semantics: z.literal(
    "rewrite-untrusted-baseline-and-close-age-deletion-and-new-ingest",
  ),
  post_termination_semantics: z.literal(
    "persisted-record-revalidated-against-current-boot",
  ),
  backup_required: z.literal(false),
  required_proof: z.literal(
    "protected-high-water-recovery-and-clock-anomaly-closure",
  ),
});

const insertionHighWaterStateSchema = z.strictObject({
  state_id: z.literal("insertion-high-water"),
  classification: z.literal("unique-ordering-state"),
  persistence: z.literal("fsynced-private-record"),
  location: z.literal(".lifecycle-insertion-high-water.json"),
  schema_version: z.literal("1.0"),
  identity_check: z.literal("record-digest"),
  recovery_strategy: z.literal("restore-or-initialize-only-without-sequence-records"),
  missing_or_corrupt_semantics: z.literal(
    "reject-when-sequence-records-exist-otherwise-initialize-at-one",
  ),
  post_termination_semantics: z.literal("load-before-per-object-reconciliation"),
  backup_required: z.literal(true),
  required_proof: z.literal("protected-insertion-high-water-restore"),
});

const perObjectInsertionSequenceStateSchema = z.strictObject({
  state_id: z.literal("per-object-insertion-sequence-records"),
  classification: z.literal("reconstructible-object-ordering-state"),
  persistence: z.literal("fsynced-per-object-private-record"),
  location_patterns: z.tuple([
    z.literal("documents/*/.lifecycle-insertion-sequence.json"),
    z.literal("renders/*/.lifecycle-insertion-sequence.json"),
  ]),
  schema_version: z.literal("1.0"),
  identity_check: z.literal("record-digest-object-key-and-high-water-bound"),
  recovery_strategy: z.literal(
    "validate-existing-or-allocate-from-persisted-high-water",
  ),
  missing_or_corrupt_semantics: z.literal(
    "allocate-missing-from-high-water-and-reject-invalid-or-duplicate",
  ),
  post_termination_semantics: z.literal(
    "validate-every-record-and-bind-below-high-water",
  ),
  backup_required: z.literal(false),
  required_proof: z.literal("protected-insertion-sequence-reconciliation"),
});

const orphanStagingStateSchema = z.strictObject({
  state_id: z.literal("orphan-staging-cleanup"),
  classification: z.literal("ephemeral-transaction-state"),
  persistence: z.literal("uncommitted-filesystem-state"),
  location: z.literal(".staging"),
  identity_check: z.literal("not-authoritative"),
  recovery_strategy: z.literal("delete-entire-inventory-before-accounting"),
  missing_or_corrupt_semantics: z.literal(
    "absence-is-valid-and-every-entry-is-discarded",
  ),
  post_termination_semantics: z.literal("empty-before-committed-object-scan"),
  backup_required: z.literal(false),
  expected_post_reconstruction_entries: z.literal(0),
  required_proof: z.literal("protected-partial-restore-cleanup"),
});

const postProcessLeaseReservationStateSchema = z.strictObject({
  state_id: z.literal("post-process-lease-reservation-reconciliation"),
  classification: z.literal("process-local-ephemeral-state"),
  persistence: z.literal("never-persisted"),
  components: z.tuple([
    z.literal("asset-leases"),
    z.literal("staging-byte-reservations"),
    z.literal("publication-reservations"),
    z.literal("publication-reserved-bytes"),
    z.literal("publication-reserved-objects"),
    z.literal("publication-reserved-inodes"),
  ]),
  identity_check: z.literal("exact-empty-ledgers-and-recomputed-committed-usage"),
  recovery_strategy: z.literal(
    "release-or-abort-on-worker-exit-then-reconstruct-empty-on-restart",
  ),
  post_termination_semantics: z.literal(
    "dead-process-leases-and-reservations-are-not-restored",
  ),
  worker_termination_semantics: z.literal(
    "release-or-abort-worker-owned-leases-and-reservations",
  ),
  restart_reconstruction_semantics: z.literal(
    "start-ledgers-empty-after-staging-cleanup-and-committed-object-scan",
  ),
  committed_usage_reconciliation: z.literal(
    "rescan-documents-and-renders-excluding-sequence-records",
  ),
  backup_required: z.literal(false),
  expected_active_leases: z.literal(0),
  expected_staging_reservations: z.literal(0),
  expected_publication_reservations: z.literal(0),
  expected_reserved_bytes: z.literal(0),
  expected_reserved_objects: z.literal(0),
  expected_reserved_inodes: z.literal(0),
  required_proof: z.literal("protected-empty-lease-reservation-reconciliation"),
});

const evidenceSchema = z.strictObject({
  status: z.literal("external_authority_required"),
  gate_id: z.literal("private-full.recovery-proof"),
  command_id: z.literal("container.private-full-recovery.v2"),
  signed_proof_schema: z.literal("recovery-proof.v2"),
  candidate_generated: z.literal(false),
  measured_rto_seconds: z.null(),
  source_backup_restore_proof_sha256: z.null(),
  derived_regeneration_proof_sha256: z.null(),
  state_reconstruction_proof_sha256: z.null(),
  controller_receipt_sha256: z.null(),
  blockers: z.tuple([
    z.literal("UNIQUE_SOURCE_BACKUP_RESTORE_PROOF_REQUIRED"),
    z.literal("DERIVED_RENDER_REGENERATION_PROOF_REQUIRED"),
    z.literal("PERSISTENT_STATE_RECONSTRUCTION_PROOF_REQUIRED"),
    z.literal("MEASURED_RTO_PROOF_REQUIRED"),
    z.literal("PROTECTED_RECOVERY_AUTHORITY_REQUIRED"),
  ]),
});

export const privateRecoveryPolicySchema = z.strictObject({
  schema_version: z.literal(1),
  policy_id: z.literal("nplg.private-full.artifact-recovery.v1"),
  profile: z.literal("private-full"),
  owner: z.literal("NPLG private storage operator"),
  rto: rtoSchema,
  subjects: z.tuple([subjectSchema, subjectSchema]),
  filesystem_expectations: privateFilesystemExpectationsSchema,
  state_inventory: z.tuple([
    clockHighWaterStateSchema,
    insertionHighWaterStateSchema,
    perObjectInsertionSequenceStateSchema,
    orphanStagingStateSchema,
    postProcessLeaseReservationStateSchema,
  ]),
  evidence: evidenceSchema,
  terminal_verdict: z.literal("do_not_release"),
  release_ready: z.literal(false),
  policy_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
}).superRefine((value, context) => {
  if (
    value.subjects[0].subject_id !== "source-pdfs"
    || value.subjects[1].subject_id !== "derived-renders"
  ) {
    context.addIssue({
      code: "custom",
      message: "recovery subject inventory must be exact and ordered",
      path: ["subjects"],
    });
  }
  if (!policyDigestMatches(value)) {
    context.addIssue({
      code: "custom",
      message: "private recovery policy digest does not match its content",
      path: ["policy_digest"],
    });
  }
});

/**
 * @param {unknown} raw
 * @returns {z.infer<typeof privateRecoveryPolicySchema>}
 */
export function parsePrivateRecoveryPolicy(raw) {
  if (!(raw instanceof Uint8Array)) {
    throw new TypeError("private recovery policy must be supplied as raw bytes");
  }
  if (raw.byteLength > MAX_RAW_POLICY_BYTES) {
    throw new RangeError("private recovery policy exceeds the raw-byte limit");
  }
  const copied = Buffer.from(raw);
  if (
    copied.length >= 3
    && copied[0] === 0xef
    && copied[1] === 0xbb
    && copied[2] === 0xbf
  ) {
    throw new SyntaxError("private recovery policy must not contain a UTF-8 BOM");
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(copied);
  } catch (error) {
    throw new SyntaxError("private recovery policy is not valid UTF-8", { cause: error });
  }
  return privateRecoveryPolicySchema.parse(parseJsonRejectingDuplicateKeys(source));
}

export async function loadPrivateRecoveryPolicy() {
  const raw = await readFile(
    new URL("../../security/private-recovery-policy.json", import.meta.url),
  );
  return parsePrivateRecoveryPolicy(raw);
}
