import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { z } from "zod";
import * as capabilityContracts from "../../contracts/zod/capability-contracts.mjs";

const {
  alpicTasksCapabilitySchema,
  alpicTasksSourceEvidenceSchema,
  alpicOAuthDiscoveryCapabilitySchema,
  oauthProviderCapabilitySchema,
  sdkAuthorizationCapabilitySchema,
} = capabilityContracts;

const root = new URL("../../", import.meta.url);

const mutableHeaderSchema = z.looseObject({
  name: z.string(),
  value: z.string(),
});
const mutableHttpSchema = z.looseObject({
  body_base64: z.string(),
  body_sha256: z.string(),
  headers: z.array(mutableHeaderSchema),
  status_code: z.number().optional(),
});
const mutableObservationSchema = z.looseObject({
  downstream_dispatch_count: z.number(),
  request: mutableHttpSchema,
  response: mutableHttpSchema,
});
const mutableSdkSchema = z.looseObject({
  asgi_case_digest: z.string(),
  asgi_observation_digest: z.string(),
  basic_authorization_observation: mutableObservationSchema,
  duplicate_authorization_observation: mutableObservationSchema,
  expired_bearer_observation: mutableObservationSchema,
  invalid_bearer_observation: mutableObservationSchema,
  missing_authorization_observation: mutableObservationSchema,
  reason: z.string(),
  reviewed_date: z.string(),
  scope_challenge: z.looseObject({ header_value: z.string() }),
  sdk_extension_point: z.string(),
  sufficient_scope_control: mutableObservationSchema,
  upstream_commit_unavailable_reason: z.string(),
  verdict_digest: z.string(),
  weak_scope_alternate_tool_observation: mutableObservationSchema,
  weak_scope_observation: mutableObservationSchema,
});
const mutableAlpicSchema = z.looseObject({
  bounded_request_fixture: mutableHttpSchema,
  detector_contract_provenance: z.string(),
  detector_contract_source: z.string(),
  exact_detector_fixture_supported: z.boolean(),
  installed_sdk_tree_sha256: z.string(),
  local_observation_digest: z.string(),
  local_sdk_observation: mutableObservationSchema,
  request_digest: z.string(),
  rewrite_mapping: z.unknown(),
  route_bindings: z.looseObject({
    backend_resource_server_url: z.string(),
    challenge_resource_metadata: z.string(),
  }),
  supported: z.boolean(),
  verdict_digest: z.string(),
  reviewed_date: z.string(),
});
const mutableProviderSchema = z.looseObject({
  blockers: z.array(z.string()),
  scopes: z.array(z.string()),
  verdict_digest: z.string(),
});
const mutableAlpicTasksSchema = z.looseObject({
  blockers: z.array(z.string()),
  extension_revision_state: z.string(),
  provider_integration: z.string(),
  provider_tasks_compute: z.string(),
  restart_recovery: z.string(),
  reviewed_date: z.string(),
  source_evidence_digest: z.string(),
  supported: z.boolean(),
  verdict_digest: z.string(),
  live_evidence: z.looseObject({ environment_id: z.string() }).optional(),
});
const mutableAlpicTasksSourceRecordSchema = z.looseObject({
  content_sha256: z.string(),
  final_url: z.string(),
  media_type: z.string(),
  url: z.string(),
});
const mutableAlpicTasksSourceEvidenceSchema = z.looseObject({
  evidence_digest: z.string(),
  schema_version: z.string(),
  sources: z.array(mutableAlpicTasksSourceRecordSchema),
});

/** @typedef {z.infer<typeof mutableHttpSchema>} MutableHttp */
/** @typedef {z.infer<typeof mutableObservationSchema>} MutableObservation */
/** @typedef {z.infer<typeof mutableSdkSchema>} MutableSdk */
/** @typedef {z.infer<typeof mutableAlpicSchema>} MutableAlpic */
/** @typedef {z.infer<typeof mutableAlpicTasksSchema>} MutableAlpicTasks */

/**
 * @param {string} name
 * @returns {Promise<unknown>}
 */
async function loadUnknown(name) {
  /** @type {unknown} */
  const decoded = JSON.parse(
    await readFile(new URL(`contracts/${name}`, root), "utf8"),
  );
  return decoded;
}

/** @returns {Promise<MutableSdk>} */
async function loadSdk() {
  return mutableSdkSchema.parse(await loadUnknown("sdk-authorization-capability.json"));
}

/** @returns {Promise<MutableAlpic>} */
async function loadAlpic() {
  return mutableAlpicSchema.parse(await loadUnknown("alpic-oauth-discovery-capability.json"));
}

/** @returns {Promise<z.infer<typeof mutableProviderSchema>>} */
async function loadProvider() {
  return mutableProviderSchema.parse(await loadUnknown("oauth-provider-capability.json"));
}

/** @returns {Promise<MutableAlpicTasks>} */
async function loadAlpicTasks() {
  return mutableAlpicTasksSchema.parse(await loadUnknown("alpic-tasks-capability.json"));
}

/** @returns {Promise<z.infer<typeof mutableAlpicTasksSourceEvidenceSchema>>} */
async function loadAlpicTasksSourceEvidence() {
  return mutableAlpicTasksSourceEvidenceSchema.parse(
    await loadUnknown("alpic-tasks-source-evidence.json"),
  );
}

/**
 * @param {string} name
 * @returns {Promise<string>}
 */
async function loadRaw(name) {
  return readFile(new URL(`contracts/${name}`, root), "utf8");
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
        .sort(([left], [right]) => (left < right ? -1 : Number(left > right)))
        .map(([key, item]) => [key, canonicalize(item)]),
    );
  }
  return value;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function digestJson(value) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalize(value)), "utf8")
    .digest("hex");
}

/**
 * @param {Record<string, unknown>} value
 * @returns {Record<string, unknown>}
 */
function withoutVerdictDigest(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== "verdict_digest"),
  );
}

/** @type {readonly ["missing_authorization_observation", "basic_authorization_observation", "invalid_bearer_observation", "expired_bearer_observation", "weak_scope_observation", "weak_scope_alternate_tool_observation", "sufficient_scope_control", "duplicate_authorization_observation"]} */
const sdkObservationFields = [
  "missing_authorization_observation",
  "basic_authorization_observation",
  "invalid_bearer_observation",
  "expired_bearer_observation",
  "weak_scope_observation",
  "weak_scope_alternate_tool_observation",
  "sufficient_scope_control",
  "duplicate_authorization_observation",
];

/**
 * @param {MutableHttp} value
 * @returns {void}
 */
function redigestHttp(value) {
  value.body_sha256 = createHash("sha256")
    .update(Buffer.from(value.body_base64, "base64"))
    .digest("hex");
}

/**
 * @param {MutableObservation} value
 * @returns {void}
 */
function redigestObservation(value) {
  redigestHttp(value.request);
  redigestHttp(value.response);
}

/**
 * @param {MutableSdk} value
 * @returns {MutableSdk}
 */
function redigestSdk(value) {
  const observations = sdkObservationFields.map((field) => value[field]);
  observations.forEach(redigestObservation);
  value.asgi_case_digest = digestJson({ requests: observations.map(({ request }) => request) });
  value.asgi_observation_digest = digestJson({ observations });
  value.verdict_digest = digestJson(withoutVerdictDigest(value));
  return value;
}

/**
 * @param {MutableAlpic} value
 * @returns {MutableAlpic}
 */
function redigestAlpic(value) {
  redigestHttp(value.bounded_request_fixture);
  redigestObservation(value.local_sdk_observation);
  value.request_digest = digestJson(value.bounded_request_fixture);
  value.local_observation_digest = digestJson(value.local_sdk_observation);
  value.verdict_digest = digestJson(withoutVerdictDigest(value));
  return value;
}

/**
 * @param {z.infer<typeof mutableProviderSchema>} value
 * @returns {z.infer<typeof mutableProviderSchema>}
 */
function redigestProvider(value) {
  value.verdict_digest = digestJson(withoutVerdictDigest(value));
  return value;
}

/**
 * @param {MutableAlpicTasks} value
 * @returns {MutableAlpicTasks}
 */
function redigestAlpicTasks(value) {
  value.verdict_digest = digestJson(withoutVerdictDigest(value));
  return value;
}

/**
 * @template T
 * @param {unknown} raw
 * @param {import("zod").ZodType<T>} schema
 * @returns {T}
 */
function parseRawContract(raw, schema) {
  const rawLoader = capabilityContracts.parseCanonicalCapabilityContract;
  if (typeof rawLoader === "function") {
    return rawLoader(raw, schema);
  }
  if (typeof raw !== "string") {
    throw new TypeError("raw capability fixture must be text");
  }
  /** @type {unknown} */
  const decoded = JSON.parse(raw);
  return schema.parse(decoded);
}

void test("Zod independently accepts the strict capability records", async () => {
  const sdk = parseRawContract(await loadRaw("sdk-authorization-capability.json"), sdkAuthorizationCapabilitySchema);
  const alpic = parseRawContract(await loadRaw("alpic-oauth-discovery-capability.json"), alpicOAuthDiscoveryCapabilitySchema);
  const provider = parseRawContract(await loadRaw("oauth-provider-capability.json"), oauthProviderCapabilitySchema);
  assert.equal(typeof alpicTasksCapabilitySchema.parse, "function");
  assert.equal(typeof alpicTasksSourceEvidenceSchema.parse, "function");
  const alpicTasksSources = parseRawContract(
    await loadRaw("alpic-tasks-source-evidence.json"),
    alpicTasksSourceEvidenceSchema,
  );
  const alpicTasks = parseRawContract(await loadRaw("alpic-tasks-capability.json"), alpicTasksCapabilitySchema);
  assert.equal(sdk.supported, false);
  assert.equal(alpic.exact_detector_fixture_supported, false);
  assert.equal(provider.supported, false);
  assert.equal(alpicTasks.supported, false);
  assert.equal(alpicTasks.source_evidence_digest, alpicTasksSources.evidence_digest);
});

void test("Zod rejects unknown fields independently of Pydantic", async () => {
  const sdk = await loadSdk();
  sdk["unexpected"] = true;
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(sdk));
});

void test("Zod rejects nested SDK evidence and digest mutations", async () => {
  const sdk = await loadSdk();
  sdk.weak_scope_observation.response.status_code = 401;
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(sdk));

  const duplicate = await loadSdk();
  duplicate.duplicate_authorization_observation.request.headers =
    duplicate.duplicate_authorization_observation.request.headers.filter(
      ({ name, value }) =>
        name !== "authorization" || value !== "Bearer strong-fixture-token",
    );
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(duplicate));

  const body = await loadSdk();
  body.invalid_bearer_observation.response.body_base64 = "QUJDRA==";
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(body));
});

void test("Zod prevents bounded Alpic evidence from becoming a vendor observation", async () => {
  const alpic = await loadAlpic();
  alpic["dispatch_counts"] = {
    sdk_authentication: 0,
    legacy: 0,
    session_manager: 0,
    handler: 0,
    second_token_verifier: 0,
  };
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(alpic));

  const vendor = await loadAlpic();
  vendor.detector_contract_source = "vendor_fixture";
  vendor.exact_detector_fixture_supported = true;
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(vendor));
});

void test("Zod raw loader rejects duplicate keys and noncanonical bytes", async () => {
  const raw = await loadRaw("sdk-authorization-capability.json");
  const duplicate = raw.replace(
    '{"asgi_case_digest":',
    '{"schema_version":"2.0","asgi_case_digest":',
  );
  assert.throws(() => parseRawContract(duplicate, sdkAuthorizationCapabilitySchema));

  const pretty = `${JSON.stringify(JSON.parse(raw), null, 2)}\n`;
  assert.throws(() => parseRawContract(pretty, sdkAuthorizationCapabilitySchema));

  assert.throws(
    () => parseRawContract(" ".repeat(2_097_153), sdkAuthorizationCapabilitySchema),
    RangeError,
  );

  const alpicTasksRaw = await loadRaw("alpic-tasks-capability.json");
  const alpicTasksDuplicate = alpicTasksRaw.replace(
    '{"artifact_delivery":',
    '{"provider":"alpic","artifact_delivery":',
  );
  assert.throws(() => parseRawContract(alpicTasksDuplicate, alpicTasksCapabilitySchema));
  const alpicTasksPretty = `${JSON.stringify(JSON.parse(alpicTasksRaw), null, 2)}\n`;
  assert.throws(() => parseRawContract(alpicTasksPretty, alpicTasksCapabilitySchema));

  const alpicTasksSourcesRaw = await loadRaw("alpic-tasks-source-evidence.json");
  const alpicTasksSourcesDuplicate = alpicTasksSourcesRaw.replace(
    '{"evidence_digest":',
    '{"schema_version":"1.0","evidence_digest":',
  );
  assert.throws(
    () => parseRawContract(alpicTasksSourcesDuplicate, alpicTasksSourceEvidenceSchema),
  );
});

void test("Zod rejects redigested SDK semantic and raw-observation forgeries", async () => {
  const extension = redigestSdk(await loadSdk());
  extension.sdk_extension_point = "parsed_operation_http_response";
  redigestSdk(extension);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(extension));

  const dispatch = await loadSdk();
  dispatch.invalid_bearer_observation.downstream_dispatch_count = 1;
  redigestSdk(dispatch);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(dispatch));

  const duplicate = await loadSdk();
  const duplicateHeader = duplicate.duplicate_authorization_observation.request.headers
    .find(({ name }) => name === "authorization");
  assert.ok(duplicateHeader !== undefined);
  duplicateHeader.value = "Bearer strong-fixture-token";
  redigestSdk(duplicate);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(duplicate));

  const challenge = await loadSdk();
  challenge.scope_challenge.header_value = 'Basic realm="forged"';
  /** @type {readonly ["weak_scope_observation", "weak_scope_alternate_tool_observation"]} */
  const weakScopeFields = [
    "weak_scope_observation",
    "weak_scope_alternate_tool_observation",
  ];
  for (const field of weakScopeFields) {
    const challengeHeader = challenge[field].response.headers
      .find(({ name }) => name === "www-authenticate");
    assert.ok(challengeHeader !== undefined);
    challengeHeader.value = 'Basic realm="forged"';
  }
  redigestSdk(challenge);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(challenge));

  const response = await loadSdk();
  const forgedBody = Buffer.from('{"error":"forged"}', "utf8").toString("base64");
  for (const field of sdkObservationFields.slice(0, 4)) {
    response[field].response.body_base64 = forgedBody;
  }
  redigestSdk(response);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(response));

  const request = await loadSdk();
  request.weak_scope_observation.request.body_base64 = Buffer.from(
    '{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{},"name":"forged"}}',
    "utf8",
  ).toString("base64");
  redigestSdk(request);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(request));
});

void test("Zod rejects redigested Alpic route, rewrite, challenge, and support forgeries", async () => {
  const supported = await loadAlpic();
  supported.supported = true;
  redigestAlpic(supported);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(supported));

  const route = await loadAlpic();
  route.route_bindings.backend_resource_server_url = "https://attacker.example";
  redigestAlpic(route);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(route));

  const rewrite = await loadAlpic();
  rewrite.rewrite_mapping = {
    observed: true,
    entries: [{ public_path: "/mcp", backend_path: "/internal" }],
  };
  redigestAlpic(rewrite);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(rewrite));

  const challenge = await loadAlpic();
  const challengeHeader = challenge.local_sdk_observation.response.headers
    .find(({ name }) => name === "www-authenticate");
  assert.ok(challengeHeader !== undefined);
  challengeHeader.value = 'Basic realm="forged"';
  redigestAlpic(challenge);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(challenge));

  const sdkIdentity = await loadAlpic();
  sdkIdentity.installed_sdk_tree_sha256 = "0".repeat(64);
  redigestAlpic(sdkIdentity);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(sdkIdentity));
});

void test("Zod rejects redigested Alpic Tasks support and deployment forgeries", async () => {
  const supported = await loadAlpicTasks();
  supported.supported = true;
  redigestAlpicTasks(supported);
  assert.throws(() => alpicTasksCapabilitySchema.parse(supported));

  const integration = await loadAlpicTasks();
  integration.provider_integration = "proven";
  redigestAlpicTasks(integration);
  assert.throws(() => alpicTasksCapabilitySchema.parse(integration));

  const compute = await loadAlpicTasks();
  compute.provider_tasks_compute = "proven";
  redigestAlpicTasks(compute);
  assert.throws(() => alpicTasksCapabilitySchema.parse(compute));

  const extension = await loadAlpicTasks();
  extension.extension_revision_state = "stable";
  redigestAlpicTasks(extension);
  assert.throws(() => alpicTasksCapabilitySchema.parse(extension));

  const blockers = await loadAlpicTasks();
  blockers.blockers.reverse();
  redigestAlpicTasks(blockers);
  assert.throws(() => alpicTasksCapabilitySchema.parse(blockers));

  const unknown = await loadAlpicTasks();
  unknown["future_approval"] = true;
  assert.throws(() => alpicTasksCapabilitySchema.parse(unknown));
});

void test("Zod reaches only a complete synthetic supported Alpic Tasks branch", async () => {
  const synthetic = await loadAlpicTasks();
  Object.assign(synthetic, {
    extension_revision_state: "stable",
    mcp_version: "2.1.0",
    mcp_types_version: "2.1.0",
    installed_sdk_tree_sha256: "1".repeat(64),
    sdk_server_support: "supported",
    sdk_client_support: "supported",
    source_evidence_digest: "2".repeat(64),
    provider_integration: "proven",
    task_creation_durability: "proven",
    restart_recovery: "proven",
    cancellation: "proven",
    isolation: "proven",
    retention: "proven",
    artifact_delivery: "proven",
    client_support: "proven",
    documentation_provenance: "Synthetic schema-reachability fixture; not operational evidence.",
    supported: true,
    blockers: [],
    reviewed_date: "2026-08-25",
    live_evidence: {
      environment_id: "synthetic-environment",
      deployment_id: "synthetic-deployment",
      pack_sha256: "3".repeat(64),
      sdk_wheel_sha256: "4".repeat(64),
      protocol_revision_sha256: "5".repeat(64),
      client_identities_sha256: "6".repeat(64),
      evidence_digest: "7".repeat(64),
      observed_at: "2026-08-25T00:00:00Z",
    },
  });
  redigestAlpicTasks(synthetic);

  const parsed = alpicTasksCapabilitySchema.parse(synthetic);

  assert.equal(parsed.supported, true);
  assert.equal(parsed.live_evidence.environment_id, "synthetic-environment");
  const missingIdentity = structuredClone(synthetic);
  delete missingIdentity.live_evidence;
  redigestAlpicTasks(missingIdentity);
  assert.throws(() => alpicTasksCapabilitySchema.parse(missingIdentity));
  const unproven = structuredClone(synthetic);
  unproven.restart_recovery = "not_assessed";
  redigestAlpicTasks(unproven);
  assert.throws(() => alpicTasksCapabilitySchema.parse(unproven));
  const invalidVersion = structuredClone(synthetic);
  invalidVersion["mcp_version"] = "not-a-version";
  redigestAlpicTasks(invalidVersion);
  assert.throws(() => alpicTasksCapabilitySchema.parse(invalidVersion));
  assert.equal((await loadAlpicTasks()).supported, false);
});

void test("Zod rejects Alpic Tasks source swaps and source-verdict splices", async () => {
  const redirected = await loadAlpicTasksSourceEvidence();
  const redirectedSource = redirected.sources[0];
  assert.ok(redirectedSource !== undefined);
  redirectedSource.final_url = "https://attacker.example/tasks";
  redirected.evidence_digest = digestJson({
    schema_version: redirected.schema_version,
    sources: redirected.sources,
  });
  assert.throws(() => alpicTasksSourceEvidenceSchema.parse(redirected));

  const refreshed = await loadAlpicTasksSourceEvidence();
  const refreshedSource = refreshed.sources[0];
  assert.ok(refreshedSource !== undefined);
  refreshedSource.content_sha256 = "0".repeat(64);
  refreshed.evidence_digest = digestJson({
    schema_version: refreshed.schema_version,
    sources: refreshed.sources,
  });
  assert.doesNotThrow(() => alpicTasksSourceEvidenceSchema.parse(refreshed));

  const verdict = await loadAlpicTasks();
  verdict.source_evidence_digest = refreshed.evidence_digest;
  verdict.verdict_digest = digestJson(withoutVerdictDigest(verdict));
  assert.throws(() => alpicTasksCapabilitySchema.parse(verdict));
});

void test("Zod requires immutable commit-pinned SDK roadmap provenance", async () => {
  const evidence = await loadAlpicTasksSourceEvidence();
  const roadmap = evidence.sources[1];
  assert.ok(roadmap !== undefined);
  roadmap.url = "https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/959569ba1505897bd8d824a1bf22800672f7cf14/ROADMAP.md";
  roadmap.final_url = roadmap.url;
  roadmap.media_type = "text/plain";
  evidence.evidence_digest = digestJson({
    schema_version: evidence.schema_version,
    sources: evidence.sources,
  });
  assert.doesNotThrow(() => alpicTasksSourceEvidenceSchema.parse(evidence));

  const mutable = await loadAlpicTasksSourceEvidence();
  const mutableRoadmap = mutable.sources[1];
  assert.ok(mutableRoadmap !== undefined);
  mutableRoadmap.url = "https://github.com/modelcontextprotocol/python-sdk/blob/main/ROADMAP.md";
  mutableRoadmap.final_url = mutableRoadmap.url;
  mutable.evidence_digest = digestJson({
    schema_version: mutable.schema_version,
    sources: mutable.sources,
  });
  assert.throws(() => alpicTasksSourceEvidenceSchema.parse(mutable));
});

void test("Zod bounds persisted strings and tuples", async () => {
  const sdk = await loadSdk();
  sdk.reason = "x".repeat(4097);
  redigestSdk(sdk);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(sdk));

  const alpic = await loadAlpic();
  alpic.detector_contract_provenance = "x".repeat(4097);
  redigestAlpic(alpic);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(alpic));

  const provider = await loadProvider();
  provider.scopes = Array.from({ length: 65 }, (_, index) => `scope:${String(index)}`);
  provider.verdict_digest = digestJson(withoutVerdictDigest(provider));
  assert.throws(() => oauthProviderCapabilitySchema.parse(provider));
});

void test("Zod rejects redigested capability provenance drift", async () => {
  /** @type {readonly ["upstream_commit_unavailable_reason", "reason", "reviewed_date"]} */
  const sdkProvenanceFields = [
    "upstream_commit_unavailable_reason",
    "reason",
    "reviewed_date",
  ];
  for (const field of sdkProvenanceFields) {
    const sdk = await loadSdk();
    sdk[field] = field === "reviewed_date" ? "2026-08-14" : "forged";
    redigestSdk(sdk);
    assert.throws(() => sdkAuthorizationCapabilitySchema.parse(sdk));
  }

  /** @type {readonly (readonly ["detector_contract_provenance" | "reviewed_date", string])[]} */
  const alpicProvenanceMutations = [
    ["detector_contract_provenance", "forged"],
    ["reviewed_date", "2026-08-14"],
  ];
  for (const [field, replacement] of alpicProvenanceMutations) {
    const alpic = await loadAlpic();
    alpic[field] = replacement;
    redigestAlpic(alpic);
    assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(alpic));
  }
});

void test("Zod preserves every selected Auth0 and Alpic DCR blocker", async () => {
  const missingDcr = await loadProvider();
  missingDcr.blockers = [
    "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
    "OAUTH_END_TO_END_FLOW_UNPROVEN",
  ];
  assert.throws(() => oauthProviderCapabilitySchema.parse(redigestProvider(missingDcr)));

  const missingFlow = await loadProvider();
  missingFlow.blockers = [
    "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
    "ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN",
  ];
  assert.throws(() => oauthProviderCapabilitySchema.parse(redigestProvider(missingFlow)));
});
