import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { z } from "zod";
import * as capabilityContracts from "../../contracts/zod/capability-contracts.mjs";

const {
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
  scopes: z.array(z.string()),
  verdict_digest: z.string(),
});

/** @typedef {z.infer<typeof mutableHttpSchema>} MutableHttp */
/** @typedef {z.infer<typeof mutableObservationSchema>} MutableObservation */
/** @typedef {z.infer<typeof mutableSdkSchema>} MutableSdk */
/** @typedef {z.infer<typeof mutableAlpicSchema>} MutableAlpic */

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
  assert.equal(sdk.supported, false);
  assert.equal(alpic.exact_detector_fixture_supported, false);
  assert.equal(provider.supported, false);
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
