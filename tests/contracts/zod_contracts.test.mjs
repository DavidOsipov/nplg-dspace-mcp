import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import * as capabilityContracts from "../../contracts/zod/capability-contracts.mjs";

const {
  alpicOAuthDiscoveryCapabilitySchema,
  oauthProviderCapabilitySchema,
  sdkAuthorizationCapabilitySchema,
} = capabilityContracts;

const root = new URL("../../", import.meta.url);

async function load(name) {
  return JSON.parse(await readFile(new URL(`contracts/${name}`, root), "utf8"));
}

async function loadRaw(name) {
  return readFile(new URL(`contracts/${name}`, root), "utf8");
}

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

function digestJson(value) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalize(value)), "utf8")
    .digest("hex");
}

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

function redigestHttp(value) {
  value.body_sha256 = createHash("sha256")
    .update(Buffer.from(value.body_base64, "base64"))
    .digest("hex");
}

function redigestObservation(value) {
  redigestHttp(value.request);
  redigestHttp(value.response);
}

function redigestSdk(value) {
  const observations = sdkObservationFields.map((field) => value[field]);
  observations.forEach(redigestObservation);
  value.asgi_case_digest = digestJson({ requests: observations.map(({ request }) => request) });
  value.asgi_observation_digest = digestJson({ observations });
  const { verdict_digest: _discarded, ...payload } = value;
  value.verdict_digest = digestJson(payload);
  return value;
}

function redigestAlpic(value) {
  redigestHttp(value.bounded_request_fixture);
  redigestObservation(value.local_sdk_observation);
  value.request_digest = digestJson(value.bounded_request_fixture);
  value.local_observation_digest = digestJson(value.local_sdk_observation);
  const { verdict_digest: _discarded, ...payload } = value;
  value.verdict_digest = digestJson(payload);
  return value;
}

function parseRawContract(raw, schema) {
  const rawLoader = capabilityContracts.parseCanonicalCapabilityContract;
  if (typeof rawLoader === "function") {
    return rawLoader(raw, schema);
  }
  return schema.parse(JSON.parse(raw));
}

test("Zod independently accepts the strict capability records", async () => {
  const sdk = parseRawContract(await loadRaw("sdk-authorization-capability.json"), sdkAuthorizationCapabilitySchema);
  const alpic = parseRawContract(await loadRaw("alpic-oauth-discovery-capability.json"), alpicOAuthDiscoveryCapabilitySchema);
  const provider = parseRawContract(await loadRaw("oauth-provider-capability.json"), oauthProviderCapabilitySchema);
  assert.equal(sdk.supported, false);
  assert.equal(alpic.exact_detector_fixture_supported, false);
  assert.equal(provider.supported, false);
});

test("Zod rejects unknown fields independently of Pydantic", async () => {
  const sdk = await load("sdk-authorization-capability.json");
  sdk.unexpected = true;
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(sdk));
});

test("Zod rejects nested SDK evidence and digest mutations", async () => {
  const sdk = await load("sdk-authorization-capability.json");
  sdk.weak_scope_observation.response.status_code = 401;
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(sdk));

  const duplicate = await load("sdk-authorization-capability.json");
  duplicate.duplicate_authorization_observation.request.headers =
    duplicate.duplicate_authorization_observation.request.headers.filter(
      ({ name, value }) =>
        name !== "authorization" || value !== "Bearer strong-fixture-token",
    );
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(duplicate));

  const body = await load("sdk-authorization-capability.json");
  body.invalid_bearer_observation.response.body_base64 = "QUJDRA==";
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(body));
});

test("Zod prevents bounded Alpic evidence from becoming a vendor observation", async () => {
  const alpic = await load("alpic-oauth-discovery-capability.json");
  alpic.dispatch_counts = {
    sdk_authentication: 0,
    legacy: 0,
    session_manager: 0,
    handler: 0,
    second_token_verifier: 0,
  };
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(alpic));

  const vendor = await load("alpic-oauth-discovery-capability.json");
  vendor.detector_contract_source = "vendor_fixture";
  vendor.exact_detector_fixture_supported = true;
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(vendor));
});

test("Zod raw loader rejects duplicate keys and noncanonical bytes", async () => {
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

test("Zod rejects redigested SDK semantic and raw-observation forgeries", async () => {
  const extension = redigestSdk(await load("sdk-authorization-capability.json"));
  extension.sdk_extension_point = "parsed_operation_http_response";
  redigestSdk(extension);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(extension));

  const dispatch = await load("sdk-authorization-capability.json");
  dispatch.invalid_bearer_observation.downstream_dispatch_count = 1;
  redigestSdk(dispatch);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(dispatch));

  const duplicate = await load("sdk-authorization-capability.json");
  duplicate.duplicate_authorization_observation.request.headers
    .filter(({ name }) => name === "authorization")[0].value = "Bearer strong-fixture-token";
  redigestSdk(duplicate);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(duplicate));

  const challenge = await load("sdk-authorization-capability.json");
  challenge.scope_challenge.header_value = 'Basic realm="forged"';
  for (const field of ["weak_scope_observation", "weak_scope_alternate_tool_observation"]) {
    challenge[field].response.headers
      .find(({ name }) => name === "www-authenticate").value = 'Basic realm="forged"';
  }
  redigestSdk(challenge);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(challenge));

  const response = await load("sdk-authorization-capability.json");
  const forgedBody = Buffer.from('{"error":"forged"}', "utf8").toString("base64");
  for (const field of sdkObservationFields.slice(0, 4)) {
    response[field].response.body_base64 = forgedBody;
  }
  redigestSdk(response);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(response));

  const request = await load("sdk-authorization-capability.json");
  request.weak_scope_observation.request.body_base64 = Buffer.from(
    '{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{},"name":"forged"}}',
    "utf8",
  ).toString("base64");
  redigestSdk(request);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(request));
});

test("Zod rejects redigested Alpic route, rewrite, challenge, and support forgeries", async () => {
  const supported = await load("alpic-oauth-discovery-capability.json");
  supported.supported = true;
  redigestAlpic(supported);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(supported));

  const route = await load("alpic-oauth-discovery-capability.json");
  route.route_bindings.backend_resource_server_url = "https://attacker.example";
  redigestAlpic(route);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(route));

  const rewrite = await load("alpic-oauth-discovery-capability.json");
  rewrite.rewrite_mapping = {
    observed: true,
    entries: [{ public_path: "/mcp", backend_path: "/internal" }],
  };
  redigestAlpic(rewrite);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(rewrite));

  const challenge = await load("alpic-oauth-discovery-capability.json");
  challenge.local_sdk_observation.response.headers
    .find(({ name }) => name === "www-authenticate").value = 'Basic realm="forged"';
  redigestAlpic(challenge);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(challenge));

  const sdkIdentity = await load("alpic-oauth-discovery-capability.json");
  sdkIdentity.installed_sdk_tree_sha256 = "0".repeat(64);
  redigestAlpic(sdkIdentity);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(sdkIdentity));
});

test("Zod bounds persisted strings and tuples", async () => {
  const sdk = await load("sdk-authorization-capability.json");
  sdk.reason = "x".repeat(4097);
  redigestSdk(sdk);
  assert.throws(() => sdkAuthorizationCapabilitySchema.parse(sdk));

  const alpic = await load("alpic-oauth-discovery-capability.json");
  alpic.detector_contract_provenance = "x".repeat(4097);
  redigestAlpic(alpic);
  assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(alpic));

  const provider = await load("oauth-provider-capability.json");
  provider.scopes = Array.from({ length: 65 }, (_, index) => `scope:${index}`);
  const { verdict_digest: _discarded, ...payload } = provider;
  provider.verdict_digest = digestJson(payload);
  assert.throws(() => oauthProviderCapabilitySchema.parse(provider));
});

test("Zod rejects redigested capability provenance drift", async () => {
  for (const field of ["upstream_commit_unavailable_reason", "reason", "reviewed_date"]) {
    const sdk = await load("sdk-authorization-capability.json");
    sdk[field] = field === "reviewed_date" ? "2026-08-14" : "forged";
    redigestSdk(sdk);
    assert.throws(() => sdkAuthorizationCapabilitySchema.parse(sdk));
  }

  for (const [field, replacement] of [
    ["detector_contract_provenance", "forged"],
    ["reviewed_date", "2026-08-14"],
  ]) {
    const alpic = await load("alpic-oauth-discovery-capability.json");
    alpic[field] = replacement;
    redigestAlpic(alpic);
    assert.throws(() => alpicOAuthDiscoveryCapabilitySchema.parse(alpic));
  }
});
