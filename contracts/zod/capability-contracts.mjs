import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { z } from "zod";

/** @typedef {import("zod").JSONType} JsonValue */
/** @typedef {{ [key: string]: JsonValue }} JsonObject */
/** @typedef {{ name: string, value: string }} Header */
/** @typedef {{ body_base64: string, body_sha256: string }} BodyEvidence */

const MAX_EXTERNAL_TEXT_LENGTH = 4096;
const MAX_PERSISTED_ITEMS = 64;
const MAX_RAW_CONTRACT_BYTES = 2_097_152;
const REVIEWED_DATE = "2026-08-15";
const SDK_UPSTREAM_COMMIT_UNAVAILABLE_REASON = "The official PyPI wheel metadata does not publish a verified VCS commit.";
const SDK_REASON = "SDK v2.0.0 applies static route scopes before MCP parsing, omits the RFC minimum-scope parameter, and accepts duplicate Authorization headers.";
const ALPIC_PROVENANCE = "Alpic public documentation summary; no versioned raw detector fixture or immutable response transcript was published for this review.";
const ALPIC_TASKS_PROVENANCE = "Alpic documents a separate long-running Tasks compute path with a default TTL of up to six hours; the official Python SDK roadmap defers SEP-2663 Tasks from mcp 2.0.0. No authorized Alpic task conformance probe exists.";
const ALPIC_TASKS_REVIEWED_DATE = "2026-08-24";
const ALPIC_TASKS_SOURCE_EVIDENCE_DIGEST = "67dadaf3dee652e1f1f63dd26b3031043badffc64af4cf9c168090c422673a1b";
const RESOURCE_METADATA_URL = "https://mcp.example.test/.well-known/oauth-protected-resource";
const INVALID_TOKEN_CHALLENGE = `Bearer error="invalid_token", error_description="Authentication required", resource_metadata="${RESOURCE_METADATA_URL}"`;
const INSUFFICIENT_SCOPE_CHALLENGE = `Bearer error="insufficient_scope", error_description="Required scope: nplg:search", resource_metadata="${RESOURCE_METADATA_URL}"`;
const INSTALLED_MCP_TREE_SHA256 = "c8a7f99464c9a0ed755526a539c63db31a12d178a09061e979234ade529eeb49";
const SDK_BOUNDARY_SHA256 = "7d3b6ce44ffd7f90b55984bf46a0f51049ce683486f5512b1a0466be69aa6ae0";
const LOCKED_MCP_ARTIFACT_SHA256S = [
  "0f440e735c13ece8bb19bc62cf0b86f4313448432fbb77d35e14034f4e050728",
  "1cb4c75d2d2c7b8c1d756355e5d82a39f2822cc7f13e22a2051d7ca3592349d6",
];

const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const gitObjectId = z.string().regex(/^[0-9a-f]{40}$/);
const base64Bytes = z.string()
  .min(4)
  .max(1_048_576)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const nonEmpty = z.string().min(1).max(MAX_EXTERNAL_TEXT_LENGTH);
const verifierToken = z.string().min(1).max(256).refine(
  (value) => Array.from(value).every((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && codePoint > 0x20 && codePoint !== 0x7f;
  }),
  "verifier token contains whitespace or control characters",
);
const reviewDate = z.string().regex(/^20[0-9]{2}-[0-9]{2}-[0-9]{2}$/);
const packageVersion = z.string().regex(
  /^[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}(?:[a-z][a-z0-9.-]{0,31})?$/,
);
const header = z.strictObject({
  name: z.string().min(1).max(128).regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/),
  value: z.string().min(1).max(4096).regex(/^[^\r\n]+$/),
});

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
 * @param {unknown} value
 * @returns {string}
 */
function digestJson(value) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalize(value)), "utf8")
    .digest("hex");
}

/**
 * @param {unknown} left
 * @param {unknown} right
 * @returns {boolean}
 */
function sameJson(left, right) {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

/**
 * @param {BodyEvidence} value
 * @returns {boolean}
 */
function bodyDigestMatches(value) {
  const decoded = Buffer.from(value.body_base64, "base64");
  return decoded.toString("base64") === value.body_base64
    && createHash("sha256").update(decoded).digest("hex") === value.body_sha256;
}

/**
 * @param {{ verdict_digest: string } & Record<string, unknown>} value
 * @returns {boolean}
 */
function verdictDigestMatches(value) {
  const { verdict_digest: verdictDigest, ...payload } = value;
  return verdictDigest === digestJson(payload);
}

/**
 * @param {string} source
 * @returns {JsonValue}
 */
function parseJsonRejectingDuplicateKeys(source) {
  let offset = 0;

  /**
   * @param {string} message
   * @returns {never}
   */
  function fail(message) {
    throw new SyntaxError(`${message} at byte ${String(Buffer.byteLength(source.slice(0, offset), "utf8"))}`);
  }

  /** @returns {void} */
  function skipWhitespace() {
    while (offset < source.length) {
      const codePoint = source.charCodeAt(offset);
      if (codePoint !== 0x09 && codePoint !== 0x0a && codePoint !== 0x0d && codePoint !== 0x20) {
        break;
      }
      offset += 1;
    }
  }

  /** @returns {string} */
  function parseString() {
    if (source.charAt(offset) !== '"') {
      fail("expected JSON string");
    }
    const start = offset;
    offset += 1;
    while (offset < source.length) {
      const character = source.charAt(offset);
      offset += 1;
      if (character === '"') {
        const parsed = /** @type {unknown} */ (JSON.parse(source.slice(start, offset)));
        if (typeof parsed !== "string") {
          fail("JSON string token decoded to a non-string value");
        }
        return parsed;
      }
      if (character === "\\") {
        if (offset >= source.length) {
          fail("unterminated JSON escape");
        }
        const escape = source.charAt(offset);
        offset += 1;
        if (escape === "u") {
          const codePoint = source.slice(offset, offset + 4);
          if (!/^[0-9A-Fa-f]{4}$/.test(codePoint)) {
            fail("invalid JSON Unicode escape");
          }
          offset += 4;
        } else if (!/["\\/bfnrt]/.test(escape)) {
          fail("invalid JSON escape");
        }
      } else if (character.charCodeAt(0) < 0x20) {
        fail("unescaped JSON control character");
      }
    }
    fail("unterminated JSON string");
  }

  /** @returns {number} */
  function parseNumber() {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      source.slice(offset),
    );
    if (match === null) {
      fail("invalid JSON number");
    }
    offset += match[0].length;
    return Number(match[0]);
  }

  /** @returns {JsonValue[]} */
  function parseArray() {
    /** @type {JsonValue[]} */
    const result = [];
    offset += 1;
    skipWhitespace();
    if (source.charAt(offset) === "]") {
      offset += 1;
      return result;
    }
    while (offset < source.length) {
      result.push(parseValue());
      skipWhitespace();
      if (source.charAt(offset) === "]") {
        offset += 1;
        return result;
      }
      if (source.charAt(offset) !== ",") {
        fail("expected JSON array separator");
      }
      offset += 1;
      skipWhitespace();
    }
    fail("unterminated JSON array");
  }

  /** @returns {JsonObject} */
  function parseObject() {
    /** @type {JsonObject} */
    const result = {};
    const keys = new Set();
    offset += 1;
    skipWhitespace();
    if (source.charAt(offset) === "}") {
      offset += 1;
      return result;
    }
    while (offset < source.length) {
      const key = parseString();
      if (keys.has(key)) {
        fail(`duplicate JSON key ${JSON.stringify(key)}`);
      }
      keys.add(key);
      skipWhitespace();
      if (source.charAt(offset) !== ":") {
        fail("expected JSON object colon");
      }
      offset += 1;
      result[key] = parseValue();
      skipWhitespace();
      if (source.charAt(offset) === "}") {
        offset += 1;
        return result;
      }
      if (source.charAt(offset) !== ",") {
        fail("expected JSON object separator");
      }
      offset += 1;
      skipWhitespace();
    }
    fail("unterminated JSON object");
  }

  /** @returns {JsonValue} */
  function parseValue() {
    skipWhitespace();
    const character = source.charAt(offset);
    if (character === '"') {
      return parseString();
    }
    if (character === "{") {
      return parseObject();
    }
    if (character === "[") {
      return parseArray();
    }
    /** @type {readonly (readonly [string, JsonValue])[]} */
    const literals = [["true", true], ["false", false], ["null", null]];
    for (const [literal, value] of literals) {
      if (source.startsWith(literal, offset)) {
        offset += literal.length;
        return value;
      }
    }
    return parseNumber();
  }

  const result = parseValue();
  skipWhitespace();
  if (offset !== source.length) {
    fail("trailing JSON data");
  }
  return result;
}

/**
 * @template T
 * @param {unknown} raw
 * @param {import("zod").ZodType<T>} schema
 * @returns {T}
 */
export function parseCanonicalCapabilityContract(raw, schema) {
  if (typeof raw !== "string") {
    throw new TypeError("capability contract must be supplied as UTF-8 text");
  }
  if (Buffer.byteLength(raw, "utf8") > MAX_RAW_CONTRACT_BYTES) {
    throw new RangeError("capability contract exceeds the raw-byte limit");
  }
  const value = parseJsonRejectingDuplicateKeys(raw);
  const canonical = `${JSON.stringify(canonicalize(value))}\n`;
  if (raw !== canonical) {
    throw new SyntaxError("capability contract is not canonical JSON");
  }
  return schema.parse(value);
}

const rawHttpRequest = z.strictObject({
  method: z.literal("POST"),
  path: z.literal("/mcp"),
  headers: z.array(header).min(1).max(32),
  body_base64: base64Bytes,
  body_sha256: sha256,
}).superRefine((value, context) => {
  if (!bodyDigestMatches(value)) {
    context.addIssue({ code: "custom", path: ["body_sha256"], message: "request body digest mismatch" });
  }
});

const rawHttpResponse = z.strictObject({
  status_code: z.number().int().min(100).max(599),
  headers: z.array(header).min(1).max(32),
  body_base64: base64Bytes,
  body_sha256: sha256,
}).superRefine((value, context) => {
  if (!bodyDigestMatches(value)) {
    context.addIssue({ code: "custom", path: ["body_sha256"], message: "response body digest mismatch" });
  }
});

const sdkCaseId = z.enum([
  "authorization.missing",
  "authorization.basic",
  "authorization.invalid-bearer",
  "authorization.expired-bearer",
  "authorization.weak-scope-search",
  "authorization.weak-scope-inspect",
  "authorization.sufficient-scope-control",
  "authorization.duplicate",
  "alpic.local-sdk-initialize",
]);

const sdkHttpObservation = z.strictObject({
  case_id: sdkCaseId,
  request: rawHttpRequest,
  response: rawHttpResponse,
  verifier_calls: z.number().int().min(0).max(1),
  verifier_tokens: z.array(verifierToken).max(1),
  downstream_dispatch_count: z.number().int().min(0).max(1),
}).superRefine((value, context) => {
  if (value.verifier_calls !== value.verifier_tokens.length) {
    context.addIssue({ code: "custom", path: ["verifier_calls"], message: "verifier counter/sequence mismatch" });
  }
});

/** @typedef {z.infer<typeof rawHttpRequest>} RawHttpRequest */
/** @typedef {z.infer<typeof rawHttpResponse>} RawHttpResponse */
/** @typedef {z.infer<typeof sdkHttpObservation>} SdkHttpObservation */
/** @typedef {z.infer<typeof sdkCaseId>} SdkCaseId */
/** @typedef {readonly [SdkCaseId, string, readonly string[], readonly string[]]} ExpectedSdkCase */

const scopeChallenge = z.strictObject({
  status_code: z.literal(403),
  header_value: z.literal(INSUFFICIENT_SCOPE_CHALLENGE),
  required_scope: z.literal("nplg:search"),
  advertised_scope: z.null(),
});

/**
 * @param {Buffer} body
 * @returns {BodyEvidence}
 */
function bodyEvidence(body) {
  return {
    body_base64: body.toString("base64"),
    body_sha256: createHash("sha256").update(body).digest("hex"),
  };
}

/**
 * @param {string} toolName
 * @returns {Buffer}
 */
function toolBody(toolName) {
  return Buffer.from(JSON.stringify(canonicalize({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: toolName,
      arguments: { query: "fixture" },
      _meta: {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    },
  })), "utf8");
}

/**
 * @param {Buffer} body
 * @param {Header[]} extraHeaders
 * @returns {RawHttpRequest}
 */
function expectedRequest(body, extraHeaders) {
  return {
    method: "POST",
    path: "/mcp",
    headers: [
      { name: "host", value: "mcp.example.test" },
      { name: "accept-encoding", value: "gzip, deflate" },
      { name: "connection", value: "keep-alive" },
      { name: "user-agent", value: "python-httpx/0.28.1" },
      ...extraHeaders,
      { name: "content-length", value: String(body.length) },
    ],
    ...bodyEvidence(body),
  };
}

/**
 * @param {string} toolName
 * @param {readonly string[]} authorization
 * @returns {RawHttpRequest}
 */
function expectedToolRequest(toolName, authorization) {
  const body = toolBody(toolName);
  return expectedRequest(body, [
    { name: "accept", value: "application/json, text/event-stream" },
    { name: "content-type", value: "application/json" },
    { name: "mcp-protocol-version", value: "2026-07-28" },
    { name: "mcp-method", value: "tools/call" },
    { name: "mcp-name", value: toolName },
    ...authorization.map((value) => ({ name: "authorization", value })),
  ]);
}

/** @returns {RawHttpRequest} */
function expectedInitializeRequest() {
  const body = Buffer.from('{"id":1,"jsonrpc":"2.0","method":"initialize","params":{}}', "utf8");
  return expectedRequest(body, [
    { name: "accept", value: "application/json, text/event-stream" },
    { name: "content-type", value: "application/json" },
  ]);
}

/**
 * @param {number} statusCode
 * @param {string} error
 * @param {string} description
 * @param {string} challenge
 * @returns {RawHttpResponse}
 */
function expectedErrorResponse(statusCode, error, description, challenge) {
  const body = Buffer.from(`{"error": "${error}", "error_description": "${description}"}`, "utf8");
  return {
    status_code: statusCode,
    headers: [
      { name: "content-length", value: String(body.length) },
      { name: "content-type", value: "application/json" },
      { name: "www-authenticate", value: challenge },
    ],
    ...bodyEvidence(body),
  };
}

/** @returns {RawHttpResponse} */
function expectedDispatchResponse() {
  const body = Buffer.from(
    '{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"fixture-dispatched","type":"text"}],"isError":false,"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"nplg-capability-probe","version":""}}}}',
    "utf8",
  );
  return {
    status_code: 200,
    headers: [
      { name: "content-length", value: String(body.length) },
      { name: "content-type", value: "application/json" },
    ],
    ...bodyEvidence(body),
  };
}

/**
 * @param {readonly Header[]} headers
 * @param {string} name
 * @returns {string[]}
 */
function headerValues(headers, name) {
  return headers
    .filter(({ name: candidate }) => candidate.toLowerCase() === name)
    .map(({ value }) => value);
}

/**
 * @param {string} value
 * @returns {Record<string, string>}
 */
function parseBearerChallenge(value) {
  if (!value.startsWith("Bearer ")) {
    throw new Error("challenge is not Bearer");
  }
  const source = value.slice("Bearer ".length);
  const pattern = /([A-Za-z][A-Za-z0-9_-]{0,63})="([^"\\\r\n]*)"/y;
  /** @type {Record<string, string>} */
  const result = {};
  let offset = 0;
  while (offset < source.length) {
    pattern.lastIndex = offset;
    const match = pattern.exec(source);
    if (match === null) {
      throw new Error("malformed Bearer challenge");
    }
    const key = match[1];
    const item = match[2];
    if (key === undefined || item === undefined || Object.hasOwn(result, key)) {
      throw new Error("malformed Bearer challenge");
    }
    result[key] = item;
    offset = pattern.lastIndex;
    if (offset === source.length) {
      break;
    }
    if (source.slice(offset, offset + 2) !== ", ") {
      throw new Error("malformed Bearer challenge separator");
    }
    offset += 2;
  }
  if (Object.keys(result).length === 0) {
    throw new Error("empty Bearer challenge");
  }
  return result;
}

/**
 * @param {string} value
 * @param {Record<string, string>} expected
 * @returns {boolean}
 */
function bearerChallengeMatches(value, expected) {
  try {
    return sameJson(parseBearerChallenge(value), expected);
  } catch {
    return false;
  }
}

const sdkBlockers = z.tuple([
  z.literal("MCP_DYNAMIC_SCOPE_403_UNSUPPORTED"),
  z.literal("SDK_DUPLICATE_AUTHORIZATION_REQUIRES_OUTER_REJECTION"),
]);

export const sdkAuthorizationCapabilitySchema = z.strictObject({
  schema_version: z.literal("2.0"),
  mcp_version: z.literal("2.0.0"),
  mcp_types_version: z.literal("2.0.0"),
  upstream_repository: z.literal("https://github.com/modelcontextprotocol/python-sdk"),
  upstream_commit: gitObjectId.nullable(),
  upstream_commit_unavailable_reason: z.literal(SDK_UPSTREAM_COMMIT_UNAVAILABLE_REASON),
  locked_artifact_sha256s: z.tuple([sha256, sha256]),
  installed_package_tree_sha256: z.literal(INSTALLED_MCP_TREE_SHA256),
  sdk_boundary_file: z.literal("mcp/server/auth/middleware/bearer_auth.py"),
  sdk_boundary_file_sha256: z.literal(SDK_BOUNDARY_SHA256),
  protocol_revision: z.literal("MCP-2026-07-28"),
  observation_source: z.literal("official_sdk_public_asgi"),
  asgi_case_digest: sha256,
  asgi_observation_digest: sha256,
  sdk_extension_point: z.literal("none"),
  parsed_operation_identity_at_http_auth_boundary: z.literal(false),
  routing_header_trusted: z.literal(false),
  private_mcp_reparse: z.literal(false),
  scope_challenge: scopeChallenge,
  missing_authorization_observation: sdkHttpObservation,
  basic_authorization_observation: sdkHttpObservation,
  invalid_bearer_observation: sdkHttpObservation,
  expired_bearer_observation: sdkHttpObservation,
  weak_scope_observation: sdkHttpObservation,
  weak_scope_alternate_tool_observation: sdkHttpObservation,
  sufficient_scope_control: sdkHttpObservation,
  duplicate_authorization_observation: sdkHttpObservation,
  supported: z.literal(false),
  blockers: sdkBlockers,
  reason: z.literal(SDK_REASON),
  reviewed_date: z.literal(REVIEWED_DATE),
  verdict_digest: sha256,
}).superRefine((value, context) => {
  /** @type {readonly SdkHttpObservation[]} */
  const observations = [
    value.missing_authorization_observation,
    value.basic_authorization_observation,
    value.invalid_bearer_observation,
    value.expired_bearer_observation,
    value.weak_scope_observation,
    value.weak_scope_alternate_tool_observation,
    value.sufficient_scope_control,
    value.duplicate_authorization_observation,
  ];
  /** @type {readonly ExpectedSdkCase[]} */
  const expectedCases = [
    ["authorization.missing", "search_documents", [], []],
    ["authorization.basic", "search_documents", ["Basic Zml4dHVyZTphdXRo"], []],
    ["authorization.invalid-bearer", "search_documents", ["Bearer invalid-fixture-token"], ["invalid-fixture-token"]],
    ["authorization.expired-bearer", "search_documents", ["Bearer expired-fixture-token"], ["expired-fixture-token"]],
    ["authorization.weak-scope-search", "search_documents", ["Bearer weak-fixture-token"], ["weak-fixture-token"]],
    ["authorization.weak-scope-inspect", "inspect_pdf", ["Bearer weak-fixture-token"], ["weak-fixture-token"]],
    ["authorization.sufficient-scope-control", "search_documents", ["Bearer strong-fixture-token"], ["strong-fixture-token"]],
    ["authorization.duplicate", "search_documents", ["Bearer weak-fixture-token", "Bearer strong-fixture-token"], ["weak-fixture-token"]],
  ];
  expectedCases.forEach(([caseId, toolName, authorization, verifierTokens], index) => {
    const observation = observations[index];
    if (observation === undefined) {
      context.addIssue({ code: "custom", path: ["missing_authorization_observation"], message: "closed SDK request/verifier matrix mismatch" });
      return;
    }
    if (
      observation.case_id !== caseId
      || !sameJson(observation.request, expectedToolRequest(toolName, authorization))
      || !sameJson(observation.verifier_tokens, verifierTokens)
    ) {
      context.addIssue({ code: "custom", path: ["missing_authorization_observation"], message: "closed SDK request/verifier matrix mismatch" });
    }
  });
  const unauthorized = expectedErrorResponse(401, "invalid_token", "Authentication required", INVALID_TOKEN_CHALLENGE);
  const insufficient = expectedErrorResponse(403, "insufficient_scope", "Required scope: nplg:search", INSUFFICIENT_SCOPE_CHALLENGE);
  const sufficientControl = observations[6];
  const duplicateAuthorization = observations[7];
  const weakScopeObservation = observations[4];
  if (
    sufficientControl === undefined
    || duplicateAuthorization === undefined
    || weakScopeObservation === undefined
    || observations.slice(0, 4).some(({ response, downstream_dispatch_count: count }) => !sameJson(response, unauthorized) || count !== 0)
    || observations.slice(4, 6).some(({ response, downstream_dispatch_count: count }) => !sameJson(response, insufficient) || count !== 0)
    || !sameJson(sufficientControl.response, expectedDispatchResponse())
    || sufficientControl.downstream_dispatch_count !== 1
    || !sameJson(duplicateAuthorization.response, insufficient)
    || duplicateAuthorization.downstream_dispatch_count !== 0
    || !sameJson(headerValues(duplicateAuthorization.request.headers, "authorization"), ["Bearer weak-fixture-token", "Bearer strong-fixture-token"])
  ) {
    context.addIssue({ code: "custom", path: ["weak_scope_observation"], message: "closed SDK response/dispatch matrix mismatch" });
  }
  if (
    weakScopeObservation === undefined
    || !sameJson(headerValues(weakScopeObservation.response.headers, "www-authenticate"), [value.scope_challenge.header_value])
    || !bearerChallengeMatches(value.scope_challenge.header_value, {
      error: "insufficient_scope",
      error_description: "Required scope: nplg:search",
      resource_metadata: RESOURCE_METADATA_URL,
    })
  ) {
    context.addIssue({ code: "custom", path: ["scope_challenge"], message: "scope challenge mismatch" });
  }
  if (!sameJson(value.locked_artifact_sha256s, LOCKED_MCP_ARTIFACT_SHA256S) || value.upstream_commit !== null) {
    context.addIssue({ code: "custom", path: ["locked_artifact_sha256s"], message: "SDK source identity mismatch" });
  }
  if (value.asgi_case_digest !== digestJson({ requests: observations.map(({ request }) => request) })) {
    context.addIssue({ code: "custom", path: ["asgi_case_digest"], message: "request matrix digest mismatch" });
  }
  if (value.asgi_observation_digest !== digestJson({ observations })) {
    context.addIssue({ code: "custom", path: ["asgi_observation_digest"], message: "observation matrix digest mismatch" });
  }
  if (!verdictDigestMatches(value)) {
    context.addIssue({ code: "custom", path: ["verdict_digest"], message: "verdict digest mismatch" });
  }
});

const routeRewrite = z.strictObject({
  public_path: z.string().min(1).max(1024),
  backend_path: z.string().min(1).max(1024),
});
const rewriteMapping = z.strictObject({
  observed: z.boolean(),
  entries: z.array(routeRewrite).max(32),
});
const routeBindings = z.strictObject({
  backend_resource_server_url: z.literal("https://mcp.example.test"),
  challenge_resource_metadata: z.literal(RESOURCE_METADATA_URL),
  local_metadata_route: z.literal("/.well-known/oauth-protected-resource"),
  local_metadata_resource: z.literal("https://mcp.example.test"),
  public_mcp_transport_endpoint: z.literal("https://mcp.example.test/mcp"),
  public_oauth_resource: z.literal("https://mcp.example.test"),
  public_oauth_audience: z.null(),
});
const dispatchCounts = z.strictObject({
  sdk_authentication: z.number().int().min(0).max(1),
  legacy: z.number().int().min(0).max(1),
  session_manager: z.number().int().min(0).max(1),
  handler: z.number().int().min(0).max(1),
  second_token_verifier: z.number().int().min(0).max(1),
});
const vendorRawObservation = z.strictObject({
  request: rawHttpRequest,
  response: rawHttpResponse,
});

const alpicBlockers = z.tuple([
  z.literal("ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN"),
  z.literal("ALPIC_PRM_ROUTE_COMPATIBILITY_UNPROVEN"),
  z.literal("ALPIC_OAUTH_DISCOVERY_ORDERING_UNPROVEN"),
]);

export const alpicOAuthDiscoveryCapabilitySchema = z.strictObject({
  schema_version: z.literal("2.0"),
  detector_contract_source: z.literal("bounded_documented_approximation"),
  detector_contract_provenance: z.literal(ALPIC_PROVENANCE),
  bounded_request_fixture: rawHttpRequest,
  request_digest: sha256,
  exact_detector_fixture_supported: z.literal(false),
  vendor_raw_observation: vendorRawObservation.nullable(),
  local_sdk_observation: sdkHttpObservation,
  local_observation_digest: sha256,
  route_bindings: routeBindings,
  rewrite_mapping: rewriteMapping,
  installed_sdk_tree_sha256: z.literal(INSTALLED_MCP_TREE_SHA256),
  authenticates_before_modern_only_routing_guard: z.null(),
  dispatch_counts: dispatchCounts.nullable(),
  supported: z.literal(false),
  blockers: alpicBlockers,
  reviewed_date: z.literal(REVIEWED_DATE),
  verdict_digest: sha256,
}).superRefine((value, context) => {
  const local = value.local_sdk_observation;
  const unauthorized = expectedErrorResponse(401, "invalid_token", "Authentication required", INVALID_TOKEN_CHALLENGE);
  if (
    value.vendor_raw_observation !== null
    || value.dispatch_counts !== null
    || !sameJson(value.rewrite_mapping, { observed: false, entries: [] })
  ) {
    context.addIssue({ code: "custom", path: ["vendor_raw_observation"], message: "bounded documentation cannot become vendor/rewrite evidence" });
  }
  if (
    local.case_id !== "alpic.local-sdk-initialize"
    || !sameJson(value.bounded_request_fixture, local.request)
    || !sameJson(local.request, expectedInitializeRequest())
    || !sameJson(local.response, unauthorized)
    || local.verifier_calls !== 0
    || local.verifier_tokens.length !== 0
    || local.downstream_dispatch_count !== 0
  ) {
    context.addIssue({ code: "custom", path: ["local_sdk_observation"], message: "closed local SDK observation mismatch" });
  }
  const challenges = headerValues(local.response.headers, "www-authenticate");
  const challenge = challenges[0];
  if (
    !sameJson(challenges, [INVALID_TOKEN_CHALLENGE])
    || challenge === undefined
    || !bearerChallengeMatches(challenge, {
      error: "invalid_token",
      error_description: "Authentication required",
      resource_metadata: value.route_bindings.challenge_resource_metadata,
    })
  ) {
    context.addIssue({ code: "custom", path: ["local_sdk_observation", "response"], message: "local Bearer challenge mismatch" });
  }
  if (value.request_digest !== digestJson(value.bounded_request_fixture)) {
    context.addIssue({ code: "custom", path: ["request_digest"], message: "bounded request digest mismatch" });
  }
  if (value.local_observation_digest !== digestJson(local)) {
    context.addIssue({ code: "custom", path: ["local_observation_digest"], message: "local observation digest mismatch" });
  }
  if (!verdictDigestMatches(value)) {
    context.addIssue({ code: "custom", path: ["verdict_digest"], message: "verdict digest mismatch" });
  }
});

const alpicTasksBlockers = z.tuple([
  z.literal("MCP_TASKS_REVISION_UNFROZEN"),
  z.literal("PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE"),
  z.literal("PYTHON_SDK_TASKS_CLIENT_UNAVAILABLE"),
  z.literal("ALPIC_TASKS_PYTHON_INTEGRATION_UNPROVEN"),
  z.literal("ALPIC_TASK_CREATION_DURABILITY_UNPROVEN"),
  z.literal("ALPIC_TASK_RESTART_RECOVERY_UNPROVEN"),
  z.literal("ALPIC_TASK_CANCELLATION_UNPROVEN"),
  z.literal("ALPIC_TASK_ISOLATION_UNPROVEN"),
  z.literal("ALPIC_TASK_RETENTION_UNPROVEN"),
  z.literal("ALPIC_TASK_ARTIFACT_DELIVERY_UNPROVEN"),
  z.literal("ALPIC_TASK_CLIENT_SUPPORT_UNPROVEN"),
]);

/**
 * @param {string} sourceId
 * @param {string} url
 * @param {string} observation
 * @param {string} mediaType
 * @returns {z.ZodType}
 */
function alpicTasksSourceRecord(sourceId, url, observation, mediaType) {
  return z.strictObject({
    source_id: z.literal(sourceId),
    url: z.literal(url),
    final_url: z.literal(url),
    retrieved_at: z.string().regex(/^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/),
    status_code: z.literal(200),
    media_type: z.literal(mediaType),
    content_length_bytes: z.number().int().min(1).max(1_048_576),
    content_sha256: sha256,
    observation: z.literal(observation),
  });
}

const alpicTasksSources = z.tuple([
  alpicTasksSourceRecord(
    "alpic_tasks_docs",
    "https://docs.alpic.ai/troubleshooting",
    "tasks_compute_advertised",
    "text/html",
  ),
  alpicTasksSourceRecord(
    "python_sdk_roadmap",
    "https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/959569ba1505897bd8d824a1bf22800672f7cf14/ROADMAP.md",
    "sdk_tasks_deferred",
    "text/plain",
  ),
  alpicTasksSourceRecord(
    "mcp_tasks_spec",
    "https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks",
    "tasks_extension_draft",
    "text/html",
  ),
]);

/** Canonical digest-only evidence from three allowlisted primary sources. */
export const alpicTasksSourceEvidenceSchema = z.strictObject({
  schema_version: z.literal("1.0"),
  sources: alpicTasksSources,
  evidence_digest: sha256,
}).superRefine((value, context) => {
  if (value.evidence_digest !== digestJson({
    schema_version: value.schema_version,
    sources: value.sources,
  })) {
    context.addIssue({ code: "custom", path: ["evidence_digest"], message: "source evidence digest mismatch" });
  }
});

const alpicTasksCommonShape = {
  schema_version: z.literal("1.0"),
  provider: z.literal("alpic"),
  extension_identifier: z.literal("io.modelcontextprotocol/tasks"),
  provider_tasks_compute: z.literal("advertised"),
  provider_ordinary_timeout_seconds: z.literal(30),
  provider_default_task_ttl_seconds: z.number().int().min(1).max(21_600),
};

const unsupportedAlpicTasksCapabilitySchema = z.strictObject({
  ...alpicTasksCommonShape,
  extension_revision_state: z.literal("draft"),
  mcp_version: z.literal("2.0.0"),
  mcp_types_version: z.literal("2.0.0"),
  installed_sdk_tree_sha256: z.literal(INSTALLED_MCP_TREE_SHA256),
  sdk_server_support: z.literal("unsupported"),
  sdk_client_support: z.literal("unsupported"),
  provider_default_task_ttl_seconds: z.literal(21_600),
  source_evidence_digest: z.literal(ALPIC_TASKS_SOURCE_EVIDENCE_DIGEST),
  provider_integration: z.literal("not_assessed"),
  task_creation_durability: z.literal("not_assessed"),
  restart_recovery: z.literal("not_assessed"),
  cancellation: z.literal("not_assessed"),
  isolation: z.literal("not_assessed"),
  retention: z.literal("not_assessed"),
  artifact_delivery: z.literal("not_assessed"),
  client_support: z.literal("not_assessed"),
  documentation_provenance: z.literal(ALPIC_TASKS_PROVENANCE),
  supported: z.literal(false),
  blockers: alpicTasksBlockers,
  reviewed_date: z.literal(ALPIC_TASKS_REVIEWED_DATE),
  verdict_digest: sha256,
});

const alpicTasksEvidenceIdentity = z.string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/);

const alpicTasksLiveEvidenceIdentitySchema = z.strictObject({
  environment_id: alpicTasksEvidenceIdentity,
  deployment_id: alpicTasksEvidenceIdentity,
  pack_sha256: sha256,
  sdk_wheel_sha256: sha256,
  protocol_revision_sha256: sha256,
  client_identities_sha256: sha256,
  evidence_digest: sha256,
  observed_at: z.string().regex(/^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/),
});

const supportedAlpicTasksCapabilitySchema = z.strictObject({
  ...alpicTasksCommonShape,
  extension_revision_state: z.literal("stable"),
  mcp_version: packageVersion,
  mcp_types_version: packageVersion,
  installed_sdk_tree_sha256: sha256,
  sdk_server_support: z.literal("supported"),
  sdk_client_support: z.literal("supported"),
  source_evidence_digest: sha256,
  provider_integration: z.literal("proven"),
  task_creation_durability: z.literal("proven"),
  restart_recovery: z.literal("proven"),
  cancellation: z.literal("proven"),
  isolation: z.literal("proven"),
  retention: z.literal("proven"),
  artifact_delivery: z.literal("proven"),
  client_support: z.literal("proven"),
  documentation_provenance: nonEmpty,
  live_evidence: alpicTasksLiveEvidenceIdentitySchema,
  supported: z.literal(true),
  blockers: z.tuple([]),
  reviewed_date: reviewDate,
  verdict_digest: sha256,
});

/** Independent false/true oracle; true fixtures never grant runtime authority. */
export const alpicTasksCapabilitySchema = z.discriminatedUnion("supported", [
  unsupportedAlpicTasksCapabilitySchema,
  supportedAlpicTasksCapabilitySchema,
]).superRefine((value, context) => {
  if (!verdictDigestMatches(value)) {
    context.addIssue({ code: "custom", path: ["verdict_digest"], message: "verdict digest mismatch" });
  }
});

export const oauthProviderCapabilitySchema = z.strictObject({
  schema_version: z.literal("1.0"),
  selected_issuer: nonEmpty.nullable(),
  discovery_issuer: nonEmpty.nullable(),
  authorization_endpoint: nonEmpty.nullable(),
  token_endpoint: nonEmpty.nullable(),
  jwks_uri: nonEmpty.nullable(),
  introspection_endpoint: nonEmpty.nullable(),
  access_token_format: z.enum(["signed_jwt", "opaque"]).nullable(),
  resource: nonEmpty.nullable(),
  audience: nonEmpty.nullable(),
  access_token_purpose_claim: nonEmpty.nullable(),
  client_identity_claim: nonEmpty.nullable(),
  pkce_method: z.enum(["S256", "unproven"]),
  authorization_response_issuer: z.enum(["required", "observed", "unproven"]),
  scopes: z.array(nonEmpty).max(MAX_PERSISTED_ITEMS),
  token_lifetime_seconds: z.number().int().min(1).nullable(),
  revocation: z.enum(["supported", "unsupported", "unproven"]),
  registration_modes: z.array(z.enum(["preregistered", "cimd", "dcr"])).max(3),
  evidence_source: nonEmpty,
  evidence_digest: sha256.nullable(),
  supported: z.boolean(),
  blockers: z.array(z.enum([
    "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
    "OAUTH_END_TO_END_FLOW_UNPROVEN",
    "ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN",
  ])).max(3),
  reviewed_date: reviewDate,
  verdict_digest: sha256,
}).superRefine((value, context) => {
  if (!value.supported && (value.selected_issuer !== null || value.access_token_format !== null || value.evidence_digest !== null)) {
    context.addIssue({ code: "custom", path: ["supported"], message: "unselected provider cannot select capabilities" });
  }
  if (!value.supported && !value.blockers.includes("OAUTH_PROVIDER_CAPABILITY_UNPROVEN")) {
    context.addIssue({ code: "custom", path: ["blockers"], message: "unselected provider must preserve its blocker" });
  }
  const expectedUnprovenBlockers = [
    "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
    "ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN",
    "OAUTH_END_TO_END_FLOW_UNPROVEN",
  ];
  if (!value.supported && (
    value.registration_modes.length !== 1 || value.registration_modes[0] !== "dcr"
  )) {
    context.addIssue({ code: "custom", path: ["registration_modes"], message: "selected Auth0/Alpic topology requires DCR" });
  }
  if (!value.supported && (
    value.blockers.length !== expectedUnprovenBlockers.length ||
    value.blockers.some((blocker, index) => blocker !== expectedUnprovenBlockers[index])
  )) {
    context.addIssue({ code: "custom", path: ["blockers"], message: "selected Auth0/Alpic DCR blockers are incomplete" });
  }
  if (!verdictDigestMatches(value)) {
    context.addIssue({ code: "custom", path: ["verdict_digest"], message: "verdict digest mismatch" });
  }
});

export const capabilitySchemas = {
  sdk: sdkAuthorizationCapabilitySchema,
  alpic: alpicOAuthDiscoveryCapabilitySchema,
  alpicTasks: alpicTasksCapabilitySchema,
  alpicTasksSources: alpicTasksSourceEvidenceSchema,
  provider: oauthProviderCapabilitySchema,
};
