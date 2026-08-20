import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import { z } from "zod";

/** @typedef {import("zod").JSONType} JsonValue */
/** @typedef {{ [key: string]: JsonValue }} JsonObject */
/** @typedef {import("zod").RefinementCtx} RefinementContext */
/** @typedef {"legacy" | "modern"} Profile */
/** @typedef {"resources.json" | "result-cases.json" | "error-cases.json"} FixtureName */
/** @typedef {"manifest.json" | "tool-catalog.json" | FixtureName} BaselineFileName */
/** @typedef {"download_document_file" | "get_document_metadata" | "get_render_manifest" | "inspect_pdf" | "list_document_files" | "render_pdf_page_tiles" | "render_pdf_pages" | "search_documents"} ToolName */
/** @typedef {{ name: string, value: string }} ReplayHeader */
/** @typedef {{ body_base64: string, body_sha256: string, headers: ReplayHeader[] }} ReplayRequest */
/** @typedef {{ fixture: FixtureName, profile: Profile, scenario: string, setup: JsonObject, request: ReplayRequest, status: number, outcome: string }} ExpectedCase */
/** @typedef {Record<BaselineFileName, Buffer>} RawBundle */

const MAX_RAW_BYTES = 4_194_304;
const MAX_REQUEST_BYTES = 65_536;
const MAX_HEADERS = 8;
const MAX_HEADER_VALUE_LENGTH = 4096;
const MAX_DEPTH = 64;
const FIXTURE_HANDLE = "1234/560449";
const FIXTURE_BITSTREAM_ID = "bs_public";
const FIXED_ARTIFACT_ID = "doc_379d908b524eceb9ab54a87b8347e11637efa642660c3d9d840438d8c5fd101f";
const FIXED_RENDER_ID = "rnd_e152c1535869cb3e01ed289c7daac9ad";
const ZERO_ARTIFACT_ID = `doc_${"0".repeat(64)}`;
const ZERO_RENDER_ID = `rnd_${"0".repeat(32)}`;
const ERROR_CANARY = "nplg-baseline-private-canary";

/** @type {readonly ["download_document_file", "get_document_metadata", "get_render_manifest", "inspect_pdf", "list_document_files", "render_pdf_page_tiles", "render_pdf_pages", "search_documents"]} */
const toolNames = [
  "download_document_file",
  "get_document_metadata",
  "get_render_manifest",
  "inspect_pdf",
  "list_document_files",
  "render_pdf_page_tiles",
  "render_pdf_pages",
  "search_documents",
];
/** @type {readonly ["legacy", "modern"]} */
const profiles = ["legacy", "modern"];
/** @type {readonly ["resources.json", "result-cases.json", "error-cases.json"]} */
const fixtureNames = ["resources.json", "result-cases.json", "error-cases.json"];
/** @type {readonly ["manifest.json", "tool-catalog.json", "resources.json", "result-cases.json", "error-cases.json"]} */
const baselineFileNames = [
  "manifest.json",
  "tool-catalog.json",
  "resources.json",
  "result-cases.json",
  "error-cases.json",
];
/**
 * @param {string} left
 * @param {string} right
 * @returns {number}
 */
function compareKeys(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
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
        .sort(([left], [right]) => compareKeys(left, right))
        .map(([key, item]) => [key, canonicalize(item)]),
    );
  }
  return value;
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
 * @param {Uint8Array} raw
 * @returns {string}
 */
function sha256(raw) {
  return createHash("sha256").update(raw).digest("hex");
}

/**
 * @param {RefinementContext} context
 * @param {(string | number)[]} path
 * @param {string} message
 * @returns {void}
 */
function issue(context, path, message) {
  context.addIssue({ code: "custom", path, message });
}

/**
 * Build a string schema whose length bounds use Unicode code points, matching
 * Python and Pydantic string-length semantics instead of UTF-16 code units.
 * @param {number} minimum
 * @param {number} maximum
 * @returns {import("zod").ZodString}
 */
function codePointString(minimum, maximum) {
  return z.string().superRefine((value, context) => {
    const length = Array.from(value).length;
    if (length < minimum || length > maximum) {
      issue(
        context,
        [],
        `string must contain between ${String(minimum)} and ${String(maximum)} Unicode code points`,
      );
    }
  });
}

/**
 * @param {JsonValue} value
 * @param {number} [depth]
 * @returns {number}
 */
function jsonDepth(value, depth = 0) {
  if (depth > MAX_DEPTH) {
    return depth;
  }
  if (Array.isArray(value)) {
    let maximum = depth;
    for (const item of value) {
      maximum = Math.max(maximum, jsonDepth(item, depth + 1));
    }
    return maximum;
  }
  if (value !== null && typeof value === "object") {
    let maximum = depth;
    for (const item of Object.values(value)) {
      maximum = Math.max(maximum, jsonDepth(item, depth + 1));
    }
    return maximum;
  }
  return depth;
}

const safeInteger = z.number()
  .int()
  .min(Number.MIN_SAFE_INTEGER)
  .max(Number.MAX_SAFE_INTEGER)
  .refine((value) => !Object.is(value, -0), "negative zero is not normalized");
/** @type {import("zod").ZodType<JsonValue>} */
const jsonValueSchema = z.lazy(() => z.union([
  z.null(),
  z.boolean(),
  safeInteger,
  z.string(),
  z.array(jsonValueSchema),
  z.record(z.string(), jsonValueSchema),
]));
const jsonObjectSchema = z.record(z.string(), jsonValueSchema);
const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const caseIdSchema = z.string()
  .min(1)
  .max(128)
  .regex(/^[a-z0-9][a-z0-9._-]{0,127}$/);

const emptySetupSchema = z.strictObject({
  kind: z.literal("empty"),
});
const documentSetupSchema = z.strictObject({
  kind: z.literal("document"),
  handle: z.literal(FIXTURE_HANDLE),
  bitstream_id: z.literal(FIXTURE_BITSTREAM_ID),
  artifact_id: z.literal(FIXED_ARTIFACT_ID),
});
const renderSetupSchema = z.strictObject({
  kind: z.literal("render"),
  handle: z.literal(FIXTURE_HANDLE),
  bitstream_id: z.literal(FIXTURE_BITSTREAM_ID),
  artifact_id: z.literal(FIXED_ARTIFACT_ID),
  pages: z.tuple([z.literal(1)]),
  mode: z.literal("native"),
  render_id: z.literal(FIXED_RENDER_ID),
});
const replaySetupSchema = z.discriminatedUnion("kind", [
  emptySetupSchema,
  documentSetupSchema,
  renderSetupSchema,
]);

const replayHeaderSchema = z.strictObject({
  name: z.string()
    .min(1)
    .max(128)
    .regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/),
  value: codePointString(1, MAX_HEADER_VALUE_LENGTH)
    .regex(/^[^\r\n]+$/),
});

const replayRequestSchema = z.strictObject({
  body_base64: z.string()
    .min(4)
    .max(Math.ceil(MAX_REQUEST_BYTES / 3) * 4)
    .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
  body_sha256: sha256Schema,
  headers: z.array(replayHeaderSchema).max(MAX_HEADERS),
}).superRefine((value, context) => {
  const decoded = Buffer.from(value.body_base64, "base64");
  if (
    decoded.length > MAX_REQUEST_BYTES
    || decoded.toString("base64") !== value.body_base64
  ) {
    issue(context, ["body_base64"], "request body is not bounded canonical Base64");
  }
  if (sha256(decoded) !== value.body_sha256) {
    issue(context, ["body_sha256"], "request body digest mismatch");
  }
  const lowered = value.headers.map(({ name }) => name.toLowerCase());
  if (new Set(lowered).size !== lowered.length) {
    issue(context, ["headers"], "request header names are duplicated");
  }
});

const replayExpectedSchema = z.strictObject({
  status: z.number().int().min(100).max(599),
  payload: jsonObjectSchema.nullable(),
}).superRefine((value, context) => {
  if (value.payload === null) {
    return;
  }
  if (jsonDepth(value.payload) > MAX_DEPTH) {
    issue(context, ["payload"], "response JSON nesting is too deep");
  }
  const raw = Buffer.from(`${JSON.stringify(canonicalize(value.payload))}\n`, "utf8");
  if (raw.length > MAX_RAW_BYTES) {
    issue(context, ["payload"], "response payload is oversized");
  }
});

const replayScenarioSchema = z.enum([
  "tool.success",
  "tool.strict-extra",
  "tool.strict-type",
  "resource.list",
  "resource.read-about",
  "resource.read-artifact",
  "resource.read-render",
  "error.app-canary",
  "error.generic-canary",
  "protocol.initialize",
  "protocol.server-discover",
  "protocol.tools-list",
  "protocol.method-unknown",
  "protocol.header-mismatch",
]);

export const replayRecordSchema = z.strictObject({
  profile: z.enum(["legacy", "modern"]),
  scenario: replayScenarioSchema,
  setup: replaySetupSchema,
  request: replayRequestSchema,
  expected: replayExpectedSchema,
}).superRefine((value, context) => {
  const headers = Object.fromEntries(
    value.request.headers.map(({ name, value: headerValue }) => [name, headerValue]),
  );
  const version = headers["MCP-Protocol-Version"];
  if (
    value.profile === "modern"
    && (version !== "2026-07-28" || headers["Mcp-Method"] === undefined)
  ) {
    issue(context, ["request", "headers"], "modern profile headers are incomplete");
  }
  if (
    value.profile === "legacy"
    && (![undefined, "2025-11-25"].includes(version) || headers["Mcp-Method"] !== undefined)
  ) {
    issue(context, ["request", "headers"], "legacy profile headers are invalid");
  }
});

/** @typedef {z.infer<typeof replayRecordSchema>} ReplayRecord */

/**
 * @param {JsonValue | undefined} value
 * @returns {value is JsonObject}
 */
function isJsonObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {string} caseId
 * @param {Profile} profile
 * @param {string} method
 * @param {JsonObject} params
 * @param {string | undefined} [nameHeader]
 * @returns {ReplayRequest}
 */
function requestEvidence(caseId, profile, method, params, nameHeader) {
  const requestParams = structuredClone(params);
  if (profile === "modern") {
    requestParams["_meta"] = {
      "io.modelcontextprotocol/clientCapabilities": {},
      "io.modelcontextprotocol/clientInfo": {
        name: "fixture-client",
        version: "1.0.0",
      },
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    };
  }
  const body = Buffer.from(JSON.stringify(canonicalize({
    id: caseId,
    jsonrpc: "2.0",
    method,
    params: requestParams,
  })), "utf8");
  /** @type {ReplayHeader[]} */
  const headers = [];
  if (method !== "initialize") {
    headers.push({
      name: "MCP-Protocol-Version",
      value: profile === "legacy" ? "2025-11-25" : "2026-07-28",
    });
  }
  if (profile === "modern") {
    headers.push({ name: "Mcp-Method", value: method });
    if (nameHeader !== undefined) {
      headers.push({ name: "Mcp-Name", value: nameHeader });
    }
  }
  return {
    body_base64: body.toString("base64"),
    body_sha256: sha256(body),
    headers,
  };
}

/** @returns {JsonObject} */
function emptySetup() {
  return { kind: "empty" };
}

/** @returns {JsonObject} */
function documentSetup() {
  return {
    kind: "document",
    handle: FIXTURE_HANDLE,
    bitstream_id: FIXTURE_BITSTREAM_ID,
    artifact_id: FIXED_ARTIFACT_ID,
  };
}

/** @returns {JsonObject} */
function renderSetup() {
  return {
    kind: "render",
    handle: FIXTURE_HANDLE,
    bitstream_id: FIXTURE_BITSTREAM_ID,
    artifact_id: FIXED_ARTIFACT_ID,
    pages: [1],
    mode: "native",
    render_id: FIXED_RENDER_ID,
  };
}

/**
 * @param {ToolName} toolName
 * @returns {JsonObject}
 */
function toolSetup(toolName) {
  if (["inspect_pdf", "render_pdf_pages"].includes(toolName)) {
    return documentSetup();
  }
  if (["get_render_manifest", "render_pdf_page_tiles"].includes(toolName)) {
    return renderSetup();
  }
  return emptySetup();
}

/** @type {Record<ToolName, JsonObject>} */
const successArguments = {
  download_document_file: {
    handle: FIXTURE_HANDLE,
    bitstream_id: FIXTURE_BITSTREAM_ID,
  },
  get_document_metadata: { handle: FIXTURE_HANDLE },
  get_render_manifest: { render_id: FIXED_RENDER_ID },
  inspect_pdf: { artifact_id: FIXED_ARTIFACT_ID },
  list_document_files: { handle: FIXTURE_HANDLE },
  render_pdf_page_tiles: {
    render_id: FIXED_RENDER_ID,
    page_number: 1,
    tile_width: 256,
    tile_height: 256,
    overlap: 32,
  },
  render_pdf_pages: {
    artifact_id: FIXED_ARTIFACT_ID,
    pages: [1],
    mode: "native",
  },
  search_documents: { query: "fixture" },
};

/** @type {Record<ToolName, JsonObject>} */
const typeArguments = {
  download_document_file: { handle: FIXTURE_HANDLE, bitstream_id: 1 },
  get_document_metadata: { handle: 1 },
  get_render_manifest: { render_id: 1 },
  inspect_pdf: { artifact_id: 1 },
  list_document_files: { handle: 1 },
  render_pdf_page_tiles: {
    render_id: ZERO_RENDER_ID,
    page_number: "1",
    tile_width: 256,
    tile_height: 256,
    overlap: 32,
  },
  render_pdf_pages: {
    artifact_id: ZERO_ARTIFACT_ID,
    pages: ["1"],
    mode: "native",
  },
  search_documents: { query: 1 },
};

function expectedCases() {
  /** @type {Map<string, ExpectedCase>} */
  const cases = new Map();
  /**
   * @param {FixtureName} fixture
   * @param {string} caseId
   * @param {Omit<ExpectedCase, "fixture">} values
   * @returns {void}
   */
  function add(fixture, caseId, values) {
    if (cases.has(caseId)) {
      throw new Error(`duplicate internal baseline case ${caseId}`);
    }
    cases.set(caseId, { fixture, ...values });
  }

  for (const toolName of toolNames) {
    for (const profile of profiles) {
      const successCaseId = `tool.${toolName}.${profile}.success`;
      add("result-cases.json", successCaseId, {
        profile,
        scenario: "tool.success",
        setup: toolSetup(toolName),
        request: requestEvidence(
          successCaseId,
          profile,
          "tools/call",
          { name: toolName, arguments: successArguments[toolName] },
          toolName,
        ),
        status: 200,
        outcome: "tool-success",
      });
      const extraArguments = structuredClone(successArguments[toolName]);
      if (Object.hasOwn(extraArguments, "artifact_id")) {
        extraArguments["artifact_id"] = ZERO_ARTIFACT_ID;
      }
      if (Object.hasOwn(extraArguments, "render_id")) {
        extraArguments["render_id"] = ZERO_RENDER_ID;
      }
      extraArguments["unexpected"] = true;
      /** @type {[string, string, JsonObject][]} */
      const failureCases = [
        ["extra", "tool.strict-extra", extraArguments],
        ["type", "tool.strict-type", typeArguments[toolName]],
      ];
      for (const [suffix, scenario, toolArguments] of failureCases) {
        const caseId = `tool.${toolName}.${profile}.${suffix}`;
        add("error-cases.json", caseId, {
          profile,
          scenario,
          setup: emptySetup(),
          request: requestEvidence(
            caseId,
            profile,
            "tools/call",
            { name: toolName, arguments: toolArguments },
            toolName,
          ),
          status: 200,
          outcome: "strict-error",
        });
      }
    }
  }

  const resourceOperations = [
    "list",
    "read-about",
    "read-artifact",
    "read-render",
  ];
  for (const operation of resourceOperations) {
    for (const profile of profiles) {
      const caseId = `resource.${operation}.${profile}`;
      let method = "resources/read";
      let setup = emptySetup();
      /** @type {string | undefined} */
      let nameHeader;
      /** @type {JsonObject} */
      let params;
      let outcome = "resource-read";
      if (operation === "list") {
        method = "resources/list";
        params = {};
        outcome = "resource-list";
      } else if (operation === "read-about") {
        nameHeader = "nplg://about";
        params = { uri: nameHeader };
      } else if (operation === "read-artifact") {
        setup = documentSetup();
        nameHeader = `nplg://artifact/${FIXED_ARTIFACT_ID}`;
        params = { uri: nameHeader };
      } else {
        setup = renderSetup();
        nameHeader = `nplg://render/${FIXED_RENDER_ID}/manifest`;
        params = { uri: nameHeader };
      }
      add("resources.json", caseId, {
        profile,
        scenario: `resource.${operation}`,
        setup,
        request: requestEvidence(caseId, profile, method, params, nameHeader),
        status: 200,
        outcome,
      });
    }
  }

  /** @type {[string, string, number, string][]} */
  const sanitizerCases = [
    ["app-canary", "error.app-canary", 200, "app-error"],
    ["generic-canary", "error.generic-canary", 500, "generic-error"],
  ];
  for (const [kind, scenario, status, outcome] of sanitizerCases) {
    for (const profile of profiles) {
      const caseId = `error.${kind}.${profile}`;
      add("error-cases.json", caseId, {
        profile,
        scenario,
        setup: emptySetup(),
        request: requestEvidence(
          caseId,
          profile,
          "tools/call",
          { name: "search_documents", arguments: { query: "fixture" } },
          "search_documents",
        ),
        status,
        outcome,
      });
    }
  }

  /** @type {[FixtureName, string, Profile, string, string, JsonObject, number, string][]} */
  const protocolCases = [
    [
      "result-cases.json",
      "protocol.initialize.legacy.success",
      "legacy",
      "protocol.initialize",
      "initialize",
      { protocolVersion: "2025-11-25" },
      200,
      "protocol-success",
    ],
    [
      "result-cases.json",
      "protocol.server-discover.modern.success",
      "modern",
      "protocol.server-discover",
      "server/discover",
      {},
      200,
      "protocol-success",
    ],
    [
      "result-cases.json",
      "protocol.tools-list.legacy.success",
      "legacy",
      "protocol.tools-list",
      "tools/list",
      {},
      200,
      "protocol-success",
    ],
    [
      "result-cases.json",
      "protocol.tools-list.modern.success",
      "modern",
      "protocol.tools-list",
      "tools/list",
      {},
      200,
      "protocol-success",
    ],
    [
      "error-cases.json",
      "protocol.method-unknown.legacy.error",
      "legacy",
      "protocol.method-unknown",
      "unknown/method",
      {},
      404,
      "protocol-error",
    ],
    [
      "error-cases.json",
      "protocol.header-mismatch.modern.error",
      "modern",
      "protocol.header-mismatch",
      "server/discover",
      {},
      400,
      "protocol-error",
    ],
  ];
  for (const [fixture, caseId, profile, scenario, method, params, status, outcome] of protocolCases) {
    const request = requestEvidence(caseId, profile, method, params);
    if (caseId === "protocol.header-mismatch.modern.error") {
      const methodHeader = request.headers.find(({ name }) => name === "Mcp-Method");
      if (methodHeader === undefined) {
        throw new Error("modern header-mismatch oracle is incomplete");
      }
      methodHeader.value = "tools/list";
    }
    add(fixture, caseId, {
      profile,
      scenario,
      setup: emptySetup(),
      request,
      status,
      outcome,
    });
  }
  if (cases.size !== 66) {
    throw new Error("baseline Zod oracle does not contain exactly 66 cases");
  }
  return cases;
}

const expectedCaseMap = expectedCases();

/** @type {Readonly<Record<string, string>>} */
const EXPECTED_PAYLOAD_SHA256 = Object.freeze({
  "error.app-canary.legacy": "0dad479e2bcfc476e2c78344a1d3960e5c0a011c046ea835b7d889a3fdb94556",
  "error.app-canary.modern": "0030642999c09609caa01d051d9e799679f52e8adbc43b194af0cb3465d42fc1",
  "error.generic-canary.legacy": "f1de952d5c11218e333a8101db36cb2721bfcae06b329fcadf3b8479c817af57",
  "error.generic-canary.modern": "440da25fade167137c0432f9c6779e4bebe6e68030c1d5f9ba8061911304a6e2",
  "protocol.header-mismatch.modern.error": "1911426a5d3a6af00c141a1eb74502b72dc58098984c24c43fec1bee158b523f",
  "protocol.initialize.legacy.success": "ad555a50c9ebbda36228384a543a7cc73413eaa2fddfb819bf6f1bbf7020c8bf",
  "protocol.method-unknown.legacy.error": "e395a31adf0311fbd515cba22066591661a124f335ed05fea1a11eb142f4a192",
  "protocol.server-discover.modern.success": "4aa3cdeafe357ae291403651bfdca1d285a5f94d96ed88d31e8a384e4b1e9362",
  "protocol.tools-list.legacy.success": "151f50c7cc5e96016b2e3b789b004a50423158c77ee75f08fbc2ebb365479543",
  "protocol.tools-list.modern.success": "4a06e1f57c8b389fd43ef44897f6961fcf15727c5deb98c0a6e3dac54ef1316a",
  "resource.list.legacy": "2051cc26938276e65cb4f4a20d5c4485193501d62a2be4b2209ec9a84982a5b5",
  "resource.list.modern": "87aa4d81d0811cf25025837232fc5805773b3bec406b7ecb9a47d4bd95434f9d",
  "resource.read-about.legacy": "741b8cfa3d8fe99883c8d45e996639456e11fe6f3843d3bdbee56a8059586df6",
  "resource.read-about.modern": "22ee2db5031085de2c990468ff0f385d90e4143252c8f667a77bb47413f04947",
  "resource.read-artifact.legacy": "bdce6cfb652667d59dd6c2c95d8c7374f1aea26da6ede09e1332c199433a7b46",
  "resource.read-artifact.modern": "9a271d5b6aa4fcaee3f638c97883ecfc5e59581829f438cfcb8bffde57866ef0",
  "resource.read-render.legacy": "1c376f81831eb7ab10d4578814105a6d7e5888f0063af526af2db4d66732881f",
  "resource.read-render.modern": "3a624556f74817a3d24c9fce23fd6e09c3894c62b1562324a226dc977bbf21b5",
  "tool.download_document_file.legacy.extra": "628c440a51f9feb0bed7166dcc56d1f5b361f25fa2c991e83fee401495dc5c5c",
  "tool.download_document_file.legacy.success": "3fa3fce175066716ffe604245fc291674421227a50a0224de8f51150b9b20077",
  "tool.download_document_file.legacy.type": "55d97982f5565819cd27f378bb2219ae1b1cd64df828ec5c426198805f8ec563",
  "tool.download_document_file.modern.extra": "6448f595f41b6a8660af50e68c6bea7cdf2cdd1fcd38ab86c920de9402de6e71",
  "tool.download_document_file.modern.success": "4e9fda49dd11225c0295184d929b883b9f79d796ef50a430dbac11560c42496e",
  "tool.download_document_file.modern.type": "05fe2eef54628fde1b1154aa90cdac5ee0810dfbd458dcdc8acfafd726f18917",
  "tool.get_document_metadata.legacy.extra": "6b2a9941520fcf600eef25b97951f1dd1f469f41512f8e74c20f7168a605b9c9",
  "tool.get_document_metadata.legacy.success": "470194c9712869efdc0ea74e01f679ab50adb8269921f38a3772cefb53b86a04",
  "tool.get_document_metadata.legacy.type": "404d8afdf8570accc13c9efbb80dd600556f0eb821d61ae1f882cb1fade9f2e4",
  "tool.get_document_metadata.modern.extra": "0617c403e58b0160c3b4fc0d1188b5eb29c9c81b70a794cfe01ac790d3a500d2",
  "tool.get_document_metadata.modern.success": "eb3cf1b3746e9238e1142934f78fbc74339cd19e4f59f781ca3004d60e4f54bf",
  "tool.get_document_metadata.modern.type": "a8cda56967b1ca4e5380622608bf544f869ebe7ca08ebd97a5f4c488fc100a1d",
  "tool.get_render_manifest.legacy.extra": "14059960f009553ce8d926cbe2ee5dece27ecdf21f47328a7deb1592d1f8bbde",
  "tool.get_render_manifest.legacy.success": "152a681b3419db64a10240568b57a9881f1e746a74f8bec17fa092461e61641b",
  "tool.get_render_manifest.legacy.type": "9fcc6a1c4fbd96533f8bf0598867378be41c4d0639dd0799bc774daa115e2487",
  "tool.get_render_manifest.modern.extra": "eb08379682b470f2ad0b129a4327a245b2491f55ac1e47df90fb20888c58140e",
  "tool.get_render_manifest.modern.success": "1d33408a0760a8e5f41db2fa4a273898b657f1df32548a3a0f97af779997781a",
  "tool.get_render_manifest.modern.type": "cb32699ac6557618fcd1e916502ef598345c4a579be9af24254baff82f651bed",
  "tool.inspect_pdf.legacy.extra": "5a36c6e19fb17acc1f2c5c1b93bcbd9f8e80fb4f339519dc636f52e40e16727c",
  "tool.inspect_pdf.legacy.success": "933e0afbab66980ad6e6b7ac1685a6a299a8d92407a503fdfbbe6a68012d05eb",
  "tool.inspect_pdf.legacy.type": "079906c252ecb14bc2ff527988d274dead1a0fe94d8ea36b0c0e860143221aa2",
  "tool.inspect_pdf.modern.extra": "ef17c0782993a5418a675f2ccbb595f2252865b6e68ce7ff7320b97e9d841b61",
  "tool.inspect_pdf.modern.success": "77ca696a6a35e0e6505c789b108d4282f8ec794a4dfdcc9f0e3f1bd458de3bd5",
  "tool.inspect_pdf.modern.type": "41138cac8a11d3c8db820fcd6de16805b3fd1da875572161d57b8af0af81c479",
  "tool.list_document_files.legacy.extra": "8e542593a8827698711f05487255e857795430b3320f4bfa87ee65c693e4ff55",
  "tool.list_document_files.legacy.success": "eb140dd7124d6483d6e6ee1a5e9ff6b7b6c2bd8a7f1a030067ff28cbe5585275",
  "tool.list_document_files.legacy.type": "9cbd6105d353cb859864a3ca04368c3f37885bec40fee3bf60027a03659532b1",
  "tool.list_document_files.modern.extra": "6132714730d7a8c75661f4ea2a133870bca79593c12c729e8b4e8d0c7448fbdc",
  "tool.list_document_files.modern.success": "b62e73b066e4e6f4b321e62b505373d62d7a4b6aff83cefe370e428a030561f0",
  "tool.list_document_files.modern.type": "c75eb56823887b55f5da0d3617f0d895474a83bfb6a746ed4653ff5d3b80c6a2",
  "tool.render_pdf_page_tiles.legacy.extra": "52daa1cae5c7eb34b97ce9f51737c0ee60036d68c8678b0bb4f38574257011d4",
  "tool.render_pdf_page_tiles.legacy.success": "e903f4cd19c7918915996b3664544e24b2124f31125e8f9054170b32b22a4fa3",
  "tool.render_pdf_page_tiles.legacy.type": "1e39c9d86e9b1d33a1b88baa170e205eb70c86f65858649b9c4a9ea107040ac6",
  "tool.render_pdf_page_tiles.modern.extra": "3f5be18058efb01dc764f4b98dc8a0a4667d7e0b20e95662eb524339ff2d9ce5",
  "tool.render_pdf_page_tiles.modern.success": "edec42308c610ae7dc33282efb6a15a5dfcc1828e440eb4b65d838ae7e19d5e8",
  "tool.render_pdf_page_tiles.modern.type": "2b63fd7b202a95676cdaff2511dac809fff9bb3f285df90cad438521069ceeca",
  "tool.render_pdf_pages.legacy.extra": "712038ac6abacb325ae45c8660bc1c92c59c2c4443c540e317ae429780722afd",
  "tool.render_pdf_pages.legacy.success": "92eacc0db7f124ff6312ba5aad8d8cfd5900dd690bb8cfd5c459e0cfade303e7",
  "tool.render_pdf_pages.legacy.type": "4de6400df5244887b3455a38ef262501ecb8d2923a992e51b5c769ba6b6440c2",
  "tool.render_pdf_pages.modern.extra": "020c3c7794f02e9bbdc3f353c001124db4c531e3626cd6ed6c7e732715c4b673",
  "tool.render_pdf_pages.modern.success": "c11f4d46c0915bd6862297802f62bb749a34032e905967eea9ac9d4469722369",
  "tool.render_pdf_pages.modern.type": "f2542e2bae6d4f81237ac50f3898cf2d1f406c0c1c666d6d279ad3e14e4ca200",
  "tool.search_documents.legacy.extra": "ddb3b04dc27131e7835590acf89014b9bfd1a29954e3ac70ddedaaef4dedfbac",
  "tool.search_documents.legacy.success": "be872ac2ba25b4e914abbb6d33b448c32f7d012e73c24b27dc0f2d8973d07b1d",
  "tool.search_documents.legacy.type": "6495b32169bb4041e343c0c241d86d8fe5a72d1e589d01f6e1f23f572b1e6871",
  "tool.search_documents.modern.extra": "438eb0f42df016fb465e80e96a65b12fe5ec565210ab0063a8e25b3663bddf80",
  "tool.search_documents.modern.success": "b888c482ff0ead3b1526ee552081f27c4b197fec32cdc760d187d220a7000bb0",
  "tool.search_documents.modern.type": "f305d65bad4c3be25fff6ddeb25f2ff7c0d15d8f15a920a04e2e4a9deb4d2aaf",
});

const expectedCaseIds = [...expectedCaseMap.keys()].sort(compareKeys);
const expectedPayloadIds = Object.keys(EXPECTED_PAYLOAD_SHA256).sort(compareKeys);
const expectedPayloadDigests = Object.values(EXPECTED_PAYLOAD_SHA256);
if (
  !sameJson(expectedPayloadIds, expectedCaseIds)
  || expectedPayloadIds.length !== 66
  || new Set(expectedPayloadDigests).size !== 66
  || expectedPayloadDigests.some((digest) => !/^[0-9a-f]{64}$/.test(digest))
) {
  throw new Error("baseline expected-payload digest oracle is malformed");
}

/**
 * @param {string} caseId
 * @param {ExpectedCase} expectedCase
 * @param {ReplayRecord} record
 * @param {RefinementContext} context
 * @returns {void}
 */
function validateOutcome(caseId, expectedCase, record, context) {
  const { payload, status } = record.expected;
  if (status !== expectedCase.status) {
    issue(context, [caseId, "expected", "status"], "case status drifted");
  }
  if (payload === null) {
    issue(context, [caseId, "expected", "payload"], "case payload is unexpectedly null");
    return;
  }
  if (JSON.stringify(payload).includes(ERROR_CANARY)) {
    issue(context, [caseId, "expected", "payload"], "private canary is exposed");
  }
  const result = payload["result"];
  if (["tool-success", "strict-error", "app-error"].includes(expectedCase.outcome)) {
    if (!isJsonObject(result)) {
      issue(context, [caseId, "expected", "payload", "result"], "tool result is absent");
      return;
    }
    const wantedError = expectedCase.outcome !== "tool-success";
    if (result["isError"] !== wantedError) {
      issue(context, [caseId, "expected", "payload", "result", "isError"], "tool error flag drifted");
    }
    const wantedCode = expectedCase.outcome === "strict-error"
      ? "INVALID_INPUT"
      : expectedCase.outcome === "app-error" ? "UPSTREAM_FAILURE" : undefined;
    const structuredContent = isJsonObject(result["structuredContent"])
      ? result["structuredContent"]
      : undefined;
    if (wantedCode !== undefined && structuredContent?.["code"] !== wantedCode) {
      issue(context, [caseId, "expected", "payload", "result", "structuredContent"], "tool error code drifted");
    }
  } else if (expectedCase.outcome === "generic-error") {
    const error = isJsonObject(payload["error"]) ? payload["error"] : undefined;
    if (error === undefined) {
      issue(context, [caseId, "expected", "payload", "error"], "generic error is not sanitized");
    } else if (error["code"] !== -32603 || error["message"] !== "Internal error") {
      issue(context, [caseId, "expected", "payload", "error"], "generic error is not sanitized");
    }
  } else if (expectedCase.outcome === "resource-list") {
    const resultObject = isJsonObject(result) ? result : undefined;
    const resources = resultObject?.["resources"];
    const firstResource = Array.isArray(resources) && isJsonObject(resources[0])
      ? resources[0]
      : undefined;
    if (
      !Array.isArray(resources)
      || resources.length !== 1
      || firstResource?.["uri"] !== "nplg://about"
    ) {
      issue(context, [caseId, "expected", "payload", "result", "resources"], "resource list is not about-only");
    }
  } else if (expectedCase.outcome === "resource-read") {
    const resultObject = isJsonObject(result) ? result : undefined;
    const contents = resultObject?.["contents"];
    if (!Array.isArray(contents) || contents.length !== 1) {
      issue(context, [caseId, "expected", "payload", "result", "contents"], "resource read outcome drifted");
    }
  } else if (expectedCase.outcome === "protocol-error") {
    const wanted = caseId.includes("method-unknown") ? -32601 : -32020;
    const error = isJsonObject(payload["error"]) ? payload["error"] : undefined;
    if (error?.["code"] !== wanted) {
      issue(context, [caseId, "expected", "payload", "error"], "protocol error code drifted");
    }
  } else if (!isJsonObject(result)) {
    issue(context, [caseId, "expected", "payload", "result"], "protocol result is absent");
  }
}

/** @type {readonly ["profile", "scenario", "setup", "request"]} */
const oracleFields = ["profile", "scenario", "setup", "request"];

/**
 * @param {FixtureName} fixtureName
 * @returns {import("zod").ZodType<Record<string, ReplayRecord>>}
 */
function fixtureSchema(fixtureName) {
  const expectedIds = [...expectedCaseMap.entries()]
    .filter(([, value]) => value.fixture === fixtureName)
    .map(([caseId]) => caseId)
    .sort();
  return z.record(caseIdSchema, replayRecordSchema).superRefine((records, context) => {
    const actualIds = Object.keys(records).sort();
    if (!sameJson(actualIds, expectedIds)) {
      issue(context, [], `fixture ${fixtureName} has an unknown or missing case`);
      return;
    }
    for (const caseId of expectedIds) {
      const record = records[caseId];
      const expected = expectedCaseMap.get(caseId);
      if (record === undefined || expected === undefined) {
        issue(context, [caseId], "case disappeared during strict validation");
        continue;
      }
      for (const field of oracleFields) {
        if (!sameJson(record[field], expected[field])) {
          issue(context, [caseId, field], `${field} does not match the independent case oracle`);
        }
      }
      validateOutcome(caseId, expected, record, context);
      const payloadBytes = Buffer.from(
        `${JSON.stringify(canonicalize(record.expected.payload))}\n`,
        "utf8",
      );
      if (sha256(payloadBytes) !== EXPECTED_PAYLOAD_SHA256[caseId]) {
        issue(
          context,
          [caseId, "expected", "payload"],
          "complete expected payload does not match the independent case oracle",
        );
      }
    }
  });
}

export const baselineFixtureSchemas = Object.freeze({
  "resources.json": fixtureSchema("resources.json"),
  "result-cases.json": fixtureSchema("result-cases.json"),
  "error-cases.json": fixtureSchema("error-cases.json"),
});

const gitObjectIdSchema = z.string().regex(/^[0-9a-f]{40}$/);
const boundedNonnegativeInteger = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
/** @typedef {{ anyOf?: ToolInputProperty[] | undefined, default?: JsonValue | undefined, items?: ToolInputProperty | undefined, maxItems?: number | undefined, maxLength?: number | undefined, maximum?: number | undefined, minItems?: number | undefined, minLength?: number | undefined, minimum?: number | undefined, pattern?: string | undefined, title?: string | undefined, type?: "array" | "integer" | "null" | "string" | undefined }} ToolInputProperty */
/** @type {import("zod").ZodType<ToolInputProperty>} */
const toolInputPropertySchema = z.lazy(() => z.strictObject({
  anyOf: z.array(toolInputPropertySchema).min(1).max(8).optional(),
  default: jsonValueSchema.optional(),
  items: toolInputPropertySchema.optional(),
  maxItems: boundedNonnegativeInteger.optional(),
  maxLength: boundedNonnegativeInteger.optional(),
  maximum: safeInteger.optional(),
  minItems: boundedNonnegativeInteger.optional(),
  minLength: boundedNonnegativeInteger.optional(),
  minimum: safeInteger.optional(),
  pattern: z.string().min(1).max(1024).optional(),
  title: z.string().min(1).max(256).optional(),
  type: z.enum(["array", "integer", "null", "string"]).optional(),
}).superRefine((value, context) => {
  if (value.type === undefined && value.anyOf === undefined) {
    issue(context, [], "tool input property has no type or union");
  }
  if (value.items !== undefined && value.type !== "array") {
    issue(context, ["items"], "tool input items require array type");
  }
  if (
    value.minimum !== undefined
    && value.maximum !== undefined
    && value.minimum > value.maximum
  ) {
    issue(context, ["minimum"], "tool input numeric bounds are reversed");
  }
  if (
    value.minLength !== undefined
    && value.maxLength !== undefined
    && value.minLength > value.maxLength
  ) {
    issue(context, ["minLength"], "tool input string bounds are reversed");
  }
  if (
    value.minItems !== undefined
    && value.maxItems !== undefined
    && value.minItems > value.maxItems
  ) {
    issue(context, ["minItems"], "tool input array bounds are reversed");
  }
}));

const toolInputSchema = z.strictObject({
  additionalProperties: z.literal(false),
  properties: z.record(z.string().min(1).max(128), toolInputPropertySchema),
  required: z.array(z.string().min(1).max(128)).max(32),
  type: z.literal("object"),
}).superRefine((value, context) => {
  if (new Set(value.required).size !== value.required.length) {
    issue(context, ["required"], "tool input required fields are duplicated");
  }
  for (const required of value.required) {
    if (!Object.hasOwn(value.properties, required)) {
      issue(context, ["required"], "tool input required field is not a property");
    }
  }
});

const toolDescriptorSchema = z.strictObject({
  annotations: z.strictObject({
    destructiveHint: z.boolean(),
    idempotentHint: z.boolean(),
    openWorldHint: z.boolean(),
    readOnlyHint: z.boolean(),
  }),
  description: z.string().min(1).max(4096),
  inputSchema: toolInputSchema,
  name: z.enum(toolNames),
  title: z.string().min(1).max(256),
});
/** @typedef {z.infer<typeof toolDescriptorSchema>} ToolDescriptor */

export const toolCatalogSchema = z.strictObject({
  download_document_file: toolDescriptorSchema,
  get_document_metadata: toolDescriptorSchema,
  get_render_manifest: toolDescriptorSchema,
  inspect_pdf: toolDescriptorSchema,
  list_document_files: toolDescriptorSchema,
  render_pdf_page_tiles: toolDescriptorSchema,
  render_pdf_pages: toolDescriptorSchema,
  search_documents: toolDescriptorSchema,
}).superRefine((catalog, context) => {
  for (const name of toolNames) {
    if (catalog[name].name !== name) {
      issue(context, [name, "name"], "tool descriptor name does not match its key");
    }
  }
});

export const baselineManifestSchema = z.strictObject({
  audit: z.strictObject({
    commit: z.literal("2ba5dc18385747aa5d12a3b560eaab2ab97b7a40"),
    src_tree: z.literal("fcd9debdb533498486a2bbeaf909ea5bfb95b52c"),
    tree: z.literal("b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8"),
  }),
  canonicalization: z.literal("nplg-json-sort-utf8-lf-v1"),
  capture_mode: z.literal("synthetic-index-staged-recovery"),
  entries: z.tuple([
    z.strictObject({ path: z.literal("tool-catalog.json"), sha256: sha256Schema }),
    z.strictObject({ path: z.literal("resources.json"), sha256: sha256Schema }),
    z.strictObject({ path: z.literal("result-cases.json"), sha256: sha256Schema }),
    z.strictObject({ path: z.literal("error-cases.json"), sha256: sha256Schema }),
  ]),
  generator: z.strictObject({
    blob: gitObjectIdSchema,
    path: z.literal("scripts/capture_baseline.py"),
    sha256: sha256Schema,
    version: z.literal("3"),
  }),
  index_transition: z.strictObject({
    candidate_index_tree: z.literal("55691718dade75b44a8ed025fcf48dabf87a7969"),
    candidate_staged_entries_sha256: z.literal(
      "9426ba909728d29d2009607264a9ffb1c028c4c645bbacd72f98867132e24f68",
    ),
    imported_index_tree: z.literal("6cb461d986c21e4cb2852a07b06f75812ec27bbb"),
    imported_staged_entries_sha256: z.literal(
      "fcfe06d851c83040d860f9f887efe18bde9dbe46c4eeb1aaa3f68b3af8f3ccaf",
    ),
    transition_id: z.literal("phase-1-reviewed-index-transition-v1"),
  }),
  input: z.strictObject({
    excluded_output_paths: z.tuple([
      z.literal("contracts/baseline/tool-catalog.json"),
      z.literal("contracts/baseline/resources.json"),
      z.literal("contracts/baseline/result-cases.json"),
      z.literal("contracts/baseline/error-cases.json"),
      z.literal("contracts/baseline/manifest.json"),
    ]),
    git_object_format: z.literal("sha1"),
    included_untracked_paths: z.tuple([
      z.literal("contracts/zod/asvs-evidence-contracts.mjs"),
      z.literal("contracts/zod/baseline-contracts.mjs"),
      z.literal("docs/security/threat-model.json"),
      z.literal("eslint.config.mjs"),
      z.literal("scripts/baseline_capture_io.py"),
      z.literal("scripts/baseline_replay.py"),
      z.literal("tests/contracts/zod_asvs_evidence_contracts.test.mjs"),
      z.literal("tests/contracts/zod_baseline_contracts.test.mjs"),
      z.literal("tests/property/test_asvs_evidence.py"),
      z.literal("tests/unit/test_build_asvs_matrix.py"),
      z.literal("tsconfig.contracts.json"),
    ]),
    src_tree: gitObjectIdSchema,
    tree_after: gitObjectIdSchema,
    tree_before: gitObjectIdSchema,
  }),
  recovery: z.strictObject({
    base_commit: z.literal("da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0"),
    base_tree: z.literal("2464df5aa1880e99168ce07c23d891ab66ed3959"),
    imported_index_tree: z.literal("6cb461d986c21e4cb2852a07b06f75812ec27bbb"),
  }),
  release_blockers: z.tuple([z.literal("BASELINE_CAPTURE_NOT_COMMIT_REACHABLE")]),
  release_eligible: z.literal(false),
  required_case_ids: z.array(caseIdSchema).length(66),
  required_tool_names: z.tuple([
    z.literal("download_document_file"),
    z.literal("get_document_metadata"),
    z.literal("get_render_manifest"),
    z.literal("inspect_pdf"),
    z.literal("list_document_files"),
    z.literal("render_pdf_page_tiles"),
    z.literal("render_pdf_pages"),
    z.literal("search_documents"),
  ]),
  response_canonicalization: z.literal("nplg-response-semantic-numbers-v1"),
  schema_version: z.literal(3),
}).superRefine((manifest, context) => {
  if (manifest.input.tree_before !== manifest.input.tree_after) {
    issue(context, ["input", "tree_after"], "capture input trees differ");
  }
  if (!sameJson(manifest.required_case_ids, expectedCaseIds)) {
    issue(context, ["required_case_ids"], "manifest case IDs do not match the oracle");
  }
  if (!sameJson(
    manifest.recovery.imported_index_tree,
    manifest.index_transition.imported_index_tree,
  )) {
    issue(
      context,
      ["index_transition", "imported_index_tree"],
      "recovery and transition imported trees differ",
    );
  }
});

export const committedBaselineManifestSchema = z.strictObject({
  attestation: z.strictObject({
    allowed_paths: z.tuple([
      z.literal("contracts/baseline/manifest.json"),
      z.literal("contracts/baseline/historical-manifest-v3.json"),
    ]),
    scheme: z.literal("current-head-single-parent-manifest-delta-v1"),
  }),
  candidate: z.strictObject({
    commit: gitObjectIdSchema,
    src_tree: gitObjectIdSchema,
    tree: gitObjectIdSchema,
  }),
  canonicalization: z.literal("nplg-json-sort-utf8-lf-v1"),
  capture_mode: z.literal("committed-candidate-attestation"),
  entries: z.tuple([
    z.strictObject({ path: z.literal("tool-catalog.json"), sha256: sha256Schema }),
    z.strictObject({ path: z.literal("resources.json"), sha256: sha256Schema }),
    z.strictObject({ path: z.literal("result-cases.json"), sha256: sha256Schema }),
    z.strictObject({ path: z.literal("error-cases.json"), sha256: sha256Schema }),
  ]),
  historical_provenance: z.strictObject({
    path: z.literal("historical-manifest-v3.json"),
    schema_version: z.literal(3),
    sha256: sha256Schema,
  }),
  required_case_ids: z.array(caseIdSchema).min(1).max(512),
  required_tool_names: z.tuple([
    z.literal("download_document_file"),
    z.literal("get_document_metadata"),
    z.literal("get_render_manifest"),
    z.literal("inspect_pdf"),
    z.literal("list_document_files"),
    z.literal("render_pdf_page_tiles"),
    z.literal("render_pdf_pages"),
    z.literal("search_documents"),
  ]),
  response_canonicalization: z.literal("nplg-response-semantic-numbers-v1"),
  schema_version: z.literal(4),
}).superRefine((manifest, context) => {
  const normalizedCaseIds = [...new Set(manifest.required_case_ids)].sort();
  if (!sameJson(manifest.required_case_ids, normalizedCaseIds)) {
    issue(
      context,
      ["required_case_ids"],
      "committed manifest case IDs must be unique and sorted",
    );
  }
});

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
    throw new SyntaxError(`${message} at character ${String(offset)}`);
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
        const value = parsed;
        for (let index = 0; index < value.length; index += 1) {
          const codeUnit = value.charCodeAt(index);
          if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const trailing = value.charCodeAt(index + 1);
            if (!(trailing >= 0xdc00 && trailing <= 0xdfff)) {
              fail("JSON string contains an unpaired surrogate");
            }
            index += 1;
          } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            fail("JSON string contains an unpaired surrogate");
          }
        }
        return value;
      }
      if (character === "\\") {
        if (offset >= source.length) {
          fail("unterminated JSON escape");
        }
        const escape = source.charAt(offset);
        offset += 1;
        if (escape === "u") {
          if (!/^[0-9A-Fa-f]{4}$/.test(source.slice(offset, offset + 4))) {
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
    const value = Number(match[0]);
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      fail("JSON number is not a normalized safe integer");
    }
    return value;
  }

  /**
   * @param {number} depth
   * @returns {JsonValue[]}
   */
  function parseArray(depth) {
    if (depth > MAX_DEPTH) {
      fail("JSON nesting is too deep");
    }
    /** @type {JsonValue[]} */
    const result = [];
    offset += 1;
    skipWhitespace();
    if (source.charAt(offset) === "]") {
      offset += 1;
      return result;
    }
    while (offset < source.length) {
      result.push(parseValue(depth + 1));
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

  /**
   * @param {number} depth
   * @returns {JsonObject}
   */
  function parseObject(depth) {
    if (depth > MAX_DEPTH) {
      fail("JSON nesting is too deep");
    }
    /** @type {JsonObject} */
    const result = { __proto__: null };
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
        fail("duplicate JSON key");
      }
      keys.add(key);
      skipWhitespace();
      if (source.charAt(offset) !== ":") {
        fail("expected JSON object colon");
      }
      offset += 1;
      result[key] = parseValue(depth + 1);
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

  /**
   * @param {number} depth
   * @returns {JsonValue}
   */
  function parseValue(depth) {
    if (depth > MAX_DEPTH) {
      fail("JSON nesting is too deep");
    }
    skipWhitespace();
    const character = source.charAt(offset);
    if (character === '"') {
      return parseString();
    }
    if (character === "{") {
      return parseObject(depth);
    }
    if (character === "[") {
      return parseArray(depth);
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

  const result = parseValue(0);
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
 * @param {number} [maxRawBytes]
 * @returns {T}
 */
export function parseCanonicalBaselineContract(
  raw,
  schema,
  maxRawBytes = MAX_RAW_BYTES,
) {
  if (!(raw instanceof Uint8Array)) {
    throw new TypeError("baseline contract must be supplied as raw bytes");
  }
  if (!Number.isSafeInteger(maxRawBytes) || maxRawBytes <= 0) {
    throw new RangeError("baseline contract raw-byte limit is invalid");
  }
  if (raw.byteLength > maxRawBytes) {
    throw new RangeError("baseline contract exceeds the raw-byte limit");
  }
  const copied = Buffer.from(raw);
  if (
    copied.length >= 3
    && copied[0] === 0xef
    && copied[1] === 0xbb
    && copied[2] === 0xbf
  ) {
    throw new SyntaxError("baseline contract must not contain a UTF-8 BOM");
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(copied);
  } catch (error) {
    throw new SyntaxError("baseline contract is not valid UTF-8", { cause: error });
  }
  const value = parseJsonRejectingDuplicateKeys(source);
  const canonical = Buffer.from(
    `${JSON.stringify(canonicalize(value))}\n`,
    "utf8",
  );
  if (!copied.equals(canonical)) {
    throw new SyntaxError("baseline contract is not canonical JSON");
  }
  return schema.parse(value);
}

/**
 * @param {unknown} rawFiles
 * @returns {RawBundle}
 */
function copyBaselineContractSet(rawFiles) {
  if (rawFiles === null || typeof rawFiles !== "object" || Array.isArray(rawFiles)) {
    throw new TypeError("baseline contract set must be a closed object");
  }
  const descriptors = Object.getOwnPropertyDescriptors(rawFiles);
  const actualNames = Object.keys(descriptors).sort(compareKeys);
  const expectedNames = [...baselineFileNames].sort(compareKeys);
  if (!sameJson(actualNames, expectedNames)) {
    throw new TypeError("baseline contract set has an unknown or missing file");
  }
  /** @type {RawBundle} */
  const copied = {
    "manifest.json": Buffer.alloc(0),
    "tool-catalog.json": Buffer.alloc(0),
    "resources.json": Buffer.alloc(0),
    "result-cases.json": Buffer.alloc(0),
    "error-cases.json": Buffer.alloc(0),
  };
  for (const name of baselineFileNames) {
    const descriptor = descriptors[name];
    const rawValue = descriptor !== undefined && "value" in descriptor
      ? /** @type {unknown} */ (descriptor.value)
      : undefined;
    if (
      descriptor === undefined
      || !(rawValue instanceof Uint8Array)
    ) {
      throw new TypeError("baseline contract set values must be raw bytes");
    }
    if (rawValue.byteLength > MAX_RAW_BYTES) {
      throw new RangeError("baseline contract exceeds the raw-byte limit");
    }
    copied[name] = Buffer.from(rawValue);
  }
  return copied;
}

/**
 * @param {ReplayRecord} record
 * @returns {z.infer<typeof toolCatalogSchema>}
 */
function catalogFromToolsListRecord(record) {
  const payload = record.expected.payload;
  const result = payload !== null && isJsonObject(payload["result"])
    ? payload["result"]
    : undefined;
  const tools = result?.["tools"];
  if (!Array.isArray(tools) || tools.length !== toolNames.length) {
    throw new Error("frozen tools-list payload does not contain the exact catalog");
  }
  /** @type {Record<string, ToolDescriptor>} */
  const catalog = {};
  for (const tool of tools) {
    if (
      !isJsonObject(tool)
      || typeof tool["name"] !== "string"
      || Object.hasOwn(catalog, tool["name"])
    ) {
      throw new Error("frozen tools-list payload contains an invalid tool");
    }
    const descriptor = toolDescriptorSchema.parse(tool);
    catalog[descriptor.name] = descriptor;
  }
  return toolCatalogSchema.parse(catalog);
}

/**
 * @param {unknown} rawFiles
 * @returns {{ manifest: z.infer<typeof baselineManifestSchema>, catalog: z.infer<typeof toolCatalogSchema>, fixtures: Record<FixtureName, Record<string, ReplayRecord>>, cases: Record<string, ReplayRecord> }}
 */
export function parseCanonicalBaselineSet(rawFiles) {
  const raw = copyBaselineContractSet(rawFiles);
  const manifest = parseCanonicalBaselineContract(
    raw["manifest.json"],
    baselineManifestSchema,
  );
  const catalog = parseCanonicalBaselineContract(
    raw["tool-catalog.json"],
    toolCatalogSchema,
  );
  /** @type {Record<FixtureName, Record<string, ReplayRecord>>} */
  const fixtures = {
    "resources.json": parseCanonicalBaselineContract(
      raw["resources.json"],
      baselineFixtureSchemas["resources.json"],
    ),
    "result-cases.json": parseCanonicalBaselineContract(
      raw["result-cases.json"],
      baselineFixtureSchemas["result-cases.json"],
    ),
    "error-cases.json": parseCanonicalBaselineContract(
      raw["error-cases.json"],
      baselineFixtureSchemas["error-cases.json"],
    ),
  };

  for (const entry of manifest.entries) {
    if (sha256(raw[entry.path]) !== entry.sha256) {
      throw new Error(`baseline manifest digest mismatch for ${entry.path}`);
    }
  }

  /** @type {Record<string, ReplayRecord>} */
  const cases = {};
  /** @type {Record<FixtureName, number>} */
  const expectedAllocation = {
    "resources.json": 8,
    "result-cases.json": 20,
    "error-cases.json": 38,
  };
  for (const name of fixtureNames) {
    const caseEntries = Object.entries(fixtures[name]);
    if (caseEntries.length !== expectedAllocation[name]) {
      throw new Error(`baseline fixture allocation drifted for ${name}`);
    }
    for (const [caseId, record] of caseEntries) {
      if (Object.hasOwn(cases, caseId)) {
        throw new Error("baseline case ID is duplicated across fixture files");
      }
      cases[caseId] = record;
    }
  }
  const actualCaseIds = Object.keys(cases).sort(compareKeys);
  if (!sameJson(actualCaseIds, expectedCaseIds)) {
    throw new Error("baseline case ID union does not match the independent oracle");
  }

  const resultCases = fixtures["result-cases.json"];
  for (const caseId of [
    "protocol.tools-list.legacy.success",
    "protocol.tools-list.modern.success",
  ]) {
    const record = resultCases[caseId];
    if (record === undefined) {
      throw new Error(`tools-list record disappeared for ${caseId}`);
    }
    const frozenCatalog = catalogFromToolsListRecord(record);
    if (!sameJson(frozenCatalog, catalog)) {
      throw new Error(`tool catalog disagrees with ${caseId}`);
    }
  }

  return Object.freeze({
    manifest,
    catalog,
    fixtures,
    cases,
  });
}

export const validateBaselineBundle = parseCanonicalBaselineSet;
