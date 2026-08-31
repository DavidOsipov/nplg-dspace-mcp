import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { ESLint } from "eslint";
import { z } from "zod";
import * as baselineContracts from "../../contracts/zod/baseline-contracts.mjs";
import {
  baselineFixtureSchemas,
  parseCanonicalBaselineContract,
  replayRecordSchema,
} from "../../contracts/zod/baseline-contracts.mjs";

/** @typedef {"manifest.json" | "tool-catalog.json" | "resources.json" | "result-cases.json" | "error-cases.json"} BaselineFileName */
/** @typedef {"resources.json" | "result-cases.json" | "error-cases.json"} FixtureName */
/** @typedef {{ [key: string]: Buffer | undefined, "manifest.json": Buffer, "tool-catalog.json": Buffer, "result-cases.json": Buffer, "error-cases.json": Buffer, "resources.json"?: Buffer }} RawBundle */

const mutableJsonObjectSchema = z.looseObject({});
const mutableHeaderSchema = z.looseObject({
  name: z.string(),
  value: z.string(),
});
const mutableRequestSchema = z.looseObject({
  body_base64: z.string(),
  body_sha256: z.string(),
  headers: z.array(mutableHeaderSchema),
});
const mutableExpectedSchema = z.looseObject({
  status: z.number(),
  payload: mutableJsonObjectSchema.nullable(),
});
const mutableReplayRecordSchema = z.looseObject({
  profile: z.string(),
  scenario: z.string(),
  setup: mutableJsonObjectSchema,
  request: mutableRequestSchema,
  expected: mutableExpectedSchema,
});
const mutableReplayFixtureSchema = z.record(z.string(), mutableReplayRecordSchema);
const mutableManifestSchema = z.looseObject({
  input: z.looseObject({
    included_untracked_paths: z.array(z.string()),
    tree_after: z.string(),
  }),
  entries: z.array(z.looseObject({
    path: z.string(),
    sha256: z.string(),
  })),
  required_case_ids: z.array(z.string()),
});
const mutableCatalogSchema = z.record(z.string(), z.looseObject({
  title: z.string(),
  annotations: mutableJsonObjectSchema,
}));
const taskOnePackageScriptsSchema = z.strictObject({
  "contracts:zod": z.literal(
    "node --test tests/contracts/zod_contracts.test.mjs",
  ),
  "contracts:baseline-zod": z.literal(
    "node --test tests/contracts/zod_baseline_contracts.test.mjs",
  ),
  "contracts:asvs-zod": z.literal(
    "node --test tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  ),
  "contracts:recovery-zod": z.literal(
    "node --test tests/contracts/zod_recovery_contracts.test.mjs",
  ),
  "contracts:zod:all": z.literal(
    "npm run contracts:zod && npm run contracts:baseline-zod && npm run contracts:asvs-zod && npm run contracts:recovery-zod",
  ),
  "contracts:lint": z.literal(
    "eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs contracts/zod/models.ts contracts/zod/contract.test.ts tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
  ),
  "contracts:typecheck": z.literal("tsc --project tsconfig.contracts.json"),
  "contracts:test": z.literal(
    "node --test contracts/zod/contract.test.ts && npm run contracts:zod:all",
  ),
  "docs:lint": z.literal(
    "markdownlint-cli2 \"*.md\" \"docs/**/*.md\" \"deploy/**/*.md\" \"skills/**/*.md\" \"src/nplg_mcp/agent_skills/georgian-newspaper-visual-analysis/SKILL.md\"",
  ),
  "contracts:baseline-static": z.literal(
    "tsc --project tsconfig.contracts.json && eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
  ),
  "test:contracts:asvs": z.literal(
    "node --test tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  ),
  "typecheck:contracts": z.literal("tsc --project tsconfig.contracts.json"),
  "lint:contracts": z.literal(
    "eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
  ),
});
const packageJsonSchema = z.looseObject({
  scripts: taskOnePackageScriptsSchema,
});
const resolvedEslintConfigSchema = z.looseObject({
  linterOptions: z.strictObject({
    noInlineConfig: z.literal(true),
    reportUnusedDisableDirectives: z.literal(2),
  }),
  rules: z.record(z.string(), z.unknown()),
});
const resolvedTsconfigSchema = z.looseObject({
  compilerOptions: z.looseObject({
    exactOptionalPropertyTypes: z.literal(true),
    forceConsistentCasingInFileNames: z.literal(true),
    module: z.literal("nodenext"),
    moduleResolution: z.literal("nodenext"),
    noEmit: z.literal(true),
    noFallthroughCasesInSwitch: z.literal(true),
    noImplicitOverride: z.literal(true),
    noImplicitReturns: z.literal(true),
    noPropertyAccessFromIndexSignature: z.literal(true),
    noUncheckedIndexedAccess: z.literal(true),
    noUncheckedSideEffectImports: z.literal(true),
    strict: z.literal(true),
    types: z.tuple([z.literal("node")]),
    useUnknownInCatchVariables: z.literal(true),
    verbatimModuleSyntax: z.literal(true),
  }),
  files: z.array(z.string()),
}).superRefine((value, context) => {
  const expected = contractFilePaths.map((path) => `./${path}`);
  if (
    value.files.length !== expected.length
    || value.files.some((path, index) => path !== expected[index])
  ) {
    context.addIssue({
      code: "custom",
      message: "TypeScript source inventory must be exact and ordered",
      path: ["files"],
    });
  }
});

/** @typedef {z.infer<typeof mutableJsonObjectSchema>} MutableJsonObject */
/** @typedef {z.infer<typeof mutableReplayRecordSchema>} MutableReplayRecord */
/** @typedef {z.infer<typeof mutableReplayFixtureSchema>} MutableReplayFixture */
/** @typedef {z.infer<typeof mutableManifestSchema>} MutableManifest */
/** @typedef {z.infer<typeof mutableCatalogSchema>} MutableCatalog */

const root = new URL("../../", import.meta.url);
const rootPath = fileURLToPath(root);
/** @type {readonly ["contracts/zod/baseline-contracts.mjs", "contracts/zod/asvs-evidence-contracts.mjs", "contracts/zod/capability-contracts.mjs", "contracts/zod/recovery-contracts.mjs", "contracts/zod/models.ts", "contracts/zod/contract.test.ts", "tests/contracts/zod_baseline_contracts.test.mjs", "tests/contracts/zod_asvs_evidence_contracts.test.mjs", "tests/contracts/zod_contracts.test.mjs", "tests/contracts/zod_recovery_contracts.test.mjs"]} */
const contractFilePaths = [
  "contracts/zod/baseline-contracts.mjs",
  "contracts/zod/asvs-evidence-contracts.mjs",
  "contracts/zod/capability-contracts.mjs",
  "contracts/zod/recovery-contracts.mjs",
  "contracts/zod/models.ts",
  "contracts/zod/contract.test.ts",
  "tests/contracts/zod_baseline_contracts.test.mjs",
  "tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  "tests/contracts/zod_contracts.test.mjs",
  "tests/contracts/zod_recovery_contracts.test.mjs",
];
/** @type {readonly ["contracts/zod/asvs-evidence-contracts.mjs", "contracts/zod/contract.test.ts", "contracts/zod/models.ts"]} */
const zodLengthGovernedFilePaths = [
  "contracts/zod/asvs-evidence-contracts.mjs",
  "contracts/zod/contract.test.ts",
  "contracts/zod/models.ts",
];
/** @type {readonly ["resources.json", "result-cases.json", "error-cases.json"]} */
const fixtureFileNames = [
  "resources.json",
  "result-cases.json",
  "error-cases.json",
];
/** @type {[string, string, string, string, string, string, string, string, string, string, string]} */
const includedUntrackedPaths = [
  "contracts/zod/asvs-evidence-contracts.mjs",
  "contracts/zod/baseline-contracts.mjs",
  "docs/security/threat-model.json",
  "eslint.config.mjs",
  "scripts/baseline_capture_io.py",
  "scripts/baseline_replay.py",
  "tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  "tests/contracts/zod_baseline_contracts.test.mjs",
  "tests/property/test_asvs_evidence.py",
  "tests/unit/test_build_asvs_matrix.py",
  "tsconfig.contracts.json",
];
/** @type {readonly string[]} */
const taskTwoUntrackedPaths = [
  "contracts/zod/asvs-evidence-contracts.mjs",
  "docs/security/threat-model.json",
  "tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  "tests/property/test_asvs_evidence.py",
  "tests/unit/test_build_asvs_matrix.py",
];

/**
 * @param {BaselineFileName} name
 * @returns {Promise<Buffer>}
 */
async function loadRaw(name) {
  return readFile(new URL(`contracts/baseline/${name}`, root));
}

/**
 * @param {string} source
 * @returns {unknown}
 */
function parseJsonUnknown(source) {
  /** @type {unknown} */
  const decoded = JSON.parse(source);
  return decoded;
}

/**
 * @overload
 * @param {FixtureName} name
 * @returns {Promise<MutableReplayFixture>}
 */
/**
 * @overload
 * @param {"manifest.json"} name
 * @returns {Promise<MutableManifest>}
 */
/**
 * @overload
 * @param {"tool-catalog.json"} name
 * @returns {Promise<MutableCatalog>}
 */
/**
 * @param {BaselineFileName} name
 * @returns {Promise<MutableReplayFixture | MutableManifest | MutableCatalog>}
 */
async function load(name) {
  const decoded = parseJsonUnknown((await loadRaw(name)).toString("utf8"));
  if (name === "manifest.json") {
    return mutableManifestSchema.parse(decoded);
  }
  if (name === "tool-catalog.json") {
    return mutableCatalogSchema.parse(decoded);
  }
  return mutableReplayFixtureSchema.parse(decoded);
}

/** @returns {Promise<RawBundle>} */
async function loadRawBundle() {
  return {
    "manifest.json": await loadRaw("manifest.json"),
    "tool-catalog.json": await loadRaw("tool-catalog.json"),
    "resources.json": await loadRaw("resources.json"),
    "result-cases.json": await loadRaw("result-cases.json"),
    "error-cases.json": await loadRaw("error-cases.json"),
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
  function sortKeysDeep(item) {
    if (Array.isArray(item)) {
      return item.map(sortKeysDeep);
    }
    if (item !== null && typeof item === "object") {
      return Object.fromEntries(
        Object.entries(item)
          .sort(([left], [right]) => Buffer.compare(
            Buffer.from(left, "utf8"),
            Buffer.from(right, "utf8"),
          ))
          .map(([key, nested]) => [key, sortKeysDeep(nested)]),
      );
    }
    return item;
  }
  const encoded = JSON.stringify(sortKeysDeep(value));
  assert.notEqual(encoded, undefined);
  return Buffer.from(`${encoded}\n`, "utf8");
}

/**
 * @param {RawBundle} rawBundle
 * @param {Exclude<BaselineFileName, "manifest.json">} path
 * @returns {void}
 */
function redigestBundleEntry(rawBundle, path) {
  const manifest = mutableManifestSchema.parse(
    parseJsonUnknown(rawBundle["manifest.json"].toString("utf8")),
  );
  const entry = manifest.entries.find((candidate) => candidate.path === path);
  assert.ok(entry !== undefined);
  const raw = rawBundle[path];
  assert.ok(raw !== undefined);
  entry.sha256 = createHash("sha256").update(raw).digest("hex");
  rawBundle["manifest.json"] = canonicalBytes(manifest);
}

/**
 * @param {MutableReplayFixture} fixture
 * @param {string} caseId
 * @returns {MutableReplayRecord}
 */
function requireRecord(fixture, caseId) {
  const record = fixture[caseId];
  assert.ok(record !== undefined);
  return record;
}

/**
 * @param {unknown} value
 * @returns {value is MutableJsonObject}
 */
function isMutableJsonObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {unknown} value
 * @returns {value is unknown[]}
 */
function isMutableJsonArray(value) {
  return Array.isArray(value);
}

/**
 * @param {() => unknown} callback
 * @param {string} message
 * @returns {void}
 */
function assertExactError(callback, message) {
  assert.throws(callback, (error) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, message);
    return true;
  });
}

/**
 * @param {MutableReplayFixture} fixture
 * @returns {MutableReplayRecord}
 */
function firstRecord(fixture) {
  const record = Object.values(fixture)[0];
  assert.ok(record !== undefined);
  return structuredClone(record);
}

/**
 * @param {MutableReplayRecord} record
 * @returns {void}
 */
function redigestRequest(record) {
  record.request.body_sha256 = createHash("sha256")
    .update(Buffer.from(record.request.body_base64, "base64"))
    .digest("hex");
}

void test("Zod independently accepts every strict frozen replay record", async () => {
  let count = 0;
  for (const name of fixtureFileNames) {
    const raw = await readFile(new URL(`contracts/baseline/${name}`, root));
    const parsed = parseCanonicalBaselineContract(raw, baselineFixtureSchemas[name]);
    for (const record of Object.values(parsed)) {
      replayRecordSchema.parse(record);
      count += 1;
    }
  }
  assert.equal(count, 66);
});

void test("Zod strictObject parity rejects unknown fields at every replay level", async () => {
  const fixture = await load("result-cases.json");
  /** @type {readonly ["record", "setup", "request", "header", "expected"]} */
  const locations = ["record", "setup", "request", "header", "expected"];
  for (const location of locations) {
    const record = structuredClone(
      requireRecord(fixture, "protocol.tools-list.modern.success"),
    );
    const header = record.request.headers[0];
    assert.ok(header !== undefined);
    const target = {
      record,
      setup: record.setup,
      request: record.request,
      header,
      expected: record.expected,
    }[location];
    target["unexpected"] = true;
    assert.throws(() => replayRecordSchema.parse(record), { name: "ZodError" });
  }
});

void test("Zod binds exact request bytes, digest, headers, and profile", async () => {
  const fixture = await load("result-cases.json");
  const modern = structuredClone(
    requireRecord(fixture, "protocol.tools-list.modern.success"),
  );
  modern.request.body_sha256 = "0".repeat(64);
  assert.throws(() => replayRecordSchema.parse(modern), { name: "ZodError" });

  const changedFixture = structuredClone(fixture);
  const changedBody = requireRecord(
    changedFixture,
    "protocol.tools-list.modern.success",
  );
  changedBody.request.body_base64 = Buffer.from("{}", "utf8").toString("base64");
  redigestRequest(changedBody);
  assert.throws(
    () => baselineFixtureSchemas["result-cases.json"].parse(changedFixture),
    { name: "ZodError" },
  );

  const duplicateHeader = structuredClone(
    requireRecord(fixture, "protocol.tools-list.modern.success"),
  );
  duplicateHeader.request.headers.push({
    name: "mcp-protocol-version",
    value: "2026-07-28",
  });
  assert.throws(() => replayRecordSchema.parse(duplicateHeader), { name: "ZodError" });

  const wrongProfile = structuredClone(
    requireRecord(fixture, "protocol.tools-list.modern.success"),
  );
  wrongProfile.profile = "legacy";
  assert.throws(() => replayRecordSchema.parse(wrongProfile), { name: "ZodError" });
});

void test("Zod header length matches Pydantic Unicode code-point semantics", async () => {
  const fixture = await load("result-cases.json");
  const record = structuredClone(
    requireRecord(fixture, "protocol.tools-list.modern.success"),
  );
  const header = { name: "X-Unicode-Test", value: "" };
  record.request.headers.push(header);

  header.value = "😀".repeat(4096);
  replayRecordSchema.parse(record);

  header.value = "😀".repeat(4097);
  assert.throws(() => replayRecordSchema.parse(record), { name: "ZodError" });
});

void test("Zod fixture oracle rejects valid-shape profile, scenario, setup, header, and status drift", async () => {
  const source = await load("result-cases.json");
  /** @type {Array<(record: MutableReplayRecord) => void>} */
  const mutations = [
    (record) => { record.profile = "legacy"; },
    (record) => { record.scenario = "tool.success"; },
    (record) => {
      record.setup = {
        kind: "document",
        handle: "1234/560449",
        bitstream_id: "bs_public",
        artifact_id: "doc_379d908b524eceb9ab54a87b8347e11637efa642660c3d9d840438d8c5fd101f",
      };
    },
    (record) => {
      const header = record.request.headers[1];
      assert.ok(header !== undefined);
      header.value = "server/discover";
    },
    (record) => { record.expected.status = 201; },
  ];
  for (const mutate of mutations) {
    const fixture = structuredClone(source);
    mutate(requireRecord(fixture, "protocol.tools-list.modern.success"));
    assert.throws(
      () => baselineFixtureSchemas["result-cases.json"].parse(fixture),
      { name: "ZodError" },
    );
  }
});

void test("Zod rejects non-normalized or unsafe response numbers", async () => {
  const fixture = await load("result-cases.json");
  for (const value of [0.5, Number.MAX_SAFE_INTEGER + 1, Number.POSITIVE_INFINITY]) {
    const record = firstRecord(fixture);
    record.expected.payload = { invalid: value };
    assert.throws(() => replayRecordSchema.parse(record), { name: "ZodError" });
  }
  const record = firstRecord(fixture);
  record.expected.payload = { boolean: true, safe: Number.MAX_SAFE_INTEGER };
  replayRecordSchema.parse(record);
});

void test("Zod raw loader rejects nested duplicates and noncanonical or oversized bytes", async () => {
  const raw = await loadRaw("result-cases.json");
  const duplicate = Buffer.from(raw.toString("utf8").replace(
    '"expected":{',
    '"expected":{"status":200,',
  ), "utf8");
  assert.throws(
    () => parseCanonicalBaselineContract(
      duplicate,
      baselineFixtureSchemas["result-cases.json"],
    ),
    SyntaxError,
  );

  const pretty = Buffer.from(
    `${JSON.stringify(JSON.parse(raw.toString("utf8")), null, 2)}\n`,
    "utf8",
  );
  assert.throws(
    () => parseCanonicalBaselineContract(
      pretty,
      baselineFixtureSchemas["result-cases.json"],
    ),
    SyntaxError,
  );
  assert.throws(
    () => parseCanonicalBaselineContract(
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), raw]),
      baselineFixtureSchemas["result-cases.json"],
    ),
    SyntaxError,
  );
  assert.throws(
    () => parseCanonicalBaselineContract(
      Buffer.alloc(4_194_305, 0x20),
      baselineFixtureSchemas["result-cases.json"],
    ),
    RangeError,
  );
});

void test("raw baseline boundary accepts only valid UTF-8 bytes", async (t) => {
  const emptySchema = z.strictObject({});
  await t.test("accepts Buffer and Uint8Array", () => {
    assert.deepEqual(
      parseCanonicalBaselineContract(Buffer.from("{}\n", "utf8"), emptySchema),
      {},
    );
    assert.deepEqual(
      parseCanonicalBaselineContract(new Uint8Array(Buffer.from("{}\n")), emptySchema),
      {},
    );
  });
  await t.test("rejects a pre-decoded string", () => {
    assert.throws(
      () => parseCanonicalBaselineContract("{}\n", emptySchema),
      TypeError,
    );
  });
  /** @type {ReadonlyArray<readonly [string, readonly number[]]>} */
  const invalidByteSequences = [
    ["isolated continuation", [0x80]],
    ["truncated sequence", [0xe2, 0x82]],
    ["overlong encoding", [0xc0, 0xaf]],
    ["encoded surrogate", [0xed, 0xa0, 0x80]],
    ["above Unicode maximum", [0xf4, 0x90, 0x80, 0x80]],
  ];
  for (const [name, invalid] of invalidByteSequences) {
    await t.test(`rejects ${name}`, () => {
      const raw = Buffer.concat([
        Buffer.from('{"value":"', "ascii"),
        Buffer.from(invalid),
        Buffer.from('"}\n', "ascii"),
      ]);
      assert.throws(
        () => parseCanonicalBaselineContract(raw, z.strictObject({ value: z.string() })),
        SyntaxError,
      );
    });
  }
});

void test("raw baseline boundary rejects structural ambiguity without prototype pollution", async (t) => {
  await t.test("rejects an escaped lone surrogate", () => {
    assert.throws(
      () => parseCanonicalBaselineContract(
        Buffer.from('{"value":"\\ud800"}\n', "ascii"),
        z.strictObject({ value: z.string() }),
      ),
      SyntaxError,
    );
  });
  await t.test("rejects depth 65", () => {
    const raw = Buffer.from(`${"[".repeat(65)}0${"]".repeat(65)}\n`, "ascii");
    assert.throws(
      () => parseCanonicalBaselineContract(raw, z.unknown()),
      SyntaxError,
    );
  });
  await t.test("rejects escaped-equivalent duplicate keys", () => {
    assert.throws(
      () => parseCanonicalBaselineContract(
        Buffer.from('{"a":1,"\\u0061":2}\n', "ascii"),
        z.record(z.string(), z.number()),
      ),
      SyntaxError,
    );
  });
  await t.test("keeps __proto__ as inert data on null-prototype objects", () => {
    /** @type {z.ZodType<MutableJsonObject>} */
    const nullPrototypeObjectSchema = z.custom(
      (value) => isMutableJsonObject(value) && Object.getPrototypeOf(value) === null,
    );
    const parsed = parseCanonicalBaselineContract(
      Buffer.from('{"__proto__":{"polluted":true}}\n', "ascii"),
      nullPrototypeObjectSchema,
    );
    assert.equal(Object.getPrototypeOf(parsed), null);
    assert.equal(Object.hasOwn(parsed, "__proto__"), true);
    const prototypeData = parsed["__proto__"];
    assert.ok(isMutableJsonObject(prototypeData));
    assert.equal(Object.getPrototypeOf(prototypeData), null);
    assert.equal(prototypeData["polluted"], true);
    assert.equal(Reflect.get(Object.prototype, "polluted"), undefined);
  });
});

void test("complete payload oracle rejects a forged field in every one of 66 cases", async (t) => {
  let count = 0;
  for (const name of fixtureFileNames) {
    const source = await load(name);
    for (const caseId of Object.keys(source).sort()) {
      await t.test(caseId, () => {
        const fixture = structuredClone(source);
        const record = requireRecord(fixture, caseId);
        const payload = record.expected.payload;
        assert.ok(payload !== null);
        payload["__forged"] = "schema-valid mutation";
        assert.throws(
          () => baselineFixtureSchemas[name].parse(fixture),
          { name: "ZodError" },
        );
      });
      count += 1;
    }
  }
  assert.equal(count, 66);
});

void test("complete payload oracle rejects empty, nested, swapped, and ID drift", async (t) => {
  const source = await load("result-cases.json");
  const caseId = "protocol.tools-list.modern.success";
  /** @type {Record<string, (payload: MutableJsonObject, record: MutableReplayRecord) => void>} */
  const mutations = {
    "empty result": (payload) => { payload["result"] = {}; },
    "nested description": (payload) => {
      const result = payload["result"];
      assert.ok(isMutableJsonObject(result));
      const tools = result["tools"];
      assert.ok(isMutableJsonArray(tools));
      const firstTool = tools[0];
      assert.ok(isMutableJsonObject(firstTool));
      const description = z.string().parse(firstTool["description"]);
      firstTool["description"] = `${description} forged`;
    },
    "swapped payload": (_payload, record) => {
      record.expected.payload = structuredClone(
        requireRecord(source, "protocol.tools-list.legacy.success").expected.payload,
      );
    },
    "response ID": (payload) => { payload["id"] = `${caseId}.forged`; },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    await t.test(name, () => {
      const fixture = structuredClone(source);
      const record = requireRecord(fixture, caseId);
      const payload = record.expected.payload;
      assert.ok(payload !== null);
      mutate(payload, record);
      assert.throws(
        () => baselineFixtureSchemas["result-cases.json"].parse(fixture),
        { name: "ZodError" },
      );
    });
  }
});

void test("strict Zod schemas accept the canonical manifest and tool catalog", async () => {
  const manifest = await load("manifest.json");
  const catalog = await load("tool-catalog.json");
  baselineContracts.baselineManifestSchema.parse(manifest);
  baselineContracts.toolCatalogSchema.parse(catalog);

  manifest.input["unexpected"] = true;
  const searchDocuments = catalog["search_documents"];
  assert.ok(searchDocuments !== undefined);
  searchDocuments.annotations["unexpected"] = true;
  assert.throws(
    () => baselineContracts.baselineManifestSchema.parse(manifest),
    { name: "ZodError" },
  );
  assert.throws(
    () => baselineContracts.toolCatalogSchema.parse(catalog),
    { name: "ZodError" },
  );
});

void test("committed manifest Zod schema is strict and has no self-hash field", async () => {
  const historical = await load("manifest.json");
  const manifest = {
    schema_version: 4,
    capture_mode: "committed-candidate-attestation",
    candidate: {
      commit: "1".repeat(40),
      tree: "2".repeat(40),
      src_tree: "3".repeat(40),
    },
    historical_provenance: {
      path: "historical-manifest-v3.json",
      schema_version: 3,
      sha256: "4".repeat(64),
    },
    attestation: {
      scheme: "current-head-single-parent-manifest-delta-v1",
      allowed_paths: [
        "contracts/baseline/manifest.json",
        "contracts/baseline/historical-manifest-v3.json",
      ],
    },
    canonicalization: historical["canonicalization"],
    response_canonicalization: historical["response_canonicalization"],
    entries: historical.entries,
    required_tool_names: historical["required_tool_names"],
    required_case_ids: historical.required_case_ids,
  };

  baselineContracts.committedBaselineManifestSchema.parse(manifest);
  assert.throws(
    () => baselineContracts.committedBaselineManifestSchema.parse({
      ...manifest,
      attestation_commit: "5".repeat(40),
    }),
    { name: "ZodError" },
  );
  assert.throws(
    () => baselineContracts.committedBaselineManifestSchema.parse({
      ...manifest,
      required_case_ids: [...manifest.required_case_ids].reverse(),
    }),
    { name: "ZodError" },
  );
});

void test("manifest Zod schema requires the reviewed v3 index transition", async () => {
  const manifest = await load("manifest.json");
  manifest["schema_version"] = 3;
  manifest.input.included_untracked_paths = structuredClone(includedUntrackedPaths);
  const generator = manifest["generator"];
  assert.ok(isMutableJsonObject(generator));
  generator["version"] = "3";
  manifest["index_transition"] = {
    transition_id: "phase-1-reviewed-index-transition-v1",
    imported_index_tree: "6cb461d986c21e4cb2852a07b06f75812ec27bbb",
    imported_staged_entries_sha256: "fcfe06d851c83040d860f9f887efe18bde9dbe46c4eeb1aaa3f68b3af8f3ccaf",
    candidate_index_tree: "55691718dade75b44a8ed025fcf48dabf87a7969",
    candidate_staged_entries_sha256: "9426ba909728d29d2009607264a9ffb1c028c4c645bbacd72f98867132e24f68",
  };

  baselineContracts.baselineManifestSchema.parse(manifest);

  const missing = structuredClone(manifest);
  const missingTransition = missing["index_transition"];
  assert.ok(isMutableJsonObject(missingTransition));
  delete missingTransition["candidate_index_tree"];
  const extra = structuredClone(manifest);
  const extraTransition = extra["index_transition"];
  assert.ok(isMutableJsonObject(extraTransition));
  extraTransition["unexpected"] = true;
  const malformed = structuredClone(manifest);
  const malformedTransition = malformed["index_transition"];
  assert.ok(isMutableJsonObject(malformedTransition));
  malformedTransition["candidate_staged_entries_sha256"] = "not-a-digest";
  const mismatch = structuredClone(manifest);
  const mismatchRecovery = mismatch["recovery"];
  assert.ok(isMutableJsonObject(mismatchRecovery));
  mismatchRecovery["imported_index_tree"] = "0".repeat(40);

  for (const candidate of [missing, extra, malformed, mismatch]) {
    assert.throws(
      () => baselineContracts.baselineManifestSchema.parse(candidate),
      { name: "ZodError" },
    );
  }
});

void test("manifest Zod schema requires the exact reviewed untracked path tuple", async () => {
  const manifest = await load("manifest.json");
  manifest.input.included_untracked_paths = structuredClone(includedUntrackedPaths);

  const parsed = baselineContracts.baselineManifestSchema.parse(manifest);

  assert.deepEqual(parsed.input.included_untracked_paths, includedUntrackedPaths);
  /** @type {string[][]} */
  const invalid = [
    [],
    includedUntrackedPaths.slice(0, 1),
    [...includedUntrackedPaths].reverse(),
    [includedUntrackedPaths[0], includedUntrackedPaths[0]],
    [...includedUntrackedPaths, "unrelated.txt"],
    ...taskTwoUntrackedPaths.map((omitted) => (
      includedUntrackedPaths.filter((path) => path !== omitted)
    )),
  ];
  for (const paths of invalid) {
    const candidate = structuredClone(manifest);
    candidate.input.included_untracked_paths = paths;
    assert.throws(
      () => baselineContracts.baselineManifestSchema.parse(candidate),
      { name: "ZodError" },
    );
  }
});

void test("five-file bundle validator accepts the exact frozen baseline", async () => {
  const parsed = baselineContracts.parseCanonicalBaselineSet(await loadRawBundle());
  assert.equal(Object.keys(parsed.cases).length, 66);
  assert.deepEqual(Object.keys(parsed.catalog).sort(), [
    "download_document_file",
    "get_document_metadata",
    "get_render_manifest",
    "inspect_pdf",
    "list_document_files",
    "render_pdf_page_tiles",
    "render_pdf_pages",
    "search_documents",
  ]);
});

void test("five-file bundle rejects redigested semantic mutations", async (t) => {
  assert.equal(typeof baselineContracts.parseCanonicalBaselineSet, "function");
  /** @type {Record<string, (fixture: MutableReplayFixture) => void>} */
  const mutations = {
    "forged payload field": (fixture) => {
      const payload = requireRecord(
        fixture,
        "protocol.tools-list.modern.success",
      ).expected.payload;
      assert.ok(payload !== null);
      payload["forged"] = true;
    },
    "empty result": (fixture) => {
      const payload = requireRecord(
        fixture,
        "protocol.tools-list.modern.success",
      ).expected.payload;
      assert.ok(payload !== null);
      payload["result"] = {};
    },
    "nested payload": (fixture) => {
      const payload = requireRecord(
        fixture,
        "protocol.tools-list.modern.success",
      ).expected.payload;
      assert.ok(payload !== null);
      const result = payload["result"];
      assert.ok(isMutableJsonObject(result));
      const tools = result["tools"];
      assert.ok(isMutableJsonArray(tools));
      const firstTool = tools[0];
      assert.ok(isMutableJsonObject(firstTool));
      const description = z.string().parse(firstTool["description"]);
      firstTool["description"] = `${description} forged`;
    },
    "swapped payload": (fixture) => {
      requireRecord(
        fixture,
        "protocol.tools-list.modern.success",
      ).expected.payload = structuredClone(requireRecord(
        fixture,
        "protocol.tools-list.legacy.success",
      ).expected.payload);
    },
    "nested status": (fixture) => {
      requireRecord(
        fixture,
        "protocol.tools-list.modern.success",
      ).expected.status = 201;
    },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    await t.test(name, async () => {
      const rawBundle = await loadRawBundle();
      const fixture = mutableReplayFixtureSchema.parse(parseJsonUnknown(
        rawBundle["result-cases.json"].toString("utf8"),
      ));
      mutate(fixture);
      rawBundle["result-cases.json"] = canonicalBytes(fixture);
      redigestBundleEntry(rawBundle, "result-cases.json");
      assert.throws(() => baselineContracts.parseCanonicalBaselineSet(rawBundle));
    });
  }
});

void test("five-file bundle rejects manifest, allocation, digest, and catalog drift", async (t) => {
  assert.equal(typeof baselineContracts.parseCanonicalBaselineSet, "function");
  /** @type {Record<string, (bundle: RawBundle) => void>} */
  const mutations = {
    "missing file": (bundle) => { delete bundle["resources.json"]; },
    "extra file": (bundle) => { bundle["extra.json"] = Buffer.from("{}\n"); },
    "digest mismatch": (bundle) => {
      const catalog = mutableCatalogSchema.parse(parseJsonUnknown(
        bundle["tool-catalog.json"].toString("utf8"),
      ));
      const searchDocuments = catalog["search_documents"];
      assert.ok(searchDocuments !== undefined);
      searchDocuments.title += " forged without redigest";
      bundle["tool-catalog.json"] = canonicalBytes(catalog);
    },
    "case moved between files": (bundle) => {
      const results = mutableReplayFixtureSchema.parse(parseJsonUnknown(
        bundle["result-cases.json"].toString("utf8"),
      ));
      const errors = mutableReplayFixtureSchema.parse(parseJsonUnknown(
        bundle["error-cases.json"].toString("utf8"),
      ));
      errors["protocol.initialize.legacy.success"] = results[
        "protocol.initialize.legacy.success"
      ] ?? assert.fail("required result case is absent");
      delete results["protocol.initialize.legacy.success"];
      bundle["result-cases.json"] = canonicalBytes(results);
      bundle["error-cases.json"] = canonicalBytes(errors);
      redigestBundleEntry(bundle, "result-cases.json");
      redigestBundleEntry(bundle, "error-cases.json");
    },
    "manifest case ID": (bundle) => {
      const manifest = mutableManifestSchema.parse(parseJsonUnknown(
        bundle["manifest.json"].toString("utf8"),
      ));
      manifest.required_case_ids[0] = "forged.case";
      bundle["manifest.json"] = canonicalBytes(manifest);
    },
    "manifest tree drift": (bundle) => {
      const manifest = mutableManifestSchema.parse(parseJsonUnknown(
        bundle["manifest.json"].toString("utf8"),
      ));
      manifest.input.tree_after = "0".repeat(40);
      bundle["manifest.json"] = canonicalBytes(manifest);
    },
    "catalog redigested": (bundle) => {
      const catalog = mutableCatalogSchema.parse(parseJsonUnknown(
        bundle["tool-catalog.json"].toString("utf8"),
      ));
      const searchDocuments = catalog["search_documents"];
      assert.ok(searchDocuments !== undefined);
      searchDocuments.title += " forged";
      bundle["tool-catalog.json"] = canonicalBytes(catalog);
      redigestBundleEntry(bundle, "tool-catalog.json");
    },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    await t.test(name, async () => {
      const rawBundle = await loadRawBundle();
      mutate(rawBundle);
      if (name === "digest mismatch") {
        assertExactError(
          () => baselineContracts.parseCanonicalBaselineSet(rawBundle),
          "baseline manifest digest mismatch for tool-catalog.json",
        );
      } else if (name === "catalog redigested") {
        assertExactError(
          () => baselineContracts.parseCanonicalBaselineSet(rawBundle),
          "tool catalog disagrees with protocol.tools-list.legacy.success",
        );
      } else {
        assert.throws(() => baselineContracts.parseCanonicalBaselineSet(rawBundle));
      }
    });
  }
});

void test("package scripts preserve capability and baseline Zod entrypoints", async () => {
  const packageJson = packageJsonSchema.parse(parseJsonUnknown(
    await readFile(new URL("package.json", root), "utf8"),
  ));
  assert.equal(
    packageJson.scripts["contracts:zod"],
    "node --test tests/contracts/zod_contracts.test.mjs",
  );
  assert.equal(
    packageJson.scripts["contracts:baseline-zod"],
    "node --test tests/contracts/zod_baseline_contracts.test.mjs",
  );
  assert.equal(
    packageJson.scripts["contracts:asvs-zod"],
    "node --test tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  );
  assert.equal(
    packageJson.scripts["contracts:recovery-zod"],
    "node --test tests/contracts/zod_recovery_contracts.test.mjs",
  );
  assert.equal(
    packageJson.scripts["contracts:zod:all"],
    "npm run contracts:zod && npm run contracts:baseline-zod && npm run contracts:asvs-zod && npm run contracts:recovery-zod",
  );
  assert.equal(
    packageJson.scripts["contracts:lint"],
    "eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs contracts/zod/models.ts contracts/zod/contract.test.ts tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
  );
  assert.equal(
    packageJson.scripts["contracts:typecheck"],
    "tsc --project tsconfig.contracts.json",
  );
  assert.equal(
    packageJson.scripts["contracts:test"],
    "node --test contracts/zod/contract.test.ts && npm run contracts:zod:all",
  );
  assert.equal(
    packageJson.scripts["docs:lint"],
    "markdownlint-cli2 \"*.md\" \"docs/**/*.md\" \"deploy/**/*.md\" \"skills/**/*.md\" \"src/nplg_mcp/agent_skills/georgian-newspaper-visual-analysis/SKILL.md\"",
  );
  assert.equal(
    packageJson.scripts["contracts:baseline-static"],
    "tsc --project tsconfig.contracts.json && eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
  );
  assert.equal(
    packageJson.scripts["test:contracts:asvs"],
    "node --test tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  );
  assert.equal(
    packageJson.scripts["typecheck:contracts"],
    "tsc --project tsconfig.contracts.json",
  );
  assert.equal(
    packageJson.scripts["lint:contracts"],
    "eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
  );
});

void test("package policy model rejects missing or weakened static commands", () => {
  /** @type {Record<string, string>} */
  const exactScripts = {
    "contracts:zod": "node --test tests/contracts/zod_contracts.test.mjs",
    "contracts:baseline-zod":
      "node --test tests/contracts/zod_baseline_contracts.test.mjs",
    "contracts:asvs-zod":
      "node --test tests/contracts/zod_asvs_evidence_contracts.test.mjs",
    "contracts:recovery-zod":
      "node --test tests/contracts/zod_recovery_contracts.test.mjs",
    "contracts:zod:all":
      "npm run contracts:zod && npm run contracts:baseline-zod && npm run contracts:asvs-zod && npm run contracts:recovery-zod",
    "contracts:lint":
      "eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs contracts/zod/models.ts contracts/zod/contract.test.ts tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
    "contracts:typecheck": "tsc --project tsconfig.contracts.json",
    "contracts:test":
      "node --test contracts/zod/contract.test.ts && npm run contracts:zod:all",
    "docs:lint":
      "markdownlint-cli2 \"*.md\" \"docs/**/*.md\" \"deploy/**/*.md\" \"skills/**/*.md\" \"src/nplg_mcp/agent_skills/georgian-newspaper-visual-analysis/SKILL.md\"",
    "contracts:baseline-static":
      "tsc --project tsconfig.contracts.json && eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
    "test:contracts:asvs":
      "node --test tests/contracts/zod_asvs_evidence_contracts.test.mjs",
    "typecheck:contracts": "tsc --project tsconfig.contracts.json",
    "lint:contracts":
      "eslint --max-warnings 0 contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
  };
  const missingStatic = { ...exactScripts };
  delete missingStatic["contracts:baseline-static"];
  const weakenedStatic = {
    ...exactScripts,
    "contracts:baseline-static":
      "tsc --project tsconfig.contracts.json && eslint contracts/zod/baseline-contracts.mjs contracts/zod/asvs-evidence-contracts.mjs contracts/zod/capability-contracts.mjs contracts/zod/recovery-contracts.mjs tests/contracts/zod_baseline_contracts.test.mjs tests/contracts/zod_asvs_evidence_contracts.test.mjs tests/contracts/zod_contracts.test.mjs tests/contracts/zod_recovery_contracts.test.mjs",
  };
  const incompleteAggregate = {
    ...exactScripts,
    "contracts:zod:all": "npm run contracts:baseline-zod",
  };

  for (const scripts of [missingStatic, weakenedStatic, incompleteAggregate]) {
    assert.throws(() => packageJsonSchema.parse({ scripts }));
  }
  for (
    const scriptName of [
      "contracts:lint",
      "contracts:typecheck",
      "contracts:test",
      "contracts:recovery-zod",
      "docs:lint",
      "test:contracts:asvs",
      "typecheck:contracts",
      "lint:contracts",
    ]
  ) {
    const missingTaskTwoEntrypoint = Object.fromEntries(
      Object.entries(exactScripts).filter(([key]) => key !== scriptName),
    );
    assert.throws(
      () => packageJsonSchema.parse({ scripts: missingTaskTwoEntrypoint }),
    );
  }
});

void test("configured ESLint rejects forbidden type escapes in every contract file", async (t) => {
  const lintEngine = new ESLint({ cwd: rootPath });
  /** @type {ReadonlyArray<readonly [string, string, string]>} */
  const mutants = [
    [
      "described @ts-expect-error",
      "/** @type {number} */\n// @ts-expect-error: intentionally hidden invalid assignment\nexport const hiddenNumber = \"not-a-number\";\n",
      "@typescript-eslint/ban-ts-comment",
    ],
    [
      "JSDoc any",
      "/** @type {any} */\nexport const hiddenAny = 1;\n",
      "task1/no-jsdoc-any",
    ],
    [
      "JSDoc all type",
      "/** @type {*} */\nexport const hiddenAllType = 1;\n",
      "task1/no-jsdoc-any",
    ],
    [
      "JSDoc unknown type escape",
      "/** @type {?} */\nexport const hiddenUnknownType = 1;\n",
      "task1/no-jsdoc-any",
    ],
  ];
  for (const filePath of contractFilePaths) {
    for (const [name, source, expectedRule] of mutants) {
      await t.test(`${filePath} rejects ${name}`, async () => {
        const results = await lintEngine.lintText(source, { filePath });
        const result = results[0];
        assert.ok(result !== undefined);
        assert.deepEqual(
          result.messages.map(({ ruleId }) => ruleId),
          [expectedRule],
        );
      });
    }
  }
});

void test("configured TypeScript ESLint rejects adversarial type escapes", async (t) => {
  const lintEngine = new ESLint({ cwd: rootPath });
  const filePath = "contracts/zod/models.ts";
  /** @type {ReadonlyArray<readonly [string, string, string]>} */
  const mutants = [
    [
      "explicit any",
      "export const escaped: any = 1;\n",
      "@typescript-eslint/no-explicit-any",
    ],
    [
      "unsafe assertion",
      "const value: unknown = {};\nexport const asserted = value as { readonly text: string };\n",
      "@typescript-eslint/no-unsafe-type-assertion",
    ],
    [
      "double unknown assertion",
      "export const asserted = 1 as unknown as string;\n",
      "@typescript-eslint/no-unsafe-type-assertion",
    ],
    [
      "unchecked JSON parse",
      "export const parsed: string = JSON.parse(\"{}\");\n",
      "@typescript-eslint/no-unsafe-assignment",
    ],
    [
      "non-exhaustive discriminated union",
      "type Value = { readonly kind: \"left\" } | { readonly kind: \"right\" };\nexport function select(value: Value): number {\n  switch (value.kind) {\n    case \"left\": return 1;\n  }\n}\n",
      "@typescript-eslint/switch-exhaustiveness-check",
    ],
  ];
  for (const [name, source, expectedRule] of mutants) {
    await t.test(name, async () => {
      const results = await lintEngine.lintText(source, { filePath });
      const result = results[0];
      assert.ok(result !== undefined);
      assert.ok(
        result.messages.some(({ ruleId }) => ruleId === expectedRule),
        `${name} did not trigger ${expectedRule}: ${JSON.stringify(result.messages)}`,
      );
    });
  }
});

void test("configured ESLint forbids native Zod string length semantics", async (t) => {
  // Mutation caught: omit the JavaScript ASVS oracle from the length-policy file filter.
  const lintEngine = new ESLint({ cwd: rootPath });
  const discoveredTypeScriptSources = (await readdir(join(rootPath, "contracts/zod")))
    .filter((name) => name.endsWith(".ts"))
    .map((name) => `contracts/zod/${name}`)
    .sort();
  assert.deepEqual(discoveredTypeScriptSources, zodLengthGovernedFilePaths.slice(1));
  for (const filePath of zodLengthGovernedFilePaths) {
    for (const method of ["min", "max", "length"]) {
      await t.test(`${filePath} ${method}`, async () => {
        const results = await lintEngine.lintText(
          `import { z } from "zod";\nexport const invalid = z.string().${method}(1);\n`,
          { filePath },
        );
        const result = results[0];
        assert.ok(result !== undefined);
        assert.ok(
          result.messages.some(
            ({ ruleId }) => ruleId === "task1/no-native-zod-string-length",
          ),
          `${filePath} ${method} did not trigger the native Zod length policy: ${JSON.stringify(result.messages)}`,
        );
      });
    }
  }
});

void test("configured ESLint rejects native Zod check factories and bound string methods", async (t) => {
  const lintEngine = new ESLint({ cwd: rootPath });
  const filePath = "contracts/zod/asvs-evidence-contracts.mjs";
  /** @type {ReadonlyArray<readonly [string, string]>} */
  const mutants = [
    [
      "direct native ZodString min call",
      'import { z } from "zod";\nexport const s = z.string().min(1);\n',
    ],
    [
      "direct native ZodString max call",
      'import { z } from "zod";\nexport const s = z.string().max(1);\n',
    ],
    [
      "direct native ZodString length call",
      'import { z } from "zod";\nexport const s = z.string().length(1);\n',
    ],
    [
      "namespace minLength check factory",
      'import { z } from "zod";\nexport const s = z.string().check(z.minLength(1));\n',
    ],
    [
      "namespace maxLength check factory",
      'import { z } from "zod";\nexport const s = z.string().check(z.maxLength(1));\n',
    ],
    [
      "namespace exact length check factory",
      'import { z } from "zod";\nexport const s = z.string().check(z.length(1));\n',
    ],
    [
      "direct named maxLength check factory",
      'import { maxLength, z } from "zod";\nexport const s = z.string().check(maxLength(1));\n',
    ],
    [
      "aliased named maxLength check factory",
      'import { maxLength as nativeMax, z } from "zod";\nexport const s = z.string().check(nativeMax(1));\n',
    ],
    [
      "destructured factory through namespace and API aliases",
      'import * as Zod from "zod";\nconst ZodAlias = Zod;\nconst { z: api } = ZodAlias;\nconst { length: nativeLength } = api;\nexport const s = api.string().check(nativeLength(1));\n',
    ],
    [
      "bound native ZodString max method",
      'import { z } from "zod";\nconst schema = z.string();\nexport const s = schema.max.bind(schema)(1);\n',
    ],
    [
      "deferred bound native ZodString max method",
      'import { z } from "zod";\nconst schema = z.string();\nconst nativeMax = schema.max.bind(schema);\nexport const s = nativeMax(1);\n',
    ],
    [
      "native ZodString max via call",
      'import { z } from "zod";\nconst schema = z.string();\nexport const s = schema.max.call(schema, 1);\n',
    ],
    [
      "native ZodString max via apply",
      'import { z } from "zod";\nconst schema = z.string();\nexport const s = schema.max.apply(schema, [1]);\n',
    ],
  ];

  for (const [name, source] of mutants) {
    await t.test(name, async () => {
      const results = await lintEngine.lintText(source, { filePath });
      const result = results[0];
      assert.ok(result !== undefined);
      const policyMessages = result.messages.filter(
        ({ ruleId }) => ruleId === "task1/no-native-zod-string-length",
      );
      assert.equal(
        policyMessages.length,
        1,
        `${name} must produce one native Zod length diagnostic: ${JSON.stringify(result.messages)}`,
      );
    });
  }
});

void test("configured ESLint permits non-string bounds and codePointString", async () => {
  const lintEngine = new ESLint({ cwd: rootPath });
  const results = await lintEngine.lintText(
    'import { z } from "zod";\n' +
      'function codePointString() { return z.string().superRefine(() => undefined); }\n' +
      'export const arrayBound = z.array(z.string()).max(1);\n' +
      'export const arrayCheckBound = z.array(z.string()).check(z.maxLength(1));\n' +
      'export const setBound = z.set(z.string()).min(1).max(2);\n' +
      'export const stringBound = codePointString();\n',
    { filePath: "contracts/zod/asvs-evidence-contracts.mjs" },
  );
  const result = results[0];
  assert.ok(result !== undefined);
  assert.ok(
    result.messages.every(({ ruleId }) => ruleId !== "task1/no-native-zod-string-length"),
    JSON.stringify(result.messages),
  );
});

void test("configured ESLint permits non-type JSDoc text containing any", async (t) => {
  const lintEngine = new ESLint({ cwd: rootPath });
  /** @type {ReadonlyArray<readonly [string, string]>} */
  const allowedSources = [
    [
      "example object key",
      "/** @example const record = { any: 1 }; */\nexport const example = 1;\n",
    ],
    [
      "prose braces",
      "/** Returns {any}. */\nexport const prose = 1;\n",
    ],
  ];
  for (const filePath of contractFilePaths) {
    for (const [name, source] of allowedSources) {
      await t.test(`${filePath} permits ${name}`, async () => {
        const results = await lintEngine.lintText(source, { filePath });
        const result = results[0];
        assert.ok(result !== undefined);
        assert.deepEqual(result.messages, []);
      });
    }
  }
});

void test("resolved ESLint policy model rejects anti-disable downgrades", () => {
  const rules = { "task1/no-jsdoc-any": [2] };
  const missingOptions = { rules };
  const inlineConfigEnabled = {
    linterOptions: {
      noInlineConfig: false,
      reportUnusedDisableDirectives: 2,
    },
    rules,
  };
  const unusedDirectivesNotErrors = {
    linterOptions: {
      noInlineConfig: true,
      reportUnusedDisableDirectives: 0,
    },
    rules,
  };

  for (const mutant of [
    missingOptions,
    inlineConfigEnabled,
    unusedDirectivesNotErrors,
  ]) {
    assert.throws(() => resolvedEslintConfigSchema.parse(mutant));
  }
});

void test("configured ESLint defeats inline disables in every contract file", async (t) => {
  const source =
    "/* eslint-disable task1/no-jsdoc-any */\n" +
    "/** @type {any} */\n" +
    "export const hiddenAny = 1;\n";
  const liveEngine = new ESLint({ cwd: rootPath });
  const falseMutantEngine = new ESLint({
    cwd: rootPath,
    overrideConfig: {
      linterOptions: {
        noInlineConfig: false,
        reportUnusedDisableDirectives: "error",
      },
    },
  });
  for (const filePath of contractFilePaths) {
    await t.test(filePath, async () => {
      const liveResults = await liveEngine.lintText(source, { filePath });
      const liveResult = liveResults[0];
      assert.ok(liveResult !== undefined);
      assert.deepEqual(
        liveResult.messages.map(({ ruleId, severity }) => ({ ruleId, severity })),
        [
          { ruleId: null, severity: 1 },
          { ruleId: "task1/no-jsdoc-any", severity: 2 },
        ],
      );

      const falseMutantResults = await falseMutantEngine.lintText(source, {
        filePath,
      });
      const falseMutantResult = falseMutantResults[0];
      assert.ok(falseMutantResult !== undefined);
      assert.deepEqual(falseMutantResult.messages, []);
    });
  }
});

void test("resolved static configuration closes directive and side-effect escapes", async () => {
  const lintEngine = new ESLint({ cwd: rootPath });
  for (const filePath of contractFilePaths) {
    /** @type {unknown} */
    const rawResolved = await lintEngine.calculateConfigForFile(filePath);
    const resolved = resolvedEslintConfigSchema.parse(rawResolved);
    assert.deepEqual(resolved.linterOptions, {
      noInlineConfig: true,
      // ESLint's resolved API normalizes configured severity "error" to 2.
      reportUnusedDisableDirectives: 2,
    });
    assert.deepEqual(resolved.rules["@typescript-eslint/ban-ts-comment"], [
      2,
      {
        "ts-check": true,
        "ts-expect-error": true,
        "ts-ignore": true,
        "ts-nocheck": true,
      },
    ]);
    assert.deepEqual(resolved.rules["task1/no-jsdoc-any"], [2]);
  }

  const tscEntrypoint = fileURLToPath(
    new URL("../../node_modules/typescript/bin/tsc", import.meta.url),
  );
  const result = spawnSync(
    process.execPath,
    [tscEntrypoint, "--showConfig", "--project", "tsconfig.contracts.json"],
    {
      cwd: rootPath,
      encoding: "utf8",
      env: {
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
        NO_COLOR: "1",
      },
      shell: false,
      timeout: 5_000,
      maxBuffer: 1_048_576,
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.signal, null);
  assert.equal(result.error, undefined);
  const resolvedTsconfig = resolvedTsconfigSchema.parse(
    parseJsonUnknown(result.stdout),
  );
  assert.equal(
    resolvedTsconfig.compilerOptions.noUncheckedSideEffectImports,
    true,
  );
  assert.deepEqual(resolvedTsconfig.files, contractFilePaths.map((path) => `./${path}`));
});

void test("resolved TypeScript policy rejects emit and source-inventory mutants", () => {
  const compilerOptions = {
    module: "nodenext",
    moduleResolution: "nodenext",
    noEmit: true,
    verbatimModuleSyntax: true,
    noUncheckedSideEffectImports: true,
    forceConsistentCasingInFileNames: true,
    types: ["node"],
    strict: true,
    noUncheckedIndexedAccess: true,
    exactOptionalPropertyTypes: true,
    noImplicitOverride: true,
    noImplicitReturns: true,
    noFallthroughCasesInSwitch: true,
    noPropertyAccessFromIndexSignature: true,
    useUnknownInCatchVariables: true,
  };
  const files = contractFilePaths.map((path) => `./${path}`);

  assert.throws(() => resolvedTsconfigSchema.parse({
    compilerOptions: { ...compilerOptions, noEmit: false },
    files,
  }));
  assert.throws(() => resolvedTsconfigSchema.parse({
    compilerOptions,
    files: [...files, "./contracts/zod/unlisted.ts"],
  }));
});

void test("TypeScript negative fixtures fail at the configured compile boundary", async (t) => {
  const tscEntrypoint = fileURLToPath(
    new URL("../../node_modules/typescript/bin/tsc", import.meta.url),
  );
  /** @type {ReadonlyArray<readonly [string, Readonly<Record<string, string>>, RegExp]>} */
  const fixtures = [
    [
      "unresolved side-effect import",
      { "fixture.ts": "import \"./missing.js\";\nexport {};\n" },
      /Cannot find module/u,
    ],
    [
      "wrong-case path",
      {
        "fixture.ts": "import { value } from \"./Helper.js\";\nexport { value };\n",
        "helper.ts": "export const value = 1;\n",
      },
      /Cannot find module/u,
    ],
    [
      "ambient browser type",
      { "fixture.ts": "export const body = document.body;\n" },
      /Cannot find name 'document'/u,
    ],
  ];

  for (const [name, sources, expected] of fixtures) {
    await t.test(name, async (fixtureTest) => {
      const directory = await mkdtemp(join(tmpdir(), "nplg-task10-tsc-"));
      fixtureTest.after(async () => {
        await rm(directory, { force: true, recursive: true });
      });
      await writeFile(
        join(directory, "package.json"),
        '{"type":"module"}\n',
        "utf8",
      );
      for (const [path, source] of Object.entries(sources)) {
        await writeFile(join(directory, path), source, "utf8");
      }
      await writeFile(
        join(directory, "tsconfig.json"),
        `${JSON.stringify({
          compilerOptions: {
            forceConsistentCasingInFileNames: true,
            lib: ["ES2024"],
            module: "NodeNext",
            moduleResolution: "NodeNext",
            noEmit: true,
            noUncheckedSideEffectImports: true,
            strict: true,
            typeRoots: [join(rootPath, "node_modules/@types")],
            types: ["node"],
          },
          files: Object.keys(sources),
        }, null, 2)}\n`,
        "utf8",
      );
      const result = spawnSync(
        process.execPath,
        [tscEntrypoint, "--project", "tsconfig.json", "--pretty", "false"],
        {
          cwd: directory,
          encoding: "utf8",
          env: {
            LANG: "C.UTF-8",
            LC_ALL: "C.UTF-8",
            NO_COLOR: "1",
          },
          shell: false,
          timeout: 5_000,
          maxBuffer: 1_048_576,
        },
      );
      assert.notEqual(result.status, 0, `${name} unexpectedly compiled`);
      assert.equal(result.signal, null);
      assert.equal(result.error, undefined);
      assert.match(`${result.stdout}\n${result.stderr}`, expected);
    });
  }
});
