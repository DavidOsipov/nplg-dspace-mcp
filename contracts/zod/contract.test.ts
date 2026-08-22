// Copyright (c) 2026 David Osipov
/** Independent Zod runtime and schema-oracle tests. */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { z } from "zod";

import {
  codePointString,
  contractKeys,
  contractModels,
  exportZodSchemas,
  injectCodePointBoundsForTest,
  primitiveModels,
  utf8ByteString,
} from "./models.ts";
import type { ContractKey, JsonObject, JsonValue } from "./models.ts";

type CorpusKey = ContractKey | keyof typeof primitiveModels;

interface OracleResult {
  readonly requirement_id: string;
  readonly accepted: boolean;
  readonly normalized: JsonValue;
  readonly error_class: "invalid_json" | "validation_error" | null;
}

interface JsonBudget {
  nodes: number;
}

const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 100_000;

const corpusEntrySchema = z.strictObject({
  requirement_id: codePointString(1, 64),
  schema_key: z.enum([
    "input.ArtifactInput",
    "input.DownloadDocumentInput",
    "input.HandleInput",
    "input.RenderIdInput",
    "input.RenderPagesInput",
    "input.RenderTilesInput",
    "input.SearchDocumentsInput",
    "output.DocumentFilesOutput",
    "output.DocumentMetadataOutput",
    "output.DownloadDocumentOutput",
    "output.PdfInspectionOutput",
    "output.RenderManifestOutput",
    "output.RenderPagesOutput",
    "output.RenderTilesOutput",
    "output.SearchDocumentsOutput",
    "primitive.CodePoint2",
    "primitive.SafeInteger",
  ]),
  mode: z.enum(["input", "output"]),
  raw_json: utf8ByteString(1, 65_536),
  parsed: z.boolean(),
  value: z.unknown(),
  expected: z.enum(["accept", "reject"]),
  normalized: z.unknown(),
  error_class: codePointString(0, 128).nullable(),
  keyword: codePointString(1, 64),
});
const corpusSchema = z.strictObject({
  version: z.literal(1),
  entries: z.array(corpusEntrySchema).min(1).max(512),
}).superRefine((value, context) => {
  const identifiers = value.entries.map((entry) => entry.requirement_id);
  if (new Set(identifiers).size !== identifiers.length) {
    context.addIssue({ code: "custom", message: "corpus requirement IDs must be unique" });
  }
  for (const [index, entry] of value.entries.entries()) {
    const expectedMode = entry.schema_key.startsWith("output.") ? "output" : "input";
    if (entry.mode !== expectedMode) {
      context.addIssue({
        code: "custom",
        path: ["entries", index, "mode"],
        message: "corpus mode does not match its schema direction",
      });
    }
    const completeVerdict = entry.expected === "accept"
      ? entry.error_class === null
      : entry.error_class !== null && entry.error_class.length > 0 && entry.normalized === null;
    if (!completeVerdict) {
      context.addIssue({
        code: "custom",
        path: ["entries", index],
        message: "corpus verdict metadata is incomplete",
      });
    }
  }
});
type CorpusEntry = z.infer<typeof corpusEntrySchema>;

function strictJsonValue(
  value: unknown,
  depth = 0,
  budget: JsonBudget = { nodes: 0 },
): JsonValue {
  budget.nodes += 1;
  if (depth > MAX_JSON_DEPTH || budget.nodes > MAX_JSON_NODES) {
    throw new TypeError("oracle JSON structure exceeds its limits");
  }
  if (
    value === null
    || typeof value === "boolean"
    || typeof value === "string"
    || (typeof value === "number" && Number.isFinite(value))
  ) {
    return typeof value === "number" && Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => strictJsonValue(item, depth + 1, budget));
  }
  if (typeof value === "object") {
    const result: JsonObject = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = strictJsonValue(item, depth + 1, budget);
    }
    return result;
  }
  throw new TypeError("oracle value is not finite JSON");
}

function rejectDuplicateJsonKeys(source: string): void {
  let offset = 0;

  const skipWhitespace = (): void => {
    while (/\s/u.test(source.charAt(offset))) {
      offset += 1;
    }
  };

  const scanString = (): string => {
    const start = offset;
    offset += 1;
    while (offset < source.length) {
      const character = source.charAt(offset);
      offset += 1;
      if (character === "\\") {
        offset += 1;
      } else if (character === '"') {
        const decoded: unknown = JSON.parse(source.slice(start, offset));
        if (typeof decoded !== "string") {
          throw new SyntaxError("JSON key did not decode to a string");
        }
        return decoded;
      }
    }
    throw new SyntaxError("unterminated JSON string");
  };

  const scanValue = (): void => {
    skipWhitespace();
    const character = source.charAt(offset);
    if (character === '"') {
      scanString();
      return;
    }
    if (character === "{") {
      scanObject();
      return;
    }
    if (character === "[") {
      offset += 1;
      skipWhitespace();
      while (source.charAt(offset) !== "]") {
        scanValue();
        skipWhitespace();
        if (source.charAt(offset) === ",") {
          offset += 1;
          continue;
        }
        break;
      }
      offset += 1;
      return;
    }
    while (offset < source.length && !/[\s,}\]]/u.test(source.charAt(offset))) {
      offset += 1;
    }
  };

  const scanObject = (): void => {
    const keys = new Set<string>();
    offset += 1;
    skipWhitespace();
    while (source.charAt(offset) !== "}") {
      const key = scanString();
      if (keys.has(key)) {
        throw new SyntaxError("duplicate JSON key");
      }
      keys.add(key);
      skipWhitespace();
      offset += 1;
      scanValue();
      skipWhitespace();
      if (source.charAt(offset) === ",") {
        offset += 1;
        skipWhitespace();
        continue;
      }
      break;
    }
    offset += 1;
  };

  scanValue();
}

function parseRaw(raw: string): { readonly ok: true; readonly value: JsonValue } | { readonly ok: false } {
  try {
    const decoded: unknown = JSON.parse(raw);
    rejectDuplicateJsonKeys(raw);
    return { ok: true, value: strictJsonValue(decoded) };
  } catch {
    return { ok: false };
  }
}

function schemaFor(key: CorpusKey): z.ZodType {
  if (key === "primitive.CodePoint2" || key === "primitive.SafeInteger") {
    return primitiveModels[key];
  }
  return contractModels[key];
}

function runEntry(entry: CorpusEntry): OracleResult {
  const raw = parseRaw(entry.raw_json);
  if (!raw.ok) {
    if (entry.parsed) {
      throw new TypeError("corpus parsed flag disagrees with raw JSON");
    }
    return {
      requirement_id: entry.requirement_id,
      accepted: false,
      normalized: null,
      error_class: "invalid_json",
    };
  }
  if (!entry.parsed) {
    throw new TypeError("corpus expected invalid JSON but decoding succeeded");
  }
  assert.deepEqual(raw.value, strictJsonValue(entry.value));
  const result = schemaFor(entry.schema_key).safeParse(raw.value);
  if (!result.success) {
    return {
      requirement_id: entry.requirement_id,
      accepted: false,
      normalized: null,
      error_class: "validation_error",
    };
  }
  return {
    requirement_id: entry.requirement_id,
    accepted: true,
    normalized: strictJsonValue(result.data),
    error_class: null,
  };
}

async function loadCorpus(): Promise<z.infer<typeof corpusSchema>> {
  const raw = await readFile(new URL("../tool-contracts.corpus.json", import.meta.url), "utf8");
  const decoded: unknown = JSON.parse(raw);
  return corpusSchema.parse(decoded);
}

async function oracleDocument(): Promise<JsonObject> {
  const corpus = await loadCorpus();
  return {
    protocol_version: 1,
    zod_version: `${String(z.core.version.major)}.${String(z.core.version.minor)}.${String(z.core.version.patch)}`,
    schemas: strictJsonValue(exportZodSchemas()),
    results: corpus.entries.map((entry) => strictJsonValue(runEntry(entry))),
  };
}

const oracleMode = process.argv.includes("--oracle");

if (!oracleMode) {
  void test("contract model inventory is exact and closed", () => {
  assert.deepEqual(Object.keys(contractModels), contractKeys);
  assert.throws(() => contractModels["input.HandleInput"].parse({
    handle: "1234/560449",
    unexpected: true,
  }));
  });

  void test("codePointString measures Unicode code points", () => {
  const schema = codePointString(1, 2);
  assert.equal(schema.parse("😀😀"), "😀😀");
  assert.throws(() => schema.parse("😀😀😀"));
  assert.throws(() => codePointString(2, 1));
  });

  void test("utf8ByteString measures serialized bytes rather than UTF-16 units", () => {
  const schema = utf8ByteString(1, 4);
  assert.equal(schema.parse("😀"), "😀");
  assert.equal(schema.parse("éé"), "éé");
  assert.throws(() => schema.parse("😀a"));
  assert.throws(() => utf8ByteString(2, 1));
  });

  void test("exported Zod schemas include registered code-point bounds", () => {
  const schemas = exportZodSchemas();
  const query = schemas["input.SearchDocumentsInput"]["properties"];
  assert.notEqual(query, undefined);
  assert.match(JSON.stringify(query), /"minLength":1/);
  assert.match(JSON.stringify(query), /"maxLength":500/);
  });

  void test("closed code-point injection rejects pointer and keyword drift", () => {
    const pointer = "/properties/value";
    const fresh = (): JsonObject => ({
      properties: { value: { type: "string" } },
    });
    const document = fresh();
    injectCodePointBoundsForTest(document, [{ pointer, minimum: 1, maximum: 2 }]);
    assert.deepEqual(document["properties"], {
      value: { type: "string", minLength: 1, maxLength: 2 },
    });
    assert.throws(() => {
      injectCodePointBoundsForTest(fresh(), [
        { pointer, minimum: 1, maximum: 2 },
        { pointer, minimum: 1, maximum: 2 },
      ]);
    }, /duplicate/u);
    assert.throws(() => {
      injectCodePointBoundsForTest(fresh(), [
        { pointer: "/properties/missing", minimum: 1, maximum: 2 },
      ]);
    }, /unknown/u);
    assert.throws(() => {
      injectCodePointBoundsForTest({
        properties: { value: { type: "string", minLength: 1 } },
      }, [{ pointer, minimum: 1, maximum: 2 }]);
    }, /conflict/u);
  });

  void test("every root Zod object rejects an extra and a missing required field", async () => {
    const corpus = await loadCorpus();
    const schemas = exportZodSchemas();
    for (const key of contractKeys) {
      const sentinel = corpus.entries.find((entry) => (
        entry.schema_key === key && entry.expected === "accept"
      ));
      assert.notEqual(sentinel, undefined, key);
      assert.ok(sentinel !== undefined);
      const value = strictJsonValue(sentinel.value);
      assert.ok(value !== null && !Array.isArray(value) && typeof value === "object");
      assert.equal(contractModels[key].safeParse({ ...value, unexpected: true }).success, false, key);
      const required = schemas[key]["required"];
      assert.ok(Array.isArray(required) && typeof required[0] === "string", key);
      const firstRequired = required[0];
      assert.equal(typeof firstRequired, "string");
      const missing = { ...value };
      assert.equal(Reflect.deleteProperty(missing, firstRequired), true);
      assert.equal(contractModels[key].safeParse(missing).success, false, key);
    }
  });

  void test("corpus protocol rejects duplicate IDs and oversized diagnostics", async () => {
    const corpus = await loadCorpus();
    assert.throws(() => corpusSchema.parse({
      ...corpus,
      entries: [...corpus.entries, corpus.entries[0]],
    }), /unique/u);
    assert.throws(() => corpusSchema.parse({
      ...corpus,
      entries: Array.from({ length: 513 }, () => corpus.entries[0]),
    }));
    assert.throws(() => corpusEntrySchema.parse({
      ...corpus.entries[0],
      error_class: "x".repeat(129),
    }));
    const first = corpus.entries[0];
    assert.notEqual(first, undefined);
    assert.ok(first !== undefined);
    assert.throws(() => corpusSchema.parse({
      ...corpus,
      entries: [
        { ...first, mode: first.mode === "input" ? "output" : "input" },
        ...corpus.entries.slice(1),
      ],
    }), /mode/u);
    assert.throws(() => corpusSchema.parse({
      ...corpus,
      entries: [
        { ...first, error_class: "validation_error" },
        ...corpus.entries.slice(1),
      ],
    }), /verdict/u);
  });

  void test("frozen corpus matches its normative Zod verdicts", async () => {
    const corpus = await loadCorpus();
    for (const entry of corpus.entries) {
      const result = runEntry(entry);
      assert.equal(result.accepted, entry.expected === "accept", entry.requirement_id);
      if (result.accepted) {
        assert.deepEqual(result.normalized, strictJsonValue(entry.normalized), entry.requirement_id);
      } else {
        assert.notEqual(entry.error_class, null, entry.requirement_id);
      }
    }
  });
} else if (process.argv.includes("--self-test-nonzero")) {
  process.exitCode = 7;
} else if (process.argv.includes("--self-test-malformed")) {
  process.stdout.write("{\n");
} else {
  if (process.argv.includes("--self-test-delay")) {
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 200);
    });
  }
  const document = await oracleDocument();
  const firstContractKey = contractKeys[0];
  if (firstContractKey === undefined) {
    throw new TypeError("contract key inventory is empty");
  }
  const schemas = document["schemas"];
  if (schemas === null || Array.isArray(schemas) || typeof schemas !== "object") {
    throw new TypeError("oracle schemas are not an object");
  }
  if (process.argv.includes("--self-test-missing-schema")) {
    if (!Reflect.deleteProperty(schemas, firstContractKey)) {
      throw new TypeError("oracle schema could not be removed");
    }
  }
  if (process.argv.includes("--self-test-extra-schema")) {
    schemas["input.UnreviewedInput"] = {};
  }
  const serialized = JSON.stringify(document);
  if (process.argv.includes("--self-test-duplicate-schema")) {
    const marker = '"schemas":{';
    const replacement = `${marker}"${firstContractKey}":{},`;
    process.stdout.write(`${serialized.replace(marker, replacement)}\n`);
  } else {
    process.stdout.write(`${serialized}\n`);
  }
}
