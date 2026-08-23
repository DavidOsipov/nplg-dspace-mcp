// Copyright (c) 2026 David Osipov
/** Independent Zod 4 runtime models and deterministic JSON Schema projection. */

import { z } from "zod";

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export interface JsonObject extends Record<string, JsonValue> {}
export type ContractDirection = "input" | "output";
export type ContractKey =
  | "input.ArtifactInput"
  | "input.DownloadDocumentInput"
  | "input.HandleInput"
  | "input.RenderIdInput"
  | "input.RenderPagesInput"
  | "input.RenderTilesInput"
  | "input.SearchDocumentsInput"
  | "output.DocumentFilesOutput"
  | "output.DocumentMetadataOutput"
  | "output.DownloadDocumentOutput"
  | "output.PdfInspectionOutput"
  | "output.RenderManifestOutput"
  | "output.RenderPagesOutput"
  | "output.RenderTilesOutput"
  | "output.SearchDocumentsOutput";

export interface CodePointBound {
  readonly pointer: string;
  readonly minimum: number;
  readonly maximum: number;
}

const MIN_SAFE_INTEGER = -9_007_199_254_740_991;
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const MIN_TILE_DIMENSION = 256;
const HARD_MAX_TILE_DIMENSION = 4096;
const HARD_MAX_TILE_OVERLAP = 512;
const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;
const SAFE_TEXT_PATTERN = new RegExp(
  "^[^\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0605\u061c\u06dd\u070f"
    + "\u0890-\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    + "\u2066-\u206f\ufeff\ufff9-\ufffb\u{110bd}\u{110cd}"
    + "\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}"
    + "\u{e0001}\u{e0020}-\u{e007f}]*$",
  "u",
);
const NON_BLANK_SAFE_TEXT_PATTERN = new RegExp(
  "^[^\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0605\u061c\u06dd\u070f"
    + "\u0890-\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    + "\u2066-\u206f\ufeff\ufff9-\ufffb\u{110bd}\u{110cd}"
    + "\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}"
    + "\u{e0001}\u{e0020}-\u{e007f}]*"
    + "[^\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0605\u061c\u06dd\u070f"
    + "\u0890-\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    + "\u2066-\u206f\ufeff\ufff9-\ufffb\u{110bd}\u{110cd}"
    + "\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}"
    + "\u{e0001}\u{e0020}-\u{e007f} \u00a0\u1680\u2000-\u200a\u2028-\u2029"
    + "\u202f\u205f\u3000]"
    + "[^\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0605\u061c\u06dd\u070f"
    + "\u0890-\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    + "\u2066-\u206f\ufeff\ufff9-\ufffb\u{110bd}\u{110cd}"
    + "\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}"
    + "\u{e0001}\u{e0020}-\u{e007f}]*$",
  "u",
);
const DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema";

/**
 * Build a Unicode-code-point bounded string without Zod's UTF-16 length checks.
 */
export function codePointString(minimum: number, maximum: number): z.ZodString {
  if (
    !Number.isSafeInteger(minimum)
    || !Number.isSafeInteger(maximum)
    || minimum < 0
    || maximum < minimum
  ) {
    throw new RangeError("code-point bounds are invalid");
  }
  return z.string().superRefine((value, context) => {
    const length = Array.from(value).length;
    if (length < minimum || length > maximum) {
      context.addIssue({
        code: "custom",
        message: "string length is outside the code-point bounds",
      });
    }
  });
}

/** Build a string bounded by its serialized UTF-8 byte length. */
export function utf8ByteString(minimum: number, maximum: number): z.ZodString {
  if (
    !Number.isSafeInteger(minimum)
    || !Number.isSafeInteger(maximum)
    || minimum < 0
    || maximum < minimum
  ) {
    throw new RangeError("UTF-8 byte bounds are invalid");
  }
  return z.string().superRefine((value, context) => {
    const length = Buffer.byteLength(value, "utf8");
    if (length < minimum || length > maximum) {
      context.addIssue({
        code: "custom",
        message: "string length is outside the UTF-8 byte bounds",
      });
    }
  });
}

interface CodePointLimit {
  readonly minimum: number;
  readonly maximum: number;
}

function codePointLimit(minimum: number, maximum: number): Readonly<CodePointLimit> {
  if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum)) {
    throw new RangeError("code-point limit declaration is invalid");
  }
  return Object.freeze({ minimum, maximum });
}

const CODE_POINT_LIMITS = Object.freeze({
  codePoint2: codePointLimit(1, 2),
  cursor: codePointLimit(0, 1024),
  handle: codePointLimit(3, 128),
  httpUrl: codePointLimit(8, 4096),
  query: codePointLimit(1, 500),
  relativePath: codePointLimit(1, 1024),
  text64: codePointLimit(1, 64),
  text128: codePointLimit(1, 128),
  text256: codePointLimit(1, 256),
  text512: codePointLimit(1, 512),
  text1024: codePointLimit(1, 1024),
  text8192: codePointLimit(1, 8192),
});

function limitedCodePointString(limit: Readonly<CodePointLimit>): z.ZodString {
  return codePointString(limit.minimum, limit.maximum);
}

function inertText(limit: Readonly<CodePointLimit>): z.ZodString {
  return limitedCodePointString(limit).regex(SAFE_TEXT_PATTERN).superRefine((value, context) => {
    if (CONTROL_OR_FORMAT.test(value)) {
      context.addIssue({
        code: "custom",
        message: "text contains a prohibited control or bidi character",
      });
    }
  });
}

const text64 = inertText(CODE_POINT_LIMITS.text64);
const text128 = inertText(CODE_POINT_LIMITS.text128);
const text256 = inertText(CODE_POINT_LIMITS.text256);
const text1024 = inertText(CODE_POINT_LIMITS.text1024);
const text8192 = inertText(CODE_POINT_LIMITS.text8192);
const outputHandle = limitedCodePointString(CODE_POINT_LIMITS.handle)
  .regex(/^[1-9][0-9]{0,31}\/[1-9][0-9]{0,31}$/);
const inputHandle = limitedCodePointString(CODE_POINT_LIMITS.handle)
  .regex(/^[1-9][0-9]{0,31}\/[1-9][0-9]{0,31}$/)
  .describe("Canonical NPLG DSpace handle.");
const bitstreamId = limitedCodePointString(CODE_POINT_LIMITS.text128)
  .regex(/^[A-Za-z0-9._~-]{1,128}$/);
const artifactId = z.string().regex(/^doc_[0-9a-f]{64}$/);
const renderId = z.string().regex(/^rnd_[0-9a-f]{32}$/);
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const artifactResourceUri = limitedCodePointString(CODE_POINT_LIMITS.text512)
  .regex(/^nplg:\/\/artifact\/doc_[0-9a-f]{64}$/);
const renderManifestResourceUri = limitedCodePointString(CODE_POINT_LIMITS.text512)
  .regex(/^nplg:\/\/render\/rnd_[0-9a-f]{32}\/manifest$/);
const httpUrl = limitedCodePointString(CODE_POINT_LIMITS.httpUrl)
  .regex(/^https?:\/\/[!-~]{1,4088}$/);
const relativePath = limitedCodePointString(CODE_POINT_LIMITS.relativePath).regex(
  /^([A-Za-z0-9_-][A-Za-z0-9._-]{0,255}|\.[A-Za-z0-9_-][A-Za-z0-9._-]{0,255}|\.\.[A-Za-z0-9_-][A-Za-z0-9._-]{0,255})(\/([A-Za-z0-9_-][A-Za-z0-9._-]{0,255}|\.[A-Za-z0-9_-][A-Za-z0-9._-]{0,255}|\.\.[A-Za-z0-9_-][A-Za-z0-9._-]{0,255})){0,15}$/,
);
const safeInteger = z.number().int().gte(MIN_SAFE_INTEGER).lte(MAX_SAFE_INTEGER);
const nonnegativeInteger = safeInteger.gte(0);
const positiveInteger = safeInteger.gte(1);
const pageNumber = safeInteger.gte(1).lte(10_000);
const pageCount = safeInteger.gte(0).lte(10_000);
const imageCount = safeInteger.gte(0).lte(100_000);
const rotation = safeInteger.gte(0).lte(359);
const tileDimension = safeInteger.gte(MIN_TILE_DIMENSION).lte(HARD_MAX_TILE_DIMENSION);
const tileOverlap = safeInteger.gte(0).lte(HARD_MAX_TILE_OVERLAP);
const finitePositive = z.number().gt(0);
const finiteRatio = z.number().gte(0).lte(1);

export const primitiveModels = {
  "primitive.CodePoint2": limitedCodePointString(CODE_POINT_LIMITS.codePoint2),
  "primitive.SafeInteger": safeInteger,
};

const string8192Array512 = z.array(text8192).max(512).meta({
  id: "FrozenSequence_Annotated_str__StringConstraints__AfterValidator___MaxLen_max_length_512_",
});
const string64Array128 = z.array(text64).max(128).meta({
  id: "FrozenSequence_Annotated_str__StringConstraints__AfterValidator___MaxLen_max_length_128_",
});

export const searchDocumentRecord = z.strictObject({
  handle: outputHandle,
  canonical_url: httpUrl,
  title: text8192,
  issue_date: text64.nullable().default(null),
  authors: string8192Array512.default([]),
}).describe("One bounded repository search result.").meta({
  id: "SearchDocumentRecord",
});

const searchDocumentRecordArray = z.array(searchDocumentRecord).max(50).meta({
  id: "FrozenSequence_SearchDocumentRecord__MaxLen_max_length_50_",
});

export const rawMetadataFieldOutput = z.strictObject({
  key: text256,
  value: text8192,
  language: text64.nullable().default(null),
}).describe("One inert normalized metadata field with explicit provenance key.").meta({
  id: "RawMetadataFieldOutput",
});

export const documentFileRecord = z.strictObject({
  bitstream_id: text128,
  handle: outputHandle,
  filename: text8192,
  source_url: httpUrl,
  reported_size: nonnegativeInteger.nullable().default(null),
  reported_format: text256.nullable().default(null),
  description: text8192.nullable().default(null),
  access_status: text64,
}).describe("One file discovered on a canonical item page.").meta({
  id: "DocumentFileRecord",
});

const documentFileRecordArray = z.array(documentFileRecord).max(512).meta({
  id: "FrozenSequence_DocumentFileRecord__MaxLen_max_length_512_",
});
const rawMetadataFieldArray = z.array(rawMetadataFieldOutput).max(4096).meta({
  id: "FrozenSequence_RawMetadataFieldOutput__MaxLen_max_length_4096_",
});

export const pageInspectionRecord = z.strictObject({
  page_number: pageNumber,
  width_points: finitePositive,
  height_points: finitePositive,
  rotation,
  classification: text64,
  image_count: imageCount,
  has_text: z.boolean(),
  has_drawings: z.boolean(),
  crop_applied: z.boolean(),
  dominant_image_index: imageCount.nullable(),
  dominant_extension: text64.nullable(),
  dominant_coverage: finiteRatio.nullable(),
  native_width: positiveInteger.nullable(),
  native_height: positiveInteger.nullable(),
  effective_dpi_x: finitePositive.nullable(),
  effective_dpi_y: finitePositive.nullable(),
  direct_jpeg_eligible: z.boolean(),
  native_raster_extract_eligible: z.boolean(),
}).describe("Bounded public inspection data for one PDF page.").meta({
  id: "PageInspectionRecord",
});

const pageInspectionArray = z.array(pageInspectionRecord).max(10_000).meta({
  id: "FrozenSequence_PageInspectionRecord__MaxLen_max_length_10000_",
});

export const renderedPageRecord = z.strictObject({
  page_number: pageNumber,
  width: positiveInteger,
  height: positiveInteger,
  rotation,
  classification: text64,
  effective_dpi_x: finitePositive,
  effective_dpi_y: finitePositive,
  resolution_source: text64,
  conversion_path: text64,
  relative_path: relativePath,
  sha256,
  media_type: z.literal("image/jpeg"),
  resize_applied: z.boolean(),
  pixel_dimensions_preserved: z.boolean(),
  renderer_resampling: text64,
  reencoded: z.boolean(),
  lossy_conversion: z.boolean(),
  asset_url: httpUrl,
  resource_uri: artifactResourceUri,
}).describe("One bounded rendered JPEG page and its provenance.").meta({
  id: "RenderedPageRecord",
});

const renderedPageArray = z.array(renderedPageRecord).min(1).max(8).meta({
  id: "FrozenSequence_RenderedPageRecord__MinLen_min_length_1__MaxLen_max_length_8_",
});

export const renderedTileRecord = z.strictObject({
  tile_id: text128,
  page_number: pageNumber,
  x: nonnegativeInteger,
  y: nonnegativeInteger,
  width: positiveInteger,
  height: positiveInteger,
  full_page_width: positiveInteger,
  full_page_height: positiveInteger,
  overlap: tileOverlap,
  relative_path: relativePath,
  sha256,
  media_type: z.literal("image/jpeg"),
  resize_applied: z.literal(false),
  pixel_dimensions_preserved: z.literal(true),
  renderer_resampling: z.literal("none"),
  reencoded: z.literal(true),
  lossy_conversion: z.literal(true),
  asset_url: httpUrl,
  resource_uri: artifactResourceUri,
}).describe("One bounded crop-only JPEG tile and its provenance.").meta({
  id: "RenderedTileRecord",
});

const renderedTileArray = z.array(renderedTileRecord).min(1).max(4096).meta({
  id: "FrozenSequence_RenderedTileRecord__MinLen_min_length_1__MaxLen_max_length_4096_",
});

export const artifactInput = z.strictObject({
  artifact_id: artifactId,
}).describe("Validated content-addressed document identifier.");

export const downloadDocumentInput = z.strictObject({
  handle: inputHandle,
  bitstream_id: bitstreamId,
}).describe("Validated input for one discovered document bitstream.");

export const handleInput = z.strictObject({
  handle: inputHandle,
}).describe("Validated canonical-handle input.");

export const renderIdInput = z.strictObject({
  render_id: renderId,
}).describe("Validated deterministic render identifier.");

export const renderPagesInput = z.strictObject({
  artifact_id: artifactId,
  pages: z.array(pageNumber).min(1).max(8),
  mode: z.literal("native").default("native"),
}).describe("Validated page-render request.");

export const renderTilesInput = z.strictObject({
  render_id: renderId,
  page_number: pageNumber,
  tile_width: tileDimension.nullable().default(null),
  tile_height: tileDimension.nullable().default(null),
  overlap: tileOverlap.nullable().default(null),
}).describe("Validated crop-only tile request.");

export const searchDocumentsInput = z.strictObject({
  query: limitedCodePointString(CODE_POINT_LIMITS.query)
    .regex(NON_BLANK_SAFE_TEXT_PATTERN)
    .superRefine((value, context) => {
      if (CONTROL_OR_FORMAT.test(value)) {
        context.addIssue({
          code: "custom",
          message: "text contains a prohibited control or bidi character",
        });
      }
      if (value.trim().length === 0) {
        context.addIssue({
          code: "custom",
          message: "query must contain non-whitespace characters",
        });
      }
    }),
  cursor: inertText(CODE_POINT_LIMITS.cursor).nullable().default(null),
  page_size: safeInteger.gte(1).lte(50).default(20),
  scope_handle: inputHandle.nullable().default(null),
}).describe("Validated input for repository search.");

export const searchDocumentsOutput = z.strictObject({
  items: searchDocumentRecordArray,
  total: nonnegativeInteger,
  next_offset: nonnegativeInteger.nullable(),
  source_url: httpUrl,
  next_cursor: text1024.nullable().default(null),
}).describe("One bounded search page with an opaque continuation cursor.");

export const documentMetadataOutput = z.strictObject({
  handle: outputHandle,
  canonical_url: httpUrl,
  title: text8192,
  issue_date: text64.nullable().default(null),
  creators: string8192Array512.default([]),
  contributors: string8192Array512.default([]),
  publishers: string8192Array512.default([]),
  descriptions: string8192Array512.default([]),
  subjects: string8192Array512.default([]),
  languages: string64Array128.default([]),
  identifiers: string8192Array512.default([]),
  rights: string8192Array512.default([]),
  owners: string8192Array512.default([]),
  collections: string8192Array512.default([]),
  types: string8192Array512.default([]),
  raw_fields: rawMetadataFieldArray.default([]),
  bitstreams: documentFileRecordArray.default([]),
  restricted: z.boolean().default(false),
  restriction_reason: text8192.nullable().default(null),
  metadata_source: text64,
}).describe("Bounded normalized metadata for one NPLG item.");

export const documentFilesOutput = z.strictObject({
  handle: outputHandle,
  files: documentFileRecordArray,
}).describe("Bounded file inventory for one canonical item.");

export const downloadDocumentOutput = z.strictObject({
  artifact_id: artifactId,
  sha256,
  size: nonnegativeInteger,
  media_type: z.literal("application/pdf"),
  relative_path: relativePath,
  asset_url: httpUrl,
  resource_uri: artifactResourceUri,
  source_bitstream_id: text128,
  source_url: httpUrl,
  bytes_downloaded: nonnegativeInteger,
}).describe("Content-addressed result of one bounded public download.");

export const pdfInspectionOutput = z.strictObject({
  artifact_id: artifactId,
  source_sha256: sha256,
  page_count: pageCount,
  renderer_version: text256,
  pages: pageInspectionArray,
  resource_uri: artifactResourceUri,
}).describe("Strict public result of inspecting one PDF.");

const renderManifestShape = {
  render_id: renderId,
  source_sha256: sha256,
  renderer_version: text256,
  mode: z.literal("native"),
  pages: renderedPageArray,
  manifest_relative_path: relativePath,
  manifest_asset_url: httpUrl,
  resource_uri: renderManifestResourceUri,
};

export const renderManifestOutput = z.strictObject(renderManifestShape)
  .describe("Strict public page-render manifest.");

export const renderPagesOutput = z.strictObject({
  ...renderManifestShape,
  artifact_id: artifactId,
}).describe("Strict public render result bound to its source artifact.");

export const renderTilesOutput = z.strictObject({
  render_id: renderId,
  page_number: pageNumber,
  page_sha256: sha256,
  tile_width: tileDimension,
  tile_height: tileDimension,
  overlap: tileOverlap,
  tiles: renderedTileArray,
  manifest_relative_path: relativePath,
  manifest_asset_url: httpUrl,
  resource_uri: artifactResourceUri,
}).describe("Strict public crop-only tile manifest.");

export const contractModels = {
  "input.ArtifactInput": artifactInput,
  "input.DownloadDocumentInput": downloadDocumentInput,
  "input.HandleInput": handleInput,
  "input.RenderIdInput": renderIdInput,
  "input.RenderPagesInput": renderPagesInput,
  "input.RenderTilesInput": renderTilesInput,
  "input.SearchDocumentsInput": searchDocumentsInput,
  "output.DocumentFilesOutput": documentFilesOutput,
  "output.DocumentMetadataOutput": documentMetadataOutput,
  "output.DownloadDocumentOutput": downloadDocumentOutput,
  "output.PdfInspectionOutput": pdfInspectionOutput,
  "output.RenderManifestOutput": renderManifestOutput,
  "output.RenderPagesOutput": renderPagesOutput,
  "output.RenderTilesOutput": renderTilesOutput,
  "output.SearchDocumentsOutput": searchDocumentsOutput,
} satisfies Record<ContractKey, z.ZodType>;

export const contractKeys: readonly ContractKey[] = [
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
];

function bound(pointer: string, limit: Readonly<CodePointLimit>): CodePointBound {
  return { pointer, minimum: limit.minimum, maximum: limit.maximum };
}

export const codePointBounds = {
  "input.ArtifactInput": [],
  "input.DownloadDocumentInput": [
    bound("/properties/bitstream_id", CODE_POINT_LIMITS.text128),
    bound("/properties/handle", CODE_POINT_LIMITS.handle),
  ],
  "input.HandleInput": [bound("/properties/handle", CODE_POINT_LIMITS.handle)],
  "input.RenderIdInput": [],
  "input.RenderPagesInput": [],
  "input.RenderTilesInput": [],
  "input.SearchDocumentsInput": [
    bound("/properties/cursor/anyOf/0", CODE_POINT_LIMITS.cursor),
    bound("/properties/query", CODE_POINT_LIMITS.query),
    bound("/properties/scope_handle/anyOf/0", CODE_POINT_LIMITS.handle),
  ],
  "output.DocumentFilesOutput": [
    bound("/$defs/DocumentFileRecord/properties/access_status", CODE_POINT_LIMITS.text64),
    bound("/$defs/DocumentFileRecord/properties/bitstream_id", CODE_POINT_LIMITS.text128),
    bound("/$defs/DocumentFileRecord/properties/description/anyOf/0", CODE_POINT_LIMITS.text8192),
    bound("/$defs/DocumentFileRecord/properties/filename", CODE_POINT_LIMITS.text8192),
    bound("/$defs/DocumentFileRecord/properties/reported_format/anyOf/0", CODE_POINT_LIMITS.text256),
    bound("/$defs/DocumentFileRecord/properties/source_url", CODE_POINT_LIMITS.httpUrl),
  ],
  "output.DocumentMetadataOutput": [
    bound("/$defs/DocumentFileRecord/properties/access_status", CODE_POINT_LIMITS.text64),
    bound("/$defs/DocumentFileRecord/properties/bitstream_id", CODE_POINT_LIMITS.text128),
    bound("/$defs/DocumentFileRecord/properties/description/anyOf/0", CODE_POINT_LIMITS.text8192),
    bound("/$defs/DocumentFileRecord/properties/filename", CODE_POINT_LIMITS.text8192),
    bound("/$defs/DocumentFileRecord/properties/reported_format/anyOf/0", CODE_POINT_LIMITS.text256),
    bound("/$defs/DocumentFileRecord/properties/source_url", CODE_POINT_LIMITS.httpUrl),
    bound("/$defs/FrozenSequence_Annotated_str__StringConstraints__AfterValidator___MaxLen_max_length_128_/items", CODE_POINT_LIMITS.text64),
    bound("/$defs/FrozenSequence_Annotated_str__StringConstraints__AfterValidator___MaxLen_max_length_512_/items", CODE_POINT_LIMITS.text8192),
    bound("/$defs/RawMetadataFieldOutput/properties/key", CODE_POINT_LIMITS.text256),
    bound("/$defs/RawMetadataFieldOutput/properties/language/anyOf/0", CODE_POINT_LIMITS.text64),
    bound("/$defs/RawMetadataFieldOutput/properties/value", CODE_POINT_LIMITS.text8192),
    bound("/properties/canonical_url", CODE_POINT_LIMITS.httpUrl),
    bound("/properties/issue_date/anyOf/0", CODE_POINT_LIMITS.text64),
    bound("/properties/metadata_source", CODE_POINT_LIMITS.text64),
    bound("/properties/restriction_reason/anyOf/0", CODE_POINT_LIMITS.text8192),
  ],
  "output.DownloadDocumentOutput": [
    bound("/properties/asset_url", CODE_POINT_LIMITS.httpUrl),
    bound("/properties/relative_path", CODE_POINT_LIMITS.relativePath),
    bound("/properties/resource_uri", CODE_POINT_LIMITS.text512),
    bound("/properties/source_bitstream_id", CODE_POINT_LIMITS.text128),
    bound("/properties/source_url", CODE_POINT_LIMITS.httpUrl),
  ],
  "output.PdfInspectionOutput": [
    bound("/$defs/PageInspectionRecord/properties/classification", CODE_POINT_LIMITS.text64),
    bound("/$defs/PageInspectionRecord/properties/dominant_extension/anyOf/0", CODE_POINT_LIMITS.text64),
    bound("/properties/renderer_version", CODE_POINT_LIMITS.text256),
    bound("/properties/resource_uri", CODE_POINT_LIMITS.text512),
  ],
  "output.RenderManifestOutput": [
    bound("/$defs/RenderedPageRecord/properties/asset_url", CODE_POINT_LIMITS.httpUrl),
    bound("/$defs/RenderedPageRecord/properties/classification", CODE_POINT_LIMITS.text64),
    bound("/$defs/RenderedPageRecord/properties/conversion_path", CODE_POINT_LIMITS.text64),
    bound("/$defs/RenderedPageRecord/properties/relative_path", CODE_POINT_LIMITS.relativePath),
    bound("/$defs/RenderedPageRecord/properties/renderer_resampling", CODE_POINT_LIMITS.text64),
    bound("/$defs/RenderedPageRecord/properties/resolution_source", CODE_POINT_LIMITS.text64),
    bound("/$defs/RenderedPageRecord/properties/resource_uri", CODE_POINT_LIMITS.text512),
    bound("/properties/manifest_asset_url", CODE_POINT_LIMITS.httpUrl),
    bound("/properties/manifest_relative_path", CODE_POINT_LIMITS.relativePath),
    bound("/properties/renderer_version", CODE_POINT_LIMITS.text256),
    bound("/properties/resource_uri", CODE_POINT_LIMITS.text512),
  ],
  "output.RenderPagesOutput": [
    bound("/$defs/RenderedPageRecord/properties/asset_url", CODE_POINT_LIMITS.httpUrl),
    bound("/$defs/RenderedPageRecord/properties/classification", CODE_POINT_LIMITS.text64),
    bound("/$defs/RenderedPageRecord/properties/conversion_path", CODE_POINT_LIMITS.text64),
    bound("/$defs/RenderedPageRecord/properties/relative_path", CODE_POINT_LIMITS.relativePath),
    bound("/$defs/RenderedPageRecord/properties/renderer_resampling", CODE_POINT_LIMITS.text64),
    bound("/$defs/RenderedPageRecord/properties/resolution_source", CODE_POINT_LIMITS.text64),
    bound("/$defs/RenderedPageRecord/properties/resource_uri", CODE_POINT_LIMITS.text512),
    bound("/properties/manifest_asset_url", CODE_POINT_LIMITS.httpUrl),
    bound("/properties/manifest_relative_path", CODE_POINT_LIMITS.relativePath),
    bound("/properties/renderer_version", CODE_POINT_LIMITS.text256),
    bound("/properties/resource_uri", CODE_POINT_LIMITS.text512),
  ],
  "output.RenderTilesOutput": [
    bound("/$defs/RenderedTileRecord/properties/asset_url", CODE_POINT_LIMITS.httpUrl),
    bound("/$defs/RenderedTileRecord/properties/relative_path", CODE_POINT_LIMITS.relativePath),
    bound("/$defs/RenderedTileRecord/properties/resource_uri", CODE_POINT_LIMITS.text512),
    bound("/$defs/RenderedTileRecord/properties/tile_id", CODE_POINT_LIMITS.text128),
    bound("/properties/manifest_asset_url", CODE_POINT_LIMITS.httpUrl),
    bound("/properties/manifest_relative_path", CODE_POINT_LIMITS.relativePath),
    bound("/properties/resource_uri", CODE_POINT_LIMITS.text512),
  ],
  "output.SearchDocumentsOutput": [
    bound("/$defs/FrozenSequence_Annotated_str__StringConstraints__AfterValidator___MaxLen_max_length_512_/items", CODE_POINT_LIMITS.text8192),
    bound("/$defs/SearchDocumentRecord/properties/canonical_url", CODE_POINT_LIMITS.httpUrl),
    bound("/$defs/SearchDocumentRecord/properties/issue_date/anyOf/0", CODE_POINT_LIMITS.text64),
    bound("/properties/next_cursor/anyOf/0", CODE_POINT_LIMITS.text1024),
    bound("/properties/source_url", CODE_POINT_LIMITS.httpUrl),
  ],
} satisfies Record<ContractKey, readonly CodePointBound[]>;

function jsonValue(value: unknown): JsonValue {
  if (
    value === null
    || typeof value === "boolean"
    || typeof value === "string"
    || (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => jsonValue(item));
  }
  if (typeof value === "object") {
    const result: JsonObject = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = jsonValue(item);
    }
    return result;
  }
  throw new TypeError("schema conversion returned a non-JSON value");
}

function jsonObject(value: unknown): JsonObject {
  const parsed = jsonValue(value);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new TypeError("schema conversion did not return an object");
  }
  return parsed;
}

function pointerSegments(pointer: string): string[] {
  if (!pointer.startsWith("/")) {
    throw new TypeError("code-point schema pointer must be absolute");
  }
  return pointer.slice(1).split("/").map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
}

function injectCodePointBounds(document: JsonObject, bounds: readonly CodePointBound[]): void {
  const seen = new Set<string>();
  for (const bound of bounds) {
    if (seen.has(bound.pointer)) {
      throw new TypeError("duplicate code-point schema pointer");
    }
    seen.add(bound.pointer);
    let current: JsonValue = document;
    for (const segment of pointerSegments(bound.pointer)) {
      if (Array.isArray(current)) {
        const index = Number(segment);
        if (!Number.isSafeInteger(index) || index < 0) {
          throw new TypeError("code-point schema pointer has an invalid array index");
        }
        const next: JsonValue | undefined = current[index];
        if (next === undefined) {
          throw new TypeError("code-point schema pointer is unknown");
        }
        current = next;
        continue;
      }
      if (current === null || typeof current !== "object") {
        throw new TypeError("code-point schema pointer does not select an object");
      }
      const next: JsonValue | undefined = current[segment];
      if (next === undefined) {
        throw new TypeError("code-point schema pointer is unknown");
      }
      current = next;
    }
    if (current === null || Array.isArray(current) || typeof current !== "object") {
      throw new TypeError("code-point schema pointer does not select a schema");
    }
    if (current["type"] !== "string") {
      throw new TypeError("code-point schema pointer does not select a string");
    }
    if (current["minLength"] !== undefined || current["maxLength"] !== undefined) {
      throw new TypeError("code-point bounds conflict with converted schema keywords");
    }
    current["minLength"] = bound.minimum;
    current["maxLength"] = bound.maximum;
  }
}

/** Exercise the closed post-conversion registry without exposing mutable state. */
export function injectCodePointBoundsForTest(
  document: JsonObject,
  bounds: readonly CodePointBound[],
): void {
  injectCodePointBounds(document, bounds);
}

export function exportZodSchemas(): Record<ContractKey, JsonObject> {
  const result: Record<ContractKey, JsonObject> = {
    "input.ArtifactInput": {},
    "input.DownloadDocumentInput": {},
    "input.HandleInput": {},
    "input.RenderIdInput": {},
    "input.RenderPagesInput": {},
    "input.RenderTilesInput": {},
    "input.SearchDocumentsInput": {},
    "output.DocumentFilesOutput": {},
    "output.DocumentMetadataOutput": {},
    "output.DownloadDocumentOutput": {},
    "output.PdfInspectionOutput": {},
    "output.RenderManifestOutput": {},
    "output.RenderPagesOutput": {},
    "output.RenderTilesOutput": {},
    "output.SearchDocumentsOutput": {},
  };
  for (const key of contractKeys) {
    const direction: ContractDirection = key.startsWith("input.") ? "input" : "output";
    const converted = jsonObject(z.toJSONSchema(contractModels[key], {
      target: "draft-2020-12",
      io: direction,
      unrepresentable: "throw",
      cycles: "throw",
      reused: "inline",
    }));
    if (converted["$schema"] !== DRAFT_2020_12) {
      throw new TypeError("Zod emitted an unexpected JSON Schema dialect");
    }
    delete converted["$schema"];
    injectCodePointBounds(converted, codePointBounds[key]);
    result[key] = converted;
  }
  return result;
}
