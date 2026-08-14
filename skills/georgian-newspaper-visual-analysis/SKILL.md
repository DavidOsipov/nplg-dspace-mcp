---
name: georgian-newspaper-visual-analysis
description: Use when researching scanned Georgian newspapers or historical documents from NPLG Iverieli, especially when OCR is missing, inaccurate, or unsuitable as evidence.
---

# Georgian Newspaper Visual Analysis

## Core rule

OCR is not authoritative for historical Georgian print. Treat repository metadata and the source PDF as provenance, then verify wording visually from page images. Do not automatically run OCR or present OCR output as a quotation.

## Required workflow

1. Call `search_documents` and select a canonical NPLG handle.
2. Call `get_document_metadata`; preserve title, date, creators, rights, collections, handle, and metadata source.
3. Call `list_document_files`; choose only a public PDF bitstream attached to that handle.
4. Call `download_document_file` with the handle and discovered `bitstream_id`. Do not submit or invent an arbitrary URL.
5. Call `inspect_pdf`; record `source_sha256`, page count, page classification, native scan dimensions, rotation, crop, and resolution source.
6. Call `render_pdf_pages` in native mode for the needed pages. Review each complete page before reading details.
7. For small type or newspaper columns, call `render_pdf_page_tiles`. Tiles are crop only and never resize the source page grid.

Use `get_render_manifest` when signed links expire. Use `delete_render` after analysis when cached images are no longer needed.

## Reading protocol

Start with the full page to establish issue identity, section, column order, headlines, continuations, illustrations, and advertisements. Then inspect overlapping tiles in reading order. Account for multi-column flow, hyphenation, damaged paper, bleed-through, archaic spelling, and text that continues on another page.

A page labelled `fallback_400_dpi` has no defensible intrinsic raster grid. Describe it as a 400-DPI fallback render, not as native resolution. A compositor-rendered native grid preserves output dimensions but may still involve renderer interpolation.

## Evidence record

For every material claim preserve:

- canonical handle and bitstream ID;
- filename and `source_sha256`;
- page number;
- tile coordinates (`x`, `y`, `width`, `height`) when a tile was used;
- whether the wording was **visually observed**, **inferred**, or **uncertain**;
- rights or access metadata relevant to reuse.

Quote only text that is visually legible. Mark supplied letters, damaged glyphs, editorial expansion, and uncertain readings explicitly. Do not silently normalize historical spelling.

## Access boundary

Do not bypass authentication, internal-network controls, or copying restrictions. When a file is `restricted`, report that status and continue with public metadata only. Technical availability does not establish public-domain status.
