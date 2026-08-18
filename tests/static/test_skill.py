# Copyright (c) 2026 David Osipov
"""Static repository-instruction tests."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
SKILL = ROOT / "skills" / "georgian-newspaper-visual-analysis" / "SKILL.md"
MAX_FRONTMATTER_BYTES = 1024


def test_skill_has_valid_discoverable_frontmatter() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    frontmatter = text.split("---\n", 2)[1]
    assert re.search(
        r"^name: georgian-newspaper-visual-analysis$", frontmatter, re.MULTILINE
    )
    assert (
        re.search(r"^description: Use when .+$", frontmatter, re.MULTILINE) is not None
    )
    assert len(frontmatter.encode("utf-8")) <= MAX_FRONTMATTER_BYTES


def test_skill_requires_the_safe_visual_analysis_sequence() -> None:
    text = SKILL.read_text(encoding="utf-8")
    required = [
        "search_documents",
        "get_document_metadata",
        "list_document_files",
        "download_document_file",
        "inspect_pdf",
        "render_pdf_pages",
        "render_pdf_page_tiles",
    ]
    positions = [text.index(name) for name in required]
    assert positions == sorted(positions)


def test_skill_preserves_evidence_and_forbids_ocr_shortcuts_or_restriction_bypass() -> (
    None
):
    text = SKILL.read_text(encoding="utf-8").lower()
    for phrase in (
        "ocr is not authoritative",
        "do not automatically run ocr",
        "visually observed",
        "inferred",
        "uncertain",
        "source_sha256",
        "tile coordinates",
        "crop only",
        "never resize",
        "fallback_400_dpi",
        "do not bypass",
        "restricted",
    ):
        assert phrase in text
