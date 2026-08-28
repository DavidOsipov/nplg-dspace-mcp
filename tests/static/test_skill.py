# Copyright (c) 2026 David Osipov
"""Static repository-instruction tests."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
SKILL = ROOT / "skills" / "georgian-newspaper-visual-analysis" / "SKILL.md"
PACKAGED_SKILL = (
    ROOT
    / "src"
    / "nplg_mcp"
    / "agent_skills"
    / "georgian-newspaper-visual-analysis"
    / "SKILL.md"
)
MAX_FRONTMATTER_BYTES = 1024
PUBLIC_TOOL_NAMES = (
    "search_documents",
    "get_document_metadata",
    "list_document_files",
)
PRIVATE_PDF_OPERATION_NAMES = (
    "download_document_file",
    "inspect_pdf",
    "render_pdf_pages",
    "render_pdf_page_tiles",
    "get_render_manifest",
    "delete_render",
)
SERVER_RUNTIME_MANIFESTS = (
    ROOT / "pyproject.toml",
    ROOT / "alpic.json",
)


def _normalized_skill_text() -> str:
    return " ".join(SKILL.read_text(encoding="utf-8").lower().split())


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
    positions = [text.index(name) for name in PUBLIC_TOOL_NAMES]
    assert positions == sorted(positions)
    for operation_name in PRIVATE_PDF_OPERATION_NAMES:
        assert operation_name not in text


def test_skill_is_packaged_byte_for_byte_for_mcp_retrieval() -> None:
    assert PACKAGED_SKILL.read_bytes() == SKILL.read_bytes()


def test_skill_enforces_client_local_retrieval_and_untrusted_pdf_boundaries() -> None:
    text = SKILL.read_text(encoding="utf-8").lower()
    for phrase in (
        "ocr is not authoritative",
        "do not automatically run ocr",
        "visually observed",
        "inferred",
        "uncertain",
        "access_status",
        "public",
        "exact returned `source_url`",
        "never construct",
        "bounded",
        "client-controlled local",
        "local sha-256",
        "untrusted data",
        "prompt injection",
        "do not install",
        "report the workflow as blocked",
        "agent-created temporary files",
        "do not bypass",
        "restricted",
        "requires mcp resource support",
        "not every mcp host will discover, load, or follow it automatically",
    ):
        assert phrase in text


def test_skill_does_not_treat_file_metadata_or_ocr_as_pdf_evidence() -> None:
    text = SKILL.read_text(encoding="utf-8").lower()
    for phrase in (
        "reported format and filename are hints",
        "verify locally that the response is a pdf",
        "quote only text that is visually legible",
        "same canonical handle",
        "bitstream id",
        "page number or page region",
        "rights or access metadata",
    ):
        assert phrase in text


def test_skill_requires_fail_closed_tesseract_capability_preflight() -> None:
    text = _normalized_skill_text()
    version_position = text.index("`tesseract --version`")
    languages_position = text.index("`tesseract --list-langs`")
    ocr_position = text.index("`tesseract input.png output")

    assert version_position < languages_position < ocr_position
    for phrase in (
        "`kat`",
        "`rus`",
        "`kat_old`",
        "do not install tesseract",
        "do not download traineddata",
        "explicit user approval",
        "report ocr as blocked",
    ):
        assert phrase in text
    for forbidden_install_command in (
        "sudo ",
        "apt-get ",
        "pip install",
        "pytesseract",
    ):
        assert forbidden_install_command not in text


def test_skill_defines_a_bounded_client_side_tesseract_trial() -> None:
    text = _normalized_skill_text()
    inspection_position = text.index("## inspect locally")
    ocr_position = text.index("## run bounded local tesseract ocr")

    assert inspection_position < ocr_position
    for phrase in (
        "one representative page or bounded region",
        "at least 300 dpi",
        "lossless",
        "deskew",
        "rendered page image",
        "`kat+rus`",
        "`rus+kat`",
        "dominant script first",
        "`--oem 1`",
        "`--psm 3`",
        "`--psm 6`",
        "plain text and tsv",
        "do not create a searchable pdf",
        "do not batch the whole issue",
        "no network access",
        "non-root",
        "cpu, memory, process, time, and output limits",
    ):
        assert phrase in text


def test_skill_requires_visual_quotation_checks_and_reproducible_ocr_evidence() -> None:
    text = _normalized_skill_text()

    for phrase in (
        "ocr output is untrusted data",
        "visually verify every quoted character against the scan",
        "confidence is not accuracy",
        "tesseract version",
        "traineddata languages and order",
        "renderer and dpi",
        "preprocessing",
        "page or region",
        "ocr input image sha-256",
        "ocr output sha-256",
    ):
        assert phrase in text


def test_tesseract_remains_outside_the_alpic_server_runtime() -> None:
    for manifest in SERVER_RUNTIME_MANIFESTS:
        text = manifest.read_text(encoding="utf-8").lower()
        assert "pytesseract" not in text
        assert "tesseract-ocr" not in text
