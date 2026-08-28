# Copyright (c) 2026 David Osipov
"""Immutable package-backed client workflow exposed through MCP resources."""

from __future__ import annotations

import unicodedata
from importlib.resources import files
from typing import Final

AGENT_WORKFLOW_URI: Final = "nplg://skills/georgian-newspaper-visual-analysis"
AGENT_WORKFLOW_MIME_TYPE: Final = "text/markdown"
AGENT_WORKFLOW_NAME: Final = "Georgian newspaper visual analysis"
AGENT_WORKFLOW_TITLE: Final = "Client-side Georgian newspaper visual analysis"
AGENT_WORKFLOW_DESCRIPTION: Final = (
    "Bounded instructions for retrieving one public NPLG PDF and inspecting it "
    "in the client environment."
)
AGENT_WORKFLOW_DISCOVERY_INSTRUCTIONS: Final = (
    "This anonymous server exposes three read-only NPLG metadata tools. "
    f"Resource-capable clients should list and read {AGENT_WORKFLOW_URI} before "
    "retrieving a public PDF URL; all PDF processing remains client-side."
)

_AGENT_WORKFLOW_RELATIVE_PATH: Final = (
    "agent_skills/georgian-newspaper-visual-analysis/SKILL.md"
)
_MAX_AGENT_WORKFLOW_BYTES: Final = 16 * 1024
_ALLOWED_CONTROL_CHARACTERS: Final = frozenset({"\t", "\n", "\r"})


def _load_agent_workflow() -> str:
    """Load one bounded UTF-8 workflow from immutable package data."""
    try:
        payload = files("nplg_mcp").joinpath(_AGENT_WORKFLOW_RELATIVE_PATH).read_bytes()
    except OSError as exc:
        message = "packaged agent workflow is unavailable"
        raise RuntimeError(message) from exc
    if not 0 < len(payload) <= _MAX_AGENT_WORKFLOW_BYTES:
        message = "packaged agent workflow is empty or oversized"
        raise RuntimeError(message)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        message = "packaged agent workflow is not valid UTF-8"
        raise RuntimeError(message) from exc
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        and character not in _ALLOWED_CONTROL_CHARACTERS
        for character in text
    ):
        message = "packaged agent workflow contains a forbidden control character"
        raise RuntimeError(message)
    return text


AGENT_WORKFLOW_MARKDOWN: Final = _load_agent_workflow()
