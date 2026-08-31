# Copyright (c) 2026 David Osipov
"""Tests for the immutable client-side workflow package resource."""
# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path

import pytest

from nplg_mcp import agent_workflow
from nplg_mcp.agent_workflow import (
    AGENT_WORKFLOW_MARKDOWN,
    AGENT_WORKFLOW_MIME_TYPE,
    AGENT_WORKFLOW_NAME,
    AGENT_WORKFLOW_URI,
)

ROOT = Path(__file__).parents[2]
PACKAGED_SKILL = (
    ROOT
    / "src"
    / "nplg_mcp"
    / "agent_skills"
    / "georgian-newspaper-visual-analysis"
    / "SKILL.md"
)


def test_agent_workflow_has_one_canonical_bounded_identity() -> None:
    assert AGENT_WORKFLOW_URI == "nplg://skills/georgian-newspaper-visual-analysis"
    assert AGENT_WORKFLOW_MIME_TYPE == "text/markdown"
    assert AGENT_WORKFLOW_NAME == "Georgian newspaper visual analysis"
    assert PACKAGED_SKILL.read_text(encoding="utf-8") == AGENT_WORKFLOW_MARKDOWN
    assert 0 < len(AGENT_WORKFLOW_MARKDOWN.encode("utf-8")) <= 16 * 1024
    assert "\x00" not in AGENT_WORKFLOW_MARKDOWN


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"", "empty or oversized"),
        (b"x" * ((16 * 1024) + 1), "empty or oversized"),
        (b"\xff", "not valid UTF-8"),
        (b"valid\x00invalid", "forbidden control character"),
        ("valid\u202einvalid".encode(), "forbidden control character"),
    ],
    ids=("empty", "oversized", "non-utf8", "nul", "bidi-control"),
)
def test_agent_workflow_loader_rejects_malformed_package_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    message: str,
) -> None:
    workflow = tmp_path / agent_workflow._AGENT_WORKFLOW_RELATIVE_PATH
    workflow.parent.mkdir(parents=True)
    _ = workflow.write_bytes(payload)

    def package_root(_package: str) -> Path:
        return tmp_path

    monkeypatch.setattr(agent_workflow, "files", package_root)

    with pytest.raises(RuntimeError, match=message):
        _ = agent_workflow._load_agent_workflow()


def test_agent_workflow_loader_wraps_missing_package_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def package_root(_package: str) -> Path:
        return tmp_path

    monkeypatch.setattr(agent_workflow, "files", package_root)

    with pytest.raises(RuntimeError, match="unavailable"):
        _ = agent_workflow._load_agent_workflow()
