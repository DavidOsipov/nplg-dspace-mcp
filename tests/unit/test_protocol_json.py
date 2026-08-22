# Copyright (c) 2026 David Osipov
"""Fail-closed JSON encoding policy for every project protocol boundary."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_every_project_json_encoder_explicitly_rejects_nonfinite_numbers() -> None:
    faults: list[str] = []
    for path in sorted((ROOT / "src" / "nplg_mcp").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=path.as_posix())
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "json"
                and node.func.attr in {"dump", "dumps"}
            ):
                continue
            allow_nan = next(
                (
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg == "allow_nan"
                ),
                None,
            )
            if not (isinstance(allow_nan, ast.Constant) and allow_nan.value is False):
                faults.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert faults == []
