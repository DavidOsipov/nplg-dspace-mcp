# Copyright (c) 2026 David Osipov
"""End-to-end PEP 561 distribution and external-consumer gate."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from nplg_mcp.json_types import load_json_value, require_json_object
from scripts.verify_pep561 import _validate_evidence_document

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts" / "verify_pep561.py"
_TIMEOUT_SECONDS = 180
_FIXTURE_CANDIDATE = "0" * 40


def _closed_environment() -> dict[str, str]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": os.pathsep.join(("/usr/bin", "/bin")),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "SOURCE_DATE_EPOCH": "0",
    }
    if os.environ.get("COVERAGE_PROCESS_START") is not None:
        environment["COVERAGE_PROCESS_START"] = os.environ["COVERAGE_PROCESS_START"]
    if os.environ.get("COVERAGE_PROCESS_CONFIG") is not None:
        environment["COVERAGE_PROCESS_CONFIG"] = os.environ["COVERAGE_PROCESS_CONFIG"]
    return environment


def test_pep561_artifacts_and_external_consumers(tmp_path: Path) -> None:
    output = tmp_path / "pep561-evidence"
    command = [
        sys.executable,
        "-I",
        "-B",
        GATE.as_posix(),
        "--worktree",
        ROOT.as_posix(),
        "--output-dir",
        output.as_posix(),
        "--candidate",
        _FIXTURE_CANDIDATE,
    ]
    if os.environ.get("NPLG_PYTHON_ONLY_CONTRACT_GATE") == "1":
        command.append("--artifact-only")
        expected_checks = {
            "artifact_inventory": True,
            "external_consumer_mypy": None,
            "external_consumer_pyright": None,
            "marker_fault_mypy": None,
            "marker_fault_pyright": None,
            "annotation_fault_mypy": None,
            "annotation_fault_pyright": None,
        }
    else:
        reviewed_node = os.environ.get("NPLG_REVIEWED_NODE")
        assert reviewed_node is not None, "reviewed Node executable is required"
        command.extend(("--node-executable", reviewed_node))
        expected_checks = {
            "artifact_inventory": True,
            "external_consumer_mypy": True,
            "external_consumer_pyright": True,
            "marker_fault_mypy": True,
            "marker_fault_pyright": True,
            "annotation_fault_mypy": True,
            "annotation_fault_pyright": True,
        }
    result = subprocess.run(  # noqa: S603
        tuple(command),
        cwd=tmp_path,
        env=_closed_environment(),
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=_TIMEOUT_SECONDS,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    evidence = require_json_object(
        load_json_value((output / "pep561-evidence.json").read_bytes()),
        context="PEP 561 gate evidence",
    )
    assert evidence["candidate"] == _FIXTURE_CANDIDATE
    assert evidence["mode"] == (
        "artifact-only"
        if os.environ.get("NPLG_PYTHON_ONLY_CONTRACT_GATE") == "1"
        else "full"
    )
    assert evidence["checks"] == expected_checks
    _validate_evidence_document(
        evidence,
        require_full=os.environ.get("NPLG_PYTHON_ONLY_CONTRACT_GATE") != "1",
    )
