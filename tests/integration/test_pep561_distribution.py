# Copyright (c) 2026 David Osipov
"""End-to-end PEP 561 distribution and external-consumer gate."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import os
import shutil
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


def _run_git(worktree: Path, *arguments: str) -> bytes:
    environment = {
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": worktree.as_posix(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(  # noqa: S603
        ("/usr/bin/git", *arguments),
        cwd=worktree,
        env=environment,
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
    ).stdout


def _committed_candidate_worktree(root: Path) -> tuple[Path, str, str]:
    worktree = root / "candidate-worktree"
    worktree.mkdir()
    for name in ("LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "pyproject.toml"):
        _ = (worktree / name).write_bytes((ROOT / name).read_bytes())
    source_package = ROOT / "src" / "nplg_mcp"
    candidate_package = worktree / "src" / "nplg_mcp"
    for member in sorted(source_package.rglob("*")):
        relative = member.relative_to(source_package)
        if "__pycache__" in relative.parts or member.suffix in {".pyc", ".pyo"}:
            continue
        assert not member.is_symlink()
        destination = candidate_package / relative
        if member.is_dir():
            destination.mkdir(mode=0o700, parents=True)
        else:
            assert member.name == "py.typed" or member.suffix == ".py"
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _ = destination.write_bytes(member.read_bytes())
    _ = _run_git(worktree, "init", "--quiet")
    _ = _run_git(
        worktree,
        "add",
        "--",
        "LICENSE",
        "README.md",
        "THIRD_PARTY_NOTICES.md",
        "pyproject.toml",
        "src/nplg_mcp",
    )
    _ = _run_git(
        worktree,
        "-c",
        "commit.gpgSign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "user.name=Fixture",
        "commit",
        "--quiet",
        "-m",
        "PEP 561 integration candidate",
    )
    candidate = (
        _run_git(worktree, "rev-parse", "--verify", "HEAD")
        .decode(
            "ascii",
            errors="strict",
        )
        .strip()
    )
    candidate_tree = (
        _run_git(
            worktree,
            "rev-parse",
            "--verify",
            "HEAD^{tree}",
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    mypy = worktree / ".venv" / "bin" / "mypy"
    mypy.parent.mkdir(mode=0o700, parents=True)
    _ = mypy.write_bytes((ROOT / ".venv" / "bin" / "mypy").read_bytes())
    mypy.chmod(0o700)
    _ = shutil.copytree(
        ROOT / "node_modules" / "pyright",
        worktree / "node_modules" / "pyright",
    )
    return worktree, candidate, candidate_tree


def test_pep561_artifacts_and_external_consumers(tmp_path: Path) -> None:
    artifact_only = os.environ.get("NPLG_PYTHON_ONLY_CONTRACT_GATE") == "1"
    if artifact_only:
        worktree = ROOT
        candidate = _FIXTURE_CANDIDATE
        candidate_tree = None
    else:
        worktree, candidate, candidate_tree = _committed_candidate_worktree(tmp_path)
    output = tmp_path / "pep561-evidence"
    command = [
        sys.executable,
        "-I",
        "-B",
        GATE.as_posix(),
        "--worktree",
        worktree.as_posix(),
        "--output-dir",
        output.as_posix(),
        "--candidate",
        candidate,
    ]
    if artifact_only:
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
    assert evidence["candidate"] == candidate
    assert evidence["candidate_tree"] == candidate_tree
    assert evidence["mode"] == ("artifact-only" if artifact_only else "full")
    assert evidence["checks"] == expected_checks
    _validate_evidence_document(
        evidence,
        require_full=not artifact_only,
    )
