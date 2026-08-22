# Copyright (c) 2026 David Osipov
"""Fail-closed unit coverage for the offline PEP 561 gate."""
# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import subprocess
import tarfile
import warnings
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from nplg_mcp.json_types import JsonObject, load_json_value, require_json_object
from scripts import verify_pep561 as gate

if TYPE_CHECKING:
    from collections.abc import Sequence

_EXPECTED_ARTIFACT_COUNT = 2
_EXPECTED_TOOL_PROBE_COUNT = 3
_EXPECTED_FAULT_CHECK_COUNT = 4
_SHA256_HEX_LENGTH = 64


def _result(
    command: Sequence[str],
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(tuple(command), returncode, stdout, stderr)


def _minimal_worktree(root: Path) -> Path:
    root.mkdir()
    for name in ("LICENSE", "README.md", "THIRD_PARTY_NOTICES.md"):
        _ = (root / name).write_text(name, encoding="utf-8")
    _ = (root / "pyproject.toml").write_text(
        "[build-system]\nrequires=[]\nbuild-backend='setuptools.build_meta'\n",
        encoding="utf-8",
    )
    package = root / "src" / "nplg_mcp"
    package.mkdir(parents=True)
    _ = (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    _ = (package / "py.typed").write_bytes(b"")
    return root


def _valid_evidence(*, require_full: bool) -> JsonObject:
    check_result = True if require_full else None
    tool = {"sha256": "2" * 64, "version": "fixture"}
    return {
        "artifacts": {
            "sdist": {"filename": "fixture.tar.gz", "sha256": "3" * 64},
            "wheel": {"filename": "fixture.whl", "sha256": "1" * 64},
        },
        "candidate": "a" * 40 if require_full else None,
        "checks": {
            "annotation_fault_mypy": check_result,
            "annotation_fault_pyright": check_result,
            "artifact_inventory": True,
            "external_consumer_mypy": check_result,
            "external_consumer_pyright": check_result,
            "marker_fault_mypy": check_result,
            "marker_fault_pyright": check_result,
        },
        "mode": "full" if require_full else "artifact-only",
        "source_snapshot_sha256": "4" * 64,
        "toolchain": {
            "mypy": dict(tool),
            "node": dict(tool),
            "pyright": dict(tool),
        }
        if require_full
        else None,
    }


def test_path_and_digest_boundaries_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(gate.Pep561GateError, match="must be absolute"):
        _ = gate._canonical_directory(Path("relative"), boundary="fixture")
    with pytest.raises(gate.Pep561GateError, match="unavailable"):
        _ = gate._canonical_directory(
            (tmp_path / "missing").resolve(),
            boundary="fixture",
        )
    regular = (tmp_path / "regular").resolve()
    _ = regular.write_bytes(b"file")
    with pytest.raises(gate.Pep561GateError, match="canonical directory"):
        _ = gate._canonical_directory(regular, boundary="fixture")

    worktree = (tmp_path / "worktree").resolve()
    worktree.mkdir()
    with pytest.raises(gate.Pep561GateError, match="must be absolute"):
        _ = gate._prepare_output(Path("relative"), worktree=worktree)
    with pytest.raises(gate.Pep561GateError, match="parent is unavailable"):
        _ = gate._prepare_output(
            (tmp_path / "missing-parent" / "output").resolve(),
            worktree=worktree,
        )
    with pytest.raises(gate.Pep561GateError, match="overlap"):
        _ = gate._prepare_output(worktree / "output", worktree=worktree)
    existing = (tmp_path / "existing").resolve()
    existing.mkdir()
    with pytest.raises(gate.Pep561GateError, match="new canonical"):
        _ = gate._prepare_output(existing, worktree=worktree)

    reviewed = tmp_path / "reviewed"
    _ = reviewed.write_bytes(b"reviewed")
    assert (
        gate._stable_sha256(reviewed, max_bytes=64)
        == hashlib.sha256(b"reviewed").hexdigest()
    )
    empty = tmp_path / "empty"
    _ = empty.write_bytes(b"")
    with pytest.raises(gate.Pep561GateError, match="bounded regular"):
        _ = gate._stable_sha256(empty, max_bytes=64)
    with pytest.raises(gate.Pep561GateError, match="unavailable"):
        _ = gate._stable_sha256(tmp_path / "absent", max_bytes=64)

    with pytest.raises(gate.Pep561GateError, match="subprocess failed"):
        _ = gate._run(
            ("/usr/bin/false",),
            cwd=tmp_path,
            environment=gate._closed_environment(tmp_path),
        )


def test_source_snapshot_owns_only_python_and_exact_marker(tmp_path: Path) -> None:
    worktree = _minimal_worktree(tmp_path / "worktree")
    cache = worktree / "src" / "nplg_mcp" / "__pycache__"
    cache.mkdir()
    _ = (cache / "ignored.pyc").write_bytes(b"cache")

    snapshot = gate._copy_source_snapshot(worktree, tmp_path / "snapshot")

    assert (snapshot / "src" / "nplg_mcp" / "py.typed").read_bytes() == b""
    assert not (snapshot / "src" / "nplg_mcp" / "__pycache__").exists()

    _ = (worktree / "src" / "nplg_mcp" / "undeclared.bin").write_bytes(b"x")
    with pytest.raises(gate.Pep561GateError, match="undeclared package data"):
        _ = gate._copy_source_snapshot(worktree, tmp_path / "rejected")

    (worktree / "src" / "nplg_mcp" / "undeclared.bin").unlink()
    (worktree / "LICENSE").unlink()
    with pytest.raises(gate.Pep561GateError, match="required build input"):
        _ = gate._copy_source_snapshot(worktree, tmp_path / "missing-input")


def test_source_snapshot_rejects_symlinks_and_nonempty_marker(tmp_path: Path) -> None:
    worktree = _minimal_worktree(tmp_path / "worktree")
    package = worktree / "src" / "nplg_mcp"
    (package / "linked.py").symlink_to(package / "__init__.py")
    with pytest.raises(gate.Pep561GateError, match="symbolic link"):
        _ = gate._copy_source_snapshot(worktree, tmp_path / "linked")

    (package / "linked.py").unlink()
    _ = (package / "py.typed").write_bytes(b"not empty")
    with pytest.raises(gate.Pep561GateError, match="marker"):
        _ = gate._copy_source_snapshot(worktree, tmp_path / "nonempty")


def test_archive_marker_validators_reject_misplacement(tmp_path: Path) -> None:
    assert gate._canonical_archive_name("root/src/nplg_mcp/py.typed") == (
        "root/src/nplg_mcp/py.typed"
    )
    with pytest.raises(gate.Pep561GateError, match="noncanonical"):
        _ = gate._canonical_archive_name("../py.typed")

    sdist = tmp_path / "fixture-1.0.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        marker = tarfile.TarInfo("fixture-1.0/wrong/py.typed")
        marker.size = 0
        archive.addfile(marker)
    with pytest.raises(gate.Pep561GateError, match="sdist marker"):
        gate._verify_sdist_marker(sdist)

    wheel = tmp_path / "fixture-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("wrong/py.typed", b"")
    with pytest.raises(gate.Pep561GateError, match="wheel marker"):
        gate._verify_wheel_marker(wheel)

    invalid_sdist = tmp_path / "invalid.tar.gz"
    _ = invalid_sdist.write_bytes(b"invalid")
    with pytest.raises(gate.Pep561GateError, match="sdist could not"):
        gate._verify_sdist_marker(invalid_sdist)
    invalid_wheel = tmp_path / "invalid.whl"
    _ = invalid_wheel.write_bytes(b"invalid")
    with pytest.raises(gate.Pep561GateError, match="wheel could not"):
        gate._verify_wheel_marker(invalid_wheel)

    duplicate_sdist = tmp_path / "duplicate.tar.gz"
    with tarfile.open(duplicate_sdist, mode="w:gz") as archive:
        duplicate = tarfile.TarInfo("duplicate/src/nplg_mcp/py.typed")
        duplicate.size = 0
        archive.addfile(duplicate)
        archive.addfile(duplicate)
    with pytest.raises(gate.Pep561GateError, match="duplicate archive"):
        gate._verify_sdist_marker(duplicate_sdist)

    duplicate_wheel = tmp_path / "duplicate.whl"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(duplicate_wheel, mode="w") as archive:
            archive.writestr("nplg_mcp/py.typed", b"")
            archive.writestr("nplg_mcp/py.typed", b"")
    with pytest.raises(gate.Pep561GateError, match="duplicate archive"):
        gate._verify_wheel_marker(duplicate_wheel)


def test_build_requires_exact_artifact_kinds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def empty_build(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment, expected_returncode
        return _result(command)

    monkeypatch.setattr(gate, "_run", empty_build)
    (tmp_path / "empty").mkdir()
    with pytest.raises(gate.Pep561GateError, match="exactly two"):
        _ = gate._build_artifacts(tmp_path, tmp_path / "empty", environment={})

    def wrong_build(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del environment, expected_returncode
        distribution = cwd / "dist"
        _ = (distribution / "first.txt").write_bytes(b"first")
        _ = (distribution / "second.txt").write_bytes(b"second")
        return _result(command)

    monkeypatch.setattr(gate, "_run", wrong_build)
    (tmp_path / "wrong").mkdir()
    with pytest.raises(gate.Pep561GateError, match="canonical sdist"):
        _ = gate._build_artifacts(tmp_path, tmp_path / "wrong", environment={})


def test_locked_checker_toolchain_is_probed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    node = tmp_path / "node"
    _ = node.write_bytes(b"node")
    calls: list[tuple[str, ...]] = []
    digest = gate._EXPECTED_NODE_SHA256
    versions = {
        "mypy": gate._EXPECTED_MYPY_VERSION,
        "node": gate._EXPECTED_NODE_VERSION,
        "pyright": gate._EXPECTED_PYRIGHT_VERSION,
    }

    def fake_digest(path: Path, *, max_bytes: int) -> str:
        del max_bytes
        return digest if path == node else "0" * 64

    def fake_run(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment, expected_returncode
        canonical = tuple(command)
        calls.append(canonical)
        if canonical[-1] != "--version":
            raise AssertionError
        if (
            canonical[0] == node.as_posix()
            and len(canonical) == _EXPECTED_ARTIFACT_COUNT
        ):
            return _result(canonical, stdout=versions["node"])
        if canonical[0] == node.as_posix():
            return _result(canonical, stdout=versions["pyright"])
        return _result(canonical, stdout=versions["mypy"])

    monkeypatch.setattr(gate, "_stable_sha256", fake_digest)
    monkeypatch.setattr(gate, "_run", fake_run)

    pyright, mypy = gate._validate_toolchain(
        worktree,
        node,
        environment={},
    )

    assert pyright == worktree / "node_modules" / "pyright" / "index.js"
    assert mypy == worktree / ".venv" / "bin" / "mypy"
    assert len(calls) == _EXPECTED_TOOL_PROBE_COUNT

    digest = "f" * 64
    with pytest.raises(gate.Pep561GateError, match="locked digest"):
        _ = gate._validate_toolchain(worktree, node, environment={})
    digest = gate._EXPECTED_NODE_SHA256
    for tool, message in (
        ("node", "Node version"),
        ("pyright", "Pyright"),
        ("mypy", "mypy"),
    ):
        expected = versions[tool]
        versions[tool] = b"wrong\n"
        with pytest.raises(gate.Pep561GateError, match=message):
            _ = gate._validate_toolchain(worktree, node, environment={})
        versions[tool] = expected


def test_consumer_environment_is_external_and_marker_owned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    wheel = tmp_path / "fixture.whl"
    _ = wheel.write_bytes(b"wheel")
    root = tmp_path / "consumer"

    def fake_run(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment, expected_returncode
        canonical = tuple(command)
        if "venv" in canonical:
            python = root / "venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            _ = python.write_bytes(b"python")
        if "sysconfig.get_path" in " ".join(canonical):
            purelib = root / "venv" / "lib" / "site-packages"
            package = purelib / "nplg_mcp"
            package.mkdir(parents=True)
            _ = (package / "py.typed").write_bytes(b"")
            return _result(canonical, stdout=f"{purelib}\n".encode())
        if "nplg_mcp,sys" in " ".join(canonical):
            return _result(canonical, stdout=b'{"module":"external","paths":[]}\n')
        return _result(canonical)

    monkeypatch.setattr(gate, "_run", fake_run)

    project, python, package = gate._prepare_consumer(
        root,
        wheel,
        worktree=worktree,
        environment={},
    )

    assert python == root / "venv" / "bin" / "python"
    assert package == root / "venv" / "lib" / "site-packages" / "nplg_mcp"
    assert "ToolCatalog" in (project / "consumer.py").read_text(encoding="utf-8")
    assert (project / "pyrightconfig.json").is_file()


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("checkout", "source checkout"),
        ("decode", "could not be resolved"),
        ("marker", "marker is absent"),
        ("probe", "leaked into"),
    ],
)
def test_consumer_environment_rejects_isolation_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    message: str,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    root = tmp_path / "consumer"

    def fault_run(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment, expected_returncode
        canonical = tuple(command)
        joined = " ".join(canonical)
        if "sysconfig.get_path" in joined:
            if fault == "decode":
                return _result(canonical, stdout=b"\xff")
            purelib = worktree if fault == "checkout" else root / "purelib"
            package = purelib / "nplg_mcp"
            package.mkdir(parents=True)
            if fault != "marker":
                _ = (package / "py.typed").write_bytes(b"")
            return _result(canonical, stdout=f"{purelib}\n".encode())
        if "nplg_mcp,sys" in joined:
            probe = worktree.as_posix() if fault == "probe" else "external"
            return _result(canonical, stdout=f"{probe}\n".encode())
        return _result(canonical)

    monkeypatch.setattr(gate, "_run", fault_run)
    with pytest.raises(gate.Pep561GateError, match=message):
        _ = gate._prepare_consumer(
            root,
            tmp_path / "wheel",
            worktree=worktree,
            environment={},
        )


def test_checker_results_require_named_success_and_fault_reasons(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands = (("pyright",), ("mypy",))

    def successful_run(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment, expected_returncode
        if tuple(command) == commands[0]:
            return _result(command, stdout=b'{"summary":{"errorCount":0}}')
        return _result(command, stdout=b"Success: no issues found in 1 source file\n")

    monkeypatch.setattr(gate, "_run", successful_run)
    gate._run_canonical_checkers(commands, project=tmp_path, environment={})
    checker_commands = gate._checker_commands(
        node=tmp_path / "node",
        pyright=tmp_path / "pyright",
        mypy=tmp_path / "mypy",
        project=tmp_path,
        python=tmp_path / "python",
    )
    assert checker_commands[0][0] == (tmp_path / "node").as_posix()

    def bad_pyright(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment, expected_returncode
        return _result(command, stdout=b'{"summary":{"errorCount":1}}')

    monkeypatch.setattr(gate, "_run", bad_pyright)
    with pytest.raises(gate.Pep561GateError, match="canonical Pyright"):
        gate._run_canonical_checkers(commands, project=tmp_path, environment={})

    def bad_mypy(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment, expected_returncode
        stdout = b'{"summary":{"errorCount":0}}' if command[0] == "pyright" else b""
        return _result(command, stdout=stdout)

    monkeypatch.setattr(gate, "_run", bad_mypy)
    with pytest.raises(gate.Pep561GateError, match="canonical mypy"):
        gate._run_canonical_checkers(commands, project=tmp_path, environment={})

    def fault_run(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, environment
        assert expected_returncode == 1
        return _result(command, returncode=1, stderr=b"missing py.typed marker")

    monkeypatch.setattr(gate, "_run", fault_run)
    gate._run_fault_checker(
        ("mypy",),
        project=tmp_path,
        environment={},
        expected_terms=(b"py.typed",),
        fault="missing-marker mypy",
    )
    with pytest.raises(gate.Pep561GateError, match="unexpected reason"):
        gate._run_fault_checker(
            ("mypy",),
            project=tmp_path,
            environment={},
            expected_terms=(b"annotation",),
            fault="missing annotation",
        )


def test_external_consumer_fault_copies_delete_only_the_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared: dict[str, Path] = {}
    canonical_calls: list[Path] = []
    fault_calls: list[str] = []

    def fake_prepare(
        root: Path,
        wheel: Path,
        *,
        worktree: Path,
        environment: dict[str, str],
    ) -> tuple[Path, Path, Path]:
        del wheel, worktree, environment
        project = root / "project"
        package = root / "site-packages" / "nplg_mcp"
        (package / "contracts").mkdir(parents=True)
        project.mkdir()
        _ = (package / "py.typed").write_bytes(b"")
        _ = (package / "contracts" / "catalog.py").write_text(
            "    def output_model(self) -> type[StrictOutput]:\n",
            encoding="utf-8",
        )
        prepared[root.name] = package
        return project, root / "python", package

    def fake_commands(
        *,
        node: Path,
        pyright: Path,
        mypy: Path,
        project: Path,
        python: Path,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        del node, pyright, mypy, python
        return ((f"{project.parent.name}-pyright",), (f"{project.parent.name}-mypy",))

    def fake_canonical(
        commands: tuple[tuple[str, ...], tuple[str, ...]],
        *,
        project: Path,
        environment: dict[str, str],
    ) -> None:
        del commands, environment
        canonical_calls.append(project)

    def fake_fault(
        command: tuple[str, ...],
        *,
        project: Path,
        environment: dict[str, str],
        expected_terms: tuple[bytes, ...],
        fault: str,
    ) -> None:
        del command, project, environment, expected_terms
        fault_calls.append(fault)

    monkeypatch.setattr(gate, "_prepare_consumer", fake_prepare)
    monkeypatch.setattr(gate, "_checker_commands", fake_commands)
    monkeypatch.setattr(gate, "_run_canonical_checkers", fake_canonical)
    monkeypatch.setattr(gate, "_run_fault_checker", fake_fault)
    context = gate._ConsumerContext(
        worktree=tmp_path / "worktree",
        node=tmp_path / "node",
        pyright=tmp_path / "pyright",
        mypy=tmp_path / "mypy",
        environment={},
    )

    gate._verify_external_consumers(
        tmp_path / "work",
        tmp_path / "wheel",
        context=context,
    )

    assert len(canonical_calls) == 1
    assert len(fault_calls) == _EXPECTED_FAULT_CHECK_COUNT
    assert not (prepared["marker-fault"] / "py.typed").exists()
    annotation_source = (
        prepared["annotation-fault"] / "contracts" / "catalog.py"
    ).read_text(encoding="utf-8")
    assert "-> type[StrictOutput]" not in annotation_source


def test_annotation_fault_target_must_be_unique(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_prepare(
        root: Path,
        wheel: Path,
        *,
        worktree: Path,
        environment: dict[str, str],
    ) -> tuple[Path, Path, Path]:
        del wheel, worktree, environment
        project = root / "project"
        package = root / "package"
        (package / "contracts").mkdir(parents=True)
        project.mkdir()
        _ = (package / "py.typed").write_bytes(b"")
        _ = (package / "contracts" / "catalog.py").write_text(
            "class RegisteredTool: pass\n",
            encoding="utf-8",
        )
        return project, root / "python", package

    def ignore_canonical(
        commands: tuple[tuple[str, ...], tuple[str, ...]],
        *,
        project: Path,
        environment: dict[str, str],
    ) -> None:
        del commands, project, environment

    def ignore_fault(
        command: tuple[str, ...],
        *,
        project: Path,
        environment: dict[str, str],
        expected_terms: tuple[bytes, ...],
        fault: str,
    ) -> None:
        del command, project, environment, expected_terms, fault

    monkeypatch.setattr(gate, "_prepare_consumer", fake_prepare)
    monkeypatch.setattr(gate, "_run_canonical_checkers", ignore_canonical)
    monkeypatch.setattr(gate, "_run_fault_checker", ignore_fault)
    context = gate._ConsumerContext(
        worktree=tmp_path / "worktree",
        node=tmp_path / "node",
        pyright=tmp_path / "pyright",
        mypy=tmp_path / "mypy",
        environment={},
    )

    with pytest.raises(gate.Pep561GateError, match="target is not unique"):
        gate._verify_external_consumers(
            tmp_path / "work",
            tmp_path / "wheel",
            context=context,
        )


def test_verify_full_mode_records_external_consumer_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = _minimal_worktree(tmp_path / "worktree").resolve()
    output = tmp_path / "evidence"
    node = tmp_path / "node"
    _ = node.write_bytes(b"node")
    pyright = tmp_path / "pyright"
    _ = pyright.write_bytes(b"pyright")
    mypy = tmp_path / "mypy"
    _ = mypy.write_bytes(b"mypy")
    external_calls: list[gate._ConsumerContext] = []

    def fake_build(
        source: Path,
        work: Path,
        *,
        environment: dict[str, str],
    ) -> tuple[Path, Path]:
        del source, environment
        distribution = work / "fake-dist"
        distribution.mkdir()
        sdist = distribution / "fixture.tar.gz"
        wheel = distribution / "fixture.whl"
        _ = sdist.write_bytes(b"sdist")
        _ = wheel.write_bytes(b"wheel")
        return sdist, wheel

    def fake_toolchain(
        root: Path,
        reviewed_node: Path,
        *,
        environment: dict[str, str],
    ) -> tuple[Path, Path]:
        del root, reviewed_node, environment
        return pyright, mypy

    def fake_external(
        work: Path,
        wheel: Path,
        *,
        context: gate._ConsumerContext,
    ) -> None:
        del work, wheel
        external_calls.append(context)

    monkeypatch.setattr(gate, "_build_artifacts", fake_build)
    monkeypatch.setattr(gate, "_validate_toolchain", fake_toolchain)
    monkeypatch.setattr(gate, "_verify_external_consumers", fake_external)

    gate.verify(
        worktree=worktree,
        output_dir=output,
        node_executable=node,
        artifact_only=False,
        candidate="a" * 40,
    )

    assert len(external_calls) == 1
    assert (output / "dist" / "fixture.tar.gz").read_bytes() == b"sdist"
    evidence = require_json_object(
        load_json_value((output / "pep561-evidence.json").read_bytes()),
        context="full PEP 561 evidence",
    )
    assert evidence["mode"] == "full"
    assert evidence["candidate"] == "a" * 40
    assert isinstance(evidence["source_snapshot_sha256"], str)
    artifacts = require_json_object(evidence["artifacts"], context="artifacts")
    assert frozenset(artifacts) == {"sdist", "wheel"}
    toolchain = require_json_object(evidence["toolchain"], context="toolchain")
    assert frozenset(toolchain) == {"mypy", "node", "pyright"}
    for tool in toolchain.values():
        identity = require_json_object(tool, context="tool identity")
        assert isinstance(identity["version"], str)
        digest = identity["sha256"]
        assert isinstance(digest, str)
        assert len(digest) == _SHA256_HEX_LENGTH
    gate._validate_evidence_document(evidence, require_full=True)
    with pytest.raises(gate.Pep561GateError, match="requires reviewed Node"):
        gate.verify(
            worktree=worktree,
            output_dir=tmp_path / "missing-node-evidence",
            node_executable=None,
            artifact_only=False,
            candidate="b" * 40,
        )


@pytest.mark.parametrize(
    "fault",
    [
        "candidate",
        "source_snapshot_sha256",
        "wheel_sha256",
        "sdist_sha256",
        "pyright_sha256",
        "mypy_sha256",
        "node_sha256",
    ],
)
def test_full_evidence_rejects_missing_identity_and_digest_fields(fault: str) -> None:
    artifact = {"filename": "fixture.whl", "sha256": "1" * 64}
    tool = {"sha256": "2" * 64, "version": "fixture"}
    evidence: JsonObject = {
        "artifacts": {
            "sdist": {"filename": "fixture.tar.gz", "sha256": "3" * 64},
            "wheel": dict(artifact),
        },
        "candidate": "a" * 40,
        "checks": {
            "annotation_fault_mypy": True,
            "annotation_fault_pyright": True,
            "artifact_inventory": True,
            "external_consumer_mypy": True,
            "external_consumer_pyright": True,
            "marker_fault_mypy": True,
            "marker_fault_pyright": True,
        },
        "mode": "full",
        "source_snapshot_sha256": "4" * 64,
        "toolchain": {
            "mypy": dict(tool),
            "node": dict(tool),
            "pyright": dict(tool),
        },
    }
    if fault in {"candidate", "source_snapshot_sha256"}:
        del evidence[fault]
    elif fault in {"wheel_sha256", "sdist_sha256"}:
        name = fault.removesuffix("_sha256")
        record = require_json_object(
            require_json_object(evidence["artifacts"], context="artifacts")[name],
            context=name,
        )
        del record["sha256"]
    else:
        name = fault.removesuffix("_sha256")
        record = require_json_object(
            require_json_object(evidence["toolchain"], context="toolchain")[name],
            context=name,
        )
        del record["sha256"]
    with pytest.raises(gate.Pep561GateError, match="evidence"):
        gate._validate_evidence_document(evidence, require_full=True)


@pytest.mark.parametrize(
    "fault",
    ["mode", "candidate", "source-digest"],
)
def test_full_evidence_rejects_top_level_authority_faults(fault: str) -> None:
    evidence = _valid_evidence(require_full=True)
    if fault == "mode":
        evidence["mode"] = "artifact-only"
    elif fault == "candidate":
        evidence["candidate"] = None
    elif fault == "source-digest":
        evidence["source_snapshot_sha256"] = "g" * 64

    with pytest.raises(gate.Pep561GateError, match="evidence"):
        gate._validate_evidence_document(evidence, require_full=True)


@pytest.mark.parametrize(
    "fault",
    [
        "mapping",
        "inventory",
        "filename-type",
        "filename-empty",
        "filename-path",
        "digest",
    ],
)
def test_full_evidence_rejects_adversarial_artifact_faults(fault: str) -> None:
    evidence = _valid_evidence(require_full=True)
    if fault == "mapping":
        evidence["artifacts"] = []
    elif fault == "inventory":
        artifacts = require_json_object(evidence["artifacts"], context="artifacts")
        del artifacts["sdist"]
    else:
        artifacts = require_json_object(evidence["artifacts"], context="artifacts")
        wheel = require_json_object(artifacts["wheel"], context="wheel")
        if fault == "filename-type":
            wheel["filename"] = 1
        elif fault == "filename-empty":
            wheel["filename"] = ""
        elif fault == "filename-path":
            wheel["filename"] = "nested/fixture.whl"
        else:
            wheel["sha256"] = "g" * 64

    with pytest.raises(gate.Pep561GateError, match="evidence"):
        gate._validate_evidence_document(evidence, require_full=True)


@pytest.mark.parametrize(
    "fault",
    [
        "check-inventory",
        "check-result",
        "toolchain-inventory",
        "toolchain-digest",
        "toolchain-version-type",
        "toolchain-version-empty",
    ],
)
def test_full_evidence_rejects_check_and_toolchain_faults(fault: str) -> None:
    evidence = _valid_evidence(require_full=True)
    if fault == "check-inventory":
        checks = require_json_object(evidence["checks"], context="checks")
        del checks["marker_fault_mypy"]
    elif fault == "check-result":
        checks = require_json_object(evidence["checks"], context="checks")
        checks["marker_fault_mypy"] = False
    else:
        toolchain = require_json_object(evidence["toolchain"], context="toolchain")
        if fault == "toolchain-inventory":
            del toolchain["mypy"]
        else:
            mypy = require_json_object(toolchain["mypy"], context="mypy")
            if fault == "toolchain-digest":
                mypy["sha256"] = "g" * 64
            elif fault == "toolchain-version-type":
                mypy["version"] = 1
            else:
                mypy["version"] = ""

    with pytest.raises(gate.Pep561GateError, match="evidence"):
        gate._validate_evidence_document(evidence, require_full=True)


@pytest.mark.parametrize("fault", ["candidate", "toolchain", "check-result"])
def test_artifact_only_evidence_rejects_full_authority_claims(fault: str) -> None:
    evidence = _valid_evidence(require_full=False)
    if fault == "candidate":
        evidence["candidate"] = "not-a-candidate"
    elif fault == "toolchain":
        evidence["toolchain"] = {"mypy": {"sha256": "2" * 64, "version": "fixture"}}
    else:
        checks = require_json_object(evidence["checks"], context="checks")
        checks["marker_fault_mypy"] = True

    with pytest.raises(gate.Pep561GateError, match="evidence"):
        gate._validate_evidence_document(evidence, require_full=False)


def test_cli_returns_fail_closed_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    def successful_verify(**_arguments: object) -> None:
        return None

    monkeypatch.setattr(gate, "verify", successful_verify)
    arguments = (
        "--worktree",
        tmp_path.as_posix(),
        "--output-dir",
        (tmp_path / "output").as_posix(),
        "--artifact-only",
    )
    assert gate.main(arguments) == 0
    assert "passed" in capfd.readouterr().out

    def failed_verify(**_arguments: object) -> None:
        message = "fixture failure"
        raise gate.Pep561GateError(message)

    monkeypatch.setattr(gate, "verify", failed_verify)
    assert gate.main(arguments) == 1
    assert "fixture failure" in capfd.readouterr().err
