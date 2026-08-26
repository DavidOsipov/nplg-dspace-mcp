# Copyright (c) 2026 David Osipov
"""Fail-closed unit coverage for the offline PEP 561 gate."""
# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import io
import os
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
    from typing import BinaryIO

_EXPECTED_ARTIFACT_COUNT = 2
_EXPECTED_TOOL_PROBE_COUNT = 3
_EXPECTED_FAULT_CHECK_COUNT = 4
_SHA256_HEX_LENGTH = 64
_SECOND_IDENTITY_READ = 2


def test_source_snapshot_identity_ignores_atime_but_detects_mutation(
    tmp_path: Path,
) -> None:
    baseline = os.stat_result((0o100600, 11, 22, 1, 1000, 1000, 7, 31, 41, 51))
    accessed = os.stat_result((0o100600, 11, 22, 1, 1000, 1000, 7, 32, 41, 51))
    assert gate._stable_file_identity(accessed) == gate._stable_file_identity(baseline)

    member = tmp_path / "member.py"
    _ = member.write_bytes(b"a")
    before = member.lstat()
    _ = member.write_bytes(b"changed")

    assert gate._stable_file_identity(member.lstat()) != gate._stable_file_identity(
        before
    )


def test_stable_digest_binds_the_opened_file_against_path_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reviewed = tmp_path / "reviewed"
    _ = reviewed.write_bytes(b"GOOD")
    substituted = b"EVIL"

    def substituted_open(
        path: Path,
        mode: str = "r",
    ) -> BinaryIO:
        assert path == reviewed
        assert mode == "rb"
        return io.BytesIO(substituted)

    monkeypatch.setattr(Path, "open", substituted_open)

    assert (
        gate._stable_sha256(reviewed, max_bytes=4)
        == hashlib.sha256(b"GOOD").hexdigest()
    )


def test_tree_digest_binds_the_opened_file_against_path_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    member = root / "member.py"
    _ = member.write_bytes(b"GOOD")
    expected = gate._tree_sha256(root)
    real_read_bytes = Path.read_bytes

    def substituted_read(path: Path) -> bytes:
        if path == member:
            return b"EVIL"
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", substituted_read)

    assert gate._tree_sha256(root) == expected


def test_source_copy_binds_the_opened_file_against_path_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = _minimal_worktree(tmp_path / "worktree-race")
    source = worktree / "src" / "nplg_mcp" / "__init__.py"
    expected = source.read_bytes()
    assert len(expected) == len(b"VALUE = 2\n")
    real_read_bytes = Path.read_bytes

    def substituted_read(path: Path) -> bytes:
        if path == source:
            return b"VALUE = 2\n"
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", substituted_read)
    snapshot = gate._copy_source_snapshot(worktree, tmp_path / "snapshot-race")

    assert (snapshot / "src" / "nplg_mcp" / "__init__.py").read_bytes() == expected


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


def _commit_candidate(worktree: Path) -> tuple[str, str]:
    environment = {
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": worktree.as_posix(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    commands = (
        ("/usr/bin/git", "init", "--quiet"),
        (
            "/usr/bin/git",
            "add",
            "--",
            "LICENSE",
            "README.md",
            "THIRD_PARTY_NOTICES.md",
            "pyproject.toml",
            "src/nplg_mcp",
        ),
        (
            "/usr/bin/git",
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
            "fixture candidate",
        ),
    )
    for command in commands:
        _ = subprocess.run(  # noqa: S603
            command,
            cwd=worktree,
            env=environment,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )

    def resolve(revision: str) -> str:
        result = subprocess.run(  # noqa: S603
            ("/usr/bin/git", "rev-parse", "--verify", revision),
            cwd=worktree,
            env=environment,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        return result.stdout.decode("ascii", errors="strict").strip()

    return resolve("HEAD"), resolve("HEAD^{tree}")


def _valid_evidence(*, require_full: bool) -> JsonObject:
    check_result = True if require_full else None
    tool = {"sha256": "2" * 64, "version": "fixture"}
    return {
        "artifacts": {
            "sdist": {"filename": "fixture.tar.gz", "sha256": "3" * 64},
            "wheel": {"filename": "fixture.whl", "sha256": "1" * 64},
        },
        "candidate": "a" * 40 if require_full else None,
        "candidate_tree": "b" * 40 if require_full else None,
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

    assert (
        gate._run(
            ("/usr/bin/true",),
            cwd=tmp_path,
            environment=gate._closed_environment(tmp_path),
        ).returncode
        == 0
    )
    with pytest.raises(gate.Pep561GateError, match="subprocess failed"):
        _ = gate._run(
            ("/usr/bin/false",),
            cwd=tmp_path,
            environment=gate._closed_environment(tmp_path),
        )


def test_stable_digest_rejects_growth_read_failure_and_size_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_lstat = Path.lstat
    real_fstat = os.fstat

    grown = tmp_path / "grown"
    _ = grown.write_bytes(b"x" * 65)

    def undersized_lstat(path: Path) -> os.stat_result:
        metadata = real_lstat(path)
        if path == grown:
            fields = list(metadata)
            fields[6] = 64
            return os.stat_result(fields)
        return metadata

    def undersized_fstat(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        fields = list(metadata)
        fields[6] = 64
        return os.stat_result(fields)

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "lstat", undersized_lstat)
        scoped.setattr(os, "fstat", undersized_fstat)
        with pytest.raises(gate.Pep561GateError, match="exceeded its byte ceiling"):
            _ = gate._stable_sha256(grown, max_bytes=64)

    disappearing = tmp_path / "disappearing"
    _ = disappearing.write_bytes(b"payload")

    def removing_lstat(path: Path) -> os.stat_result:
        metadata = real_lstat(path)
        if path == disappearing:
            path.unlink()
        return metadata

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "lstat", removing_lstat)
        with pytest.raises(gate.Pep561GateError, match="could not be read"):
            _ = gate._stable_sha256(disappearing, max_bytes=64)

    drifted = tmp_path / "drifted"
    _ = drifted.write_bytes(b"drift")

    def wrong_size_lstat(path: Path) -> os.stat_result:
        metadata = real_lstat(path)
        if path == drifted:
            fields = list(metadata)
            fields[6] += 1
            return os.stat_result(fields)
        return metadata

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "lstat", wrong_size_lstat)
        with pytest.raises(gate.Pep561GateError, match="changed while it was read"):
            _ = gate._stable_sha256(drifted, max_bytes=64)


def test_descriptor_reader_fails_closed_without_nofollow_on_open_or_close_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reviewed = tmp_path / "descriptor-errors"
    _ = reviewed.write_bytes(b"payload")
    metadata = reviewed.lstat()
    policy = gate._StableReadPolicy(
        max_bytes=64,
        read_error="descriptor read failed",
        changed_error="descriptor identity changed",
        ceiling_error="descriptor exceeded ceiling",
    )

    with monkeypatch.context() as scoped:
        scoped.delattr(os, "O_NOFOLLOW")
        with pytest.raises(gate.Pep561GateError, match="descriptor read failed"):
            _ = gate._read_stable_file(
                reviewed,
                before=metadata,
                policy=policy,
                consume=bytearray().extend,
            )

    def failing_open(_path: Path, _flags: int) -> int:
        message = "simulated open failure"
        raise OSError(message)

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "open", failing_open)
        with pytest.raises(gate.Pep561GateError, match="descriptor read failed"):
            _ = gate._read_stable_file(
                reviewed,
                before=metadata,
                policy=policy,
                consume=bytearray().extend,
            )

    def failing_read(_descriptor: int, _maximum_bytes: int) -> bytes:
        message = "simulated read failure"
        raise OSError(message)

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "read", failing_read)
        with pytest.raises(gate.Pep561GateError, match="descriptor read failed"):
            _ = gate._read_stable_file(
                reviewed,
                before=metadata,
                policy=policy,
                consume=bytearray().extend,
            )

    real_close = os.close

    def failing_close(descriptor: int) -> None:
        real_close(descriptor)
        message = "simulated close failure"
        raise OSError(message)

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "close", failing_close)
        with pytest.raises(gate.Pep561GateError, match="descriptor read failed"):
            _ = gate._read_stable_file(
                reviewed,
                before=metadata,
                policy=policy,
                consume=bytearray().extend,
            )


def test_descriptor_reader_consumes_one_exact_stable_file(tmp_path: Path) -> None:
    reviewed = tmp_path / "stable-descriptor"
    payload = b"descriptor-bound payload"
    _ = reviewed.write_bytes(payload)
    consumed = bytearray()

    total = gate._read_stable_file(
        reviewed,
        before=reviewed.lstat(),
        policy=gate._StableReadPolicy(
            max_bytes=len(payload),
            read_error="descriptor read failed",
            changed_error="descriptor identity changed",
            ceiling_error="descriptor exceeded ceiling",
        ),
        consume=consumed.extend,
    )

    assert total == len(payload)
    assert bytes(consumed) == payload


def test_descriptor_reader_rejects_a_preopen_identity_mismatch(tmp_path: Path) -> None:
    reviewed = tmp_path / "identity-mismatch"
    _ = reviewed.write_bytes(b"payload")
    metadata_fields = list(reviewed.lstat())
    metadata_fields[1] += 1
    mismatched_identity = os.stat_result(metadata_fields)
    consumed = bytearray()

    with pytest.raises(gate.Pep561GateError, match="descriptor identity changed"):
        _ = gate._read_stable_file(
            reviewed,
            before=mismatched_identity,
            policy=gate._StableReadPolicy(
                max_bytes=64,
                read_error="descriptor read failed",
                changed_error="descriptor identity changed",
                ceiling_error="descriptor exceeded ceiling",
            ),
            consume=consumed.extend,
        )

    assert consumed == b""


def test_tree_digest_rejects_symlink_special_read_and_identity_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symlink_root = tmp_path / "symlink-tree"
    symlink_root.mkdir()
    target = symlink_root / "target"
    _ = target.write_bytes(b"target")
    (symlink_root / "alias").symlink_to(target)
    with pytest.raises(gate.Pep561GateError, match="symbolic link"):
        _ = gate._tree_sha256(symlink_root)

    special_root = tmp_path / "special-tree"
    special_root.mkdir()
    os.mkfifo(special_root / "pipe")
    with pytest.raises(gate.Pep561GateError, match="non-regular file"):
        _ = gate._tree_sha256(special_root)

    read_root = tmp_path / "read-tree"
    read_root.mkdir()
    disappearing = read_root / "member"
    _ = disappearing.write_bytes(b"member")
    real_open = os.open

    def removing_open(path: Path, flags: int) -> int:
        if path == disappearing:
            path.unlink()
        return real_open(path, flags)

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "open", removing_open)
        with pytest.raises(gate.Pep561GateError, match="could not read a file"):
            _ = gate._tree_sha256(read_root)

    identity_root = tmp_path / "identity-tree"
    identity_root.mkdir()
    member = identity_root / "member"
    _ = member.write_bytes(b"member")
    real_lstat = Path.lstat
    calls = 0

    def drifting_lstat(path: Path) -> os.stat_result:
        nonlocal calls
        metadata = real_lstat(path)
        if path == member:
            calls += 1
            if calls == _SECOND_IDENTITY_READ:
                fields = list(metadata)
                fields[1] += 1
                return os.stat_result(fields)
        return metadata

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "lstat", drifting_lstat)
        with pytest.raises(gate.Pep561GateError, match="changed while it was digested"):
            _ = gate._tree_sha256(identity_root)


def test_evidence_mapping_and_source_copy_reject_nonregular_members(
    tmp_path: Path,
) -> None:
    with pytest.raises(gate.Pep561GateError, match="non-string key"):
        _ = gate._require_evidence_mapping({1: "value"}, context="fixture")

    worktree = _minimal_worktree(tmp_path / "nested-worktree")
    package = worktree / "src" / "nplg_mcp"
    nested = package / "nested"
    nested.mkdir()
    _ = (nested / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    snapshot = gate._copy_source_snapshot(worktree, tmp_path / "nested-snapshot")
    assert (snapshot / "src" / "nplg_mcp" / "nested" / "module.py").is_file()

    special_worktree = _minimal_worktree(tmp_path / "special-worktree")
    os.mkfifo(special_worktree / "src" / "nplg_mcp" / "pipe")
    with pytest.raises(gate.Pep561GateError, match="non-regular file"):
        _ = gate._copy_source_snapshot(special_worktree, tmp_path / "special-snapshot")


def test_subprocess_output_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def oversized_run(
        *_arguments: object,
        **_keywords: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return _result(("fixture",), stdout=b"x" * (gate._MAX_OUTPUT_BYTES + 1))

    monkeypatch.setattr(subprocess, "run", oversized_run)
    with pytest.raises(gate.Pep561GateError, match="output bound"):
        _ = gate._run(("fixture",), cwd=tmp_path, environment={})


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
    required_worktree = _minimal_worktree(tmp_path / "required-worktree")
    required_input = required_worktree / "LICENSE"
    required_target = tmp_path / "license-target"
    _ = required_target.write_bytes(b"license")
    required_input.unlink()
    required_input.symlink_to(required_target)
    with pytest.raises(gate.Pep561GateError, match="required build input"):
        _ = gate._copy_source_snapshot(
            required_worktree,
            tmp_path / "required-linked",
        )

    worktree = _minimal_worktree(tmp_path / "worktree")
    package = worktree / "src" / "nplg_mcp"
    (package / "linked.py").symlink_to(package / "__init__.py")
    with pytest.raises(gate.Pep561GateError, match="symbolic link"):
        _ = gate._copy_source_snapshot(worktree, tmp_path / "linked")

    (package / "linked.py").unlink()
    _ = (package / "py.typed").write_bytes(b"not empty")
    with pytest.raises(gate.Pep561GateError, match="marker"):
        _ = gate._copy_source_snapshot(worktree, tmp_path / "nonempty")


def test_source_snapshot_rejects_a_symlinked_package_ancestor(
    tmp_path: Path,
) -> None:
    worktree = _minimal_worktree(tmp_path / "worktree-ancestor")
    package = worktree / "src" / "nplg_mcp"
    (package / "__init__.py").unlink()
    (package / "py.typed").unlink()
    package.rmdir()
    external_package = tmp_path / "external-package"
    external_package.mkdir()
    external_payload = b"EXTERNAL_VALUE = 1\n"
    _ = (external_package / "__init__.py").write_bytes(external_payload)
    _ = (external_package / "py.typed").write_bytes(b"")
    package.symlink_to(external_package, target_is_directory=True)
    snapshot = tmp_path / "ancestor-snapshot"

    with pytest.raises(gate.Pep561GateError, match="source package directory"):
        _ = gate._copy_source_snapshot(worktree, snapshot)

    assert not (snapshot / "src" / "nplg_mcp" / "__init__.py").exists()


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


@pytest.mark.parametrize(
    "marker_payload",
    [None, b"not-empty"],
    ids=("missing-stream", "nonempty-stream"),
)
def test_sdist_marker_rejects_missing_or_nonempty_extracted_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    marker_payload: bytes | None,
) -> None:
    sdist = tmp_path / "fixture-1.0.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        marker = tarfile.TarInfo("fixture-1.0/src/nplg_mcp/py.typed")
        marker.size = 0
        archive.addfile(marker)

    def extracted_stream(
        _archive: tarfile.TarFile,
        _member: tarfile.TarInfo,
    ) -> io.BytesIO | None:
        return None if marker_payload is None else io.BytesIO(marker_payload)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", extracted_stream)
    with pytest.raises(gate.Pep561GateError, match="marker payload is not empty"):
        gate._verify_sdist_marker(sdist)


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


def test_build_accepts_exact_bounded_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work = tmp_path / "work"
    work.mkdir()

    def exact_build(
        command: Sequence[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        del environment, expected_returncode
        distribution = cwd / "dist"
        sdist = distribution / "fixture-1.0.tar.gz"
        with tarfile.open(sdist, mode="w:gz") as archive:
            marker = tarfile.TarInfo("fixture-1.0/src/nplg_mcp/py.typed")
            marker.size = 0
            archive.addfile(marker)
        wheel = distribution / "fixture-1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, mode="w") as archive:
            archive.writestr("nplg_mcp/py.typed", b"")
        return _result(command)

    monkeypatch.setattr(gate, "_run", exact_build)

    sdist, wheel = gate._build_artifacts(tmp_path, work, environment={})

    assert sdist.name == "fixture-1.0.tar.gz"
    assert wheel.name == "fixture-1.0-py3-none-any.whl"


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


@pytest.mark.parametrize(
    ("artifact_only", "candidate", "message"),
    [
        (False, None, "requires an exact candidate SHA"),
        (True, "not-a-candidate", "candidate SHA is invalid"),
    ],
    ids=("full-missing-candidate", "artifact-invalid-candidate"),
)
def test_verify_rejects_mode_confused_candidate_before_output(
    tmp_path: Path,
    *,
    artifact_only: bool,
    candidate: str | None,
    message: str,
) -> None:
    worktree = _minimal_worktree(tmp_path / "worktree").resolve()
    output = tmp_path / "evidence"

    with pytest.raises(gate.Pep561GateError, match=message):
        gate.verify(
            worktree=worktree,
            output_dir=output,
            node_executable=None,
            artifact_only=artifact_only,
            candidate=candidate,
        )

    assert not output.exists()


def test_verify_artifact_only_records_no_toolchain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = _minimal_worktree(tmp_path / "worktree").resolve()
    output = tmp_path / "evidence"

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

    monkeypatch.setattr(gate, "_build_artifacts", fake_build)

    gate.verify(
        worktree=worktree,
        output_dir=output,
        node_executable=None,
        artifact_only=True,
        candidate=None,
    )

    evidence = require_json_object(
        load_json_value((output / "pep561-evidence.json").read_bytes()),
        context="artifact-only evidence",
    )
    assert evidence["mode"] == "artifact-only"
    assert evidence["candidate_tree"] is None
    assert evidence["toolchain"] is None


def test_verify_full_mode_rejects_candidate_whose_tree_differs_from_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = _minimal_worktree(tmp_path / "candidate-worktree").resolve()
    candidate, _candidate_tree = _commit_candidate(worktree)
    _ = (worktree / "src" / "nplg_mcp" / "__init__.py").write_text(
        "VALUE = 2\n",
        encoding="utf-8",
    )
    output = tmp_path / "mismatched-candidate-evidence"
    node = tmp_path / "node"
    pyright = tmp_path / "pyright"
    mypy = tmp_path / "mypy"
    build_calls: list[Path] = []
    external_calls: list[gate._ConsumerContext] = []
    for tool in (node, pyright, mypy):
        _ = tool.write_bytes(tool.name.encode())

    def fake_build(
        source: Path,
        work: Path,
        *,
        environment: dict[str, str],
    ) -> tuple[Path, Path]:
        del source, environment
        build_calls.append(work)
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

    with pytest.raises(
        gate.Pep561GateError,
        match="candidate source tree does not match the captured snapshot",
    ):
        gate.verify(
            worktree=worktree,
            output_dir=output,
            node_executable=node,
            artifact_only=False,
            candidate=candidate,
        )

    assert not (output / "pep561-evidence.json").exists()
    assert build_calls == []
    assert external_calls == []


def test_verify_full_mode_records_external_consumer_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = _minimal_worktree(tmp_path / "worktree").resolve()
    candidate, candidate_tree = _commit_candidate(worktree)
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
        candidate=candidate,
    )

    assert len(external_calls) == 1
    assert (output / "dist" / "fixture.tar.gz").read_bytes() == b"sdist"
    evidence = require_json_object(
        load_json_value((output / "pep561-evidence.json").read_bytes()),
        context="full PEP 561 evidence",
    )
    assert evidence["mode"] == "full"
    assert evidence["candidate"] == candidate
    assert evidence["candidate_tree"] == candidate_tree
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
        "candidate_tree",
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
        "candidate_tree": "b" * 40,
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
    if fault in {"candidate", "candidate_tree", "source_snapshot_sha256"}:
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
    ["mode", "candidate", "candidate-tree", "source-digest"],
)
def test_full_evidence_rejects_top_level_authority_faults(fault: str) -> None:
    evidence = _valid_evidence(require_full=True)
    if fault == "mode":
        evidence["mode"] = "artifact-only"
    elif fault == "candidate":
        evidence["candidate"] = None
    elif fault == "candidate-tree":
        evidence["candidate_tree"] = evidence["candidate"]
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


@pytest.mark.parametrize(
    "fault",
    ["candidate", "candidate-tree", "toolchain", "check-result"],
)
def test_artifact_only_evidence_rejects_full_authority_claims(fault: str) -> None:
    evidence = _valid_evidence(require_full=False)
    if fault == "candidate":
        evidence["candidate"] = "not-a-candidate"
    elif fault == "candidate-tree":
        evidence["candidate_tree"] = "b" * 40
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
