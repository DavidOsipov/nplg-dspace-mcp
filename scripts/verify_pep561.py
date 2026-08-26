# Copyright (c) 2026 David Osipov
"""Build and verify the PEP 561 distribution and external-consumer contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, NoReturn, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

_EXPECTED_NODE_SHA256 = (
    "bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"
)
_EXPECTED_NODE_VERSION = b"v24.19.0\n"
_EXPECTED_PYRIGHT_VERSION = b"pyright 1.1.413\n"
_EXPECTED_MYPY_VERSION = b"mypy 2.3.1 (compiled: yes)\n"
_EXPECTED_ARTIFACT_COUNT = 2
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_PROCESS_TIMEOUT_SECONDS = 120
_SOURCE_DATE_EPOCH = "315532800"
_SHA256_HEX_LENGTH = 64
_GIT_SHA_HEX_LENGTH = 40
_GIT = "/usr/bin/git"
_REQUIRED_BUILD_INPUTS: tuple[str, ...] = (
    "LICENSE",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "pyproject.toml",
)
_SOURCE_GIT_PATHS: tuple[str, ...] = (
    *_REQUIRED_BUILD_INPUTS,
    "src/nplg_mcp",
)
_ERR_CANDIDATE_BINDING = "candidate source tree does not match the captured snapshot"
_EVIDENCE_FIELDS = frozenset(
    {
        "artifacts",
        "candidate",
        "candidate_tree",
        "checks",
        "mode",
        "source_snapshot_sha256",
        "toolchain",
    }
)
_CHECK_FIELDS = frozenset(
    {
        "annotation_fault_mypy",
        "annotation_fault_pyright",
        "artifact_inventory",
        "external_consumer_mypy",
        "external_consumer_pyright",
        "marker_fault_mypy",
        "marker_fault_pyright",
    }
)
_CONSUMER_SOURCE = """\
from __future__ import annotations

from typing import assert_type

from nplg_mcp.contracts import (
    DeploymentProfile,
    RegisteredTool,
    SearchDocumentsInput,
    SearchDocumentsOutput,
    StrictInput,
    StrictOutput,
    ToolAnnotations,
    ToolCatalog,
    ToolDefinition,
)


def input_contract() -> type[StrictInput]:
    return SearchDocumentsInput


def profile_contract() -> DeploymentProfile:
    return DeploymentProfile.ALPIC_METADATA


def annotation_contract(value: ToolAnnotations) -> bool:
    return value.read_only_hint


def definition_contract(
    value: ToolDefinition[SearchDocumentsInput, SearchDocumentsOutput],
) -> type[SearchDocumentsInput]:
    assert_type(value.input_model, type[SearchDocumentsInput])
    return value.input_model


def registered_contract(value: RegisteredTool) -> type[StrictOutput]:
    assert_type(value.output_model, type[StrictOutput])
    return value.output_model


async def catalog_contract(value: ToolCatalog) -> StrictOutput:
    result = await value.call("search_documents", {"query": "fixture"})
    assert_type(result, StrictOutput)
    return result
"""


class Pep561GateError(RuntimeError):
    """Raised when PEP 561 artifact or consumer proof is incomplete."""


@dataclass(frozen=True, slots=True)
class _ConsumerContext:
    worktree: Path
    node: Path
    pyright: Path
    mypy: Path
    environment: dict[str, str]


@dataclass(frozen=True, slots=True)
class _EvidenceContext:
    output: Path
    artifact_only: bool
    candidate: str | None
    candidate_tree: str | None
    source_snapshot_sha256: str
    sdist: Path
    wheel: Path
    toolchain: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class _StableReadPolicy:
    max_bytes: int
    read_error: str
    changed_error: str
    ceiling_error: str


def _fail(message: str) -> NoReturn:
    raise Pep561GateError(message)


def _canonical_directory(path: Path, *, boundary: str) -> Path:
    if not path.is_absolute():
        _fail(f"{boundary} must be absolute")
    try:
        canonical = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError:
        _fail(f"{boundary} is unavailable")
    if canonical != path or not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{boundary} must be a canonical directory")
    return canonical


def _prepare_output(path: Path, *, worktree: Path) -> Path:
    if not path.is_absolute():
        _fail("output directory must be absolute")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        _fail("output directory parent is unavailable")
    output = parent / path.name
    if output != path or output.exists():
        _fail("output directory must be a new canonical path")
    if output == worktree or worktree in output.parents or output in worktree.parents:
        _fail("output directory must not overlap the worktree")
    output.mkdir(mode=0o700)
    return output


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return mutation-relevant identity fields without volatile access time."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _lstat_at(path: str | Path, *, dir_fd: int | None) -> os.stat_result:
    if dir_fd is None:
        return Path(path).lstat()
    return os.stat(path, dir_fd=dir_fd, follow_symlinks=False)


def _directory_open_flags(*, error: str) -> int:
    values = tuple(
        cast("object", getattr(os, name, None))
        for name in ("O_RDONLY", "O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    )
    if any(type(value) is not int for value in values):
        _fail(error)
    read_only, close_on_exec, directory, no_follow = cast(
        "tuple[int, int, int, int]",
        values,
    )
    return read_only | close_on_exec | directory | no_follow


def _open_stable_directory(
    path: str | Path,
    *,
    dir_fd: int | None,
    error: str,
) -> tuple[int, os.stat_result]:
    try:
        before = _lstat_at(path, dir_fd=dir_fd)
    except OSError:
        _fail(error)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        _fail(error)
    try:
        descriptor = os.open(
            path,
            _directory_open_flags(error=error),
            dir_fd=dir_fd,
        )
    except OSError:
        _fail(error)
    try:
        opened = os.fstat(descriptor)
        after = _lstat_at(path, dir_fd=dir_fd)
    except OSError:
        os.close(descriptor)
        _fail(error)
    expected = _stable_file_identity(before)
    if (
        _stable_file_identity(opened) != expected
        or _stable_file_identity(after) != expected
    ):
        os.close(descriptor)
        _fail(error)
    return descriptor, before


def _require_stable_directory(
    descriptor: int,
    *,
    path: str | Path,
    dir_fd: int | None,
    before: os.stat_result,
    error: str,
) -> None:
    try:
        opened_after = os.fstat(descriptor)
        path_after = _lstat_at(path, dir_fd=dir_fd)
    except OSError:
        _fail(error)
    expected = _stable_file_identity(before)
    if (
        _stable_file_identity(opened_after) != expected
        or _stable_file_identity(path_after) != expected
    ):
        _fail(error)


def _read_stable_file(
    path: str | Path,
    *,
    before: os.stat_result,
    policy: _StableReadPolicy,
    consume: Callable[[bytes], None],
    dir_fd: int | None = None,
) -> int:
    """Read one no-follow descriptor while binding its path and file identity."""
    try:
        no_follow = os.O_NOFOLLOW
    except AttributeError:
        _fail(policy.read_error)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | no_follow
    try:
        descriptor = (
            os.open(path, flags)
            if dir_fd is None
            else os.open(path, flags, dir_fd=dir_fd)
        )
    except OSError:
        _fail(policy.read_error)
    try:
        opened = os.fstat(descriptor)
        if _stable_file_identity(opened) != _stable_file_identity(before):
            _fail(policy.changed_error)
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > policy.max_bytes:
                _fail(policy.ceiling_error)
            consume(chunk)
        opened_after = os.fstat(descriptor)
        path_after = _lstat_at(path, dir_fd=dir_fd)
    except OSError:
        _fail(policy.read_error)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            _fail(policy.read_error)
    expected_identity = _stable_file_identity(before)
    if (
        _stable_file_identity(opened_after) != expected_identity
        or _stable_file_identity(path_after) != expected_identity
        or total != before.st_size
    ):
        _fail(policy.changed_error)
    return total


def _stable_sha256(path: Path, *, max_bytes: int) -> str:
    try:
        before = path.lstat()
    except OSError:
        _fail("reviewed file is unavailable")
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > max_bytes
    ):
        _fail("reviewed file is not a bounded regular file")
    digest = hashlib.sha256()
    _ = _read_stable_file(
        path,
        before=before,
        policy=_StableReadPolicy(
            max_bytes=max_bytes,
            read_error="reviewed file could not be read",
            changed_error="reviewed file changed while it was read",
            ceiling_error="reviewed file exceeded its byte ceiling",
        ),
        consume=digest.update,
    )
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    """Bind a source snapshot to every canonical relative path and byte."""
    digest = hashlib.sha256(b"nplg-pep561-source-tree-v1\0")
    for member in sorted(root.rglob("*")):
        relative = member.relative_to(root).as_posix().encode()
        metadata = member.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            _fail("source snapshot digest encountered a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            digest.update(b"d\0" + relative + b"\0")
            continue
        if not stat.S_ISREG(metadata.st_mode):
            _fail("source snapshot digest encountered a non-regular file")
        digest.update(b"f\0" + relative + b"\0")
        payload = bytearray()
        _ = _read_stable_file(
            member,
            before=metadata,
            policy=_StableReadPolicy(
                max_bytes=_MAX_ARTIFACT_BYTES,
                read_error="source snapshot digest could not read a file",
                changed_error="source snapshot changed while it was digested",
                ceiling_error="source snapshot digest file exceeded its byte ceiling",
            ),
            consume=payload.extend,
        )
        digest.update(len(payload).to_bytes(8, byteorder="big"))
        digest.update(payload)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_candidate(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _GIT_SHA_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_evidence_mapping(value: object, *, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"PEP 561 evidence {context} is not an object")
    raw = cast("dict[object, object]", value)
    if any(not isinstance(key, str) for key in raw):
        _fail(f"PEP 561 evidence {context} has a non-string key")
    return cast("dict[str, object]", value)


def _validate_artifact_evidence(value: object) -> None:
    """Require exact retained sdist and wheel identities."""
    artifacts = _require_evidence_mapping(value, context="artifacts")
    if set(artifacts) != {"sdist", "wheel"}:
        _fail("PEP 561 evidence artifact inventory is incomplete")
    for name in ("sdist", "wheel"):
        identity = _require_evidence_mapping(
            artifacts[name],
            context=f"{name} identity",
        )
        if set(identity) != {"filename", "sha256"}:
            _fail(f"PEP 561 evidence {name} identity is incomplete")
        filename = identity["filename"]
        if (
            not isinstance(filename, str)
            or not filename
            or PurePosixPath(filename).name != filename
            or not _is_sha256(identity["sha256"])
        ):
            _fail(f"PEP 561 evidence {name} identity is invalid")


def _validate_check_evidence(value: object, *, require_full: bool) -> None:
    """Require every named consumer and deliberate-fault verdict."""
    checks = _require_evidence_mapping(value, context="checks")
    if frozenset(checks) != _CHECK_FIELDS:
        _fail("PEP 561 evidence check inventory is incomplete")
    for name, result in checks.items():
        expected = True if require_full or name == "artifact_inventory" else None
        if result is not expected:
            _fail(f"PEP 561 evidence check {name} is incomplete")


def _validate_toolchain_evidence(value: object, *, require_full: bool) -> None:
    """Require exact checker versions and byte identities in full mode."""
    if not require_full:
        if value is not None:
            _fail("artifact-only PEP 561 evidence claims a checker toolchain")
        return
    toolchain = _require_evidence_mapping(value, context="toolchain")
    if set(toolchain) != {"mypy", "node", "pyright"}:
        _fail("PEP 561 evidence toolchain inventory is incomplete")
    for name in ("mypy", "node", "pyright"):
        identity = _require_evidence_mapping(
            toolchain[name],
            context=f"{name} identity",
        )
        if set(identity) != {"sha256", "version"}:
            _fail(f"PEP 561 evidence {name} identity is incomplete")
        version = identity["version"]
        if (
            not _is_sha256(identity["sha256"])
            or not isinstance(version, str)
            or not version
        ):
            _fail(f"PEP 561 evidence {name} identity is invalid")


def _validate_evidence_document(
    evidence: Mapping[str, object],
    *,
    require_full: bool,
) -> None:
    """Reject incomplete or ambiguous retained PEP 561 evidence."""
    if frozenset(evidence) != _EVIDENCE_FIELDS:
        _fail("PEP 561 evidence top-level inventory is incomplete")
    expected_mode = "full" if require_full else "artifact-only"
    if evidence["mode"] != expected_mode:
        _fail("PEP 561 evidence mode does not match the invoked authority")
    candidate = evidence["candidate"]
    candidate_tree = evidence["candidate_tree"]
    if require_full and not _is_candidate(candidate):
        _fail("PEP 561 evidence candidate is missing or invalid")
    if not require_full and candidate is not None and not _is_candidate(candidate):
        _fail("PEP 561 evidence candidate is invalid")
    if require_full and (
        not _is_candidate(candidate_tree) or candidate_tree == candidate
    ):
        _fail("PEP 561 evidence candidate tree is missing or invalid")
    if not require_full and candidate_tree is not None:
        _fail("artifact-only PEP 561 evidence claims a candidate tree")
    if not _is_sha256(evidence["source_snapshot_sha256"]):
        _fail("PEP 561 evidence source snapshot digest is missing or invalid")
    _validate_artifact_evidence(evidence["artifacts"])
    _validate_check_evidence(evidence["checks"], require_full=require_full)
    _validate_toolchain_evidence(evidence["toolchain"], require_full=require_full)


def _closed_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": home.as_posix(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": os.pathsep.join(("/usr/bin", "/bin")),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "SOURCE_DATE_EPOCH": _SOURCE_DATE_EPOCH,
    }


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    expected_returncode: int = 0,
    max_output_bytes: int = _MAX_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(  # noqa: S603
        tuple(command),
        cwd=cwd,
        env=environment,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=_PROCESS_TIMEOUT_SECONDS,
    )
    if (
        result.returncode != expected_returncode
        or len(result.stdout) > max_output_bytes
        or len(result.stderr) > max_output_bytes
    ):
        _fail("offline PEP 561 subprocess failed or exceeded its output bound")
    return result


def _git_environment(environment: dict[str, str]) -> dict[str, str]:
    return {
        **environment,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git_output(
    root: Path,
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str],
    max_output_bytes: int = _MAX_OUTPUT_BYTES,
) -> bytes:
    return _run(
        (
            _GIT,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.helper=",
            *arguments,
        ),
        cwd=root,
        environment=_git_environment(environment),
        max_output_bytes=max_output_bytes,
    ).stdout


def _parse_git_tree(payload: bytes) -> dict[str, str]:
    if not payload or not payload.endswith(b"\x00"):
        _fail(_ERR_CANDIDATE_BINDING)
    entries: dict[str, str] = {}
    for record in payload[:-1].split(b"\x00"):
        try:
            raw_identity, raw_path = record.split(b"\t", maxsplit=1)
            mode, object_type, raw_object_id = raw_identity.split(b" ")
            path = raw_path.decode("utf-8", errors="strict")
            object_id = raw_object_id.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError):
            _fail(_ERR_CANDIDATE_BINDING)
        pure = PurePosixPath(path)
        if (
            mode not in {b"100644", b"100755"}
            or object_type != b"blob"
            or not _is_candidate(object_id)
            or pure.is_absolute()
            or pure.as_posix() != path
            or any(part in {"", ".", ".."} for part in pure.parts)
            or not (path in _REQUIRED_BUILD_INPUTS or path.startswith("src/nplg_mcp/"))
            or path in entries
        ):
            _fail(_ERR_CANDIDATE_BINDING)
        entries[path] = object_id
    return entries


def _snapshot_file_identities(source: Path) -> dict[str, tuple[int, str]]:
    identities: dict[str, tuple[int, str]] = {}
    for member in sorted(source.rglob("*")):
        try:
            metadata = member.lstat()
        except OSError:
            _fail(_ERR_CANDIDATE_BINDING)
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_ARTIFACT_BYTES
        ):
            _fail(_ERR_CANDIDATE_BINDING)
        digest = hashlib.sha256()
        _ = _read_stable_file(
            member,
            before=metadata,
            policy=_StableReadPolicy(
                max_bytes=_MAX_ARTIFACT_BYTES,
                read_error=_ERR_CANDIDATE_BINDING,
                changed_error=_ERR_CANDIDATE_BINDING,
                ceiling_error=_ERR_CANDIDATE_BINDING,
            ),
            consume=digest.update,
        )
        identities[member.relative_to(source).as_posix()] = (
            metadata.st_size,
            digest.hexdigest(),
        )
    return identities


def _bind_candidate_source(
    root: Path,
    source: Path,
    *,
    candidate: str,
    environment: dict[str, str],
) -> str:
    """Bind captured artifact inputs to one exact Git commit and tree."""
    try:
        top_level = _git_output(
            root,
            ("rev-parse", "--show-toplevel"),
            environment=environment,
        )
        resolved_candidate = _git_output(
            root,
            ("rev-parse", "--verify", f"{candidate}^{{commit}}"),
            environment=environment,
        )
        raw_tree = _git_output(
            root,
            ("rev-parse", "--verify", f"{candidate}^{{tree}}"),
            environment=environment,
        )
        if (
            top_level != root.as_posix().encode() + b"\n"
            or resolved_candidate != candidate.encode() + b"\n"
            or not raw_tree.endswith(b"\n")
        ):
            _fail(_ERR_CANDIDATE_BINDING)
        candidate_tree = raw_tree.removesuffix(b"\n").decode(
            "ascii",
            errors="strict",
        )
        if not _is_candidate(candidate_tree) or candidate_tree == candidate:
            _fail(_ERR_CANDIDATE_BINDING)
        tree_entries = _parse_git_tree(
            _git_output(
                root,
                (
                    "ls-tree",
                    "-r",
                    "-z",
                    "--full-tree",
                    candidate,
                    "--",
                    *_SOURCE_GIT_PATHS,
                ),
                environment=environment,
            )
        )
        snapshot_files = _snapshot_file_identities(source)
        if set(tree_entries) != set(snapshot_files):
            _fail(_ERR_CANDIDATE_BINDING)
        for path, object_id in tree_entries.items():
            blob = _git_output(
                root,
                ("cat-file", "blob", object_id),
                environment=environment,
                max_output_bytes=_MAX_ARTIFACT_BYTES,
            )
            expected_size, expected_digest = snapshot_files[path]
            if (
                len(blob) != expected_size
                or hashlib.sha256(blob).hexdigest() != expected_digest
            ):
                _fail(_ERR_CANDIDATE_BINDING)
    except (OSError, Pep561GateError, subprocess.SubprocessError, UnicodeError):
        _fail(_ERR_CANDIDATE_BINDING)
    return candidate_tree


def _validate_toolchain(
    worktree: Path, node: Path, *, environment: dict[str, str]
) -> tuple[Path, Path]:
    if _stable_sha256(node, max_bytes=_MAX_EXECUTABLE_BYTES) != _EXPECTED_NODE_SHA256:
        _fail("reviewed Node executable does not match its locked digest")
    if (
        _run(
            (node.as_posix(), "--version"), cwd=worktree, environment=environment
        ).stdout
        != _EXPECTED_NODE_VERSION
    ):
        _fail("reviewed Node version is not locked v24.19.0")
    pyright = worktree / "node_modules" / "pyright" / "index.js"
    mypy = worktree / ".venv" / "bin" / "mypy"
    _ = _stable_sha256(pyright, max_bytes=_MAX_ARTIFACT_BYTES)
    _ = _stable_sha256(mypy, max_bytes=_MAX_ARTIFACT_BYTES)
    if (
        _run(
            (node.as_posix(), pyright.as_posix(), "--version"),
            cwd=worktree,
            environment=environment,
        ).stdout
        != _EXPECTED_PYRIGHT_VERSION
    ):
        _fail("Pyright is not locked at 1.1.413")
    if (
        _run(
            (mypy.as_posix(), "--version"),
            cwd=worktree,
            environment=environment,
        ).stdout
        != _EXPECTED_MYPY_VERSION
    ):
        _fail("mypy is not locked at 2.3.1")
    return pyright, mypy


def _stable_directory_names(descriptor: int) -> tuple[str, ...]:
    try:
        names = os.listdir(descriptor)
    except OSError:
        _fail("source package directory changed while it was copied")
    if any(
        not name or name in {".", ".."} or "/" in name or "\x00" in name
        for name in names
    ):
        _fail("source package directory contains an invalid member name")
    return tuple(sorted(names))


def _copy_package_directory(
    descriptor: int,
    *,
    destination: Path,
    relative_parts: tuple[str, ...],
    markers: list[Path],
) -> None:
    names_before = _stable_directory_names(descriptor)
    for name in names_before:
        try:
            metadata = _lstat_at(name, dir_fd=descriptor)
        except OSError:
            _fail("source package snapshot changed while it was copied")
        if stat.S_ISLNK(metadata.st_mode):
            _fail("source package snapshot contains a symbolic link")
        relative = (*relative_parts, name)
        if "__pycache__" in relative or Path(name).suffix in {".pyc", ".pyo"}:
            continue
        member = destination.joinpath(*relative)
        if stat.S_ISDIR(metadata.st_mode):
            member.mkdir(mode=0o700)
            child, child_before = _open_stable_directory(
                name,
                dir_fd=descriptor,
                error="source package directory changed while it was copied",
            )
            try:
                _copy_package_directory(
                    child,
                    destination=destination,
                    relative_parts=relative,
                    markers=markers,
                )
            finally:
                try:
                    _require_stable_directory(
                        child,
                        path=name,
                        dir_fd=descriptor,
                        before=child_before,
                        error="source package directory changed while it was copied",
                    )
                finally:
                    os.close(child)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            _fail("source package snapshot contains a non-regular file")
        if name == "py.typed":
            markers.append(member)
        elif Path(name).suffix != ".py":
            _fail("source package snapshot contains undeclared package data")
        payload = bytearray()
        _ = _read_stable_file(
            name,
            before=metadata,
            policy=_StableReadPolicy(
                max_bytes=_MAX_ARTIFACT_BYTES,
                read_error="source package snapshot file could not be read",
                changed_error="source package snapshot changed while it was copied",
                ceiling_error="source package snapshot file exceeded its byte ceiling",
            ),
            consume=payload.extend,
            dir_fd=descriptor,
        )
        _ = member.write_bytes(payload)
    if _stable_directory_names(descriptor) != names_before:
        _fail("source package directory changed while it was copied")


def _copy_source_snapshot(worktree: Path, destination: Path) -> Path:
    destination.mkdir(mode=0o700)
    root_descriptor, root_before = _open_stable_directory(
        worktree,
        dir_fd=None,
        error="source worktree directory is unavailable or unsafe",
    )
    try:
        for name in _REQUIRED_BUILD_INPUTS:
            try:
                metadata = _lstat_at(name, dir_fd=root_descriptor)
            except OSError:
                _fail("required build input is not a regular file")
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                _fail("required build input is not a regular file")
            payload = bytearray()
            _ = _read_stable_file(
                name,
                before=metadata,
                policy=_StableReadPolicy(
                    max_bytes=_MAX_ARTIFACT_BYTES,
                    read_error="required build input could not be read",
                    changed_error="required build input changed while it was copied",
                    ceiling_error="required build input exceeded its byte ceiling",
                ),
                consume=payload.extend,
                dir_fd=root_descriptor,
            )
            _ = (destination / name).write_bytes(payload)
        package_destination = destination / "src" / "nplg_mcp"
        package_destination.mkdir(mode=0o700, parents=True)
        source_descriptor, source_before = _open_stable_directory(
            "src",
            dir_fd=root_descriptor,
            error="source package directory is unavailable or unsafe",
        )
        try:
            package_descriptor, package_before = _open_stable_directory(
                "nplg_mcp",
                dir_fd=source_descriptor,
                error="source package directory is unavailable or unsafe",
            )
            try:
                markers: list[Path] = []
                _copy_package_directory(
                    package_descriptor,
                    destination=package_destination,
                    relative_parts=(),
                    markers=markers,
                )
            finally:
                try:
                    _require_stable_directory(
                        package_descriptor,
                        path="nplg_mcp",
                        dir_fd=source_descriptor,
                        before=package_before,
                        error="source package directory changed while it was copied",
                    )
                finally:
                    os.close(package_descriptor)
        finally:
            try:
                _require_stable_directory(
                    source_descriptor,
                    path="src",
                    dir_fd=root_descriptor,
                    before=source_before,
                    error="source package directory changed while it was copied",
                )
            finally:
                os.close(source_descriptor)
        _require_stable_directory(
            root_descriptor,
            path=worktree,
            dir_fd=None,
            before=root_before,
            error="source worktree directory changed while it was copied",
        )
    finally:
        os.close(root_descriptor)
    expected_marker = package_destination / "py.typed"
    if markers != [expected_marker] or expected_marker.read_bytes() != b"":
        _fail("source package marker is missing, misplaced, duplicated, or nonempty")
    return destination


def _canonical_archive_name(name: str) -> str:
    pure = PurePosixPath(name)
    if (
        pure.is_absolute()
        or pure.as_posix() != name
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "\\" in name
    ):
        _fail("distribution archive contains a noncanonical path")
    return name


def _verify_sdist_marker(path: Path) -> None:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            names = tuple(_canonical_archive_name(member.name) for member in members)
            if len(names) != len(set(names)):
                _fail("sdist contains duplicate archive members")
            marker_members = [
                member
                for member in members
                if PurePosixPath(member.name).name == "py.typed"
            ]
            root = path.name.removesuffix(".tar.gz")
            expected = f"{root}/src/nplg_mcp/py.typed"
            if (
                len(marker_members) != 1
                or marker_members[0].name != expected
                or not marker_members[0].isreg()
                or marker_members[0].size != 0
            ):
                _fail("sdist marker is missing, misplaced, duplicated, or nonempty")
            marker_stream = archive.extractfile(marker_members[0])
            if marker_stream is None or marker_stream.read(1) != b"":
                _fail("sdist marker payload is not empty")
    except (OSError, tarfile.TarError):
        _fail("sdist could not be parsed safely")


def _verify_wheel_marker(path: Path) -> None:
    try:
        with zipfile.ZipFile(path, mode="r") as archive:
            members = archive.infolist()
            names = tuple(
                _canonical_archive_name(member.filename) for member in members
            )
            if len(names) != len(set(names)):
                _fail("wheel contains duplicate archive members")
            marker_members = [
                member
                for member in members
                if PurePosixPath(member.filename).name == "py.typed"
            ]
            if (
                len(marker_members) != 1
                or marker_members[0].filename != "nplg_mcp/py.typed"
                or marker_members[0].file_size != 0
                or archive.read(marker_members[0]) != b""
            ):
                _fail("wheel marker is missing, misplaced, duplicated, or nonempty")
    except (OSError, zipfile.BadZipFile):
        _fail("wheel could not be parsed safely")


def _build_artifacts(
    source: Path,
    work: Path,
    *,
    environment: dict[str, str],
) -> tuple[Path, Path]:
    distribution = work / "dist"
    distribution.mkdir(mode=0o700)
    _ = _run(
        (
            sys.executable,
            "-I",
            "-B",
            "-m",
            "build",
            "--sdist",
            "--wheel",
            "--no-isolation",
            "--outdir",
            distribution.as_posix(),
            source.as_posix(),
        ),
        cwd=work,
        environment=environment,
    )
    artifacts = tuple(sorted(distribution.iterdir()))
    if len(artifacts) != _EXPECTED_ARTIFACT_COUNT or any(
        not artifact.is_file()
        or artifact.is_symlink()
        or artifact.stat().st_size > _MAX_ARTIFACT_BYTES
        for artifact in artifacts
    ):
        _fail("build did not produce exactly two bounded regular artifacts")
    sdists = tuple(path for path in artifacts if path.name.endswith(".tar.gz"))
    wheels = tuple(path for path in artifacts if path.suffix == ".whl")
    if len(sdists) != 1 or len(wheels) != 1:
        _fail("build did not produce one canonical sdist and one canonical wheel")
    _verify_sdist_marker(sdists[0])
    _verify_wheel_marker(wheels[0])
    return sdists[0], wheels[0]


def _write_consumer_project(project: Path, *, environment_root: Path) -> None:
    project.mkdir(mode=0o700)
    _ = (project / "consumer.py").write_text(_CONSUMER_SOURCE, encoding="utf-8")
    configuration = {
        "include": ["consumer.py"],
        "pythonPlatform": "Linux",
        "pythonVersion": f"{sys.version_info.major}.{sys.version_info.minor}",
        "reportMissingTypeStubs": "error",
        "typeCheckingMode": "strict",
        "venv": "venv",
        "venvPath": environment_root.as_posix(),
    }
    _ = (project / "pyrightconfig.json").write_text(
        json.dumps(configuration, ensure_ascii=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _prepare_consumer(
    root: Path,
    wheel: Path,
    *,
    worktree: Path,
    environment: dict[str, str],
) -> tuple[Path, Path, Path]:
    root.mkdir(mode=0o700, parents=True)
    virtual_environment = root / "venv"
    project = root / "project"
    _ = _run(
        (
            sys.executable,
            "-I",
            "-B",
            "-m",
            "venv",
            "--copies",
            virtual_environment.as_posix(),
        ),
        cwd=root,
        environment=environment,
    )
    python = virtual_environment / "bin" / "python"
    _ = _run(
        (
            python.as_posix(),
            "-I",
            "-B",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--no-deps",
            wheel.as_posix(),
        ),
        cwd=root,
        environment=environment,
    )
    purelib_result = _run(
        (
            python.as_posix(),
            "-I",
            "-B",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ),
        cwd=root,
        environment=environment,
    )
    try:
        purelib = Path(purelib_result.stdout.decode("utf-8", errors="strict").strip())
        package = (purelib / "nplg_mcp").resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _fail("installed package root could not be resolved")
    if not package.is_dir() or worktree in package.parents:
        _fail("external consumer resolved the source checkout")
    probe = _run(
        (
            python.as_posix(),
            "-I",
            "-B",
            "-c",
            (
                "import json,nplg_mcp,sys;"
                "print(json.dumps({'module':nplg_mcp.__file__,'paths':sys.path},"
                "sort_keys=True))"
            ),
        ),
        cwd=root,
        environment=environment,
    )
    checkout_bytes = worktree.as_posix().encode()
    if checkout_bytes in probe.stdout or b"PYTHONPATH" in probe.stdout:
        _fail("source checkout leaked into external consumer import paths")
    marker = package / "py.typed"
    if not marker.is_file() or marker.is_symlink() or marker.read_bytes() != b"":
        _fail("installed package marker is absent or malformed")
    _write_consumer_project(project, environment_root=root)
    return project, python, package


def _checker_commands(
    *,
    node: Path,
    pyright: Path,
    mypy: Path,
    project: Path,
    python: Path,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        (
            node.as_posix(),
            pyright.as_posix(),
            "--outputjson",
            "--project",
            (project / "pyrightconfig.json").as_posix(),
            "--pythonpath",
            python.as_posix(),
        ),
        (
            mypy.as_posix(),
            "--no-incremental",
            "--cache-dir=/dev/null",
            "--strict",
            "--disallow-any-expr",
            "--python-executable",
            python.as_posix(),
            "--config-file=/dev/null",
            (project / "consumer.py").as_posix(),
        ),
    )


def _run_canonical_checkers(
    commands: tuple[tuple[str, ...], tuple[str, ...]],
    *,
    project: Path,
    environment: dict[str, str],
) -> None:
    pyright_result = _run(commands[0], cwd=project, environment=environment)
    if b'"errorCount":0' not in pyright_result.stdout.replace(b" ", b""):
        _fail("canonical Pyright consumer did not produce a zero-error summary")
    mypy_result = _run(commands[1], cwd=project, environment=environment)
    if b"Success: no issues found" not in mypy_result.stdout:
        _fail("canonical mypy consumer did not produce a zero-error summary")


def _run_fault_checker(
    command: tuple[str, ...],
    *,
    project: Path,
    environment: dict[str, str],
    expected_terms: tuple[bytes, ...],
    fault: str,
) -> None:
    result = _run(
        command,
        cwd=project,
        environment=environment,
        expected_returncode=1,
    )
    output = (result.stdout + result.stderr).lower()
    if not any(term in output for term in expected_terms):
        _fail(f"{fault} consumer failed for an unexpected reason")


def _verify_external_consumers(
    work: Path,
    wheel: Path,
    *,
    context: _ConsumerContext,
) -> None:
    consumers = work / "consumers"
    canonical_project, canonical_python, _canonical_package = _prepare_consumer(
        consumers / "canonical",
        wheel,
        worktree=context.worktree,
        environment=context.environment,
    )
    _run_canonical_checkers(
        _checker_commands(
            node=context.node,
            pyright=context.pyright,
            mypy=context.mypy,
            project=canonical_project,
            python=canonical_python,
        ),
        project=canonical_project,
        environment=context.environment,
    )

    marker_project, marker_python, marker_package = _prepare_consumer(
        consumers / "marker-fault",
        wheel,
        worktree=context.worktree,
        environment=context.environment,
    )
    (marker_package / "py.typed").unlink()
    marker_commands = _checker_commands(
        node=context.node,
        pyright=context.pyright,
        mypy=context.mypy,
        project=marker_project,
        python=marker_python,
    )
    _run_fault_checker(
        marker_commands[0],
        project=marker_project,
        environment=context.environment,
        expected_terms=(b"stub file", b"could not be resolved"),
        fault="missing-marker Pyright",
    )
    _run_fault_checker(
        marker_commands[1],
        project=marker_project,
        environment=context.environment,
        expected_terms=(b"py.typed", b"missing library stubs"),
        fault="missing-marker mypy",
    )

    annotation_project, annotation_python, annotation_package = _prepare_consumer(
        consumers / "annotation-fault",
        wheel,
        worktree=context.worktree,
        environment=context.environment,
    )
    catalog = annotation_package / "contracts" / "catalog.py"
    source = catalog.read_text(encoding="utf-8")
    annotation = "    def output_model(self) -> type[StrictOutput]:\n"
    if source.count(annotation) != 1:
        _fail("public annotation fault target is not unique")
    _ = catalog.write_text(
        source.replace(annotation, "    def output_model(self):\n"), encoding="utf-8"
    )
    annotation_commands = _checker_commands(
        node=context.node,
        pyright=context.pyright,
        mypy=context.mypy,
        project=annotation_project,
        python=annotation_python,
    )
    _run_fault_checker(
        annotation_commands[0],
        project=annotation_project,
        environment=context.environment,
        expected_terms=(b"unknown", b"assert_type"),
        fault="missing-annotation Pyright",
    )
    _run_fault_checker(
        annotation_commands[1],
        project=annotation_project,
        environment=context.environment,
        expected_terms=(b"any", b"assert_type"),
        fault="missing-annotation mypy",
    )


def _write_evidence(
    context: _EvidenceContext,
) -> None:
    checked: bool | None = None if context.artifact_only else True
    evidence: dict[str, object] = {
        "artifacts": {
            "sdist": {
                "filename": context.sdist.name,
                "sha256": _stable_sha256(
                    context.sdist,
                    max_bytes=_MAX_ARTIFACT_BYTES,
                ),
            },
            "wheel": {
                "filename": context.wheel.name,
                "sha256": _stable_sha256(
                    context.wheel,
                    max_bytes=_MAX_ARTIFACT_BYTES,
                ),
            },
        },
        "candidate": context.candidate,
        "candidate_tree": context.candidate_tree,
        "checks": {
            "annotation_fault_mypy": checked,
            "annotation_fault_pyright": checked,
            "artifact_inventory": True,
            "external_consumer_mypy": checked,
            "external_consumer_pyright": checked,
            "marker_fault_mypy": checked,
            "marker_fault_pyright": checked,
        },
        "mode": "artifact-only" if context.artifact_only else "full",
        "source_snapshot_sha256": context.source_snapshot_sha256,
        "toolchain": context.toolchain,
    }
    _validate_evidence_document(
        evidence,
        require_full=not context.artifact_only,
    )
    payload = (
        json.dumps(
            evidence,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    evidence_path = context.output / "pep561-evidence.json"
    with evidence_path.open("xb") as stream:
        _ = stream.write(payload)


def verify(
    *,
    worktree: Path,
    output_dir: Path,
    node_executable: Path | None,
    artifact_only: bool,
    candidate: str | None,
) -> None:
    """Run the deterministic offline PEP 561 artifact and consumer gate."""
    root = _canonical_directory(worktree, boundary="worktree")
    if not artifact_only and not _is_candidate(candidate):
        _fail(
            "full candidate-bound PEP 561 verification requires an exact candidate SHA"
        )
    if artifact_only and candidate is not None and not _is_candidate(candidate):
        _fail("PEP 561 candidate SHA is invalid")
    if not artifact_only and node_executable is None:
        _fail("external-consumer mode requires reviewed Node")
    output = _prepare_output(output_dir, worktree=root)
    with tempfile.TemporaryDirectory(prefix="nplg-pep561-") as temporary:
        work = Path(temporary).resolve(strict=True)
        home = work / "home"
        home.mkdir(mode=0o700)
        environment = _closed_environment(home)
        source = _copy_source_snapshot(root, work / "source")
        source_snapshot_sha256 = _tree_sha256(source)
        candidate_tree: str | None = None
        if not artifact_only:
            candidate_tree = _bind_candidate_source(
                root,
                source,
                candidate=cast("str", candidate),
                environment=environment,
            )
        sdist, wheel = _build_artifacts(source, work, environment=environment)
        artifact_output = output / "dist"
        artifact_output.mkdir(mode=0o700)
        retained_sdist = artifact_output / sdist.name
        retained_wheel = artifact_output / wheel.name
        _ = retained_sdist.write_bytes(sdist.read_bytes())
        _ = retained_wheel.write_bytes(wheel.read_bytes())
        toolchain: dict[str, object] | None = None
        if not artifact_only:
            node = cast("Path", node_executable).resolve(strict=True)
            pyright, mypy = _validate_toolchain(root, node, environment=environment)
            _verify_external_consumers(
                work,
                wheel,
                context=_ConsumerContext(
                    worktree=root,
                    node=node,
                    pyright=pyright,
                    mypy=mypy,
                    environment=environment,
                ),
            )
            toolchain = {
                "mypy": {
                    "sha256": _stable_sha256(
                        mypy,
                        max_bytes=_MAX_ARTIFACT_BYTES,
                    ),
                    "version": _EXPECTED_MYPY_VERSION.decode().strip(),
                },
                "node": {
                    "sha256": _stable_sha256(
                        node,
                        max_bytes=_MAX_EXECUTABLE_BYTES,
                    ),
                    "version": _EXPECTED_NODE_VERSION.decode().strip(),
                },
                "pyright": {
                    "sha256": _stable_sha256(
                        pyright,
                        max_bytes=_MAX_ARTIFACT_BYTES,
                    ),
                    "version": _EXPECTED_PYRIGHT_VERSION.decode().strip(),
                },
            }
        _write_evidence(
            _EvidenceContext(
                output=output,
                artifact_only=artifact_only,
                candidate=candidate,
                candidate_tree=candidate_tree,
                source_snapshot_sha256=source_snapshot_sha256,
                sdist=retained_sdist,
                wheel=retained_wheel,
                toolchain=toolchain,
            )
        )


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--worktree", type=Path, required=True)
    _ = parser.add_argument("--output-dir", type=Path, required=True)
    _ = parser.add_argument("--node-executable", type=Path)
    _ = parser.add_argument("--candidate")
    _ = parser.add_argument("--artifact-only", action="store_true")
    return parser.parse_args(argv)


class _Arguments(argparse.Namespace):
    worktree: Path = Path()
    output_dir: Path = Path()
    node_executable: Path | None = None
    candidate: str | None = None
    artifact_only: bool = False


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a fail-closed process status."""
    arguments = cast("_Arguments", _arguments(argv))
    try:
        verify(
            worktree=arguments.worktree,
            output_dir=arguments.output_dir,
            node_executable=arguments.node_executable,
            artifact_only=arguments.artifact_only,
            candidate=arguments.candidate,
        )
    except (OSError, Pep561GateError, subprocess.SubprocessError, ValueError) as exc:
        _ = os.write(2, f"PEP 561 gate failed: {exc}\n".encode())
        return 1
    _ = os.write(1, b"PEP 561 gate passed\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
