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
    from collections.abc import Mapping, Sequence

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
_EVIDENCE_FIELDS = frozenset(
    {
        "artifacts",
        "candidate",
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
    source_snapshot_sha256: str
    sdist: Path
    wheel: Path
    toolchain: dict[str, object] | None


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
    total = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(64 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    _fail("reviewed file exceeded its byte ceiling")
                digest.update(chunk)
        after = path.lstat()
    except OSError:
        _fail("reviewed file could not be read")
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity or total != before.st_size:
        _fail("reviewed file changed while it was read")
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
        try:
            payload = member.read_bytes()
        except OSError:
            _fail("source snapshot digest could not read a file")
        if member.lstat() != metadata:
            _fail("source snapshot changed while it was digested")
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
    if require_full and not _is_candidate(candidate):
        _fail("PEP 561 evidence candidate is missing or invalid")
    if not require_full and candidate is not None and not _is_candidate(candidate):
        _fail("PEP 561 evidence candidate is invalid")
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
        or len(result.stdout) > _MAX_OUTPUT_BYTES
        or len(result.stderr) > _MAX_OUTPUT_BYTES
    ):
        _fail("offline PEP 561 subprocess failed or exceeded its output bound")
    return result


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


def _copy_package_member(
    source_member: Path,
    *,
    package_source: Path,
    package_destination: Path,
) -> Path | None:
    relative = source_member.relative_to(package_source)
    if "__pycache__" in relative.parts or source_member.suffix in {".pyc", ".pyo"}:
        return None
    metadata = source_member.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        _fail("source package snapshot contains a symbolic link")
    member = package_destination / relative
    if stat.S_ISDIR(metadata.st_mode):
        member.mkdir(mode=0o700, parents=True)
        return None
    if not stat.S_ISREG(metadata.st_mode):
        _fail("source package snapshot contains a non-regular file")
    marker = member if source_member.name == "py.typed" else None
    if marker is None and source_member.suffix != ".py":
        _fail("source package snapshot contains undeclared package data")
    member.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _ = member.write_bytes(source_member.read_bytes())
    return marker


def _copy_source_snapshot(worktree: Path, destination: Path) -> Path:
    destination.mkdir(mode=0o700)
    for name in (
        "LICENSE",
        "README.md",
        "THIRD_PARTY_NOTICES.md",
        "pyproject.toml",
    ):
        source = worktree / name
        if not source.is_file() or source.is_symlink():
            _fail("required build input is not a regular file")
        _ = (destination / name).write_bytes(source.read_bytes())
    package_source = worktree / "src" / "nplg_mcp"
    package_destination = destination / "src" / "nplg_mcp"
    package_destination.parent.mkdir(mode=0o700)
    markers: list[Path] = []
    for source_member in sorted(package_source.rglob("*")):
        marker = _copy_package_member(
            source_member,
            package_source=package_source,
            package_destination=package_destination,
        )
        if marker is not None:
            markers.append(marker)
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
        _fail("full PEP 561 authority requires an exact candidate SHA")
    if artifact_only and candidate is not None and not _is_candidate(candidate):
        _fail("PEP 561 candidate SHA is invalid")
    output = _prepare_output(output_dir, worktree=root)
    with tempfile.TemporaryDirectory(prefix="nplg-pep561-") as temporary:
        work = Path(temporary).resolve(strict=True)
        home = work / "home"
        home.mkdir(mode=0o700)
        environment = _closed_environment(home)
        source = _copy_source_snapshot(root, work / "source")
        source_snapshot_sha256 = _tree_sha256(source)
        sdist, wheel = _build_artifacts(source, work, environment=environment)
        artifact_output = output / "dist"
        artifact_output.mkdir(mode=0o700)
        retained_sdist = artifact_output / sdist.name
        retained_wheel = artifact_output / wheel.name
        _ = retained_sdist.write_bytes(sdist.read_bytes())
        _ = retained_wheel.write_bytes(wheel.read_bytes())
        toolchain: dict[str, object] | None = None
        if not artifact_only:
            if node_executable is None:
                _fail("external-consumer mode requires reviewed Node")
            node = node_executable.resolve(strict=True)
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
