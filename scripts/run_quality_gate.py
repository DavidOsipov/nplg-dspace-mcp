# Copyright (c) 2026 David Osipov
"""Single ordered entry point for the repository's static-quality tools."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NoReturn, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Sequence
    from typing import BinaryIO, TextIO

    from scripts.bootstrap_toolchain import ToolchainError, load_lock
else:
    try:
        from scripts.bootstrap_toolchain import ToolchainError, load_lock
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        from bootstrap_toolchain import ToolchainError, load_lock


class GateError(RuntimeError):
    """Raised when the quality gate cannot prove a clean run."""


class _Digest(Protocol):
    """Minimal typed interface shared by supported SHA-256 implementations."""

    def update(self, data: bytes, /) -> None:
        """Consume immutable bytes."""
        ...

    def hexdigest(self) -> str:
        """Return the lowercase hexadecimal digest."""
        ...


_TRANSIENT_DIRECTORY_NAMES = frozenset(
    {
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
    }
)

_TOOL_TIMEOUT_SECONDS = 60.0
_TOOL_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
_TOOL_STDERR_LIMIT_BYTES = 256 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_TERMINATION_GRACE_SECONDS = 0.5
_EXECUTABLE_LIMIT_BYTES = 256 * 1024 * 1024
_SOURCE_FILE_LIMIT_BYTES = 16 * 1024 * 1024
_SOURCE_TOTAL_LIMIT_BYTES = 128 * 1024 * 1024
_GIT_FIELD_LIMIT_BYTES = 4096
_PORCELAIN_STATUS_RECORD_MIN_BYTES = 4
_WORKTREE_REQUIRED_FIELD_COUNT = 3


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    """Immutable deadline and byte ceilings for one child process."""

    timeout_seconds: float = _TOOL_TIMEOUT_SECONDS
    stdout_limit_bytes: int = _TOOL_STDOUT_LIMIT_BYTES
    stderr_limit_bytes: int = _TOOL_STDERR_LIMIT_BYTES

    def __post_init__(self) -> None:
        """Reject non-positive resource bounds before process creation."""
        if (
            self.timeout_seconds <= 0
            or self.stdout_limit_bytes <= 0
            or self.stderr_limit_bytes <= 0
        ):
            _fail("execution limits must be positive")


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    """Immutable exit, stderr, deadline, and output policy for one command."""

    allow_diagnostics: bool = False
    allow_ascii_whitespace_stderr: bool = False
    limits: ExecutionLimits = ExecutionLimits()


_DEFAULT_EXECUTION_POLICY = ExecutionPolicy()


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Complete bounded child result; partial streams are never returned."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    output_complete: bool = True


type ToolName = Literal["ruff", "pyright", "mypy"]
type PythonTarget = Literal["3.12", "3.13", "3.14"]


@dataclass(frozen=True, slots=True)
class ToolCommand:
    """One immutable, version-bound command in the quality plan."""

    tool: ToolName
    version: str
    python_target: PythonTarget
    diagnostic: bool
    argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VersionProbe:
    """One exact, bounded version assertion for a reviewed executable."""

    command: tuple[str, ...]
    expected_stdout: bytes


@dataclass(frozen=True, slots=True)
class GitSnapshot:
    """Immutable logical repository state surrounding a quality run."""

    head: str
    staged_entries_sha256: str
    refs_sha256: str
    worktree_status_sha256: str
    worktree_clean: bool


def _fail(message: str) -> NoReturn:
    raise GateError(message)


def _validated_git_relative_path(raw: bytes, *, boundary: str) -> str:
    try:
        value = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail(f"{boundary} contains a non-UTF-8 path")
    if (
        not value
        or len(raw) > _GIT_FIELD_LIMIT_BYTES
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(character < " " or character == "\x7f" for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        _fail(f"{boundary} contains an invalid path")
    return value


def parse_porcelain_status(payload: bytes) -> tuple[str, bool]:
    """Validate and digest porcelain-v1 `-z` status without rendering paths."""
    if type(payload) is not bytes or len(payload) > _TOOL_STDOUT_LIMIT_BYTES:
        _fail("Git worktree status evidence is invalid")
    digest = hashlib.sha256(payload).hexdigest()
    if not payload:
        return digest, True
    if not payload.endswith(b"\0"):
        _fail("Git worktree status evidence is truncated")
    records = payload[:-1].split(b"\0")
    index = 0
    while index < len(records):
        record = records[index]
        if len(record) < _PORCELAIN_STATUS_RECORD_MIN_BYTES or record[2:3] != b" ":
            _fail("Git worktree status record is invalid")
        status_code = record[:2]
        if status_code == b"??":
            rename_or_copy = False
        elif (
            status_code == b"  "
            or b"?" in status_code
            or b"!" in status_code
            or any(code not in b" MADRCU" for code in status_code)
        ):
            _fail("Git worktree status code is invalid")
        else:
            rename_or_copy = b"R" in status_code or b"C" in status_code
        _ = _validated_git_relative_path(
            record[3:],
            boundary="Git worktree status evidence",
        )
        index += 1
        if rename_or_copy:
            if index >= len(records):
                _fail("Git worktree status rename record is truncated")
            _ = _validated_git_relative_path(
                records[index],
                boundary="Git worktree status evidence",
            )
            index += 1
    return digest, False


@dataclass(frozen=True, slots=True)
class GateArguments:
    """Typed command-line arguments for the quality runner."""

    paths: tuple[Path, ...]
    node_executable: Path
    worktree: Path
    cache_dir: Path | None
    self_test: bool
    require_clean: bool
    candidate: str | None


@dataclass(frozen=True, slots=True)
class QualityGateRequest:
    """Immutable inputs for one in-process quality run."""

    paths: tuple[Path, ...] | None
    node_executable: Path
    cache_dir: Path | None
    expected_git_snapshot: GitSnapshot | None


@dataclass(frozen=True, slots=True)
class _GateExecution:
    """Validated immutable command-execution context."""

    root: Path
    paths: tuple[Path, ...]
    cache: Path
    reviewed_node: Path


def _expand(path: Path) -> tuple[Path, ...]:
    try:
        supplied_status = path.lstat()
    except OSError:
        _fail("quality fingerprint input does not exist")
    if stat.S_ISLNK(supplied_status.st_mode):
        _fail("quality fingerprint input contains a symlink")
    if stat.S_ISREG(supplied_status.st_mode):
        return (path,)
    if not stat.S_ISDIR(supplied_status.st_mode):
        _fail("quality fingerprint input contains a special file")
    return _expand_directory(path)


def _expand_directory(path: Path) -> tuple[Path, ...]:
    expanded: list[Path] = []
    for candidate in path.rglob("*"):
        relative_parts = candidate.relative_to(path).parts
        if any(part in _TRANSIENT_DIRECTORY_NAMES for part in relative_parts):
            continue
        try:
            status = candidate.lstat()
        except OSError:
            _fail("quality fingerprint input changed during traversal")
        if stat.S_ISLNK(status.st_mode):
            _fail("quality fingerprint input contains a symlink")
        if stat.S_ISREG(status.st_mode):
            expanded.append(candidate)
        elif not stat.S_ISDIR(status.st_mode):
            _fail("quality fingerprint input contains a special file")
    return tuple(sorted(expanded))


def _file_metadata(status: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _fingerprint_file(
    digest: _Digest,
    relative: str,
    path: Path,
    total: int,
) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
    except OSError:
        _fail("quality fingerprint input could not be opened")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != before_path.st_dev
            or before.st_ino != before_path.st_ino
            or before.st_size > _SOURCE_FILE_LIMIT_BYTES
        ):
            _fail("quality fingerprint input is not a bounded regular file")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                _fail("quality fingerprint input was truncated while reading")
            digest.update(chunk)
            remaining -= len(chunk)
            total += len(chunk)
            if total > _SOURCE_TOTAL_LIMIT_BYTES:
                _fail("quality fingerprint input exceeds the total byte limit")
        after = os.fstat(descriptor)
        after_path = path.lstat()
        if _file_metadata(before) != _file_metadata(after) or _file_metadata(
            after
        ) != _file_metadata(after_path):
            _fail("quality fingerprint input changed while it was read")
        return total
    finally:
        os.close(descriptor)


def fingerprint_paths(paths: Iterable[Path], *, root: Path) -> str:
    """Hash every selected path and its bytes in deterministic order."""
    canonical_root = root.resolve(strict=True)
    digest = hashlib.sha256()
    expanded: list[Path] = []
    for path in paths:
        candidate = path if path.is_absolute() else canonical_root / path
        expanded.extend(_expand(candidate))
    total = 0
    relative_files: list[tuple[str, Path]] = []
    for path in set(expanded):
        try:
            relative = path.relative_to(canonical_root).as_posix()
        except ValueError:
            _fail("quality fingerprint input escapes the worktree")
        relative_files.append((relative, path))
    for relative, path in sorted(relative_files):
        total = _fingerprint_file(digest, relative, path, total)
    return digest.hexdigest()


def _resolve_inventory_input(canonical_root: Path, supplied: Path) -> Path:
    if not supplied.is_absolute() and any(
        part in {".", ".."} for part in supplied.parts
    ):
        _fail("quality input path is ambiguous")
    lexical = supplied if supplied.is_absolute() else canonical_root / supplied
    try:
        relative = lexical.relative_to(canonical_root)
    except ValueError:
        _fail("quality input path escapes the worktree")
    cursor = canonical_root
    for part in relative.parts:
        cursor /= part
        try:
            status = cursor.lstat()
        except OSError:
            _fail("quality input path does not exist")
        if stat.S_ISLNK(status.st_mode):
            _fail("quality input inventory contains a symlink")
    try:
        canonical = lexical.resolve(strict=True)
    except OSError:
        _fail("quality input path does not exist")
    if canonical != lexical:
        _fail("quality input path is not canonical")
    return canonical


def _inventory_files(canonical_root: Path, canonical: Path) -> set[str]:
    inventory: set[str] = set()
    candidates = (canonical,) if canonical.is_file() else tuple(canonical.rglob("*"))
    for candidate in candidates:
        candidate_relative = candidate.relative_to(canonical_root)
        if any(part in _TRANSIENT_DIRECTORY_NAMES for part in candidate_relative.parts):
            continue
        try:
            status = candidate.lstat()
        except OSError:
            _fail("quality input path changed during inventory")
        if stat.S_ISLNK(status.st_mode):
            _fail("quality input inventory contains a symlink")
        if stat.S_ISDIR(status.st_mode):
            continue
        if not stat.S_ISREG(status.st_mode):
            _fail("quality input inventory contains a special file")
        inventory.add(candidate_relative.as_posix())
    return inventory


def freeze_input_inventory(
    root: Path,
    paths: Sequence[Path],
) -> frozenset[str]:
    """Return a closed, regular, symlink-free repository input inventory."""
    canonical_root = root.resolve(strict=True)
    inventory: set[str] = set()
    for supplied in paths:
        canonical = _resolve_inventory_input(canonical_root, supplied)
        inventory.update(_inventory_files(canonical_root, canonical))
    return frozenset(inventory)


def _decode_bounded_git_field(raw: bytes, *, boundary: str) -> str:
    try:
        value = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail(f"{boundary} is not UTF-8")
    if (
        not value
        or len(raw) > _GIT_FIELD_LIMIT_BYTES
        or any(character < " " or character == "\x7f" for character in value)
    ):
        _fail(f"{boundary} is invalid")
    return value


def _canonical_existing_worktree(path: Path, *, boundary: str) -> Path:
    if not path.is_absolute():
        _fail(f"{boundary} is not absolute")
    try:
        canonical = path.resolve(strict=True)
    except OSError:
        _fail(f"{boundary} is unavailable")
    if canonical != path or not canonical.is_dir():
        _fail(f"{boundary} is not canonical")
    return canonical


def _validate_worktree_branch(field: bytes) -> None:
    if field == b"detached":
        return
    if not field.startswith(b"branch refs/heads/"):
        _fail("registered worktree branch is invalid")
    _ = _decode_bounded_git_field(
        field.removeprefix(b"branch "),
        boundary="registered worktree branch",
    )


def _validate_worktree_optional_fields(fields: Sequence[bytes]) -> None:
    optional_tags: set[bytes] = set()
    for field in fields:
        tag, separator, reason = field.partition(b" ")
        if tag not in {b"locked", b"prunable"} or tag in optional_tags:
            _fail("registered worktree optional field is invalid")
        optional_tags.add(tag)
        if separator:
            _ = _decode_bounded_git_field(
                reason,
                boundary="registered worktree optional reason",
            )


def _parse_registered_worktree_block(block: bytes) -> Path | None:
    fields = block.split(b"\0")
    if len(fields) < _WORKTREE_REQUIRED_FIELD_COUNT or not fields[0].startswith(
        b"worktree "
    ):
        _fail("registered worktree record is incomplete")
    path_text = _decode_bounded_git_field(
        fields[0].removeprefix(b"worktree "),
        boundary="registered worktree path",
    )
    if re.fullmatch(rb"HEAD [0-9a-f]{40}", fields[1]) is None:
        _fail("registered worktree HEAD is invalid")
    _validate_worktree_branch(fields[2])
    optional_fields = fields[_WORKTREE_REQUIRED_FIELD_COUNT:]
    _validate_worktree_optional_fields(optional_fields)
    path = Path(path_text)
    try:
        canonical = _canonical_existing_worktree(
            path,
            boundary="registered worktree path",
        )
    except GateError:
        is_prunable = any(
            field.partition(b" ")[0] == b"prunable" for field in optional_fields
        )
        if path.is_absolute() and is_prunable and not os.path.lexists(path):
            return None
        raise
    return canonical


def parse_registered_worktrees(
    payload: bytes,
    *,
    current_root: Path,
) -> tuple[Path, ...]:
    """Parse bounded Git porcelain-v1 worktree records without path logging."""
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > _TOOL_STDOUT_LIMIT_BYTES
        or not payload.endswith(b"\0\0")
    ):
        _fail("registered worktree evidence is truncated or invalid")
    canonical_current = _canonical_existing_worktree(
        current_root,
        boundary="current worktree",
    )
    parsed = tuple(
        _parse_registered_worktree_block(block) for block in payload[:-2].split(b"\0\0")
    )
    roots = tuple(root for root in parsed if root is not None)
    if len(roots) != len(set(roots)):
        _fail("registered worktree inventory is duplicated")
    if canonical_current not in roots:
        _fail("current worktree is absent from registered evidence")
    return roots


def registered_worktree_roots(root: Path) -> tuple[Path, ...]:
    """Enumerate every registered worktree through bounded reviewed Git."""
    result = run_bounded_command(
        ("/usr/bin/git", "worktree", "list", "--porcelain", "-z"),
        root=root,
        cache_dir=Path("/dev/null"),
    )
    return parse_registered_worktrees(result.stdout, current_root=root)


def _canonical_registered_worktrees(
    registered_worktrees: tuple[Path, ...],
) -> tuple[Path, ...]:
    if not registered_worktrees:
        _fail("registered worktree inventory is empty")
    canonical = tuple(
        _canonical_existing_worktree(
            registered,
            boundary="registered worktree path",
        )
        for registered in registered_worktrees
    )
    if len(canonical) != len(set(canonical)):
        _fail("registered worktree inventory is duplicated")
    return canonical


def _canonical_new_cache(cache_dir: Path) -> Path:
    if os.path.lexists(cache_dir):
        _fail("quality cache must not already exist")
    try:
        parent = cache_dir.parent.resolve(strict=True)
    except OSError:
        _fail("quality cache parent does not exist")
    if parent != cache_dir.parent:
        _fail("quality cache parent must be canonical and symlink-free")
    return parent / cache_dir.name


def _paths_intersect(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def validate_external_cache(
    worktree: Path,
    cache_dir: Path,
    *,
    registered_worktrees: tuple[Path, ...],
) -> Path:
    """Require an absolute cache outside every registered worktree."""
    if not worktree.is_absolute() or not cache_dir.is_absolute():
        _fail("worktree and cache directory must be absolute")
    canonical_worktrees = _canonical_registered_worktrees(registered_worktrees)
    root = _canonical_existing_worktree(worktree, boundary="current worktree")
    if root not in canonical_worktrees:
        _fail("current worktree is absent from the registered inventory")
    cache = _canonical_new_cache(cache_dir)
    if any(_paths_intersect(cache, registered) for registered in canonical_worktrees):
        _fail("quality cache must be outside every registered worktree")
    return cache


def command_plan(
    root: Path,
    paths: Sequence[Path],
    *,
    node_executable: Path,
) -> tuple[ToolCommand, ...]:
    """Return the fixed format, lint, Pyright, and mypy command sequence."""
    selected_paths = tuple(paths)
    if Path("typings") not in selected_paths:
        selected_paths += (Path("typings"),)
    selected = tuple((root / path).as_posix() for path in selected_paths)
    config = ("--config", (root / "pyproject.toml").as_posix())
    ruff = (root / ".venv" / "bin" / "ruff").as_posix()
    pyright = (root / "node_modules" / "pyright" / "index.js").as_posix()
    mypy = (root / ".venv" / "bin" / "mypy").as_posix()
    commands: list[ToolCommand] = [
        ToolCommand(
            tool="ruff",
            version="0.16.3",
            python_target="3.12",
            diagnostic=False,
            argv=(ruff, "format", "--check", *config, *selected),
        ),
        ToolCommand(
            tool="ruff",
            version="0.16.3",
            python_target="3.12",
            diagnostic=True,
            argv=(ruff, "check", "--output-format", "json", *config, *selected),
        ),
    ]
    for python_target in ("3.12", "3.13", "3.14"):
        commands.extend(
            (
                ToolCommand(
                    tool="pyright",
                    version="1.1.413",
                    python_target=python_target,
                    diagnostic=True,
                    argv=(
                        node_executable.as_posix(),
                        pyright,
                        "--outputjson",
                        "--pythonversion",
                        python_target,
                        "--project",
                        (root / "pyrightconfig.json").as_posix(),
                        *selected,
                    ),
                ),
                ToolCommand(
                    tool="mypy",
                    version="2.3.1",
                    python_target=python_target,
                    diagnostic=True,
                    argv=(
                        mypy,
                        "--output",
                        "json",
                        "--no-error-summary",
                        "--python-version",
                        python_target,
                        "--config-file",
                        (root / "pyproject.toml").as_posix(),
                        *selected,
                    ),
                ),
            )
        )
    return tuple(commands)


def version_probes(root: Path, node_executable: Path) -> tuple[VersionProbe, ...]:
    """Return the exact bounded version probes for the pinned analyzers."""
    return (
        VersionProbe(
            command=((root / ".venv" / "bin" / "ruff").as_posix(), "--version"),
            expected_stdout=b"ruff 0.16.3\n",
        ),
        VersionProbe(
            command=(node_executable.as_posix(), "--version"),
            expected_stdout=b"v24.19.0\n",
        ),
        VersionProbe(
            command=(
                node_executable.as_posix(),
                (root / "node_modules" / "pyright" / "index.js").as_posix(),
                "--version",
            ),
            expected_stdout=b"pyright 1.1.413\n",
        ),
        VersionProbe(
            command=((root / ".venv" / "bin" / "mypy").as_posix(), "--version"),
            expected_stdout=b"mypy 2.3.1 (compiled: yes)\n",
        ),
    )


def _closed_environment(cache_dir: Path) -> dict[str, str]:
    return {
        "FORCE_COLOR": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "MYPY_CACHE_DIR": (cache_dir / "mypy").as_posix(),
        "NO_COLOR": "1",
        "PATH": os.pathsep.join(("/usr/bin", "/bin")),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPYCACHEPREFIX": (cache_dir / "pycache").as_posix(),
        "RUFF_CACHE_DIR": (cache_dir / "ruff").as_posix(),
    }


def _validated_executable(command: tuple[str, ...]) -> Path:
    if not command or not command[0] or "\0" in command[0]:
        _fail("tool command is empty or invalid")
    candidate = Path(command[0])
    if not candidate.is_absolute():
        _fail("tool command requires an absolute reviewed executable")
    try:
        resolved = candidate.resolve(strict=True)
        status = candidate.stat(follow_symlinks=False)
    except OSError:
        _fail("tool command executable is unavailable")
    if (
        resolved != candidate
        or not stat.S_ISREG(status.st_mode)
        or not os.access(candidate, os.X_OK)
    ):
        _fail("tool command executable is not a regular executable")
    return candidate


def _stable_regular_file_sha256(path: Path, *, max_bytes: int) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail("reviewed executable could not be opened")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > max_bytes
        ):
            _fail("reviewed executable is not a bounded single-link regular file")
        digest = hashlib.sha256()
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, max_bytes + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if total > max_bytes:
            _fail("reviewed executable exceeds its byte limit")
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            _fail("reviewed executable changed while it was hashed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def validate_managed_node(root: Path, node_executable: Path) -> Path:
    """Bind a canonical Node executable to the accepted bootstrap-lock bytes."""
    try:
        records = load_lock(root / "security" / "bootstrap-toolchain-lock.json")
    except (OSError, ToolchainError):
        _fail("bootstrap toolchain lock is invalid")
    dependencies = tuple(
        dependency
        for record in records
        if record.tool == "npm"
        and record.target == "x86_64-unknown-linux-gnu"
        and record.lock_review_status == "accepted"
        for dependency in record.runtime_dependencies
        if dependency.tool == "node"
    )
    if len(dependencies) != 1 or dependencies[0].chosen_version != "24.19.0":
        _fail("bootstrap toolchain lock has no unique reviewed Node dependency")
    reviewed = _validated_executable((node_executable.as_posix(),))
    if (
        _stable_regular_file_sha256(reviewed, max_bytes=_EXECUTABLE_LIMIT_BYTES)
        != dependencies[0].executable_sha256
    ):
        _fail("managed Node executable does not match its locked digest")
    return reviewed


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        _ = process.wait(timeout=_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        _ = process.wait()


def _consume_pipe_event(
    descriptor: int,
    event: int,
    stream: bytearray,
    ceiling: int,
) -> bool:
    if event & select.POLLNVAL:
        _fail("tool process pipe became invalid")
    chunk = os.read(descriptor, _READ_CHUNK_BYTES)
    if not chunk:
        return False
    stream.extend(chunk)
    if len(stream) > ceiling:
        _fail("tool output limit exceeded")
    return True


def _read_bounded_streams(
    process: subprocess.Popen[bytes],
    *,
    limits: ExecutionLimits,
) -> tuple[bytes, bytes]:
    stdout_value = cast("object", process.stdout)
    stderr_value = cast("object", process.stderr)
    if stdout_value is None or stderr_value is None:
        _kill_process_group(process)
        _fail("tool process pipes were not created")
    stdout_pipe = cast("BinaryIO", stdout_value)
    stderr_pipe = cast("BinaryIO", stderr_value)
    descriptors = {
        stdout_pipe.fileno(): "stdout",
        stderr_pipe.fileno(): "stderr",
    }
    poller = select.poll()
    for descriptor in descriptors:
        poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    ceilings = {
        "stdout": limits.stdout_limit_bytes,
        "stderr": limits.stderr_limit_bytes,
    }
    deadline = time.monotonic() + limits.timeout_seconds
    try:
        while descriptors:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                _fail("tool process exceeded its deadline")
            timeout_milliseconds = max(1, int(remaining * 1000))
            events = poller.poll(timeout_milliseconds)
            if not events:
                _kill_process_group(process)
                _fail("tool process exceeded its deadline")
            for descriptor, event in events:
                name = descriptors[descriptor]
                if not _consume_pipe_event(
                    descriptor,
                    event,
                    streams[name],
                    ceilings[name],
                ):
                    poller.unregister(descriptor)
                    del descriptors[descriptor]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_process_group(process)
            _fail("tool process exceeded its deadline")
        try:
            _ = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            _fail("tool process exceeded its deadline")
        return bytes(streams["stdout"]), bytes(streams["stderr"])
    finally:
        stdout_pipe.close()
        stderr_pipe.close()


def _stream_evidence(stream: bytes) -> str:
    return f"bytes={len(stream)} sha256={hashlib.sha256(stream).hexdigest()}"


def run_bounded_command(
    command: tuple[str, ...],
    *,
    root: Path,
    cache_dir: Path,
    policy: ExecutionPolicy = _DEFAULT_EXECUTION_POLICY,
) -> CommandResult:
    """Run one reviewed executable with bounded output and process cleanup."""
    executable = _validated_executable(command)
    argv = (executable.as_posix(), *command[1:])
    try:
        # S603 is narrowly accepted here: argv[0] is an absolute, resolved,
        # executable regular file; shell=False and the environment is closed.
        process = subprocess.Popen(  # noqa: S603
            argv,
            cwd=root,
            env=_closed_environment(cache_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
            shell=False,
        )
    except OSError:
        _fail("tool process could not be started")
    try:
        stdout, stderr = _read_bounded_streams(process, limits=policy.limits)
        returncode_value = cast("object", process.returncode)
        if returncode_value is None:
            _fail("tool process status is unavailable")
        if type(returncode_value) is not int:
            _fail("tool process status has an invalid runtime type")
        returncode = returncode_value
        if returncode < 0:
            _fail("tool process terminated by signal")
        if stderr:
            whitespace_only = all(byte in b" \t\r\n\v\f" for byte in stderr)
            if not policy.allow_ascii_whitespace_stderr or not whitespace_only:
                _fail(
                    "tool emitted forbidden stderr bytes ("
                    + _stream_evidence(stderr)
                    + ")"
                )
        if returncode != 0 and not (policy.allow_diagnostics and returncode == 1):
            _fail(
                "".join(
                    (
                        "tool exited with an invalid status ",
                        f"status={returncode} stdout({_stream_evidence(stdout)}) ",
                        f"stderr({_stream_evidence(stderr)})",
                    )
                )
            )
        return CommandResult(
            argv=argv,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )
    finally:
        _kill_process_group(process)


def verify_exact_version(
    command: tuple[str, ...],
    *,
    expected_stdout: bytes,
    root: Path,
    cache_dir: Path,
) -> None:
    """Require one reviewed executable to emit its exact pinned version."""
    if type(expected_stdout) is not bytes or not expected_stdout:
        _fail("expected version output must be immutable nonempty bytes")
    result = run_bounded_command(command, root=root, cache_dir=cache_dir)
    if result.stdout != expected_stdout:
        _fail(
            "".join(
                (
                    "tool version output is not exact ",
                    f"stdout({_stream_evidence(result.stdout)})",
                )
            )
        )


def git_snapshot(root: Path, cache_dir: Path) -> GitSnapshot:
    """Capture bounded logical HEAD, index, and reference evidence."""
    git = "/usr/bin/git"
    head_result = run_bounded_command(
        (git, "rev-parse", "--verify", "HEAD"),
        root=root,
        cache_dir=cache_dir,
    )
    try:
        head = head_result.stdout.decode("ascii", errors="strict").removesuffix("\n")
    except UnicodeDecodeError:
        _fail("Git HEAD evidence is not ASCII")
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        _fail("Git HEAD evidence is malformed")
    staged = run_bounded_command(
        (git, "ls-files", "--stage", "-z"),
        root=root,
        cache_dir=cache_dir,
    ).stdout
    refs = run_bounded_command(
        (git, "show-ref", "--head", "--dereference"),
        root=root,
        cache_dir=cache_dir,
    ).stdout
    status = run_bounded_command(
        (git, "status", "--porcelain=v1", "-z", "--untracked-files=all"),
        root=root,
        cache_dir=cache_dir,
    ).stdout
    status_sha256, worktree_clean = parse_porcelain_status(status)
    return GitSnapshot(
        head=head,
        staged_entries_sha256=hashlib.sha256(staged).hexdigest(),
        refs_sha256=hashlib.sha256(refs).hexdigest(),
        worktree_status_sha256=status_sha256,
        worktree_clean=worktree_clean,
    )


def _selected_paths(paths: tuple[Path, ...] | None) -> tuple[Path, ...]:
    selected = paths or (Path("src"), Path("tests"), Path("scripts"))
    return selected if Path("typings") in selected else (*selected, Path("typings"))


@contextmanager
def _quality_cache(root: Path, requested: Path | None) -> Generator[Path]:
    registered = registered_worktree_roots(root)
    if requested is None:
        with tempfile.TemporaryDirectory(prefix="nplg-quality-") as temporary:
            cache = Path(temporary).resolve(strict=True)
            if any(
                cache == worktree
                or worktree in cache.parents
                or cache in worktree.parents
                for worktree in registered
            ):
                _fail("temporary quality cache intersects a registered worktree")
            yield cache
        return
    cache = validate_external_cache(
        root,
        requested,
        registered_worktrees=registered,
    )
    cache.mkdir(mode=0o700)
    yield cache


def _checked_paths(root: Path, selected: tuple[Path, ...]) -> tuple[Path, ...]:
    return tuple(
        root / path
        for path in (
            *selected,
            Path("pyproject.toml"),
            Path("pyrightconfig.json"),
            Path("package-lock.json"),
            Path("requirements-dev.lock"),
            Path("security/bootstrap-toolchain-lock.json"),
            Path("scripts/run_quality_gate.py"),
        )
    )


def _verify_versions(root: Path, cache: Path, reviewed_node: Path) -> None:
    for probe in version_probes(root, reviewed_node):
        verify_exact_version(
            probe.command,
            root=root,
            cache_dir=cache,
            expected_stdout=probe.expected_stdout,
        )


def _run_quality_commands(execution: _GateExecution) -> None:
    """Run each exact quality command in fail-closed direct-zero mode."""
    for command in command_plan(
        execution.root,
        execution.paths,
        node_executable=execution.reviewed_node,
    ):
        _ = run_bounded_command(
            command.argv,
            root=execution.root,
            cache_dir=execution.cache,
            policy=ExecutionPolicy(
                allow_ascii_whitespace_stderr=command.tool == "pyright",
            ),
        )


def run_quality_gate(
    root: Path,
    request: QualityGateRequest,
) -> None:
    """Run the ordered quality commands and require literal global zero."""
    canonical_root = root.resolve(strict=True)
    selected = _selected_paths(request.paths)
    with _quality_cache(canonical_root, request.cache_dir) as cache:
        _ = freeze_input_inventory(canonical_root, selected)
        checked = _checked_paths(canonical_root, selected)
        before = fingerprint_paths(checked, root=canonical_root)
        git_before = git_snapshot(canonical_root, cache)
        if request.expected_git_snapshot is not None and (
            git_before != request.expected_git_snapshot or not git_before.worktree_clean
        ):
            _fail("release repository state changed after validation")
        reviewed_node = validate_managed_node(canonical_root, request.node_executable)
        _verify_versions(canonical_root, cache, reviewed_node)
        _run_quality_commands(
            _GateExecution(
                root=canonical_root,
                paths=selected,
                cache=cache,
                reviewed_node=reviewed_node,
            )
        )
        after = fingerprint_paths(checked, root=canonical_root)
        if after != before:
            _fail("quality tools mutated checked repository bytes")
        git_after = git_snapshot(canonical_root, cache)
        if git_after != git_before:
            _fail("quality tools mutated repository state")


def run_self_test(root: Path, node_executable: Path) -> None:
    """Prove real Ruff and strict-type findings cannot false-green the gate."""
    root = root.resolve(strict=True)
    checked = tuple(
        root / path
        for path in (
            Path("src"),
            Path("tests"),
            Path("scripts"),
            Path("typings"),
            Path("pyproject.toml"),
            Path("pyrightconfig.json"),
            Path("package-lock.json"),
            Path("requirements-dev.lock"),
            Path("security/bootstrap-toolchain-lock.json"),
        )
    )
    before = fingerprint_paths(checked, root=root)
    with tempfile.TemporaryDirectory(prefix="nplg-quality-self-test-") as temporary:
        temporary_path = Path(temporary)
        cache = temporary_path / "cache"
        cache.mkdir(mode=0o700)
        git_before = git_snapshot(root, cache)
        probe = temporary_path / "probe.py"
        probe_payload = b"".join(
            (
                b"# Copyright (c) 2026 David Osipov\n",
                b'"""Quality gate adversarial self-test."""\n\n',
                b"import os\n\n",
                b'value: int = "not-an-int"\n',
            )
        )
        _ = probe.write_bytes(probe_payload)
        reviewed_node = validate_managed_node(root, node_executable)
        for version_probe in version_probes(root, reviewed_node):
            verify_exact_version(
                version_probe.command,
                expected_stdout=version_probe.expected_stdout,
                root=root,
                cache_dir=cache,
            )
        commands: tuple[ToolCommand, ToolCommand, ToolCommand] = (
            ToolCommand(
                tool="ruff",
                version="0.16.3",
                python_target="3.12",
                diagnostic=True,
                argv=(
                    (root / ".venv" / "bin" / "ruff").as_posix(),
                    "check",
                    "--output-format",
                    "json",
                    "--config",
                    (root / "pyproject.toml").as_posix(),
                    probe.as_posix(),
                ),
            ),
            ToolCommand(
                tool="pyright",
                version="1.1.413",
                python_target="3.12",
                diagnostic=True,
                argv=(
                    reviewed_node.as_posix(),
                    (root / "node_modules" / "pyright" / "index.js").as_posix(),
                    "--outputjson",
                    "--pythonversion",
                    "3.12",
                    "--project",
                    (root / "pyrightconfig.json").as_posix(),
                    probe.as_posix(),
                ),
            ),
            ToolCommand(
                tool="mypy",
                version="2.3.1",
                python_target="3.12",
                diagnostic=True,
                argv=(
                    (root / ".venv" / "bin" / "mypy").as_posix(),
                    "--output",
                    "json",
                    "--no-error-summary",
                    "--python-version",
                    "3.12",
                    "--config-file",
                    (root / "pyproject.toml").as_posix(),
                    probe.as_posix(),
                ),
            ),
        )
        observed_diagnostic_tools: set[ToolName] = set()
        for command in commands:
            result = run_bounded_command(
                command.argv,
                root=root,
                cache_dir=cache,
                policy=ExecutionPolicy(
                    allow_diagnostics=True,
                    allow_ascii_whitespace_stderr=command.tool == "pyright",
                ),
            )
            if (
                result.argv != command.argv
                or result.returncode != 1
                or not result.stdout
            ):
                _fail("quality self-test diagnostic result was not exact")
            observed_diagnostic_tools.add(command.tool)
        failure_commands: tuple[ToolCommand, ToolCommand] = (
            commands[0],
            commands[1],
        )
        for command in failure_commands:
            try:
                _ = run_bounded_command(
                    command.argv,
                    root=root,
                    cache_dir=cache,
                    policy=ExecutionPolicy(
                        allow_ascii_whitespace_stderr=command.tool == "pyright"
                    ),
                )
            except GateError:
                continue
            _fail("final quality mode accepted a diagnostic exit")
        if git_snapshot(root, cache) != git_before:
            _fail("quality self-test mutated repository index, HEAD, or refs")
    if temporary_path.exists():
        _fail("quality self-test temporary state was not removed")
    after = fingerprint_paths(checked, root=root)
    if after != before:
        _fail("quality self-test mutated checked repository bytes")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=None,
    )
    _ = parser.add_argument("--worktree", type=Path, default=Path())
    _ = parser.add_argument("--node-executable", type=Path, required=True)
    _ = parser.add_argument("--cache-dir", type=Path)
    _ = parser.add_argument("--self-test", action="store_true")
    _ = parser.add_argument("--require-clean", action="store_true")
    _ = parser.add_argument("--candidate")
    return parser


def parse_arguments(argv: Sequence[str] | None) -> GateArguments:
    """Parse the complete typed command-line contract."""
    values = cast("dict[str, object]", vars(_parser().parse_args(argv)))
    paths_value = values["paths"]
    paths = (
        [Path("src"), Path("tests"), Path("scripts"), Path("typings")]
        if not paths_value
        else cast("list[Path]", paths_value)
    )
    worktree = cast("Path", values["worktree"])
    node_executable = cast("Path", values["node_executable"])
    cache_dir = cast("Path | None", values["cache_dir"])
    self_test = cast("bool", values["self_test"])
    require_clean = cast("bool", values["require_clean"])
    candidate = cast("str | None", values["candidate"])
    return GateArguments(
        paths=tuple(paths),
        node_executable=node_executable,
        worktree=worktree,
        cache_dir=cache_dir,
        self_test=self_test,
        require_clean=require_clean,
        candidate=candidate,
    )


def validate_release_arguments(arguments: GateArguments) -> None:
    """Require a complete explicit identity for release-mode execution."""
    if arguments.candidate is not None and not arguments.require_clean:
        _fail("release mode candidate requires --require-clean")
    if not arguments.require_clean:
        return
    if (
        not arguments.worktree.is_absolute()
        or arguments.cache_dir is None
        or not arguments.cache_dir.is_absolute()
        or arguments.candidate is None
        or re.fullmatch(r"[0-9a-f]{40}", arguments.candidate) is None
    ):
        _fail("release mode requires exact absolute paths and candidate commit")


def validate_release_state(
    root: Path,
    cache_dir: Path,
    candidate: str,
) -> GitSnapshot:
    """Bind a clean release worktree to its exact candidate commit."""
    snapshot = git_snapshot(root, cache_dir)
    if not snapshot.worktree_clean:
        _fail("release quality gate requires a clean worktree")
    if snapshot.head != candidate:
        _fail("release candidate does not equal HEAD")
    return snapshot


def main(argv: Sequence[str] | None = None) -> int:
    """Run the quality gate command-line interface."""
    args = parse_arguments(argv)
    validate_release_arguments(args)
    root = args.worktree.resolve()
    expected_git_snapshot: GitSnapshot | None = None
    if args.self_test:
        if (
            args.cache_dir is not None
            or args.require_clean
            or args.candidate is not None
        ):
            _fail("self-test cannot be combined with gate or release options")
        run_self_test(root, args.node_executable)
        return 0
    if args.require_clean:
        expected_git_snapshot = validate_release_state(
            root,
            cast("Path", args.cache_dir),
            cast("str", args.candidate),
        )
    run_quality_gate(
        root,
        QualityGateRequest(
            paths=args.paths,
            node_executable=args.node_executable,
            cache_dir=args.cache_dir,
            expected_git_snapshot=expected_git_snapshot,
        ),
    )
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    """Render one bounded process-facing error without an internal traceback."""
    try:
        return main(argv)
    except GateError as error:
        rendered = "quality gate failed: " + str(error) + "\n"
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write(rendered)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
