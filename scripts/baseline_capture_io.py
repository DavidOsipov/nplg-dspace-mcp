# Copyright (c) 2026 David Osipov
"""Closed, typed operating-system and Git boundary for baseline capture."""

from __future__ import annotations

import hashlib
import json
import os
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Generator, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

BASELINE_FILES: tuple[BaselineFileName, ...] = (
    "tool-catalog.json",
    "resources.json",
    "result-cases.json",
    "error-cases.json",
)
BASELINE_MANIFEST_FILE = "manifest.json"
BASELINE_DIRECTORY_FILES = (*BASELINE_FILES, BASELINE_MANIFEST_FILE)
EXCLUDED_OUTPUT_PATHS = tuple(
    f"contracts/baseline/{name}" for name in BASELINE_DIRECTORY_FILES
)
INCLUDED_UNTRACKED_PATHS: IncludedUntrackedPaths = (
    "contracts/zod/asvs-evidence-contracts.mjs",
    "contracts/zod/baseline-contracts.mjs",
    "docs/security/threat-model.json",
    "eslint.config.mjs",
    "scripts/baseline_capture_io.py",
    "scripts/baseline_replay.py",
    "tests/contracts/zod_asvs_evidence_contracts.test.mjs",
    "tests/contracts/zod_baseline_contracts.test.mjs",
    "tests/property/test_asvs_evidence.py",
    "tests/unit/test_build_asvs_matrix.py",
    "tsconfig.contracts.json",
)
MAX_CANONICAL_JSON_BYTES = 4 * 1024 * 1024
MAX_CANONICAL_JSON_DEPTH = 64
MIN_CANONICAL_JSON_INTEGER = -(2**63)
MAX_CANONICAL_JSON_INTEGER = (2**63) - 1
MAX_MATERIALIZED_FILE_BYTES = 8 * 1024 * 1024
MAX_MATERIALIZED_TREE_BYTES = 64 * 1024 * 1024
MAX_MATERIALIZED_TREE_ENTRIES = 10_000
MAX_GIT_STDOUT_BYTES = 16 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
GIT_TIMEOUT_SECONDS = 15.0
MAX_GIT_INDEX_BYTES = 16 * 1024 * 1024
MAX_GIT_METADATA_BYTES = 4 * 1024 * 1024
MAX_REAL_OBJECT_DATABASE_BYTES = 512 * 1024 * 1024
MAX_REAL_OBJECT_DATABASE_ENTRIES = 100_000
O_CLOEXEC: Final = os.O_CLOEXEC
O_DIRECTORY: Final = os.O_DIRECTORY
O_NOFOLLOW: Final = os.O_NOFOLLOW
REGULAR_FILE_MODE: Final = 0o644
PRIVATE_DIRECTORY_MODE: Final = 0o700
PRIVATE_FILE_MODE: Final = 0o600
SHA1_HEX_LENGTH = 40
CONTROL_CHARACTER_BOUNDARY = 32
DELETE_CHARACTER = 127
PACKED_REFERENCE_FIELDS = 2
TREE_RECORD_FIELDS = 4
HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitObjectId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
type BaselineFileName = Literal[
    "tool-catalog.json",
    "resources.json",
    "result-cases.json",
    "error-cases.json",
]
type BaselineOutputPath = Literal[
    "contracts/baseline/tool-catalog.json",
    "contracts/baseline/resources.json",
    "contracts/baseline/result-cases.json",
    "contracts/baseline/error-cases.json",
    "contracts/baseline/manifest.json",
]
type IncludedUntrackedPaths = tuple[
    Literal["contracts/zod/asvs-evidence-contracts.mjs"],
    Literal["contracts/zod/baseline-contracts.mjs"],
    Literal["docs/security/threat-model.json"],
    Literal["eslint.config.mjs"],
    Literal["scripts/baseline_capture_io.py"],
    Literal["scripts/baseline_replay.py"],
    Literal["tests/contracts/zod_asvs_evidence_contracts.test.mjs"],
    Literal["tests/contracts/zod_baseline_contracts.test.mjs"],
    Literal["tests/property/test_asvs_evidence.py"],
    Literal["tests/unit/test_build_asvs_matrix.py"],
    Literal["tsconfig.contracts.json"],
]
type JsonValue = bool | int | str | list[JsonValue] | dict[str, JsonValue] | None
type JsonObject = dict[str, JsonValue]


class BaselineCaptureError(RuntimeError):
    """Raised when baseline input or publication cannot be trusted."""


class _IoModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
    )


class CaptureInputIdentity(_IoModel):
    """Synthetic input-tree identity bound into the baseline manifest."""

    tree_before: GitObjectId
    tree_after: GitObjectId
    src_tree: GitObjectId
    git_object_format: Literal["sha1"]
    excluded_output_paths: Annotated[
        tuple[BaselineOutputPath, ...],
        Field(min_length=5, max_length=5),
    ]
    included_untracked_paths: IncludedUntrackedPaths


class GeneratorIdentity(_IoModel):
    """Exact generator identity from the synthetic input tree."""

    path: Literal["scripts/capture_baseline.py"]
    version: Literal["3"]
    blob: GitObjectId
    sha256: HexDigest


class IndexTransitionIdentity(_IoModel):
    """Reviewed transition from the historical import to the live candidate."""

    transition_id: Literal["phase-1-reviewed-index-transition-v1"]
    imported_index_tree: GitObjectId
    imported_staged_entries_sha256: HexDigest
    candidate_index_tree: GitObjectId
    candidate_staged_entries_sha256: HexDigest


class CapturePolicy(_IoModel):
    """Exact identities admitted by the staged-recovery capture."""

    audit_commit: GitObjectId
    audit_tree: GitObjectId
    audit_src_tree: GitObjectId
    base_commit: GitObjectId
    base_tree: GitObjectId
    index_transition: IndexTransitionIdentity
    included_untracked_paths: IncludedUntrackedPaths


DEFAULT_CAPTURE_POLICY = CapturePolicy(
    audit_commit="2ba5dc18385747aa5d12a3b560eaab2ab97b7a40",
    audit_tree="b17c840ddd3c0dc0ec98fb150e18c22cf6c3b9e8",
    audit_src_tree="fcd9debdb533498486a2bbeaf909ea5bfb95b52c",
    base_commit="da5cc20e4f8bf3e1cacf74c49d5391487cb11cb0",
    base_tree="2464df5aa1880e99168ce07c23d891ab66ed3959",
    index_transition=IndexTransitionIdentity(
        transition_id="phase-1-reviewed-index-transition-v1",
        imported_index_tree="6cb461d986c21e4cb2852a07b06f75812ec27bbb",
        imported_staged_entries_sha256=(
            "fcfe06d851c83040d860f9f887efe18bde9dbe46c4eeb1aaa3f68b3af8f3ccaf"
        ),
        candidate_index_tree="55691718dade75b44a8ed025fcf48dabf87a7969",
        candidate_staged_entries_sha256=(
            "9426ba909728d29d2009607264a9ffb1c028c4c645bbacd72f98867132e24f68"
        ),
    ),
    included_untracked_paths=INCLUDED_UNTRACKED_PATHS,
)


@dataclass(frozen=True, slots=True)
class SyntheticInputSnapshot:
    """One materialized, provenance-bound capture input."""

    root: Path
    identity: CaptureInputIdentity
    generator: GeneratorIdentity


@dataclass(frozen=True, slots=True)
class CollectedBaseline:
    """In-memory fixtures bound to an unchanged synthetic input tree."""

    identity: CaptureInputIdentity
    generator: GeneratorIdentity
    fixtures: dict[BaselineFileName, dict[str, object]]


@dataclass(frozen=True, slots=True)
class _SyntheticWorkspace:
    root: Path
    repository: Path
    git_environment: dict[str, str]
    tree_before: str
    src_tree: str
    generator: GeneratorIdentity
    tree_inventory: tuple[_GitTreeEntry, ...]
    materialized_state: tuple[_MaterializedFileState, ...]


@dataclass(frozen=True, slots=True)
class _GitTreeEntry:
    relative_path: str
    mode: Literal["100644", "100755"]
    object_id: str
    size: int


@dataclass(frozen=True, slots=True)
class _MaterializedFileState:
    relative_path: str
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    object_id: str


type FixtureCollector = Callable[
    [Path],
    Mapping[BaselineFileName, Mapping[str, object]],
]
type ReplaceFunction = Callable[[Path, Path], None]
type StageFunction = Callable[[Path, bytes], None]
type DirectoryValidator = Callable[[Path], object]


@dataclass(frozen=True, slots=True)
class PublicationOperations:
    """Injectable filesystem operations for fail-closed baseline publication."""

    validator: DirectoryValidator
    replace: ReplaceFunction
    rollback: ReplaceFunction
    stage: StageFunction


@dataclass(frozen=True, slots=True)
class _DestinationState:
    existed: bool
    device: int | None
    inode: int | None
    mode: int | None
    raw: bytes | None


@dataclass(frozen=True, slots=True)
class ChildResult:
    """Bounded child-process result with exact byte streams."""

    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class ProcessLimits:
    """Deadline and byte ceilings for one bounded child process."""

    timeout_seconds: float
    stdout_bytes: int
    stderr_bytes: int

    def validate(self) -> None:
        """Reject non-positive deadlines and negative byte ceilings."""
        if self.timeout_seconds <= 0 or min(self.stdout_bytes, self.stderr_bytes) < 0:
            msg = "bounded child process limits are invalid"
            raise ValueError(msg)


@dataclass(slots=True)
class _PipeState:
    """One process-output descriptor and its bounded buffer."""

    descriptor: int
    name: Literal["stdout", "stderr"]
    limit: int
    buffer: bytearray


@dataclass(frozen=True, slots=True)
class _RegularFileSnapshot:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class _DirectorySnapshot:
    relative_path: str
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _ReviewedUntrackedInputSnapshot:
    relative_path: str
    directories: tuple[_DirectorySnapshot, ...]
    file: _RegularFileSnapshot


@dataclass(frozen=True, slots=True)
class _RealGitMetadata:
    worktree_git_directory: Path
    common_git_directory: Path
    index_path: Path
    object_directory: Path
    index_snapshot: _RegularFileSnapshot


@dataclass(frozen=True, slots=True)
class ObjectDatabaseEntry:
    """One immutable object-database inventory entry."""

    relative_path: str
    kind: Literal["directory", "file"]
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str | None


type StatIdentity = tuple[int, int, int, int, int, int, int]
type _SelectFunction = Callable[
    [list[int], list[int], list[int], float],
    tuple[list[int], list[int], list[int]],
]

_SELECT: Final[_SelectFunction] = select.select


def _stat_identity(value: os.stat_result) -> StatIdentity:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def canonical_json_bytes(value: object) -> bytes:
    """Encode a closed JSON value with sorted keys, UTF-8, and one final LF."""
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            msg = f"duplicate JSON object key: {key}"
            raise BaselineCaptureError(msg)
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> object:
    msg = f"non-finite JSON number is forbidden: {value}"
    raise BaselineCaptureError(msg)


def _reject_float(value: str) -> object:
    msg = f"floating-point JSON number is forbidden: {value}"
    raise BaselineCaptureError(msg)


def _bounded_integer(value: str) -> int:
    parsed = int(value, 10)
    if not MIN_CANONICAL_JSON_INTEGER <= parsed <= MAX_CANONICAL_JSON_INTEGER:
        msg = f"JSON integer is outside the signed 64-bit range: {value}"
        raise BaselineCaptureError(msg)
    return parsed


def validate_json_depth(value: object, *, depth: int = 0) -> None:
    """Reject JSON values nested beyond the closed canonical depth bound."""
    if depth > MAX_CANONICAL_JSON_DEPTH:
        msg = f"JSON nesting exceeds {MAX_CANONICAL_JSON_DEPTH} levels"
        raise BaselineCaptureError(msg)
    if type(value) is dict:
        for item in cast("dict[str, object]", value).values():
            validate_json_depth(item, depth=depth + 1)
    elif type(value) is list:
        for item in cast("list[object]", value):
            validate_json_depth(item, depth=depth + 1)


def load_canonical_json(
    path: Path,
    *,
    max_bytes: int = MAX_CANONICAL_JSON_BYTES,
) -> object:
    """Load one bounded regular file and require exact canonical JSON bytes."""
    if max_bytes < 1:
        msg = "max_bytes must be positive"
        raise ValueError(msg)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        msg = f"canonical JSON input must be a regular file: {path}"
        raise BaselineCaptureError(msg)
    if before.st_size > max_bytes:
        msg = f"canonical JSON input exceeds {max_bytes} bytes: {path}"
        raise BaselineCaptureError(msg)
    flags = os.O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            msg = f"canonical JSON input changed during open: {path}"
            raise BaselineCaptureError(msg)
        raw = os.read(descriptor, max_bytes + 1)
        if len(raw) > max_bytes or os.read(descriptor, 1):
            msg = f"canonical JSON input exceeds {max_bytes} bytes: {path}"
            raise BaselineCaptureError(msg)
    finally:
        os.close(descriptor)
    if raw.startswith(b"\xef\xbb\xbf"):
        msg = f"UTF-8 BOM is forbidden in canonical JSON: {path}"
        raise BaselineCaptureError(msg)
    try:
        text = raw.decode("utf-8", errors="strict")
        parsed = cast(
            "object",
            json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
                parse_float=_reject_float,
                parse_int=_bounded_integer,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = f"invalid canonical JSON: {path}"
        raise BaselineCaptureError(msg) from exc
    validate_json_depth(parsed)
    if canonical_json_bytes(parsed) != raw:
        msg = f"JSON is not canonical: {path}"
        raise BaselineCaptureError(msg)
    return parsed


def require_string_object(value: object, *, context: str) -> dict[str, object]:
    """Narrow one parsed JSON value to a string-keyed object."""
    if type(value) is not dict:
        msg = f"{context} must be a JSON object"
        raise BaselineCaptureError(msg)
    mapping = cast("dict[object, object]", value)
    if any(type(key) is not str for key in mapping):
        msg = f"{context} must have only string keys"
        raise BaselineCaptureError(msg)
    return cast("dict[str, object]", value)


def _snapshot_regular_file(
    path: Path,
    *,
    max_bytes: int,
    context: str,
) -> _RegularFileSnapshot:
    try:
        before = path.lstat()
    except OSError as exc:
        msg = f"{context} is unavailable"
        raise BaselineCaptureError(msg) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > max_bytes
    ):
        msg = f"{context} is not a bounded, singly linked regular file"
        raise BaselineCaptureError(msg)
    flags = os.O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            msg = f"{context} changed during open"
            raise BaselineCaptureError(msg)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after_read = os.fstat(descriptor)
        if len(raw) > max_bytes or _stat_identity(after_read) != _stat_identity(opened):
            msg = f"{context} changed or exceeded its bound during read"
            raise BaselineCaptureError(msg)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    if _stat_identity(after_path) != _stat_identity(before):
        msg = f"{context} changed during verification"
        raise BaselineCaptureError(msg)
    return _RegularFileSnapshot(
        device=before.st_dev,
        inode=before.st_ino,
        mode=before.st_mode,
        links=before.st_nlink,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        changed_ns=before.st_ctime_ns,
        sha256=hashlib.sha256(raw).hexdigest(),
        raw=raw,
    )


def _snapshot_reviewed_untracked_input(
    repository: Path,
    relative_path: str,
) -> _ReviewedUntrackedInputSnapshot:
    pure_path = PurePosixPath(relative_path)
    parts = pure_path.parts
    if (
        not repository.is_absolute()
        or not parts
        or pure_path.is_absolute()
        or pure_path.as_posix() != relative_path
        or any(part in {"", ".", ".."} for part in parts)
    ):
        msg = "reviewed untracked input path is not a closed relative path"
        raise BaselineCaptureError(msg)
    directory_snapshots: list[_DirectorySnapshot] = []
    current = repository
    try:
        for index, part in enumerate(parts[:-1], start=1):
            current /= part
            metadata = current.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                msg = "reviewed untracked input has a linked or non-directory ancestor"
                raise BaselineCaptureError(msg)
            directory_snapshots.append(
                _DirectorySnapshot(
                    relative_path=PurePosixPath(*parts[:index]).as_posix(),
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    mode=metadata.st_mode,
                    links=metadata.st_nlink,
                    size=metadata.st_size,
                    modified_ns=metadata.st_mtime_ns,
                    changed_ns=metadata.st_ctime_ns,
                ),
            )
        file_snapshot = _snapshot_regular_file(
            repository / relative_path,
            max_bytes=MAX_MATERIALIZED_FILE_BYTES,
            context=f"reviewed untracked input {relative_path}",
        )
    except OSError as exc:
        msg = f"reviewed untracked input is unavailable: {relative_path}"
        raise BaselineCaptureError(msg) from exc
    if stat.S_IMODE(file_snapshot.mode) != REGULAR_FILE_MODE:
        msg = f"reviewed untracked input must have mode 0644: {relative_path}"
        raise BaselineCaptureError(msg)
    return _ReviewedUntrackedInputSnapshot(
        relative_path=relative_path,
        directories=tuple(directory_snapshots),
        file=file_snapshot,
    )


def _snapshot_reviewed_untracked_inputs(
    repository: Path,
    paths: IncludedUntrackedPaths,
) -> tuple[_ReviewedUntrackedInputSnapshot, ...]:
    return tuple(_snapshot_reviewed_untracked_input(repository, path) for path in paths)


def _metadata_line(path: Path, *, context: str) -> str:
    raw = _snapshot_regular_file(
        path,
        max_bytes=MAX_GIT_METADATA_BYTES,
        context=context,
    ).raw
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\0" in raw:
        msg = f"{context} has an invalid record shape"
        raise BaselineCaptureError(msg)
    try:
        value = raw[:-1].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        msg = f"{context} is not valid UTF-8"
        raise BaselineCaptureError(msg) from exc
    if not value:
        msg = f"{context} is empty"
        raise BaselineCaptureError(msg)
    return value


def _require_git_directory(path: Path, *, context: str) -> Path:
    normalized = path.absolute()
    try:
        resolved = normalized.resolve(strict=True)
        path_stat = resolved.lstat()
    except OSError as exc:
        msg = f"{context} is unavailable"
        raise BaselineCaptureError(msg) from exc
    if (
        resolved != normalized
        or not stat.S_ISDIR(path_stat.st_mode)
        or path_stat.st_uid != os.geteuid()
    ):
        msg = f"{context} must be an owned, canonical directory"
        raise BaselineCaptureError(msg)
    return resolved


def _resolve_git_directory(base: Path, value: str, *, context: str) -> Path:
    if not value or "\0" in value or "\n" in value or "\r" in value:
        msg = f"{context} path is malformed"
        raise BaselineCaptureError(msg)
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = base / candidate
    return _require_git_directory(candidate, context=context)


def _is_sha1_object_id(value: str) -> bool:
    return len(value) == SHA1_HEX_LENGTH and all(
        character in "0123456789abcdef" for character in value
    )


def _head_reference_parts(head: str) -> tuple[str, tuple[str, ...]]:
    prefix = "ref: "
    if not head.startswith(prefix):
        msg = "Git HEAD is neither a SHA-1 object ID nor a symbolic ref"
        raise BaselineCaptureError(msg)
    reference = head.removeprefix(prefix)
    parts = PurePosixPath(reference).parts
    if (
        not reference.startswith("refs/")
        or not parts
        or "\\" in reference
        or any(part in {"", ".", ".."} for part in parts)
        or any(
            ord(character) < CONTROL_CHARACTER_BOUNDARY
            or ord(character) == DELETE_CHARACTER
            for character in reference
        )
    ):
        msg = "Git HEAD symbolic ref is unsafe"
        raise BaselineCaptureError(msg)
    return reference, parts


def _loose_reference_object_id(
    directories: tuple[Path, Path],
    parts: tuple[str, ...],
) -> str | None:
    for base in directories:
        candidate = base.joinpath(*parts)
        try:
            _ = candidate.lstat()
        except FileNotFoundError:
            continue
        value = _metadata_line(candidate, context="Git HEAD target")
        if not _is_sha1_object_id(value):
            msg = "Git HEAD target is not a SHA-1 object ID"
            raise BaselineCaptureError(msg)
        return value
    return None


def _packed_reference_object_id(common_git_directory: Path, reference: str) -> str:
    packed_refs = common_git_directory / "packed-refs"
    try:
        packed = _snapshot_regular_file(
            packed_refs,
            max_bytes=MAX_GIT_METADATA_BYTES,
            context="Git packed refs",
        ).raw.decode("ascii", errors="strict")
    except (BaselineCaptureError, UnicodeDecodeError) as exc:
        msg = "Git HEAD target cannot be resolved"
        raise BaselineCaptureError(msg) from exc
    matches: list[str] = []
    for line in packed.splitlines():
        if not line or line.startswith(("#", "^")):
            continue
        fields = line.split(" ")
        if len(fields) != PACKED_REFERENCE_FIELDS:
            msg = "Git packed refs contain malformed data"
            raise BaselineCaptureError(msg)
        object_id, packed_reference = fields
        if packed_reference == reference:
            matches.append(object_id)
    if len(matches) != 1 or not _is_sha1_object_id(matches[0]):
        msg = "Git HEAD target cannot be resolved unambiguously"
        raise BaselineCaptureError(msg)
    return matches[0]


def _resolve_head_commit(
    worktree_git_directory: Path,
    common_git_directory: Path,
) -> str:
    head = _metadata_line(worktree_git_directory / "HEAD", context="Git HEAD")
    if _is_sha1_object_id(head):
        return head
    reference, parts = _head_reference_parts(head)
    loose = _loose_reference_object_id(
        (worktree_git_directory, common_git_directory),
        parts,
    )
    if loose is not None:
        return loose
    return _packed_reference_object_id(common_git_directory, reference)


def _discover_real_git_metadata(
    repository: Path,
    *,
    expected_head: str,
) -> _RealGitMetadata:
    dot_git = repository / ".git"
    try:
        dot_git_stat = dot_git.lstat()
    except OSError as exc:
        msg = "capture repository Git metadata is unavailable"
        raise BaselineCaptureError(msg) from exc
    if stat.S_ISDIR(dot_git_stat.st_mode):
        worktree_git_directory = _require_git_directory(
            dot_git,
            context="worktree Git directory",
        )
    elif stat.S_ISREG(dot_git_stat.st_mode) and dot_git_stat.st_nlink == 1:
        line = _metadata_line(dot_git, context="worktree Git pointer")
        prefix = "gitdir: "
        if not line.startswith(prefix):
            msg = "worktree Git pointer is malformed"
            raise BaselineCaptureError(msg)
        worktree_git_directory = _resolve_git_directory(
            repository,
            line.removeprefix(prefix),
            context="worktree Git directory",
        )
    else:
        msg = "capture repository .git entry is a link or special file"
        raise BaselineCaptureError(msg)
    commondir_path = worktree_git_directory / "commondir"
    try:
        _ = commondir_path.lstat()
    except FileNotFoundError:
        common_git_directory = worktree_git_directory
    else:
        common_git_directory = _resolve_git_directory(
            worktree_git_directory,
            _metadata_line(commondir_path, context="Git common-dir pointer"),
            context="common Git directory",
        )
    if (
        _resolve_head_commit(worktree_git_directory, common_git_directory)
        != expected_head
    ):
        msg = "capture Git HEAD does not match the fixed recovery base"
        raise BaselineCaptureError(msg)
    index_path = worktree_git_directory / "index"
    index_snapshot = _snapshot_regular_file(
        index_path,
        max_bytes=MAX_GIT_INDEX_BYTES,
        context="real Git index",
    )
    object_directory = _require_git_directory(
        common_git_directory / "objects",
        context="real Git object directory",
    )
    return _RealGitMetadata(
        worktree_git_directory=worktree_git_directory,
        common_git_directory=common_git_directory,
        index_path=index_path,
        object_directory=object_directory,
        index_snapshot=index_snapshot,
    )


def _same_object_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    return _stat_identity(left) == _stat_identity(right)


def _directory_entry_name(entry: os.DirEntry[str]) -> str:
    return entry.name


def _object_entry_sort_key(entry: ObjectDatabaseEntry) -> tuple[str, str]:
    return entry.relative_path, entry.kind


@dataclass(slots=True)
class _ObjectDatabaseScanner:
    copy_root: Path | None
    entries: list[ObjectDatabaseEntry] = field(
        default_factory=list[ObjectDatabaseEntry],
    )
    total_size: int = 0
    entry_count: int = 0
    directory_flags: int = field(
        init=False,
        default=os.O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW,
    )
    file_flags: int = field(
        init=False,
        default=os.O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
    )

    def _children(self, directory_descriptor: int) -> list[os.DirEntry[str]]:
        with os.scandir(directory_descriptor) as untyped_iterator:
            iterator = cast("Iterator[os.DirEntry[str]]", untyped_iterator)
            return sorted(iterator, key=_directory_entry_name)

    @staticmethod
    def _validate_name(name: str) -> None:
        try:
            _ = name.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            msg = "real Git object database contains a non-UTF-8 path"
            raise BaselineCaptureError(msg) from exc
        if (
            not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or any(
                ord(character) < CONTROL_CHARACTER_BOUNDARY
                or ord(character) == DELETE_CHARACTER
                for character in name
            )
        ):
            msg = "real Git object database contains an unsafe path"
            raise BaselineCaptureError(msg)

    @staticmethod
    def _entry(
        relative_path: str,
        kind: Literal["directory", "file"],
        metadata: os.stat_result,
        digest: str | None,
    ) -> ObjectDatabaseEntry:
        return ObjectDatabaseEntry(
            relative_path=relative_path,
            kind=kind,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            links=metadata.st_nlink,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
            sha256=digest,
        )

    def _copied_directory(self, relative_path: str) -> Path | None:
        if self.copy_root is None:
            return None
        copied = self.copy_root.joinpath(*PurePosixPath(relative_path).parts)
        copied.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        copied.chmod(PRIVATE_DIRECTORY_MODE)
        return copied

    @staticmethod
    def _require_unchanged(
        before: os.stat_result,
        after_open: os.stat_result,
        after_path: os.stat_result,
        *,
        context: str,
    ) -> None:
        if not _same_object_metadata(before, after_open) or not (
            _same_object_metadata(before, after_path)
        ):
            raise BaselineCaptureError(context)

    def _scan_child_directory(
        self,
        directory_descriptor: int,
        child: os.DirEntry[str],
        child_stat: os.stat_result,
        relative_path: str,
        depth: int,
    ) -> None:
        try:
            descriptor = os.open(
                child.name,
                self.directory_flags,
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            msg = "real Git object database directory changed during open"
            raise BaselineCaptureError(msg) from exc
        try:
            opened = os.fstat(descriptor)
            if not _same_object_metadata(child_stat, opened):
                msg = "real Git object database directory changed during open"
                raise BaselineCaptureError(msg)
            self.entries.append(self._entry(relative_path, "directory", opened, None))
            copied = self._copied_directory(relative_path)
            self.scan(descriptor, relative_path, depth + 1)
            self._require_unchanged(
                opened,
                os.fstat(descriptor),
                os.stat(
                    child.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                ),
                context="real Git object database directory changed during scan",
            )
            if copied is not None:
                os.utime(
                    copied,
                    ns=(opened.st_mtime_ns, opened.st_mtime_ns),
                    follow_symlinks=False,
                )
        finally:
            os.close(descriptor)

    def _read_child_file(
        self,
        directory_descriptor: int,
        child: os.DirEntry[str],
        child_stat: os.stat_result,
    ) -> bytes:
        try:
            descriptor = os.open(
                child.name,
                self.file_flags,
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            msg = "real Git object file changed during open"
            raise BaselineCaptureError(msg) from exc
        try:
            opened = os.fstat(descriptor)
            if not _same_object_metadata(child_stat, opened):
                msg = "real Git object file changed during open"
                raise BaselineCaptureError(msg)
            chunks: list[bytes] = []
            remaining = MAX_REAL_OBJECT_DATABASE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            self._require_unchanged(
                opened,
                os.fstat(descriptor),
                os.stat(
                    child.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                ),
                context=(
                    "real Git object file changed or exceeded its bound during read"
                ),
            )
            if len(raw) != opened.st_size:
                msg = "real Git object file changed or exceeded its bound during read"
                raise BaselineCaptureError(msg)
            return raw
        finally:
            os.close(descriptor)

    def _scan_child_file(
        self,
        directory_descriptor: int,
        child: os.DirEntry[str],
        child_stat: os.stat_result,
        relative_path: str,
    ) -> None:
        if not stat.S_ISREG(child_stat.st_mode) or child_stat.st_nlink != 1:
            msg = "real Git object database contains a link or special file"
            raise BaselineCaptureError(msg)
        if child_stat.st_size > MAX_REAL_OBJECT_DATABASE_BYTES:
            msg = "real Git object database exceeds the verification bound"
            raise BaselineCaptureError(msg)
        raw = self._read_child_file(directory_descriptor, child, child_stat)
        self.total_size += len(raw)
        if self.total_size > MAX_REAL_OBJECT_DATABASE_BYTES:
            msg = "real Git object database exceeds the verification bound"
            raise BaselineCaptureError(msg)
        digest = hashlib.sha256(raw).hexdigest()
        self.entries.append(self._entry(relative_path, "file", child_stat, digest))
        if self.copy_root is not None:
            copied = self.copy_root.joinpath(*PurePosixPath(relative_path).parts)
            write_private_file(copied, raw, mode=PRIVATE_FILE_MODE)
            os.utime(
                copied,
                ns=(child_stat.st_mtime_ns, child_stat.st_mtime_ns),
                follow_symlinks=False,
            )

    def _scan_child(
        self,
        directory_descriptor: int,
        prefix: str,
        child: os.DirEntry[str],
        depth: int,
    ) -> None:
        self.entry_count += 1
        if self.entry_count > MAX_REAL_OBJECT_DATABASE_ENTRIES:
            msg = "real Git object database has too many entries"
            raise BaselineCaptureError(msg)
        self._validate_name(child.name)
        relative_path = child.name if not prefix else f"{prefix}/{child.name}"
        if relative_path in {"info/alternates", "info/http-alternates"}:
            msg = "real Git object database uses an alternate object store"
            raise BaselineCaptureError(msg)
        try:
            child_stat = child.stat(follow_symlinks=False)
        except OSError as exc:
            msg = "real Git object database changed during inventory"
            raise BaselineCaptureError(msg) from exc
        if stat.S_ISDIR(child_stat.st_mode):
            self._scan_child_directory(
                directory_descriptor,
                child,
                child_stat,
                relative_path,
                depth,
            )
            return
        self._scan_child_file(
            directory_descriptor,
            child,
            child_stat,
            relative_path,
        )

    def scan(self, directory_descriptor: int, prefix: str, depth: int) -> None:
        if depth > MAX_CANONICAL_JSON_DEPTH:
            msg = "real Git object database nesting exceeds the depth bound"
            raise BaselineCaptureError(msg)
        for child in self._children(directory_descriptor):
            self._scan_child(directory_descriptor, prefix, child, depth)

    def scan_root(self, root: Path) -> tuple[ObjectDatabaseEntry, ...]:
        try:
            root_before = root.lstat()
            if not stat.S_ISDIR(root_before.st_mode):
                msg = "real Git object database root is a link or special file"
                raise BaselineCaptureError(msg)
            descriptor = os.open(root, self.directory_flags)
        except OSError as exc:
            msg = "real Git object database is unavailable"
            raise BaselineCaptureError(msg) from exc
        try:
            opened = os.fstat(descriptor)
            if not _same_object_metadata(root_before, opened):
                msg = "real Git object database root changed during open"
                raise BaselineCaptureError(msg)
            self.scan(descriptor, "", 0)
            self._require_unchanged(
                opened,
                os.fstat(descriptor),
                root.lstat(),
                context="real Git object database root changed during scan",
            )
        finally:
            os.close(descriptor)
        return tuple(sorted(self.entries, key=_object_entry_sort_key))


def _scan_object_database(
    root: Path,
    *,
    copy_root: Path | None = None,
) -> tuple[ObjectDatabaseEntry, ...]:
    return _ObjectDatabaseScanner(copy_root=copy_root).scan_root(root)


def object_database_inventory(root: Path) -> tuple[ObjectDatabaseEntry, ...]:
    """Return a closed, race-checked object-database inventory."""
    return _scan_object_database(root)


def _object_copy_identity(
    entry: ObjectDatabaseEntry,
) -> tuple[str, str, int, int, int, str | None]:
    return (
        entry.relative_path,
        entry.kind,
        stat.S_IMODE(entry.mode),
        entry.links if entry.kind == "file" else 0,
        entry.size if entry.kind == "file" else 0,
        entry.sha256,
    )


def _require_empty_snapshot_destination(destination: Path) -> None:
    metadata = destination.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or any(destination.iterdir()):
        msg = "private Git object snapshot destination is not an empty directory"
        raise BaselineCaptureError(msg)


def _require_object_inventory(
    actual: tuple[ObjectDatabaseEntry, ...],
    expected: tuple[ObjectDatabaseEntry, ...],
    *,
    message: str,
) -> None:
    if actual != expected:
        raise BaselineCaptureError(message)


def copy_object_database_snapshot(
    source: Path,
    destination: Path,
    expected: tuple[ObjectDatabaseEntry, ...],
) -> tuple[ObjectDatabaseEntry, ...]:
    """Copy an exact object store into private files without shared links."""
    try:
        _require_empty_snapshot_destination(destination)
        destination.chmod(PRIVATE_DIRECTORY_MODE)
        during_copy = _scan_object_database(source, copy_root=destination)
        _require_object_inventory(
            during_copy,
            expected,
            message=("real Git object database changed before or during snapshot copy"),
        )
        source_after = object_database_inventory(source)
        _require_object_inventory(
            source_after,
            expected,
            message="real Git object database changed during snapshot copy",
        )
        copied = object_database_inventory(destination)
    except OSError as exc:
        msg = "private Git object snapshot copy failed"
        raise BaselineCaptureError(msg) from exc
    expected_copy_identity = tuple(
        (
            entry.relative_path,
            entry.kind,
            PRIVATE_DIRECTORY_MODE if entry.kind == "directory" else PRIVATE_FILE_MODE,
            1 if entry.kind == "file" else 0,
            entry.size if entry.kind == "file" else 0,
            entry.sha256,
        )
        for entry in expected
    )
    if tuple(map(_object_copy_identity, copied)) != expected_copy_identity:
        msg = "private Git object snapshot does not match the source inventory"
        raise BaselineCaptureError(msg)
    expected_files = {
        entry.relative_path: entry for entry in expected if entry.kind == "file"
    }
    for entry in copied:
        if entry.kind != "file":
            continue
        source_entry = expected_files[entry.relative_path]
        if (
            entry.links != 1
            or entry.modified_ns != source_entry.modified_ns
            or (entry.device, entry.inode) == (source_entry.device, source_entry.inode)
        ):
            msg = "private Git object snapshot file metadata is unsafe"
            raise BaselineCaptureError(msg)
    return copied


def _wait_for_process_group_exit(process_group: int, *, deadline: float) -> None:
    while True:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return
        if time.monotonic() >= deadline:
            msg = "bounded child process group did not terminate"
            raise BaselineCaptureError(msg)
        time.sleep(0.005)


def _kill_process_group(
    process: subprocess.Popen[bytes],
    *,
    deadline: float | None = None,
) -> None:
    cleanup_deadline = time.monotonic() + 1 if deadline is None else deadline
    if process.returncode is not None:
        msg = "bounded child leader was reaped before process-group cleanup"
        raise BaselineCaptureError(msg)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        _ = process.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        msg = "bounded child leader could not be reaped"
        raise BaselineCaptureError(msg) from exc
    _wait_for_process_group_exit(process.pid, deadline=cleanup_deadline)


def _wait_for_leader_exit_without_reaping(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> None:
    while True:
        status = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
        if status is not None:
            return
        if time.monotonic() >= deadline:
            msg = "bounded child process timed out"
            raise BaselineCaptureError(msg)
        time.sleep(0.005)


def _finish_process_group(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> int:
    _wait_for_leader_exit_without_reaping(process, deadline=deadline)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        msg = "bounded child leader could not be reaped"
        raise BaselineCaptureError(msg) from exc
    _wait_for_process_group_exit(process.pid, deadline=deadline)
    return returncode


def _remaining_process_time(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        msg = "bounded child process timed out"
        raise BaselineCaptureError(msg)
    return remaining


def _read_pipe_state(state: _PipeState) -> bool:
    chunk = os.read(
        state.descriptor,
        min(64 * 1024, state.limit - len(state.buffer) + 1),
    )
    if not chunk:
        return False
    state.buffer.extend(chunk)
    if len(state.buffer) > state.limit:
        msg = f"bounded child {state.name} output limit exceeded"
        raise BaselineCaptureError(msg)
    return True


def _drain_process_pipes(
    states: dict[int, _PipeState],
    *,
    deadline: float,
) -> None:
    while states:
        descriptors: list[int] = list(states)
        readable, _, _ = _SELECT(
            descriptors,
            descriptors[:0],
            descriptors[:0],
            _remaining_process_time(deadline),
        )
        if not readable:
            msg = "bounded child process timed out"
            raise BaselineCaptureError(msg)
        for descriptor in readable:
            state = states[descriptor]
            if not _read_pipe_state(state):
                os.close(descriptor)
                del states[descriptor]


def _close_descriptors(descriptors: tuple[int, ...]) -> None:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            continue


def run_bounded_process(
    command: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    limits: ProcessLimits,
) -> ChildResult:
    """Run one child with a closed environment and bounded pipe consumption."""
    limits.validate()
    if not command or not Path(command[0]).is_absolute():
        msg = "bounded child process configuration is invalid"
        raise ValueError(msg)
    stdout_read, stdout_write = os.pipe2(O_CLOEXEC)
    stderr_read, stderr_write = os.pipe2(O_CLOEXEC)
    try:
        # Security rationale: command[0] is an absolute reviewed executable.
        # Callers pass tuple argv and a closed environment; output/time are bounded.
        # shell=False/new session are enforced; see https://github.com/astral-sh/ruff/issues/4045.
        process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603
            command,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=stdout_write,
            stderr=stderr_write,
            close_fds=True,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        _close_descriptors((stdout_read, stdout_write, stderr_read, stderr_write))
        msg = "bounded child process could not be started"
        raise BaselineCaptureError(msg) from exc
    _close_descriptors((stdout_write, stderr_write))
    stdout_state = _PipeState(stdout_read, "stdout", limits.stdout_bytes, bytearray())
    stderr_state = _PipeState(stderr_read, "stderr", limits.stderr_bytes, bytearray())
    states = {
        stdout_read: stdout_state,
        stderr_read: stderr_state,
    }
    deadline = time.monotonic() + limits.timeout_seconds
    try:
        _drain_process_pipes(states, deadline=deadline)
        returncode = _finish_process_group(process, deadline=deadline)
    finally:
        if process.returncode is None:
            _kill_process_group(process)
        _close_descriptors(tuple(states))
    return ChildResult(
        returncode=returncode,
        stdout=bytes(stdout_state.buffer),
        stderr=bytes(stderr_state.buffer),
    )


def write_private_file(
    path: Path, raw: bytes, *, mode: int = PRIVATE_FILE_MODE
) -> None:
    """Exclusively write and fsync a bounded private regular file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_CLOEXEC | O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        _write_all(
            descriptor,
            raw,
            error_message="short write while constructing the private Git boundary",
        )
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    os.close(descriptor)


def _write_all(descriptor: int, raw: bytes, *, error_message: str) -> None:
    view = memoryview(raw)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise BaselineCaptureError(error_message)
        written += count


def _git_config_path_value(path: Path) -> str:
    value = str(path)
    if any(character in value for character in ("\0", "\n", "\r")):
        msg = "private Git configuration path contains a control character"
        raise BaselineCaptureError(msg)
    return value.replace("\\", "\\\\").replace('"', '\\"')


@dataclass(frozen=True, slots=True)
class _PrivateGitEnvironmentRequest:
    temporary_root: Path
    repository: Path
    metadata: _RealGitMetadata
    expected_head: str
    persist_objects: bool
    object_inventory: tuple[ObjectDatabaseEntry, ...] | None


def _create_private_git_environment(
    request: _PrivateGitEnvironmentRequest,
) -> dict[str, str]:
    private_git = request.temporary_root / "git"
    private_git.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    hooks = private_git / "hooks"
    hooks.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    info = private_git / "info"
    info.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    refs = private_git / "refs"
    refs.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    (refs / "heads").mkdir(mode=PRIVATE_DIRECTORY_MODE)
    (refs / "tags").mkdir(mode=PRIVATE_DIRECTORY_MODE)
    private_objects = private_git / "objects"
    private_objects.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    home = request.temporary_root / "home"
    home.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    xdg = request.temporary_root / "xdg"
    xdg.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    private_index = request.temporary_root / "capture.index"
    write_private_file(private_index, request.metadata.index_snapshot.raw)
    write_private_file(
        private_git / "HEAD",
        f"{request.expected_head}\n".encode("ascii"),
    )
    hooks_value = _git_config_path_value(hooks)
    config = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tbare = false\n"
        "\tautocrlf = false\n"
        "\tsafecrlf = true\n"
        "\tfsmonitor = false\n"
        f'\thooksPath = "{hooks_value}"\n'
        "[gc]\n"
        "\tauto = 0\n"
    ).encode()
    write_private_file(private_git / "config", config)
    if not request.persist_objects:
        if request.object_inventory is None:
            msg = "check capture requires a fixed real-object inventory"
            raise BaselineCaptureError(msg)
        _ = copy_object_database_snapshot(
            request.metadata.object_directory,
            private_objects,
            request.object_inventory,
        )
    overrides = {
        "GIT_CEILING_DIRECTORIES": str(request.repository.parent),
        "GIT_DIR": str(private_git),
        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
        "GIT_INDEX_FILE": str(private_index),
        "GIT_OBJECT_DIRECTORY": str(
            request.metadata.object_directory
            if request.persist_objects
            else private_objects
        ),
        "GIT_WORK_TREE": str(request.repository),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(xdg),
    }
    return _git_environment(overrides)


def _git_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        "GIT_ASKPASS": "/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "SSH_ASKPASS": "/bin/false",
    }
    if overrides is not None:
        environment.update(overrides)
    return environment


def git_bytes(
    repository: Path,
    arguments: tuple[str, ...],
    *,
    environment: Mapping[str, str] | None = None,
) -> bytes:
    """Run one exact Git command and return bounded stdout bytes."""
    git = shutil.which("git", path=os.defpath)
    if git is None or not Path(git).is_absolute():
        msg = "an absolute system Git executable is required"
        raise BaselineCaptureError(msg)
    command = (
        git,
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.safecrlf=true",
        "-C",
        str(repository),
        *arguments,
    )
    completed = run_bounded_process(
        command,
        cwd=repository,
        environment=_git_environment(environment),
        limits=ProcessLimits(
            timeout_seconds=GIT_TIMEOUT_SECONDS,
            stdout_bytes=MAX_GIT_STDOUT_BYTES,
            stderr_bytes=MAX_GIT_STDERR_BYTES,
        ),
    )
    if completed.returncode != 0 or completed.stderr:
        operation = arguments[0] if arguments else "unknown"
        msg = f"Git capture operation failed: {operation}"
        raise BaselineCaptureError(msg)
    return completed.stdout


def git_text(
    repository: Path,
    *arguments: str,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Return one exact, newline-terminated ASCII Git record."""
    raw = git_bytes(
        repository,
        tuple(arguments),
        environment=environment,
    )
    operation = arguments[0] if arguments else "unknown"
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or not raw[:-1]:
        msg = f"Git returned malformed identity data: {operation}"
        raise BaselineCaptureError(msg)
    try:
        return raw[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        msg = f"Git returned non-ASCII identity data: {operation}"
        raise BaselineCaptureError(msg) from exc


def git_no_output(
    repository: Path,
    *arguments: str,
    environment: Mapping[str, str] | None = None,
) -> None:
    """Require an exact Git operation to produce no stdout bytes."""
    if git_bytes(
        repository,
        tuple(arguments),
        environment=environment,
    ):
        operation = arguments[0] if arguments else "unknown"
        msg = f"Git returned unexpected output: {operation}"
        raise BaselineCaptureError(msg)


def git_object_id(
    repository: Path,
    *arguments: str,
    environment: Mapping[str, str],
) -> str:
    """Return and validate one SHA-1 Git object identifier."""
    value = git_text(
        repository,
        *arguments,
        environment=environment,
    )
    if not _is_sha1_object_id(value):
        operation = arguments[0] if arguments else "unknown"
        msg = f"Git returned a malformed SHA-1 object ID: {operation}"
        raise BaselineCaptureError(msg)
    return value


def _staged_entries_sha256(
    repository: Path,
    *,
    environment: Mapping[str, str],
) -> str:
    """Hash the canonical NUL-delimited stage-zero entry stream."""
    staged = git_bytes(
        repository,
        ("ls-files", "--stage", "-z"),
        environment=environment,
    )
    return hashlib.sha256(staged).hexdigest()


def _require_git_type(
    repository: Path,
    object_id: str,
    expected_type: Literal["commit", "tree", "blob"],
    *,
    environment: Mapping[str, str] | None = None,
) -> None:
    if (
        git_text(
            repository,
            "cat-file",
            "-t",
            object_id,
            environment=environment,
        )
        != expected_type
    ):
        msg = f"Git object type mismatch for required {expected_type}"
        raise BaselineCaptureError(msg)


def _validate_candidate_index(
    repository: Path,
    transition: IndexTransitionIdentity,
    *,
    environment: Mapping[str, str],
) -> None:
    try:
        _require_git_type(
            repository,
            transition.imported_index_tree,
            "tree",
            environment=environment,
        )
    except BaselineCaptureError as exc:
        msg = "capture imported index tree is unavailable"
        raise BaselineCaptureError(msg) from exc
    try:
        _require_git_type(
            repository,
            transition.candidate_index_tree,
            "tree",
            environment=environment,
        )
    except BaselineCaptureError as exc:
        msg = "capture candidate index tree is unavailable"
        raise BaselineCaptureError(msg) from exc
    if (
        git_object_id(repository, "write-tree", environment=environment)
        != transition.candidate_index_tree
    ):
        msg = "capture candidate index tree drifted"
        raise BaselineCaptureError(msg)
    if (
        _staged_entries_sha256(repository, environment=environment)
        != transition.candidate_staged_entries_sha256
    ):
        msg = "capture candidate staged-entry digest drifted"
        raise BaselineCaptureError(msg)


def _validate_capture_policy(
    repository: Path,
    policy: CapturePolicy,
    *,
    environment: Mapping[str, str],
) -> None:
    root_stat = repository.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or repository.resolve() != repository:
        msg = "capture repository must be an absolute, non-symlink directory"
        raise BaselineCaptureError(msg)
    if (
        Path(
            git_text(
                repository,
                "rev-parse",
                "--show-toplevel",
                environment=environment,
            ),
        )
        != repository
    ):
        msg = "capture repository is not the exact Git worktree root"
        raise BaselineCaptureError(msg)
    if (
        git_text(
            repository,
            "rev-parse",
            "--show-object-format",
            environment=environment,
        )
        != "sha1"
    ):
        msg = "capture repository does not use the manifest-bound SHA-1 format"
        raise BaselineCaptureError(msg)
    _require_git_type(
        repository, policy.audit_commit, "commit", environment=environment
    )
    _require_git_type(repository, policy.audit_tree, "tree", environment=environment)
    _require_git_type(
        repository, policy.audit_src_tree, "tree", environment=environment
    )
    _require_git_type(repository, policy.base_commit, "commit", environment=environment)
    _require_git_type(repository, policy.base_tree, "tree", environment=environment)
    _validate_candidate_index(
        repository,
        policy.index_transition,
        environment=environment,
    )
    required_pairs = (
        (
            git_object_id(
                repository,
                "rev-parse",
                f"{policy.audit_commit}^{{tree}}",
                environment=environment,
            ),
            policy.audit_tree,
        ),
        (
            git_object_id(
                repository,
                "rev-parse",
                f"{policy.audit_commit}:src",
                environment=environment,
            ),
            policy.audit_src_tree,
        ),
        (
            git_object_id(
                repository,
                "rev-parse",
                f"{policy.base_commit}^{{tree}}",
                environment=environment,
            ),
            policy.base_tree,
        ),
        (
            git_object_id(
                repository,
                "rev-parse",
                "HEAD",
                environment=environment,
            ),
            policy.base_commit,
        ),
        (
            git_object_id(
                repository,
                "rev-parse",
                "HEAD^{tree}",
                environment=environment,
            ),
            policy.base_tree,
        ),
    )
    if any(actual != expected for actual, expected in required_pairs):
        msg = "capture base or audit identity drifted"
        raise BaselineCaptureError(msg)
    try:
        ancestry_output = git_bytes(
            repository,
            ("merge-base", "--is-ancestor", policy.audit_commit, policy.base_commit),
            environment=environment,
        )
    except BaselineCaptureError as exc:
        msg = "capture audit commit is not an ancestor of the recovery base"
        raise BaselineCaptureError(msg) from exc
    if ancestry_output:
        msg = "Git returned unexpected merge-base output"
        raise BaselineCaptureError(msg)


def _decode_tree_record(
    raw_record: bytes,
) -> tuple[bytes, str, str, str, str, str, int]:
    try:
        metadata, raw_path = raw_record.split(b"\t", maxsplit=1)
    except ValueError as exc:
        msg = "synthetic input tree contains malformed Git metadata"
        raise BaselineCaptureError(msg) from exc
    try:
        metadata_fields = metadata.decode("ascii", errors="strict").split()
        path = raw_path.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        msg = "synthetic input tree contains malformed Git metadata"
        raise BaselineCaptureError(msg) from exc
    if len(metadata_fields) != TREE_RECORD_FIELDS:
        msg = "synthetic input tree contains malformed Git metadata"
        raise BaselineCaptureError(msg)
    mode, object_type, object_id, raw_size = metadata_fields
    if not raw_size.isascii() or not raw_size.isdecimal():
        msg = "synthetic input tree contains malformed Git metadata"
        raise BaselineCaptureError(msg)
    return raw_path, mode, object_type, object_id, raw_size, path, int(raw_size, 10)


def validate_tree_modes(
    repository: Path,
    tree: str,
    *,
    environment: Mapping[str, str],
) -> tuple[_GitTreeEntry, ...]:
    """Parse and validate the exact flat blob inventory for a Git tree."""
    records = git_bytes(
        repository,
        ("ls-tree", "-r", "-z", "--long", tree),
        environment=environment,
    )
    if not records.endswith(b"\0"):
        msg = "synthetic input tree contains malformed Git metadata"
        raise BaselineCaptureError(msg)
    parsed: list[_GitTreeEntry] = []
    seen_paths: set[str] = set()
    total_size = 0
    previous_raw_path: bytes | None = None
    for raw_record in records[:-1].split(b"\0"):
        if not raw_record or len(parsed) >= MAX_MATERIALIZED_TREE_ENTRIES:
            msg = "synthetic input tree contains malformed Git metadata"
            raise BaselineCaptureError(msg)
        raw_path, mode, object_type, object_id, raw_size, path, size = (
            _decode_tree_record(raw_record)
        )
        parts = PurePosixPath(path).parts
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or len(object_id) != SHA1_HEX_LENGTH
            or any(character not in "0123456789abcdef" for character in object_id)
            or (len(raw_size) > 1 and raw_size.startswith("0"))
            or size > MAX_MATERIALIZED_FILE_BYTES
            or not parts
            or path.startswith("/")
            or "\\" in path
            or any(
                ord(character) < CONTROL_CHARACTER_BOUNDARY
                or ord(character) == DELETE_CHARACTER
                for character in path
            )
            or any(part in {"", ".", ".."} for part in parts)
            or PurePosixPath(path).as_posix() != path
            or path in seen_paths
            or (previous_raw_path is not None and raw_path <= previous_raw_path)
        ):
            msg = "synthetic input tree contains malformed or unsafe Git metadata"
            raise BaselineCaptureError(msg)
        seen_paths.add(path)
        previous_raw_path = raw_path
        total_size += size
        if total_size > MAX_MATERIALIZED_TREE_BYTES:
            msg = "synthetic input tree exceeds the materialization size limit"
            raise BaselineCaptureError(msg)
        parsed.append(
            _GitTreeEntry(
                relative_path=path,
                mode=cast("Literal['100644', '100755']", mode),
                object_id=object_id,
                size=size,
            ),
        )
    return tuple(parsed)


def _derive_input_tree(
    repository: Path,
    policy: CapturePolicy,
    *,
    environment: Mapping[str, str],
) -> tuple[str, str, GeneratorIdentity, tuple[_GitTreeEntry, ...]]:
    transition = policy.index_transition
    git_no_output(
        repository,
        "read-tree",
        transition.imported_index_tree,
        environment=environment,
    )
    if (
        git_object_id(repository, "write-tree", environment=environment)
        != transition.imported_index_tree
    ):
        msg = "capture imported index tree materialization drifted"
        raise BaselineCaptureError(msg)
    if (
        _staged_entries_sha256(repository, environment=environment)
        != transition.imported_staged_entries_sha256
    ):
        msg = "capture imported staged-entry digest drifted"
        raise BaselineCaptureError(msg)
    git_no_output(repository, "add", "-u", "--", ".", environment=environment)
    git_no_output(
        repository,
        "update-index",
        "--force-remove",
        "--",
        *(f"contracts/baseline/{name}" for name in BASELINE_DIRECTORY_FILES),
        environment=environment,
    )
    if git_bytes(
        repository,
        ("ls-files", "--stage", "--", *policy.included_untracked_paths),
        environment=environment,
    ):
        msg = "reviewed untracked inputs unexpectedly exist in the imported index"
        raise BaselineCaptureError(msg)
    reviewed_before = _snapshot_reviewed_untracked_inputs(
        repository,
        policy.included_untracked_paths,
    )
    git_no_output(
        repository,
        "add",
        "--",
        *policy.included_untracked_paths,
        environment=environment,
    )
    reviewed_after_add = _snapshot_reviewed_untracked_inputs(
        repository,
        policy.included_untracked_paths,
    )
    if reviewed_after_add != reviewed_before:
        msg = "reviewed untracked input changed during exact private-index add"
        raise BaselineCaptureError(msg)
    tree = git_object_id(repository, "write-tree", environment=environment)
    _require_git_type(repository, tree, "tree", environment=environment)
    src_tree = git_object_id(
        repository,
        "rev-parse",
        f"{tree}:src",
        environment=environment,
    )
    generator_blob = git_object_id(
        repository,
        "rev-parse",
        f"{tree}:scripts/capture_baseline.py",
        environment=environment,
    )
    generator_bytes = git_bytes(
        repository,
        ("cat-file", "blob", generator_blob),
        environment=environment,
    )
    inventory = validate_tree_modes(repository, tree, environment=environment)
    reviewed_after_tree = _snapshot_reviewed_untracked_inputs(
        repository,
        policy.included_untracked_paths,
    )
    if reviewed_after_tree != reviewed_before:
        msg = "reviewed untracked input changed during synthetic-tree derivation"
        raise BaselineCaptureError(msg)
    inventory_by_path = {entry.relative_path: entry for entry in inventory}
    for reviewed in reviewed_before:
        entry = inventory_by_path.get(reviewed.relative_path)
        if (
            entry is None
            or entry.mode != "100644"
            or entry.size != reviewed.file.size
            or entry.object_id != _git_blob_object_id(reviewed.file.raw)
        ):
            msg = "reviewed untracked input is not exactly bound to the synthetic tree"
            raise BaselineCaptureError(msg)
    generator_entries = tuple(
        entry
        for entry in inventory
        if entry.relative_path == "scripts/capture_baseline.py"
    )
    if (
        len(generator_entries) != 1
        or generator_entries[0].object_id != generator_blob
        or generator_entries[0].size != len(generator_bytes)
        or _git_blob_object_id(generator_bytes) != generator_blob
    ):
        msg = "capture generator blob is not bound to the synthetic tree inventory"
        raise BaselineCaptureError(msg)
    return (
        tree,
        src_tree,
        GeneratorIdentity(
            path="scripts/capture_baseline.py",
            version="3",
            blob=generator_blob,
            sha256=hashlib.sha256(generator_bytes).hexdigest(),
        ),
        inventory,
    )


def _git_blob_object_id(raw: bytes) -> str:
    digest = hashlib.new("sha1", usedforsecurity=False)
    digest.update(f"blob {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _read_materialized_file(
    path: Path,
    expected: _GitTreeEntry,
) -> _MaterializedFileState:
    before = path.lstat()
    expected_mode = 0o755 if expected.mode == "100755" else REGULAR_FILE_MODE
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != expected_mode
        or before.st_nlink != 1
        or before.st_size != expected.size
    ):
        msg = f"materialized input file metadata drifted: {expected.relative_path}"
        raise BaselineCaptureError(msg)
    flags = os.O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            msg = f"materialized input changed during open: {expected.relative_path}"
            raise BaselineCaptureError(msg)
        chunks: list[bytes] = []
        remaining = expected.size + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after_read = os.fstat(descriptor)
        if _stat_identity(after_read) != _stat_identity(opened):
            msg = f"materialized input changed during read: {expected.relative_path}"
            raise BaselineCaptureError(msg)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    if len(raw) != expected.size or _stat_identity(after_path) != _stat_identity(
        before
    ):
        msg = (
            f"materialized input changed during verification: {expected.relative_path}"
        )
        raise BaselineCaptureError(msg)
    object_id = _git_blob_object_id(raw)
    if object_id != expected.object_id:
        msg = f"materialized input content drifted: {expected.relative_path}"
        raise BaselineCaptureError(msg)
    return _MaterializedFileState(
        relative_path=expected.relative_path,
        device=before.st_dev,
        inode=before.st_ino,
        mode=before.st_mode,
        links=before.st_nlink,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        changed_ns=before.st_ctime_ns,
        object_id=object_id,
    )


def _validate_materialized_tree(
    root: Path,
    inventory: tuple[_GitTreeEntry, ...],
    *,
    previous: tuple[_MaterializedFileState, ...] | None = None,
) -> tuple[_MaterializedFileState, ...]:
    expected = {entry.relative_path: entry for entry in inventory}
    expected_directories = {
        "/".join(PurePosixPath(relative_path).parts[:position])
        for relative_path in expected
        for position in range(1, len(PurePosixPath(relative_path).parts))
    }
    actual_files: set[str] = set()
    actual_directories: set[str] = set()

    def scan(directory: Path, prefix: str, depth: int) -> None:
        if depth > MAX_CANONICAL_JSON_DEPTH:
            msg = "materialized input directory nesting is excessive"
            raise BaselineCaptureError(msg)
        directory_stat = directory.lstat()
        if not stat.S_ISDIR(directory_stat.st_mode):
            msg = f"materialized input contains a link or special directory: {prefix}"
            raise BaselineCaptureError(msg)
        with os.scandir(directory) as entries:
            for item in entries:
                relative_path = item.name if not prefix else f"{prefix}/{item.name}"
                try:
                    _ = relative_path.encode("utf-8", errors="strict")
                except UnicodeEncodeError as exc:
                    msg = "materialized input contains a non-UTF-8 path"
                    raise BaselineCaptureError(msg) from exc
                item_stat = item.stat(follow_symlinks=False)
                if stat.S_ISDIR(item_stat.st_mode):
                    actual_directories.add(relative_path)
                    scan(Path(item.path), relative_path, depth + 1)
                elif stat.S_ISREG(item_stat.st_mode):
                    actual_files.add(relative_path)
                else:
                    msg = (
                        "materialized input contains a link or special file: "
                        f"{relative_path}"
                    )
                    raise BaselineCaptureError(msg)

    scan(root, "", 0)
    if actual_files != set(expected) or actual_directories != expected_directories:
        msg = "materialized input inventory does not match the synthetic Git tree"
        raise BaselineCaptureError(msg)
    states = tuple(
        _read_materialized_file(root / entry.relative_path, entry)
        for entry in inventory
    )
    if previous is not None and states != previous:
        msg = "materialized input inode or content state changed during capture"
        raise BaselineCaptureError(msg)
    return states


@contextmanager
def synthetic_workspace(
    repository: Path,
    *,
    policy: CapturePolicy,
    persist_objects: bool,
) -> Generator[_SyntheticWorkspace]:
    """Yield an isolated synthetic-index workspace and verify cleanup invariants."""
    repository = repository.absolute()
    root_stat = repository.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or repository.resolve() != repository:
        msg = "capture repository must be an absolute, non-symlink directory"
        raise BaselineCaptureError(msg)
    metadata = _discover_real_git_metadata(
        repository,
        expected_head=policy.base_commit,
    )
    object_inventory_before = (
        None
        if persist_objects
        else object_database_inventory(metadata.object_directory)
    )
    with tempfile.TemporaryDirectory(prefix="nplg-baseline-input-") as temporary:
        temporary_root = Path(temporary).absolute()
        temporary_root.chmod(PRIVATE_DIRECTORY_MODE)
        environment = _create_private_git_environment(
            _PrivateGitEnvironmentRequest(
                temporary_root=temporary_root,
                repository=repository,
                metadata=metadata,
                expected_head=policy.base_commit,
                persist_objects=persist_objects,
                object_inventory=object_inventory_before,
            ),
        )
        try:
            _validate_capture_policy(repository, policy, environment=environment)
            tree, src_tree, generator, tree_inventory = _derive_input_tree(
                repository,
                policy,
                environment=environment,
            )
            materialized = (temporary_root / "root").absolute()
            materialized.mkdir(mode=PRIVATE_DIRECTORY_MODE)
            git_no_output(
                repository,
                "checkout-index",
                "--all",
                "--force",
                f"--prefix={materialized}{os.sep}",
                environment=environment,
            )
            materialized.chmod(PRIVATE_DIRECTORY_MODE)
            materialized_state = _validate_materialized_tree(
                materialized,
                tree_inventory,
            )
            yield _SyntheticWorkspace(
                root=materialized,
                repository=repository,
                git_environment=environment,
                tree_before=tree,
                src_tree=src_tree,
                generator=generator,
                tree_inventory=tree_inventory,
                materialized_state=materialized_state,
            )
        finally:
            index_after = _snapshot_regular_file(
                metadata.index_path,
                max_bytes=MAX_GIT_INDEX_BYTES,
                context="real Git index",
            )
            if index_after != metadata.index_snapshot:
                msg = "real Git index changed during baseline capture"
                raise BaselineCaptureError(msg)
            if (
                object_inventory_before is not None
                and object_database_inventory(metadata.object_directory)
                != object_inventory_before
            ):
                msg = "real Git object database changed during check capture"
                raise BaselineCaptureError(msg)


@contextmanager
def materialize_synthetic_input(
    repository: Path,
    *,
    policy: CapturePolicy,
    persist_objects: bool,
) -> Generator[SyntheticInputSnapshot]:
    """Materialize the exact output-excluded synthetic index for inspection."""
    with synthetic_workspace(
        repository,
        policy=policy,
        persist_objects=persist_objects,
    ) as workspace:
        before_capture = _validate_materialized_tree(
            workspace.root,
            workspace.tree_inventory,
            previous=workspace.materialized_state,
        )
        yield SyntheticInputSnapshot(
            root=workspace.root,
            identity=CaptureInputIdentity(
                tree_before=workspace.tree_before,
                tree_after=workspace.tree_before,
                src_tree=workspace.src_tree,
                git_object_format="sha1",
                excluded_output_paths=cast(
                    "tuple[BaselineOutputPath, ...]",
                    EXCLUDED_OUTPUT_PATHS,
                ),
                included_untracked_paths=INCLUDED_UNTRACKED_PATHS,
            ),
            generator=workspace.generator,
        )
        _ = _validate_materialized_tree(
            workspace.root,
            workspace.tree_inventory,
            previous=before_capture,
        )
        tree_after, src_after, generator_after, inventory_after = _derive_input_tree(
            workspace.repository,
            policy,
            environment=workspace.git_environment,
        )
        if (
            tree_after != workspace.tree_before
            or src_after != workspace.src_tree
            or generator_after != workspace.generator
            or inventory_after != workspace.tree_inventory
        ):
            msg = "capture input changed during materialization"
            raise BaselineCaptureError(msg)


def collect_from_synthetic_input(
    repository: Path,
    *,
    policy: CapturePolicy,
    persist_objects: bool,
    collector: FixtureCollector,
) -> CollectedBaseline:
    """Collect fixtures from an exact tree and reject concurrent input drift."""
    with synthetic_workspace(
        repository,
        policy=policy,
        persist_objects=persist_objects,
    ) as workspace:
        before_capture = _validate_materialized_tree(
            workspace.root,
            workspace.tree_inventory,
            previous=workspace.materialized_state,
        )
        values = collector(workspace.root)
        _ = _validate_materialized_tree(
            workspace.root,
            workspace.tree_inventory,
            previous=before_capture,
        )
        fixtures: dict[BaselineFileName, dict[str, object]] = {}
        if set(values) != set(BASELINE_FILES):
            msg = "fixture collector did not return the exact four baseline files"
            raise BaselineCaptureError(msg)
        for name in BASELINE_FILES:
            fixtures[name] = dict(values[name])
        tree_after, src_after, generator_after, inventory_after = _derive_input_tree(
            workspace.repository,
            policy,
            environment=workspace.git_environment,
        )
        if (
            tree_after != workspace.tree_before
            or src_after != workspace.src_tree
            or generator_after != workspace.generator
            or inventory_after != workspace.tree_inventory
        ):
            msg = "capture input changed before fixture collection completed"
            raise BaselineCaptureError(msg)
        return CollectedBaseline(
            identity=CaptureInputIdentity(
                tree_before=workspace.tree_before,
                tree_after=tree_after,
                src_tree=workspace.src_tree,
                git_object_format="sha1",
                excluded_output_paths=cast(
                    "tuple[BaselineOutputPath, ...]",
                    EXCLUDED_OUTPUT_PATHS,
                ),
                included_untracked_paths=INCLUDED_UNTRACKED_PATHS,
            ),
            generator=workspace.generator,
            fixtures=fixtures,
        )


def write_staged_file(path: Path, raw: bytes) -> None:
    """Exclusively write and fsync one regular staging file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_CLOEXEC | O_NOFOLLOW
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    try:
        _write_all(
            descriptor,
            raw,
            error_message=f"short write while staging baseline output: {path.name}",
        )
        os.fchmod(descriptor, REGULAR_FILE_MODE)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    os.close(descriptor)


def read_regular_bytes(path: Path) -> bytes:
    """Read one bounded no-follow baseline destination."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        msg = f"baseline destination must be a regular file: {path.name}"
        raise BaselineCaptureError(msg)
    if before.st_size > MAX_CANONICAL_JSON_BYTES:
        msg = f"baseline destination is oversized: {path.name}"
        raise BaselineCaptureError(msg)
    flags = os.O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            msg = f"baseline destination changed during read: {path.name}"
            raise BaselineCaptureError(msg)
        raw = os.read(descriptor, MAX_CANONICAL_JSON_BYTES + 1)
        if len(raw) > MAX_CANONICAL_JSON_BYTES or os.read(descriptor, 1):
            msg = f"baseline destination is oversized: {path.name}"
            raise BaselineCaptureError(msg)
        return raw
    finally:
        os.close(descriptor)


def _directory_fsync(path: Path) -> None:
    flags = os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _destination_state(path: Path) -> _DestinationState:
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        return _DestinationState(
            existed=False,
            device=None,
            inode=None,
            mode=None,
            raw=None,
        )
    if not stat.S_ISREG(path_stat.st_mode):
        msg = f"baseline destination must not be a link or special file: {path.name}"
        raise BaselineCaptureError(msg)
    return _DestinationState(
        existed=True,
        device=path_stat.st_dev,
        inode=path_stat.st_ino,
        mode=stat.S_IMODE(path_stat.st_mode),
        raw=read_regular_bytes(path),
    )


def _require_unchanged_destination(path: Path, state: _DestinationState) -> None:
    if not state.existed:
        if path.exists() or path.is_symlink():
            msg = f"baseline destination appeared during publication: {path.name}"
            raise BaselineCaptureError(msg)
        return
    current = path.lstat()
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != state.device
        or current.st_ino != state.inode
    ):
        msg = f"baseline destination changed during publication: {path.name}"
        raise BaselineCaptureError(msg)


def replace_path(source: Path, destination: Path) -> None:
    """Atomically replace one explicit destination path."""
    _ = source.replace(destination)


def _publication_states(
    root: Path,
    outputs: Mapping[str, bytes],
) -> dict[str, _DestinationState]:
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or root.resolve() != root:
        msg = "baseline output root must be an absolute non-symlink directory"
        raise BaselineCaptureError(msg)
    if set(outputs) != set(BASELINE_DIRECTORY_FILES):
        msg = "publication requires exactly four fixtures and one manifest"
        raise BaselineCaptureError(msg)
    unexpected = {path.name for path in root.iterdir()} - set(BASELINE_DIRECTORY_FILES)
    if unexpected:
        msg = "baseline output root contains unexpected files"
        raise BaselineCaptureError(msg)
    return {name: _destination_state(root / name) for name in BASELINE_DIRECTORY_FILES}


def _stage_publication(
    staged: Path,
    backups: Path,
    outputs: Mapping[str, bytes],
    states: Mapping[str, _DestinationState],
    operations: PublicationOperations,
) -> None:
    staged.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    backups.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    for name in BASELINE_DIRECTORY_FILES:
        raw = outputs[name]
        if len(raw) > MAX_CANONICAL_JSON_BYTES:
            msg = f"generated baseline output is oversized: {name}"
            raise BaselineCaptureError(msg)
        operations.stage(staged / name, raw)
        state = states[name]
        if state.raw is not None:
            write_staged_file(backups / name, state.raw)
            if state.mode is not None:
                (backups / name).chmod(state.mode)
    _ = operations.validator(staged)


def _publish_staged_files(
    root: Path,
    staged: Path,
    states: Mapping[str, _DestinationState],
    operations: PublicationOperations,
    published: list[str],
) -> None:
    for position, name in enumerate(BASELINE_DIRECTORY_FILES):
        destination = root / name
        _require_unchanged_destination(destination, states[name])
        operations.replace(staged / name, destination)
        published.append(name)
        if position == len(BASELINE_FILES) - 1:
            _directory_fsync(root)
    _directory_fsync(root)
    _ = operations.validator(root)


def _restore_destination(
    root: Path,
    backups: Path,
    name: str,
    state: _DestinationState,
    rollback: ReplaceFunction,
) -> None:
    destination = root / name
    if state.existed:
        rollback(backups / name, destination)
        return
    current = destination.lstat()
    if not stat.S_ISREG(current.st_mode):
        msg = f"unsafe rollback destination: {name}"
        raise BaselineCaptureError(msg)
    destination.unlink()


def _rollback_publication(
    root: Path,
    backups: Path,
    published: list[str],
    states: Mapping[str, _DestinationState],
    rollback: ReplaceFunction,
) -> Exception | None:
    rollback_error: Exception | None = None
    for name in reversed(published):
        try:
            _restore_destination(root, backups, name, states[name], rollback)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            rollback_error = exc
    try:
        _directory_fsync(root)
    except OSError as exc:
        rollback_error = exc
    return rollback_error


def publish_output_bytes(
    root: Path,
    outputs: Mapping[str, bytes],
    *,
    operations: PublicationOperations,
) -> None:
    """Publish four fixtures then the manifest, rolling back caught faults."""
    root = root.absolute()
    states = _publication_states(root, outputs)
    published: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix=".baseline-publish-",
        dir=root.parent,
    ) as temporary:
        transaction = Path(temporary)
        staged = transaction / "staged"
        backups = transaction / "backups"
        try:
            _stage_publication(staged, backups, outputs, states, operations)
            _publish_staged_files(
                root,
                staged,
                states,
                operations,
                published,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            rollback_error = _rollback_publication(
                root,
                backups,
                published,
                states,
                operations.rollback,
            )
            if rollback_error is not None:
                msg = "baseline publication failed and rollback could not be completed"
                raise BaselineCaptureError(msg) from rollback_error
            if isinstance(exc, BaselineCaptureError):
                raise
            msg = "baseline publication failed before the manifest was committed"
            raise BaselineCaptureError(msg) from exc
