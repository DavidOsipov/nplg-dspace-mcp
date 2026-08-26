# Copyright (c) 2026 David Osipov
"""Adversarial edge coverage for the closed baseline-capture I/O boundary."""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, cast

import pytest

from scripts import baseline_capture_io
from tests.contracts.test_frozen_baseline import make_capture_git_repository

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

type StatIdentity = tuple[int, int, int, int, int, int, int]
type OpenPath = str | bytes | os.PathLike[str] | os.PathLike[bytes]
_SECOND_CALL = 2


class _SnapshotRegularFile(Protocol):
    def __call__(
        self,
        path: Path,
        *,
        max_bytes: int,
        context: str,
    ) -> object: ...


class _ReviewedInput(Protocol):
    def __call__(self, repository: Path, relative_path: str) -> object: ...


class _MetadataLine(Protocol):
    def __call__(self, path: Path, *, context: str) -> str: ...


class _RequireGitDirectory(Protocol):
    def __call__(self, path: Path, *, context: str) -> Path: ...


class _ResolveGitDirectory(Protocol):
    def __call__(self, base: Path, value: str, *, context: str) -> Path: ...


class _LooseReference(Protocol):
    def __call__(
        self,
        directories: tuple[Path, Path],
        parts: tuple[str, ...],
    ) -> str | None: ...


class _PackedReference(Protocol):
    def __call__(self, common_git_directory: Path, reference: str) -> str: ...


class _DiscoverMetadata(Protocol):
    def __call__(self, repository: Path, *, expected_head: str) -> object: ...


class _WaitForProcessGroup(Protocol):
    def __call__(self, process_group: int, *, deadline: float) -> None: ...


class _KillProcessGroup(Protocol):
    def __call__(self, process: object, *, deadline: float | None = None) -> None: ...


class _WaitForLeader(Protocol):
    def __call__(self, process: object, *, deadline: float) -> None: ...


class _FinishProcessGroup(Protocol):
    def __call__(self, process: object, *, deadline: float) -> int: ...


class _RemainingTime(Protocol):
    def __call__(self, deadline: float) -> float: ...


class _CloseDescriptors(Protocol):
    def __call__(self, descriptors: tuple[int, ...]) -> None: ...


class _WriteAll(Protocol):
    def __call__(self, descriptor: int, raw: bytes, *, error_message: str) -> None: ...


class _GitConfigPath(Protocol):
    def __call__(self, path: Path) -> str: ...


class _KeywordFactory(Protocol):
    def __call__(self, **values: object) -> object: ...


class _CreatePrivateGitEnvironment(Protocol):
    def __call__(self, request: object) -> dict[str, str]: ...


class _ValidateCandidateIndex(Protocol):
    def __call__(
        self,
        repository: Path,
        transition: baseline_capture_io.IndexTransitionIdentity,
        *,
        environment: Mapping[str, str],
    ) -> None: ...


class _ValidateCapturePolicy(Protocol):
    def __call__(
        self,
        repository: Path,
        policy: baseline_capture_io.CapturePolicy,
        *,
        environment: Mapping[str, str],
    ) -> None: ...


class _DecodeTreeRecord(Protocol):
    def __call__(
        self,
        raw_record: bytes,
    ) -> tuple[bytes, str, str, str, str, str, int]: ...


class _DeriveInputTree(Protocol):
    def __call__(
        self,
        repository: Path,
        policy: baseline_capture_io.CapturePolicy,
        *,
        environment: Mapping[str, str],
    ) -> tuple[str, str, baseline_capture_io.GeneratorIdentity, tuple[object, ...]]: ...


class _ReadMaterializedFile(Protocol):
    def __call__(self, path: Path, expected: object) -> object: ...


class _ValidateMaterializedTree(Protocol):
    def __call__(
        self,
        root: Path,
        inventory: tuple[object, ...],
        *,
        previous: tuple[object, ...] | None = None,
    ) -> tuple[object, ...]: ...


class _StagePublication(Protocol):
    def __call__(
        self,
        staged: Path,
        backups: Path,
        outputs: Mapping[str, bytes],
        states: Mapping[str, object],
        operations: baseline_capture_io.PublicationOperations,
    ) -> None: ...


class _RestoreDestination(Protocol):
    def __call__(
        self,
        root: Path,
        backups: Path,
        name: str,
        state: object,
        rollback: baseline_capture_io.ReplaceFunction,
    ) -> None: ...


class _RollbackPublication(Protocol):
    def __call__(
        self,
        root: Path,
        backups: Path,
        published: list[str],
        states: Mapping[str, object],
        rollback: baseline_capture_io.ReplaceFunction,
    ) -> Exception | None: ...


@dataclass(frozen=True, slots=True)
class _FakeProcess:
    pid: int
    returncode: int | None
    wait_times_out: bool = False

    def wait(self, timeout: float | None = None) -> int:
        if self.wait_times_out:
            command = "controlled-child"
            raise subprocess.TimeoutExpired(
                command,
                0.0 if timeout is None else timeout,
            )
        return 0


@dataclass(frozen=True, slots=True)
class _FakeReviewedFile:
    size: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class _FakeReviewedInput:
    relative_path: str
    file: _FakeReviewedFile


@dataclass(frozen=True, slots=True)
class _FakeTreeEntry:
    relative_path: str
    mode: Literal["100644", "100755"]
    object_id: str
    size: int


def _private(name: str) -> object:
    """Resolve one deliberately exercised private boundary without static coupling."""
    return cast(
        "object",
        object.__getattribute__(baseline_capture_io, f"_{name}"),
    )


def _sha1_blob(raw: bytes) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _identity_sequence(
    mismatch_pair: int,
) -> tuple[Callable[[os.stat_result], StatIdentity], list[int]]:
    calls: list[int] = []

    def identity(_value: os.stat_result) -> StatIdentity:
        calls.append(len(calls) + 1)
        pair = (len(calls) + 1) // 2
        marker = 1 if pair == mismatch_pair and len(calls) % 2 == 1 else 0
        return (marker, 0, 0, 0, 0, 0, 0)

    return identity, calls


@pytest.mark.parametrize("mismatch_pair", [1, 2, 3])
def test_regular_snapshot_rejects_each_identity_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch_pair: int,
) -> None:
    path = tmp_path / "subject"
    _ = path.write_bytes(b"content")
    identity, calls = _identity_sequence(mismatch_pair)
    monkeypatch.setattr(baseline_capture_io, "_stat_identity", identity)
    snapshot = cast("_SnapshotRegularFile", _private("snapshot_regular_file"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="changed"):
        _ = snapshot(path, max_bytes=32, context="controlled snapshot")

    assert len(calls) == mismatch_pair * 2


def test_regular_snapshot_detects_growth_that_exhausts_the_read_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "subject"
    _ = path.write_bytes(b"")

    def growing_read(_descriptor: int, size: int) -> bytes:
        return b"x" * size

    monkeypatch.setattr(os, "read", growing_read)
    snapshot = cast("_SnapshotRegularFile", _private("snapshot_regular_file"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="exceeded"):
        _ = snapshot(path, max_bytes=1, context="controlled snapshot")


@pytest.mark.parametrize("relative_path", ["", "/absolute", "a/../b"])
def test_reviewed_input_rejects_nonclosed_paths(
    tmp_path: Path,
    relative_path: str,
) -> None:
    reviewed_input = cast(
        "_ReviewedInput", _private("snapshot_reviewed_untracked_input")
    )

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError, match="closed relative"
    ):
        _ = reviewed_input(tmp_path.absolute(), relative_path)


def test_reviewed_input_maps_missing_ancestor_to_closed_error(tmp_path: Path) -> None:
    reviewed_input = cast(
        "_ReviewedInput", _private("snapshot_reviewed_untracked_input")
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="unavailable"):
        _ = reviewed_input(tmp_path.absolute(), "missing/file")


@pytest.mark.parametrize(
    ("raw", "message"),
    [(b"no-newline", "shape"), (b"\xff\n", "UTF-8"), (b"\n", "empty")],
)
def test_metadata_line_rejects_ambiguous_encodings(
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    path = tmp_path / "metadata"
    _ = path.write_bytes(raw)
    metadata_line = cast("_MetadataLine", _private("metadata_line"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match=message):
        _ = metadata_line(path, context="controlled metadata")


def test_git_directory_requires_existing_canonical_directory(tmp_path: Path) -> None:
    require_directory = cast("_RequireGitDirectory", _private("require_git_directory"))
    missing = tmp_path / "missing"
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="unavailable"):
        _ = require_directory(missing, context="controlled Git directory")
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="canonical"):
        _ = require_directory(linked, context="controlled Git directory")


def test_git_directory_resolution_rejects_controls_and_accepts_both_path_forms(
    tmp_path: Path,
) -> None:
    base = tmp_path.absolute()
    child = base / "child"
    child.mkdir()
    resolve_directory = cast("_ResolveGitDirectory", _private("resolve_git_directory"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="malformed"):
        _ = resolve_directory(base, "", context="controlled Git directory")
    assert resolve_directory(base, "child", context="controlled Git directory") == child
    assert (
        resolve_directory(base, str(child), context="controlled Git directory") == child
    )


def test_reference_readers_reject_invalid_loose_and_packed_values(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "worktree"
    common = tmp_path / "common"
    (worktree / "refs" / "heads").mkdir(parents=True)
    common.mkdir()
    _ = (worktree / "refs" / "heads" / "main").write_text(
        "not-an-object\n",
        encoding="ascii",
    )
    loose = cast("_LooseReference", _private("loose_reference_object_id"))
    packed = cast("_PackedReference", _private("packed_reference_object_id"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="SHA-1"):
        _ = loose((worktree, common), ("refs", "heads", "main"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="resolved"):
        _ = packed(common, "refs/heads/main")

    _ = (common / "packed-refs").write_bytes(
        b"# pack-refs\n1111111111111111111111111111111111111111 refs/heads/other\n",
    )
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="unambiguously"):
        _ = packed(common, "refs/heads/main")


@pytest.mark.parametrize("layout", ["worktree", "common"])
def test_real_git_metadata_accepts_file_pointer_worktrees(
    tmp_path: Path,
    layout: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    worktree_git = tmp_path / "worktree-git"
    worktree_git.mkdir()
    common_git = tmp_path / "common-git"
    if layout == "common":
        common_git.mkdir()
        (common_git / "objects").mkdir()
        _ = (worktree_git / "commondir").write_text(
            f"{common_git}\n",
            encoding="ascii",
        )
    else:
        (worktree_git / "objects").mkdir()
    head = "1" * 40
    _ = (repository / ".git").write_text(
        f"gitdir: {worktree_git}\n",
        encoding="ascii",
    )
    _ = (worktree_git / "HEAD").write_text(f"{head}\n", encoding="ascii")
    _ = (worktree_git / "index").write_bytes(b"index")
    discover = cast("_DiscoverMetadata", _private("discover_real_git_metadata"))

    _ = discover(repository.absolute(), expected_head=head)


def test_real_git_metadata_rejects_malformed_file_pointer(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _ = (repository / ".git").write_text("not-a-git-pointer\n", encoding="ascii")
    discover = cast("_DiscoverMetadata", _private("discover_real_git_metadata"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="malformed"):
        _ = discover(repository.absolute(), expected_head="1" * 40)


@pytest.mark.parametrize("entry_kind", ["directory", "file"])
def test_object_inventory_rejects_directory_and_file_open_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_kind: str,
) -> None:
    root = tmp_path / "objects"
    root.mkdir()
    entry = root / entry_kind
    if entry_kind == "directory":
        entry.mkdir()
    else:
        _ = entry.write_bytes(b"object")
    real_open = os.open

    def failing_open(
        path: OpenPath,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == entry_kind:
            message = "controlled open race"
            raise OSError(message)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", failing_open)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="changed"):
        _ = baseline_capture_io.object_database_inventory(root)


@pytest.mark.parametrize("mismatch_call", [1, 2])
def test_object_inventory_rejects_root_or_child_identity_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch_call: int,
) -> None:
    root = tmp_path / "objects"
    root.mkdir()
    (root / "child").mkdir()
    calls = 0

    def same_metadata(_left: os.stat_result, _right: os.stat_result) -> bool:
        nonlocal calls
        calls += 1
        return calls != mismatch_call

    monkeypatch.setattr(baseline_capture_io, "_same_object_metadata", same_metadata)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="changed"):
        _ = baseline_capture_io.object_database_inventory(root)


def test_object_inventory_rejects_file_identity_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "objects"
    root.mkdir()
    _ = (root / "object").write_bytes(b"object")
    calls = 0

    def same_metadata(_left: os.stat_result, _right: os.stat_result) -> bool:
        nonlocal calls
        calls += 1
        return calls != _SECOND_CALL

    monkeypatch.setattr(baseline_capture_io, "_same_object_metadata", same_metadata)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="changed"):
        _ = baseline_capture_io.object_database_inventory(root)


def test_object_inventory_detects_growth_after_exhausting_file_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "objects"
    root.mkdir()
    _ = (root / "object").write_bytes(b"")

    def growing_read(_descriptor: int, _size: int) -> bytes:
        return b"x"

    monkeypatch.setattr(baseline_capture_io, "MAX_REAL_OBJECT_DATABASE_BYTES", 0)
    monkeypatch.setattr(os, "read", growing_read)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="changed"):
        _ = baseline_capture_io.object_database_inventory(root)


def test_object_inventory_maps_disappearing_child_to_closed_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "objects"
    root.mkdir()
    _ = (root / "object").write_bytes(b"object")
    scanner_type = cast("type[object]", _private("ObjectDatabaseScanner"))

    def disappearing_children(
        _scanner: object,
        directory_descriptor: int,
    ) -> list[os.DirEntry[str]]:
        with os.scandir(directory_descriptor) as entries:
            children = list(entries)
        for child in children:
            os.unlink(child.name, dir_fd=directory_descriptor)
        return children

    monkeypatch.setattr(scanner_type, "_children", disappearing_children)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="inventory"):
        _ = baseline_capture_io.object_database_inventory(root)


def test_object_snapshot_rejects_copied_mtime_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    _ = (source / "object").write_bytes(b"object")
    expected = baseline_capture_io.object_database_inventory(source)
    inventory = baseline_capture_io.object_database_inventory
    calls = 0

    def drifted_inventory(
        root: Path,
    ) -> tuple[baseline_capture_io.ObjectDatabaseEntry, ...]:
        nonlocal calls
        calls += 1
        actual = inventory(root)
        if calls != _SECOND_CALL:
            return actual
        return tuple(
            replace(entry, modified_ns=entry.modified_ns + 1)
            if entry.kind == "file"
            else entry
            for entry in actual
        )

    monkeypatch.setattr(
        baseline_capture_io, "object_database_inventory", drifted_inventory
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="metadata"):
        _ = baseline_capture_io.copy_object_database_snapshot(
            source, destination, expected
        )


def test_process_group_wait_and_leader_wait_fail_closed_at_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wait_group = cast("_WaitForProcessGroup", _private("wait_for_process_group_exit"))
    wait_leader = cast(
        "_WaitForLeader", _private("wait_for_leader_exit_without_reaping")
    )

    def surviving_group(_group: int, _signal: int) -> None:
        return None

    def no_status(
        _id_type: int,
        _identifier: int,
        _options: int,
    ) -> os.waitid_result | None:
        return None

    def now() -> float:
        return 2.0

    monkeypatch.setattr(os, "killpg", surviving_group)
    monkeypatch.setattr(os, "waitid", no_status)
    monkeypatch.setattr(time, "monotonic", now)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="terminate"):
        wait_group(123, deadline=1.0)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="timed out"):
        wait_leader(_FakeProcess(123, None), deadline=1.0)


def test_leader_wait_polls_until_status_is_observable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wait_leader = cast(
        "_WaitForLeader", _private("wait_for_leader_exit_without_reaping")
    )
    statuses = iter((None, cast("os.waitid_result", object())))
    sleeps: list[float] = []

    def next_status(
        _id_type: int,
        _identifier: int,
        _options: int,
    ) -> os.waitid_result | None:
        return next(statuses)

    def before_deadline() -> float:
        return 1.0

    def observe_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(os, "waitid", next_status)
    monkeypatch.setattr(time, "monotonic", before_deadline)
    monkeypatch.setattr(time, "sleep", observe_sleep)

    wait_leader(_FakeProcess(123, None), deadline=2.0)

    assert sleeps == [0.005]


def test_process_group_cleanup_rejects_reaped_or_unreapable_leaders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kill_group = cast("_KillProcessGroup", _private("kill_process_group"))
    finish_group = cast("_FinishProcessGroup", _private("finish_process_group"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="reaped"):
        kill_group(_FakeProcess(123, 0))

    def ignore_kill(_group: int, _signal: int) -> None:
        return None

    def leader_exited(_process: object, *, deadline: float) -> None:
        del deadline

    monkeypatch.setattr(os, "killpg", ignore_kill)
    monkeypatch.setattr(
        baseline_capture_io,
        "_wait_for_leader_exit_without_reaping",
        leader_exited,
    )
    process = _FakeProcess(123, None, wait_times_out=True)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="reaped"):
        kill_group(process, deadline=1.0)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="reaped"):
        _ = finish_group(process, deadline=1.0)


def test_low_level_process_and_write_helpers_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remaining = cast("_RemainingTime", _private("remaining_process_time"))
    close_descriptors = cast("_CloseDescriptors", _private("close_descriptors"))
    write_all = cast("_WriteAll", _private("write_all"))
    config_path = cast("_GitConfigPath", _private("git_config_path_value"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="timed out"):
        _ = remaining(0.0)
    close_descriptors((-1,))

    def short_write(
        _descriptor: int, _raw: bytes | bytearray | memoryview[bytes]
    ) -> int:
        return 0

    monkeypatch.setattr(os, "write", short_write)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="controlled"):
        write_all(1, b"x", error_message="controlled short write")
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="control"):
        _ = config_path(Path("unsafe\npath"))


def test_private_git_environment_requires_object_inventory_for_check_capture(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    object_directory = tmp_path / "objects"
    object_directory.mkdir()
    index_path = tmp_path / "index"
    _ = index_path.write_bytes(b"index")
    snapshot = cast("_SnapshotRegularFile", _private("snapshot_regular_file"))(
        index_path,
        max_bytes=32,
        context="controlled index",
    )
    factory = cast("_KeywordFactory", _private("RealGitMetadata"))
    metadata = factory(
        worktree_git_directory=tmp_path,
        common_git_directory=tmp_path,
        index_path=index_path,
        object_directory=object_directory,
        index_snapshot=snapshot,
    )
    request_factory = cast("_KeywordFactory", _private("PrivateGitEnvironmentRequest"))
    request = request_factory(
        temporary_root=tmp_path / "private",
        repository=repository.absolute(),
        metadata=metadata,
        expected_head="1" * 40,
        persist_objects=False,
        object_inventory=None,
    )
    (tmp_path / "private").mkdir()
    create_environment = cast(
        "_CreatePrivateGitEnvironment",
        _private("create_private_git_environment"),
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="inventory"):
        _ = create_environment(request)


@pytest.mark.parametrize("unavailable_call", [1, 2])
def test_candidate_index_maps_unavailable_required_trees(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unavailable_call: int,
) -> None:
    calls = 0

    def unavailable_type(
        _repository: Path,
        _object_id: str,
        _expected_type: str,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        nonlocal calls
        del environment
        calls += 1
        if calls == unavailable_call:
            message = "controlled unavailable tree"
            raise baseline_capture_io.BaselineCaptureError(message)

    monkeypatch.setattr(baseline_capture_io, "_require_git_type", unavailable_type)
    validate = cast("_ValidateCandidateIndex", _private("validate_candidate_index"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="unavailable"):
        validate(
            tmp_path,
            baseline_capture_io.DEFAULT_CAPTURE_POLICY.index_transition,
            environment={},
        )


def _install_policy_success_stubs(
    monkeypatch: pytest.MonkeyPatch,
    repository: Path,
    *,
    ancestry: bytes | Exception = b"",
    mismatched_identity: bool = False,
) -> None:
    policy = baseline_capture_io.DEFAULT_CAPTURE_POLICY

    def git_text(
        _root: Path,
        *arguments: str,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        del environment
        return str(repository) if arguments[-1] == "--show-toplevel" else "sha1"

    def require_type(
        _root: Path,
        _object_id: str,
        _expected_type: str,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        del environment

    def validate_index(
        _root: Path,
        _transition: baseline_capture_io.IndexTransitionIdentity,
        *,
        environment: Mapping[str, str],
    ) -> None:
        del environment

    identities = {
        f"{policy.audit_commit}^{{tree}}": policy.audit_tree,
        f"{policy.audit_commit}:src": policy.audit_src_tree,
        f"{policy.base_commit}^{{tree}}": policy.base_tree,
        "HEAD": policy.base_commit,
        "HEAD^{tree}": policy.base_tree,
    }

    def git_object_id(
        _root: Path,
        *arguments: str,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        del environment
        value = identities[arguments[-1]]
        return "0" * 40 if mismatched_identity else value

    def git_bytes(
        _root: Path,
        _arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str] | None = None,
    ) -> bytes:
        del environment
        if isinstance(ancestry, Exception):
            raise ancestry
        return ancestry

    monkeypatch.setattr(baseline_capture_io, "git_text", git_text)
    monkeypatch.setattr(baseline_capture_io, "_require_git_type", require_type)
    monkeypatch.setattr(
        baseline_capture_io, "_validate_candidate_index", validate_index
    )
    monkeypatch.setattr(baseline_capture_io, "git_object_id", git_object_id)
    monkeypatch.setattr(baseline_capture_io, "git_bytes", git_bytes)


def test_capture_policy_rejects_invalid_root_worktree_and_object_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validate = cast("_ValidateCapturePolicy", _private("validate_capture_policy"))
    policy = baseline_capture_io.DEFAULT_CAPTURE_POLICY
    non_directory = tmp_path / "not-directory"
    _ = non_directory.write_bytes(b"x")

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="directory"):
        validate(non_directory, policy, environment={})

    repository = (tmp_path / "repository").absolute()
    repository.mkdir()

    def wrong_root(
        _root: Path,
        *_arguments: str,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        del environment
        return str(tmp_path)

    monkeypatch.setattr(baseline_capture_io, "git_text", wrong_root)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="worktree root"):
        validate(repository, policy, environment={})

    calls = 0

    def wrong_format(
        _root: Path,
        *_arguments: str,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        nonlocal calls
        del environment
        calls += 1
        return str(repository) if calls == 1 else "sha256"

    monkeypatch.setattr(baseline_capture_io, "git_text", wrong_format)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="SHA-1"):
        validate(repository, policy, environment={})


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("identity", "identity drifted"),
        ("ancestry-error", "not an ancestor"),
        ("ancestry-output", "unexpected merge-base"),
    ],
)
def test_capture_policy_rejects_identity_and_ancestry_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    message: str,
) -> None:
    repository = (tmp_path / "repository").absolute()
    repository.mkdir()
    ancestry: bytes | Exception = b""
    if fault == "ancestry-error":
        ancestry = baseline_capture_io.BaselineCaptureError("controlled ancestry")
    elif fault == "ancestry-output":
        ancestry = b"unexpected"
    _install_policy_success_stubs(
        monkeypatch,
        repository,
        ancestry=ancestry,
        mismatched_identity=fault == "identity",
    )
    validate = cast("_ValidateCapturePolicy", _private("validate_capture_policy"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match=message):
        validate(repository, baseline_capture_io.DEFAULT_CAPTURE_POLICY, environment={})


@pytest.mark.parametrize(
    "raw_record",
    [b"missing-tab", b"100644 blob id\tpath", b"100644 blob id size\tpath"],
)
def test_tree_record_decoder_rejects_each_malformed_field_shape(
    raw_record: bytes,
) -> None:
    decode = cast("_DecodeTreeRecord", _private("decode_tree_record"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="malformed"):
        _ = decode(raw_record)


def test_tree_mode_inventory_rejects_empty_record_and_total_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        (
            b"\0\0",
            b"100644 blob 1111111111111111111111111111111111111111 1\ta\0",
        ),
    )

    def git_bytes(
        _root: Path,
        _arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str] | None = None,
    ) -> bytes:
        del environment
        return next(outputs)

    monkeypatch.setattr(baseline_capture_io, "git_bytes", git_bytes)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="malformed"):
        _ = baseline_capture_io.validate_tree_modes(tmp_path, "1" * 40, environment={})
    monkeypatch.setattr(baseline_capture_io, "MAX_MATERIALIZED_TREE_BYTES", 0)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="size limit"):
        _ = baseline_capture_io.validate_tree_modes(tmp_path, "1" * 40, environment={})


def _install_derive_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    snapshots: list[tuple[_FakeReviewedInput, ...]],
    inventory: tuple[_FakeTreeEntry, ...],
    imported_tree_mismatch: bool = False,
    imported_paths_present: bool = False,
) -> None:
    policy = baseline_capture_io.DEFAULT_CAPTURE_POLICY
    object_ids = iter(
        (
            "0" * 40
            if imported_tree_mismatch
            else policy.index_transition.imported_index_tree,
            "2" * 40,
            "3" * 40,
            "4" * 40,
        ),
    )

    def no_output(
        _root: Path,
        *_arguments: str,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        del environment

    def object_id(
        _root: Path,
        *_arguments: str,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        del environment
        return next(object_ids)

    def staged_digest(
        _root: Path,
        *,
        environment: Mapping[str, str],
    ) -> str:
        del environment
        return policy.index_transition.imported_staged_entries_sha256

    def git_bytes(
        _root: Path,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str] | None = None,
    ) -> bytes:
        del environment
        if arguments[0] == "ls-files":
            return b"present" if imported_paths_present else b""
        return b"generator"

    snapshot_iterator = iter(snapshots)

    def reviewed_inputs(
        _root: Path,
        _paths: baseline_capture_io.IncludedUntrackedPaths,
    ) -> tuple[_FakeReviewedInput, ...]:
        return next(snapshot_iterator)

    def require_type(
        _root: Path,
        _object_id: str,
        _expected_type: str,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        del environment

    def tree_modes(
        _root: Path,
        _tree: str,
        *,
        environment: Mapping[str, str],
    ) -> tuple[_FakeTreeEntry, ...]:
        del environment
        return inventory

    monkeypatch.setattr(baseline_capture_io, "git_no_output", no_output)
    monkeypatch.setattr(baseline_capture_io, "git_object_id", object_id)
    monkeypatch.setattr(baseline_capture_io, "_staged_entries_sha256", staged_digest)
    monkeypatch.setattr(baseline_capture_io, "git_bytes", git_bytes)
    monkeypatch.setattr(
        baseline_capture_io,
        "_snapshot_reviewed_untracked_inputs",
        reviewed_inputs,
    )
    monkeypatch.setattr(baseline_capture_io, "_require_git_type", require_type)
    monkeypatch.setattr(baseline_capture_io, "validate_tree_modes", tree_modes)


def test_input_tree_derivation_rejects_imported_tree_and_path_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive = cast("_DeriveInputTree", _private("derive_input_tree"))
    _install_derive_stubs(
        monkeypatch,
        snapshots=[],
        inventory=(),
        imported_tree_mismatch=True,
    )
    with pytest.raises(
        baseline_capture_io.BaselineCaptureError, match="materialization"
    ):
        _ = derive(tmp_path, baseline_capture_io.DEFAULT_CAPTURE_POLICY, environment={})

    monkeypatch.undo()
    _install_derive_stubs(
        monkeypatch,
        snapshots=[],
        inventory=(),
        imported_paths_present=True,
    )
    with pytest.raises(
        baseline_capture_io.BaselineCaptureError, match="imported index"
    ):
        _ = derive(tmp_path, baseline_capture_io.DEFAULT_CAPTURE_POLICY, environment={})


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("after-tree", "derivation"),
        ("reviewed-binding", "exactly bound"),
        ("generator-binding", "generator blob"),
    ],
)
def test_input_tree_derivation_rejects_late_binding_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    message: str,
) -> None:
    raw = b"reviewed"
    reviewed = _FakeReviewedInput("reviewed", _FakeReviewedFile(len(raw), raw))
    changed = _FakeReviewedInput("reviewed", _FakeReviewedFile(len(raw), b"changed!"))
    reviewed_entry = _FakeTreeEntry("reviewed", "100644", _sha1_blob(raw), len(raw))
    snapshots: list[tuple[_FakeReviewedInput, ...]] = [
        (reviewed,),
        (reviewed,),
        (reviewed,),
    ]
    inventory: tuple[_FakeTreeEntry, ...] = (reviewed_entry,)
    if fault == "after-tree":
        snapshots[-1] = (changed,)
    elif fault == "reviewed-binding":
        inventory = ()
    _install_derive_stubs(monkeypatch, snapshots=snapshots, inventory=inventory)
    derive = cast("_DeriveInputTree", _private("derive_input_tree"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match=message):
        _ = derive(tmp_path, baseline_capture_io.DEFAULT_CAPTURE_POLICY, environment={})


@pytest.mark.parametrize("mismatch_pair", [1, 2, 3])
def test_materialized_file_rejects_identity_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch_pair: int,
) -> None:
    path = tmp_path / "materialized"
    raw = b"content"
    _ = path.write_bytes(raw)
    entry = _FakeTreeEntry("materialized", "100644", _sha1_blob(raw), len(raw))
    identity, calls = _identity_sequence(mismatch_pair)
    monkeypatch.setattr(baseline_capture_io, "_stat_identity", identity)
    read_materialized = cast(
        "_ReadMaterializedFile", _private("read_materialized_file")
    )

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="changed"):
        _ = read_materialized(path, entry)

    assert len(calls) == mismatch_pair * 2


def test_materialized_file_rejects_short_growth_and_content_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_materialized = cast(
        "_ReadMaterializedFile", _private("read_materialized_file")
    )
    path = tmp_path / "materialized"
    _ = path.write_bytes(b"")
    empty = _FakeTreeEntry("materialized", "100644", _sha1_blob(b""), 0)

    def growing_read(_descriptor: int, _size: int) -> bytes:
        return b"x"

    monkeypatch.setattr(os, "read", growing_read)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="verification"):
        _ = read_materialized(path, empty)

    monkeypatch.undo()
    _ = path.write_bytes(b"x")
    wrong_digest = _FakeTreeEntry("materialized", "100644", "0" * 40, 1)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="content"):
        _ = read_materialized(path, wrong_digest)


@pytest.mark.parametrize("fault", ["depth", "special-root", "non-utf8"])
def test_materialized_tree_rejects_hostile_directory_shapes(
    tmp_path: Path,
    fault: str,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    if fault == "depth":
        nested = root
        for position in range(baseline_capture_io.MAX_CANONICAL_JSON_DEPTH + 2):
            nested /= f"d{position}"
            nested.mkdir()
    elif fault == "special-root":
        target = tmp_path / "target"
        target.mkdir()
        root.rmdir()
        root.symlink_to(target, target_is_directory=True)
    else:
        descriptor = os.open(
            os.fsencode(root) + b"/non-utf8-\xff",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
        )
        os.close(descriptor)
    validate = cast("_ValidateMaterializedTree", _private("validate_materialized_tree"))

    with pytest.raises(baseline_capture_io.BaselineCaptureError):
        _ = validate(root, ())


def test_synthetic_workspace_rejects_non_directory_root(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _ = repository.write_bytes(b"not-directory")

    with (
        pytest.raises(baseline_capture_io.BaselineCaptureError, match="directory"),
        baseline_capture_io.synthetic_workspace(
            repository,
            policy=baseline_capture_io.DEFAULT_CAPTURE_POLICY,
            persist_objects=True,
        ),
    ):
        pytest.fail("non-directory repository reached the workspace")


@pytest.mark.parametrize(
    ("drift", "message"),
    [("index", "index"), ("objects", "object database")],
)
def test_synthetic_workspace_detects_real_git_boundary_drift(
    tmp_path: Path,
    drift: str,
    message: str,
) -> None:
    repository = tmp_path / "repository"
    policy = baseline_capture_io.CapturePolicy(
        **make_capture_git_repository(repository)
    )

    def mutate_boundary() -> None:
        with baseline_capture_io.synthetic_workspace(
            repository,
            policy=policy,
            persist_objects=False,
        ):
            if drift == "index":
                with (repository / ".git" / "index").open("ab") as stream:
                    _ = stream.write(b"drift")
            else:
                _ = (repository / ".git" / "objects" / "race").write_bytes(b"drift")

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match=message):
        mutate_boundary()


def test_materialization_rejects_post_yield_tree_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    policy = baseline_capture_io.CapturePolicy(
        **make_capture_git_repository(repository)
    )
    original = cast("_DeriveInputTree", _private("derive_input_tree"))
    calls = 0

    def drifted_derive(
        root: Path,
        capture_policy: baseline_capture_io.CapturePolicy,
        *,
        environment: Mapping[str, str],
    ) -> tuple[str, str, baseline_capture_io.GeneratorIdentity, tuple[object, ...]]:
        nonlocal calls
        calls += 1
        result = original(root, capture_policy, environment=environment)
        if calls == _SECOND_CALL:
            return ("0" * 40, result[1], result[2], result[3])
        return result

    monkeypatch.setattr(baseline_capture_io, "_derive_input_tree", drifted_derive)
    with (
        pytest.raises(
            baseline_capture_io.BaselineCaptureError, match="materialization"
        ),
        baseline_capture_io.materialize_synthetic_input(
            repository,
            policy=policy,
            persist_objects=True,
        ),
    ):
        pass


def test_fixture_collection_requires_exact_closed_output_set(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    policy = baseline_capture_io.CapturePolicy(
        **make_capture_git_repository(repository)
    )

    def empty_collector(
        _root: Path,
    ) -> Mapping[baseline_capture_io.BaselineFileName, Mapping[str, object]]:
        return {}

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="exact four"):
        _ = baseline_capture_io.collect_from_synthetic_input(
            repository,
            policy=policy,
            persist_objects=True,
            collector=empty_collector,
        )


def test_regular_readers_reject_open_identity_and_stream_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "subject"
    other = tmp_path / "other"
    _ = path.write_bytes(b"{}\n")
    _ = other.write_bytes(b"{}\n")
    other_descriptor = os.open(other, os.O_RDONLY)
    other_stat = os.fstat(other_descriptor)
    os.close(other_descriptor)

    def mismatched_fstat(_descriptor: int) -> os.stat_result:
        return other_stat

    monkeypatch.setattr(os, "fstat", mismatched_fstat)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="changed"):
        _ = baseline_capture_io.load_canonical_json(path)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="changed"):
        _ = baseline_capture_io.read_regular_bytes(path)

    monkeypatch.undo()
    reads = iter((b"{}\nX", b""))

    def growing_read(_descriptor: int, _size: int) -> bytes:
        return next(reads)

    monkeypatch.setattr(os, "read", growing_read)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="exceeds"):
        _ = baseline_capture_io.load_canonical_json(path, max_bytes=3)

    reads = iter((b"{}\nX", b""))
    monkeypatch.setattr(baseline_capture_io, "MAX_CANONICAL_JSON_BYTES", 3)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="oversized"):
        _ = baseline_capture_io.read_regular_bytes(path)


def _publication_operations() -> baseline_capture_io.PublicationOperations:
    def validate(_root: Path) -> object:
        return object()

    def replace_path(source: Path, destination: Path) -> None:
        _ = source.replace(destination)

    return baseline_capture_io.PublicationOperations(
        validator=validate,
        replace=replace_path,
        rollback=replace_path,
        stage=baseline_capture_io.write_staged_file,
    )


def test_publication_staging_rejects_oversize_and_handles_absent_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_factory = cast("_KeywordFactory", _private("DestinationState"))
    stage_publication = cast("_StagePublication", _private("stage_publication"))
    outputs: dict[str, bytes] = dict.fromkeys(
        baseline_capture_io.BASELINE_DIRECTORY_FILES,
        b"x",
    )
    states: dict[str, object] = {
        name: state_factory(existed=True, device=1, inode=1, mode=None, raw=b"old")
        for name in baseline_capture_io.BASELINE_DIRECTORY_FILES
    }
    monkeypatch.setattr(baseline_capture_io, "MAX_CANONICAL_JSON_BYTES", 0)
    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="oversized"):
        stage_publication(
            tmp_path / "oversize-staged",
            tmp_path / "oversize-backups",
            outputs,
            states,
            _publication_operations(),
        )

    monkeypatch.setattr(baseline_capture_io, "MAX_CANONICAL_JSON_BYTES", 16)
    stage_publication(
        tmp_path / "staged",
        tmp_path / "backups",
        outputs,
        states,
        _publication_operations(),
    )


def test_rollback_rejects_special_destination_and_reports_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_factory = cast("_KeywordFactory", _private("DestinationState"))
    missing_state = state_factory(
        existed=False,
        device=None,
        inode=None,
        mode=None,
        raw=None,
    )
    root = tmp_path / "root"
    backups = tmp_path / "backups"
    root.mkdir()
    backups.mkdir()
    (root / "fixture.json").mkdir()
    restore = cast("_RestoreDestination", _private("restore_destination"))
    rollback = cast("_RollbackPublication", _private("rollback_publication"))

    def replace_path(source: Path, destination: Path) -> None:
        _ = source.replace(destination)

    with pytest.raises(baseline_capture_io.BaselineCaptureError, match="unsafe"):
        restore(root, backups, "fixture.json", missing_state, replace_path)

    failure = OSError("controlled directory fsync")

    def fail_fsync(_root: Path) -> None:
        raise failure

    monkeypatch.setattr(baseline_capture_io, "_directory_fsync", fail_fsync)
    assert rollback(root, backups, [], {}, replace_path) is failure
