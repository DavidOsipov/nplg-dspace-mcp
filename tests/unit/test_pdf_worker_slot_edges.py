# Copyright (c) 2026 David Osipov
"""Adversarial edge tests for the dedicated PDF worker slot."""

from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Protocol, cast

import pytest

import nplg_mcp.pdf_worker_slot as worker_slot_module
from nplg_mcp.pdf_worker_slot import (
    DirectoryFd,
    PdfWorkerSlotError,
    PdfWorkerSlotPolicy,
    QuotaBoundStagingRoot,
    WorkerSlotFilesystem,
    WorkerSlotFilesystemInspector,
    WorkerSlotLease,
    WorkerStagingQuota,
    load_pdf_worker_slot_policy,
    open_child_directory_fd,
    open_configured_root_fd,
    validate_quota_bound_staging_root,
    validate_safe_path_segment,
)

_SLOT_TOTAL_BYTES = 1_073_741_824
_SLOT_MINIMUM_AVAILABLE_BYTES = 805_306_368
_SLOT_TOTAL_INODES = 65_536
_SLOT_MINIMUM_AVAILABLE_INODES = 32_768
_MAX_POLICY_BYTES = 16 * 1024
_REVIEWED_MOUNT_OPTIONS = frozenset({"rw", "nodev", "nosuid", "noexec"})
_INHERITABLE_DESCRIPTOR = True


class _DirectoryFdFactory(Protocol):
    def __call__(self, descriptor: int, *, device: int) -> DirectoryFd: ...


class _ValidateDirectoryDescriptor(Protocol):
    def __call__(
        self,
        raw_descriptor: int,
        *,
        directory_fd: DirectoryFd | None,
    ) -> DirectoryFd: ...


class _OpenValidatedDirectory(Protocol):
    def __call__(
        self,
        path: str | Path,
        *,
        directory_fd: DirectoryFd | None = None,
    ) -> DirectoryFd: ...


class _MountDetails(Protocol):
    def __call__(self, root: Path, device: int) -> tuple[frozenset[str], str]: ...


class _DecodeMountinfoPath(Protocol):
    def __call__(self, value: str) -> str: ...


class _InspectorFallback(Protocol):
    def __call__(self, instance: object, root: Path) -> WorkerSlotFilesystem: ...


_WORKER_SLOT_NAMESPACE = cast(
    "dict[str, object]",
    cast("object", worker_slot_module.__dict__),
)
_DIRECTORY_FD_FROM_VALIDATED = cast(
    "_DirectoryFdFactory",
    _WORKER_SLOT_NAMESPACE["_directory_fd_from_validated"],
)
_VALIDATED_DIRECTORY_FROM_DESCRIPTOR = cast(
    "_ValidateDirectoryDescriptor",
    _WORKER_SLOT_NAMESPACE["_validated_directory_from_descriptor"],
)
_OPEN_VALIDATED_DIRECTORY = cast(
    "_OpenValidatedDirectory",
    _WORKER_SLOT_NAMESPACE["_open_validated_directory"],
)
_DECODE_MOUNTINFO_PATH = cast(
    "_DecodeMountinfoPath",
    _WORKER_SLOT_NAMESPACE["_decode_mountinfo_path"],
)
_MOUNT_DETAILS = cast(
    "_MountDetails",
    _WORKER_SLOT_NAMESPACE["_mount_details"],
)
_INSPECTOR_NAMESPACE = cast(
    "dict[str, object]",
    cast("object", WorkerSlotFilesystemInspector.__dict__),
)
_INSPECTOR_FALLBACK = cast(
    "_InspectorFallback",
    _INSPECTOR_NAMESPACE["inspect"],
)


def _policy_payload(
    *, root: str = "/var/lib/nplg/pdf-worker-slot"
) -> dict[str, object]:
    return {
        "version": 1,
        "root": root,
        "filesystem_type": "ext4",
        "maximum_total_bytes": _SLOT_TOTAL_BYTES,
        "minimum_available_bytes": _SLOT_MINIMUM_AVAILABLE_BYTES,
        "maximum_total_inodes": _SLOT_TOTAL_INODES,
        "minimum_available_inodes": _SLOT_MINIMUM_AVAILABLE_INODES,
        "mount_options": ["rw", "nodev", "nosuid", "noexec"],
        "concurrency": 1,
    }


def _policy(*, root: str = "/var/lib/nplg/pdf-worker-slot") -> PdfWorkerSlotPolicy:
    """Return one independently specified valid worker-slot policy."""
    return PdfWorkerSlotPolicy.model_validate(
        _policy_payload(root=root),
        strict=True,
    )


class _FixedInspector:
    """Return a complete healthy observation without touching the host mount table."""

    def __init__(self, root: Path, observed: WorkerSlotFilesystem) -> None:
        super().__init__()
        self._root = root
        self._observed = observed

    def inspect(self, root: Path) -> WorkerSlotFilesystem:
        assert root == self._root
        return self._observed


class _SequencedInspector:
    """Return deterministic startup and per-dispatch filesystem observations."""

    def __init__(
        self,
        root: Path,
        observations: list[WorkerSlotFilesystem],
    ) -> None:
        super().__init__()
        self._root = root
        self._observations = observations

    def inspect(self, root: Path) -> WorkerSlotFilesystem:
        assert root == self._root
        if not self._observations:
            pytest.fail("worker slot was inspected more often than specified")
        return self._observations.pop(0)


def _healthy_filesystem() -> WorkerSlotFilesystem:
    return WorkerSlotFilesystem(
        filesystem_type="ext4",
        mount_options=_REVIEWED_MOUNT_OPTIONS,
        total_bytes=_SLOT_TOTAL_BYTES,
        available_bytes=_SLOT_MINIMUM_AVAILABLE_BYTES,
        total_inodes=_SLOT_TOTAL_INODES,
        available_inodes=_SLOT_MINIMUM_AVAILABLE_INODES,
    )


def _healthy_inspector() -> _FixedInspector:
    return _FixedInspector(
        Path("/var/lib/nplg/pdf-worker-slot"),
        _healthy_filesystem(),
    )


def test_foreign_lease_cannot_release_another_worker_slot() -> None:
    """Catch cross-quota release that defeats exclusive slot ownership."""
    policy = _policy()
    first = WorkerStagingQuota(policy=policy, inspector=_healthy_inspector())
    second = WorkerStagingQuota(policy=policy, inspector=_healthy_inspector())
    foreign_lease = first.lease()
    _ = second.lease()
    try:
        with pytest.raises(PdfWorkerSlotError, match="lease is invalid"):
            second.release(foreign_lease)
        with pytest.raises(PdfWorkerSlotError, match="already leased"):
            _ = second.lease()
    finally:
        foreign_lease.release()


def test_same_quota_forged_lease_cannot_enter_the_worker_slot() -> None:
    """Catch a caller-forged lease that bypasses the quota reservation."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    forged = WorkerSlotLease(quota=quota, root=quota.root)

    with pytest.raises(PdfWorkerSlotError, match="lease is invalid"), forged:
        pytest.fail("a non-issued lease exposed the worker root")

    issued = quota.lease()
    issued.release()


def test_same_quota_forged_lease_cannot_release_the_active_slot() -> None:
    """Catch a forged same-authority lease that frees another reservation."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    active = quota.lease()
    forged = WorkerSlotLease(quota=quota, root=quota.root)
    try:
        with pytest.raises(PdfWorkerSlotError, match="lease is invalid"):
            quota.release(forged)
        with pytest.raises(PdfWorkerSlotError, match="already leased"):
            _ = quota.lease()
    finally:
        active.release()


def test_direct_release_invalidates_the_issued_lease_before_reuse() -> None:
    """Catch direct quota release that leaves an issued root capability live."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    lease = quota.lease()

    quota.release(lease)

    with pytest.raises(PdfWorkerSlotError, match="already released"), lease:
        pytest.fail("a directly released lease exposed the worker root")
    replacement = quota.lease()
    replacement.release()


def test_stale_direct_release_cannot_free_the_current_issued_lease() -> None:
    """Catch replay of an old lease against a newer slot reservation."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    stale = quota.lease()
    stale.release()
    active = quota.lease()
    try:
        quota.release(stale)
        with pytest.raises(PdfWorkerSlotError, match="already leased"):
            _ = quota.lease()
    finally:
        active.release()


def test_released_lease_cannot_reenter_the_worker_slot() -> None:
    """Catch reuse of a root handle after its exclusive reservation ended."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    lease = quota.lease()
    lease.release()

    with pytest.raises(PdfWorkerSlotError, match="lease was already released"), lease:
        pytest.fail("a released lease exposed the worker root")


def test_duplicate_enter_cannot_create_two_holders_of_one_issued_lease() -> None:
    """Catch one exact lease exposing the serialized slot more than once."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    lease = quota.lease()

    _ = lease.__enter__()
    try:
        with pytest.raises(PdfWorkerSlotError, match="lease is already entered"):
            _ = lease.__enter__()
        with pytest.raises(PdfWorkerSlotError, match="already leased"):
            _ = quota.lease()
    finally:
        lease.__exit__(None, None, None)


@pytest.mark.parametrize("operation", ["enter", "release"])
def test_active_lease_rejects_a_missing_lifecycle_state(operation: str) -> None:
    """Catch invariant corruption that would otherwise expose or free the slot."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    lease = quota.lease()
    object.__setattr__(quota, "_active_lease_state", None)

    if operation == "enter":
        with pytest.raises(PdfWorkerSlotError, match="lease is invalid"):
            _ = lease.__enter__()
    else:
        with pytest.raises(PdfWorkerSlotError, match="lease is invalid"):
            lease.release()


def test_failed_nested_enter_cannot_release_the_outer_slot_holder() -> None:
    """Catch nested context unwinding that makes a still-used slot reusable."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    lease = quota.lease()

    with lease:
        with (
            pytest.raises(PdfWorkerSlotError, match="lease is already entered"),
            lease,
        ):
            pytest.fail("a nested context entered one live lease twice")
        with pytest.raises(PdfWorkerSlotError, match="already leased"):
            _ = quota.lease()

    replacement = quota.lease()
    replacement.release()


@pytest.mark.asyncio
async def test_issued_lease_cannot_transfer_to_a_sibling_async_context() -> None:
    """Catch same-thread task transfer before the issuing task enters its lease."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    lease = quota.lease()

    async def attempt_transfer() -> None:
        with pytest.raises(PdfWorkerSlotError, match="another execution context"):
            _ = lease.__enter__()
        with pytest.raises(PdfWorkerSlotError, match="another execution context"):
            lease.release()

    await asyncio.create_task(attempt_transfer())

    with lease, pytest.raises(PdfWorkerSlotError, match="already leased"):
        _ = quota.lease()


def test_concurrent_context_cannot_release_an_entered_lease() -> None:
    """Catch a foreign thread freeing a slot while its exact owner still uses it."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    lease = quota.lease()

    def attempt_transfer() -> None:
        with pytest.raises(PdfWorkerSlotError, match="another execution context"):
            _ = lease.__enter__()
        with pytest.raises(PdfWorkerSlotError, match="another execution context"):
            lease.release()

    with lease, ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(attempt_transfer).result(timeout=2)
        with pytest.raises(PdfWorkerSlotError, match="already leased"):
            _ = quota.lease()

    replacement = quota.lease()
    replacement.release()


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"version": 2}, "version"),
        ({"root": "relative-slot"}, "canonical absolute"),
        ({"filesystem_type": "xfs"}, "must be ext4"),
        ({"maximum_total_bytes": 0}, "positive integers"),
        ({"mount_options": ("rw", "nodev", "nosuid", "noexec")}, "JSON array"),
        ({"mount_options": ["rw", "nodev", "nosuid"]}, "reviewed set"),
        ({"concurrency": 2}, "concurrency"),
        ({"minimum_available_bytes": _SLOT_TOTAL_BYTES + 1}, "byte headroom"),
        ({"minimum_available_inodes": _SLOT_TOTAL_INODES + 1}, "inode headroom"),
    ],
)
def test_slot_policy_rejects_each_fail_closed_schema_boundary(
    update: dict[str, object],
    message: str,
) -> None:
    """Catch removal of a reviewed mount, capacity, or serialization invariant."""
    payload = _policy_payload()
    payload.update(update)

    with pytest.raises(ValueError, match=message):
        _ = PdfWorkerSlotPolicy.model_validate(payload, strict=True)


def test_filesystem_observation_rejects_negative_metrics() -> None:
    """Catch a forged statvfs observation that bypasses non-negative accounting."""
    with pytest.raises(ValueError, match="non-negative"):
        _ = WorkerSlotFilesystem(
            filesystem_type="ext4",
            mount_options=_REVIEWED_MOUNT_OPTIONS,
            total_bytes=-1,
            available_bytes=0,
            total_inodes=0,
            available_inodes=0,
        )


def test_incomplete_inspector_fails_closed_instead_of_forging_an_observation() -> None:
    """Catch an incomplete injected inspector that silently returns no facts."""
    with pytest.raises(NotImplementedError):
        _ = _INSPECTOR_FALLBACK(object(), Path("/var/lib/nplg/pdf-worker-slot"))


def test_policy_loader_rejects_relative_and_unsafe_regular_files(
    tmp_path: Path,
) -> None:
    """Catch policy admission without an absolute path or immutable file mode."""
    with pytest.raises(PdfWorkerSlotError, match="path is invalid"):
        _ = load_pdf_worker_slot_policy(Path("relative-policy.json"))

    writable_policy = tmp_path / "writable-policy.json"
    _ = writable_policy.write_bytes(b"{}")
    writable_policy.chmod(0o666)
    with pytest.raises(PdfWorkerSlotError, match="safe regular file"):
        _ = load_pdf_worker_slot_policy(writable_policy)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"xx", "valid JSON"),
        (b"\xff\xff", "valid JSON"),
        (b"[]", "root must be a JSON object"),
        (b"{}", "strict schema"),
    ],
)
def test_policy_loader_rejects_malformed_or_nonconforming_documents(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    """Catch parser or schema fallback for an attacker-controlled policy file."""
    path = tmp_path / "policy.json"
    _ = path.write_bytes(payload)

    with pytest.raises(PdfWorkerSlotError, match=message):
        _ = load_pdf_worker_slot_policy(path)


def test_policy_loader_rejects_a_post_stat_size_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a policy whose bytes no longer match its descriptor metadata."""
    path = tmp_path / "policy.json"
    _ = path.write_bytes(b"{}")
    reads = iter((b"{}x", b""))

    def changed_read(descriptor: int, maximum: int) -> bytes:
        del descriptor, maximum
        return next(reads)

    monkeypatch.setattr(os, "read", changed_read)

    with pytest.raises(PdfWorkerSlotError, match="changed or exceeded"):
        _ = load_pdf_worker_slot_policy(path)


def test_policy_loader_stops_after_the_bounded_read_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch an unbounded read when descriptor bytes outgrow reviewed metadata."""
    path = tmp_path / "policy.json"
    _ = path.write_bytes(b"{}")

    def oversized_read(descriptor: int, maximum: int) -> bytes:
        del descriptor, maximum
        return b"x" * (_MAX_POLICY_BYTES + 1)

    monkeypatch.setattr(os, "read", oversized_read)

    with pytest.raises(PdfWorkerSlotError, match="changed or exceeded"):
        _ = load_pdf_worker_slot_policy(path)


@pytest.mark.parametrize("value", [None, ".", "..", "contains/slash", "x" * 129])
def test_child_segment_rejects_noncanonical_names(value: object) -> None:
    """Catch descriptor-relative traversal through an unsafe child segment."""
    with pytest.raises(PdfWorkerSlotError, match="child name is invalid"):
        _ = validate_safe_path_segment(value)

    assert validate_safe_path_segment("request-01.safe") == "request-01.safe"


def test_configured_and_child_directory_descriptors_are_owned_and_closed(
    tmp_path: Path,
) -> None:
    """Catch descriptor leakage or path-based child traversal after validation."""
    root = tmp_path / "slot"
    root.mkdir(mode=0o700)
    child = root / "request-01"
    child.mkdir(mode=0o700)
    root_descriptor_number = -1
    child_descriptor_number = -1

    with (
        open_configured_root_fd(_policy(root=str(root))) as root_descriptor,
        open_child_directory_fd(root_descriptor, "request-01") as child_descriptor,
    ):
        root_descriptor_number = root_descriptor.fileno
        assert root_descriptor.device == root.stat().st_dev
        child_descriptor_number = child_descriptor.fileno
        assert child_descriptor.device == root_descriptor.device

    with pytest.raises(OSError, match="Bad file descriptor"):
        _ = os.fstat(root_descriptor_number)
    with pytest.raises(OSError, match="Bad file descriptor"):
        _ = os.fstat(child_descriptor_number)


def test_directory_open_rejects_invalid_parent_and_missing_target(
    tmp_path: Path,
) -> None:
    """Catch forged parent descriptors and missing path admission."""
    with pytest.raises(PdfWorkerSlotError, match="parent descriptor is invalid"):
        _ = open_child_directory_fd(cast("DirectoryFd", object()), "child")
    with pytest.raises(PdfWorkerSlotError, match="cannot be opened safely"):
        _ = _OPEN_VALIDATED_DIRECTORY(tmp_path / "missing")


def test_directory_descriptor_validation_rejects_invalid_inheritable_and_file_fds(
    tmp_path: Path,
) -> None:
    """Catch forged, inheritable, and non-directory descriptor admission."""
    with pytest.raises(PdfWorkerSlotError, match="descriptor is invalid"):
        _ = _VALIDATED_DIRECTORY_FROM_DESCRIPTOR(-1, directory_fd=None)

    directory_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.set_inheritable(directory_descriptor, _INHERITABLE_DESCRIPTOR)
        with pytest.raises(PdfWorkerSlotError, match="descriptor is inheritable"):
            _ = _VALIDATED_DIRECTORY_FROM_DESCRIPTOR(
                directory_descriptor,
                directory_fd=None,
            )
    finally:
        os.close(directory_descriptor)

    regular_file = tmp_path / "regular-file"
    _ = regular_file.write_bytes(b"not a directory")
    file_descriptor = os.open(regular_file, os.O_RDONLY)
    try:
        with pytest.raises(PdfWorkerSlotError, match="not a safe directory"):
            _ = _VALIDATED_DIRECTORY_FROM_DESCRIPTOR(
                file_descriptor,
                directory_fd=None,
            )
    finally:
        os.close(file_descriptor)


def test_child_descriptor_cannot_cross_the_validated_device(tmp_path: Path) -> None:
    """Catch a bind-mount escape beneath a descriptor-relative worker root."""
    root_descriptor_number = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    child_descriptor_number = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    root_descriptor = _DIRECTORY_FD_FROM_VALIDATED(
        root_descriptor_number,
        device=tmp_path.stat().st_dev + 1,
    )
    try:
        with pytest.raises(PdfWorkerSlotError, match="another device"):
            _ = _VALIDATED_DIRECTORY_FROM_DESCRIPTOR(
                child_descriptor_number,
                directory_fd=root_descriptor,
            )
    finally:
        os.close(child_descriptor_number)
        root_descriptor.close()


def test_directory_open_requires_nofollow_and_closes_failed_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch platforms without no-follow support and validation-error fd leaks."""
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(PdfWorkerSlotError, match="requires O_NOFOLLOW"):
        _ = _OPEN_VALIDATED_DIRECTORY(tmp_path)
    monkeypatch.undo()

    closed: list[int] = []
    original_close = os.close

    def inheritable(_descriptor: int) -> bool:
        return True

    def recording_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(os, "get_inheritable", inheritable)
    monkeypatch.setattr(os, "close", recording_close)
    with pytest.raises(PdfWorkerSlotError, match="descriptor is inheritable"):
        _ = _OPEN_VALIDATED_DIRECTORY(tmp_path)

    assert len(closed) == 1


def test_unsafe_root_metadata_closes_the_open_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch an unsafe root-mode rejection that leaks its owned descriptor."""
    root = tmp_path / "slot"
    root.mkdir(mode=0o755)
    closed: list[int] = []
    original_close = os.close

    def recording_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(os, "close", recording_close)

    with pytest.raises(PdfWorkerSlotError, match="ownership or mode is unsafe"):
        _ = open_configured_root_fd(_policy(root=str(root)))

    assert len(closed) == 1


def test_failed_dispatch_validation_restores_the_slot_reservation() -> None:
    """Catch a failed revalidation that permanently wedges the single slot."""
    root = Path("/var/lib/nplg/pdf-worker-slot")
    healthy = _healthy_filesystem()
    exhaustion_update: dict[str, object] = {"available_inodes": 1}
    exhausted = healthy.model_copy(update=exhaustion_update)
    quota = WorkerStagingQuota(
        policy=_policy(),
        inspector=_SequencedInspector(root, [healthy, exhausted, healthy]),
    )

    with pytest.raises(PdfWorkerSlotError, match="available inode"):
        _ = quota.lease()

    recovered = quota.lease()
    recovered.release()


def test_slot_release_is_idempotent_and_rejects_nonlease_objects() -> None:
    """Keep every ordinary cleanup path idempotent without accepting forgeries."""
    quota = WorkerStagingQuota(policy=_policy(), inspector=_healthy_inspector())
    lease = quota.lease()
    lease.release()
    lease.release()
    quota.release(lease)
    with pytest.raises(PdfWorkerSlotError, match="lease is invalid"):
        _ = quota.enter(cast("WorkerSlotLease", object()))
    with pytest.raises(PdfWorkerSlotError, match="lease is invalid"):
        quota.release(cast("WorkerSlotLease", object()))


def test_default_quota_inspector_fails_closed_for_a_nonmount_root(
    tmp_path: Path,
) -> None:
    """Catch startup that skips host mount-table validation without an inspector."""
    root = tmp_path / "slot"
    root.mkdir(mode=0o700)

    with pytest.raises(PdfWorkerSlotError, match="exactly one non-nested mount"):
        _ = WorkerStagingQuota(policy=_policy(root=str(root)))


def test_system_inspector_rejects_a_nondirectory_root(tmp_path: Path) -> None:
    """Catch statvfs admission of a regular file in place of the worker root."""
    root = tmp_path / "not-a-directory"
    _ = root.write_bytes(b"file")

    with pytest.raises(PdfWorkerSlotError, match="not a regular directory"):
        _ = validate_quota_bound_staging_root(_policy(root=str(root)))


def test_system_inspector_projects_mount_and_statvfs_facts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch capacity projection that omits host statvfs block or inode facts."""
    root = tmp_path / "slot"
    root.mkdir(mode=0o700)
    stats = os.statvfs(root)
    total_bytes = stats.f_blocks * stats.f_frsize
    available_bytes = stats.f_bavail * stats.f_frsize
    total_inodes = stats.f_files
    available_inodes = stats.f_favail
    assert min(total_bytes, available_bytes, total_inodes, available_inodes) > 0

    def reviewed_mount(
        observed_root: Path,
        device: int,
    ) -> tuple[frozenset[str], str]:
        assert observed_root == root
        assert device == root.stat().st_dev
        return _REVIEWED_MOUNT_OPTIONS, "ext4"

    monkeypatch.setattr(worker_slot_module, "_mount_details", reviewed_mount)
    payload = _policy_payload(root=str(root))
    payload.update(
        {
            "maximum_total_bytes": total_bytes,
            "minimum_available_bytes": available_bytes,
            "maximum_total_inodes": total_inodes,
            "minimum_available_inodes": available_inodes,
        }
    )
    policy = PdfWorkerSlotPolicy.model_validate(payload, strict=True)

    validated = validate_quota_bound_staging_root(policy)

    assert validated == QuotaBoundStagingRoot(path=root, policy=policy)


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"filesystem_type": "xfs"}, "filesystem type"),
        ({"mount_options": frozenset({"rw", "nodev", "nosuid"})}, "mount options"),
        ({"total_bytes": _SLOT_TOTAL_BYTES - 1}, "total byte"),
        ({"available_bytes": _SLOT_MINIMUM_AVAILABLE_BYTES - 1}, "byte headroom"),
        ({"total_inodes": _SLOT_TOTAL_INODES - 1}, "total inode"),
        ({"available_inodes": _SLOT_MINIMUM_AVAILABLE_INODES - 1}, "inode headroom"),
    ],
)
def test_quota_validation_rejects_every_policy_observation_mismatch(
    update: dict[str, object],
    message: str,
) -> None:
    """Catch omission of any byte, inode, filesystem, or mount-option check."""
    observed = _healthy_filesystem().model_copy(update=update)

    with pytest.raises(PdfWorkerSlotError, match=message):
        _ = validate_quota_bound_staging_root(
            _policy(),
            inspector=_FixedInspector(
                Path("/var/lib/nplg/pdf-worker-slot"),
                observed,
            ),
        )

    assert validate_quota_bound_staging_root(
        _policy(),
        inspector=_healthy_inspector(),
    ).path == Path("/var/lib/nplg/pdf-worker-slot")


def test_mountinfo_escape_decoder_accepts_only_complete_octal_sequences() -> None:
    """Catch mountpoint confusion through malformed or non-octal escapes."""
    assert _DECODE_MOUNTINFO_PATH("plain") == "plain"
    assert _DECODE_MOUNTINFO_PATH(r"/slot\040with\040space") == "/slot with space"
    assert _DECODE_MOUNTINFO_PATH(r"/slot\999name") == r"/slot\999name"
    assert _DECODE_MOUNTINFO_PATH("/slot\\") == "/slot\\"


def _mountinfo_line(
    mountpoint: str,
    *,
    device: str = "8:1",
) -> str:
    return (
        f"36 25 {device} / {mountpoint} rw,nodev,nosuid,noexec "
        "- ext4 /dev/worker-slot rw\n"
    )


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("malformed\n", "metadata is malformed"),
        (_mountinfo_line("/slot", device="8:2"), "device does not match"),
        (_mountinfo_line("/other"), "exactly one non-nested mount"),
        (
            _mountinfo_line("/slot") + _mountinfo_line("/slot/nested"),
            "exactly one non-nested mount",
        ),
        (
            _mountinfo_line("/slot") + _mountinfo_line("/slot"),
            "exactly one non-nested mount",
        ),
    ],
)
def test_mount_details_rejects_malformed_ambiguous_or_mismatched_tables(
    monkeypatch: pytest.MonkeyPatch,
    contents: str,
    message: str,
) -> None:
    """Catch mount-table ambiguity, nesting, or device substitution."""

    def read_mountinfo(
        path: Path,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> str:
        del encoding, errors
        assert path == Path("/proc/self/mountinfo")
        return contents

    monkeypatch.setattr(Path, "read_text", read_mountinfo)

    with pytest.raises(PdfWorkerSlotError, match=message):
        _ = _MOUNT_DETAILS(Path("/slot"), os.makedev(8, 1))


def test_mount_details_decodes_one_exact_reviewed_mount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch failure to bind the decoded root to its exact device and options."""

    def read_mountinfo(
        path: Path,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> str:
        del encoding, errors
        assert path == Path("/proc/self/mountinfo")
        return _mountinfo_line(r"/slot\040with\040space")

    monkeypatch.setattr(Path, "read_text", read_mountinfo)

    assert _MOUNT_DETAILS(
        Path("/slot with space"),
        os.makedev(8, 1),
    ) == (_REVIEWED_MOUNT_OPTIONS, "ext4")


def test_mount_details_fails_closed_when_proc_metadata_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch continuation after the authoritative mount table cannot be read."""

    def fail_mountinfo_read(
        path: Path,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> str:
        del path, encoding, errors
        message = "synthetic procfs failure"
        raise OSError(message)

    monkeypatch.setattr(Path, "read_text", fail_mountinfo_read)

    with pytest.raises(PdfWorkerSlotError, match="metadata is unavailable"):
        _ = _MOUNT_DETAILS(Path("/slot"), os.makedev(8, 1))
