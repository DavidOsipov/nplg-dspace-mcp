# Copyright (c) 2026 David Osipov
"""Tests for the dedicated, filesystem-bounded PDF worker slot."""

from __future__ import annotations

import time
from pathlib import Path
from uuid import UUID

import pytest

from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.pdf_ipc import InspectCommand, InspectParams
from nplg_mcp.pdf_worker_client import UnixSocketPdfExecutor, WorkerStagingBinding
from nplg_mcp.pdf_worker_slot import (
    PdfWorkerSlotError,
    PdfWorkerSlotPolicy,
    WorkerSlotFilesystem,
    WorkerStagingQuota,
    load_pdf_worker_slot_policy,
    open_configured_root_fd,
    validate_quota_bound_staging_root,
)
from nplg_mcp.storage import ContentAddressedStore

_PROJECT_ROOT = Path(__file__).parents[2]
_SLOT_TOTAL_BYTES = 1_073_741_824
_SLOT_MINIMUM_AVAILABLE_BYTES = 805_306_368
_SLOT_TOTAL_INODES = 65_536
_SLOT_MINIMUM_AVAILABLE_INODES = 32_768


def _policy_payload(
    *, root: str = "/var/lib/nplg/pdf-worker-slot"
) -> dict[str, object]:
    """Return one fully typed reviewed worker-slot policy fixture."""
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


class _FixedFilesystemInspector:
    """Return a hand-checked filesystem observation for the tested slot."""

    def __init__(self, observed: WorkerSlotFilesystem) -> None:
        super().__init__()
        self.observed = observed

    def inspect(self, root: Path) -> WorkerSlotFilesystem:
        assert root == Path("/var/lib/nplg/pdf-worker-slot")
        return self.observed


class _SequencedFilesystemInspector:
    """Return separate startup and dispatch observations for one slot."""

    def __init__(self, root: Path, observations: list[WorkerSlotFilesystem]) -> None:
        super().__init__()
        self.root = root
        self.observations = observations

    def inspect(self, root: Path) -> WorkerSlotFilesystem:
        assert root == self.root
        if not self.observations:
            pytest.fail("worker slot was inspected more often than expected")
        return self.observations.pop(0)


def test_worker_slot_rejects_insufficient_inode_headroom_before_dispatch() -> None:
    """Catch a policy bypass that considers bytes but ignores inode exhaustion."""
    policy = PdfWorkerSlotPolicy.model_validate(_policy_payload())
    inspector = _FixedFilesystemInspector(
        WorkerSlotFilesystem(
            filesystem_type="ext4",
            mount_options=frozenset({"rw", "nodev", "nosuid", "noexec"}),
            total_bytes=1_073_741_824,
            available_bytes=805_306_368,
            total_inodes=65_536,
            available_inodes=32_767,
        )
    )

    with pytest.raises(PdfWorkerSlotError, match="available inode"):
        _ = validate_quota_bound_staging_root(policy, inspector=inspector)


def test_worker_slot_lease_rejects_a_concurrent_dispatch() -> None:
    """Catch a slot implementation that admits two writers to one hard quota."""
    policy = PdfWorkerSlotPolicy.model_validate(_policy_payload())
    inspector = _FixedFilesystemInspector(
        WorkerSlotFilesystem(
            filesystem_type="ext4",
            mount_options=frozenset({"rw", "nodev", "nosuid", "noexec"}),
            total_bytes=1_073_741_824,
            available_bytes=805_306_368,
            total_inodes=65_536,
            available_inodes=32_768,
        )
    )
    quota = WorkerStagingQuota(policy=policy, inspector=inspector)

    with quota.lease() as root:
        assert root.path == Path("/var/lib/nplg/pdf-worker-slot")
        with pytest.raises(PdfWorkerSlotError, match="already leased"):
            _ = quota.lease()


def test_worker_slot_quota_rejects_bad_mount_during_startup() -> None:
    """Catch deferred validation that would start private-full without a quota."""
    policy = PdfWorkerSlotPolicy.model_validate(_policy_payload())
    inspector = _FixedFilesystemInspector(
        WorkerSlotFilesystem(
            filesystem_type="ext4",
            mount_options=frozenset({"rw", "nodev", "nosuid", "noexec"}),
            total_bytes=1_073_741_824,
            available_bytes=805_306_368,
            total_inodes=65_536,
            available_inodes=1,
        )
    )

    with pytest.raises(PdfWorkerSlotError, match="available inode"):
        _ = WorkerStagingQuota(policy=policy, inspector=inspector)


def test_worker_slot_policy_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    """Catch an ambiguous policy where a parser could choose the weaker root."""
    policy_path = tmp_path / "pdf-worker-slot-policy.json"
    _ = policy_path.write_text(
        """
{
  "version": 1,
  "root": "/var/lib/nplg/pdf-worker-slot",
  "root": "/tmp/attacker-slot",
  "filesystem_type": "ext4",
  "maximum_total_bytes": 1073741824,
  "minimum_available_bytes": 805306368,
  "maximum_total_inodes": 65536,
  "minimum_available_inodes": 32768,
  "mount_options": ["rw", "nodev", "nosuid", "noexec"],
  "concurrency": 1
}
""",
        encoding="utf-8",
    )

    with pytest.raises(PdfWorkerSlotError, match="duplicate"):
        _ = load_pdf_worker_slot_policy(policy_path)


def test_unix_worker_rejects_the_authoritative_store_as_its_slot(
    tmp_path: Path,
) -> None:
    """Catch a private worker that can write directly into published artifacts."""
    store = ContentAddressedStore(tmp_path / "cache")

    with pytest.raises(ValueError, match="dedicated"):
        _ = UnixSocketPdfExecutor(
            store=store,
            socket_path=tmp_path / "worker.sock",
            staging=WorkerStagingBinding(root=store.root),
        )


def test_local_worker_slot_construction_rejects_a_missing_policy(
    tmp_path: Path,
) -> None:
    """Exercise the missing-policy invariant below the production OAuth gate."""
    missing_policy = (tmp_path / "pdf-worker-slot-policy.json").resolve()

    with pytest.raises(PdfWorkerSlotError, match="cannot be opened safely"):
        _ = load_pdf_worker_slot_policy(missing_policy)


def test_checked_in_worker_slot_policy_keeps_the_reviewed_hard_limits() -> None:
    """Catch a policy edit that weakens the dedicated worker filesystem contract."""
    policy = load_pdf_worker_slot_policy(
        _PROJECT_ROOT / "deploy" / "pdf-worker-slot-policy.json"
    )

    assert policy.root == "/var/lib/nplg/pdf-worker-slot"
    assert policy.filesystem_type == "ext4"
    assert policy.maximum_total_bytes == _SLOT_TOTAL_BYTES
    assert policy.minimum_available_bytes == _SLOT_MINIMUM_AVAILABLE_BYTES
    assert policy.maximum_total_inodes == _SLOT_TOTAL_INODES
    assert policy.minimum_available_inodes == _SLOT_MINIMUM_AVAILABLE_INODES
    assert policy.mount_options == ("nodev", "noexec", "nosuid", "rw")
    assert policy.concurrency == 1


@pytest.mark.asyncio
async def test_unix_worker_revalidates_the_slot_before_staging_input(
    tmp_path: Path,
) -> None:
    """Catch dispatch that writes into a slot after inode headroom disappears."""
    slot = tmp_path / "slot"
    slot.mkdir()
    policy = PdfWorkerSlotPolicy.model_validate(_policy_payload(root=str(slot)))
    healthy = WorkerSlotFilesystem(
        filesystem_type="ext4",
        mount_options=frozenset({"rw", "nodev", "nosuid", "noexec"}),
        total_bytes=1_073_741_824,
        available_bytes=805_306_368,
        total_inodes=65_536,
        available_inodes=32_768,
    )
    exhaustion_update: dict[str, object] = {"available_inodes": 1}
    exhausted = healthy.model_copy(update=exhaustion_update)
    quota = WorkerStagingQuota(
        policy=policy,
        inspector=_SequencedFilesystemInspector(slot, [healthy, exhausted]),
    )
    store = ContentAddressedStore(tmp_path / "cache")
    artifact = store.put_bytes(
        b"%PDF-1.7\nslot-revalidation",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    executor = UnixSocketPdfExecutor(
        store=store,
        socket_path=tmp_path / "worker.sock",
        staging=WorkerStagingBinding(root=slot, quota=quota),
    )

    with pytest.raises(PdfWorkerSlotError, match="available inode"):
        _ = await executor.execute(
            InspectCommand(
                request_id=UUID(int=73),
                operation="inspect",
                source_relative_path=artifact.relative_path,
                parameters=InspectParams(),
            ),
            deadline=MonotonicDeadline(time.monotonic(), time.monotonic() + 5.0),
        )
    assert list(slot.iterdir()) == []


def test_configured_slot_root_open_rejects_a_symlink_replacement(
    tmp_path: Path,
) -> None:
    """Catch a time-of-check/time-of-use swap of the dedicated slot root."""
    target = tmp_path / "target"
    target.mkdir()
    replaced_root = tmp_path / "slot"
    replaced_root.symlink_to(target, target_is_directory=True)
    policy = PdfWorkerSlotPolicy.model_validate(
        _policy_payload(root=str(replaced_root))
    )

    with pytest.raises(PdfWorkerSlotError, match="directory"):
        _ = open_configured_root_fd(policy)
