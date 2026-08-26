# Copyright (c) 2026 David Osipov
"""Deterministic concurrency regressions for render lifecycle atomicity."""

from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from threading import Event, Lock, RLock, Thread, get_ident
from typing import TYPE_CHECKING, Protocol, Self, cast

import pytest

import nplg_mcp.storage as storage_module
from nplg_mcp.errors import AppError
from nplg_mcp.storage_lifecycle import RetentionClockSample
from tests.helpers.lease_store import lease_barrier_store

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from types import TracebackType

    from nplg_mcp.storage import ContentAddressedStore
    from nplg_mcp.storage_lifecycle import (
        PruneReport,
        RetentionPolicy,
        StorageCapacity,
    )

_SYNC_TIMEOUT_SECONDS = 2.0
_LOCK_PROBE_SECONDS = 0.1
_EXPECTED_CAPACITY_SAMPLES = 2
_FOREIGN_CONTEXT_ERROR = "render transaction belongs to another execution context"


class _RenderTransactionProtocol(Protocol):
    """Expose only the terminal transaction operations exercised by this test."""

    @property
    def complete(self) -> bool: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def reset(self) -> None: ...

    def stage(self, *, suffix: str = "") -> _StagedRenderWriterProtocol: ...


class _StagedRenderWriterProtocol(Protocol):
    """Narrow transaction-scoped writer used by the atomicity tests."""

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...

    def write(self, data: bytes) -> int: ...

    def commit_render(self, relative_path: str) -> tuple[str, str]: ...


class _RenderDestinationValidator(Protocol):
    """Typed view of the defensive transaction-destination guard."""

    def __call__(
        self,
        destination: Path,
        transaction_subtree: Path | None,
        transaction_token: object | None,
    ) -> None: ...


def _render_destination_validator() -> _RenderDestinationValidator:
    attribute = "_require_render_transaction_destination"
    return cast(
        "_RenderDestinationValidator",
        getattr(storage_module.ContentAddressedStore, attribute),
    )


@dataclass(frozen=True, slots=True)
class _ExpiredRenderTransaction:
    """Bind one real expired render to its active prune-protected transaction."""

    store: ContentAddressedStore
    policy: RetentionPolicy
    clock: RetentionClockSample
    subtree: str
    manifest: Path
    transaction: _RenderTransactionProtocol


class _ForeignCleanupError(RuntimeError):
    """Distinguish the operation failure that drives foreign-thread cleanup."""


class _CoordinatedQuotaLock:
    """Expose whether prune can enter the quota lock at the validation barrier."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = Lock()
        self._armed = False
        self._prune_thread_id: int | None = None
        self._prune_acquired: bool | None = None
        self._validation_observed = Event()
        self._release_validation = Event()
        self._prune_decided = Event()
        self._prune_finished = Event()

    def arm(self) -> None:
        self._armed = True

    def identify_prune_thread(self) -> None:
        self._prune_thread_id = get_ident()

    def pause_after_completion_validation(self) -> None:
        self._validation_observed.set()
        if not self._release_validation.wait(_SYNC_TIMEOUT_SECONDS):
            message = "completion-validation barrier was not released"
            raise TimeoutError(message)

    def wait_until_completion_validated(self) -> bool:
        return self._validation_observed.wait(_SYNC_TIMEOUT_SECONDS)

    def wait_until_prune_lock_decided(self) -> bool:
        return self._prune_decided.wait(_SYNC_TIMEOUT_SECONDS)

    @property
    def prune_acquired_during_validation(self) -> bool:
        if self._prune_acquired is None:
            message = "prune lock decision is unavailable"
            raise RuntimeError(message)
        return self._prune_acquired

    def finish_prune(self) -> None:
        self._prune_finished.set()

    def wait_until_prune_finished(self) -> bool:
        return self._prune_finished.wait(_SYNC_TIMEOUT_SECONDS)

    def release_completion_validation(self) -> None:
        self._release_validation.set()

    def acquire(self) -> bool:
        if self._armed and get_ident() == self._prune_thread_id:
            acquired = self._lock.acquire(blocking=False)
            self._prune_acquired = acquired
            self._prune_decided.set()
            if acquired:
                return True
        return self._lock.acquire()

    def release(self) -> None:
        self._lock.release()

    def __enter__(self) -> object:
        _ = self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
        /,
    ) -> None:
        del exc_type, exc_value, traceback
        self.release()


class _TransactionPruneRace:
    """Run the exact completion-validation/prune interleaving to completion."""

    def __init__(
        self,
        *,
        store: ContentAddressedStore,
        policy: RetentionPolicy,
        clock: RetentionClockSample,
        render_id: str,
        quota_lock: _CoordinatedQuotaLock,
    ) -> None:
        super().__init__()
        self._store = store
        self._policy = policy
        self._clock = clock
        self._render_id = render_id
        self._quota_lock = quota_lock
        self._transaction_ready = Event()
        self._release_transaction = Event()

    def _prune_at_validation_barrier(self) -> PruneReport:
        self._quota_lock.identify_prune_thread()
        try:
            return self._store.prune(self._policy, clock=self._clock)
        finally:
            self._quota_lock.finish_prune()

    def _hold_transaction_on_owner_thread(self) -> bool:
        transaction = self._store.begin_render_transaction(
            f"renders/{self._render_id}",
            completion_file="manifest.json",
        )
        self._transaction_ready.set()
        try:
            if not self._release_transaction.wait(_SYNC_TIMEOUT_SECONDS):
                message = "render transaction was not released"
                raise TimeoutError(message)
            return transaction.complete
        finally:
            transaction.rollback()

    def run(self) -> tuple[bool, PruneReport]:
        with ThreadPoolExecutor(max_workers=2) as executor:
            begin_future = executor.submit(self._hold_transaction_on_owner_thread)
            try:
                assert self._quota_lock.wait_until_completion_validated()
                prune_future = executor.submit(self._prune_at_validation_barrier)
                assert self._quota_lock.wait_until_prune_lock_decided()
                if self._quota_lock.prune_acquired_during_validation:
                    assert self._quota_lock.wait_until_prune_finished()
                self._quota_lock.release_completion_validation()
                assert self._transaction_ready.wait(_SYNC_TIMEOUT_SECONDS)
                report = prune_future.result(timeout=_SYNC_TIMEOUT_SECONDS)
            finally:
                self._quota_lock.release_completion_validation()
                self._release_transaction.set()
            complete = begin_future.result(timeout=_SYNC_TIMEOUT_SECONDS)
        return complete, report


def _publish_expired_render(
    store: ContentAddressedStore,
    policy: RetentionPolicy,
    clock: RetentionClockSample,
) -> tuple[str, Path]:
    render_id = "rnd_" + "a" * 32
    relative_manifest = f"renders/{render_id}/manifest.json"
    _ = store.put_render_bytes(relative_manifest, b"{}")
    manifest = store.root / relative_manifest
    expired_timestamp = clock.utc_now.timestamp() - policy.maximum_age_seconds - 1.0
    os.utime(
        manifest.parent,
        (expired_timestamp, expired_timestamp),
        follow_symlinks=False,
    )
    return render_id, manifest


def _open_expired_transaction(tmp_path: Path) -> _ExpiredRenderTransaction:
    store, policy, clock = lease_barrier_store(tmp_path)
    render_id, manifest = _publish_expired_render(store, policy, clock)
    subtree = f"renders/{render_id}"
    transaction = store.begin_render_transaction(
        subtree,
        completion_file="manifest.json",
    )
    return _ExpiredRenderTransaction(
        store=store,
        policy=policy,
        clock=clock,
        subtree=subtree,
        manifest=manifest,
        transaction=transaction,
    )


def _reject_foreign_operation(operation: Callable[[], None]) -> RuntimeError:
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(operation)
        with pytest.raises(RuntimeError, match=_FOREIGN_CONTEXT_ERROR) as raised:
            _ = future.result(timeout=_SYNC_TIMEOUT_SECONDS)
    return raised.value


def _set_transaction_complete(
    transaction: _RenderTransactionProtocol,
    *,
    value: bool,
) -> None:
    object.__setattr__(transaction, "complete", value)


def _assert_thread_finished(
    event: Event,
    thread: Thread,
    *,
    message: str,
) -> None:
    assert event.wait(_SYNC_TIMEOUT_SECONDS), message
    thread.join(timeout=_SYNC_TIMEOUT_SECONDS)
    assert not thread.is_alive()


def _assert_transaction_remains_prune_protected(
    fixture: _ExpiredRenderTransaction,
) -> None:
    report = fixture.store.prune(fixture.policy, clock=fixture.clock)

    assert report.freed_objects == 0
    assert report.retained_leased_objects == 1
    assert fixture.manifest.is_file()


def _assert_render_stripe_reusable_after_owner_close(
    fixture: _ExpiredRenderTransaction,
) -> None:
    completed = Event()
    failures: list[Exception] = []

    def reopen_and_rollback() -> None:
        try:
            transaction = fixture.store.begin_render_transaction(
                fixture.subtree,
                completion_file="manifest.json",
            )
            transaction.rollback()
        except (AppError, OSError, RuntimeError, ValueError) as exc:
            failures.append(exc)
        finally:
            completed.set()

    thread = Thread(target=reopen_and_rollback, daemon=True)
    thread.start()
    assert completed.wait(_SYNC_TIMEOUT_SECONDS), "render lock stripe remained stranded"
    thread.join(timeout=_SYNC_TIMEOUT_SECONDS)
    assert not thread.is_alive()
    if failures:
        message = "the released render lock stripe could not be reused"
        raise AssertionError(message) from failures[0]

    report = fixture.store.prune(fixture.policy, clock=fixture.clock)
    assert report.freed_objects == 1
    assert not fixture.manifest.exists()


def _install_completion_barrier(
    monkeypatch: pytest.MonkeyPatch,
    quota_lock: _CoordinatedQuotaLock,
    manifest: Path,
) -> None:
    def controlled_completion_exists(completion: Path) -> bool:
        assert completion == manifest
        exists = completion.is_file()
        quota_lock.pause_after_completion_validation()
        return exists

    monkeypatch.setattr(
        storage_module,
        "_render_completion_exists",
        controlled_completion_exists,
    )


def test_begin_render_transaction_atomically_leases_validated_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prune must not delete a completion between validation and lease entry."""
    quota_lock = _CoordinatedQuotaLock()
    real_rlock = RLock
    lock_calls = 0

    def coordinated_accounting_lock() -> object:
        nonlocal lock_calls
        lock_calls += 1
        if lock_calls == 1:
            return quota_lock
        return real_rlock()

    monkeypatch.setattr(storage_module, "RLock", coordinated_accounting_lock)
    store, policy, clock = lease_barrier_store(tmp_path)
    render_id, manifest = _publish_expired_render(store, policy, clock)
    _install_completion_barrier(monkeypatch, quota_lock, manifest)
    quota_lock.arm()
    transaction_was_complete, report = _TransactionPruneRace(
        store=store,
        policy=policy,
        clock=clock,
        render_id=render_id,
        quota_lock=quota_lock,
    ).run()

    assert transaction_was_complete is True
    assert report.freed_objects == 0
    assert report.retained_leased_objects == 1
    assert report.status == "satisfied"
    assert manifest.is_file()

    released_report = store.prune(
        policy,
        clock=clock,
    )

    assert released_report.freed_objects == 1
    assert not manifest.exists()


def test_foreign_commit_cannot_close_or_expose_render_transaction(
    tmp_path: Path,
) -> None:
    fixture = _open_expired_transaction(tmp_path)

    _ = _reject_foreign_operation(fixture.transaction.commit)
    _assert_transaction_remains_prune_protected(fixture)
    fixture.transaction.commit()
    _assert_render_stripe_reusable_after_owner_close(fixture)


def test_foreign_rollback_cannot_close_or_expose_render_transaction(
    tmp_path: Path,
) -> None:
    fixture = _open_expired_transaction(tmp_path)

    _ = _reject_foreign_operation(fixture.transaction.rollback)
    _assert_transaction_remains_prune_protected(fixture)
    fixture.transaction.rollback()
    _assert_render_stripe_reusable_after_owner_close(fixture)


def test_foreign_exception_cleanup_cannot_close_or_expose_transaction(
    tmp_path: Path,
) -> None:
    fixture = _open_expired_transaction(tmp_path)

    def rollback_during_exception_cleanup() -> None:
        try:
            message = "foreign operation failed"
            raise _ForeignCleanupError(message)
        finally:
            fixture.transaction.rollback()

    rejected = _reject_foreign_operation(rollback_during_exception_cleanup)

    assert isinstance(rejected.__context__, _ForeignCleanupError)
    _assert_transaction_remains_prune_protected(fixture)
    fixture.transaction.rollback()
    _assert_render_stripe_reusable_after_owner_close(fixture)


def test_foreign_reset_cannot_mutate_or_expose_render_transaction(
    tmp_path: Path,
) -> None:
    fixture = _open_expired_transaction(tmp_path)

    _ = _reject_foreign_operation(fixture.transaction.reset)

    assert fixture.transaction.complete is True
    _assert_transaction_remains_prune_protected(fixture)
    fixture.transaction.commit()
    _assert_render_stripe_reusable_after_owner_close(fixture)


@pytest.mark.asyncio
async def test_foreign_async_task_cannot_mutate_or_expose_render_transaction(
    tmp_path: Path,
) -> None:
    fixture = _open_expired_transaction(tmp_path)

    async def reset_from_foreign_task() -> None:
        fixture.transaction.reset()

    with pytest.raises(RuntimeError, match=_FOREIGN_CONTEXT_ERROR):
        await asyncio.create_task(reset_from_foreign_task())

    assert fixture.transaction.complete is True
    _assert_transaction_remains_prune_protected(fixture)
    fixture.transaction.commit()
    _assert_render_stripe_reusable_after_owner_close(fixture)


def test_nested_transaction_for_same_render_is_rejected_without_lease_leak(
    tmp_path: Path,
) -> None:
    fixture = _open_expired_transaction(tmp_path)

    with pytest.raises(RuntimeError, match="render transaction is already active"):
        _ = fixture.store.begin_render_transaction(
            fixture.subtree,
            completion_file="manifest.json",
        )

    _assert_transaction_remains_prune_protected(fixture)
    fixture.transaction.commit()
    _assert_render_stripe_reusable_after_owner_close(fixture)


def test_foreign_thread_cannot_mutate_transaction_completion_state(
    tmp_path: Path,
) -> None:
    fixture = _open_expired_transaction(tmp_path)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            _set_transaction_complete,
            fixture.transaction,
            value=False,
        )
        with pytest.raises(AttributeError):
            _ = future.result(timeout=_SYNC_TIMEOUT_SECONDS)

    assert fixture.transaction.complete is True
    fixture.transaction.commit()
    _assert_render_stripe_reusable_after_owner_close(fixture)


@pytest.mark.asyncio
async def test_foreign_async_task_cannot_mutate_transaction_completion_state(
    tmp_path: Path,
) -> None:
    fixture = _open_expired_transaction(tmp_path)

    async def mutate_completion_state() -> None:
        _set_transaction_complete(fixture.transaction, value=False)

    with pytest.raises(AttributeError):
        await asyncio.create_task(mutate_completion_state())

    assert fixture.transaction.complete is True
    fixture.transaction.commit()
    _assert_render_stripe_reusable_after_owner_close(fixture)


def test_active_render_transaction_blocks_new_reader_until_owner_close(
    tmp_path: Path,
) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "e" * 32
    subtree = f"renders/{render_id}"
    relative_path = f"{subtree}/manifest.json"
    _ = store.put_render_bytes(relative_path, b"manifest")
    transaction = store.begin_render_transaction(
        subtree,
        completion_file="manifest.json",
    )

    with (
        pytest.raises(AppError, match="currently in use"),
        store.lease_asset(relative_path),
    ):
        pytest.fail("an active render transaction exposed a new reader")

    transaction.commit()
    with store.lease_asset(relative_path) as leased_path:
        assert leased_path.read_bytes() == b"manifest"


@pytest.mark.parametrize("operation", ["put", "replace"])
def test_active_render_transaction_rejects_unscoped_render_mutation(
    tmp_path: Path,
    operation: str,
) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "f" * 32
    subtree = f"renders/{render_id}"
    manifest_path = f"{subtree}/manifest.json"
    index_path = f"{subtree}/resources/index.json"
    _ = store.put_render_bytes(manifest_path, b"manifest")
    _, original_digest = store.put_render_bytes(index_path, b"old-index")
    transaction = store.begin_render_transaction(
        subtree,
        completion_file="manifest.json",
    )
    mutation: Callable[[], object]
    if operation == "put":
        mutation = partial(
            store.put_render_bytes,
            f"{subtree}/page-0001.jpg",
            b"page",
        )
    else:
        mutation = partial(
            store.replace_render_bytes_if_matches,
            index_path,
            b"new-index",
            expected_sha256=original_digest,
        )

    with pytest.raises(AppError, match="currently in use"):
        _ = mutation()

    transaction.commit()


def test_transaction_scoped_writer_publishes_complete_render(
    tmp_path: Path,
) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "1" * 32
    subtree = f"renders/{render_id}"
    page_path = f"{subtree}/page-0001.jpg"
    manifest_path = f"{subtree}/manifest.json"
    transaction = store.begin_render_transaction(
        subtree,
        completion_file="manifest.json",
    )
    try:
        with transaction.stage(suffix=".jpg") as staged:
            _ = staged.write(b"page")
            _ = staged.commit_render(page_path)
        with transaction.stage(suffix=".json") as staged:
            _ = staged.write(b"manifest")
            _ = staged.commit_render(manifest_path)
        transaction.commit()
    finally:
        transaction.rollback()

    assert store.resolve_asset(page_path).read_bytes() == b"page"
    assert store.resolve_asset(manifest_path).read_bytes() == b"manifest"


def test_foreign_thread_cannot_write_through_transaction_scoped_writer(
    tmp_path: Path,
) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "2" * 32
    subtree = f"renders/{render_id}"
    transaction = store.begin_render_transaction(
        subtree,
        completion_file="manifest.json",
    )
    try:
        with transaction.stage(suffix=".jpg") as writer:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(writer.write, b"foreign")
                with pytest.raises(RuntimeError, match=_FOREIGN_CONTEXT_ERROR):
                    _ = future.result(timeout=_SYNC_TIMEOUT_SECONDS)
            assert writer.write(b"owner") == len(b"owner")
            _ = writer.commit_render(f"{subtree}/page-0001.jpg")
        with transaction.stage(suffix=".json") as manifest:
            _ = manifest.write(b"manifest")
            _ = manifest.commit_render(f"{subtree}/manifest.json")
        transaction.commit()
    finally:
        transaction.rollback()

    assert store.resolve_asset(f"{subtree}/page-0001.jpg").read_bytes() == b"owner"


@pytest.mark.asyncio
async def test_foreign_async_task_cannot_write_transaction_scoped_writer(
    tmp_path: Path,
) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "3" * 32
    subtree = f"renders/{render_id}"
    transaction = store.begin_render_transaction(
        subtree,
        completion_file="manifest.json",
    )
    try:
        with transaction.stage(suffix=".jpg") as writer:

            async def write_from_foreign_task() -> None:
                _ = writer.write(b"foreign")

            with pytest.raises(RuntimeError, match=_FOREIGN_CONTEXT_ERROR):
                await asyncio.create_task(write_from_foreign_task())
    finally:
        transaction.rollback()


def test_owner_can_cleanup_scoped_writer_after_transaction_rollback(
    tmp_path: Path,
) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "4" * 32
    transaction = store.begin_render_transaction(
        f"renders/{render_id}",
        completion_file="manifest.json",
    )
    writer = transaction.stage(suffix=".jpg")
    _ = writer.__enter__()
    _ = writer.write(b"discarded")
    transaction.rollback()

    writer.__exit__(None, None, None)

    assert store.reserved_bytes == 0
    assert tuple(store.staging_dir.iterdir()) == ()


def test_closed_render_transaction_cannot_open_new_staged_writer(
    tmp_path: Path,
) -> None:
    """A closed transaction must not allocate another staging capability."""
    store = storage_module.ContentAddressedStore(tmp_path)
    transaction = store.begin_render_transaction(
        "renders/rnd_" + "5" * 32,
        completion_file="manifest.json",
    )
    transaction.rollback()

    with pytest.raises(RuntimeError, match="render transaction is already closed"):
        _ = transaction.stage(suffix=".jpg")

    assert tuple(store.staging_dir.iterdir()) == ()


def test_active_render_transaction_rejects_forged_mutation_capability(
    tmp_path: Path,
) -> None:
    """A complete-looking but foreign capability cannot publish into a live render."""
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "6" * 32
    subtree = f"renders/{render_id}"
    transaction = store.begin_render_transaction(
        subtree,
        completion_file="manifest.json",
    )
    try:
        with store.stage(
            suffix=".jpg",
            _transaction_token=object(),
            _transaction_guard=lambda: None,
            _transaction_cleanup_guard=lambda: None,
            _transaction_subtree=store.root / subtree,
        ) as staged:
            _ = staged.write(b"forged")
            with pytest.raises(
                RuntimeError,
                match="render transaction mutation authority is unavailable",
            ):
                _ = staged.commit_render(f"{subtree}/page-0001.jpg")
    finally:
        transaction.rollback()

    assert not (store.root / subtree / "page-0001.jpg").exists()


def test_unscoped_render_mutation_cannot_claim_transaction_subtree(
    tmp_path: Path,
) -> None:
    """A missing token may not be paired with transaction path authority."""
    require_destination = _render_destination_validator()

    with pytest.raises(
        RuntimeError,
        match="render transaction destination authority is invalid",
    ):
        require_destination(
            tmp_path / "renders" / "rnd_unscoped" / "page-0001.jpg",
            tmp_path / "renders" / "rnd_unscoped",
            None,
        )


@pytest.mark.parametrize(
    ("destination_kind", "expected_exception"),
    [
        ("missing_subtree", RuntimeError),
        ("outside_subtree", AppError),
        ("subtree_root", AppError),
    ],
)
def test_token_bound_render_mutation_requires_child_destination(
    tmp_path: Path,
    destination_kind: str,
    expected_exception: type[Exception],
) -> None:
    """A token is valid only for a non-root file beneath its exact subtree."""
    require_destination = _render_destination_validator()
    subtree = tmp_path / "renders" / "rnd_bound"
    if destination_kind == "outside_subtree":
        destination = tmp_path / "renders" / "rnd_other" / "page-0001.jpg"
        transaction_subtree: Path | None = subtree
    elif destination_kind == "subtree_root":
        destination = subtree
        transaction_subtree = subtree
    else:
        destination = subtree / "page-0001.jpg"
        transaction_subtree = None

    with pytest.raises(
        expected_exception,
        match=(
            "render transaction destination authority is invalid"
            if transaction_subtree is None
            else "Render asset path is outside its transaction subtree"
        ),
    ):
        require_destination(destination, transaction_subtree, object())


def test_stage_rejects_partially_supplied_transaction_authority(
    tmp_path: Path,
) -> None:
    """Staging refuses incomplete transaction capability bundles before allocation."""
    store = storage_module.ContentAddressedStore(tmp_path)

    with pytest.raises(
        RuntimeError,
        match="render transaction staging authority is invalid",
    ):
        _ = store.stage(_transaction_token=object())

    assert tuple(store.staging_dir.iterdir()) == ()


def test_lifecycle_alert_observer_can_read_store_without_deadlock(
    tmp_path: Path,
) -> None:
    store, policy, clock = lease_barrier_store(tmp_path)
    observer_entered = Event()
    observer_finished = Event()
    prune_finished = Event()
    reports: list[PruneReport] = []
    failures: list[Exception] = []
    untrusted_clock = RetentionClockSample(
        utc_now=clock.utc_now,
        monotonic_now=clock.monotonic_now,
        boot_id=clock.boot_id,
        synchronized=False,
    )

    def reentrant_observer(alert: object) -> None:
        del alert
        observer_entered.set()
        _ = store.lifecycle_admission_closed
        observer_finished.set()

    def prune_with_alert() -> None:
        try:
            reports.append(
                store.prune(
                    policy,
                    clock=untrusted_clock,
                )
            )
        except (AppError, OSError, RuntimeError, ValueError) as exc:
            failures.append(exc)
        finally:
            prune_finished.set()

    store.install_lifecycle_probes_for_test(alert_observer=reentrant_observer)
    thread = Thread(target=prune_with_alert, daemon=True)
    thread.start()

    assert observer_entered.wait(_SYNC_TIMEOUT_SECONDS)
    assert observer_finished.wait(_SYNC_TIMEOUT_SECONDS), (
        "lifecycle alert observer deadlocked while reading store state"
    )
    assert prune_finished.wait(_SYNC_TIMEOUT_SECONDS)
    thread.join(timeout=_SYNC_TIMEOUT_SECONDS)
    assert not thread.is_alive()
    assert failures == []
    assert len(reports) == 1
    assert reports[0].status == "unsatisfied"


def test_capacity_sampler_can_read_store_without_deadlock(tmp_path: Path) -> None:
    store, policy, clock = lease_barrier_store(tmp_path)
    original_capacity = store.lifecycle_capacity_for_test()
    sampler_entered = Event()
    sampler_finished = Event()
    prune_finished = Event()
    failures: list[Exception] = []
    reports: list[PruneReport] = []
    sample_count = 0

    def reentrant_capacity_sampler() -> StorageCapacity:
        nonlocal sample_count
        sampler_entered.set()
        _ = store.used_bytes
        sample_count += 1
        sampler_finished.set()
        return original_capacity

    def prune_with_reentrant_sampler() -> None:
        try:
            reports.append(store.prune(policy, clock=clock))
        except (AppError, OSError, RuntimeError, ValueError) as exc:
            failures.append(exc)
        finally:
            prune_finished.set()

    store.install_lifecycle_probes_for_test(capacity_sampler=reentrant_capacity_sampler)
    thread = Thread(target=prune_with_reentrant_sampler, daemon=True)
    thread.start()

    assert sampler_entered.wait(_SYNC_TIMEOUT_SECONDS)
    assert sampler_finished.wait(_SYNC_TIMEOUT_SECONDS), (
        "capacity sampler deadlocked while reading store state"
    )
    assert prune_finished.wait(_SYNC_TIMEOUT_SECONDS)
    thread.join(timeout=_SYNC_TIMEOUT_SECONDS)
    assert not thread.is_alive()
    assert failures == []
    assert len(reports) == 1
    assert reports[0].status == "satisfied"
    assert sample_count == _EXPECTED_CAPACITY_SAMPLES


def test_post_prune_capacity_sample_serializes_accounting_mutation(
    tmp_path: Path,
) -> None:
    store, policy, clock = lease_barrier_store(tmp_path)
    capacity = store.lifecycle_capacity_for_test()
    post_sample_entered = Event()
    release_post_sample = Event()
    prune_finished = Event()
    mutation_finished = Event()
    failures: list[Exception] = []
    reports: list[PruneReport] = []
    sample_count = 0

    def blocking_capacity_sampler() -> StorageCapacity:
        nonlocal sample_count
        sample_count += 1
        if sample_count == _EXPECTED_CAPACITY_SAMPLES:
            post_sample_entered.set()
            if not release_post_sample.wait(_SYNC_TIMEOUT_SECONDS):
                message = "post-prune capacity sample was not released"
                raise TimeoutError(message)
        return capacity

    def run_prune() -> None:
        try:
            reports.append(store.prune(policy, clock=clock))
        except (AppError, OSError, RuntimeError, ValueError) as exc:
            failures.append(exc)
        finally:
            prune_finished.set()

    def mutate_accounting() -> None:
        try:
            _ = store.put_bytes(
                b"concurrent",
                namespace="documents",
                filename="source.bin",
                media_type="application/octet-stream",
            )
        except (AppError, OSError, RuntimeError, ValueError) as exc:
            failures.append(exc)
        finally:
            mutation_finished.set()

    store.install_lifecycle_probes_for_test(capacity_sampler=blocking_capacity_sampler)
    prune_thread = Thread(target=run_prune, daemon=True)
    prune_thread.start()
    assert post_sample_entered.wait(_SYNC_TIMEOUT_SECONDS)
    mutation_thread = Thread(target=mutate_accounting, daemon=True)
    mutation_thread.start()
    try:
        assert not mutation_finished.wait(_LOCK_PROBE_SECONDS), (
            "accounting mutation passed the post-prune capacity sample"
        )
    finally:
        release_post_sample.set()
    _assert_thread_finished(
        prune_finished,
        prune_thread,
        message="prune did not finish after releasing its capacity sample",
    )
    _assert_thread_finished(
        mutation_finished,
        mutation_thread,
        message="accounting mutation did not resume after prune",
    )
    assert failures == []
    assert len(reports) == 1
    assert reports[0].status == "satisfied"


def test_explicit_render_deletion_preserves_active_asset_lease(
    tmp_path: Path,
) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "b" * 32
    subtree = f"renders/{render_id}"
    relative_path = f"{subtree}/manifest.json"
    _ = store.put_render_bytes(relative_path, b"manifest")

    with store.lease_asset(relative_path) as leased_path:
        with pytest.raises(AppError, match="currently in use"):
            _ = store.delete_render_subtree(subtree)
        assert leased_path.read_bytes() == b"manifest"

    assert store.delete_render_subtree(subtree) is True
    assert not leased_path.exists()


def test_render_replacement_preserves_active_asset_lease(tmp_path: Path) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "c" * 32
    relative_path = f"renders/{render_id}/resources/index.json"
    _, original_digest = store.put_render_bytes(relative_path, b"old-index")

    with store.lease_asset(relative_path) as leased_path:
        with pytest.raises(AppError, match="currently in use"):
            _ = store.replace_render_bytes_if_matches(
                relative_path,
                b"new-index",
                expected_sha256=original_digest,
            )
        assert leased_path.read_bytes() == b"old-index"

    _, replacement_digest = store.replace_render_bytes_if_matches(
        relative_path,
        b"new-index",
        expected_sha256=original_digest,
    )
    assert replacement_digest != original_digest
    assert leased_path.read_bytes() == b"new-index"


def test_transaction_reset_preserves_unrelated_active_asset_lease(
    tmp_path: Path,
) -> None:
    store = storage_module.ContentAddressedStore(tmp_path)
    render_id = "rnd_" + "d" * 32
    subtree = f"renders/{render_id}"
    relative_path = f"{subtree}/manifest.json"
    _ = store.put_render_bytes(relative_path, b"manifest")

    with store.lease_asset(relative_path) as leased_path:
        transaction = store.begin_render_transaction(
            subtree,
            completion_file="manifest.json",
        )
        assert transaction.complete is True
        with pytest.raises(AppError, match="currently in use"):
            transaction.reset()
        assert transaction.complete is True
        assert leased_path.read_bytes() == b"manifest"
        transaction.commit()

    assert store.delete_render_subtree(subtree) is True
