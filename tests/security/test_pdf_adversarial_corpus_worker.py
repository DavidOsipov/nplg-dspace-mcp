# Copyright (c) 2026 David Osipov
"""Execute every non-inert adversarial PDF corpus case in a real worker."""

from __future__ import annotations

import asyncio
import hashlib
import math
import os
import stat
import time
from pathlib import Path
from uuid import UUID

import pytest

from nplg_mcp.contracts import MonotonicDeadline
from nplg_mcp.errors import ErrorCode
from nplg_mcp.pdf_ipc import (
    InspectCommand,
    InspectParams,
    InspectPayload,
    PdfFailure,
    PdfSuccess,
)
from nplg_mcp.pdf_worker_client import SubprocessPdfExecutor
from nplg_mcp.storage import ContentAddressedStore
from tests.helpers.pdf_adversarial_corpus import (
    CorpusEntry,
    load_and_validate_corpus,
)

_ROOT = Path(__file__).resolve().parents[2]
_CORPUS_ROOT = _ROOT / "tests" / "fixtures" / "pdf" / "adversarial"
_MAX_PUBLIC_ERROR_MESSAGE_BYTES = 512
_PRIVATE_FILE_MODE = 0o600
_MANIFEST = load_and_validate_corpus(_CORPUS_ROOT)
_REJECTION_CASES = tuple(
    entry
    for entry in _MANIFEST.entries
    if entry.expected_behavior == "reject_invalid_document"
)
_BOUNDED_METADATA_CASES = tuple(
    entry
    for entry in _MANIFEST.entries
    if entry.expected_behavior == "accept_bounded_metadata"
)
_REUSE_CASES = tuple(
    entry
    for entry in _MANIFEST.entries
    if entry.expected_behavior == "reuse_without_mutation"
)
_INERT_CASES = tuple(
    entry
    for entry in _MANIFEST.entries
    if entry.expected_behavior == "inert_test_marker"
)


def _deadline() -> MonotonicDeadline:
    return MonotonicDeadline.after(10.0, clock=time.monotonic)


def _case_id(entry: CorpusEntry) -> str:
    return entry.case_id


def _stored_fixture(
    store: ContentAddressedStore,
    entry: CorpusEntry,
) -> tuple[str, Path, bytes]:
    source = _CORPUS_ROOT / entry.relative_path
    payload = source.read_bytes()
    artifact = store.put_bytes(
        payload,
        namespace="documents",
        filename=f"{entry.case_id}.pdf",
        media_type="application/pdf",
    )
    stored = store.resolve_asset(artifact.relative_path)
    return artifact.relative_path, stored, payload


async def _inspect(
    executor: SubprocessPdfExecutor,
    relative_path: str,
    *,
    request_number: int,
) -> PdfSuccess | PdfFailure:
    return await executor.execute(
        InspectCommand(
            request_id=UUID(int=request_number),
            operation="inspect",
            source_relative_path=relative_path,
            parameters=InspectParams(),
        ),
        deadline=_deadline(),
    )


def test_manifest_partitions_every_case_without_promoting_inert_markers() -> None:
    """Keep behavioral evidence complete without treating labels as payloads."""
    executed = {
        *(entry.case_id for entry in _REJECTION_CASES),
        *(entry.case_id for entry in _BOUNDED_METADATA_CASES),
        *(entry.case_id for entry in _REUSE_CASES),
    }

    assert executed == {
        entry.case_id
        for entry in _MANIFEST.entries
        if entry.expected_behavior != "inert_test_marker"
    }
    assert {entry.case_id for entry in _INERT_CASES} == {
        "crash-marker",
        "timeout-marker",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", _REJECTION_CASES, ids=_case_id)
async def test_real_worker_rejects_invalid_corpus_documents(
    tmp_path: Path,
    entry: CorpusEntry,
) -> None:
    """Invalid checked-in bytes must return only the bounded public failure."""
    store = ContentAddressedStore(tmp_path / "cache")
    relative_path, stored, original = _stored_fixture(store, entry)
    before = stored.stat()

    result = await _inspect(
        SubprocessPdfExecutor(store=store),
        relative_path,
        request_number=_MANIFEST.entries.index(entry) + 1,
    )

    assert isinstance(result, PdfFailure)
    assert result.payload.code is ErrorCode.INVALID_DOCUMENT
    assert 0 < len(result.payload.message) <= _MAX_PUBLIC_ERROR_MESSAGE_BYTES
    assert stored.read_bytes() == original
    after = stored.stat()
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entry",
    _BOUNDED_METADATA_CASES,
    ids=_case_id,
)
async def test_real_worker_accepts_only_bounded_corpus_metadata(
    tmp_path: Path,
    entry: CorpusEntry,
) -> None:
    """Deep or huge declarations may yield metadata but no render allocation."""
    store = ContentAddressedStore(tmp_path / "cache")
    relative_path, stored, original = _stored_fixture(store, entry)

    result = await _inspect(
        SubprocessPdfExecutor(store=store),
        relative_path,
        request_number=_MANIFEST.entries.index(entry) + 1,
    )

    assert isinstance(result, PdfSuccess)
    assert isinstance(result.payload, InspectPayload)
    inspection = result.payload.value
    assert inspection.source_sha256 == entry.sha256
    assert inspection.page_count == 1
    assert len(inspection.pages) == inspection.page_count
    assert all(
        page.width_points > 0
        and page.height_points > 0
        and math.isfinite(page.width_points)
        and math.isfinite(page.height_points)
        for page in inspection.pages
    )
    assert stored.read_bytes() == original
    assert not any((store.root / "renders").iterdir())


@pytest.mark.asyncio
async def test_real_worker_serializes_reuse_without_mutating_source(
    tmp_path: Path,
) -> None:
    """Concurrent callers reuse immutable bytes through the serialized worker."""
    (entry,) = _REUSE_CASES
    store = ContentAddressedStore(tmp_path / "cache")
    relative_path, stored, original = _stored_fixture(store, entry)
    before = stored.stat()
    executor = SubprocessPdfExecutor(store=store)

    first, second = await asyncio.gather(
        _inspect(executor, relative_path, request_number=101),
        _inspect(executor, relative_path, request_number=102),
    )

    assert isinstance(first, PdfSuccess)
    assert isinstance(second, PdfSuccess)
    assert isinstance(first.payload, InspectPayload)
    assert isinstance(second.payload, InspectPayload)
    assert first.payload.value == second.payload.value
    assert first.payload.value.source_sha256 == hashlib.sha256(original).hexdigest()
    after = stored.stat()
    assert stored.read_bytes() == original
    assert stat.S_IMODE(after.st_mode) == _PRIVATE_FILE_MODE
    assert after.st_nlink == 1
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )


@pytest.mark.asyncio
async def test_real_worker_staging_survives_a_restrictive_umask(
    tmp_path: Path,
) -> None:
    """Worker cache parents and source files must reach exact private modes."""
    (entry,) = _REUSE_CASES
    store = ContentAddressedStore(tmp_path / "cache")
    relative_path, stored, original = _stored_fixture(store, entry)
    executor = SubprocessPdfExecutor(store=store)

    previous_umask = os.umask(0o777)
    try:
        result = await _inspect(executor, relative_path, request_number=103)
    finally:
        _ = os.umask(previous_umask)

    assert isinstance(result, PdfSuccess)
    assert isinstance(result.payload, InspectPayload)
    assert result.payload.value.source_sha256 == entry.sha256
    assert stored.read_bytes() == original
