# Copyright (c) 2026 David Osipov
"""Bounded properties for the public content-addressed storage seams."""

from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.storage import ContentAddressedStore

if TYPE_CHECKING:
    from collections.abc import Callable

    from hypothesis.strategies import SearchStrategy

_NAMESPACE_PREFIXES = {"documents": "doc", "renders": "rnd"}
_FILENAME_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ"
    " ._-"
)


def _safe_filename(stem: str) -> str:
    return f"file-{stem}.bin"


def _invalid_namespace(value: str) -> str:
    return f"invalid-{value}"


def _invalid_filename(value: tuple[str, str]) -> str:
    stem, separator = value
    return f"file-{stem}{separator}child.bin"


def _render_subtree(identity: bytes) -> str:
    return f"renders/rnd_{identity.hex()}"


_PAYLOAD_STRATEGY: SearchStrategy[bytes] = st.binary(max_size=512)
_SMALL_PAYLOAD_STRATEGY: SearchStrategy[bytes] = st.binary(max_size=128)
_FILENAME_STEM_STRATEGY: SearchStrategy[str] = st.text(
    alphabet=_FILENAME_ALPHABET,
    max_size=20,
)
_SAFE_FILENAME_STRATEGY: SearchStrategy[str] = _FILENAME_STEM_STRATEGY.map(
    _safe_filename
)
_NAMESPACE_STRATEGY: SearchStrategy[str] = st.sampled_from(tuple(_NAMESPACE_PREFIXES))
_INVALID_NAMESPACE_STRATEGY: SearchStrategy[str] = st.one_of(
    st.sampled_from(("", "../documents", "documents/child", "DOCUMENTS")),
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-",
        max_size=20,
    ).map(_invalid_namespace),
)
_INVALID_FILENAME_STRATEGY: SearchStrategy[str] = st.one_of(
    st.sampled_from(("", ".", "..", "/absolute.bin")),
    st.tuples(
        _FILENAME_STEM_STRATEGY,
        st.sampled_from(("/", "\\", "\x00")),
    ).map(_invalid_filename),
)
_QUOTA_STRATEGY: SearchStrategy[int] = st.integers(min_value=1, max_value=256)
_BYTE_STRATEGY: SearchStrategy[int] = st.integers(min_value=0, max_value=255)
_CHUNKS_STRATEGY: SearchStrategy[list[bytes]] = st.lists(
    st.binary(max_size=32),
    max_size=6,
)
_RENDER_IDENTITY_STRATEGY: SearchStrategy[bytes] = st.binary(
    min_size=16,
    max_size=16,
)

_GIVEN_ARTIFACT = cast(
    "Callable[[Callable[[bytes, str, str], None]], Callable[[], None]]",
    given(
        payload=_PAYLOAD_STRATEGY,
        filename=_SAFE_FILENAME_STRATEGY,
        namespace=_NAMESPACE_STRATEGY,
    ),
)


@_GIVEN_ARTIFACT
def test_content_identity_is_deterministic_and_independent_of_filename(
    payload: bytes,
    filename: str,
    namespace: str,
) -> None:
    digest = hashlib.sha256(payload).hexdigest()
    alternate_filename = f"copy-{filename}"
    with TemporaryDirectory(prefix="nplg-storage-property-") as directory:
        root = Path(directory)
        store = ContentAddressedStore(root, max_bytes=max(1, len(payload) * 2))

        first = store.put_bytes(
            payload,
            namespace=namespace,
            filename=filename,
            media_type="application/octet-stream",
        )
        alternate = store.put_bytes(
            payload,
            namespace=namespace,
            filename=alternate_filename,
            media_type="application/octet-stream",
        )
        repeated = store.put_bytes(
            payload,
            namespace=namespace,
            filename=filename,
            media_type="application/octet-stream",
        )

        expected_id = f"{_NAMESPACE_PREFIXES[namespace]}_{digest}"
        assert first == repeated
        assert first.object_id == expected_id
        assert alternate.object_id == expected_id
        assert first.sha256 == alternate.sha256 == digest
        assert first.size == alternate.size == len(payload)
        assert first.relative_path == f"{namespace}/{expected_id}/{filename}"
        assert alternate.relative_path == (
            f"{namespace}/{expected_id}/{alternate_filename}"
        )
        assert first.absolute_path.read_bytes() == payload
        assert alternate.absolute_path.read_bytes() == payload
        assert first.absolute_path.parent == alternate.absolute_path.parent
        assert not tuple(store.staging_dir.iterdir())


_GIVEN_INVALID_NAMESPACE = cast(
    "Callable[[Callable[[str], None]], Callable[[], None]]",
    given(namespace=_INVALID_NAMESPACE_STRATEGY),
)


@_GIVEN_INVALID_NAMESPACE
def test_unapproved_namespaces_never_publish_an_artifact(namespace: str) -> None:
    with TemporaryDirectory(prefix="nplg-storage-property-") as directory:
        store = ContentAddressedStore(Path(directory), max_bytes=1)

        with pytest.raises(AppError) as captured:
            _ = store.put_bytes(
                b"x",
                namespace=namespace,
                filename="source.bin",
                media_type="application/octet-stream",
            )

        assert captured.value.code is ErrorCode.INVALID_INPUT
        assert store.used_bytes == 0
        assert store.reserved_bytes == 0
        assert not tuple(store.staging_dir.iterdir())


_GIVEN_INVALID_FILENAME = cast(
    "Callable[[Callable[[str], None]], Callable[[], None]]",
    given(filename=_INVALID_FILENAME_STRATEGY),
)


@_GIVEN_INVALID_FILENAME
def test_unsafe_filenames_never_publish_an_artifact(filename: str) -> None:
    with TemporaryDirectory(prefix="nplg-storage-property-") as directory:
        store = ContentAddressedStore(Path(directory), max_bytes=1)

        with pytest.raises(AppError) as captured:
            _ = store.put_bytes(
                b"x",
                namespace="documents",
                filename=filename,
                media_type="application/octet-stream",
            )

        assert captured.value.code is ErrorCode.INVALID_INPUT
        assert store.used_bytes == 0
        assert store.reserved_bytes == 0
        assert not tuple(store.staging_dir.iterdir())


_GIVEN_QUOTA = cast(
    "Callable[[Callable[[int, int], None]], Callable[[], None]]",
    given(limit=_QUOTA_STRATEGY, fill=_BYTE_STRATEGY),
)


@_GIVEN_QUOTA
def test_exact_quota_is_accepted_and_one_more_byte_is_rejected(
    limit: int,
    fill: int,
) -> None:
    accepted = bytes((fill,)) * limit
    rejected = bytes((fill ^ 0xFF,))
    with TemporaryDirectory(prefix="nplg-storage-property-") as directory:
        store = ContentAddressedStore(Path(directory), max_bytes=limit)
        artifact = store.put_bytes(
            accepted,
            namespace="documents",
            filename="source.bin",
            media_type="application/octet-stream",
        )

        with pytest.raises(AppError) as captured:
            _ = store.put_bytes(
                rejected,
                namespace="renders",
                filename="overflow.bin",
                media_type="application/octet-stream",
            )

        assert captured.value.code is ErrorCode.CACHE_FULL
        assert artifact.absolute_path.read_bytes() == accepted
        assert store.used_bytes == limit
        assert store.reserved_bytes == 0
        assert not tuple(store.staging_dir.iterdir())


_GIVEN_CHUNKS = cast(
    "Callable[[Callable[[list[bytes]], None]], Callable[[], None]]",
    given(chunks=_CHUNKS_STRATEGY),
)


@_GIVEN_CHUNKS
def test_uncommitted_staging_is_always_cleaned_up(chunks: list[bytes]) -> None:
    total = sum(map(len, chunks))
    with TemporaryDirectory(prefix="nplg-storage-property-") as directory:
        store = ContentAddressedStore(Path(directory), max_bytes=max(1, total))

        with store.stage(suffix=".bin") as staged:
            for chunk in chunks:
                assert staged.write(chunk) == len(chunk)

        assert store.used_bytes == 0
        assert store.reserved_bytes == 0
        assert not tuple(store.staging_dir.iterdir())


_GIVEN_RENDER_ROLLBACK = cast(
    "Callable[[Callable[[bytes, bytes], None]], Callable[[], None]]",
    given(identity=_RENDER_IDENTITY_STRATEGY, payload=_SMALL_PAYLOAD_STRATEGY),
)


@_GIVEN_RENDER_ROLLBACK
def test_incomplete_render_transaction_rollback_removes_every_artifact(
    identity: bytes,
    payload: bytes,
) -> None:
    subtree = _render_subtree(identity)
    relative_asset = f"{subtree}/partial.bin"
    with TemporaryDirectory(prefix="nplg-storage-property-") as directory:
        root = Path(directory)
        store = ContentAddressedStore(root, max_bytes=max(1, len(payload)))
        transaction = store.begin_render_transaction(
            subtree,
            completion_file="manifest.json",
        )
        _ = store.put_render_bytes(relative_asset, payload)
        assert store.resolve_asset(relative_asset).read_bytes() == payload

        transaction.rollback()

        assert not root.joinpath(*subtree.split("/")).exists()
        assert store.used_bytes == 0
        assert store.reserved_bytes == 0
        assert not tuple(store.staging_dir.iterdir())
