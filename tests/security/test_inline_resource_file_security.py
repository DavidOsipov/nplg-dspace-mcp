# Copyright (c) 2026 David Osipov
"""Adversarial filesystem tests for bounded inline MCP resource reads."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Literal, cast

import pytest

import nplg_mcp.tools as tools_module
from nplg_mcp.config import HARD_MAX_INLINE_RESOURCE_BYTES
from nplg_mcp.errors import AppError

_FIFO_REJECTION_DEADLINE_SECONDS = 0.25
_FINAL_LSTAT_CALL = 2


def _private_file(tmp_path: Path, content: bytes = b"bounded-resource") -> Path:
    path = tmp_path / "resource.bin"
    _ = path.write_bytes(content)
    path.chmod(0o600)
    return path


def test_inline_resource_open_uses_all_required_secure_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing nonblocking/no-follow/close-on-exec flags must fail this test."""
    path = _private_file(tmp_path)
    real_open = os.open
    observed_flags: list[int] = []

    def recording_open(open_path: Path, flags: int) -> int:
        observed_flags.append(flags)
        return real_open(open_path, flags)

    monkeypatch.setattr(os, "open", recording_open)

    assert (
        tools_module.read_verified_inline_resource_file(
            path,
            expected_size=len(b"bounded-resource"),
        )
        == b"bounded-resource"
    )
    required = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    assert len(observed_flags) == 1
    assert observed_flags[0] & required == required


@pytest.mark.parametrize("missing_flag", ["O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"])
def test_inline_resource_open_fails_closed_without_required_os_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_flag: str,
) -> None:
    """A platform lacking any required secure-open primitive is unsupported."""
    path = _private_file(tmp_path)
    monkeypatch.delattr(os, missing_flag)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools_module.read_verified_inline_resource_file(
            path,
            expected_size=len(b"bounded-resource"),
        )


def test_inline_resource_accepts_exact_byte_cap(tmp_path: Path) -> None:
    content = b"x" * HARD_MAX_INLINE_RESOURCE_BYTES
    path = _private_file(tmp_path, content)

    result = tools_module.read_verified_inline_resource_file(
        path,
        expected_size=HARD_MAX_INLINE_RESOURCE_BYTES,
    )

    assert len(result) == HARD_MAX_INLINE_RESOURCE_BYTES
    assert result[:1] == b"x"
    assert result[-1:] == b"x"


@pytest.mark.parametrize("invalid_size", [True, False, 0, -1, "1", 1.0])
def test_inline_resource_rejects_noncanonical_expected_size(
    tmp_path: Path,
    invalid_size: object,
) -> None:
    path = _private_file(tmp_path, b"x")

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools_module.read_verified_inline_resource_file(
            path,
            expected_size=cast("int | None", invalid_size),
        )


def test_inline_resource_rejects_actual_oversize_before_os_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_file(tmp_path)
    with path.open("r+b") as stream:
        _ = stream.truncate(HARD_MAX_INLINE_RESOURCE_BYTES + 1)
    read_called = False

    def forbidden_read(descriptor: int, size: int) -> bytes:
        nonlocal read_called
        del descriptor, size
        read_called = True
        pytest.fail("oversize resource reached os.read")

    monkeypatch.setattr(os, "read", forbidden_read)

    with pytest.raises(AppError, match="bounded inline delivery limit"):
        _ = tools_module.read_verified_inline_resource_file(
            path,
            expected_size=None,
        )

    assert read_called is False


@pytest.mark.parametrize(
    "mutation",
    ["symlink", "hardlink", "mode", "owner", "group"],
)
def test_inline_resource_rejects_untrusted_file_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    path = _private_file(tmp_path)
    read_path = path
    if mutation == "symlink":
        read_path = tmp_path / "resource-link.bin"
        read_path.symlink_to(path)
    elif mutation == "hardlink":
        read_path = tmp_path / "resource-hardlink.bin"
        os.link(path, read_path)
    elif mutation == "mode":
        path.chmod(0o640)
    elif mutation == "owner":
        unexpected_owner = os.geteuid() + 1
        monkeypatch.setattr(os, "geteuid", lambda: unexpected_owner)
    else:
        unexpected_group = os.getegid() + 1
        monkeypatch.setattr(os, "getegid", lambda: unexpected_group)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools_module.read_verified_inline_resource_file(
            read_path,
            expected_size=len(b"bounded-resource"),
        )


def test_inline_resource_fifo_swap_is_nonblocking_and_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_file(tmp_path)
    real_open = os.open
    fifo_created = threading.Event()

    def swap_to_fifo(open_path: Path, flags: int) -> int:
        path.unlink()
        os.mkfifo(path, mode=0o600)
        fifo_created.set()
        return real_open(open_path, flags)

    monkeypatch.setattr(os, "open", swap_to_fifo)
    finished = threading.Event()
    outcomes: list[bytes | AppError] = []

    def read_swapped_fifo() -> None:
        try:
            outcomes.append(
                tools_module.read_verified_inline_resource_file(
                    path,
                    expected_size=len(b"bounded-resource"),
                )
            )
        except AppError as exc:
            outcomes.append(exc)
        finally:
            finished.set()

    reader = threading.Thread(target=read_swapped_fifo)
    reader.start()
    assert fifo_created.wait(1)
    completed_promptly = finished.wait(_FIFO_REJECTION_DEADLINE_SECONDS)
    writer_descriptor: int | None = None
    try:
        if not completed_promptly:
            writer_descriptor = real_open(path, os.O_RDWR | os.O_NONBLOCK)
            assert finished.wait(1)
    finally:
        if writer_descriptor is not None:
            os.close(writer_descriptor)
        reader.join(timeout=1)

    assert completed_promptly
    assert not reader.is_alive()
    assert len(outcomes) == 1
    failure = outcomes[0]
    assert isinstance(failure, AppError)
    assert "integrity verification failed" in str(failure)


def test_inline_resource_rejects_short_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_file(tmp_path)

    def short_read(descriptor: int, size: int) -> bytes:
        del descriptor, size
        return b""

    monkeypatch.setattr(os, "read", short_read)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools_module.read_verified_inline_resource_file(
            path,
            expected_size=len(b"bounded-resource"),
        )


def test_inline_resource_rejects_growth_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_file(tmp_path)
    real_read = os.read
    read_calls = 0

    def grow_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal read_calls
        content = real_read(descriptor, size)
        read_calls += 1
        if read_calls == 1:
            with path.open("ab") as stream:
                _ = stream.write(b"!")
        return content

    monkeypatch.setattr(os, "read", grow_after_first_read)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools_module.read_verified_inline_resource_file(
            path,
            expected_size=len(b"bounded-resource"),
        )


def test_inline_resource_rejects_post_read_namespace_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_file(tmp_path)
    real_lstat = Path.lstat
    target_lstats = 0

    def replace_before_final_lstat(candidate: Path) -> os.stat_result:
        nonlocal target_lstats
        if candidate == path:
            target_lstats += 1
            if target_lstats == _FINAL_LSTAT_CALL:
                path.unlink()
                _ = path.write_bytes(b"bounded-resource")
                path.chmod(0o600)
        return real_lstat(candidate)

    monkeypatch.setattr(Path, "lstat", replace_before_final_lstat)

    with pytest.raises(AppError, match="integrity verification failed"):
        _ = tools_module.read_verified_inline_resource_file(
            path,
            expected_size=len(b"bounded-resource"),
        )


@pytest.mark.parametrize("outcome", ["success", "error"])
def test_inline_resource_closes_descriptor_on_every_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: Literal["success", "error"],
) -> None:
    path = _private_file(tmp_path)
    real_open = os.open
    opened_descriptors: list[int] = []

    def recording_open(open_path: Path, flags: int) -> int:
        descriptor = real_open(open_path, flags)
        opened_descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(os, "open", recording_open)
    if outcome == "error":

        def failed_read(_descriptor: int, _size: int) -> bytes:
            return b""

        monkeypatch.setattr(os, "read", failed_read)
        with pytest.raises(AppError, match="integrity verification failed"):
            _ = tools_module.read_verified_inline_resource_file(
                path,
                expected_size=len(b"bounded-resource"),
            )
    else:
        assert (
            tools_module.read_verified_inline_resource_file(
                path,
                expected_size=len(b"bounded-resource"),
            )
            == b"bounded-resource"
        )

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError, match="Bad file descriptor"):
        _ = os.fstat(opened_descriptors[0])
