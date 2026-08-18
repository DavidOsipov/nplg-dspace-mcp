# Copyright (c) 2026 David Osipov
"""Deterministic public fault tests for Phase 1 canonical input handling."""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

import pytest

from scripts import baseline_capture_io

if TYPE_CHECKING:
    from pathlib import Path


def test_canonical_json_rejects_replacement_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = tmp_path / "subject.json"
    replacement = tmp_path / "replacement.json"
    _ = subject.write_bytes(b"{}\n")
    _ = replacement.write_bytes(b"{}\n")
    real_open = os.open
    swapped = False

    def swap_before_open(
        path: os.PathLike[str] | str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and os.fspath(path) == os.fspath(subject):
            swapped = True
            _ = replacement.replace(subject)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_before_open)

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="changed during open",
    ):
        _ = baseline_capture_io.load_canonical_json(subject)


def test_canonical_json_rejects_growth_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = tmp_path / "subject.json"
    _ = subject.write_bytes(b"{}\n")
    real_read = os.read
    grew = False

    def grow_before_read(descriptor: int, size: int) -> bytes:
        nonlocal grew
        if not grew:
            grew = True
            with subject.open("ab") as stream:
                _ = stream.write(b"x")
        return real_read(descriptor, size)

    monkeypatch.setattr(os, "read", grow_before_read)

    with pytest.raises(
        baseline_capture_io.BaselineCaptureError,
        match="exceeds 3 bytes",
    ):
        _ = baseline_capture_io.load_canonical_json(subject, max_bytes=3)


def test_bounded_child_waits_after_early_stdio_close(tmp_path: Path) -> None:
    result = baseline_capture_io.run_bounded_process(
        (
            sys.executable,
            "-c",
            "import os,time; os.close(1); os.close(2); time.sleep(0.1)",
        ),
        cwd=tmp_path,
        environment={},
        limits=baseline_capture_io.ProcessLimits(2.0, 128, 128),
    )

    assert result.returncode == 0
    assert result.stdout == b""
    assert result.stderr == b""
