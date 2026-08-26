# Copyright (c) 2026 David Osipov
"""File-identity race tests for the offline Alpic Tasks probe."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts import probe_alpic_tasks_capability as probe

_PROJECT_ROOT = Path(__file__).parents[2]
_SOURCE_EVIDENCE = _PROJECT_ROOT / "contracts" / "alpic-tasks-source-evidence.json"
_VERDICT = _PROJECT_ROOT / "contracts" / "alpic-tasks-capability.json"
_POST_READ_OBSERVATION = 2


def _with_changed_inode(metadata: os.stat_result) -> os.stat_result:
    return os.stat_result(
        (
            metadata.st_mode,
            metadata.st_ino + 1,
            metadata.st_dev,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_atime,
            metadata.st_mtime,
            metadata.st_ctime,
        )
    )


def test_probe_rejects_output_replacement_between_lstat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "existing-verdict.json"
    _ = output.write_bytes(_VERDICT.read_bytes())
    real_fstat = os.fstat

    def replaced_identity(descriptor: int) -> os.stat_result:
        return _with_changed_inode(real_fstat(descriptor))

    monkeypatch.setattr(os, "fstat", replaced_identity)

    with pytest.raises(probe.ProbeOutputError, match="changed before validation"):
        _ = probe.run(_SOURCE_EVIDENCE, output)


def test_probe_rejects_output_replacement_while_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "existing-verdict.json"
    _ = output.write_bytes(_VERDICT.read_bytes())
    real_lstat = os.lstat
    output_observations = 0

    def changing_identity(path: Path) -> os.stat_result:
        nonlocal output_observations
        metadata = real_lstat(path)
        if path == output:
            output_observations += 1
            if output_observations == _POST_READ_OBSERVATION:
                return _with_changed_inode(metadata)
        return metadata

    monkeypatch.setattr(os, "lstat", changing_identity)

    with pytest.raises(probe.ProbeOutputError, match="changed during validation"):
        _ = probe.run(_SOURCE_EVIDENCE, output)
