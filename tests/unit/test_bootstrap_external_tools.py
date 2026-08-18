# Copyright (c) 2026 David Osipov
"""Tests for the thin external quality-tool bootstrap adapter."""

from __future__ import annotations

import hashlib
import io
import json
import runpy
import stat
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

import scripts.bootstrap_external_tools as external_tools
from scripts.bootstrap_external_tools import ExternalToolOptions, install_external_tool
from scripts.bootstrap_toolchain import ToolchainError, load_lock

PROJECT_ROOT = Path(__file__).parents[2]
_CLI_FAILURE = 2


@dataclass(slots=True)
class _UnexpectedDownloader:
    requested_urls: list[str] = field(default_factory=list[str])

    def download(self, url: str, *, max_bytes: int) -> bytes:
        del max_bytes
        self.requested_urls.append(url)
        pytest.fail("unsupported platforms must fail before download")


@dataclass(slots=True)
class _LocalDownloader:
    artifact_url: str
    payload: bytes
    requested_urls: list[str] = field(default_factory=list[str])

    def download(self, url: str, *, max_bytes: int) -> bytes:
        self.requested_urls.append(url)
        if url != self.artifact_url:
            pytest.fail("adapter requested non-artifact review evidence")
        if len(self.payload) > max_bytes:
            msg = "fixture partial download"
            raise ToolchainError(msg)
        return self.payload


def _zip_artifact(*, name: str = "fixture-tool", payload: bytes = b"fixture") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        member = zipfile.ZipInfo(name)
        member.create_system = 3
        member.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(member, payload)
    return output.getvalue()


def _symlink_artifact() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        member = zipfile.ZipInfo("fixture-tool")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "target")
    return output.getvalue()


def _write_lock(
    root: Path,
    artifact: bytes,
    *,
    artifact_sha256: str | None = None,
) -> tuple[Path, str]:
    artifact_url = "https://example.test/fixture-tool.zip"
    record: dict[str, object] = {
        "tool": "actionlint",
        "target": "x86_64-unknown-linux-gnu",
        "publisher": "Fixture Publisher",
        "runtime_trust_policy": "repository_pinned_sha256",
        "lock_review_status": "accepted",
        "materialized_link_wrappers": [],
        "chosen_version": "1.2.3",
        "current_version": "1.2.3",
        "hold_rationale": "local adapter fixture",
        "artifact_url": artifact_url,
        "artifact_sha256": artifact_sha256 or hashlib.sha256(artifact).hexdigest(),
        "signature_url": None,
        "signature_sha256": None,
        "archive_format": "zip",
        "allowed_top_level_entries": ["fixture-tool"],
        "embedded_version_command": ["{path}", "--version"],
        "max_artifact_bytes": 1024 * 1024,
        "max_signature_bytes": 1024,
        "checksum_url": "https://example.test/fixture-tool.sha256",
        "checksum_sha256": "a" * 64,
        "signature_key_fingerprint": None,
        "signature_reason": "fixture publisher offers no detached signature",
        "max_archive_members": 16,
        "max_extracted_bytes": 1024 * 1024,
        "upstream_integrity": None,
        "runtime_dependencies": list[object](),
        "regular_entrypoints": list[object](),
    }
    lock_path = root / "toolchain-lock.json"
    lock_payload: dict[str, object] = {"schema_version": 1, "records": [record]}
    _ = lock_path.write_text(
        json.dumps(lock_payload),
        encoding="utf-8",
    )
    return lock_path, artifact_url


def test_install_external_tool_rejects_unsupported_platform_before_download(
    tmp_path: Path,
) -> None:
    downloader = _UnexpectedDownloader()
    destination = tmp_path / "installed"

    with pytest.raises(ToolchainError, match="unsupported external-tool platform"):
        _ = install_external_tool(
            tmp_path / "absent-lock.json",
            tool="actionlint",
            destination=destination,
            downloader=downloader,
            options=ExternalToolOptions(system_name="Darwin", machine="arm64"),
        )

    assert downloader.requested_urls == []
    assert not destination.exists()


def test_install_external_tool_delegates_supported_platform_to_locked_installer(
    tmp_path: Path,
) -> None:
    artifact = _zip_artifact()
    lock_path, artifact_url = _write_lock(tmp_path, artifact)
    downloader = _LocalDownloader(artifact_url, artifact)
    destination = tmp_path / "installed"

    result = install_external_tool(
        lock_path,
        tool="actionlint",
        destination=destination,
        downloader=downloader,
        options=ExternalToolOptions(
            system_name="Linux",
            machine="x86_64",
            version_checker=lambda _path, _command: "1.2.3",
        ),
    )

    assert result == destination
    assert (destination / "fixture-tool").read_bytes() == b"fixture"
    assert downloader.requested_urls == [artifact_url]


def test_install_external_tool_rejects_digest_mismatch_without_publication(
    tmp_path: Path,
) -> None:
    artifact = _zip_artifact()
    lock_path, artifact_url = _write_lock(
        tmp_path,
        artifact,
        artifact_sha256="0" * 64,
    )
    destination = tmp_path / "installed"

    with pytest.raises(ToolchainError, match="artifact digest mismatch"):
        _ = install_external_tool(
            lock_path,
            tool="actionlint",
            destination=destination,
            downloader=_LocalDownloader(artifact_url, artifact),
            options=ExternalToolOptions(
                system_name="Linux",
                machine="x86_64",
                version_checker=lambda _path, _command: "1.2.3",
            ),
        )

    assert not destination.exists()


@pytest.mark.parametrize(
    ("artifact", "message"),
    [
        (_zip_artifact(name="../escape"), "archive contains a traversal member"),
        (_symlink_artifact(), "archive contains a symlink or special file"),
    ],
)
def test_install_external_tool_rejects_unsafe_archive_entries(
    tmp_path: Path,
    artifact: bytes,
    message: str,
) -> None:
    lock_path, artifact_url = _write_lock(tmp_path, artifact)
    destination = tmp_path / "installed"

    with pytest.raises(ToolchainError, match=message):
        _ = install_external_tool(
            lock_path,
            tool="actionlint",
            destination=destination,
            downloader=_LocalDownloader(artifact_url, artifact),
            options=ExternalToolOptions(
                system_name="Linux",
                machine="x86_64",
                version_checker=lambda _path, _command: "1.2.3",
            ),
        )

    assert not destination.exists()


def test_install_external_tool_rejects_wrong_embedded_version(
    tmp_path: Path,
) -> None:
    artifact = _zip_artifact()
    lock_path, artifact_url = _write_lock(tmp_path, artifact)
    destination = tmp_path / "installed"

    with pytest.raises(ToolchainError, match="installed tool version mismatch"):
        _ = install_external_tool(
            lock_path,
            tool="actionlint",
            destination=destination,
            downloader=_LocalDownloader(artifact_url, artifact),
            options=ExternalToolOptions(
                system_name="Linux",
                machine="x86_64",
                version_checker=lambda _path, _command: "9.9.9",
            ),
        )

    assert not destination.exists()


def test_install_external_tool_propagates_partial_download_failure(
    tmp_path: Path,
) -> None:
    artifact = _zip_artifact()
    lock_path, artifact_url = _write_lock(tmp_path, artifact)
    destination = tmp_path / "installed"
    downloader = _LocalDownloader(artifact_url, artifact)
    downloader.payload = artifact * (1024 * 1024)

    with pytest.raises(ToolchainError, match="fixture partial download"):
        _ = install_external_tool(
            lock_path,
            tool="actionlint",
            destination=destination,
            downloader=downloader,
            options=ExternalToolOptions(
                system_name="Linux",
                machine="x86_64",
                version_checker=lambda _path, _command: "1.2.3",
            ),
        )

    assert not destination.exists()


def test_install_external_tool_never_replaces_existing_destination(
    tmp_path: Path,
) -> None:
    artifact = _zip_artifact()
    lock_path, _artifact_url = _write_lock(tmp_path, artifact)
    destination = tmp_path / "installed"
    destination.mkdir()
    marker = destination / "owned"
    _ = marker.write_bytes(b"preserve")
    downloader = _UnexpectedDownloader()

    with pytest.raises(ToolchainError, match="refusing to replace"):
        _ = install_external_tool(
            lock_path,
            tool="actionlint",
            destination=destination,
            downloader=downloader,
            options=ExternalToolOptions(
                system_name="Linux",
                machine="x86_64",
                version_checker=lambda _path, _command: "1.2.3",
            ),
        )

    assert marker.read_bytes() == b"preserve"
    assert downloader.requested_urls == []


def test_checked_in_external_tool_lock_pins_exact_reviewed_artifacts() -> None:
    records = load_lock(PROJECT_ROOT / "security" / "toolchain-lock.json")

    assert tuple(
        (
            record.tool,
            record.target,
            record.chosen_version,
            record.artifact_url,
            record.artifact_sha256,
            record.checksum_sha256,
        )
        for record in records
    ) == (
        (
            "actionlint",
            "x86_64-unknown-linux-gnu",
            "1.7.12",
            "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
            "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
            "433028cf0ba3c42163ea1a668dedce30fcdbe84fe912b1a5e288c006eab8a4f5",
        ),
        (
            "actionlint",
            "aarch64-unknown-linux-gnu",
            "1.7.12",
            "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_arm64.tar.gz",
            "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6",
            "433028cf0ba3c42163ea1a668dedce30fcdbe84fe912b1a5e288c006eab8a4f5",
        ),
        (
            "gitleaks",
            "x86_64-unknown-linux-gnu",
            "8.30.1",
            "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
            "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
            "061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae",
        ),
        (
            "gitleaks",
            "aarch64-unknown-linux-gnu",
            "8.30.1",
            "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
            "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
            "061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae",
        ),
        (
            "trivy",
            "x86_64-unknown-linux-gnu",
            "0.74.0",
            "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz",
            "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
            "bc701c3c3ee8b9acbea2c23257e41381e3854888f51281616a6ba5dc96963821",
        ),
        (
            "trivy",
            "aarch64-unknown-linux-gnu",
            "0.74.0",
            "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz",
            "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5",
            "bc701c3c3ee8b9acbea2c23257e41381e3854888f51281616a6ba5dc96963821",
        ),
    )


def test_main_reports_unsupported_host_without_reading_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "scripts.bootstrap_external_tools.platform.system", lambda: "Darwin"
    )
    monkeypatch.setattr(
        "scripts.bootstrap_external_tools.platform.machine", lambda: "arm64"
    )

    status = external_tools.main(
        [
            "--lock",
            (tmp_path / "absent.json").as_posix(),
            "--tool",
            "actionlint",
            "--destination",
            (tmp_path / "installed").as_posix(),
        ]
    )

    assert status == _CLI_FAILURE
    assert capsys.readouterr().err == (
        "external-tool bootstrap failed: unsupported external-tool platform\n"
    )


def test_main_reports_success_from_locked_installer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "installed"
    observed: list[tuple[Path, str, Path]] = []

    def install(
        lock_path: Path,
        *,
        tool: str,
        destination: Path,
        downloader: object,
    ) -> Path:
        del downloader
        observed.append((lock_path, tool, destination))
        return destination

    monkeypatch.setattr(external_tools, "install_external_tool", install)
    lock = tmp_path / "lock.json"

    assert (
        external_tools.main(
            [
                "--lock",
                lock.as_posix(),
                "--tool",
                "actionlint",
                "--destination",
                destination.as_posix(),
            ]
        )
        == 0
    )
    assert observed == [(lock, "actionlint", destination)]


def test_bootstrap_external_tools_direct_script_help(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = PROJECT_ROOT / "scripts" / "bootstrap_external_tools.py"
    monkeypatch.setattr(sys, "argv", [script.as_posix(), "--help"])
    with pytest.raises(SystemExit) as raised:
        _ = cast(
            "dict[str, object]",
            runpy.run_path(script.as_posix(), run_name="__main__"),
        )
    assert raised.value.code == 0
