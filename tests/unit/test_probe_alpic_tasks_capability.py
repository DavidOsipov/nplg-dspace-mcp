# Copyright (c) 2026 David Osipov
"""Black-box tests for the fail-closed offline Alpic Tasks probe command."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Self

import pytest
from pydantic import ValidationError

import nplg_mcp.capabilities as capability_module
from nplg_mcp.capabilities import (
    AlpicTasksSourceEvidence,
    load_alpic_tasks_source_evidence,
)
from scripts import probe_alpic_tasks_capability as probe

if TYPE_CHECKING:
    from collections.abc import Mapping

_PROJECT_ROOT = Path(__file__).parents[2]
_SCRIPT = _PROJECT_ROOT / "scripts" / "probe_alpic_tasks_capability.py"
_SOURCE_EVIDENCE = _PROJECT_ROOT / "contracts" / "alpic-tasks-source-evidence.json"
_VERDICT = _PROJECT_ROOT / "contracts" / "alpic-tasks-capability.json"
_UNSUPPORTED_EXIT = 24
_FIXTURE_BYTES = 3
_EXPECTED_DOWNLOADER_HANDLERS = 3
_REDIRECT_STATUS = 302


class _StaticSourceDownloader:
    def __init__(
        self,
        *,
        final_url_suffix: str = "",
        content_length_bytes: int = _FIXTURE_BYTES,
    ) -> None:
        super().__init__()
        self._final_url_suffix = final_url_suffix
        self._content_length_bytes = content_length_bytes

    def download(
        self,
        requirement: probe.SourceRequirement,
    ) -> probe.SourceDownload:
        return probe.SourceDownload(
            final_url=f"{requirement.url}{self._final_url_suffix}",
            status_code=200,
            media_type=requirement.media_type,
            content_length_bytes=self._content_length_bytes,
            content_sha256=hashlib.sha256(
                requirement.source_id.encode("utf-8")
            ).hexdigest(),
        )


class _Response:
    def __init__(
        self,
        *,
        body: bytes,
        headers: Mapping[str, str],
        final_url: str,
        status: int = 200,
    ) -> None:
        super().__init__()
        self.status = status
        self.headers = headers
        self._body = body
        self._final_url = final_url
        self._offset = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *arguments: object) -> None:
        return None

    def geturl(self) -> str:
        return self._final_url

    def read(self, amount: int) -> bytes:
        chunk = self._body[self._offset : self._offset + amount]
        self._offset += len(chunk)
        return chunk


class _Opener:
    def __init__(self, response: _Response) -> None:
        super().__init__()
        self.response = response
        self.addheaders: list[tuple[str, str]] = []
        self.requests: list[tuple[str, int]] = []

    def open(self, url: str, *, timeout: int) -> _Response:
        self.requests.append((url, timeout))
        return self.response


class _OSErrorOpener:
    def __init__(self) -> None:
        super().__init__()
        self.addheaders: list[tuple[str, str]] = []

    def open(self, _url: str, *, timeout: int) -> _Response:
        del timeout
        msg = "simulated transport failure"
        raise OSError(msg)


def _run_probe(
    output: Path,
    *,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run only the isolated, offline capability command."""
    return subprocess.run(  # noqa: S603
        (
            sys.executable,
            "-I",
            str(_SCRIPT),
            "--source-evidence",
            str(_SOURCE_EVIDENCE),
            "--output",
            str(output),
        ),
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )


def test_offline_probe_emits_the_canonical_unsupported_verdict(tmp_path: Path) -> None:
    """Mutation caught: an unsupported SDK result is reported as success."""
    output = tmp_path / "alpic-tasks-capability.json"

    completed = _run_probe(output)

    assert completed.returncode == _UNSUPPORTED_EXIT, completed.stderr
    assert output.read_bytes() == _VERDICT.read_bytes()


def test_offline_probe_never_uses_ambient_proxy_configuration(tmp_path: Path) -> None:
    """Mutation caught: offline verification honors proxy environment values."""
    output = tmp_path / "alpic-tasks-capability.json"
    environment = dict(os.environ)
    environment.update(
        {
            "ALL_PROXY": "http://127.0.0.1:1",
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "NO_PROXY": "",
        }
    )

    completed = _run_probe(output, environment=environment)

    assert completed.returncode == _UNSUPPORTED_EXIT, completed.stderr
    assert output.read_bytes() == _VERDICT.read_bytes()


def test_offline_probe_refuses_a_symlink_output_without_publishing(
    tmp_path: Path,
) -> None:
    """Mutation caught: a capability write follows an attacker-controlled link."""
    victim = tmp_path / "victim.json"
    _ = victim.write_text("do-not-touch", encoding="utf-8")
    output = tmp_path / "alpic-tasks-capability.json"
    output.symlink_to(victim)

    completed = _run_probe(output)

    assert completed.returncode != _UNSUPPORTED_EXIT
    assert victim.read_text(encoding="utf-8") == "do-not-touch"


def test_offline_probe_refuses_a_hard_link_output_without_publishing(
    tmp_path: Path,
) -> None:
    """Mutation caught: a capability write reuses an attacker-shared inode."""
    shared = tmp_path / "shared.json"
    _ = shared.write_text("do-not-touch", encoding="utf-8")
    output = tmp_path / "alpic-tasks-capability.json"
    os.link(shared, output)

    completed = _run_probe(output)

    assert completed.returncode != _UNSUPPORTED_EXIT
    assert shared.read_text(encoding="utf-8") == "do-not-touch"


def test_direct_offline_run_publishes_once_and_rejects_noncanonical_replacement(
    tmp_path: Path,
) -> None:
    """Mutation caught: direct callers can overwrite an existing verdict."""
    output = tmp_path / "alpic-tasks-capability.json"

    assert probe.run(_SOURCE_EVIDENCE, output) == _UNSUPPORTED_EXIT
    assert output.read_bytes() == _VERDICT.read_bytes()
    assert probe.run(_SOURCE_EVIDENCE, output) == _UNSUPPORTED_EXIT

    _ = output.write_text("forged", encoding="utf-8")
    with pytest.raises(probe.ProbeOutputError, match="noncanonical"):
        _ = probe.run(_SOURCE_EVIDENCE, output)


def test_main_rejects_missing_source_evidence_without_an_output(tmp_path: Path) -> None:
    """Mutation caught: malformed offline input can still publish a verdict."""
    output = tmp_path / "alpic-tasks-capability.json"

    status = probe.main(
        [
            "--source-evidence",
            str(tmp_path / "missing-source-evidence.json"),
            "--output",
            str(output),
        ]
    )

    assert status == 1
    assert not output.exists()


def test_capture_sources_writes_a_separate_canonical_evidence_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: source capture does not use the exclusive writer."""
    evidence = load_alpic_tasks_source_evidence(_SOURCE_EVIDENCE)
    output = tmp_path / "captured-source-evidence.json"

    def captured_evidence() -> AlpicTasksSourceEvidence:
        return evidence

    monkeypatch.setattr(probe, "capture_source_evidence", captured_evidence)

    assert probe.capture_sources(output) == 0
    assert load_alpic_tasks_source_evidence(output) == evidence


def test_probe_exposes_a_dedicated_source_capture_mode() -> None:
    """Mutation caught: source refresh is silently folded into offline probing."""
    assert callable(probe.capture_source_evidence)


def test_source_capture_produces_digest_only_evidence() -> None:
    """Mutation caught: source capture persists prose or omits its canonical digest."""
    evidence = probe.capture_source_evidence(_StaticSourceDownloader())

    assert evidence.evidence_digest
    assert tuple(source.source_id for source in evidence.sources) == (
        "alpic_tasks_docs",
        "python_sdk_roadmap",
        "mcp_tasks_spec",
    )
    assert all(
        source.content_length_bytes == _FIXTURE_BYTES for source in evidence.sources
    )


def test_source_capture_rejects_redirects_and_oversize_metadata() -> None:
    """Mutation caught: an unreviewed redirect or excess body enters source evidence."""
    with pytest.raises(ValidationError, match="final_url"):
        _ = probe.capture_source_evidence(
            _StaticSourceDownloader(final_url_suffix="?redirected")
        )
    with pytest.raises(ValidationError, match="content_length_bytes"):
        _ = probe.capture_source_evidence(
            _StaticSourceDownloader(content_length_bytes=1_048_577)
        )


def test_https_source_downloader_disables_proxies_and_rejects_content_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: source capture accepts a proxy or transformed response."""
    source = probe.SOURCE_REQUIREMENTS[0]
    opener = _Opener(
        _Response(
            body=b"abc",
            headers={"Content-Type": "text/html; charset=utf-8"},
            final_url=source.url,
        )
    )
    recorded_handlers: list[object] = []
    recorded_proxy_configurations: list[dict[str, str]] = []

    def build_opener(*handlers: object) -> _Opener:
        recorded_handlers.extend(handlers)
        return opener

    def proxy_handler(proxies: dict[str, str]) -> object:
        recorded_proxy_configurations.append(proxies)
        return object()

    monkeypatch.setattr(urllib.request, "ProxyHandler", proxy_handler)
    monkeypatch.setattr(urllib.request, "build_opener", build_opener)

    downloaded = probe.HttpsSourceDownloader().download(source)

    assert downloaded.content_sha256 == hashlib.sha256(b"abc").hexdigest()
    assert opener.requests == [(source.url, 30)]
    assert len(recorded_handlers) == _EXPECTED_DOWNLOADER_HANDLERS
    assert recorded_proxy_configurations == [{}]

    encoded = _Opener(
        _Response(
            body=b"abc",
            headers={"Content-Encoding": "gzip", "Content-Type": "text/html"},
            final_url=source.url,
        )
    )

    def encoded_opener(*_handlers: object) -> _Opener:
        return encoded

    monkeypatch.setattr(urllib.request, "build_opener", encoded_opener)
    with pytest.raises(probe.ProbeOutputError, match="unexpected representation"):
        _ = probe.HttpsSourceDownloader().download(source)


def test_https_source_downloader_rejects_an_unregistered_source_before_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: a helper caller widens source-capture egress scope."""
    unregistered = probe.SourceRequirement(
        "alpic_tasks_docs",
        "https://attacker.example/tasks",
        "tasks_compute_advertised",
    )
    opener = _Opener(
        _Response(
            body=b"untrusted",
            headers={"Content-Type": "text/html"},
            final_url=unregistered.url,
        )
    )

    def unregistered_opener(*_handlers: object) -> _Opener:
        return opener

    monkeypatch.setattr(urllib.request, "build_opener", unregistered_opener)

    with pytest.raises(probe.ProbeOutputError, match="not allowlisted"):
        _ = probe.HttpsSourceDownloader().download(unregistered)

    assert opener.requests == []


def test_source_downloader_rejects_redirects_malformed_urls_and_bad_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: source capture accepts a redirect, unsafe URL, or bad body."""
    source = probe.SOURCE_REQUIREMENTS[0]
    request = urllib.request.Request(source.url)  # noqa: S310
    with pytest.raises(probe.ProbeOutputError, match="redirects are forbidden"):
        _ = probe.NoRedirectHandler().redirect_request(
            request,
            object(),
            _REDIRECT_STATUS,
            "redirected",
            object(),
            "https://attacker.example/tasks",
        )

    malformed = probe.SourceRequirement(
        source.source_id,
        "http://docs.alpic.ai/troubleshooting",
        source.observation,
    )
    monkeypatch.setattr(probe, "SOURCE_REQUIREMENTS", (malformed,))
    with pytest.raises(probe.ProbeOutputError, match="credential-free HTTPS"):
        _ = probe.HttpsSourceDownloader().download(malformed)

    monkeypatch.setattr(probe, "SOURCE_REQUIREMENTS", (source,))
    oversized = _Opener(
        _Response(
            body=b"x" * (1_048_577),
            headers={"Content-Type": "text/html"},
            final_url=source.url,
        )
    )

    def oversized_opener(*_handlers: object) -> _Opener:
        return oversized

    monkeypatch.setattr(urllib.request, "build_opener", oversized_opener)
    with pytest.raises(probe.ProbeOutputError, match="content budget"):
        _ = probe.HttpsSourceDownloader().download(source)

    empty = _Opener(
        _Response(
            body=b"",
            headers={"Content-Type": "text/html"},
            final_url=source.url,
        )
    )

    def empty_opener(*_handlers: object) -> _Opener:
        return empty

    monkeypatch.setattr(urllib.request, "build_opener", empty_opener)
    with pytest.raises(probe.ProbeOutputError, match="empty representation"):
        _ = probe.HttpsSourceDownloader().download(source)

    no_content_type = _Opener(_Response(body=b"x", headers={}, final_url=source.url))

    def no_content_type_opener(*_handlers: object) -> _Opener:
        return no_content_type

    monkeypatch.setattr(urllib.request, "build_opener", no_content_type_opener)
    with pytest.raises(probe.ProbeOutputError, match="unexpected representation"):
        _ = probe.HttpsSourceDownloader().download(source)

    def failing_opener(*_handlers: object) -> _OSErrorOpener:
        return _OSErrorOpener()

    monkeypatch.setattr(urllib.request, "build_opener", failing_opener)
    with pytest.raises(probe.ProbeOutputError, match="source capture failed"):
        _ = probe.HttpsSourceDownloader().download(source)


def test_canonical_json_writer_rejects_an_oversized_payload() -> None:
    """Mutation caught: a large verdict bypasses the output size ceiling."""
    with pytest.raises(probe.ProbeOutputError, match="output budget"):
        _ = probe.canonical_json_bytes({"payload": "x" * 2_097_153})


def test_run_rejects_missing_unsafe_and_mismatched_evidence_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: unsafe input/output identities reach publication logic."""
    missing_output = tmp_path / "missing-source-output.json"
    with pytest.raises(probe.ProbeOutputError, match="input is missing"):
        _ = probe.run(tmp_path / "missing-source-evidence.json", missing_output)
    assert not missing_output.exists()

    source_directory = tmp_path / "source-directory"
    source_directory.mkdir()
    with pytest.raises(probe.ProbeOutputError, match="single-link regular file"):
        _ = probe.run(source_directory, tmp_path / "directory-source-output.json")

    missing_parent_output = tmp_path / "missing-parent" / "verdict.json"
    with pytest.raises(probe.ProbeOutputError, match="directory is missing"):
        _ = probe.run(_SOURCE_EVIDENCE, missing_parent_output)

    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path)
    with pytest.raises(probe.ProbeOutputError, match="directory is unsafe"):
        _ = probe.run(_SOURCE_EVIDENCE, linked_parent / "verdict.json")

    target = tmp_path / "symlink-target.json"
    _ = target.write_bytes(_VERDICT.read_bytes())
    symlink_output = tmp_path / "symlink-output.json"
    symlink_output.symlink_to(target)
    with pytest.raises(probe.ProbeOutputError, match="single-link regular file"):
        _ = probe.run(_SOURCE_EVIDENCE, symlink_output)

    evidence = load_alpic_tasks_source_evidence(_SOURCE_EVIDENCE)
    mismatched = evidence.model_copy()
    object.__setattr__(mismatched, "evidence_digest", "0" * 64)

    def mismatched_loader(_path: Path) -> AlpicTasksSourceEvidence:
        return mismatched

    monkeypatch.setattr(
        capability_module,
        "load_alpic_tasks_source_evidence",
        mismatched_loader,
    )
    with pytest.raises(probe.ProbeOutputError, match="does not bind"):
        _ = probe.run(_SOURCE_EVIDENCE, tmp_path / "mismatched-verdict.json")


def test_run_cleans_up_when_exclusive_publication_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: a failed hard-link publish leaves a temporary verdict behind."""
    output = tmp_path / "alpic-tasks-capability.json"

    def failing_link(*_arguments: object, **_keywords: object) -> None:
        msg = "simulated hard-link failure"
        raise OSError(msg)

    monkeypatch.setattr(os, "link", failing_link)
    with pytest.raises(probe.ProbeOutputError, match="publication failed"):
        _ = probe.run(_SOURCE_EVIDENCE, output)

    assert not output.exists()
    assert list(tmp_path.glob(".*.tmp")) == []


def test_run_refuses_output_open_failures_and_reconciles_a_publish_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: output-open and cleanup failures are treated as success."""
    existing = tmp_path / "existing-verdict.json"
    _ = existing.write_bytes(_VERDICT.read_bytes())

    def failing_open(*_arguments: object, **_keywords: object) -> int:
        msg = "simulated open failure"
        raise OSError(msg)

    monkeypatch.setattr(os, "open", failing_open)
    with pytest.raises(probe.ProbeOutputError, match="cannot be opened safely"):
        _ = probe.run(_SOURCE_EVIDENCE, existing)

    monkeypatch.undo()
    output = tmp_path / "cleanup-verdict.json"
    original_unlink = os.unlink

    def failing_temporary_unlink(path: str, *, dir_fd: int | None = None) -> None:
        if path.startswith("."):
            msg = "simulated temporary unlink failure"
            raise OSError(msg)
        if dir_fd is None:
            original_unlink(path)
        else:
            original_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", failing_temporary_unlink)
    with pytest.raises(probe.ProbeOutputError, match="publication failed"):
        _ = probe.run(_SOURCE_EVIDENCE, output)

    assert not output.exists()


def test_main_dispatches_capture_sources_without_reading_offline_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: capture mode reaches offline verdict generation first."""
    captured_outputs: list[Path] = []

    def capture(output: Path) -> int:
        captured_outputs.append(output)
        return 0

    monkeypatch.setattr(probe, "capture_sources", capture)
    capture_output = Path("capture-source-evidence.json")

    assert (
        probe.main(["--capture-sources", "--source-evidence", str(capture_output)]) == 0
    )
    assert captured_outputs == [capture_output]
