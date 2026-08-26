# Copyright (c) 2026 David Osipov
"""Emit only the canonical, fail-closed offline Alpic Tasks capability verdict."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, Protocol, Self, cast, override

from nplg_mcp import capabilities

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import TextIO

_PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
_DEFAULT_SOURCE_EVIDENCE: Final = (
    _PROJECT_ROOT / "contracts" / "alpic-tasks-source-evidence.json"
)
_DEFAULT_OUTPUT: Final = _PROJECT_ROOT / "contracts" / "alpic-tasks-capability.json"
_UNSUPPORTED_EXIT: Final = 24
_MAX_OUTPUT_BYTES: Final = 2_097_152
_MAX_SOURCE_BYTES: Final = 1_048_576
_READ_CHUNK_BYTES: Final = 65_536
_HTTP_OK: Final = 200


@dataclass(frozen=True, slots=True)
class SourceRequirement:
    """One closed source to capture without retaining third-party prose."""

    source_id: capabilities.AlpicTasksSourceId
    url: str
    observation: capabilities.AlpicTasksSourceObservation
    media_type: Literal["text/html", "text/plain"] = "text/html"


@dataclass(frozen=True, slots=True)
class SourceDownload:
    """Bounded identity-encoded response metadata without its body."""

    final_url: str
    status_code: Literal[200]
    media_type: Literal["text/html", "text/plain"]
    content_length_bytes: int
    content_sha256: str


_PYTHON_SDK_RAW_ROOT: Final = (
    "https://raw.githubusercontent.com/modelcontextprotocol/python-sdk"
)
_PYTHON_SDK_ROADMAP_REVISION: Final = "959569ba1505897bd8d824a1bf22800672f7cf14"


SOURCE_REQUIREMENTS: Final = (
    SourceRequirement(
        "alpic_tasks_docs",
        "https://docs.alpic.ai/troubleshooting",
        "tasks_compute_advertised",
    ),
    SourceRequirement(
        "python_sdk_roadmap",
        f"{_PYTHON_SDK_RAW_ROOT}/{_PYTHON_SDK_ROADMAP_REVISION}/ROADMAP.md",
        "sdk_tasks_deferred",
        "text/plain",
    ),
    SourceRequirement(
        "mcp_tasks_spec",
        "https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks",
        "tasks_extension_draft",
    ),
)


class ProbeOutputError(RuntimeError):
    """Raised when the command cannot securely publish its local verdict."""


class _SourceDownloader(Protocol):
    """Fetch one exact allowlisted source without ambient authority."""

    def download(self, requirement: SourceRequirement) -> SourceDownload:
        """Return only bounded representation metadata and digest."""
        ...


class _HttpResponse(Protocol):
    """Small typed surface needed from a standard-library HTTP response."""

    status: int
    headers: Mapping[str, str]

    def __enter__(self) -> Self: ...

    def __exit__(self, *arguments: object) -> None: ...

    def geturl(self) -> str: ...

    def read(self, amount: int) -> bytes: ...


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Convert every redirect into a fail-closed source-capture failure."""

    @override
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        del req, fp, code, msg, headers, newurl
        error_message = "redirects are forbidden for Alpic Tasks source capture"
        raise ProbeOutputError(error_message)


class HttpsSourceDownloader:
    """Capture a single primary source with proxies and content transforms disabled."""

    def download(self, requirement: SourceRequirement) -> SourceDownload:
        """Return a digest-only response after strict transport and size checks."""
        if requirement not in SOURCE_REQUIREMENTS:
            msg = "source capture requirement is not allowlisted"
            raise ProbeOutputError(msg)
        parsed = urllib.parse.urlsplit(requirement.url)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            msg = "source capture URL is not canonical credential-free HTTPS"
            raise ProbeOutputError(msg)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        opener.addheaders = [
            ("Accept", requirement.media_type),
            ("Accept-Encoding", "identity"),
            ("User-Agent", "nplg-mcp-capability-probe/1.0"),
        ]
        try:
            with cast(
                "_HttpResponse", opener.open(requirement.url, timeout=30)
            ) as response:
                content_type = response.headers.get("Content-Type")
                content_encoding = response.headers.get("Content-Encoding")
                raw_media_type = ""
                if content_type is not None:
                    raw_media_type = content_type.split(";", maxsplit=1)[0]
                media_type = raw_media_type.strip().lower()
                if (
                    response.status != _HTTP_OK
                    or response.geturl() != requirement.url
                    or media_type != requirement.media_type
                    or content_encoding is not None
                ):
                    msg = "source capture returned an unexpected representation"
                    raise ProbeOutputError(msg)
                digest = hashlib.sha256()
                content_length_bytes = 0
                while True:
                    chunk = response.read(_READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    content_length_bytes += len(chunk)
                    if content_length_bytes > _MAX_SOURCE_BYTES:
                        msg = "source capture exceeds the content budget"
                        raise ProbeOutputError(msg)
                    digest.update(chunk)
        except (OSError, urllib.error.URLError) as error:
            msg = "source capture failed"
            raise ProbeOutputError(msg) from error
        if content_length_bytes < 1:
            msg = "source capture returned an empty representation"
            raise ProbeOutputError(msg)
        return SourceDownload(
            final_url=requirement.url,
            status_code=_HTTP_OK,
            media_type=requirement.media_type,
            content_length_bytes=content_length_bytes,
            content_sha256=digest.hexdigest(),
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate offline Alpic Tasks evidence and emit its strict verdict."
    )
    _ = parser.add_argument(
        "--capture-sources",
        action="store_true",
        help="capture allowlisted source metadata into a new evidence file",
    )
    _ = parser.add_argument(
        "--source-evidence",
        type=Path,
        default=_DEFAULT_SOURCE_EVIDENCE,
        help="canonical digest-bound source evidence input",
    )
    _ = parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help="new canonical verdict destination",
    )
    return parser


def canonical_json_bytes(value: dict[str, object]) -> bytes:
    """Serialize one already-validated Pydantic record deterministically."""
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    encoded = rendered.encode("utf-8") + b"\n"
    if len(encoded) > _MAX_OUTPUT_BYTES:
        msg = "capability verdict exceeds its output budget"
        raise ProbeOutputError(msg)
    return encoded


def _canonical_bytes(verdict: capabilities.AlpicTasksCapabilityVerdict) -> bytes:
    """Serialize one already-validated Pydantic verdict deterministically."""
    return canonical_json_bytes(capabilities.canonical_model_json(verdict))


def _utc_timestamp() -> str:
    """Return the current retrieval time in the only accepted UTC representation."""
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def capture_source_evidence(
    downloader: _SourceDownloader | None = None,
) -> capabilities.AlpicTasksSourceEvidence:
    """Capture the three closed source identities without persisting their prose."""
    effective_downloader = HttpsSourceDownloader() if downloader is None else downloader
    sources: list[capabilities.AlpicTasksSourceRecord] = []
    for requirement in SOURCE_REQUIREMENTS:
        downloaded = effective_downloader.download(requirement)
        sources.append(
            capabilities.AlpicTasksSourceRecord(
                source_id=requirement.source_id,
                url=requirement.url,
                final_url=downloaded.final_url,
                retrieved_at=_utc_timestamp(),
                status_code=downloaded.status_code,
                media_type=downloaded.media_type,
                content_length_bytes=downloaded.content_length_bytes,
                content_sha256=downloaded.content_sha256,
                observation=requirement.observation,
            )
        )
    raw_sources = [capabilities.canonical_model_json(source) for source in sources]
    evidence_payload: dict[str, object] = {
        "schema_version": "1.0",
        "sources": raw_sources,
    }
    evidence_digest = hashlib.sha256(
        json.dumps(
            evidence_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return capabilities.AlpicTasksSourceEvidence(
        schema_version="1.0",
        sources=tuple(sources),
        evidence_digest=evidence_digest,
    )


def capture_sources(output: Path) -> int:
    """Capture source metadata into a new output, never modifying existing evidence."""
    evidence = capture_source_evidence()
    _publish_new_regular_file(
        output,
        canonical_json_bytes(capabilities.canonical_model_json(evidence)),
    )
    return 0


def _lstat_regular_single_link(path: Path) -> os.stat_result:
    """Return a stable regular-file identity without dereferencing a final link."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as error:
        msg = "required capability input is missing"
        raise ProbeOutputError(msg) from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        msg = "capability path must be a single-link regular file"
        raise ProbeOutputError(msg)
    return metadata


def _verify_directory_chain(directory: Path) -> None:
    """Reject a symlinked directory component before publishing any output."""
    absolute = directory.absolute()
    current = absolute
    while True:
        try:
            metadata = os.lstat(current)
        except FileNotFoundError as error:
            msg = "capability output directory is missing"
            raise ProbeOutputError(msg) from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            msg = "capability output directory is unsafe"
            raise ProbeOutputError(msg)
        if current == current.parent:
            return
        current = current.parent


def _read_if_matching(path: Path, expected: bytes) -> bool:
    """Accept a pre-existing result only when it is exactly the trusted bytes."""
    try:
        before = _lstat_regular_single_link(path)
    except ProbeOutputError:
        if path.exists() or path.is_symlink():
            raise
        return False
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        msg = "capability output cannot be opened safely"
        raise ProbeOutputError(msg) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            msg = "capability output identity changed before validation"
            raise ProbeOutputError(msg)
        contents = os.read(descriptor, len(expected) + 1)
    finally:
        os.close(descriptor)
    after = _lstat_regular_single_link(path)
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
        msg = "capability output identity changed during validation"
        raise ProbeOutputError(msg)
    if contents != expected:
        msg = "refusing to overwrite a noncanonical capability output"
        raise ProbeOutputError(msg)
    return True


def _publish_new_regular_file(output: Path, contents: bytes) -> None:
    """Atomically publish a new, no-clobber regular file in its trusted directory."""
    _verify_directory_chain(output.parent)
    if _read_if_matching(output, contents):
        return
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        directory_descriptor = os.open(output.parent, directory_flags)
    except OSError as error:
        msg = "capability output directory cannot be opened safely"
        raise ProbeOutputError(msg) from error
    temporary_name = f".{output.name}.{secrets.token_hex(16)}.tmp"
    temporary_created = False
    published = False
    try:
        temporary_flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        descriptor = os.open(
            temporary_name,
            temporary_flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_created = True
        try:
            written = 0
            while written < len(contents):
                written += os.write(descriptor, contents[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(
            temporary_name,
            output.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        published = True
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_created = False
        os.fsync(directory_descriptor)
    except OSError as error:
        if published:
            with suppress(OSError):
                os.unlink(output.name, dir_fd=directory_descriptor)
        msg = "capability output publication failed"
        raise ProbeOutputError(msg) from error
    finally:
        if temporary_created:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        os.close(directory_descriptor)


def run(source_evidence: Path, output: Path) -> int:
    """Validate offline evidence and publish only the corresponding exact verdict."""
    _ = _lstat_regular_single_link(source_evidence)
    evidence = capabilities.load_alpic_tasks_source_evidence(source_evidence)
    verdict = capabilities.probe_alpic_tasks_capability()
    if verdict.source_evidence_digest != evidence.evidence_digest:
        msg = "source evidence does not bind the capability verdict"
        raise ProbeOutputError(msg)
    _publish_new_regular_file(output, _canonical_bytes(verdict))
    return _UNSUPPORTED_EXIT


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the command with no network, proxy, credential, or deployment authority."""
    parsed = _parser().parse_args(arguments)
    capture_sources_requested = cast("bool", parsed.capture_sources)
    source_evidence = cast("Path", parsed.source_evidence)
    output = cast("Path", parsed.output)
    try:
        if capture_sources_requested:
            return capture_sources(source_evidence)
        return run(source_evidence, output)
    except (
        capabilities.CapabilityContractError,
        OSError,
        ProbeOutputError,
        ValueError,
    ):
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write(
            "Alpic Tasks capability probe failed without publishing a verdict.\n"
        )
        return 1


if __name__ == "__main__":  # pragma: no cover - exercised via isolated subprocess
    raise SystemExit(main())
