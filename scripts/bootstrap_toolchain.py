# Copyright (c) 2026 David Osipov
"""Fail-closed installation primitives for the pinned developer toolchain.

Runtime authorizes one immutable direct artifact only by its closed-lock
SHA-256; upstream checksum, signature, fingerprint, and registry-integrity
evidence is reviewed when the lock changes and is never fetched at bootstrap
time. The module has no import-time network, subprocess, or filesystem effects,
and its download/version seams permit standard-library-only local tests.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import hashlib
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, Self, cast, override

if TYPE_CHECKING:
    from typing import TextIO


class ToolchainError(RuntimeError):
    """Raised when a locked toolchain input cannot be trusted."""


class Downloader(Protocol):
    """Download one exact URL without following untrusted redirects."""

    def download(self, url: str, *, max_bytes: int) -> bytes:
        """Return a bounded response body or raise :class:`ToolchainError`."""
        ...


VersionChecker = Callable[[Path, tuple[str, ...]], str]
RUNTIME_TRUST_POLICY = "repository_pinned_sha256"
LOCK_REVIEW_STATUS = "accepted"
SHA256_HEX_LENGTH = 64
OPENPGP_FINGERPRINT_LENGTH = 40
SHA512_DIGEST_BYTES = 64
HTTP_SUCCESS_STATUS = 200
MINIMUM_CHECKSUM_FIELDS = 2
PRIVATE_DIRECTORY_MODE = 0o700


class _HttpResponse(Protocol):
    status: int
    headers: Mapping[str, str]

    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

    def read(self, amount: int) -> bytes: ...


class _RenameAt2(Protocol):
    """Typed boundary for the Linux libc renameat2 symbol."""

    argtypes: tuple[object, ...]
    restype: object

    def __call__(
        self,
        source_directory: int,
        source: bytes,
        destination_directory: int,
        destination: bytes,
        flags: int,
        /,
    ) -> int:
        """Invoke renameat2 with already encoded paths."""
        ...


@dataclass(frozen=True, slots=True)
class MaterializedLinkWrapper:
    """One reviewed archive link replaced by a local regular wrapper file."""

    archive_path: str
    target: str


@dataclass(frozen=True, slots=True)
class RuntimeDependency:
    """One exact executable dependency required by a locked tool."""

    tool: str
    chosen_version: str
    executable_path: str
    executable_sha256: str


@dataclass(frozen=True, slots=True)
class RegularEntrypoint:
    """One reviewed regular wrapper generated for an extracted tool."""

    path: str
    target: str
    dependency_tool: str


@dataclass(frozen=True, slots=True)
class ToolchainRecord:
    """One immutable, platform-specific artifact trust record."""

    tool: str
    target: str
    publisher: str
    runtime_trust_policy: str
    lock_review_status: str
    materialized_link_wrappers: tuple[MaterializedLinkWrapper, ...]
    chosen_version: str
    current_version: str
    hold_rationale: str
    artifact_url: str
    artifact_sha256: str
    signature_url: str | None
    signature_sha256: str | None
    archive_format: str
    allowed_top_level_entries: tuple[str, ...]
    embedded_version_command: tuple[str, ...]
    max_artifact_bytes: int
    max_signature_bytes: int
    checksum_url: str | None = None
    checksum_sha256: str | None = None
    signature_key_fingerprint: str | None = None
    signature_reason: str = ""
    max_archive_members: int = 1024
    max_extracted_bytes: int = 128 * 1024 * 1024
    upstream_integrity: str | None = None
    runtime_dependencies: tuple[RuntimeDependency, ...] = ()
    regular_entrypoints: tuple[RegularEntrypoint, ...] = ()


def _string(value: object, field: str) -> str:
    if type(value) is not str or not value:
        msg = f"{field} must be a non-empty string"
        raise ToolchainError(msg)
    return value


def _digest(value: object, field: str) -> str:
    candidate = _string(value, field)
    if len(candidate) != SHA256_HEX_LENGTH or any(
        char not in "0123456789abcdef" for char in candidate
    ):
        msg = f"{field} must be a lowercase SHA-256 digest"
        raise ToolchainError(msg)
    return candidate


def _openpgp_fingerprint(value: object) -> str:
    candidate = _string(value, "signature_key_fingerprint")
    if len(candidate) != OPENPGP_FINGERPRINT_LENGTH or any(
        char not in "0123456789ABCDEF" for char in candidate
    ):
        msg = "fingerprint must be 40 uppercase hexadecimal characters"
        raise ToolchainError(msg)
    return candidate


def _sha512_sri(value: object) -> str:
    candidate = _string(value, "upstream_integrity")
    algorithm, separator, encoded_digest = candidate.partition("-")
    if algorithm != "sha512" or not separator or not encoded_digest:
        msg = "npm registry integrity must be one SHA-512 SRI value"
        raise ToolchainError(msg)
    try:
        decoded = base64.b64decode(encoded_digest, validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = "npm registry integrity must contain a valid SHA-512 digest"
        raise ToolchainError(msg) from exc
    if (
        len(decoded) != SHA512_DIGEST_BYTES
        or base64.b64encode(decoded).decode("ascii") != encoded_digest
    ):
        msg = "npm registry integrity must contain an exact 64-byte SHA-512 digest"
        raise ToolchainError(msg)
    return candidate


def _positive_int(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        msg = f"{field} must be a positive integer"
        raise ToolchainError(msg)
    return value


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    items = cast("list[object]", value)
    if (
        type(value) is not list
        or not value
        or any(type(item) is not str or not item for item in items)
    ):
        msg = f"{field} must be a non-empty string array"
        raise ToolchainError(msg)
    return tuple(cast("list[str]", value))


def _link_wrappers(value: object) -> tuple[MaterializedLinkWrapper, ...]:
    if type(value) is not list:
        msg = "materialized_link_wrappers must be an array"
        raise ToolchainError(msg)
    wrappers: list[MaterializedLinkWrapper] = []
    for item in cast("list[object]", value):
        if type(item) is not dict or set(cast("dict[str, object]", item)) != {
            "archive_path",
            "target",
        }:
            msg = "materialized link wrapper has unknown or missing fields"
            raise ToolchainError(msg)
        mapping = cast("dict[str, object]", item)
        wrappers.append(
            MaterializedLinkWrapper(
                archive_path=_string(mapping["archive_path"], "archive_path"),
                target=_string(mapping["target"], "target"),
            )
        )
    if len({item.archive_path for item in wrappers}) != len(wrappers):
        msg = "materialized link wrapper paths must be unique"
        raise ToolchainError(msg)
    return tuple(wrappers)


def _runtime_dependencies(value: object) -> tuple[RuntimeDependency, ...]:
    if type(value) is not list:
        msg = "runtime_dependencies must be an array"
        raise ToolchainError(msg)
    dependencies: list[RuntimeDependency] = []
    expected = {
        "tool",
        "chosen_version",
        "executable_path",
        "executable_sha256",
    }
    for item in cast("list[object]", value):
        if type(item) is not dict or set(cast("dict[str, object]", item)) != expected:
            msg = "runtime dependency has unknown or missing fields"
            raise ToolchainError(msg)
        mapping = cast("dict[str, object]", item)
        dependencies.append(
            RuntimeDependency(
                tool=_string(mapping["tool"], "dependency tool"),
                chosen_version=_string(
                    mapping["chosen_version"], "dependency chosen_version"
                ),
                executable_path=_string(
                    mapping["executable_path"], "dependency executable_path"
                ),
                executable_sha256=_digest(
                    mapping["executable_sha256"], "dependency executable_sha256"
                ),
            )
        )
    if len({item.tool for item in dependencies}) != len(dependencies):
        msg = "runtime dependency tools must be unique"
        raise ToolchainError(msg)
    return tuple(dependencies)


def _regular_entrypoints(value: object) -> tuple[RegularEntrypoint, ...]:
    if type(value) is not list:
        msg = "regular_entrypoints must be an array"
        raise ToolchainError(msg)
    entrypoints: list[RegularEntrypoint] = []
    expected = {"path", "target", "dependency_tool"}
    for item in cast("list[object]", value):
        if type(item) is not dict or set(cast("dict[str, object]", item)) != expected:
            msg = "regular entrypoint has unknown or missing fields"
            raise ToolchainError(msg)
        mapping = cast("dict[str, object]", item)
        entrypoints.append(
            RegularEntrypoint(
                path=_string(mapping["path"], "entrypoint path"),
                target=_string(mapping["target"], "entrypoint target"),
                dependency_tool=_string(
                    mapping["dependency_tool"], "entrypoint dependency_tool"
                ),
            )
        )
    if len({item.path for item in entrypoints}) != len(entrypoints):
        msg = "regular entrypoint paths must be unique"
        raise ToolchainError(msg)
    return tuple(entrypoints)


def _closed_relative_path(value: str, field: str) -> tuple[str, ...]:
    components = value.split("/")
    if (
        value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(component in {"", ".", ".."} for component in components)
    ):
        msg = f"{field} must be a closed relative path"
        raise ToolchainError(msg)
    return tuple(components)


def _validate_signature_review(record: ToolchainRecord) -> None:
    if record.signature_url is None:
        if (
            record.signature_sha256 is not None
            or record.signature_key_fingerprint is not None
        ):
            msg = "unsigned review evidence cannot contain signature material"
            raise ToolchainError(msg)
    elif record.signature_key_fingerprint is None:
        msg = "signature review evidence requires a key fingerprint"
        raise ToolchainError(msg)
    if not record.signature_reason:
        msg = "signature review evidence requires a rationale"
        raise ToolchainError(msg)


def _validate_archive_review(record: ToolchainRecord) -> None:
    if record.archive_format != "tar.gz" and record.materialized_link_wrappers:
        msg = "only tar archives may declare materialized link wrappers"
        raise ToolchainError(msg)
    if record.archive_format != "tar.gz" and record.regular_entrypoints:
        msg = "only tar archives may declare regular entrypoints"
        raise ToolchainError(msg)


def _validate_runtime_dependency_review(record: ToolchainRecord) -> None:
    dependency_tools = {item.tool for item in record.runtime_dependencies}
    for dependency in record.runtime_dependencies:
        _ = _closed_relative_path(
            dependency.executable_path, "runtime dependency executable path"
        )
    if any(
        entrypoint.dependency_tool not in dependency_tools
        for entrypoint in record.regular_entrypoints
    ):
        msg = "regular entrypoint dependency is not declared"
        raise ToolchainError(msg)
    for entrypoint in record.regular_entrypoints:
        _ = _closed_relative_path(entrypoint.path, "regular entrypoint path")
        target_parts = _closed_relative_path(
            entrypoint.target, "regular entrypoint target"
        )
        if target_parts[0] not in record.allowed_top_level_entries:
            msg = "regular entrypoint target is outside reviewed archive roots"
            raise ToolchainError(msg)


def _validate_registry_review(record: ToolchainRecord) -> None:
    if record.tool == "npm":
        _ = _sha512_sri(record.upstream_integrity)
        if record.embedded_version_command != (
            "{dependency:node}",
            "{path}/bin/npm-cli.js",
            "--version",
        ):
            msg = "npm version probe must execute the extracted locked artifact"
            raise ToolchainError(msg)
    elif record.upstream_integrity is not None:
        msg = "non-npm record cannot contain npm registry integrity evidence"
        raise ToolchainError(msg)


def _validate_review_policy(record: ToolchainRecord) -> None:
    if record.runtime_trust_policy != RUNTIME_TRUST_POLICY:
        msg = "runtime trust policy is not accepted"
        raise ToolchainError(msg)
    if record.lock_review_status != LOCK_REVIEW_STATUS:
        msg = "lock review status is not accepted"
        raise ToolchainError(msg)
    if record.checksum_url is None or record.checksum_sha256 is None:
        msg = "checksum review evidence is incomplete"
        raise ToolchainError(msg)
    _validate_signature_review(record)
    _validate_archive_review(record)
    _validate_runtime_dependency_review(record)
    _validate_registry_review(record)


def _archive_format(value: object) -> str:
    archive_format = _string(value, "archive_format")
    if archive_format not in {"tar.gz", "wheel", "zip"}:
        msg = "archive_format is unsupported"
        raise ToolchainError(msg)
    return archive_format


def _https_url(value: object, field: str) -> str:
    url = _string(value, field)
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        msg = f"{field} must be an HTTPS URL without credentials"
        raise ToolchainError(msg)
    return url


def _signature_url(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        msg = "signature_url must be null or a string"
        raise ToolchainError(msg)
    return _https_url(value, "signature_url")


def _record_from_mapping(value: object) -> ToolchainRecord:
    if type(value) is not dict:
        msg = "toolchain record must be an object"
        raise ToolchainError(msg)
    record = cast("dict[str, object]", value)
    expected = {
        "tool",
        "target",
        "publisher",
        "runtime_trust_policy",
        "lock_review_status",
        "materialized_link_wrappers",
        "chosen_version",
        "current_version",
        "hold_rationale",
        "artifact_url",
        "artifact_sha256",
        "signature_url",
        "signature_sha256",
        "archive_format",
        "allowed_top_level_entries",
        "embedded_version_command",
        "max_artifact_bytes",
        "max_signature_bytes",
        "checksum_url",
        "checksum_sha256",
        "signature_key_fingerprint",
        "signature_reason",
        "max_archive_members",
        "max_extracted_bytes",
        "upstream_integrity",
        "runtime_dependencies",
        "regular_entrypoints",
    }
    if set(record) != expected:
        msg = "toolchain record has unknown or missing fields"
        raise ToolchainError(msg)
    archive_format = _archive_format(record["archive_format"])
    artifact_url = _https_url(record["artifact_url"], "artifact_url")
    checksum_url = _https_url(record["checksum_url"], "checksum_url")
    signature_url = _signature_url(record["signature_url"])
    if (signature_url is None) != (record["signature_sha256"] is None):
        msg = "signature URL and digest must be both present or both absent"
        raise ToolchainError(msg)
    entries = _string_tuple(
        record["allowed_top_level_entries"], "allowed_top_level_entries"
    )
    if len(set(entries)) != len(entries):
        msg = "allowed_top_level_entries must be unique"
        raise ToolchainError(msg)
    command = _string_tuple(
        record["embedded_version_command"], "embedded_version_command"
    )
    if not any("{path}" in item for item in command):
        msg = "embedded_version_command must contain {path}"
        raise ToolchainError(msg)
    parsed_record = ToolchainRecord(
        tool=_string(record["tool"], "tool"),
        target=_string(record["target"], "target"),
        publisher=_string(record["publisher"], "publisher"),
        runtime_trust_policy=_string(
            record["runtime_trust_policy"], "runtime_trust_policy"
        ),
        lock_review_status=_string(record["lock_review_status"], "lock_review_status"),
        materialized_link_wrappers=_link_wrappers(record["materialized_link_wrappers"]),
        chosen_version=_string(record["chosen_version"], "chosen_version"),
        current_version=_string(record["current_version"], "current_version"),
        hold_rationale=_string(record["hold_rationale"], "hold_rationale"),
        artifact_url=artifact_url,
        artifact_sha256=_digest(record["artifact_sha256"], "artifact_sha256"),
        signature_url=signature_url,
        signature_sha256=(
            None
            if record["signature_sha256"] is None
            else _digest(record["signature_sha256"], "signature_sha256")
        ),
        archive_format=archive_format,
        allowed_top_level_entries=entries,
        embedded_version_command=command,
        max_artifact_bytes=_positive_int(
            record["max_artifact_bytes"], "max_artifact_bytes"
        ),
        max_signature_bytes=_positive_int(
            record["max_signature_bytes"], "max_signature_bytes"
        ),
        checksum_url=checksum_url,
        checksum_sha256=_digest(record["checksum_sha256"], "checksum_sha256"),
        signature_key_fingerprint=(
            None
            if record["signature_key_fingerprint"] is None
            else _openpgp_fingerprint(record["signature_key_fingerprint"])
        ),
        signature_reason=_string(record["signature_reason"], "signature_reason"),
        max_archive_members=_positive_int(
            record["max_archive_members"], "max_archive_members"
        ),
        max_extracted_bytes=_positive_int(
            record["max_extracted_bytes"], "max_extracted_bytes"
        ),
        upstream_integrity=(
            None
            if record["upstream_integrity"] is None
            else _sha512_sri(record["upstream_integrity"])
        ),
        runtime_dependencies=_runtime_dependencies(record["runtime_dependencies"]),
        regular_entrypoints=_regular_entrypoints(record["regular_entrypoints"]),
    )
    _validate_review_policy(parsed_record)
    return parsed_record


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            msg = f"duplicate JSON name: {name}"
            raise ToolchainError(msg)
        result[name] = value
    return result


def load_lock(path: Path) -> tuple[ToolchainRecord, ...]:
    """Load and validate a closed JSON trust ledger."""
    try:
        raw = cast(
            "object",
            json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_closed_json_object,
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        msg = "cannot read toolchain lock"
        raise ToolchainError(msg) from exc
    if type(raw) is not dict:
        msg = "toolchain lock has unknown or missing fields"
        raise ToolchainError(msg)
    record_map = cast("dict[str, object]", raw)
    if set(record_map) != {"schema_version", "records"}:
        msg = "toolchain lock has unknown or missing fields"
        raise ToolchainError(msg)
    if (
        type(record_map["schema_version"]) is not int
        or record_map["schema_version"] != 1
    ):
        msg = "schema_version must be the integer 1"
        raise ToolchainError(msg)
    if type(record_map["records"]) is not list:
        msg = "unsupported toolchain lock"
        raise ToolchainError(msg)
    records = tuple(
        _record_from_mapping(item)
        for item in cast("list[object]", record_map["records"])
    )
    if not records or len({(item.tool, item.target) for item in records}) != len(
        records
    ):
        msg = "toolchain lock records must be unique and non-empty"
        raise ToolchainError(msg)
    for record in records:
        for dependency in record.runtime_dependencies:
            matches = tuple(
                item
                for item in records
                if item.tool == dependency.tool
                and item.target == record.target
                and item.chosen_version == dependency.chosen_version
            )
            if len(matches) != 1:
                msg = "runtime dependency is not uniquely locked"
                raise ToolchainError(msg)
    return records


class HttpsDownloader:
    """Small no-proxy/no-redirect downloader for exact locked URLs."""

    def download(self, url: str, *, max_bytes: int) -> bytes:
        """Return one bounded body from a credential-free HTTPS URL."""
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            msg = "download URL is not a credential-free HTTPS URL"
            raise ToolchainError(msg)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
        )
        # Security rationale: urlsplit above requires HTTPS and rejects credentials.
        # No proxy/redirect handler is installed; reads stop at max_bytes + 1.
        # Ruff cannot infer these checks; S310 is limited to the next statement.
        request = urllib.request.Request(  # noqa: S310
            url,
            headers={"Accept-Encoding": "identity"},
        )
        try:
            with cast(
                "_HttpResponse",
                opener.open(request, timeout=30),
            ) as response:
                if response.status != HTTP_SUCCESS_STATUS:
                    msg = "toolchain download returned a non-200 status"
                    raise ToolchainError(msg)
                content_length = response.headers.get("Content-Length")
                if content_length is not None and (
                    not content_length.isdigit() or int(content_length) > max_bytes
                ):
                    msg = "toolchain download exceeds its byte ceiling"
                    raise ToolchainError(msg)
                body = response.read(max_bytes + 1)
        except (OSError, urllib.error.URLError) as exc:
            msg = "toolchain download failed"
            raise ToolchainError(msg) from exc
        if len(body) > max_bytes:
            msg = "toolchain download exceeds its byte ceiling"
            raise ToolchainError(msg)
        return body


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
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
        msg_0 = "redirects are forbidden for toolchain downloads"
        raise ToolchainError(msg_0)


def _verify_digest(payload: bytes, expected: str, field: str) -> None:
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        msg = f"{field} digest mismatch"
        raise ToolchainError(msg)


def _verify_checksum_manifest(
    payload: bytes, artifact: bytes, *, artifact_url: str
) -> None:
    """Bind the downloaded artifact to the publisher's exact checksum entry."""
    artifact_name = Path(urllib.parse.urlsplit(artifact_url).path).name
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        msg = "publisher checksum manifest is not ASCII"
        raise ToolchainError(msg) from exc
    expected: str | None = None
    for line in lines:
        fields = line.strip().split()
        if (
            len(fields) >= MINIMUM_CHECKSUM_FIELDS
            and Path(fields[-1].lstrip("*")).name == artifact_name
        ):
            expected = fields[0]
            break
    if expected is None:
        msg = "publisher checksum manifest omits the locked artifact"
        raise ToolchainError(msg)
    _verify_digest(artifact, expected, "publisher checksum")


# Retained solely for the offline lock-review workflow; runtime bootstrap must
# continue to authorize the repository-pinned artifact digest without fetching
# or activating publisher checksum evidence.
_ = _verify_checksum_manifest


def _safe_member_name(name: str) -> tuple[str, ...]:
    components = name.split("/")
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or "\x00" in name
        or any(not component for component in components[:-1])
    ):
        msg = "archive contains an unsafe member name"
        raise ToolchainError(msg)
    parts = tuple(part for part in components if part)
    if not parts or any(part in {".", ".."} for part in parts):
        msg = "archive contains a traversal member"
        raise ToolchainError(msg)
    return parts


def _safe_destination(stage: Path, parts: tuple[str, ...]) -> Path:
    destination = stage.joinpath(*parts)
    resolved_stage = stage.resolve()
    if resolved_stage not in destination.resolve().parents:
        msg = "archive member escapes the staging directory"
        raise ToolchainError(msg)
    return destination


def _top_level(parts: tuple[str, ...]) -> str:
    return parts[0]


def _enforce_extracted_size(sizes: Sequence[int], maximum: int) -> None:
    if any(size < 0 for size in sizes) or sum(sizes) > maximum:
        msg = "archive exceeds its extracted byte ceiling"
        raise ToolchainError(msg)


def _enforce_member_count(actual: int, maximum: int) -> None:
    if actual > maximum:
        msg = "archive exceeds its member count ceiling"
        raise ToolchainError(msg)


def _extract_zip(
    payload: bytes,
    stage: Path,
    allowed: frozenset[str],
    *,
    max_archive_members: int,
    max_extracted_bytes: int,
) -> None:
    archive = zipfile.ZipFile(io.BytesIO(payload))
    with archive:
        members = archive.infolist()
        _enforce_member_count(len(members), max_archive_members)
        _enforce_extracted_size(
            [member.file_size for member in members if not member.is_dir()],
            max_extracted_bytes,
        )
        seen: set[tuple[str, ...]] = set()
        for member in members:
            parts = _safe_member_name(member.filename)
            if parts in seen or _top_level(parts) not in allowed:
                msg = "archive contains a duplicate or unlisted entry"
                raise ToolchainError(msg)
            seen.add(parts)
            destination = _safe_destination(stage, parts)
            archive_mode = member.external_attr >> 16
            file_type = archive_mode & 0o170000
            if (
                file_type == stat.S_IFLNK
                or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                or archive_mode & 0o7000
            ):
                msg = "archive contains a symlink or special file"
                raise ToolchainError(msg)
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                destination.chmod((archive_mode & 0o777) or 0o700)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            destination.chmod((archive_mode & 0o777) or 0o600)


def _resolve_wrapper_target(
    link_parts: tuple[str, ...], target: str
) -> tuple[str, ...]:
    if not target or target.startswith("/") or "\\" in target or "\x00" in target:
        msg = "materialized wrapper target must be a relative safe path"
        raise ToolchainError(msg)
    components = target.split("/")
    if any(not component or component == "." for component in components):
        msg = "materialized wrapper target has an unsafe component"
        raise ToolchainError(msg)
    resolved = list(link_parts[:-1])
    for component in components:
        if component == "..":
            if len(resolved) <= 1:
                msg = "materialized wrapper target escapes its top-level entry"
                raise ToolchainError(msg)
            _ = resolved.pop()
        else:
            resolved.append(component)
    if not resolved or resolved[0] != link_parts[0]:
        msg = "materialized wrapper target escapes its top-level entry"
        raise ToolchainError(msg)
    return tuple(resolved)


def _open_tar(payload: bytes) -> tarfile.TarFile:
    try:
        return tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        msg = "invalid tar archive"
        raise ToolchainError(msg) from exc


def _validated_tar_member_parts(
    member: tarfile.TarInfo,
    *,
    seen: set[tuple[str, ...]],
    allowed: frozenset[str],
) -> tuple[str, ...]:
    parts = _safe_member_name(member.name)
    if parts in seen or _top_level(parts) not in allowed:
        msg = "archive contains a duplicate or unlisted entry"
        raise ToolchainError(msg)
    seen.add(parts)
    return parts


def _record_tar_wrapper(
    member: tarfile.TarInfo,
    parts: tuple[str, ...],
    *,
    declared_wrappers: Mapping[str, str],
    wrapper_targets: dict[tuple[str, ...], tuple[str, ...]],
) -> None:
    expected_target = declared_wrappers.get(member.name)
    if expected_target is None:
        msg = "archive contains an undeclared symlink wrapper"
        raise ToolchainError(msg)
    if member.linkname != expected_target:
        msg = "archive link target differs from reviewed wrapper policy"
        raise ToolchainError(msg)
    wrapper_targets[parts] = _resolve_wrapper_target(parts, member.linkname)


def _extract_regular_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    stage: Path,
    parts: tuple[str, ...],
) -> None:
    if not (member.isdir() or member.isreg()) or member.islnk() or member.mode & 0o7000:
        msg = "archive contains a symlink or special file"
        raise ToolchainError(msg)
    destination = _safe_destination(stage, parts)
    if member.isdir():
        destination.mkdir(parents=True, exist_ok=True)
        return
    source = archive.extractfile(member)
    if source is None:
        msg = "archive member has no readable body"
        raise ToolchainError(msg)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source, destination.open("xb") as target:
        shutil.copyfileobj(source, target, length=1024 * 1024)
    destination.chmod(member.mode & 0o777)


def _tar_wrapper_payload(
    stage: Path,
    link_parts: tuple[str, ...],
    target_parts: tuple[str, ...],
    wrapper_target: str,
) -> tuple[Path, bytes]:
    target_path = _safe_destination(stage, target_parts)
    if not target_path.is_file() or target_path.is_symlink():
        msg = "materialized wrapper target must be a regular extracted file"
        raise ToolchainError(msg)
    node_path = stage / link_parts[0] / "bin" / "node"
    if not node_path.is_file() or node_path.is_symlink():
        msg = "materialized wrapper requires a regular extracted node"
        raise ToolchainError(msg)
    destination = _safe_destination(stage, link_parts)
    if destination.exists() or destination.is_symlink():
        msg = "materialized wrapper conflicts with an extracted path"
        raise ToolchainError(msg)
    wrapper = (
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import sys\n"
        "here = os.path.dirname(os.path.abspath(__file__))\n"
        "node = os.path.join(here, 'node')\n"
        f"target = os.path.normpath(os.path.join(here, {wrapper_target!r}))\n"
        "os.execv(node, [node, target, *sys.argv[1:]])\n"
    ).encode()
    return destination, wrapper


def _materialize_tar_wrappers(
    stage: Path,
    declared_wrappers: Mapping[str, str],
    wrapper_targets: Mapping[tuple[str, ...], tuple[str, ...]],
    regular_bytes: int,
    maximum_bytes: int,
) -> None:
    declared_paths = {_safe_member_name(path) for path in declared_wrappers}
    if set(wrapper_targets) != declared_paths:
        msg = "archive is missing a declared link wrapper"
        raise ToolchainError(msg)
    if any(target in wrapper_targets for target in wrapper_targets.values()):
        msg = "materialized wrapper target cannot be a link chain"
        raise ToolchainError(msg)
    wrapper_payloads = [
        _tar_wrapper_payload(
            stage,
            link_parts,
            target_parts,
            declared_wrappers["/".join(link_parts)],
        )
        for link_parts, target_parts in wrapper_targets.items()
    ]
    _enforce_extracted_size(
        [regular_bytes, *(len(payload) for _, payload in wrapper_payloads)],
        maximum_bytes,
    )
    for destination, wrapper in wrapper_payloads:
        destination.parent.mkdir(parents=True, exist_ok=True)
        _ = destination.write_bytes(wrapper)
        destination.chmod(0o755)


def _extract_tar(payload: bytes, stage: Path, record: ToolchainRecord) -> None:
    with _open_tar(payload) as archive:
        members = archive.getmembers()
        _enforce_member_count(len(members), record.max_archive_members)
        regular_bytes = sum(member.size for member in members if member.isreg())
        _enforce_extracted_size([regular_bytes], record.max_extracted_bytes)
        declared_wrappers = {
            item.archive_path: item.target for item in record.materialized_link_wrappers
        }
        wrapper_targets: dict[tuple[str, ...], tuple[str, ...]] = {}
        seen: set[tuple[str, ...]] = set()
        allowed = frozenset(record.allowed_top_level_entries)
        for member in members:
            parts = _validated_tar_member_parts(
                member,
                seen=seen,
                allowed=allowed,
            )
            if member.issym():
                _record_tar_wrapper(
                    member,
                    parts,
                    declared_wrappers=declared_wrappers,
                    wrapper_targets=wrapper_targets,
                )
            else:
                _extract_regular_tar_member(archive, member, stage, parts)
        _materialize_tar_wrappers(
            stage,
            declared_wrappers,
            wrapper_targets,
            regular_bytes,
            record.max_extracted_bytes,
        )


def _default_version_checker(
    path: Path, command: tuple[str, ...], record: ToolchainRecord
) -> str:
    argv = tuple(item.replace("{path}", path.as_posix()) for item in command)
    try:
        # Security rationale: argv is rendered from the reviewed, digest-pinned
        # extracted artifact; shell=False and a fixed timeout are mandatory.
        # Ruff cannot infer these checks; S603 is limited to the next statement.
        completed = subprocess.run(  # noqa: S603
            argv,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        msg = "installed tool version probe failed"
        raise ToolchainError(msg) from exc
    if completed.stderr:
        msg = "installed tool version probe wrote to stderr"
        raise ToolchainError(msg)
    if record.tool == "uv":
        expected_stdout = f"uv {record.chosen_version} ({record.target})\n"
    elif record.tool == "node":
        expected_stdout = f"v{record.chosen_version}\n"
    elif record.tool == "npm":
        expected_stdout = f"{record.chosen_version}\n"
    else:
        expected_stdout = f"{record.tool} {record.chosen_version}\n"
    if completed.stdout != expected_stdout:
        msg = (
            "installed npm version output is not exact"
            if record.tool == "npm"
            else "installed tool version output is not exact"
        )
        raise ToolchainError(msg)
    return record.chosen_version


def _render_version_command(
    path: Path,
    command: tuple[str, ...],
    dependency_executables: Mapping[str, Path],
) -> tuple[str, ...]:
    rendered: list[str] = []
    for item in command:
        value = item.replace("{path}", path.as_posix())
        for tool, executable in dependency_executables.items():
            value = value.replace(f"{{dependency:{tool}}}", executable.as_posix())
        if "{dependency:" in value:
            msg = "version command contains an unresolved dependency"
            raise ToolchainError(msg)
        rendered.append(value)
    return tuple(rendered)


def _materialize_regular_entrypoints(
    record: ToolchainRecord,
    *,
    stage: Path,
    destination: Path,
    dependency_executables: Mapping[str, Path],
) -> None:
    wrappers: list[tuple[Path, bytes]] = []
    for entrypoint in record.regular_entrypoints:
        path_parts = _closed_relative_path(entrypoint.path, "regular entrypoint path")
        target_parts = _closed_relative_path(
            entrypoint.target, "regular entrypoint target"
        )
        staged_target = _safe_destination(stage, target_parts)
        if not staged_target.is_file() or staged_target.is_symlink():
            msg = "regular entrypoint target must be a regular extracted file"
            raise ToolchainError(msg)
        staged_entrypoint = _safe_destination(stage, path_parts)
        if staged_entrypoint.exists() or staged_entrypoint.is_symlink():
            msg = "regular entrypoint conflicts with an extracted path"
            raise ToolchainError(msg)
        dependency = dependency_executables[entrypoint.dependency_tool]
        final_target = destination.joinpath(*target_parts)
        wrapper = (
            "#!/bin/sh\n"
            f"exec {shlex.quote(dependency.as_posix())} "
            f'{shlex.quote(final_target.as_posix())} "$@"\n'
        ).encode()
        wrappers.append((staged_entrypoint, wrapper))
    if wrappers:
        existing_bytes = sum(
            path.stat().st_size for path in stage.rglob("*") if path.is_file()
        )
        _enforce_extracted_size(
            [existing_bytes, *(len(body) for _, body in wrappers)],
            record.max_extracted_bytes,
        )
    for path, body in wrappers:
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_bytes(body)
        path.chmod(0o755)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
    except OSError as exc:
        msg = "cannot read runtime dependency executable"
        raise ToolchainError(msg) from exc
    return digest.hexdigest()


def _validated_dependency_executable(
    dependency: RuntimeDependency,
    root: Path,
) -> Path:
    if not root.is_absolute():
        msg = "runtime dependency root must be absolute"
        raise ToolchainError(msg)
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        msg = "runtime dependency root does not exist"
        raise ToolchainError(msg) from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        msg = "runtime dependency root must be a real directory"
        raise ToolchainError(msg)
    parts = _safe_member_name(dependency.executable_path)
    executable = root.joinpath(*parts)
    current = root
    try:
        for part in parts:
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                msg = "runtime dependency path cannot contain symlinks"
                raise ToolchainError(msg)
    except OSError as exc:
        msg = "runtime dependency executable does not exist"
        raise ToolchainError(msg) from exc
    metadata = executable.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        msg = "runtime dependency executable must be a regular executable"
        raise ToolchainError(msg)
    if _file_sha256(executable) != dependency.executable_sha256:
        msg = "runtime dependency executable digest mismatch"
        raise ToolchainError(msg)
    return executable


def _validate_dependency_version(
    dependency: RuntimeDependency,
    executable: Path,
) -> None:
    try:
        # Security rationale: the executable is absolute, regular, and executable,
        # SHA-256 pinned, shell=False, and constrained by a fixed timeout.
        # Ruff cannot infer these checks; S603 is limited to the next statement.
        completed = subprocess.run(  # noqa: S603
            (executable, "--version"),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        msg = "runtime dependency version probe failed"
        raise ToolchainError(msg) from exc
    if completed.stderr or completed.stdout != f"v{dependency.chosen_version}\n":
        msg = "runtime dependency version output is not exact"
        raise ToolchainError(msg)


def _validated_dependency_executables(
    record: ToolchainRecord, dependency_roots: Mapping[str, Path]
) -> dict[str, Path]:
    executables: dict[str, Path] = {}
    for dependency in record.runtime_dependencies:
        executable = _validated_dependency_executable(
            dependency,
            dependency_roots[dependency.tool],
        )
        _validate_dependency_version(dependency, executable)
        executables[dependency.tool] = executable
    return executables


def _validate_tool_root(tool_root: Path) -> None:
    """Require a caller-created, private directory as the publication root."""
    try:
        metadata = tool_root.lstat()
    except OSError as exc:
        msg = "tool root must already exist"
        raise ToolchainError(msg) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        msg = "tool root must be a real directory"
        raise ToolchainError(msg)
    if stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE:
        msg = "tool root must have mode 0700"
        raise ToolchainError(msg)
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        msg = "tool root must be owned by the current user"
        raise ToolchainError(msg)


def _atomic_publish_noreplace(source: Path, destination: Path) -> None:
    """Atomically rename one staged directory without replacing any target."""
    if sys.platform != "linux":
        msg = "atomic no-replace publication requires Linux"
        raise ToolchainError(msg)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = cast("_RenameAt2", libc.renameat2)
    except (AttributeError, OSError) as exc:
        msg = "Linux renameat2 is unavailable"
        raise ToolchainError(msg) from exc
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    result = renameat2(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(destination),
        rename_noreplace,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        msg = "refusing to replace an existing installation"
        raise ToolchainError(msg)
    error = OSError(error_number, os.strerror(error_number), destination)
    msg = "atomic tool publication failed"
    raise ToolchainError(msg) from error


def _validated_install_dependencies(
    record: ToolchainRecord,
    dependency_roots: Mapping[str, Path] | None,
) -> dict[str, Path]:
    roots = dependency_roots or {}
    required_dependencies = {item.tool for item in record.runtime_dependencies}
    provided_dependencies = set(roots)
    if required_dependencies - provided_dependencies:
        msg = "required runtime dependency is missing"
        raise ToolchainError(msg)
    if provided_dependencies - required_dependencies:
        msg = "unexpected runtime dependency was provided"
        raise ToolchainError(msg)
    return _validated_dependency_executables(record, roots)


def _require_absent_destination(destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        msg = "refusing to replace an existing installation"
        raise ToolchainError(msg)


def _extract_locked_archive(
    record: ToolchainRecord,
    artifact: bytes,
    stage: Path,
) -> None:
    allowed = frozenset(record.allowed_top_level_entries)
    try:
        if record.archive_format in {"wheel", "zip"}:
            _extract_zip(
                artifact,
                stage,
                allowed,
                max_archive_members=record.max_archive_members,
                max_extracted_bytes=record.max_extracted_bytes,
            )
        else:
            _extract_tar(artifact, stage, record)
    except (tarfile.TarError, zipfile.BadZipFile) as exc:
        msg = "invalid or corrupt toolchain archive"
        raise ToolchainError(msg) from exc


def _installed_archive_path(record: ToolchainRecord, stage: Path) -> Path:
    installed_path = stage / record.allowed_top_level_entries[0]
    if not installed_path.exists() or installed_path.is_symlink():
        msg = "archive did not publish the expected top-level entry"
        raise ToolchainError(msg)
    return installed_path


def _validate_installed_version(
    record: ToolchainRecord,
    installed_path: Path,
    dependency_executables: Mapping[str, Path],
    version_checker: VersionChecker | None,
) -> None:
    version_command = _render_version_command(
        installed_path,
        record.embedded_version_command,
        dependency_executables,
    )
    if version_checker is None:
        observed = _default_version_checker(installed_path, version_command, record)
    else:
        observed = version_checker(installed_path, version_command)
    if observed != record.chosen_version:
        msg = "installed tool version mismatch"
        raise ToolchainError(msg)


def install_tool(
    record: ToolchainRecord,
    *,
    destination: Path,
    downloader: Downloader,
    version_checker: VersionChecker | None = None,
    dependency_roots: Mapping[str, Path] | None = None,
) -> Path:
    """Verify, safely extract, version-check, and atomically publish one tool."""
    _validate_review_policy(record)
    if record.current_version != record.chosen_version:
        msg = "toolchain current/chosen version drift"
        raise ToolchainError(msg)
    dependency_executables = _validated_install_dependencies(record, dependency_roots)
    _require_absent_destination(destination)
    _validate_tool_root(destination.parent)
    artifact = downloader.download(
        record.artifact_url, max_bytes=record.max_artifact_bytes
    )
    _verify_digest(artifact, record.artifact_sha256, "artifact")
    stage = Path(tempfile.mkdtemp(prefix=f".{record.tool}-", dir=destination.parent))
    try:
        stage.chmod(PRIVATE_DIRECTORY_MODE)
        _extract_locked_archive(record, artifact, stage)
        installed_path = _installed_archive_path(record, stage)
        _materialize_regular_entrypoints(
            record,
            stage=stage,
            destination=destination,
            dependency_executables=dependency_executables,
        )
        _validate_installed_version(
            record,
            installed_path,
            dependency_executables,
            version_checker,
        )
        _require_absent_destination(destination)
        _atomic_publish_noreplace(stage, destination)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return destination


# Compatibility rationale: selection and trust seams remain explicit.
# Bundling or typed kwargs could hide misspelled security controls.
# PLR0913 is limited to this stable, closed install boundary.
def install_from_lock(  # noqa: PLR0913
    lock_path: Path,
    *,
    tool: str,
    target: str,
    destination: Path,
    downloader: Downloader | None = None,
    version_checker: VersionChecker | None = None,
    dependency_roots: Mapping[str, Path] | None = None,
) -> Path:
    """Select one exact record and install it using the supplied trust seams."""
    records = load_lock(lock_path)
    matches = tuple(
        item for item in records if item.tool == tool and item.target == target
    )
    if len(matches) != 1:
        msg = "toolchain target is not uniquely locked"
        raise ToolchainError(msg)
    if downloader is None:
        msg = "network seam must be explicit"
        raise ToolchainError(msg)
    return install_tool(
        matches[0],
        destination=destination,
        downloader=downloader,
        version_checker=version_checker,
        dependency_roots=dependency_roots,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--lock", type=Path, required=True)
    _ = parser.add_argument("--tool", required=True)
    _ = parser.add_argument("--target", required=True)
    _ = parser.add_argument("--destination", type=Path, required=True)
    _ = parser.add_argument("--dependency", action="append")
    return parser


@dataclass(frozen=True, slots=True)
class _BootstrapArguments:
    """Strictly narrowed bootstrap command-line values."""

    lock: Path
    tool: str
    target: str
    destination: Path
    dependencies: tuple[str, ...]


def _parse_arguments(argv: Sequence[str] | None) -> _BootstrapArguments:
    values = cast("dict[str, object]", vars(_parser().parse_args(argv)))
    lock = values["lock"]
    tool = values["tool"]
    target = values["target"]
    destination = values["destination"]
    dependencies = values["dependency"]
    if (
        not isinstance(lock, Path)
        or type(tool) is not str
        or type(target) is not str
        or not isinstance(destination, Path)
    ):
        msg = "bootstrap arguments have invalid runtime types"
        raise ToolchainError(msg)
    if dependencies is None:
        dependency_values: tuple[str, ...] = ()
    elif type(dependencies) is list and all(
        type(item) is str for item in cast("list[object]", dependencies)
    ):
        dependency_values = tuple(cast("list[str]", dependencies))
    else:
        msg = "bootstrap dependencies have invalid runtime types"
        raise ToolchainError(msg)
    return _BootstrapArguments(
        lock=lock,
        tool=tool,
        target=target,
        destination=destination,
        dependencies=dependency_values,
    )


def _dependency_arguments(values: Sequence[str]) -> dict[str, Path]:
    dependencies: dict[str, Path] = {}
    for value in values:
        tool, separator, path = value.partition("=")
        if not separator or not tool or not path or tool in dependencies:
            msg = "dependency must be a unique TOOL=PATH pair"
            raise ToolchainError(msg)
        dependencies[tool] = Path(path)
    return dependencies


def main(argv: Sequence[str] | None = None) -> int:
    """Install one locked tool, returning a stable nonzero status on rejection."""
    try:
        arguments = _parse_arguments(argv)
        dependency_roots = _dependency_arguments(arguments.dependencies)
        _ = install_from_lock(
            arguments.lock,
            tool=arguments.tool,
            target=arguments.target,
            destination=arguments.destination,
            downloader=HttpsDownloader(),
            dependency_roots=dependency_roots,
        )
    except ToolchainError as exc:
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write(f"bootstrap failed: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
