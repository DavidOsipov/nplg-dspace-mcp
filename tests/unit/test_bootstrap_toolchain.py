# Copyright (c) 2026 David Osipov
"""Local-only tests for fail-closed toolchain installation."""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import os
import stat
import tarfile
import tempfile
import unittest
import urllib.request
import zipfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Self
from unittest import mock

import pytest

from nplg_mcp.json_types import JsonObject, JsonValue, dataclass_to_json, dump_json
from scripts.bootstrap_toolchain import (
    HttpsDownloader,
    MaterializedLinkWrapper,
    RegularEntrypoint,
    RuntimeDependency,
    ToolchainError,
    ToolchainRecord,
    install_from_lock,
    install_tool,
    load_lock,
    main,
)

EXECUTABLE_MODE = 0o755
EXPECTED_DESTINATION_CHECKS = 2
DOWNLOAD_TIMEOUT_SECONDS = 30
CLI_FAILURE_STATUS = 2
ABSOLUTE_NPM_PATH = (Path("/") / "tmp" / "npm").as_posix()
ABSOLUTE_NPM_TARGET = (Path("/") / "tmp" / "npm-cli.js").as_posix()
EXPECTED_NPM_INTEGRITY_PARTS = (
    "sha512-T67M4L5wNm0cZ7EBLErcEkY1SmzEW/WJ+SADBzsFUY1UdAPf",
    "FHXFQtZ6SEXiK0+vzXysCvAsepbMaBTwnrAD+w==",
)


type TarMemberFixture = tuple[str, bytes, bytes | str, int]
type LockFieldCase = tuple[str, str, JsonValue, str]


@dataclass(slots=True)
class _Downloader:
    bodies: dict[str, bytes]

    def download(self, url: str, *, max_bytes: int) -> bytes:
        body = self.bodies[url]
        if len(body) > max_bytes:
            msg = "fixture exceeds limit"
            raise ToolchainError(msg)
        return body


@dataclass(slots=True)
class _ArtifactOnlyDownloader:
    url: str
    artifact: bytes
    requested_urls: list[str] = field(default_factory=list[str], init=False)

    def download(self, url: str, *, max_bytes: int) -> bytes:
        self.requested_urls.append(url)
        if url != self.url:
            msg = "runtime requested lock-review evidence"
            raise ToolchainError(msg)
        if len(self.artifact) > max_bytes:
            msg = "fixture exceeds limit"
            raise ToolchainError(msg)
        return self.artifact


@dataclass(slots=True)
class _HttpFixtureResponse:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict[str, str])

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> None:
        del exception_type, exception, traceback

    def read(self, maximum: int) -> bytes:
        return self.body[:maximum]


@dataclass(slots=True)
class _HttpFixtureOpener:
    response: _HttpFixtureResponse
    failure: OSError | None = None
    requests: list[tuple[urllib.request.Request, int]] = field(
        default_factory=list[tuple[urllib.request.Request, int]], init=False
    )

    def open(
        self,
        request: urllib.request.Request,
        *,
        timeout: int,
    ) -> _HttpFixtureResponse:
        self.requests.append((request, timeout))
        if self.failure is not None:
            raise self.failure
        return self.response


@dataclass(slots=True)
class _RenameAt2Failure:
    argtypes: object = None
    restype: object = None

    def __call__(self, *arguments: object) -> int:
        del arguments
        return -1


@dataclass(slots=True)
class _LibcRenameFailure:
    renameat2: _RenameAt2Failure = field(default_factory=_RenameAt2Failure)


def _archive(
    entries: dict[str, bytes], *, modes: dict[str, int] | None = None
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, body in entries.items():
            if modes is None or name not in modes:
                archive.writestr(name, body)
                continue
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | modes[name]) << 16
            archive.writestr(member, body)
    return output.getvalue()


def _raw_zip_member(name: str, *, mode: int, body: bytes = b"payload") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        member = zipfile.ZipInfo(name)
        member.create_system = 3
        member.external_attr = mode << 16
        archive.writestr(member, body)
    return output.getvalue()


def _raw_tar_member(
    name: str,
    *,
    mode: int,
    member_type: bytes = tarfile.REGTYPE,
    body: bytes = b"payload",
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.mode = mode
        member.type = member_type
        if member.isreg():
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        else:
            member.linkname = "fixture-tool"
            archive.addfile(member)
    return output.getvalue()


def _tar_archive(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, body in entries.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o600
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    return output.getvalue()


def _tar_members(
    entries: list[TarMemberFixture],
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, member_type, payload, mode in entries:
            member = tarfile.TarInfo(name)
            member.type = member_type
            member.mode = mode
            if member_type == tarfile.REGTYPE:
                assert isinstance(payload, bytes)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            else:
                assert isinstance(payload, str)
                member.linkname = payload
                archive.addfile(member)
    return output.getvalue()


def _version_script_archive(*, stdout: str, stderr: str = "") -> bytes:
    script = (
        f"import sys\nsys.stdout.write({stdout!r})\nsys.stderr.write({stderr!r})\n"
    ).encode()
    return _archive({"fixture-tool": script})


def _record(artifact: bytes, *, version: str = "1.2.3") -> ToolchainRecord:
    checksum = f"{hashlib.sha256(artifact).hexdigest()}  tool.zip\n".encode("ascii")
    return ToolchainRecord(
        tool="fixture-tool",
        target="x86_64-unknown-linux-gnu",
        publisher="Fixture Tool Project",
        runtime_trust_policy="repository_pinned_sha256",
        lock_review_status="accepted",
        materialized_link_wrappers=(),
        chosen_version=version,
        current_version=version,
        hold_rationale="fixture",
        artifact_url="https://example.test/tool.zip",
        artifact_sha256=hashlib.sha256(artifact).hexdigest(),
        signature_url="https://example.test/tool.sig",
        signature_sha256=hashlib.sha256(b"valid-signature").hexdigest(),
        archive_format="zip",
        allowed_top_level_entries=("fixture-tool",),
        embedded_version_command=("{path}", "--version"),
        max_artifact_bytes=1024 * 1024,
        max_signature_bytes=1024,
        checksum_url="https://example.test/tool.sha256",
        checksum_sha256=hashlib.sha256(checksum).hexdigest(),
        signature_key_fingerprint="A" * 40,
        signature_reason="fixture has a detached test signature",
    )


def _checksum_body(artifact: bytes) -> bytes:
    return f"{hashlib.sha256(artifact).hexdigest()}  tool.zip\n".encode("ascii")


def _bodies(record: ToolchainRecord, artifact: bytes) -> dict[str, bytes]:
    assert record.checksum_url is not None
    assert record.signature_url is not None
    return {
        record.artifact_url: artifact,
        record.checksum_url: _checksum_body(artifact),
        record.signature_url: b"valid-signature",
    }


def _write_lock(path: Path, record: ToolchainRecord) -> None:
    _write_raw_lock(path, _record_json(record))


def _record_json(record: ToolchainRecord) -> JsonObject:
    return dataclass_to_json(record, context="toolchain test record")


def _write_raw_lock(
    path: Path,
    record: JsonObject,
    *,
    schema_version: JsonValue = 1,
) -> None:
    lock: JsonObject = {"schema_version": schema_version, "records": [record]}
    _ = path.write_text(dump_json(lock), encoding="utf-8")


def _managed_node(root: Path, *, node_version: str = "24.19.0") -> tuple[Path, bytes]:
    executable = root / "node-v24.19.0-linux-x64" / "bin" / "node"
    executable.parent.mkdir(parents=True)
    body = (
        "#!/usr/bin/python3\n"
        "import pathlib\n"
        "import sys\n"
        f"node_version = {node_version!r}\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print(f'v{node_version}')\n"
        "elif len(sys.argv) == 3 and sys.argv[2] == '--version':\n"
        "    print(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
        "else:\n"
        "    raise SystemExit(2)\n"
    ).encode()
    _ = executable.write_bytes(body)
    executable.chmod(0o755)
    return executable, body


def _npm_record(
    artifact: bytes, node_body: bytes, *, version: str = "11.18.0"
) -> ToolchainRecord:
    return replace(
        _record(artifact, version=version),
        tool="npm",
        archive_format="tar.gz",
        allowed_top_level_entries=("package",),
        embedded_version_command=(
            "{dependency:node}",
            "{path}/bin/npm-cli.js",
            "--version",
        ),
        upstream_integrity="sha512-" + base64.b64encode(b"x" * 64).decode("ascii"),
        runtime_dependencies=(
            RuntimeDependency(
                tool="node",
                chosen_version="24.19.0",
                executable_path="node-v24.19.0-linux-x64/bin/node",
                executable_sha256=hashlib.sha256(node_body).hexdigest(),
            ),
        ),
        regular_entrypoints=(
            RegularEntrypoint(
                path="bin/npm",
                target="package/bin/npm-cli.js",
                dependency_tool="node",
            ),
            RegularEntrypoint(
                path="bin/npx",
                target="package/bin/npx-cli.js",
                dependency_tool="node",
            ),
        ),
    )


class BootstrapToolchainTests(unittest.TestCase):
    """Exercise the fail-closed local bootstrap boundary."""

    def test_lock_rejects_malformed_field_shapes_and_values(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        base = _record_json(_record(artifact))
        empty_object: JsonObject = {}
        wrapper: JsonObject = {
            "archive_path": "fixture-tool/bin/npm",
            "target": "../lib/npm.js",
        }
        dependency: JsonObject = {
            "tool": "node",
            "chosen_version": "24.19.0",
            "executable_path": "node/bin/node",
            "executable_sha256": "0" * 64,
        }
        entrypoint: JsonObject = {
            "path": "bin/npm",
            "target": "fixture-tool/npm.js",
            "dependency_tool": "node",
        }
        cases: tuple[LockFieldCase, ...] = (
            ("digest", "artifact_sha256", "not-a-digest", "SHA-256 digest"),
            ("positive-integer", "max_archive_members", 0, "positive integer"),
            (
                "string-array",
                "allowed_top_level_entries",
                [],
                "non-empty string array",
            ),
            (
                "wrappers-array",
                "materialized_link_wrappers",
                "not-an-array",
                "wrappers must be an array",
            ),
            (
                "wrapper-shape",
                "materialized_link_wrappers",
                [empty_object],
                "wrapper has unknown or missing fields",
            ),
            (
                "wrapper-duplicate",
                "materialized_link_wrappers",
                [wrapper, dict(wrapper)],
                "wrapper paths must be unique",
            ),
            (
                "dependencies-array",
                "runtime_dependencies",
                "not-an-array",
                "dependencies must be an array",
            ),
            (
                "dependency-shape",
                "runtime_dependencies",
                [empty_object],
                "dependency has unknown or missing fields",
            ),
            (
                "dependency-duplicate",
                "runtime_dependencies",
                [dependency, dict(dependency)],
                "dependency tools must be unique",
            ),
            (
                "entrypoints-array",
                "regular_entrypoints",
                "not-an-array",
                "entrypoints must be an array",
            ),
            (
                "entrypoint-shape",
                "regular_entrypoints",
                [empty_object],
                "entrypoint has unknown or missing fields",
            ),
            (
                "entrypoint-duplicate",
                "regular_entrypoints",
                [entrypoint, dict(entrypoint)],
                "entrypoint paths must be unique",
            ),
            ("archive-format", "archive_format", "rar", "unsupported"),
            ("artifact-url", "artifact_url", "http://example.test/x", "HTTPS URL"),
            ("signature-url-type", "signature_url", 7, "null or a string"),
            (
                "duplicate-top-level",
                "allowed_top_level_entries",
                ["fixture-tool", "fixture-tool"],
                "top_level_entries must be unique",
            ),
            (
                "missing-path-placeholder",
                "embedded_version_command",
                ["fixture-tool", "--version"],
                r"must contain \{path\}",
            ),
            ("signature-rationale", "signature_reason", "", "non-empty string"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock.json"
            for name, field_name, value, expected in cases:
                with self.subTest(case=name):
                    record = dict(base)
                    record[field_name] = value
                    _write_raw_lock(lock, record)
                    with pytest.raises(ToolchainError, match=expected):
                        _ = load_lock(lock)

    def test_lock_rejects_relational_review_policy_conflicts(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        base = _record_json(_record(artifact))
        wrapper: JsonObject = {
            "archive_path": "fixture-tool/bin/npm",
            "target": "../lib/npm.js",
        }
        dependency: JsonObject = {
            "tool": "node",
            "chosen_version": "24.19.0",
            "executable_path": "node/bin/node",
            "executable_sha256": "0" * 64,
        }
        entrypoint: JsonObject = {
            "path": "bin/npm",
            "target": "fixture-tool/npm.js",
            "dependency_tool": "node",
        }
        unsigned_with_key = dict(base)
        unsigned_with_key["signature_url"] = None
        unsigned_with_key["signature_sha256"] = None
        zip_wrapper = dict(base)
        zip_wrapper["materialized_link_wrappers"] = [wrapper]
        zip_entrypoint = dict(base)
        zip_entrypoint["regular_entrypoints"] = [entrypoint]
        undeclared_dependency = dict(base)
        undeclared_dependency["archive_format"] = "tar.gz"
        undeclared_dependency["regular_entrypoints"] = [entrypoint]
        outside_root = dict(base)
        outside_root["archive_format"] = "tar.gz"
        outside_root["runtime_dependencies"] = [dependency]
        outside_entrypoint = dict(entrypoint)
        outside_entrypoint["target"] = "outside/npm.js"
        outside_root["regular_entrypoints"] = [outside_entrypoint]
        non_npm_integrity = dict(base)
        non_npm_integrity["upstream_integrity"] = "sha512-" + base64.b64encode(
            b"x" * 64
        ).decode("ascii")
        pending_review = dict(base)
        pending_review["lock_review_status"] = "pending"
        unlocked_dependency = dict(base)
        unlocked_dependency["runtime_dependencies"] = [dependency]
        cases: tuple[tuple[str, JsonObject, str], ...] = (
            ("unsigned-key", unsigned_with_key, "cannot contain signature material"),
            ("zip-wrapper", zip_wrapper, "only tar archives.*link wrappers"),
            ("zip-entrypoint", zip_entrypoint, "only tar archives.*entrypoints"),
            (
                "undeclared-entrypoint-dependency",
                undeclared_dependency,
                "dependency is not declared",
            ),
            ("entrypoint-outside-root", outside_root, "outside reviewed archive roots"),
            ("non-npm-integrity", non_npm_integrity, "non-npm record"),
            ("pending-review", pending_review, "review status is not accepted"),
            (
                "unlocked-runtime-dependency",
                unlocked_dependency,
                "runtime dependency is not uniquely locked",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock.json"
            for name, record, expected in cases:
                with self.subTest(case=name):
                    _write_raw_lock(lock, record)
                    with pytest.raises(ToolchainError, match=expected):
                        _ = load_lock(lock)

    def test_lock_rejects_malformed_document_envelopes(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record_json(_record(artifact))
        documents: tuple[tuple[str, JsonValue, str], ...] = (
            ("non-object", [], "unknown or missing fields"),
            (
                "unknown-top-level",
                {"schema_version": 1, "records": [record], "extra": True},
                "unknown or missing fields",
            ),
            (
                "records-not-array",
                {"schema_version": 1, "records": "invalid"},
                "unsupported toolchain lock",
            ),
            (
                "empty-records",
                {"schema_version": 1, "records": []},
                "records must be unique and non-empty",
            ),
            (
                "duplicate-records",
                {"schema_version": 1, "records": [record, record]},
                "records must be unique and non-empty",
            ),
            (
                "non-object-record",
                {"schema_version": 1, "records": [False]},
                "record must be an object",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock.json"
            with pytest.raises(ToolchainError, match="cannot read toolchain lock"):
                _ = load_lock(lock)
            _ = lock.write_bytes(b"\xff")
            with pytest.raises(ToolchainError, match="cannot read toolchain lock"):
                _ = load_lock(lock)
            for name, document, expected in documents:
                with self.subTest(case=name):
                    _ = lock.write_text(dump_json(document), encoding="utf-8")
                    with pytest.raises(ToolchainError, match=expected):
                        _ = load_lock(lock)

    def test_https_downloader_rejects_invalid_urls_before_network_access(self) -> None:
        downloader = HttpsDownloader()
        for url in (
            "http://example.test/tool",
            "https://user:secret@example.test/tool",
            "https:///tool",
        ):
            with (
                self.subTest(url=url),
                pytest.raises(ToolchainError, match="credential-free HTTPS URL"),
            ):
                _ = downloader.download(url, max_bytes=4)

    def test_https_downloader_enforces_status_and_byte_ceilings(self) -> None:
        url = "https://example.test/tool"
        scenarios = (
            (
                "status",
                _HttpFixtureResponse(status=503, body=b""),
                None,
                4,
                "non-200 status",
            ),
            (
                "invalid-content-length",
                _HttpFixtureResponse(
                    status=200,
                    body=b"ok",
                    headers={"Content-Length": "invalid"},
                ),
                None,
                4,
                "byte ceiling",
            ),
            (
                "oversized-content-length",
                _HttpFixtureResponse(
                    status=200,
                    body=b"12345",
                    headers={"Content-Length": "5"},
                ),
                None,
                4,
                "byte ceiling",
            ),
            (
                "oversized-body",
                _HttpFixtureResponse(status=200, body=b"12345"),
                None,
                4,
                "byte ceiling",
            ),
            (
                "transport-failure",
                _HttpFixtureResponse(status=200, body=b""),
                OSError("connection failed"),
                4,
                "download failed",
            ),
        )
        for name, response, failure, maximum, expected in scenarios:
            with self.subTest(case=name):
                opener = _HttpFixtureOpener(response=response, failure=failure)
                with (
                    mock.patch.object(
                        urllib.request,
                        "build_opener",
                        return_value=opener,
                    ),
                    pytest.raises(ToolchainError, match=expected),
                ):
                    _ = HttpsDownloader().download(url, max_bytes=maximum)

    def test_https_downloader_returns_one_bounded_identity_encoded_body(self) -> None:
        url = "https://example.test/tool"
        opener = _HttpFixtureOpener(
            response=_HttpFixtureResponse(
                status=200,
                body=b"body",
                headers={"Content-Length": "4"},
            )
        )

        with mock.patch.object(
            urllib.request,
            "build_opener",
            return_value=opener,
        ):
            body = HttpsDownloader().download(url, max_bytes=4)

        assert body == b"body"
        assert len(opener.requests) == 1
        request, timeout = opener.requests[0]
        assert request.full_url == url
        assert request.get_header("Accept-encoding") == "identity"
        assert timeout == DOWNLOAD_TIMEOUT_SECONDS

    def test_install_rejects_an_empty_signature_review_rationale(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = replace(_record(artifact), signature_reason="")
        with (
            tempfile.TemporaryDirectory() as temporary,
            pytest.raises(
                ToolchainError, match="signature review evidence requires a rationale"
            ),
        ):
            _ = install_tool(
                record,
                destination=Path(temporary) / "fixture-tool",
                downloader=_ArtifactOnlyDownloader(
                    url=record.artifact_url,
                    artifact=artifact,
                ),
            )

    def test_archive_rejects_unlisted_zip_roots_and_invalid_tar_bytes(self) -> None:
        cases = (
            ("unlisted-zip", _archive({"other": b"payload"}), "zip", "unlisted"),
            ("invalid-tar", b"not-a-tar-archive", "tar.gz", "invalid tar"),
        )
        for name, artifact, archive_format, expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                record = replace(_record(artifact), archive_format=archive_format)
                destination = Path(temporary) / "fixture-tool"
                with pytest.raises(ToolchainError, match=expected):
                    _ = install_tool(
                        record,
                        destination=destination,
                        downloader=_ArtifactOnlyDownloader(
                            url=record.artifact_url,
                            artifact=artifact,
                        ),
                        version_checker=lambda _path, _command: "1.2.3",
                    )
                assert not destination.exists()

    def test_explicit_zip_and_tar_directories_are_safely_materialized(self) -> None:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=zipfile.ZIP_STORED
        ) as archive:
            directory = zipfile.ZipInfo("fixture-tool/")
            directory.create_system = 3
            directory.external_attr = (stat.S_IFDIR | 0o700) << 16
            archive.writestr(directory, b"")
        archives = (
            ("zip", zip_buffer.getvalue(), "zip"),
            (
                "tar",
                _raw_tar_member(
                    "fixture-tool",
                    mode=0o700,
                    member_type=tarfile.DIRTYPE,
                ),
                "tar.gz",
            ),
        )
        for name, artifact, archive_format in archives:
            with self.subTest(format=name), tempfile.TemporaryDirectory() as temporary:
                record = replace(_record(artifact), archive_format=archive_format)
                destination = Path(temporary) / "install"
                installed = install_tool(
                    record,
                    destination=destination,
                    downloader=_ArtifactOnlyDownloader(
                        url=record.artifact_url,
                        artifact=artifact,
                    ),
                    version_checker=lambda _path, _command: "1.2.3",
                )
                assert installed == destination
                assert (destination / "fixture-tool").is_dir()

    def test_version_validation_rejects_unresolved_or_unstartable_commands(
        self,
    ) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        records = (
            (
                "unresolved-dependency",
                replace(
                    _record(artifact),
                    embedded_version_command=("{dependency:ghost}", "{path}"),
                ),
                "unresolved dependency",
            ),
            (
                "unstartable-command",
                replace(
                    _record(artifact),
                    embedded_version_command=(
                        "/definitely/missing/toolchain-probe",
                        "{path}",
                    ),
                ),
                "version probe failed",
            ),
        )
        for name, record, expected in records:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "fixture-tool"
                with pytest.raises(ToolchainError, match=expected):
                    _ = install_tool(
                        record,
                        destination=destination,
                        downloader=_ArtifactOnlyDownloader(
                            url=record.artifact_url,
                            artifact=artifact,
                        ),
                    )
                assert not destination.exists()

    def test_npm_entrypoint_target_must_exist_without_path_conflicts(self) -> None:
        cases = (
            (
                "missing-target",
                {"package/bin/npm-cli.js": b"11.18.0"},
                ("package",),
                "target must be a regular extracted file",
            ),
            (
                "path-conflict",
                {
                    "package/bin/npm-cli.js": b"11.18.0",
                    "package/bin/npx-cli.js": b"11.18.0",
                    "bin/npm": b"conflict",
                },
                ("package", "bin"),
                "conflicts with an extracted path",
            ),
        )
        for name, entries, allowed, expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, node_body = _managed_node(root / "node")
                artifact = _tar_archive(entries)
                record = replace(
                    _npm_record(artifact, node_body),
                    allowed_top_level_entries=allowed,
                )
                destination = root / "npm"
                with pytest.raises(ToolchainError, match=expected):
                    _ = install_tool(
                        record,
                        destination=destination,
                        downloader=_ArtifactOnlyDownloader(
                            url=record.artifact_url,
                            artifact=artifact,
                        ),
                        dependency_roots={"node": root / "node"},
                    )
                assert not destination.exists()

    def test_runtime_dependency_paths_fail_closed_before_archive_install(self) -> None:
        artifact = _tar_archive(
            {
                "package/bin/npm-cli.js": b"11.18.0",
                "package/bin/npx-cli.js": b"11.18.0",
            }
        )
        cases = (
            ("relative-root", "root must be absolute"),
            ("missing-root", "root does not exist"),
            ("symlink-root", "root must be a real directory"),
            ("symlink-component", "path cannot contain symlinks"),
            ("missing-executable", "executable does not exist"),
            ("non-executable", "must be a regular executable"),
            ("probe-failure", "version probe failed"),
            ("unexpected-extra", "unexpected runtime dependency"),
        )
        for name, expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                node_root = root / "node"
                executable, node_body = _managed_node(node_root)
                dependency_root: Path = node_root
                extra_roots: dict[str, Path] = {}
                if name == "relative-root":
                    dependency_root = Path("relative-node-root")
                elif name == "missing-root":
                    dependency_root = root / "missing"
                elif name == "symlink-root":
                    dependency_root = root / "node-link"
                    dependency_root.symlink_to(node_root, target_is_directory=True)
                elif name == "symlink-component":
                    version_root = executable.parents[1]
                    real_version_root = root / "real-node-version"
                    _ = version_root.rename(real_version_root)
                    version_root.symlink_to(real_version_root, target_is_directory=True)
                elif name == "missing-executable":
                    executable.unlink()
                elif name == "non-executable":
                    executable.chmod(0o600)
                elif name == "probe-failure":
                    node_body = b"#!/definitely/missing/interpreter\n"
                    _ = executable.write_bytes(node_body)
                    executable.chmod(0o755)
                elif name == "unexpected-extra":
                    extra_roots["python"] = root / "python"
                record = _npm_record(artifact, node_body)
                with pytest.raises(ToolchainError, match=expected):
                    _ = install_tool(
                        record,
                        destination=root / "npm",
                        downloader=_ArtifactOnlyDownloader(
                            url=record.artifact_url,
                            artifact=artifact,
                        ),
                        dependency_roots={"node": dependency_root, **extra_roots},
                    )
                assert not (root / "npm").exists()

    def test_runtime_dependency_read_failure_aborts_before_download(self) -> None:
        artifact = _tar_archive(
            {
                "package/bin/npm-cli.js": b"11.18.0",
                "package/bin/npx-cli.js": b"11.18.0",
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable, node_body = _managed_node(root / "node")
            record = _npm_record(artifact, node_body)
            downloader = _ArtifactOnlyDownloader(
                url=record.artifact_url,
                artifact=artifact,
            )

            def fail_dependency_open(
                path: Path,
                *arguments: object,
                **keywords: object,
            ) -> object:
                assert path == executable
                assert arguments == ("rb",)
                assert keywords == {}
                message = "simulated dependency read failure"
                raise OSError(message)

            with (
                mock.patch.object(Path, "open", new=fail_dependency_open),
                pytest.raises(
                    ToolchainError,
                    match="cannot read runtime dependency executable",
                ),
            ):
                _ = install_tool(
                    record,
                    destination=root / "npm",
                    downloader=downloader,
                    dependency_roots={"node": root / "node"},
                )

            assert downloader.requested_urls == []
            assert not (root / "npm").exists()

    def test_install_rejects_unowned_roots_and_publication_capability_failures(
        self,
    ) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)

        def attempt(destination: Path) -> Path:
            return install_tool(
                record,
                destination=destination,
                downloader=_ArtifactOnlyDownloader(
                    url=record.artifact_url,
                    artifact=artifact,
                ),
                version_checker=lambda _path, _command: "1.2.3",
            )

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "ownership"
            with (
                mock.patch.object(os, "geteuid", return_value=-1),
                pytest.raises(ToolchainError, match="owned by the current user"),
            ):
                _ = attempt(destination)
            assert not destination.exists()

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "platform"
            with (
                mock.patch("scripts.bootstrap_toolchain.sys.platform", "darwin"),
                pytest.raises(ToolchainError, match="requires Linux"),
            ):
                _ = attempt(destination)
            assert not destination.exists()

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "missing-syscall"
            with (
                mock.patch(
                    "scripts.bootstrap_toolchain.ctypes.CDLL",
                    return_value=object(),
                ),
                pytest.raises(ToolchainError, match="renameat2 is unavailable"),
            ):
                _ = attempt(destination)
            assert not destination.exists()

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "syscall-failure"
            with (
                mock.patch(
                    "scripts.bootstrap_toolchain.ctypes.CDLL",
                    return_value=_LibcRenameFailure(),
                ),
                mock.patch(
                    "scripts.bootstrap_toolchain.ctypes.get_errno",
                    return_value=errno.EIO,
                ),
                pytest.raises(ToolchainError, match="atomic tool publication failed"),
            ):
                _ = attempt(destination)
            assert not destination.exists()

    def test_install_rejects_an_archive_missing_its_primary_root(self) -> None:
        artifact = _archive({"metadata": b"payload"})
        record = replace(
            _record(artifact),
            allowed_top_level_entries=("fixture-tool", "metadata"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            with pytest.raises(
                ToolchainError, match="did not publish the expected top-level entry"
            ):
                _ = install_tool(
                    record,
                    destination=destination,
                    downloader=_ArtifactOnlyDownloader(
                        url=record.artifact_url,
                        artifact=artifact,
                    ),
                    version_checker=lambda _path, _command: "1.2.3",
                )
            assert not destination.exists()

    def test_lock_selection_requires_one_match_and_an_explicit_network_seam(
        self,
    ) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "lock.json"
            _write_lock(lock, record)
            with pytest.raises(ToolchainError, match="not uniquely locked"):
                _ = install_from_lock(
                    lock,
                    tool="missing",
                    target=record.target,
                    destination=root / "missing",
                    downloader=_ArtifactOnlyDownloader(
                        url=record.artifact_url,
                        artifact=artifact,
                    ),
                )
            with pytest.raises(ToolchainError, match="network seam must be explicit"):
                _ = install_from_lock(
                    lock,
                    tool=record.tool,
                    target=record.target,
                    destination=root / "fixture-tool",
                )

    def test_cli_returns_a_stable_error_for_invalid_dependency_arguments(self) -> None:
        stderr = io.StringIO()
        with mock.patch("scripts.bootstrap_toolchain.sys.stderr", stderr):
            status = main(
                [
                    "--lock",
                    "/unused/lock.json",
                    "--tool",
                    "npm",
                    "--target",
                    "x86_64-unknown-linux-gnu",
                    "--destination",
                    "/unused/npm",
                    "--dependency",
                    "node-without-a-path",
                ]
            )
        assert status == CLI_FAILURE_STATUS
        assert stderr.getvalue() == (
            "bootstrap failed: dependency must be a unique TOOL=PATH pair\n"
        )

    def test_cli_passes_a_closed_caller_provided_node_dependency_for_npm(self) -> None:
        captured_arguments: list[tuple[tuple[object, ...], dict[str, object]]] = []

        def install_fixture(*args: object, **kwargs: object) -> Path:
            captured_arguments.append((args, dict(kwargs)))
            destination = kwargs.get("destination")
            assert isinstance(destination, Path)
            return destination

        with mock.patch(
            "scripts.bootstrap_toolchain.install_from_lock",
            new=install_fixture,
        ):
            status = main(
                [
                    "--lock",
                    "/repo/security/bootstrap-toolchain-lock.json",
                    "--tool",
                    "npm",
                    "--target",
                    "x86_64-unknown-linux-gnu",
                    "--destination",
                    "/private/tools/npm",
                    "--dependency",
                    "node=/private/tools/node",
                ]
            )
        assert status == 0
        assert len(captured_arguments) == 1
        positional, keyword = captured_arguments[0]
        assert positional == (Path("/repo/security/bootstrap-toolchain-lock.json"),)
        assert keyword["tool"] == "npm"
        assert keyword["target"] == "x86_64-unknown-linux-gnu"
        assert keyword["destination"] == Path("/private/tools/npm")
        assert isinstance(keyword["downloader"], HttpsDownloader)
        assert keyword["dependency_roots"] == {"node": Path("/private/tools/node")}

    def test_npm_rejects_a_missing_or_wrong_managed_dependency(self) -> None:
        artifact = _tar_archive({"package/bin/npm-cli.js": b"11.18.0"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, node_body = _managed_node(root / "node")
            record = _npm_record(artifact, node_body)
            dependency_cases: tuple[tuple[str, dict[str, Path]], ...] = (
                ("missing", {}),
                ("unexpected", {"python": root / "node"}),
            )
            for name, dependency_roots in dependency_cases:
                with self.subTest(case=name):
                    with pytest.raises(
                        ToolchainError,
                        match=r"dependency.*missing|unexpected.*dependency",
                    ):
                        _ = install_tool(
                            record,
                            destination=root / "npm",
                            downloader=_Downloader(_bodies(record, artifact)),
                            dependency_roots=dependency_roots,
                        )
                    assert not (root / "npm").exists()

    def test_npm_rejects_an_off_lock_node_executable(self) -> None:
        artifact = _tar_archive({"package/bin/npm-cli.js": b"11.18.0"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, node_body = _managed_node(root / "node")
            record = _npm_record(artifact, node_body)
            off_lock = replace(
                record,
                runtime_dependencies=(
                    replace(record.runtime_dependencies[0], executable_sha256="0" * 64),
                ),
            )
            with pytest.raises(
                ToolchainError, match=r"dependency executable digest mismatch"
            ):
                _ = install_tool(
                    off_lock,
                    destination=root / "npm",
                    downloader=_Downloader(_bodies(off_lock, artifact)),
                    dependency_roots={"node": root / "node"},
                )
            assert not (root / "npm").exists()

    def test_npm_rejects_a_wrong_managed_node_version(self) -> None:
        artifact = _tar_archive({"package/bin/npm-cli.js": b"11.18.0"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, node_body = _managed_node(root / "node", node_version="23.0.0")
            record = _npm_record(artifact, node_body)
            with pytest.raises(
                ToolchainError, match=r"runtime dependency version output is not exact"
            ):
                _ = install_tool(
                    record,
                    destination=root / "npm",
                    downloader=_Downloader(_bodies(record, artifact)),
                    dependency_roots={"node": root / "node"},
                )
            assert not (root / "npm").exists()

    def test_npm_regular_entrypoint_paths_and_targets_cannot_escape(self) -> None:
        artifact = _tar_archive({"package/bin/npm-cli.js": b"11.18.0"})
        cases: dict[str, tuple[str, str]] = {
            "traversal-path": ("../bin/npm", "package/bin/npm-cli.js"),
            "absolute-path": (ABSOLUTE_NPM_PATH, "package/bin/npm-cli.js"),
            "traversal-target": ("bin/npm", "../npm-cli.js"),
            "absolute-target": ("bin/npm", ABSOLUTE_NPM_TARGET),
        }
        for name, (path, target) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, node_body = _managed_node(root / "node")
                record = replace(
                    _npm_record(artifact, node_body),
                    regular_entrypoints=(
                        RegularEntrypoint(
                            path=path,
                            target=target,
                            dependency_tool="node",
                        ),
                    ),
                )
                with pytest.raises(
                    ToolchainError, match=r"regular entrypoint (path|target)"
                ):
                    _ = install_tool(
                        record,
                        destination=root / "npm",
                        downloader=_Downloader(_bodies(record, artifact)),
                        dependency_roots={"node": root / "node"},
                    )
                assert not (root / "npm").exists()

    def test_exact_npm_11_18_0_is_published_with_regular_entrypoints(self) -> None:
        artifact = _tar_archive(
            {
                "package/bin/npm-cli.js": b"11.18.0",
                "package/bin/npx-cli.js": b"11.18.0",
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, node_body = _managed_node(root / "node")
            record = _npm_record(artifact, node_body)
            destination = root / "npm"
            installed = install_tool(
                record,
                destination=destination,
                downloader=_Downloader(_bodies(record, artifact)),
                dependency_roots={"node": root / "node"},
            )
            assert installed == destination
            for name in ("npm", "npx"):
                entrypoint = destination / "bin" / name
                assert entrypoint.is_file()
                assert not entrypoint.is_symlink()
                assert stat.S_IMODE(entrypoint.stat().st_mode) == EXECUTABLE_MODE
            assert not any(path.is_symlink() for path in destination.rglob("*"))

    def test_bundled_node_npm_cannot_satisfy_the_separate_npm_record(self) -> None:
        artifact = _tar_archive(
            {
                "package/bin/npm-cli.js": b"11.18.0",
                "package/bin/npx-cli.js": b"11.18.0",
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, node_body = _managed_node(root / "node")
            record = replace(
                _npm_record(artifact, node_body),
                embedded_version_command=("{dependency:node}", "--version"),
            )
            with pytest.raises(
                ToolchainError,
                match=r"npm version probe must execute the extracted locked artifact",
            ):
                _ = install_tool(
                    record,
                    destination=root / "npm",
                    downloader=_Downloader(_bodies(record, artifact)),
                    dependency_roots={"node": root / "node"},
                )
            assert not (root / "npm").exists()

    def test_wrong_npm_version_is_rejected_without_publication(self) -> None:
        artifact = _tar_archive(
            {
                "package/bin/npm-cli.js": b"11.17.0",
                "package/bin/npx-cli.js": b"11.17.0",
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, node_body = _managed_node(root / "node")
            record = _npm_record(artifact, node_body)
            with pytest.raises(
                ToolchainError, match=r"installed npm version output is not exact"
            ):
                _ = install_tool(
                    record,
                    destination=root / "npm",
                    downloader=_Downloader(_bodies(record, artifact)),
                    dependency_roots={"node": root / "node"},
                )
            assert not (root / "npm").exists()

    def test_runtime_downloads_only_the_reviewed_digest_pinned_artifact(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        downloader = _ArtifactOnlyDownloader(url=record.artifact_url, artifact=artifact)

        with tempfile.TemporaryDirectory() as temporary:
            try:
                _ = install_tool(
                    record,
                    destination=Path(temporary) / "fixture-tool",
                    downloader=downloader,
                    version_checker=lambda _path, _command: "1.2.3",
                )
            except ToolchainError as exc:
                self.fail(f"accepted lock-review policy was not sufficient: {exc}")

        assert downloader.requested_urls == [record.artifact_url]

    def test_cli_safely_installs_the_locked_uv_wheel_layout(self) -> None:
        executable = (
            b'#!/usr/bin/env python3\nprint("uv 0.12.5 (x86_64-unknown-linux-gnu)")\n'
        )
        entries = {
            "uv/__init__.py": b"",
            "uv-0.12.5.data/scripts/uv": executable,
            "uv-0.12.5.data/scripts/uvx": b"uvx",
            "uv-0.12.5.dist-info/METADATA": b"Version: 0.12.5\n",
        }
        artifact = _archive(
            entries,
            modes={
                "uv-0.12.5.data/scripts/uv": 0o755,
                "uv-0.12.5.data/scripts/uvx": 0o755,
            },
        )
        record = replace(
            _record(artifact, version="0.12.5"),
            tool="uv",
            artifact_url=(
                "https://files.pythonhosted.org/packages/93/22/"
                "dacc9a0bc8604187a1ba954a3aef8329e4104eb0af772d2c3c634893bd9b/"
                "uv-0.12.5-py3-none-manylinux_2_17_x86_64."
                "manylinux2014_x86_64.whl"
            ),
            archive_format="wheel",
            allowed_top_level_entries=(
                "uv-0.12.5.data",
                "uv",
                "uv-0.12.5.dist-info",
            ),
            embedded_version_command=("{path}/scripts/uv", "--version"),
            signature_url=None,
            signature_sha256=None,
            signature_key_fingerprint=None,
            signature_reason="PyPI publishes a digest but no detached signature",
        )
        downloader = _ArtifactOnlyDownloader(url=record.artifact_url, artifact=artifact)

        def download_fixture(
            _self: HttpsDownloader,
            url: str,
            *,
            max_bytes: int,
        ) -> bytes:
            return downloader.download(url, max_bytes=max_bytes)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "lock.json"
            destination = root / "uv"
            _write_lock(lock, record)
            with mock.patch.object(
                HttpsDownloader,
                "download",
                new=download_fixture,
            ):
                status = main(
                    [
                        "--lock",
                        str(lock),
                        "--tool",
                        "uv",
                        "--target",
                        "x86_64-unknown-linux-gnu",
                        "--destination",
                        str(destination),
                    ]
                )

            uv = destination / "uv-0.12.5.data" / "scripts" / "uv"
            assert status == 0
            assert stat.S_IMODE(uv.stat().st_mode) == EXECUTABLE_MODE
            assert downloader.requested_urls == [record.artifact_url]

    def test_cli_installs_a_checksum_verified_tool_and_returns_success(self) -> None:
        artifact = _archive({"fixture-tool": b'print("fixture-tool 1.2.3")\n'})
        record = replace(
            _record(artifact),
            signature_url=None,
            signature_sha256=None,
            signature_key_fingerprint=None,
            signature_reason="publisher checksum only",
            embedded_version_command=("python3", "{path}"),
        )
        bodies = _bodies(_record(artifact), artifact)
        assert record.checksum_url is not None
        bodies = {
            record.artifact_url: artifact,
            record.checksum_url: bodies[record.checksum_url],
        }
        downloader = _Downloader(bodies)

        def download_fixture(
            _self: HttpsDownloader,
            url: str,
            *,
            max_bytes: int,
        ) -> bytes:
            return downloader.download(url, max_bytes=max_bytes)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "lock.json"
            destination = root / "fixture-tool-install"
            _write_lock(lock, record)

            with mock.patch.object(
                HttpsDownloader,
                "download",
                new=download_fixture,
            ):
                status = main(
                    [
                        "--lock",
                        str(lock),
                        "--tool",
                        record.tool,
                        "--target",
                        record.target,
                        "--destination",
                        str(destination),
                    ]
                )

            assert status == 0
            assert (destination / "fixture-tool").is_file()

    def test_install_rejects_missing_permissive_or_symlinked_tool_roots(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            permissive_root = base / "permissive"
            permissive_root.mkdir(mode=0o700)
            permissive_root.chmod(0o755)
            real_root = base / "real"
            real_root.mkdir(mode=0o700)
            symlink_root = base / "symlink"
            symlink_root.symlink_to(real_root, target_is_directory=True)
            roots = (base / "missing", permissive_root, symlink_root)

            for root in roots:
                with self.subTest(root=root.name):
                    destination = root / "fixture-tool"
                    with pytest.raises(ToolchainError, match=r"tool root"):
                        _ = install_tool(
                            record,
                            destination=destination,
                            downloader=_Downloader(_bodies(record, artifact)),
                            version_checker=lambda _path, _command: "1.2.3",
                        )
                    assert not destination.exists()

    def test_zip_extraction_preserves_the_locked_executable_mode(self) -> None:
        artifact = _archive(
            {"fixture-tool": b"executable"}, modes={"fixture-tool": 0o755}
        )
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            _ = install_tool(
                record,
                destination=destination,
                downloader=_Downloader(_bodies(record, artifact)),
                version_checker=lambda _path, _command: "1.2.3",
            )

            installed_mode = stat.S_IMODE((destination / "fixture-tool").stat().st_mode)
            assert installed_mode == EXECUTABLE_MODE

    def test_zip_rejects_unsafe_paths_symlinks_and_special_files(self) -> None:
        cases: dict[str, bytes] = {
            "absolute-path": _raw_zip_member(
                "/fixture-tool", mode=stat.S_IFREG | 0o755
            ),
            "empty-path-component": _raw_zip_member(
                "fixture-tool//nested", mode=stat.S_IFREG | 0o600
            ),
            "symlink": _raw_zip_member("fixture-tool/link", mode=stat.S_IFLNK | 0o777),
            "fifo": _raw_zip_member("fixture-tool/fifo", mode=stat.S_IFIFO | 0o600),
            "setuid": _raw_zip_member(
                "fixture-tool", mode=stat.S_IFREG | stat.S_ISUID | 0o755
            ),
        }
        for name, artifact in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "fixture-tool"
                record = _record(artifact)
                with pytest.raises(
                    ToolchainError, match=r"unsafe|symlink|special|traversal"
                ):
                    _ = install_tool(
                        record,
                        destination=destination,
                        downloader=_Downloader(_bodies(record, artifact)),
                        version_checker=lambda _path, _command: "1.2.3",
                    )
                assert not destination.exists()

    def test_tar_extraction_preserves_the_locked_executable_mode(self) -> None:
        artifact = _raw_tar_member("fixture-tool", mode=0o755)
        record = replace(_record(artifact), archive_format="tar.gz")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            _ = install_tool(
                record,
                destination=destination,
                downloader=_Downloader(_bodies(record, artifact)),
                version_checker=lambda _path, _command: "1.2.3",
            )

            installed_mode = stat.S_IMODE((destination / "fixture-tool").stat().st_mode)
            assert installed_mode == EXECUTABLE_MODE

    def test_tar_rejects_unsafe_paths_links_and_special_files(self) -> None:
        cases = {
            "absolute-path": _raw_tar_member("/fixture-tool", mode=0o755),
            "symlink": _raw_tar_member(
                "fixture-tool", mode=0o777, member_type=tarfile.SYMTYPE
            ),
            "fifo": _raw_tar_member(
                "fixture-tool", mode=0o600, member_type=tarfile.FIFOTYPE
            ),
            "setuid": _raw_tar_member("fixture-tool", mode=stat.S_ISUID | 0o755),
        }
        for name, artifact in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "fixture-tool"
                record = replace(_record(artifact), archive_format="tar.gz")
                with pytest.raises(
                    ToolchainError, match=r"unsafe|symlink|special|traversal"
                ):
                    _ = install_tool(
                        record,
                        destination=destination,
                        downloader=_Downloader(_bodies(record, artifact)),
                        version_checker=lambda _path, _command: "1.2.3",
                    )
                assert not destination.exists()

    def test_declared_internal_tar_link_becomes_a_regular_executable_wrapper(
        self,
    ) -> None:
        fake_node = b'#!/usr/bin/env python3\nprint("npm 1.2.3")\n'
        artifact = _tar_members(
            [
                ("fixture-tool/bin/node", tarfile.REGTYPE, fake_node, 0o755),
                ("fixture-tool/lib/npm.js", tarfile.REGTYPE, b"npm", 0o644),
                (
                    "fixture-tool/bin/npm",
                    tarfile.SYMTYPE,
                    "../lib/npm.js",
                    0o777,
                ),
            ]
        )
        record = replace(
            _record(artifact),
            archive_format="tar.gz",
            materialized_link_wrappers=(
                MaterializedLinkWrapper(
                    archive_path="fixture-tool/bin/npm",
                    target="../lib/npm.js",
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            try:
                _ = install_tool(
                    record,
                    destination=destination,
                    downloader=_ArtifactOnlyDownloader(
                        url=record.artifact_url, artifact=artifact
                    ),
                    version_checker=lambda _path, _command: "1.2.3",
                )
            except ToolchainError as exc:
                self.fail(f"reviewed internal link was not materialized: {exc}")

            npm = destination / "fixture-tool" / "bin" / "npm"
            assert npm.is_file()
            assert not npm.is_symlink()
            assert stat.S_IMODE(npm.stat().st_mode) == EXECUTABLE_MODE
            for path in destination.rglob("*"):
                assert not path.is_symlink(), path
            wrapper = npm.read_text(encoding="utf-8")
            assert "os.execv(node, [node, target, *sys.argv[1:]])" in wrapper
            assert "'../lib/npm.js'" in wrapper

    def test_tar_wrapper_policy_rejects_every_unreviewed_link_shape(self) -> None:
        regular_node = (
            "fixture-tool/bin/node",
            tarfile.REGTYPE,
            b"node",
            0o755,
        )
        regular_target = (
            "fixture-tool/lib/npm.js",
            tarfile.REGTYPE,
            b"npm",
            0o644,
        )
        declared = MaterializedLinkWrapper(
            archive_path="fixture-tool/bin/npm", target="../lib/npm.js"
        )
        cases: dict[
            str,
            tuple[list[TarMemberFixture], tuple[MaterializedLinkWrapper, ...]],
        ] = {
            "undeclared": (
                [
                    regular_node,
                    regular_target,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../lib/npm.js",
                        0o777,
                    ),
                ],
                (),
            ),
            "wrong-target": (
                [
                    regular_node,
                    regular_target,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../lib/other.js",
                        0o777,
                    ),
                ],
                (declared,),
            ),
            "absolute-target": (
                [
                    regular_node,
                    regular_target,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "/etc/passwd",
                        0o777,
                    ),
                ],
                (
                    MaterializedLinkWrapper(
                        archive_path="fixture-tool/bin/npm", target="/etc/passwd"
                    ),
                ),
            ),
            "escaping-target": (
                [
                    regular_node,
                    regular_target,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../../../etc/passwd",
                        0o777,
                    ),
                ],
                (
                    MaterializedLinkWrapper(
                        archive_path="fixture-tool/bin/npm",
                        target="../../../etc/passwd",
                    ),
                ),
            ),
            "unsafe-target-component": (
                [
                    regular_node,
                    regular_target,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../lib//npm.js",
                        0o777,
                    ),
                ],
                (
                    MaterializedLinkWrapper(
                        archive_path="fixture-tool/bin/npm",
                        target="../lib//npm.js",
                    ),
                ),
            ),
            "missing-target": (
                [
                    regular_node,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../lib/npm.js",
                        0o777,
                    ),
                ],
                (declared,),
            ),
            "missing-node": (
                [
                    regular_target,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../lib/npm.js",
                        0o777,
                    ),
                ],
                (declared,),
            ),
            "missing-declared-wrapper": (
                [regular_node, regular_target],
                (declared,),
            ),
            "link-chain": (
                [
                    regular_node,
                    regular_target,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "npx",
                        0o777,
                    ),
                    (
                        "fixture-tool/bin/npx",
                        tarfile.SYMTYPE,
                        "../lib/npm.js",
                        0o777,
                    ),
                ],
                (
                    MaterializedLinkWrapper(
                        archive_path="fixture-tool/bin/npm", target="npx"
                    ),
                    MaterializedLinkWrapper(
                        archive_path="fixture-tool/bin/npx",
                        target="../lib/npm.js",
                    ),
                ),
            ),
            "nonregular-target": (
                [
                    regular_node,
                    (
                        "fixture-tool/lib/npm.js",
                        tarfile.SYMTYPE,
                        "real.js",
                        0o777,
                    ),
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../lib/npm.js",
                        0o777,
                    ),
                ],
                (
                    declared,
                    MaterializedLinkWrapper(
                        archive_path="fixture-tool/lib/npm.js", target="real.js"
                    ),
                ),
            ),
            "duplicate-conflict": (
                [
                    regular_node,
                    regular_target,
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../lib/npm.js",
                        0o777,
                    ),
                    (
                        "fixture-tool/bin/npm",
                        tarfile.SYMTYPE,
                        "../lib/npm.js",
                        0o777,
                    ),
                ],
                (declared,),
            ),
        }
        for name, (members, wrappers) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                artifact = _tar_members(members)
                record = replace(
                    _record(artifact),
                    archive_format="tar.gz",
                    materialized_link_wrappers=wrappers,
                )
                with pytest.raises(
                    ToolchainError,
                    match=(
                        r"undeclared|target|node|link chain|duplicate|conflict|wrapper"
                    ),
                ):
                    _ = install_tool(
                        record,
                        destination=Path(temporary) / "fixture-tool",
                        downloader=_ArtifactOnlyDownloader(
                            url=record.artifact_url, artifact=artifact
                        ),
                        version_checker=lambda _path, _command: "1.2.3",
                    )

    def test_exact_uv_and_node_embedded_version_outputs_are_accepted(self) -> None:
        cases = {
            "uv": "uv 1.2.3 (x86_64-unknown-linux-gnu)\n",
            "node": "v1.2.3\n",
        }
        for tool, output in cases.items():
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as temporary:
                artifact = _version_script_archive(stdout=output)
                record = replace(
                    _record(artifact),
                    tool=tool,
                    embedded_version_command=("python3", "{path}"),
                )
                destination = Path(temporary) / tool
                installed = install_tool(
                    record,
                    destination=destination,
                    downloader=_Downloader(_bodies(record, artifact)),
                )
                assert installed == destination

    def test_embedded_version_rejects_wrong_target_stderr_or_trailing_output(
        self,
    ) -> None:
        cases = {
            "uv-wrong-target": (
                "uv",
                "uv 1.2.3 (aarch64-unknown-linux-gnu)\n",
                "",
            ),
            "uv-trailing": (
                "uv",
                "uv 1.2.3 (x86_64-unknown-linux-gnu) trailing-material\n",
                "",
            ),
            "uv-stderr": (
                "uv",
                "uv 1.2.3 (x86_64-unknown-linux-gnu)\n",
                "warning\n",
            ),
            "node-trailing": ("node", "v1.2.3 trailing-material\n", ""),
            "node-stderr": ("node", "v1.2.3\n", "warning\n"),
        }
        for name, (tool, stdout, stderr) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                artifact = _version_script_archive(stdout=stdout, stderr=stderr)
                record = replace(
                    _record(artifact),
                    tool=tool,
                    embedded_version_command=("python3", "{path}"),
                )
                destination = Path(temporary) / tool
                with pytest.raises(
                    ToolchainError, match=r"version probe|version output"
                ):
                    _ = install_tool(
                        record,
                        destination=destination,
                        downloader=_Downloader(_bodies(record, artifact)),
                    )
                assert not destination.exists()

    def test_reviewed_lock_is_closed_and_truthful_about_signature_evidence(
        self,
    ) -> None:
        records = load_lock(
            Path(__file__).parents[2] / "security" / "bootstrap-toolchain-lock.json"
        )
        assert {record.tool for record in records} == {"node", "npm", "uv"}
        assert {record.target for record in records} == {"x86_64-unknown-linux-gnu"}
        for record in records:
            assert record.current_version == record.chosen_version
            assert record.artifact_url.startswith("https://")
            assert record.checksum_url is not None
            if record.signature_url is None:
                assert record.signature_sha256 is None
                assert record.signature_key_fingerprint is None
                assert record.signature_reason
            else:
                assert record.signature_sha256 is not None
                assert record.signature_key_fingerprint is not None

    def test_reviewed_lock_uses_direct_artifacts_and_complete_review_policy(
        self,
    ) -> None:
        records = {
            record.tool: record
            for record in load_lock(
                Path(__file__).parents[2] / "security" / "bootstrap-toolchain-lock.json"
            )
        }
        uv = records["uv"]
        assert (
            uv.artifact_url
            == "https://files.pythonhosted.org/packages/93/22/dacc9a0bc8604187a1ba954a3aef8329e4104eb0af772d2c3c634893bd9b/uv-0.12.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
        )
        assert (
            uv.artifact_sha256
            == "3e195ccf1ed60c8bb24a6447ce306441a4181d54b602407e09bc56e963911c15"
        )
        assert uv.archive_format == "wheel"
        assert uv.allowed_top_level_entries == (
            "uv-0.12.5.data",
            "uv",
            "uv-0.12.5.dist-info",
        )
        assert uv.embedded_version_command == ("{path}/scripts/uv", "--version")
        for record in records.values():
            assert record.runtime_trust_policy == "repository_pinned_sha256"
            assert record.lock_review_status == "accepted"
            assert record.checksum_url is not None
            assert record.checksum_sha256 is not None
        node = records["node"]
        assert node.signature_url is not None
        assert node.signature_sha256 is not None
        assert node.signature_key_fingerprint is not None

    def test_reviewed_lock_has_a_separate_exact_npm_11_18_0_record(self) -> None:
        records = {
            record.tool: record
            for record in load_lock(
                Path(__file__).parents[2] / "security" / "bootstrap-toolchain-lock.json"
            )
        }
        npm = records["npm"]
        assert npm.chosen_version == "11.18.0"
        assert npm.artifact_url == "https://registry.npmjs.org/npm/-/npm-11.18.0.tgz"
        assert (
            npm.artifact_sha256
            == "73f6155215ebabf4ed96dca1f567c2372cc713c33af2e5b9b62fde4e92373e2e"
        )
        assert npm.upstream_integrity == "".join(EXPECTED_NPM_INTEGRITY_PARTS)
        assert npm.checksum_url == "https://registry.npmjs.org/npm/11.18.0"
        assert (
            npm.checksum_sha256
            == "ec61b012150789bfbf8a7132b46251ba9a841a0e1aa5902163cf60c72c0160c2"
        )
        dependencies = npm.runtime_dependencies
        assert len(dependencies) == 1
        assert dependencies[0].tool == "node"
        assert dependencies[0].chosen_version == "24.19.0"
        assert (
            dependencies[0].executable_sha256
            == "bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"
        )
        entrypoints = npm.regular_entrypoints
        assert tuple(
            (item.path, item.target, item.dependency_tool) for item in entrypoints
        ) == (
            ("bin/npm", "package/bin/npm-cli.js", "node"),
            ("bin/npx", "package/bin/npx-cli.js", "node"),
        )

    def test_npm_lock_rejects_malformed_or_wrong_length_sha512_sri(self) -> None:
        npm = next(
            record
            for record in load_lock(
                Path(__file__).parents[2] / "security" / "bootstrap-toolchain-lock.json"
            )
            if record.tool == "npm"
        )
        cases = (
            "sha512-not-base64",
            "sha512-" + base64.b64encode(b"x" * 63).decode("ascii"),
            "sha512-" + base64.b64encode(b"x" * 64).decode("ascii") + "!",
            "sha256-" + base64.b64encode(b"x" * 64).decode("ascii"),
        )
        for integrity in cases:
            with (
                self.subTest(integrity=integrity),
                tempfile.TemporaryDirectory() as temporary,
            ):
                mutated = _record_json(npm)
                mutated["upstream_integrity"] = integrity
                path = Path(temporary) / "lock.json"
                _write_raw_lock(path, mutated)
                with pytest.raises(
                    ToolchainError, match=r"npm registry integrity.*SHA-512"
                ):
                    _ = load_lock(path)

    def test_reviewed_lock_declares_only_the_three_node_wrapper_mappings(
        self,
    ) -> None:
        records = {
            record.tool: record
            for record in load_lock(
                Path(__file__).parents[2] / "security" / "bootstrap-toolchain-lock.json"
            )
        }
        node_wrappers = tuple(
            (wrapper.archive_path, wrapper.target)
            for wrapper in records["node"].materialized_link_wrappers
        )
        assert node_wrappers == (
            (
                "node-v24.19.0-linux-x64/bin/corepack",
                "../lib/node_modules/corepack/dist/corepack.js",
            ),
            (
                "node-v24.19.0-linux-x64/bin/npx",
                "../lib/node_modules/npm/bin/npx-cli.js",
            ),
            (
                "node-v24.19.0-linux-x64/bin/npm",
                "../lib/node_modules/npm/bin/npm-cli.js",
            ),
        )
        assert records["uv"].materialized_link_wrappers == ()

    def test_readme_exposes_only_the_locked_bootstrap_and_sync_workflow(self) -> None:
        readme = (Path(__file__).parents[2] / "README.md").read_text(encoding="utf-8")
        assert "pip install -e" not in readme
        required_commands = (
            "python3 scripts/bootstrap_toolchain.py",
            "--tool uv",
            "--tool node",
            "--tool npm",
            '--dependency "node=$TOOL_ROOT/node"',
            "--target x86_64-unknown-linux-gnu",
            'NPM_BIN="$TOOL_ROOT/npm/bin"',
            (
                "uv pip sync --python .venv/bin/python --require-hashes "
                "requirements-dev.lock"
            ),
            "npm ci --ignore-scripts",
        )
        for command in required_commands:
            with self.subTest(command=command):
                assert command in readme

    def test_verified_archive_is_published_atomically(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            tool_root = Path(temporary) / "tools"
            tool_root.mkdir(mode=0o700)
            destination = tool_root / "fixture-tool"
            installed = install_tool(
                record,
                destination=destination,
                downloader=_Downloader(_bodies(record, artifact)),
                version_checker=lambda _path, _command: "1.2.3",
            )
            assert installed == destination
            assert (destination / "fixture-tool").read_bytes() == b"executable"
            assert tuple(path.name for path in destination.parent.iterdir()) == (
                "fixture-tool",
            )

    def test_wrong_digest_is_rejected_without_publication(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        invalid = replace(record, artifact_sha256="0" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            with pytest.raises(ToolchainError, match=r"digest mismatch"):
                _ = install_tool(
                    invalid,
                    destination=destination,
                    downloader=_Downloader(_bodies(invalid, artifact)),
                    version_checker=lambda _path, _command: "1.2.3",
                )
            assert not destination.exists()

    def test_traversal_archive_is_rejected_without_publication(self) -> None:
        artifact = _archive({"../escape": b"nope"})
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            with pytest.raises(ToolchainError):
                _ = install_tool(
                    record,
                    destination=destination,
                    downloader=_Downloader(_bodies(record, artifact)),
                    version_checker=lambda _path, _command: "1.2.3",
                )
            assert not (Path(temporary) / "escape").exists()
            assert not destination.exists()

    def test_embedded_version_drift_is_rejected_without_publication(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            with pytest.raises(ToolchainError, match=r"version mismatch"):
                _ = install_tool(
                    record,
                    destination=destination,
                    downloader=_Downloader(_bodies(record, artifact)),
                    version_checker=lambda _path, _command: "9.9.9",
                )
            assert not destination.exists()

    def test_current_and_chosen_version_drift_is_rejected(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        drifted = ToolchainRecord(
            tool=record.tool,
            target=record.target,
            publisher=record.publisher,
            runtime_trust_policy=record.runtime_trust_policy,
            lock_review_status=record.lock_review_status,
            materialized_link_wrappers=record.materialized_link_wrappers,
            chosen_version=record.chosen_version,
            current_version="9.9.9",
            hold_rationale=record.hold_rationale,
            artifact_url=record.artifact_url,
            artifact_sha256=record.artifact_sha256,
            signature_url=record.signature_url,
            signature_sha256=record.signature_sha256,
            archive_format=record.archive_format,
            allowed_top_level_entries=record.allowed_top_level_entries,
            embedded_version_command=record.embedded_version_command,
            max_artifact_bytes=record.max_artifact_bytes,
            max_signature_bytes=record.max_signature_bytes,
            checksum_url=record.checksum_url,
            checksum_sha256=record.checksum_sha256,
            signature_key_fingerprint=record.signature_key_fingerprint,
            signature_reason=record.signature_reason,
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            pytest.raises(ToolchainError, match=r"current/chosen"),
        ):
            _ = install_tool(
                drifted,
                destination=Path(temporary) / "fixture-tool",
                downloader=_Downloader(_bodies(drifted, artifact)),
                version_checker=lambda _path, _command: "1.2.3",
            )

    def test_lock_rejects_mismatched_signature_url_and_digest(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record_json(_record(artifact))
        record["signature_sha256"] = None
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            _write_raw_lock(path, record)
            with pytest.raises(ToolchainError, match=r"both present or both absent"):
                _ = load_lock(path)

    def test_lock_rejects_duplicate_json_object_names(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record_json = dump_json(_record_json(_record(artifact)))
        lock_json = (
            f'{{"schema_version":999,"schema_version":1,"records":[{record_json}]}}'
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            _ = path.write_text(lock_json, encoding="utf-8")
            with pytest.raises(ToolchainError, match=r"duplicate JSON name"):
                _ = load_lock(path)

    def test_lock_requires_schema_version_to_be_the_exact_integer_one(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record_json(_record(artifact))
        for schema_version in (True, 1.0):
            with (
                self.subTest(schema_version=schema_version),
                tempfile.TemporaryDirectory() as temporary,
            ):
                path = Path(temporary) / "lock.json"
                _write_raw_lock(path, record, schema_version=schema_version)
                with pytest.raises(
                    ToolchainError, match=r"schema_version must be the integer 1"
                ):
                    _ = load_lock(path)

    def test_lock_rejects_records_without_explicit_archive_limits(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        raw = _record_json(_record(artifact))
        _ = raw.pop("max_archive_members", None)
        _ = raw.pop("max_extracted_bytes", None)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            _write_raw_lock(path, raw)
            with pytest.raises(ToolchainError, match=r"unknown or missing"):
                _ = load_lock(path)

    def test_lock_rejects_a_record_without_upstream_publisher(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        raw = _record_json(_record(artifact))
        _ = raw.pop("publisher", None)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            _write_raw_lock(path, raw)
            with pytest.raises(ToolchainError, match=r"unknown or missing"):
                _ = load_lock(path)

    def test_lock_rejects_an_empty_upstream_publisher(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        raw = _record_json(_record(artifact))
        raw["publisher"] = ""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            _write_raw_lock(path, raw)
            with pytest.raises(
                ToolchainError, match=r"publisher must be a non-empty string"
            ):
                _ = load_lock(path)

    def test_lock_rejects_missing_or_unaccepted_runtime_review_policy(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        base = _record_json(_record(artifact))
        cases: dict[str, JsonObject] = {}
        missing = dict(base)
        _ = missing.pop("runtime_trust_policy", None)
        _ = missing.pop("lock_review_status", None)
        cases["missing"] = missing
        unaccepted = dict(base)
        unaccepted["runtime_trust_policy"] = "download-time-upstream-verification"
        unaccepted["lock_review_status"] = "pending"
        cases["unaccepted"] = unaccepted

        for name, raw in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "lock.json"
                _write_raw_lock(path, raw)
                with pytest.raises(
                    ToolchainError,
                    match=r"unknown or missing|runtime trust policy|review status",
                ):
                    _ = load_lock(path)

    def test_node_review_policy_requires_complete_signature_evidence(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        raw = _record_json(_record(artifact))
        raw["runtime_trust_policy"] = "repository_pinned_sha256"
        raw["lock_review_status"] = "accepted"
        raw["signature_key_fingerprint"] = None
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            _write_raw_lock(path, raw)
            with pytest.raises(
                ToolchainError,
                match=r"signature review evidence requires a key fingerprint",
            ):
                _ = load_lock(path)

    def test_lock_rejects_malformed_openpgp_fingerprints(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        base = _record_json(_record(artifact))
        cases = ("not-a-fingerprint", "A" * 39, "a" * 40, "G" * 40)
        for fingerprint in cases:
            with (
                self.subTest(fingerprint=fingerprint),
                tempfile.TemporaryDirectory() as temporary,
            ):
                raw = dict(base)
                raw["signature_key_fingerprint"] = fingerprint
                path = Path(temporary) / "lock.json"
                _write_raw_lock(path, raw)
                with pytest.raises(
                    ToolchainError,
                    match=r"fingerprint must be 40 uppercase hexadecimal",
                ):
                    _ = load_lock(path)

    def test_zip_and_tar_reject_extracted_bytes_above_the_locked_ceiling(
        self,
    ) -> None:
        archives = {
            "zip": (_archive({"fixture-tool": b"12345"}), "zip"),
            "tar": (
                _raw_tar_member("fixture-tool", mode=0o755, body=b"12345"),
                "tar.gz",
            ),
        }
        for name, (artifact, archive_format) in archives.items():
            with self.subTest(format=name), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "fixture-tool"
                record = replace(
                    _record(artifact),
                    archive_format=archive_format,
                    max_extracted_bytes=4,
                )
                with pytest.raises(ToolchainError, match=r"extracted byte"):
                    _ = install_tool(
                        record,
                        destination=destination,
                        downloader=_Downloader(_bodies(record, artifact)),
                        version_checker=lambda _path, _command: "1.2.3",
                    )
                assert not destination.exists()

    def test_zip_and_tar_reject_member_counts_above_the_locked_ceiling(
        self,
    ) -> None:
        entries = {
            "fixture-tool/one": b"one",
            "fixture-tool/two": b"two",
        }
        archives = {
            "zip": (_archive(entries), "zip"),
            "tar": (_tar_archive(entries), "tar.gz"),
        }
        for name, (artifact, archive_format) in archives.items():
            with self.subTest(format=name), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "fixture-tool"
                record = replace(
                    _record(artifact),
                    archive_format=archive_format,
                    max_archive_members=1,
                )
                with pytest.raises(ToolchainError, match=r"member count"):
                    _ = install_tool(
                        record,
                        destination=destination,
                        downloader=_Downloader(_bodies(record, artifact)),
                        version_checker=lambda _path, _command: "1.2.3",
                    )
                assert not destination.exists()

    def test_late_destination_race_cannot_replace_or_partially_publish(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            tool_root = Path(temporary)
            destination = tool_root / "fixture-tool"

            def create_racing_destination(path: Path, command: tuple[str, ...]) -> str:
                del path, command
                destination.mkdir()
                return "1.2.3"

            with pytest.raises(ToolchainError, match=r"existing installation"):
                _ = install_tool(
                    record,
                    destination=destination,
                    downloader=_Downloader(_bodies(record, artifact)),
                    version_checker=create_racing_destination,
                )

            assert destination.is_dir()
            assert tuple(destination.iterdir()) == ()
            assert tuple(tool_root.iterdir()) == (destination,)

    def test_publication_syscall_never_replaces_a_racing_destination(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            tool_root = Path(temporary)
            destination = tool_root / "fixture-tool"
            real_exists = Path.exists
            destination_checks = 0

            def create_destination_after_final_check(path: Path) -> bool:
                nonlocal destination_checks
                exists = real_exists(path)
                if path == destination:
                    destination_checks += 1
                    if destination_checks == EXPECTED_DESTINATION_CHECKS and not exists:
                        destination.mkdir()
                        return False
                return exists

            with (
                mock.patch.object(
                    Path, "exists", new=create_destination_after_final_check
                ),
                pytest.raises(ToolchainError, match=r"existing installation"),
            ):
                _ = install_tool(
                    record,
                    destination=destination,
                    downloader=_Downloader(_bodies(record, artifact)),
                    version_checker=lambda _path, _command: "1.2.3",
                )

            assert destination_checks == EXPECTED_DESTINATION_CHECKS
            assert destination.is_dir()
            assert tuple(destination.iterdir()) == ()
            assert tuple(tool_root.iterdir()) == (destination,)

    def test_malformed_zip_is_reported_as_a_fail_closed_toolchain_error(self) -> None:
        artifact = b"not a zip archive"
        record = _record(artifact)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            with pytest.raises(ToolchainError, match="archive"):
                _ = install_tool(
                    record,
                    destination=destination,
                    downloader=_Downloader(_bodies(record, artifact)),
                    version_checker=lambda _path, _command: "1.2.3",
                )
            assert not destination.exists()

    def test_json_lock_rejects_unknown_fields(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = _record(artifact)
        raw: JsonObject = {
            "schema_version": 1,
            "records": [
                {
                    "tool": record.tool,
                    "target": record.target,
                    "chosen_version": record.chosen_version,
                    "current_version": record.current_version,
                    "hold_rationale": record.hold_rationale,
                    "artifact_url": record.artifact_url,
                    "artifact_sha256": record.artifact_sha256,
                    "signature_url": record.signature_url,
                    "signature_sha256": record.signature_sha256,
                    "archive_format": record.archive_format,
                    "allowed_top_level_entries": list(record.allowed_top_level_entries),
                    "embedded_version_command": list(record.embedded_version_command),
                    "max_artifact_bytes": record.max_artifact_bytes,
                    "max_signature_bytes": record.max_signature_bytes,
                    "unexpected": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock.json"
            _ = lock.write_text(dump_json(raw), encoding="utf-8")
            with pytest.raises(ToolchainError, match=r"unknown or missing"):
                _ = install_from_lock(
                    lock,
                    tool=record.tool,
                    target=record.target,
                    destination=Path(temporary) / "fixture-tool",
                    downloader=_Downloader({}),
                )

    def test_publisher_checksum_without_detached_signature_is_explicitly_supported(
        self,
    ) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = replace(
            _record(artifact),
            signature_url=None,
            signature_sha256=None,
            signature_key_fingerprint=None,
            signature_reason="publisher checksum only; no detached signature asset",
        )
        assert record.checksum_url is not None
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture-tool"
            installed = install_tool(
                record,
                destination=destination,
                downloader=_Downloader(
                    {
                        record.artifact_url: artifact,
                        record.checksum_url: _checksum_body(artifact),
                    },
                ),
                version_checker=lambda _path, _command: "1.2.3",
            )
            assert installed == destination

    def test_checksum_evidence_is_required_before_publication(self) -> None:
        artifact = _archive({"fixture-tool": b"executable"})
        record = replace(_record(artifact), checksum_url=None, checksum_sha256=None)
        assert record.signature_url is not None
        with (
            tempfile.TemporaryDirectory() as temporary,
            pytest.raises(ToolchainError, match=r"checksum review evidence"),
        ):
            _ = install_tool(
                record,
                destination=Path(temporary) / "fixture-tool",
                downloader=_Downloader(
                    {
                        record.artifact_url: artifact,
                        record.signature_url: b"valid-signature",
                    },
                ),
            )


if __name__ == "__main__":
    _ = unittest.main()
