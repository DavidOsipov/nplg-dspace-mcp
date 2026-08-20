# Copyright (c) 2026 David Osipov
"""Adversarial tests for the release Pyright installation identity."""

from __future__ import annotations

import hashlib
import json
import os
from typing import TYPE_CHECKING

import pytest

from nplg_mcp.json_types import load_json_value, require_json_object
from scripts.pyright_identity import (
    PyrightIdentityError,
    stable_regular_file_sha256,
    validate_pyright_package,
)

if TYPE_CHECKING:
    from pathlib import Path

_RESOLVED = "https://registry.npmjs.org/pyright/-/pyright-1.1.413.tgz"
_INTEGRITY = (
    "sha512-1lpxKrh0DHHpfAQOfciZo2ojua2jase3wwO9at8kldc+F/"
    "p1PBscxA5CQ3G1qg5lMOMhXo6ZaiMLMXEAqADIAg=="
)
_TREE_DOMAIN = b"nplg-pyright-package-tree-v1\0"
_POST_CONTENT_READ = 2


def _relative_package_name(path: Path, package: Path) -> str:
    return path.relative_to(package).as_posix()


def _test_tree_digest(package: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256(_TREE_DOMAIN)
    named_files = sorted(
        (_relative_package_name(path, package), path)
        for path in package.rglob("*")
        if path.is_file()
    )
    files = [path for _, path in named_files]
    total = 0
    for path in files:
        relative = path.relative_to(package).as_posix().encode()
        content = path.read_bytes()
        total += len(content)
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(hashlib.sha256(content).digest())
    return f"sha256:{digest.hexdigest()}", len(files), total


def _write_fixture(root: Path) -> None:
    package = root / "node_modules" / "pyright"
    package.mkdir(parents=True)
    _ = (package / "index.js").write_bytes(b"console.log('pyright 1.1.413');\n")
    _ = (package / "package.json").write_bytes(
        b'{"name":"pyright","version":"1.1.413"}\n'
    )
    (package / "lib").mkdir()
    _ = (package / "lib" / "schema.json").write_bytes(b"{}\n")
    package_lock = {
        "name": "fixture",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/pyright": {
                "version": "1.1.413",
                "resolved": _RESOLVED,
                "integrity": _INTEGRITY,
            }
        },
    }
    package_lock_bytes = json.dumps(
        package_lock, sort_keys=True, separators=(",", ":")
    ).encode()
    _ = (root / "package-lock.json").write_bytes(package_lock_bytes)
    tree_sha256, file_count, total_bytes = _test_tree_digest(package)
    identity = {
        "schema_version": 1,
        "package": "pyright",
        "version": "1.1.413",
        "resolved": _RESOLVED,
        "integrity": _INTEGRITY,
        "package_lock_sha256": (
            f"sha256:{hashlib.sha256(package_lock_bytes).hexdigest()}"
        ),
        "package_tree_sha256": tree_sha256,
        "file_count": file_count,
        "total_bytes": total_bytes,
    }
    security = root / "security"
    security.mkdir()
    _ = (security / "pyright-package-lock.json").write_text(
        json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _rebind_package_lock(root: Path, document: dict[str, object]) -> None:
    package_lock_bytes = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    _ = (root / "package-lock.json").write_bytes(package_lock_bytes)
    identity_path = root / "security" / "pyright-package-lock.json"
    identity = require_json_object(
        load_json_value(identity_path.read_bytes()),
        context="Pyright identity fixture",
    )
    identity["package_lock_sha256"] = (
        f"sha256:{hashlib.sha256(package_lock_bytes).hexdigest()}"
    )
    _ = identity_path.write_text(
        json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def test_pyright_identity_binds_lockfile_and_every_installed_byte(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path)

    identity = validate_pyright_package(tmp_path)

    assert identity.version == "1.1.413"
    assert identity.package_tree_sha256.startswith("sha256:")
    assert identity.package_lock_sha256.startswith("sha256:")
    assert identity.identity_lock_sha256.startswith("sha256:")
    assert identity.offline_evidence == (
        identity.identity_lock_sha256,
        identity.package_lock_sha256,
        identity.package_tree_sha256,
    )


def test_pyright_identity_rejects_installed_byte_drift(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    _ = (tmp_path / "node_modules" / "pyright" / "index.js").write_bytes(b"tampered")

    with pytest.raises(PyrightIdentityError, match="installed package tree"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_package_lock_drift(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    with (tmp_path / "package-lock.json").open("ab") as stream:
        _ = stream.write(b" ")

    with pytest.raises(PyrightIdentityError, match="package-lock"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_symlinked_package_member(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    package = tmp_path / "node_modules" / "pyright"
    external = tmp_path / "external.js"
    _ = external.write_bytes(b"external")
    (package / "linked.js").symlink_to(external)

    with pytest.raises(PyrightIdentityError, match="regular files"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_hard_linked_package_member(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    package = tmp_path / "node_modules" / "pyright"
    os.link(package / "index.js", package / "duplicate.js")

    with pytest.raises(PyrightIdentityError, match="link count"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_an_unenumerable_package_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)

    def failing_listdir(_descriptor: int) -> list[str]:
        message = "synthetic enumeration failure"
        raise OSError(message)

    with monkeypatch.context() as patch:
        patch.setattr(os, "listdir", failing_listdir)
        with pytest.raises(PyrightIdentityError, match="could not be enumerated"):
            _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_a_non_utf8_package_name(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    package = tmp_path / "node_modules" / "pyright"
    descriptor = os.open(
        os.fsencode(package) + b"/\xff",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    os.close(descriptor)

    with pytest.raises(PyrightIdentityError, match="paths must be UTF-8"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_an_invalid_enumerated_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)

    def invalid_listdir(_descriptor: int) -> list[str]:
        return [""]

    with monkeypatch.context() as patch:
        patch.setattr(os, "listdir", invalid_listdir)
        with pytest.raises(PyrightIdentityError, match="path is invalid"):
            _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_an_oversized_relative_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)
    monkeypatch.setattr("scripts.pyright_identity._MAX_RELATIVE_PATH_BYTES", 1)

    with pytest.raises(PyrightIdentityError, match="path is oversized"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_excessive_directory_depth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)
    monkeypatch.setattr("scripts.pyright_identity._MAX_DIRECTORY_DEPTH", 0)

    with pytest.raises(PyrightIdentityError, match="tree is too deep"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_enumeration_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)
    real_listdir = os.listdir
    calls: dict[int, int] = {}

    def drifting_listdir(descriptor: int) -> list[str]:
        count = calls.get(descriptor, 0) + 1
        calls[descriptor] = count
        names = real_listdir(descriptor)
        return names if count == 1 else [*names, "appeared-during-scan"]

    with monkeypatch.context() as patch:
        patch.setattr(os, "listdir", drifting_listdir)
        with pytest.raises(PyrightIdentityError, match="changed during enumeration"):
            _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_a_disappearing_enumerated_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)

    def missing_listdir(_descriptor: int) -> list[str]:
        return ["missing.js"]

    with monkeypatch.context() as patch:
        patch.setattr(os, "listdir", missing_listdir)
        with pytest.raises(PyrightIdentityError, match="changed during enumeration"):
            _ = validate_pyright_package(tmp_path)


@pytest.mark.parametrize("member", ["index.js", "lib"])
def test_pyright_identity_rejects_a_member_that_disappears_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    member: str,
) -> None:
    _write_fixture(tmp_path)
    real_open = os.open

    def failing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == member and dir_fd is not None:
            message = "synthetic open race"
            raise OSError(message)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    expected = (
        "directories must be regular" if member == "lib" else "members must be regular"
    )
    with monkeypatch.context() as patch:
        patch.setattr(os, "open", failing_open)
        with pytest.raises(PyrightIdentityError, match=expected):
            _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_a_directory_swapped_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)
    alternate = tmp_path / "alternate"
    alternate.mkdir()
    real_open = os.open

    def substituting_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "lib" and dir_fd is not None:
            return real_open(alternate, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", substituting_open)
        with pytest.raises(PyrightIdentityError, match="changed during enumeration"):
            _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_an_oversized_aggregate_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)
    monkeypatch.setattr("scripts.pyright_identity._MAX_PACKAGE_BYTES", 1)

    with pytest.raises(PyrightIdentityError, match="tree is oversized"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_too_many_package_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_fixture(tmp_path)
    monkeypatch.setattr("scripts.pyright_identity._MAX_PACKAGE_FILES", 1)

    with pytest.raises(PyrightIdentityError, match="too many files"):
        _ = validate_pyright_package(tmp_path)


def test_stable_regular_file_hash_rejects_missing_and_truncated_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "reviewed-node"
    _ = source.write_bytes(b"stable")
    assert stable_regular_file_sha256(source, max_bytes=64).startswith("sha256:")
    with pytest.raises(PyrightIdentityError, match="unavailable"):
        _ = stable_regular_file_sha256(tmp_path / "missing", max_bytes=64)

    def empty_read(_descriptor: int, _size: int) -> bytes:
        return b""

    with monkeypatch.context() as patch:
        patch.setattr(os, "read", empty_read)
        with pytest.raises(PyrightIdentityError, match="changed while it was read"):
            _ = stable_regular_file_sha256(source, max_bytes=64)


def test_stable_regular_file_hash_rejects_trailing_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "reviewed-node"
    _ = source.write_bytes(b"stable")
    real_read = os.read
    calls = 0

    def trailing_read(descriptor: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == _POST_CONTENT_READ:
            return b"x"
        return real_read(descriptor, size)

    with monkeypatch.context() as patch:
        patch.setattr(os, "read", trailing_read)
        with pytest.raises(PyrightIdentityError, match="changed while it was read"):
            _ = stable_regular_file_sha256(source, max_bytes=64)


def test_stable_regular_file_hash_rejects_metadata_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "reviewed-node"
    _ = source.write_bytes(b"stable")
    initial = source.stat()
    real_read = os.read
    calls = 0

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == _POST_CONTENT_READ:
            os.utime(
                source,
                ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
            )
        return real_read(descriptor, size)

    with monkeypatch.context() as patch:
        patch.setattr(os, "read", mutating_read)
        with pytest.raises(PyrightIdentityError, match="changed while it was read"):
            _ = stable_regular_file_sha256(source, max_bytes=64)


def test_pyright_identity_rejects_a_symlinked_package_root(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    package = tmp_path / "node_modules" / "pyright"
    actual = tmp_path / "node_modules" / "actual-pyright"
    _ = package.rename(actual)
    package.symlink_to(actual, target_is_directory=True)

    with pytest.raises(PyrightIdentityError, match="path must not contain symlinks"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_a_missing_package_root(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    package = tmp_path / "node_modules" / "pyright"
    _ = package.rename(tmp_path / "removed-pyright")

    with pytest.raises(PyrightIdentityError, match="tree is unavailable"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_an_invalid_package_lock_record(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path)
    _rebind_package_lock(tmp_path, {"packages": {}})

    with pytest.raises(PyrightIdentityError, match="record is invalid"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_rejects_package_lock_identity_drift(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    _rebind_package_lock(
        tmp_path,
        {
            "packages": {
                "node_modules/pyright": {
                    "version": "0.0.0",
                    "resolved": _RESOLVED,
                    "integrity": _INTEGRITY,
                }
            }
        },
    )

    with pytest.raises(PyrightIdentityError, match="differs from reviewed identity"):
        _ = validate_pyright_package(tmp_path)


def test_pyright_identity_lock_schema_forbids_unknown_fields(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    lock_path = tmp_path / "security" / "pyright-package-lock.json"
    raw = require_json_object(
        load_json_value(lock_path.read_bytes()),
        context="Pyright identity fixture",
    )
    raw["unexpected"] = True
    _ = lock_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(PyrightIdentityError, match="identity lock"):
        _ = validate_pyright_package(tmp_path)
