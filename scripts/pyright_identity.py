# Copyright (c) 2026 David Osipov
"""Fail-closed identity verification for the reviewed Pyright installation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from nplg_mcp.json_types import load_json_value, require_json_object

if TYPE_CHECKING:
    from pathlib import Path

type Sha256 = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$"),
]

_PYRIGHT_VERSION: Literal["1.1.413"] = "1.1.413"
_TREE_DOMAIN = b"nplg-pyright-package-tree-v1\0"
_MAX_LOCK_BYTES = 1024 * 1024
_MAX_PACKAGE_FILES = 10_000
_MAX_PACKAGE_BYTES = 64 * 1024 * 1024
_MAX_PACKAGE_FILE_BYTES = 16 * 1024 * 1024
_MAX_RELATIVE_PATH_BYTES = 4096
_MAX_DIRECTORY_DEPTH = 32
_READ_SIZE = 64 * 1024


class PyrightIdentityError(RuntimeError):
    """Raised when the reviewed Pyright package identity cannot be proven."""


def _fail(message: str) -> NoReturn:
    raise PyrightIdentityError(message)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _PyrightPackageLock(_StrictModel):
    schema_version: Literal[1]
    package: Literal["pyright"]
    version: Literal["1.1.413"]
    resolved: Literal["https://registry.npmjs.org/pyright/-/pyright-1.1.413.tgz"]
    integrity: Literal[
        "sha512-1lpxKrh0DHHpfAQOfciZo2ojua2jase3wwO9at8kldc+F/p1PBscxA5CQ3G1qg5lMOMhXo6ZaiMLMXEAqADIAg=="
    ]
    package_lock_sha256: Sha256
    package_tree_sha256: Sha256
    file_count: int = Field(ge=1, le=_MAX_PACKAGE_FILES)
    total_bytes: int = Field(ge=1, le=_MAX_PACKAGE_BYTES)


@dataclass(frozen=True, slots=True)
class PyrightPackageIdentity:
    """Digest evidence for the lock, npm graph, and installed package tree."""

    version: Literal["1.1.413"]
    package_tree_sha256: str
    package_lock_sha256: str
    identity_lock_sha256: str

    @property
    def offline_evidence(self) -> tuple[str, str, str]:
        """Return the complete immutable evidence tuple for release records."""
        return (
            self.identity_lock_sha256,
            self.package_lock_sha256,
            self.package_tree_sha256,
        )


@dataclass(frozen=True, slots=True)
class _FileRecord:
    relative_path: bytes
    size: int
    content_sha256: bytes


def _directory_signature(status: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _directory_names(descriptor: int) -> list[str]:
    try:
        return sorted(os.listdir(descriptor))
    except OSError:
        _fail("Pyright installed package tree could not be enumerated")


def _relative_path(parts: tuple[str, ...], name: str) -> tuple[tuple[str, ...], bytes]:
    try:
        encoded_name = name.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail("Pyright installed package paths must be UTF-8")
    if not encoded_name or b"/" in encoded_name or b"\0" in encoded_name:
        _fail("Pyright installed package path is invalid")
    relative_parts = (*parts, name)
    relative = "/".join(relative_parts).encode("utf-8", errors="strict")
    if len(relative) > _MAX_RELATIVE_PATH_BYTES:
        _fail("Pyright installed package path is oversized")
    return relative_parts, relative


def _empty_file_records() -> list[_FileRecord]:
    return []


def _record_path(record: _FileRecord) -> bytes:
    return record.relative_path


@dataclass(slots=True)
class _TreeScanner:
    records: list[_FileRecord] = field(default_factory=_empty_file_records)
    total_bytes: int = 0

    def scan(self, root_descriptor: int) -> tuple[_FileRecord, ...]:
        self._visit(root_descriptor, ())
        return tuple(sorted(self.records, key=_record_path))

    def _visit(self, directory_descriptor: int, parts: tuple[str, ...]) -> None:
        if len(parts) > _MAX_DIRECTORY_DEPTH:
            _fail("Pyright installed package tree is too deep")
        before = os.fstat(directory_descriptor)
        names = _directory_names(directory_descriptor)
        for name in names:
            self._visit_entry(directory_descriptor, parts, name)
        after_names = _directory_names(directory_descriptor)
        after = os.fstat(directory_descriptor)
        if names != after_names or _directory_signature(before) != _directory_signature(
            after
        ):
            _fail("Pyright installed package tree changed during enumeration")

    def _visit_entry(
        self,
        directory_descriptor: int,
        parts: tuple[str, ...],
        name: str,
    ) -> None:
        relative_parts, relative = _relative_path(parts, name)
        try:
            expected = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            _fail("Pyright installed package tree changed during enumeration")
        if stat.S_ISDIR(expected.st_mode):
            self._visit_directory(
                directory_descriptor,
                name,
                expected,
                relative_parts,
            )
        elif stat.S_ISREG(expected.st_mode):
            self._visit_file(directory_descriptor, name, expected, relative)
        else:
            _fail("Pyright installed package members must be regular files")

    def _visit_directory(
        self,
        parent_descriptor: int,
        name: str,
        expected: os.stat_result,
        relative_parts: tuple[str, ...],
    ) -> None:
        try:
            child = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                dir_fd=parent_descriptor,
            )
        except OSError:
            _fail("Pyright installed package directories must be regular")
        try:
            opened = os.fstat(child)
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
            ) != (
                expected.st_dev,
                expected.st_ino,
                expected.st_mode,
            ):
                _fail("Pyright installed package tree changed during enumeration")
            self._visit(child, relative_parts)
        finally:
            os.close(child)

    def _visit_file(
        self,
        directory_descriptor: int,
        name: str,
        expected: os.stat_result,
        relative: bytes,
    ) -> None:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_descriptor,
            )
        except OSError:
            _fail("Pyright installed package members must be regular files")
        try:
            content = _stable_descriptor_bytes(
                descriptor,
                expected=expected,
                max_bytes=_MAX_PACKAGE_FILE_BYTES,
                context="Pyright installed package member",
            )
        finally:
            os.close(descriptor)
        self.total_bytes += len(content)
        if self.total_bytes > _MAX_PACKAGE_BYTES:
            _fail("Pyright installed package tree is oversized")
        self.records.append(
            _FileRecord(
                relative_path=relative,
                size=len(content),
                content_sha256=hashlib.sha256(content).digest(),
            )
        )
        if len(self.records) > _MAX_PACKAGE_FILES:
            _fail("Pyright installed package tree has too many files")


def _stable_descriptor_bytes(
    descriptor: int,
    *,
    expected: os.stat_result,
    max_bytes: int,
    context: str,
) -> bytes:
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_size < 0
        or opened.st_size > max_bytes
        or (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size)
        != (expected.st_dev, expected.st_ino, expected.st_mode, expected.st_size)
    ):
        _fail(f"{context} is not one bounded regular file with link count one")
    chunks: list[bytes] = []
    remaining = opened.st_size
    while remaining:
        chunk = os.read(descriptor, min(_READ_SIZE, remaining))
        if not chunk:
            _fail(f"{context} changed while it was read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        _fail(f"{context} changed while it was read")
    after = os.fstat(descriptor)
    if (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_nlink,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        _fail(f"{context} changed while it was read")
    return b"".join(chunks)


def _read_stable_file(path: Path, *, max_bytes: int, context: str) -> bytes:
    try:
        expected = path.stat(follow_symlinks=False)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        _fail(f"{context} is unavailable")
    try:
        return _stable_descriptor_bytes(
            descriptor,
            expected=expected,
            max_bytes=max_bytes,
            context=context,
        )
    finally:
        os.close(descriptor)


def stable_regular_file_sha256(path: Path, *, max_bytes: int) -> str:
    """Hash one stable, no-follow, single-link regular file."""
    content = _read_stable_file(
        path,
        max_bytes=max_bytes,
        context="reviewed executable",
    )
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _package_records(package: Path) -> tuple[_FileRecord, ...]:
    try:
        if package.resolve(strict=True) != package:
            _fail("Pyright package path must not contain symlinks")
        root_descriptor = os.open(
            package,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
    except OSError:
        _fail("Pyright installed package tree is unavailable")
    try:
        return _TreeScanner().scan(root_descriptor)
    finally:
        os.close(root_descriptor)


def _tree_identity(package: Path) -> tuple[str, int, int]:
    records = _package_records(package)
    digest = hashlib.sha256(_TREE_DOMAIN)
    total_bytes = 0
    for record in records:
        total_bytes += record.size
        digest.update(len(record.relative_path).to_bytes(4, "big"))
        digest.update(record.relative_path)
        digest.update(record.size.to_bytes(8, "big"))
        digest.update(record.content_sha256)
    return f"sha256:{digest.hexdigest()}", len(records), total_bytes


def _validate_package_lock(raw: bytes, lock: _PyrightPackageLock) -> None:
    if f"sha256:{hashlib.sha256(raw).hexdigest()}" != lock.package_lock_sha256:
        _fail("package-lock.json does not match its reviewed digest")
    try:
        document = require_json_object(
            load_json_value(raw),
            context="package-lock.json",
        )
        packages = require_json_object(
            document["packages"],
            context="package-lock.json packages",
        )
        record = require_json_object(
            packages["node_modules/pyright"],
            context="package-lock.json Pyright record",
        )
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("package-lock.json Pyright record is invalid")
    if (
        record.get("version") != lock.version
        or record.get("resolved") != lock.resolved
        or record.get("integrity") != lock.integrity
    ):
        _fail("package-lock.json Pyright record differs from reviewed identity")


def validate_pyright_package(root: Path) -> PyrightPackageIdentity:
    """Validate exact lock bytes and every installed Pyright package byte."""
    lock_path = root / "security" / "pyright-package-lock.json"
    lock_raw = _read_stable_file(
        lock_path,
        max_bytes=_MAX_LOCK_BYTES,
        context="Pyright identity lock",
    )
    try:
        lock = _PyrightPackageLock.model_validate_json(lock_raw, strict=True)
    except ValidationError:
        _fail("Pyright identity lock schema is invalid")
    package_lock_raw = _read_stable_file(
        root / "package-lock.json",
        max_bytes=_MAX_LOCK_BYTES,
        context="package-lock.json",
    )
    _validate_package_lock(package_lock_raw, lock)
    tree_sha256, file_count, total_bytes = _tree_identity(
        root / "node_modules" / "pyright"
    )
    if (
        tree_sha256 != lock.package_tree_sha256
        or file_count != lock.file_count
        or total_bytes != lock.total_bytes
    ):
        _fail("Pyright installed package tree differs from reviewed identity")
    return PyrightPackageIdentity(
        version=_PYRIGHT_VERSION,
        package_tree_sha256=tree_sha256,
        package_lock_sha256=lock.package_lock_sha256,
        identity_lock_sha256=f"sha256:{hashlib.sha256(lock_raw).hexdigest()}",
    )
