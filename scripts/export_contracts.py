# Copyright (c) 2026 David Osipov
"""Generate or verify the deterministic Phase 2 contract-schema artifacts."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from nplg_mcp.contracts.schema import (
    aggregate_contract_schema,
    canonical_json_bytes,
    schema_manifest,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import TextIO

_ROOT = Path(__file__).resolve().parent.parent
_OUTPUT = _ROOT / "contracts" / "generated"
_EXPECTED_FILES = frozenset({"schema-manifest.json", "tool-contracts.schema.json"})
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024


class ExportError(RuntimeError):
    """One bounded contract-export failure."""


@dataclass(frozen=True, slots=True)
class ExportRequest:
    """Closed command request."""

    check: bool


def _fail(message: str) -> None:
    raise ExportError(message)


def _artifacts() -> dict[str, bytes]:
    schema = aggregate_contract_schema()
    manifest = schema_manifest()
    artifacts = {
        "schema-manifest.json": canonical_json_bytes(manifest),
        "tool-contracts.schema.json": canonical_json_bytes(schema),
    }
    if frozenset(artifacts) != _EXPECTED_FILES:
        _fail("contract exporter produced an unexpected artifact inventory")
    if any(
        not payload or len(payload) > _MAX_ARTIFACT_BYTES
        for payload in artifacts.values()
    ):
        _fail("contract exporter produced an empty or oversized artifact")
    return artifacts


def _validated_output_directory(*, create: bool) -> Path:
    if create and not _OUTPUT.exists():
        _OUTPUT.mkdir(mode=0o755)
    try:
        metadata = _OUTPUT.lstat()
    except OSError as exc:
        message = "generated contract directory is unavailable"
        raise ExportError(message) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        _fail("generated contract path must be a real directory")
    return _OUTPUT


def _inventory(directory: Path) -> frozenset[str]:
    try:
        entries = tuple(directory.iterdir())
    except OSError as exc:
        message = "generated contract inventory is unavailable"
        raise ExportError(message) from exc
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        _fail("generated contract directory contains a non-regular entry")
    return frozenset(entry.name for entry in entries)


def _read_artifact(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        message = "generated contract artifact is missing"
        raise ExportError(message) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > _MAX_ARTIFACT_BYTES
    ):
        _fail("generated contract artifact is not a bounded regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        message = "generated contract artifact could not be read"
        raise ExportError(message) from exc


def _write_artifact(path: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        try:
            os.fchmod(descriptor, 0o644)
            view = memoryview(payload)
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    _fail("generated contract artifact write was incomplete")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except ExportError:
        temporary.unlink(missing_ok=True)
        raise
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        message = "generated contract artifact could not be written"
        raise ExportError(message) from exc
    try:
        _ = temporary.replace(path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        message = "generated contract artifact could not be replaced"
        raise ExportError(message) from exc


def export_contracts(request: ExportRequest) -> None:
    """Generate or byte-verify the exact artifact pair."""
    artifacts = _artifacts()
    directory = _validated_output_directory(create=not request.check)
    if request.check:
        if _inventory(directory) != _EXPECTED_FILES:
            _fail("generated contract inventory does not match the closed policy")
        for name, expected in artifacts.items():
            if _read_artifact(directory / name) != expected:
                _fail(f"generated contract artifact is stale: {name}")
        return
    unexpected = _inventory(directory) - _EXPECTED_FILES
    if unexpected:
        _fail("generated contract directory contains an unexpected artifact")
    for name, payload in artifacts.items():
        _write_artifact(directory / name, payload)
    if _inventory(directory) != _EXPECTED_FILES:
        _fail("generated contract inventory changed during export")


def parse_arguments(argv: Sequence[str] | None = None) -> ExportRequest:
    """Parse the deliberately tiny exporter CLI."""
    parser = argparse.ArgumentParser(
        description="Generate or verify strict MCP contract schemas.",
        allow_abbrev=False,
    )
    _ = parser.add_argument("--check", action="store_true")
    values = cast("dict[str, object]", vars(parser.parse_args(argv)))
    return ExportRequest(check=cast("bool", values["check"]))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the exporter."""
    export_contracts(parse_arguments(argv))
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    """Render a bounded process-facing error without a traceback."""
    try:
        return main(argv)
    except ExportError as exc:
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write(f"contract export failed: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
