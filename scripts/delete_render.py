#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Delete one cached render from the local deployment filesystem."""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from re import fullmatch
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import TextIO

from nplg_mcp.errors import AppError
from nplg_mcp.pdf import PdfProcessor
from nplg_mcp.storage import ContentAddressedStore


class RenderDeleter(Protocol):
    """Small injected boundary needed by the operator CLI."""

    def delete_render(self, render_id: str) -> bool:
        """Delete one render by identifier."""
        ...


class ProcessorFactory(Protocol):
    """Build the render-deletion service for one cache root."""

    def __call__(self, root: Path) -> RenderDeleter:
        """Return a service bound to ``root``."""
        ...


@dataclass(frozen=True, slots=True)
class CliDependencies:
    """Injected environment and effects for ``main``."""

    environ: Mapping[str, str]
    stdin: TextIO
    stdout: TextIO
    stderr: TextIO
    processor_factory: ProcessorFactory


@dataclass(frozen=True, slots=True)
class DeleteArguments:
    """Validated deletion command arguments."""

    render_id: str
    cache_dir: Path
    confirmation: str | None


def _parser(environ: Mapping[str, str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "render_id",
        help="Render identifier, for example rnd_<32 lowercase hex characters>",
    )
    _ = parser.add_argument(
        "--cache-dir",
        default=environ.get("CACHE_DIR", "/data/cache"),
        help="Cache root; defaults to CACHE_DIR or /data/cache",
    )
    _ = parser.add_argument(
        "--confirm",
        help="Exact render identifier required for noninteractive deletion",
    )
    return parser


def _parse_arguments(
    argv: Sequence[str], dependencies: CliDependencies
) -> DeleteArguments | int:
    parser = _parser(dependencies.environ)
    try:
        with (
            redirect_stdout(dependencies.stdout),
            redirect_stderr(dependencies.stderr),
        ):
            values = cast("dict[str, object]", vars(parser.parse_args(argv)))
    except SystemExit as exc:
        return exc.code if type(exc.code) is int else 1
    render_id = values["render_id"]
    cache_dir = values["cache_dir"]
    confirmation = values["confirm"]
    if not isinstance(render_id, str) or not isinstance(cache_dir, str):
        return _write_failure(dependencies, "argument parser returned invalid values")
    if confirmation is not None and not isinstance(confirmation, str):
        return _write_failure(dependencies, "argument parser returned invalid values")
    return DeleteArguments(
        render_id=render_id,
        cache_dir=Path(cache_dir),
        confirmation=confirmation,
    )


def _default_processor_factory(root: Path) -> RenderDeleter:
    return PdfProcessor(store=ContentAddressedStore(root))


def _default_dependencies() -> CliDependencies:
    return CliDependencies(
        environ=os.environ,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        processor_factory=_default_processor_factory,
    )


def _write_failure(dependencies: CliDependencies, message: str) -> int:
    try:
        _ = dependencies.stderr.write(f"FAIL: {message}\n")
    except (OSError, UnicodeError):
        return 1
    return 2


def _confirm(arguments: DeleteArguments, dependencies: CliDependencies) -> bool:
    confirmation = arguments.confirmation
    if confirmation is None and not dependencies.stdin.isatty():
        _ = _write_failure(dependencies, "noninteractive deletion requires --confirm")
        return False
    if confirmation is None:
        try:
            _ = dependencies.stderr.write(
                f"Type {arguments.render_id} to confirm deletion: "
            )
            confirmation = dependencies.stdin.readline().rstrip("\r\n")
        except (OSError, UnicodeError):
            _ = _write_failure(dependencies, "confirmation input failed")
            return False
    if confirmation == arguments.render_id:
        return True
    _ = _write_failure(dependencies, "confirmation did not match render identifier")
    return False


def _write_result(
    dependencies: CliDependencies, *, render_id: str, deleted: bool
) -> int:
    payload: dict[str, str | bool] = {"render_id": render_id, "deleted": deleted}
    try:
        _ = dependencies.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    except (OSError, UnicodeError):
        _ = _write_failure(dependencies, "output write failed")
        return 1
    return 0


def _delete(arguments: DeleteArguments, dependencies: CliDependencies) -> int:
    root = arguments.cache_dir.expanduser().resolve()
    if not root.is_dir() or not (root / "renders").is_dir():
        return _write_failure(dependencies, "cache directory is not initialized")
    try:
        deleted = dependencies.processor_factory(root).delete_render(
            arguments.render_id
        )
    except AppError as exc:
        return _write_failure(dependencies, exc.message)
    except KeyboardInterrupt:
        _ = _write_failure(dependencies, "cancelled")
        return 130
    return _write_result(dependencies, render_id=arguments.render_id, deleted=deleted)


def main(argv: Sequence[str], *, dependencies: CliDependencies) -> int:
    """Run the injected deletion CLI."""
    parsed = _parse_arguments(argv, dependencies)
    if isinstance(parsed, int):
        return parsed
    if fullmatch(r"rnd_[0-9a-f]{32}", parsed.render_id) is None:
        return _write_failure(dependencies, "invalid render identifier")
    try:
        confirmed = _confirm(parsed, dependencies)
    except KeyboardInterrupt:
        _ = _write_failure(dependencies, "cancelled")
        return 130
    if not confirmed:
        return 2
    return _delete(parsed, dependencies)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], dependencies=_default_dependencies()))
