# Copyright (c) 2026 David Osipov
"""Install an enumerated external quality tool from the reviewed lock."""

from __future__ import annotations

import argparse
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import TextIO

if __name__ == "__main__" and not __package__:
    script_package_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, script_package_root.as_posix())
    __package__ = "scripts"

from scripts.bootstrap_toolchain import (
    Downloader,
    HttpsDownloader,
    ToolchainError,
    VersionChecker,
    install_from_lock,
)

_SUPPORTED_TARGETS = {
    ("linux", "amd64"): "x86_64-unknown-linux-gnu",
    ("linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("linux", "aarch64"): "aarch64-unknown-linux-gnu",
    ("linux", "arm64"): "aarch64-unknown-linux-gnu",
}


@dataclass(frozen=True, slots=True)
class ExternalToolOptions:
    """Host and version seam for one locked external-tool installation."""

    system_name: str | None = None
    machine: str | None = None
    version_checker: VersionChecker | None = None


_DEFAULT_OPTIONS = ExternalToolOptions()


def install_external_tool(
    lock_path: Path,
    *,
    tool: str,
    destination: Path,
    downloader: Downloader,
    options: ExternalToolOptions = _DEFAULT_OPTIONS,
) -> Path:
    """Install one exact external tool for an explicitly supported platform."""
    observed_system = (
        platform.system() if options.system_name is None else options.system_name
    )
    observed_machine = (
        platform.machine() if options.machine is None else options.machine
    )
    target = _SUPPORTED_TARGETS.get(
        (observed_system.casefold(), observed_machine.casefold())
    )
    if target is None:
        msg = "unsupported external-tool platform"
        raise ToolchainError(msg)
    return install_from_lock(
        lock_path,
        tool=tool,
        target=target,
        destination=destination,
        downloader=downloader,
        version_checker=options.version_checker,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--lock", type=Path, required=True)
    _ = parser.add_argument("--tool", required=True)
    _ = parser.add_argument("--destination", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Install one host-selected locked tool with a stable failure status."""
    values = cast("dict[str, object]", vars(_parser().parse_args(argv)))
    lock_path = cast("Path", values["lock"])
    tool = cast("str", values["tool"])
    destination = cast("Path", values["destination"])
    try:
        _ = install_external_tool(
            lock_path,
            tool=tool,
            destination=destination,
            downloader=HttpsDownloader(),
        )
    except ToolchainError as exc:
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write(f"external-tool bootstrap failed: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
