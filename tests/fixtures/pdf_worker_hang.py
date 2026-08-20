# Copyright (c) 2026 David Osipov
"""Spawn one descendant and hang for PDF worker lifecycle tests."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path


def main() -> None:
    """Publish process identities and remain alive until the group is killed."""
    descendant = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pid_path = Path(sys.argv[1])
    temporary_path = pid_path.with_name(f".{pid_path.name}.{os.getpid()}.tmp")
    _ = temporary_path.write_text(
        f"{os.getpid()}\n{descendant.pid}\n",
        encoding="ascii",
    )
    _ = temporary_path.replace(pid_path)
    time.sleep(60)


if __name__ == "__main__":
    main()
