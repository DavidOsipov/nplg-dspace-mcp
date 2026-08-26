# Copyright (c) 2026 David Osipov
"""Adversarial parser worker that leaves both a leader and descendant hung."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


def main() -> None:
    """Publish identities, then remain alive until the parent kills the group."""
    identity_path = Path(sys.argv[1])
    descendant = subprocess.Popen(
        (sys.executable, "-c", "import time; time.sleep(60)"),
        close_fds=True,
    )
    temporary = identity_path.with_name(f".{identity_path.name}.tmp")
    _ = temporary.write_text(
        f"{descendant.pid}\n",
        encoding="ascii",
    )
    _ = temporary.replace(identity_path)
    time.sleep(60)


if __name__ == "__main__":
    main()
