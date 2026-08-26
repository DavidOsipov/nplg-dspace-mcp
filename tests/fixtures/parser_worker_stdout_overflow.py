# Copyright (c) 2026 David Osipov
"""Adversarial parser worker that emits an oversized result stream."""

from __future__ import annotations

import sys
from typing import IO, cast

_OVERFLOW_BYTES = (4 * 1024 * 1024) + 1


def main() -> None:
    """Ignore the command and exceed the parent-owned stdout budget."""
    stdin = cast("IO[bytes]", sys.stdin.buffer)
    stdout = cast("IO[bytes]", sys.stdout.buffer)
    _ = stdin.read()
    _ = stdout.write(b"x" * _OVERFLOW_BYTES)
    _ = stdout.flush()


if __name__ == "__main__":
    main()
