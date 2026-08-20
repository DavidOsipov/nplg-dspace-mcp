# Copyright (c) 2026 David Osipov
"""Fill stderr before stdout for bounded-pipe worker tests."""

from __future__ import annotations

import sys
import time
from typing import BinaryIO, cast

if __name__ == "__main__":
    stderr = cast("BinaryIO", sys.stderr.buffer)
    _ = stderr.write(b"x" * 70_000)
    stderr.flush()
    time.sleep(60)
