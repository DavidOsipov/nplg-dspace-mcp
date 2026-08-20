# Copyright (c) 2026 David Osipov
"""Emit malformed worker transport frames for parent-side rejection tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, cast

from nplg_mcp.pdf_ipc import MAX_RESULT_FRAME_BYTES


def main() -> None:
    """Consume stdin, then emit the selected malformed response."""
    input_stream = cast("BinaryIO", sys.stdin.buffer)
    output_stream = cast("BinaryIO", sys.stdout.buffer)
    _ = input_stream.read()
    mode = sys.argv[1]
    if mode == "permission-tree":
        work_root = Path(os.environ["NPLG_PDF_WORK_ROOT"])
        blocked = work_root / "worker-output" / "mode-zero"
        blocked.mkdir(parents=True)
        _ = blocked.joinpath("leaf").write_bytes(b"hostile worker output")
        blocked.chmod(0)
        mode = "truncated"
    if mode == "truncated":
        _ = output_stream.write((12).to_bytes(4, "big") + b"{}")
    elif mode == "oversized":
        _ = output_stream.write((MAX_RESULT_FRAME_BYTES + 1).to_bytes(4, "big"))
    elif mode == "trailing":
        _ = output_stream.write((2).to_bytes(4, "big") + b"{}x")
    elif mode == "invalid-json":
        _ = output_stream.write((1).to_bytes(4, "big") + b"{")
    else:
        raise RuntimeError(mode)
    output_stream.flush()


if __name__ == "__main__":
    main()
