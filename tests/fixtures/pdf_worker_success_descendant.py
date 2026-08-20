# Copyright (c) 2026 David Osipov
"""Return a valid result after spawning one same-group descendant."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO, cast

from nplg_mcp.pdf_ipc import (
    MAX_RESULT_FRAME_BYTES,
    InspectCommand,
    InspectPayload,
    PdfInspectionOutput,
    PdfSuccess,
    encode_frame,
    parse_command_frame,
)


def main() -> int:
    """Emit a source-bound inspection while leaving a descendant running."""
    input_stream = cast("BinaryIO", sys.stdin.buffer)
    output_stream = cast("BinaryIO", sys.stdout.buffer)
    size = int.from_bytes(input_stream.read(4), "big")
    command = parse_command_frame(input_stream.read(size))
    if not isinstance(command, InspectCommand):
        msg = "success-descendant fixture accepts only inspect commands"
        raise TypeError(msg)
    work_root = Path(os.environ["NPLG_PDF_WORK_ROOT"])
    source_path = work_root / "cache" / command.source_relative_path
    source_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
    descendant = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pid_path = Path(sys.argv[1])
    temporary_path = pid_path.with_name(f".{pid_path.name}.{os.getpid()}.tmp")
    _ = temporary_path.write_text(f"{descendant.pid}\n", encoding="ascii")
    _ = temporary_path.replace(pid_path)
    result = PdfSuccess(
        request_id=command.request_id,
        status="ok",
        payload=InspectPayload(
            operation="inspect",
            value=PdfInspectionOutput(
                source_sha256=source_sha256,
                page_count=0,
                renderer_version="success-descendant-test-worker",
                pages=(),
            ),
        ),
    )
    _ = output_stream.write(encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES))
    output_stream.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
