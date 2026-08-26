# Copyright (c) 2026 David Osipov
"""Disposable Unix-worker child scenarios for process-lifecycle tests."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
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

_HANG_REQUESTS = frozenset({1, 4})
_CRASH_REQUEST = 2
_VALID_FRAME_CRASH_REQUEST = 11
_DESCENDANT_CRASH_REQUEST = 14


def _publish_processes(path: Path, processes: tuple[int, ...]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    _ = temporary.write_text(
        "".join(f"{process_id}\n" for process_id in processes),
        encoding="ascii",
    )
    _ = temporary.replace(path)


def main() -> int:
    """Hang, crash, or return a source-bound success by exact request ID."""
    input_stream = cast("BinaryIO", sys.stdin.buffer)
    output_stream = cast("BinaryIO", sys.stdout.buffer)
    size = int.from_bytes(input_stream.read(4), "big")
    command = parse_command_frame(input_stream.read(size))
    if not isinstance(command, InspectCommand):
        message = "job-scenario fixture accepts only inspect commands"
        raise TypeError(message)

    probe_root = Path(sys.argv[1])
    process_path = probe_root / f"{command.request_id.hex}.pids"
    if command.request_id.int in _HANG_REQUESTS:
        descendant = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _publish_processes(process_path, (os.getpid(), descendant.pid))
        time.sleep(60)
        return 1

    _publish_processes(process_path, (os.getpid(),))
    if command.request_id.int == _CRASH_REQUEST:
        return 23
    if command.request_id.int == _DESCENDANT_CRASH_REQUEST:
        descendant = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
        )
        _publish_processes(process_path, (os.getpid(), descendant.pid))
        return 23

    work_root = Path(os.environ["NPLG_PDF_WORK_ROOT"])
    source = work_root / "cache" / command.source_relative_path
    result = PdfSuccess(
        request_id=command.request_id,
        status="ok",
        payload=InspectPayload(
            operation="inspect",
            value=PdfInspectionOutput(
                source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                page_count=0,
                renderer_version="job-scenario-test-worker",
                pages=(),
            ),
        ),
    )
    _ = output_stream.write(encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES))
    output_stream.flush()
    return 23 if command.request_id.int == _VALID_FRAME_CRASH_REQUEST else 0


if __name__ == "__main__":
    raise SystemExit(main())
