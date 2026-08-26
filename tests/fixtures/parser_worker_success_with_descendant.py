# Copyright (c) 2026 David Osipov
"""Emit a valid parser result while leaving one process-group child alive."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import IO, cast

from nplg_mcp.parser_ipc import (
    MAX_PARSER_COMMAND_BYTES,
    MAX_PARSER_RESULT_BYTES,
    MetadataFormatsCommand,
    MetadataFormatsPayload,
    ParserSuccess,
    encode_parser_frame,
    parse_command_frame,
)

_IDENTITY_ARGUMENT_COUNT = 2


def _publish_identity(path: Path, process_id: int) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    _ = temporary.write_text(f"{process_id}\n", encoding="ascii")
    _ = temporary.replace(path)


def main() -> int:
    """Return a correlated success after spawning a pipe-detached child."""
    descendant = subprocess.Popen(
        (sys.executable, "-c", "import time; time.sleep(60)"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    if len(sys.argv) == _IDENTITY_ARGUMENT_COUNT:
        _publish_identity(Path(sys.argv[1]), descendant.pid)
    stdin = cast("IO[bytes]", sys.stdin.buffer)
    command = parse_command_frame(stdin.read(MAX_PARSER_COMMAND_BYTES + 1))
    if not isinstance(command, MetadataFormatsCommand):
        return 2
    result = ParserSuccess(
        request_id=command.request_id,
        status="ok",
        payload=MetadataFormatsPayload(
            operation="metadata_formats",
            value=(str(descendant.pid),),
        ),
    )
    frame = encode_parser_frame(result, maximum=MAX_PARSER_RESULT_BYTES)
    stdout = cast("IO[bytes]", sys.stdout.buffer)
    _ = stdout.write(frame)
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
