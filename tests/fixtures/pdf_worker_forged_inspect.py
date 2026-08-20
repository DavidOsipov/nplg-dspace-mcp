# Copyright (c) 2026 David Osipov
"""Emit a well-typed inspection response bound to the wrong source digest."""

from __future__ import annotations

import sys
from typing import BinaryIO, cast
from uuid import UUID

from nplg_mcp.errors import ErrorCode
from nplg_mcp.pdf_ipc import (
    MAX_RESULT_FRAME_BYTES,
    InspectPayload,
    PdfFailure,
    PdfInspectionOutput,
    PdfSuccess,
    PublicWorkerError,
    encode_frame,
    parse_command_frame,
)


def main() -> int:
    """Read one command and forge only the otherwise-valid source digest."""
    input_stream = cast("BinaryIO", sys.stdin.buffer)
    output_stream = cast("BinaryIO", sys.stdout.buffer)
    size = int.from_bytes(input_stream.read(4), "big")
    command = parse_command_frame(input_stream.read(size))
    mode = sys.argv[1] if len(sys.argv) > 1 else "source"
    if mode == "operation":
        failure = PdfFailure(
            request_id=command.request_id,
            status="error",
            operation="manifest",
            payload=PublicWorkerError(
                code=ErrorCode.INVALID_INPUT,
                message="forged operation",
            ),
        )
        _ = output_stream.write(encode_frame(failure, maximum=MAX_RESULT_FRAME_BYTES))
        output_stream.flush()
        return 0
    request_id = (
        UUID("00000000-0000-4000-8000-000000000099")
        if mode == "request"
        else command.request_id
    )
    result = PdfSuccess(
        request_id=request_id,
        status="ok",
        payload=InspectPayload(
            operation="inspect",
            value=PdfInspectionOutput(
                source_sha256="0" * 64,
                page_count=0,
                renderer_version="forged-test-worker",
                pages=(),
            ),
        ),
    )
    _ = output_stream.write(encode_frame(result, maximum=MAX_RESULT_FRAME_BYTES))
    output_stream.flush()
    return 1 if mode == "exit-nonzero" else 0


if __name__ == "__main__":
    raise SystemExit(main())
