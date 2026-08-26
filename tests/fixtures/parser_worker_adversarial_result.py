# Copyright (c) 2026 David Osipov
"""Emit correlated and adversarial parser result frames for parent validation."""

from __future__ import annotations

import sys
from typing import IO, cast
from uuid import UUID

from nplg_mcp.errors import ErrorCode
from nplg_mcp.parser_ipc import (
    MAX_PARSER_COMMAND_BYTES,
    MAX_PARSER_RESULT_BYTES,
    MetadataFormatsCommand,
    MetadataFormatsPayload,
    ParserErrorDetails,
    ParserFailure,
    ParserPublicError,
    ParserResult,
    ParserSuccess,
    SearchPayload,
    encode_parser_frame,
    parse_command_frame,
)
from nplg_mcp.parsers import SearchPage

_STDERR_OVERFLOW_BYTES = 16_385
_PRIVATE_STDERR_CANARY = b"parser-private-stderr-canary"


def _result(mode: str, command: MetadataFormatsCommand) -> ParserResult:
    request_id = (
        UUID("00000000-0000-4000-8000-000000000001")
        if mode == "request-id"
        else command.request_id
    )
    if mode == "success-operation":
        return ParserSuccess(
            request_id=request_id,
            status="ok",
            payload=SearchPayload(
                operation="search",
                value=SearchPage(
                    items=(),
                    total=0,
                    next_offset=None,
                    source_url="https://example.test/search",
                ),
            ),
        )
    if mode in {"failure-operation", "expected-failure"}:
        return ParserFailure(
            request_id=request_id,
            status="error",
            operation=("search" if mode == "failure-operation" else "metadata_formats"),
            payload=ParserPublicError(
                code=ErrorCode.RESTRICTED,
                message="The parser fixture denied this record.",
                http_status=403,
                details=ParserErrorDetails(metadata_prefix="dim"),
            ),
        )
    return ParserSuccess(
        request_id=request_id,
        status="ok",
        payload=MetadataFormatsPayload(
            operation="metadata_formats",
            value=("dim",),
        ),
    )


def main() -> int:
    """Read one command and emit the selected bounded adversarial response."""
    mode = sys.argv[1]
    stdin = cast("IO[bytes]", sys.stdin.buffer)
    stdout = cast("IO[bytes]", sys.stdout.buffer)
    stderr = cast("IO[bytes]", sys.stderr.buffer)
    command = parse_command_frame(stdin.read(MAX_PARSER_COMMAND_BYTES + 1))
    if not isinstance(command, MetadataFormatsCommand):
        return 2
    frame = encode_parser_frame(_result(mode, command), maximum=MAX_PARSER_RESULT_BYTES)
    if mode == "noncanonical":
        frame = b" " + frame
    elif mode == "malformed":
        frame = b'{"status":'
    elif mode == "stderr":
        _ = stderr.write(_PRIVATE_STDERR_CANARY)
        stderr.flush()
    elif mode == "stderr-overflow":
        _ = stderr.write(b"x" * _STDERR_OVERFLOW_BYTES)
        stderr.flush()
    _ = stdout.write(frame)
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
