# Copyright (c) 2026 David Osipov
"""One-shot, resource-limited worker for untrusted repository markup."""

from __future__ import annotations

import os
import resource
import sys
from typing import IO, cast

from .errors import AppError, ErrorCode
from .parser_ipc import (
    MAX_PARSER_COMMAND_BYTES,
    MAX_PARSER_RESULT_BYTES,
    ItemCommand,
    ItemPayload,
    MetadataFormatsCommand,
    MetadataFormatsPayload,
    OaiRecordPayload,
    ParserCommand,
    ParserErrorDetails,
    ParserFailure,
    ParserIpcError,
    ParserPublicError,
    ParserResult,
    ParserSuccess,
    SearchCommand,
    SearchPayload,
    SearchVersionCommand,
    SearchVersionPayload,
    encode_parser_frame,
    parse_command_frame,
)
from .parsers import (
    parse_item_page,
    parse_metadata_formats,
    parse_oai_record,
    parse_search_results,
    parse_search_version,
)

_CPU_SECONDS = 3
_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024
_OPEN_FILES = 32
_PROCESSES = 1


def apply_resource_limits() -> None:
    """Apply immutable hard ceilings before reading attacker-controlled bytes."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (_CPU_SECONDS, _CPU_SECONDS))
    resource.setrlimit(
        resource.RLIMIT_AS,
        (_ADDRESS_SPACE_BYTES, _ADDRESS_SPACE_BYTES),
    )
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (_OPEN_FILES, _OPEN_FILES))
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (_PROCESSES, _PROCESSES))


def _error_details(error: AppError) -> ParserErrorDetails | None:
    raw = error.safe_details
    if raw is None:
        return None
    values = dict(raw)
    allowed = {"source_url", "oai_error", "metadata_prefix"}
    if not set(values).issubset(allowed) or any(
        type(value) is not str for value in values.values()
    ):
        return None
    return ParserErrorDetails.model_validate(values, strict=True)


def _expected_failure(command: ParserCommand, error: AppError) -> ParserFailure:
    return ParserFailure(
        request_id=command.request_id,
        status="error",
        operation=command.operation,
        payload=ParserPublicError(
            code=error.code,
            message=error.message,
            http_status=error.http_status,
            details=_error_details(error),
        ),
    )


def _unexpected_failure(command: ParserCommand) -> ParserFailure:
    return ParserFailure(
        request_id=command.request_id,
        status="error",
        operation=command.operation,
        payload=ParserPublicError(
            code=ErrorCode.UPSTREAM_FAILURE,
            message="The repository response could not be parsed safely.",
            http_status=502,
        ),
    )


def _execute(command: ParserCommand) -> ParserSuccess:
    if isinstance(command, SearchCommand):
        return ParserSuccess(
            request_id=command.request_id,
            status="ok",
            payload=SearchPayload(
                operation="search",
                value=parse_search_results(
                    command.markup,
                    source_url=command.source_url,
                    page_size=command.page_size,
                ),
            ),
        )
    if isinstance(command, SearchVersionCommand):
        return ParserSuccess(
            request_id=command.request_id,
            status="ok",
            payload=SearchVersionPayload(
                operation="search_version",
                value=parse_search_version(
                    command.markup,
                    source_url=command.source_url,
                ),
            ),
        )
    if isinstance(command, ItemCommand):
        return ParserSuccess(
            request_id=command.request_id,
            status="ok",
            payload=ItemPayload(
                operation="item",
                value=parse_item_page(
                    command.markup,
                    expected_handle=command.expected_handle,
                    source_url=command.source_url,
                ),
            ),
        )
    if isinstance(command, MetadataFormatsCommand):
        return ParserSuccess(
            request_id=command.request_id,
            status="ok",
            payload=MetadataFormatsPayload(
                operation="metadata_formats",
                value=parse_metadata_formats(command.markup),
            ),
        )
    return ParserSuccess(
        request_id=command.request_id,
        status="ok",
        payload=OaiRecordPayload(
            operation="oai_record",
            value=parse_oai_record(
                command.markup,
                expected_handle=command.expected_handle,
                metadata_prefix=command.metadata_prefix,
            ),
        ),
    )


def _read_command() -> ParserCommand:
    stdin = cast("IO[bytes]", sys.stdin.buffer)
    frame = stdin.read(MAX_PARSER_COMMAND_BYTES + 1)
    if len(frame) > MAX_PARSER_COMMAND_BYTES:
        message = "parser command exceeded its byte limit"
        raise ParserIpcError(message)
    return parse_command_frame(frame)


def main() -> int:
    """Execute exactly one command and emit exactly one canonical result."""
    _ = os.umask(0o077)
    try:
        apply_resource_limits()
        command = _read_command()
    except (OSError, ParserIpcError, ValueError):
        return 2
    try:
        result: ParserResult = _execute(command)
    except AppError as error:
        result = _expected_failure(command, error)
    except Exception:  # noqa: BLE001 - isolate all parser-library failures.
        result = _unexpected_failure(command)
    try:
        frame = encode_parser_frame(result, maximum=MAX_PARSER_RESULT_BYTES)
        stdout = cast("IO[bytes]", sys.stdout.buffer)
        _ = stdout.write(frame)
        stdout.flush()
    except (BrokenPipeError, OSError, ParserIpcError):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
