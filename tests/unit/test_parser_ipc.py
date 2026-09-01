# Copyright (c) 2026 David Osipov
"""Strict parser IPC and pre-spawn validation tests."""

from __future__ import annotations

import asyncio
from typing import NoReturn, cast
from uuid import UUID

import pytest
from pydantic import ValidationError

from nplg_mcp.parser_executor import (
    InlineParserExecutor,
    ParserWorkerError,
    SubprocessParserExecutor,
)
from nplg_mcp.parser_ipc import (
    MAX_PARSER_COMMAND_BYTES,
    MAX_PARSER_RESULT_BYTES,
    MetadataFormatsCommand,
    MetadataFormatsPayload,
    ParserIpcError,
    ParserSuccess,
    SearchCommand,
    SearchVersionCommand,
    SearchVersionPayload,
    encode_parser_frame,
    parse_command_frame,
    parse_result_frame,
)

_REQUEST_ID = UUID("12345678-1234-5678-9234-567812345678")


def test_empty_parser_worker_command_is_rejected_instead_of_selecting_default() -> None:
    with pytest.raises(TypeError, match="non-empty tuple"):
        _ = SubprocessParserExecutor(worker_argv=())


@pytest.mark.asyncio
async def test_oversized_parser_command_fails_closed_before_process_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def reject_spawn(*_args: object, **_kwargs: object) -> NoReturn:
        message = "oversized parser command reached process creation"
        raise AssertionError(message)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", reject_spawn)
    executor = SubprocessParserExecutor()

    with pytest.raises(ParserWorkerError, match="command"):
        _ = await executor.parse_metadata_formats(
            "x" * (MAX_PARSER_COMMAND_BYTES + 1),
            deadline=asyncio.get_running_loop().time() + 1.0,
        )

    assert executor.active == 0


@pytest.mark.asyncio
async def test_parser_spawn_failure_is_sanitized_and_inherits_no_secret_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel_value = "parser-environment-sentinel"
    captured_environment: dict[str, str] = {}

    async def fail_spawn(*_args: object, **kwargs: object) -> NoReturn:
        environment = kwargs.get("env")
        assert type(environment) is dict
        raw_environment = cast("dict[object, object]", environment)
        assert all(
            type(key) is str and type(value) is str
            for key, value in raw_environment.items()
        )
        captured_environment.update(cast("dict[str, str]", raw_environment))
        message = "private spawn failure details"
        raise OSError(message)

    monkeypatch.setenv("NPLG_TEST_PARSER_SECRET", sentinel_value)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_spawn)
    executor = SubprocessParserExecutor()

    with pytest.raises(ParserWorkerError, match="could not be started") as captured:
        _ = await executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 1.0,
        )

    assert sentinel_value not in repr(captured.value)
    assert sentinel_value not in captured_environment.values()
    assert executor.active == 0


def test_parser_command_frame_requires_strict_canonical_duplicate_free_json() -> None:
    command = MetadataFormatsCommand(
        request_id=_REQUEST_ID,
        operation="metadata_formats",
        markup="<OAI-PMH/>",
    )
    frame = encode_parser_frame(command, maximum=MAX_PARSER_COMMAND_BYTES)

    assert parse_command_frame(frame) == command

    duplicate = frame.replace(
        b'{"request_id":',
        b'{"operation":"metadata_formats","request_id":',
        1,
    )
    extra = frame[:-1] + b',"extra":true}'
    for rejected in (duplicate, extra, b" " + frame, frame + b"\n"):
        with pytest.raises(ParserIpcError):
            _ = parse_command_frame(rejected)


def test_parser_result_frame_requires_exact_closed_payload_schema() -> None:
    result = ParserSuccess(
        request_id=_REQUEST_ID,
        status="ok",
        payload=MetadataFormatsPayload(
            operation="metadata_formats",
            value=("dim", "oai_dc"),
        ),
    )
    frame = encode_parser_frame(result, maximum=MAX_PARSER_RESULT_BYTES)

    assert parse_result_frame(frame) == result

    extra = frame.replace(
        b'"value":["dim","oai_dc"]',
        b'"value":["dim","oai_dc"],"extra":"forged"',
        1,
    )
    duplicate_status = frame.replace(
        b'"status":"ok",',
        b'"status":"ok","status":"error",',
        1,
    )
    for rejected in (
        extra,
        duplicate_status,
        b"{}",
        b"",
        b"x" * (MAX_PARSER_RESULT_BYTES + 1),
    ):
        with pytest.raises(ParserIpcError):
            _ = parse_result_frame(rejected)


def test_search_version_ipc_round_trip_is_strict_and_discriminated() -> None:
    command = SearchVersionCommand(
        request_id=_REQUEST_ID,
        operation="search_version",
        markup='<html><head><meta name="sourcefv" content="ex20251112"></head></html>',
        source_url="https://dspace.nplg.gov.ge/simple-search",
    )
    command_frame = encode_parser_frame(command, maximum=MAX_PARSER_COMMAND_BYTES)
    result = ParserSuccess(
        request_id=_REQUEST_ID,
        status="ok",
        payload=SearchVersionPayload(
            operation="search_version",
            value="ex20251112",
        ),
    )
    result_frame = encode_parser_frame(result, maximum=MAX_PARSER_RESULT_BYTES)

    assert parse_command_frame(command_frame) == command
    assert parse_result_frame(result_frame) == result


@pytest.mark.asyncio
async def test_inline_parser_executor_parses_search_version_within_deadline() -> None:
    executor = InlineParserExecutor()

    marker = await executor.parse_search_version(
        '<html><head><meta name="sourcefv" content="ex20251112"></head></html>',
        source_url="https://dspace.nplg.gov.ge/simple-search",
        deadline=asyncio.get_running_loop().time() + 1.0,
    )

    assert marker == "ex20251112"


@pytest.mark.asyncio
async def test_search_version_executor_rejects_invalid_command_before_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def reject_spawn(*_args: object, **_kwargs: object) -> NoReturn:
        message = "invalid search-version command reached process creation"
        raise AssertionError(message)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", reject_spawn)
    executor = SubprocessParserExecutor()

    with pytest.raises(ParserWorkerError, match="strict validation"):
        _ = await executor.parse_search_version(
            "<html/>",
            source_url="x" * 2_049,
            deadline=asyncio.get_running_loop().time() + 1.0,
        )

    assert executor.active == 0


@pytest.mark.asyncio
async def test_search_version_executor_rejects_wrong_payload_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def wrong_payload(
        *_args: object,
        **_kwargs: object,
    ) -> MetadataFormatsPayload:
        return MetadataFormatsPayload(
            operation="metadata_formats",
            value=("dim",),
        )

    monkeypatch.setattr(SubprocessParserExecutor, "_execute", wrong_payload)
    executor = SubprocessParserExecutor()

    with pytest.raises(ParserWorkerError, match="wrong search-version payload"):
        _ = await executor.parse_search_version(
            "<html/>",
            source_url="https://dspace.nplg.gov.ge/simple-search",
            deadline=asyncio.get_running_loop().time() + 1.0,
        )

    assert executor.active == 0


@pytest.mark.parametrize("value", ["EX20251112", "ex2025111", "ex202511120"])
def test_search_version_payload_rejects_unobserved_shapes(value: str) -> None:
    payload: dict[str, object] = {"operation": "search_version", "value": value}
    with pytest.raises(ValidationError):
        _ = SearchVersionPayload.model_validate(
            payload,
            strict=True,
        )


@pytest.mark.parametrize("page_size", [True, 1.0, "1", 0, 51])
def test_parser_command_models_reject_coercion_and_out_of_policy_values(
    page_size: object,
) -> None:
    payload: dict[str, object] = {
        "request_id": _REQUEST_ID,
        "operation": "search",
        "markup": "<html/>",
        "source_url": "https://dspace.nplg.gov.ge/simple-search",
        "page_size": page_size,
    }
    with pytest.raises(ValidationError):
        _ = SearchCommand.model_validate(payload, strict=True)
