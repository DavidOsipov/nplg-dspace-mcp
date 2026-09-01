# Copyright (c) 2026 David Osipov
"""Behavioral tests for the disposable parser worker entry point."""

from __future__ import annotations

import io
import os
import resource
import runpy
import sys
from pathlib import Path
from typing import NoReturn, Protocol, TextIO, cast
from uuid import UUID

import pytest

import nplg_mcp.parser_worker_main as worker_main
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parser_ipc import (
    MAX_PARSER_COMMAND_BYTES,
    ItemCommand,
    ItemPayload,
    MetadataFormatsCommand,
    MetadataFormatsPayload,
    OaiRecordCommand,
    OaiRecordPayload,
    ParserCommand,
    ParserErrorDetails,
    ParserFailure,
    ParserIpcError,
    ParserResult,
    ParserSuccess,
    SearchCommand,
    SearchPayload,
    SearchVersionCommand,
    SearchVersionPayload,
    encode_parser_frame,
    parse_result_frame,
)


class _ApplyResourceLimits(Protocol):
    def __call__(self) -> None: ...


class _ErrorDetails(Protocol):
    def __call__(self, error: AppError) -> ParserErrorDetails | None: ...


class _Execute(Protocol):
    def __call__(self, command: ParserCommand) -> ParserSuccess: ...


_WORKER_NAMESPACE = cast(
    "dict[str, object]",
    cast("object", worker_main.__dict__),
)
_APPLY_RESOURCE_LIMITS = cast(
    "_ApplyResourceLimits",
    _WORKER_NAMESPACE["apply_resource_limits"],
)
_ERROR_DETAILS = cast("_ErrorDetails", _WORKER_NAMESPACE["_error_details"])
_EXECUTE = cast("_Execute", _WORKER_NAMESPACE["_execute"])
_FIXTURES = Path(__file__).parents[1] / "fixtures"
_SEARCH_SOURCE = "https://dspace.nplg.gov.ge/simple-search?query=test"
_EMPTY_SEARCH_SOURCE = (
    "https://dspace.nplg.gov.ge/simple-search?"
    "query=nplgcontractprobe-20260901&rpp=1&start=0&envfv=ex20251112"
)
_ITEM_SOURCE = "https://dspace.nplg.gov.ge/handle/1234/560449?mode=full"
_EXPECTED_SEARCH_ITEMS = 2
_UPSTREAM_HTTP_STATUS = 502
_INVALID_COMMAND_EXIT = 2
_TRANSPORT_FAILURE_EXIT = 3


def _fixture(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


def _command_frame(command: ParserCommand) -> bytes:
    return encode_parser_frame(command, maximum=MAX_PARSER_COMMAND_BYTES)


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    frame: bytes,
) -> tuple[int, bytes, tuple[int, ...]]:
    stdin = io.TextIOWrapper(io.BytesIO(frame), encoding="utf-8")
    output = io.BytesIO()
    stdout = io.TextIOWrapper(output, encoding="utf-8")
    observed_umasks: list[int] = []

    def record_umask(mask: int) -> int:
        observed_umasks.append(mask)
        return 0o022

    monkeypatch.setattr(sys, "stdin", cast("TextIO", stdin))
    monkeypatch.setattr(sys, "stdout", cast("TextIO", stdout))
    monkeypatch.setattr(os, "umask", record_umask)
    monkeypatch.setitem(_WORKER_NAMESPACE, "apply_resource_limits", lambda: None)

    exit_code = worker_main.main()
    return exit_code, output.getvalue(), tuple(observed_umasks)


def test_worker_applies_exact_kernel_resource_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, tuple[int, int]]] = []

    def record_limit(limit: int, values: tuple[int, int]) -> None:
        calls.append((limit, values))

    monkeypatch.setattr(resource, "setrlimit", record_limit)
    nproc_limit = resource.RLIMIT_NPROC
    expected = [
        (resource.RLIMIT_CORE, (0, 0)),
        (resource.RLIMIT_CPU, (3, 3)),
        (resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024)),
        (resource.RLIMIT_FSIZE, (0, 0)),
        (resource.RLIMIT_NOFILE, (32, 32)),
        (nproc_limit, (1, 1)),
    ]

    _APPLY_RESOURCE_LIMITS()

    assert calls == expected

    calls.clear()
    monkeypatch.delattr(resource, "RLIMIT_NPROC")
    _APPLY_RESOURCE_LIMITS()

    assert calls == expected[:-1]


def test_worker_error_details_allow_only_strict_public_schema_fields() -> None:
    details = _ERROR_DETAILS(
        AppError(
            ErrorCode.RESTRICTED,
            "restricted",
            safe_details={
                "source_url": "https://dspace.nplg.gov.ge/handle/1234/1",
                "metadata_prefix": "dim",
            },
        )
    )

    assert details is not None
    assert details.as_public_mapping() == {
        "source_url": "https://dspace.nplg.gov.ge/handle/1234/1",
        "metadata_prefix": "dim",
    }
    assert _ERROR_DETAILS(AppError(ErrorCode.RESTRICTED, "restricted")) is None
    assert (
        _ERROR_DETAILS(
            AppError(
                ErrorCode.RESTRICTED,
                "restricted",
                safe_details={"private_canary": "must-not-cross"},
            )
        )
        is None
    )
    assert (
        _ERROR_DETAILS(
            AppError(
                ErrorCode.RESTRICTED,
                "restricted",
                safe_details={"source_url": 7},
            )
        )
        is None
    )


def test_worker_dispatches_search_to_the_real_bounded_parser() -> None:
    result = _EXECUTE(
        SearchCommand(
            request_id=UUID(int=1),
            operation="search",
            markup=_fixture("search_results.html"),
            source_url=_SEARCH_SOURCE,
            page_size=2,
        )
    )

    assert isinstance(result.payload, SearchPayload)
    assert result.payload.operation == "search"
    assert len(result.payload.value.items) == _EXPECTED_SEARCH_ITEMS


def test_worker_dispatches_current_empty_search_page_to_the_real_bounded_parser() -> (
    None
):
    """Catch treating NPLG's observed empty search response as malformed IPC data."""
    result = _EXECUTE(
        SearchCommand(
            request_id=UUID(int=2),
            operation="search",
            markup=_fixture("search_no_results.html"),
            source_url=_EMPTY_SEARCH_SOURCE,
            page_size=1,
        )
    )

    assert isinstance(result.payload, SearchPayload)
    assert result.payload.operation == "search"
    assert result.payload.value.items == ()
    assert result.payload.value.total == 0
    assert result.payload.value.next_offset is None
    assert result.payload.value.source_url == _EMPTY_SEARCH_SOURCE


def test_worker_dispatches_search_version_to_the_real_bounded_parser() -> None:
    result = _EXECUTE(
        SearchVersionCommand(
            request_id=UUID(int=10),
            operation="search_version",
            markup=_fixture("search_results.html"),
            source_url=_SEARCH_SOURCE,
        )
    )

    assert isinstance(result.payload, SearchVersionPayload)
    assert result.payload.operation == "search_version"
    assert result.payload.value == "ex20251112"


def test_worker_dispatches_item_to_the_real_bounded_parser() -> None:
    result = _EXECUTE(
        ItemCommand(
            request_id=UUID(int=2),
            operation="item",
            markup=_fixture("item_full.html"),
            expected_handle="1234/560449",
            source_url=_ITEM_SOURCE,
        )
    )

    assert isinstance(result.payload, ItemPayload)
    assert result.payload.operation == "item"
    assert result.payload.value.handle == "1234/560449"


def test_worker_dispatches_metadata_formats_to_the_real_bounded_parser() -> None:
    result = _EXECUTE(
        MetadataFormatsCommand(
            request_id=UUID(int=3),
            operation="metadata_formats",
            markup=_fixture("oai_formats.xml"),
        )
    )

    assert isinstance(result.payload, MetadataFormatsPayload)
    assert result.payload.operation == "metadata_formats"
    assert result.payload.value == ("oai_dc", "dim")


def test_worker_dispatches_oai_record_to_the_real_bounded_parser() -> None:
    result = _EXECUTE(
        OaiRecordCommand(
            request_id=UUID(int=4),
            operation="oai_record",
            markup=_fixture("oai_dim_record.xml"),
            expected_handle="1234/560975",
            metadata_prefix="dim",
        )
    )

    assert isinstance(result.payload, OaiRecordPayload)
    assert result.payload.operation == "oai_record"
    assert result.payload.value.handle == "1234/560975"


def test_main_reads_one_command_and_emits_one_canonical_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = MetadataFormatsCommand(
        request_id=UUID(int=5),
        operation="metadata_formats",
        markup=_fixture("oai_formats.xml"),
    )

    exit_code, frame, umasks = _run_main(monkeypatch, _command_frame(command))
    result = parse_result_frame(frame)

    assert exit_code == 0
    assert umasks == (0o077,)
    assert isinstance(result, ParserSuccess)
    assert result.request_id == command.request_id
    assert isinstance(result.payload, MetadataFormatsPayload)
    assert result.payload.value == ("oai_dc", "dim")


def test_main_serializes_expected_parser_failures_with_safe_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = OaiRecordCommand(
        request_id=UUID(int=6),
        operation="oai_record",
        markup=_fixture("oai_error.xml"),
        expected_handle="1234/560975",
        metadata_prefix="dim",
    )

    exit_code, frame, _umasks = _run_main(monkeypatch, _command_frame(command))
    result = parse_result_frame(frame)

    assert exit_code == 0
    assert isinstance(result, ParserFailure)
    assert result.request_id == command.request_id
    assert result.operation == "oai_record"
    assert result.payload.code is ErrorCode.UPSTREAM_FAILURE
    assert result.payload.details is not None
    assert result.payload.details.as_public_mapping() == {
        "oai_error": "cannotDisseminateFormat"
    }


def test_main_redacts_unexpected_parser_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = MetadataFormatsCommand(
        request_id=UUID(int=7),
        operation="metadata_formats",
        markup=_fixture("oai_formats.xml"),
    )

    def fail_unexpectedly(_command: ParserCommand) -> NoReturn:
        message = "parser-private-canary"
        raise RuntimeError(message)

    monkeypatch.setitem(_WORKER_NAMESPACE, "_execute", fail_unexpectedly)

    exit_code, frame, _umasks = _run_main(monkeypatch, _command_frame(command))
    result = parse_result_frame(frame)

    assert exit_code == 0
    assert isinstance(result, ParserFailure)
    assert result.payload.code is ErrorCode.UPSTREAM_FAILURE
    assert result.payload.http_status == _UPSTREAM_HTTP_STATUS
    assert "parser-private-canary" not in result.payload.message


def test_main_rejects_oversized_input_without_emitting_a_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exit_code, frame, umasks = _run_main(
        monkeypatch,
        b"x" * (MAX_PARSER_COMMAND_BYTES + 1),
    )

    assert exit_code == _INVALID_COMMAND_EXIT
    assert frame == b""
    assert umasks == (0o077,)


def test_main_returns_transport_failure_when_result_cannot_be_encoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = MetadataFormatsCommand(
        request_id=UUID(int=8),
        operation="metadata_formats",
        markup=_fixture("oai_formats.xml"),
    )
    command_frame = _command_frame(command)

    def reject_result(_result: ParserResult, *, maximum: int) -> NoReturn:
        del maximum
        message = "result exceeded its byte limit"
        raise ParserIpcError(message)

    monkeypatch.setitem(_WORKER_NAMESPACE, "encode_parser_frame", reject_result)

    exit_code, frame, _umasks = _run_main(monkeypatch, command_frame)

    assert exit_code == _TRANSPORT_FAILURE_EXIT
    assert frame == b""


def test_python_module_entry_point_executes_the_framed_worker_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = MetadataFormatsCommand(
        request_id=UUID(int=9),
        operation="metadata_formats",
        markup=_fixture("oai_formats.xml"),
    )
    stdin = io.TextIOWrapper(
        io.BytesIO(_command_frame(command)),
        encoding="utf-8",
    )
    output = io.BytesIO()
    stdout = io.TextIOWrapper(output, encoding="utf-8")

    def ignore_umask(_mask: int) -> int:
        return 0o022

    def ignore_resource_limit(
        _limit: int,
        _values: tuple[int, int],
    ) -> None:
        return None

    monkeypatch.setattr(sys, "stdin", cast("TextIO", stdin))
    monkeypatch.setattr(sys, "stdout", cast("TextIO", stdout))
    monkeypatch.setattr(os, "umask", ignore_umask)
    monkeypatch.setattr(resource, "setrlimit", ignore_resource_limit)
    module_name = "nplg_mcp.parser_worker_main"
    imported_module = sys.modules.pop(module_name)
    try:
        with pytest.raises(SystemExit) as raised:
            _ = cast(
                "object",
                runpy.run_module(module_name, run_name="__main__", alter_sys=True),
            )
    finally:
        sys.modules[module_name] = imported_module

    result = parse_result_frame(output.getvalue())
    assert raised.value.code == 0
    assert isinstance(result, ParserSuccess)
    assert result.request_id == command.request_id
