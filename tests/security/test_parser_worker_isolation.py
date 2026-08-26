# Copyright (c) 2026 David Osipov
"""Killability and resource-boundary tests for disposable metadata parsers."""

from __future__ import annotations

import asyncio
import os
import resource
import signal
import sys
import time
from contextlib import suppress
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

import httpx
import pytest

from nplg_mcp import parser_executor as parser_executor_module
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parser_executor import ParserWorkerError, SubprocessParserExecutor
from nplg_mcp.repository import NplgRepository

if TYPE_CHECKING:
    from asyncio.subprocess import Process

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "parser_worker_hang.py"
_SUCCESS_WITH_DESCENDANT_FIXTURE = (
    _FIXTURE.parent / "parser_worker_success_with_descendant.py"
)
_ADVERSARIAL_RESULT_FIXTURE = _FIXTURE.parent / "parser_worker_adversarial_result.py"
_EXPECTED_SEARCH_ITEMS = 2
_PROCESS_STATE_INDEX = 2


class _CreateSubprocess(Protocol):
    async def __call__(
        self,
        *args: str | bytes,
        **kwargs: object,
    ) -> Process: ...


def _process_is_gone(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return True
    status_path = Path(f"/proc/{process_id}/stat")
    try:
        fields = status_path.read_text(encoding="ascii").split()
    except (FileNotFoundError, ProcessLookupError):
        return True
    return len(fields) > _PROCESS_STATE_INDEX and fields[_PROCESS_STATE_INDEX] == "Z"


async def _wait_for_identity(path: Path) -> int:
    expires_at = asyncio.get_running_loop().time() + 2.0
    while asyncio.get_running_loop().time() < expires_at:
        try:
            payload = await asyncio.to_thread(path.read_text, encoding="ascii")
            return int(payload.strip())
        except (FileNotFoundError, ValueError):
            await asyncio.sleep(0.005)
    message = "parser worker did not publish its descendant identity"
    raise TimeoutError(message)


def _wait_for_process_gone(process_id: int) -> bool:
    expires_at = time.monotonic() + 2.0
    while time.monotonic() < expires_at:
        if _process_is_gone(process_id):
            return True
        time.sleep(0.005)
    return _process_is_gone(process_id)


@pytest.mark.asyncio
async def test_timed_out_parser_kills_its_entire_process_group_and_recovers_capacity(
    tmp_path: Path,
) -> None:
    identity_path = tmp_path / "parser-processes.txt"
    executor = SubprocessParserExecutor(
        worker_argv=(sys.executable, str(_FIXTURE), str(identity_path)),
    )
    deadline = asyncio.get_running_loop().time() + 0.25

    parse = asyncio.create_task(
        executor.parse_metadata_formats("<OAI-PMH/>", deadline=deadline)
    )
    descendant_id = await _wait_for_identity(identity_path)

    with pytest.raises(TimeoutError):
        _ = await parse

    assert executor.active == 0
    assert await asyncio.to_thread(_wait_for_process_gone, descendant_id)


@pytest.mark.asyncio
async def test_real_disposable_parser_returns_one_strict_validated_result() -> None:
    executor = SubprocessParserExecutor()
    markup = (_FIXTURE.parent / "oai_formats.xml").read_text(encoding="utf-8")

    formats = await executor.parse_metadata_formats(
        markup,
        deadline=asyncio.get_running_loop().time() + 5.0,
    )

    assert formats == ("oai_dc", "dim")
    assert executor.active == 0


@pytest.mark.asyncio
async def test_successful_parser_cleans_descendants_before_returning(
    tmp_path: Path,
) -> None:
    identity_path = tmp_path / "successful-parser-descendant.txt"
    executor = SubprocessParserExecutor(
        worker_argv=(
            sys.executable,
            str(_SUCCESS_WITH_DESCENDANT_FIXTURE),
            str(identity_path),
        ),
    )

    formats = await executor.parse_metadata_formats(
        "<OAI-PMH/>",
        deadline=asyncio.get_running_loop().time() + 5.0,
    )
    descendant_id = int(formats[0])

    assert descendant_id == await _wait_for_identity(identity_path)
    assert executor.active == 0
    assert await asyncio.to_thread(_wait_for_process_gone, descendant_id)


@pytest.mark.asyncio
async def test_parser_start_cancellation_retains_process_ownership_until_group_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_path = tmp_path / "start-cancel-parser-descendant.txt"
    real_create = cast("_CreateSubprocess", asyncio.create_subprocess_exec)
    spawned: asyncio.Future[Process] = asyncio.get_running_loop().create_future()
    release_spawn = asyncio.Event()

    async def hold_spawn_return(
        *args: str | bytes,
        **kwargs: object,
    ) -> Process:
        process = await real_create(*args, **kwargs)
        spawned.set_result(process)
        _ = await release_spawn.wait()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", hold_spawn_return)
    executor = SubprocessParserExecutor(
        worker_argv=(
            sys.executable,
            str(_SUCCESS_WITH_DESCENDANT_FIXTURE),
            str(identity_path),
        ),
    )
    parse = asyncio.create_task(
        executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 5.0,
        )
    )
    leader = await asyncio.wait_for(spawned, timeout=1.0)
    descendant_id = await _wait_for_identity(identity_path)

    _ = parse.cancel()
    await asyncio.sleep(0)
    release_spawn.set()
    try:
        with pytest.raises(asyncio.CancelledError):
            _ = await parse

        assert executor.active == 0
        assert await asyncio.to_thread(_wait_for_process_gone, descendant_id)
        assert _process_is_gone(leader.pid)
    finally:
        if not _process_is_gone(descendant_id):
            with suppress(ProcessLookupError):
                os.killpg(leader.pid, signal.SIGKILL)
        if leader.returncode is None:
            _ = await leader.wait()


@pytest.mark.asyncio
async def test_repository_default_never_parses_untrusted_markup_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    markup = (_FIXTURE.parent / "search_results.html").read_text(encoding="utf-8")

    def reject_in_process(*_args: object, **_kwargs: object) -> object:
        message = "untrusted parser executed in the ASGI process"
        raise AssertionError(message)

    monkeypatch.setattr(
        parser_executor_module,
        "parse_search_results",
        reject_in_process,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=markup,
            headers={"content-type": "text/html; charset=utf-8"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = NplgRepository(
            client=client,
            validate_dns=False,
            total_timeout_seconds=5.0,
        )
        page = await repository.search("ივერია", page_size=2)

    assert len(page.items) == _EXPECTED_SEARCH_ITEMS


@pytest.mark.asyncio
async def test_cancelled_parser_kills_descendants_before_releasing_capacity(
    tmp_path: Path,
) -> None:
    identity_path = tmp_path / "cancelled-parser-processes.txt"
    executor = SubprocessParserExecutor(
        worker_argv=(sys.executable, str(_FIXTURE), str(identity_path)),
    )
    parse = asyncio.create_task(
        executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 5.0,
        )
    )
    descendant_id = await _wait_for_identity(identity_path)

    _ = parse.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await parse

    assert executor.active == 0
    assert await asyncio.to_thread(_wait_for_process_gone, descendant_id)


@pytest.mark.asyncio
async def test_parser_stdout_overflow_is_bounded_and_process_is_reaped() -> None:
    executor = SubprocessParserExecutor(
        worker_argv=(
            sys.executable,
            str(_FIXTURE.parent / "parser_worker_stdout_overflow.py"),
        ),
    )

    with pytest.raises(ParserWorkerError, match="byte limit"):
        _ = await executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 5.0,
        )

    assert executor.active == 0


@pytest.mark.parametrize(
    "mode",
    ["request-id", "success-operation", "failure-operation"],
)
@pytest.mark.asyncio
async def test_parser_rejects_mismatched_identity_or_operation(mode: str) -> None:
    executor = SubprocessParserExecutor(
        worker_argv=(sys.executable, str(_ADVERSARIAL_RESULT_FIXTURE), mode),
    )

    with pytest.raises(ParserWorkerError, match="did not match"):
        _ = await executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 5.0,
        )

    assert executor.active == 0


@pytest.mark.parametrize("mode", ["noncanonical", "malformed"])
@pytest.mark.asyncio
async def test_parser_rejects_invalid_result_encoding(mode: str) -> None:
    executor = SubprocessParserExecutor(
        worker_argv=(sys.executable, str(_ADVERSARIAL_RESULT_FIXTURE), mode),
    )

    with pytest.raises(ParserWorkerError, match="invalid result"):
        _ = await executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 5.0,
        )

    assert executor.active == 0


@pytest.mark.asyncio
async def test_parser_reconstructs_only_schema_owned_public_failure_details() -> None:
    executor = SubprocessParserExecutor(
        worker_argv=(
            sys.executable,
            str(_ADVERSARIAL_RESULT_FIXTURE),
            "expected-failure",
        ),
    )

    with pytest.raises(AppError) as captured:
        _ = await executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 5.0,
        )

    assert captured.value.code is ErrorCode.RESTRICTED
    assert captured.value.http_status == HTTPStatus.FORBIDDEN
    assert captured.value.message == "The parser fixture denied this record."
    assert captured.value.safe_details == {"metadata_prefix": "dim"}
    assert captured.value.internal_details is None
    assert executor.active == 0


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("stderr", "without one valid result"),
        ("stderr-overflow", "byte limit"),
    ],
)
@pytest.mark.asyncio
async def test_parser_bounds_and_redacts_worker_stderr(
    mode: str,
    message: str,
) -> None:
    executor = SubprocessParserExecutor(
        worker_argv=(sys.executable, str(_ADVERSARIAL_RESULT_FIXTURE), mode),
    )

    with pytest.raises(ParserWorkerError, match=message) as captured:
        _ = await executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 5.0,
        )

    assert "parser-private-stderr-canary" not in repr(captured.value)
    assert executor.active == 0


@pytest.mark.asyncio
async def test_disposable_parser_process_has_exact_kernel_resource_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_create = cast("_CreateSubprocess", asyncio.create_subprocess_exec)
    process_id: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def capture_process(
        *args: str | bytes,
        **kwargs: object,
    ) -> Process:
        process = await real_create(*args, **kwargs)
        process_id.set_result(process.pid)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_process)
    executor = SubprocessParserExecutor(
        worker_argv=(
            sys.executable,
            str(_FIXTURE.parent / "parser_worker_limited_hang.py"),
        ),
    )
    parse = asyncio.create_task(
        executor.parse_metadata_formats(
            "<OAI-PMH/>",
            deadline=asyncio.get_running_loop().time() + 5.0,
        )
    )
    parser_process_id = await asyncio.wait_for(process_id, timeout=1.0)

    expected = {
        resource.RLIMIT_CORE: (0, 0),
        resource.RLIMIT_CPU: (3, 3),
        resource.RLIMIT_AS: (512 * 1024 * 1024, 512 * 1024 * 1024),
        resource.RLIMIT_FSIZE: (0, 0),
        resource.RLIMIT_NOFILE: (32, 32),
    }
    if hasattr(resource, "RLIMIT_NPROC"):
        expected[resource.RLIMIT_NPROC] = (1, 1)
    expires_at = asyncio.get_running_loop().time() + 2.0
    observed: dict[int, tuple[int, int]] = {}
    while asyncio.get_running_loop().time() < expires_at:
        observed = {
            limit: resource.prlimit(parser_process_id, limit) for limit in expected
        }
        if observed == expected:
            break
        await asyncio.sleep(0.01)

    _ = parse.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await parse

    assert observed == expected
    assert executor.active == 0
    assert _process_is_gone(parser_process_id)
