# Copyright (c) 2026 David Osipov
"""Typed inline and disposable-process executors for repository parsers."""

from __future__ import annotations

import asyncio
import math
import os
import signal
import sys
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from uuid import uuid4

from pydantic import ValidationError

from .admission import AdmissionGate
from .bounded_work import PARSER_WORK, BlockingWorkCapacityError
from .errors import AppError
from .parser_ipc import (
    MAX_PARSER_COMMAND_BYTES,
    MAX_PARSER_RESULT_BYTES,
    ItemCommand,
    ItemPayload,
    MetadataFormatsCommand,
    MetadataFormatsPayload,
    MetadataPrefix,
    OaiRecordCommand,
    OaiRecordPayload,
    ParserFailure,
    ParserIpcError,
    ParserPayload,
    SearchCommand,
    SearchPayload,
    encode_parser_frame,
    parse_result_frame,
)
from .parsers import (
    DocumentRecord,
    SearchPage,
    parse_item_page,
    parse_metadata_formats,
    parse_oai_record,
    parse_search_results,
)

if TYPE_CHECKING:
    from asyncio.subprocess import Process

_MAX_STDERR_BYTES = 16_384
_STREAM_CHUNK_BYTES = 65_536
_TERMINATION_GRACE_SECONDS = 0.25
_MAX_WORKER_ARGUMENT_CODE_POINTS = 4_096

type StrictParserCommand = (
    SearchCommand | ItemCommand | MetadataFormatsCommand | OaiRecordCommand
)


class ParserWorkerError(RuntimeError):
    """Report one non-public parser-process or transport failure."""


@runtime_checkable
class ParserExecutor(Protocol):
    """Typed execution seam for all repository parser operations."""

    async def parse_search(
        self,
        markup: str,
        *,
        source_url: str,
        page_size: int,
        deadline: float,
    ) -> SearchPage:
        """Parse one repository search response."""
        ...

    async def parse_item(
        self,
        markup: str,
        *,
        expected_handle: str,
        source_url: str,
        deadline: float,
    ) -> DocumentRecord:
        """Parse one repository item response."""
        ...

    async def parse_metadata_formats(
        self,
        markup: str,
        *,
        deadline: float,
    ) -> tuple[str, ...]:
        """Parse one OAI-PMH metadata-format response."""
        ...

    async def parse_oai_record(
        self,
        markup: str,
        *,
        expected_handle: str,
        metadata_prefix: MetadataPrefix,
        deadline: float,
    ) -> DocumentRecord:
        """Parse one OAI-PMH record response."""
        ...


class InlineParserExecutor:
    """Run trusted test fixtures in the legacy bounded thread runner."""

    @property
    def active(self) -> int:
        """Return the number of currently active inline parses."""
        return PARSER_WORK.active

    async def parse_search(
        self,
        markup: str,
        *,
        source_url: str,
        page_size: int,
        deadline: float,
    ) -> SearchPage:
        """Parse trusted search markup without a process boundary."""
        async with asyncio.timeout_at(deadline):
            return await PARSER_WORK.run(
                lambda: parse_search_results(
                    markup,
                    source_url=source_url,
                    page_size=page_size,
                )
            )

    async def parse_item(
        self,
        markup: str,
        *,
        expected_handle: str,
        source_url: str,
        deadline: float,
    ) -> DocumentRecord:
        """Parse trusted item markup without a process boundary."""
        async with asyncio.timeout_at(deadline):
            return await PARSER_WORK.run(
                lambda: parse_item_page(
                    markup,
                    expected_handle=expected_handle,
                    source_url=source_url,
                )
            )

    async def parse_metadata_formats(
        self,
        markup: str,
        *,
        deadline: float,
    ) -> tuple[str, ...]:
        """Parse trusted format markup without a process boundary."""
        async with asyncio.timeout_at(deadline):
            return await PARSER_WORK.run(lambda: parse_metadata_formats(markup))

    async def parse_oai_record(
        self,
        markup: str,
        *,
        expected_handle: str,
        metadata_prefix: MetadataPrefix,
        deadline: float,
    ) -> DocumentRecord:
        """Parse trusted OAI markup without a process boundary."""
        async with asyncio.timeout_at(deadline):
            return await PARSER_WORK.run(
                lambda: parse_oai_record(
                    markup,
                    expected_handle=expected_handle,
                    metadata_prefix=metadata_prefix,
                )
            )


def _validate_worker_argv(worker_argv: tuple[str, ...]) -> tuple[str, ...]:
    if type(worker_argv) is not tuple or not worker_argv:
        message = "parser worker argv must be one non-empty tuple"
        raise TypeError(message)
    if any(
        type(argument) is not str
        or not argument
        or len(argument) > _MAX_WORKER_ARGUMENT_CODE_POINTS
        or "\x00" in argument
        for argument in worker_argv
    ):
        message = "parser worker argv contains an invalid argument"
        raise ValueError(message)
    if not Path(worker_argv[0]).is_absolute():
        message = "parser worker executable must be absolute"
        raise ValueError(message)
    return worker_argv


def _worker_environment() -> dict[str, str]:
    """Return a closed environment with no inherited application secrets."""
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    }


async def _spawn_owned_process(worker_argv: tuple[str, ...]) -> Process:
    """Retain ownership when cancellation races process construction."""

    async def create_process() -> Process:
        return await asyncio.create_subprocess_exec(
            *worker_argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/",
            env=_worker_environment(),
            shell=False,
            start_new_session=True,
            close_fds=True,
        )

    spawn = asyncio.create_task(create_process())
    try:
        return await asyncio.shield(spawn)
    except OSError as exc:
        message = "parser worker could not be started"
        raise ParserWorkerError(message) from exc
    except asyncio.CancelledError as cancellation:
        process: Process | None = None
        while not spawn.done():
            try:
                process = await asyncio.shield(spawn)
            except asyncio.CancelledError:
                continue
            except BaseException as exc:
                raise cancellation from exc
        if spawn.cancelled():
            raise
        if process is None:
            try:
                process = spawn.result()
            except BaseException as exc:
                raise cancellation from exc
        with suppress(asyncio.CancelledError):
            await _wait_for_cleanup(process)
        raise


async def _read_bounded(
    stream: asyncio.StreamReader,
    *,
    maximum: int,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = maximum - total
        chunk = await stream.read(min(_STREAM_CHUNK_BYTES, remaining + 1))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > maximum:
            message = "parser worker output exceeded its byte limit"
            raise ParserWorkerError(message)
        chunks.append(chunk)


async def _terminate_process_group(process: Process) -> None:
    """Terminate a disposable parser group and always reap its leader."""
    process_group = process.pid
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGTERM)
    if process.returncode is None:
        try:
            async with asyncio.timeout(_TERMINATION_GRACE_SECONDS):
                _ = await process.wait()
        except TimeoutError:
            pass
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGKILL)
    if process.returncode is None:
        _ = await process.wait()


async def _wait_for_cleanup(process: Process) -> None:
    """Finish process cleanup even if cancellation is delivered repeatedly."""
    cleanup = asyncio.create_task(_terminate_process_group(process))
    cancellation: asyncio.CancelledError | None = None
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as exc:
            cancellation = exc
    _ = cleanup.result()
    if cancellation is not None:
        raise cancellation


def _validated_result_payload(
    frame: bytes,
    *,
    command: StrictParserCommand,
) -> ParserPayload:
    try:
        result = parse_result_frame(frame)
    except ParserIpcError as exc:
        message = "parser worker returned an invalid result"
        raise ParserWorkerError(message) from exc
    if result.request_id != command.request_id:
        message = "parser worker response identity did not match the command"
        raise ParserWorkerError(message)
    if isinstance(result, ParserFailure):
        if result.operation != command.operation:
            message = "parser worker response operation did not match the command"
            raise ParserWorkerError(message)
        details = (
            result.payload.details.as_public_mapping()
            if result.payload.details is not None
            else None
        )
        raise AppError(
            result.payload.code,
            result.payload.message,
            http_status=result.payload.http_status,
            safe_details=details,
        )
    if result.payload.operation != command.operation:
        message = "parser worker response operation did not match the command"
        raise ParserWorkerError(message)
    return result.payload


class SubprocessParserExecutor:
    """Execute every untrusted parse in a fresh, killable process group."""

    def __init__(
        self,
        *,
        worker_argv: tuple[str, ...] | None = None,
        capacity: int = 1,
    ) -> None:
        """Create one fail-fast process admission gate and fixed worker command."""
        super().__init__()
        self._worker_argv = _validate_worker_argv(
            worker_argv
            if worker_argv is not None
            else (sys.executable, "-m", "nplg_mcp.parser_worker_main")
        )
        self._gate = AdmissionGate(capacity)

    @property
    def active(self) -> int:
        """Return parser jobs whose process cleanup is not complete."""
        return self._gate.active

    async def _exchange(
        self,
        process: Process,
        command: StrictParserCommand,
    ) -> ParserPayload:
        stdin = process.stdin
        stdout = process.stdout
        stderr = process.stderr
        if stdin is None or stdout is None or stderr is None:
            message = "parser worker pipes were not created"
            raise ParserWorkerError(message)
        try:
            frame = encode_parser_frame(command, maximum=MAX_PARSER_COMMAND_BYTES)
        except ParserIpcError as exc:
            message = "parser command could not be encoded within its boundary"
            raise ParserWorkerError(message) from exc
        stdout_task = asyncio.create_task(
            _read_bounded(stdout, maximum=MAX_PARSER_RESULT_BYTES)
        )
        stderr_task = asyncio.create_task(
            _read_bounded(stderr, maximum=_MAX_STDERR_BYTES)
        )
        wait_task = asyncio.create_task(process.wait())
        tasks = (stdout_task, stderr_task, wait_task)
        try:
            stdin.write(frame)
            await stdin.drain()
            stdin.close()
            await stdin.wait_closed()
            stdout_bytes, stderr_bytes, return_code = await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    _ = task.cancel()
            _done, _pending = await asyncio.wait(tasks)
            for task in tasks:
                if not task.cancelled():
                    _ = task.exception()
        if return_code != 0 or stderr_bytes:
            message = "parser worker exited without one valid result"
            raise ParserWorkerError(message)
        return _validated_result_payload(stdout_bytes, command=command)

    async def _execute(
        self,
        command: StrictParserCommand,
        *,
        deadline: float,
    ) -> ParserPayload:
        loop = asyncio.get_running_loop()
        if type(deadline) is not float or not math.isfinite(deadline):
            message = "parser deadline must be one finite float"
            raise TypeError(message)
        if deadline <= loop.time():
            raise TimeoutError
        if not self._gate.try_acquire():
            message = "bounded parser-process capacity is exhausted"
            raise BlockingWorkCapacityError(message)
        try:
            async with asyncio.timeout_at(deadline):
                process = await _spawn_owned_process(self._worker_argv)
                try:
                    return await self._exchange(process, command)
                finally:
                    await _wait_for_cleanup(process)
        finally:
            self._gate.release()

    async def parse_search(
        self,
        markup: str,
        *,
        source_url: str,
        page_size: int,
        deadline: float,
    ) -> SearchPage:
        """Parse search HTML in one disposable process."""
        try:
            command = SearchCommand(
                request_id=uuid4(),
                operation="search",
                markup=markup,
                source_url=source_url,
                page_size=page_size,
            )
        except ValidationError as exc:
            message = "parser command failed strict validation"
            raise ParserWorkerError(message) from exc
        payload = await self._execute(command, deadline=deadline)
        if not isinstance(payload, SearchPayload):
            message = "parser worker returned the wrong search payload"
            raise ParserWorkerError(message)
        return payload.value

    async def parse_item(
        self,
        markup: str,
        *,
        expected_handle: str,
        source_url: str,
        deadline: float,
    ) -> DocumentRecord:
        """Parse item HTML in one disposable process."""
        try:
            command = ItemCommand(
                request_id=uuid4(),
                operation="item",
                markup=markup,
                expected_handle=expected_handle,
                source_url=source_url,
            )
        except ValidationError as exc:
            message = "parser command failed strict validation"
            raise ParserWorkerError(message) from exc
        payload = await self._execute(command, deadline=deadline)
        if not isinstance(payload, ItemPayload):
            message = "parser worker returned the wrong item payload"
            raise ParserWorkerError(message)
        return payload.value

    async def parse_metadata_formats(
        self,
        markup: str,
        *,
        deadline: float,
    ) -> tuple[str, ...]:
        """Parse OAI-PMH format discovery in one disposable process."""
        try:
            command = MetadataFormatsCommand(
                request_id=uuid4(),
                operation="metadata_formats",
                markup=markup,
            )
        except ValidationError as exc:
            message = "parser command failed strict validation"
            raise ParserWorkerError(message) from exc
        payload = await self._execute(command, deadline=deadline)
        if not isinstance(payload, MetadataFormatsPayload):
            message = "parser worker returned the wrong metadata-formats payload"
            raise ParserWorkerError(message)
        return payload.value

    async def parse_oai_record(
        self,
        markup: str,
        *,
        expected_handle: str,
        metadata_prefix: MetadataPrefix,
        deadline: float,
    ) -> DocumentRecord:
        """Parse one OAI-PMH record in one disposable process."""
        try:
            command = OaiRecordCommand(
                request_id=uuid4(),
                operation="oai_record",
                markup=markup,
                expected_handle=expected_handle,
                metadata_prefix=metadata_prefix,
            )
        except ValidationError as exc:
            message = "parser command failed strict validation"
            raise ParserWorkerError(message) from exc
        payload = await self._execute(command, deadline=deadline)
        if not isinstance(payload, OaiRecordPayload):
            message = "parser worker returned the wrong OAI-record payload"
            raise ParserWorkerError(message)
        return payload.value
