# Copyright (c) 2026 David Osipov
"""Parent-side disposable PDF worker client."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import shutil
import signal
import stat
import sys
import tempfile
import time
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

from PIL import Image, UnidentifiedImageError

from .bounded_work import (
    STORAGE_WORK,
    BlockingWorkCapacityError,
    BoundedThreadRunner,
)
from .errors import AppError
from .pdf_executor import (
    MonotonicDeadline,
    PdfCircuitBreaker,
    PdfWorkerError,
    PdfWorkerOperationalError,
    PdfWorkerPolicy,
)
from .pdf_identity import render_identifier
from .pdf_ipc import (
    MAX_COMMAND_FRAME_BYTES,
    MAX_RESULT_FRAME_BYTES,
    InspectCommand,
    InspectPayload,
    ManifestCommand,
    ManifestPayload,
    PdfCommand,
    PdfFailure,
    PdfResult,
    PdfSuccess,
    RenderPagesCommand,
    RenderPagesOutput,
    RenderPagesPayload,
    RenderTilesCommand,
    RenderTilesOutput,
    RenderTilesPayload,
    encode_frame,
    parse_result_frame,
)

if TYPE_CHECKING:
    from asyncio import StreamReader, StreamWriter
    from asyncio.subprocess import Process
    from collections.abc import Callable

    from .storage import ContentAddressedStore

_FRAME_PREFIX_BYTES = 4
_WORKER_JOB_DIRECTORY = ".pdf-worker-jobs"
_StorageT = TypeVar("_StorageT")


class SubprocessPdfExecutor:
    """Run each PDF operation in a new process group and private directory."""

    def __init__(
        self,
        *,
        store: ContentAddressedStore,
        policy: PdfWorkerPolicy | None = None,
        worker_argv: tuple[str, ...] | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind the authoritative parent store and fixed worker command."""
        super().__init__()
        actual_policy = policy or PdfWorkerPolicy()
        argv = worker_argv or (
            sys.executable,
            "-m",
            "nplg_mcp.pdf_worker_main",
        )
        executable = Path(argv[0])
        if (
            not executable.is_absolute()
            or not executable.is_file()
            or not os.access(executable, os.X_OK)
            or any(not value or "\x00" in value for value in argv)
        ):
            message = "PDF worker argv is invalid"
            raise ValueError(message)
        self._store = store
        self._limits = actual_policy.resources
        self._processor_settings = actual_policy.processor
        self._circuit = PdfCircuitBreaker(
            policy=actual_policy.circuit,
            clock=monotonic_clock,
        )
        self._worker_argv = argv
        self._permit = asyncio.Semaphore(actual_policy.capacity)
        # Cleanup cannot share fail-fast publication capacity: a rejected staging
        # operation may itself need to remove a job directory. The executor is
        # serialized, so this reserved worker has exactly one cleanup producer.
        self._cleanup_work = BoundedThreadRunner(
            capacity=1,
            thread_name_prefix="nplg-pdf-cleanup",
        )

    def ensure_ready(self) -> None:
        """Fail while transport failures require a successful recovery probe."""
        self._circuit.ensure_ready()

    @staticmethod
    async def _run_storage(operation: Callable[[], _StorageT]) -> _StorageT:
        try:
            return await STORAGE_WORK.run_to_completion(operation)
        except BlockingWorkCapacityError as exc:
            message = "PDF storage publication capacity is exhausted"
            raise PdfWorkerOperationalError(message) from exc

    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        """Stage inputs, run one child, validate its result, and clean up."""
        acquired = False
        try:
            try:
                async with asyncio.timeout(deadline.remaining()):
                    _ = await self._permit.acquire()
            except TimeoutError as exc:
                message = "PDF worker exceeded its deadline while awaiting capacity"
                raise PdfWorkerOperationalError(message) from exc
            acquired = True
            self._circuit.before_attempt()
            try:
                result = await self._execute_with_permit(command, deadline=deadline)
            except PdfWorkerOperationalError:
                self._circuit.record_operational_failure()
                raise
            except asyncio.CancelledError:
                self._circuit.record_cancelled()
                raise
            except BaseException:
                self._circuit.record_cancelled()
                raise
            self._circuit.record_success()
            return result
        finally:
            if acquired:
                self._permit.release()

    async def _execute_with_permit(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        work_parent = self._store.root / _WORKER_JOB_DIRECTORY
        work_parent.mkdir(mode=0o700, exist_ok=True)
        work_parent_metadata = work_parent.lstat()
        if not stat.S_ISDIR(work_parent_metadata.st_mode) or stat.S_ISLNK(
            work_parent_metadata.st_mode
        ):
            message = "PDF worker job root is not a private directory"
            raise PdfWorkerError(message)
        work_parent.chmod(0o700)
        job_path = Path(tempfile.mkdtemp(prefix=".nplg-pdf-worker-", dir=work_parent))
        process: Process | None = None
        try:
            self._require_deadline(deadline, phase="input staging")
            expected_source_sha256 = await self._run_storage(
                partial(
                    self._stage_inputs,
                    command,
                    job_path,
                    deadline=deadline,
                )
            )
            self._require_deadline(deadline, phase="input staging")
            try:
                process = await asyncio.create_subprocess_exec(
                    *self._worker_argv,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd="/",
                    env=self._worker_environment(job_path),
                    shell=False,
                    start_new_session=True,
                    close_fds=True,
                )
            except OSError as exc:
                message = "PDF worker process could not be started"
                raise PdfWorkerOperationalError(message) from exc
            try:
                result = await asyncio.wait_for(
                    self._exchange(process, command),
                    timeout=deadline.remaining(),
                )
            except TimeoutError as exc:
                message = "PDF worker exceeded its deadline"
                raise PdfWorkerOperationalError(message) from exc
            except asyncio.CancelledError:
                raise
            except (asyncio.IncompleteReadError, OSError, ValueError) as exc:
                message = "PDF worker transport failed"
                raise PdfWorkerOperationalError(message) from exc
            if process.returncode != 0:
                message = "PDF worker exited unsuccessfully"
                raise PdfWorkerOperationalError(message)
            await self._run_storage(
                partial(
                    self._validate_and_publish,
                    command,
                    result,
                    job_path,
                    expected_source_sha256=expected_source_sha256,
                    deadline=deadline,
                )
            )
            self._require_deadline(deadline, phase="result validation")
            return result
        finally:
            cleanup = asyncio.create_task(self._cleanup_worker(process, job_path))
            await self._wait_for_cleanup(cleanup)

    async def _cleanup_worker(self, process: Process | None, job_path: Path) -> None:
        """Reap the worker and remove its job tree as one shielded operation."""
        try:
            if process is not None:
                await self._terminate_process_group(process)
        finally:
            try:
                await self._cleanup_work.run_to_completion(
                    partial(self._remove_job_tree, job_path)
                )
            except (BlockingWorkCapacityError, OSError, RuntimeError) as exc:
                message = "PDF worker job cleanup failed"
                raise PdfWorkerOperationalError(message) from exc

    @classmethod
    def _remove_job_tree(cls, job_path: Path) -> None:
        """Remove a private job tree, retrying one permission recovery only."""
        try:
            shutil.rmtree(job_path)
        except FileNotFoundError:
            return
        except PermissionError:
            cls._restore_job_tree_permissions(job_path)
            try:
                shutil.rmtree(job_path)
            except FileNotFoundError:
                return

    @staticmethod
    def _restore_job_tree_permissions(job_path: Path) -> None:
        """Make only real directories in the private tree traversable."""
        metadata = job_path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            message = "PDF worker job path is not a private directory"
            raise OSError(message)
        job_path.chmod(0o700, follow_symlinks=False)
        for root, directories, _files in os.walk(
            job_path,
            topdown=True,
            followlinks=False,
        ):
            root_path = Path(root)
            root_path.chmod(0o700, follow_symlinks=False)
            for directory_name in directories:
                directory = root_path / directory_name
                try:
                    child_metadata = directory.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(child_metadata.st_mode) and not stat.S_ISLNK(
                    child_metadata.st_mode
                ):
                    directory.chmod(0o700, follow_symlinks=False)

    @staticmethod
    async def _wait_for_cleanup(cleanup: asyncio.Task[None]) -> None:
        """Defer repeated caller cancellation until cleanup really finishes."""
        cancellation: asyncio.CancelledError | None = None
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError as exc:
                cancellation = exc
        cleanup.result()
        if cancellation is not None:
            raise cancellation

    def _validate_and_publish(
        self,
        command: PdfCommand,
        result: PdfResult,
        job_path: Path,
        *,
        expected_source_sha256: str | None,
        deadline: MonotonicDeadline,
    ) -> None:
        self._validate_result_binding(
            command,
            result,
            expected_source_sha256=expected_source_sha256,
            job_path=job_path,
            deadline=deadline,
        )
        if isinstance(result, PdfSuccess):
            self._publish_outputs(
                command,
                result,
                job_path,
                deadline=deadline,
            )

    def _worker_environment(self, job_path: Path) -> dict[str, str]:
        source_root = Path(__file__).resolve().parents[1]
        limits = self._limits
        settings = self._processor_settings
        return {
            "LANG": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": str(source_root),
            "PYTHONUTF8": "1",
            "NPLG_PDF_WORK_ROOT": str(job_path),
            "NPLG_PDF_CPU_SECONDS": str(limits.cpu_seconds),
            "NPLG_PDF_ADDRESS_SPACE_BYTES": str(limits.address_space_bytes),
            "NPLG_PDF_FILE_SIZE_BYTES": str(limits.file_size_bytes),
            "NPLG_PDF_OPEN_FILES": str(limits.open_files),
            "NPLG_PDF_PROCESSES": str(limits.processes),
            "NPLG_PDF_MAX_PAGES_PER_RENDER": str(settings.max_pages_per_render),
            "NPLG_PDF_MAX_PAGE_PIXELS": str(settings.max_page_pixels),
            "NPLG_PDF_MAX_RENDER_PIXELS": str(settings.max_render_pixels),
            "NPLG_PDF_FALLBACK_DPI": str(settings.fallback_dpi),
            "NPLG_PDF_TILE_WIDTH": str(settings.tile_width),
            "NPLG_PDF_TILE_HEIGHT": str(settings.tile_height),
            "NPLG_PDF_TILE_OVERLAP": str(settings.tile_overlap),
            "NPLG_PDF_MAX_TILES_PER_PAGE": str(settings.max_tiles_per_page),
        }

    @staticmethod
    def _require_deadline(deadline: MonotonicDeadline, *, phase: str) -> None:
        if deadline.remaining() <= 0:
            message = f"PDF worker deadline expired during {phase}"
            raise PdfWorkerOperationalError(message)

    def _stage_inputs(
        self,
        command: PdfCommand,
        job_path: Path,
        *,
        deadline: MonotonicDeadline,
    ) -> str | None:
        cache_root = job_path / "cache"
        cache_root.mkdir(mode=0o700)
        if isinstance(command, (InspectCommand, RenderPagesCommand)):
            source = self._store.resolve_asset(command.source_relative_path)
            destination = cache_root.joinpath(*Path(command.source_relative_path).parts)
            destination.parent.mkdir(parents=True, mode=0o700)
            return self._copy_regular_file(
                source,
                destination,
                deadline=deadline,
            )
        render_id = command.parameters.render_id
        source_root = self._store.root / "renders" / render_id
        destination_root = cache_root / "renders" / render_id
        self._copy_regular_tree(source_root, destination_root, deadline=deadline)
        return None

    @classmethod
    def _copy_regular_file(
        cls,
        source: Path,
        destination: Path,
        *,
        deadline: MonotonicDeadline,
    ) -> str:
        cls._require_deadline(deadline, phase="input staging")
        before_open = source.lstat()
        if not stat.S_ISREG(before_open.st_mode) or before_open.st_nlink < 1:
            message = "PDF worker input is not a regular file"
            raise PdfWorkerError(message)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(source, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                before_open.st_dev,
                before_open.st_ino,
            ):
                message = "PDF worker input identity changed before staging"
                raise PdfWorkerError(message)
            digest = hashlib.sha256()
            with (
                os.fdopen(descriptor, "rb", closefd=False) as input_stream,
                destination.open("xb") as output_stream,
            ):
                while chunk := input_stream.read(1024 * 1024):
                    cls._require_deadline(deadline, phase="input staging")
                    digest.update(chunk)
                    written = output_stream.write(chunk)
                    if written != len(chunk):
                        message = "PDF worker input staging was incomplete"
                        raise PdfWorkerError(message)
                output_stream.flush()
                os.fsync(output_stream.fileno())
                cls._require_deadline(deadline, phase="input staging")
            after_copy = os.fstat(descriptor)
            if opened.st_size != after_copy.st_size or (
                opened.st_dev,
                opened.st_ino,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ) != (
                after_copy.st_dev,
                after_copy.st_ino,
                after_copy.st_mtime_ns,
                after_copy.st_ctime_ns,
            ):
                destination.unlink(missing_ok=True)
                message = "PDF worker input identity changed during staging"
                raise PdfWorkerError(message)
        finally:
            os.close(descriptor)
        destination.chmod(0o600)
        return digest.hexdigest()

    @classmethod
    def _copy_regular_tree(
        cls,
        source: Path,
        destination: Path,
        *,
        deadline: MonotonicDeadline,
    ) -> None:
        cls._require_deadline(deadline, phase="input staging")
        if source.is_symlink() or not source.is_dir():
            message = "PDF worker render input is unavailable"
            raise PdfWorkerError(message)
        destination.mkdir(parents=True, mode=0o700)
        for directory, directories, files in os.walk(source, followlinks=False):
            cls._require_deadline(deadline, phase="input staging")
            current = Path(directory)
            relative = current.relative_to(source)
            for name in directories:
                candidate = current / name
                if candidate.is_symlink():
                    message = "PDF worker render input contains a symlink"
                    raise PdfWorkerError(message)
                (destination / relative / name).mkdir(mode=0o700)
            for name in files:
                _ = cls._copy_regular_file(
                    current / name,
                    destination / relative / name,
                    deadline=deadline,
                )

    async def _exchange(self, process: Process, command: PdfCommand) -> PdfResult:
        input_stream = process.stdin
        output_stream = process.stdout
        error_stream = process.stderr
        if input_stream is None or output_stream is None or error_stream is None:
            message = "PDF worker pipes are unavailable"
            raise PdfWorkerOperationalError(message)
        request = encode_frame(command, maximum=MAX_COMMAND_FRAME_BYTES)
        write_task = asyncio.create_task(self._write_request(input_stream, request))
        result_task = asyncio.create_task(self._read_result_body(output_stream))
        stderr_task = asyncio.create_task(self._read_stderr(error_stream))
        tasks = {write_task, result_task, stderr_task}
        try:
            while tasks:
                done, tasks = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_EXCEPTION,
                )
                for completed in done:
                    exception = completed.exception()
                    if exception is not None:
                        raise exception
            body = result_task.result()
        finally:
            for pending in tasks:
                _ = pending.cancel()
            if tasks:
                _done, _pending = await asyncio.wait(tasks)
        _ = await process.wait()
        return parse_result_frame(body)

    @staticmethod
    async def _write_request(stream: StreamWriter, request: bytes) -> None:
        stream.write(request)
        await stream.drain()
        stream.close()

    @staticmethod
    async def _read_result_body(stream: StreamReader) -> bytes:
        header = await stream.readexactly(_FRAME_PREFIX_BYTES)
        size = int.from_bytes(header, "big")
        if size < 1 or size > MAX_RESULT_FRAME_BYTES:
            message = "PDF worker result length is outside the allowed range"
            raise PdfWorkerOperationalError(message)
        body = await stream.readexactly(size)
        if await stream.read(1):
            message = "PDF worker emitted trailing output"
            raise PdfWorkerOperationalError(message)
        return body

    async def _read_stderr(self, stream: StreamReader) -> None:
        total = 0
        while chunk := await stream.read(8_192):
            total += len(chunk)
            if total > self._limits.stderr_bytes:
                message = "PDF worker stderr exceeded its limit"
                raise PdfWorkerOperationalError(message)

    async def _terminate_process_group(self, process: Process) -> None:
        process_id = process.pid
        with suppress(ProcessLookupError):
            os.killpg(process_id, signal.SIGTERM)
        with suppress(TimeoutError):
            async with asyncio.timeout(self._limits.termination_grace_seconds):
                _ = await process.wait()
        with suppress(ProcessLookupError):
            os.killpg(process_id, signal.SIGKILL)
        if process.returncode is None:
            _ = await process.wait()
        await self._wait_for_process_group_exit(process_id)

    async def _wait_for_process_group_exit(self, process_group: int) -> None:
        expires_at = (
            asyncio.get_running_loop().time() + self._limits.termination_grace_seconds
        )
        while True:
            try:
                os.killpg(process_group, 0)
            except ProcessLookupError:
                return
            if asyncio.get_running_loop().time() >= expires_at:
                message = "PDF worker process group survived termination"
                raise PdfWorkerOperationalError(message)
            await asyncio.sleep(0.01)

    def _validate_result_binding(
        self,
        command: PdfCommand,
        result: PdfResult,
        *,
        expected_source_sha256: str | None,
        job_path: Path,
        deadline: MonotonicDeadline,
    ) -> None:
        if result.request_id != command.request_id:
            message = "PDF worker response request ID mismatch"
            raise PdfWorkerError(message)
        operation = (
            result.operation
            if isinstance(result, PdfFailure)
            else result.payload.operation
        )
        if operation != command.operation:
            message = "PDF worker response operation mismatch"
            raise PdfWorkerError(message)
        self._validate_result_pixel_budget(result)
        if (
            expected_source_sha256 is not None
            and isinstance(result, PdfSuccess)
            and isinstance(result.payload, (InspectPayload, RenderPagesPayload))
            and result.payload.value.source_sha256 != expected_source_sha256
        ):
            message = "PDF worker response source digest mismatch"
            raise PdfWorkerError(message)
        if (
            isinstance(command, RenderPagesCommand)
            and isinstance(result, PdfSuccess)
            and isinstance(result.payload, RenderPagesPayload)
        ):
            rendered = result.payload.value
            if tuple(page.page_number for page in rendered.pages) != (
                command.parameters.pages
            ):
                message = "PDF worker response page selection mismatch"
                raise PdfWorkerError(message)
            if expected_source_sha256 is None:
                message = "PDF worker response source identity is unavailable"
                raise PdfWorkerError(message)
            expected_render_id = render_identifier(
                source_sha256=expected_source_sha256,
                pages=command.parameters.pages,
                mode=command.parameters.mode,
                renderer_version=rendered.renderer_version,
                fallback_dpi=self._processor_settings.fallback_dpi,
            )
            if rendered.render_id != expected_render_id:
                message = "PDF worker response render ID mismatch"
                raise PdfWorkerError(message)
        if (
            isinstance(command, (RenderTilesCommand, ManifestCommand))
            and isinstance(result, PdfSuccess)
            and isinstance(result.payload, (RenderTilesPayload, ManifestPayload))
            and result.payload.value.render_id != command.parameters.render_id
        ):
            message = "PDF worker response render ID mismatch"
            raise PdfWorkerError(message)
        if (
            isinstance(command, RenderTilesCommand)
            and isinstance(result, PdfSuccess)
            and isinstance(result.payload, RenderTilesPayload)
        ):
            self._validate_tile_result_binding(
                command,
                result.payload.value,
                job_path,
                deadline=deadline,
            )

    def _validate_result_pixel_budget(self, result: PdfResult) -> None:
        if isinstance(result, PdfSuccess) and isinstance(
            result.payload,
            (RenderPagesPayload, ManifestPayload),
        ):
            self._validate_render_pixel_budget(result.payload.value)

    def _validate_render_pixel_budget(self, rendered: RenderPagesOutput) -> None:
        """Enforce parent-owned page and aggregate pixel ceilings."""
        settings = self._processor_settings
        if len(rendered.pages) > settings.max_pages_per_render:
            message = "PDF worker response exceeded the page-count limit"
            raise PdfWorkerError(message)
        total_pixels = 0
        for page in rendered.pages:
            page_pixels = page.width * page.height
            if page_pixels > settings.max_page_pixels:
                message = "PDF worker response exceeded the page pixel limit"
                raise PdfWorkerError(message)
            total_pixels += page_pixels
            if total_pixels > settings.max_render_pixels:
                message = "PDF worker response exceeded the aggregate pixel limit"
                raise PdfWorkerError(message)

    def _publish_outputs(
        self,
        command: PdfCommand,
        result: PdfSuccess,
        job_path: Path,
        *,
        deadline: MonotonicDeadline,
    ) -> None:
        payload = result.payload
        if isinstance(payload, RenderPagesPayload):
            self._publish_page_render(payload.value, job_path, deadline=deadline)
        elif isinstance(command, RenderTilesCommand) and isinstance(
            payload, RenderTilesPayload
        ):
            self._publish_tile_render(
                command,
                payload.value,
                job_path,
                deadline=deadline,
            )

    def _publish_page_render(
        self,
        rendered: RenderPagesOutput,
        job_path: Path,
        *,
        deadline: MonotonicDeadline,
    ) -> None:
        self._require_deadline(deadline, phase="output validation")
        root = f"renders/{rendered.render_id}"
        expected = {page.relative_path for page in rendered.pages}
        expected.add(rendered.manifest_relative_path)
        expected_digests: dict[str, str] = {}
        if rendered.manifest_relative_path != f"{root}/manifest.json":
            message = "PDF worker returned an unexpected render manifest path"
            raise PdfWorkerError(message)
        for page in rendered.pages:
            if page.relative_path != f"{root}/page-{page.page_number:04d}.jpg":
                message = "PDF worker returned an unexpected page path"
                raise PdfWorkerError(message)
            self._validate_output_file(
                job_path,
                page.relative_path,
                expected_sha256=page.sha256,
                expected_dimensions=(page.width, page.height),
                deadline=deadline,
            )
            expected_digests[page.relative_path] = page.sha256
        expected_digests[rendered.manifest_relative_path] = (
            self._validate_manifest_file(
                job_path,
                rendered.manifest_relative_path,
                rendered,
                deadline=deadline,
            )
        )
        self._require_exact_output_set(
            job_path,
            root,
            expected,
            deadline=deadline,
        )
        transaction = self._store.begin_render_transaction(
            root,
            completion_file="manifest.json",
        )
        try:
            if transaction.complete:
                if self._authoritative_matches(
                    job_path,
                    expected,
                    deadline=deadline,
                ):
                    transaction.commit()
                    return
                transaction.reset()
            for relative_path in sorted(expected - {rendered.manifest_relative_path}):
                self._publish_one(
                    job_path,
                    relative_path,
                    expected_sha256=expected_digests[relative_path],
                    deadline=deadline,
                )
            self._publish_one(
                job_path,
                rendered.manifest_relative_path,
                expected_sha256=expected_digests[rendered.manifest_relative_path],
                deadline=deadline,
            )
            transaction.commit()
        finally:
            transaction.rollback()

    def _publish_tile_render(
        self,
        command: RenderTilesCommand,
        rendered: RenderTilesOutput,
        job_path: Path,
        *,
        deadline: MonotonicDeadline,
    ) -> None:
        self._require_deadline(deadline, phase="output validation")
        parameters = command.parameters
        tile_width = parameters.tile_width or self._processor_settings.tile_width
        tile_height = parameters.tile_height or self._processor_settings.tile_height
        overlap = (
            parameters.overlap
            if parameters.overlap is not None
            else self._processor_settings.tile_overlap
        )
        geometry = f"w{tile_width:04d}-h{tile_height:04d}-o{overlap:03d}"
        root = (
            f"renders/{parameters.render_id}/tiles/"
            f"page-{parameters.page_number:04d}/{geometry}"
        )
        expected = {tile.relative_path for tile in rendered.tiles}
        expected.add(rendered.manifest_relative_path)
        expected_digests: dict[str, str] = {}
        if rendered.manifest_relative_path != f"{root}/manifest.json":
            message = "PDF worker returned an unexpected tile manifest path"
            raise PdfWorkerError(message)
        for tile in rendered.tiles:
            if tile.relative_path != f"{root}/{tile.tile_id}.jpg":
                message = "PDF worker returned an unexpected tile path"
                raise PdfWorkerError(message)
            self._validate_output_file(
                job_path,
                tile.relative_path,
                expected_sha256=tile.sha256,
                expected_dimensions=(tile.width, tile.height),
                deadline=deadline,
            )
            expected_digests[tile.relative_path] = tile.sha256
        expected_digests[rendered.manifest_relative_path] = (
            self._validate_manifest_file(
                job_path,
                rendered.manifest_relative_path,
                rendered,
                deadline=deadline,
            )
        )
        self._require_exact_output_set(
            job_path,
            root,
            expected,
            deadline=deadline,
        )
        transaction = self._store.begin_render_transaction(
            root,
            completion_file="manifest.json",
        )
        try:
            if transaction.complete:
                if self._authoritative_matches(
                    job_path,
                    expected,
                    deadline=deadline,
                ):
                    transaction.commit()
                    return
                transaction.reset()
            for relative_path in sorted(expected - {rendered.manifest_relative_path}):
                self._publish_one(
                    job_path,
                    relative_path,
                    expected_sha256=expected_digests[relative_path],
                    deadline=deadline,
                )
            self._publish_one(
                job_path,
                rendered.manifest_relative_path,
                expected_sha256=expected_digests[rendered.manifest_relative_path],
                deadline=deadline,
            )
            transaction.commit()
        finally:
            transaction.rollback()

    def _validated_descriptor(self, job_path: Path, relative_path: str) -> int:
        root = job_path / "cache"
        parts = Path(relative_path).parts
        directory_flags = os.O_RDONLY | os.O_DIRECTORY
        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
            file_flags |= os.O_NOFOLLOW
        descriptors = [os.open(root, directory_flags)]
        try:
            for part in parts[:-1]:
                descriptors.append(
                    os.open(part, directory_flags, dir_fd=descriptors[-1])
                )
            descriptor = os.open(parts[-1], file_flags, dir_fd=descriptors[-1])
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                os.close(descriptor)
                message = "PDF worker output is not a regular file"
                raise PdfWorkerError(message)
        except OSError as exc:
            message = "PDF worker output path is invalid"
            raise PdfWorkerError(message) from exc
        else:
            return descriptor
        finally:
            for directory_descriptor in reversed(descriptors):
                os.close(directory_descriptor)

    def _validate_output_file(
        self,
        job_path: Path,
        relative_path: str,
        *,
        expected_sha256: str,
        expected_dimensions: tuple[int, int],
        deadline: MonotonicDeadline,
    ) -> None:
        self._require_deadline(deadline, phase="output validation")
        self._validate_image_dimensions(expected_dimensions)
        descriptor = self._validated_descriptor(job_path, relative_path)
        try:
            before = os.fstat(descriptor)
            digest = hashlib.sha256()
            total = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                self._require_deadline(deadline, phase="output validation")
                total += len(chunk)
                if total > self._limits.file_size_bytes:
                    message = "PDF worker output exceeded its file-size limit"
                    raise PdfWorkerError(message)
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                digest.hexdigest() != expected_sha256
                or total != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                message = "PDF worker output failed identity or digest validation"
                raise PdfWorkerError(message)
            with os.fdopen(os.dup(descriptor), "rb") as image_stream:
                self._require_deadline(deadline, phase="output validation")
                _ = image_stream.seek(0)
                with Image.open(image_stream) as image:
                    self._validate_image_dimensions(image.size)
                    if image.format != "JPEG" or image.size != expected_dimensions:
                        message = "PDF worker image dimensions are invalid"
                        raise PdfWorkerError(message)
                    image.verify()
                _ = image_stream.seek(0)
                with Image.open(image_stream) as image:
                    self._validate_image_dimensions(image.size)
                    if image.format != "JPEG" or image.size != expected_dimensions:
                        message = "PDF worker image dimensions are invalid"
                        raise PdfWorkerError(message)
                    _ = image.load()
        except (OSError, UnidentifiedImageError, ValueError) as exc:
            message = "PDF worker image body is invalid"
            raise PdfWorkerError(message) from exc
        finally:
            os.close(descriptor)

    def _validate_image_dimensions(self, dimensions: tuple[int, int]) -> None:
        width, height = dimensions
        if width * height > self._processor_settings.max_page_pixels:
            message = "PDF worker image exceeded the page pixel limit"
            raise PdfWorkerError(message)

    def _load_staged_render_manifest(
        self,
        job_path: Path,
        render_id: str,
        *,
        deadline: MonotonicDeadline,
    ) -> RenderPagesOutput:
        relative_path = f"renders/{render_id}/manifest.json"
        descriptor = self._validated_descriptor(job_path, relative_path)
        try:
            data = bytearray()
            while chunk := os.read(descriptor, 64 * 1024):
                self._require_deadline(deadline, phase="tile source validation")
                if len(data) + len(chunk) > MAX_RESULT_FRAME_BYTES:
                    message = "PDF worker source manifest exceeded its limit"
                    raise PdfWorkerError(message)
                data.extend(chunk)
            try:
                manifest = RenderPagesOutput.model_validate_json(data, strict=True)
            except ValueError as exc:
                message = "PDF worker source manifest is invalid"
                raise PdfWorkerError(message) from exc
        finally:
            os.close(descriptor)
        if (
            manifest.render_id != render_id
            or manifest.manifest_relative_path != relative_path
        ):
            message = "PDF worker source manifest identity mismatch"
            raise PdfWorkerError(message)
        self._validate_render_pixel_budget(manifest)
        return manifest

    def _validate_tile_result_binding(
        self,
        command: RenderTilesCommand,
        rendered: RenderTilesOutput,
        job_path: Path,
        *,
        deadline: MonotonicDeadline,
    ) -> None:
        parameters = command.parameters
        expected_width = parameters.tile_width or self._processor_settings.tile_width
        expected_height = parameters.tile_height or self._processor_settings.tile_height
        expected_overlap = (
            parameters.overlap
            if parameters.overlap is not None
            else self._processor_settings.tile_overlap
        )
        if rendered.page_number != parameters.page_number:
            message = "PDF worker response page selection mismatch"
            raise PdfWorkerError(message)
        if (
            rendered.tile_width,
            rendered.tile_height,
            rendered.overlap,
        ) != (expected_width, expected_height, expected_overlap):
            message = "PDF worker response tile geometry mismatch"
            raise PdfWorkerError(message)
        manifest = self._load_staged_render_manifest(
            job_path,
            parameters.render_id,
            deadline=deadline,
        )
        page = next(
            (
                item
                for item in manifest.pages
                if item.page_number == parameters.page_number
            ),
            None,
        )
        if page is None or rendered.page_sha256 != page.sha256:
            message = "PDF worker response source page mismatch"
            raise PdfWorkerError(message)
        stride_x = expected_width - expected_overlap
        stride_y = expected_height - expected_overlap
        columns = ((page.width - 1) // stride_x) + 1
        rows = ((page.height - 1) // stride_y) + 1
        tile_count = columns * rows
        if tile_count > self._processor_settings.max_tiles_per_page:
            message = "PDF worker response exceeded the tile-count limit"
            raise PdfWorkerError(message)
        expected_tiles = tuple(
            (
                x,
                y,
                min(expected_width, page.width - x),
                min(expected_height, page.height - y),
            )
            for y in range(0, page.height, stride_y)
            for x in range(0, page.width, stride_x)
        )
        actual_tiles = tuple(
            (tile.x, tile.y, tile.width, tile.height) for tile in rendered.tiles
        )
        if actual_tiles != expected_tiles:
            message = "PDF worker response tile metadata mismatch"
            raise PdfWorkerError(message)
        geometry = (
            f"w{expected_width:04d}-h{expected_height:04d}-o{expected_overlap:03d}"
        )
        for tile in rendered.tiles:
            expected_tile_id = (
                f"p{parameters.page_number:04d}_{geometry}_x{tile.x:06d}_y{tile.y:06d}"
            )
            if (
                tile.tile_id != expected_tile_id
                or tile.page_number != parameters.page_number
                or tile.full_page_width != page.width
                or tile.full_page_height != page.height
                or tile.overlap != expected_overlap
            ):
                message = "PDF worker response tile metadata mismatch"
                raise PdfWorkerError(message)

    def _validate_manifest_file(
        self,
        job_path: Path,
        relative_path: str,
        expected: RenderPagesOutput | RenderTilesOutput,
        *,
        deadline: MonotonicDeadline,
    ) -> str:
        self._require_deadline(deadline, phase="manifest validation")
        descriptor = self._validated_descriptor(job_path, relative_path)
        try:
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, 64 * 1024):
                self._require_deadline(deadline, phase="manifest validation")
                total += len(chunk)
                if total > MAX_RESULT_FRAME_BYTES:
                    message = "PDF worker manifest exceeded its limit"
                    raise PdfWorkerError(message)
                chunks.append(chunk)
            data = b"".join(chunks)
            try:
                if isinstance(expected, RenderPagesOutput):
                    page_actual = RenderPagesOutput.model_validate_json(
                        data,
                        strict=True,
                    )
                    matches = page_actual == expected
                else:
                    tile_actual = RenderTilesOutput.model_validate_json(
                        data,
                        strict=True,
                    )
                    matches = tile_actual == expected
            except ValueError as exc:
                message = "PDF worker manifest is invalid"
                raise PdfWorkerError(message) from exc
            if not matches:
                message = "PDF worker manifest does not match its result"
                raise PdfWorkerError(message)
            return hashlib.sha256(data).hexdigest()
        finally:
            os.close(descriptor)

    def _require_exact_output_set(
        self,
        job_path: Path,
        relative_root: str,
        expected: set[str],
        *,
        deadline: MonotonicDeadline,
    ) -> None:
        self._require_deadline(deadline, phase="output inventory")
        root = job_path / "cache" / relative_root
        actual: set[str] = set()
        for directory, directories, files in os.walk(root, followlinks=False):
            self._require_deadline(deadline, phase="output inventory")
            base = Path(directory)
            for name in directories:
                if (base / name).is_symlink():
                    message = "PDF worker output contains a symlink"
                    raise PdfWorkerError(message)
            for name in files:
                path = base / name
                if path.is_symlink() or not path.is_file():
                    message = "PDF worker output contains a special file"
                    raise PdfWorkerError(message)
                actual.add(path.relative_to(job_path / "cache").as_posix())
        if actual != expected:
            message = "PDF worker returned unexpected or missing output paths"
            raise PdfWorkerError(message)

    def _authoritative_matches(
        self,
        job_path: Path,
        expected: set[str],
        *,
        deadline: MonotonicDeadline,
    ) -> bool:
        try:
            for relative_path in expected:
                self._require_deadline(deadline, phase="authoritative comparison")
                authoritative = self._store.resolve_asset(relative_path)
                candidate = job_path / "cache" / relative_path
                if self._sha256_path(
                    authoritative,
                    deadline=deadline,
                ) != self._sha256_path(candidate, deadline=deadline):
                    return False
        except (AppError, OSError, ValueError):
            return False
        return True

    @classmethod
    def _sha256_path(
        cls,
        path: Path,
        *,
        deadline: MonotonicDeadline,
    ) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                cls._require_deadline(deadline, phase="authoritative comparison")
                digest.update(chunk)
        return digest.hexdigest()

    def _publish_one(
        self,
        job_path: Path,
        relative_path: str,
        *,
        expected_sha256: str,
        deadline: MonotonicDeadline,
    ) -> None:
        self._require_deadline(deadline, phase="output publication")
        descriptor = self._validated_descriptor(job_path, relative_path)
        try:
            with self._store.stage(suffix=Path(relative_path).suffix) as staged:
                self._require_deadline(deadline, phase="output publication")
                digest = hashlib.sha256()
                while chunk := os.read(descriptor, 1024 * 1024):
                    self._require_deadline(deadline, phase="output publication")
                    digest.update(chunk)
                    written = staged.write(chunk)
                    if written != len(chunk):
                        message = "PDF worker output publication was incomplete"
                        raise PdfWorkerError(message)
                if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
                    message = "PDF worker output publication digest mismatch"
                    raise PdfWorkerError(message)
                self._require_deadline(deadline, phase="output publication")
                _ = staged.commit_render(relative_path)
        finally:
            os.close(descriptor)
