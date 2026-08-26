# Copyright (c) 2026 David Osipov
"""Adversarial edge tests for the PDF worker process entry point."""

from __future__ import annotations

import asyncio
import errno
import io
import os
import resource
import runpy
import socket
import stat
import sys
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, Self, cast, override
from uuid import UUID

import pytest

import nplg_mcp.pdf_worker_main as worker_main_module
from nplg_mcp.pdf_executor import PdfProcessorSettings
from nplg_mcp.pdf_ipc import (
    MAX_COMMAND_FRAME_BYTES,
    InspectCommand,
    InspectParams,
    PdfCommand,
    PdfFailure,
    encode_frame,
    parse_result_frame,
)
from nplg_mcp.storage import ContentAddressedStore

if TYPE_CHECKING:
    from collections.abc import Awaitable
    from types import TracebackType
    from typing import TextIO


class _PeerCredentials(Protocol):
    def __call__(self, value: bytes) -> tuple[int, int, int]: ...


class _ReadSocketCommand(Protocol):
    def __call__(self, reader: asyncio.StreamReader) -> Awaitable[PdfCommand]: ...


class _RequestRoot(Protocol):
    def __call__(self, root: Path, command: PdfCommand) -> Path: ...


class _VerifyUnixPeer(Protocol):
    def __call__(self, writer: object) -> None: ...


class _OpenSocketPath(Protocol):
    def __call__(self, path: Path) -> int: ...


class _RequireUnusedSocketName(Protocol):
    def __call__(self, parent_descriptor: int, name: str) -> None: ...


class _EndpointIdentity(Protocol):
    def __call__(self, parent_descriptor: int, name: str) -> object: ...


class _RequirePrivateSocket(Protocol):
    def __call__(self, identity: object) -> None: ...


class _RemoveServerSocket(Protocol):
    def __call__(
        self,
        parent_descriptor: int,
        name: str,
        expected: object,
    ) -> None: ...


class _ServeOneUnixRequest(Protocol):
    def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: object,
        *,
        execution: object,
    ) -> Awaitable[None]: ...


class _ServeUnixSocket(Protocol):
    def __call__(
        self,
        path: Path,
        *,
        root: Path,
        max_bytes: int,
        settings: PdfProcessorSettings,
        job_options: object | None = None,
    ) -> Awaitable[None]: ...


class _JobExecutionContextFactory(Protocol):
    def __call__(
        self,
        *,
        root: Path,
        max_bytes: int,
        settings: PdfProcessorSettings,
        worker_argv: tuple[str, ...],
        timeout_seconds: float,
    ) -> object: ...


class _JobLaunchOptionsView(Protocol):
    worker_argv: tuple[str, ...]
    timeout_seconds: float


class _StartUnixServer(Protocol):
    async def __call__(
        self,
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool = True,
        cleanup_socket: bool = True,
    ) -> asyncio.Server: ...


_WORKER_MAIN_NAMESPACE = cast(
    "dict[str, object]",
    cast("object", worker_main_module.__dict__),
)
_SERVE_UNIX_SOCKET = cast(
    "_ServeUnixSocket",
    _WORKER_MAIN_NAMESPACE["_serve_unix_socket"],
)
_PEER_CREDENTIALS = cast(
    "_PeerCredentials",
    _WORKER_MAIN_NAMESPACE["_peer_credentials"],
)
_READ_SOCKET_COMMAND = cast(
    "_ReadSocketCommand",
    _WORKER_MAIN_NAMESPACE["_read_socket_command"],
)
_REQUEST_ROOT = cast(
    "_RequestRoot",
    _WORKER_MAIN_NAMESPACE["_request_root"],
)
_VERIFIED_UNIX_PEER = cast(
    "_VerifyUnixPeer",
    _WORKER_MAIN_NAMESPACE["_verified_unix_peer"],
)
_VALIDATE_SERVER_SOCKET_PATH = cast(
    "_OpenSocketPath",
    _WORKER_MAIN_NAMESPACE["_validate_server_socket_path"],
)
_REQUIRE_UNUSED_SOCKET_NAME = cast(
    "_RequireUnusedSocketName",
    _WORKER_MAIN_NAMESPACE["_require_unused_socket_name"],
)
_ENDPOINT_IDENTITY = cast(
    "_EndpointIdentity",
    _WORKER_MAIN_NAMESPACE["_endpoint_identity"],
)
_REQUIRE_PRIVATE_SOCKET = cast(
    "_RequirePrivateSocket",
    _WORKER_MAIN_NAMESPACE["_require_private_socket"],
)
_REMOVE_SERVER_SOCKET = cast(
    "_RemoveServerSocket",
    _WORKER_MAIN_NAMESPACE["_remove_server_socket"],
)
_SERVE_ONE_UNIX_REQUEST = cast(
    "_ServeOneUnixRequest",
    _WORKER_MAIN_NAMESPACE["_serve_one_unix_request"],
)
_JOB_EXECUTION_CONTEXT = cast(
    "_JobExecutionContextFactory",
    _WORKER_MAIN_NAMESPACE["_JobExecutionContext"],
)

_FRAME_PREFIX_BYTES = 4
_PEER_CREDENTIAL_BYTES = 12
_EXPECTED_FILE_LIMIT = 536_870_912
_REPLACEMENT_TARGET_MODE = 0o640
_NONPRIVATE_SOCKET_MODE = 0o640
_TEST_PRIVATE_UMASK = 0o027
_TEST_SOCKET_TIMEOUT_SECONDS = 0.25
_EXPECTED_VALIDATION_CALLS_AFTER_RESTART = 2
_EXPECTED_JOB_TIMEOUT_SECONDS = 31.0


def _inspect_command(*, request_id: int = 91) -> InspectCommand:
    return InspectCommand(
        request_id=UUID(int=request_id),
        operation="inspect",
        source_relative_path="documents/doc_" + "0" * 64 + "/source.pdf",
        parameters=InspectParams(),
    )


def _job_execution(root: Path) -> object:
    return _JOB_EXECUTION_CONTEXT(
        root=root,
        max_bytes=1_048_576,
        settings=PdfProcessorSettings(),
        worker_argv=(sys.executable, "-m", "nplg_mcp.pdf_worker_main"),
        timeout_seconds=30.0,
    )


def _stream_reader(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


def _assert_descriptor_relative_socket_path(path: str, *, name: str) -> None:
    """Require the listener to bind through its validated parent descriptor."""
    assert path.startswith("/proc/self/fd/")
    assert path.rsplit("/", maxsplit=1)[-1] == name


def _assert_caller_owned_listener(
    *,
    start_serving: bool,
    cleanup_socket: bool,
) -> None:
    """Require deferred accepts and one explicit endpoint-cleanup owner."""
    assert not start_serving
    if sys.version_info >= (3, 13):
        assert not cleanup_socket


def _set_test_path_mode(path: str, mode: int) -> None:
    """Apply a synchronous test mutation outside the async lint surface."""
    Path(path).chmod(mode)


def _descriptor_is_open(descriptor: int) -> bool:
    """Report whether a captured descriptor still names an open resource."""
    try:
        _ = os.fstat(descriptor)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        return False
    return True


def _unix_connection_succeeds(path: Path) -> bool:
    """Probe whether a supposedly cancelled listener still accepts clients."""
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(_TEST_SOCKET_TIMEOUT_SECONDS)
    try:
        probe.connect(str(path))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _unlink_if_present(path: Path) -> None:
    """Remove a real test endpoint without widening async filesystem access."""
    with suppress(FileNotFoundError):
        path.unlink()


def _path_entry_exists(path: Path) -> bool:
    """Observe a final path entry without hiding a dangling replacement link."""
    return os.path.lexists(path)


def _peer_record(process_id: int, user_id: int, group_id: int) -> bytes:
    return b"".join(
        value.to_bytes(4, byteorder=sys.byteorder, signed=True)
        for value in (process_id, user_id, group_id)
    )


class _PeerSocket:
    """Return one deterministic native peer-credential record."""

    def __init__(
        self,
        *,
        family: socket.AddressFamily,
        credentials: bytes,
    ) -> None:
        super().__init__()
        self.family = family
        self._credentials = credentials

    def getsockopt(self, level: int, option: int, buffer_size: int) -> bytes:
        assert level == socket.SOL_SOCKET
        assert option == socket.SO_PEERCRED
        assert buffer_size == _PEER_CREDENTIAL_BYTES
        return self._credentials


class _FakeWriter:
    """Capture one framed response and connection cleanup."""

    def __init__(
        self,
        peer: object,
        *,
        wait_error: OSError | None = None,
    ) -> None:
        super().__init__()
        self._peer = peer
        self._wait_error = wait_error
        self.payload = bytearray()
        self.drained = False
        self.closed = False
        self.waited_closed = False

    def get_extra_info(self, name: str) -> object:
        assert name == "socket"
        return self._peer

    def write(self, payload: bytes) -> None:
        self.payload.extend(payload)

    async def drain(self) -> None:
        self.drained = True

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited_closed = True
        if self._wait_error is not None:
            raise self._wait_error


def _worker_environment(work_root: Path) -> dict[str, str]:
    return {
        "NPLG_PDF_WORK_ROOT": str(work_root),
        "NPLG_PDF_CPU_SECONDS": "30",
        "NPLG_PDF_ADDRESS_SPACE_BYTES": "1073741824",
        "NPLG_PDF_FILE_SIZE_BYTES": "536870912",
        "NPLG_PDF_OPEN_FILES": "64",
        "NPLG_PDF_PROCESSES": "8",
        "NPLG_PDF_FALLBACK_DPI": "400",
        "NPLG_PDF_MAX_PAGES_PER_RENDER": "8",
        "NPLG_PDF_MAX_PAGE_PIXELS": "100000000",
        "NPLG_PDF_MAX_RENDER_PIXELS": "250000000",
        "NPLG_PDF_TILE_WIDTH": "2048",
        "NPLG_PDF_TILE_HEIGHT": "2048",
        "NPLG_PDF_TILE_OVERLAP": "128",
        "NPLG_PDF_MAX_TILES_PER_PAGE": "100",
    }


def _apply_worker_environment(
    monkeypatch: pytest.MonkeyPatch,
    work_root: Path,
) -> None:
    for name, value in _worker_environment(work_root).items():
        monkeypatch.setenv(name, value)


def _disable_process_mutations(monkeypatch: pytest.MonkeyPatch) -> None:
    def ignore_limit(_resource: int, _limits: tuple[int, int]) -> None:
        return None

    def ignore_umask(_mask: int) -> int:
        return 0o022

    monkeypatch.setattr(resource, "setrlimit", ignore_limit)
    monkeypatch.setattr(os, "umask", ignore_umask)


def _bind_standard_streams(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> io.BytesIO:
    input_buffer = io.BytesIO(payload)
    output_buffer = io.BytesIO()
    input_stream = io.TextIOWrapper(input_buffer, encoding="utf-8")
    output_stream = io.TextIOWrapper(output_buffer, encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", cast("TextIO", input_stream))
    monkeypatch.setattr(sys, "stdout", cast("TextIO", output_stream))
    return output_buffer


class _FakeUnixServer:
    """Record cleanup without opening a host socket."""

    def __init__(self, *, serve_error: Exception | None = None) -> None:
        super().__init__()
        self._serve_error = serve_error
        self.closed = False
        self.waited_closed = False
        self.entered = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited_closed = True

    async def serve_forever(self) -> None:
        if self._serve_error is not None:
            raise self._serve_error
        pytest.fail("server accepted work before its socket mode was private")

    async def __aenter__(self) -> Self:
        self.entered = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()
        await self.wait_closed()


class _ReplacingUnixServer(_FakeUnixServer):
    """Replace the bound endpoint while preserving the listener descriptor."""

    def __init__(self, *, path: Path, listener: socket.socket) -> None:
        super().__init__()
        self._path = path
        self._listener = listener

    @override
    def close(self) -> None:
        super().close()
        self._listener.close()

    @override
    async def serve_forever(self) -> None:
        self._path.unlink()
        _ = self._path.write_bytes(b"attacker replacement")
        message = "synthetic replacement after bind"
        raise RuntimeError(message)


class _ListeningUnixServer(_FakeUnixServer):
    """Pair the fake asyncio lifecycle with a real bound Unix socket."""

    def __init__(
        self,
        *,
        listener: socket.socket,
        serve_error: Exception,
    ) -> None:
        super().__init__(serve_error=serve_error)
        self._listener = listener

    @override
    def close(self) -> None:
        super().close()
        self._listener.close()


class _BarrierUnixServerFactory:
    """Bind a real listener and expose its pre-return cancellation boundary."""

    def __init__(self) -> None:
        super().__init__()
        self._start = cast(
            "_StartUnixServer",
            cast("object", asyncio.start_unix_server),
        )
        self.bound = asyncio.Event()
        self.release_started_server = asyncio.Event()
        self.created_servers: list[asyncio.Server] = []
        self.listener_descriptor: int | None = None
        self.parent_descriptor: int | None = None

    async def __call__(
        self,
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool = True,
        cleanup_socket: bool = True,
    ) -> asyncio.Server:
        if sys.version_info >= (3, 13):
            server = await self._start(
                client_connected_callback,
                path=path,
                start_serving=start_serving,
                cleanup_socket=cleanup_socket,
            )
        else:
            server = await self._start(
                client_connected_callback,
                path=path,
                start_serving=start_serving,
            )
        sockets = server.sockets
        self.created_servers.append(server)
        self.listener_descriptor = sockets[0].fileno()
        self.parent_descriptor = int(path.split("/")[4])
        self.bound.set()
        if start_serving:
            _ = await self.release_started_server.wait()
        return server

    async def close(self, path: Path) -> None:
        """Reclaim a deliberately leaked RED listener after observations."""
        self.release_started_server.set()
        for server in self.created_servers:
            server.close()
            await server.wait_closed()
        _unlink_if_present(path)


@pytest.mark.asyncio
async def test_unix_server_rejects_a_non_socket_endpoint_without_deleting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Treat a non-socket result as a replacement rather than owned cleanup."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    server = _FakeUnixServer()

    async def start_unix_server(
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool = True,
        cleanup_socket: bool = True,
    ) -> _FakeUnixServer:
        del client_connected_callback
        _assert_caller_owned_listener(
            start_serving=start_serving,
            cleanup_socket=cleanup_socket,
        )
        _assert_descriptor_relative_socket_path(path, name=socket_path.name)
        _ = socket_path.write_bytes(b"synthetic socket endpoint")
        return server

    monkeypatch.setattr(asyncio, "start_unix_server", start_unix_server)

    with pytest.raises(RuntimeError, match="socket endpoint is invalid"):
        await _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )

    assert server.closed
    assert server.waited_closed
    assert socket_path.read_bytes() == b"synthetic socket endpoint"


@pytest.mark.parametrize("defect", ["mode", "uid", "gid", "hardlink"])
@pytest.mark.asyncio
async def test_unix_server_rejects_every_nonprivate_bound_socket_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    """Validate mode, owner, group, and link count before accepting peers."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    servers: list[_ListeningUnixServer] = []
    foreign_uid = os.geteuid() + 1
    foreign_gid = os.getegid() + 1

    async def start_unix_server(
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool = True,
        cleanup_socket: bool = True,
    ) -> _ListeningUnixServer:
        del client_connected_callback
        _assert_caller_owned_listener(
            start_serving=start_serving,
            cleanup_socket=cleanup_socket,
        )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        if defect == "mode":
            _set_test_path_mode(path, _NONPRIVATE_SOCKET_MODE)
        elif defect == "uid":
            monkeypatch.setattr(os, "geteuid", lambda: foreign_uid)
        elif defect == "gid":
            monkeypatch.setattr(os, "getegid", lambda: foreign_gid)
        else:
            os.link(path, socket_parent / "worker-hardlink.sock")
        server = _ListeningUnixServer(
            listener=listener,
            serve_error=RuntimeError("must not serve"),
        )
        servers.append(server)
        return server

    monkeypatch.setattr(asyncio, "start_unix_server", start_unix_server)

    with pytest.raises(RuntimeError, match="socket endpoint is invalid"):
        await _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )

    assert len(servers) == 1
    assert servers[0].closed
    assert servers[0].waited_closed


@pytest.mark.asyncio
async def test_unix_server_restores_umask_and_parent_fd_when_start_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation or bind failure cannot leak process or descriptor state."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    parent_descriptors: list[int] = []

    async def start_unix_server(
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool = True,
        cleanup_socket: bool = True,
    ) -> _FakeUnixServer:
        del client_connected_callback
        _assert_caller_owned_listener(
            start_serving=start_serving,
            cleanup_socket=cleanup_socket,
        )
        _assert_descriptor_relative_socket_path(path, name=socket_path.name)
        parent_descriptors.append(int(path.split("/")[4]))
        message = "synthetic bind failure"
        raise OSError(message)

    monkeypatch.setattr(asyncio, "start_unix_server", start_unix_server)
    original_umask = os.umask(_TEST_PRIVATE_UMASK)
    try:
        with pytest.raises(OSError, match="synthetic bind failure"):
            await _SERVE_UNIX_SOCKET(
                socket_path,
                root=tmp_path,
                max_bytes=1_048_576,
                settings=PdfProcessorSettings(),
            )
        observed_umask = os.umask(original_umask)
        assert observed_umask == _TEST_PRIVATE_UMASK
    finally:
        _ = os.umask(original_umask)

    assert len(parent_descriptors) == 1
    with pytest.raises(OSError, match="Bad file descriptor"):
        _ = os.fstat(parent_descriptors[0])


@pytest.mark.asyncio
async def test_unix_server_uses_the_python_312_listener_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not pass the Python 3.13 cleanup option on the supported 3.12 API."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    parent_descriptors: list[int] = []

    async def start_unix_server(
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool,
    ) -> _FakeUnixServer:
        del client_connected_callback
        assert not start_serving
        parent_descriptors.append(int(path.split("/")[4]))
        message = "synthetic Python 3.12 bind failure"
        raise OSError(message)

    monkeypatch.setattr(sys, "version_info", (3, 12))
    monkeypatch.setattr(asyncio, "start_unix_server", start_unix_server)

    with pytest.raises(OSError, match=r"synthetic Python 3\.12 bind failure"):
        await _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )

    assert len(parent_descriptors) == 1
    with pytest.raises(OSError, match="Bad file descriptor"):
        _ = os.fstat(parent_descriptors[0])


@pytest.mark.asyncio
async def test_unix_server_cancellation_after_bind_reclaims_listener_and_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation before ownership transfer must not orphan a live listener."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    factory = _BarrierUnixServerFactory()
    monkeypatch.setattr(asyncio, "start_unix_server", factory)
    operation: asyncio.Future[None] = asyncio.ensure_future(
        _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )
    )
    _ = await factory.bound.wait()
    _ = operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation

    endpoint_remained = socket_path.exists()
    assert factory.listener_descriptor is not None
    assert factory.parent_descriptor is not None
    listener_open = _descriptor_is_open(factory.listener_descriptor)
    parent_open = _descriptor_is_open(factory.parent_descriptor)
    connection_succeeded = _unix_connection_succeeds(socket_path)
    await factory.close(socket_path)

    assert not endpoint_remained
    assert not listener_open
    assert not parent_open
    assert not connection_succeeded


@pytest.mark.asyncio
async def test_validation_rejection_reclaims_exact_endpoint_before_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a rejected created endpoint that permanently blocks worker restart."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    validation_calls = 0
    restarted = asyncio.Event()

    def reject_first_created_endpoint(identity: object) -> None:
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 1:
            message = "synthetic exact endpoint rejection"
            raise RuntimeError(message)
        _REQUIRE_PRIVATE_SOCKET(identity)
        restarted.set()

    monkeypatch.setattr(
        worker_main_module,
        "_require_private_socket",
        reject_first_created_endpoint,
    )

    with pytest.raises(RuntimeError, match="synthetic exact endpoint rejection"):
        await _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )

    assert not _path_entry_exists(socket_path)

    operation: asyncio.Future[None] = asyncio.ensure_future(
        _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )
    )
    try:
        async with asyncio.timeout(1):
            _ = await restarted.wait()
        assert not operation.done()
        assert socket_path.is_socket()
    finally:
        _ = operation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await operation

    assert validation_calls == _EXPECTED_VALIDATION_CALLS_AFTER_RESTART
    assert not _path_entry_exists(socket_path)


@pytest.mark.parametrize("credential_bytes", [b"", b"x" * 11, b"x" * 13])
def test_peer_credentials_rejects_every_noncanonical_record_size(
    credential_bytes: bytes,
) -> None:
    """Catch partial or overlong native credential decoding."""
    with pytest.raises(RuntimeError, match="credentials are malformed"):
        _ = _PEER_CREDENTIALS(credential_bytes)

    assert _PEER_CREDENTIALS(_peer_record(123, 456, 789)) == (123, 456, 789)


@pytest.mark.asyncio
async def test_socket_command_reader_accepts_one_exact_eof_delimited_frame() -> None:
    """Catch failure to parse a complete bounded command at EOF."""
    command = _inspect_command()
    parsed = await _READ_SOCKET_COMMAND(
        _stream_reader(encode_frame(command, maximum=MAX_COMMAND_FRAME_BYTES))
    )

    assert parsed == command


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [0, MAX_COMMAND_FRAME_BYTES + 1])
async def test_socket_command_reader_rejects_out_of_range_lengths(size: int) -> None:
    """Catch empty or oversized socket request frames before body allocation."""
    reader = _stream_reader(size.to_bytes(_FRAME_PREFIX_BYTES, "big"))

    with pytest.raises(RuntimeError, match="length is outside"):
        _ = await _READ_SOCKET_COMMAND(reader)


@pytest.mark.asyncio
async def test_socket_command_reader_rejects_truncation_and_trailing_data() -> None:
    """Catch partial bodies and a second command hidden behind the first frame."""
    truncated = _stream_reader((2).to_bytes(_FRAME_PREFIX_BYTES, "big") + b"{")
    with pytest.raises(asyncio.IncompleteReadError):
        _ = await _READ_SOCKET_COMMAND(truncated)

    command = _inspect_command()
    trailing = _stream_reader(
        encode_frame(command, maximum=MAX_COMMAND_FRAME_BYTES) + b"x"
    )
    with pytest.raises(RuntimeError, match="trailing data"):
        _ = await _READ_SOCKET_COMMAND(trailing)


def test_request_root_requires_one_private_uuid_directory(tmp_path: Path) -> None:
    """Catch missing or non-directory request staging components."""
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    command = _inspect_command()
    request_path = root / command.request_id.hex

    with pytest.raises(RuntimeError, match="is unavailable"):
        _ = _REQUEST_ROOT(root, command)

    _ = request_path.write_bytes(b"regular file")
    with pytest.raises(RuntimeError, match="directory is invalid"):
        _ = _REQUEST_ROOT(root, command)


@pytest.mark.parametrize("defect", ["symlink", "permissions"])
def test_request_root_rejects_symlink_or_public_directory(
    tmp_path: Path,
    defect: str,
) -> None:
    """Catch request-root substitution or exposure to other identities."""
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    command = _inspect_command()
    request_path = root / command.request_id.hex
    if defect == "symlink":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        request_path.symlink_to(target, target_is_directory=True)
    else:
        request_path.mkdir(mode=0o755)

    with pytest.raises(RuntimeError, match="directory is invalid"):
        _ = _REQUEST_ROOT(root, command)


def test_request_root_accepts_one_private_directory(tmp_path: Path) -> None:
    """Catch accidental rejection of the parent-created private request root."""
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    command = _inspect_command()
    request_path = root / command.request_id.hex
    request_path.mkdir(mode=0o700)

    assert _REQUEST_ROOT(root, command) == request_path


@pytest.mark.parametrize(
    ("peer", "message"),
    [
        (object(), "transport is not AF_UNIX"),
        (
            _PeerSocket(
                family=socket.AF_INET,
                credentials=_peer_record(1, os.geteuid(), os.getegid()),
            ),
            "transport is not AF_UNIX",
        ),
        (
            _PeerSocket(family=socket.AF_UNIX, credentials=b"short"),
            "credentials are malformed",
        ),
        (
            _PeerSocket(
                family=socket.AF_UNIX,
                credentials=_peer_record(1, os.geteuid() + 1, os.getegid()),
            ),
            "peer identity is invalid",
        ),
    ],
)
def test_unix_peer_verification_rejects_transport_and_identity_forgery(
    peer: object,
    message: str,
) -> None:
    """Catch non-Unix, malformed, or cross-identity worker clients."""
    with pytest.raises(RuntimeError, match=message):
        _VERIFIED_UNIX_PEER(_FakeWriter(peer))


def test_unix_peer_verification_accepts_the_current_identity() -> None:
    """Catch rejection of the expected same-identity private parent."""
    peer = _PeerSocket(
        family=socket.AF_UNIX,
        credentials=_peer_record(1, os.geteuid(), os.getegid()),
    )

    _VERIFIED_UNIX_PEER(_FakeWriter(peer))


def test_server_socket_path_rejects_relative_existing_and_link_targets(
    tmp_path: Path,
) -> None:
    """Catch bind replacement or traversal through the endpoint itself."""
    with pytest.raises(RuntimeError, match="socket path is invalid"):
        _ = _VALIDATE_SERVER_SOCKET_PATH(Path("relative.sock"))

    existing = tmp_path / "existing.sock"
    _ = existing.write_bytes(b"occupied")
    with pytest.raises(RuntimeError, match="socket path is invalid"):
        _ = _VALIDATE_SERVER_SOCKET_PATH(existing)

    target = tmp_path / "missing-target"
    link = tmp_path / "dangling.sock"
    link.symlink_to(target)
    with pytest.raises(RuntimeError, match="socket path is invalid"):
        _ = _VALIDATE_SERVER_SOCKET_PATH(link)


@pytest.mark.parametrize("defect", ["regular", "symlink", "permissions"])
def test_server_socket_path_requires_one_private_real_parent(
    tmp_path: Path,
    defect: str,
) -> None:
    """Catch bind admission beneath a replaceable or non-private parent."""
    parent = tmp_path / "parent"
    if defect == "regular":
        _ = parent.write_bytes(b"not a directory")
    elif defect == "symlink":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        parent.symlink_to(target, target_is_directory=True)
    else:
        parent.mkdir(mode=0o755)

    with pytest.raises(RuntimeError, match="socket directory is invalid"):
        _ = _VALIDATE_SERVER_SOCKET_PATH(parent / "worker.sock")


def test_server_socket_path_accepts_a_private_unused_endpoint(tmp_path: Path) -> None:
    """Catch accidental rejection of the reviewed private socket layout."""
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)

    descriptor = _VALIDATE_SERVER_SOCKET_PATH(parent / "worker.sock")
    os.close(descriptor)


@pytest.mark.parametrize("flag_name", ["O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"])
def test_server_socket_path_requires_every_descriptor_protection_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag_name: str,
) -> None:
    """Fail closed when descriptor-relative path protection is unavailable."""
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    monkeypatch.delattr(os, flag_name)

    with pytest.raises(RuntimeError, match="directory protection is unavailable"):
        _ = _VALIDATE_SERVER_SOCKET_PATH(parent / "worker.sock")


def test_unused_socket_name_wraps_non_missing_stat_failures(tmp_path: Path) -> None:
    """Do not misclassify descriptor or permission failures as path absence."""
    descriptor = os.open(tmp_path, os.O_RDONLY)
    os.close(descriptor)

    with pytest.raises(RuntimeError, match="socket path is invalid"):
        _REQUIRE_UNUSED_SOCKET_NAME(descriptor, "worker.sock")


@pytest.mark.parametrize("identity", ["uid", "gid"])
def test_server_socket_path_requires_current_process_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    identity: str,
) -> None:
    """Reject a private-mode parent controlled by a different principal."""
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    if identity == "uid":
        monkeypatch.setattr(os, "geteuid", lambda: parent.stat().st_uid + 1)
    else:
        monkeypatch.setattr(os, "getegid", lambda: parent.stat().st_gid + 1)

    with pytest.raises(RuntimeError, match="socket directory is invalid"):
        _ = _VALIDATE_SERVER_SOCKET_PATH(parent / "worker.sock")


def test_socket_cleanup_is_idempotent_only_for_a_missing_exact_endpoint(
    tmp_path: Path,
) -> None:
    """Distinguish an absent owned endpoint from every other stat failure."""
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    path = parent / "worker.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        expected = _ENDPOINT_IDENTITY(descriptor, path.name)
        path.unlink()
        _REMOVE_SERVER_SOCKET(descriptor, path.name, expected)
        os.close(descriptor)
        with pytest.raises(RuntimeError, match="socket endpoint is invalid"):
            _REMOVE_SERVER_SOCKET(descriptor, path.name, expected)
    finally:
        listener.close()
        with suppress(OSError):
            os.close(descriptor)


@pytest.mark.asyncio
async def test_one_unix_request_sanitizes_missing_job_and_closes_connection(
    tmp_path: Path,
) -> None:
    """Catch a per-request failure that escapes unsanitized or leaks the peer."""
    command = _inspect_command()
    reader = _stream_reader(encode_frame(command, maximum=MAX_COMMAND_FRAME_BYTES))
    peer = _PeerSocket(
        family=socket.AF_UNIX,
        credentials=_peer_record(1, os.geteuid(), os.getegid()),
    )
    writer = _FakeWriter(peer)

    await _SERVE_ONE_UNIX_REQUEST(
        reader,
        writer,
        execution=_job_execution(tmp_path),
    )

    assert writer.drained
    assert writer.closed
    assert writer.waited_closed
    frame = bytes(writer.payload)
    size = int.from_bytes(frame[:_FRAME_PREFIX_BYTES], "big")
    result = parse_result_frame(frame[_FRAME_PREFIX_BYTES:])
    assert len(frame) == _FRAME_PREFIX_BYTES + size
    assert isinstance(result, PdfFailure)
    assert result.payload.message == "The PDF worker could not complete the request."


@pytest.mark.asyncio
async def test_one_unix_request_silently_closes_on_transport_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reset local peer must not escape through the event-loop callback."""

    async def reset_during_read(_reader: asyncio.StreamReader) -> PdfCommand:
        message = "ATTACKER_CONTROLLED_RESET_SENTINEL"
        raise ConnectionResetError(message)

    monkeypatch.setitem(
        _WORKER_MAIN_NAMESPACE,
        "_read_socket_command",
        reset_during_read,
    )
    writer = _FakeWriter(
        _PeerSocket(
            family=socket.AF_UNIX,
            credentials=_peer_record(1, os.geteuid(), os.getegid()),
        )
    )

    await _SERVE_ONE_UNIX_REQUEST(
        _stream_reader(b""),
        writer,
        execution=_job_execution(tmp_path),
    )

    assert writer.payload == b""
    assert writer.closed
    assert writer.waited_closed


@pytest.mark.asyncio
async def test_one_unix_request_closes_even_when_peer_and_wait_close_fail(
    tmp_path: Path,
) -> None:
    """Catch cleanup loss when authentication and transport shutdown both fail."""
    writer = _FakeWriter(
        object(),
        wait_error=OSError("synthetic wait-close failure"),
    )

    with pytest.raises(RuntimeError, match="transport is not AF_UNIX"):
        await _SERVE_ONE_UNIX_REQUEST(
            _stream_reader(b""),
            writer,
            execution=_job_execution(tmp_path),
        )

    assert writer.closed
    assert writer.waited_closed


@pytest.mark.asyncio
async def test_unix_server_cleans_up_after_serve_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch ordinary serve failure that leaves the private endpoint behind."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    servers: list[_ListeningUnixServer] = []

    async def start_unix_server(
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool = True,
        cleanup_socket: bool = True,
    ) -> _ListeningUnixServer:
        del client_connected_callback
        _assert_caller_owned_listener(
            start_serving=start_serving,
            cleanup_socket=cleanup_socket,
        )
        _assert_descriptor_relative_socket_path(path, name=socket_path.name)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        server = _ListeningUnixServer(
            listener=listener,
            serve_error=RuntimeError("synthetic serve failure"),
        )
        servers.append(server)
        return server

    monkeypatch.setattr(asyncio, "start_unix_server", start_unix_server)

    with pytest.raises(RuntimeError, match="synthetic serve failure"):
        await _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )

    assert len(servers) == 1
    assert servers[0].entered
    assert servers[0].closed
    assert servers[0].waited_closed
    assert not socket_path.exists()


@pytest.mark.asyncio
async def test_unix_server_preserves_replacement_inode_during_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Never unlink a pathname that no longer names the bound socket inode."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"

    async def start_unix_server(
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool = True,
        cleanup_socket: bool = True,
    ) -> _ReplacingUnixServer:
        del client_connected_callback
        _assert_caller_owned_listener(
            start_serving=start_serving,
            cleanup_socket=cleanup_socket,
        )
        _assert_descriptor_relative_socket_path(path, name=socket_path.name)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        return _ReplacingUnixServer(path=socket_path, listener=listener)

    monkeypatch.setattr(asyncio, "start_unix_server", start_unix_server)

    with pytest.raises(RuntimeError, match="socket endpoint identity changed"):
        await _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )

    assert socket_path.read_bytes() == b"attacker replacement"


@pytest.mark.asyncio
async def test_unix_server_never_chmods_or_unlinks_a_replacement_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a post-validation symlink without following or deleting it."""
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    target = tmp_path / "replacement-target"
    _ = target.write_bytes(b"protected")
    target.chmod(_REPLACEMENT_TARGET_MODE)
    server = _FakeUnixServer(serve_error=RuntimeError("must not serve"))

    async def start_unix_server(
        client_connected_callback: object,
        *,
        path: str,
        start_serving: bool = True,
        cleanup_socket: bool = True,
    ) -> _FakeUnixServer:
        del client_connected_callback
        _assert_caller_owned_listener(
            start_serving=start_serving,
            cleanup_socket=cleanup_socket,
        )
        _assert_descriptor_relative_socket_path(path, name=socket_path.name)
        socket_path.symlink_to(target)
        return server

    monkeypatch.setattr(asyncio, "start_unix_server", start_unix_server)

    with pytest.raises(RuntimeError):
        await _SERVE_UNIX_SOCKET(
            socket_path,
            root=tmp_path,
            max_bytes=1_048_576,
            settings=PdfProcessorSettings(),
        )

    assert stat.S_IMODE(target.stat().st_mode) == _REPLACEMENT_TARGET_MODE
    assert socket_path.is_symlink()


def test_main_selects_the_unix_socket_server_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a CLI socket option that falls through to stdin framing."""
    root = tmp_path / "worker"
    root.mkdir(mode=0o700)
    socket_parent = tmp_path / "socket-parent"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "worker.sock"
    _apply_worker_environment(monkeypatch, root)

    def reject_supervisor_limit(
        _resource: int,
        _limits: tuple[int, int],
    ) -> None:
        message = "persistent Unix supervisor received per-job limits"
        raise AssertionError(message)

    def record_umask(_mask: int) -> int:
        return 0o022

    monkeypatch.setattr(resource, "setrlimit", reject_supervisor_limit)
    monkeypatch.setattr(os, "umask", record_umask)
    calls: list[tuple[Path, Path, int, PdfProcessorSettings, object]] = []

    async def record_server(
        path: Path,
        *,
        root: Path,
        max_bytes: int,
        settings: PdfProcessorSettings,
        job_options: object | None = None,
    ) -> None:
        if job_options is None:
            message = "Unix worker job options were not configured"
            raise AssertionError(message)
        calls.append((path, root, max_bytes, settings, job_options))

    monkeypatch.setattr(worker_main_module, "_serve_unix_socket", record_server)

    assert worker_main_module.main(["--unix-socket", str(socket_path)]) == 0
    assert len(calls) == 1
    assert calls[0][0] == socket_path
    assert calls[0][1] == root
    assert calls[0][2] == _EXPECTED_FILE_LIMIT
    options = cast("_JobLaunchOptionsView", calls[0][4])
    assert options.worker_argv == (
        sys.executable,
        "-m",
        "nplg_mcp.pdf_worker_main",
    )
    assert options.timeout_seconds == _EXPECTED_JOB_TIMEOUT_SECONDS


def test_module_entry_point_emits_a_sanitized_frame_and_exits_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a `python -m` entry point that bypasses the framed main contract."""
    root = tmp_path / "worker"
    root.mkdir(mode=0o700)
    _ = ContentAddressedStore(root / "cache")
    _apply_worker_environment(monkeypatch, root)
    _disable_process_mutations(monkeypatch)
    output = _bind_standard_streams(
        monkeypatch,
        encode_frame(_inspect_command(), maximum=MAX_COMMAND_FRAME_BYTES),
    )
    monkeypatch.setattr(sys, "argv", ["pdf_worker_main"])
    module_name = "nplg_mcp.pdf_worker_main"
    imported_module = sys.modules.pop(module_name)
    try:
        with pytest.raises(SystemExit) as raised:
            _ = cast(
                "object",
                runpy.run_module(module_name, run_name="__main__", alter_sys=True),
            )
    finally:
        sys.modules[module_name] = imported_module

    assert raised.value.code == 0
    frame = output.getvalue()
    size = int.from_bytes(frame[:_FRAME_PREFIX_BYTES], "big")
    assert len(frame) == _FRAME_PREFIX_BYTES + size
    assert isinstance(parse_result_frame(frame[_FRAME_PREFIX_BYTES:]), PdfFailure)
