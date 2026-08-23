# Copyright (c) 2026 David Osipov
# pyright: reportPrivateUsage=false
"""Deterministic tests for the candidate-bound Task 17 live oracle."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import runpy
import subprocess
import time
import warnings
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast, override

import httpcore
import httpx
import pytest
from pydantic import ValidationError

from nplg_mcp.network import (
    BoundNetworkObservation,
    CanonicalHostname,
    ObservedBoundHTTPTransport,
    ResolvedEndpoint,
    SocketOption,
    create_observed_bound_http_transport,
    create_resolved_endpoint,
)
from nplg_mcp.security import NPLG_ORIGIN
from scripts import run_live_nplg_canary as canary_module
from scripts.run_live_nplg_canary import (
    CanaryNetworkProof,
    CandidateIdentity,
    NplgLiveCanaryRecord,
    canary_network_proof,
    canonical_record_digest,
    command_policy_digest,
    current_candidate_identity,
    execute_canary_probe,
    main,
    network_observation_digest,
    validate_candidate_binding,
    validate_record_digest,
    write_record_exclusive,
)

if TYPE_CHECKING:
    import ssl
    from collections.abc import Iterable
    from pathlib import Path

_DIGEST = "a" * 64
_COMMIT = "b" * 40
_TREE = "c" * 40
_ORIGIN = "https://dspace.nplg.gov.ge/simple-search"
_PRIVATE_FILE_MODE = 0o600
_FORGED_BOOLEAN: object = True
_REQUEST_ERROR_DETAIL = "sensitive upstream detail"
_UNEXPECTED_TRANSPORT = "transport must not be constructed"
_ONE_RESULT = b"""<!doctype html><html><body>
<div id="aspect_discovery_SimpleSearch_div_search-results">
<p>Results 1-1 of 42</p><table class="search-results"><thead><tr>
<th>Issue Date</th><th>Title</th><th>Author</th></tr></thead><tbody><tr>
<td>1898</td><td><a href="/handle/1234/499564">Iveria 161</a></td><td>-</td>
</tr></tbody></table></div></body></html>"""


class _ObservedCanaryStream(httpcore.AsyncNetworkStream):
    def __init__(self) -> None:
        super().__init__()
        self._response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            + (
                f"Content-Length: {len(_ONE_RESULT)}\r\nConnection: close\r\n\r\n"
            ).encode()
            + _ONE_RESULT
        )

    @override
    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del max_bytes, timeout
        response, self._response = self._response, b""
        return response

    @override
    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del buffer, timeout

    @override
    async def aclose(self) -> None:
        return

    @override
    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del ssl_context, server_hostname, timeout
        return self

    @override
    def get_extra_info(self, info: str) -> object | None:
        return ("1.1.1.1", 443) if info == "server_addr" else None


class _ObservedCanaryBackend(httpcore.AsyncNetworkBackend):
    @override
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        assert (host, port) == ("1.1.1.1", 443)
        return _ObservedCanaryStream()

    @override
    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        message = "Unix socket must not be used"
        raise AssertionError(message)

    @override
    async def sleep(self, seconds: float) -> None:
        del seconds


def _record(**updates: object) -> NplgLiveCanaryRecord:
    started = datetime(2026, 8, 22, tzinfo=UTC)
    values: dict[str, object] = {
        "schema_version": 1,
        "gate_version": "live.nplg-bound-endpoint.v2",
        "candidate_commit": _COMMIT,
        "candidate_tree": _TREE,
        "endpoint_origin_digest": _DIGEST,
        "network_observation_digest": "d" * 64,
        "command_policy_digest": "e" * 64,
        "probe_id": "nplg.simple-search.bound-origin.v1",
        "started_at": started,
        "completed_at": started + timedelta(seconds=1),
        "request_count": 1,
        "success_count": 1,
        "failure_count": 0,
        "duration_seconds": 1.0,
        "outcome": "success",
        "blocker": None,
        "record_digest": "0" * 64,
    }
    values.update(updates)
    provisional = NplgLiveCanaryRecord.model_validate(values)
    values["record_digest"] = canonical_record_digest(provisional)
    return NplgLiveCanaryRecord.model_validate(values)


def test_record_rejects_unaware_time_and_inconsistent_outcome_counters() -> None:
    """Mutation caught: accepting unbound timing or contradictory outcome counts."""
    unaware = datetime(2026, 8, 22, tzinfo=UTC).replace(tzinfo=None)
    with pytest.raises(ValidationError):
        _ = _record(started_at=unaware, success_count=0)


def test_candidate_binding_rejects_wrong_commit_or_tree_before_oracle(
    tmp_path: Path,
) -> None:
    """Mutation caught: trusting caller candidate identity before network effects."""

    def identity(_root: Path) -> CandidateIdentity:
        return CandidateIdentity(commit=_COMMIT, tree=_TREE)

    validate_candidate_binding(
        candidate_commit=_COMMIT,
        candidate_tree=_TREE,
        repository_root=tmp_path,
        identity_source=identity,
    )
    with pytest.raises(SystemExit, match="immutable Git subject"):
        validate_candidate_binding(
            candidate_commit="d" * 40,
            candidate_tree=_TREE,
            repository_root=tmp_path,
            identity_source=identity,
        )
    with pytest.raises(SystemExit, match="immutable Git subject"):
        validate_candidate_binding(
            candidate_commit=_COMMIT,
            candidate_tree="e" * 40,
            repository_root=tmp_path,
            identity_source=identity,
        )


def test_network_observation_requires_selected_peer_and_complete_tls_identity() -> None:
    """Mutation caught: success digest from incomplete or mismatched network proof."""
    proof = CanaryNetworkProof(
        canonical_hostname="dspace.nplg.gov.ge",
        host_header="dspace.nplg.gov.ge",
        tls_sni_hostname="dspace.nplg.gov.ge",
        certificate_hostname="dspace.nplg.gov.ge",
        validated_addresses=("1.1.1.1",),
        selected_address="1.1.1.1",
        actual_peer="1.1.1.1",
        resolver_path="bound-backend",
        proxy_used=False,
        ttl_proven=True,
        request_count=1,
    )
    assert network_observation_digest(proof) != "0" * 64
    values = cast("dict[str, object]", proof.model_dump(mode="python"))
    values["actual_peer"] = "8.8.8.8"
    with pytest.raises(ValidationError, match="network observation"):
        _ = CanaryNetworkProof.model_validate(values)

    for invalid_address in ("127.0.0.1", "01.01.01.01", "2001:DB8::1", "1.1.1.1%eth0"):
        invalid_values = cast("dict[str, object]", proof.model_dump(mode="python"))
        invalid_values["validated_addresses"] = (invalid_address,)
        invalid_values["selected_address"] = invalid_address
        invalid_values["actual_peer"] = invalid_address
        with pytest.raises(ValidationError, match="network observation"):
            _ = CanaryNetworkProof.model_validate(invalid_values)


def test_record_digest_detects_candidate_or_outcome_tampering() -> None:
    """Mutation caught: digest omitting candidate identity or oracle outcome."""
    record = _record()
    validate_record_digest(record)

    tampered_values = cast(
        "dict[str, object]",
        record.model_dump(mode="python"),
    )
    tampered_values["candidate_tree"] = "f" * 40
    tampered = NplgLiveCanaryRecord.model_validate(tampered_values)
    with pytest.raises(ValueError, match="digest"):
        validate_record_digest(tampered)


def test_command_policy_digest_binds_fixed_parameters_and_response_oracle() -> None:
    """Mutation caught: omitting request parameters or semantic oracle policy."""
    assert command_policy_digest() == (
        "487d9eed85624c955cb5dc75c2edef28e27e9c27f81fdc6ddbb5ab402c0b91a6"
    )


def test_exclusive_writer_creates_only_a_new_mode_0600_external_result(
    tmp_path: Path,
) -> None:
    """Mutation caught: permissive, contained, or overwrite-prone evidence writes."""
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    result = external / "result.json"

    write_record_exclusive(_record(), result_path=result, repository_root=repository)

    assert result.stat().st_mode & 0o777 == _PRIVATE_FILE_MODE
    persisted = cast(
        "dict[str, object]",
        json.loads(result.read_text(encoding="utf-8")),
    )
    assert persisted["record_digest"] == _record().record_digest
    with pytest.raises(FileExistsError):
        write_record_exclusive(
            _record(), result_path=result, repository_root=repository
        )


def test_exclusive_writer_rejects_symlink_containment_and_nonprivate_parent(
    tmp_path: Path,
) -> None:
    """Mutation caught: following a symlink or writing under an unsafe parent."""
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    contained = repository / "result.json"
    with pytest.raises(ValueError, match="external"):
        write_record_exclusive(
            _record(), result_path=contained, repository_root=repository
        )

    external = tmp_path / "external"
    external.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="0700"):
        write_record_exclusive(
            _record(), result_path=external / "result.json", repository_root=repository
        )

    external.chmod(0o700)
    target = tmp_path / "target"
    _ = target.write_text("existing", encoding="utf-8")
    symlink = external / "result.json"
    symlink.symlink_to(target)
    with pytest.raises(FileExistsError):
        write_record_exclusive(
            _record(), result_path=symlink, repository_root=repository
        )
    assert target.read_text(encoding="utf-8") == "existing"


def test_exclusive_writer_handles_partial_writes_and_cleans_up_fsync_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mutation caught: one-shot write or retained partial evidence after fsync."""
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    result = external / "result.json"
    original_write = os.write

    def partial_write(file_fd: int, payload: bytes) -> int:
        return original_write(file_fd, payload[:7])

    monkeypatch.setattr(os, "write", partial_write)
    write_record_exclusive(_record(), result_path=result, repository_root=repository)
    persisted = NplgLiveCanaryRecord.model_validate_json(result.read_bytes())
    validate_record_digest(persisted)

    result.unlink()

    def failed_fsync(_file_fd: int) -> None:
        message = "task17-fsync-secret"
        raise OSError(message)

    monkeypatch.setattr(os, "fsync", failed_fsync)
    with pytest.raises(OSError, match="task17-fsync-secret") as captured:
        write_record_exclusive(
            _record(), result_path=result, repository_root=repository
        )
    assert "task17-fsync-secret" in str(captured.value)
    assert not result.exists()


@pytest.mark.asyncio
async def test_probe_issues_exactly_one_fixed_request_without_credentials() -> None:
    """Catch extra, reordered, credentialed, or differently parameterized probes."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            content=_ONE_RESULT,
            headers={"content-type": "text/html; charset=utf-8"},
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), trust_env=False
    ) as client:
        await execute_canary_probe(client, timeout_seconds=5.0)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "GET"
    assert str(request.url) == (
        _ORIGIN
        + "?query=%E1%83%98%E1%83%95%E1%83%94%E1%83%A0%E1%83%98%E1%83%90&rpp=1&start=0"
    )
    assert "authorization" not in request.headers
    assert "cookie" not in request.headers


@pytest.mark.parametrize(
    ("status", "body", "content_type"),
    [
        (302, _ONE_RESULT, "text/html; charset=utf-8"),
        (200, b"", "text/html; charset=utf-8"),
        (200, b"<html><table class='search-results'></table></html>", "text/html"),
        (200, _ONE_RESULT, "application/json"),
        (200, _ONE_RESULT, "text/html; charset=iso-8859-1"),
    ],
)
@pytest.mark.asyncio
async def test_probe_rejects_redirect_empty_unparsed_or_wrong_media_responses(
    status: int,
    body: bytes,
    content_type: str,
) -> None:
    """Mutation caught: treating mere HTTP success as live-oracle success."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, content=body, headers={"content-type": content_type}
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), trust_env=False
    ) as client:
        with pytest.raises(ValueError, match="canary"):
            await execute_canary_probe(client, timeout_seconds=5.0)


@pytest.mark.asyncio
async def test_probe_propagates_cancellation_without_recordable_outcome() -> None:
    """Mutation caught: swallowing cancellation and continuing toward success."""

    def cancelled(_request: httpx.Request) -> httpx.Response:
        raise asyncio.CancelledError

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(cancelled), trust_env=False
    ) as client:
        with pytest.raises(asyncio.CancelledError):
            await execute_canary_probe(client, timeout_seconds=5.0)


def test_record_json_never_contains_query_url_ip_body_headers_or_credentials() -> None:
    """Catch sensitive or high-cardinality diagnostics leaking into evidence."""
    serialized = _record().model_dump_json().lower()

    for forbidden in (
        "ივერია",
        "/simple-search",
        "dspace.nplg.gov.ge",
        "1.1.1.1",
        "authorization",
        "cookie",
        "task17-secret-canary",
    ):
        assert forbidden not in serialized


def test_main_derives_success_proof_from_observed_transport_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mutation caught: accepting an unrelated post-request synthetic proof."""
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    result_path = external / "result.json"
    records: list[NplgLiveCanaryRecord] = []
    times = iter(
        (
            datetime(2026, 8, 23, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 23, 10, 0, 1, tzinfo=UTC),
        )
    )

    async def resolve(host: str) -> ResolvedEndpoint:
        return create_resolved_endpoint(
            hostname=host,
            port=443,
            addresses=("1.1.1.1",),
            ttl_seconds=30.0,
            clock=time.monotonic,
        )

    def transport_factory(*, limits: httpx.Limits) -> ObservedBoundHTTPTransport:
        return create_observed_bound_http_transport(
            limits=limits,
            delegate=_ObservedCanaryBackend(),
            resolver=resolve,
        )

    def identity(_root: Path) -> CandidateIdentity:
        return CandidateIdentity(commit=_COMMIT, tree=_TREE)

    def writer(
        record: NplgLiveCanaryRecord,
        *,
        result_path: Path,
        repository_root: Path,
    ) -> None:
        del result_path, repository_root
        records.append(record)

    monkeypatch.setenv("NPLG_ALLOW_LIVE_TESTS", "1")
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_live_nplg_canary.py",
            "--result-json",
            str(result_path),
            "--candidate-commit",
            _COMMIT,
            "--candidate-tree",
            _TREE,
            "--endpoint-url",
            NPLG_ORIGIN,
        ],
    )

    assert (
        main(
            wall_clock=lambda: next(times),
            identity_source=identity,
            writer=writer,
            transport_factory=transport_factory,
        )
        == 0
    )
    assert len(records) == 1
    record = records[0]
    assert record.outcome == "success"
    assert record.network_observation_digest not in {"0" * 64, "d" * 64}
    validate_record_digest(record)

    sensitive_marker = "task17-writer-sensitive-marker"
    failed_times = iter(
        (
            datetime(2026, 8, 23, 10, 1, tzinfo=UTC),
            datetime(2026, 8, 23, 10, 1, 1, tzinfo=UTC),
        )
    )

    def failed_writer(
        record: NplgLiveCanaryRecord,
        *,
        result_path: Path,
        repository_root: Path,
    ) -> None:
        del record, result_path, repository_root
        raise OSError(sensitive_marker)

    with pytest.raises(SystemExit) as captured:
        _ = main(
            wall_clock=lambda: next(failed_times),
            identity_source=identity,
            writer=failed_writer,
            transport_factory=transport_factory,
        )
    assert str(captured.value) == "canary result write failed"
    assert sensitive_marker not in str(captured.value)

    rollback_times = iter(
        (
            datetime(2026, 8, 23, 10, 2, 1, tzinfo=UTC),
            datetime(2026, 8, 23, 10, 2, tzinfo=UTC),
        )
    )
    with pytest.raises(SystemExit, match="clock interval"):
        _ = main(
            wall_clock=lambda: next(rollback_times),
            identity_source=identity,
            writer=writer,
            transport_factory=transport_factory,
        )
    assert len(records) == 1


def test_git_identity_fails_closed_for_command_stderr_nonascii_and_dirty_tree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mutation caught: trusting ambiguous, malformed, or dirty Git identity."""

    class _Completed:
        def __init__(
            self,
            *,
            returncode: int = 0,
            stdout: bytes = b"",
            stderr: bytes = b"",
        ) -> None:
            super().__init__()
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def ambiguous(*_args: object, **_kwargs: object) -> _Completed:
        return _Completed(stderr=b"ambiguous")

    monkeypatch.setattr(
        subprocess,
        "run",
        ambiguous,
    )
    with pytest.raises(SystemExit, match="unavailable"):
        _ = canary_module._git_output(tmp_path, ("status",))  # noqa: SLF001

    def non_ascii(*_args: object, **_kwargs: object) -> _Completed:
        return _Completed(stdout=b"\xff")

    monkeypatch.setattr(
        subprocess,
        "run",
        non_ascii,
    )
    with pytest.raises(ValueError, match="malformed"):
        _ = canary_module._git_output(tmp_path, ("status",))  # noqa: SLF001

    responses = iter(
        (
            _Completed(stdout=b"dirty\x00"),
            _Completed(stdout=_COMMIT.encode()),
            _Completed(stdout=_TREE.encode()),
        )
    )

    def dirty_response(*_args: object, **_kwargs: object) -> _Completed:
        return next(responses)

    monkeypatch.setattr(
        subprocess,
        "run",
        dirty_response,
    )
    with pytest.raises(SystemExit, match="not clean"):
        _ = current_candidate_identity(tmp_path)

    clean_responses = iter(
        (
            _Completed(),
            _Completed(stdout=(_COMMIT + "\n").encode()),
            _Completed(stdout=(_TREE + "\n").encode()),
        )
    )

    def clean_response(*_args: object, **_kwargs: object) -> _Completed:
        return next(clean_responses)

    monkeypatch.setattr(
        subprocess,
        "run",
        clean_response,
    )
    assert current_candidate_identity(tmp_path) == CandidateIdentity(
        commit=_COMMIT,
        tree=_TREE,
    )
    assert canary_module._utc_now().tzinfo is UTC  # noqa: SLF001


def test_backend_proof_conversion_rejects_forgery_and_preserves_bound_values() -> None:
    """Mutation caught: converting arbitrary post-request data into trusted proof."""
    with pytest.raises(TypeError, match="authority"):
        _ = canary_network_proof(cast("BoundNetworkObservation", object()))

    observation = BoundNetworkObservation(
        canonical_hostname=CanonicalHostname("dspace.nplg.gov.ge"),
        host_header=CanonicalHostname("dspace.nplg.gov.ge"),
        tls_sni_hostname=CanonicalHostname("dspace.nplg.gov.ge"),
        certificate_hostname=CanonicalHostname("dspace.nplg.gov.ge"),
        validated_addresses=(ipaddress.ip_address("1.1.1.1"),),
        selected_address=ipaddress.ip_address("1.1.1.1"),
        actual_peer=ipaddress.ip_address("1.1.1.1"),
        request_count=1,
    )
    proof = canary_network_proof(observation)
    assert proof.validated_addresses == ("1.1.1.1",)
    assert proof.selected_address == proof.actual_peer == "1.1.1.1"


@pytest.mark.parametrize(
    "updates",
    [
        {"completed_at": datetime(2026, 8, 21, tzinfo=UTC)},
        {"success_count": 0, "failure_count": 0},
        {"outcome": "blocked", "success_count": 0, "failure_count": 1, "blocker": None},
        {
            "outcome": "failure",
            "success_count": 0,
            "failure_count": 1,
            "blocker": "unexpected",
        },
    ],
)
def test_record_rejects_clock_counter_and_all_outcome_contradictions(
    updates: dict[str, object],
) -> None:
    """Mutation caught: signing a contradictory blocked/failure/timing record."""
    with pytest.raises(ValidationError, match=r"completion|counter|outcome"):
        _ = _record(**updates)

    blocked = _record(
        outcome="blocked",
        success_count=0,
        failure_count=1,
        blocker="protected authority absent",
    )
    failed = _record(
        outcome="failure",
        success_count=0,
        failure_count=1,
        blocker=None,
    )
    assert blocked.blocker == "protected authority absent"
    assert failed.blocker is None


def test_output_parent_and_low_level_writer_reject_every_unsafe_branch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mutation caught: unsafe parent ownership/shape/flags or zero-progress writes."""
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    target_parent = tmp_path / "target-parent"
    target_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(target_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="parent must not be a symlink"):
        write_record_exclusive(
            _record(),
            result_path=linked_parent / "result.json",
            repository_root=repository,
        )

    parent_file = tmp_path / "parent-file"
    _ = parent_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValueError, match="not a directory"):
        _ = canary_module._validated_output_parent(  # noqa: SLF001
            result_path=parent_file / "..",
            repository_root=repository,
        )

    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    actual_uid = external.stat().st_uid
    monkeypatch.setattr(os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(ValueError, match="wrong owner"):
        _ = canary_module._validated_output_parent(  # noqa: SLF001
            result_path=external / "result.json",
            repository_root=repository,
        )
    monkeypatch.undo()

    with pytest.raises(ValueError, match="filename"):
        _ = canary_module._validated_output_parent(  # noqa: SLF001
            result_path=external / "..",
            repository_root=repository,
        )

    monkeypatch.setattr(os, "O_DIRECTORY", cast("int", "invalid"))
    with pytest.raises(RuntimeError, match="file flag"):
        _ = canary_module._optional_os_flag("O_DIRECTORY")  # noqa: SLF001
    monkeypatch.undo()

    def zero_write(_fd: int, _payload: bytes) -> int:
        return 0

    monkeypatch.setattr(os, "write", zero_write)
    result = external / "result.json"
    with pytest.raises(OSError, match="did not progress"):
        write_record_exclusive(
            _record(),
            result_path=result,
            repository_root=repository,
        )
    assert not result.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (b"x" * 1_048_577, {"content-type": "text/html; charset=utf-8"}),
        (b"\xff", {"content-type": "text/html; charset=utf-8"}),
        (
            (
                b"<html><p>Results 0-0 of 0</p>"
                b"<table class='search-results'><tbody></tbody></table></html>"
            ),
            {"content-type": "text/html; charset=utf-8"},
        ),
    ],
    ids=("oversized", "invalid-utf8", "empty-page"),
)
async def test_probe_rejects_changed_url_encoding_size_decode_and_cardinality(
    body: bytes,
    headers: dict[str, str],
) -> None:
    """Mutation caught: treating malformed metadata/body as oracle success."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers=headers, request=request)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), trust_env=False
    ) as client:
        with pytest.raises(ValueError, match="canary response rejected"):
            await execute_canary_probe(client, timeout_seconds=5.0)


@pytest.mark.parametrize(
    ("url", "content_encoding"),
    [
        (f"{NPLG_ORIGIN}/changed", "identity"),
        (_ORIGIN, "gzip"),
    ],
)
def test_probe_metadata_rejects_changed_url_and_content_encoding(
    url: str,
    content_encoding: str,
) -> None:
    """Mutation caught: accepting redirect or transformed response metadata."""
    response = httpx.Response(
        200,
        headers={
            "content-type": "text/html; charset=utf-8",
            "content-encoding": content_encoding,
        },
        request=httpx.Request("GET", url),
    )
    with pytest.raises(ValueError, match="canary response rejected"):
        canary_module._validate_response_metadata(response, _ORIGIN)  # noqa: SLF001


@pytest.mark.asyncio
async def test_probe_rejects_invalid_item_identity_timeout_and_request_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: accepting invalid parsed item, timeout, or transport error."""

    class _Item:
        handle = ""
        title = "valid"

    class _Page:
        total = 1
        items = (_Item(),)

    def invalid_page(_text: str, *, source_url: str, page_size: int) -> object:
        del source_url, page_size
        return _Page()

    monkeypatch.setattr(canary_module, "parse_search_results", invalid_page)

    def valid_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_ONE_RESULT,
            headers={"content-type": "text/html; charset=utf-8"},
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(valid_handler), trust_env=False
    ) as client:
        with pytest.raises(ValueError, match="item identity"):
            await execute_canary_probe(client, timeout_seconds=5.0)

        for timeout in (
            cast("float", _FORGED_BOOLEAN),
            0.0,
            float("nan"),
            61.0,
        ):
            with pytest.raises(ValueError, match="timeout"):
                await execute_canary_probe(client, timeout_seconds=timeout)

    def request_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(_REQUEST_ERROR_DETAIL, request=request)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(request_error), trust_env=False
    ) as client:
        with pytest.raises(ValueError, match="failed or timed out") as captured:
            await execute_canary_probe(client, timeout_seconds=5.0)
    assert "sensitive upstream detail" not in str(captured.value)


def test_parsed_probe_rejects_zero_result_cardinality(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation caught: treating a parsed empty page as canary success."""

    class _EmptyPage:
        total = 0
        items: tuple[object, ...] = ()

    def empty_page(_text: str, *, source_url: str, page_size: int) -> object:
        del source_url, page_size
        return _EmptyPage()

    monkeypatch.setattr(canary_module, "parse_search_results", empty_page)
    with pytest.raises(ValueError, match="cardinality"):
        canary_module._validate_parsed_body(  # noqa: SLF001
            _ONE_RESULT,
            request_url=_ORIGIN,
        )


def test_main_rejects_authority_origin_and_relative_output_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mutation caught: constructing a network client before closed CLI preflight."""
    calls = 0

    def forbidden_factory(*, limits: httpx.Limits) -> ObservedBoundHTTPTransport:
        nonlocal calls
        del limits
        calls += 1
        raise AssertionError(_UNEXPECTED_TRANSPORT)

    def arguments(endpoint: str, result: str) -> list[str]:
        return [
            "run_live_nplg_canary.py",
            "--result-json",
            result,
            "--candidate-commit",
            _COMMIT,
            "--candidate-tree",
            _TREE,
            "--endpoint-url",
            endpoint,
        ]

    monkeypatch.delenv("NPLG_ALLOW_LIVE_TESTS", raising=False)
    monkeypatch.setattr("sys.argv", arguments(NPLG_ORIGIN, str(tmp_path / "r.json")))
    with pytest.raises(SystemExit, match="authority"):
        _ = main(transport_factory=forbidden_factory)

    monkeypatch.setenv("NPLG_ALLOW_LIVE_TESTS", "1")
    monkeypatch.setattr(
        "sys.argv", arguments("https://example.test", str(tmp_path / "r.json"))
    )
    with pytest.raises(SystemExit, match="endpoint URL"):
        _ = main(transport_factory=forbidden_factory)

    monkeypatch.setattr("sys.argv", arguments(NPLG_ORIGIN, "relative.json"))
    with pytest.raises(SystemExit, match="absolute"):
        _ = main(transport_factory=forbidden_factory)
    assert calls == 0


def test_module_entrypoint_fails_closed_without_live_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mutation caught: script entrypoint bypassing main's authority check."""
    monkeypatch.delenv("NPLG_ALLOW_LIVE_TESTS", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_live_nplg_canary.py",
            "--result-json",
            str(tmp_path / "result.json"),
            "--candidate-commit",
            _COMMIT,
            "--candidate-tree",
            _TREE,
            "--endpoint-url",
            NPLG_ORIGIN,
        ],
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        with pytest.raises(SystemExit, match="authority"):
            _ = cast(
                "dict[str, object]",
                runpy.run_path(
                    "scripts/run_live_nplg_canary.py",
                    run_name="__main__",
                ),
            )
