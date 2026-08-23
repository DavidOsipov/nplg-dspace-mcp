# Copyright (c) 2026 David Osipov
"""Candidate-bound one-request developer diagnostic for the NPLG origin."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import math
import os
import stat
import subprocess
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, NoReturn, Protocol, cast

import httpx
from pydantic import Field, StringConstraints, model_validator

from nplg_mcp.contracts import ContractText, StrictModel
from nplg_mcp.errors import AppError
from nplg_mcp.http_types import HttpResponseProtocol
from nplg_mcp.network import (
    BoundNetworkObservation,
    ObservedBoundHTTPTransport,
    create_observed_bound_http_transport,
)
from nplg_mcp.parsers import parse_search_results
from nplg_mcp.security import (
    NPLG_ORIGIN,
    OutboundPurpose,
    build_outbound_headers,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

PROBE_ID: Literal["nplg.simple-search.bound-origin.v1"] = (
    "nplg.simple-search.bound-origin.v1"
)
GATE_VERSION: Literal["live.nplg-bound-endpoint.v2"] = "live.nplg-bound-endpoint.v2"
_CANARY_PATH = "/simple-search"
_CANARY_URL = f"{NPLG_ORIGIN}{_CANARY_PATH}"
_MAX_BODY_BYTES = 1_048_576
_MAX_TITLE_CODE_POINTS = 512
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_MAX_CANARY_SECONDS = 60.0
_HTTP_OK = 200

GitObjectId = Annotated[
    str, StringConstraints(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
BoundedBlocker = Annotated[
    ContractText, StringConstraints(min_length=1, max_length=256)
]


class _CanaryResponse(HttpResponseProtocol, Protocol):
    @property
    def url(self) -> httpx.URL:
        """Return the final response URL."""
        ...


class CanaryClient(Protocol):
    """Injected no-redirect streaming client for the fixed probe."""

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = False,
        timeout: float,
    ) -> AbstractAsyncContextManager[_CanaryResponse]:
        """Open one bounded response stream."""
        ...


@dataclass(frozen=True, slots=True)
class CandidateIdentity:
    """Exact clean candidate commit/tree observed before network authority."""

    commit: str
    tree: str


CandidateIdentitySource = Callable[[Path], CandidateIdentity]
WallClock = Callable[[], datetime]


class RecordWriter(Protocol):
    """Injected exclusive result writer."""

    def __call__(
        self,
        record: NplgLiveCanaryRecord,
        *,
        result_path: Path,
        repository_root: Path,
    ) -> None:
        """Write one validated record exclusively."""
        ...


def _git_output(repository_root: Path, arguments: tuple[str, ...]) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed Git executable and argv
        ("/usr/bin/git", "-c", "credential.helper=", *arguments),
        cwd=repository_root,
        check=False,
        capture_output=True,
        timeout=5.0,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/dev/null",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
        },
    )
    if completed.returncode != 0 or completed.stderr:
        _exit("candidate Git identity is unavailable")
    try:
        return completed.stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        message = "candidate Git identity is malformed"
        raise ValueError(message) from exc


def current_candidate_identity(repository_root: Path) -> CandidateIdentity:
    """Read one clean immutable Git commit/tree through a closed command set."""
    repository = repository_root.resolve(strict=True)
    dirty = _git_output(
        repository,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
    )
    if dirty:
        _exit("candidate worktree is not clean")
    commit = _git_output(repository, ("rev-parse", "--verify", "HEAD")).strip()
    tree = _git_output(repository, ("rev-parse", "--verify", "HEAD^{tree}")).strip()
    return CandidateIdentity(commit=commit, tree=tree)


def validate_candidate_binding(
    *,
    candidate_commit: str,
    candidate_tree: str,
    repository_root: Path,
    identity_source: CandidateIdentitySource = current_candidate_identity,
) -> None:
    """Reject caller candidate values that differ from the clean Git subject."""
    identity = identity_source(repository_root)
    if (
        candidate_commit != identity.commit
        or candidate_tree != identity.tree
        or candidate_commit == candidate_tree
    ):
        _exit("candidate commit/tree do not match the immutable Git subject")


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class CanaryNetworkProof(StrictModel):
    """Ephemeral network facts required before a success record can exist."""

    canonical_hostname: Literal["dspace.nplg.gov.ge"]
    host_header: Literal["dspace.nplg.gov.ge"]
    tls_sni_hostname: Literal["dspace.nplg.gov.ge"]
    certificate_hostname: Literal["dspace.nplg.gov.ge"]
    validated_addresses: tuple[str, ...]
    selected_address: str
    actual_peer: str
    resolver_path: Literal["bound-backend"]
    proxy_used: Literal[False]
    ttl_proven: Literal[True]
    request_count: Literal[1]

    @model_validator(mode="after")
    def _complete_bound_observation(self) -> CanaryNetworkProof:
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for raw_address in self.validated_addresses:
            if type(raw_address) is not str or "%" in raw_address:
                message = "network observation contains an invalid address"
                raise ValueError(message)
            try:
                parsed = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                message = "network observation contains an invalid address"
                raise ValueError(message) from exc
            if raw_address != str(parsed) or not parsed.is_global:
                message = "network observation contains a noncanonical address"
                raise ValueError(message)
            parsed_addresses.append(parsed)
        if (
            not self.validated_addresses
            or self.selected_address not in self.validated_addresses
            or self.actual_peer != self.selected_address
            or len(set(parsed_addresses)) != len(parsed_addresses)
        ):
            message = "network observation is incomplete or inconsistent"
            raise ValueError(message)
        return self


def network_observation_digest(proof: CanaryNetworkProof) -> str:
    """Digest complete ephemeral proof without persisting its IP set."""
    payload = proof.model_dump_json(exclude_none=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def canary_network_proof(observation: BoundNetworkObservation) -> CanaryNetworkProof:
    """Convert only backend-derived immutable facts into the public proof model."""
    if type(observation) is not BoundNetworkObservation:
        message = "network observation authority returned an invalid value"
        raise TypeError(message)
    values: dict[str, object] = {
        "canonical_hostname": observation.canonical_hostname,
        "host_header": observation.host_header,
        "tls_sni_hostname": observation.tls_sni_hostname,
        "certificate_hostname": observation.certificate_hostname,
        "validated_addresses": tuple(
            str(address) for address in observation.validated_addresses
        ),
        "selected_address": str(observation.selected_address),
        "actual_peer": str(observation.actual_peer),
        "resolver_path": "bound-backend",
        "proxy_used": False,
        "ttl_proven": True,
        "request_count": observation.request_count,
    }
    return CanaryNetworkProof.model_validate(values)


def command_policy_digest() -> str:
    """Bind the fixed one-request/no-proxy/no-redirect command policy."""
    document: dict[str, object] = {
        "request": {
            "headers_policy": "canary-closed-v1",
            "method": "GET",
            "origin": NPLG_ORIGIN,
            "parameters": [
                ["query", "ივერია"],
                ["rpp", "1"],
                ["start", "0"],
            ],
            "path": _CANARY_PATH,
        },
        "response_oracle": {
            "accepted_charsets": ["utf-8", "utf8"],
            "accepted_content_encodings": ["", "identity"],
            "body_bytes": {"maximum": _MAX_BODY_BYTES, "minimum": 1},
            "final_origin": NPLG_ORIGIN,
            "final_path": _CANARY_PATH,
            "handle": "nonempty-canonical",
            "media_type": "text/html",
            "minimum_total": 1,
            "parser": "parse_search_results",
            "result_count": 1,
            "status": _HTTP_OK,
            "title_code_points": {
                "maximum": _MAX_TITLE_CODE_POINTS,
                "minimum": 1,
            },
        },
        "transport": {
            "follow_redirects": False,
            "proxy": False,
            "request_count": 1,
            "timeout_seconds": 15.0,
        },
    }
    payload = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class NplgLiveCanaryRecord(StrictModel):
    """Strict candidate-bound result shape for the protected live oracle."""

    schema_version: Literal[1]
    gate_version: Literal["live.nplg-bound-endpoint.v2"]
    candidate_commit: GitObjectId
    candidate_tree: GitObjectId
    endpoint_origin_digest: Sha256Digest
    network_observation_digest: Sha256Digest
    command_policy_digest: Sha256Digest
    probe_id: Literal["nplg.simple-search.bound-origin.v1"]
    started_at: datetime
    completed_at: datetime
    request_count: Literal[1]
    success_count: Literal[0, 1]
    failure_count: Literal[0, 1]
    duration_seconds: float = Field(ge=0.0, le=60.0)
    outcome: Literal["success", "blocked", "failure"]
    blocker: BoundedBlocker | None
    record_digest: Sha256Digest

    @model_validator(mode="after")
    def _consistent_evidence(self) -> NplgLiveCanaryRecord:
        for observed in (self.started_at, self.completed_at):
            if observed.tzinfo is None or observed.utcoffset() != UTC.utcoffset(
                observed
            ):
                message = "canary timestamps must be aware UTC values"
                raise ValueError(message)
        if self.completed_at < self.started_at:
            message = "canary completion precedes its start"
            raise ValueError(message)
        if self.success_count + self.failure_count != self.request_count:
            message = "canary outcome counters are inconsistent"
            raise ValueError(message)
        if self.outcome == "success":
            valid_outcome = (
                self.success_count == 1
                and self.failure_count == 0
                and self.blocker is None
            )
        elif self.outcome == "blocked":
            valid_outcome = (
                self.success_count == 0
                and self.failure_count == 1
                and self.blocker is not None
            )
        else:
            valid_outcome = (
                self.success_count == 0
                and self.failure_count == 1
                and self.blocker is None
            )
        if not valid_outcome:
            message = "canary outcome does not match its counters"
            raise ValueError(message)
        return self


def canonical_record_digest(record: NplgLiveCanaryRecord) -> str:
    """Return a deterministic digest over every record field except itself."""
    payload = cast(
        "dict[str, object]",
        record.model_dump(mode="json", exclude={"record_digest"}),
    )
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_record_digest(record: NplgLiveCanaryRecord) -> None:
    """Reject a record whose digest does not bind all of its fields."""
    if record.record_digest != canonical_record_digest(record):
        message = "canary record digest mismatch"
        raise ValueError(message)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        _ = path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validated_output_parent(
    *,
    result_path: Path,
    repository_root: Path,
) -> Path:
    repository = repository_root.resolve(strict=True)
    supplied = result_path.parent
    if supplied.is_symlink():
        message = "canary result parent must not be a symlink"
        raise ValueError(message)
    parent = supplied.resolve(strict=True)
    if _is_relative_to(parent, repository):
        message = "canary result must use an external parent"
        raise ValueError(message)
    metadata = parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        message = "canary result parent is not a directory"
        raise ValueError(message)
    if stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE:
        message = "canary result parent must have mode 0700"
        raise ValueError(message)
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        message = "canary result parent has the wrong owner"
        raise ValueError(message)
    if result_path.name in {"", ".", ".."}:
        message = "canary result filename is invalid"
        raise ValueError(message)
    return parent


def _write_all(file_fd: int, payload: bytes) -> None:
    written = 0
    while written < len(payload):
        count = os.write(file_fd, payload[written:])
        if count <= 0:
            message = "canary result write did not progress"
            raise OSError(message)
        written += count


def _optional_os_flag(name: str) -> int:
    value = cast("object", getattr(os, name, 0))
    if type(value) is not int:
        message = "operating-system file flag is invalid"
        raise RuntimeError(message)
    return value


def _write_payload_exclusive(*, parent: Path, name: str, payload: bytes) -> None:
    directory_flags = os.O_RDONLY | _optional_os_flag("O_DIRECTORY")
    directory_flags |= _optional_os_flag("O_NOFOLLOW")
    directory_fd = os.open(parent, directory_flags)
    file_fd: int | None = None
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= _optional_os_flag("O_NOFOLLOW")
        file_fd = os.open(
            name,
            flags,
            _PRIVATE_FILE_MODE,
            dir_fd=directory_fd,
        )
        created = True
        os.fchmod(file_fd, _PRIVATE_FILE_MODE)
        _write_all(file_fd, payload)
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        os.fsync(directory_fd)
    except BaseException:
        if file_fd is not None:
            os.close(file_fd)
        if created:
            with suppress(FileNotFoundError):
                os.unlink(name, dir_fd=directory_fd)
        raise
    finally:
        os.close(directory_fd)


def write_record_exclusive(
    record: NplgLiveCanaryRecord,
    *,
    result_path: Path,
    repository_root: Path,
) -> None:
    """Write one new mode-0600 record below an external mode-0700 parent."""
    validate_record_digest(record)
    parent = _validated_output_parent(
        result_path=result_path,
        repository_root=repository_root,
    )
    payload = record.model_dump_json().encode("utf-8") + b"\n"
    _write_payload_exclusive(parent=parent, name=result_path.name, payload=payload)


class CanaryProbeError(ValueError):
    """Sanitized deterministic rejection of a live-oracle response."""

    def __init__(self, reason: str) -> None:
        """Keep the public diagnostic bounded and free of response data."""
        super().__init__(f"canary response rejected: {reason}")


def _reject_probe(reason: str) -> NoReturn:
    raise CanaryProbeError(reason)


def _reject_probe_from(reason: str, cause: BaseException) -> NoReturn:
    raise CanaryProbeError(reason) from cause


def _validate_response_metadata(response: _CanaryResponse, request_url: str) -> None:
    if response.status_code != _HTTP_OK:
        _reject_probe("status is not 200")
    if str(response.url) != request_url:
        _reject_probe("final URL changed")
    raw_content_type = response.headers.get("content-type", "")
    content_type, *parameters = raw_content_type.split(";")
    if content_type.strip().lower() != "text/html":
        _reject_probe("media type is not HTML")
    charsets = [
        value.split("=", 1)[1].strip().strip('"').lower()
        for value in parameters
        if value.strip().lower().startswith("charset=")
    ]
    if len(charsets) != 1 or charsets[0] not in {"utf-8", "utf8"}:
        _reject_probe("charset is not explicitly UTF-8 compatible")
    if response.headers.get("content-encoding", "identity").lower() not in {
        "",
        "identity",
    }:
        _reject_probe("content encoding is not identity")


async def _read_bounded_body(response: _CanaryResponse) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(chunk) > _MAX_BODY_BYTES - len(body):
            _reject_probe("body exceeds the byte limit")
        body.extend(chunk)
    if not body:
        _reject_probe("body is empty")
    return bytes(body)


def _validate_parsed_body(body: bytes, *, request_url: str) -> None:
    try:
        text = body.decode("utf-8")
        page = parse_search_results(text, source_url=request_url, page_size=1)
    except (UnicodeDecodeError, AppError) as exc:
        _reject_probe_from("HTML did not parse", exc)
    if page.total < 1 or len(page.items) != 1:
        _reject_probe("result cardinality is invalid")
    item = page.items[0]
    if (
        not item.handle
        or not item.title.strip()
        or len(item.title) > _MAX_TITLE_CODE_POINTS
    ):
        _reject_probe("item identity or title is invalid")


async def execute_canary_probe(
    client: CanaryClient,
    *,
    timeout_seconds: float,
) -> None:
    """Execute exactly one fixed, bounded, no-redirect NPLG search request."""
    if (
        type(timeout_seconds) is not float
        or not math.isfinite(timeout_seconds)
        or not 0.0 < timeout_seconds <= _MAX_CANARY_SECONDS
    ):
        _reject_probe("timeout is invalid")
    request_url = str(
        httpx.URL(
            _CANARY_URL,
            params=(("query", "ივერია"), ("rpp", "1"), ("start", "0")),
        )
    )
    headers = build_outbound_headers(OutboundPurpose.CANARY)
    try:
        async with (
            asyncio.timeout(timeout_seconds),
            client.stream(
                "GET",
                request_url,
                headers=headers,
                follow_redirects=False,
                timeout=timeout_seconds,
            ) as response,
        ):
            _validate_response_metadata(response, request_url)
            body = await _read_bounded_body(response)
    except (TimeoutError, httpx.RequestError) as exc:
        _reject_probe_from("request failed or timed out", exc)
    _validate_parsed_body(body, request_url=request_url)


def _exit(message: str) -> NoReturn:
    raise SystemExit(message)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--result-json", type=Path, required=True)
    _ = parser.add_argument("--candidate-commit", required=True)
    _ = parser.add_argument("--candidate-tree", required=True)
    _ = parser.add_argument("--endpoint-url", required=True)
    return parser


class ObservedTransportFactory(Protocol):
    """Typed construction seam for the trusted instrumented transport bundle."""

    def __call__(
        self,
        *,
        limits: httpx.Limits,
    ) -> ObservedBoundHTTPTransport:
        """Construct one transport and its backend-owned proof capability."""
        ...


def main(
    *,
    wall_clock: WallClock = _utc_now,
    identity_source: CandidateIdentitySource = current_candidate_identity,
    writer: RecordWriter = write_record_exclusive,
    transport_factory: ObservedTransportFactory = create_observed_bound_http_transport,
) -> int:
    """Fail closed unless the developer diagnostic has explicit live authority."""
    arguments = _parser().parse_args()
    endpoint_url = cast("str", arguments.endpoint_url)
    result_json = cast("Path", arguments.result_json)
    candidate_commit = cast("str", arguments.candidate_commit)
    candidate_tree = cast("str", arguments.candidate_tree)
    if os.environ.get("NPLG_ALLOW_LIVE_TESTS") != "1":
        _exit("live authority is absent")
    if endpoint_url != NPLG_ORIGIN:
        _exit("endpoint URL is not the canonical NPLG origin")
    if not result_json.is_absolute():
        _exit("result path must be absolute")

    repository_root = Path.cwd().resolve(strict=True)
    validate_candidate_binding(
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
        repository_root=repository_root,
        identity_source=identity_source,
    )
    _ = _validated_output_parent(
        result_path=result_json,
        repository_root=repository_root,
    )
    started_wall = wall_clock()
    started = asyncio.new_event_loop()
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)
    observed = transport_factory(limits=limits)
    try:

        async def run() -> None:
            async with httpx.AsyncClient(
                transport=observed.transport,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                await execute_canary_probe(client, timeout_seconds=15.0)

        started.run_until_complete(run())
    finally:
        started.close()
    completed_wall = wall_clock()
    network_proof = canary_network_proof(observed.authority.finalize())
    duration = (completed_wall - started_wall).total_seconds()
    if duration < 0.0 or duration > _MAX_CANARY_SECONDS:
        _exit("canary clock interval is invalid")
    origin_digest = hashlib.sha256(NPLG_ORIGIN.encode("ascii")).hexdigest()
    provisional = NplgLiveCanaryRecord(
        schema_version=1,
        gate_version=GATE_VERSION,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
        endpoint_origin_digest=origin_digest,
        network_observation_digest=network_observation_digest(network_proof),
        command_policy_digest=command_policy_digest(),
        probe_id=PROBE_ID,
        started_at=started_wall,
        completed_at=completed_wall,
        request_count=1,
        success_count=1,
        failure_count=0,
        duration_seconds=duration,
        outcome="success",
        blocker=None,
        record_digest="0" * 64,
    )
    record_values = cast(
        "dict[str, object]",
        provisional.model_dump(mode="python"),
    )
    record_values["record_digest"] = canonical_record_digest(provisional)
    record = NplgLiveCanaryRecord.model_validate(record_values)
    try:
        writer(
            record,
            result_path=result_json,
            repository_root=repository_root,
        )
    except (OSError, ValueError):
        message = "canary result write failed"
        raise SystemExit(message) from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
