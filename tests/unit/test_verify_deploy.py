# Copyright (c) 2026 David Osipov
"""Unit tests for deployment verification helpers."""

from __future__ import annotations

import io
import json
import runpy
import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast, override

import pytest

import scripts.verify_deploy as verify_deploy_module
from scripts.verify_deploy import (
    ALPIC_METADATA_TOOLS,
    CACHE_WRITING_TOOLS,
    EXPECTED_TOOLS,
    MAX_RESPONSE_BYTES,
    PRIVATE_FULL_TOOLS,
    PROTOCOL,
    CliDependencies,
    DeploymentClient,
    DeploymentProfile,
    JsonObject,
    JsonValue,
    McpClient,
    VerificationError,
    verify,
    verify_probes,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from http.client import HTTPConnection

ARGUMENT_ERROR_EXIT = 2
CANCELLED_EXIT = 130
AUTH_VALUE = "reviewed-auth-value"
SECOND_AUTH_VALUE = "reviewed-api-value"
TIMEOUT_DETAIL = "private timeout detail"
BODY_DETAIL = '"private":"body"'
OUTPUT_FAILURE = "output unavailable"
BODY_MARKER = "reviewed-response-body-marker"
OVERSIZED_OUTPUT_CHARS = 200_000
HIGH_FINITE_TIMEOUT = 10_000.0


@dataclass(slots=True)
class FakeClient:
    """Return a complete, controllable deployment contract."""

    read_only: bool | None
    tool_names: frozenset[str] = ALPIC_METADATA_TOOLS
    get_paths: list[str] = field(default_factory=list[str])

    def get(self, path: str) -> JsonObject:
        """Return the expected health object."""
        self.get_paths.append(path)
        return {"status": "ok"} if path == "/healthz" else {"status": "ready"}

    def rpc(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        name: str | None = None,
    ) -> tuple[JsonObject, dict[str, str]]:
        """Return one deterministic MCP result."""
        del params, name
        headers: dict[str, str] = {}
        if method == "server/discover":
            return {
                "supportedVersions": [PROTOCOL],
                "cacheScope": "private",
            }, headers
        if method == "tools/list":
            tools: list[JsonValue] = [
                {
                    "name": tool_name,
                    "annotations": {
                        "readOnlyHint": (
                            tool_name not in CACHE_WRITING_TOOLS
                            if self.read_only is None
                            else self.read_only
                        ),
                        "destructiveHint": False,
                    },
                }
                for tool_name in sorted(self.tool_names)
            ]
            return {"tools": tools, "cacheScope": "private"}, headers
        if method == "resources/list":
            return {"resources": [{"uri": "nplg://about"}]}, headers
        if method == "resources/read":
            return {"contents": [{"uri": "nplg://about"}]}, headers
        raise AssertionError(method)


@dataclass(frozen=True, slots=True)
class RecordedRequest:
    """One request passed to the HTTP adapter."""

    method: str
    target: str
    body: bytes | None
    headers: dict[str, str]


def _new_request_log() -> list[RecordedRequest]:
    return []


@dataclass(slots=True)
class RecordingResponse:
    """Bounded response fake with explicit lifecycle recording."""

    body: bytes
    status: int = 200
    headers: tuple[tuple[str, str], ...] = ()
    read_error: BaseException | None = None
    closed: bool = False
    read_limit: int | None = None

    def read(self, amount: int | None = None) -> bytes:
        """Return at most the requested bytes or raise the configured error."""
        self.read_limit = amount
        if self.read_error is not None:
            raise self.read_error
        return self.body if amount is None else self.body[:amount]

    def getheaders(self) -> list[tuple[str, str]]:
        """Return configured response headers."""
        return list(self.headers)

    def close(self) -> None:
        """Record response closure."""
        self.closed = True


@dataclass(slots=True)
class RecordingConnection:
    """In-memory replacement for one ``HTTPSConnection``."""

    response: RecordingResponse
    requests: list[RecordedRequest] = field(default_factory=_new_request_log)
    closed: bool = False

    def request(
        self,
        method: str,
        target: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        """Record one outbound request without opening a socket."""
        self.requests.append(RecordedRequest(method, target, body, dict(headers or {})))

    def getresponse(self) -> RecordingResponse:
        """Return the configured response."""
        return self.response

    def close(self) -> None:
        """Record connection closure."""
        self.closed = True


@dataclass(slots=True)
class RecordingConnectionFactory:
    """Capture the exact origin selected by the default HTTP adapter."""

    response: RecordingResponse
    hostname: str | None = None
    port: int | None = None
    timeout: float | None = None
    connection: RecordingConnection = field(init=False)

    def __post_init__(self) -> None:
        """Create the single connection returned by this factory."""
        self.connection = RecordingConnection(self.response)

    def __call__(
        self,
        hostname: str,
        port: int | None = None,
        *,
        timeout: float,
    ) -> HTTPConnection:
        """Return the recording connection under the stdlib client type."""
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        return cast("HTTPConnection", self.connection)


def _new_client_call_log() -> list[tuple[str, str | None, float, str | None]]:
    return []


@dataclass(slots=True)
class StaticClientFactory:
    """Return one injected deployment client and record CLI configuration."""

    client: DeploymentClient
    calls: list[tuple[str, str | None, float, str | None]] = field(
        default_factory=_new_client_call_log
    )

    def __call__(
        self,
        *,
        base_url: str,
        bearer_token: str | None,
        timeout: float,
        api_key: str | None,
    ) -> DeploymentClient:
        """Record exact CLI configuration and return the fake client."""
        self.calls.append((base_url, bearer_token, timeout, api_key))
        return self.client


class FailingWriter(io.StringIO):
    """Output sink that rejects every write."""

    @override
    def write(self, value: str) -> int:
        """Raise a deterministic output failure."""
        del value
        raise OSError(OUTPUT_FAILURE)


def _install_https(
    monkeypatch: pytest.MonkeyPatch,
    response: RecordingResponse,
) -> RecordingConnectionFactory:
    factory = RecordingConnectionFactory(response)
    monkeypatch.setattr(verify_deploy_module, "HTTPSConnection", factory)
    return factory


def _complete_rpc_response(*, request_id: int = 1) -> bytes:
    payload: JsonObject = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"resultType": "complete", "cacheScope": "private"},
    }
    return json.dumps(payload).encode()


def _success(
    _client: DeploymentClient,
    *,
    profile: DeploymentProfile,
) -> JsonObject:
    del profile
    return {"status": "pass", "tool_count": len(EXPECTED_TOOLS)}


def _reviewed_failure(
    _client: DeploymentClient,
    *,
    profile: DeploymentProfile,
) -> JsonObject:
    del profile
    msg = "reviewed failure"
    raise VerificationError(msg)


def _cancel(
    _client: DeploymentClient,
    *,
    profile: DeploymentProfile,
) -> JsonObject:
    del profile
    raise KeyboardInterrupt


def _oversized_success(
    _client: DeploymentClient,
    *,
    profile: DeploymentProfile,
) -> JsonObject:
    del profile
    return {"status": "pass", "detail": "x" * OVERSIZED_OUTPUT_CHARS}


def _health_only(
    client: DeploymentClient,
    *,
    profile: DeploymentProfile,
) -> JsonObject:
    del profile
    return client.get("/healthz")


def _real_client_factory(
    *,
    base_url: str,
    bearer_token: str | None,
    timeout: float,
    api_key: str | None,
) -> DeploymentClient:
    return McpClient(
        base_url=base_url,
        bearer_token=bearer_token,
        timeout=timeout,
        api_key=api_key,
    )


def _nested_array_body(depth: int, *, prefix: bytes = b'{"value":') -> bytes:
    return prefix + (b"[" * depth) + b"null" + (b"]" * depth) + b"}"


def test_deployment_verifier_preserves_baseline_result_fields() -> None:
    expected: JsonObject = {
        "status": "pass",
        "protocol": PROTOCOL,
        "profile": "alpic-metadata",
        "tool_count": len(ALPIC_METADATA_TOOLS),
        "probes_checked": False,
        "sessionless": True,
    }
    client = FakeClient(read_only=None)

    assert verify(client) == expected
    assert client.get_paths == []


def test_deployment_verifier_is_profile_aware() -> None:
    client = FakeClient(read_only=None, tool_names=PRIVATE_FULL_TOOLS)

    result = verify(client, profile="private-full")

    assert result["profile"] == "private-full"
    assert result["tool_count"] == len(PRIVATE_FULL_TOOLS)
    assert client.get_paths == []


def test_deployment_verifier_rejects_unknown_profile_before_requests() -> None:
    client = FakeClient(read_only=None)

    with pytest.raises(VerificationError, match="profile is unsupported"):
        _ = verify(
            client,
            profile=cast("DeploymentProfile", "unknown-profile"),
        )

    assert client.get_paths == []


def test_private_probe_verification_is_explicit() -> None:
    client = FakeClient(read_only=None)

    assert verify_probes(client) == {
        "health": {"status": "ok"},
        "ready": {"status": "ready"},
    }
    assert client.get_paths == ["/healthz", "/readyz"]


def test_deployment_verifier_rejects_misclassified_tool_catalog() -> None:
    with pytest.raises(VerificationError, match="annotation mismatch"):
        _ = verify(FakeClient(read_only=False))


@pytest.mark.parametrize(
    "base_url",
    [
        "ftp://mcp.example",
        "http://mcp.example",
        "https://user:password@mcp.example",
        "https://mcp.example/path?secret=value",
        "https://mcp.example/path#fragment",
    ],
)
def test_client_rejects_unsafe_url_policy(base_url: str) -> None:
    with pytest.raises(VerificationError):
        _ = McpClient(base_url)


def test_client_rejects_ambiguous_auth_and_invalid_deadline() -> None:
    with pytest.raises(VerificationError, match="either a bearer token"):
        _ = McpClient(
            "https://mcp.example",
            bearer_token=AUTH_VALUE,
            api_key=SECOND_AUTH_VALUE,
        )
    for timeout in (0.0, -1.0, float("inf"), float("nan")):
        with pytest.raises(VerificationError, match="positive finite"):
            _ = McpClient("https://mcp.example", timeout=timeout)
    assert (
        McpClient("https://mcp.example", timeout=HIGH_FINITE_TIMEOUT).timeout
        == HIGH_FINITE_TIMEOUT
    )


def test_default_adapter_uses_exact_https_host_path_deadline_and_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = RecordingResponse(_complete_rpc_response())
    factory = _install_https(monkeypatch, response)
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid")
    monkeypatch.setenv("API_KEY", "ambient-secret")
    client = McpClient(
        "https://mcp.example:8443/gateway",
        bearer_token=AUTH_VALUE,
        timeout=4.25,
    )

    result, _ = client.rpc("server/discover")

    assert result["cacheScope"] == "private"
    assert (factory.hostname, factory.port, factory.timeout) == (
        "mcp.example",
        8443,
        4.25,
    )
    [request] = factory.connection.requests
    assert request.method == "POST"
    assert request.target == "/gateway/mcp"
    assert request.headers["Origin"] == "https://mcp.example:8443"
    assert request.headers["Authorization"] == f"Bearer {AUTH_VALUE}"
    assert "x-api-key" not in request.headers
    assert "proxy.invalid" not in request.target
    assert "ambient-secret" not in request.headers.values()
    assert response.read_limit == MAX_RESPONSE_BYTES + 1
    assert response.closed
    assert factory.connection.closed


def test_default_adapter_does_not_follow_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = RecordingResponse(
        b'{"redirect":"https://attacker.invalid"}',
        status=302,
        headers=(("Location", "https://attacker.invalid"),),
    )
    factory = _install_https(monkeypatch, response)

    with pytest.raises(VerificationError, match="HTTP 302"):
        _ = McpClient("https://mcp.example").get("/healthz")

    assert len(factory.connection.requests) == 1
    assert response.closed
    assert factory.connection.closed


@pytest.mark.parametrize(
    ("response", "message"),
    [
        pytest.param(
            RecordingResponse(b"{"),
            "malformed JSON",
            id="malformed",
        ),
        pytest.param(
            RecordingResponse(b"x" * (MAX_RESPONSE_BYTES + 2)),
            "size limit",
            id="oversized",
        ),
        pytest.param(
            RecordingResponse(b'{"secret":"body"}', status=503),
            "HTTP 503",
            id="nonzero",
        ),
        pytest.param(
            RecordingResponse(b"", read_error=TimeoutError(TIMEOUT_DETAIL)),
            "request failed",
            id="timeout",
        ),
    ],
)
def test_default_adapter_closes_and_sanitizes_failures(
    monkeypatch: pytest.MonkeyPatch,
    response: RecordingResponse,
    message: str,
) -> None:
    factory = _install_https(monkeypatch, response)

    with pytest.raises(VerificationError, match=message) as captured:
        _ = McpClient(
            "https://mcp.example",
            bearer_token=AUTH_VALUE,
        ).get("/healthz")

    diagnostic = str(captured.value)
    assert AUTH_VALUE not in diagnostic
    assert TIMEOUT_DETAIL not in diagnostic
    assert BODY_DETAIL not in diagnostic
    assert response.closed
    assert factory.connection.closed


def test_default_adapter_closes_on_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = RecordingResponse(b"", read_error=KeyboardInterrupt())
    factory = _install_https(monkeypatch, response)

    with pytest.raises(KeyboardInterrupt):
        _ = McpClient("https://mcp.example").get("/healthz")

    assert response.closed
    assert factory.connection.closed


@pytest.mark.parametrize(
    ("body", "message"),
    [
        pytest.param(
            b'{"jsonrpc":"2.0","id":1,"error":{"message":"secret"}}',
            "JSON-RPC error",
            id="json-rpc-error",
        ),
        pytest.param(
            b'{"jsonrpc":"2.0","id":99,"result":{}}',
            "invalid JSON-RPC envelope",
            id="invalid-envelope",
        ),
    ],
)
def test_rpc_rejects_protocol_failures_without_body_disclosure(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    message: str,
) -> None:
    response = RecordingResponse(body)
    _ = _install_https(monkeypatch, response)

    with pytest.raises(VerificationError, match=message) as captured:
        _ = McpClient("https://mcp.example").rpc("tools/list")

    assert "secret" not in str(captured.value)


@pytest.mark.parametrize(
    "timeout",
    [
        pytest.param("nan", id="nan"),
        pytest.param("inf", id="infinite"),
        pytest.param("0", id="zero"),
        pytest.param("-1", id="negative"),
    ],
)
def test_main_rejects_out_of_policy_timeout_before_client_creation(
    timeout: str,
) -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = StaticClientFactory(FakeClient(read_only=None))
    dependencies = CliDependencies(
        environ={},
        stdout=stdout,
        stderr=stderr,
        client_factory=factory,
        verifier=_success,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example", "--timeout", timeout],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: --timeout must be a positive finite number\n"


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(_nested_array_body(1_500), id="nesting-1500"),
        pytest.param(
            b'{"private":"'
            + BODY_MARKER.encode()
            + b'","value":'
            + (b"9" * 5_000)
            + b"}",
            id="integer-5000-digits",
        ),
    ],
)
def test_main_sanitizes_pathological_json_and_closes_default_adapter(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> None:
    response = RecordingResponse(body)
    connection_factory = _install_https(monkeypatch, response)
    stdout = io.StringIO()
    stderr = io.StringIO()
    dependencies = CliDependencies(
        environ={"API_BEARER_TOKEN": AUTH_VALUE},
        stdout=stdout,
        stderr=stderr,
        client_factory=_real_client_factory,
        verifier=_health_only,
    )

    assert (
        verify_deploy_module.main(
            [
                "--base-url",
                "https://mcp.example",
            ],
            dependencies=dependencies,
        )
        == 1
    )
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: deployment returned malformed JSON\n"
    assert AUTH_VALUE not in stderr.getvalue()
    assert BODY_MARKER not in stderr.getvalue()
    assert response.closed
    assert connection_factory.connection.closed


def test_main_prints_success_json_and_exact_client_configuration() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = StaticClientFactory(FakeClient(read_only=None))
    dependencies = CliDependencies(
        environ={"API_BEARER_TOKEN": "token"},
        stdout=stdout,
        stderr=stderr,
        client_factory=factory,
        verifier=_success,
    )

    assert (
        verify_deploy_module.main(
            [
                "--base-url",
                "https://mcp.example",
                "--timeout",
                "10000",
            ],
            dependencies=dependencies,
        )
        == 0
    )
    assert factory.calls == [
        ("https://mcp.example", "token", HIGH_FINITE_TIMEOUT, None)
    ]
    expected_output = (
        json.dumps(
            _success(factory.client, profile="alpic-metadata"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    assert stdout.getvalue() == expected_output
    assert stderr.getvalue() == ""


def test_main_selects_profile_and_queries_probes_only_on_distinct_private_url() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    client = FakeClient(read_only=None, tool_names=PRIVATE_FULL_TOOLS)
    factory = StaticClientFactory(client)
    observed_profiles: list[DeploymentProfile] = []

    def profile_verifier(
        _client: DeploymentClient,
        *,
        profile: DeploymentProfile,
    ) -> JsonObject:
        observed_profiles.append(profile)
        return {
            "status": "pass",
            "profile": profile,
            "probes_checked": False,
        }

    dependencies = CliDependencies(
        environ={"API_BEARER_TOKEN": "token"},
        stdout=stdout,
        stderr=stderr,
        client_factory=factory,
        verifier=profile_verifier,
    )

    assert (
        verify_deploy_module.main(
            [
                "--base-url",
                "https://mcp.example",
                "--profile",
                "private-full",
                "--probe-base-url",
                "http://127.0.0.1:8000",
            ],
            dependencies=dependencies,
        )
        == 0
    )
    assert observed_profiles == ["private-full"]
    assert factory.calls == [
        ("https://mcp.example", "token", 30.0, None),
        ("http://127.0.0.1:8000", None, 30.0, None),
    ]
    assert client.get_paths == ["/healthz", "/readyz"]
    expected_result: JsonObject = {
        "health": {"status": "ok"},
        "probes_checked": True,
        "profile": "private-full",
        "ready": {"status": "ready"},
        "status": "pass",
    }
    expected_output = (
        json.dumps(
            expected_result,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    assert stdout.getvalue() == expected_output
    assert stderr.getvalue() == ""


@pytest.mark.parametrize(
    ("base_url", "probe_base_url"),
    [
        ("https://mcp.example/", "https://mcp.example"),
        ("https://mcp.example", "https://MCP.EXAMPLE/"),
        ("https://mcp.example", "https://mcp.example:443"),
        ("http://localhost/gateway", "http://LOCALHOST:80"),
    ],
)
def test_main_rejects_public_origin_reuse_for_private_probes(
    base_url: str,
    probe_base_url: str,
) -> None:
    factory = StaticClientFactory(FakeClient(read_only=None))
    stderr = io.StringIO()
    dependencies = CliDependencies(
        environ={},
        stdout=io.StringIO(),
        stderr=stderr,
        client_factory=factory,
        verifier=_success,
    )

    assert (
        verify_deploy_module.main(
            [
                "--base-url",
                base_url,
                "--probe-base-url",
                probe_base_url,
            ],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []
    assert stderr.getvalue() == (
        "FAIL: --probe-base-url must be distinct from --base-url\n"
    )


@pytest.mark.parametrize(
    "probe_base_url",
    [
        "https://private.example",
        "http://10.0.0.1:8000",
        "http://app:8000",
    ],
)
def test_main_restricts_private_probe_target_to_loopback_http(
    probe_base_url: str,
) -> None:
    factory = StaticClientFactory(FakeClient(read_only=None))
    stderr = io.StringIO()
    dependencies = CliDependencies(
        environ={},
        stdout=io.StringIO(),
        stderr=stderr,
        client_factory=factory,
        verifier=_success,
    )

    assert (
        verify_deploy_module.main(
            [
                "--base-url",
                "https://mcp.example",
                "--probe-base-url",
                probe_base_url,
            ],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []
    assert stderr.getvalue() == (
        "FAIL: --probe-base-url must use a loopback HTTP origin\n"
    )


def test_main_rejects_non_string_environment_credential_before_client() -> None:
    factory = StaticClientFactory(FakeClient(read_only=None))
    dependencies = CliDependencies(
        environ=cast("Mapping[str, str]", {"API_BEARER_TOKEN": 7}),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        client_factory=factory,
        verifier=_success,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example"],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []


@pytest.mark.parametrize(
    "credential_arguments",
    [
        ["--token", AUTH_VALUE],
        [f"--token={AUTH_VALUE}"],
        ["--api-key", SECOND_AUTH_VALUE],
        [f"--api-key={SECOND_AUTH_VALUE}"],
    ],
)
def test_main_rejects_credential_argv_without_echoing_values(
    credential_arguments: list[str],
) -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = StaticClientFactory(FakeClient(read_only=None))
    dependencies = CliDependencies(
        environ={},
        stdout=stdout,
        stderr=stderr,
        client_factory=factory,
        verifier=_success,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example", *credential_arguments],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "FAIL: credentials must be supplied through environment variables\n"
    )
    assert AUTH_VALUE not in stderr.getvalue()
    assert SECOND_AUTH_VALUE not in stderr.getvalue()


def test_main_prints_sanitized_failure_with_exit_one() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    dependencies = CliDependencies(
        environ={},
        stdout=stdout,
        stderr=stderr,
        client_factory=StaticClientFactory(FakeClient(read_only=None)),
        verifier=_reviewed_failure,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example"], dependencies=dependencies
        )
        == 1
    )
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: reviewed failure\n"


def test_main_rejects_oversized_canonical_output_without_partial_write() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    dependencies = CliDependencies(
        environ={},
        stdout=stdout,
        stderr=stderr,
        client_factory=StaticClientFactory(FakeClient(read_only=None)),
        verifier=_oversized_success,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example"], dependencies=dependencies
        )
        == 1
    )
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: deployment output exceeded the size limit\n"


def test_main_propagates_argument_and_cancellation_exit_codes() -> None:
    dependencies = CliDependencies(
        environ={},
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        client_factory=StaticClientFactory(FakeClient(read_only=None)),
        verifier=_cancel,
    )

    assert (
        verify_deploy_module.main([], dependencies=dependencies) == ARGUMENT_ERROR_EXIT
    )
    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example"], dependencies=dependencies
        )
        == CANCELLED_EXIT
    )


def test_main_reports_output_failure() -> None:
    stderr = io.StringIO()
    dependencies = CliDependencies(
        environ={},
        stdout=FailingWriter(),
        stderr=stderr,
        client_factory=StaticClientFactory(FakeClient(read_only=None)),
        verifier=_success,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example"], dependencies=dependencies
        )
        == 1
    )
    assert stderr.getvalue() == "FAIL: output write failed\n"


def _rpc_body(result: JsonObject, *, request_id: int = 1) -> bytes:
    payload: JsonObject = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }
    return json.dumps(payload).encode()


def _valid_tool_items() -> list[JsonValue]:
    return [
        {
            "name": tool_name,
            "annotations": {
                "readOnlyHint": tool_name not in CACHE_WRITING_TOOLS,
                "destructiveHint": False,
            },
        }
        for tool_name in sorted(EXPECTED_TOOLS)
    ]


@dataclass(frozen=True, slots=True)
class ContractMutationClient:
    """Return one deliberately malformed public deployment contract."""

    mutation: str

    def get(self, path: str) -> JsonObject:
        """Return health data with an optional reviewed mutation."""
        if path == "/healthz":
            return {"status": "degraded" if self.mutation == "health" else "ok"}
        return {"status": "ready"}

    def _discover(self) -> tuple[JsonObject, dict[str, str]]:
        headers: dict[str, str] = {}
        result: JsonObject = {
            "supportedVersions": (
                ["unsupported"] if self.mutation == "protocol" else [PROTOCOL]
            ),
            "cacheScope": "public" if self.mutation == "cache" else "private",
        }
        if self.mutation == "session":
            headers["mcp-session-id"] = "unexpected-session"
        return result, headers

    def _tools(self) -> tuple[JsonObject, dict[str, str]]:
        tools = _valid_tool_items()
        if self.mutation == "catalog-not-list":
            raw_tools: JsonValue = {}
        else:
            if self.mutation == "catalog-entry":
                tools[0] = None
            elif self.mutation == "catalog-name":
                tools[0] = {"annotations": {}}
            elif self.mutation == "catalog-product":
                _ = tools.pop()
            elif self.mutation == "annotations":
                tools[0] = {"name": min(EXPECTED_TOOLS)}
            raw_tools = tools
        return {"tools": raw_tools, "cacheScope": "private"}, {}

    def _resources(self) -> tuple[JsonObject, dict[str, str]]:
        if self.mutation == "resources-not-list":
            return {"resources": {}}, {}
        uri = "nplg://other" if self.mutation == "about-not-listed" else "nplg://about"
        return {"resources": [{"uri": uri}]}, {}

    def _read_resource(self) -> tuple[JsonObject, dict[str, str]]:
        if self.mutation == "contents-not-list":
            return {"contents": {}}, {}
        if self.mutation == "about-unreadable":
            return {"contents": [None]}, {}
        return {"contents": [{"uri": "nplg://about"}]}, {}

    def rpc(
        self,
        method: str,
        params: JsonObject | None = None,
        *,
        name: str | None = None,
    ) -> tuple[JsonObject, dict[str, str]]:
        """Return the selected malformed discovery, tool, or resource value."""
        del params, name
        if method == "server/discover":
            return self._discover()
        if method == "tools/list":
            return self._tools()
        if method == "resources/list":
            return self._resources()
        if method == "resources/read":
            return self._read_resource()
        raise AssertionError(method)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("protocol", "requested protocol"),
        ("catalog-not-list", "not a list"),
        ("catalog-entry", "invalid entry"),
        ("catalog-name", "unnamed entry"),
        ("catalog-product", "catalog mismatch"),
        ("annotations", "annotation mismatch"),
        ("cache", "private cache scope"),
        ("session", "unexpectedly created a session"),
        ("resources-not-list", "expected entry"),
        ("about-not-listed", "resource was not listed"),
        ("contents-not-list", "expected entry"),
        ("about-unreadable", "could not be read"),
    ],
)
def test_deployment_verifier_fails_closed_for_contract_mutations(
    mutation: str,
    message: str,
) -> None:
    with pytest.raises(VerificationError, match=message):
        _ = verify(ContractMutationClient(mutation))


def test_private_probe_verifier_fails_closed() -> None:
    with pytest.raises(VerificationError, match="Health or readiness"):
        _ = verify_probes(ContractMutationClient("health"))


def test_default_adapter_accepts_finite_json_float_and_rejects_nonfinite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finite = RecordingResponse(b'{"latency":1.5}')
    _ = _install_https(monkeypatch, finite)
    assert McpClient("https://mcp.example").get("/healthz") == {"latency": 1.5}

    nonfinite = RecordingResponse(b'{"latency":NaN}')
    _ = _install_https(monkeypatch, nonfinite)
    with pytest.raises(VerificationError, match="invalid JSON value"):
        _ = McpClient("https://mcp.example").get("/healthz")


def test_default_adapter_requires_json_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = RecordingResponse(b"[]")
    _ = _install_https(monkeypatch, response)

    with pytest.raises(VerificationError, match="invalid object"):
        _ = McpClient("https://mcp.example").get("/healthz")


def test_default_adapter_supports_local_http_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = RecordingResponse(b'{"status":"ok"}')
    factory = RecordingConnectionFactory(response)
    monkeypatch.setattr(verify_deploy_module, "HTTPConnection", factory)

    result = McpClient("http://localhost:8080/gateway").get("/healthz")

    assert result == {"status": "ok"}
    assert (factory.hostname, factory.port) == ("localhost", 8080)
    [request] = factory.connection.requests
    assert request.target == "/gateway/healthz"


@pytest.mark.parametrize(
    ("name", "expected_form"),
    [("nplg://about", "plain"), ("unsafe\nname", "encoded")],
    ids=("printable", "encoded"),
)
def test_rpc_sanitizes_optional_name_header(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    expected_form: str,
) -> None:
    response = RecordingResponse(_complete_rpc_response())
    factory = _install_https(monkeypatch, response)
    client = McpClient(
        "https://mcp.example",
        api_key=SECOND_AUTH_VALUE,
    )

    _ = client.rpc("resources/read", {"uri": "nplg://about"}, name=name)

    [request] = factory.connection.requests
    assert request.headers["x-api-key"] == SECOND_AUTH_VALUE
    assert "Authorization" not in request.headers
    header = request.headers["Mcp-Name"]
    if expected_form == "encoded":
        assert header.startswith("=?base64?")
    else:
        assert header == name


def test_rpc_rejects_http_and_modern_result_shape_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonzero = RecordingResponse(b"{}", status=503)
    _ = _install_https(monkeypatch, nonzero)
    with pytest.raises(VerificationError, match="HTTP 503"):
        _ = McpClient("https://mcp.example").rpc("tools/list")

    incomplete = RecordingResponse(
        _rpc_body({"resultType": "pending"}),
    )
    _ = _install_https(monkeypatch, incomplete)
    with pytest.raises(VerificationError, match="modern MCP result shape"):
        _ = McpClient("https://mcp.example").rpc("tools/list")


def test_call_tool_returns_structured_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = RecordingResponse(
        _rpc_body(
            {
                "resultType": "complete",
                "structuredContent": {"status": "ok"},
            }
        )
    )
    _ = _install_https(monkeypatch, response)

    result = McpClient("https://mcp.example").call_tool("inspect_pdf", {})

    assert result == {"status": "ok"}


@pytest.mark.parametrize(
    ("result", "message"),
    [
        ({"resultType": "complete", "isError": True}, "failed"),
        ({"resultType": "complete"}, "no structuredContent"),
    ],
    ids=("tool-error", "missing-structured-content"),
)
def test_call_tool_rejects_failed_or_unstructured_results(
    monkeypatch: pytest.MonkeyPatch,
    result: JsonObject,
    message: str,
) -> None:
    response = RecordingResponse(_rpc_body(result))
    _ = _install_https(monkeypatch, response)

    with pytest.raises(VerificationError, match=message):
        _ = McpClient("https://mcp.example").call_tool("inspect_pdf", {})


def _invalid_json_output(
    _client: DeploymentClient,
    *,
    profile: DeploymentProfile,
) -> JsonObject:
    del profile
    return {"status": float("nan")}


def test_main_rejects_invalid_verifier_json_without_partial_output() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    dependencies = CliDependencies(
        environ={},
        stdout=stdout,
        stderr=stderr,
        client_factory=StaticClientFactory(FakeClient(read_only=None)),
        verifier=_invalid_json_output,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example"],
            dependencies=dependencies,
        )
        == 1
    )
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: deployment returned invalid JSON\n"


def test_main_preserves_exit_code_when_failure_output_is_unavailable() -> None:
    dependencies = CliDependencies(
        environ={},
        stdout=io.StringIO(),
        stderr=FailingWriter(),
        client_factory=StaticClientFactory(FakeClient(read_only=None)),
        verifier=_reviewed_failure,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example"],
            dependencies=dependencies,
        )
        == 1
    )


def test_main_uses_environment_credentials_without_echoing_them() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = StaticClientFactory(FakeClient(read_only=None))
    dependencies = CliDependencies(
        environ={"API_BEARER_TOKEN": AUTH_VALUE},
        stdout=stdout,
        stderr=stderr,
        client_factory=factory,
        verifier=_success,
    )

    assert (
        verify_deploy_module.main(
            ["--base-url", "https://mcp.example"],
            dependencies=dependencies,
        )
        == 0
    )
    assert factory.calls == [("https://mcp.example", AUTH_VALUE, 30.0, None)]
    assert AUTH_VALUE not in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_client_fails_closed_if_its_validated_url_is_later_corrupted() -> None:
    client = McpClient("https://mcp.example")
    client.base_url = "https://"

    with pytest.raises(VerificationError, match="host is unavailable"):
        _ = client.get("/healthz")


def test_real_script_entry_rejects_invalid_url_before_network(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["verify_deploy.py", "--base-url", "ftp://invalid.example"],
    )

    with pytest.raises(SystemExit) as captured:
        _ = cast(
            "object",
            runpy.run_path("scripts/verify_deploy.py", run_name="__main__"),
        )

    assert captured.value.code == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "FAIL: --base-url must be an HTTP(S) origin or base path\n"
