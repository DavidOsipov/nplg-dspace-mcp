# Copyright (c) 2026 David Osipov
"""Fail-closed tests for the official MCP conformance runner."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, cast

import pytest
from mcp_types import MISSING_REQUIRED_CLIENT_CAPABILITY
from starlette.testclient import TestClient

import scripts.run_mcp_conformance as runner
from scripts.run_mcp_conformance import (
    ConformanceRunError,
    RunEvidence,
    RunnerOptions,
    build_harness_argv,
    main,
    validate_harness_results,
    validate_options,
)
from tests.conformance.official_fixture_server import (
    app as official_fixture_app,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_runner_uses_exact_locked_offline_argv(tmp_path: Path) -> None:
    """Invoke only the reviewed local package through offline npm execution."""
    result_dir = tmp_path / "results"

    assert build_harness_argv(
        url="http://127.0.0.1:43210/mcp",
        result_dir=result_dir,
        scenario="server-stateless",
        spec_version="2026-07-28",
    ) == (
        "npm",
        "exec",
        "--offline",
        "--package=@modelcontextprotocol/conformance@0.2.0-alpha.11",
        "--",
        "conformance",
        "server",
        "--url",
        "http://127.0.0.1:43210/mcp",
        "--scenario",
        "server-stateless",
        "--spec-version",
        "2026-07-28",
        "--output-dir",
        str(result_dir),
    )


def test_official_conformance_dependency_is_exact_and_reviewed() -> None:
    """Bind package, lock integrity, runner identity, and reviewed commit."""
    package = _require_object(
        cast(
            "object",
            json.loads((runner.REPOSITORY_ROOT / "package.json").read_text()),
        )
    )
    dependencies = _require_object(package["devDependencies"])
    assert dependencies[runner.CONFORMANCE_PACKAGE] == runner.CONFORMANCE_VERSION

    lock = _require_object(
        cast(
            "object",
            json.loads((runner.REPOSITORY_ROOT / "package-lock.json").read_text()),
        )
    )
    packages = _require_object(lock["packages"])
    locked = _require_object(packages[f"node_modules/{runner.CONFORMANCE_PACKAGE}"])
    assert locked["version"] == runner.CONFORMANCE_VERSION
    assert locked["integrity"] == runner.CONFORMANCE_INTEGRITY
    assert locked["dev"] is True
    assert runner.CONFORMANCE_COMMIT == "c321dd32035556e6769d3724a8ee97d87c3faaac"


@pytest.mark.parametrize(
    "options",
    [
        RunnerOptions(bind_host="0.0.0.0"),  # noqa: S104 - rejection mutant
        RunnerOptions(fixture_module="nplg_mcp.__main__:app"),
        RunnerOptions(profile="metadata"),
        RunnerOptions(bearer_token="rejection-sentinel"),  # noqa: S106
        RunnerOptions(forwarding_proxy="http://127.0.0.1:9999"),
        RunnerOptions(scenario="tools-list"),
        RunnerOptions(spec_version="2025-11-25"),
        RunnerOptions(requirements="2026-07-28"),
        RunnerOptions(suite="active"),
    ],
)
def test_runner_refuses_non_fixture_or_non_loopback_inputs(
    options: RunnerOptions,
) -> None:
    """Keep the developmental proof isolated from production and broad suites."""
    with pytest.raises(ValueError, match="official conformance fixture"):
        validate_options(options)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "malformed-json",
        "stale",
        "failed-check",
        "harness-error",
        "unexpected-directory",
        "malformed-check",
    ],
)
def test_runner_rejects_missing_malformed_stale_or_failed_checks(
    tmp_path: Path,
    fault: str,
) -> None:
    """Refuse incomplete, stale, ambiguous, or unsuccessful harness evidence."""
    started_at_ns = tmp_path.stat().st_mtime_ns
    scenario_dir = tmp_path / "server-server-stateless-2026-08-21T00-00-00-000Z"
    scenario_dir.mkdir()
    checks_path = scenario_dir / "checks.json"
    checks: list[dict[str, object]] = [
        {
            "id": "sep-2575-example",
            "name": "Example",
            "description": "wire assertion",
            "status": "SUCCESS",
            "timestamp": "2026-08-21T00:00:00.000Z",
            "details": {"wire": {"status": 200}},
        }
    ]
    _ = checks_path.write_text(json.dumps(checks), encoding="utf-8")

    if fault == "missing":
        checks_path.unlink()
    elif fault == "malformed-json":
        _ = checks_path.write_text("{", encoding="utf-8")
    elif fault == "stale":
        os.utime(checks_path, ns=(started_at_ns - 1, started_at_ns - 1))
    elif fault == "failed-check":
        checks[0]["status"] = "FAILURE"
        _ = checks_path.write_text(json.dumps(checks), encoding="utf-8")
    elif fault == "harness-error":
        checks[0]["errorMessage"] = "harness internal error"
        _ = checks_path.write_text(json.dumps(checks), encoding="utf-8")
    elif fault == "unexpected-directory":
        (tmp_path / "server-tools-list-unexpected").mkdir()
    elif fault == "malformed-check":
        checks = [{"id": "sep-2575-example", "status": "SUCCESS"}]
        _ = checks_path.write_text(json.dumps(checks), encoding="utf-8")

    with pytest.raises(ConformanceRunError):
        _ = validate_harness_results(tmp_path, started_at_ns=started_at_ns)


def test_runner_preserves_successful_wire_check_records(tmp_path: Path) -> None:
    """Return the complete immutable check record rather than a pass count only."""
    scenario_dir = tmp_path / "server-server-stateless-2026-08-21T00-00-00-000Z"
    scenario_dir.mkdir()
    checks_path = scenario_dir / "checks.json"
    started_at_ns = tmp_path.stat().st_mtime_ns
    check: dict[str, object] = {
        "id": "sep-2575-example",
        "name": "Example",
        "description": "wire assertion",
        "status": "SUCCESS",
        "timestamp": "2026-08-21T00:00:00.000Z",
        "details": {"wire": {"status": 200}},
    }
    checks: list[dict[str, object]] = [check]
    _ = checks_path.write_text(json.dumps(checks), encoding="utf-8")

    assert validate_harness_results(tmp_path, started_at_ns=started_at_ns) == (check,)


def test_runner_fails_closed_on_listener_exit_timeout_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bound orchestration and always reap the private fixture child."""
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        port = cast("tuple[str, int]", occupied.getsockname())[1]
        with pytest.raises(ConformanceRunError, match="listener"):
            runner.ensure_listener_available("127.0.0.1", port)

    @dataclass
    class FakeProcess:
        exit_code: int | None = None
        terminated: bool = False
        killed: bool = False

        def poll(self) -> int | None:
            return self.exit_code

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float | None = None) -> int:
            _ = timeout
            return 0

    with pytest.raises(ConformanceRunError, match="exited before readiness"):
        runner.wait_for_fixture(
            FakeProcess(exit_code=9),
            "127.0.0.1",
            41000,
            timeout=0.01,
        )

    fixture = FakeProcess()

    def choose_port() -> int:
        return 41000

    def listener_available(_host: str, _port: int) -> None:
        return None

    def fixture_ready(*_args: object, **_kwargs: object) -> None:
        return None

    def open_fixture(*_args: object, **_kwargs: object) -> FakeProcess:
        return fixture

    monkeypatch.setattr(runner, "choose_loopback_port", choose_port)
    monkeypatch.setattr(runner, "ensure_listener_available", listener_available)
    monkeypatch.setattr(runner, "wait_for_fixture", fixture_ready)
    monkeypatch.setattr(subprocess, "Popen", open_fixture)

    def timeout(
        *_args: object,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(cmd=("npm",), timeout=1.0)

    monkeypatch.setattr(subprocess, "run", timeout)

    with pytest.raises(ConformanceRunError, match="timed out"):
        _ = runner.run_conformance(RunnerOptions(), harness_timeout=1.0)
    assert fixture.terminated is True
    assert fixture.killed is False


def test_runner_cli_records_identity_selectors_and_proof_class(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Emit reviewed harness identity without inflating fixture evidence claims."""
    check: dict[str, object] = {
        "id": "sep-2575-example",
        "name": "Example",
        "description": "wire assertion",
        "status": "SUCCESS",
        "timestamp": "2026-08-21T00:00:00.000Z",
        "details": {"status": 200},
    }

    def completed(_options: RunnerOptions) -> RunEvidence:
        return RunEvidence(
            package="@modelcontextprotocol/conformance",
            version="0.2.0-alpha.11",
            integrity=(
                "sha512-imPK9tx5gQsL6ZKQq4MrsyDYfSaIwpRmX6+ogjbeAXs9LGvxkBxWcY7"
                "KcS7TvwaBk/ZiVWl6b/naF4q83UwDRA=="
            ),
            upstream_commit="c321dd32035556e6769d3724a8ee97d87c3faaac",
            scenario="server-stateless",
            spec_version="2026-07-28",
            proof_class="official-auth-disabled-fixture-harness",
            checks=(check,),
        )

    monkeypatch.setattr(runner, "run_conformance", completed)

    assert main(["--scenario", "server-stateless", "--spec-version", "2026-07-28"]) == 0
    record = _require_object(cast("object", json.loads(capsys.readouterr().out)))
    assert record["upstream_commit"] == "c321dd32035556e6769d3724a8ee97d87c3faaac"
    assert record["proof_class"] == "official-auth-disabled-fixture-harness"
    assert record["checks"] == [check]


def test_official_fixture_uses_project_sdk_http_composition() -> None:
    """Exercise the harness-only diagnostic surface through the real SDK mount."""
    metadata: dict[str, object] = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Host": "127.0.0.1:8000",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }
    list_body: dict[str, object] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {"_meta": metadata},
    }
    with TestClient(official_fixture_app) as client:
        listed = client.post(
            "/mcp",
            headers=headers,
            content=json.dumps(list_body).encode(),
        )
        assert listed.status_code == HTTPStatus.OK
        payload = _response_payload(listed.text)
        result = _require_object(payload["result"])
        tools = _require_array(result["tools"])
        names = {_require_string(_require_object(tool)["name"]) for tool in tools}
        assert names == {
            "test_logging_tool",
            "test_missing_capability",
            "test_streaming_elicitation",
        }

        call_body: dict[str, object] = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "test_missing_capability",
                "arguments": {},
                "_meta": metadata,
            },
        }
        missing_capability = client.post(
            "/mcp",
            headers={
                **headers,
                "Mcp-Method": "tools/call",
                "Mcp-Name": "test_missing_capability",
            },
            content=json.dumps(call_body).encode(),
        )
        assert missing_capability.status_code == HTTPStatus.BAD_REQUEST
        error = _require_object(_response_payload(missing_capability.text)["error"])
        assert error["code"] == MISSING_REQUIRED_CLIENT_CAPABILITY
        data = _require_object(error["data"])
        assert data["requiredCapabilities"] == {"sampling": {}}


def _response_payload(text: str) -> dict[str, object]:
    """Decode one JSON response or the first official SDK SSE data frame."""
    if text.startswith(("event:", "data:")):
        data_line = next(line for line in text.splitlines() if line.startswith("data:"))
        return cast(
            "dict[str, object]",
            json.loads(data_line.removeprefix("data:").strip()),
        )
    return cast("dict[str, object]", json.loads(text))


def _require_object(value: object) -> dict[str, object]:
    """Assert one decoded JSON object for strict test-side navigation."""
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def _require_array(value: object) -> list[object]:
    """Assert one decoded JSON array for strict test-side navigation."""
    assert isinstance(value, list)
    return cast("list[object]", value)


def _require_string(value: object) -> str:
    """Assert one decoded JSON string for strict test-side navigation."""
    assert isinstance(value, str)
    return value
