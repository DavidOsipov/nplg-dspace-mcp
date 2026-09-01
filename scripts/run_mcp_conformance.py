# Copyright (c) 2026 David Osipov
"""Run the reviewed official MCP fixture harness without network resolution."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

CONFORMANCE_PACKAGE = "@modelcontextprotocol/conformance"
CONFORMANCE_VERSION = "0.2.0-alpha.11"
CONFORMANCE_COMMIT = "c321dd32035556e6769d3724a8ee97d87c3faaac"
CONFORMANCE_INTEGRITY = (
    "sha512-imPK9tx5gQsL6ZKQq4MrsyDYfSaIwpRmX6+ogjbeAXs9LGvxkBxWcY7KcS7TvwaB"
    "k/ZiVWl6b/naF4q83UwDRA=="
)
FIXTURE_MODULE = "tests.conformance.official_fixture_server:app"
FIXTURE_PROFILE = "official-conformance-fixture"
SCENARIO = "server-stateless"
SPEC_VERSION = "2026-07-28"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class RunnerOptions:
    """Closed set of inputs allowed for the developmental fixture proof."""

    bind_host: str = "127.0.0.1"
    fixture_module: str = FIXTURE_MODULE
    profile: str = FIXTURE_PROFILE
    bearer_token: str | None = None
    forwarding_proxy: str | None = None
    scenario: str = SCENARIO
    spec_version: str = SPEC_VERSION
    requirements: str | None = None
    suite: str | None = None


class ConformanceRunError(RuntimeError):
    """The official fixture run did not produce fresh passing evidence."""


class FixtureProcess(Protocol):
    """Minimum child-process surface used by bounded fixture orchestration."""

    def poll(self) -> int | None:
        """Return the current exit code or None while running."""
        ...

    def terminate(self) -> None:
        """Ask the process to terminate."""
        ...

    def kill(self) -> None:
        """Force the process to terminate."""
        ...

    def wait(self, timeout: float | None = None) -> int:
        """Wait for process completion."""
        ...


class TextWriter(Protocol):
    """Strict view of the standard text streams used by the CLI."""

    def write(self, value: str) -> int:
        """Write text and return the number of accepted characters."""
        ...


@dataclass(frozen=True, slots=True)
class RunEvidence:
    """Immutable developmental-fixture proof with reviewed harness identity."""

    package: str
    version: str
    integrity: str
    upstream_commit: str
    scenario: str
    spec_version: str
    proof_class: str
    checks: tuple[dict[str, object], ...]


def validate_options(options: RunnerOptions) -> None:
    """Reject every input that escapes or broadens the reviewed fixture run."""
    trusted = (
        options.bind_host == "127.0.0.1"
        and options.fixture_module == FIXTURE_MODULE
        and options.profile == FIXTURE_PROFILE
        and options.bearer_token is None
        and options.forwarding_proxy is None
        and options.scenario == SCENARIO
        and options.spec_version == SPEC_VERSION
        and options.requirements is None
        and options.suite is None
    )
    if not trusted:
        msg = "only the loopback official conformance fixture is permitted"
        raise ValueError(msg)


def _is_check_record(value: object) -> bool:
    """Return whether one official record has the required bounded shape."""
    if not isinstance(value, dict):
        return False
    record = cast("dict[object, object]", value)
    required_strings = ("id", "name", "description", "status", "timestamp")
    if any(not isinstance(record.get(field), str) for field in required_strings):
        return False
    if any(not cast("str", record[field]) for field in required_strings):
        return False
    try:
        _ = datetime.fromisoformat(cast("str", record["timestamp"]))
    except ValueError:
        return False
    return isinstance(record.get("details", {}), dict)


def _single_checks_path(result_dir: Path) -> Path:
    """Resolve the sole checks artifact for the sole expected scenario."""
    try:
        entries = tuple(result_dir.iterdir())
    except OSError as exc:
        msg = "official conformance results are unavailable"
        raise ConformanceRunError(msg) from exc
    if (
        len(entries) != 1
        or not entries[0].is_dir()
        or not entries[0].name.startswith("server-server-stateless-")
    ):
        msg = "official conformance output directory is ambiguous"
        raise ConformanceRunError(msg)
    scenario_entries = tuple(entries[0].iterdir())
    if len(scenario_entries) != 1 or scenario_entries[0].name != "checks.json":
        msg = "official conformance checks.json is missing or output is unexpected"
        raise ConformanceRunError(msg)
    return scenario_entries[0]


def validate_harness_results(
    result_dir: Path,
    *,
    started_at_ns: int,
) -> tuple[dict[str, object], ...]:
    """Validate and preserve every fresh check emitted by one named scenario."""
    checks_path = _single_checks_path(result_dir)
    if checks_path.stat().st_mtime_ns < started_at_ns:
        msg = "official conformance checks.json is stale"
        raise ConformanceRunError(msg)
    try:
        raw = cast("object", json.loads(checks_path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        msg = "official conformance checks.json is malformed"
        raise ConformanceRunError(msg) from exc
    if not isinstance(raw, list):
        msg = "official conformance checks.json has an invalid record"
        raise ConformanceRunError(msg)
    raw_records = cast("list[object]", raw)
    if not raw_records or any(not _is_check_record(item) for item in raw_records):
        msg = "official conformance checks.json has an invalid record"
        raise ConformanceRunError(msg)
    checks = tuple(cast("dict[str, object]", item) for item in raw_records)
    for check in checks:
        if check["status"] not in {"SUCCESS", "SKIPPED"}:
            msg = "official conformance emitted a scored failing check"
            raise ConformanceRunError(msg)
        if "errorMessage" in check:
            msg = "official conformance emitted a harness error"
            raise ConformanceRunError(msg)
    if not any(check["status"] == "SUCCESS" for check in checks):
        msg = "official conformance emitted no successful checks"
        raise ConformanceRunError(msg)
    return checks


def choose_loopback_port() -> int:
    """Ask the kernel for a currently unused IPv4 loopback port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        address = cast("tuple[str, int]", probe.getsockname())
        return address[1]


def ensure_listener_available(host: str, port: int) -> None:
    """Fail if the selected fixture address already has a listener."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((host, port))
    except OSError as exc:
        msg = "official conformance fixture listener is already occupied"
        raise ConformanceRunError(msg) from exc


def wait_for_fixture(
    process: FixtureProcess,
    host: str,
    port: int,
    *,
    timeout: float,
) -> None:
    """Wait a bounded interval for the private fixture TCP listener."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            msg = f"official conformance fixture exited before readiness ({exit_code})"
            raise ConformanceRunError(msg)
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    msg = "official conformance fixture readiness timed out"
    raise ConformanceRunError(msg)


def _terminate_fixture(process: FixtureProcess) -> None:
    """Reap the fixture process, escalating once after a bounded grace period."""
    if process.poll() is not None:
        _ = process.wait(timeout=0.0)
        return
    process.terminate()
    try:
        _ = process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        _ = process.wait(timeout=5.0)


def _sanitized_environment() -> dict[str, str]:
    """Pass only execution essentials and explicit loopback/no-network policy."""
    environment = {
        "NO_PROXY": "127.0.0.1,localhost",
        "NPM_CONFIG_OFFLINE": "true",
        "no_proxy": "127.0.0.1,localhost",
    }
    for name in ("LANG", "PATH", "PYTHONPATH"):
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    return environment


def run_conformance(
    options: RunnerOptions,
    *,
    readiness_timeout: float = 5.0,
    harness_timeout: float = 120.0,
) -> RunEvidence:
    """Run one fresh auth-disabled official fixture scenario and validate output."""
    validate_options(options)
    if readiness_timeout <= 0 or harness_timeout <= 0:
        msg = "official conformance timeouts must be positive"
        raise ValueError(msg)
    port = choose_loopback_port()
    ensure_listener_available(options.bind_host, port)
    url = f"http://{options.bind_host}:{port}/mcp"
    fixture_argv = (
        sys.executable,
        "-m",
        "uvicorn",
        options.fixture_module,
        "--host",
        options.bind_host,
        "--port",
        str(port),
        "--log-level",
        "warning",
        "--no-access-log",
    )
    environment = _sanitized_environment()
    environment["NPLG_MCP_FIXTURE_PORT"] = str(port)
    process = cast(
        "FixtureProcess",
        subprocess.Popen(  # noqa: S603 - executable and argv are closed constants
            fixture_argv,
            cwd=REPOSITORY_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ),
    )
    try:
        wait_for_fixture(
            process,
            options.bind_host,
            port,
            timeout=readiness_timeout,
        )
        with tempfile.TemporaryDirectory(prefix="nplg-mcp-conformance-") as raw_dir:
            result_dir = Path(raw_dir)
            result_dir.chmod(0o700)
            # Compare timestamps sampled by the same filesystem clock. A userspace
            # wall-clock sample can narrowly lead a subsequently written inode.
            started_at_ns = result_dir.stat().st_mtime_ns
            argv = build_harness_argv(
                url=url,
                result_dir=result_dir,
                scenario=options.scenario,
                spec_version=options.spec_version,
            )
            try:
                completed = subprocess.run(  # noqa: S603 - validated closed argv
                    argv,
                    cwd=REPOSITORY_ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=harness_timeout,
                )
            except subprocess.TimeoutExpired as exc:
                msg = "official conformance harness timed out"
                raise ConformanceRunError(msg) from exc
            if completed.returncode != 0:
                msg = (
                    "official conformance harness exited unsuccessfully "
                    f"({completed.returncode})"
                )
                raise ConformanceRunError(msg)
            checks = validate_harness_results(
                result_dir,
                started_at_ns=started_at_ns,
            )
            return RunEvidence(
                package=CONFORMANCE_PACKAGE,
                version=CONFORMANCE_VERSION,
                integrity=CONFORMANCE_INTEGRITY,
                upstream_commit=CONFORMANCE_COMMIT,
                scenario=options.scenario,
                spec_version=options.spec_version,
                proof_class="official-auth-disabled-fixture-harness",
                checks=checks,
            )
    finally:
        _terminate_fixture(process)


def main(argv: list[str] | None = None) -> int:
    """Run the single approved fixture scenario and emit structured evidence."""
    parser = argparse.ArgumentParser(
        description="Run the auth-disabled official MCP conformance fixture.",
    )
    _ = parser.add_argument("--scenario", choices=(SCENARIO,), required=True)
    _ = parser.add_argument(
        "--spec-version",
        choices=(SPEC_VERSION,),
        required=True,
    )
    arguments = parser.parse_args(argv)
    options = RunnerOptions(
        scenario=cast("str", arguments.scenario),
        spec_version=cast("str", arguments.spec_version),
    )
    try:
        evidence = run_conformance(options)
    except (ConformanceRunError, ValueError) as exc:
        _ = cast("TextWriter", sys.stderr).write(f"conformance fixture failed: {exc}\n")
        return 1
    record: dict[str, object] = {
        "package": evidence.package,
        "version": evidence.version,
        "integrity": evidence.integrity,
        "upstream_commit": evidence.upstream_commit,
        "scenario": evidence.scenario,
        "spec_version": evidence.spec_version,
        "proof_class": evidence.proof_class,
        "checks": list(evidence.checks),
    }
    stdout = cast("TextWriter", sys.stdout)
    _ = stdout.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
    _ = stdout.write("\n")
    return 0


def build_harness_argv(
    *,
    url: str,
    result_dir: Path,
    scenario: str,
    spec_version: str,
) -> tuple[str, ...]:
    """Return the exact shell-free command for the reviewed local harness."""
    return (
        "npm",
        "exec",
        "--offline",
        f"--package={CONFORMANCE_PACKAGE}@{CONFORMANCE_VERSION}",
        "--",
        "conformance",
        "server",
        "--url",
        url,
        "--scenario",
        scenario,
        "--spec-version",
        spec_version,
        "--output-dir",
        str(result_dir),
    )


if __name__ == "__main__":
    raise SystemExit(main())
