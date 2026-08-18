# Copyright (c) 2026 David Osipov
"""Unit tests for the ordered quality runner."""

from __future__ import annotations

import hashlib
import os
import runpy
import select
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Literal, cast

import pytest

import scripts.run_quality_gate as quality_gate_module
from scripts.run_quality_gate import (
    CommandResult,
    ExecutionLimits,
    ExecutionPolicy,
    GateError,
    GitSnapshot,
    QualityGateRequest,
    ToolCommand,
    VersionProbe,
    command_plan,
    fingerprint_paths,
    freeze_input_inventory,
    git_snapshot,
    parse_arguments,
    run_bounded_command,
    validate_external_cache,
    validate_managed_node,
    validate_release_arguments,
    validate_release_state,
    verify_exact_version,
    version_probes,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

ARGPARSE_ERROR_EXIT = 2
EXPECTED_WAIT_CALLS = 2
GIT_OBJECT_ID_LENGTH = 40
PRIVATE_CACHE_MODE = 0o700
SECOND_CALL = 2
SHA256_HEX_LENGTH = 64
STDERR_CANARY_SCRIPT = (
    "import sys; sys.stderr.write('QUALITY_SECRET_CANARY'); raise SystemExit(2)"
)
STDOUT_CANARY_SCRIPT = (
    "import sys; sys.stdout.write('QUALITY_SECRET_CANARY'); raise SystemExit(2)"
)


def _worktree_record(
    path: bytes,
    *,
    head: bytes = b"1" * GIT_OBJECT_ID_LENGTH,
    branch: bytes = b"branch refs/heads/main",
    optional: tuple[bytes, ...] = (),
) -> bytes:
    return (
        b"\0".join((b"worktree " + path, b"HEAD " + head, branch, *optional)) + b"\0\0"
    )


def _populate_quality_root(root: Path) -> None:
    for directory in ("src", "tests", "scripts", "typings"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for filename in (
        "pyproject.toml",
        "pyrightconfig.json",
        "package-lock.json",
        "requirements-dev.lock",
        "security/bootstrap-toolchain-lock.json",
        "scripts/run_quality_gate.py",
    ):
        destination = root / filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        _ = destination.write_bytes(b"bounded\n")


def _completed_process_poll() -> int:
    return 0


def _completed_process_wait(*, timeout: float | None = None) -> int:
    del timeout
    return 0


def _ignore_process_kill() -> None:
    return None


def _ignore_process_group_kill(_process_id: int, _signal_number: int) -> None:
    return None


def _ignore_version_check(
    command: tuple[str, ...],
    *,
    expected_stdout: bytes,
    root: Path,
    cache_dir: Path,
) -> None:
    del command, expected_stdout, root, cache_dir


@dataclass(slots=True)
class _SelfTestFaults:
    """Stateful fault boundary for the quality runner's isolated self-test."""

    scenario: str
    clean: GitSnapshot
    changed: GitSnapshot
    diagnostic_calls: int = 0
    fingerprint_calls: int = 0
    snapshot_calls: int = 0

    def fingerprint(self, _paths: Iterable[Path], *, root: Path) -> str:
        del root
        self.fingerprint_calls += 1
        if self.scenario == "bytes" and self.fingerprint_calls == SECOND_CALL:
            return "after"
        return "before"

    def snapshot(self, _root: Path, _cache: Path) -> GitSnapshot:
        self.snapshot_calls += 1
        if self.scenario == "git" and self.snapshot_calls == SECOND_CALL:
            return self.changed
        return self.clean

    def run(
        self,
        command: tuple[str, ...],
        *,
        root: Path,
        cache_dir: Path,
        policy: ExecutionPolicy,
    ) -> CommandResult:
        del root, cache_dir
        if policy.allow_diagnostics:
            self.diagnostic_calls += 1
            return CommandResult(
                command,
                (
                    0
                    if self.scenario == "diagnostic" and self.diagnostic_calls == 1
                    else 1
                ),
                b"diagnostic",
                b"",
            )
        if self.scenario == "false-green":
            return CommandResult(command, 1, b"diagnostic", b"")
        failure_message = "final mode rejected the diagnostic"
        raise GateError(failure_message)


def test_quality_command_plan_is_ordered_and_includes_typings() -> None:
    commands = command_plan(
        Path("/repo"),
        (Path("src"),),
        node_executable=Path("/managed/bin/node"),
    )
    assert [
        (command.tool, command.python_target, command.diagnostic)
        for command in commands
    ] == [
        ("ruff", "3.12", False),
        ("ruff", "3.12", True),
        ("pyright", "3.12", True),
        ("mypy", "3.12", True),
        ("pyright", "3.13", True),
        ("mypy", "3.13", True),
        ("pyright", "3.14", True),
        ("mypy", "3.14", True),
    ]
    assert all(Path(command.argv[0]).is_absolute() for command in commands)
    assert all("typings" in " ".join(command.argv) for command in commands)
    assert commands[0].argv[1:3] == ("format", "--check")
    assert commands[1].argv[1:4] == ("check", "--output-format", "json")
    assert commands[2].argv[:2] == (
        "/managed/bin/node",
        "/repo/node_modules/pyright/index.js",
    )
    assert "--outputjson" in commands[2].argv
    assert commands[3].argv[1:4] == (
        "--output",
        "json",
        "--no-error-summary",
    )
    assert "--python-version" in commands[3].argv


@pytest.mark.parametrize("removed_option", ["--ratchet", "--write-baseline"])
def test_removed_baseline_options_are_rejected(removed_option: str) -> None:
    with pytest.raises(SystemExit) as raised:
        _ = parse_arguments(
            (
                "--node-executable",
                "/managed/bin/node",
                removed_option,
                "removed.json",
            )
        )

    assert raised.value.code == ARGPARSE_ERROR_EXIT


def test_quality_gate_models_have_no_baseline_or_projection_fields() -> None:
    assert "staged_entries_projection_sha256" not in dir(GitSnapshot)
    assert "ratchet" not in dir(QualityGateRequest)
    assert "write_baseline_path" not in dir(QualityGateRequest)


def test_real_gate_cli_requires_an_explicit_managed_node_executable() -> None:
    with pytest.raises(SystemExit) as raised:
        _ = parse_arguments(("src",))

    assert raised.value.code == ARGPARSE_ERROR_EXIT


def test_real_gate_cli_defaults_to_the_complete_frozen_scope() -> None:
    arguments = parse_arguments(("--node-executable", "/managed/bin/node"))

    assert arguments.paths == (
        Path("src"),
        Path("tests"),
        Path("scripts"),
        Path("typings"),
    )


def test_managed_node_must_match_the_bootstrap_lock_digest() -> None:
    root = Path(__file__).resolve().parents[2]

    with pytest.raises(GateError, match="locked digest"):
        _ = validate_managed_node(root, Path(sys.executable).resolve())


def test_version_probe_rejects_nonexact_output_without_echoing_it(
    tmp_path: Path,
) -> None:
    canary = "VERSION_SECRET_CANARY"
    with pytest.raises(GateError) as raised:
        verify_exact_version(
            (
                Path(sys.executable).resolve().as_posix(),
                "-c",
                f"print('{canary}')",
            ),
            expected_stdout=b"tool 1.0\n",
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
        )

    assert canary not in str(raised.value)
    assert "version output" in str(raised.value)


def test_tool_version_probes_are_exact_and_use_managed_node_directly() -> None:
    probes = version_probes(Path("/repo"), Path("/managed/bin/node"))

    assert [(probe.command, probe.expected_stdout) for probe in probes] == [
        (("/repo/.venv/bin/ruff", "--version"), b"ruff 0.16.3\n"),
        (("/managed/bin/node", "--version"), b"v24.19.0\n"),
        (
            (
                "/managed/bin/node",
                "/repo/node_modules/pyright/index.js",
                "--version",
            ),
            b"pyright 1.1.413\n",
        ),
        (
            ("/repo/.venv/bin/mypy", "--version"),
            b"mypy 2.3.1 (compiled: yes)\n",
        ),
    ]


def test_input_inventory_rejects_absolute_escape_and_symlink(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    _ = (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    _ = outside.write_text("x = 2\n", encoding="utf-8")
    (source / "linked.py").symlink_to(outside)

    with pytest.raises(GateError, match="symlink"):
        _ = freeze_input_inventory(tmp_path, (Path("src"),))
    with pytest.raises(GateError, match="escapes"):
        _ = freeze_input_inventory(tmp_path, (outside,))


def test_git_snapshot_hashes_logical_index_and_refs_without_mutation(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    before_index = (root / ".git" / "index").read_bytes()

    snapshot = git_snapshot(root, tmp_path)

    assert len(snapshot.head) == GIT_OBJECT_ID_LENGTH
    assert len(snapshot.staged_entries_sha256) == SHA256_HEX_LENGTH
    assert len(snapshot.refs_sha256) == SHA256_HEX_LENGTH
    assert len(snapshot.worktree_status_sha256) == SHA256_HEX_LENGTH
    assert (root / ".git" / "index").read_bytes() == before_index


def test_porcelain_status_parser_is_bounded_nul_safe_and_rename_aware() -> None:
    empty_digest, empty_clean = quality_gate_module.parse_porcelain_status(b"")
    dirty = b" M src/a.py\0?? untracked.py\0R  dst.py\0src.py\0"
    dirty_digest, dirty_clean = quality_gate_module.parse_porcelain_status(dirty)

    assert empty_digest == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert empty_clean is True
    assert dirty_digest != empty_digest
    assert dirty_clean is False

    malformed = (
        b" M src/a.py",
        b"XX src/a.py\0",
        b" M \0",
        b"R  dst.py\0",
        b" M \xff\0",
    )
    for raw in malformed:
        with pytest.raises(GateError, match="status"):
            _ = quality_gate_module.parse_porcelain_status(raw)


def test_self_test_cli_runs_only_the_isolated_self_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Path, Path]] = []

    def fake_self_test(root: Path, node_executable: Path) -> None:
        calls.append((root, node_executable))

    def forbidden_gate(*_args: object, **_kwargs: object) -> None:
        message = "normal gate must not run during self-test"
        raise AssertionError(message)

    monkeypatch.setattr(quality_gate_module, "run_self_test", fake_self_test)
    monkeypatch.setattr(quality_gate_module, "run_quality_gate", forbidden_gate)

    exit_code = quality_gate_module.main(
        ("--node-executable", "/managed/bin/node", "--self-test")
    )

    assert exit_code == 0
    assert calls == [(Path.cwd().resolve(), Path("/managed/bin/node"))]


def test_process_cli_reports_gate_failure_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_safely(_argv: object = None) -> int:
        message = "bounded quality failure"
        raise GateError(message)

    monkeypatch.setattr(quality_gate_module, "main", fail_safely)

    assert quality_gate_module.cli(()) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "quality gate failed: bounded quality failure\n"
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ("--node-executable", "/managed/bin/node", "--require-clean"),
        (
            "--node-executable",
            "/managed/bin/node",
            "--require-clean",
            "--worktree",
            "/repo",
            "--candidate",
            "f" * 40,
        ),
        (
            "--node-executable",
            "/managed/bin/node",
            "--require-clean",
            "--worktree",
            "relative",
            "--cache-dir",
            "/nplg-external-cache",
            "--candidate",
            "f" * 40,
        ),
        (
            "--node-executable",
            "/managed/bin/node",
            "--candidate",
            "f" * 40,
        ),
    ],
)
def test_release_mode_requires_complete_explicit_absolute_identity(
    argv: tuple[str, ...],
) -> None:
    with pytest.raises(GateError, match="release mode"):
        validate_release_arguments(parse_arguments(argv))


def test_release_state_rejects_candidate_head_mismatch_without_path_search(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested: list[tuple[str, ...]] = []

    def fake_run(
        command: tuple[str, ...],
        *,
        root: Path,
        cache_dir: Path,
        **_kwargs: object,
    ) -> CommandResult:
        del root, cache_dir
        requested.append(command)
        if command[1:3] == ("rev-parse", "--verify"):
            stdout = b"e" * 40 + b"\n"
        elif command[1:3] == ("ls-files", "--stage"):
            stdout = b""
        elif command[1:3] == ("show-ref", "--head"):
            stdout = b"e" * 40 + b" HEAD\n"
        elif command[1:3] == ("status", "--porcelain=v1"):
            stdout = b""
        else:
            message = f"unexpected Git command shape: {command!r}"
            raise AssertionError(message)
        return CommandResult(
            argv=command,
            returncode=0,
            stdout=stdout,
            stderr=b"",
        )

    monkeypatch.setattr(quality_gate_module, "run_bounded_command", fake_run)
    with pytest.raises(GateError, match="candidate does not equal HEAD"):
        _ = validate_release_state(
            tmp_path,
            tmp_path.parent / f"{tmp_path.name}-cache",
            "f" * 40,
        )

    assert requested
    assert all(command[0] == "/usr/bin/git" for command in requested)


def test_release_cli_passes_validated_snapshot_into_the_quality_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path.parent / f"{tmp_path.name}-release-cache"
    expected = GitSnapshot(
        head="f" * 40,
        staged_entries_sha256="a" * 64,
        refs_sha256="b" * 64,
        worktree_status_sha256=(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        worktree_clean=True,
    )
    received: list[GitSnapshot | None] = []

    def fake_release_state(
        root: Path,
        cache_dir: Path,
        candidate: str,
    ) -> GitSnapshot:
        assert root == tmp_path
        assert cache_dir == cache
        assert candidate == "f" * 40
        return expected

    def fake_quality_gate(
        _root: Path,
        request: QualityGateRequest,
    ) -> None:
        received.append(request.expected_git_snapshot)

    monkeypatch.setattr(
        quality_gate_module, "validate_release_state", fake_release_state
    )
    monkeypatch.setattr(quality_gate_module, "run_quality_gate", fake_quality_gate)

    exit_code = quality_gate_module.main(
        (
            "--node-executable",
            "/managed/bin/node",
            "--worktree",
            tmp_path.as_posix(),
            "--cache-dir",
            cache.as_posix(),
            "--require-clean",
            "--candidate",
            "f" * 40,
        )
    )

    assert exit_code == 0
    assert received == [expected]


@pytest.mark.parametrize(
    "status_payload",
    [b" M src/a.py\0", b"?? post-preflight.py\0"],
)
def test_quality_run_rejects_repository_state_changed_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status_payload: bytes,
) -> None:
    for directory in ("src", "tests", "scripts", "typings"):
        (tmp_path / directory).mkdir()
    for filename in (
        "pyproject.toml",
        "pyrightconfig.json",
        "package-lock.json",
        "requirements-dev.lock",
        "security/bootstrap-toolchain-lock.json",
        "scripts/run_quality_gate.py",
    ):
        destination = tmp_path / filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        _ = destination.write_bytes(b"bounded\n")
    validated = GitSnapshot(
        head="f" * 40,
        staged_entries_sha256="a" * 64,
        refs_sha256="b" * 64,
        worktree_status_sha256=(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        worktree_clean=True,
    )
    changed_status_sha256, changed_clean = quality_gate_module.parse_porcelain_status(
        status_payload
    )
    changed = GitSnapshot(
        head="f" * 40,
        staged_entries_sha256="a" * 64,
        refs_sha256="b" * 64,
        worktree_status_sha256=changed_status_sha256,
        worktree_clean=changed_clean,
    )

    def fake_snapshot(_root: Path, _cache_dir: Path) -> GitSnapshot:
        return changed

    def fake_worktrees(_root: Path) -> tuple[Path, ...]:
        return (tmp_path,)

    monkeypatch.setattr(quality_gate_module, "git_snapshot", fake_snapshot)
    monkeypatch.setattr(
        quality_gate_module,
        "registered_worktree_roots",
        fake_worktrees,
    )

    with pytest.raises(GateError, match="changed after validation"):
        quality_gate_module.run_quality_gate(
            tmp_path,
            QualityGateRequest(
                paths=(Path("src"), Path("tests"), Path("scripts"), Path("typings")),
                node_executable=Path("/managed/bin/node"),
                cache_dir=None,
                expected_git_snapshot=validated,
            ),
        )


def test_release_run_rechecks_outside_scope_worktree_dirt_after_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for directory in ("src", "tests", "scripts", "typings"):
        (tmp_path / directory).mkdir()
    for filename in (
        "pyproject.toml",
        "pyrightconfig.json",
        "package-lock.json",
        "requirements-dev.lock",
        "security/bootstrap-toolchain-lock.json",
        "scripts/run_quality_gate.py",
    ):
        destination = tmp_path / filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        _ = destination.write_bytes(b"bounded\n")
    clean = GitSnapshot(
        head="f" * 40,
        staged_entries_sha256="a" * 64,
        refs_sha256="b" * 64,
        worktree_status_sha256=(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        worktree_clean=True,
    )
    dirty = GitSnapshot(
        head=clean.head,
        staged_entries_sha256=clean.staged_entries_sha256,
        refs_sha256=clean.refs_sha256,
        worktree_status_sha256="d" * 64,
        worktree_clean=False,
    )
    outside = tmp_path / "outside-selected-scope.txt"

    def fake_snapshot(_root: Path, _cache_dir: Path) -> GitSnapshot:
        return dirty if outside.exists() else clean

    def fake_worktrees(_root: Path) -> tuple[Path, ...]:
        return (tmp_path,)

    def fake_node(_root: Path, node_executable: Path) -> Path:
        return node_executable

    def fake_versions(_root: Path, _cache: Path, _node: Path) -> None:
        return None

    def create_outside_dirt(_execution: object) -> None:
        _ = outside.write_bytes(b"tool-created\n")

    monkeypatch.setattr(quality_gate_module, "git_snapshot", fake_snapshot)
    monkeypatch.setattr(
        quality_gate_module,
        "registered_worktree_roots",
        fake_worktrees,
    )
    monkeypatch.setattr(quality_gate_module, "validate_managed_node", fake_node)
    monkeypatch.setattr(quality_gate_module, "_verify_versions", fake_versions)
    monkeypatch.setattr(
        quality_gate_module,
        "_run_quality_commands",
        create_outside_dirt,
    )

    with pytest.raises(GateError, match="mutated repository"):
        quality_gate_module.run_quality_gate(
            tmp_path,
            QualityGateRequest(
                paths=(Path("src"), Path("tests"), Path("scripts"), Path("typings")),
                node_executable=Path("/managed/bin/node"),
                cache_dir=None,
                expected_git_snapshot=clean,
            ),
        )


def test_bounded_runner_rejects_path_searched_executables(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="absolute reviewed executable"):
        _ = run_bounded_command(
            ("python", "-c", "raise SystemExit(0)"),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
        )


@pytest.mark.parametrize(
    ("stream", "script"),
    [
        (
            "stderr",
            STDERR_CANARY_SCRIPT,
        ),
        (
            "stdout",
            STDOUT_CANARY_SCRIPT,
        ),
    ],
)
def test_bounded_runner_failure_never_echoes_untrusted_tool_bytes(
    tmp_path: Path,
    stream: str,
    script: str,
) -> None:
    with pytest.raises(GateError) as raised:
        _ = run_bounded_command(
            (Path(sys.executable).resolve().as_posix(), "-c", script),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
        )

    assert "QUALITY_SECRET_CANARY" not in str(raised.value)
    assert stream in {"stdout", "stderr"}


def test_bounded_runner_rejects_stdout_overflow(tmp_path: Path) -> None:
    output_bytes = 8 * 1024 * 1024 + 1
    script = f"import os; os.write(1, b'x' * {output_bytes})"

    with pytest.raises(GateError, match="output limit"):
        _ = run_bounded_command(
            (Path(sys.executable).resolve().as_posix(), "-c", script),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
        )


def test_bounded_runner_reaps_lingering_descendant_on_success(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived"
    child = (
        "import pathlib,time; time.sleep(0.35); "
        f"pathlib.Path({marker.as_posix()!r}).write_text('survived')"
    )
    parent = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL)"
    )

    _ = run_bounded_command(
        (Path(sys.executable).resolve().as_posix(), "-c", parent),
        root=tmp_path,
        cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
    )
    time.sleep(0.55)

    assert not marker.exists()


def test_bounded_runner_times_out_and_reaps_its_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "timed-out-descendant-survived"
    child = (
        "import pathlib,time; time.sleep(0.35); "
        f"pathlib.Path({marker.as_posix()!r}).write_text('survived')"
    )
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(5)"
    )

    with pytest.raises(GateError, match="deadline"):
        _ = run_bounded_command(
            (Path(sys.executable).resolve().as_posix(), "-c", parent),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
            policy=ExecutionPolicy(
                limits=ExecutionLimits(
                    timeout_seconds=0.08,
                    stdout_limit_bytes=1024,
                    stderr_limit_bytes=1024,
                )
            ),
        )
    time.sleep(0.5)

    assert not marker.exists()


def test_bounded_runner_allows_only_explicit_ascii_whitespace_stderr(
    tmp_path: Path,
) -> None:
    executable = Path(sys.executable).resolve().as_posix()
    cache = tmp_path.parent / f"{tmp_path.name}-cache"
    accepted = run_bounded_command(
        (executable, "-c", "import sys; sys.stderr.buffer.write(b' \\t\\r\\n\\v\\f')"),
        root=tmp_path,
        cache_dir=cache,
        policy=ExecutionPolicy(allow_ascii_whitespace_stderr=True),
    )
    assert accepted.stderr == b" \t\r\n\v\f"

    with pytest.raises(GateError, match="forbidden stderr"):
        _ = run_bounded_command(
            (executable, "-c", "import sys; sys.stderr.buffer.write(b'x')"),
            root=tmp_path,
            cache_dir=cache,
            policy=ExecutionPolicy(allow_ascii_whitespace_stderr=True),
        )


def test_bounded_runner_reaps_process_group_when_capture_is_cancelled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = tmp_path / "parent-ready"
    marker = tmp_path / "cancelled-descendant-survived"
    child = (
        "import pathlib,time; time.sleep(0.35); "
        f"pathlib.Path({marker.as_posix()!r}).write_text('survived')"
    )
    parent = (
        "import pathlib,subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
        f"pathlib.Path({ready.as_posix()!r}).write_text('ready'); time.sleep(5)"
    )

    def interrupt_capture(
        _process: object,
        *,
        limits: ExecutionLimits,
    ) -> tuple[bytes, bytes]:
        deadline = time.monotonic() + limits.timeout_seconds
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        raise KeyboardInterrupt

    monkeypatch.setattr(quality_gate_module, "_read_bounded_streams", interrupt_capture)
    with pytest.raises(KeyboardInterrupt):
        _ = run_bounded_command(
            (Path(sys.executable).resolve().as_posix(), "-c", parent),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
        )
    time.sleep(0.5)

    assert ready.exists()
    assert not marker.exists()


def test_external_cache_must_be_absolute_and_outside_worktree(tmp_path: Path) -> None:
    cache = tmp_path.parent / f"{tmp_path.name}-cache"
    _ = validate_external_cache(
        tmp_path,
        cache,
        registered_worktrees=(tmp_path,),
    )
    with pytest.raises(GateError):
        _ = validate_external_cache(
            tmp_path,
            tmp_path / "nested" / "cache",
            registered_worktrees=(tmp_path,),
        )
    with pytest.raises(GateError):
        _ = validate_external_cache(
            tmp_path,
            Path("relative-cache"),
            registered_worktrees=(tmp_path,),
        )


def test_external_cache_rejects_every_registered_sibling_worktree(
    tmp_path: Path,
) -> None:
    current = tmp_path / "current"
    sibling = tmp_path / "sibling"
    current.mkdir()
    sibling.mkdir()

    with pytest.raises(GateError, match="registered worktree"):
        _ = validate_external_cache(
            current,
            sibling / "quality-cache",
            registered_worktrees=(current, sibling),
        )


def test_registered_worktree_parser_accepts_only_closed_nul_records(
    tmp_path: Path,
) -> None:
    current = tmp_path / "current"
    sibling = tmp_path / "sibling"
    current.mkdir()
    sibling.mkdir()
    current_record = (
        b"worktree "
        + current.as_posix().encode()
        + b"\0HEAD "
        + (b"1" * 40)
        + b"\0branch refs/heads/main\0\0"
    )
    sibling_record = (
        b"worktree "
        + sibling.as_posix().encode()
        + b"\0HEAD "
        + (b"2" * 40)
        + b"\0detached\0locked reviewed\0\0"
    )
    payload = current_record + sibling_record

    assert quality_gate_module.parse_registered_worktrees(
        payload,
        current_root=current,
    ) == (current, sibling)

    malformed = (
        payload.removesuffix(b"\0"),
        current_record + current_record,
        current_record.replace(b"branch ", b"unknown "),
        current_record.replace(current.as_posix().encode(), b"relative"),
    )
    for raw in malformed:
        with pytest.raises(GateError, match="worktree"):
            _ = quality_gate_module.parse_registered_worktrees(
                raw,
                current_root=current,
            )


def test_registered_worktrees_are_enumerated_by_bounded_reviewed_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve(strict=True)
    payload = (
        b"worktree "
        + root.as_posix().encode()
        + b"\0HEAD "
        + (b"1" * 40)
        + b"\0branch refs/heads/main\0\0"
    )
    calls: list[tuple[tuple[str, ...], Path, Path]] = []

    def fake_run(
        command: tuple[str, ...],
        *,
        root: Path,
        cache_dir: Path,
        **_kwargs: object,
    ) -> CommandResult:
        calls.append((command, root, cache_dir))
        return CommandResult(
            argv=command,
            returncode=0,
            stdout=payload,
            stderr=b"",
        )

    monkeypatch.setattr(quality_gate_module, "run_bounded_command", fake_run)

    assert quality_gate_module.registered_worktree_roots(root) == (root,)
    assert calls == [
        (
            ("/usr/bin/git", "worktree", "list", "--porcelain", "-z"),
            root,
            Path("/dev/null"),
        )
    ]


def test_external_cache_must_be_new_and_cannot_be_a_symlink(tmp_path: Path) -> None:
    existing = tmp_path.parent / f"{tmp_path.name}-existing-cache"
    existing.mkdir()
    with pytest.raises(GateError, match="must not already exist"):
        _ = validate_external_cache(
            tmp_path,
            existing,
            registered_worktrees=(tmp_path,),
        )

    target = tmp_path.parent / f"{tmp_path.name}-cache-target"
    target.mkdir()
    linked = tmp_path.parent / f"{tmp_path.name}-linked-cache"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(GateError, match="must not already exist"):
        _ = validate_external_cache(
            tmp_path,
            linked,
            registered_worktrees=(tmp_path,),
        )


def test_source_fingerprint_changes_when_checked_bytes_change(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    _ = source.write_text("x = 1\n", encoding="utf-8")
    before = fingerprint_paths((source,), root=tmp_path)
    _ = source.write_text("x = 2\n", encoding="utf-8")
    after = fingerprint_paths((source,), root=tmp_path)
    assert after != before


def test_source_fingerprint_ignores_checker_generated_caches(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    cache = tmp_path / "__pycache__" / "source.cpython-313.pyc"
    _ = source.write_text("x = 1\n", encoding="utf-8")
    cache.parent.mkdir()
    _ = cache.write_bytes(b"before")
    before = fingerprint_paths((tmp_path,), root=tmp_path)
    _ = cache.write_bytes(b"after")
    after = fingerprint_paths((tmp_path,), root=tmp_path)
    assert after == before


def test_source_fingerprint_rejects_symlink_inputs(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    linked = tmp_path / "linked.py"
    _ = target.write_text("x = 1\n", encoding="utf-8")
    linked.symlink_to(target)

    with pytest.raises(GateError, match="symlink"):
        _ = fingerprint_paths((linked,), root=tmp_path)


def test_source_fingerprint_is_clone_location_independent(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    (first_root / "src").mkdir(parents=True)
    (second_root / "src").mkdir(parents=True)
    _ = (first_root / "src" / "a.py").write_bytes(b"x = 1\n")
    _ = (second_root / "src" / "a.py").write_bytes(b"x = 1\n")

    first = fingerprint_paths((first_root / "src",), root=first_root)
    second = fingerprint_paths((second_root / "src",), root=second_root)

    assert first == second


@pytest.mark.parametrize(
    ("timeout_seconds", "stdout_limit_bytes", "stderr_limit_bytes"),
    [
        (0.0, 1, 1),
        (1.0, 0, 1),
        (1.0, 1, 0),
    ],
)
def test_execution_limits_reject_nonpositive_resource_bounds(
    timeout_seconds: float,
    stdout_limit_bytes: int,
    stderr_limit_bytes: int,
) -> None:
    with pytest.raises(GateError, match="must be positive"):
        _ = ExecutionLimits(
            timeout_seconds=timeout_seconds,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
        )


def test_command_plan_does_not_duplicate_an_explicit_typings_path() -> None:
    commands = command_plan(
        Path("/repo"),
        (Path("src"), Path("typings")),
        node_executable=Path("/managed/bin/node"),
    )

    assert all(command.argv.count("/repo/typings") == 1 for command in commands)


def test_porcelain_status_rejects_wrong_runtime_type_and_invalid_path() -> None:
    with pytest.raises(GateError, match="evidence is invalid"):
        _ = quality_gate_module.parse_porcelain_status(cast("bytes", bytearray()))
    with pytest.raises(GateError, match="invalid path"):
        _ = quality_gate_module.parse_porcelain_status(b" M /absolute.py\0")


def test_source_fingerprint_rejects_missing_special_and_escaping_inputs(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.py"
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    special = tmp_path / "special"
    _ = outside.write_bytes(b"outside\n")
    os.mkfifo(special)

    with pytest.raises(GateError, match="does not exist"):
        _ = fingerprint_paths((missing,), root=tmp_path)
    with pytest.raises(GateError, match="special file"):
        _ = fingerprint_paths((special,), root=tmp_path)
    with pytest.raises(GateError, match="escapes"):
        _ = fingerprint_paths((outside,), root=tmp_path)


def test_source_fingerprint_rejects_nested_symlink_and_special_file(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    nested = source / "nested"
    nested.mkdir(parents=True)
    regular = nested / "a.py"
    _ = regular.write_bytes(b"x = 1\n")

    digest = fingerprint_paths((source,), root=tmp_path)
    assert len(digest) == SHA256_HEX_LENGTH

    linked = source / "linked.py"
    linked.symlink_to(regular)
    with pytest.raises(GateError, match="symlink"):
        _ = fingerprint_paths((source,), root=tmp_path)
    linked.unlink()

    special = source / "special"
    os.mkfifo(special)
    with pytest.raises(GateError, match="special file"):
        _ = fingerprint_paths((source,), root=tmp_path)


def test_input_inventory_rejects_ambiguous_missing_and_noncanonical_paths(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(source, target_is_directory=True)

    with pytest.raises(GateError, match="ambiguous"):
        _ = freeze_input_inventory(tmp_path, (Path("src/../src"),))
    with pytest.raises(GateError, match="does not exist"):
        _ = freeze_input_inventory(tmp_path, (Path("missing"),))
    with pytest.raises(GateError, match="symlink"):
        _ = freeze_input_inventory(tmp_path, (Path("linked"),))
    with pytest.raises(GateError, match="not canonical"):
        _ = freeze_input_inventory(tmp_path, (source / ".." / "src",))


def test_input_inventory_skips_transient_files_and_rejects_special_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    nested = source / "nested"
    transient = source / "__pycache__"
    nested.mkdir(parents=True)
    transient.mkdir()
    _ = (nested / "a.py").write_bytes(b"x = 1\n")
    _ = (transient / "a.pyc").write_bytes(b"generated")

    assert freeze_input_inventory(tmp_path, (Path("src"),)) == frozenset(
        {"src/nested/a.py"}
    )

    special = source / "special"
    os.mkfifo(special)
    with pytest.raises(GateError, match="special file"):
        _ = freeze_input_inventory(tmp_path, (Path("src"),))


def test_registered_worktree_parser_rejects_each_field_boundary(
    tmp_path: Path,
) -> None:
    current = tmp_path / "current"
    sibling = tmp_path / "sibling"
    regular = tmp_path / "regular"
    current.mkdir()
    sibling.mkdir()
    _ = regular.write_bytes(b"not a directory")
    current_bytes = current.as_posix().encode()

    malformed = (
        _worktree_record(b"/\xff"),
        _worktree_record(b""),
        _worktree_record((tmp_path / "missing").as_posix().encode()),
        _worktree_record(regular.as_posix().encode()),
        _worktree_record(current_bytes, optional=(b"locked", b"locked")),
        b"HEAD " + (b"1" * GIT_OBJECT_ID_LENGTH) + b"\0detached\0\0",
        _worktree_record(current_bytes, head=b"not-an-object-id"),
    )
    for payload in malformed:
        with pytest.raises(GateError, match="worktree"):
            _ = quality_gate_module.parse_registered_worktrees(
                payload,
                current_root=current,
            )

    assert quality_gate_module.parse_registered_worktrees(
        _worktree_record(current_bytes, optional=(b"locked", b"prunable")),
        current_root=current,
    ) == (current,)

    assert quality_gate_module.parse_registered_worktrees(
        _worktree_record(current_bytes)
        + _worktree_record(
            (tmp_path / "missing").as_posix().encode(),
            optional=(b"prunable gitdir is unavailable",),
        ),
        current_root=current,
    ) == (current,)

    with pytest.raises(GateError, match="absent"):
        _ = quality_gate_module.parse_registered_worktrees(
            _worktree_record(sibling.as_posix().encode()),
            current_root=current,
        )


def test_external_cache_rejects_invalid_registered_inventory_and_parent_alias(
    tmp_path: Path,
) -> None:
    current = tmp_path / "current"
    sibling = tmp_path / "sibling"
    cache_parent = tmp_path / "cache-parent"
    aliased_parent = tmp_path / "aliased-parent"
    current.mkdir()
    sibling.mkdir()
    cache_parent.mkdir()
    aliased_parent.symlink_to(cache_parent, target_is_directory=True)
    external = tmp_path / "external-cache"

    with pytest.raises(GateError, match="inventory is empty"):
        _ = validate_external_cache(current, external, registered_worktrees=())
    with pytest.raises(GateError, match="inventory is duplicated"):
        _ = validate_external_cache(
            current,
            external,
            registered_worktrees=(current, current),
        )
    with pytest.raises(GateError, match="absent"):
        _ = validate_external_cache(
            current,
            external,
            registered_worktrees=(sibling,),
        )
    with pytest.raises(GateError, match="symlink-free"):
        _ = validate_external_cache(
            current,
            aliased_parent / "cache",
            registered_worktrees=(current,),
        )


def test_source_fingerprint_rejects_a_file_disappearing_during_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    candidate = source / "a.py"
    _ = candidate.write_bytes(b"x = 1\n")
    real_lstat = Path.lstat

    def fail_candidate(path: Path) -> os.stat_result:
        if path == candidate:
            raise OSError
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fail_candidate)
    with pytest.raises(GateError, match="changed during traversal"):
        _ = fingerprint_paths((source,), root=tmp_path)


def test_source_fingerprint_rejects_an_open_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.py"
    _ = source.write_bytes(b"x = 1\n")
    real_open = os.open

    def fail_source_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == source:
            raise OSError
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_source_open)
    with pytest.raises(GateError, match="could not be opened"):
        _ = fingerprint_paths((source,), root=tmp_path)


def test_source_fingerprint_enforces_individual_and_total_byte_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.py"
    _ = source.write_bytes(b"ab")

    monkeypatch.setattr(quality_gate_module, "_SOURCE_FILE_LIMIT_BYTES", 1)
    with pytest.raises(GateError, match="bounded regular file"):
        _ = fingerprint_paths((source,), root=tmp_path)

    monkeypatch.setattr(quality_gate_module, "_SOURCE_FILE_LIMIT_BYTES", 2)
    monkeypatch.setattr(quality_gate_module, "_SOURCE_TOTAL_LIMIT_BYTES", 1)
    with pytest.raises(GateError, match="total byte limit"):
        _ = fingerprint_paths((source,), root=tmp_path)


def test_source_fingerprint_rejects_truncation_and_read_time_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.py"
    _ = source.write_bytes(b"ab")
    real_read = os.read

    def truncated_read(_descriptor: int, _amount: int) -> bytes:
        return b""

    monkeypatch.setattr(os, "read", truncated_read)
    with pytest.raises(GateError, match="truncated"):
        _ = fingerprint_paths((source,), root=tmp_path)

    changed = False

    def changing_read(descriptor: int, amount: int) -> bytes:
        nonlocal changed
        chunk = real_read(descriptor, amount)
        if not changed:
            status = source.stat()
            os.utime(
                source,
                ns=(status.st_atime_ns, status.st_mtime_ns + 1_000_000_000),
            )
            changed = True
        return chunk

    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(GateError, match="changed while it was read"):
        _ = fingerprint_paths((source,), root=tmp_path)


def test_input_inventory_rejects_resolve_and_inventory_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    candidate = source / "a.py"
    _ = candidate.write_bytes(b"x = 1\n")
    real_resolve = Path.resolve

    def fail_source_resolve(path: Path, *, strict: bool = False) -> Path:
        if path == source:
            raise OSError
        return real_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", fail_source_resolve)
    with pytest.raises(GateError, match="does not exist"):
        _ = freeze_input_inventory(tmp_path, (Path("src"),))

    monkeypatch.setattr(Path, "resolve", real_resolve)
    real_lstat = Path.lstat

    def fail_candidate_lstat(path: Path) -> os.stat_result:
        if path == candidate:
            raise OSError
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fail_candidate_lstat)
    with pytest.raises(GateError, match="changed during inventory"):
        _ = freeze_input_inventory(tmp_path, (Path("src"),))


def test_bounded_runner_rejects_empty_missing_and_nonexecutable_commands(
    tmp_path: Path,
) -> None:
    nonexecutable = tmp_path / "tool"
    _ = nonexecutable.write_bytes(b"tool")
    cache = tmp_path.parent / f"{tmp_path.name}-cache"

    with pytest.raises(GateError, match="empty or invalid"):
        _ = run_bounded_command((), root=tmp_path, cache_dir=cache)
    with pytest.raises(GateError, match="unavailable"):
        _ = run_bounded_command(
            ((tmp_path / "missing").as_posix(),),
            root=tmp_path,
            cache_dir=cache,
        )
    with pytest.raises(GateError, match="regular executable"):
        _ = run_bounded_command(
            (nonexecutable.as_posix(),),
            root=tmp_path,
            cache_dir=cache,
        )


def test_managed_node_rejects_lock_and_dependency_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "node"
    _ = executable.write_bytes(b"node")
    executable.chmod(0o700)

    def invalid_lock(_path: Path) -> tuple[object, ...]:
        raise OSError

    monkeypatch.setattr(quality_gate_module, "load_lock", invalid_lock)
    with pytest.raises(GateError, match="lock is invalid"):
        _ = validate_managed_node(tmp_path, executable)

    record_without_node = SimpleNamespace(
        tool="npm",
        target="x86_64-unknown-linux-gnu",
        lock_review_status="accepted",
        runtime_dependencies=(),
    )

    def lock_without_node(_path: Path) -> tuple[object, ...]:
        return (record_without_node,)

    monkeypatch.setattr(
        quality_gate_module,
        "load_lock",
        lock_without_node,
    )
    with pytest.raises(GateError, match="no unique reviewed Node"):
        _ = validate_managed_node(tmp_path, executable)


def test_managed_node_accepts_the_exact_single_link_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "node"
    payload = b"reviewed-node"
    _ = executable.write_bytes(payload)
    executable.chmod(0o700)
    dependency = SimpleNamespace(
        tool="node",
        chosen_version="24.19.0",
        executable_sha256=hashlib.sha256(payload).hexdigest(),
    )
    record = SimpleNamespace(
        tool="npm",
        target="x86_64-unknown-linux-gnu",
        lock_review_status="accepted",
        runtime_dependencies=(dependency,),
    )

    def accepted_lock(_path: Path) -> tuple[object, ...]:
        return (record,)

    monkeypatch.setattr(quality_gate_module, "load_lock", accepted_lock)

    assert validate_managed_node(tmp_path, executable) == executable


def test_managed_node_rejects_unbounded_open_and_hash_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "node"
    _ = executable.write_bytes(b"x")
    executable.chmod(0o700)
    dependency = SimpleNamespace(
        tool="node",
        chosen_version="24.19.0",
        executable_sha256="0" * SHA256_HEX_LENGTH,
    )
    record = SimpleNamespace(
        tool="npm",
        target="x86_64-unknown-linux-gnu",
        lock_review_status="accepted",
        runtime_dependencies=(dependency,),
    )

    def accepted_lock(_path: Path) -> tuple[object, ...]:
        return (record,)

    monkeypatch.setattr(quality_gate_module, "load_lock", accepted_lock)

    _ = executable.write_bytes(b"")
    with pytest.raises(GateError, match="bounded single-link regular file"):
        _ = validate_managed_node(tmp_path, executable)

    _ = executable.write_bytes(b"x")
    real_open = os.open

    def fail_executable_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == executable:
            raise OSError
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_executable_open)
    with pytest.raises(GateError, match="could not be opened"):
        _ = validate_managed_node(tmp_path, executable)

    monkeypatch.setattr(os, "open", real_open)
    monkeypatch.setattr(quality_gate_module, "_EXECUTABLE_LIMIT_BYTES", 1)
    real_read = os.read
    grew = False

    def growing_read(descriptor: int, amount: int) -> bytes:
        nonlocal grew
        if not grew:
            with executable.open("ab") as stream:
                _ = stream.write(b"yz")
            grew = True
        return real_read(descriptor, amount)

    monkeypatch.setattr(os, "read", growing_read)
    with pytest.raises(GateError, match="exceeds its byte limit"):
        _ = validate_managed_node(tmp_path, executable)

    _ = executable.write_bytes(b"x")
    monkeypatch.setattr(quality_gate_module, "_EXECUTABLE_LIMIT_BYTES", 1024)
    changed = False

    def changing_read(descriptor: int, amount: int) -> bytes:
        nonlocal changed
        chunk = real_read(descriptor, amount)
        if not changed:
            status = executable.stat()
            os.utime(
                executable,
                ns=(status.st_atime_ns, status.st_mtime_ns + 1_000_000_000),
            )
            changed = True
        return chunk

    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(GateError, match="changed while it was hashed"):
        _ = validate_managed_node(tmp_path, executable)


def test_bounded_runner_reports_spawn_and_signal_failures(tmp_path: Path) -> None:
    executable = Path(sys.executable).resolve().as_posix()
    cache = tmp_path.parent / f"{tmp_path.name}-cache"

    with pytest.raises(GateError, match="could not be started"):
        _ = run_bounded_command(
            (executable, "-c", "raise SystemExit(0)"),
            root=tmp_path / "missing",
            cache_dir=cache,
        )

    script = f"import os; os.kill(os.getpid(), {signal.SIGKILL})"
    with pytest.raises(GateError, match="terminated by signal"):
        _ = run_bounded_command(
            (executable, "-c", script),
            root=tmp_path,
            cache_dir=cache,
        )


def test_bounded_runner_times_out_after_a_child_closes_both_pipes(
    tmp_path: Path,
) -> None:
    script = "import os,time; os.close(1); os.close(2); time.sleep(5)"

    with pytest.raises(GateError, match="deadline"):
        _ = run_bounded_command(
            (Path(sys.executable).resolve().as_posix(), "-c", script),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
            policy=ExecutionPolicy(
                limits=ExecutionLimits(
                    timeout_seconds=0.1,
                    stdout_limit_bytes=1024,
                    stderr_limit_bytes=1024,
                )
            ),
        )


def test_exact_version_requires_nonempty_bytes_and_accepts_exact_output(
    tmp_path: Path,
) -> None:
    command = (
        Path(sys.executable).resolve().as_posix(),
        "-c",
        "print('tool 1.0')",
    )
    cache = tmp_path.parent / f"{tmp_path.name}-cache"

    with pytest.raises(GateError, match="immutable nonempty bytes"):
        verify_exact_version(
            command,
            expected_stdout=b"",
            root=tmp_path,
            cache_dir=cache,
        )

    verify_exact_version(
        command,
        expected_stdout=b"tool 1.0\n",
        root=tmp_path,
        cache_dir=cache,
    )


@pytest.mark.parametrize("head", [b"\xff\n", b"not-an-object-id\n"])
def test_git_snapshot_rejects_invalid_head_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    head: bytes,
) -> None:
    def fake_run(
        command: tuple[str, ...],
        *,
        root: Path,
        cache_dir: Path,
        **_kwargs: object,
    ) -> CommandResult:
        del root, cache_dir
        stdout = head if command[1:3] == ("rev-parse", "--verify") else b""
        return CommandResult(
            argv=command,
            returncode=0,
            stdout=stdout,
            stderr=b"",
        )

    monkeypatch.setattr(quality_gate_module, "run_bounded_command", fake_run)
    with pytest.raises(GateError, match="HEAD evidence"):
        _ = git_snapshot(tmp_path, tmp_path.parent / f"{tmp_path.name}-cache")


@pytest.mark.parametrize(
    ("returncode", "message"),
    [(None, "status is unavailable"), ("0", "invalid runtime type")],
)
def test_bounded_runner_rejects_invalid_process_status_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: object,
    message: str,
) -> None:
    process = SimpleNamespace(
        pid=123_456,
        returncode=returncode,
        poll=_completed_process_poll,
        wait=_completed_process_wait,
        kill=_ignore_process_kill,
    )

    def fake_popen(*_args: object, **_kwargs: object) -> object:
        return process

    def complete_capture(
        _process: object,
        *,
        limits: ExecutionLimits,
    ) -> tuple[bytes, bytes]:
        del limits
        return b"", b""

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(quality_gate_module, "_read_bounded_streams", complete_capture)
    monkeypatch.setattr(os, "killpg", _ignore_process_group_kill)

    with pytest.raises(GateError, match=message):
        _ = run_bounded_command(
            (Path(sys.executable).resolve().as_posix(),),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
        )


def test_bounded_runner_rejects_missing_capture_pipes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = SimpleNamespace(
        pid=123_456,
        returncode=0,
        stdout=None,
        stderr=None,
        poll=_completed_process_poll,
        wait=_completed_process_wait,
        kill=_ignore_process_kill,
    )

    def fake_popen(*_args: object, **_kwargs: object) -> object:
        return process

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(os, "killpg", _ignore_process_group_kill)

    with pytest.raises(GateError, match="pipes were not created"):
        _ = run_bounded_command(
            (Path(sys.executable).resolve().as_posix(),),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
        )


def test_bounded_runner_rejects_an_invalid_poll_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_descriptor, stdout_writer = os.pipe()
    stderr_descriptor, stderr_writer = os.pipe()
    stdout = os.fdopen(stdout_descriptor, "rb")
    stderr = os.fdopen(stderr_descriptor, "rb")
    process = SimpleNamespace(
        pid=123_456,
        returncode=0,
        stdout=stdout,
        stderr=stderr,
        poll=_completed_process_poll,
        wait=_completed_process_wait,
        kill=_ignore_process_kill,
    )

    def register(_descriptor: int, _events: int) -> None:
        return None

    def invalid_event(_timeout: int) -> list[tuple[int, int]]:
        return [(stdout_descriptor, select.POLLNVAL)]

    def unregister(_descriptor: int) -> None:
        return None

    poller = SimpleNamespace(
        register=register,
        poll=invalid_event,
        unregister=unregister,
    )

    def fake_popen(*_args: object, **_kwargs: object) -> object:
        return process

    def fake_poll() -> object:
        return poller

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(select, "poll", fake_poll)
    monkeypatch.setattr(os, "killpg", _ignore_process_group_kill)
    try:
        with pytest.raises(GateError, match="pipe became invalid"):
            _ = run_bounded_command(
                (Path(sys.executable).resolve().as_posix(),),
                root=tmp_path,
                cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
            )
    finally:
        os.close(stdout_writer)
        os.close(stderr_writer)


def test_bounded_runner_checks_deadline_before_polling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_descriptor, stdout_writer = os.pipe()
    stderr_descriptor, stderr_writer = os.pipe()
    process = SimpleNamespace(
        pid=123_456,
        returncode=0,
        stdout=os.fdopen(stdout_descriptor, "rb"),
        stderr=os.fdopen(stderr_descriptor, "rb"),
        poll=_completed_process_poll,
        wait=_completed_process_wait,
        kill=_ignore_process_kill,
    )
    samples = iter((0.0, 2.0))

    def monotonic() -> float:
        return next(samples, 2.0)

    def fake_popen(*_args: object, **_kwargs: object) -> object:
        return process

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(os, "killpg", _ignore_process_group_kill)
    try:
        with pytest.raises(GateError, match="deadline"):
            _ = run_bounded_command(
                (Path(sys.executable).resolve().as_posix(),),
                root=tmp_path,
                cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
                policy=ExecutionPolicy(
                    limits=ExecutionLimits(
                        timeout_seconds=1.0,
                        stdout_limit_bytes=1024,
                        stderr_limit_bytes=1024,
                    )
                ),
            )
    finally:
        os.close(stdout_writer)
        os.close(stderr_writer)


def test_bounded_runner_checks_deadline_after_both_pipes_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_descriptor, stdout_writer = os.pipe()
    stderr_descriptor, stderr_writer = os.pipe()
    os.close(stdout_writer)
    os.close(stderr_writer)
    process = SimpleNamespace(
        pid=123_456,
        returncode=0,
        stdout=os.fdopen(stdout_descriptor, "rb"),
        stderr=os.fdopen(stderr_descriptor, "rb"),
        poll=_completed_process_poll,
        wait=_completed_process_wait,
        kill=_ignore_process_kill,
    )
    samples = iter((0.0, 0.1, 2.0))

    def monotonic() -> float:
        return next(samples, 2.0)

    def register(_descriptor: int, _events: int) -> None:
        return None

    def closed_events(_timeout: int) -> list[tuple[int, int]]:
        return [
            (stdout_descriptor, select.POLLHUP),
            (stderr_descriptor, select.POLLHUP),
        ]

    def unregister(_descriptor: int) -> None:
        return None

    poller = SimpleNamespace(
        register=register,
        poll=closed_events,
        unregister=unregister,
    )

    def fake_popen(*_args: object, **_kwargs: object) -> object:
        return process

    def fake_poll() -> object:
        return poller

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(select, "poll", fake_poll)
    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(os, "killpg", _ignore_process_group_kill)

    with pytest.raises(GateError, match="deadline"):
        _ = run_bounded_command(
            (Path(sys.executable).resolve().as_posix(),),
            root=tmp_path,
            cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
            policy=ExecutionPolicy(
                limits=ExecutionLimits(
                    timeout_seconds=1.0,
                    stdout_limit_bytes=1024,
                    stderr_limit_bytes=1024,
                )
            ),
        )


def test_bounded_runner_escalates_when_group_wait_does_not_finish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    waits = 0
    killed = False

    def wait(*, timeout: float | None = None) -> int:
        nonlocal waits
        del timeout
        waits += 1
        if waits == 1:
            raise subprocess.TimeoutExpired(("tool",), 0.5)
        return 0

    def kill() -> None:
        nonlocal killed
        killed = True

    process = SimpleNamespace(
        pid=123_456,
        returncode=0,
        poll=_completed_process_poll,
        wait=wait,
        kill=kill,
    )

    def fake_popen(*_args: object, **_kwargs: object) -> object:
        return process

    def complete_capture(
        _process: object,
        *,
        limits: ExecutionLimits,
    ) -> tuple[bytes, bytes]:
        del limits
        return b"", b""

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(quality_gate_module, "_read_bounded_streams", complete_capture)
    monkeypatch.setattr(os, "killpg", _ignore_process_group_kill)

    result = run_bounded_command(
        (Path(sys.executable).resolve().as_posix(),),
        root=tmp_path,
        cache_dir=tmp_path.parent / f"{tmp_path.name}-cache",
    )

    assert result.returncode == 0
    assert killed is True
    assert waits == EXPECTED_WAIT_CALLS


@pytest.mark.parametrize("cache_kind", ["temporary", "external"])
def test_quality_gate_runs_versions_and_commands_in_an_isolated_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cache_kind: Literal["temporary", "external"],
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _populate_quality_root(root)
    cache = tmp_path / "cache" if cache_kind == "external" else None
    clean = GitSnapshot(
        head="f" * GIT_OBJECT_ID_LENGTH,
        staged_entries_sha256="a" * SHA256_HEX_LENGTH,
        refs_sha256="b" * SHA256_HEX_LENGTH,
        worktree_status_sha256="c" * SHA256_HEX_LENGTH,
        worktree_clean=True,
    )
    reviewed_node = tmp_path / "node"
    version_calls: list[tuple[tuple[str, ...], bytes, Path]] = []
    quality_calls: list[tuple[tuple[str, ...], ExecutionPolicy]] = []

    def registered_roots(_root: Path) -> tuple[Path, ...]:
        return (root,)

    def clean_snapshot(_root: Path, _cache: Path) -> GitSnapshot:
        return clean

    def reviewed_executable(_root: Path, _node: Path) -> Path:
        return reviewed_node

    def probes(_root: Path, _node: Path) -> tuple[VersionProbe, ...]:
        return (VersionProbe(("/version-tool",), b"tool 1\n"),)

    monkeypatch.setattr(
        quality_gate_module,
        "registered_worktree_roots",
        registered_roots,
    )
    monkeypatch.setattr(quality_gate_module, "git_snapshot", clean_snapshot)
    monkeypatch.setattr(
        quality_gate_module,
        "validate_managed_node",
        reviewed_executable,
    )
    monkeypatch.setattr(
        quality_gate_module,
        "version_probes",
        probes,
    )

    def fake_verify(
        command: tuple[str, ...],
        *,
        expected_stdout: bytes,
        root: Path,
        cache_dir: Path,
    ) -> None:
        del root
        version_calls.append((command, expected_stdout, cache_dir))

    commands = (
        ToolCommand(
            tool="ruff",
            version="0.16.3",
            python_target="3.12",
            diagnostic=False,
            argv=("/ruff", "check"),
        ),
        ToolCommand(
            tool="pyright",
            version="1.1.413",
            python_target="3.12",
            diagnostic=True,
            argv=("/node", "/pyright"),
        ),
    )

    def fake_command_plan(
        _root: Path,
        _paths: tuple[Path, ...],
        *,
        node_executable: Path,
    ) -> tuple[ToolCommand, ...]:
        assert node_executable == reviewed_node
        return commands

    def fake_run(
        command: tuple[str, ...],
        *,
        root: Path,
        cache_dir: Path,
        policy: ExecutionPolicy,
    ) -> CommandResult:
        assert root == (tmp_path / "repo")
        del cache_dir
        quality_calls.append((command, policy))
        return CommandResult(command, 0, b"", b"")

    monkeypatch.setattr(quality_gate_module, "verify_exact_version", fake_verify)
    monkeypatch.setattr(quality_gate_module, "command_plan", fake_command_plan)
    monkeypatch.setattr(quality_gate_module, "run_bounded_command", fake_run)

    quality_gate_module.run_quality_gate(
        root,
        QualityGateRequest(
            paths=(Path("src"), Path("tests"), Path("scripts"), Path("typings")),
            node_executable=reviewed_node,
            cache_dir=cache,
            expected_git_snapshot=clean,
        ),
    )

    assert len(version_calls) == 1
    assert [call[0] for call in quality_calls] == [command.argv for command in commands]
    assert quality_calls[0][1].allow_ascii_whitespace_stderr is False
    assert quality_calls[1][1].allow_ascii_whitespace_stderr is True
    used_cache = version_calls[0][2]
    assert used_cache.exists() is (cache_kind == "external")
    if cache is not None:
        assert used_cache == cache
        assert cache.stat().st_mode & 0o777 == PRIVATE_CACHE_MODE


def test_quality_gate_rejects_a_temporary_cache_inside_the_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()

    def registered_roots(_root: Path) -> tuple[Path, ...]:
        return (root,)

    monkeypatch.setattr(
        quality_gate_module,
        "registered_worktree_roots",
        registered_roots,
    )
    monkeypatch.setattr(tempfile, "tempdir", root.as_posix())

    with pytest.raises(GateError, match="cache intersects"):
        quality_gate_module.run_quality_gate(
            root,
            QualityGateRequest(
                paths=(Path("src"),),
                node_executable=tmp_path / "node",
                cache_dir=None,
                expected_git_snapshot=None,
            ),
        )


def test_quality_gate_rejects_checked_bytes_mutated_by_a_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _populate_quality_root(root)
    source = root / "src" / "a.py"
    _ = source.write_bytes(b"before\n")
    clean = GitSnapshot(
        head="f" * GIT_OBJECT_ID_LENGTH,
        staged_entries_sha256="a" * SHA256_HEX_LENGTH,
        refs_sha256="b" * SHA256_HEX_LENGTH,
        worktree_status_sha256="c" * SHA256_HEX_LENGTH,
        worktree_clean=True,
    )

    def mutate_source(_execution: object) -> None:
        _ = source.write_bytes(b"after\n")

    def registered_roots(_root: Path) -> tuple[Path, ...]:
        return (root,)

    def clean_snapshot(_root: Path, _cache: Path) -> GitSnapshot:
        return clean

    def reviewed_executable(_root: Path, node: Path) -> Path:
        return node

    def ignore_versions(_root: Path, _cache: Path, _node: Path) -> None:
        return None

    monkeypatch.setattr(
        quality_gate_module,
        "registered_worktree_roots",
        registered_roots,
    )
    monkeypatch.setattr(quality_gate_module, "git_snapshot", clean_snapshot)
    monkeypatch.setattr(
        quality_gate_module,
        "validate_managed_node",
        reviewed_executable,
    )
    monkeypatch.setattr(quality_gate_module, "_verify_versions", ignore_versions)
    monkeypatch.setattr(quality_gate_module, "_run_quality_commands", mutate_source)

    with pytest.raises(GateError, match="mutated checked repository bytes"):
        quality_gate_module.run_quality_gate(
            root,
            QualityGateRequest(
                paths=(Path("src"), Path("tests"), Path("scripts"), Path("typings")),
                node_executable=tmp_path / "node",
                cache_dir=None,
                expected_git_snapshot=None,
            ),
        )


def test_release_state_rejects_dirty_worktree_and_accepts_matching_clean_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clean = GitSnapshot(
        head="f" * GIT_OBJECT_ID_LENGTH,
        staged_entries_sha256="a" * SHA256_HEX_LENGTH,
        refs_sha256="b" * SHA256_HEX_LENGTH,
        worktree_status_sha256="c" * SHA256_HEX_LENGTH,
        worktree_clean=True,
    )
    dirty = GitSnapshot(
        head=clean.head,
        staged_entries_sha256=clean.staged_entries_sha256,
        refs_sha256=clean.refs_sha256,
        worktree_status_sha256="d" * SHA256_HEX_LENGTH,
        worktree_clean=False,
    )
    cache = tmp_path.parent / f"{tmp_path.name}-cache"

    def dirty_snapshot(_root: Path, _cache: Path) -> GitSnapshot:
        return dirty

    def clean_snapshot(_root: Path, _cache: Path) -> GitSnapshot:
        return clean

    monkeypatch.setattr(quality_gate_module, "git_snapshot", dirty_snapshot)
    with pytest.raises(GateError, match="requires a clean worktree"):
        _ = validate_release_state(tmp_path, cache, clean.head)

    monkeypatch.setattr(quality_gate_module, "git_snapshot", clean_snapshot)
    assert validate_release_state(tmp_path, cache, clean.head) == clean


def test_main_rejects_self_test_combined_with_gate_options() -> None:
    with pytest.raises(GateError, match="self-test cannot be combined"):
        _ = quality_gate_module.main(
            (
                "--node-executable",
                "/managed/bin/node",
                "--cache-dir",
                "/external/cache",
                "--self-test",
            )
        )


def test_main_routes_an_ordinary_gate_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[tuple[Path, QualityGateRequest]] = []

    def fake_gate(root: Path, request: QualityGateRequest) -> None:
        received.append((root, request))

    monkeypatch.setattr(quality_gate_module, "run_quality_gate", fake_gate)

    assert (
        quality_gate_module.main(
            (
                "--node-executable",
                "/managed/bin/node",
                "--worktree",
                tmp_path.as_posix(),
            )
        )
        == 0
    )
    assert len(received) == 1
    assert received[0][0] == tmp_path
    assert received[0][1].expected_git_snapshot is None


def test_direct_script_entrypoint_propagates_argument_parser_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "run_quality_gate.py"
    monkeypatch.setattr(sys, "argv", [script.as_posix()])

    with pytest.raises(SystemExit) as raised:
        _ = cast(
            "dict[str, object]", runpy.run_path(script.as_posix(), run_name="__main__")
        )

    assert raised.value.code == ARGPARSE_ERROR_EXIT


def test_quality_self_test_accepts_exact_diagnostics_and_rejects_them_in_final_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _populate_quality_root(root)
    clean = GitSnapshot(
        head="f" * GIT_OBJECT_ID_LENGTH,
        staged_entries_sha256="a" * SHA256_HEX_LENGTH,
        refs_sha256="b" * SHA256_HEX_LENGTH,
        worktree_status_sha256="c" * SHA256_HEX_LENGTH,
        worktree_clean=True,
    )
    reviewed_node = tmp_path / "node"

    def fake_run(
        command: tuple[str, ...],
        *,
        root: Path,
        cache_dir: Path,
        policy: ExecutionPolicy,
    ) -> CommandResult:
        del root, cache_dir
        if policy.allow_diagnostics:
            return CommandResult(command, 1, b"diagnostic", b"")
        message = "final mode rejected the diagnostic"
        raise GateError(message)

    def stable_fingerprint(_paths: Iterable[Path], *, root: Path) -> str:
        del root
        return "stable"

    def clean_snapshot(_root: Path, _cache: Path) -> GitSnapshot:
        return clean

    def reviewed_executable(_root: Path, _node: Path) -> Path:
        return reviewed_node

    def probes(_root: Path, _node: Path) -> tuple[VersionProbe, ...]:
        return (VersionProbe(("/version-tool",), b"tool 1\n"),)

    monkeypatch.setattr(
        quality_gate_module,
        "fingerprint_paths",
        stable_fingerprint,
    )
    monkeypatch.setattr(quality_gate_module, "git_snapshot", clean_snapshot)
    monkeypatch.setattr(
        quality_gate_module,
        "validate_managed_node",
        reviewed_executable,
    )
    monkeypatch.setattr(
        quality_gate_module,
        "version_probes",
        probes,
    )
    monkeypatch.setattr(
        quality_gate_module,
        "verify_exact_version",
        _ignore_version_check,
    )
    monkeypatch.setattr(quality_gate_module, "run_bounded_command", fake_run)

    quality_gate_module.run_self_test(root, reviewed_node)


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("diagnostic", "diagnostic result was not exact"),
        ("false-green", "accepted a diagnostic exit"),
        ("git", "mutated repository index"),
        ("temporary", "temporary state was not removed"),
        ("bytes", "mutated checked repository bytes"),
    ],
)
def test_quality_self_test_rejects_each_false_green_or_mutation_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    message: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _populate_quality_root(root)
    clean = GitSnapshot(
        head="f" * GIT_OBJECT_ID_LENGTH,
        staged_entries_sha256="a" * SHA256_HEX_LENGTH,
        refs_sha256="b" * SHA256_HEX_LENGTH,
        worktree_status_sha256="c" * SHA256_HEX_LENGTH,
        worktree_clean=True,
    )
    changed = GitSnapshot(
        head=clean.head,
        staged_entries_sha256=clean.staged_entries_sha256,
        refs_sha256=clean.refs_sha256,
        worktree_status_sha256="d" * SHA256_HEX_LENGTH,
        worktree_clean=False,
    )
    reviewed_node = tmp_path / "node"
    faults = _SelfTestFaults(scenario, clean, changed)

    def reviewed_executable(_root: Path, _node: Path) -> Path:
        return reviewed_node

    def probes(_root: Path, _node: Path) -> tuple[VersionProbe, ...]:
        return (VersionProbe(("/version-tool",), b"tool 1\n"),)

    monkeypatch.setattr(quality_gate_module, "fingerprint_paths", faults.fingerprint)
    monkeypatch.setattr(quality_gate_module, "git_snapshot", faults.snapshot)
    monkeypatch.setattr(
        quality_gate_module,
        "validate_managed_node",
        reviewed_executable,
    )
    monkeypatch.setattr(
        quality_gate_module,
        "version_probes",
        probes,
    )
    monkeypatch.setattr(
        quality_gate_module,
        "verify_exact_version",
        _ignore_version_check,
    )
    monkeypatch.setattr(quality_gate_module, "run_bounded_command", faults.run)
    if scenario == "temporary":
        leaked = tmp_path / "leaked-self-test"

        def leaky_temporary_directory(**_kwargs: object) -> nullcontext[str]:
            leaked.mkdir()
            return nullcontext(leaked.as_posix())

        monkeypatch.setattr(
            tempfile,
            "TemporaryDirectory",
            leaky_temporary_directory,
        )

    with pytest.raises(GateError, match=message):
        quality_gate_module.run_self_test(root, reviewed_node)
