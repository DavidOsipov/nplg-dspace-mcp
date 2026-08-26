# Copyright (c) 2026 David Osipov
"""Unit tests for the externally isolated killed-only mutation gate."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import stat
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

import scripts.run_mutation_gate as mutation_gate_module
from scripts.baseline_capture_io import ProcessLimits, run_bounded_process
from scripts.run_mutation_gate import (
    CommandRequest,
    CommandResult,
    MutationGateError,
    MutationGateRequest,
    MutationPolicy,
    cli,
    initial_mutation_policy,
    mutation_policy_for_targets,
    parse_arguments,
    parse_mutation_results,
    run_mutation_gate,
)
from scripts.run_quality_gate import run_bounded_command

if TYPE_CHECKING:
    from collections.abc import Buffer, Iterator, Mapping, Sequence

    from scripts.run_test_gate import Executor


_NO_TESTS_STATUS = 33
_EXPECTED_TARGETS = (
    "src/nplg_mcp/security.py",
    "src/nplg_mcp/tokens.py",
    "src/nplg_mcp/downloader.py",
    "src/nplg_mcp/storage.py",
    "src/nplg_mcp/errors.py",
    "scripts/delete_render.py",
    "scripts/smoke_live.py",
    "scripts/run_quality_gate.py",
)
_EXPECTED_MUTANT_COUNT = 139
_MINIMUM_KILLED_PERCENT = 65
_MUTATION_TIMEOUT_SECONDS = 1_800.0
_THIRD_ROOT_SCAN = 3
_NINTH_META_READ = 9
_TASK_SEVENTEEN_TARGETS = (
    "src/nplg_mcp/app.py",
    "src/nplg_mcp/http_types.py",
    "src/nplg_mcp/security.py",
    "src/nplg_mcp/network.py",
    "src/nplg_mcp/resilience.py",
    "src/nplg_mcp/downloader.py",
    "scripts/run_live_nplg_canary.py",
)
_TASK_SIXTEEN_A_TARGETS = (
    "src/nplg_mcp/malware.py",
    "src/nplg_mcp/downloader.py",
    "src/nplg_mcp/storage.py",
    "src/nplg_mcp/storage_lifecycle.py",
    "src/nplg_mcp/tools.py",
    "src/nplg_mcp/pdf_worker_client.py",
    "scripts/verify_scanner_container.py",
    "scripts/verify_pdf_worker_quota.py",
    "scripts/verify_private_recovery.py",
)
_EXPECTED_MODULES: dict[str, str] = {
    "src/nplg_mcp/security.py": "nplg_mcp.security",
    "src/nplg_mcp/tokens.py": "nplg_mcp.tokens",
    "src/nplg_mcp/downloader.py": "nplg_mcp.downloader",
    "src/nplg_mcp/storage.py": "nplg_mcp.storage",
    "src/nplg_mcp/errors.py": "nplg_mcp.errors",
    "scripts/delete_render.py": "scripts.delete_render",
    "scripts/smoke_live.py": "scripts.smoke_live",
    "scripts/run_quality_gate.py": "scripts.run_quality_gate",
}
_EXPECTED_LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "src/nplg_mcp/security.py": (
        "x__default_resolver",
        "x__invalid",
        "x__validate_origin",
        "x_build_item_url",
        "x_is_forbidden_address",
        "x_parse_handle_input",
        "x_resolve_approved_addresses",
        "x_validate_upstream_url",
    ),
    "src/nplg_mcp/tokens.py": (
        "x__b64decode",
        "x__b64encode",
        "x__validate_asset_claims",
        "x__validate_path",
        "x_sign_asset_token",
        "x_verify_asset_token",
    ),
    "src/nplg_mcp/downloader.py": ("x__validate_nplg_dns",),
    "src/nplg_mcp/storage.py": (
        "x__cleanup_render_tiles",
        "x__cleanup_tile_page",
        "x__fsync_directory",
        "x__remove_storage_path",
        "x__render_completion_exists",
        "x__sha256_path",
        "xǁContentAddressedStoreǁ__init__",
        "xǁContentAddressedStoreǁ_cache_full",
        "xǁContentAddressedStoreǁ_cleanup_incomplete_renders",
        "xǁContentAddressedStoreǁ_cleanup_stale_staging",
        "xǁContentAddressedStoreǁ_commit_staged_file",
        "xǁContentAddressedStoreǁ_commit_staged_render",
        "xǁContentAddressedStoreǁ_delete_render_subtree_locked",
        "xǁContentAddressedStoreǁ_discard_staged_file",
        "xǁContentAddressedStoreǁ_is_render_id",
        "xǁContentAddressedStoreǁ_release_staging_bytes",
        "xǁContentAddressedStoreǁ_render_lock_for",
        "xǁContentAddressedStoreǁ_render_tree_bytes",
        "xǁContentAddressedStoreǁ_reserve_staging_bytes",
        "xǁContentAddressedStoreǁ_scan_existing_bytes",
        "xǁContentAddressedStoreǁ_validate_filename",
        "xǁContentAddressedStoreǁ_validate_media_type",
        "xǁContentAddressedStoreǁ_validate_namespace",
        "xǁContentAddressedStoreǁ_validate_staged_identity",
        "xǁContentAddressedStoreǁ_validated_render_subtree",
        "xǁContentAddressedStoreǁbegin_render_transaction",
        "xǁContentAddressedStoreǁdelete_render_subtree",
        "xǁContentAddressedStoreǁput_bytes",
        "xǁContentAddressedStoreǁput_render_bytes",
        "xǁContentAddressedStoreǁresolve_asset",
        "xǁContentAddressedStoreǁstage",
        "xǁ_RenderTransactionǁ__init__",
        "xǁ_RenderTransactionǁcommit",
        "xǁ_RenderTransactionǁreset",
        "xǁ_RenderTransactionǁrollback",
        "xǁ_StagedWriterǁ__enter__",
        "xǁ_StagedWriterǁ__exit__",
        "xǁ_StagedWriterǁ__init__",
        "xǁ_StagedWriterǁ_snapshot",
        "xǁ_StagedWriterǁcommit",
        "xǁ_StagedWriterǁcommit_render",
        "xǁ_StagedWriterǁwrite",
    ),
    "src/nplg_mcp/errors.py": (
        "x__checked_string_total",
        "x__consume_public_detail_value",
        "x__internal_public_error",
        "x__snapshot_frame",
        "x__snapshot_public_details",
        "x__snapshot_scalar",
        "x__store_snapshot",
        "x_to_public_error",
        "x_validate_resource_uri",
    ),
    "scripts/delete_render.py": (
        "x__confirm",
        "x__default_dependencies",
        "x__default_processor_factory",
        "x__delete",
        "x__parse_arguments",
        "x__parser",
        "x__write_failure",
        "x__write_result",
        "x_main",
    ),
    "scripts/smoke_live.py": (
        "x__add_download_output",
        "x__add_render_output",
        "x__argument_failure",
        "x__arguments_from_values",
        "x__default_client_factory",
        "x__default_dependencies",
        "x__default_verifier",
        "x__object_list",
        "x__optional_string",
        "x__parse_args",
        "x__parser",
        "x__required_string",
        "x__run_smoke",
        "x__selected_handle",
        "x__write_failure",
        "x__write_output",
        "x_first_public_pdf",
        "x_main",
    ),
    "scripts/run_quality_gate.py": (
        "x__canonical_existing_worktree",
        "x__canonical_new_cache",
        "x__canonical_registered_worktrees",
        "x__checked_paths",
        "x__closed_environment",
        "x__consume_pipe_event",
        "x__decode_bounded_git_field",
        "x__expand",
        "x__expand_directory",
        "x__fail",
        "x__fingerprint_file",
        "x__inventory_files",
        "x__kill_process_group",
        "x__parse_registered_worktree_block",
        "x__parser",
        "x__paths_intersect",
        "x__read_bounded_streams",
        "x__resolve_inventory_input",
        "x__run_quality_commands",
        "x__selected_paths",
        "x__stable_regular_file_sha256",
        "x__stream_evidence",
        "x__validate_worktree_branch",
        "x__validate_worktree_optional_fields",
        "x__validated_executable",
        "x__validated_git_relative_path",
        "x__verify_versions",
        "x_cli",
        "x_command_plan",
        "x_fingerprint_paths",
        "x_freeze_input_inventory",
        "x_git_snapshot",
        "x_main",
        "x_parse_arguments",
        "x_parse_porcelain_status",
        "x_parse_registered_worktrees",
        "x_registered_worktree_roots",
        "x_run_bounded_command",
        "x_run_quality_gate",
        "x_run_self_test",
        "x_validate_external_cache",
        "x_validate_managed_node",
        "x_validate_release_arguments",
        "x_validate_release_state",
        "x_verify_exact_version",
        "x_version_probes",
    ),
}


class _Clock:
    def monotonic(self) -> float:
        return 0.0


class _SequenceClock:
    def __init__(self, values: Sequence[float]) -> None:
        super().__init__()
        self._values = iter(values)

    def monotonic(self) -> float:
        return next(self._values)


class _Filesystem:
    def read_bytes(self, path: Path) -> bytes:
        return path.read_bytes()


class _RealGit:
    def __init__(
        self,
        cache: Path,
        *,
        tree_defect_root: Path | None = None,
    ) -> None:
        super().__init__()
        self._cache = cache
        self._tree_defect_root = tree_defect_root

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> CommandResult:
        del environment
        if self._tree_defect_root == cwd and argv[1:] == (
            "rev-parse",
            "--verify",
            "HEAD^{tree}",
        ):
            return CommandResult(
                argv=argv,
                returncode=0,
                stdout=(b"0" * 40) + b"\n",
                stderr=b"",
            )
        result = run_bounded_command(argv, root=cwd, cache_dir=self._cache)
        return CommandResult(
            argv=result.argv,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


class _MutationExecutor:
    def __init__(
        self,
        policy: MutationPolicy,
        *,
        returncode: int = 0,
        meta_defect: str | None = None,
        raw_drift_repository: Path | None = None,
        workspace_defect: str | None = None,
    ) -> None:
        super().__init__()
        self._policy = policy
        self._returncode = returncode
        self._meta_defect = meta_defect
        self._raw_drift_repository = raw_drift_repository
        self._workspace_defect = workspace_defect
        self.requests: list[CommandRequest] = []

    def __call__(self, request: CommandRequest) -> CommandResult:
        self.requests.append(request)
        self._write_metadata(request.cwd)
        self._apply_meta_defect(request.cwd)
        self._apply_repository_drift()
        self._apply_workspace_defect(request.cwd)
        return CommandResult(
            argv=request.argv,
            returncode=self._returncode,
            stdout=b"synthetic mutmut output\n",
            stderr=b"",
        )

    def _write_metadata(self, workspace: Path) -> None:
        required = dict(self._policy.required_functions)
        for target in self._policy.targets:
            if self._meta_defect == "missing" and target == self._policy.targets[-1]:
                continue
            names = {f"{function}__mutmut_1": 1 for function in required[target]}
            destination = workspace / "mutants" / f"{target}.meta"
            destination.parent.mkdir(parents=True, exist_ok=True)
            _ = destination.write_bytes(_meta(json.dumps(names).encode()))

    def _apply_meta_defect(self, workspace: Path) -> None:
        if self._meta_defect == "extra":
            extra = workspace / "mutants" / "unexpected.py.meta"
            _ = extra.write_bytes(_meta(b'{"unexpected.x_bad__mutmut_1":1}'))
        elif self._meta_defect == "replaced":
            replaced = workspace / "mutants" / f"{self._policy.targets[-1]}.meta"
            replaced.unlink()
            replaced.symlink_to(
                workspace / "mutants" / f"{self._policy.targets[0]}.meta"
            )
        elif self._meta_defect == "empty":
            empty = workspace / "mutants" / f"{self._policy.targets[-1]}.meta"
            _ = empty.write_bytes(b"")

    def _apply_repository_drift(self) -> None:
        if self._raw_drift_repository is not None:
            object_directory = self._raw_drift_repository / ".git" / "objects" / "aa"
            object_directory.mkdir(exist_ok=True)
            _ = object_directory.joinpath("0" * 38).write_bytes(b"raw drift")

    def _apply_workspace_defect(self, workspace: Path) -> None:
        if self._workspace_defect == "late-input":
            _ = workspace.joinpath("tests", "late_conftest.py").write_text(
                "raise RuntimeError('late input executed')\n",
                encoding="utf-8",
            )
        elif self._workspace_defect == "replace-root":
            output = workspace.parent
            renamed = output.with_name(output.name + "-renamed")
            _ = output.rename(renamed)
            _ = shutil.copytree(renamed, output, symlinks=True)
        elif self._workspace_defect == "config-change":
            with workspace.joinpath("setup.cfg").open("ab") as stream:
                _ = stream.write(b"# changed\n")
        elif self._workspace_defect == "entry-bound":
            overflow = workspace / "overflow"
            overflow.mkdir()
            for index in range(129):
                overflow.joinpath(str(index)).touch()
        elif self._workspace_defect == "extra-output":
            _ = workspace.parent.joinpath("unexpected").write_bytes(b"unexpected\n")
        elif self._workspace_defect == "missing-output":
            workspace.parent.joinpath("cache").rmdir()
        elif self._workspace_defect == "replace-output-child":
            cache = workspace.parent / "cache"
            cache.rmdir()
            cache.mkdir(mode=0o750)
        elif self._workspace_defect == "source-drift":
            assert self._raw_drift_repository is not None
            source = self._raw_drift_repository / "pyproject.toml"
            _ = source.write_text(
                source.read_text(encoding="utf-8") + "# changed\n",
                encoding="utf-8",
            )


class _DescriptorBoundaryFault:
    def __init__(
        self,
        *,
        defect: str,
        output: Path,
        executor: _MutationExecutor,
    ) -> None:
        super().__init__()
        self._defect = defect
        self._output = output
        self._workspace = output / "snapshot"
        self._executor = executor
        self._original_open = os.open
        self._original_stat = os.stat
        self._armed = False
        self._triggered = False
        self._inventory_changed = False
        self._root_error = OSError("root open failure")
        self._child_error = OSError("child open failure")

    def execute(self, request: CommandRequest) -> CommandResult:
        result = self._executor(request)
        self._armed = True
        return result

    def open(
        self,
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        decoded = Path(os.fsdecode(path))
        root_descriptor = self._apply_root_fault(
            path,
            flags,
            mode,
            dir_fd=dir_fd,
            decoded=decoded,
        )
        if root_descriptor is not None:
            return root_descriptor
        self._apply_child_fault(dir_fd=dir_fd, decoded=decoded)
        return self._original_open(path, flags, mode, dir_fd=dir_fd)

    def _apply_root_fault(
        self,
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int,
        *,
        dir_fd: int | None,
        decoded: Path,
    ) -> int | None:
        if self._triggered or dir_fd is not None or decoded != self._output:
            return None
        if self._defect == "root-open":
            self._triggered = True
            raise self._root_error
        if self._defect != "root-replace":
            return None
        self._triggered = True
        descriptor = self._original_open(path, flags, mode, dir_fd=dir_fd)
        _ = self._output.rename(self._output.with_name(self._output.name + "-replaced"))
        self._output.mkdir(mode=0o700)
        return descriptor

    def _apply_child_fault(self, *, dir_fd: int | None, decoded: Path) -> None:
        if (
            self._triggered
            or not self._armed
            or dir_fd is None
            or decoded != Path("src")
        ):
            return
        self._triggered = True
        if self._defect == "child-open":
            raise self._child_error
        if self._defect == "child-replace":
            source = self._workspace / "src"
            _ = source.rename(self._workspace / "src-replaced")
            source.mkdir()

    def stat(
        self,
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if (
            self._armed
            and not self._inventory_changed
            and dir_fd is not None
            and not isinstance(path, int)
            and os.fsdecode(path) == "setup.cfg"
        ):
            self._inventory_changed = True
            policy_file = self._workspace / "setup.cfg"
            payload = policy_file.read_bytes()
            _ = policy_file.rename(self._workspace / "setup-original.cfg")
            _ = policy_file.write_bytes(payload)
        return self._original_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )


def _failing_executor(request: CommandRequest) -> CommandResult:
    del request
    error = OSError("executor failure")
    raise error


def _install_policy_create_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    original_open = os.open
    create_error = OSError("policy create failure")

    def fail_policy_create(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if Path(os.fsdecode(path)).name == "setup.cfg":
            raise create_error
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_policy_create)


def _install_policy_write_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    original_write = os.write

    def short_policy_write(descriptor: int, payload: Buffer) -> int:
        opened = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
        if opened.name == "setup.cfg":
            return 0
        return original_write(descriptor, payload)

    monkeypatch.setattr(os, "write", short_policy_write)


def _install_policy_read_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    original_fchmod = os.fchmod
    original_write = os.write

    def alter_policy_after_write(descriptor: int, mode: int) -> None:
        original_fchmod(descriptor, mode)
        opened = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
        if opened.name == "setup.cfg":
            _ = original_write(descriptor, b"# changed\n")

    monkeypatch.setattr(os, "fchmod", alter_policy_after_write)


def _external_boundary_executor(
    policy: MutationPolicy,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> Executor:
    if defect == "executor":
        return _failing_executor
    if defect == "create":
        _install_policy_create_fault(monkeypatch)
    elif defect == "write":
        _install_policy_write_fault(monkeypatch)
    elif defect == "policy-read":
        _install_policy_read_fault(monkeypatch)
    return _MutationExecutor(policy)


def _meta(exit_codes: bytes) -> bytes:
    names = tuple(
        part.split(b'"', maxsplit=1)[0] for part in exit_codes.split(b'"')[1::2]
    )
    duration_entries = b",".join(b'"' + name + b'":0.1' for name in names)
    functions = tuple(
        sorted({name.partition(b"__mutmut_")[0].rpartition(b".")[2] for name in names})
    )
    hash_entries = b",".join(b'"' + name + b'":"0123456789ab"' for name in functions)
    return (
        b'{"exit_code_by_key":'
        + exit_codes
        + b',"hash_by_function_name":{'
        + hash_entries
        + b'},"type_check_error_by_key":{},'
        + b'"durations_by_key":{'
        + duration_entries
        + b'},"estimated_durations_by_key":{'
        + duration_entries
        + b"}}"
    )


def _valid_payloads() -> list[tuple[str, bytes]]:
    payloads: list[tuple[str, bytes]] = []
    for target in _EXPECTED_TARGETS:
        names: dict[str, int] = {
            f"{_EXPECTED_MODULES[target]}.{function}__mutmut_1": 1
            for function in _EXPECTED_LOCAL_FUNCTIONS[target]
        }
        payloads.append((target, _meta(json.dumps(names).encode())))
    return payloads


def _git_command(root: Path, cache: Path, *arguments: str) -> bytes:
    result = run_bounded_command(
        ("/usr/bin/git", *arguments),
        root=root,
        cache_dir=cache,
    )
    return result.stdout


def _initialize_mutation_repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    cache = tmp_path / "git-cache"
    repository.mkdir()
    cache.mkdir(mode=0o700)
    _ = _git_command(repository, cache, "init", "-q", ".")
    for relative in initial_mutation_policy().targets:
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_text("def covered() -> int:\n    return 1\n", encoding="utf-8")
    tests = repository / "tests"
    tests.mkdir()
    _ = tests.joinpath("test_ok.py").write_text(
        "def test_ok() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    _ = repository.joinpath("pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
        encoding="utf-8",
    )
    _ = _git_command(repository, cache, "add", "--all")
    _ = _git_command(
        repository,
        cache,
        "-c",
        "user.name=NPLG Mutation Gate",
        "-c",
        "user.email=nplg-mutation-gate.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "base",
    )
    security = repository / "src" / "nplg_mcp" / "security.py"
    _ = security.write_text(
        security.read_text(encoding="utf-8") + "\nDIRTY = True\n",
        encoding="utf-8",
    )
    return repository.resolve(strict=True), cache.resolve(strict=True)


def _source_git_state(repository: Path, cache: Path) -> tuple[bytes, ...]:
    return tuple(
        _git_command(repository, cache, *arguments)
        for arguments in (
            ("rev-parse", "HEAD"),
            ("ls-files", "--stage", "-z"),
            ("show-ref", "--head", "--dereference"),
            ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        )
    )


def test_mutation_gate_records_are_immutable(tmp_path: Path) -> None:
    request = MutationGateRequest(
        worktree=tmp_path,
        output_dir=tmp_path.parent / "new-output",
        targets=("src/nplg_mcp/errors.py",),
    )

    with pytest.raises(FrozenInstanceError):
        request.__setattr__("targets", ())


@pytest.mark.parametrize("invocation", ["direct", "module"])
def test_mutation_gate_cli_is_available_from_both_supported_invocations(
    tmp_path: Path,
    invocation: str,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    del tmp_path
    python = sys.executable
    argv: tuple[str, ...]
    if invocation == "direct":
        argv = (
            python,
            (repository / "scripts" / "run_mutation_gate.py").as_posix(),
            "--help",
        )
    else:
        argv = (python, "-m", "scripts.run_mutation_gate", "--help")

    result = run_bounded_process(
        argv,
        cwd=repository,
        environment={
            "LANG": "C.UTF-8",
            "PATH": Path(sys.executable).parent.as_posix(),
            "PYTHONNOUSERSITE": "1",
        },
        limits=ProcessLimits(
            timeout_seconds=30.0,
            stdout_bytes=64 * 1024,
            stderr_bytes=64 * 1024,
        ),
    )

    assert result.returncode == 0
    assert result.stderr == b""
    assert b"usage:" in result.stdout
    assert b"--targets" in result.stdout


def test_mutation_gate_cli_rejects_incomplete_target_set_in_real_subprocess(
    tmp_path: Path,
) -> None:
    repository, _cache = _initialize_mutation_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    project = Path(__file__).resolve().parents[2]
    result = run_bounded_process(
        (
            sys.executable,
            "-m",
            "scripts.run_mutation_gate",
            "--worktree",
            repository.as_posix(),
            "--output-dir",
            output.as_posix(),
            "--targets",
            "src/nplg_mcp/sdk_boundary.py",
        ),
        cwd=project,
        environment={
            "LANG": "C.UTF-8",
            "PATH": Path(sys.executable).parent.as_posix(),
            "PYTHONNOUSERSITE": "1",
        },
        limits=ProcessLimits(
            timeout_seconds=30.0,
            stdout_bytes=64 * 1024,
            stderr_bytes=64 * 1024,
        ),
    )

    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == (
        b"mutation gate failed: mutation request does not match "
        b"the closed initial policy\n"
    )
    assert not output.exists()


def test_direct_script_help_runs_the_real_main_guard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = Path(__file__).resolve().parents[2]
    script = repository / "scripts" / "run_mutation_gate.py"
    original_path = sys.path.copy()
    monkeypatch.setattr(sys, "argv", [script.as_posix(), "--help"])

    try:
        with pytest.raises(SystemExit) as raised:
            _ = cast(
                "dict[str, object]",
                runpy.run_path(script.as_posix(), run_name="__main__"),
            )
    finally:
        sys.path[:] = original_path

    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "--targets" in captured.out
    assert captured.err == ""


def test_initial_mutation_policy_matches_the_independent_literal_oracle() -> None:
    policy = initial_mutation_policy()
    expected_functions = tuple(
        (
            target,
            tuple(
                f"{_EXPECTED_MODULES[target]}.{function}"
                for function in _EXPECTED_LOCAL_FUNCTIONS[target]
            ),
        )
        for target in _EXPECTED_TARGETS
    )

    assert policy.targets == _EXPECTED_TARGETS
    assert policy.killed_exit_codes == frozenset({1})
    assert policy.accepted_exit_codes == frozenset({-24, 0, 1, 33})
    assert policy.minimum_killed_percent == _MINIMUM_KILLED_PERCENT
    assert policy.required_functions == expected_functions


def test_phase_two_mutation_policies_are_closed_and_test_selected() -> None:
    task_nine_targets = (
        "src/nplg_mcp/contracts/base.py",
        "src/nplg_mcp/contracts/inputs.py",
        "src/nplg_mcp/contracts/outputs.py",
        "src/nplg_mcp/contracts/catalog.py",
        "src/nplg_mcp/tools.py",
    )
    task_ten_targets = (
        "src/nplg_mcp/contracts/schema.py",
        "scripts/export_contracts.py",
    )

    task_nine = mutation_policy_for_targets(task_nine_targets)
    task_ten = mutation_policy_for_targets(task_ten_targets)

    assert task_nine.targets == task_nine_targets
    assert task_nine.test_paths == (
        "tests/contracts/test_pydantic_contracts.py",
        "tests/property/test_contract_properties.py",
        "tests/unit/test_tools.py",
        (
            "tests/contracts/test_frozen_baseline.py::"
            "test_frozen_case_replays_through_parse_and_handle_against_independent_oracle"
        ),
    )
    assert dict(task_nine.required_functions)["src/nplg_mcp/contracts/outputs.py"] == ()
    assert task_ten.targets == task_ten_targets
    assert task_ten.test_paths == ("tests/contracts/test_zod_contracts.py",)
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets(tuple(reversed(task_ten_targets)))


def test_phase_three_mutation_policies_are_closed_and_test_selected() -> None:
    task_eleven_and_fourteen_targets = (
        "src/nplg_mcp/mcp_server.py",
        "src/nplg_mcp/sdk_boundary.py",
        "src/nplg_mcp/errors.py",
    )
    task_twelve_targets = ("src/nplg_mcp/errors.py",)
    task_thirteen_targets = (
        "src/nplg_mcp/sdk_boundary.py",
        "src/nplg_mcp/http_security.py",
        "src/nplg_mcp/json_preflight.py",
        "src/nplg_mcp/config.py",
        "src/nplg_mcp/app.py",
        "src/nplg_mcp/__main__.py",
    )

    task_eleven_and_fourteen = mutation_policy_for_targets(
        task_eleven_and_fourteen_targets
    )
    task_twelve = mutation_policy_for_targets(task_twelve_targets)
    task_thirteen = mutation_policy_for_targets(task_thirteen_targets)

    assert task_eleven_and_fourteen.targets == task_eleven_and_fourteen_targets
    assert task_eleven_and_fourteen.test_paths == (
        "tests/contracts/test_sdk_client.py",
        "tests/contracts/test_sdk_boundary.py",
        "tests/contracts/test_sdk_parity.py",
        "tests/conformance/test_mcp_http.py",
        "tests/unit/test_errors.py",
    )
    assert task_eleven_and_fourteen.deselected_tests == (
        "tests/unit/test_errors.py::test_detail_mapping_growth_during_copy_fails_closed",
        "tests/unit/test_errors.py::test_detail_list_growth_during_copy_fails_closed",
    )
    phase_three_functions = dict(task_eleven_and_fourteen.required_functions)
    assert phase_three_functions["src/nplg_mcp/mcp_server.py"] == (
        "nplg_mcp.mcp_server.x_create_mcp_server",
    )
    assert phase_three_functions["src/nplg_mcp/sdk_boundary.py"] == (
        "nplg_mcp.sdk_boundary.x__adapt_resource",
        "nplg_mcp.sdk_boundary.x__binding_for_tool",
        "nplg_mcp.sdk_boundary.x__serialized_output",
    )
    assert phase_three_functions["src/nplg_mcp/errors.py"] == (
        "nplg_mcp.errors.x__checked_string_total",
        "nplg_mcp.errors.x__consume_public_detail_value",
        "nplg_mcp.errors.x__internal_public_error",
        "nplg_mcp.errors.x__snapshot_frame",
        "nplg_mcp.errors.x__snapshot_public_details",
        "nplg_mcp.errors.x__snapshot_scalar",
        "nplg_mcp.errors.x__store_snapshot",
        "nplg_mcp.errors.x_to_public_error",
        "nplg_mcp.errors.x_validate_resource_uri",
    )
    assert task_twelve.targets == task_twelve_targets
    assert task_twelve.test_paths == ("tests/contracts/test_sdk_parity.py",)
    assert task_thirteen.targets == task_thirteen_targets
    assert task_thirteen.test_paths == (
        "tests/conformance/test_mcp_http.py",
        "tests/contracts/test_sdk_parity.py",
        "tests/security/test_auth_activation.py",
        "tests/unit/test_app_lifespan.py",
        "tests/unit/test_json_preflight.py",
        "tests/property/test_json_preflight_properties.py",
        "tests/unit/test_config.py",
    )
    task_thirteen_functions = dict(task_thirteen.required_functions)
    assert {
        "nplg_mcp.app.x__reject_distributed_full",
        "nplg_mcp.app.x__reject_unavailable_production_oauth",
        "nplg_mcp.app.x__validate_production_auth_activation",
    }.issubset(task_thirteen_functions["src/nplg_mcp/app.py"])
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets(tuple(reversed(task_thirteen_targets)))


def test_task_seventeen_mutation_policy_selects_exact_security_suite() -> None:
    """Mutation caught: Task 17 falling through to another phase's test policy."""
    policy = mutation_policy_for_targets(_TASK_SEVENTEEN_TARGETS)

    assert policy.targets == _TASK_SEVENTEEN_TARGETS
    assert policy.test_paths == (
        "tests/security/test_ssrf_binding.py",
        "tests/unit/test_upstream_resilience.py",
        "tests/unit/test_live_nplg_canary.py",
        "tests/security/test_downloader.py",
        "tests/integration/test_repository.py",
        "tests/conformance/test_mcp_http.py",
    )
    assert policy.deselected_tests == (
        (
            "tests/integration/test_repository.py::"
            "test_live_nplg_canary_uses_bound_public_endpoint"
        ),
    )


def test_task_sixteen_a_mutation_policy_is_exact_closed_and_recovery_selected() -> None:
    """Task 16A's documented command must select its complete adversarial suite."""
    policy = mutation_policy_for_targets(_TASK_SIXTEEN_A_TARGETS)

    assert policy.targets == _TASK_SIXTEEN_A_TARGETS
    assert policy.test_paths == (
        "tests/unit/test_scanner_container_verifier.py",
        "tests/unit/test_pdf_worker_quota_verifier.py",
        "tests/unit/test_private_recovery_verifier.py",
        "tests/security/test_malware.py",
        "tests/security/test_downloader.py",
        "tests/security/test_pdf_worker.py",
        "tests/security/test_pdf_adversarial_corpus_worker.py",
        "tests/unit/test_pdf_worker_client_edges.py",
        "tests/unit/test_storage.py",
        "tests/unit/test_storage_internals.py",
        "tests/unit/test_storage_transaction_atomicity.py",
        "tests/property/test_storage_properties.py",
        "tests/unit/test_storage_lifecycle.py",
        "tests/unit/test_pdf_publication_reservation.py",
        "tests/unit/test_tools.py",
        "tests/integration/test_pdf.py",
        "tests/static/test_deployment.py",
    )
    assert policy.deselected_tests == ()
    required = dict(policy.required_functions)
    storage_required = set(required["src/nplg_mcp/storage.py"])
    assert {
        (
            "nplg_mcp.storage."
            "xǁContentAddressedStoreǁ_activate_publication_reservation_locked"
        ),
        (
            "nplg_mcp.storage."
            "xǁContentAddressedStoreǁ_commit_publication_reservation_locked"
        ),
        "nplg_mcp.storage.xǁContentAddressedStoreǁ_finish_prune_locked",
        (
            "nplg_mcp.storage."
            "xǁContentAddressedStoreǁ_register_render_transaction_locked"
        ),
        "nplg_mcp.storage.x__current_async_task",
        ("nplg_mcp.storage.xǁContentAddressedStoreǁ_invoke_render_transaction_guard"),
        (
            "nplg_mcp.storage."
            "xǁContentAddressedStoreǁ_require_render_mutation_authority_locked"
        ),
        (
            "nplg_mcp.storage."
            "xǁContentAddressedStoreǁ_require_render_transaction_destination"
        ),
        "nplg_mcp.storage.xǁContentAddressedStoreǁ_stage_render_transaction",
        ("nplg_mcp.storage.xǁ_RenderTransactionǁ_require_active_owner_context"),
        "nplg_mcp.storage.xǁ_RenderTransactionǁ_require_owner_context",
        "nplg_mcp.storage.xǁ_RenderTransactionǁstage",
    } <= storage_required
    assert required["scripts/verify_private_recovery.py"] == (
        "scripts.verify_private_recovery.x__reject_duplicate_names",
        "scripts.verify_private_recovery.x__reject_noninteger_number",
        "scripts.verify_private_recovery.x__bounded_json_integer",
        "scripts.verify_private_recovery.x__require_canonical_receipt",
        "scripts.verify_private_recovery.x__require_receipt_digest",
        "scripts.verify_private_recovery.x__parse_recovery_receipt",
        "scripts.verify_private_recovery.x__validated_policy",
        "scripts.verify_private_recovery.x__bind_receipt",
        "scripts.verify_private_recovery.x_verify",
    )
    lifecycle_prefix = "nplg_mcp.storage_lifecycle."
    assert tuple(
        function.removeprefix(lifecycle_prefix)
        for function in required["src/nplg_mcp/storage_lifecycle.py"]
    ) == (
        "x__has_private_state_metadata",
        "x__prepare_private_state_descriptor",
        "x__system_utc_now",
        "x__read_boot_identity_unchecked",
        "x__read_boot_identity",
        "xǁSystemRetentionClockǁ__init__",
        "xǁSystemRetentionClockǁ__call__",
        "xǁInsertionSequenceRecordǁbuild",
        "xǁInsertionHighWaterRecordǁbuild",
        "xǁPublicationReservationErrorǁ__init__",
        "x_validate_retention_capacity",
        "x_filesystem_capacity",
        "x__canonical_json_bytes",
        "x__json_digest",
        "x__clock_record",
        "x__reject_duplicate_keys",
        "xǁClockHighWaterǁ__init__",
        "xǁClockHighWaterǁ_read",
        "xǁClockHighWaterǁ_write",
        "xǁClockHighWaterǁ_assessment",
        "xǁClockHighWaterǁ_baseline",
        "xǁClockHighWaterǁobserve",
        "x__read_private_record",
        "x__write_private_record",
        "x__insertion_object_key",
        "xǁPersistentInsertionOrderǁ__init__",
        "xǁPersistentInsertionOrderǁ_validated_object_path",
        "xǁPersistentInsertionOrderǁ_write_high_water",
        "xǁPersistentInsertionOrderǁ_allocate",
        "xǁPersistentInsertionOrderǁ_load_object_sequence",
        "xǁPersistentInsertionOrderǁinitialize",
        "xǁPersistentInsertionOrderǁensure",
        "xǁPersistentInsertionOrderǁsequence_for",
        "xǁPersistentInsertionOrderǁremove",
    )
    assert all(required[target] for target in _TASK_SIXTEEN_A_TARGETS)
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets(tuple(reversed(_TASK_SIXTEEN_A_TARGETS)))
    partial_targets = cast("tuple[str, ...]", _TASK_SIXTEEN_A_TARGETS[:-1])
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets(partial_targets)


def test_task_eighteen_mutation_policy_selects_exact_parser_suite() -> None:
    """Mutation caught: Task 18 falling through the closed target registry."""
    targets = (
        "src/nplg_mcp/parsers.py",
        "src/nplg_mcp/repository.py",
        "src/nplg_mcp/tokens.py",
    )

    policy = mutation_policy_for_targets(targets)

    assert policy.targets == targets
    assert policy.test_paths == (
        "tests/unit/test_parsers.py",
        "tests/integration/test_repository.py",
        "tests/property/test_parser_properties.py",
    )
    assert policy.deselected_tests == ()
    mutation_configuration = mutation_gate_module._mutation_configuration(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        policy
    )
    assert b"--deselect" not in mutation_configuration
    required = {
        target: frozenset(name.removeprefix(f"{module}.") for name in names)
        for (target, names), module in zip(
            policy.required_functions,
            ("nplg_mcp.parsers", "nplg_mcp.repository", "nplg_mcp.tokens"),
            strict=True,
        )
    }
    assert required == {
        "src/nplg_mcp/parsers.py": frozenset(
            {
                "x__bitstream_id",
                "x__canonical_item_from_href",
                "x__class_contains",
                "x__collections",
                "x__dc_fields",
                "x__dim_fields",
                "x__extract_handle",
                "x__field_values",
                "x__first_descendant",
                "x__full_fields",
                "x__has_full_metadata_text",
                "x__has_next_page_class",
                "x__has_search_results_class",
                "x__html_attribute_text",
                "x__html_field_code_points",
                "x__html_semantic_text_code_points",
                "x__local_name",
                "x__match_group",
                "x__next_search_offset",
                "x__normalize",
                "x__normalize_date",
                "x__oai_fields",
                "x__parse_bitstreams",
                "x__parse_size",
                "x__parse_xml",
                "x__preflight_html",
                "x__preflight_xml",
                "x__raise_for_oai_error",
                "x__record_from_fields",
                "x__require_exact_owned_child",
                "x__require_preflight_agreement",
                "x__saturating_increment",
                "x__search_columns",
                "x__search_items",
                "x__search_total",
                "x__summary_fields",
                "x__tag_attribute",
                "x__tag_text",
                "x__unique",
                "x__upstream_failure",
                "x__validate_html_tree",
                "x__validate_oai_identifier",
                "x__validate_text_budget",
                "x__validate_xml_tree",
                "x_parse_item_page",
                "x_parse_metadata_formats",
                "x_parse_oai_record",
                "x_parse_search_results",
                "xǁ_HtmlBudgetParserǁ__init__",
                "xǁ_HtmlBudgetParserǁ_add_attributes",
                "xǁ_HtmlBudgetParserǁ_add_element",
                "xǁ_HtmlBudgetParserǁ_add_text",
                "xǁ_HtmlBudgetParserǁcheck_deadline",
            }
        ),
        "src/nplg_mcp/repository.py": frozenset(
            {
                "x__canonical_search_query",
                "x__publish_metadata_formats",
                "x__record_dns_app_error",
                "x__record_transport_error",
                "x__require_metadata_prefix",
                "x__validate_nplg_dns",
                "x_decode_cursor",
                "x_encode_cursor",
            }
        ),
        "src/nplg_mcp/tokens.py": frozenset(
            {
                "x__b64decode",
                "x__b64encode",
                "x__reject_duplicate_cursor_keys",
                "x__require_matching_signature",
                "x__validate_asset_claims",
                "x__validate_path",
                "x_cursor_query_hash",
                "x_derive_cursor_signing_key",
                "x_sign_asset_token",
                "x_sign_cursor",
                "x_verify_asset_token",
                "x_verify_cursor",
            }
        ),
    }
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets(tuple(reversed(targets)))


def test_task_nineteen_profile_mutation_policy_is_exact_and_closed() -> None:
    """Mutation caught: profile mutation falls through to a broader test policy."""
    target = "src/nplg_mcp/profiles.py"

    policy = mutation_policy_for_targets((target,))

    assert policy.targets == (target,)
    assert policy.test_paths == (
        "tests/integration/test_profiles.py",
        "tests/contracts/test_sdk_client.py",
        "tests/unit/test_config.py",
    )
    assert policy.deselected_tests == ()
    assert policy.required_functions == (
        (target, ("nplg_mcp.profiles.x_tool_names_for_profile",)),
    )
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets((target, "src/nplg_mcp/capabilities.py"))


def test_task_twenty_one_a_capability_mutation_policy_is_exact_and_closed() -> None:
    """Mutation caught: capability mutants or their selected suites drift."""
    target = "src/nplg_mcp/capabilities.py"
    local_functions = (
        "x__body_evidence",
        "x__canonical_bytes",
        "x__canonical_negative_alpic_tasks_blockers",
        "x__decode_base64",
        "x__expected_dispatch_response",
        "x__expected_error_response",
        "x__expected_initialize_request",
        "x__expected_tool_request",
        "x__finalize",
        "x__header_values",
        "x__headers",
        "x__initialize_body",
        "x__load",
        "x__load_alpic_tasks_contract",
        "x__model_json",
        "x__observe_alpic_local_sdk",
        "x__observe_http_case",
        "x__observe_sdk_matrix",
        "x__package_file_sha256",
        "x__package_tree_sha256",
        "x__parse_bearer_challenge",
        "x__raw_request",
        "x__reject_duplicate_pairs",
        "x__sdk_probe_app",
        "x__sdk_tasks_public_api_available",
        "x__sha256_json",
        "x__tool_call_body",
        "x__tool_headers",
        "x_canonical_json_sha256",
        "x_canonical_model_json",
        "x_load_alpic_tasks_source_evidence",
        "x_load_alpic_tasks_verdict",
        "x_load_alpic_verdict",
        "x_load_provider_verdict",
        "x_load_sdk_verdict",
        "x_probe_alpic_oauth_discovery",
        "x_probe_alpic_tasks_capability",
        "x_probe_oauth_provider",
        "x_probe_sdk_authorization",
        "x_validate_alpic_tasks_verdict_json",
        "x_validate_synthetic_alpic_tasks_verdict",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_http_semantics",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_installed_identity",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_matrix_digests",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_matrix_identity",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_support_decision",
        "xǁ_FixtureDispatchCounterǁ__init__",
        "xǁ_FixtureDispatchCounterǁcall_tool",
        "xǁ_FixtureProbeStateǁ__init__",
        "xǁ_FixtureTokenVerifierǁ__init__",
        "xǁ_FixtureTokenVerifierǁverify_token",
    )

    policy = mutation_policy_for_targets((target,))

    assert policy.targets == (target,)
    assert policy.test_paths == (
        "tests/contracts/test_sdk_auth_feasibility.py",
        "tests/contracts/test_alpic_oauth_discovery.py",
        "tests/contracts/test_oauth_provider_capability.py",
        "tests/contracts/test_alpic_tasks_capability.py",
        "tests/unit/test_probe_alpic_tasks_capability.py",
        "tests/integration/test_profiles.py",
    )
    assert policy.deselected_tests == ()
    assert policy.required_functions == (
        (
            target,
            tuple(f"nplg_mcp.capabilities.{function}" for function in local_functions),
        ),
    )
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets((target, "src/nplg_mcp/profiles.py"))


def test_task_twenty_two_mutation_policy_selects_exact_release_loader_suites() -> None:
    """Mutation caught: Task 22 accepts an arbitrary or untested target."""
    targets = ("scripts/verify_release.py",)

    policy = mutation_policy_for_targets(targets)

    assert policy.targets == targets
    assert policy.test_paths == ("tests/static/test_release_gate.py",)
    assert policy.deselected_tests == ()
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets((*targets, "scripts/run_mutation_gate.py"))


def test_task_twenty_two_mutation_metadata_requires_exact_observed_inventory() -> None:
    """Mutation caught: Task 22 silently accepts stale or incomplete metadata."""
    target = "scripts/verify_release.py"
    module = "scripts.verify_release"
    local_functions: tuple[str, ...] = (
        "x__dependency_window",
        "x__duplicate_json_name",
        "x__external_requirements",
        "x__fail",
        "x__fail_from",
        "x__gate_command",
        "x__load_json_object",
        "x__load_model",
        "x__parser",
        "x__reject_json_number",
        "x__source_entry",
        "x__trusted_python_gate_command",
        "x__trusted_release_tool_proof",
        "x__unsafe_command_text",
        "x__utc_timestamp",
        "x__valid_closed_python_tool_success",
        "x__valid_success_evidence",
        "x__validate_dependency_evidence_identity",
        "x__validate_dependency_exception",
        "x__validate_dependency_finding",
        "x__validate_pyright_runtime_identity",
        "x_assert_source_snapshot",
        "x_candidate_release_status",
        "x_capture_source_descriptor_snapshot",
        "x_cli",
        "x_load_dependency_evidence",
        "x_load_dependency_risk_policy",
        "x_load_release_command_manifest",
        "x_load_release_controller_policy",
        "x_load_release_policies",
        "x_load_trivy_database_receipt",
        "x_load_trusted_package_sources_policy",
        "x_local_gate_commands",
        "x_main",
        "x_materialize_source",
        "x_release_command_manifest_digest",
        "x_run_gate_battery",
        "x_run_local_gates",
        "x_validate_candidate_contract_transcript",
        "x_validate_external_gate_manifest_join",
        "x_write_source_snapshot",
        "x\u01c1SystemCommandRunner\u01c1__call__",
    )
    policy = mutation_policy_for_targets((target,))
    expected_functions = tuple(f"{module}.{function}" for function in local_functions)

    assert policy.required_functions == ((target, expected_functions),)

    def payload_for(functions: tuple[str, ...]) -> tuple[tuple[str, bytes], ...]:
        statuses = {f"{module}.{function}__mutmut_1": 1 for function in functions}
        return ((target, _meta(json.dumps(statuses).encode())),)

    summary = parse_mutation_results(payload_for(local_functions))
    assert summary.total == len(local_functions)
    assert summary.killed == len(local_functions)

    with pytest.raises(MutationGateError, match="unexpected generated functions"):
        _ = parse_mutation_results(payload_for(local_functions[1:]))
    with pytest.raises(MutationGateError, match="unexpected generated functions"):
        _ = parse_mutation_results(
            payload_for((*local_functions, "x_unexpected_generated_function"))
        )


def test_phase_three_mutation_metadata_accepts_only_exact_generated_functions() -> None:
    targets = (
        "src/nplg_mcp/mcp_server.py",
        "src/nplg_mcp/sdk_boundary.py",
        "src/nplg_mcp/errors.py",
    )
    modules = {
        targets[0]: "nplg_mcp.mcp_server",
        targets[1]: "nplg_mcp.sdk_boundary",
        targets[2]: "nplg_mcp.errors",
    }
    local_functions: dict[str, tuple[str, ...]] = {
        targets[0]: ("x_create_mcp_server",),
        targets[1]: (
            "x__adapt_resource",
            "x__binding_for_tool",
            "x__serialized_output",
        ),
        targets[2]: (
            "x__checked_string_total",
            "x__consume_public_detail_value",
            "x__internal_public_error",
            "x__snapshot_frame",
            "x__snapshot_public_details",
            "x__snapshot_scalar",
            "x__store_snapshot",
            "x_to_public_error",
            "x_validate_resource_uri",
        ),
    }

    def payloads_for(
        functions: dict[str, tuple[str, ...]],
    ) -> tuple[tuple[str, bytes], ...]:
        payloads: list[tuple[str, bytes]] = []
        for target in targets:
            statuses: dict[str, int] = {
                f"{modules[target]}.{function}__mutmut_1": 1
                for function in functions[target]
            }
            payloads.append((target, _meta(json.dumps(statuses).encode())))
        return tuple(payloads)

    expected_count = sum(len(functions) for functions in local_functions.values())
    summary = parse_mutation_results(payloads_for(local_functions))
    assert summary.total == expected_count
    assert summary.killed == expected_count

    unexpected = dict(local_functions)
    unexpected[targets[1]] = (*local_functions[targets[1]], "x_any_sdk_function")
    with pytest.raises(MutationGateError, match="unexpected generated functions"):
        _ = parse_mutation_results(payloads_for(unexpected))


@pytest.mark.parametrize(
    "targets",
    [
        cast("tuple[str, ...]", ["src/nplg_mcp/contracts/schema.py"]),
        cast("tuple[str, ...]", ("src/nplg_mcp/contracts/schema.py", 1)),
    ],
)
def test_mutation_policy_registry_rejects_malformed_runtime_target_types(
    targets: tuple[str, ...],
) -> None:
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = mutation_policy_for_targets(targets)


def test_phase_two_mutation_metadata_rejects_non_object_result_map() -> None:
    targets = (
        "src/nplg_mcp/contracts/schema.py",
        "scripts/export_contracts.py",
    )
    payloads = (
        (targets[0], _meta(b"[]")),
        (targets[1], _meta(b"{}")),
    )

    with pytest.raises(MutationGateError, match="results are malformed"):
        _ = parse_mutation_results(payloads)


def test_run_mutation_gate_rejects_malformed_request_before_repository_access() -> None:
    targets = (
        "src/nplg_mcp/contracts/schema.py",
        "scripts/export_contracts.py",
    )
    executor = _MutationExecutor(mutation_policy_for_targets(targets))
    clock = _Clock()
    filesystem = _Filesystem()
    git = cast("_RealGit", object())

    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=cast("Path", "not-a-path"),
                output_dir=None,
                targets=targets,
            ),
            executor=executor,
            clock=clock,
            filesystem=filesystem,
            git=git,
        )
    with pytest.raises(MutationGateError, match="closed initial policy"):
        _ = run_mutation_gate(
            cast("MutationGateRequest", object()),
            executor=executor,
            clock=clock,
            filesystem=filesystem,
            git=git,
        )


def test_mutation_result_parser_reaches_behavioral_red() -> None:
    exit_codes: dict[str, dict[str, int]] = {
        target: {
            f"{_EXPECTED_MODULES[target]}.{function}__mutmut_1": 1
            for function in _EXPECTED_LOCAL_FUNCTIONS[target]
        }
        for target in _EXPECTED_TARGETS
    }
    payloads = tuple(
        (
            target,
            _meta(json.dumps(exit_codes[target]).encode()),
        )
        for target in _EXPECTED_TARGETS
    )
    expected_mutants = 139

    summary = parse_mutation_results(payloads)

    assert summary.total == expected_mutants
    assert summary.killed == expected_mutants


def _mutation_payloads_with_statuses(
    statuses: list[int],
) -> tuple[tuple[str, bytes], ...]:
    payloads = _valid_payloads()
    pending = iter(statuses)
    exhausted = False
    for index, (target, payload) in enumerate(payloads):
        document = cast("dict[str, object]", json.loads(payload))
        exit_codes = cast("dict[str, int]", document["exit_code_by_key"])
        durations = cast("dict[str, float]", document["durations_by_key"])
        for mutant in exit_codes:
            try:
                status = next(pending)
            except StopIteration:
                exhausted = True
                break
            exit_codes[mutant] = status
            if status == _NO_TESTS_STATUS:
                _ = durations.pop(mutant)
        payloads[index] = (
            target,
            json.dumps(document, separators=(",", ":")).encode(),
        )
        if exhausted:
            break
    return tuple(payloads)


def test_mutation_result_parser_enforces_closed_statuses_and_kill_floor() -> None:
    summary = parse_mutation_results(
        _mutation_payloads_with_statuses([0, 33, -24]),
    )
    assert summary.total == _EXPECTED_MUTANT_COUNT
    assert summary.killed == _EXPECTED_MUTANT_COUNT - 3

    with pytest.raises(MutationGateError, match="kill floor"):
        _ = parse_mutation_results(_mutation_payloads_with_statuses([0] * 49))


@pytest.mark.parametrize(
    "defect",
    [
        "wrong-module",
        "status-3",
        "extra-decorated",
        "missing-function",
        "target-order",
        "duplicate-mutant",
    ],
)
def test_mutation_results_reject_closed_policy_faults(defect: str) -> None:
    exit_codes = {
        target: {
            f"{_EXPECTED_MODULES[target]}.{function}__mutmut_1": 1
            for function in _EXPECTED_LOCAL_FUNCTIONS[target]
        }
        for target in _EXPECTED_TARGETS
    }
    security = "src/nplg_mcp/security.py"
    tokens = "src/nplg_mcp/tokens.py"
    downloader = "src/nplg_mcp/downloader.py"
    if defect == "wrong-module":
        first = next(iter(exit_codes[security]))
        _ = exit_codes[security].pop(first)
        storage_key = next(iter(exit_codes["src/nplg_mcp/storage.py"]))
        exit_codes[security][storage_key] = 1
    elif defect == "status-3":
        first = next(iter(exit_codes[security]))
        exit_codes[security][first] = 3
    elif defect == "extra-decorated":
        unexpected = "nplg_mcp.downloader.xǁDocumentDownloaderǁfetch__mutmut_1"
        exit_codes[downloader][unexpected] = 1
    elif defect == "missing-function":
        first = next(iter(exit_codes[security]))
        _ = exit_codes[security].pop(first)
    elif defect == "duplicate-mutant":
        first_token = next(iter(exit_codes[tokens]))
        _ = exit_codes[tokens].pop(first_token)
        repeated = next(iter(exit_codes[security]))
        exit_codes[tokens][repeated] = 1
    payloads = tuple(
        (target, _meta(json.dumps(exit_codes[target]).encode()))
        for target in _EXPECTED_TARGETS
    )
    if defect == "target-order":
        payloads = tuple(reversed(payloads))

    with pytest.raises(MutationGateError):
        _ = parse_mutation_results(payloads)


@pytest.mark.parametrize(
    "defect",
    [
        "empty",
        "invalid-utf8",
        "malformed-json",
        "duplicate-key",
        "nonfinite-constant",
        "nonfinite-float",
        "oversized-integer",
        "non-object",
        "wrong-fields",
    ],
)
def test_mutation_results_reject_malformed_json(defect: str) -> None:
    payloads = _valid_payloads()
    target, payload = payloads[0]
    if defect == "empty":
        payload = b""
    elif defect == "invalid-utf8":
        payload = b"\xff"
    elif defect == "malformed-json":
        payload = b"{"
    elif defect == "duplicate-key":
        payload = payload.replace(
            b'{"exit_code_by_key":',
            b'{"exit_code_by_key":{},"exit_code_by_key":',
            1,
        )
    elif defect == "nonfinite-constant":
        payload = payload.replace(b": 1", b": NaN", 1)
    elif defect == "nonfinite-float":
        payload = payload.replace(b":0.1", b":1e999", 1)
    elif defect == "oversized-integer":
        payload = payload.replace(b": 1", b": 2147483648", 1)
    elif defect == "non-object":
        payload = b"[]"
    elif defect == "wrong-fields":
        payload = b"{}"
    payloads[0] = (target, payload)

    with pytest.raises(MutationGateError):
        _ = parse_mutation_results(tuple(payloads))


@pytest.mark.parametrize(
    "defect",
    [
        "no-results",
        "map-type",
        "type-errors",
        "duration-missing",
        "duration-negative",
        "hash-malformed",
        "hash-missing",
    ],
)
def test_mutation_results_reject_malformed_fields(defect: str) -> None:
    payloads = _valid_payloads()
    target, payload = payloads[0]
    document = cast("dict[str, object]", json.loads(payload))
    if defect == "no-results":
        document["exit_code_by_key"] = {}
    elif defect == "map-type":
        document["hash_by_function_name"] = []
    elif defect == "type-errors":
        document["type_check_error_by_key"] = {"bad": True}
    elif defect == "duration-missing":
        durations = cast("dict[str, object]", document["durations_by_key"])
        _ = durations.pop(next(iter(durations)))
    elif defect == "duration-negative":
        durations = cast("dict[str, object]", document["durations_by_key"])
        durations[next(iter(durations))] = -1
    elif defect == "hash-malformed":
        hashes = cast("dict[str, object]", document["hash_by_function_name"])
        hashes[next(iter(hashes))] = "not-a-hash"
    elif defect == "hash-missing":
        document["hash_by_function_name"] = {}
    payloads[0] = (target, json.dumps(document, separators=(",", ":")).encode())

    with pytest.raises(MutationGateError):
        _ = parse_mutation_results(tuple(payloads))


def test_public_argument_parser_and_cli_reject_incomplete_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parsed = parse_arguments(
        [
            "--worktree",
            tmp_path.as_posix(),
            "--targets",
            *_EXPECTED_TARGETS,
        ]
    )
    assert parsed.worktree == tmp_path
    assert parsed.targets == _EXPECTED_TARGETS

    status = cli(
        [
            "--worktree",
            tmp_path.as_posix(),
            "--targets",
            "src/nplg_mcp/sdk_boundary.py",
        ]
    )

    assert status == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "mutation request does not match" in captured.err


def test_public_cli_renders_success_from_the_existing_adapter_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    executor = _MutationExecutor(policy)
    clock = _Clock()
    filesystem = _Filesystem()
    git = _RealGit(cache)
    monkeypatch.setattr(mutation_gate_module, "SystemExecutor", lambda: executor)
    monkeypatch.setattr(mutation_gate_module, "SystemClock", lambda: clock)
    monkeypatch.setattr(mutation_gate_module, "SystemFilesystem", lambda: filesystem)
    monkeypatch.setattr(mutation_gate_module, "SystemGit", lambda: git)

    status = cli(
        [
            "--worktree",
            repository.as_posix(),
            "--output-dir",
            output.as_posix(),
            "--targets",
            *policy.targets,
        ]
    )

    assert status == 0
    assert capsys.readouterr().out == "mutation gate passed: 139/139 killed\n"


@pytest.mark.parametrize(
    "defect",
    [
        "relative-worktree",
        "missing-worktree",
        "symlink-worktree",
    ],
)
def test_run_mutation_gate_rejects_invalid_worktree(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    if defect == "relative-worktree":
        worktree = Path("relative-worktree")
    elif defect == "missing-worktree":
        worktree = (tmp_path / "missing-worktree").resolve()
    else:
        worktree = tmp_path / "repository-link"
        worktree.symlink_to(repository, target_is_directory=True)

    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    with pytest.raises(MutationGateError):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=worktree,
                output_dir=output,
                targets=policy.targets,
            ),
            executor=_MutationExecutor(policy),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    [
        "missing-project",
        "source-policy",
        "missing-target",
        "malformed-project",
        "tool-not-table",
        "source-mutmut",
    ],
)
def test_run_mutation_gate_rejects_invalid_source_snapshot(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    if defect == "missing-project":
        repository.joinpath("pyproject.toml").unlink()
    elif defect == "source-policy":
        _ = repository.joinpath("setup.cfg").write_text("[mutmut]\n", encoding="utf-8")
        _ = _git_command(repository, cache, "add", "setup.cfg")
    elif defect == "missing-target":
        repository.joinpath(_EXPECTED_TARGETS[0]).unlink()
    elif defect == "malformed-project":
        _ = repository.joinpath("pyproject.toml").write_text("[", encoding="utf-8")
    elif defect == "tool-not-table":
        _ = repository.joinpath("pyproject.toml").write_text(
            'tool = "not-a-table"\n',
            encoding="utf-8",
        )
    else:
        _ = repository.joinpath("pyproject.toml").write_text(
            "[tool.mutmut]\n",
            encoding="utf-8",
        )

    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    with pytest.raises(MutationGateError):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=output,
                targets=policy.targets,
            ),
            executor=_MutationExecutor(policy),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    [
        "partial-release",
        "invalid-candidate",
    ],
)
def test_run_mutation_gate_rejects_invalid_release_request(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    candidate = None if defect == "partial-release" else "main"

    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    with pytest.raises(MutationGateError):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=output,
                targets=policy.targets,
                require_clean=True,
                candidate=candidate,
            ),
            executor=_MutationExecutor(policy),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )
    assert not output.exists()


@pytest.mark.parametrize("defect", ["create", "write", "policy-read", "executor"])
def test_run_mutation_gate_rejects_external_boundary_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    executor = _external_boundary_executor(policy, monkeypatch, defect)

    with pytest.raises(MutationGateError):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=output,
                targets=policy.targets,
            ),
            executor=executor,
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    ["root-open", "root-replace", "child-open", "child-replace", "inventory-change"],
)
def test_run_mutation_gate_rejects_descriptor_boundary_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    fault = _DescriptorBoundaryFault(
        defect=defect,
        output=output,
        executor=_MutationExecutor(policy),
    )
    monkeypatch.setattr(os, "open", fault.open)
    if defect == "inventory-change":
        monkeypatch.setattr(os, "stat", fault.stat)

    with pytest.raises(MutationGateError):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=output,
                targets=policy.targets,
            ),
            executor=fault.execute,
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )
    assert not output.exists()


@pytest.mark.parametrize("defect", ["inventory", "content"])
def test_run_mutation_gate_rejects_late_metadata_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    base_executor = _MutationExecutor(policy)

    def execute(request: CommandRequest) -> CommandResult:
        result = base_executor(request)
        if defect == "inventory":
            original_scandir = os.scandir
            root_scans = 0

            def alter_third_root_scan(
                path: int | str | bytes | os.PathLike[str],
            ) -> Iterator[os.DirEntry[str]]:
                nonlocal root_scans
                if isinstance(path, int):
                    opened = Path(f"/proc/self/fd/{path}").resolve(strict=True)
                    if opened == request.cwd:
                        root_scans += 1
                        if root_scans == _THIRD_ROOT_SCAN:
                            target = (
                                request.cwd / "mutants" / f"{policy.targets[-1]}.meta"
                            )
                            target.unlink()
                return cast("Iterator[os.DirEntry[str]]", original_scandir(path))

            monkeypatch.setattr(os, "scandir", alter_third_root_scan)
        else:
            original_open = os.open
            meta_reads = 0

            def alter_ninth_meta_read(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal meta_reads
                if dir_fd is not None and os.fsdecode(path).endswith(".meta"):
                    meta_reads += 1
                    if meta_reads == _NINTH_META_READ:
                        target = request.cwd / "mutants" / f"{policy.targets[0]}.meta"
                        payload = target.read_bytes().replace(b":0.1", b":0.2")
                        _ = target.write_bytes(payload)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            monkeypatch.setattr(os, "open", alter_ninth_meta_read)
        return result

    with pytest.raises(MutationGateError):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=output,
                targets=policy.targets,
            ),
            executor=execute,
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )
    assert not output.exists()


def test_run_mutation_gate_reaches_behavioral_red(tmp_path: Path) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    executor = _MutationExecutor(policy)
    before = _source_git_state(repository, cache)
    request = MutationGateRequest(
        worktree=repository,
        output_dir=output,
        targets=policy.targets,
    )

    result = run_mutation_gate(
        request,
        executor=executor,
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(cache),
    )

    assert result.summary.total == sum(
        len(functions) for _target, functions in policy.required_functions
    )
    assert result.summary.killed == result.summary.total
    assert result.output_dir == output
    assert _source_git_state(repository, cache) == before
    assert stat.S_IMODE(output.stat().st_mode) == stat.S_IRWXU
    mutation_configuration = (output / "snapshot" / "setup.cfg").read_text()
    expected_copy_policy = """also_copy =
    contracts
    pyproject.toml
    requirements.in
    src/nplg_mcp
    scripts
    security
"""
    assert expected_copy_policy in mutation_configuration
    assert (
        "    --deselect\n"
        "    tests/unit/test_errors.py::test_detail_mapping_growth_"
        "during_copy_fails_closed\n"
        "    --deselect\n"
        "    tests/unit/test_errors.py::test_detail_list_growth_"
        "during_copy_fails_closed\n"
        "    --deselect\n"
        "    tests/unit/test_quality_gate.py::test_git_snapshot_hashes_"
        "logical_index_and_refs_without_mutation\n"
    ) in mutation_configuration
    assert (
        "pytest_add_cli_args_test_selection =\n"
        "    tests/security/test_security.py\n"
        "    tests/security/test_tokens.py\n"
        "    tests/security/test_downloader.py\n"
        "    tests/unit/test_storage.py\n"
        "    tests/property/test_storage_properties.py\n"
        "    tests/unit/test_errors.py\n"
        "    tests/unit/test_delete_render.py\n"
        "    tests/unit/test_smoke_live.py\n"
        "    tests/unit/test_quality_gate.py\n"
    ) in mutation_configuration
    assert (
        "pytest_add_cli_args_test_selection =\n    tests\n"
        not in mutation_configuration
    )
    assert executor.requests
    command = executor.requests[0]
    assert command.argv[0] == sys.executable
    assert command.argv[1:4] == ("-I", "-B", "-c")
    assert command.argv[5] == "mutmut"
    assert command.argv[-3:] == ("run", "--max-children", "8")
    assert command.timeout_seconds == _MUTATION_TIMEOUT_SECONDS
    assert "PYTHONPATH" not in dict(command.environment)
    assert not (repository / "mutants").exists()


def test_run_mutation_gate_rejects_candidate_tool_shadow_before_execution(
    tmp_path: Path,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    _ = repository.joinpath("src", "mutmut.py").write_text(
        "raise RuntimeError('candidate code executed')\n",
        encoding="utf-8",
    )
    policy = initial_mutation_policy()
    executor = _MutationExecutor(policy)

    with pytest.raises(MutationGateError, match="shadows a trusted mutation tool"):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=(tmp_path / "external-output").resolve(),
                targets=policy.targets,
            ),
            executor=executor,
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )

    assert executor.requests == []


@pytest.mark.parametrize("meta_defect", ["missing", "extra", "replaced", "empty"])
def test_run_mutation_gate_rejects_inexact_descriptor_bound_meta_inventory(
    tmp_path: Path,
    meta_defect: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()

    with pytest.raises(MutationGateError):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=output,
                targets=policy.targets,
            ),
            executor=_MutationExecutor(policy, meta_defect=meta_defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )

    assert not output.exists()


@pytest.mark.parametrize(
    ("defect", "expected"),
    [
        (None, "pass"),
        ("candidate-tree", "fail"),
        ("raw-object", "fail"),
        ("dirty-source", "fail"),
    ],
)
def test_release_mutation_gate_binds_candidate_tree_and_raw_git_evidence(
    tmp_path: Path,
    defect: str | None,
    expected: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    if defect != "dirty-source":
        _ = _git_command(
            repository,
            cache,
            "checkout",
            "--",
            "src/nplg_mcp/security.py",
        )
    candidate = _git_command(repository, cache, "rev-parse", "HEAD").decode().strip()
    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()
    executor = _MutationExecutor(
        policy,
        raw_drift_repository=repository if defect == "raw-object" else None,
    )
    git = _RealGit(
        cache,
        tree_defect_root=repository if defect == "candidate-tree" else None,
    )
    request = MutationGateRequest(
        worktree=repository,
        output_dir=output,
        targets=policy.targets,
        require_clean=True,
        candidate=candidate,
    )

    if expected == "pass":
        result = run_mutation_gate(
            request,
            executor=executor,
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=git,
        )
        assert result.summary.killed == result.summary.total
        assert output.is_dir()
    else:
        with pytest.raises(MutationGateError):
            _ = run_mutation_gate(
                request,
                executor=executor,
                clock=_Clock(),
                filesystem=_Filesystem(),
                git=git,
            )
        assert not output.exists()


@pytest.mark.parametrize(
    "workspace_defect",
    [
        "late-input",
        "replace-root",
        "config-change",
        "entry-bound",
        "source-drift",
        "extra-output",
        "missing-output",
        "replace-output-child",
    ],
)
def test_mutation_gate_rejects_late_input_and_external_root_replacement(
    tmp_path: Path,
    workspace_defect: str,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    policy = initial_mutation_policy()

    with pytest.raises(MutationGateError):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=output,
                targets=policy.targets,
            ),
            executor=_MutationExecutor(
                policy,
                raw_drift_repository=(
                    repository if workspace_defect == "source-drift" else None
                ),
                workspace_defect=workspace_defect,
            ),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )

    assert not output.exists()
    if workspace_defect == "replace-root":
        assert output.with_name(output.name + "-renamed").is_dir()


@pytest.mark.parametrize(
    ("returncode", "clock"),
    [
        (1, _Clock()),
        (0, _SequenceClock((0.0, 1800.1))),
    ],
)
def test_run_mutation_gate_rejects_unhealthy_outer_process(
    tmp_path: Path,
    returncode: int,
    clock: _Clock | _SequenceClock,
) -> None:
    repository, cache = _initialize_mutation_repository(tmp_path)
    policy = initial_mutation_policy()

    with pytest.raises(MutationGateError, match="mutation command"):
        _ = run_mutation_gate(
            MutationGateRequest(
                worktree=repository,
                output_dir=(tmp_path / "external-output").resolve(),
                targets=policy.targets,
            ),
            executor=_MutationExecutor(policy, returncode=returncode),
            clock=clock,
            filesystem=_Filesystem(),
            git=_RealGit(cache),
        )
