# Copyright (c) 2026 David Osipov
"""Externally isolated killed-only mutation authority."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, TextIO, cast

if __name__ == "__main__" and not __package__:
    script_package_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, script_package_root.as_posix())
    __package__ = "scripts"

from scripts.run_test_gate import (
    Clock,
    CommandRequest,
    CommandResult,
    Executor,
    Filesystem,
    Git,
    ReleaseGitEvidence,
    SourceSnapshot,
    SystemClock,
    SystemExecutor,
    SystemFilesystem,
    SystemGit,
    bind_external_snapshot,
    capture_source_snapshot,
    create_external_output,
    materialize_snapshot,
    read_bound_regular_file,
    registered_worktrees,
    reject_mutation_tool_shadows,
    release_git_evidence,
    repository_evidence,
    stable_snapshot_file,
    trusted_mutation_python_command,
)
from scripts.run_test_gate import TestGateError as MutationGateError

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

__all__ = (
    "CommandRequest",
    "CommandResult",
    "MutationGateError",
    "MutationGateRequest",
    "MutationGateResult",
    "MutationPolicy",
    "MutationSummary",
    "cli",
    "initial_mutation_policy",
    "main",
    "parse_arguments",
    "parse_mutation_results",
    "run_mutation_gate",
)

_MAX_META_BYTES = 16 * 1024 * 1024
_MAX_MUTANT_DURATION_SECONDS = 86_400
_MAX_MUTANT_NAME_CHARACTERS = 512
_NO_TESTS_STATUS = 33
_META_KEYS = frozenset(
    {
        "exit_code_by_key",
        "hash_by_function_name",
        "type_check_error_by_key",
        "durations_by_key",
        "estimated_durations_by_key",
    }
)
_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_LOCAL_FUNCTION_TEXT = (
    rf"(?:x_{_IDENTIFIER}|xǁ{_IDENTIFIER}(?:\.{_IDENTIFIER})*ǁ{_IDENTIFIER})"
)
_MUTANT_NAME = re.compile(
    "".join(
        (
            rf"(?P<function>{_IDENTIFIER}(?:\.{_IDENTIFIER})*\.{_LOCAL_FUNCTION_TEXT})",
            r"__mutmut_(?P<ordinal>[1-9][0-9]*)\Z",
        )
    )
)
_FUNCTION_HASH = re.compile(r"[0-9a-f]{12}\Z")
_GIT_OBJECT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_MAX_REF_BYTES = 1024
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_OUTPUT_DIRECTORIES = frozenset({"cache", "home", "pycache", "snapshot", "tmp"})
_INITIAL_TARGETS = (
    "src/nplg_mcp/security.py",
    "src/nplg_mcp/tokens.py",
    "src/nplg_mcp/downloader.py",
    "src/nplg_mcp/storage.py",
    "src/nplg_mcp/errors.py",
    "scripts/delete_render.py",
    "scripts/smoke_live.py",
    "scripts/run_quality_gate.py",
)
_TARGET_MODULES = {
    "src/nplg_mcp/security.py": "nplg_mcp.security",
    "src/nplg_mcp/tokens.py": "nplg_mcp.tokens",
    "src/nplg_mcp/downloader.py": "nplg_mcp.downloader",
    "src/nplg_mcp/storage.py": "nplg_mcp.storage",
    "src/nplg_mcp/errors.py": "nplg_mcp.errors",
    "scripts/delete_render.py": "scripts.delete_render",
    "scripts/smoke_live.py": "scripts.smoke_live",
    "scripts/run_quality_gate.py": "scripts.run_quality_gate",
}
_REQUIRED_LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
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


def _fail(message: str) -> NoReturn:
    raise MutationGateError(message)


def _fail_from(message: str, cause: BaseException) -> NoReturn:
    raise MutationGateError(message) from cause


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("mutation JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_nonfinite_number(_value: str) -> NoReturn:
    _fail("mutation JSON forbids non-finite values")


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _fail("mutation JSON forbids non-finite values")
    return parsed


def _bounded_json_integer(value: str) -> int:
    parsed = int(value, 10)
    if not -(2**31) <= parsed < 2**31:
        _fail("mutation JSON integer is outside the closed range")
    return parsed


def _load_meta(payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_META_BYTES:
        _fail("mutation metadata is empty, oversized, or invalid")
    try:
        value = cast(
            "object",
            json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=_closed_object,
                parse_constant=_reject_nonfinite_number,
                parse_float=_finite_json_float,
                parse_int=_bounded_json_integer,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        _fail_from("mutation metadata is malformed", exc)
    if type(value) is not dict:
        _fail("mutation metadata must be an object")
    result = cast("dict[str, object]", value)
    if frozenset(result) != _META_KEYS:
        _fail("mutation metadata fields do not match mutmut 3.7.0")
    return result


@dataclass(frozen=True, slots=True)
class MutationPolicy:
    """Closed target, status, and minimum-kill policy."""

    targets: tuple[str, ...]
    killed_exit_codes: frozenset[int]
    accepted_exit_codes: frozenset[int]
    minimum_killed_percent: int
    required_functions: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True, slots=True)
class MutationSummary:
    """Validated complete mutant-status summary."""

    total: int
    killed: int
    target_counts: tuple[tuple[str, int], ...]
    function_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class MutationGateRequest:
    """Immutable developer or release mutation-gate request."""

    worktree: Path
    output_dir: Path | None
    targets: tuple[str, ...]
    require_clean: bool = False
    candidate: str | None = None


@dataclass(frozen=True, slots=True)
class MutationGateResult:
    """Validated mutation result and external workspace."""

    summary: MutationSummary
    output_dir: Path


def initial_mutation_policy() -> MutationPolicy:
    """Return Task 7's exact reviewed pinned-mutmut target inventory."""
    required = tuple(
        (
            target,
            tuple(
                f"{_TARGET_MODULES[target]}.{local_function}"
                for local_function in _REQUIRED_LOCAL_FUNCTIONS[target]
            ),
        )
        for target in _INITIAL_TARGETS
    )
    return MutationPolicy(
        targets=_INITIAL_TARGETS,
        killed_exit_codes=frozenset({1}),
        accepted_exit_codes=frozenset({-24, 0, 1, 33}),
        minimum_killed_percent=65,
        required_functions=required,
    )


@dataclass(frozen=True, slots=True)
class _TargetMetadata:
    exit_codes: dict[object, object]
    hashes: dict[object, object]
    durations: dict[object, object]
    estimates: dict[object, object]


def _validated_target_metadata(payload: bytes) -> _TargetMetadata:
    metadata = _load_meta(payload)
    exit_codes_value = metadata["exit_code_by_key"]
    if type(exit_codes_value) is not dict or not exit_codes_value:
        _fail("mutation target has no generated mutant results")
    values = (
        metadata["hash_by_function_name"],
        metadata["durations_by_key"],
        metadata["estimated_durations_by_key"],
        metadata["type_check_error_by_key"],
    )
    if not all(type(value) is dict for value in values):
        _fail("mutation metadata maps have invalid runtime types")
    hashes_value, durations_value, estimates_value, type_errors_value = values
    type_errors = cast("dict[object, object]", type_errors_value)
    if type_errors:
        _fail("killed-only mutation evidence contains type-check results")
    return _TargetMetadata(
        exit_codes=cast("dict[object, object]", exit_codes_value),
        hashes=cast("dict[object, object]", hashes_value),
        durations=cast("dict[object, object]", durations_value),
        estimates=cast("dict[object, object]", estimates_value),
    )


def _validate_target_support(metadata: _TargetMetadata) -> None:
    mutant_names = set(metadata.exit_codes)
    unexecuted_mutants = {
        name
        for name, status in metadata.exit_codes.items()
        if status == _NO_TESTS_STATUS
    }
    if (
        set(metadata.durations) != mutant_names - unexecuted_mutants
        or set(metadata.estimates) != mutant_names
    ):
        _fail("mutation duration evidence is incomplete")
    if any(
        type(key) is not str
        or type(value) is not str
        or _FUNCTION_HASH.fullmatch(value) is None
        for key, value in metadata.hashes.items()
    ):
        _fail("mutation function hashes are malformed")
    for value in (*metadata.durations.values(), *metadata.estimates.values()):
        if (
            type(value) not in {int, float}
            or not math.isfinite(cast("int | float", value))
            or cast("int | float", value) < 0
            or cast("int | float", value) > _MAX_MUTANT_DURATION_SECONDS
        ):
            _fail("mutation duration evidence is malformed")


def _parse_target_mutants(
    metadata: _TargetMetadata,
    *,
    target_module: str,
    policy: MutationPolicy,
    seen_mutants: set[str],
    function_counts: dict[str, int],
) -> tuple[int, int, frozenset[str]]:
    target_count = 0
    killed_count = 0
    target_functions: set[str] = set()
    for name_value, exit_code in metadata.exit_codes.items():
        name = cast("str", name_value)
        match = _MUTANT_NAME.fullmatch(name)
        if (
            match is None
            or len(name) > _MAX_MUTANT_NAME_CHARACTERS
            or name in seen_mutants
        ):
            _fail("mutation result name is malformed or duplicated")
        function = cast("str", match.group("function"))
        if not function.startswith(f"{target_module}."):
            _fail("mutation result does not belong to its declared target")
        if type(exit_code) is not int or exit_code not in policy.accepted_exit_codes:
            _fail("mutation result has an unaccepted status")
        seen_mutants.add(name)
        target_functions.add(function.removeprefix(f"{target_module}."))
        function_counts[function] = function_counts.get(function, 0) + 1
        target_count += 1
        if exit_code in policy.killed_exit_codes:
            killed_count += 1
    if set(metadata.hashes) != target_functions:
        _fail("mutation function hash evidence is incomplete")
    return (
        target_count,
        killed_count,
        frozenset(f"{target_module}.{function}" for function in target_functions),
    )


def parse_mutation_results(
    payloads: tuple[tuple[str, bytes], ...],
) -> MutationSummary:
    """Parse exact pinned-mutmut per-target results."""
    policy = initial_mutation_policy()
    required = dict(policy.required_functions)
    supplied_targets = tuple(target for target, _payload in payloads)
    if supplied_targets != policy.targets:
        _fail("mutation evidence targets do not exactly match the policy")
    total = 0
    killed = 0
    seen_mutants: set[str] = set()
    target_counts: list[tuple[str, int]] = []
    function_count_map: dict[str, int] = {}
    for target, payload in payloads:
        metadata = _validated_target_metadata(payload)
        _validate_target_support(metadata)
        target_count, target_killed, generated_functions = _parse_target_mutants(
            metadata,
            target_module=_TARGET_MODULES[target],
            policy=policy,
            seen_mutants=seen_mutants,
            function_counts=function_count_map,
        )
        if generated_functions != frozenset(required[target]):
            _fail(f"mutation target {target} has unexpected generated functions")
        total += target_count
        killed += target_killed
        target_counts.append((target, target_count))

    if killed * 100 < total * policy.minimum_killed_percent:
        _fail("mutation test-failure kill floor was not met")

    return MutationSummary(
        total=total,
        killed=killed,
        target_counts=tuple(target_counts),
        function_counts=tuple(sorted(function_count_map.items())),
    )


def _canonical_worktree(path: Path) -> Path:
    if not path.is_absolute():
        _fail("mutation worktree must be absolute")
    try:
        canonical = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        _fail_from("mutation worktree is unavailable", exc)
    if (
        canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
    ):
        _fail("mutation worktree must be a canonical directory")
    return canonical


def _validate_snapshot_inputs(
    snapshot: SourceSnapshot,
    policy: MutationPolicy,
) -> None:
    records = {record.path: record for record in snapshot.files}
    if "pyproject.toml" not in records or not any(
        path.startswith("tests/") for path in records
    ):
        _fail("mutation snapshot lacks project configuration or tests")
    if "setup.cfg" in records:
        _fail("source setup.cfg would conflict with the external mutation policy")
    if any(target not in records for target in policy.targets):
        _fail("mutation snapshot lacks an exact reviewed target")
    try:
        project = cast(
            "dict[str, object]",
            tomllib.loads(records["pyproject.toml"].payload.decode("utf-8")),
        )
    except ValueError as exc:
        _fail_from("project configuration is malformed", exc)
    tool = project.get("tool", {})
    if type(tool) is not dict:
        _fail("project tool configuration is malformed")
    if "mutmut" in cast("dict[object, object]", tool):
        _fail("source mutmut configuration is forbidden")


def _mutation_configuration(policy: MutationPolicy) -> bytes:
    targets = "\n".join(f"    {target}" for target in policy.targets)
    return (
        "[mutmut]\n"
        "source_paths =\n"
        f"{targets}\n"
        "pytest_add_cli_args =\n"
        "    -q\n"
        "    --strict-markers\n"
        "    --strict-config\n"
        "    -p\n"
        "    no:cacheprovider\n"
        "    --deselect\n"
        "    tests/unit/test_errors.py::test_detail_mapping_growth_"
        "during_copy_fails_closed\n"
        "    --deselect\n"
        "    tests/unit/test_errors.py::test_detail_list_growth_"
        "during_copy_fails_closed\n"
        "    --deselect\n"
        "    tests/unit/test_quality_gate.py::test_git_snapshot_hashes_"
        "logical_index_and_refs_without_mutation\n"
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
        "also_copy =\n"
        "    src/nplg_mcp\n"
        "    scripts\n"
        "    security\n"
        "use_git_change_detection = false\n"
        "use_setproctitle = false\n"
    ).encode()


def _write_private_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    except OSError as exc:
        _fail_from("external mutation policy could not be created", exc)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                _fail("external mutation policy write was incomplete")
            written += count
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
    finally:
        os.close(descriptor)


def _closed_environment(output: Path) -> tuple[tuple[str, str], ...]:
    directories = {
        "HOME": output / "home",
        "TMPDIR": output / "tmp",
        "XDG_CACHE_HOME": output / "cache",
        "PYTHONPYCACHEPREFIX": output / "pycache",
    }
    for directory in directories.values():
        directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
    return tuple(
        sorted(
            {
                **{name: path.as_posix() for name, path in directories.items()},
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
            }.items()
        )
    )


def _mutation_command(workspace: Path, output: Path) -> CommandRequest:
    return CommandRequest(
        argv=trusted_mutation_python_command(
            import_roots=(workspace / "src", workspace),
            arguments=("run", "--max-children", "8"),
        ),
        cwd=workspace,
        environment=_closed_environment(output),
        timeout_seconds=1_800.0,
    )


def _validated_command_result(
    executor: Executor,
    request: CommandRequest,
    *,
    clock: Clock,
) -> CommandResult:
    started = clock.monotonic()
    try:
        result = executor(request)
    except (OSError, RuntimeError, ValueError) as exc:
        _fail_from("mutation command failed at the process boundary", exc)
    finished = clock.monotonic()
    if (
        type(started) not in {int, float}
        or type(finished) not in {int, float}
        or not math.isfinite(started)
        or not math.isfinite(finished)
        or finished < started
        or finished - started > request.timeout_seconds
        or type(result) is not CommandResult
        or result.argv != request.argv
        or type(result.returncode) is not int
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > request.stdout_limit_bytes
        or len(result.stderr) > request.stderr_limit_bytes
    ):
        _fail("mutation command evidence is malformed")
    return result


def _read_meta(workspace: Path, relative: str) -> bytes:
    metadata, payload = read_bound_regular_file(
        workspace,
        relative,
        max_bytes=_MAX_META_BYTES,
    )
    if metadata.st_size < 1 or not payload:
        _fail("mutation metadata is empty")
    return payload


def _filesystem_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_bound_directory(path: Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as exc:
        _fail_from("mutation output directory could not be opened safely", exc)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _filesystem_identity(before) != _filesystem_identity(opened)
        or _filesystem_identity(opened) != _filesystem_identity(after)
    ):
        os.close(descriptor)
        _fail("mutation output directory changed during descriptor binding")
    return descriptor


def _open_bound_child(parent: int, name: str, expected: os.stat_result) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
        opened = os.fstat(descriptor)
    except OSError as exc:
        _fail_from("mutation output child directory could not be opened safely", exc)
    if not stat.S_ISDIR(opened.st_mode) or _filesystem_identity(
        expected
    ) != _filesystem_identity(opened):
        os.close(descriptor)
        _fail("mutation output child directory changed during descriptor binding")
    return descriptor


def _inventory_entry_ceiling(snapshot: SourceSnapshot) -> int:
    return max(128, (len(snapshot.files) * 8) + 64)


def _workspace_file_inventory(
    workspace: Path,
    *,
    entry_ceiling: int,
) -> frozenset[str]:
    root = _open_bound_directory(workspace)
    pending = [(root, "")]
    found: set[str] = set()
    visited = 0
    try:
        while pending:
            directory, prefix = pending.pop()
            try:
                with os.scandir(directory) as raw_entries:
                    entries = cast("Iterator[os.DirEntry[str]]", raw_entries)
                    for entry in entries:
                        visited += 1
                        if visited > entry_ceiling:
                            _fail("mutation output exceeds its entry bound")
                        before = entry.stat(follow_symlinks=False)
                        linked = os.stat(
                            entry.name,
                            dir_fd=directory,
                            follow_symlinks=False,
                        )
                        if _filesystem_identity(before) != _filesystem_identity(linked):
                            _fail("mutation output changed during inventory")
                        relative = f"{prefix}/{entry.name}" if prefix else entry.name
                        if stat.S_ISDIR(before.st_mode):
                            if relative == ".git":
                                continue
                            pending.append(
                                (
                                    _open_bound_child(directory, entry.name, before),
                                    relative,
                                )
                            )
                        elif not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                            _fail("mutation output contains a linked or special entry")
                        else:
                            found.add(relative)
            finally:
                os.close(directory)
    finally:
        for directory, _prefix in pending:
            os.close(directory)
    return frozenset(found)


def _meta_inventory(workspace: Path, *, entry_ceiling: int) -> frozenset[str]:
    return frozenset(
        relative
        for relative in _workspace_file_inventory(
            workspace,
            entry_ceiling=entry_ceiling,
        )
        if relative.startswith("mutants/") and relative.endswith(".meta")
    )


def _bound_directory_identity(path: Path) -> tuple[int, int, int, int]:
    descriptor = _open_bound_directory(path)
    try:
        metadata = os.fstat(descriptor)
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
        )
    finally:
        os.close(descriptor)


def _bound_output_layout(
    output: Path,
) -> tuple[tuple[str, tuple[int, int, int, int]], ...]:
    root = _open_bound_directory(output)
    found: dict[str, tuple[int, int, int, int]] = {}
    try:
        with os.scandir(root) as raw_entries:
            entries = cast("Iterator[os.DirEntry[str]]", raw_entries)
            for entry in entries:
                before = entry.stat(follow_symlinks=False)
                linked = os.stat(entry.name, dir_fd=root, follow_symlinks=False)
                if (
                    entry.name not in _OUTPUT_DIRECTORIES
                    or entry.name in found
                    or _filesystem_identity(before) != _filesystem_identity(linked)
                ):
                    _fail("external mutation output layout is not closed")
                child = _open_bound_child(root, entry.name, before)
                try:
                    opened = os.fstat(child)
                    found[entry.name] = (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_mode,
                        opened.st_uid,
                    )
                finally:
                    os.close(child)
    finally:
        os.close(root)
    if found.keys() != _OUTPUT_DIRECTORIES:
        _fail("external mutation output layout is incomplete")
    return tuple(sorted(found.items()))


def _require_directory_identity(
    path: Path,
    expected: tuple[int, int, int, int],
) -> None:
    if _bound_directory_identity(path) != expected:
        _fail("external mutation directory was renamed or replaced")


def _require_output_layout(
    output: Path,
    expected: tuple[tuple[str, tuple[int, int, int, int]], ...],
) -> None:
    if _bound_output_layout(output) != expected:
        _fail("external mutation output layout changed")


def _validate_workspace_inputs(workspace: Path, snapshot: SourceSnapshot) -> None:
    expected = frozenset(("setup.cfg", *(record.path for record in snapshot.files)))
    actual = frozenset(
        relative
        for relative in _workspace_file_inventory(
            workspace,
            entry_ceiling=_inventory_entry_ceiling(snapshot),
        )
        if not relative.startswith("mutants/")
    )
    if actual != expected:
        _fail("external mutation workspace has an unexpected input")


def _exact_meta_payloads(
    workspace: Path,
    policy: MutationPolicy,
    *,
    entry_ceiling: int,
) -> tuple[tuple[str, bytes], ...]:
    expected = frozenset(f"mutants/{target}.meta" for target in policy.targets)
    if _meta_inventory(workspace, entry_ceiling=entry_ceiling) != expected:
        _fail("mutation metadata filenames do not exactly match the policy")
    payloads = tuple(
        (target, _read_meta(workspace, f"mutants/{target}.meta"))
        for target in policy.targets
    )
    if _meta_inventory(workspace, entry_ceiling=entry_ceiling) != expected:
        _fail("mutation metadata inventory changed while being read")
    return payloads


def _release_mode(request: MutationGateRequest, policy: MutationPolicy) -> bool:
    if (
        type(request) is not MutationGateRequest
        or not isinstance(cast("object", request.worktree), Path)
        or request.targets != policy.targets
        or type(cast("object", request.require_clean)) is not bool
        or (
            request.output_dir is not None
            and not isinstance(cast("object", request.output_dir), Path)
        )
    ):
        _fail("mutation request does not match the closed initial policy")
    release_mode = request.require_clean and request.candidate is not None
    if request.require_clean != (request.candidate is not None):
        _fail("release mutation mode requires both clean and candidate controls")
    if request.candidate is not None and (
        type(request.candidate) is not str
        or len(request.candidate) > _MAX_REF_BYTES
        or _GIT_OBJECT.fullmatch(request.candidate) is None
    ):
        _fail("mutation candidate is not an exact Git object name")
    return release_mode


def _capture_release_evidence(
    git: Git,
    *,
    root: Path,
    release_mode: bool,
) -> ReleaseGitEvidence | None:
    if not release_mode:
        return None
    return release_git_evidence(git, root=root)


def _validate_release_tree(
    evidence: ReleaseGitEvidence | None,
    *,
    candidate: str | None,
    materialized_tree: str,
) -> None:
    if evidence is not None and (
        evidence.commit != candidate or evidence.tree != materialized_tree
    ):
        _fail("release mutation snapshot is not the exact candidate tree")


def _validate_release_evidence_unchanged(
    before: ReleaseGitEvidence | None,
    after: ReleaseGitEvidence | None,
) -> None:
    if before != after:
        _fail("release mutation execution changed raw Git evidence")


def _execute_external_mutation(
    *,
    workspace: Path,
    source_snapshot: SourceSnapshot,
    policy: MutationPolicy,
    executor: Executor,
    clock: Clock,
) -> MutationSummary:
    output = workspace.parent
    entry_ceiling = _inventory_entry_ceiling(source_snapshot)
    expected_configuration = _mutation_configuration(policy)
    _write_private_file(workspace / "setup.cfg", expected_configuration)
    configuration = stable_snapshot_file(workspace, "setup.cfg")
    if (
        configuration.payload != expected_configuration
        or configuration.mode != _PRIVATE_FILE_MODE
    ):
        _fail("external mutation policy does not match the closed configuration")
    _validate_workspace_inputs(workspace, source_snapshot)
    command = _mutation_command(workspace, output)
    output_identity = _bound_directory_identity(output)
    workspace_identity = _bound_directory_identity(workspace)
    output_layout = _bound_output_layout(output)
    _ = _validated_command_result(executor, command, clock=clock)
    _require_directory_identity(output, output_identity)
    _require_directory_identity(workspace, workspace_identity)
    _require_output_layout(output, output_layout)
    _validate_workspace_inputs(workspace, source_snapshot)
    payloads = _exact_meta_payloads(
        workspace,
        policy,
        entry_ceiling=entry_ceiling,
    )
    summary = parse_mutation_results(payloads)
    if (
        _exact_meta_payloads(
            workspace,
            policy,
            entry_ceiling=entry_ceiling,
        )
        != payloads
    ):
        _fail("mutation metadata bytes changed after validation")
    if stable_snapshot_file(workspace, "setup.cfg") != configuration:
        _fail("external mutation policy changed during execution")
    _require_directory_identity(output, output_identity)
    _require_directory_identity(workspace, workspace_identity)
    _require_output_layout(output, output_layout)
    _validate_workspace_inputs(workspace, source_snapshot)
    return summary


def run_mutation_gate(
    request: MutationGateRequest,
    *,
    executor: Executor,
    clock: Clock,
    filesystem: Filesystem,
    git: Git,
) -> MutationGateResult:
    """Run mutation testing only in an external disposable workspace."""
    del filesystem
    policy = initial_mutation_policy()
    release_mode = _release_mode(request, policy)

    root = _canonical_worktree(request.worktree)
    before_repository = repository_evidence(git, root=root)
    before_release = _capture_release_evidence(
        git,
        root=root,
        release_mode=release_mode,
    )
    if release_mode and (
        not before_repository.clean or request.candidate != before_repository.head
    ):
        _fail("release mutation source is not the clean exact candidate")
    worktrees = registered_worktrees(git, root=root)
    before_snapshot = capture_source_snapshot(git, root=root)
    reject_mutation_tool_shadows(before_snapshot)
    _validate_snapshot_inputs(before_snapshot, policy)
    output, temporary = create_external_output(
        request.output_dir,
        registered_worktrees=worktrees,
    )
    succeeded = False
    try:
        materialized = materialize_snapshot(
            root,
            before_snapshot,
            merge_base=before_repository.head,
            output=output,
            git=git,
        )
        binding = bind_external_snapshot(
            git,
            materialized=materialized,
            source_snapshot=before_snapshot,
        )
        _validate_release_tree(
            before_release,
            candidate=request.candidate,
            materialized_tree=binding.tree,
        )
        summary = _execute_external_mutation(
            workspace=materialized.root,
            source_snapshot=before_snapshot,
            policy=policy,
            executor=executor,
            clock=clock,
        )
        _ = bind_external_snapshot(
            git,
            materialized=materialized,
            source_snapshot=before_snapshot,
        )
        after_snapshot = capture_source_snapshot(git, root=root)
        after_repository = repository_evidence(git, root=root)
        after_release = _capture_release_evidence(
            git,
            root=root,
            release_mode=release_mode,
        )
        _validate_release_evidence_unchanged(before_release, after_release)
        if after_snapshot != before_snapshot or after_repository != before_repository:
            _fail("mutation execution changed the source snapshot or Git state")
        succeeded = True
        return MutationGateResult(summary=summary, output_dir=output)
    finally:
        if temporary or not succeeded:
            shutil.rmtree(output, ignore_errors=True)


def parse_arguments(argv: Sequence[str] | None = None) -> MutationGateRequest:
    """Parse the closed mutation-gate command-line contract."""
    parser = argparse.ArgumentParser(
        description="Run the externally contained NPLG mutation gate.",
        allow_abbrev=False,
    )
    _ = parser.add_argument("--worktree", type=Path, default=Path.cwd())
    _ = parser.add_argument("--output-dir", type=Path)
    _ = parser.add_argument("--require-clean", action="store_true")
    _ = parser.add_argument("--candidate")
    _ = parser.add_argument("--targets", nargs="+", required=True)
    values = cast("dict[str, object]", vars(parser.parse_args(argv)))
    return MutationGateRequest(
        worktree=cast("Path", values["worktree"]),
        output_dir=cast("Path | None", values["output_dir"]),
        targets=tuple(cast("list[str]", values["targets"])),
        require_clean=cast("bool", values["require_clean"]),
        candidate=cast("str | None", values["candidate"]),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the mutation gate through the shared production adapters."""
    result = run_mutation_gate(
        parse_arguments(argv),
        executor=SystemExecutor(),
        clock=SystemClock(),
        filesystem=SystemFilesystem(),
        git=SystemGit(),
    )
    stdout = cast("TextIO", sys.stdout)
    _ = stdout.write(
        f"mutation gate passed: {result.summary.killed}/{result.summary.total} killed\n"
    )
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    """Render one bounded process-facing error without a traceback."""
    try:
        return main(argv)
    except MutationGateError as error:
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write("mutation gate failed: " + str(error) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
