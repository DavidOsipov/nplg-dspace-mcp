# Copyright (c) 2026 David Osipov
"""Unit tests for the externally contained release-quality test gate."""

from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import inspect
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, dataclass, replace
from pathlib import Path
from tomllib import loads as load_toml
from types import SimpleNamespace
from typing import TYPE_CHECKING, Protocol, cast, override

import pytest
from coverage.config import DEFAULT_EXCLUDE
from coverage.misc import join_regex
from coverage.parser import PythonParser
from hypothesis import settings

import scripts.run_test_gate as test_gate_module
from scripts.run_quality_gate import run_bounded_command
from scripts.run_test_gate import (
    CommandRequest,
    CommandResult,
    CoveragePolicy,
    CoverageReportResult,
    InstalledFileRecord,
    SystemClock,
    SystemExecutor,
    SystemFilesystem,
    SystemGit,
    cli,
    parse_arguments,
    parse_coverage_policy,
    parse_coverage_reports,
    parse_external_gate_registry,
    run_test_gate,
    verify_installed_package,
)
from scripts.run_test_gate import (
    TestGateError as GateError,
)
from scripts.run_test_gate import (
    TestGateRequest as GateRequest,
)
from scripts.run_test_gate import (
    TestGateResult as GateResult,
)

if TYPE_CHECKING:
    from collections.abc import (
        Callable,
        Generator,
        Iterable,
        Iterator,
        Mapping,
        Sequence,
    )
    from types import ModuleType


_CI_MAX_EXAMPLES = 200
_FULL_PERCENT = 100.0
_FULL_BRANCH_FLOOR = 100
_MIN_MARKER_ARGUMENTS = 2
_TRUSTED_PROOF_FIELDS = 4
_PRIVATE_DIRECTORY_MODE = 0o700
_EXPECTED_COMMAND_RECORDS = 9
_EXPECTED_COVERAGE_REPORT_COMMANDS = 3
_TRUSTED_DRIVER_MODE_INDEX = 5
_TRUSTED_DRIVER_ROOTS_INDEX = 6
_TRUSTED_DRIVER_PROOF_INDEX = 7
_TRUSTED_DRIVER_PACKAGE_ROOT_INDEX = 8
_TRUSTED_DRIVER_REJECTION = 97
_COLLECTION_OUTPUT_LIMIT_BYTES = 32 * 1024 * 1024
_CLI_FAILURE = 1
_SECOND_CALL = 2
_THIRD_CALL = 3
_DETERMINISTIC_NODE = "tests/test_ok.py::test_ok"
_LIVE_CANARY_NODE = (
    "tests/integration/test_repository.py::"
    "test_live_nplg_canary_uses_bound_public_endpoint"
)
_MATCH_BRANCH_SOURCE = """if anchor:
    pass
match value:
    case 1:
        pass
    case _:
        pass
"""
_TYPE_CHECKING_SOURCE = """if anchor:
    pass
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    pass
"""


class _NodeCollector(Protocol):
    def __call__(self, payload: bytes, *, allow_empty: bool) -> tuple[str, ...]: ...


_SHARED_AUTHORITY_NAMES = (
    "RepositoryEvidence",
    "ReleaseGitEvidence",
    "SnapshotFile",
    "SourceSnapshot",
    "MaterializedSnapshot",
    "ExternalSnapshotBinding",
    "repository_evidence",
    "release_git_evidence",
    "registered_worktrees",
    "read_bound_regular_file",
    "stable_snapshot_file",
    "capture_source_snapshot",
    "create_external_output",
    "materialize_snapshot",
    "bind_external_snapshot",
    "reject_mutation_tool_shadows",
    "trusted_mutation_python_command",
)


@contextmanager
def _isolated_coverage_bindings() -> Generator[None]:
    saved = {
        name: module
        for name, module in tuple(sys.modules.items())
        if name == "coverage" or name.startswith("coverage.")
    }
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in tuple(sys.modules):
            if name == "coverage" or name.startswith("coverage."):
                del sys.modules[name]
        sys.modules.update(saved)


def _loaded_file_module(path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "nplg_hostile_coverage",
        path,
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class _HypothesisProfile(Protocol):
    derandomize: bool
    database: object | None
    deadline: object | None
    max_examples: int
    print_blob: bool


class _PathFixtureDecorator(Protocol):
    def __call__(
        self,
        function: Callable[[], Iterator[Path]],
        /,
    ) -> Callable[[], Iterator[Path]]: ...


class _SignatureTarget(Protocol):
    def __call__(self, *args: object, **kwargs: object) -> object: ...


class _DistributionFinder(Protocol):
    def __call__(
        self,
        *,
        name: str | None = None,
        path: Sequence[str] | None = None,
    ) -> Iterable[importlib.metadata.Distribution]: ...


class _SpecificationFinder(Protocol):
    def __call__(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None: ...


def _trusted_command_proof(
    argv: tuple[str, ...],
) -> tuple[tuple[str, str, str, str], ...]:
    value = cast(
        "object",
        json.loads(argv[_TRUSTED_DRIVER_PROOF_INDEX]),
    )
    assert type(value) is list
    proof: list[tuple[str, str, str, str]] = []
    for raw_row in cast("list[object]", value):
        assert type(raw_row) is list
        row = cast("list[object]", raw_row)
        assert len(row) == _TRUSTED_PROOF_FIELDS
        assert all(type(item) is str for item in row)
        module, distribution, version, origin = cast("list[str]", row)
        proof.append((module, distribution, version, origin))
    return tuple(proof)


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


class _FaultFilesystem:
    def __init__(self, defect: str) -> None:
        super().__init__()
        self._defect = defect
        self._used = False

    def read_bytes(self, path: Path) -> bytes:
        payload = path.read_bytes()
        if self._used:
            return payload
        self._used = True
        if self._defect == "read-error":
            message = "synthetic read failure"
            raise OSError(message)
        if self._defect == "non-bytes":
            return cast("bytes", cast("object", "not bytes"))
        if self._defect == "short":
            return payload[:-1]
        if self._defect == "changed":
            _ = path.write_bytes(payload + b"x")
        return payload


class _RealGit:
    def __init__(self, cache: Path) -> None:
        super().__init__()
        self._cache = cache

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> CommandResult:
        del environment
        result = run_bounded_command(argv, root=cwd, cache_dir=self._cache)
        return CommandResult(
            argv=result.argv,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


class _EnvironmentGit:
    def __init__(self) -> None:
        super().__init__()
        self.environments: list[dict[str, str]] = []

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> CommandResult:
        self.environments.append(dict(environment))
        result = subprocess.run(  # noqa: S603
            argv,
            cwd=cwd,
            env=environment,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        return CommandResult(
            argv=argv,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


class _LateExternalGit:
    def __init__(self, cache: Path) -> None:
        super().__init__()
        self._base = _RealGit(cache)
        self._snapshot_statuses = 0
        self.mutated = False

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> CommandResult:
        result = self._base.run(argv, cwd=cwd, environment=environment)
        if cwd.name == "snapshot" and argv[1:3] == ("status", "--porcelain=v1"):
            self._snapshot_statuses += 1
            if self._snapshot_statuses == _SECOND_CALL:
                _ = cwd.joinpath("late-input.txt").write_bytes(b"late\n")
                self.mutated = True
        return result


class _FaultGit:
    def __init__(self, cache: Path, defect: str, *, source: Path | None = None) -> None:
        super().__init__()
        self._base = _RealGit(cache)
        self._defect = defect
        self._source = source
        self._counts: dict[str, int] = {}

    def _occurrence(self, key: str) -> int:
        value = self._counts.get(key, 0) + 1
        self._counts[key] = value
        return value

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> CommandResult:
        result = self._base.run(argv, cwd=cwd, environment=environment)
        arguments = argv[1:]
        key = self._command_key(arguments)
        occurrence = self._occurrence(key) if key else 0
        boundary_fault = self._boundary_result_fault(
            argv,
            key=key,
            occurrence=occurrence,
        )
        if boundary_fault is not None:
            return boundary_fault
        payload = self._payload_fault(
            key,
            occurrence=occurrence,
            original=result.stdout,
        )
        if payload is not None:
            return CommandResult(
                argv=argv,
                returncode=0,
                stdout=payload,
                stderr=b"",
            )
        if key == "clone" and self._defect == "source-drift-after-clone":
            assert self._source is not None
            _ = self._source.write_text("changed during clone\n", encoding="utf-8")
        if key == "clone":
            self._apply_clone_fault(arguments)
        return result

    def _apply_clone_fault(self, arguments: tuple[str, ...]) -> None:
        destination = Path(arguments[-1])
        if self._defect == "clone-missing":
            shutil.rmtree(destination)
        elif self._defect == "clone-alias":
            target = destination.with_name("snapshot-target")
            _ = destination.rename(target)
            destination.symlink_to(target, target_is_directory=True)
        elif self._defect == "snapshot-preexisting":
            existing = destination / "scripts" / "delete_render.py"
            existing.parent.mkdir(parents=True)
            _ = existing.write_bytes(b"occupied\n")
        elif self._defect == "private-preexisting":
            _ = destination.parent.joinpath("coverage.rc").write_bytes(b"occupied\n")

    @staticmethod
    def _command_key(arguments: tuple[str, ...]) -> str:
        exact: dict[tuple[str, ...], str] = {
            ("rev-parse", "--verify", "HEAD"): "head",
            ("rev-parse", "--path-format=absolute", "--git-dir"): "git-dir",
            ("worktree", "list", "--porcelain", "-z"): "worktrees",
            ("ls-files", "--stage", "-z"): "tracked",
            ("ls-files", "--others", "--exclude-standard", "-z"): "untracked",
        }
        if arguments in exact:
            return exact[arguments]
        prefixes = {
            ("diff", "--name-only"): "names",
            ("diff", "--unified=0"): "hunks",
        }
        prefix = (
            (arguments[0], arguments[1]) if len(arguments) >= _SECOND_CALL else ("", "")
        )
        if prefix in prefixes:
            return prefixes[prefix]
        return "clone" if "clone" in arguments else ""

    def _boundary_result_fault(
        self,
        argv: tuple[str, ...],
        *,
        key: str,
        occurrence: int,
    ) -> CommandResult | None:
        if occurrence != 1:
            return None
        values = {
            ("git-result", "head"): (1, b"", b"bad"),
            ("head-nonascii", "head"): (0, b"\xff\n", b""),
            ("head-malformed", "head"): (0, b"bad\n", b""),
            ("worktrees-malformed", "worktrees"): (0, b"bad\0", b""),
        }
        fault = values.get((self._defect, key))
        if fault is None:
            return None
        returncode, stdout, stderr = fault
        return CommandResult(
            argv=argv,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def _payload_fault(
        self,
        key: str,
        *,
        occurrence: int,
        original: bytes,
    ) -> bytes | None:
        if key == "tracked" and occurrence == _SECOND_CALL:
            return self._tracked_fault(original)
        if key == "git-dir" and occurrence == 1:
            return self._git_directory_fault()
        if key == "untracked" and occurrence == 1:
            return self._untracked_fault()
        if key == "names":
            return self._changed_name_fault()
        if key == "hunks":
            return self._hunk_fault()
        return None

    def _git_directory_fault(self) -> bytes | None:
        values = {
            "git-dir-nonascii": b"\xff\n",
            "git-dir-malformed": b"/malformed",
            "git-dir-relative": b"relative\n",
        }
        payload = values.get(self._defect)
        if payload is not None:
            return payload
        if self._defect in {"git-dir-missing", "git-dir-not-directory"}:
            assert self._source is not None
            return f"{self._source.as_posix()}\n".encode()
        return None

    def _tracked_fault(self, payload: bytes) -> bytes | None:
        fake = b"100644 " + (b"0" * 40) + b" 0\t"
        entry = fake + b"tests/test_ok.py\0"
        values = {
            "tracked-truncated": b"x",
            "tracked-malformed": b"x\0",
            "tracked-unsupported": b"120000 " + (b"0" * 40) + b" 0\tbad\0",
            "tracked-duplicate": entry + entry,
            "tracked-nonascii": fake + b"tests/\xff.py\0",
            "tracked-canonical": fake + b"../bad.py\0",
            "tracked-symlink-parent": payload + fake + b"vendor/link/test_ok.py\0",
            "tracked-missing-parent": payload + fake + b"vendor/missing/file.py\0",
            "tracked-root-symlink": payload + fake + b".env.example\0",
        }
        return values.get(self._defect)

    def _untracked_fault(self) -> bytes | None:
        return {
            "untracked-truncated": b"x",
            "untracked-duplicate": b"tests/new.py\0tests/new.py\0",
            "untracked-outside": b"outside.txt\0",
            "inventory-overlap": b"tests/test_ok.py\0",
        }.get(self._defect)

    def _changed_name_fault(self) -> bytes | None:
        return {
            "name-truncated": b"scripts/new.py",
            "name-duplicate": b"scripts/new.py\0scripts/new.py\0",
            "name-nonpython": b"scripts/readme.txt\0",
        }.get(self._defect)

    def _hunk_fault(self) -> bytes | None:
        return {
            "hunk-binary": b"Binary files a and b differ\n",
            "hunk-marker-text": (
                b"diff --git a/scripts/new.py b/scripts/new.py\n"
                b"--- /dev/null\n"
                b"+++ b/scripts/new.py\n"
                b"@@ -0,0 +1 @@\n"
                b'+MARKERS = (b"GIT binary patch", b"Binary files a and b differ")\n'
            ),
            "hunk-malformed": b"@@ broken @@\n",
            "hunk-zero-count": b"@@ -1 +0,0 @@\n",
            "hunk-zero-start": b"@@ -1 +0 @@\n",
        }.get(self._defect)


class _CoverageExecutor:
    def __init__(
        self,
        *,
        coverage_defects: Mapping[str, str] | None = None,
        external_marker: str | None = None,
        junit_skipped: bool = False,
        dynamic_deselection: bool = False,
        mutate_source: Path | None = None,
    ) -> None:
        super().__init__()
        self.requests: list[CommandRequest] = []
        self._coverage_defects = dict(coverage_defects or {})
        self._external_marker = external_marker
        self._junit_skipped = junit_skipped
        self._dynamic_deselection = dynamic_deselection
        self._mutate_source = mutate_source
        self._source_mutated = False

    def __call__(self, request: CommandRequest) -> CommandResult:
        self.requests.append(request)
        argv = request.argv
        if "--collect-only" in argv:
            marker = (
                argv[-1]
                if len(argv) >= _MIN_MARKER_ARGUMENTS and argv[-2] == "-m"
                else None
            )
            if (
                self._mutate_source is not None
                and marker is None
                and not self._source_mutated
            ):
                _ = self._mutate_source.write_text(
                    "changed during gate\n", encoding="utf-8"
                )
                self._source_mutated = True
            nodes: tuple[str, ...]
            if marker is None:
                nodes = (_DETERMINISTIC_NODE, _LIVE_CANARY_NODE)
            elif marker == "live":
                nodes = (_LIVE_CANARY_NODE,)
            else:
                nodes = ()
            if marker is not None and marker == self._external_marker:
                nodes = (_DETERMINISTIC_NODE, *nodes)
            return CommandResult(
                argv=argv,
                returncode=0 if nodes else 5,
                stdout=("\n".join((*nodes, "")).encode() if nodes else b""),
                stderr=b"",
            )
        if "run" in argv and (
            "coverage" in argv
            or "coverage-installed" in argv
            or "coverage-pytest" in argv
            or "coverage-pytest-installed" in argv
        ):
            environment = dict(request.environment)
            coverage_file = Path(environment["COVERAGE_FILE"] + ".fake")
            _ = coverage_file.write_bytes(b"synthetic coverage data\n")
            junit_argument = next(
                argument for argument in argv if argument.startswith("--junitxml=")
            )
            junit_path = Path(junit_argument.partition("=")[2])
            skipped = 1 if self._junit_skipped else 0
            skipped_child = b"<skipped/>" if self._junit_skipped else b""
            _ = junit_path.write_bytes(
                b"".join(
                    (
                        (
                            '<testsuites tests="1" failures="0" errors="0" '
                            f'skipped="{skipped}">'
                        ).encode(),
                        (
                            '<testsuite tests="1" failures="0" errors="0" '
                            f'skipped="{skipped}">'
                        ).encode(),
                        b'<testcase classname="tests.test_ok" name="test_ok">',
                        skipped_child,
                        b"</testcase>",
                        b"</testsuite></testsuites>",
                    )
                )
            )
            audit_path = Path(
                next(value for value in argv if value.endswith("pytest-audit.json"))
            )
            audit = {
                "version": 1,
                "collected": ["tests/test_ok.py::test_ok"],
                "deselected": (
                    ["tests/test_ok.py::test_ok"] if self._dynamic_deselection else []
                ),
                "calls": [["tests/test_ok.py::test_ok", "passed"]],
            }
            audit_payload = json.dumps(audit, separators=(",", ":")).encode()
            _ = audit_path.write_bytes(audit_payload)
        elif "coverage" in argv and ("xml" in argv or "json" in argv):
            destination = Path(argv[argv.index("-o") + 1])
            if destination.name == "installed-coverage.json":
                self._write_installed_coverage(request, destination)
            else:
                self._write_coverage_reports(request.cwd, destination)
        elif "diff-cover" in argv:
            report_argument = argv[argv.index("--format") + 1].removeprefix("json:")
            _ = Path(report_argument).write_bytes(b"{}\n")
        stdout = b"1 deselected\n" if self._dynamic_deselection else b""
        return CommandResult(argv=argv, returncode=0, stdout=stdout, stderr=b"")

    @staticmethod
    def _write_installed_coverage(
        request: CommandRequest,
        destination: Path,
    ) -> None:
        roots = cast("list[str]", json.loads(request.argv[_TRUSTED_DRIVER_ROOTS_INDEX]))
        package = Path(roots[0]) / "nplg_mcp"
        files: dict[str, dict[str, list[int]]] = {
            path.resolve(strict=True).as_posix(): {"executed_lines": [1]}
            for path in package.rglob("*.py")
        }
        document: dict[str, object] = {"files": files}
        _ = destination.write_text(
            json.dumps(document, separators=(",", ":")),
            encoding="utf-8",
        )

    def _write_coverage_reports(self, snapshot: Path, destination: Path) -> None:
        modules = tuple(
            sorted(
                path.relative_to(snapshot).as_posix()
                for root in (snapshot / "src" / "nplg_mcp", snapshot / "scripts")
                for path in root.rglob("*.py")
            )
        )
        counters = {module: self._coverage_counters(module) for module in modules}
        total_covered = sum(covered for covered, _total in counters.values())
        total_branches = sum(total for _covered, total in counters.values())
        if destination.suffix == ".xml":
            classes = "".join(
                (
                    f'<class filename="{module}" '
                    f'branch-rate="{self._rate(*counters[module])}" line-rate="1">'
                    f"<lines>{self._xml_line(module)}</lines></class>"
                )
                for module in modules
            )
            payload = (
                '<?xml version="1.0" ?>'
                f'<coverage branch-rate="{self._rate(total_covered, total_branches)}" '
                f'branches-covered="{total_covered}" branches-valid="{total_branches}">'
                f"<sources><source>{snapshot.as_posix()}</source></sources>"
                f'<packages><package name="project"><classes>{classes}'
                "</classes></package></packages></coverage>"
            ).encode()
        else:
            files: dict[str, object] = {
                module: self._json_file(module) for module in modules
            }
            document: dict[str, object] = {
                "meta": {"branch_coverage": True},
                "totals": {
                    "percent_covered": self._percent(total_covered, total_branches),
                    "num_branches": total_branches,
                    "covered_branches": total_covered,
                    "missing_branches": total_branches - total_covered,
                },
                "files": files,
            }
            payload = json.dumps(
                document,
                separators=(",", ":"),
            ).encode()
        _ = destination.write_bytes(payload)

    def _coverage_counters(self, module: str) -> tuple[int, int]:
        defect = self._coverage_defects.get(module)
        if defect == "line":
            return 0, 0
        if defect == "arc":
            return 1, 2
        return 2, 2

    def _xml_line(self, module: str) -> str:
        defect = self._coverage_defects.get(module)
        if defect == "line":
            return '<line number="1" hits="0" branch="false"/>'
        if defect == "arc":
            return (
                '<line number="1" hits="1" branch="true" '
                'condition-coverage="50% (1/2)"/>'
            )
        return (
            '<line number="1" hits="1" branch="true" condition-coverage="100% (2/2)"/>'
        )

    def _json_file(self, module: str) -> dict[str, object]:
        defect = self._coverage_defects.get(module)
        covered, total = self._coverage_counters(module)
        executed_branches = (
            []
            if defect == "line"
            else [[1, 2]]
            if defect == "arc"
            else [[1, 2], [1, 3]]
        )
        return {
            "executed_lines": [] if defect == "line" else [1],
            "missing_lines": [1] if defect == "line" else [],
            "excluded_lines": [],
            "executed_branches": executed_branches,
            "missing_branches": [[1, 3]] if defect == "arc" else [],
            "summary": {
                "percent_covered": self._percent(covered, total),
                "num_branches": total,
                "covered_branches": covered,
                "missing_branches": total - covered,
            },
        }

    @staticmethod
    def _percent(covered: int, total: int) -> float:
        return 100.0 if total == 0 else covered * 100.0 / total

    @classmethod
    def _rate(cls, covered: int, total: int) -> str:
        return format(cls._percent(covered, total) / 100.0, ".12g")


class _InstalledCoverageFaultExecutor:
    def __init__(self, installed: Path, defect: str) -> None:
        super().__init__()
        self._base = _CoverageExecutor()
        self._installed = installed
        self._defect = defect

    def __call__(self, request: CommandRequest) -> CommandResult:
        result = self._base(request)
        argv = request.argv
        if "coverage" not in argv or "json" not in argv or "-o" not in argv:
            return result
        destination = Path(argv[argv.index("-o") + 1])
        if destination.name != "installed-coverage.json":
            return result
        files = tuple(
            sorted(
                path.resolve(strict=True).as_posix()
                for path in self._installed.rglob("*.py")
            )
        )
        first = files[0]
        records: dict[str, object]
        if self._defect == "root":
            document: object = []
        elif self._defect == "files":
            document = {"files": []}
        elif self._defect == "relative":
            document = {"files": {"relative.py": {"executed_lines": [1]}}}
        elif self._defect == "absent":
            missing = self._installed.parent.joinpath("absent.py").as_posix()
            document = {"files": {missing: {"executed_lines": [1]}}}
        else:
            if self._defect == "record":
                records = {first: 1}
            elif self._defect == "lines":
                records = {first: {"executed_lines": 1}}
            else:
                records = {
                    path: {"executed_lines": cast("list[object]", [])} for path in files
                }
            document = {"files": records}
        _ = destination.write_text(
            json.dumps(document, separators=(",", ":")),
            encoding="utf-8",
        )
        return result


class _FaultExecutor:
    def __init__(self, defect: str) -> None:
        super().__init__()
        self._base = _CoverageExecutor()
        self._defect = defect
        self._collect_count = 0

    def __call__(self, request: CommandRequest) -> CommandResult:
        result = self._base(request)
        if "--collect-only" in request.argv:
            self._collect_count += 1
            result = self._collection_fault(result)
            return self._command_fault(result, request)
        if "run" in request.argv and (
            "coverage" in request.argv
            or "coverage-installed" in request.argv
            or "coverage-pytest" in request.argv
            or "coverage-pytest-installed" in request.argv
        ):
            self._junit_fault(request)
        return self._command_fault(result, request)

    def _collection_fault(self, result: CommandResult) -> CommandResult:
        payload: object = result.stdout
        returncode = result.returncode
        if self._defect == "collection-type" and self._collect_count == 1:
            payload = "bad"
        elif self._defect == "collection-empty" and self._collect_count == 1:
            payload = b""
        elif self._defect == "collection-nonascii" and self._collect_count == 1:
            payload = b"tests/test_ok.py::test_\xff\n"
        elif self._defect == "collection-outside" and self._collect_count == 1:
            payload = b"outside.py::test_bad\n"
        elif self._defect == "collection-duplicate" and self._collect_count == 1:
            payload = b"tests/test_ok.py::test_ok\n" * 2
        elif (
            self._defect == "empty-code-with-nodes"
            and self._collect_count == _SECOND_CALL
        ):
            payload = b"tests/test_ok.py::test_ok\n"
            returncode = 5
        elif self._defect == "marker-outside" and self._collect_count == _SECOND_CALL:
            payload = b"tests/test_other.py::test_other\n"
            returncode = 0
        elif self._defect == "marker-overlap" and self._collect_count in {
            _SECOND_CALL,
            _THIRD_CALL,
        }:
            payload = b"tests/test_ok.py::test_ok\n"
            returncode = 0
        return CommandResult(
            argv=result.argv,
            returncode=returncode,
            stdout=cast("bytes", payload),
            stderr=result.stderr,
        )

    def _junit_fault(self, request: CommandRequest) -> None:
        argument = next(
            value for value in request.argv if value.startswith("--junitxml=")
        )
        path = Path(argument.partition("=")[2])
        if self._defect == "junit-missing":
            path.unlink()
        elif self._defect == "junit-empty":
            _ = path.write_bytes(b"")
        elif self._defect == "junit-malformed":
            _ = path.write_bytes(b"<broken")
        elif self._defect == "junit-root":
            _ = path.write_bytes(b"<not-tests/>")
        elif self._defect == "junit-count":
            _ = path.write_bytes(b'<testsuite tests="0"/>')
        elif self._defect == "junit-failure":
            _ = path.write_bytes(
                b'<testsuite tests="1"><testcase><failure/></testcase></testsuite>'
            )
        elif self._defect == "junit-summary":
            _ = path.write_bytes(
                b'<testsuite tests="1" failures="bad"><testcase/></testsuite>'
            )
        elif self._defect == "junit-root-count":
            _ = path.write_bytes(b'<testsuite tests="2"><testcase/></testsuite>')
        elif self._defect == "junit-hardlink":
            alias = path.with_name("junit-alias.xml")
            os.link(path, alias)

    def _command_fault(
        self,
        result: CommandResult,
        request: CommandRequest,
    ) -> CommandResult:
        if self._collect_count != 1 or not self._defect.startswith("command-"):
            return result
        invalid_integer = cast("int", cast("object", bool(self._defect)))
        invalid_bytes = cast("bytes", cast("object", "bad"))
        oversized = b"x" * (4 * 1024 * 1024 + 1)
        faults = {
            "command-argv": CommandResult(
                argv=("wrong",), returncode=0, stdout=b"", stderr=b""
            ),
            "command-return-type": CommandResult(
                argv=request.argv,
                returncode=invalid_integer,
                stdout=b"",
                stderr=b"",
            ),
            "command-negative": CommandResult(
                argv=request.argv, returncode=-1, stdout=b"", stderr=b""
            ),
            "command-code": CommandResult(
                argv=request.argv, returncode=1, stdout=b"", stderr=b""
            ),
            "command-stdout-type": CommandResult(
                argv=request.argv, returncode=0, stdout=invalid_bytes, stderr=b""
            ),
            "command-stderr-type": CommandResult(
                argv=request.argv, returncode=0, stdout=b"", stderr=invalid_bytes
            ),
            "command-stdout-bound": CommandResult(
                argv=request.argv, returncode=0, stdout=oversized, stderr=b""
            ),
            "command-stderr-bound": CommandResult(
                argv=request.argv, returncode=0, stdout=b"", stderr=oversized
            ),
        }
        return faults[self._defect]


class _ExternalMutationExecutor:
    def __init__(self, defect: str) -> None:
        super().__init__()
        self._base = _CoverageExecutor()
        self._defect = defect

    def __call__(self, request: CommandRequest) -> CommandResult:
        result = self._base(request)
        if "diff-cover" not in request.argv:
            return result
        output = Path(dict(request.environment)["COVERAGE_FILE"]).parent
        if self._defect in {
            "restored-deleted",
            "external-other-head",
            "external-untracked",
        }:
            self._mutate_external_snapshot(request)
            return result
        if self._defect in {
            "unexpected-directory",
            "hardlinked-output",
            "missing-authority",
        }:
            self._mutate_external_output(output)
            return result
        if self._defect in {
            "missing-report",
            "directory-report",
            "audit-fields",
            "audit-version",
            "audit-call",
            "audit-missing-call",
        }:
            self._mutate_post_capture_report(output)
            return result
        self._mutate_bound_artifact(request, output)
        return result

    def _mutate_bound_artifact(self, request: CommandRequest, output: Path) -> None:
        if self._defect == "snapshot":
            _ = request.cwd.joinpath("src/nplg_mcp/errors.py").write_text(
                "if changed:\n    pass\n",
                encoding="utf-8",
            )
        elif self._defect == "configuration":
            _ = Path(dict(request.environment)["COVERAGE_PROCESS_START"]).write_text(
                "[run]\nsource = attacker\n",
                encoding="utf-8",
            )
        elif self._defect == "external-head":
            _ = request.cwd.joinpath(".git/HEAD").write_bytes(b"0" * 40 + b"\n")
        elif self._defect == "report":
            report = output / "coverage.json"
            _ = report.write_bytes(report.read_bytes() + b" ")
        elif self._defect == "installed-report":
            report = output / "installed-coverage.json"
            _ = report.write_bytes(report.read_bytes() + b" ")
        elif self._defect == "installed-configuration":
            configuration = output / "installed-coverage.rc"
            _ = configuration.write_bytes(configuration.read_bytes() + b"# changed\n")
        else:
            _ = output.joinpath("forged-authority.json").write_bytes(b"{}\n")

    def _mutate_external_snapshot(self, request: CommandRequest) -> None:
        if self._defect == "restored-deleted":
            restored = request.cwd / "docs" / "deleted.md"
            restored.parent.mkdir(exist_ok=True)
            _ = restored.write_bytes(b"restored\n")
        elif self._defect == "external-other-head":
            _ = request.cwd.joinpath(".git/HEAD").write_bytes(
                b"ref: refs/heads/master\n"
            )
        elif self._defect == "external-untracked":
            _ = request.cwd.joinpath("untracked-evidence.txt").write_bytes(b"changed\n")

    def _mutate_external_output(self, output: Path) -> None:
        if self._defect == "unexpected-directory":
            output.joinpath("unexpected-directory").mkdir()
        elif self._defect == "hardlinked-output":
            os.link(output / ".coverage.fake", output / ".coverage.alias")
        elif self._defect == "missing-authority":
            output.joinpath("coverage.rc").unlink()

    def _mutate_post_capture_report(self, output: Path) -> None:
        if self._defect == "missing-report":
            output.joinpath("pytest-junit.xml").unlink()
        elif self._defect == "directory-report":
            report = output / "pytest-junit.xml"
            report.unlink()
            report.mkdir()
        elif self._defect == "audit-fields":
            _ = output.joinpath("pytest-audit.json").write_bytes(
                b'{"version":1,"collected":[],"deselected":[],"calls":[],"extra":0}'
            )
        elif self._defect == "audit-version":
            _ = output.joinpath("pytest-audit.json").write_bytes(
                b'{"version":2,"collected":[],"deselected":[],"calls":[]}'
            )
        elif self._defect in {"audit-call", "audit-missing-call"}:
            path = output / "pytest-audit.json"
            document = cast(
                "dict[str, object]",
                cast("object", json.loads(path.read_bytes())),
            )
            document["calls"] = (
                [["tests/test_ok.py::test_ok", "failed"]]
                if self._defect == "audit-call"
                else []
            )
            _ = path.write_text(
                json.dumps(document, separators=(",", ":")),
                encoding="utf-8",
            )


class _RefMutatingExecutor:
    def __init__(self, repository: Path, cache: Path) -> None:
        super().__init__()
        self._base = _CoverageExecutor()
        self._repository = repository
        self._cache = cache
        self._mutated = False

    def __call__(self, request: CommandRequest) -> CommandResult:
        if "--collect-only" in request.argv and not self._mutated:
            _ = _git_command(self._repository, self._cache, "branch", "tamper")
            self._mutated = True
        return self._base(request)


class _RawGitMutatingExecutor:
    def __init__(self, repository: Path, cache: Path, defect: str) -> None:
        super().__init__()
        self._base = _CoverageExecutor()
        self._repository = repository
        self._cache = cache
        self._defect = defect
        self._mutated = False

    def __call__(self, request: CommandRequest) -> CommandResult:
        if "--collect-only" in request.argv and not self._mutated:
            self._mutate()
            self._mutated = True
        return self._base(request)

    def _mutate(self) -> None:
        git_directory = self._repository / ".git"
        if self._defect == "detached-head":
            _ = _git_command(
                self._repository,
                self._cache,
                "checkout",
                "--detach",
                "-q",
            )
            return
        if self._defect == "object-addition":
            added = git_directory / "objects" / "ff" / ("f" * 38)
            added.parent.mkdir(exist_ok=True)
            _ = added.write_bytes(b"synthetic unregistered object\n")
            return
        target = git_directory / "index"
        if self._defect == "ref-replacement":
            head = (git_directory / "HEAD").read_text(encoding="ascii").strip()
            target = git_directory / head.removeprefix("ref: ")
        replacement = target.with_name(f"{target.name}.replacement")
        _ = replacement.write_bytes(target.read_bytes())
        replacement.chmod(stat.S_IMODE(target.stat().st_mode))
        _ = replacement.replace(target)


class _InstalledInputMutatingExecutor:
    def __init__(self, path: Path) -> None:
        super().__init__()
        self._base = _CoverageExecutor()
        self._path = path
        self._mutated = False

    def __call__(self, request: CommandRequest) -> CommandResult:
        if "--collect-only" in request.argv and not self._mutated:
            _ = self._path.write_bytes(self._path.read_bytes() + b"\n")
            self._mutated = True
        return self._base(request)


class _FaultDirectoryEntry:
    """Synthetic scan entry that changes before type classification."""

    name = "unstable"
    path = "/synthetic/unstable"

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        del follow_symlinks
        message = "synthetic entry changed"
        raise OSError(message)

    def is_symlink(self) -> bool:
        message = "synthetic entry changed"
        raise OSError(message)

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        del follow_symlinks
        return False

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        del follow_symlinks
        return False


class _FaultScandirIterator:
    def __init__(self) -> None:
        super().__init__()
        self._entries = iter(
            (cast("os.DirEntry[str]", cast("object", _FaultDirectoryEntry())),)
        )

    def __iter__(self) -> _FaultScandirIterator:
        return self

    def __next__(self) -> os.DirEntry[str]:
        return next(self._entries)

    def close(self) -> None:
        pass


class _ExplodingScandirIterator:
    def __init__(self, close: Callable[[], None]) -> None:
        super().__init__()
        self._close = close

    def __iter__(self) -> _ExplodingScandirIterator:
        return self

    def __next__(self) -> os.DirEntry[str]:
        message = "synthetic directory iteration failure"
        raise OSError(message)

    def close(self) -> None:
        self._close()


def _policy() -> CoveragePolicy:
    return CoveragePolicy(
        version=1,
        project_branch_floor=95,
        diff_line_floor=95,
        diff_branch_arc_floor=95,
        decision_module_branch_floor=100,
        measured_roots=("src/nplg_mcp", "scripts"),
        decision_modules=(
            "src/nplg_mcp/admission.py",
            "src/nplg_mcp/errors.py",
            "src/nplg_mcp/http_security.py",
            "src/nplg_mcp/json_preflight.py",
            "src/nplg_mcp/network.py",
            "src/nplg_mcp/resilience.py",
            "src/nplg_mcp/resource_admission.py",
            "src/nplg_mcp/pdf_executor.py",
            "src/nplg_mcp/pdf_ipc.py",
            "src/nplg_mcp/malware.py",
            "src/nplg_mcp/pdf_worker_client.py",
            "src/nplg_mcp/storage.py",
            "src/nplg_mcp/storage_lifecycle.py",
            "src/nplg_mcp/rate_limit.py",
            "src/nplg_mcp/mcp_server.py",
            "src/nplg_mcp/sdk_boundary.py",
            "src/nplg_mcp/security.py",
            "src/nplg_mcp/tokens.py",
            "scripts/build_asvs_matrix.py",
            "scripts/delete_render.py",
            "scripts/run_live_nplg_canary.py",
            "scripts/smoke_live.py",
            "scripts/run_quality_gate.py",
            "scripts/run_test_gate.py",
            "scripts/run_mutation_gate.py",
            "scripts/verify_scanner_container.py",
            "scripts/verify_pdf_worker_quota.py",
            "scripts/verify_private_recovery.py",
            "scripts/verify_release.py",
            "scripts/bootstrap_external_tools.py",
            "scripts/pyright_identity.py",
        ),
    )


def test_mcp_server_profile_branch_is_registered_as_a_decision_module() -> None:
    """Profile-dependent SDK registration is held to 100% branch coverage."""
    relative = "src/nplg_mcp/mcp_server.py"
    parser = PythonParser(filename=relative, exclude=join_regex(DEFAULT_EXCLUDE))
    parser.parse_source()
    branch_exits = sum(
        exits - 1 for exits in parser.exit_counts().values() if exits > 1
    )
    root = Path(__file__).resolve().parents[2]
    policy = parse_coverage_policy(
        (root / "security" / "coverage-policy.json").read_bytes(),
        root=root,
    )

    assert branch_exits == 1
    assert policy.decision_module_branch_floor == _FULL_BRANCH_FLOOR
    assert relative in policy.decision_modules


def test_inline_resource_admission_is_registered_as_a_decision_module() -> None:
    """Byte-denominated overload/accounting decisions require full branches."""
    relative = "src/nplg_mcp/resource_admission.py"
    parser = PythonParser(filename=relative, exclude=join_regex(DEFAULT_EXCLUDE))
    parser.parse_source()
    branch_exits = sum(
        exits - 1 for exits in parser.exit_counts().values() if exits > 1
    )
    root = Path(__file__).resolve().parents[2]
    policy = parse_coverage_policy(
        (root / "security" / "coverage-policy.json").read_bytes(),
        root=root,
    )

    assert branch_exits > 0
    assert policy.decision_module_branch_floor == _FULL_BRANCH_FLOOR
    assert relative in policy.decision_modules


def test_checked_in_asvs_matrix_policy_module_matches_gate_inventory() -> None:
    """ASVS candidate decisions stay covered by the gate's closed policy."""
    root = Path(__file__).resolve().parents[2]
    policy = parse_coverage_policy(
        (root / "security" / "coverage-policy.json").read_bytes(),
        root=root,
    )

    assert policy.decision_module_branch_floor == _FULL_BRANCH_FLOOR
    assert "scripts/build_asvs_matrix.py" in policy.decision_modules


def test_task_sixteen_a_decision_modules_are_registered_at_full_branch_floor() -> None:
    """Every Task 16A decision surface remains in the closed 100% inventory."""
    root = Path(__file__).resolve().parents[2]
    policy = parse_coverage_policy(
        (root / "security" / "coverage-policy.json").read_bytes(),
        root=root,
    )

    assert policy.decision_module_branch_floor == _FULL_BRANCH_FLOOR
    assert {
        "src/nplg_mcp/malware.py",
        "src/nplg_mcp/pdf_worker_client.py",
        "src/nplg_mcp/storage.py",
        "src/nplg_mcp/storage_lifecycle.py",
        "scripts/verify_scanner_container.py",
        "scripts/verify_pdf_worker_quota.py",
        "scripts/verify_private_recovery.py",
    }.issubset(policy.decision_modules)


def _policy_document() -> dict[str, object]:
    policy = _policy()
    return {
        "version": policy.version,
        "project_branch_floor": policy.project_branch_floor,
        "diff_line_floor": policy.diff_line_floor,
        "diff_branch_arc_floor": policy.diff_branch_arc_floor,
        "decision_module_branch_floor": policy.decision_module_branch_floor,
        "measured_roots": list(policy.measured_roots),
        "decision_modules": list(policy.decision_modules),
    }


def _report_policy() -> CoveragePolicy:
    return CoveragePolicy(
        version=1,
        project_branch_floor=95,
        diff_line_floor=95,
        diff_branch_arc_floor=95,
        decision_module_branch_floor=100,
        measured_roots=("src/nplg_mcp", "scripts"),
        decision_modules=("src/nplg_mcp/errors.py",),
    )


def _materialize_policy_modules(root: Path) -> None:
    for relative in _policy().decision_modules:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_text("# covered decision module\n", encoding="utf-8")


def test_gate_records_are_immutable(tmp_path: Path) -> None:
    request = GateRequest(
        worktree=tmp_path,
        compare_branch="origin/main",
        output_dir=tmp_path.parent / "new-output",
    )

    with pytest.raises(FrozenInstanceError):
        request.__setattr__("compare_branch", "HEAD^")


def test_collection_parser_ignores_non_node_diagnostic_lines() -> None:
    """Pytest banners and summaries cannot be mistaken for collected node IDs."""
    payload = f"diagnostic banner\n{_DETERMINISTIC_NODE}\n1 test collected\n".encode()
    namespace = cast(
        "dict[str, object]",
        cast("object", test_gate_module.__dict__),
    )
    collect_nodes = cast(
        "_NodeCollector",
        namespace["_collected_nodes"],
    )

    assert collect_nodes(payload, allow_empty=False) == (_DETERMINISTIC_NODE,)


def test_coverage_policy_parser_reaches_behavioral_red(tmp_path: Path) -> None:
    _materialize_policy_modules(tmp_path)
    policy_path = tmp_path / "coverage-policy.json"
    _ = policy_path.write_bytes(
        b"".join(
            (
                b'{"version":1,"project_branch_floor":95,',
                b'"diff_line_floor":95,"diff_branch_arc_floor":95,',
                b'"decision_module_branch_floor":100,',
                b'"measured_roots":["src/nplg_mcp","scripts"],',
                b'"decision_modules":["src/nplg_mcp/admission.py",',
                b'"src/nplg_mcp/errors.py","src/nplg_mcp/http_security.py",',
                b'"src/nplg_mcp/json_preflight.py","src/nplg_mcp/network.py",',
                b'"src/nplg_mcp/resilience.py",',
                b'"src/nplg_mcp/resource_admission.py",',
                b'"src/nplg_mcp/pdf_executor.py","src/nplg_mcp/pdf_ipc.py",',
                b'"src/nplg_mcp/malware.py",',
                b'"src/nplg_mcp/pdf_worker_client.py","src/nplg_mcp/storage.py",',
                b'"src/nplg_mcp/storage_lifecycle.py",',
                b'"src/nplg_mcp/rate_limit.py",',
                b'"src/nplg_mcp/mcp_server.py",',
                b'"src/nplg_mcp/sdk_boundary.py",',
                b'"src/nplg_mcp/security.py","src/nplg_mcp/tokens.py",',
                b'"scripts/build_asvs_matrix.py",',
                b'"scripts/delete_render.py","scripts/run_live_nplg_canary.py",',
                b'"scripts/smoke_live.py",',
                b'"scripts/run_quality_gate.py","scripts/run_test_gate.py",',
                b'"scripts/run_mutation_gate.py",',
                b'"scripts/verify_scanner_container.py",',
                b'"scripts/verify_pdf_worker_quota.py",',
                b'"scripts/verify_private_recovery.py","scripts/verify_release.py",',
                b'"scripts/bootstrap_external_tools.py",',
                b'"scripts/pyright_identity.py"]}\n',
            )
        )
    )

    policy = parse_coverage_policy(policy_path.read_bytes(), root=tmp_path)

    assert policy == _policy()


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"version":true}',
        b'{"version":1,"version":1}',
        b'{"version":1.0}',
        b'{"version":NaN}',
        b'[{"version":1}]',
        b"\xff",
    ],
)
def test_coverage_policy_rejects_malformed_closed_json(
    tmp_path: Path,
    payload: bytes,
) -> None:
    with pytest.raises(GateError):
        _ = parse_coverage_policy(payload, root=tmp_path)


def test_coverage_policy_rejects_nonexistent_or_unmeasured_modules(
    tmp_path: Path,
) -> None:
    payload = (
        b'{"version":1,"project_branch_floor":95,'
        b'"diff_line_floor":95,"diff_branch_arc_floor":95,'
        b'"decision_module_branch_floor":100,'
        b'"measured_roots":["src/nplg_mcp","scripts"],'
        b'"decision_modules":["outside.py"]}'
    )

    with pytest.raises(GateError):
        _ = parse_coverage_policy(payload, root=tmp_path)


def test_external_registry_rejects_a_missing_protected_gate_inventory() -> None:
    """A Task 7-era empty registry is no longer a valid release policy."""
    with pytest.raises(GateError, match="reviewed protected-gate inventory"):
        _ = parse_external_gate_registry(b'{"version":1,"gates":[]}\n')


def test_repository_policy_files_match_the_closed_phase3_contract() -> None:
    root = Path(__file__).resolve().parents[2]

    assert (
        parse_coverage_policy(
            (root / "security" / "coverage-policy.json").read_bytes(),
            root=root,
        )
        == _policy()
    )
    registry = parse_external_gate_registry(
        (root / "security" / "external-test-gates.json").read_bytes()
    )
    assert registry.version == 1
    assert tuple(gate.gate_id for gate in registry.gates) == (
        "common.nplg-live-canary",
        "private-full.edge-http",
        "private-full.pdf-worker-container",
        "private-full.pdf-worker-write-quota",
        "private-full.recovery-proof",
        "private-full.scanner-container",
    )
    assert tuple(gate.command_id for gate in registry.gates) == (
        "live.nplg-bound-endpoint.v2",
        "staging.private-full-edge.v2",
        "container.pdf-worker.v2",
        "container.pdf-worker-quota.v2",
        "container.private-full-recovery.v2",
        "container.scanner.v2",
    )
    assert tuple(gate.kind for gate in registry.gates) == (
        "live",
        "staging",
        "container",
        "container",
        "container",
        "container",
    )
    assert tuple(gate.node_id for gate in registry.gates) == (
        (
            "tests/integration/test_repository.py::"
            "test_live_nplg_canary_uses_bound_public_endpoint"
        ),
        None,
        None,
        None,
        None,
        None,
    )
    assert tuple(gate.timeout_seconds for gate in registry.gates) == (
        60,
        1800,
        300,
        300,
        900,
        300,
    )
    assert tuple(gate.result_schema for gate in registry.gates) == (
        "nplg-live-canary.v2",
        "private-edge-proof.v2",
        "container-proof.v2",
        "worker-quota-proof.v2",
        "recovery-proof.v2",
        "container-proof.v2",
    )


def test_external_registry_contains_only_controller_bound_gates() -> None:
    """Every excluded test has a complete protected operational contract."""
    root = Path(__file__).resolve().parents[2]
    registry = parse_external_gate_registry(
        (root / "security" / "external-test-gates.json").read_bytes()
    )

    for gate in registry.gates:
        assert gate.gate_id is not None
        assert gate.command_id is not None
        assert gate.profiles
        assert gate.mode == "preexecuted-operational"
        assert gate.protected_command
        assert gate.protected_cwd == "protected-controller-root"
        assert gate.broker_kind is not None
        assert gate.authority is not None
        assert gate.timeout_seconds is not None
        assert gate.result_schema is not None
        assert gate.signed_proof_schema is not None


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "command-drift", "invented-private-node"],
)
def test_external_registry_rejects_missing_extra_or_drifted_gates(
    mutation: str,
) -> None:
    """The checked-in registry is one closed policy, not an extensible hint."""
    root = Path(__file__).resolve().parents[2]
    value = cast(
        "dict[str, object]",
        cast(
            "object",
            json.loads((root / "security" / "external-test-gates.json").read_bytes()),
        ),
    )
    gates = cast("list[dict[str, object]]", value["gates"])
    if mutation == "missing":
        _ = gates.pop()
    elif mutation == "extra":
        gates.append(copy.deepcopy(gates[-1]))
    elif mutation == "command-drift":
        gates[-1]["command_id"] = "container.scanner.v3"
    else:
        gates[-1]["node_id"] = "tests/security/test_forged.py::test_forged"

    with pytest.raises(GateError, match="reviewed protected-gate inventory"):
        _ = parse_external_gate_registry(
            json.dumps(value, separators=(",", ":")).encode()
        )


def test_coverage_pytest_and_hypothesis_configuration_is_closed() -> None:
    root = Path(__file__).resolve().parents[2]
    configuration = cast(
        "dict[str, object]",
        cast(
            "object",
            load_toml((root / "pyproject.toml").read_text(encoding="utf-8")),
        ),
    )
    tool = cast("dict[str, object]", configuration["tool"])
    coverage = cast("dict[str, object]", tool["coverage"])
    coverage_run = cast("dict[str, object]", coverage["run"])
    pytest = cast("dict[str, object]", tool["pytest"])
    pytest_options = cast("dict[str, object]", pytest["ini_options"])
    profile = cast("_HypothesisProfile", settings.get_profile("ci"))

    assert coverage_run == {
        "branch": True,
        "parallel": True,
        "patch": ["subprocess"],
        "source": ["nplg_mcp", "scripts"],
    }
    assert pytest_options["markers"] == [
        "live: requires network access to the live NPLG repository",
        "staging: requires explicit access to a reviewed staging deployment",
        "container: requires an authorized isolated container runtime",
    ]
    assert profile.derandomize is True
    assert profile.database is None
    assert profile.deadline is None
    assert profile.max_examples == _CI_MAX_EXAMPLES
    assert profile.print_blob is True
    assert (
        ".hypothesis/" in (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"version":1,"gates":[{}]}',
        b'{"version":1,"gates":[],"extra":false}',
        b'{"version":true,"gates":[]}',
        b'{"version":1,"gates":[],"gates":[]}',
        b'{"gates":[],"version":1.0}',
    ],
)
def test_external_registry_rejects_every_unknown_or_nonclosed_form(
    payload: bytes,
) -> None:
    with pytest.raises(GateError):
        _ = parse_external_gate_registry(payload)


def test_coverage_report_parser_reaches_behavioral_red(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if True:\n    pass\n", encoding="utf-8")

    result = parse_coverage_reports(
        xml_payload=_coverage_xml(tmp_path),
        json_payload=_coverage_json(),
        policy=_report_policy(),
        snapshot_root=tmp_path,
        changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
    )

    assert result.project_branch_percent == _FULL_PERCENT


@dataclass(frozen=True, slots=True)
class _XmlFixture:
    filename: str = "src/nplg_mcp/errors.py"
    root_branch_rate: str = "1"
    class_branch_rate: str = "1"
    covered: int = 2
    valid: int = 2
    condition: str = "100% (2/2)"
    branch_line: int = 1


@dataclass(frozen=True, slots=True)
class _JsonFixture:
    filename: str = "src/nplg_mcp/errors.py"
    branch_coverage: bool = True
    executed_lines: tuple[int, ...] = (1,)
    missing_lines: tuple[int, ...] = ()
    executed_branches: tuple[tuple[int, int], ...] = ((1, 2), (1, 3))
    missing_branches: tuple[tuple[int, int], ...] = ()
    covered: int = 2
    missing: int = 0
    total: int = 2
    percent: int = 100


_DEFAULT_XML_FIXTURE = _XmlFixture()
_DEFAULT_JSON_FIXTURE = _JsonFixture()


def _coverage_xml(
    root: Path,
    fixture: _XmlFixture = _DEFAULT_XML_FIXTURE,
) -> bytes:
    return (
        '<?xml version="1.0" ?>'
        f'<coverage branch-rate="{fixture.root_branch_rate}" line-rate="1" '
        f'branches-covered="{fixture.covered}" branches-valid="{fixture.valid}">'
        f"<sources><source>{root.as_posix()}</source></sources>"
        '<packages><package name="project"><classes>'
        f'<class filename="{fixture.filename}" '
        f'branch-rate="{fixture.class_branch_rate}" '
        f'line-rate="1"><lines><line number="{fixture.branch_line}" '
        'hits="1" branch="true" '
        f'condition-coverage="{fixture.condition}"/></lines></class>'
        "</classes></package></packages></coverage>"
    ).encode()


def _coverage_json(
    fixture: _JsonFixture = _DEFAULT_JSON_FIXTURE,
) -> bytes:
    return json.dumps(
        _coverage_json_document(fixture),
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _coverage_json_document(
    fixture: _JsonFixture = _DEFAULT_JSON_FIXTURE,
) -> dict[str, object]:
    return {
        "meta": {"branch_coverage": fixture.branch_coverage},
        "totals": {
            "percent_covered": fixture.percent,
            "percent_covered_display": str(fixture.percent),
            "num_branches": fixture.total,
            "covered_branches": fixture.covered,
            "missing_branches": fixture.missing,
        },
        "files": {
            fixture.filename: {
                "executed_lines": fixture.executed_lines,
                "missing_lines": fixture.missing_lines,
                "excluded_lines": [],
                "executed_branches": fixture.executed_branches,
                "missing_branches": fixture.missing_branches,
                "summary": {
                    "percent_covered": fixture.percent,
                    "num_branches": fixture.total,
                    "covered_branches": fixture.covered,
                    "missing_branches": fixture.missing,
                },
            }
        },
    }


def _object_mapping(value: object) -> dict[str, object]:
    assert type(value) is dict
    return cast("dict[str, object]", value)


def _json_payload(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode()


def _fresh_coverage_json_file() -> tuple[dict[str, object], dict[str, object]]:
    document = copy.deepcopy(_coverage_json_document())
    files = _object_mapping(document["files"])
    return document, _object_mapping(files["src/nplg_mcp/errors.py"])


def _assert_invalid_coverage_documents(
    root: Path,
    documents: list[dict[str, object]],
) -> None:
    for document in documents:
        with pytest.raises(GateError):
            _ = parse_coverage_reports(
                xml_payload=_coverage_xml(root),
                json_payload=_json_payload(document),
                policy=_report_policy(),
                snapshot_root=root,
                changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
            )


def test_coverage_reports_accept_the_exact_diff_line_floor(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text(
        "if value:\n    value_2 = 1\n"
        + "\n".join(f"value_{index} = 1" for index in range(3, 21)),
        encoding="utf-8",
    )

    result = parse_coverage_reports(
        xml_payload=_coverage_xml(tmp_path),
        json_payload=_coverage_json(
            _JsonFixture(
                executed_lines=tuple(range(1, 20)),
                missing_lines=(20,),
            )
        ),
        policy=_report_policy(),
        snapshot_root=tmp_path,
        changed_lines={
            "src/nplg_mcp/errors.py": frozenset(range(1, 21)),
        },
    )

    assert result.diff_line_percent == float(_report_policy().diff_line_floor)
    assert result.diff_branch_arc_percent == _FULL_PERCENT


@pytest.mark.parametrize(
    ("xml_fixture", "json_fixture", "changed_lines"),
    [
        (
            _XmlFixture(class_branch_rate="0.9999"),
            _JsonFixture(),
            {"src/nplg_mcp/errors.py": frozenset({1})},
        ),
        (
            _XmlFixture(),
            _JsonFixture(branch_coverage=False),
            {"src/nplg_mcp/errors.py": frozenset({1})},
        ),
        (
            _XmlFixture(),
            _JsonFixture(executed_branches=()),
            {"src/nplg_mcp/errors.py": frozenset({1})},
        ),
        (
            _XmlFixture(
                root_branch_rate="0.5",
                covered=1,
                condition="50% (1/2)",
            ),
            _JsonFixture(
                executed_branches=((1, 2),),
                missing_branches=((1, 3),),
                covered=1,
                missing=1,
                percent=50,
            ),
            {"src/nplg_mcp/errors.py": frozenset({1})},
        ),
        (
            _XmlFixture(),
            _JsonFixture(executed_lines=(), missing_lines=(1,)),
            {"src/nplg_mcp/errors.py": frozenset({1})},
        ),
        (
            _XmlFixture(),
            _JsonFixture(),
            {"outside.py": frozenset({1})},
        ),
    ],
)
def test_coverage_reports_fail_closed_on_disagreement_or_missing_evidence(
    tmp_path: Path,
    xml_fixture: _XmlFixture,
    json_fixture: _JsonFixture,
    changed_lines: dict[str, frozenset[int]],
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if True:\n    pass\n", encoding="utf-8")

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path, xml_fixture),
            json_payload=_coverage_json(json_fixture),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines=changed_lines,
        )


def test_changed_conditional_requires_branch_pairs_for_the_same_source_line(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("value = True\nif value:\n    pass\n", encoding="utf-8")

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(
                tmp_path,
                _XmlFixture(branch_line=2),
            ),
            json_payload=_coverage_json(
                _JsonFixture(executed_lines=(1, 2)),
            ),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset({2})},
        )


def test_coverage_reports_reject_joint_omission_of_a_changed_conditional(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text(
        "if first:\n    pass\nif second:\n    pass\n",
        encoding="utf-8",
    )

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset({3})},
        )


@pytest.mark.parametrize(
    ("source", "changed_line"),
    [
        ("if anchor:\n    pass\nfor item in values:\n    pass\n", 3),
        ("if anchor:\n    pass\nif value:  # pragma: no branch\n    pass\n", 3),
        (_MATCH_BRANCH_SOURCE, 4),
    ],
)
def test_coverage_reports_reject_joint_omission_of_static_branch_sources(
    tmp_path: Path,
    source: str,
    changed_line: int,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text(source, encoding="utf-8")

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset({changed_line})},
        )


@pytest.mark.parametrize(
    ("source", "changed_line"),
    [
        (_TYPE_CHECKING_SOURCE, 4),
        ("if anchor:\n    pass\nif value:  # pragma: no cover\n    pass\n", 3),
        ("if anchor:\n    pass\nif True:\n    pass\n", 3),
    ],
)
def test_coverage_reports_do_not_invent_excluded_or_partial_branches(
    tmp_path: Path,
    source: str,
    changed_line: int,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text(source, encoding="utf-8")

    result = parse_coverage_reports(
        xml_payload=_coverage_xml(tmp_path),
        json_payload=_coverage_json(),
        policy=_report_policy(),
        snapshot_root=tmp_path,
        changed_lines={"src/nplg_mcp/errors.py": frozenset({changed_line})},
    )

    assert result.diff_branch_arc_percent == _FULL_PERCENT


def test_coverage_reports_cold_load_the_real_pinned_parser(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if anchor:\n    pass\n", encoding="utf-8")

    with _isolated_coverage_bindings():
        assert "coverage" not in sys.modules
        result = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
        )

    assert result.diff_branch_arc_percent == _FULL_PERCENT


@pytest.mark.parametrize(
    ("defect", "message"),
    [
        ("no-origin", "trusted Coverage module has no import origin"),
        ("missing-origin", "trusted Coverage module import origin is unavailable"),
        ("wrong-origin", "trusted Coverage module import origin is invalid"),
        ("orphan", "trusted Coverage package has an orphaned module binding"),
    ],
)
def test_coverage_reports_reject_hostile_real_preloaded_bindings(
    tmp_path: Path,
    defect: str,
    message: str,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if anchor:\n    pass\n", encoding="utf-8")
    hostile_path = tmp_path / "hostile-coverage.py"
    _ = hostile_path.write_text("VALUE = 1\n", encoding="utf-8")
    hostile_module = _loaded_file_module(hostile_path)
    real_parser = importlib.import_module("coverage.parser")
    if defect == "missing-origin":
        hostile_path.unlink()

    with _isolated_coverage_bindings():
        if defect == "no-origin":
            sys.modules["coverage"] = sys
        elif defect == "orphan":
            sys.modules["coverage.parser"] = real_parser
        else:
            sys.modules["coverage"] = hostile_module
        with pytest.raises(GateError, match=message):
            _ = parse_coverage_reports(
                xml_payload=_coverage_xml(tmp_path),
                json_payload=_coverage_json(),
                policy=_report_policy(),
                snapshot_root=tmp_path,
                changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
            )


def test_coverage_reports_clean_partial_bindings_after_real_load_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if anchor:\n    pass\n", encoding="utf-8")
    original_exec = importlib.machinery.SourceFileLoader.exec_module

    def fail_coverage_load(
        loader: importlib.machinery.SourceFileLoader,
        module: ModuleType,
    ) -> None:
        if module.__name__ == "coverage":
            msg = "synthetic real-loader failure"
            raise ImportError(msg)
        original_exec(loader, module)

    monkeypatch.setattr(
        importlib.machinery.SourceFileLoader,
        "exec_module",
        fail_coverage_load,
    )
    with _isolated_coverage_bindings():
        with pytest.raises(
            GateError, match="trusted Coverage package could not be loaded"
        ):
            _ = parse_coverage_reports(
                xml_payload=_coverage_xml(tmp_path),
                json_payload=_coverage_json(),
                policy=_report_policy(),
                snapshot_root=tmp_path,
                changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
            )
        assert not any(
            name == "coverage" or name.startswith("coverage.") for name in sys.modules
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"\xff\n", "changed source is not UTF-8"),
        (b"if:\n", "changed source syntax is invalid"),
    ],
)
def test_coverage_reports_reject_unparseable_changed_source(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_bytes(payload)

    with pytest.raises(GateError, match=message):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
        )


def test_coverage_reports_reject_absent_decision_module_and_source_escape(
    tmp_path: Path,
) -> None:
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(
                tmp_path.parent,
                _XmlFixture(filename="src/nplg_mcp/security.py"),
            ),
            json_payload=_coverage_json(
                _JsonFixture(filename="src/nplg_mcp/security.py"),
            ),
            policy=_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/security.py": frozenset({1})},
        )


def test_coverage_xml_rejects_closed_structure_and_counter_faults(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if True:\n    pass\n", encoding="utf-8")
    valid = _coverage_xml(tmp_path)
    source = f"<source>{tmp_path.as_posix()}</source>".encode()
    class_node = (
        b'<class filename="src/nplg_mcp/errors.py" branch-rate="1" line-rate="1">'
        b'<lines><line number="1" hits="1" branch="true" '
        b'condition-coverage="100% (2/2)"/></lines></class>'
    )
    payloads = (
        b"",
        b"<",
        b"<!DOCTYPE coverage [<!ENTITY x 'unsafe'>]><coverage>&x;</coverage>",
        valid.replace(b"<coverage ", b"<wrong ", 1).replace(
            b"</coverage>", b"</wrong>"
        ),
        valid.replace(b"<sources>" + source + b"</sources>", b"<sources/>", 1),
        valid.replace(source, b"<source></source>", 1),
        valid.replace(source, b"<source>relative</source>", 1),
        valid.replace(source, b"<source>/definitely/absent/nplg</source>", 1),
        valid.replace(
            source,
            f"<source>{tmp_path.parent.as_posix()}</source>".encode(),
            1,
        ),
        valid.replace(source, source + source, 1),
        valid.replace(b"<classes>" + class_node + b"</classes>", b"<classes/>", 1),
        valid.replace(b' filename="src/nplg_mcp/errors.py"', b"", 1),
        valid.replace(b"src/nplg_mcp/errors.py", b"../errors.py", 1),
        valid.replace(b"src/nplg_mcp/errors.py", b"src/nplg_mcp/absent.py", 1),
        valid.replace(b'branch="true"', b'branch="invalid"', 1),
        valid.replace(
            b"</lines>",
            b"".join(
                (
                    b'<line number="1" hits="1" branch="true" ',
                    b'condition-coverage="100% (2/2)"/></lines>',
                )
            ),
            1,
        ),
        valid.replace(
            b'condition-coverage="100% (2/2)"', b'condition-coverage="bad"', 1
        ),
        valid.replace(b"100% (2/2)", b"100% (3/2)", 1),
        valid.replace(b"100% (2/2)", b"50% (2/2)", 1),
        valid.replace(
            b'branch-rate="1" line-rate="1"><lines>', b'line-rate="1"><lines>', 1
        ),
        valid.replace(
            b'branch-rate="1" line-rate="1"><lines>',
            b'branch-rate="bad" line-rate="1"><lines>',
            1,
        ),
        valid.replace(
            b'branch-rate="1" line-rate="1"><lines>',
            b'branch-rate="2" line-rate="1"><lines>',
            1,
        ),
        valid.replace(b'branches-covered="2"', b'branches-covered="x"', 1),
        valid.replace(b'branches-valid="2"', b'branches-valid="1"', 1),
        valid.replace(b"</classes>", class_node + b"</classes>", 1),
    )
    for payload in payloads:
        with pytest.raises(GateError):
            _ = parse_coverage_reports(
                xml_payload=payload,
                json_payload=_coverage_json(),
                policy=_report_policy(),
                snapshot_root=tmp_path,
                changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
            )

    first = tmp_path / "first"
    second = tmp_path / "second"
    for root in (first, second):
        target = root / "src" / "nplg_mcp" / "errors.py"
        target.parent.mkdir(parents=True)
        _ = target.write_text("if True:\n    pass\n", encoding="utf-8")
    ambiguous = valid.replace(
        source,
        (
            f"<source>{first.as_posix()}</source><source>{second.as_posix()}</source>"
        ).encode(),
        1,
    )
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=ambiguous,
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
        )


def test_coverage_reports_reject_symlink_and_hardlink_subjects(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if True:\n    pass\n", encoding="utf-8")
    alias = tmp_path / "alias.py"
    os.link(reported, alias)
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
        )
    alias.unlink()
    reported.unlink()
    reported.symlink_to(tmp_path / "outside.py")
    _ = (tmp_path / "outside.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
        )


def test_coverage_json_rejects_closed_document_and_counter_faults(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if True:\n    pass\n", encoding="utf-8")
    documents: list[object] = [[], {}, {"meta": {}, "files": {}, "totals": {}}]

    document = copy.deepcopy(_coverage_json_document())
    _object_mapping(document["meta"])["extra"] = False
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    del _object_mapping(document["meta"])["branch_coverage"]
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    _object_mapping(document["totals"])["extra"] = 0
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    del _object_mapping(document["totals"])["covered_branches"]
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    _object_mapping(document["totals"])["percent_covered"] = "100"
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    _object_mapping(document["totals"])["percent_covered"] = -1
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    _object_mapping(document["totals"])["num_branches"] = True
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    _object_mapping(document["totals"])["missing_branches"] = 1
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    document["files"] = {}
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    files = _object_mapping(document["files"])
    files["../errors.py"] = files.pop("src/nplg_mcp/errors.py")
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    _object_mapping(document["totals"])["covered_branches"] = 1
    documents.append(document)
    document = copy.deepcopy(_coverage_json_document())
    totals = _object_mapping(document["totals"])
    totals["percent_branches_covered"] = 1
    documents.append(document)

    raw_payloads = (
        b"",
        b"{",
        b"\xff",
        _coverage_json().replace(b'"percent_covered":100', b'"percent_covered":NaN', 1),
        b"[" * 70 + b"0" + b"]" * 70,
    )
    for payload in (*raw_payloads, *(_json_payload(item) for item in documents)):
        with pytest.raises(GateError):
            _ = parse_coverage_reports(
                xml_payload=_coverage_xml(tmp_path),
                json_payload=payload,
                policy=_report_policy(),
                snapshot_root=tmp_path,
                changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
            )


def test_coverage_json_rejects_file_and_line_faults(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if True:\n    pass\n", encoding="utf-8")
    documents: list[dict[str, object]] = []

    document, record = _fresh_coverage_json_file()
    record["extra"] = None
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    del record["summary"]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["executed_lines"] = "1"
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["executed_lines"] = [0]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["executed_lines"] = [1, 1]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["missing_lines"] = [1]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["excluded_lines"] = [True]
    documents.append(document)

    _assert_invalid_coverage_documents(tmp_path, documents)


def test_coverage_json_rejects_branch_and_summary_faults(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if True:\n    pass\n", encoding="utf-8")
    documents: list[dict[str, object]] = []

    document, record = _fresh_coverage_json_file()
    record["executed_branches"] = "1,2"
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["executed_branches"] = [[1]]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["executed_branches"] = [[0, 2]]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["executed_branches"] = [[1, 0]]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["executed_branches"] = [[1, 2], [1, 2]]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["missing_branches"] = [[1, 2]]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    record["summary"] = []
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    summary = _object_mapping(record["summary"])
    summary["extra"] = 0
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    summary = _object_mapping(record["summary"])
    del summary["num_branches"]
    documents.append(document)
    document, record = _fresh_coverage_json_file()
    summary = _object_mapping(record["summary"])
    summary["covered_branches"] = 1
    documents.append(document)

    _assert_invalid_coverage_documents(tmp_path, documents)


def test_coverage_changed_evidence_and_zero_branch_cases_fail_closed(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("if True:\n    pass\n", encoding="utf-8")
    invalid_changed = (
        cast("dict[str, frozenset[int]]", cast("object", [])),
        {"../errors.py": frozenset[int]({1})},
        cast(
            "dict[str, frozenset[int]]",
            cast("object", {"src/nplg_mcp/errors.py": list[int]([1])}),
        ),
        {"src/nplg_mcp/errors.py": frozenset({0})},
        {"scripts/absent.py": frozenset({1})},
    )
    for changed in invalid_changed:
        with pytest.raises(GateError):
            _ = parse_coverage_reports(
                xml_payload=_coverage_xml(tmp_path),
                json_payload=_coverage_json(),
                policy=_report_policy(),
                snapshot_root=tmp_path,
                changed_lines=changed,
            )

    zero_xml = _coverage_xml(
        tmp_path,
        _XmlFixture(covered=0, valid=0, condition="0% (0/0)"),
    )
    zero_json = _coverage_json(
        _JsonFixture(
            executed_branches=(),
            covered=0,
            total=0,
            percent=100,
        )
    )
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=zero_xml,
            json_payload=zero_json,
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={"src/nplg_mcp/errors.py": frozenset()},
        )

    decimal_document = _coverage_json_document()
    _object_mapping(decimal_document["totals"])["percent_covered"] = 100.0
    _object_mapping(
        _object_mapping(decimal_document["files"])["src/nplg_mcp/errors.py"]
    )["summary"] = {
        "percent_covered": 100.0,
        "num_branches": 2,
        "covered_branches": 2,
        "missing_branches": 0,
    }
    result = parse_coverage_reports(
        xml_payload=_coverage_xml(tmp_path),
        json_payload=_json_payload(decimal_document),
        policy=_report_policy(),
        snapshot_root=tmp_path,
        changed_lines={"src/nplg_mcp/errors.py": frozenset({1})},
    )
    assert result.project_branch_percent == _FULL_PERCENT


def _write_package(root: Path, files: dict[str, bytes]) -> None:
    for relative, payload in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_bytes(payload)
        target.chmod(0o644)


def _package_manifest(
    files: dict[str, bytes],
    *,
    declared_package_data: tuple[str, ...] = (),
) -> bytes:
    return _json_payload(
        _package_manifest_document(
            files,
            declared_package_data=declared_package_data,
        )
    )


def _package_manifest_document(
    files: dict[str, bytes],
    *,
    declared_package_data: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "version": 1,
        "package": "nplg_mcp",
        "declared_package_data": list(declared_package_data),
        "files": [
            {
                "path": path,
                "mode": 0o644,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for path, payload in sorted(files.items())
        ],
    }


def _manifest_files(document: dict[str, object]) -> list[object]:
    value = document["files"]
    assert type(value) is list
    return cast("list[object]", value)


def _first_manifest_record(document: dict[str, object]) -> dict[str, object]:
    files = _manifest_files(document)
    assert files
    return _object_mapping(files[0])


def _assert_invalid_manifests(
    source: Path,
    installed: Path,
    documents: list[object],
) -> None:
    for document in documents:
        with pytest.raises(GateError):
            _ = verify_installed_package(
                installed_package_root=installed,
                source_package_root=source,
                manifest_payload=_json_payload(document),
                discovered_package_roots=(installed,),
            )


def test_installed_package_inventory_authorizes_only_the_exact_alias(
    tmp_path: Path,
) -> None:
    files = {"__init__.py": b"VALUE = 7\n", "py.typed": b""}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)

    proof = verify_installed_package(
        installed_package_root=installed,
        source_package_root=source,
        manifest_payload=_package_manifest(files),
        discovered_package_roots=(installed,),
    )

    assert proof.source_package_root == source
    assert proof.installed_package_root == installed
    assert proof.files == (
        InstalledFileRecord(
            path="__init__.py",
            mode=0o644,
            sha256=hashlib.sha256(files["__init__.py"]).hexdigest(),
        ),
        InstalledFileRecord(
            path="py.typed",
            mode=0o644,
            sha256=hashlib.sha256(files["py.typed"]).hexdigest(),
        ),
    )
    assert (
        proof.coverage_paths_configuration
        == (
            "[paths]\n"
            "nplg_mcp =\n"
            f"    {source.as_posix()}\n"
            f"    {installed.as_posix()}\n"
        ).encode()
    )


def test_installed_package_inventory_rejects_parent_component_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = {
        "__init__.py": b"",
        "nested/value.py": b"VALUE = 7\n",
    }
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    outside = tmp_path / "outside"
    _write_package(source, files)
    _write_package(installed, files)
    _write_package(outside, {"value.py": files["nested/value.py"]})
    original_lstat = Path.lstat
    original_open = os.open
    swapped = False

    def replace_parent() -> None:
        nonlocal swapped
        if not swapped:
            _ = installed.joinpath("nested").rename(installed / "nested-original")
            installed.joinpath("nested").symlink_to(outside, target_is_directory=True)
            swapped = True

    def swap_parent_lstat(path: Path) -> os.stat_result:
        if path == installed / "nested" / "value.py":
            replace_parent()
        return original_lstat(path)

    def swap_parent_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if (
            path == "nested"
            and dir_fd is not None
            and Path(f"/proc/self/fd/{dir_fd}").resolve(strict=True) == installed
        ):
            replace_parent()
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(Path, "lstat", swap_parent_lstat)
    monkeypatch.setattr("scripts.run_test_gate.os.open", swap_parent_open)

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=_package_manifest(files),
            discovered_package_roots=(installed,),
        )
    assert swapped


def test_installed_inventory_rejects_unexpected_tree_before_opening_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = {
        "__init__.py": b"",
        "expected/value.py": b"VALUE = 7\n",
    }
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    _write_package(source, {"unexpected/value.py": b"VALUE = 8\n"})
    original_open = os.open
    expected_opened = False
    unexpected_opened = False

    def observe_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal expected_opened, unexpected_opened
        if dir_fd is not None and path == "expected":
            expected_opened = True
        if dir_fd is not None and path == "unexpected":
            unexpected_opened = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("scripts.run_test_gate.os.open", observe_open)
    descriptors_before = len(tuple(Path("/proc/self/fd").iterdir()))
    with pytest.raises(GateError, match="unexpected package inventory entry"):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=_package_manifest(files),
            discovered_package_roots=(installed,),
        )
    descriptors_after = len(tuple(Path("/proc/self/fd").iterdir()))

    assert expected_opened
    assert not unexpected_opened
    assert descriptors_after == descriptors_before


@pytest.mark.parametrize(
    "defect",
    [
        "extra-installed",
        "changed-installed",
        "installed-symlink",
        "second-package",
        "source-import",
        "manifest-escape",
        "manifest-duplicate",
        "undeclared-data",
    ],
)
def test_installed_package_inventory_rejects_every_mismatch_or_spoof(
    tmp_path: Path,
    defect: str,
) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    manifest = _package_manifest(files)
    discovered: tuple[Path, ...] = (installed,)
    if defect == "extra-installed":
        _write_package(installed, {"extra.py": b"EXTRA = True\n"})
    elif defect == "changed-installed":
        _ = (installed / "__init__.py").write_bytes(b"VALUE = 8\n")
    elif defect == "installed-symlink":
        (installed / "__init__.py").unlink()
        (installed / "__init__.py").symlink_to(source / "__init__.py")
    elif defect == "second-package":
        second = tmp_path / "other-site-packages" / "nplg_mcp"
        _write_package(second, files)
        discovered = (installed, second)
    elif defect == "source-import":
        discovered = (source,)
    elif defect == "manifest-escape":
        manifest = manifest.replace(b'"path":"__init__.py"', b'"path":"../escape.py"')
    elif defect == "manifest-duplicate":
        record: dict[str, object] = {
            "path": "__init__.py",
            "mode": 0o644,
            "sha256": hashlib.sha256(files["__init__.py"]).hexdigest(),
        }
        duplicate_document: dict[str, object] = {
            "version": 1,
            "package": "nplg_mcp",
            "declared_package_data": list[str](),
            "files": [record, record],
        }
        manifest = json.dumps(duplicate_document).encode()
    else:
        _write_package(source, {"schema.json": b"{}\n"})
        _write_package(installed, {"schema.json": b"{}\n"})
        manifest = _package_manifest({**files, "schema.json": b"{}\n"})

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=manifest,
            discovered_package_roots=discovered,
        )


def test_installed_manifest_rejects_document_and_declaration_faults(
    tmp_path: Path,
) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    documents: list[object] = [[], {}, {"version": 1}]

    document = _package_manifest_document(files)
    document["extra"] = None
    documents.append(document)
    document = _package_manifest_document(files)
    document["package"] = "other"
    documents.append(document)
    document = _package_manifest_document(files)
    document["declared_package_data"] = "schema.json"
    documents.append(document)
    document = _package_manifest_document(files)
    document["declared_package_data"] = [1]
    documents.append(document)
    document = _package_manifest_document(files)
    document["declared_package_data"] = ["z.json", "a.json"]
    documents.append(document)
    document = _package_manifest_document(files)
    document["declared_package_data"] = ["module.py"]
    documents.append(document)
    document = _package_manifest_document(files)
    document["declared_package_data"] = ["schema.json"]
    documents.append(document)
    _assert_invalid_manifests(source, installed, documents)


def test_installed_manifest_rejects_file_record_and_inventory_faults(
    tmp_path: Path,
) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    documents: list[object] = []

    document = _package_manifest_document(files)
    document["files"] = "not-an-array"
    documents.append(document)
    document = _package_manifest_document(files)
    document["files"] = []
    documents.append(document)
    document = _package_manifest_document(files)
    document["files"] = [[]]
    documents.append(document)
    document = _package_manifest_document(files)
    _first_manifest_record(document)["extra"] = None
    documents.append(document)
    document = _package_manifest_document(files)
    _first_manifest_record(document)["path"] = "/absolute.py"
    documents.append(document)
    document = _package_manifest_document(files)
    _first_manifest_record(document)["mode"] = True
    documents.append(document)
    document = _package_manifest_document(files)
    _first_manifest_record(document)["mode"] = -1
    documents.append(document)
    document = _package_manifest_document(files)
    _first_manifest_record(document)["sha256"] = 7
    documents.append(document)
    document = _package_manifest_document(files)
    _first_manifest_record(document)["sha256"] = "bad"
    documents.append(document)
    document = _package_manifest_document(files)
    _first_manifest_record(document)["path"] = "schema.json"
    documents.append(document)
    document = _package_manifest_document({"__init__.py": b"x", "z.py": b"z"})
    _manifest_files(document).reverse()
    documents.append(document)
    document = _package_manifest_document({"module.py": b"x"})
    documents.append(document)

    _assert_invalid_manifests(source, installed, documents)


def test_installed_inventory_accepts_declared_nested_data_and_dist_packages(
    tmp_path: Path,
) -> None:
    workflow_path = "agent_skills/georgian-newspaper-visual-analysis/SKILL.md"
    files = {"__init__.py": b"VALUE = 7\n", workflow_path: b"workflow\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "dist-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)

    proof = verify_installed_package(
        installed_package_root=installed,
        source_package_root=source,
        manifest_payload=_package_manifest(
            files,
            declared_package_data=(workflow_path,),
        ),
        discovered_package_roots=(installed,),
    )

    assert tuple(record.path for record in proof.files) == (
        "__init__.py",
        workflow_path,
    )


def test_installed_manifest_rejects_duplicate_package_data_declaration(
    tmp_path: Path,
) -> None:
    workflow_path = "agent_skills/georgian-newspaper-visual-analysis/SKILL.md"
    files = {"__init__.py": b"VALUE = 7\n", workflow_path: b"workflow\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)

    with pytest.raises(GateError, match="entries must be unique"):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=_package_manifest(
                files,
                declared_package_data=(workflow_path, workflow_path),
            ),
            discovered_package_roots=(installed,),
        )


@pytest.mark.parametrize(
    "defect",
    [
        "relative-source",
        "wrong-source-name",
        "missing-source",
        "source-alias",
        "source-file",
        "wrong-source-parent",
        "wrong-installed-parent",
        "overlap",
    ],
)
def test_installed_inventory_rejects_root_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    manifest = _package_manifest(files)
    if defect == "relative-source":
        source = Path("src/nplg_mcp")
    elif defect == "wrong-source-name":
        source = tmp_path / "src" / "wrong"
        _write_package(source, files)
    elif defect == "missing-source":
        source = tmp_path / "src" / "missing" / "nplg_mcp"
    elif defect == "source-alias":
        alias_parent = tmp_path / "alias-src"
        alias_parent.mkdir()
        alias = alias_parent / "nplg_mcp"
        alias.symlink_to(source, target_is_directory=True)
        source = alias
    elif defect == "source-file":
        source = tmp_path / "file-src" / "nplg_mcp"
        source.parent.mkdir()
        _ = source.write_bytes(b"not a directory")
    elif defect == "wrong-source-parent":
        source = tmp_path / "source" / "nplg_mcp"
        _write_package(source, files)
    elif defect == "wrong-installed-parent":
        installed = tmp_path / "installed" / "nplg_mcp"
        _write_package(installed, files)
    else:
        installed = source / "site-packages" / "nplg_mcp"
        _write_package(installed, files)

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=manifest,
            discovered_package_roots=(installed,),
        )


@pytest.mark.parametrize(
    "defect",
    [
        "empty",
        "special",
        "hardlink",
    ],
)
def test_installed_inventory_rejects_filesystem_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    manifest = _package_manifest(files)
    if defect == "empty":
        source.joinpath("__init__.py").unlink()
    elif defect == "special":
        os.mkfifo(source / "special.py")
    else:
        os.link(source / "__init__.py", source / "alias.py")

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=manifest,
            discovered_package_roots=(installed,),
        )


@pytest.mark.parametrize("limit", ["file", "total"])
def test_installed_inventory_enforces_byte_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    constant = (
        "scripts.run_test_gate._MAX_PACKAGE_FILE_BYTES"
        if limit == "file"
        else "scripts.run_test_gate._MAX_PACKAGE_TOTAL_BYTES"
    )
    monkeypatch.setattr(constant, 1)

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=_package_manifest(files),
            discovered_package_roots=(installed,),
        )


def _git_command(root: Path, cache: Path, *arguments: str) -> bytes:
    result = run_bounded_command(
        ("/usr/bin/git", *arguments),
        root=root,
        cache_dir=cache,
    )
    return result.stdout


def _initialize_gate_repository(
    tmp_path: Path,
    *,
    extra_files: Mapping[str, bytes] | None = None,
    dirty: bool = True,
) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    cache = tmp_path / "git-cache"
    repository.mkdir()
    cache.mkdir(mode=0o700)
    _ = _git_command(repository, cache, "init", "-q", ".")
    for relative in _policy().decision_modules:
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_text("if True:\n    pass\n", encoding="utf-8")
    policy_document: dict[str, object] = {
        "version": 1,
        "project_branch_floor": 95,
        "diff_line_floor": 95,
        "diff_branch_arc_floor": 95,
        "decision_module_branch_floor": 100,
        "measured_roots": list(_policy().measured_roots),
        "decision_modules": list(_policy().decision_modules),
    }
    security = repository / "security"
    security.mkdir()
    _ = (security / "coverage-policy.json").write_text(
        json.dumps(policy_document, separators=(",", ":")),
        encoding="utf-8",
    )
    _ = (security / "external-test-gates.json").write_bytes(
        Path(__file__)
        .resolve()
        .parents[2]
        .joinpath("security/external-test-gates.json")
        .read_bytes()
    )
    tests = repository / "tests"
    tests.mkdir()
    _ = (tests / "test_ok.py").write_text(
        "def test_ok() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    integration = tests / "integration"
    integration.mkdir()
    _ = integration.joinpath("test_repository.py").write_text(
        """
import pytest


@pytest.mark.live
def test_live_nplg_canary_uses_bound_public_endpoint() -> None:
    assert True
""".lstrip(),
        encoding="utf-8",
    )
    _ = repository.joinpath("pytest.ini").write_text(
        """
[pytest]
markers =
    live: protected live authority
    staging: protected staging authority
    container: protected container authority
""".lstrip(),
        encoding="utf-8",
    )
    for relative, payload in (extra_files or {}).items():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_bytes(payload)
    _ = _git_command(repository, cache, "add", "--all")
    _ = _git_command(
        repository,
        cache,
        "-c",
        "user.name=NPLG Test Gate",
        "-c",
        "user.email=nplg-test-gate.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "base",
    )
    _ = _git_command(repository, cache, "branch", "base")
    if dirty:
        _ = (repository / "src" / "nplg_mcp" / "errors.py").write_text(
            "if False:\n    pass\n",
            encoding="utf-8",
        )
    else:
        _ = (repository / "src" / "nplg_mcp" / "errors.py").write_text(
            "if False:\n    pass\n",
            encoding="utf-8",
        )
        _ = _git_command(repository, cache, "add", "src/nplg_mcp/errors.py")
        _ = _git_command(
            repository,
            cache,
            "-c",
            "user.name=NPLG Test Gate",
            "-c",
            "user.email=nplg-test-gate.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "candidate",
        )
    return repository.resolve(strict=True), cache.resolve(strict=True)


def _initialize_real_cli_repository(
    tmp_path: Path,
    *,
    cover_every_branch: bool,
) -> tuple[Path, Path]:
    repository, cache = _initialize_gate_repository(tmp_path, dirty=False)
    for relative in _policy().decision_modules:
        _ = repository.joinpath(relative).write_text(
            """
def decide(value: bool) -> int:
    result = 0
    if value:
        result = 1
    return result
""".lstrip(),
            encoding="utf-8",
        )
    _ = repository.joinpath("src/nplg_mcp/__init__.py").write_bytes(b"")
    _ = repository.joinpath("tests/conftest.py").write_text(
        """
from hypothesis import settings

settings.register_profile(
    "ci",
    settings(
        database=None,
        deadline=None,
        derandomize=True,
        max_examples=1,
        print_blob=True,
    ),
)
""".lstrip(),
        encoding="utf-8",
    )
    module_names = tuple(
        (relative.removeprefix("src/").removesuffix(".py").replace("/", "."))
        for relative in _policy().decision_modules
    )
    false_module_names = tuple(
        name for name in module_names if cover_every_branch or name != "nplg_mcp.errors"
    )
    test_source = "\n".join(
        (
            "import importlib",
            "",
            f"MODULE_NAMES = {module_names!r}",
            f"FALSE_MODULE_NAMES = {false_module_names!r}",
            "",
            "def test_all_decisions() -> None:",
            "    for name in MODULE_NAMES:",
            "        module = importlib.import_module(name)",
            "        assert module.decide(True) == 1",
            "    for name in FALSE_MODULE_NAMES:",
            "        module = importlib.import_module(name)",
            "        assert module.decide(False) == 0",
            "",
        )
    )
    _ = repository.joinpath("tests/test_ok.py").write_text(
        test_source,
        encoding="utf-8",
    )
    return repository, cache


def _initialize_installed_gate(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, str]:
    repository, git_cache = _initialize_gate_repository(
        tmp_path,
        extra_files={"src/nplg_mcp/__init__.py": b""},
        dirty=False,
    )
    source = repository / "src" / "nplg_mcp"
    files = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(installed, files)
    manifest = tmp_path / "package-manifest.json"
    _ = manifest.write_bytes(_package_manifest(files))
    head = _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()
    return repository, git_cache, installed, manifest, head


def _installed_gate_request(
    repository: Path,
    output: Path,
    installed: Path,
    manifest: Path,
    head: str,
) -> GateRequest:
    return GateRequest(
        worktree=repository,
        compare_branch="refs/heads/base",
        output_dir=output,
        require_clean=True,
        candidate=head,
        installed_package_root=installed,
        package_manifest=manifest,
    )


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


def test_run_test_gate_reaches_behavioral_red(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    before = _source_git_state(repository, git_cache)
    executor = _CoverageExecutor()
    request = GateRequest(
        worktree=repository,
        compare_branch="refs/heads/base",
        output_dir=output,
    )

    result = run_test_gate(
        request,
        executor=executor,
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert result.coverage_xml == output / "coverage.xml"
    assert result.coverage_json == output / "coverage.json"
    assert result.measurements.project_branch_percent == _FULL_PERCENT
    assert _source_git_state(repository, git_cache) == before
    assert stat.S_IMODE(output.stat().st_mode) == _PRIVATE_DIRECTORY_MODE
    assert not (repository / ".coverage").exists()
    assert not (repository / ".pytest_cache").exists()
    assert (output / "snapshot" / ".git").is_dir()
    assert (output / "coverage.rc").is_file()
    assert (output / "pytest-junit.xml").is_file()
    assert (output / "diff-cover.json").read_bytes() == b"{}\n"
    assert (output / ".coverage.fake").is_file()
    command_record = cast(
        "dict[str, object]",
        cast("object", json.loads((output / "command-records.json").read_bytes())),
    )
    assert command_record["version"] == 1
    assert (
        len(cast("list[object]", command_record["commands"]))
        == _EXPECTED_COMMAND_RECORDS
    )
    assert executor.requests
    collection_requests = tuple(
        child for child in executor.requests if "--collect-only" in child.argv
    )
    assert collection_requests
    assert all(
        child.stdout_limit_bytes == _COLLECTION_OUTPUT_LIMIT_BYTES
        for child in collection_requests
    )


def test_coverage_report_commands_prebind_materialized_package(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    executor = _CoverageExecutor()

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=executor,
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    expected_package_root = output / "snapshot" / "src" / "nplg_mcp"
    coverage_reports = tuple(
        request
        for request in executor.requests
        if len(request.argv) > _TRUSTED_DRIVER_PACKAGE_ROOT_INDEX
        and request.argv[_TRUSTED_DRIVER_MODE_INDEX] == "coverage"
    )
    assert len(coverage_reports) == _EXPECTED_COVERAGE_REPORT_COMMANDS
    assert all(
        cast(
            "object",
            json.loads(request.argv[_TRUSTED_DRIVER_PACKAGE_ROOT_INDEX]),
        )
        == expected_package_root.as_posix()
        for request in coverage_reports
    )


def test_coverage_configuration_binds_materialized_source_roots(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    snapshot = output / "snapshot"
    configuration = (output / "coverage.rc").read_text(encoding="utf-8")
    assert f"source =\n    {snapshot.as_posix()}\n" in configuration
    assert f"omit =\n    {(snapshot / 'tests' / '*').as_posix()}\n" in configuration
    assert "    nplg_mcp\n" not in configuration
    assert "    scripts\n" not in configuration


def test_run_test_gate_accepts_a_bounded_large_pytest_audit(tmp_path: Path) -> None:
    class LargeAuditExecutor(_CoverageExecutor):
        @override
        def __call__(self, request: CommandRequest) -> CommandResult:
            result = super().__call__(request)
            if "coverage-pytest" in request.argv:
                audit_path = Path(
                    next(
                        value
                        for value in request.argv
                        if value.endswith("pytest-audit.json")
                    )
                )
                payload = audit_path.read_bytes()
                _ = audit_path.write_bytes(b" " * (64 * 1024) + payload)
            return result

    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=LargeAuditExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert result.measurements.project_branch_percent == _FULL_PERCENT


def test_run_test_gate_accepts_multiple_passing_subtest_reports(tmp_path: Path) -> None:
    class SubtestAuditExecutor(_CoverageExecutor):
        @override
        def __call__(self, request: CommandRequest) -> CommandResult:
            result = super().__call__(request)
            if "coverage-pytest" in request.argv:
                audit_path = Path(
                    next(
                        value
                        for value in request.argv
                        if value.endswith("pytest-audit.json")
                    )
                )
                audit = cast(
                    "dict[str, object]",
                    cast("object", json.loads(audit_path.read_bytes())),
                )
                calls = cast("list[object]", audit["calls"])
                calls.append(["tests/test_ok.py::test_ok", "passed"])
                _ = audit_path.write_text(
                    json.dumps(audit, separators=(",", ":")),
                    encoding="utf-8",
                )
            return result

    repository, git_cache = _initialize_gate_repository(tmp_path)

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=(tmp_path / "external-output").resolve(),
        ),
        executor=SubtestAuditExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert result.measurements.project_branch_percent == _FULL_PERCENT


def test_test_gate_cli_parser_reaches_behavioral_red(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    output = tmp_path / "external-output"

    request = parse_arguments(
        (
            "--compare-branch",
            "refs/heads/base",
            "--worktree",
            repository.as_posix(),
            "--output-dir",
            output.as_posix(),
            "--require-clean",
            "--candidate",
            "a" * 40,
        )
    )

    assert request == GateRequest(
        worktree=repository,
        compare_branch="refs/heads/base",
        output_dir=output,
        require_clean=True,
        candidate="a" * 40,
    )


def test_test_gate_system_adapters_reach_behavioral_red(tmp_path: Path) -> None:
    payload = tmp_path / "payload.bin"
    _ = payload.write_bytes(b"payload")
    environment = (
        ("LANG", "C.UTF-8"),
        ("PATH", "/usr/bin:/bin"),
        ("PYTHONNOUSERSITE", "1"),
    )

    result = SystemExecutor()(
        CommandRequest(
            argv=(
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'bounded')",
            ),
            cwd=tmp_path,
            environment=environment,
            timeout_seconds=10.0,
        )
    )
    git_result = SystemGit().run(
        ("/usr/bin/git", "--version"),
        cwd=tmp_path,
        environment=dict(environment),
    )

    assert result.stdout == b"bounded"
    assert result.stderr == b""
    assert git_result.stdout.startswith(b"git version ")
    assert SystemFilesystem().read_bytes(payload) == b"payload"
    assert SystemClock().monotonic() > 0


def _system_request(tmp_path: Path) -> CommandRequest:
    return CommandRequest(
        argv=(sys.executable, "-c", "raise SystemExit(0)"),
        cwd=tmp_path,
        environment=(
            ("LANG", "C.UTF-8"),
            ("PATH", "/usr/bin:/bin"),
            ("PYTHONNOUSERSITE", "1"),
        ),
        timeout_seconds=10.0,
    )


@pytest.mark.parametrize(
    "defect",
    ["list", "empty", "argument-type", "empty-argument", "nul", "oversized"],
)
def test_system_executor_rejects_malformed_argv(
    tmp_path: Path,
    defect: str,
) -> None:
    request = _system_request(tmp_path)
    values: object
    if defect == "list":
        values = list(request.argv)
    elif defect == "empty":
        values = ()
    elif defect == "argument-type":
        values = (sys.executable, 7)
    elif defect == "empty-argument":
        values = (sys.executable, "")
    elif defect == "nul":
        values = (sys.executable, "bad\0argument")
    else:
        values = (sys.executable, "x" * (1024 * 1024 + 1))

    with pytest.raises(GateError):
        _ = SystemExecutor()(replace(request, argv=cast("tuple[str, ...]", values)))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout", True),
        ("timeout", float("nan")),
        ("timeout", 0.0),
        ("timeout", 86_401.0),
        ("stdout", True),
        ("stdout", 0),
        ("stdout", 64 * 1024 * 1024 + 1),
        ("stderr", True),
        ("stderr", 0),
        ("stderr", 64 * 1024 * 1024 + 1),
    ],
)
def test_system_executor_rejects_invalid_resource_bounds(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    request = _system_request(tmp_path)
    if field == "timeout":
        request = replace(request, timeout_seconds=cast("float", value))
    elif field == "stdout":
        request = replace(request, stdout_limit_bytes=cast("int", value))
    else:
        request = replace(request, stderr_limit_bytes=cast("int", value))

    with pytest.raises(GateError):
        _ = SystemExecutor()(request)


@pytest.mark.parametrize("defect", ["type", "relative", "missing", "alias", "file"])
def test_system_executor_rejects_noncanonical_working_directories(
    tmp_path: Path,
    defect: str,
) -> None:
    request = _system_request(tmp_path)
    cwd: object
    if defect == "type":
        cwd = tmp_path.as_posix()
    elif defect == "relative":
        cwd = Path("relative")
    elif defect == "missing":
        cwd = (tmp_path / "missing").resolve()
    elif defect == "alias":
        alias = tmp_path.parent / f"{tmp_path.name}-alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        cwd = alias
    else:
        file_path = tmp_path / "not-a-directory"
        _ = file_path.write_bytes(b"x")
        cwd = file_path

    with pytest.raises(GateError):
        _ = SystemExecutor()(replace(request, cwd=cast("Path", cwd)))


@pytest.mark.parametrize(
    "defect",
    ["mapping", "pair", "length", "key-type", "value-type", "key", "nul", "duplicate"],
)
def test_system_executor_rejects_malformed_closed_environments(
    tmp_path: Path,
    defect: str,
) -> None:
    request = _system_request(tmp_path)
    environment: object
    if defect == "mapping":
        environment = list(request.environment)
    elif defect == "pair":
        environment = (["LANG", "C.UTF-8"],)
    elif defect == "length":
        environment = (("LANG",),)
    elif defect == "key-type":
        environment = ((7, "value"),)
    elif defect == "value-type":
        environment = (("LANG", 7),)
    elif defect == "key":
        environment = (("lowercase", "value"),)
    elif defect == "nul":
        environment = (("LANG", "bad\0value"),)
    else:
        environment = (("LANG", "one"), ("LANG", "two"))

    with pytest.raises(GateError):
        _ = SystemExecutor()(
            replace(
                request,
                environment=cast("tuple[tuple[str, str], ...]", environment),
            )
        )


@pytest.mark.parametrize(
    "defect",
    ["outside", "missing", "directory", "target", "mode"],
)
def test_system_executor_rejects_unreviewed_executable_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    if defect == "outside":
        request = replace(_system_request(tmp_path), argv=("/bin/true",))
    else:
        executable = tmp_path / "python"
        if defect == "missing":
            pass
        elif defect == "directory":
            executable.mkdir()
        elif defect == "target":
            target = tmp_path / "target-directory"
            target.mkdir()
            executable.symlink_to(target, target_is_directory=True)
        else:
            _ = executable.write_bytes(b"not executable")
            executable.chmod(0o600)
        monkeypatch.setattr(sys, "executable", executable.as_posix())
        request = _system_request(tmp_path)

    with pytest.raises(GateError):
        _ = SystemExecutor()(request)


def test_system_executor_translates_bounded_process_failure(tmp_path: Path) -> None:
    request = replace(
        _system_request(tmp_path),
        argv=(sys.executable, "-c", "print('too large')"),
        stdout_limit_bytes=1,
    )

    with pytest.raises(GateError, match="bounded system command failed"):
        _ = SystemExecutor()(request)


def test_system_executor_rejects_executable_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identities = iter(((1,), (2,)))

    def identity(_path: Path) -> tuple[int, ...]:
        return next(identities)

    def bounded(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("scripts.run_test_gate._system_executable_identity", identity)
    monkeypatch.setattr("scripts.run_test_gate.run_bounded_process", bounded)

    with pytest.raises(GateError, match="executable changed"):
        _ = SystemExecutor()(_system_request(tmp_path))


def test_test_gate_main_reaches_behavioral_red(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    output = tmp_path / "external-output"
    observed: list[GateRequest] = []

    def fake_gate(
        request: GateRequest,
        *,
        executor: object,
        clock: object,
        filesystem: object,
        git: object,
    ) -> GateResult:
        assert isinstance(executor, SystemExecutor)
        assert isinstance(clock, SystemClock)
        assert isinstance(filesystem, SystemFilesystem)
        assert isinstance(git, SystemGit)
        observed.append(request)
        return GateResult(
            coverage_xml=output / "coverage.xml",
            coverage_json=output / "coverage.json",
            measurements=CoverageReportResult(
                project_branch_percent=100.0,
                diff_line_percent=100.0,
                diff_branch_arc_percent=100.0,
                decision_module_branch_percent=(("scripts/run_test_gate.py", 100.0),),
            ),
        )

    monkeypatch.setattr("scripts.run_test_gate.run_test_gate", fake_gate)

    result = cli(
        (
            "--compare-branch",
            "refs/heads/base",
            "--worktree",
            repository.as_posix(),
            "--output-dir",
            output.as_posix(),
        )
    )

    assert result == 0
    assert observed == [
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        )
    ]
    rendered = cast(
        "dict[str, object]",
        cast("object", json.loads(capsys.readouterr().out)),
    )
    assert rendered["project_branch_percent"] == _FULL_PERCENT


def test_test_gate_script_help_is_directly_invocable(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    result = SystemExecutor()(
        CommandRequest(
            argv=(
                sys.executable,
                (repository / "scripts" / "run_test_gate.py").as_posix(),
                "--help",
            ),
            cwd=repository,
            environment=(
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
                ("PATH", "/usr/bin:/bin"),
                ("PYTHONNOUSERSITE", "1"),
                ("PYTHONPATH", repository.as_posix()),
                ("TMPDIR", tmp_path.as_posix()),
            ),
            timeout_seconds=10.0,
        )
    )

    assert result.returncode == 0
    assert b"--compare-branch" in result.stdout
    assert result.stderr == b""


@pytest.mark.parametrize("defect", ["python", "cwd", "missing-tool", "wrong-tool"])
def test_test_gate_runtime_preflight_and_cli_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    defect: str,
) -> None:
    if defect == "python":
        monkeypatch.setattr(sys, "version_info", SimpleNamespace(major=2, minor=7))
    elif defect == "cwd":
        current = Path.cwd()
        real_resolve = Path.resolve

        def failing_resolve(path: Path, *, strict: bool = False) -> Path:
            if path == current:
                message = "synthetic cwd failure"
                raise OSError(message)
            return real_resolve(path, strict=strict)

        monkeypatch.setattr(Path, "resolve", failing_resolve)
    elif defect == "missing-tool":

        def missing_version(distribution: str) -> str:
            raise importlib.metadata.PackageNotFoundError(distribution)

        monkeypatch.setattr(importlib.metadata, "version", missing_version)
    else:

        def wrong_version(_distribution: str) -> str:
            return "0.0.0"

        monkeypatch.setattr(importlib.metadata, "version", wrong_version)

    result = cli(
        (
            "--compare-branch",
            "refs/heads/base",
            "--worktree",
            tmp_path.as_posix(),
        )
    )

    assert result == 1
    assert capsys.readouterr().err.startswith("test gate failed: ")


def test_test_gate_main_module_guard_is_executable(
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    script = project_root / "scripts" / "run_test_gate.py"
    result = SystemExecutor()(
        CommandRequest(
            argv=(sys.executable, script.as_posix(), "--help"),
            cwd=project_root,
            environment=(
                ("HOME", tmp_path.as_posix()),
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
                ("PATH", Path(sys.executable).parent.as_posix()),
                ("PYTHONNOUSERSITE", "1"),
                ("TMPDIR", tmp_path.as_posix()),
            ),
            timeout_seconds=30.0,
            stdout_limit_bytes=64 * 1024,
            stderr_limit_bytes=64 * 1024,
        )
    )

    assert result.returncode == 0
    assert b"--compare-branch" in result.stdout
    assert result.stderr == b""


def test_test_gate_main_guard_runs_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "run_test_gate.py"
    monkeypatch.setattr(sys, "argv", [script.as_posix(), "--help"])

    with pytest.raises(SystemExit) as raised:
        _ = cast(
            "dict[str, object]",
            runpy.run_path(script.as_posix(), run_name="__main__"),
        )

    assert raised.value.code == 0


@pytest.mark.parametrize("cover_every_branch", [True, False])
def test_real_cli_accepts_complete_coverage_and_rejects_an_uncovered_branch(
    tmp_path: Path,
    *,
    cover_every_branch: bool,
) -> None:
    repository, _cache = _initialize_real_cli_repository(
        tmp_path,
        cover_every_branch=cover_every_branch,
    )
    project_root = Path(__file__).resolve().parents[2]
    output = (tmp_path / "real-cli-output").resolve()
    home = tmp_path / "real-cli-home"
    temporary = tmp_path / "real-cli-tmp"
    home.mkdir()
    temporary.mkdir()
    result = SystemExecutor()(
        CommandRequest(
            argv=(
                sys.executable,
                "-m",
                "scripts.run_test_gate",
                "--compare-branch",
                "refs/heads/base",
                "--worktree",
                repository.as_posix(),
                "--output-dir",
                output.as_posix(),
            ),
            cwd=project_root,
            environment=(
                ("HOME", home.as_posix()),
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
                (
                    "PATH",
                    os.pathsep.join(
                        (Path(sys.executable).parent.as_posix(), "/usr/bin", "/bin")
                    ),
                ),
                ("PYTHONNOUSERSITE", "1"),
                ("TMPDIR", temporary.as_posix()),
            ),
            timeout_seconds=120.0,
            stdout_limit_bytes=8 * 1024 * 1024,
            stderr_limit_bytes=8 * 1024 * 1024,
        )
    )

    if cover_every_branch:
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        document = _object_mapping(
            cast("object", json.loads(result.stdout.decode("utf-8")))
        )
        assert document["project_branch_percent"] == _FULL_PERCENT
        assert output.is_dir()
    else:
        assert result.returncode == _CLI_FAILURE
        assert result.stderr == (
            b"test gate failed: decision module src/nplg_mcp/errors.py "
            b"is below its branch floor\n"
        )
        assert not output.exists()


@pytest.mark.parametrize(
    ("relative", "defect"),
    [
        ("src/nplg_mcp/new_module.py", "line"),
        ("src/nplg_mcp/new_module.py", "arc"),
        ("scripts/new_command.py", "line"),
        ("scripts/new_command.py", "arc"),
    ],
)
def test_developer_snapshot_cannot_hide_untracked_python_coverage(
    tmp_path: Path,
    relative: str,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    _ = target.write_text("if True:\n    pass\n", encoding="utf-8")
    green_output = (tmp_path / "green-output").resolve()

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=green_output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert result.measurements.diff_line_percent == _FULL_PERCENT
    assert result.measurements.diff_branch_arc_percent == _FULL_PERCENT
    red_output = (tmp_path / "red-output").resolve()
    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=red_output,
            ),
            executor=_CoverageExecutor(coverage_defects={relative: defect}),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not red_output.exists()


def test_untracked_test_and_ignored_generated_inputs_are_classified(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    _ = (repository / ".gitignore").write_text(
        ".coverage*\n.pytest_cache/\nignored.pipe\n",
        encoding="utf-8",
    )
    _ = (repository / "tests" / "test_new.py").write_text(
        "def test_new() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    _ = (repository / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    ignored = repository / "ignored.pipe"
    ignored.touch()
    output = (tmp_path / "external-output").resolve()

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert ignored.is_file()
    assert (output / "snapshot" / "tests" / "test_new.py").is_file()
    assert (output / "snapshot" / "uv.lock").is_file()
    assert not (output / "snapshot" / "ignored.pipe").exists()


@pytest.mark.parametrize("operation", ["rename", "delete"])
def test_snapshot_handles_tracked_rename_and_delete_without_evasion(
    tmp_path: Path,
    operation: str,
) -> None:
    relative = "src/nplg_mcp/legacy_extra.py"
    repository, git_cache = _initialize_gate_repository(
        tmp_path,
        extra_files={relative: b"if True:\n    pass\n"},
    )
    original = repository / relative
    if operation == "rename":
        _ = original.rename(repository / "src" / "nplg_mcp" / "renamed_extra.py")
    else:
        original.unlink()
    output = (tmp_path / "external-output").resolve()

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert result.measurements.diff_line_percent == _FULL_PERCENT
    assert not (output / "snapshot" / relative).exists()


@pytest.mark.parametrize("defect", ["binary", "symlink", "special"])
def test_snapshot_rejects_binary_or_nonregular_untracked_python(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    target = repository / "src" / "nplg_mcp" / "untrusted.py"
    if defect == "binary":
        _ = target.write_bytes(b"\x00\x01\x02")
    elif defect == "symlink":
        target.symlink_to(repository / "src" / "nplg_mcp" / "errors.py")
    else:
        target.unlink(missing_ok=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(target)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def test_snapshot_rejects_source_bytes_changed_during_execution(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    source = repository / "src" / "nplg_mcp" / "errors.py"
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(mutate_source=source),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )

    assert source.read_text(encoding="utf-8") == "changed during gate\n"
    assert not output.exists()


def test_snapshot_includes_ignored_regular_owned_inputs(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    ignored = repository / "tests" / "ignored_test.py"
    _ = repository.joinpath(".gitignore").write_text(
        "tests/ignored_test.py\n.pytest_cache/\n",
        encoding="utf-8",
    )
    _ = ignored.write_text(
        "def test_ignored_input_is_not_omitted() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    cache_file = repository / "tests" / ".pytest_cache" / "ignored"
    cache_file.parent.mkdir()
    _ = cache_file.write_text("generated cache\n", encoding="utf-8")
    output = (tmp_path / "external-output").resolve()

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert (output / "snapshot" / "tests" / "ignored_test.py").read_bytes() == (
        ignored.read_bytes()
    )
    assert not (output / "snapshot" / "tests" / ".pytest_cache").exists()


def test_reviewed_snapshot_excludes_only_generated_egg_info_directories(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    _ = (repository / ".gitignore").write_text("*.egg-info/\n", encoding="utf-8")
    generated = repository / "src" / "nplg_dspace_mcp.egg-info"
    generated.mkdir(parents=True)
    _ = generated.joinpath("PKG-INFO").write_text("generated\n", encoding="utf-8")
    ordinary_file = repository / "src" / "ordinary.egg-info"
    _ = ordinary_file.write_text("ordinary file\n", encoding="utf-8")
    ordinary_directory = repository / "src" / "ordinary.egg-info.backup"
    ordinary_directory.mkdir()
    _ = ordinary_directory.joinpath("module.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )
    output = (tmp_path / "external-output").resolve()

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert not (output / "snapshot" / "src" / "nplg_dspace_mcp.egg-info").exists()
    assert (output / "snapshot" / "src" / "ordinary.egg-info").is_file()
    assert (
        output / "snapshot" / "src" / "ordinary.egg-info.backup/module.py"
    ).is_file()


@pytest.mark.parametrize("tracked", [False, True], ids=("unignored", "tracked"))
def test_snapshot_excludes_generated_egg_info_from_every_inventory_source(
    tmp_path: Path,
    *,
    tracked: bool,
) -> None:
    relative = "src/nplg_dspace_mcp.egg-info/PKG-INFO"
    repository, git_cache = _initialize_gate_repository(
        tmp_path,
        extra_files={relative: b"generated\n"} if tracked else None,
    )
    generated = repository / "src" / "nplg_dspace_mcp.egg-info"
    if not tracked:
        generated.mkdir()
        _ = generated.joinpath("PKG-INFO").write_text("generated\n", encoding="utf-8")
    ordinary_file = repository / "src" / "ordinary.egg-info"
    _ = ordinary_file.write_text("ordinary file\n", encoding="utf-8")
    ordinary_directory = repository / "src" / "ordinary.egg-info-backup"
    ordinary_directory.mkdir()
    _ = ordinary_directory.joinpath("module.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )
    output = (tmp_path / "external-output").resolve()

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert not (output / "snapshot" / relative).exists()
    assert (output / "snapshot" / "src" / "ordinary.egg-info").is_file()
    assert (
        output / "snapshot" / "src" / "ordinary.egg-info-backup/module.py"
    ).is_file()


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("leaf-stat-race", "generated repository input changed during scan"),
        ("symlink", "generated repository input is not a single-link regular file"),
    ],
)
def test_generated_egg_info_inventory_fails_closed_on_leaf_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    message: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    generated = repository / "src" / "nplg_dspace_mcp.egg-info"
    generated.mkdir()
    leaf = generated / "PKG-INFO"
    _ = leaf.write_text("generated\n", encoding="utf-8")
    if fault == "leaf-stat-race":
        original_stat = os.stat

        def fail_leaf_stat(
            path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *,
            dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> os.stat_result:
            if (
                path == leaf.name
                and dir_fd is not None
                and Path(f"/proc/self/fd/{dir_fd}").resolve(strict=True) == generated
            ):
                raise OSError(message)
            return original_stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )

        monkeypatch.setattr("scripts.run_test_gate.os.stat", fail_leaf_stat)
    else:
        leaf.unlink()
        leaf.symlink_to(repository / "src" / "nplg_mcp" / "errors.py")

    with pytest.raises(GateError, match=message):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=(tmp_path / "external-output").resolve(),
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_release_gate_rejects_a_comparison_ref_that_resolves_to_the_candidate(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path, dirty=False)
    head = _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()

    with pytest.raises(GateError, match="comparison ref resolves to the candidate"):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="HEAD",
                output_dir=(tmp_path / "external-output").resolve(),
                require_clean=True,
                candidate=head,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_release_gate_rejects_a_descendant_comparison_ref(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path, dirty=False)
    head = _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()
    branch = (
        _git_command(repository, git_cache, "branch", "--show-current").decode().strip()
    )
    _ = _git_command(repository, git_cache, "branch", "descendant")
    _ = _git_command(repository, git_cache, "checkout", "-q", "descendant")
    descendant = repository / "docs" / "descendant.md"
    descendant.parent.mkdir()
    _ = descendant.write_text("descendant\n", encoding="utf-8")
    _ = _git_command(repository, git_cache, "add", "docs/descendant.md")
    _ = _git_command(
        repository,
        git_cache,
        "-c",
        "user.name=NPLG Test Gate",
        "-c",
        "user.email=nplg-test-gate.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "descendant",
    )
    _ = _git_command(repository, git_cache, "checkout", "-q", branch)

    with pytest.raises(GateError, match="comparison ref resolves to the candidate"):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/descendant",
                output_dir=(tmp_path / "external-output").resolve(),
                require_clean=True,
                candidate=head,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_release_gate_ignores_replace_refs_with_exact_closed_git_environments(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path, dirty=False)
    candidate = (
        _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()
    )
    comparison = (
        _git_command(repository, git_cache, "rev-parse", "refs/heads/base")
        .decode()
        .strip()
    )
    _ = _git_command(repository, git_cache, "replace", candidate, comparison)
    git = _EnvironmentGit()

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=(tmp_path / "external-output").resolve(),
            require_clean=True,
            candidate=candidate,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=git,
    )

    assert result.measurements.project_branch_percent == _FULL_PERCENT
    assert git.environments
    for environment in git.environments:
        assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
        assert environment["GIT_OPTIONAL_LOCKS"] == "0"
        assert frozenset(environment) in {
            frozenset({"GIT_NO_REPLACE_OBJECTS", "GIT_OPTIONAL_LOCKS"}),
            frozenset(
                {
                    "GIT_AUTHOR_DATE",
                    "GIT_COMMITTER_DATE",
                    "GIT_NO_REPLACE_OBJECTS",
                    "GIT_OPTIONAL_LOCKS",
                }
            ),
        }


@pytest.mark.parametrize(
    "defect",
    ["snapshot", "configuration", "external-head", "report"],
)
def test_gate_rejects_post_command_external_evidence_mutation(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_ExternalMutationExecutor(defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    ["installed-report", "installed-configuration", "unexpected-output"],
)
def test_gate_rejects_unbound_or_unexpected_external_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    output = (tmp_path / "external-output").resolve()
    if defect == "unexpected-output":
        repository, git_cache = _initialize_gate_repository(tmp_path)
        request = GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        )
    else:
        repository, git_cache, installed, manifest, head = _initialize_installed_gate(
            tmp_path
        )
        monkeypatch.setattr(sys, "path", [installed.parent.as_posix()])
        request = _installed_gate_request(
            repository,
            output,
            installed,
            manifest,
            head,
        )

    with pytest.raises(GateError):
        _ = run_test_gate(
            request,
            executor=_ExternalMutationExecutor(defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )

    assert not output.exists()


@pytest.mark.parametrize("defect", ["missing-base", "shallow"])
def test_comparison_base_must_exist_in_a_nonshallow_repository(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    compare = "refs/heads/missing" if defect == "missing-base" else "refs/heads/base"
    if defect == "shallow":
        head = _git_command(repository, git_cache, "rev-parse", "HEAD").strip()
        _ = (repository / ".git" / "shallow").write_bytes(head + b"\n")
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch=compare,
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize("defect", ["external-marker", "skipped"])
def test_collection_and_junit_cannot_silently_omit_tests(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    executor = (
        _CoverageExecutor(external_marker="live")
        if defect == "external-marker"
        else _CoverageExecutor(junit_skipped=True)
    )

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=executor,
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def test_dynamic_deselection_fails_even_when_junit_count_matches(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=(tmp_path / "external-output").resolve(),
            ),
            executor=_CoverageExecutor(dynamic_deselection=True),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


@pytest.mark.parametrize(
    "kind",
    ["relative", "preexisting", "inside-worktree", "symlink"],
)
def test_explicit_output_must_be_new_canonical_and_external(
    tmp_path: Path,
    kind: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    if kind == "relative":
        output = Path("relative-output")
    elif kind == "inside-worktree":
        output = repository / "inside-output"
    else:
        output = (tmp_path / "external-output").resolve()
        if kind == "preexisting":
            output.mkdir()
        else:
            target = tmp_path / "target"
            target.mkdir()
            output.symlink_to(target, target_is_directory=True)

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


@pytest.mark.parametrize(
    "relative",
    [
        "pytest.py",
        "coverage.py",
        "diff_cover.py",
        "pytest/__init__.py",
        "coverage/__init__.py",
        "diff_cover/__init__.py",
        "src/pytest.py",
        "src/coverage/__init__.py",
        "sitecustomize.py",
        "src/usercustomize.py",
    ],
)
def test_candidate_cannot_shadow_trusted_test_tools(
    tmp_path: Path,
    relative: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(
        tmp_path,
        extra_files={relative: b"raise RuntimeError('candidate tool shadow')\n"},
    )

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=(tmp_path / "external-output").resolve(),
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_every_python_test_child_uses_an_isolated_trusted_driver(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    executor = _CoverageExecutor()

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=(tmp_path / "external-output").resolve(),
        ),
        executor=executor,
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    python_children = tuple(
        request
        for request in executor.requests
        if request.argv[0] == sys.executable
        and ("--collect-only" in request.argv or "coverage" in request.argv)
    )
    assert python_children
    assert all(request.argv[1:4] == ("-I", "-B", "-c") for request in python_children)
    assert all(
        "PYTHONPATH" not in dict(request.environment) for request in python_children
    )


def test_isolated_driver_rechecks_trusted_tool_origins_after_pytest(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    executor = _CoverageExecutor()
    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=(tmp_path / "synthetic-output").resolve(),
        ),
        executor=executor,
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )
    template = next(
        request
        for request in executor.requests
        if len(request.argv) > _TRUSTED_DRIVER_MODE_INDEX
        and request.argv[_TRUSTED_DRIVER_MODE_INDEX] == "coverage-pytest"
    )
    candidate = (tmp_path / "origin-candidate").resolve()
    candidate.mkdir()
    test_file = candidate / "test_origin_tamper.py"
    _ = test_file.write_text(
        """
def test_tamper_loaded_tool_origins() -> None:
    import coverage
    import diff_cover
    import pytest

    coverage.__file__ = __file__
    diff_cover.__file__ = __file__
    pytest.__file__ = __file__
""".lstrip(),
        encoding="utf-8",
    )
    rcfile = candidate / "coverage.rc"
    _ = rcfile.write_text(
        "".join(
            (
                "[run]\nbranch = true\nsource = .\n",
                f"data_file = {(candidate / '.coverage').as_posix()}\n",
            )
        ),
        encoding="utf-8",
    )
    home = candidate / "home"
    temporary = candidate / "tmp"
    home.mkdir()
    temporary.mkdir()
    candidate_roots: list[str] = [candidate.as_posix()]
    command = (
        *template.argv[: _TRUSTED_DRIVER_MODE_INDEX + 1],
        json.dumps(candidate_roots, separators=(",", ":")),
        template.argv[_TRUSTED_DRIVER_PROOF_INDEX],
        json.dumps(None),
        rcfile.as_posix(),
        (candidate / "audit.json").as_posix(),
        "run",
        "-q",
        "--import-mode=importlib",
        test_file.as_posix(),
    )

    result = SystemExecutor()(
        CommandRequest(
            argv=command,
            cwd=candidate,
            environment=(
                ("COVERAGE_FILE", (candidate / ".coverage").as_posix()),
                ("HOME", home.as_posix()),
                ("LANG", "C.UTF-8"),
                ("PATH", "/usr/bin:/bin"),
                ("PYTHONNOUSERSITE", "1"),
                ("TMPDIR", temporary.as_posix()),
            ),
            timeout_seconds=30.0,
        )
    )

    assert result.returncode == _TRUSTED_DRIVER_REJECTION


def test_installed_driver_prebinds_the_exact_package_before_pytest(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    executor = _CoverageExecutor()
    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=(tmp_path / "synthetic-output").resolve(),
        ),
        executor=executor,
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )
    template = next(
        request
        for request in executor.requests
        if len(request.argv) > _TRUSTED_DRIVER_MODE_INDEX
        and request.argv[_TRUSTED_DRIVER_MODE_INDEX] == "coverage-pytest"
    )
    candidate = (tmp_path / "installed-candidate").resolve()
    package = candidate / "site-packages" / "nplg_mcp"
    package.mkdir(parents=True)
    _ = package.joinpath("__init__.py").write_bytes(b"VALUE = 7\n")
    test_file = candidate / "test_installed_origin.py"
    _ = test_file.write_text(
        "\n".join(
            (
                "from pathlib import Path",
                "import nplg_mcp",
                "",
                "def test_installed_origin() -> None:",
                "    assert Path(nplg_mcp.__file__).resolve().parent == ",
                f"        Path({package.as_posix()!r})",
                "",
            )
        ).replace("== \n        ", "== "),
        encoding="utf-8",
    )
    rcfile = candidate / "coverage.rc"
    _ = rcfile.write_text(
        "\n".join(
            (
                "[run]",
                "branch = true",
                f"source = {package.as_posix()}",
                f"data_file = {(candidate / '.coverage').as_posix()}",
                "",
            )
        ),
        encoding="utf-8",
    )
    home = candidate / "home"
    temporary = candidate / "tmp"
    home.mkdir()
    temporary.mkdir()
    roots: list[str] = [package.parent.as_posix(), candidate.as_posix()]
    command = (
        *template.argv[:_TRUSTED_DRIVER_MODE_INDEX],
        "coverage-pytest-installed",
        json.dumps(roots, separators=(",", ":")),
        template.argv[_TRUSTED_DRIVER_PROOF_INDEX],
        json.dumps(package.as_posix()),
        rcfile.as_posix(),
        (candidate / "audit.json").as_posix(),
        "run",
        "-q",
        "--import-mode=importlib",
        test_file.as_posix(),
    )

    result = SystemExecutor()(
        CommandRequest(
            argv=command,
            cwd=candidate,
            environment=(
                ("COVERAGE_FILE", (candidate / ".coverage").as_posix()),
                ("HOME", home.as_posix()),
                ("LANG", "C.UTF-8"),
                ("PATH", "/usr/bin:/bin"),
                ("PYTHONNOUSERSITE", "1"),
                ("TMPDIR", temporary.as_posix()),
            ),
            timeout_seconds=30.0,
        )
    )

    assert result.returncode == 0, result.stderr.decode(errors="replace")


@pytest.mark.parametrize("unsafe", ["line\n[run]\nsource=attacker", "percent%path"])
def test_output_path_cannot_inject_generated_configuration(
    tmp_path: Path,
    unsafe: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=(tmp_path / unsafe).resolve(),
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_default_output_is_private_and_removed_after_success(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert not result.coverage_xml.exists()
    assert not result.coverage_json.exists()


@pytest.mark.parametrize(
    "defect",
    [
        "relative-worktree",
        "missing-worktree",
        "aliased-worktree",
        "invalid-ref",
        "clean-without-candidate",
        "candidate-without-clean",
        "installed-without-manifest",
        "manifest-without-installed",
        "installed-developer-mode",
    ],
)
def test_gate_request_rejects_incomplete_or_noncanonical_modes(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    worktree = repository
    compare = "refs/heads/base"
    require_clean = False
    candidate: str | None = None
    installed: Path | None = None
    manifest: Path | None = None
    if defect == "relative-worktree":
        worktree = Path("repository")
    elif defect == "missing-worktree":
        worktree = (tmp_path / "missing").resolve()
    elif defect == "aliased-worktree":
        alias = tmp_path / "alias"
        alias.symlink_to(repository, target_is_directory=True)
        worktree = alias
    elif defect == "invalid-ref":
        compare = "--upload-pack=evil"
    elif defect == "clean-without-candidate":
        require_clean = True
    elif defect == "candidate-without-clean":
        candidate = "0" * 40
    elif defect == "installed-without-manifest":
        installed = (tmp_path / "site-packages" / "nplg_mcp").resolve()
    elif defect == "manifest-without-installed":
        manifest = (tmp_path / "manifest.json").resolve()
    else:
        installed = (tmp_path / "site-packages" / "nplg_mcp").resolve()
        manifest = (tmp_path / "manifest.json").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=worktree,
                compare_branch=compare,
                output_dir=(tmp_path / "external-output").resolve(),
                require_clean=require_clean,
                candidate=candidate,
                installed_package_root=installed,
                package_manifest=manifest,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_release_mode_requires_and_preserves_exact_clean_head(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path, dirty=False)
    head = _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()
    _ = _git_command(repository, git_cache, "pack-refs", "--all")
    output = (tmp_path / "release-output").resolve()

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
            require_clean=True,
            candidate=head,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert result.measurements.project_branch_percent == _FULL_PERCENT
    for candidate in ("bad", "0" * 40):
        with pytest.raises(GateError):
            _ = run_test_gate(
                GateRequest(
                    worktree=repository,
                    compare_branch="refs/heads/base",
                    output_dir=(tmp_path / f"bad-{len(candidate)}").resolve(),
                    require_clean=True,
                    candidate=candidate,
                ),
                executor=_CoverageExecutor(),
                clock=_Clock(),
                filesystem=_Filesystem(),
                git=_RealGit(git_cache),
            )


@pytest.mark.parametrize(
    "defect",
    [
        "git-dir-nonascii",
        "git-dir-malformed",
        "git-dir-relative",
        "git-dir-missing",
        "git-dir-not-directory",
    ],
)
def test_release_mode_rejects_git_directory_payload_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path, dirty=False)
    head = _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()
    source = tmp_path / "missing-git-directory"
    if defect == "git-dir-not-directory":
        source = tmp_path / "not-a-directory"
        _ = source.write_bytes(b"regular\n")
    output = (tmp_path / "release-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
                require_clean=True,
                candidate=head,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_FaultGit(git_cache, defect, source=source),
        )
    assert not output.exists()


@pytest.mark.parametrize("database", ["refs", "objects"])
def test_release_mode_rejects_unsafe_real_git_database_entry(
    tmp_path: Path,
    database: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path, dirty=False)
    head = _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()
    unsafe = repository / ".git" / database / "unsafe-entry"
    if database == "refs":
        os.mkfifo(unsafe)
    else:
        unsafe.symlink_to(tmp_path / "outside-object")
    output = (tmp_path / "release-output").resolve()

    with pytest.raises(GateError, match="inventory is unavailable or unstable"):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
                require_clean=True,
                candidate=head,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    [
        "detached-head",
        "index-replacement",
        "ref-replacement",
        "object-addition",
    ],
)
def test_release_mode_preserves_raw_git_state(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path, dirty=False)
    head = _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=(tmp_path / "release-output").resolve(),
                require_clean=True,
                candidate=head,
            ),
            executor=_RawGitMutatingExecutor(repository, git_cache, defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_release_candidate_tree_must_equal_the_materialized_input_tree(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(
        tmp_path,
        dirty=False,
        extra_files={
            ".gitignore": b"tests/ignored_release.py\n",
            "tests/ignored_release.py": (
                b"def test_ignored_release() -> None:\n    assert True\n"
            ),
        },
    )
    head = _git_command(repository, git_cache, "rev-parse", "HEAD").decode().strip()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=(tmp_path / "release-output").resolve(),
                require_clean=True,
                candidate=head,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_installed_wheel_mode_is_wired_into_the_external_coverage_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, git_cache, installed, manifest, head = _initialize_installed_gate(
        tmp_path
    )
    source = repository / "src" / "nplg_mcp"
    output = (tmp_path / "wheel-output").resolve()
    monkeypatch.setattr(
        sys,
        "path",
        [
            os.path.relpath(tmp_path, Path.cwd()),
            "",
            installed.parent.as_posix(),
        ],
    )

    result = run_test_gate(
        _installed_gate_request(repository, output, installed, manifest, head),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert result.measurements.project_branch_percent == _FULL_PERCENT
    coverage_configuration = (output / "coverage.rc").read_bytes()
    assert b"[paths]\n" in coverage_configuration
    assert source.as_posix().encode() not in coverage_configuration
    snapshot_package = output / "snapshot" / "src" / "nplg_mcp"
    assert snapshot_package.as_posix().encode() in coverage_configuration
    assert installed.as_posix().encode() in coverage_configuration


def test_installed_wheel_mode_executes_a_separately_recorded_installed_suite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, git_cache, installed, manifest, head = _initialize_installed_gate(
        tmp_path
    )
    output = (tmp_path / "wheel-output").resolve()
    monkeypatch.setattr(sys, "path", [installed.parent.as_posix()])
    executor = _CoverageExecutor()

    _ = run_test_gate(
        _installed_gate_request(repository, output, installed, manifest, head),
        executor=executor,
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    installed_runs = tuple(
        request
        for request in executor.requests
        if (
            "coverage" in request.argv
            or "coverage-installed" in request.argv
            or "coverage-pytest" in request.argv
            or "coverage-pytest-installed" in request.argv
        )
        and "run" in request.argv
        and installed.parent.as_posix()
        in cast(
            "list[str]",
            json.loads(request.argv[_TRUSTED_DRIVER_ROOTS_INDEX]),
        )
    )
    assert len(installed_runs) == 1
    roots = cast(
        "list[str]",
        json.loads(installed_runs[0].argv[_TRUSTED_DRIVER_ROOTS_INDEX]),
    )
    assert (output / "snapshot" / "src").as_posix() not in roots
    assert any(
        value == f"--junitxml={(output / 'installed-pytest-junit.xml').as_posix()}"
        for value in installed_runs[0].argv
    )
    assert (output / "installed-pytest-junit.xml").is_file()


@pytest.mark.parametrize(
    "defect",
    ["root", "files", "relative", "absent", "record", "lines", "not-executed"],
)
def test_installed_wheel_mode_rejects_malformed_runtime_coverage_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache, installed, manifest, head = _initialize_installed_gate(
        tmp_path
    )
    output = (tmp_path / "wheel-output").resolve()
    monkeypatch.setattr(sys, "path", [installed.parent.as_posix()])

    with pytest.raises(GateError):
        _ = run_test_gate(
            _installed_gate_request(repository, output, installed, manifest, head),
            executor=_InstalledCoverageFaultExecutor(installed, defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    ["missing", "editable", "extra", "malformed", "nul", "resolve-error"],
)
def test_installed_wheel_mode_rejects_runtime_discovery_spoofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache, installed, manifest, head = _initialize_installed_gate(
        tmp_path
    )
    entries: object
    if defect == "missing":
        entries = [tmp_path.joinpath("missing").as_posix()]
    elif defect == "editable":
        entries = [(repository / "src").as_posix()]
    elif defect == "extra":
        second = tmp_path / "other-site-packages" / "nplg_mcp"
        _ = shutil.copytree(installed, second)
        entries = [installed.parent.as_posix(), second.parent.as_posix()]
    elif defect == "malformed":
        entries = [7]
    elif defect == "nul":
        entries = ["bad\0path"]
    else:
        bad_runtime = tmp_path / "bad-runtime"
        bad_runtime.mkdir()
        entries = [bad_runtime.as_posix()]
        real_resolve = Path.resolve

        def failing_resolve(path: Path, *, strict: bool = False) -> Path:
            if path == bad_runtime:
                message = "synthetic runtime discovery failure"
                raise PermissionError(message)
            return real_resolve(path, strict=strict)

        monkeypatch.setattr(Path, "resolve", failing_resolve)
    monkeypatch.setattr(sys, "path", cast("list[str]", entries))
    output = (tmp_path / "wheel-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            _installed_gate_request(repository, output, installed, manifest, head),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    ["relative", "missing", "symlink", "hardlink", "directory"],
)
def test_installed_wheel_mode_rejects_manifest_path_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache, installed, manifest, head = _initialize_installed_gate(
        tmp_path
    )
    selected = manifest
    if defect == "relative":
        selected = Path("package-manifest.json")
    elif defect == "missing":
        selected = (tmp_path / "missing.json").resolve()
    elif defect == "symlink":
        selected = tmp_path / "manifest-link.json"
        selected.symlink_to(manifest)
    elif defect == "hardlink":
        selected = tmp_path / "manifest-hardlink.json"
        os.link(manifest, selected)
    elif defect == "directory":
        selected = tmp_path / "manifest-directory.json"
        selected.mkdir()
    monkeypatch.setattr(sys, "path", [installed.parent.as_posix()])
    output = (tmp_path / "wheel-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            _installed_gate_request(repository, output, installed, selected, head),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize("defect", ["read-error", "non-bytes", "short", "changed"])
def test_installed_wheel_mode_rejects_unstable_manifest_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache, installed, manifest, head = _initialize_installed_gate(
        tmp_path
    )
    monkeypatch.setattr(sys, "path", [installed.parent.as_posix()])
    output = (tmp_path / "wheel-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            _installed_gate_request(repository, output, installed, manifest, head),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_FaultFilesystem(defect),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize("subject", ["manifest", "installed", "discovery"])
def test_installed_wheel_mode_rejects_proof_drift_during_testing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    subject: str,
) -> None:
    repository, git_cache, installed, manifest, head = _initialize_installed_gate(
        tmp_path
    )
    if subject == "discovery":
        discoveries = iter(((installed,), ()))
        monkeypatch.setattr(
            "scripts.run_test_gate._discover_runtime_package_roots",
            lambda: next(discoveries),
        )
        executor: _CoverageExecutor | _InstalledInputMutatingExecutor = (
            _CoverageExecutor()
        )
    else:
        monkeypatch.setattr(sys, "path", [installed.parent.as_posix()])
        target = manifest if subject == "manifest" else installed / "errors.py"
        executor = _InstalledInputMutatingExecutor(target)
    output = (tmp_path / "wheel-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            _installed_gate_request(repository, output, installed, manifest, head),
            executor=executor,
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()

    _ = (repository / "tests" / "dirty.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=(tmp_path / "dirty-release").resolve(),
                require_clean=True,
                candidate=head,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_output_parent_must_not_be_a_symlink_alias(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    alias = tmp_path / "parent-alias"
    alias.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=alias / "output",
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


@pytest.mark.parametrize(
    "defect",
    [
        "git-result",
        "head-nonascii",
        "head-malformed",
        "worktrees-malformed",
        "tracked-truncated",
        "tracked-malformed",
        "tracked-unsupported",
        "tracked-duplicate",
        "tracked-nonascii",
        "tracked-canonical",
        "untracked-truncated",
        "untracked-duplicate",
        "untracked-outside",
        "inventory-overlap",
        "name-truncated",
        "name-duplicate",
        "hunk-binary",
        "hunk-malformed",
        "hunk-zero-start",
    ],
)
def test_gate_rejects_malformed_git_boundary_evidence(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_FaultGit(git_cache, defect),
        )
    assert not output.exists()


def test_gate_accepts_binary_marker_text_inside_changed_python_source(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_FaultGit(git_cache, "hunk-marker-text"),
    )

    assert result.measurements.diff_line_percent == _FULL_PERCENT


@pytest.mark.parametrize("defect", ["name-nonpython", "hunk-zero-count"])
def test_gate_accepts_irrelevant_paths_and_zero_length_hunks(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_FaultGit(git_cache, defect),
    )

    assert result.measurements.diff_line_percent == _FULL_PERCENT


def test_gate_rejects_source_drift_during_snapshot_materialization(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    source = repository / "src" / "nplg_mcp" / "errors.py"
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_FaultGit(git_cache, "source-drift-after-clone", source=source),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    [
        "collection-type",
        "collection-empty",
        "collection-nonascii",
        "collection-outside",
        "collection-duplicate",
        "empty-code-with-nodes",
        "marker-outside",
        "marker-overlap",
        "command-argv",
        "command-return-type",
        "command-negative",
        "command-code",
        "command-stdout-type",
        "command-stderr-type",
        "command-stdout-bound",
        "command-stderr-bound",
    ],
)
def test_gate_rejects_command_and_collection_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_FaultExecutor(defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "values",
    [
        (float("nan"), 0.0),
        (0.0, float("nan")),
        (1.0, 0.0),
    ],
)
def test_gate_rejects_invalid_command_clock_evidence(
    tmp_path: Path,
    values: tuple[float, float],
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_SequenceClock(values),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    [
        "junit-missing",
        "junit-empty",
        "junit-malformed",
        "junit-root",
        "junit-count",
        "junit-failure",
        "junit-summary",
        "junit-root-count",
        "junit-hardlink",
    ],
)
def test_gate_rejects_junit_faults(tmp_path: Path, defect: str) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_FaultExecutor(defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize("defect", ["read-error", "non-bytes", "short", "changed"])
def test_gate_rejects_unstable_external_report_reads(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_FaultFilesystem(defect),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def test_gate_rejects_missing_output_parent(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = tmp_path / "missing-parent" / "output"

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


def test_snapshot_scan_skips_generated_directories(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    generated = repository / "tests" / "__pycache__"
    generated.mkdir()
    os.mkfifo(generated / "ignored.pipe")
    output = (tmp_path / "external-output").resolve()

    result = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=output,
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert result.measurements.project_branch_percent == _FULL_PERCENT


def test_snapshot_enforces_total_and_scan_entry_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    for name, constant in (
        ("total", "scripts.run_test_gate._MAX_SNAPSHOT_TOTAL_BYTES"),
        ("entries", "scripts.run_test_gate._MAX_SNAPSHOT_ENTRIES"),
    ):
        monkeypatch.setattr(constant, 0)
        with pytest.raises(GateError):
            _ = run_test_gate(
                GateRequest(
                    worktree=repository,
                    compare_branch="refs/heads/base",
                    output_dir=(tmp_path / f"output-{name}").resolve(),
                ),
                executor=_CoverageExecutor(),
                clock=_Clock(),
                filesystem=_Filesystem(),
                git=_RealGit(git_cache),
            )
        monkeypatch.undo()


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b'"not-an-object"',
        b'{"version":9223372036854775808}',
        b'{"version":1,"gates":[],"padding":"' + (b"x" * (64 * 1024)) + b'"}',
    ],
    ids=["empty", "non-object", "integer-overflow", "oversize"],
)
def test_policy_json_boundary_rejects_empty_wrong_overflow_and_oversize(
    tmp_path: Path,
    payload: bytes,
) -> None:
    with pytest.raises(GateError):
        _ = parse_coverage_policy(payload, root=tmp_path)


@pytest.mark.parametrize(
    "defect",
    ["measured-order", "duplicate-module", "absent-module", "symlink-module"],
)
def test_coverage_policy_rejects_closed_inventory_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    _materialize_policy_modules(tmp_path)
    document = _policy_document()
    if defect == "measured-order":
        document["measured_roots"] = ["scripts", "src/nplg_mcp"]
    elif defect == "duplicate-module":
        modules = list(_policy().decision_modules)
        document["decision_modules"] = [*modules, modules[0]]
    elif defect == "absent-module":
        (tmp_path / _policy().decision_modules[0]).unlink()
    else:
        target = tmp_path / _policy().decision_modules[0]
        target.unlink()
        outside = tmp_path / "outside.py"
        _ = outside.write_text("pass\n", encoding="utf-8")
        target.symlink_to(outside)

    with pytest.raises(GateError):
        _ = parse_coverage_policy(_json_payload(document), root=tmp_path)


@pytest.mark.parametrize("filename", ["", "x" * 4097])
def test_coverage_json_rejects_unbounded_measured_names(
    tmp_path: Path,
    filename: str,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    document = _coverage_json_document()
    files = _object_mapping(document["files"])
    files[filename] = files.pop("src/nplg_mcp/errors.py")

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_json_payload(document),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


@pytest.mark.parametrize("defect", ["absent", "symlink"])
def test_coverage_json_subject_must_be_a_present_regular_snapshot_file(
    tmp_path: Path,
    defect: str,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    subject = "src/nplg_mcp/absent.py"
    if defect == "symlink":
        subject = "src/nplg_mcp/alias.py"
        (tmp_path / subject).symlink_to(reported)
    document = _coverage_json_document()
    files = _object_mapping(document["files"])
    files[subject] = files.pop("src/nplg_mcp/errors.py")

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_json_payload(document),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_coverage_xml_and_json_enforce_aggregate_counter_equality(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    xml = _coverage_xml(
        tmp_path,
        _XmlFixture(root_branch_rate="0.5", covered=1, valid=2),
    )
    document = _coverage_json_document()
    totals = _object_mapping(document["totals"])
    totals["covered_branches"] = 1
    totals["missing_branches"] = 1
    totals["percent_covered"] = 50

    for xml_payload, json_payload in (
        (xml, _coverage_json()),
        (_coverage_xml(tmp_path), _json_payload(document)),
    ):
        with pytest.raises(GateError):
            _ = parse_coverage_reports(
                xml_payload=xml_payload,
                json_payload=json_payload,
                policy=_report_policy(),
                snapshot_root=tmp_path,
                changed_lines={},
            )


def test_coverage_branch_percentage_fields_accept_only_exact_values(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    document, record = _fresh_coverage_json_file()
    _object_mapping(record["summary"])["percent_branches_covered"] = 100
    _object_mapping(document["totals"])["percent_branches_covered"] = 100

    result = parse_coverage_reports(
        xml_payload=_coverage_xml(tmp_path),
        json_payload=_json_payload(document),
        policy=_report_policy(),
        snapshot_root=tmp_path,
        changed_lines={},
    )

    assert result.project_branch_percent == _FULL_PERCENT

    zero_document = _coverage_json_document(
        _JsonFixture(
            executed_branches=(),
            covered=0,
            missing=0,
            total=0,
            percent=100,
        )
    )
    zero_record = _object_mapping(
        _object_mapping(zero_document["files"])["src/nplg_mcp/errors.py"]
    )
    _object_mapping(zero_record["summary"])["percent_branches_covered"] = 99
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_json_payload(zero_document),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


@pytest.mark.parametrize("defect", ["missing-root", "file-root"])
def test_coverage_snapshot_root_must_be_a_present_directory(
    tmp_path: Path,
    defect: str,
) -> None:
    root = tmp_path / "missing"
    if defect == "file-root":
        _ = root.write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=b"unused",
            json_payload=b"unused",
            policy=_report_policy(),
            snapshot_root=root,
            changed_lines={},
        )


def test_coverage_reports_enforce_project_and_decision_floors(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    half_xml = _coverage_xml(
        tmp_path,
        _XmlFixture(
            root_branch_rate="0.5",
            class_branch_rate="0.5",
            covered=1,
            valid=2,
            condition="50% (1/2)",
        ),
    )
    half_json = _coverage_json(
        _JsonFixture(
            executed_branches=((1, 2),),
            missing_branches=((1, 3),),
            covered=1,
            missing=1,
            total=2,
            percent=50,
        )
    )
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=half_xml,
            json_payload=half_json,
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )

    permissive = CoveragePolicy(
        version=1,
        project_branch_floor=0,
        diff_line_floor=95,
        diff_branch_arc_floor=95,
        decision_module_branch_floor=100,
        measured_roots=("src/nplg_mcp", "scripts"),
        decision_modules=("src/nplg_mcp/errors.py",),
    )
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=half_xml,
            json_payload=half_json,
            policy=permissive,
            snapshot_root=tmp_path,
            changed_lines={},
        )

    absent_decision = CoveragePolicy(
        version=1,
        project_branch_floor=95,
        diff_line_floor=95,
        diff_branch_arc_floor=95,
        decision_module_branch_floor=100,
        measured_roots=("src/nplg_mcp", "scripts"),
        decision_modules=("src/nplg_mcp/security.py",),
    )
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_coverage_json(),
            policy=absent_decision,
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_zero_branch_reports_reach_the_explicit_project_evidence_rejection(
    tmp_path: Path,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    fixture = _JsonFixture(
        executed_branches=(),
        covered=0,
        missing=0,
        total=0,
        percent=100,
    )

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(
                tmp_path,
                _XmlFixture(covered=0, valid=0, condition="100% (0/0)"),
            ),
            json_payload=_coverage_json(fixture),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_installed_package_root_rejects_control_characters(tmp_path: Path) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src\n" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=_package_manifest(files),
            discovered_package_roots=(installed,),
        )


def test_coverage_json_rejects_decimal_context_overflow(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    payload = _coverage_json().replace(
        b'"percent_covered":100',
        b'"percent_covered":1e999999999999999999999999999999999999',
        1,
    )

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=payload,
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_zero_branch_xml_requires_unit_rate(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")

    zero_rate = _coverage_xml(
        tmp_path,
        _XmlFixture(
            class_branch_rate="0",
            covered=0,
            valid=0,
        ),
    ).replace(b'branch="true"', b'branch="false"')
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=zero_rate,
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_coverage_xml_enforces_element_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr("scripts.run_test_gate._MAX_XML_ELEMENTS", 0)

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=_coverage_xml(tmp_path),
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_paired_reports_reject_project_counter_disagreement(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    half_xml = _coverage_xml(
        tmp_path,
        _XmlFixture(
            root_branch_rate="0.5",
            class_branch_rate="0.5",
            covered=1,
            valid=2,
            condition="50% (1/2)",
        ),
    )

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=half_xml,
            json_payload=_coverage_json(),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_paired_reports_reject_per_file_counter_swaps(tmp_path: Path) -> None:
    errors = tmp_path / "src" / "nplg_mcp" / "errors.py"
    security = tmp_path / "src" / "nplg_mcp" / "security.py"
    errors.parent.mkdir(parents=True)
    for path in (errors, security):
        _ = path.write_text("pass\n", encoding="utf-8")
    xml = (
        f'<coverage branch-rate="0.5" branches-covered="2" branches-valid="4">'
        f"<sources><source>{tmp_path.as_posix()}</source></sources>"
        '<packages><package><classes><class filename="src/nplg_mcp/errors.py" '
        'branch-rate="1"><lines><line number="1" hits="1" branch="true" '
        'condition-coverage="100% (2/2)"/></lines></class>'
        '<class filename="src/nplg_mcp/security.py" branch-rate="0"><lines>'
        '<line number="1" hits="1" branch="true" '
        'condition-coverage="0% (0/2)"/></lines></class>'
        "</classes></package></packages></coverage>"
    ).encode()
    first = _coverage_json_document(
        _JsonFixture(
            executed_branches=((1, 2),),
            missing_branches=((1, 3),),
            covered=1,
            missing=1,
            total=2,
            percent=50,
        )
    )
    second = _coverage_json_document(
        _JsonFixture(
            filename="src/nplg_mcp/security.py",
            executed_branches=((1, 2),),
            missing_branches=((1, 3),),
            covered=1,
            missing=1,
            total=2,
            percent=50,
        )
    )
    _object_mapping(first["files"]).update(_object_mapping(second["files"]))
    first["totals"] = {
        "percent_covered": 50,
        "num_branches": 4,
        "covered_branches": 2,
        "missing_branches": 2,
    }

    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=xml,
            json_payload=_json_payload(first),
            policy=_report_policy(),
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_zero_branch_reports_reject_absent_project_evidence(tmp_path: Path) -> None:
    reported = tmp_path / "src" / "nplg_mcp" / "errors.py"
    reported.parent.mkdir(parents=True)
    _ = reported.write_text("pass\n", encoding="utf-8")
    fixture = _JsonFixture(
        executed_branches=(),
        covered=0,
        missing=0,
        total=0,
        percent=100,
    )
    policy = CoveragePolicy(
        version=1,
        project_branch_floor=95,
        diff_line_floor=95,
        diff_branch_arc_floor=95,
        decision_module_branch_floor=100,
        measured_roots=("src/nplg_mcp", "scripts"),
        decision_modules=(),
    )

    zero_xml = _coverage_xml(
        tmp_path,
        _XmlFixture(covered=0, valid=0),
    ).replace(b'branch="true"', b'branch="false"')
    with pytest.raises(GateError):
        _ = parse_coverage_reports(
            xml_payload=zero_xml,
            json_payload=_coverage_json(fixture),
            policy=policy,
            snapshot_root=tmp_path,
            changed_lines={},
        )


def test_installed_manifest_rejects_empty_package_path(tmp_path: Path) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    document = _package_manifest_document(files)
    _first_manifest_record(document)["path"] = ""

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=_json_payload(document),
            discovered_package_roots=(installed,),
        )


def test_installed_inventory_rejects_undeclared_nonpython_data(tmp_path: Path) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, {**files, "unreviewed.bin": b"x"})
    _write_package(installed, files)

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=_package_manifest(files),
            discovered_package_roots=(installed,),
        )


@pytest.mark.parametrize("defect", ["open", "truncate", "change", "traversal"])
def test_installed_inventory_rejects_file_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    files = {"__init__.py": b"VALUE = 7\n"}
    source = tmp_path / "src" / "nplg_mcp"
    installed = tmp_path / "site-packages" / "nplg_mcp"
    _write_package(source, files)
    _write_package(installed, files)
    target = source / "__init__.py"
    _install_file_race(monkeypatch, target, defect)

    with pytest.raises(GateError):
        _ = verify_installed_package(
            installed_package_root=installed,
            source_package_root=source,
            manifest_payload=_package_manifest(files),
            discovered_package_roots=(installed,),
        )


def _install_file_race(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    defect: str,
) -> None:
    if defect == "open":
        original_open = os.open

        def fault_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if (
                path == target.name
                and dir_fd is not None
                and Path(f"/proc/self/fd/{dir_fd}").resolve(strict=True)
                == target.parent
            ):
                message = "synthetic open race"
                raise OSError(message)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr("scripts.run_test_gate.os.open", fault_open)
    elif defect in {"truncate", "change"}:
        original_read = os.read
        used = False

        def fault_read(descriptor: int, count: int) -> bytes:
            nonlocal used
            descriptor_path = Path(f"/proc/self/fd/{descriptor}").readlink()
            if descriptor_path == target and not used:
                used = True
                if defect == "truncate":
                    return b""
                payload = original_read(descriptor, count)
                _ = target.write_bytes(target.read_bytes() + b"x")
                return payload
            return original_read(descriptor, count)

        monkeypatch.setattr("scripts.run_test_gate.os.read", fault_read)
    else:
        original_stat = os.stat
        used = False

        def fault_stat(
            path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *,
            dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> os.stat_result:
            nonlocal used
            if (
                path == target.name
                and dir_fd is not None
                and Path(f"/proc/self/fd/{dir_fd}").resolve(strict=True)
                == target.parent
                and not used
            ):
                used = True
                message = "synthetic traversal race"
                raise OSError(message)
            return original_stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )

        monkeypatch.setattr("scripts.run_test_gate.os.stat", fault_stat)


@pytest.mark.parametrize(
    "defect",
    [
        "clone-missing",
        "clone-alias",
        "snapshot-preexisting",
        "private-preexisting",
    ],
)
def test_gate_rejects_external_materialization_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_FaultGit(git_cache, defect),
        )
    assert not output.exists()


def test_snapshot_materialization_cannot_follow_a_swapped_parent_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "tests/nested/test_extra.py"
    repository, git_cache = _initialize_gate_repository(
        tmp_path,
        extra_files={relative: b"def test_extra() -> None:\n    assert True\n"},
    )
    output = (tmp_path / "external-output").resolve()
    escape = tmp_path / "escape"
    escape.mkdir()
    target = output / "snapshot" / relative
    original_open = os.open
    swapped = False

    def swap_parent_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        raw_path = os.fspath(path)
        candidate = Path(raw_path) if isinstance(raw_path, str) else None
        descriptor_parent = (
            Path(f"/proc/self/fd/{dir_fd}").resolve()
            if dir_fd is not None and candidate == Path(target.name)
            else None
        )
        if (
            (candidate == target or descriptor_parent == target.parent)
            and flags & os.O_CREAT
            and not swapped
        ):
            swapped = True
            saved = output / "saved-nested"
            _ = target.parent.rename(saved)
            target.parent.symlink_to(escape, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("scripts.run_test_gate.os.open", swap_parent_before_open)

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )

    assert swapped
    assert not (escape / "test_extra.py").exists()


def test_owned_source_inventory_uses_bound_directory_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    original_scandir = os.scandir
    unbound_owned_scans: list[Path] = []

    def record_scandir(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> Iterator[os.DirEntry[str]]:
        if not isinstance(path, int) and not isinstance(path, bytes):
            raw_path = os.fspath(path)
            if isinstance(raw_path, str):
                candidate = Path(raw_path)
                if candidate == repository or repository in candidate.parents:
                    unbound_owned_scans.append(candidate)
        return cast("Iterator[os.DirEntry[str]]", original_scandir(path))

    monkeypatch.setattr("scripts.run_test_gate.os.scandir", record_scandir)

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=(tmp_path / "external-output").resolve(),
        ),
        executor=_CoverageExecutor(),
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(git_cache),
    )

    assert unbound_owned_scans == []


@pytest.mark.parametrize(
    "defect",
    ["symlink-parent", "missing-parent", "root-symlink", "hardlink"],
)
def test_snapshot_rejects_parent_and_file_identity_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    git_defect = "tracked-symlink-parent"
    if defect == "symlink-parent":
        vendor = repository / "vendor"
        vendor.mkdir()
        (vendor / "link").symlink_to(
            repository / "tests",
            target_is_directory=True,
        )
        exclude = repository / ".git" / "info" / "exclude"
        _ = exclude.write_text("vendor/\n", encoding="utf-8")
    elif defect == "missing-parent":
        git_defect = "tracked-missing-parent"
        missing = repository / "vendor" / "missing" / "file.py"
        original_lexists = os.path.lexists

        def fault_lexists(path: str | os.PathLike[str]) -> bool:
            return Path(path) == missing or original_lexists(path)

        monkeypatch.setattr("scripts.run_test_gate.os.path.lexists", fault_lexists)
    elif defect == "root-symlink":
        git_defect = ""
        (repository / ".env.example").symlink_to(repository / "tests" / "test_ok.py")
    else:
        git_defect = ""
        os.link(repository / "tests" / "test_ok.py", repository / ".env.example")
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=(
                _RealGit(git_cache)
                if not git_defect
                else _FaultGit(git_cache, git_defect)
            ),
        )
    assert not output.exists()


@pytest.mark.parametrize("defect", ["truncate", "change"])
def test_snapshot_rejects_source_file_read_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    target = repository / "src" / "nplg_mcp" / "errors.py"
    _install_read_fault(monkeypatch, target, defect)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def _install_read_fault(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    defect: str,
) -> None:
    original_read = os.read
    used = False

    def fault_read(descriptor: int, count: int) -> bytes:
        nonlocal used
        descriptor_path = Path(f"/proc/self/fd/{descriptor}").readlink()
        if descriptor_path == target and not used:
            used = True
            if defect == "truncate":
                return b""
            payload = original_read(descriptor, count)
            _ = target.write_bytes(target.read_bytes() + b"x")
            return payload
        return original_read(descriptor, count)

    monkeypatch.setattr("scripts.run_test_gate.os.read", fault_read)


@pytest.mark.parametrize("defect", ["root", "entry"])
def test_snapshot_rejects_scan_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    target = repository / "tests"
    original_scandir = os.scandir

    def fault_scandir(path: int | Path) -> Iterator[os.DirEntry[str]]:
        if isinstance(path, int):
            candidate = Path(f"/proc/self/fd/{path}").resolve()
        else:
            candidate = Path(path)
        if candidate == target:
            if defect == "root":
                message = "synthetic scan failure"
                raise OSError(message)
            return cast(
                "Iterator[os.DirEntry[str]]",
                cast("object", _FaultScandirIterator()),
            )
        return cast("Iterator[os.DirEntry[str]]", original_scandir(path))

    monkeypatch.setattr("scripts.run_test_gate.os.scandir", fault_scandir)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def test_explicit_output_rejects_creation_failure(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = tmp_path / ("x" * 300)

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


@pytest.mark.parametrize("mode", ["explicit", "temporary"])
def test_output_rejects_post_creation_identity_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    requested = (
        None if mode == "temporary" else (tmp_path / "external-output").resolve()
    )
    original_lstat = Path.lstat

    def fault_lstat(path: Path) -> os.stat_result:
        is_target = (
            path.name.startswith("nplg-test-gate-")
            if mode == "temporary"
            else path == requested
        )
        if is_target and path.exists():
            message = "synthetic output identity race"
            raise OSError(message)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fault_lstat)
    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=requested,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )


@pytest.mark.parametrize("boundary", ["snapshot", "private"])
def test_gate_rejects_incomplete_external_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    original_write = os.write
    used = False

    def fault_write(descriptor: int, payload: bytes) -> int:
        nonlocal used
        descriptor_path = Path(f"/proc/self/fd/{descriptor}").readlink()
        is_target = (
            "snapshot" in descriptor_path.parts
            if boundary == "snapshot"
            else descriptor_path.name == "coverage.rc"
        )
        if is_target and not used:
            used = True
            return 0
        return original_write(descriptor, payload)

    monkeypatch.setattr("scripts.run_test_gate.os.write", fault_write)
    output = (tmp_path / "external-output").resolve()
    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert used
    assert not output.exists()


def test_gate_rejects_absent_snapshot_policy(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    (repository / "security" / "coverage-policy.json").unlink()
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def test_gate_rejects_ref_only_mutation_during_execution(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_RefMutatingExecutor(repository, git_cache),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    ["restored-deleted", "external-other-head", "external-untracked"],
)
def test_external_snapshot_binding_rejects_deleted_head_and_inventory_drift(
    tmp_path: Path,
    defect: str,
) -> None:
    extra = {"docs/deleted.md": b"deleted\n"} if defect == "restored-deleted" else None
    repository, git_cache = _initialize_gate_repository(
        tmp_path,
        extra_files=extra,
    )
    if defect == "restored-deleted":
        (repository / "docs" / "deleted.md").unlink()
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_ExternalMutationExecutor(defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def test_final_artifact_binding_rejects_late_snapshot_drift(
    tmp_path: Path,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    git = _LateExternalGit(git_cache)
    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=git,
        )
    assert git.mutated
    assert not output.exists()


def test_gate_rejects_a_real_unsafe_owned_entry_name(tmp_path: Path) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    _ = repository.joinpath("tests/unsafe\nname.py").write_bytes(b"pass\n")
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(
        GateError,
        match="reviewed repository input contains an unsafe entry name",
    ):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def test_gate_rejects_reviewed_root_stat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, git_cache = _initialize_gate_repository(
        tmp_path,
        extra_files={".env.example": b"NPLG_TEST=1\n"},
    )
    original_stat = os.stat

    def fail_reviewed_root_stat(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if (
            path == ".env.example"
            and dir_fd is not None
            and Path(f"/proc/self/fd/{dir_fd}").readlink() == repository
        ):
            message = "synthetic reviewed-root stat failure"
            raise OSError(message)
        return original_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(
        "scripts.run_test_gate.os.stat",
        fail_reviewed_root_stat,
    )
    output = (tmp_path / "external-output").resolve()
    with pytest.raises(GateError, match="reviewed root input changed during scan"):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    ["site-root", "distribution", "absent", "missing-origin", "directory"],
)
def test_gate_rejects_unbound_trusted_module_spec_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)

    def missing_site_root(_name: str) -> None:
        return None

    def no_distributions(*, name: str, path: list[str]) -> tuple[()]:
        del name, path
        return ()

    if defect == "site-root":
        monkeypatch.setattr(
            "scripts.run_test_gate.sysconfig.get_path",
            missing_site_root,
        )
    elif defect == "distribution":
        monkeypatch.setattr(
            "scripts.run_test_gate.importlib.metadata.distributions",
            no_distributions,
        )

    def find_specification(
        fullname: str,
        _path: Sequence[str] | None = None,
        _target: object | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if defect == "absent":
            return None
        if defect == "missing-origin":
            return importlib.machinery.ModuleSpec(
                fullname,
                loader=None,
                origin=tmp_path.joinpath("missing.py").as_posix(),
            )
        return importlib.machinery.ModuleSpec(
            fullname,
            loader=None,
            origin=tmp_path.as_posix(),
        )

    monkeypatch.setattr(
        "scripts.run_test_gate.importlib.machinery.PathFinder.find_spec",
        find_specification,
    )
    output = (tmp_path / "external-output").resolve()
    expected = {
        "site-root": "trusted site-packages root is unavailable",
        "distribution": "trusted test tool is unavailable",
        "absent": "trusted test tool version or import origin is invalid",
        "missing-origin": "trusted test tool import origin is unavailable",
        "directory": "trusted test tool import origin is not a regular file",
    }[defect]
    with pytest.raises(GateError, match=expected):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


def _install_public_root_open_fault(
    monkeypatch: pytest.MonkeyPatch,
    *,
    repository: Path,
) -> None:
    original_open = os.open

    def fault_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        raw = os.fspath(path)
        candidate = Path(raw) if isinstance(raw, str) else None
        if candidate == repository and dir_fd is None and flags & os.O_DIRECTORY:
            message = "synthetic root open failure"
            raise OSError(message)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("scripts.run_test_gate.os.open", fault_open)


def _install_public_identity_fault(
    monkeypatch: pytest.MonkeyPatch,
    *,
    target: Path,
) -> None:
    original_fstat = os.fstat

    def fault_fstat(descriptor: int) -> os.stat_result:
        metadata = original_fstat(descriptor)
        try:
            candidate = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
        except OSError:
            return metadata
        if candidate == target:
            fields = list(metadata)
            fields[1] += 1
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr("scripts.run_test_gate.os.fstat", fault_fstat)


def _install_public_mkdir_fault(
    monkeypatch: pytest.MonkeyPatch,
    *,
    output: Path,
) -> None:
    original_mkdir = os.mkdir

    def fault_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if (
            path == "scripts"
            and dir_fd is not None
            and Path(f"/proc/self/fd/{dir_fd}").resolve(strict=True)
            == output / "snapshot"
        ):
            message = "synthetic parent creation failure"
            raise OSError(message)
        original_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr("scripts.run_test_gate.os.mkdir", fault_mkdir)


def _install_public_scandir_fault(
    monkeypatch: pytest.MonkeyPatch,
    *,
    repository: Path,
) -> None:
    original_scandir = os.scandir

    def fault_scandir(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> Iterator[os.DirEntry[str]]:
        iterator = original_scandir(path)
        if (
            isinstance(path, int)
            and Path(f"/proc/self/fd/{path}").resolve(strict=True)
            == repository / "tests"
        ):
            return cast(
                "Iterator[os.DirEntry[str]]",
                cast("object", _ExplodingScandirIterator(iterator.close)),
            )
        return cast("Iterator[os.DirEntry[str]]", iterator)

    monkeypatch.setattr("scripts.run_test_gate.os.scandir", fault_scandir)


def _install_public_entry_identity_fault(
    monkeypatch: pytest.MonkeyPatch,
    *,
    repository: Path,
) -> None:
    original_stat = os.stat
    other = repository / "tests" / "other.py"
    _ = other.write_bytes(b"pass\n")

    def fault_entry_stat(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if (
            path == "test_ok.py"
            and dir_fd is not None
            and Path(f"/proc/self/fd/{dir_fd}").resolve(strict=True)
            == repository / "tests"
        ):
            return original_stat(
                "other.py",
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )
        return original_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr("scripts.run_test_gate.os.stat", fault_entry_stat)


def _install_public_descriptor_fault(
    monkeypatch: pytest.MonkeyPatch,
    *,
    defect: str,
    repository: Path,
    output: Path,
) -> None:
    if defect == "root-open":
        _install_public_root_open_fault(monkeypatch, repository=repository)
    elif defect in {"root-identity", "child-identity", "snapshot-file-identity"}:
        target = {
            "root-identity": repository,
            "child-identity": repository / "tests",
            "snapshot-file-identity": output / "snapshot" / "scripts/delete_render.py",
        }[defect]
        _install_public_identity_fault(monkeypatch, target=target)
    elif defect == "mkdir":
        _install_public_mkdir_fault(monkeypatch, output=output)
    elif defect == "scandir-iteration":
        _install_public_scandir_fault(monkeypatch, repository=repository)
    else:
        _install_public_entry_identity_fault(monkeypatch, repository=repository)


@pytest.mark.parametrize(
    "defect",
    [
        "root-open",
        "root-identity",
        "child-identity",
        "mkdir",
        "scandir-iteration",
        "entry-identity",
        "snapshot-file-identity",
    ],
)
def test_public_gate_rejects_descriptor_and_materialization_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()
    _install_public_descriptor_fault(
        monkeypatch,
        defect=defect,
        repository=repository,
        output=output,
    )

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_CoverageExecutor(),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    ["unexpected-directory", "hardlinked-output", "missing-authority"],
)
def test_public_gate_rejects_external_output_layout_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_ExternalMutationExecutor(defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize("defect", ["missing-report", "directory-report"])
def test_public_gate_rejects_post_capture_report_shape_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_ExternalMutationExecutor(defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "defect",
    ["audit-fields", "audit-version", "audit-call", "audit-missing-call"],
)
def test_public_gate_rejects_post_capture_pytest_audit_faults(
    tmp_path: Path,
    defect: str,
) -> None:
    repository, git_cache = _initialize_gate_repository(tmp_path)
    output = (tmp_path / "external-output").resolve()

    with pytest.raises(GateError):
        _ = run_test_gate(
            GateRequest(
                worktree=repository,
                compare_branch="refs/heads/base",
                output_dir=output,
            ),
            executor=_ExternalMutationExecutor(defect),
            clock=_Clock(),
            filesystem=_Filesystem(),
            git=_RealGit(git_cache),
        )
    assert not output.exists()


_path_fixture = cast(
    "_PathFixtureDecorator",
    cast("object", pytest.fixture),
)


@_path_fixture
def shared_seam_root() -> Iterator[Path]:
    root = Path(
        tempfile.mkdtemp(prefix="nplg-test-gate-shared-seam-", dir="/tmp")
    ).resolve(strict=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_shared_authority_exports_are_direct_aliases_with_identical_signatures() -> (
    None
):
    private_names = (
        "_RepositoryEvidence",
        "_ReleaseGitEvidence",
        "_SnapshotFile",
        "_SourceSnapshot",
        "_MaterializedSnapshot",
        "_ExternalSnapshotBinding",
        "_repository_evidence",
        "_release_git_evidence",
        "_registered_worktrees",
        "_read_bound_regular_file",
        "_stable_snapshot_file",
        "_capture_source_snapshot",
        "_create_external_output",
        "_materialize_snapshot",
        "_bind_external_snapshot",
        "reject_mutation_tool_shadows",
        "trusted_mutation_python_command",
    )

    namespace = cast(
        "Mapping[str, object]",
        cast("object", test_gate_module.__dict__),
    )
    for public_name, private_name in zip(
        _SHARED_AUTHORITY_NAMES,
        private_names,
        strict=True,
    ):
        public = namespace[public_name]
        private = namespace[private_name]
        if public_name not in {
            "reject_mutation_tool_shadows",
            "trusted_mutation_python_command",
        }:
            assert public is private
            assert inspect.signature(
                cast("_SignatureTarget", public)
            ) == inspect.signature(cast("_SignatureTarget", private))

    for forbidden in (
        "descriptor_entries",
        "filesystem_identity",
        "open_root_directory",
        "validated_source_entry",
        "write_snapshot_file",
    ):
        assert not hasattr(test_gate_module, forbidden)


def test_shared_authority_aliases_preserve_reviewed_repository_behavior(
    shared_seam_root: Path,
) -> None:
    repository, cache = _initialize_gate_repository(shared_seam_root)
    git = _RealGit(cache)

    repository_record = test_gate_module.repository_evidence(git, root=repository)
    release_record = test_gate_module.release_git_evidence(git, root=repository)
    worktrees = test_gate_module.registered_worktrees(git, root=repository)
    source_snapshot = test_gate_module.capture_source_snapshot(git, root=repository)
    test_gate_module.reject_mutation_tool_shadows(source_snapshot)
    metadata, payload = test_gate_module.read_bound_regular_file(
        repository,
        "tests/test_ok.py",
        max_bytes=4096,
    )
    stable_file = test_gate_module.stable_snapshot_file(
        repository,
        "tests/test_ok.py",
    )
    output, temporary = test_gate_module.create_external_output(
        shared_seam_root / "external-output",
        registered_worktrees=worktrees,
    )
    merge_base = (
        _git_command(
            repository,
            cache,
            "rev-parse",
            "refs/heads/base",
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    materialized = test_gate_module.materialize_snapshot(
        repository,
        source_snapshot,
        merge_base=merge_base,
        output=output,
        git=git,
    )
    binding = test_gate_module.bind_external_snapshot(
        git,
        materialized=materialized,
        source_snapshot=source_snapshot,
    )

    assert isinstance(repository_record, test_gate_module.RepositoryEvidence)
    assert isinstance(release_record, test_gate_module.ReleaseGitEvidence)
    assert worktrees == (repository,)
    assert isinstance(source_snapshot, test_gate_module.SourceSnapshot)
    assert stat.S_ISREG(metadata.st_mode)
    assert payload == b"def test_ok() -> None:\n    assert True\n"
    assert stable_file.path == "tests/test_ok.py"
    assert stable_file.payload == payload
    assert not temporary
    assert isinstance(materialized, test_gate_module.MaterializedSnapshot)
    assert isinstance(binding, test_gate_module.ExternalSnapshotBinding)
    assert binding.repository.head == materialized.candidate_commit
    assert binding.copied_inputs == source_snapshot.files


def test_legacy_trusted_driver_modes_and_proofs_remain_closed(
    shared_seam_root: Path,
) -> None:
    repository, cache = _initialize_gate_repository(shared_seam_root)
    executor = _CoverageExecutor()

    _ = run_test_gate(
        GateRequest(
            worktree=repository,
            compare_branch="refs/heads/base",
            output_dir=(shared_seam_root / "legacy-output").resolve(),
        ),
        executor=executor,
        clock=_Clock(),
        filesystem=_Filesystem(),
        git=_RealGit(cache),
    )

    trusted = tuple(
        request.argv
        for request in executor.requests
        if len(request.argv) > _TRUSTED_DRIVER_PROOF_INDEX
        and request.argv[0] == sys.executable
        and request.argv[1:4] == ("-I", "-B", "-c")
    )
    assert tuple(argv[_TRUSTED_DRIVER_MODE_INDEX] for argv in trusted) == (
        "pytest",
        "pytest",
        "pytest",
        "pytest",
        "coverage-pytest",
        "coverage",
        "coverage",
        "coverage",
        "diff-cover",
    )
    proofs = tuple(_trusted_command_proof(argv) for argv in trusted)
    assert proofs
    assert all(proof == proofs[0] for proof in proofs)
    assert tuple(
        (module, distribution, version)
        for module, distribution, version, _origin in proofs[0]
    ) == (
        ("coverage", "coverage", "7.16.0"),
        ("diff_cover", "diff-cover", "10.5.1"),
        ("pytest", "pytest", "9.1.1"),
    )


def test_trusted_mutation_command_dispatches_the_fixed_toolchain(
    shared_seam_root: Path,
) -> None:
    home = shared_seam_root / "home"
    temporary = shared_seam_root / "tmp"
    source = shared_seam_root / "code"
    home.mkdir()
    temporary.mkdir()
    source.mkdir()
    _ = source.joinpath("sample.py").write_bytes(b"VALUE = 1\n")
    _ = shared_seam_root.joinpath("setup.cfg").write_bytes(
        b"[mutmut]\nsource_paths=code\n"
    )
    command = test_gate_module.trusted_mutation_python_command(
        import_roots=(),
        arguments=("--help",),
    )

    assert command[0] == sys.executable
    assert command[1:4] == ("-I", "-B", "-c")
    assert command[_TRUSTED_DRIVER_MODE_INDEX] == "mutmut"
    assert tuple(
        (module, distribution, version)
        for module, distribution, version, _origin in _trusted_command_proof(command)
    ) == (
        ("mutmut", "mutmut", "3.7.0"),
        ("pytest", "pytest", "9.1.1"),
        ("coverage", "coverage", "7.16.0"),
    )
    result = SystemExecutor()(
        CommandRequest(
            argv=command,
            cwd=shared_seam_root,
            environment=(
                ("HOME", home.as_posix()),
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
                ("PATH", "/usr/bin:/bin"),
                ("PYTHONNOUSERSITE", "1"),
                ("TMPDIR", temporary.as_posix()),
            ),
            timeout_seconds=30.0,
        )
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"Usage:" in result.stdout
    assert result.stderr == b""


@pytest.mark.parametrize(
    "relative",
    [
        "mutmut.py",
        "mutmut/__init__.py",
        "pytest.py",
        "pytest/__init__.py",
        "coverage.py",
        "coverage/__init__.py",
        "src/mutmut.py",
        "src/mutmut/__init__.py",
        "src/pytest.py",
        "src/pytest/__init__.py",
        "src/coverage.py",
        "src/coverage/__init__.py",
        "sitecustomize.py",
        "usercustomize.py",
        "src/sitecustomize.py",
        "src/usercustomize.py",
    ],
)
def test_mutation_trusted_tool_shadows_fail_closed(
    shared_seam_root: Path,
    relative: str,
) -> None:
    repository, cache = _initialize_gate_repository(
        shared_seam_root,
        extra_files={relative: b"raise RuntimeError('candidate tool shadow')\n"},
    )
    source_snapshot = test_gate_module.capture_source_snapshot(
        _RealGit(cache),
        root=repository,
    )

    with pytest.raises(GateError, match="mutation tool"):
        test_gate_module.reject_mutation_tool_shadows(source_snapshot)


@pytest.mark.parametrize(
    "relative",
    [
        "mutmut.pyx",
        "src/coverage.py.notes",
        "sitecustomize.py.bak",
    ],
)
def test_mutation_shadow_policy_allows_nonshadow_file_suffixes(
    shared_seam_root: Path,
    relative: str,
) -> None:
    repository, cache = _initialize_gate_repository(
        shared_seam_root,
        extra_files={relative: b"VALUE = 1\n"},
    )
    source_snapshot = test_gate_module.capture_source_snapshot(
        _RealGit(cache),
        root=repository,
    )

    test_gate_module.reject_mutation_tool_shadows(source_snapshot)


@pytest.mark.parametrize("defect", ["missing", "version", "origin"])
def test_trusted_mutation_command_rejects_invalid_parent_tool_proof(
    shared_seam_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    original_distributions = cast(
        "_DistributionFinder",
        cast("object", importlib.metadata.distributions),
    )
    original_find_spec = cast(
        "_SpecificationFinder",
        cast("object", importlib.machinery.PathFinder.find_spec),
    )

    def distributions(
        *,
        name: str | None = None,
        path: Sequence[str] | None = None,
    ) -> Iterable[importlib.metadata.Distribution]:
        if name != "mutmut":
            return original_distributions(name=name, path=path)
        if defect == "missing":
            return ()
        if defect == "version":
            return (
                cast(
                    "importlib.metadata.Distribution",
                    SimpleNamespace(version="0.0.0"),
                ),
            )
        return original_distributions(name=name, path=path)

    def find_specification(
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if fullname == "mutmut" and defect == "origin":
            hostile = shared_seam_root / "mutmut.py"
            _ = hostile.write_bytes(b"raise RuntimeError('hostile mutmut')\n")
            return importlib.machinery.ModuleSpec(
                fullname,
                loader=None,
                origin=hostile.as_posix(),
            )
        return original_find_spec(fullname, path, target)

    monkeypatch.setattr(
        "scripts.run_test_gate.importlib.metadata.distributions",
        distributions,
    )
    monkeypatch.setattr(
        "scripts.run_test_gate.importlib.machinery.PathFinder.find_spec",
        find_specification,
    )

    with pytest.raises(GateError, match="trusted test tool"):
        _ = test_gate_module.trusted_mutation_python_command(
            import_roots=(),
            arguments=("--help",),
        )


@pytest.mark.parametrize("defect", ["version", "origin"])
def test_trusted_mutation_child_rejects_wrong_serialized_proof(
    shared_seam_root: Path,
    defect: str,
) -> None:
    command = list(
        test_gate_module.trusted_mutation_python_command(
            import_roots=(),
            arguments=("--help",),
        )
    )
    proof = [list(row) for row in _trusted_command_proof(tuple(command))]
    if defect == "version":
        proof[0][2] = "0.0.0"
    else:
        hostile = shared_seam_root / "mutmut.py"
        _ = hostile.write_bytes(b"raise RuntimeError('hostile mutmut')\n")
        proof[0][3] = hostile.as_posix()
    command[_TRUSTED_DRIVER_PROOF_INDEX] = json.dumps(
        proof,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    home = shared_seam_root / "home"
    temporary = shared_seam_root / "tmp"
    home.mkdir()
    temporary.mkdir()

    result = SystemExecutor()(
        CommandRequest(
            argv=tuple(command),
            cwd=shared_seam_root,
            environment=(
                ("HOME", home.as_posix()),
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
                ("PATH", "/usr/bin:/bin"),
                ("PYTHONNOUSERSITE", "1"),
                ("TMPDIR", temporary.as_posix()),
            ),
            timeout_seconds=30.0,
        )
    )

    assert result.returncode == _TRUSTED_DRIVER_REJECTION
