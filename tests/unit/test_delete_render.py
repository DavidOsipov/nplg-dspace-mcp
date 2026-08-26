# Copyright (c) 2026 David Osipov
"""Unit tests for the injected render-deletion operator CLI."""

from __future__ import annotations

import io
import runpy
import sys
from argparse import Namespace
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast, override

import pytest

from nplg_mcp.errors import AppError, ErrorCode
from scripts.delete_render import CliDependencies, main

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path
    from typing import Never

RENDER_ID = "rnd_0123456789abcdef0123456789abcdef"
OTHER_RENDER_ID = "rnd_fedcba9876543210fedcba9876543210"
OUTPUT_FAILURE_EXIT = 1
OPERATOR_FAILURE_EXIT = 2
ARGUMENT_ERROR_EXIT = 2
CANCELLED_EXIT = 130
INTERNAL_MARKER = "private-delete-detail"
OUTPUT_FAILURE = "output unavailable"
PRIVATE_DIRECTORY_MODE = 0o700


class InteractiveInput(io.StringIO):
    """Deterministic interactive confirmation input."""

    @override
    def isatty(self) -> bool:
        return True


class CancellingInteractiveInput(InteractiveInput):
    """Raise operator cancellation while reading an interactive confirmation."""

    @override
    def readline(self, size: int | None = -1, /) -> Never:
        """Raise the same interruption as Ctrl-C at the confirmation prompt."""
        del size
        raise KeyboardInterrupt


class FailingInteractiveInput(InteractiveInput):
    """Raise a deterministic input error at the confirmation boundary."""

    @override
    def readline(self, size: int | None = -1, /) -> Never:
        """Reject the confirmation read without exposing private input."""
        del size
        raise OSError(OUTPUT_FAILURE)


class FailingWriter(io.StringIO):
    """Output sink that rejects every write."""

    @override
    def write(self, value: str) -> int:
        """Raise a deterministic output failure."""
        del value
        raise OSError(OUTPUT_FAILURE)


@dataclass(frozen=True, slots=True)
class StaticArgumentParser:
    """Return one controlled parser result for fail-closed boundary tests."""

    values: dict[str, object]

    def parse_args(self, _argv: Sequence[str]) -> Namespace:
        """Return the configured namespace without applying argparse coercion."""
        return Namespace(**self.values)


def _new_identifier_log() -> list[str]:
    return []


@dataclass(slots=True)
class FakeDeleter:
    """Record the identifier and return or raise one configured outcome."""

    outcome: bool | AppError | KeyboardInterrupt
    render_ids: list[str] = field(default_factory=_new_identifier_log)

    def delete_render(self, render_id: str) -> bool:
        """Return or raise the configured deletion outcome."""
        self.render_ids.append(render_id)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def _new_root_log() -> list[Path]:
    return []


@dataclass(slots=True)
class FakeProcessorFactory:
    """Return one deletion fake and record the normalized cache root."""

    deleter: FakeDeleter
    roots: list[Path] = field(default_factory=_new_root_log)

    def __call__(self, root: Path) -> FakeDeleter:
        """Record the root and return the fake deleter."""
        self.roots.append(root)
        return self.deleter


@dataclass(frozen=True, slots=True)
class DeleteHarness:
    """Injected delete CLI effects and their observable fakes."""

    dependencies: CliDependencies
    factory: FakeProcessorFactory
    stdout: io.StringIO
    stderr: io.StringIO


def _harness(
    tmp_path: Path,
    *,
    outcome: bool | AppError | KeyboardInterrupt = True,
    stdin: io.StringIO | None = None,
    stdout: io.StringIO | None = None,
    stderr: io.StringIO | None = None,
) -> DeleteHarness:
    (tmp_path / "renders").mkdir(mode=PRIVATE_DIRECTORY_MODE, exist_ok=True)
    output = stdout or io.StringIO()
    errors = stderr or io.StringIO()
    factory = FakeProcessorFactory(FakeDeleter(outcome))
    dependencies = CliDependencies(
        environ={"CACHE_DIR": str(tmp_path)},
        stdin=io.StringIO() if stdin is None else stdin,
        stdout=output,
        stderr=errors,
        processor_factory=factory,
    )
    return DeleteHarness(dependencies, factory, output, errors)


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param([], id="missing-target"),
        pytest.param([RENDER_ID, OTHER_RENDER_ID], id="ambiguous-target"),
    ],
)
def test_main_rejects_missing_or_ambiguous_target(
    tmp_path: Path,
    argv: list[str],
) -> None:
    harness = _harness(tmp_path)

    assert main(argv, dependencies=harness.dependencies) == ARGUMENT_ERROR_EXIT
    assert harness.factory.roots == []
    assert harness.stdout.getvalue() == ""
    assert "usage:" in harness.stderr.getvalue()


def test_main_rejects_path_where_render_identifier_is_required(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    path_target = str(tmp_path / RENDER_ID)

    assert (
        main(
            [path_target, "--confirm", path_target],
            dependencies=harness.dependencies,
        )
        == OPERATOR_FAILURE_EXIT
    )
    assert harness.factory.roots == []
    assert harness.stderr.getvalue() == "FAIL: invalid render identifier\n"


def test_main_rejects_confirmation_mismatch_before_deletion(tmp_path: Path) -> None:
    harness = _harness(tmp_path)

    assert (
        main(
            [RENDER_ID, "--confirm", OTHER_RENDER_ID],
            dependencies=harness.dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert harness.factory.roots == []
    assert harness.stderr.getvalue() == (
        "FAIL: confirmation did not match render identifier\n"
    )


def test_main_refuses_noninteractive_deletion_without_confirm(tmp_path: Path) -> None:
    harness = _harness(tmp_path)

    assert main([RENDER_ID], dependencies=harness.dependencies) == ARGUMENT_ERROR_EXIT
    assert harness.factory.roots == []
    assert harness.stderr.getvalue() == (
        "FAIL: noninteractive deletion requires --confirm\n"
    )


def test_main_accepts_exact_interactive_confirmation(tmp_path: Path) -> None:
    harness = _harness(tmp_path, stdin=InteractiveInput(f"{RENDER_ID}\n"))

    assert main([RENDER_ID], dependencies=harness.dependencies) == 0
    assert harness.factory.deleter.render_ids == [RENDER_ID]
    assert harness.stdout.getvalue() == (
        f'{{"deleted": true, "render_id": "{RENDER_ID}"}}\n'
    )
    assert harness.stderr.getvalue() == f"Type {RENDER_ID} to confirm deletion: "


def test_main_maps_interactive_read_cancellation_to_sanitized_exit_130(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path, stdin=CancellingInteractiveInput())

    assert main([RENDER_ID], dependencies=harness.dependencies) == CANCELLED_EXIT
    assert harness.factory.roots == []
    assert harness.factory.deleter.render_ids == []
    assert harness.stdout.getvalue() == ""
    assert harness.stderr.getvalue() == (
        f"Type {RENDER_ID} to confirm deletion: FAIL: cancelled\n"
    )


def test_main_maps_interactive_input_failure_to_sanitized_operator_error(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path, stdin=FailingInteractiveInput())

    assert main([RENDER_ID], dependencies=harness.dependencies) == OPERATOR_FAILURE_EXIT
    assert harness.factory.roots == []
    assert harness.stderr.getvalue() == (
        f"Type {RENDER_ID} to confirm deletion: FAIL: confirmation input failed\n"
    )


@pytest.mark.parametrize(
    "values",
    [
        pytest.param(
            {"render_id": 1, "cache_dir": "/cache", "confirm": None},
            id="invalid-render-id",
        ),
        pytest.param(
            {"render_id": RENDER_ID, "cache_dir": "/cache", "confirm": 1},
            id="invalid-confirmation",
        ),
    ],
)
def test_main_fails_closed_if_argument_parser_returns_invalid_types(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    values: dict[str, object],
) -> None:
    harness = _harness(tmp_path)
    parser = StaticArgumentParser(values)

    def parser_factory(_environ: Mapping[str, str]) -> StaticArgumentParser:
        return parser

    monkeypatch.setattr("scripts.delete_render._parser", parser_factory)

    assert main([], dependencies=harness.dependencies) == OPERATOR_FAILURE_EXIT
    assert harness.factory.roots == []
    assert (
        harness.stderr.getvalue() == "FAIL: argument parser returned invalid values\n"
    )


def test_main_rejects_an_uninitialized_cache_without_constructing_processor(
    tmp_path: Path,
) -> None:
    missing_root = tmp_path / "missing-cache"
    harness = _harness(tmp_path)

    assert (
        main(
            [
                RENDER_ID,
                "--cache-dir",
                str(missing_root),
                "--confirm",
                RENDER_ID,
            ],
            dependencies=harness.dependencies,
        )
        == OPERATOR_FAILURE_EXIT
    )
    assert harness.factory.roots == []
    assert harness.stderr.getvalue() == "FAIL: cache directory is not initialized\n"


def test_process_entrypoint_uses_real_default_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "renders").mkdir(mode=PRIVATE_DIRECTORY_MODE)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "scripts/delete_render.py",
            RENDER_ID,
            "--cache-dir",
            str(tmp_path),
            "--confirm",
            RENDER_ID,
        ],
    )

    with pytest.raises(SystemExit) as captured:
        _ = cast(
            "object",
            runpy.run_path("scripts/delete_render.py", run_name="__main__"),
        )

    process_output = capsys.readouterr()
    assert captured.value.code == 0
    assert process_output.out == f'{{"deleted": false, "render_id": "{RENDER_ID}"}}\n'
    assert process_output.err == ""


def test_main_treats_not_found_as_idempotent_success(tmp_path: Path) -> None:
    harness = _harness(tmp_path, outcome=False)

    assert (
        main(
            [RENDER_ID, "--confirm", RENDER_ID],
            dependencies=harness.dependencies,
        )
        == 0
    )
    assert harness.factory.deleter.render_ids == [RENDER_ID]
    assert harness.stdout.getvalue() == (
        f'{{"deleted": false, "render_id": "{RENDER_ID}"}}\n'
    )
    assert harness.stderr.getvalue() == ""


def test_main_emits_only_safe_app_error_message(tmp_path: Path) -> None:
    safe_message = "Render could not be deleted"
    error = AppError(
        ErrorCode.NOT_FOUND,
        safe_message,
        internal_details={"path": INTERNAL_MARKER},
    )
    harness = _harness(tmp_path, outcome=error)

    assert (
        main(
            [RENDER_ID, "--confirm", RENDER_ID],
            dependencies=harness.dependencies,
        )
        == OPERATOR_FAILURE_EXIT
    )
    assert harness.stdout.getvalue() == ""
    assert harness.stderr.getvalue() == f"FAIL: {safe_message}\n"
    assert INTERNAL_MARKER not in harness.stderr.getvalue()


def test_main_maps_cancellation_to_exit_130(tmp_path: Path) -> None:
    harness = _harness(tmp_path, outcome=KeyboardInterrupt())

    assert (
        main(
            [RENDER_ID, "--confirm", RENDER_ID],
            dependencies=harness.dependencies,
        )
        == CANCELLED_EXIT
    )
    assert harness.stdout.getvalue() == ""
    assert harness.stderr.getvalue() == "FAIL: cancelled\n"


def test_main_reports_output_failure(tmp_path: Path) -> None:
    harness = _harness(tmp_path, stdout=FailingWriter())

    assert (
        main(
            [RENDER_ID, "--confirm", RENDER_ID],
            dependencies=harness.dependencies,
        )
        == OUTPUT_FAILURE_EXIT
    )
    assert harness.stderr.getvalue() == "FAIL: output write failed\n"


def test_main_returns_internal_failure_if_error_output_is_unavailable(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path, stderr=FailingWriter())

    assert main(["invalid"], dependencies=harness.dependencies) == OUTPUT_FAILURE_EXIT
    assert harness.factory.roots == []
