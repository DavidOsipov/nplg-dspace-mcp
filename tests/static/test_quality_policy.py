# Copyright (c) 2026 David Osipov
"""Static tests for strict quality-policy configuration."""

from __future__ import annotations

import json
import re
import tomllib
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

import pytest
import yaml
from pydantic import BaseModel, ConfigDict, Field

from nplg_mcp.json_types import JsonObject, load_json_value, require_json_object
from scripts.run_quality_gate import run_bounded_command

if TYPE_CHECKING:
    from collections.abc import Callable


load_yaml_object = cast("Callable[[str], object]", yaml.safe_load)


def _load_workflow_object(text: str) -> object:
    quoted_on = re.sub(r"(?m)^on:$", '"on":', text)
    return load_yaml_object(quoted_on)


class _PolicyModel(BaseModel):
    """Strict immutable base for typed policy configuration reads."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)


class _CopyrightPolicy(_PolicyModel):
    """Reviewed Ruff copyright rule settings."""

    notice_regex: str = Field(alias="notice-rgx")
    minimum_file_size: int = Field(alias="min-file-size")


class _RuffLintPolicy(_PolicyModel):
    """Reviewed Ruff lint settings."""

    select: tuple[str, ...]
    copyright: _CopyrightPolicy = Field(alias="flake8-copyright")
    per_file_ignores: dict[str, tuple[str, ...]] = Field(alias="per-file-ignores")


class _RuffPolicy(_PolicyModel):
    """Reviewed Ruff configuration subset."""

    lint: _RuffLintPolicy


class _CoverageRunPolicy(_PolicyModel):
    """Reviewed coverage execution settings."""

    branch: bool


class _CoverageReportPolicy(_PolicyModel):
    """Reviewed coverage reporting settings."""

    fail_under: int


class _CoveragePolicy(_PolicyModel):
    """Reviewed coverage settings."""

    run: _CoverageRunPolicy
    report: _CoverageReportPolicy


class _MypyPolicy(_PolicyModel):
    """Reviewed mypy strictness settings."""

    strict: bool
    mypy_path: str
    disallow_any_decorated: bool
    disallow_any_explicit: bool
    disallow_any_expr: bool
    disallow_any_generics: bool
    disallow_any_unimported: bool
    extra_checks: bool
    strict_bytes: bool
    strict_equality_for_none: bool
    warn_unreachable: bool
    warn_unused_configs: bool


class _ToolPolicy(_PolicyModel):
    """Reviewed pyproject tool settings."""

    ruff: _RuffPolicy
    coverage: _CoveragePolicy
    mypy: _MypyPolicy


class _PyprojectPolicy(_PolicyModel):
    """Typed subset of the repository pyproject."""

    tool: _ToolPolicy


class _PyrightPolicy(_PolicyModel):
    """Typed subset of the repository Pyright configuration."""

    type_checking_mode: Literal["strict"] = Field(alias="typeCheckingMode")
    include: tuple[str, ...]
    venv_path: str = Field(alias="venvPath")
    venv: str
    stub_path: str = Field(alias="stubPath")
    enable_type_ignore_comments: bool = Field(alias="enableTypeIgnoreComments")
    report_missing_type_stubs: Literal["error"] = Field(alias="reportMissingTypeStubs")
    report_call_in_default_initializer: Literal["error"] = Field(
        alias="reportCallInDefaultInitializer"
    )
    report_implicit_override: Literal["error"] = Field(alias="reportImplicitOverride")
    report_implicit_string_concatenation: Literal["error"] = Field(
        alias="reportImplicitStringConcatenation"
    )
    report_import_cycles: Literal["error"] = Field(alias="reportImportCycles")
    report_missing_module_source: Literal["error"] = Field(
        alias="reportMissingModuleSource"
    )
    report_missing_super_call: Literal["error"] = Field(alias="reportMissingSuperCall")
    report_property_type_mismatch: Literal["error"] = Field(
        alias="reportPropertyTypeMismatch"
    )
    report_uninitialized_instance_variable: Literal["error"] = Field(
        alias="reportUninitializedInstanceVariable"
    )
    report_unnecessary_type_ignore_comment: Literal["error"] = Field(
        alias="reportUnnecessaryTypeIgnoreComment"
    )
    report_unreachable: Literal["error"] = Field(alias="reportUnreachable")
    report_unused_call_result: Literal["error"] = Field(alias="reportUnusedCallResult")


def _model_from_json[T: BaseModel](model: type[T], raw: object) -> T:
    payload = json.dumps(raw, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return model.model_validate_json(payload, strict=True)


def _workflow_steps(relative_path: str) -> tuple[JsonObject, ...]:
    jobs = _workflow_jobs(relative_path)
    steps: list[JsonObject] = []
    for job_name, job in jobs.items():
        raw_steps = job["steps"]
        if not isinstance(raw_steps, list):
            message = f"{relative_path}.jobs.{job_name}.steps must be an array"
            raise TypeError(message)
        for index, raw_step in enumerate(cast("list[object]", raw_steps)):
            steps.append(
                require_json_object(
                    raw_step,
                    context=f"{relative_path}.jobs.{job_name}.steps[{index}]",
                )
            )
    return tuple(steps)


def _workflow_jobs(relative_path: str) -> dict[str, JsonObject]:
    path = ROOT / relative_path
    assert path.is_file(), f"required workflow is absent: {relative_path}"
    workflow = require_json_object(
        _load_workflow_object(path.read_text(encoding="utf-8")),
        context=relative_path,
    )
    jobs = require_json_object(workflow["jobs"], context=f"{relative_path}.jobs")
    typed_jobs: dict[str, JsonObject] = {}
    for job_name, raw_job in jobs.items():
        typed_jobs[job_name] = require_json_object(
            raw_job,
            context=f"{relative_path}.jobs.{job_name}",
        )
    return typed_jobs


def _workflow_text(relative_path: str) -> str:
    path = ROOT / relative_path
    assert path.is_file(), f"required workflow is absent: {relative_path}"
    return path.read_text(encoding="utf-8")


ROOT = Path(__file__).parents[2]
COVERAGE_FLOOR = 95
QUALITY_RUNNER = "run: python scripts/run_quality_gate.py "
MANAGED_NODE_ARGUMENT = '--node-executable "$(command -v node)" '
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
WORKFLOW_PATHS = (
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
)
WORKFLOW_JOB_INVENTORY = {
    ".github/workflows/ci.yml": frozenset(
        {"lint", "types", "tests", "contracts", "package"}
    ),
    ".github/workflows/security.yml": frozenset(
        {"sast", "sca", "sbom", "secrets", "container"}
    ),
}
ACTION_INVENTORY = {
    CHECKOUT_ACTION: "v7.0.1",
    "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97": "v7.0.0",
    "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020": "v7.0.0",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": "v7.0.1",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c": "v8.0.1",
    "github/codeql-action@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd": "v4.37.7",
}
EXPECTED_PYTHON_PATCHES = ("3.12.14", "3.13.15", "3.14.7")
CONTRACT_SOURCE_INVENTORY = (
    "contracts/zod/baseline-contracts.mjs",
    "contracts/zod/asvs-evidence-contracts.mjs",
    "contracts/zod/capability-contracts.mjs",
    "contracts/zod/models.ts",
    "contracts/zod/contract.test.ts",
    "tests/contracts/zod_baseline_contracts.test.mjs",
    "tests/contracts/zod_asvs_evidence_contracts.test.mjs",
    "tests/contracts/zod_contracts.test.mjs",
)
PHASE_TWO_NODE_PINS = {
    "@eslint/js": "10.0.1",
    "@types/node": "24.13.3",
    "eslint": "10.8.1",
    "markdownlint-cli2": "0.23.2",
    "typescript": "6.0.3",
    "typescript-eslint": "8.67.0",
    "zod": "4.4.3",
}
PACKAGE_LOCK_EVIDENCE_JOBS = 2
EXPECTED_SEMGREP_RULE_IDS = frozenset(
    {
        "nplg.no-subprocess-shell",
        "nplg.no-unverified-tls",
        "nplg.no-unbounded-http-client",
        "nplg.no-path-reopen-after-validation",
        "nplg.no-secret-in-log",
        "nplg.strict-pydantic-boundary",
    }
)
FULL_ACTION_REFERENCE = re.compile(
    r"^[a-z0-9_.-]+/[a-z0-9_.-]+(?:/[a-z0-9_.-]+)?@[0-9a-f]{40}$"
)


def _action_identity(action: str) -> str:
    name, separator, revision = action.rpartition("@")
    assert separator == "@"
    if name.startswith("github/codeql-action/"):
        name = "github/codeql-action"
    return f"{name}@{revision}"


REMOVED_QUALITY_RATCHET_PATHS = (
    "quality-baseline.json",
    "scripts/quality_ratchet.py",
    "tests/unit/test_quality_ratchet.py",
    "tests/property/test_quality_ratchet.py",
    "contracts/zod/quality-baseline-contracts.mjs",
    "tests/contracts/zod_quality_baseline_contracts.test.mjs",
)
QUALITY_RATCHET_DEPENDENTS = (
    "scripts/run_quality_gate.py",
    "scripts/baseline_capture_io.py",
    "tests/contracts/test_frozen_baseline.py",
    "contracts/zod/baseline-contracts.mjs",
    "tests/contracts/zod_baseline_contracts.test.mjs",
    "package.json",
    "eslint.config.mjs",
    "tsconfig.contracts.json",
    ".github/workflows/ci.yml",
)
REMOVED_QUALITY_RATCHET_TOKENS = (
    "quality-baseline.json",
    "quality_ratchet",
    "quality-baseline-contracts",
    "zod_quality_baseline_contracts",
    "--ratchet",
    "--write-baseline",
    "staged_entries_projection",
)


def test_quality_configuration_is_maximally_strict() -> None:
    pyproject_raw = cast(
        "object",
        tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8")),
    )
    pyright_raw = cast(
        "object",
        json.loads((ROOT / "pyrightconfig.json").read_text(encoding="utf-8")),
    )
    pyproject = _model_from_json(_PyprojectPolicy, pyproject_raw)
    pyright = _model_from_json(_PyrightPolicy, pyright_raw)
    assert pyproject.tool.ruff.lint.select == ("ALL",)
    assert pyproject.tool.ruff.lint.copyright.notice_regex == (
        r"Copyright \(c\) 2026 David Osipov"
    )
    assert pyproject.tool.ruff.lint.copyright.minimum_file_size == 0
    assert pyproject.tool.ruff.lint.per_file_ignores == {
        "tests/**/*.py": ("D102", "D103", "S101"),
    }
    assert pyright.type_checking_mode == "strict"
    assert pyright.include == ("src", "tests", "scripts", "typings")
    assert pyright.venv_path == "."
    assert pyright.venv == ".venv"
    assert pyright.stub_path == "typings"
    assert pyright.enable_type_ignore_comments is False
    assert pyright.report_missing_type_stubs == "error"
    assert all(
        setting == "error"
        for setting in (
            pyright.report_call_in_default_initializer,
            pyright.report_implicit_override,
            pyright.report_implicit_string_concatenation,
            pyright.report_import_cycles,
            pyright.report_missing_module_source,
            pyright.report_missing_super_call,
            pyright.report_property_type_mismatch,
            pyright.report_uninitialized_instance_variable,
            pyright.report_unnecessary_type_ignore_comment,
            pyright.report_unreachable,
            pyright.report_unused_call_result,
        )
    )
    assert pyproject.tool.coverage.run.branch is True
    assert pyproject.tool.coverage.report.fail_under == COVERAGE_FLOOR
    mypy = pyproject.tool.mypy
    assert mypy.strict is True
    assert mypy.mypy_path == "typings:src"
    assert all(
        (
            mypy.disallow_any_decorated,
            mypy.disallow_any_explicit,
            mypy.disallow_any_expr,
            mypy.disallow_any_generics,
            mypy.disallow_any_unimported,
            mypy.extra_checks,
            mypy.strict_bytes,
            mypy.strict_equality_for_none,
            mypy.warn_unreachable,
            mypy.warn_unused_configs,
        )
    )


def test_quality_lock_keeps_security_linter_separate() -> None:
    development = (ROOT / "requirements-dev.in").read_text(encoding="utf-8")
    security = (ROOT / "requirements-security.in").read_text(encoding="utf-8")
    assert "semgrep" not in development.lower()
    assert "semgrep==1.173.0" in security


def test_ci_runs_the_strict_quality_contract_with_release_identity() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for command in (
        "run: npm run contracts:lint",
        "run: npm run contracts:typecheck",
        "run: npm run contracts:test",
        "run: npm run docs:lint",
    ):
        assert command in workflow
    assert "python scripts/export_contracts.py --check" in workflow
    assert (
        "check-jsonschema --check-metaschema "
        "contracts/generated/tool-contracts.schema.json"
    ) in workflow
    assert "git diff --exit-code -- contracts/generated" in workflow
    assert QUALITY_RUNNER + MANAGED_NODE_ARGUMENT + "--self-test" in workflow
    assert (
        QUALITY_RUNNER
        + MANAGED_NODE_ARGUMENT
        + '--worktree "$GITHUB_WORKSPACE" '
        + '--cache-dir "$RUNNER_TEMP/nplg-quality-${{ matrix.python-version }}" '
        + '--require-clean --candidate "$GITHUB_SHA" '
        + "src tests scripts typings"
    ) in workflow


def test_phase_two_node_and_typescript_policy_is_exact() -> None:
    package = require_json_object(
        load_json_value((ROOT / "package.json").read_bytes()),
        context="package.json",
    )
    dependencies = require_json_object(
        package["devDependencies"],
        context="package.json devDependencies",
    )
    assert {
        name: dependencies[name] for name in PHASE_TWO_NODE_PINS
    } == PHASE_TWO_NODE_PINS
    assert package["type"] == "module"
    assert package["packageManager"] == "npm@11.18.0"

    tsconfig = require_json_object(
        load_json_value((ROOT / "tsconfig.contracts.json").read_bytes()),
        context="tsconfig.contracts.json",
    )
    assert tsconfig["include"] == list(CONTRACT_SOURCE_INVENTORY)
    options = require_json_object(
        tsconfig["compilerOptions"],
        context="tsconfig compilerOptions",
    )
    assert options == {
        "allowImportingTsExtensions": True,
        "allowJs": True,
        "checkJs": True,
        "erasableSyntaxOnly": True,
        "exactOptionalPropertyTypes": True,
        "forceConsistentCasingInFileNames": True,
        "lib": ["ES2024"],
        "module": "NodeNext",
        "moduleDetection": "force",
        "moduleResolution": "NodeNext",
        "noEmit": True,
        "noFallthroughCasesInSwitch": True,
        "noImplicitOverride": True,
        "noImplicitReturns": True,
        "noPropertyAccessFromIndexSignature": True,
        "noUncheckedIndexedAccess": True,
        "noUncheckedSideEffectImports": True,
        "noUnusedLocals": True,
        "noUnusedParameters": True,
        "strict": True,
        "target": "ES2024",
        "types": ["node"],
        "useUnknownInCatchVariables": True,
        "verbatimModuleSyntax": True,
    }


def test_markdown_policy_is_closed_and_covers_owned_markdown() -> None:
    expected_config = """// Copyright (c) 2026 David Osipov

export default {
  config: {
    default: true,
    MD013: false,
    MD024: { siblings_only: true },
    MD040: true,
    MD046: { style: \"fenced\" },
    MD048: { style: \"backtick\" },
  },
  ignores: [\"THIRD_PARTY_NOTICES.md\"],
};
"""
    assert (ROOT / ".markdownlint-cli2.mjs").read_text(
        encoding="utf-8"
    ) == expected_config
    package = require_json_object(
        load_json_value((ROOT / "package.json").read_bytes()),
        context="package.json",
    )
    scripts = require_json_object(package["scripts"], context="package scripts")
    assert scripts["docs:lint"] == (
        'markdownlint-cli2 "*.md" "docs/**/*.md" "deploy/**/*.md" "skills/**/*.md"'
    )
    result = run_bounded_command(
        (
            "/usr/bin/git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.md",
        ),
        root=ROOT,
        cache_dir=Path("/dev/null"),
    )
    paths = tuple(
        field.decode("utf-8") for field in result.stdout.split(b"\0") if field
    )
    assert paths
    assert all(
        "/" not in path or path.startswith(("docs/", "deploy/", "skills/"))
        for path in paths
    )


def test_security_workflow_binds_node_sca_and_sbom_to_package_lock() -> None:
    workflow = _workflow_text(".github/workflows/security.yml")
    assert (
        "npm audit --audit-level=low --package-lock-only --ignore-scripts --json"
        in workflow
    )
    assert "npm sbom --package-lock-only --sbom-format cyclonedx" in workflow
    assert workflow.count("sha256sum package-lock.json") == PACKAGE_LOCK_EVIDENCE_JOBS


def test_ci_checkout_is_credentialless_and_fetches_full_history() -> None:
    checkout_steps = tuple(
        step
        for step in _workflow_steps(".github/workflows/ci.yml")
        if step.get("uses") == CHECKOUT_ACTION
    )
    assert checkout_steps, "CI must use the reviewed checkout Action"
    for step in checkout_steps:
        assert "with" in step, "checkout must declare credential and history controls"
        inputs = require_json_object(step["with"], context="checkout.with")
        assert inputs.get("persist-credentials") is False
        assert inputs.get("fetch-depth") == 0


def test_workflow_job_inventory_is_complete_and_closed() -> None:
    for relative_path, expected_jobs in WORKFLOW_JOB_INVENTORY.items():
        assert frozenset(_workflow_jobs(relative_path)) == expected_jobs


def test_workflow_actions_are_pinned_to_the_closed_reviewed_inventory() -> None:
    observed_actions: set[str] = set()
    for relative_path in WORKFLOW_PATHS:
        text = _workflow_text(relative_path)
        for step in _workflow_steps(relative_path):
            action = step.get("uses")
            if action is None:
                continue
            assert type(action) is str
            assert FULL_ACTION_REFERENCE.fullmatch(action) is not None, action
            identity = _action_identity(action)
            assert identity in ACTION_INVENTORY, action
            expected_line = f"uses: {action} # {ACTION_INVENTORY[identity]}"
            assert expected_line in text, expected_line
            observed_actions.add(identity)
    assert observed_actions == set(ACTION_INVENTORY)


def test_codeql_action_uses_explicit_init_and_analyze_entrypoints() -> None:
    entrypoints = {
        str(step["uses"]).split("@", maxsplit=1)[0]
        for step in _workflow_steps(".github/workflows/security.yml")
        if str(step.get("uses", "")).startswith("github/codeql-action/")
    }
    assert entrypoints == {"github/codeql-action/init", "github/codeql-action/analyze"}


def test_all_workflow_checkouts_are_credentialless_and_full_history() -> None:
    for relative_path in WORKFLOW_PATHS:
        checkout_steps = tuple(
            step
            for step in _workflow_steps(relative_path)
            if step.get("uses") == CHECKOUT_ACTION
        )
        assert checkout_steps, relative_path
        for step in checkout_steps:
            inputs = require_json_object(step["with"], context="checkout.with")
            assert inputs.get("persist-credentials") is False
            assert inputs.get("fetch-depth") == 0


def test_workflows_use_least_privilege_and_publish_digest_bound_evidence() -> None:
    forbidden_fragments = (
        "pull_request_target:",
        "id-token: write",
        "ACTIONS_ID_TOKEN_REQUEST_",
        "http.extraheader",
        "http.*.extraheader",
        "credential.helper",
        "${{ secrets.",
        "GITHUB_TOKEN",
    )
    upload_action = next(
        action
        for action in ACTION_INVENTORY
        if action.startswith("actions/upload-artifact@")
    )
    for relative_path in WORKFLOW_PATHS:
        text = _workflow_text(relative_path)
        assert "permissions:\n  contents: read" in text
        assert "cancel-in-progress: true" in text
        for fragment in forbidden_fragments:
            assert fragment not in text, f"{relative_path}: {fragment}"
        for job_name, job in _workflow_jobs(relative_path).items():
            raw_steps = job["steps"]
            assert isinstance(raw_steps, list)
            steps = tuple(
                require_json_object(
                    raw_step,
                    context=f"{relative_path}.jobs.{job_name}.steps",
                )
                for raw_step in cast("list[object]", raw_steps)
            )
            assert any(step.get("uses") == upload_action for step in steps), job_name
            assert any("sha256sum" in str(step.get("run", "")) for step in steps), (
                job_name
            )


def test_ci_runs_exact_python_node_quality_test_and_package_gates() -> None:
    jobs = _workflow_jobs(".github/workflows/ci.yml")
    tests_job = jobs["tests"]
    strategy = require_json_object(tests_job["strategy"], context="ci.tests.strategy")
    matrix = require_json_object(strategy["matrix"], context="ci.tests.strategy.matrix")
    raw_patches = matrix["python-version"]
    assert isinstance(raw_patches, list)
    assert tuple(cast("list[str]", raw_patches)) == EXPECTED_PYTHON_PATCHES
    steps = _workflow_steps(".github/workflows/ci.yml")
    node_steps = tuple(
        step
        for step in steps
        if str(step.get("uses", "")).startswith("actions/setup-node@")
    )
    assert node_steps
    for step in node_steps:
        inputs = require_json_object(step["with"], context="setup-node.with")
        assert inputs.get("node-version") == "24.19.0"
    workflow = _workflow_text(".github/workflows/ci.yml")
    assert MANAGED_NODE_ARGUMENT in workflow
    assert "scripts/run_test_gate.py --compare-branch origin/main" in workflow
    assert "python -m build --no-isolation" in workflow
    assert "--require-hashes -r requirements-dev.lock" in workflow
    assert 'requires_python == ">=3.12,<3.15"' in workflow
    assert "--override-ini=pythonpath=" in workflow


def _assert_full_pep561_ci_command(command: str) -> None:
    required = (
        "python -I -B scripts/verify_pep561.py",
        '--worktree "$GITHUB_WORKSPACE"',
        '--output-dir "$RUNNER_TEMP/nplg-pep561"',
        '--node-executable "$(command -v node)"',
        '--candidate "$GITHUB_SHA"',
    )
    for fragment in required:
        assert fragment in command, fragment
    assert "--artifact-only" not in command


def test_ci_requires_full_pep561_authority_and_uploads_bound_evidence() -> None:
    jobs = _workflow_jobs(".github/workflows/ci.yml")
    types_job = require_json_object(jobs["types"], context="ci.types")
    raw_steps = types_job["steps"]
    assert isinstance(raw_steps, list)
    steps = tuple(
        require_json_object(step, context="ci.types.steps")
        for step in cast("list[object]", raw_steps)
    )
    authority = next(
        step
        for step in steps
        if step.get("name") == "Verify the full PEP 561 authority"
    )
    command = authority["run"]
    assert isinstance(command, str)
    _assert_full_pep561_ci_command(command)
    upload = next(
        step
        for step in steps
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    )
    inputs = require_json_object(upload["with"], context="PEP 561 upload inputs")
    assert "${{ runner.temp }}/nplg-pep561" in str(inputs["path"])


def _add_artifact_only(command: str) -> str:
    return command + " --artifact-only"


def _remove_candidate(command: str) -> str:
    return command.replace('--candidate "$GITHUB_SHA"', "")


def _remove_output(command: str) -> str:
    return command.replace('--output-dir "$RUNNER_TEMP/nplg-pep561"', "")


def _remove_node(command: str) -> str:
    return command.replace('--node-executable "$(command -v node)"', "")


_PEP561_CI_MUTATIONS: tuple[Callable[[str], str], ...] = (
    _add_artifact_only,
    _remove_candidate,
    _remove_output,
    _remove_node,
)


@pytest.mark.parametrize("mutation", list(_PEP561_CI_MUTATIONS))
def test_full_pep561_ci_command_mutants_are_rejected(
    mutation: Callable[[str], str],
) -> None:
    canonical = (
        "python -I -B scripts/verify_pep561.py "
        '--worktree "$GITHUB_WORKSPACE" '
        '--output-dir "$RUNNER_TEMP/nplg-pep561" '
        '--node-executable "$(command -v node)" '
        '--candidate "$GITHUB_SHA"'
    )
    with pytest.raises(AssertionError):
        _assert_full_pep561_ci_command(mutation(canonical))


def test_every_node_ci_job_bootstraps_and_invokes_locked_npm_11_18() -> None:
    jobs = _workflow_jobs(".github/workflows/ci.yml")
    node_jobs = {"contracts", "lint", "types"}
    for job_name in node_jobs:
        job = require_json_object(jobs[job_name], context=f"ci.{job_name}")
        raw_steps = job["steps"]
        assert isinstance(raw_steps, list)
        steps = tuple(
            require_json_object(step, context=f"ci.{job_name}.steps")
            for step in cast("list[object]", raw_steps)
        )
        bootstrap = next(
            step
            for step in steps
            if step.get("name") == "Bootstrap the locked JavaScript toolchain"
        )
        command = bootstrap["run"]
        assert isinstance(command, str)
        for fragment in (
            "--tool node",
            "--tool npm",
            '--dependency "node=$RUNNER_TEMP/nplg-js-toolchain/node"',
            '"$RUNNER_TEMP/nplg-js-toolchain/npm/bin/npm" --version',
            "grep -Fx '11.18.0'",
            '"$RUNNER_TEMP/nplg-js-toolchain/npm/bin" >> "$GITHUB_PATH"',
        ):
            assert fragment in command, f"{job_name}: {fragment}"


_NODE_BIN_PATH = "$RUNNER_TEMP/nplg-js-toolchain/node/node-v24.19.0-linux-x64/bin"
_NPM_BIN_PATH = "$RUNNER_TEMP/nplg-js-toolchain/npm/bin"
_NODE_GITHUB_PATH = f'echo "{_NODE_BIN_PATH}" >> "$GITHUB_PATH"'
_NPM_GITHUB_PATH = f'echo "{_NPM_BIN_PATH}" >> "$GITHUB_PATH"'
_NPM_IDENTITY = f'test "$(command -v npm)" = "{_NPM_BIN_PATH}/npm"'
_NPM_VERSION = 'test "$(npm --version)" = "11.18.0"'
_BARE_NPM_COMMAND = re.compile(r"(?m)(?:^|[;&|]\s*)npm(?:\s|$)")


def _assert_locked_npm_precedes_bare_use(
    steps: tuple[JsonObject, ...],
    *,
    context: str,
) -> None:
    bootstrap_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Bootstrap the locked JavaScript toolchain"
    )
    bootstrap = steps[bootstrap_index]
    bootstrap_command = bootstrap["run"]
    assert isinstance(bootstrap_command, str)
    assert bootstrap_command.index(_NODE_GITHUB_PATH) < bootstrap_command.index(
        _NPM_GITHUB_PATH
    ), context

    proof_index = bootstrap_index + 1
    proof = steps[proof_index]
    assert proof.get("name") == "Verify locked npm command resolution", context
    proof_command = proof["run"]
    assert isinstance(proof_command, str)
    assert proof_command.index(_NPM_IDENTITY) < proof_command.index(_NPM_VERSION), (
        context
    )

    for step in steps[:proof_index]:
        command = step.get("run")
        if isinstance(command, str):
            assert _BARE_NPM_COMMAND.search(command) is None, context


def test_every_node_ci_job_resolves_locked_npm_before_bare_use() -> None:
    jobs = _workflow_jobs(".github/workflows/ci.yml")
    for job_name in ("contracts", "lint", "types"):
        job = require_json_object(jobs[job_name], context=f"ci.{job_name}")
        raw_steps = job["steps"]
        assert isinstance(raw_steps, list)
        steps = tuple(
            require_json_object(step, context=f"ci.{job_name}.steps")
            for step in cast("list[object]", raw_steps)
        )
        _assert_locked_npm_precedes_bare_use(steps, context=job_name)

        bootstrap_index = next(
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Bootstrap the locked JavaScript toolchain"
        )
        reversed_bootstrap = dict(steps[bootstrap_index])
        command = reversed_bootstrap["run"]
        assert isinstance(command, str)
        reversed_bootstrap["run"] = command.replace(
            f"{_NODE_GITHUB_PATH}\n{_NPM_GITHUB_PATH}",
            f"{_NPM_GITHUB_PATH}\n{_NODE_GITHUB_PATH}",
        )
        reversed_steps = (
            *steps[:bootstrap_index],
            reversed_bootstrap,
            *steps[bootstrap_index + 1 :],
        )
        with pytest.raises(AssertionError):
            _assert_locked_npm_precedes_bare_use(
                reversed_steps,
                context=f"{job_name}.reversed",
            )

        proof_index = bootstrap_index + 1
        missing_identity = dict(steps[proof_index])
        proof_command = missing_identity["run"]
        assert isinstance(proof_command, str)
        missing_identity["run"] = proof_command.replace(_NPM_IDENTITY, "")
        missing_identity_steps = (
            *steps[:proof_index],
            missing_identity,
            *steps[proof_index + 1 :],
        )
        with pytest.raises((AssertionError, ValueError)):
            _assert_locked_npm_precedes_bare_use(
                missing_identity_steps,
                context=f"{job_name}.missing-identity",
            )

        early_npm: JsonObject = {
            "name": "Unverified bare npm",
            "run": "npm --version",
        }
        early_npm_steps = (
            *steps[:proof_index],
            early_npm,
            *steps[proof_index:],
        )
        with pytest.raises(AssertionError):
            _assert_locked_npm_precedes_bare_use(
                early_npm_steps,
                context=f"{job_name}.early-npm",
            )


def test_semgrep_rules_are_closed_and_digest_verified() -> None:
    rules_path = ROOT / "security" / "semgrep" / "rules.yml"
    sums_path = ROOT / "security" / "semgrep" / "SHA256SUMS"
    assert rules_path.is_file(), "reviewed Semgrep rules are absent"
    assert sums_path.is_file(), "Semgrep digest manifest is absent"
    raw_policy = require_json_object(
        load_yaml_object(rules_path.read_text(encoding="utf-8")),
        context="security/semgrep/rules.yml",
    )
    raw_rules = raw_policy["rules"]
    assert isinstance(raw_rules, list)
    rule_ids = frozenset(
        require_json_object(rule, context="semgrep rule")["id"]
        for rule in cast("list[object]", raw_rules)
    )
    assert rule_ids == EXPECTED_SEMGREP_RULE_IDS
    rules_digest = sha256(rules_path.read_bytes()).hexdigest()
    assert sums_path.read_text(encoding="utf-8") == f"{rules_digest}  rules.yml\n"
    assert "auto" not in rules_path.read_text(encoding="utf-8").lower()


def test_temporary_quality_ratchet_and_all_direct_references_are_removed() -> None:
    for relative_path in REMOVED_QUALITY_RATCHET_PATHS:
        assert not (ROOT / relative_path).exists(), relative_path
    for relative_path in QUALITY_RATCHET_DEPENDENTS:
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        for token in REMOVED_QUALITY_RATCHET_TOKENS:
            assert token not in text, f"{relative_path}: {token}"


def test_pep_561_marker_is_empty_and_not_declared_as_package_data() -> None:
    """Leave PEP 561's automatic marker inclusion outside package-data records."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert (ROOT / "src/nplg_mcp/py.typed").read_bytes() == b""
    assert "[tool.setuptools.package-data]" not in pyproject
