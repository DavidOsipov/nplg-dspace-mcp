# Copyright (c) 2026 David Osipov
"""Capture deterministic ToolService/MCP contract fixtures."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, cast

if __name__ == "__main__" and not __package__:
    script_package_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(script_package_root))
    __package__ = "scripts"

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
)

from scripts import baseline_capture_io
from scripts.baseline_capture_io import (
    BASELINE_DIRECTORY_FILES,
    BASELINE_FILES,
    BASELINE_MANIFEST_FILE,
    DEFAULT_CAPTURE_POLICY,
    EXCLUDED_OUTPUT_PATHS,
    INCLUDED_UNTRACKED_PATHS,
    MAX_GIT_STDERR_BYTES,
    BaselineCaptureError,
    BaselineFileName,
    CaptureInputIdentity,
    CapturePolicy,
    CollectedBaseline,
    FixtureCollector,
    GeneratorIdentity,
    GitObjectId,
    IndexTransitionIdentity,
    PublicationOperations,
    ReplaceFunction,
    StageFunction,
    canonical_json_bytes,
    collect_from_synthetic_input,
    load_canonical_json,
    read_regular_bytes,
    replace_path,
    require_string_object,
    write_staged_file,
)
from scripts.baseline_capture_io import (
    publish_output_bytes as publish_io_output_bytes,
)

__all__ = [
    "DEFAULT_CAPTURE_POLICY",
    "BaselineCaptureError",
    "CapturePolicy",
    "load_canonical_json",
]

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

BASELINE_DIR = Path("contracts/baseline")
RESPONSE_NUMBER_CANONICALIZATION: Literal["nplg-response-semantic-numbers-v1"] = (
    "nplg-response-semantic-numbers-v1"
)
HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CaseId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")]
EXPECTED_TOOL_NAMES = frozenset(
    {
        "download_document_file",
        "get_document_metadata",
        "get_render_manifest",
        "inspect_pdf",
        "list_document_files",
        "render_pdf_page_tiles",
        "render_pdf_pages",
        "search_documents",
    },
)


class _BaselineModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
    )


class BaselineEntry(_BaselineModel):
    """Digest-bound entry for one generated fixture file."""

    path: BaselineFileName
    sha256: HexDigest


class GitSourceIdentity(_BaselineModel):
    """Audited Git commit, tree, and source-tree identity."""

    commit: GitObjectId
    tree: GitObjectId
    src_tree: GitObjectId


class RecoveryIdentity(_BaselineModel):
    """Recovery base and imported-index identities."""

    base_commit: GitObjectId
    base_tree: GitObjectId
    imported_index_tree: GitObjectId


class BaselineManifest(_BaselineModel):
    """Strict provenance and allocation contract for the frozen baseline."""

    schema_version: Literal[3]
    capture_mode: Literal["synthetic-index-staged-recovery"]
    audit: GitSourceIdentity
    recovery: RecoveryIdentity
    index_transition: IndexTransitionIdentity
    input: CaptureInputIdentity
    generator: GeneratorIdentity
    canonicalization: Literal["nplg-json-sort-utf8-lf-v1"]
    response_canonicalization: Literal["nplg-response-semantic-numbers-v1"]
    entries: Annotated[tuple[BaselineEntry, ...], Field(min_length=4, max_length=4)]
    required_tool_names: Annotated[
        tuple[CaseId, ...],
        Field(min_length=8, max_length=8),
    ]
    required_case_ids: Annotated[
        tuple[CaseId, ...],
        Field(min_length=1, max_length=512),
    ]
    release_eligible: Literal[False]
    release_blockers: Annotated[
        tuple[Literal["BASELINE_CAPTURE_NOT_COMMIT_REACHABLE"], ...],
        Field(min_length=1, max_length=1),
    ]


def _load_baseline_files(root: Path) -> dict[BaselineFileName, dict[str, object]]:
    loaded: dict[BaselineFileName, dict[str, object]] = {}
    for name in BASELINE_FILES:
        loaded[name] = require_string_object(
            load_canonical_json(root / name),
            context=name,
        )
    return loaded


def _load_baseline_manifest(root: Path) -> BaselineManifest:
    manifest_value = load_canonical_json(root / BASELINE_MANIFEST_FILE)
    try:
        return BaselineManifest.model_validate_json(
            canonical_json_bytes(manifest_value),
            strict=True,
        )
    except ValidationError as exc:
        msg = "baseline manifest does not satisfy the closed v3 schema"
        raise BaselineCaptureError(msg) from exc


def _validate_manifest_input(manifest: BaselineManifest) -> None:
    if (
        manifest.recovery.imported_index_tree
        != manifest.index_transition.imported_index_tree
    ):
        msg = "baseline recovery and transition imported trees differ"
        raise BaselineCaptureError(msg)
    if manifest.input.tree_before != manifest.input.tree_after:
        msg = "baseline input tree changed during capture"
        raise BaselineCaptureError(msg)
    if manifest.input.excluded_output_paths != EXCLUDED_OUTPUT_PATHS:
        msg = "baseline input exclusions are incomplete, duplicated, or reordered"
        raise BaselineCaptureError(msg)
    if manifest.input.included_untracked_paths != INCLUDED_UNTRACKED_PATHS:
        msg = (
            "baseline reviewed untracked inputs are incomplete, duplicated, "
            "or reordered"
        )
        raise BaselineCaptureError(msg)


def _validate_manifest_allocation(
    manifest: BaselineManifest,
    loaded: Mapping[BaselineFileName, Mapping[str, object]],
) -> None:
    entry_paths = tuple(entry.path for entry in manifest.entries)
    if entry_paths != BASELINE_FILES or len(set(entry_paths)) != len(entry_paths):
        msg = "baseline manifest entries must name the four fixtures exactly once"
        raise BaselineCaptureError(msg)
    tool_names = tuple(sorted(EXPECTED_TOOL_NAMES))
    if manifest.required_tool_names != tool_names:
        msg = "baseline required tool names are incomplete, duplicated, or unsorted"
        raise BaselineCaptureError(msg)
    if tuple(sorted(set(manifest.required_case_ids))) != manifest.required_case_ids:
        msg = "baseline required case IDs must be unique and sorted"
        raise BaselineCaptureError(msg)
    if frozenset(loaded["tool-catalog.json"]) != EXPECTED_TOOL_NAMES:
        msg = "baseline tool catalog does not match the required tool names"
        raise BaselineCaptureError(msg)


def _captured_case_ids(
    loaded: Mapping[BaselineFileName, Mapping[str, object]],
) -> set[str]:
    captured: set[str] = set()
    for name in BASELINE_FILES[1:]:
        for case_id in loaded[name]:
            if case_id in captured:
                msg = f"duplicate case ID across baseline fixture files: {case_id}"
                raise BaselineCaptureError(msg)
            captured.add(case_id)
    return captured


def _validate_manifest_digests(root: Path, manifest: BaselineManifest) -> None:
    for entry in manifest.entries:
        digest = hashlib.sha256((root / entry.path).read_bytes()).hexdigest()
        if digest != entry.sha256:
            msg = f"baseline fixture digest mismatch: {entry.path}"
            raise BaselineCaptureError(msg)


def validate_baseline_directory(root: Path) -> BaselineManifest:
    """Validate a closed five-file baseline directory and return manifest v3."""
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode):
        msg = f"baseline root must be a directory, not a link or special file: {root}"
        raise BaselineCaptureError(msg)
    actual_names = tuple(sorted(entry.name for entry in root.iterdir()))
    expected_names = tuple(sorted(BASELINE_DIRECTORY_FILES))
    if actual_names != expected_names:
        msg = "baseline directory has an unknown or missing file"
        raise BaselineCaptureError(msg)
    loaded = _load_baseline_files(root)
    manifest = _load_baseline_manifest(root)
    _validate_manifest_input(manifest)
    _validate_manifest_allocation(manifest, loaded)
    captured_case_ids = _captured_case_ids(loaded)
    if captured_case_ids != set(manifest.required_case_ids):
        msg = "baseline case inventory does not match the manifest"
        raise BaselineCaptureError(msg)
    _validate_manifest_digests(root, manifest)
    return manifest


def publish_output_bytes(
    root: Path,
    outputs: Mapping[str, bytes],
    *,
    replace: ReplaceFunction = replace_path,
    rollback: ReplaceFunction = replace_path,
    stage: StageFunction = write_staged_file,
) -> None:
    """Publish validated bytes through the closed operating-system boundary."""
    publish_io_output_bytes(
        root,
        outputs,
        operations=PublicationOperations(
            validator=validate_baseline_directory,
            replace=replace,
            rollback=rollback,
            stage=stage,
        ),
    )


def _build_output_bytes(
    collected: CollectedBaseline,
    *,
    policy: CapturePolicy,
) -> dict[str, bytes]:
    fixture_bytes: dict[BaselineFileName, bytes] = {
        name: canonical_json_bytes(collected.fixtures[name]) for name in BASELINE_FILES
    }
    if frozenset(collected.fixtures["tool-catalog.json"]) != EXPECTED_TOOL_NAMES:
        msg = "captured tool catalog does not contain the exact eight tools"
        raise BaselineCaptureError(msg)
    required_case_ids: set[str] = set()
    for name in BASELINE_FILES[1:]:
        for case_id in collected.fixtures[name]:
            if case_id in required_case_ids:
                msg = f"duplicate case ID across captured fixture files: {case_id}"
                raise BaselineCaptureError(msg)
            required_case_ids.add(case_id)
    manifest = BaselineManifest(
        schema_version=3,
        capture_mode="synthetic-index-staged-recovery",
        audit=GitSourceIdentity(
            commit=policy.audit_commit,
            tree=policy.audit_tree,
            src_tree=policy.audit_src_tree,
        ),
        recovery=RecoveryIdentity(
            base_commit=policy.base_commit,
            base_tree=policy.base_tree,
            imported_index_tree=policy.index_transition.imported_index_tree,
        ),
        index_transition=policy.index_transition,
        input=collected.identity,
        generator=collected.generator,
        canonicalization="nplg-json-sort-utf8-lf-v1",
        response_canonicalization=RESPONSE_NUMBER_CANONICALIZATION,
        entries=tuple(
            BaselineEntry(
                path=name,
                sha256=hashlib.sha256(fixture_bytes[name]).hexdigest(),
            )
            for name in BASELINE_FILES
        ),
        required_tool_names=tuple(sorted(EXPECTED_TOOL_NAMES)),
        required_case_ids=tuple(sorted(required_case_ids)),
        release_eligible=False,
        release_blockers=("BASELINE_CAPTURE_NOT_COMMIT_REACHABLE",),
    )
    outputs: dict[str, bytes] = {}
    for name in BASELINE_FILES:
        outputs[name] = fixture_bytes[name]
    outputs[BASELINE_MANIFEST_FILE] = canonical_json_bytes(
        cast("object", manifest.model_dump(mode="json")),
    )
    return outputs


def run_capture_mode(
    repository: Path,
    *,
    policy: CapturePolicy,
    write: bool,
    collector: FixtureCollector | None = None,
) -> None:
    """Generate in memory, then either compare exact bytes or publish once."""
    repository = repository.absolute()
    active_collector = (
        capture_from_materialized_root if collector is None else collector
    )
    collected = collect_from_synthetic_input(
        repository,
        policy=policy,
        persist_objects=write,
        collector=active_collector,
    )
    outputs = _build_output_bytes(collected, policy=policy)
    baseline_root = repository / "contracts" / "baseline"
    if write:
        publish_output_bytes(baseline_root, outputs)
        return
    _ = validate_baseline_directory(baseline_root)
    for name in BASELINE_DIRECTORY_FILES:
        if read_regular_bytes(baseline_root / name) != outputs[name]:
            msg = f"frozen baseline differs from generated bytes: {name}"
            raise BaselineCaptureError(msg)


def capture_from_materialized_root(
    materialized_root: Path,
) -> dict[BaselineFileName, dict[str, object]]:
    """Run the tree-bound generator in a fresh Python child and parse its output."""
    materialized_root = materialized_root.absolute()
    root_stat = materialized_root.lstat()
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or materialized_root.resolve() != materialized_root
    ):
        msg = "materialized capture root must be an absolute non-symlink directory"
        raise BaselineCaptureError(msg)
    script = materialized_root / "scripts" / "capture_baseline.py"
    script_stat = script.lstat()
    if not stat.S_ISREG(script_stat.st_mode):
        msg = "materialized capture generator must be a regular file"
        raise BaselineCaptureError(msg)
    replay_script = materialized_root / "scripts" / "baseline_replay.py"
    if not stat.S_ISREG(replay_script.lstat().st_mode):
        msg = "materialized replay generator must be a regular file"
        raise BaselineCaptureError(msg)
    executable = Path(sys.executable).absolute()
    if not executable.is_absolute() or not executable.is_file():
        msg = "capture requires an absolute current Python executable"
        raise BaselineCaptureError(msg)
    with tempfile.TemporaryDirectory(prefix="nplg-baseline-child-") as temporary:
        exchange_root = Path(temporary)
        exchange_root.chmod(0o700)
        output = (exchange_root / "capture.json").absolute()
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": os.pathsep.join(
                (str(materialized_root / "src"), str(materialized_root)),
            ),
        }
        completed = baseline_capture_io.run_bounded_process(
            (
                str(executable),
                "-P",
                "-m",
                "scripts.baseline_replay",
                "--internal-output",
                str(output),
            ),
            cwd=materialized_root,
            environment=environment,
            limits=baseline_capture_io.ProcessLimits(
                timeout_seconds=60,
                stdout_bytes=MAX_GIT_STDERR_BYTES,
                stderr_bytes=MAX_GIT_STDERR_BYTES,
            ),
        )
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            msg = "materialized baseline capture child failed"
            raise BaselineCaptureError(msg)
        raw_values = require_string_object(
            load_canonical_json(output),
            context="materialized capture output",
        )
    if set(raw_values) != set(BASELINE_FILES):
        msg = "materialized capture returned an unknown or missing fixture"
        raise BaselineCaptureError(msg)
    fixtures: dict[BaselineFileName, dict[str, object]] = {}
    for name in BASELINE_FILES:
        fixtures[name] = require_string_object(
            raw_values[name],
            context=f"materialized {name}",
        )
    return fixtures


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.capture_baseline",
        description="Capture or verify the provenance-bound MCP baseline.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    _ = mode.add_argument(
        "--check",
        action="store_true",
        help="verify exact fixture bytes",
    )
    _ = mode.add_argument(
        "--write", action="store_true", help="publish regenerated fixtures"
    )
    return parser


class _Arguments(argparse.Namespace):
    check: bool = False
    write: bool = False


def main(argv: Sequence[str] | None = None) -> int:
    """Run one explicit capture mode."""
    arguments = cast("_Arguments", _argument_parser().parse_args(argv))
    try:
        repository = Path(__file__).resolve().parents[1]
        run_capture_mode(
            repository,
            policy=DEFAULT_CAPTURE_POLICY,
            write=arguments.write,
        )
    except BaselineCaptureError as exc:
        _ = os.write(2, f"baseline capture failed: {exc}\n".encode())
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
