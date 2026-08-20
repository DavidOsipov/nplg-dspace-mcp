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
from typing import TYPE_CHECKING, Annotated, Final, Literal, cast

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
BASELINE_FAILURE_STATUS: Final = 2
COMMITTED_MANIFEST_SCHEMA_VERSION: Final = 4
SINGLE_PARENT_RECORD_FIELDS: Final = 2
HISTORICAL_MANIFEST_FILE: Literal["historical-manifest-v3.json"] = (
    "historical-manifest-v3.json"
)
COMMITTED_BASELINE_DIRECTORY_FILES = (
    *BASELINE_FILES,
    HISTORICAL_MANIFEST_FILE,
    BASELINE_MANIFEST_FILE,
)
MANIFEST_REPOSITORY_PATH: Literal["contracts/baseline/manifest.json"] = (
    "contracts/baseline/manifest.json"
)
HISTORICAL_MANIFEST_REPOSITORY_PATH: Literal[
    "contracts/baseline/historical-manifest-v3.json"
] = "contracts/baseline/historical-manifest-v3.json"
ATTESTATION_PATHS: tuple[
    Literal["contracts/baseline/manifest.json"],
    Literal["contracts/baseline/historical-manifest-v3.json"],
] = (
    MANIFEST_REPOSITORY_PATH,
    HISTORICAL_MANIFEST_REPOSITORY_PATH,
)
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


class HistoricalManifestIdentity(_BaselineModel):
    """Digest identity for the archived one-time recovery manifest."""

    path: Literal["historical-manifest-v3.json"]
    schema_version: Literal[3]
    sha256: HexDigest


class AttestationPolicy(_BaselineModel):
    """Closed rule for the commit that attests the clean candidate."""

    scheme: Literal["current-head-single-parent-manifest-delta-v1"]
    allowed_paths: tuple[
        Literal["contracts/baseline/manifest.json"],
        Literal["contracts/baseline/historical-manifest-v3.json"],
    ]


class CommittedBaselineManifest(_BaselineModel):
    """Small digest manifest for a clean committed candidate."""

    schema_version: Literal[4]
    capture_mode: Literal["committed-candidate-attestation"]
    candidate: GitSourceIdentity
    historical_provenance: HistoricalManifestIdentity
    attestation: AttestationPolicy
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


def _load_committed_manifest(root: Path) -> CommittedBaselineManifest:
    manifest_value = load_canonical_json(root / BASELINE_MANIFEST_FILE)
    try:
        return CommittedBaselineManifest.model_validate_json(
            canonical_json_bytes(manifest_value),
            strict=True,
        )
    except ValidationError as exc:
        msg = "baseline manifest does not satisfy the closed v4 schema"
        raise BaselineCaptureError(msg) from exc


def _load_historical_manifest(root: Path) -> BaselineManifest:
    manifest_value = load_canonical_json(root / HISTORICAL_MANIFEST_FILE)
    try:
        return BaselineManifest.model_validate_json(
            canonical_json_bytes(manifest_value),
            strict=True,
        )
    except ValidationError as exc:
        msg = "historical baseline manifest does not satisfy the closed v3 schema"
        raise BaselineCaptureError(msg) from exc


def _validate_historical_bundle(
    root: Path,
    loaded: Mapping[BaselineFileName, Mapping[str, object]],
) -> tuple[BaselineManifest, set[str]]:
    historical = _load_historical_manifest(root)
    _validate_manifest_input(historical)
    _validate_manifest_allocation(historical, loaded)
    captured_case_ids = _captured_case_ids(loaded)
    if captured_case_ids != set(historical.required_case_ids):
        msg = "historical baseline case inventory does not match the manifest"
        raise BaselineCaptureError(msg)
    _validate_manifest_digests(root, historical)
    return historical, captured_case_ids


def _validate_committed_allocation(
    manifest: CommittedBaselineManifest,
    historical: BaselineManifest,
    captured_case_ids: set[str],
) -> None:
    entry_paths = tuple(entry.path for entry in manifest.entries)
    if entry_paths != BASELINE_FILES or len(set(entry_paths)) != len(entry_paths):
        msg = "committed baseline entries must name the four fixtures exactly once"
        raise BaselineCaptureError(msg)
    if manifest.required_tool_names != tuple(sorted(EXPECTED_TOOL_NAMES)):
        msg = "committed baseline tool inventory is incomplete or reordered"
        raise BaselineCaptureError(msg)
    if manifest.required_case_ids != tuple(sorted(captured_case_ids)):
        msg = "committed baseline case inventory does not match the fixtures"
        raise BaselineCaptureError(msg)
    if manifest.required_case_ids != historical.required_case_ids:
        msg = "committed and historical baseline case inventories differ"
        raise BaselineCaptureError(msg)
    if manifest.attestation.allowed_paths != ATTESTATION_PATHS:
        msg = "committed baseline attestation paths are incomplete or reordered"
        raise BaselineCaptureError(msg)


def validate_committed_baseline_directory(root: Path) -> CommittedBaselineManifest:
    """Validate the closed v4 digest bundle without consulting Git."""
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode):
        msg = f"baseline root must be a directory, not a link or special file: {root}"
        raise BaselineCaptureError(msg)
    actual_names = tuple(sorted(entry.name for entry in root.iterdir()))
    expected_names = tuple(sorted(COMMITTED_BASELINE_DIRECTORY_FILES))
    if actual_names != expected_names:
        msg = "committed baseline directory has an unknown or missing file"
        raise BaselineCaptureError(msg)
    loaded = _load_baseline_files(root)
    historical, captured_case_ids = _validate_historical_bundle(root, loaded)
    manifest = _load_committed_manifest(root)
    _validate_committed_allocation(manifest, historical, captured_case_ids)
    historical_raw = read_regular_bytes(root / HISTORICAL_MANIFEST_FILE)
    if hashlib.sha256(historical_raw).hexdigest() != (
        manifest.historical_provenance.sha256
    ):
        msg = "historical baseline manifest digest mismatch"
        raise BaselineCaptureError(msg)
    for entry in manifest.entries:
        digest = hashlib.sha256(read_regular_bytes(root / entry.path)).hexdigest()
        if digest != entry.sha256:
            msg = f"committed baseline fixture digest mismatch: {entry.path}"
            raise BaselineCaptureError(msg)
    return manifest


def _require_repository(repository: Path) -> Path:
    absolute = repository.absolute()
    repository_stat = absolute.lstat()
    if not stat.S_ISDIR(repository_stat.st_mode) or absolute.resolve() != absolute:
        msg = "baseline repository must be an absolute non-symlink directory"
        raise BaselineCaptureError(msg)
    return absolute


def _git_source_identity(repository: Path, commit_spec: str) -> GitSourceIdentity:
    try:
        return GitSourceIdentity(
            commit=baseline_capture_io.git_text(
                repository,
                "rev-parse",
                "--verify",
                f"{commit_spec}^{{commit}}",
            ),
            tree=baseline_capture_io.git_text(
                repository,
                "rev-parse",
                "--verify",
                f"{commit_spec}^{{tree}}",
            ),
            src_tree=baseline_capture_io.git_text(
                repository,
                "rev-parse",
                "--verify",
                f"{commit_spec}:src",
            ),
        )
    except ValidationError as exc:
        msg = "Git returned a malformed committed baseline identity"
        raise BaselineCaptureError(msg) from exc


def _require_clean_worktree(repository: Path, *, context: str) -> None:
    status = baseline_capture_io.git_bytes(
        repository,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
    )
    if status:
        msg = f"{context} worktree must be clean"
        raise BaselineCaptureError(msg)


def _build_committed_manifest_bytes(
    root: Path,
    *,
    candidate: GitSourceIdentity,
    historical_raw: bytes,
    historical: BaselineManifest,
) -> bytes:
    manifest = CommittedBaselineManifest(
        schema_version=COMMITTED_MANIFEST_SCHEMA_VERSION,
        capture_mode="committed-candidate-attestation",
        candidate=candidate,
        historical_provenance=HistoricalManifestIdentity(
            path=HISTORICAL_MANIFEST_FILE,
            schema_version=3,
            sha256=hashlib.sha256(historical_raw).hexdigest(),
        ),
        attestation=AttestationPolicy(
            scheme="current-head-single-parent-manifest-delta-v1",
            allowed_paths=ATTESTATION_PATHS,
        ),
        canonicalization="nplg-json-sort-utf8-lf-v1",
        response_canonicalization=RESPONSE_NUMBER_CANONICALIZATION,
        entries=tuple(
            BaselineEntry(
                path=name,
                sha256=hashlib.sha256(read_regular_bytes(root / name)).hexdigest(),
            )
            for name in BASELINE_FILES
        ),
        required_tool_names=historical.required_tool_names,
        required_case_ids=historical.required_case_ids,
    )
    return canonical_json_bytes(cast("object", manifest.model_dump(mode="json")))


def _publish_committed_manifests(
    root: Path,
    *,
    historical_raw: bytes,
    manifest_raw: bytes,
) -> None:
    """Publish only provenance files; never rewrite behavior fixtures."""
    manifest_path = root / BASELINE_MANIFEST_FILE
    historical_path = root / HISTORICAL_MANIFEST_FILE
    manifest_state = manifest_path.lstat()
    if not stat.S_ISREG(manifest_state.st_mode):
        msg = "baseline manifest must be a regular file"
        raise BaselineCaptureError(msg)
    if historical_path.exists() or historical_path.is_symlink():
        msg = "historical baseline manifest already exists"
        raise BaselineCaptureError(msg)
    with tempfile.TemporaryDirectory(
        prefix=".baseline-attestation-",
        dir=root.parent,
    ) as temporary:
        transaction = Path(temporary)
        staged_historical = transaction / HISTORICAL_MANIFEST_FILE
        staged_manifest = transaction / BASELINE_MANIFEST_FILE
        backup_manifest = transaction / "manifest-v3.backup"
        write_staged_file(staged_historical, historical_raw)
        write_staged_file(staged_manifest, manifest_raw)
        write_staged_file(backup_manifest, historical_raw)

        validation = transaction / "validation"
        validation.mkdir(mode=0o700)
        for name in BASELINE_FILES:
            write_staged_file(validation / name, read_regular_bytes(root / name))
        write_staged_file(validation / HISTORICAL_MANIFEST_FILE, historical_raw)
        write_staged_file(validation / BASELINE_MANIFEST_FILE, manifest_raw)
        _ = validate_committed_baseline_directory(validation)

        historical_published = False
        manifest_published = False
        try:
            replace_path(staged_historical, historical_path)
            historical_published = True
            current = manifest_path.lstat()
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_dev != manifest_state.st_dev
                or current.st_ino != manifest_state.st_ino
            ):
                msg = "baseline manifest changed during attestation publication"
                raise BaselineCaptureError(msg)
            replace_path(staged_manifest, manifest_path)
            manifest_published = True
            _ = validate_committed_baseline_directory(root)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            try:
                if manifest_published:
                    replace_path(backup_manifest, manifest_path)
                if historical_published:
                    historical_path.unlink()
            except OSError as rollback_exc:
                msg = "baseline attestation publication rollback failed"
                raise BaselineCaptureError(msg) from rollback_exc
            if isinstance(exc, BaselineCaptureError):
                raise
            msg = "baseline attestation publication failed"
            raise BaselineCaptureError(msg) from exc


def write_committed_candidate_manifest(repository: Path) -> None:
    """Migrate a clean committed v3 candidate to an unattested v4 manifest."""
    repository = _require_repository(repository)
    _require_clean_worktree(repository, context="candidate")
    baseline_root = repository / BASELINE_DIR
    historical = validate_baseline_directory(baseline_root)
    historical_raw = read_regular_bytes(baseline_root / BASELINE_MANIFEST_FILE)
    candidate = _git_source_identity(repository, "HEAD")
    manifest_raw = _build_committed_manifest_bytes(
        baseline_root,
        candidate=candidate,
        historical_raw=historical_raw,
        historical=historical,
    )
    if _git_source_identity(repository, "HEAD") != candidate:
        msg = "candidate commit changed during baseline migration"
        raise BaselineCaptureError(msg)
    _require_clean_worktree(repository, context="candidate")
    _publish_committed_manifests(
        baseline_root,
        historical_raw=historical_raw,
        manifest_raw=manifest_raw,
    )


def _attestation_delta(repository: Path, candidate: str, head: str) -> tuple[str, ...]:
    raw = baseline_capture_io.git_bytes(
        repository,
        (
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-z",
            "-r",
            candidate,
            head,
            "--",
        ),
    )
    if not raw or not raw.endswith(b"\0"):
        msg = "baseline attestation commit has a malformed or empty delta"
        raise BaselineCaptureError(msg)
    try:
        encoded_paths = raw[:-1].split(b"\0")
        paths = tuple(part.decode("utf-8", errors="strict") for part in encoded_paths)
    except UnicodeDecodeError as exc:
        msg = "baseline attestation commit contains a non-UTF-8 path"
        raise BaselineCaptureError(msg) from exc
    return paths


def verify_committed_candidate_attestation(
    repository: Path,
) -> CommittedBaselineManifest:
    """Verify that HEAD only attests the exact clean candidate named by v4."""
    repository = _require_repository(repository)
    baseline_root = repository / BASELINE_DIR
    active_value = require_string_object(
        load_canonical_json(baseline_root / BASELINE_MANIFEST_FILE),
        context="baseline manifest",
    )
    if active_value.get("schema_version") != COMMITTED_MANIFEST_SCHEMA_VERSION:
        msg = "committed baseline attestation required"
        raise BaselineCaptureError(msg)
    manifest = validate_committed_baseline_directory(baseline_root)
    _require_clean_worktree(repository, context="attestation")
    head = _git_source_identity(repository, "HEAD")
    parent_record = baseline_capture_io.git_text(
        repository,
        "rev-list",
        "--parents",
        "-n",
        "1",
        "HEAD",
    ).split()
    if (
        len(parent_record) != SINGLE_PARENT_RECORD_FIELDS
        or parent_record[0] != head.commit
    ):
        msg = "baseline attestation must be the current single-parent commit"
        raise BaselineCaptureError(msg)
    if parent_record[1] != manifest.candidate.commit:
        msg = "baseline attestation parent does not match the committed candidate"
        raise BaselineCaptureError(msg)
    candidate_identity = _git_source_identity(
        repository,
        manifest.candidate.commit,
    )
    if candidate_identity != manifest.candidate:
        msg = "committed baseline candidate identity does not match Git"
        raise BaselineCaptureError(msg)
    paths = _attestation_delta(repository, manifest.candidate.commit, head.commit)
    if MANIFEST_REPOSITORY_PATH not in paths:
        msg = "baseline attestation commit does not update the active manifest"
        raise BaselineCaptureError(msg)
    if len(set(paths)) != len(paths) or not set(paths).issubset(ATTESTATION_PATHS):
        msg = "attestation commit changes an unauthorized path"
        raise BaselineCaptureError(msg)
    if _git_source_identity(repository, "HEAD") != head:
        msg = "baseline attestation commit changed during verification"
        raise BaselineCaptureError(msg)
    _require_clean_worktree(repository, context="attestation")
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
        help="verify the committed candidate attestation and fixture digests",
    )
    _ = mode.add_argument(
        "--write",
        action="store_true",
        help="migrate a clean committed v3 candidate to an unattested v4 manifest",
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
        if arguments.write:
            write_committed_candidate_manifest(repository)
        else:
            _ = verify_committed_candidate_attestation(repository)
    except BaselineCaptureError as exc:
        _ = os.write(2, f"baseline capture failed: {exc}\n".encode())
        return BASELINE_FAILURE_STATUS
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
