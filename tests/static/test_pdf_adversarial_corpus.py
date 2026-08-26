# Copyright (c) 2026 David Osipov
"""Fail-closed integrity tests for the checked-in synthetic PDF corpus."""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from pydantic import ValidationError

from nplg_mcp.json_types import (
    JsonObject,
    JsonValue,
    dump_json,
    load_json_value,
    require_json_object,
)
from tests.helpers.pdf_adversarial_corpus import (
    MAX_FIXTURE_BYTES,
    FixtureCaseId,
    build_fixture_bytes,
    load_and_validate_corpus,
)

if TYPE_CHECKING:
    from collections.abc import Callable


ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = ROOT / "tests" / "fixtures" / "pdf" / "adversarial"
EXPECTED_CASES = {
    "concurrency-reuse": "concurrency_reuse",
    "crash-marker": "crash_marker",
    "declared-huge-page": "declared_huge_page",
    "encrypted": "encrypted",
    "malformed": "malformed",
    "nested-high-object": "nested_high_object",
    "timeout-marker": "timeout_marker",
    "truncated": "truncated",
}


def _copy_corpus(tmp_path: Path) -> Path:
    destination = tmp_path / "corpus"
    return Path(shutil.copytree(CORPUS_ROOT, destination))


def _manifest_payload(root: Path) -> JsonObject:
    return require_json_object(
        load_json_value((root / "manifest.json").read_bytes()),
        context="PDF adversarial corpus manifest fixture",
    )


def _manifest_entries(payload: JsonObject) -> list[JsonValue]:
    entries = payload["entries"]
    if not isinstance(entries, list):
        message = "PDF adversarial corpus entries must be a JSON array"
        raise TypeError(message)
    return entries


def _entry(payload: JsonObject, index: int = 0) -> JsonObject:
    return require_json_object(
        _manifest_entries(payload)[index],
        context="PDF adversarial corpus entry fixture",
    )


def _write_manifest(root: Path, payload: JsonObject) -> None:
    _ = (root / "manifest.json").write_text(
        f"{dump_json(payload, sort_keys=True)}\n",
        encoding="utf-8",
    )


def _add_unlisted_file(root: Path, _fixture: Path) -> None:
    _ = (root / "cases" / "unlisted.pdf").write_bytes(b"%PDF-1.7\n%%EOF\n")


def _remove_fixture(_root: Path, fixture: Path) -> None:
    fixture.unlink()


def _tamper_fixture(_root: Path, fixture: Path) -> None:
    original = fixture.read_bytes()
    _ = fixture.write_bytes(bytes([original[0] ^ 1]) + original[1:])


def _replace_fixture_with_symlink(root: Path, fixture: Path) -> None:
    fixture.unlink()
    fixture.symlink_to(root / "LICENSE.txt")


def _remove_manifest(root: Path) -> None:
    (root / "manifest.json").unlink()


def _oversize_manifest(root: Path) -> None:
    _ = (root / "manifest.json").write_bytes(b" " * (MAX_FIXTURE_BYTES + 1))


def _replace_manifest_with_fifo(root: Path) -> None:
    manifest = root / "manifest.json"
    manifest.unlink()
    os.mkfifo(manifest)


def _add_empty_directory(root: Path) -> None:
    (root / "unlisted-directory").mkdir()


def _add_special_file(root: Path) -> None:
    os.mkfifo(root / "cases" / "unlisted-fifo")


def _mutate_top_level_unknown(payload: JsonObject) -> None:
    payload["unexpected"] = True


def _mutate_entry_unknown(payload: JsonObject) -> None:
    _entry(payload)["unexpected"] = True


def _mutate_coerced_size(payload: JsonObject) -> None:
    first = _entry(payload)
    first["size_bytes"] = str(first["size_bytes"])


def _mutate_coerced_deterministic(payload: JsonObject) -> None:
    generator = require_json_object(
        payload["generator"], context="PDF corpus generator fixture"
    )
    generator["deterministic"] = "true"


def _mutate_duplicate_case(payload: JsonObject) -> None:
    _entry(payload, 1)["case_id"] = _entry(payload)["case_id"]


def _mutate_duplicate_entry(payload: JsonObject) -> None:
    _manifest_entries(payload)[1] = _entry(payload).copy()


def _mutate_duplicate_path(payload: JsonObject) -> None:
    _entry(payload, 1)["relative_path"] = _entry(payload)["relative_path"]


def _mutate_duplicate_digest(payload: JsonObject) -> None:
    _entry(payload, 1)["sha256"] = _entry(payload)["sha256"]


def _mutate_wrong_behavior(payload: JsonObject) -> None:
    _entry(payload)["expected_behavior"] = "inert_test_marker"


def _mutate_path_traversal(payload: JsonObject) -> None:
    _entry(payload)["relative_path"] = "cases/../malformed.pdf"


def _mutate_oversized_fixture(payload: JsonObject) -> None:
    _entry(payload)["size_bytes"] = MAX_FIXTURE_BYTES + 1


def test_checked_in_pdf_adversarial_corpus_is_complete_and_reproducible() -> None:
    manifest = load_and_validate_corpus(CORPUS_ROOT)

    assert manifest.schema_version == "1.0"
    assert manifest.license.spdx_identifier == "CC0-1.0"
    assert manifest.generator.deterministic is True
    assert manifest.generator.contains_third_party_documents is False
    assert {
        entry.case_id: entry.category for entry in manifest.entries
    } == EXPECTED_CASES

    for entry in manifest.entries:
        fixture = CORPUS_ROOT / entry.relative_path
        observed = fixture.read_bytes()
        assert observed == build_fixture_bytes(entry.case_id)
        assert len(observed) == entry.size_bytes
        assert len(observed) <= MAX_FIXTURE_BYTES
        assert hashlib.sha256(observed).hexdigest() == entry.sha256


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(_mutate_top_level_unknown, id="unknown-top-level-field"),
        pytest.param(_mutate_entry_unknown, id="unknown-entry-field"),
        pytest.param(_mutate_coerced_size, id="strict-size-type"),
        pytest.param(_mutate_coerced_deterministic, id="strict-boolean-type"),
        pytest.param(_mutate_duplicate_case, id="duplicate-case-id"),
        pytest.param(_mutate_duplicate_entry, id="duplicate-complete-entry"),
        pytest.param(_mutate_duplicate_path, id="duplicate-relative-path"),
        pytest.param(_mutate_duplicate_digest, id="duplicate-content-digest"),
        pytest.param(_mutate_wrong_behavior, id="case-behavior-mismatch"),
        pytest.param(_mutate_path_traversal, id="noncanonical-relative-path"),
        pytest.param(_mutate_oversized_fixture, id="fixture-size-above-bound"),
    ],
)
def test_manifest_schema_rejects_unknown_coerced_or_duplicate_values(
    tmp_path: Path,
    mutate: Callable[[JsonObject], None],
) -> None:
    root = _copy_corpus(tmp_path)
    payload = _manifest_payload(root)
    mutate(payload)
    _write_manifest(root, payload)

    with pytest.raises(ValidationError):
        _ = load_and_validate_corpus(root)


def test_manifest_rejects_duplicate_raw_json_object_keys(tmp_path: Path) -> None:
    root = _copy_corpus(tmp_path)
    manifest_path = root / "manifest.json"
    original = manifest_path.read_text(encoding="utf-8")
    duplicate = original.replace(
        '  "schema_version": "1.0",',
        '  "schema_version": "1.0",\n  "schema_version": "1.0",',
        1,
    )
    assert duplicate != original
    _ = manifest_path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON object field"):
        _ = load_and_validate_corpus(root)


def test_generator_rejects_unknown_case_without_emitting_bytes() -> None:
    unknown = cast("FixtureCaseId", "unknown-case")

    with pytest.raises(ValueError, match="fixture case is not implemented"):
        _ = build_fixture_bytes(unknown)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        pytest.param(_remove_manifest, "not a readable", id="missing-manifest"),
        pytest.param(_oversize_manifest, "exceeds its byte bound", id="oversized"),
        pytest.param(_replace_manifest_with_fifo, "not a regular file", id="fifo"),
    ],
)
def test_manifest_file_must_be_present_regular_and_bounded(
    tmp_path: Path,
    mutate: Callable[[Path], None],
    message: str,
) -> None:
    root = _copy_corpus(tmp_path)
    mutate(root)

    with pytest.raises(ValueError, match=message):
        _ = load_and_validate_corpus(root)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(_add_empty_directory, id="unlisted-directory"),
        pytest.param(_add_special_file, id="special-file"),
    ],
)
def test_corpus_inventory_rejects_unlisted_directory_or_special_file(
    tmp_path: Path,
    mutate: Callable[[Path], None],
) -> None:
    root = _copy_corpus(tmp_path)
    mutate(root)

    with pytest.raises(ValueError, match="corpus inventory"):
        _ = load_and_validate_corpus(root)


@pytest.mark.parametrize(
    ("target", "message"),
    [
        pytest.param("license-size", "license size", id="license-size"),
        pytest.param("license-digest", "SHA-256", id="license-digest"),
        pytest.param("fixture-size", "corpus size", id="fixture-size"),
    ],
)
def test_manifest_metadata_must_match_checked_in_byte_counts_and_digests(
    tmp_path: Path,
    target: str,
    message: str,
) -> None:
    root = _copy_corpus(tmp_path)
    payload = _manifest_payload(root)
    if target.startswith("license-"):
        record = require_json_object(
            payload["license"], context="PDF corpus license fixture"
        )
    else:
        record = _entry(payload)
    if target.endswith("-size"):
        size = record["size_bytes"]
        assert isinstance(size, int)
        assert not isinstance(size, bool)
        record["size_bytes"] = size + 1
    else:
        record["sha256"] = "0" * 64
    _write_manifest(root, payload)

    with pytest.raises(ValueError, match=message):
        _ = load_and_validate_corpus(root)


def test_corpus_root_rejects_missing_and_symlink_directories(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    linked = tmp_path / "linked"
    linked.symlink_to(CORPUS_ROOT, target_is_directory=True)

    for root in (missing, linked):
        with pytest.raises(ValueError, match="corpus root"):
            _ = load_and_validate_corpus(root)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(_add_unlisted_file, id="unlisted-file"),
        pytest.param(_remove_fixture, id="missing-file"),
        pytest.param(_tamper_fixture, id="digest-mismatch"),
        pytest.param(_replace_fixture_with_symlink, id="symlink"),
    ],
)
def test_corpus_inventory_rejects_unlisted_missing_symlink_or_tampered_files(
    tmp_path: Path,
    mutate: Callable[[Path, Path], object],
) -> None:
    root = _copy_corpus(tmp_path)
    first = load_and_validate_corpus(root).entries[0]
    fixture = root / first.relative_path
    _ = mutate(root, fixture)

    with pytest.raises(ValueError, match=r"corpus (?:inventory|SHA-256)"):
        _ = load_and_validate_corpus(root)


def test_generator_provenance_rejects_rehashed_substitute_content(
    tmp_path: Path,
) -> None:
    root = _copy_corpus(tmp_path)
    payload = _manifest_payload(root)
    first = _entry(payload)
    relative_path = first["relative_path"]
    assert isinstance(relative_path, str)
    fixture = root / relative_path
    substitute = fixture.read_bytes() + b"% substituted but safely bounded\n"
    _ = fixture.write_bytes(substitute)
    first["size_bytes"] = len(substitute)
    first["sha256"] = hashlib.sha256(substitute).hexdigest()
    _write_manifest(root, payload)

    with pytest.raises(ValueError, match="deterministic generator"):
        _ = load_and_validate_corpus(root)
