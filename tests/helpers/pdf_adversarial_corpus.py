# Copyright (c) 2026 David Osipov
"""Strict manifest and deterministic bytes for the synthetic PDF corpus."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from nplg_mcp.json_types import JsonObject, is_json_value, load_json_value

MAX_FIXTURE_BYTES = 65_536
_MAX_MANIFEST_BYTES = 65_536
_MAX_LICENSE_BYTES = 4_096
_RELATIVE_PATH_PARTS = 2
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_RELATIVE_PATH_PATTERN = r"^cases/[a-z][a-z0-9-]*\.pdf$"

type FixtureCaseId = Literal[
    "concurrency-reuse",
    "crash-marker",
    "declared-huge-page",
    "encrypted",
    "malformed",
    "nested-high-object",
    "timeout-marker",
    "truncated",
]
type FixtureCategory = Literal[
    "concurrency_reuse",
    "crash_marker",
    "declared_huge_page",
    "encrypted",
    "malformed",
    "nested_high_object",
    "timeout_marker",
    "truncated",
]
type ExpectedBehavior = Literal[
    "accept_bounded_metadata",
    "inert_test_marker",
    "reject_invalid_document",
    "reuse_without_mutation",
]
type Sha256 = Annotated[
    str,
    StringConstraints(strict=True, pattern=_SHA256_PATTERN),
]
type CaseId = FixtureCaseId
type RelativeFixturePath = Annotated[
    str,
    StringConstraints(strict=True, pattern=_RELATIVE_PATH_PATTERN),
]
type FixtureSize = Annotated[int, Field(strict=True, gt=0, le=MAX_FIXTURE_BYTES)]

_EXPECTED_CATEGORIES: dict[FixtureCaseId, FixtureCategory] = {
    "concurrency-reuse": "concurrency_reuse",
    "crash-marker": "crash_marker",
    "declared-huge-page": "declared_huge_page",
    "encrypted": "encrypted",
    "malformed": "malformed",
    "nested-high-object": "nested_high_object",
    "timeout-marker": "timeout_marker",
    "truncated": "truncated",
}
_EXPECTED_BEHAVIORS: dict[FixtureCaseId, ExpectedBehavior] = {
    "concurrency-reuse": "reuse_without_mutation",
    "crash-marker": "inert_test_marker",
    "declared-huge-page": "accept_bounded_metadata",
    "encrypted": "reject_invalid_document",
    "malformed": "reject_invalid_document",
    "nested-high-object": "accept_bounded_metadata",
    "timeout-marker": "inert_test_marker",
    "truncated": "reject_invalid_document",
}


class _StrictManifestModel(BaseModel):
    """Immutable Pydantic base with coercion and extension fields disabled."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class CorpusLicense(_StrictManifestModel):
    """Redistribution license bound to its checked-in notice bytes."""

    spdx_identifier: Literal["CC0-1.0"]
    document_path: Literal["LICENSE.txt"]
    sha256: Sha256
    size_bytes: Annotated[int, Field(strict=True, gt=0, le=_MAX_LICENSE_BYTES)]


class CorpusGenerator(_StrictManifestModel):
    """Repository-owned generator provenance for every synthetic document."""

    name: Literal["nplg-pdf-adversarial-corpus"]
    implementation_path: Literal["tests/helpers/pdf_adversarial_corpus.py"]
    callable: Literal["build_fixture_bytes"]
    version: Literal["1"]
    deterministic: Literal[True]
    contains_third_party_documents: Literal[False]
    source_statement: Literal[
        "Repository-authored synthetic bytes; no third-party documents or payloads."
    ]


class CorpusEntry(_StrictManifestModel):
    """One content-addressed, size-bounded adversarial PDF case."""

    case_id: CaseId
    category: FixtureCategory
    relative_path: RelativeFixturePath
    media_type: Literal["application/pdf"]
    sha256: Sha256
    size_bytes: FixtureSize
    expected_behavior: ExpectedBehavior
    description: Annotated[
        str,
        StringConstraints(strict=True, min_length=12, max_length=240),
    ]

    @field_validator("relative_path")
    @classmethod
    def _require_canonical_relative_path(cls, value: str) -> str:
        relative = PurePosixPath(value)
        if (
            relative.is_absolute()
            or relative.as_posix() != value
            or len(relative.parts) != _RELATIVE_PATH_PARTS
            or relative.parts[0] != "cases"
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            message = "relative_path must be one canonical file below cases/"
            raise ValueError(message)
        return value

    @model_validator(mode="after")
    def _require_case_semantics(self) -> Self:
        if self.category != _EXPECTED_CATEGORIES[self.case_id]:
            message = "category does not match case_id"
            raise ValueError(message)
        if self.expected_behavior != _EXPECTED_BEHAVIORS[self.case_id]:
            message = "expected_behavior does not match case_id"
            raise ValueError(message)
        if self.relative_path != f"cases/{self.case_id}.pdf":
            message = "relative_path does not match case_id"
            raise ValueError(message)
        return self


class CorpusManifest(_StrictManifestModel):
    """Closed manifest for the complete checked-in adversarial corpus."""

    schema_version: Literal["1.0"]
    corpus_id: Literal["nplg-pdf-adversarial-synthetic"]
    max_fixture_bytes: Literal[65_536]
    license: CorpusLicense
    generator: CorpusGenerator
    entries: Annotated[tuple[CorpusEntry, ...], Field(min_length=8, max_length=8)]

    @model_validator(mode="after")
    def _require_complete_unique_inventory(self) -> Self:
        case_ids = tuple(entry.case_id for entry in self.entries)
        paths = tuple(entry.relative_path for entry in self.entries)
        digests = tuple(entry.sha256 for entry in self.entries)
        if len(set(case_ids)) != len(case_ids):
            message = "corpus case_id values must be unique"
            raise ValueError(message)
        if len(set(paths)) != len(paths):
            message = "corpus relative_path values must be unique"
            raise ValueError(message)
        if len(set(digests)) != len(digests):
            message = "corpus SHA-256 values must be unique"
            raise ValueError(message)
        if set(case_ids) != set(_EXPECTED_CATEGORIES):
            message = "corpus must contain every required adversarial case exactly once"
            raise ValueError(message)
        return self


def _serialize_pdf(
    objects: tuple[bytes, ...],
    *,
    trailer_entries: bytes = b"",
) -> bytes:
    header = b"%PDF-1.7\n% NPLG repository-authored synthetic fixture\n"
    parts = [header]
    offsets = [0]
    length = len(header)
    for object_number, body in enumerate(objects, start=1):
        offsets.append(length)
        framed = f"{object_number} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
        parts.append(framed)
        length += len(framed)
    xref_offset = length
    xref = [f"xref\n0 {len(objects) + 1}\n".encode("ascii"), b"0000000000 65535 f \n"]
    xref.extend(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets[1:])
    trailer = (
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode("ascii")
        + b" /Root 1 0 R"
        + trailer_entries
        + b" >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return b"".join((*parts, *xref, trailer))


def _stream(marker: str) -> bytes:
    payload = f"% {marker}\n".encode("ascii")
    return (
        b"<< /Length "
        + str(len(payload)).encode("ascii")
        + b" >>\nstream\n"
        + payload
        + b"endstream"
    )


def _basic_pdf(
    marker: str,
    *,
    media_box: tuple[int, int, int, int] = (0, 0, 72, 72),
) -> bytes:
    coordinates = " ".join(str(value) for value in media_box).encode("ascii")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox ["
        + coordinates
        + b"] /Resources << >> /Contents 4 0 R >>",
        _stream(marker),
        b"<< /Producer (NPLG synthetic corpus) /Subject ("
        + marker.encode("ascii")
        + b") >>",
    )
    return _serialize_pdf(objects, trailer_entries=b" /Info 5 0 R")


def _nested_high_object_pdf() -> bytes:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] "
            b"/Resources << >> /Contents 4 0 R /NplgNested 5 0 R >>"
        ),
        _stream("NPLG_SYNTHETIC_NESTED_HIGH_OBJECT"),
    ]
    final_object_number = 64
    for object_number in range(5, final_object_number + 1):
        next_reference = (
            f" /Next {object_number + 1} 0 R".encode("ascii")
            if object_number < final_object_number
            else b""
        )
        objects.append(
            b"<< /Depth "
            + str(object_number - 4).encode("ascii")
            + next_reference
            + b" /Payload [0 [1 [2 [3 [4]]]]] >>"
        )
    return _serialize_pdf(tuple(objects))


def _encrypted_pdf() -> bytes:
    owner = b"0" * 64
    user = b"1" * 64
    identifier = b"4e504c4753594e54484554494346495854555245"
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] "
            b"/Resources << >> /Contents 4 0 R >>"
        ),
        _stream("NPLG_SYNTHETIC_ENCRYPTED"),
        (
            b"<< /Filter /Standard /V 1 /R 2 /Length 128 /O <"
            + owner
            + b"> /U <"
            + user
            + b"> /P -4 >>"
        ),
    )
    return _serialize_pdf(
        objects,
        trailer_entries=(
            b" /Encrypt 5 0 R /ID [<" + identifier + b"> <" + identifier + b">]"
        ),
    )


def build_fixture_bytes(case_id: FixtureCaseId) -> bytes:
    """Build exactly one bounded, harmless synthetic adversarial document."""
    payload = b""
    match case_id:
        case "concurrency-reuse":
            payload = _basic_pdf("NPLG_SYNTHETIC_CONCURRENCY_REUSE")
        case "crash-marker":
            payload = _basic_pdf("NPLG_SYNTHETIC_CRASH_MARKER_INERT")
        case "declared-huge-page":
            payload = _basic_pdf(
                "NPLG_SYNTHETIC_DECLARED_HUGE_PAGE",
                media_box=(0, 0, 1_000_000, 1_000_000),
            )
        case "encrypted":
            payload = _encrypted_pdf()
        case "malformed":
            payload = (
                b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 99 0 R >>\n"
                b"endobj\nstartxref\nnot-an-offset\n%%EOF\n"
            )
        case "nested-high-object":
            payload = _nested_high_object_pdf()
        case "timeout-marker":
            payload = _basic_pdf("NPLG_SYNTHETIC_TIMEOUT_MARKER_INERT")
        case "truncated":
            payload = _basic_pdf("NPLG_SYNTHETIC_TRUNCATED")[:160]
    if not payload:
        message = "fixture case is not implemented"
        raise ValueError(message)
    return payload


def _read_bounded_regular_file(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        message = f"corpus path is not a readable non-symlink file: {path.name}"
        raise ValueError(message) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            message = f"corpus path is not a regular file: {path.name}"
            raise ValueError(message)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(payload) > maximum:
        message = f"corpus file exceeds its byte bound: {path.name}"
        raise ValueError(message)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(payload) != after.st_size
    ):
        message = f"corpus file changed while it was read: {path.name}"
        raise ValueError(message)
    return payload


def _require_exact_inventory(root: Path, manifest: CorpusManifest) -> None:
    expected_files = {
        "manifest.json",
        manifest.license.document_path,
        *(entry.relative_path for entry in manifest.entries),
    }
    expected_directories = {
        PurePosixPath(relative).parent.as_posix()
        for relative in expected_files
        if PurePosixPath(relative).parent.as_posix() != "."
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        if candidate.is_symlink():
            message = f"corpus inventory contains a symlink: {relative}"
            raise ValueError(message)
        if candidate.is_dir():
            observed_directories.add(relative)
        elif candidate.is_file():
            observed_files.add(relative)
        else:
            message = f"corpus inventory contains a special file: {relative}"
            raise ValueError(message)
    if observed_files != expected_files:
        message = "corpus inventory contains unlisted or missing files"
        raise ValueError(message)
    if observed_directories != expected_directories:
        message = "corpus inventory contains unlisted or missing directories"
        raise ValueError(message)


def _require_digest(payload: bytes, *, expected: str, label: str) -> None:
    if hashlib.sha256(payload).hexdigest() != expected:
        message = f"corpus SHA-256 mismatch for {label}"
        raise ValueError(message)


def _strict_model_from_json[T: BaseModel](model: type[T], payload: bytes) -> T:
    return model.model_validate_json(payload, strict=True)


def _unique_json_object(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            message = f"duplicate JSON object field: {key}"
            raise ValueError(message)
        if not is_json_value(value):
            message = f"non-JSON value for object field: {key}"
            raise TypeError(message)
        result[key] = value
    return result


def load_and_validate_corpus(root: Path) -> CorpusManifest:
    """Load the corpus with strict schema, inventory, and byte provenance checks."""
    if root.is_symlink() or not root.is_dir():
        message = "PDF adversarial corpus root must be a non-symlink directory"
        raise ValueError(message)
    manifest_bytes = _read_bounded_regular_file(
        root / "manifest.json",
        maximum=_MAX_MANIFEST_BYTES,
    )
    _ = load_json_value(manifest_bytes, object_pairs_hook=_unique_json_object)
    manifest = _strict_model_from_json(CorpusManifest, manifest_bytes)
    _require_exact_inventory(root, manifest)

    license_bytes = _read_bounded_regular_file(
        root / manifest.license.document_path,
        maximum=_MAX_LICENSE_BYTES,
    )
    if len(license_bytes) != manifest.license.size_bytes:
        message = "corpus license size does not match its manifest"
        raise ValueError(message)
    _require_digest(
        license_bytes,
        expected=manifest.license.sha256,
        label=manifest.license.document_path,
    )

    for entry in manifest.entries:
        payload = _read_bounded_regular_file(
            root / entry.relative_path,
            maximum=manifest.max_fixture_bytes,
        )
        if len(payload) != entry.size_bytes:
            message = f"corpus size does not match its manifest: {entry.case_id}"
            raise ValueError(message)
        _require_digest(payload, expected=entry.sha256, label=entry.case_id)
        if payload != build_fixture_bytes(entry.case_id):
            message = (
                "corpus bytes do not match the deterministic generator: "
                f"{entry.case_id}"
            )
            raise ValueError(message)
    return manifest
