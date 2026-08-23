# Copyright (c) 2026 David Osipov
"""Constant-time token hashing and validation helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Annotated, Literal

from annotated_types import Ge, Le
from pydantic import AwareDatetime, StringConstraints, ValidationError, model_validator

from .contracts import StrictModel
from .errors import AppError, ErrorCode
from .json_types import JsonObject, is_json_value, load_json_value, require_json_object

if TYPE_CHECKING:
    from collections.abc import Mapping

HARD_MAX_ASSET_TOKEN_TTL_SECONDS = 86_400
HARD_MAX_CURSOR_TTL_SECONDS = 3_600
DEFAULT_CURSOR_TTL_SECONDS = 900
CURSOR_KEY_ID = "cursor-v1"
_CURSOR_KEY_PURPOSE = b"nplg-mcp:cursor-signing:v1"
_MIN_SIGNING_SECRET_BYTES = 32
_MAX_CURSOR_OFFSET = 10_000_000
_MAX_CURSOR_TOKEN_BYTES = 1_024

BoundedKeyId = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$"
    ),
]
Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
CanonicalHandle = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=65,
        pattern=r"^[1-9][0-9]{0,31}/[1-9][0-9]{0,31}$",
    ),
]
NonNegativeInt = Annotated[int, Ge(0), Le(_MAX_CURSOR_OFFSET)]
PageSize = Annotated[int, Ge(1), Le(50)]


class CursorV1(StrictModel):
    """Strict authenticated continuation context."""

    version: Literal[1]
    key_id: BoundedKeyId
    query_hash: Sha256
    scope_handle: CanonicalHandle | None
    offset: NonNegativeInt
    page_size: PageSize
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def bounded_lifetime(self) -> CursorV1:
        """Require an ordered lifetime within the reviewed cursor ceiling."""
        lifetime = self.expires_at - self.issued_at
        if lifetime <= timedelta(0) or lifetime > timedelta(
            seconds=HARD_MAX_CURSOR_TTL_SECONDS
        ):
            msg = "cursor lifetime is invalid"
            raise ValueError(msg)
        return self


def derive_cursor_signing_key(root_secret: bytes) -> bytes:
    """Derive a purpose-separated cursor key from an application root secret."""
    if type(root_secret) is not bytes or len(root_secret) < _MIN_SIGNING_SECRET_BYTES:
        msg = "cursor root secret must contain at least 32 bytes"
        raise ValueError(msg)
    return hmac.new(root_secret, _CURSOR_KEY_PURPOSE, hashlib.sha256).digest()


def cursor_query_hash(normalized_query: str) -> str:
    """Hash an already-normalized query exactly as canonical UTF-8."""
    if type(normalized_query) is not str or not normalized_query:
        msg = "normalized cursor query must be nonempty"
        raise ValueError(msg)
    return hashlib.sha256(normalized_query.encode("utf-8")).hexdigest()


def _reject_duplicate_cursor_keys(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            msg = "duplicate cursor claim"
            raise ValueError(msg)
        if not is_json_value(value):
            msg = "cursor claim is not a JSON value"
            raise TypeError(msg)
        result[key] = value
    return result


def sign_cursor(secret: bytes, cursor: CursorV1) -> str:
    """Serialize and authenticate one strict cursor with a fixed algorithm."""
    key = derive_cursor_signing_key(secret)
    payload = cursor.model_dump_json().encode("utf-8")
    encoded_payload = _b64encode(payload)
    signature = hmac.new(key, encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64encode(signature)}"


def _require_matching_signature(supplied: bytes, expected: bytes) -> None:
    if not hmac.compare_digest(supplied, expected):
        message = "cursor signature mismatch"
        raise ValueError(message)


def verify_cursor(  # noqa: PLR0913 - explicit authenticated context
    secret: bytes,
    token: str,
    *,
    normalized_query: str,
    scope_handle: str | None,
    page_size: int,
    now: datetime,
) -> CursorV1:
    """Verify authentication, expiry, and every bound pagination context."""
    if (
        type(token) is not str
        or not token
        or len(token.encode("utf-8")) > _MAX_CURSOR_TOKEN_BYTES
    ):
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor is malformed.")
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        supplied_signature = _b64decode(encoded_signature)
        expected_signature = hmac.new(
            derive_cursor_signing_key(secret),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        _require_matching_signature(supplied_signature, expected_signature)
        raw = require_json_object(
            load_json_value(
                _b64decode(encoded_payload),
                object_pairs_hook=_reject_duplicate_cursor_keys,
            ),
            context="cursor payload",
        )
        cursor = CursorV1.model_validate_json(
            json.dumps(
                raw,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (
        AppError,
        UnicodeError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
        ValidationError,
    ) as exc:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor is malformed.") from exc
    if cursor.key_id != CURSOR_KEY_ID or cursor.version != 1:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor version is unsupported.")
    current = now.astimezone(UTC)
    if current < cursor.issued_at or current >= cursor.expires_at:
        raise AppError(ErrorCode.INVALID_INPUT, "Cursor lifetime is invalid.")
    if (
        cursor.query_hash != cursor_query_hash(normalized_query)
        or cursor.scope_handle != scope_handle
        or cursor.page_size != page_size
    ):
        raise AppError(
            ErrorCode.INVALID_INPUT,
            "Cursor does not match the search context.",
        )
    return cursor


@dataclass(frozen=True, slots=True)
class AssetGrant:
    """Validated claims carried by a signed asset token."""

    path: str
    media_type: str
    expires_at: int


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise AppError(
            ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401
        ) from exc


def _validate_path(path: str) -> str:
    if not path or "\\" in path:
        raise AppError(ErrorCode.INVALID_INPUT, "Asset path is invalid.")
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or path in {".", ".."}
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise AppError(ErrorCode.INVALID_INPUT, "Asset path is invalid.")
    normalized = parsed.as_posix()
    if normalized != path:
        raise AppError(ErrorCode.INVALID_INPUT, "Asset path is not canonical.")
    return normalized


def sign_asset_token(
    secret: bytes,
    *,
    path: str,
    media_type: str,
    expires_at: datetime,
) -> str:
    """Sign a canonical asset grant without changing its stable token format."""
    canonical_path = _validate_path(path)
    if expires_at.tzinfo is None:
        raise AppError(ErrorCode.INVALID_INPUT, "Asset expiry must include a timezone.")
    payload = {
        "exp": int(expires_at.astimezone(UTC).timestamp()),
        "media_type": media_type,
        "path": canonical_path,
        "v": 1,
    }
    encoded_payload = _b64encode(
        json.dumps(
            payload,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )
    signature = hmac.new(
        secret, encoded_payload.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{encoded_payload}.{_b64encode(signature)}"


def _validate_asset_claims(payload: Mapping[str, object]) -> tuple[str, str, int]:
    if payload.get("v") != 1:
        msg = "unsupported payload"
        raise ValueError(msg)
    raw_path = payload.get("path")
    raw_media_type = payload.get("media_type")
    raw_expiry = payload.get("exp")
    if (
        not isinstance(raw_path, str)
        or not isinstance(raw_media_type, str)
        or type(raw_expiry) is not int
    ):
        msg = "malformed payload"
        raise ValueError(msg)
    return _validate_path(raw_path), raw_media_type, raw_expiry


def verify_asset_token(
    secret: bytes,
    token: str,
    *,
    max_ttl_seconds: int = HARD_MAX_ASSET_TOKEN_TTL_SECONDS,
    now: datetime | None = None,
) -> AssetGrant:
    """Verify a token in constant time and return its validated claims."""
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
    except ValueError as exc:
        raise AppError(
            ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401
        ) from exc
    supplied_signature = _b64decode(encoded_signature)
    try:
        encoded_payload_bytes = encoded_payload.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AppError(
            ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401
        ) from exc
    expected_signature = hmac.new(
        secret, encoded_payload_bytes, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise AppError(
            ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401
        )
    try:
        payload = require_json_object(
            load_json_value(_b64decode(encoded_payload)),
            context="asset token payload",
        )
        path, media_type, expires_at = _validate_asset_claims(payload)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AppError(
            ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401
        ) from exc
    if type(max_ttl_seconds) is not int or not (
        1 <= max_ttl_seconds <= HARD_MAX_ASSET_TOKEN_TTL_SECONDS
    ):
        msg = (
            "max_ttl_seconds must be an integer between 1 and "
            f"{HARD_MAX_ASSET_TOKEN_TTL_SECONDS}"
        )
        raise ValueError(msg)
    current = now or datetime.now(UTC)
    current_timestamp = int(current.astimezone(UTC).timestamp())
    if current_timestamp >= expires_at:
        raise AppError(
            ErrorCode.UNAUTHORIZED, "The asset token has expired.", http_status=401
        )
    if expires_at - current_timestamp > max_ttl_seconds:
        raise AppError(
            ErrorCode.UNAUTHORIZED,
            "The asset token lifetime is invalid.",
            http_status=401,
        )
    return AssetGrant(path=path, media_type=media_type, expires_at=expires_at)
