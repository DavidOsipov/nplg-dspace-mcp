# Copyright (c) 2026 David Osipov
"""Constant-time token hashing and validation helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from .errors import AppError, ErrorCode
from .json_types import load_json_value, require_json_object

if TYPE_CHECKING:
    from collections.abc import Mapping

HARD_MAX_ASSET_TOKEN_TTL_SECONDS = 86_400


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
