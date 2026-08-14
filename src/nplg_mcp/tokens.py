from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath

from .errors import AppError, ErrorCode


@dataclass(frozen=True, slots=True)
class AssetGrant:
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
    except (ValueError, base64.binascii.Error) as exc:
        raise AppError(ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401) from exc


def _validate_path(path: str) -> str:
    if not path or "\\" in path:
        raise AppError(ErrorCode.INVALID_INPUT, "Asset path is invalid.")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or path in {".", ".."} or any(part in {"", ".", ".."} for part in parsed.parts):
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
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    )
    signature = hmac.new(secret, encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64encode(signature)}"


def verify_asset_token(
    secret: bytes,
    token: str,
    *,
    now: datetime | None = None,
) -> AssetGrant:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
    except ValueError as exc:
        raise AppError(ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401) from exc
    supplied_signature = _b64decode(encoded_signature)
    try:
        encoded_payload_bytes = encoded_payload.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AppError(ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401) from exc
    expected_signature = hmac.new(secret, encoded_payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise AppError(ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401)
    try:
        payload = json.loads(_b64decode(encoded_payload))
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise ValueError("unsupported payload")
        path = _validate_path(str(payload["path"]))
        media_type = str(payload["media_type"])
        expires_at = int(payload["exp"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AppError(ErrorCode.UNAUTHORIZED, "The asset token is invalid.", http_status=401) from exc
    current = now or datetime.now(UTC)
    if int(current.astimezone(UTC).timestamp()) >= expires_at:
        raise AppError(ErrorCode.UNAUTHORIZED, "The asset token has expired.", http_status=401)
    return AssetGrant(path=path, media_type=media_type, expires_at=expires_at)
