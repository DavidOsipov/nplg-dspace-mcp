# Copyright (c) 2026 David Osipov
"""Tests for token validation and constant-time comparisons."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import TYPE_CHECKING, cast

import pytest
from pydantic import ValidationError

from nplg_mcp import tokens as token_module
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.tokens import (
    CURSOR_KEY_ID,
    HARD_MAX_CURSOR_TTL_SECONDS,
    AssetGrant,
    CursorV1,
    cursor_query_hash,
    derive_cursor_signing_key,
    sign_asset_token,
    sign_cursor,
    verify_asset_token,
    verify_cursor,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from nplg_mcp.json_types import JsonObject

SECRET = b"s" * 32
NOW = datetime(2026, 8, 14, 18, 0, tzinfo=UTC)
_CURSOR_QUERY = "strict cursor query"
_CURSOR_SCOPE = "1234/560449"
_CURSOR_PAIRS_HOOK = "_reject_duplicate_cursor_keys"


def _signed_raw_payload(payload: bytes) -> str:
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(
        SECRET,
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded_payload}.{encoded_signature}"


def _cursor(**updates: object) -> CursorV1:
    payload: dict[str, object] = {
        "version": 1,
        "key_id": CURSOR_KEY_ID,
        "query_hash": cursor_query_hash(_CURSOR_QUERY),
        "scope_handle": _CURSOR_SCOPE,
        "offset": 50,
        "page_size": 25,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
    }
    payload.update(updates)
    return CursorV1.model_validate(payload, strict=True)


def _signed_cursor_payload(payload: bytes) -> str:
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(
        derive_cursor_signing_key(SECRET),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded_payload}.{encoded_signature}"


def test_cursor_round_trip_binds_every_search_context_field() -> None:
    cursor = _cursor()
    token = sign_cursor(SECRET, cursor)

    assert (
        verify_cursor(
            SECRET,
            token,
            normalized_query=_CURSOR_QUERY,
            scope_handle=_CURSOR_SCOPE,
            page_size=25,
            now=NOW,
        )
        == cursor
    )


@pytest.mark.parametrize(
    "expires_at",
    [
        NOW,
        NOW + timedelta(seconds=HARD_MAX_CURSOR_TTL_SECONDS + 1),
    ],
)
def test_cursor_model_rejects_nonpositive_and_overlong_lifetimes(
    expires_at: datetime,
) -> None:
    with pytest.raises(ValidationError, match="cursor lifetime is invalid"):
        _ = _cursor(expires_at=expires_at)


@pytest.mark.parametrize("secret", [b"short", "s" * 32])
def test_cursor_key_derivation_rejects_short_or_nonbyte_secrets(secret: object) -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        _ = derive_cursor_signing_key(cast("bytes", secret))


@pytest.mark.parametrize("query", ["", b"not-text"])
def test_cursor_query_hash_rejects_empty_or_nontext_input(query: object) -> None:
    with pytest.raises(ValueError, match="must be nonempty"):
        _ = cursor_query_hash(cast("str", query))


def test_cursor_json_hook_rejects_duplicate_and_nonjson_claims() -> None:
    duplicated = _signed_cursor_payload(
        b'{"version":1,"version":1,"key_id":"cursor-v1"}'
    )
    with pytest.raises(AppError, match="malformed"):
        _ = verify_cursor(
            SECRET,
            duplicated,
            normalized_query=_CURSOR_QUERY,
            scope_handle=_CURSOR_SCOPE,
            page_size=25,
            now=NOW,
        )

    reject_pairs = cast(
        "Callable[[list[tuple[str, object]]], JsonObject]",
        getattr(token_module, _CURSOR_PAIRS_HOOK),
    )
    with pytest.raises(TypeError, match="not a JSON value"):
        _ = reject_pairs([("claim", object())])


def test_cursor_rejects_bad_signature_and_unsupported_key_id() -> None:
    token = sign_cursor(SECRET, _cursor())
    with pytest.raises(AppError, match="malformed"):
        _ = verify_cursor(
            b"x" * 32,
            token,
            normalized_query=_CURSOR_QUERY,
            scope_handle=_CURSOR_SCOPE,
            page_size=25,
            now=NOW,
        )

    unsupported = sign_cursor(SECRET, _cursor(key_id="cursor-v2"))
    with pytest.raises(AppError, match="unsupported"):
        _ = verify_cursor(
            SECRET,
            unsupported,
            normalized_query=_CURSOR_QUERY,
            scope_handle=_CURSOR_SCOPE,
            page_size=25,
            now=NOW,
        )


def test_asset_token_round_trips_and_is_bound_to_path_and_media_type() -> None:
    token = sign_asset_token(
        SECRET,
        path="renders/rnd_abc/page-0001.jpg",
        media_type="image/jpeg",
        expires_at=NOW + timedelta(minutes=10),
    )

    grant = verify_asset_token(SECRET, token, now=NOW)

    assert grant == AssetGrant(
        path="renders/rnd_abc/page-0001.jpg",
        media_type="image/jpeg",
        expires_at=int((NOW + timedelta(minutes=10)).timestamp()),
    )


def test_tampering_is_rejected() -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW + timedelta(minutes=10),
    )
    payload, signature = token.split(".")
    tampered = ("A" if payload[0] != "A" else "B") + payload[1:] + "." + signature

    with pytest.raises(AppError) as raised:
        _ = verify_asset_token(SECRET, tampered, now=NOW)
    assert raised.value.code is ErrorCode.UNAUTHORIZED


def test_expired_token_is_rejected() -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW - timedelta(seconds=1),
    )

    with pytest.raises(AppError, match="expired"):
        _ = verify_asset_token(SECRET, token, now=NOW)


def test_token_is_expired_at_its_exact_expiry_second() -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW,
    )

    with pytest.raises(AppError, match="expired"):
        _ = verify_asset_token(SECRET, token, now=NOW)


def test_asset_token_rejects_expiry_beyond_the_hard_lifetime_ceiling() -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW + timedelta(days=1, seconds=1),
    )

    with pytest.raises(AppError, match="lifetime"):
        _ = verify_asset_token(SECRET, token, now=NOW)


@pytest.mark.parametrize(
    "max_ttl_seconds",
    [
        pytest.param(True, id="boolean"),
        pytest.param(0, id="zero"),
        pytest.param(86_401, id="above-hard-ceiling"),
    ],
)
def test_asset_token_rejects_invalid_verifier_lifetime_ceiling(
    max_ttl_seconds: int,
) -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW + timedelta(minutes=10),
    )

    with pytest.raises(ValueError, match="max_ttl_seconds must be an integer"):
        _ = verify_asset_token(
            SECRET,
            token,
            now=NOW,
            max_ttl_seconds=max_ttl_seconds,
        )


def test_wrong_secret_is_rejected() -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW + timedelta(minutes=10),
    )

    with pytest.raises(AppError):
        _ = verify_asset_token(b"x" * 32, token, now=NOW)


def test_non_ascii_payload_segment_is_rejected_as_an_invalid_token() -> None:
    with pytest.raises(AppError) as captured:
        _ = verify_asset_token(SECRET, "é.AA", now=NOW)

    assert captured.value.code == ErrorCode.UNAUTHORIZED
    assert captured.value.http_status == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("missing-separator", id="missing-separator"),
        pytest.param("e30.!", id="invalid-base64-signature"),
    ],
)
def test_malformed_token_framing_is_rejected(token: str) -> None:
    with pytest.raises(AppError) as captured:
        _ = verify_asset_token(SECRET, token, now=NOW)

    assert captured.value.code is ErrorCode.UNAUTHORIZED
    assert captured.value.http_status == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            {"exp": 1, "media_type": "image/jpeg", "path": "asset.jpg", "v": 2},
            id="unsupported-version",
        ),
        pytest.param(
            {
                "exp": True,
                "media_type": "image/jpeg",
                "path": "asset.jpg",
                "v": 1,
            },
            id="boolean-expiry",
        ),
    ],
)
def test_signed_but_invalid_claims_are_rejected(payload: dict[str, object]) -> None:
    token = _signed_raw_payload(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(AppError) as captured:
        _ = verify_asset_token(SECRET, token, now=NOW)

    assert captured.value.code is ErrorCode.UNAUTHORIZED
    assert captured.value.http_status == HTTPStatus.UNAUTHORIZED


def test_signed_non_json_payload_is_rejected() -> None:
    token = _signed_raw_payload(b"not-json")

    with pytest.raises(AppError) as captured:
        _ = verify_asset_token(SECRET, token, now=NOW)

    assert captured.value.code is ErrorCode.UNAUTHORIZED
    assert captured.value.http_status == HTTPStatus.UNAUTHORIZED


def test_signing_rejects_naive_expiry() -> None:
    with pytest.raises(AppError) as captured:
        _ = sign_asset_token(
            SECRET,
            path="asset.jpg",
            media_type="image/jpeg",
            expires_at=NOW.replace(tzinfo=None),
        )

    assert captured.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "path",
    [
        "/absolute.jpg",
        "../escape.jpg",
        "renders/../../escape.jpg",
        "renders\\escape.jpg",
        "renders//escape.jpg",
        "",
        ".",
    ],
)
def test_unsafe_asset_paths_are_rejected(path: str) -> None:
    with pytest.raises(AppError) as raised:
        _ = sign_asset_token(
            SECRET,
            path=path,
            media_type="image/jpeg",
            expires_at=NOW + timedelta(minutes=10),
        )
    assert raised.value.code is ErrorCode.INVALID_INPUT
