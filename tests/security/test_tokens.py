from datetime import UTC, datetime, timedelta

import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.tokens import AssetGrant, sign_asset_token, verify_asset_token

SECRET = b"s" * 32
NOW = datetime(2026, 8, 14, 18, 0, tzinfo=UTC)


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
        verify_asset_token(SECRET, tampered, now=NOW)
    assert raised.value.code is ErrorCode.UNAUTHORIZED


def test_expired_token_is_rejected() -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW - timedelta(seconds=1),
    )

    with pytest.raises(AppError, match="expired"):
        verify_asset_token(SECRET, token, now=NOW)


def test_token_is_expired_at_its_exact_expiry_second() -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW,
    )

    with pytest.raises(AppError, match="expired"):
        verify_asset_token(SECRET, token, now=NOW)


def test_wrong_secret_is_rejected() -> None:
    token = sign_asset_token(
        SECRET,
        path="documents/doc_abc/source.pdf",
        media_type="application/pdf",
        expires_at=NOW + timedelta(minutes=10),
    )

    with pytest.raises(AppError):
        verify_asset_token(b"x" * 32, token, now=NOW)


def test_non_ascii_payload_segment_is_rejected_as_an_invalid_token() -> None:
    with pytest.raises(AppError) as captured:
        verify_asset_token(SECRET, "é.AA", now=NOW)

    assert captured.value.code == ErrorCode.UNAUTHORIZED
    assert captured.value.http_status == 401


@pytest.mark.parametrize(
    "path",
    ["/absolute.jpg", "../escape.jpg", "renders/../../escape.jpg", "renders\\escape.jpg", "", "."],
)
def test_unsafe_asset_paths_are_rejected(path: str) -> None:
    with pytest.raises(AppError) as raised:
        sign_asset_token(
            SECRET,
            path=path,
            media_type="image/jpeg",
            expires_at=NOW + timedelta(minutes=10),
        )
    assert raised.value.code is ErrorCode.INVALID_INPUT
