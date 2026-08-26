# Copyright (c) 2026 David Osipov
"""Closed-inventory edge tests for private mTLS material validation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID
from pydantic import ValidationError

from nplg_mcp import private_tls
from nplg_mcp.private_tls import PrivateTlsMaterialError, PrivateTlsPaths

if TYPE_CHECKING:
    from collections.abc import Callable

_NOW = datetime(2026, 8, 25, tzinfo=UTC)
type _SigningKey = (
    rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
)
_NAIVE_NOW = _NOW.replace(tzinfo=None)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _sign(
    builder: x509.CertificateBuilder,
    key: _SigningKey,
) -> x509.Certificate:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return builder.sign(key, None)
    return builder.sign(key, hashes.SHA256())


@dataclass(frozen=True, slots=True)
class _AuthorityOptions:
    common_name: str = "private-ca"
    include_basic_constraints: bool = True
    include_key_usage: bool = True
    is_ca: bool = True
    key_cert_sign: bool = True


_DEFAULT_AUTHORITY_OPTIONS = _AuthorityOptions()


def _authority(
    key: _SigningKey,
    *,
    options: _AuthorityOptions = _DEFAULT_AUTHORITY_OPTIONS,
) -> x509.Certificate:
    name = _name(options.common_name)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=30))
    )
    if options.include_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=options.is_ca,
                path_length=0 if options.is_ca else None,
            ),
            critical=True,
        )
    if options.include_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=options.key_cert_sign,
                crl_sign=options.key_cert_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return _sign(builder, key)


@dataclass(frozen=True, slots=True)
class _ServerCertificateOptions:
    include_basic_constraints: bool = True
    include_extended_key_usage: bool = True
    include_subject_alternative_name: bool = True
    server_auth: bool = True


_DEFAULT_SERVER_CERTIFICATE_OPTIONS = _ServerCertificateOptions()


def _server_certificate(
    authority_key: _SigningKey,
    authority_certificate: x509.Certificate,
    server_key: ec.EllipticCurvePrivateKey,
    *,
    options: _ServerCertificateOptions = _DEFAULT_SERVER_CERTIFICATE_OPTIONS,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("app.internal"))
        .issuer_name(authority_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=7))
    )
    if options.include_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    if options.include_extended_key_usage:
        usage = (
            ExtendedKeyUsageOID.SERVER_AUTH
            if options.server_auth
            else ExtendedKeyUsageOID.CLIENT_AUTH
        )
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    if options.include_subject_alternative_name:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("app.internal")]),
            critical=False,
        )
    return _sign(builder, authority_key)


def _paths_payload(tmp_path: Path) -> dict[str, object]:
    return {
        "server_certificate": tmp_path / "server.pem",
        "server_key": tmp_path / "server-key.pem",
        "app_server_ca": tmp_path / "app-ca.pem",
        "caddy_client_ca": tmp_path / "client-ca.pem",
        "server_name": "app.internal",
    }


def _placeholder_paths(tmp_path: Path) -> PrivateTlsPaths:
    return PrivateTlsPaths.model_validate(_paths_payload(tmp_path))


def _write_private(path: Path, value: bytes) -> None:
    _ = path.write_bytes(value)
    path.chmod(0o400)


@pytest.mark.parametrize("invalid_path_kind", ["relative", "nul"])
def test_private_tls_paths_reject_nonabsolute_or_nul_path(
    tmp_path: Path,
    invalid_path_kind: str,
) -> None:
    payload = _paths_payload(tmp_path)
    invalid_path = (
        Path("relative.pem")
        if invalid_path_kind == "relative"
        else tmp_path / "nul\x00.pem"
    )
    payload["server_certificate"] = invalid_path

    with pytest.raises(ValidationError, match="absolute and NUL-free"):
        _ = PrivateTlsPaths.model_validate(payload)


def test_private_tls_paths_reject_reused_path(tmp_path: Path) -> None:
    payload = _paths_payload(tmp_path)
    payload["server_key"] = payload["server_certificate"]

    with pytest.raises(ValidationError, match="must be distinct"):
        _ = PrivateTlsPaths.model_validate(payload)


def test_read_secret_rejects_unreadable_path(tmp_path: Path) -> None:
    with pytest.raises(PrivateTlsMaterialError, match="unreadable"):
        _ = private_tls._read_secret(tmp_path / "missing.pem")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_read_secret_rejects_truncation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "secret.pem"
    _write_private(path, b"x")

    def read_nothing(_descriptor: int, _maximum: int) -> bytes:
        return b""

    monkeypatch.setattr(os, "read", read_nothing)
    with pytest.raises(PrivateTlsMaterialError, match="truncated secret"):
        _ = private_tls._read_secret(path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_read_secret_rejects_growth_after_descriptor_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "secret.pem"
    _write_private(path, b"x")
    responses = iter((b"x", b"y"))

    def read_growing_secret(_descriptor: int, _maximum: int) -> bytes:
        return next(responses)

    monkeypatch.setattr(os, "read", read_growing_secret)
    with pytest.raises(PrivateTlsMaterialError, match="oversized secret"):
        _ = private_tls._read_secret(path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_material_loaders_reject_malformed_pem() -> None:
    with pytest.raises(PrivateTlsMaterialError, match="invalid server certificate"):
        _ = private_tls._load_certificate(b"not a certificate", role="server")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PrivateTlsMaterialError, match="invalid private key"):
        _ = private_tls._load_private_key(b"not a private key")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_private_key_loader_rejects_unsupported_key_type() -> None:
    key = dsa.generate_private_key(key_size=2_048)
    encoded = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    with pytest.raises(PrivateTlsMaterialError, match="unsupported private key"):
        _ = private_tls._load_private_key(encoded)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "key",
    [
        rsa.generate_private_key(public_exponent=65_537, key_size=2_048),
        rsa.generate_private_key(public_exponent=3, key_size=3_072),
    ],
)
def test_key_strength_rejects_weak_rsa(key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(PrivateTlsMaterialError, match="weak probe RSA key"):
        private_tls._validate_key_strength(key, role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_key_strength_accepts_reviewed_ec_and_ed25519_keys() -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()

    private_tls._validate_key_strength(ec_key.public_key(), role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    private_tls._validate_key_strength(ec_key, role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    private_tls._validate_key_strength(ed_key.public_key(), role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    private_tls._validate_key_strength(ed_key, role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_key_strength_rejects_unreviewed_ec_curve_and_unknown_key() -> None:
    weak_ec_key = ec.generate_private_key(ec.SECP224R1())

    with pytest.raises(PrivateTlsMaterialError, match="weak probe EC key"):
        private_tls._validate_key_strength(weak_ec_key, role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PrivateTlsMaterialError, match="unsupported probe key"):
        private_tls._validate_key_strength(object(), role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@dataclass(frozen=True, slots=True)
class _ValidityProbe:
    not_valid_before_utc: datetime
    not_valid_after_utc: datetime


@pytest.mark.parametrize(
    ("not_before", "not_after"),
    [
        (_NAIVE_NOW, datetime(2026, 8, 26, tzinfo=UTC)),
        (datetime(2026, 8, 26, tzinfo=UTC), datetime(2026, 8, 24, tzinfo=UTC)),
    ],
)
def test_validity_rejects_malformed_intervals(
    not_before: datetime,
    not_after: datetime,
) -> None:
    certificate = cast(
        "x509.Certificate",
        _ValidityProbe(not_valid_before_utc=not_before, not_valid_after_utc=not_after),
    )

    with pytest.raises(PrivateTlsMaterialError, match="invalid probe validity"):
        private_tls._validate_validity(certificate, now=_NOW, role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@dataclass(frozen=True, slots=True)
class _SignatureAlgorithmProbe:
    signature_algorithm_oid: x509.ObjectIdentifier
    signature_hash_algorithm: hashes.HashAlgorithm | None


def test_signature_algorithm_accepts_real_ed25519_shape() -> None:
    certificate = cast(
        "x509.Certificate",
        _SignatureAlgorithmProbe(
            signature_algorithm_oid=SignatureAlgorithmOID.ED25519,
            signature_hash_algorithm=None,
        ),
    )

    private_tls._validate_signature_algorithm(certificate, role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "certificate",
    [
        _SignatureAlgorithmProbe(
            signature_algorithm_oid=SignatureAlgorithmOID.ED25519,
            signature_hash_algorithm=hashes.SHA256(),
        ),
        _SignatureAlgorithmProbe(
            signature_algorithm_oid=SignatureAlgorithmOID.RSA_WITH_SHA256,
            signature_hash_algorithm=hashes.SHA3_256(),
        ),
    ],
)
def test_signature_algorithm_rejects_inconsistent_or_weak_shape(
    certificate: _SignatureAlgorithmProbe,
) -> None:
    with pytest.raises(PrivateTlsMaterialError, match="weak probe signature algorithm"):
        private_tls._validate_signature_algorithm(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            cast("x509.Certificate", certificate),
            role="probe",
        )


def _authority_without_basic_constraints(
    key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    return _authority(
        key,
        options=_AuthorityOptions(include_basic_constraints=False),
    )


def _authority_without_ca_flag(
    key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    return _authority(key, options=_AuthorityOptions(is_ca=False))


def _authority_without_signing_usage(
    key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    return _authority(
        key,
        options=_AuthorityOptions(key_cert_sign=False),
    )


@pytest.mark.parametrize(
    "certificate_factory",
    [
        _authority_without_basic_constraints,
        _authority_without_ca_flag,
        _authority_without_signing_usage,
    ],
)
def test_ca_validation_rejects_missing_or_inoperative_extensions(
    certificate_factory: Callable[[ec.EllipticCurvePrivateKey], x509.Certificate],
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = certificate_factory(key)

    with pytest.raises(PrivateTlsMaterialError, match="invalid probe CA extensions"):
        private_tls._validate_ca(certificate, now=_NOW, role="probe")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@dataclass(frozen=True, slots=True)
class _SignatureProbe:
    issuer: x509.Name
    signature_algorithm_oid: x509.ObjectIdentifier
    signature_hash_algorithm: hashes.HashAlgorithm | None
    signature: bytes = b"invalid"
    tbs_certificate_bytes: bytes = b"invalid"


@dataclass(frozen=True, slots=True)
class _AuthorityProbe:
    subject: x509.Name
    key_factory: Callable[[], object]

    def public_key(self) -> object:
        return self.key_factory()


def test_signature_verification_rejects_wrong_issuer() -> None:
    authority_key = ec.generate_private_key(ec.SECP256R1())
    authority = _authority(
        authority_key,
        options=_AuthorityOptions(common_name="expected-ca"),
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    other_authority = _authority(
        authority_key,
        options=_AuthorityOptions(common_name="other-ca"),
    )
    certificate = _server_certificate(authority_key, other_authority, server_key)

    with pytest.raises(PrivateTlsMaterialError, match="server certificate issuer"):
        private_tls._verify_certificate_signature(certificate, authority)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "authority_key",
    [
        rsa.generate_private_key(public_exponent=65_537, key_size=3_072),
        ec.generate_private_key(ec.SECP256R1()),
    ],
)
def test_signature_verification_rejects_missing_hash_algorithm(
    authority_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
) -> None:
    authority = _authority(authority_key)
    certificate = cast(
        "x509.Certificate",
        _SignatureProbe(
            issuer=authority.subject,
            signature_algorithm_oid=SignatureAlgorithmOID.RSA_WITH_SHA256,
            signature_hash_algorithm=None,
        ),
    )

    with pytest.raises(PrivateTlsMaterialError, match="server certificate signature"):
        private_tls._verify_certificate_signature(certificate, authority)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "authority_key",
    [
        ec.generate_private_key(ec.SECP256R1()),
        ed25519.Ed25519PrivateKey.generate(),
    ],
)
def test_signature_verification_accepts_reviewed_non_rsa_authority(
    authority_key: ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey,
) -> None:
    authority = _authority(authority_key)
    server_key = ec.generate_private_key(ec.SECP256R1())
    certificate = _server_certificate(authority_key, authority, server_key)

    private_tls._verify_certificate_signature(certificate, authority)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_signature_verification_rejects_unsupported_authority_key() -> None:
    subject = _name("unsupported-ca")
    unsupported_key = dsa.generate_private_key(key_size=2_048).public_key()
    authority = cast(
        "x509.Certificate",
        _AuthorityProbe(subject=subject, key_factory=lambda: unsupported_key),
    )
    certificate = cast(
        "x509.Certificate",
        _SignatureProbe(
            issuer=subject,
            signature_algorithm_oid=SignatureAlgorithmOID.RSA_WITH_SHA256,
            signature_hash_algorithm=hashes.SHA256(),
        ),
    )

    with pytest.raises(PrivateTlsMaterialError, match="unsupported app server CA key"):
        private_tls._verify_certificate_signature(certificate, authority)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_signature_verification_translates_invalid_signature() -> None:
    subject = "same-subject-different-key"
    signing_key = ec.generate_private_key(ec.SECP256R1())
    authority_key = ec.generate_private_key(ec.SECP256R1())
    signing_authority = _authority(
        signing_key,
        options=_AuthorityOptions(common_name=subject),
    )
    authority = _authority(
        authority_key,
        options=_AuthorityOptions(common_name=subject),
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    certificate = _server_certificate(signing_key, signing_authority, server_key)

    with pytest.raises(PrivateTlsMaterialError, match="server certificate signature"):
        private_tls._verify_certificate_signature(certificate, authority)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


class _BrokenPublicKey:
    def public_bytes(
        self,
        _encoding: serialization.Encoding,
        _format: serialization.PublicFormat,
    ) -> bytes:
        msg = "synthetic encoding failure"
        raise ValueError(msg)


class _BrokenPrivateKey:
    def public_key(self) -> _BrokenPublicKey:
        return _BrokenPublicKey()


def test_server_validation_translates_private_key_encoding_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_key = ec.generate_private_key(ec.SECP256R1())
    authority = _authority(authority_key)
    server_key = ec.generate_private_key(ec.SECP256R1())
    certificate = _server_certificate(authority_key, authority, server_key)

    def accept_key_strength(_key: object, *, role: str) -> None:
        del role

    monkeypatch.setattr(private_tls, "_validate_key_strength", accept_key_strength)
    malformed_key = cast(
        "rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey",
        _BrokenPrivateKey(),
    )

    with pytest.raises(PrivateTlsMaterialError, match="invalid private key"):
        private_tls._validate_server_certificate(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            certificate,
            malformed_key,
            authority,
            paths=_placeholder_paths(tmp_path),
            now=_NOW,
        )


def test_server_validation_rejects_missing_required_extension(tmp_path: Path) -> None:
    authority_key = ec.generate_private_key(ec.SECP256R1())
    authority = _authority(authority_key)
    server_key = ec.generate_private_key(ec.SECP256R1())
    certificate = _server_certificate(
        authority_key,
        authority,
        server_key,
        options=_ServerCertificateOptions(include_basic_constraints=False),
    )

    with pytest.raises(PrivateTlsMaterialError, match="missing server certificate"):
        private_tls._validate_server_certificate(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            certificate,
            server_key,
            authority,
            paths=_placeholder_paths(tmp_path),
            now=_NOW,
        )


def test_server_validation_rejects_non_server_eku(tmp_path: Path) -> None:
    authority_key = ec.generate_private_key(ec.SECP256R1())
    authority = _authority(authority_key)
    server_key = ec.generate_private_key(ec.SECP256R1())
    certificate = _server_certificate(
        authority_key,
        authority,
        server_key,
        options=_ServerCertificateOptions(server_auth=False),
    )

    with pytest.raises(PrivateTlsMaterialError, match="server certificate EKU"):
        private_tls._validate_server_certificate(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            certificate,
            server_key,
            authority,
            paths=_placeholder_paths(tmp_path),
            now=_NOW,
        )


def test_public_validator_rejects_naive_clock_before_reading_material(
    tmp_path: Path,
) -> None:
    with pytest.raises(PrivateTlsMaterialError, match="invalid validation clock"):
        private_tls.validate_private_tls_material(
            _placeholder_paths(tmp_path),
            now=_NAIVE_NOW,
        )
