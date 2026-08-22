# Copyright (c) 2026 David Osipov
"""Adversarial tests for fixed-path private mTLS startup validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import ValidationError

from nplg_mcp.private_tls import (
    PrivateTlsMaterialError,
    PrivateTlsPaths,
    validate_private_tls_material,
)

if TYPE_CHECKING:
    from pathlib import Path

_NOW = datetime(2026, 8, 22, tzinfo=UTC)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate_authority(
    common_name: str,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=3_072)
    name = _name(common_name)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA384())
    )
    return key, certificate


def _server_certificate(
    authority_key: rsa.RSAPrivateKey,
    authority_certificate: x509.Certificate,
    *,
    hostname: str = "app.internal",
    expired: bool = False,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=3_072)
    not_after = _NOW - timedelta(seconds=1) if expired else _NOW + timedelta(days=7)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(hostname))
        .issuer_name(authority_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(authority_key, hashes.SHA384())
    )
    return key, certificate


def _write_secret(path: Path, value: bytes, *, mode: int = 0o400) -> None:
    _ = path.write_bytes(value)
    path.chmod(mode)


@dataclass(frozen=True, slots=True)
class _TlsScenario:
    hostname: str = "app.internal"
    expired: bool = False
    key_matches: bool = True
    mode: int = 0o400
    shared_ca: bool = False


_DEFAULT_SCENARIO = _TlsScenario()


def _paths(
    tmp_path: Path,
    *,
    scenario: _TlsScenario = _DEFAULT_SCENARIO,
) -> PrivateTlsPaths:
    app_ca_key, app_ca = _certificate_authority("app-server-ca")
    _client_ca_key, client_ca = _certificate_authority("caddy-client-ca")
    server_key, server_certificate = _server_certificate(
        app_ca_key,
        app_ca,
        hostname=scenario.hostname,
        expired=scenario.expired,
    )
    if not scenario.key_matches:
        server_key = rsa.generate_private_key(public_exponent=65_537, key_size=3_072)
    server_certificate_path = tmp_path / "app-server-cert.pem"
    server_key_path = tmp_path / "app-server-key.pem"
    app_ca_path = tmp_path / "app-server-ca.pem"
    client_ca_path = tmp_path / "caddy-client-ca.pem"
    _write_secret(
        server_certificate_path,
        server_certificate.public_bytes(serialization.Encoding.PEM),
        mode=scenario.mode,
    )
    _write_secret(
        server_key_path,
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        mode=scenario.mode,
    )
    _write_secret(
        app_ca_path,
        app_ca.public_bytes(serialization.Encoding.PEM),
        mode=scenario.mode,
    )
    _write_secret(
        client_ca_path,
        (app_ca if scenario.shared_ca else client_ca).public_bytes(
            serialization.Encoding.PEM
        ),
        mode=scenario.mode,
    )
    return PrivateTlsPaths(
        server_certificate=server_certificate_path,
        server_key=server_key_path,
        app_server_ca=app_ca_path,
        caddy_client_ca=client_ca_path,
        server_name="app.internal",
    )


def test_private_tls_validator_accepts_fixed_valid_distinct_material(
    tmp_path: Path,
) -> None:
    validate_private_tls_material(_paths(tmp_path), now=_NOW)


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        (_TlsScenario(hostname="wrong.internal"), "SAN"),
        (_TlsScenario(expired=True), "validity"),
        (_TlsScenario(key_matches=False), "private key"),
        (_TlsScenario(mode=0o444), "permissions"),
        (_TlsScenario(mode=0o600), "permissions"),
        (_TlsScenario(shared_ca=True), "reused"),
    ],
)
def test_private_tls_validator_fails_closed_on_invalid_material(
    tmp_path: Path,
    scenario: _TlsScenario,
    expected: str,
) -> None:
    with pytest.raises(PrivateTlsMaterialError, match=expected):
        validate_private_tls_material(_paths(tmp_path, scenario=scenario), now=_NOW)


def test_private_tls_paths_rejects_coerced_secret_paths(tmp_path: Path) -> None:
    payload: dict[str, object] = {
        "server_certificate": str(tmp_path / "app-server-cert.pem"),
        "server_key": tmp_path / "app-server-key.pem",
        "app_server_ca": tmp_path / "app-server-ca.pem",
        "caddy_client_ca": tmp_path / "caddy-client-ca.pem",
        "server_name": "app.internal",
    }
    with pytest.raises(ValidationError):
        _ = PrivateTlsPaths.model_validate(payload)
