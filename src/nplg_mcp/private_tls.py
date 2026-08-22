# Copyright (c) 2026 David Osipov
"""Fail-closed validation of fixed private-edge mTLS secret mounts."""

from __future__ import annotations

import hmac
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, NoReturn

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, SignatureAlgorithmOID
from pydantic import StringConstraints, field_validator, model_validator
from pydantic_core import PydanticCustomError

from .contracts import StrictModel

_MAX_MATERIAL_BYTES = 512 * 1024
_REQUIRED_SECRET_MODE = stat.S_IRUSR
_MIN_RSA_BITS = 3_072
_RSA_PUBLIC_EXPONENT = 65_537
_PATH_TYPE_ERROR = "path_type"
_PATH_TYPE_MESSAGE = "TLS material paths must be pathlib.Path instances"
_UNREADABLE = "unreadable"
_INVALID_PRIVATE_KEY = "invalid private key"
_SERVER_SIGNATURE = "server certificate signature"
_MISSING_SERVER_EXTENSIONS = "missing server certificate extensions"
_ALLOWED_EC_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})
_SERVER_NAME = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=253,
        pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",
    ),
]
type PrivateKey = (
    rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
)


class PrivateTlsMaterialError(RuntimeError):
    """Private TLS startup material did not satisfy the reviewed policy."""

    @classmethod
    def for_reason(cls, reason: str) -> PrivateTlsMaterialError:
        """Create a bounded diagnostic which never includes secret material."""
        return cls(f"private TLS material rejected: {reason}")


class PrivateTlsPaths(StrictModel):
    """Fixed paths for the application identity and both private trust roots."""

    server_certificate: Path
    server_key: Path
    app_server_ca: Path
    caddy_client_ca: Path
    server_name: _SERVER_NAME

    @field_validator(
        "server_certificate",
        "server_key",
        "app_server_ca",
        "caddy_client_ca",
        mode="before",
    )
    @classmethod
    def _require_path_instance(cls, value: object) -> Path:
        """Reject string coercion and preserve the configured path type."""
        if not isinstance(value, Path):
            raise PydanticCustomError(_PATH_TYPE_ERROR, _PATH_TYPE_MESSAGE)
        return value

    @model_validator(mode="after")
    def _validate_distinct_absolute_paths(self) -> PrivateTlsPaths:
        """Reject path reuse before opening any supposedly separate material."""
        paths = (
            self.server_certificate,
            self.server_key,
            self.app_server_ca,
            self.caddy_client_ca,
        )
        if any(not path.is_absolute() or "\x00" in str(path) for path in paths):
            msg = "TLS material paths must be absolute and NUL-free"
            raise ValueError(msg)
        if len({str(path) for path in paths}) != len(paths):
            msg = "TLS material paths must be distinct"
            raise ValueError(msg)
        return self


def _reject(reason: str) -> NoReturn:
    """Raise a bounded startup error without exposing secret content."""
    raise PrivateTlsMaterialError.for_reason(reason)


def _read_secret(path: Path) -> bytes:
    """Read one regular non-symlink secret through a no-follow descriptor."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        error = PrivateTlsMaterialError.for_reason(_UNREADABLE)
        raise error from exc
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or status.st_uid != os.geteuid()
            or stat.S_IMODE(status.st_mode) != _REQUIRED_SECRET_MODE
            or not 0 < status.st_size <= _MAX_MATERIAL_BYTES
        ):
            _reject("permissions")
        chunks: list[bytes] = []
        remaining = status.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                _reject("truncated secret")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _reject("oversized secret")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_certificate(value: bytes, *, role: str) -> x509.Certificate:
    """Load exactly one PEM certificate without retaining its source bytes."""
    try:
        return x509.load_pem_x509_certificate(value)
    except ValueError as exc:
        reason = f"invalid {role} certificate"
        error = PrivateTlsMaterialError.for_reason(reason)
        raise error from exc


def _load_private_key(value: bytes) -> PrivateKey:
    """Load an unencrypted server key, as required by the ASGI TLS server."""
    try:
        key = serialization.load_pem_private_key(value, password=None)
    except (TypeError, ValueError) as exc:
        error = PrivateTlsMaterialError.for_reason(_INVALID_PRIVATE_KEY)
        raise error from exc
    if isinstance(
        key,
        (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey),
    ):
        return key
    _reject("unsupported private key")


def _validate_key_strength(key: object, *, role: str) -> None:
    """Reject weak or unsupported keys before an internal TLS listener starts."""
    if isinstance(key, rsa.RSAPublicKey | rsa.RSAPrivateKey):
        public_numbers = (
            key.public_numbers()
            if isinstance(key, rsa.RSAPublicKey)
            else key.private_numbers().public_numbers
        )
        if key.key_size < _MIN_RSA_BITS or public_numbers.e != _RSA_PUBLIC_EXPONENT:
            _reject(f"weak {role} RSA key")
        return
    if isinstance(key, ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey):
        if key.curve.name not in _ALLOWED_EC_CURVES:
            _reject(f"weak {role} EC key")
        return
    if isinstance(key, ed25519.Ed25519PublicKey | ed25519.Ed25519PrivateKey):
        return
    _reject(f"unsupported {role} key")


def _validate_validity(
    certificate: x509.Certificate,
    *,
    now: datetime,
    role: str,
) -> None:
    """Require one current certificate interval under the injected UTC clock."""
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if not_before.tzinfo is None or not_after.tzinfo is None or not_before > not_after:
        _reject(f"invalid {role} validity")
    if not not_before <= now <= not_after:
        _reject(f"invalid {role} validity")


def _validate_signature_algorithm(certificate: x509.Certificate, *, role: str) -> None:
    """Permit only modern certificate signature algorithms."""
    algorithm = certificate.signature_hash_algorithm
    if certificate.signature_algorithm_oid == SignatureAlgorithmOID.ED25519:
        if algorithm is not None:
            _reject(f"weak {role} signature algorithm")
        return
    if not isinstance(algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
        _reject(f"weak {role} signature algorithm")


def _validate_ca(certificate: x509.Certificate, *, now: datetime, role: str) -> None:
    """Require a valid signing CA with a modern key and key-cert-sign usage."""
    _validate_validity(certificate, now=now, role=role)
    _validate_signature_algorithm(certificate, role=role)
    _validate_key_strength(certificate.public_key(), role=role)
    try:
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        reason = f"invalid {role} CA extensions"
        error = PrivateTlsMaterialError.for_reason(reason)
        raise error from exc
    if not basic_constraints.ca or not key_usage.key_cert_sign:
        _reject(f"invalid {role} CA extensions")


def _verify_certificate_signature(
    certificate: x509.Certificate,
    authority: x509.Certificate,
) -> None:
    """Verify the direct private-CA signature without a platform trust fallback."""
    if certificate.issuer != authority.subject:
        _reject("server certificate issuer")
    authority_key = authority.public_key()
    try:
        if isinstance(authority_key, rsa.RSAPublicKey):
            algorithm = certificate.signature_hash_algorithm
            if algorithm is None:
                _reject("server certificate signature")
            authority_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                algorithm,
            )
        elif isinstance(authority_key, ec.EllipticCurvePublicKey):
            algorithm = certificate.signature_hash_algorithm
            if algorithm is None:
                _reject("server certificate signature")
            authority_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(algorithm),
            )
        elif isinstance(authority_key, ed25519.Ed25519PublicKey):
            authority_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
        else:
            _reject("unsupported app server CA key")
    except InvalidSignature as exc:
        error = PrivateTlsMaterialError.for_reason(_SERVER_SIGNATURE)
        raise error from exc


def _validate_server_certificate(
    certificate: x509.Certificate,
    private_key: PrivateKey,
    app_server_ca: x509.Certificate,
    *,
    paths: PrivateTlsPaths,
    now: datetime,
) -> None:
    """Bind the fixed app identity, key, host, EKU, and issuing private CA."""
    _validate_validity(certificate, now=now, role="server certificate")
    _validate_signature_algorithm(certificate, role="server certificate")
    _validate_key_strength(certificate.public_key(), role="server certificate")
    _validate_key_strength(private_key, role="server private")
    try:
        key_public = private_key.public_key()
        certificate_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_der = key_public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        error = PrivateTlsMaterialError.for_reason(_INVALID_PRIVATE_KEY)
        raise error from exc
    if not hmac.compare_digest(certificate_der, key_der):
        _reject("private key does not match server certificate")
    try:
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        extended_key_usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        subject_alternative_name = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as exc:
        error = PrivateTlsMaterialError.for_reason(_MISSING_SERVER_EXTENSIONS)
        raise error from exc
    expected_extended_key_usage = x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.SERVER_AUTH]
    )
    if basic_constraints.ca or extended_key_usage != expected_extended_key_usage:
        _reject("server certificate EKU")
    dns_names = tuple(subject_alternative_name.get_values_for_type(x509.DNSName))
    if dns_names != (paths.server_name,) or len(subject_alternative_name) != 1:
        _reject("server certificate SAN")
    _verify_certificate_signature(certificate, app_server_ca)


def validate_private_tls_material(paths: PrivateTlsPaths, *, now: datetime) -> None:
    """Validate every app-side mTLS secret before Uvicorn opens its listener."""
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
        _reject("invalid validation clock")
    utc_now = now.astimezone(UTC)
    certificate = _load_certificate(
        _read_secret(paths.server_certificate), role="server"
    )
    private_key = _load_private_key(_read_secret(paths.server_key))
    app_server_ca = _load_certificate(
        _read_secret(paths.app_server_ca), role="app server CA"
    )
    caddy_client_ca = _load_certificate(
        _read_secret(paths.caddy_client_ca), role="Caddy client CA"
    )
    _validate_ca(app_server_ca, now=utc_now, role="app server")
    _validate_ca(caddy_client_ca, now=utc_now, role="Caddy client")
    app_ca_der = app_server_ca.public_bytes(serialization.Encoding.DER)
    client_ca_der = caddy_client_ca.public_bytes(serialization.Encoding.DER)
    server_der = certificate.public_bytes(serialization.Encoding.DER)
    if (
        hmac.compare_digest(app_ca_der, client_ca_der)
        or hmac.compare_digest(server_der, app_ca_der)
        or hmac.compare_digest(server_der, client_ca_der)
    ):
        _reject("reused certificate material")
    _validate_server_certificate(
        certificate,
        private_key,
        app_server_ca,
        paths=paths,
        now=utc_now,
    )
