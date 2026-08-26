#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Validate controller-injected PDF-worker quota probes."""

from __future__ import annotations

from .verification_envelope import (
    ControllerBinding,
    VerificationError,
    VerificationProof,
    VerificationRequest,
    controller_policy,
    verify_request,
)

_VERIFIER = "pdf-worker-quota"
_AUTHORITY_ERROR = "verifier authority mismatch"

PROBES = (
    "image.identity",
    "quota.supported",
    "quota.exact-byte-accepted",
    "quota.n-plus-one-byte-denied",
    "quota.exact-inode-accepted",
    "quota.n-plus-one-file-denied",
    "quota.n-plus-one-directory-denied",
    "quota.zero-byte-flood-denied",
    "quota.sparse-blocks-bounded",
    "quota.concurrent-overrun-denied",
    "process.overrun-killed",
    "cleanup.root-removed",
    "headroom.restored",
)


def verify(
    request: VerificationRequest,
    *,
    binding: ControllerBinding,
) -> VerificationProof:
    """Validate the exact quota schedule supplied by a protected controller."""
    if request.verifier != _VERIFIER:
        raise VerificationError(_AUTHORITY_ERROR)
    return verify_request(
        request,
        policy=controller_policy(_VERIFIER, PROBES, binding),
        executor=binding.executor,
        proof_path=binding.proof_path,
    )
