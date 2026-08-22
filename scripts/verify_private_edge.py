#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Validate controller-injected private mTLS edge probes."""

from __future__ import annotations

from .verification_envelope import (
    ControllerBinding,
    VerificationProof,
    VerificationRequest,
    controller_policy,
    verify_request,
)

PROBES = (
    "subjects.identity",
    "public.tls-chain-hostname",
    "public.tls12-policy",
    "public.tls13-policy",
    "public.headers-framing",
    "public.slow-client-bounded",
    "public.body-header-deadline-concurrency",
    "public.auth-negative",
    "origin.not-publicly-bypassable",
    "origin.mtls-server-auth",
    "origin.mtls-client-auth",
    "origin.host-origin-policy",
    "origin.plaintext-denied",
    "logs.no-secret",
    "subjects.unchanged",
    "cleanup.complete",
)


def verify(
    request: VerificationRequest,
    *,
    binding: ControllerBinding,
) -> VerificationProof:
    """Validate the exact private-edge schedule supplied by a protected controller."""
    return verify_request(
        request,
        policy=controller_policy("private-edge", PROBES, binding),
        executor=binding.executor,
        proof_path=binding.proof_path,
    )
