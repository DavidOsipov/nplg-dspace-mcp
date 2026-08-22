#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Validate controller-injected no-network scanner probes."""

from __future__ import annotations

from .verification_envelope import (
    ControllerBinding,
    VerificationProof,
    VerificationRequest,
    controller_policy,
    verify_request,
)

PROBES = (
    "image.identity",
    "network.dns-denied",
    "network.ipv4-denied",
    "network.ipv6-denied",
    "secrets.unavailable",
    "filesystem.root-read-only",
    "signatures.authentic-and-fresh",
    "sample.clean-accepted",
    "sample.eicar-rejected",
    "archive-bomb.bounded",
    "process.deadline-kill",
    "cleanup.complete",
)


def verify(
    request: VerificationRequest,
    *,
    binding: ControllerBinding,
) -> VerificationProof:
    """Validate the exact scanner schedule supplied by a protected controller."""
    return verify_request(
        request,
        policy=controller_policy("scanner-container", PROBES, binding),
        executor=binding.executor,
        proof_path=binding.proof_path,
    )
