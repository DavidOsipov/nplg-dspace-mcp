#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Validate controller-injected no-network PDF-worker probes."""

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
    "network.netlink-denied",
    "secrets.unavailable",
    "filesystem.root-read-only",
    "filesystem.staging-only-write",
    "process.pid-ceiling",
    "process.deadline-kill",
    "ipc.peer-credentials",
    "ipc.nonce-replay-denied",
    "corpus.complete",
    "cleanup.complete",
)


def verify(
    request: VerificationRequest,
    *,
    binding: ControllerBinding,
) -> VerificationProof:
    """Validate the exact PDF-worker schedule supplied by a protected controller."""
    return verify_request(
        request,
        policy=controller_policy("pdf-worker-container", PROBES, binding),
        executor=binding.executor,
        proof_path=binding.proof_path,
    )
