#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Validate controller-injected private-full recovery probes."""

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
    "volume.complete-loss",
    "backup.restore-or-derived-regeneration",
    "content.digest",
    "filesystem.owner-mode",
    "high-water.restore",
    "clock-anomaly.closed",
    "leases.restore",
    "reservations.restore",
    "corrupt-state.closed",
    "partial-restore.cleaned",
    "rto.measured-within-policy",
    "subjects.unchanged",
    "cleanup.complete",
)


def verify(
    request: VerificationRequest,
    *,
    binding: ControllerBinding,
) -> VerificationProof:
    """Validate the exact recovery schedule supplied by a protected controller."""
    return verify_request(
        request,
        policy=controller_policy("private-recovery", PROBES, binding),
        executor=binding.executor,
        proof_path=binding.proof_path,
    )
