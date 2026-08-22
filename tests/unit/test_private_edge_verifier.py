# Copyright (c) 2026 David Osipov
"""Private-edge proof schedule regression tests."""

from scripts.verify_private_edge import PROBES


def test_private_edge_schedule_covers_mtls_and_origin_bypass() -> None:
    assert PROBES == (
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
