# Copyright (c) 2026 David Osipov
"""Scanner proof schedule regression tests."""

from scripts.verify_scanner_container import PROBES


def test_scanner_schedule_covers_freshness_limits_and_cleanup() -> None:
    assert PROBES == (
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
