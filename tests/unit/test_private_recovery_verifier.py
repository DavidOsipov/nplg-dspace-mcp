# Copyright (c) 2026 David Osipov
"""Recovery proof schedule regression tests."""

from scripts.verify_private_recovery import PROBES


def test_recovery_schedule_covers_state_integrity_and_rto() -> None:
    assert PROBES == (
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
