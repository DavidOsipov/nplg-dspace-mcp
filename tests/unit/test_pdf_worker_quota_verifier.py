# Copyright (c) 2026 David Osipov
"""Quota proof schedule regression tests."""

from scripts.verify_pdf_worker_quota import PROBES


def test_quota_schedule_covers_kernel_enforced_overruns() -> None:
    assert PROBES == (
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
