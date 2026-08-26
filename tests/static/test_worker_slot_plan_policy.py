# Copyright (c) 2026 David Osipov
"""Keep the Task 16A plan synchronized with the enforced worker-slot policy."""

from __future__ import annotations

from pathlib import Path
from typing import Final

_PROJECT_ROOT: Final = Path(__file__).parents[2]
_CANONICAL_WORKER_SLOT_POLICY: Final = (
    '{"concurrency":1,"filesystem_type":"ext4",'
    '"maximum_total_bytes":1073741824,"maximum_total_inodes":65536,'
    '"minimum_available_bytes":805306368,"minimum_available_inodes":32768,'
    '"mount_options":["nodev","noexec","nosuid","rw"],'
    '"root":"/var/lib/nplg/pdf-worker-slot","version":1}'
)


def test_task_16a_plan_and_deploy_policy_share_the_exact_canonical_contract() -> None:
    """Catch stale limits or schema names in either reviewed policy authority."""
    checked_in_policy = (
        _PROJECT_ROOT / "deploy" / "pdf-worker-slot-policy.json"
    ).read_text(encoding="utf-8")
    plan = (
        _PROJECT_ROOT
        / "docs"
        / "2026-08-14-official-mcp-sdk-alpic-tdd-implementation-plan.md"
    ).read_text(encoding="utf-8")

    assert checked_in_policy == f"{_CANONICAL_WORKER_SLOT_POLICY}\n"
    assert (
        "`deploy/pdf-worker-slot-policy.json` is exactly "
        f"`{_CANONICAL_WORKER_SLOT_POLICY}` in canonical-key form."
    ) in plan
