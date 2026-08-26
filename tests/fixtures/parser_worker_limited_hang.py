# Copyright (c) 2026 David Osipov
"""Parser fixture that applies production limits and remains observable."""

from __future__ import annotations

import time

from nplg_mcp.parser_worker_main import apply_resource_limits


def main() -> None:
    """Apply the production policy, then wait for parent-owned termination."""
    apply_resource_limits()
    time.sleep(60)


if __name__ == "__main__":
    main()
