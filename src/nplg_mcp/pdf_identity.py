# Copyright (c) 2026 David Osipov
"""Pure deterministic identities shared by the PDF parent and worker."""

from __future__ import annotations

import hashlib
import json
from typing import Literal


def render_identifier(
    *,
    source_sha256: str,
    pages: tuple[int, ...],
    mode: Literal["native"],
    renderer_version: str,
    fallback_dpi: int,
) -> str:
    """Bind one render root to its complete deterministic request identity."""
    key = {
        "fallback_dpi": fallback_dpi,
        "mode": mode,
        "pages": list(pages),
        "renderer_version": renderer_version,
        "source_sha256": source_sha256,
    }
    digest = hashlib.sha256(
        json.dumps(
            key,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return f"rnd_{digest[:32]}"
