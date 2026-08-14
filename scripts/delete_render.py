#!/usr/bin/env python3
"""Delete one cached render from the local deployment filesystem."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from nplg_mcp.errors import AppError
from nplg_mcp.pdf import PdfProcessor
from nplg_mcp.storage import ContentAddressedStore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("render_id", help="Render identifier, for example rnd_<32 lowercase hex characters>")
    parser.add_argument(
        "--cache-dir",
        default=os.getenv("CACHE_DIR", "/data/cache"),
        help="Cache root; defaults to CACHE_DIR or /data/cache",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.cache_dir).expanduser().resolve()
    if not root.is_dir() or not (root / "renders").is_dir():
        print(f"FAIL: cache directory is not initialized: {root}", file=sys.stderr)
        return 2
    try:
        deleted = PdfProcessor(store=ContentAddressedStore(root)).delete_render(args.render_id)
    except AppError as exc:
        print(f"FAIL: {exc.message}", file=sys.stderr)
        return 2
    print(json.dumps({"render_id": args.render_id, "deleted": deleted}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
