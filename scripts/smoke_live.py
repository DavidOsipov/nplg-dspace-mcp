#!/usr/bin/env python3
"""Exercise live NPLG search and metadata through a deployed MCP."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from verify_deploy import McpClient, VerificationError, verify


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", default=os.getenv("API_BEARER_TOKEN"))
    parser.add_argument("--api-key", default=os.getenv("API_KEY"))
    parser.add_argument("--query", default="ივერია")
    parser.add_argument("--scope-handle")
    parser.add_argument("--handle", help="Inspect this handle instead of the first search result")
    parser.add_argument("--page-size", type=int, default=5)
    parser.add_argument("--download", action="store_true", help="Download the first public PDF attached to the selected item")
    parser.add_argument("--render-page", type=int, help="With --download, render this 1-based page")
    parser.add_argument("--tiles", action="store_true", help="With --render-page, also create default crop-only tiles")
    parser.add_argument("--timeout", type=float, default=90.0)
    return parser.parse_args()


def first_public_pdf(files: list[dict[str, Any]]) -> dict[str, Any] | None:
    for item in files:
        if item.get("access_status") != "public":
            continue
        filename = str(item.get("filename", "")).lower()
        reported = str(item.get("reported_format", "")).lower()
        if filename.endswith(".pdf") or "pdf" in reported:
            return item
    return None


def main() -> int:
    args = parse_args()
    if args.tiles and args.render_page is None:
        print("FAIL: --tiles requires --render-page", file=sys.stderr)
        return 2
    if args.render_page is not None and not args.download:
        print("FAIL: --render-page requires --download", file=sys.stderr)
        return 2

    client = McpClient(
        base_url=args.base_url,
        bearer_token=args.token,
        timeout=args.timeout,
        api_key=args.api_key,
    )
    try:
        conformance = verify(client)
        search_args: dict[str, Any] = {"query": args.query, "page_size": args.page_size}
        if args.scope_handle:
            search_args["scope_handle"] = args.scope_handle
        search = client.call_tool("search_documents", search_args)
        items = search.get("items", [])
        handle = args.handle or (items[0].get("handle") if items else None)
        if not isinstance(handle, str) or not handle:
            raise VerificationError("Search returned no item; provide --handle or use another query")

        metadata = client.call_tool("get_document_metadata", {"handle": handle})
        inventory = client.call_tool("list_document_files", {"handle": handle})
        output: dict[str, Any] = {
            "status": "pass",
            "conformance": conformance,
            "search": {"query": args.query, "total": search.get("total"), "returned": len(items)},
            "selected": {
                "handle": handle,
                "title": metadata.get("title"),
                "metadata_source": metadata.get("metadata_source"),
                "restricted": metadata.get("restricted"),
                "file_count": len(inventory.get("files", [])),
            },
        }

        if args.download:
            bitstream = first_public_pdf(inventory.get("files", []))
            if bitstream is None:
                raise VerificationError("Selected item has no public PDF bitstream")
            downloaded = client.call_tool(
                "download_document_file",
                {"handle": handle, "bitstream_id": bitstream["bitstream_id"]},
            )
            inspected = client.call_tool("inspect_pdf", {"artifact_id": downloaded["artifact_id"]})
            output["download"] = {
                "filename": bitstream.get("filename"),
                "artifact_id": downloaded.get("artifact_id"),
                "source_sha256": inspected.get("source_sha256"),
                "page_count": inspected.get("page_count"),
            }
            if args.render_page is not None:
                rendered = client.call_tool(
                    "render_pdf_pages",
                    {"artifact_id": downloaded["artifact_id"], "pages": [args.render_page], "mode": "native"},
                )
                page = rendered.get("pages", [{}])[0]
                output["render"] = {
                    "render_id": rendered.get("render_id"),
                    "page_number": page.get("page_number"),
                    "width": page.get("width"),
                    "height": page.get("height"),
                    "resolution_source": page.get("resolution_source"),
                    "conversion_path": page.get("conversion_path"),
                    "resize_applied": page.get("resize_applied"),
                }
                if args.tiles:
                    tiled = client.call_tool(
                        "render_pdf_page_tiles",
                        {"render_id": rendered["render_id"], "page_number": args.render_page},
                    )
                    output["tiles"] = {
                        "count": len(tiled.get("tiles", [])),
                        "tile_width": tiled.get("tile_width"),
                        "tile_height": tiled.get("tile_height"),
                        "overlap": tiled.get("overlap"),
                    }
    except (VerificationError, KeyError, IndexError, TypeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
