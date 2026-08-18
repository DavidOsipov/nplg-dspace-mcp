#!/usr/bin/env python3
# Copyright (c) 2026 David Osipov
"""Exercise live NPLG search and metadata through a deployed MCP."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from typing import TextIO

    from scripts.verify_deploy import (
        DeploymentClient,
        JsonObject,
        JsonValue,
    )
    from scripts.verify_deploy import (
        McpClient as McpClientType,
    )
    from scripts.verify_deploy import (
        VerificationError as VerificationErrorType,
    )


class _RuntimeVerifyModule(Protocol):
    """Runtime surface shared by package and direct-script imports."""

    McpClient: type[McpClientType]
    VerificationError: type[VerificationErrorType]
    verify: Callable[[DeploymentClient], JsonObject]


_VERIFY_MODULE_NAME = "scripts.verify_deploy" if __package__ else "verify_deploy"
_VERIFY_MODULE = cast("_RuntimeVerifyModule", import_module(_VERIFY_MODULE_NAME))
McpClient = _VERIFY_MODULE.McpClient
VerificationError = _VERIFY_MODULE.VerificationError
verify = _VERIFY_MODULE.verify

_MAX_PAGE_SIZE = 50
_MAX_CANONICAL_OUTPUT_BYTES = 65_536


class SmokeClient(Protocol):
    """Injected deployed-MCP client boundary."""

    def call_tool(self, name: str, arguments: JsonObject) -> JsonObject:
        """Call one MCP tool."""
        ...


class ClientFactory(Protocol):
    """Construct a smoke client without ambient network creation in tests."""

    def __call__(
        self,
        *,
        base_url: str,
        bearer_token: str | None,
        timeout: float,
        api_key: str | None,
    ) -> SmokeClient:
        """Return a configured client."""
        ...


@dataclass(frozen=True, slots=True)
class CliDependencies:
    """Injected environment and effects for ``main``."""

    environ: Mapping[str, str]
    stdout: TextIO
    stderr: TextIO
    client_factory: ClientFactory
    verifier: Callable[[SmokeClient], JsonObject]


@dataclass(frozen=True, slots=True)
class SmokeArguments:
    """Validated live-smoke CLI arguments."""

    base_url: str
    token: str | None
    api_key: str | None
    query: str
    scope_handle: str | None
    handle: str | None
    page_size: int
    download: bool
    render_page: int | None
    tiles: bool
    timeout: float


def _parser(environ: Mapping[str, str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--base-url", required=True)
    _ = parser.add_argument("--token", default=environ.get("API_BEARER_TOKEN"))
    _ = parser.add_argument("--api-key", default=environ.get("API_KEY"))
    _ = parser.add_argument("--query", default="ივერია")
    _ = parser.add_argument("--scope-handle")
    _ = parser.add_argument(
        "--handle", help="Inspect this handle instead of the first search result"
    )
    _ = parser.add_argument("--page-size", type=int, default=5)
    _ = parser.add_argument(
        "--download",
        action="store_true",
        help="Download the first public PDF attached to the selected item",
    )
    _ = parser.add_argument(
        "--render-page", type=int, help="With --download, render this 1-based page"
    )
    _ = parser.add_argument(
        "--tiles",
        action="store_true",
        help="With --render-page, also create default crop-only tiles",
    )
    _ = parser.add_argument("--timeout", type=float, default=90.0)
    return parser


def _optional_string(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    msg = "argument parser returned an invalid optional string"
    raise VerificationError(msg)


def _arguments_from_values(values: Mapping[str, object]) -> SmokeArguments:
    base_url = values["base_url"]
    query = values["query"]
    page_size = values["page_size"]
    download = values["download"]
    render_page = values["render_page"]
    tiles = values["tiles"]
    timeout = values["timeout"]
    if (
        not isinstance(base_url, str)
        or not isinstance(query, str)
        or type(page_size) is not int
        or type(download) is not bool
        or (render_page is not None and type(render_page) is not int)
        or type(tiles) is not bool
        or type(timeout) is not float
    ):
        msg = "argument parser returned invalid values"
        raise VerificationError(msg)
    return SmokeArguments(
        base_url=base_url,
        token=_optional_string(values["token"]),
        api_key=_optional_string(values["api_key"]),
        query=query,
        scope_handle=_optional_string(values["scope_handle"]),
        handle=_optional_string(values["handle"]),
        page_size=page_size,
        download=download,
        render_page=render_page,
        tiles=tiles,
        timeout=timeout,
    )


def _parse_args(
    argv: Sequence[str], dependencies: CliDependencies
) -> SmokeArguments | int:
    try:
        with (
            redirect_stdout(dependencies.stdout),
            redirect_stderr(dependencies.stderr),
        ):
            values = cast(
                "dict[str, object]",
                vars(_parser(dependencies.environ).parse_args(argv)),
            )
    except SystemExit as exc:
        return exc.code if type(exc.code) is int else 1
    return _arguments_from_values(values)


def _default_client_factory(
    *,
    base_url: str,
    bearer_token: str | None,
    timeout: float,
    api_key: str | None,
) -> SmokeClient:
    return McpClient(
        base_url=base_url,
        bearer_token=bearer_token,
        timeout=timeout,
        api_key=api_key,
    )


def _default_verifier(client: SmokeClient) -> JsonObject:
    deployment_client = cast("DeploymentClient", client)
    return verify(deployment_client)


def _default_dependencies() -> CliDependencies:
    return CliDependencies(
        environ=os.environ,
        stdout=sys.stdout,
        stderr=sys.stderr,
        client_factory=_default_client_factory,
        verifier=_default_verifier,
    )


def _object_list(value: JsonValue | None, *, context: str) -> list[JsonObject]:
    if not isinstance(value, list):
        msg = f"{context} returned an invalid list"
        raise VerificationError(msg)
    objects: list[JsonObject] = []
    for item in value:
        if not isinstance(item, dict):
            msg = f"{context} returned an invalid entry"
            raise VerificationError(msg)
        objects.append(item)
    return objects


def _required_string(item: JsonObject, key: str, *, context: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        msg = f"{context} omitted {key}"
        raise VerificationError(msg)
    return value


def first_public_pdf(files: Sequence[JsonObject]) -> JsonObject | None:
    """Return the first public item reported or named as a PDF."""
    for item in files:
        if item.get("access_status") != "public":
            continue
        filename = str(item.get("filename", "")).lower()
        reported = str(item.get("reported_format", "")).lower()
        if filename.endswith(".pdf") or "pdf" in reported:
            return item
    return None


def _selected_handle(args: SmokeArguments, items: Sequence[JsonObject]) -> str:
    if args.handle:
        return args.handle
    if items:
        value = items[0].get("handle")
        if isinstance(value, str) and value:
            return value
    msg = "Search returned no item; provide --handle or use another query"
    raise VerificationError(msg)


def _add_render_output(
    output: JsonObject,
    args: SmokeArguments,
    client: SmokeClient,
    artifact_id: str,
) -> None:
    if args.render_page is None:
        return
    rendered = client.call_tool(
        "render_pdf_pages",
        {
            "artifact_id": artifact_id,
            "pages": [args.render_page],
            "mode": "native",
        },
    )
    pages = _object_list(rendered.get("pages"), context="render_pdf_pages")
    if not pages:
        msg = "render_pdf_pages returned no page"
        raise VerificationError(msg)
    page = pages[0]
    output["render"] = {
        "render_id": rendered.get("render_id"),
        "page_number": page.get("page_number"),
        "width": page.get("width"),
        "height": page.get("height"),
        "resolution_source": page.get("resolution_source"),
        "conversion_path": page.get("conversion_path"),
        "resize_applied": page.get("resize_applied"),
    }
    if not args.tiles:
        return
    render_id = _required_string(rendered, "render_id", context="render_pdf_pages")
    tiled = client.call_tool(
        "render_pdf_page_tiles",
        {"render_id": render_id, "page_number": args.render_page},
    )
    tiles = _object_list(tiled.get("tiles"), context="render_pdf_page_tiles")
    output["tiles"] = {
        "count": len(tiles),
        "tile_width": tiled.get("tile_width"),
        "tile_height": tiled.get("tile_height"),
        "overlap": tiled.get("overlap"),
    }


def _add_download_output(
    output: JsonObject,
    args: SmokeArguments,
    client: SmokeClient,
    handle: str,
    files: Sequence[JsonObject],
) -> None:
    if not args.download:
        return
    bitstream = first_public_pdf(files)
    if bitstream is None:
        msg = "Selected item has no public PDF bitstream"
        raise VerificationError(msg)
    bitstream_id = _required_string(
        bitstream,
        "bitstream_id",
        context="list_document_files",
    )
    downloaded = client.call_tool(
        "download_document_file",
        {"handle": handle, "bitstream_id": bitstream_id},
    )
    artifact_id = _required_string(
        downloaded,
        "artifact_id",
        context="download_document_file",
    )
    inspected = client.call_tool("inspect_pdf", {"artifact_id": artifact_id})
    output["download"] = {
        "filename": bitstream.get("filename"),
        "artifact_id": downloaded.get("artifact_id"),
        "source_sha256": inspected.get("source_sha256"),
        "page_count": inspected.get("page_count"),
    }
    _add_render_output(output, args, client, artifact_id)


def _run_smoke(args: SmokeArguments, dependencies: CliDependencies) -> JsonObject:
    client = dependencies.client_factory(
        base_url=args.base_url,
        bearer_token=args.token,
        timeout=args.timeout,
        api_key=args.api_key,
    )
    conformance = dependencies.verifier(client)
    search_args: JsonObject = {"query": args.query, "page_size": args.page_size}
    if args.scope_handle:
        search_args["scope_handle"] = args.scope_handle
    search = client.call_tool("search_documents", search_args)
    items = _object_list(search.get("items", []), context="search_documents")
    handle = _selected_handle(args, items)
    metadata = client.call_tool("get_document_metadata", {"handle": handle})
    inventory = client.call_tool("list_document_files", {"handle": handle})
    files = _object_list(
        inventory.get("files", []),
        context="list_document_files",
    )
    output: JsonObject = {
        "status": "pass",
        "conformance": conformance,
        "search": {
            "query": args.query,
            "total": search.get("total"),
            "returned": len(items),
        },
        "selected": {
            "handle": handle,
            "title": metadata.get("title"),
            "metadata_source": metadata.get("metadata_source"),
            "restricted": metadata.get("restricted"),
            "file_count": len(files),
        },
    }
    _add_download_output(output, args, client, handle, files)
    return output


def _argument_failure(args: SmokeArguments) -> str | None:
    if not 1 <= args.page_size <= _MAX_PAGE_SIZE:
        return f"--page-size must be between 1 and {_MAX_PAGE_SIZE}"
    if args.render_page is not None and args.render_page < 1:
        return "--render-page must be at least 1"
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        return "--timeout must be a positive finite number"
    if args.tiles and args.render_page is None:
        return "--tiles requires --render-page"
    if args.render_page is not None and not args.download:
        return "--render-page requires --download"
    return None


def _write_failure(
    dependencies: CliDependencies,
    message: str,
    *,
    exit_code: int,
) -> int:
    try:
        _ = dependencies.stderr.write(f"FAIL: {message}\n")
    except (OSError, UnicodeError):
        return exit_code
    return exit_code


def _write_output(output: JsonObject, dependencies: CliDependencies) -> int:
    try:
        payload = (
            json.dumps(
                output,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        encoded = payload.encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError):
        return _write_failure(
            dependencies,
            "live smoke returned invalid JSON",
            exit_code=1,
        )
    if len(encoded) > _MAX_CANONICAL_OUTPUT_BYTES:
        return _write_failure(
            dependencies,
            "live smoke output exceeded the size limit",
            exit_code=1,
        )
    try:
        _ = dependencies.stdout.write(payload)
    except (OSError, UnicodeError):
        return _write_failure(dependencies, "output write failed", exit_code=1)
    return 0


def main(argv: Sequence[str], *, dependencies: CliDependencies) -> int:
    """Run the injected live-smoke CLI."""
    try:
        parsed = _parse_args(argv, dependencies)
    except VerificationError:
        return _write_failure(
            dependencies,
            "invalid smoke arguments",
            exit_code=2,
        )
    if isinstance(parsed, int):
        return parsed
    argument_failure = _argument_failure(parsed)
    if argument_failure is not None:
        return _write_failure(dependencies, argument_failure, exit_code=2)
    try:
        output = _run_smoke(parsed, dependencies)
    except (VerificationError, KeyError, IndexError, TypeError):
        return _write_failure(
            dependencies,
            "live smoke request failed",
            exit_code=1,
        )
    except KeyboardInterrupt:
        return _write_failure(dependencies, "live smoke cancelled", exit_code=130)
    return _write_output(output, dependencies)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], dependencies=_default_dependencies()))
