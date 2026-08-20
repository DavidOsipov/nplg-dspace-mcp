# Copyright (c) 2026 David Osipov
"""Test-only adapter from deterministic PDF fakes to the strict executor API."""

from __future__ import annotations

import asyncio
import json
from functools import partial
from typing import TYPE_CHECKING, Protocol

from nplg_mcp.json_types import dataclass_to_json
from nplg_mcp.pdf_executor import PdfWorkerError
from nplg_mcp.pdf_ipc import (
    InspectCommand,
    InspectPayload,
    ManifestPayload,
    PdfInspectionOutput,
    PdfSuccess,
    RenderPagesCommand,
    RenderPagesOutput,
    RenderPagesPayload,
    RenderTilesCommand,
    RenderTilesOutput,
    RenderTilesPayload,
)

if TYPE_CHECKING:
    from pathlib import Path

    from nplg_mcp.pdf import PdfInspection, RenderManifest, TileManifest
    from nplg_mcp.pdf_executor import MonotonicDeadline
    from nplg_mcp.pdf_ipc import PdfCommand, PdfResult
    from nplg_mcp.storage import ContentAddressedStore


def _strict_json(value: object, *, context: str) -> str:
    return json.dumps(
        dataclass_to_json(value, context=context),
        allow_nan=False,
        separators=(",", ":"),
    )


class SyncPdfProcessor(Protocol):
    """Synchronous deterministic PDF collaborator used only by tests."""

    def inspect(self, pdf_path: Path) -> PdfInspection: ...

    def render_pages(
        self,
        pdf_path: Path,
        *,
        pages: tuple[int, ...],
        mode: str,
    ) -> RenderManifest: ...

    def render_tiles(
        self,
        render_id: str,
        *,
        page_number: int,
        tile_width: int | None = None,
        tile_height: int | None = None,
        overlap: int | None = None,
    ) -> TileManifest: ...

    def get_manifest(self, render_id: str) -> RenderManifest: ...


class InlinePdfExecutor:
    """Adapt trusted test doubles without creating a production bypass."""

    def __init__(
        self,
        *,
        processor: SyncPdfProcessor,
        store: ContentAddressedStore,
    ) -> None:
        """Bind one trusted processor and its authoritative fixture store."""
        super().__init__()
        self._processor = processor
        self._store = store

    def ensure_ready(self) -> None:
        """Return successfully because this test adapter has no circuit."""

    async def execute(
        self,
        command: PdfCommand,
        *,
        deadline: MonotonicDeadline,
    ) -> PdfResult:
        """Dispatch one strict command and validate the fake's output model."""
        if deadline.remaining() <= 0:
            message = "test PDF operation exceeded its deadline"
            raise PdfWorkerError(message)
        if isinstance(command, InspectCommand):
            source = self._store.resolve_asset(command.source_relative_path)
            inspected = await asyncio.to_thread(self._processor.inspect, source)
            inspection_value = PdfInspectionOutput.model_validate_json(
                _strict_json(inspected, context="test PDF inspection"),
                strict=True,
            )
            return PdfSuccess(
                request_id=command.request_id,
                status="ok",
                payload=InspectPayload(operation="inspect", value=inspection_value),
            )
        if isinstance(command, RenderPagesCommand):
            source = self._store.resolve_asset(command.source_relative_path)
            rendered = await asyncio.to_thread(
                partial(
                    self._processor.render_pages,
                    source,
                    pages=command.parameters.pages,
                    mode=command.parameters.mode,
                )
            )
            render_value = RenderPagesOutput.model_validate_json(
                _strict_json(rendered, context="test render manifest"),
                strict=True,
            )
            return PdfSuccess(
                request_id=command.request_id,
                status="ok",
                payload=RenderPagesPayload(
                    operation="render_pages",
                    value=render_value,
                ),
            )
        if isinstance(command, RenderTilesCommand):
            parameters = command.parameters
            tiled = await asyncio.to_thread(
                partial(
                    self._processor.render_tiles,
                    parameters.render_id,
                    page_number=parameters.page_number,
                    tile_width=parameters.tile_width,
                    tile_height=parameters.tile_height,
                    overlap=parameters.overlap,
                )
            )
            tile_value = RenderTilesOutput.model_validate_json(
                _strict_json(tiled, context="test tile manifest"),
                strict=True,
            )
            return PdfSuccess(
                request_id=command.request_id,
                status="ok",
                payload=RenderTilesPayload(
                    operation="render_tiles",
                    value=tile_value,
                ),
            )
        rendered = await asyncio.to_thread(
            self._processor.get_manifest,
            command.parameters.render_id,
        )
        manifest_value = RenderPagesOutput.model_validate_json(
            _strict_json(rendered, context="test render manifest"),
            strict=True,
        )
        return PdfSuccess(
            request_id=command.request_id,
            status="ok",
            payload=ManifestPayload(operation="manifest", value=manifest_value),
        )
