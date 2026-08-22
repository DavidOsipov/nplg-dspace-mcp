# Copyright (c) 2026 David Osipov
"""Public strict contract surface for NPLG MCP tools."""

from .base import (
    MAX_SAFE_INTEGER,
    MIN_SAFE_INTEGER,
    ContractText,
    FrozenSequence,
    MonotonicDeadline,
    SafeInteger,
    StrictInput,
    StrictModel,
    StrictOutput,
)
from .catalog import RegisteredTool, ToolCatalog, ToolDefinition
from .inputs import (
    ArtifactInput,
    DownloadDocumentInput,
    HandleInput,
    RenderIdInput,
    RenderPagesInput,
    RenderTilesInput,
    SearchDocumentsInput,
)
from .outputs import (
    DocumentFilesOutput,
    DocumentMetadataOutput,
    DownloadDocumentOutput,
    PdfInspectionOutput,
    RenderManifestOutput,
    RenderPagesOutput,
    RenderTilesOutput,
    SearchDocumentsOutput,
)
from .profiles import DeploymentProfile, ToolAnnotations

__all__ = [
    "MAX_SAFE_INTEGER",
    "MIN_SAFE_INTEGER",
    "ArtifactInput",
    "ContractText",
    "DeploymentProfile",
    "DocumentFilesOutput",
    "DocumentMetadataOutput",
    "DownloadDocumentInput",
    "DownloadDocumentOutput",
    "FrozenSequence",
    "HandleInput",
    "MonotonicDeadline",
    "PdfInspectionOutput",
    "RegisteredTool",
    "RenderIdInput",
    "RenderManifestOutput",
    "RenderPagesInput",
    "RenderPagesOutput",
    "RenderTilesInput",
    "RenderTilesOutput",
    "SafeInteger",
    "SearchDocumentsInput",
    "SearchDocumentsOutput",
    "StrictInput",
    "StrictModel",
    "StrictOutput",
    "ToolAnnotations",
    "ToolCatalog",
    "ToolDefinition",
]
