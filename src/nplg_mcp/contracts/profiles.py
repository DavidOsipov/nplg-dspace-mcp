# Copyright (c) 2026 David Osipov
"""Closed deployment-profile and MCP annotation contracts."""

from __future__ import annotations

from pydantic import Field

from nplg_mcp.profiles import DeploymentProfile

from .base import StrictModel

__all__ = ["DeploymentProfile", "ToolAnnotations"]


class ToolAnnotations(StrictModel):
    """Strict MCP tool behavior hints serialized with protocol aliases."""

    read_only_hint: bool = Field(serialization_alias="readOnlyHint")
    destructive_hint: bool = Field(serialization_alias="destructiveHint")
    idempotent_hint: bool = Field(serialization_alias="idempotentHint")
    open_world_hint: bool = Field(serialization_alias="openWorldHint")
