# Copyright (c) 2026 David Osipov
"""Shared pytest fixtures for deterministic service construction."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from hypothesis import settings

from tests.helpers.app_factory import make_app_services, make_tool_service

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from nplg_mcp.services import MetadataServiceComposition
    from nplg_mcp.tools import ToolService

    type ToolServiceFactory = Callable[[Path], ToolService]
    type ToolServiceFixture = Callable[[ToolServiceFactory], ToolServiceFactory]
    type MetadataServiceFactory = Callable[[Path], MetadataServiceComposition]
    type MetadataServiceFixture = Callable[
        [MetadataServiceFactory], MetadataServiceFactory
    ]


tool_service_fixture = cast(
    "ToolServiceFixture",
    pytest.fixture,
)
app_services_fixture = cast(
    "MetadataServiceFixture",
    pytest.fixture,
)

settings.register_profile(
    "ci",
    database=None,
    deadline=None,
    derandomize=True,
    max_examples=200,
    print_blob=True,
)


@tool_service_fixture
def tool_service(tmp_path: Path) -> ToolService:
    return make_tool_service(tmp_path)


@app_services_fixture
def app_services(tmp_path: Path) -> MetadataServiceComposition:
    return make_app_services(tmp_path)
