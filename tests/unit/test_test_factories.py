# Copyright (c) 2026 David Osipov
"""Unit tests for shared deterministic service factories."""

from __future__ import annotations

from typing import TYPE_CHECKING

from nplg_mcp.config import load_config
from nplg_mcp.tools import ToolService
from tests.helpers.app_factory import (
    base_environment,
    make_app_services,
    make_tool_service,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_shared_factories_reproduce_current_service_defaults(tmp_path: Path) -> None:
    environment = base_environment(CACHE_DIR=str(tmp_path))
    config = load_config(environment)
    service = make_tool_service(tmp_path)
    services = make_app_services(tmp_path)

    assert isinstance(service, ToolService)
    assert service.config == config
    assert service.config.pdf_executor == "serialized"
    assert service.config.max_concurrent_pdf_jobs == 1
    assert service.list_tools() == services.tools.list_tools()
    assert services.store.root == tmp_path
    assert services.http_client is None
