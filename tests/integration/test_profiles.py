# Copyright (c) 2026 David Osipov
"""Runtime-composition tests for the closed deployment profiles."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from pydantic import SecretStr
from pypdf import PdfWriter

import nplg_mcp.app as app_module
from nplg_mcp.config import ApiPrincipalCredential, load_config
from nplg_mcp.errors import AppError, ErrorCode
from tests.helpers.app_factory import base_environment
from tests.helpers.pdf_factory import make_raster_pdf

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import BinaryIO

    from nplg_mcp.storage import ContentAddressedStore

_PROJECT_ROOT = Path(__file__).parents[2]
_RUNTIME_DEPENDENCY_TOUCHED = "runtime dependency constructed"
_SERVICES_CONSTRUCTED_EARLY = "services constructed before config validation"


def test_alpic_metadata_starts_without_importing_full_profile_components() -> None:
    script = r"""
import asyncio
import importlib.abc
from pathlib import Path
import sys

source_root = Path.cwd().resolve() / "src"
sys.path.insert(0, source_root.as_posix())

blocked = frozenset({
    "nplg_mcp.downloader",
    "nplg_mcp.full_runtime",
    "nplg_mcp.pdf",
    "nplg_mcp.pdf_executor",
    "nplg_mcp.pdf_worker_client",
    "nplg_mcp.pdf_worker_main",
    "nplg_mcp.scanner",
    "nplg_mcp.storage",
})

class BlockFullProfile(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        del path, target
        if fullname in blocked:
            raise RuntimeError("full profile module touched: " + fullname)
        return None

sys.meta_path.insert(0, BlockFullProfile())
import nplg_mcp.app as app_module
from nplg_mcp.app import create_app
from nplg_mcp.config import load_config

assert Path(app_module.__file__).resolve().is_relative_to(source_root)

config = load_config({
    "NODE_ENV": "production",
    "DEPLOYMENT_PROFILE": "alpic-metadata",
    "ALPIC_HOST": "mcp.example.test",
    "ASSET_SIGNING_SECRET": "s" * 32,
    "API_PRINCIPALS_JSON": (
        '[{"principal_id":"researcher","api_key":"' + ("k" * 32) + '"}]'
    ),
    "ALLOW_ANONYMOUS": "false",
})
application = create_app(config)
assert application.services is not None
assert application.services.store is None
assert [item["name"] for item in application.services.tools.list_tools()] == [
    "get_document_metadata",
    "list_document_files",
    "search_documents",
]
application.services.tools.ensure_ready()
assert blocked.isdisjoint(sys.modules)
assert application.services.http_client is not None
asyncio.run(application.services.http_client.aclose())
"""

    completed = subprocess.run(  # noqa: S603
        (sys.executable, "-I", "-c", script),
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr


def test_private_full_uses_the_disposable_pdf_executor_without_importing_pdfium() -> (
    None
):
    script = r"""
import asyncio
import importlib.abc
from pathlib import Path
import sys
import tempfile

source_root = Path.cwd().resolve() / "src"
sys.path.insert(0, source_root.as_posix())

class BlockInProcessPdf(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        del path, target
        if fullname == "nplg_mcp.pdf":
            raise RuntimeError("in-process PDF module touched by control plane")
        return None

sys.meta_path.insert(0, BlockInProcessPdf())
import nplg_mcp.app as app_module
from nplg_mcp.app import create_app
from nplg_mcp.config import load_config
from nplg_mcp.pdf_worker_client import SubprocessPdfExecutor

assert Path(app_module.__file__).resolve().is_relative_to(source_root)

with tempfile.TemporaryDirectory() as cache_dir:
    config = load_config({
        "NODE_ENV": "test",
        "DEPLOYMENT_PROFILE": "private-full",
        "CACHE_DIR": cache_dir,
        "ASSET_SIGNING_SECRET": "s" * 32,
        "ALLOW_ANONYMOUS": "true",
    })
    application = create_app(config)
    assert application.services is not None
    assert isinstance(application.services.tools.pdf, SubprocessPdfExecutor)
    assert "nplg_mcp.pdf" not in sys.modules
    assert application.services.http_client is not None
    asyncio.run(application.services.http_client.aclose())
"""

    completed = subprocess.run(  # noqa: S603
        (sys.executable, "-I", "-c", script),
        cwd=_PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.asyncio
async def test_private_full_tool_call_crosses_the_disposable_worker_boundary(
    tmp_path: Path,
) -> None:
    config = load_config(
        base_environment(
            CACHE_DIR=str(tmp_path / "cache"),
            DEPLOYMENT_PROFILE="private-full",
        )
    )
    application = app_module.create_app(config)
    services = application.services
    assert services is not None
    assert services.store is not None
    store = cast("ContentAddressedStore", services.store)
    fixture = make_raster_pdf(
        tmp_path / "profile-worker-source.pdf",
        width=64,
        height=48,
        dpi=200,
    )
    artifact = store.put_bytes(
        fixture.path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    try:
        inspected = await services.tools.call(
            "inspect_pdf",
            {"artifact_id": artifact.object_id},
        )
    finally:
        assert services.http_client is not None
        await services.http_client.aclose()

    assert inspected.get("artifact_id") == artifact.object_id
    assert inspected.get("page_count") == 1


@pytest.mark.asyncio
async def test_private_full_worker_preserves_configured_render_ceiling(
    tmp_path: Path,
) -> None:
    config = load_config(
        base_environment(
            CACHE_DIR=str(tmp_path / "cache"),
            DEPLOYMENT_PROFILE="private-full",
            MAX_RENDER_PAGES="1",
        )
    )
    application = app_module.create_app(config)
    services = application.services
    assert services is not None
    assert services.store is not None
    store = cast("ContentAddressedStore", services.store)
    writer = PdfWriter()
    _ = writer.add_blank_page(width=72, height=72)
    _ = writer.add_blank_page(width=72, height=72)
    source_path = tmp_path / "two-pages.pdf"
    with source_path.open("wb") as stream:
        write_pdf = cast("Callable[[BinaryIO], object]", writer.write)
        _ = write_pdf(stream)
    artifact = store.put_bytes(
        source_path.read_bytes(),
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    try:
        with pytest.raises(AppError) as caught:
            _ = await services.tools.call(
                "render_pdf_pages",
                {"artifact_id": artifact.object_id, "pages": [1, 2]},
            )
    finally:
        assert services.http_client is not None
        await services.http_client.aclose()

    assert caught.value.code is ErrorCode.INVALID_INPUT


def test_distributed_full_fails_before_runtime_dependency_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(
        base_environment(
            CACHE_DIR=str(tmp_path),
            DEPLOYMENT_PROFILE="distributed-full",
        )
    )

    def fail_on_touch(*_args: object, **_kwargs: object) -> None:
        raise AssertionError(_RUNTIME_DEPENDENCY_TOUCHED)

    monkeypatch.setattr(httpx, "AsyncClient", fail_on_touch)
    monkeypatch.setattr(app_module, "create_bound_http_transport", fail_on_touch)

    with pytest.raises(ValueError, match="distributed-full is not implemented"):
        _ = app_module.create_app(config)


def test_create_app_rejects_forged_anonymous_production_config_before_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = load_config(
        base_environment(
            NODE_ENV="test",
            CACHE_DIR=str(tmp_path),
            DEPLOYMENT_PROFILE="alpic-metadata",
        )
    )
    forged = replace(valid, environment="production", allow_anonymous=True)

    def fail_on_touch(_config: object) -> None:
        raise AssertionError(_SERVICES_CONSTRUCTED_EARLY)

    monkeypatch.setattr(app_module, "_runtime_services", fail_on_touch)

    with pytest.raises(ValueError, match="anonymous"):
        _ = app_module.create_app(forged)


def test_create_app_rejects_forged_production_config_without_principals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = load_config(
        base_environment(
            NODE_ENV="test",
            CACHE_DIR=str(tmp_path),
            DEPLOYMENT_PROFILE="alpic-metadata",
        )
    )
    forged = replace(
        valid,
        environment="production",
        allow_anonymous=False,
        api_principals=(),
    )

    def fail_on_touch(_config: object) -> None:
        raise AssertionError(_SERVICES_CONSTRUCTED_EARLY)

    monkeypatch.setattr(app_module, "_runtime_services", fail_on_touch)

    with pytest.raises(ValueError, match="named API principal registry"):
        _ = app_module.create_app(forged)


def test_create_app_rejects_forged_production_principal_cap_without_reserve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = load_config(
        base_environment(
            NODE_ENV="test",
            CACHE_DIR=str(tmp_path),
            DEPLOYMENT_PROFILE="alpic-metadata",
        )
    )
    credential = ApiPrincipalCredential(
        principal_id="researcher",
        bearer_token=SecretStr("t" * 32),
    )
    forged = replace(
        valid,
        environment="production",
        allow_anonymous=False,
        api_principals=(credential,),
        max_concurrent_mcp_requests=4,
        max_concurrent_mcp_requests_per_principal=4,
    )

    def fail_on_touch(_config: object) -> None:
        raise AssertionError(_SERVICES_CONSTRUCTED_EARLY)

    monkeypatch.setattr(app_module, "_runtime_services", fail_on_touch)

    with pytest.raises(ValueError, match="reserve global capacity"):
        _ = app_module.create_app(forged)


def test_private_full_production_fails_before_runtime_dependency_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = load_config(
        base_environment(
            CACHE_DIR=str(tmp_path),
            DEPLOYMENT_PROFILE="private-full",
        )
    )
    forged = replace(
        valid,
        environment="production",
        allow_anonymous=False,
        api_principals=(
            ApiPrincipalCredential(
                principal_id="researcher",
                bearer_token=SecretStr("t" * 32),
            ),
        ),
    )

    def fail_on_touch(_config: object) -> None:
        raise AssertionError(_SERVICES_CONSTRUCTED_EARLY)

    monkeypatch.setattr(app_module, "_runtime_services", fail_on_touch)

    with pytest.raises(ValueError, match="OS-isolated PDF worker"):
        _ = app_module.create_app(forged)
