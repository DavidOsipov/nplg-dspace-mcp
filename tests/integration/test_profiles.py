# Copyright (c) 2026 David Osipov
"""Runtime-composition tests for the closed deployment profiles."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from pydantic import SecretStr
from pypdf import PdfWriter

import nplg_mcp.app as app_module
from nplg_mcp import capabilities
from nplg_mcp.capabilities import load_alpic_tasks_verdict
from nplg_mcp.config import ApiPrincipalCredential, load_config
from nplg_mcp.contracts import PdfInspectionOutput
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.profiles import DeploymentProfile, tool_names_for_profile
from nplg_mcp.services import FullServiceComposition, MetadataServiceComposition
from tests.helpers.app_factory import (
    base_environment,
    make_app_services,
    make_tool_service,
)
from tests.helpers.pdf_factory import make_raster_pdf

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import BinaryIO

    from nplg_mcp.storage import ContentAddressedStore

_PROJECT_ROOT = Path(__file__).parents[2]
_RUNTIME_DEPENDENCY_TOUCHED = "runtime dependency constructed"
_SERVICES_CONSTRUCTED_EARLY = "services constructed before config validation"
_INVALID_PARAMS = -32602
_METHOD_NOT_FOUND = -32601
_ALPIC_TASKS_CAPABILITY = _PROJECT_ROOT / "contracts" / "alpic-tasks-capability.json"


def _synthetic_supported_tasks_verdict() -> (
    capabilities.SupportedAlpicTasksCapabilityVerdict
):
    payload = capabilities.canonical_model_json(
        capabilities.probe_alpic_tasks_capability()
    )
    payload.update(
        {
            "extension_revision_state": "stable",
            "mcp_version": "2.1.0",
            "mcp_types_version": "2.1.0",
            "installed_sdk_tree_sha256": "1" * 64,
            "sdk_server_support": "supported",
            "sdk_client_support": "supported",
            "source_evidence_digest": "2" * 64,
            "provider_integration": "proven",
            "task_creation_durability": "proven",
            "restart_recovery": "proven",
            "cancellation": "proven",
            "isolation": "proven",
            "retention": "proven",
            "artifact_delivery": "proven",
            "client_support": "proven",
            "documentation_provenance": (
                "Synthetic schema-reachability fixture; not operational evidence."
            ),
            "supported": True,
            "blockers": [],
            "reviewed_date": "2026-08-25",
            "live_evidence": {
                "environment_id": "synthetic-environment",
                "deployment_id": "synthetic-deployment",
                "pack_sha256": "3" * 64,
                "sdk_wheel_sha256": "4" * 64,
                "protocol_revision_sha256": "5" * 64,
                "client_identities_sha256": "6" * 64,
                "evidence_digest": "7" * 64,
                "observed_at": "2026-08-25T00:00:00Z",
            },
        }
    )
    payload["verdict_digest"] = capabilities.canonical_json_sha256(
        {key: value for key, value in payload.items() if key != "verdict_digest"}
    )
    return capabilities.validate_synthetic_alpic_tasks_verdict(payload)


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
    "NODE_ENV": "test",
    "DEPLOYMENT_PROFILE": "alpic-metadata",
    "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
    "CURSOR_SIGNING_SECRET": "c" * 32,
    "ALLOW_ANONYMOUS": "true",
})
application = create_app(config)
assert application.services is not None
assert not hasattr(application.services, "store")
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


@pytest.mark.asyncio
async def test_alpic_metadata_uses_a_cursor_secret_without_an_asset_secret() -> None:
    """Metadata composition has neither asset-token state nor its HTTP route."""
    config = load_config(
        {
            "NODE_ENV": "test",
            "DEPLOYMENT_PROFILE": "alpic-metadata",
            "CURSOR_SIGNING_SECRET": "c" * 32,
            "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
            "ALLOW_ANONYMOUS": "true",
        }
    )

    assert config.asset_signing_secret is None
    application = app_module.create_app(config)
    services = application.services
    assert services is not None
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://mcp.example.test",
        ) as client:
            response = await client.get("/assets/not-present")
    finally:
        assert services.http_client is not None
        await services.http_client.aclose()

    assert response.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_alpic_metadata_mcp_does_not_register_resource_routes() -> None:
    """Metadata-only MCP advertises and registers neither resource route."""
    config = load_config(
        {
            "NODE_ENV": "test",
            "DEPLOYMENT_PROFILE": "alpic-metadata",
            "CURSOR_SIGNING_SECRET": "c" * 32,
            "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
            "ALLOW_ANONYMOUS": "true",
        }
    )
    application = app_module.create_app(config)
    services = application.services
    assert services is not None
    mcp_server = application.mcp_server
    assert mcp_server is not None
    try:
        async with Client(mcp_server, mode="2026-07-28") as client:
            assert client.server_capabilities.resources is None
            with pytest.raises(MCPError) as list_caught:  # type: ignore[misc]
                _ = await client.list_resources()
            with pytest.raises(MCPError) as read_caught:  # type: ignore[misc]
                _ = await client.read_resource("nplg://about")
    finally:
        assert services.http_client is not None
        await services.http_client.aclose()

    assert list_caught.value.error.code == _METHOD_NOT_FOUND
    assert read_caught.value.error.code == _METHOD_NOT_FOUND


def test_create_app_rejects_full_services_for_metadata_profile(tmp_path: Path) -> None:
    """Injected full services cannot expand a metadata-only application."""
    config = load_config(
        base_environment(
            CACHE_DIR=str(tmp_path / "metadata-config"),
            DEPLOYMENT_PROFILE="alpic-metadata",
        )
    )
    tools = make_tool_service(
        tmp_path / "full-services",
        deployment_profile="private-full",
    )
    store = tools.store
    services = FullServiceComposition(tools=tools, store=store)

    with pytest.raises(ValueError, match=r"deployment profile.*service composition"):
        _ = app_module.create_app(config, services=services)


def test_create_app_rejects_metadata_services_for_private_profile(
    tmp_path: Path,
) -> None:
    """Injected metadata services cannot leave a private-full profile incomplete."""
    config = load_config(
        base_environment(
            CACHE_DIR=str(tmp_path / "private-config"),
            DEPLOYMENT_PROFILE="private-full",
        )
    )
    services = make_app_services(tmp_path / "metadata-services")
    assert isinstance(services, MetadataServiceComposition)

    with pytest.raises(ValueError, match=r"deployment profile.*service composition"):
        _ = app_module.create_app(config, services=services)


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
from nplg_mcp.services import FullServiceComposition

assert Path(app_module.__file__).resolve().is_relative_to(source_root)

with tempfile.TemporaryDirectory() as cache_dir:
    config = load_config({
        "NODE_ENV": "test",
        "DEPLOYMENT_PROFILE": "private-full",
        "CACHE_DIR": cache_dir,
        "ASSET_SIGNING_SECRET": "s" * 32,
        "CURSOR_SIGNING_SECRET": "c" * 32,
        "ALLOW_ANONYMOUS": "true",
    })
    application = create_app(config)
    assert application.services is not None
    assert isinstance(application.services, FullServiceComposition)
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


def test_private_full_can_select_the_unix_socket_pdf_worker() -> None:
    """Exercise the profile composition seam for the isolated worker transport."""
    script = r"""
import asyncio
import tempfile
from nplg_mcp.app import create_app
from nplg_mcp.config import load_config
from nplg_mcp.services import FullServiceComposition
from nplg_mcp.storage_lifecycle import RetentionPolicy

with tempfile.TemporaryDirectory() as cache_dir:
    config = load_config({
        "NODE_ENV": "test",
        "DEPLOYMENT_PROFILE": "private-full",
        "PDF_EXECUTOR": "unix-worker",
        "CACHE_DIR": cache_dir,
        "ASSET_SIGNING_SECRET": "s" * 32,
        "CURSOR_SIGNING_SECRET": "c" * 32,
        "ALLOW_ANONYMOUS": "true",
    })
    application = create_app(config)
    assert isinstance(application.services, FullServiceComposition)
    assert type(application.services.tools.pdf).__name__ == "UnixSocketPdfExecutor"
    scanner = application.services.tools.downloader.scanner
    assert type(scanner).__name__ == "ClamAvUnixSocketScanner"
    assert application.services.tools.downloader.require_scanner
    expected_retention = RetentionPolicy(
        maximum_age_seconds=config.retention_max_age_seconds,
        maximum_bytes=config.cache_max_bytes,
        maximum_objects=config.retention_max_objects,
        minimum_free_bytes=config.retention_min_free_bytes,
        minimum_free_inodes=config.retention_min_free_inodes,
    )
    assert application.services.tools.downloader.retention_policy == expected_retention
    assert application.services.tools.downloader.retention_clock is not None
    application.services.store.prune(
        expected_retention,
        clock=application.services.tools.downloader.retention_clock(),
    )
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
    assert isinstance(services, FullServiceComposition)
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

    assert isinstance(inspected, PdfInspectionOutput)
    assert inspected.artifact_id == artifact.object_id
    assert inspected.page_count == 1


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
    assert isinstance(services, FullServiceComposition)
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
    tasks_verdict = load_alpic_tasks_verdict(_ALPIC_TASKS_CAPABILITY)
    assert tasks_verdict.supported is False
    assert "PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE" in tasks_verdict.blockers
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
    monkeypatch.setattr(
        app_module,
        "probe_alpic_tasks_capability",
        lambda: tasks_verdict,
    )

    with pytest.raises(ValueError, match="Alpic Tasks capability is unsupported"):
        _ = app_module.create_app(config)


def test_distributed_full_probe_error_fails_before_dependency_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(
        base_environment(
            CACHE_DIR=str(tmp_path),
            DEPLOYMENT_PROFILE="distributed-full",
        )
    )

    def fail_probe() -> capabilities.AlpicTasksCapabilityVerdict:
        message = "synthetic probe drift"
        raise capabilities.CapabilityContractError(message)

    def fail_on_touch(*_args: object, **_kwargs: object) -> None:
        raise AssertionError(_RUNTIME_DEPENDENCY_TOUCHED)

    monkeypatch.setattr(app_module, "probe_alpic_tasks_capability", fail_probe)
    monkeypatch.setattr(httpx, "AsyncClient", fail_on_touch)
    monkeypatch.setattr(app_module, "create_bound_http_transport", fail_on_touch)

    with pytest.raises(ValueError, match="capability assessment failed closed"):
        _ = app_module.create_app(config)


def test_synthetic_supported_tasks_still_requires_a_separate_plan(
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

    monkeypatch.setattr(
        app_module,
        "probe_alpic_tasks_capability",
        _synthetic_supported_tasks_verdict,
    )
    monkeypatch.setattr(httpx, "AsyncClient", fail_on_touch)
    monkeypatch.setattr(app_module, "create_bound_http_transport", fail_on_touch)

    with pytest.raises(ValueError, match="separately approved implementation plan"):
        _ = app_module.create_app(config)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "profile",
    [DeploymentProfile.ALPIC_METADATA, DeploymentProfile.PRIVATE_FULL],
)
async def test_existing_profiles_never_probe_alpic_tasks(
    profile: DeploymentProfile,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(
        base_environment(
            CACHE_DIR=str(tmp_path),
            DEPLOYMENT_PROFILE=profile.value,
        )
    )

    def fail_probe() -> capabilities.AlpicTasksCapabilityVerdict:
        message = "Alpic Tasks probe touched by an existing profile"
        raise AssertionError(message)

    monkeypatch.setattr(app_module, "probe_alpic_tasks_capability", fail_probe)

    application = app_module.create_app(config)
    services = application.services
    assert services is not None
    assert services.http_client is not None
    await services.http_client.aclose()


def test_distributed_full_catalog_helper_fails_closed() -> None:
    """An unreachable profile must never inherit the private tool catalog."""
    with pytest.raises(ValueError, match="distributed-full is not implemented"):
        _ = tool_names_for_profile(DeploymentProfile.DISTRIBUTED_FULL)


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


def test_production_oauth_gate_rejects_before_services_without_static_fallback(
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

    with pytest.raises(ValueError, match="OAuth provider capability is unsupported"):
        _ = app_module.create_app(forged)


def test_create_app_rejects_forged_production_static_principal_before_services(
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

    with pytest.raises(ValueError, match=r"static authentication.*production"):
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
    )

    def fail_on_touch(_config: object) -> None:
        raise AssertionError(_SERVICES_CONSTRUCTED_EARLY)

    monkeypatch.setattr(app_module, "_runtime_services", fail_on_touch)

    with pytest.raises(ValueError, match="OS-isolated PDF worker"):
        _ = app_module.create_app(forged)
