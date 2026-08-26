# Copyright (c) 2026 David Osipov
"""Adversarial coverage for fail-closed changed-branch guards."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
from http import HTTPStatus
from typing import TYPE_CHECKING, cast

import pytest
from bs4 import BeautifulSoup

from nplg_mcp import parsers as parser_module
from nplg_mcp.config import load_config
from nplg_mcp.downloader import DocumentDownloader
from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.parsers import parse_item_page
from nplg_mcp.storage import ContentAddressedStore
from nplg_mcp.storage_lifecycle import RetentionPolicy
from nplg_mcp.tools import ToolService, ToolServiceDependencies
from tests.helpers.app_factory import base_environment, make_tool_service
from tests.helpers.lease_store import lease_barrier_store

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

    from nplg_mcp.http_types import HttpClientProtocol

_ITEM_HANDLE = "1234/499564"
_ITEM_SOURCE = f"https://dspace.nplg.gov.ge/handle/{_ITEM_HANDLE}"
_RENDER_ID = "rnd_" + "a" * 32
_INDEXED_ARTIFACT_ID = "doc_" + "b" * 64
_FIELD_LIMIT_OVERFLOW = 65_537


class _RejectedLease:
    """Context manager that injects one storage-boundary AppError."""

    def __init__(self, error: AppError) -> None:
        super().__init__()
        self._error = error

    def __enter__(self) -> Path:
        raise self._error

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback


def _item_document(*, field_value: str = "Title") -> str:
    return (
        '<div id="aspect_artifactbrowser_ItemViewer_div_item-view">'
        f"<code>{_ITEM_HANDLE}</code>"
        '<table class="itemDisplayTable">'
        f"<tr><td>Title:</td><td>{field_value}</td></tr>"
        "</table></div>"
    )


def _install_rejected_lease(
    monkeypatch: pytest.MonkeyPatch,
    store: ContentAddressedStore,
    error: AppError,
) -> None:
    def reject_lease(_relative_path: str) -> _RejectedLease:
        return _RejectedLease(error)

    monkeypatch.setattr(store, "lease_asset", reject_lease)


def test_metadata_profile_rejects_private_asset_signing_capability(
    tmp_path: Path,
) -> None:
    environment = base_environment(
        CACHE_DIR=str(tmp_path),
        DEPLOYMENT_PROFILE="alpic-metadata",
    )
    del environment["ASSET_SIGNING_SECRET"]
    config = load_config(environment)

    with pytest.raises(ValueError, match="asset signing is unavailable"):
        _ = config.require_asset_signing_secret()


def test_downloader_rejects_half_configured_retention_authority(
    tmp_path: Path,
) -> None:
    policy = RetentionPolicy(
        maximum_age_seconds=3600,
        maximum_bytes=1024,
        maximum_objects=1,
        minimum_free_bytes=64 * 1024 * 1024,
        minimum_free_inodes=128,
    )

    with pytest.raises(ValueError, match="configured together"):
        _ = DocumentDownloader(
            client=cast("HttpClientProtocol", object()),
            store=ContentAddressedStore(tmp_path),
            max_bytes=1024,
            retention_policy=policy,
            retention_clock=None,
        )


def test_html_tree_recount_rejects_post_preflight_field_amplification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The independently constructed DOM must retain its own field ceiling."""
    amplified = BeautifulSoup(
        _item_document(field_value="x" * _FIELD_LIMIT_OVERFLOW),
        "lxml",
    )

    def amplified_tree_builder(_html: str, _features: str) -> BeautifulSoup:
        return amplified

    monkeypatch.setattr(parser_module, "BeautifulSoup", amplified_tree_builder)

    with pytest.raises(AppError, match="field code-point limit") as caught:
        _ = parse_item_page(
            _item_document(),
            expected_handle=_ITEM_HANDLE,
            source_url=_ITEM_SOURCE,
        )

    assert caught.value.code is ErrorCode.UPSTREAM_FAILURE


def test_private_readiness_rejects_an_unsatisfied_lifecycle(
    tmp_path: Path,
) -> None:
    store, _policy, _clock = lease_barrier_store(tmp_path / "lifecycle")
    store.release_lease_barrier()
    first = store.put_bytes(
        b"first leased document",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    second = store.put_bytes(
        b"second leased document",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    collaborators = make_tool_service(tmp_path / "collaborators")
    tools = ToolService(
        dependencies=ToolServiceDependencies(
            repository=collaborators.repository,
            downloader=collaborators.downloader,
            pdf=collaborators.pdf,
            store=store,
        ),
        config=replace(collaborators.config, cache_dir=store.root),
    )

    with ExitStack() as leases:
        _ = leases.enter_context(store.lease_asset(first.relative_path))
        _ = leases.enter_context(store.lease_asset(second.relative_path))
        with pytest.raises(AppError, match="lifecycle is not ready") as caught:
            tools.ensure_ready()

    assert caught.value.code is ErrorCode.CACHE_FULL
    assert caught.value.http_status == HTTPStatus.SERVICE_UNAVAILABLE


def test_metadata_profile_exposes_no_private_resources(tmp_path: Path) -> None:
    tools = make_tool_service(tmp_path, deployment_profile="alpic-metadata")

    assert tools.list_resources() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("lease_error_code", "expected_code"),
    [
        pytest.param(
            ErrorCode.INTERNAL_ERROR,
            ErrorCode.INTERNAL_ERROR,
            id="unexpected-store-error-is-preserved",
        ),
        pytest.param(
            ErrorCode.NOT_FOUND,
            ErrorCode.INTERNAL_ERROR,
            id="existing-index-not-found-race-is-corruption",
        ),
    ],
)
async def test_render_index_lease_errors_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lease_error_code: ErrorCode,
    expected_code: ErrorCode,
) -> None:
    tools = make_tool_service(tmp_path)
    index_path = (
        tools.store.root
        / "renders"
        / _RENDER_ID
        / "resources"
        / _INDEXED_ARTIFACT_ID
        / "index.json"
    )
    index_path.parent.mkdir(parents=True, mode=0o700)
    _ = index_path.write_text("{}", encoding="utf-8")
    index_path.chmod(0o600)
    lease_error = AppError(
        lease_error_code,
        "Injected render-index lease failure.",
        http_status=(
            HTTPStatus.NOT_FOUND
            if lease_error_code is ErrorCode.NOT_FOUND
            else HTTPStatus.INTERNAL_SERVER_ERROR
        ),
    )
    _install_rejected_lease(monkeypatch, tools.store, lease_error)

    with pytest.raises(AppError) as caught:
        _ = await tools.read_resource(f"nplg://artifact/{_INDEXED_ARTIFACT_ID}")

    assert caught.value.code is expected_code
    if lease_error_code is ErrorCode.INTERNAL_ERROR:
        assert caught.value is lease_error
    else:
        assert caught.value.__cause__ is lease_error


@pytest.mark.asyncio
async def test_document_resource_preserves_unexpected_lease_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = make_tool_service(tmp_path)
    document = tools.store.put_bytes(
        b"%PDF-1.7\nunexpected lease error",
        namespace="documents",
        filename="source.pdf",
        media_type="application/pdf",
    )
    lease_error = AppError(
        ErrorCode.INTERNAL_ERROR,
        "Injected document lease failure.",
        http_status=HTTPStatus.INTERNAL_SERVER_ERROR,
    )
    _install_rejected_lease(monkeypatch, tools.store, lease_error)

    with pytest.raises(AppError) as caught:
        _ = await tools.read_resource(f"nplg://artifact/{document.object_id}")

    assert caught.value is lease_error
