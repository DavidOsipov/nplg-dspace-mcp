# Copyright (c) 2026 David Osipov
# mypy: disable-error-code="explicit-any,misc"
"""Differential contracts between frozen legacy behavior and the official SDK."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError

from nplg_mcp.mcp_server import create_mcp_server
from nplg_mcp.profiles import DeploymentProfile
from nplg_mcp.sdk_parity import (
    SdkParityNormalizationError,
    normalize_public_error,
    normalize_tool_catalog,
    normalize_tool_result,
)
from nplg_mcp.services import FullServiceComposition
from tests.helpers.app_factory import FIXTURE_ERROR_CANARY, make_tool_service

if TYPE_CHECKING:
    from nplg_mcp.json_types import JsonObject
    from nplg_mcp.services import MetadataServices


DIFFERENCE_LEDGER = Path("contracts/accepted-sdk-differences.json")
BASELINE_DIR = Path("contracts/baseline")
MODERN_PROTOCOL_VERSION = "2026-07-28"
INTERNAL_ERROR = -32603
_METADATA_TOOL_NAMES = (
    "get_document_metadata",
    "list_document_files",
    "search_documents",
)


def _stable_tool(name: object) -> dict[str, object]:
    """Build one minimal parity catalog entry with controlled name typing."""
    return {
        "annotations": {},
        "description": "fixture",
        "name": name,
        "title": "Fixture",
    }


def test_parity_catalog_rejects_non_array_input() -> None:
    with pytest.raises(SdkParityNormalizationError, match="must be a JSON array"):
        _ = normalize_tool_catalog({})


def test_parity_catalog_rejects_non_string_name() -> None:
    with pytest.raises(SdkParityNormalizationError, match="entry name: is invalid"):
        _ = normalize_tool_catalog([_stable_tool(1)])


def test_parity_catalog_rejects_duplicate_names() -> None:
    with pytest.raises(SdkParityNormalizationError, match="has duplicate names"):
        _ = normalize_tool_catalog([_stable_tool("same"), _stable_tool("same")])


def test_parity_tool_result_accepts_python_sdk_snake_case_projection() -> None:
    assert normalize_tool_result({"structured_content": {"ok": True}}) == {"ok": True}


def test_parity_tool_result_rejects_missing_structured_content() -> None:
    with pytest.raises(SdkParityNormalizationError, match="no structured content"):
        _ = normalize_tool_result({})


def test_parity_tool_result_rejects_non_object_structured_content() -> None:
    with pytest.raises(SdkParityNormalizationError, match="is not an object"):
        _ = normalize_tool_result({"structuredContent": []})


@pytest.mark.parametrize("code", [True, "-32603"])
def test_parity_public_error_rejects_non_integer_code(code: object) -> None:
    with pytest.raises(SdkParityNormalizationError, match="error code: is invalid"):
        _ = normalize_public_error({"code": code})


def _canonical_digest(value: object) -> str:
    """Digest one JSON value with the reviewed compact canonical representation."""
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(f"{encoded}\n".encode()).hexdigest()


def _load_digest_verified_fixture(name: str) -> JsonObject:
    """Load one immutable baseline file only after verifying its manifest digest."""
    manifest = cast(
        "JsonObject",
        json.loads((BASELINE_DIR / "manifest.json").read_text(encoding="utf-8")),
    )
    entries = manifest["entries"]
    assert isinstance(entries, list)
    expected = next(
        entry["sha256"]
        for entry in entries
        if isinstance(entry, dict) and entry.get("path") == name
    )
    raw = (BASELINE_DIR / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    return cast("JsonObject", json.loads(raw))


def _frozen_result(fixture: JsonObject, case_id: str) -> JsonObject:
    """Return one fixture's immutable normalized expected result object."""
    record = cast("JsonObject", fixture[case_id])
    expected = cast("JsonObject", record["expected"])
    payload = cast("JsonObject", expected["payload"])
    return cast("JsonObject", payload["result"])


@pytest.mark.asyncio
async def test_sdk_and_legacy_metadata_semantics_are_differentially_equal(
    app_services: MetadataServices,
) -> None:
    """Catalog, result, resource, and read semantics match without envelopes."""
    server = create_mcp_server(app_services, DeploymentProfile.ALPIC_METADATA)
    catalog_fixture = _load_digest_verified_fixture("tool-catalog.json")
    result_fixture = _load_digest_verified_fixture("result-cases.json")
    resource_fixture = _load_digest_verified_fixture("resources.json")
    legacy_catalog = [catalog_fixture[name] for name in _METADATA_TOOL_NAMES]
    legacy_result = _frozen_result(
        result_fixture,
        "tool.search_documents.modern.success",
    )
    legacy_resources = _frozen_result(resource_fixture, "resource.list.modern")
    legacy_resource = _frozen_result(
        resource_fixture,
        "resource.read-about.modern",
    )

    async with Client(server, mode=MODERN_PROTOCOL_VERSION) as client:
        sdk_catalog = await client.list_tools()
        sdk_result = await client.call_tool("search_documents", {"query": "fixture"})
        sdk_resources = await client.list_resources()
        sdk_resource = await client.read_resource("nplg://about")

    assert normalize_tool_catalog(legacy_catalog) == normalize_tool_catalog(
        sdk_catalog.tools,
    )
    assert normalize_tool_result(legacy_result) == normalize_tool_result(sdk_result)
    assert legacy_resources["resources"] == [
        resource.model_dump(mode="json", by_alias=True, exclude_none=True)
        for resource in sdk_resources.resources
    ]
    assert legacy_resource["contents"] == [
        content.model_dump(mode="json", by_alias=True, exclude_none=True)
        for content in sdk_resource.contents
    ]
    ledger = _load_difference_ledger()
    assert ledger["differences"] == [
        {
            "approval_date": "2026-08-21",
            "case_id": "metadata-tool-catalog-schema-projection",
            "frozen_value_sha256": _canonical_digest(legacy_catalog),
            "normative_source": "https://modelcontextprotocol.io/specification/2026-07-28/server/tools",
            "official_sdk_value_sha256": _canonical_digest(
                sdk_catalog.model_dump(mode="json", by_alias=True)["tools"]
            ),
            "rationale": (
                "The frozen custom protocol suppresses outputSchema and selected "
                "input-schema constraints; its retained compatibility result is "
                "ledgered until Task 14 removes the adapter."
            ),
            "reviewer": "Codex local implementation review (not release authority)",
        }
    ]


@pytest.mark.asyncio
async def test_sdk_and_legacy_generic_failures_have_the_same_safe_meaning(
    tmp_path: Path,
) -> None:
    """The same injected generic failure is sanitized identically on both paths."""
    canary = FIXTURE_ERROR_CANARY
    error_fixture = _load_digest_verified_fixture("error-cases.json")
    generic_record = cast("JsonObject", error_fixture["error.generic-canary.modern"])
    generic_expected = cast("JsonObject", generic_record["expected"])
    generic_payload = cast("JsonObject", generic_expected["payload"])
    legacy_error = cast("JsonObject", generic_payload["error"])
    tools = make_tool_service(tmp_path, fault_mode="generic_error")
    services = FullServiceComposition(tools=tools, store=tools.store)
    server = create_mcp_server(services, DeploymentProfile.PRIVATE_FULL)

    async with Client(server, mode=MODERN_PROTOCOL_VERSION) as client:
        with pytest.raises(MCPError) as captured:
            _ = await client.call_tool("search_documents", {"query": "fixture"})

    sdk_error = captured.value.error.model_dump(mode="json", by_alias=True)
    assert captured.value.error.code == INTERNAL_ERROR
    assert normalize_public_error(legacy_error) == {"code": -32603}
    assert normalize_public_error(sdk_error) == normalize_public_error(legacy_error)
    assert canary not in str(legacy_error)
    assert canary not in captured.value.error.message


def _load_difference_ledger() -> JsonObject:
    """Load the static review ledger at a synchronous test boundary."""
    raw = json.loads(DIFFERENCE_LEDGER.read_text())
    return cast("JsonObject", raw)


def test_accepted_sdk_difference_ledger_is_closed_and_digest_bound() -> None:
    """Every normalization omission has one digest-bound, review-labelled record."""
    raw = _load_difference_ledger()

    assert raw["schema_version"] == "1.0"
    differences = raw["differences"]
    assert isinstance(differences, list)
    for entry in differences:
        assert isinstance(entry, dict)
        assert set(entry) == {
            "approval_date",
            "case_id",
            "frozen_value_sha256",
            "normative_source",
            "official_sdk_value_sha256",
            "rationale",
            "reviewer",
        }
