# Copyright (c) 2026 David Osipov
"""Strict runtime-contract tests for the Phase 2 tool catalog."""

from __future__ import annotations

import asyncio
import math
from dataclasses import replace
from typing import TYPE_CHECKING, Annotated, cast

import pytest
from pydantic import Field, ValidationError

from nplg_mcp.contracts import (
    DeploymentProfile,
    MonotonicDeadline,
    RenderPagesInput,
    RenderPagesOutput,
    SafeInteger,
    SearchDocumentsInput,
    SearchDocumentsOutput,
    StrictInput,
    StrictOutput,
    ToolAnnotations,
    ToolCatalog,
    ToolDefinition,
)
from nplg_mcp.contracts.base import reject_unsafe_text
from nplg_mcp.errors import AppError, to_public_error

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from nplg_mcp.contracts.outputs import SearchDocumentRecord
    from nplg_mcp.tools import ToolService

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_EXPECTED_TOOL_COUNT = 8
_CLOCK_CREATED_AT = 10.0
_CLOCK_EXPIRES_AT = 70.0
_MAX_DEADLINE_BUDGET = 60.0


class FiniteScoreOutput(StrictOutput):
    """Probe model proving finite strict floating-point output policy."""

    score: Annotated[
        float,
        Field(strict=True, allow_inf_nan=False, ge=0.0, le=1.0),
    ]


class SafeIntegerProbe(StrictInput):
    """Probe model for the shared cross-language JSON integer policy."""

    value: SafeInteger


def _safe_integer_probe(value: object) -> SafeIntegerProbe:
    payload: dict[str, object] = {"value": value}
    return SafeIntegerProbe.model_validate(payload, strict=True)


def test_explicit_text_validator_rejects_control_characters() -> None:
    with pytest.raises(ValueError, match="prohibited control"):
        _ = reject_unsafe_text("safe\u0000unsafe")


def test_explicit_query_validator_rejects_blank_normalized_text() -> None:
    with pytest.raises(ValueError, match="non-whitespace"):
        _ = SearchDocumentsInput.non_blank_query("   ")


def _valid_search_output() -> SearchDocumentsOutput:
    payload: dict[str, object] = {
        "items": [
            {
                "authors": ["Author"],
                "canonical_url": ("https://dspace.nplg.gov.ge/handle/1234/560449"),
                "handle": "1234/560449",
                "issue_date": None,
                "title": "Fixture",
            }
        ],
        "next_cursor": None,
        "next_offset": None,
        "source_url": "https://dspace.nplg.gov.ge/simple-search",
        "total": 1,
    }
    return SearchDocumentsOutput.model_validate(payload, strict=True)


def _search_catalog(
    handler: Callable[[SearchDocumentsInput], Awaitable[SearchDocumentsOutput]],
) -> ToolCatalog:
    return ToolCatalog((_search_definition(handler),))


def _search_definition(
    handler: Callable[[SearchDocumentsInput], Awaitable[SearchDocumentsOutput]],
) -> ToolDefinition[SearchDocumentsInput, SearchDocumentsOutput]:
    return ToolDefinition[SearchDocumentsInput, SearchDocumentsOutput](
        name="search_documents",
        title="Search",
        description="Search fixture",
        input_model=SearchDocumentsInput,
        output_model=SearchDocumentsOutput,
        handler=handler,
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=True,
        ),
        profiles=frozenset({DeploymentProfile.ALPIC_METADATA}),
    )


def test_every_tool_declares_closed_input_and_output_schemas(
    tool_service: ToolService,
) -> None:
    tools = tool_service.list_tools()
    assert len(tools) == _EXPECTED_TOOL_COUNT
    for tool in tools:
        input_schema = cast("dict[str, object]", tool["inputSchema"])
        output_schema = cast("dict[str, object]", tool["outputSchema"])
        assert input_schema["additionalProperties"] is False
        assert output_schema["additionalProperties"] is False


@pytest.mark.asyncio
async def test_tool_service_returns_the_declared_strict_output(
    tool_service: ToolService,
) -> None:
    result = await tool_service.call("search_documents", {"query": "fixture"})
    assert isinstance(result, SearchDocumentsOutput)
    assert result.total == 1


@pytest.mark.asyncio
async def test_invalid_handler_output_is_rejected_without_leaking_values() -> None:
    async def invalid_handler(_: SearchDocumentsInput) -> SearchDocumentsOutput:
        return cast("SearchDocumentsOutput", {"unexpected": "secret-value"})

    catalog = _search_catalog(invalid_handler)
    with pytest.raises(AppError) as raised:
        _ = await catalog.call("search_documents", {"query": "x"})
    assert "secret-value" not in str(to_public_error(raised.value))


@pytest.mark.asyncio
async def test_constructed_or_nested_invalid_model_is_revalidated() -> None:
    invalid = SearchDocumentsOutput.model_construct(
        items=(cast("SearchDocumentRecord", {"unexpected": "canary"}),),
        next_cursor=None,
        next_offset=None,
        source_url="https://dspace.nplg.gov.ge/simple-search",
        total=1,
    )

    async def constructed_handler(_: SearchDocumentsInput) -> SearchDocumentsOutput:
        return invalid

    with pytest.raises(AppError) as raised:
        _ = await _search_catalog(constructed_handler).call(
            "search_documents",
            {"query": "x"},
        )
    assert "canary" not in str(to_public_error(raised.value))


@pytest.mark.asyncio
async def test_catalog_rejects_unknown_tools_and_unknown_input_fields() -> None:
    async def handler(_: SearchDocumentsInput) -> SearchDocumentsOutput:
        return _valid_search_output()

    catalog = _search_catalog(handler)
    with pytest.raises(AppError):
        _ = await catalog.call("missing", {})
    with pytest.raises(AppError) as raised:
        _ = await catalog.call(
            "search_documents",
            {"query": "x", "unexpected": "secret"},
        )
    assert "secret" not in str(to_public_error(raised.value))


def test_tool_definition_rejects_invalid_catalog_metadata() -> None:
    async def handler(_: SearchDocumentsInput) -> SearchDocumentsOutput:
        return _valid_search_output()

    valid = _search_definition(handler)
    with pytest.raises(ValueError, match="tool name is invalid"):
        _ = replace(valid, name="Invalid-name")
    with pytest.raises(ValueError, match="tool title length is invalid"):
        _ = replace(valid, title="")
    with pytest.raises(ValueError, match="tool description length is invalid"):
        _ = replace(valid, description="")
    with pytest.raises(ValueError, match="at least one deployment profile"):
        _ = replace(valid, profiles=frozenset[DeploymentProfile]())


def test_tool_catalog_rejects_empty_and_duplicate_definitions() -> None:
    async def handler(_: SearchDocumentsInput) -> SearchDocumentsOutput:
        return _valid_search_output()

    definition = _search_definition(handler)
    with pytest.raises(ValueError, match="must not be empty"):
        _ = ToolCatalog(())
    with pytest.raises(ValueError, match="duplicate names"):
        _ = ToolCatalog((definition, definition))


def test_tool_catalog_rejects_model_pairs_outside_authoritative_inventory() -> None:
    async def mismatched_handler(_: RenderPagesInput) -> SearchDocumentsOutput:
        return _valid_search_output()

    mismatched = ToolDefinition[RenderPagesInput, SearchDocumentsOutput](
        name="search_documents",
        title="Search",
        description="Mismatched inventory fixture",
        input_model=RenderPagesInput,
        output_model=SearchDocumentsOutput,
        handler=mismatched_handler,
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=True,
        ),
        profiles=frozenset({DeploymentProfile.ALPIC_METADATA}),
    )
    with pytest.raises(ValueError, match="authoritative model inventory"):
        _ = ToolCatalog((mismatched,))


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_output_is_rejected(value: float) -> None:
    with pytest.raises(ValidationError):
        _ = FiniteScoreOutput(score=value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, 0),
        (-0.0, 0),
        (1, 1),
        (1.0, 1),
        (-_MAX_SAFE_INTEGER, -_MAX_SAFE_INTEGER),
        (_MAX_SAFE_INTEGER, _MAX_SAFE_INTEGER),
    ],
)
def test_safe_integer_accepts_exact_json_integer_forms(
    value: float,
    expected: int,
) -> None:
    assert _safe_integer_probe(value).value == expected


@pytest.mark.parametrize(
    "value",
    [
        True,
        "1",
        1.5,
        math.nan,
        math.inf,
        -math.inf,
        -_MAX_SAFE_INTEGER - 1,
        _MAX_SAFE_INTEGER + 1,
    ],
)
def test_safe_integer_rejects_ambiguous_or_inexact_values(value: object) -> None:
    with pytest.raises(ValidationError):
        _ = _safe_integer_probe(value)


def test_output_validation_owns_nested_collections() -> None:
    authors = ["Author"]
    raw: dict[str, object] = {
        "items": [
            {
                "authors": authors,
                "canonical_url": "https://dspace.nplg.gov.ge/handle/1234/560449",
                "handle": "1234/560449",
                "issue_date": None,
                "title": "Fixture",
            }
        ],
        "next_cursor": None,
        "next_offset": None,
        "source_url": "https://dspace.nplg.gov.ge/simple-search",
        "total": 1,
    }
    validated = SearchDocumentsOutput.model_validate(raw, strict=True)
    authors.append("Injected")
    assert validated.items[0].authors == ("Author",)
    forged = SearchDocumentsOutput.model_construct(
        items=(cast("SearchDocumentRecord", {"unexpected": "constructed"}),),
        next_cursor=validated.next_cursor,
        next_offset=validated.next_offset,
        source_url=validated.source_url,
        total=validated.total,
    )
    with pytest.raises(ValidationError):
        _ = SearchDocumentsOutput.model_validate(forged, strict=True)


@pytest.mark.asyncio
async def test_catalog_owns_malicious_handler_aliases_before_and_after_return() -> None:
    """Caller and handler nested aliases cannot rewrite either owned model."""
    loop = asyncio.get_running_loop()
    started: asyncio.Future[None] = loop.create_future()
    release: asyncio.Future[None] = loop.create_future()
    retained_inputs: list[RenderPagesInput] = []
    retained_input_json: list[str] = []
    retained_outputs: list[dict[str, object]] = []

    async def malicious_handler(
        parsed: RenderPagesInput,
    ) -> RenderPagesOutput:
        retained_inputs.append(parsed)
        retained_input_json.append(parsed.model_dump_json())
        started.set_result(None)
        await release
        retained_input_json.append(parsed.model_dump_json())
        render_id = "rnd_" + "0" * 32
        output: dict[str, object] = {
            "artifact_id": "doc_" + "0" * 64,
            "manifest_asset_url": "https://example.invalid/manifest.json",
            "manifest_relative_path": f"renders/{render_id}/manifest.json",
            "mode": "native",
            "pages": [
                {
                    "asset_url": "https://example.invalid/page-1.jpg",
                    "classification": "fixture",
                    "conversion_path": "native",
                    "effective_dpi_x": 72.0,
                    "effective_dpi_y": 72.0,
                    "height": 100,
                    "lossy_conversion": True,
                    "media_type": "image/jpeg",
                    "page_number": parsed.pages[0],
                    "pixel_dimensions_preserved": True,
                    "reencoded": True,
                    "relative_path": f"renders/{render_id}/page-0001.jpg",
                    "renderer_resampling": "none",
                    "resize_applied": False,
                    "resolution_source": "fixture",
                    "resource_uri": "nplg://artifact/doc_" + "0" * 64,
                    "rotation": 0,
                    "sha256": "0" * 64,
                    "width": 100,
                }
            ],
            "render_id": render_id,
            "renderer_version": "fixture",
            "resource_uri": f"nplg://render/{render_id}/manifest",
            "source_sha256": "0" * 64,
        }
        retained_outputs.append(output)
        return cast("RenderPagesOutput", output)

    definition = ToolDefinition[RenderPagesInput, RenderPagesOutput](
        name="render_pdf_pages",
        title="Render pages",
        description="Nested ownership fixture",
        input_model=RenderPagesInput,
        output_model=RenderPagesOutput,
        handler=malicious_handler,
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
        profiles=frozenset({DeploymentProfile.PRIVATE_FULL}),
    )
    caller_pages = [1]
    arguments: dict[str, object] = {
        "artifact_id": "doc_" + "0" * 64,
        "pages": caller_pages,
    }
    pending = asyncio.create_task(
        ToolCatalog((definition,)).call("render_pdf_pages", arguments)
    )
    await started
    parsed = retained_inputs[0]
    canonical_input = parsed.model_dump_json()
    assert parsed.pages == (1,)
    caller_pages[0] = 2
    caller_pages.append(3)
    assert parsed.pages == (1,)
    assert parsed.model_dump_json() == canonical_input
    release.set_result(None)
    result = await pending
    assert isinstance(result, RenderPagesOutput)
    canonical_output = result.model_dump_json()
    assert retained_input_json == [canonical_input, canonical_input]
    assert result.pages[0].page_number == 1

    caller_pages[0] = 4
    caller_pages.append(5)
    raw_pages = cast("list[dict[str, object]]", retained_outputs[0]["pages"])
    raw_pages[0]["page_number"] = 9
    raw_pages[0]["classification"] = "mutated-after-return"
    raw_pages.append(dict(raw_pages[0]))

    assert parsed.pages == (1,)
    assert parsed.model_dump_json() == canonical_input
    assert result.pages[0].page_number == 1
    assert result.pages[0].classification == "fixture"
    assert len(result.pages) == 1
    assert result.model_dump_json() == canonical_output


@pytest.mark.parametrize(
    "query",
    ["safe\u0000suffix", "safe\u202esuffix", "safe\u2066suffix"],
)
def test_untrusted_contract_text_rejects_control_and_bidi_characters(
    query: str,
) -> None:
    with pytest.raises(ValidationError):
        _ = SearchDocumentsInput(query=query)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"budget_seconds": True},
        {"budget_seconds": 1},
        {"budget_seconds": -0.1},
        {"budget_seconds": 60.1},
        {"budget_seconds": math.nan},
        {"budget_seconds": math.inf},
    ],
)
def test_deadline_rejects_non_strict_or_unbounded_budgets(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="budget_seconds"):
        _ = MonotonicDeadline.after(
            cast("float", kwargs["budget_seconds"]),
            clock=lambda: 10.0,
        )


def test_deadline_uses_injected_monotonic_clock_and_rejects_clock_regression() -> None:
    deadline = MonotonicDeadline.after(
        _MAX_DEADLINE_BUDGET, clock=lambda: _CLOCK_CREATED_AT
    )
    assert deadline.created_at == _CLOCK_CREATED_AT
    assert deadline.expires_at == _CLOCK_EXPIRES_AT
    assert deadline.remaining(now=_CLOCK_CREATED_AT) == _MAX_DEADLINE_BUDGET
    assert deadline.remaining(now=70.1) == 0.0
    with pytest.raises(ValueError, match="backwards"):
        _ = deadline.remaining(now=9.9)


@pytest.mark.parametrize("now", [True, 1, -0.1, math.nan, math.inf])
def test_deadline_rejects_invalid_current_clock_samples(now: object) -> None:
    deadline = MonotonicDeadline.after(1.0, clock=lambda: _CLOCK_CREATED_AT)
    with pytest.raises(ValueError, match="now must be a finite nonnegative float"):
        _ = deadline.remaining(now=cast("float", now))


@pytest.mark.parametrize("pages", [[], list(range(1, 10))])
def test_render_pages_rejects_empty_and_oversized_page_selections(
    pages: list[int],
) -> None:
    payload: dict[str, object] = {
        "artifact_id": "doc_" + ("0" * 64),
        "pages": pages,
    }
    with pytest.raises(ValidationError):
        _ = RenderPagesInput.model_validate(payload, strict=True)


@pytest.mark.parametrize(
    ("created_at", "expires_at"),
    [
        (0.0, 60.0),
        (0.0, 0.0),
        (-1.0, 0.0),
        (0.0, -1.0),
        (10.0, 9.0),
        (0.0, 60.000_001),
        (math.nan, 1.0),
        (0.0, math.inf),
    ],
)
def test_deadline_constructor_enforces_closed_invariants(
    created_at: float,
    expires_at: float,
) -> None:
    should_accept = (created_at, expires_at) in {(0.0, 60.0), (0.0, 0.0)}
    if should_accept:
        assert MonotonicDeadline(created_at, expires_at).expires_at == expires_at
    else:
        with pytest.raises(ValueError, match=r"must|deadline budget"):
            _ = MonotonicDeadline(created_at, expires_at)
