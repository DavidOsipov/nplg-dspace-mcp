# Copyright (c) 2026 David Osipov
"""Unit tests for safe public errors."""

from __future__ import annotations

import math
import sys
from collections.abc import Mapping
from operator import attrgetter
from typing import TYPE_CHECKING, cast, override

import pytest

from nplg_mcp import errors as errors_module
from nplg_mcp.errors import (
    AppError,
    ErrorCode,
    InvalidResourceUriError,
    to_public_error,
    validate_resource_uri,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import CodeType
    from typing import Protocol

    from nplg_mcp.json_types import JsonObject

    class SnapshotFrameFunction(Protocol):
        """Typed callable surface for the internal snapshot guard."""

        @property
        def __code__(self) -> CodeType:
            """Expose the callable code object for local monitoring."""
            ...

        def __call__(
            self,
            source: object,
            target: object,
            *,
            depth: int,
            remaining_values: int,
        ) -> object: ...

    class ConsumeValueFunction(Protocol):
        """Typed callable surface for the internal value-budget guard."""

        def __call__(self, current: int) -> int: ...

    class StoreSnapshotFunction(Protocol):
        """Typed callable surface for the internal snapshot-store guard."""

        def __call__(self, target: object, key: object, value: object) -> None: ...


_PRIVATE_MAPPING_SENTINEL = "PRIVATE_MAPPING_SENTINEL"
_PRIVATE_ITERATION_SENTINEL = "PRIVATE_ITERATION_SENTINEL"
_PRIVATE_CONTAINER_SENTINEL = "PRIVATE_CONTAINER_SENTINEL"
_MAX_PUBLIC_DETAIL_DEPTH = 32
_MAX_PUBLIC_DETAIL_VALUES = 4_096
_MAX_PUBLIC_DETAIL_STRING_CODE_POINTS = 65_536
_MAX_PUBLIC_DETAIL_INTEGER_BITS = 256
_MAX_MONITORING_TOOL_ID = 5


@pytest.mark.parametrize("uri", ["", "x" * 513])
def test_resource_uri_rejects_values_outside_the_bounded_length(uri: str) -> None:
    """Empty and overlong resource URIs fail before grammar evaluation."""
    with pytest.raises(InvalidResourceUriError):
        _ = validate_resource_uri(uri)


class _HostileMapping(Mapping[str, object]):
    @override
    def __getitem__(self, _key: str) -> object:
        raise RuntimeError(_PRIVATE_MAPPING_SENTINEL)

    @override
    def __iter__(self) -> Iterator[str]:
        raise RuntimeError(_PRIVATE_MAPPING_SENTINEL)

    @override
    def __len__(self) -> int:
        raise RuntimeError(_PRIVATE_MAPPING_SENTINEL)

    def __bool__(self) -> bool:
        raise RuntimeError(_PRIVATE_MAPPING_SENTINEL)


class _HostileList(list[object]):
    @override
    def __iter__(self) -> Iterator[object]:
        raise RuntimeError(_PRIVATE_CONTAINER_SENTINEL)


class _HostileIterationMapping(Mapping[str, object]):
    @override
    def __getitem__(self, _key: str) -> object:
        raise RuntimeError(_PRIVATE_ITERATION_SENTINEL)

    @override
    def __iter__(self) -> Iterator[str]:
        raise RuntimeError(_PRIVATE_ITERATION_SENTINEL)

    @override
    def __len__(self) -> int:
        return 1

    def __bool__(self) -> bool:
        return True


def _serialize_with_interleaved_mutation(
    error: AppError,
    *,
    trigger_line: int,
    mutate: Callable[[], None],
) -> JsonObject:
    snapshot_frame = cast(
        "SnapshotFrameFunction",
        attrgetter("_snapshot_frame")(errors_module),
    )
    snapshot_code = snapshot_frame.__code__
    tool_id: int | None = None
    for candidate in range(_MAX_MONITORING_TOOL_ID, -1, -1):
        if sys.monitoring.get_tool(candidate) is None:
            sys.monitoring.use_tool_id(candidate, "nplg-errors-race-test")
            tool_id = candidate
            break
    if tool_id is None:
        pytest.fail("no free sys.monitoring tool ID for deterministic race injection")
    mutation_observed = False

    def line_callback(code: CodeType, line_number: int) -> object | None:
        nonlocal mutation_observed
        if code is snapshot_code and line_number == trigger_line:
            mutate()
            mutation_observed = True
            return sys.monitoring.DISABLE
        return None

    _ = cast(
        "object",
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.LINE,
            line_callback,
        ),
    )
    sys.monitoring.set_local_events(tool_id, snapshot_code, sys.monitoring.events.LINE)
    try:
        public = to_public_error(error)
    finally:
        sys.monitoring.set_local_events(tool_id, snapshot_code, 0)
        _ = cast(
            "object",
            sys.monitoring.register_callback(
                tool_id,
                sys.monitoring.events.LINE,
                None,
            ),
        )
        sys.monitoring.free_tool_id(tool_id)
    assert mutation_observed
    return public


def test_public_error_keeps_safe_context_and_redacts_internal_cause() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository did not return a valid item page.",
        http_status=502,
        safe_details={"handle": "1234/567"},
        internal_details={"upstream_body": "secret debug body"},
    )

    public = to_public_error(error)

    assert public == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository did not return a valid item page.",
        "details": {"handle": "1234/567"},
    }
    assert "secret" not in repr(public)


def test_unexpected_exception_becomes_stable_internal_error() -> None:
    public = to_public_error(RuntimeError("database password leaked"))

    assert public == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


@pytest.mark.parametrize("invalid_value", [object(), math.nan, math.inf, -math.inf])
def test_invalid_safe_details_fail_closed(invalid_value: object) -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"unsafe": invalid_value},
    )

    assert to_public_error(error) == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_cyclic_safe_details_fail_closed_without_recursion_error() -> None:
    cycle: list[object] = []
    cycle.append(cycle)
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"cycle": cycle},
    )

    assert to_public_error(error) == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_excessively_nested_safe_details_fail_closed() -> None:
    nested: object = "leaf"
    for _ in range(_MAX_PUBLIC_DETAIL_DEPTH + 1):
        nested = [nested]
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"nested": nested},
    )

    assert to_public_error(error) == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_oversized_safe_details_fail_closed() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"items": [0] * (_MAX_PUBLIC_DETAIL_VALUES - 1)},
    )

    assert to_public_error(error) == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_oversized_safe_detail_string_fails_closed() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"": "x" * (_MAX_PUBLIC_DETAIL_STRING_CODE_POINTS + 1)},
    )

    assert to_public_error(error) == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_oversized_safe_detail_integer_fails_closed() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"integer": 1 << _MAX_PUBLIC_DETAIL_INTEGER_BITS},
    )

    assert to_public_error(error) == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_hostile_top_level_mapping_fails_closed_without_invocation() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details=_HostileMapping(),
    )

    public = to_public_error(error)

    assert public == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }
    assert _PRIVATE_MAPPING_SENTINEL not in repr(public)


def test_hostile_top_level_mapping_iteration_is_never_invoked() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details=_HostileIterationMapping(),
    )

    public = to_public_error(error)

    assert public == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }
    assert _PRIVATE_ITERATION_SENTINEL not in repr(public)


def test_hostile_nested_container_fails_closed_without_invocation() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"hostile": _HostileList()},
    )

    public = to_public_error(error)

    assert public == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }
    assert _PRIVATE_CONTAINER_SENTINEL not in repr(public)


def test_valid_safe_details_preserve_nested_values_and_shared_containers() -> None:
    shared: list[object] = ["same", {"ok": True}]
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={
            "depth": [[[["leaf"]]]],
            "first": shared,
            "float": -0.0,
            "integer": 1 << (_MAX_PUBLIC_DETAIL_INTEGER_BITS - 1),
            "second": shared,
        },
    )

    assert to_public_error(error) == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository rejected the request.",
        "details": {
            "depth": [[[["leaf"]]]],
            "first": ["same", {"ok": True}],
            "float": -0.0,
            "integer": 1 << (_MAX_PUBLIC_DETAIL_INTEGER_BITS - 1),
            "second": ["same", {"ok": True}],
        },
    }


def test_public_safe_details_are_detached_from_mutable_input() -> None:
    nested: list[object] = [{"state": "before"}]
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"nested": nested},
    )

    public = to_public_error(error)
    nested.append({"state": "after"})

    assert public == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository rejected the request.",
        "details": {"nested": [{"state": "before"}]},
    }


def test_safe_details_accept_exact_reviewed_depth_limit() -> None:
    nested: object = "leaf"
    for _ in range(_MAX_PUBLIC_DETAIL_DEPTH):
        nested = [nested]
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"nested": nested},
    )

    assert to_public_error(error) == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository rejected the request.",
        "details": {"nested": nested},
    }


def test_safe_details_accept_exact_reviewed_value_limit() -> None:
    items = [0] * (_MAX_PUBLIC_DETAIL_VALUES - 2)
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"items": items},
    )

    assert to_public_error(error) == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository rejected the request.",
        "details": {"items": items},
    }


def test_safe_details_accept_exact_reviewed_string_limit() -> None:
    text = "x" * _MAX_PUBLIC_DETAIL_STRING_CODE_POINTS
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"": text},
    )

    assert to_public_error(error) == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository rejected the request.",
        "details": {"": text},
    }


def test_empty_safe_details_remain_omitted() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={},
    )

    assert to_public_error(error) == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository rejected the request.",
    }


def test_app_error_without_safe_details_remains_public() -> None:
    error = AppError(
        code=ErrorCode.NOT_FOUND,
        message="The requested document was not found.",
    )

    assert to_public_error(error) == {
        "code": "NOT_FOUND",
        "message": "The requested document was not found.",
    }


def test_safe_details_preserve_none_scalar() -> None:
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"optional": None},
    )

    assert to_public_error(error) == {
        "code": "UPSTREAM_FAILURE",
        "message": "The repository rejected the request.",
        "details": {"optional": None},
    }


def test_oversized_top_level_detail_mapping_fails_closed() -> None:
    details = {str(index): index for index in range(_MAX_PUBLIC_DETAIL_VALUES)}
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details=details,
    )

    assert to_public_error(error) == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_non_string_detail_key_fails_closed() -> None:
    details = cast("Mapping[str, object]", {1: "unsafe"})
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details=details,
    )

    assert to_public_error(error) == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_detail_mapping_growth_during_copy_fails_closed() -> None:
    details: dict[str, object] = {
        str(index): index for index in range(_MAX_PUBLIC_DETAIL_VALUES - 1)
    }
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details=details,
    )

    public = _serialize_with_interleaved_mutation(
        error,
        trigger_line=111,
        mutate=lambda: details.__setitem__("late", None),
    )

    assert public == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_detail_list_growth_during_copy_fails_closed() -> None:
    items: list[object] = [0] * (_MAX_PUBLIC_DETAIL_VALUES - 2)
    error = AppError(
        code=ErrorCode.UPSTREAM_FAILURE,
        message="The repository rejected the request.",
        safe_details={"items": items},
    )

    public = _serialize_with_interleaved_mutation(
        error,
        trigger_line=120,
        mutate=lambda: items.append(0),
    )

    assert public == {
        "code": "INTERNAL_ERROR",
        "message": "The server could not complete the request.",
    }


def test_snapshot_frame_rejects_non_container_source() -> None:
    snapshot_frame = cast(
        "SnapshotFrameFunction",
        attrgetter("_snapshot_frame")(errors_module),
    )
    invalid_details_error = cast(
        "type[ValueError]",
        attrgetter("_InvalidPublicDetailsError")(errors_module),
    )
    target: JsonObject = {}

    with pytest.raises(invalid_details_error):
        _ = snapshot_frame(object(), target, depth=0, remaining_values=1)


def test_public_detail_counter_rejects_overflow() -> None:
    consume_value = cast(
        "ConsumeValueFunction",
        attrgetter("_consume_public_detail_value")(errors_module),
    )
    invalid_details_error = cast(
        "type[ValueError]",
        attrgetter("_InvalidPublicDetailsError")(errors_module),
    )

    with pytest.raises(invalid_details_error):
        _ = consume_value(_MAX_PUBLIC_DETAIL_VALUES)


def test_snapshot_store_rejects_non_string_mapping_key() -> None:
    store_snapshot = cast(
        "StoreSnapshotFunction",
        attrgetter("_store_snapshot")(errors_module),
    )
    invalid_details_error = cast(
        "type[ValueError]",
        attrgetter("_InvalidPublicDetailsError")(errors_module),
    )
    target: JsonObject = {}

    with pytest.raises(invalid_details_error):
        store_snapshot(target, 1, None)
