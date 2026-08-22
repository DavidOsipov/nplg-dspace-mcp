# Copyright (c) 2026 David Osipov
"""Typed heterogeneous tool catalog with strict input and output validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

from pydantic import ValidationError

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.json_types import validation_details

from .base import StrictInput, StrictOutput, reject_unsafe_text
from .tool_models import require_tool_model_binding

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from .profiles import DeploymentProfile, ToolAnnotations

_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_TOOL_TITLE_LENGTH = 128
_MAX_TOOL_DESCRIPTION_LENGTH = 2_048


def _registered_tool_name(definition: RegisteredTool) -> str:
    """Return one registered name for deterministic sorting."""
    return definition.name


class _ContractValidationError(Exception):
    """Private validation failure that never renders untrusted values."""

    def __init__(self, *, stage: str, error: ValidationError) -> None:
        super().__init__("tool contract validation failed")
        self.stage = stage
        self.error = error


@dataclass(frozen=True, slots=True)
class ToolDefinition[InputT: StrictInput, OutputT: StrictOutput]:
    """One fully typed MCP tool definition."""

    name: str
    title: str
    description: str
    input_model: type[InputT]
    output_model: type[OutputT]
    handler: Callable[[InputT], Awaitable[OutputT]]
    annotations: ToolAnnotations
    profiles: frozenset[DeploymentProfile]

    def __post_init__(self) -> None:
        """Reject malformed metadata before it can enter the catalog."""
        if _TOOL_NAME.fullmatch(self.name) is None:
            message = "tool name is invalid"
            raise ValueError(message)
        _ = reject_unsafe_text(self.title)
        _ = reject_unsafe_text(self.description)
        if not 1 <= len(self.title) <= _MAX_TOOL_TITLE_LENGTH:
            message = "tool title length is invalid"
            raise ValueError(message)
        if not 1 <= len(self.description) <= _MAX_TOOL_DESCRIPTION_LENGTH:
            message = "tool description length is invalid"
            raise ValueError(message)
        if not self.profiles:
            message = "tool must belong to at least one deployment profile"
            raise ValueError(message)

    async def invoke(self, arguments: Mapping[str, object]) -> OutputT:
        """Strictly validate untouched arguments and the untrusted handler return."""
        try:
            owned_arguments: dict[str, object] = dict(arguments)
            parsed = self.input_model.model_validate(owned_arguments, strict=True)
        except ValidationError as exc:
            raise _ContractValidationError(stage="input", error=exc) from exc
        untrusted_output = await self.handler(parsed)
        try:
            return self.output_model.model_validate(untrusted_output, strict=True)
        except ValidationError as exc:
            raise _ContractValidationError(stage="output", error=exc) from exc


class RegisteredTool(Protocol):
    """Read-only erased view of a heterogeneous tool definition."""

    @property
    def name(self) -> str:
        """Return the stable public tool name."""
        ...

    @property
    def title(self) -> str:
        """Return the bounded human-readable title."""
        ...

    @property
    def description(self) -> str:
        """Return the bounded human-readable description."""
        ...

    @property
    def input_model(self) -> type[StrictInput]:
        """Return the strict public input model."""
        ...

    @property
    def output_model(self) -> type[StrictOutput]:
        """Return the strict public output model."""
        ...

    @property
    def annotations(self) -> ToolAnnotations:
        """Return immutable MCP behavior annotations."""
        ...

    @property
    def profiles(self) -> frozenset[DeploymentProfile]:
        """Return the deployment profiles allowed to expose this tool."""
        ...

    async def invoke(self, arguments: Mapping[str, object]) -> StrictOutput:
        """Validate and invoke the erased heterogeneous tool definition."""
        ...


class ToolCatalog:
    """Closed deterministic registry for every reviewed tool definition."""

    def __init__(self, definitions: tuple[RegisteredTool, ...]) -> None:
        """Own, validate, and index one deterministic definition snapshot."""
        super().__init__()
        ordered = tuple(sorted(definitions, key=_registered_tool_name))
        names = tuple(definition.name for definition in ordered)
        if len(names) != len(set(names)):
            message = "tool catalog contains duplicate names"
            raise ValueError(message)
        if not names:
            message = "tool catalog must not be empty"
            raise ValueError(message)
        for definition in ordered:
            require_tool_model_binding(
                definition.name,
                definition.input_model,
                definition.output_model,
            )
        self._ordered = ordered
        self._definitions = MappingProxyType(
            {definition.name: definition for definition in ordered}
        )

    @property
    def definitions(self) -> tuple[RegisteredTool, ...]:
        """Return the immutable deterministic definition sequence."""
        return self._ordered

    async def call(
        self,
        name: str,
        arguments: Mapping[str, object],
    ) -> StrictOutput:
        """Invoke a known tool and translate validation failures safely."""
        definition = self._definitions.get(name)
        if definition is None:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "The requested tool does not exist.",
            )
        try:
            return await definition.invoke(arguments)
        except _ContractValidationError as exc:
            if exc.stage == "input":
                raw_errors: object = exc.error.errors(
                    include_url=False,
                    include_input=False,
                )
                raise AppError(
                    ErrorCode.INVALID_INPUT,
                    "Tool arguments did not match the declared schema.",
                    safe_details={"validation": validation_details(raw_errors)},
                ) from exc
            raise AppError(
                ErrorCode.INTERNAL_ERROR,
                "The tool returned an invalid result.",
                http_status=500,
            ) from exc
