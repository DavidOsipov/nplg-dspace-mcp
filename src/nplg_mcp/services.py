# Copyright (c) 2026 David Osipov
"""Acyclic typed application-service composition contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from contextlib import AbstractContextManager
    from pathlib import Path

    from .config import DeploymentProfile
    from .contracts import StrictOutput
    from .http_types import HttpClientProtocol
    from .json_types import JsonObject


class ToolSurface(Protocol):
    """Strict tool and resource capability exposed to application composition."""

    def list_tools(self) -> list[JsonObject]:
        """Return the advertised tool definitions."""
        ...

    async def call(self, name: str, arguments: JsonObject) -> StrictOutput | JsonObject:
        """Invoke one tool through its strict validated boundary."""
        ...

    def list_resources(self) -> list[JsonObject]:
        """Return the advertised resource definitions."""
        ...

    async def read_resource(self, uri: str) -> dict[str, str]:
        """Read one bounded resource by its validated URI."""
        ...


class AssetStore(Protocol):
    """Narrow asset/readiness store surface required by the HTTP application."""

    def ensure_ready(self) -> None:
        """Validate storage readiness without changing persistent state."""
        ...

    def resolve_asset(self, relative_path: str) -> Path:
        """Resolve one validated relative asset path."""
        ...

    def lease_asset(
        self,
        relative_path: str,
    ) -> AbstractContextManager[Path]:
        """Hold one resolved object against pruning for a complete read."""
        ...

    def stage(
        self,
        *,
        suffix: str = ".tmp",
    ) -> AbstractContextManager[object, bool | None]:
        """Create one bounded artifact staging file."""
        ...


@runtime_checkable
class MetadataServices(Protocol):
    """Services available to the metadata-only deployment profile."""

    @property
    def tools(self) -> ToolSurface:
        """Return the strict metadata tool surface."""
        ...

    @property
    def http_client(self) -> HttpClientProtocol | None:
        """Return the application-owned upstream client, when present."""
        ...


@runtime_checkable
class FullServices(MetadataServices, Protocol):
    """Services required by a full deployment without optional state holes."""

    @property
    def store(self) -> AssetStore:
        """Return the required private content-addressed asset store."""
        ...


@dataclass(frozen=True, slots=True)
class MetadataServiceComposition:
    """Concrete metadata-only composition with no PDF or store capability."""

    tools: ToolSurface
    http_client: HttpClientProtocol | None = None


@dataclass(frozen=True, slots=True)
class FullServiceComposition:
    """Concrete full composition with a required private asset store."""

    tools: ToolSurface
    store: AssetStore
    http_client: HttpClientProtocol | None = None


type AppServices = MetadataServiceComposition | FullServiceComposition


def validate_service_composition(
    profile: DeploymentProfile,
    services: AppServices,
) -> None:
    """Reject a service graph that does not exactly match its profile."""
    matches = (
        profile == "alpic-metadata" and isinstance(services, MetadataServiceComposition)
    ) or (profile == "private-full" and isinstance(services, FullServiceComposition))
    if not matches:
        msg = "deployment profile does not match service composition"
        raise ValueError(msg)
