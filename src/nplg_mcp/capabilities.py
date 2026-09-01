# Copyright (c) 2026 David Osipov
"""Strict, offline capability records used to gate later authentication work."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import importlib.metadata
import json
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, cast
from urllib.parse import urlsplit

import httpx
import mcp.types as mcp_types
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.lowlevel.server import Server
from mcp.types import LATEST_PROTOCOL_VERSION
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationInfo,
    field_validator,
    model_validator,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Mapping

    from mcp.server.context import ServerRequestContext
    from starlette.applications import Starlette

HTTP_UNAUTHORIZED: Literal[401] = 401
HTTP_FORBIDDEN: Literal[403] = 403
_AUTHORIZATION_HEADER_COUNT = 2
_SDK_BOUNDARY_FILE = "mcp/server/auth/middleware/bearer_auth.py"
_RESOURCE_METADATA_URL = "https://mcp.example.test/.well-known/oauth-protected-resource"
_INVALID_TOKEN_CHALLENGE = (
    'Bearer error="invalid_token", error_description="Authentication required", '
    f'resource_metadata="{_RESOURCE_METADATA_URL}"'
)
_INSUFFICIENT_SCOPE_CHALLENGE = (
    'Bearer error="insufficient_scope", '
    'error_description="Required scope: nplg:search", '
    f'resource_metadata="{_RESOURCE_METADATA_URL}"'
)
_MAX_EXTERNAL_TEXT_LENGTH = 4096
_MAX_PERSISTED_ITEMS = 64
_MAX_RAW_CONTRACT_BYTES = 2_097_152
_REVIEWED_DATE = "2026-09-01"
_SDK_UPSTREAM_COMMIT_UNAVAILABLE_REASON = (
    "The official PyPI wheel metadata does not publish a verified VCS commit."
)
_SDK_REASON = (
    "SDK v2.1.1 applies static route scopes before MCP parsing, omits the RFC "
    "minimum-scope parameter, and accepts duplicate Authorization headers."
)
_ALPIC_PROVENANCE = (
    "Alpic public documentation summary; no versioned raw detector fixture or "
    "immutable response transcript was published for this review."
)
_ALPIC_TASKS_PROVENANCE = (
    "Alpic documents a separate long-running Tasks compute path with a default "
    "TTL of up to six hours; the official Python SDK roadmap defers SEP-2663 "
    "Tasks from mcp 2.1.1. No authorized Alpic task conformance probe exists."
)
_ALPIC_TASKS_BLOCKERS = (
    "MCP_TASKS_REVISION_UNFROZEN",
    "PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE",
    "PYTHON_SDK_TASKS_CLIENT_UNAVAILABLE",
    "ALPIC_TASKS_PYTHON_INTEGRATION_UNPROVEN",
    "ALPIC_TASK_CREATION_DURABILITY_UNPROVEN",
    "ALPIC_TASK_RESTART_RECOVERY_UNPROVEN",
    "ALPIC_TASK_CANCELLATION_UNPROVEN",
    "ALPIC_TASK_ISOLATION_UNPROVEN",
    "ALPIC_TASK_RETENTION_UNPROVEN",
    "ALPIC_TASK_ARTIFACT_DELIVERY_UNPROVEN",
    "ALPIC_TASK_CLIENT_SUPPORT_UNPROVEN",
)
_TASKS_REVIEWED_DATE = "2026-09-01"
_ALPIC_TASKS_SOURCE_EVIDENCE_DIGEST = (
    "67dadaf3dee652e1f1f63dd26b3031043badffc64af4cf9c168090c422673a1b"
)
_ALPIC_TASKS_SOURCE_REQUIREMENTS = (
    (
        "alpic_tasks_docs",
        "https://docs.alpic.ai/troubleshooting",
        "tasks_compute_advertised",
    ),
    (
        "python_sdk_roadmap",
        (
            "https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/"
            "959569ba1505897bd8d824a1bf22800672f7cf14/ROADMAP.md"
        ),
        "sdk_tasks_deferred",
    ),
    (
        "mcp_tasks_spec",
        "https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks",
        "tasks_extension_draft",
    ),
)
_LOCKED_MCP_ARTIFACT_SHA256S = (
    "1c6c31c5d6471c58db76af3af8af67f46d11d01f0a59077d0a308cbdb3d3e915",
    "50b7ba1ebbe117008ea7bdd288234043e69c20b403d6851d19661e6d431a75ef",
)

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]
GitObjectId = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{40}$", strict=True),
]
NonEmpty = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=_MAX_EXTERNAL_TEXT_LENGTH,
        strict=True,
    ),
]
VerifierToken = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=256,
        pattern=r"^[^\x00-\x20\x7f]+$",
        strict=True,
    ),
]
Base64Bytes = Annotated[
    str,
    StringConstraints(
        min_length=4,
        max_length=1_048_576,
        pattern=r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
        strict=True,
    ),
]
HeaderName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$",
        strict=True,
    ),
]
HeaderValue = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=4096,
        pattern=r"^[^\r\n]+$",
        strict=True,
    ),
]
ReviewDate = Annotated[
    str,
    StringConstraints(pattern=r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}$", strict=True),
]
PackageVersion = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}"
            r"(?:[a-z][a-z0-9.-]{0,31})?$"
        ),
        strict=True,
    ),
]
UtcTimestamp = Annotated[
    str,
    StringConstraints(
        pattern=r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
        strict=True,
    ),
]


class CapabilityContractError(ValueError):
    """Raised when a reviewed capability record is not the expected evidence."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _DigestModel(_StrictModel):
    verdict_digest: Sha256

    @model_validator(mode="after")
    def _verify_verdict_digest(
        self,
        info: ValidationInfo[dict[str, object] | None],
    ) -> _DigestModel:
        if info.context is not None and info.context.get("skip_digest") is True:
            return self
        expected = _sha256_json(
            cast(
                "dict[str, object]",
                self.model_dump(mode="json", exclude={"verdict_digest"}),
            ),
        )
        if self.verdict_digest != expected:
            msg = "verdict_digest does not match the canonical record"
            raise ValueError(msg)
        return self


class Header(_StrictModel):
    """One order-preserving ASGI header field."""

    name: HeaderName
    value: HeaderValue


class RawHttpRequest(_StrictModel):
    """Exact normalized request presented to the official SDK ASGI app."""

    method: Literal["POST"]
    path: Literal["/mcp"]
    headers: Annotated[tuple[Header, ...], Field(min_length=1, max_length=32)]
    body_base64: Base64Bytes
    body_sha256: Sha256

    @model_validator(mode="after")
    def _verify_body_digest(self) -> RawHttpRequest:
        if (
            hashlib.sha256(_decode_base64(self.body_base64)).hexdigest()
            != self.body_sha256
        ):
            msg = "request body_sha256 does not match body_base64"
            raise ValueError(msg)
        return self


class RawHttpResponse(_StrictModel):
    """Exact normalized response returned by the official SDK ASGI app."""

    status_code: int = Field(ge=100, le=599)
    headers: Annotated[tuple[Header, ...], Field(min_length=1, max_length=32)]
    body_base64: Base64Bytes
    body_sha256: Sha256

    @model_validator(mode="after")
    def _verify_body_digest(self) -> RawHttpResponse:
        if (
            hashlib.sha256(_decode_base64(self.body_base64)).hexdigest()
            != self.body_sha256
        ):
            msg = "response body_sha256 does not match body_base64"
            raise ValueError(msg)
        return self


SdkCaseId = Literal[
    "authorization.missing",
    "authorization.basic",
    "authorization.invalid-bearer",
    "authorization.expired-bearer",
    "authorization.weak-scope-search",
    "authorization.weak-scope-inspect",
    "authorization.sufficient-scope-control",
    "authorization.duplicate",
    "alpic.local-sdk-initialize",
]
_EXPECTED_SDK_CASE_IDS: tuple[SdkCaseId, ...] = (
    "authorization.missing",
    "authorization.basic",
    "authorization.invalid-bearer",
    "authorization.expired-bearer",
    "authorization.weak-scope-search",
    "authorization.weak-scope-inspect",
    "authorization.sufficient-scope-control",
    "authorization.duplicate",
)


class SdkHttpObservation(_StrictModel):
    """One request/response observation plus public-boundary counters."""

    case_id: SdkCaseId
    request: RawHttpRequest
    response: RawHttpResponse
    verifier_calls: int = Field(ge=0, le=1)
    verifier_tokens: Annotated[tuple[VerifierToken, ...], Field(max_length=1)]
    downstream_dispatch_count: int = Field(ge=0, le=1)

    @model_validator(mode="after")
    def _check_observed_counters(self) -> SdkHttpObservation:
        if self.verifier_calls != len(self.verifier_tokens):
            msg = "verifier_calls must equal the retained verifier token sequence"
            raise ValueError(msg)
        return self


class ScopeChallenge(_StrictModel):
    """Observed weak-scope challenge semantics."""

    status_code: Literal[403]
    header_value: HeaderValue
    required_scope: Literal["nplg:search"]
    advertised_scope: None


class SdkAuthorizationCapabilityVerdict(_DigestModel):
    """Closed authorization-capability verdict for the pinned official SDK."""

    schema_version: Literal["2.0"]
    mcp_version: Literal["2.1.1"]
    mcp_types_version: Literal["2.1.1"]
    upstream_repository: Literal["https://github.com/modelcontextprotocol/python-sdk"]
    upstream_commit: GitObjectId | None
    upstream_commit_unavailable_reason: NonEmpty
    locked_artifact_sha256s: Annotated[
        tuple[Sha256, ...],
        Field(min_length=2, max_length=2),
    ]
    installed_package_tree_sha256: Sha256
    sdk_boundary_file: Literal["mcp/server/auth/middleware/bearer_auth.py"]
    sdk_boundary_file_sha256: Sha256
    protocol_revision: Literal["MCP-2026-07-28"]
    observation_source: Literal["official_sdk_public_asgi"]
    asgi_case_digest: Sha256
    asgi_observation_digest: Sha256
    sdk_extension_point: Literal["none"]
    parsed_operation_identity_at_http_auth_boundary: Literal[False]
    routing_header_trusted: Literal[False]
    private_mcp_reparse: Literal[False]
    scope_challenge: ScopeChallenge
    missing_authorization_observation: SdkHttpObservation
    basic_authorization_observation: SdkHttpObservation
    invalid_bearer_observation: SdkHttpObservation
    expired_bearer_observation: SdkHttpObservation
    weak_scope_observation: SdkHttpObservation
    weak_scope_alternate_tool_observation: SdkHttpObservation
    sufficient_scope_control: SdkHttpObservation
    duplicate_authorization_observation: SdkHttpObservation
    supported: Literal[False]
    blockers: Annotated[
        tuple[
            Literal[
                "MCP_DYNAMIC_SCOPE_403_UNSUPPORTED",
                "SDK_DUPLICATE_AUTHORIZATION_REQUIRES_OUTER_REJECTION",
            ],
            ...,
        ],
        Field(min_length=2, max_length=2),
    ]
    reason: NonEmpty
    reviewed_date: ReviewDate

    @model_validator(mode="after")
    def _check_supported_state(self) -> SdkAuthorizationCapabilityVerdict:
        self._check_support_decision()
        self._check_installed_identity()
        observations = self._observations()
        self._check_matrix_identity(observations)
        self._check_matrix_digests(observations)
        self._check_http_semantics(observations)
        return self

    def _check_support_decision(self) -> None:
        if self.blockers != (
            "MCP_DYNAMIC_SCOPE_403_UNSUPPORTED",
            "SDK_DUPLICATE_AUTHORIZATION_REQUIRES_OUTER_REJECTION",
        ):
            msg = "an unsupported SDK verdict must preserve its stable blocker"
            raise ValueError(msg)
        if self.upstream_commit is not None:
            msg = "the reviewed PyPI wheel does not publish a verified upstream commit"
            raise ValueError(msg)
        if (
            self.upstream_commit_unavailable_reason
            != _SDK_UPSTREAM_COMMIT_UNAVAILABLE_REASON
            or self.reason != _SDK_REASON
            or self.reviewed_date != _REVIEWED_DATE
        ):
            msg = "SDK capability provenance differs from the reviewed observation"
            raise ValueError(msg)

    def _check_installed_identity(self) -> None:
        if self.locked_artifact_sha256s != _LOCKED_MCP_ARTIFACT_SHA256S:
            msg = "locked SDK artifact digests differ from requirements-dev.lock"
            raise ValueError(msg)
        if self.mcp_version != importlib.metadata.version("mcp"):
            msg = "installed mcp version differs from capability record"
            raise ValueError(msg)
        if self.mcp_types_version != importlib.metadata.version("mcp-types"):
            msg = "installed mcp-types version differs from capability record"
            raise ValueError(msg)
        if self.installed_package_tree_sha256 != _package_tree_sha256("mcp"):
            msg = "installed SDK package tree differs from capability record"
            raise ValueError(msg)
        if self.sdk_boundary_file_sha256 != _package_file_sha256(
            "mcp",
            _SDK_BOUNDARY_FILE.removeprefix("mcp/"),
        ):
            msg = "installed SDK authorization boundary differs from capability record"
            raise ValueError(msg)

    @staticmethod
    def _check_matrix_identity(
        observations: tuple[SdkHttpObservation, ...],
    ) -> None:
        if tuple(item.case_id for item in observations) != _EXPECTED_SDK_CASE_IDS:
            msg = "SDK observations are not the closed reviewed case matrix"
            raise ValueError(msg)

    def _check_matrix_digests(
        self,
        observations: tuple[SdkHttpObservation, ...],
    ) -> None:
        requests: list[object] = [_model_json(item.request) for item in observations]
        if self.asgi_case_digest != _sha256_json(
            {"requests": requests},
        ):
            msg = "asgi_case_digest does not bind the observed requests"
            raise ValueError(msg)
        values: list[object] = [_model_json(item) for item in observations]
        if self.asgi_observation_digest != _sha256_json(
            {"observations": values},
        ):
            msg = "asgi_observation_digest does not bind the observations"
            raise ValueError(msg)

    def _check_http_semantics(
        self,
        observations: tuple[SdkHttpObservation, ...],
    ) -> None:
        expected_tools = (
            "search_documents",
            "search_documents",
            "search_documents",
            "search_documents",
            "search_documents",
            "inspect_pdf",
            "search_documents",
            "search_documents",
        )
        expected_authorization: tuple[tuple[str, ...], ...] = (
            (),
            ("Basic Zml4dHVyZTphdXRo",),
            ("Bearer invalid-fixture-token",),
            ("Bearer expired-fixture-token",),
            ("Bearer weak-fixture-token",),
            ("Bearer weak-fixture-token",),
            ("Bearer strong-fixture-token",),
            ("Bearer weak-fixture-token", "Bearer strong-fixture-token"),
        )
        expected_verifier_tokens: tuple[tuple[str, ...], ...] = (
            (),
            (),
            ("invalid-fixture-token",),
            ("expired-fixture-token",),
            ("weak-fixture-token",),
            ("weak-fixture-token",),
            ("strong-fixture-token",),
            ("weak-fixture-token",),
        )
        for item, tool_name, authorization, verifier_tokens in zip(
            observations,
            expected_tools,
            expected_authorization,
            expected_verifier_tokens,
            strict=True,
        ):
            if item.request != _expected_tool_request(tool_name, authorization):
                msg = f"{item.case_id} request differs from the closed SDK case"
                raise ValueError(msg)
            if item.verifier_tokens != verifier_tokens:
                msg = f"{item.case_id} verifier sequence differs from observation"
                raise ValueError(msg)

        unauthorized = _expected_error_response(
            status_code=HTTP_UNAUTHORIZED,
            error="invalid_token",
            description="Authentication required",
            challenge=_INVALID_TOKEN_CHALLENGE,
        )
        insufficient = _expected_error_response(
            status_code=HTTP_FORBIDDEN,
            error="insufficient_scope",
            description="Required scope: nplg:search",
            challenge=_INSUFFICIENT_SCOPE_CHALLENGE,
        )
        if any(
            item.response != unauthorized or item.downstream_dispatch_count != 0
            for item in observations[:4]
        ):
            msg = "credential failures must match the exact SDK 401 observation"
            raise ValueError(msg)
        if any(
            item.response != insufficient or item.downstream_dispatch_count != 0
            for item in observations[4:6]
        ):
            msg = "weak-scope cases must match the exact pre-dispatch SDK 403"
            raise ValueError(msg)
        if (
            observations[6].response != _expected_dispatch_response()
            or observations[6].downstream_dispatch_count != 1
        ):
            msg = "the sufficient-scope control must reach the counted SDK handler"
            raise ValueError(msg)
        if (
            observations[7].response != insufficient
            or observations[7].downstream_dispatch_count != 0
            or _header_values(observations[7].request.headers, "authorization")
            != expected_authorization[7]
            or len(
                _header_values(observations[7].request.headers, "authorization"),
            )
            != _AUTHORIZATION_HEADER_COUNT
        ):
            msg = (
                "duplicate Authorization must preserve the observed first-value choice"
            )
            raise ValueError(msg)
        challenge_headers = _header_values(
            observations[4].response.headers,
            "www-authenticate",
        )
        if (
            challenge_headers != (self.scope_challenge.header_value,)
            or self.scope_challenge.header_value != _INSUFFICIENT_SCOPE_CHALLENGE
            or _parse_bearer_challenge(self.scope_challenge.header_value)
            != {
                "error": "insufficient_scope",
                "error_description": "Required scope: nplg:search",
                "resource_metadata": _RESOURCE_METADATA_URL,
            }
        ):
            msg = "scope challenge does not match the observed single response header"
            raise ValueError(msg)

    def _observations(self) -> tuple[SdkHttpObservation, ...]:
        return (
            self.missing_authorization_observation,
            self.basic_authorization_observation,
            self.invalid_bearer_observation,
            self.expired_bearer_observation,
            self.weak_scope_observation,
            self.weak_scope_alternate_tool_observation,
            self.sufficient_scope_control,
            self.duplicate_authorization_observation,
        )


class RouteRewrite(_StrictModel):
    """One documented public-to-backend route rewrite."""

    public_path: Annotated[str, StringConstraints(min_length=1, max_length=1024)]
    backend_path: Annotated[str, StringConstraints(min_length=1, max_length=1024)]


class RewriteMapping(_StrictModel):
    """Whether route rewrites were observed and their exact mapping."""

    observed: bool
    entries: Annotated[tuple[RouteRewrite, ...], Field(max_length=32)]


class RouteBindings(_StrictModel):
    """Bound local and public OAuth resource coordinates."""

    backend_resource_server_url: Literal["https://mcp.example.test"]
    challenge_resource_metadata: Literal[
        "https://mcp.example.test/.well-known/oauth-protected-resource"
    ]
    local_metadata_route: Literal["/.well-known/oauth-protected-resource"]
    local_metadata_resource: Literal["https://mcp.example.test"]
    public_mcp_transport_endpoint: Literal["https://mcp.example.test/mcp"]
    public_oauth_resource: Literal["https://mcp.example.test"]
    public_oauth_audience: None


class DispatchCounts(_StrictModel):
    """Vendor-only dispatch counters when a public observation hook exists."""

    sdk_authentication: int = Field(ge=0, le=1)
    legacy: int = Field(ge=0, le=1)
    session_manager: int = Field(ge=0, le=1)
    handler: int = Field(ge=0, le=1)
    second_token_verifier: int = Field(ge=0, le=1)


class VendorRawObservation(_StrictModel):
    """Raw vendor request/response evidence, when Alpic publishes it."""

    request: RawHttpRequest
    response: RawHttpResponse


class AlpicOAuthDiscoveryCapabilityVerdict(_DigestModel):
    """Closed Alpic discovery verdict separating local and vendor evidence."""

    schema_version: Literal["2.0"]
    detector_contract_source: Literal["bounded_documented_approximation"]
    detector_contract_provenance: NonEmpty
    bounded_request_fixture: RawHttpRequest
    request_digest: Sha256
    exact_detector_fixture_supported: Literal[False]
    vendor_raw_observation: None
    local_sdk_observation: SdkHttpObservation
    local_observation_digest: Sha256
    route_bindings: RouteBindings
    rewrite_mapping: RewriteMapping
    installed_sdk_tree_sha256: Sha256
    authenticates_before_modern_only_routing_guard: None
    dispatch_counts: None
    supported: Literal[False]
    blockers: Annotated[
        tuple[
            Literal[
                "ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN",
                "ALPIC_PRM_ROUTE_COMPATIBILITY_UNPROVEN",
                "ALPIC_OAUTH_DISCOVERY_ORDERING_UNPROVEN",
            ],
            ...,
        ],
        Field(min_length=3, max_length=3),
    ]
    reviewed_date: ReviewDate

    @model_validator(mode="after")
    def _check_alpic_state(self) -> AlpicOAuthDiscoveryCapabilityVerdict:
        if self.request_digest != _sha256_json(
            _model_json(self.bounded_request_fixture),
        ):
            msg = "request_digest does not bind the bounded request fixture"
            raise ValueError(msg)
        if self.local_observation_digest != _sha256_json(
            _model_json(self.local_sdk_observation),
        ):
            msg = "local_observation_digest does not bind the SDK observation"
            raise ValueError(msg)
        local = self.local_sdk_observation
        if (
            local.case_id != "alpic.local-sdk-initialize"
            or local.request != self.bounded_request_fixture
            or local.request != _expected_initialize_request()
            or local.response
            != _expected_error_response(
                status_code=HTTP_UNAUTHORIZED,
                error="invalid_token",
                description="Authentication required",
                challenge=_INVALID_TOKEN_CHALLENGE,
            )
            or local.verifier_calls != 0
            or local.verifier_tokens
            or local.downstream_dispatch_count != 0
        ):
            msg = "local SDK probe must observe one pre-dispatch HTTP 401 challenge"
            raise ValueError(msg)
        challenge_values = _header_values(local.response.headers, "www-authenticate")
        if challenge_values != (_INVALID_TOKEN_CHALLENGE,) or _parse_bearer_challenge(
            challenge_values[0]
        ) != {
            "error": "invalid_token",
            "error_description": "Authentication required",
            "resource_metadata": self.route_bindings.challenge_resource_metadata,
        }:
            msg = "local SDK challenge is not the bound Bearer resource challenge"
            raise ValueError(msg)
        if self.rewrite_mapping != RewriteMapping(observed=False, entries=()):
            msg = "no Alpic rewrite was observed in the bounded local probe"
            raise ValueError(msg)
        if self.installed_sdk_tree_sha256 != _package_tree_sha256("mcp"):
            msg = "installed SDK package tree differs from Alpic capability record"
            raise ValueError(msg)
        if (
            self.detector_contract_provenance != _ALPIC_PROVENANCE
            or self.reviewed_date != _REVIEWED_DATE
        ):
            msg = "Alpic capability provenance differs from the reviewed observation"
            raise ValueError(msg)
        if self.blockers != (
            "ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN",
            "ALPIC_PRM_ROUTE_COMPATIBILITY_UNPROVEN",
            "ALPIC_OAUTH_DISCOVERY_ORDERING_UNPROVEN",
        ):
            msg = "an unsupported Alpic verdict must preserve every stable blocker"
            raise ValueError(msg)
        return self


TokenFormat = Literal["signed_jwt", "opaque"]
RegistrationMode = Literal["preregistered", "cimd", "dcr"]


class OAuthProviderCapabilityVerdict(_DigestModel):
    """Closed provider-capability verdict for a selected OAuth issuer."""

    schema_version: Literal["1.0"]
    selected_issuer: NonEmpty | None
    discovery_issuer: NonEmpty | None
    authorization_endpoint: NonEmpty | None
    token_endpoint: NonEmpty | None
    jwks_uri: NonEmpty | None
    introspection_endpoint: NonEmpty | None
    access_token_format: TokenFormat | None
    resource: NonEmpty | None
    audience: NonEmpty | None
    access_token_purpose_claim: NonEmpty | None
    client_identity_claim: NonEmpty | None
    pkce_method: Literal["S256", "unproven"]
    authorization_response_issuer: Literal["required", "observed", "unproven"]
    scopes: Annotated[tuple[NonEmpty, ...], Field(max_length=_MAX_PERSISTED_ITEMS)]
    token_lifetime_seconds: int | None = Field(default=None, ge=1)
    revocation: Literal["supported", "unsupported", "unproven"]
    registration_modes: Annotated[
        tuple[RegistrationMode, ...],
        Field(max_length=3),
    ]
    evidence_source: NonEmpty
    evidence_digest: Sha256 | None
    supported: bool
    blockers: Annotated[
        tuple[
            Literal[
                "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
                "OAUTH_END_TO_END_FLOW_UNPROVEN",
                "ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN",
            ],
            ...,
        ],
        Field(max_length=3),
    ]
    reviewed_date: ReviewDate

    @model_validator(mode="after")
    def _check_provider_state(self) -> OAuthProviderCapabilityVerdict:
        if self.supported:
            if (
                self.selected_issuer is None
                or self.access_token_format is None
                or not self.evidence_digest
            ):
                msg = (
                    "a supported provider verdict requires selected, evidenced "
                    "capabilities"
                )
                raise ValueError(msg)
            if not self.registration_modes:
                msg = "a supported provider verdict requires a registration mode"
                raise ValueError(msg)
        elif any(
            value is not None
            for value in (
                self.selected_issuer,
                self.discovery_issuer,
                self.access_token_format,
                self.evidence_digest,
            )
        ):
            msg = (
                "an unselected provider verdict cannot select issuer, token format, "
                "or evidence"
            )
            raise ValueError(msg)
        if not self.supported and self.registration_modes != ("dcr",):
            msg = "the selected Auth0/Alpic topology requires DCR registration"
            raise ValueError(msg)
        if not self.supported and self.blockers != (
            "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
            "ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN",
            "OAUTH_END_TO_END_FLOW_UNPROVEN",
        ):
            msg = (
                "an unselected provider must preserve every selected Auth0/Alpic "
                "DCR blocker; must preserve OAUTH_PROVIDER_CAPABILITY_UNPROVEN"
            )
            raise ValueError(msg)
        return self


TaskSdkSupport = Literal["unsupported", "supported"]
TasksRevisionState = Literal["draft", "stable"]
TasksProviderState = Literal["not_assessed", "proven", "unsupported"]
AlpicTasksSourceId = Literal[
    "alpic_tasks_docs",
    "python_sdk_roadmap",
    "mcp_tasks_spec",
]
AlpicTasksSourceObservation = Literal[
    "tasks_compute_advertised",
    "sdk_tasks_deferred",
    "tasks_extension_draft",
]
AlpicTasksBlocker = Literal[
    "MCP_TASKS_REVISION_UNFROZEN",
    "PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE",
    "PYTHON_SDK_TASKS_CLIENT_UNAVAILABLE",
    "ALPIC_TASKS_PYTHON_INTEGRATION_UNPROVEN",
    "ALPIC_TASK_CREATION_DURABILITY_UNPROVEN",
    "ALPIC_TASK_RESTART_RECOVERY_UNPROVEN",
    "ALPIC_TASK_CANCELLATION_UNPROVEN",
    "ALPIC_TASK_ISOLATION_UNPROVEN",
    "ALPIC_TASK_RETENTION_UNPROVEN",
    "ALPIC_TASK_ARTIFACT_DELIVERY_UNPROVEN",
    "ALPIC_TASK_CLIENT_SUPPORT_UNPROVEN",
]
EvidenceIdentity = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$",
        strict=True,
    ),
]


def _canonical_negative_alpic_tasks_blockers(
    *,
    extension_revision_state: TasksRevisionState,
    sdk_server_support: TaskSdkSupport,
    sdk_client_support: TaskSdkSupport,
    provider_states: tuple[tuple[TasksProviderState, AlpicTasksBlocker], ...],
) -> tuple[AlpicTasksBlocker, ...]:
    """Derive the exact ordered blockers implied by one negative state."""
    required: set[AlpicTasksBlocker] = {
        blocker for state, blocker in provider_states if state != "proven"
    }
    if extension_revision_state != "stable":
        required.add("MCP_TASKS_REVISION_UNFROZEN")
    if sdk_server_support != "supported":
        required.add("PYTHON_SDK_TASKS_EXTENSION_UNAVAILABLE")
    if sdk_client_support != "supported":
        required.add("PYTHON_SDK_TASKS_CLIENT_UNAVAILABLE")
    return tuple(blocker for blocker in _ALPIC_TASKS_BLOCKERS if blocker in required)


class AlpicTasksSourceRecord(_StrictModel):
    """A bounded digest-only capture of one allowlisted primary source."""

    source_id: AlpicTasksSourceId
    url: NonEmpty
    final_url: NonEmpty
    retrieved_at: UtcTimestamp
    status_code: Literal[200]
    media_type: Literal["text/html", "text/plain"]
    content_length_bytes: int = Field(ge=1, le=1_048_576)
    content_sha256: Sha256
    observation: AlpicTasksSourceObservation

    @field_validator("url", "final_url")
    @classmethod
    def _require_allowlisted_https_url(cls, value: str) -> str:
        """Reject credentials, redirects, and ambiguous source locations."""
        try:
            parsed = urlsplit(value)
        except ValueError as error:
            msg = "Alpic Tasks source URL is malformed"
            raise ValueError(msg) from error
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
        ):
            msg = "Alpic Tasks source URL must be credential-free canonical HTTPS"
            raise ValueError(msg)
        if parsed.hostname in {"github.com", "raw.githubusercontent.com"} and (
            parsed.hostname != "raw.githubusercontent.com"
            or re.fullmatch(
                r"/modelcontextprotocol/python-sdk/[0-9a-f]{40}/ROADMAP\.md",
                parsed.path,
            )
            is None
        ):
            msg = "the Python SDK roadmap URL must name an immutable commit"
            raise ValueError(msg)
        return value


class AlpicTasksSourceEvidence(_StrictModel):
    """Canonical source metadata, never a substitute for live provider proof."""

    schema_version: Literal["1.0"]
    sources: Annotated[
        tuple[AlpicTasksSourceRecord, ...], Field(min_length=3, max_length=3)
    ]
    evidence_digest: Sha256

    @model_validator(mode="after")
    def _check_source_evidence(self) -> AlpicTasksSourceEvidence:
        expected = _ALPIC_TASKS_SOURCE_REQUIREMENTS
        observed = tuple(
            (source.source_id, source.url, source.observation)
            for source in self.sources
        )
        if observed != expected:
            msg = (
                "Alpic Tasks source evidence has an unexpected source, URL, "
                "or observation"
            )
            raise ValueError(msg)
        if any(source.final_url != source.url for source in self.sources):
            msg = "Alpic Tasks source evidence must not follow redirects"
            raise ValueError(msg)
        if tuple(source.media_type for source in self.sources) != (
            "text/html",
            "text/plain",
            "text/html",
        ):
            msg = "Alpic Tasks source evidence has an unexpected media type"
            raise ValueError(msg)
        expected_digest = _sha256_json(
            cast(
                "dict[str, object]",
                self.model_dump(mode="json", exclude={"evidence_digest"}),
            )
        )
        if self.evidence_digest != expected_digest:
            msg = "evidence_digest does not match the canonical source evidence"
            raise ValueError(msg)
        return self


class _AlpicTasksCapabilityBase(_DigestModel):
    """Fields shared by both closed Alpic Tasks capability states."""

    schema_version: Literal["1.0"]
    provider: Literal["alpic"]
    extension_identifier: Literal["io.modelcontextprotocol/tasks"]
    installed_sdk_tree_sha256: Sha256
    provider_tasks_compute: Literal["advertised"]
    provider_ordinary_timeout_seconds: Literal[30]
    source_evidence_digest: Sha256
    documentation_provenance: NonEmpty
    reviewed_date: ReviewDate


class AlpicTasksLiveEvidenceIdentity(_StrictModel):
    """Digest-only identities required by an authorized positive assessment."""

    environment_id: EvidenceIdentity
    deployment_id: EvidenceIdentity
    pack_sha256: Sha256
    sdk_wheel_sha256: Sha256
    protocol_revision_sha256: Sha256
    client_identities_sha256: Sha256
    evidence_digest: Sha256
    observed_at: UtcTimestamp


class UnsupportedAlpicTasksCapabilityVerdict(_AlpicTasksCapabilityBase):
    """A strict negative verdict that cannot carry live-evidence identities."""

    extension_revision_state: TasksRevisionState
    mcp_version: Literal["2.1.1"]
    mcp_types_version: Literal["2.1.1"]
    sdk_server_support: TaskSdkSupport
    sdk_client_support: TaskSdkSupport
    provider_default_task_ttl_seconds: Literal[21600]
    provider_integration: TasksProviderState
    task_creation_durability: TasksProviderState
    restart_recovery: TasksProviderState
    cancellation: TasksProviderState
    isolation: TasksProviderState
    retention: TasksProviderState
    artifact_delivery: TasksProviderState
    client_support: TasksProviderState
    supported: Literal[False]
    blockers: Annotated[
        tuple[AlpicTasksBlocker, ...],
        Field(min_length=1, max_length=len(_ALPIC_TASKS_BLOCKERS)),
    ]

    @model_validator(mode="after")
    def _check_current_negative_state(
        self,
    ) -> UnsupportedAlpicTasksCapabilityVerdict:
        if self.mcp_version != importlib.metadata.version("mcp"):
            msg = "installed mcp version differs from Alpic Tasks capability record"
            raise ValueError(msg)
        if self.mcp_types_version != importlib.metadata.version("mcp-types"):
            msg = (
                "installed mcp-types version differs from Alpic Tasks capability record"
            )
            raise ValueError(msg)
        if self.source_evidence_digest != _ALPIC_TASKS_SOURCE_EVIDENCE_DIGEST:
            msg = "Alpic Tasks verdict is not bound to the reviewed source evidence"
            raise ValueError(msg)
        if self.installed_sdk_tree_sha256 != _package_tree_sha256("mcp"):
            msg = (
                "installed SDK package tree differs from Alpic Tasks capability record"
            )
            raise ValueError(msg)
        if (
            self.documentation_provenance != _ALPIC_TASKS_PROVENANCE
            or self.reviewed_date != _TASKS_REVIEWED_DATE
        ):
            msg = "Alpic Tasks provenance differs from the reviewed assessment"
            raise ValueError(msg)
        provider_values = (
            self.provider_integration,
            self.task_creation_durability,
            self.restart_recovery,
            self.cancellation,
            self.isolation,
            self.retention,
            self.artifact_delivery,
            self.client_support,
        )
        if any(state == "proven" for state in provider_values):
            msg = "unauthorized provider claims require live evidence identities"
            raise ValueError(msg)
        provider_states: tuple[tuple[TasksProviderState, AlpicTasksBlocker], ...] = (
            (
                self.provider_integration,
                "ALPIC_TASKS_PYTHON_INTEGRATION_UNPROVEN",
            ),
            (
                self.task_creation_durability,
                "ALPIC_TASK_CREATION_DURABILITY_UNPROVEN",
            ),
            (self.restart_recovery, "ALPIC_TASK_RESTART_RECOVERY_UNPROVEN"),
            (self.cancellation, "ALPIC_TASK_CANCELLATION_UNPROVEN"),
            (self.isolation, "ALPIC_TASK_ISOLATION_UNPROVEN"),
            (self.retention, "ALPIC_TASK_RETENTION_UNPROVEN"),
            (self.artifact_delivery, "ALPIC_TASK_ARTIFACT_DELIVERY_UNPROVEN"),
            (self.client_support, "ALPIC_TASK_CLIENT_SUPPORT_UNPROVEN"),
        )
        canonical_blockers = _canonical_negative_alpic_tasks_blockers(
            extension_revision_state=self.extension_revision_state,
            sdk_server_support=self.sdk_server_support,
            sdk_client_support=self.sdk_client_support,
            provider_states=provider_states,
        )
        if self.blockers != canonical_blockers:
            msg = "the negative Alpic Tasks verdict must preserve every blocker"
            raise ValueError(msg)
        return self


class SupportedAlpicTasksCapabilityVerdict(_AlpicTasksCapabilityBase):
    """Structurally complete positive branch, inaccessible to operational loading."""

    extension_revision_state: Literal["stable"]
    mcp_version: PackageVersion
    mcp_types_version: PackageVersion
    sdk_server_support: Literal["supported"]
    sdk_client_support: Literal["supported"]
    provider_default_task_ttl_seconds: int = Field(strict=True, ge=1, le=21600)
    provider_integration: Literal["proven"]
    task_creation_durability: Literal["proven"]
    restart_recovery: Literal["proven"]
    cancellation: Literal["proven"]
    isolation: Literal["proven"]
    retention: Literal["proven"]
    artifact_delivery: Literal["proven"]
    client_support: Literal["proven"]
    live_evidence: AlpicTasksLiveEvidenceIdentity
    supported: Literal[True]
    blockers: Annotated[tuple[AlpicTasksBlocker, ...], Field(max_length=0)]

    @model_validator(mode="after")
    def _require_protected_operational_validation(
        self,
        info: ValidationInfo[dict[str, object] | None],
    ) -> SupportedAlpicTasksCapabilityVerdict:
        if (
            info.context is None
            or info.context.get("allow_synthetic_tasks_supported") is not True
        ):
            msg = (
                "a supported Alpic Tasks verdict requires protected operational "
                "validation"
            )
            raise ValueError(msg)
        return self


type AlpicTasksCapabilityVerdict = Annotated[
    UnsupportedAlpicTasksCapabilityVerdict | SupportedAlpicTasksCapabilityVerdict,
    Field(discriminator="supported"),
]

_ALPIC_TASKS_VERDICT_ADAPTER: TypeAdapter[AlpicTasksCapabilityVerdict] = TypeAdapter(
    AlpicTasksCapabilityVerdict
)


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_json(value: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _model_json(value: BaseModel) -> dict[str, object]:
    return cast("dict[str, object]", value.model_dump(mode="json"))


def canonical_json_sha256(value: Mapping[str, object]) -> str:
    """Return the SHA-256 digest of a canonical JSON-compatible mapping."""
    return _sha256_json(value)


def canonical_model_json(value: BaseModel) -> dict[str, object]:
    """Return a JSON-compatible Pydantic payload with no untyped values."""
    return _model_json(value)


def validate_alpic_tasks_verdict_json(
    raw: str | bytes,
) -> AlpicTasksCapabilityVerdict:
    """Validate an operational Alpic Tasks union record from JSON bytes."""
    return _ALPIC_TASKS_VERDICT_ADAPTER.validate_json(raw)


def validate_synthetic_alpic_tasks_verdict(
    value: Mapping[str, object],
) -> SupportedAlpicTasksCapabilityVerdict:
    """Reach the positive schema branch without granting operational authority."""
    verdict = _ALPIC_TASKS_VERDICT_ADAPTER.validate_json(
        _canonical_bytes(dict(value)),
        context=cast(
            "dict[str, object]",
            {"allow_synthetic_tasks_supported": True},
        ),
    )
    if not isinstance(verdict, SupportedAlpicTasksCapabilityVerdict):
        msg = "synthetic Alpic Tasks validation requires supported=true"
        raise CapabilityContractError(msg)
    return verdict


def _finalize[DigestModelT: _DigestModel](
    model_type: type[DigestModelT],
    values: Mapping[str, object],
) -> DigestModelT:
    draft = model_type.model_validate(
        cast("dict[str, object]", {**values, "verdict_digest": "0" * 64}),
        context=cast("dict[str, object]", {"skip_digest": True}),
    )
    payload = cast(
        "dict[str, object]",
        draft.model_dump(mode="json", exclude={"verdict_digest"}),
    )
    return draft.model_copy(
        update=cast("dict[str, object]", {"verdict_digest": _sha256_json(payload)}),
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            msg = f"duplicate JSON key: {key}"
            raise CapabilityContractError(msg)
        result[key] = value
    return result


def _load[ModelT: _StrictModel](path: Path, model_type: type[ModelT]) -> ModelT:
    with path.open("rb") as stream:
        raw = stream.read(_MAX_RAW_CONTRACT_BYTES + 1)
    if len(raw) > _MAX_RAW_CONTRACT_BYTES:
        msg = "capability contract exceeds the raw-byte limit"
        raise CapabilityContractError(msg)
    try:
        value = cast(
            "object",
            json.loads(raw, object_pairs_hook=_reject_duplicate_pairs),
        )
    except (CapabilityContractError, json.JSONDecodeError) as exc:
        msg = f"invalid capability JSON: {path}"
        raise CapabilityContractError(msg) from exc
    if not isinstance(value, dict):
        msg = "capability contract must be a JSON object"
        raise CapabilityContractError(msg)
    try:
        model = model_type.model_validate_json(raw)
    except Exception as exc:
        msg = f"capability contract failed validation: {path}"
        raise CapabilityContractError(msg) from exc
    canonical = (
        _canonical_bytes(cast("dict[str, object]", model.model_dump(mode="json")))
        + b"\n"
    )
    if raw != canonical:
        msg = "capability contract is not canonical JSON"
        raise CapabilityContractError(msg)
    return model


def _load_alpic_tasks_contract(path: Path) -> AlpicTasksCapabilityVerdict:
    """Load the Tasks union while refusing synthetic positive authority."""
    with path.open("rb") as stream:
        raw = stream.read(_MAX_RAW_CONTRACT_BYTES + 1)
    if len(raw) > _MAX_RAW_CONTRACT_BYTES:
        msg = "capability contract exceeds the raw-byte limit"
        raise CapabilityContractError(msg)
    try:
        value = cast(
            "object",
            json.loads(raw, object_pairs_hook=_reject_duplicate_pairs),
        )
    except (CapabilityContractError, json.JSONDecodeError) as exc:
        msg = f"invalid capability JSON: {path}"
        raise CapabilityContractError(msg) from exc
    if type(value) is not dict:
        msg = "capability contract must be a JSON object"
        raise CapabilityContractError(msg)
    contract_value = cast("dict[str, object]", value)
    if contract_value.get("supported") is True:
        msg = (
            "supported Alpic Tasks capability requires protected operational validation"
        )
        raise CapabilityContractError(msg)
    try:
        model = validate_alpic_tasks_verdict_json(raw)
    except Exception as exc:
        msg = f"capability contract failed validation: {path}"
        raise CapabilityContractError(msg) from exc
    canonical = (
        _canonical_bytes(cast("dict[str, object]", model.model_dump(mode="json")))
        + b"\n"
    )
    if raw != canonical:
        msg = "capability contract is not canonical JSON"
        raise CapabilityContractError(msg)
    return model


def _package_tree_sha256(package_name: str) -> str:
    package = importlib.import_module(package_name)
    if package.__file__ is None:
        msg = "capability package has no filesystem path"
        raise CapabilityContractError(msg)
    root = Path(package.__file__).parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if (
            path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        ):
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        msg = "invalid base64 evidence"
        raise ValueError(msg) from exc


def _body_evidence(value: bytes) -> tuple[str, str]:
    return base64.b64encode(value).decode("ascii"), hashlib.sha256(value).hexdigest()


def _header_values(headers: tuple[Header, ...], name: str) -> tuple[str, ...]:
    lowered = name.lower()
    return tuple(header.value for header in headers if header.name.lower() == lowered)


def _headers(values: list[tuple[str, str]]) -> tuple[Header, ...]:
    return tuple(Header(name=name, value=value) for name, value in values)


def _parse_bearer_challenge(value: str) -> dict[str, str]:
    prefix = "Bearer "
    if not value.startswith(prefix):
        msg = "WWW-Authenticate challenge is not Bearer"
        raise ValueError(msg)
    source = value[len(prefix) :]
    parameter = re.compile(
        r'(?P<name>[A-Za-z][A-Za-z0-9_-]{0,63})="(?P<value>[^"\\\r\n]*)"',
    )
    result: dict[str, str] = {}
    offset = 0
    while offset < len(source):
        match = parameter.match(source, offset)
        if match is None:
            msg = "WWW-Authenticate Bearer parameters are malformed"
            raise ValueError(msg)
        name = match.group("name")
        if name in result:
            msg = "WWW-Authenticate Bearer parameter is duplicated"
            raise ValueError(msg)
        result[name] = match.group("value")
        offset = match.end()
        if offset == len(source):
            break
        if source[offset : offset + 2] != ", ":
            msg = "WWW-Authenticate Bearer parameters use invalid separators"
            raise ValueError(msg)
        offset += 2
    if not result:
        msg = "WWW-Authenticate Bearer challenge has no parameters"
        raise ValueError(msg)
    return result


def _raw_request(body: bytes, headers: tuple[tuple[str, str], ...]) -> RawHttpRequest:
    with httpx.Client(base_url="https://mcp.example.test") as client:
        prepared = client.build_request(
            "POST",
            "/mcp",
            headers=list(headers),
            content=body,
        )
    body_base64, body_sha256 = _body_evidence(body)
    return RawHttpRequest(
        method="POST",
        path="/mcp",
        headers=_headers(list(prepared.headers.multi_items())),
        body_base64=body_base64,
        body_sha256=body_sha256,
    )


def _expected_tool_request(
    tool_name: str,
    authorization_values: tuple[str, ...],
) -> RawHttpRequest:
    return _raw_request(
        _tool_call_body(tool_name),
        _tool_headers(
            tool_name,
            *(("Authorization", value) for value in authorization_values),
        ),
    )


def _expected_initialize_request() -> RawHttpRequest:
    return _raw_request(
        _initialize_body(),
        (
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
        ),
    )


def _expected_error_response(
    *,
    status_code: Literal[401, 403],
    error: Literal["invalid_token", "insufficient_scope"],
    description: str,
    challenge: str,
) -> RawHttpResponse:
    error_payload: dict[str, str] = {
        "error": error,
        "error_description": description,
    }
    body = json.dumps(
        error_payload,
        allow_nan=False,
        ensure_ascii=False,
    ).encode("utf-8")
    body_base64, body_sha256 = _body_evidence(body)
    return RawHttpResponse(
        status_code=status_code,
        headers=_headers(
            [
                ("content-length", str(len(body))),
                ("content-type", "application/json"),
                ("www-authenticate", challenge),
            ],
        ),
        body_base64=body_base64,
        body_sha256=body_sha256,
    )


def _expected_dispatch_response() -> RawHttpResponse:
    body = (
        b'{"jsonrpc":"2.0","id":1,"result":{"content":'
        b'[{"text":"fixture-dispatched","type":"text"}],"isError":false,'
        b'"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":'
        b'{"name":"nplg-capability-probe","version":""}}}}'
    )
    body_base64, body_sha256 = _body_evidence(body)
    return RawHttpResponse(
        status_code=200,
        headers=_headers(
            [
                ("content-length", str(len(body))),
                ("content-type", "application/json"),
            ],
        ),
        body_base64=body_base64,
        body_sha256=body_sha256,
    )


def _package_file_sha256(package_name: str, relative_path: str) -> str:
    package = importlib.import_module(package_name)
    if package.__file__ is None:
        msg = "capability package has no filesystem path"
        raise CapabilityContractError(msg)
    path = Path(package.__file__).parent / relative_path
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _FixtureTokenVerifier:
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

    async def verify_token(self, token: str) -> AccessToken | None:
        self.calls.append(token)
        fixture: tuple[list[str], int | None] | None = {
            "weak-fixture-token": (["nplg:connect"], None),
            "strong-fixture-token": (["nplg:connect", "nplg:search"], None),
            "expired-fixture-token": (["nplg:search"], 1),
        }.get(token)
        if fixture is None:
            return None
        scopes, expires_at = fixture
        return AccessToken(
            token=token,
            client_id="fixture-client",
            scopes=scopes,
            expires_at=expires_at,
        )


class _FixtureDispatchCounter:
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    async def call_tool(
        self,
        _context: ServerRequestContext[None, mcp_types.CallToolRequestParams],
        _params: mcp_types.CallToolRequestParams,
    ) -> mcp_types.CallToolResult:
        self.calls += 1
        return mcp_types.CallToolResult(
            content=[
                mcp_types.TextContent(type="text", text="fixture-dispatched"),
            ],
        )


class _FixtureProbeState:
    def __init__(self) -> None:
        super().__init__()
        self.verifier = _FixtureTokenVerifier()
        self.dispatch = _FixtureDispatchCounter()


@asynccontextmanager
async def _fixture_lifespan(_server: Server[None]) -> AsyncGenerator[None]:
    yield None


def _sdk_probe_app(
    state: _FixtureProbeState,
) -> Starlette:
    server: Server[None] = Server(
        "nplg-capability-probe",
        lifespan=_fixture_lifespan,
        on_call_tool=state.dispatch.call_tool,
    )
    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        host="mcp.example.test",
        auth=AuthSettings(
            issuer_url=AnyHttpUrl("https://issuer.example.test"),
            resource_server_url=AnyHttpUrl("https://mcp.example.test"),
            required_scopes=["nplg:search"],
        ),
        token_verifier=state.verifier,
    )


def _tool_call_body(tool_name: str) -> bytes:
    return _canonical_bytes(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {"query": "fixture"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        },
    )


def _initialize_body() -> bytes:
    return _canonical_bytes(
        {"id": 1, "jsonrpc": "2.0", "method": "initialize", "params": {}},
    )


async def _observe_http_case(
    client: httpx.AsyncClient,
    state: _FixtureProbeState,
    *,
    case_id: SdkCaseId,
    body: bytes,
    headers: tuple[tuple[str, str], ...],
) -> SdkHttpObservation:
    verifier_before = len(state.verifier.calls)
    dispatch_before = state.dispatch.calls
    response = await client.post("/mcp", headers=list(headers), content=body)
    request_body = response.request.content
    response_body = response.content
    if response.request.url.raw_path != b"/mcp":
        msg = "SDK probe request path changed"
        raise CapabilityContractError(msg)
    request_base64, request_sha256 = _body_evidence(request_body)
    response_base64, response_sha256 = _body_evidence(response_body)
    return SdkHttpObservation(
        case_id=case_id,
        request=RawHttpRequest(
            method="POST",
            path="/mcp",
            headers=_headers(list(response.request.headers.multi_items())),
            body_base64=request_base64,
            body_sha256=request_sha256,
        ),
        response=RawHttpResponse(
            status_code=response.status_code,
            headers=_headers(sorted(response.headers.multi_items())),
            body_base64=response_base64,
            body_sha256=response_sha256,
        ),
        verifier_calls=len(state.verifier.calls) - verifier_before,
        verifier_tokens=tuple(state.verifier.calls[verifier_before:]),
        downstream_dispatch_count=state.dispatch.calls - dispatch_before,
    )


def _tool_headers(
    tool_name: str,
    *authorization: tuple[str, str],
) -> tuple[tuple[str, str], ...]:
    return (
        ("Accept", "application/json, text/event-stream"),
        ("Content-Type", "application/json"),
        ("MCP-Protocol-Version", LATEST_PROTOCOL_VERSION),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", tool_name),
        *authorization,
    )


async def _observe_sdk_matrix() -> tuple[SdkHttpObservation, ...]:
    state = _FixtureProbeState()
    app = _sdk_probe_app(state)
    cases: tuple[
        tuple[SdkCaseId, str, tuple[tuple[str, str], ...]],
        ...,
    ] = (
        ("authorization.missing", "search_documents", ()),
        (
            "authorization.basic",
            "search_documents",
            (("Authorization", "Basic Zml4dHVyZTphdXRo"),),
        ),
        (
            "authorization.invalid-bearer",
            "search_documents",
            (("Authorization", "Bearer invalid-fixture-token"),),
        ),
        (
            "authorization.expired-bearer",
            "search_documents",
            (("Authorization", "Bearer expired-fixture-token"),),
        ),
        (
            "authorization.weak-scope-search",
            "search_documents",
            (("Authorization", "Bearer weak-fixture-token"),),
        ),
        (
            "authorization.weak-scope-inspect",
            "inspect_pdf",
            (("Authorization", "Bearer weak-fixture-token"),),
        ),
        (
            "authorization.sufficient-scope-control",
            "search_documents",
            (("Authorization", "Bearer strong-fixture-token"),),
        ),
        (
            "authorization.duplicate",
            "search_documents",
            (
                ("Authorization", "Bearer weak-fixture-token"),
                ("Authorization", "Bearer strong-fixture-token"),
            ),
        ),
    )
    observations: list[SdkHttpObservation] = []
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://mcp.example.test",
        ) as client,
    ):
        for case_id, tool_name, authorization in cases:
            observations.append(
                await _observe_http_case(
                    client,
                    state,
                    case_id=case_id,
                    body=_tool_call_body(tool_name),
                    headers=_tool_headers(tool_name, *authorization),
                ),
            )
    return tuple(observations)


async def _observe_alpic_local_sdk() -> SdkHttpObservation:
    state = _FixtureProbeState()
    app = _sdk_probe_app(state)
    headers = (
        ("Accept", "application/json, text/event-stream"),
        ("Content-Type", "application/json"),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://mcp.example.test",
    ) as client:
        return await _observe_http_case(
            client,
            state,
            case_id="alpic.local-sdk-initialize",
            body=_initialize_body(),
            headers=headers,
        )


def probe_sdk_authorization() -> SdkAuthorizationCapabilityVerdict:
    """Observe the pinned SDK authorization boundary through its public ASGI app."""
    observations = asyncio.run(_observe_sdk_matrix())
    weak = observations[4]
    challenge_values = _header_values(weak.response.headers, "www-authenticate")
    if len(challenge_values) != 1:
        msg = "official SDK did not emit exactly one weak-scope challenge"
        raise CapabilityContractError(msg)
    requests: list[object] = [_model_json(item.request) for item in observations]
    observation_values: list[object] = [_model_json(item) for item in observations]
    return _finalize(
        SdkAuthorizationCapabilityVerdict,
        {
            "schema_version": "2.0",
            "mcp_version": importlib.metadata.version("mcp"),
            "mcp_types_version": importlib.metadata.version("mcp-types"),
            "upstream_repository": "https://github.com/modelcontextprotocol/python-sdk",
            "upstream_commit": None,
            "upstream_commit_unavailable_reason": (
                _SDK_UPSTREAM_COMMIT_UNAVAILABLE_REASON
            ),
            "locked_artifact_sha256s": (
                "1c6c31c5d6471c58db76af3af8af67f46d11d01f0a59077d0a308cbdb3d3e915",
                "50b7ba1ebbe117008ea7bdd288234043e69c20b403d6851d19661e6d431a75ef",
            ),
            "installed_package_tree_sha256": _package_tree_sha256("mcp"),
            "sdk_boundary_file": "mcp/server/auth/middleware/bearer_auth.py",
            "sdk_boundary_file_sha256": _package_file_sha256(
                "mcp",
                "server/auth/middleware/bearer_auth.py",
            ),
            "protocol_revision": f"MCP-{LATEST_PROTOCOL_VERSION}",
            "observation_source": "official_sdk_public_asgi",
            "asgi_case_digest": _sha256_json({"requests": requests}),
            "asgi_observation_digest": _sha256_json(
                {"observations": observation_values},
            ),
            "sdk_extension_point": "none",
            "parsed_operation_identity_at_http_auth_boundary": False,
            "routing_header_trusted": False,
            "private_mcp_reparse": False,
            "scope_challenge": ScopeChallenge(
                status_code=403,
                header_value=challenge_values[0],
                required_scope="nplg:search",
                advertised_scope=None,
            ),
            "missing_authorization_observation": observations[0],
            "basic_authorization_observation": observations[1],
            "invalid_bearer_observation": observations[2],
            "expired_bearer_observation": observations[3],
            "weak_scope_observation": observations[4],
            "weak_scope_alternate_tool_observation": observations[5],
            "sufficient_scope_control": observations[6],
            "duplicate_authorization_observation": observations[7],
            "supported": False,
            "blockers": (
                "MCP_DYNAMIC_SCOPE_403_UNSUPPORTED",
                "SDK_DUPLICATE_AUTHORIZATION_REQUIRES_OUTER_REJECTION",
            ),
            "reason": _SDK_REASON,
            "reviewed_date": _REVIEWED_DATE,
        },
    )


def probe_alpic_oauth_discovery() -> AlpicOAuthDiscoveryCapabilityVerdict:
    """Record a local SDK 401 without promoting it to an Alpic observation."""
    local = asyncio.run(_observe_alpic_local_sdk())
    bounded_request = local.request
    bindings = RouteBindings(
        backend_resource_server_url="https://mcp.example.test",
        challenge_resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource",
        local_metadata_route="/.well-known/oauth-protected-resource",
        local_metadata_resource="https://mcp.example.test",
        public_mcp_transport_endpoint="https://mcp.example.test/mcp",
        public_oauth_resource="https://mcp.example.test",
        public_oauth_audience=None,
    )
    rewrite = RewriteMapping(observed=False, entries=())
    return _finalize(
        AlpicOAuthDiscoveryCapabilityVerdict,
        {
            "schema_version": "2.0",
            "detector_contract_source": "bounded_documented_approximation",
            "detector_contract_provenance": _ALPIC_PROVENANCE,
            "bounded_request_fixture": bounded_request,
            "request_digest": _sha256_json(
                _model_json(bounded_request),
            ),
            "exact_detector_fixture_supported": False,
            "vendor_raw_observation": None,
            "local_sdk_observation": local,
            "local_observation_digest": _sha256_json(
                _model_json(local),
            ),
            "route_bindings": bindings,
            "rewrite_mapping": rewrite,
            "installed_sdk_tree_sha256": _package_tree_sha256("mcp"),
            "authenticates_before_modern_only_routing_guard": None,
            "dispatch_counts": None,
            "supported": False,
            "blockers": (
                "ALPIC_OAUTH_DETECTOR_FIXTURE_UNPROVEN",
                "ALPIC_PRM_ROUTE_COMPATIBILITY_UNPROVEN",
                "ALPIC_OAUTH_DISCOVERY_ORDERING_UNPROVEN",
            ),
            "reviewed_date": _REVIEWED_DATE,
        },
    )


def probe_oauth_provider() -> OAuthProviderCapabilityVerdict:
    """Return the fail-closed provider verdict until an issuer is selected."""
    return _finalize(
        OAuthProviderCapabilityVerdict,
        {
            "schema_version": "1.0",
            "selected_issuer": None,
            "discovery_issuer": None,
            "authorization_endpoint": None,
            "token_endpoint": None,
            "jwks_uri": None,
            "introspection_endpoint": None,
            "access_token_format": None,
            "resource": None,
            "audience": None,
            "access_token_purpose_claim": None,
            "client_identity_claim": None,
            "pkce_method": "unproven",
            "authorization_response_issuer": "unproven",
            "scopes": (),
            "token_lifetime_seconds": None,
            "revocation": "unproven",
            "registration_modes": ("dcr",),
            "evidence_source": (
                "Auth0 plus Alpic DCR topology selected; tenant/environment and "
                "witnessed flow unproven"
            ),
            "evidence_digest": None,
            "supported": False,
            "blockers": (
                "OAUTH_PROVIDER_CAPABILITY_UNPROVEN",
                "ALPIC_DCR_ISSUER_SEMANTICS_UNPROVEN",
                "OAUTH_END_TO_END_FLOW_UNPROVEN",
            ),
            "reviewed_date": "2026-08-25",
        },
    )


def _sdk_tasks_public_api_available() -> bool:
    """Check the public types unique to the current SEP-2663 Tasks extension."""
    return all(
        hasattr(mcp_types, name)
        for name in (
            "CreateTaskResult",
            "GetTaskRequest",
            "CancelTaskRequest",
            "UpdateTaskRequest",
        )
    )


def probe_alpic_tasks_capability() -> UnsupportedAlpicTasksCapabilityVerdict:
    """Return the exact fail-closed Alpic Tasks verdict for the pinned SDK."""
    if _sdk_tasks_public_api_available():
        msg = "the pinned SDK Tasks surface changed; re-review the capability record"
        raise CapabilityContractError(msg)
    return _finalize(
        UnsupportedAlpicTasksCapabilityVerdict,
        {
            "schema_version": "1.0",
            "provider": "alpic",
            "extension_identifier": "io.modelcontextprotocol/tasks",
            "extension_revision_state": "draft",
            "mcp_version": importlib.metadata.version("mcp"),
            "mcp_types_version": importlib.metadata.version("mcp-types"),
            "installed_sdk_tree_sha256": _package_tree_sha256("mcp"),
            "sdk_server_support": "unsupported",
            "sdk_client_support": "unsupported",
            "provider_tasks_compute": "advertised",
            "provider_ordinary_timeout_seconds": 30,
            "provider_default_task_ttl_seconds": 21600,
            "source_evidence_digest": _ALPIC_TASKS_SOURCE_EVIDENCE_DIGEST,
            "provider_integration": "not_assessed",
            "task_creation_durability": "not_assessed",
            "restart_recovery": "not_assessed",
            "cancellation": "not_assessed",
            "isolation": "not_assessed",
            "retention": "not_assessed",
            "artifact_delivery": "not_assessed",
            "client_support": "not_assessed",
            "documentation_provenance": _ALPIC_TASKS_PROVENANCE,
            "supported": False,
            "blockers": _ALPIC_TASKS_BLOCKERS,
            "reviewed_date": _TASKS_REVIEWED_DATE,
        },
    )


def load_sdk_verdict(path: Path) -> SdkAuthorizationCapabilityVerdict:
    """Load and validate a canonical SDK capability contract."""
    return _load(path, SdkAuthorizationCapabilityVerdict)


def load_alpic_verdict(path: Path) -> AlpicOAuthDiscoveryCapabilityVerdict:
    """Load and validate a canonical Alpic capability contract."""
    return _load(path, AlpicOAuthDiscoveryCapabilityVerdict)


def load_provider_verdict(path: Path) -> OAuthProviderCapabilityVerdict:
    """Load and validate a canonical OAuth-provider capability contract."""
    return _load(path, OAuthProviderCapabilityVerdict)


def load_alpic_tasks_verdict(path: Path) -> AlpicTasksCapabilityVerdict:
    """Load and validate a canonical Alpic Tasks capability contract."""
    return _load_alpic_tasks_contract(path)


def load_alpic_tasks_source_evidence(path: Path) -> AlpicTasksSourceEvidence:
    """Load and validate canonical, digest-bound Alpic Tasks source metadata."""
    return _load(path, AlpicTasksSourceEvidence)
