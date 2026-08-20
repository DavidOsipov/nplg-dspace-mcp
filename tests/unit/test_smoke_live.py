# Copyright (c) 2026 David Osipov
"""Unit tests for the injected deployed-MCP smoke CLI."""

from __future__ import annotations

import io
import json
import runpy
import sys
from argparse import Namespace
from dataclasses import dataclass, field
from operator import attrgetter
from typing import TYPE_CHECKING, cast, override

import pytest

from scripts import smoke_live as smoke_live_module
from scripts.smoke_live import CliDependencies, SmokeClient, main
from scripts.verify_deploy import JsonObject, JsonValue, VerificationError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

ARGUMENT_ERROR_EXIT = 2
CANCELLED_EXIT = 130
AUTH_MARKER = "reviewed-auth-marker"
AMBIENT_MARKER = "reviewed-ambient-marker"
QUERY_MARKER = "reviewed-query-marker"
BODY_MARKER = "reviewed-body-marker"
OUTPUT_FAILURE = "output unavailable"
MAX_EXPECTED_OUTPUT_BYTES = 2_048
OVERSIZED_OUTPUT_CHARS = 200_000


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One call made through the smoke client seam."""

    name: str
    arguments: JsonObject


def _new_call_log() -> list[ToolCall]:
    return []


def _new_failure_map() -> dict[str, BaseException]:
    return {}


@dataclass(slots=True)
class ScriptedClient:
    """Return deterministic tool results without network access."""

    responses: dict[str, JsonObject]
    failures: dict[str, BaseException] = field(default_factory=_new_failure_map)
    calls: list[ToolCall] = field(default_factory=_new_call_log)

    def call_tool(self, name: str, arguments: JsonObject) -> JsonObject:
        """Record a tool call and return or raise its scripted outcome."""
        self.calls.append(ToolCall(name, arguments))
        failure = self.failures.get(name)
        if failure is not None:
            raise failure
        return self.responses[name]


def _new_factory_log() -> list[tuple[str, str | None, float, str | None]]:
    return []


@dataclass(slots=True)
class StaticClientFactory:
    """Return one fake and record the exact client deadline/configuration."""

    client: SmokeClient
    failure: VerificationError | None = None
    calls: list[tuple[str, str | None, float, str | None]] = field(
        default_factory=_new_factory_log
    )

    def __call__(
        self,
        *,
        base_url: str,
        bearer_token: str | None,
        timeout: float,
        api_key: str | None,
    ) -> SmokeClient:
        """Record arguments and return the configured client."""
        self.calls.append((base_url, bearer_token, timeout, api_key))
        if self.failure is not None:
            raise self.failure
        return self.client


class FailingWriter(io.StringIO):
    """Output sink that rejects every write."""

    @override
    def write(self, value: str) -> int:
        """Raise a deterministic output failure."""
        del value
        raise OSError(OUTPUT_FAILURE)


@dataclass(frozen=True, slots=True)
class StaticArgumentParser:
    """Return one controlled parser result for fail-closed boundary tests."""

    values: dict[str, object]

    def parse_args(self, _argv: Sequence[str]) -> Namespace:
        """Return the configured namespace without argparse coercion."""
        return Namespace(**self.values)


def _base_responses() -> dict[str, JsonObject]:
    return {
        "search_documents": {
            "items": [{"handle": "123/456"}],
            "total": 1,
        },
        "get_document_metadata": {
            "title": "Reviewed title",
            "metadata_source": "api",
            "restricted": False,
        },
        "list_document_files": {
            "files": [
                {
                    "access_status": "public",
                    "filename": "document.pdf",
                    "reported_format": "application/pdf",
                    "bitstream_id": "bitstream-1",
                }
            ]
        },
    }


def _all_feature_responses() -> dict[str, JsonObject]:
    responses = _base_responses()
    responses.update(
        {
            "download_document_file": {"artifact_id": "artifact-1"},
            "inspect_pdf": {
                "source_sha256": "a" * 64,
                "page_count": 2,
            },
            "render_pdf_pages": {
                "render_id": "rnd_0123456789abcdef0123456789abcdef",
                "pages": [
                    {
                        "page_number": 1,
                        "width": 100,
                        "height": 200,
                        "resolution_source": "native",
                        "conversion_path": "direct",
                        "resize_applied": False,
                    }
                ],
            },
            "render_pdf_page_tiles": {
                "tiles": [{"index": 0}],
                "tile_width": 100,
                "tile_height": 100,
                "overlap": 0,
            },
        }
    )
    return responses


def _conformance(_client: SmokeClient) -> JsonObject:
    return {"status": "pass"}


def _argument_values() -> dict[str, object]:
    return {
        "base_url": "https://mcp.example",
        "token": None,
        "api_key": None,
        "query": "ივერია",
        "scope_handle": None,
        "handle": None,
        "page_size": 5,
        "download": False,
        "render_page": None,
        "tiles": False,
        "timeout": 90.0,
    }


def _dependencies(
    client: SmokeClient,
    *,
    stdout: io.StringIO | None = None,
    stderr: io.StringIO | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[CliDependencies, StaticClientFactory, io.StringIO, io.StringIO]:
    output = stdout or io.StringIO()
    errors = stderr or io.StringIO()
    factory = StaticClientFactory(client)
    return (
        CliDependencies(
            environ={} if environ is None else environ,
            stdout=output,
            stderr=errors,
            client_factory=factory,
            verifier=_conformance,
        ),
        factory,
        output,
        errors,
    )


@pytest.mark.parametrize(
    ("extra_args", "message"),
    [
        pytest.param(
            ["--tiles"],
            "FAIL: --tiles requires --render-page\n",
            id="tiles-without-render",
        ),
        pytest.param(
            ["--render-page", "1"],
            "FAIL: --render-page requires --download\n",
            id="render-without-download",
        ),
    ],
)
def test_main_rejects_argument_relationships_before_client_creation(
    extra_args: list[str],
    message: str,
) -> None:
    client = ScriptedClient(_base_responses())
    dependencies, factory, _, stderr = _dependencies(client)

    assert (
        main(
            ["--base-url", "https://mcp.example", *extra_args],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []
    assert client.calls == []
    assert stderr.getvalue() == message


def test_main_returns_argparse_exit_without_constructing_client() -> None:
    client = ScriptedClient(_base_responses())
    dependencies, factory, stdout, stderr = _dependencies(client)

    assert main([], dependencies=dependencies) == ARGUMENT_ERROR_EXIT
    assert factory.calls == []
    assert stdout.getvalue() == ""
    assert "usage:" in stderr.getvalue()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("base_url", 1, id="required-value"),
        pytest.param("token", 1, id="optional-string"),
    ],
)
def test_main_fails_closed_if_argument_parser_returns_invalid_types(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    values = _argument_values()
    values[field] = value
    parser = StaticArgumentParser(values)
    client = ScriptedClient(_base_responses())
    dependencies, factory, stdout, stderr = _dependencies(client)

    def parser_factory(_environ: Mapping[str, str]) -> StaticArgumentParser:
        return parser

    monkeypatch.setattr("scripts.smoke_live._parser", parser_factory)

    assert main([], dependencies=dependencies) == ARGUMENT_ERROR_EXIT
    assert factory.calls == []
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: invalid smoke arguments\n"


@pytest.mark.parametrize(
    ("extra_args", "message"),
    [
        pytest.param(
            ["--page-size", "0"],
            "FAIL: --page-size must be between 1 and 50\n",
            id="zero-page-size",
        ),
        pytest.param(
            ["--page-size", "-1"],
            "FAIL: --page-size must be between 1 and 50\n",
            id="negative-page-size",
        ),
        pytest.param(
            ["--page-size", "51"],
            "FAIL: --page-size must be between 1 and 50\n",
            id="page-size-above-maximum",
        ),
        pytest.param(
            ["--download", "--render-page", "0"],
            "FAIL: --render-page must be at least 1\n",
            id="zero-render-page",
        ),
        pytest.param(
            ["--download", "--render-page", "-1"],
            "FAIL: --render-page must be at least 1\n",
            id="negative-render-page",
        ),
        pytest.param(
            ["--timeout", "nan"],
            "FAIL: --timeout must be a positive finite number\n",
            id="nan-timeout",
        ),
        pytest.param(
            ["--timeout", "inf"],
            "FAIL: --timeout must be a positive finite number\n",
            id="infinite-timeout",
        ),
        pytest.param(
            ["--timeout", "0"],
            "FAIL: --timeout must be a positive finite number\n",
            id="zero-timeout",
        ),
        pytest.param(
            ["--timeout", "-1"],
            "FAIL: --timeout must be a positive finite number\n",
            id="negative-timeout",
        ),
    ],
)
def test_main_rejects_out_of_policy_numbers_before_client_creation(
    extra_args: list[str],
    message: str,
) -> None:
    client = ScriptedClient(_base_responses())
    dependencies, factory, stdout, stderr = _dependencies(client)

    assert (
        main(
            ["--base-url", "https://mcp.example", *extra_args],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []
    assert client.calls == []
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == message


def test_main_preserves_high_positive_render_page_and_finite_timeout() -> None:
    client = ScriptedClient(_all_feature_responses())
    dependencies, factory, _, stderr = _dependencies(client)

    assert (
        main(
            [
                "--base-url",
                "https://mcp.example",
                "--download",
                "--render-page",
                "2001",
                "--timeout",
                "10000",
            ],
            dependencies=dependencies,
        )
        == 0
    )
    assert factory.calls == [("https://mcp.example", None, 10_000.0, None)]
    assert client.calls[-1].arguments["pages"] == [2001]
    assert stderr.getvalue() == ""


def test_main_passes_exact_deadline_and_bounds_success_requests_and_output() -> None:
    client = ScriptedClient(_base_responses())
    dependencies, factory, stdout, stderr = _dependencies(client)

    assert (
        main(
            [
                "--base-url",
                "https://mcp.example/gateway",
                "--query",
                "ივერია",
                "--timeout",
                "12.5",
            ],
            dependencies=dependencies,
        )
        == 0
    )
    assert factory.calls == [("https://mcp.example/gateway", None, 12.5, None)]
    assert [call.name for call in client.calls] == [
        "search_documents",
        "get_document_metadata",
        "list_document_files",
    ]
    assert client.calls[0].arguments == {"query": "ივერია", "page_size": 5}
    expected: JsonObject = {
        "status": "pass",
        "conformance": {"status": "pass"},
        "search": {"query": "ივერია", "total": 1, "returned": 1},
        "selected": {
            "handle": "123/456",
            "title": "Reviewed title",
            "metadata_source": "api",
            "restricted": False,
            "file_count": 1,
        },
    }
    expected_output = (
        json.dumps(expected, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    assert stdout.getvalue() == expected_output
    assert len(stdout.getvalue().encode()) < MAX_EXPECTED_OUTPUT_BYTES
    assert stderr.getvalue() == ""


def test_main_passes_scope_and_explicit_handle_without_using_search_selection() -> None:
    client = ScriptedClient(_base_responses())
    dependencies, _, _, stderr = _dependencies(client)

    assert (
        main(
            [
                "--base-url",
                "https://mcp.example",
                "--scope-handle",
                "123/100",
                "--handle",
                "123/999",
            ],
            dependencies=dependencies,
        )
        == 0
    )
    assert client.calls[0] == ToolCall(
        "search_documents",
        {"query": "ივერია", "page_size": 5, "scope_handle": "123/100"},
    )
    assert client.calls[1].arguments == {"handle": "123/999"}
    assert stderr.getvalue() == ""


@pytest.mark.parametrize(
    "items",
    [
        pytest.param([], id="empty"),
        pytest.param([{"handle": ""}], id="blank-handle"),
    ],
)
def test_main_rejects_search_results_without_a_usable_handle(
    items: list[JsonValue],
) -> None:
    responses = _base_responses()
    responses["search_documents"] = {"items": items, "total": len(items)}
    client = ScriptedClient(responses)
    dependencies, _, stdout, stderr = _dependencies(client)

    assert main(["--base-url", "https://mcp.example"], dependencies=dependencies) == 1
    assert [call.name for call in client.calls] == ["search_documents"]
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke request failed\n"


def test_main_rejects_non_object_search_entry() -> None:
    responses = _base_responses()
    responses["search_documents"] = {"items": [None], "total": 1}
    client = ScriptedClient(responses)
    dependencies, _, stdout, stderr = _dependencies(client)

    assert main(["--base-url", "https://mcp.example"], dependencies=dependencies) == 1
    assert [call.name for call in client.calls] == ["search_documents"]
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke request failed\n"


def test_main_bounds_the_complete_download_render_tile_sequence() -> None:
    client = ScriptedClient(_all_feature_responses())
    dependencies, _, stdout, stderr = _dependencies(client)

    assert (
        main(
            [
                "--base-url",
                "https://mcp.example",
                "--download",
                "--render-page",
                "1",
                "--tiles",
            ],
            dependencies=dependencies,
        )
        == 0
    )
    assert [call.name for call in client.calls] == [
        "search_documents",
        "get_document_metadata",
        "list_document_files",
        "download_document_file",
        "inspect_pdf",
        "render_pdf_pages",
        "render_pdf_page_tiles",
    ]
    assert client.calls[-1].arguments == {
        "render_id": "rnd_0123456789abcdef0123456789abcdef",
        "page_number": 1,
    }
    assert '"count": 1' in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_main_downloads_without_rendering_when_no_page_is_requested() -> None:
    client = ScriptedClient(_all_feature_responses())
    dependencies, _, stdout, stderr = _dependencies(client)

    assert (
        main(
            ["--base-url", "https://mcp.example", "--download"],
            dependencies=dependencies,
        )
        == 0
    )
    assert [call.name for call in client.calls] == [
        "search_documents",
        "get_document_metadata",
        "list_document_files",
        "download_document_file",
        "inspect_pdf",
    ]
    assert '"download"' in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_main_rejects_download_when_no_public_pdf_is_available() -> None:
    responses = _base_responses()
    responses["list_document_files"] = {
        "files": [
            {
                "access_status": "restricted",
                "filename": "restricted.pdf",
                "reported_format": "application/pdf",
            },
            {
                "access_status": "public",
                "filename": "notes.txt",
                "reported_format": "text/plain",
            },
        ]
    }
    client = ScriptedClient(responses)
    dependencies, _, stdout, stderr = _dependencies(client)

    assert (
        main(
            ["--base-url", "https://mcp.example", "--download"],
            dependencies=dependencies,
        )
        == 1
    )
    assert [call.name for call in client.calls] == [
        "search_documents",
        "get_document_metadata",
        "list_document_files",
    ]
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke request failed\n"


def test_main_rejects_public_pdf_without_bitstream_identifier() -> None:
    responses = _base_responses()
    responses["list_document_files"] = {
        "files": [
            {
                "access_status": "public",
                "filename": "document.pdf",
                "reported_format": "application/pdf",
            }
        ]
    }
    client = ScriptedClient(responses)
    dependencies, _, stdout, stderr = _dependencies(client)

    assert (
        main(
            ["--base-url", "https://mcp.example", "--download"],
            dependencies=dependencies,
        )
        == 1
    )
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke request failed\n"


def test_main_rejects_empty_render_page_list() -> None:
    responses = _all_feature_responses()
    responses["render_pdf_pages"] = {
        "render_id": "rnd_0123456789abcdef0123456789abcdef",
        "pages": [],
    }
    client = ScriptedClient(responses)
    dependencies, _, stdout, stderr = _dependencies(client)

    assert (
        main(
            [
                "--base-url",
                "https://mcp.example",
                "--download",
                "--render-page",
                "1",
            ],
            dependencies=dependencies,
        )
        == 1
    )
    assert client.calls[-1].name == "render_pdf_pages"
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke request failed\n"


@pytest.mark.parametrize(
    "failure_kind",
    ["timeout", "nonzero", "malformed", "oversized"],
)
def test_main_sanitizes_each_upstream_failure_and_stops_after_one_request(
    failure_kind: str,
) -> None:
    responses = _base_responses()
    failures: dict[str, BaseException] = {}
    if failure_kind == "malformed":
        responses["search_documents"] = {"items": "not-a-list"}
    else:
        detail = f"{failure_kind}: {BODY_MARKER}"
        failures["search_documents"] = VerificationError(detail)
    client = ScriptedClient(responses, failures)
    dependencies, _, stdout, stderr = _dependencies(client)

    assert main(["--base-url", "https://mcp.example"], dependencies=dependencies) == 1
    assert len(client.calls) == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke request failed\n"
    assert BODY_MARKER not in stderr.getvalue()


def test_main_redacts_credentials_response_body_and_query() -> None:
    detail = f"{AUTH_MARKER} {AMBIENT_MARKER} {QUERY_MARKER} {BODY_MARKER}"
    client = ScriptedClient(
        _base_responses(),
        {"search_documents": VerificationError(detail)},
    )
    dependencies, factory, _, stderr = _dependencies(
        client,
        environ={
            "API_BEARER_TOKEN": AUTH_MARKER,
            "API_KEY": AMBIENT_MARKER,
        },
    )

    assert (
        main(
            [
                "--base-url",
                "https://mcp.example",
                "--query",
                QUERY_MARKER,
            ],
            dependencies=dependencies,
        )
        == 1
    )
    assert factory.calls == [("https://mcp.example", AUTH_MARKER, 90.0, AMBIENT_MARKER)]
    assert stderr.getvalue() == "FAIL: live smoke request failed\n"
    for marker in (AUTH_MARKER, AMBIENT_MARKER, QUERY_MARKER, BODY_MARKER):
        assert marker not in stderr.getvalue()


@pytest.mark.parametrize(
    "credential_arguments",
    [
        ["--token", AUTH_MARKER],
        [f"--token={AUTH_MARKER}"],
        ["--api-key", AMBIENT_MARKER],
        [f"--api-key={AMBIENT_MARKER}"],
    ],
)
def test_main_rejects_credential_argv_without_echoing_values(
    credential_arguments: list[str],
) -> None:
    client = ScriptedClient(_base_responses())
    dependencies, factory, stdout, stderr = _dependencies(client)

    assert (
        main(
            ["--base-url", "https://mcp.example", *credential_arguments],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "FAIL: credentials must be supplied through environment variables\n"
    )
    assert AUTH_MARKER not in stderr.getvalue()
    assert AMBIENT_MARKER not in stderr.getvalue()


def test_main_rejects_oversized_canonical_output_without_partial_write() -> None:
    responses = _base_responses()
    responses["get_document_metadata"] = {
        "title": BODY_MARKER + ("x" * OVERSIZED_OUTPUT_CHARS),
        "metadata_source": "api",
        "restricted": False,
    }
    client = ScriptedClient(responses)
    dependencies, _, stdout, stderr = _dependencies(client)

    assert main(["--base-url", "https://mcp.example"], dependencies=dependencies) == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke output exceeded the size limit\n"
    assert BODY_MARKER not in stderr.getvalue()


def test_main_rejects_nonfinite_json_output_without_partial_write() -> None:
    responses = _base_responses()
    responses["get_document_metadata"] = {
        "title": float("nan"),
        "metadata_source": "api",
        "restricted": False,
    }
    client = ScriptedClient(responses)
    dependencies, _, stdout, stderr = _dependencies(client)

    assert main(["--base-url", "https://mcp.example"], dependencies=dependencies) == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke returned invalid JSON\n"


def test_main_sanitizes_client_construction_failure() -> None:
    client = ScriptedClient(_base_responses())
    dependencies, factory, stdout, stderr = _dependencies(client)
    factory.failure = VerificationError(f"deadline: {BODY_MARKER}")

    assert main(["--base-url", "https://mcp.example"], dependencies=dependencies) == 1
    assert client.calls == []
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke request failed\n"
    assert BODY_MARKER not in stderr.getvalue()


def test_main_maps_cancellation_to_exit_130() -> None:
    client = ScriptedClient(
        _base_responses(),
        {"search_documents": KeyboardInterrupt()},
    )
    dependencies, _, stdout, stderr = _dependencies(client)

    assert (
        main(["--base-url", "https://mcp.example"], dependencies=dependencies)
        == CANCELLED_EXIT
    )
    assert len(client.calls) == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "FAIL: live smoke cancelled\n"


def test_main_reports_output_failure() -> None:
    client = ScriptedClient(_base_responses())
    stderr = io.StringIO()
    dependencies, _, _, _ = _dependencies(
        client,
        stdout=FailingWriter(),
        stderr=stderr,
    )

    assert main(["--base-url", "https://mcp.example"], dependencies=dependencies) == 1
    assert stderr.getvalue() == "FAIL: output write failed\n"


def test_main_preserves_exit_code_if_failure_output_is_unavailable() -> None:
    client = ScriptedClient(_base_responses())
    dependencies, factory, stdout, _ = _dependencies(
        client,
        stderr=FailingWriter(),
    )

    assert (
        main(
            ["--base-url", "https://mcp.example", "--tiles"],
            dependencies=dependencies,
        )
        == ARGUMENT_ERROR_EXIT
    )
    assert factory.calls == []
    assert stdout.getvalue() == ""


def test_default_dependencies_bind_client_and_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ScriptedClient(_base_responses())
    factory_calls: list[tuple[str, str | None, float, str | None]] = []

    def client_factory(
        *,
        base_url: str,
        bearer_token: str | None,
        timeout: float,
        api_key: str | None,
    ) -> SmokeClient:
        factory_calls.append((base_url, bearer_token, timeout, api_key))
        return client

    def verifier(candidate: object) -> JsonObject:
        assert candidate is client
        return {"status": "pass"}

    monkeypatch.setattr(smoke_live_module, "McpClient", client_factory)
    monkeypatch.setattr(smoke_live_module, "verify", verifier)
    default_dependencies = cast(
        "Callable[[], CliDependencies]",
        attrgetter("_default_dependencies")(smoke_live_module),
    )
    dependencies = default_dependencies()

    assert (
        dependencies.client_factory(
            base_url="https://mcp.example",
            bearer_token=AUTH_MARKER,
            timeout=12.5,
            api_key=AMBIENT_MARKER,
        )
        is client
    )
    assert dependencies.verifier(client) == {"status": "pass"}
    assert factory_calls == [("https://mcp.example", AUTH_MARKER, 12.5, AMBIENT_MARKER)]


def test_process_entrypoint_uses_default_dependencies_for_help(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["scripts/smoke_live.py", "--help"])
    monkeypatch.setattr(sys, "path", ["scripts", *sys.path])

    with pytest.raises(SystemExit) as captured:
        _ = cast(
            "object",
            runpy.run_path("scripts/smoke_live.py", run_name="__main__"),
        )

    process_output = capsys.readouterr()
    assert captured.value.code == 0
    assert "usage:" in process_output.out
    assert process_output.err == ""
