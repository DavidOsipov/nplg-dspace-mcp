# Copyright (c) 2026 David Osipov
"""Static deployment-policy tests."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path
from stat import S_IMODE
from typing import TYPE_CHECKING, cast

import pytest
import yaml

from nplg_mcp.json_types import (
    JsonObject,
    JsonValue,
    load_json_value,
    require_json_object,
)
from scripts.verify_deploy import ALPIC_METADATA_TOOLS

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).parents[2]
OPERATOR_SCRIPT_MODE = 0o755
PRIVATE_SECRET_MODE = 0o400
MAX_CONTAINER_PIDS = 256
PDF_WORKER_PIDS = 8
SCANNER_PIDS = 16
DEPENDABOT_POLICY_VERSION = 2
MIN_DEPENDABOT_COOLDOWN_DAYS = 7
EXPECTED_DOCKER_BASE = (
    "FROM python:3.13.14-slim-trixie@sha256:"
    "6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91"
)
EXPECTED_CADDY_IMAGE = (
    "caddy:2.11.4-alpine@sha256:"
    "5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
)
EXPECTED_CLAMAV_IMAGE = (
    "clamav/clamav:1.4.6@sha256:"
    "c3bfbf2a2c9abc1fc179e63832a9e8bfac901ede83853e3fa10acf6f1fb5c803"
)
EXPECTED_ALPIC_INSTALL_COMMAND = (
    "uv venv --python python3 .venv && uv pip install --python .venv/bin/python "
    "--require-hashes --no-deps --only-binary=:all: -r requirements.lock"
)

load_yaml_object = cast("Callable[[str], object]", yaml.safe_load)
load_toml_object = cast("Callable[[str], object]", tomllib.loads)


def _read_json_object(path: Path) -> JsonObject:
    return require_json_object(
        load_json_value(path.read_text(encoding="utf-8")),
        context=str(path.relative_to(ROOT)),
    )


def _read_toml_object(path: Path) -> JsonObject:
    return require_json_object(
        load_toml_object(path.read_text(encoding="utf-8")),
        context=str(path.relative_to(ROOT)),
    )


def _read_yaml_object(path: Path) -> JsonObject:
    return require_json_object(
        load_yaml_object(path.read_text(encoding="utf-8")),
        context=str(path.relative_to(ROOT)),
    )


def _object_field(parent: JsonObject, key: str, *, context: str) -> JsonObject:
    return require_json_object(parent[key], context=f"{context}.{key}")


def _string_array(value: JsonValue, *, context: str) -> list[str]:
    if not isinstance(value, list):
        message = f"{context} must be an array"
        raise TypeError(message)
    items = cast("list[object]", value)
    if not all(type(item) is str for item in items):
        message = f"{context} must contain only strings"
        raise TypeError(message)
    return cast("list[str]", items)


def test_obsolete_typescript_scaffold_is_removed() -> None:
    for relative in (
        "tsconfig.json",
        "src/app/config.ts",
        "src/domain/errors.ts",
        "src/domain/types.ts",
        "test/unit/config.test.ts",
    ):
        assert not (ROOT / relative).exists(), relative
    package = _read_json_object(ROOT / "package.json")
    assert package["private"] is True
    assert package["packageManager"] == "npm@11.18.0"
    assert package["devDependencies"] == {
        "@eslint/js": "10.0.1",
        "@modelcontextprotocol/conformance": "0.2.0-alpha.11",
        "@types/node": "24.13.3",
        "eslint": "10.8.1",
        "markdownlint-cli2": "0.23.2",
        "pyright": "1.1.413",
        "typescript": "6.0.3",
        "typescript-eslint": "8.67.0",
        "zod": "4.4.3",
    }


def test_environment_example_matches_strict_runtime_configuration() -> None:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    for line in (
        "NPLG_BASE_URL=https://dspace.nplg.gov.ge/",
        "HOST=0.0.0.0",
        "PORT=8000",
        "ALLOW_ANONYMOUS=false",
        "DEPLOYMENT_PROFILE=alpic-metadata",
        'API_PRINCIPALS_JSON=[{"principal_id":"primary","bearer_token":',
        "UPSTREAM_RATE_PER_SECOND=1.0",
        "MAX_REQUEST_BODY_BYTES=1048576",
        "REQUEST_BODY_TIMEOUT_SECONDS=10",
        "PDF_EXECUTOR=serialized",
        "PRIVATE_EDGE_TLS=false",
        "MAX_CONCURRENT_PDF_JOBS=1",
        "MAX_CONCURRENT_MCP_REQUESTS=16",
        "MAX_CONCURRENT_MCP_REQUESTS_PER_PRINCIPAL=4",
        "MAX_CONCURRENT_ASSET_STREAMS=8",
        "ASSET_STREAM_IDLE_TIMEOUT_SECONDS=10",
        "ASSET_STREAM_TOTAL_TIMEOUT_SECONDS=120",
        "MAX_CONCURRENT_HTTP_REQUESTS=128",
        "CACHE_MAX_BYTES=21474836480",
        "TILE_WIDTH=2048",
        "TILE_HEIGHT=2048",
        "TILE_OVERLAP=128",
    ):
        assert line in text
    assert "OPTIONAL_BEARER_TOKEN" not in text
    assert "SANDBOX_MODE" not in text


def test_dockerfile_is_pinned_non_root_and_health_checked() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert text.startswith(EXPECTED_DOCKER_BASE)
    assert "requirements.lock" in text
    assert "--no-deps" in text
    assert "--require-hashes" in text
    assert "useradd" in text
    assert "USER 10001:10001" in text
    assert "HEALTHCHECK" in text
    assert 'CMD ["python", "-m", "nplg_mcp"]' in text
    assert "chmod -R a=rX /app/src /app/scripts" in text
    assert "ASSET_SIGNING_SECRET=" not in text
    assert "API_BEARER_TOKEN=" not in text


def test_pdf_worker_uses_only_the_reviewed_dedicated_filesystem_slot() -> None:
    """Catch a Compose change that reconnects the parser to the shared cache."""
    compose = _read_yaml_object(ROOT / "compose.yaml")
    services = _object_field(compose, "services", context="compose.yaml")
    app = _object_field(services, "app", context="compose.yaml.services")
    worker = _object_field(services, "pdf-worker", context="compose.yaml.services")
    initializer = _object_field(
        services,
        "pdf-worker-init",
        context="compose.yaml.services",
    )
    expected_mount = "nplg_pdf_worker_slot:/var/lib/nplg/pdf-worker-slot"

    assert expected_mount in _string_array(
        app["volumes"],
        context="compose.services.app.volumes",
    )
    assert _string_array(
        worker["volumes"],
        context="compose.services.pdf-worker.volumes",
    ) == [expected_mount, "nplg_pdf_socket:/run/nplg-pdf-worker"]
    assert expected_mount in _string_array(
        initializer["volumes"],
        context="compose.services.pdf-worker-init.volumes",
    )
    environment = worker["environment"]
    assert isinstance(environment, dict)
    assert environment["NPLG_PDF_WORK_ROOT"] == "/var/lib/nplg/pdf-worker-slot"


def test_pdf_worker_has_no_network_and_only_private_job_mounts() -> None:
    """Keep hostile PDF parsing outside the app network and authoritative cache."""
    compose = _read_yaml_object(ROOT / "compose.yaml")
    services = _object_field(compose, "services", context="compose.yaml")
    app = _object_field(services, "app", context="compose.yaml.services")
    worker = _object_field(services, "pdf-worker", context="compose.yaml.services")

    assert worker["network_mode"] == "none"
    assert worker["read_only"] is True
    assert worker["cap_drop"] == ["ALL"]
    assert worker["security_opt"] == [
        "no-new-privileges:true",
        "seccomp=./deploy/pdf-worker-seccomp.json",
    ]
    seccomp = _read_json_object(ROOT / "deploy" / "pdf-worker-seccomp.json")
    assert seccomp["defaultAction"] == "SCMP_ACT_ALLOW"
    rules = seccomp["syscalls"]
    assert isinstance(rules, list)
    assert rules == [
        {
            "names": ["socket", "socketpair"],
            "action": "SCMP_ACT_ERRNO",
            "args": [
                {
                    "index": 0,
                    "value": 1,
                    "valueTwo": 0,
                    "op": "SCMP_CMP_NE",
                }
            ],
        }
    ]
    assert worker["pids_limit"] == PDF_WORKER_PIDS
    assert worker["mem_limit"] == "1g"
    assert worker["cpus"] == 1.0
    assert "env_file" not in worker
    assert "nplg_cache:/data/cache" not in _string_array(
        worker["volumes"],
        context="compose.yaml.services.pdf-worker.volumes",
    )
    assert (
        _string_array(
            app["volumes"],
            context="compose.yaml.services.app.volumes",
        ).count("nplg_pdf_worker_slot:/var/lib/nplg/pdf-worker-slot")
        == 1
    )
    assert _string_array(
        worker["volumes"],
        context="compose.yaml.services.pdf-worker.volumes",
    ) == [
        "nplg_pdf_worker_slot:/var/lib/nplg/pdf-worker-slot",
        "nplg_pdf_socket:/run/nplg-pdf-worker",
    ]


def test_scanner_is_no_network_and_exposes_only_a_private_unix_socket() -> None:
    """Scanning stays outside both the application and PDF-worker networks."""
    compose = _read_yaml_object(ROOT / "compose.yaml")
    services = _object_field(compose, "services", context="compose.yaml")
    app = _object_field(services, "app", context="compose.yaml.services")
    scanner = _object_field(services, "scanner", context="compose.yaml.services")

    assert scanner["image"] == EXPECTED_CLAMAV_IMAGE
    assert scanner["network_mode"] == "none"
    assert scanner["read_only"] is True
    assert scanner["cap_drop"] == ["ALL"]
    assert scanner["security_opt"] == ["no-new-privileges:true"]
    assert scanner["pids_limit"] == SCANNER_PIDS
    assert "env_file" not in scanner
    assert "ports" not in scanner
    assert _string_array(
        scanner["volumes"],
        context="compose.yaml.services.scanner.volumes",
    ) == [
        "nplg_scanner_db:/var/lib/clamav:ro",
        "nplg_scanner_socket:/run/nplg-scanner",
        "./deploy/clamd.conf:/etc/clamav/clamd.conf:ro",
    ]
    assert "nplg_scanner_socket:/run/nplg-scanner:ro" in _string_array(
        app["volumes"],
        context="compose.yaml.services.app.volumes",
    )


def test_official_conformance_fixture_is_not_in_production_artifacts() -> None:
    """Keep the auth-disabled harness fixture outside every release surface."""
    fixture_module = "tests.conformance.official_fixture_server"
    diagnostic_tools = {
        "test_logging_tool",
        "test_missing_capability",
        "test_streaming_elicitation",
    }

    project = _read_toml_object(ROOT / "pyproject.toml")
    tool = _object_field(project, "tool", context="pyproject.toml")
    setuptools = _object_field(tool, "setuptools", context="pyproject.toml.tool")
    packages = _object_field(
        setuptools,
        "packages",
        context="pyproject.toml.tool.setuptools",
    )
    find = _object_field(
        packages,
        "find",
        context="pyproject.toml.tool.setuptools.packages",
    )
    assert _string_array(
        find["where"],
        context="pyproject.toml.tool.setuptools.packages.find.where",
    ) == ["src"]

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "tests" in dockerignore
    assert "COPY tests" not in dockerfile
    assert "official_fixture_server" not in dockerfile

    alpic = _read_json_object(ROOT / "alpic.json")
    for command in ("installCommand", "buildCommand", "startCommand"):
        value = alpic[command]
        assert isinstance(value, str)
        assert "tests" not in value
        assert "official_fixture_server" not in value

    production_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src").rglob("*.py"))
    )
    assert fixture_module not in production_text
    assert diagnostic_tools.isdisjoint(ALPIC_METADATA_TOOLS)


def test_runtime_lock_is_complete_and_exactly_pinned() -> None:
    lock_text = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    lines = {
        line.strip().removesuffix(" \\")
        for line in lock_text.splitlines()
        if line and not line[0].isspace() and "==" in line
    }
    expected = {
        "annotated-doc==0.0.4",
        "annotated-types==0.7.0",
        "anyio==4.13.0",
        "beautifulsoup4==4.14.3",
        "certifi==2026.5.20",
        "click==8.3.3",
        "colorama==0.4.6 ; sys_platform == 'win32'",
        "cryptography==50.0.0",
        "defusedxml==0.7.1",
        "fastapi==0.133.0",
        "h11==0.16.0",
        "httpcore==1.0.9",
        "httpcore2==2.9.0",
        "httpx==0.28.1",
        "httpx2==2.9.0",
        "idna==3.18",
        "jsonschema==4.26.0",
        "lxml==6.1.1",
        "mcp==2.0.0",
        "mcp-types==2.0.0",
        "opentelemetry-api==1.44.0",
        "pillow==12.3.0",
        "prometheus-client==0.25.0",
        "pydantic==2.13.4",
        "pydantic-core==2.46.4",
        "pypdfium2==5.8.0",
        "pyjwt[crypto]==2.13.0",
        "python-multipart==0.0.32",
        "pywin32==311 ; sys_platform == 'win32'",
        "soupsieve==2.8.4",
        "sse-starlette==3.4.8",
        "starlette==1.3.1",
        "truststore==0.10.4",
        "typing-extensions==4.16.0",
        "typing-inspection==0.4.2",
        "uvicorn==0.48.0",
    }
    input_lines = {
        line.strip()
        for line in (ROOT / "requirements.in").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    expected_lock = (expected - {"pyjwt[crypto]==2.13.0"}) | {
        "attrs==26.1.0",
        "cffi==2.1.1 ; platform_python_implementation != 'PyPy'",
        "jsonschema-specifications==2025.9.1",
        (
            "pycparser==3.0 ; implementation_name != 'PyPy' and "
            "platform_python_implementation != 'PyPy'"
        ),
        "pyjwt==2.13.0",
        "referencing==0.37.0",
        "rpds-py==2026.6.3",
    }
    assert input_lines == expected
    assert lines == expected_lock
    blocks = lock_text.splitlines()
    requirement_indexes = [
        index
        for index, line in enumerate(blocks)
        if line and not line[0].isspace() and "==" in line
    ]
    for position, start in enumerate(requirement_indexes):
        end = (
            requirement_indexes[position + 1]
            if position + 1 < len(requirement_indexes)
            else len(blocks)
        )
        assert any("--hash=sha256:" in line for line in blocks[start:end])


def test_compose_has_reverse_proxy_persistent_cache_and_container_hardening() -> None:
    data = _read_yaml_object(ROOT / "compose.yaml")
    services = _object_field(data, "services", context="compose")
    app = _object_field(services, "app", context="compose.services")
    caddy = _object_field(services, "caddy", context="compose.services")
    assert "ports" not in app
    assert app["expose"] == ["8443"]
    assert app["read_only"] is True
    assert app["cap_drop"] == ["ALL"]
    security_options = _string_array(
        app["security_opt"], context="compose.services.app.security_opt"
    )
    assert "no-new-privileges:true" in security_options
    pids_limit = app["pids_limit"]
    assert type(pids_limit) is int
    assert pids_limit <= MAX_CONTAINER_PIDS
    assert app["restart"] == "unless-stopped"
    app_volumes = _string_array(app["volumes"], context="compose.services.app.volumes")
    assert any("nplg_cache:/data/cache" in volume for volume in app_volumes)
    assert app["healthcheck"] == {"disable": True}
    app_secret_values = app["secrets"]
    assert isinstance(app_secret_values, list)
    app_secrets = [
        require_json_object(item, context="compose.services.app.secrets")
        for item in app_secret_values
    ]
    expected_secret_targets = {
        "app_server_cert",
        "app_server_key",
        "app_server_ca",
        "caddy_client_ca",
    }
    secret_targets = [secret["target"] for secret in app_secrets]
    assert all(type(target) is str for target in secret_targets)
    assert set(secret_targets) == expected_secret_targets
    assert len(secret_targets) == len(set(secret_targets))
    for secret in app_secrets:
        target = secret["target"]
        assert type(target) is str
        assert secret["source"] == target
        assert secret["uid"] == "10001"
        assert secret["gid"] == "10001"
        assert secret["mode"] == PRIVATE_SECRET_MODE
    assert caddy["image"] == EXPECTED_CADDY_IMAGE
    depends_on = _object_field(caddy, "depends_on", context="compose.services.caddy")
    app_dependency = _object_field(
        depends_on, "app", context="compose.services.caddy.depends_on"
    )
    assert app_dependency["condition"] == "service_started"
    caddy_ports = _string_array(caddy["ports"], context="compose.services.caddy.ports")
    assert set(caddy_ports) == {"80:80", "443:443"}
    volumes = _object_field(data, "volumes", context="compose")
    assert set(volumes) >= {"nplg_cache", "caddy_data", "caddy_config"}


def test_caddy_and_guide_cover_operations_and_residual_egress_risk() -> None:
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8").lower()
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8").lower()
    assert "reverse_proxy https://app.internal:8443" in caddy
    assert "reverse_proxy app:8000" not in caddy
    directive = "tls_client_auth"
    client_certificate = "/run/secrets/caddy_client_cert"
    client_key = "/run/secrets/caddy_client_key"
    client_auth = f"{directive} {client_certificate} {client_key}"
    assert client_auth in caddy
    assert "tls_trust_pool file /run/secrets/app_server_ca" in caddy
    assert "tls_server_name app.internal" in caddy
    assert "tls_insecure_skip_verify" not in caddy
    assert "max_size 1mb" in caddy
    assert "strict-transport-security" in caddy
    assert "@private_metrics path /metrics" in caddy
    assert "respond @private_metrics 404" in caddy
    assert "@private_probes path /healthz /readyz" in caddy
    assert "respond @private_probes 404" in caddy
    assert "\n    log {" not in caddy
    for phrase in (
        "docker compose config",
        "verify_deploy.py",
        "smoke_live.py",
        "backup",
        "egress",
        "docker may bypass ufw",
        "dspace.nplg.gov.ge",
        "residual risk",
        "signed asset tokens",
        "access logs are disabled",
        "metrics are not exposed through caddy",
        "alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce",
        "--network none",
        "--read-only",
        "--cap-drop all",
        "--security-opt no-new-privileges",
        "--user 10001:10001",
        "sha256sum",
        "private-full candidate",
        "app_server_cert",
        "caddy_client_cert",
        "controller-authoritative",
        "no plaintext",
        "application health check",
        "scanner-updater",
    ):
        assert phrase in guide


def test_operator_scripts_parse_as_python() -> None:
    for relative in (
        "scripts/verify_deploy.py",
        "scripts/smoke_live.py",
        "scripts/delete_render.py",
    ):
        _ = ast.parse((ROOT / relative).read_text(encoding="utf-8"), filename=relative)


@pytest.mark.parametrize(
    "relative",
    [
        "scripts/verify_deploy.py",
        "scripts/smoke_live.py",
        "scripts/delete_render.py",
    ],
)
def test_operator_scripts_are_executable(relative: str) -> None:
    assert S_IMODE((ROOT / relative).stat().st_mode) == OPERATOR_SCRIPT_MODE


def test_operator_render_cleanup_script_is_available_inside_the_app_image() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY scripts/delete_render.py ./scripts/delete_render.py" in dockerfile


def test_operator_render_cleanup_requires_the_app_to_be_stopped() -> None:
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8")
    assert "docker compose exec -T app python scripts/delete_render.py" not in guide
    assert (
        "docker compose run --rm --no-deps app python scripts/delete_render.py" in guide
    )


def test_public_tool_verifier_expects_a_read_only_catalog() -> None:
    text = (ROOT / "scripts" / "verify_deploy.py").read_text(encoding="utf-8")
    assert '"delete_render"' not in text
    assert "EXPECTED_TOOLS" in text


def test_public_edge_and_verifier_share_the_metadata_profile_boundary() -> None:
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8")

    assert {
        "get_document_metadata",
        "list_document_files",
        "search_documents",
    } == ALPIC_METADATA_TOOLS
    assert "respond @private_probes 404" in caddy
    assert "--probe-base-url" in guide
    assert "does not query the public probe paths" in guide


def test_operator_guide_covers_chatgpt_and_openai_auth_boundaries() -> None:
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8").lower()
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    for phrase in (
        "chatgpt developer mode",
        "scan tools",
        "chatgpt pro",
        "read/fetch",
        "responses api",
        "authorization: bearer",
        "oauth gateway",
        "do not set `allow_anonymous=true`",
    ):
        assert phrase in guide
    assert "`delete_render`" not in readme
    assert "scripts/delete_render.py" in guide


def test_docker_context_includes_operator_cleanup_script() -> None:
    patterns = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert "scripts" not in patterns
    assert "scripts/" not in patterns
    assert "!scripts/delete_render.py" in patterns


def test_local_recovery_and_agent_state_are_excluded_from_git_and_images() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    for pattern in (".tmp/", ".serena/", "lancedb/", ".venv/", "backups/"):
        assert pattern in gitignore
        assert pattern in dockerignore
    assert "*.egg-info/" in gitignore
    assert "*.egg-info/" in dockerignore
    assert "**/*.egg-info/" in dockerignore
    assert "**/__pycache__/" in dockerignore
    assert "**/*.py[cod]" in dockerignore
    assert ".env.*" in dockerignore


def test_pdf_runtime_and_test_fixtures_use_only_permissive_dependencies() -> None:
    pyproject = _read_toml_object(ROOT / "pyproject.toml")
    project = _object_field(pyproject, "project", context="pyproject")
    optional_dependencies = _object_field(
        project, "optional-dependencies", context="pyproject.project"
    )
    runtime = set(
        _string_array(project["dependencies"], context="project.dependencies")
    )
    test_dependencies = set(
        _string_array(
            optional_dependencies["test"],
            context="project.optional-dependencies.test",
        )
    )
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    source = (ROOT / "src" / "nplg_mcp" / "pdf.py").read_text(encoding="utf-8")
    fixtures = (ROOT / "tests" / "helpers" / "pdf_factory.py").read_text(
        encoding="utf-8"
    )

    assert "pypdfium2==5.8.0" in runtime
    assert "PyMuPDF==1.26.7" not in runtime
    assert "PyMuPDF==1.26.7" not in test_dependencies
    assert "reportlab==4.4.9" in test_dependencies
    assert "pypdf==6.16.1" in test_dependencies
    assert "pypdfium2==5.8.0" in lock
    assert "PyMuPDF==1.26.7" not in lock
    assert "import pypdfium2" in source
    assert "import pymupdf" not in source
    assert "pymupdf" not in fixtures.lower()


def test_distribution_includes_pdfium_notices_and_connected_image_scan_gate() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    notice = (
        (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        if (ROOT / "THIRD_PARTY_NOTICES.md").exists()
        else ""
    )
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8").lower()

    assert (
        "COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md ./" in dockerfile
    )
    assert "pypdfium2" in notice
    assert "apache-2.0" in notice.lower()
    assert "bsd-3-clause" in notice.lower()
    assert "pymupdf/mupdf is not" in notice.lower()
    assert "reportlab" in notice.lower()
    assert "pypdf" in notice.lower()
    assert "trivy image" in guide
    assert "high,critical" in guide
    assert "unfixed" in guide
    assert "cve triage" in guide


def test_dependabot_covers_each_reviewed_dependency_ecosystem_weekly() -> None:
    path = ROOT / ".github" / "dependabot.yml"
    assert path.is_file(), "Dependabot policy is absent"
    policy = _read_yaml_object(path)
    assert policy["version"] == DEPENDABOT_POLICY_VERSION
    raw_updates = policy["updates"]
    assert isinstance(raw_updates, list)
    updates = tuple(
        require_json_object(update, context="dependabot update")
        for update in cast("list[object]", raw_updates)
    )
    ecosystems: set[str] = set()
    for update in updates:
        ecosystem = update["package-ecosystem"]
        assert type(ecosystem) is str
        ecosystems.add(ecosystem)
    assert ecosystems == {
        "pip",
        "npm",
        "github-actions",
    }
    for update in updates:
        assert update["directory"] == "/"
        schedule = require_json_object(update["schedule"], context="schedule")
        assert schedule["interval"] == "weekly"
        cooldown = require_json_object(update["cooldown"], context="cooldown")
        default_days = cooldown["default-days"]
        assert type(default_days) is int
        assert default_days >= MIN_DEPENDABOT_COOLDOWN_DAYS


def test_security_policy_has_private_reporting_and_closed_response_windows() -> None:
    path = ROOT / "SECURITY.md"
    assert path.is_file(), "SECURITY.md is absent"
    policy = path.read_text(encoding="utf-8").lower()
    for phrase in (
        "supported versions",
        "security/advisories/new",
        "do not open a public issue",
        "known exploited",
        "critical",
        "24 hours",
        "7 days",
        "high",
        "3 days",
        "30 days",
        "medium",
        "14 days",
        "90 days",
        "low",
        "180 days",
        "unknown severity",
        "release blocker",
        "dependabot",
        "discovery",
        "not evidence",
    ):
        assert phrase in policy


def test_operator_guide_requires_offline_digest_scans_and_external_receipts() -> None:
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8").lower()
    for phrase in (
        "immutable image digest",
        "offline scan",
        "externally acquired",
        "independently signed receipt",
        "24 hours",
        "do_not_release",
        "--skip-db-update",
        "--offline-scan",
    ):
        assert phrase in guide
    for forbidden in (
        "## connected image scan",
        "--ignore-unfixed",
        'app_image="$(docker compose images -q app)"',
        'caddy_image="$(docker compose images -q caddy)"',
    ):
        assert forbidden not in guide


def test_distribution_uses_non_deprecated_spdx_license_metadata() -> None:
    pyproject = _read_toml_object(ROOT / "pyproject.toml")
    build_system = _object_field(pyproject, "build-system", context="pyproject")
    project = _object_field(pyproject, "project", context="pyproject")
    assert build_system["requires"] == [
        "setuptools==84.0.0",
        "wheel==0.48.0",
    ]
    assert project["license"] == "MIT"


def test_wheel_metadata_includes_third_party_notices() -> None:
    pyproject = _read_toml_object(ROOT / "pyproject.toml")
    project = _object_field(pyproject, "project", context="pyproject")
    assert project["license-files"] == [
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
    ]


def test_alpic_declares_python_runtime_and_explicit_uv_commands() -> None:
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.13"
    data = _read_json_object(ROOT / "alpic.json")
    assert data == {
        "$schema": "https://assets.alpic.ai/alpic.json",
        "installCommand": EXPECTED_ALPIC_INSTALL_COMMAND,
        "buildCommand": ".venv/bin/python -m compileall -q src scripts",
        "startCommand": "HOST=0.0.0.0 PYTHONPATH=src .venv/bin/python -m nplg_mcp",
    }


def test_alpic_operator_guide_states_platform_limits_without_overclaiming() -> None:
    guide = (ROOT / "deploy" / "ALPIC.md").read_text(encoding="utf-8").lower()
    for phrase in (
        "python 3.13",
        "streamable http",
        "30-second",
        "dynamic `/assets/`",
        "serverless",
        "not a supported full-fidelity deployment target",
        "allow_anonymous=false",
        "x-api-key",
    ):
        assert phrase in guide
    assert "read -rsp" in guide
    assert "export api_key='<" not in guide


def test_readme_routes_alpic_users_to_the_limited_profile() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "deploy/ALPIC.md" in readme
    assert "Alpic" in readme


def test_compose_validation_examples_do_not_print_rendered_secrets() -> None:
    for relative in ("README.md", "deploy/README.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "docker compose --env-file .env config --quiet" in text
        assert "docker compose --env-file .env config\n" not in text
