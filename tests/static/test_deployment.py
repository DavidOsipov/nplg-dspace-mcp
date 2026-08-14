from __future__ import annotations

import ast
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def test_obsolete_typescript_scaffold_is_removed() -> None:
    for relative in (
        "package.json",
        "tsconfig.json",
        "src/app/config.ts",
        "src/domain/errors.ts",
        "src/domain/types.ts",
        "test/unit/config.test.ts",
    ):
        assert not (ROOT / relative).exists(), relative


def test_environment_example_matches_strict_runtime_configuration() -> None:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    for line in (
        "NPLG_BASE_URL=https://dspace.nplg.gov.ge/",
        "HOST=0.0.0.0",
        "PORT=8000",
        "ALLOW_ANONYMOUS=false",
        "API_BEARER_TOKEN=replace-with-at-least-32-random-characters",
        "UPSTREAM_RATE_PER_SECOND=1.0",
        "MAX_REQUEST_BODY_BYTES=1048576",
        "REQUEST_BODY_TIMEOUT_SECONDS=10",
        "MAX_CONCURRENT_MCP_REQUESTS=16",
        "MAX_CONCURRENT_ASSET_STREAMS=8",
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
    assert text.startswith("FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91")
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
        "defusedxml==0.7.1",
        "fastapi==0.133.0",
        "h11==0.16.0",
        "httpcore==1.0.9",
        "httpx==0.28.1",
        "idna==3.17",
        "lxml==6.1.1",
        "pillow==12.3.0",
        "prometheus-client==0.25.0",
        "pydantic==2.13.4",
        "pydantic-core==2.46.4",
        "pypdfium2==5.8.0",
        "soupsieve==2.8.4",
        "starlette==1.3.1",
        "typing-extensions==4.16.0",
        "typing-inspection==0.4.2",
        "uvicorn==0.48.0",
    }
    input_lines = {
        line.strip()
        for line in (ROOT / "requirements.in").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert input_lines == expected
    assert lines == expected
    blocks = lock_text.splitlines()
    requirement_indexes = [index for index, line in enumerate(blocks) if line and not line[0].isspace() and "==" in line]
    for position, start in enumerate(requirement_indexes):
        end = requirement_indexes[position + 1] if position + 1 < len(requirement_indexes) else len(blocks)
        assert any("--hash=sha256:" in line for line in blocks[start:end])

def test_compose_has_reverse_proxy_persistent_cache_and_container_hardening() -> None:
    data = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    app = data["services"]["app"]
    caddy = data["services"]["caddy"]
    assert "ports" not in app
    assert app["expose"] == ["8000"]
    assert app["read_only"] is True
    assert app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in app["security_opt"]
    assert app["pids_limit"] <= 256
    assert app["restart"] == "unless-stopped"
    assert any("nplg_cache:/data/cache" in volume for volume in app["volumes"])
    assert "healthcheck" in app
    assert caddy["image"] == "caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
    assert caddy["depends_on"]["app"]["condition"] == "service_healthy"
    assert set(caddy["ports"]) == {"80:80", "443:443"}
    assert set(data["volumes"]) >= {"nplg_cache", "caddy_data", "caddy_config"}


def test_caddy_and_operator_guide_cover_tls_limits_smoke_backup_and_residual_egress_risk() -> None:
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8").lower()
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8").lower()
    assert "reverse_proxy app:8000" in caddy
    assert "max_size 1mb" in caddy
    assert "strict-transport-security" in caddy
    assert "@private_metrics path /metrics" in caddy
    assert "respond @private_metrics 404" in caddy
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
    ):
        assert phrase in guide


def test_operator_scripts_parse_as_python() -> None:
    for relative in ("scripts/verify_deploy.py", "scripts/smoke_live.py", "scripts/delete_render.py"):
        ast.parse((ROOT / relative).read_text(encoding="utf-8"), filename=relative)


def test_operator_render_cleanup_script_is_available_inside_the_app_image() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY scripts/delete_render.py ./scripts/delete_render.py" in dockerfile


def test_operator_render_cleanup_requires_the_app_to_be_stopped() -> None:
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8")
    assert "docker compose exec -T app python scripts/delete_render.py" not in guide
    assert "docker compose run --rm --no-deps app python scripts/delete_render.py" in guide


def test_public_tool_verifier_expects_a_read_only_catalog() -> None:
    text = (ROOT / "scripts" / "verify_deploy.py").read_text(encoding="utf-8")
    assert '"delete_render"' not in text
    assert "EXPECTED_TOOLS" in text


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
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = set(pyproject["project"]["dependencies"])
    test_dependencies = set(pyproject["project"]["optional-dependencies"]["test"])
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    source = (ROOT / "src" / "nplg_mcp" / "pdf.py").read_text(encoding="utf-8")
    fixtures = (ROOT / "tests" / "helpers" / "pdf_factory.py").read_text(encoding="utf-8")

    assert "pypdfium2==5.8.0" in runtime
    assert "PyMuPDF==1.26.7" not in runtime
    assert "PyMuPDF==1.26.7" not in test_dependencies
    assert "reportlab==4.4.9" in test_dependencies
    assert "pypdf==5.9.0" in test_dependencies
    assert "pypdfium2==5.8.0" in lock
    assert "PyMuPDF==1.26.7" not in lock
    assert "import pypdfium2" in source
    assert "import pymupdf" not in source
    assert "pymupdf" not in fixtures.lower()


def test_distribution_includes_pdfium_notices_and_connected_image_scan_gate() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    notice = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8") if (ROOT / "THIRD_PARTY_NOTICES.md").exists() else ""
    guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8").lower()

    assert "COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md ./" in dockerfile
    assert "pypdfium2" in notice
    assert "apache-2.0" in notice.lower()
    assert "bsd-3-clause" in notice.lower()
    assert "pymupdf/mupdf is not" in notice.lower()
    assert "reportlab" in notice.lower() and "pypdf" in notice.lower()
    assert "trivy image" in guide
    assert "high,critical" in guide
    assert "unfixed" in guide
    assert "cve triage" in guide


def test_distribution_uses_non_deprecated_spdx_license_metadata() -> None:
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["build-system"]["requires"][0] == "setuptools>=77"
    assert pyproject["project"]["license"] == "MIT"


def test_wheel_metadata_includes_third_party_notices() -> None:
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["license-files"] == ["LICENSE", "THIRD_PARTY_NOTICES.md"]


def test_alpic_declares_python_runtime_and_explicit_uv_commands() -> None:
    import json

    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.13"
    data = json.loads((ROOT / "alpic.json").read_text(encoding="utf-8"))
    assert data == {
        "$schema": "https://assets.alpic.ai/alpic.json",
        "installCommand": "uv venv --python python3 .venv && uv pip install --python .venv/bin/python --require-hashes --no-deps --only-binary=:all: -r requirements.lock",
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
