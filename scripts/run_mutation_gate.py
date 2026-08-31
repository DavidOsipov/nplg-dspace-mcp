# Copyright (c) 2026 David Osipov
"""Externally isolated killed-only mutation authority."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, TextIO, cast

if __name__ == "__main__" and not __package__:
    script_package_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, script_package_root.as_posix())
    __package__ = "scripts"

from scripts.run_test_gate import (
    Clock,
    CommandRequest,
    CommandResult,
    Executor,
    Filesystem,
    Git,
    ReleaseGitEvidence,
    SourceSnapshot,
    SystemClock,
    SystemExecutor,
    SystemFilesystem,
    SystemGit,
    bind_external_snapshot,
    capture_source_snapshot,
    create_external_output,
    materialize_snapshot,
    read_bound_regular_file,
    registered_worktrees,
    reject_mutation_tool_shadows,
    release_git_evidence,
    repository_evidence,
    stable_snapshot_file,
    trusted_mutation_python_command,
)
from scripts.run_test_gate import TestGateError as MutationGateError

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

__all__ = (
    "CommandRequest",
    "CommandResult",
    "MutationGateError",
    "MutationGateRequest",
    "MutationGateResult",
    "MutationPolicy",
    "MutationSummary",
    "cli",
    "initial_mutation_policy",
    "main",
    "mutation_policy_for_targets",
    "parse_arguments",
    "parse_mutation_results",
    "run_mutation_gate",
)

_MAX_META_BYTES = 16 * 1024 * 1024
_MAX_MUTANT_DURATION_SECONDS = 86_400
_MAX_MUTANT_NAME_CHARACTERS = 512
_NO_TESTS_STATUS = 33
_META_KEYS = frozenset(
    {
        "exit_code_by_key",
        "hash_by_function_name",
        "type_check_error_by_key",
        "durations_by_key",
        "estimated_durations_by_key",
    }
)
_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_LOCAL_FUNCTION_TEXT = (
    rf"(?:x_{_IDENTIFIER}|xǁ{_IDENTIFIER}(?:\.{_IDENTIFIER})*ǁ{_IDENTIFIER})"
)
_MUTANT_NAME = re.compile(
    "".join(
        (
            rf"(?P<function>{_IDENTIFIER}(?:\.{_IDENTIFIER})*\.{_LOCAL_FUNCTION_TEXT})",
            r"__mutmut_(?P<ordinal>[1-9][0-9]*)\Z",
        )
    )
)
_FUNCTION_HASH = re.compile(r"[0-9a-f]{12}\Z")
_GIT_OBJECT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_MAX_REF_BYTES = 1024
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_OUTPUT_DIRECTORIES = frozenset({"cache", "home", "pycache", "snapshot", "tmp"})
_INITIAL_TARGETS = (
    "src/nplg_mcp/security.py",
    "src/nplg_mcp/tokens.py",
    "src/nplg_mcp/downloader.py",
    "src/nplg_mcp/storage.py",
    "src/nplg_mcp/errors.py",
    "scripts/delete_render.py",
    "scripts/smoke_live.py",
    "scripts/run_quality_gate.py",
)
_TASK_NINE_TARGETS = (
    "src/nplg_mcp/contracts/base.py",
    "src/nplg_mcp/contracts/inputs.py",
    "src/nplg_mcp/contracts/outputs.py",
    "src/nplg_mcp/contracts/catalog.py",
    "src/nplg_mcp/tools.py",
)
_TASK_TEN_TARGETS = (
    "src/nplg_mcp/contracts/schema.py",
    "scripts/export_contracts.py",
)
_TASK_ELEVEN_AND_FOURTEEN_TARGETS = (
    "src/nplg_mcp/mcp_server.py",
    "src/nplg_mcp/sdk_boundary.py",
    "src/nplg_mcp/errors.py",
)
_TASK_TWELVE_TARGETS = ("src/nplg_mcp/errors.py",)
_TASK_THIRTEEN_TARGETS = (
    "src/nplg_mcp/sdk_boundary.py",
    "src/nplg_mcp/http_security.py",
    "src/nplg_mcp/json_preflight.py",
    "src/nplg_mcp/config.py",
    "src/nplg_mcp/app.py",
    "src/nplg_mcp/__main__.py",
)
_TASK_SIXTEEN_A_TARGETS = (
    "src/nplg_mcp/malware.py",
    "src/nplg_mcp/downloader.py",
    "src/nplg_mcp/storage.py",
    "src/nplg_mcp/storage_lifecycle.py",
    "src/nplg_mcp/tools.py",
    "src/nplg_mcp/pdf_worker_client.py",
    "scripts/verify_scanner_container.py",
    "scripts/verify_pdf_worker_quota.py",
    "scripts/verify_private_recovery.py",
)
_TASK_SEVENTEEN_TARGETS = (
    "src/nplg_mcp/app.py",
    "src/nplg_mcp/http_types.py",
    "src/nplg_mcp/security.py",
    "src/nplg_mcp/network.py",
    "src/nplg_mcp/resilience.py",
    "src/nplg_mcp/downloader.py",
    "scripts/run_live_nplg_canary.py",
)
_TASK_EIGHTEEN_TARGETS = (
    "src/nplg_mcp/parsers.py",
    "src/nplg_mcp/repository.py",
    "src/nplg_mcp/tokens.py",
)
_TASK_NINETEEN_TARGETS = ("src/nplg_mcp/profiles.py",)
_TASK_TWENTY_ONE_A_TARGETS = ("src/nplg_mcp/capabilities.py",)
_TASK_TWENTY_TWO_TARGETS = ("scripts/verify_release.py",)
_TASK_ONE_TARGETS = ("scripts/build_asvs_matrix.py",)
_TARGET_MODULES = {
    "scripts/build_asvs_matrix.py": "scripts.build_asvs_matrix",
    "src/nplg_mcp/security.py": "nplg_mcp.security",
    "src/nplg_mcp/tokens.py": "nplg_mcp.tokens",
    "src/nplg_mcp/downloader.py": "nplg_mcp.downloader",
    "src/nplg_mcp/storage.py": "nplg_mcp.storage",
    "src/nplg_mcp/storage_lifecycle.py": "nplg_mcp.storage_lifecycle",
    "src/nplg_mcp/errors.py": "nplg_mcp.errors",
    "scripts/delete_render.py": "scripts.delete_render",
    "scripts/smoke_live.py": "scripts.smoke_live",
    "scripts/run_quality_gate.py": "scripts.run_quality_gate",
    "src/nplg_mcp/contracts/base.py": "nplg_mcp.contracts.base",
    "src/nplg_mcp/contracts/inputs.py": "nplg_mcp.contracts.inputs",
    "src/nplg_mcp/contracts/outputs.py": "nplg_mcp.contracts.outputs",
    "src/nplg_mcp/contracts/catalog.py": "nplg_mcp.contracts.catalog",
    "src/nplg_mcp/tools.py": "nplg_mcp.tools",
    "src/nplg_mcp/contracts/schema.py": "nplg_mcp.contracts.schema",
    "scripts/export_contracts.py": "scripts.export_contracts",
    "src/nplg_mcp/mcp_server.py": "nplg_mcp.mcp_server",
    "src/nplg_mcp/sdk_boundary.py": "nplg_mcp.sdk_boundary",
    "src/nplg_mcp/http_security.py": "nplg_mcp.http_security",
    "src/nplg_mcp/json_preflight.py": "nplg_mcp.json_preflight",
    "src/nplg_mcp/config.py": "nplg_mcp.config",
    "src/nplg_mcp/app.py": "nplg_mcp.app",
    "src/nplg_mcp/__main__.py": "nplg_mcp.__main__",
    "src/nplg_mcp/http_types.py": "nplg_mcp.http_types",
    "src/nplg_mcp/network.py": "nplg_mcp.network",
    "src/nplg_mcp/resilience.py": "nplg_mcp.resilience",
    "scripts/run_live_nplg_canary.py": "scripts.run_live_nplg_canary",
    "src/nplg_mcp/parsers.py": "nplg_mcp.parsers",
    "src/nplg_mcp/repository.py": "nplg_mcp.repository",
    "src/nplg_mcp/profiles.py": "nplg_mcp.profiles",
    "src/nplg_mcp/capabilities.py": "nplg_mcp.capabilities",
    "scripts/verify_release.py": "scripts.verify_release",
    "src/nplg_mcp/malware.py": "nplg_mcp.malware",
    "src/nplg_mcp/pdf_worker_client.py": "nplg_mcp.pdf_worker_client",
    "scripts/verify_scanner_container.py": "scripts.verify_scanner_container",
    "scripts/verify_pdf_worker_quota.py": "scripts.verify_pdf_worker_quota",
    "scripts/verify_private_recovery.py": "scripts.verify_private_recovery",
}
_REQUIRED_LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "src/nplg_mcp/security.py": (
        "x__default_resolver",
        "x__invalid",
        "x__validate_origin",
        "x_build_item_url",
        "x_is_forbidden_address",
        "x_parse_handle_input",
        "x_resolve_approved_addresses",
        "x_validate_upstream_url",
    ),
    "src/nplg_mcp/tokens.py": (
        "x__b64decode",
        "x__b64encode",
        "x__validate_asset_claims",
        "x__validate_path",
        "x_sign_asset_token",
        "x_verify_asset_token",
    ),
    "src/nplg_mcp/downloader.py": ("x__validate_nplg_dns",),
    "src/nplg_mcp/http_types.py": (),
    "src/nplg_mcp/network.py": (
        "x_create_resolved_endpoint",
        "xǁBoundAsyncNetworkBackendǁ_deadline",
        "xǁBoundAsyncNetworkBackendǁconnect_tcp",
        "xǁBoundAsyncNetworkBackendǁconnect_unix_socket",
        "xǁBoundAsyncNetworkBackendǁsleep",
    ),
    "src/nplg_mcp/resilience.py": (
        "xǁUpstreamGuardPolicyǁ__post_init__",
        "xǁUpstreamGuardǁadmit",
        "xǁUpstreamGuardǁcomplete_attempt",
        "xǁUpstreamGuardǁ_open_interval",
    ),
    "scripts/run_live_nplg_canary.py": (
        "x_canonical_record_digest",
        "x_execute_canary_probe",
        "x_validate_record_digest",
        "x_write_record_exclusive",
    ),
    "src/nplg_mcp/parsers.py": (
        "x__bitstream_id",
        "x__canonical_item_from_href",
        "x__class_contains",
        "x__collections",
        "x__dc_fields",
        "x__dim_fields",
        "x__extract_handle",
        "x__field_values",
        "x__first_descendant",
        "x__full_fields",
        "x__has_full_metadata_text",
        "x__has_next_page_class",
        "x__has_search_results_class",
        "x__html_attribute_text",
        "x__html_field_code_points",
        "x__html_semantic_text_code_points",
        "x__local_name",
        "x__match_group",
        "x__next_search_offset",
        "x__normalize",
        "x__normalize_date",
        "x__oai_fields",
        "x__parse_bitstreams",
        "x__parse_size",
        "x__parse_xml",
        "x__preflight_html",
        "x__preflight_xml",
        "x__raise_for_oai_error",
        "x__record_from_fields",
        "x__require_exact_owned_child",
        "x__require_preflight_agreement",
        "x__saturating_increment",
        "x__search_columns",
        "x__search_items",
        "x__search_total",
        "x__summary_fields",
        "x__tag_attribute",
        "x__tag_text",
        "x__unique",
        "x__upstream_failure",
        "x__validate_html_tree",
        "x__validate_oai_identifier",
        "x__validate_text_budget",
        "x__validate_xml_tree",
        "x_parse_item_page",
        "x_parse_metadata_formats",
        "x_parse_oai_record",
        "x_parse_search_results",
        "xǁ_HtmlBudgetParserǁ__init__",
        "xǁ_HtmlBudgetParserǁ_add_attributes",
        "xǁ_HtmlBudgetParserǁ_add_element",
        "xǁ_HtmlBudgetParserǁ_add_text",
        "xǁ_HtmlBudgetParserǁcheck_deadline",
    ),
    "src/nplg_mcp/repository.py": (
        "x__canonical_search_query",
        "x__publish_metadata_formats",
        "x__record_dns_app_error",
        "x__record_transport_error",
        "x__require_metadata_prefix",
        "x__validate_nplg_dns",
        "x_decode_cursor",
        "x_encode_cursor",
    ),
    "src/nplg_mcp/storage.py": (
        "x__cleanup_render_tiles",
        "x__cleanup_tile_page",
        "x__fsync_directory",
        "x__remove_storage_path",
        "x__render_completion_exists",
        "x__sha256_path",
        "xǁContentAddressedStoreǁ__init__",
        "xǁContentAddressedStoreǁ_cache_full",
        "xǁContentAddressedStoreǁ_cleanup_incomplete_renders",
        "xǁContentAddressedStoreǁ_cleanup_stale_staging",
        "xǁContentAddressedStoreǁ_commit_staged_file",
        "xǁContentAddressedStoreǁ_commit_staged_render",
        "xǁContentAddressedStoreǁ_delete_render_subtree_locked",
        "xǁContentAddressedStoreǁ_discard_staged_file",
        "xǁContentAddressedStoreǁ_is_render_id",
        "xǁContentAddressedStoreǁ_release_staging_bytes",
        "xǁContentAddressedStoreǁ_render_lock_for",
        "xǁContentAddressedStoreǁ_render_tree_bytes",
        "xǁContentAddressedStoreǁ_reserve_staging_bytes",
        "xǁContentAddressedStoreǁ_scan_existing_bytes",
        "xǁContentAddressedStoreǁ_validate_filename",
        "xǁContentAddressedStoreǁ_validate_media_type",
        "xǁContentAddressedStoreǁ_validate_namespace",
        "xǁContentAddressedStoreǁ_validate_staged_identity",
        "xǁContentAddressedStoreǁ_validated_render_subtree",
        "xǁContentAddressedStoreǁbegin_render_transaction",
        "xǁContentAddressedStoreǁdelete_render_subtree",
        "xǁContentAddressedStoreǁput_bytes",
        "xǁContentAddressedStoreǁput_render_bytes",
        "xǁContentAddressedStoreǁresolve_asset",
        "xǁContentAddressedStoreǁstage",
        "xǁ_RenderTransactionǁ__init__",
        "xǁ_RenderTransactionǁcommit",
        "xǁ_RenderTransactionǁreset",
        "xǁ_RenderTransactionǁrollback",
        "xǁ_StagedWriterǁ__enter__",
        "xǁ_StagedWriterǁ__exit__",
        "xǁ_StagedWriterǁ__init__",
        "xǁ_StagedWriterǁ_snapshot",
        "xǁ_StagedWriterǁcommit",
        "xǁ_StagedWriterǁcommit_render",
        "xǁ_StagedWriterǁwrite",
    ),
    "src/nplg_mcp/errors.py": (
        "x__checked_string_total",
        "x__consume_public_detail_value",
        "x__internal_public_error",
        "x__snapshot_frame",
        "x__snapshot_public_details",
        "x__snapshot_scalar",
        "x__store_snapshot",
        "x_to_public_error",
        "x_validate_resource_uri",
    ),
    "scripts/delete_render.py": (
        "x__confirm",
        "x__default_dependencies",
        "x__default_processor_factory",
        "x__delete",
        "x__parse_arguments",
        "x__parser",
        "x__write_failure",
        "x__write_result",
        "x_main",
    ),
    "scripts/smoke_live.py": (
        "x__add_download_output",
        "x__add_render_output",
        "x__argument_failure",
        "x__arguments_from_values",
        "x__default_client_factory",
        "x__default_dependencies",
        "x__default_verifier",
        "x__object_list",
        "x__optional_string",
        "x__parse_args",
        "x__parser",
        "x__required_string",
        "x__run_smoke",
        "x__selected_handle",
        "x__write_failure",
        "x__write_output",
        "x_first_public_pdf",
        "x_main",
    ),
    "scripts/run_quality_gate.py": (
        "x__canonical_existing_worktree",
        "x__canonical_new_cache",
        "x__canonical_registered_worktrees",
        "x__checked_paths",
        "x__closed_environment",
        "x__consume_pipe_event",
        "x__decode_bounded_git_field",
        "x__expand",
        "x__expand_directory",
        "x__fail",
        "x__fingerprint_file",
        "x__inventory_files",
        "x__kill_process_group",
        "x__parse_registered_worktree_block",
        "x__parser",
        "x__paths_intersect",
        "x__read_bounded_streams",
        "x__resolve_inventory_input",
        "x__run_quality_commands",
        "x__selected_paths",
        "x__stable_regular_file_sha256",
        "x__stream_evidence",
        "x__validate_worktree_branch",
        "x__validate_worktree_optional_fields",
        "x__validated_executable",
        "x__validated_git_relative_path",
        "x__verify_versions",
        "x_cli",
        "x_command_plan",
        "x_fingerprint_paths",
        "x_freeze_input_inventory",
        "x_git_snapshot",
        "x_main",
        "x_parse_arguments",
        "x_parse_porcelain_status",
        "x_parse_registered_worktrees",
        "x_registered_worktree_roots",
        "x_run_bounded_command",
        "x_run_quality_gate",
        "x_run_self_test",
        "x_validate_external_cache",
        "x_validate_managed_node",
        "x_validate_release_arguments",
        "x_validate_release_state",
        "x_verify_exact_version",
        "x_version_probes",
    ),
    "src/nplg_mcp/contracts/base.py": (
        "x__own_sequence",
        "x__validate_safe_integer",
        "x_reject_unsafe_text",
    ),
    "src/nplg_mcp/contracts/inputs.py": ("x__validate_page_selection_length",),
    "src/nplg_mcp/contracts/outputs.py": (),
    "src/nplg_mcp/contracts/catalog.py": (
        "xǁToolCatalogǁ__init__",
        "xǁToolCatalogǁcall",
        "xǁ_ContractValidationErrorǁ__init__",
    ),
    "src/nplg_mcp/tools.py": (
        "x__frozen_protocol_input_schema",
        "x__joined_text",
        "x__json_integer",
        "x__json_string",
        "x__model_json",
        "x__public_model_schema",
        "x__system_utc_now",
        "x__tool_annotations",
        "x__validated_serialized_pdf_capacity",
        "xǁRepositoryProtocolǁsearch",
        "xǁToolServiceǁ__init__",
        "xǁToolServiceǁ_download_document",
        "xǁToolServiceǁ_ensure_profile_catalog",
        "xǁToolServiceǁ_get_metadata",
        "xǁToolServiceǁ_get_render_manifest",
        "xǁToolServiceǁ_inspect_pdf",
        "xǁToolServiceǁ_list_files",
        "xǁToolServiceǁ_manifest_dict",
        "xǁToolServiceǁ_render_pages",
        "xǁToolServiceǁ_render_tiles",
        "xǁToolServiceǁ_resolve_document",
        "xǁToolServiceǁ_run_pdf_job",
        "xǁToolServiceǁ_search",
        "xǁToolServiceǁ_signed_asset_url",
        "xǁToolServiceǁcall",
        "xǁToolServiceǁensure_ready",
        "xǁToolServiceǁlist_resources",
        "xǁToolServiceǁlist_tools",
        "xǁToolServiceǁread_resource",
    ),
    "src/nplg_mcp/contracts/schema.py": (
        "x__child_schemas",
        "x__contract_model_key",
        "x__model_schema",
        "x__rewrite_references",
        "x__utf8_key",
        "x__validate_node_identity",
        "x__validate_node_values",
        "x__validate_numeric_bounds",
        "x__validate_pattern",
        "x__validate_required",
        "x__validate_schema",
        "x_aggregate_contract_schema",
        "x_canonical_json_bytes",
        "x_contract_models",
        "x_export_contract_schemas",
        "x_normalized_schema",
        "x_schema_manifest",
    ),
    "scripts/export_contracts.py": (
        "x__artifacts",
        "x__fail",
        "x__inventory",
        "x__read_artifact",
        "x__validated_output_directory",
        "x__write_artifact",
        "x_cli",
        "x_export_contracts",
        "x_main",
        "x_parse_arguments",
    ),
    "src/nplg_mcp/mcp_server.py": ("x_create_mcp_server",),
    "src/nplg_mcp/sdk_boundary.py": (
        "x__adapt_resource",
        "x__binding_for_tool",
        "x__serialized_output",
    ),
    "src/nplg_mcp/http_security.py": (
        "x_build_transport_security_settings",
        "xǁMcpSecurityMiddlewareǁ__call__",
        "xǁMcpSecurityMiddlewareǁ__init__",
        "xǁMcpSecurityMiddlewareǁ_admitted_call",
        "xǁMcpSecurityMiddlewareǁ_authenticated_principal",
        "xǁMcpSecurityMiddlewareǁ_bounded_body",
        "xǁMcpSecurityMiddlewareǁ_security_call",
        "xǁMcpSecurityMiddlewareǁ_send_response",
        "xǁMcpSecurityMiddlewareǁ_send_with_policy",
        "xǁMcpSecurityMiddlewareǁshutdown",
        "xǁMcpSecurityMiddlewareǁstart",
        "xǁMcpSecurityMiddlewareǁ_try_acquire_admission",
        "xǁ_JSONResponseǁ__init__",
    ),
    "src/nplg_mcp/json_preflight.py": (
        "x_preflight_json",
        "xǁJsonPreflightErrorǁ__init__",
        "xǁ_JsonPreflightParserǁ__init__",
        "xǁ_JsonPreflightParserǁ_begin_value",
        "xǁ_JsonPreflightParserǁ_consume_array_separator",
        "xǁ_JsonPreflightParserǁ_consume_byte",
        "xǁ_JsonPreflightParserǁ_consume_escape",
        "xǁ_JsonPreflightParserǁ_consume_exponent",
        "xǁ_JsonPreflightParserǁ_consume_fraction",
        "xǁ_JsonPreflightParserǁ_consume_integer",
        "xǁ_JsonPreflightParserǁ_consume_number",
        "xǁ_JsonPreflightParserǁ_consume_object_key",
        "xǁ_JsonPreflightParserǁ_consume_object_separator",
        "xǁ_JsonPreflightParserǁ_consume_one_or_more_digits",
        "xǁ_JsonPreflightParserǁ_consume_sign",
        "xǁ_JsonPreflightParserǁ_consume_string",
        "xǁ_JsonPreflightParserǁ_consume_unicode_code_unit",
        "xǁ_JsonPreflightParserǁ_count_token",
        "xǁ_JsonPreflightParserǁ_finish_container",
        "xǁ_JsonPreflightParserǁ_finish_scalar",
        "xǁ_JsonPreflightParserǁ_increment_array_item",
        "xǁ_JsonPreflightParserǁ_increment_object_member",
        "xǁ_JsonPreflightParserǁ_is_digit",
        "xǁ_JsonPreflightParserǁ_is_nonzero_digit",
        "xǁ_JsonPreflightParserǁ_peek_byte",
        "xǁ_JsonPreflightParserǁ_push_container",
        "xǁ_JsonPreflightParserǁ_skip_whitespace",
        "xǁ_JsonPreflightParserǁvalidate",
    ),
    "src/nplg_mcp/config.py": (
        "x__api_principal_registry",
        "x__authorization",
        "x__bool",
        "x__canonical_alpic_gateway_host",
        "x__canonical_host",
        "x__canonical_origin",
        "x__deployment_profile",
        "x__environment",
        "x__float",
        "x__int",
        "x__is_loopback_host",
        "x__mcp_transport_allowlists",
        "x__normalize_public_base_url",
        "x__pdf_executor",
        "x__pdf_settings",
        "x__reject_duplicate_json_keys",
        "x__signing_secret",
        "x__strict_json_string_list",
        "x__tile_geometry",
        "x__validate_anonymous_scope",
        "x__validate_credential_separation",
        "x_load_config",
        "x_validate_deployment_profile",
        "xǁApiPrincipalCredentialǁapi_key_value",
        "xǁApiPrincipalCredentialǁbearer_value",
        "xǁApiPrincipalCredentialǁcredential_value",
    ),
    "src/nplg_mcp/app.py": (
        "x__api_principal",
        "x__app_error_response",
        "x__asset_response",
        "x__ensure_runtime_ready",
        "x__enter_owned_context",
        "x__full_runtime_module",
        "x__has_valid_api_credential",
        "x__header_values",
        "x__json_response",
        "x__metrics_response",
        "x__origin",
        "x__reject_distributed_full",
        "x__reject_unavailable_production_oauth",
        "x__request_authority",
        "x__require_public_host",
        "x__runtime_services",
        "x__validate_production_auth_activation",
        "x__validate_startup_config",
        "x_create_app",
        "xǁ_DisconnectAwareFileResponseǁ__init__",
        "xǁ_DisconnectAwareFileResponseǁ_wait_for_disconnect",
    ),
    "src/nplg_mcp/__main__.py": (
        "x__http_concurrency_limit",
        "x_main",
    ),
}

_TASK_SIXTEEN_A_REQUIRED_LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "src/nplg_mcp/malware.py": (
        "x__peer_credentials",
        "x__sha256_path",
        "x_validate_clean_scan_result",
    ),
    "src/nplg_mcp/downloader.py": tuple(
        sorted(
            frozenset(_REQUIRED_LOCAL_FUNCTIONS["src/nplg_mcp/downloader.py"])
            | {
                "x__record_dns_app_error",
                "x__record_transport_error",
                "x__run_storage_commit",
                "x__run_storage_write",
                "x__system_scan_now",
            }
        )
    ),
    "src/nplg_mcp/storage.py": tuple(
        sorted(
            frozenset(_REQUIRED_LOCAL_FUNCTIONS["src/nplg_mcp/storage.py"])
            | {
                "x__delete_orphan_staging_inventory",
                "x__current_async_task",
                "x__directory_identity",
                "x__inventory_orphan_staging",
                "x__open_verified_directory",
                "x__open_verified_regular_file",
                "x__regular_file_identity",
                "x__same_staging_entry",
                "x__validate_staging_entry_name",
                "xǁContentAddressedStoreǁ_asset_object_key",
                "xǁContentAddressedStoreǁ_activate_publication_reservation_locked",
                "xǁContentAddressedStoreǁ_close_admission",
                "xǁContentAddressedStoreǁ_commit_publication_reservation_locked",
                "xǁContentAddressedStoreǁ_consume_existing_document_locked",
                "xǁContentAddressedStoreǁ_emit_lifecycle_alert",
                "xǁContentAddressedStoreǁ_ensure_insertion_sequence",
                "xǁContentAddressedStoreǁ_finish_prune_locked",
                "xǁContentAddressedStoreǁ_invoke_render_transaction_guard",
                "xǁContentAddressedStoreǁ_object_roots",
                "xǁContentAddressedStoreǁ_prune_pressure",
                "xǁContentAddressedStoreǁ_prune_unleased",
                "xǁContentAddressedStoreǁ_publication_denial",
                "xǁContentAddressedStoreǁ_publish_new_document_locked",
                "xǁContentAddressedStoreǁ_reconcile_staged_size_locked",
                "xǁContentAddressedStoreǁ_register_render_transaction_locked",
                "xǁContentAddressedStoreǁ_record_unsatisfied_prune",
                "xǁContentAddressedStoreǁ_release_publication_reservation_locked",
                "xǁContentAddressedStoreǁ_release_staged_reservation_locked",
                "xǁContentAddressedStoreǁ_replace_staged_render",
                "xǁContentAddressedStoreǁ_require_lifecycle_policy",
                "xǁContentAddressedStoreǁ_require_render_mutation_authority_locked",
                "xǁContentAddressedStoreǁ_require_render_transaction_destination",
                "xǁContentAddressedStoreǁ_sample_capacity",
                "xǁContentAddressedStoreǁ_stage_render_transaction",
                "xǁContentAddressedStoreǁ_stored_objects",
                "xǁContentAddressedStoreǁ_tree_stats",
                "xǁContentAddressedStoreǁ_validate_actual_publication",
                "xǁContentAddressedStoreǁ_validate_publication_maximum",
                "xǁContentAddressedStoreǁ_validate_published_identity",
                "xǁContentAddressedStoreǁ_validated_render_destination",
                "xǁContentAddressedStoreǁ_verify_store_root_identity",
                "xǁContentAddressedStoreǁabort_publication_reservation",
                "xǁContentAddressedStoreǁacquire_asset_lease",
                "xǁContentAddressedStoreǁbegin_publication_reservation",
                "xǁContentAddressedStoreǁcommit_publication_reservation",
                "xǁContentAddressedStoreǁlease_asset",
                "xǁContentAddressedStoreǁprune",
                "xǁContentAddressedStoreǁreconcile_lifecycle",
                "xǁContentAddressedStoreǁrelease_asset_lease",
                "xǁContentAddressedStoreǁreplace_render_bytes_if_matches",
                "xǁContentAddressedStoreǁreserve_publication",
                "xǁ_AssetLeaseǁ__enter__",
                "xǁ_AssetLeaseǁ__exit__",
                "xǁ_AssetLeaseǁ__init__",
                "xǁ_PublicationReservationContextǁ__aexit__",
                "xǁ_PublicationReservationContextǁ__init__",
                "xǁ_PublicationReservationǁ__init__",
                "xǁ_PublicationReservationǁabort",
                "xǁ_PublicationReservationǁactivate",
                "xǁ_PublicationReservationǁbegin",
                "xǁ_PublicationReservationǁclose",
                "xǁ_PublicationReservationǁcommit",
                "xǁ_RenderTransactionǁ_require_active_owner_context",
                "xǁ_RenderTransactionǁ_require_owner_context",
                "xǁ_RenderTransactionǁstage",
                "xǁ_StagedWriterǁprepare_for_scan",
                "xǁ_StagedWriterǁreplace_render",
            }
        )
    ),
    "src/nplg_mcp/storage_lifecycle.py": (
        "x__has_private_state_metadata",
        "x__prepare_private_state_descriptor",
        "x__system_utc_now",
        "x__read_boot_identity_unchecked",
        "x__read_boot_identity",
        "xǁSystemRetentionClockǁ__init__",
        "xǁSystemRetentionClockǁ__call__",
        "xǁInsertionSequenceRecordǁbuild",
        "xǁInsertionHighWaterRecordǁbuild",
        "xǁPublicationReservationErrorǁ__init__",
        "x_validate_retention_capacity",
        "x_filesystem_capacity",
        "x__canonical_json_bytes",
        "x__json_digest",
        "x__clock_record",
        "x__reject_duplicate_keys",
        "xǁClockHighWaterǁ__init__",
        "xǁClockHighWaterǁ_read",
        "xǁClockHighWaterǁ_write",
        "xǁClockHighWaterǁ_assessment",
        "xǁClockHighWaterǁ_baseline",
        "xǁClockHighWaterǁobserve",
        "x__read_private_record",
        "x__write_private_record",
        "x__insertion_object_key",
        "xǁPersistentInsertionOrderǁ__init__",
        "xǁPersistentInsertionOrderǁ_validated_object_path",
        "xǁPersistentInsertionOrderǁ_write_high_water",
        "xǁPersistentInsertionOrderǁ_allocate",
        "xǁPersistentInsertionOrderǁ_load_object_sequence",
        "xǁPersistentInsertionOrderǁinitialize",
        "xǁPersistentInsertionOrderǁensure",
        "xǁPersistentInsertionOrderǁsequence_for",
        "xǁPersistentInsertionOrderǁremove",
    ),
    "src/nplg_mcp/tools.py": tuple(
        sorted(
            (
                frozenset(_REQUIRED_LOCAL_FUNCTIONS["src/nplg_mcp/tools.py"])
                - {"x__json_integer", "x__validated_serialized_pdf_capacity"}
            )
            | {
                "x__remove_private_pdf_pipeline_versions",
                "x__validated_pdf_worker_capacity",
                "xǁToolServiceǁ_about_resource",
                "xǁToolServiceǁ_discover_render_artifact",
                "xǁToolServiceǁ_load_render_resource_index",
                "xǁToolServiceǁ_matching_render_owner",
                "xǁToolServiceǁ_persist_render_resource_index",
                "xǁToolServiceǁ_prune_resource_index",
                "xǁToolServiceǁ_read_artifact_resource",
                "xǁToolServiceǁ_read_bounded_resource_index",
                "xǁToolServiceǁ_read_registered_owner_group",
                "xǁToolServiceǁ_register_render_artifact",
                "xǁToolServiceǁ_registered_artifact",
                "xǁToolServiceǁ_render_artifact_content_identity",
                "xǁToolServiceǁ_render_resource_index_payload",
                "xǁToolServiceǁ_replace_render_resource_index",
                "xǁToolServiceǁ_representative_is_missing",
                "xǁToolServiceǁ_require_bounded_resource_index",
                "xǁToolServiceǁ_resource_index_relative_path",
                "xǁToolServiceǁ_utc_timestamp",
                "xǁToolServiceǁ_validate_registered_artifact",
                "xǁToolServiceǁ_validated_representative_candidate",
            }
        )
    ),
    "src/nplg_mcp/pdf_worker_client.py": (
        "x__peer_credentials",
        "xǁSubprocessPdfExecutorǁ__init__",
        "xǁSubprocessPdfExecutorǁ_run_storage",
        "xǁSubprocessPdfExecutorǁexecute",
        "xǁSubprocessPdfExecutorǁ_execute_with_permit",
        "xǁSubprocessPdfExecutorǁ_cleanup_worker",
        "xǁSubprocessPdfExecutorǁ_remove_job_tree",
        "xǁSubprocessPdfExecutorǁ_restore_job_tree_permissions",
        "xǁSubprocessPdfExecutorǁ_wait_for_cleanup",
        "xǁSubprocessPdfExecutorǁ_validate_and_publish",
        "xǁSubprocessPdfExecutorǁ_worker_environment",
        "xǁSubprocessPdfExecutorǁ_require_deadline",
        "xǁSubprocessPdfExecutorǁ_stage_inputs",
        "xǁSubprocessPdfExecutorǁ_diagnose_unavailable_render_tree",
        "xǁSubprocessPdfExecutorǁ_copy_regular_file",
        "xǁSubprocessPdfExecutorǁ_copy_regular_tree",
        "xǁSubprocessPdfExecutorǁ_exchange",
        "xǁSubprocessPdfExecutorǁ_write_request",
        "xǁSubprocessPdfExecutorǁ_read_result_body",
        "xǁSubprocessPdfExecutorǁ_read_stderr",
        "xǁSubprocessPdfExecutorǁ_terminate_process_group",
        "xǁSubprocessPdfExecutorǁ_wait_for_process_group_exit",
        "xǁSubprocessPdfExecutorǁ_validate_result_binding",
        "xǁSubprocessPdfExecutorǁ_validate_result_pixel_budget",
        "xǁSubprocessPdfExecutorǁ_validate_render_pixel_budget",
        "xǁSubprocessPdfExecutorǁ_publish_outputs",
        "xǁSubprocessPdfExecutorǁ_publish_page_render",
        "xǁSubprocessPdfExecutorǁ_publish_tile_render",
        "xǁSubprocessPdfExecutorǁ_validated_descriptor",
        "xǁSubprocessPdfExecutorǁ_validate_output_file",
        "xǁSubprocessPdfExecutorǁ_validate_image_dimensions",
        "xǁSubprocessPdfExecutorǁ_load_staged_render_manifest",
        "xǁSubprocessPdfExecutorǁ_validate_tile_result_binding",
        "xǁSubprocessPdfExecutorǁ_validate_manifest_file",
        "xǁSubprocessPdfExecutorǁ_require_exact_output_set",
        "xǁSubprocessPdfExecutorǁ_authoritative_matches",
        "xǁSubprocessPdfExecutorǁ_sha256_path",
        "xǁSubprocessPdfExecutorǁ_publish_one",
        "xǁUnixSocketPdfExecutorǁ__init__",
        "xǁUnixSocketPdfExecutorǁ_prepare_work_parent",
        "xǁUnixSocketPdfExecutorǁ_execute_in_work_root",
        "xǁUnixSocketPdfExecutorǁ_verify_socket_path",
        "xǁUnixSocketPdfExecutorǁ_exchange_unix",
    ),
    "scripts/verify_scanner_container.py": ("x_verify",),
    "scripts/verify_pdf_worker_quota.py": ("x_verify",),
    "scripts/verify_private_recovery.py": (
        "x__reject_duplicate_names",
        "x__reject_noninteger_number",
        "x__bounded_json_integer",
        "x__require_canonical_receipt",
        "x__require_receipt_digest",
        "x__parse_recovery_receipt",
        "x__validated_policy",
        "x__bind_receipt",
        "x_verify",
    ),
}

_TASK_EIGHTEEN_REQUIRED_LOCAL_FUNCTIONS = {
    target: (
        (
            "x_derive_cursor_signing_key",
            "x_cursor_query_hash",
            "x__reject_duplicate_cursor_keys",
            "x_sign_cursor",
            "x__require_matching_signature",
            "x_verify_cursor",
            *_REQUIRED_LOCAL_FUNCTIONS[target],
        )
        if target == "src/nplg_mcp/tokens.py"
        else _REQUIRED_LOCAL_FUNCTIONS[target]
    )
    for target in _TASK_EIGHTEEN_TARGETS
}
_TASK_NINETEEN_REQUIRED_LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "src/nplg_mcp/profiles.py": ("x_tool_names_for_profile",),
}
_TASK_TWENTY_ONE_A_REQUIRED_LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "src/nplg_mcp/capabilities.py": (
        "x__body_evidence",
        "x__canonical_bytes",
        "x__canonical_negative_alpic_tasks_blockers",
        "x__decode_base64",
        "x__expected_dispatch_response",
        "x__expected_error_response",
        "x__expected_initialize_request",
        "x__expected_tool_request",
        "x__finalize",
        "x__header_values",
        "x__headers",
        "x__initialize_body",
        "x__load",
        "x__load_alpic_tasks_contract",
        "x__model_json",
        "x__observe_alpic_local_sdk",
        "x__observe_http_case",
        "x__observe_sdk_matrix",
        "x__package_file_sha256",
        "x__package_tree_sha256",
        "x__parse_bearer_challenge",
        "x__raw_request",
        "x__reject_duplicate_pairs",
        "x__sdk_probe_app",
        "x__sdk_tasks_public_api_available",
        "x__sha256_json",
        "x__tool_call_body",
        "x__tool_headers",
        "x_canonical_json_sha256",
        "x_canonical_model_json",
        "x_load_alpic_tasks_source_evidence",
        "x_load_alpic_tasks_verdict",
        "x_load_alpic_verdict",
        "x_load_provider_verdict",
        "x_load_sdk_verdict",
        "x_probe_alpic_oauth_discovery",
        "x_probe_alpic_tasks_capability",
        "x_probe_oauth_provider",
        "x_probe_sdk_authorization",
        "x_validate_alpic_tasks_verdict_json",
        "x_validate_synthetic_alpic_tasks_verdict",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_http_semantics",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_installed_identity",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_matrix_digests",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_matrix_identity",
        "xǁSdkAuthorizationCapabilityVerdictǁ_check_support_decision",
        "xǁ_FixtureDispatchCounterǁ__init__",
        "xǁ_FixtureDispatchCounterǁcall_tool",
        "xǁ_FixtureProbeStateǁ__init__",
        "xǁ_FixtureTokenVerifierǁ__init__",
        "xǁ_FixtureTokenVerifierǁverify_token",
    ),
}
_TASK_TWENTY_TWO_REQUIRED_LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "scripts/verify_release.py": (
        "x__dependency_window",
        "x__duplicate_json_name",
        "x__external_requirements",
        "x__fail",
        "x__fail_from",
        "x__gate_command",
        "x__load_json_object",
        "x__load_model",
        "x__parser",
        "x__reject_json_number",
        "x__source_entry",
        "x__trusted_python_gate_command",
        "x__trusted_release_tool_proof",
        "x__unsafe_command_text",
        "x__utc_timestamp",
        "x__valid_closed_python_tool_success",
        "x__valid_success_evidence",
        "x__validate_dependency_evidence_identity",
        "x__validate_dependency_exception",
        "x__validate_dependency_finding",
        "x__validate_pyright_runtime_identity",
        "x_assert_source_snapshot",
        "x_candidate_release_status",
        "x_capture_source_descriptor_snapshot",
        "x_cli",
        "x_load_dependency_evidence",
        "x_load_dependency_risk_policy",
        "x_load_release_command_manifest",
        "x_load_release_controller_policy",
        "x_load_release_policies",
        "x_load_trivy_database_receipt",
        "x_load_trusted_package_sources_policy",
        "x_local_gate_commands",
        "x_main",
        "x_materialize_source",
        "x_release_command_manifest_digest",
        "x_run_gate_battery",
        "x_run_local_gates",
        "x_validate_candidate_contract_transcript",
        "x_validate_external_gate_manifest_join",
        "x_write_source_snapshot",
        "xǁSystemCommandRunnerǁ__call__",
    ),
}
_TASK_ONE_REQUIRED_LOCAL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "scripts/build_asvs_matrix.py": (
        "x__bootstrap_profile_release",
        "x__candidate_reference_blockers",
        "x__candidate_profile_release",
        "x_evaluate_profile_release",
    ),
}


def _fail(message: str) -> NoReturn:
    raise MutationGateError(message)


def _fail_from(message: str, cause: BaseException) -> NoReturn:
    raise MutationGateError(message) from cause


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("mutation JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_nonfinite_number(_value: str) -> NoReturn:
    _fail("mutation JSON forbids non-finite values")


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _fail("mutation JSON forbids non-finite values")
    return parsed


def _bounded_json_integer(value: str) -> int:
    parsed = int(value, 10)
    if not -(2**31) <= parsed < 2**31:
        _fail("mutation JSON integer is outside the closed range")
    return parsed


def _load_meta(payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_META_BYTES:
        _fail("mutation metadata is empty, oversized, or invalid")
    try:
        value = cast(
            "object",
            json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=_closed_object,
                parse_constant=_reject_nonfinite_number,
                parse_float=_finite_json_float,
                parse_int=_bounded_json_integer,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        _fail_from("mutation metadata is malformed", exc)
    if type(value) is not dict:
        _fail("mutation metadata must be an object")
    result = cast("dict[str, object]", value)
    if frozenset(result) != _META_KEYS:
        _fail("mutation metadata fields do not match mutmut 3.7.0")
    return result


@dataclass(frozen=True, slots=True)
class MutationPolicy:
    """Closed target, status, and minimum-kill policy."""

    targets: tuple[str, ...]
    killed_exit_codes: frozenset[int]
    accepted_exit_codes: frozenset[int]
    minimum_killed_percent: int
    required_functions: tuple[tuple[str, tuple[str, ...]], ...] = ()
    test_paths: tuple[str, ...] = ()
    deselected_tests: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MutationSummary:
    """Validated complete mutant-status summary."""

    total: int
    killed: int
    target_counts: tuple[tuple[str, int], ...]
    function_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class MutationGateRequest:
    """Immutable developer or release mutation-gate request."""

    worktree: Path
    output_dir: Path | None
    targets: tuple[str, ...]
    require_clean: bool = False
    candidate: str | None = None


@dataclass(frozen=True, slots=True)
class MutationGateResult:
    """Validated mutation result and external workspace."""

    summary: MutationSummary
    output_dir: Path


def _mutation_policy(
    targets: tuple[str, ...],
    *,
    test_paths: tuple[str, ...],
    deselected_tests: tuple[str, ...] = (),
    required_local_functions: dict[str, tuple[str, ...]] | None = None,
) -> MutationPolicy:
    """Build one exact policy from the closed target/function registries."""
    function_registry = (
        _REQUIRED_LOCAL_FUNCTIONS
        if required_local_functions is None
        else required_local_functions
    )
    required = tuple(
        (
            target,
            tuple(
                f"{_TARGET_MODULES[target]}.{local_function}"
                for local_function in function_registry[target]
            ),
        )
        for target in targets
    )
    return MutationPolicy(
        targets=targets,
        killed_exit_codes=frozenset({1}),
        accepted_exit_codes=frozenset({-24, 0, 1, 33}),
        minimum_killed_percent=65,
        required_functions=required,
        test_paths=test_paths,
        deselected_tests=deselected_tests,
    )


def _later_task_mutation_policy(targets: tuple[str, ...]) -> MutationPolicy:
    if targets == _TASK_SIXTEEN_A_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=(
                "tests/unit/test_scanner_container_verifier.py",
                "tests/unit/test_pdf_worker_quota_verifier.py",
                "tests/unit/test_private_recovery_verifier.py",
                "tests/security/test_malware.py",
                "tests/security/test_downloader.py",
                "tests/security/test_pdf_worker.py",
                "tests/security/test_pdf_adversarial_corpus_worker.py",
                "tests/unit/test_pdf_worker_client_edges.py",
                "tests/unit/test_storage.py",
                "tests/unit/test_storage_internals.py",
                "tests/unit/test_storage_transaction_atomicity.py",
                "tests/property/test_storage_properties.py",
                "tests/unit/test_storage_lifecycle.py",
                "tests/unit/test_pdf_publication_reservation.py",
                "tests/unit/test_tools.py",
                "tests/integration/test_pdf.py",
                "tests/static/test_deployment.py",
            ),
            required_local_functions=_TASK_SIXTEEN_A_REQUIRED_LOCAL_FUNCTIONS,
        )
    if targets == _TASK_THIRTEEN_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=(
                "tests/conformance/test_mcp_http.py",
                "tests/contracts/test_sdk_parity.py",
                "tests/security/test_auth_activation.py",
                "tests/unit/test_app_lifespan.py",
                "tests/unit/test_json_preflight.py",
                "tests/property/test_json_preflight_properties.py",
                "tests/unit/test_config.py",
            ),
        )
    if targets == _TASK_EIGHTEEN_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=(
                "tests/unit/test_parsers.py",
                "tests/integration/test_repository.py",
                "tests/property/test_parser_properties.py",
            ),
            required_local_functions=_TASK_EIGHTEEN_REQUIRED_LOCAL_FUNCTIONS,
        )
    if targets == _TASK_NINETEEN_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=(
                "tests/integration/test_profiles.py",
                "tests/contracts/test_sdk_client.py",
                "tests/unit/test_config.py",
            ),
            required_local_functions=_TASK_NINETEEN_REQUIRED_LOCAL_FUNCTIONS,
        )
    if targets == _TASK_TWENTY_ONE_A_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=(
                "tests/contracts/test_sdk_auth_feasibility.py",
                "tests/contracts/test_alpic_oauth_discovery.py",
                "tests/contracts/test_oauth_provider_capability.py",
                "tests/contracts/test_alpic_tasks_capability.py",
                "tests/unit/test_probe_alpic_tasks_capability.py",
                "tests/integration/test_profiles.py",
            ),
            required_local_functions=_TASK_TWENTY_ONE_A_REQUIRED_LOCAL_FUNCTIONS,
        )
    test_paths: tuple[str, ...]
    deselected_tests: tuple[str, ...]
    required_local_functions: dict[str, tuple[str, ...]] | None
    if targets == _TASK_ONE_TARGETS:
        test_paths = (
            "tests/unit/test_build_asvs_matrix.py",
            "tests/property/test_asvs_evidence.py",
            "tests/static/test_asvs_evidence.py",
        )
        deselected_tests = (
            (
                "tests/static/test_asvs_evidence.py::"
                "test_task2_subprocess_suppression_has_exact_closed_inventory"
            ),
        )
        required_local_functions = _TASK_ONE_REQUIRED_LOCAL_FUNCTIONS
    elif targets == _TASK_TWENTY_TWO_TARGETS:
        test_paths = ("tests/static/test_release_gate.py",)
        deselected_tests = ()
        required_local_functions = _TASK_TWENTY_TWO_REQUIRED_LOCAL_FUNCTIONS
    else:
        test_paths = (
            "tests/security/test_ssrf_binding.py",
            "tests/unit/test_upstream_resilience.py",
            "tests/unit/test_live_nplg_canary.py",
            "tests/security/test_downloader.py",
            "tests/integration/test_repository.py",
            "tests/conformance/test_mcp_http.py",
        )
        deselected_tests = (
            (
                "tests/integration/test_repository.py::"
                "test_live_nplg_canary_uses_bound_public_endpoint"
            ),
        )
        required_local_functions = None
    return _mutation_policy(
        targets,
        test_paths=test_paths,
        deselected_tests=deselected_tests,
        required_local_functions=required_local_functions,
    )


def mutation_policy_for_targets(targets: tuple[str, ...]) -> MutationPolicy:
    """Return the exact reviewed mutation policy for one approved target tuple."""
    if type(targets) is not tuple or any(type(target) is not str for target in targets):
        _fail("mutation request does not match the closed initial policy")
    if targets == _INITIAL_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=(
                "tests/security/test_security.py",
                "tests/security/test_tokens.py",
                "tests/security/test_downloader.py",
                "tests/unit/test_storage.py",
                "tests/property/test_storage_properties.py",
                "tests/unit/test_errors.py",
                "tests/unit/test_delete_render.py",
                "tests/unit/test_smoke_live.py",
                "tests/unit/test_quality_gate.py",
            ),
            deselected_tests=(
                "tests/unit/test_errors.py::test_detail_mapping_growth_during_copy_fails_closed",
                "tests/unit/test_errors.py::test_detail_list_growth_during_copy_fails_closed",
                "tests/unit/test_quality_gate.py::test_git_snapshot_hashes_logical_index_and_refs_without_mutation",
            ),
        )
    if targets == _TASK_NINE_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=(
                "tests/contracts/test_pydantic_contracts.py",
                "tests/property/test_contract_properties.py",
                "tests/unit/test_tools.py",
                (
                    "tests/contracts/test_frozen_baseline.py::"
                    "test_frozen_case_replays_through_parse_and_handle_against_independent_oracle"
                ),
            ),
        )
    if targets == _TASK_TEN_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=("tests/contracts/test_zod_contracts.py",),
        )
    if targets == _TASK_ELEVEN_AND_FOURTEEN_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=(
                "tests/contracts/test_sdk_client.py",
                "tests/contracts/test_sdk_boundary.py",
                "tests/contracts/test_sdk_parity.py",
                "tests/conformance/test_mcp_http.py",
                "tests/unit/test_errors.py",
            ),
            deselected_tests=(
                "tests/unit/test_errors.py::test_detail_mapping_growth_during_copy_fails_closed",
                "tests/unit/test_errors.py::test_detail_list_growth_during_copy_fails_closed",
            ),
        )
    if targets == _TASK_TWELVE_TARGETS:
        return _mutation_policy(
            targets,
            test_paths=("tests/contracts/test_sdk_parity.py",),
        )
    if targets in {
        _TASK_THIRTEEN_TARGETS,
        _TASK_SIXTEEN_A_TARGETS,
        _TASK_SEVENTEEN_TARGETS,
        _TASK_EIGHTEEN_TARGETS,
        _TASK_NINETEEN_TARGETS,
        _TASK_TWENTY_ONE_A_TARGETS,
        _TASK_TWENTY_TWO_TARGETS,
        _TASK_ONE_TARGETS,
    }:
        return _later_task_mutation_policy(targets)
    _fail("mutation request does not match the closed initial policy")


def initial_mutation_policy() -> MutationPolicy:
    """Return Task 7's exact reviewed pinned-mutmut target inventory."""
    return mutation_policy_for_targets(_INITIAL_TARGETS)


@dataclass(frozen=True, slots=True)
class _TargetMetadata:
    exit_codes: dict[object, object]
    hashes: dict[object, object]
    durations: dict[object, object]
    estimates: dict[object, object]


def _validated_target_metadata(payload: bytes) -> _TargetMetadata:
    metadata = _load_meta(payload)
    exit_codes_value = metadata["exit_code_by_key"]
    if type(exit_codes_value) is not dict:
        _fail("mutation target results are malformed")
    values = (
        metadata["hash_by_function_name"],
        metadata["durations_by_key"],
        metadata["estimated_durations_by_key"],
        metadata["type_check_error_by_key"],
    )
    if not all(type(value) is dict for value in values):
        _fail("mutation metadata maps have invalid runtime types")
    hashes_value, durations_value, estimates_value, type_errors_value = values
    type_errors = cast("dict[object, object]", type_errors_value)
    if type_errors:
        _fail("killed-only mutation evidence contains type-check results")
    return _TargetMetadata(
        exit_codes=cast("dict[object, object]", exit_codes_value),
        hashes=cast("dict[object, object]", hashes_value),
        durations=cast("dict[object, object]", durations_value),
        estimates=cast("dict[object, object]", estimates_value),
    )


def _validate_target_support(
    metadata: _TargetMetadata,
    *,
    selected_mutants: frozenset[str],
    generated_local_functions: frozenset[str],
) -> None:
    duration_names_raw = set(metadata.durations)
    estimate_names_raw = set(metadata.estimates)
    hash_names_raw = set(metadata.hashes)
    if any(
        type(name) is not str
        for name in (*duration_names_raw, *estimate_names_raw, *hash_names_raw)
    ):
        _fail("mutation metadata names are malformed")
    duration_names = cast("set[str]", duration_names_raw)
    estimate_names = cast("set[str]", estimate_names_raw)
    hash_names = cast("set[str]", hash_names_raw)
    unexecuted_mutants: set[str] = {
        name
        for name, status in metadata.exit_codes.items()
        if type(name) is str and name in selected_mutants and status == _NO_TESTS_STATUS
    }
    if duration_names != set(
        selected_mutants - unexecuted_mutants
    ) or estimate_names != set(selected_mutants):
        _fail("mutation duration evidence is incomplete")
    if any(
        type(value) is not str or _FUNCTION_HASH.fullmatch(value) is None
        for value in metadata.hashes.values()
    ):
        _fail("mutation function hashes are malformed")
    if hash_names != set(generated_local_functions):
        _fail("mutation function hash evidence is incomplete")
    for value in (*metadata.durations.values(), *metadata.estimates.values()):
        if (
            type(value) not in {int, float}
            or not math.isfinite(cast("int | float", value))
            or cast("int | float", value) < 0
            or cast("int | float", value) > _MAX_MUTANT_DURATION_SECONDS
        ):
            _fail("mutation duration evidence is malformed")


def _parse_target_mutants(
    metadata: _TargetMetadata,
    *,
    target: str,
    policy: MutationPolicy,
    seen_mutants: set[str],
    function_counts: dict[str, int],
) -> tuple[int, int, frozenset[str]]:
    target_module = _TARGET_MODULES[target]
    required_functions = frozenset(dict(policy.required_functions)[target])
    target_count = 0
    killed_count = 0
    target_functions: set[str] = set()
    selected_mutants: set[str] = set()
    generated_local_functions: set[str] = set()
    for name_value, exit_code in metadata.exit_codes.items():
        if type(name_value) is not str:
            _fail("mutation result name is malformed or duplicated")
        name = name_value
        match = _MUTANT_NAME.fullmatch(name)
        if (
            match is None
            or len(name) > _MAX_MUTANT_NAME_CHARACTERS
            or name in seen_mutants
        ):
            _fail("mutation result name is malformed or duplicated")
        function = cast("str", match.group("function"))
        if not function.startswith(f"{target_module}."):
            _fail("mutation result does not belong to its declared target")
        generated_local_functions.add(function.rpartition(".")[2])
        seen_mutants.add(name)
        if function not in required_functions:
            if exit_code is not None:
                _fail("unrequested mutation function; unexpected generated functions")
            continue
        if type(exit_code) is not int or exit_code not in policy.accepted_exit_codes:
            _fail("mutation result has an unaccepted status")
        selected_mutants.add(name)
        target_functions.add(function.removeprefix(f"{target_module}."))
        function_counts[function] = function_counts.get(function, 0) + 1
        target_count += 1
        if exit_code in policy.killed_exit_codes:
            killed_count += 1
    _validate_target_support(
        metadata,
        selected_mutants=frozenset(selected_mutants),
        generated_local_functions=frozenset(generated_local_functions),
    )
    return (
        target_count,
        killed_count,
        frozenset(f"{target_module}.{function}" for function in target_functions),
    )


def parse_mutation_results(
    payloads: tuple[tuple[str, bytes], ...],
) -> MutationSummary:
    """Parse exact pinned-mutmut per-target results."""
    supplied_targets = tuple(target for target, _payload in payloads)
    policy = mutation_policy_for_targets(supplied_targets)
    required = dict(policy.required_functions)
    total = 0
    killed = 0
    seen_mutants: set[str] = set()
    target_counts: list[tuple[str, int]] = []
    function_count_map: dict[str, int] = {}
    for target, payload in payloads:
        metadata = _validated_target_metadata(payload)
        target_required_functions = frozenset(required[target])
        target_count, target_killed, generated_functions = _parse_target_mutants(
            metadata,
            target=target,
            policy=policy,
            seen_mutants=seen_mutants,
            function_counts=function_count_map,
        )
        if generated_functions != target_required_functions:
            _fail(f"mutation target {target} has unexpected generated functions")
        total += target_count
        killed += target_killed
        target_counts.append((target, target_count))

    if killed * 100 < total * policy.minimum_killed_percent:
        _fail("mutation test-failure kill floor was not met")

    return MutationSummary(
        total=total,
        killed=killed,
        target_counts=tuple(target_counts),
        function_counts=tuple(sorted(function_count_map.items())),
    )


def _canonical_worktree(path: Path) -> Path:
    if not path.is_absolute():
        _fail("mutation worktree must be absolute")
    try:
        canonical = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        _fail_from("mutation worktree is unavailable", exc)
    if (
        canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
    ):
        _fail("mutation worktree must be a canonical directory")
    return canonical


def _validate_snapshot_inputs(
    snapshot: SourceSnapshot,
    policy: MutationPolicy,
) -> None:
    records = {record.path: record for record in snapshot.files}
    if "pyproject.toml" not in records or not any(
        path.startswith("tests/") for path in records
    ):
        _fail("mutation snapshot lacks project configuration or tests")
    if "setup.cfg" in records:
        _fail("source setup.cfg would conflict with the external mutation policy")
    if any(target not in records for target in policy.targets):
        _fail("mutation snapshot lacks an exact reviewed target")
    try:
        project = cast(
            "dict[str, object]",
            tomllib.loads(records["pyproject.toml"].payload.decode("utf-8")),
        )
    except ValueError as exc:
        _fail_from("project configuration is malformed", exc)
    tool = project.get("tool", {})
    if type(tool) is not dict:
        _fail("project tool configuration is malformed")
    if "mutmut" in cast("dict[object, object]", tool):
        _fail("source mutmut configuration is forbidden")


def _mutation_configuration(policy: MutationPolicy) -> bytes:
    targets = "\n".join(f"    {target}" for target in policy.targets)
    deselections = "".join(
        f"    --deselect\n    {test}\n" for test in policy.deselected_tests
    )
    test_selection = "".join(f"    {test}\n" for test in policy.test_paths)
    return (
        "[mutmut]\n"
        "source_paths =\n"
        f"{targets}\n"
        "pytest_add_cli_args =\n"
        "    -q\n"
        "    --strict-markers\n"
        "    --strict-config\n"
        "    -p\n"
        "    no:cacheprovider\n"
        f"{deselections}"
        "pytest_add_cli_args_test_selection =\n"
        f"{test_selection}"
        "also_copy =\n"
        "    contracts\n"
        "    docs\n"
        "    pyproject.toml\n"
        "    requirements.in\n"
        "    src/nplg_mcp\n"
        "    scripts\n"
        "    security\n"
        "use_git_change_detection = false\n"
        "use_setproctitle = false\n"
    ).encode()


def _write_private_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    except OSError as exc:
        _fail_from("external mutation policy could not be created", exc)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                _fail("external mutation policy write was incomplete")
            written += count
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
    finally:
        os.close(descriptor)


def _closed_environment(output: Path) -> tuple[tuple[str, str], ...]:
    directories = {
        "HOME": output / "home",
        "TMPDIR": output / "tmp",
        "XDG_CACHE_HOME": output / "cache",
        "PYTHONPYCACHEPREFIX": output / "pycache",
    }
    for directory in directories.values():
        directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
    return tuple(
        sorted(
            {
                **{name: path.as_posix() for name, path in directories.items()},
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "NPLG_PYTHON_ONLY_CONTRACT_GATE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
            }.items()
        )
    )


def _required_mutant_patterns(policy: MutationPolicy) -> tuple[str, ...]:
    """Select exactly the closed function inventory within each target module."""
    return tuple(
        f"{function}__mutmut_*"
        for _target, functions in policy.required_functions
        for function in functions
    )


def _mutation_command(
    workspace: Path,
    output: Path,
    policy: MutationPolicy,
) -> CommandRequest:
    return CommandRequest(
        argv=trusted_mutation_python_command(
            import_roots=(workspace / "src", workspace),
            arguments=(
                "run",
                "--max-children",
                "8",
                *_required_mutant_patterns(policy),
            ),
        ),
        cwd=workspace,
        environment=_closed_environment(output),
        timeout_seconds=1_800.0,
    )


def _validated_command_result(
    executor: Executor,
    request: CommandRequest,
    *,
    clock: Clock,
) -> CommandResult:
    started = clock.monotonic()
    try:
        result = executor(request)
    except (OSError, RuntimeError, ValueError) as exc:
        _fail_from("mutation command failed at the process boundary", exc)
    finished = clock.monotonic()
    if (
        type(started) not in {int, float}
        or type(finished) not in {int, float}
        or not math.isfinite(started)
        or not math.isfinite(finished)
        or finished < started
        or finished - started > request.timeout_seconds
        or type(result) is not CommandResult
        or result.argv != request.argv
        or type(result.returncode) is not int
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > request.stdout_limit_bytes
        or len(result.stderr) > request.stderr_limit_bytes
    ):
        _fail("mutation command evidence is malformed")
    return result


def _read_meta(workspace: Path, relative: str) -> bytes:
    metadata, payload = read_bound_regular_file(
        workspace,
        relative,
        max_bytes=_MAX_META_BYTES,
    )
    if metadata.st_size < 1 or not payload:
        _fail("mutation metadata is empty")
    return payload


def _filesystem_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_bound_directory(path: Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as exc:
        _fail_from("mutation output directory could not be opened safely", exc)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _filesystem_identity(before) != _filesystem_identity(opened)
        or _filesystem_identity(opened) != _filesystem_identity(after)
    ):
        os.close(descriptor)
        _fail("mutation output directory changed during descriptor binding")
    return descriptor


def _open_bound_child(parent: int, name: str, expected: os.stat_result) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
        opened = os.fstat(descriptor)
    except OSError as exc:
        _fail_from("mutation output child directory could not be opened safely", exc)
    if not stat.S_ISDIR(opened.st_mode) or _filesystem_identity(
        expected
    ) != _filesystem_identity(opened):
        os.close(descriptor)
        _fail("mutation output child directory changed during descriptor binding")
    return descriptor


def _inventory_entry_ceiling(snapshot: SourceSnapshot) -> int:
    return max(128, (len(snapshot.files) * 8) + 64)


def _workspace_file_inventory(
    workspace: Path,
    *,
    entry_ceiling: int,
) -> frozenset[str]:
    root = _open_bound_directory(workspace)
    pending = [(root, "")]
    found: set[str] = set()
    visited = 0
    try:
        while pending:
            directory, prefix = pending.pop()
            try:
                with os.scandir(directory) as raw_entries:
                    entries = cast("Iterator[os.DirEntry[str]]", raw_entries)
                    for entry in entries:
                        visited += 1
                        if visited > entry_ceiling:
                            _fail("mutation output exceeds its entry bound")
                        before = entry.stat(follow_symlinks=False)
                        linked = os.stat(
                            entry.name,
                            dir_fd=directory,
                            follow_symlinks=False,
                        )
                        if _filesystem_identity(before) != _filesystem_identity(linked):
                            _fail("mutation output changed during inventory")
                        relative = f"{prefix}/{entry.name}" if prefix else entry.name
                        if stat.S_ISDIR(before.st_mode):
                            if relative == ".git":
                                continue
                            pending.append(
                                (
                                    _open_bound_child(directory, entry.name, before),
                                    relative,
                                )
                            )
                        elif not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                            _fail("mutation output contains a linked or special entry")
                        else:
                            found.add(relative)
            finally:
                os.close(directory)
    finally:
        for directory, _prefix in pending:
            os.close(directory)
    return frozenset(found)


def _meta_inventory(workspace: Path, *, entry_ceiling: int) -> frozenset[str]:
    return frozenset(
        relative
        for relative in _workspace_file_inventory(
            workspace,
            entry_ceiling=entry_ceiling,
        )
        if relative.startswith("mutants/") and relative.endswith(".meta")
    )


def _bound_directory_identity(path: Path) -> tuple[int, int, int, int]:
    descriptor = _open_bound_directory(path)
    try:
        metadata = os.fstat(descriptor)
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
        )
    finally:
        os.close(descriptor)


def _bound_output_layout(
    output: Path,
) -> tuple[tuple[str, tuple[int, int, int, int]], ...]:
    root = _open_bound_directory(output)
    found: dict[str, tuple[int, int, int, int]] = {}
    try:
        with os.scandir(root) as raw_entries:
            entries = cast("Iterator[os.DirEntry[str]]", raw_entries)
            for entry in entries:
                before = entry.stat(follow_symlinks=False)
                linked = os.stat(entry.name, dir_fd=root, follow_symlinks=False)
                if (
                    entry.name not in _OUTPUT_DIRECTORIES
                    or entry.name in found
                    or _filesystem_identity(before) != _filesystem_identity(linked)
                ):
                    _fail("external mutation output layout is not closed")
                child = _open_bound_child(root, entry.name, before)
                try:
                    opened = os.fstat(child)
                    found[entry.name] = (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_mode,
                        opened.st_uid,
                    )
                finally:
                    os.close(child)
    finally:
        os.close(root)
    if found.keys() != _OUTPUT_DIRECTORIES:
        _fail("external mutation output layout is incomplete")
    return tuple(sorted(found.items()))


def _require_directory_identity(
    path: Path,
    expected: tuple[int, int, int, int],
) -> None:
    if _bound_directory_identity(path) != expected:
        _fail("external mutation directory was renamed or replaced")


def _require_output_layout(
    output: Path,
    expected: tuple[tuple[str, tuple[int, int, int, int]], ...],
) -> None:
    if _bound_output_layout(output) != expected:
        _fail("external mutation output layout changed")


def _validate_workspace_inputs(workspace: Path, snapshot: SourceSnapshot) -> None:
    expected = frozenset(("setup.cfg", *(record.path for record in snapshot.files)))
    actual = frozenset(
        relative
        for relative in _workspace_file_inventory(
            workspace,
            entry_ceiling=_inventory_entry_ceiling(snapshot),
        )
        if not relative.startswith("mutants/")
    )
    if actual != expected:
        _fail("external mutation workspace has an unexpected input")


def _exact_meta_payloads(
    workspace: Path,
    policy: MutationPolicy,
    *,
    entry_ceiling: int,
) -> tuple[tuple[str, bytes], ...]:
    expected = frozenset(f"mutants/{target}.meta" for target in policy.targets)
    if _meta_inventory(workspace, entry_ceiling=entry_ceiling) != expected:
        _fail("mutation metadata filenames do not exactly match the policy")
    payloads = tuple(
        (target, _read_meta(workspace, f"mutants/{target}.meta"))
        for target in policy.targets
    )
    if _meta_inventory(workspace, entry_ceiling=entry_ceiling) != expected:
        _fail("mutation metadata inventory changed while being read")
    return payloads


def _release_mode(request: MutationGateRequest, policy: MutationPolicy) -> bool:
    if (
        type(request) is not MutationGateRequest
        or not isinstance(cast("object", request.worktree), Path)
        or request.targets != policy.targets
        or type(cast("object", request.require_clean)) is not bool
        or (
            request.output_dir is not None
            and not isinstance(cast("object", request.output_dir), Path)
        )
    ):
        _fail("mutation request does not match the closed initial policy")
    release_mode = request.require_clean and request.candidate is not None
    if request.require_clean != (request.candidate is not None):
        _fail("release mutation mode requires both clean and candidate controls")
    if request.candidate is not None and (
        type(request.candidate) is not str
        or len(request.candidate) > _MAX_REF_BYTES
        or _GIT_OBJECT.fullmatch(request.candidate) is None
    ):
        _fail("mutation candidate is not an exact Git object name")
    return release_mode


def _capture_release_evidence(
    git: Git,
    *,
    root: Path,
    release_mode: bool,
) -> ReleaseGitEvidence | None:
    if not release_mode:
        return None
    return release_git_evidence(git, root=root)


def _validate_release_tree(
    evidence: ReleaseGitEvidence | None,
    *,
    candidate: str | None,
    materialized_tree: str,
) -> None:
    if evidence is not None and (
        evidence.commit != candidate or evidence.tree != materialized_tree
    ):
        _fail("release mutation snapshot is not the exact candidate tree")


def _validate_release_evidence_unchanged(
    before: ReleaseGitEvidence | None,
    after: ReleaseGitEvidence | None,
) -> None:
    if before != after:
        _fail("release mutation execution changed raw Git evidence")


def _execute_external_mutation(
    *,
    workspace: Path,
    source_snapshot: SourceSnapshot,
    policy: MutationPolicy,
    executor: Executor,
    clock: Clock,
) -> MutationSummary:
    output = workspace.parent
    entry_ceiling = _inventory_entry_ceiling(source_snapshot)
    expected_configuration = _mutation_configuration(policy)
    _write_private_file(workspace / "setup.cfg", expected_configuration)
    configuration = stable_snapshot_file(workspace, "setup.cfg")
    if (
        configuration.payload != expected_configuration
        or configuration.mode != _PRIVATE_FILE_MODE
    ):
        _fail("external mutation policy does not match the closed configuration")
    _validate_workspace_inputs(workspace, source_snapshot)
    command = _mutation_command(workspace, output, policy)
    output_identity = _bound_directory_identity(output)
    workspace_identity = _bound_directory_identity(workspace)
    output_layout = _bound_output_layout(output)
    _ = _validated_command_result(executor, command, clock=clock)
    _require_directory_identity(output, output_identity)
    _require_directory_identity(workspace, workspace_identity)
    _require_output_layout(output, output_layout)
    _validate_workspace_inputs(workspace, source_snapshot)
    payloads = _exact_meta_payloads(
        workspace,
        policy,
        entry_ceiling=entry_ceiling,
    )
    summary = parse_mutation_results(payloads)
    if (
        _exact_meta_payloads(
            workspace,
            policy,
            entry_ceiling=entry_ceiling,
        )
        != payloads
    ):
        _fail("mutation metadata bytes changed after validation")
    if stable_snapshot_file(workspace, "setup.cfg") != configuration:
        _fail("external mutation policy changed during execution")
    _require_directory_identity(output, output_identity)
    _require_directory_identity(workspace, workspace_identity)
    _require_output_layout(output, output_layout)
    _validate_workspace_inputs(workspace, source_snapshot)
    return summary


def run_mutation_gate(
    request: MutationGateRequest,
    *,
    executor: Executor,
    clock: Clock,
    filesystem: Filesystem,
    git: Git,
) -> MutationGateResult:
    """Run mutation testing only in an external disposable workspace."""
    del filesystem
    if type(request) is not MutationGateRequest:
        _fail("mutation request does not match the closed initial policy")
    policy = mutation_policy_for_targets(request.targets)
    release_mode = _release_mode(request, policy)

    root = _canonical_worktree(request.worktree)
    before_repository = repository_evidence(git, root=root)
    before_release = _capture_release_evidence(
        git,
        root=root,
        release_mode=release_mode,
    )
    if release_mode and (
        not before_repository.clean or request.candidate != before_repository.head
    ):
        _fail("release mutation source is not the clean exact candidate")
    worktrees = registered_worktrees(git, root=root)
    before_snapshot = capture_source_snapshot(git, root=root)
    reject_mutation_tool_shadows(before_snapshot)
    _validate_snapshot_inputs(before_snapshot, policy)
    output, temporary = create_external_output(
        request.output_dir,
        registered_worktrees=worktrees,
    )
    succeeded = False
    try:
        materialized = materialize_snapshot(
            root,
            before_snapshot,
            merge_base=before_repository.head,
            output=output,
            git=git,
        )
        binding = bind_external_snapshot(
            git,
            materialized=materialized,
            source_snapshot=before_snapshot,
        )
        _validate_release_tree(
            before_release,
            candidate=request.candidate,
            materialized_tree=binding.tree,
        )
        summary = _execute_external_mutation(
            workspace=materialized.root,
            source_snapshot=before_snapshot,
            policy=policy,
            executor=executor,
            clock=clock,
        )
        _ = bind_external_snapshot(
            git,
            materialized=materialized,
            source_snapshot=before_snapshot,
        )
        after_snapshot = capture_source_snapshot(git, root=root)
        after_repository = repository_evidence(git, root=root)
        after_release = _capture_release_evidence(
            git,
            root=root,
            release_mode=release_mode,
        )
        _validate_release_evidence_unchanged(before_release, after_release)
        if after_snapshot != before_snapshot or after_repository != before_repository:
            _fail("mutation execution changed the source snapshot or Git state")
        succeeded = True
        return MutationGateResult(summary=summary, output_dir=output)
    finally:
        if temporary or not succeeded:
            shutil.rmtree(output, ignore_errors=True)


def parse_arguments(argv: Sequence[str] | None = None) -> MutationGateRequest:
    """Parse the closed mutation-gate command-line contract."""
    parser = argparse.ArgumentParser(
        description="Run the externally contained NPLG mutation gate.",
        allow_abbrev=False,
    )
    _ = parser.add_argument("--worktree", type=Path, default=Path.cwd())
    _ = parser.add_argument("--output-dir", type=Path)
    _ = parser.add_argument("--require-clean", action="store_true")
    _ = parser.add_argument("--candidate")
    _ = parser.add_argument("--targets", nargs="+", required=True)
    values = cast("dict[str, object]", vars(parser.parse_args(argv)))
    return MutationGateRequest(
        worktree=cast("Path", values["worktree"]),
        output_dir=cast("Path | None", values["output_dir"]),
        targets=tuple(cast("list[str]", values["targets"])),
        require_clean=cast("bool", values["require_clean"]),
        candidate=cast("str | None", values["candidate"]),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the mutation gate through the shared production adapters."""
    result = run_mutation_gate(
        parse_arguments(argv),
        executor=SystemExecutor(),
        clock=SystemClock(),
        filesystem=SystemFilesystem(),
        git=SystemGit(),
    )
    stdout = cast("TextIO", sys.stdout)
    _ = stdout.write(
        f"mutation gate passed: {result.summary.killed}/{result.summary.total} killed\n"
    )
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    """Render one bounded process-facing error without a traceback."""
    try:
        return main(argv)
    except MutationGateError as error:
        stderr = cast("TextIO", sys.stderr)
        _ = stderr.write("mutation gate failed: " + str(error) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
