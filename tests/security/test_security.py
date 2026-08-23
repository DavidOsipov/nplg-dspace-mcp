# Copyright (c) 2026 David Osipov
"""Adversarial tests for network and admission security."""

import ipaddress
import socket
from http import HTTPStatus
from typing import Unpack
from urllib.parse import SplitResult

import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.security import (
    NPLG_HOST,
    DnsAnswer,
    ResolverOptions,
    build_item_url,
    is_forbidden_address,
    parse_handle_input,
    resolve_approved_addresses,
    validate_upstream_url,
)

_HTTPS_PORT = 443
_PRIVATE_RESOLVER_DETAIL = "private resolver detail"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1234/560975", "1234/560975"),
        ("/handle/1234/560975", "1234/560975"),
        ("https://dspace.nplg.gov.ge/handle/1234/560975", "1234/560975"),
        ("https://dspace.nplg.gov.ge/handle/1234/560975?mode=full", "1234/560975"),
    ],
)
def test_handle_inputs_are_canonicalized(value: str, expected: str) -> None:
    assert parse_handle_input(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "1234",
        "1234/abc",
        "../../etc/passwd",
        "https://example.com/handle/1234/560975",
        "https://dspace.nplg.gov.ge.evil.test/handle/1234/560975",
        "https://dspace.nplg.gov.ge@evil.test/handle/1234/560975",
        "https://dspace.nplg.gov.ge:444/handle/1234/560975",
        "https://dspace.nplg.gov.ge:not-a-port/handle/1234/560975",
        "https://dspace.nplg.gov.ge/%2f%2fevil.test/handle/1234/560975",
        "/handle/1234/560975?unexpected=true",
    ],
)
def test_invalid_handle_inputs_fail_closed(value: str) -> None:
    with pytest.raises(AppError) as raised:
        _ = parse_handle_input(value)
    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_item_url_builder_never_accepts_path_syntax() -> None:
    assert (
        build_item_url("1234/560975") == "https://dspace.nplg.gov.ge/handle/1234/560975"
    )
    assert build_item_url("1234/560975", full=True).endswith("?mode=full")
    with pytest.raises(AppError):
        _ = build_item_url("1234/560975/../../admin")


@pytest.mark.parametrize(
    "url",
    [
        "https://dspace.nplg.gov.ge/simple-search?query=ივერია",
        "https://dspace.nplg.gov.ge/oai/request?verb=Identify",
        "https://dspace.nplg.gov.ge/handle/1234/560975",
        "https://dspace.nplg.gov.ge/bitstream/1234/560975/1/file.pdf",
    ],
)
def test_allowed_upstream_urls_remain_on_exact_origin(url: str) -> None:
    assert validate_upstream_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://dspace.nplg.gov.ge/handle/1234/1",
        "https://example.com/handle/1234/1",
        "https://dspace.nplg.gov.ge:8443/handle/1234/1",
        "https://user@dspace.nplg.gov.ge/handle/1234/1",
        "https://dspace.nplg.gov.ge/robots.txt",
        "https://dspace.nplg.gov.ge/handle/1234/1#fragment",
        "https://dspace.nplg.gov.ge\\@evil.test/handle/1234/1",
        "https://dspace.nplg.gov.ge%2eevil.test/handle/1234/1",
    ],
)
def test_foreign_or_unexpected_upstream_urls_are_rejected(url: str) -> None:
    with pytest.raises(AppError) as raised:
        _ = validate_upstream_url(url)
    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "url",
    [
        " https://dspace.nplg.gov.ge/handle/1234/1",
        "https://dspace.nplg.gov.ge/bitstream/1234/1/../../admin",
        "https://dspace.nplg.gov.ge/bitstream/1234/1/%2e%2e/admin",
        "https://dspace.nplg.gov.ge/bitstream/1234/1/%2Fadmin",
        "https://dspace.nplg.gov.ge/bitstream/1234/1/%5cadmin",
        "https://dspace.nplg.gov.ge/bitstream/1234/1/file%00.pdf",
        "https://dspace.nplg.gov.ge/bitstream/1234/1/file%zz.pdf",
    ],
)
def test_upstream_paths_reject_http_client_canonicalization_ambiguities(
    url: str,
) -> None:
    with pytest.raises(AppError) as raised:
        _ = validate_upstream_url(url)
    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        0,
        "::1",
        "fc00::1",
        "fe80::1",
        "192.0.2.10",
    ],
)
def test_non_global_addresses_are_forbidden(value: str | int) -> None:
    assert is_forbidden_address(ipaddress.ip_address(value)) is True


@pytest.mark.parametrize(
    "value",
    [
        "::ffff:8.8.8.8",
        "2606:4700:4700::1111%eth0",
    ],
)
def test_special_form_ipv6_addresses_are_forbidden(value: str) -> None:
    """Mutation caught: treating mapped or scoped global IPv6 as public."""
    assert is_forbidden_address(ipaddress.ip_address(value)) is True


def test_global_addresses_are_allowed() -> None:
    assert is_forbidden_address(ipaddress.ip_address("1.1.1.1")) is False
    assert is_forbidden_address(ipaddress.ip_address("2606:4700:4700::1111")) is False


def test_handle_path_fails_closed_if_url_parser_reports_an_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def inconsistent_urlsplit(_value: str) -> SplitResult:
        return SplitResult(
            scheme="https",
            netloc="dspace.nplg.gov.ge",
            path="/handle/1234/560975",
            query="",
            fragment="",
        )

    monkeypatch.setattr("nplg_mcp.security.urlsplit", inconsistent_urlsplit)

    with pytest.raises(AppError, match="malformed"):
        _ = parse_handle_input("/handle/1234/560975")


def test_default_resolver_uses_stream_tcp_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int, int, int]] = []

    def getaddrinfo(
        host: str,
        port: int,
        **options: Unpack[ResolverOptions],
    ) -> list[DnsAnswer]:
        calls.append((host, port, options["type"], options["proto"]))
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("1.1.1.1", port),
            )
        ]

    monkeypatch.setattr("nplg_mcp.security.socket.getaddrinfo", getaddrinfo)

    assert resolve_approved_addresses(NPLG_HOST) == ("1.1.1.1",)
    assert calls == [(NPLG_HOST, _HTTPS_PORT, socket.SOCK_STREAM, socket.IPPROTO_TCP)]


def test_dns_resolution_rejects_any_other_hostname_before_lookup() -> None:
    def unexpected_resolver(
        host: str,
        port: int,
        **options: Unpack[ResolverOptions],
    ) -> list[DnsAnswer]:
        del host, port, options
        pytest.fail("resolver must not be called for an unapproved hostname")

    with pytest.raises(AppError, match="only for the NPLG host"):
        _ = resolve_approved_addresses("example.com", resolver=unexpected_resolver)


def test_dns_resolution_maps_resolver_failure_to_public_upstream_error() -> None:
    def failing_resolver(
        host: str,
        port: int,
        **options: Unpack[ResolverOptions],
    ) -> list[DnsAnswer]:
        del host, port, options
        message = _PRIVATE_RESOLVER_DETAIL
        raise OSError(message)

    with pytest.raises(AppError) as captured:
        _ = resolve_approved_addresses(NPLG_HOST, resolver=failing_resolver)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE
    assert captured.value.http_status == HTTPStatus.BAD_GATEWAY
    assert _PRIVATE_RESOLVER_DETAIL not in captured.value.message


def test_dns_resolution_rejects_invalid_address_text() -> None:
    def resolver(
        host: str,
        port: int,
        **options: Unpack[ResolverOptions],
    ) -> list[DnsAnswer]:
        del host, options
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("not-an-address", port),
            )
        ]

    with pytest.raises(AppError, match="invalid network address") as captured:
        _ = resolve_approved_addresses(NPLG_HOST, resolver=resolver)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE


def test_dns_resolution_rejects_an_empty_answer_set() -> None:
    def resolver(
        host: str,
        port: int,
        **options: Unpack[ResolverOptions],
    ) -> list[DnsAnswer]:
        del host, port, options
        return []

    with pytest.raises(AppError, match="no usable addresses") as captured:
        _ = resolve_approved_addresses(NPLG_HOST, resolver=resolver)

    assert captured.value.code is ErrorCode.UPSTREAM_FAILURE


def test_dns_resolution_fails_if_any_answer_is_not_global() -> None:
    def resolver(host: str, port: int, **_: Unpack[ResolverOptions]) -> list[DnsAnswer]:
        assert host == NPLG_HOST
        assert port == _HTTPS_PORT
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("1.1.1.1", _HTTPS_PORT),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", _HTTPS_PORT),
            ),
        ]

    with pytest.raises(AppError, match="non-public"):
        _ = resolve_approved_addresses(NPLG_HOST, resolver=resolver)


def test_dns_resolution_rejects_deprecated_ipv6_site_local_address() -> None:
    def resolver(host: str, port: int, **_: Unpack[ResolverOptions]) -> list[DnsAnswer]:
        assert host == NPLG_HOST
        assert port == _HTTPS_PORT
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("fec0::1", _HTTPS_PORT, 0, 0),
            )
        ]

    with pytest.raises(AppError, match="non-public"):
        _ = resolve_approved_addresses(NPLG_HOST, resolver=resolver)


def test_dns_resolution_returns_deduplicated_global_addresses() -> None:
    def resolver(host: str, port: int, **_: Unpack[ResolverOptions]) -> list[DnsAnswer]:
        assert host == NPLG_HOST
        assert port == _HTTPS_PORT
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("1.1.1.1", _HTTPS_PORT),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("1.1.1.1", _HTTPS_PORT),
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2606:4700:4700::1111", _HTTPS_PORT, 0, 0),
            ),
        ]

    assert resolve_approved_addresses(NPLG_HOST, resolver=resolver) == (
        "1.1.1.1",
        "2606:4700:4700::1111",
    )
