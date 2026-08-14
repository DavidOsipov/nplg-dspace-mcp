import ipaddress
import socket

import pytest

from nplg_mcp.errors import AppError, ErrorCode
from nplg_mcp.security import (
    NPLG_HOST,
    build_item_url,
    is_forbidden_address,
    parse_handle_input,
    resolve_approved_addresses,
    validate_upstream_url,
)


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
        "https://dspace.nplg.gov.ge/%2f%2fevil.test/handle/1234/560975",
    ],
)
def test_invalid_handle_inputs_fail_closed(value: str) -> None:
    with pytest.raises(AppError) as raised:
        parse_handle_input(value)
    assert raised.value.code is ErrorCode.INVALID_INPUT


def test_item_url_builder_never_accepts_path_syntax() -> None:
    assert build_item_url("1234/560975") == "https://dspace.nplg.gov.ge/handle/1234/560975"
    assert build_item_url("1234/560975", full=True).endswith("?mode=full")
    with pytest.raises(AppError):
        build_item_url("1234/560975/../../admin")


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
        validate_upstream_url(url)
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
    ],
)
def test_upstream_paths_reject_http_client_canonicalization_ambiguities(url: str) -> None:
    with pytest.raises(AppError) as raised:
        validate_upstream_url(url)
    assert raised.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "192.0.2.10",
    ],
)
def test_non_global_addresses_are_forbidden(value: str) -> None:
    assert is_forbidden_address(ipaddress.ip_address(value)) is True


def test_global_addresses_are_allowed() -> None:
    assert is_forbidden_address(ipaddress.ip_address("1.1.1.1")) is False
    assert is_forbidden_address(ipaddress.ip_address("2606:4700:4700::1111")) is False


def test_dns_resolution_fails_if_any_answer_is_not_global() -> None:
    def resolver(host: str, port: int, **_: object):
        assert host == NPLG_HOST
        assert port == 443
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]

    with pytest.raises(AppError, match="non-public"):
        resolve_approved_addresses(NPLG_HOST, resolver=resolver)


def test_dns_resolution_returns_deduplicated_global_addresses() -> None:
    def resolver(host: str, port: int, **_: object):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
        ]

    assert resolve_approved_addresses(NPLG_HOST, resolver=resolver) == (
        "1.1.1.1",
        "2606:4700:4700::1111",
    )
