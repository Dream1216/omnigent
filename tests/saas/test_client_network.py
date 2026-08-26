from __future__ import annotations

from collections.abc import Sequence

import pytest
from starlette.requests import Request

from saas.control_plane.client_network import (
    ClientNetworkUnavailableError,
    TrustedClientNetworkConfig,
    TrustedClientNetworkResolver,
)


def _request(
    peer: str | None,
    headers: Sequence[tuple[bytes, bytes]] = (),
) -> Request:
    client = None if peer is None else (peer, 443)
    return Request(
        {
            "type": "http",
            "asgi": {"spec_version": "2.3", "version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "root_path": "",
            "headers": list(headers),
            "client": client,
            "server": ("testserver", 443),
        }
    )


def _resolver(
    *,
    trusted_proxy_cidrs: tuple[str, ...] = ("10.0.0.0/8",),
    ipv4_prefix_length: int = 24,
    ipv6_prefix_length: int = 64,
    max_forwarded_hops: int = 8,
) -> TrustedClientNetworkResolver:
    return TrustedClientNetworkResolver(
        TrustedClientNetworkConfig(
            trusted_proxy_cidrs=trusted_proxy_cidrs,
            ipv4_prefix_length=ipv4_prefix_length,
            ipv6_prefix_length=ipv6_prefix_length,
            max_forwarded_hops=max_forwarded_hops,
        )
    )


def test_untrusted_peer_ignores_all_forwarding_headers() -> None:
    request = _request(
        "198.51.100.77",
        (
            (b"forwarded", b"for=not-an-address"),
            (b"x-forwarded-for", b"203.0.113.8"),
        ),
    )

    assert _resolver().resolve(request) == "client-network:ipv4:198.51.100.0/24"


@pytest.mark.parametrize(
    ("header", "value"),
    (
        (b"x-forwarded-for", b"198.51.100.45, 10.1.2.3"),
        (
            b"forwarded",
            b'for="198.51.100.45:47011";proto=https;host="api.example.com:443", '
            b"for=10.1.2.3;by=10.1.2.4",
        ),
    ),
)
def test_trusted_proxy_chain_stops_at_first_untrusted_address(
    header: bytes,
    value: bytes,
) -> None:
    request = _request("10.2.3.4", ((header, value),))

    assert _resolver().resolve(request) == "client-network:ipv4:198.51.100.0/24"


def test_untrusted_prefix_left_of_actual_client_cannot_override_subject() -> None:
    request = _request(
        "10.2.3.4",
        ((b"x-forwarded-for", b"192.0.2.200, 198.51.100.45, 10.1.2.3"),),
    )

    assert _resolver().resolve(request) == "client-network:ipv4:198.51.100.0/24"


@pytest.mark.parametrize(
    "headers",
    (
        (),
        ((b"forwarded", b"for=198.51.100.10"), (b"x-forwarded-for", b"198.51.100.10")),
        ((b"x-forwarded-for", b"198.51.100.10"), (b"x-forwarded-for", b"198.51.100.11")),
    ),
)
def test_trusted_peer_requires_exactly_one_unambiguous_header(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    with pytest.raises(ClientNetworkUnavailableError, match=r"^client network unavailable$"):
        _resolver().resolve(_request("10.2.3.4", headers))


@pytest.mark.parametrize(
    ("header", "value"),
    (
        (b"x-forwarded-for", b"unknown"),
        (b"x-forwarded-for", b"example.com"),
        (b"x-forwarded-for", b"[198.51.100.10]"),
        (b"x-forwarded-for", b"198.51.100.10,,10.1.2.3"),
        (b"forwarded", b"for=_hidden"),
        (b"forwarded", b"for=unknown"),
        (b"forwarded", b"for=198.51.100.10;for=198.51.100.11"),
        (b"forwarded", b"proto=https"),
        (b"forwarded", b'for="[2001:db8::1]'),
    ),
)
def test_invalid_or_ambiguous_values_fail_with_generic_error(
    header: bytes,
    value: bytes,
) -> None:
    with pytest.raises(ClientNetworkUnavailableError) as raised:
        _resolver().resolve(_request("10.2.3.4", ((header, value),)))

    assert str(raised.value) == "client network unavailable"
    assert raised.value.__cause__ is None
    assert value.decode("ascii") not in str(raised.value)


def test_forwarded_hop_cap_is_enforced() -> None:
    request = _request(
        "10.2.3.4",
        ((b"x-forwarded-for", b"198.51.100.10, 10.1.1.1, 10.1.1.2"),),
    )

    with pytest.raises(ClientNetworkUnavailableError):
        _resolver(max_forwarded_hops=2).resolve(request)


def test_all_trusted_chain_has_no_resolvable_client() -> None:
    request = _request(
        "10.2.3.4",
        ((b"x-forwarded-for", b"10.1.1.1, 10.1.1.2"),),
    )

    with pytest.raises(ClientNetworkUnavailableError):
        _resolver().resolve(request)


def test_quoted_bracketed_ipv6_and_trusted_ipv6_proxy_chain() -> None:
    request = _request(
        "2001:db8:ffff::10",
        (
            (
                b"forwarded",
                b'for="[2001:db8:1234:5678::cafe]:443";proto=https, for="[2001:db8:ffff::9]"',
            ),
        ),
    )

    assert (
        _resolver(
            trusted_proxy_cidrs=("2001:db8:ffff::/48",),
        ).resolve(request)
        == "client-network:ipv6:2001:db8:1234:5678::/64"
    )


def test_network_prefixes_are_configurable_and_ipv4_mapped_is_canonical() -> None:
    assert (
        _resolver(ipv4_prefix_length=20).resolve(_request("::ffff:198.51.100.77"))
        == "client-network:ipv4:198.51.96.0/20"
    )
    assert (
        _resolver(trusted_proxy_cidrs=(), ipv6_prefix_length=56).resolve(
            _request("2001:db8:abcd:12::9")
        )
        == "client-network:ipv6:2001:db8:abcd::/56"
    )


def test_configuration_is_canonical_immutable_and_validated() -> None:
    configured = TrustedClientNetworkConfig(
        trusted_proxy_cidrs=["10.0.0.0/8"],  # type: ignore[arg-type]
    )
    assert configured.trusted_proxy_cidrs == ("10.0.0.0/8",)

    with pytest.raises((AttributeError, TypeError)):
        configured.trusted_proxy_cidrs += ("192.0.2.0/24",)
    with pytest.raises(ValueError):
        TrustedClientNetworkConfig(trusted_proxy_cidrs=("10.1.0.1/8",))
    with pytest.raises(ValueError):
        TrustedClientNetworkConfig(trusted_proxy_cidrs=("0.0.0.0/0",))
    with pytest.raises(ValueError):
        TrustedClientNetworkConfig(ipv4_prefix_length=33)
    with pytest.raises(ValueError):
        TrustedClientNetworkConfig(ipv4_prefix_length="24")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        TrustedClientNetworkConfig(ipv6_prefix_length=0)
    with pytest.raises(ValueError):
        TrustedClientNetworkConfig(max_forwarded_hops=0)


def test_missing_or_invalid_transport_peer_fails_closed() -> None:
    with pytest.raises(ClientNetworkUnavailableError):
        _resolver().resolve(_request(None))
    with pytest.raises(ClientNetworkUnavailableError):
        _resolver().resolve(_request("not-an-address"))
