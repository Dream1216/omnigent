"""Trusted transport-derived client network subjects for public HTTP controls."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import ClassVar, TypeAlias

from starlette.requests import Request

_IPAddress: TypeAlias = IPv4Address | IPv6Address
_IPNetwork: TypeAlias = IPv4Network | IPv6Network

_FORWARDED_HEADER = b"forwarded"
_X_FORWARDED_FOR_HEADER = b"x-forwarded-for"
_MAX_HEADER_BYTES = 8192
_TOKEN_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class ClientNetworkUnavailableError(RuntimeError):
    """Raised when a trustworthy client network cannot be resolved."""

    code: ClassVar[str] = "client_network_unavailable"

    def __init__(self) -> None:
        super().__init__("client network unavailable")


@dataclass(frozen=True, slots=True)
class TrustedClientNetworkConfig:
    """Immutable proxy trust and client-network bucketing policy."""

    trusted_proxy_cidrs: tuple[str, ...] = ()
    ipv4_prefix_length: int = 24
    ipv6_prefix_length: int = 64
    max_forwarded_hops: int = 8
    _trusted_proxy_networks: tuple[_IPNetwork, ...] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if type(self.ipv4_prefix_length) is not int or not 1 <= self.ipv4_prefix_length <= 32:
            raise ValueError("IPv4 prefix length must be between 1 and 32")
        if type(self.ipv6_prefix_length) is not int or not 1 <= self.ipv6_prefix_length <= 128:
            raise ValueError("IPv6 prefix length must be between 1 and 128")
        if type(self.max_forwarded_hops) is not int or not 1 <= self.max_forwarded_hops <= 32:
            raise ValueError("forwarded hop limit must be between 1 and 32")

        try:
            if isinstance(self.trusted_proxy_cidrs, str):
                raise TypeError
            configured_cidrs = tuple(self.trusted_proxy_cidrs)
        except TypeError as error:
            raise ValueError("trusted proxy CIDRs must be an immutable sequence") from error
        networks: list[_IPNetwork] = []
        try:
            for cidr in configured_cidrs:
                if not isinstance(cidr, str) or not cidr:
                    raise ValueError
                network = ip_network(cidr, strict=True)
                if network.prefixlen == 0 or network in networks:
                    raise ValueError
                networks.append(network)
        except ValueError as error:
            raise ValueError("trusted proxy CIDRs must be unique canonical networks") from error

        object.__setattr__(
            self,
            "trusted_proxy_cidrs",
            tuple(network.with_prefixlen for network in networks),
        )
        object.__setattr__(self, "_trusted_proxy_networks", tuple(networks))


class TrustedClientNetworkResolver:
    """Resolve a bounded network subject from an ASGI transport peer."""

    def __init__(self, config: TrustedClientNetworkConfig) -> None:
        self._config = config

    def resolve(self, request: Request) -> str:
        """Return a canonical network prefix without exposing raw header values."""

        direct_peer = _transport_peer(request)
        if not self._is_trusted_proxy(direct_peer):
            return self._network_subject(direct_peer)

        forwarded_values = _header_values(request, _FORWARDED_HEADER)
        x_forwarded_for_values = _header_values(request, _X_FORWARDED_FOR_HEADER)
        if len(forwarded_values) + len(x_forwarded_for_values) != 1 or (
            forwarded_values and x_forwarded_for_values
        ):
            raise ClientNetworkUnavailableError

        if forwarded_values:
            chain = _parse_forwarded(forwarded_values[0])
        else:
            chain = _parse_x_forwarded_for(x_forwarded_for_values[0])
        if not chain or len(chain) > self._config.max_forwarded_hops:
            raise ClientNetworkUnavailableError

        for address in reversed(chain):
            if not self._is_trusted_proxy(address):
                return self._network_subject(address)
        raise ClientNetworkUnavailableError

    def _is_trusted_proxy(self, address: _IPAddress) -> bool:
        return any(
            address.version == network.version and address in network
            for network in self._config._trusted_proxy_networks
        )

    def _network_subject(self, address: _IPAddress) -> str:
        if isinstance(address, IPv4Address):
            prefix_length = self._config.ipv4_prefix_length
            family = "ipv4"
        else:
            prefix_length = self._config.ipv6_prefix_length
            family = "ipv6"
        network = ip_network(f"{address}/{prefix_length}", strict=False)
        return f"client-network:{family}:{network.with_prefixlen}"


def _transport_peer(request: Request) -> _IPAddress:
    try:
        client = request.client
        if client is None or not isinstance(client.host, str):
            raise ClientNetworkUnavailableError
        return _parse_ip(client.host)
    except (AttributeError, TypeError, ValueError):
        raise ClientNetworkUnavailableError from None


def _header_values(request: Request, name: bytes) -> tuple[str, ...]:
    raw_headers = request.scope.get("headers")
    if not isinstance(raw_headers, list):
        raise ClientNetworkUnavailableError

    values: list[str] = []
    for raw_header in raw_headers:
        if not isinstance(raw_header, tuple) or len(raw_header) != 2:
            raise ClientNetworkUnavailableError
        raw_name, raw_value = raw_header
        if not isinstance(raw_name, bytes) or not isinstance(raw_value, bytes):
            raise ClientNetworkUnavailableError
        if raw_name.lower() != name:
            continue
        if len(raw_value) > _MAX_HEADER_BYTES:
            raise ClientNetworkUnavailableError
        try:
            value = raw_value.decode("ascii")
        except UnicodeDecodeError:
            raise ClientNetworkUnavailableError from None
        if not value or _contains_unsafe_control(value):
            raise ClientNetworkUnavailableError
        values.append(value)
    return tuple(values)


def _parse_forwarded(value: str) -> tuple[_IPAddress, ...]:
    elements = _split_quoted(value, ",")
    addresses: list[_IPAddress] = []
    for element in elements:
        parameters = _split_quoted(element, ";")
        seen_names: set[str] = set()
        forwarded_for: str | None = None
        for parameter in parameters:
            name, separator, raw_parameter_value = parameter.strip().partition("=")
            normalized_name = name.casefold()
            if (
                not separator
                or not _TOKEN_PATTERN.fullmatch(name)
                or normalized_name in seen_names
            ):
                raise ClientNetworkUnavailableError
            seen_names.add(normalized_name)
            parameter_value, was_quoted = _parameter_value(raw_parameter_value.strip())
            if normalized_name == "for":
                forwarded_for = parameter_value
            elif not was_quoted and not _TOKEN_PATTERN.fullmatch(parameter_value):
                raise ClientNetworkUnavailableError
        if forwarded_for is None:
            raise ClientNetworkUnavailableError
        addresses.append(_parse_forwarded_node(forwarded_for))
    return tuple(addresses)


def _parse_x_forwarded_for(value: str) -> tuple[_IPAddress, ...]:
    raw_nodes = value.split(",")
    if not raw_nodes or any(not node.strip() for node in raw_nodes):
        raise ClientNetworkUnavailableError
    return tuple(_parse_x_forwarded_for_node(node.strip()) for node in raw_nodes)


def _split_quoted(value: str, delimiter: str) -> tuple[str, ...]:
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if quoted and character == "\\":
            current.append(character)
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            current.append(character)
            continue
        if character == delimiter and not quoted:
            part = "".join(current).strip()
            if not part:
                raise ClientNetworkUnavailableError
            parts.append(part)
            current = []
            continue
        current.append(character)
    if quoted or escaped:
        raise ClientNetworkUnavailableError
    part = "".join(current).strip()
    if not part:
        raise ClientNetworkUnavailableError
    parts.append(part)
    return tuple(parts)


def _parameter_value(value: str) -> tuple[str, bool]:
    if not value:
        raise ClientNetworkUnavailableError
    if not value.startswith('"'):
        if '"' in value:
            raise ClientNetworkUnavailableError
        return value, False
    if len(value) < 2 or not value.endswith('"'):
        raise ClientNetworkUnavailableError

    unquoted: list[str] = []
    escaped = False
    for character in value[1:-1]:
        if escaped:
            unquoted.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            raise ClientNetworkUnavailableError
        else:
            unquoted.append(character)
    if escaped or not unquoted:
        raise ClientNetworkUnavailableError
    return "".join(unquoted), True


def _parse_forwarded_node(value: str) -> _IPAddress:
    normalized = value.casefold()
    if normalized == "unknown" or value.startswith("_"):
        raise ClientNetworkUnavailableError
    if value.startswith("["):
        address, suffix = _bracketed_address(value)
        _validate_optional_port(suffix)
        if not isinstance(address, IPv6Address):
            raise ClientNetworkUnavailableError
        return address
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        address = _parse_ip(host)
        if not isinstance(address, IPv4Address):
            raise ClientNetworkUnavailableError
        _validate_port(port)
        return address
    address = _parse_ip(value)
    if isinstance(address, IPv6Address):
        raise ClientNetworkUnavailableError
    return address


def _parse_x_forwarded_for_node(value: str) -> _IPAddress:
    normalized = value.casefold()
    if normalized == "unknown" or value.startswith("_") or '"' in value:
        raise ClientNetworkUnavailableError
    if value.startswith("["):
        address, suffix = _bracketed_address(value)
        _validate_optional_port(suffix)
        if not isinstance(address, IPv6Address):
            raise ClientNetworkUnavailableError
        return address
    try:
        return _parse_ip(value)
    except ClientNetworkUnavailableError:
        if value.count(":") != 1:
            raise
        host, port = value.rsplit(":", 1)
        address = _parse_ip(host)
        if not isinstance(address, IPv4Address):
            raise ClientNetworkUnavailableError from None
        _validate_port(port)
        return address


def _bracketed_address(value: str) -> tuple[_IPAddress, str]:
    closing_bracket = value.find("]")
    if closing_bracket <= 1:
        raise ClientNetworkUnavailableError
    address = _parse_ip(value[1:closing_bracket])
    suffix = value[closing_bracket + 1 :]
    return address, suffix


def _validate_optional_port(value: str) -> None:
    if value:
        if not value.startswith(":"):
            raise ClientNetworkUnavailableError
        _validate_port(value[1:])


def _validate_port(value: str) -> None:
    if not value.isascii() or not value.isdecimal():
        raise ClientNetworkUnavailableError
    port = int(value)
    if not 1 <= port <= 65535:
        raise ClientNetworkUnavailableError


def _parse_ip(value: str) -> _IPAddress:
    if not value or "%" in value or value != value.strip():
        raise ClientNetworkUnavailableError
    try:
        address = ip_address(value)
    except ValueError:
        raise ClientNetworkUnavailableError from None
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _contains_unsafe_control(value: str) -> bool:
    return any(
        ord(character) == 127 or (ord(character) < 32 and character != "\t") for character in value
    )
