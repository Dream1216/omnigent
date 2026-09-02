"""Content-blind TLS readiness adapter for the isolated Preview Edge.

The Server and Worker receive no Preview database credential or relay client
identity. They can only probe one deployment-fixed HTTPS endpoint whose DNS
name, resolved cluster address, port, CA, and TLS server name are all pinned by
configuration. The response is an exact bounded constant and carries no tenant
or topology data.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import os
import re
import socket
import ssl
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

from saas.preview_relay_transport import PreviewRelayEndpointPolicy

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_EXPECTED_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"content-type: text/plain; charset=utf-8\r\n"
    b"content-length: 6\r\n"
    b"cache-control: no-store\r\n"
    b"connection: close\r\n"
    b"\r\n"
    b"ready\n"
)
_NOT_READY_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"content-type: text/plain; charset=utf-8\r\n"
    b"content-length: 10\r\n"
    b"cache-control: no-store\r\n"
    b"connection: close\r\n"
    b"\r\n"
    b"not ready\n"
)


class PreviewReadinessError(RuntimeError):
    """Stable failure without endpoint, certificate, or response detail."""


class PreviewReadinessReleaseConfig(Protocol):
    @property
    def product_revision(self) -> str: ...


ReadinessProbe = Callable[[str, int, str, Path, float], bytes]
LocalReadinessProbe = Callable[[], None]


def _request(server_name: str) -> bytes:
    return (
        b"GET /readyz HTTP/1.1\r\n"
        + b"host: "
        + server_name.encode("ascii")
        + b"\r\nconnection: close\r\n\r\n"
    )


@dataclass(frozen=True, slots=True)
class RemoteTlsPreviewReadiness:
    """Resolve, pin, authenticate, and probe one fixed internal Edge endpoint."""

    connect_host: str
    port: int
    server_name: str
    ca_certificate_path: Path
    endpoint_policy: PreviewRelayEndpointPolicy
    timeout_seconds: float = 2.0
    getaddrinfo: Callable[..., object] = field(default=socket.getaddrinfo, repr=False)
    probe: ReadinessProbe = field(default=lambda *values: _tls_probe(*values), repr=False)

    def assert_production_ready(self) -> None:
        try:
            self.endpoint_policy.require_allowed_port(self.port)
            connect_name = self.endpoint_policy.require_allowed_name(self.connect_host)
            server_name = self.endpoint_policy.require_allowed_name(self.server_name)
            answers = cast(
                list[tuple[int, int, int, str, tuple[object, ...]]],
                self.getaddrinfo(
                    connect_name,
                    self.port,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                ),
            )
            addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
            for family, socket_type, protocol, _canonical_name, socket_address in answers:
                if (
                    family not in {socket.AF_INET, socket.AF_INET6}
                    or socket_type != socket.SOCK_STREAM
                    or protocol not in {0, socket.IPPROTO_TCP}
                    or not socket_address
                    or not isinstance(socket_address[0], str)
                ):
                    continue
                addresses.add(self.endpoint_policy.require_allowed_address(socket_address[0]))
            if not addresses:
                raise PreviewReadinessError("Preview readiness endpoint is unavailable")
            address = min(addresses, key=lambda item: (item.version, int(item)))
            response = self.probe(
                str(address),
                self.port,
                server_name,
                self.ca_certificate_path,
                self.timeout_seconds,
            )
        except PreviewReadinessError:
            raise
        except Exception as exc:
            raise PreviewReadinessError("Preview readiness endpoint is unavailable") from exc
        if not hmac.compare_digest(response, _EXPECTED_RESPONSE):
            raise PreviewReadinessError("Preview readiness response is invalid")


def _tls_probe(
    connect_host: str,
    port: int,
    server_name: str,
    ca_certificate_path: Path,
    timeout_seconds: float,
) -> bytes:
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=str(ca_certificate_path),
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    request = _request(server_name)
    try:
        with (
            socket.create_connection((connect_host, port), timeout=timeout_seconds) as raw_socket,
            context.wrap_socket(
                raw_socket,
                server_hostname=server_name,
            ) as connection,
        ):
            connection.settimeout(timeout_seconds)
            connection.sendall(request)
            response = bytearray()
            while len(response) <= len(_EXPECTED_RESPONSE):
                chunk = connection.recv(len(_EXPECTED_RESPONSE) + 1 - len(response))
                if not chunk:
                    break
                response.extend(chunk)
    except (OSError, ssl.SSLError, UnicodeError) as exc:
        raise PreviewReadinessError("Preview readiness TLS probe failed") from exc
    return bytes(response)


class TlsPreviewReadinessServer:
    """Fixed TLS1.3 `/readyz` listener with no database or topology body."""

    def __init__(
        self,
        tls_context: ssl.SSLContext,
        *,
        server_name: str,
        readiness_probe: LocalReadinessProbe,
        timeout_seconds: float = 2.0,
    ) -> None:
        if (
            tls_context.minimum_version != ssl.TLSVersion.TLSv1_3
            or tls_context.maximum_version != ssl.TLSVersion.TLSv1_3
            or tls_context.verify_mode != ssl.CERT_NONE
        ):
            raise ValueError("Preview readiness must use server-auth-only TLS 1.3")
        if not 0.1 <= timeout_seconds <= 10:
            raise ValueError("Preview readiness timeout is invalid")
        try:
            expected_request = _request(server_name)
        except UnicodeError as exc:
            raise ValueError("Preview readiness server name is invalid") from exc
        if len(expected_request) > 1024:
            raise ValueError("Preview readiness server name is invalid")
        self._tls_context = tls_context
        self._expected_request = expected_request
        self._readiness_probe = readiness_probe
        self._timeout = timeout_seconds
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Preview readiness server is not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self, *, host: str, port: int) -> None:
        if self._server is not None:
            raise RuntimeError("Preview readiness server is already started")
        self._server = await asyncio.start_server(
            self._handle,
            host,
            port,
            ssl=self._tls_context,
            ssl_handshake_timeout=self._timeout,
            start_serving=True,
            limit=2048,
        )

    async def aclose(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        response = _NOT_READY_RESPONSE
        try:
            request = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=self._timeout,
            )
            if hmac.compare_digest(request, self._expected_request):
                await asyncio.wait_for(
                    asyncio.to_thread(self._readiness_probe),
                    timeout=self._timeout,
                )
                response = _EXPECTED_RESPONSE
        except Exception:  # noqa: BLE001 - readiness returns only fixed constants.
            pass
        try:
            writer.write(response)
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
        except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()


def build_preview_readiness_server_tls_context(
    *, certificate_path: Path, key_path: Path
) -> ssl.SSLContext:
    """Build the server-auth-only TLS context used by Preview Edge."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_NONE
    try:
        context.load_cert_chain(str(certificate_path), str(key_path))
    except (OSError, ssl.SSLError) as exc:
        raise PreviewReadinessError("Preview readiness server certificate is invalid") from exc
    return context


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise PreviewReadinessError(f"{name} is invalid")
    return value


def _csv(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    values = tuple(value.strip() for value in _required(source, name).split(","))
    if any(not value for value in values) or len(set(values)) != len(values):
        raise PreviewReadinessError(f"{name} is invalid")
    return values


def _ca_path(source: Mapping[str, str]) -> Path:
    path = Path(_required(source, "OMNIGENT_SAAS_PREVIEW_READINESS_CA_CERTIFICATE_FILE"))
    if not path.is_absolute():
        raise PreviewReadinessError("Preview readiness CA is invalid")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PreviewReadinessError("Preview readiness CA is invalid") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or not 1 <= metadata.st_size <= 1_048_576
    ):
        raise PreviewReadinessError("Preview readiness CA is invalid")
    return path


def build_remote_tls_preview_readiness(
    *,
    config: PreviewReadinessReleaseConfig,
    environ: Mapping[str, str] | None = None,
) -> RemoteTlsPreviewReadiness:
    """Build the concrete Server/Worker adapter without any Preview DSN."""

    source: Mapping[str, str] = os.environ if environ is None else environ
    source_revision = _required(source, "OMNIGENT_SAAS_SOURCE_SHA")
    if (
        _FULL_GIT_SHA.fullmatch(source_revision) is None
        or _FULL_GIT_SHA.fullmatch(config.product_revision) is None
        or not hmac.compare_digest(source_revision, config.product_revision)
    ):
        raise PreviewReadinessError("Preview readiness release identity is invalid")
    try:
        port = int(_required(source, "OMNIGENT_SAAS_PREVIEW_READINESS_PORT"))
        allowed_ports = tuple(
            int(value) for value in _csv(source, "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_PORTS")
        )
        policy = PreviewRelayEndpointPolicy.from_strings(
            allowed_dns_suffixes=_csv(
                source, "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_DNS_SUFFIXES"
            ),
            allowed_cidrs=_csv(source, "OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_CIDRS"),
            allowed_ports=allowed_ports,
        )
    except (TypeError, ValueError) as exc:
        raise PreviewReadinessError("Preview readiness endpoint policy is invalid") from exc
    if not 1 <= port <= 65_535:
        raise PreviewReadinessError("Preview readiness endpoint is invalid")
    return RemoteTlsPreviewReadiness(
        connect_host=_required(source, "OMNIGENT_SAAS_PREVIEW_READINESS_HOST").lower(),
        port=port,
        server_name=_required(source, "OMNIGENT_SAAS_PREVIEW_READINESS_SERVER_NAME").lower(),
        ca_certificate_path=_ca_path(source),
        endpoint_policy=policy,
    )


__all__ = [
    "PreviewReadinessError",
    "RemoteTlsPreviewReadiness",
    "TlsPreviewReadinessServer",
    "build_preview_readiness_server_tls_context",
    "build_remote_tls_preview_readiness",
]
