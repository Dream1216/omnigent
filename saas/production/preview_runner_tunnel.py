"""Runner-side one-use Preview tunnel with a pinned TLS/endpoint policy.

This downstream adapter reuses the official frame dispatcher under an exact
source contract.  It doesn't copy or fork the official request/WS state
machine.  Every reconnect first mints a new single-use registration through
the Runner-control mTLS channel, pins the server-selected endpoint to an
allowed cluster address, and then binds that bearer to its token-derived
official Runner id.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import ipaddress
import os
import re
import ssl
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast
from urllib.parse import quote
from uuid import UUID

import websockets
from starlette.types import Receive, Scope, Send
from websockets.exceptions import ConnectionClosed, WebSocketException
from websockets.typing import Origin

from omnigent.runner.identity import (
    OMNIGENT_INTERNAL_WS_ORIGIN,
    RUNNER_TUNNEL_TOKEN_HEADER,
)
from omnigent.runner.transports.ws_tunnel.limits import (
    RUNNER_TUNNEL_MAX_MESSAGE_BYTES,
    TUNNEL_KEEPALIVE_PING_INTERVAL_S,
    TUNNEL_KEEPALIVE_PING_TIMEOUT_S,
)
from omnigent.runner.transports.ws_tunnel.serve import (
    _cancel_dispatch_tasks,
    _cancel_ws_channels,
    _handle_tunnel_frame,
    _send_hello,
)
from saas.preview_relay_transport import (
    PreviewRelayEndpoint,
    PreviewRelayEndpointPolicy,
    PreviewRelayTransportError,
    resolve_policy_bound_preview_endpoint,
)
from saas.preview_tunnel import LocalPreviewTargetRegistry, PreviewRunnerASGI
from saas.production.runner_control import RunnerPreviewTunnelRegistration
from saas.runner_adapter.preview_supervisor import RunnerPreviewProcessSupervisor

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_OFFICIAL_RUNNER_ID = re.compile(r"^runner_token_[0-9a-f]{32}$")
_PRIVATE_CONTRACT_HASHES = MappingProxyType(
    {
        "_cancel_dispatch_tasks": (
            "8ab33b9b8c9dc1401bd0fa0234735378162614fa49ccc2ab9402f616ea8a1387"
        ),
        "_cancel_ws_channels": (
            "a2da0dc05ff42f8e36c5d9ecd289ed14a0e618004cd424b268b810821f0c216a"
        ),
        "_handle_tunnel_frame": (
            "a7214e59f86b90d18f7b7dc0561cf8bdc2688fe9ffb8f9c0b1b9a043098a9835"
        ),
        "_send_hello": ("50b4d4821faacd8ee16eaa270206e3e5b25a7e51cfac98e692a3df95828cc763"),
    }
)


class ProductionPreviewRunnerTunnelError(RuntimeError):
    """Stable Runner-facing error without bearer, endpoint, or filesystem detail."""


class PreviewTunnelRegistrationClient(Protocol):
    async def mint_preview_tunnel(self) -> RunnerPreviewTunnelRegistration: ...


@dataclass(frozen=True, slots=True)
class ProductionPreviewRunnerTunnelConfig:
    source_revision: str
    product_revision: str
    runner_id: UUID
    connection_generation: int
    ca_certificate_path: Path
    endpoint_policy: PreviewRelayEndpointPolicy
    socket_root: Path
    log_root: Path
    open_timeout_seconds: float
    reconnect_min_seconds: float
    reconnect_max_seconds: float


async def _deny_non_preview(_scope: Scope, _receive: Receive, send: Send) -> None:
    body = b'{"detail":{"code":"preview_route_not_found"}}'
    await send(
        {
            "type": "http.response.start",
            "status": 404,
            "headers": [
                (b"cache-control", b"no-store"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _csv(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    raw = source.get(name, "")
    values = tuple(value.strip() for value in raw.split(","))
    if (
        not raw
        or any(not value or "\x00" in value for value in values)
        or len(values) != len(set(values))
    ):
        raise ProductionPreviewRunnerTunnelError(f"{name} is invalid")
    return values


def _number(
    source: Mapping[str, str],
    name: str,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(source.get(name, str(default)))
    except ValueError as error:
        raise ProductionPreviewRunnerTunnelError(f"{name} is invalid") from error
    if not minimum <= value <= maximum:
        raise ProductionPreviewRunnerTunnelError(f"{name} is invalid")
    return value


def _private_directory(source: Mapping[str, str], name: str) -> Path:
    raw = source.get(name, "")
    path = Path(raw)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProductionPreviewRunnerTunnelError(f"{name} is unavailable") from error
    if (
        not raw
        or raw != raw.strip()
        or not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ProductionPreviewRunnerTunnelError(f"{name} is unavailable")
    return path.resolve(strict=True)


def _ca_file(source: Mapping[str, str]) -> Path:
    raw = source.get("OMNIGENT_SAAS_PREVIEW_RUNNER_CA_CERTIFICATE_FILE", "")
    path = Path(raw)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProductionPreviewRunnerTunnelError("Preview Runner CA is unavailable") from error
    if (
        not raw
        or raw != raw.strip()
        or not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or not 1 <= metadata.st_size <= 1_048_576
    ):
        raise ProductionPreviewRunnerTunnelError("Preview Runner CA is unavailable")
    return path


def load_production_preview_runner_tunnel_config(
    *,
    runner_id: UUID,
    connection_generation: int,
    environ: Mapping[str, str] | None = None,
) -> ProductionPreviewRunnerTunnelConfig:
    source: Mapping[str, str] = os.environ if environ is None else environ
    source_revision = source.get("OMNIGENT_SAAS_SOURCE_SHA", "")
    product_revision = source.get("OMNIGENT_SAAS_PRODUCT_REVISION", "")
    if (
        _FULL_GIT_SHA.fullmatch(source_revision) is None
        or _FULL_GIT_SHA.fullmatch(product_revision) is None
        or not secrets_compare(source_revision, product_revision)
        or runner_id.int == 0
        or connection_generation <= 0
    ):
        raise ProductionPreviewRunnerTunnelError(
            "Preview Runner release or incarnation is invalid"
        )
    try:
        ports = tuple(
            int(value) for value in _csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS")
        )
        policy = PreviewRelayEndpointPolicy.from_strings(
            allowed_dns_suffixes=_csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_DNS_SUFFIXES"),
            allowed_cidrs=_csv(source, "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS"),
            allowed_ports=ports,
        )
    except (TypeError, ValueError) as error:
        raise ProductionPreviewRunnerTunnelError(
            "Preview Runner endpoint policy is invalid"
        ) from error
    reconnect_min = _number(
        source,
        "OMNIGENT_SAAS_PREVIEW_RUNNER_RECONNECT_MIN_SECONDS",
        default=0.5,
        minimum=0.1,
        maximum=10,
    )
    reconnect_max = _number(
        source,
        "OMNIGENT_SAAS_PREVIEW_RUNNER_RECONNECT_MAX_SECONDS",
        default=10,
        minimum=1,
        maximum=60,
    )
    if reconnect_min > reconnect_max:
        raise ProductionPreviewRunnerTunnelError("Preview Runner reconnect policy is invalid")
    return ProductionPreviewRunnerTunnelConfig(
        source_revision=source_revision,
        product_revision=product_revision,
        runner_id=runner_id,
        connection_generation=connection_generation,
        ca_certificate_path=_ca_file(source),
        endpoint_policy=policy,
        socket_root=_private_directory(source, "OMNIGENT_SAAS_PREVIEW_RUNNER_SOCKET_ROOT"),
        log_root=_private_directory(source, "OMNIGENT_SAAS_PREVIEW_RUNNER_LOG_ROOT"),
        open_timeout_seconds=_number(
            source,
            "OMNIGENT_SAAS_PREVIEW_RUNNER_OPEN_TIMEOUT_SECONDS",
            default=10,
            minimum=1,
            maximum=60,
        ),
        reconnect_min_seconds=reconnect_min,
        reconnect_max_seconds=reconnect_max,
    )


def secrets_compare(left: str, right: str) -> bool:
    """Keep release comparison timing-independent without treating it as a secret."""

    return (
        hashlib.sha256(left.encode("ascii")).digest()
        == hashlib.sha256(right.encode("ascii")).digest()
    )


def _assert_official_contract() -> None:
    for name, function in (
        ("_cancel_dispatch_tasks", _cancel_dispatch_tasks),
        ("_cancel_ws_channels", _cancel_ws_channels),
        ("_handle_tunnel_frame", _handle_tunnel_frame),
        ("_send_hello", _send_hello),
    ):
        try:
            actual = hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
        except (OSError, TypeError) as error:
            raise ProductionPreviewRunnerTunnelError(
                "Official Runner tunnel contract is unavailable"
            ) from error
        if actual != _PRIVATE_CONTRACT_HASHES[name]:
            raise ProductionPreviewRunnerTunnelError("Official Runner tunnel contract changed")


class ProductionPreviewRunnerTunnel:
    """Own the Runner-local target registry and dynamic one-use WSS lifecycle."""

    def __init__(
        self,
        config: ProductionPreviewRunnerTunnelConfig,
        registration_client: PreviewTunnelRegistrationClient,
    ) -> None:
        _assert_official_contract()
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=str(config.ca_certificate_path),
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        self.config = config
        self._registration_client = registration_client
        self._tls_context = context
        self.targets = LocalPreviewTargetRegistry()
        self.supervisor = RunnerPreviewProcessSupervisor(
            self.targets,
            config.socket_root,
            config.log_root,
            runner_id=config.runner_id,
            connection_generation=config.connection_generation,
        )
        self.app = PreviewRunnerASGI(_deny_non_preview, self.targets)
        self._internal_stop = asyncio.Event()
        self._closed = False

    def assert_production_ready(self) -> None:
        if self._closed:
            raise ProductionPreviewRunnerTunnelError("Preview Runner tunnel is closed")
        _assert_official_contract()
        if (
            self._tls_context.minimum_version != ssl.TLSVersion.TLSv1_3
            or self._tls_context.maximum_version != ssl.TLSVersion.TLSv1_3
            or self._tls_context.verify_mode != ssl.CERT_REQUIRED
            or not self._tls_context.check_hostname
        ):
            raise ProductionPreviewRunnerTunnelError("Preview Runner TLS policy is invalid")

    async def run(self, stop: asyncio.Event) -> None:
        self.assert_production_ready()
        delay = self.config.reconnect_min_seconds
        while not stop.is_set() and not self._internal_stop.is_set():
            registration = await self._registration_client.mint_preview_tunnel()
            endpoint = await asyncio.to_thread(self._endpoint, registration)
            try:
                await self._serve_once(registration, endpoint, stop)
                delay = self.config.reconnect_min_seconds
            except asyncio.CancelledError:
                raise
            except (ConnectionClosed, OSError, TimeoutError, WebSocketException):
                if stop.is_set() or self._internal_stop.is_set():
                    return
                await self._wait_or_stop(stop, delay)
                delay = min(delay * 2, self.config.reconnect_max_seconds)

    async def aclose(self) -> None:
        self._closed = True
        self._internal_stop.set()
        await self.supervisor.aclose()

    def _endpoint(self, registration: RunnerPreviewTunnelRegistration) -> PreviewRelayEndpoint:
        now = datetime.now(timezone.utc)
        if (
            registration.runner_id != self.config.runner_id
            or registration.connection_generation != self.config.connection_generation
            or _OFFICIAL_RUNNER_ID.fullmatch(registration.official_runner_id) is None
            or registration.audience != registration.server_name
            or registration.expires_at <= now
        ):
            raise ProductionPreviewRunnerTunnelError("Preview tunnel registration is stale")
        try:
            return resolve_policy_bound_preview_endpoint(
                PreviewRelayEndpoint(
                    registration.endpoint_host,
                    registration.endpoint_port,
                    registration.server_name,
                ),
                self.config.endpoint_policy,
            )
        except (PreviewRelayTransportError, ValueError) as error:
            raise ProductionPreviewRunnerTunnelError(
                "Preview tunnel endpoint is denied"
            ) from error

    async def _serve_once(
        self,
        registration: RunnerPreviewTunnelRegistration,
        endpoint: PreviewRelayEndpoint,
        stop: asyncio.Event,
    ) -> None:
        connect_host = endpoint.connect_host
        try:
            if ipaddress.ip_address(connect_host).version == 6:
                connect_host = f"[{connect_host}]"
        except ValueError:  # pragma: no cover - resolver always pins a literal
            raise ProductionPreviewRunnerTunnelError(
                "Preview tunnel endpoint is not pinned"
            ) from None
        uri = (
            f"wss://{connect_host}:{endpoint.port}/v1/runners/"
            f"{quote(registration.official_runner_id, safe='')}/tunnel"
        )
        dispatch_tasks: dict[str, asyncio.Task[None]] = {}
        ws_channels: dict[str, Any] = {}
        headers = {RUNNER_TUNNEL_TOKEN_HEADER: registration.registration_token}
        async with websockets.connect(
            uri,
            origin=Origin(OMNIGENT_INTERNAL_WS_ORIGIN),
            additional_headers=headers,
            compression=None,
            user_agent_header=None,
            open_timeout=self.config.open_timeout_seconds,
            close_timeout=2,
            max_size=RUNNER_TUNNEL_MAX_MESSAGE_BYTES,
            ping_interval=TUNNEL_KEEPALIVE_PING_INTERVAL_S,
            ping_timeout=TUNNEL_KEEPALIVE_PING_TIMEOUT_S,
            ssl=self._tls_context,
            server_hostname=endpoint.server_name,
        ) as websocket:
            await _send_hello(websocket.send, self.config.product_revision)
            external_stop = asyncio.create_task(stop.wait(), name="preview-runner-stop")
            internal_stop = asyncio.create_task(
                self._internal_stop.wait(), name="preview-runner-close"
            )
            try:
                while True:
                    receive = asyncio.create_task(websocket.recv())
                    done, _pending = await asyncio.wait(
                        {receive, external_stop, internal_stop},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if external_stop in done or internal_stop in done:
                        receive.cancel()
                        with suppress(asyncio.CancelledError, ConnectionClosed):
                            await receive
                        return
                    raw = receive.result()
                    await _handle_tunnel_frame(
                        self.app,
                        raw,
                        websocket.send,
                        dispatch_tasks,
                        cast(Any, ws_channels),
                    )
            finally:
                external_stop.cancel()
                internal_stop.cancel()
                with suppress(asyncio.CancelledError):
                    await external_stop
                with suppress(asyncio.CancelledError):
                    await internal_stop
                await _cancel_dispatch_tasks(dispatch_tasks)
                await _cancel_ws_channels(cast(Any, ws_channels))

    async def _wait_or_stop(self, stop: asyncio.Event, delay: float) -> None:
        external_stop = asyncio.create_task(stop.wait())
        internal_stop = asyncio.create_task(self._internal_stop.wait())
        try:
            await asyncio.wait(
                {external_stop, internal_stop},
                timeout=delay,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            external_stop.cancel()
            internal_stop.cancel()
            with suppress(asyncio.CancelledError):
                await external_stop
            with suppress(asyncio.CancelledError):
                await internal_stop


def build_runner_preview_tunnel_client(
    *,
    runner_id: UUID,
    connection_generation: int,
    registration_client: PreviewTunnelRegistrationClient,
    environ: Mapping[str, str] | None = None,
) -> ProductionPreviewRunnerTunnel:
    """Concrete downstream factory used by the production Runner Agent."""

    return ProductionPreviewRunnerTunnel(
        load_production_preview_runner_tunnel_config(
            runner_id=runner_id,
            connection_generation=connection_generation,
            environ=environ,
        ),
        registration_client,
    )


__all__ = [
    "PreviewTunnelRegistrationClient",
    "ProductionPreviewRunnerTunnel",
    "ProductionPreviewRunnerTunnelConfig",
    "ProductionPreviewRunnerTunnelError",
    "build_runner_preview_tunnel_client",
    "load_production_preview_runner_tunnel_config",
]
