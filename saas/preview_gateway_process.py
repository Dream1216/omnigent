"""Executable composition boundary for one managed Preview Gateway process.

Deployment-specific control-plane clients, Relay TLS state, external CA/HSM access,
and drain observation are supplied by one trusted factory.  This module owns only
strict process configuration, unique process identity, local health reporting, and
the fail-closed runtime lifecycle; it never accepts a platform database credential.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import ipaddress
import json
import logging
import math
import os
import secrets
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, fields
from datetime import timedelta
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from saas.preview_gateway_runtime import (
    PreviewGatewayCertificateLifecycleClient,
    PreviewGatewayCertificateProvider,
    PreviewGatewayDirectoryClient,
    PreviewGatewayDrainObserver,
    PreviewGatewayReadinessProbe,
    PreviewGatewayRelayServer,
    PreviewGatewayRuntime,
    PreviewGatewayRuntimeConfig,
    run_preview_gateway_runtime,
)

_LOGGER = logging.getLogger("omnigent-saas-preview-gateway")
_MAX_CONFIG_BYTES = 65_536
_MAX_HEALTH_REQUEST_BYTES = 2_048
_INSTANCE_PREFIX = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


class PreviewGatewayProcessError(RuntimeError):
    """Stable process configuration/startup error without topology or secrets."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _number(value: object, *, name: str, integer: bool = False) -> float | int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PreviewGatewayProcessError(
            "preview_gateway_process_config_invalid", f"{name} must be a number"
        )
    if integer and not isinstance(value, int):
        raise PreviewGatewayProcessError(
            "preview_gateway_process_config_invalid", f"{name} must be an integer"
        )
    if not math.isfinite(float(value)) or value <= 0:
        raise PreviewGatewayProcessError(
            "preview_gateway_process_config_invalid", f"{name} must be positive"
        )
    return value


@dataclass(frozen=True, slots=True)
class PreviewGatewayProcessConfig:
    """Non-secret, deployment-owned process configuration."""

    instance_id_prefix: str
    bind_host: str
    bind_port: int
    connect_host: str
    connect_port: int
    server_name: str
    failure_domain: str
    source_revision: str
    adapter_contract_version: str
    health_host: str = "127.0.0.1"
    health_port: int = 9080
    lease_seconds: float = 45.0
    heartbeat_seconds: float = 15.0
    renewal_before_seconds: float = 600.0
    rotation_overlap_seconds: float = 300.0
    readiness_timeout_seconds: float = 10.0
    drain_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        text_fields = (
            self.instance_id_prefix,
            self.bind_host,
            self.connect_host,
            self.server_name,
            self.failure_domain,
            self.source_revision,
            self.adapter_contract_version,
            self.health_host,
        )
        if any(not isinstance(value, str) for value in text_fields):
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_invalid",
                "Preview Gateway process text configuration is invalid",
            )
        try:
            health_address = ipaddress.ip_address(self.health_host)
        except ValueError as exc:
            raise PreviewGatewayProcessError(
                "preview_gateway_process_health_bind_invalid",
                "Preview Gateway health host must be a loopback IP address",
            ) from exc
        if (
            not _INSTANCE_PREFIX.fullmatch(self.instance_id_prefix)
            or not self.bind_host.strip()
            or not self.connect_host.strip()
            or not self.server_name.strip()
            or not self.failure_domain.strip()
            or not self.source_revision.strip()
            or not self.adapter_contract_version.strip()
            or not health_address.is_loopback
            or any(
                isinstance(port, bool) or not 1 <= port <= 65_535
                for port in (self.bind_port, self.connect_port, self.health_port)
            )
        ):
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_invalid",
                "Preview Gateway process configuration is invalid",
            )
        for name in (
            "lease_seconds",
            "heartbeat_seconds",
            "renewal_before_seconds",
            "readiness_timeout_seconds",
            "drain_timeout_seconds",
        ):
            _number(getattr(self, name), name=name)
        overlap = self.rotation_overlap_seconds
        if (
            isinstance(overlap, bool)
            or not isinstance(overlap, int | float)
            or not math.isfinite(float(overlap))
            or overlap < 0
        ):
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_invalid",
                "rotation_overlap_seconds must be non-negative",
            )
        # Repeat the important lifecycle relationship at the process boundary so a
        # broken deployment never reaches the control plane.
        if self.heartbeat_seconds * 3 > self.lease_seconds:
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_invalid",
                "heartbeat_seconds must fit at least three times inside lease_seconds",
            )
        if self.rotation_overlap_seconds >= self.renewal_before_seconds:
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_invalid",
                "rotation overlap must be shorter than the renewal window",
            )

    @classmethod
    def from_mapping(cls, document: Mapping[str, object]) -> PreviewGatewayProcessConfig:
        expected = {field.name for field in fields(cls)}
        # Dataclasses uses MISSING for both fields; spelling it explicitly keeps the
        # accepted document schema closed and rejects static IDs/tokens as unknown.
        from dataclasses import MISSING

        required = {
            field.name
            for field in fields(cls)
            if field.default is MISSING and field.default_factory is MISSING
        }
        if set(document) - expected or not required.issubset(document):
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_invalid",
                "Preview Gateway configuration fields are invalid",
            )
        values = dict(document)
        for name in ("bind_port", "connect_port", "health_port"):
            if name in values:
                values[name] = cast(int, _number(values[name], name=name, integer=True))
        for name in (
            "lease_seconds",
            "heartbeat_seconds",
            "renewal_before_seconds",
            "readiness_timeout_seconds",
            "drain_timeout_seconds",
        ):
            if name in values:
                values[name] = float(_number(values[name], name=name))
        if "rotation_overlap_seconds" in values:
            overlap = values["rotation_overlap_seconds"]
            if (
                isinstance(overlap, bool)
                or not isinstance(overlap, int | float)
                or not math.isfinite(float(overlap))
                or overlap < 0
            ):
                raise PreviewGatewayProcessError(
                    "preview_gateway_process_config_invalid",
                    "rotation_overlap_seconds must be non-negative",
                )
            values["rotation_overlap_seconds"] = float(overlap)
        try:
            return cls(**values)  # type: ignore[arg-type]
        except TypeError as exc:
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_invalid",
                "Preview Gateway configuration values are invalid",
            ) from exc

    def runtime_config(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
    ) -> PreviewGatewayRuntimeConfig:
        return PreviewGatewayRuntimeConfig(
            gateway_instance_id=gateway_instance_id,
            registration_token=registration_token,
            bind_host=self.bind_host,
            bind_port=self.bind_port,
            connect_host=self.connect_host,
            advertised_connect_port=self.connect_port,
            server_name=self.server_name,
            failure_domain=self.failure_domain,
            source_revision=self.source_revision,
            adapter_contract_version=self.adapter_contract_version,
            lease_duration=timedelta(seconds=self.lease_seconds),
            heartbeat_interval=timedelta(seconds=self.heartbeat_seconds),
            renewal_before=timedelta(seconds=self.renewal_before_seconds),
            rotation_overlap=timedelta(seconds=self.rotation_overlap_seconds),
            readiness_timeout=timedelta(seconds=self.readiness_timeout_seconds),
            drain_timeout=timedelta(seconds=self.drain_timeout_seconds),
        )


def load_preview_gateway_process_config(path: str | Path) -> PreviewGatewayProcessConfig:
    """Read one bounded, root/current-user-owned, non-writable, non-symlink JSON file."""

    candidate = Path(path)
    if not candidate.is_absolute():
        raise PreviewGatewayProcessError(
            "preview_gateway_process_config_path_invalid",
            "Preview Gateway configuration path must be absolute",
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise PreviewGatewayProcessError(
            "preview_gateway_process_config_unavailable",
            "Preview Gateway configuration is unavailable",
        ) from exc
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid not in {0, os.geteuid()}
            or facts.st_mode & 0o022
            or not 1 <= facts.st_size <= _MAX_CONFIG_BYTES
        ):
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_file_invalid",
                "Preview Gateway configuration file ownership or mode is invalid",
            )
        encoded = bytearray()
        while len(encoded) <= _MAX_CONFIG_BYTES:
            chunk = os.read(descriptor, min(8192, _MAX_CONFIG_BYTES + 1 - len(encoded)))
            if not chunk:
                break
            encoded.extend(chunk)
        if not encoded or len(encoded) > _MAX_CONFIG_BYTES:
            raise PreviewGatewayProcessError(
                "preview_gateway_process_config_file_invalid",
                "Preview Gateway configuration file size is invalid",
            )
    finally:
        os.close(descriptor)
    def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise PreviewGatewayProcessError(
                    "preview_gateway_process_config_invalid",
                    "Preview Gateway configuration contains duplicate fields",
                )
            document[key] = value
        return document

    try:
        document = json.loads(bytes(encoded), object_pairs_hook=reject_duplicate_members)
    except PreviewGatewayProcessError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PreviewGatewayProcessError(
            "preview_gateway_process_config_invalid",
            "Preview Gateway configuration is not valid JSON",
        ) from exc
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        raise PreviewGatewayProcessError(
            "preview_gateway_process_config_invalid",
            "Preview Gateway configuration must be a JSON object",
        )
    return PreviewGatewayProcessConfig.from_mapping(document)


@dataclass(frozen=True, slots=True)
class PreviewGatewayProcessComponents:
    """Deployment-supplied implementations behind the permanent runtime partition."""

    directory: PreviewGatewayDirectoryClient
    certificate_lifecycle: PreviewGatewayCertificateLifecycleClient
    certificate_provider: PreviewGatewayCertificateProvider
    relay_server: PreviewGatewayRelayServer
    readiness_probe: PreviewGatewayReadinessProbe
    drain_observer: PreviewGatewayDrainObserver

    def __post_init__(self) -> None:
        requirements = {
            "directory": (
                "register_gateway",
                "activate_gateway",
                "heartbeat_gateway",
                "begin_draining",
                "release_gateway",
            ),
            "certificate_lifecycle": ("activate_certificate", "revoke_certificate"),
            "certificate_provider": ("prepare", "install", "discard"),
            "relay_server": ("start", "aclose"),
            "readiness_probe": ("verify",),
            "drain_observer": ("wait_until_drained",),
        }
        for name, methods in requirements.items():
            component = getattr(self, name)
            if any(not callable(getattr(component, method, None)) for method in methods):
                raise PreviewGatewayProcessError(
                    "preview_gateway_process_factory_invalid",
                    "Preview Gateway process factory returned incomplete components",
                )


class PreviewGatewayProcessFactory(Protocol):
    """Trusted deployment adapter loaded before any listener is bound."""

    def build(
        self,
        *,
        config: PreviewGatewayProcessConfig,
        gateway_instance_id: str,
    ) -> PreviewGatewayProcessComponents: ...


def _load_factory(reference: str) -> PreviewGatewayProcessFactory:
    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        raise PreviewGatewayProcessError(
            "preview_gateway_process_factory_invalid",
            "Preview Gateway factory must use module:attribute form",
        )
    candidate = getattr(importlib.import_module(module_name), attribute_name)
    if isinstance(candidate, type):
        factory = candidate()
    elif callable(getattr(candidate, "build", None)):
        factory = candidate
    elif callable(candidate):
        factory = candidate()
    else:
        raise PreviewGatewayProcessError(
            "preview_gateway_process_factory_invalid",
            "Preview Gateway factory reference is invalid",
        )
    if not callable(getattr(factory, "build", None)):
        raise PreviewGatewayProcessError(
            "preview_gateway_process_factory_invalid",
            "Preview Gateway factory does not provide build()",
        )
    return cast(PreviewGatewayProcessFactory, factory)


class _RuntimeHealthView(Protocol):
    @property
    def state(self) -> str: ...

    @property
    def ready(self) -> bool: ...

    @property
    def fatal_error(self) -> BaseException | None: ...


class PreviewGatewayHealthServer:
    """Loopback-only fixed liveness/readiness interface for a service manager."""

    def __init__(
        self,
        runtime: _RuntimeHealthView,
        *,
        host: str,
        port: int,
        request_timeout_seconds: float = 2.0,
    ) -> None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("Preview Gateway health host must be a loopback IP") from exc
        if (
            not address.is_loopback
            or isinstance(port, bool)
            or not 0 <= port <= 65_535
            or request_timeout_seconds <= 0
        ):
            raise ValueError("Preview Gateway health server configuration is invalid")
        self._runtime = runtime
        self._host = host
        self._port = port
        self._request_timeout_seconds = request_timeout_seconds
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Preview Gateway health server is not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("Preview Gateway health server is already started")
        self._server = await asyncio.start_server(
            self._handle,
            self._host,
            self._port,
            limit=_MAX_HEALTH_REQUEST_BYTES,
        )

    async def aclose(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        status = 400
        method = "GET"
        try:
            request = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=self._request_timeout_seconds
            )
            if len(request) > _MAX_HEALTH_REQUEST_BYTES:
                raise ValueError
            first_line = request.split(b"\r\n", 1)[0]
            method_bytes, target, version = first_line.split(b" ")
            method = method_bytes.decode("ascii")
            if method not in {"GET", "HEAD"} or version != b"HTTP/1.1":
                status = 405
            elif target == b"/livez":
                status = (
                    200
                    if self._runtime.state not in {"failed", "stopped"}
                    and self._runtime.fatal_error is None
                    else 503
                )
            elif target == b"/readyz":
                status = (
                    200
                    if self._runtime.ready
                    and self._runtime.state == "active"
                    and self._runtime.fatal_error is None
                    else 503
                )
            else:
                status = 404
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ValueError):
            status = 400
        reason = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            405: "Method Not Allowed",
            503: "Service Unavailable",
        }[status]
        body = b"ok\n" if status == 200 else b"unavailable\n"
        encoded_body = b"" if method == "HEAD" else body
        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + encoded_body
        writer.write(response)
        try:
            await writer.drain()
        finally:
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()


async def check_preview_gateway_health(
    *, host: str, port: int, readiness: bool, timeout_seconds: float = 2.0
) -> bool:
    """Service-manager probe used by the Kubernetes exec probe."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if (
        not address.is_loopback
        or isinstance(port, bool)
        or not 1 <= port <= 65_535
        or timeout_seconds <= 0
    ):
        return False
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout_seconds
        )
        path = "/readyz" if readiness else "/livez"
        writer.write(
            f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode()
        )
        await asyncio.wait_for(writer.drain(), timeout=timeout_seconds)
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout_seconds)
        return status_line == b"HTTP/1.1 200 OK\r\n"
    except (ConnectionError, OSError, TimeoutError):
        return False
    finally:
        if writer is not None:
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()


async def run_preview_gateway_process(
    config: PreviewGatewayProcessConfig,
    factory: PreviewGatewayProcessFactory,
    *,
    instance_id_factory: Callable[[], str] | None = None,
    registration_token_factory: Callable[[], str] | None = None,
) -> None:
    """Build deployment adapters, publish loopback health, and run to signal/failure."""

    gateway_instance_id = (
        instance_id_factory()
        if instance_id_factory is not None
        else f"{config.instance_id_prefix}-{uuid4().hex}"
    )
    registration_token = (
        registration_token_factory()
        if registration_token_factory is not None
        else secrets.token_urlsafe(48)
    )
    runtime_config = config.runtime_config(
        gateway_instance_id=gateway_instance_id,
        registration_token=registration_token,
    )
    built = factory.build(config=config, gateway_instance_id=gateway_instance_id)
    if inspect.isawaitable(built):
        built = await built
    if not isinstance(built, PreviewGatewayProcessComponents):
        raise PreviewGatewayProcessError(
            "preview_gateway_process_factory_invalid",
            "Preview Gateway process factory returned an invalid value",
        )
    runtime = PreviewGatewayRuntime(
        runtime_config,
        directory=built.directory,
        certificate_authority=built.certificate_lifecycle,
        certificate_provider=built.certificate_provider,
        relay_server=built.relay_server,
        readiness_probe=built.readiness_probe,
        drain_observer=built.drain_observer,
    )
    health = PreviewGatewayHealthServer(
        runtime,
        host=config.health_host,
        port=config.health_port,
    )
    await health.start()
    try:
        await run_preview_gateway_runtime(runtime)
    finally:
        await health.aclose()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="omnigent-saas-preview-gateway")
    parser.add_argument("--config")
    parser.add_argument("--factory")
    parser.add_argument("--probe", choices=("live", "ready"))
    parser.add_argument("--health-host", default="127.0.0.1")
    parser.add_argument("--health-port", type=int, default=9080)
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="INFO",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a Gateway process or one loopback service-manager health check."""

    arguments = _parser().parse_args(argv)
    if arguments.probe is not None:
        if arguments.config or arguments.factory:
            _parser().error("--probe cannot be combined with --config or --factory")
        return int(
            not asyncio.run(
                check_preview_gateway_health(
                    host=arguments.health_host,
                    port=arguments.health_port,
                    readiness=arguments.probe == "ready",
                )
            )
        )
    if not arguments.config or not arguments.factory:
        _parser().error("--config and --factory are required in process mode")
    logging.basicConfig(level=arguments.log_level)
    try:
        config = load_preview_gateway_process_config(arguments.config)
        factory = _load_factory(arguments.factory)
        asyncio.run(run_preview_gateway_process(config, factory))
    except Exception as exc:  # noqa: BLE001 - entrypoint emits only stable, non-secret facts
        code = getattr(exc, "code", "preview_gateway_process_failed")
        _LOGGER.error("Preview Gateway process stopped: %s (%s)", code, type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PreviewGatewayHealthServer",
    "PreviewGatewayProcessComponents",
    "PreviewGatewayProcessConfig",
    "PreviewGatewayProcessError",
    "PreviewGatewayProcessFactory",
    "check_preview_gateway_health",
    "load_preview_gateway_process_config",
    "main",
    "run_preview_gateway_process",
]
