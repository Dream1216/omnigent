"""Fail-closed process lifecycle for one managed Preview Gateway replica.

The runtime is deliberately downstream-owned.  It binds the Relay listener before
publishing a routable endpoint, keeps the registration token in process memory only,
activates both purpose-separated leaves, heartbeats the durable lease, coordinates
certificate rotation, and removes readiness before drain or failure cleanup.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import signal
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from cryptography import x509

from saas.control_plane import (
    ActivatedPreviewGatewayCertificate,
    PreviewGatewayCertificateAuthority,
    PreviewGatewayDirectoryAuthority,
)

_GATEWAY_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PURPOSES = ("preview_relay_client", "preview_relay_server")


class PreviewGatewayRuntimeError(RuntimeError):
    """Stable process-level error that never includes a token, key, or certificate."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PreviewGatewayRuntimeLeaf:
    """Public metadata for a locally held leaf; the private key stays in its provider."""

    purpose: str
    certificate_der: bytes = field(repr=False)
    trust_bundle_version: str
    not_after: datetime

    def __post_init__(self) -> None:
        try:
            certificate_not_after = x509.load_der_x509_certificate(
                self.certificate_der
            ).not_valid_after_utc
        except (TypeError, ValueError):
            certificate_not_after = None
        if (
            self.purpose not in _PURPOSES
            or not self.certificate_der
            or len(self.certificate_der) > 32_768
            or not self.trust_bundle_version.strip()
            or len(self.trust_bundle_version) > 64
            or self.not_after.tzinfo is None
            or certificate_not_after != self.not_after.astimezone(timezone.utc)
        ):
            raise ValueError("Preview Gateway runtime leaf is invalid")

    @property
    def fingerprint_sha256(self) -> str:
        return hashlib.sha256(self.certificate_der).hexdigest()


@dataclass(frozen=True, slots=True)
class PreviewGatewayRuntimeCertificateSet:
    """One client/server pair prepared and installed atomically by a key provider."""

    client: PreviewGatewayRuntimeLeaf
    server: PreviewGatewayRuntimeLeaf

    def __post_init__(self) -> None:
        if (
            self.client.purpose != "preview_relay_client"
            or self.server.purpose != "preview_relay_server"
            or self.client.fingerprint_sha256 == self.server.fingerprint_sha256
            or self.client.trust_bundle_version != self.server.trust_bundle_version
        ):
            raise ValueError("Preview Gateway runtime certificate set is invalid")

    @property
    def leaves(self) -> tuple[PreviewGatewayRuntimeLeaf, PreviewGatewayRuntimeLeaf]:
        return self.client, self.server

    @property
    def minimum_not_after(self) -> datetime:
        return min(_aware(self.client.not_after), _aware(self.server.not_after))


class PreviewGatewayCertificateProvider(Protocol):
    """Local/HSM provider that never returns private-key bytes to the coordinator."""

    async def prepare(
        self,
        *,
        gateway_instance_id: str,
        server_name: str,
    ) -> PreviewGatewayRuntimeCertificateSet: ...

    async def install(self, certificates: PreviewGatewayRuntimeCertificateSet) -> None: ...

    async def discard(self, certificates: PreviewGatewayRuntimeCertificateSet) -> None: ...


class PreviewGatewayRelayServer(Protocol):
    """Bound TLS Relay listener controlled by the process coordinator."""

    @property
    def port(self) -> int: ...

    async def start(self, *, host: str, port: int) -> None: ...

    async def aclose(self) -> None: ...


class PreviewGatewayReadinessProbe(Protocol):
    """Probe the advertised endpoint with a separately authorized health identity.

    The implementation pins ``certificates.server`` but must not authenticate as
    ``certificates.client``: a starting Gateway leaf remains unauthorized for
    ordinary Relay traffic until directory activation commits.
    """

    async def verify(
        self,
        *,
        gateway_instance_id: str,
        connect_host: str,
        connect_port: int,
        server_name: str,
        certificates: PreviewGatewayRuntimeCertificateSet,
    ) -> None: ...


class PreviewGatewayDrainObserver(Protocol):
    """Observe local Runner Tunnel ownership without enumerating cross-replica topology."""

    async def wait_until_drained(
        self,
        *,
        gateway_instance_id: str,
        timeout_seconds: float,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class PreviewGatewayRuntimeConfig:
    """Immutable server-owned process configuration."""

    gateway_instance_id: str
    registration_token: str = field(repr=False)
    bind_host: str
    bind_port: int
    connect_host: str
    server_name: str
    failure_domain: str
    source_revision: str
    adapter_contract_version: str
    advertised_connect_port: int | None = None
    lease_duration: timedelta = timedelta(seconds=45)
    heartbeat_interval: timedelta = timedelta(seconds=15)
    renewal_before: timedelta = timedelta(minutes=10)
    rotation_overlap: timedelta = timedelta(minutes=5)
    readiness_timeout: timedelta = timedelta(seconds=10)
    drain_timeout: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        advertised_port = self.advertised_connect_port
        if (
            not _GATEWAY_INSTANCE.fullmatch(self.gateway_instance_id)
            or len(self.registration_token) < 32
            or len(self.registration_token) > 512
            or self.registration_token.strip() != self.registration_token
            or not self.bind_host.strip()
            or not 0 <= self.bind_port <= 65_535
            or (advertised_port is not None and not 1 <= advertised_port <= 65_535)
            or not self.connect_host.strip()
            or len(self.connect_host) > 253
            or not self.server_name.strip()
            or len(self.server_name) > 253
            or not self.failure_domain.strip()
            or len(self.failure_domain) > 128
            or not self.source_revision.strip()
            or len(self.source_revision) > 64
            or not self.adapter_contract_version.strip()
            or len(self.adapter_contract_version) > 32
            or self.lease_duration <= timedelta(0)
            or self.heartbeat_interval <= timedelta(0)
            or self.heartbeat_interval * 3 > self.lease_duration
            or self.renewal_before <= timedelta(0)
            or self.rotation_overlap < timedelta(0)
            or self.rotation_overlap >= self.renewal_before
            or self.readiness_timeout <= timedelta(0)
            or self.drain_timeout <= timedelta(0)
        ):
            raise ValueError("Preview Gateway runtime configuration is invalid")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class PreviewGatewayRuntime:
    """Coordinate listener, durable identity, leaves, readiness, heartbeat, and drain."""

    def __init__(
        self,
        config: PreviewGatewayRuntimeConfig,
        *,
        directory: PreviewGatewayDirectoryAuthority,
        certificate_authority: PreviewGatewayCertificateAuthority,
        certificate_provider: PreviewGatewayCertificateProvider,
        relay_server: PreviewGatewayRelayServer,
        readiness_probe: PreviewGatewayReadinessProbe,
        drain_observer: PreviewGatewayDrainObserver,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._config = config
        self._directory = directory
        self._certificate_authority = certificate_authority
        self._certificate_provider = certificate_provider
        self._relay_server = relay_server
        self._readiness_probe = readiness_probe
        self._drain_observer = drain_observer
        self._clock = clock
        self._state = "new"
        self._ready = False
        self._registered = False
        self._relay_started = False
        self._certificates: PreviewGatewayRuntimeCertificateSet | None = None
        self._maintenance_task: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()
        self._transition_lock = asyncio.Lock()
        self._fatal_error: BaseException | None = None

    @property
    def state(self) -> str:
        return self._state

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def fatal_error(self) -> BaseException | None:
        return self._fatal_error

    async def start(self) -> None:
        async with self._transition_lock:
            if self._state != "new":
                raise PreviewGatewayRuntimeError(
                    "preview_gateway_runtime_already_started",
                    "Preview Gateway runtime is already started",
                )
            self._state = "starting"
            try:
                certificates = await self._certificate_provider.prepare(
                    gateway_instance_id=self._config.gateway_instance_id,
                    server_name=self._config.server_name,
                )
                self._certificates = certificates
                self._require_certificate_window(certificates)
                await self._certificate_provider.install(certificates)
                await self._relay_server.start(
                    host=self._config.bind_host,
                    port=self._config.bind_port,
                )
                self._relay_started = True
                connect_port = self._config.advertised_connect_port or self._relay_server.port
                await asyncio.to_thread(
                    self._directory.register_gateway,
                    gateway_instance_id=self._config.gateway_instance_id,
                    connect_host=self._config.connect_host,
                    connect_port=connect_port,
                    server_name=self._config.server_name,
                    failure_domain=self._config.failure_domain,
                    source_revision=self._config.source_revision,
                    adapter_contract_version=self._config.adapter_contract_version,
                    registration_token=self._config.registration_token,
                    lease_duration=self._config.lease_duration,
                )
                self._registered = True
                await self._activate_certificates(certificates)
                await asyncio.wait_for(
                    self._readiness_probe.verify(
                        gateway_instance_id=self._config.gateway_instance_id,
                        connect_host=self._config.connect_host,
                        connect_port=connect_port,
                        server_name=self._config.server_name,
                        certificates=certificates,
                    ),
                    timeout=self._config.readiness_timeout.total_seconds(),
                )
                await asyncio.to_thread(
                    self._directory.activate_gateway,
                    gateway_instance_id=self._config.gateway_instance_id,
                    registration_token=self._config.registration_token,
                )
            except Exception as exc:
                await self._cleanup_failed_start()
                self._fatal_error = exc
                self._state = "failed"
                self._closed.set()
                raise PreviewGatewayRuntimeError(
                    "preview_gateway_runtime_start_failed",
                    "Preview Gateway runtime failed to start",
                ) from exc
            self._state = "active"
            self._ready = True
            self._maintenance_task = asyncio.create_task(
                self._maintenance_loop(),
                name=f"preview-gateway-maintenance:{self._config.gateway_instance_id}",
            )

    async def wait(self) -> None:
        await self._closed.wait()
        if self._fatal_error is not None:
            raise PreviewGatewayRuntimeError(
                "preview_gateway_runtime_failed",
                "Preview Gateway runtime stopped after a fatal lifecycle failure",
            ) from self._fatal_error

    async def aclose(self, *, reason: str = "planned_shutdown") -> bool:
        async with self._transition_lock:
            if self._state in {"stopped", "failed"}:
                return False
            if self._state == "new":
                self._state = "stopped"
                self._closed.set()
                return True
            self._ready = False
            self._state = "draining"
            drain_started = False
            cleanup_errors: list[BaseException] = []
            try:
                if self._registered:
                    await asyncio.to_thread(
                        self._directory.begin_draining,
                        gateway_instance_id=self._config.gateway_instance_id,
                        registration_token=self._config.registration_token,
                    )
                    drain_started = True
                if drain_started:
                    with suppress(TimeoutError):
                        await asyncio.wait_for(
                            self._drain_observer.wait_until_drained(
                                gateway_instance_id=self._config.gateway_instance_id,
                                timeout_seconds=self._config.drain_timeout.total_seconds(),
                            ),
                            timeout=self._config.drain_timeout.total_seconds(),
                        )
            except Exception as exc:  # noqa: BLE001 - cleanup must still run to completion
                cleanup_errors.append(exc)
            finally:
                cleanup_errors.extend(
                    await self._cleanup_resources(
                        reason=reason,
                        cancel_maintenance=True,
                    )
                )
                self._state = "stopped"
                self._closed.set()
            if cleanup_errors:
                raise PreviewGatewayRuntimeError(
                    "preview_gateway_runtime_shutdown_failed",
                    "Preview Gateway runtime shutdown cleanup did not complete cleanly",
                ) from cleanup_errors[0]
            return True

    async def _maintenance_loop(self) -> None:
        try:
            while self._state in {"active", "draining"}:
                await asyncio.sleep(self._config.heartbeat_interval.total_seconds())
                if self._state not in {"active", "draining"}:
                    return
                await asyncio.to_thread(
                    self._directory.heartbeat_gateway,
                    gateway_instance_id=self._config.gateway_instance_id,
                    registration_token=self._config.registration_token,
                    lease_duration=self._config.lease_duration,
                )
                certificates = self._certificates
                if (
                    self._state == "active"
                    and certificates is not None
                    and certificates.minimum_not_after - self._clock()
                    <= self._config.renewal_before
                ):
                    await self._rotate_certificates()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - any maintenance failure is fail-closed
            self._fatal_error = exc
            await self._fail_closed()

    async def _rotate_certificates(self) -> None:
        previous = self._certificates
        replacement = await self._certificate_provider.prepare(
            gateway_instance_id=self._config.gateway_instance_id,
            server_name=self._config.server_name,
        )
        self._require_certificate_window(replacement)
        activated: list[ActivatedPreviewGatewayCertificate] = []
        try:
            activated = await self._activate_certificates(replacement)
            await self._certificate_provider.install(replacement)
        except Exception:
            await self._revoke_receipts(
                activated,
                reason="gateway_runtime_rotation_install_failed",
            )
            with suppress(Exception):
                await self._certificate_provider.discard(replacement)
            raise
        self._certificates = replacement
        if previous is not None:
            await self._certificate_provider.discard(previous)

    async def _activate_certificates(
        self, certificates: PreviewGatewayRuntimeCertificateSet
    ) -> list[ActivatedPreviewGatewayCertificate]:
        activated: list[ActivatedPreviewGatewayCertificate] = []
        try:
            for leaf in certificates.leaves:
                receipt = await asyncio.to_thread(
                    self._certificate_authority.activate_certificate,
                    gateway_instance_id=self._config.gateway_instance_id,
                    purpose=leaf.purpose,
                    certificate_der=leaf.certificate_der,
                    trust_bundle_version=leaf.trust_bundle_version,
                    rotation_overlap=self._config.rotation_overlap,
                )
                activated.append(receipt)
        except Exception:
            await self._revoke_receipts(
                activated,
                reason="gateway_runtime_certificate_pair_activation_failed",
            )
            raise
        return activated

    def _require_certificate_window(
        self, certificates: PreviewGatewayRuntimeCertificateSet
    ) -> None:
        if certificates.minimum_not_after <= self._clock() + self._config.renewal_before:
            raise PreviewGatewayRuntimeError(
                "preview_gateway_runtime_certificate_window_invalid",
                "Preview Gateway certificate validity window is too short",
            )

    async def _cleanup_failed_start(self) -> None:
        self._ready = False
        await self._cleanup_resources(
            reason="gateway_runtime_start_failed",
            cancel_maintenance=False,
        )

    async def _fail_closed(self) -> None:
        async with self._transition_lock:
            if self._state == "stopped":
                self._closed.set()
                return
            self._ready = False
            self._state = "failed"
            await self._cleanup_resources(
                reason="gateway_runtime_maintenance_failed",
                cancel_maintenance=False,
            )
            self._closed.set()

    async def _cleanup_resources(
        self,
        *,
        reason: str,
        cancel_maintenance: bool,
    ) -> list[BaseException]:
        errors: list[BaseException] = []
        if self._relay_started:
            try:
                await self._relay_server.aclose()
            except Exception as exc:  # noqa: BLE001 - continue fail-closed cleanup
                errors.append(exc)
            finally:
                self._relay_started = False
        if cancel_maintenance:
            task = self._maintenance_task
            self._maintenance_task = None
            if task is not None and task is not asyncio.current_task():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception as exc:  # noqa: BLE001 - continue remaining cleanup
                    errors.append(exc)
        await self._release_registration(reason=reason)
        certificates = self._certificates
        if certificates is not None:
            await self._revoke_certificates(certificates, reason=reason)
            try:
                await self._discard_certificates()
            except Exception as exc:  # noqa: BLE001 - surface after every cleanup step
                errors.append(exc)
        return errors

    async def _revoke_certificates(
        self,
        certificates: PreviewGatewayRuntimeCertificateSet,
        *,
        reason: str,
    ) -> None:
        for leaf in certificates.leaves:
            with suppress(Exception):
                await asyncio.to_thread(
                    self._certificate_authority.revoke_certificate,
                    fingerprint_sha256=leaf.fingerprint_sha256,
                    reason=reason,
                )

    async def _revoke_receipts(
        self,
        receipts: list[ActivatedPreviewGatewayCertificate],
        *,
        reason: str,
    ) -> None:
        for receipt in receipts:
            with suppress(Exception):
                await asyncio.to_thread(
                    self._certificate_authority.revoke_certificate,
                    fingerprint_sha256=receipt.fingerprint_sha256,
                    reason=reason,
                )

    async def _release_registration(self, *, reason: str) -> None:
        if not self._registered:
            return
        try:
            await asyncio.to_thread(
                self._directory.release_gateway,
                gateway_instance_id=self._config.gateway_instance_id,
                registration_token=self._config.registration_token,
                reason=reason,
            )
        except Exception:  # noqa: BLE001 - listener is already closed; lease expiry is fallback
            # Listener closure is authoritative during a database outage; the durable
            # lease remains bounded and the platform reconciler will expire it.
            pass
        finally:
            self._registered = False

    async def _discard_certificates(self) -> None:
        certificates = self._certificates
        self._certificates = None
        if certificates is not None:
            await self._certificate_provider.discard(certificates)


async def run_preview_gateway_runtime(runtime: PreviewGatewayRuntime) -> None:
    """Run until SIGTERM/SIGINT or a fatal maintenance failure."""

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    installed: list[signal.Signals] = []
    for candidate in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(candidate, stop.set)
            installed.append(candidate)
        except (NotImplementedError, RuntimeError):
            continue
    wait_for_signal: asyncio.Task[bool] | None = None
    wait_for_runtime: asyncio.Task[None] | None = None
    try:
        await runtime.start()
        wait_for_signal = asyncio.create_task(stop.wait())
        wait_for_runtime = asyncio.create_task(runtime.wait())
        done, _ = await asyncio.wait(
            {wait_for_signal, wait_for_runtime},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if wait_for_runtime in done:
            await wait_for_runtime
        else:
            await runtime.aclose(reason="process_signal")
    finally:
        for task in (wait_for_signal, wait_for_runtime):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (wait_for_signal, wait_for_runtime) if task is not None),
            return_exceptions=True,
        )
        for candidate in installed:
            loop.remove_signal_handler(candidate)


__all__ = [
    "PreviewGatewayCertificateProvider",
    "PreviewGatewayDrainObserver",
    "PreviewGatewayReadinessProbe",
    "PreviewGatewayRelayServer",
    "PreviewGatewayRuntime",
    "PreviewGatewayRuntimeCertificateSet",
    "PreviewGatewayRuntimeConfig",
    "PreviewGatewayRuntimeError",
    "PreviewGatewayRuntimeLeaf",
    "run_preview_gateway_runtime",
]
