"""Standalone Preview Owner with one-use official Runner WebSocket registration."""

from __future__ import annotations

import asyncio
import contextvars
import os
import re
import signal
import ssl
import stat
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID, uuid4

import uvicorn
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi import FastAPI, Response, WebSocket
from fastapi.responses import JSONResponse
from fastapi.routing import APIWebSocketRoute

from omnigent.runner.identity import RUNNER_TUNNEL_TOKEN_HEADER, token_bound_runner_id
from omnigent.runner.transports.ws_tunnel.registry import TunnelRegistry
from omnigent.server.routes.runner_tunnel import (
    RUNNER_ID_MISMATCH_CLOSE_CODE,
    create_runner_tunnel_router,
)
from saas.control_plane.preview_tunnel_registration import (
    PreviewTunnelBindingGrant,
    PreviewTunnelOwnerAuthority,
    PreviewTunnelRegistrationError,
)
from saas.preview_relay_transport import PreviewRelayTransportError
from saas.preview_tunnel import LocalRunnerTunnelBindings, RunnerTunnelBinding
from saas.production.preview_relay import (
    ProductionPreviewRelayOwner,
    ProductionPreviewRelayOwnerConfig,
    build_production_preview_relay_owner,
    load_production_preview_relay_owner_config,
)

_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_CONNECTION_RESERVATION: contextvars.ContextVar[UUID | None] = contextvars.ContextVar(
    "preview_owner_connection_reservation", default=None
)


class ProductionPreviewOwnerError(RuntimeError):
    """Stable fail-closed standalone Owner error."""


class PreviewOwnerTunnelAuthority(Protocol):
    def preauthorize(
        self,
        *,
        official_runner_id: str,
        registration_token: str,
    ) -> PreviewTunnelBindingGrant | None: ...

    def redeem(
        self,
        *,
        official_runner_id: str,
        registration_token: str,
    ) -> PreviewTunnelBindingGrant: ...

    def heartbeat(
        self,
        *,
        official_runner_id: str,
        registration_token: str,
    ) -> bool: ...

    def disconnect(
        self,
        *,
        official_runner_id: str,
        registration_token: str,
    ) -> bool: ...


class PreviewOwnerGatewayLeaseAuthority(Protocol):
    def heartbeat_gateway(self) -> bool: ...

    def release_gateway(self) -> bool: ...


@dataclass(slots=True)
class _TunnelState:
    reservation_id: UUID
    official_runner_id: str
    registration_token: str = field(repr=False)
    preauthorized: PreviewTunnelBindingGrant
    redeemed: PreviewTunnelBindingGrant | None = None
    binding: RunnerTunnelBinding | None = None
    heartbeat_task: asyncio.Task[None] | None = field(default=None, repr=False)
    finished: bool = False


class PreviewOwnerTunnelLifecycle:
    """Bind DB one-use registration, official session, and local route atomically."""

    def __init__(
        self,
        registry: TunnelRegistry,
        bindings: LocalRunnerTunnelBindings,
        authority: PreviewOwnerTunnelAuthority,
        *,
        heartbeat_seconds: float = 15.0,
    ) -> None:
        if not 1 <= heartbeat_seconds <= 30:
            raise ValueError("Preview tunnel heartbeat interval is invalid")
        self._registry = registry
        self._bindings = bindings
        self._authority = authority
        self._heartbeat_seconds = heartbeat_seconds
        self._states: dict[UUID, _TunnelState] = {}
        self._runner_reservations: dict[str, UUID] = {}
        self._lock = asyncio.Lock()

    async def reserve(self, *, official_runner_id: str, registration_token: str) -> UUID:
        if (
            not registration_token
            or registration_token != registration_token.strip()
            or token_bound_runner_id(registration_token) != official_runner_id
        ):
            raise PreviewTunnelRegistrationError("preview_tunnel_registration_stale")
        preauthorized = await asyncio.to_thread(
            self._authority.preauthorize,
            official_runner_id=official_runner_id,
            registration_token=registration_token,
        )
        if preauthorized is None or preauthorized.official_runner_id != official_runner_id:
            raise PreviewTunnelRegistrationError("preview_tunnel_registration_stale")
        reservation_id = uuid4()
        async with self._lock:
            if official_runner_id in self._runner_reservations:
                raise PreviewTunnelRegistrationError("preview_tunnel_registration_replayed")
            self._runner_reservations[official_runner_id] = reservation_id
            self._states[reservation_id] = _TunnelState(
                reservation_id=reservation_id,
                official_runner_id=official_runner_id,
                registration_token=registration_token,
                preauthorized=preauthorized,
            )
        return reservation_id

    async def connected(self, reservation_id: UUID, official_runner_id: str) -> None:
        state = await self._state(reservation_id, official_runner_id)
        redeemed = False
        binding: RunnerTunnelBinding | None = None
        try:
            grant = await asyncio.to_thread(
                self._authority.redeem,
                official_runner_id=official_runner_id,
                registration_token=state.registration_token,
            )
            redeemed = True
            if (
                grant.registration_id != state.preauthorized.registration_id
                or grant.runner_id != state.preauthorized.runner_id
                or grant.connection_generation != state.preauthorized.connection_generation
                or grant.runtime_placement_id != state.preauthorized.runtime_placement_id
                or grant.official_runner_id != official_runner_id
            ):
                raise PreviewTunnelRegistrationError("preview_tunnel_registration_stale")
            binding = self._bindings.bind(
                runner_id=grant.runner_id,
                connection_generation=grant.connection_generation,
                official_runner_id=official_runner_id,
            )
            async with self._lock:
                current = self._states.get(reservation_id)
                if current is not state or state.finished:
                    raise PreviewTunnelRegistrationError("preview_tunnel_registration_stale")
                state.redeemed = grant
                state.binding = binding
                state.heartbeat_task = asyncio.create_task(
                    self._heartbeat(reservation_id),
                    name=f"preview-tunnel-heartbeat:{grant.runner_id}:{grant.connection_generation}",
                )
        except Exception:
            if binding is not None:
                self._bindings.unbind(binding)
            if redeemed:
                with suppress(Exception):
                    await asyncio.to_thread(
                        self._authority.disconnect,
                        official_runner_id=official_runner_id,
                        registration_token=state.registration_token,
                    )
            await self._close_official_session(official_runner_id, "registration rejected")
            raise

    async def disconnected(self, reservation_id: UUID, official_runner_id: str) -> None:
        state = await self._remove(reservation_id, official_runner_id)
        if state is None:
            return
        task = state.heartbeat_task
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        if state.binding is not None:
            self._bindings.unbind(state.binding)
        if state.redeemed is not None:
            with suppress(Exception):
                await asyncio.to_thread(
                    self._authority.disconnect,
                    official_runner_id=official_runner_id,
                    registration_token=state.registration_token,
                )

    async def finish(self, reservation_id: UUID, official_runner_id: str) -> None:
        await self.disconnected(reservation_id, official_runner_id)

    async def aclose(self) -> None:
        async with self._lock:
            values = tuple(
                (reservation_id, state.official_runner_id)
                for reservation_id, state in self._states.items()
            )
        for reservation_id, official_runner_id in values:
            await self._close_official_session(official_runner_id, "owner shutdown")
            await self.disconnected(reservation_id, official_runner_id)

    async def _heartbeat(self, reservation_id: UUID) -> None:
        while True:
            await asyncio.sleep(self._heartbeat_seconds)
            async with self._lock:
                state = self._states.get(reservation_id)
                if state is None or state.finished:
                    return
                official_runner_id = state.official_runner_id
                registration_token = state.registration_token
            try:
                current = await asyncio.to_thread(
                    self._authority.heartbeat,
                    official_runner_id=official_runner_id,
                    registration_token=registration_token,
                )
            except Exception:  # noqa: BLE001 - any authority outage expires ownership
                current = False
            if not current:
                await self._close_official_session(official_runner_id, "ownership expired")
                await self.disconnected(reservation_id, official_runner_id)
                return

    async def _state(self, reservation_id: UUID, official_runner_id: str) -> _TunnelState:
        async with self._lock:
            state = self._states.get(reservation_id)
            if (
                state is None
                or state.finished
                or state.official_runner_id != official_runner_id
                or self._runner_reservations.get(official_runner_id) != reservation_id
            ):
                raise PreviewTunnelRegistrationError("preview_tunnel_registration_stale")
            return state

    async def _remove(self, reservation_id: UUID, official_runner_id: str) -> _TunnelState | None:
        async with self._lock:
            state = self._states.get(reservation_id)
            if state is None or state.official_runner_id != official_runner_id or state.finished:
                return None
            state.finished = True
            self._states.pop(reservation_id, None)
            if self._runner_reservations.get(official_runner_id) == reservation_id:
                self._runner_reservations.pop(official_runner_id, None)
            return state

    async def _close_official_session(self, official_runner_id: str, reason: str) -> None:
        session = self._registry.get(official_runner_id)
        if session is None:
            return
        close = getattr(session.ws, "close", None)
        if callable(close):
            with suppress(Exception):
                close_call = cast(Callable[..., Awaitable[None]], close)
                await close_call(code=RUNNER_ID_MISMATCH_CLOSE_CODE, reason=reason)
        self._registry.deregister(official_runner_id, session)


def create_preview_owner_tunnel_app(
    *,
    registry: TunnelRegistry,
    bindings: LocalRunnerTunnelBindings,
    authority: PreviewOwnerTunnelAuthority,
    heartbeat_seconds: float = 15.0,
    readiness_probe: Callable[[], None] | None = None,
) -> tuple[FastAPI, PreviewOwnerTunnelLifecycle]:
    """Mount only the downstream-guarded official WS endpoint plus health probes."""

    lifecycle = PreviewOwnerTunnelLifecycle(
        registry,
        bindings,
        authority,
        heartbeat_seconds=heartbeat_seconds,
    )

    async def on_connect(official_runner_id: str) -> None:
        reservation_id = _CONNECTION_RESERVATION.get()
        if reservation_id is None:
            raise PreviewTunnelRegistrationError("preview_tunnel_registration_stale")
        await lifecycle.connected(reservation_id, official_runner_id)

    async def on_disconnect(official_runner_id: str) -> None:
        reservation_id = _CONNECTION_RESERVATION.get()
        if reservation_id is not None:
            await lifecycle.disconnected(reservation_id, official_runner_id)

    official = create_runner_tunnel_router(
        registry,
        on_runner_connect=on_connect,
        on_runner_disconnect=on_disconnect,
    )
    websocket_routes = [route for route in official.routes if isinstance(route, APIWebSocketRoute)]
    if len(websocket_routes) != 1 or websocket_routes[0].path != "/runners/{runner_id}/tunnel":
        raise ProductionPreviewOwnerError("Official Runner tunnel route contract changed")
    official_endpoint = websocket_routes[0].endpoint
    app = FastAPI(title="Omnigent Preview Owner", docs_url=None, redoc_url=None)

    @app.websocket("/v1/runners/{runner_id}/tunnel")
    async def tunnel(websocket: WebSocket, runner_id: str) -> None:
        token = websocket.headers.get(RUNNER_TUNNEL_TOKEN_HEADER, "")
        try:
            reservation_id = await lifecycle.reserve(
                official_runner_id=runner_id,
                registration_token=token,
            )
        except (PreviewTunnelRegistrationError, ValueError):
            await websocket.close(
                code=RUNNER_ID_MISMATCH_CLOSE_CODE,
                reason="registration rejected",
            )
            return
        reset = _CONNECTION_RESERVATION.set(reservation_id)
        try:
            await official_endpoint(websocket, runner_id)
        finally:
            await lifecycle.finish(reservation_id, runner_id)
            _CONNECTION_RESERVATION.reset(reset)

    @app.get("/livez", include_in_schema=False)
    def livez(response: Response) -> dict[str, str]:
        response.headers["Cache-Control"] = "no-store"
        return {"status": "live"}

    @app.get("/readyz", include_in_schema=False, response_model=None)
    def readyz(response: Response) -> dict[str, str] | JSONResponse:
        response.headers["Cache-Control"] = "no-store"
        if readiness_probe is not None:
            try:
                readiness_probe()
            except Exception:  # noqa: BLE001 - readiness stays content-blind.
                return JSONResponse(
                    {"status": "unavailable"},
                    status_code=503,
                    headers={"Cache-Control": "no-store"},
                )
        return {"status": "ready"}

    return app, lifecycle


@dataclass(frozen=True, slots=True)
class ProductionPreviewOwnerConfig:
    relay: ProductionPreviewRelayOwnerConfig
    gateway_registration_token_path: Path = field(repr=False)
    runner_tunnel_bind_host: str
    runner_tunnel_port: int
    runner_tunnel_server_name: str
    heartbeat_seconds: float


def _owner_secret_file(source: Mapping[str, str], name: str) -> Path:
    raw = source.get(name, "")
    path = Path(raw)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProductionPreviewOwnerError(f"{name} is unavailable") from error
    if (
        not raw
        or raw != raw.strip()
        or not path.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or not 32 <= metadata.st_size <= 512
    ):
        raise ProductionPreviewOwnerError(f"{name} is unavailable")
    return path


def load_production_preview_owner_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionPreviewOwnerConfig:
    source: Mapping[str, str] = os.environ if environ is None else environ
    relay = load_production_preview_relay_owner_config(source)
    bind_host = source.get("OMNIGENT_SAAS_PREVIEW_RUNNER_TUNNEL_BIND_HOST", "")
    server_name = source.get("OMNIGENT_SAAS_PREVIEW_RUNNER_TUNNEL_SERVER_NAME", "").lower()
    try:
        port = int(source.get("OMNIGENT_SAAS_PREVIEW_RUNNER_TUNNEL_PORT", "9442"))
        heartbeat_seconds = float(
            source.get("OMNIGENT_SAAS_PREVIEW_RUNNER_TUNNEL_HEARTBEAT_SECONDS", "15")
        )
        relay.relay_endpoint_policy.require_allowed_name(server_name)
        relay.relay_endpoint_policy.require_allowed_port(port)
    except (ValueError, PreviewRelayTransportError) as error:
        raise ProductionPreviewOwnerError("Preview Owner tunnel endpoint is invalid") from error
    if (
        bind_host not in {"0.0.0.0", "::"}
        or _HOST.fullmatch(server_name) is None
        or port == relay.bind_port
        or not 1 <= heartbeat_seconds <= 15
    ):
        raise ProductionPreviewOwnerError("Preview Owner tunnel endpoint is invalid")
    return ProductionPreviewOwnerConfig(
        relay=relay,
        gateway_registration_token_path=_owner_secret_file(
            source, "OMNIGENT_SAAS_PREVIEW_GATEWAY_REGISTRATION_TOKEN_FILE"
        ),
        runner_tunnel_bind_host=bind_host,
        runner_tunnel_port=port,
        runner_tunnel_server_name=server_name,
        heartbeat_seconds=heartbeat_seconds,
    )


def _gateway_token(path: Path) -> str:
    try:
        token = path.read_text(encoding="ascii").rstrip("\r\n")
    except (OSError, UnicodeError) as error:
        raise ProductionPreviewOwnerError(
            "Preview Owner gateway credential is unavailable"
        ) from error
    if not 32 <= len(token) <= 512 or token != token.strip() or "\x00" in token:
        raise ProductionPreviewOwnerError("Preview Owner gateway credential is unavailable")
    return token


def _assert_tunnel_server_certificate(config: ProductionPreviewOwnerConfig) -> None:
    try:
        certificate = x509.load_pem_x509_certificate(
            config.relay.relay_server_certificate_path.read_bytes()
        )
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except (OSError, ValueError, x509.ExtensionNotFound) as error:
        raise ProductionPreviewOwnerError("Preview Owner server certificate is invalid") from error
    if (
        config.runner_tunnel_server_name not in san.get_values_for_type(x509.DNSName)
        or ExtendedKeyUsageOID.SERVER_AUTH not in eku
    ):
        raise ProductionPreviewOwnerError("Preview Owner server certificate is invalid")


class ProductionPreviewOwner:
    """One process owns the registry, WSS lifecycle, relay listener, and DB placement."""

    def __init__(
        self,
        config: ProductionPreviewOwnerConfig,
        relay: ProductionPreviewRelayOwner,
        authority: PreviewTunnelOwnerAuthority,
    ) -> None:
        _assert_tunnel_server_certificate(config)
        self.config = config
        self.relay = relay
        self._gateway_authority = cast(PreviewOwnerGatewayLeaseAuthority, authority)
        self.app, self.lifecycle = create_preview_owner_tunnel_app(
            registry=relay.registry,
            bindings=relay.bindings,
            authority=authority,
            heartbeat_seconds=config.heartbeat_seconds,
            readiness_probe=relay.assert_production_ready,
        )
        self._server: uvicorn.Server | None = None

    async def _maintain_gateway_lease(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.config.heartbeat_seconds)
            if stop.is_set():
                return
            try:
                renewed = await asyncio.to_thread(self._gateway_authority.heartbeat_gateway)
            except Exception as error:
                raise ProductionPreviewOwnerError(
                    "Preview Owner gateway lease renewal failed"
                ) from error
            if not renewed:
                raise ProductionPreviewOwnerError("Preview Owner gateway lease is stale")

    def assert_production_ready(self) -> None:
        self.relay.assert_production_ready()
        if self._server is not None and not self._server.started:
            raise ProductionPreviewOwnerError("Preview Owner WSS listener is not ready")

    async def run(self, stop: asyncio.Event) -> None:
        if not await asyncio.to_thread(self._gateway_authority.heartbeat_gateway):
            raise ProductionPreviewOwnerError("Preview Owner gateway lease is stale")
        await self.relay.start()
        uvicorn_config = uvicorn.Config(
            self.app,
            host=self.config.runner_tunnel_bind_host,
            port=self.config.runner_tunnel_port,
            proxy_headers=False,
            server_header=False,
            ssl_certfile=str(self.config.relay.relay_server_certificate_path),
            ssl_keyfile=str(self.config.relay.relay_server_key_path),
            ssl_cert_reqs=ssl.CERT_NONE,
        )
        uvicorn_config.load()
        tls_context = uvicorn_config.ssl
        if not isinstance(tls_context, ssl.SSLContext):
            raise ProductionPreviewOwnerError("Preview Owner TLS context is unavailable")
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.maximum_version = ssl.TLSVersion.TLSv1_3
        server = uvicorn.Server(uvicorn_config)
        self._server = server
        serving = asyncio.create_task(server.serve(), name="preview-owner-wss")
        stopping = asyncio.create_task(stop.wait(), name="preview-owner-stop")
        gateway_lease = asyncio.create_task(
            self._maintain_gateway_lease(stop), name="preview-owner-gateway-lease"
        )
        try:
            done, _pending = await asyncio.wait(
                {serving, stopping, gateway_lease},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if serving in done and not stop.is_set():
                raise ProductionPreviewOwnerError("Preview Owner WSS listener stopped")
            if gateway_lease in done and not stop.is_set():
                failure = gateway_lease.exception()
                if failure is not None:
                    raise failure
                raise ProductionPreviewOwnerError("Preview Owner gateway lease stopped")
            server.should_exit = True
            await serving
        finally:
            stopping.cancel()
            gateway_lease.cancel()
            with suppress(asyncio.CancelledError):
                await stopping
            with suppress(asyncio.CancelledError):
                await gateway_lease
            with suppress(Exception):
                await asyncio.to_thread(self._gateway_authority.release_gateway)
            await self.lifecycle.aclose()
            await self.relay.aclose()
            self._server = None

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        with suppress(Exception):
            await asyncio.to_thread(self._gateway_authority.release_gateway)
        await self.lifecycle.aclose()
        await self.relay.aclose()

    def close(self) -> None:
        self.relay.close()


def build_production_preview_owner(
    *, config: ProductionPreviewOwnerConfig | None = None
) -> ProductionPreviewOwner:
    owner_config = config or load_production_preview_owner_config()
    relay = build_production_preview_relay_owner(config=owner_config.relay)
    authority = PreviewTunnelOwnerAuthority(
        relay.session_factory,
        gateway_instance_id=owner_config.relay.gateway_instance_id,
        gateway_registration_token=_gateway_token(owner_config.gateway_registration_token_path),
    )
    return ProductionPreviewOwner(owner_config, relay, authority)


def verify_installed_preview_owner_lineage(config: ProductionPreviewOwnerConfig) -> None:
    """Bind the standalone Owner process to the wheel's exact source revision."""

    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError) as error:
        raise ProductionPreviewOwnerError(
            "Installed Preview Owner release identity is unavailable"
        ) from error
    if installed_revision != config.relay.source_revision:
        raise ProductionPreviewOwnerError(
            "Installed Preview Owner release identity does not match configuration"
        )


async def _run(config: ProductionPreviewOwnerConfig) -> None:
    owner = build_production_preview_owner(config=config)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for value in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError):
            loop.add_signal_handler(value, stop.set)
    try:
        await owner.run(stop)
    finally:
        owner.close()


def main(_argv: Sequence[str] | None = None) -> int:
    config = load_production_preview_owner_config()
    verify_installed_preview_owner_lineage(config)
    asyncio.run(_run(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PreviewOwnerTunnelLifecycle",
    "ProductionPreviewOwner",
    "ProductionPreviewOwnerConfig",
    "ProductionPreviewOwnerError",
    "build_production_preview_owner",
    "create_preview_owner_tunnel_app",
    "load_production_preview_owner_config",
    "main",
    "verify_installed_preview_owner_lineage",
]
