from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from omnigent.runner.identity import token_bound_runner_id
from omnigent.runner.transports.ws_tunnel.frames import HelloFrame
from omnigent.runner.transports.ws_tunnel.registry import TunnelRegistry
from saas.control_plane import PreviewRouteGrant
from saas.control_plane.preview_tunnel_registration import (
    PreviewTunnelBindingGrant,
    PreviewTunnelRegistrationError,
)
from saas.preview_tunnel import LocalRunnerTunnelBindings, PreviewTunnelAdapterError
from saas.production.preview_owner import (
    PreviewOwnerTunnelLifecycle,
    ProductionPreviewOwner,
    ProductionPreviewOwnerConfig,
    ProductionPreviewOwnerError,
    create_preview_owner_tunnel_app,
    verify_installed_preview_owner_lineage,
)


class _WebSocket:
    def __init__(self) -> None:
        self.closed: list[tuple[int, str]] = []

    async def send_text(self, _data: str) -> None:  # pragma: no cover - sender idle
        return None

    async def receive_text(self) -> str:  # pragma: no cover - receiver idle
        return await asyncio.Future()

    async def close(self, *, code: int, reason: str) -> None:
        self.closed.append((code, reason))


def _hello() -> HelloFrame:
    return HelloFrame(
        runner_version="test",
        frame_protocol_version=1,
        harnesses=["codex"],
        envs=["local"],
    )


def _grant(
    *,
    official_runner_id: str,
    runner_id: UUID | None = None,
    generation: int = 7,
    runtime_placement_id: UUID | None = None,
) -> PreviewTunnelBindingGrant:
    return PreviewTunnelBindingGrant(
        registration_id=uuid4(),
        runner_id=runner_id or uuid4(),
        connection_generation=generation,
        runtime_placement_id=runtime_placement_id or uuid4(),
        tunnel_placement_id=uuid4(),
        routing_generation=3,
        relay_subject="rtp_" + "a" * 32,
        official_runner_id=official_runner_id,
    )


def _route(grant: PreviewTunnelBindingGrant) -> PreviewRouteGrant:
    return PreviewRouteGrant(
        preview_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        runner_id=grant.runner_id,
        runner_connection_generation=grant.connection_generation,
        run_id=uuid4(),
        run_fence_token=9,
        worktree_id=uuid4(),
        worktree_lease_generation=4,
        opaque_preview_key="pvr_owner_contract",
        preview_token_hash="a" * 64,
        upstream_request_headers={},
        response_headers={"Content-Security-Policy": "sandbox"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        preview_host="preview.example.test",
    )


class _Authority:
    def __init__(self, grant: PreviewTunnelBindingGrant) -> None:
        self.grant = grant
        self.connected = False
        self.current = True
        self.disconnections = 0
        self._lock = threading.Lock()

    def preauthorize(
        self, *, official_runner_id: str, registration_token: str
    ) -> PreviewTunnelBindingGrant | None:
        del registration_token
        return self.grant if official_runner_id == self.grant.official_runner_id else None

    def redeem(
        self, *, official_runner_id: str, registration_token: str
    ) -> PreviewTunnelBindingGrant:
        del registration_token
        with self._lock:
            if self.connected or official_runner_id != self.grant.official_runner_id:
                raise PreviewTunnelRegistrationError("preview_tunnel_registration_stale")
            self.connected = True
            return self.grant

    def heartbeat(self, *, official_runner_id: str, registration_token: str) -> bool:
        del official_runner_id, registration_token
        return self.current

    def disconnect(self, *, official_runner_id: str, registration_token: str) -> bool:
        del official_runner_id, registration_token
        with self._lock:
            if not self.connected:
                return False
            self.connected = False
            self.disconnections += 1
            return True


def _registry_with_session(official_runner_id: str) -> tuple[TunnelRegistry, _WebSocket]:
    registry = TunnelRegistry()
    websocket = _WebSocket()
    registry.register(official_runner_id, websocket, _hello())
    return registry, websocket


@pytest.mark.asyncio
async def test_owner_registration_is_one_use_across_replicas() -> None:
    token = "r" * 48
    official_runner_id = token_bound_runner_id(token)
    grant = _grant(official_runner_id=official_runner_id)
    authority = _Authority(grant)
    registry_a, _socket_a = _registry_with_session(official_runner_id)
    registry_b, socket_b = _registry_with_session(official_runner_id)
    lifecycle_a = PreviewOwnerTunnelLifecycle(
        registry_a, LocalRunnerTunnelBindings(registry_a), authority
    )
    lifecycle_b = PreviewOwnerTunnelLifecycle(
        registry_b, LocalRunnerTunnelBindings(registry_b), authority
    )

    reservation_a, reservation_b = await asyncio.gather(
        lifecycle_a.reserve(official_runner_id=official_runner_id, registration_token=token),
        lifecycle_b.reserve(official_runner_id=official_runner_id, registration_token=token),
    )
    await lifecycle_a.connected(reservation_a, official_runner_id)
    with pytest.raises(PreviewTunnelRegistrationError) as replayed:
        await lifecycle_b.connected(reservation_b, official_runner_id)
    assert replayed.value.code == "preview_tunnel_registration_stale"
    assert socket_b.closed

    await lifecycle_b.finish(reservation_b, official_runner_id)
    await lifecycle_a.finish(reservation_a, official_runner_id)
    assert authority.disconnections == 1


@pytest.mark.asyncio
async def test_owner_rejects_wrong_placement_without_leaking_binding() -> None:
    token = "s" * 48
    official_runner_id = token_bound_runner_id(token)
    preauthorized = _grant(official_runner_id=official_runner_id)
    authority = _Authority(preauthorized)
    authority.grant = replace(authority.grant, runtime_placement_id=uuid4())
    registry, websocket = _registry_with_session(official_runner_id)
    bindings = LocalRunnerTunnelBindings(registry)
    lifecycle = PreviewOwnerTunnelLifecycle(registry, bindings, authority)
    reservation = await lifecycle.reserve(
        official_runner_id=official_runner_id, registration_token=token
    )
    authority.grant = replace(
        authority.grant,
        registration_id=preauthorized.registration_id,
        runtime_placement_id=uuid4(),
    )

    with pytest.raises(PreviewTunnelRegistrationError) as mismatch:
        await lifecycle.connected(reservation, official_runner_id)
    assert mismatch.value.code == "preview_tunnel_registration_stale"
    with pytest.raises(PreviewTunnelAdapterError):
        bindings.resolve(_route(preauthorized))
    assert websocket.closed
    await lifecycle.finish(reservation, official_runner_id)


@pytest.mark.asyncio
async def test_old_disconnect_cannot_remove_new_generation_binding() -> None:
    runner_id = uuid4()
    old_token = "o" * 48
    new_token = "n" * 48
    old_official = token_bound_runner_id(old_token)
    new_official = token_bound_runner_id(new_token)
    old_grant = _grant(official_runner_id=old_official, runner_id=runner_id, generation=7)
    new_grant = _grant(official_runner_id=new_official, runner_id=runner_id, generation=8)
    registry = TunnelRegistry()
    registry.register(old_official, _WebSocket(), _hello())
    registry.register(new_official, _WebSocket(), _hello())
    bindings = LocalRunnerTunnelBindings(registry)
    old_lifecycle = PreviewOwnerTunnelLifecycle(registry, bindings, _Authority(old_grant))
    new_lifecycle = PreviewOwnerTunnelLifecycle(registry, bindings, _Authority(new_grant))
    old_reservation = await old_lifecycle.reserve(
        official_runner_id=old_official, registration_token=old_token
    )
    await old_lifecycle.connected(old_reservation, old_official)
    new_reservation = await new_lifecycle.reserve(
        official_runner_id=new_official, registration_token=new_token
    )
    await new_lifecycle.connected(new_reservation, new_official)

    await old_lifecycle.disconnected(old_reservation, old_official)
    assert bindings.resolve(_route(new_grant)).connection_generation == 8
    await new_lifecycle.disconnected(new_reservation, new_official)


def test_owner_app_exposes_only_guarded_tunnel_and_health() -> None:
    token = "x" * 48
    official_runner_id = token_bound_runner_id(token)
    registry = TunnelRegistry()
    app, _lifecycle = create_preview_owner_tunnel_app(
        registry=registry,
        bindings=LocalRunnerTunnelBindings(registry),
        authority=_Authority(_grant(official_runner_id=official_runner_id)),
    )

    paths = {(route.path, type(route).__name__) for route in app.routes}
    assert ("/v1/runners/{runner_id}/tunnel", "APIWebSocketRoute") in paths
    assert ("/livez", "APIRoute") in paths
    assert ("/readyz", "APIRoute") in paths
    assert all("/token" not in path and path != "/v1/runners" for path, _kind in paths)


def test_owner_readiness_is_content_blind_and_authority_backed() -> None:
    token = "z" * 48
    official_runner_id = token_bound_runner_id(token)
    registry = TunnelRegistry()
    state = {"ready": False}

    def probe() -> None:
        if not state["ready"]:
            raise RuntimeError("database-host-and-certificate-detail")

    app, _lifecycle = create_preview_owner_tunnel_app(
        registry=registry,
        bindings=LocalRunnerTunnelBindings(registry),
        authority=_Authority(_grant(official_runner_id=official_runner_id)),
        readiness_probe=probe,
    )
    client = TestClient(app)

    unavailable = client.get("/readyz")
    assert unavailable.status_code == 503
    assert unavailable.json() == {"status": "unavailable"}
    assert "database-host" not in unavailable.text
    assert unavailable.headers["cache-control"] == "no-store"

    state["ready"] = True
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}


def test_owner_lineage_requires_installed_exact_source_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from omnigent import _build_info

    config = cast(
        ProductionPreviewOwnerConfig,
        SimpleNamespace(relay=SimpleNamespace(source_revision="a" * 40)),
    )
    monkeypatch.setattr(_build_info, "COMMIT_SHA", "a" * 40)
    verify_installed_preview_owner_lineage(config)

    monkeypatch.setattr(_build_info, "COMMIT_SHA", "b" * 40)
    with pytest.raises(ProductionPreviewOwnerError, match="does not match"):
        verify_installed_preview_owner_lineage(config)


@pytest.mark.asyncio
async def test_owner_gateway_lease_failure_is_a_process_failure() -> None:
    class _GatewayLease:
        calls = 0

        def heartbeat_gateway(self) -> bool:
            self.calls += 1
            return self.calls < 2

    owner = object.__new__(ProductionPreviewOwner)
    owner.config = cast(
        ProductionPreviewOwnerConfig,
        SimpleNamespace(heartbeat_seconds=0.001),
    )
    owner._gateway_authority = _GatewayLease()

    with pytest.raises(ProductionPreviewOwnerError, match="lease is stale"):
        await asyncio.wait_for(owner._maintain_gateway_lease(asyncio.Event()), timeout=1)
