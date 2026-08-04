from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    ControlPlaneOutboxEvent,
    PreviewRouteGrant,
    RunnerConnection,
    RunnerTunnelPlacement,
    RunnerTunnelPlacementAuthority,
    RunnerTunnelPlacementError,
    RunnerTunnelPlacementRecord,
    RuntimePlacementRecord,
    SaasBase,
    SchedulingControlPlane,
)
from saas.preview_gateway import PreviewTunnelRequest, PreviewTunnelResponse
from saas.preview_tunnel import (
    OfficialRunnerPreviewTunnel,
    PlacementRoutedPreviewTunnel,
    PreviewTunnelAdapterError,
)


def _fixture() -> tuple[
    sessionmaker[Session], SchedulingControlPlane, UUID, RunnerConnection, datetime
]:
    engine = sa.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @sa.event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    placement_id = uuid4()
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="placement-db",
                object_store_ref="placement-objects",
                kms_key_ref="placement-kms",
                official_schema_revision="runtime-schema-v1",
                capacity_class="shared-medium",
                status="active",
            )
        )
    scheduling = SchedulingControlPlane(factory)
    pool_id = scheduling.create_pool(
        placement_id=placement_id,
        name="preview-routing",
        queue_class="interactive",
        capacity_slots=2,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    connection = scheduling.register_runner(
        pool_id=pool_id,
        instance_key="runner-placement-1",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["preview.serve"],
        max_concurrency=2,
        now=now,
    )
    return factory, scheduling, pool_id, connection, now


def _reconnect(
    scheduling: SchedulingControlPlane, pool_id: UUID, now: datetime
) -> RunnerConnection:
    return scheduling.register_runner(
        pool_id=pool_id,
        instance_key="runner-placement-1",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["preview.serve"],
        max_concurrency=2,
        now=now,
    )


def _route(runner_id: UUID, generation: int) -> PreviewRouteGrant:
    return PreviewRouteGrant(
        preview_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        runner_id=runner_id,
        runner_connection_generation=generation,
        run_id=uuid4(),
        run_fence_token=3,
        worktree_id=uuid4(),
        worktree_lease_generation=2,
        opaque_preview_key="pvr_placement",
        preview_token_hash="a" * 64,
        upstream_request_headers={},
        response_headers={},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


def _request(route: PreviewRouteGrant) -> PreviewTunnelRequest:
    return PreviewTunnelRequest(
        route=route,
        method="GET",
        path="/",
        query="",
        headers={},
        body=b"",
    )


def test_tunnel_placement_fences_reconnects_and_expires_monotonically() -> None:
    factory, scheduling, pool_id, connection, now = _fixture()
    runner_id = connection.runner_id
    generation = connection.connection_generation
    connection_token = connection.connection_token
    gateway_a = RunnerTunnelPlacementAuthority(
        factory, route_session_factory=factory, gateway_instance_id="gateway-a"
    )
    gateway_b = RunnerTunnelPlacementAuthority(
        factory, route_session_factory=factory, gateway_instance_id="gateway-b"
    )
    ownership_a = "owner-a-" + "x" * 40

    first = gateway_a.claim_connection(
        runner_id=runner_id,
        runner_connection_generation=generation,
        runner_connection_token=connection_token,
        ownership_token=ownership_a,
        now=now,
    )
    assert (
        gateway_a.claim_connection(
            runner_id=runner_id,
            runner_connection_generation=generation,
            runner_connection_token=connection_token,
            ownership_token=ownership_a,
            now=now + timedelta(seconds=1),
        )
        == first
    )
    assert (
        gateway_b.resolve_preview_route(
            runner_id=runner_id,
            runner_connection_generation=generation,
            preview_token_hash="a" * 64,
            now=now + timedelta(seconds=1),
        ).placement_id
        == first.placement_id
    )
    with pytest.raises(RunnerTunnelPlacementError) as duplicate:
        gateway_b.claim_connection(
            runner_id=runner_id,
            runner_connection_generation=generation,
            runner_connection_token=connection_token,
            ownership_token="owner-b-" + "y" * 40,
            now=now + timedelta(seconds=1),
        )
    assert duplicate.value.code == "runner_tunnel_already_owned"

    heartbeat = gateway_a.heartbeat_connection(
        placement_id=first.placement_id,
        runner_id=runner_id,
        runner_connection_generation=generation,
        runner_connection_token=connection_token,
        ownership_token=ownership_a,
        routing_generation=first.routing_generation,
        now=now + timedelta(seconds=10),
    )
    assert heartbeat.lease_expires_at == now + timedelta(seconds=55)
    assert gateway_a.begin_draining(
        placement_id=first.placement_id,
        runner_id=runner_id,
        runner_connection_generation=generation,
        ownership_token=ownership_a,
        routing_generation=first.routing_generation,
    )

    second_connection = _reconnect(scheduling, pool_id, now + timedelta(seconds=11))
    second = gateway_b.claim_connection(
        runner_id=runner_id,
        runner_connection_generation=second_connection.connection_generation,
        runner_connection_token=second_connection.connection_token,
        ownership_token="owner-b-" + "z" * 40,
        lease_duration=timedelta(seconds=20),
        now=now + timedelta(seconds=12),
    )
    assert second.routing_generation == first.routing_generation + 1
    assert second.gateway_instance_id == "gateway-b"
    with factory() as db:
        old = db.get(RunnerTunnelPlacementRecord, first.placement_id)
        assert old is not None
        assert old.status == "released"
        assert old.release_reason == "runner_reconnected"

    with pytest.raises(RunnerTunnelPlacementError) as stale:
        gateway_a.heartbeat_connection(
            placement_id=first.placement_id,
            runner_id=runner_id,
            runner_connection_generation=generation,
            runner_connection_token=connection_token,
            ownership_token=ownership_a,
            routing_generation=first.routing_generation,
            now=now + timedelta(seconds=13),
        )
    assert stale.value.code == "runner_tunnel_connection_stale"

    assert gateway_a.reconcile_expired(now=now + timedelta(seconds=33)) == (second.placement_id,)
    with pytest.raises(RunnerTunnelPlacementError) as expired:
        gateway_b.resolve_preview_route(
            runner_id=runner_id,
            runner_connection_generation=second_connection.connection_generation,
            preview_token_hash="a" * 64,
            now=now + timedelta(seconds=33),
        )
    assert expired.value.code == "runner_tunnel_route_unavailable"
    with factory() as db:
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_type == "runner_tunnel_placement"
                )
            )
        )
    assert [event.event_type for event in events] == [
        "runner.tunnel_placement.claimed",
        "runner.tunnel_placement.draining",
        "runner.tunnel_placement.released",
        "runner.tunnel_placement.claimed",
        "runner.tunnel_placement.expired",
    ]


class _LocalTunnel:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[PreviewTunnelRequest] = []

    async def forward(self, request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        self.calls.append(request)
        return PreviewTunnelResponse(status_code=200, headers={}, body=self.name.encode())


class _Relay:
    def __init__(self) -> None:
        self.routes: dict[str, PlacementRoutedPreviewTunnel] = {}
        self.calls: list[RunnerTunnelPlacement] = []

    async def forward(
        self,
        placement: RunnerTunnelPlacement,
        request: PreviewTunnelRequest,
    ) -> PreviewTunnelResponse:
        self.calls.append(placement)
        return await self.routes[placement.relay_subject].accept_relay(placement, request)


async def _exercise_placement_router_reconnect() -> None:
    factory, scheduling, pool_id, connection, now = _fixture()
    runner_id = connection.runner_id
    generation = connection.connection_generation
    connection_token = connection.connection_token
    authority_a = RunnerTunnelPlacementAuthority(
        factory, route_session_factory=factory, gateway_instance_id="gateway-a"
    )
    authority_b = RunnerTunnelPlacementAuthority(
        factory, route_session_factory=factory, gateway_instance_id="gateway-b"
    )
    placement_b = authority_b.claim_connection(
        runner_id=runner_id,
        runner_connection_generation=generation,
        runner_connection_token=connection_token,
        ownership_token="relay-owner-b-" + "x" * 40,
        now=now,
    )
    local_a = _LocalTunnel("gateway-a")
    local_b = _LocalTunnel("gateway-b")
    relay = _Relay()
    router_b = PlacementRoutedPreviewTunnel(
        gateway_instance_id="gateway-b",
        placements=authority_b,
        local_tunnel=cast(OfficialRunnerPreviewTunnel, local_b),
        relay=None,
    )
    relay.routes[placement_b.relay_subject] = router_b
    router_a = PlacementRoutedPreviewTunnel(
        gateway_instance_id="gateway-a",
        placements=authority_a,
        local_tunnel=cast(OfficialRunnerPreviewTunnel, local_a),
        relay=relay,
    )
    route = _route(runner_id, generation)
    response = await router_a.forward(_request(route))
    assert response.body == b"gateway-b"
    assert len(relay.calls) == 1 and len(local_b.calls) == 1 and not local_a.calls

    reconnected = _reconnect(scheduling, pool_id, now + timedelta(seconds=1))
    placement_a = authority_a.claim_connection(
        runner_id=runner_id,
        runner_connection_generation=reconnected.connection_generation,
        runner_connection_token=reconnected.connection_token,
        ownership_token="relay-owner-a-" + "y" * 40,
        now=now + timedelta(seconds=2),
    )
    current_route = replace(
        route,
        runner_connection_generation=reconnected.connection_generation,
    )
    local_response = await router_a.forward(_request(current_route))
    assert local_response.body == b"gateway-a"
    assert placement_a.gateway_instance_id == "gateway-a"
    assert len(local_a.calls) == 1

    with pytest.raises(PreviewTunnelAdapterError) as stale:
        await router_b.accept_relay(placement_b, _request(route))
    assert stale.value.code == "preview_runner_placement_stale"


def test_placement_router_forwards_to_owner_and_receiver_rechecks_reconnect() -> None:
    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(lambda: asyncio.run(_exercise_placement_router_reconnect())).result()


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for placement acceptance")
    return value


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _role_factory(engine: sa.Engine, role: str) -> sessionmaker[Session]:
    factory = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(factory, "after_begin")
    def _bind_role(
        _session: Session,
        _transaction: object,
        connection: sa.Connection,
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")

    return factory


def test_real_postgresql_concurrent_placement_claim_and_monotonic_guards() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=4, max_overflow=0)
    placement_id = uuid4()
    nonce = uuid4().hex[:12]
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_placements "
                "(id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
                "status) VALUES (:id, 'omnigent', 'cn-east-1', 'cn-east-1a', :db, :objects, "
                ":kms, 'runtime-schema-v1', 'shared-medium', 'active')"
            ),
            {
                "id": placement_id,
                "db": f"db-placement-{nonce}",
                "objects": f"objects-placement-{nonce}",
                "kms": f"kms-placement-{nonce}",
            },
        )

    platform = SchedulingControlPlane(_role_factory(engine, "saas_platform"))
    executor_factory = _role_factory(engine, "saas_executor")
    scheduling = SchedulingControlPlane(executor_factory)
    pool_id = platform.create_pool(
        placement_id=placement_id,
        name=f"placement-{nonce}",
        queue_class="interactive",
        capacity_slots=2,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    connection = scheduling.register_runner(
        pool_id=pool_id,
        instance_key=f"placement-runner-{nonce}",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["preview.serve"],
        max_concurrency=2,
        now=now,
    )
    gateways = (
        RunnerTunnelPlacementAuthority(
            executor_factory,
            route_session_factory=executor_factory,
            gateway_instance_id=f"gateway-a-{nonce}",
        ),
        RunnerTunnelPlacementAuthority(
            executor_factory,
            route_session_factory=executor_factory,
            gateway_instance_id=f"gateway-b-{nonce}",
        ),
    )
    barrier = Barrier(2)

    def claim(index: int) -> RunnerTunnelPlacement | str:
        barrier.wait()
        try:
            return gateways[index].claim_connection(
                runner_id=connection.runner_id,
                runner_connection_generation=connection.connection_generation,
                runner_connection_token=connection.connection_token,
                ownership_token=f"postgres-owner-{index}-{nonce}-" + "x" * 32,
                now=now,
            )
        except RunnerTunnelPlacementError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim, (0, 1)))
    winners = [value for value in results if isinstance(value, RunnerTunnelPlacement)]
    failures = [value for value in results if isinstance(value, str)]
    assert len(winners) == 1
    assert failures == ["runner_tunnel_already_owned"]
    winner = winners[0]

    with pytest.raises(DBAPIError, match="row-level security"):
        with engine.begin() as raw:
            raw.exec_driver_sql("SET LOCAL ROLE saas_executor")
            raw.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count) VALUES "
                    "(:id, NULL, 'unrelated_global_event', 'unrelated', 'unrelated.created', "
                    "CAST(:payload AS jsonb), :key, :hash, 0)"
                ),
                {
                    "id": uuid4(),
                    "payload": "{}",
                    "key": f"unrelated:{nonce}",
                    "hash": "f" * 64,
                },
            )

    reconnected = scheduling.register_runner(
        pool_id=pool_id,
        instance_key=f"placement-runner-{nonce}",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["preview.serve"],
        max_concurrency=2,
        now=now + timedelta(seconds=1),
    )
    replacement_authority = next(
        gateway
        for gateway in gateways
        if gateway.gateway_instance_id != winner.gateway_instance_id
    )
    replacement = replacement_authority.claim_connection(
        runner_id=reconnected.runner_id,
        runner_connection_generation=reconnected.connection_generation,
        runner_connection_token=reconnected.connection_token,
        ownership_token=f"postgres-replacement-{nonce}-" + "y" * 32,
        now=now + timedelta(seconds=2),
    )
    assert replacement.routing_generation == winner.routing_generation + 1
    with _role_factory(engine, "saas_platform")() as db:
        previous = db.get(RunnerTunnelPlacementRecord, winner.placement_id)
        assert previous is not None
        assert previous.status == "released"
        assert previous.release_reason == "runner_reconnected"

    with pytest.raises(DBAPIError, match="placement time is monotonic"):
        with engine.begin() as raw:
            raw.exec_driver_sql("SET LOCAL ROLE saas_executor")
            raw.execute(
                sa.text(
                    "UPDATE saas_runner_tunnel_placements "
                    "SET last_heartbeat_at = claimed_at - INTERVAL '1 second' WHERE id = :id"
                ),
                {"id": replacement.placement_id},
            )
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as raw:
            raw.exec_driver_sql("SET LOCAL ROLE saas_platform")
            raw.execute(
                sa.text("DELETE FROM saas_runner_tunnel_placements WHERE id = :id"),
                {"id": replacement.placement_id},
            )
    engine.dispose()
