from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi import FastAPI, Request, WebSocket
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from starlette.websockets import WebSocketDisconnect

from saas.compatibility import current_runtime_context
from saas.control_plane import (
    ContextSnapshotPolicy,
    ContextSnapshotService,
    ControlPlaneAvailabilityGate,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityManagementService,
    MembershipLifecycleService,
    PasswordCredentialService,
    RuntimeCompatibilityPolicy,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    SaasCookieConfig,
    Space,
    SpaceMembership,
    SqlAlchemyContextResolver,
    Tenant,
    TenantMembership,
    create_saas_http_integration,
)


@dataclass
class _Clock:
    now: datetime

    def __call__(self) -> datetime:
        return self.now


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for replica acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _role_factory(
    engine: sa.Engine,
    role: str,
    *,
    actor_id: UUID | None = None,
    tenant_id: UUID | None = None,
    space_id: UUID | None = None,
) -> sessionmaker[Session]:
    factory = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(factory, "after_begin")
    def _bind_role_and_fixed_context(
        _session: Session,
        _transaction: object,
        connection: sa.Connection,
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")
        for name, value in (
            ("app.actor_id", actor_id),
            ("app.tenant_id", tenant_id),
            ("app.space_id", space_id),
        ):
            if value is not None:
                connection.execute(
                    sa.text("SELECT set_config(:name, :value, true)"),
                    {"name": name, "value": str(value)},
                )

    return factory


def _build_replica(
    *,
    auth_factory: sessionmaker[Session],
    app_factory: sessionmaker[Session],
    snapshot_service: ContextSnapshotService,
    availability_gate: ControlPlaneAvailabilityGate,
) -> FastAPI:
    lifecycle = MembershipLifecycleService(auth_factory)
    resolver = SqlAlchemyContextResolver(
        app_factory,
        RuntimeCompatibilityPolicy(
            runtime_type="omnigent",
            allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
            allowed_source_revisions=frozenset({"15dd7becff2bda8ee2b9afd5d16abc4feafb9552"}),
            allowed_schema_revisions=frozenset({"c4d5e6f7a8b9"}),
            adapter_contract_version="0.2.0",
        ),
    )
    integration = create_saas_http_integration(
        lifecycle=lifecycle,
        identities=IdentityManagementService(auth_factory),
        passwords=PasswordCredentialService(auth_factory),
        context_resolver=resolver,
        cookie_config=SaasCookieConfig(name="saas_session", secure=False),
        context_snapshots=snapshot_service,
        availability_gate=availability_gate,
        degraded_read_paths=frozenset({"/v1/low-risk"}),
    )
    app = FastAPI()
    router, prefix, tags = integration.extra_router
    app.include_router(router, prefix=prefix, tags=tags)

    @app.get("/v1/low-risk")
    def low_risk(request: Request) -> dict[str, object]:
        runtime = current_runtime_context()
        return {
            "actor_id": str(runtime.actor_id),
            "tenant_id": str(runtime.tenant_id),
            "workspace_id": runtime.physical_workspace_id,
            "degraded": bool(request.scope["state"].get("saas_degraded_authorization")),
        }

    @app.get("/v1/secret")
    def secret() -> dict[str, bool]:
        return {"secret": True}

    @app.post("/v1/new-run")
    def new_run() -> dict[str, bool]:
        return {"created": True}

    @app.websocket("/v1/ws")
    async def websocket_runtime(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_json({"connected": True})
        await websocket.close()

    integration.install_middleware(app)
    return app


def test_real_postgresql_context_shell_replica_revocation_and_degradation() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=8, max_overflow=0)
    owner_id, user_id = uuid4(), uuid4()
    tenant_id, other_tenant_id = uuid4(), uuid4()
    space_id, other_space_id = uuid4(), uuid4()
    placement_id, partition_id = uuid4(), uuid4()
    clock = _Clock(datetime.now(timezone.utc).replace(microsecond=0))

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_context_auth') THEN
                    CREATE ROLE saas_context_auth NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_context_app') THEN
                    CREATE ROLE saas_context_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_context_govern') THEN
                    CREATE ROLE saas_context_govern NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$;
            ALTER ROLE saas_context_auth NOLOGIN NOSUPERUSER NOBYPASSRLS;
            ALTER ROLE saas_context_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
            ALTER ROLE saas_context_govern NOLOGIN NOSUPERUSER NOBYPASSRLS;
            GRANT saas_authenticator TO saas_context_auth;
            GRANT saas_app TO saas_context_app;
            GRANT saas_governance TO saas_context_govern;
            """
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.insert(GlobalUser),
            [
                {"id": owner_id, "status": "active", "security_version": 1},
                {"id": user_id, "status": "active", "security_version": 1},
            ],
        )
        connection.execute(
            sa.insert(Tenant),
            [
                {
                    "id": tenant_id,
                    "slug": f"context-{tenant_id.hex}",
                    "name": "Context Tenant",
                    "status": "active",
                    "plan": "team",
                    "home_region": "cn-east-1",
                },
                {
                    "id": other_tenant_id,
                    "slug": f"other-{other_tenant_id.hex}",
                    "name": "Invisible Tenant",
                    "status": "active",
                    "plan": "team",
                    "home_region": "cn-east-1",
                },
            ],
        )
        connection.execute(
            sa.insert(Space),
            [
                {
                    "id": space_id,
                    "tenant_id": tenant_id,
                    "slug": "engineering",
                    "name": "Engineering",
                    "status": "active",
                },
                {
                    "id": other_space_id,
                    "tenant_id": other_tenant_id,
                    "slug": "invisible",
                    "name": "Invisible Space",
                    "status": "active",
                },
            ],
        )
        connection.execute(
            sa.insert(TenantMembership),
            [
                {
                    "tenant_id": tenant_id,
                    "user_id": owner_id,
                    "role": "owner",
                    "status": "active",
                    "version": 1,
                },
                {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "role": "member",
                    "status": "active",
                    "version": 1,
                },
                {
                    "tenant_id": other_tenant_id,
                    "user_id": owner_id,
                    "role": "owner",
                    "status": "active",
                    "version": 1,
                },
            ],
        )
        connection.execute(
            sa.insert(SpaceMembership),
            [
                {
                    "tenant_id": tenant_id,
                    "space_id": space_id,
                    "user_id": owner_id,
                    "role": "owner",
                    "status": "active",
                    "version": 1,
                },
                {
                    "tenant_id": tenant_id,
                    "space_id": space_id,
                    "user_id": user_id,
                    "role": "member",
                    "status": "active",
                    "version": 1,
                },
                {
                    "tenant_id": other_tenant_id,
                    "space_id": other_space_id,
                    "user_id": owner_id,
                    "role": "owner",
                    "status": "active",
                    "version": 1,
                },
            ],
        )
        connection.execute(
            sa.insert(RuntimePlacementRecord).values(
                id=placement_id,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="cn-east-1a",
                database_cluster_ref="context-db-a",
                object_store_ref="context-objects-a",
                kms_key_ref="context-kms-a",
                official_schema_revision="c4d5e6f7a8b9",
                capacity_class="shared-medium",
                status="active",
            )
        )
        connection.execute(
            sa.insert(RuntimePartitionRecord).values(
                id=partition_id,
                tenant_id=tenant_id,
                space_id=space_id,
                placement_id=placement_id,
                runtime_type="omnigent",
                runtime_version="0.9.0.dev0",
                physical_partition_key="91",
                placement_generation=5,
                source_revision="15dd7becff2bda8ee2b9afd5d16abc4feafb9552",
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
        connection.execute(
            sa.insert(RuntimeIdentityAliasRecord).values(
                runtime_partition_id=partition_id,
                user_id=user_id,
                runtime_user_key=f"context-user-{user_id.hex}",
                status="active",
            )
        )

    auth_factory_a = _role_factory(engine, "saas_context_auth")
    auth_factory_b = _role_factory(engine, "saas_context_auth")
    app_factory_a = _role_factory(engine, "saas_context_app")
    app_factory_b = _role_factory(engine, "saas_context_app")
    governance_factory = _role_factory(
        engine,
        "saas_context_govern",
        actor_id=owner_id,
        tenant_id=tenant_id,
        space_id=space_id,
    )
    lifecycle_a = MembershipLifecycleService(auth_factory_a)
    issued_session = lifecycle_a.issue_auth_session(
        user_id=user_id,
        authn_method="password",
        expires_at=clock.now + timedelta(hours=1),
        now=clock.now,
    )
    shared_keys = {"context-v1": b"replica-shared-context-key-material-v1"}
    service_a = ContextSnapshotService(
        ContextSnapshotPolicy(
            active_key_id="context-v1",
            keys=shared_keys,
            issuer="omnigent-saas-replica-test",
            audience="omnigent-api",
            clock=clock,
        )
    )
    service_b = ContextSnapshotService(
        ContextSnapshotPolicy(
            active_key_id="context-v1",
            keys=shared_keys,
            issuer="omnigent-saas-replica-test",
            audience="omnigent-api",
            clock=clock,
        )
    )
    gate_a = ControlPlaneAvailabilityGate()
    gate_b = ControlPlaneAvailabilityGate()
    client_a = TestClient(
        _build_replica(
            auth_factory=auth_factory_a,
            app_factory=app_factory_a,
            snapshot_service=service_a,
            availability_gate=gate_a,
        )
    )
    client_b = TestClient(
        _build_replica(
            auth_factory=auth_factory_b,
            app_factory=app_factory_b,
            snapshot_service=service_b,
            availability_gate=gate_b,
        )
    )
    authorization = {"Authorization": f"Bearer {issued_session.token}"}

    scopes = client_a.get("/saas/context/scopes", headers=authorization)
    assert scopes.status_code == 200
    assert [(item["tenant_id"], item["space_id"]) for item in scopes.json()] == [
        (str(tenant_id), str(space_id))
    ]
    assert "placement_id" not in scopes.text
    assert "physical_workspace_id" not in scopes.text

    snapshot_response = client_a.post(
        "/saas/context/snapshots",
        headers=authorization,
        json={"tenant_id": str(tenant_id), "space_id": str(space_id)},
    )
    assert snapshot_response.status_code == 201
    snapshot = snapshot_response.json()["context_snapshot"]
    snapshot_headers = {**authorization, "X-SaaS-Context-Snapshot": snapshot}

    replica_b = client_b.get("/v1/low-risk", headers=snapshot_headers)
    assert replica_b.status_code == 200, replica_b.text
    assert replica_b.json() == {
        "actor_id": str(user_id),
        "tenant_id": str(tenant_id),
        "workspace_id": 91,
        "degraded": False,
    }
    selector_conflict = client_b.get(
        "/v1/low-risk",
        headers={**snapshot_headers, "X-SaaS-Tenant-Id": str(other_tenant_id)},
    )
    assert selector_conflict.status_code == 403
    assert selector_conflict.json()["error"]["code"] == "context_selector_conflict"

    gate_b.set_available(False)
    degraded = client_b.get("/v1/low-risk", headers=snapshot_headers)
    assert degraded.status_code == 200
    assert degraded.json()["degraded"] is True
    assert degraded.headers["x-saas-degraded-authorization"] == "snapshot"
    for method, path in (
        ("GET", "/v1/secret"),
        ("GET", "/v1/export"),
        ("GET", "/v1/members"),
        ("GET", "/v1/billing"),
        ("GET", "/v1/support"),
        ("POST", "/v1/new-run"),
        ("GET", "/saas/context/scopes"),
        ("POST", "/saas/context/snapshots"),
    ):
        denied = client_b.request(
            method,
            path,
            headers=snapshot_headers,
            json={"tenant_id": str(tenant_id), "space_id": str(space_id)}
            if path == "/saas/context/snapshots"
            else None,
        )
        assert denied.status_code == 503
        assert denied.json()["error"]["code"] == "control_plane_unavailable"
    assert client_b.get("/v1/low-risk", headers=authorization).status_code == 503
    assert (
        client_b.post(
            "/saas/auth/login",
            json={"email": "unavailable@example.com", "password": "unavailable"},
        ).status_code
        == 503
    )
    with pytest.raises(WebSocketDisconnect) as websocket_error:
        with client_b.websocket_connect("/v1/ws", headers=snapshot_headers):
            pass
    assert websocket_error.value.code == 1008

    gate_b.set_available(True)
    changed = MembershipLifecycleService(governance_factory).update_space_membership(
        actor_id=owner_id,
        tenant_id=tenant_id,
        space_id=space_id,
        user_id=user_id,
        role="member",
        status="suspended",
        expected_version=1,
        idempotency_key=f"context-revoke-{user_id}",
        now=clock.now,
    )
    assert changed.security_version == 2
    assert changed.revoked_session_count == 1
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        invalidation_event = connection.scalar(
            sa.select(sa.func.count())
            .select_from(ControlPlaneOutboxEvent)
            .where(
                ControlPlaneOutboxEvent.tenant_id == tenant_id,
                ControlPlaneOutboxEvent.event_type == "space.membership.updated",
            )
        )
    assert invalidation_event == 1
    revoked_on_replica_b = client_b.get("/v1/low-risk", headers=snapshot_headers)
    assert revoked_on_replica_b.status_code == 401
    assert revoked_on_replica_b.json()["error"]["code"] == "invalid_session"

    gate_b.set_available(False)
    bounded_stale_read = client_b.get("/v1/low-risk", headers=snapshot_headers)
    assert bounded_stale_read.status_code == 200
    assert bounded_stale_read.json()["degraded"] is True
    assert client_b.get("/v1/secret", headers=snapshot_headers).status_code == 503
    clock.now += timedelta(seconds=61)
    expired = client_b.get("/v1/low-risk", headers=snapshot_headers)
    assert expired.status_code == 503
    assert expired.json()["error"]["code"] == "control_plane_unavailable"

    engine.dispose()
