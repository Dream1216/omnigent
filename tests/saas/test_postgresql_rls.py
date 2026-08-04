from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Lock
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import (
    ControlPlaneOutboxEvent,
    IdentityManagementService,
    LifecycleError,
    MembershipGovernanceService,
    OutboxDispatcher,
)
from saas.outbox_worker import verify_dispatcher_database_role

_CONTROL_PLANE_RLS_TABLES = {
    "saas_global_users",
    "saas_identity_connections",
    "saas_identity_conflicts",
    "saas_oidc_login_transactions",
    "saas_auth_sessions",
    "saas_password_credentials",
    "saas_tenants",
    "saas_spaces",
    "saas_tenant_memberships",
    "saas_space_memberships",
    "saas_membership_invitations",
    "saas_projects",
    "saas_project_memberships",
    "saas_resource_grants",
    "saas_authorization_decisions",
    "saas_runtime_placements",
    "saas_runtime_partitions",
    "saas_runtime_identity_aliases",
    "saas_runtime_resource_bindings",
    "saas_runtime_binding_sagas",
    "saas_ownership_transfers",
    "saas_member_removal_preflights",
    "saas_control_plane_outbox",
    "saas_tasks",
    "saas_execution_sessions",
    "saas_session_tasks",
    "saas_runs",
    "saas_run_events",
    "saas_admission_quotas",
    "saas_quota_reservations",
    "saas_effect_calls",
    "saas_artifacts",
    "saas_run_artifacts",
    "saas_runner_pools",
    "saas_runner_certificates",
    "saas_runner_registrations",
    "saas_tenant_queue_shares",
    "saas_run_dispatches",
    "saas_capability_tokens",
    "saas_repositories",
    "saas_changeset_groups",
    "saas_changesets",
    "saas_worktree_quotas",
    "saas_worktree_instances",
    "saas_worktree_events",
}


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for real RLS acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def test_real_postgresql_rls_denies_cross_tenant_and_missing_context() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    actor_a, actor_b, tenant_a, tenant_b, cross_tenant = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    event_key = f"rls-seed-{uuid4()}"
    oidc_transaction_id = uuid4()
    identity_conflict_id = uuid4()
    oidc_state_hash = uuid4().hex + uuid4().hex
    conflict_subject = f"rls-conflict-{uuid4()}"

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_app_login') THEN
                    CREATE ROLE saas_rls_app_login NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_auth_login') THEN
                    CREATE ROLE saas_rls_auth_login NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_dispatch_login'
                ) THEN
                    CREATE ROLE saas_rls_dispatch_login NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$
            """
        )
        connection.exec_driver_sql("GRANT saas_app TO saas_rls_app_login")
        connection.exec_driver_sql("GRANT saas_authenticator TO saas_rls_auth_login")
        connection.exec_driver_sql("GRANT saas_dispatcher TO saas_rls_dispatch_login")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:actor_a, 'active', 1), (:actor_b, 'active', 1)"
            ),
            {"actor_a": actor_a, "actor_b": actor_b},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:tenant_a, :slug_a, 'RLS A', 'active', 'team', 'cn-east-1'), "
                "(:tenant_b, :slug_b, 'RLS B', 'active', 'team', 'cn-east-1')"
            ),
            {
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
                "slug_a": f"rls-a-{tenant_a.hex}",
                "slug_b": f"rls-b-{tenant_b.hex}",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox "
                "(id, tenant_id, aggregate_type, aggregate_key, event_type, "
                "idempotency_key, request_hash, payload, attempt_count) VALUES "
                "(:id, :tenant_id, 'tenant', 'a', 'tenant.created', "
                ":event_key, :request_hash, CAST(:payload AS jsonb), 0)"
            ),
            {
                "id": uuid4(),
                "tenant_id": tenant_a,
                "event_key": event_key,
                "request_hash": "a" * 64,
                "payload": "{}",
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_app_login")
        connection.execute(
            sa.text("SELECT set_config('app.actor_id', :value, true)"),
            {"value": str(actor_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        visible_tenants = set(connection.execute(sa.text("SELECT id FROM saas_tenants")).scalars())
        visible_users = set(
            connection.execute(sa.text("SELECT id FROM saas_global_users")).scalars()
        )
        assert visible_tenants == {tenant_a}
        assert visible_users == {actor_a}

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_app_login")
        assert connection.execute(sa.text("SELECT count(*) FROM saas_tenants")).scalar_one() == 0
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_global_users")).scalar_one() == 0
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET ROLE saas_rls_app_login")
            connection.execute(
                sa.text("SELECT set_config('app.actor_id', :value, true)"),
                {"value": str(actor_a)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.tenant_id', :value, true)"),
                {"value": str(tenant_a)},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenants "
                    "(id, slug, name, status, plan, home_region) VALUES "
                    "(:id, 'cross-tenant', 'Cross Tenant', 'active', 'team', 'cn-east-1')"
                ),
                {"id": cross_tenant},
            )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_auth_login")
        visible_users = set(
            connection.execute(sa.text("SELECT id FROM saas_global_users")).scalars()
        )
        assert {actor_a, actor_b} <= visible_users
        connection.execute(
            sa.text(
                "INSERT INTO saas_oidc_login_transactions "
                "(id, provider, state_hash, browser_binding_hash, nonce_hash, "
                "code_verifier_ciphertext, purpose, status, expires_at) VALUES "
                "(:id, 'test', :state_hash, :browser_hash, :nonce_hash, "
                "'encrypted-verifier', 'login', 'pending', now() + interval '5 minutes')"
            ),
            {
                "id": oidc_transaction_id,
                "state_hash": oidc_state_hash,
                "browser_hash": "b" * 64,
                "nonce_hash": "c" * 64,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_identity_conflicts "
                "(id, provider, issuer, subject, email_normalized, candidate_user_id, "
                "status, version) VALUES "
                "(:id, 'test', 'https://idp.example.test', :subject, "
                "'actor-a@example.test', :candidate, 'pending', 1)"
            ),
            {
                "id": identity_conflict_id,
                "subject": conflict_subject,
                "candidate": actor_a,
            },
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_oidc_login_transactions WHERE id = :id"),
                {"id": oidc_transaction_id},
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_identity_conflicts WHERE id = :id"),
                {"id": identity_conflict_id},
            ).scalar_one()
            == 1
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET ROLE saas_rls_app_login")
            connection.execute(sa.text("SELECT count(*) FROM saas_oidc_login_transactions"))

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_dispatch_login")
        event_id = connection.execute(
            sa.text("SELECT id FROM saas_control_plane_outbox WHERE idempotency_key = :event_key"),
            {"event_key": event_key},
        ).scalar_one()
        result = connection.execute(
            sa.text("UPDATE saas_control_plane_outbox SET published_at = now() WHERE id = :id"),
            {"id": event_id},
        )
        assert result.rowcount == 1

    engine.dispose()


def test_real_postgresql_project_space_matrix_and_non_bypass_roles() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    tenant_a, tenant_b = uuid4(), uuid4()
    spaces_a = (uuid4(), uuid4())
    spaces_b = (uuid4(), uuid4())
    owner_a, admin_a, member_a = uuid4(), uuid4(), uuid4()
    owner_b, admin_b, member_b = uuid4(), uuid4(), uuid4()
    users = (owner_a, admin_a, member_a, owner_b, admin_b, member_b)
    projects_by_space = {space_id: (uuid4(), uuid4()) for space_id in (*spaces_a, *spaces_b)}

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_project_login'
                ) THEN
                    CREATE ROLE saas_rls_project_login NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_project_governance'
                ) THEN
                    CREATE ROLE saas_rls_project_governance NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$;
            GRANT saas_app TO saas_rls_project_login;
            GRANT saas_governance TO saas_rls_project_governance;
            """
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:id, 'active', 1)"
            ),
            [{"id": user_id} for user_id in users],
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:id, :slug, :name, 'active', 'team', 'cn-east-1')"
            ),
            [
                {"id": tenant_a, "slug": f"project-a-{tenant_a.hex}", "name": "Project A"},
                {"id": tenant_b, "slug": f"project-b-{tenant_b.hex}", "name": "Project B"},
            ],
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) "
                "VALUES (:id, :tenant_id, :slug, :name, 'active')"
            ),
            [
                {
                    "id": space_id,
                    "tenant_id": tenant_id,
                    "slug": f"space-{space_id.hex}",
                    "name": f"Space {index}",
                }
                for tenant_id, tenant_spaces in (
                    (tenant_a, spaces_a),
                    (tenant_b, spaces_b),
                )
                for index, space_id in enumerate(tenant_spaces)
            ],
        )
        tenant_memberships = [
            (tenant_a, owner_a, "owner"),
            (tenant_a, admin_a, "admin"),
            (tenant_a, member_a, "member"),
            (tenant_b, owner_b, "owner"),
            (tenant_b, admin_b, "admin"),
            (tenant_b, member_b, "member"),
        ]
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version) "
                "VALUES (:tenant_id, :user_id, :role, 'active', 1)"
            ),
            [
                {"tenant_id": tenant_id, "user_id": user_id, "role": role}
                for tenant_id, user_id, role in tenant_memberships
            ],
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_space_memberships "
                "(tenant_id, space_id, user_id, role, status, version) "
                "VALUES (:tenant_id, :space_id, :user_id, :role, 'active', 1)"
            ),
            [
                {
                    "tenant_id": tenant_id,
                    "space_id": space_id,
                    "user_id": user_id,
                    "role": role,
                }
                for tenant_id, tenant_spaces, members in (
                    (
                        tenant_a,
                        spaces_a,
                        ((owner_a, "owner"), (admin_a, "admin"), (member_a, "member")),
                    ),
                    (
                        tenant_b,
                        spaces_b,
                        ((owner_b, "owner"), (admin_b, "admin"), (member_b, "member")),
                    ),
                )
                for space_id in tenant_spaces
                for user_id, role in members
            ],
        )
        project_rows: list[dict[str, object]] = []
        membership_rows: list[dict[str, object]] = []
        for tenant_id, tenant_spaces, owner_id in (
            (tenant_a, spaces_a, owner_a),
            (tenant_b, spaces_b, owner_b),
        ):
            for space_id in tenant_spaces:
                for index, project_id in enumerate(projects_by_space[space_id]):
                    project_rows.append(
                        {
                            "id": project_id,
                            "tenant_id": tenant_id,
                            "space_id": space_id,
                            "name": f"Project {index}",
                            "visibility": "restricted" if index == 0 else "space",
                            "created_by": owner_id,
                        }
                    )
                    membership_rows.append(
                        {
                            "tenant_id": tenant_id,
                            "space_id": space_id,
                            "project_id": project_id,
                            "subject_id": owner_id,
                            "created_by": owner_id,
                        }
                    )
        connection.execute(
            sa.text(
                "INSERT INTO saas_projects "
                "(id, tenant_id, space_id, name, visibility, created_by, status, "
                "authorization_version) VALUES "
                "(:id, :tenant_id, :space_id, :name, :visibility, :created_by, "
                "'active', 1)"
            ),
            project_rows,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_project_memberships "
                "(tenant_id, space_id, project_id, subject_type, subject_id, role, "
                "status, created_by, version) VALUES "
                "(:tenant_id, :space_id, :project_id, 'user', :subject_id, 'owner', "
                "'active', :created_by, 1)"
            ),
            membership_rows,
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_project_login")
        connection.execute(
            sa.text("SELECT set_config('app.actor_id', :value, true)"),
            {"value": str(owner_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.space_id', :value, true)"),
            {"value": str(spaces_a[0])},
        )
        visible_projects = set(
            connection.execute(sa.text("SELECT id FROM saas_projects")).scalars()
        )
        assert visible_projects == set(projects_by_space[spaces_a[0]])
        decision_id = uuid4()
        connection.execute(
            sa.text(
                "INSERT INTO saas_authorization_decisions "
                "(id, tenant_id, space_id, project_id, actor_id, action, mode, allowed, "
                "reason, sources, policy_version, trace_id) VALUES "
                "(:id, :tenant_id, :space_id, :project_id, :actor_id, "
                "'project.read_metadata', 'enforce', true, 'allowed', "
                "CAST('[]' AS json), 'test', 'pg-project-matrix')"
            ),
            {
                "id": decision_id,
                "tenant_id": tenant_a,
                "space_id": spaces_a[0],
                "project_id": projects_by_space[spaces_a[0]][0],
                "actor_id": owner_a,
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_project_login")
        connection.execute(
            sa.text("SELECT set_config('app.actor_id', :value, true)"),
            {"value": str(owner_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.space_id', :value, true)"),
            {"value": str(spaces_b[0])},
        )
        assert connection.execute(sa.text("SELECT count(*) FROM saas_projects")).scalar_one() == 0

    with engine.begin() as connection:
        connection.exec_driver_sql("SET ROLE saas_rls_project_governance")
        connection.execute(
            sa.text("SELECT set_config('app.actor_id', :value, true)"),
            {"value": str(admin_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        assert connection.execute(sa.text("SELECT count(*) FROM saas_projects")).scalar_one() == 4

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET ROLE saas_rls_project_login")
            connection.execute(
                sa.text("SELECT set_config('app.actor_id', :value, true)"),
                {"value": str(owner_a)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.tenant_id', :value, true)"),
                {"value": str(tenant_a)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.space_id', :value, true)"),
                {"value": str(spaces_a[0])},
            )
            connection.exec_driver_sql("SET LOCAL row_security = off")
            connection.execute(sa.text("SELECT count(*) FROM saas_projects")).scalar_one()

    with engine.begin() as connection:
        role_facts = connection.execute(
            sa.text(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname IN ('saas_app', 'saas_governance', "
                "'saas_rls_project_login', 'saas_rls_project_governance')"
            )
        ).all()
        assert len(role_facts) == 4
        assert all(not is_super and not bypass for _name, is_super, bypass in role_facts)
        protected = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relrowsecurity "
                    "AND relforcerowsecurity "
                    "AND relname IN ('saas_projects', 'saas_project_memberships', "
                    "'saas_resource_grants', 'saas_authorization_decisions', "
                    "'saas_runtime_binding_sagas')"
                )
            ).scalars()
        )
        assert protected == {
            "saas_projects",
            "saas_project_memberships",
            "saas_resource_grants",
            "saas_authorization_decisions",
            "saas_runtime_binding_sagas",
        }
        forced = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relrowsecurity "
                    "AND relforcerowsecurity AND relname = ANY(:table_names)"
                ),
                {"table_names": sorted(_CONTROL_PLANE_RLS_TABLES)},
            ).scalars()
        )
        assert forced == _CONTROL_PLANE_RLS_TABLES

    engine.dispose()


def test_real_postgresql_outbox_dispatcher_concurrent_claim_and_lease_recovery() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=4, max_overflow=0)
    event_ids = (uuid4(), uuid4())
    stale_event_id = uuid4()
    dispatch_at = datetime(2026, 8, 4, 6, 0, tzinfo=timezone.utc)

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_outbox_worker'
                ) THEN
                    CREATE ROLE saas_rls_outbox_worker NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$;
            ALTER ROLE saas_rls_outbox_worker NOLOGIN NOSUPERUSER NOBYPASSRLS;
            GRANT saas_dispatcher TO saas_rls_outbox_worker;
            SET LOCAL ROLE saas_platform;
            """
        )
        connection.execute(
            sa.update(ControlPlaneOutboxEvent)
            .where(ControlPlaneOutboxEvent.published_at.is_(None))
            .values(available_at=dispatch_at + timedelta(days=1))
        )
        for event_id in event_ids:
            connection.execute(
                sa.insert(ControlPlaneOutboxEvent).values(
                    id=event_id,
                    tenant_id=None,
                    aggregate_type="concurrent-outbox",
                    aggregate_key=str(event_id),
                    event_type="acceptance.concurrent",
                    idempotency_key=f"pg-concurrent-{event_id}",
                    request_hash="c" * 64,
                    payload={"event_id": str(event_id)},
                    attempt_count=0,
                )
            )

    sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(sessions, "after_begin")
    def _use_dispatch_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql("SET LOCAL ROLE saas_rls_outbox_worker")

    class ConcurrentPublisher:
        def __init__(self) -> None:
            self.barrier = Barrier(2)
            self.lock = Lock()
            self.event_ids: list[object] = []

        def publish(self, *, event_id: object, **_event: object) -> None:
            with self.lock:
                self.event_ids.append(event_id)
            self.barrier.wait(timeout=10)

    publisher = ConcurrentPublisher()
    dispatchers = (OutboxDispatcher(sessions, publisher), OutboxDispatcher(sessions, publisher))
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(dispatcher.dispatch_once, batch_size=1, now=dispatch_at)
            for dispatcher in dispatchers
        ]
        results = [future.result(timeout=15) for future in futures]
    assert {(result.claimed, result.published, result.failed) for result in results} == {(1, 1, 0)}
    assert set(publisher.event_ids) == set(event_ids)
    assert len(publisher.event_ids) == len(set(publisher.event_ids))

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.insert(ControlPlaneOutboxEvent).values(
                id=stale_event_id,
                tenant_id=None,
                aggregate_type="stale-outbox",
                aggregate_key=str(stale_event_id),
                event_type="acceptance.stale",
                idempotency_key=f"pg-stale-{stale_event_id}",
                request_hash="d" * 64,
                payload={"event_id": str(stale_event_id)},
                attempt_count=1,
                claimed_at=dispatch_at - timedelta(seconds=31),
                claim_token=uuid4(),
            )
        )

    class RecordingPublisher:
        def __init__(self) -> None:
            self.event_ids: list[object] = []

        def publish(self, *, event_id: object, **_event: object) -> None:
            self.event_ids.append(event_id)

    recovery_publisher = RecordingPublisher()
    recovered = OutboxDispatcher(sessions, recovery_publisher).dispatch_once(
        batch_size=1, now=dispatch_at
    )
    assert (recovered.claimed, recovered.published, recovered.failed) == (1, 1, 0)
    assert recovery_publisher.event_ids == [stale_event_id]

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        rows = connection.execute(
            sa.select(
                ControlPlaneOutboxEvent.id,
                ControlPlaneOutboxEvent.attempt_count,
                ControlPlaneOutboxEvent.published_at,
            ).where(ControlPlaneOutboxEvent.id.in_((*event_ids, stale_event_id)))
        ).all()
    assert len(rows) == 3
    assert all(published_at is not None for _id, _attempt, published_at in rows)
    assert {attempt for event_id, attempt, _published in rows if event_id == stale_event_id} == {2}
    engine.dispose()


def test_real_postgresql_owner_transfer_serializes_and_preserves_single_owner() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=4, max_overflow=0)
    owner_id, target_id, tenant_id = uuid4(), uuid4(), uuid4()
    changed_at = datetime(2026, 8, 4, 6, 30, tzinfo=timezone.utc)

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_governance_worker'
                ) THEN
                    CREATE ROLE saas_rls_governance_worker NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$;
            ALTER ROLE saas_rls_governance_worker NOLOGIN NOSUPERUSER NOBYPASSRLS;
            GRANT saas_governance TO saas_rls_governance_worker;
            SET LOCAL ROLE saas_platform;
            """
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:owner_id, 'active', 1), (:target_id, 'active', 1)"
            ),
            {"owner_id": owner_id, "target_id": target_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:tenant_id, :slug, 'Concurrent Governance', 'active', 'team', "
                "'cn-east-1')"
            ),
            {"tenant_id": tenant_id, "slug": f"owner-race-{tenant_id.hex}"},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version) VALUES "
                "(:tenant_id, :owner_id, 'owner', 'active', 1), "
                "(:tenant_id, :target_id, 'member', 'active', 1)"
            ),
            {"tenant_id": tenant_id, "owner_id": owner_id, "target_id": target_id},
        )

    sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(sessions, "after_begin")
    def _use_governance_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql("SET LOCAL ROLE saas_rls_governance_worker")

    service = MembershipGovernanceService(sessions)
    start = Barrier(2)

    def _transfer(idempotency_key: str) -> str:
        start.wait(timeout=10)
        try:
            service.transfer_ownership(
                actor_id=owner_id,
                tenant_id=tenant_id,
                from_user_id=owner_id,
                to_user_id=target_id,
                source_expected_version=1,
                target_expected_version=1,
                reason="concurrent owner handover acceptance",
                reauthenticated_at=changed_at,
                idempotency_key=idempotency_key,
                now=changed_at,
            )
        except LifecycleError as error:
            return error.code
        return "transferred"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = {
            future.result(timeout=15)
            for future in (
                executor.submit(_transfer, "pg-owner-race-a"),
                executor.submit(_transfer, "pg-owner-race-b"),
            )
        }
    assert outcomes == {"transferred", "owner_required"}

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        memberships = connection.execute(
            sa.text(
                "SELECT user_id, role, version FROM saas_tenant_memberships "
                "WHERE tenant_id = :tenant_id ORDER BY user_id"
            ),
            {"tenant_id": tenant_id},
        ).all()
        transfer_count = connection.execute(
            sa.text("SELECT count(*) FROM saas_ownership_transfers WHERE tenant_id = :tenant_id"),
            {"tenant_id": tenant_id},
        ).scalar_one()
    assert {(user_id, role, version) for user_id, role, version in memberships} == {
        (owner_id, "admin", 2),
        (target_id, "owner", 2),
    }
    assert transfer_count == 1
    engine.dispose()


def test_real_postgresql_concurrent_identity_revocation_preserves_login_method() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=4, max_overflow=0)
    user_id, first_connection_id, second_connection_id = uuid4(), uuid4(), uuid4()

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_roles WHERE rolname = 'saas_rls_identity_worker'
                ) THEN
                    CREATE ROLE saas_rls_identity_worker NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$;
            ALTER ROLE saas_rls_identity_worker NOLOGIN NOSUPERUSER NOBYPASSRLS;
            GRANT saas_authenticator TO saas_rls_identity_worker;
            SET LOCAL ROLE saas_platform;
            """
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:user_id, 'active', 1)"
            ),
            {"user_id": user_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_identity_connections "
                "(id, user_id, provider, issuer, subject, email_verified, status) VALUES "
                "(:first_id, :user_id, 'oidc', :issuer, :first_subject, true, 'active'), "
                "(:second_id, :user_id, 'oidc', :issuer, :second_subject, true, 'active')"
            ),
            {
                "first_id": first_connection_id,
                "second_id": second_connection_id,
                "user_id": user_id,
                "issuer": f"https://identity-{user_id}.example.com",
                "first_subject": f"first-{user_id}",
                "second_subject": f"second-{user_id}",
            },
        )

    sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(sessions, "after_begin")
    def _use_identity_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql("SET LOCAL ROLE saas_rls_identity_worker")

    service = IdentityManagementService(sessions)
    start = Barrier(2)

    def _revoke(connection_id: UUID, suffix: str) -> str:
        start.wait(timeout=10)
        try:
            service.revoke_identity(
                user_id=user_id,
                connection_id=connection_id,
                idempotency_key=f"pg-identity-race-{suffix}",
            )
        except LifecycleError as error:
            return error.code
        return "revoked"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = {
            future.result(timeout=15)
            for future in (
                executor.submit(_revoke, first_connection_id, "first"),
                executor.submit(_revoke, second_connection_id, "second"),
            )
        }
    assert outcomes == {"revoked", "last_login_method"}

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        statuses = connection.execute(
            sa.text(
                "SELECT status FROM saas_identity_connections WHERE user_id = :user_id ORDER BY id"
            ),
            {"user_id": user_id},
        ).scalars()
        security_version = connection.execute(
            sa.text("SELECT security_version FROM saas_global_users WHERE id = :user_id"),
            {"user_id": user_id},
        ).scalar_one()
    assert sorted(statuses) == ["active", "revoked"]
    assert security_version == 2
    engine.dispose()


def test_real_postgresql_outbox_worker_rejects_privileged_or_wrong_service_login() -> None:
    root = Path(__file__).resolve().parents[2]
    owner_engine = sa.create_engine(_postgres_url())
    suffix = uuid4().hex[:16]
    dispatcher_login = f"saas_dispatch_login_{suffix}"
    wrong_login = f"saas_wrong_login_{suffix}"
    mixed_login = f"saas_mixed_login_{suffix}"
    schema_login = f"saas_schema_login_{suffix}"
    dispatcher_password = f"dispatcher-{uuid4().hex}"
    wrong_password = f"wrong-{uuid4().hex}"
    mixed_password = f"mixed-{uuid4().hex}"
    schema_password = f"schema-{uuid4().hex}"
    with owner_engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"""
            CREATE ROLE {dispatcher_login} LOGIN PASSWORD '{dispatcher_password}'
                NOSUPERUSER NOBYPASSRLS INHERIT;
            CREATE ROLE {wrong_login} LOGIN PASSWORD '{wrong_password}'
                NOSUPERUSER NOBYPASSRLS INHERIT;
            CREATE ROLE {mixed_login} LOGIN PASSWORD '{mixed_password}'
                NOSUPERUSER NOBYPASSRLS INHERIT;
            CREATE ROLE {schema_login} LOGIN PASSWORD '{schema_password}'
                NOSUPERUSER NOBYPASSRLS INHERIT;
            GRANT saas_dispatcher TO {dispatcher_login};
            GRANT saas_app TO {wrong_login};
            GRANT saas_dispatcher, saas_app TO {mixed_login};
            GRANT saas_dispatcher TO {schema_login};
            ALTER ROLE {schema_login} SET search_path = pg_catalog, public;
            """
        )

    base = sa.engine.make_url(_postgres_url())
    dispatcher_engine = sa.create_engine(
        base.set(username=dispatcher_login, password=dispatcher_password),
        pool_pre_ping=True,
    )
    wrong_engine = sa.create_engine(
        base.set(username=wrong_login, password=wrong_password),
        pool_pre_ping=True,
    )
    mixed_engine = sa.create_engine(
        base.set(username=mixed_login, password=mixed_password),
        pool_pre_ping=True,
    )
    schema_engine = sa.create_engine(
        base.set(username=schema_login, password=schema_password),
        pool_pre_ping=True,
    )
    try:
        verify_dispatcher_database_role(dispatcher_engine)
        with pytest.raises(RuntimeError, match="dispatcher privilege boundary"):
            verify_dispatcher_database_role(wrong_engine)
        with pytest.raises(RuntimeError, match="dispatcher privilege boundary"):
            verify_dispatcher_database_role(mixed_engine)
        with pytest.raises(RuntimeError, match="public search_path"):
            verify_dispatcher_database_role(schema_engine)
    finally:
        dispatcher_engine.dispose()
        wrong_engine.dispose()
        mixed_engine.dispose()
        schema_engine.dispose()
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP ROLE {dispatcher_login}")
            connection.exec_driver_sql(f"DROP ROLE {wrong_login}")
            connection.exec_driver_sql(f"DROP ROLE {mixed_login}")
            connection.exec_driver_sql(f"DROP ROLE {schema_login}")
        owner_engine.dispose()
