from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane import (
    AdmissionQuotaRecord,
    ExecutionControlPlane,
    ExecutionControlPlaneError,
    ExecutionRevisionSet,
    GlobalUser,
    ProjectMembershipRecord,
    ProjectRecord,
    QuotaReservationRecord,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)

_P3_RLS_TABLES = {
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
}
_APP_ROLE = "saas_p3_rls_app_login"
_EXECUTOR_ROLE = "saas_p3_rls_executor_login"


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for P3 PostgreSQL acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _seed_scope(
    connection: sa.Connection,
    *,
    actor_id: UUID,
    tenant_id: UUID,
    space_id: UUID,
    project_id: UUID,
    task_id: UUID,
    run_id: UUID,
    suffix: str,
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO saas_global_users (id, status, security_version) "
            "VALUES (:actor, 'active', 1)"
        ),
        {"actor": actor_id},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_tenants "
            "(id, slug, name, status, plan, home_region) VALUES "
            "(:tenant, :slug, 'P3 RLS', 'active', 'team', 'cn-east-1')"
        ),
        {"tenant": tenant_id, "slug": f"p3-rls-{suffix}-{tenant_id.hex}"},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) VALUES "
            "(:space, :tenant, :slug, 'P3 Space', 'active')"
        ),
        {"space": space_id, "tenant": tenant_id, "slug": f"p3-{suffix}"},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_projects "
            "(id, tenant_id, space_id, name, visibility, created_by, status, "
            "authorization_version) VALUES "
            "(:project, :tenant, :space, 'P3 Project', 'restricted', :actor, 'active', 1)"
        ),
        {
            "project": project_id,
            "tenant": tenant_id,
            "space": space_id,
            "actor": actor_id,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_tasks "
            "(id, tenant_id, space_id, project_id, created_by, title, version) VALUES "
            "(:task, :tenant, :space, :project, :actor, 'P3 Task', 1)"
        ),
        {
            "task": task_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "actor": actor_id,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_runs "
            "(id, tenant_id, space_id, project_id, task_id, created_by, status, version, "
            "event_sequence, queue_class, priority, idempotency_key, request_hash, input, "
            "product_revision, upstream_revision, schema_revision, adapter_contract_version, "
            "fence_token) VALUES "
            "(:run, :tenant, :space, :project, :task, :actor, 'queued', 1, 0, "
            "'interactive', 0, :key, :request_hash, CAST(:input AS jsonb), "
            "'product', 'upstream', 'p3a000000001', '0.2.0', 0)"
        ),
        {
            "run": run_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "task": task_id,
            "actor": actor_id,
            "key": f"p3-rls-{suffix}-{run_id}",
            "request_hash": suffix[0] * 64,
            "input": "{}",
        },
    )


def test_real_postgresql_p3_rls_executor_and_artifact_immutability() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    actor_a, actor_b = uuid4(), uuid4()
    tenant_a, tenant_b = uuid4(), uuid4()
    space_a, space_b = uuid4(), uuid4()
    project_a, project_b = uuid4(), uuid4()
    task_a, task_b = uuid4(), uuid4()
    run_a, run_b = uuid4(), uuid4()
    artifact_id = uuid4()

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{_APP_ROLE}') THEN
                    CREATE ROLE {_APP_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{_EXECUTOR_ROLE}') THEN
                    CREATE ROLE {_EXECUTOR_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS;
                END IF;
            END
            $$;
            ALTER ROLE {_APP_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT;
            ALTER ROLE {_EXECUTOR_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT;
            GRANT saas_app TO {_APP_ROLE};
            GRANT saas_executor TO {_EXECUTOR_ROLE};
            """
        )
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        _seed_scope(
            connection,
            actor_id=actor_a,
            tenant_id=tenant_a,
            space_id=space_a,
            project_id=project_a,
            task_id=task_a,
            run_id=run_a,
            suffix="a",
        )
        _seed_scope(
            connection,
            actor_id=actor_b,
            tenant_id=tenant_b,
            space_id=space_b,
            project_id=project_b,
            task_id=task_b,
            run_id=run_b,
            suffix="b",
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_artifacts "
                "(id, tenant_id, space_id, project_id, sha256, size_bytes, media_type, "
                "object_uri, source_revision, created_by, metadata) VALUES "
                "(:id, :tenant, :space, :project, :digest, 1, 'text/plain', "
                "'s3://p3/immutable', 'product', :actor, CAST(:metadata AS jsonb))"
            ),
            {
                "id": artifact_id,
                "tenant": tenant_a,
                "space": space_a,
                "project": project_a,
                "digest": "c" * 64,
                "actor": actor_a,
                "metadata": "{}",
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {_APP_ROLE}")
        connection.execute(
            sa.text("SELECT set_config('app.actor_id', :value, true)"),
            {"value": str(actor_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.space_id', :value, true)"),
            {"value": str(space_a)},
        )
        assert set(connection.execute(sa.text("SELECT id FROM saas_runs")).scalars()) == {run_a}
        cross_update = connection.execute(
            sa.text("UPDATE saas_runs SET priority = 9 WHERE id = :run"), {"run": run_b}
        )
        assert cross_update.rowcount == 0

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {_APP_ROLE}")
        assert connection.execute(sa.text("SELECT count(*) FROM saas_runs")).scalar_one() == 0

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {_EXECUTOR_ROLE}")
        assert set(connection.execute(sa.text("SELECT id FROM saas_runs")).scalars()) >= {
            run_a,
            run_b,
        }

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {_EXECUTOR_ROLE}")
            connection.exec_driver_sql("SET LOCAL row_security = off")
            connection.execute(sa.text("SELECT count(*) FROM saas_runs")).scalar_one()

    for mutation in (
        "UPDATE saas_artifacts SET object_uri = 's3://changed' WHERE id = :id",
        "DELETE FROM saas_artifacts WHERE id = :id",
    ):
        with pytest.raises(DBAPIError):
            with engine.begin() as connection:
                connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
                connection.execute(sa.text(mutation), {"id": artifact_id})

    with engine.begin() as connection:
        forced = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
                    "AND relrowsecurity AND relforcerowsecurity AND relname = ANY(:tables)"
                ),
                {"tables": sorted(_P3_RLS_TABLES)},
            ).scalars()
        )
        flags = connection.execute(
            sa.text(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname IN (:app, :executor) ORDER BY rolname"
            ),
            {"app": _APP_ROLE, "executor": _EXECUTOR_ROLE},
        ).all()
        assert forced == _P3_RLS_TABLES
        assert all(not row.rolsuper and not row.rolbypassrls for row in flags)
    engine.dispose()


def test_real_postgresql_admission_quota_race_has_one_winner() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=4, max_overflow=0)
    with engine.begin() as connection:
        _migrate(connection, root)
    factory = sessionmaker(engine, expire_on_commit=False)
    actor_id, tenant_id, space_id, project_id = uuid4(), uuid4(), uuid4(), uuid4()
    with factory.begin() as db:
        db.add(GlobalUser(id=actor_id, status="active", security_version=1))
        db.add(
            Tenant(
                id=tenant_id,
                slug=f"p3-race-{tenant_id.hex}",
                name="P3 race",
                status="active",
                plan="team",
                home_region="cn-east-1",
            )
        )
        db.flush()
        db.add(
            Space(
                id=space_id,
                tenant_id=tenant_id,
                slug="race",
                name="Race",
                status="active",
            )
        )
        db.flush()
        db.add(
            TenantMembership(
                tenant_id=tenant_id,
                user_id=actor_id,
                role="owner",
                status="active",
                version=1,
            )
        )
        db.flush()
        db.add(
            SpaceMembership(
                tenant_id=tenant_id,
                space_id=space_id,
                user_id=actor_id,
                role="owner",
                status="active",
                version=1,
            )
        )
        db.add(
            ProjectRecord(
                id=project_id,
                tenant_id=tenant_id,
                space_id=space_id,
                name="Race project",
                visibility="restricted",
                created_by=actor_id,
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                subject_type="user",
                subject_id=actor_id,
                role="owner",
                status="active",
                created_by=actor_id,
                version=1,
            )
        )
    request = RequestContext(
        actor_id=actor_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="p3-quota-race",
    )
    service = ExecutionControlPlane(factory)
    quota_id = service.configure_quota(
        request, project_id=project_id, resource="run_units", limit_units=1
    )
    task_ids = [
        service.create_task(request, project_id=project_id, title=f"Race {index}")
        for index in range(2)
    ]
    revisions = ExecutionRevisionSet("product", "upstream", "p3a000000001", "0.2.0")

    def _admit(index: int) -> str:
        try:
            service.admit_run(
                request,
                project_id=project_id,
                task_id=task_ids[index],
                session_id=None,
                input_payload={"index": index},
                quota_resource="run_units",
                quota_units=1,
                idempotency_key=f"quota-race-{index}",
                revisions=revisions,
            )
        except ExecutionControlPlaneError as error:
            return error.code
        return "admitted"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(_admit, range(2)))
    assert outcomes == ["admitted", "quota_exceeded"]
    with factory() as db:
        quota = db.get(AdmissionQuotaRecord, quota_id)
        assert quota is not None and quota.reserved_units == 1
        assert (
            db.execute(sa.select(sa.func.count()).select_from(QuotaReservationRecord)).scalar_one()
            >= 1
        )
    engine.dispose()
