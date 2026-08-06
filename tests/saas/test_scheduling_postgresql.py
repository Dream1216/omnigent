from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import RunRecord, SchedulingControlPlane

_SCHEDULING_RLS_TABLES = {
    "saas_runner_pools",
    "saas_runner_registrations",
    "saas_runner_tunnel_placements",
    "saas_tenant_queue_shares",
    "saas_run_dispatches",
    "saas_capability_tokens",
}


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for P4 PostgreSQL acceptance")
    return url


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
            "(:tenant, :slug, 'P4 Scheduler', 'active', 'team', 'cn-east-1')"
        ),
        {"tenant": tenant_id, "slug": f"p4-scheduler-{suffix}-{tenant_id.hex}"},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) VALUES "
            "(:space, :tenant, :slug, 'P4 Space', 'active')"
        ),
        {"space": space_id, "tenant": tenant_id, "slug": f"p4-{suffix}"},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_projects "
            "(id, tenant_id, space_id, name, visibility, created_by, status, "
            "authorization_version) VALUES "
            "(:project, :tenant, :space, 'P4 Project', 'restricted', :actor, 'active', 1)"
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
            "(:task, :tenant, :space, :project, :actor, 'P4 Task', 1)"
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
            "'product', 'upstream', 'p4a000000001', '0.2.0', 0)"
        ),
        {
            "run": run_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "task": task_id,
            "actor": actor_id,
            "key": f"p4-scheduler-{suffix}-{run_id}",
            "request_hash": suffix[0] * 64,
            "input": "{}",
        },
    )


def _set_scope(
    connection: sa.Connection, *, tenant_id: UUID | None, space_id: UUID | None
) -> None:
    connection.execute(
        sa.text("SELECT set_config('app.tenant_id', :value, true)"),
        {"value": str(tenant_id) if tenant_id else ""},
    )
    connection.execute(
        sa.text("SELECT set_config('app.space_id', :value, true)"),
        {"value": str(space_id) if space_id else ""},
    )


def test_real_postgresql_scheduling_rls_and_concurrent_fair_claims() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=8, max_overflow=0)
    probe_role = f"saas_p4_scope_probe_{uuid4().hex[:12]}"
    placement_id = uuid4()
    scopes = tuple(
        {
            "actor": uuid4(),
            "tenant": uuid4(),
            "space": uuid4(),
            "project": uuid4(),
            "task": uuid4(),
            "run": uuid4(),
            "suffix": suffix,
        }
        for suffix in ("a", "b")
    )

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"CREATE ROLE {probe_role} NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT; "
            f"GRANT SELECT, UPDATE ON "
            "saas_runner_pools, saas_runner_registrations, saas_tenant_queue_shares, "
            "saas_run_dispatches, saas_capability_tokens, saas_runner_tunnel_placements "
            f"TO {probe_role}; "
            "GRANT SELECT ON saas_secret_access_leases, saas_preview_leases, "
            "saas_runner_certificates "
            f"TO {probe_role}; "
            "SET LOCAL ROLE saas_platform"
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_placements "
                "(id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
                "status) VALUES "
                "(:id, 'omnigent', 'cn-east-1', 'cn-east-1a', 'db-p4', 'objects-p4', "
                "'kms-p4', 'runtime-schema-v1', 'shared-medium', 'active')"
            ),
            {"id": placement_id},
        )
        for scope in scopes:
            _seed_scope(
                connection,
                actor_id=scope["actor"],
                tenant_id=scope["tenant"],
                space_id=scope["space"],
                project_id=scope["project"],
                task_id=scope["task"],
                run_id=scope["run"],
                suffix=scope["suffix"],
            )

    platform = SchedulingControlPlane(_role_factory(engine, "saas_platform"))
    executor_factory = _role_factory(engine, "saas_executor")
    scheduler_a = SchedulingControlPlane(executor_factory)
    scheduler_b = SchedulingControlPlane(executor_factory)
    pool_id = platform.create_pool(
        placement_id=placement_id,
        name="postgresql-interactive",
        queue_class="interactive",
        capacity_slots=2,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    for scope in scopes:
        scheduler_a.configure_tenant_share(
            tenant_id=scope["tenant"],
            pool_id=pool_id,
            weight=1,
            max_concurrent=1,
            burst_limit=1,
        )
    now = datetime(2026, 8, 4, 10, 30, tzinfo=timezone.utc)
    for scope in scopes:
        assert not scheduler_a.prepare_dispatch(
            run_id=scope["run"],
            pool_id=pool_id,
            required_capabilities=["shell"],
            eligible_at=now,
            maximum_wait=timedelta(hours=1),
        )
    runners = tuple(
        scheduler_a.register_runner(
            pool_id=pool_id,
            instance_key=f"postgresql-runner-{index}",
            failure_domain=f"cn-east-1{domain}",
            protocol_version=2,
            source_revision="upstream",
            schema_revision="runtime-schema-v1",
            adapter_contract_version="0.2.0",
            capabilities=["shell"],
            max_concurrency=1,
            now=now,
        )
        for index, domain in enumerate(("a", "a"), start=1)
    )

    barrier = Barrier(2)

    def claim(index: int):
        barrier.wait()
        scheduler = (scheduler_a, scheduler_b)[index]
        runner = runners[index]
        return scheduler.claim_fair_run(
            runner_id=runner.runner_id,
            connection_generation=runner.connection_generation,
            connection_token=runner.connection_token,
            lease_duration=timedelta(minutes=5),
            capability_actions=["worktree.read"],
            capability_resource_scope={"worktree_id": f"wt-{index}"},
            now=now + timedelta(seconds=1),
        )

    with ThreadPoolExecutor(max_workers=2) as workers:
        leases = tuple(workers.map(claim, range(2)))
    assert all(lease is not None for lease in leases)
    claimed_run_ids = {lease.run_id for lease in leases if lease is not None}
    assert claimed_run_ids == {scope["run"] for scope in scopes}
    assert len({lease.runner_id for lease in leases if lease is not None}) == 2

    with executor_factory() as db:
        claimed_runs = tuple(
            db.scalars(sa.select(RunRecord).where(RunRecord.id.in_(claimed_run_ids)))
        )
        assert {run.tenant_id for run in claimed_runs} == {scope["tenant"] for scope in scopes}
        assert all(run.status == "leased" and run.fence_token == 1 for run in claimed_runs)
        counters = db.execute(
            sa.text(
                "SELECT "
                "(SELECT sum(active_leases) FROM saas_runner_registrations "
                "WHERE pool_id = :pool_id), "
                "(SELECT sum(active_leases) FROM saas_tenant_queue_shares "
                "WHERE pool_id = :pool_id)"
            ),
            {"pool_id": pool_id},
        ).one()
        assert counters == (2, 2)

    with engine.begin() as connection:
        forced = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
                    "AND relrowsecurity AND relforcerowsecurity AND relname = ANY(:tables)"
                ),
                {"tables": sorted(_SCHEDULING_RLS_TABLES)},
            ).scalars()
        )
        assert forced == _SCHEDULING_RLS_TABLES

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {probe_role}")
        _set_scope(connection, tenant_id=None, space_id=None)
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_runner_pools")).scalar_one() == 0
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_runner_registrations")
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_run_dispatches")).scalar_one()
            == 0
        )

    for scope in scopes:
        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {probe_role}")
            _set_scope(
                connection,
                tenant_id=scope["tenant"],
                space_id=scope["space"],
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_tenant_queue_shares")
                ).scalar_one()
                == 1
            )
            # Tenant/Space context alone is not execution authority. Dispatch
            # and capability rows are visible only to platform/executor or the
            # exact p6a9 machine-metering identity.
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_run_dispatches")
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_capability_tokens")
                ).scalar_one()
                == 0
            )

        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {probe_role}")
            _set_scope(connection, tenant_id=scope["tenant"], space_id=uuid4())
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_tenant_queue_shares")
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_run_dispatches")
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    sa.text("SELECT count(*) FROM saas_capability_tokens")
                ).scalar_one()
                == 0
            )

    with engine.begin() as connection:
        connection.exec_driver_sql(
            "REVOKE ALL PRIVILEGES ON "
            "saas_runner_pools, saas_runner_registrations, saas_tenant_queue_shares, "
            "saas_run_dispatches, saas_capability_tokens, saas_runner_tunnel_placements "
            f"FROM {probe_role}; "
            "REVOKE ALL PRIVILEGES ON saas_secret_access_leases, saas_preview_leases, "
            "saas_runner_certificates "
            f"FROM {probe_role}; "
            f"DROP ROLE {probe_role}"
        )
    engine.dispose()
