from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from threading import Barrier, Event
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import (
    OutboxClaimRoute,
    OutboxDispatcher,
    RunDispatchRecord,
    RunRecord,
    SchedulingControlPlane,
    SchedulingError,
)
from saas.control_plane.run_dispatch_projection import RunQueuedDispatchProjection

_SCHEDULING_RLS_TABLES = {
    "saas_runner_pools",
    "saas_runner_registrations",
    "saas_runner_tunnel_placements",
    "saas_tenant_queue_shares",
    "saas_run_dispatches",
    "saas_capability_tokens",
}


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
    egress_policy_id: UUID,
    execution_profile_id: UUID,
    execution_profile_hash: str,
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
            "INSERT INTO saas_egress_policies "
            "(id, tenant_id, space_id, project_id, created_by, name, rules, rules_hash, "
            "allow_private_destinations, status, version) VALUES "
            "(:id, :tenant, :space, :project, :actor, 'scheduler-default-deny', "
            "CAST('[]' AS jsonb), :rules_hash, false, 'active', 1)"
        ),
        {
            "id": egress_policy_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "actor": actor_id,
            "rules_hash": "0" * 64,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_execution_profiles "
            "(id, tenant_id, space_id, project_id, egress_policy_id, created_by, name, "
            "sandbox_backend, network_mode, root_read_only, run_as_uid, run_as_gid, "
            "no_new_privileges, host_socket_access, syscall_profile_ref, cpu_millis, "
            "memory_bytes, pids_limit, allowed_tools, approval_required_tools, denied_tools, "
            "config_hash, status, version) VALUES "
            "(:id, :tenant, :space, :project, :egress_policy, :actor, "
            "'scheduler-managed-default', 'linux_bwrap', 'proxy_only', true, 65532, 65532, "
            "true, false, 'oci-default-v1', 1000, 536870912, 128, "
            "CAST('[\"shell\"]' AS jsonb), CAST('[]' AS jsonb), CAST('[]' AS jsonb), "
            ":config_hash, 'active', 1)"
        ),
        {
            "id": execution_profile_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "egress_policy": egress_policy_id,
            "actor": actor_id,
            "config_hash": execution_profile_hash,
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


def test_real_postgresql_outbox_claim_route_projects_only_exact_run_queued_event(
    isolated_postgres_url: str,
) -> None:
    """Prove the production dispatcher-to-executor route is database-exact."""

    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url, pool_size=4, max_overflow=0)
    actor_id, tenant_id, space_id, project_id, task_id, run_id = (uuid4() for _ in range(6))
    egress_policy_id, execution_profile_id, placement_id, partition_id, pool_id = (
        uuid4() for _ in range(5)
    )
    binding_id = uuid4()
    other_project_id, other_placement_id, other_partition_id, other_binding_id, other_pool_id = (
        uuid4() for _ in range(5)
    )
    run_event_id, queued_outbox_id = uuid4(), uuid4()
    unrelated_ids = tuple(uuid4() for _ in range(3))
    created_at = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
    queued_payload: dict[str, object] = {
        "status": "queued",
        "queue_class": "interactive",
        "priority": 0,
    }
    envelope: dict[str, object] = {
        "event_id": str(run_event_id),
        "run_id": str(run_id),
        "tenant_id": str(tenant_id),
        "space_id": str(space_id),
        "project_id": str(project_id),
        "sequence": 1,
        "event_type": "run.queued",
        "payload": queued_payload,
        "trace_id": "postgres-outbox-claim-route",
    }
    request_hash = sha256(
        json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        _seed_scope(
            connection,
            actor_id=actor_id,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            task_id=task_id,
            run_id=run_id,
            egress_policy_id=egress_policy_id,
            execution_profile_id=execution_profile_id,
            execution_profile_hash="c" * 64,
            suffix="route",
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_placements "
                "(id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
                "status) VALUES (:id, 'omnigent', 'cn-east-1', 'cn-east-1a', 'db-route', "
                "'objects-route', 'kms-route', 'p4a000000001', 'shared-medium', 'active')"
            ),
            {"id": placement_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_partitions "
                "(id, tenant_id, space_id, placement_id, runtime_type, runtime_version, "
                "physical_partition_key, placement_generation, source_revision, "
                "adapter_contract_version, status) VALUES "
                "(:id, :tenant, :space, :placement, 'omnigent', '1.0.0', 'route-1', 1, "
                "'upstream', '0.2.0', 'active')"
            ),
            {
                "id": partition_id,
                "tenant": tenant_id,
                "space": space_id,
                "placement": placement_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_resource_bindings "
                "(id, runtime_partition_id, tenant_id, space_id, project_id, resource_type, "
                "runtime_resource_id, saas_resource_id, partition_generation, "
                "binding_generation, status) VALUES "
                "(:id, :partition, :tenant, :space, :project, 'project', 'route-project', "
                ":project, 1, 1, 'active')"
            ),
            {
                "id": binding_id,
                "partition": partition_id,
                "tenant": tenant_id,
                "space": space_id,
                "project": project_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runner_pools "
                "(id, placement_id, failure_domain, name, queue_class, capacity_slots, "
                "reserved_slots, status, protocol_version, source_revision, schema_revision, "
                "adapter_contract_version) VALUES "
                "(:id, :placement, 'cn-east-1a', 'route-pool', 'interactive', 1, 0, "
                "'active', 2, 'upstream', 'p4a000000001', '0.2.0')"
            ),
            {"id": pool_id, "placement": placement_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_queue_shares "
                "(id, tenant_id, pool_id, queue_class, weight, max_concurrent, burst_limit, "
                "active_leases, virtual_runtime, version) VALUES "
                "(:id, :tenant, :pool, 'interactive', 1, 1, 1, 0, 0, 1)"
            ),
            {"id": uuid4(), "tenant": tenant_id, "pool": pool_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_projects "
                "(id, tenant_id, space_id, name, visibility, created_by, status, "
                "authorization_version) VALUES "
                "(:project, :tenant, :space, 'Other route project', 'restricted', "
                ":actor, 'active', 1)"
            ),
            {
                "project": other_project_id,
                "tenant": tenant_id,
                "space": space_id,
                "actor": actor_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_placements "
                "(id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
                "status) VALUES (:id, 'omnigent', 'cn-east-1', 'cn-east-1b', "
                "'db-route-other', 'objects-route-other', 'kms-route-other', "
                "'p4a000000001', 'shared-medium', 'active')"
            ),
            {"id": other_placement_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_partitions "
                "(id, tenant_id, space_id, placement_id, runtime_type, runtime_version, "
                "physical_partition_key, placement_generation, source_revision, "
                "adapter_contract_version, status) VALUES "
                "(:id, :tenant, :space, :placement, 'omnigent', '1.0.0', "
                "'route-other-1', 1, 'upstream', '0.2.0', 'active')"
            ),
            {
                "id": other_partition_id,
                "tenant": tenant_id,
                "space": space_id,
                "placement": other_placement_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_resource_bindings "
                "(id, runtime_partition_id, tenant_id, space_id, project_id, resource_type, "
                "runtime_resource_id, saas_resource_id, partition_generation, "
                "binding_generation, status) VALUES "
                "(:id, :partition, :tenant, :space, :project, 'project', "
                "'route-other-project', :project, 1, 1, 'active')"
            ),
            {
                "id": other_binding_id,
                "partition": other_partition_id,
                "tenant": tenant_id,
                "space": space_id,
                "project": other_project_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runner_pools "
                "(id, placement_id, failure_domain, name, queue_class, capacity_slots, "
                "reserved_slots, status, protocol_version, source_revision, schema_revision, "
                "adapter_contract_version) VALUES "
                "(:id, :placement, 'cn-east-1b', 'route-pool-other', 'interactive', 1, 0, "
                "'active', 2, 'upstream', 'p4a000000001', '0.2.0')"
            ),
            {"id": other_pool_id, "placement": other_placement_id},
        )
        connection.execute(
            sa.text("UPDATE saas_runs SET event_sequence = 1 WHERE id = :run"),
            {"run": run_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_run_events "
                "(id, tenant_id, space_id, project_id, run_id, sequence, event_type, payload, "
                "trace_id, created_at) VALUES "
                "(:event, :tenant, :space, :project, :run, 1, 'run.queued', "
                "CAST(:queued_payload AS jsonb), 'postgres-outbox-claim-route', :created_at)"
            ),
            {
                "event": run_event_id,
                "tenant": tenant_id,
                "space": space_id,
                "project": project_id,
                "run": run_id,
                "queued_payload": json.dumps(queued_payload),
                "created_at": created_at,
            },
        )
        mixed_rows = (
            (
                queued_outbox_id,
                "run",
                "run.event.persisted",
                envelope,
                f"run-event:{run_id}:1",
                request_hash,
            ),
            (
                unrelated_ids[0],
                "task",
                "run.event.persisted",
                envelope,
                f"route-unrelated-{unrelated_ids[0]}",
                "d" * 64,
            ),
            (
                unrelated_ids[1],
                "run",
                "run.queued",
                envelope,
                f"route-unrelated-{unrelated_ids[1]}",
                "e" * 64,
            ),
            (
                unrelated_ids[2],
                "run",
                "run.event.persisted",
                {**envelope, "event_type": "run.started"},
                f"route-unrelated-{unrelated_ids[2]}",
                "f" * 64,
            ),
        )
        for event_id, aggregate_type, event_type, payload, idempotency_key, digest in mixed_rows:
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, created_at) VALUES "
                    "(:id, :tenant, :aggregate_type, :aggregate_key, :event_type, "
                    "CAST(:payload AS jsonb), :idempotency_key, :request_hash, 0, :created_at)"
                ),
                {
                    "id": event_id,
                    "tenant": tenant_id,
                    "aggregate_type": aggregate_type,
                    "aggregate_key": str(run_id),
                    "event_type": event_type,
                    "payload": json.dumps(payload),
                    "idempotency_key": idempotency_key,
                    "request_hash": digest,
                    "created_at": created_at,
                },
            )

    route_tables = (
        ("saas_runtime_placements", placement_id, other_placement_id),
        ("saas_runtime_partitions", partition_id, other_partition_id),
        ("saas_runtime_resource_bindings", binding_id, other_binding_id),
        ("saas_runner_pools", pool_id, other_pool_id),
    )
    with engine.begin() as connection:
        route_lock_acls = set(
            connection.execute(
                sa.text(
                    "SELECT table_name, column_name, privilege_type, is_grantable "
                    "FROM information_schema.column_privileges "
                    "WHERE table_schema = 'public' AND grantee = 'saas_executor' "
                    "AND table_name = ANY(:tables) AND privilege_type = 'UPDATE'"
                ),
                {"tables": [table for table, _inside, _outside in route_tables]},
            )
        )
        assert route_lock_acls == {
            (table, "id", "UPDATE", "NO") for table, _inside, _outside in route_tables
        }
        assert (
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM information_schema.table_privileges "
                    "WHERE table_schema = 'public' AND grantee = 'saas_executor' "
                    "AND table_name = ANY(:tables) AND privilege_type = 'UPDATE'"
                ),
                {"tables": [table for table, _inside, _outside in route_tables]},
            )
            == 0
        )

    executor_factory = _role_factory(engine, "saas_executor")
    with executor_factory.begin() as db:
        _set_scope(db.connection(), tenant_id=tenant_id, space_id=space_id)
        db.execute(
            sa.text("SELECT set_config('app.project_id', :project, true)"),
            {"project": str(project_id)},
        )
        for table, inside_id, outside_id in route_tables:
            assert (
                db.scalar(
                    sa.text(f"SELECT id FROM {table} WHERE id = :id FOR SHARE"),
                    {"id": inside_id},
                )
                == inside_id
            )
            assert (
                db.scalar(
                    sa.text(f"SELECT id FROM {table} WHERE id = :id FOR SHARE"),
                    {"id": outside_id},
                )
                is None
            )
            with pytest.raises(DBAPIError):
                with db.begin_nested():
                    db.execute(
                        sa.text(f"UPDATE {table} SET id = id WHERE id = :id"),
                        {"id": inside_id},
                    )
            assert (
                db.execute(
                    sa.text(f"UPDATE {table} SET id = id WHERE id = :id"),
                    {"id": outside_id},
                ).rowcount
                == 0
            )
            with pytest.raises(DBAPIError):
                with db.begin_nested():
                    db.execute(
                        sa.text(f"UPDATE {table} SET status = status WHERE id = :id"),
                        {"id": inside_id},
                    )

    projection = RunQueuedDispatchProjection(executor_factory)
    dispatcher = OutboxDispatcher(
        _role_factory(engine, "saas_dispatcher"),
        projection,
        claim_routes=(OutboxClaimRoute("run", "run.event.persisted", "run.queued"),),
    )
    result = dispatcher.dispatch_once(batch_size=10, now=created_at + timedelta(seconds=1))
    assert (result.claimed, result.published, result.failed, result.quarantined) == (
        1,
        1,
        0,
        0,
    )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        exact = connection.execute(
            sa.text(
                "SELECT attempt_count, claimed_at, claim_token, published_at "
                "FROM saas_control_plane_outbox WHERE id = :id"
            ),
            {"id": queued_outbox_id},
        ).one()
        assert exact.attempt_count == 1
        assert exact.claimed_at is None and exact.claim_token is None
        assert exact.published_at == created_at + timedelta(seconds=1)
        untouched = connection.execute(
            sa.text(
                "SELECT id, attempt_count, claimed_at, claim_token, published_at "
                "FROM saas_control_plane_outbox WHERE id = ANY(:ids) ORDER BY id"
            ),
            {"ids": list(unrelated_ids)},
        ).all()
        assert len(untouched) == 3
        assert all(
            row.attempt_count == 0
            and row.claimed_at is None
            and row.claim_token is None
            and row.published_at is None
            for row in untouched
        )
        dispatch = connection.execute(
            sa.text(
                "SELECT execution_profile_id, egress_policy_id, status "
                "FROM saas_run_dispatches WHERE run_id = :run"
            ),
            {"run": run_id},
        ).one()
        assert dispatch == (execution_profile_id, egress_policy_id, "pending")
    engine.dispose()


def test_real_postgresql_scheduling_rls_and_concurrent_fair_claims(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url, pool_size=8, max_overflow=0)
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
            "profile": uuid4(),
            "egress": uuid4(),
            "profile_hash": ("6" if suffix == "a" else "7") * 64,
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
            f"GRANT USAGE ON SCHEMA public TO {probe_role}; "
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
                egress_policy_id=scope["egress"],
                execution_profile_id=scope["profile"],
                execution_profile_hash=scope["profile_hash"],
                suffix=scope["suffix"],
            )

    platform_factory = _role_factory(engine, "saas_platform")
    platform = SchedulingControlPlane(platform_factory)
    executor_factory = _role_factory(engine, "saas_executor")
    scheduler_a = SchedulingControlPlane(executor_factory)
    scheduler_b = SchedulingControlPlane(executor_factory)
    with engine.begin() as connection:
        profile_lock_acls = set(
            connection.execute(
                sa.text(
                    "SELECT table_name, column_name, privilege_type, is_grantable "
                    "FROM information_schema.column_privileges "
                    "WHERE table_schema = 'public' AND grantee = 'saas_executor' "
                    "AND table_name IN "
                    "('saas_egress_policies', 'saas_execution_profiles') "
                    "AND privilege_type = 'UPDATE'"
                )
            )
        )
        assert profile_lock_acls == {
            ("saas_egress_policies", "id", "UPDATE", "NO"),
            ("saas_execution_profiles", "id", "UPDATE", "NO"),
        }
        assert (
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM information_schema.table_privileges "
                    "WHERE table_schema = 'public' AND grantee = 'saas_executor' "
                    "AND table_name IN "
                    "('saas_egress_policies', 'saas_execution_profiles') "
                    "AND privilege_type = 'UPDATE'"
                )
            )
            == 0
        )
        profile_policies = {
            (
                str(row.tablename),
                str(row.policyname),
                str(row.cmd),
                None if row.with_check is None else str(row.with_check),
                str(row.qual),
            )
            for row in connection.execute(
                sa.text(
                    "SELECT tablename, policyname, cmd, with_check, qual "
                    "FROM pg_catalog.pg_policies WHERE schemaname = 'public' "
                    "AND policyname IN ("
                    "'rls_saas_egress_policies_dispatch_executor_select', "
                    "'rls_saas_egress_policies_dispatch_executor_lock', "
                    "'rls_saas_execution_profiles_dispatch_executor_select', "
                    "'rls_saas_execution_profiles_dispatch_executor_lock')"
                )
            )
        }
        assert {
            (table, policy, command, check)
            for table, policy, command, check, _qual in profile_policies
        } == {
            (
                "saas_egress_policies",
                "rls_saas_egress_policies_dispatch_executor_select",
                "SELECT",
                None,
            ),
            (
                "saas_egress_policies",
                "rls_saas_egress_policies_dispatch_executor_lock",
                "UPDATE",
                "false",
            ),
            (
                "saas_execution_profiles",
                "rls_saas_execution_profiles_dispatch_executor_select",
                "SELECT",
                None,
            ),
            (
                "saas_execution_profiles",
                "rls_saas_execution_profiles_dispatch_executor_lock",
                "UPDATE",
                "false",
            ),
        }
        for _table, _policy, _command, _check, qualification in profile_policies:
            assert "saas_executor" in qualification
            assert "app.tenant_id" in qualification
            assert "app.space_id" in qualification
            assert "app.project_id" in qualification

    with executor_factory.begin() as db:
        _set_scope(
            db.connection(),
            tenant_id=scopes[0]["tenant"],
            space_id=scopes[0]["space"],
        )
        db.execute(
            sa.text("SELECT set_config('app.project_id', :value, true)"),
            {"value": str(scopes[0]["project"])},
        )
        for table, key in (
            ("saas_execution_profiles", "profile"),
            ("saas_egress_policies", "egress"),
        ):
            assert (
                db.scalar(
                    sa.text(f"SELECT id FROM {table} WHERE id = :record FOR SHARE"),
                    {"record": scopes[0][key]},
                )
                == scopes[0][key]
            )
            assert (
                db.scalar(
                    sa.text(f"SELECT id FROM {table} WHERE id = :record FOR SHARE"),
                    {"record": scopes[1][key]},
                )
                is None
            )
    for statement, record_id in (
        (
            "UPDATE saas_execution_profiles SET id = id WHERE id = :record",
            scopes[0]["profile"],
        ),
        (
            "UPDATE saas_execution_profiles SET status = status WHERE id = :record",
            scopes[0]["profile"],
        ),
        (
            "UPDATE saas_execution_profiles SET config_hash = config_hash WHERE id = :record",
            scopes[0]["profile"],
        ),
        (
            "UPDATE saas_egress_policies SET id = id WHERE id = :record",
            scopes[0]["egress"],
        ),
        (
            "UPDATE saas_egress_policies SET status = status WHERE id = :record",
            scopes[0]["egress"],
        ),
        (
            "UPDATE saas_egress_policies SET rules_hash = rules_hash WHERE id = :record",
            scopes[0]["egress"],
        ),
    ):
        with pytest.raises(DBAPIError):
            with executor_factory.begin() as db:
                _set_scope(
                    db.connection(),
                    tenant_id=scopes[0]["tenant"],
                    space_id=scopes[0]["space"],
                )
                db.execute(
                    sa.text("SELECT set_config('app.project_id', :value, true)"),
                    {"value": str(scopes[0]["project"])},
                )
                db.execute(
                    sa.text(statement),
                    {"record": record_id},
                )
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
    with pytest.raises(SchedulingError) as cross_scope:
        scheduler_a.prepare_dispatch(
            run_id=scopes[0]["run"],
            pool_id=pool_id,
            required_capabilities=["shell"],
            execution_profile_id=scopes[1]["profile"],
            execution_profile_hash=scopes[1]["profile_hash"],
            eligible_at=now,
            maximum_wait=timedelta(hours=1),
        )
    assert cross_scope.value.code == "dispatch_execution_profile_invalid"
    for scope in scopes:
        assert not scheduler_a.prepare_dispatch(
            run_id=scope["run"],
            pool_id=pool_id,
            required_capabilities=["shell"],
            execution_profile_id=scope["profile"],
            execution_profile_hash=scope["profile_hash"],
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

    # Reconnect and expired-dispatch recovery contend on the same pool/Runner.
    # Their shared pool -> Runner lock order must serialize without a deadlock.
    reconnect_barrier = Barrier(2)

    def reconnect_runner():
        reconnect_barrier.wait()
        return scheduler_a.register_runner(
            pool_id=pool_id,
            instance_key="postgresql-runner-1",
            failure_domain="cn-east-1a",
            protocol_version=2,
            source_revision="upstream",
            schema_revision="runtime-schema-v1",
            adapter_contract_version="0.2.0",
            capabilities=["shell"],
            max_concurrency=1,
            now=now + timedelta(minutes=6),
        )

    def recover_dispatches():
        reconnect_barrier.wait()
        return scheduler_b.recover_expired_dispatches(now=now + timedelta(minutes=6))

    with ThreadPoolExecutor(max_workers=2) as workers:
        reconnect_future = workers.submit(reconnect_runner)
        recovery_future = workers.submit(recover_dispatches)
        replacement = reconnect_future.result(timeout=15)
        recovered = recovery_future.result(timeout=15)
    assert replacement.runner_id == runners[0].runner_id
    assert replacement.connection_generation == runners[0].connection_generation + 1
    assert set(recovered) == claimed_run_ids
    with executor_factory() as db:
        counters = db.execute(
            sa.text(
                "SELECT "
                "(SELECT sum(active_leases) FROM saas_runner_registrations "
                "WHERE pool_id = :pool_id), "
                "(SELECT sum(active_leases) FROM saas_tenant_queue_shares "
                "WHERE pool_id = :pool_id), "
                "(SELECT count(*) FROM saas_run_dispatches "
                "WHERE pool_id = :pool_id AND recovery_quarantined_at IS NOT NULL)"
            ),
            {"pool_id": pool_id},
        ).one()
        assert counters == (0, 0, 0)

    def assert_retirement_waits_for_claim(*, retirement_sql: str, record_id: UUID) -> None:
        lock_acquired = Event()
        release_lock = Event()
        retirement_finished = Event()

        def hold_claim_profile_lock() -> None:
            with executor_factory.begin() as db:
                run = scheduler_a._run(db, scopes[0]["run"], lock=True)
                scheduler_a._apply_run_context(db, run)
                dispatch = db.get(RunDispatchRecord, run.id)
                assert dispatch is not None
                scheduler_a._require_dispatch_profile_binding(db, dispatch=dispatch, run=run)
                lock_acquired.set()
                assert release_lock.wait(timeout=10)

        def retire_record() -> None:
            assert lock_acquired.wait(timeout=10)
            with platform_factory() as db:
                transaction = db.begin()
                updated = db.scalar(sa.text(retirement_sql), {"record": record_id})
                assert updated == record_id
                retirement_finished.set()
                transaction.rollback()

        with ThreadPoolExecutor(max_workers=2) as workers:
            lock_future = workers.submit(hold_claim_profile_lock)
            assert lock_acquired.wait(timeout=10)
            retirement_future = workers.submit(retire_record)
            assert not retirement_finished.wait(timeout=0.25)
            release_lock.set()
            lock_future.result(timeout=10)
            retirement_future.result(timeout=10)
        assert retirement_finished.is_set()

    assert_retirement_waits_for_claim(
        retirement_sql=(
            "UPDATE saas_execution_profiles SET status = 'retired' WHERE id = :record RETURNING id"
        ),
        record_id=scopes[0]["profile"],
    )
    assert_retirement_waits_for_claim(
        retirement_sql=(
            "UPDATE saas_egress_policies SET status = 'retired' WHERE id = :record RETURNING id"
        ),
        record_id=scopes[0]["egress"],
    )

    binding_locked = Event()
    release_binding = Event()

    def hold_profile_binding() -> None:
        with executor_factory.begin() as db:
            run = scheduler_a._run(db, scopes[0]["run"], lock=True)
            scheduler_a._apply_run_context(db, run)
            dispatch = db.get(RunDispatchRecord, run.id)
            assert dispatch is not None
            scheduler_a._require_dispatch_profile_binding(db, dispatch=dispatch, run=run)
            binding_locked.set()
            assert release_binding.wait(timeout=10)

    def insert_active_profile_phantom() -> None:
        assert binding_locked.wait(timeout=10)
        with platform_factory.begin() as db:
            db.execute(
                sa.text(
                    "INSERT INTO saas_execution_profiles "
                    "(id, tenant_id, space_id, project_id, egress_policy_id, created_by, "
                    "name, sandbox_backend, network_mode, root_read_only, run_as_uid, "
                    "run_as_gid, no_new_privileges, host_socket_access, syscall_profile_ref, "
                    "cpu_millis, memory_bytes, pids_limit, allowed_tools, "
                    "approval_required_tools, denied_tools, config_hash, status, version) "
                    "VALUES (:id, :tenant, :space, :project, :egress, :actor, "
                    "'phantom-profile', 'linux_bwrap', 'proxy_only', true, 65532, 65532, "
                    "true, false, 'oci-default-v1', 1000, 536870912, 128, "
                    "CAST('[\"shell\"]' AS jsonb), CAST('[]' AS jsonb), "
                    "CAST('[]' AS jsonb), :config_hash, 'active', 1)"
                ),
                {
                    "id": uuid4(),
                    "tenant": scopes[0]["tenant"],
                    "space": scopes[0]["space"],
                    "project": scopes[0]["project"],
                    "egress": scopes[0]["egress"],
                    "actor": scopes[0]["actor"],
                    "config_hash": "8" * 64,
                },
            )

    with ThreadPoolExecutor(max_workers=2) as workers:
        lock_future = workers.submit(hold_profile_binding)
        assert binding_locked.wait(timeout=10)
        insert_future = workers.submit(insert_active_profile_phantom)
        with pytest.raises(DBAPIError):
            insert_future.result(timeout=10)
        release_binding.set()
        lock_future.result(timeout=10)

    # A poison binding must be quarantined durably without preventing the same
    # claim call from leasing a healthy tenant.  Bias fair-share order so the
    # invalid row is deterministically examined first.
    with platform_factory.begin() as db:
        db.execute(
            sa.text(
                "UPDATE saas_run_dispatches SET egress_policy_hash = :poison WHERE run_id = :run"
            ),
            {"poison": "f" * 64, "run": scopes[0]["run"]},
        )
        db.execute(
            sa.text(
                "UPDATE saas_tenant_queue_shares SET virtual_runtime = "
                "CASE WHEN tenant_id = :poisoned THEN 0 ELSE 100 END "
                "WHERE pool_id = :pool"
            ),
            {"poisoned": scopes[0]["tenant"], "pool": pool_id},
        )
    healthy_after_quarantine = scheduler_a.claim_fair_run(
        runner_id=replacement.runner_id,
        connection_generation=replacement.connection_generation,
        connection_token=replacement.connection_token,
        lease_duration=timedelta(minutes=5),
        capability_actions=["worktree.read"],
        capability_resource_scope={"worktree_id": "quarantine-continuation"},
        now=now + timedelta(minutes=6, seconds=2),
    )
    assert healthy_after_quarantine is not None
    assert healthy_after_quarantine.run_id == scopes[1]["run"]
    with platform_factory() as db:
        quarantined = db.get(RunDispatchRecord, scopes[0]["run"])
        healthy = db.get(RunDispatchRecord, scopes[1]["run"])
        forensic = db.scalar(
            sa.text(
                "SELECT payload FROM saas_control_plane_outbox "
                "WHERE aggregate_type = 'run_dispatch' AND aggregate_key = :run "
                "AND event_type = 'run.dispatch.quarantined'"
            ),
            {"run": str(scopes[0]["run"])},
        )
        counters = db.execute(
            sa.text(
                "SELECT "
                "(SELECT active_leases FROM saas_tenant_queue_shares "
                "WHERE pool_id = :pool AND tenant_id = :poisoned), "
                "(SELECT active_leases FROM saas_tenant_queue_shares "
                "WHERE pool_id = :pool AND tenant_id = :healthy)"
            ),
            {
                "pool": pool_id,
                "poisoned": scopes[0]["tenant"],
                "healthy": scopes[1]["tenant"],
            },
        ).one()
        assert quarantined is not None and quarantined.status == "pending"
        assert quarantined.recovery_quarantined_at is not None
        assert quarantined.recovery_quarantine_reason == "dispatch_egress_policy_hash_mismatch"
        assert healthy is not None and healthy.status == "leased"
        assert forensic is not None
        assert forensic["forensic_hash"]
        assert forensic["egress_policy_hash"] == "f" * 64
        assert counters == (0, 1)

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
            f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {probe_role}; "
            f"DROP ROLE {probe_role}"
        )
    engine.dispose()
