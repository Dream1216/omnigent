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
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import (
    SchedulingControlPlane,
    WorktreeControlPlane,
    WorktreeControlPlaneError,
    WorktreeRemovalImpactProvider,
)

_WORKTREE_RLS_TABLES = {
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
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for P4 Worktree acceptance")
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


def _seed_scope(
    connection: sa.Connection,
    *,
    actor_id: UUID,
    tenant_id: UUID,
    space_id: UUID,
    project_id: UUID,
    task_id: UUID,
    run_id: UUID,
    execution_profile_id: UUID,
    execution_profile_hash: str,
    repository_id: UUID,
    group_id: UUID,
    change_set_id: UUID,
    quota_id: UUID,
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
            "INSERT INTO saas_tenants (id, slug, name, status, plan, home_region) VALUES "
            "(:tenant, :slug, 'P4 Worktree', 'active', 'team', 'cn-east-1')"
        ),
        {"tenant": tenant_id, "slug": f"p4-worktree-{suffix}-{tenant_id.hex}"},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) VALUES "
            "(:space, :tenant, :slug, 'P4 Space', 'active')"
        ),
        {"space": space_id, "tenant": tenant_id, "slug": f"p4-worktree-{suffix}"},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_projects "
            "(id, tenant_id, space_id, name, visibility, created_by, status, "
            "authorization_version) VALUES "
            "(:project, :tenant, :space, 'P4 Project', 'restricted', :actor, 'active', 1)"
        ),
        {"project": project_id, "tenant": tenant_id, "space": space_id, "actor": actor_id},
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
    egress_policy_id = uuid4()
    connection.execute(
        sa.text(
            "INSERT INTO saas_egress_policies "
            "(id, tenant_id, space_id, project_id, created_by, name, rules, rules_hash, "
            "allow_private_destinations, status, version) VALUES "
            "(:id, :tenant, :space, :project, :actor, 'worktree-default-deny', "
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
            "'worktree-managed-default', 'linux_bwrap', 'proxy_only', true, 65532, 65532, "
            "true, false, 'oci-default-v1', 1000, 536870912, 128, "
            "CAST('[\"git\",\"shell\"]' AS jsonb), CAST('[]' AS jsonb), "
            "CAST('[]' AS jsonb), :config_hash, 'active', 1)"
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
            "'product', 'upstream', 'p4b000000001', '0.2.0', 0)"
        ),
        {
            "run": run_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "task": task_id,
            "actor": actor_id,
            "key": f"p4-worktree-{suffix}-{run_id}",
            "request_hash": suffix[0] * 64,
            "input": "{}",
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_repositories "
            "(id, tenant_id, space_id, project_id, created_by, provider, source_binding_key, "
            "display_name, default_branch, status, version) VALUES "
            "(:repository, :tenant, :space, :project, :actor, 'github-app', :binding, "
            "'P4 Repository', 'main', 'active', 1)"
        ),
        {
            "repository": repository_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "actor": actor_id,
            "binding": f"repo_{suffix}_{repository_id.hex}",
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_changeset_groups "
            "(id, tenant_id, space_id, project_id, created_by, title, status, version) VALUES "
            "(:group_id, :tenant, :space, :project, :actor, 'P4 Change', 'open', 1)"
        ),
        {
            "group_id": group_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "actor": actor_id,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_changesets "
            "(id, tenant_id, space_id, project_id, group_id, repository_id, created_by, "
            "base_revision, branch_ref, status, version) VALUES "
            "(:change_set, :tenant, :space, :project, :group_id, :repository, :actor, "
            ":base_revision, :branch_ref, 'open', 1)"
        ),
        {
            "change_set": change_set_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "group_id": group_id,
            "repository": repository_id,
            "actor": actor_id,
            "base_revision": suffix[0] * 40,
            "branch_ref": f"refs/heads/codex/{suffix}",
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_worktree_quotas "
            "(id, tenant_id, space_id, project_id, max_active_instances, max_active_writers, "
            "max_reserved_bytes, max_lease_seconds, max_lifetime_seconds, gc_grace_seconds, "
            "active_instances, active_writers, reserved_bytes, version) VALUES "
            "(:quota, :tenant, :space, :project, 2, 2, 4000000, 300, 3600, 10, 0, 0, 0, 1)"
        ),
        {"quota": quota_id, "tenant": tenant_id, "space": space_id, "project": project_id},
    )


def test_real_postgresql_worktree_rls_single_writer_and_governance_preflight() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=8, max_overflow=0)
    probe_role = f"saas_p4_worktree_probe_{uuid4().hex[:12]}"
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
            "profile_hash": ("8" if suffix == "a" else "9") * 64,
            "repository": uuid4(),
            "group": uuid4(),
            "change_set": uuid4(),
            "quota": uuid4(),
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
            f"GRANT saas_app TO {probe_role}; "
            f"GRANT USAGE ON SCHEMA public TO {probe_role}; "
            f"GRANT SELECT, INSERT, UPDATE ON {', '.join(sorted(_WORKTREE_RLS_TABLES))} "
            f"TO {probe_role}; GRANT SELECT ON saas_preview_leases, "
            f"saas_runner_certificates TO {probe_role}; "
            "SET LOCAL ROLE saas_platform"
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runtime_placements "
                "(id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
                "status) VALUES "
                "(:id, 'omnigent', 'cn-east-1', 'cn-east-1a', 'db-p4-worktree', "
                "'objects-p4-worktree', 'kms-p4-worktree', 'runtime-schema-v1', "
                "'shared-medium', 'active')"
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
                execution_profile_id=scope["profile"],
                execution_profile_hash=scope["profile_hash"],
                repository_id=scope["repository"],
                group_id=scope["group"],
                change_set_id=scope["change_set"],
                quota_id=scope["quota"],
                suffix=scope["suffix"],
            )

    platform = SchedulingControlPlane(_role_factory(engine, "saas_platform"))
    executor_factory = _role_factory(engine, "saas_executor")
    scheduler = SchedulingControlPlane(executor_factory)
    pool_id = platform.create_pool(
        placement_id=placement_id,
        name="postgresql-worktrees",
        queue_class="interactive",
        capacity_slots=2,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    scheduler.configure_tenant_share(
        tenant_id=scopes[0]["tenant"],
        pool_id=pool_id,
        weight=1,
        max_concurrent=1,
        burst_limit=1,
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    scheduler.prepare_dispatch(
        run_id=scopes[0]["run"],
        pool_id=pool_id,
        required_capabilities=["git", "shell"],
        execution_profile_id=scopes[0]["profile"],
        execution_profile_hash=scopes[0]["profile_hash"],
        eligible_at=now,
        maximum_wait=timedelta(hours=1),
    )
    runner = scheduler.register_runner(
        pool_id=pool_id,
        instance_key="postgresql-worktree-runner",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["git", "shell"],
        max_concurrency=1,
        now=now,
    )
    run_lease = scheduler.claim_fair_run(
        runner_id=runner.runner_id,
        connection_generation=runner.connection_generation,
        connection_token=runner.connection_token,
        lease_duration=timedelta(minutes=2),
        capability_actions=["worktree.read", "worktree.write"],
        capability_resource_scope={"change_set_id": str(scopes[0]["change_set"])},
        now=now + timedelta(seconds=1),
    )
    assert run_lease is not None
    barrier = Barrier(2)

    def allocate(_index: int):
        barrier.wait()
        try:
            return WorktreeControlPlane(
                executor_factory, scheduler=SchedulingControlPlane(executor_factory)
            ).allocate_worktree(
                capability_token=run_lease.capability_token,
                runner_id=runner.runner_id,
                run_id=run_lease.run_id,
                change_set_id=scopes[0]["change_set"],
                access_mode="writer",
                reserved_bytes=1_000_000,
                lease_duration=timedelta(seconds=90),
                trace_id="postgresql:concurrent-allocate",
                now=now + timedelta(seconds=2),
            )
        except WorktreeControlPlaneError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = tuple(workers.map(allocate, range(2)))
    leases = [result for result in results if not isinstance(result, WorktreeControlPlaneError)]
    errors = [result for result in results if isinstance(result, WorktreeControlPlaneError)]
    assert len(leases) == 1
    assert len(errors) == 1 and errors[0].code == "changeset_writer_conflict"
    lease = leases[0]

    with pytest.raises(DBAPIError):
        with executor_factory.begin() as db:
            db.execute(
                sa.text("UPDATE saas_changesets SET base_revision = :revision WHERE id = :id"),
                {"revision": "f" * 40, "id": scopes[0]["change_set"]},
            )
    with pytest.raises(DBAPIError):
        with _role_factory(engine, "saas_platform").begin() as db:
            db.execute(
                sa.text(
                    "UPDATE saas_worktree_events SET payload = CAST(:payload AS jsonb) "
                    "WHERE worktree_id = :id"
                ),
                {"payload": "{}", "id": lease.worktree_id},
            )

    with engine.begin() as connection:
        forced = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
                    "AND relrowsecurity AND relforcerowsecurity AND relname = ANY(:tables)"
                ),
                {"tables": sorted(_WORKTREE_RLS_TABLES)},
            ).scalars()
        )
        assert forced == _WORKTREE_RLS_TABLES

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {probe_role}")
        _set_scope(connection, tenant_id=None, space_id=None)
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_repositories")).scalar_one() == 0
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_worktree_instances")
            ).scalar_one()
            == 0
        )
    for index, scope in enumerate(scopes):
        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {probe_role}")
            _set_scope(connection, tenant_id=scope["tenant"], space_id=scope["space"])
            assert (
                connection.execute(sa.text("SELECT count(*) FROM saas_repositories")).scalar_one()
                == 1
            )
            assert (
                connection.execute(sa.text("SELECT count(*) FROM saas_changesets")).scalar_one()
                == 1
            )
            assert connection.execute(
                sa.text("SELECT count(*) FROM saas_worktree_instances")
            ).scalar_one() == int(index == 0)

    governance_factory = _role_factory(engine, "saas_governance")
    impact = WorktreeRemovalImpactProvider(governance_factory).collect(
        tenant_id=scopes[0]["tenant"],
        space_id=scopes[0]["space"],
        user_id=scopes[0]["actor"],
    )
    assert impact.blocking_count == 2
    with pytest.raises(DBAPIError):
        with governance_factory.begin() as db:
            _set_scope(db.connection(), tenant_id=scopes[0]["tenant"], space_id=scopes[0]["space"])
            db.execute(
                sa.text("UPDATE saas_worktree_instances SET status = 'deleted' WHERE id = :id"),
                {"id": lease.worktree_id},
            )
    with pytest.raises(DBAPIError):
        with executor_factory.begin() as db:
            db.execute(
                sa.text("UPDATE saas_repositories SET status = 'archived' WHERE id = :id"),
                {"id": scopes[0]["repository"]},
            )

    with engine.begin() as connection:
        connection.exec_driver_sql(
            f"REVOKE ALL PRIVILEGES ON {', '.join(sorted(_WORKTREE_RLS_TABLES))} "
            f"FROM {probe_role}; REVOKE ALL PRIVILEGES ON saas_preview_leases, "
            f"saas_runner_certificates "
            f"FROM {probe_role}; REVOKE USAGE ON SCHEMA public FROM {probe_role}; "
            f"REVOKE saas_app FROM {probe_role}; DROP ROLE {probe_role}"
        )
    engine.dispose()
