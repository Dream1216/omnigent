from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.dispatch_binding import dispatch_requirements_hash
from saas.control_plane.isolation import IsolationControlPlane, IsolationControlPlaneError
from saas.control_plane.preview_execution import (
    PreviewExecutionControlPlaneError,
    PreviewRunnerExecutionAuthority,
)
from saas.control_plane.runner_execution_spec import managed_run_execution_spec
from saas.control_plane.scheduling import RunnerExecutionEnvelope
from saas.control_plane.worktrees import WorktreeControlPlane, WorktreeControlPlaneError
from saas.control_plane.worktrees import _canonical_hash as _worktree_hash
from saas.production.runner_control import RunnerControlClientLease, RunnerControlError
from saas.production.runner_executor import (
    _RUNNER_AGENT_CONTRACT_FUNCTION_NAMES,
    _RUNNER_AGENT_DATABASE_CONNECTION_LIMIT,
    _RUNNER_AGENT_DATABASE_MAX_OVERFLOW,
    _RUNNER_AGENT_DATABASE_POOL_SIZE,
    _RUNNER_AGENT_DENIED_PG_CATALOG_FUNCTIONS,
    ProductionHostIsolationExecutor,
    _runner_agent_database_login,
    _verify_runner_agent_database_authority,
)
from saas.runner_adapter import RunnerIsolationAdapter, RunnerWorktreeAdapter
from tests.saas.test_scheduling_postgresql import _migrate, _seed_scope

_PRODUCT_REVISION = "a" * 40
_IMAGE_DIGEST = "sha256:" + "b" * 64
_SCHEMA_REVISION = "runtime-schema-v1"
_ADAPTER_CONTRACT = "0.2.0"


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _saas_migration_config(connection: sa.Connection) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option(
        "script_location",
        str(root / "saas/control_plane/migrations"),
    )
    config.attributes["connection"] = connection
    return config


@dataclass(frozen=True, slots=True)
class _Config:
    product_revision: str
    image_digest: str
    runner_id: UUID
    connection_generation: int


class _SecretProvider:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str:
        self.calls += 1
        assert (provider, version_ref) == ("test-vault", "v1")
        assert vault_ref.startswith("runner/")
        return "test-secret-material"


def _assert_database_denied(
    engine: sa.Engine,
    statement: str | sa.TextClause,
    parameters: dict[str, object] | None = None,
) -> None:
    with pytest.raises(sa.exc.ProgrammingError, match="permission denied"):
        with engine.begin() as connection:
            if isinstance(statement, str):
                connection.exec_driver_sql(statement)
            else:
                connection.execute(statement, parameters or {})


def _assert_rls_denied(
    engine: sa.Engine,
    statement: sa.TextClause,
    parameters: dict[str, object],
) -> None:
    with pytest.raises(sa.exc.ProgrammingError, match="row-level security"):
        with engine.begin() as connection:
            connection.execute(statement, parameters)


def _wait_for_database_lock(
    engine: sa.Engine,
    *,
    application_name: str,
    timeout_seconds: float = 5.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with engine.connect() as connection:
            blocked = connection.scalar(
                sa.text(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE datname = current_database() "
                    "AND application_name = :application_name "
                    "AND wait_event_type = 'Lock')"
                ),
                {"application_name": application_name},
            )
        if blocked:
            return
        time.sleep(0.01)
    raise AssertionError(f"{application_name} did not block on a database lock")


def _public_database_privileges(connection: sa.Connection) -> dict[str, frozenset[str]]:
    rows = connection.execute(
        sa.text(
            "SELECT database.datname, acl.privilege_type "
            "FROM pg_database AS database CROSS JOIN LATERAL "
            "aclexplode(COALESCE(database.datacl, "
            "acldefault('d', database.datdba))) AS acl "
            "WHERE database.datallowconn AND acl.grantee = 0 "
            "ORDER BY database.datname, acl.privilege_type"
        )
    ).all()
    result: dict[str, set[str]] = {}
    for database_name, privilege in rows:
        result.setdefault(str(database_name), set()).add(str(privilege))
    return {name: frozenset(privileges) for name, privileges in result.items()}


def _converge_external_runner_database_boundary(connection: sa.Connection) -> None:
    current_database = str(connection.scalar(sa.text("SELECT current_database()")))
    preparer = connection.dialect.identifier_preparer
    database_names = connection.scalars(
        sa.text(
            "SELECT datname FROM pg_database "
            "WHERE datallowconn AND datname <> current_database() ORDER BY datname"
        )
    ).all()
    for database_name in database_names:
        quoted_database = preparer.quote(str(database_name))
        connection.exec_driver_sql(
            f"REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE {quoted_database} FROM PUBLIC"
        )
    quoted_current = preparer.quote(current_database)
    connection.exec_driver_sql(
        f"REVOKE CREATE, TEMPORARY ON DATABASE {quoted_current} FROM PUBLIC"
    )


def _restore_external_public_database_privileges(
    connection: sa.Connection,
    privileges: dict[str, frozenset[str]],
) -> None:
    current_database = str(connection.scalar(sa.text("SELECT current_database()")))
    preparer = connection.dialect.identifier_preparer
    for database_name, allowed in privileges.items():
        if database_name == current_database:
            continue
        quoted_database = preparer.quote(database_name)
        connection.exec_driver_sql(
            f"REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE {quoted_database} FROM PUBLIC"
        )
        if allowed:
            privilege_list = ", ".join(sorted(allowed))
            connection.exec_driver_sql(
                f"GRANT {privilege_list} ON DATABASE {quoted_database} TO PUBLIC"
            )


def _seed_worktree_authority(
    connection: sa.Connection,
    *,
    actor_id: UUID,
    tenant_id: UUID,
    space_id: UUID,
    project_id: UUID,
    repository_id: UUID,
    group_id: UUID,
    change_set_id: UUID,
    quota_id: UUID,
    suffix: str,
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO saas_repositories "
            "(id, tenant_id, space_id, project_id, created_by, provider, "
            "source_binding_key, display_name, default_branch, status, version) VALUES "
            "(:repository, :tenant, :space, :project, :actor, 'github-app', :binding, "
            "'Runner repository', 'main', 'active', 1)"
        ),
        {
            "repository": repository_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "actor": actor_id,
            "binding": f"runner_repo_{suffix}_{repository_id.hex}",
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_changeset_groups "
            "(id, tenant_id, space_id, project_id, created_by, title, status, version) VALUES "
            "(:group_id, :tenant, :space, :project, :actor, 'Runner change', 'open', 1)"
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
            "base_revision": "1" * 40,
            "branch_ref": f"refs/heads/codex/{suffix}",
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_worktree_quotas "
            "(id, tenant_id, space_id, project_id, max_active_instances, "
            "max_active_writers, max_reserved_bytes, max_lease_seconds, "
            "max_lifetime_seconds, gc_grace_seconds, active_instances, active_writers, "
            "reserved_bytes, version) VALUES "
            "(:quota, :tenant, :space, :project, 8, 4, 8000000, 300, 3600, 10, 0, 0, 0, 1)"
        ),
        {
            "quota": quota_id,
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
        },
    )


def test_exact_runner_login_and_run_envelope_rls_binding(
    isolated_postgres_url: str,
) -> None:
    """Exercise the Runner executor through its own LOGIN + FORCE RLS."""

    root = Path(__file__).resolve().parents[2]
    owner_engine = sa.create_engine(isolated_postgres_url)
    admin_role = str(owner_engine.url.username)
    quoted_admin_role = owner_engine.dialect.identifier_preparer.quote(admin_role)
    login_engine = None
    suffix = uuid4().hex[:12]
    schema_owner = f"saas_test_runner_owner_{suffix}"
    external_public_database_privileges: dict[str, frozenset[str]] = {}
    password = f"Runner-{uuid4().hex}"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    actor_id = uuid4()
    tenant_id = uuid4()
    space_id = uuid4()
    project_id = uuid4()
    task_id = uuid4()
    run_id = uuid4()
    capability_id = uuid4()
    capability_token = f"cap_{uuid4().hex}"
    egress_policy_id = uuid4()
    execution_profile_id = uuid4()
    execution_profile_hash = "c" * 64
    alternate_execution_profile_id = uuid4()
    alternate_execution_profile_hash = "d" * 64
    secret_binding_id = uuid4()
    late_secret_binding_id = uuid4()
    alternate_secret_binding_id = uuid4()
    repository_id = uuid4()
    group_id = uuid4()
    quota_id = uuid4()
    placement_id = uuid4()
    pool_id = uuid4()
    runner_id = uuid4()
    login = _runner_agent_database_login(runner_id, 3)
    other_runner_id = uuid4()
    other_actor_id = uuid4()
    other_tenant_id = uuid4()
    other_space_id = uuid4()
    other_project_id = uuid4()
    other_task_id = uuid4()
    other_run_id = uuid4()
    other_capability_id = uuid4()
    other_egress_policy_id = uuid4()
    other_execution_profile_id = uuid4()
    other_execution_profile_hash = "9" * 64
    other_change_set_id = uuid4()
    other_repository_id = uuid4()
    other_group_id = uuid4()
    other_quota_id = uuid4()
    change_set_id = uuid4()
    lease_token = uuid4()
    input_payload: dict[str, object] = {
        "change_set_id": str(change_set_id),
        "execution": {
            "kind": "omnigent.agent.v1",
            "agent_path": "agents/review.yaml",
            "prompt": "Review the managed change set",
        },
    }
    execution_spec = managed_run_execution_spec(input_payload)
    dispatch_max_wait = now + timedelta(minutes=10)
    required_runner_capabilities = [
        "egress.proxy",
        "sandbox.linux_bwrap",
        "sandbox.no_host_socket",
        "sandbox.no_new_privileges",
        "sandbox.nonroot",
        "sandbox.readonly_root",
        "sandbox.resource_limits",
        "secret.broker",
        "syscall.oci-default-v1",
    ]
    requirements_hash = dispatch_requirements_hash(
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        pool_id=pool_id,
        execution_profile_id=execution_profile_id,
        execution_profile_hash=execution_profile_hash,
        egress_policy_id=egress_policy_id,
        egress_policy_hash="0" * 64,
        queue_class="interactive",
        required_capabilities=required_runner_capabilities,
        cost_units=1,
        eligible_at=now,
        max_wait_at=dispatch_max_wait,
    )
    other_requirements_hash = dispatch_requirements_hash(
        tenant_id=other_tenant_id,
        space_id=other_space_id,
        project_id=other_project_id,
        pool_id=pool_id,
        execution_profile_id=other_execution_profile_id,
        execution_profile_hash=other_execution_profile_hash,
        egress_policy_id=other_egress_policy_id,
        egress_policy_hash="8" * 64,
        queue_class="interactive",
        required_capabilities=required_runner_capabilities,
        cost_units=1,
        eligible_at=now,
        max_wait_at=dispatch_max_wait,
    )

    try:
        with owner_engine.begin() as connection:
            external_public_database_privileges = _public_database_privileges(connection)
            _converge_external_runner_database_boundary(connection)
            quoted_owner = connection.dialect.identifier_preparer.quote(schema_owner)
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_owner} NOLOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1"
            )
            connection.exec_driver_sql(f"GRANT USAGE, CREATE ON SCHEMA public TO {quoted_owner}")
            connection.exec_driver_sql("CREATE EXTENSION pg_trgm WITH SCHEMA public")
            connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_owner}")
            _migrate(connection, root)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
            connection.exec_driver_sql("RESET ROLE")

        psql = shutil.which("psql")
        assert psql is not None
        wrapper_environment = {
            "PATH": os.environ.get("PATH", ""),
            "PGHOST": str(owner_engine.url.host),
            "PGPORT": str(owner_engine.url.port),
            "PGUSER": str(owner_engine.url.username),
            "PGDATABASE": str(owner_engine.url.database),
        }
        if owner_engine.url.password is not None:
            wrapper_environment["PGPASSWORD"] = owner_engine.url.password
        wrapper = root / "saas/control_plane/postgresql_runner_agent_cluster.psql"
        with owner_engine.begin() as connection:
            assert connection.scalar(
                sa.text(
                    "SELECT EXISTS (SELECT 1 FROM pg_proc procedure "
                    "CROSS JOIN LATERAL aclexplode(COALESCE(procedure.proacl, "
                    "acldefault('f', procedure.proowner))) acl "
                    "WHERE procedure.oid = "
                    "'pg_catalog.pg_current_xact_id()'::regprocedure "
                    "AND acl.grantee = 0 AND acl.privilege_type = 'EXECUTE')"
                )
            )
            connection.exec_driver_sql(
                "UPDATE saas_alembic_version SET version_num = 'p0s000000009'"
            )
        rejected_bootstrap = subprocess.run(
            [psql, "-X", "--no-password", "-f", str(wrapper)],
            env=wrapper_environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert rejected_bootstrap.returncode != 0
        assert "Runner cluster admission rejected" in rejected_bootstrap.stderr
        with owner_engine.begin() as connection:
            assert connection.scalar(
                sa.text(
                    "SELECT EXISTS (SELECT 1 FROM pg_proc procedure "
                    "CROSS JOIN LATERAL aclexplode(COALESCE(procedure.proacl, "
                    "acldefault('f', procedure.proowner))) acl "
                    "WHERE procedure.oid = "
                    "'pg_catalog.pg_current_xact_id()'::regprocedure "
                    "AND acl.grantee = 0 AND acl.privilege_type = 'EXECUTE')"
                )
            )
            connection.exec_driver_sql(
                "UPDATE saas_alembic_version SET version_num = 'p0s000000012'"
            )
        subprocess.run(
            [psql, "-X", "--no-password", "-f", str(wrapper)],
            env=wrapper_environment,
            capture_output=True,
            text=True,
            check=True,
        )

        with owner_engine.begin() as connection:
            database_name = str(
                connection.execute(sa.text("SELECT current_database()")).scalar_one()
            )
            quoted_database = connection.dialect.identifier_preparer.quote(database_name)
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted_database} TO saas_runner_agent"
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runtime_placements "
                    "(id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                    "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
                    "status) VALUES "
                    "(:id, 'omnigent', 'cn-east-1', 'cn-east-1a', 'db-runner', "
                    "'objects-runner', 'kms-runner', :schema, 'shared-medium', 'active')"
                ),
                {"id": placement_id, "schema": _SCHEMA_REVISION},
            )
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
                execution_profile_hash=execution_profile_hash,
                suffix="runner",
            )
            _seed_worktree_authority(
                connection,
                actor_id=actor_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                repository_id=repository_id,
                group_id=group_id,
                change_set_id=change_set_id,
                quota_id=quota_id,
                suffix="runner",
            )
            _seed_scope(
                connection,
                actor_id=other_actor_id,
                tenant_id=other_tenant_id,
                space_id=other_space_id,
                project_id=other_project_id,
                task_id=other_task_id,
                run_id=other_run_id,
                egress_policy_id=other_egress_policy_id,
                execution_profile_id=other_execution_profile_id,
                execution_profile_hash=other_execution_profile_hash,
                suffix=f"runner-other-{suffix}",
            )
            _seed_worktree_authority(
                connection,
                actor_id=other_actor_id,
                tenant_id=other_tenant_id,
                space_id=other_space_id,
                project_id=other_project_id,
                repository_id=other_repository_id,
                group_id=other_group_id,
                change_set_id=other_change_set_id,
                quota_id=other_quota_id,
                suffix=f"runner-other-{suffix}",
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_execution_profiles "
                    "(id, tenant_id, space_id, project_id, egress_policy_id, created_by, name, "
                    "sandbox_backend, network_mode, root_read_only, run_as_uid, run_as_gid, "
                    "no_new_privileges, host_socket_access, syscall_profile_ref, cpu_millis, "
                    "memory_bytes, pids_limit, allowed_tools, approval_required_tools, "
                    "denied_tools, config_hash, status, version) "
                    "SELECT :alternate, tenant_id, space_id, project_id, egress_policy_id, "
                    "created_by, 'runner-retired-alternate', sandbox_backend, network_mode, "
                    "root_read_only, run_as_uid, run_as_gid, no_new_privileges, "
                    "host_socket_access, syscall_profile_ref, cpu_millis, memory_bytes, "
                    "pids_limit, allowed_tools, approval_required_tools, denied_tools, "
                    ":config_hash, 'retired', 2 FROM saas_execution_profiles WHERE id = :profile"
                ),
                {
                    "alternate": alternate_execution_profile_id,
                    "config_hash": alternate_execution_profile_hash,
                    "profile": execution_profile_id,
                },
            )
            for binding_id, profile_id, name in (
                (secret_binding_id, execution_profile_id, "runner-secret"),
                (
                    alternate_secret_binding_id,
                    alternate_execution_profile_id,
                    "runner-other-profile-secret",
                ),
            ):
                connection.execute(
                    sa.text(
                        "INSERT INTO saas_secret_bindings "
                        "(id, tenant_id, space_id, project_id, execution_profile_id, "
                        "created_by, name, vault_provider, vault_ref, version_ref, "
                        "credential_scheme, host, inject_env, metadata_hash, status, version) "
                        "VALUES (:id, :tenant, :space, :project, :profile, :actor, :name, "
                        "'test-vault', :vault_ref, 'v1', 'bearer', 'api.example.test', "
                        "CAST('[\"RUNNER_TOKEN\"]' AS jsonb), :metadata_hash, 'active', 1)"
                    ),
                    {
                        "id": binding_id,
                        "tenant": tenant_id,
                        "space": space_id,
                        "project": project_id,
                        "profile": profile_id,
                        "actor": actor_id,
                        "name": name,
                        "vault_ref": f"runner/{binding_id}",
                        "metadata_hash": _digest(f"binding:{binding_id}"),
                    },
                )
            connection.execute(
                sa.text(
                    "UPDATE saas_runs SET input = CAST(:input AS jsonb), "
                    "product_revision = :product_revision, status = 'running', "
                    "lease_owner = :lease_owner, lease_token = :lease_token, "
                    "lease_expires_at = :lease_expires_at, heartbeat_at = :now, "
                    "fence_token = 7 WHERE id = :run_id"
                ),
                {
                    "input": json.dumps(input_payload),
                    "product_revision": _PRODUCT_REVISION,
                    "lease_owner": str(runner_id),
                    "lease_token": lease_token,
                    "lease_expires_at": now + timedelta(minutes=5),
                    "now": now,
                    "run_id": run_id,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runner_pools "
                    "(id, placement_id, failure_domain, name, queue_class, capacity_slots, "
                    "reserved_slots, status, protocol_version, source_revision, "
                    "schema_revision, adapter_contract_version) VALUES "
                    "(:id, :placement, 'cn-east-1a', 'runner-production', 'interactive', "
                    "1, 0, 'active', 2, :product, :schema, :adapter)"
                ),
                {
                    "id": pool_id,
                    "placement": placement_id,
                    "product": _PRODUCT_REVISION,
                    "schema": _SCHEMA_REVISION,
                    "adapter": _ADAPTER_CONTRACT,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runner_registrations "
                    "(id, pool_id, placement_id, instance_key, failure_domain, status, "
                    "connection_generation, connection_token_hash, protocol_version, "
                    "source_revision, schema_revision, adapter_contract_version, "
                    "capabilities, capabilities_hash, max_concurrency, active_leases, "
                    "last_heartbeat_at, registered_at) VALUES "
                    "(:id, :pool, :placement, 'runner-production-1', 'cn-east-1a', "
                    "'online', 3, :token_hash, 2, :product, :schema, :adapter, "
                    "CAST(:capabilities AS jsonb), :capabilities_hash, 1, 0, :now, :now)"
                ),
                {
                    "id": runner_id,
                    "pool": pool_id,
                    "placement": placement_id,
                    "token_hash": "d" * 64,
                    "product": _PRODUCT_REVISION,
                    "schema": _SCHEMA_REVISION,
                    "adapter": _ADAPTER_CONTRACT,
                    "capabilities": json.dumps(required_runner_capabilities),
                    "capabilities_hash": _digest(
                        json.dumps(required_runner_capabilities, separators=(",", ":"))
                    ),
                    "now": now,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runner_registrations "
                    "(id, pool_id, placement_id, instance_key, failure_domain, status, "
                    "connection_generation, connection_token_hash, protocol_version, "
                    "source_revision, schema_revision, adapter_contract_version, "
                    "capabilities, capabilities_hash, max_concurrency, active_leases, "
                    "last_heartbeat_at, registered_at) "
                    "SELECT :other_runner, pool_id, placement_id, 'runner-production-2', "
                    "failure_domain, 'online', 1, :token_hash, protocol_version, "
                    "source_revision, schema_revision, adapter_contract_version, "
                    "capabilities, capabilities_hash, max_concurrency, 0, :now, :now "
                    "FROM saas_runner_registrations WHERE id = :runner"
                ),
                {
                    "other_runner": other_runner_id,
                    "runner": runner_id,
                    "token_hash": "1" * 64,
                    "now": now,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_run_dispatches "
                    "(run_id, tenant_id, space_id, project_id, pool_id, "
                    "execution_profile_id, execution_profile_hash, egress_policy_id, "
                    "egress_policy_hash, queue_class, required_capabilities, "
                    "requirements_hash, cost_units, eligible_at, max_wait_at, status, "
                    "selected_runner_id, selected_failure_domain, dispatch_generation) VALUES "
                    "(:run, :tenant, :space, :project, :pool, :profile, :profile_hash, "
                    ":egress, :egress_hash, 'interactive', CAST(:capabilities AS jsonb), "
                    ":requirements_hash, 1, :now, :max_wait, 'leased', "
                    ":runner, 'cn-east-1a', 1)"
                ),
                {
                    "run": run_id,
                    "tenant": tenant_id,
                    "space": space_id,
                    "project": project_id,
                    "pool": pool_id,
                    "profile": execution_profile_id,
                    "profile_hash": execution_profile_hash,
                    "egress": egress_policy_id,
                    "egress_hash": "0" * 64,
                    "capabilities": json.dumps(required_runner_capabilities),
                    "requirements_hash": requirements_hash,
                    "now": now,
                    "max_wait": dispatch_max_wait,
                    "runner": runner_id,
                },
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_runs SET input = CAST(:input AS jsonb), "
                    "product_revision = :product_revision, status = 'running', "
                    "lease_owner = :lease_owner, lease_token = :lease_token, "
                    "lease_expires_at = :lease_expires_at, heartbeat_at = :now, "
                    "fence_token = 11 WHERE id = :run_id"
                ),
                {
                    "input": json.dumps(
                        {
                            "change_set_id": str(other_change_set_id),
                            "execution": input_payload["execution"],
                        }
                    ),
                    "product_revision": _PRODUCT_REVISION,
                    "lease_owner": str(other_runner_id),
                    "lease_token": uuid4(),
                    "lease_expires_at": now + timedelta(minutes=5),
                    "now": now,
                    "run_id": other_run_id,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_run_dispatches "
                    "(run_id, tenant_id, space_id, project_id, pool_id, "
                    "execution_profile_id, execution_profile_hash, egress_policy_id, "
                    "egress_policy_hash, queue_class, required_capabilities, "
                    "requirements_hash, cost_units, eligible_at, max_wait_at, status, "
                    "selected_runner_id, selected_failure_domain, dispatch_generation) VALUES "
                    "(:run, :tenant, :space, :project, :pool, :profile, :profile_hash, "
                    ":egress, :egress_hash, 'interactive', CAST(:capabilities AS jsonb), "
                    ":requirements_hash, 1, :now, :max_wait, 'leased', "
                    ":runner, 'cn-east-1a', 2)"
                ),
                {
                    "run": other_run_id,
                    "tenant": other_tenant_id,
                    "space": other_space_id,
                    "project": other_project_id,
                    "pool": pool_id,
                    "profile": other_execution_profile_id,
                    "profile_hash": other_execution_profile_hash,
                    "egress": other_egress_policy_id,
                    "egress_hash": "8" * 64,
                    "capabilities": json.dumps(required_runner_capabilities),
                    "requirements_hash": other_requirements_hash,
                    "now": now,
                    "max_wait": dispatch_max_wait,
                    "runner": other_runner_id,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_capability_tokens "
                    "(id, token_hash, tenant_id, space_id, project_id, run_id, "
                    "runner_id, runner_connection_generation, dispatch_generation, "
                    "fence_token, allowed_actions, resource_scope, issued_at, expires_at) "
                    "VALUES (:id, :token_hash, :tenant, :space, :project, :run, :runner, "
                    "1, 2, 11, CAST(:actions AS jsonb), CAST(:scope AS jsonb), :now, :expires)"
                ),
                {
                    "id": other_capability_id,
                    "token_hash": "7" * 64,
                    "tenant": other_tenant_id,
                    "space": other_space_id,
                    "project": other_project_id,
                    "run": other_run_id,
                    "runner": other_runner_id,
                    "actions": json.dumps(
                        [
                            "run.execute",
                            "sandbox.launch",
                            "worktree.read",
                            "worktree.write",
                        ]
                    ),
                    "scope": json.dumps({"change_set_id": str(other_change_set_id)}),
                    "now": now,
                    "expires": now + timedelta(minutes=5),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_capability_tokens "
                    "(id, token_hash, tenant_id, space_id, project_id, run_id, "
                    "runner_id, runner_connection_generation, dispatch_generation, "
                    "fence_token, allowed_actions, resource_scope, issued_at, expires_at) "
                    "VALUES (:id, :token_hash, :tenant, :space, :project, :run, :runner, "
                    "3, 1, 7, CAST(:actions AS jsonb), CAST(:scope AS jsonb), :now, :expires)"
                ),
                {
                    "id": capability_id,
                    "token_hash": _digest(capability_token),
                    "tenant": tenant_id,
                    "space": space_id,
                    "project": project_id,
                    "run": run_id,
                    "runner": runner_id,
                    "actions": json.dumps(
                        [
                            "run.execute",
                            "sandbox.launch",
                            "worktree.read",
                            "worktree.write",
                        ]
                    ),
                    "scope": json.dumps({"change_set_id": str(change_set_id)}),
                    "now": now,
                    "expires": now + timedelta(minutes=5),
                },
            )
            quoted_login = connection.dialect.identifier_preparer.quote(login)
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_login} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS "
                f"CONNECTION LIMIT {_RUNNER_AGENT_DATABASE_CONNECTION_LIMIT} "
                f"PASSWORD '{password}'"
            )
            connection.exec_driver_sql(
                f"GRANT saas_runner_agent TO {quoted_login} WITH INHERIT TRUE, SET FALSE"
            )

            expected_xact_roles = (
                "saas_app",
                "saas_governance",
                "saas_public_api",
                "saas_dispatcher",
                "saas_executor",
                "saas_platform",
                "saas_platform_governance",
                "saas_platform_support",
                "saas_privacy_executor",
                "saas_privacy_dispatcher",
                "saas_registration",
                "saas_onboarding",
                "saas_billing",
                "saas_metering",
            )
            assert all(
                connection.scalar(
                    sa.text(
                        "SELECT has_function_privilege("
                        ":role, 'pg_catalog.pg_advisory_xact_lock(bigint)', 'EXECUTE')"
                    ),
                    {"role": role},
                )
                for role in expected_xact_roles
            )
            assert connection.scalar(
                sa.text(
                    "SELECT has_function_privilege("
                    "'saas_governance', 'pg_catalog.pg_advisory_lock(bigint)', 'EXECUTE')"
                )
            )
            assert not connection.scalar(
                sa.text(
                    "SELECT has_function_privilege("
                    "'saas_app', 'pg_catalog.pg_advisory_lock(bigint)', 'EXECUTE')"
                )
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM pg_proc procedure "
                        "CROSS JOIN LATERAL aclexplode(procedure.proacl) acl "
                        "JOIN pg_database database ON database.datname = current_database() "
                        "WHERE procedure.oid = "
                        "'pg_catalog.pg_try_advisory_lock(bigint)'::regprocedure "
                        "AND acl.grantee = database.datdba "
                        "AND acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable"
                    )
                )
                == 1
            )
            assert connection.scalar(
                sa.text(
                    "SELECT has_function_privilege("
                    ":role, 'pg_catalog.pg_advisory_xact_lock(bigint)', 'EXECUTE')"
                ),
                {"role": schema_owner},
            )
            assert not connection.scalar(
                sa.text(
                    "SELECT has_function_privilege("
                    ":role, 'pg_catalog.pg_try_advisory_lock(bigint)', 'EXECUTE')"
                ),
                {"role": schema_owner},
            )

        canonical_payload = {
            "ascii": 'quote:" slash:\\ control:\n',
            "nested": {"false": False, "integer": 42, "none": None},
        }
        with owner_engine.connect() as connection:
            assert connection.scalar(
                sa.text("SELECT public.saas_canonical_json_sha256_v1(CAST(:payload AS jsonb))"),
                {"payload": json.dumps(canonical_payload)},
            ) == _worktree_hash(canonical_payload)
            for invalid_payload in ({"unicode": "\u4e2d\u6587"}, {"fraction": 1.5}):
                with pytest.raises(sa.exc.DataError):
                    with connection.begin_nested():
                        connection.scalar(
                            sa.text(
                                "SELECT public.saas_canonical_json_sha256_v1("
                                "CAST(:payload AS jsonb))"
                            ),
                            {"payload": json.dumps(invalid_payload)},
                        )

        executor_url = owner_engine.url.set(username=login, password=password)
        login_engine = sa.create_engine(
            executor_url,
            pool_pre_ping=True,
            pool_size=_RUNNER_AGENT_DATABASE_POOL_SIZE,
            max_overflow=_RUNNER_AGENT_DATABASE_MAX_OVERFLOW,
        )
        _verify_runner_agent_database_authority(
            login_engine,
            runner_id=runner_id,
            connection_generation=3,
        )
        sessions = sessionmaker(login_engine, expire_on_commit=False, class_=Session)
        config = _Config(
            product_revision=_PRODUCT_REVISION,
            image_digest=_IMAGE_DIGEST,
            runner_id=runner_id,
            connection_generation=3,
        )

        def build_executor() -> ProductionHostIsolationExecutor:
            return ProductionHostIsolationExecutor(
                config=config,
                engine=login_engine,
                sessions=sessions,
                worktrees=cast(WorktreeControlPlane, object()),
                isolation=cast(IsolationControlPlane, object()),
                worktree_adapter=cast(RunnerWorktreeAdapter, object()),
                isolation_adapter=cast(RunnerIsolationAdapter, object()),
                reserved_bytes=1,
                worktree_lease_seconds=30,
                command_timeout_seconds=30,
            )

        def assert_dynamic_authority_drift(
            *,
            apply_sql: str,
            restore_sql: str,
        ) -> None:
            candidate = build_executor()
            candidate.assert_claimable()
            with owner_engine.begin() as connection:
                connection.exec_driver_sql(apply_sql)
            try:
                with pytest.raises(RunnerControlError) as drifted:
                    candidate.assert_claimable()
                assert drifted.value.code == "runner_database_authority_drifted"
            finally:
                with owner_engine.begin() as connection:
                    connection.exec_driver_sql(restore_sql)
            with pytest.raises(RunnerControlError) as poisoned:
                candidate.assert_claimable()
            assert poisoned.value.code == "runner_database_authority_poisoned"

        def assert_postmaster_setting_drift(
            *,
            name: str,
            rejected_value: int,
            restored_value: int,
        ) -> None:
            assert name in {"max_notify_queue_pages", "max_prepared_transactions"}

            def configure(value: int, *, pending_restart: bool) -> None:
                with owner_engine.connect().execution_options(
                    isolation_level="AUTOCOMMIT"
                ) as connection:
                    connection.exec_driver_sql(f"ALTER SYSTEM SET {name} = {value}")
                    connection.execute(sa.text("SELECT pg_reload_conf()"))
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with owner_engine.connect() as connection:
                        observed = bool(
                            connection.scalar(
                                sa.text(
                                    "SELECT pending_restart FROM pg_settings WHERE name = :name"
                                ),
                                {"name": name},
                            )
                        )
                    if observed is pending_restart:
                        return
                    time.sleep(0.02)
                raise AssertionError(f"{name} pending_restart did not converge")

            candidate = build_executor()
            candidate.assert_claimable()
            configure(rejected_value, pending_restart=True)
            try:
                with pytest.raises(RunnerControlError) as drifted:
                    candidate.assert_claimable()
                assert drifted.value.code == "runner_database_authority_drifted"
            finally:
                configure(restored_value, pending_restart=False)
            with pytest.raises(RunnerControlError) as poisoned:
                candidate.assert_claimable()
            assert poisoned.value.code == "runner_database_authority_poisoned"

        executor = build_executor()
        envelope = RunnerExecutionEnvelope(
            change_set_id=change_set_id,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            run_id=run_id,
            runner_id=runner_id,
            fence_token=7,
            execution_profile_id=execution_profile_id,
            execution_profile_hash=execution_profile_hash,
            egress_policy_id=egress_policy_id,
            egress_policy_hash="0" * 64,
            product_revision=_PRODUCT_REVISION,
            image_digest=_IMAGE_DIGEST,
            execution_spec_hash=execution_spec.spec_hash,
            launch_argv=execution_spec.launch_argv,
        )
        lease = RunnerControlClientLease(
            run_id=run_id,
            lease_token=lease_token,
            fence_token=7,
            dispatch_generation=1,
            failure_domain="cn-east-1a",
            expires_at=now + timedelta(minutes=5),
            capability_id=capability_id,
            capability_token=capability_token,
            execution_envelope=envelope,
        )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_runner_registrations SET active_leases = 1 WHERE id = :runner_id"
                ),
                {"runner_id": runner_id},
            )
        with pytest.raises(RunnerControlError) as busy_claim_boundary:
            _verify_runner_agent_database_authority(
                login_engine,
                runner_id=runner_id,
                connection_generation=3,
            )
        assert busy_claim_boundary.value.code == "runner_executor_not_ready"
        loaded_run, loaded_execution = executor._load_run(lease)
        assert loaded_run.id == run_id
        assert loaded_execution.launch_argv == execution_spec.launch_argv

        # Even attacker-controlled tenant GUCs cannot escape the restrictive
        # Runner fence.  Runner B and its second-tenant Run remain invisible.
        with login_engine.begin() as connection:
            connection.execute(
                sa.text("SELECT set_config('app.tenant_id', :tenant, true)"),
                {"tenant": str(other_tenant_id)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.space_id', :space, true)"),
                {"space": str(other_space_id)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.project_id', :project, true)"),
                {"project": str(other_project_id)},
            )
            assert connection.scalars(
                sa.text("SELECT id FROM saas_runner_registrations ORDER BY id")
            ).all() == [runner_id]
            assert connection.scalars(
                sa.text("SELECT id FROM saas_capability_tokens ORDER BY id")
            ).all() == [capability_id]
            assert connection.scalars(
                sa.text("SELECT run_id FROM saas_run_dispatches ORDER BY run_id")
            ).all() == [run_id]
            assert connection.scalars(sa.text("SELECT id FROM saas_runs ORDER BY id")).all() == [
                run_id
            ]
        _assert_database_denied(
            login_engine,
            sa.text("UPDATE saas_runs SET id = id WHERE id = :run_id"),
            {"run_id": other_run_id},
        )
        _assert_database_denied(
            login_engine,
            sa.text("UPDATE saas_runner_registrations SET id = id WHERE id = :runner_id"),
            {"runner_id": other_runner_id},
        )

        # The real Runner LOGIN can perform its intended writer lifecycle, and
        # FK-free Outbox rows are flushed only after their authoritative entity.
        worktree_control = WorktreeControlPlane(sessions)
        isolation_control = IsolationControlPlane(sessions)
        rebuild_source_id = uuid4()
        ambiguous_rebuild_source_id = uuid4()
        historical_worktrees = [
            {
                "id": rebuild_source_id,
                "status": "rebuild_pending",
                "access_mode": "writer",
                "dirty": True,
                "recovery": "artifact://runner/rebuild-source",
                "fence": 101,
            },
            {
                "id": ambiguous_rebuild_source_id,
                "status": "rebuild_pending",
                "access_mode": "writer",
                "dirty": True,
                "recovery": "artifact://runner/ambiguous-rebuild-source",
                "fence": 109,
            },
            {
                "id": uuid4(),
                "status": "released",
                "access_mode": "writer",
                "dirty": True,
                "recovery": "artifact://runner/released",
                "fence": 102,
            },
            {
                "id": uuid4(),
                "status": "quarantined",
                "access_mode": "writer",
                "dirty": True,
                "recovery": "artifact://runner/quarantined",
                "fence": 103,
            },
            {
                "id": uuid4(),
                "status": "gc_eligible",
                "access_mode": "writer",
                "dirty": True,
                "recovery": "artifact://runner/gc-eligible",
                "fence": 104,
            },
            {
                "id": uuid4(),
                "status": "deleted",
                "access_mode": "writer",
                "dirty": True,
                "recovery": "artifact://runner/deleted",
                "fence": 105,
            },
            {
                "id": uuid4(),
                "status": "rebuild_pending",
                "access_mode": "readonly",
                "dirty": False,
                "recovery": "artifact://runner/readonly",
                "fence": 106,
            },
            {
                "id": uuid4(),
                "status": "rebuild_pending",
                "access_mode": "writer",
                "dirty": False,
                "recovery": "artifact://runner/clean",
                "fence": 107,
            },
            {
                "id": uuid4(),
                "status": "rebuild_pending",
                "access_mode": "writer",
                "dirty": True,
                "recovery": None,
                "fence": 108,
            },
        ]
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO saas_worktree_instances "
                    "(id, tenant_id, space_id, project_id, change_set_id, run_id, "
                    "runner_id, created_by, opaque_runtime_key, access_mode, status, "
                    "lease_generation, run_fence_token, runner_connection_generation, "
                    "lease_token_hash, lease_expires_at, heartbeat_at, maximum_lifetime_at, "
                    "reserved_bytes, actual_bytes, dirty, recovery_artifact_ref, "
                    "environment_snapshot_ref, event_sequence, released_at, "
                    "quarantine_reason, deleted_at, created_at, updated_at) VALUES "
                    "(:id, :tenant, :space, :project, :change_set, :run, :runner, :actor, "
                    ":runtime_key, :access_mode, :status, 1, :fence, 1, NULL, NULL, :now, "
                    ":maximum, 1, 1, :dirty, :recovery, NULL, 0, :released_at, "
                    ":quarantine_reason, :deleted_at, :now, :now)"
                ),
                [
                    {
                        **candidate,
                        "tenant": tenant_id,
                        "space": space_id,
                        "project": project_id,
                        "change_set": change_set_id,
                        "run": run_id,
                        "runner": other_runner_id,
                        "actor": actor_id,
                        "runtime_key": f"wti_{uuid4().hex}{uuid4().hex[:16]}",
                        "now": now,
                        "maximum": now + timedelta(hours=1),
                        "released_at": (
                            now
                            if candidate["status"]
                            in {"released", "quarantined", "gc_eligible", "deleted"}
                            else None
                        ),
                        "quarantine_reason": (
                            "historical" if candidate["status"] == "quarantined" else None
                        ),
                        "deleted_at": now if candidate["status"] == "deleted" else None,
                    }
                    for candidate in historical_worktrees
                ],
            )
        with login_engine.connect() as connection:
            assert connection.scalars(
                sa.text(
                    "SELECT id FROM saas_worktree_instances "
                    "WHERE id = ANY(CAST(:ids AS uuid[])) ORDER BY id"
                ),
                {"ids": [str(item["id"]) for item in historical_worktrees]},
            ).all() == sorted([rebuild_source_id, ambiguous_rebuild_source_id])
        with pytest.raises(WorktreeControlPlaneError) as readonly_rebuild:
            worktree_control.allocate_worktree(
                capability_token=capability_token,
                runner_id=runner_id,
                run_id=run_id,
                change_set_id=change_set_id,
                access_mode="readonly",
                reserved_bytes=1024,
                lease_duration=timedelta(seconds=60),
                trace_id="runner-agent-postgresql-readonly-rebuild",
                rebuild_from_id=rebuild_source_id,
                now=now,
            )
        assert readonly_rebuild.value.code == "runner_worktree_rebuild_requires_writer"
        with pytest.raises(WorktreeControlPlaneError) as ambiguous_rebuild:
            worktree_control.allocate_worktree(
                capability_token=capability_token,
                runner_id=runner_id,
                run_id=run_id,
                change_set_id=change_set_id,
                access_mode="writer",
                reserved_bytes=1024,
                lease_duration=timedelta(seconds=60),
                trace_id="runner-agent-postgresql-ambiguous-rebuild",
                now=now,
            )
        assert ambiguous_rebuild.value.code == "runner_worktree_rebuild_source_invalid"
        with owner_engine.begin() as connection:
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_worktree_instances "
                        "WHERE run_id = :run_id AND run_fence_token = 7"
                    ),
                    {"run_id": run_id},
                )
                == 0
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_worktree_instances SET status = 'released', "
                    "released_at = :now WHERE id = :source"
                ),
                {"now": now, "source": ambiguous_rebuild_source_id},
            )
        worktree_lease = worktree_control.allocate_worktree(
            capability_token=capability_token,
            runner_id=runner_id,
            run_id=run_id,
            change_set_id=change_set_id,
            access_mode="writer",
            reserved_bytes=1024,
            lease_duration=timedelta(seconds=60),
            trace_id="runner-agent-postgresql",
            now=now,
        )
        replayed_worktree_lease = worktree_control.allocate_worktree(
            capability_token=capability_token,
            runner_id=runner_id,
            run_id=run_id,
            change_set_id=change_set_id,
            access_mode="writer",
            reserved_bytes=1024,
            lease_duration=timedelta(seconds=60),
            trace_id="runner-agent-postgresql-retry-after-lost-response",
            now=now + timedelta(seconds=30),
        )
        assert replayed_worktree_lease == worktree_lease
        with pytest.raises(WorktreeControlPlaneError) as altered_same_fence:
            worktree_control.allocate_worktree(
                capability_token=capability_token,
                runner_id=runner_id,
                run_id=run_id,
                change_set_id=change_set_id,
                access_mode="writer",
                reserved_bytes=2048,
                lease_duration=timedelta(seconds=60),
                trace_id="runner-agent-postgresql-altered-same-fence",
                now=now + timedelta(seconds=31),
            )
        assert altered_same_fence.value.code == "runner_worktree_run_already_allocated"
        with login_engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.text("SELECT id FROM saas_worktree_instances WHERE id = :source"),
                    {"source": rebuild_source_id},
                )
                is None
            )
        with owner_engine.begin() as connection:
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_worktree_instances "
                        "WHERE run_id = :run_id AND run_fence_token = 7"
                    ),
                    {"run_id": run_id},
                )
                == 1
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_worktree_events "
                        "WHERE worktree_id = :worktree AND event_type = 'worktree.rebuilt'"
                    ),
                    {"worktree": worktree_lease.worktree_id},
                )
                == 1
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE idempotency_key = :key"
                    ),
                    {"key": f"worktree:{worktree_lease.worktree_id}:1"},
                )
                == 1
            )
        for denied_statement in (
            "SELECT connection_token_hash FROM public.saas_runner_registrations",
            "SELECT token_hash FROM public.saas_capability_tokens",
            "SELECT lease_token_hash FROM public.saas_worktree_instances",
            "INSERT INTO public.saas_worktree_instances DEFAULT VALUES",
            "INSERT INTO public.saas_worktree_events DEFAULT VALUES",
            "INSERT INTO public.saas_control_plane_outbox DEFAULT VALUES",
            "INSERT INTO public.saas_preview_commands DEFAULT VALUES",
            "UPDATE public.saas_worktree_instances SET status = 'released'",
        ):
            _assert_database_denied(login_engine, denied_statement)
        materializing = worktree_control.begin_materialization(
            worktree_id=worktree_lease.worktree_id,
            runner_id=runner_id,
            lease_generation=worktree_lease.lease_generation,
            run_fence_token=worktree_lease.run_fence_token,
            lease_token=worktree_lease.lease_token,
            trace_id="runner-agent-postgresql",
            now=now,
        )
        assert materializing.status == "materializing"

        # Authority must be re-read after the last potentially blocking write
        # lock.  A request that observed a live capability before waiting on
        # its own Worktree cannot commit after the central kill switch fires.
        blocked_application_name = f"runner-fresh-authority-{suffix}"
        blocked_engine = sa.create_engine(
            executor_url,
            connect_args={"application_name": blocked_application_name},
            pool_pre_ping=True,
            pool_size=1,
            max_overflow=0,
        )
        blocked_sessions = sessionmaker(
            blocked_engine,
            expire_on_commit=False,
            class_=Session,
        )
        blocked_worktrees = WorktreeControlPlane(blocked_sessions)
        try:
            with owner_engine.connect() as held_connection:
                held_transaction = held_connection.begin()
                before_wait = held_connection.execute(
                    sa.text(
                        "SELECT status, event_sequence, actual_bytes, heartbeat_at, "
                        "lease_expires_at, xmin::text FROM saas_worktree_instances "
                        "WHERE id = :worktree FOR UPDATE"
                    ),
                    {"worktree": worktree_lease.worktree_id},
                ).one()
                pool = ThreadPoolExecutor(max_workers=1)
                try:
                    waiting_transition = pool.submit(
                        blocked_worktrees.acknowledge_ready,
                        worktree_id=worktree_lease.worktree_id,
                        runner_id=runner_id,
                        lease_generation=worktree_lease.lease_generation,
                        run_fence_token=worktree_lease.run_fence_token,
                        lease_token=worktree_lease.lease_token,
                        actual_bytes=512,
                        trace_id="runner-agent-revoked-after-wait",
                        now=now,
                    )
                    try:
                        _wait_for_database_lock(
                            owner_engine,
                            application_name=blocked_application_name,
                        )
                        kill_switch_started = time.monotonic()
                        with owner_engine.begin() as central_connection:
                            central_connection.exec_driver_sql("SET LOCAL lock_timeout = '400ms'")
                            central_connection.execute(
                                sa.text(
                                    "UPDATE saas_capability_tokens SET "
                                    "revoked_at = clock_timestamp(), "
                                    "revocation_reason = 'fresh-authority-test' "
                                    "WHERE id = :id"
                                ),
                                {"id": capability_id},
                            )
                            central_connection.execute(
                                sa.text(
                                    "UPDATE saas_runner_registrations "
                                    "SET status = 'offline' WHERE id = :id"
                                ),
                                {"id": runner_id},
                            )
                            central_connection.execute(
                                sa.text(
                                    "UPDATE saas_execution_profiles SET status = status "
                                    "WHERE id = :id"
                                ),
                                {"id": execution_profile_id},
                            )
                        kill_switch_elapsed = time.monotonic() - kill_switch_started
                        assert not waiting_transition.done()
                    finally:
                        if held_transaction.is_active:
                            held_transaction.rollback()
                    with pytest.raises(WorktreeControlPlaneError) as stale_after_wait:
                        waiting_transition.result(timeout=5)
                    assert kill_switch_elapsed < 0.5
                    assert stale_after_wait.value.code in {
                        "runner_worktree_runner_stale",
                        "runner_worktree_capability_stale",
                    }
                finally:
                    pool.shutdown(wait=True, cancel_futures=True)
        finally:
            blocked_engine.dispose()

        with owner_engine.begin() as connection:
            after_wait = connection.execute(
                sa.text(
                    "SELECT status, event_sequence, actual_bytes, heartbeat_at, "
                    "lease_expires_at, xmin::text FROM saas_worktree_instances "
                    "WHERE id = :worktree"
                ),
                {"worktree": worktree_lease.worktree_id},
            ).one()
            assert after_wait == before_wait
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_worktree_events "
                        "WHERE worktree_id = :worktree "
                        "AND event_type = 'worktree.mounted'"
                    ),
                    {"worktree": worktree_lease.worktree_id},
                )
                == 0
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_capability_tokens SET revoked_at = NULL, "
                    "revocation_reason = NULL WHERE id = :id"
                ),
                {"id": capability_id},
            )
            connection.execute(
                sa.text("UPDATE saas_runner_registrations SET status = 'online' WHERE id = :id"),
                {"id": runner_id},
            )

        materialization_grant = worktree_control.materialization_grant(
            worktree_id=worktree_lease.worktree_id,
            runner_id=runner_id,
            lease_generation=worktree_lease.lease_generation,
            run_fence_token=worktree_lease.run_fence_token,
            lease_token=worktree_lease.lease_token,
            now=now,
        )
        issued_grant = isolation_control.issue_launch_grant(
            capability_token=capability_token,
            runner_id=runner_id,
            run_id=run_id,
            worktree_grant=materialization_grant,
            now=now,
        )
        replayed_grant = isolation_control.issue_launch_grant(
            capability_token=capability_token,
            runner_id=runner_id,
            run_id=run_id,
            worktree_grant=materialization_grant,
            now=now + timedelta(seconds=30),
        )
        assert replayed_grant == issued_grant

        # Read-only metadata admission must not let a malicious outer
        # transaction hold shared profile, policy, or binding rows hostage.
        with login_engine.connect() as held_connection:
            held_transaction = held_connection.begin()
            held_connection.scalar(
                sa.text(
                    "SELECT public.saas_runner_isolation_metadata_v1("
                    ":token_hash, :runner_id, :run_id)"
                ),
                {
                    "token_hash": _digest(issued_grant.token),
                    "runner_id": runner_id,
                    "run_id": run_id,
                },
            )
            with owner_engine.connect() as central_connection:
                central_transaction = central_connection.begin()
                central_connection.exec_driver_sql("SET LOCAL lock_timeout = '500ms'")
                central_connection.execute(
                    sa.text("UPDATE saas_execution_profiles SET status = status WHERE id = :id"),
                    {"id": execution_profile_id},
                )
                central_connection.execute(
                    sa.text("UPDATE saas_egress_policies SET status = status WHERE id = :id"),
                    {"id": egress_policy_id},
                )
                central_connection.execute(
                    sa.text("UPDATE saas_secret_bindings SET status = status WHERE id = :id"),
                    {"id": secret_binding_id},
                )
                central_transaction.rollback()
            held_transaction.rollback()

        raw_isolation_insert = sa.text(
            "INSERT INTO saas_run_isolation_grants "
            "(id, token_hash, tenant_id, space_id, project_id, run_id, runner_id, "
            "worktree_id, execution_profile_id, capability_id, run_fence_token, "
            "runner_connection_generation, worktree_lease_generation, grant_hash, status, "
            "expires_at) VALUES (:id, :token_hash, :tenant, :space, :project, :run, :runner, "
            ":worktree, :profile, :capability, 7, 3, 1, :grant_hash, 'active', :expires)"
        )
        raw_isolation_parameters: dict[str, object] = {
            "id": uuid4(),
            "token_hash": _digest(f"forged-isolation:{suffix}"),
            "tenant": tenant_id,
            "space": space_id,
            "project": project_id,
            "run": run_id,
            "runner": runner_id,
            "worktree": worktree_lease.worktree_id,
            "profile": execution_profile_id,
            "capability": capability_id,
            "grant_hash": "6" * 64,
            "expires": now + timedelta(minutes=10),
        }
        _assert_database_denied(login_engine, raw_isolation_insert, raw_isolation_parameters)
        _assert_database_denied(
            login_engine,
            raw_isolation_insert,
            {
                **raw_isolation_parameters,
                "id": uuid4(),
                "token_hash": _digest(f"forged-profile:{suffix}"),
                "profile": alternate_execution_profile_id,
                "expires": now + timedelta(seconds=30),
            },
        )

        forged_secret_token = f"sec_forged_{uuid4().hex}"
        _assert_database_denied(
            login_engine,
            sa.text(
                "INSERT INTO saas_secret_access_leases "
                "(id, token_hash, tenant_id, space_id, project_id, isolation_grant_id, "
                "secret_binding_id, run_id, runner_id, run_fence_token, "
                "runner_connection_generation, status, expires_at) VALUES "
                "(:id, :token_hash, :tenant, :space, :project, :grant, :binding, :run, "
                ":runner, 7, 3, 'active', :expires)"
            ),
            {
                "id": uuid4(),
                "token_hash": _digest(forged_secret_token),
                "tenant": tenant_id,
                "space": space_id,
                "project": project_id,
                "grant": issued_grant.grant_id,
                "binding": alternate_secret_binding_id,
                "run": run_id,
                "runner": runner_id,
                "expires": issued_grant.expires_at,
            },
        )
        with pytest.raises(IsolationControlPlaneError) as forged_redeem:
            isolation_control.redeem_secret(
                token=forged_secret_token,
                runner_id=runner_id,
                run_id=run_id,
                provider=_SecretProvider(),
                now=now,
            )
        assert forged_redeem.value.code == "secret_lease_invalid"

        launch = isolation_control.redeem_launch_grant(
            token=issued_grant.token,
            runner_id=runner_id,
            run_id=run_id,
            now=now,
        )
        replayed_launch = isolation_control.redeem_launch_grant(
            token=issued_grant.token,
            runner_id=runner_id,
            run_id=run_id,
            now=now + timedelta(seconds=30),
        )
        assert replayed_launch == launch
        assert [secret.binding_id for secret in launch.secret_leases] == [secret_binding_id]

        # Redemption freezes the exact binding set.  A later central binding
        # addition or deactivation cannot mint another lease from the already
        # redeemed grant, and the rejected replay leaves grant/outbox evidence
        # and every existing lease untouched.
        with owner_engine.begin() as connection:
            frozen_grant = connection.execute(
                sa.text(
                    "SELECT status, redeemed_at, xmin::text "
                    "FROM saas_run_isolation_grants WHERE id = :grant"
                ),
                {"grant": issued_grant.grant_id},
            ).one()
            frozen_lease_count = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM saas_secret_access_leases "
                    "WHERE isolation_grant_id = :grant"
                ),
                {"grant": issued_grant.grant_id},
            )
            frozen_outbox_count = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM saas_control_plane_outbox WHERE idempotency_key = :key"
                ),
                {"key": f"run-isolation:{issued_grant.grant_id}:redeemed"},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_secret_bindings "
                    "(id, tenant_id, space_id, project_id, execution_profile_id, "
                    "created_by, name, vault_provider, vault_ref, version_ref, "
                    "credential_scheme, host, inject_env, metadata_hash, status, version) "
                    "VALUES (:id, :tenant, :space, :project, :profile, :actor, "
                    "'runner-late-secret', 'test-vault', :vault_ref, 'v1', 'bearer', "
                    "'api.example.test', CAST('[\"RUNNER_LATE_TOKEN\"]' AS jsonb), "
                    ":metadata_hash, 'active', 1)"
                ),
                {
                    "id": late_secret_binding_id,
                    "tenant": tenant_id,
                    "space": space_id,
                    "project": project_id,
                    "profile": execution_profile_id,
                    "actor": actor_id,
                    "vault_ref": f"runner/{late_secret_binding_id}",
                    "metadata_hash": _digest(f"binding:{late_secret_binding_id}"),
                },
            )
        with pytest.raises(IsolationControlPlaneError) as added_binding_replay:
            isolation_control.redeem_launch_grant(
                token=issued_grant.token,
                runner_id=runner_id,
                run_id=run_id,
                now=now + timedelta(seconds=31),
            )
        assert added_binding_replay.value.code == "runner_isolation_binding_drift"
        with owner_engine.begin() as connection:
            assert (
                connection.execute(
                    sa.text(
                        "SELECT status, redeemed_at, xmin::text "
                        "FROM saas_run_isolation_grants WHERE id = :grant"
                    ),
                    {"grant": issued_grant.grant_id},
                ).one()
                == frozen_grant
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_secret_access_leases "
                        "WHERE isolation_grant_id = :grant"
                    ),
                    {"grant": issued_grant.grant_id},
                )
                == frozen_lease_count
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE idempotency_key = :key"
                    ),
                    {"key": f"run-isolation:{issued_grant.grant_id}:redeemed"},
                )
                == frozen_outbox_count
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_secret_access_leases "
                        "WHERE secret_binding_id = :binding"
                    ),
                    {"binding": late_secret_binding_id},
                )
                == 0
            )
            connection.execute(
                sa.text("DELETE FROM saas_secret_bindings WHERE id = :binding"),
                {"binding": late_secret_binding_id},
            )

        # Secret delivery revalidates authority after waiting on the lease it
        # will mutate.  A central capability revocation must stay
        # non-blocking and prevent both the DB transition and provider access.
        secret_application_name = f"runner-secret-fresh-authority-{suffix}"
        secret_engine = sa.create_engine(
            executor_url,
            connect_args={"application_name": secret_application_name},
            pool_pre_ping=True,
            pool_size=1,
            max_overflow=0,
        )
        secret_sessions = sessionmaker(
            secret_engine,
            expire_on_commit=False,
            class_=Session,
        )
        blocked_isolation = IsolationControlPlane(secret_sessions)
        blocked_secret_provider = _SecretProvider()
        secret_token = launch.secret_leases[0].token
        try:
            with owner_engine.connect() as held_connection:
                held_transaction = held_connection.begin()
                secret_lease_before_wait = held_connection.execute(
                    sa.text(
                        "SELECT id, status, redeemed_at, xmin::text "
                        "FROM saas_secret_access_leases "
                        "WHERE token_hash = :token_hash FOR UPDATE"
                    ),
                    {"token_hash": _digest(secret_token)},
                ).one()
                pool = ThreadPoolExecutor(max_workers=1)
                try:
                    waiting_secret = pool.submit(
                        blocked_isolation.redeem_secret,
                        token=secret_token,
                        runner_id=runner_id,
                        run_id=run_id,
                        provider=blocked_secret_provider,
                        now=now,
                    )
                    try:
                        _wait_for_database_lock(
                            owner_engine,
                            application_name=secret_application_name,
                        )
                        secret_kill_switch_started = time.monotonic()
                        with owner_engine.begin() as central_connection:
                            central_connection.exec_driver_sql("SET LOCAL lock_timeout = '400ms'")
                            central_connection.execute(
                                sa.text(
                                    "UPDATE saas_capability_tokens SET "
                                    "revoked_at = clock_timestamp(), "
                                    "revocation_reason = 'secret-fresh-authority-test' "
                                    "WHERE id = :id"
                                ),
                                {"id": capability_id},
                            )
                            for table_name, row_id in (
                                ("saas_execution_profiles", execution_profile_id),
                                ("saas_egress_policies", egress_policy_id),
                                ("saas_secret_bindings", secret_binding_id),
                            ):
                                central_connection.execute(
                                    sa.text(
                                        f"UPDATE {table_name} SET status = status WHERE id = :id"
                                    ),
                                    {"id": row_id},
                                )
                        secret_kill_switch_elapsed = time.monotonic() - secret_kill_switch_started
                        assert not waiting_secret.done()
                    finally:
                        if held_transaction.is_active:
                            held_transaction.rollback()
                    with pytest.raises(IsolationControlPlaneError) as stale_secret:
                        waiting_secret.result(timeout=5)
                    assert secret_kill_switch_elapsed < 0.5
                    assert stale_secret.value.code == "runner_isolation_capability_stale"
                finally:
                    pool.shutdown(wait=True, cancel_futures=True)
        finally:
            secret_engine.dispose()

        with owner_engine.begin() as connection:
            secret_lease_after_wait = connection.execute(
                sa.text(
                    "SELECT id, status, redeemed_at, xmin::text "
                    "FROM saas_secret_access_leases "
                    "WHERE token_hash = :token_hash"
                ),
                {"token_hash": _digest(secret_token)},
            ).one()
            assert secret_lease_after_wait == secret_lease_before_wait
            assert blocked_secret_provider.calls == 0
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE idempotency_key = :key"
                    ),
                    {"key": f"secret-access:{secret_lease_before_wait.id}:redeemed"},
                )
                == 0
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_capability_tokens SET revoked_at = NULL, "
                    "revocation_reason = NULL WHERE id = :id"
                ),
                {"id": capability_id},
            )

        secret_provider = _SecretProvider()
        secret_material = isolation_control.redeem_secret(
            token=secret_token,
            runner_id=runner_id,
            run_id=run_id,
            provider=secret_provider,
            now=now,
        )
        assert secret_material.binding_id == secret_binding_id
        assert secret_material.value == "test-secret-material"
        assert secret_provider.calls == 1
        with pytest.raises(IsolationControlPlaneError) as duplicate_secret_claim:
            isolation_control.redeem_secret(
                token=secret_token,
                runner_id=runner_id,
                run_id=run_id,
                provider=secret_provider,
                now=now + timedelta(seconds=1),
            )
        assert duplicate_secret_claim.value.code == "secret_lease_stale"
        assert secret_provider.calls == 1
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_secret_bindings SET status = 'disabled' WHERE id = :binding"),
                {"binding": secret_binding_id},
            )
        with pytest.raises(IsolationControlPlaneError) as removed_binding_replay:
            isolation_control.redeem_launch_grant(
                token=issued_grant.token,
                runner_id=runner_id,
                run_id=run_id,
                now=now + timedelta(seconds=32),
            )
        assert removed_binding_replay.value.code == "runner_isolation_binding_drift"
        with owner_engine.begin() as connection:
            assert (
                connection.execute(
                    sa.text(
                        "SELECT status, redeemed_at, xmin::text "
                        "FROM saas_run_isolation_grants WHERE id = :grant"
                    ),
                    {"grant": issued_grant.grant_id},
                ).one()
                == frozen_grant
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_secret_access_leases "
                        "WHERE isolation_grant_id = :grant"
                    ),
                    {"grant": issued_grant.grant_id},
                )
                == frozen_lease_count
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE idempotency_key = :key"
                    ),
                    {"key": f"run-isolation:{issued_grant.grant_id}:redeemed"},
                )
                == frozen_outbox_count
            )
            assert connection.scalars(
                sa.text(
                    "SELECT event_type FROM saas_worktree_events "
                    "WHERE worktree_id = :worktree ORDER BY sequence"
                ),
                {"worktree": worktree_lease.worktree_id},
            ).all() == ["worktree.rebuilt", "worktree.materializing"]
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox WHERE "
                        "aggregate_key IN (:worktree, :grant)"
                    ),
                    {
                        "worktree": str(worktree_lease.worktree_id),
                        "grant": str(issued_grant.grant_id),
                    },
                )
                == 4
            )
            assert connection.execute(
                sa.text(
                    "SELECT event_type, count(*) FROM saas_control_plane_outbox "
                    "WHERE event_type IN ('run.isolation_grant.issued', "
                    "'run.isolation_grant.redeemed', 'secret.access.redeemed') "
                    "GROUP BY event_type ORDER BY event_type"
                )
            ).all() == [
                ("run.isolation_grant.issued", 1),
                ("run.isolation_grant.redeemed", 1),
                ("secret.access.redeemed", 1),
            ]

        # Preview command claim has the same post-lock authority boundary.  A
        # queued child Run is deliberately independent from the writer Run so
        # the test also proves possession of the exact preview capability.
        preview_group_id = uuid4()
        preview_change_set_id = uuid4()
        preview_child_run_id = uuid4()
        preview_capability_id = uuid4()
        preview_capability_token = f"cap_preview_{uuid4().hex}"
        preview_execution_id = uuid4()
        preview_command_id = uuid4()
        preview_fence_token = 13
        checkpoint_revision = "a" * 40
        preview_input = {
            "change_set_id": str(preview_change_set_id),
            "execution": {
                "checkpoint_revision": checkpoint_revision,
                "kind": "omnigent.preview.v1",
                "preview_execution_id": str(preview_execution_id),
                "profile": "static_web_v1",
            },
        }
        preview_command_hash = _worktree_hash(
            {
                "command_type": "start",
                "generation": 1,
                "preview_execution_id": str(preview_execution_id),
            }
        )
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO saas_changeset_groups "
                    "(id, tenant_id, space_id, project_id, created_by, title, status, version) "
                    "VALUES (:id, :tenant, :space, :project, :actor, "
                    "'Preview immutable source', 'completed', 1)"
                ),
                {
                    "id": preview_group_id,
                    "tenant": tenant_id,
                    "space": space_id,
                    "project": project_id,
                    "actor": actor_id,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_changesets "
                    "(id, tenant_id, space_id, project_id, group_id, repository_id, "
                    "created_by, base_revision, head_revision, branch_ref, "
                    "recovery_artifact_ref, status, version) VALUES "
                    "(:id, :tenant, :space, :project, :group_id, :repository, :actor, "
                    ":base, :head, :branch, :recovery, 'committed', 1)"
                ),
                {
                    "id": preview_change_set_id,
                    "tenant": tenant_id,
                    "space": space_id,
                    "project": project_id,
                    "group_id": preview_group_id,
                    "repository": repository_id,
                    "actor": actor_id,
                    "base": "1" * 40,
                    "head": checkpoint_revision,
                    "branch": f"refs/heads/codex/preview-{suffix}",
                    "recovery": f"artifact://preview/{preview_change_set_id}",
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runs "
                    "(id, tenant_id, space_id, project_id, task_id, parent_run_id, "
                    "created_by, status, version, event_sequence, queue_class, priority, "
                    "idempotency_key, request_hash, input, product_revision, "
                    "upstream_revision, schema_revision, adapter_contract_version, "
                    "lease_owner, lease_token, lease_expires_at, heartbeat_at, fence_token) "
                    "SELECT :child_run, tenant_id, space_id, project_id, task_id, id, "
                    "created_by, 'running', 1, 0, 'preview', 0, :idempotency_key, "
                    ":request_hash, CAST(:input AS jsonb), product_revision, "
                    "upstream_revision, schema_revision, adapter_contract_version, "
                    ":runner, :lease_token, :expires, :now, :fence "
                    "FROM saas_runs WHERE id = :source_run"
                ),
                {
                    "child_run": preview_child_run_id,
                    "idempotency_key": f"preview-child-{preview_execution_id}",
                    "request_hash": _worktree_hash(preview_input),
                    "input": json.dumps(preview_input),
                    "runner": str(runner_id),
                    "lease_token": uuid4(),
                    "expires": now + timedelta(minutes=5),
                    "now": now,
                    "fence": preview_fence_token,
                    "source_run": run_id,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_run_dispatches "
                    "(run_id, tenant_id, space_id, project_id, pool_id, "
                    "execution_profile_id, execution_profile_hash, egress_policy_id, "
                    "egress_policy_hash, queue_class, required_capabilities, "
                    "requirements_hash, cost_units, eligible_at, max_wait_at, status, "
                    "selected_runner_id, selected_failure_domain, dispatch_generation) "
                    "SELECT :child_run, tenant_id, space_id, project_id, pool_id, "
                    "execution_profile_id, execution_profile_hash, egress_policy_id, "
                    "egress_policy_hash, 'preview', required_capabilities, "
                    ":requirements_hash, cost_units, :now, :expires, 'leased', "
                    "selected_runner_id, selected_failure_domain, 2 "
                    "FROM saas_run_dispatches WHERE run_id = :source_run"
                ),
                {
                    "child_run": preview_child_run_id,
                    "requirements_hash": "4" * 64,
                    "now": now,
                    "expires": now + timedelta(minutes=5),
                    "source_run": run_id,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_capability_tokens "
                    "(id, token_hash, tenant_id, space_id, project_id, run_id, "
                    "runner_id, runner_connection_generation, dispatch_generation, "
                    "fence_token, allowed_actions, resource_scope, issued_at, expires_at) "
                    "VALUES (:id, :token_hash, :tenant, :space, :project, :run, :runner, "
                    "3, 2, :fence, CAST(:actions AS jsonb), CAST(:scope AS jsonb), "
                    ":now, :expires)"
                ),
                {
                    "id": preview_capability_id,
                    "token_hash": _digest(preview_capability_token),
                    "tenant": tenant_id,
                    "space": space_id,
                    "project": project_id,
                    "run": preview_child_run_id,
                    "runner": runner_id,
                    "fence": preview_fence_token,
                    "actions": json.dumps(["run.execute", "preview.serve", "worktree.read"]),
                    "scope": json.dumps({"change_set_id": str(preview_change_set_id)}),
                    "now": now,
                    "expires": now + timedelta(minutes=5),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_preview_executions "
                    "(id, tenant_id, space_id, project_id, source_run_id, child_run_id, "
                    "change_set_id, created_by, profile, idempotency_key_hash, request_hash, "
                    "opaque_preview_key, preview_host, status, command_generation, "
                    "expires_at, version) VALUES "
                    "(:id, :tenant, :space, :project, :source_run, :child_run, "
                    ":change_set, :actor, 'static_web_v1', :idempotency_hash, "
                    ":request_hash, :opaque_key, :preview_host, 'queued', 1, :expires, 1)"
                ),
                {
                    "id": preview_execution_id,
                    "tenant": tenant_id,
                    "space": space_id,
                    "project": project_id,
                    "source_run": run_id,
                    "child_run": preview_child_run_id,
                    "change_set": preview_change_set_id,
                    "actor": actor_id,
                    "idempotency_hash": "5" * 64,
                    "request_hash": "6" * 64,
                    "opaque_key": f"pvr_{uuid4().hex}{uuid4().hex[:16]}",
                    "preview_host": f"{uuid4().hex}.preview.example.test",
                    "expires": now + timedelta(minutes=5),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_preview_commands "
                    "(id, tenant_id, space_id, project_id, preview_execution_id, "
                    "command_type, generation, request_hash, status, attempt_count, "
                    "available_at) VALUES "
                    "(:id, :tenant, :space, :project, :execution, 'start', 1, "
                    ":request_hash, 'pending', 0, :now)"
                ),
                {
                    "id": preview_command_id,
                    "tenant": tenant_id,
                    "space": space_id,
                    "project": project_id,
                    "execution": preview_execution_id,
                    "request_hash": preview_command_hash,
                    "now": now,
                },
            )

        preview_application_name = f"runner-preview-fresh-authority-{suffix}"
        preview_engine = sa.create_engine(
            executor_url,
            connect_args={"application_name": preview_application_name},
            pool_pre_ping=True,
            pool_size=1,
            max_overflow=0,
        )
        preview_sessions = sessionmaker(
            preview_engine,
            expire_on_commit=False,
            class_=Session,
        )
        blocked_preview = PreviewRunnerExecutionAuthority(preview_sessions)
        try:
            with owner_engine.connect() as held_connection:
                held_transaction = held_connection.begin()
                preview_execution_before_wait = held_connection.execute(
                    sa.text(
                        "SELECT status, runner_id, runner_connection_generation, "
                        "run_fence_token, version, xmin::text "
                        "FROM saas_preview_executions WHERE id = :id FOR UPDATE"
                    ),
                    {"id": preview_execution_id},
                ).one()
                preview_command_before_wait = held_connection.execute(
                    sa.text(
                        "SELECT status, runner_id, runner_connection_generation, "
                        "run_fence_token, claim_token_hash, attempt_count, xmin::text "
                        "FROM saas_preview_commands WHERE id = :id"
                    ),
                    {"id": preview_command_id},
                ).one()
                pool = ThreadPoolExecutor(max_workers=1)
                try:
                    waiting_preview = pool.submit(
                        blocked_preview.claim_start,
                        tenant_id=tenant_id,
                        space_id=space_id,
                        project_id=project_id,
                        child_run_id=preview_child_run_id,
                        runner_id=runner_id,
                        connection_generation=3,
                        run_fence_token=preview_fence_token,
                        capability_token=preview_capability_token,
                        preview_execution_id=preview_execution_id,
                        now=now,
                    )
                    try:
                        _wait_for_database_lock(
                            owner_engine,
                            application_name=preview_application_name,
                        )
                        preview_kill_switch_started = time.monotonic()
                        with owner_engine.begin() as central_connection:
                            central_connection.exec_driver_sql("SET LOCAL lock_timeout = '400ms'")
                            central_connection.execute(
                                sa.text(
                                    "UPDATE saas_capability_tokens SET "
                                    "revoked_at = clock_timestamp(), "
                                    "revocation_reason = 'preview-fresh-authority-test' "
                                    "WHERE id = :id"
                                ),
                                {"id": preview_capability_id},
                            )
                            central_connection.execute(
                                sa.text(
                                    "UPDATE saas_runner_registrations "
                                    "SET status = 'offline' WHERE id = :id"
                                ),
                                {"id": runner_id},
                            )
                            central_connection.execute(
                                sa.text(
                                    "UPDATE saas_execution_profiles SET status = status "
                                    "WHERE id = :id"
                                ),
                                {"id": execution_profile_id},
                            )
                        preview_kill_switch_elapsed = (
                            time.monotonic() - preview_kill_switch_started
                        )
                        assert not waiting_preview.done()
                    finally:
                        if held_transaction.is_active:
                            held_transaction.rollback()
                    with pytest.raises(PreviewExecutionControlPlaneError) as stale_preview:
                        waiting_preview.result(timeout=5)
                    assert preview_kill_switch_elapsed < 0.5
                    assert stale_preview.value.code == "preview_execution_stale"
                finally:
                    pool.shutdown(wait=True, cancel_futures=True)
        finally:
            preview_engine.dispose()

        with owner_engine.begin() as connection:
            assert (
                connection.execute(
                    sa.text(
                        "SELECT status, runner_id, runner_connection_generation, "
                        "run_fence_token, version, xmin::text "
                        "FROM saas_preview_executions WHERE id = :id"
                    ),
                    {"id": preview_execution_id},
                ).one()
                == preview_execution_before_wait
            )
            assert (
                connection.execute(
                    sa.text(
                        "SELECT status, runner_id, runner_connection_generation, "
                        "run_fence_token, claim_token_hash, attempt_count, xmin::text "
                        "FROM saas_preview_commands WHERE id = :id"
                    ),
                    {"id": preview_command_id},
                ).one()
                == preview_command_before_wait
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_capability_tokens SET revoked_at = NULL, "
                    "revocation_reason = NULL WHERE id = :id"
                ),
                {"id": preview_capability_id},
            )
            connection.execute(
                sa.text("UPDATE saas_runner_registrations SET status = 'online' WHERE id = :id"),
                {"id": runner_id},
            )

        preview_authority = PreviewRunnerExecutionAuthority(sessions)
        with pytest.raises(PreviewExecutionControlPlaneError) as wrong_preview_capability:
            preview_authority.claim_start(
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                child_run_id=preview_child_run_id,
                runner_id=runner_id,
                connection_generation=3,
                run_fence_token=preview_fence_token,
                capability_token=capability_token,
                preview_execution_id=preview_execution_id,
                now=now,
            )
        assert wrong_preview_capability.value.code == "preview_execution_stale"
        preview_claim = preview_authority.claim_start(
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            child_run_id=preview_child_run_id,
            runner_id=runner_id,
            connection_generation=3,
            run_fence_token=preview_fence_token,
            capability_token=preview_capability_token,
            preview_execution_id=preview_execution_id,
            now=now,
        )
        preview_claim_replay = preview_authority.claim_start(
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            child_run_id=preview_child_run_id,
            runner_id=runner_id,
            connection_generation=3,
            run_fence_token=preview_fence_token,
            capability_token=preview_capability_token,
            preview_execution_id=preview_execution_id,
            now=now + timedelta(seconds=1),
        )
        assert preview_claim_replay.command_id == preview_claim.command_id
        assert preview_claim_replay.claim_token == preview_claim.claim_token

        preview_authority.mark_starting(
            preview_claim,
            runner_id=runner_id,
            connection_generation=3,
            run_fence_token=preview_fence_token,
        )
        preview_worktree = worktree_control.allocate_worktree(
            capability_token=preview_capability_token,
            runner_id=runner_id,
            run_id=preview_child_run_id,
            change_set_id=preview_change_set_id,
            access_mode="readonly",
            reserved_bytes=512,
            lease_duration=timedelta(seconds=60),
            trace_id="runner-preview-postgresql",
        )
        worktree_control.begin_materialization(
            worktree_id=preview_worktree.worktree_id,
            runner_id=runner_id,
            lease_generation=preview_worktree.lease_generation,
            run_fence_token=preview_worktree.run_fence_token,
            lease_token=preview_worktree.lease_token,
            trace_id="runner-preview-postgresql",
        )
        worktree_control.acknowledge_ready(
            worktree_id=preview_worktree.worktree_id,
            runner_id=runner_id,
            lease_generation=preview_worktree.lease_generation,
            run_fence_token=preview_worktree.run_fence_token,
            lease_token=preview_worktree.lease_token,
            actual_bytes=256,
            trace_id="runner-preview-postgresql",
        )

        # Route preparation and ready publication lock the exact Preview and
        # Worktree rows, then re-read authority using clock_timestamp(). A
        # concurrent release, or a deadline crossed while waiting, must not
        # publish stale routing state.
        route_application_name = f"runner-preview-route-fence-{suffix}"
        route_engine = sa.create_engine(
            executor_url,
            connect_args={"application_name": route_application_name},
            pool_pre_ping=True,
            pool_size=1,
            max_overflow=0,
        )
        route_authority = PreviewRunnerExecutionAuthority(
            sessionmaker(route_engine, expire_on_commit=False, class_=Session)
        )
        try:
            with owner_engine.connect() as held_connection:
                held_transaction = held_connection.begin()
                held_connection.execute(
                    sa.text("SELECT id FROM saas_worktree_instances WHERE id = :id FOR UPDATE"),
                    {"id": preview_worktree.worktree_id},
                ).one()
                before_route = held_connection.execute(
                    sa.text(
                        "SELECT execution.status, execution.version, execution.ready_at, "
                        "command.status, command.completed_at "
                        "FROM saas_preview_executions execution "
                        "JOIN saas_preview_commands command "
                        "ON command.preview_execution_id = execution.id "
                        "WHERE execution.id = :id AND command.id = :command"
                    ),
                    {"id": preview_execution_id, "command": preview_command_id},
                ).one()
                pool = ThreadPoolExecutor(max_workers=1)
                try:
                    waiting_route = pool.submit(
                        route_authority.prepare_route,
                        preview_claim,
                        runner_id=runner_id,
                        connection_generation=3,
                        run_fence_token=preview_fence_token,
                        worktree_id=preview_worktree.worktree_id,
                        worktree_lease_generation=preview_worktree.lease_generation,
                    )
                    _wait_for_database_lock(
                        owner_engine,
                        application_name=route_application_name,
                    )
                    held_connection.execute(
                        sa.text(
                            "UPDATE saas_worktree_instances SET status = 'released', "
                            "released_at = clock_timestamp() WHERE id = :id"
                        ),
                        {"id": preview_worktree.worktree_id},
                    )
                    held_transaction.commit()
                    with pytest.raises(PreviewExecutionControlPlaneError) as released_route:
                        waiting_route.result(timeout=5)
                    assert released_route.value.code == "preview_execution_stale"
                finally:
                    if held_transaction.is_active:
                        held_transaction.rollback()
                    pool.shutdown(wait=True, cancel_futures=True)
            with owner_engine.begin() as connection:
                assert (
                    connection.execute(
                        sa.text(
                            "SELECT execution.status, execution.version, execution.ready_at, "
                            "command.status, command.completed_at "
                            "FROM saas_preview_executions execution "
                            "JOIN saas_preview_commands command "
                            "ON command.preview_execution_id = execution.id "
                            "WHERE execution.id = :id AND command.id = :command"
                        ),
                        {"id": preview_execution_id, "command": preview_command_id},
                    ).one()
                    == before_route
                )
                connection.execute(
                    sa.text(
                        "UPDATE saas_worktree_instances SET status = 'ready', "
                        "released_at = NULL WHERE id = :id"
                    ),
                    {"id": preview_worktree.worktree_id},
                )
                connection.execute(
                    sa.text(
                        "UPDATE saas_preview_executions SET "
                        "expires_at = clock_timestamp() + interval '750 milliseconds' "
                        "WHERE id = :id"
                    ),
                    {"id": preview_execution_id},
                )

            with owner_engine.connect() as held_connection:
                held_transaction = held_connection.begin()
                before_expiry = held_connection.execute(
                    sa.text(
                        "SELECT execution.status, execution.version, execution.ready_at, "
                        "command.status, command.completed_at "
                        "FROM saas_preview_executions execution "
                        "JOIN saas_preview_commands command "
                        "ON command.preview_execution_id = execution.id "
                        "WHERE execution.id = :id AND command.id = :command "
                        "FOR UPDATE OF execution"
                    ),
                    {"id": preview_execution_id, "command": preview_command_id},
                ).one()
                pool = ThreadPoolExecutor(max_workers=1)
                try:
                    waiting_ready = pool.submit(
                        route_authority.mark_ready,
                        preview_claim,
                        runner_id=runner_id,
                        connection_generation=3,
                        run_fence_token=preview_fence_token,
                        worktree_id=preview_worktree.worktree_id,
                        worktree_lease_generation=preview_worktree.lease_generation,
                    )
                    _wait_for_database_lock(
                        owner_engine,
                        application_name=route_application_name,
                    )
                    time.sleep(1.0)
                    held_transaction.rollback()
                    with pytest.raises(PreviewExecutionControlPlaneError) as expired_ready:
                        waiting_ready.result(timeout=5)
                    assert expired_ready.value.code == "preview_execution_stale"
                finally:
                    if held_transaction.is_active:
                        held_transaction.rollback()
                    pool.shutdown(wait=True, cancel_futures=True)
            with owner_engine.begin() as connection:
                assert (
                    connection.execute(
                        sa.text(
                            "SELECT execution.status, execution.version, execution.ready_at, "
                            "command.status, command.completed_at "
                            "FROM saas_preview_executions execution "
                            "JOIN saas_preview_commands command "
                            "ON command.preview_execution_id = execution.id "
                            "WHERE execution.id = :id AND command.id = :command"
                        ),
                        {"id": preview_execution_id, "command": preview_command_id},
                    ).one()
                    == before_expiry
                )
        finally:
            route_engine.dispose()

        _assert_database_denied(
            login_engine,
            sa.text("UPDATE saas_runs SET id = id WHERE id = :run_id"),
            {"run_id": run_id},
        )
        for fleet_table in (
            "saas_runner_pools",
            "saas_runner_certificates",
            "saas_runner_tunnel_placements",
            "saas_preview_gateway_instances",
            "saas_preview_gateway_certificates",
        ):
            _assert_database_denied(login_engine, f"SELECT 1 FROM public.{fleet_table} LIMIT 1")
        _assert_database_denied(login_engine, "SET ROLE saas_executor")

        wrong_scope = RunnerExecutionEnvelope(
            change_set_id=envelope.change_set_id,
            tenant_id=envelope.tenant_id,
            space_id=envelope.space_id,
            project_id=uuid4(),
            run_id=envelope.run_id,
            runner_id=envelope.runner_id,
            fence_token=envelope.fence_token,
            execution_profile_id=envelope.execution_profile_id,
            execution_profile_hash=envelope.execution_profile_hash,
            egress_policy_id=envelope.egress_policy_id,
            egress_policy_hash=envelope.egress_policy_hash,
            product_revision=envelope.product_revision,
            image_digest=envelope.image_digest,
            execution_spec_hash=envelope.execution_spec_hash,
            launch_argv=envelope.launch_argv,
        )
        wrong_lease = RunnerControlClientLease(
            run_id=lease.run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            dispatch_generation=lease.dispatch_generation,
            failure_domain=lease.failure_domain,
            expires_at=lease.expires_at,
            capability_id=lease.capability_id,
            capability_token=lease.capability_token,
            execution_envelope=wrong_scope,
        )
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(wrong_lease)

        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(replace(lease, lease_token=uuid4()))
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(replace(lease, dispatch_generation=2))
        with pytest.raises(RunnerControlError, match="Execution envelope is misbound"):
            executor._load_run(
                replace(lease, execution_envelope=replace(envelope, runner_id=uuid4()))
            )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_runs SET lease_owner = :other_runner WHERE id = :run_id"),
                {"other_runner": str(other_runner_id), "run_id": run_id},
            )
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(lease)
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_runs SET lease_owner = :runner WHERE id = :run_id"),
                {"runner": str(runner_id), "run_id": run_id},
            )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_run_dispatches SET status = 'released', "
                    "released_at = :now WHERE run_id = :run_id"
                ),
                {"now": now, "run_id": run_id},
            )
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(lease)
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_run_dispatches SET status = 'leased', released_at = NULL "
                    "WHERE run_id = :run_id"
                ),
                {"run_id": run_id},
            )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_run_dispatches SET selected_runner_id = :other_runner "
                    "WHERE run_id = :run_id"
                ),
                {"other_runner": other_runner_id, "run_id": run_id},
            )
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(lease)
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_run_dispatches SET selected_runner_id = :runner "
                    "WHERE run_id = :run_id"
                ),
                {"runner": runner_id, "run_id": run_id},
            )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_run_dispatches SET selected_failure_domain = 'cn-east-1b' "
                    "WHERE run_id = :run_id"
                ),
                {"run_id": run_id},
            )
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(lease)
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_run_dispatches SET selected_failure_domain = 'cn-east-1a' "
                    "WHERE run_id = :run_id"
                ),
                {"run_id": run_id},
            )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_runs SET status = 'cancelling' WHERE id = :run_id"),
                {"run_id": run_id},
            )
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(lease)
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_runs SET status = 'running' WHERE id = :run_id"),
                {"run_id": run_id},
            )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_runs SET lease_expires_at = :expired WHERE id = :run_id"),
                {"expired": now - timedelta(seconds=1), "run_id": run_id},
            )
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(lease)
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_runs SET lease_expires_at = :active WHERE id = :run_id"),
                {"active": now + timedelta(minutes=5), "run_id": run_id},
            )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_run_dispatches SET requirements_hash = :invalid "
                    "WHERE run_id = :run_id"
                ),
                {"invalid": "f" * 64, "run_id": run_id},
            )
        with pytest.raises(RunnerControlError, match="Run changed after claim"):
            executor._load_run(lease)
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_run_dispatches SET requirements_hash = :valid "
                    "WHERE run_id = :run_id"
                ),
                {"valid": requirements_hash, "run_id": run_id},
            )

        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_runner_registrations SET active_leases = 0 WHERE id = :runner_id"
                ),
                {"runner_id": runner_id},
            )

        # Every catalog surface is re-read before a claim. Direct core-catalog
        # grants, PUBLIC expansion, grant-option drift, RLS flag drift,
        # ownership, per-database role settings, and an extra schema all poison
        # the current process even after an operator repairs the database.
        assert_dynamic_authority_drift(
            apply_sql=(
                "GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO saas_runner_agent"
            ),
            restore_sql=(
                "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) FROM saas_runner_agent"
            ),
        )
        assert_dynamic_authority_drift(
            apply_sql=(
                f"GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO {quoted_login}"
            ),
            restore_sql=(
                f"REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) FROM {quoted_login}"
            ),
        )
        assert_dynamic_authority_drift(
            apply_sql=("GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO PUBLIC"),
            restore_sql=("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) FROM PUBLIC"),
        )
        drift_schema = f"runner_agent_drift_{suffix}"
        quoted_drift_schema = owner_engine.dialect.identifier_preparer.quote(drift_schema)
        assert_dynamic_authority_drift(
            apply_sql=(
                f"CREATE SCHEMA {quoted_drift_schema}; "
                f"GRANT USAGE ON SCHEMA {quoted_drift_schema} TO saas_runner_agent"
            ),
            restore_sql=f"DROP SCHEMA {quoted_drift_schema}",
        )
        assert_dynamic_authority_drift(
            apply_sql=(
                f"ALTER ROLE saas_runner_agent IN DATABASE {quoted_database} SET work_mem = '8MB'"
            ),
            restore_sql=(f"ALTER ROLE saas_runner_agent IN DATABASE {quoted_database} RESET ALL"),
        )
        assert_dynamic_authority_drift(
            apply_sql=(
                f"SET LOCAL ROLE {quoted_owner}; "
                "GRANT SELECT ON public.saas_runs TO saas_runner_agent "
                "WITH GRANT OPTION"
            ),
            restore_sql=(
                f"SET LOCAL ROLE {quoted_owner}; "
                "REVOKE GRANT OPTION FOR SELECT ON public.saas_runs "
                "FROM saas_runner_agent"
            ),
        )
        assert_dynamic_authority_drift(
            apply_sql="ALTER TABLE public.saas_runs DISABLE ROW LEVEL SECURITY",
            restore_sql=(
                "ALTER TABLE public.saas_runs ENABLE ROW LEVEL SECURITY; "
                "ALTER TABLE public.saas_runs FORCE ROW LEVEL SECURITY"
            ),
        )
        assert_dynamic_authority_drift(
            apply_sql="ALTER TABLE public.saas_runs NO FORCE ROW LEVEL SECURITY",
            restore_sql="ALTER TABLE public.saas_runs FORCE ROW LEVEL SECURITY",
        )
        assert_dynamic_authority_drift(
            apply_sql=f"ALTER TABLE public.saas_runs OWNER TO {quoted_admin_role}",
            restore_sql=f"ALTER TABLE public.saas_runs OWNER TO {quoted_owner}",
        )

        # A post-bootstrap SECURITY DEFINER function in pg_catalog has a normal
        # OID and implicit PUBLIC EXECUTE. It is never accepted as an initdb
        # baseline object, and removing it cannot unpoison this process.
        catalog_function = f"runner_catalog_drift_{suffix}"
        assert_dynamic_authority_drift(
            apply_sql=(
                f"CREATE FUNCTION pg_catalog.{catalog_function}() RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'"
            ),
            restore_sql=f"DROP FUNCTION pg_catalog.{catalog_function}()",
        )
        information_function = f"runner_information_drift_{suffix}"
        assert_dynamic_authority_drift(
            apply_sql=(
                f"CREATE FUNCTION information_schema.{information_function}() "
                "RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'"
            ),
            restore_sql=(f"DROP FUNCTION information_schema.{information_function}()"),
        )
        toast_function = f"runner_toast_drift_{suffix}"
        assert_dynamic_authority_drift(
            apply_sql=(
                f"CREATE FUNCTION pg_toast.{toast_function}() RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'; "
                "GRANT USAGE ON SCHEMA pg_toast TO PUBLIC"
            ),
            restore_sql=(
                "REVOKE USAGE ON SCHEMA pg_toast FROM PUBLIC; "
                f"DROP FUNCTION pg_toast.{toast_function}()"
            ),
        )
        direct_toast_function = f"runner_toast_direct_drift_{suffix}"
        assert_dynamic_authority_drift(
            apply_sql=(
                f"CREATE FUNCTION pg_toast.{direct_toast_function}() RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'; "
                f"REVOKE ALL ON FUNCTION pg_toast.{direct_toast_function}() FROM PUBLIC; "
                "GRANT USAGE ON SCHEMA pg_toast TO saas_runner_agent; "
                f"GRANT EXECUTE ON FUNCTION pg_toast.{direct_toast_function}() "
                "TO saas_runner_agent"
            ),
            restore_sql=(
                f"REVOKE EXECUTE ON FUNCTION pg_toast.{direct_toast_function}() "
                "FROM saas_runner_agent; "
                "REVOKE USAGE ON SCHEMA pg_toast FROM saas_runner_agent; "
                f"DROP FUNCTION pg_toast.{direct_toast_function}()"
            ),
        )

        # The two XID-allocating read-looking functions are unavailable to the
        # Runner LOGIN, preventing unmetered transaction-ID consumption.
        for xid_allocator in ("pg_current_xact_id()", "txid_current()"):
            _assert_database_denied(
                login_engine,
                f"SELECT pg_catalog.{xid_allocator}",
            )
        with login_engine.connect() as connection:
            for function_name, arguments in _RUNNER_AGENT_DENIED_PG_CATALOG_FUNCTIONS:
                signature = f"pg_catalog.{function_name}({arguments})"
                assert not connection.scalar(
                    sa.text(
                        "SELECT has_function_privilege("
                        "current_user, CAST(:signature AS regprocedure), 'EXECUTE')"
                    ),
                    {"signature": signature},
                )

        assert_postmaster_setting_drift(
            name="max_notify_queue_pages",
            rejected_value=65,
            restored_value=64,
        )
        assert_postmaster_setting_drift(
            name="max_prepared_transactions",
            rejected_value=1,
            restored_value=0,
        )

        # Every claim boundary revalidates the live role graph.  Once drift is
        # observed this process incarnation remains poisoned even after an
        # operator removes the bad grant; a replacement process is required.
        executor.assert_claimable()
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"GRANT saas_executor TO {quoted_login}")
        with pytest.raises(RunnerControlError) as membership_drift:
            executor.assert_claimable()
        assert membership_drift.value.code == "runner_database_authority_drifted"
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE saas_executor FROM {quoted_login}")
        with pytest.raises(RunnerControlError) as membership_poisoned:
            executor.assert_claimable()
        assert membership_poisoned.value.code == "runner_database_authority_poisoned"

        policy_executor = build_executor()
        policy_executor.assert_claimable()
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER POLICY rls_saas_runs_runner_select_fence ON public.saas_runs USING (true)"
            )
        with pytest.raises(RunnerControlError) as policy_drift:
            policy_executor.assert_claimable()
        assert policy_drift.value.code == "runner_database_authority_drifted"
        with pytest.raises(RunnerControlError) as policy_poisoned:
            policy_executor.assert_claimable()
        assert policy_poisoned.value.code == "runner_database_authority_poisoned"

    finally:
        if login_engine is not None:
            login_engine.dispose()
        with owner_engine.begin() as connection:
            quoted_login = connection.dialect.identifier_preparer.quote(login)
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_login}")
            if external_public_database_privileges:
                _restore_external_public_database_privileges(
                    connection,
                    external_public_database_privileges,
                )
            quoted_owner = connection.dialect.identifier_preparer.quote(schema_owner)
            connection.exec_driver_sql(f"REASSIGN OWNED BY {quoted_owner} TO CURRENT_USER")
            connection.exec_driver_sql(f"DROP OWNED BY {quoted_owner}")
            connection.exec_driver_sql(f"DROP ROLE {quoted_owner}")
        owner_engine.dispose()


def test_p0s10_runner_authority_downgrade_requires_complete_drain(
    isolated_postgres_url: str,
) -> None:
    """The first downgrade statement rejects every live Runner authority."""

    root = Path(__file__).resolve().parents[2]
    owner_engine = sa.create_engine(isolated_postgres_url)
    suffix = uuid4().hex[:12]
    schema_owner = f"saas_test_runner_down_{suffix}"
    runner_id = uuid4()
    login = _runner_agent_database_login(runner_id, 1)
    password = f"Runner-Drain-{uuid4().hex}"
    login_engine: sa.Engine | None = None
    login_connection: sa.Connection | None = None
    quoted_owner = owner_engine.dialect.identifier_preparer.quote(schema_owner)
    quoted_login = owner_engine.dialect.identifier_preparer.quote(login)
    quoted_database = owner_engine.dialect.identifier_preparer.quote(owner_engine.url.database)

    try:
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_owner} NOLOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1"
            )
            connection.exec_driver_sql(f"GRANT USAGE, CREATE ON SCHEMA public TO {quoted_owner}")
            connection.exec_driver_sql("CREATE EXTENSION pg_trgm WITH SCHEMA public")
            connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_owner}")
            _migrate(connection, root)
            connection.exec_driver_sql("RESET ROLE")
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted_database} TO saas_runner_agent"
            )
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_login} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 "
                f"PASSWORD '{password}'"
            )
            connection.exec_driver_sql(
                f"GRANT saas_runner_agent TO {quoted_login} "
                "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            )

        login_engine = sa.create_engine(owner_engine.url.set(username=login, password=password))
        login_connection = login_engine.connect()
        assert login_connection.scalar(sa.text("SELECT current_user")) == login

        def current_projection() -> tuple[object, ...]:
            with owner_engine.connect() as connection:
                return (
                    connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version")),
                    connection.scalar(
                        sa.text(
                            "SELECT count(*) FROM pg_proc procedure "
                            "JOIN pg_namespace namespace "
                            "ON namespace.oid = procedure.pronamespace "
                            "WHERE namespace.nspname = 'public' "
                            "AND procedure.proname = ANY(CAST(:names AS text[]))"
                        ),
                        {"names": list(_RUNNER_AGENT_CONTRACT_FUNCTION_NAMES)},
                    ),
                    connection.scalar(
                        sa.text(
                            "SELECT count(*) FROM pg_policy policy "
                            "WHERE policy.polname ~ '^rls_.*_runner_api_definer$'"
                        )
                    ),
                    connection.scalar(
                        sa.text(
                            "SELECT count(*) FROM pg_class relation "
                            "WHERE relation.relname IN ("
                            "'uq_worktree_runner_run_fence_v1', "
                            "'uq_runner_isolation_grant_capability_worktree_v1')"
                        )
                    ),
                )

        before = current_projection()
        assert before == ("p0s000000012", 18, 19, 2)
        with pytest.raises(sa.exc.DBAPIError, match="must be drained before downgrade"):
            with owner_engine.begin() as connection:
                connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_owner}")
                command.downgrade(
                    _saas_migration_config(connection),
                    "p0s000000009",
                )
        assert current_projection() == before

        login_connection.close()
        login_connection = None
        login_engine.dispose()
        login_engine = None
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE saas_runner_agent FROM {quoted_login}")
            connection.exec_driver_sql(f"DROP ROLE {quoted_login}")
            connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_owner}")
            command.downgrade(
                _saas_migration_config(connection),
                "p0s000000009",
            )
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )

        with owner_engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == "p0s000000009"
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM pg_proc procedure "
                        "JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace "
                        "WHERE namespace.nspname = 'public' "
                        "AND procedure.proname = ANY(CAST(:names AS text[]))"
                    ),
                    {"names": list(_RUNNER_AGENT_CONTRACT_FUNCTION_NAMES)},
                )
                == 0
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM pg_policy policy "
                        "WHERE policy.polname ~ '^rls_.*_runner_api_definer$'"
                    )
                )
                == 0
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM pg_class relation WHERE relation.relname IN ("
                        "'uq_worktree_runner_run_fence_v1', "
                        "'uq_runner_isolation_grant_capability_worktree_v1')"
                    )
                )
                == 0
            )

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_owner}")
            command.upgrade(_saas_migration_config(connection), "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
        # The roles projection re-verifies the exact policy/function digests,
        # owners, FORCE RLS flags, and sole Runner EXECUTE edges.  Reaching the
        # identical structural projection proves a clean current-head restoration.
        assert current_projection() == before
    finally:
        if login_connection is not None:
            login_connection.close()
        if login_engine is not None:
            login_engine.dispose()
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_login}")
            connection.exec_driver_sql(f"REASSIGN OWNED BY {quoted_owner} TO CURRENT_USER")
            connection.exec_driver_sql(f"DROP OWNED BY {quoted_owner}")
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_owner}")
        owner_engine.dispose()


def test_pg16_runner_direct_authority_is_fail_closed(
    isolated_postgres_url: str,
) -> None:
    """PG16 remains migration-compatible but can never admit a direct Runner."""

    root = Path(__file__).resolve().parents[2]
    owner_engine = sa.create_engine(isolated_postgres_url)
    with owner_engine.connect() as connection:
        server_major = int(connection.scalar(sa.text("SHOW server_version_num"))) // 10_000
    if server_major != 16:
        owner_engine.dispose()
        pytest.skip("direct Runner N-1 rejection is a PostgreSQL 16 contract")

    suffix = uuid4().hex[:12]
    schema_owner = f"saas_test_runner_n1_{suffix}"
    runner_id = uuid4()
    login = _runner_agent_database_login(runner_id, 1)
    password = f"Runner-N1-{uuid4().hex}"
    login_engine: sa.Engine | None = None
    quoted_owner = owner_engine.dialect.identifier_preparer.quote(schema_owner)
    quoted_login = owner_engine.dialect.identifier_preparer.quote(login)

    try:
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_owner} NOLOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1"
            )
            connection.exec_driver_sql(f"GRANT USAGE, CREATE ON SCHEMA public TO {quoted_owner}")
            connection.exec_driver_sql("CREATE EXTENSION pg_trgm WITH SCHEMA public")
            connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_owner}")
            _migrate(connection, root)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
            connection.exec_driver_sql("RESET ROLE")

        public_xid_authority = sa.text(
            "SELECT EXISTS (SELECT 1 FROM pg_proc procedure "
            "CROSS JOIN LATERAL aclexplode(COALESCE(procedure.proacl, "
            "acldefault('f', procedure.proowner))) acl "
            "WHERE procedure.oid = "
            "'pg_catalog.pg_current_xact_id()'::regprocedure "
            "AND acl.grantee = 0 AND acl.privilege_type = 'EXECUTE')"
        )
        with owner_engine.connect() as connection:
            assert connection.scalar(public_xid_authority)

        psql = shutil.which("psql")
        assert psql is not None
        wrapper_environment = {
            "PATH": os.environ.get("PATH", ""),
            "PGHOST": str(owner_engine.url.host),
            "PGPORT": str(owner_engine.url.port),
            "PGUSER": str(owner_engine.url.username),
            "PGDATABASE": str(owner_engine.url.database),
        }
        if owner_engine.url.password is not None:
            wrapper_environment["PGPASSWORD"] = owner_engine.url.password
        rejected_bootstrap = subprocess.run(
            [
                psql,
                "-X",
                "--no-password",
                "-f",
                str(root / "saas/control_plane/postgresql_runner_agent_cluster.psql"),
            ],
            env=wrapper_environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert rejected_bootstrap.returncode != 0
        assert "PostgreSQL 18 superuser required" in rejected_bootstrap.stderr
        with owner_engine.connect() as connection:
            assert connection.scalar(public_xid_authority)

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_login} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 "
                f"PASSWORD '{password}'"
            )
            connection.exec_driver_sql(
                f"GRANT saas_runner_agent TO {quoted_login} "
                "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            )

        login_engine = sa.create_engine(owner_engine.url.set(username=login, password=password))

        def mutation_projection() -> tuple[object, ...]:
            with owner_engine.connect() as connection:
                return (
                    connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version")),
                    connection.scalar(sa.text("SELECT count(*) FROM saas_runs")),
                    connection.scalar(sa.text("SELECT count(*) FROM saas_run_dispatches")),
                    connection.scalar(sa.text("SELECT count(*) FROM saas_capability_tokens")),
                    connection.scalar(sa.text("SELECT count(*) FROM saas_worktree_instances")),
                    connection.scalar(sa.text("SELECT count(*) FROM saas_control_plane_outbox")),
                )

        before = mutation_projection()
        assert before == ("p0s000000012", 0, 0, 0, 0, 0)
        with pytest.raises(RunnerControlError) as rejected:
            _verify_runner_agent_database_authority(
                login_engine,
                runner_id=runner_id,
                connection_generation=1,
            )
        assert rejected.value.code == "runner_executor_not_ready"
        assert mutation_projection() == before
    finally:
        if login_engine is not None:
            login_engine.dispose()
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_login}")
            connection.exec_driver_sql(f"REASSIGN OWNED BY {quoted_owner} TO CURRENT_USER")
            connection.exec_driver_sql(f"DROP OWNED BY {quoted_owner}")
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_owner}")
        owner_engine.dispose()
