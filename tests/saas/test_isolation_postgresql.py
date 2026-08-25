from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypedDict
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import RunnerTunnelPlacementAuthority
from tests.saas.test_worktree_postgresql import _seed_scope, _set_scope

_ISOLATION_RLS_TABLES = {
    "saas_egress_policies",
    "saas_execution_profiles",
    "saas_preview_leases",
    "saas_run_isolation_grants",
    "saas_secret_access_leases",
    "saas_secret_bindings",
    "saas_runner_certificates",
    "saas_runner_tunnel_placements",
}


class _IsolationScope(TypedDict):
    actor: UUID
    tenant: UUID
    space: UUID
    project: UUID
    task: UUID
    run: UUID
    repository: UUID
    group: UUID
    change_set: UUID
    quota: UUID
    runner: UUID
    capability: UUID
    worktree: UUID
    policy: UUID
    profile: UUID
    binding: UUID
    grant: UUID
    secret_lease: UUID
    preview: UUID
    tunnel_placement: UUID
    isolation_token_hash: str
    secret_token_hash: str
    preview_token_hash: str
    suffix: str


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for P4 isolation acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path, revision: str) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    if revision.startswith("-"):
        command.downgrade(config, revision[1:])
    else:
        command.upgrade(config, revision)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _set_token(connection: sa.Connection, setting: str, value: str | None) -> None:
    connection.execute(
        sa.text(f"SELECT set_config('{setting}', :value, true)"),
        {"value": value or ""},
    )


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


def _seed_isolation_scope(
    connection: sa.Connection,
    *,
    scope: _IsolationScope,
    pool_id: UUID,
    placement_id: UUID,
    now: datetime,
) -> None:
    suffix = str(scope["suffix"])
    runner_id = scope["runner"]
    capability_id = scope["capability"]
    worktree_id = scope["worktree"]
    policy_id = scope["policy"]
    profile_id = scope["profile"]
    binding_id = scope["binding"]
    grant_id = scope["grant"]
    secret_lease_id = scope["secret_lease"]
    preview_id = scope["preview"]
    tunnel_placement_id = scope["tunnel_placement"]
    connection.execute(
        sa.text(
            "UPDATE saas_runs SET status = 'leased', version = 2, lease_owner = :owner, "
            "lease_token = :lease_token, fence_token = 1, lease_expires_at = :expires, "
            "heartbeat_at = :now WHERE id = :run"
        ),
        {
            "owner": f"runner:{runner_id}",
            "lease_token": uuid4(),
            "expires": now + timedelta(minutes=30),
            "now": now,
            "run": scope["run"],
        },
    )
    capabilities = [
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
    connection.execute(
        sa.text(
            "INSERT INTO saas_runner_registrations "
            "(id, pool_id, placement_id, instance_key, failure_domain, status, "
            "connection_generation, connection_token_hash, protocol_version, source_revision, "
            "schema_revision, adapter_contract_version, capabilities, capabilities_hash, "
            "max_concurrency, active_leases, last_heartbeat_at, registered_at) VALUES "
            "(:id, :pool, :placement, :key, 'cn-east-1a', 'online', 1, :token_hash, 2, "
            "'upstream', 'runtime-schema-v1', '0.2.0', CAST(:capabilities AS json), "
            ":capabilities_hash, 1, 1, :now, :now)"
        ),
        {
            "id": runner_id,
            "pool": pool_id,
            "placement": placement_id,
            "key": f"p4-isolation-runner-{suffix}-{runner_id}",
            "token_hash": _digest(f"runner:{suffix}"),
            "capabilities": json.dumps(capabilities),
            "capabilities_hash": _digest(json.dumps(capabilities, separators=(",", ":"))),
            "now": now,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_capability_tokens "
            "(id, token_hash, tenant_id, space_id, project_id, run_id, runner_id, "
            "runner_connection_generation, dispatch_generation, fence_token, allowed_actions, "
            "resource_scope, issued_at, expires_at) VALUES "
            "(:id, :token_hash, :tenant, :space, :project, :run, :runner, 1, 1, 1, "
            "CAST(:actions AS json), CAST(:resource_scope AS json), :now, :expires)"
        ),
        {
            "id": capability_id,
            "token_hash": _digest(f"capability:{suffix}"),
            "tenant": scope["tenant"],
            "space": scope["space"],
            "project": scope["project"],
            "run": scope["run"],
            "runner": runner_id,
            "actions": json.dumps(["preview.serve", "sandbox.launch"]),
            "resource_scope": json.dumps({"worktree_id": str(worktree_id)}),
            "now": now,
            "expires": now + timedelta(minutes=20),
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_worktree_instances "
            "(id, tenant_id, space_id, project_id, change_set_id, run_id, runner_id, "
            "created_by, opaque_runtime_key, access_mode, status, lease_generation, "
            "run_fence_token, runner_connection_generation, lease_token_hash, "
            "lease_expires_at, heartbeat_at, maximum_lifetime_at, reserved_bytes, "
            "actual_bytes, dirty, event_sequence) VALUES "
            "(:id, :tenant, :space, :project, :change_set, :run, :runner, :actor, :key, "
            "'writer', 'ready', 1, 1, 1, :lease_hash, :lease_expires, :now, :maximum, "
            "1000000, 1024, false, 1)"
        ),
        {
            "id": worktree_id,
            "tenant": scope["tenant"],
            "space": scope["space"],
            "project": scope["project"],
            "change_set": scope["change_set"],
            "run": scope["run"],
            "runner": runner_id,
            "actor": scope["actor"],
            "key": f"wt-{suffix}-{worktree_id}",
            "lease_hash": _digest(f"worktree:{suffix}"),
            "lease_expires": now + timedelta(minutes=15),
            "now": now,
            "maximum": now + timedelta(hours=1),
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_egress_policies "
            "(id, tenant_id, space_id, project_id, created_by, name, rules, rules_hash, "
            "allow_private_destinations, status, version) VALUES "
            "(:id, :tenant, :space, :project, :actor, :name, CAST(:rules AS json), :hash, "
            "false, 'active', 1)"
        ),
        {
            "id": policy_id,
            "tenant": scope["tenant"],
            "space": scope["space"],
            "project": scope["project"],
            "actor": scope["actor"],
            "name": f"github-{suffix}",
            "rules": json.dumps([{"method": "GET", "host": "api.github.com", "path": "/**"}]),
            "hash": _digest(f"policy:{suffix}"),
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
            "(:id, :tenant, :space, :project, :policy, :actor, :name, 'linux_bwrap', "
            "'proxy_only', true, 65532, 65532, true, false, 'oci-default-v1', 1000, "
            "1073741824, 256, CAST(:allowed AS json), CAST(:approval AS json), "
            "CAST(:denied AS json), :hash, 'active', 1)"
        ),
        {
            "id": profile_id,
            "tenant": scope["tenant"],
            "space": scope["space"],
            "project": scope["project"],
            "policy": policy_id,
            "actor": scope["actor"],
            "name": f"managed-{suffix}",
            "allowed": json.dumps(["sys_os_read"]),
            "approval": json.dumps([]),
            "denied": json.dumps(["host.docker_socket"]),
            "hash": _digest(f"profile:{suffix}"),
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_secret_bindings "
            "(id, tenant_id, space_id, project_id, execution_profile_id, created_by, name, "
            "vault_provider, vault_ref, version_ref, credential_scheme, host, inject_env, "
            "metadata_hash, status, version) VALUES "
            "(:id, :tenant, :space, :project, :profile, :actor, :name, 'vault-prod', "
            ":vault_ref, 'v1', 'bearer', 'api.github.com', CAST(:inject_env AS json), "
            ":hash, 'active', 1)"
        ),
        {
            "id": binding_id,
            "tenant": scope["tenant"],
            "space": scope["space"],
            "project": scope["project"],
            "profile": profile_id,
            "actor": scope["actor"],
            "name": f"github-token-{suffix}",
            "vault_ref": f"projects/{suffix}/github",
            "inject_env": json.dumps(["GH_TOKEN"]),
            "hash": _digest(f"binding:{suffix}"),
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_run_isolation_grants "
            "(id, token_hash, tenant_id, space_id, project_id, run_id, runner_id, "
            "worktree_id, execution_profile_id, capability_id, run_fence_token, "
            "runner_connection_generation, worktree_lease_generation, grant_hash, status, "
            "expires_at) VALUES "
            "(:id, :token_hash, :tenant, :space, :project, :run, :runner, :worktree, "
            ":profile, :capability, 1, 1, 1, :grant_hash, 'active', :expires)"
        ),
        {
            "id": grant_id,
            "token_hash": str(scope["isolation_token_hash"]),
            "tenant": scope["tenant"],
            "space": scope["space"],
            "project": scope["project"],
            "run": scope["run"],
            "runner": runner_id,
            "worktree": worktree_id,
            "profile": profile_id,
            "capability": capability_id,
            "grant_hash": _digest(f"grant:{suffix}"),
            "expires": now + timedelta(minutes=10),
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_secret_access_leases "
            "(id, token_hash, tenant_id, space_id, project_id, isolation_grant_id, "
            "secret_binding_id, run_id, runner_id, run_fence_token, "
            "runner_connection_generation, status, expires_at) VALUES "
            "(:id, :token_hash, :tenant, :space, :project, :grant, :binding, :run, "
            ":runner, 1, 1, 'active', :expires)"
        ),
        {
            "id": secret_lease_id,
            "token_hash": str(scope["secret_token_hash"]),
            "tenant": scope["tenant"],
            "space": scope["space"],
            "project": scope["project"],
            "grant": grant_id,
            "binding": binding_id,
            "run": scope["run"],
            "runner": runner_id,
            "expires": now + timedelta(minutes=5),
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_preview_leases "
            "(id, token_hash, tenant_id, space_id, project_id, run_id, runner_id, "
            "worktree_id, created_by, opaque_preview_key, preview_host, run_fence_token, "
            "runner_connection_generation, worktree_lease_generation, response_policy_hash, "
            "status, expires_at) VALUES "
            "(:id, :token_hash, :tenant, :space, :project, :run, :runner, :worktree, "
            ":actor, :key, :host, 1, 1, 1, :response_hash, 'active', :expires)"
        ),
        {
            "id": preview_id,
            "token_hash": str(scope["preview_token_hash"]),
            "tenant": scope["tenant"],
            "space": scope["space"],
            "project": scope["project"],
            "run": scope["run"],
            "runner": runner_id,
            "worktree": worktree_id,
            "actor": scope["actor"],
            "key": f"preview-{suffix}-{preview_id}",
            "host": f"{preview_id.hex}.preview.example.test",
            "response_hash": _digest(f"preview-response:{suffix}"),
            "expires": now + timedelta(minutes=15),
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_preview_gateway_instances "
            "(id, connect_host, connect_port, server_name, failure_domain, source_revision, "
            "adapter_contract_version, registration_token_hash, status, registered_at, "
            "activated_at, last_heartbeat_at, lease_expires_at) VALUES "
            "(:gateway, '127.0.0.1', 8443, 'localhost', 'cn-east-1a', 'upstream', "
            "'0.2.0', :gateway_token_hash, 'active', :now, :now, :now, :expires)"
        ),
        {
            "gateway": f"gateway-{suffix}",
            "gateway_token_hash": _digest(f"preview-gateway:{suffix}"),
            "now": now,
            "expires": now + timedelta(minutes=10),
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_runner_tunnel_placements "
            "(id, runner_id, runner_connection_generation, routing_generation, "
            "gateway_instance_id, relay_subject, ownership_token_hash, status, claimed_at, "
            "last_heartbeat_at, lease_expires_at) VALUES "
            "(:id, :runner, 1, 1, :gateway, :relay, :token_hash, 'active', :now, :now, "
            ":expires)"
        ),
        {
            "id": tunnel_placement_id,
            "runner": runner_id,
            "gateway": f"gateway-{suffix}",
            "relay": f"rtp_{tunnel_placement_id.hex}",
            "token_hash": _digest(f"tunnel-placement:{suffix}"),
            "now": now,
            "expires": now + timedelta(minutes=10),
        },
    )


def _scope_record(suffix: str) -> _IsolationScope:
    return {
        "actor": uuid4(),
        "tenant": uuid4(),
        "space": uuid4(),
        "project": uuid4(),
        "task": uuid4(),
        "run": uuid4(),
        "repository": uuid4(),
        "group": uuid4(),
        "change_set": uuid4(),
        "quota": uuid4(),
        "runner": uuid4(),
        "capability": uuid4(),
        "worktree": uuid4(),
        "policy": uuid4(),
        "profile": uuid4(),
        "binding": uuid4(),
        "grant": uuid4(),
        "secret_lease": uuid4(),
        "preview": uuid4(),
        "tunnel_placement": uuid4(),
        "isolation_token_hash": _digest(f"isolation:{suffix}"),
        "secret_token_hash": _digest(f"secret:{suffix}"),
        "preview_token_hash": _digest(f"preview:{suffix}"),
        "suffix": suffix,
    }


def test_real_postgresql_isolation_token_rls_and_monotonic_leases() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=4, max_overflow=0)
    placement_id = uuid4()
    pool_id = uuid4()
    nonce = uuid4().hex[:10]
    scopes = (_scope_record(f"a{nonce}"), _scope_record(f"b{nonce}"))
    now = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=1)

    with engine.begin() as connection:
        _migrate(connection, root, "head")
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
                "db": f"db-isolation-{nonce}",
                "objects": f"objects-isolation-{nonce}",
                "kms": f"kms-isolation-{nonce}",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runner_pools "
                "(id, placement_id, failure_domain, name, queue_class, capacity_slots, "
                "reserved_slots, status, protocol_version, source_revision, schema_revision, "
                "adapter_contract_version) VALUES "
                "(:id, :placement, 'cn-east-1a', :name, 'interactive', 2, 0, 'active', 2, "
                "'upstream', 'runtime-schema-v1', '0.2.0')"
            ),
            {"id": pool_id, "placement": placement_id, "name": f"isolation-{nonce}"},
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
                repository_id=scope["repository"],
                group_id=scope["group"],
                change_set_id=scope["change_set"],
                quota_id=scope["quota"],
                suffix=str(scope["suffix"]),
            )
            _seed_isolation_scope(
                connection,
                scope=scope,
                pool_id=pool_id,
                placement_id=placement_id,
                now=now,
            )

    with engine.begin() as connection:
        forced = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
                    "AND relrowsecurity AND relforcerowsecurity AND relname = ANY(:tables)"
                ),
                {"tables": sorted(_ISOLATION_RLS_TABLES)},
            ).scalars()
        )
        assert forced == _ISOLATION_RLS_TABLES
        attributes = connection.execute(
            sa.text(
                "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles "
                "WHERE rolname IN ('saas_secret_broker', 'saas_preview_gateway') "
                "ORDER BY rolname"
            )
        ).all()
        assert attributes == [
            ("saas_preview_gateway", False, False, False),
            ("saas_secret_broker", False, False, False),
        ]
        memberships = connection.execute(
            sa.text(
                "SELECT "
                "pg_has_role('saas_secret_broker', 'saas_executor', 'member'), "
                "pg_has_role('saas_secret_broker', 'saas_platform', 'member'), "
                "pg_has_role('saas_preview_gateway', 'saas_executor', 'member'), "
                "pg_has_role('saas_preview_gateway', 'saas_platform', 'member')"
            )
        ).one()
        assert memberships == (False, False, False, False)

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_app")
        _set_scope(connection, tenant_id=None, space_id=None)
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_egress_policies")).scalar_one()
            == 0
        )
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_preview_leases")).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_secret_access_leases")
            ).scalar_one()
            == 0
        )
    for scope in scopes:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_app")
            _set_scope(connection, tenant_id=scope["tenant"], space_id=scope["space"])
            for table in (
                "saas_egress_policies",
                "saas_execution_profiles",
                "saas_secret_bindings",
                "saas_preview_leases",
            ):
                assert (
                    connection.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar_one() == 1
                )

    first, second = scopes
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_secret_broker")
        _set_scope(connection, tenant_id=first["tenant"], space_id=first["space"])
        _set_token(connection, "app.secret_token_hash", None)
        for table in (
            "saas_secret_access_leases",
            "saas_secret_bindings",
            "saas_runs",
            "saas_runner_registrations",
        ):
            assert connection.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar_one() == 0

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_secret_broker")
        _set_scope(connection, tenant_id=second["tenant"], space_id=second["space"])
        _set_token(connection, "app.secret_token_hash", str(first["secret_token_hash"]))
        assert (
            connection.execute(sa.text("SELECT id FROM saas_secret_access_leases")).scalar_one()
            == first["secret_lease"]
        )
        assert (
            connection.execute(sa.text("SELECT id FROM saas_secret_bindings")).scalar_one()
            == first["binding"]
        )
        assert connection.execute(sa.text("SELECT id FROM saas_runs")).scalar_one() == first["run"]
        assert (
            connection.execute(sa.text("SELECT id FROM saas_runner_registrations")).scalar_one()
            == first["runner"]
        )
        assert (
            connection.execute(
                sa.text(
                    "UPDATE saas_secret_access_leases SET status = 'redeemed', "
                    "redeemed_at = :now WHERE id = :id"
                ),
                {"now": now + timedelta(minutes=2), "id": first["secret_lease"]},
            ).rowcount
            == 1
        )

    with pytest.raises(DBAPIError, match="permission denied"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_secret_broker")
            connection.execute(sa.text("SELECT id FROM saas_runner_tunnel_placements"))

    with pytest.raises(DBAPIError, match="Secret lease lifecycle is monotonic"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_secret_broker")
            _set_token(connection, "app.secret_token_hash", str(first["secret_token_hash"]))
            connection.execute(
                sa.text(
                    "UPDATE saas_secret_access_leases SET status = 'active', "
                    "redeemed_at = NULL WHERE id = :id"
                ),
                {"id": first["secret_lease"]},
            )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_gateway")
        _set_token(connection, "app.preview_token_hash", None)
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_runner_tunnel_placements")
            ).scalar_one()
            == 0
        )

    resolver = RunnerTunnelPlacementAuthority(
        _role_factory(engine, "saas_platform"),
        route_session_factory=_role_factory(engine, "saas_preview_gateway"),
        gateway_instance_id=f"gateway-{first['suffix']}",
    )
    resolved = resolver.resolve_preview_route(
        runner_id=first["runner"],
        runner_connection_generation=1,
        preview_token_hash=first["preview_token_hash"],
        now=now + timedelta(minutes=1),
    )
    assert resolved.placement_id == first["tunnel_placement"]

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_gateway")
        _set_scope(connection, tenant_id=second["tenant"], space_id=second["space"])
        _set_token(connection, "app.preview_token_hash", str(first["preview_token_hash"]))
        assert (
            connection.execute(sa.text("SELECT id FROM saas_preview_leases")).scalar_one()
            == first["preview"]
        )
        assert connection.execute(sa.text("SELECT id FROM saas_runs")).scalar_one() == first["run"]
        assert (
            connection.execute(sa.text("SELECT id FROM saas_runner_registrations")).scalar_one()
            == first["runner"]
        )
        assert (
            connection.execute(
                sa.text("SELECT id FROM saas_runner_tunnel_placements")
            ).scalar_one()
            == first["tunnel_placement"]
        )
        assert (
            connection.execute(sa.text("SELECT id FROM saas_worktree_instances")).scalar_one()
            == first["worktree"]
        )
        assert (
            connection.execute(
                sa.text("UPDATE saas_preview_leases SET last_accessed_at = :now WHERE id = :id"),
                {"now": now + timedelta(minutes=2), "id": first["preview"]},
            ).rowcount
            == 1
        )
        assert (
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_leases SET status = 'revoked', revoked_at = :now "
                    "WHERE id = :id"
                ),
                {"now": now + timedelta(minutes=3), "id": first["preview"]},
            ).rowcount
            == 1
        )

    with pytest.raises(DBAPIError, match="Preview lease lifecycle is monotonic"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_preview_gateway")
            _set_token(connection, "app.preview_token_hash", str(first["preview_token_hash"]))
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_leases SET status = 'active', revoked_at = NULL "
                    "WHERE id = :id"
                ),
                {"id": first["preview"]},
            )

    with pytest.raises(DBAPIError, match="Isolation authority bindings are immutable"):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_app")
            _set_scope(connection, tenant_id=first["tenant"], space_id=first["space"])
            connection.execute(
                sa.text("UPDATE saas_secret_bindings SET vault_ref = 'changed' WHERE id = :id"),
                {"id": first["binding"]},
            )

    engine.dispose()


def test_real_postgresql_isolation_migration_downgrade_removes_guards_and_policies(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    with engine.begin() as connection:
        _migrate(connection, root, "head")
        _migrate(connection, root, "-p4b000000001")
        tables = set(
            connection.execute(
                sa.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                    "AND tablename = ANY(:tables)"
                ),
                {"tables": sorted(_ISOLATION_RLS_TABLES)},
            ).scalars()
        )
        assert not tables
        policies = connection.execute(
            sa.text(
                "SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND ("
                "policyname LIKE 'rls_%_secret_broker' "
                "OR policyname LIKE 'rls_%_preview_gateway')"
            )
        ).scalar_one()
        assert policies == 0
        functions = connection.execute(
            sa.text(
                "SELECT count(*) FROM pg_proc JOIN pg_namespace "
                "ON pg_namespace.oid = pronamespace "
                "WHERE nspname = 'public' AND proname = ANY(:functions)"
            ),
            {
                "functions": [
                    "saas_guard_egress_policy_immutable",
                    "saas_guard_execution_profile_immutable",
                    "saas_guard_preview_lease_immutable",
                    "saas_guard_run_isolation_grant_immutable",
                    "saas_guard_secret_access_lease_immutable",
                    "saas_guard_secret_binding_immutable",
                ]
            },
        ).scalar_one()
        assert functions == 0
        _migrate(connection, root, "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
    engine.dispose()
