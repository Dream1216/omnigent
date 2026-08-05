"""Run a disposable PostgreSQL logical backup and isolated-restore contract.

This is deliberately CI evidence, not production recovery evidence. It proves that
an exact migrated PostgreSQL database can be dumped, restored into a different
database, replay post-backup deletion/revocation facts, retain forced RLS, and match
selected content hashes. It does not exercise WAL/PITR, another failure domain,
multi-AZ failover, external KMS/object storage, or production data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import URL, make_url

from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
from saas.runtime_rls import install_runtime_rls, load_runtime_rls_contract, verify_runtime_rls

_DATABASE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_SELECTED_HASH_TABLES = (
    "alembic_version",
    "saas_alembic_version",
    "users",
    "saas_global_users",
    "saas_identity_connections",
    "saas_auth_sessions",
    "saas_tenants",
    "saas_spaces",
    "saas_tenant_memberships",
    "saas_space_memberships",
    "saas_service_accounts",
    "saas_api_credentials",
    "saas_control_plane_outbox",
)


class PostgreSqlRestoreContractError(RuntimeError):
    """Raised when the disposable restore cannot prove the CI contract."""


@dataclass(frozen=True, slots=True)
class PostgreSqlEndpoint:
    """Non-secret PostgreSQL connection coordinates plus an isolated password."""

    drivername: str
    username: str
    password: str | None
    host: str
    port: int
    admin_database: str

    @classmethod
    def parse(cls, raw_url: str) -> PostgreSqlEndpoint:
        """Parse a TCP PostgreSQL URL and reject ambiguous or unsafe targets."""

        url = make_url(raw_url)
        if not url.drivername.startswith("postgresql"):
            raise PostgreSqlRestoreContractError("admin URL must use PostgreSQL")
        if not url.username or not url.host or not url.port or not url.database:
            raise PostgreSqlRestoreContractError(
                "admin URL must declare username, TCP host, port, and database"
            )
        if url.query:
            raise PostgreSqlRestoreContractError("admin URL query parameters are not allowed")
        return cls(
            drivername=url.drivername,
            username=url.username,
            password=url.password,
            host=url.host,
            port=url.port,
            admin_database=url.database,
        )

    def sqlalchemy_url(self, database: str) -> URL:
        _require_database_name(database)
        return URL.create(
            self.drivername,
            username=self.username,
            password=self.password,
            host=self.host,
            port=self.port,
            database=database,
        )


def _require_database_name(database: str) -> None:
    if _DATABASE_NAME.fullmatch(database) is None:
        raise PostgreSqlRestoreContractError("unsafe generated database name")


def _database_name(kind: str) -> str:
    return f"omnigent_{kind}_{uuid4().hex[:20]}"


def _admin_engine(endpoint: PostgreSqlEndpoint) -> sa.Engine:
    return sa.create_engine(
        endpoint.sqlalchemy_url(endpoint.admin_database),
        isolation_level="AUTOCOMMIT",
        poolclass=sa.pool.NullPool,
    )


def _create_database(endpoint: PostgreSqlEndpoint, database: str) -> None:
    _require_database_name(database)
    engine = _admin_engine(endpoint)
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database}"')
    finally:
        engine.dispose()


def _drop_database(endpoint: PostgreSqlEndpoint, database: str) -> None:
    _require_database_name(database)
    engine = _admin_engine(endpoint)
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
    finally:
        engine.dispose()


def _alembic_upgrade(connection: sa.Connection, config_path: Path, script_path: Path) -> None:
    config = Config(config_path)
    config.set_main_option("script_location", str(script_path))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _migrate_source(repo: Path, endpoint: PostgreSqlEndpoint, database: str) -> None:
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            _alembic_upgrade(
                connection,
                repo / "omnigent/db/alembic.ini",
                repo / "omnigent/db/migrations",
            )
            _alembic_upgrade(
                connection,
                repo / "saas/control_plane/alembic.ini",
                repo / "saas/control_plane/migrations",
            )
            install_runtime_rls(connection)
            connection.exec_driver_sql(
                (repo / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
            connection.exec_driver_sql(
                (repo / "saas/runtime_rls/postgresql_roles.sql").read_text(encoding="utf-8")
            )
    finally:
        engine.dispose()


def _seed_source(endpoint: PostgreSqlEndpoint, database: str) -> dict[str, str | int]:
    identifiers: dict[str, str | int] = {
        "actor_a": "10000000-0000-4000-8000-000000000001",
        "actor_b": "10000000-0000-4000-8000-000000000002",
        "tenant_a": "20000000-0000-4000-8000-000000000001",
        "tenant_b": "20000000-0000-4000-8000-000000000002",
        "space_a": "30000000-0000-4000-8000-000000000001",
        "space_b": "30000000-0000-4000-8000-000000000002",
        "identity_a": "40000000-0000-4000-8000-000000000001",
        "identity_b": "40000000-0000-4000-8000-000000000002",
        "session_a": "50000000-0000-4000-8000-000000000001",
        "session_b": "50000000-0000-4000-8000-000000000002",
        "service_account_a": "70000000-0000-4000-8000-000000000001",
        "service_account_b": "70000000-0000-4000-8000-000000000002",
        "api_credential_a": "80000000-0000-4000-8000-000000000001",
        "api_credential_b": "80000000-0000-4000-8000-000000000002",
        "outbox_seed": "60000000-0000-4000-8000-000000000001",
        "outbox_replay": "60000000-0000-4000-8000-000000000002",
        "workspace_a": 11001,
        "workspace_b": 22002,
    }
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO users (workspace_id, id, is_admin) VALUES "
                    "(:workspace_a, 'runtime-a', false), (:workspace_b, 'runtime-b', false)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_global_users "
                    "(id, status, security_version, display_name, primary_email_normalized) "
                    "VALUES (:actor_a, 'active', 1, 'Recovery A', 'a@example.test'), "
                    "(:actor_b, 'active', 1, 'Recovery B', 'b@example.test')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenants (id, slug, name, status, plan, home_region) "
                    "VALUES (:tenant_a, 'recovery-a', 'Recovery A', 'active', "
                    "'test', 'region-a'), "
                    "(:tenant_b, 'recovery-b', 'Recovery B', 'active', 'test', 'region-a')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) VALUES "
                    "(:space_a, :tenant_a, 'main', 'Main A', 'active'), "
                    "(:space_b, :tenant_b, 'main', 'Main B', 'active')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenant_memberships "
                    "(tenant_id, user_id, role, status, version, joined_at) VALUES "
                    "(:tenant_a, :actor_a, 'owner', 'active', 1, now()), "
                    "(:tenant_b, :actor_b, 'owner', 'active', 1, now())"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_space_memberships "
                    "(tenant_id, space_id, user_id, role, status, version, joined_at) VALUES "
                    "(:tenant_a, :space_a, :actor_a, 'owner', 'active', 1, now()), "
                    "(:tenant_b, :space_b, :actor_b, 'owner', 'active', 1, now())"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_identity_connections "
                    "(id, user_id, provider, issuer, subject, email_normalized, "
                    "email_verified, status) VALUES "
                    "(:identity_a, :actor_a, 'oidc', 'https://id.example.test', 'actor-a', "
                    "'a@example.test', true, 'active'), "
                    "(:identity_b, :actor_b, 'oidc', 'https://id.example.test', 'actor-b', "
                    "'b@example.test', true, 'active')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_auth_sessions "
                    "(id, user_id, token_hash, security_version, authn_method, expires_at) VALUES "
                    "(:session_a, :actor_a, :token_a, 1, 'oidc', now() + interval '1 day'), "
                    "(:session_b, :actor_b, :token_b, 1, 'oidc', now() + interval '1 day')"
                ),
                {
                    **identifiers,
                    "token_a": "a" * 64,
                    "token_b": "b" * 64,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_service_accounts "
                    "(id, tenant_id, space_id, name, steward_user_id, created_by, status, "
                    "security_version) VALUES "
                    "(:service_account_a, :tenant_a, :space_a, 'Recovery Bot A', :actor_a, "
                    ":actor_a, 'active', 1), "
                    "(:service_account_b, :tenant_b, :space_b, 'Recovery Bot B', :actor_b, "
                    ":actor_b, 'active', 1)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_api_credentials "
                    "(id, tenant_id, service_account_id, name, token_hash, display_prefix, "
                    "permission_scopes, allowed_networks, account_security_version, status, "
                    "expires_at, created_by) VALUES "
                    "(:api_credential_a, :tenant_a, :service_account_a, 'Recovery Key A', "
                    ":token_hash_a, 'omk_recovery_a', CAST(:scopes AS jsonb), '[]'::jsonb, 1, "
                    "'active', now() + interval '1 day', :actor_a), "
                    "(:api_credential_b, :tenant_b, :service_account_b, 'Recovery Key B', "
                    ":token_hash_b, 'omk_recovery_b', CAST(:scopes AS jsonb), '[]'::jsonb, 1, "
                    "'active', now() + interval '1 day', :actor_b)"
                ),
                {
                    **identifiers,
                    "token_hash_a": "e" * 64,
                    "token_hash_b": "f" * 64,
                    "scopes": json.dumps(["project.read_metadata"]),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, available_at) VALUES "
                    "(:outbox_seed, :tenant_a, 'recovery', 'seed', 'recovery.seeded', "
                    "CAST(:payload AS jsonb), 'recovery-seed', :request_hash, 0, now())"
                ),
                {
                    **identifiers,
                    "payload": json.dumps({"kind": "ci_contract", "tenant": "a"}),
                    "request_hash": "c" * 64,
                },
            )
    finally:
        engine.dispose()
    return identifiers


def _apply_post_backup_replay(
    endpoint: PostgreSqlEndpoint,
    database: str,
    identifiers: Mapping[str, str | int],
) -> None:
    replay_parameters = {
        **identifiers,
        "replay_at": datetime(2026, 8, 5, 0, 0, tzinfo=UTC),
        "tenant_b_key": str(identifiers["tenant_b"]),
    }
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_global_users SET security_version = 2 WHERE id = :actor_b"),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_identity_connections SET status = 'revoked' "
                    "WHERE id = :identity_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_auth_sessions SET revoked_at = :replay_at WHERE id = :session_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_service_accounts SET status = 'suspended', "
                    "security_version = 2, updated_at = :replay_at "
                    "WHERE id = :service_account_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_api_credentials SET status = 'revoked', "
                    "revoked_at = :replay_at WHERE id = :api_credential_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_tenant_memberships SET status = 'removed', version = 2 "
                    "WHERE tenant_id = :tenant_b AND user_id = :actor_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_space_memberships SET status = 'removed', version = 2 "
                    "WHERE tenant_id = :tenant_b AND space_id = :space_b "
                    "AND user_id = :actor_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_tenants SET status = 'pending_deletion' WHERE id = :tenant_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, available_at, created_at) "
                    "VALUES (:outbox_replay, :tenant_b, 'tenant', :tenant_b_key, "
                    "'tenant.deletion_requested', CAST(:payload AS jsonb), "
                    "'recovery-replay', :request_hash, 0, :replay_at, :replay_at)"
                ),
                {
                    **replay_parameters,
                    "payload": json.dumps(
                        {
                            "identity_revoked": True,
                            "service_account_suspended": True,
                            "api_credential_revoked": True,
                            "membership_removed": True,
                            "tenant_pending_deletion": True,
                        }
                    ),
                    "request_hash": "d" * 64,
                },
            )
    finally:
        engine.dispose()


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in sorted(value.items())}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _database_digest(endpoint: PostgreSqlEndpoint, database: str) -> tuple[str, dict[str, int]]:
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    table_counts: dict[str, int] = {}
    canonical_rows: dict[str, list[dict[str, Any]]] = {}
    try:
        with engine.connect() as connection:
            inspector = sa.inspect(connection)
            for table in _SELECTED_HASH_TABLES:
                if not inspector.has_table(table, schema="public"):
                    raise PostgreSqlRestoreContractError(f"missing hash table {table}")
                quoted = connection.dialect.identifier_preparer.quote(table)
                rows = [
                    {str(key): _normalize(value) for key, value in row.items()}
                    for row in connection.execute(
                        sa.text(f"SELECT * FROM public.{quoted}")
                    ).mappings()
                ]
                rows.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
                canonical_rows[table] = rows
                table_counts[table] = len(rows)
    finally:
        engine.dispose()
    encoded = json.dumps(
        canonical_rows,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), table_counts


def _verify_control_plane_rls(connection: sa.Connection) -> None:
    rows = connection.execute(
        sa.text(
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relname = ANY(:tables)"
        ),
        {"tables": sorted(CONTROL_PLANE_RLS_TABLES)},
    ).mappings()
    facts = {row["relname"]: (row["relrowsecurity"], row["relforcerowsecurity"]) for row in rows}
    if set(facts) != set(CONTROL_PLANE_RLS_TABLES) or any(
        fact != (True, True) for fact in facts.values()
    ):
        raise PostgreSqlRestoreContractError("restored control-plane forced RLS drifted")


def _verify_restored_database(
    endpoint: PostgreSqlEndpoint,
    database: str,
    identifiers: Mapping[str, str | int],
) -> dict[str, Any]:
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            saas_head = connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one()
            if saas_head != "p6a000000001":
                raise PostgreSqlRestoreContractError("restored SaaS migration head drifted")
            official_heads = sorted(
                connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalars()
            )
            if not official_heads:
                raise PostgreSqlRestoreContractError("restored official migration head is missing")
            _verify_control_plane_rls(connection)
            verify_runtime_rls(connection)
            connection.exec_driver_sql(
                "SET LOCAL ROLE saas_app; "
                f"SET LOCAL app.actor_id = '{identifiers['actor_a']}'; "
                f"SET LOCAL app.tenant_id = '{identifiers['tenant_a']}'"
            )
            visible_tenants = set(
                connection.execute(sa.text("SELECT id::text FROM saas_tenants")).scalars()
            )
            if visible_tenants != {identifiers["tenant_a"]}:
                raise PostgreSqlRestoreContractError("restored SaaS RLS exposed another tenant")
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "SET LOCAL ROLE omnigent_runtime_app; "
                f"SET LOCAL app.runtime_workspace_id = '{identifiers['workspace_a']}'"
            )
            visible_runtime_users = set(
                connection.execute(sa.text("SELECT id FROM users")).scalars()
            )
            if visible_runtime_users != {"runtime-a"}:
                raise PostgreSqlRestoreContractError(
                    "restored Runtime RLS exposed another workspace"
                )
        with engine.connect() as connection:
            replay = connection.execute(
                sa.text(
                    "SELECT u.security_version, i.status, s.revoked_at IS NOT NULL, "
                    "tm.status, sm.status, t.status, machine.status, "
                    "machine.security_version, credential.status, "
                    "credential.revoked_at IS NOT NULL "
                    "FROM saas_global_users u "
                    "JOIN saas_identity_connections i ON i.user_id = u.id "
                    "JOIN saas_auth_sessions s ON s.user_id = u.id "
                    "JOIN saas_tenant_memberships tm ON tm.user_id = u.id "
                    "JOIN saas_space_memberships sm ON sm.user_id = u.id "
                    "JOIN saas_tenants t ON t.id = tm.tenant_id "
                    "JOIN saas_service_accounts machine ON machine.steward_user_id = u.id "
                    "AND machine.tenant_id = t.id "
                    "JOIN saas_api_credentials credential "
                    "ON credential.service_account_id = machine.id "
                    "WHERE u.id = :actor_b"
                ),
                identifiers,
            ).one()
            if tuple(replay) != (
                2,
                "revoked",
                True,
                "removed",
                "removed",
                "pending_deletion",
                "suspended",
                2,
                "revoked",
                True,
            ):
                raise PostgreSqlRestoreContractError(
                    "post-backup revocation/deletion replay is incomplete"
                )
        return {
            "saas_migration_head": saas_head,
            "official_migration_heads": official_heads,
            "control_plane_forced_rls_tables": len(CONTROL_PLANE_RLS_TABLES),
            "runtime_forced_rls_tables": len(load_runtime_rls_contract()),
            "cross_tenant_negative_probe": "passed",
            "cross_workspace_negative_probe": "passed",
            "post_backup_revocation_and_deletion_marker_replay": "passed",
        }
    finally:
        engine.dispose()


def _tool_version_major(tool: str) -> int | None:
    path = shutil.which(tool)
    if path is None:
        return None
    completed = subprocess.run(
        [path, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    match = re.search(r"(\d+)(?:\.\d+)?", completed.stdout)
    return int(match.group(1)) if completed.returncode == 0 and match else None


def _run_pg_tool(
    tool: str,
    endpoint: PostgreSqlEndpoint,
    database: str,
    archive: Path,
) -> str:
    _require_database_name(database)
    password_env = {**os.environ}
    if endpoint.password is not None:
        password_env["PGPASSWORD"] = endpoint.password
    host_tool = shutil.which(tool)
    if host_tool is not None and _tool_version_major(tool) == 16:
        command_line = [
            host_tool,
            "--host",
            endpoint.host,
            "--port",
            str(endpoint.port),
            "--username",
            endpoint.username,
            "--no-password",
        ]
        if tool == "pg_dump":
            command_line.extend(
                [
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    f"--file={archive}",
                    database,
                ]
            )
        else:
            command_line.extend(
                [
                    "--exit-on-error",
                    "--no-owner",
                    "--no-privileges",
                    f"--dbname={database}",
                    str(archive),
                ]
            )
        implementation = "host-postgresql-client-16"
    else:
        docker = shutil.which("docker")
        if docker is None:
            raise PostgreSqlRestoreContractError(
                "PostgreSQL 16 client or Docker is required for the restore contract"
            )
        mounted_archive = f"/evidence/{archive.name}"
        command_line = [
            docker,
            "run",
            "--rm",
            "--network=host",
            f"--volume={archive.parent}:/evidence",
            "--env=PGPASSWORD",
            "postgres:16",
            tool,
            "--host",
            endpoint.host,
            "--port",
            str(endpoint.port),
            "--username",
            endpoint.username,
            "--no-password",
        ]
        if tool == "pg_dump":
            command_line.extend(
                [
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    f"--file={mounted_archive}",
                    database,
                ]
            )
        else:
            command_line.extend(
                [
                    "--exit-on-error",
                    "--no-owner",
                    "--no-privileges",
                    f"--dbname={database}",
                    mounted_archive,
                ]
            )
        implementation = "docker-postgres-16-client"
    completed = subprocess.run(
        command_line,
        check=False,
        capture_output=True,
        text=True,
        env=password_env,
        timeout=180,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout)[-4096:]
        raise PostgreSqlRestoreContractError(f"{tool} failed: {detail}")
    return implementation


def run_logical_restore_contract(
    repo: Path,
    admin_url: str,
    *,
    product_revision: str,
    allow_disposable_databases: bool = False,
) -> dict[str, Any]:
    """Execute the disposable logical restore and return non-production proof."""

    if not allow_disposable_databases:
        raise PostgreSqlRestoreContractError(
            "explicit disposable-database authorization is required"
        )
    if re.fullmatch(r"[0-9a-f]{40}", product_revision) is None:
        raise PostgreSqlRestoreContractError("product_revision must be a full Git SHA")
    endpoint = PostgreSqlEndpoint.parse(admin_url)
    source_database = _database_name("restore_source")
    target_database = _database_name("restore_target")
    started = datetime.now(UTC)
    created: list[str] = []
    try:
        _create_database(endpoint, source_database)
        created.append(source_database)
        _migrate_source(repo, endpoint, source_database)
        identifiers = _seed_source(endpoint, source_database)
        with tempfile.TemporaryDirectory(prefix="omnigent-logical-restore-") as temporary:
            archive = Path(temporary) / "backup.dump"
            dump_client = _run_pg_tool("pg_dump", endpoint, source_database, archive)
            if not archive.is_file() or archive.stat().st_size <= 0:
                raise PostgreSqlRestoreContractError("pg_dump produced an empty archive")
            backup_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
            _apply_post_backup_replay(endpoint, source_database, identifiers)
            source_hash, source_counts = _database_digest(endpoint, source_database)
            _create_database(endpoint, target_database)
            created.append(target_database)
            restore_client = _run_pg_tool("pg_restore", endpoint, target_database, archive)
        target_engine = sa.create_engine(
            endpoint.sqlalchemy_url(target_database), poolclass=sa.pool.NullPool
        )
        try:
            with target_engine.begin() as connection:
                connection.exec_driver_sql(
                    (repo / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
                )
                connection.exec_driver_sql(
                    (repo / "saas/runtime_rls/postgresql_roles.sql").read_text(encoding="utf-8")
                )
        finally:
            target_engine.dispose()
        _apply_post_backup_replay(endpoint, target_database, identifiers)
        restored_facts = _verify_restored_database(endpoint, target_database, identifiers)
        target_hash, target_counts = _database_digest(endpoint, target_database)
        if target_hash != source_hash or target_counts != source_counts:
            raise PostgreSqlRestoreContractError("restored selected-table content hash drifted")
        completed = datetime.now(UTC)
        return {
            "schema_version": 1,
            "contract": "ci-isolated-postgresql-logical-restore",
            "status": "pass",
            "evidence_kind": "ci_contract_not_production_drill",
            "product_revision": product_revision,
            "upstream_revision": "8e17c9ec081fc0219c71db773cc7bb0cb516633a",
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "duration_seconds": round((completed - started).total_seconds(), 3),
            "postgresql_client": dump_client,
            "postgresql_restore_client": restore_client,
            "backup_archive_sha256": backup_sha256,
            "selected_table_content_sha256": target_hash,
            "selected_table_row_counts": target_counts,
            **restored_facts,
            "source_and_restore_database_names_were_distinct": source_database != target_database,
            "temporary_databases_dropped_after_report": True,
            "not_proven": [
                "production data backup or restore",
                "WAL continuity or point-in-time recovery",
                "multi-AZ failover or another failure domain",
                "external KMS object lock backup retention or signed recovery evidence",
                "production Tenant or cluster RPO and RTO",
            ],
        }
    finally:
        for database in reversed(created):
            _drop_database(endpoint, database)
