from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from psycopg import sql

from saas.control_plane import SaasBase
from saas.scripts.build_n1_compat import materialize_n1_compat


def _migration_config(connection: sa.Connection) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option(
        "script_location",
        str(root / "saas/control_plane/migrations"),
    )
    config.attributes["connection"] = connection
    return config


def _render_static_sql(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append("{expression}")
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _render_static_sql(node.left)
        right = _render_static_sql(node.right)
        return None if left is None or right is None else left + right
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "text"
        and node.args
    ):
        return _render_static_sql(node.args[0])
    return None


def test_all_control_plane_migrations_leave_cluster_role_graph_to_principal_operator() -> None:
    root = Path(__file__).resolve().parents[2]
    migration_directory = root / "saas/control_plane/migrations/versions"
    violations: list[str] = []
    role_ddl = re.compile(r"\b(?:CREATE|ALTER|DROP)\s+ROLE\b", re.IGNORECASE)
    membership = re.compile(r"\b(?:GRANT|REVOKE)\b.*\b(?:TO|FROM)\b", re.IGNORECASE)

    for path in sorted(migration_directory.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if not (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in {"execute", "exec_driver_sql"}
                and call.args
            ):
                continue
            sql_text = _render_static_sql(call.args[0])
            if sql_text is None:
                continue
            for statement in sql_text.split(";"):
                normalized = " ".join(statement.split())
                if role_ddl.search(normalized) or (
                    membership.search(normalized) and " ON " not in f" {normalized.upper()} "
                ):
                    violations.append(f"{path.name}:{call.lineno}:{normalized}")

    assert violations == []


def test_control_plane_migration_matches_declared_model_columns() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "head")

        inspector = sa.inspect(connection)
        application_tables = set(inspector.get_table_names()) - {"saas_alembic_version"}
        assert application_tables == set(SaasBase.metadata.tables)
        for table_name, table in SaasBase.metadata.tables.items():
            migrated_columns = {column["name"] for column in inspector.get_columns(table_name)}
            assert migrated_columns == set(table.columns.keys())

        revision = connection.execute(
            sa.text("SELECT version_num FROM saas_alembic_version")
        ).scalar_one()
        assert revision == "p0s000000006"
        first_run_scope = next(
            foreign_key
            for foreign_key in inspector.get_foreign_keys("saas_tenant_onboardings")
            if foreign_key["name"] == "fk_tenant_onboarding_first_run_scope"
        )
        assert first_run_scope["constrained_columns"] == [
            "first_run_id",
            "tenant_id",
            "space_id",
            "default_project_id",
        ]
        assert first_run_scope["referred_table"] == "saas_runs"
        assert first_run_scope["referred_columns"] == [
            "id",
            "tenant_id",
            "space_id",
            "project_id",
        ]
        assert first_run_scope["options"].get("ondelete") == "RESTRICT"
        runtime_placement = next(
            foreign_key
            for foreign_key in inspector.get_foreign_keys("saas_tenant_onboardings")
            if foreign_key["name"] == "fk_tenant_onboarding_runtime_placement"
        )
        assert runtime_placement["constrained_columns"] == ["runtime_placement_id"]
        assert runtime_placement["referred_table"] == "saas_runtime_placements"
        assert runtime_placement["referred_columns"] == ["id"]
        assert runtime_placement["options"].get("ondelete") == "RESTRICT"
        onboarding_checks = {
            check["name"] for check in inspector.get_check_constraints("saas_tenant_onboardings")
        }
        assert {
            "ck_tenant_onboarding_runtime_request",
            "ck_tenant_onboarding_initial_placement",
            "ck_tenant_onboarding_ready_placement",
            "ck_tenant_onboarding_failure_evidence",
        } <= onboarding_checks
        preflight_indexes = {
            value["name"] for value in inspector.get_indexes("saas_enterprise_access_preflights")
        }
        assert {
            "ix_enterprise_access_preflight_requester",
            "ix_enterprise_access_preflight_inbox",
        } <= preflight_indexes
        assert "ix_tenant_membership_directory" in {
            value["name"] for value in inspector.get_indexes("saas_tenant_memberships")
        }
        assert "ix_space_membership_member_directory" in {
            value["name"] for value in inspector.get_indexes("saas_space_memberships")
        }
        assert "ix_invitation_tenant_status_expiry" in {
            value["name"] for value in inspector.get_indexes("saas_membership_invitations")
        }

        command.downgrade(config, "base")
        remaining_tables = set(sa.inspect(connection).get_table_names())
        assert remaining_tables <= {"saas_alembic_version"}
    engine.dispose()


def test_registration_rate_limit_migration_has_exact_schema_and_rollback() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000004")
        assert "saas_registration_rate_limits" not in sa.inspect(connection).get_table_names()
        assert (
            "saas_registration_rate_limit_policies" not in sa.inspect(connection).get_table_names()
        )

        command.upgrade(config, "p0s000000005")
        inspector = sa.inspect(connection)
        assert {
            column["name"]
            for column in inspector.get_columns("saas_registration_rate_limit_policies")
        } == {
            "action",
            "subject_kind",
            "limit_count",
            "window_seconds",
            "retention_seconds",
            "max_rows",
            "current_rows",
            "policy_revision",
            "created_at",
            "updated_at",
        }
        assert {
            column["name"] for column in inspector.get_columns("saas_registration_rate_limits")
        } == {
            "action",
            "subject_kind",
            "key_id",
            "subject_hmac",
            "window_started_at",
            "request_count",
            "expires_at",
            "policy_revision",
            "version",
            "created_at",
            "updated_at",
        }
        assert inspector.get_pk_constraint("saas_registration_rate_limits")[
            "constrained_columns"
        ] == ["action", "subject_kind", "key_id", "subject_hmac"]
        assert {
            index["name"] for index in inspector.get_indexes("saas_registration_rate_limits")
        } == {"ix_registration_rate_limit_expiry"}
        assert {
            tuple(row)
            for row in connection.execute(
                sa.text("SELECT action, subject_kind FROM saas_registration_rate_limit_policies")
            )
        } == {
            ("registration.request", "email"),
            ("registration.resend", "email"),
            ("registration.verify", "registration"),
        }
        old_now = datetime(2026, 8, 26, 5, 55, tzinfo=timezone.utc)
        connection.execute(
            sa.text(
                "INSERT INTO saas_registration_rate_limits "
                "(action, subject_kind, key_id, subject_hmac, window_started_at, "
                "request_count, expires_at, policy_revision, version) "
                "VALUES ('registration.request', 'email', 'p0s5-test', :subject_hmac, "
                ":now, 1, :expires_at, 'registration-rate-limit-v1', 1)"
            ),
            {
                "subject_hmac": "b" * 64,
                "now": old_now,
                "expires_at": old_now + timedelta(minutes=1),
            },
        )
        connection.execute(
            sa.text(
                "UPDATE saas_registration_rate_limit_policies SET current_rows = 1 "
                "WHERE action = 'registration.request' AND subject_kind = 'email'"
            )
        )

        command.upgrade(config, "p0s000000006")
        assert (
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM saas_registration_rate_limits WHERE key_id = 'p0s5-test'"
                )
            )
            == 1
        )
        policies = {
            tuple(row)
            for row in connection.execute(
                sa.text(
                    "SELECT action, subject_kind, limit_count, window_seconds, "
                    "retention_seconds, max_rows, current_rows, policy_revision "
                    "FROM saas_registration_rate_limit_policies"
                )
            )
        }
        assert policies == {
            (
                "registration.request",
                "email",
                5,
                900,
                86400,
                1_000_000,
                1,
                "registration-rate-limit-v1",
            ),
            (
                "registration.request",
                "network",
                60,
                900,
                86400,
                1_000_000,
                0,
                "registration-rate-limit-v1",
            ),
            (
                "registration.resend",
                "email",
                3,
                900,
                86400,
                1_000_000,
                0,
                "registration-rate-limit-v1",
            ),
            (
                "registration.resend",
                "network",
                60,
                900,
                86400,
                1_000_000,
                0,
                "registration-rate-limit-v1",
            ),
            (
                "registration.verify",
                "registration",
                10,
                900,
                86400,
                1_000_000,
                0,
                "registration-rate-limit-v1",
            ),
            (
                "registration.verify",
                "network",
                120,
                900,
                86400,
                1_000_000,
                0,
                "registration-rate-limit-v1",
            ),
        }
        now = datetime(2026, 8, 26, 6, 0, tzinfo=timezone.utc)
        connection.execute(
            sa.text(
                "INSERT INTO saas_registration_rate_limits "
                "(action, subject_kind, key_id, subject_hmac, window_started_at, "
                "request_count, expires_at, policy_revision, version) "
                "VALUES ('registration.request', 'network', 'test-v1', :subject_hmac, "
                ":now, 1, :expires_at, 'registration-rate-limit-v1', 1)"
            ),
            {
                "subject_hmac": "a" * 64,
                "now": now,
                "expires_at": now + timedelta(minutes=1),
            },
        )

        with pytest.raises(RuntimeError, match=r"p0s000000006.*network rate-limit counters"):
            command.downgrade(config, "p0s000000005")
        connection.execute(
            sa.text("DELETE FROM saas_registration_rate_limits WHERE subject_kind = 'network'")
        )
        connection.execute(
            sa.text(
                "UPDATE saas_registration_rate_limit_policies SET limit_count = 61 "
                "WHERE action = 'registration.request' AND subject_kind = 'network'"
            )
        )
        with pytest.raises(RuntimeError, match=r"p0s000000006.*network policy drift"):
            command.downgrade(config, "p0s000000005")
        connection.execute(
            sa.text(
                "UPDATE saas_registration_rate_limit_policies SET limit_count = 60 "
                "WHERE action = 'registration.request' AND subject_kind = 'network'"
            )
        )
        command.downgrade(config, "p0s000000005")
        assert {
            tuple(row)
            for row in connection.execute(
                sa.text("SELECT action, subject_kind FROM saas_registration_rate_limit_policies")
            )
        } == {
            ("registration.request", "email"),
            ("registration.resend", "email"),
            ("registration.verify", "registration"),
        }
        assert (
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM saas_registration_rate_limits "
                    "WHERE key_id = 'p0s5-test' AND subject_kind = 'email'"
                )
            )
            == 1
        )
        with pytest.raises(sa.exc.IntegrityError):
            connection.execute(
                sa.text(
                    "INSERT INTO saas_registration_rate_limit_policies "
                    "(action, subject_kind, limit_count, window_seconds, retention_seconds, "
                    "max_rows, current_rows, policy_revision) VALUES "
                    "('registration.request', 'network', 60, 900, 86400, 1000000, 0, "
                    "'registration-rate-limit-v1')"
                )
            )
        connection.execute(sa.text("DELETE FROM saas_registration_rate_limits"))
        command.downgrade(config, "p0s000000004")
        assert "saas_registration_rate_limits" not in sa.inspect(connection).get_table_names()
        assert (
            "saas_registration_rate_limit_policies" not in sa.inspect(connection).get_table_names()
        )
        assert (
            connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
            == "p0s000000004"
        )
    engine.dispose()


def test_registration_rate_limit_migration_declares_exact_force_rls_policies() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (
        root / "saas/control_plane/migrations/versions/p0s000000005_registration_rate_limits.py"
    ).read_text(encoding="utf-8")

    assert "ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY" in source
    assert "app.registration_rate_limit_subject_hash" not in source
    assert "CREATE POLICY rls_registration_rate_limit_policies_owner" in source
    assert "CREATE POLICY rls_registration_rate_limits_owner" in source
    assert "SECURITY DEFINER" in source
    assert "saas_consume_registration_rate_limit" in source
    assert "saas_prune_registration_rate_limits" in source
    assert "saas_registration_rate_limit_status" in source
    assert "REVOKE ALL ON FUNCTION public.saas_consume_registration_rate_limit" in source


def test_outbox_quarantine_postgresql_boundary_contract_is_transactional() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (
        root / "saas/control_plane/migrations/versions/p0s000000003_outbox_quarantine.py"
    ).read_text(encoding="utf-8")
    lock_helper = source[
        source.index("def _lock_and_expose_owner_rows") : source.index("def _restore_force_rls")
    ]
    upgrade = source[source.index("def upgrade()") : source.index("def downgrade()")]
    downgrade = source[source.index("def downgrade()") :]
    compatibility = source[
        source.index("def _install_n1_outbox_compatibility") : source.index(
            "def _install_outbox_producer_initial_state_policy"
        )
    ]
    role_source = (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")

    assert "FROM public.saas_outbox_quarantine_events AS receipt WHERE" in source
    assert lock_helper.index("LOCK TABLE public.{quoted_table} IN ACCESS EXCLUSIVE MODE") < (
        lock_helper.index("ALTER TABLE public.{quoted_table} NO FORCE ROW LEVEL SECURITY")
    )
    assert upgrade.index(
        '_lock_and_expose_owner_rows("saas_control_plane_outbox")'
    ) < upgrade.index("_extend_outbox()")
    assert upgrade.index("_install_postgresql_authority()") < upgrade.index(
        '_restore_force_rls("saas_control_plane_outbox")'
    )
    assert (
        "_lock_and_expose_owner_rows(\n"
        '        "saas_control_plane_outbox",\n'
        '        "saas_outbox_quarantine_events",\n'
        "    )"
    ) in downgrade
    assert downgrade.index("_lock_and_expose_owner_rows(") < downgrade.index(
        "quarantine_evidence ="
    )

    # The ordinary dispatcher downgrade contract remains unchanged.  The
    # security-patched N-1 bridge below has its own fixed column projection.
    assert ("REVOKE ALL PRIVILEGES ON saas_control_plane_outbox FROM saas_dispatcher") in downgrade
    assert ("GRANT SELECT, UPDATE ON saas_control_plane_outbox TO saas_dispatcher") in downgrade
    assert downgrade.index(
        "GRANT SELECT, UPDATE ON saas_control_plane_outbox TO saas_dispatcher"
    ) < downgrade.index('_restore_force_rls("saas_control_plane_outbox")')
    assert (
        "GRANT UPDATE (attempt_count, available_at, claimed_at, claim_token, "
        '"\n        "last_error_code, last_error_digest, published_at, quarantined_at) '
    ) in source
    assert "_preflight_n1_compat_role_isolated()" in compatibility
    assert "_revoke_all_saas_table_privileges" not in source
    assert "_N1_OUTBOX_SELECT_COLUMNS" in source
    assert "_N1_OUTBOX_UPDATE_COLUMNS" in source
    assert "GRANT SELECT, UPDATE ON saas_control_plane_outbox" not in compatibility
    assert "must drain this worker before any Outbox" in compatibility
    assert "ON saas_platform_role_assignments TO" not in compatibility
    assert "ON saas_platform_support_sessions TO" not in compatibility
    assert "Schema-forward application rollback only" in role_source
    assert "Never replay the 9451a64" in role_source
    assert "p0s3 N-1 Outbox compatibility guards are absent or disabled" in role_source


def test_control_plane_role_psql_entrypoint_is_atomic_and_first_error_stopping() -> None:
    root = Path(__file__).resolve().parents[2]
    wrapper = (root / "saas/control_plane/postgresql_roles.psql").read_text(encoding="utf-8")
    body = (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")

    assert wrapper.index("\\set ON_ERROR_STOP on") < wrapper.index("BEGIN;")
    assert wrapper.index("BEGIN;") < wrapper.index("\\ir postgresql_roles.sql")
    assert wrapper.index("\\ir postgresql_roles.sql") < wrapper.index("COMMIT;")
    assert "never invoke this file directly with plain `psql -f`" in body
    assert "CREATE ROLE" not in body
    assert "ALTER ROLE" not in body
    assert "DROP ROLE" not in body
    assert "GRANT saas_dispatcher TO saas_dispatcher_n1_compat" not in body
    assert "GRANT saas_platform_governance TO saas_privacy_executor" not in body
    assert "control-plane principal preflight rejected" in body
    assert "control-plane fixed principal membership preflight rejected" in body


def test_control_plane_database_psql_entrypoint_revokes_public_temporary_atomically() -> None:
    root = Path(__file__).resolve().parents[2]
    wrapper = (root / "saas/control_plane/postgresql_database.psql").read_text(encoding="utf-8")
    body = (root / "saas/control_plane/postgresql_database.sql").read_text(encoding="utf-8")

    assert wrapper.index("\\set ON_ERROR_STOP on") < wrapper.index("BEGIN;")
    assert wrapper.index("BEGIN;") < wrapper.index("\\ir postgresql_database.sql")
    assert wrapper.index("\\ir postgresql_database.sql") < wrapper.index("COMMIT;")
    assert "caller is not the database owner" in body
    assert "quote_ident(current_database()) || ' FROM PUBLIC'" in body
    assert "PUBLIC TEMPORARY remains enabled" in body


def test_control_plane_principal_bootstrap_is_atomic_and_separate_from_alembic() -> None:
    root = Path(__file__).resolve().parents[2]
    wrapper = (root / "saas/control_plane/postgresql_principals.psql").read_text(encoding="utf-8")
    body = (root / "saas/control_plane/postgresql_principals.sql").read_text(encoding="utf-8")

    assert wrapper.index("\\set ON_ERROR_STOP on") < wrapper.index("BEGIN;")
    assert wrapper.index("BEGIN;") < wrapper.index("\\ir postgresql_principals.sql")
    assert wrapper.index("\\ir postgresql_principals.sql") < wrapper.index("COMMIT;")
    assert "EXECUTE 'CREATE ROLE ' || quote_ident(principal_name)" in body
    assert "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION" in body
    assert "|| ' RESET ALL'" in body
    assert "saas_runtime_provider_journal" in body
    assert (
        "GRANT saas_dispatcher TO saas_dispatcher_n1_compat\n        WITH INHERIT FALSE, SET FALSE"
    ) in body
    assert "GRANT saas_platform_governance TO saas_privacy_executor" in body
    for forbidden in (
        "GRANT USAGE ON SCHEMA",
        "GRANT SELECT",
        "GRANT INSERT",
        "GRANT UPDATE",
        "ALTER TABLE",
        "CREATE TABLE",
    ):
        assert forbidden not in body

    migrations = (
        root / "saas/control_plane/migrations/versions/p0s000000001_self_service_onboarding.py",
        root / "saas/control_plane/migrations/versions/pc6a00000001_public_api_execution.py",
        root / "saas/control_plane/migrations/versions/p0s000000003_outbox_quarantine.py",
        root / "saas/control_plane/migrations/versions/p0s000000004_runtime_provider_journal.py",
        root / "saas/control_plane/migrations/versions/p0s000000005_registration_rate_limits.py",
    )
    first_schema_mutations = (
        "_replace_authority_checks(",
        'with op.batch_alter_table("saas_service_accounts")',
        '_lock_and_expose_owner_rows("saas_control_plane_outbox")',
        "op.create_table(",
        "op.create_table(",
    )
    for migration, first_schema_mutation in zip(migrations, first_schema_mutations, strict=True):
        source = migration.read_text(encoding="utf-8")
        assert "CREATE ROLE" not in source
        assert "ALTER ROLE" not in source
        assert "postgresql_principals.psql before Alembic" in source
        assert "rolconnlimit" in source
        assert "rolconfig" in source
        assert "pg_auth_members" in source
        upgrade = source[source.index("def upgrade()") : source.index("def downgrade()")]
        assert upgrade.index("_preflight_postgresql_") < upgrade.index(first_schema_mutation)
    p0s3_source = migrations[2].read_text(encoding="utf-8")
    assert "GRANT saas_dispatcher TO saas_dispatcher_n1_compat" not in p0s3_source
    assert "REVOKE saas_dispatcher FROM saas_dispatcher_n1_compat" not in p0s3_source


def test_real_postgresql_nocreaterole_schema_owner_migrates_to_head(
    isolated_postgres_url: str,
) -> None:
    psql = shutil.which("psql")
    if psql is None:
        pytest.skip("psql is required for NOCREATEROLE authority acceptance")
    root = Path(__file__).resolve().parents[2]
    principals = (root / "saas/control_plane/postgresql_principals.sql").read_text(
        encoding="utf-8"
    )
    engine = sa.create_engine(isolated_postgres_url)
    schema_owner = f"saas_schema_owner_{uuid4().hex[:12]}"
    quoted_owner = engine.dialect.identifier_preparer.quote(schema_owner)
    database_name = sa.engine.make_url(isolated_postgres_url).database
    assert database_name is not None
    quoted_database = engine.dialect.identifier_preparer.quote(database_name)
    administrator = ""
    try:
        with engine.begin() as connection:
            # The cluster-principal phase is intentionally idempotent and is
            # complete before the schema owner exists or Alembic starts.
            connection.exec_driver_sql(principals)
            connection.exec_driver_sql(principals)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_database.sql").read_text(encoding="utf-8")
            )
            administrator = str(connection.scalar(sa.text("SELECT current_user")))
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_owner} NOLOGIN INHERIT NOSUPERUSER "
                "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            )
            connection.exec_driver_sql(f"ALTER SCHEMA public OWNER TO {quoted_owner}")
            connection.exec_driver_sql(
                f"GRANT CONNECT, CREATE, TEMPORARY ON DATABASE {quoted_database} TO {quoted_owner}"
            )

        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_owner}")
            role_facts = connection.execute(
                sa.text(
                    "SELECT current_user, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user"
                )
            ).one()
            assert role_facts == (schema_owner, False, False, False, False, False)
            command.upgrade(_migration_config(connection), "head")
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == "p0s000000006"
            )
            assert connection.scalar(sa.text("SELECT current_user")) == schema_owner

        url = sa.engine.make_url(isolated_postgres_url)
        environment = os.environ.copy()
        environment["PGDATABASE"] = url.database or "postgres"
        environment["PGOPTIONS"] = f"-c role={schema_owner}"
        if url.username:
            environment["PGUSER"] = url.username
        if url.password:
            environment["PGPASSWORD"] = url.password
        if url.host:
            environment["PGHOST"] = url.host
        if url.port:
            environment["PGPORT"] = str(url.port)
        completed = subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "--file",
                str(root / "saas/control_plane/postgresql_roles.psql"),
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
            timeout=90,
        )
        assert completed.returncode == 0, completed.stderr
        with engine.connect() as connection:
            assert connection.scalar(
                sa.text(
                    "SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole "
                    "AND NOT rolreplication AND NOT rolbypassrls "
                    "FROM pg_roles WHERE rolname = :role"
                ),
                {"role": schema_owner},
            )
            assert not connection.scalar(
                sa.text(
                    "SELECT EXISTS (SELECT 1 FROM pg_database AS database "
                    "CROSS JOIN LATERAL aclexplode(COALESCE(database.datacl, "
                    "acldefault('d', database.datdba))) AS privilege "
                    "WHERE database.datname = current_database() "
                    "AND privilege.grantee = 0 "
                    "AND privilege.privilege_type = 'TEMPORARY')"
                )
            )
    finally:
        if administrator:
            quoted_administrator = engine.dialect.identifier_preparer.quote(administrator)
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    f"REASSIGN OWNED BY {quoted_owner} TO {quoted_administrator}"
                )
                connection.exec_driver_sql(f"DROP OWNED BY {quoted_owner}")
                connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_owner}")
        engine.dispose()


def test_real_psql_role_entrypoint_rolls_back_after_n1_preflight_rejection(
    isolated_postgres_url: str,
) -> None:
    psql = shutil.which("psql")
    if psql is None:
        pytest.skip("psql is required for transactional authority-entrypoint acceptance")

    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    login = f"n1_psql_guard_{uuid4().hex[:12]}"
    quoted_login = engine.dialect.identifier_preparer.quote(login)
    try:
        with engine.begin() as connection:
            command.upgrade(_migration_config(connection), "p0s000000003")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_login} NOLOGIN INHERIT NOSUPERUSER "
                "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            )
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher_n1_compat TO {quoted_login} WITH INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                "DROP POLICY rls_n1_compat_role_assignments_deny "
                "ON public.saas_platform_role_assignments"
            )

        url = sa.engine.make_url(isolated_postgres_url)
        environment = os.environ.copy()
        environment.update(
            {
                "PGHOST": url.host or "127.0.0.1",
                "PGPORT": str(url.port or 5432),
                "PGDATABASE": url.database or "postgres",
                "PGUSER": url.username or "postgres",
                "PGPASSWORD": url.password or "",
            }
        )
        completed = subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "--file",
                str(root / "saas/control_plane/postgresql_roles.psql"),
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
            timeout=60,
        )

        assert completed.returncode != 0
        assert "N-1 Outbox compatibility login admission rejected" in completed.stderr
        with engine.connect() as connection:
            policy_count = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_policy "
                    "WHERE polrelid = "
                    "'public.saas_platform_role_assignments'::regclass "
                    "AND polname = 'rls_n1_compat_role_assignments_deny'"
                )
            ).scalar_one()
        assert policy_count == 0
    finally:
        with engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE saas_dispatcher_n1_compat FROM {quoted_login}")
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_login}")
        engine.dispose()


def test_outbox_quarantine_migration_backfills_safe_error_and_terminal_constraints() -> None:
    engine = sa.create_engine("sqlite://")
    event_id, published_id = uuid4(), uuid4()
    legacy_secret = "provider rejected customer-secret"
    now = datetime(2026, 8, 25, 1, 0, tzinfo=timezone.utc)
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000002")
        for identifier, published_at, last_error in (
            (event_id, None, legacy_secret),
            (published_id, now, None),
        ):
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, published_at, last_error) "
                    "VALUES (:id, NULL, 'migration', :aggregate_key, 'migration.event', '{}', "
                    ":idempotency_key, :request_hash, 1, :published_at, :last_error)"
                ),
                {
                    "id": identifier.hex,
                    "aggregate_key": str(identifier),
                    "idempotency_key": f"migration-{identifier}",
                    "request_hash": "a" * 64,
                    "published_at": published_at,
                    "last_error": last_error,
                },
            )

        command.upgrade(config, "p0s000000003")
        migrated = connection.execute(
            sa.text(
                "SELECT last_error, last_error_code, last_error_digest, quarantined_at "
                "FROM saas_control_plane_outbox WHERE id = :id"
            ),
            {"id": event_id.hex},
        ).one()
        assert migrated.last_error is None
        assert migrated.last_error_code == "legacy_delivery_error"
        assert (
            migrated.last_error_digest
            == sha256(b"legacy_delivery_error\0" + event_id.hex.encode()).hexdigest()
        )
        assert migrated.last_error_digest != sha256(legacy_secret.encode()).hexdigest()
        assert migrated.quarantined_at is None
        with pytest.raises(sa.exc.IntegrityError), connection.begin_nested():
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET last_error = 'new secret' WHERE id = :id"
                ),
                {"id": event_id.hex},
            )
        with pytest.raises(sa.exc.IntegrityError), connection.begin_nested():
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET request_hash = :request_hash "
                    "WHERE id = :id"
                ),
                {"id": event_id.hex, "request_hash": "z" * 64},
            )
        columns = {
            value["name"]
            for value in sa.inspect(connection).get_columns("saas_control_plane_outbox")
        }
        assert {"last_error_code", "last_error_digest", "quarantined_at"} <= columns
        outbox_checks = {
            value["name"]
            for value in sa.inspect(connection).get_check_constraints("saas_control_plane_outbox")
        }
        assert "ck_outbox_quarantine_dispatch_clear" in outbox_checks
        connection.execute(
            sa.text("UPDATE saas_control_plane_outbox SET available_at = :now WHERE id = :id"),
            {"id": event_id.hex, "now": now},
        )
        with pytest.raises(sa.exc.IntegrityError), connection.begin_nested():
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET quarantined_at = :now WHERE id = :id"
                ),
                {"id": event_id.hex, "now": now},
            )
        with pytest.raises(sa.exc.IntegrityError):
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET quarantined_at = :now WHERE id = :id"
                ),
                {"id": published_id.hex, "now": now},
            )

        with pytest.raises(
            RuntimeError,
            match="durable Outbox delivery evidence",
        ):
            command.downgrade(config, "p0s000000002")
        assert (
            connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one()
            == "p0s000000003"
        )
        assert {"last_error_code", "last_error_digest", "quarantined_at"} <= {
            value["name"]
            for value in sa.inspect(connection).get_columns("saas_control_plane_outbox")
        }
        connection.execute(
            sa.text(
                "UPDATE saas_control_plane_outbox SET last_error_code = NULL, "
                "last_error_digest = NULL WHERE id = :id"
            ),
            {"id": event_id.hex},
        )

        command.downgrade(config, "p0s000000002")
        downgraded_columns = {
            value["name"]
            for value in sa.inspect(connection).get_columns("saas_control_plane_outbox")
        }
        assert {"last_error_code", "last_error_digest", "quarantined_at"}.isdisjoint(
            downgraded_columns
        )
    engine.dispose()


def test_outbox_quarantine_migration_rejects_dirty_terminal_dispatch_state() -> None:
    engine = sa.create_engine("sqlite://")
    event_id = uuid4()
    now = datetime(2026, 8, 25, 1, 15, tzinfo=timezone.utc)
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000002")
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox "
                "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, available_at) VALUES "
                "(:id, NULL, 'migration', :aggregate_key, 'migration.dirty', '{}', "
                ":idempotency_key, :request_hash, 1, :available_at)"
            ),
            {
                "id": event_id.hex,
                "aggregate_key": str(event_id),
                "idempotency_key": f"migration-dirty-{event_id}",
                "request_hash": "a" * 64,
                "available_at": now,
            },
        )
        # Model a prior interrupted or manually staged p0s3 rollout: all new
        # columns exist, but the terminal row still carries dispatch state.
        connection.exec_driver_sql(
            "ALTER TABLE saas_control_plane_outbox ADD COLUMN last_error_code VARCHAR(128)"
        )
        connection.exec_driver_sql(
            "ALTER TABLE saas_control_plane_outbox ADD COLUMN last_error_digest VARCHAR(64)"
        )
        connection.exec_driver_sql(
            "ALTER TABLE saas_control_plane_outbox ADD COLUMN quarantined_at DATETIME"
        )
        connection.execute(
            sa.text("UPDATE saas_control_plane_outbox SET quarantined_at = :now WHERE id = :id"),
            {"id": event_id.hex, "now": now},
        )

        with pytest.raises(
            RuntimeError,
            match="retains dispatch scheduling or lease state",
        ):
            command.upgrade(config, "p0s000000003")
        revision = connection.execute(
            sa.text("SELECT version_num FROM saas_alembic_version")
        ).scalar_one()
        assert revision == "p0s000000002"
        assert "saas_outbox_quarantine_events" not in sa.inspect(connection).get_table_names()
    engine.dispose()


def test_outbox_quarantine_migration_ledger_is_content_blind_and_immutable() -> None:
    engine = sa.create_engine("sqlite://")
    source_event_id, receipt_id = uuid4(), uuid4()
    now = datetime(2026, 8, 25, 1, 30, tzinfo=timezone.utc)
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "head")
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox "
                "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, last_error_code, "
                "last_error_digest, quarantined_at) VALUES "
                "(:id, NULL, 'migration', :aggregate_key, 'migration.poison', '{}', "
                ":idempotency_key, :request_hash, 1, 'onboarding_event_invalid', "
                ":error_digest, :now)"
            ),
            {
                "id": source_event_id.hex,
                "aggregate_key": str(source_event_id),
                "idempotency_key": f"migration-poison-{source_event_id}",
                "request_hash": "a" * 64,
                "error_digest": "b" * 64,
                "now": now,
            },
        )
        with pytest.raises(
            RuntimeError,
            match="durable Outbox delivery evidence",
        ):
            command.downgrade(config, "p0s000000002")
        assert (
            connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one()
            == "p0s000000003"
        )
        assert "saas_outbox_quarantine_events" in sa.inspect(connection).get_table_names()
        connection.execute(
            sa.text(
                "INSERT INTO saas_outbox_quarantine_events "
                "(id, source_event_id, tenant_id, source_request_hash, "
                "source_attempt_count, action, error_code, error_digest, sequence, "
                "previous_hash, event_hash, created_at) VALUES "
                "(:id, :source_event_id, NULL, :source_hash, 1, 'quarantined', "
                "'onboarding_event_invalid', :error_digest, 1, :previous_hash, "
                ":event_hash, :now)"
            ),
            {
                "id": receipt_id.hex,
                "source_event_id": source_event_id.hex,
                "source_hash": "a" * 64,
                "error_digest": "b" * 64,
                "previous_hash": "0" * 64,
                "event_hash": "c" * 64,
                "now": now,
            },
        )
        ledger_columns = {
            value["name"]
            for value in sa.inspect(connection).get_columns("saas_outbox_quarantine_events")
        }
        assert "payload" not in ledger_columns
        assert {
            "source_event_id",
            "source_request_hash",
            "error_digest",
            "sequence",
            "previous_hash",
            "event_hash",
        } <= ledger_columns
        for statement in (
            "UPDATE saas_outbox_quarantine_events SET error_code = 'mutated' WHERE id = :id",
            "DELETE FROM saas_outbox_quarantine_events WHERE id = :id",
        ):
            with pytest.raises(
                sa.exc.DatabaseError, match="outbox quarantine events are immutable"
            ):
                connection.execute(sa.text(statement), {"id": receipt_id.hex})
        connection.execute(
            sa.text(
                "UPDATE saas_control_plane_outbox SET last_error_code = NULL, "
                "last_error_digest = NULL, quarantined_at = NULL WHERE id = :id"
            ),
            {"id": source_event_id.hex},
        )
        with pytest.raises(
            RuntimeError,
            match="durable Outbox delivery evidence",
        ):
            command.downgrade(config, "p0s000000002")
        assert (
            connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one()
            == "p0s000000003"
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_outbox_quarantine_events")
            ).scalar_one()
            == 1
        )
    engine.dispose()


def test_real_postgresql_outbox_quarantine_lock_and_acl_round_trip(
    isolated_postgres_url: str,
) -> None:
    engine = sa.create_engine(isolated_postgres_url)
    event_id = uuid4()
    allowed_p0s3_updates = {
        "attempt_count",
        "available_at",
        "claimed_at",
        "claim_token",
        "last_error_code",
        "last_error_digest",
        "published_at",
        "quarantined_at",
    }

    def _dispatcher_update_columns(connection: sa.Connection) -> set[str]:
        columns = connection.execute(
            sa.text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' "
                "AND table_name = 'saas_control_plane_outbox'"
            )
        ).scalars()
        return {
            str(column)
            for column in columns
            if connection.scalar(
                sa.text(
                    "SELECT has_column_privilege("  # nosec B608 - fixed catalog query
                    "'saas_dispatcher', 'public.saas_control_plane_outbox', "
                    ":column, 'UPDATE')"
                ),
                {"column": column},
            )
        }

    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000002")
        # Production role bootstrap grants these content-blind projections so
        # PostgreSQL can privilege-check the pre-existing PC3 Outbox SELECT
        # policy while a dispatcher updates an N-1 row.  Keep this migration
        # test focused on the p0s2/p0s3 Outbox ACL transition itself.
        connection.exec_driver_sql(
            "GRANT SELECT (principal_id, role, status, expires_at) "
            "ON saas_platform_role_assignments TO saas_dispatcher"
        )
        connection.exec_driver_sql(
            "GRANT SELECT (principal_id, token_hash, revoked_at, expires_at) "
            "ON saas_platform_support_sessions TO saas_dispatcher"
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox "
                "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count) VALUES "
                "(:id, NULL, 'migration', :aggregate_key, 'migration.round_trip', "
                "'{}', :idempotency_key, :request_hash, 0)"
            ),
            {
                "id": event_id,
                "aggregate_key": str(event_id),
                "idempotency_key": f"migration-round-trip-{event_id}",
                "request_hash": "a" * 64,
            },
        )

    # Even an ACCESS SHARE holder must block p0s3 before it can temporarily
    # relax FORCE RLS or inspect/backfill a legacy row.  A lock timeout proves
    # the failed transaction leaves neither columns nor revision drift behind.
    blocker = engine.connect()
    blocker_transaction = blocker.begin()
    try:
        blocker.exec_driver_sql("LOCK TABLE public.saas_control_plane_outbox IN ACCESS SHARE MODE")
        migration_connection = engine.connect()
        migration_transaction = migration_connection.begin()
        try:
            migration_connection.exec_driver_sql("SET LOCAL lock_timeout = '250ms'")
            with pytest.raises(sa.exc.DBAPIError):
                command.upgrade(
                    _migration_config(migration_connection),
                    "p0s000000003",
                )
        finally:
            migration_transaction.rollback()
            migration_connection.close()

        with engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == "p0s000000002"
            )
            columns = {
                str(column)
                for column in connection.execute(
                    sa.text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' "
                        "AND table_name = 'saas_control_plane_outbox'"
                    )
                ).scalars()
            }
            assert {"last_error_code", "last_error_digest", "quarantined_at"}.isdisjoint(columns)
    finally:
        blocker_transaction.rollback()
        blocker.close()

    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000003")
        assert not connection.scalar(
            sa.text(
                "SELECT has_table_privilege("  # nosec B608 - fixed catalog query
                "'saas_dispatcher', 'public.saas_control_plane_outbox', 'UPDATE')"
            )
        )
        assert _dispatcher_update_columns(connection) == allowed_p0s3_updates
        assert connection.scalar(
            sa.text(
                "SELECT relforcerowsecurity FROM pg_class "
                "WHERE oid = 'public.saas_control_plane_outbox'::regclass"
            )
        )

        command.downgrade(config, "p0s000000002")
        assert connection.scalar(
            sa.text(
                "SELECT has_table_privilege("  # nosec B608 - fixed catalog query
                "'saas_dispatcher', 'public.saas_control_plane_outbox', 'SELECT')"
            )
        )
        assert connection.scalar(
            sa.text(
                "SELECT has_table_privilege("  # nosec B608 - fixed catalog query
                "'saas_dispatcher', 'public.saas_control_plane_outbox', 'UPDATE')"
            )
        )
        assert connection.scalar(
            sa.text(
                "SELECT has_column_privilege("  # nosec B608 - fixed catalog query
                "'saas_dispatcher', 'public.saas_control_plane_outbox', "
                "'last_error', 'UPDATE')"
            )
        )
        connection.exec_driver_sql("SET LOCAL ROLE saas_dispatcher")
        connection.execute(
            sa.text(
                "UPDATE saas_control_plane_outbox "
                "SET last_error = 'n-minus-one-delivery-error' WHERE id = :id"
            ),
            {"id": event_id},
        )
        connection.exec_driver_sql("RESET ROLE")
        assert connection.scalar(
            sa.text(
                "SELECT relforcerowsecurity FROM pg_class "
                "WHERE oid = 'public.saas_control_plane_outbox'::regclass"
            )
        )

        command.upgrade(config, "p0s000000003")
        assert _dispatcher_update_columns(connection) == allowed_p0s3_updates
        assert not connection.scalar(
            sa.text(
                "SELECT has_column_privilege("  # nosec B608 - fixed catalog query
                "'saas_dispatcher', 'public.saas_control_plane_outbox', "
                "'last_error', 'UPDATE')"
            )
        )
        scrubbed = connection.execute(
            sa.text(
                "SELECT last_error, last_error_code, last_error_digest "
                "FROM saas_control_plane_outbox WHERE id = :id"
            ),
            {"id": event_id},
        ).one()
        assert scrubbed.last_error is None
        assert scrubbed.last_error_code == "legacy_delivery_error"
        assert scrubbed.last_error_digest is not None
    engine.dispose()


def test_real_postgresql_pinned_n1_outbox_compatibility_bridge(
    isolated_postgres_url: str,
) -> None:
    """Exercise 9451a64's claim/ack/failure SQL through the p0s3 bridge."""

    engine = sa.create_engine(isolated_postgres_url)
    ack_id, failure_id, quarantined_id = uuid4(), uuid4(), uuid4()
    receipt_id = uuid4()
    # Sort after the compatibility role to prove admission is independent of
    # pg_auth_members row ordering.
    login_role = f"zz_n1_outbox_probe_{uuid4().hex[:12]}"
    login_password = f"n1-test-{uuid4().hex}{uuid4().hex}"
    planning_principal_id = uuid4()
    now = datetime(2026, 8, 25, 4, 0, tzinfo=timezone.utc)
    request_hash = "a" * 64
    raw_error = "provider rejected plaintext customer-secret"
    allowed_p0s3_updates = {
        "attempt_count",
        "available_at",
        "claimed_at",
        "claim_token",
        "last_error_code",
        "last_error_digest",
        "published_at",
        "quarantined_at",
    }

    with engine.begin() as connection:
        config = _migration_config(connection)
        # Install the predecessor first so this test exercises the exact p0s3
        # migration body rather than a metadata-only schema create.
        command.upgrade(config, "p0s000000002")
        command.upgrade(config, "p0s000000003")

        # Replaying the current N authority is supported and must preserve the
        # bridge. Replaying 9451a64's migration/roles SQL is explicitly not.
        root = Path(__file__).resolve().parents[2]
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_staff_principals "
                "(id, identity_connection_ref, issuer, subject, status, security_version, "
                "created_at, updated_at) VALUES "
                "(:id, :identity_ref, 'https://n1-planning.test', :subject, "
                "'active', 1, :now, :now)"
            ),
            {
                "id": planning_principal_id,
                "identity_ref": f"n1-planning:{planning_principal_id}",
                "subject": f"n1-planning-{planning_principal_id}",
                "now": now,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_role_assignments "
                "(id, principal_id, role, status, version, assigned_by_principal_id, "
                "approval_ref, reason, created_at, updated_at) VALUES "
                "(:id, :principal, 'platform_operator', 'active', 1, :principal, "
                "'n1-planning-test', 'N-1 planning policy test', :now, :now)"
            ),
            {"id": uuid4(), "principal": planning_principal_id, "now": now},
        )

        all_columns = list(
            connection.execute(
                sa.text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'saas_control_plane_outbox'"
                )
            ).scalars()
        )
        base_updates = {
            str(column)
            for column in all_columns
            if connection.scalar(
                sa.text(
                    "SELECT has_column_privilege("  # nosec B608 - fixed catalog query
                    "'saas_dispatcher', 'public.saas_control_plane_outbox', "
                    ":column, 'UPDATE')"
                ),
                {"column": column},
            )
        }
        assert not connection.scalar(
            sa.text(
                "SELECT has_table_privilege("  # nosec B608 - fixed catalog query
                "'saas_dispatcher', 'public.saas_control_plane_outbox', 'UPDATE')"
            )
        )
        assert base_updates == allowed_p0s3_updates

        for event_id, event_type in (
            (ack_id, "migration.n1_ack"),
            (failure_id, "migration.n1_failure"),
        ):
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count) VALUES "
                    "(:id, NULL, 'migration', :aggregate_key, :event_type, '{}', "
                    ":idempotency_key, :request_hash, 0)"
                ),
                {
                    "id": event_id,
                    "aggregate_key": str(event_id),
                    "event_type": event_type,
                    "idempotency_key": f"n1-compat-{event_id}",
                    "request_hash": request_hash,
                },
            )
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox "
                "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, last_error_code, "
                "last_error_digest, quarantined_at) VALUES "
                "(:id, NULL, 'migration', :aggregate_key, 'migration.quarantined', '{}', "
                ":idempotency_key, :request_hash, 1, 'terminal_error', :error_digest, :now)"
            ),
            {
                "id": quarantined_id,
                "aggregate_key": str(quarantined_id),
                "idempotency_key": f"n1-compat-{quarantined_id}",
                "request_hash": "b" * 64,
                "error_digest": "c" * 64,
                "now": now,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_outbox_quarantine_events "
                "(id, source_event_id, tenant_id, source_request_hash, "
                "source_attempt_count, action, error_code, error_digest, sequence, "
                "previous_hash, event_hash, created_at) VALUES "
                "(:id, :source_event_id, NULL, :source_request_hash, 1, 'quarantined', "
                "'terminal_error', :error_digest, 1, :previous_hash, :event_hash, :now)"
            ),
            {
                "id": receipt_id,
                "source_event_id": quarantined_id,
                "source_request_hash": "b" * 64,
                "error_digest": "c" * 64,
                "previous_hash": "0" * 64,
                "event_hash": "d" * 64,
                "now": now,
            },
        )

        quoted_login = connection.dialect.identifier_preparer.quote(login_role)
        driver_connection = connection.connection.driver_connection
        assert driver_connection is not None
        with driver_connection.cursor() as cursor:
            cursor.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                ).format(sql.Identifier(login_role), sql.Literal(login_password))
            )
        connection.exec_driver_sql(
            f"GRANT saas_dispatcher_n1_compat TO {quoted_login} WITH INHERIT TRUE, SET FALSE"
        )
        try:
            connection.exec_driver_sql(f"SET SESSION AUTHORIZATION {quoted_login}")
            schema, search_path = connection.execute(
                sa.text("SELECT current_schema(), current_schemas(false)")
            ).one()
            assert schema == "public"
            assert list(search_path) == ["public"]
            facts = connection.execute(
                sa.text(
                    "SELECT current_user, session_user, role.rolsuper, "
                    "role.rolbypassrls, role.rolinherit, "
                    "pg_has_role(current_user, 'saas_dispatcher', 'member'), "
                    "pg_has_role(current_user, 'saas_platform', 'member'), "
                    "pg_has_role(current_user, 'saas_app', 'member'), "
                    "pg_has_role(current_user, 'saas_authenticator', 'member'), "
                    "pg_has_role(current_user, 'saas_governance', 'member'), "
                    "pg_has_role(current_user, 'saas_executor', 'member') "
                    "FROM pg_roles AS role WHERE role.rolname = current_user"
                )
            ).one()
            assert facts == (
                login_role,
                login_role,
                False,
                False,
                True,
                True,
                False,
                False,
                False,
                False,
                False,
            )
            owned_tables = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
                    "WHERE namespace.nspname = 'public' "
                    "AND relation.relkind IN ('r', 'p') "
                    "AND relation.relname LIKE 'saas_%' AND owner.rolname = current_user"
                )
            )
            forbidden_tables = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'public' "
                    "AND relation.relkind IN ('r', 'p') "
                    "AND relation.relname LIKE 'saas_%' "
                    "AND relation.relname <> 'saas_control_plane_outbox' AND ("
                    "has_table_privilege(current_user, relation.oid, 'SELECT') OR "
                    "has_table_privilege(current_user, relation.oid, 'INSERT') OR "
                    "has_table_privilege(current_user, relation.oid, 'UPDATE') OR "
                    "has_table_privilege(current_user, relation.oid, 'DELETE') OR "
                    "has_table_privilege(current_user, relation.oid, 'TRUNCATE') OR "
                    "has_table_privilege(current_user, relation.oid, 'REFERENCES') OR "
                    "has_table_privilege(current_user, relation.oid, 'TRIGGER'))"
                )
            )
            privileges = connection.execute(
                sa.text(
                    "SELECT "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'SELECT'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'UPDATE'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'INSERT'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'DELETE'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'TRUNCATE'), "
                    "has_table_privilege(current_user, "
                    "'public.saas_control_plane_outbox', 'TRIGGER')"
                )
            ).one()
            assert owned_tables == 0
            assert forbidden_tables == 0
            assert privileges == (False, False, False, False, False, False)

            visible_ids = set(
                connection.execute(sa.text("SELECT id FROM saas_control_plane_outbox")).scalars()
            )
            assert {ack_id, failure_id} <= visible_ids
            assert quarantined_id not in visible_ids

            with pytest.raises(sa.exc.DBAPIError), connection.begin_nested():
                connection.execute(
                    sa.text(
                        "UPDATE saas_control_plane_outbox SET payload = CAST(:payload AS json) "
                        "WHERE id = :id"
                    ),
                    {"id": failure_id, "payload": '{"tampered":true}'},
                )
            with pytest.raises(sa.exc.DBAPIError), connection.begin_nested():
                connection.execute(
                    sa.text(
                        "UPDATE saas_control_plane_outbox SET published_at = :now WHERE id = :id"
                    ),
                    {"id": failure_id, "now": now},
                )

            ack_token, failure_token = uuid4(), uuid4()
            for event_id, token in ((ack_id, ack_token), (failure_id, failure_token)):
                # Exact 9451a64 claim shape, including last_error=NULL.
                connection.execute(
                    sa.text(
                        "UPDATE saas_control_plane_outbox SET claimed_at = :now, "
                        "claim_token = :token, attempt_count = attempt_count + 1, "
                        "last_error = NULL WHERE id = :id AND published_at IS NULL"
                    ),
                    {"id": event_id, "now": now, "token": token},
                )

            # Exact 9451a64 acknowledgement shape.
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET published_at = :published_at, "
                    "claimed_at = NULL, claim_token = NULL, last_error = NULL "
                    "WHERE id = :id AND claim_token = :token AND published_at IS NULL"
                ),
                {
                    "id": ack_id,
                    "token": ack_token,
                    "published_at": now,
                },
            )
            # Exact 9451a64 failure/backoff shape. The raw text reaches the
            # compatibility trigger as an old-client bind value but never the
            # stored row or its digest material.
            retry_at = now.replace(second=2)
            connection.execute(
                sa.text(
                    "UPDATE saas_control_plane_outbox SET available_at = :retry_at, "
                    "claimed_at = NULL, claim_token = NULL, last_error = :raw_error "
                    "WHERE id = :id AND claim_token = :token AND published_at IS NULL"
                ),
                {
                    "id": failure_id,
                    "token": failure_token,
                    "retry_at": retry_at,
                    "raw_error": raw_error,
                },
            )
        finally:
            connection.exec_driver_sql("RESET SESSION AUTHORIZATION")

        # The fixed N-1 SELECT projection deliberately excludes p0s3-only
        # terminal metadata. Inspect it only after restoring the schema owner.
        ack = connection.execute(
            sa.text(
                "SELECT published_at, claimed_at, claim_token, last_error, "
                "last_error_code, last_error_digest "
                "FROM saas_control_plane_outbox WHERE id = :id"
            ),
            {"id": ack_id},
        ).one()
        assert ack.published_at == now
        assert ack.claimed_at is None
        assert ack.claim_token is None
        assert ack.last_error is None
        assert ack.last_error_code is None
        assert ack.last_error_digest is None

        failure = connection.execute(
            sa.text(
                "SELECT attempt_count, available_at, claimed_at, claim_token, "
                "last_error, last_error_code, last_error_digest, row_to_json(source)::text "
                "FROM saas_control_plane_outbox AS source WHERE id = :id"
            ),
            {"id": failure_id},
        ).one()
        expected_digest = sha256(
            (
                f"omnigent:n1-outbox:error:v1:{failure_id}:{request_hash}:{failure.attempt_count}"
            ).encode()
        ).hexdigest()
        assert failure.attempt_count == 1
        assert failure.available_at == retry_at
        assert failure.claimed_at is None
        assert failure.claim_token is None
        assert failure.last_error is None
        assert failure.last_error_code == "n1_compat_delivery_error"
        assert failure.last_error_digest == expected_digest
        assert raw_error not in failure[-1]
        assert failure.last_error_digest != sha256(raw_error.encode()).hexdigest()

    login_url = sa.engine.make_url(isolated_postgres_url).set(
        username=login_role,
        password=login_password,
    )
    login_engine = sa.create_engine(login_url, hide_parameters=True)
    try:
        with materialize_n1_compat(Path(__file__).resolve().parents[2]) as (
            patched_root,
            _,
        ):
            specification = importlib.util.spec_from_file_location(
                "n1_real_postgresql_patched_admission",
                patched_root / "saas/n1_outbox_compat_admission.py",
            )
            assert specification is not None and specification.loader is not None
            patched_admission = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(patched_admission)

            fingerprint = patched_admission.catalog_fingerprint(
                login_engine,
                expected_login=login_role,
            )
            assert len(fingerprint) == 64

            # Outbox DDL is a drain boundary. Even an additive column that the
            # fixed ACL does not expose must fail the pre-run catalog recheck.
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "ALTER TABLE saas_control_plane_outbox ADD COLUMN n1_test_future_column text"
                )
            try:
                with pytest.raises(RuntimeError) as schema_drift:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(schema_drift.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert schema_drift.value.__suppress_context__
                assert login_password not in str(schema_drift.value)
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_control_plane_outbox DROP COLUMN n1_test_future_column"
                    )

            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "GRANT SELECT ON saas_control_plane_outbox TO saas_dispatcher_n1_compat"
                )
            try:
                with pytest.raises(RuntimeError) as table_acl_drift:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(table_acl_drift.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert table_acl_drift.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        "REVOKE SELECT ON saas_control_plane_outbox FROM saas_dispatcher_n1_compat"
                    )
                    connection.exec_driver_sql(
                        "GRANT SELECT (id, published_at, available_at, claimed_at, "
                        "created_at, claim_token, event_type, aggregate_type, "
                        "aggregate_key, payload, attempt_count) "
                        "ON saas_control_plane_outbox TO saas_dispatcher_n1_compat"
                    )

            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "GRANT SELECT (tenant_id) ON saas_control_plane_outbox TO PUBLIC"
                )
            try:
                with pytest.raises(RuntimeError) as public_outbox_acl:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(public_outbox_acl.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert public_outbox_acl.value.__suppress_context__
                assert login_password not in str(public_outbox_acl.value)
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        "REVOKE SELECT (tenant_id) ON saas_control_plane_outbox FROM PUBLIC"
                    )

            with engine.begin() as connection:
                connection.exec_driver_sql("GRANT SELECT (id) ON saas_tenants TO PUBLIC")
            try:
                with pytest.raises(RuntimeError) as public_forbidden_acl:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(public_forbidden_acl.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert public_forbidden_acl.value.__suppress_context__
                assert login_password not in str(public_forbidden_acl.value)
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql("REVOKE SELECT (id) ON saas_tenants FROM PUBLIC")

            planning_rule = f"n1_planning_rule_{uuid4().hex[:12]}"
            quoted_planning_rule = engine.dialect.identifier_preparer.quote(planning_rule)
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    f"CREATE RULE {quoted_planning_rule} AS ON UPDATE "
                    "TO saas_platform_role_assignments DO ALSO NOTHING"
                )
            try:
                with pytest.raises(RuntimeError) as planning_rewrite:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(planning_rewrite.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert planning_rewrite.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        f"DROP RULE {quoted_planning_rule} ON saas_platform_role_assignments"
                    )

            security_schema = f"n1_secdef_schema_{uuid4().hex[:12]}"
            quoted_security_schema = engine.dialect.identifier_preparer.quote(security_schema)
            security_definer = f"n1_secdef_{uuid4().hex[:12]}"
            quoted_security_definer = engine.dialect.identifier_preparer.quote(security_definer)
            with engine.begin() as connection:
                connection.exec_driver_sql(f"CREATE SCHEMA {quoted_security_schema}")
                connection.exec_driver_sql(
                    f"GRANT USAGE ON SCHEMA {quoted_security_schema} TO PUBLIC"
                )
                connection.exec_driver_sql(
                    f"CREATE FUNCTION {quoted_security_schema}.{quoted_security_definer}() "
                    "RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'"
                )
            try:
                with pytest.raises(RuntimeError) as executable_secdef:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(executable_secdef.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert executable_secdef.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(f"DROP SCHEMA {quoted_security_schema} CASCADE")

            function_schema = f"n1_function_schema_{uuid4().hex[:12]}"
            quoted_function_schema = engine.dialect.identifier_preparer.quote(function_schema)
            probe_function = f"n1_function_{uuid4().hex[:12]}"
            quoted_probe_function = engine.dialect.identifier_preparer.quote(probe_function)
            with engine.begin() as connection:
                connection.exec_driver_sql(f"CREATE SCHEMA {quoted_function_schema}")
                connection.exec_driver_sql(
                    f"CREATE FUNCTION {quoted_function_schema}.{quoted_probe_function}() "
                    "RETURNS integer LANGUAGE sql AS 'SELECT 1'"
                )
                connection.exec_driver_sql(
                    f"REVOKE ALL ON FUNCTION "
                    f"{quoted_function_schema}.{quoted_probe_function}() FROM PUBLIC"
                )
                connection.exec_driver_sql(
                    f"GRANT EXECUTE ON FUNCTION "
                    f"{quoted_function_schema}.{quoted_probe_function}() "
                    "TO saas_dispatcher_n1_compat"
                )
            try:
                with pytest.raises(RuntimeError) as direct_function_acl:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(direct_function_acl.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert direct_function_acl.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(f"DROP SCHEMA {quoted_function_schema} CASCADE")

            probe_view = f"n1_view_{uuid4().hex[:12]}"
            quoted_probe_view = engine.dialect.identifier_preparer.quote(probe_view)
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    f"CREATE VIEW public.{quoted_probe_view} AS SELECT id FROM public.saas_tenants"
                )
                connection.exec_driver_sql(f"GRANT SELECT ON public.{quoted_probe_view} TO PUBLIC")
            try:
                with pytest.raises(RuntimeError) as public_view_acl:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(public_view_acl.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert public_view_acl.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(f"DROP VIEW public.{quoted_probe_view}")

            probe_sequence = f"n1_sequence_{uuid4().hex[:12]}"
            quoted_probe_sequence = engine.dialect.identifier_preparer.quote(probe_sequence)
            with engine.begin() as connection:
                connection.exec_driver_sql(f"CREATE SEQUENCE public.{quoted_probe_sequence}")
                connection.exec_driver_sql(
                    f"GRANT USAGE ON SEQUENCE public.{quoted_probe_sequence} TO PUBLIC"
                )
            try:
                with pytest.raises(RuntimeError) as public_sequence_acl:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(public_sequence_acl.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert public_sequence_acl.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(f"DROP SEQUENCE public.{quoted_probe_sequence}")

            external_schema = f"n1_external_{uuid4().hex[:12]}"
            quoted_external_schema = engine.dialect.identifier_preparer.quote(external_schema)
            with engine.begin() as connection:
                connection.exec_driver_sql(f"CREATE SCHEMA {quoted_external_schema}")
                connection.exec_driver_sql(
                    f"GRANT USAGE ON SCHEMA {quoted_external_schema} TO saas_dispatcher_n1_compat"
                )
            try:
                with pytest.raises(RuntimeError) as external_schema_acl:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(external_schema_acl.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert external_schema_acl.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(f"DROP SCHEMA {quoted_external_schema} CASCADE")

            owned_schema = f"n1_owned_{uuid4().hex[:12]}"
            quoted_owned_schema = engine.dialect.identifier_preparer.quote(owned_schema)
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    f"CREATE SCHEMA {quoted_owned_schema} AUTHORIZATION saas_dispatcher_n1_compat"
                )
            try:
                with pytest.raises(RuntimeError) as external_schema_ownership:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(external_schema_ownership.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert external_schema_ownership.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(f"DROP SCHEMA {quoted_owned_schema} CASCADE")

            with engine.connect() as connection:
                database_name = str(connection.scalar(sa.text("SELECT current_database()")))
            quoted_database = engine.dialect.identifier_preparer.quote(database_name)
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    f"GRANT TEMPORARY ON DATABASE {quoted_database} TO saas_dispatcher_n1_compat"
                )
            try:
                with pytest.raises(RuntimeError) as direct_temp:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(direct_temp.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert direct_temp.value.__suppress_context__
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        f"REVOKE TEMPORARY ON DATABASE {quoted_database} "
                        "FROM saas_dispatcher_n1_compat"
                    )

            with engine.begin() as connection:
                connection.exec_driver_sql(
                    f"GRANT TEMPORARY ON DATABASE {quoted_database} TO PUBLIC"
                )
            try:
                with login_engine.begin() as connection:
                    connection.exec_driver_sql(
                        "CREATE TEMP TABLE saas_control_plane_outbox (id uuid)"
                    )
                    assert (
                        connection.scalar(
                            sa.text("SELECT to_regclass('pg_temp.saas_control_plane_outbox')")
                        )
                        is not None
                    )
                with pytest.raises(RuntimeError) as temp_shadow:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(temp_shadow.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert temp_shadow.value.__suppress_context__
            finally:
                login_engine.dispose()
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        f"REVOKE TEMPORARY ON DATABASE {quoted_database} FROM PUBLIC"
                    )

            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "ALTER TABLE saas_control_plane_outbox "
                    "DISABLE TRIGGER trg_outbox_n1_compatibility"
                )
            try:
                with pytest.raises(RuntimeError) as disabled_trigger:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(disabled_trigger.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert disabled_trigger.value.__suppress_context__
                assert login_password not in str(disabled_trigger.value)
                assert raw_error not in str(disabled_trigger.value)
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_control_plane_outbox "
                        "ENABLE TRIGGER trg_outbox_n1_compatibility"
                    )

            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "CREATE POLICY n1_test_permissive_planning_leak "
                    "ON saas_platform_role_assignments AS PERMISSIVE FOR SELECT "
                    "TO saas_dispatcher_n1_compat USING (true)"
                )
            try:
                with login_engine.connect() as connection:
                    assert (
                        connection.scalar(
                            sa.text(
                                "SELECT count(principal_id) FROM saas_platform_role_assignments"
                            )
                        )
                        == 0
                    )
                with pytest.raises(RuntimeError) as policy_drift:
                    patched_admission.catalog_fingerprint(
                        login_engine,
                        expected_login=login_role,
                    )
                assert str(policy_drift.value) == (
                    "N-1 Outbox compatibility catalog admission rejected"
                )
                assert policy_drift.value.__suppress_context__
                assert login_password not in str(policy_drift.value)
            finally:
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        "DROP POLICY n1_test_permissive_planning_leak "
                        "ON saas_platform_role_assignments"
                    )

            assert (
                patched_admission.catalog_fingerprint(
                    login_engine,
                    expected_login=login_role,
                )
                == fingerprint
            )
    finally:
        login_engine.dispose()
        with engine.begin() as connection:
            quoted_login = connection.dialect.identifier_preparer.quote(login_role)
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_login}")
        engine.dispose()


def test_real_postgresql_p0s3_rejects_preexisting_n1_compat_member(
    isolated_postgres_url: str,
) -> None:
    engine = sa.create_engine(isolated_postgres_url)
    incoming_role = f"n1_outbox_incoming_{uuid4().hex[:12]}"
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), "p0s000000002")
        connection.exec_driver_sql(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles "
            "WHERE rolname = 'saas_dispatcher_n1_compat') THEN "
            "CREATE ROLE saas_dispatcher_n1_compat NOLOGIN NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT; END IF; END $$"
        )
        quoted_incoming = connection.dialect.identifier_preparer.quote(incoming_role)
        connection.exec_driver_sql(
            f"CREATE ROLE {quoted_incoming} NOLOGIN INHERIT NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
        )
        connection.exec_driver_sql(f"GRANT saas_dispatcher_n1_compat TO {quoted_incoming}")

    migration_connection = engine.connect()
    migration_transaction = migration_connection.begin()
    try:
        with pytest.raises(RuntimeError, match="incoming/outgoing membership"):
            command.upgrade(
                _migration_config(migration_connection),
                "p0s000000003",
            )
    finally:
        migration_transaction.rollback()
        migration_connection.close()

    try:
        with engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == "p0s000000002"
            )
            columns = {
                str(column)
                for column in connection.execute(
                    sa.text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' "
                        "AND table_name = 'saas_control_plane_outbox'"
                    )
                ).scalars()
            }
            assert {"last_error_code", "last_error_digest", "quarantined_at"}.isdisjoint(columns)
    finally:
        with engine.begin() as connection:
            quoted_incoming = connection.dialect.identifier_preparer.quote(incoming_role)
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_incoming}")
        engine.dispose()


def test_real_postgresql_outbox_downgrade_nonbypass_owner_sees_evidence(
    isolated_postgres_url: str,
) -> None:
    engine = sa.create_engine(isolated_postgres_url)
    source_event_id, receipt_id = uuid4(), uuid4()
    now = datetime(2026, 8, 25, 2, 0, tzinfo=timezone.utc)
    probe_role = f"p0s3_owner_{uuid4().hex[:12]}"
    admin_role = ""
    role_created = False
    ownership_transferred = False

    try:
        with engine.begin() as connection:
            command.upgrade(_migration_config(connection), "p0s000000003")
            admin_role = str(connection.scalar(sa.text("SELECT current_user")))
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, last_error_code, "
                    "last_error_digest, quarantined_at) VALUES "
                    "(:id, NULL, 'migration', :aggregate_key, 'migration.owner_probe', "
                    "'{}', :idempotency_key, :request_hash, 1, "
                    "'owner_visibility_probe', :error_digest, :now)"
                ),
                {
                    "id": source_event_id,
                    "aggregate_key": str(source_event_id),
                    "idempotency_key": f"migration-owner-probe-{source_event_id}",
                    "request_hash": "a" * 64,
                    "error_digest": "b" * 64,
                    "now": now,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_outbox_quarantine_events "
                    "(id, source_event_id, tenant_id, source_request_hash, "
                    "source_attempt_count, action, error_code, error_digest, sequence, "
                    "previous_hash, event_hash, created_at) VALUES "
                    "(:id, :source_event_id, NULL, :source_hash, 1, 'quarantined', "
                    "'owner_visibility_probe', :error_digest, 1, :previous_hash, "
                    ":event_hash, :now)"
                ),
                {
                    "id": receipt_id,
                    "source_event_id": source_event_id,
                    "source_hash": "a" * 64,
                    "error_digest": "b" * 64,
                    "previous_hash": "0" * 64,
                    "event_hash": "c" * 64,
                    "now": now,
                },
            )

        # Commit the exact Receipt pair first so the deferred constraint
        # trigger has fired before ALTER OWNER acquires its DDL lock.
        with engine.begin() as connection:
            quoted_probe = connection.dialect.identifier_preparer.quote(probe_role)
            quoted_admin = connection.dialect.identifier_preparer.quote(admin_role)
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_probe} NOLOGIN NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            )
            connection.exec_driver_sql(f"GRANT {quoted_probe} TO {quoted_admin}")
            connection.exec_driver_sql(
                f"ALTER TABLE public.saas_control_plane_outbox OWNER TO {quoted_probe}"
            )
            connection.exec_driver_sql(
                f"ALTER TABLE public.saas_outbox_quarantine_events OWNER TO {quoted_probe}"
            )
            connection.exec_driver_sql(
                f"GRANT SELECT ON public.saas_alembic_version TO {quoted_probe}"
            )
            # PC3's pre-existing Outbox SELECT policy contains content-blind
            # Staff-assignment/support-session subqueries.  PostgreSQL checks
            # their table privileges even though this probe has no Staff role.
            connection.exec_driver_sql(
                "GRANT SELECT (principal_id, role, status, expires_at) "
                "ON public.saas_platform_role_assignments TO "
                f"{quoted_probe}"
            )
            connection.exec_driver_sql(
                "GRANT SELECT (principal_id, token_hash, revoked_at, expires_at) "
                "ON public.saas_platform_support_sessions TO "
                f"{quoted_probe}"
            )
        role_created = True
        ownership_transferred = True

        migration_connection = engine.connect()
        migration_transaction = migration_connection.begin()
        try:
            quoted_probe = migration_connection.dialect.identifier_preparer.quote(probe_role)
            migration_connection.exec_driver_sql(f"SET LOCAL ROLE {quoted_probe}")
            # FORCE RLS hides both evidence rows even from their non-bypass
            # table owner before the migration deliberately relaxes it.
            assert (
                migration_connection.scalar(
                    sa.text("SELECT count(*) FROM saas_control_plane_outbox")
                )
                == 0
            )
            assert (
                migration_connection.scalar(
                    sa.text("SELECT count(*) FROM saas_outbox_quarantine_events")
                )
                == 0
            )
            with pytest.raises(
                RuntimeError,
                match="durable Outbox delivery evidence",
            ):
                command.downgrade(
                    _migration_config(migration_connection),
                    "p0s000000002",
                )
        finally:
            # The caller owns this transaction.  Explicit rollback is the
            # assertion boundary that restores both temporary NO FORCE DDLs.
            migration_transaction.rollback()
            migration_connection.close()

        with engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == "p0s000000003"
            )
            force_rows = connection.execute(
                sa.text(
                    "SELECT relname, relforcerowsecurity FROM pg_class "
                    "WHERE oid IN ('public.saas_control_plane_outbox'::regclass, "
                    "'public.saas_outbox_quarantine_events'::regclass)"
                )
            ).all()
            assert {str(row.relname): bool(row.relforcerowsecurity) for row in force_rows} == {
                "saas_control_plane_outbox": True,
                "saas_outbox_quarantine_events": True,
            }
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_outbox_quarantine_events"))
                == 1
            )
    finally:
        if role_created:
            with engine.begin() as connection:
                quoted_probe = connection.dialect.identifier_preparer.quote(probe_role)
                quoted_admin = connection.dialect.identifier_preparer.quote(admin_role)
                if ownership_transferred:
                    connection.exec_driver_sql(
                        f"ALTER TABLE public.saas_control_plane_outbox OWNER TO {quoted_admin}"
                    )
                    connection.exec_driver_sql(
                        f"ALTER TABLE public.saas_outbox_quarantine_events OWNER TO {quoted_admin}"
                    )
                connection.exec_driver_sql(f"DROP OWNED BY {quoted_probe}")
                connection.exec_driver_sql(f"REVOKE {quoted_probe} FROM {quoted_admin}")
                connection.exec_driver_sql(f"DROP ROLE {quoted_probe}")
        engine.dispose()


@pytest.mark.parametrize(
    ("legacy_status", "runtime_ready", "activated", "expected_cursor"),
    (
        ("billing_ready", False, False, "billing"),
        ("runtime_ready", True, False, "runtime"),
        ("active", True, True, "project"),
    ),
)
def test_onboarding_vertical_migration_backfills_ids_snapshot_and_pending_intent(
    legacy_status: str,
    runtime_ready: bool,
    activated: bool,
    expected_cursor: str,
) -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000001")
        now = datetime(2026, 8, 24, 3, 0, tzinfo=timezone.utc)
        identifiers = {
            name: uuid4()
            for name in (
                "registration_id",
                "onboarding_id",
                "user_id",
                "tenant_id",
                "space_id",
                "subscription_id",
                "runtime_partition_id",
                "outbox_id",
            )
        }
        values = {name: str(value) for name, value in identifiers.items()}
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:user_id, 'active', 1)"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, lifecycle_version) "
                "VALUES (:tenant_id, 'legacy-vertical', 'Legacy Vertical', "
                "'provisioning', 'starter', 'cn-east-1', 1)"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) "
                "VALUES (:space_id, :tenant_id, 'default', 'Default', 'suspended')"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_self_service_registrations "
                "(id, email_normalized, email_hash, tenant_name, tenant_slug, "
                "default_space_name, default_space_slug, plan_key, plan_policy_revision, "
                "home_region, status, challenge_generation, expires_at, verified_at, "
                "terminal_at, user_id, tenant_id, space_id, subscription_id, "
                "runtime_partition_id, onboarding_id, idempotency_key, request_hash, "
                "version, created_at, updated_at) VALUES "
                "(:registration_id, 'legacy@example.test', :email_hash, 'Legacy Vertical', "
                "'legacy-vertical', 'Default', 'default', 'starter', 'starter-v1', "
                "'cn-east-1', 'verified', 1, :expires_at, :now, :now, :user_id, "
                ":tenant_id, :space_id, :subscription_id, :runtime_partition_id, "
                ":onboarding_id, :idempotency_key, :request_hash, 2, :now, :now)"
            ),
            {
                **values,
                "email_hash": "a" * 64,
                "idempotency_key": "b" * 64,
                "request_hash": "c" * 64,
                "now": now,
                "expires_at": now.replace(day=25),
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_onboardings "
                "(id, registration_id, user_id, tenant_id, space_id, subscription_id, "
                "runtime_partition_id, plan_key, plan_policy_revision, home_region, "
                "trial_days, trial_started_at, trial_ends_at, status, idempotency_key, "
                "request_hash, version, attempt_count, available_at, billing_ready_at, "
                "runtime_ready_at, activated_at, last_transition_at, created_at, updated_at) "
                "VALUES "
                "(:onboarding_id, :registration_id, :user_id, :tenant_id, :space_id, "
                ":subscription_id, :runtime_partition_id, 'starter', 'starter-v1', "
                "'cn-east-1', 14, :now, :trial_ends_at, :legacy_status, "
                ":saga_key, :saga_hash, 2, 1, :now, :now, :runtime_ready_at, "
                ":activated_at, :now, :now, :now)"
            ),
            {
                **values,
                "now": now,
                "trial_ends_at": now.replace(day=31),
                "saga_key": "d" * 64,
                "saga_hash": "e" * 64,
                "legacy_status": legacy_status,
                "runtime_ready_at": now if runtime_ready else None,
                "activated_at": now if activated else None,
            },
        )
        old_payload = {
            "onboarding_id": str(identifiers["onboarding_id"]),
            "registration_id": str(identifiers["registration_id"]),
            "tenant_id": str(identifiers["tenant_id"]),
            "plan_policy_revision": "starter-v1",
        }
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox "
                "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, available_at) VALUES "
                "(:outbox_id, :tenant_id, 'tenant_onboarding', :onboarding_key, "
                "'onboarding.billing.requested', :payload, 'legacy-billing-intent', "
                ":outbox_hash, 0, :now)"
            ),
            {
                **values,
                "onboarding_key": str(identifiers["onboarding_id"]),
                "payload": json.dumps(old_payload),
                "outbox_hash": "f" * 64,
                "now": now,
            },
        )

        command.upgrade(config, "p0s000000002")
        registration = connection.execute(
            sa.text(
                "SELECT default_project_id, pricing_snapshot_id, entitlement_id, "
                "runtime_binding_id, plan_snapshot, plan_snapshot_hash "
                "FROM saas_self_service_registrations WHERE id = :registration_id"
            ),
            values,
        ).one()
        saga = connection.execute(
            sa.text(
                "SELECT default_project_id, pricing_snapshot_id, entitlement_id, "
                "runtime_binding_id, plan_snapshot, plan_snapshot_hash, "
                "status, failure_stage, compensation_cursor, runtime_placement_id, "
                "runtime_target_snapshot, runtime_request_hash, trial_started_at, "
                "trial_ends_at, activated_at FROM saas_tenant_onboardings "
                "WHERE id = :onboarding_id"
            ),
            values,
        ).one()
        snapshot = {
            "schema_version": 1,
            "key": "starter",
            "policy_revision": "starter-v1",
            "trial_days": 14,
            "currency": "USD",
            "trial_run_limit": 100,
            "trial_concurrency_limit": 2,
            "runtime_type": "omnigent",
            "capacity_class": "starter",
            "default_project_name": "Getting Started",
            "default_project_visibility": "private",
            "quota_resource": "interactive_runs",
            "quota_limit": 100,
        }
        canonical_snapshot = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        assert tuple(UUID(str(value)) for value in registration[:4]) == tuple(
            UUID(str(value)) for value in saga[:4]
        )
        assert json.loads(registration.plan_snapshot) == snapshot
        assert json.loads(saga.plan_snapshot) == snapshot
        assert (
            registration.plan_snapshot_hash
            == sha256(canonical_snapshot.encode("utf-8")).hexdigest()
        )
        assert saga.plan_snapshot_hash == registration.plan_snapshot_hash
        assert saga.status == "manual_review"
        assert saga.failure_stage == f"legacy_{legacy_status}"
        assert saga.compensation_cursor == expected_cursor
        assert saga.runtime_placement_id is None
        assert saga.runtime_target_snapshot is None
        assert saga.runtime_request_hash is None
        assert saga.trial_started_at is not None
        assert saga.trial_ends_at > saga.trial_started_at
        assert (saga.activated_at is not None) is activated
        with pytest.raises(sa.exc.IntegrityError):
            with connection.begin_nested():
                connection.execute(
                    sa.text(
                        "UPDATE saas_tenant_onboardings "
                        "SET runtime_target_snapshot = '{}' WHERE id = :onboarding_id"
                    ),
                    values,
                )
        with pytest.raises(sa.exc.IntegrityError):
            with connection.begin_nested():
                connection.execute(
                    sa.text(
                        "UPDATE saas_tenant_onboardings "
                        "SET compensation_cursor = 'unbounded' WHERE id = :onboarding_id"
                    ),
                    values,
                )

        outbox = connection.execute(
            sa.text(
                "SELECT payload, request_hash FROM saas_control_plane_outbox WHERE id = :outbox_id"
            ),
            values,
        ).one()
        payload = json.loads(outbox.payload)
        assert payload == {
            **old_payload,
            "user_id": str(identifiers["user_id"]),
            "space_id": str(identifiers["space_id"]),
            "default_project_id": str(UUID(str(saga.default_project_id))),
            "expected_status": "tenant_created",
            "version": 2,
        }
        assert (
            outbox.request_hash
            == sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        )

        command.downgrade(config, "p0s000000001")
        registration_columns = {
            column["name"]
            for column in sa.inspect(connection).get_columns("saas_self_service_registrations")
        }
        assert "default_project_id" not in registration_columns
        legacy_saga = connection.execute(
            sa.text(
                "SELECT status, trial_started_at, trial_ends_at, activated_at "
                "FROM saas_tenant_onboardings WHERE id = :onboarding_id"
            ),
            values,
        ).one()
        assert legacy_saga.status == legacy_status
        assert legacy_saga.trial_started_at is not None
        assert legacy_saga.trial_ends_at > legacy_saga.trial_started_at
        assert (legacy_saga.activated_at is not None) is activated
    engine.dispose()


@pytest.mark.parametrize(
    ("legacy_status", "published_old_billing", "expected_event"),
    (
        ("tenant_created", True, "onboarding.billing.requested"),
        ("compensating", False, "onboarding.compensation.requested"),
    ),
)
def test_onboarding_vertical_migration_ensures_nonterminal_recovery_wake(
    legacy_status: str,
    published_old_billing: bool,
    expected_event: str,
) -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p0s000000001")
        now = datetime(2026, 8, 24, 5, 0, tzinfo=timezone.utc)
        identifiers = {
            name: uuid4()
            for name in (
                "registration_id",
                "onboarding_id",
                "user_id",
                "tenant_id",
                "space_id",
                "subscription_id",
                "runtime_partition_id",
                "old_outbox_id",
                "duplicate_outbox_a",
                "duplicate_outbox_b",
            )
        }
        values = {name: str(value) for name, value in identifiers.items()}
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:user_id, 'active', 1)"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, lifecycle_version) "
                "VALUES (:tenant_id, :tenant_slug, 'Recovery Wake', "
                "'provisioning', 'starter', 'cn-east-1', 1)"
            ),
            {**values, "tenant_slug": f"recovery-{legacy_status}"},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) "
                "VALUES (:space_id, :tenant_id, 'default', 'Default', 'suspended')"
            ),
            values,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_self_service_registrations "
                "(id, email_normalized, email_hash, tenant_name, tenant_slug, "
                "default_space_name, default_space_slug, plan_key, plan_policy_revision, "
                "home_region, status, challenge_generation, expires_at, verified_at, "
                "terminal_at, user_id, tenant_id, space_id, subscription_id, "
                "runtime_partition_id, onboarding_id, idempotency_key, request_hash, "
                "version, created_at, updated_at) VALUES "
                "(:registration_id, :email, :email_hash, 'Recovery Wake', :tenant_slug, "
                "'Default', 'default', 'starter', 'starter-v1', 'cn-east-1', 'verified', "
                "1, :expires_at, :now, :now, :user_id, :tenant_id, :space_id, "
                ":subscription_id, :runtime_partition_id, :onboarding_id, "
                ":registration_key, :registration_hash, 2, :now, :now)"
            ),
            {
                **values,
                "email": f"{legacy_status}@example.test",
                "email_hash": sha256(legacy_status.encode()).hexdigest(),
                "tenant_slug": f"recovery-{legacy_status}",
                "registration_key": sha256(f"key:{legacy_status}".encode()).hexdigest(),
                "registration_hash": sha256(f"hash:{legacy_status}".encode()).hexdigest(),
                "now": now,
                "expires_at": now.replace(day=25),
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_onboardings "
                "(id, registration_id, user_id, tenant_id, space_id, subscription_id, "
                "runtime_partition_id, plan_key, plan_policy_revision, home_region, "
                "trial_days, status, idempotency_key, request_hash, version, attempt_count, "
                "available_at, last_transition_at, created_at, updated_at) VALUES "
                "(:onboarding_id, :registration_id, :user_id, :tenant_id, :space_id, "
                ":subscription_id, :runtime_partition_id, 'starter', 'starter-v1', "
                "'cn-east-1', 14, :legacy_status, :saga_key, :saga_hash, 2, 0, "
                ":now, :now, :now, :now)"
            ),
            {
                **values,
                "legacy_status": legacy_status,
                "saga_key": sha256(f"saga:{legacy_status}".encode()).hexdigest(),
                "saga_hash": sha256(f"request:{legacy_status}".encode()).hexdigest(),
                "now": now,
            },
        )
        if published_old_billing:
            old_payload = {
                "onboarding_id": str(identifiers["onboarding_id"]),
                "registration_id": str(identifiers["registration_id"]),
                "tenant_id": str(identifiers["tenant_id"]),
            }
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, available_at, published_at) "
                    "VALUES (:old_outbox_id, :tenant_id, 'tenant_onboarding', "
                    ":onboarding_key, 'onboarding.billing.requested', :payload, "
                    ":old_key, :old_hash, 1, :now, :now)"
                ),
                {
                    **values,
                    "onboarding_key": str(identifiers["onboarding_id"]),
                    "payload": json.dumps(old_payload),
                    "old_key": sha256(b"published-old-billing").hexdigest(),
                    "old_hash": sha256(
                        json.dumps(old_payload, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                    "now": now,
                },
            )
            for duplicate_name in ("duplicate_outbox_a", "duplicate_outbox_b"):
                duplicate_payload = {
                    **old_payload,
                    "legacy_duplicate": duplicate_name,
                }
                connection.execute(
                    sa.text(
                        "INSERT INTO saas_control_plane_outbox "
                        "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                        "idempotency_key, request_hash, attempt_count, available_at) "
                        "VALUES (:duplicate_id, :tenant_id, 'tenant_onboarding', "
                        ":onboarding_key, 'onboarding.billing.requested', :payload, "
                        ":duplicate_key, :duplicate_hash, 3, :now)"
                    ),
                    {
                        **values,
                        # ORM writes use compact UUID hex on SQLite, while raw
                        # legacy fixtures may contain the dashed form.
                        "duplicate_id": identifiers[duplicate_name].hex,
                        "onboarding_key": str(identifiers["onboarding_id"]),
                        "payload": json.dumps(duplicate_payload),
                        "duplicate_key": sha256(duplicate_name.encode()).hexdigest(),
                        "duplicate_hash": sha256(
                            json.dumps(
                                duplicate_payload, sort_keys=True, separators=(",", ":")
                            ).encode()
                        ).hexdigest(),
                        "now": now,
                    },
                )

        command.upgrade(config, "p0s000000002")

        saga = connection.execute(
            sa.text(
                "SELECT status, version, default_project_id, failure_stage, "
                "compensation_cursor FROM saas_tenant_onboardings "
                "WHERE id = :onboarding_id"
            ),
            values,
        ).one()
        assert saga.status == legacy_status
        if legacy_status == "compensating":
            assert saga.failure_stage == "tenant_created"
            assert saga.compensation_cursor == "billing"
        wakes = connection.execute(
            sa.text(
                "SELECT payload, request_hash, idempotency_key, claimed_at, claim_token, "
                "last_error FROM saas_control_plane_outbox "
                "WHERE aggregate_type = 'tenant_onboarding' "
                "AND aggregate_key = :onboarding_key AND event_type = :expected_event "
                "AND published_at IS NULL"
            ),
            {
                "onboarding_key": str(identifiers["onboarding_id"]),
                "expected_event": expected_event,
            },
        ).all()
        assert len(wakes) == 1
        wake = wakes[0]
        payload = json.loads(wake.payload)
        assert payload == {
            "onboarding_id": str(identifiers["onboarding_id"]),
            "registration_id": str(identifiers["registration_id"]),
            "user_id": str(identifiers["user_id"]),
            "tenant_id": str(identifiers["tenant_id"]),
            "space_id": str(identifiers["space_id"]),
            "default_project_id": str(UUID(str(saga.default_project_id))),
            "expected_status": legacy_status,
            "version": saga.version,
        }
        assert (
            wake.request_hash
            == sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        assert (
            wake.idempotency_key
            == sha256(
                (
                    f"p0s000000002:{identifiers['onboarding_id']}:{expected_event}:{saga.version}"
                ).encode()
            ).hexdigest()
        )
        assert wake.claimed_at is None
        assert wake.claim_token is None
        assert wake.last_error is None
        if published_old_billing:
            assert (
                connection.execute(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE id = :old_outbox_id AND published_at IS NOT NULL"
                    ),
                    values,
                ).scalar_one()
                == 1
            )

        command.downgrade(config, "p0s000000001")
    engine.dispose()


def test_enterprise_lifecycle_migration_backfills_legacy_terminal_states() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "p6a000000002")

        metadata = sa.MetaData()
        metadata.reflect(
            bind=connection,
            only=(
                "saas_global_users",
                "saas_tenants",
                "saas_spaces",
                "saas_projects",
                "saas_enterprise_groups",
                "saas_enterprise_custom_roles",
            ),
        )
        user_id = uuid4()
        tenant_id = uuid4()
        space_id = uuid4()
        project_id = uuid4()
        group_id = uuid4()
        role_id = uuid4()
        legacy_time = datetime(2026, 8, 4, 12, tzinfo=timezone.utc)
        connection.execute(
            metadata.tables["saas_global_users"].insert(),
            {
                "id": user_id.hex,
                "status": "active",
                "security_version": 1,
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_tenants"].insert(),
            {
                "id": tenant_id.hex,
                "slug": "legacy-lifecycle",
                "name": "Legacy Lifecycle",
                "status": "active",
                "plan": "enterprise",
                "home_region": "cn-east-1",
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_spaces"].insert(),
            {
                "id": space_id.hex,
                "tenant_id": tenant_id.hex,
                "slug": "legacy-space",
                "name": "Legacy Space",
                "status": "active",
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_projects"].insert(),
            {
                "id": project_id.hex,
                "tenant_id": tenant_id.hex,
                "space_id": space_id.hex,
                "name": "Legacy Project",
                "visibility": "restricted",
                "created_by": user_id.hex,
                "status": "active",
                "authorization_version": 1,
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_enterprise_groups"].insert(),
            {
                "id": group_id.hex,
                "tenant_id": tenant_id.hex,
                "name": "Legacy Archived Group",
                "status": "archived",
                "version": 2,
                "created_by": user_id.hex,
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )
        connection.execute(
            metadata.tables["saas_enterprise_custom_roles"].insert(),
            {
                "id": role_id.hex,
                "tenant_id": tenant_id.hex,
                "space_id": space_id.hex,
                "project_id": project_id.hex,
                "name": "Legacy Retired Role",
                "permissions": ["project.read_metadata"],
                "status": "retired",
                "version": 2,
                "created_by": user_id.hex,
                "created_at": legacy_time,
                "updated_at": legacy_time,
            },
        )

        command.upgrade(config, "head")
        group = connection.execute(
            sa.text(
                "SELECT archived_at, archived_by, archive_reason "
                "FROM saas_enterprise_groups WHERE id = :id"
            ),
            {"id": group_id.hex},
        ).one()
        role = connection.execute(
            sa.text(
                "SELECT retired_at, retired_by, retire_reason "
                "FROM saas_enterprise_custom_roles WHERE id = :id"
            ),
            {"id": role_id.hex},
        ).one()

        assert group.archived_at is not None
        assert group.archived_by == user_id.hex
        assert group.archive_reason == "legacy-state-backfill:p6a000000003"
        assert role.retired_at is not None
        assert role.retired_by == user_id.hex
        assert role.retire_reason == "legacy-state-backfill:p6a000000003"
    engine.dispose()


def test_scim_schema_extension_migration_defaults_and_refuses_lossy_downgrade() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "head")
        inspector = sa.inspect(connection)
        assert {"provider_type", "attribute_mapping"} <= {
            column["name"] for column in inspector.get_columns("saas_enterprise_scim_directories")
        }
        assert {"core_attributes", "enterprise_attributes"} <= {
            column["name"] for column in inspector.get_columns("saas_enterprise_scim_users")
        }

        now = datetime(2026, 8, 10, 8, tzinfo=timezone.utc)
        user_id, tenant_id, directory_id = uuid4(), uuid4(), uuid4()
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users "
                "(id, status, security_version, created_at, updated_at) "
                "VALUES (:id, 'active', 1, :now, :now)"
            ),
            {"id": user_id.hex, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, created_at, updated_at) "
                "VALUES (:id, 'scim-migration', 'SCIM Migration', 'active', "
                "'enterprise', 'cn-east-1', :now, :now)"
            ),
            {"id": tenant_id.hex, "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_enterprise_scim_directories "
                "(id, tenant_id, display_name, provider_type, attribute_mapping, "
                "token_hash, token_prefix, status, version, configured_by, "
                "created_at, updated_at) "
                "VALUES (:id, :tenant_id, 'Migration IdP', 'okta', :mapping, :token_hash, "
                "'omniscim_migration', 'active', 1, :configured_by, :now, :now)"
            ),
            {
                "id": directory_id.hex,
                "tenant_id": tenant_id.hex,
                "mapping": (
                    '{"department":"urn:ietf:params:scim:schemas:extension:'
                    'enterprise:2.0:User:department"}'
                ),
                "token_hash": "a" * 64,
                "configured_by": user_id.hex,
                "now": now,
            },
        )

        with pytest.raises(RuntimeError, match="cannot downgrade SCIM schema extensions"):
            command.downgrade(config, "pc6a00000001")

        connection.execute(
            sa.text("DELETE FROM saas_enterprise_scim_directories WHERE id = :id"),
            {"id": directory_id.hex},
        )
        command.downgrade(config, "pc6a00000001")
        downgraded = sa.inspect(connection)
        assert "provider_type" not in {
            column["name"] for column in downgraded.get_columns("saas_enterprise_scim_directories")
        }
    engine.dispose()
