from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from psycopg import sql

from saas.n1_outbox_admission import (
    admit_n1_outbox_compatibility_login,
    verify_n1_outbox_compatibility_schema_login,
)

_REJECTION = "N-1 Outbox compatibility login admission rejected"


def _migration_config(connection: sa.Connection) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option(
        "script_location",
        str(root / "saas/control_plane/migrations"),
    )
    config.attributes["connection"] = connection
    return config


def _roles_source() -> str:
    root = Path(__file__).resolve().parents[2]
    return (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")


def _principals_source() -> str:
    root = Path(__file__).resolve().parents[2]
    return (root / "saas/control_plane/postgresql_principals.sql").read_text(encoding="utf-8")


def _assert_secret_free_rejection(
    engine: sa.Engine,
    *,
    expected_login: str,
    forbidden_values: tuple[str, ...],
) -> None:
    with pytest.raises(RuntimeError) as rejected:
        verify_n1_outbox_compatibility_schema_login(engine, expected_login=expected_login)
    assert str(rejected.value) == _REJECTION
    assert rejected.value.__suppress_context__
    assert all(value not in str(rejected.value) for value in forbidden_values)


def _assert_production_admission_blocked(
    engine: sa.Engine,
    *,
    expected_login: str,
    forbidden_values: tuple[str, ...],
) -> None:
    with pytest.raises(RuntimeError) as rejected:
        admit_n1_outbox_compatibility_login(engine, expected_login=expected_login)
    assert str(rejected.value) == _REJECTION
    assert rejected.value.__suppress_context__
    assert all(value not in str(rejected.value) for value in forbidden_values)


def _assert_roles_replay_rejected(engine: sa.Engine) -> None:
    connection = engine.connect()
    transaction = connection.begin()
    try:
        with pytest.raises(sa.exc.DBAPIError, match=_REJECTION):
            connection.exec_driver_sql(_roles_source())
    finally:
        transaction.rollback()
        connection.close()


def test_n1_roles_bootstrap_keeps_production_enable_fail_closed() -> None:
    principals_source = _principals_source()
    source = _roles_source()
    preflight = principals_source.index(
        "control-plane principal bootstrap rejected: N-1 compatibility principal "
        "has an incoming member"
    )
    first_role_mutation = principals_source.index("EXECUTE 'CREATE ROLE '")

    assert preflight < first_role_mutation
    assert "CREATE ROLE" not in source
    assert "ALTER ROLE" not in source
    assert "DROP ROLE" not in source
    assert "incoming_login_memberships" in source
    assert "FROM pg_auth_members WHERE roleid = incoming_oid" in source
    assert "A later patched worker may be enabled only" in source
    assert "to_regprocedure('public.saas_bridge_n1_outbox_update()')" in source
    assert "06622ed237a21880bf84846f082deb876c3935597cd692f283d6f505cb616e3a" in source
    assert "AND (tgtype & 19) = 19" in source
    assert "saas_platform_role_assignments" in source
    assert "saas_platform_support_sessions" in source
    assert "rls_n1_compat_role_assignments_deny" in source
    assert "rls_n1_compat_support_sessions_deny" in source
    assert "AS RESTRICTIVE FOR SELECT" in source
    assert "USING (false)" in source
    assert "FROM pg_rewrite" in source
    public_execute_revoke = source.index(
        "REVOKE EXECUTE ON FUNCTION public.saas_bridge_n1_outbox_update() FROM PUBLIC"
    )
    guard_verification = source.index(
        "p0s3 N-1 Outbox compatibility guards are absent or disabled"
    )
    assert public_execute_revoke < guard_verification
    compat_grants = source[
        source.index("REVOKE ALL ON SCHEMA public FROM saas_dispatcher_n1_compat") :
    ]
    assert "GRANT SELECT, UPDATE ON saas_control_plane_outbox" not in compat_grants
    assert "id, published_at, available_at, claimed_at, created_at, claim_token" in compat_grants
    assert (
        "attempt_count, available_at, claimed_at, claim_token, last_error, published_at"
        in compat_grants
    )
    assert "must drain the compat worker" in compat_grants
    schema_contract = source.index(
        "-- This authority body is intentionally replayable at the two supported"
    )
    first_acl_mutation = source.index("GRANT USAGE ON SCHEMA public")
    rate_projection = source.index("-- Rate-limit state is reachable only through")
    assert schema_contract < first_acl_mutation < rate_projection
    assert "schema_revision IN ('p0s000000003', 'p0s000000004')" in source
    assert "IF privacy_column_present" in source
    assert "OR rate_policy_table IS NOT NULL" in source
    assert "OR rate_counter_table IS NOT NULL" in source
    assert "IF registration_table IS NULL" in source
    assert "OR rate_policy_table IS NULL" in source
    assert "OR rate_counter_table IS NULL" in source
    assert "control-plane schema revision/object contract rejected" in source
    privacy_guard = source.index("schema_revision IN ('p0s000000003', 'p0s000000004')")
    privacy_projection = source.index(
        "GRANT SELECT (id, user_id, tenant_id, deletion_manifest_id, version)"
    )
    assert privacy_guard < privacy_projection


def test_real_postgresql_n1_compat_login_admission_and_roles_replay(
    isolated_postgres_url: str,
) -> None:
    """Admit only a direct, externally credentialed compatibility LOGIN."""

    admin_engine = sa.create_engine(isolated_postgres_url)
    login_name = f"n1_compat_login_{uuid4().hex[:12]}"
    extra_member = f"n1_compat_extra_{uuid4().hex[:12]}"
    password = uuid4().hex + uuid4().hex
    admission_engine: sa.Engine | None = None
    login_created = False
    extra_member_created = False
    reverse_roles_created: set[str] = set()
    schema_name = f"n1_compat_owned_{uuid4().hex[:12]}"

    try:
        with admin_engine.begin() as connection:
            command.upgrade(_migration_config(connection), "p0s000000003")

            # Credential material is supplied by the external provisioning
            # boundary.  Production replaces this test-only value with a
            # non-exporting KMS/HSM integration; the admission module neither
            # accepts a password argument nor creates a LOGIN.
            driver_connection = connection.connection.driver_connection
            assert driver_connection is not None
            with driver_connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN INHERIT NOSUPERUSER NOCREATEDB "
                        "NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                    ).format(sql.Identifier(login_name), sql.Literal(password))
                )
            quoted_login = connection.dialect.identifier_preparer.quote(login_name)
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher_n1_compat TO {quoted_login} WITH INHERIT TRUE, SET FALSE"
            )

        login_created = True
        source_url = sa.engine.make_url(isolated_postgres_url)
        direct_url = source_url.set(
            username=login_name,
            password=password,
            host=source_url.host or "127.0.0.1",
            port=source_url.port or 5432,
        )
        admission_engine = sa.create_engine(direct_url, pool_pre_ping=True)

        # p0s3 installs the schema-forward bridge, but only roles.sql supplies
        # the exact planning-column ACLs required by 9451a64's RLS queries.
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )

        # The authority bootstrap runs only while the compatibility role has
        # zero incoming members.  Credential binding occurs afterwards and
        # production admission remains independently closed.
        with admin_engine.begin() as connection:
            quoted_login = connection.dialect.identifier_preparer.quote(login_name)
            connection.exec_driver_sql(f"REVOKE saas_dispatcher_n1_compat FROM {quoted_login}")
            connection.exec_driver_sql(_roles_source())
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher_n1_compat TO {quoted_login} WITH INHERIT TRUE, SET FALSE"
            )

        verify_n1_outbox_compatibility_schema_login(
            admission_engine,
            expected_login=login_name,
        )
        _assert_production_admission_blocked(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        _assert_roles_replay_rejected(admin_engine)

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT SELECT ON public.saas_control_plane_outbox TO saas_dispatcher_n1_compat"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE SELECT ON public.saas_control_plane_outbox FROM saas_dispatcher_n1_compat"
            )
            connection.exec_driver_sql(
                "GRANT SELECT (id, published_at, available_at, claimed_at, created_at, "
                "claim_token, event_type, aggregate_type, aggregate_key, payload, "
                "attempt_count) ON public.saas_control_plane_outbox "
                "TO saas_dispatcher_n1_compat"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE public.saas_control_plane_outbox "
                "ADD COLUMN n1_test_future_column text"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE public.saas_control_plane_outbox DROP COLUMN n1_test_future_column"
            )

        verify_n1_outbox_compatibility_schema_login(
            admission_engine,
            expected_login=login_name,
        )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "DROP POLICY rls_n1_compat_role_assignments_deny "
                "ON public.saas_platform_role_assignments"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE POLICY rls_n1_compat_role_assignments_deny "
                "ON public.saas_platform_role_assignments AS RESTRICTIVE FOR SELECT "
                "TO saas_dispatcher_n1_compat USING (false)"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE POLICY n1_test_permissive_planning_drift "
                "ON public.saas_platform_role_assignments AS PERMISSIVE FOR SELECT "
                "TO saas_dispatcher_n1_compat USING (true)"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "DROP POLICY n1_test_permissive_planning_drift "
                "ON public.saas_platform_role_assignments"
            )

        verify_n1_outbox_compatibility_schema_login(
            admission_engine,
            expected_login=login_name,
        )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE public.saas_control_plane_outbox "
                "DISABLE TRIGGER trg_outbox_n1_compatibility"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE public.saas_control_plane_outbox "
                "ENABLE TRIGGER trg_outbox_n1_compatibility"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE public.saas_platform_role_assignments NO FORCE ROW LEVEL SECURITY"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE public.saas_platform_role_assignments FORCE ROW LEVEL SECURITY"
            )

        probe_rule = f"n1_outbox_probe_{uuid4().hex[:12]}"
        quoted_probe_rule = admin_engine.dialect.identifier_preparer.quote(probe_rule)
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE RULE {quoted_probe_rule} AS ON UPDATE TO "
                "public.saas_control_plane_outbox DO ALSO NOTHING"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"DROP RULE {quoted_probe_rule} ON public.saas_control_plane_outbox"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE SELECT (expires_at) ON "
                "public.saas_platform_role_assignments "
                "FROM saas_dispatcher_n1_compat"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT SELECT (expires_at) ON "
                "public.saas_platform_role_assignments "
                "TO saas_dispatcher_n1_compat"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT SELECT (id) ON public.saas_platform_role_assignments "
                "TO saas_dispatcher_n1_compat"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE SELECT (id) ON public.saas_platform_role_assignments "
                "FROM saas_dispatcher_n1_compat"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE UPDATE ON public.saas_control_plane_outbox FROM saas_dispatcher_n1_compat"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT UPDATE (attempt_count, available_at, claimed_at, claim_token, "
                "last_error, published_at) ON public.saas_control_plane_outbox "
                "TO saas_dispatcher_n1_compat"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT UPDATE ON public.saas_control_plane_outbox TO saas_dispatcher_n1_compat"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE UPDATE ON public.saas_control_plane_outbox FROM saas_dispatcher_n1_compat"
            )
            connection.exec_driver_sql(
                "GRANT UPDATE (attempt_count, available_at, claimed_at, claim_token, "
                "last_error, published_at) ON public.saas_control_plane_outbox "
                "TO saas_dispatcher_n1_compat"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT INSERT ON public.saas_control_plane_outbox TO saas_dispatcher_n1_compat"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE INSERT ON public.saas_control_plane_outbox FROM saas_dispatcher_n1_compat"
            )

        with admin_engine.begin() as connection:
            original_sanitizer = str(
                connection.scalar(
                    sa.text(
                        "SELECT pg_get_functiondef("
                        "'public.saas_bridge_n1_outbox_update()'::regprocedure)"
                    )
                )
            )
            connection.exec_driver_sql(
                "CREATE OR REPLACE FUNCTION public.saas_bridge_n1_outbox_update() "
                "RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog "
                "AS $$ BEGIN RETURN NEW; END $$"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(original_sanitizer)

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER FUNCTION public.saas_bridge_n1_outbox_update() SECURITY DEFINER"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER FUNCTION public.saas_bridge_n1_outbox_update() SECURITY INVOKER"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER FUNCTION public.saas_bridge_n1_outbox_update() SET search_path = public"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER FUNCTION public.saas_bridge_n1_outbox_update() SET search_path = pg_catalog"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "GRANT EXECUTE ON FUNCTION public.saas_bridge_n1_outbox_update() "
                "TO saas_dispatcher_n1_compat"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                "REVOKE EXECUTE ON FUNCTION public.saas_bridge_n1_outbox_update() "
                "FROM saas_dispatcher_n1_compat"
            )

        probe_function = f"saas_n1_early_probe_{uuid4().hex[:12]}"
        probe_trigger = f"aaa_n1_early_probe_{uuid4().hex[:12]}"
        quoted_probe_function = admin_engine.dialect.identifier_preparer.quote(probe_function)
        quoted_probe_trigger = admin_engine.dialect.identifier_preparer.quote(probe_trigger)
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE FUNCTION public.{quoted_probe_function}() RETURNS trigger "
                "LANGUAGE plpgsql SET search_path = pg_catalog "
                "AS $$ BEGIN RETURN NEW; END $$"
            )
            connection.exec_driver_sql(
                f"CREATE TRIGGER {quoted_probe_trigger} BEFORE UPDATE ON "
                "public.saas_control_plane_outbox FOR EACH ROW "
                f"EXECUTE FUNCTION public.{quoted_probe_function}()"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"DROP TRIGGER {quoted_probe_trigger} ON public.saas_control_plane_outbox"
            )
            connection.exec_driver_sql(f"DROP FUNCTION public.{quoted_probe_function}()")

        # The verifier must observe a real direct login.  An owner connection
        # cannot substitute SET ROLE or session authorization for admission.
        _assert_secret_free_rejection(
            admin_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login="unsafe;identifier",
            forbidden_values=(login_name, password),
        )

        quoted_login = admin_engine.dialect.identifier_preparer.quote(login_name)
        quoted_extra = admin_engine.dialect.identifier_preparer.quote(extra_member)
        quoted_schema = admin_engine.dialect.identifier_preparer.quote(schema_name)

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER ROLE {quoted_login} SET application_name = 'not-admitted'"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f"ALTER ROLE {quoted_login} RESET ALL")

        for unsafe_flag, safe_flag in (
            ("CREATEDB", "NOCREATEDB"),
            ("CREATEROLE", "NOCREATEROLE"),
            ("REPLICATION", "NOREPLICATION"),
        ):
            with admin_engine.begin() as connection:
                connection.exec_driver_sql(f"ALTER ROLE {quoted_login} {unsafe_flag}")
            _assert_secret_free_rejection(
                admission_engine,
                expected_login=login_name,
                forbidden_values=(login_name, password),
            )
            with admin_engine.begin() as connection:
                connection.exec_driver_sql(f"ALTER ROLE {quoted_login} {safe_flag}")

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT SELECT ON public.saas_outbox_quarantine_events TO {quoted_login}"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE SELECT ON public.saas_outbox_quarantine_events FROM {quoted_login}"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE SCHEMA {quoted_schema} AUTHORIZATION {quoted_login}"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP SCHEMA {quoted_schema}")

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT saas_app TO {quoted_login} WITH INHERIT TRUE, SET FALSE"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE saas_app FROM {quoted_login}")

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE saas_dispatcher_n1_compat FROM {quoted_login}")
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher_n1_compat TO {quoted_login} WITH INHERIT TRUE, SET TRUE"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE saas_dispatcher_n1_compat FROM {quoted_login}")
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher_n1_compat TO {quoted_login} WITH INHERIT TRUE, SET FALSE"
            )

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher_n1_compat TO {quoted_login} "
                "WITH ADMIN TRUE, INHERIT TRUE, SET FALSE"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE saas_dispatcher_n1_compat FROM {quoted_login}")
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher_n1_compat TO {quoted_login} WITH INHERIT TRUE, SET FALSE"
            )

        reverse_membership_specs = (
            (f"n1_reverse_login_{uuid4().hex[:12]}", "LOGIN", "INHERIT TRUE, SET FALSE"),
            (f"n1_reverse_nologin_{uuid4().hex[:12]}", "NOLOGIN", "INHERIT TRUE, SET FALSE"),
            (f"n1_reverse_admin_{uuid4().hex[:12]}", "NOLOGIN", "ADMIN TRUE, SET FALSE"),
            (f"n1_reverse_set_{uuid4().hex[:12]}", "NOLOGIN", "INHERIT TRUE, SET TRUE"),
        )
        for reverse_role, login_flag, membership_options in reverse_membership_specs:
            quoted_reverse = admin_engine.dialect.identifier_preparer.quote(reverse_role)
            with admin_engine.begin() as connection:
                connection.exec_driver_sql(
                    f"CREATE ROLE {quoted_reverse} {login_flag} INHERIT NOSUPERUSER "
                    "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                )
                reverse_roles_created.add(reverse_role)
                connection.exec_driver_sql(
                    f"GRANT {quoted_login} TO {quoted_reverse} WITH {membership_options}"
                )
            _assert_secret_free_rejection(
                admission_engine,
                expected_login=login_name,
                forbidden_values=(login_name, password, reverse_role),
            )
            _assert_roles_replay_rejected(admin_engine)
            with admin_engine.begin() as connection:
                connection.exec_driver_sql(f"REVOKE {quoted_login} FROM {quoted_reverse}")
                connection.exec_driver_sql(f"DROP ROLE {quoted_reverse}")
                reverse_roles_created.remove(reverse_role)

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_extra} NOLOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            )
            extra_member_created = True
            connection.exec_driver_sql(
                f"GRANT saas_dispatcher_n1_compat TO {quoted_extra} WITH INHERIT TRUE, SET FALSE"
            )
        _assert_secret_free_rejection(
            admission_engine,
            expected_login=login_name,
            forbidden_values=(login_name, password),
        )

        # roles.sql must reject the same ambiguous incoming membership before
        # reconverging the fixed-column bridge.
        _assert_roles_replay_rejected(admin_engine)

        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP ROLE {quoted_extra}")
            extra_member_created = False

        verify_n1_outbox_compatibility_schema_login(
            admission_engine,
            expected_login=login_name,
        )
    finally:
        if admission_engine is not None:
            admission_engine.dispose()
        with admin_engine.begin() as connection:
            quoted_login = connection.dialect.identifier_preparer.quote(login_name)
            quoted_extra = connection.dialect.identifier_preparer.quote(extra_member)
            if extra_member_created:
                connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_extra}")
            for reverse_role in sorted(reverse_roles_created):
                quoted_reverse = connection.dialect.identifier_preparer.quote(reverse_role)
                connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_reverse}")
            if login_created:
                connection.exec_driver_sql(f"DROP OWNED BY {quoted_login}")
                connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_login}")
        admin_engine.dispose()


@pytest.mark.parametrize("schema_revision", ["p0s000000003", "p0s000000004"])
def test_real_postgresql_roles_allow_exact_rollback_schema_and_reject_newer_marker_drift(
    isolated_postgres_url: str,
    schema_revision: str,
) -> None:
    engine = sa.create_engine(isolated_postgres_url)
    try:
        with engine.begin() as connection:
            command.upgrade(_migration_config(connection), schema_revision)
            connection.exec_driver_sql(_roles_source())
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == schema_revision
            )
            assert connection.scalar(
                sa.text("SELECT to_regclass('public.saas_registration_rate_limits') IS NULL")
            )
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE public.saas_self_service_registrations "
                "ADD COLUMN deletion_manifest_id uuid"
            )
        with pytest.raises(
            sa.exc.DBAPIError,
            match="control-plane schema revision/object contract rejected",
        ):
            with engine.begin() as connection:
                connection.exec_driver_sql(_roles_source())
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("schema_revision", "drift_sql"),
    [
        (
            "p0s000000005",
            "DROP POLICY rls_self_service_registrations_privacy_target "
            "ON public.saas_self_service_registrations",
        ),
        (
            "p0s000000006",
            "ALTER TABLE public.saas_registration_rate_limits NO FORCE ROW LEVEL SECURITY",
        ),
    ],
)
def test_real_postgresql_current_schema_object_drift_rejects_roles_replay(
    isolated_postgres_url: str,
    schema_revision: str,
    drift_sql: str,
) -> None:
    engine = sa.create_engine(isolated_postgres_url)
    try:
        with engine.begin() as connection:
            command.upgrade(_migration_config(connection), schema_revision)
            connection.exec_driver_sql(_roles_source())
            connection.exec_driver_sql(drift_sql)
        with pytest.raises(
            sa.exc.DBAPIError,
            match="control-plane schema revision/object contract rejected",
        ):
            with engine.begin() as connection:
                connection.exec_driver_sql(_roles_source())
    finally:
        engine.dispose()


@pytest.mark.parametrize("schema_revision", ["p0s000000005", "p0s000000006"])
def test_real_postgresql_exact_catalog_contract_rejects_semantic_drift(
    isolated_postgres_url: str,
    schema_revision: str,
) -> None:
    engine = sa.create_engine(isolated_postgres_url)
    status_tamper = """
        CREATE OR REPLACE FUNCTION public.saas_registration_rate_limit_status()
        RETURNS TABLE(
            action text,
            subject_kind text,
            limit_count integer,
            window_seconds integer,
            retention_seconds integer,
            max_rows integer,
            current_rows integer,
            policy_revision text,
            expired_rows bigint
        )
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $tampered$
            SELECT 'registration.request'::text, 'email'::text, 1, 60, 60,
                   1, 0, 'tampered'::text, 0::bigint
        $tampered$
    """
    privacy_trigger_tamper = """
        CREATE OR REPLACE FUNCTION public.saas_guard_self_service_registration_privacy_erasure()
        RETURNS trigger
        LANGUAGE plpgsql
        VOLATILE
        SECURITY INVOKER
        AS $tampered$
        BEGIN
            RETURN NEW;
        END
        $tampered$
    """
    drifts = [
        "ALTER POLICY rls_self_service_registrations_privacy_target "
        "ON public.saas_self_service_registrations USING (true)",
        "CREATE POLICY rls_registration_rate_limits_rogue "
        "ON public.saas_registration_rate_limits FOR SELECT TO PUBLIC USING (true)",
        "ALTER TABLE public.saas_registration_rate_limits "
        "DROP CONSTRAINT ck_registration_rate_limit_count; "
        "ALTER TABLE public.saas_registration_rate_limits "
        "ADD CONSTRAINT ck_registration_rate_limit_count "
        "CHECK (request_count >= 0) NOT VALID",
        "ALTER TABLE public.saas_registration_rate_limit_policies "
        "ALTER COLUMN updated_at DROP NOT NULL",
        status_tamper,
        privacy_trigger_tamper,
    ]
    if schema_revision == "p0s000000006":
        drifts.append(
            "UPDATE public.saas_registration_rate_limit_policies "
            "SET limit_count = 61 WHERE action = 'registration.request' "
            "AND subject_kind = 'network'"
        )

    try:
        with engine.begin() as connection:
            command.upgrade(_migration_config(connection), schema_revision)
            connection.exec_driver_sql(_roles_source())
            for drift_sql in drifts:
                savepoint = connection.begin_nested()
                try:
                    connection.exec_driver_sql(drift_sql)
                    with pytest.raises(
                        sa.exc.DBAPIError,
                        match="control-plane schema revision/object contract rejected",
                    ):
                        connection.exec_driver_sql(_roles_source())
                finally:
                    savepoint.rollback()
                connection.exec_driver_sql(_roles_source())
    finally:
        engine.dispose()


def test_real_postgresql_rate_limit_authority_replay_removes_poisoned_acls(
    isolated_postgres_url: str,
) -> None:
    engine = sa.create_engine(isolated_postgres_url)
    consume_signature = (
        "public.saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)"
    )
    prune_signature = "public.saas_prune_registration_rate_limits(text,text,integer)"
    status_signature = "public.saas_registration_rate_limit_status()"
    rogue_role = f"rate_acl_rogue_{uuid4().hex[:12]}"
    try:
        with engine.begin() as connection:
            command.upgrade(_migration_config(connection), "p0s000000006")
            quoted_rogue = connection.dialect.identifier_preparer.quote(rogue_role)
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_rogue} NOLOGIN INHERIT NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            )
            connection.exec_driver_sql(
                "GRANT SELECT ON public.saas_registration_rate_limit_policies TO saas_public_api"
            )
            connection.exec_driver_sql(
                "GRANT UPDATE (action) ON public.saas_registration_rate_limit_policies "
                "TO saas_approval_scheduler_audit"
            )
            connection.exec_driver_sql(
                "GRANT SELECT (request_count) ON public.saas_registration_rate_limits TO PUBLIC"
            )
            connection.exec_driver_sql(
                "GRANT EXECUTE ON FUNCTION " + consume_signature + " "
                "TO saas_approval_scheduler_audit"
            )
            connection.exec_driver_sql(
                "GRANT SELECT ON public.saas_registration_rate_limit_policies TO " + quoted_rogue
            )
            connection.exec_driver_sql(
                "GRANT UPDATE (request_count) ON public.saas_registration_rate_limits TO "
                + quoted_rogue
            )
            for signature in (consume_signature, prune_signature, status_signature):
                connection.exec_driver_sql(
                    "GRANT EXECUTE ON FUNCTION " + signature + " TO " + quoted_rogue
                )
            connection.exec_driver_sql(_roles_source())

            assert (
                connection.scalar(
                    sa.text(
                        "SELECT has_table_privilege('saas_public_api', "
                        "'public.saas_registration_rate_limit_policies', 'SELECT')"
                    )
                )
                is False
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT has_column_privilege('saas_approval_scheduler_audit', "
                        "'public.saas_registration_rate_limit_policies', 'action', 'UPDATE')"
                    )
                )
                is False
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM pg_attribute AS attribute "
                        "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
                        "WHERE attribute.attrelid = "
                        "'public.saas_registration_rate_limits'::regclass "
                        "AND attribute.attname = 'request_count' "
                        "AND acl.grantee = 0 AND acl.privilege_type = 'SELECT'"
                    )
                )
                == 0
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT has_function_privilege('saas_approval_scheduler_audit', "
                        ":signature, 'EXECUTE')"
                    ),
                    {"signature": consume_signature},
                )
                is False
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT has_function_privilege('saas_registration', :signature, 'EXECUTE')"
                    ),
                    {"signature": consume_signature},
                )
                is True
            )
            for signature in (prune_signature, status_signature):
                assert (
                    connection.scalar(
                        sa.text(
                            "SELECT has_function_privilege('saas_platform', :signature, 'EXECUTE')"
                        ),
                        {"signature": signature},
                    )
                    is True
                )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT has_table_privilege(:role, "
                        "'public.saas_registration_rate_limit_policies', 'SELECT')"
                    ),
                    {"role": rogue_role},
                )
                is False
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT has_column_privilege(:role, "
                        "'public.saas_registration_rate_limits', 'request_count', 'UPDATE')"
                    ),
                    {"role": rogue_role},
                )
                is False
            )
            for signature in (consume_signature, prune_signature, status_signature):
                assert (
                    connection.scalar(
                        sa.text("SELECT has_function_privilege(:role, :signature, 'EXECUTE')"),
                        {"role": rogue_role, "signature": signature},
                    )
                    is False
                )
            connection.exec_driver_sql(f"DROP ROLE {quoted_rogue}")
    finally:
        engine.dispose()
