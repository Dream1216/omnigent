from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError


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


def test_real_postgresql_platform_roles_are_content_blind_exact_and_not_emergency() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    operator_id, roleless_id, user_id, tenant_a, tenant_b = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    assignment_id, operator_session_id, roleless_session_id = uuid4(), uuid4(), uuid4()
    operator_token_hash = sha256(f"operator-{uuid4()}".encode()).hexdigest()
    roleless_token_hash = sha256(f"roleless-{uuid4()}".encode()).hexdigest()
    forged_token_hash = sha256(f"forged-{uuid4()}".encode()).hexdigest()
    roles = {
        "pc1_platform_app_login": "saas_platform_app",
        "pc1_platform_auth_login": "saas_platform_authenticator",
        "pc1_platform_governance_login": "saas_platform_governance",
        "pc1_platform_projector_login": "saas_platform_projector",
        "pc1_tenant_app_login": "saas_app",
    }

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        for login_role in roles:
            connection.exec_driver_sql(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{login_role}') THEN
                        CREATE ROLE {login_role} NOLOGIN NOSUPERUSER NOBYPASSRLS;
                    END IF;
                END
                $$
                """
            )
            for inherited in (
                "saas_app",
                "saas_platform_app",
                "saas_platform_authenticator",
                "saas_platform_governance",
                "saas_platform_projector",
                "saas_platform",
            ):
                connection.exec_driver_sql(f"REVOKE {inherited} FROM {login_role}")
            connection.exec_driver_sql(f"GRANT {roles[login_role]} TO {login_role}")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_staff_principals "
                "(id, identity_connection_ref, issuer, subject, status, security_version) VALUES "
                "(:operator, :operator_ref, :issuer, :operator_subject, 'active', 1), "
                "(:roleless, :roleless_ref, :issuer, :roleless_subject, 'active', 1)"
            ),
            {
                "operator": operator_id,
                "operator_ref": f"staff-idp:{operator_id}",
                "operator_subject": f"operator-{operator_id}",
                "roleless": roleless_id,
                "roleless_ref": f"staff-idp:{roleless_id}",
                "roleless_subject": f"roleless-{roleless_id}",
                "issuer": "https://staff-idp.example.test",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_role_assignments "
                "(id, principal_id, role, status, version, assigned_by_principal_id, "
                "approval_ref, reason) VALUES "
                "(:id, :principal, 'platform_operator', 'active', 1, :assigned_by, "
                "'pc1-postgresql-approval', 'PC1 PostgreSQL acceptance')"
            ),
            {"id": assignment_id, "principal": operator_id, "assigned_by": roleless_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_auth_sessions "
                "(id, principal_id, token_hash, csrf_token_hash, security_version, audience, "
                "origin, authn_method, mfa_strength, authenticated_at, expires_at) VALUES "
                "(:operator_id, :operator, :operator_hash, :operator_csrf, 1, "
                "'omnigent-platform-admin', 'https://platform-admin.example.test', "
                "'passkey', 'phishing_resistant', now(), now() + interval '1 hour'), "
                "(:roleless_id, :roleless, :roleless_hash, :roleless_csrf, 1, "
                "'omnigent-platform-admin', 'https://platform-admin.example.test', "
                "'passkey', 'phishing_resistant', now(), now() + interval '1 hour')"
            ),
            {
                "operator_id": operator_session_id,
                "operator": operator_id,
                "operator_hash": operator_token_hash,
                "operator_csrf": "a" * 64,
                "roleless_id": roleless_session_id,
                "roleless": roleless_id,
                "roleless_hash": roleless_token_hash,
                "roleless_csrf": "b" * 64,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_tenant_projections "
                "(tenant_id, slug, name, status, plan, home_region, member_count, "
                "space_count, source_version, updated_at) VALUES "
                "(:tenant_a, :slug_a, 'Tenant A', 'active', 'team', 'cn-east-1', 3, 1, 1, now()), "
                "(:tenant_b, :slug_b, 'Tenant B', 'active', 'team', 'cn-east-1', 4, 2, 1, now())"
            ),
            {
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
                "slug_a": f"pc1-a-{tenant_a.hex}",
                "slug_b": f"pc1-b-{tenant_b.hex}",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_platform_user_projections "
                "(user_id, status, display_name, email_masked, membership_count, "
                "security_version, source_version, created_at, updated_at) VALUES "
                "(:id, 'active', 'Customer User', 'c***@example.test', 2, 1, 1, now(), now())"
            ),
            {"id": user_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:id, 'active', 1)"
            ),
            {"id": user_id},
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_auth_login")
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_platform_auth_sessions")
            ).scalar_one()
            == 0
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_session_token_hash', :value, true)"),
            {"value": operator_token_hash},
        )
        assert (
            connection.execute(sa.text("SELECT id FROM saas_platform_auth_sessions")).scalar_one()
            == operator_session_id
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_auth_login")
        connection.execute(
            sa.text("SELECT set_config('app.platform_identity_issuer', :value, true)"),
            {"value": "https://staff-idp.example.test"},
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_identity_subject', :value, true)"),
            {"value": f"operator-{operator_id}"},
        )
        assert (
            connection.execute(
                sa.text("SELECT id FROM saas_platform_staff_principals")
            ).scalar_one()
            == operator_id
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_auth_login")
        connection.execute(
            sa.text("SELECT set_config('app.platform_identity_issuer', :value, true)"),
            {"value": "https://staff-idp.example.test"},
        )
        connection.execute(
            sa.text("SELECT set_config('app.platform_identity_subject', 'unknown', true)")
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_platform_staff_principals")
            ).scalar_one()
            == 0
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_app_login")
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(operator_id)},
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(*) FROM saas_platform_tenant_projections "
                    "WHERE tenant_id IN (:tenant_a, :tenant_b)"
                ),
                {"tenant_a": tenant_a, "tenant_b": tenant_b},
            ).scalar_one()
            == 2
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT email_masked FROM saas_platform_user_projections "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user_id},
            ).scalar_one()
            == "c***@example.test"
        )
        assert not connection.execute(
            sa.text("SELECT pg_has_role(current_user, 'saas_platform', 'member')")
        ).scalar_one()
        connection.execute(
            sa.text(
                "INSERT INTO saas_email_provider_configurations "
                "(purpose, enabled, host, port, security, username, password_ciphertext, "
                "from_address, timeout_seconds, version, updated_by_principal_id, updated_at) "
                "VALUES ('onboarding_verification', true, 'smtp.example.test', 587, "
                "'starttls', 'smtp-user', 'kms-ciphertext', 'verify@example.test', 10, 1, "
                ":principal, now())"
            ),
            {"principal": operator_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_email_provider_configuration_receipts "
                "(id, purpose, configuration_version, actor_principal_id, action, "
                "configuration_hash, password_rotated, occurred_at) VALUES "
                "(:id, 'onboarding_verification', 1, :principal, 'configured', "
                ":configuration_hash, true, now())"
            ),
            {
                "id": uuid4(),
                "principal": operator_id,
                "configuration_hash": "d" * 64,
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_app_login")
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(roleless_id)},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_platform_tenant_projections")
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_email_provider_configurations")
            ).scalar_one()
            == 0
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_onboarding")
        assert (
            connection.execute(
                sa.text(
                    "SELECT host FROM saas_email_provider_configurations "
                    "WHERE purpose = 'onboarding_verification'"
                )
            ).scalar_one()
            == "smtp.example.test"
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_onboarding")
            connection.execute(
                sa.text(
                    "UPDATE saas_email_provider_configurations SET enabled = false "
                    "WHERE purpose = 'onboarding_verification'"
                )
            )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_auth_login")
            connection.execute(
                sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
                {"value": str(operator_id)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.platform_session_token_hash', :value, true)"),
                {"value": forged_token_hash},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_auth_sessions "
                    "(id, principal_id, token_hash, csrf_token_hash, security_version, "
                    "audience, origin, authn_method, mfa_strength, authenticated_at, "
                    "expires_at) VALUES (:id, :roleless, :token_hash, :csrf, 1, "
                    "'omnigent-platform-admin', 'https://platform-admin.example.test', "
                    "'passkey', 'phishing_resistant', now(), now() + interval '1 hour')"
                ),
                {
                    "id": uuid4(),
                    "roleless": roleless_id,
                    "token_hash": forged_token_hash,
                    "csrf": "c" * 64,
                },
            )
        connection.execute(
            sa.text("SELECT set_config('app.platform_principal_id', :value, true)"),
            {"value": str(roleless_id)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_platform_tenant_projections")
            ).scalar_one()
            == 0
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            # SET ROLE from a superuser connection would retain the original
            # session user's ability to assume any role. Switch the local
            # session identity so this proves the deployed login cannot
            # escalate into the emergency authority.
            connection.exec_driver_sql("SET LOCAL SESSION AUTHORIZATION pc1_platform_app_login")
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_app_login")
            connection.execute(sa.text("SELECT primary_email_normalized FROM saas_global_users"))

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE pc1_tenant_app_login")
            connection.execute(sa.text("SELECT * FROM saas_platform_tenant_projections"))

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_projector_login")
            connection.execute(sa.text("SELECT * FROM saas_global_users"))

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE pc1_platform_governance_login")
            connection.execute(sa.text("SELECT * FROM saas_global_users"))

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(sa.text("DELETE FROM saas_email_provider_configuration_receipts"))
        connection.execute(sa.text("DELETE FROM saas_email_provider_configurations"))

    engine.dispose()
