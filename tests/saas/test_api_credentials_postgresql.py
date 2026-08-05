from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane import ApiCredentialError, ApiCredentialService


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


def test_real_postgresql_api_key_uses_exact_rls_and_revokes_immediately() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    owner_id, steward_id = uuid4(), uuid4()
    tenant_id, space_id, project_id = uuid4(), uuid4(), uuid4()
    checked_at = datetime(2026, 8, 5, 11, 0, tzinfo=timezone.utc)
    pepper = b"postgres-api-credential-pepper-material-v1"
    suffix = uuid4().hex[:12]
    governance_role = f"saas_api_governance_{suffix}"
    auth_role = f"saas_api_auth_{suffix}"

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"""
            CREATE ROLE {governance_role} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT;
            CREATE ROLE {auth_role} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT;
            GRANT saas_governance TO {governance_role};
            GRANT saas_authenticator TO {auth_role};
            SET LOCAL ROLE saas_platform;
            """
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) VALUES "
                "(:owner, 'active', 1), (:steward, 'active', 1)"
            ),
            {"owner": owner_id, "steward": steward_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:tenant, :slug, 'API RLS', 'active', 'team', 'cn-east-1')"
            ),
            {"tenant": tenant_id, "slug": f"api-rls-{tenant_id.hex}"},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version) VALUES "
                "(:tenant, :owner, 'owner', 'active', 1), "
                "(:tenant, :steward, 'member', 'active', 1)"
            ),
            {"tenant": tenant_id, "owner": owner_id, "steward": steward_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) VALUES "
                "(:space, :tenant, 'api', 'API', 'active')"
            ),
            {"space": space_id, "tenant": tenant_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_space_memberships "
                "(tenant_id, space_id, user_id, role, status, version) VALUES "
                "(:tenant, :space, :owner, 'owner', 'active', 1), "
                "(:tenant, :space, :steward, 'member', 'active', 1)"
            ),
            {
                "tenant": tenant_id,
                "space": space_id,
                "owner": owner_id,
                "steward": steward_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_projects "
                "(id, tenant_id, space_id, name, visibility, created_by, status, "
                "authorization_version) VALUES "
                "(:project, :tenant, :space, 'API Project', 'private', :owner, 'active', 1)"
            ),
            {
                "project": project_id,
                "tenant": tenant_id,
                "space": space_id,
                "owner": owner_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_project_memberships "
                "(tenant_id, space_id, project_id, subject_type, subject_id, role, status, "
                "created_by, version) VALUES "
                "(:tenant, :space, :project, 'user', :owner, 'owner', 'active', :owner, 1)"
            ),
            {
                "tenant": tenant_id,
                "space": space_id,
                "project": project_id,
                "owner": owner_id,
            },
        )

    governance_sessions = sessionmaker(engine, expire_on_commit=False)
    auth_sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(governance_sessions, "after_begin")
    def _use_governance_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {governance_role}")

    @sa.event.listens_for(auth_sessions, "after_begin")
    def _use_auth_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {auth_role}")

    governance = ApiCredentialService(governance_sessions, credential_pepper=pepper)
    authenticator = ApiCredentialService(auth_sessions, credential_pepper=pepper)
    account = governance.create_service_account(
        actor_id=owner_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        steward_user_id=steward_id,
        name="postgres-bot",
        description=None,
        authenticated_at=checked_at,
        idempotency_key=f"pg-account-{suffix}",
        now=checked_at,
    )
    issued = governance.issue_api_credential(
        actor_id=owner_id,
        tenant_id=tenant_id,
        service_account_id=account.id,
        name="postgres-key",
        permission_scopes=("run.create",),
        allowed_networks=("127.0.0.1/32",),
        expires_at=checked_at + timedelta(days=1),
        authenticated_at=checked_at,
        idempotency_key=f"pg-key-{suffix}",
        now=checked_at,
    )
    assert issued.token is not None

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {auth_role}")
        hidden_count = connection.execute(
            sa.text("SELECT count(*) FROM saas_api_credentials")
        ).scalar_one()
        assert hidden_count == 0
        connection.execute(
            sa.text("SELECT set_config('app.api_credential_id', :value, true)"),
            {"value": str(issued.credential_id)},
        )
        exact_count = connection.execute(
            sa.text("SELECT count(*) FROM saas_api_credentials")
        ).scalar_one()
        assert exact_count == 1

    principal = authenticator.authenticate(
        issued.token, source_ip="127.0.0.1", now=checked_at
    )
    assert principal.service_account_id == account.id
    governance.revoke_api_credential(
        actor_id=owner_id,
        tenant_id=tenant_id,
        service_account_id=account.id,
        credential_id=issued.credential_id,
        authenticated_at=checked_at,
        idempotency_key=f"pg-revoke-{suffix}",
        now=checked_at,
    )
    with pytest.raises(ApiCredentialError):
        authenticator.authenticate(issued.token, source_ip="127.0.0.1", now=checked_at)

    with engine.begin() as connection:
        protected = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relrowsecurity AND relforcerowsecurity "
                    "AND relname IN ('saas_service_accounts', 'saas_api_credentials')"
                )
            ).scalars()
        )
        assert protected == {"saas_service_accounts", "saas_api_credentials"}
        posture = connection.execute(
            sa.text(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname IN (:governance, :auth) ORDER BY rolname"
            ),
            {"governance": governance_role, "auth": auth_role},
        ).all()
        assert len(posture) == 2
        assert all(not superuser and not bypass for _role, superuser, bypass in posture)
        connection.exec_driver_sql(f"REVOKE saas_governance FROM {governance_role}")
        connection.exec_driver_sql(f"REVOKE saas_authenticator FROM {auth_role}")
        connection.exec_driver_sql(f"DROP ROLE {governance_role}")
        connection.exec_driver_sql(f"DROP ROLE {auth_role}")
    engine.dispose()
