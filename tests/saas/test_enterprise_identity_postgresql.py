from __future__ import annotations

import os
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.enterprise_identity import EnterpriseScimService
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for PC5 SCIM RLS acceptance")
    return url


def _context(*, actor: UUID, tenant: UUID, space: UUID) -> RequestContext:
    return RequestContext(
        actor_id=actor,
        tenant_id=tenant,
        space_id=space,
        project_id=None,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="pc5-scim-postgresql",
    )


def test_real_postgresql_scim_token_rls_event_immutability_and_deprovision_order() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    suffix = uuid4().hex[:12]
    login_role = f"pc5_scim_governance_{suffix}"
    owner_id, tenant_id, other_tenant_id, space_id = (uuid4() for _ in range(4))

    with engine.begin() as connection:
        config = Config(root / "saas/control_plane/alembic.ini")
        config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"CREATE ROLE {login_role} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT"
        )
        connection.exec_driver_sql(f"GRANT saas_governance TO {login_role}")
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:owner, 'active', 1)"
            ),
            {"owner": owner_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:tenant, :slug, 'PC5 SCIM', 'active', 'enterprise', 'cn-east-1'), "
                "(:other, :other_slug, 'Other PC5', 'active', 'enterprise', 'cn-east-1')"
            ),
            {
                "tenant": tenant_id,
                "slug": f"pc5-scim-{suffix}",
                "other": other_tenant_id,
                "other_slug": f"pc5-other-{suffix}",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version) "
                "VALUES (:tenant, :owner, 'owner', 'active', 1)"
            ),
            {"tenant": tenant_id, "owner": owner_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) "
                "VALUES (:space, :tenant, 'main', 'Main', 'active')"
            ),
            {"space": space_id, "tenant": tenant_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_space_memberships "
                "(tenant_id, space_id, user_id, role, status, version) "
                "VALUES (:tenant, :space, :owner, 'owner', 'active', 1)"
            ),
            {"tenant": tenant_id, "space": space_id, "owner": owner_id},
        )

    governance_sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(governance_sessions, "after_begin")
    def _use_governance_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {login_role}")

    service = EnterpriseScimService(governance_sessions)
    issued = service.issue_directory(
        _context(actor=owner_id, tenant=tenant_id, space=space_id),
        display_name=f"Corporate IdP {suffix}",
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key=f"pc5-directory-{suffix}",
    )
    assert issued.bearer_token is not None
    old_token = issued.bearer_token
    rotated = service.rotate_directory_credential(
        _context(actor=owner_id, tenant=tenant_id, space=space_id),
        directory_id=issued.id,
        expected_version=1,
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key=f"pc5-directory-rotate-{suffix}",
    )
    assert rotated.bearer_token is not None
    token = rotated.bearer_token
    with pytest.raises(LifecycleError) as old_token_denied:
        service.get_user(old_token, scim_user_id=uuid4())
    assert old_token_denied.value.code == "scim_authentication_failed"
    created = service.upsert_user(
        token,
        event_id=f"pc5-user-create-{suffix}",
        external_id=f"employee-{suffix}",
        user_name=f"employee-{suffix}@example.test",
        display_name="PC5 Employee",
        active=True,
        source_version=1,
    )
    assert created.user_id is not None
    group = service.sync_group(
        token,
        event_id=f"pc5-group-1-{suffix}",
        external_id=f"engineering-{suffix}",
        display_name=f"Engineering {suffix}",
        member_external_ids=[f"employee-{suffix}"],
        active=True,
        source_version=1,
    )
    assert group.active_member_count == 1
    deprovisioned = service.upsert_user(
        token,
        event_id=f"pc5-user-delete-{suffix}",
        external_id=f"employee-{suffix}",
        user_name=f"employee-{suffix}@example.test",
        display_name="PC5 Employee",
        active=False,
        source_version=2,
    )
    assert deprovisioned.membership_status == "removed"
    late_group = service.sync_group(
        token,
        event_id=f"pc5-group-2-{suffix}",
        external_id=f"engineering-{suffix}",
        display_name=f"Engineering {suffix}",
        member_external_ids=[f"employee-{suffix}"],
        active=True,
        source_version=2,
    )
    assert late_group.disposition == "blocked"
    assert late_group.active_member_count == 0

    with pytest.raises(LifecycleError) as wrong_token:
        service.upsert_user(
            "omniscim_invalid",
            event_id=f"invalid-{suffix}",
            external_id="invalid",
            user_name="invalid@example.test",
            display_name=None,
            active=True,
            source_version=1,
        )
    assert wrong_token.value.code == "scim_authentication_failed"

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {login_role}")
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_enterprise_scim_directories")
            ).scalar_one()
            == 0
        )
        connection.execute(
            sa.text("SELECT set_config('app.scim_token_hash', :token_hash, true)"),
            {"token_hash": sha256(token.encode()).hexdigest()},
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_enterprise_scim_directories")
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_enterprise_scim_users")
            ).scalar_one()
            == 0
        )

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_enterprise_scim_events SET disposition = 'stale' "
                    "WHERE directory_id = :directory"
                ),
                {"directory": issued.id},
            )

    disabled = service.disable_directory(
        _context(actor=owner_id, tenant=tenant_id, space=space_id),
        directory_id=issued.id,
        expected_version=2,
        reauthenticated_at=datetime.now(timezone.utc),
        idempotency_key=f"pc5-directory-disable-{suffix}",
    )
    assert disabled.status == "disabled"
    assert disabled.version == 3
    with pytest.raises(LifecycleError) as disabled_token:
        service.get_group(token, scim_group_id=group.id)
    assert disabled_token.value.code == "scim_authentication_failed"

    assert len(CONTROL_PLANE_RLS_TABLES) == 85
    assert {
        "saas_enterprise_scim_directories",
        "saas_enterprise_scim_users",
        "saas_enterprise_scim_groups",
        "saas_enterprise_scim_events",
    } <= CONTROL_PLANE_RLS_TABLES

    # The shared CI database must remain reusable. Immutable facts are removed
    # only by the fixture superuser before returning to the PC3 predecessor.
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE TABLE saas_enterprise_scim_events, saas_enterprise_scim_groups, "
            "saas_enterprise_scim_users, saas_enterprise_scim_directories CASCADE"
        )
        config = Config(root / "saas/control_plane/alembic.ini")
        config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
        config.attributes["connection"] = connection
        command.downgrade(config, "pc3a00000001")
    engine.dispose()
