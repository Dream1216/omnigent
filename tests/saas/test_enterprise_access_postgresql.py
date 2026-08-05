from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane import (
    EnterpriseAccessService,
    LifecycleError,
    MembershipLifecycleService,
    ProjectAuthorizer,
)
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES

_NOW = datetime(2026, 8, 5, 14, 0, tzinfo=timezone.utc)


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


def _context(*, actor: UUID, tenant: UUID, space: UUID, trace: str) -> RequestContext:
    return RequestContext(
        actor_id=actor,
        tenant_id=tenant,
        space_id=space,
        project_id=None,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id=trace,
    )


def test_real_postgresql_enterprise_group_role_isolated_and_revoked_atomically() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    suffix = uuid4().hex[:12]
    governance_role = f"saas_enterprise_governance_{suffix}"
    app_role = f"saas_enterprise_app_{suffix}"
    owner_a, member_a, owner_b, member_b = (uuid4() for _ in range(4))
    tenant_a, tenant_b, space_a, space_b, project_a, project_b = (uuid4() for _ in range(6))

    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        connection.exec_driver_sql(
            f"""
            CREATE ROLE {governance_role} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT;
            CREATE ROLE {app_role} NOLOGIN NOSUPERUSER NOBYPASSRLS INHERIT;
            GRANT saas_governance TO {governance_role};
            GRANT saas_app TO {app_role};
            SET LOCAL ROLE saas_platform;
            """
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) VALUES "
                "(:owner_a, 'active', 1), (:member_a, 'active', 1), "
                "(:owner_b, 'active', 1), (:member_b, 'active', 1)"
            ),
            {
                "owner_a": owner_a,
                "member_a": member_a,
                "owner_b": owner_b,
                "member_b": member_b,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:tenant_a, :slug_a, 'Enterprise A', 'active', 'enterprise', 'cn-east-1'), "
                "(:tenant_b, :slug_b, 'Enterprise B', 'active', 'enterprise', 'cn-east-1')"
            ),
            {
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
                "slug_a": f"enterprise-a-{suffix}",
                "slug_b": f"enterprise-b-{suffix}",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version) VALUES "
                "(:tenant_a, :owner_a, 'owner', 'active', 1), "
                "(:tenant_a, :member_a, 'member', 'active', 1), "
                "(:tenant_b, :owner_b, 'owner', 'active', 1), "
                "(:tenant_b, :member_b, 'member', 'active', 1)"
            ),
            {
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
                "owner_a": owner_a,
                "member_a": member_a,
                "owner_b": owner_b,
                "member_b": member_b,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) VALUES "
                "(:space_a, :tenant_a, 'main', 'Main A', 'active'), "
                "(:space_b, :tenant_b, 'main', 'Main B', 'active')"
            ),
            {
                "space_a": space_a,
                "space_b": space_b,
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_space_memberships "
                "(tenant_id, space_id, user_id, role, status, version) VALUES "
                "(:tenant_a, :space_a, :owner_a, 'owner', 'active', 1), "
                "(:tenant_a, :space_a, :member_a, 'member', 'active', 1), "
                "(:tenant_b, :space_b, :owner_b, 'owner', 'active', 1), "
                "(:tenant_b, :space_b, :member_b, 'member', 'active', 1)"
            ),
            {
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
                "space_a": space_a,
                "space_b": space_b,
                "owner_a": owner_a,
                "member_a": member_a,
                "owner_b": owner_b,
                "member_b": member_b,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_projects "
                "(id, tenant_id, space_id, name, visibility, created_by, status, "
                "authorization_version) VALUES "
                "(:project_a, :tenant_a, :space_a, 'Project A', 'restricted', :owner_a, "
                "'active', 1), "
                "(:project_b, :tenant_b, :space_b, 'Project B', 'restricted', :owner_b, "
                "'active', 1)"
            ),
            {
                "project_a": project_a,
                "project_b": project_b,
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
                "space_a": space_a,
                "space_b": space_b,
                "owner_a": owner_a,
                "owner_b": owner_b,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_project_memberships "
                "(tenant_id, space_id, project_id, subject_type, subject_id, role, status, "
                "created_by, version) VALUES "
                "(:tenant_a, :space_a, :project_a, 'user', :owner_a, 'owner', 'active', "
                ":owner_a, 1), "
                "(:tenant_b, :space_b, :project_b, 'user', :owner_b, 'owner', 'active', "
                ":owner_b, 1)"
            ),
            {
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
                "space_a": space_a,
                "space_b": space_b,
                "project_a": project_a,
                "project_b": project_b,
                "owner_a": owner_a,
                "owner_b": owner_b,
            },
        )

    governance_sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(governance_sessions, "after_begin")
    def _use_governance_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {governance_role}")

    service = EnterpriseAccessService(governance_sessions)
    owner_context_a = _context(
        actor=owner_a, tenant=tenant_a, space=space_a, trace="pg-enterprise-owner-a"
    )
    owner_context_b = _context(
        actor=owner_b, tenant=tenant_b, space=space_b, trace="pg-enterprise-owner-b"
    )

    def _provision(
        context: RequestContext, project_id: UUID, member_id: UUID, label: str
    ) -> tuple[UUID, UUID]:
        group = service.create_group(
            context,
            name=f"Operators {label}",
            description=None,
            idempotency_key=f"pg-group-{label}-{suffix}",
        )
        service.add_group_member(
            context,
            group_id=group.id,
            user_id=member_id,
            expires_at=None,
            idempotency_key=f"pg-member-{label}-{suffix}",
            now=_NOW,
        )
        role = service.create_custom_role(
            context,
            project_id=project_id,
            name=f"Runner {label}",
            description=None,
            permissions=["run.create"],
            idempotency_key=f"pg-role-{label}-{suffix}",
        )
        service.assign_group_role(
            context,
            project_id=project_id,
            group_id=group.id,
            custom_role_id=role.id,
            expires_at=None,
            idempotency_key=f"pg-assignment-{label}-{suffix}",
            now=_NOW,
        )
        return group.id, role.id

    group_a, role_a = _provision(owner_context_a, project_a, member_a, "a")
    group_b, role_b = _provision(owner_context_b, project_b, member_b, "b")

    member_context_a = _context(
        actor=member_a, tenant=tenant_a, space=space_a, trace="pg-enterprise-member-a"
    )
    assert (
        ProjectAuthorizer(governance_sessions)
        .evaluate(
            member_context_a,
            action="run.create",
            project_id=project_a,
            now=_NOW,
        )
        .allowed
    )

    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {app_role}")
        connection.execute(
            sa.text("SELECT set_config('app.actor_id', :value, true)"),
            {"value": str(owner_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.space_id', :value, true)"),
            {"value": str(space_a)},
        )
        assert set(
            connection.execute(sa.text("SELECT id FROM saas_enterprise_groups")).scalars()
        ) == {group_a}
        assert set(
            connection.execute(sa.text("SELECT id FROM saas_enterprise_custom_roles")).scalars()
        ) == {role_a}
        assert group_b != group_a and role_b != role_a

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {app_role}")
            connection.execute(
                sa.text("SELECT set_config('app.actor_id', :value, true)"),
                {"value": str(owner_a)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.tenant_id', :value, true)"),
                {"value": str(tenant_a)},
            )
            connection.execute(
                sa.text("SELECT set_config('app.space_id', :value, true)"),
                {"value": str(space_a)},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_groups "
                    "(id, tenant_id, name, status, version, created_by) VALUES "
                    "(:id, :tenant, 'Cross Tenant', 'active', 1, :actor)"
                ),
                {"id": uuid4(), "tenant": tenant_b, "actor": owner_a},
            )

    lifecycle = MembershipLifecycleService(governance_sessions)
    issued = lifecycle.issue_auth_session(
        user_id=member_a,
        authn_method="password",
        expires_at=_NOW + timedelta(hours=1),
        now=_NOW,
    )

    def _remove(key: str) -> str:
        try:
            value = service.remove_group_member(
                owner_context_a,
                group_id=group_a,
                user_id=member_a,
                expected_version=1,
                idempotency_key=key,
                now=_NOW + timedelta(minutes=1),
            )
            return value.status
        except LifecycleError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(
                _remove,
                (f"pg-remove-a-{suffix}", f"pg-remove-b-{suffix}"),
            )
        )
    assert outcomes.count("removed") == 1
    assert set(outcomes) <= {"removed", "group_membership_not_active"}

    archive_group, _archive_role = _provision(
        owner_context_a, project_a, member_a, "archive-a"
    )
    archive_session = lifecycle.issue_auth_session(
        user_id=member_a,
        authn_method="password",
        expires_at=_NOW + timedelta(hours=1),
        now=_NOW + timedelta(minutes=2),
    )

    def _archive(key: str) -> str:
        try:
            value = service.archive_group(
                owner_context_a,
                group_id=archive_group,
                expected_version=1,
                reason="directory group became authoritative",
                idempotency_key=key,
                now=_NOW + timedelta(minutes=3),
            )
            return value.status
        except LifecycleError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        archive_outcomes = list(
            pool.map(
                _archive,
                (f"pg-archive-a-{suffix}", f"pg-archive-b-{suffix}"),
            )
        )
    assert archive_outcomes.count("archived") == 1
    assert set(archive_outcomes) <= {"archived", "group_not_active"}

    _retire_group, retire_role = _provision(
        owner_context_a, project_a, member_a, "retire-a"
    )

    def _retire(key: str) -> str:
        try:
            value = service.retire_custom_role(
                owner_context_a,
                project_id=project_a,
                custom_role_id=retire_role,
                expected_version=1,
                reason="role replaced by centrally governed role",
                idempotency_key=key,
                now=_NOW + timedelta(minutes=4),
            )
            return value.status
        except LifecycleError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        retire_outcomes = list(
            pool.map(
                _retire,
                (f"pg-retire-a-{suffix}", f"pg-retire-b-{suffix}"),
            )
        )
    assert retire_outcomes.count("retired") == 1
    assert set(retire_outcomes) <= {"retired", "custom_role_not_active"}

    race_group, race_role = _provision(
        owner_context_a, project_a, member_a, "archive-retire-race-a"
    )

    def _cross_lifecycle(action: str) -> str:
        if action == "archive":
            return service.archive_group(
                owner_context_a,
                group_id=race_group,
                expected_version=1,
                reason="group and role are retired together",
                idempotency_key=f"pg-cross-archive-{suffix}",
                now=_NOW + timedelta(minutes=5),
            ).status
        return service.retire_custom_role(
            owner_context_a,
            project_id=project_a,
            custom_role_id=race_role,
            expected_version=1,
            reason="group and role are retired together",
            idempotency_key=f"pg-cross-retire-{suffix}",
            now=_NOW + timedelta(minutes=5),
        ).status

    with ThreadPoolExecutor(max_workers=2) as pool:
        cross_lifecycle_outcomes = list(
            pool.map(_cross_lifecycle, ("archive", "retire"))
        )
    assert set(cross_lifecycle_outcomes) == {"archived", "retired"}

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        security_version, revoked_at, project_version = connection.execute(
            sa.text(
                "SELECT u.security_version, s.revoked_at, p.authorization_version "
                "FROM saas_global_users u JOIN saas_auth_sessions s ON s.user_id = u.id "
                "JOIN saas_projects p ON p.id = :project "
                "WHERE u.id = :member AND s.id = :session"
            ),
            {"project": project_a, "member": member_a, "session": issued.session_id},
        ).one()
        assert security_version == 4
        assert revoked_at is not None
        assert project_version in {13, 14}
        connection.exec_driver_sql("RESET ROLE")
        connection.exec_driver_sql(f"SET LOCAL ROLE {governance_role}")
        connection.execute(
            sa.text("SELECT set_config('app.actor_id', :value, true)"),
            {"value": str(owner_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :value, true)"),
            {"value": str(tenant_a)},
        )
        connection.execute(
            sa.text("SELECT set_config('app.space_id', :value, true)"),
            {"value": str(space_a)},
        )
        (
            archive_status,
            archived_by,
            archive_reason,
            archive_membership_status,
            archive_assignment_status,
            archive_session_revoked_at,
        ) = connection.execute(
            sa.text(
                "SELECT g.status, g.archived_by, g.archive_reason, m.status, a.status, "
                "s.revoked_at "
                "FROM saas_enterprise_groups g "
                "JOIN saas_enterprise_group_memberships m ON m.group_id = g.id "
                "JOIN saas_enterprise_group_role_assignments a ON a.group_id = g.id "
                "JOIN saas_auth_sessions s ON s.id = :session "
                "WHERE g.id = :group AND m.user_id = :member"
            ),
            {
                "group": archive_group,
                "member": member_a,
                "session": archive_session.session_id,
            },
        ).one()
        assert archive_status == "archived"
        assert archived_by == owner_a
        assert archive_reason == "directory group became authoritative"
        assert archive_membership_status == "removed"
        assert archive_assignment_status == "revoked"
        assert archive_session_revoked_at is not None
        retire_state = connection.execute(
            sa.text(
                "SELECT r.status, r.retired_by, r.retire_reason, a.status "
                "FROM saas_enterprise_custom_roles r "
                "JOIN saas_enterprise_group_role_assignments a ON a.custom_role_id = r.id "
                "WHERE r.id = :role"
            ),
            {"role": retire_role},
        ).one()
        assert retire_state == (
            "retired",
            owner_a,
            "role replaced by centrally governed role",
            "revoked",
        )
        connection.exec_driver_sql("RESET ROLE")
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        protected = set(
            connection.execute(
                sa.text(
                    "SELECT relname FROM pg_class WHERE relrowsecurity AND relforcerowsecurity "
                    "AND relname = ANY(:tables)"
                ),
                {"tables": sorted(CONTROL_PLANE_RLS_TABLES)},
            ).scalars()
        )
        assert protected == set(CONTROL_PLANE_RLS_TABLES)
        posture = connection.execute(
            sa.text(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname IN (:governance, :app) ORDER BY rolname"
            ),
            {"governance": governance_role, "app": app_role},
        ).all()
        assert len(posture) == 2
        assert all(not superuser and not bypass for _role, superuser, bypass in posture)
        connection.exec_driver_sql("RESET ROLE")
        connection.exec_driver_sql(f"REVOKE saas_governance FROM {governance_role}")
        connection.exec_driver_sql(f"REVOKE saas_app FROM {app_role}")
        connection.exec_driver_sql(f"DROP ROLE {governance_role}")
        connection.exec_driver_sql(f"DROP ROLE {app_role}")
    engine.dispose()
