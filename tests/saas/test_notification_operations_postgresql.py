from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError

from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for notification RLS acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _digest(value: int) -> str:
    return f"{value:064x}"


def _scope(
    connection: sa.Connection,
    *,
    realm: str,
    actor_realm: str,
    tenant_id: UUID | None,
    user_id: UUID | None = None,
    principal_id: UUID | None = None,
    work_item_id: UUID | None = None,
    delivery_id: UUID | None = None,
    template_id: UUID | None = None,
    operation_id: UUID | None = None,
    mutation: str = "read",
) -> None:
    connection.execute(
        sa.text(
            "SELECT "
            "set_config('app.notification_realm', :realm, true), "
            "set_config('app.notification_actor_realm', :actor_realm, true), "
            "set_config('app.notification_tenant_id', :tenant_id, true), "
            "set_config('app.notification_recipient_user_id', :user_id, true), "
            "set_config('app.notification_staff_principal_id', :principal_id, true), "
            "set_config('app.notification_work_item_id', :work_item_id, true), "
            "set_config('app.notification_delivery_id', :delivery_id, true), "
            "set_config('app.notification_template_id', :template_id, true), "
            "set_config('app.notification_source_operation_id', :operation_id, true), "
            "set_config('app.notification_source_authority', '', true), "
            "set_config('app.notification_source_support_grant_id', '', true), "
            "set_config('app.notification_mutation', :mutation, true)"
        ),
        {
            "realm": realm,
            "actor_realm": actor_realm,
            "tenant_id": str(tenant_id) if tenant_id else "",
            "user_id": str(user_id) if user_id else "",
            "principal_id": str(principal_id) if principal_id else "",
            "work_item_id": str(work_item_id) if work_item_id else "",
            "delivery_id": str(delivery_id) if delivery_id else "",
            "template_id": str(template_id) if template_id else "",
            "operation_id": str(operation_id) if operation_id else "",
            "mutation": mutation,
        },
    )


def _tenant_identity(connection: sa.Connection, *, user_id: UUID, tenant_id: UUID) -> None:
    connection.execute(
        sa.text(
            "SELECT set_config('app.actor_id', :user_id, true), "
            "set_config('app.tenant_id', :tenant_id, true)"
        ),
        {"user_id": str(user_id), "tenant_id": str(tenant_id)},
    )


def _staff_identity(connection: sa.Connection, *, principal_id: UUID) -> None:
    connection.execute(
        sa.text("SELECT set_config('app.platform_principal_id', :principal_id, true)"),
        {"principal_id": str(principal_id)},
    )


def _insert_work(
    connection: sa.Connection,
    *,
    work_id: UUID,
    tenant_id: UUID,
    requester_id: UUID,
    operation_id: UUID,
    now: datetime,
    assignee_id: UUID | None = None,
    realm: str = "tenant",
    requester_realm: str = "tenant",
    permission: str = "tenant.operation.approve",
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO saas_approval_work_items "
            "(id, realm, tenant_id, requester_realm, requested_by_user_id, "
            "requested_by_principal_id, assignee_user_id, assignee_principal_id, "
            "operation_kind, operation_id, action, target_type, target_locator_hmac, "
            "hmac_key_id, required_permission, risk_level, snapshot_hash, status, priority, "
            "due_at, escalation_at, escalation_count, version, created_at, updated_at) "
            "VALUES (:id, :realm, :tenant, :requester_realm, :requester_user, "
            ":requester_principal, :assignee_user, :assignee_principal, 'enterprise', "
            ":operation, 'approve_change', 'enterprise_preflight', :target_hmac, "
            "'notification-test-v1', :permission, 'high', :snapshot, 'pending', 'normal', "
            ":due, :escalation, 0, 1, :now, :now)"
        ),
        {
            "id": work_id,
            "realm": realm,
            "tenant": tenant_id,
            "requester_realm": requester_realm,
            "requester_user": requester_id if requester_realm == "tenant" else None,
            "requester_principal": requester_id if requester_realm == "staff" else None,
            "assignee_user": assignee_id if realm == "tenant" else None,
            "assignee_principal": assignee_id if realm == "staff" else None,
            "operation": operation_id,
            "target_hmac": _digest(work_id.int % 1000 + 100),
            "permission": permission,
            "snapshot": _digest(operation_id.int % 1000 + 1000),
            "due": now + timedelta(hours=1),
            "escalation": now + timedelta(minutes=5),
            "now": now,
        },
    )


def _insert_delivery(
    connection: sa.Connection,
    *,
    delivery_id: UUID,
    tenant_id: UUID,
    recipient_id: UUID,
    template_id: UUID,
    now: datetime,
    work_item_id: UUID | None = None,
    status: str = "pending",
    attempt_count: int = 0,
    last_error: bool = False,
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO saas_notification_deliveries "
            "(id, realm, tenant_id, recipient_user_id, recipient_principal_id, event_type, "
            "channel, template_id, approval_work_item_id, operation_batch_id, "
            "deduplication_key, recipient_locator_hmac, render_context_hmac, hmac_key_id, "
            "status, attempt_count, max_attempts, available_at, lease_generation, "
            "replay_generation, last_error_code, last_error_hmac, version, created_at, "
            "updated_at) VALUES (:id, 'tenant', :tenant, :recipient, NULL, "
            "'approval.reminder', 'in_app', :template, :work, NULL, :dedup, :recipient_hmac, "
            ":context_hmac, 'notification-test-v1', :status, :attempt_count, 8, :now, "
            ":lease_generation, 0, :error_code, :error_hmac, 1, :now, :now)"
        ),
        {
            "id": delivery_id,
            "tenant": tenant_id,
            "recipient": recipient_id,
            "template": template_id,
            "work": work_item_id,
            "dedup": _digest(delivery_id.int % 1_000_000 + 10_000),
            "recipient_hmac": _digest(delivery_id.int % 1_000_000 + 20_000),
            "context_hmac": _digest(delivery_id.int % 1_000_000 + 30_000),
            "status": status,
            "attempt_count": attempt_count,
            "lease_generation": attempt_count,
            "error_code": "provider_rejected" if last_error else None,
            "error_hmac": _digest(99) if last_error else None,
            "now": now,
        },
    )


def _assert_sqlstate(error: pytest.ExceptionInfo[DBAPIError], expected: str) -> None:
    assert getattr(error.value.orig, "sqlstate", None) == expected


def test_real_postgresql_notification_approval_security_and_worker_contracts() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_pre_ping=True)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    tenant_a, tenant_b = uuid4(), uuid4()
    requester, approver, assignee, delegate, outsider, tenant_b_user = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    operator, staff_assignee, staff_delegate, staff_outsider = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    template_global, template_a, template_b = uuid4(), uuid4(), uuid4()
    work_send, operation_send = uuid4(), uuid4()
    work_delegated, operation_delegated = uuid4(), uuid4()
    staff_work, staff_operation = uuid4(), uuid4()
    enterprise_work, enterprise_operation = uuid4(), uuid4()
    delivery_send, delivery_terminal, delivery_dlq = uuid4(), uuid4(), uuid4()

    with engine.begin() as connection:
        _migrate(connection, root)
        authority = (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        connection.exec_driver_sql(authority)
        connection.exec_driver_sql(authority)

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users "
                "(id, status, security_version, created_at, updated_at) VALUES "
                "(:requester, 'active', 1, :now, :now), "
                "(:approver, 'active', 1, :now, :now), "
                "(:assignee, 'active', 1, :now, :now), "
                "(:delegate, 'active', 1, :now, :now), "
                "(:outsider, 'active', 1, :now, :now), "
                "(:tenant_b_user, 'active', 1, :now, :now)"
            ),
            {
                "requester": requester,
                "approver": approver,
                "assignee": assignee,
                "delegate": delegate,
                "outsider": outsider,
                "tenant_b_user": tenant_b_user,
                "now": now,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, lifecycle_version, "
                "created_at, updated_at) VALUES "
                "(:tenant_a, :slug_a, 'Notification A', 'active', 'enterprise', "
                "'cn-east-1', 1, :now, :now), "
                "(:tenant_b, :slug_b, 'Notification B', 'active', 'enterprise', "
                "'cn-east-1', 1, :now, :now)"
            ),
            {
                "tenant_a": tenant_a,
                "slug_a": f"notification-a-{tenant_a.hex}",
                "tenant_b": tenant_b,
                "slug_b": f"notification-b-{tenant_b.hex}",
                "now": now,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version, joined_at) VALUES "
                "(:tenant_a, :requester, 'owner', 'active', 1, :now), "
                "(:tenant_a, :approver, 'admin', 'active', 1, :now), "
                "(:tenant_a, :assignee, 'admin', 'active', 1, :now), "
                "(:tenant_a, :delegate, 'admin', 'active', 1, :now), "
                "(:tenant_a, :outsider, 'admin', 'active', 1, :now), "
                "(:tenant_b, :tenant_b_user, 'owner', 'active', 1, :now)"
            ),
            {
                "tenant_a": tenant_a,
                "tenant_b": tenant_b,
                "requester": requester,
                "approver": approver,
                "assignee": assignee,
                "delegate": delegate,
                "outsider": outsider,
                "tenant_b_user": tenant_b_user,
                "now": now,
            },
        )
        staff = (operator, staff_assignee, staff_delegate, staff_outsider)
        for principal in staff:
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_staff_principals "
                    "(id, identity_connection_ref, issuer, subject, status, security_version, "
                    "created_at, updated_at) VALUES (:id, :ref, 'https://staff.test', "
                    ":subject, 'active', 1, :now, :now)"
                ),
                {
                    "id": principal,
                    "ref": f"staff:{principal}",
                    "subject": str(principal),
                    "now": now,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_role_assignments "
                    "(id, principal_id, role, status, version, assigned_by_principal_id, "
                    "approval_ref, reason, created_at, updated_at) VALUES "
                    "(:id, :principal, :role, 'active', 1, :operator, "
                    "'notification-acceptance', 'notification acceptance', :now, :now)"
                ),
                {
                    "id": uuid4(),
                    "principal": principal,
                    "role": "platform_operator" if principal == operator else "support_agent",
                    "operator": operator,
                    "now": now,
                },
            )
        for template, tenant, version in (
            (template_global, None, 1),
            (template_a, tenant_a, 2),
            (template_b, tenant_b, 2),
        ):
            connection.execute(
                sa.text(
                    "INSERT INTO saas_notification_templates "
                    "(id, realm, tenant_id, created_by_principal_id, template_key, channel, "
                    "locale, version, content_artifact_handle, content_sha256, "
                    "variables_schema_sha256, hmac_key_id, create_idempotency_hmac, "
                    "create_request_hmac, status, created_at) VALUES "
                    "(:id, 'staff', :tenant, :operator, :template_key, 'in_app', "
                    "'en-US', :version, :handle, :content, :schema, 'notification-test-v1', "
                    ":idempotency, :request, 'active', :now)"
                ),
                {
                    "id": template,
                    "tenant": tenant,
                    "operator": operator,
                    "template_key": f"approval.reminder.{template.hex}",
                    "version": version,
                    "handle": f"artifact{template.hex}",
                    "content": _digest(template.int % 1000 + 1),
                    "schema": _digest(template.int % 1000 + 2000),
                    "idempotency": _digest(template.int % 1000 + 4000),
                    "request": _digest(template.int % 1000 + 6000),
                    "now": now,
                },
            )
        _insert_work(
            connection,
            work_id=work_send,
            tenant_id=tenant_a,
            requester_id=requester,
            operation_id=operation_send,
            now=now,
        )
        _insert_work(
            connection,
            work_id=work_delegated,
            tenant_id=tenant_a,
            requester_id=requester,
            assignee_id=assignee,
            operation_id=operation_delegated,
            now=now,
        )
        _insert_work(
            connection,
            work_id=staff_work,
            tenant_id=tenant_a,
            requester_id=operator,
            assignee_id=staff_assignee,
            operation_id=staff_operation,
            now=now,
            realm="staff",
            requester_realm="staff",
            permission="platform.operation.approve",
        )
        for delegation_id, realm, delegator, delegated_to, operation, permission in (
            (
                uuid4(),
                "tenant",
                assignee,
                delegate,
                operation_delegated,
                "tenant.operation.approve",
            ),
            (
                uuid4(),
                "staff",
                staff_assignee,
                staff_delegate,
                staff_operation,
                "platform.operation.approve",
            ),
        ):
            connection.execute(
                sa.text(
                    "INSERT INTO saas_approval_delegations "
                    "(id, realm, tenant_id, delegator_user_id, delegator_principal_id, "
                    "delegate_user_id, delegate_principal_id, permission_code, scope_type, "
                    "scope_id, starts_at, expires_at, status, reason_hmac, hmac_key_id, "
                    "create_idempotency_hmac, create_request_hmac, version, created_at, "
                    "updated_at) VALUES (:id, :realm, :tenant, :delegator_user, "
                    ":delegator_principal, :delegate_user, :delegate_principal, :permission, "
                    "'operation', :scope, :starts, :expires, 'active', :reason, "
                    "'notification-test-v1', :idempotency, :request, 1, :now, :now)"
                ),
                {
                    "id": delegation_id,
                    "realm": realm,
                    "tenant": tenant_a,
                    "delegator_user": delegator if realm == "tenant" else None,
                    "delegator_principal": delegator if realm == "staff" else None,
                    "delegate_user": delegated_to if realm == "tenant" else None,
                    "delegate_principal": delegated_to if realm == "staff" else None,
                    "permission": permission,
                    "scope": operation,
                    "starts": now - timedelta(minutes=1),
                    "expires": now + timedelta(hours=1),
                    "reason": _digest(delegation_id.int % 1000 + 8000),
                    "idempotency": _digest(delegation_id.int % 1000 + 9000),
                    "request": _digest(delegation_id.int % 1000 + 10_000),
                    "now": now,
                },
            )
        expired_delegation = uuid4()
        connection.execute(
            sa.text(
                "INSERT INTO saas_approval_delegations "
                "(id, realm, tenant_id, delegator_user_id, delegator_principal_id, "
                "delegate_user_id, delegate_principal_id, permission_code, scope_type, "
                "scope_id, starts_at, expires_at, status, reason_hmac, hmac_key_id, "
                "create_idempotency_hmac, create_request_hmac, version, created_at, "
                "updated_at) VALUES (:id, 'tenant', :tenant, :delegator, NULL, :delegate, "
                "NULL, 'tenant.operation.approve', 'operation', :scope, :starts, :expires, "
                "'expired', :reason, 'notification-test-v1', :idempotency, :request, 1, "
                ":created, :created)"
            ),
            {
                "id": expired_delegation,
                "tenant": tenant_a,
                "delegator": assignee,
                "delegate": delegate,
                "scope": operation_delegated,
                "starts": now - timedelta(hours=3),
                "expires": now - timedelta(hours=1),
                "reason": _digest(43),
                "idempotency": _digest(44),
                "request": _digest(45),
                "created": now - timedelta(hours=4),
            },
        )
        _insert_delivery(
            connection,
            delivery_id=delivery_send,
            tenant_id=tenant_a,
            recipient_id=requester,
            template_id=template_global,
            work_item_id=work_send,
            now=now,
        )
        _insert_delivery(
            connection,
            delivery_id=delivery_dlq,
            tenant_id=tenant_a,
            recipient_id=requester,
            template_id=template_a,
            now=now,
            status="dead_letter",
            attempt_count=8,
            last_error=True,
        )

    with engine.begin() as connection:
        protected = connection.execute(
            sa.select(sa.literal_column("relname"))
            .select_from(
                sa.text("pg_class JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace")
            )
            .where(
                sa.literal_column("nspname") == "public",
                sa.literal_column("relname").in_(CONTROL_PLANE_RLS_TABLES),
                sa.literal_column("relrowsecurity"),
                sa.literal_column("relforcerowsecurity"),
            )
        ).scalars()
        assert set(protected) == set(CONTROL_PLANE_RLS_TABLES)
        role_facts = connection.execute(
            sa.text(
                "SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, rolinherit "
                "FROM pg_roles WHERE rolname IN "
                "('saas_notification_scheduler', 'saas_notification_dispatcher') "
                "ORDER BY rolname"
            )
        ).all()
        assert role_facts == [
            ("saas_notification_dispatcher", False, False, False, True),
            ("saas_notification_scheduler", False, False, False, True),
        ]
        assert connection.execute(
            sa.text(
                "SELECT has_column_privilege('saas_notification_scheduler', "
                "'saas_approval_work_items', 'priority', 'UPDATE'), "
                "has_column_privilege('saas_notification_scheduler', "
                "'saas_approval_work_items', 'escalation_at', 'UPDATE'), "
                "has_column_privilege('saas_notification_scheduler', "
                "'saas_approval_work_items', 'action', 'UPDATE'), "
                "has_column_privilege('saas_notification_dispatcher', "
                "'saas_approval_work_items', 'status', 'SELECT'), "
                "has_column_privilege('saas_notification_dispatcher', "
                "'saas_approval_work_items', 'action', 'SELECT')"
            )
        ).one() == (True, True, False, True, False)

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
        _tenant_identity(connection, user_id=delegate, tenant_id=tenant_a)
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=delegate,
            work_item_id=work_delegated,
            operation_id=operation_delegated,
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_approval_work_items WHERE id = :id"),
                {"id": work_delegated},
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                sa.text(
                    "UPDATE saas_approval_work_items SET priority = 'high', "
                    "version = version + 1, updated_at = :now WHERE id = :id"
                ),
                {"id": work_delegated, "now": now + timedelta(seconds=1)},
            ).rowcount
            == 1
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
        _tenant_identity(connection, user_id=outsider, tenant_id=tenant_a)
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=outsider,
            work_item_id=work_delegated,
            operation_id=operation_delegated,
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_approval_work_items WHERE id = :id"),
                {"id": work_delegated},
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                sa.text("UPDATE saas_approval_work_items SET updated_at = :now WHERE id = :id"),
                {"id": work_delegated, "now": now + timedelta(seconds=2)},
            ).rowcount
            == 0
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform_governance")
        _staff_identity(connection, principal_id=staff_delegate)
        _scope(
            connection,
            realm="staff",
            actor_realm="staff",
            tenant_id=tenant_a,
            principal_id=staff_delegate,
            work_item_id=staff_work,
            operation_id=staff_operation,
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_approval_work_items WHERE id = :id"),
                {"id": staff_work},
            ).scalar_one()
            == 1
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform_governance")
        _staff_identity(connection, principal_id=staff_outsider)
        _scope(
            connection,
            realm="staff",
            actor_realm="staff",
            tenant_id=tenant_a,
            principal_id=staff_outsider,
            work_item_id=staff_work,
            operation_id=staff_operation,
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_approval_work_items WHERE id = :id"),
                {"id": staff_work},
            ).scalar_one()
            == 0
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform_governance")
        _staff_identity(connection, principal_id=staff_delegate)
        _scope(
            connection,
            realm="staff",
            actor_realm="staff",
            tenant_id=tenant_b,
            principal_id=staff_delegate,
            work_item_id=staff_work,
            operation_id=staff_operation,
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_approval_work_items WHERE id = :id"),
                {"id": staff_work},
            ).scalar_one()
            == 0
        )

    with pytest.raises(DBAPIError) as enterprise_wrong_tenant:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
            _tenant_identity(connection, user_id=tenant_b_user, tenant_id=tenant_b)
            wrong_work, wrong_operation = uuid4(), uuid4()
            _scope(
                connection,
                realm="tenant",
                actor_realm="tenant",
                tenant_id=tenant_b,
                user_id=tenant_b_user,
                work_item_id=wrong_work,
                operation_id=wrong_operation,
                mutation="project",
            )
            connection.execute(
                sa.text(
                    "SELECT set_config('app.notification_source_authority', 'enterprise', true)"
                )
            )
            _insert_work(
                connection,
                work_id=wrong_work,
                tenant_id=tenant_a,
                requester_id=tenant_b_user,
                operation_id=wrong_operation,
                now=now,
            )
    _assert_sqlstate(enterprise_wrong_tenant, "42501")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
        _tenant_identity(connection, user_id=requester, tenant_id=tenant_a)
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=requester,
            work_item_id=enterprise_work,
            operation_id=enterprise_operation,
            mutation="project",
        )
        connection.execute(
            sa.text("SELECT set_config('app.notification_source_authority', 'enterprise', true)")
        )
        _insert_work(
            connection,
            work_id=enterprise_work,
            tenant_id=tenant_a,
            requester_id=requester,
            operation_id=enterprise_operation,
            now=now,
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
        _tenant_identity(connection, user_id=approver, tenant_id=tenant_a)
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=approver,
            work_item_id=enterprise_work,
            operation_id=enterprise_operation,
            mutation="terminal",
        )
        assert (
            connection.execute(
                sa.text(
                    "UPDATE saas_approval_work_items SET status = 'approved', "
                    "decided_by_user_id = :approver, decision_code = 'enterprise_approved', "
                    "decided_at = :now, version = version + 1, updated_at = :now WHERE id = :id"
                ),
                {
                    "approver": approver,
                    "now": now + timedelta(seconds=3),
                    "id": enterprise_work,
                },
            ).rowcount
            == 1
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        _insert_delivery(
            connection,
            delivery_id=delivery_terminal,
            tenant_id=tenant_a,
            recipient_id=requester,
            template_id=template_global,
            work_item_id=enterprise_work,
            now=now,
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_notification_scheduler")
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_approval_work_items WHERE status = 'pending'")
            ).scalar_one()
            >= 3
        )
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=requester,
            work_item_id=work_send,
            operation_id=operation_send,
            mutation="scheduler",
        )
        assert (
            connection.execute(
                sa.text(
                    "UPDATE saas_approval_work_items SET priority = 'high', "
                    "escalation_at = :escalation, escalation_count = 1, version = 2, "
                    "updated_at = :updated WHERE id = :id"
                ),
                {
                    "escalation": now + timedelta(minutes=20),
                    "updated": now + timedelta(minutes=5),
                    "id": work_send,
                },
            ).rowcount
            == 1
        )

    with pytest.raises(DBAPIError) as source_binding:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_notification_scheduler")
            _scope(
                connection,
                realm="tenant",
                actor_realm="tenant",
                tenant_id=tenant_a,
                user_id=requester,
                work_item_id=work_send,
                operation_id=operation_send,
                mutation="scheduler",
            )
            connection.execute(
                sa.text("UPDATE saas_approval_work_items SET action = 'forged' WHERE id = :id"),
                {"id": work_send},
            )
    _assert_sqlstate(source_binding, "42501")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_notification_dispatcher")
        assert (
            connection.execute(
                sa.text(
                    "SELECT count(*) FROM saas_notification_deliveries "
                    "WHERE status IN ('pending', 'retry')"
                )
            ).scalar_one()
            >= 2
        )
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=requester,
            work_item_id=work_send,
            delivery_id=delivery_send,
            template_id=template_global,
            mutation="dispatch",
        )
        assert (
            connection.execute(
                sa.text("SELECT status FROM saas_approval_work_items WHERE id = :id"),
                {"id": work_send},
            ).scalar_one()
            == "pending"
        )
        connection.execute(
            sa.text(
                "UPDATE saas_notification_deliveries SET status = 'leased', "
                "attempt_count = 1, leased_at = :now, lease_expires_at = :expires, "
                "lease_token_hash = :lease, executor_identity_sha256 = :executor, "
                "lease_generation = 1, version = 2, updated_at = :now WHERE id = :id"
            ),
            {
                "now": now + timedelta(minutes=1),
                "expires": now + timedelta(minutes=2),
                "lease": _digest(31),
                "executor": _digest(32),
                "id": delivery_send,
            },
        )
        assert (
            connection.execute(
                sa.text("SELECT status FROM saas_notification_deliveries WHERE id = :id"),
                {"id": delivery_send},
            ).scalar_one()
            == "leased"
        )
        attempt_id = uuid4()
        connection.execute(
            sa.text(
                "INSERT INTO saas_notification_delivery_attempts "
                "(id, delivery_id, realm, tenant_id, recipient_user_id, "
                "recipient_principal_id, attempt_number, lease_generation, outcome, "
                "content_hmac, provider_request_hmac, provider_receipt_hmac, hmac_key_id, "
                "executor_identity_sha256, started_at, completed_at, created_at) VALUES "
                "(:id, :delivery, 'tenant', :tenant, :recipient, NULL, 1, 1, 'succeeded', "
                ":content, :request, :receipt, 'notification-test-v1', :executor, "
                ":started, :completed, :completed)"
            ),
            {
                "id": attempt_id,
                "delivery": delivery_send,
                "tenant": tenant_a,
                "recipient": requester,
                "content": _digest(delivery_send.int % 1_000_000 + 30_000),
                "request": _digest(33),
                "receipt": _digest(34),
                "executor": _digest(32),
                "started": now + timedelta(minutes=1),
                "completed": now + timedelta(minutes=1, seconds=1),
            },
        )
        connection.execute(
            sa.text(
                "UPDATE saas_notification_deliveries SET status = 'succeeded', "
                "leased_at = NULL, lease_expires_at = NULL, lease_token_hash = NULL, "
                "executor_identity_sha256 = NULL, provider_message_hmac = :provider, "
                "delivered_at = :delivered, version = 3, updated_at = :delivered "
                "WHERE id = :id"
            ),
            {
                "provider": _digest(35),
                "delivered": now + timedelta(minutes=1, seconds=1),
                "id": delivery_send,
            },
        )

    with pytest.raises(DBAPIError) as dispatcher_ack:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_notification_dispatcher")
            _scope(
                connection,
                realm="tenant",
                actor_realm="tenant",
                tenant_id=tenant_a,
                user_id=requester,
                delivery_id=delivery_send,
                template_id=template_global,
                mutation="dispatch",
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_notification_deliveries SET recipient_read_at = :now "
                    "WHERE id = :id"
                ),
                {"now": now + timedelta(minutes=2), "id": delivery_send},
            )
    _assert_sqlstate(dispatcher_ack, "42501")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
        _tenant_identity(connection, user_id=requester, tenant_id=tenant_a)
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=requester,
            delivery_id=delivery_send,
            template_id=template_global,
            mutation="ack",
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_notification_deliveries")
            ).scalar_one()
            == 3
        )
        connection.execute(
            sa.text(
                "UPDATE saas_notification_deliveries SET recipient_read_at = :read_at, "
                "read_idempotency_hmac = :idempotency, read_request_hmac = :request, "
                "version = 4, updated_at = :read_at WHERE id = :id"
            ),
            {
                "read_at": now + timedelta(minutes=2),
                "idempotency": _digest(36),
                "request": _digest(37),
                "id": delivery_send,
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_notification_dispatcher")
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=requester,
            work_item_id=enterprise_work,
            delivery_id=delivery_terminal,
            template_id=template_global,
            mutation="dispatch",
        )
        assert (
            connection.execute(
                sa.text("SELECT status FROM saas_approval_work_items WHERE id = :id"),
                {"id": enterprise_work},
            ).scalar_one()
            == "approved"
        )
        connection.execute(
            sa.text(
                "UPDATE saas_notification_deliveries SET status = 'suppressed', "
                "suppression_code = 'approval_terminal', version = 2, updated_at = :now "
                "WHERE id = :id"
            ),
            {"now": now + timedelta(minutes=3), "id": delivery_terminal},
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform_governance")
        _staff_identity(connection, principal_id=operator)
        _scope(
            connection,
            realm="tenant",
            actor_realm="staff",
            tenant_id=tenant_a,
            principal_id=operator,
            delivery_id=delivery_dlq,
            template_id=template_a,
            mutation="replay",
        )
        assert delivery_dlq in set(
            connection.execute(
                sa.text("SELECT id FROM saas_notification_deliveries WHERE status = 'dead_letter'")
            ).scalars()
        )
        connection.execute(
            sa.text(
                "UPDATE saas_notification_deliveries SET status = 'pending', "
                "attempt_count = 0, available_at = :available, replay_generation = 1, "
                "replay_receipt_generation = 1, replay_idempotency_hmac = :idempotency, "
                "replay_request_hmac = :request, last_error_code = NULL, "
                "last_error_hmac = NULL, version = 2, updated_at = :available WHERE id = :id"
            ),
            {
                "available": datetime.now(timezone.utc) + timedelta(seconds=1),
                "idempotency": _digest(38),
                "request": _digest(39),
                "id": delivery_dlq,
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
        _tenant_identity(connection, user_id=requester, tenant_id=tenant_a)
        _scope(
            connection,
            realm="staff",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=requester,
            mutation="template_list",
        )
        visible_templates = set(
            connection.execute(sa.text("SELECT id FROM saas_notification_templates")).scalars()
        )
        assert visible_templates == {template_global, template_a}

    with pytest.raises(DBAPIError) as cross_tenant_template:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            _insert_delivery(
                connection,
                delivery_id=uuid4(),
                tenant_id=tenant_a,
                recipient_id=requester,
                template_id=template_b,
                now=now,
            )
    _assert_sqlstate(cross_tenant_template, "42501")

    with pytest.raises(DBAPIError) as template_mutation:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_notification_templates SET content_sha256 = :content "
                    "WHERE id = :id"
                ),
                {"content": _digest(40), "id": template_a},
            )
    _assert_sqlstate(template_mutation, "55000")

    with pytest.raises(DBAPIError) as attempt_mutation:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_notification_dispatcher")
            _scope(
                connection,
                realm="tenant",
                actor_realm="tenant",
                tenant_id=tenant_a,
                user_id=requester,
                delivery_id=delivery_send,
                template_id=template_global,
                mutation="dispatch",
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_notification_delivery_attempts SET outcome = 'dead_letter' "
                    "WHERE id = :id"
                ),
                {"id": attempt_id},
            )
    _assert_sqlstate(attempt_mutation, "42501")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "UPDATE saas_approval_delegations SET status = 'revoked', "
                "revoke_idempotency_hmac = :idempotency, revoke_request_hmac = :request, "
                "revoked_at = :now, version = version + 1, updated_at = :now "
                "WHERE realm = 'tenant' AND scope_id = :scope"
            ),
            {
                "idempotency": _digest(41),
                "request": _digest(42),
                "now": now + timedelta(minutes=4),
                "scope": operation_delegated,
            },
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
        _tenant_identity(connection, user_id=delegate, tenant_id=tenant_a)
        _scope(
            connection,
            realm="tenant",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=delegate,
            work_item_id=work_delegated,
            operation_id=operation_delegated,
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_approval_work_items WHERE id = :id"),
                {"id": work_delegated},
            ).scalar_one()
            == 0
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "UPDATE saas_platform_staff_principals SET status = 'suspended', "
                "updated_at = :now WHERE id = :id"
            ),
            {"now": now + timedelta(minutes=5), "id": operator},
        )
        connection.execute(
            sa.text(
                "UPDATE saas_global_users SET status = 'suspended', "
                "updated_at = :now WHERE id = :id"
            ),
            {"now": now + timedelta(minutes=5), "id": requester},
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform_governance")
        _staff_identity(connection, principal_id=operator)
        _scope(
            connection,
            realm="staff",
            actor_realm="staff",
            tenant_id=None,
            principal_id=operator,
            mutation="template_list",
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_notification_templates")
            ).scalar_one()
            == 0
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_governance")
        _tenant_identity(connection, user_id=requester, tenant_id=tenant_a)
        _scope(
            connection,
            realm="staff",
            actor_realm="tenant",
            tenant_id=tenant_a,
            user_id=requester,
            mutation="template_list",
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_notification_templates")
            ).scalar_one()
            == 0
        )

    engine.dispose()
