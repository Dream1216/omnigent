from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError

SOURCE_ROLES = {
    "enterprise": "saas_approval_scheduler_enterprise",
    "privacy": "saas_approval_scheduler_privacy",
    "audit": "saas_approval_scheduler_audit",
    "support.customer": "saas_approval_scheduler_support_customer",
    "support.staff": "saas_approval_scheduler_support_staff",
}


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for source-role RLS")
    return url


def _config(root: Path, connection: sa.Connection) -> Config:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    return config


def _digest(value: int) -> str:
    return f"{value:064x}"


def _sqlstate(error: pytest.ExceptionInfo[DBAPIError]) -> str | None:
    return getattr(error.value.orig, "sqlstate", None)


def _login_url(source: str, *, username: str, password: str) -> URL:
    parsed = make_url(source)
    query_host_value = parsed.query.get("host")
    query_host = query_host_value if isinstance(query_host_value, str) else None
    query_port_value = parsed.query.get("port")
    query_port = query_port_value if isinstance(query_port_value, str) else None
    host = parsed.host or (query_host if query_host and not query_host.startswith("/") else None)
    return URL.create(
        "postgresql+psycopg",
        username=username,
        password=password,
        host=host or "localhost",
        port=parsed.port or (int(query_port) if query_port is not None else 5432),
        database=parsed.database,
    )


def _source_context(
    connection: sa.Connection,
    *,
    kind: str,
    mutation: str,
    realm: str,
    tenant_id: UUID | None,
    operation_id: UUID | None = None,
    subject_id: UUID | None = None,
    work_item_id: UUID | None = None,
) -> None:
    connection.execute(
        sa.text(
            "SELECT set_config('app.approval_source_kind', :kind, true), "
            "set_config('app.approval_source_mutation', :mutation, true), "
            "set_config('app.approval_source_realm', :realm, true), "
            "set_config('app.approval_source_tenant_id', :tenant, true), "
            "set_config('app.approval_source_operation_id', :operation, true), "
            "set_config('app.approval_source_subject_id', :subject, true), "
            "set_config('app.approval_source_work_item_id', :work, true)"
        ),
        {
            "kind": kind,
            "mutation": mutation,
            "realm": realm,
            "tenant": str(tenant_id) if tenant_id else "",
            "operation": str(operation_id) if operation_id else "",
            "subject": str(subject_id) if subject_id else "",
            "work": str(work_item_id) if work_item_id else "",
        },
    )


def _notification_context(
    connection: sa.Connection,
    *,
    realm: str,
    tenant_id: UUID,
    recipient_id: UUID,
    work_item_id: UUID,
    delivery_id: UUID,
    template_id: UUID,
) -> None:
    connection.execute(
        sa.text(
            "SELECT set_config('app.notification_realm', :realm, true), "
            "set_config('app.notification_tenant_id', :tenant, true), "
            "set_config('app.notification_recipient_user_id', :user, true), "
            "set_config('app.notification_staff_principal_id', :principal, true), "
            "set_config('app.notification_work_item_id', :work, true), "
            "set_config('app.notification_batch_id', '', true), "
            "set_config('app.notification_delivery_id', :delivery, true), "
            "set_config('app.notification_template_id', :template, true), "
            "set_config('app.notification_mutation', 'enqueue', true), "
            "set_config('app.notification_event_type', 'approval.requested', true), "
            "set_config('app.notification_channels', 'in_app', true), "
            "set_config('app.notification_locale', 'en-US', true)"
        ),
        {
            "realm": realm,
            "tenant": str(tenant_id),
            "user": str(recipient_id) if realm == "tenant" else "",
            "principal": str(recipient_id) if realm == "staff" else "",
            "work": str(work_item_id),
            "delivery": str(delivery_id),
            "template": str(template_id),
        },
    )


def _insert_work(
    connection: sa.Connection,
    *,
    work_id: UUID,
    operation_id: UUID,
    operation_kind: str,
    realm: str,
    tenant_id: UUID | None,
    requester_id: UUID,
    snapshot_hash: str,
    now: datetime,
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO saas_approval_work_items ("
            "id, realm, tenant_id, requester_realm, requested_by_user_id, "
            "requested_by_principal_id, assignee_user_id, assignee_principal_id, "
            "operation_kind, operation_id, action, target_type, target_locator_hmac, "
            "hmac_key_id, required_permission, risk_level, snapshot_hash, status, "
            "priority, due_at, escalation_at, escalation_count, version, created_at, "
            "updated_at) VALUES ("
            ":id, :realm, :tenant, 'staff', NULL, :requester, NULL, NULL, :kind, "
            ":operation, :action, :target_type, :target_hash, 'source-role-test-v1', "
            ":permission, 'high', :snapshot, 'pending', 'high', :due, :escalation, "
            "0, 1, :now, :now)"
        ),
        {
            "id": work_id,
            "realm": realm,
            "tenant": tenant_id,
            "requester": requester_id,
            "kind": operation_kind,
            "operation": operation_id,
            "action": f"{operation_kind}.approve",
            "target_type": (
                "support_grant" if operation_kind.startswith("support") else "operation"
            ),
            "target_hash": _digest(work_id.int % 10_000 + 1),
            "permission": (
                "support.customer.approve"
                if operation_kind == "support.customer"
                else "platform.support_grant.manage"
                if operation_kind == "support.staff"
                else "platform.operation.approve"
            ),
            "snapshot": snapshot_hash,
            "due": now + timedelta(hours=1),
            "escalation": now + timedelta(minutes=5),
            "now": now,
        },
    )


def _insert_delivery(
    connection: sa.Connection,
    *,
    delivery_id: UUID,
    realm: str,
    tenant_id: UUID,
    recipient_id: UUID,
    template_id: UUID,
    work_item_id: UUID,
    now: datetime,
) -> None:
    connection.execute(
        sa.text(
            "INSERT INTO saas_notification_deliveries ("
            "id, realm, tenant_id, recipient_user_id, recipient_principal_id, "
            "event_type, channel, template_id, approval_work_item_id, operation_batch_id, "
            "source_delivery_id, deduplication_key, recipient_locator_hmac, "
            "render_context_hmac, hmac_key_id, status, attempt_count, max_attempts, "
            "available_at, lease_generation, replay_generation, version, created_at, "
            "updated_at) VALUES ("
            ":id, :realm, :tenant, :user, :principal, 'approval.requested', 'in_app', "
            ":template, :work, NULL, NULL, :dedupe, :recipient_hash, :context_hash, "
            "'source-role-test-v1', 'pending', 0, 8, :now, 0, 0, 1, :now, :now)"
        ),
        {
            "id": delivery_id,
            "realm": realm,
            "tenant": tenant_id,
            "user": recipient_id if realm == "tenant" else None,
            "principal": recipient_id if realm == "staff" else None,
            "template": template_id,
            "work": work_item_id,
            "dedupe": _digest(delivery_id.int % 100_000 + 10_000),
            "recipient_hash": _digest(delivery_id.int % 100_000 + 20_000),
            "context_hash": _digest(delivery_id.int % 100_000 + 30_000),
            "now": now,
        },
    )


def test_source_roles_cross_realm_forgery_and_n_minus_one_rollback() -> None:
    root = Path(__file__).resolve().parents[2]
    base_url = make_url(_postgres_url())
    role_sql = (root / "saas/control_plane/postgresql_roles.sql").read_text(
        encoding="utf-8"
    )
    login_suffix = uuid4().hex[:10]
    database_name = f"omnigent_notification_source_{login_suffix}"
    database_url = base_url.set(database=database_name)
    postgres_url = database_url.render_as_string(hide_password=False)
    admin_engine = sa.create_engine(base_url, isolation_level="AUTOCOMMIT")
    engine = sa.create_engine(database_url, pool_pre_ping=True)
    database_created = False
    password = f"SourceRole-{uuid4().hex}"
    login_engines: dict[str, sa.Engine] = {}
    login_names: dict[str, str] = {}
    now = datetime.now(timezone.utc).replace(microsecond=0)

    try:
        with admin_engine.connect() as connection:
            server_version = connection.exec_driver_sql("SHOW server_version_num").scalar_one()
            assert int(server_version) >= 180000
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
        database_created = True
        with engine.begin() as connection:
            config = _config(root, connection)
            command.upgrade(config, "pc5c00000001")
            assert connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one() == "pc5c00000001"
            command.upgrade(config, "pc5c00000002")
            connection.exec_driver_sql(role_sql)

            role_facts = connection.execute(
                sa.text(
                    "SELECT rolname, rolcanlogin, rolsuper, rolbypassrls FROM pg_roles "
                    "WHERE rolname = ANY(:roles) ORDER BY rolname"
                ),
                {"roles": list(SOURCE_ROLES.values())},
            ).all()
            assert role_facts == [
                (role, False, False, False) for role in sorted(SOURCE_ROLES.values())
            ]

            for index, (kind, source_role) in enumerate(SOURCE_ROLES.items()):
                login = f"notif_src_{index}_{login_suffix}"
                quoted = connection.dialect.identifier_preparer.quote(login)
                connection.exec_driver_sql(
                    f"CREATE ROLE {quoted} LOGIN INHERIT NOSUPERUSER NOBYPASSRLS "
                    f"PASSWORD '{password}'"
                )
                connection.exec_driver_sql(f"GRANT {source_role} TO {quoted}")
                login_names[kind] = login

        for kind, login in login_names.items():
            login_engine = sa.create_engine(
                _login_url(postgres_url, username=login, password=password),
                pool_pre_ping=True,
            )
            login_engines[kind] = login_engine
            own_query = {
                "enterprise": "SELECT count(id) FROM saas_enterprise_access_preflights",
                "privacy": "SELECT count(operation_id) FROM saas_privacy_approval_bindings",
                "audit": (
                    "SELECT count(id) FROM saas_platform_admin_operations "
                    "WHERE action = 'audit_export'"
                ),
                "support.customer": "SELECT count(id) FROM saas_platform_support_grants",
                "support.staff": "SELECT count(id) FROM saas_platform_support_grants",
            }[kind]
            with login_engine.begin() as connection:
                _source_context(
                    connection,
                    kind=kind,
                    mutation="scan",
                    realm="tenant" if kind in {"enterprise", "support.customer"} else "staff",
                    tenant_id=None,
                )
                assert connection.execute(sa.text(own_query)).scalar_one() == 0
                assert connection.execute(
                    sa.text("SELECT pg_has_role(current_user, :role, 'member')"),
                    {"role": SOURCE_ROLES[kind]},
                ).scalar_one()

            wrong_query = (
                "SELECT id FROM saas_platform_admin_operations LIMIT 1"
                if kind == "enterprise"
                else "SELECT id FROM saas_enterprise_access_preflights LIMIT 1"
            )
            with pytest.raises(DBAPIError) as wrong_source:
                with login_engine.begin() as connection:
                    connection.execute(sa.text(wrong_query))
            assert _sqlstate(wrong_source) == "42501"

            fake_operation, fake_work, fake_tenant, fake_requester = (
                uuid4(),
                uuid4(),
                uuid4(),
                uuid4(),
            )
            realm = "tenant" if kind in {"enterprise", "support.customer"} else "staff"
            with pytest.raises(DBAPIError) as forged_source:
                with login_engine.begin() as connection:
                    _source_context(
                        connection,
                        kind=kind,
                        mutation="project",
                        realm=realm,
                        tenant_id=fake_tenant if realm == "tenant" else None,
                        operation_id=fake_operation,
                        subject_id=fake_operation if kind.startswith("support") else None,
                        work_item_id=fake_work,
                    )
                    _insert_work(
                        connection,
                        work_id=fake_work,
                        operation_id=fake_operation,
                        operation_kind=kind,
                        realm=realm,
                        tenant_id=fake_tenant if realm == "tenant" else None,
                        requester_id=fake_requester,
                        snapshot_hash=_digest(90_000 + len(kind)),
                        now=now,
                    )
            assert _sqlstate(forged_source) == "42501"

        tenant_id, customer_id, requester_id, operator_id = (
            uuid4(),
            uuid4(),
            uuid4(),
            uuid4(),
        )
        operation_id, grant_id, template_id = uuid4(), uuid4(), uuid4()
        request_hash = _digest(777)
        customer_work, staff_work = uuid4(), uuid4()
        customer_delivery, staff_delivery = uuid4(), uuid4()

        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "INSERT INTO saas_global_users "
                    "(id, status, security_version, created_at, updated_at) "
                    "VALUES (:id, 'active', 1, :now, :now)"
                ),
                {"id": customer_id, "now": now},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenants "
                    "(id, slug, name, status, plan, home_region, lifecycle_version, "
                    "created_at, updated_at) VALUES "
                    "(:id, :slug, 'Source Role Tenant', 'active', 'enterprise', "
                    "'cn-east-1', 1, :now, :now)"
                ),
                {"id": tenant_id, "slug": f"source-role-{tenant_id.hex}", "now": now},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenant_memberships "
                    "(tenant_id, user_id, role, status, version, joined_at) "
                    "VALUES (:tenant, :user, 'owner', 'active', 1, :now)"
                ),
                {"tenant": tenant_id, "user": customer_id, "now": now},
            )
            for principal in (requester_id, operator_id):
                connection.execute(
                    sa.text(
                        "INSERT INTO saas_platform_staff_principals "
                        "(id, identity_connection_ref, issuer, subject, status, "
                        "security_version, created_at, updated_at) VALUES "
                        "(:id, :ref, 'https://source-role.test', :subject, 'active', "
                        "1, :now, :now)"
                    ),
                    {
                        "id": principal,
                        "ref": f"source-role:{principal}",
                        "subject": str(principal),
                        "now": now,
                    },
                )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_role_assignments "
                    "(id, principal_id, role, status, version, assigned_by_principal_id, "
                    "approval_ref, reason, created_at, updated_at) VALUES "
                    "(:id, :principal, 'platform_operator', 'active', 1, :principal, "
                    "'source-role-test', 'source role acceptance', :now, :now)"
                ),
                {"id": uuid4(), "principal": operator_id, "now": now},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_admin_operations "
                    "(id, action, risk_level, tenant_id, target_type, target_id, "
                    "requested_by_principal_id, approved_by_principal_id, idempotency_key, "
                    "request_hash, reason, status, version, created_at, updated_at) VALUES "
                    "(:id, 'support_grant_request', 'high', :tenant, 'support_grant', "
                    ":grant, :requester, NULL, :idempotency, :hash, 'support request', "
                    "'pending_customer_approval', 1, :now, :now)"
                ),
                {
                    "id": operation_id,
                    "tenant": tenant_id,
                    "grant": grant_id,
                    "requester": requester_id,
                    "idempotency": f"source-role-{operation_id}",
                    "hash": request_hash,
                    "now": now,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_support_grants "
                    "(id, operation_id, tenant_id, requested_by_principal_id, mode, scopes, "
                    "project_ids, reason, customer_approval_required, status, version, "
                    "requested_at, expires_at, created_at, updated_at) VALUES "
                    "(:id, :operation, :tenant, :requester, 'standard', CAST(:scopes AS json), "
                    "CAST(:projects AS json), 'support request', true, "
                    "'pending_customer_approval', 1, :now, :expires, :now, :now)"
                ),
                {
                    "id": grant_id,
                    "operation": operation_id,
                    "tenant": tenant_id,
                    "requester": requester_id,
                    "scopes": json.dumps(["tenant.metadata.read"]),
                    "projects": json.dumps([]),
                    "now": now,
                    "expires": now + timedelta(hours=2),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_notification_templates "
                    "(id, realm, tenant_id, created_by_principal_id, template_key, channel, "
                    "locale, version, content_artifact_handle, content_sha256, "
                    "variables_schema_sha256, hmac_key_id, create_idempotency_hmac, "
                    "create_request_hmac, status, created_at) VALUES "
                    "(:id, 'staff', NULL, :operator, 'approval.requested', 'in_app', "
                    "'en-US', 1, :handle, :content, :schema, 'source-role-test-v1', "
                    ":idempotency, :request, 'active', :now)"
                ),
                {
                    "id": template_id,
                    "operator": operator_id,
                    "handle": f"artifact-{template_id.hex}",
                    "content": _digest(778),
                    "schema": _digest(779),
                    "idempotency": _digest(780),
                    "request": _digest(781),
                    "now": now,
                },
            )

            assert connection.execute(
                sa.text("SELECT count(id) FROM saas_platform_staff_principals")
            ).scalar_one() == 2
            assert connection.execute(
                sa.text("SELECT count(user_id) FROM saas_tenant_memberships")
            ).scalar_one() == 1

        # Planning-only column grants must not turn into directory reads. The
        # source audience policies require the explicit ``audience`` mutation;
        # real rows therefore remain invisible during an ordinary source scan.
        for kind, login_engine in login_engines.items():
            realm = "tenant" if kind in {"enterprise", "support.customer"} else "staff"
            with login_engine.begin() as connection:
                _source_context(
                    connection,
                    kind=kind,
                    mutation="scan",
                    realm=realm,
                    tenant_id=tenant_id if realm == "tenant" else None,
                )
                assert connection.execute(
                    sa.text("SELECT count(id) FROM saas_platform_staff_principals")
                ).scalar_one() == 0
                assert connection.execute(
                    sa.text("SELECT count(user_id) FROM saas_tenant_memberships")
                ).scalar_one() == 0

        customer_engine = login_engines["support.customer"]
        with customer_engine.begin() as connection:
            _source_context(
                connection,
                kind="support.customer",
                mutation="project",
                realm="tenant",
                tenant_id=tenant_id,
                operation_id=grant_id,
                subject_id=grant_id,
                work_item_id=customer_work,
            )
            _insert_work(
                connection,
                work_id=customer_work,
                operation_id=grant_id,
                operation_kind="support.customer",
                realm="tenant",
                tenant_id=tenant_id,
                requester_id=requester_id,
                snapshot_hash=request_hash,
                now=now,
            )
            _notification_context(
                connection,
                realm="tenant",
                tenant_id=tenant_id,
                recipient_id=customer_id,
                work_item_id=customer_work,
                delivery_id=customer_delivery,
                template_id=template_id,
            )
            assert connection.execute(
                sa.text(
                    "SELECT count(id) FROM saas_approval_work_items WHERE id = :work"
                ),
                {"work": customer_work},
            ).scalar_one() == 1
            assert connection.execute(
                sa.text(
                    "SELECT count(user_id) FROM saas_tenant_memberships "
                    "WHERE tenant_id = :tenant AND user_id = :user"
                ),
                {"tenant": tenant_id, "user": customer_id},
            ).scalar_one() == 1
            assert connection.execute(
                sa.text(
                    "SELECT approval_notification_binding_is_valid("
                    "'tenant', :tenant, :user, NULL, 'approval.requested', "
                    ":work, NULL)"
                ),
                {"tenant": tenant_id, "user": customer_id, "work": customer_work},
            ).scalar_one()
            _insert_delivery(
                connection,
                delivery_id=customer_delivery,
                realm="tenant",
                tenant_id=tenant_id,
                recipient_id=customer_id,
                template_id=template_id,
                work_item_id=customer_work,
                now=now,
            )
            assert connection.execute(
                sa.text("SELECT count(id) FROM saas_notification_deliveries WHERE id = :id"),
                {"id": customer_delivery},
            ).scalar_one() == 1

        with pytest.raises(DBAPIError) as forged_terminal:
            with customer_engine.begin() as connection:
                _source_context(
                    connection,
                    kind="support.customer",
                    mutation="terminal",
                    realm="tenant",
                    tenant_id=tenant_id,
                    operation_id=grant_id,
                    subject_id=grant_id,
                    work_item_id=customer_work,
                )
                connection.execute(
                    sa.text(
                        "UPDATE saas_approval_work_items SET status = 'approved', "
                        "decided_by_user_id = :customer, decision_code = 'forged', "
                        "decided_at = :now, version = version + 1, updated_at = :now "
                        "WHERE id = :work"
                    ),
                    {
                        "customer": customer_id,
                        "now": now + timedelta(milliseconds=500),
                        "work": customer_work,
                    },
                )
        assert _sqlstate(forged_terminal) == "42501"

        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE saas_platform_support_grants SET "
                    "status = 'pending_staff_approval', "
                    "customer_approved_by_user_id = :customer, "
                    "customer_approval_reason = 'approved', customer_approved_at = :now, "
                    "version = 2, updated_at = :now WHERE id = :id"
                ),
                {"customer": customer_id, "now": now + timedelta(seconds=1), "id": grant_id},
            )

        staff_engine = login_engines["support.staff"]
        with staff_engine.begin() as connection:
            _source_context(
                connection,
                kind="support.staff",
                mutation="project",
                realm="staff",
                tenant_id=tenant_id,
                operation_id=grant_id,
                subject_id=grant_id,
                work_item_id=staff_work,
            )
            _insert_work(
                connection,
                work_id=staff_work,
                operation_id=grant_id,
                operation_kind="support.staff",
                realm="staff",
                tenant_id=tenant_id,
                requester_id=requester_id,
                snapshot_hash=request_hash,
                now=now,
            )
            _notification_context(
                connection,
                realm="staff",
                tenant_id=tenant_id,
                recipient_id=operator_id,
                work_item_id=staff_work,
                delivery_id=staff_delivery,
                template_id=template_id,
            )
            _insert_delivery(
                connection,
                delivery_id=staff_delivery,
                realm="staff",
                tenant_id=tenant_id,
                recipient_id=operator_id,
                template_id=template_id,
                work_item_id=staff_work,
                now=now,
            )
            assert connection.execute(
                sa.text("SELECT count(id) FROM saas_notification_deliveries WHERE id = :id"),
                {"id": staff_delivery},
            ).scalar_one() == 1

        for login_engine in login_engines.values():
            login_engine.dispose()

        with engine.begin() as connection:
            command.downgrade(_config(root, connection), "pc5c00000001")
            assert connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one() == "pc5c00000001"
            for source_role in SOURCE_ROLES.values():
                assert not connection.execute(
                    sa.text(
                        "SELECT has_table_privilege(:role, "
                        "'saas_approval_work_items', 'SELECT')"
                    ),
                    {"role": source_role},
                ).scalar_one()
                assert not connection.execute(
                    sa.text(
                        "SELECT has_table_privilege(:role, "
                        "'saas_notification_deliveries', 'INSERT')"
                    ),
                    {"role": source_role},
                ).scalar_one()
            command.upgrade(_config(root, connection), "pc5c00000002")
            connection.exec_driver_sql(role_sql)
            assert connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one() == "pc5c00000002"
    finally:
        for login_engine in login_engines.values():
            login_engine.dispose()
        engine.dispose()
        with admin_engine.connect() as connection:
            if database_created:
                connection.exec_driver_sql(
                    f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)'
                )
            for login in login_names.values():
                quoted = connection.dialect.identifier_preparer.quote(login)
                connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted}")
        admin_engine.dispose()
