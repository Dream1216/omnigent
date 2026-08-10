"""Harden notification replay and isolate exact directory reads.

Revision ID: pc5c00000002
Revises: pc5c00000001
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "pc5c00000002"
down_revision: str | None = "pc5c00000001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REALM = "NULLIF(current_setting('app.notification_realm', true), '')"
_TENANT = "NULLIF(current_setting('app.notification_tenant_id', true), '')::uuid"
_USER = "NULLIF(current_setting('app.notification_recipient_user_id', true), '')::uuid"
_PRINCIPAL = (
    "NULLIF(current_setting('app.notification_staff_principal_id', true), '')::uuid"
)
_DELIVERY = "NULLIF(current_setting('app.notification_delivery_id', true), '')::uuid"
_TEMPLATE = "NULLIF(current_setting('app.notification_template_id', true), '')::uuid"
_WORK_ITEM = "NULLIF(current_setting('app.notification_work_item_id', true), '')::uuid"
_BATCH = "NULLIF(current_setting('app.notification_batch_id', true), '')::uuid"
_MUTATION = "NULLIF(current_setting('app.notification_mutation', true), '')"
_EVENT = "NULLIF(current_setting('app.notification_event_type', true), '')"
_CHANNELS = "NULLIF(current_setting('app.notification_channels', true), '')"
_LOCALE = "NULLIF(current_setting('app.notification_locale', true), '')"

_SCHEDULER = "pg_has_role(current_user, 'saas_notification_scheduler', 'member')"
_DISPATCHER = "pg_has_role(current_user, 'saas_notification_dispatcher', 'member')"
_TENANT_GOVERNANCE = "pg_has_role(current_user, 'saas_governance', 'member')"
_STAFF_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"

_DIRECTORY = "pg_has_role(current_user, 'saas_notification_directory', 'member')"
_DIRECTORY_KIND = (
    "NULLIF(current_setting('app.notification_directory_recipient_kind', true), '')"
)
_DIRECTORY_RECIPIENT = (
    "NULLIF(current_setting('app.notification_directory_recipient_id', true), '')::uuid"
)
_DEAD_LETTER_SOURCE = (
    "NULLIF(current_setting('app.notification_dead_letter_source_delivery_id', true), '')::uuid"
)
_DEAD_LETTER_AUDIENCE = (
    "NULLIF(current_setting('app.notification_dead_letter_audience', true), '')"
)
_NOTIFICATION_READER_ROLES = (
    "'platform_operator', 'platform_security_auditor', "
    "'support_agent', 'compliance_operator'"
)

_SOURCE_KIND = "NULLIF(current_setting('app.approval_source_kind', true), '')"
_SOURCE_OPERATION = (
    "NULLIF(current_setting('app.approval_source_operation_id', true), '')::uuid"
)
_SOURCE_SUBJECT = (
    "NULLIF(current_setting('app.approval_source_subject_id', true), '')::uuid"
)
_SOURCE_WORK_ITEM = (
    "NULLIF(current_setting('app.approval_source_work_item_id', true), '')::uuid"
)
_SOURCE_TENANT = (
    "NULLIF(current_setting('app.approval_source_tenant_id', true), '')::uuid"
)
_SOURCE_REALM = "NULLIF(current_setting('app.approval_source_realm', true), '')"
_SOURCE_MUTATION = "NULLIF(current_setting('app.approval_source_mutation', true), '')"

_SOURCE_ROLES = {
    "enterprise": "saas_approval_scheduler_enterprise",
    "privacy": "saas_approval_scheduler_privacy",
    "audit": "saas_approval_scheduler_audit",
    "support.customer": "saas_approval_scheduler_support_customer",
    "support.staff": "saas_approval_scheduler_support_staff",
}


def _has_source_role(kind: str) -> str:
    return f"pg_has_role(current_user, '{_SOURCE_ROLES[kind]}', 'member')"


def _source_role_union() -> str:
    return " OR ".join(f"({_has_source_role(kind)})" for kind in _SOURCE_ROLES)


def _source_role_kind() -> str:
    return " OR ".join(
        f"({_has_source_role(kind)} AND {_SOURCE_KIND} = '{kind}')"
        for kind in _SOURCE_ROLES
    )


def _active_platform_operator() -> str:
    return (
        f"({_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_staff_principals notification_replay_principal "
        f"WHERE notification_replay_principal.id = {_PRINCIPAL} "
        "AND notification_replay_principal.status = 'active') AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments notification_replay_assignment "
        f"WHERE notification_replay_assignment.principal_id = {_PRINCIPAL} "
        "AND notification_replay_assignment.role = 'platform_operator' "
        "AND notification_replay_assignment.status = 'active' "
        "AND (notification_replay_assignment.expires_at IS NULL "
        "OR notification_replay_assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _add_dead_letter_source() -> None:
    with op.batch_alter_table("saas_notification_deliveries") as batch_op:
        batch_op.add_column(sa.Column("source_delivery_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            "fk_notification_delivery_source",
            "saas_notification_deliveries",
            ["source_delivery_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_check_constraint(
            "ck_notification_delivery_dead_letter_source",
            "(event_type = 'notification.delivery_dead_letter' "
            "AND realm = 'staff' AND channel = 'in_app' "
            "AND source_delivery_id IS NOT NULL "
            "AND approval_work_item_id IS NULL AND operation_batch_id IS NULL) OR "
            "(event_type <> 'notification.delivery_dead_letter' "
            "AND source_delivery_id IS NULL)",
        )
        batch_op.create_index(
            "ix_notification_delivery_source", ["source_delivery_id", "id"]
        )


def _replace_policy(table: str, name: str, command: str, predicate: str) -> None:
    op.execute(f"DROP POLICY IF EXISTS {name} ON {table}")
    if command == "SELECT":
        op.execute(
            f"CREATE POLICY {name} ON {table} FOR SELECT USING ({predicate})"
        )
    elif command == "ALL":
        op.execute(
            f"CREATE POLICY {name} ON {table} FOR ALL USING ({predicate}) "
            f"WITH CHECK ({predicate})"
        )
    else:
        raise ValueError(f"unsupported policy command: {command}")


def _install_source_security() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    enterprise = f"({_has_source_role('enterprise')} AND {_SOURCE_KIND} = 'enterprise')"
    privacy = f"({_has_source_role('privacy')} AND {_SOURCE_KIND} = 'privacy')"
    audit = f"({_has_source_role('audit')} AND {_SOURCE_KIND} = 'audit')"
    support_customer = (
        f"({_has_source_role('support.customer')} "
        f"AND {_SOURCE_KIND} = 'support.customer')"
    )
    support_staff = (
        f"({_has_source_role('support.staff')} "
        f"AND {_SOURCE_KIND} = 'support.staff')"
    )
    exact_source = f"({_SOURCE_MUTATION} <> 'scan' AND id = {_SOURCE_OPERATION})"

    _replace_policy(
        "saas_enterprise_access_preflights",
        "rls_enterprise_preflight_approval_scheduler_source",
        "SELECT",
        f"{enterprise} AND ({_SOURCE_MUTATION} = 'scan' OR "
        f"({exact_source} AND tenant_id = {_SOURCE_TENANT}))",
    )
    privacy_actions = (
        "'privacy_deletion_start', 'privacy_deletion_finalize', "
        "'privacy_surface_replay', 'privacy_backup_purge_replay'"
    )
    _replace_policy(
        "saas_privacy_approval_bindings",
        "rls_privacy_binding_approval_scheduler_source",
        "SELECT",
        f"{privacy} AND ({_SOURCE_MUTATION} = 'scan' OR "
        f"(operation_id = {_SOURCE_OPERATION} "
        f"AND tenant_id IS NOT DISTINCT FROM {_SOURCE_TENANT}))",
    )
    _replace_policy(
        "saas_platform_admin_operations",
        "rls_platform_admin_operation_approval_scheduler_privacy",
        "SELECT",
        f"{privacy} AND action IN ({privacy_actions}) AND "
        f"({_SOURCE_MUTATION} = 'scan' OR id = {_SOURCE_OPERATION})",
    )
    _replace_policy(
        "saas_platform_admin_operations",
        "rls_platform_admin_operation_approval_scheduler_audit",
        "SELECT",
        f"{audit} AND action = 'audit_export' AND "
        f"({_SOURCE_MUTATION} = 'scan' OR id = {_SOURCE_OPERATION})",
    )
    customer_grant = f"({support_customer} AND mode = 'standard')"
    staff_grant = (
        f"({support_staff} AND (mode = 'break_glass' "
        "OR status <> 'pending_customer_approval'))"
    )
    _replace_policy(
        "saas_platform_support_grants",
        "rls_support_grant_approval_scheduler_source",
        "SELECT",
        f"({customer_grant} OR {staff_grant}) AND "
        f"({_SOURCE_MUTATION} = 'scan' OR "
        f"(id = {_SOURCE_OPERATION} AND id = {_SOURCE_SUBJECT} "
        f"AND tenant_id = {_SOURCE_TENANT}))",
    )
    support_operation = (
        "EXISTS (SELECT 1 FROM saas_platform_support_grants source_grant "
        "WHERE source_grant.operation_id = saas_platform_admin_operations.id "
        f"AND (({support_customer} AND source_grant.mode = 'standard') "
        f"OR ({support_staff} AND (source_grant.mode = 'break_glass' "
        "OR source_grant.status <> 'pending_customer_approval'))) "
        f"AND ({_SOURCE_MUTATION} = 'scan' OR "
        f"(source_grant.id = {_SOURCE_OPERATION} "
        f"AND source_grant.id = {_SOURCE_SUBJECT})))"
    )
    _replace_policy(
        "saas_platform_admin_operations",
        "rls_platform_admin_operation_approval_scheduler_support",
        "SELECT",
        support_operation,
    )

    tenant_audience = (
        f"({_SOURCE_MUTATION} = 'audience' AND {_SOURCE_TENANT} IS NOT NULL "
        f"AND ({enterprise} OR {support_customer}))"
    )
    _replace_policy(
        "saas_tenant_memberships",
        "rls_tenant_membership_approval_scheduler_audience",
        "SELECT",
        f"{tenant_audience} AND tenant_id = {_SOURCE_TENANT} AND status = 'active'",
    )
    _replace_policy(
        "saas_global_users",
        "rls_global_user_approval_scheduler_audience",
        "SELECT",
        f"{tenant_audience} AND status = 'active' AND EXISTS ("
        "SELECT 1 FROM saas_tenant_memberships source_member "
        "WHERE source_member.user_id = saas_global_users.id "
        f"AND source_member.tenant_id = {_SOURCE_TENANT} "
        "AND source_member.status = 'active')",
    )
    enterprise_tables = {
        "saas_tenants": "id",
        "saas_spaces": "tenant_id",
        "saas_space_memberships": "tenant_id",
        "saas_projects": "tenant_id",
        "saas_project_memberships": "tenant_id",
        "saas_resource_grants": "tenant_id",
        "saas_enterprise_groups": "tenant_id",
        "saas_enterprise_group_memberships": "tenant_id",
        "saas_enterprise_custom_roles": "tenant_id",
        "saas_enterprise_group_role_assignments": "tenant_id",
    }
    for table, tenant_column in enterprise_tables.items():
        _replace_policy(
            table,
            f"rls_{table.removeprefix('saas_')}_approval_scheduler_enterprise",
            "SELECT",
            f"{enterprise} AND {_SOURCE_MUTATION} = 'audience' "
            f"AND {tenant_column} = {_SOURCE_TENANT}",
        )

    staff_audience = (
        f"({_SOURCE_MUTATION} = 'audience' "
        f"AND ({privacy} OR {audit} OR {support_staff}))"
    )
    _replace_policy(
        "saas_platform_staff_principals",
        "rls_platform_staff_approval_scheduler_audience",
        "SELECT",
        f"{staff_audience} AND status = 'active'",
    )
    _replace_policy(
        "saas_platform_role_assignments",
        "rls_platform_assignment_approval_scheduler_audience",
        "SELECT",
        f"{staff_audience} AND status = 'active' "
        "AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
    )

    op.execute(
        "CREATE OR REPLACE FUNCTION approval_source_work_binding_is_valid("
        "p_work_id uuid, p_realm text, p_tenant_id uuid, "
        "p_requested_by_user_id uuid, p_requested_by_principal_id uuid, "
        "p_operation_kind text, p_operation_id uuid, p_snapshot_hash text, "
        "p_work_status text) RETURNS boolean LANGUAGE plpgsql STABLE "
        "SECURITY INVOKER SET search_path = pg_catalog, public AS $$ "
        "DECLARE source_kind text := NULLIF(current_setting("
        "'app.approval_source_kind', true), ''); source_subject uuid := "
        "NULLIF(current_setting('app.approval_source_subject_id', true), '')::uuid; "
        "BEGIN "
        "IF source_kind = 'enterprise' AND pg_has_role(current_user, "
        "'saas_approval_scheduler_enterprise', 'member') THEN RETURN EXISTS ("
        "SELECT 1 FROM saas_enterprise_access_preflights source_row "
        "WHERE source_row.id = p_operation_id AND source_row.id = p_work_id "
        "AND source_row.tenant_id = p_tenant_id "
        "AND source_row.requested_by = p_requested_by_user_id "
        "AND source_row.snapshot_hash = p_snapshot_hash AND (("
        "source_row.status = 'pending_approval' AND (p_work_status = 'pending' OR "
        "(p_work_status = 'expired' AND source_row.expires_at <= CURRENT_TIMESTAMP))) "
        "OR (source_row.status IN ('approved', 'executed') "
        "AND p_work_status IN ('pending', 'approved')) OR "
        "(source_row.status = 'rejected' "
        "AND p_work_status IN ('pending', 'rejected')))); "
        "ELSIF source_kind = 'privacy' AND pg_has_role(current_user, "
        "'saas_approval_scheduler_privacy', 'member') THEN RETURN EXISTS ("
        "SELECT 1 FROM saas_platform_admin_operations source_operation "
        "JOIN saas_privacy_approval_bindings source_binding "
        "ON source_binding.operation_id = source_operation.id "
        "WHERE source_operation.id = p_operation_id "
        "AND source_operation.id = p_work_id "
        "AND source_binding.tenant_id IS NOT DISTINCT FROM p_tenant_id "
        "AND source_operation.requested_by_principal_id = "
        "p_requested_by_principal_id "
        "AND source_binding.snapshot_hash = p_snapshot_hash "
        "AND source_operation.action IN ('privacy_deletion_start', "
        "'privacy_deletion_finalize', 'privacy_surface_replay', "
        "'privacy_backup_purge_replay') AND (("
        "source_operation.status = 'pending_staff_approval' AND ("
        "p_work_status = 'pending' OR (p_work_status = 'expired' "
        "AND source_binding.expires_at <= CURRENT_TIMESTAMP))) OR "
        "(source_operation.status = 'succeeded' "
        "AND p_work_status IN ('pending', 'approved')) OR "
        "(source_operation.status = 'rejected' "
        "AND p_work_status IN ('pending', 'rejected')) OR "
        "(source_operation.status IN ('failed', 'revoked') AND (("
        "source_operation.error_code = 'approval_expired' "
        "AND p_work_status IN ('pending', 'expired')) OR ("
        "source_operation.error_code IS DISTINCT FROM 'approval_expired' "
        "AND p_work_status IN ('pending', 'cancelled')))))); "
        "ELSIF source_kind = 'audit' AND pg_has_role(current_user, "
        "'saas_approval_scheduler_audit', 'member') THEN RETURN EXISTS ("
        "SELECT 1 FROM saas_platform_admin_operations source_operation "
        "WHERE source_operation.id = p_operation_id "
        "AND source_operation.id = p_work_id "
        "AND source_operation.action = 'audit_export' "
        "AND source_operation.tenant_id IS NOT DISTINCT FROM p_tenant_id "
        "AND source_operation.requested_by_principal_id = "
        "p_requested_by_principal_id "
        "AND source_operation.request_hash = p_snapshot_hash AND (("
        "source_operation.status = 'pending_staff_approval' AND ("
        "p_work_status = 'pending' OR (p_work_status = 'expired' "
        "AND source_operation.created_at + INTERVAL '24 hours' "
        "<= CURRENT_TIMESTAMP))) OR (source_operation.status = 'succeeded' "
        "AND p_work_status IN ('pending', 'approved')) OR "
        "(source_operation.status IN ('rejected', 'failed') "
        "AND p_work_status IN ('pending', 'rejected')))); "
        "ELSIF source_kind IN ('support.customer', 'support.staff') "
        "AND ((source_kind = 'support.customer' AND pg_has_role(current_user, "
        "'saas_approval_scheduler_support_customer', 'member')) OR "
        "(source_kind = 'support.staff' AND pg_has_role(current_user, "
        "'saas_approval_scheduler_support_staff', 'member'))) THEN RETURN EXISTS ("
        "SELECT 1 FROM saas_platform_support_grants source_grant "
        "JOIN saas_platform_admin_operations source_operation "
        "ON source_operation.id = source_grant.operation_id "
        "WHERE source_grant.id = p_operation_id "
        "AND source_grant.id = source_subject "
        "AND source_grant.tenant_id = p_tenant_id "
        "AND source_grant.requested_by_principal_id = "
        "p_requested_by_principal_id "
        "AND source_operation.request_hash = p_snapshot_hash "
        "AND source_operation.action = 'support_grant_request' AND (("
        "source_kind = 'support.customer' AND p_operation_kind = 'support.customer' "
        "AND p_realm = 'tenant' AND source_grant.mode = 'standard' AND (("
        "source_grant.status = 'pending_customer_approval' AND ("
        "p_work_status = 'pending' OR (p_work_status = 'expired' "
        "AND source_grant.expires_at <= CURRENT_TIMESTAMP))) OR ("
        "source_grant.status = 'rejected' "
        "AND source_grant.customer_approved_at IS NOT NULL "
        "AND source_grant.staff_approved_at IS NULL "
        "AND p_work_status IN ('pending', 'rejected')) OR ("
        "source_grant.status <> 'pending_customer_approval' AND NOT ("
        "source_grant.status = 'rejected' "
        "AND source_grant.customer_approved_at IS NOT NULL "
        "AND source_grant.staff_approved_at IS NULL) "
        "AND p_work_status IN ('pending', 'approved')))) OR ("
        "source_kind = 'support.staff' AND p_operation_kind = 'support.staff' "
        "AND p_realm = 'staff' AND (source_grant.mode = 'break_glass' "
        "OR source_grant.status <> 'pending_customer_approval') AND (("
        "source_grant.status = 'pending_staff_approval' AND ("
        "p_work_status = 'pending' OR (p_work_status = 'expired' "
        "AND source_grant.expires_at <= CURRENT_TIMESTAMP))) OR ("
        "source_grant.staff_approved_at IS NOT NULL "
        "AND source_grant.status IN ('active', 'revoked') "
        "AND p_work_status IN ('pending', 'approved')) OR ("
        "source_grant.staff_approved_at IS NOT NULL "
        "AND source_grant.status NOT IN ('active', 'revoked') "
        "AND p_work_status IN ('pending', 'rejected')))))); "
        "END IF; RETURN false; END; $$"
    )

    source_work_kind = (
        f"({_has_source_role('enterprise')} AND {_SOURCE_KIND} = 'enterprise' "
        "AND operation_kind = 'enterprise' "
        f"AND {_SOURCE_SUBJECT} IS NULL) OR "
        f"({_has_source_role('privacy')} AND {_SOURCE_KIND} = 'privacy' "
        "AND operation_kind = 'privacy' "
        f"AND {_SOURCE_SUBJECT} IS NULL) OR "
        f"({_has_source_role('audit')} AND {_SOURCE_KIND} = 'audit' "
        "AND operation_kind = 'audit' "
        f"AND {_SOURCE_SUBJECT} IS NULL) OR "
        f"({_has_source_role('support.customer')} "
        f"AND {_SOURCE_KIND} = 'support.customer' "
        "AND operation_kind = 'support.customer' "
        f"AND operation_id = {_SOURCE_SUBJECT}) OR "
        f"({_has_source_role('support.staff')} "
        f"AND {_SOURCE_KIND} = 'support.staff' "
        "AND operation_kind = 'support.staff' "
        f"AND operation_id = {_SOURCE_SUBJECT})"
    )
    source_authority_binding = (
        f"({_has_source_role('enterprise')} "
        "AND EXISTS (SELECT 1 FROM saas_enterprise_access_preflights source_row "
        "WHERE source_row.id = saas_approval_work_items.operation_id "
        "AND source_row.id = saas_approval_work_items.id "
        "AND source_row.tenant_id = saas_approval_work_items.tenant_id "
        "AND source_row.requested_by = saas_approval_work_items.requested_by_user_id "
        "AND source_row.snapshot_hash = saas_approval_work_items.snapshot_hash "
        "AND ((source_row.status = 'pending_approval' "
        "AND (saas_approval_work_items.status = 'pending' OR "
        "(saas_approval_work_items.status = 'expired' "
        "AND source_row.expires_at <= CURRENT_TIMESTAMP))) "
        "OR (source_row.status IN ('approved', 'executed') "
        "AND saas_approval_work_items.status IN ('pending', 'approved')) "
        "OR (source_row.status = 'rejected' "
        "AND saas_approval_work_items.status IN ('pending', 'rejected'))))) OR "
        f"({_has_source_role('privacy')} "
        "AND EXISTS (SELECT 1 FROM saas_platform_admin_operations source_operation "
        "JOIN saas_privacy_approval_bindings source_binding "
        "ON source_binding.operation_id = source_operation.id "
        "WHERE source_operation.id = saas_approval_work_items.operation_id "
        "AND source_operation.id = saas_approval_work_items.id "
        "AND source_binding.tenant_id IS NOT DISTINCT FROM "
        "saas_approval_work_items.tenant_id "
        "AND source_operation.requested_by_principal_id = "
        "saas_approval_work_items.requested_by_principal_id "
        "AND source_binding.snapshot_hash = saas_approval_work_items.snapshot_hash "
        f"AND source_operation.action IN ({privacy_actions}) "
        "AND ((source_operation.status = 'pending_staff_approval' AND "
        "(saas_approval_work_items.status = 'pending' OR "
        "(saas_approval_work_items.status = 'expired' "
        "AND source_binding.expires_at <= CURRENT_TIMESTAMP))) "
        "OR (source_operation.status = 'succeeded' "
        "AND saas_approval_work_items.status IN ('pending', 'approved')) "
        "OR (source_operation.status = 'rejected' "
        "AND saas_approval_work_items.status IN ('pending', 'rejected')) "
        "OR (source_operation.status IN ('failed', 'revoked') "
        "AND ((source_operation.error_code = 'approval_expired' "
        "AND saas_approval_work_items.status IN ('pending', 'expired')) "
        "OR (source_operation.error_code IS DISTINCT FROM 'approval_expired' "
        "AND saas_approval_work_items.status IN ('pending', 'cancelled')))))))) OR "
        f"({_has_source_role('audit')} "
        "AND EXISTS (SELECT 1 FROM saas_platform_admin_operations source_operation "
        "WHERE source_operation.id = saas_approval_work_items.operation_id "
        "AND source_operation.id = saas_approval_work_items.id "
        "AND source_operation.action = 'audit_export' "
        "AND source_operation.tenant_id IS NOT DISTINCT FROM "
        "saas_approval_work_items.tenant_id "
        "AND source_operation.requested_by_principal_id = "
        "saas_approval_work_items.requested_by_principal_id "
        "AND source_operation.request_hash = saas_approval_work_items.snapshot_hash "
        "AND ((source_operation.status = 'pending_staff_approval' AND "
        "(saas_approval_work_items.status = 'pending' OR "
        "(saas_approval_work_items.status = 'expired' "
        "AND source_operation.created_at + INTERVAL '24 hours' "
        "<= CURRENT_TIMESTAMP))) "
        "OR (source_operation.status = 'succeeded' "
        "AND saas_approval_work_items.status IN ('pending', 'approved')) "
        "OR (source_operation.status IN ('rejected', 'failed') "
        "AND saas_approval_work_items.status IN ('pending', 'rejected'))))) OR "
        f"(({_has_source_role('support.customer')} "
        f"OR {_has_source_role('support.staff')}) "
        "AND EXISTS (SELECT 1 FROM saas_platform_support_grants source_grant "
        "JOIN saas_platform_admin_operations source_operation "
        "ON source_operation.id = source_grant.operation_id "
        "WHERE source_grant.id = saas_approval_work_items.operation_id "
        f"AND source_grant.id = {_SOURCE_SUBJECT} "
        "AND source_grant.tenant_id = saas_approval_work_items.tenant_id "
        "AND source_grant.requested_by_principal_id = "
        "saas_approval_work_items.requested_by_principal_id "
        "AND source_operation.request_hash = saas_approval_work_items.snapshot_hash "
        "AND source_operation.action = 'support_grant_request' "
        "AND (((saas_approval_work_items.operation_kind = 'support.customer' "
        "AND source_grant.mode = 'standard' "
        "AND saas_approval_work_items.realm = 'tenant' AND ("
        "(source_grant.status = 'pending_customer_approval' AND "
        "(saas_approval_work_items.status = 'pending' OR "
        "(saas_approval_work_items.status = 'expired' "
        "AND source_grant.expires_at <= CURRENT_TIMESTAMP))) OR "
        "(source_grant.status = 'rejected' "
        "AND source_grant.customer_approved_at IS NOT NULL "
        "AND source_grant.staff_approved_at IS NULL "
        "AND saas_approval_work_items.status IN ('pending', 'rejected')) OR "
        "(source_grant.status <> 'pending_customer_approval' "
        "AND NOT (source_grant.status = 'rejected' "
        "AND source_grant.customer_approved_at IS NOT NULL "
        "AND source_grant.staff_approved_at IS NULL) "
        "AND saas_approval_work_items.status IN ('pending', 'approved')))) OR "
        "(saas_approval_work_items.operation_kind = 'support.staff' "
        "AND saas_approval_work_items.realm = 'staff' "
        "AND (source_grant.mode = 'break_glass' "
        "OR source_grant.status <> 'pending_customer_approval') AND ("
        "(source_grant.status = 'pending_staff_approval' AND "
        "(saas_approval_work_items.status = 'pending' OR "
        "(saas_approval_work_items.status = 'expired' "
        "AND source_grant.expires_at <= CURRENT_TIMESTAMP))) OR "
        "(source_grant.staff_approved_at IS NOT NULL "
        "AND source_grant.status IN ('active', 'revoked') "
        "AND saas_approval_work_items.status IN ('pending', 'approved')) OR "
        "(source_grant.staff_approved_at IS NOT NULL "
        "AND source_grant.status NOT IN ('active', 'revoked') "
        "AND saas_approval_work_items.status IN ('pending', 'rejected')))))))"
    )
    source_authority_binding = (
        "approval_source_work_binding_is_valid("
        "id, realm, tenant_id, requested_by_user_id, requested_by_principal_id, "
        "operation_kind, operation_id, snapshot_hash, status)"
    )
    exact_work = (
        f"({_SOURCE_MUTATION} IN ('project', 'terminal') "
        f"AND id = {_SOURCE_WORK_ITEM} AND operation_id = {_SOURCE_OPERATION} "
        f"AND realm = {_SOURCE_REALM} "
        f"AND tenant_id IS NOT DISTINCT FROM {_SOURCE_TENANT} "
        f"AND ({source_work_kind}) AND ({source_authority_binding}))"
    )
    _replace_policy(
        "saas_approval_work_items",
        "rls_approval_work_approval_scheduler_source",
        "ALL",
        exact_work,
    )

    source_roles = _source_role_union()
    op.execute(
        "CREATE OR REPLACE FUNCTION approval_notification_binding_is_valid("
        "p_realm text, p_tenant_id uuid, p_recipient_user_id uuid, "
        "p_recipient_principal_id uuid, p_event_type text, "
        "p_work_item_id uuid, p_batch_id uuid) RETURNS boolean "
        "LANGUAGE plpgsql STABLE SECURITY INVOKER "
        "SET search_path = pg_catalog, public AS $$ "
        "DECLARE work_row record; batch_row record; routed boolean := false; "
        "requester boolean := false; BEGIN "
        "IF NOT (pg_has_role(current_user, 'saas_notification_scheduler', 'member') "
        "OR pg_has_role(current_user, 'saas_governance', 'member') "
        "OR pg_has_role(current_user, 'saas_platform_governance', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_enterprise', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_privacy', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_audit', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_support_customer', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_support_staff', 'member')) "
        "THEN RETURN false; END IF; "
        "IF (p_work_item_id IS NULL) = (p_batch_id IS NULL) THEN RETURN false; END IF; "
        "IF p_work_item_id IS NOT NULL THEN "
        "SELECT realm, tenant_id, requester_realm, requested_by_user_id, "
        "requested_by_principal_id, assignee_user_id, assignee_principal_id, "
        "operation_kind, operation_id, required_permission, status "
        "INTO work_row FROM saas_approval_work_items "
        "WHERE id = p_work_item_id AND tenant_id IS NOT DISTINCT FROM p_tenant_id; "
        "IF NOT FOUND THEN RETURN false; END IF; "
        "requester := COALESCE(p_realm = work_row.requester_realm AND ((p_realm = 'tenant' "
        "AND p_recipient_user_id = work_row.requested_by_user_id) OR "
        "(p_realm = 'staff' AND p_recipient_principal_id = "
        "work_row.requested_by_principal_id)), false); "
        "IF work_row.realm = 'tenant' AND p_realm = 'tenant' "
        "AND p_recipient_user_id IS NOT NULL THEN "
        "routed := COALESCE(work_row.assignee_user_id = p_recipient_user_id, false); "
        "IF NOT routed AND work_row.assignee_user_id IS NULL THEN "
        "SELECT EXISTS (SELECT 1 FROM saas_tenant_memberships route_member "
        "WHERE route_member.tenant_id = work_row.tenant_id "
        "AND route_member.user_id = p_recipient_user_id "
        "AND route_member.status = 'active' AND (("
        "work_row.operation_kind = 'support.customer' AND route_member.role IN "
        "('owner', 'admin', 'security_auditor')) OR ("
        "work_row.operation_kind <> 'support.customer' "
        "AND route_member.role IN ('owner', 'admin')))) INTO routed; END IF; "
        "IF NOT routed AND work_row.assignee_user_id IS NOT NULL THEN "
        "SELECT EXISTS (SELECT 1 FROM saas_approval_delegations route_delegation "
        "WHERE route_delegation.realm = 'tenant' "
        "AND route_delegation.tenant_id = work_row.tenant_id "
        "AND route_delegation.delegator_user_id = work_row.assignee_user_id "
        "AND route_delegation.delegate_user_id = p_recipient_user_id "
        "AND route_delegation.permission_code = work_row.required_permission "
        "AND route_delegation.scope_id = work_row.operation_id "
        "AND route_delegation.status = 'active' "
        "AND route_delegation.starts_at <= CURRENT_TIMESTAMP "
        "AND route_delegation.expires_at > CURRENT_TIMESTAMP) INTO routed; END IF; "
        "ELSIF work_row.realm = 'staff' AND p_realm = 'staff' "
        "AND p_recipient_principal_id IS NOT NULL THEN "
        "routed := COALESCE(work_row.assignee_principal_id = "
        "p_recipient_principal_id, false); "
        "IF NOT routed AND work_row.assignee_principal_id IS NULL THEN "
        "SELECT EXISTS (SELECT 1 FROM saas_platform_role_assignments route_assignment "
        "WHERE route_assignment.principal_id = p_recipient_principal_id "
        "AND route_assignment.role = 'platform_operator' "
        "AND route_assignment.status = 'active' AND ("
        "route_assignment.expires_at IS NULL OR "
        "route_assignment.expires_at > CURRENT_TIMESTAMP)) INTO routed; END IF; "
        "IF NOT routed AND work_row.assignee_principal_id IS NOT NULL THEN "
        "SELECT EXISTS (SELECT 1 FROM saas_approval_delegations route_delegation "
        "WHERE route_delegation.realm = 'staff' "
        "AND route_delegation.tenant_id IS NOT DISTINCT FROM work_row.tenant_id "
        "AND route_delegation.delegator_principal_id = "
        "work_row.assignee_principal_id "
        "AND route_delegation.delegate_principal_id = p_recipient_principal_id "
        "AND route_delegation.permission_code = work_row.required_permission "
        "AND route_delegation.scope_id = work_row.operation_id "
        "AND route_delegation.status = 'active' "
        "AND route_delegation.starts_at <= CURRENT_TIMESTAMP "
        "AND route_delegation.expires_at > CURRENT_TIMESTAMP) INTO routed; END IF; "
        "END IF; "
        "IF p_event_type IN ('approval.requested', 'approval.reminder', "
        "'approval.escalated', 'approval.decision_failed') THEN "
        "RETURN work_row.status = 'pending' AND routed; "
        "ELSIF p_event_type = 'approval.expired' THEN "
        "RETURN work_row.status = 'expired' AND (routed OR requester); "
        "ELSIF p_event_type = 'approval.decided' THEN "
        "RETURN work_row.status IN ('approved', 'rejected', 'cancelled') "
        "AND requester; END IF; RETURN false; "
        "END IF; "
        "IF pg_has_role(current_user, 'saas_approval_scheduler_enterprise', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_privacy', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_audit', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_support_customer', 'member') "
        "OR pg_has_role(current_user, 'saas_approval_scheduler_support_staff', 'member') "
        "THEN RETURN false; END IF; "
        "SELECT realm, tenant_id, requested_by_user_id, requested_by_principal_id, status "
        "INTO batch_row FROM saas_operation_batches WHERE id = p_batch_id "
        "AND tenant_id IS NOT DISTINCT FROM p_tenant_id; "
        "IF NOT FOUND THEN RETURN false; END IF; "
        "RETURN p_event_type = 'operation_batch.completed' "
        "AND batch_row.status IN ('partial', 'succeeded', 'failed', 'cancelled') "
        "AND ((p_realm = 'tenant' AND batch_row.realm = 'tenant' "
        "AND p_recipient_user_id = batch_row.requested_by_user_id) OR "
        "(p_realm = 'staff' AND batch_row.realm = 'staff' "
        "AND p_recipient_principal_id = batch_row.requested_by_principal_id)); "
        "END; $$"
    )
    source_template = (
        f"({source_roles}) AND {_SOURCE_MUTATION} IN ('project', 'terminal') "
        "AND realm = 'staff' AND status = 'active' "
        f"AND (tenant_id IS NULL OR tenant_id = {_TENANT}) "
        f"AND {_LOCALE} IS NOT NULL AND template_key = {_EVENT} "
        f"AND locale IN ({_LOCALE}, 'en-US') "
        f"AND channel = ANY(string_to_array({_CHANNELS}, ','))"
    )
    _replace_policy(
        "saas_notification_templates",
        "rls_notification_template_approval_scheduler_source",
        "SELECT",
        source_template,
    )
    source_recipient = (
        f"(realm = {_REALM} AND tenant_id IS NOT DISTINCT FROM {_TENANT} AND "
        f"((realm = 'tenant' AND recipient_user_id = {_USER}) OR "
        f"(realm = 'staff' AND recipient_principal_id = {_PRINCIPAL})))"
    )
    _replace_policy(
        "saas_notification_preferences",
        "rls_notification_preference_approval_scheduler_source",
        "SELECT",
        f"({source_roles}) AND {_SOURCE_MUTATION} IN ('project', 'terminal') "
        f"AND {source_recipient}",
    )
    _replace_policy(
        "saas_approval_delegations",
        "rls_approval_delegation_approval_scheduler_source",
        "SELECT",
        f"({_source_role_union()}) AND {_SOURCE_MUTATION} IN ('project', 'terminal') "
        f"AND realm = {_SOURCE_REALM} "
        f"AND tenant_id IS NOT DISTINCT FROM {_SOURCE_TENANT} "
        f"AND scope_id = {_SOURCE_OPERATION} AND status = 'active' "
        "AND starts_at <= CURRENT_TIMESTAMP AND expires_at > CURRENT_TIMESTAMP",
    )

    notification_writer = (
        f"({_SCHEDULER} OR {_TENANT_GOVERNANCE} OR {_STAFF_GOVERNANCE} "
        f"OR ({source_roles}))"
    )
    notification_binding = (
        f"({_MUTATION} IN ('enqueue_template_resolve', 'enqueue') "
        f"AND id = {_WORK_ITEM} AND tenant_id IS NOT DISTINCT FROM {_TENANT})"
    )
    source_exact_for_notification = (
        f"({_SOURCE_MUTATION} IN ('project', 'terminal') "
        f"AND id = {_SOURCE_WORK_ITEM} AND id = {_WORK_ITEM} "
        f"AND operation_id = {_SOURCE_OPERATION} "
        f"AND tenant_id IS NOT DISTINCT FROM {_SOURCE_TENANT} "
        f"AND realm = {_SOURCE_REALM} AND ({source_work_kind}))"
    )
    _replace_policy(
        "saas_approval_work_items",
        "rls_approval_work_notification_binding_read",
        "SELECT",
        f"{notification_binding} AND ("
        f"{_SCHEDULER} OR {_TENANT_GOVERNANCE} OR {_STAFF_GOVERNANCE} "
        f"OR {source_exact_for_notification})",
    )
    _replace_policy(
        "saas_operation_batches",
        "rls_operation_batch_notification_binding_read",
        "SELECT",
        f"{_MUTATION} = 'enqueue' AND id = {_BATCH} "
        f"AND tenant_id IS NOT DISTINCT FROM {_TENANT} "
        f"AND ({_SCHEDULER} OR {_TENANT_GOVERNANCE} OR {_STAFF_GOVERNANCE})",
    )

    notification_tenant_identity = (
        f"({_MUTATION} = 'enqueue' AND {_USER} IS NOT NULL "
        f"AND ({notification_writer}) AND tenant_id = {_TENANT} "
        f"AND user_id = {_USER} AND status = 'active')"
    )
    _replace_policy(
        "saas_tenant_memberships",
        "rls_tenant_membership_notification_writer_exact",
        "SELECT",
        notification_tenant_identity,
    )
    _replace_policy(
        "saas_global_users",
        "rls_global_user_notification_writer_exact",
        "SELECT",
        f"{_MUTATION} = 'enqueue' AND ({notification_writer}) "
        f"AND id = {_USER} AND status = 'active'",
    )
    _replace_policy(
        "saas_platform_staff_principals",
        "rls_platform_staff_notification_writer_exact",
        "SELECT",
        f"{_MUTATION} = 'enqueue' AND ({notification_writer}) "
        f"AND id = {_PRINCIPAL} AND status = 'active'",
    )
    _replace_policy(
        "saas_platform_role_assignments",
        "rls_platform_assignment_notification_writer_exact",
        "SELECT",
        f"{_MUTATION} = 'enqueue' AND ({notification_writer}) "
        f"AND principal_id = {_PRINCIPAL} AND role = 'platform_operator' "
        "AND status = 'active' "
        "AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
    )

    exact_delivery = (
        f"saas_notification_deliveries.id = {_DELIVERY} "
        f"AND saas_notification_deliveries.realm = {_REALM} "
        f"AND saas_notification_deliveries.tenant_id IS NOT DISTINCT FROM {_TENANT} "
        f"AND saas_notification_deliveries.template_id = {_TEMPLATE} "
        f"AND saas_notification_deliveries.event_type = {_EVENT} "
        "AND saas_notification_deliveries.channel = "
        f"ANY(string_to_array({_CHANNELS}, ',')) "
        "AND ((saas_notification_deliveries.realm = 'tenant' "
        f"AND saas_notification_deliveries.recipient_user_id = {_USER}) "
        "OR (saas_notification_deliveries.realm = 'staff' "
        f"AND saas_notification_deliveries.recipient_principal_id = {_PRINCIPAL}))"
    )
    bound_source = (
        "saas_notification_deliveries.source_delivery_id IS NULL AND (("
        f"saas_notification_deliveries.approval_work_item_id = {_WORK_ITEM} "
        "AND saas_notification_deliveries.operation_batch_id IS NULL) OR ("
        "saas_notification_deliveries.approval_work_item_id IS NULL AND "
        f"saas_notification_deliveries.operation_batch_id = {_BATCH})) AND "
        "approval_notification_binding_is_valid("
        "saas_notification_deliveries.realm, "
        "saas_notification_deliveries.tenant_id, "
        "saas_notification_deliveries.recipient_user_id, "
        "saas_notification_deliveries.recipient_principal_id, "
        "saas_notification_deliveries.event_type, "
        "saas_notification_deliveries.approval_work_item_id, "
        "saas_notification_deliveries.operation_batch_id)"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_saas_notification_deliveries_governance_insert "
        "ON saas_notification_deliveries"
    )
    op.execute(
        "CREATE POLICY rls_saas_notification_deliveries_governance_insert "
        f"ON saas_notification_deliveries FOR INSERT WITH CHECK ({_EMERGENCY})"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_saas_notification_deliveries_scheduler_insert "
        "ON saas_notification_deliveries"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_saas_notification_deliveries_bound_insert "
        "ON saas_notification_deliveries"
    )
    op.execute(
        "CREATE POLICY rls_saas_notification_deliveries_bound_insert "
        "ON saas_notification_deliveries FOR INSERT WITH CHECK ("
        f"{_MUTATION} = 'enqueue' AND ({notification_writer}) "
        f"AND ({exact_delivery}) AND ({bound_source}))"
    )
    op.execute(
        "DROP POLICY IF EXISTS "
        "rls_saas_notification_deliveries_source_exact_read "
        "ON saas_notification_deliveries"
    )
    op.execute(
        "CREATE POLICY rls_saas_notification_deliveries_source_exact_read "
        "ON saas_notification_deliveries FOR SELECT USING ("
        f"({_source_role_kind()}) "
        f"AND {_SOURCE_MUTATION} IN ('project', 'terminal') "
        f"AND {_MUTATION} = 'enqueue' AND ({exact_delivery}) "
        f"AND saas_notification_deliveries.approval_work_item_id = {_SOURCE_WORK_ITEM} "
        f"AND ({bound_source}))"
    )


def _install_postgresql_security() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    platform_operator = _active_platform_operator()
    operator_target = (
        f"(id = {_DELIVERY} AND realm = {_REALM} AND "
        f"((realm = 'tenant' AND tenant_id = {_TENANT}) OR "
        f"(realm = 'staff' AND ({_TENANT} IS NULL "
        f"OR tenant_id IS NOT DISTINCT FROM {_TENANT}))))"
    )
    op.execute(
        "DROP POLICY IF EXISTS "
        "rls_saas_notification_deliveries_platform_exact_replay_read "
        "ON saas_notification_deliveries"
    )
    op.execute(
        "CREATE POLICY "
        "rls_saas_notification_deliveries_platform_exact_replay_read "
        "ON saas_notification_deliveries FOR SELECT "
        f"USING ({platform_operator} AND {_MUTATION} = 'replay' "
        "AND status IN ('dead_letter', 'pending') "
        f"AND {operator_target})"
    )

    worker_template_scope = (
        "realm = 'staff' AND status = 'active' "
        f"AND (tenant_id IS NULL OR tenant_id = {_TENANT})"
    )
    worker_template_resolve = (
        f"({_MUTATION} = 'enqueue_template_resolve' "
        f"AND {_LOCALE} IS NOT NULL AND template_key = {_EVENT} "
        f"AND locale IN ({_LOCALE}, 'en-US') "
        f"AND channel = ANY(string_to_array({_CHANNELS}, ',')))"
    )
    worker_template_exact = (
        f"(id = {_TEMPLATE} AND {_MUTATION} IN ('enqueue', 'dispatch') "
        f"AND {_LOCALE} IS NOT NULL AND template_key = {_EVENT} "
        f"AND locale IN ({_LOCALE}, 'en-US') "
        f"AND channel = ANY(string_to_array({_CHANNELS}, ',')))"
    )
    for role_name, role in (
        ("scheduler", "saas_notification_scheduler"),
        ("dispatcher", "saas_notification_dispatcher"),
    ):
        op.execute(
            f"DROP POLICY IF EXISTS rls_saas_notification_templates_{role_name}_read "
            "ON saas_notification_templates"
        )
        op.execute(
            f"CREATE POLICY rls_saas_notification_templates_{role_name}_read "
            "ON saas_notification_templates FOR SELECT USING ("
            f"pg_has_role(current_user, '{role}', 'member') AND "
            f"{worker_template_scope} AND "
            f"({worker_template_resolve} OR {worker_template_exact}))"
        )

    dispatcher_dead_letter = (
        f"({_DISPATCHER} AND {_MUTATION} = 'enqueue' "
        f"AND {_EVENT} = 'notification.delivery_dead_letter')"
    )
    op.execute(
        "DROP POLICY IF EXISTS "
        "rls_saas_notification_deliveries_dispatcher_dead_letter_source_read "
        "ON saas_notification_deliveries"
    )
    op.execute(
        "CREATE POLICY "
        "rls_saas_notification_deliveries_dispatcher_dead_letter_source_read "
        "ON saas_notification_deliveries FOR SELECT USING ("
        f"{dispatcher_dead_letter} AND id = {_DEAD_LETTER_SOURCE} "
        "AND status = 'dead_letter' "
        "AND event_type <> 'notification.delivery_dead_letter')"
    )
    op.execute(
        "DROP POLICY IF EXISTS "
        "rls_platform_staff_notification_dispatcher_dead_letter_audience "
        "ON saas_platform_staff_principals"
    )
    op.execute(
        "CREATE POLICY "
        "rls_platform_staff_notification_dispatcher_dead_letter_audience "
        "ON saas_platform_staff_principals FOR SELECT USING ("
        f"{dispatcher_dead_letter} AND id = {_PRINCIPAL} AND status = 'active')"
    )
    op.execute(
        "DROP POLICY IF EXISTS "
        "rls_platform_assignments_notification_dispatcher_dead_letter_audience "
        "ON saas_platform_role_assignments"
    )
    op.execute(
        "CREATE POLICY "
        "rls_platform_assignments_notification_dispatcher_dead_letter_audience "
        "ON saas_platform_role_assignments FOR SELECT USING ("
        f"{dispatcher_dead_letter} AND principal_id = {_PRINCIPAL} "
        f"AND role IN ({_NOTIFICATION_READER_ROLES}) AND status = 'active' "
        "AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP))"
    )
    op.execute(
        "DROP POLICY IF EXISTS "
        "rls_saas_notification_deliveries_dispatcher_dead_letter_insert "
        "ON saas_notification_deliveries"
    )
    op.execute(
        "CREATE POLICY "
        "rls_saas_notification_deliveries_dispatcher_dead_letter_insert "
        "ON saas_notification_deliveries FOR INSERT WITH CHECK ("
        f"{dispatcher_dead_letter} AND id = {_DELIVERY} "
        "AND source_delivery_id = "
        f"{_DEAD_LETTER_SOURCE} AND realm = 'staff' "
        f"AND tenant_id IS NOT DISTINCT FROM {_TENANT} "
        f"AND recipient_principal_id = {_PRINCIPAL} "
        "AND recipient_user_id IS NULL AND channel = 'in_app' "
        f"AND template_id = {_TEMPLATE} "
        "AND approval_work_item_id IS NULL AND operation_batch_id IS NULL "
        "AND status = 'pending' AND attempt_count = 0 AND lease_generation = 0 "
        "AND replay_generation = 0 AND version = 1 "
        "AND EXISTS (SELECT 1 FROM saas_platform_staff_principals dead_letter_recipient "
        f"WHERE dead_letter_recipient.id = {_PRINCIPAL} "
        "AND dead_letter_recipient.status = 'active') "
        "AND EXISTS (SELECT 1 FROM saas_platform_role_assignments dead_letter_assignment "
        f"WHERE dead_letter_assignment.principal_id = {_PRINCIPAL} "
        f"AND dead_letter_assignment.role IN ({_NOTIFICATION_READER_ROLES}) "
        "AND dead_letter_assignment.status = 'active' "
        "AND (dead_letter_assignment.expires_at IS NULL "
        "OR dead_letter_assignment.expires_at > CURRENT_TIMESTAMP)) "
        "AND EXISTS (SELECT 1 FROM saas_notification_templates dead_letter_template "
        f"WHERE dead_letter_template.id = {_TEMPLATE} "
        "AND dead_letter_template.realm = 'staff' "
        "AND dead_letter_template.status = 'active' "
        "AND dead_letter_template.template_key = 'notification.delivery_dead_letter' "
        "AND dead_letter_template.channel = 'in_app' "
        f"AND {_LOCALE} IS NOT NULL "
        f"AND dead_letter_template.locale IN ({_LOCALE}, 'en-US') "
        "AND (dead_letter_template.tenant_id IS NULL "
        f"OR dead_letter_template.tenant_id = {_TENANT})))"
    )

    op.execute(
        "CREATE OR REPLACE FUNCTION enforce_notification_dead_letter_source() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE source_tenant uuid; source_status text; source_event text; BEGIN "
        "IF TG_OP = 'UPDATE' AND NEW.source_delivery_id IS DISTINCT FROM "
        "OLD.source_delivery_id THEN "
        "RAISE EXCEPTION 'notification source delivery is immutable' "
        "USING ERRCODE = '55000'; END IF; "
        "IF NEW.event_type <> 'notification.delivery_dead_letter' THEN "
        "RETURN NEW; END IF; "
        "SELECT tenant_id, status, event_type "
        "INTO source_tenant, source_status, source_event "
        "FROM saas_notification_deliveries "
        "WHERE id = NEW.source_delivery_id FOR KEY SHARE; "
        "IF NOT FOUND OR source_status <> 'dead_letter' "
        "OR source_event = 'notification.delivery_dead_letter' "
        "OR source_tenant IS DISTINCT FROM NEW.tenant_id THEN "
        "RAISE EXCEPTION 'notification dead-letter source is invalid' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; END; $$"
    )
    op.execute(
        "CREATE TRIGGER trg_saas_notification_deliveries_dead_letter_source "
        "BEFORE INSERT OR UPDATE OF source_delivery_id ON saas_notification_deliveries "
        "FOR EACH ROW EXECUTE FUNCTION enforce_notification_dead_letter_source()"
    )

    op.execute(
        "DROP POLICY IF EXISTS rls_global_users_notification_directory_exact "
        "ON saas_global_users"
    )
    op.execute(
        "CREATE POLICY rls_global_users_notification_directory_exact "
        "ON saas_global_users FOR SELECT USING ("
        f"{_DIRECTORY} AND {_DIRECTORY_KIND} = 'user' "
        f"AND id = {_DIRECTORY_RECIPIENT} "
        "AND status = 'active')"
    )

    op.execute(
        "DROP POLICY IF EXISTS rls_platform_staff_notification_directory "
        "ON saas_platform_staff_principals"
    )
    op.execute(
        "CREATE POLICY rls_platform_staff_notification_directory "
        "ON saas_platform_staff_principals FOR SELECT USING ("
        f"{_DIRECTORY} AND status = 'active' AND (("
        f"{_DIRECTORY_KIND} = 'principal' AND id = {_DIRECTORY_RECIPIENT}) OR ("
        f"{_DIRECTORY_KIND} IS NULL "
        f"AND {_DEAD_LETTER_AUDIENCE} = 'platform.notification.read' "
        "AND EXISTS (SELECT 1 FROM saas_platform_role_assignments directory_assignment "
        "WHERE directory_assignment.principal_id = saas_platform_staff_principals.id "
        f"AND directory_assignment.role IN ({_NOTIFICATION_READER_ROLES}) "
        "AND directory_assignment.status = 'active' "
        "AND (directory_assignment.expires_at IS NULL "
        "OR directory_assignment.expires_at > CURRENT_TIMESTAMP)))))"
    )

    op.execute(
        "DROP POLICY IF EXISTS rls_platform_assignments_notification_directory "
        "ON saas_platform_role_assignments"
    )
    op.execute(
        "CREATE POLICY rls_platform_assignments_notification_directory "
        "ON saas_platform_role_assignments FOR SELECT USING ("
        f"{_DIRECTORY} AND {_DIRECTORY_KIND} IS NULL "
        f"AND {_DEAD_LETTER_AUDIENCE} = 'platform.notification.read' "
        f"AND role IN ({_NOTIFICATION_READER_ROLES}) AND status = 'active' "
        "AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP))"
    )


def upgrade() -> None:
    _add_dead_letter_source()
    _install_postgresql_security()
    _install_source_security()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "trg_saas_notification_deliveries_dead_letter_source "
            "ON saas_notification_deliveries"
        )
        op.execute("DROP FUNCTION IF EXISTS enforce_notification_dead_letter_source()")
        for policy, table in (
            (
                "rls_enterprise_preflight_approval_scheduler_source",
                "saas_enterprise_access_preflights",
            ),
            (
                "rls_privacy_binding_approval_scheduler_source",
                "saas_privacy_approval_bindings",
            ),
            (
                "rls_platform_admin_operation_approval_scheduler_privacy",
                "saas_platform_admin_operations",
            ),
            (
                "rls_platform_admin_operation_approval_scheduler_audit",
                "saas_platform_admin_operations",
            ),
            (
                "rls_support_grant_approval_scheduler_source",
                "saas_platform_support_grants",
            ),
            (
                "rls_platform_admin_operation_approval_scheduler_support",
                "saas_platform_admin_operations",
            ),
            (
                "rls_tenant_membership_approval_scheduler_audience",
                "saas_tenant_memberships",
            ),
            (
                "rls_global_user_approval_scheduler_audience",
                "saas_global_users",
            ),
            (
                "rls_platform_staff_approval_scheduler_audience",
                "saas_platform_staff_principals",
            ),
            (
                "rls_platform_assignment_approval_scheduler_audience",
                "saas_platform_role_assignments",
            ),
            (
                "rls_approval_work_approval_scheduler_source",
                "saas_approval_work_items",
            ),
            (
                "rls_notification_template_approval_scheduler_source",
                "saas_notification_templates",
            ),
            (
                "rls_notification_preference_approval_scheduler_source",
                "saas_notification_preferences",
            ),
            (
                "rls_approval_delegation_approval_scheduler_source",
                "saas_approval_delegations",
            ),
            (
                "rls_approval_work_notification_binding_read",
                "saas_approval_work_items",
            ),
            (
                "rls_operation_batch_notification_binding_read",
                "saas_operation_batches",
            ),
            (
                "rls_tenant_membership_notification_writer_exact",
                "saas_tenant_memberships",
            ),
            (
                "rls_global_user_notification_writer_exact",
                "saas_global_users",
            ),
            (
                "rls_platform_staff_notification_writer_exact",
                "saas_platform_staff_principals",
            ),
            (
                "rls_platform_assignment_notification_writer_exact",
                "saas_platform_role_assignments",
            ),
            (
                "rls_saas_notification_deliveries_bound_insert",
                "saas_notification_deliveries",
            ),
            (
                "rls_saas_notification_deliveries_source_exact_read",
                "saas_notification_deliveries",
            ),
            (
                "rls_platform_assignments_notification_directory",
                "saas_platform_role_assignments",
            ),
            (
                "rls_platform_staff_notification_directory",
                "saas_platform_staff_principals",
            ),
            ("rls_global_users_notification_directory_exact", "saas_global_users"),
            (
                "rls_saas_notification_deliveries_platform_exact_replay_read",
                "saas_notification_deliveries",
            ),
            (
                "rls_saas_notification_deliveries_dispatcher_dead_letter_source_read",
                "saas_notification_deliveries",
            ),
            (
                "rls_saas_notification_deliveries_dispatcher_dead_letter_insert",
                "saas_notification_deliveries",
            ),
            (
                "rls_platform_staff_notification_dispatcher_dead_letter_audience",
                "saas_platform_staff_principals",
            ),
            (
                "rls_platform_assignments_notification_dispatcher_dead_letter_audience",
                "saas_platform_role_assignments",
            ),
        ):
            op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
        for table in (
            "saas_tenants",
            "saas_spaces",
            "saas_space_memberships",
            "saas_projects",
            "saas_project_memberships",
            "saas_resource_grants",
            "saas_enterprise_groups",
            "saas_enterprise_group_memberships",
            "saas_enterprise_custom_roles",
            "saas_enterprise_group_role_assignments",
        ):
            op.execute(
                "DROP POLICY IF EXISTS "
                f"rls_{table.removeprefix('saas_')}_approval_scheduler_enterprise "
                f"ON {table}"
            )

        tenant_actor = (
            f"({_TENANT_GOVERNANCE} AND {_REALM} = 'tenant' "
            f"AND {_TENANT} IS NOT NULL AND {_USER} IS NOT NULL AND EXISTS ("
            "SELECT 1 FROM saas_tenant_memberships downgrade_member "
            f"WHERE downgrade_member.tenant_id = {_TENANT} "
            f"AND downgrade_member.user_id = {_USER} "
            "AND downgrade_member.status = 'active') AND EXISTS ("
            "SELECT 1 FROM saas_global_users downgrade_user "
            f"WHERE downgrade_user.id = {_USER} "
            "AND downgrade_user.status = 'active'))"
        )
        staff_actor = (
            f"({_STAFF_GOVERNANCE} AND {_REALM} = 'staff' "
            f"AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
            "SELECT 1 FROM saas_platform_staff_principals downgrade_principal "
            f"WHERE downgrade_principal.id = {_PRINCIPAL} "
            "AND downgrade_principal.status = 'active'))"
        )
        exact_target = (
            f"id = {_DELIVERY} AND realm = {_REALM} AND "
            f"((realm = 'tenant' AND tenant_id = {_TENANT}) OR "
            f"(realm = 'staff' AND tenant_id IS NOT DISTINCT FROM {_TENANT}))"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_saas_notification_deliveries_governance_insert "
            "ON saas_notification_deliveries"
        )
        op.execute(
            "CREATE POLICY rls_saas_notification_deliveries_governance_insert "
            "ON saas_notification_deliveries FOR INSERT WITH CHECK ("
            f"{_EMERGENCY} OR ((({tenant_actor}) OR ({staff_actor})) "
            f"AND ({exact_target})))"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_saas_notification_deliveries_scheduler_insert "
            "ON saas_notification_deliveries"
        )
        op.execute(
            "CREATE POLICY rls_saas_notification_deliveries_scheduler_insert "
            "ON saas_notification_deliveries FOR INSERT WITH CHECK ("
            f"{_SCHEDULER} AND ({exact_target}))"
        )
        worker_scope = (
            f"id = {_TEMPLATE} AND realm = 'staff' AND status = 'active' "
            f"AND (tenant_id IS NULL OR tenant_id = {_TENANT})"
        )
        for role_name, role in (
            ("scheduler", "saas_notification_scheduler"),
            ("dispatcher", "saas_notification_dispatcher"),
        ):
            op.execute(
                f"DROP POLICY IF EXISTS rls_saas_notification_templates_{role_name}_read "
                "ON saas_notification_templates"
            )
            op.execute(
                f"CREATE POLICY rls_saas_notification_templates_{role_name}_read "
                "ON saas_notification_templates FOR SELECT USING ("
                f"pg_has_role(current_user, '{role}', 'member') AND ({worker_scope}))"
            )

        op.execute(
            "DROP FUNCTION IF EXISTS approval_notification_binding_is_valid("
            "text, uuid, uuid, uuid, text, uuid, uuid)"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS approval_source_work_binding_is_valid("
            "uuid, text, uuid, uuid, uuid, text, uuid, text, text)"
        )

        source_authority_tables = (
            "saas_enterprise_access_preflights",
            "saas_platform_admin_operations",
            "saas_platform_support_grants",
            "saas_platform_support_sessions",
            "saas_privacy_approval_bindings",
            "saas_approval_work_items",
            "saas_approval_delegations",
            "saas_notification_templates",
            "saas_notification_preferences",
            "saas_notification_deliveries",
            "saas_global_users",
            "saas_tenants",
            "saas_spaces",
            "saas_tenant_memberships",
            "saas_space_memberships",
            "saas_projects",
            "saas_project_memberships",
            "saas_resource_grants",
            "saas_enterprise_groups",
            "saas_enterprise_group_memberships",
            "saas_enterprise_custom_roles",
            "saas_enterprise_group_role_assignments",
            "saas_platform_staff_principals",
            "saas_platform_role_assignments",
        )
        present_roles = {
            row[0]
            for row in bind.execute(
                sa.text("SELECT rolname FROM pg_roles WHERE rolname = ANY(:roles)"),
                {"roles": list(_SOURCE_ROLES.values())},
            )
        }
        for role in present_roles:
            op.execute(
                "REVOKE ALL PRIVILEGES ON TABLE "
                f"{', '.join(source_authority_tables)} FROM {role}"
            )
            op.execute(f"REVOKE USAGE ON SCHEMA public FROM {role}")
            inherited_roles = bind.execute(
                sa.text(
                    "SELECT parent.rolname FROM pg_auth_members membership "
                    "JOIN pg_roles parent ON parent.oid = membership.roleid "
                    "JOIN pg_roles member ON member.oid = membership.member "
                    "WHERE member.rolname = :role"
                ),
                {"role": role},
            ).scalars()
            for inherited_role in inherited_roles:
                op.execute(f"REVOKE {inherited_role} FROM {role}")

    source_count = bind.execute(
        sa.text(
            "SELECT count(*) FROM saas_notification_deliveries "
            "WHERE source_delivery_id IS NOT NULL"
        )
    ).scalar_one()
    if source_count:
        raise RuntimeError(
            "pc5c00000002 downgrade refused: dead-letter source bindings exist"
        )
    with op.batch_alter_table("saas_notification_deliveries") as batch_op:
        batch_op.drop_index("ix_notification_delivery_source")
        batch_op.drop_constraint(
            "ck_notification_delivery_dead_letter_source", type_="check"
        )
        batch_op.drop_constraint("fk_notification_delivery_source", type_="foreignkey")
        batch_op.drop_column("source_delivery_id")
