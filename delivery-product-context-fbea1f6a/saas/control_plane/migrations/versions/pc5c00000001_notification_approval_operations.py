"""Add content-blind notification and approval operations authority.

Revision ID: pc5c00000001
Revises: pc5b00000003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc5c00000001"
down_revision: str | None = "pc5b00000003"
branch_labels: str | None = None
depends_on: str | None = None

_NEW_TABLES = (
    "saas_approval_work_items",
    "saas_approval_delegations",
    "saas_notification_templates",
    "saas_notification_preferences",
    "saas_operation_batches",
    "saas_operation_batch_items",
    "saas_notification_deliveries",
    "saas_notification_delivery_attempts",
)

_REALM = "NULLIF(current_setting('app.notification_realm', true), '')"
_ACTOR_REALM = "NULLIF(current_setting('app.notification_actor_realm', true), '')"
_TENANT = "NULLIF(current_setting('app.notification_tenant_id', true), '')::uuid"
_USER = "NULLIF(current_setting('app.notification_recipient_user_id', true), '')::uuid"
_PRINCIPAL = "NULLIF(current_setting('app.notification_staff_principal_id', true), '')::uuid"
_WORK_ITEM = "NULLIF(current_setting('app.notification_work_item_id', true), '')::uuid"
_DELIVERY = "NULLIF(current_setting('app.notification_delivery_id', true), '')::uuid"
_TEMPLATE = "NULLIF(current_setting('app.notification_template_id', true), '')::uuid"
_BATCH = "NULLIF(current_setting('app.notification_batch_id', true), '')::uuid"
_MUTATION = "NULLIF(current_setting('app.notification_mutation', true), '')"
_SOURCE_AUTHORITY = "NULLIF(current_setting('app.notification_source_authority', true), '')"
_SOURCE_OPERATION = (
    "NULLIF(current_setting('app.notification_source_operation_id', true), '')::uuid"
)
_SOURCE_SUPPORT_GRANT = (
    "NULLIF(current_setting('app.notification_source_support_grant_id', true), '')::uuid"
)
_SCHEDULER = "pg_has_role(current_user, 'saas_notification_scheduler', 'member')"
_DISPATCHER = "pg_has_role(current_user, 'saas_notification_dispatcher', 'member')"
_TENANT_GOVERNANCE = "pg_has_role(current_user, 'saas_governance', 'member')"
_STAFF_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _realm_constraint(tenant_actor: str, staff_actor: str) -> str:
    return (
        "(realm = 'tenant' AND tenant_id IS NOT NULL "
        f"AND {tenant_actor} IS NOT NULL AND {staff_actor} IS NULL) OR "
        f"(realm = 'staff' AND {tenant_actor} IS NULL AND {staff_actor} IS NOT NULL)"
    )


def _create_work_items() -> None:
    op.create_table(
        "saas_approval_work_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("realm", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("requester_realm", sa.String(16), nullable=False),
        sa.Column("requested_by_user_id", sa.Uuid()),
        sa.Column("requested_by_principal_id", sa.Uuid()),
        sa.Column("assignee_user_id", sa.Uuid()),
        sa.Column("assignee_principal_id", sa.Uuid()),
        sa.Column("operation_kind", sa.String(64), nullable=False),
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(96), nullable=False),
        sa.Column("target_type", sa.String(64), nullable=False),
        sa.Column("target_locator_hmac", sa.String(64), nullable=False),
        sa.Column("hmac_key_id", sa.String(128), nullable=False),
        sa.Column("required_permission", sa.String(128), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("escalation_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("escalation_count", sa.Integer(), nullable=False),
        sa.Column("decided_by_user_id", sa.Uuid()),
        sa.Column("decided_by_principal_id", sa.Uuid()),
        sa.Column("decision_code", sa.String(128)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("realm IN ('tenant', 'staff')", name="ck_approval_work_realm"),
        sa.CheckConstraint(
            "(realm = 'tenant' AND tenant_id IS NOT NULL) OR realm = 'staff'",
            name="ck_approval_work_queue_realm",
        ),
        sa.CheckConstraint(
            "(requester_realm = 'tenant' AND requested_by_user_id IS NOT NULL "
            "AND requested_by_principal_id IS NULL) OR "
            "(requester_realm = 'staff' AND requested_by_user_id IS NULL "
            "AND requested_by_principal_id IS NOT NULL)",
            name="ck_approval_work_requester_realm",
        ),
        sa.CheckConstraint(
            "(assignee_user_id IS NULL AND assignee_principal_id IS NULL) OR "
            "(realm = 'tenant' AND assignee_user_id IS NOT NULL "
            "AND assignee_principal_id IS NULL) OR "
            "(realm = 'staff' AND assignee_user_id IS NULL "
            "AND assignee_principal_id IS NOT NULL)",
            name="ck_approval_work_optional_assignee_realm",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')",
            name="ck_approval_work_status",
        ),
        sa.CheckConstraint(
            "priority IN ('normal', 'high', 'critical')", name="ck_approval_work_priority"
        ),
        sa.CheckConstraint(
            "length(operation_kind) > 0 AND length(action) > 0 "
            "AND length(target_type) > 0 AND length(required_permission) > 0",
            name="ck_approval_work_codes",
        ),
        sa.CheckConstraint("length(target_locator_hmac) = 64", name="ck_approval_work_target"),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_approval_work_hmac_key"
        ),
        sa.CheckConstraint("length(snapshot_hash) = 64", name="ck_approval_work_snapshot"),
        sa.CheckConstraint(
            "risk_level IN ('medium', 'high', 'critical')", name="ck_approval_work_risk"
        ),
        sa.CheckConstraint(
            "due_at > created_at AND escalation_at <= due_at AND escalation_count >= 0",
            name="ck_approval_work_deadlines",
        ),
        sa.CheckConstraint("version > 0", name="ck_approval_work_version"),
        sa.CheckConstraint(
            "(status = 'pending' AND decided_by_user_id IS NULL "
            "AND decided_by_principal_id IS NULL AND decision_code IS NULL "
            "AND decided_at IS NULL) OR "
            "(status IN ('approved', 'rejected') AND length(decision_code) > 0 "
            "AND decided_at IS NOT NULL AND ((realm = 'tenant' "
            "AND decided_by_user_id IS NOT NULL AND decided_by_principal_id IS NULL) OR "
            "(realm = 'staff' AND decided_by_user_id IS NULL "
            "AND decided_by_principal_id IS NOT NULL))) OR "
            "(status IN ('expired', 'cancelled') AND decided_by_user_id IS NULL "
            "AND decided_by_principal_id IS NULL AND length(decision_code) > 0 "
            "AND decided_at IS NOT NULL)",
            name="ck_approval_work_decision",
        ),
        sa.CheckConstraint(
            "requester_realm <> 'tenant' OR decided_by_user_id IS NULL "
            "OR decided_by_user_id <> requested_by_user_id",
            name="ck_approval_work_distinct_tenant_approver",
        ),
        sa.CheckConstraint(
            "requester_realm <> 'staff' OR decided_by_principal_id IS NULL "
            "OR decided_by_principal_id <> requested_by_principal_id",
            name="ck_approval_work_distinct_staff_approver",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["assignee_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["assignee_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["decided_by_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["decided_by_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "realm",
            "operation_kind",
            "operation_id",
            "required_permission",
            name="uq_approval_work_operation_permission",
        ),
    )
    op.create_index(
        "ix_approval_work_tenant_inbox",
        "saas_approval_work_items",
        ["tenant_id", "assignee_user_id", "status", "priority", "due_at", "id"],
    )
    op.create_index(
        "ix_approval_work_staff_inbox",
        "saas_approval_work_items",
        ["tenant_id", "assignee_principal_id", "status", "priority", "due_at", "id"],
    )
    op.create_index(
        "ix_approval_work_escalation",
        "saas_approval_work_items",
        ["status", "escalation_at", "id"],
    )


def _create_delegations() -> None:
    op.create_table(
        "saas_approval_delegations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("realm", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("delegator_user_id", sa.Uuid()),
        sa.Column("delegator_principal_id", sa.Uuid()),
        sa.Column("delegate_user_id", sa.Uuid()),
        sa.Column("delegate_principal_id", sa.Uuid()),
        sa.Column("permission_code", sa.String(128), nullable=False),
        sa.Column("scope_type", sa.String(64), nullable=False),
        sa.Column("scope_id", sa.Uuid(), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reason_hmac", sa.String(64), nullable=False),
        sa.Column("hmac_key_id", sa.String(128), nullable=False),
        sa.Column("create_idempotency_hmac", sa.String(64), nullable=False),
        sa.Column("create_request_hmac", sa.String(64), nullable=False),
        sa.Column("revoke_idempotency_hmac", sa.String(64)),
        sa.Column("revoke_request_hmac", sa.String(64)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("realm IN ('tenant', 'staff')", name="ck_approval_delegation_realm"),
        sa.CheckConstraint(
            _realm_constraint("delegator_user_id", "delegator_principal_id"),
            name="ck_approval_delegation_delegator_realm",
        ),
        sa.CheckConstraint(
            "(realm = 'tenant' AND delegate_user_id IS NOT NULL "
            "AND delegate_principal_id IS NULL) OR "
            "(realm = 'staff' AND delegate_user_id IS NULL "
            "AND delegate_principal_id IS NOT NULL)",
            name="ck_approval_delegation_delegate_realm",
        ),
        sa.CheckConstraint(
            "(realm = 'tenant' AND delegate_user_id <> delegator_user_id) OR "
            "(realm = 'staff' AND delegate_principal_id <> delegator_principal_id)",
            name="ck_approval_delegation_distinct_actor",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked', 'expired')", name="ck_approval_delegation_status"
        ),
        sa.CheckConstraint(
            "length(permission_code) > 0 AND length(scope_type) > 0",
            name="ck_approval_delegation_scope",
        ),
        sa.CheckConstraint("length(reason_hmac) = 64", name="ck_approval_delegation_reason"),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_approval_delegation_hmac_key"
        ),
        sa.CheckConstraint(
            "length(create_idempotency_hmac) = 64 AND length(create_request_hmac) = 64",
            name="ck_approval_delegation_create_idempotency",
        ),
        sa.CheckConstraint(
            "(revoke_idempotency_hmac IS NULL AND revoke_request_hmac IS NULL) OR "
            "(length(revoke_idempotency_hmac) = 64 AND length(revoke_request_hmac) = 64)",
            name="ck_approval_delegation_revoke_idempotency",
        ),
        sa.CheckConstraint(
            "starts_at < expires_at AND expires_at > created_at",
            name="ck_approval_delegation_expiry",
        ),
        sa.CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL) OR "
            "(status <> 'revoked' AND revoked_at IS NULL)",
            name="ck_approval_delegation_revocation",
        ),
        sa.CheckConstraint("version > 0", name="ck_approval_delegation_version"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["delegator_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["delegator_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["delegate_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["delegate_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_approval_delegation_tenant_idempotency",
        "saas_approval_delegations",
        ["tenant_id", "delegator_user_id", "create_idempotency_hmac"],
        unique=True,
        sqlite_where=sa.text("realm = 'tenant'"),
        postgresql_where=sa.text("realm = 'tenant'"),
    )
    op.create_index(
        "uq_approval_delegation_staff_tenant_idempotency",
        "saas_approval_delegations",
        ["tenant_id", "delegator_principal_id", "create_idempotency_hmac"],
        unique=True,
        sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
        postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
    )
    op.create_index(
        "uq_approval_delegation_staff_global_idempotency",
        "saas_approval_delegations",
        ["delegator_principal_id", "create_idempotency_hmac"],
        unique=True,
        sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
        postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
    )
    op.create_index(
        "uq_approval_delegation_tenant_scope",
        "saas_approval_delegations",
        [
            "tenant_id",
            "delegator_user_id",
            "delegate_user_id",
            "permission_code",
            "scope_type",
            "scope_id",
            "starts_at",
        ],
        unique=True,
        sqlite_where=sa.text("realm = 'tenant'"),
        postgresql_where=sa.text("realm = 'tenant'"),
    )
    op.create_index(
        "uq_approval_delegation_staff_tenant_scope",
        "saas_approval_delegations",
        [
            "tenant_id",
            "delegator_principal_id",
            "delegate_principal_id",
            "permission_code",
            "scope_type",
            "scope_id",
            "starts_at",
        ],
        unique=True,
        sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
        postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
    )
    op.create_index(
        "uq_approval_delegation_staff_global_scope",
        "saas_approval_delegations",
        [
            "delegator_principal_id",
            "delegate_principal_id",
            "permission_code",
            "scope_type",
            "scope_id",
            "starts_at",
        ],
        unique=True,
        sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
        postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
    )
    op.create_index(
        "ix_approval_delegation_tenant_active",
        "saas_approval_delegations",
        ["tenant_id", "delegate_user_id", "status", "expires_at", "id"],
    )
    op.create_index(
        "ix_approval_delegation_staff_active",
        "saas_approval_delegations",
        ["delegate_principal_id", "status", "expires_at", "id"],
    )


def _create_templates() -> None:
    op.create_table(
        "saas_notification_templates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("realm", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("created_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("template_key", sa.String(128), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("locale", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("content_artifact_handle", sa.String(128), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("variables_schema_sha256", sa.String(64), nullable=False),
        sa.Column("hmac_key_id", sa.String(128), nullable=False),
        sa.Column("create_idempotency_hmac", sa.String(64), nullable=False),
        sa.Column("create_request_hmac", sa.String(64), nullable=False),
        sa.Column("retire_idempotency_hmac", sa.String(64)),
        sa.Column("retire_request_hmac", sa.String(64)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("realm = 'staff'", name="ck_notification_template_realm"),
        sa.CheckConstraint(
            "channel IN ('in_app', 'email')", name="ck_notification_template_channel"
        ),
        sa.CheckConstraint(
            "status IN ('active', 'retired')", name="ck_notification_template_status"
        ),
        sa.CheckConstraint(
            "length(template_key) > 0 AND length(locale) > 0 "
            "AND length(content_artifact_handle) BETWEEN 16 AND 128 "
            "AND content_artifact_handle NOT LIKE '%://%' "
            "AND content_artifact_handle NOT LIKE '/%' "
            "AND content_artifact_handle NOT LIKE '%/%' "
            "AND content_artifact_handle NOT LIKE '% %'",
            name="ck_notification_template_identity",
        ),
        sa.CheckConstraint(
            "length(content_sha256) = 64 AND length(variables_schema_sha256) = 64",
            name="ck_notification_template_hashes",
        ),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128 "
            "AND length(create_idempotency_hmac) = 64 "
            "AND length(create_request_hmac) = 64",
            name="ck_notification_template_create_idempotency",
        ),
        sa.CheckConstraint(
            "(status = 'active' AND retire_idempotency_hmac IS NULL "
            "AND retire_request_hmac IS NULL) OR "
            "(status = 'retired' AND length(retire_idempotency_hmac) = 64 "
            "AND length(retire_request_hmac) = 64)",
            name="ck_notification_template_retire_idempotency",
        ),
        sa.CheckConstraint("version > 0", name="ck_notification_template_version"),
        sa.CheckConstraint(
            "(status = 'active' AND retired_at IS NULL) OR "
            "(status = 'retired' AND retired_at IS NOT NULL)",
            name="ck_notification_template_retirement",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["created_by_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_notification_template_staff_tenant_idempotency",
        "saas_notification_templates",
        ["tenant_id", "created_by_principal_id", "create_idempotency_hmac"],
        unique=True,
        sqlite_where=sa.text("tenant_id IS NOT NULL"),
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )
    op.create_index(
        "uq_notification_template_staff_global_idempotency",
        "saas_notification_templates",
        ["created_by_principal_id", "create_idempotency_hmac"],
        unique=True,
        sqlite_where=sa.text("tenant_id IS NULL"),
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_notification_template_staff_tenant_version",
        "saas_notification_templates",
        ["tenant_id", "template_key", "channel", "locale", "version"],
        unique=True,
        sqlite_where=sa.text("tenant_id IS NOT NULL"),
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )
    op.create_index(
        "uq_notification_template_staff_global_version",
        "saas_notification_templates",
        ["template_key", "channel", "locale", "version"],
        unique=True,
        sqlite_where=sa.text("tenant_id IS NULL"),
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "ix_notification_template_lookup",
        "saas_notification_templates",
        ["realm", "tenant_id", "template_key", "channel", "locale", "status", "version"],
    )


def _create_preferences() -> None:
    op.create_table(
        "saas_notification_preferences",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("realm", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("recipient_user_id", sa.Uuid()),
        sa.Column("recipient_principal_id", sa.Uuid()),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("locale", sa.String(32), nullable=False),
        sa.Column("idempotency_key_hmac", sa.String(64), nullable=False),
        sa.Column("request_hmac", sa.String(64), nullable=False),
        sa.Column("hmac_key_id", sa.String(128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "realm IN ('tenant', 'staff')", name="ck_notification_preference_realm"
        ),
        sa.CheckConstraint(
            _realm_constraint("recipient_user_id", "recipient_principal_id"),
            name="ck_notification_preference_recipient_realm",
        ),
        sa.CheckConstraint(
            "channel IN ('in_app', 'email')", name="ck_notification_preference_channel"
        ),
        sa.CheckConstraint(
            "length(event_type) > 0 AND length(locale) > 0",
            name="ck_notification_preference_identity",
        ),
        sa.CheckConstraint(
            "length(idempotency_key_hmac) = 64 AND length(request_hmac) = 64 "
            "AND length(hmac_key_id) BETWEEN 1 AND 128",
            name="ck_notification_preference_idempotency",
        ),
        sa.CheckConstraint("version > 0", name="ck_notification_preference_version"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["recipient_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["recipient_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_notification_preference_tenant_recipient_event",
        "saas_notification_preferences",
        ["tenant_id", "recipient_user_id", "event_type", "channel"],
        unique=True,
        sqlite_where=sa.text("realm = 'tenant'"),
        postgresql_where=sa.text("realm = 'tenant'"),
    )
    op.create_index(
        "uq_notification_preference_staff_tenant_event",
        "saas_notification_preferences",
        ["tenant_id", "recipient_principal_id", "event_type", "channel"],
        unique=True,
        sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
        postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
    )
    op.create_index(
        "uq_notification_preference_staff_global_event",
        "saas_notification_preferences",
        ["recipient_principal_id", "event_type", "channel"],
        unique=True,
        sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
        postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
    )
    op.create_index(
        "ix_notification_preference_tenant_recipient",
        "saas_notification_preferences",
        ["tenant_id", "recipient_user_id", "event_type", "channel"],
    )
    op.create_index(
        "ix_notification_preference_staff_recipient",
        "saas_notification_preferences",
        ["recipient_principal_id", "event_type", "channel"],
    )


def _create_batches() -> None:
    op.create_table(
        "saas_operation_batches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("realm", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("requested_by_user_id", sa.Uuid()),
        sa.Column("requested_by_principal_id", sa.Uuid()),
        sa.Column("operation_kind", sa.String(64), nullable=False),
        sa.Column("action", sa.String(96), nullable=False),
        sa.Column("decision_code", sa.String(16), nullable=False),
        sa.Column("authority_decision_code", sa.String(128), nullable=False),
        sa.Column("decision_reason_hmac", sa.String(64), nullable=False),
        sa.Column("idempotency_key_hmac", sa.String(64), nullable=False),
        sa.Column("request_hmac", sa.String(64), nullable=False),
        sa.Column("hmac_key_id", sa.String(128), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("success_count", sa.Integer(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("result_hmac", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("leased_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("lease_token_hmac", sa.String(64)),
        sa.Column("executor_identity_sha256", sa.String(64)),
        sa.Column("lease_generation", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("realm IN ('tenant', 'staff')", name="ck_operation_batch_realm"),
        sa.CheckConstraint(
            _realm_constraint("requested_by_user_id", "requested_by_principal_id"),
            name="ck_operation_batch_requester_realm",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'partial', 'succeeded', 'failed', 'cancelled')",
            name="ck_operation_batch_status",
        ),
        sa.CheckConstraint(
            "length(operation_kind) > 0 AND length(action) > 0 "
            "AND length(idempotency_key_hmac) = 64",
            name="ck_operation_batch_identity",
        ),
        sa.CheckConstraint(
            "decision_code IN ('approve', 'reject')", name="ck_operation_batch_decision"
        ),
        sa.CheckConstraint(
            "length(authority_decision_code) BETWEEN 1 AND 128",
            name="ck_operation_batch_authority_decision",
        ),
        sa.CheckConstraint(
            "length(decision_reason_hmac) = 64", name="ck_operation_batch_decision_reason"
        ),
        sa.CheckConstraint("length(request_hmac) = 64", name="ck_operation_batch_request"),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_operation_batch_hmac_key"
        ),
        sa.CheckConstraint(
            "item_count BETWEEN 1 AND 25 AND success_count >= 0 AND failure_count >= 0 "
            "AND success_count + failure_count <= item_count",
            name="ck_operation_batch_counts",
        ),
        sa.CheckConstraint(
            "version > 0 AND lease_generation >= 0", name="ck_operation_batch_version"
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND started_at IS NULL AND completed_at IS NULL "
            "AND result_hmac IS NULL AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hmac IS NULL AND executor_identity_sha256 IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL "
            "AND result_hmac IS NULL AND leased_at IS NOT NULL "
            "AND lease_expires_at > leased_at AND length(lease_token_hmac) = 64 "
            "AND length(executor_identity_sha256) = 64) OR "
            "(status IN ('partial', 'succeeded', 'failed', 'cancelled') "
            "AND completed_at IS NOT NULL AND length(result_hmac) = 64 "
            "AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hmac IS NULL AND executor_identity_sha256 IS NULL)",
            name="ck_operation_batch_lifecycle",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_operation_batch_tenant_idempotency",
        "saas_operation_batches",
        ["tenant_id", "requested_by_user_id", "idempotency_key_hmac"],
        unique=True,
        sqlite_where=sa.text("realm = 'tenant'"),
        postgresql_where=sa.text("realm = 'tenant'"),
    )
    op.create_index(
        "uq_operation_batch_staff_tenant_idempotency",
        "saas_operation_batches",
        ["tenant_id", "requested_by_principal_id", "idempotency_key_hmac"],
        unique=True,
        sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
        postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NOT NULL"),
    )
    op.create_index(
        "uq_operation_batch_staff_global_idempotency",
        "saas_operation_batches",
        ["requested_by_principal_id", "idempotency_key_hmac"],
        unique=True,
        sqlite_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
        postgresql_where=sa.text("realm = 'staff' AND tenant_id IS NULL"),
    )
    op.create_index(
        "ix_operation_batch_tenant_queue",
        "saas_operation_batches",
        ["tenant_id", "requested_by_user_id", "status", "created_at", "id"],
    )
    op.create_index(
        "ix_operation_batch_staff_queue",
        "saas_operation_batches",
        ["requested_by_principal_id", "status", "created_at", "id"],
    )


def _create_batch_items() -> None:
    op.create_table(
        "saas_operation_batch_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("realm", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("requested_by_user_id", sa.Uuid()),
        sa.Column("requested_by_principal_id", sa.Uuid()),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("target_type", sa.String(64), nullable=False),
        sa.Column("target_locator_hmac", sa.String(64), nullable=False),
        sa.Column("hmac_key_id", sa.String(128), nullable=False),
        sa.Column("operation_id", sa.Uuid()),
        sa.Column("approval_work_item_id", sa.Uuid(), nullable=False),
        sa.Column("expected_work_item_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("error_code", sa.String(128)),
        sa.Column("error_hmac", sa.String(64)),
        sa.Column("result_hmac", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("realm IN ('tenant', 'staff')", name="ck_operation_batch_item_realm"),
        sa.CheckConstraint(
            _realm_constraint("requested_by_user_id", "requested_by_principal_id"),
            name="ck_operation_batch_item_requester_realm",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed', 'skipped')",
            name="ck_operation_batch_item_status",
        ),
        sa.CheckConstraint("sequence > 0", name="ck_operation_batch_item_sequence"),
        sa.CheckConstraint(
            "expected_work_item_version > 0", name="ck_operation_batch_item_expected_version"
        ),
        sa.CheckConstraint(
            "length(target_type) > 0 AND length(target_locator_hmac) = 64",
            name="ck_operation_batch_item_target",
        ),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_operation_batch_item_hmac_key"
        ),
        sa.CheckConstraint(
            "(error_code IS NULL AND error_hmac IS NULL) OR "
            "(length(error_code) > 0 AND length(error_hmac) = 64)",
            name="ck_operation_batch_item_error",
        ),
        sa.CheckConstraint(
            "(status IN ('pending', 'running') AND result_hmac IS NULL "
            "AND error_code IS NULL AND error_hmac IS NULL) OR "
            "(status = 'succeeded' AND length(result_hmac) = 64 "
            "AND error_code IS NULL AND error_hmac IS NULL) OR "
            "(status IN ('failed', 'skipped') AND length(result_hmac) = 64 "
            "AND length(error_code) > 0 AND length(error_hmac) = 64)",
            name="ck_operation_batch_item_result",
        ),
        sa.CheckConstraint("version > 0", name="ck_operation_batch_item_version"),
        sa.ForeignKeyConstraint(["batch_id"], ["saas_operation_batches.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approval_work_item_id"], ["saas_approval_work_items.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("batch_id", "sequence", name="uq_operation_batch_item_sequence"),
        sa.UniqueConstraint(
            "batch_id", "approval_work_item_id", name="uq_operation_batch_item_work_item"
        ),
        sa.UniqueConstraint(
            "batch_id", "target_type", "target_locator_hmac", name="uq_operation_batch_item_target"
        ),
    )
    op.create_index(
        "ix_operation_batch_item_queue",
        "saas_operation_batch_items",
        ["batch_id", "status", "sequence", "id"],
    )


def _create_deliveries() -> None:
    op.create_table(
        "saas_notification_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("realm", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("recipient_user_id", sa.Uuid()),
        sa.Column("recipient_principal_id", sa.Uuid()),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("template_id", sa.Uuid(), nullable=False),
        sa.Column("approval_work_item_id", sa.Uuid()),
        sa.Column("operation_batch_id", sa.Uuid()),
        sa.Column("deduplication_key", sa.String(64), nullable=False),
        sa.Column("recipient_locator_hmac", sa.String(64), nullable=False),
        sa.Column("render_context_hmac", sa.String(64), nullable=False),
        sa.Column("hmac_key_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leased_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("lease_token_hash", sa.String(64)),
        sa.Column("executor_identity_sha256", sa.String(64)),
        sa.Column("lease_generation", sa.Integer(), nullable=False),
        sa.Column("replay_generation", sa.Integer(), nullable=False),
        sa.Column("replay_receipt_generation", sa.Integer()),
        sa.Column("replay_idempotency_hmac", sa.String(64)),
        sa.Column("replay_request_hmac", sa.String(64)),
        sa.Column("provider_message_hmac", sa.String(64)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("recipient_read_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("read_idempotency_hmac", sa.String(64)),
        sa.Column("read_request_hmac", sa.String(64)),
        sa.Column("suppression_code", sa.String(128)),
        sa.Column("inflight_boundary_code", sa.String(64)),
        sa.Column("last_error_code", sa.String(128)),
        sa.Column("last_error_hmac", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("realm IN ('tenant', 'staff')", name="ck_notification_delivery_realm"),
        sa.CheckConstraint(
            _realm_constraint("recipient_user_id", "recipient_principal_id"),
            name="ck_notification_delivery_recipient_realm",
        ),
        sa.CheckConstraint(
            "channel IN ('in_app', 'email')", name="ck_notification_delivery_channel"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'leased', 'retry', 'succeeded', 'dead_letter', 'suppressed')",
            name="ck_notification_delivery_status",
        ),
        sa.CheckConstraint("length(event_type) > 0", name="ck_notification_delivery_event"),
        sa.CheckConstraint(
            "length(deduplication_key) = 64 AND length(recipient_locator_hmac) = 64 "
            "AND length(render_context_hmac) = 64",
            name="ck_notification_delivery_hashes",
        ),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_notification_delivery_hmac_key"
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 8 "
            "AND attempt_count <= max_attempts",
            name="ck_notification_delivery_attempt_budget",
        ),
        sa.CheckConstraint(
            "lease_generation >= 0 AND replay_generation >= 0 AND version > 0",
            name="ck_notification_delivery_versions",
        ),
        sa.CheckConstraint(
            "(replay_generation = 0 AND replay_receipt_generation IS NULL "
            "AND replay_idempotency_hmac IS NULL AND replay_request_hmac IS NULL) OR "
            "(replay_generation > 0 AND replay_receipt_generation = replay_generation "
            "AND length(replay_idempotency_hmac) = 64 "
            "AND length(replay_request_hmac) = 64)",
            name="ck_notification_delivery_replay",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND leased_at IS NOT NULL AND lease_expires_at > leased_at "
            "AND length(lease_token_hash) = 64 "
            "AND length(executor_identity_sha256) = 64) OR "
            "(status <> 'leased' AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hash IS NULL AND executor_identity_sha256 IS NULL)",
            name="ck_notification_delivery_lease",
        ),
        sa.CheckConstraint(
            "(last_error_code IS NULL AND last_error_hmac IS NULL) OR "
            "(length(last_error_code) > 0 AND length(last_error_hmac) = 64)",
            name="ck_notification_delivery_error",
        ),
        sa.CheckConstraint(
            "(status = 'succeeded' AND length(provider_message_hmac) = 64 "
            "AND delivered_at IS NOT NULL AND suppression_code IS NULL "
            "AND last_error_code IS NULL AND last_error_hmac IS NULL) OR "
            "(status = 'suppressed' AND provider_message_hmac IS NULL "
            "AND delivered_at IS NULL AND length(suppression_code) > 0 "
            "AND last_error_code IS NULL AND last_error_hmac IS NULL) OR "
            "(status NOT IN ('succeeded', 'suppressed') AND provider_message_hmac IS NULL "
            "AND delivered_at IS NULL AND suppression_code IS NULL)",
            name="ck_notification_delivery_terminal",
        ),
        sa.CheckConstraint(
            "(recipient_read_at IS NULL AND acknowledged_at IS NULL "
            "AND read_idempotency_hmac IS NULL AND read_request_hmac IS NULL) OR "
            "(channel = 'in_app' AND status = 'succeeded' "
            "AND recipient_read_at IS NOT NULL "
            "AND length(read_idempotency_hmac) = 64 AND length(read_request_hmac) = 64 "
            "AND (acknowledged_at IS NULL OR acknowledged_at >= recipient_read_at))",
            name="ck_notification_delivery_recipient_ack",
        ),
        sa.CheckConstraint(
            "channel <> 'email' OR (recipient_read_at IS NULL AND acknowledged_at IS NULL "
            "AND read_idempotency_hmac IS NULL AND read_request_hmac IS NULL)",
            name="ck_notification_delivery_email_ack",
        ),
        sa.CheckConstraint(
            "inflight_boundary_code IS NULL OR (status = 'succeeded' "
            "AND inflight_boundary_code = 'approval_terminal_after_send')",
            name="ck_notification_delivery_inflight_boundary",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["recipient_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["recipient_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["template_id"], ["saas_notification_templates.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["approval_work_item_id"], ["saas_approval_work_items.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["operation_batch_id"], ["saas_operation_batches.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("deduplication_key", name="uq_notification_delivery_deduplication"),
    )
    op.create_index(
        "ix_notification_delivery_dispatch",
        "saas_notification_deliveries",
        ["status", "available_at", "lease_expires_at", "id"],
    )
    op.create_index(
        "ix_notification_delivery_tenant_recipient",
        "saas_notification_deliveries",
        ["tenant_id", "recipient_user_id", "created_at", "id"],
    )
    op.create_index(
        "ix_notification_delivery_staff_recipient",
        "saas_notification_deliveries",
        ["recipient_principal_id", "created_at", "id"],
    )


def _create_delivery_attempts() -> None:
    op.create_table(
        "saas_notification_delivery_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("delivery_id", sa.Uuid(), nullable=False),
        sa.Column("realm", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("recipient_user_id", sa.Uuid()),
        sa.Column("recipient_principal_id", sa.Uuid()),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("lease_generation", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("content_hmac", sa.String(64), nullable=False),
        sa.Column("provider_request_hmac", sa.String(64)),
        sa.Column("provider_receipt_hmac", sa.String(64)),
        sa.Column("error_code", sa.String(128)),
        sa.Column("error_hmac", sa.String(64)),
        sa.Column("inflight_boundary_code", sa.String(64)),
        sa.Column("hmac_key_id", sa.String(128), nullable=False),
        sa.Column("executor_identity_sha256", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_available_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("realm IN ('tenant', 'staff')", name="ck_notification_attempt_realm"),
        sa.CheckConstraint(
            _realm_constraint("recipient_user_id", "recipient_principal_id"),
            name="ck_notification_attempt_recipient_realm",
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'retry', 'dead_letter', 'lease_lost', 'suppressed')",
            name="ck_notification_attempt_outcome",
        ),
        sa.CheckConstraint(
            "attempt_number > 0 AND lease_generation > 0",
            name="ck_notification_attempt_generation",
        ),
        sa.CheckConstraint(
            "length(content_hmac) = 64 AND length(executor_identity_sha256) = 64",
            name="ck_notification_attempt_hashes",
        ),
        sa.CheckConstraint(
            "length(hmac_key_id) BETWEEN 1 AND 128", name="ck_notification_attempt_hmac_key"
        ),
        sa.CheckConstraint(
            "provider_request_hmac IS NULL OR length(provider_request_hmac) = 64",
            name="ck_notification_attempt_request",
        ),
        sa.CheckConstraint(
            "provider_receipt_hmac IS NULL OR length(provider_receipt_hmac) = 64",
            name="ck_notification_attempt_receipt",
        ),
        sa.CheckConstraint(
            "(error_code IS NULL AND error_hmac IS NULL) OR "
            "(length(error_code) > 0 AND length(error_hmac) = 64)",
            name="ck_notification_attempt_error",
        ),
        sa.CheckConstraint(
            "inflight_boundary_code IS NULL OR (outcome = 'succeeded' "
            "AND inflight_boundary_code = 'approval_terminal_after_send')",
            name="ck_notification_attempt_inflight_boundary",
        ),
        sa.CheckConstraint("completed_at >= started_at", name="ck_notification_attempt_time"),
        sa.CheckConstraint(
            "(outcome = 'succeeded' AND length(provider_request_hmac) = 64 "
            "AND length(provider_receipt_hmac) = 64 AND error_code IS NULL "
            "AND error_hmac IS NULL AND next_available_at IS NULL) OR "
            "(outcome = 'retry' AND length(error_code) > 0 "
            "AND length(error_hmac) = 64 AND next_available_at > completed_at) OR "
            "(outcome IN ('dead_letter', 'lease_lost') AND length(error_code) > 0 "
            "AND length(error_hmac) = 64 AND next_available_at IS NULL) OR "
            "(outcome = 'suppressed' AND provider_request_hmac IS NULL "
            "AND provider_receipt_hmac IS NULL AND length(error_code) > 0 "
            "AND length(error_hmac) = 64 AND next_available_at IS NULL)",
            name="ck_notification_attempt_result",
        ),
        sa.ForeignKeyConstraint(
            ["delivery_id"], ["saas_notification_deliveries.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["recipient_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["recipient_principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "delivery_id",
            "lease_generation",
            "attempt_number",
            name="uq_notification_attempt_generation_number",
        ),
    )
    op.create_index(
        "ix_notification_attempt_delivery",
        "saas_notification_delivery_attempts",
        ["delivery_id", "attempt_number", "id"],
    )


def _realm_scope(*, tenant_actor: str, staff_actor: str) -> str:
    return (
        f"(realm = {_REALM} AND ((realm = 'tenant' AND tenant_id = {_TENANT} "
        f"AND {tenant_actor} = {_USER}) OR (realm = 'staff' "
        f"AND ({_TENANT} IS NULL OR tenant_id = {_TENANT}) "
        f"AND {staff_actor} = {_PRINCIPAL})))"
    )


def _target_scope() -> str:
    return (
        f"(realm = {_REALM} AND ((realm = 'tenant' AND tenant_id = {_TENANT} "
        f"AND {_USER} IS NOT NULL) OR (realm = 'staff' "
        f"AND ({_TENANT} IS NULL OR tenant_id IS NOT DISTINCT FROM {_TENANT}) "
        f"AND {_PRINCIPAL} IS NOT NULL)))"
    )


def _authenticated_actor() -> str:
    tenant_actor = (
        "EXISTS (SELECT 1 FROM saas_tenant_memberships notification_member "
        f"WHERE notification_member.tenant_id = {_TENANT} "
        f"AND notification_member.user_id = {_USER} "
        "AND notification_member.status = 'active') AND "
        "EXISTS (SELECT 1 FROM saas_global_users notification_user "
        f"WHERE notification_user.id = {_USER} AND notification_user.status = 'active')"
    )
    staff_actor = (
        "EXISTS (SELECT 1 FROM saas_platform_staff_principals notification_principal "
        f"WHERE notification_principal.id = {_PRINCIPAL} "
        "AND notification_principal.status = 'active') AND "
        "EXISTS (SELECT 1 FROM saas_platform_role_assignments notification_assignment "
        f"WHERE notification_assignment.principal_id = {_PRINCIPAL} "
        "AND notification_assignment.status = 'active' "
        "AND (notification_assignment.expires_at IS NULL "
        "OR notification_assignment.expires_at > CURRENT_TIMESTAMP))"
    )
    return (
        f"({_ACTOR_REALM} = {_REALM} AND "
        f"(({_ACTOR_REALM} = 'tenant' AND {_TENANT_GOVERNANCE} AND {tenant_actor}) OR "
        f"({_ACTOR_REALM} = 'staff' AND {_STAFF_GOVERNANCE} AND {staff_actor})))"
    )


def _authenticated_staff() -> str:
    return (
        f"({_STAFF_GOVERNANCE} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_staff_principals notification_source_principal "
        f"WHERE notification_source_principal.id = {_PRINCIPAL} "
        "AND notification_source_principal.status = 'active') AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments notification_source_assignment "
        f"WHERE notification_source_assignment.principal_id = {_PRINCIPAL} "
        "AND notification_source_assignment.status = 'active' "
        "AND (notification_source_assignment.expires_at IS NULL "
        "OR notification_source_assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _active_staff_roles(roles: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{role}'" for role in roles)
    return (
        f"({_STAFF_GOVERNANCE} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_staff_principals notification_operator_principal "
        f"WHERE notification_operator_principal.id = {_PRINCIPAL} "
        "AND notification_operator_principal.status = 'active') AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments notification_operator_assignment "
        f"WHERE notification_operator_assignment.principal_id = {_PRINCIPAL} "
        f"AND notification_operator_assignment.role IN ({quoted}) "
        "AND notification_operator_assignment.status = 'active' "
        "AND (notification_operator_assignment.expires_at IS NULL "
        "OR notification_operator_assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _install_postgresql_security() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    actor = _authenticated_actor()
    target = _target_scope()

    for table in _NEW_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    op.execute(
        "CREATE POLICY rls_tenant_memberships_notification_actor "
        "ON saas_tenant_memberships FOR SELECT USING ("
        f"{_TENANT_GOVERNANCE} AND tenant_id = {_TENANT} AND user_id = {_USER})"
    )

    work = "saas_approval_work_items"
    exact_work = f"({target} AND id = {_WORK_ITEM})"
    tenant_work_routing = (
        f"(realm = 'tenant' AND tenant_id = {_TENANT} AND (assignee_user_id IS NULL "
        f"OR assignee_user_id = {_USER} OR EXISTS ("
        "SELECT 1 FROM saas_approval_delegations notification_tenant_delegation "
        "WHERE notification_tenant_delegation.realm = 'tenant' "
        "AND notification_tenant_delegation.tenant_id = saas_approval_work_items.tenant_id "
        "AND notification_tenant_delegation.delegator_user_id = "
        "saas_approval_work_items.assignee_user_id "
        f"AND notification_tenant_delegation.delegate_user_id = {_USER} "
        "AND notification_tenant_delegation.permission_code = "
        "saas_approval_work_items.required_permission "
        "AND notification_tenant_delegation.scope_id = saas_approval_work_items.operation_id "
        "AND notification_tenant_delegation.status = 'active' "
        "AND notification_tenant_delegation.starts_at <= CURRENT_TIMESTAMP "
        "AND notification_tenant_delegation.expires_at > CURRENT_TIMESTAMP)))"
    )
    staff_work_routing = (
        f"(realm = 'staff' AND ({_TENANT} IS NULL "
        f"OR tenant_id IS NOT DISTINCT FROM {_TENANT}) "
        "AND (assignee_principal_id IS NULL "
        f"OR assignee_principal_id = {_PRINCIPAL} OR EXISTS ("
        "SELECT 1 FROM saas_approval_delegations notification_staff_delegation "
        "WHERE notification_staff_delegation.realm = 'staff' "
        "AND notification_staff_delegation.tenant_id IS NOT DISTINCT FROM "
        "saas_approval_work_items.tenant_id "
        "AND notification_staff_delegation.delegator_principal_id = "
        "saas_approval_work_items.assignee_principal_id "
        f"AND notification_staff_delegation.delegate_principal_id = {_PRINCIPAL} "
        "AND notification_staff_delegation.permission_code = "
        "saas_approval_work_items.required_permission "
        "AND notification_staff_delegation.scope_id = saas_approval_work_items.operation_id "
        "AND notification_staff_delegation.status = 'active' "
        "AND notification_staff_delegation.starts_at <= CURRENT_TIMESTAMP "
        "AND notification_staff_delegation.expires_at > CURRENT_TIMESTAMP)))"
    )
    work_routing = f"({tenant_work_routing} OR {staff_work_routing})"
    op.execute(
        f"CREATE POLICY rls_{work}_governance ON {work} FOR ALL "
        f"USING ({_EMERGENCY} OR ({actor} AND {exact_work} AND {work_routing})) "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {exact_work} AND {work_routing}))"
    )
    work_inbox = (
        f"(({tenant_work_routing} AND {_REALM} = 'tenant') OR "
        f"({staff_work_routing} AND {_REALM} = 'staff'))"
    )
    op.execute(
        f"CREATE POLICY rls_{work}_governance_inbox ON {work} FOR SELECT "
        f"USING ({actor} AND {work_inbox})"
    )
    staff_source_scope = (
        f"(id = {_WORK_ITEM} AND operation_id = {_SOURCE_OPERATION} "
        f"AND {_SOURCE_AUTHORITY} IN ('support', 'privacy', 'audit') "
        "AND requester_realm = 'staff' "
        f"AND requested_by_principal_id = {_PRINCIPAL} "
        f"AND realm = {_REALM} AND ((realm = 'tenant' AND tenant_id = {_TENANT}) OR "
        f"(realm = 'staff' AND tenant_id IS NOT DISTINCT FROM {_TENANT})))"
    )
    op.execute(
        f"CREATE POLICY rls_{work}_staff_source_projection ON {work} FOR INSERT "
        f"WITH CHECK ({_authenticated_staff()} AND {staff_source_scope})"
    )
    tenant_transition_actor = (
        f"({_TENANT_GOVERNANCE} AND {_ACTOR_REALM} = 'tenant' AND {_USER} IS NOT NULL "
        "AND EXISTS (SELECT 1 FROM saas_tenant_memberships notification_customer_member "
        f"WHERE notification_customer_member.tenant_id = {_TENANT} "
        f"AND notification_customer_member.user_id = {_USER} "
        "AND notification_customer_member.status = 'active') AND EXISTS ("
        "SELECT 1 FROM saas_global_users notification_customer_user "
        f"WHERE notification_customer_user.id = {_USER} "
        "AND notification_customer_user.status = 'active'))"
    )
    enterprise_source_scope = (
        f"({_SOURCE_AUTHORITY} = 'enterprise' AND {_REALM} = 'tenant' "
        f"AND id = {_WORK_ITEM} AND operation_id = {_SOURCE_OPERATION} "
        f"AND realm = 'tenant' AND tenant_id = {_TENANT} "
        "AND requester_realm = 'tenant' "
        f"AND requested_by_user_id = {_USER})"
    )
    op.execute(
        f"CREATE POLICY rls_{work}_enterprise_source_projection ON {work} FOR INSERT "
        f"WITH CHECK ({tenant_transition_actor} AND {enterprise_source_scope})"
    )
    support_transition = (
        f"({_SOURCE_AUTHORITY} = 'support' AND {_REALM} = 'staff' "
        f"AND id = {_WORK_ITEM} AND operation_id = {_SOURCE_OPERATION} "
        "AND realm = 'staff' AND tenant_id = "
        f"{_TENANT} AND requester_realm = 'staff' AND EXISTS ("
        "SELECT 1 FROM saas_platform_support_grants notification_support_grant "
        "WHERE notification_support_grant.id = "
        f"{_SOURCE_SUPPORT_GRANT} AND notification_support_grant.operation_id = "
        f"{_SOURCE_OPERATION} "
        f"AND notification_support_grant.tenant_id = {_TENANT} "
        "AND notification_support_grant.requested_by_principal_id = "
        "saas_approval_work_items.requested_by_principal_id "
        "AND notification_support_grant.customer_approved_by_user_id = "
        f"{_USER} AND notification_support_grant.status = 'pending_staff_approval'))"
    )
    op.execute(
        f"CREATE POLICY rls_{work}_support_customer_transition ON {work} FOR INSERT "
        f"WITH CHECK ({tenant_transition_actor} AND {support_transition})"
    )
    op.execute(
        f"CREATE POLICY rls_{work}_scheduler_read ON {work} FOR SELECT "
        f"USING ({_SCHEDULER} AND status = 'pending')"
    )
    op.execute(
        f"CREATE POLICY rls_{work}_scheduler_update ON {work} FOR UPDATE "
        f"USING ({_SCHEDULER} AND {exact_work}) "
        f"WITH CHECK ({_SCHEDULER} AND {exact_work})"
    )
    op.execute(
        f"CREATE POLICY rls_{work}_dispatcher_exact_read ON {work} FOR SELECT "
        f"USING ({_DISPATCHER} AND id = {_WORK_ITEM})"
    )

    delegation = "saas_approval_delegations"
    delegation_actor = (
        f"({_realm_scope(tenant_actor='delegator_user_id', staff_actor='delegator_principal_id')} "
        f"OR {_realm_scope(tenant_actor='delegate_user_id', staff_actor='delegate_principal_id')})"
    )
    op.execute(
        f"CREATE POLICY rls_{delegation}_governance ON {delegation} FOR ALL "
        f"USING ({_EMERGENCY} OR ({actor} AND {delegation_actor})) "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {delegation_actor}))"
    )
    op.execute(
        f"CREATE POLICY rls_{delegation}_scheduler_read ON {delegation} FOR SELECT "
        f"USING ({_SCHEDULER} AND status IN ('active', 'expired'))"
    )

    template = "saas_notification_templates"
    tenant_template_reader = (
        f"({_TENANT_GOVERNANCE} AND {_ACTOR_REALM} = 'tenant' AND {_USER} IS NOT NULL "
        "AND EXISTS (SELECT 1 FROM saas_tenant_memberships notification_template_member "
        f"WHERE notification_template_member.tenant_id = {_TENANT} "
        f"AND notification_template_member.user_id = {_USER} "
        "AND notification_template_member.status = 'active') AND EXISTS ("
        "SELECT 1 FROM saas_global_users notification_template_user "
        f"WHERE notification_template_user.id = {_USER} "
        "AND notification_template_user.status = 'active'))"
    )
    op.execute(
        f"CREATE POLICY rls_{template}_tenant_catalog_read ON {template} FOR SELECT "
        f"USING ({tenant_template_reader} AND realm = 'staff' AND status = 'active' "
        f"AND (tenant_id IS NULL OR tenant_id = {_TENANT}))"
    )
    platform_template_reader = _active_staff_roles(
        ("platform_operator", "platform_security_auditor", "support_agent", "compliance_operator")
    )
    platform_template_manager = _active_staff_roles(("platform_operator",))
    op.execute(
        f"CREATE POLICY rls_{template}_platform_catalog_read ON {template} FOR SELECT "
        f"USING ({_EMERGENCY} OR ({platform_template_reader} AND realm = 'staff'))"
    )
    op.execute(
        f"CREATE POLICY rls_{template}_platform_exact_write ON {template} FOR ALL "
        f"USING ({_EMERGENCY} OR ({platform_template_manager} AND realm = 'staff' "
        f"AND id = {_TEMPLATE})) WITH CHECK ({_EMERGENCY} OR "
        f"({platform_template_manager} AND realm = 'staff' AND id = {_TEMPLATE}))"
    )
    worker_template = (
        f"(id = {_TEMPLATE} AND realm = 'staff' AND status = 'active' "
        f"AND (tenant_id IS NULL OR tenant_id = {_TENANT}))"
    )
    for role_name, predicate in (
        ("scheduler", _SCHEDULER),
        ("dispatcher", _DISPATCHER),
    ):
        op.execute(
            f"CREATE POLICY rls_{template}_{role_name}_read ON {template} FOR SELECT "
            f"USING ({predicate} AND {worker_template})"
        )

    preference = "saas_notification_preferences"
    recipient = _realm_scope(
        tenant_actor="recipient_user_id", staff_actor="recipient_principal_id"
    )
    op.execute(
        f"CREATE POLICY rls_{preference}_governance ON {preference} FOR ALL "
        f"USING ({_EMERGENCY} OR ({actor} AND {recipient})) "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {recipient}))"
    )
    for role_name, predicate in (
        ("scheduler", _SCHEDULER),
        ("dispatcher", _DISPATCHER),
    ):
        op.execute(
            f"CREATE POLICY rls_{preference}_{role_name}_read ON {preference} FOR SELECT "
            f"USING ({predicate} AND {recipient})"
        )

    batch = "saas_operation_batches"
    exact_batch = f"({target} AND id = {_BATCH})"
    op.execute(
        f"CREATE POLICY rls_{batch}_governance ON {batch} FOR ALL "
        f"USING ({_EMERGENCY} OR ({actor} AND {exact_batch})) "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {exact_batch}))"
    )
    op.execute(
        f"CREATE POLICY rls_{batch}_scheduler_read ON {batch} FOR SELECT "
        f"USING ({_SCHEDULER} AND {exact_batch})"
    )
    op.execute(
        f"CREATE POLICY rls_{batch}_scheduler_update ON {batch} FOR UPDATE "
        f"USING ({_SCHEDULER} AND {exact_batch}) "
        f"WITH CHECK ({_SCHEDULER} AND {exact_batch})"
    )

    item = "saas_operation_batch_items"
    exact_item = f"({target} AND batch_id = {_BATCH})"
    op.execute(
        f"CREATE POLICY rls_{item}_governance ON {item} FOR ALL "
        f"USING ({_EMERGENCY} OR ({actor} AND {exact_item})) "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {exact_item}))"
    )
    op.execute(
        f"CREATE POLICY rls_{item}_scheduler_read ON {item} FOR SELECT "
        f"USING ({_SCHEDULER} AND {exact_item})"
    )
    op.execute(
        f"CREATE POLICY rls_{item}_scheduler_update ON {item} FOR UPDATE "
        f"USING ({_SCHEDULER} AND {exact_item}) "
        f"WITH CHECK ({_SCHEDULER} AND {exact_item})"
    )

    delivery = "saas_notification_deliveries"
    exact_delivery = f"({target} AND id = {_DELIVERY})"
    recipient_delivery = recipient
    exact_recipient_delivery = f"({recipient} AND id = {_DELIVERY})"
    op.execute(
        f"CREATE POLICY rls_{delivery}_governance_read ON {delivery} FOR SELECT "
        f"USING ({_EMERGENCY} OR ({actor} AND {recipient_delivery}))"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_recipient_ack ON {delivery} FOR UPDATE "
        f"USING ({actor} AND {_MUTATION} = 'ack' AND {exact_recipient_delivery}) "
        f"WITH CHECK ({actor} AND {_MUTATION} = 'ack' AND {exact_recipient_delivery})"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_governance_replay ON {delivery} FOR UPDATE "
        f"USING ({actor} AND {_MUTATION} = 'replay' AND {exact_delivery}) "
        f"WITH CHECK ({actor} AND {_MUTATION} = 'replay' AND {exact_delivery})"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_governance_insert ON {delivery} FOR INSERT "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {exact_delivery}))"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_scheduler_read ON {delivery} FOR SELECT "
        f"USING ({_SCHEDULER} AND {exact_delivery})"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_scheduler_insert ON {delivery} FOR INSERT "
        f"WITH CHECK ({_SCHEDULER} AND {exact_delivery})"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_dispatcher_read ON {delivery} FOR SELECT "
        f"USING ({_DISPATCHER} AND (status IN ('pending', 'retry') OR "
        "(status = 'leased' AND lease_expires_at <= CURRENT_TIMESTAMP)))"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_dispatcher_exact_read ON {delivery} FOR SELECT "
        f"USING ({_DISPATCHER} AND {exact_recipient_delivery})"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_dispatcher_update ON {delivery} FOR UPDATE "
        f"USING ({_DISPATCHER} AND {exact_recipient_delivery}) "
        f"WITH CHECK ({_DISPATCHER} AND {exact_recipient_delivery})"
    )
    platform_reader = _active_staff_roles(
        ("platform_operator", "platform_security_auditor", "compliance_operator")
    )
    platform_operator = _active_staff_roles(("platform_operator",))
    operator_target = (
        f"(id = {_DELIVERY} AND realm = {_REALM} AND "
        f"((realm = 'tenant' AND tenant_id = {_TENANT}) OR "
        f"(realm = 'staff' AND ({_TENANT} IS NULL "
        f"OR tenant_id IS NOT DISTINCT FROM {_TENANT}))))"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_platform_dlq_read ON {delivery} FOR SELECT "
        f"USING ({platform_reader} AND status = 'dead_letter')"
    )
    op.execute(
        f"CREATE POLICY rls_{delivery}_platform_dlq_replay ON {delivery} FOR UPDATE "
        f"USING ({platform_operator} AND {_MUTATION} = 'replay' AND {operator_target}) "
        f"WITH CHECK ({platform_operator} AND {_MUTATION} = 'replay' AND {operator_target})"
    )

    attempt = "saas_notification_delivery_attempts"
    exact_attempt = f"({recipient} AND delivery_id = {_DELIVERY})"
    op.execute(
        f"CREATE POLICY rls_{attempt}_governance_read ON {attempt} FOR SELECT "
        f"USING ({_EMERGENCY} OR ({actor} AND {recipient}))"
    )
    op.execute(
        f"CREATE POLICY rls_{attempt}_dispatcher_read ON {attempt} FOR SELECT "
        f"USING ({_DISPATCHER} AND {exact_attempt})"
    )
    op.execute(
        f"CREATE POLICY rls_{attempt}_dispatcher_insert ON {attempt} FOR INSERT "
        f"WITH CHECK ({_DISPATCHER} AND {exact_attempt})"
    )
    op.execute(
        f"CREATE POLICY rls_{attempt}_platform_dlq_read ON {attempt} FOR SELECT "
        f"USING ({platform_reader} AND delivery_id = {_DELIVERY})"
    )

    op.execute(
        "CREATE OR REPLACE FUNCTION enforce_notification_template_scope() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM saas_notification_templates scoped_template "
        "WHERE scoped_template.id = NEW.template_id "
        "AND scoped_template.realm = 'staff' AND scoped_template.status = 'active' "
        "AND scoped_template.channel = NEW.channel "
        "AND (scoped_template.tenant_id IS NULL "
        "OR scoped_template.tenant_id = NEW.tenant_id)) THEN "
        "RAISE EXCEPTION 'notification template is outside the delivery tenant scope' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; END; $$"
    )
    op.execute(
        "CREATE TRIGGER trg_saas_notification_deliveries_template_scope "
        "BEFORE INSERT OR UPDATE OF template_id, tenant_id, channel "
        "ON saas_notification_deliveries FOR EACH ROW "
        "EXECUTE FUNCTION enforce_notification_template_scope()"
    )

    op.execute(
        "CREATE OR REPLACE FUNCTION enforce_notification_immutable_facts() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "IF TG_OP = 'DELETE' THEN "
        "RAISE EXCEPTION 'notification operation facts cannot be deleted' "
        "USING ERRCODE = '55000'; END IF; "
        "IF TG_TABLE_NAME = 'saas_notification_delivery_attempts' THEN "
        "RAISE EXCEPTION 'notification delivery attempts are immutable' "
        "USING ERRCODE = '55000'; END IF; "
        "IF TG_TABLE_NAME = 'saas_notification_templates' THEN "
        "IF ROW(OLD.realm, OLD.tenant_id, OLD.created_by_principal_id, "
        "OLD.template_key, OLD.channel, OLD.locale, "
        "OLD.version, OLD.content_artifact_handle, OLD.content_sha256, "
        "OLD.variables_schema_sha256, OLD.hmac_key_id, OLD.create_idempotency_hmac, "
        "OLD.create_request_hmac, OLD.created_at) IS DISTINCT FROM "
        "ROW(NEW.realm, NEW.tenant_id, NEW.created_by_principal_id, "
        "NEW.template_key, NEW.channel, NEW.locale, "
        "NEW.version, NEW.content_artifact_handle, NEW.content_sha256, "
        "NEW.variables_schema_sha256, NEW.hmac_key_id, NEW.create_idempotency_hmac, "
        "NEW.create_request_hmac, NEW.created_at) OR NOT "
        "((OLD.status = NEW.status AND OLD.retired_at IS NOT DISTINCT FROM NEW.retired_at) "
        "AND OLD.retire_idempotency_hmac IS NOT DISTINCT FROM NEW.retire_idempotency_hmac "
        "AND OLD.retire_request_hmac IS NOT DISTINCT FROM NEW.retire_request_hmac "
        "OR (OLD.status = 'active' AND NEW.status = 'retired' "
        "AND OLD.retired_at IS NULL AND NEW.retired_at IS NOT NULL "
        "AND OLD.retire_idempotency_hmac IS NULL AND OLD.retire_request_hmac IS NULL "
        "AND length(NEW.retire_idempotency_hmac) = 64 "
        "AND length(NEW.retire_request_hmac) = 64)) THEN "
        "RAISE EXCEPTION 'notification template versions are immutable' "
        "USING ERRCODE = '55000'; END IF; RETURN NEW; END IF; "
        "IF TG_TABLE_NAME = 'saas_approval_work_items' THEN "
        "IF ROW(OLD.realm, OLD.tenant_id, OLD.requester_realm, OLD.requested_by_user_id, "
        "OLD.requested_by_principal_id, OLD.operation_kind, OLD.operation_id, "
        "OLD.action, OLD.target_type, OLD.target_locator_hmac, OLD.hmac_key_id, "
        "OLD.required_permission, OLD.risk_level, OLD.snapshot_hash, OLD.created_at) "
        "IS DISTINCT FROM ROW(NEW.realm, NEW.tenant_id, NEW.requester_realm, "
        "NEW.requested_by_user_id, "
        "NEW.requested_by_principal_id, NEW.operation_kind, NEW.operation_id, "
        "NEW.action, NEW.target_type, NEW.target_locator_hmac, NEW.hmac_key_id, "
        "NEW.required_permission, NEW.risk_level, NEW.snapshot_hash, NEW.created_at) THEN "
        "RAISE EXCEPTION 'approval source binding is immutable' USING ERRCODE = '55000'; "
        "END IF; RETURN NEW; END IF; "
        "IF TG_TABLE_NAME = 'saas_operation_batches' THEN "
        "IF ROW(OLD.realm, OLD.tenant_id, OLD.requested_by_user_id, "
        "OLD.requested_by_principal_id, OLD.operation_kind, OLD.action, "
        "OLD.decision_code, OLD.authority_decision_code, OLD.decision_reason_hmac, "
        "OLD.idempotency_key_hmac, OLD.request_hmac, OLD.hmac_key_id, "
        "OLD.item_count, OLD.created_at) IS DISTINCT FROM "
        "ROW(NEW.realm, NEW.tenant_id, NEW.requested_by_user_id, "
        "NEW.requested_by_principal_id, NEW.operation_kind, NEW.action, "
        "NEW.decision_code, NEW.authority_decision_code, NEW.decision_reason_hmac, "
        "NEW.idempotency_key_hmac, NEW.request_hmac, NEW.hmac_key_id, "
        "NEW.item_count, NEW.created_at) THEN "
        "RAISE EXCEPTION 'Operation Batch approval binding is immutable' "
        "USING ERRCODE = '55000'; END IF; RETURN NEW; END IF; "
        "IF TG_TABLE_NAME = 'saas_notification_deliveries' THEN "
        "IF ROW(OLD.realm, OLD.tenant_id, OLD.recipient_user_id, "
        "OLD.recipient_principal_id, OLD.event_type, OLD.channel, OLD.template_id, "
        "OLD.approval_work_item_id, OLD.operation_batch_id, OLD.deduplication_key, "
        "OLD.recipient_locator_hmac, OLD.render_context_hmac, OLD.hmac_key_id, "
        "OLD.max_attempts, OLD.created_at) IS DISTINCT FROM "
        "ROW(NEW.realm, NEW.tenant_id, NEW.recipient_user_id, "
        "NEW.recipient_principal_id, NEW.event_type, NEW.channel, NEW.template_id, "
        "NEW.approval_work_item_id, NEW.operation_batch_id, NEW.deduplication_key, "
        "NEW.recipient_locator_hmac, NEW.render_context_hmac, NEW.hmac_key_id, "
        "NEW.max_attempts, NEW.created_at) THEN "
        "RAISE EXCEPTION 'notification delivery envelope is immutable' "
        "USING ERRCODE = '55000'; END IF; RETURN NEW; END IF; "
        "RETURN NEW; END; $$"
    )
    for table in _NEW_TABLES:
        op.execute(
            f"CREATE TRIGGER trg_{table}_nodelete BEFORE DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION enforce_notification_immutable_facts()"
        )
    for table in (
        "saas_notification_delivery_attempts",
        "saas_notification_templates",
        "saas_approval_work_items",
        "saas_operation_batches",
        "saas_notification_deliveries",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable BEFORE UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION enforce_notification_immutable_facts()"
        )

    op.execute(
        "CREATE OR REPLACE FUNCTION enforce_notification_worker_transition() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        f"IF {_DISPATCHER} AND TG_TABLE_NAME = 'saas_notification_deliveries' THEN "
        "IF NOT ((OLD.status IN ('pending', 'retry') "
        "AND NEW.status IN ('leased', 'suppressed')) OR "
        "(OLD.status = 'leased' AND NEW.status IN "
        "('leased', 'retry', 'succeeded', 'dead_letter', 'suppressed'))) THEN "
        "RAISE EXCEPTION 'invalid notification delivery transition' "
        "USING ERRCODE = '55000'; END IF; "
        "IF ROW(OLD.recipient_read_at, OLD.acknowledged_at, "
        "OLD.read_idempotency_hmac, OLD.read_request_hmac, OLD.replay_generation, "
        "OLD.replay_receipt_generation, OLD.replay_idempotency_hmac, "
        "OLD.replay_request_hmac) IS DISTINCT FROM "
        "ROW(NEW.recipient_read_at, NEW.acknowledged_at, "
        "NEW.read_idempotency_hmac, NEW.read_request_hmac, NEW.replay_generation, "
        "NEW.replay_receipt_generation, NEW.replay_idempotency_hmac, "
        "NEW.replay_request_hmac) THEN "
        "RAISE EXCEPTION 'notification dispatcher cannot mutate recipient facts' "
        "USING ERRCODE = '55000'; END IF; "
        f"ELSIF TG_TABLE_NAME = 'saas_notification_deliveries' AND {_MUTATION} = 'ack' THEN "
        "IF ROW(OLD.status, OLD.attempt_count, OLD.available_at, OLD.leased_at, "
        "OLD.lease_expires_at, OLD.lease_token_hash, OLD.executor_identity_sha256, "
        "OLD.lease_generation, OLD.replay_generation, OLD.replay_receipt_generation, "
        "OLD.replay_idempotency_hmac, "
        "OLD.replay_request_hmac, OLD.provider_message_hmac, OLD.delivered_at, "
        "OLD.suppression_code, OLD.inflight_boundary_code, OLD.last_error_code, "
        "OLD.last_error_hmac) IS DISTINCT FROM "
        "ROW(NEW.status, NEW.attempt_count, NEW.available_at, NEW.leased_at, "
        "NEW.lease_expires_at, NEW.lease_token_hash, NEW.executor_identity_sha256, "
        "NEW.lease_generation, NEW.replay_generation, NEW.replay_receipt_generation, "
        "NEW.replay_idempotency_hmac, "
        "NEW.replay_request_hmac, NEW.provider_message_hmac, NEW.delivered_at, "
        "NEW.suppression_code, NEW.inflight_boundary_code, NEW.last_error_code, "
        "NEW.last_error_hmac) THEN "
        "RAISE EXCEPTION 'recipient acknowledgement cannot mutate delivery state' "
        "USING ERRCODE = '55000'; END IF; "
        f"ELSIF TG_TABLE_NAME = 'saas_notification_deliveries' AND {_MUTATION} = 'replay' THEN "
        "IF NOT (OLD.status = 'dead_letter' AND NEW.status = 'pending' "
        "AND NEW.replay_generation = OLD.replay_generation + 1 "
        "AND NEW.replay_receipt_generation = NEW.replay_generation "
        "AND length(NEW.replay_idempotency_hmac) = 64 "
        "AND length(NEW.replay_request_hmac) = 64 "
        "AND NEW.attempt_count = 0 AND NEW.available_at >= CURRENT_TIMESTAMP "
        "AND NEW.last_error_code IS NULL AND NEW.last_error_hmac IS NULL) THEN "
        "RAISE EXCEPTION 'invalid notification replay transition' "
        "USING ERRCODE = '55000'; END IF; "
        f"ELSIF {_SCHEDULER} AND TG_TABLE_NAME = 'saas_approval_work_items' THEN "
        "IF NOT ((OLD.status = 'pending' AND NEW.status = 'pending' "
        "AND NEW.escalation_count = OLD.escalation_count + 1 "
        "AND NEW.priority = CASE WHEN NEW.escalation_count >= 2 "
        "THEN 'critical' ELSE 'high' END "
        "AND NEW.escalation_at > OLD.escalation_at "
        "AND NEW.escalation_at <= NEW.due_at "
        "AND NEW.version = OLD.version + 1) OR "
        "(OLD.status = 'pending' AND NEW.status = 'expired' "
        "AND NEW.priority = OLD.priority "
        "AND NEW.escalation_at = OLD.escalation_at "
        "AND NEW.escalation_count = OLD.escalation_count "
        "AND NEW.version = OLD.version + 1)) THEN "
        "RAISE EXCEPTION 'invalid approval scheduler transition' "
        "USING ERRCODE = '55000'; END IF; "
        f"ELSIF {_SCHEDULER} AND TG_TABLE_NAME = 'saas_operation_batches' THEN "
        "IF NOT ((OLD.status = 'pending' AND NEW.status = 'running') OR "
        "(OLD.status = 'running' AND NEW.status IN "
        "('running', 'partial', 'succeeded', 'failed', 'cancelled'))) THEN "
        "RAISE EXCEPTION 'invalid Operation Batch transition' "
        "USING ERRCODE = '55000'; END IF; END IF; RETURN NEW; END; $$"
    )
    for table in (
        "saas_notification_deliveries",
        "saas_approval_work_items",
        "saas_operation_batches",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_worker_transition BEFORE UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION enforce_notification_worker_transition()"
        )


def _require_no_new_facts() -> None:
    bind = op.get_bind()
    counts = {
        table: bind.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar_one()
        for table in _NEW_TABLES
    }
    if any(counts.values()):
        raise RuntimeError(
            "pc5c00000001 downgrade refused: notification, approval, delegation, "
            "delivery, or Operation Batch facts exist; preserve them with a reviewed "
            "forward migration"
        )


def _drop_tables() -> None:
    op.drop_table("saas_notification_delivery_attempts")
    op.drop_table("saas_notification_deliveries")
    op.drop_table("saas_operation_batch_items")
    op.drop_table("saas_operation_batches")
    op.drop_table("saas_notification_preferences")
    op.drop_table("saas_notification_templates")
    op.drop_table("saas_approval_delegations")
    op.drop_table("saas_approval_work_items")


def _drop_cross_table_policies() -> None:
    """Remove policies that depend on a table dropped before their owner table."""
    if op.get_bind().dialect.name != "postgresql":
        return
    for policy in (
        "rls_saas_approval_work_items_governance",
        "rls_saas_approval_work_items_governance_inbox",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON saas_approval_work_items")


def _drop_postgresql_functions() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP POLICY IF EXISTS rls_tenant_memberships_notification_actor "
        "ON saas_tenant_memberships"
    )
    op.execute("DROP FUNCTION IF EXISTS enforce_notification_worker_transition()")
    op.execute("DROP FUNCTION IF EXISTS enforce_notification_immutable_facts()")
    op.execute("DROP FUNCTION IF EXISTS enforce_notification_template_scope()")


def upgrade() -> None:
    _create_work_items()
    _create_delegations()
    _create_templates()
    _create_preferences()
    _create_batches()
    _create_batch_items()
    _create_deliveries()
    _create_delivery_attempts()
    _install_postgresql_security()


def downgrade() -> None:
    _require_no_new_facts()
    _drop_cross_table_policies()
    _drop_tables()
    _drop_postgresql_functions()
