"""Add governed JIT support, Admin Operations, and immutable audit exports.

Revision ID: pc3a00000001
Revises: pc2b00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc3a00000001"
down_revision: str | None = "pc2b00000001"
branch_labels: str | None = None
depends_on: str | None = None

_TABLES = (
    "saas_platform_admin_operations",
    "saas_platform_support_grants",
    "saas_platform_support_sessions",
    "saas_platform_audit_chain_heads",
    "saas_platform_audit_events",
    "saas_platform_audit_exports",
)
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_ACTOR = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_TARGET_TENANT = "NULLIF(current_setting('app.platform_target_tenant_id', true), '')::uuid"
_TARGET_GRANT = "NULLIF(current_setting('app.platform_target_support_grant_id', true), '')::uuid"
_TARGET_OPERATION = (
    "NULLIF(current_setting('app.platform_target_admin_operation_id', true), '')::uuid"
)
_SUPPORT_TOKEN = "NULLIF(current_setting('app.platform_support_session_token_hash', true), '')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_SUPPORT = "pg_has_role(current_user, 'saas_platform_support', 'member')"
_TENANT_APP = "pg_has_role(current_user, 'saas_app', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _active_staff(roles: str) -> str:
    return (
        f"({_GOVERNANCE} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments pc3_assignment "
        f"WHERE pc3_assignment.principal_id = {_PRINCIPAL} "
        f"AND pc3_assignment.role IN ({roles}) "
        "AND pc3_assignment.status = 'active' "
        "AND (pc3_assignment.expires_at IS NULL "
        "OR pc3_assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _tenant_admin() -> str:
    return (
        f"(({_TENANT_APP} OR {_GOVERNANCE}) AND {_ACTOR} IS NOT NULL "
        f"AND {_TENANT} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_tenant_memberships pc3_member "
        f"WHERE pc3_member.tenant_id = {_TENANT} "
        f"AND pc3_member.user_id = {_ACTOR} "
        "AND pc3_member.status = 'active' "
        "AND pc3_member.role IN ('owner', 'admin', 'security_auditor')))"
    )


def _create_tables() -> None:
    op.create_table(
        "saas_platform_admin_operations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("target_type", sa.String(64), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("approved_by_principal_id", sa.Uuid()),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("result", sa.JSON()),
        sa.Column("error_code", sa.String(128)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "action IN ('support_grant_request', 'support_grant_staff_decision', "
            "'support_session_issue', 'support_grant_revoke', 'audit_export')",
            name="ck_platform_admin_operation_action",
        ),
        sa.CheckConstraint(
            "risk_level IN ('high', 'critical')", name="ck_platform_admin_operation_risk"
        ),
        sa.CheckConstraint(
            "status IN ('pending_customer_approval', 'pending_staff_approval', "
            "'succeeded', 'rejected', 'revoked', 'failed')",
            name="ck_platform_admin_operation_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_platform_admin_operation_version"),
        sa.CheckConstraint(
            "length(idempotency_key) > 0", name="ck_platform_admin_operation_idempotency_nonempty"
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64", name="ck_platform_admin_operation_request_hash"
        ),
        sa.CheckConstraint(
            "length(reason) > 0", name="ck_platform_admin_operation_reason_nonempty"
        ),
        sa.CheckConstraint(
            "approved_by_principal_id IS NULL OR "
            "approved_by_principal_id <> requested_by_principal_id",
            name="ck_platform_admin_operation_distinct_approver",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["requested_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "requested_by_principal_id",
            "idempotency_key",
            name="uq_platform_admin_operation_actor_idempotency",
        ),
    )
    op.create_index(
        "ix_platform_admin_operation_queue",
        "saas_platform_admin_operations",
        ["status", "created_at", "id"],
    )
    op.create_index(
        "ix_platform_admin_operation_target",
        "saas_platform_admin_operations",
        ["target_type", "target_id", "created_at"],
    )

    op.create_table(
        "saas_platform_support_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("project_ids", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("incident_ref", sa.String(256)),
        sa.Column("customer_approval_required", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("customer_approved_by_user_id", sa.Uuid()),
        sa.Column("customer_approval_reason", sa.String(1024)),
        sa.Column("customer_approved_at", sa.DateTime(timezone=True)),
        sa.Column("staff_approved_by_principal_id", sa.Uuid()),
        sa.Column("staff_approval_reason", sa.String(1024)),
        sa.Column("staff_approved_at", sa.DateTime(timezone=True)),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_by_actor_type", sa.String(16)),
        sa.Column("revoked_by_actor_id", sa.Uuid()),
        sa.Column("revocation_reason", sa.String(1024)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "mode IN ('standard', 'break_glass')", name="ck_platform_support_grant_mode"
        ),
        sa.CheckConstraint(
            "status IN ('pending_customer_approval', 'pending_staff_approval', "
            "'active', 'rejected', 'revoked', 'expired')",
            name="ck_platform_support_grant_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_platform_support_grant_version"),
        sa.CheckConstraint("length(reason) > 0", name="ck_platform_support_grant_reason_nonempty"),
        sa.CheckConstraint(
            "requested_at < expires_at", name="ck_platform_support_grant_expiry_order"
        ),
        sa.CheckConstraint(
            "(mode = 'standard' AND customer_approval_required = true) OR "
            "(mode = 'break_glass' AND customer_approval_required = false "
            "AND length(incident_ref) > 0)",
            name="ck_platform_support_grant_mode_policy",
        ),
        sa.CheckConstraint(
            "staff_approved_by_principal_id IS NULL OR "
            "staff_approved_by_principal_id <> requested_by_principal_id",
            name="ck_platform_support_grant_distinct_staff_approver",
        ),
        sa.CheckConstraint(
            "revoked_by_actor_type IS NULL OR revoked_by_actor_type IN ('staff', 'customer')",
            name="ck_platform_support_grant_revoker_type",
        ),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["saas_platform_admin_operations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["requested_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["customer_approved_by_user_id"], ["saas_global_users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["staff_approved_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_id"),
    )
    op.create_index(
        "ix_platform_support_grant_tenant",
        "saas_platform_support_grants",
        ["tenant_id", "status", "expires_at", "id"],
    )
    op.create_index(
        "ix_platform_support_grant_requester",
        "saas_platform_support_grants",
        ["requested_by_principal_id", "status", "expires_at"],
    )

    op.create_table(
        "saas_platform_support_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("grant_id", sa.Uuid(), nullable=False),
        sa.Column("principal_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "length(token_hash) = 64", name="ck_platform_support_session_token_hash"
        ),
        sa.CheckConstraint(
            "issued_at < expires_at", name="ck_platform_support_session_expiry_order"
        ),
        sa.ForeignKeyConstraint(
            ["grant_id"], ["saas_platform_support_grants.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["saas_platform_staff_principals.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_platform_support_session_active",
        "saas_platform_support_sessions",
        ["grant_id", "principal_id", "revoked_at", "expires_at"],
    )

    op.create_table(
        "saas_platform_audit_chain_heads",
        sa.Column("partition_key", sa.String(64), nullable=False),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("last_event_hash", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("last_sequence >= 0", name="ck_platform_audit_head_sequence"),
        sa.CheckConstraint("length(last_event_hash) = 64", name="ck_platform_audit_head_hash"),
        sa.PrimaryKeyConstraint("partition_key"),
    )
    # Serialize the first append as well as every later append. Keeping a
    # permanent empty head prevents concurrent first writers from racing on the
    # primary key while remaining an empty/fact-free downgrade state.
    op.execute(
        sa.text(
            "INSERT INTO saas_platform_audit_chain_heads "
            "(partition_key, last_sequence, last_event_hash, updated_at) "
            "VALUES ('platform', 0, :zero_hash, CURRENT_TIMESTAMP)"
        ).bindparams(zero_hash="0" * 64)
    )

    op.create_table(
        "saas_platform_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sequence_no", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("target_type", sa.String(64), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("operation_id", sa.Uuid()),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("sequence_no > 0", name="ck_platform_audit_event_sequence"),
        sa.CheckConstraint(
            "actor_type IN ('staff', 'customer', 'system')",
            name="ck_platform_audit_event_actor_type",
        ),
        sa.CheckConstraint("length(event_type) > 0", name="ck_platform_audit_event_type_nonempty"),
        sa.CheckConstraint(
            "length(target_type) > 0", name="ck_platform_audit_target_type_nonempty"
        ),
        sa.CheckConstraint("length(payload_hash) = 64", name="ck_platform_audit_payload_hash"),
        sa.CheckConstraint("length(previous_hash) = 64", name="ck_platform_audit_previous_hash"),
        sa.CheckConstraint("length(event_hash) = 64", name="ck_platform_audit_event_hash"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["saas_platform_admin_operations.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sequence_no"),
        sa.UniqueConstraint("event_hash"),
    )
    op.create_index(
        "ix_platform_audit_tenant_sequence",
        "saas_platform_audit_events",
        ["tenant_id", "sequence_no"],
    )
    op.create_index(
        "ix_platform_audit_target_sequence",
        "saas_platform_audit_events",
        ["target_type", "target_id", "sequence_no"],
    )

    op.create_table(
        "saas_platform_audit_exports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("approved_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("from_sequence", sa.Integer(), nullable=False),
        sa.Column("to_sequence", sa.Integer(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("chain_head_hash", sa.String(64), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("signature_algorithm", sa.String(32), nullable=False),
        sa.Column("signing_key_id", sa.String(128), nullable=False),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("from_sequence > 0", name="ck_platform_audit_export_from"),
        sa.CheckConstraint("to_sequence >= from_sequence", name="ck_platform_audit_export_range"),
        sa.CheckConstraint("event_count > 0", name="ck_platform_audit_export_count"),
        sa.CheckConstraint(
            "length(chain_head_hash) = 64", name="ck_platform_audit_export_chain_hash"
        ),
        sa.CheckConstraint(
            "length(content_hash) = 64", name="ck_platform_audit_export_content_hash"
        ),
        sa.CheckConstraint(
            "signature_algorithm = 'hmac-sha256'",
            name="ck_platform_audit_export_signature_algorithm",
        ),
        sa.CheckConstraint(
            "length(signing_key_id) > 0", name="ck_platform_audit_export_key_nonempty"
        ),
        sa.CheckConstraint("length(signature) = 64", name="ck_platform_audit_export_signature"),
        sa.CheckConstraint(
            "requested_by_principal_id <> approved_by_principal_id",
            name="ck_platform_audit_export_distinct_approver",
        ),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["saas_platform_admin_operations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_id"),
    )
    op.create_index(
        "ix_platform_audit_export_created",
        "saas_platform_audit_exports",
        ["created_at", "id"],
    )


def _install_postgresql_security() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    support_agent = _active_staff("'support_agent'")
    operator = _active_staff("'platform_operator'")
    auditor = _active_staff(
        "'platform_operator', 'platform_security_auditor', 'compliance_operator'"
    )
    support_reader = _active_staff(
        "'platform_operator', 'platform_security_auditor', 'support_agent', 'compliance_operator'"
    )
    customer = _tenant_admin()
    exact_grant_customer = f"({customer} AND tenant_id = {_TENANT} AND id = {_TARGET_GRANT})"
    support_token_session = (
        f"({_SUPPORT} AND token_hash = {_SUPPORT_TOKEN} "
        "AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP)"
    )
    support_token_grant = (
        f"({_SUPPORT} AND tenant_id = {_TARGET_TENANT} AND status = 'active' "
        "AND expires_at > CURRENT_TIMESTAMP AND EXISTS ("
        "SELECT 1 FROM saas_platform_support_sessions pc3_support_session "
        "WHERE pc3_support_session.grant_id = saas_platform_support_grants.id "
        f"AND pc3_support_session.token_hash = {_SUPPORT_TOKEN} "
        "AND pc3_support_session.revoked_at IS NULL "
        "AND pc3_support_session.expires_at > CURRENT_TIMESTAMP))"
    )

    op.execute(
        'CREATE POLICY "rls_platform_admin_operation_read" ON saas_platform_admin_operations '
        f"FOR SELECT USING ({_EMERGENCY} OR {support_reader} OR "
        f"({customer} AND tenant_id = {_TENANT} AND EXISTS ("
        "SELECT 1 FROM saas_platform_support_grants pc3_grant "
        "WHERE pc3_grant.operation_id = saas_platform_admin_operations.id "
        f"AND pc3_grant.id = {_TARGET_GRANT})))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_admin_operation_insert" ON saas_platform_admin_operations '
        f"FOR INSERT WITH CHECK ({_EMERGENCY} OR (({support_agent} OR {auditor}) "
        f"AND id = {_TARGET_OPERATION} AND requested_by_principal_id = {_PRINCIPAL}))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_admin_operation_update" ON saas_platform_admin_operations '
        f"FOR UPDATE USING ({_EMERGENCY} OR ({operator} AND id = {_TARGET_OPERATION}) OR "
        f"({customer} AND tenant_id = {_TENANT} AND EXISTS ("
        "SELECT 1 FROM saas_platform_support_grants pc3_grant "
        "WHERE pc3_grant.operation_id = saas_platform_admin_operations.id "
        f"AND pc3_grant.id = {_TARGET_GRANT}))) WITH CHECK ("
        f"{_EMERGENCY} OR ({operator} AND id = {_TARGET_OPERATION}) OR "
        f"({customer} AND tenant_id = {_TENANT} AND EXISTS ("
        "SELECT 1 FROM saas_platform_support_grants pc3_grant "
        "WHERE pc3_grant.operation_id = saas_platform_admin_operations.id "
        f"AND pc3_grant.id = {_TARGET_GRANT})))"
    )

    op.execute(
        'CREATE POLICY "rls_platform_support_grant_read" ON saas_platform_support_grants '
        f"FOR SELECT USING ({_EMERGENCY} OR {support_reader} OR "
        f"({customer} AND tenant_id = {_TENANT}) OR {support_token_grant})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_support_grant_insert" ON saas_platform_support_grants '
        f"FOR INSERT WITH CHECK ({_EMERGENCY} OR ({support_agent} "
        f"AND id = {_TARGET_GRANT} AND tenant_id = {_TARGET_TENANT} "
        f"AND requested_by_principal_id = {_PRINCIPAL}))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_support_grant_update" ON saas_platform_support_grants '
        f"FOR UPDATE USING ({_EMERGENCY} OR ({operator} AND id = {_TARGET_GRANT}) "
        f"OR {exact_grant_customer}) WITH CHECK ({_EMERGENCY} OR "
        f"({operator} AND id = {_TARGET_GRANT}) OR {exact_grant_customer})"
    )

    op.execute(
        'CREATE POLICY "rls_platform_support_session_read" ON saas_platform_support_sessions '
        f"FOR SELECT USING ({_EMERGENCY} OR {_GOVERNANCE} OR {support_token_session})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_support_session_insert" ON saas_platform_support_sessions '
        f"FOR INSERT WITH CHECK ({_EMERGENCY} OR ({support_agent} "
        f"AND principal_id = {_PRINCIPAL} AND grant_id = {_TARGET_GRANT}))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_support_session_update" ON saas_platform_support_sessions '
        f"FOR UPDATE USING ({_EMERGENCY} OR ({operator} AND grant_id = {_TARGET_GRANT}) "
        f"OR ({customer} AND grant_id = {_TARGET_GRANT}) OR {support_token_session}) "
        f"WITH CHECK ({_EMERGENCY} OR ({operator} AND grant_id = {_TARGET_GRANT}) "
        f"OR ({customer} AND grant_id = {_TARGET_GRANT}) OR {support_token_session})"
    )

    op.execute(
        'CREATE POLICY "rls_platform_audit_head_governance" ON saas_platform_audit_chain_heads '
        f"FOR ALL USING ({_EMERGENCY} OR {_GOVERNANCE}) "
        f"WITH CHECK ({_EMERGENCY} OR {_GOVERNANCE})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_audit_event_read" ON saas_platform_audit_events '
        f"FOR SELECT USING ({_EMERGENCY} OR {auditor} OR "
        f"({customer} AND tenant_id = {_TENANT}))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_audit_event_insert" ON saas_platform_audit_events '
        f"FOR INSERT WITH CHECK ({_EMERGENCY} OR ({_GOVERNANCE} AND ("
        f"(actor_type = 'staff' AND actor_id = {_PRINCIPAL}) OR "
        f"(actor_type = 'customer' AND actor_id = {_ACTOR} AND tenant_id = {_TENANT}))))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_audit_export_read" ON saas_platform_audit_exports '
        f"FOR SELECT USING ({_EMERGENCY} OR {auditor})"
    )
    op.execute(
        'CREATE POLICY "rls_platform_audit_export_insert" ON saas_platform_audit_exports '
        f"FOR INSERT WITH CHECK ({_EMERGENCY} OR ({operator} "
        f"AND operation_id = {_TARGET_OPERATION} "
        f"AND approved_by_principal_id = {_PRINCIPAL}))"
    )

    op.execute(
        'CREATE POLICY "rls_outbox_pc3_platform_insert" ON saas_control_plane_outbox '
        f"FOR INSERT WITH CHECK ({_EMERGENCY} OR (({support_agent} OR {operator}) "
        f"AND tenant_id = {_TARGET_TENANT}))"
    )
    op.execute(
        'CREATE POLICY "rls_outbox_pc3_platform_read" ON saas_control_plane_outbox '
        f"FOR SELECT USING ({_EMERGENCY} OR (({support_agent} OR {operator}) "
        f"AND tenant_id = {_TARGET_TENANT}))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_staff_support_session" ON saas_platform_staff_principals '
        f"FOR SELECT USING ({_SUPPORT} AND EXISTS ("
        "SELECT 1 FROM saas_platform_support_sessions pc3_support_session "
        "WHERE pc3_support_session.principal_id = saas_platform_staff_principals.id "
        f"AND pc3_support_session.token_hash = {_SUPPORT_TOKEN} "
        "AND pc3_support_session.revoked_at IS NULL "
        "AND pc3_support_session.expires_at > CURRENT_TIMESTAMP))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_assignment_support_session" '
        "ON saas_platform_role_assignments "
        f"FOR SELECT USING ({_SUPPORT} AND EXISTS ("
        "SELECT 1 FROM saas_platform_support_sessions pc3_support_session "
        "WHERE pc3_support_session.principal_id = saas_platform_role_assignments.principal_id "
        f"AND pc3_support_session.token_hash = {_SUPPORT_TOKEN} "
        "AND pc3_support_session.revoked_at IS NULL "
        "AND pc3_support_session.expires_at > CURRENT_TIMESTAMP))"
    )

    op.execute(
        "CREATE FUNCTION saas_reject_platform_audit_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
        "'platform audit records are immutable' USING ERRCODE = '55000'; END $$"
    )
    for table in ("saas_platform_audit_events", "saas_platform_audit_exports"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION saas_reject_platform_audit_mutation()"
        )


def upgrade() -> None:
    _create_tables()
    _install_postgresql_security()


def _require_no_pc3_facts() -> None:
    bind = op.get_bind()
    counts = {
        table: bind.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar_one()
        for table in _TABLES
        if table != "saas_platform_audit_chain_heads"
    }
    head_events = bind.execute(
        sa.text("SELECT count(*) FROM saas_platform_audit_chain_heads WHERE last_sequence > 0")
    ).scalar_one()
    if any(counts.values()) or head_events:
        raise RuntimeError(
            "pc3a00000001 downgrade refused: governed access, Admin Operation, or "
            "immutable audit facts exist; retain this revision or perform an explicitly "
            "approved forward-compatible archival migration"
        )


def downgrade() -> None:
    _require_no_pc3_facts()
    if op.get_bind().dialect.name == "postgresql":
        # Remove cross-table policy dependencies before reversing table
        # creation order. PostgreSQL otherwise correctly refuses to drop the
        # referenced support Session/Grant tables.
        op.execute(
            'DROP POLICY IF EXISTS "rls_platform_admin_operation_read" '
            "ON saas_platform_admin_operations"
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_platform_admin_operation_update" '
            "ON saas_platform_admin_operations"
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_platform_support_grant_read" '
            "ON saas_platform_support_grants"
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_platform_assignment_support_session" '
            "ON saas_platform_role_assignments"
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_platform_staff_support_session" '
            "ON saas_platform_staff_principals"
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_outbox_pc3_platform_read" ON saas_control_plane_outbox'
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_outbox_pc3_platform_insert" ON saas_control_plane_outbox'
        )
        op.execute("DROP FUNCTION IF EXISTS saas_reject_platform_audit_mutation() CASCADE")
    for table in reversed(_TABLES):
        op.drop_table(table)
