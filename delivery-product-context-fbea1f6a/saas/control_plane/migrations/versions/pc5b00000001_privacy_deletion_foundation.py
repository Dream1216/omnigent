"""Add PC5 Legal Hold, deletion Manifest, and identity Tombstone authority.

Revision ID: pc5b00000001
Revises: pc5a00000003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc5b00000001"
down_revision: str | None = "pc5a00000003"
branch_labels: str | None = None
depends_on: str | None = None

_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_TARGET_TENANT = "NULLIF(current_setting('app.platform_target_tenant_id', true), '')::uuid"
_TARGET_USER = "NULLIF(current_setting('app.platform_target_user_id', true), '')::uuid"
_TARGET_MANIFEST = "NULLIF(current_setting('app.platform_privacy_manifest_id', true), '')::uuid"
_LOCATOR_HASH = "NULLIF(current_setting('app.privacy_locator_hash', true), '')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_AUTHENTICATOR = "pg_has_role(current_user, 'saas_authenticator', 'member')"
_SCIM = "pg_has_role(current_user, 'saas_governance', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _privacy_actor() -> str:
    return (
        f"({_GOVERNANCE} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} "
        "AND assignment.role IN ('platform_operator', 'compliance_operator') "
        "AND assignment.status = 'active' "
        "AND (assignment.expires_at IS NULL OR assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _create_tables() -> None:
    op.create_table(
        "saas_privacy_legal_holds",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("authority_ref", sa.String(256), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("review_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("placed_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("released_by_principal_id", sa.Uuid()),
        sa.Column("release_reason", sa.String(1024)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("released_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant')", name="ck_privacy_hold_target_type"
        ),
        sa.CheckConstraint("status IN ('active', 'released')", name="ck_privacy_hold_status"),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_hold_target_scope",
        ),
        sa.CheckConstraint("length(authority_ref) > 0", name="ck_privacy_hold_authority"),
        sa.CheckConstraint("length(reason) > 0", name="ck_privacy_hold_reason"),
        sa.CheckConstraint("review_due_at > created_at", name="ck_privacy_hold_review_deadline"),
        sa.CheckConstraint("version > 0", name="ck_privacy_hold_version"),
        sa.CheckConstraint(
            "(status = 'active' AND released_by_principal_id IS NULL "
            "AND release_reason IS NULL AND released_at IS NULL) OR "
            "(status = 'released' AND released_by_principal_id IS NOT NULL "
            "AND length(release_reason) > 0 AND released_at IS NOT NULL)",
            name="ck_privacy_hold_release_state",
        ),
        sa.ForeignKeyConstraint(
            ["placed_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["released_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_privacy_active_hold_target",
        "saas_privacy_legal_holds",
        ["target_type", "target_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_privacy_hold_target",
        "saas_privacy_legal_holds",
        ["target_type", "target_id", "status", "id"],
    )

    op.create_table(
        "saas_privacy_deletion_manifests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("requested_by_principal_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("approval_ref", sa.String(256), nullable=False),
        sa.Column("completion_approval_ref", sa.String(256)),
        sa.Column("reason", sa.String(1024), nullable=False),
        sa.Column("expected_target_version", sa.Integer(), nullable=False),
        sa.Column("preview_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("blockers", sa.JSON(), nullable=False),
        sa.Column("surface_outcomes", sa.JSON(), nullable=False),
        sa.Column("manifest_hash", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant')", name="ck_privacy_manifest_target_type"
        ),
        sa.CheckConstraint(
            "status IN ('executing', 'ready_to_finalize', 'completed')",
            name="ck_privacy_manifest_status",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_manifest_target_scope",
        ),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_privacy_manifest_idempotency"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_privacy_manifest_request_hash"),
        sa.CheckConstraint("length(approval_ref) > 0", name="ck_privacy_manifest_approval"),
        sa.CheckConstraint(
            "completion_approval_ref IS NULL OR length(completion_approval_ref) > 0",
            name="ck_privacy_manifest_completion_approval",
        ),
        sa.CheckConstraint("length(reason) > 0", name="ck_privacy_manifest_reason"),
        sa.CheckConstraint(
            "expected_target_version > 0", name="ck_privacy_manifest_target_version"
        ),
        sa.CheckConstraint("length(preview_hash) = 64", name="ck_privacy_manifest_preview_hash"),
        sa.CheckConstraint("version > 0", name="ck_privacy_manifest_version"),
        sa.CheckConstraint(
            "(status <> 'completed' AND completed_at IS NULL AND manifest_hash IS NULL "
            "AND completion_approval_ref IS NULL) OR "
            "(status = 'completed' AND completed_at IS NOT NULL AND length(manifest_hash) = 64 "
            "AND length(completion_approval_ref) > 0)",
            name="ck_privacy_manifest_completion",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_principal_id"],
            ["saas_platform_staff_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "requested_by_principal_id",
            "idempotency_key",
            name="uq_privacy_manifest_requester_idempotency",
        ),
    )
    op.create_index(
        "uq_privacy_open_manifest_target",
        "saas_privacy_deletion_manifests",
        ["target_type", "target_id"],
        unique=True,
        sqlite_where=sa.text("status <> 'completed'"),
        postgresql_where=sa.text("status <> 'completed'"),
    )
    op.create_index(
        "ix_privacy_manifest_target",
        "saas_privacy_deletion_manifests",
        ["target_type", "target_id", "status", "id"],
    )

    op.create_table(
        "saas_privacy_identity_tombstones",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("manifest_id", sa.Uuid(), nullable=False),
        sa.Column("target_user_id", sa.Uuid()),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("locator_kind", sa.String(32), nullable=False),
        sa.Column("locator_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "locator_kind IN ('oidc_subject', 'scim_user')",
            name="ck_privacy_tombstone_kind",
        ),
        sa.CheckConstraint("length(locator_hash) = 64", name="ck_privacy_tombstone_hash"),
        sa.ForeignKeyConstraint(
            ["manifest_id"],
            ["saas_privacy_deletion_manifests.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("locator_hash"),
    )
    op.create_index(
        "ix_privacy_tombstone_target",
        "saas_privacy_identity_tombstones",
        ["target_user_id", "tenant_id", "locator_kind"],
    )
    with op.batch_alter_table("saas_membership_invitations") as batch:
        batch.add_column(sa.Column("deletion_manifest_id", sa.Uuid()))
        batch.create_foreign_key(
            "fk_invitation_deletion_manifest",
            "saas_privacy_deletion_manifests",
            ["deletion_manifest_id"],
            ["id"],
            ondelete="RESTRICT",
        )
    with op.batch_alter_table("saas_enterprise_scim_events") as batch:
        batch.add_column(sa.Column("redacted_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("redaction_manifest_id", sa.Uuid()))
        batch.add_column(sa.Column("original_result_hash", sa.String(64)))
        batch.create_foreign_key(
            "fk_scim_event_redaction_manifest",
            "saas_privacy_deletion_manifests",
            ["redaction_manifest_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_scim_event_redaction",
            "(redacted_at IS NULL AND redaction_manifest_id IS NULL "
            "AND original_result_hash IS NULL) OR "
            "(redacted_at IS NOT NULL AND redaction_manifest_id IS NOT NULL "
            "AND length(original_result_hash) = 64)",
        )


def _install_postgresql_policies() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    actor = _privacy_actor()
    target = (
        f"((target_type = 'tenant' AND target_id = {_TARGET_TENANT}) OR "
        f"(target_type = 'global_user' AND target_id = {_TARGET_USER}))"
    )
    for table in ("saas_privacy_legal_holds", "saas_privacy_deletion_manifests"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY rls_{table}_platform ON {table} FOR ALL "
            f"USING ({_EMERGENCY} OR ({actor} AND {target})) "
            f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {target}))"
        )

    tombstone = "saas_privacy_identity_tombstones"
    op.execute(f"ALTER TABLE {tombstone} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {tombstone} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY rls_{tombstone}_platform ON {tombstone} FOR ALL "
        f"USING ({_EMERGENCY} OR ({actor} AND (manifest_id = {_TARGET_MANIFEST} "
        f"OR target_user_id = {_TARGET_USER} OR tenant_id = {_TARGET_TENANT}))) "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND manifest_id = {_TARGET_MANIFEST}))"
    )
    op.execute(
        f"CREATE POLICY rls_{tombstone}_locator ON {tombstone} FOR SELECT "
        f"USING ((({_AUTHENTICATOR}) OR ({_SCIM})) AND locator_hash = {_LOCATOR_HASH})"
    )

    user_scope = f"({_EMERGENCY} OR ({actor} AND id = {_TARGET_USER}))"
    op.execute(
        "CREATE POLICY rls_saas_global_users_privacy_target ON saas_global_users FOR ALL "
        f"USING ({user_scope}) WITH CHECK ({user_scope})"
    )
    for table, predicate in {
        "saas_identity_connections": f"user_id = {_TARGET_USER}",
        "saas_auth_sessions": f"user_id = {_TARGET_USER}",
        "saas_password_credentials": f"user_id = {_TARGET_USER}",
        "saas_tenants": f"id = {_TARGET_TENANT}",
        "saas_tenant_memberships": (f"tenant_id = {_TARGET_TENANT} OR user_id = {_TARGET_USER}"),
        "saas_space_memberships": (f"tenant_id = {_TARGET_TENANT} OR user_id = {_TARGET_USER}"),
        "saas_project_memberships": (
            f"tenant_id = {_TARGET_TENANT} OR "
            f"(subject_type = 'user' AND subject_id = {_TARGET_USER})"
        ),
        "saas_resource_grants": (
            f"tenant_id = {_TARGET_TENANT} OR "
            f"(subject_type = 'user' AND subject_id = {_TARGET_USER})"
        ),
        "saas_service_accounts": (
            f"tenant_id = {_TARGET_TENANT} OR steward_user_id = {_TARGET_USER}"
        ),
        "saas_api_credentials": f"tenant_id = {_TARGET_TENANT}",
        "saas_enterprise_group_memberships": (
            f"tenant_id = {_TARGET_TENANT} OR user_id = {_TARGET_USER}"
        ),
        "saas_enterprise_scim_directories": f"tenant_id = {_TARGET_TENANT}",
        "saas_enterprise_scim_users": (
            f"tenant_id = {_TARGET_TENANT} OR user_id = {_TARGET_USER} OR ("
            "user_id IS NULL AND EXISTS ("
            "SELECT 1 FROM saas_privacy_identity_tombstones privacy_scim_tombstone "
            f"WHERE privacy_scim_tombstone.manifest_id = {_TARGET_MANIFEST} "
            f"AND privacy_scim_tombstone.target_user_id = {_TARGET_USER} "
            "AND privacy_scim_tombstone.tenant_id = saas_enterprise_scim_users.tenant_id "
            "AND privacy_scim_tombstone.locator_kind = 'scim_user' "
            "AND saas_enterprise_scim_users.external_id = "
            "'deleted:' || privacy_scim_tombstone.locator_hash))"
        ),
        "saas_enterprise_scim_groups": f"tenant_id = {_TARGET_TENANT}",
        "saas_enterprise_scim_events": (
            f"tenant_id = {_TARGET_TENANT} OR EXISTS ("
            "SELECT 1 FROM saas_enterprise_scim_users privacy_scim_subject "
            "WHERE privacy_scim_subject.directory_id = "
            "saas_enterprise_scim_events.directory_id "
            f"AND privacy_scim_subject.user_id = {_TARGET_USER})"
        ),
        "saas_platform_user_projections": f"user_id = {_TARGET_USER}",
        "saas_runs": f"tenant_id = {_TARGET_TENANT}",
        "saas_platform_support_grants": f"tenant_id = {_TARGET_TENANT}",
    }.items():
        op.execute(
            f"CREATE POLICY rls_{table}_privacy_target ON {table} FOR ALL "
            f"USING ({_EMERGENCY} OR ({actor} AND ({predicate}))) "
            f"WITH CHECK ({_EMERGENCY} OR ({actor} AND ({predicate})))"
        )
    invitation_old = (
        f"tenant_id = {_TARGET_TENANT} OR accepted_by = {_TARGET_USER} OR "
        "email_normalized = (SELECT privacy_subject.primary_email_normalized "
        "FROM saas_global_users privacy_subject "
        f"WHERE privacy_subject.id = {_TARGET_USER})"
    )
    invitation_new = (
        f"tenant_id = {_TARGET_TENANT} OR ({_TARGET_USER} IS NOT NULL "
        f"AND deletion_manifest_id = {_TARGET_MANIFEST} AND EXISTS ("
        "SELECT 1 FROM saas_privacy_deletion_manifests privacy_invitation_manifest "
        f"WHERE privacy_invitation_manifest.id = {_TARGET_MANIFEST} "
        "AND privacy_invitation_manifest.target_type = 'global_user' "
        f"AND privacy_invitation_manifest.target_id = {_TARGET_USER}) "
        "AND accepted_by IS NULL AND status <> 'pending' "
        "AND email_normalized ~ '^deleted-[0-9a-f]{64}@invalid$')"
    )
    op.execute(
        "CREATE POLICY rls_saas_membership_invitations_privacy_target "
        "ON saas_membership_invitations FOR ALL "
        f"USING ({_EMERGENCY} OR ({actor} AND ({invitation_old} OR {invitation_new}))) "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND ({invitation_new})))"
    )
    op.execute(
        "CREATE OR REPLACE FUNCTION reject_scim_event_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN "
        "IF TG_OP = 'UPDATE' AND OLD.redacted_at IS NULL AND NEW.redacted_at IS NOT NULL "
        f"AND NEW.redaction_manifest_id = {_TARGET_MANIFEST} "
        "AND (to_jsonb(NEW) - ARRAY['result', 'redacted_at', 'redaction_manifest_id', "
        "'original_result_hash']) = (to_jsonb(OLD) - ARRAY['result', 'redacted_at', "
        "'redaction_manifest_id', 'original_result_hash']) "
        "THEN RETURN NEW; END IF; "
        "RAISE EXCEPTION 'SCIM event receipts are immutable except one governed redaction'; "
        "END; $$"
    )
    op.execute(
        "CREATE POLICY rls_outbox_privacy_insert ON saas_control_plane_outbox "
        f"FOR INSERT WITH CHECK ({_EMERGENCY} OR {actor})"
    )


def upgrade() -> None:
    _create_tables()
    _install_postgresql_policies()


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM saas_privacy_legal_holds LIMIT 1) "
            "OR EXISTS (SELECT 1 FROM saas_privacy_deletion_manifests LIMIT 1) "
            "OR EXISTS (SELECT 1 FROM saas_privacy_identity_tombstones LIMIT 1) "
            "THEN RAISE EXCEPTION 'cannot downgrade with PC5 privacy records'; END IF; END $$"
        )
        for table in (
            "saas_identity_connections",
            "saas_auth_sessions",
            "saas_password_credentials",
            "saas_tenants",
            "saas_tenant_memberships",
            "saas_space_memberships",
            "saas_membership_invitations",
            "saas_project_memberships",
            "saas_resource_grants",
            "saas_service_accounts",
            "saas_api_credentials",
            "saas_enterprise_group_memberships",
            "saas_enterprise_scim_directories",
            "saas_enterprise_scim_users",
            "saas_enterprise_scim_groups",
            "saas_enterprise_scim_events",
            "saas_platform_user_projections",
            "saas_runs",
            "saas_platform_support_grants",
            "saas_global_users",
        ):
            op.execute(f"DROP POLICY IF EXISTS rls_{table}_privacy_target ON {table}")
        op.execute("DROP POLICY IF EXISTS rls_outbox_privacy_insert ON saas_control_plane_outbox")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "CREATE OR REPLACE FUNCTION reject_scim_event_mutation() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN "
            "RAISE EXCEPTION 'SCIM event receipts are immutable'; END; $$"
        )
    with op.batch_alter_table("saas_enterprise_scim_events") as batch:
        batch.drop_constraint("ck_scim_event_redaction", type_="check")
        batch.drop_constraint("fk_scim_event_redaction_manifest", type_="foreignkey")
        batch.drop_column("original_result_hash")
        batch.drop_column("redaction_manifest_id")
        batch.drop_column("redacted_at")
    with op.batch_alter_table("saas_membership_invitations") as batch:
        batch.drop_constraint("fk_invitation_deletion_manifest", type_="foreignkey")
        batch.drop_column("deletion_manifest_id")
    op.drop_index("ix_privacy_tombstone_target", table_name="saas_privacy_identity_tombstones")
    op.drop_table("saas_privacy_identity_tombstones")
    op.drop_index("ix_privacy_manifest_target", table_name="saas_privacy_deletion_manifests")
    op.drop_index("uq_privacy_open_manifest_target", table_name="saas_privacy_deletion_manifests")
    op.drop_table("saas_privacy_deletion_manifests")
    op.drop_index("ix_privacy_hold_target", table_name="saas_privacy_legal_holds")
    op.drop_index("uq_privacy_active_hold_target", table_name="saas_privacy_legal_holds")
    op.drop_table("saas_privacy_legal_holds")
