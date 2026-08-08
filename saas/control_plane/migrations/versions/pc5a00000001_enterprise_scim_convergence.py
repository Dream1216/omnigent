"""Create PC5 enterprise SCIM convergence authority.

Revision ID: pc5a00000001
Revises: pc3a00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "pc5a00000001"
down_revision: str | None = "pc3a00000001"
branch_labels: str | None = None
depends_on: str | None = None

_TABLES = (
    "saas_enterprise_scim_directories",
    "saas_enterprise_scim_users",
    "saas_enterprise_scim_groups",
    "saas_enterprise_scim_events",
)


def _create_tables() -> None:
    op.create_table(
        "saas_enterprise_scim_directories",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("token_prefix", sa.String(24), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("configured_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("rotated_at", sa.DateTime(timezone=True)),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("length(display_name) > 0", name="ck_scim_directory_name_nonempty"),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_scim_directory_token_hash"),
        sa.CheckConstraint("length(token_prefix) > 0", name="ck_scim_directory_token_prefix"),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_scim_directory_status"),
        sa.CheckConstraint("version > 0", name="ck_scim_directory_version"),
        sa.CheckConstraint(
            "(status = 'active' AND disabled_at IS NULL) OR "
            "(status = 'disabled' AND disabled_at IS NOT NULL)",
            name="ck_scim_directory_disable_state",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["configured_by"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
        sa.UniqueConstraint("tenant_id", "display_name", name="uq_scim_directory_tenant_name"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_scim_directory_tenant_id"),
    )
    op.create_index(
        "ix_scim_directory_tenant_status",
        "saas_enterprise_scim_directories",
        ["tenant_id", "status", "id"],
    )

    op.create_table(
        "saas_enterprise_scim_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("directory_id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False),
        sa.Column("user_id", sa.Uuid()),
        sa.Column("user_name_normalized", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(256)),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("source_version", sa.Integer(), nullable=False),
        sa.Column("source_state_hash", sa.String(64), nullable=False),
        sa.Column("deprovisioned_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(external_id) > 0", name="ck_scim_user_external_nonempty"),
        sa.CheckConstraint("length(user_name_normalized) > 0", name="ck_scim_user_name_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_scim_user_version"),
        sa.CheckConstraint("source_version > 0", name="ck_scim_user_source_version"),
        sa.CheckConstraint("length(source_state_hash) = 64", name="ck_scim_user_state_hash"),
        sa.CheckConstraint(
            "(active = true AND user_id IS NOT NULL AND deprovisioned_at IS NULL) OR "
            "(active = false AND deprovisioned_at IS NOT NULL)",
            name="ck_scim_user_lifecycle",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "directory_id"],
            [
                "saas_enterprise_scim_directories.tenant_id",
                "saas_enterprise_scim_directories.id",
            ],
            ondelete="RESTRICT",
            name="fk_scim_user_directory",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["saas_global_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "directory_id", "external_id", name="uq_scim_user_external"
        ),
        sa.UniqueConstraint("directory_id", "id", name="uq_scim_user_directory_id"),
        sa.UniqueConstraint("directory_id", "user_id", name="uq_scim_user_global_user"),
    )
    op.create_index(
        "ix_scim_user_directory_active",
        "saas_enterprise_scim_users",
        ["tenant_id", "directory_id", "active", "id"],
    )

    op.create_table(
        "saas_enterprise_scim_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("directory_id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False),
        sa.Column("enterprise_group_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("source_version", sa.Integer(), nullable=False),
        sa.Column("source_state_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(external_id) > 0", name="ck_scim_group_external_nonempty"),
        sa.CheckConstraint("length(display_name) > 0", name="ck_scim_group_name_nonempty"),
        sa.CheckConstraint("version > 0", name="ck_scim_group_version"),
        sa.CheckConstraint("source_version > 0", name="ck_scim_group_source_version"),
        sa.CheckConstraint("length(source_state_hash) = 64", name="ck_scim_group_state_hash"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "directory_id"],
            [
                "saas_enterprise_scim_directories.tenant_id",
                "saas_enterprise_scim_directories.id",
            ],
            ondelete="RESTRICT",
            name="fk_scim_group_directory",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "enterprise_group_id"],
            ["saas_enterprise_groups.tenant_id", "saas_enterprise_groups.id"],
            ondelete="RESTRICT",
            name="fk_scim_group_enterprise_group",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "directory_id", "external_id", name="uq_scim_group_external"
        ),
        sa.UniqueConstraint("directory_id", "id", name="uq_scim_group_directory_id"),
        sa.UniqueConstraint(
            "directory_id", "enterprise_group_id", name="uq_scim_group_enterprise_group"
        ),
    )
    op.create_index(
        "ix_scim_group_directory_active",
        "saas_enterprise_scim_groups",
        ["tenant_id", "directory_id", "active", "id"],
    )

    op.create_table(
        "saas_enterprise_scim_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("directory_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.String(256), nullable=False),
        sa.Column("resource_type", sa.String(16), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("source_version", sa.Integer(), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("disposition", sa.String(32), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("length(event_id) > 0", name="ck_scim_event_id_nonempty"),
        sa.CheckConstraint(
            "resource_type IN ('User', 'Group')", name="ck_scim_event_resource_type"
        ),
        sa.CheckConstraint("source_version > 0", name="ck_scim_event_source_version"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_scim_event_request_hash"),
        sa.CheckConstraint(
            "disposition IN ('applied', 'stale', 'blocked')",
            name="ck_scim_event_disposition",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "directory_id"],
            [
                "saas_enterprise_scim_directories.tenant_id",
                "saas_enterprise_scim_directories.id",
            ],
            ondelete="RESTRICT",
            name="fk_scim_event_directory",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("directory_id", "event_id", name="uq_scim_event_request"),
    )
    op.create_index(
        "ix_scim_event_directory_created",
        "saas_enterprise_scim_events",
        ["tenant_id", "directory_id", "created_at", "id"],
    )


def _enable_postgresql_guards() -> None:
    tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
    token = "NULLIF(current_setting('app.scim_token_hash', true), '')"
    platform = "pg_has_role(current_user, 'saas_platform', 'member')"
    tenant_scope = f"({platform} OR tenant_id = {tenant})"
    directory_read = f"({tenant_scope} OR token_hash = {token})"
    predicates = {
        "saas_enterprise_scim_directories": directory_read,
        "saas_enterprise_scim_users": tenant_scope,
        "saas_enterprise_scim_groups": tenant_scope,
        "saas_enterprise_scim_events": tenant_scope,
    }
    for table, predicate in predicates.items():
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY rls_{table}_select ON {table} FOR SELECT USING ({predicate})")
        write_predicate = tenant_scope
        op.execute(
            f"CREATE POLICY rls_{table}_insert ON {table} FOR INSERT "
            f"WITH CHECK ({write_predicate})"
        )
        if table != "saas_enterprise_scim_events":
            op.execute(
                f"CREATE POLICY rls_{table}_update ON {table} FOR UPDATE "
                f"USING ({write_predicate}) WITH CHECK ({write_predicate})"
            )
    op.execute(
        "CREATE FUNCTION reject_scim_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN RAISE EXCEPTION 'SCIM event receipts are immutable'; END; $$"
    )
    op.execute(
        "CREATE TRIGGER trg_scim_event_immutable BEFORE UPDATE OR DELETE "
        "ON saas_enterprise_scim_events FOR EACH ROW EXECUTE FUNCTION reject_scim_event_mutation()"
    )


def upgrade() -> None:
    _create_tables()
    if op.get_bind().dialect.name == "postgresql":
        _enable_postgresql_guards()


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM saas_enterprise_scim_events LIMIT 1) "
            "THEN RAISE EXCEPTION 'cannot downgrade with immutable PC5 SCIM receipts'; "
            "END IF; END $$"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS trg_scim_event_immutable ON saas_enterprise_scim_events"
        )
        op.execute("DROP FUNCTION IF EXISTS reject_scim_event_mutation()")
    op.drop_index("ix_scim_event_directory_created", table_name="saas_enterprise_scim_events")
    op.drop_table("saas_enterprise_scim_events")
    op.drop_index("ix_scim_group_directory_active", table_name="saas_enterprise_scim_groups")
    op.drop_table("saas_enterprise_scim_groups")
    op.drop_index("ix_scim_user_directory_active", table_name="saas_enterprise_scim_users")
    op.drop_table("saas_enterprise_scim_users")
    op.drop_index("ix_scim_directory_tenant_status", table_name="saas_enterprise_scim_directories")
    op.drop_table("saas_enterprise_scim_directories")
