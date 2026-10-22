"""Add durable cross-database Runtime Binding Saga state."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p2a000000003"
down_revision: str | None = "p2a000000002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_SPACE = "NULLIF(current_setting('app.space_id', true), '')::uuid"
_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_GOVERNANCE = "pg_has_role(current_user, 'saas_governance', 'member')"


def upgrade() -> None:
    """Create Saga state separately from official runtime migrations."""

    op.create_table(
        "saas_runtime_binding_sagas",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("runtime_partition_id", sa.Uuid(), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("saas_resource_id", sa.Uuid(), nullable=False),
        sa.Column("runtime_resource_id", sa.String(256), nullable=True),
        sa.Column("binding_id", sa.Uuid(), nullable=True),
        sa.Column("partition_generation", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(2048), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'runtime_created', 'bound', 'compensating', "
            "'compensated', 'failed')",
            name="ck_binding_saga_status",
        ),
        sa.CheckConstraint("length(resource_type) > 0", name="ck_binding_saga_type_nonempty"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="ck_binding_saga_key_nonempty"),
        sa.CheckConstraint("length(request_hash) = 64", name="ck_binding_saga_request_hash"),
        sa.CheckConstraint("partition_generation > 0", name="ck_binding_saga_generation"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_binding_saga_attempt_count"),
        sa.CheckConstraint(
            "(status = 'pending' AND runtime_resource_id IS NULL) OR "
            "(status <> 'pending' AND runtime_resource_id IS NOT NULL)",
            name="ck_binding_saga_runtime_resource_state",
        ),
        sa.CheckConstraint(
            "(status = 'bound' AND binding_id IS NOT NULL) OR "
            "(status <> 'bound' AND binding_id IS NULL)",
            name="ck_binding_saga_binding_state",
        ),
        sa.ForeignKeyConstraint(
            ("binding_id",),
            ("saas_runtime_resource_bindings.id",),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id", "project_id"),
            ("saas_projects.tenant_id", "saas_projects.space_id", "saas_projects.id"),
            name="fk_binding_saga_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("runtime_partition_id", "tenant_id", "space_id"),
            (
                "saas_runtime_partitions.id",
                "saas_runtime_partitions.tenant_id",
                "saas_runtime_partitions.space_id",
            ),
            name="fk_binding_saga_partition",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_index(
        "ix_binding_saga_scope_status",
        "saas_runtime_binding_sagas",
        ["tenant_id", "space_id", "project_id", "status"],
    )

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute('ALTER TABLE "saas_runtime_binding_sagas" ENABLE ROW LEVEL SECURITY')
        predicate = (
            f"({_PLATFORM} OR ({_GOVERNANCE} AND tenant_id = {_TENANT}) OR "
            f"(tenant_id = {_TENANT} AND space_id = {_SPACE}))"
        )
        op.execute(
            'CREATE POLICY "rls_binding_saga_tenant_space" '
            'ON "saas_runtime_binding_sagas" '
            f"FOR ALL USING ({predicate}) WITH CHECK ({predicate})"
        )


def downgrade() -> None:
    """Remove durable Binding Saga state."""

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            'DROP POLICY IF EXISTS "rls_binding_saga_tenant_space" ON "saas_runtime_binding_sagas"'
        )
        op.execute('ALTER TABLE "saas_runtime_binding_sagas" DISABLE ROW LEVEL SECURITY')
    op.drop_index("ix_binding_saga_scope_status", table_name="saas_runtime_binding_sagas")
    op.drop_table("saas_runtime_binding_sagas")
