"""Add immutable P6 billing period close and entitlement rollover.

Revision ID: p6b000000001
Revises: pc2a00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p6b000000001"
down_revision: str | None = "pc2a00000001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "saas_billing_period_closes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("reconciliation_batch_id", sa.Uuid(), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("rolled_entitlement_count", sa.Integer(), nullable=False),
        sa.Column("usage_event_count", sa.Integer(), nullable=False),
        sa.Column("customer_charge_minor", sa.BigInteger(), nullable=False),
        sa.Column("customer_settled_minor", sa.BigInteger(), nullable=False),
        sa.Column("provider_cost_minor", sa.BigInteger(), nullable=False),
        sa.Column("reconciliation_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("close_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("closed_by", sa.Uuid(), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('closed', 'closed_with_resolved_exceptions')",
            name="ck_billing_period_close_status",
        ),
        sa.CheckConstraint("period_end > period_start", name="ck_billing_period_close_period"),
        sa.CheckConstraint(
            "rolled_entitlement_count >= 0 AND usage_event_count >= 0",
            name="ck_billing_period_close_counts",
        ),
        sa.CheckConstraint(
            "customer_charge_minor >= 0 AND customer_settled_minor >= 0 "
            "AND provider_cost_minor >= 0",
            name="ck_billing_period_close_amounts",
        ),
        sa.CheckConstraint(
            "length(reconciliation_evidence_sha256) = 64",
            name="ck_billing_period_close_reconciliation_hash",
        ),
        sa.CheckConstraint(
            "length(close_evidence_sha256) = 64",
            name="ck_billing_period_close_evidence_hash",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "reconciliation_batch_id"],
            [
                "saas_billing_reconciliation_batches.tenant_id",
                "saas_billing_reconciliation_batches.id",
            ],
            ondelete="RESTRICT",
            name="fk_billing_period_close_reconciliation",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "closed_by"],
            ["saas_tenant_memberships.tenant_id", "saas_tenant_memberships.user_id"],
            ondelete="RESTRICT",
            name="fk_billing_period_close_actor",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_period_close_scope"),
        sa.UniqueConstraint(
            "tenant_id", "period_start", "period_end", name="uq_billing_period_close_period"
        ),
    )
    op.create_index(
        "ix_billing_period_close_list",
        "saas_billing_period_closes",
        ["tenant_id", "period_end", "id"],
    )
    if op.get_bind().dialect.name == "postgresql":
        tenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
        platform = "pg_has_role(current_user, 'saas_platform', 'member')"
        billing = "pg_has_role(current_user, 'saas_billing', 'member')"
        predicate = f"({platform} OR ({billing} AND tenant_id = {tenant}))"
        op.execute("ALTER TABLE saas_billing_period_closes ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE saas_billing_period_closes FORCE ROW LEVEL SECURITY")
        op.execute(
            'CREATE POLICY "rls_saas_billing_period_closes_tenant" '
            "ON saas_billing_period_closes FOR ALL "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
        op.execute(
            "CREATE TRIGGER trg_saas_billing_period_closes_immutable "
            "BEFORE UPDATE OR DELETE ON saas_billing_period_closes "
            "FOR EACH ROW EXECUTE FUNCTION saas_reject_billing_fact_mutation()"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_saas_billing_period_closes_immutable "
            "ON saas_billing_period_closes"
        )
        op.execute(
            'DROP POLICY IF EXISTS "rls_saas_billing_period_closes_tenant" '
            "ON saas_billing_period_closes"
        )
    op.drop_index("ix_billing_period_close_list", table_name="saas_billing_period_closes")
    op.drop_table("saas_billing_period_closes")
