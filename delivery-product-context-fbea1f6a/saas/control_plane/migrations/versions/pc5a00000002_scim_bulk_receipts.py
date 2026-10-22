"""Allow immutable PC5 SCIM Bulk request and result receipts.

Revision ID: pc5a00000002
Revises: pc5a00000001
"""

from __future__ import annotations

from alembic import op

revision: str = "pc5a00000002"
down_revision: str | None = "pc5a00000001"
branch_labels: str | None = None
depends_on: str | None = None


def _replace_resource_type_constraint(values: str) -> None:
    with op.batch_alter_table("saas_enterprise_scim_events") as batch:
        batch.drop_constraint("ck_scim_event_resource_type", type_="check")
        batch.create_check_constraint(
            "ck_scim_event_resource_type",
            f"resource_type IN ({values})",
        )


def upgrade() -> None:
    _replace_resource_type_constraint("'User', 'Group', 'Bulk'")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM saas_enterprise_scim_events "
            "WHERE resource_type = 'Bulk' LIMIT 1) THEN RAISE EXCEPTION "
            "'cannot downgrade with immutable SCIM Bulk receipts'; END IF; END $$"
        )
    _replace_resource_type_constraint("'User', 'Group'")
