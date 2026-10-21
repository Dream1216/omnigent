"""Keep bounded customer price references without new foreign keys.

Revision ID: lm2s00000001
Revises: lm2r00000001

Existing price selection/immutability guards and append-only price authority stay
in place. Application rollback retains this schema and every execution fact.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2s00000001"
down_revision = "lm2r00000001"
branch_labels = None
depends_on = None

_REFERENCES = (
    ("saas_execution_sessions", "fk_session_customer_pricing"),
    ("saas_runs", "fk_run_customer_pricing"),
)


def upgrade() -> None:
    for table, name in _REFERENCES:
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(name, type_="foreignkey")


def downgrade() -> None:
    bind = op.get_bind()
    for table, _name in _REFERENCES:
        if bind.scalar(sa.select(sa.literal(1)).select_from(sa.table(table)).limit(1)):
            raise RuntimeError("retained execution schema cannot be downgraded")
    for table, name in reversed(_REFERENCES):
        with op.batch_alter_table(table) as batch:
            batch.create_foreign_key(
                name,
                "saas_pricing_snapshots",
                ["tenant_id", "customer_pricing_snapshot_id"],
                ["tenant_id", "id"],
                ondelete="RESTRICT",
            )
