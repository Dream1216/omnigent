"""Permit the existing scoped budget RPC under a non-bypass schema owner.

Revision ID: lm2t00000001
Revises: lm2s00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2t00000001"
down_revision = "lm2s00000001"
branch_labels = None
depends_on = None

_TABLE = "public.saas_model_provider_budget_reservations"
_POLICY = "rls_model_budget_owner_settlement"
_SCOPE = f"""
current_user = pg_catalog.pg_get_userbyid((
    SELECT relowner FROM pg_catalog.pg_class WHERE oid = '{_TABLE}'::regclass
))
AND id = NULLIF(current_setting('app.model_budget_reservation_id', true), '')::uuid
AND tenant_id = NULLIF(current_setting('app.metering_tenant_id', true), '')::uuid
AND run_id = NULLIF(current_setting('app.metering_run_id', true), '')::uuid
AND provider_id = 'deepseek' AND purpose = 'tenant_run' AND status = 'reserved'
AND expires_at > CURRENT_TIMESTAMP
"""


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        f"CREATE POLICY {_POLICY} ON {_TABLE} FOR UPDATE USING ({_SCOPE}) WITH CHECK ({_SCOPE})"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    if bind.scalar(sa.text(f"SELECT 1 FROM {_TABLE} LIMIT 1")) is not None:
        raise RuntimeError("retained model budgets require owner settlement policy")
    op.execute(f"DROP POLICY {_POLICY} ON {_TABLE}")
