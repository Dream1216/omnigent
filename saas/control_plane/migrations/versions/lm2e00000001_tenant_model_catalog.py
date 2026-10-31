"""Allow active customer contexts to read non-secret candidate metadata.

Revision ID: lm2e00000001
Revises: lm2d00000001
"""

from __future__ import annotations

from alembic import op

revision = "lm2e00000001"
down_revision = "lm2d00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_model_publication_versions"
_COLUMNS = "tenant_id, public_model_id, wire_api, generation, canonical_snapshot, snapshot_sha256"


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        f"CREATE POLICY rls_model_catalog_customer_read ON public.{_TABLE} "
        "FOR SELECT TO saas_app USING ("
        "tenant_id = NULLIF(current_setting('app.tenant_id',true),'')::uuid "
        "AND EXISTS (SELECT 1 FROM public.saas_tenant_memberships membership "
        f"WHERE membership.tenant_id={_TABLE}.tenant_id "
        "AND membership.user_id=NULLIF(current_setting('app.actor_id',true),'')::uuid "
        "AND membership.status='active') "
        "AND EXISTS (SELECT 1 FROM public.saas_space_memberships membership "
        f"WHERE membership.tenant_id={_TABLE}.tenant_id "
        "AND membership.space_id=NULLIF(current_setting('app.space_id',true),'')::uuid "
        "AND membership.user_id=NULLIF(current_setting('app.actor_id',true),'')::uuid "
        "AND membership.status='active'))"
    )
    op.execute(f"GRANT SELECT ({_COLUMNS}) ON public.{_TABLE} TO saas_app")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(f"DROP POLICY rls_model_catalog_customer_read ON public.{_TABLE}")
    op.execute(f"REVOKE SELECT ({_COLUMNS}) ON public.{_TABLE} FROM saas_app")
