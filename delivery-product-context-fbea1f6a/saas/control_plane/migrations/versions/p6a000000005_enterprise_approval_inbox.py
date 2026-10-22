"""Index scope-safe enterprise approval inbox queries.

Revision ID: p6a000000005
Revises: p6a000000004
"""

from __future__ import annotations

from alembic import op

revision: str = "p6a000000005"
down_revision: str | None = "p6a000000004"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_index(
        "ix_enterprise_access_preflight_requester",
        "saas_enterprise_access_preflights",
        ["tenant_id", "requested_by", "id", "status"],
    )
    op.create_index(
        "ix_enterprise_access_preflight_inbox",
        "saas_enterprise_access_preflights",
        [
            "tenant_id",
            "space_id",
            "project_id",
            "operation_type",
            "status",
            "id",
            "expires_at",
        ],
    )


def downgrade() -> None:
    table = "saas_enterprise_access_preflights"
    op.drop_index("ix_enterprise_access_preflight_inbox", table_name=table)
    op.drop_index("ix_enterprise_access_preflight_requester", table_name=table)
