"""Index scope-safe Tenant Members directory queries.

Revision ID: p6a000000006
Revises: p6a000000005
"""

from __future__ import annotations

from alembic import op

revision: str = "p6a000000006"
down_revision: str | None = "p6a000000005"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_index(
        "ix_tenant_membership_directory",
        "saas_tenant_memberships",
        ["tenant_id", "status", "role", "user_id"],
    )
    op.create_index(
        "ix_space_membership_member_directory",
        "saas_space_memberships",
        ["tenant_id", "user_id", "status", "space_id"],
    )
    op.create_index(
        "ix_invitation_tenant_status_expiry",
        "saas_membership_invitations",
        ["tenant_id", "status", "expires_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_invitation_tenant_status_expiry",
        table_name="saas_membership_invitations",
    )
    op.drop_index(
        "ix_space_membership_member_directory",
        table_name="saas_space_memberships",
    )
    op.drop_index(
        "ix_tenant_membership_directory",
        table_name="saas_tenant_memberships",
    )
