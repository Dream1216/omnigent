"""Add CAS metadata for external-host machine credentials.

Revision ID: h8c0d1e2f3a4
Revises: g8b9c0d1e2f3
Create Date: 2026-08-21

``credential_generation`` is a monotonic compare-and-swap fence shared by
all App replicas. ``credential_operation_id`` makes an issue request
idempotent when the response is lost. Existing and managed host rows start at
generation zero; no raw credential material is introduced by this migration.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "h8c0d1e2f3a4"
down_revision: str = "g8b9c0d1e2f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add external-host credential fencing metadata."""
    with op.batch_alter_table("hosts") as batch_op:
        batch_op.add_column(
            sa.Column(
                "credential_generation",
                sa.BigInteger(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column("credential_operation_id", sa.String(length=64), nullable=True)
        )


def downgrade() -> None:
    """Remove external-host credential fencing metadata."""
    with op.batch_alter_table("hosts") as batch_op:
        batch_op.drop_column("credential_operation_id")
        batch_op.drop_column("credential_generation")
