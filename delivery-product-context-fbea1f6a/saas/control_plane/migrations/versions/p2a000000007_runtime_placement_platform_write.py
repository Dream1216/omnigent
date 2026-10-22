"""Restore platform-only Runtime Placement writes under forced RLS."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "p2a000000007"
down_revision: str | None = "p2a000000006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"


def upgrade() -> None:
    """Permit only the platform role to provision or mutate Placements."""

    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        'CREATE POLICY "rls_runtime_placements_platform_write" '
        'ON "saas_runtime_placements" FOR ALL '
        f"USING ({_PLATFORM}) WITH CHECK ({_PLATFORM})"
    )


def downgrade() -> None:
    """Remove the platform mutation policy while retaining scoped reads."""

    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        'DROP POLICY IF EXISTS "rls_runtime_placements_platform_write" '
        'ON "saas_runtime_placements"'
    )
