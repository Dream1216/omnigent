"""Confirm stopped terminal interactive Runs without rewriting their outcome.

Revision ID: lm2o00000001
Revises: lm2n00000001
"""

from alembic import op

from saas.control_plane.migrations.versions.lm2k00000001_interactive_physical_recovery import (
    _BODY as _ORPHAN_BODY,
)
from saas.control_plane.migrations.versions.lm2k00000001_interactive_physical_recovery import (
    _FUNCTION,
)

revision = "lm2o00000001"
down_revision = "lm2n00000001"
branch_labels = None
depends_on = None

_BODY = _ORPHAN_BODY.replace(
    "r.status='orphaned'",
    "r.status IN ('cancelled','succeeded','failed','timed_out','orphaned')",
)


def _replace(body: str) -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            f"CREATE OR REPLACE FUNCTION {_FUNCTION} RETURNS trigger "
            "LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog "
            f"AS $function${body}$function$"
        )


def upgrade() -> None:
    _replace(_BODY)


def downgrade() -> None:
    # Existing immutable receipts survive; only new confirmations narrow again.
    _replace(_ORPHAN_BODY)
