"""Retain in-flight and uncertain provider budget holds until evidence arrives.

Revision ID: lm1d00000001
Revises: lm1c00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64

revision: str = "lm1d00000001"
down_revision: str | None = "lm1c00000001"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "saas_model_provider_budget_reservations"


def _constraints(*, attempts: bool) -> dict[str, str]:
    pending = (
        "status IN ('reserved', 'in_flight', 'uncertain')" if attempts else "status = 'reserved'"
    )
    terminal = (
        "status NOT IN ('reserved', 'in_flight', 'uncertain')"
        if attempts
        else "status <> 'reserved'"
    )
    statuses = (
        "'reserved', 'in_flight', 'uncertain', 'settled', 'released', 'rejected', 'expired'"
        if attempts
        else "'reserved', 'settled', 'released', 'rejected', 'expired'"
    )
    return {
        "ck_model_provider_budget_reservation_status": f"status IN ({statuses})",
        "ck_model_provider_budget_reservation_conservation": (
            "settled_microusd >= 0 AND released_microusd >= 0 "
            "AND settled_tokens >= 0 AND released_tokens >= 0 "
            f"AND (({pending} AND released_microusd = 0 "
            "AND released_tokens = 0 AND settled_microusd <= admitted_microusd "
            "AND settled_tokens <= admitted_tokens) "
            f"OR ({terminal} "
            "AND settled_microusd + released_microusd = admitted_microusd "
            "AND settled_tokens + released_tokens = admitted_tokens))"
        ),
        "ck_model_provider_budget_reservation_state": (
            f"({pending} AND admitted_microusd = requested_microusd "
            "AND admitted_tokens = requested_tokens "
            "AND released_microusd = 0 AND released_tokens = 0 "
            "AND rejection_code IS NULL) OR "
            "(status = 'settled' AND settled_microusd > 0 AND settled_tokens > 0 "
            "AND rejection_code IS NULL) OR "
            "(status IN ('released', 'expired') AND admitted_microusd > 0 "
            "AND admitted_tokens > 0 AND rejection_code IS NULL) OR "
            "(status = 'rejected' AND admitted_microusd = 0 AND admitted_tokens = 0 "
            "AND rejection_code IS NOT NULL)"
        ),
    }


def upgrade() -> None:
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(sa.Column("outcome_evidence_sha256", sa.String(64), nullable=True))
        for name, expression in _constraints(attempts=True).items():
            batch.drop_constraint(name, type_="check")
            batch.create_check_constraint(name, expression)
        batch.create_check_constraint(
            "ck_model_provider_budget_outcome_evidence",
            "outcome_evidence_sha256 IS NULL OR (status IN ('settled', 'released') AND "
            + _hex64("outcome_evidence_sha256")
            + ")",
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE")
        op.execute(f"ALTER TABLE {_TABLE} NO FORCE ROW LEVEL SECURITY")
    if bind.execute(
        sa.text(
            f"SELECT EXISTS (SELECT 1 FROM {_TABLE} "
            "WHERE status IN ('in_flight', 'uncertain') OR outcome_evidence_sha256 IS NOT NULL)"
        )
    ).scalar_one():
        raise RuntimeError("cannot remove retained model budget attempt evidence")
    if bind.dialect.name == "postgresql":
        op.execute(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY")
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_constraint("ck_model_provider_budget_outcome_evidence", type_="check")
        for name, expression in _constraints(attempts=False).items():
            batch.drop_constraint(name, type_="check")
            batch.create_check_constraint(name, expression)
        batch.drop_column("outcome_evidence_sha256")
