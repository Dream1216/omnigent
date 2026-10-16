"""SQLite parity for the PostgreSQL-owned execution price insertion contract."""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.orm import Session

from saas.control_plane.billing_models import BillingSubscriptionRecord, PricingSnapshotRecord
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord


def freeze_sqlite_customer_pricing(db: Session, row: ExecutionSessionRecord | RunRecord) -> None:
    """Production derives these fields inside the INSERT trigger, never from a caller."""

    if db.get_bind().dialect.name != "sqlite":
        return
    row.created_at = row.created_at or datetime.now(timezone.utc)
    row.customer_pricing_frozen = False
    row.customer_pricing_snapshot_id = None
    if isinstance(row, RunRecord) and row.session_id is not None:
        parent = db.scalar(
            sa.select(ExecutionSessionRecord).where(
                ExecutionSessionRecord.id == row.session_id,
                ExecutionSessionRecord.tenant_id == row.tenant_id,
                ExecutionSessionRecord.space_id == row.space_id,
                ExecutionSessionRecord.project_id == row.project_id,
            )
        )
        if parent is not None:
            row.customer_pricing_frozen = parent.customer_pricing_frozen
            row.customer_pricing_snapshot_id = parent.customer_pricing_snapshot_id
        return
    subscription = db.scalar(
        sa.select(BillingSubscriptionRecord).where(
            BillingSubscriptionRecord.tenant_id == row.tenant_id
        )
    )
    if subscription is None:
        return
    row.customer_pricing_frozen = True
    if subscription.status not in {"active", "trialing"}:
        return
    admitted = row.created_at
    candidates = list(
        db.scalars(
            sa.select(PricingSnapshotRecord.id)
            .where(
                PricingSnapshotRecord.tenant_id == row.tenant_id,
                PricingSnapshotRecord.plan_key == subscription.plan_key,
                PricingSnapshotRecord.effective_from <= admitted,
                sa.or_(
                    PricingSnapshotRecord.effective_until.is_(None),
                    PricingSnapshotRecord.effective_until > admitted,
                ),
            )
            .limit(2)
        )
    )
    if len(candidates) == 1:
        row.customer_pricing_snapshot_id = candidates[0]
