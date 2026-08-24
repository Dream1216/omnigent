"""Lease-based, at-least-once dispatcher for control-plane Outbox events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent


class OutboxPublisher(Protocol):
    """Idempotent event sink; consumers deduplicate by immutable event ID."""

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """One bounded dispatcher pass."""

    claimed: int
    published: int
    failed: int


@dataclass(frozen=True, slots=True)
class ClaimedOutboxEvent:
    """Detached-safe copy of one leased event."""

    id: UUID
    event_type: str
    aggregate_type: str
    aggregate_key: str
    payload: dict[str, object]
    attempt_count: int


def _now() -> datetime:
    return datetime.now(timezone.utc)


class OutboxDispatcher:
    """Claim, publish, and acknowledge events without holding DB locks over I/O."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        publisher: OutboxPublisher,
        *,
        lease_duration: timedelta = timedelta(seconds=30),
        max_backoff: timedelta = timedelta(minutes=5),
    ) -> None:
        if lease_duration <= timedelta(0) or max_backoff <= timedelta(0):
            raise ValueError("Outbox lease and backoff must be positive")
        self._session_factory = session_factory
        self._publisher = publisher
        self._lease_duration = lease_duration
        self._max_backoff = max_backoff

    def dispatch_once(
        self, *, batch_size: int = 100, now: datetime | None = None
    ) -> DispatchResult:
        """Publish one claimed batch and release failures for bounded retry."""

        if not 1 <= batch_size <= 1000:
            raise ValueError("Outbox batch_size must be between 1 and 1000")
        dispatched_at = now or _now()
        if dispatched_at.tzinfo is None:
            raise ValueError("Outbox dispatch time must include a timezone")
        claim_token = uuid4()
        events = self._claim(
            claim_token=claim_token,
            batch_size=batch_size,
            now=dispatched_at,
        )
        published = 0
        failed = 0
        for event in events:
            try:
                self._publisher.publish(
                    event_id=event.id,
                    event_type=event.event_type,
                    aggregate_type=event.aggregate_type,
                    aggregate_key=event.aggregate_key,
                    payload=event.payload,
                )
            except Exception as error:  # noqa: BLE001 - external sink failures are retried
                failed += 1
                self._release_failure(event, claim_token, error, dispatched_at)
            else:
                if self._acknowledge(event.id, claim_token, dispatched_at):
                    published += 1
                else:
                    # Publishing may outlive this worker's lease.  A newer
                    # owner must retain its claim, and one stale acknowledgement
                    # must not prevent the rest of this detached batch from
                    # being processed.
                    failed += 1
        return DispatchResult(claimed=len(events), published=published, failed=failed)

    def _claim(
        self,
        *,
        claim_token: UUID,
        batch_size: int,
        now: datetime,
    ) -> list[ClaimedOutboxEvent]:
        stale_before = now - self._lease_duration
        with self._session_factory.begin() as db:
            query = (
                sa.select(ControlPlaneOutboxEvent.id)
                .where(
                    ControlPlaneOutboxEvent.published_at.is_(None),
                    sa.or_(
                        ControlPlaneOutboxEvent.available_at.is_(None),
                        ControlPlaneOutboxEvent.available_at <= now,
                    ),
                    sa.or_(
                        ControlPlaneOutboxEvent.claimed_at.is_(None),
                        ControlPlaneOutboxEvent.claimed_at < stale_before,
                    ),
                )
                .order_by(ControlPlaneOutboxEvent.created_at, ControlPlaneOutboxEvent.id)
                .limit(batch_size)
            )
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            candidate_ids = list(db.execute(query).scalars())
            if not candidate_ids:
                return []
            db.execute(
                sa.update(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.id.in_(candidate_ids),
                    ControlPlaneOutboxEvent.published_at.is_(None),
                    sa.or_(
                        ControlPlaneOutboxEvent.claimed_at.is_(None),
                        ControlPlaneOutboxEvent.claimed_at < stale_before,
                    ),
                )
                .values(
                    claimed_at=now,
                    claim_token=claim_token,
                    attempt_count=ControlPlaneOutboxEvent.attempt_count + 1,
                    last_error=None,
                )
                .execution_options(synchronize_session=False)
            )
            rows = db.execute(
                sa.select(
                    ControlPlaneOutboxEvent.id,
                    ControlPlaneOutboxEvent.event_type,
                    ControlPlaneOutboxEvent.aggregate_type,
                    ControlPlaneOutboxEvent.aggregate_key,
                    ControlPlaneOutboxEvent.payload,
                    ControlPlaneOutboxEvent.attempt_count,
                )
                .where(ControlPlaneOutboxEvent.claim_token == claim_token)
                .order_by(ControlPlaneOutboxEvent.created_at, ControlPlaneOutboxEvent.id)
            ).all()
            return [
                ClaimedOutboxEvent(
                    id=row.id,
                    event_type=row.event_type,
                    aggregate_type=row.aggregate_type,
                    aggregate_key=row.aggregate_key,
                    payload=row.payload,
                    attempt_count=row.attempt_count,
                )
                for row in rows
            ]

    def _acknowledge(self, event_id: UUID, claim_token: UUID, published_at: datetime) -> bool:
        with self._session_factory.begin() as db:
            result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(ControlPlaneOutboxEvent)
                    .where(
                        ControlPlaneOutboxEvent.id == event_id,
                        ControlPlaneOutboxEvent.claim_token == claim_token,
                        ControlPlaneOutboxEvent.published_at.is_(None),
                    )
                    .values(
                        published_at=published_at,
                        claimed_at=None,
                        claim_token=None,
                        last_error=None,
                    )
                ),
            )
            return result.rowcount == 1

    def _release_failure(
        self,
        event: ClaimedOutboxEvent,
        claim_token: UUID,
        error: Exception,
        failed_at: datetime,
    ) -> None:
        backoff_seconds = min(
            self._max_backoff.total_seconds(),
            float(2 ** min(max(event.attempt_count - 1, 0), 12)),
        )
        with self._session_factory.begin() as db:
            db.execute(
                sa.update(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.id == event.id,
                    ControlPlaneOutboxEvent.claim_token == claim_token,
                    ControlPlaneOutboxEvent.published_at.is_(None),
                )
                .values(
                    available_at=failed_at + timedelta(seconds=backoff_seconds),
                    claimed_at=None,
                    claim_token=None,
                    last_error=str(error)[:2048],
                )
            )
