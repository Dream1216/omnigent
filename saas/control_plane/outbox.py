"""Lease-based, at-least-once dispatcher for control-plane Outbox events."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Protocol, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    ControlPlaneOutboxQuarantineEvent,
)

_ZERO_HASH = "0" * 64
_SAFE_ERROR_CODE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")


class OutboxPublishError(RuntimeError):
    """Stable publisher classification understood by the generic dispatcher.

    A non-retryable error is eligible for immediate quarantine only when the
    publisher proves that it arose before an external side effect. Unknown
    exceptions and post-side-effect failures always consume the retry budget.
    """

    def __init__(self, code: str, *, retryable: bool, pre_side_effect: bool) -> None:
        if _SAFE_ERROR_CODE.fullmatch(code) is None:
            raise ValueError("Outbox publish error code is invalid")
        self.code = code
        self.retryable = retryable
        self.pre_side_effect = pre_side_effect
        super().__init__(code)


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
    quarantined: int = 0


@dataclass(frozen=True, slots=True)
class ClaimedOutboxEvent:
    """Detached-safe copy of one leased event."""

    id: UUID
    tenant_id: UUID | None
    event_type: str
    aggregate_type: str
    aggregate_key: str
    payload: dict[str, object]
    request_hash: str
    attempt_count: int


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _delivery_error_digest(error: Exception) -> str:
    if isinstance(error, OutboxPublishError):
        material: dict[str, object] = {
            "type": f"{type(error).__module__}.{type(error).__qualname__}",
            "code": error.code,
            "retryable": error.retryable,
            "pre_side_effect": error.pre_side_effect,
        }
    else:
        # Provider text can contain credentials, customer data, or tokens.
        # Do not even derive persisted evidence from that text: a digest of a
        # low-entropy secret can still be dictionary-tested offline.
        material = {
            "type": f"{type(error).__module__}.{type(error).__qualname__}",
            "code": "outbox_publish_failed",
        }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def _quarantine_event_hash(
    *,
    source_event_id: UUID,
    tenant_id: UUID | None,
    source_request_hash: str,
    source_attempt_count: int,
    action: str,
    error_code: str,
    error_digest: str,
    sequence: int,
    previous_hash: str,
    created_at: datetime,
) -> str:
    material = {
        "source_event_id": str(source_event_id),
        "tenant_id": str(tenant_id) if tenant_id is not None else None,
        "source_request_hash": source_request_hash,
        "source_attempt_count": source_attempt_count,
        "action": action,
        "error_code": error_code,
        "error_digest": error_digest,
        "sequence": sequence,
        "previous_hash": previous_hash,
        "created_at": _canonical_timestamp(created_at),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


class OutboxDispatcher:
    """Claim, publish, and acknowledge events without holding DB locks over I/O."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        publisher: OutboxPublisher,
        *,
        lease_duration: timedelta = timedelta(seconds=30),
        max_backoff: timedelta = timedelta(minutes=5),
        max_attempts: int = 8,
    ) -> None:
        if lease_duration <= timedelta(0) or max_backoff <= timedelta(0):
            raise ValueError("Outbox lease and backoff must be positive")
        if not 1 <= max_attempts <= 32:
            raise ValueError("Outbox max_attempts must be between 1 and 32")
        self._session_factory = session_factory
        self._publisher = publisher
        self._lease_duration = lease_duration
        self._max_backoff = max_backoff
        self._max_attempts = max_attempts

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
        quarantined = 0
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
                error_digest = _delivery_error_digest(error)
                explicitly_poisoned = (
                    isinstance(error, OutboxPublishError)
                    and not error.retryable
                    and error.pre_side_effect
                )
                attempts_exhausted = event.attempt_count >= self._max_attempts
                try:
                    if explicitly_poisoned or attempts_exhausted:
                        error_code = (
                            error.code
                            if explicitly_poisoned and isinstance(error, OutboxPublishError)
                            else "outbox_retry_exhausted"
                        )
                        if self._quarantine(
                            event,
                            claim_token,
                            error_code=error_code,
                            error_digest=error_digest,
                            quarantined_at=dispatched_at,
                        ):
                            quarantined += 1
                    else:
                        error_code = (
                            error.code
                            if isinstance(error, OutboxPublishError)
                            else "outbox_publish_failed"
                        )
                        self._release_failure(
                            event,
                            claim_token,
                            error_code=error_code,
                            error_digest=error_digest,
                            failed_at=dispatched_at,
                        )
                except Exception:  # noqa: BLE001 - never chain a Provider error into DB logs
                    raise RuntimeError("Outbox failure-state persistence failed") from None
            else:
                if self._acknowledge(event.id, claim_token, dispatched_at):
                    published += 1
                else:
                    # Publishing may outlive this worker's lease.  A newer
                    # owner must retain its claim, and one stale acknowledgement
                    # must not prevent the rest of this detached batch from
                    # being processed.
                    failed += 1
        return DispatchResult(
            claimed=len(events),
            published=published,
            failed=failed,
            quarantined=quarantined,
        )

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
                    ControlPlaneOutboxEvent.quarantined_at.is_(None),
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
                    ControlPlaneOutboxEvent.quarantined_at.is_(None),
                    sa.or_(
                        ControlPlaneOutboxEvent.claimed_at.is_(None),
                        ControlPlaneOutboxEvent.claimed_at < stale_before,
                    ),
                )
                .values(
                    claimed_at=now,
                    claim_token=claim_token,
                    attempt_count=ControlPlaneOutboxEvent.attempt_count + 1,
                )
                .execution_options(synchronize_session=False)
            )
            rows = db.execute(
                sa.select(
                    ControlPlaneOutboxEvent.id,
                    ControlPlaneOutboxEvent.tenant_id,
                    ControlPlaneOutboxEvent.event_type,
                    ControlPlaneOutboxEvent.aggregate_type,
                    ControlPlaneOutboxEvent.aggregate_key,
                    ControlPlaneOutboxEvent.payload,
                    ControlPlaneOutboxEvent.request_hash,
                    ControlPlaneOutboxEvent.attempt_count,
                )
                .where(ControlPlaneOutboxEvent.claim_token == claim_token)
                .order_by(ControlPlaneOutboxEvent.created_at, ControlPlaneOutboxEvent.id)
            ).all()
            return [
                ClaimedOutboxEvent(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    event_type=row.event_type,
                    aggregate_type=row.aggregate_type,
                    aggregate_key=row.aggregate_key,
                    payload=row.payload,
                    request_hash=row.request_hash,
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
                        ControlPlaneOutboxEvent.quarantined_at.is_(None),
                    )
                    .values(
                        published_at=published_at,
                        claimed_at=None,
                        claim_token=None,
                        last_error_code=None,
                        last_error_digest=None,
                    )
                ),
            )
            return result.rowcount == 1

    def _release_failure(
        self,
        event: ClaimedOutboxEvent,
        claim_token: UUID,
        *,
        error_code: str,
        error_digest: str,
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
                    ControlPlaneOutboxEvent.quarantined_at.is_(None),
                )
                .values(
                    available_at=failed_at + timedelta(seconds=backoff_seconds),
                    claimed_at=None,
                    claim_token=None,
                    last_error_code=error_code,
                    last_error_digest=error_digest,
                )
            )

    def _quarantine(
        self,
        event: ClaimedOutboxEvent,
        claim_token: UUID,
        *,
        error_code: str,
        error_digest: str,
        quarantined_at: datetime,
    ) -> bool:
        """Atomically terminalize one currently owned event and append its receipt."""

        with self._session_factory.begin() as db:
            result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(ControlPlaneOutboxEvent)
                    .where(
                        ControlPlaneOutboxEvent.id == event.id,
                        ControlPlaneOutboxEvent.claim_token == claim_token,
                        ControlPlaneOutboxEvent.published_at.is_(None),
                        ControlPlaneOutboxEvent.quarantined_at.is_(None),
                    )
                    .values(
                        available_at=None,
                        claimed_at=None,
                        claim_token=None,
                        last_error_code=error_code,
                        last_error_digest=error_digest,
                        quarantined_at=quarantined_at,
                    )
                ),
            )
            if result.rowcount != 1:
                return False
            previous = db.scalar(
                sa.select(ControlPlaneOutboxQuarantineEvent)
                .where(ControlPlaneOutboxQuarantineEvent.source_event_id == event.id)
                .order_by(ControlPlaneOutboxQuarantineEvent.sequence.desc())
                .limit(1)
            )
            sequence = 1 if previous is None else previous.sequence + 1
            previous_hash = _ZERO_HASH if previous is None else previous.event_hash
            action = "quarantined"
            db.add(
                ControlPlaneOutboxQuarantineEvent(
                    source_event_id=event.id,
                    tenant_id=event.tenant_id,
                    source_request_hash=event.request_hash,
                    source_attempt_count=event.attempt_count,
                    action=action,
                    error_code=error_code,
                    error_digest=error_digest,
                    sequence=sequence,
                    previous_hash=previous_hash,
                    event_hash=_quarantine_event_hash(
                        source_event_id=event.id,
                        tenant_id=event.tenant_id,
                        source_request_hash=event.request_hash,
                        source_attempt_count=event.attempt_count,
                        action=action,
                        error_code=error_code,
                        error_digest=error_digest,
                        sequence=sequence,
                        previous_hash=previous_hash,
                        created_at=quarantined_at,
                    ),
                    created_at=quarantined_at,
                )
            )
            db.flush()
            return True
