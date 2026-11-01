"""Durable, credential-free notification ingestion and bounded worker leases."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.identity_event_models import IdentityEventInboxRecord
from saas.control_plane.identity_events import (
    IdentityNotification,
    IdentitySyncError,
    identity_digest,
    safe_identity_error_code,
)


def _utc(value: datetime | None = None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise ValueError("identity sync time must have a timezone")
    return result.astimezone(timezone.utc)


def _stored(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def identity_locator(issuer: str, organization: str, kind: str, value: str) -> str:
    if kind not in {"subject", "username"}:
        raise ValueError("invalid identity locator kind")
    return identity_digest(
        {
            "schema_version": 1,
            "provider": "casdoor",
            "issuer": issuer,
            "organization": organization,
            "kind": kind,
            "value": value,
        }
    )


@dataclass(frozen=True, slots=True)
class IdentitySyncPolicy:
    issuer: str
    organization: str
    event_lease: timedelta = timedelta(seconds=120)
    provider_lease: timedelta = timedelta(seconds=30)
    reconcile_interval: timedelta = timedelta(seconds=60)
    max_attempts: int = 10
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        url = urlsplit(self.issuer)
        if (
            not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path
            or (
                url.scheme != "https"
                and not (
                    self.allow_insecure_loopback
                    and url.scheme == "http"
                    and url.hostname in {"localhost", "127.0.0.1", "::1"}
                )
            )
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.organization)
            or self.organization == "built-in"
            or not 1 <= self.max_attempts <= 20
            or not timedelta(seconds=10) <= self.provider_lease <= timedelta(seconds=120)
            or not timedelta(seconds=10) <= self.event_lease <= timedelta(minutes=5)
            or not timedelta(seconds=1) <= self.reconcile_interval <= timedelta(seconds=60)
        ):
            raise ValueError("identity synchronization policy is invalid")


@dataclass(frozen=True, slots=True)
class IdentityInboxView:
    id: UUID
    event_id: str
    status: str
    attempt_count: int
    processed_connection_count: int
    duplicate: bool = False


@dataclass(frozen=True, slots=True)
class IdentityInboxClaim:
    id: UUID
    token: UUID = field(repr=False)
    issuer: str
    organization: str
    event_id: str
    action: str
    subject_locator_sha256: str | None
    username_locator_sha256: str
    occurred_at: datetime
    security_event: bool
    request_sha256: str


class IdentityEventInboxService:
    def __init__(self, sessions: sessionmaker[Session], *, policy: IdentitySyncPolicy) -> None:
        self._sessions, self.policy = sessions, policy

    @staticmethod
    def _view(record: IdentityEventInboxRecord, *, duplicate: bool = False) -> IdentityInboxView:
        return IdentityInboxView(
            record.id,
            record.event_id,
            record.status,
            record.attempt_count,
            record.processed_connection_count,
            duplicate,
        )

    def ingest(
        self, notification: IdentityNotification, *, now: datetime | None = None
    ) -> IdentityInboxView:
        received = _utc(now)
        if notification.organization != self.policy.organization:
            raise IdentitySyncError("identity_notification_scope_mismatch")
        candidate = uuid4()
        values = {
            "id": candidate,
            "provider": "casdoor",
            "issuer": self.policy.issuer,
            "organization": self.policy.organization,
            "event_id": notification.event_id,
            "action": notification.action,
            "security_event": notification.invalidates_sessions,
            "subject_locator_sha256": identity_locator(
                self.policy.issuer, self.policy.organization, "subject", notification.subject
            )
            if notification.subject
            else None,
            "username_locator_sha256": identity_locator(
                self.policy.issuer, self.policy.organization, "username", notification.username
            ),
            "request_sha256": notification.digest(),
            "occurred_at": notification.occurred_at,
            "received_at": received,
            "available_at": received,
            "status": "pending",
            "attempt_count": 0,
            "version": 1,
            "processed_connection_count": 0,
        }
        with self._sessions.begin() as db:
            dialect = db.get_bind().dialect.name
            insert = (
                pg_insert
                if dialect == "postgresql"
                else sqlite_insert
                if dialect == "sqlite"
                else None
            )
            if insert is None:
                raise ValueError("identity Inbox requires PostgreSQL or SQLite")
            db.execute(
                insert(IdentityEventInboxRecord)
                .values(**values)
                .on_conflict_do_nothing(index_elements=["issuer", "organization", "event_id"])
            )
            record = db.scalar(
                sa.select(IdentityEventInboxRecord)
                .where(
                    IdentityEventInboxRecord.issuer == self.policy.issuer,
                    IdentityEventInboxRecord.organization == self.policy.organization,
                    IdentityEventInboxRecord.event_id == notification.event_id,
                )
                .with_for_update()
            )
            assert record is not None
            if record.request_sha256 != notification.digest():
                raise IdentitySyncError("identity_notification_idempotency_conflict")
            return self._view(record, duplicate=record.id != candidate)

    @staticmethod
    def _claim(record: IdentityEventInboxRecord) -> IdentityInboxClaim:
        assert record.claim_token is not None
        return IdentityInboxClaim(
            record.id,
            record.claim_token,
            record.issuer,
            record.organization,
            record.event_id,
            record.action,
            record.subject_locator_sha256,
            record.username_locator_sha256,
            _stored(record.occurred_at),
            record.security_event,
            record.request_sha256,
        )

    def claim_next(self, *, now: datetime | None = None) -> IdentityInboxClaim | None:
        for _ in range(100):
            checked = _utc(now)
            with self._sessions.begin() as db:
                record = db.scalar(
                    sa.select(IdentityEventInboxRecord)
                    .where(
                        IdentityEventInboxRecord.issuer == self.policy.issuer,
                        IdentityEventInboxRecord.organization == self.policy.organization,
                        sa.or_(
                            sa.and_(
                                IdentityEventInboxRecord.status.in_(("pending", "retry")),
                                IdentityEventInboxRecord.available_at <= checked,
                            ),
                            sa.and_(
                                IdentityEventInboxRecord.status == "processing",
                                IdentityEventInboxRecord.lease_expires_at <= checked,
                            ),
                        ),
                    )
                    .order_by(
                        IdentityEventInboxRecord.available_at,
                        IdentityEventInboxRecord.received_at,
                        IdentityEventInboxRecord.id,
                    )
                    .with_for_update(skip_locked=True)
                    .limit(1)
                )
                if record is None:
                    return None
                checked = _utc(now)
                if record.attempt_count >= self.policy.max_attempts:
                    record.status = "dead"
                    record.completed_at = checked
                    record.claim_token = None
                    record.lease_expires_at = None
                    record.last_error_code = "identity_notification_attempts_exhausted"
                    record.version += 1
                    continue
                record.status = "processing"
                record.attempt_count += 1
                record.version += 1
                record.claim_token = uuid4()
                record.lease_expires_at = checked + self.policy.event_lease
                return self._claim(record)
        return None

    def _locked(self, db: Session, claim: IdentityInboxClaim, now: datetime | None):
        record = db.scalar(
            sa.select(IdentityEventInboxRecord)
            .where(IdentityEventInboxRecord.id == claim.id)
            .with_for_update()
        )
        checked = _utc(now)
        if (
            record is None
            or record.status != "processing"
            or record.claim_token != claim.token
            or record.lease_expires_at is None
            or _stored(record.lease_expires_at) <= checked
            or self._claim(record) != claim
            or claim.issuer != self.policy.issuer
            or claim.organization != self.policy.organization
        ):
            raise IdentitySyncError("identity_inbox_claim_stale")
        return record, checked

    def finish(
        self, claim: IdentityInboxClaim, *, processed_connections: int, now: datetime | None = None
    ) -> IdentityInboxView:
        if type(processed_connections) is not int or processed_connections < 0:
            raise ValueError("invalid processed connection count")
        with self._sessions.begin() as db:
            record, checked = self._locked(db, claim, now)
            record.status = "completed" if processed_connections else "ignored"
            record.processed_connection_count = processed_connections
            record.completed_at = checked
            record.claim_token = None
            record.lease_expires_at = None
            record.last_error_code = None
            record.version += 1
            return self._view(record)

    def fail(
        self, claim: IdentityInboxClaim, error: IdentitySyncError, *, now: datetime | None = None
    ) -> IdentityInboxView:
        with self._sessions.begin() as db:
            record, checked = self._locked(db, claim, now)
            retry = error.retryable and record.attempt_count < self.policy.max_attempts
            record.status = "retry" if retry else "dead"
            record.completed_at = None if retry else checked
            record.available_at = checked + timedelta(
                seconds=min(60, 2 ** min(record.attempt_count, 6))
            )
            record.last_error_code = safe_identity_error_code(error)
            record.claim_token = None
            record.lease_expires_at = None
            record.version += 1
            return self._view(record)
