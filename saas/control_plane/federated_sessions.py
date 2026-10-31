"""Durable, race-safe local-session binding and OIDC logout convergence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import AuthSessionRecord, OidcSessionFence
from saas.control_plane.lifecycle import LifecycleError


def _time(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _hash(value: str) -> str:
    return sha256(value.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ExternalSessionIdentity:
    provider: str
    issuer: str
    subject: str
    issued_at: datetime
    sid: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.provider
            or len(self.provider) > 64
            or not self.issuer
            or len(self.issuer) > 512
            or not self.subject
            or len(self.subject) > 512
            or (self.sid is not None and (not self.sid or len(self.sid) > 512))
            or self.issued_at.tzinfo is None
        ):
            raise ValueError("external authentication identity is invalid")


@dataclass(frozen=True, slots=True)
class VerifiedLogoutEvent:
    provider: str
    issuer: str
    jti: str
    issued_at: datetime
    subject: str | None
    sid: str | None

    def __post_init__(self) -> None:
        if (not self.subject and not self.sid) or not self.jti or len(self.jti) > 512:
            raise ValueError("logout event must identify a subject or external session")


def _lock_fences(
    db: Session, *, provider: str, issuer: str, selectors: list[tuple[str, str]]
) -> dict[str, OidcSessionFence]:
    dialect = db.get_bind().dialect.name
    insert = (
        pg_insert if dialect == "postgresql" else sqlite_insert if dialect == "sqlite" else None
    )
    if insert is None:
        raise ValueError("federated sessions require PostgreSQL or SQLite")
    fences = {}
    for kind, value in sorted(selectors):
        key = {"provider": provider, "issuer": issuer, "kind": kind, "key_hash": _hash(value)}
        db.execute(insert(OidcSessionFence).values(**key).on_conflict_do_nothing())
        row = db.execute(
            sa.select(OidcSessionFence).filter_by(**key).with_for_update()
        ).scalar_one()
        fences[kind] = row
    return fences


def bind_external_session(db: Session, identity: ExternalSessionIdentity) -> Mapping[str, object]:
    selectors = [("subject", identity.subject)]
    selectors.append(
        ("sid", identity.sid) if identity.sid else ("subject_no_sid", identity.subject)
    )
    fences = _lock_fences(
        db, provider=identity.provider, issuer=identity.issuer, selectors=selectors
    )
    if any(
        row.logout_issued_at is not None and _time(row.logout_issued_at) >= identity.issued_at
        for row in fences.values()
    ):
        raise LifecycleError("oidc_session_ended", "identity session ended; sign in again")
    return {
        "external_provider": identity.provider,
        "external_issuer": identity.issuer,
        "external_subject": identity.subject,
        "external_sid": identity.sid,
        "external_issued_at": identity.issued_at,
    }


class FederatedSessionService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def revoke(self, event: VerifiedLogoutEvent, *, now: datetime) -> bool:
        """Commit an idempotency receipt, fences and matching revocations together."""

        selectors = [("event", event.jti)]
        if event.subject:
            selectors.extend([("subject", event.subject), ("subject_no_sid", event.subject)])
        if event.sid:
            selectors.append(("sid", event.sid))
        payload_hash = _hash(
            json.dumps(
                {
                    "sub": event.subject,
                    "sid": event.sid,
                    "iat": event.issued_at.isoformat(),
                },
                sort_keys=True,
            )
        )
        with self._sessions.begin() as db:
            fences = _lock_fences(
                db, provider=event.provider, issuer=event.issuer, selectors=selectors
            )
            receipt = fences["event"]
            if receipt.event_hash is not None:
                if receipt.event_hash != payload_hash:
                    raise LifecycleError(
                        "oidc_logout_event_invalid", "logout event identity was reused"
                    )
                return True
            receipt.event_hash = payload_hash
            receipt.logout_issued_at = event.issued_at
            kinds = {"sid", "subject_no_sid"} if event.sid else {"subject"}
            for kind in kinds.intersection(fences):
                row = fences[kind]
                if row.logout_issued_at is None or _time(row.logout_issued_at) < event.issued_at:
                    row.logout_issued_at = event.issued_at
            predicates = [
                AuthSessionRecord.external_provider == event.provider,
                AuthSessionRecord.external_issuer == event.issuer,
                AuthSessionRecord.external_issued_at <= event.issued_at,
                AuthSessionRecord.revoked_at.is_(None),
            ]
            if event.subject:
                predicates.append(AuthSessionRecord.external_subject == event.subject)
            if event.sid:
                sid = AuthSessionRecord.external_sid == event.sid
                predicates.append(
                    sa.or_(sid, AuthSessionRecord.external_sid.is_(None)) if event.subject else sid
                )
            db.execute(sa.update(AuthSessionRecord).where(*predicates).values(revoked_at=now))
        return False
