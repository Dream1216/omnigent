"""Read provider state outside transactions, then apply under account and session fences."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import AuthSessionRecord, GlobalUser, IdentityConnection
from saas.control_plane.federated_sessions import _lock_fences
from saas.control_plane.identity import _add_event, _invalidate_sessions
from saas.control_plane.identity_event_models import IdentityProviderStateRecord
from saas.control_plane.identity_events import (
    IdentityStateProvider,
    IdentitySyncError,
    ProviderIdentityState,
    identity_digest,
    safe_identity_error_code,
)
from saas.control_plane.identity_inbox import (
    IdentityEventInboxService,
    IdentityInboxClaim,
    IdentitySyncPolicy,
    _stored,
    _utc,
    identity_locator,
)
from saas.control_plane.identity_read_protocol import validate_provider_state
from saas.control_plane.lifecycle import normalize_email


@dataclass(frozen=True, slots=True)
class IdentityStateClaim:
    connection_id: UUID
    user_id: UUID
    token: UUID = field(repr=False)
    issuer: str
    organization: str
    subject: str = field(repr=False)
    security_version: int
    connection_updated_at: datetime
    email_normalized: str | None = field(repr=False)
    email_verified: bool
    lease_expires_at: datetime
    phone_e164: str | None = field(default=None, repr=False)
    phone_verified: bool = False

    def digest(self) -> str:
        return identity_digest(
            {
                "schema_version": 2,
                "connection_id": str(self.connection_id),
                "user_id": str(self.user_id),
                "token": str(self.token),
                "issuer": self.issuer,
                "organization": self.organization,
                "subject": self.subject,
                "security_version": self.security_version,
                "connection_updated_at": self.connection_updated_at.isoformat(),
                "email_normalized": self.email_normalized,
                "email_verified": self.email_verified,
                "phone_e164": self.phone_e164,
                "phone_verified": self.phone_verified,
                "lease_expires_at": self.lease_expires_at.isoformat(),
            }
        )


@dataclass(frozen=True, slots=True)
class IdentityStateApplied:
    connection_id: UUID
    status: str
    security_version: int
    revoked_session_count: int
    changed: bool


class IdentityStateSyncService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        provider: IdentityStateProvider,
        policy: IdentitySyncPolicy,
    ) -> None:
        self._sessions, self._provider, self.policy = sessions, provider, policy
        self.inbox = IdentityEventInboxService(sessions, policy=policy)

    def _locator(self, subject: str) -> str:
        return identity_locator(self.policy.issuer, self.policy.organization, "subject", subject)

    def claim(
        self, connection_id: UUID, *, force: bool = False, now: datetime | None = None
    ) -> IdentityStateClaim | None:
        with self._sessions.begin() as db:
            user_id = db.scalar(
                sa.select(IdentityConnection.user_id).where(IdentityConnection.id == connection_id)
            )
            if user_id is None:
                return None
            user = db.scalar(
                sa.select(GlobalUser)
                .where(GlobalUser.id == user_id)
                .with_for_update(skip_locked=True)
            )
            if user is None or user.status != "active":
                return None
            connection = db.scalar(
                sa.select(IdentityConnection)
                .where(IdentityConnection.id == connection_id)
                .with_for_update()
            )
            if (
                connection is None
                or connection.user_id != user.id
                or connection.status != "active"
                or connection.provider != "casdoor"
                or connection.issuer != self.policy.issuer
            ):
                return None
            state = db.scalar(
                sa.select(IdentityProviderStateRecord)
                .where(IdentityProviderStateRecord.connection_id == connection.id)
                .with_for_update()
            )
            checked = _utc(now)
            if state is None:
                state = IdentityProviderStateRecord(
                    connection_id=connection.id,
                    subject_locator_sha256=self._locator(connection.subject),
                    status="active",
                    next_check_at=checked,
                    attempt_count=0,
                    version=1,
                )
                db.add(state)
            if state.subject_locator_sha256 != self._locator(connection.subject):
                raise IdentitySyncError("identity_provider_locator_mismatch")
            if (
                state.status == "deleted"
                or (
                    state.lease_expires_at is not None
                    and _stored(state.lease_expires_at) > checked
                )
                or (not force and _stored(state.next_check_at) > checked)
            ):
                return None
            claim = IdentityStateClaim(
                connection.id,
                user.id,
                uuid4(),
                self.policy.issuer,
                self.policy.organization,
                connection.subject,
                user.security_version,
                _stored(connection.updated_at),
                connection.email_normalized,
                connection.email_verified,
                checked + self.policy.provider_lease,
                connection.phone_e164,
                connection.phone_verified,
            )
            state.claim_token, state.claim_sha256 = claim.token, claim.digest()
            state.lease_expires_at = claim.lease_expires_at
            state.attempt_count += 1
            state.version += 1
            state.updated_at = checked
            return claim

    def claim_due(self, *, now: datetime | None = None) -> IdentityStateClaim | None:
        checked = _utc(now)
        with self._sessions() as db:
            candidates = list(
                db.scalars(
                    sa.select(IdentityConnection.id)
                    .join(GlobalUser, GlobalUser.id == IdentityConnection.user_id)
                    .outerjoin(
                        IdentityProviderStateRecord,
                        IdentityProviderStateRecord.connection_id == IdentityConnection.id,
                    )
                    .where(
                        GlobalUser.status == "active",
                        IdentityConnection.status == "active",
                        IdentityConnection.provider == "casdoor",
                        IdentityConnection.issuer == self.policy.issuer,
                        sa.or_(
                            IdentityProviderStateRecord.connection_id.is_(None),
                            sa.and_(
                                IdentityProviderStateRecord.status != "deleted",
                                IdentityProviderStateRecord.next_check_at <= checked,
                                sa.or_(
                                    IdentityProviderStateRecord.lease_expires_at.is_(None),
                                    IdentityProviderStateRecord.lease_expires_at <= checked,
                                ),
                            ),
                        ),
                    )
                    .order_by(
                        IdentityProviderStateRecord.next_check_at.asc().nulls_first(),
                        IdentityConnection.id,
                    )
                    .limit(100)
                )
            )
        for connection_id in candidates:
            claim = self.claim(connection_id, now=now)
            if claim is not None:
                return claim
        return None

    def _locked(self, db: Session, claim: IdentityStateClaim, now: datetime | None):
        user = db.scalar(
            sa.select(GlobalUser).where(GlobalUser.id == claim.user_id).with_for_update()
        )
        connection = db.scalar(
            sa.select(IdentityConnection)
            .where(IdentityConnection.id == claim.connection_id)
            .with_for_update()
        )
        state = db.scalar(
            sa.select(IdentityProviderStateRecord)
            .where(IdentityProviderStateRecord.connection_id == claim.connection_id)
            .with_for_update()
        )
        checked = _utc(now)
        if (
            user is None
            or user.status != "active"
            or user.security_version != claim.security_version
            or connection is None
            or connection.user_id != user.id
            or connection.status != "active"
            or connection.provider != "casdoor"
            or connection.issuer != claim.issuer
            or connection.subject != claim.subject
            or _stored(connection.updated_at) != claim.connection_updated_at
            or connection.email_normalized != claim.email_normalized
            or connection.email_verified != claim.email_verified
            or connection.phone_e164 != claim.phone_e164
            or connection.phone_verified != claim.phone_verified
            or claim.issuer != self.policy.issuer
            or claim.organization != self.policy.organization
            or state is None
            or state.status == "deleted"
            or state.subject_locator_sha256 != self._locator(claim.subject)
            or state.claim_token != claim.token
            or state.claim_sha256 != claim.digest()
            or state.lease_expires_at is None
            or _stored(state.lease_expires_at) != claim.lease_expires_at
            or _stored(state.lease_expires_at) <= checked
        ):
            raise IdentitySyncError("identity_state_claim_stale", retryable=True)
        return user, connection, state, checked

    def _validate(
        self, claim: IdentityStateClaim, proof: ProviderIdentityState, checked: datetime
    ) -> None:
        validate_provider_state(
            proof,
            issuer=claim.issuer,
            organization=claim.organization,
            subject=claim.subject,
            now=checked,
        )

    @staticmethod
    def _release(state: IdentityProviderStateRecord) -> None:
        state.claim_token = state.claim_sha256 = state.lease_expires_at = None

    def apply(
        self,
        claim: IdentityStateClaim,
        proof: ProviderIdentityState,
        *,
        security_cutoff: datetime | None = None,
        now: datetime | None = None,
    ) -> IdentityStateApplied:
        with self._sessions.begin() as db:
            user, connection, state, checked = self._locked(db, claim, now)
            self._validate(claim, proof, checked)
            if security_cutoff is not None:
                security_cutoff = _utc(security_cutoff)
                if security_cutoff > checked + timedelta(seconds=60):
                    raise IdentitySyncError("identity_notification_invalid")
            status = (
                "deleted"
                if not proof.exists or proof.deleted
                else "active"
                if proof.usable
                else "disabled"
            )
            email = normalize_email(proof.email) if proof.email_verified and proof.email else None
            verified = email is not None
            phone = proof.phone_e164 if proof.phone_verified else None
            phone_verified = phone is not None
            contact_changed = (
                connection.email_normalized != email
                or connection.email_verified != verified
                or connection.phone_e164 != phone
                or connection.phone_verified != phone_verified
            )
            password_changed = (
                state.checked_at is not None
                and state.password_revision_sha256 != proof.password_revision_sha256
            )
            transition = state.status != status
            changed = transition or contact_changed or password_changed
            cutoff = checked if changed else security_cutoff
            if state.checked_at is None and proof.password_changed_at is not None:
                cutoff = max(filter(None, (cutoff, proof.password_changed_at)))
            revoke = changed
            count, security_version = 0, user.security_version
            if cutoff is not None:
                fences = _lock_fences(
                    db,
                    provider="casdoor",
                    issuer=claim.issuer,
                    selectors=[("subject", claim.subject)],
                )
                fence = fences["subject"]
                advances = (
                    fence.logout_issued_at is None or _stored(fence.logout_issued_at) < cutoff
                )
                if advances:
                    fence.logout_issued_at = cutoff
                    revoke |= (
                        db.scalar(
                            sa.select(AuthSessionRecord.id)
                            .where(
                                AuthSessionRecord.user_id == user.id,
                                AuthSessionRecord.revoked_at.is_(None),
                                AuthSessionRecord.expires_at > checked,
                                sa.or_(
                                    AuthSessionRecord.external_issued_at <= cutoff,
                                    sa.and_(
                                        AuthSessionRecord.external_issued_at.is_(None),
                                        AuthSessionRecord.created_at <= cutoff,
                                    ),
                                ),
                            )
                            .limit(1)
                        )
                        is not None
                    )
                changed |= advances
            if revoke:
                security_version, count = _invalidate_sessions(db, user.id, checked)
            if connection.email_normalized != email or connection.email_verified != verified:
                if user.primary_email_normalized in {None, connection.email_normalized}:
                    user.primary_email_normalized = email
                connection.email_normalized, connection.email_verified = email, verified
                connection.updated_at = checked
            if connection.phone_e164 != phone or connection.phone_verified != phone_verified:
                connection.phone_e164, connection.phone_verified = phone, phone_verified
                connection.updated_at = checked
            state.status = status
            snapshot_sha256 = proof.snapshot_sha256()
            state.snapshot_sha256 = snapshot_sha256
            state.password_revision_sha256 = proof.password_revision_sha256
            state.password_changed_at = proof.password_changed_at
            if proof.username is not None:
                state.username_locator_sha256 = identity_locator(
                    claim.issuer, claim.organization, "username", proof.username
                )
            state.checked_at = state.updated_at = checked
            state.next_check_at = checked + self.policy.reconcile_interval
            state.last_error_code = None
            state.attempt_count = 0
            state.version += 1
            self._release(state)
            if changed:
                _add_event(
                    db,
                    event_type="identity.provider_state.applied",
                    aggregate_type="global_user",
                    aggregate_key=str(user.id),
                    idempotency_key=f"provider-state:{claim.connection_id}:{claim.token}",
                    request_hash=snapshot_sha256,
                    payload={
                        "identity_connection_id": str(connection.id),
                        "status": status,
                        "snapshot_sha256": state.snapshot_sha256,
                        "security_version": security_version,
                        "revoked_session_count": count,
                    },
                )
            return IdentityStateApplied(connection.id, status, security_version, count, changed)

    def fail(
        self, claim: IdentityStateClaim, error: IdentitySyncError, *, now: datetime | None = None
    ) -> None:
        with self._sessions.begin() as db:
            _user, _connection, state, checked = self._locked(db, claim, now)
            state.last_error_code = safe_identity_error_code(error)
            state.next_check_at = checked + timedelta(
                seconds=min(60, 2 ** min(state.attempt_count, 6))
            )
            state.updated_at = checked
            state.version += 1
            self._release(state)

    def process(
        self,
        claim: IdentityStateClaim,
        *,
        security_cutoff: datetime | None = None,
        now: datetime | None = None,
    ) -> IdentityStateApplied:
        try:
            proof = self._provider.read_identity(claim.subject)
            return self.apply(claim, proof, security_cutoff=security_cutoff, now=now)
        except IdentitySyncError as error:
            with suppress(IdentitySyncError):
                self.fail(claim, error, now=now)
            raise

    def _targets(self, claim: IdentityInboxClaim, now: datetime | None) -> list[UUID]:
        with self._sessions() as db:
            # Validate the durable claim without holding Inbox locks across account work.
            self.inbox._locked(db, claim, now)
            selector = (
                IdentityProviderStateRecord.subject_locator_sha256 == claim.subject_locator_sha256
                if claim.subject_locator_sha256 is not None
                else IdentityProviderStateRecord.username_locator_sha256
                == claim.username_locator_sha256
            )
            rows = db.execute(
                sa.select(
                    IdentityConnection.id,
                    IdentityConnection.status,
                    IdentityProviderStateRecord.status,
                )
                .join(
                    IdentityProviderStateRecord,
                    IdentityProviderStateRecord.connection_id == IdentityConnection.id,
                )
                .where(
                    IdentityConnection.provider == "casdoor",
                    IdentityConnection.issuer == claim.issuer,
                    selector,
                )
            ).all()
            if not rows:
                raise IdentitySyncError("identity_mapping_unavailable", retryable=True)
            return [row[0] for row in rows if row[1] == "active" and row[2] != "deleted"]

    def process_next_event(self, *, now: datetime | None = None) -> bool:
        event = self.inbox.claim_next(now=now)
        if event is None:
            return False
        try:
            processed = 0
            for connection_id in self._targets(event, now):
                claim = self.claim(connection_id, force=True, now=now)
                if claim is None:
                    # A parallel read will converge; retry the event for its security hint.
                    raise IdentitySyncError("identity_state_busy", retryable=True)
                self.process(
                    claim,
                    security_cutoff=event.occurred_at if event.security_event else None,
                    now=now,
                )
                processed += 1
            self.inbox.finish(event, processed_connections=processed, now=now)
            return True
        except IdentitySyncError as error:
            self.inbox.fail(event, error, now=now)
            raise
