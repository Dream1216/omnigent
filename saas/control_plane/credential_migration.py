"""Fenced, resumable credential import and explicit authority cutover."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import sqlalchemy as sa
from argon2 import Type, extract_parameters
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.credential_migration_models import CredentialMigrationRecord
from saas.control_plane.db_models import (
    GlobalUser,
    IdentityConflict,
    IdentityConnection,
    PasswordCredential,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.identity import _add_event, _invalidate_sessions, _reject_deleted_identity
from saas.control_plane.lifecycle import LifecycleError, normalize_email

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TERMINAL = frozenset({"completed", "conflict", "failed", "recovered"})


def _hash(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _digest(value: dict[str, object]) -> str:
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _time(value: datetime | None = None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise ValueError("migration timestamps require a timezone")
    return result.astimezone(timezone.utc)


def _stored_time(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class CredentialMigrationError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class CredentialMigrationPolicy:
    issuer: str
    organization: str
    policy_sha256: str
    allow_insecure_loopback: bool = False
    lease_duration: timedelta = timedelta(minutes=2)
    max_attempts: int = 5

    def __post_init__(self) -> None:
        parsed = urlsplit(self.issuer)
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path
            or (
                parsed.scheme != "https"
                and not (self.allow_insecure_loopback and loopback and parsed.scheme == "http")
            )
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", self.organization)
            or not _SHA256.fullmatch(self.policy_sha256)
            or not timedelta(seconds=10) <= self.lease_duration <= timedelta(minutes=10)
            or not 1 <= self.max_attempts <= 20
        ):
            raise ValueError("credential migration policy is invalid")


@dataclass(frozen=True, slots=True)
class CredentialMigrationView:
    id: UUID
    user_id: UUID
    batch_id: str
    status: str
    issuer: str
    organization: str
    provider_subject: str
    version: int
    last_error_code: str | None
    mode: str = "hash_import"


@dataclass(frozen=True, slots=True)
class CredentialImportClaim:
    receipt_id: UUID
    user_id: UUID
    issuer: str
    organization: str
    subject: str
    username: str
    policy_sha256: str
    source_password_sha256: str
    source_email_sha256: str
    claim_token: UUID
    password_hash: str = field(repr=False)
    email: str = field(repr=False)
    mode: str = "hash_import"
    provider_snapshot_sha256: str | None = None

    def marker_document(self) -> dict[str, object]:
        if self.mode != "hash_import":
            raise CredentialMigrationError("provider_import_claim_invalid")
        return {
            "receipt_id": str(self.receipt_id),
            "user_id": str(self.user_id),
            "issuer": self.issuer,
            "organization": self.organization,
            "subject": self.subject,
            "username": self.username,
            "policy_sha256": self.policy_sha256,
            "source_password_sha256": self.source_password_sha256,
            "source_email_sha256": self.source_email_sha256,
        }


@dataclass(frozen=True, slots=True)
class VerifiedMigrationIdentity:
    """Only a trusted provider adapter constructs this server-read snapshot."""

    issuer: str
    organization: str
    subject: str
    username: str
    email: str = field(repr=False)
    email_verified: bool = False
    active: bool = False
    is_admin: bool = False
    is_global_admin: bool = False
    marker_verified: bool = False

    def snapshot_sha256(self) -> str:
        return _digest(
            {
                "issuer": self.issuer,
                "organization": self.organization,
                "subject": self.subject,
                "username": self.username,
                "email_sha256": _hash(normalize_email(self.email)),
                "email_verified": self.email_verified,
                "active": self.active,
                "is_admin": self.is_admin,
                "is_global_admin": self.is_global_admin,
                "marker_verified": self.marker_verified,
            }
        )


class CredentialImportProvider(Protocol):
    def ensure_import(self, claim: CredentialImportClaim) -> VerifiedMigrationIdentity:
        """Deduplicate by the durable receipt and read authoritative provider state."""
        ...


@dataclass(frozen=True, slots=True)
class VerifiedLinkedCredentialIdentity:
    identity: VerifiedMigrationIdentity
    password_configured: bool

    def snapshot_sha256(self) -> str:
        return _digest(
            {
                "identity_snapshot_sha256": self.identity.snapshot_sha256(),
                "password_configured": self.password_configured,
            }
        )


@runtime_checkable
class LinkedCredentialIdentityProvider(Protocol):
    def read_linked_identity(self, subject: str) -> VerifiedLinkedCredentialIdentity:
        """Read a previously authenticated identity; never import or change its credential."""
        ...


class CredentialMigrationService:
    """Private worker authority; no public endpoint accepts imported identity mappings."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        policy: CredentialMigrationPolicy,
        provider: CredentialImportProvider,
    ) -> None:
        self._sessions = sessions
        self._policy = policy
        self._provider = provider

    @staticmethod
    def _view(record: CredentialMigrationRecord) -> CredentialMigrationView:
        return CredentialMigrationView(
            record.id,
            record.user_id,
            record.batch_id,
            record.status,
            record.issuer,
            record.organization,
            record.provider_subject,
            record.version,
            record.last_error_code,
            record.mode,
        )

    @staticmethod
    def _user(db: Session, user_id: UUID) -> GlobalUser:
        user = db.scalar(sa.select(GlobalUser).where(GlobalUser.id == user_id).with_for_update())
        if user is None:
            raise CredentialMigrationError("migration_user_unavailable")
        return user

    def get(self, receipt_id: UUID) -> CredentialMigrationView:
        with self._sessions() as db:
            record = db.get(CredentialMigrationRecord, receipt_id)
            if record is None:
                raise CredentialMigrationError("migration_receipt_unavailable")
            return self._view(record)

    def prepare(
        self,
        *,
        user_id: UUID,
        batch_id: str,
        expected_password_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> CredentialMigrationView:
        prepared_at = _time(now)
        if not _LABEL.fullmatch(batch_id) or not 1 <= len(idempotency_key) <= 128:
            raise CredentialMigrationError("migration_request_invalid")
        key = scoped_idempotency_key("credential-migration", user_id, idempotency_key)
        request_hash = _digest(
            {
                "user_id": str(user_id),
                "batch_id": batch_id,
                "expected_password_version": expected_password_version,
                "issuer": self._policy.issuer,
                "organization": self._policy.organization,
                "policy_sha256": self._policy.policy_sha256,
            }
        )
        with self._sessions.begin() as db:
            user = self._user(db, user_id)
            existing = db.scalar(
                sa.select(CredentialMigrationRecord).where(
                    sa.or_(
                        CredentialMigrationRecord.idempotency_key == key,
                        sa.and_(
                            CredentialMigrationRecord.user_id == user_id,
                            CredentialMigrationRecord.batch_id == batch_id,
                        ),
                    )
                )
            )
            if existing is not None:
                if existing.idempotency_key != key or existing.request_hash != request_hash:
                    raise CredentialMigrationError("idempotency_conflict")
                return self._view(existing)
            if user.status != "active" or user.credential_owner != "legacy":
                raise CredentialMigrationError("migration_user_ineligible")
            active = db.scalar(
                sa.select(CredentialMigrationRecord.id).where(
                    CredentialMigrationRecord.user_id == user_id,
                    CredentialMigrationRecord.status.in_(("pending", "imported")),
                )
            )
            if active is not None:
                raise CredentialMigrationError("migration_already_pending")
            credential = db.get(PasswordCredential, user_id)
            if credential is None or credential.password_version != expected_password_version:
                raise CredentialMigrationError("credential_version_conflict")
            email = credential.login_email_normalized
            verified = db.scalar(
                sa.select(IdentityConnection.id)
                .where(
                    IdentityConnection.user_id == user_id,
                    IdentityConnection.status == "active",
                    IdentityConnection.email_verified.is_(True),
                    IdentityConnection.email_normalized == email,
                )
                .limit(1)
            )
            if verified is None:
                raise CredentialMigrationError("verified_email_required")
            try:
                parameters = extract_parameters(credential.password_hash)
                if parameters.type != Type.ID or parameters.memory_cost > 1_048_576:
                    raise ValueError("unsupported credential")
            except (ValueError, TypeError) as error:
                raise CredentialMigrationError("credential_import_unsupported") from error
            subject = str(user_id)
            _reject_deleted_identity(db, self._policy.issuer, subject)
            record = CredentialMigrationRecord(
                id=uuid4(),
                user_id=user_id,
                batch_id=batch_id,
                issuer=self._policy.issuer,
                organization=self._policy.organization,
                provider_subject=subject,
                provider_username="omnigent-" + user_id.hex,
                source_password_version=credential.password_version,
                source_security_version=user.security_version,
                source_password_sha256=_hash(credential.password_hash),
                source_email_sha256=_hash(email),
                policy_sha256=self._policy.policy_sha256,
                idempotency_key=key,
                request_hash=request_hash,
                status="pending",
                mode="hash_import",
                attempt_count=0,
                version=1,
                created_at=prepared_at,
                updated_at=prepared_at,
            )
            db.add(record)
            user.migration_state = "pending"
            self._event(db, record, "prepared")
            return self._view(record)

    @staticmethod
    def _existing_preparation(
        db: Session, *, user_id: UUID, batch_id: str, key: str, request_hash: str
    ) -> CredentialMigrationRecord | None:
        record = db.scalar(
            sa.select(CredentialMigrationRecord).where(
                sa.or_(
                    CredentialMigrationRecord.idempotency_key == key,
                    sa.and_(
                        CredentialMigrationRecord.user_id == user_id,
                        CredentialMigrationRecord.batch_id == batch_id,
                    ),
                )
            )
        )
        if record is not None and (
            record.idempotency_key != key or record.request_hash != request_hash
        ):
            raise CredentialMigrationError("idempotency_conflict")
        return record

    def _linked_source(
        self, db: Session, user: GlobalUser, connection_id: UUID, password_version: int
    ) -> tuple[PasswordCredential, IdentityConnection, str]:
        if user.status != "active" or user.credential_owner != "legacy":
            raise CredentialMigrationError("migration_user_ineligible")
        if (
            db.scalar(
                sa.select(CredentialMigrationRecord.id).where(
                    CredentialMigrationRecord.user_id == user.id,
                    CredentialMigrationRecord.status.in_(("pending", "imported")),
                )
            )
            is not None
        ):
            raise CredentialMigrationError("migration_already_pending")
        credential = db.get(PasswordCredential, user.id)
        if credential is None or credential.password_version != password_version:
            raise CredentialMigrationError("credential_version_conflict")
        connection = db.get(IdentityConnection, connection_id)
        if (
            connection is None
            or connection.user_id != user.id
            or connection.provider != "casdoor"
            or connection.issuer != self._policy.issuer
            or connection.status != "active"
            or not connection.email_verified
            or connection.email_normalized is None
        ):
            raise CredentialMigrationError("migration_existing_link_required")
        if (
            db.scalar(
                sa.select(IdentityConnection.id)
                .where(
                    IdentityConnection.user_id == user.id,
                    IdentityConnection.status == "active",
                    IdentityConnection.email_verified.is_(True),
                    IdentityConnection.email_normalized == credential.login_email_normalized,
                )
                .limit(1)
            )
            is None
        ):
            raise CredentialMigrationError("verified_email_required")
        _reject_deleted_identity(db, connection.issuer, connection.subject)
        snapshot = _digest(
            {
                "user_id": str(user.id),
                "security_version": user.security_version,
                "password_version": credential.password_version,
                "password_sha256": _hash(credential.password_hash),
                "login_email_sha256": _hash(credential.login_email_normalized),
                "connection_id": str(connection.id),
                "subject": connection.subject,
                "connection_email_sha256": _hash(connection.email_normalized),
            }
        )
        return credential, connection, snapshot

    def prepare_existing_link(
        self,
        *,
        user_id: UUID,
        connection_id: UUID,
        batch_id: str,
        expected_password_version: int,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> CredentialMigrationView:
        prepared_at = _time(now)
        if not _LABEL.fullmatch(batch_id) or not 1 <= len(idempotency_key) <= 128:
            raise CredentialMigrationError("migration_request_invalid")
        if not isinstance(self._provider, LinkedCredentialIdentityProvider):
            raise CredentialMigrationError("linked_provider_unavailable", retryable=True)
        key = scoped_idempotency_key("credential-migration", user_id, idempotency_key)
        request_hash = _digest(
            {
                "mode": "existing_link",
                "user_id": str(user_id),
                "connection_id": str(connection_id),
                "batch_id": batch_id,
                "expected_password_version": expected_password_version,
                "issuer": self._policy.issuer,
                "organization": self._policy.organization,
                "policy_sha256": self._policy.policy_sha256,
            }
        )
        lookup = {
            "user_id": user_id,
            "batch_id": batch_id,
            "key": key,
            "request_hash": request_hash,
        }
        with self._sessions.begin() as db:
            user = self._user(db, user_id)
            existing = self._existing_preparation(db, **lookup)
            if existing is not None:
                return self._view(existing)
            _credential, connection, source_snapshot = self._linked_source(
                db, user, connection_id, expected_password_version
            )
            subject = connection.subject
            email_sha256 = _hash(connection.email_normalized or "")
        proof = self._provider.read_linked_identity(subject)
        identity = proof.identity
        if (
            identity.issuer != self._policy.issuer
            or identity.organization != self._policy.organization
            or identity.subject != subject
            or not 1 <= len(identity.username) <= 128
        ):
            raise CredentialMigrationError("provider_mapping_conflict")
        if not identity.active or identity.is_admin or identity.is_global_admin:
            raise CredentialMigrationError("provider_identity_ineligible")
        try:
            verified_email_sha256 = _hash(normalize_email(identity.email))
        except LifecycleError:
            raise CredentialMigrationError("provider_verified_email_mismatch") from None
        if not identity.email_verified or verified_email_sha256 != email_sha256:
            raise CredentialMigrationError("provider_verified_email_mismatch")
        if not proof.password_configured:
            raise CredentialMigrationError("provider_password_setup_required")
        with self._sessions.begin() as db:
            user = self._user(db, user_id)
            existing = self._existing_preparation(db, **lookup)
            if existing is not None:
                return self._view(existing)
            credential, connection, current_snapshot = self._linked_source(
                db, user, connection_id, expected_password_version
            )
            if current_snapshot != source_snapshot:
                raise CredentialMigrationError("source_credential_changed")
            record = CredentialMigrationRecord(
                id=uuid4(),
                user_id=user_id,
                batch_id=batch_id,
                issuer=self._policy.issuer,
                organization=self._policy.organization,
                provider_subject=connection.subject,
                provider_username=identity.username,
                source_password_version=credential.password_version,
                source_security_version=user.security_version,
                source_password_sha256=_hash(credential.password_hash),
                source_email_sha256=_hash(credential.login_email_normalized),
                policy_sha256=self._policy.policy_sha256,
                idempotency_key=key,
                request_hash=request_hash,
                mode="existing_link",
                status="pending",
                attempt_count=0,
                version=1,
                identity_connection_id=connection.id,
                provider_snapshot_sha256=proof.snapshot_sha256(),
                created_at=prepared_at,
                updated_at=prepared_at,
            )
            db.add(record)
            user.migration_state = "pending"
            self._event(db, record, "prepared")
            return self._view(record)

    def _source_error(
        self,
        user: GlobalUser,
        credential: PasswordCredential | None,
        record: CredentialMigrationRecord,
    ) -> str | None:
        if user.status != "active" or user.credential_owner != "legacy":
            return "migration_user_ineligible"
        if record.policy_sha256 != self._policy.policy_sha256:
            return "migration_policy_changed"
        if (
            credential is None
            or credential.password_version != record.source_password_version
            or _hash(credential.password_hash) != record.source_password_sha256
            or _hash(credential.login_email_normalized) != record.source_email_sha256
            or user.security_version != record.source_security_version
        ):
            return "source_credential_changed"
        return None

    @staticmethod
    def _linked_source_error(
        db: Session,
        user: GlobalUser,
        record: CredentialMigrationRecord,
        proof: VerifiedMigrationIdentity | VerifiedLinkedCredentialIdentity | None = None,
    ) -> str | None:
        if record.mode != "existing_link":
            return None
        connection = db.scalar(
            sa.select(IdentityConnection)
            .where(
                IdentityConnection.id == record.identity_connection_id,
                IdentityConnection.user_id == user.id,
            )
            .with_for_update()
        )
        if (
            connection is None
            or connection.status != "active"
            or connection.provider != "casdoor"
            or connection.issuer != record.issuer
            or connection.subject != record.provider_subject
            or not connection.email_verified
            or connection.email_normalized is None
        ):
            return "migration_existing_link_required"
        if isinstance(proof, VerifiedLinkedCredentialIdentity) and (
            normalize_email(proof.identity.email) != connection.email_normalized
        ):
            return "provider_verified_email_mismatch"
        return None

    def claim(
        self,
        receipt_id: UUID,
        *,
        now: datetime | None = None,
    ) -> CredentialImportClaim | CredentialMigrationView:
        claimed_at = _time(now)
        with self._sessions.begin() as db:
            user_id = db.scalar(
                sa.select(CredentialMigrationRecord.user_id).where(
                    CredentialMigrationRecord.id == receipt_id
                )
            )
            if user_id is None:
                raise CredentialMigrationError("migration_receipt_unavailable")
            user = self._user(db, user_id)
            record = db.scalar(
                sa.select(CredentialMigrationRecord)
                .where(CredentialMigrationRecord.id == receipt_id)
                .with_for_update()
            )
            assert record is not None
            claimed_at = _time(now)
            if record.status in _TERMINAL:
                return self._view(record)
            if (
                record.claim_token is not None
                and record.lease_expires_at is not None
                and (_stored_time(record.lease_expires_at) > claimed_at)
            ):
                raise CredentialMigrationError("migration_claim_busy", retryable=True)
            credential = db.get(PasswordCredential, user_id)
            error = self._source_error(user, credential, record) or self._linked_source_error(
                db, user, record
            )
            if error is not None:
                self._fail(db, record, user, error, "conflict", claimed_at)
                return self._view(record)
            if record.attempt_count >= self._policy.max_attempts:
                self._fail(db, record, user, "migration_attempts_exhausted", "failed", claimed_at)
                return self._view(record)
            assert credential is not None
            claim_token = uuid4()
            record.claim_token = claim_token
            record.lease_expires_at = claimed_at + self._policy.lease_duration
            record.attempt_count += 1
            record.version += 1
            record.updated_at = claimed_at
            return CredentialImportClaim(
                record.id,
                user_id,
                record.issuer,
                record.organization,
                record.provider_subject,
                record.provider_username,
                record.policy_sha256,
                record.source_password_sha256,
                record.source_email_sha256,
                claim_token,
                credential.password_hash if record.mode == "hash_import" else "",
                credential.login_email_normalized if record.mode == "hash_import" else "",
                record.mode,
                record.provider_snapshot_sha256 if record.mode == "existing_link" else None,
            )

    @staticmethod
    def _identity_error(
        claim: CredentialImportClaim,
        proof: VerifiedMigrationIdentity | VerifiedLinkedCredentialIdentity,
    ) -> str | None:
        identity = proof.identity if isinstance(proof, VerifiedLinkedCredentialIdentity) else proof
        if (
            identity.issuer != claim.issuer
            or identity.organization != claim.organization
            or identity.subject != claim.subject
            or identity.username != claim.username
        ):
            return "provider_mapping_conflict"
        if claim.mode == "hash_import":
            if isinstance(proof, VerifiedLinkedCredentialIdentity) or not identity.marker_verified:
                return "provider_mapping_conflict"
        elif claim.mode == "existing_link":
            if (
                not isinstance(proof, VerifiedLinkedCredentialIdentity)
                or not proof.password_configured
            ):
                return "provider_password_setup_required"
            if proof.snapshot_sha256() != claim.provider_snapshot_sha256:
                return "provider_link_snapshot_changed"
        else:
            return "migration_mode_invalid"
        if not identity.active or identity.is_admin or identity.is_global_admin:
            return "provider_identity_ineligible"
        try:
            email_sha256 = _hash(normalize_email(identity.email))
        except LifecycleError:
            return "provider_verified_email_mismatch"
        if not identity.email_verified or (
            claim.mode == "hash_import" and email_sha256 != claim.source_email_sha256
        ):
            return "provider_verified_email_mismatch"
        return None

    def run_once(
        self,
        receipt_id: UUID,
        *,
        cutover: bool = False,
        now: datetime | None = None,
    ) -> CredentialMigrationView:
        claim = self.claim(receipt_id, now=now)
        if isinstance(claim, CredentialMigrationView):
            return claim
        try:
            if claim.mode == "existing_link":
                if not isinstance(self._provider, LinkedCredentialIdentityProvider):
                    raise CredentialMigrationError("linked_provider_unavailable", retryable=True)
                identity = self._provider.read_linked_identity(claim.subject)
            else:
                identity = self._provider.ensure_import(claim)
            error = self._identity_error(claim, identity)
            if error is not None:
                raise CredentialMigrationError(error)
        except CredentialMigrationError as error:
            return self.record_failure(claim, error, now=now)
        return self.finish(claim, identity, cutover=cutover, now=now)

    def _locked_claim(
        self,
        db: Session,
        claim: CredentialImportClaim,
        now: datetime | None,
    ) -> tuple[GlobalUser, CredentialMigrationRecord, datetime]:
        user = self._user(db, claim.user_id)
        record = db.scalar(
            sa.select(CredentialMigrationRecord)
            .where(
                CredentialMigrationRecord.id == claim.receipt_id,
                CredentialMigrationRecord.user_id == claim.user_id,
            )
            .with_for_update()
        )
        checked_at = _time(now)
        if (
            record is None
            or record.status in _TERMINAL
            or record.claim_token != claim.claim_token
            or record.lease_expires_at is None
            or _stored_time(record.lease_expires_at) <= checked_at
            or any(
                getattr(claim, left) != getattr(record, right)
                for left, right in (
                    ("issuer", "issuer"),
                    ("organization", "organization"),
                    ("subject", "provider_subject"),
                    ("username", "provider_username"),
                    ("policy_sha256", "policy_sha256"),
                    ("source_password_sha256", "source_password_sha256"),
                    ("source_email_sha256", "source_email_sha256"),
                    ("mode", "mode"),
                )
            )
            or (
                record.mode == "existing_link"
                and claim.provider_snapshot_sha256 != record.provider_snapshot_sha256
            )
        ):
            raise CredentialMigrationError("migration_claim_stale")
        return user, record, checked_at

    def record_failure(
        self,
        claim: CredentialImportClaim,
        error: CredentialMigrationError,
        *,
        now: datetime | None = None,
    ) -> CredentialMigrationView:
        with self._sessions.begin() as db:
            user, record, checked_at = self._locked_claim(db, claim, now)
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", error.code):
                raise ValueError("migration errors must use content-blind codes")
            status = (
                record.status
                if error.retryable and record.attempt_count < self._policy.max_attempts
                else ("failed" if error.retryable else "conflict")
            )
            self._fail(db, record, user, error.code, status, checked_at)
            return self._view(record)

    def finish(
        self,
        claim: CredentialImportClaim,
        identity: VerifiedMigrationIdentity | VerifiedLinkedCredentialIdentity,
        *,
        cutover: bool,
        now: datetime | None = None,
    ) -> CredentialMigrationView:
        proof = identity
        identity = proof.identity if isinstance(proof, VerifiedLinkedCredentialIdentity) else proof
        with self._sessions.begin() as db:
            user, record, checked_at = self._locked_claim(db, claim, now)
            credential = db.get(PasswordCredential, user.id)
            error = (
                self._source_error(user, credential, record)
                or self._identity_error(claim, proof)
                or self._linked_source_error(db, user, record, proof)
            )
            if error is not None:
                self._fail(db, record, user, error, "conflict", checked_at)
                return self._view(record)
            _reject_deleted_identity(db, claim.issuer, claim.subject)
            first_import = record.imported_at is None
            record.status = "imported"
            if record.mode == "hash_import":
                record.provider_snapshot_sha256 = identity.snapshot_sha256()
            record.imported_at = record.imported_at or checked_at
            record.last_error_code = None
            record.claim_token = None
            record.lease_expires_at = None
            record.version += 1
            record.updated_at = checked_at
            user.migration_state = "imported"
            if first_import:
                self._event(
                    db, record, "imported" if record.mode == "hash_import" else "link_verified"
                )
            if not cutover:
                return self._view(record)
            connection = db.scalar(
                sa.select(IdentityConnection)
                .where(
                    IdentityConnection.issuer == claim.issuer,
                    IdentityConnection.subject == claim.subject,
                )
                .with_for_update()
            )
            if connection is not None and (
                connection.user_id != user.id
                or connection.provider != "casdoor"
                or connection.status != "active"
            ):
                self._fail(db, record, user, "provider_mapping_conflict", "conflict", checked_at)
                return self._view(record)
            conflicts = list(
                db.scalars(
                    sa.select(IdentityConflict)
                    .where(
                        IdentityConflict.issuer == claim.issuer,
                        IdentityConflict.subject == claim.subject,
                    )
                    .with_for_update()
                )
            )
            if any(
                c.status == "rejected"
                or c.platform_review_status == "blocked"
                or (c.candidate_user_id is not None and c.candidate_user_id != user.id)
                for c in conflicts
            ):
                self._fail(db, record, user, "identity_review_blocked", "conflict", checked_at)
                return self._view(record)
            if any(conflict.status == "pending" for conflict in conflicts):
                self._fail(db, record, user, "identity_review_required", "conflict", checked_at)
                return self._view(record)
            if connection is None:
                connection = IdentityConnection(
                    id=uuid4(),
                    user_id=user.id,
                    provider="casdoor",
                    issuer=claim.issuer,
                    subject=claim.subject,
                    email_normalized=normalize_email(identity.email),
                    email_verified=True,
                    status="active",
                )
                db.add(connection)
                db.flush()
            connection.email_normalized = normalize_email(identity.email)
            connection.email_verified = True
            record.identity_connection_id = connection.id
            record.status = "completed"
            record.completed_at = checked_at
            user.credential_owner = "casdoor"
            user.migration_state = "cutover"
            security_version, revoked = _invalidate_sessions(db, user.id, checked_at)
            self._event(
                db,
                record,
                "cutover",
                {
                    "identity_connection_id": str(connection.id),
                    "security_version": security_version,
                    "revoked_session_count": revoked,
                },
            )
            return self._view(record)

    @staticmethod
    def _event(
        db: Session,
        record: CredentialMigrationRecord,
        action: str,
        extra: dict[str, object] | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "user_id": str(record.user_id),
            "receipt_id": str(record.id),
            "batch_id": record.batch_id,
            "status": record.status,
            "mode": record.mode,
            "provider_snapshot_sha256": record.provider_snapshot_sha256,
            **(extra or {}),
        }
        _add_event(
            db,
            event_type="identity.credential_migration." + action,
            aggregate_type="global_user",
            aggregate_key=str(record.user_id),
            idempotency_key=f"credential-migration:{record.id}:{action}:{record.version}",
            request_hash=_digest(payload),
            payload=payload,
        )

    def _fail(
        self,
        db: Session,
        record: CredentialMigrationRecord,
        user: GlobalUser,
        code: str,
        status: str,
        now: datetime,
    ) -> None:
        record.status = status
        record.last_error_code = code
        record.claim_token = None
        record.lease_expires_at = None
        record.version += 1
        record.updated_at = now
        if status in _TERMINAL and user.credential_owner == "legacy":
            user.migration_state = "legacy"
        self._event(db, record, "attempt_failed", {"code": code})
