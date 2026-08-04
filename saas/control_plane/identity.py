"""Global identity connections and SaaS-owned password credentials."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from omnigent.server.passwords import (
    InvalidPasswordError,
    hash_password,
    needs_rehash,
    verify_password,
)
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    PasswordCredential,
)
from saas.control_plane.lifecycle import LifecycleError, normalize_email

_MAX_PASSWORD_FAILURES = 5
_PASSWORD_LOCK_TIME = timedelta(minutes=15)
_MIN_PASSWORD_LENGTH = 12
_MAX_PASSWORD_LENGTH = 1024


@dataclass(frozen=True, slots=True)
class VerifiedIdentityAssertion:
    """Provider-verified identity facts; never construct from a public request body."""

    provider: str
    issuer: str
    subject: str
    email: str | None
    email_verified: bool
    display_name: str | None = None

    def validate(self) -> None:
        if not self.provider.strip() or len(self.provider) > 64:
            raise LifecycleError("identity_assertion_invalid", "identity provider is invalid")
        if not self.issuer.strip() or len(self.issuer) > 512:
            raise LifecycleError("identity_assertion_invalid", "identity issuer is invalid")
        if not self.subject.strip() or len(self.subject) > 512:
            raise LifecycleError("identity_assertion_invalid", "identity subject is invalid")
        if self.email is not None:
            normalize_email(self.email)


@dataclass(frozen=True, slots=True)
class PasswordChanged:
    """Password mutation result after security-version invalidation."""

    password_version: int
    security_version: int
    revoked_session_count: int
    replayed: bool


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _comparable_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _hash_payload(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


def _add_event(
    db: Session,
    *,
    event_type: str,
    aggregate_type: str,
    aggregate_key: str,
    idempotency_key: str,
    request_hash: str,
    payload: dict[str, object],
) -> None:
    db.add(
        ControlPlaneOutboxEvent(
            tenant_id=None,
            aggregate_type=aggregate_type,
            aggregate_key=aggregate_key,
            event_type=event_type,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            payload=payload,
            attempt_count=0,
        )
    )


def _invalidate_sessions(db: Session, user_id: UUID, changed_at: datetime) -> tuple[int, int]:
    security_version = db.execute(
        sa.update(GlobalUser)
        .where(GlobalUser.id == user_id, GlobalUser.status == "active")
        .values(security_version=GlobalUser.security_version + 1)
        .returning(GlobalUser.security_version)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()
    if security_version is None:
        raise LifecycleError("user_inactive", "active user is required")
    result = cast(
        CursorResult[tuple[object]],
        db.execute(
            sa.update(AuthSessionRecord)
            .where(
                AuthSessionRecord.user_id == user_id,
                AuthSessionRecord.revoked_at.is_(None),
            )
            .values(revoked_at=changed_at)
        ),
    )
    return security_version, result.rowcount


class IdentityManagementService:
    """Provision, link, list, and revoke immutable provider subjects."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def provision_identity(self, assertion: VerifiedIdentityAssertion) -> UUID:
        """Resolve an existing subject or create a new Global User without email merging."""

        assertion.validate()
        email = normalize_email(assertion.email) if assertion.email else None
        with self._session_factory.begin() as db:
            existing = db.execute(
                sa.select(IdentityConnection).where(
                    IdentityConnection.issuer == assertion.issuer,
                    IdentityConnection.subject == assertion.subject,
                )
            ).scalar_one_or_none()
            if existing is not None:
                if existing.status != "active":
                    raise LifecycleError("identity_revoked", "identity connection is revoked")
                return existing.user_id

            user_id = uuid4()
            connection_id = uuid4()
            db.add(
                GlobalUser(
                    id=user_id,
                    status="active",
                    display_name=assertion.display_name,
                    primary_email_normalized=email if assertion.email_verified else None,
                    security_version=1,
                )
            )
            db.add(
                IdentityConnection(
                    id=connection_id,
                    user_id=user_id,
                    provider=assertion.provider,
                    issuer=assertion.issuer,
                    subject=assertion.subject,
                    email_normalized=email,
                    email_verified=assertion.email_verified,
                    status="active",
                )
            )
            try:
                db.flush()
            except IntegrityError as error:
                raise LifecycleError(
                    "identity_conflict", "identity subject was linked concurrently"
                ) from error
            request_hash = _hash_payload(
                {
                    "provider": assertion.provider,
                    "issuer": assertion.issuer,
                    "subject": assertion.subject,
                    "email": email,
                    "email_verified": assertion.email_verified,
                }
            )
            _add_event(
                db,
                event_type="identity.connection.provisioned",
                aggregate_type="global_user",
                aggregate_key=str(user_id),
                idempotency_key=f"identity-provision:{request_hash}",
                request_hash=request_hash,
                payload={
                    "user_id": str(user_id),
                    "identity_connection_id": str(connection_id),
                    "provider": assertion.provider,
                    "issuer": assertion.issuer,
                },
            )
            return user_id

    def link_identity(
        self,
        *,
        user_id: UUID,
        assertion: VerifiedIdentityAssertion,
        idempotency_key: str,
    ) -> UUID:
        """Link a provider-verified subject to an already authenticated Global User."""

        assertion.validate()
        if not idempotency_key or len(idempotency_key) > 128:
            raise LifecycleError("invalid_idempotency_key", "idempotency key is invalid")
        email = normalize_email(assertion.email) if assertion.email else None
        request_hash = _hash_payload(
            {
                "user_id": str(user_id),
                "provider": assertion.provider,
                "issuer": assertion.issuer,
                "subject": assertion.subject,
                "email": email,
                "email_verified": assertion.email_verified,
            }
        )
        with self._session_factory.begin() as db:
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == idempotency_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return UUID(cast(str, receipt.payload["identity_connection_id"]))

            user = db.get(GlobalUser, user_id)
            if user is None or user.status != "active":
                raise LifecycleError("user_inactive", "active user is required")
            existing = db.execute(
                sa.select(IdentityConnection).where(
                    IdentityConnection.issuer == assertion.issuer,
                    IdentityConnection.subject == assertion.subject,
                )
            ).scalar_one_or_none()
            if existing is not None:
                if existing.user_id != user_id:
                    raise LifecycleError(
                        "identity_conflict", "identity subject belongs to another Global User"
                    )
                if existing.status == "active":
                    _add_event(
                        db,
                        event_type="identity.connection.linked",
                        aggregate_type="global_user",
                        aggregate_key=str(user_id),
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        payload={
                            "user_id": str(user_id),
                            "identity_connection_id": str(existing.id),
                            "provider": existing.provider,
                            "issuer": existing.issuer,
                        },
                    )
                    return existing.id
                raise LifecycleError("identity_revoked", "revoked identities cannot be relinked")

            connection_id = uuid4()
            db.add(
                IdentityConnection(
                    id=connection_id,
                    user_id=user_id,
                    provider=assertion.provider,
                    issuer=assertion.issuer,
                    subject=assertion.subject,
                    email_normalized=email,
                    email_verified=assertion.email_verified,
                    status="active",
                )
            )
            _add_event(
                db,
                event_type="identity.connection.linked",
                aggregate_type="global_user",
                aggregate_key=str(user_id),
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload={
                    "user_id": str(user_id),
                    "identity_connection_id": str(connection_id),
                    "provider": assertion.provider,
                    "issuer": assertion.issuer,
                },
            )
            return connection_id

    def list_identities(self, user_id: UUID) -> list[IdentityConnection]:
        """Return the caller's identity connections without credential secrets."""

        with self._session_factory() as db:
            return list(
                db.execute(
                    sa.select(IdentityConnection)
                    .where(IdentityConnection.user_id == user_id)
                    .order_by(IdentityConnection.created_at)
                ).scalars()
            )

    def revoke_identity(
        self,
        *,
        user_id: UUID,
        connection_id: UUID,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> None:
        """Revoke one identity while preserving at least one login method."""

        changed_at = now or _now()
        if not idempotency_key or len(idempotency_key) > 128:
            raise LifecycleError("invalid_idempotency_key", "idempotency key is invalid")
        request_hash = _hash_payload(
            {"user_id": str(user_id), "connection_id": str(connection_id)}
        )
        with self._session_factory.begin() as db:
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == idempotency_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return
            connection = db.get(IdentityConnection, connection_id)
            if connection is None or connection.user_id != user_id:
                raise LifecycleError("identity_not_found", "identity connection does not exist")
            if connection.status == "revoked":
                return
            active_count = db.execute(
                sa.select(sa.func.count())
                .select_from(IdentityConnection)
                .where(
                    IdentityConnection.user_id == user_id,
                    IdentityConnection.status == "active",
                )
            ).scalar_one()
            has_password = db.get(PasswordCredential, user_id) is not None
            if active_count <= 1 and not has_password:
                raise LifecycleError(
                    "last_login_method", "the last login method cannot be revoked"
                )
            connection.status = "revoked"
            security_version, revoked_count = _invalidate_sessions(db, user_id, changed_at)
            _add_event(
                db,
                event_type="identity.connection.revoked",
                aggregate_type="global_user",
                aggregate_key=str(user_id),
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload={
                    "user_id": str(user_id),
                    "identity_connection_id": str(connection_id),
                    "security_version": security_version,
                    "revoked_session_count": revoked_count,
                },
            )


class PasswordCredentialService:
    """Set and verify Argon2id credentials with lockout and versioned revocation."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        self._dummy_password_hash = hash_password("not-a-real-password-value")

    @staticmethod
    def _validate_new_password(password: str) -> None:
        if not _MIN_PASSWORD_LENGTH <= len(password) <= _MAX_PASSWORD_LENGTH:
            raise LifecycleError(
                "password_policy",
                f"password must contain {_MIN_PASSWORD_LENGTH} to "
                f"{_MAX_PASSWORD_LENGTH} characters",
            )

    def authenticate(self, email: str, password: str, *, now: datetime | None = None) -> UUID:
        """Authenticate one unambiguous verified email without revealing failure cause."""

        checked_at = now or _now()
        normalized = normalize_email(email)
        with self._session_factory() as db:
            credential = db.execute(
                sa.select(PasswordCredential)
                .join(GlobalUser, GlobalUser.id == PasswordCredential.user_id)
                .where(
                    PasswordCredential.login_email_normalized == normalized,
                    GlobalUser.status == "active",
                )
            ).scalar_one_or_none()

        password_hash = (
            credential.password_hash if credential is not None else self._dummy_password_hash
        )
        password_valid = True
        try:
            verify_password(password, password_hash)
        except InvalidPasswordError:
            password_valid = False

        if credential is None:
            raise LifecycleError("invalid_credentials", "email or password is invalid")
        if (
            credential.locked_until is not None
            and _comparable_time(credential.locked_until) > checked_at
        ):
            raise LifecycleError("invalid_credentials", "email or password is invalid")
        if not password_valid:
            with self._session_factory.begin() as db:
                db.execute(
                    sa.update(PasswordCredential)
                    .where(
                        PasswordCredential.user_id == credential.user_id,
                        PasswordCredential.password_hash == credential.password_hash,
                    )
                    .values(
                        failed_attempts=PasswordCredential.failed_attempts + 1,
                        locked_until=sa.case(
                            (
                                PasswordCredential.failed_attempts + 1 >= _MAX_PASSWORD_FAILURES,
                                checked_at + _PASSWORD_LOCK_TIME,
                            ),
                            else_=PasswordCredential.locked_until,
                        ),
                    )
                )
            raise LifecycleError("invalid_credentials", "email or password is invalid")

        with self._session_factory.begin() as db:
            values: dict[str, object] = {"failed_attempts": 0, "locked_until": None}
            if needs_rehash(credential.password_hash):
                values["password_hash"] = hash_password(password)
            result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(PasswordCredential)
                    .where(
                        PasswordCredential.user_id == credential.user_id,
                        PasswordCredential.password_hash == credential.password_hash,
                    )
                    .values(**values)
                ),
            )
            if result.rowcount != 1:
                raise LifecycleError("credentials_changed", "credential changed during login")
        return credential.user_id

    def set_password(
        self,
        *,
        user_id: UUID,
        new_password: str,
        idempotency_key: str,
        expected_version: int | None = None,
        current_password: str | None = None,
        now: datetime | None = None,
    ) -> PasswordChanged:
        """Create or rotate a password and invalidate every existing session."""

        self._validate_new_password(new_password)
        if not idempotency_key or len(idempotency_key) > 128:
            raise LifecycleError("invalid_idempotency_key", "idempotency key is invalid")
        changed_at = now or _now()
        request_hash = _hash_payload(
            {"user_id": str(user_id), "expected_version": expected_version}
        )
        with self._session_factory() as db:
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == idempotency_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if (
                    receipt.request_hash != request_hash
                    or receipt.event_type != "identity.password.changed"
                ):
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return PasswordChanged(
                    password_version=cast(int, receipt.payload["password_version"]),
                    security_version=cast(int, receipt.payload["security_version"]),
                    revoked_session_count=cast(int, receipt.payload["revoked_session_count"]),
                    replayed=True,
                )
            current = db.get(PasswordCredential, user_id)
            current_hash = current.password_hash if current else None
            current_version = current.password_version if current else None
            login_email = current.login_email_normalized if current else None
            if login_email is None:
                user = db.get(GlobalUser, user_id)
                if user is None or user.status != "active":
                    raise LifecycleError("user_inactive", "active user is required")
                login_email = user.primary_email_normalized
            if login_email is None:
                verified_emails = set(
                    db.execute(
                        sa.select(IdentityConnection.email_normalized).where(
                            IdentityConnection.user_id == user_id,
                            IdentityConnection.email_verified.is_(True),
                            IdentityConnection.status == "active",
                            IdentityConnection.email_normalized.is_not(None),
                        )
                    ).scalars()
                )
                if len(verified_emails) != 1:
                    raise LifecycleError(
                        "password_login_email_required",
                        "one unambiguous verified email is required for password login",
                    )
                login_email = verified_emails.pop()
        if current_hash is not None:
            if current_password is None:
                raise LifecycleError("current_password_required", "current password is required")
            try:
                verify_password(current_password, current_hash)
            except InvalidPasswordError as error:
                raise LifecycleError(
                    "invalid_credentials", "current password is invalid"
                ) from error
        if expected_version != current_version:
            raise LifecycleError("credential_version_conflict", "password credential changed")

        new_hash = hash_password(new_password)
        with self._session_factory.begin() as db:
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == idempotency_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if (
                    receipt.request_hash != request_hash
                    or receipt.event_type != "identity.password.changed"
                ):
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return PasswordChanged(
                    password_version=cast(int, receipt.payload["password_version"]),
                    security_version=cast(int, receipt.payload["security_version"]),
                    revoked_session_count=cast(int, receipt.payload["revoked_session_count"]),
                    replayed=True,
                )

            user = db.get(GlobalUser, user_id)
            if user is None or user.status != "active":
                raise LifecycleError("user_inactive", "active user is required")
            credential = db.get(PasswordCredential, user_id)
            if credential is None:
                if current_hash is not None:
                    raise LifecycleError("credential_version_conflict", "password changed")
                new_version = 1
                db.add(
                    PasswordCredential(
                        user_id=user_id,
                        login_email_normalized=login_email,
                        password_hash=new_hash,
                        password_version=new_version,
                        failed_attempts=0,
                        locked_until=None,
                    )
                )
            else:
                if credential.password_hash != current_hash:
                    raise LifecycleError("credential_version_conflict", "password changed")
                new_version = credential.password_version + 1
                credential.password_hash = new_hash
                credential.password_version = new_version
                credential.failed_attempts = 0
                credential.locked_until = None
            try:
                db.flush()
            except IntegrityError as error:
                raise LifecycleError(
                    "password_login_email_conflict",
                    "verified email already belongs to another password credential",
                ) from error
            security_version, revoked_count = _invalidate_sessions(db, user_id, changed_at)
            payload: dict[str, object] = {
                "user_id": str(user_id),
                "password_version": new_version,
                "security_version": security_version,
                "revoked_session_count": revoked_count,
            }
            _add_event(
                db,
                event_type="identity.password.changed",
                aggregate_type="global_user",
                aggregate_key=str(user_id),
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=payload,
            )
            return PasswordChanged(
                password_version=new_version,
                security_version=security_version,
                revoked_session_count=revoked_count,
                replayed=False,
            )
