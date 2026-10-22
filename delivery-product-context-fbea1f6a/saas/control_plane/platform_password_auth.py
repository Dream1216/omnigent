"""Local username/password authentication for the independent Staff Realm."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from omnigent.server.passwords import (
    InvalidPasswordError,
    hash_password,
    needs_rehash,
    verify_password,
)
from saas.control_plane.platform_models import (
    PlatformAuthSessionRecord,
    PlatformPasswordCredentialRecord,
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)
from saas.control_plane.platform_security import (
    IssuedPlatformSession,
    PlatformSecurityError,
    PlatformSessionService,
    StaffIdentityAssertion,
)
from saas.control_plane.rls import PlatformRlsContext, apply_platform_rls_context

STAFF_PASSWORD_ISSUER = "urn:omnigent:staff-password"
_USERNAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._@+-]{2,127}")
_MIN_PASSWORD_LENGTH = 12
_MAX_PASSWORD_LENGTH = 1024
_MAX_FAILURES = 5
_LOCK_TIME = timedelta(minutes=15)
_SESSION_TTL = timedelta(hours=8)
_INITIAL_STAFF_BOOTSTRAP_LOCK = 0x4F4D4E4953545057
_LOCAL_OPERATOR_TRANSITION_LOCK = 0x4F4D4E4953544C50


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _comparable(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def normalize_staff_username(username: str) -> str:
    normalized = username.strip().casefold()
    if _USERNAME_PATTERN.fullmatch(normalized) is None:
        raise PlatformSecurityError(
            "platform_username_invalid",
            "Staff username must contain 3 to 128 supported characters",
        )
    return normalized


def _validate_password(password: str) -> None:
    if not _MIN_PASSWORD_LENGTH <= len(password) <= _MAX_PASSWORD_LENGTH:
        raise PlatformSecurityError(
            "platform_password_policy",
            f"Staff password must contain {_MIN_PASSWORD_LENGTH} to "
            f"{_MAX_PASSWORD_LENGTH} characters",
        )


class PlatformPasswordAuthenticationService:
    """Provision and authenticate local Staff accounts without an external IdP."""

    def __init__(
        self,
        authentication_factory: sessionmaker[Session],
        sessions: PlatformSessionService,
        *,
        governance_factory: sessionmaker[Session] | None = None,
    ) -> None:
        self._authentication = authentication_factory
        self._governance = governance_factory or authentication_factory
        self._sessions = sessions
        self._dummy_password_hash = hash_password("not-a-real-staff-password")

    def provision_account(
        self,
        *,
        username: str,
        password: str,
        display_name: str | None = None,
        email_normalized: str | None = None,
        now: datetime | None = None,
    ) -> UUID:
        """Create one role-less local Staff account through governance authority."""

        normalized = normalize_staff_username(username)
        _validate_password(password)
        changed_at = now or _utcnow()
        if changed_at.tzinfo is None or changed_at.utcoffset() is None:
            raise PlatformSecurityError("platform_time_invalid", "now must include a timezone")
        encoded = hash_password(password)
        principal_id = uuid4()
        with self._governance.begin() as db:
            existing = db.execute(
                sa.select(PlatformPasswordCredentialRecord.principal_id).where(
                    PlatformPasswordCredentialRecord.username_normalized == normalized
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise PlatformSecurityError(
                    "platform_account_conflict", "Staff username already exists"
                )
            db.add(
                PlatformStaffPrincipalRecord(
                    id=principal_id,
                    identity_connection_ref=f"local-password:{normalized}",
                    issuer=STAFF_PASSWORD_ISSUER,
                    subject=normalized,
                    display_name=display_name.strip() if display_name else None,
                    email_normalized=(
                        email_normalized.strip().casefold() if email_normalized else None
                    ),
                    status="active",
                    security_version=1,
                    created_at=changed_at,
                    updated_at=changed_at,
                )
            )
            db.flush()
            db.add(
                PlatformPasswordCredentialRecord(
                    principal_id=principal_id,
                    username_normalized=normalized,
                    password_hash=encoded,
                    password_version=1,
                    failed_attempts=0,
                    updated_at=changed_at,
                )
            )
        return principal_id

    def bootstrap_initial_operator(
        self,
        *,
        username: str,
        password: str,
        display_name: str | None = None,
        email_normalized: str | None = None,
        now: datetime | None = None,
    ) -> UUID:
        """Create the first local Staff operator exactly once."""

        normalized = normalize_staff_username(username)
        _validate_password(password)
        changed_at = now or _utcnow()
        if changed_at.tzinfo is None or changed_at.utcoffset() is None:
            raise PlatformSecurityError("platform_time_invalid", "now must include a timezone")
        encoded = hash_password(password)
        principal_id = uuid4()
        with self._governance.begin() as db:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text("SELECT pg_advisory_xact_lock(:lock_id)"),
                    {"lock_id": _INITIAL_STAFF_BOOTSTRAP_LOCK},
                )
            occupied = any(
                db.execute(sa.select(sa.func.count()).select_from(model)).scalar_one() != 0
                for model in (
                    PlatformStaffPrincipalRecord,
                    PlatformPasswordCredentialRecord,
                    PlatformRoleAssignmentRecord,
                    PlatformAuthSessionRecord,
                )
            )
            if occupied:
                raise PlatformSecurityError(
                    "platform_bootstrap_conflict",
                    "initial local Staff bootstrap is no longer available",
                )
            db.add(
                PlatformStaffPrincipalRecord(
                    id=principal_id,
                    identity_connection_ref=f"local-password:{normalized}",
                    issuer=STAFF_PASSWORD_ISSUER,
                    subject=normalized,
                    display_name=display_name.strip() if display_name else None,
                    email_normalized=(
                        email_normalized.strip().casefold() if email_normalized else None
                    ),
                    status="active",
                    security_version=1,
                    created_at=changed_at,
                    updated_at=changed_at,
                )
            )
            db.flush()
            db.add(
                PlatformPasswordCredentialRecord(
                    principal_id=principal_id,
                    username_normalized=normalized,
                    password_hash=encoded,
                    password_version=1,
                    failed_attempts=0,
                    updated_at=changed_at,
                )
            )
            db.add(
                PlatformRoleAssignmentRecord(
                    id=uuid4(),
                    principal_id=principal_id,
                    role="platform_operator",
                    status="active",
                    version=1,
                    assigned_by_principal_id=principal_id,
                    approval_ref="local-password-initial-bootstrap",
                    reason="initial local Staff operator",
                    created_at=changed_at,
                    updated_at=changed_at,
                )
            )
        return principal_id

    def transition_local_operator(
        self,
        *,
        username: str,
        password: str,
        authorized_by_principal_id: UUID,
        approval_ref: str,
        reason: str,
        display_name: str | None = None,
        email_normalized: str | None = None,
        now: datetime | None = None,
    ) -> UUID:
        """Create the first local operator in an occupied legacy Staff store.

        The named authorizer must be an active operator. Retries return the same
        principal only when the username, password, assignment, and approval all
        match the completed transition.
        """

        normalized = normalize_staff_username(username)
        _validate_password(password)
        approval = approval_ref.strip()
        justification = reason.strip()
        changed_at = now or _utcnow()
        if changed_at.tzinfo is None or changed_at.utcoffset() is None:
            raise PlatformSecurityError("platform_time_invalid", "now must include a timezone")
        if (
            authorized_by_principal_id.int == 0
            or not approval
            or len(approval) > 256
            or not justification
            or len(justification) > 1024
        ):
            raise PlatformSecurityError(
                "platform_transition_invalid", "local Staff operator transition is incomplete"
            )
        encoded = hash_password(password)
        with self._governance.begin() as db:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text("SELECT pg_advisory_xact_lock(:lock_id)"),
                    {"lock_id": _LOCAL_OPERATOR_TRANSITION_LOCK},
                )
            authorizer = db.get(PlatformStaffPrincipalRecord, authorized_by_principal_id)
            authorizer_assignment = db.execute(
                sa.select(PlatformRoleAssignmentRecord).where(
                    PlatformRoleAssignmentRecord.principal_id == authorized_by_principal_id,
                    PlatformRoleAssignmentRecord.role == "platform_operator",
                    PlatformRoleAssignmentRecord.status == "active",
                    sa.or_(
                        PlatformRoleAssignmentRecord.expires_at.is_(None),
                        PlatformRoleAssignmentRecord.expires_at > changed_at,
                    ),
                )
            ).scalar_one_or_none()
            if (
                authorizer is None
                or authorizer.status != "active"
                or authorizer_assignment is None
            ):
                raise PlatformSecurityError(
                    "platform_transition_authority_invalid",
                    "active legacy Staff operator authorization is required",
                )

            credential = db.execute(
                sa.select(PlatformPasswordCredentialRecord).where(
                    PlatformPasswordCredentialRecord.username_normalized == normalized
                )
            ).scalar_one_or_none()
            if credential is not None:
                principal = db.get(PlatformStaffPrincipalRecord, credential.principal_id)
                assignment = db.execute(
                    sa.select(PlatformRoleAssignmentRecord).where(
                        PlatformRoleAssignmentRecord.principal_id == credential.principal_id,
                        PlatformRoleAssignmentRecord.role == "platform_operator",
                        PlatformRoleAssignmentRecord.status == "active",
                        sa.or_(
                            PlatformRoleAssignmentRecord.expires_at.is_(None),
                            PlatformRoleAssignmentRecord.expires_at > changed_at,
                        ),
                    )
                ).scalar_one_or_none()
                try:
                    verify_password(password, credential.password_hash)
                except InvalidPasswordError:
                    password_matches = False
                else:
                    password_matches = True
                if (
                    principal is None
                    or principal.status != "active"
                    or principal.issuer != STAFF_PASSWORD_ISSUER
                    or principal.subject != normalized
                    or assignment is None
                    or assignment.assigned_by_principal_id != authorized_by_principal_id
                    or assignment.approval_ref != approval
                    or assignment.reason != justification
                    or not password_matches
                ):
                    raise PlatformSecurityError(
                        "platform_transition_conflict",
                        "local Staff operator transition conflicts with existing state",
                    )
                return principal.id

            existing_local_accounts = db.execute(
                sa.select(sa.func.count()).select_from(PlatformPasswordCredentialRecord)
            ).scalar_one()
            if existing_local_accounts != 0:
                raise PlatformSecurityError(
                    "platform_transition_conflict",
                    "the first local Staff operator transition is no longer available",
                )

            principal_id = uuid4()
            db.add(
                PlatformStaffPrincipalRecord(
                    id=principal_id,
                    identity_connection_ref=f"local-password:{normalized}",
                    issuer=STAFF_PASSWORD_ISSUER,
                    subject=normalized,
                    display_name=display_name.strip() if display_name else None,
                    email_normalized=(
                        email_normalized.strip().casefold() if email_normalized else None
                    ),
                    status="active",
                    security_version=1,
                    created_at=changed_at,
                    updated_at=changed_at,
                )
            )
            db.flush()
            db.add(
                PlatformPasswordCredentialRecord(
                    principal_id=principal_id,
                    username_normalized=normalized,
                    password_hash=encoded,
                    password_version=1,
                    failed_attempts=0,
                    updated_at=changed_at,
                )
            )
            db.add(
                PlatformRoleAssignmentRecord(
                    id=uuid4(),
                    principal_id=principal_id,
                    role="platform_operator",
                    status="active",
                    version=1,
                    assigned_by_principal_id=authorized_by_principal_id,
                    approval_ref=approval,
                    reason=justification,
                    created_at=changed_at,
                    updated_at=changed_at,
                )
            )
        return principal_id

    def authenticate(
        self,
        username: str,
        password: str,
        *,
        now: datetime | None = None,
    ) -> IssuedPlatformSession:
        """Verify local credentials and issue an isolated Staff browser session."""

        checked_at = now or _utcnow()
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise PlatformSecurityError("platform_time_invalid", "now must include a timezone")
        username_valid = True
        try:
            normalized = normalize_staff_username(username)
        except PlatformSecurityError:
            normalized = "invalid-staff-user"
            username_valid = False

        with self._authentication.begin() as db:
            apply_platform_rls_context(
                db,
                PlatformRlsContext(
                    identity_issuer=STAFF_PASSWORD_ISSUER,
                    identity_subject=normalized,
                ),
            )
            credential = db.execute(
                sa.select(PlatformPasswordCredentialRecord)
                .join(
                    PlatformStaffPrincipalRecord,
                    PlatformStaffPrincipalRecord.id
                    == PlatformPasswordCredentialRecord.principal_id,
                )
                .where(
                    sa.true() if username_valid else sa.false(),
                    PlatformPasswordCredentialRecord.username_normalized == normalized,
                    PlatformStaffPrincipalRecord.issuer == STAFF_PASSWORD_ISSUER,
                    PlatformStaffPrincipalRecord.subject == normalized,
                    PlatformStaffPrincipalRecord.status == "active",
                )
            ).scalar_one_or_none()

        encoded = credential.password_hash if credential is not None else self._dummy_password_hash
        password_valid = True
        try:
            verify_password(password, encoded)
        except InvalidPasswordError:
            password_valid = False

        if credential is None:
            raise PlatformSecurityError(
                "platform_invalid_credentials", "username or password is invalid"
            )
        if (
            credential.locked_until is not None
            and _comparable(credential.locked_until) > checked_at
        ):
            raise PlatformSecurityError(
                "platform_invalid_credentials", "username or password is invalid"
            )
        if not password_valid:
            with self._authentication.begin() as db:
                apply_platform_rls_context(
                    db,
                    PlatformRlsContext(
                        identity_issuer=STAFF_PASSWORD_ISSUER,
                        identity_subject=normalized,
                    ),
                )
                expired_lock = sa.and_(
                    PlatformPasswordCredentialRecord.locked_until.is_not(None),
                    PlatformPasswordCredentialRecord.locked_until <= checked_at,
                )
                next_failures = sa.case(
                    (expired_lock, 1),
                    else_=PlatformPasswordCredentialRecord.failed_attempts + 1,
                )
                db.execute(
                    sa.update(PlatformPasswordCredentialRecord)
                    .where(
                        PlatformPasswordCredentialRecord.principal_id == credential.principal_id,
                        PlatformPasswordCredentialRecord.password_hash == encoded,
                    )
                    .values(
                        failed_attempts=next_failures,
                        locked_until=sa.case(
                            (expired_lock, None),
                            (
                                next_failures >= _MAX_FAILURES,
                                checked_at + _LOCK_TIME,
                            ),
                            else_=PlatformPasswordCredentialRecord.locked_until,
                        ),
                        updated_at=checked_at,
                    )
                )
            raise PlatformSecurityError(
                "platform_invalid_credentials", "username or password is invalid"
            )

        with self._authentication.begin() as db:
            apply_platform_rls_context(
                db,
                PlatformRlsContext(
                    identity_issuer=STAFF_PASSWORD_ISSUER,
                    identity_subject=normalized,
                ),
            )
            values: dict[str, object] = {
                "failed_attempts": 0,
                "locked_until": None,
                "updated_at": checked_at,
            }
            if needs_rehash(encoded):
                values["password_hash"] = hash_password(password)
            result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(PlatformPasswordCredentialRecord)
                    .where(
                        PlatformPasswordCredentialRecord.principal_id == credential.principal_id,
                        PlatformPasswordCredentialRecord.password_hash == encoded,
                        sa.or_(
                            PlatformPasswordCredentialRecord.locked_until.is_(None),
                            PlatformPasswordCredentialRecord.locked_until <= checked_at,
                        ),
                    )
                    .values(**values)
                ),
            )
            if result.rowcount != 1:
                raise PlatformSecurityError(
                    "platform_invalid_credentials", "username or password is invalid"
                )

        return self._sessions.issue_session(
            StaffIdentityAssertion(
                issuer=STAFF_PASSWORD_ISSUER,
                subject=normalized,
                authn_method="password",
                mfa_strength="not_required",
                authenticated_at=checked_at,
            ),
            expires_at=checked_at + _SESSION_TTL,
            now=checked_at,
        )

    def reset_password(
        self,
        *,
        principal_id: UUID,
        new_password: str,
        expected_version: int,
        now: datetime | None = None,
    ) -> int:
        """Reset one Staff password and revoke every existing browser session."""

        _validate_password(new_password)
        changed_at = now or _utcnow()
        if changed_at.tzinfo is None or changed_at.utcoffset() is None:
            raise PlatformSecurityError("platform_time_invalid", "now must include a timezone")
        encoded = hash_password(new_password)
        with self._governance.begin() as db:
            apply_platform_rls_context(db, PlatformRlsContext(principal_id=principal_id))
            credential = db.get(PlatformPasswordCredentialRecord, principal_id)
            principal = db.get(PlatformStaffPrincipalRecord, principal_id)
            if credential is None or principal is None or principal.status == "deleted":
                raise PlatformSecurityError(
                    "platform_account_not_found", "local Staff account was not found"
                )
            if credential.password_version != expected_version:
                raise PlatformSecurityError(
                    "platform_credentials_conflict", "Staff credential version has changed"
                )
            credential.password_hash = encoded
            credential.password_version += 1
            credential.failed_attempts = 0
            credential.locked_until = None
            credential.updated_at = changed_at
            principal.security_version += 1
            principal.updated_at = changed_at
            db.execute(
                sa.update(PlatformAuthSessionRecord)
                .where(
                    PlatformAuthSessionRecord.principal_id == principal_id,
                    PlatformAuthSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=changed_at)
            )
            return credential.password_version
