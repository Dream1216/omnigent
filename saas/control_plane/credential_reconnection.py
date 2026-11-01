"""Offline-authorized return through the exact identity revoked by recovery."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import UUID

import sqlalchemy as sa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.credential_migration import (
    CredentialMigrationError,
    CredentialMigrationPolicy,
    CredentialMigrationService,
    LinkedCredentialIdentityProvider,
    VerifiedLinkedCredentialIdentity,
    _hash,
    _time,
)
from saas.control_plane.credential_migration_models import CredentialMigrationRecord
from saas.control_plane.credential_recovery import (
    CredentialRecoveryKeyring,
    _decode,
    recovery_grant_payload,
)
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    IdentityConflict,
    IdentityConnection,
    PasswordCredential,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.identity import _add_event, _invalidate_sessions, _reject_deleted_identity
from saas.control_plane.identity_event_models import IdentityProviderStateRecord
from saas.control_plane.lifecycle import normalize_email

RECONNECTION_SIGNATURE_DOMAIN = b"omnigent.credential-reconnection.v1\x00"
RECONNECTION_REQUEST_FIELDS = frozenset(
    {
        "user_id",
        "receipt_id",
        "connection_id",
        "recovery_grant_sha256",
        "expected_security_version",
        "expected_password_version",
        "source_password_sha256",
        "provider_snapshot_sha256",
        "source_email_sha256",
        "connection_email_sha256",
        "review_reference",
        "reason_code",
    }
)
_GRANT_FIELDS = RECONNECTION_REQUEST_FIELDS | {
    "schema_version",
    "grant_id",
    "issued_at",
    "expires_at",
}


@dataclass(frozen=True, slots=True)
class CredentialReconnectionKeyring:
    public_keys: Mapping[str, bytes]

    def __post_init__(self) -> None:
        validated = CredentialRecoveryKeyring(self.public_keys)
        object.__setattr__(self, "public_keys", validated.public_keys)

    def verify(self, token: str, *, now: datetime) -> dict[str, object]:
        try:
            if len(token) > 8192:
                raise ValueError
            version, key_id, encoded, signature = token.split(".")
            if version != "v1" or key_id not in self.public_keys:
                raise ValueError
            payload = _decode(encoded)
            Ed25519PublicKey.from_public_bytes(self.public_keys[key_id]).verify(
                _decode(signature), RECONNECTION_SIGNATURE_DOMAIN + payload
            )
            document = json.loads(payload)
            versions = {"schema_version", "expected_security_version", "expected_password_version"}
            if (
                not isinstance(document, dict)
                or set(document) != _GRANT_FIELDS
                or payload != recovery_grant_payload(document)
                or any(type(document[name]) is not int or document[name] <= 0 for name in versions)
                or document["schema_version"] != 1
                or any(not isinstance(document[name], str) for name in _GRANT_FIELDS - versions)
                or any(
                    not re.fullmatch(r"[0-9a-f]{64}", document[name])
                    for name in (
                        "recovery_grant_sha256",
                        "source_password_sha256",
                        "provider_snapshot_sha256",
                        "source_email_sha256",
                        "connection_email_sha256",
                    )
                )
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", document["review_reference"]
                )
                or document["reason_code"] != "identity_restored"
            ):
                raise ValueError
            for name in ("grant_id", "user_id", "receipt_id", "connection_id"):
                if str(UUID(document[name])) != document[name]:
                    raise ValueError
            issued = _time(datetime.fromisoformat(document["issued_at"]))
            expires = _time(datetime.fromisoformat(document["expires_at"]))
            if not issued <= now < expires or not timedelta(0) < expires - issued <= timedelta(
                minutes=5
            ):
                raise ValueError
            return document
        except (ValueError, TypeError, KeyError, InvalidSignature, UnicodeError):
            raise CredentialMigrationError("credential_reconnection_grant_invalid") from None


class CredentialReconnectionService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        policy: CredentialMigrationPolicy,
        provider: LinkedCredentialIdentityProvider,
        verification_keys: CredentialReconnectionKeyring,
    ) -> None:
        self._sessions, self._policy, self._provider, self._keys = (
            sessions,
            policy,
            provider,
            verification_keys,
        )

    def _state(self, db: Session, user_id: UUID, receipt_id: UUID):
        user = CredentialMigrationService._user(db, user_id)
        record = db.scalar(
            sa.select(CredentialMigrationRecord)
            .where(
                CredentialMigrationRecord.id == receipt_id,
                CredentialMigrationRecord.user_id == user_id,
            )
            .with_for_update()
        )
        credential = db.get(PasswordCredential, user_id)
        if (
            record is None
            or record.status != "recovered"
            or record.recovered_at is None
            or user.status != "active"
            or user.credential_owner != "legacy"
            or user.migration_state != "recovered"
            or credential is None
            or record.issuer != self._policy.issuer
            or record.organization != self._policy.organization
            or db.scalar(
                sa.select(CredentialMigrationRecord.id).where(
                    CredentialMigrationRecord.user_id == user_id,
                    CredentialMigrationRecord.status.in_(("pending", "imported")),
                )
            )
            is not None
        ):
            raise CredentialMigrationError("credential_reconnection_state_conflict")
        connection = db.scalar(
            sa.select(IdentityConnection)
            .where(
                IdentityConnection.id == record.identity_connection_id,
            )
            .with_for_update()
        )
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(user_id),
                ControlPlaneOutboxEvent.event_type == "identity.credential_migration.recovered",
                ControlPlaneOutboxEvent.payload["receipt_id"].as_string() == str(receipt_id),
            )
        )
        reconnectable = event.payload.get("reconnectable_connection_ids") if event else None
        if (
            connection is None
            or connection.user_id != user_id
            or connection.provider != "casdoor"
            or connection.issuer != record.issuer
            or connection.subject != record.provider_subject
            or connection.status != "revoked"
            or not connection.email_verified
            or not connection.email_normalized
            or event is None
            or not isinstance(reconnectable, list)
            or str(connection.id) not in reconnectable
            or not isinstance(event.payload.get("grant_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", event.payload["grant_sha256"])
        ):
            raise CredentialMigrationError("credential_reconnection_state_conflict")
        _reject_deleted_identity(db, connection.issuer, connection.subject)
        provider_state = db.scalar(
            sa.select(IdentityProviderStateRecord)
            .where(IdentityProviderStateRecord.connection_id == connection.id)
            .with_for_update()
        )
        if provider_state is not None and provider_state.status == "deleted":
            raise CredentialMigrationError("credential_reconnection_state_conflict")
        if (
            db.scalar(
                sa.select(IdentityConflict.id).where(
                    IdentityConflict.issuer == connection.issuer,
                    IdentityConflict.subject == connection.subject,
                    sa.or_(
                        IdentityConflict.status.in_(("pending", "rejected")),
                        IdentityConflict.platform_review_status == "blocked",
                    ),
                )
            )
            is not None
        ):
            raise CredentialMigrationError("identity_review_blocked")
        return connection, {
            "user_id": str(user_id),
            "receipt_id": str(receipt_id),
            "connection_id": str(connection.id),
            "recovery_grant_sha256": event.payload["grant_sha256"],
            "expected_security_version": user.security_version,
            "expected_password_version": credential.password_version,
            "source_password_sha256": _hash(credential.password_hash),
            "source_email_sha256": _hash(credential.login_email_normalized),
            "connection_email_sha256": _hash(connection.email_normalized),
        }

    def _proof(self, connection: IdentityConnection) -> VerifiedLinkedCredentialIdentity:
        proof = self._provider.read_linked_identity(connection.subject)
        identity = proof.identity
        if (
            identity.issuer != self._policy.issuer
            or identity.organization != self._policy.organization
            or identity.subject != connection.subject
            or not identity.active
            or not identity.email_verified
            or identity.is_admin
            or identity.is_global_admin
            or not proof.password_configured
            or normalize_email(identity.email) != connection.email_normalized
        ):
            raise CredentialMigrationError("credential_reconnection_provider_invalid")
        return proof

    def prepare_request(
        self,
        *,
        user_id: UUID,
        receipt_id: UUID,
        review_reference: str,
    ) -> dict[str, object]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", review_reference):
            raise CredentialMigrationError("credential_reconnection_request_invalid")
        with self._sessions.begin() as db:
            connection, before = self._state(db, user_id, receipt_id)
            db.expunge(connection)
        proof = self._proof(connection)
        with self._sessions.begin() as db:
            _connection, after = self._state(db, user_id, receipt_id)
            if before != after:
                raise CredentialMigrationError("credential_reconnection_state_conflict")
        return {
            **after,
            "provider_snapshot_sha256": proof.snapshot_sha256(),
            "review_reference": review_reference,
            "reason_code": "identity_restored",
        }

    @staticmethod
    def _applied(db: Session, user_id: UUID, key: str, grant_hash: str) -> bool:
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key
                == scoped_idempotency_key("user", user_id, key)
            )
        )
        if event is not None and event.request_hash != grant_hash:
            raise CredentialMigrationError("idempotency_conflict")
        return event is not None

    def reconnect(self, *, signed_grant: str, now: datetime | None = None) -> UUID:
        grant = self._keys.verify(signed_grant, now=_time(now))
        user_id, receipt_id = UUID(str(grant["user_id"])), UUID(str(grant["receipt_id"]))
        key = scoped_idempotency_key("credential-reconnection", user_id, str(grant["grant_id"]))
        grant_hash = sha256(signed_grant.encode()).hexdigest()
        with self._sessions.begin() as db:
            CredentialMigrationService._user(db, user_id)
            if self._applied(db, user_id, key, grant_hash):
                return UUID(str(grant["connection_id"]))
            connection, before = self._state(db, user_id, receipt_id)
            db.expunge(connection)
        proof = self._proof(connection)
        with self._sessions.begin() as db:
            CredentialMigrationService._user(db, user_id)
            if self._applied(db, user_id, key, grant_hash):
                return UUID(str(grant["connection_id"]))
            current, after = self._state(db, user_id, receipt_id)
            # The grant and fresh provider read must both match the state after locks.
            if (
                before != after
                or any(grant[name] != value for name, value in after.items())
                or (grant["provider_snapshot_sha256"] != proof.snapshot_sha256())
            ):
                raise CredentialMigrationError("credential_reconnection_state_conflict")
            completed_at = _time(now)
            self._keys.verify(signed_grant, now=completed_at)
            current.status = "active"
            provider_state = db.get(IdentityProviderStateRecord, current.id)
            if provider_state is not None:
                provider_state.status = "active"
                provider_state.checked_at = None
                provider_state.next_check_at = completed_at
                provider_state.claim_token = None
                provider_state.claim_sha256 = None
                provider_state.lease_expires_at = None
                provider_state.version += 1
                provider_state.updated_at = completed_at
            security_version, revoked = _invalidate_sessions(db, user_id, completed_at)
            _add_event(
                db,
                event_type="identity.credential_migration.reconnected",
                aggregate_type="global_user",
                aggregate_key=str(user_id),
                idempotency_key=key,
                request_hash=grant_hash,
                payload={
                    "user_id": str(user_id),
                    "receipt_id": str(receipt_id),
                    "identity_connection_id": str(current.id),
                    "grant_id": grant["grant_id"],
                    "grant_sha256": grant_hash,
                    "review_reference": grant["review_reference"],
                    "provider_snapshot_sha256": proof.snapshot_sha256(),
                    "security_version": security_version,
                    "revoked_session_count": revoked,
                },
            )
            return current.id
