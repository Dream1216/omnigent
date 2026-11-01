"""Offline-authorized fresh-password recovery; retained passwords stay unusable."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
from types import MappingProxyType
from uuid import UUID

import sqlalchemy as sa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session, sessionmaker

from omnigent.server.passwords import InvalidPasswordError, needs_rehash, verify_password
from saas.control_plane.credential_migration import (
    CredentialMigrationError,
    CredentialMigrationService,
    CredentialMigrationView,
    _digest,
    _hash,
    _time,
)
from saas.control_plane.credential_migration_models import CredentialMigrationRecord
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    IdentityConnection,
    PasswordCredential,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.identity import PasswordCredentialService, _add_event, _invalidate_sessions

RECOVERY_SIGNATURE_DOMAIN = b"omnigent.credential-recovery.v1\x00"
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GRANT_FIELDS = frozenset(
    {
        "schema_version",
        "grant_id",
        "user_id",
        "receipt_id",
        "expected_security_version",
        "new_password_hash_sha256",
        "issued_at",
        "expires_at",
        "review_reference",
        "reason_code",
    }
)


def recovery_grant_payload(document: Mapping[str, object]) -> bytes:
    """Canonical bytes signed offline; the worker holds public verification keys only."""
    return json.dumps(
        dict(document), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


@dataclass(frozen=True, slots=True)
class CredentialRecoveryKeyring:
    public_keys: Mapping[str, bytes]

    def __post_init__(self) -> None:
        if not 1 <= len(self.public_keys) <= 8 or any(
            not _KEY_ID.fullmatch(key_id) or not isinstance(key, bytes) or len(key) != 32
            for key_id, key in self.public_keys.items()
        ):
            raise ValueError("credential recovery verification keys are invalid")
        object.__setattr__(self, "public_keys", MappingProxyType(dict(self.public_keys)))

    def verify(self, token: str, *, now: datetime) -> dict[str, object]:
        try:
            if len(token) > 8192:
                raise ValueError
            version, key_id, encoded, signature = token.split(".")
            if version != "v1" or key_id not in self.public_keys:
                raise ValueError
            payload = _decode(encoded)
            Ed25519PublicKey.from_public_bytes(self.public_keys[key_id]).verify(
                _decode(signature), RECOVERY_SIGNATURE_DOMAIN + payload
            )
            document = json.loads(payload)
            if (
                not isinstance(document, dict)
                or set(document) != _GRANT_FIELDS
                or payload != recovery_grant_payload(document)
                or type(document["schema_version"]) is not int
                or document["schema_version"] != 1
                or type(document["expected_security_version"]) is not int
                or document["expected_security_version"] <= 0
                or any(
                    not isinstance(document[name], str)
                    for name in _GRANT_FIELDS - {"schema_version", "expected_security_version"}
                )
                or not _SHA256.fullmatch(document["new_password_hash_sha256"])
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", document["review_reference"]
                )
                or document["reason_code"] not in {"identity_outage", "migration_rollback"}
            ):
                raise ValueError
            for name in ("grant_id", "user_id", "receipt_id"):
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
            raise CredentialMigrationError("credential_recovery_grant_invalid") from None


@dataclass(frozen=True, slots=True)
class CredentialRecoverySecret:
    new_password: str = field(repr=False)
    new_password_hash: str = field(repr=False)


class CredentialRecoveryService:
    """No public endpoint or online signing key can authorize this operation."""

    def __init__(
        self, sessions: sessionmaker[Session], *, verification_keys: CredentialRecoveryKeyring
    ) -> None:
        self._sessions = sessions
        self._keys = verification_keys

    def recover(
        self,
        *,
        signed_grant: str,
        secret: CredentialRecoverySecret,
        now: datetime | None = None,
    ) -> CredentialMigrationView:
        recovered_at = _time(now)
        grant = self._keys.verify(signed_grant, now=recovered_at)
        user_id = UUID(str(grant["user_id"]))
        receipt_id = UUID(str(grant["receipt_id"]))
        grant_hash = sha256(signed_grant.encode()).hexdigest()
        if _hash(secret.new_password_hash) != grant["new_password_hash_sha256"]:
            raise CredentialMigrationError("credential_recovery_secret_mismatch")
        PasswordCredentialService._validate_new_password(secret.new_password)
        try:
            if needs_rehash(secret.new_password_hash):
                raise ValueError
            verify_password(secret.new_password, secret.new_password_hash)
        except (InvalidPasswordError, ValueError):
            raise CredentialMigrationError("credential_recovery_secret_mismatch") from None
        key = scoped_idempotency_key("credential-recovery", user_id, str(grant["grant_id"]))
        with self._sessions.begin() as db:
            user = CredentialMigrationService._user(db, user_id)
            record = db.scalar(
                sa.select(CredentialMigrationRecord)
                .where(
                    CredentialMigrationRecord.id == receipt_id,
                    CredentialMigrationRecord.user_id == user_id,
                )
                .with_for_update()
            )
            event = db.scalar(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key
                    == scoped_idempotency_key("user", user_id, key)
                )
            )
            if event is not None:
                if (
                    event.request_hash != grant_hash
                    or record is None
                    or record.status != "recovered"
                ):
                    raise CredentialMigrationError("idempotency_conflict")
                return CredentialMigrationService._view(record)
            credential = db.get(PasswordCredential, user_id)
            if (
                record is None
                or record.status != "completed"
                or user.status != "active"
                or user.credential_owner != "casdoor"
                or user.migration_state not in {"cutover", "recovery_required"}
                or user.security_version != grant["expected_security_version"]
                or credential is None
                or credential.password_version != record.source_password_version
                or _hash(credential.password_hash) != record.source_password_sha256
            ):
                raise CredentialMigrationError("credential_recovery_state_conflict")
            try:
                verify_password(secret.new_password, credential.password_hash)
            except InvalidPasswordError:
                pass
            else:
                raise CredentialMigrationError("credential_recovery_requires_fresh_password")
            connections = list(
                db.scalars(
                    sa.select(IdentityConnection)
                    .where(
                        IdentityConnection.user_id == user_id,
                        IdentityConnection.provider == "casdoor",
                    )
                    .with_for_update()
                )
            )
            if not any(
                connection.id == record.identity_connection_id for connection in connections
            ):
                raise CredentialMigrationError("credential_recovery_state_conflict")
            recovered_at = _time(now)
            self._keys.verify(signed_grant, now=recovered_at)
            reconnectable = [
                str(connection.id)
                for connection in connections
                if connection.id == record.identity_connection_id and connection.status == "active"
            ]
            for connection in connections:
                connection.status = "revoked"
            credential.password_hash = secret.new_password_hash
            credential.password_version += 1
            credential.failed_attempts = 0
            credential.locked_until = None
            user.credential_owner = "legacy"
            user.migration_state = "recovered"
            record.status = "recovered"
            record.recovered_at = recovered_at
            record.updated_at = recovered_at
            record.version += 1
            security_version, revoked = _invalidate_sessions(db, user_id, recovered_at)
            _add_event(
                db,
                event_type="identity.credential_migration.recovered",
                aggregate_type="global_user",
                aggregate_key=str(user_id),
                idempotency_key=key,
                request_hash=grant_hash,
                payload={
                    "user_id": str(user_id),
                    "receipt_id": str(receipt_id),
                    "grant_id": grant["grant_id"],
                    "grant_sha256": grant_hash,
                    "review_reference": grant["review_reference"],
                    "reason_code": grant["reason_code"],
                    "new_password_hash_sha256": _hash(secret.new_password_hash),
                    "security_version": security_version,
                    "revoked_session_count": revoked,
                    "reconnectable_connection_ids": reconnectable,
                    "source_receipt_sha256": _digest(
                        {"receipt_id": str(record.id), "source": record.source_password_sha256}
                    ),
                },
            )
            return CredentialMigrationService._view(record)
