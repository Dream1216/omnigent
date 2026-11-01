"""Offline-reviewed dead-letter replay with an atomic, append-only audit receipt."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from types import MappingProxyType
from uuid import UUID, uuid4

import sqlalchemy as sa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.identity_event_models import IdentityEventInboxRecord
from saas.control_plane.identity_events import (
    IdentitySyncError,
    _unique_object,
    safe_identity_error_code,
)
from saas.control_plane.identity_inbox import IdentitySyncPolicy, _stored, _utc

REPLAY_SIGNATURE_DOMAIN = b"omnigent.identity-inbox-replay.v1\x00"
REPLAY_REASONS = frozenset({"provider_restored", "mapping_repaired", "configuration_repaired"})
_KEY_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SAFE_ERRORS = frozenset(
    {
        "identity_replay_grant_invalid",
        "identity_replay_scope_mismatch",
        "identity_replay_not_found",
        "identity_replay_not_reviewable",
        "identity_replay_review_stale",
        "identity_replay_idempotency_conflict",
    }
)
_GRANT_FIELDS = frozenset(
    {
        "schema_version",
        "grant_id",
        "product_revision",
        "issuer",
        "organization",
        "inbox_id",
        "review_sha256",
        "issued_at",
        "expires_at",
        "review_reference",
        "reason_code",
    }
)


class IdentityReplayError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code if code in _SAFE_ERRORS else "identity_replay_rejected"
        super().__init__(self.code)


def replay_payload(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(document), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def replay_signature_input(key_id: str, payload: bytes) -> bytes:
    if not _KEY_ID.fullmatch(key_id):
        raise ValueError("invalid replay verification key ID")
    return REPLAY_SIGNATURE_DOMAIN + key_id.encode("ascii") + b"\x00" + payload


def _decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError
    return decoded


@dataclass(frozen=True, slots=True)
class IdentityReplayKeyring:
    public_keys: Mapping[str, bytes]

    def __post_init__(self) -> None:
        if not 1 <= len(self.public_keys) <= 8 or any(
            not isinstance(key_id, str)
            or not _KEY_ID.fullmatch(key_id)
            or not isinstance(value, bytes)
            or len(value) != 32
            for key_id, value in self.public_keys.items()
        ):
            raise ValueError("identity replay verification keys are invalid")
        object.__setattr__(self, "public_keys", MappingProxyType(dict(self.public_keys)))

    def verify(self, token: str, *, now: datetime) -> tuple[str, dict[str, object]]:
        try:
            if not isinstance(token, str) or len(token) > 8192:
                raise ValueError
            version, key_id, encoded, signature = token.split(".")
            if version != "v1" or key_id not in self.public_keys:
                raise ValueError
            payload = _decode(encoded)
            Ed25519PublicKey.from_public_bytes(self.public_keys[key_id]).verify(
                _decode(signature), replay_signature_input(key_id, payload)
            )
            document = json.loads(payload, object_pairs_hook=_unique_object)
            if (
                not isinstance(document, dict)
                or set(document) != _GRANT_FIELDS
                or payload != replay_payload(document)
                or type(document["schema_version"]) is not int
                or document["schema_version"] != 1
                or any(
                    not isinstance(document[name], str)
                    for name in _GRANT_FIELDS - {"schema_version"}
                )
                or not re.fullmatch(r"[0-9a-f]{40}", document["product_revision"])
                or not _SHA256.fullmatch(document["review_sha256"])
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", document["review_reference"]
                )
                or document["reason_code"] not in REPLAY_REASONS
            ):
                raise ValueError
            for name in ("grant_id", "inbox_id"):
                if str(UUID(document[name])) != document[name]:
                    raise ValueError
            IdentitySyncPolicy(issuer=document["issuer"], organization=document["organization"])
            issued = _utc(datetime.fromisoformat(document["issued_at"]))
            expires = _utc(datetime.fromisoformat(document["expires_at"]))
            if not issued <= _utc(now) < expires or not timedelta(
                0
            ) < expires - issued <= timedelta(minutes=5):
                raise ValueError
            return key_id, document
        except (ValueError, TypeError, KeyError, InvalidSignature, UnicodeError):
            raise IdentityReplayError("identity_replay_grant_invalid") from None


class IdentityDeadLetterService:
    """Replay changes only Inbox scheduling; workers still verify current provider state."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        policy: IdentitySyncPolicy,
        product_revision: str,
        verification_keys: IdentityReplayKeyring,
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{40}", product_revision) is None:
            raise ValueError("identity replay product revision is invalid")
        self._sessions, self.policy = sessions, policy
        self.product_revision, self._keys = product_revision, verification_keys

    def _scope(self):
        return (
            IdentityEventInboxRecord.provider == "casdoor",
            IdentityEventInboxRecord.issuer == self.policy.issuer,
            IdentityEventInboxRecord.organization == self.policy.organization,
        )

    def _review(self, record: IdentityEventInboxRecord) -> dict[str, object]:
        if (
            record.status != "dead"
            or record.claim_token is not None
            or record.lease_expires_at is not None
            or record.completed_at is None
            or record.last_error_code is None
            or safe_identity_error_code(IdentitySyncError(record.last_error_code))
            != record.last_error_code
        ):
            raise IdentityReplayError("identity_replay_not_reviewable")
        review = {
            "schema_version": 1,
            "product_revision": self.product_revision,
            "inbox_id": str(record.id),
            "issuer": record.issuer,
            "organization": record.organization,
            "event_id": record.event_id,
            "action": record.action,
            "security_event": record.security_event,
            "subject_locator_sha256": record.subject_locator_sha256,
            "username_locator_sha256": record.username_locator_sha256,
            "request_sha256": record.request_sha256,
            "occurred_at": _stored(record.occurred_at).isoformat(),
            "received_at": _stored(record.received_at).isoformat(),
            "completed_at": _stored(record.completed_at).isoformat(),
            "attempt_count": record.attempt_count,
            "processed_connection_count": record.processed_connection_count,
            "version": record.version,
            "last_error_code": record.last_error_code,
            "status": record.status,
        }
        return {
            "schema_version": 1,
            "review": review,
            "review_sha256": sha256(replay_payload(review)).hexdigest(),
        }

    def list_dead(self, *, limit: int = 50) -> list[dict[str, object]]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("identity dead-letter limit is invalid")
        with self._sessions() as db:
            records = db.scalars(
                sa.select(IdentityEventInboxRecord)
                .where(
                    *self._scope(),
                    IdentityEventInboxRecord.status == "dead",
                )
                .order_by(IdentityEventInboxRecord.received_at, IdentityEventInboxRecord.id)
                .limit(limit)
            )
            return [self._review(record) for record in records]

    def review(self, inbox_id: UUID) -> dict[str, object]:
        with self._sessions() as db:
            record = db.scalar(
                sa.select(IdentityEventInboxRecord).where(
                    *self._scope(),
                    IdentityEventInboxRecord.id == inbox_id,
                )
            )
            if record is None:
                raise IdentityReplayError("identity_replay_not_found")
            return self._review(record)

    def replay(self, signed_grant: str, *, now: datetime | None = None) -> dict[str, object]:
        key_id, grant = self._keys.verify(signed_grant, now=_utc(now))
        if any(
            grant[name] != value
            for name, value in (
                ("product_revision", self.product_revision),
                ("issuer", self.policy.issuer),
                ("organization", self.policy.organization),
            )
        ):
            raise IdentityReplayError("identity_replay_scope_mismatch")
        inbox_id = UUID(str(grant["inbox_id"]))
        grant_hash = sha256(signed_grant.encode()).hexdigest()
        idempotency_key = scoped_idempotency_key(
            "identity-inbox-replay", self.product_revision, str(grant["grant_id"])
        )
        with self._sessions.begin() as db:
            record = db.scalar(
                sa.select(IdentityEventInboxRecord)
                .where(
                    *self._scope(),
                    IdentityEventInboxRecord.id == inbox_id,
                )
                .with_for_update()
            )
            # Lock waits must not extend an offline authorization's lifetime.
            checked = _utc(now)
            self._keys.verify(signed_grant, now=checked)
            if record is None:
                raise IdentityReplayError("identity_replay_not_found")
            prior = db.scalar(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                if (
                    prior.request_hash != grant_hash
                    or prior.aggregate_key != str(inbox_id)
                    or prior.event_type != "identity.notification.replayed"
                ):
                    raise IdentityReplayError("identity_replay_idempotency_conflict")
                return {
                    "inbox_id": str(inbox_id),
                    "audit_id": str(prior.id),
                    "duplicate": True,
                    "status": record.status,
                }
            review = self._review(record)
            if review["review_sha256"] != grant["review_sha256"]:
                raise IdentityReplayError("identity_replay_review_stale")
            audit = ControlPlaneOutboxEvent(
                id=uuid4(),
                tenant_id=None,
                aggregate_type="identity_event_inbox",
                aggregate_key=str(inbox_id),
                event_type="identity.notification.replayed",
                idempotency_key=idempotency_key,
                request_hash=grant_hash,
                attempt_count=0,
                payload={
                    "inbox_id": str(inbox_id),
                    "grant_id": grant["grant_id"],
                    "grant_sha256": grant_hash,
                    "review_sha256": grant["review_sha256"],
                    "reviewer_key_id": key_id,
                    "review_reference": grant["review_reference"],
                    "reason_code": grant["reason_code"],
                    "previous_version": record.version,
                    "previous_attempt_count": record.attempt_count,
                    "previous_last_error_code": record.last_error_code,
                    "request_sha256": record.request_sha256,
                    "replayed_at": checked.isoformat(),
                },
            )
            db.add(audit)
            record.status, record.attempt_count, record.processed_connection_count = (
                "pending",
                0,
                0,
            )
            record.available_at, record.completed_at, record.last_error_code = checked, None, None
            record.claim_token, record.lease_expires_at = None, None
            record.version += 1
            return {
                "inbox_id": str(inbox_id),
                "audit_id": str(audit.id),
                "duplicate": False,
                "status": record.status,
            }
