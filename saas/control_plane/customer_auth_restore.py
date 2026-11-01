"""Audited invalidation of restored customer authentication state before traffic."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.credential_migration_models import CredentialMigrationRecord
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    OidcLoginTransaction,
    OidcSessionFence,
)
from saas.control_plane.federated_sessions import _lock_fences
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.identity_event_models import (
    IdentityEventInboxRecord,
    IdentityProviderStateRecord,
)
from saas.control_plane.identity_inbox import _stored, _utc

_TABLES: tuple[sa.Table, ...] = tuple(
    sorted(
        (
            cast(sa.Table, model.__table__)
            for model in (
                GlobalUser,
                AuthSessionRecord,
                IdentityConnection,
                OidcLoginTransaction,
                OidcSessionFence,
                CredentialMigrationRecord,
                IdentityEventInboxRecord,
                IdentityProviderStateRecord,
            )
        ),
        key=lambda table: table.name,
    )
)
_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "restore_id",
        "product_revision",
        "backup_set_sha256",
        "target_binding_sha256",
        "captured_at",
        "expires_at",
        "tables",
    }
)


class CustomerAuthRestoreError(RuntimeError):
    """Content-blind restore rejection suitable for private operation diagnostics."""


def _json(value: object) -> bytes:
    def encode(item):
        if isinstance(item, datetime):
            return (
                item.replace(tzinfo=timezone.utc)
                if item.tzinfo is None
                else item.astimezone(timezone.utc)
            ).isoformat()
        return str(item)

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=encode
    ).encode()


def restore_review_sha256(review: dict[str, object]) -> str:
    return sha256(_json(review)).hexdigest()


class CustomerAuthRestoreService:
    """The caller drains writers and verifies the paired backup before this operation."""

    def __init__(self, sessions: sessionmaker[Session], *, product_revision: str):
        if re.fullmatch(r"[0-9a-f]{40}", product_revision) is None:
            raise ValueError("customer restore revision is invalid")
        self._sessions, self.product_revision = sessions, product_revision

    @staticmethod
    def _target(db: Session) -> str:
        if db.get_bind().dialect.name == "postgresql":
            row = db.execute(
                sa.text(
                    "SELECT current_database(),current_user,"
                    "inet_server_addr()::text,inet_server_port()"
                )
            ).one()
            return sha256(_json(list(row))).hexdigest()
        if db.get_bind().dialect.name == "sqlite":
            return sha256(b"owned-sqlite-restore-test").hexdigest()
        raise CustomerAuthRestoreError("customer_restore_database_unsupported")

    @staticmethod
    def _snapshot(db: Session) -> dict[str, object]:
        snapshots: dict[str, object] = {}
        for table in _TABLES:
            digest = sha256()
            count = 0
            rows = (
                db.execute(
                    sa.select(table)
                    .order_by(*table.primary_key.columns)
                    .execution_options(stream_results=True, max_row_buffer=128)
                )
                .mappings()
                .yield_per(128)
            )
            for row in rows:
                digest.update(sha256(_json(dict(row))).digest())
                count += 1
            snapshots[table.name] = {"row_count": count, "sha256": digest.hexdigest()}
        return snapshots

    def review(
        self, *, restore_id: UUID, backup_set_sha256: str, now: datetime | None = None
    ) -> dict[str, object]:
        if re.fullmatch(r"[0-9a-f]{64}", backup_set_sha256) is None:
            raise ValueError("backup set digest is invalid")
        captured = _utc(now)
        with self._sessions() as db:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(sa.text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            return {
                "schema_version": 1,
                "operation": "customer_authentication_restore",
                "restore_id": str(restore_id),
                "product_revision": self.product_revision,
                "backup_set_sha256": backup_set_sha256,
                "target_binding_sha256": self._target(db),
                "captured_at": captured.isoformat(),
                "expires_at": (captured + timedelta(minutes=5)).isoformat(),
                "tables": self._snapshot(db),
            }

    def _validate(self, review: dict[str, object], expected_sha256: str, now: datetime) -> None:
        try:
            if (
                set(review) != _FIELDS
                or type(review["schema_version"]) is not int
                or review["schema_version"] != 1
                or review["operation"] != "customer_authentication_restore"
                or review["product_revision"] != self.product_revision
                or any(
                    not isinstance(review[key], str)
                    for key in _FIELDS - {"schema_version", "tables"}
                )
                or any(
                    re.fullmatch(r"[0-9a-f]{64}", str(review[key])) is None
                    for key in ("backup_set_sha256", "target_binding_sha256")
                )
                or not isinstance(review["tables"], dict)
                or set(review["tables"]) != {table.name for table in _TABLES}
                or restore_review_sha256(review) != expected_sha256
                or str(UUID(str(review["restore_id"]))) != review["restore_id"]
            ):
                raise ValueError
            for value in review["tables"].values():
                if (
                    not isinstance(value, dict)
                    or set(value) != {"row_count", "sha256"}
                    or type(value["row_count"]) is not int
                    or value["row_count"] < 0
                    or not isinstance(value["sha256"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
                ):
                    raise ValueError
            start = _utc(datetime.fromisoformat(str(review["captured_at"])))
            end = _utc(datetime.fromisoformat(str(review["expires_at"])))
            if not start <= now < end or not timedelta(0) < end - start <= timedelta(minutes=5):
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise CustomerAuthRestoreError("customer_restore_review_invalid") from None

    @staticmethod
    def _fence(db: Session, cutoff: datetime) -> None:
        if db.get_bind().dialect.name == "postgresql":
            statement = pg_insert(OidcSessionFence).from_select(
                ["provider", "issuer", "kind", "key_hash", "logout_issued_at"],
                sa.select(
                    IdentityConnection.provider,
                    IdentityConnection.issuer,
                    sa.literal("subject"),
                    sa.func.encode(
                        sa.func.sha256(sa.func.convert_to(IdentityConnection.subject, "UTF8")),
                        "hex",
                    ),
                    sa.literal(cutoff),
                ),
            )
            db.execute(
                statement.on_conflict_do_update(
                    index_elements=["provider", "issuer", "kind", "key_hash"],
                    set_={
                        "logout_issued_at": sa.func.greatest(
                            OidcSessionFence.logout_issued_at, cutoff
                        )
                    },
                )
            )
        else:
            for provider, issuer, subject in db.execute(
                sa.select(
                    IdentityConnection.provider,
                    IdentityConnection.issuer,
                    IdentityConnection.subject,
                )
            ):
                row = _lock_fences(
                    db, provider=provider, issuer=issuer, selectors=[("subject", subject)]
                )["subject"]
                if row.logout_issued_at is None or _stored(row.logout_issued_at) < cutoff:
                    row.logout_issued_at = cutoff

    def apply(
        self,
        review: dict[str, object],
        *,
        expected_sha256: str,
        review_reference: str,
        now: datetime | None = None,
    ) -> dict[str, object]:
        self._validate(review, expected_sha256, _utc(now))
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", review_reference) is None:
            raise ValueError("customer restore review reference is invalid")
        key = scoped_idempotency_key(
            "customer-authentication-restore", self.product_revision, str(review["restore_id"])
        )
        with self._sessions.begin() as db:
            if db.get_bind().dialect.name == "postgresql":
                if not db.scalar(
                    sa.text("SELECT pg_try_advisory_xact_lock(:key)"),
                    {
                        "key": int.from_bytes(
                            sha256(b"omnigent.customer-auth-restore.v1").digest()[:8],
                            "big",
                            signed=True,
                        )
                    },
                ):
                    raise CustomerAuthRestoreError("customer_restore_already_running")
                # Traffic and all writers must already be drained. Column-scoped
                # authenticators can lock existing rows without owner/table grants.
                ordered = sorted(
                    _TABLES, key=lambda table: (table.name != GlobalUser.__tablename__, table.name)
                )
                for table in ordered:
                    rows = db.execute(
                        sa.select(table)
                        .order_by(*table.primary_key.columns)
                        .with_for_update()
                        .execution_options(stream_results=True, max_row_buffer=128)
                    ).yield_per(128)
                    for _row in rows:
                        pass
            cutoff = _utc(now)
            self._validate(review, expected_sha256, cutoff)
            if self._target(db) != review["target_binding_sha256"]:
                raise CustomerAuthRestoreError("customer_restore_target_mismatch")
            prior = db.scalar(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == key
                )
            )
            if prior is not None:
                if (
                    prior.request_hash != expected_sha256
                    or prior.event_type != "identity.customer_restore.invalidated"
                ):
                    raise CustomerAuthRestoreError("customer_restore_idempotency_conflict")
                return {
                    "duplicate": True,
                    "audit_id": str(prior.id),
                    "counts": prior.payload["counts"],
                }
            if self._snapshot(db) != review["tables"]:
                raise CustomerAuthRestoreError("customer_restore_review_stale")
            counts = {
                "users": db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)),
                "sessions": db.scalar(
                    sa.select(sa.func.count())
                    .select_from(AuthSessionRecord)
                    .where(AuthSessionRecord.revoked_at.is_(None))
                ),
                "oidc_transactions": db.scalar(
                    sa.select(sa.func.count())
                    .select_from(OidcLoginTransaction)
                    .where(OidcLoginTransaction.status == "pending")
                ),
                "provider_claims": db.scalar(
                    sa.select(sa.func.count())
                    .select_from(IdentityProviderStateRecord)
                    .where(IdentityProviderStateRecord.claim_token.is_not(None))
                ),
                "inbox_claims": db.scalar(
                    sa.select(sa.func.count())
                    .select_from(IdentityEventInboxRecord)
                    .where(IdentityEventInboxRecord.status == "processing")
                ),
                "migration_claims": db.scalar(
                    sa.select(sa.func.count())
                    .select_from(CredentialMigrationRecord)
                    .where(CredentialMigrationRecord.claim_token.is_not(None))
                ),
            }
            db.execute(
                sa.update(GlobalUser).values(security_version=GlobalUser.security_version + 1)
            )
            self._fence(db, cutoff)
            db.execute(
                sa.update(AuthSessionRecord)
                .where(AuthSessionRecord.revoked_at.is_(None))
                .values(revoked_at=cutoff)
            )
            db.execute(
                sa.update(OidcLoginTransaction)
                .where(OidcLoginTransaction.status == "pending")
                .values(status="failed", consumed_at=cutoff)
            )
            db.execute(
                sa.update(CredentialMigrationRecord)
                .where(CredentialMigrationRecord.claim_token.is_not(None))
                .values(
                    claim_token=None,
                    lease_expires_at=None,
                    version=CredentialMigrationRecord.version + 1,
                    updated_at=cutoff,
                )
            )
            db.execute(
                sa.update(IdentityProviderStateRecord).values(
                    claim_token=None,
                    claim_sha256=None,
                    lease_expires_at=None,
                    next_check_at=cutoff,
                    version=IdentityProviderStateRecord.version + 1,
                    updated_at=cutoff,
                )
            )
            db.execute(
                sa.update(IdentityEventInboxRecord)
                .where(IdentityEventInboxRecord.status.in_(("pending", "retry", "processing")))
                .values(
                    status="retry",
                    claim_token=None,
                    lease_expires_at=None,
                    completed_at=None,
                    available_at=cutoff,
                    last_error_code="identity_inbox_claim_stale",
                    version=IdentityEventInboxRecord.version + 1,
                )
            )
            for model, predicate in (
                (AuthSessionRecord, AuthSessionRecord.revoked_at.is_(None)),
                (OidcLoginTransaction, OidcLoginTransaction.status == "pending"),
                (CredentialMigrationRecord, CredentialMigrationRecord.claim_token.is_not(None)),
                (
                    IdentityProviderStateRecord,
                    IdentityProviderStateRecord.claim_token.is_not(None),
                ),
                (IdentityEventInboxRecord, IdentityEventInboxRecord.status == "processing"),
            ):
                if db.scalar(sa.select(sa.func.count()).select_from(model).where(predicate)):
                    raise CustomerAuthRestoreError("customer_restore_invalidation_incomplete")
            self._validate(review, expected_sha256, _utc(now))
            audit = ControlPlaneOutboxEvent(
                id=uuid4(),
                tenant_id=None,
                aggregate_type="customer_authentication_restore",
                aggregate_key=str(review["restore_id"]),
                event_type="identity.customer_restore.invalidated",
                idempotency_key=key,
                request_hash=expected_sha256,
                attempt_count=0,
                payload={
                    "product_revision": self.product_revision,
                    "restore_id": review["restore_id"],
                    "backup_set_sha256": review["backup_set_sha256"],
                    "review_sha256": expected_sha256,
                    "target_binding_sha256": review["target_binding_sha256"],
                    "review_reference": review_reference,
                    "counts": counts,
                    "cutoff_at": cutoff.isoformat(),
                },
            )
            db.add(audit)
            return {"duplicate": False, "audit_id": str(audit.id), "counts": counts}
